package com.peculiarventures.mtaqr.issuer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.peculiarventures.mtaqr.cascade.Cascade;
import com.peculiarventures.mtaqr.signing.Signer;
import com.peculiarventures.mtaqr.trust.TrustConfig;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * MTA-QR Issuer.
 *
 * <p>Maintains an in-memory transparency log, issues signed QR code payloads,
 * and publishes cosigned checkpoints. All signing is delegated to the injected
 * {@link Signer} — the Issuer never holds private key material.
 *
 * <p>Witness keys are ephemeral Ed25519 keys generated at startup.
 *
 * <p>Usage:
 * <pre>{@code
 * Issuer issuer = Issuer.builder()
 *     .origin("example.com/log/v1")
 *     .schemaId(1)
 *     .signer(signer)
 *     .build();
 * issuer.init().join();
 * IssuedQR qr = issuer.issue(Map.of("subject", "Alice"), Duration.ofHours(1)).join();
 * }</pre>
 */
public final class Issuer {

    /** Result of a successful issue call. */
    public record IssuedQR(
        long   entryIndex,
        long   treeSize,
        byte[] payload,
        String payloadBase64Url
    ) {}

    // --- builder ---

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String origin;
        private long   schemaId = 1;
        private int    mode = 1;
        private int    batchSize = 16;
        private int    witnessCount = 2;
        private Signer signer;

        public Builder origin(String v)      { origin = v; return this; }
        public Builder schemaId(long v)      { schemaId = v; return this; }
        public Builder mode(int v)           { mode = v; return this; }
        public Builder batchSize(int v)      { batchSize = v; return this; }
        public Builder witnessCount(int v)   { witnessCount = v; return this; }
        public Builder signer(Signer v)      { signer = v; return this; }

        public Issuer build() {
            Objects.requireNonNull(origin, "origin is required");
            Objects.requireNonNull(signer, "signer is required");
            return new Issuer(origin, schemaId, mode, batchSize, witnessCount, signer);
        }
    }

    // --- internals ---

    private static final byte ENTRY_TYPE_NULL = 0x00;
    private static final byte ENTRY_TYPE_DATA = 0x01;
    private static final int  MODE_EMBEDDED   = 0;
    private static final int  MODE_CACHED     = 1;
    private static final int  MODE_ONLINE     = 2;

    private record WitnessKey(
        String name, byte[] keyId, Ed25519PrivateKeyParameters priv, byte[] pub) {}

    private record LogEntry(long index, byte[] tbs, byte[] entryHash) {}

    private record Batch(List<LogEntry> entries, byte[] root) {}

    private record SignedCheckpoint(
        long treeSize, byte[] rootHash,
        byte[] body,      byte[] issuerSig,  List<WitnessCosig> cosigs,
        byte[] plainBody, byte[] plainSig,   List<WitnessCosig> plainCosigs) {}

    private record WitnessCosig(byte[] keyId, long timestamp, byte[] signature) {}

    private final String origin;
    private final long   schemaId;
    private final int    mode;
    private final int    batchSize;
    private final int    witnessCount;
    private final Signer signer;

    private final Object lock = new Object();
    private long   originId;
    private byte[] issuerPub;
    private List<WitnessKey> witnesses;
    private List<Batch>      batches      = new ArrayList<>();
    private List<LogEntry>   currentBatch = new ArrayList<>();
    private SignedCheckpoint latestCkpt;
    private final Set<Long>  revokedIndices = new HashSet<>();
    private volatile String  latestRevArtifact;

    private Issuer(String origin, long schemaId, int mode, int batchSize, int witnessCount, Signer signer) {
        this.origin       = origin;
        this.schemaId     = schemaId;
        this.mode         = (mode == 0) ? 0 : (mode == 2) ? 2 : 1;
        this.batchSize    = batchSize;
        this.witnessCount = witnessCount;
        this.signer       = signer;
    }

    /**
     * Initializes the issuer. Must be called before {@link #issue}.
     * Resolves the signing key's public key, generates witness keys, and
     * appends the genesis null_entry.
     */
    public CompletableFuture<Void> init() {
        return signer.publicKeyBytes().thenCompose(pub -> {
            synchronized (lock) {
                issuerPub = pub;
                originId  = computeOriginId(origin);
                witnesses = new ArrayList<>();
                for (int i = 0; i < witnessCount; i++) {
                    byte[] seed = new byte[32];
                    new SecureRandom().nextBytes(seed);
                    Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(seed, 0);
                    byte[] wPub = priv.generatePublicKey().getEncoded();
                    String name = "witness-" + i;
                    witnesses.add(new WitnessKey(name, witnessKeyId(name, wPub), priv, wPub));
                }
                appendEntryLocked(new byte[]{ENTRY_TYPE_NULL});
            }
            return publishCheckpoint();
        });
    }

    /**
     * Issues a QR code payload for the given claims.
     *
     * @param claims  key-value claims to include in the assertion
     * @param ttl     assertion validity duration
     * @return a future resolving to the issued QR payload
     */
    public CompletableFuture<IssuedQR> issue(Map<String, Object> claims, Duration ttl) {
        if (latestCkpt == null) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Issuer: call init() before issue()"));
        }
        long now    = Instant.now().getEpochSecond();
        long expiry = now + ttl.getSeconds();
        byte[] tbs  = encodeTbs(now, expiry, claims);

        long idx;
        synchronized (lock) {
            idx = appendEntryLocked(tbs);
        }
        return publishCheckpoint().thenApply(v -> {
            byte[] payload = buildPayload(idx, tbs);
            return new IssuedQR(
                idx, latestCkpt.treeSize(), payload,
                Base64.getUrlEncoder().withoutPadding().encodeToString(payload));
        });
    }

    /**
     * Returns the trust config as a JSON string for verifiers.
     */
    public String trustConfigJson(String checkpointUrl) {
        if (latestCkpt == null) throw new IllegalStateException("call init() first");
        List<Map<String, String>> wList = witnesses.stream().map(w -> Map.of(
            "name",        w.name(),
            "key_id_hex",  HexFormat.of().formatHex(w.keyId()),
            "pub_key_hex", HexFormat.of().formatHex(w.pub())
        )).toList();
        try {
            // Map.of supports ≤10 entries; use Map.ofEntries to avoid the limit.
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(
                Map.ofEntries(
                    Map.entry("origin",             origin),
                    Map.entry("origin_id",          String.format("%016x", originId)),
                    Map.entry("issuer_key_name",    signer.getKeyName()),
                    Map.entry("issuer_pub_key_hex", HexFormat.of().formatHex(issuerPub)),
                    Map.entry("sig_alg",            signer.getAlg()),
                    Map.entry("witness_quorum",     witnesses.size()),
                    Map.entry("checkpoint_url",     checkpointUrl),
                    Map.entry("revocation_url",    revocationUrlFrom(checkpointUrl)),
                    Map.entry("batch_size",         batchSize),
                    Map.entry("witnesses",          wList)
                ));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns the current signed checkpoint in tlog-checkpoint signed-note format.
     * Expose this via a {@code /checkpoint} HTTP endpoint.
     */
    public String checkpointNote() {
        SignedCheckpoint ckpt = latestCkpt;
        if (ckpt == null) throw new IllegalStateException("call init() first");
        StringBuilder sb = new StringBuilder();
        sb.append(new String(ckpt.body(), StandardCharsets.UTF_8)).append('\n');
        // Per c2sp.org/signed-note: sig payload = 4-byte key_hash || raw_signature
        byte[] issuerKeyId = witnessKeyId(signer.getKeyName(), issuerPub);
        byte[] issuerPayload = new byte[4 + ckpt.issuerSig().length];
        System.arraycopy(issuerKeyId, 0, issuerPayload, 0, 4);
        System.arraycopy(ckpt.issuerSig(), 0, issuerPayload, 4, ckpt.issuerSig().length);
        sb.append("— ").append(signer.getKeyName()).append(' ')
          .append(Base64.getEncoder().encodeToString(issuerPayload)).append('\n');
        for (int i = 0; i < witnesses.size(); i++) {
            WitnessKey w = witnesses.get(i);
            WitnessCosig c = ckpt.cosigs().get(i);
            // Per c2sp.org/signed-note + tlog-cosignature:
            //   4-byte key_hash || 8-byte timestamp || 64-byte Ed25519 sig = 76 bytes
            byte[] payload = new byte[76];
            System.arraycopy(w.keyId(), 0, payload, 0, 4);
            ByteBuffer.wrap(payload, 4, 8).putLong(c.timestamp());
            System.arraycopy(c.signature(), 0, payload, 12, 64);
            sb.append("— ").append(w.name()).append(' ')
              .append(Base64.getEncoder().encodeToString(payload)).append('\n');
        }
        return sb.toString();
    }

    // --- private protocol logic ---

    private long appendEntryLocked(byte[] tbs) {
        long idx = totalEntriesLocked();
        currentBatch.add(new LogEntry(idx, tbs, entryHash(tbs)));
        if (currentBatch.size() >= batchSize) {
            byte[] root = merkleRoot(currentBatch.stream().map(LogEntry::entryHash).toList());
            batches.add(new Batch(new ArrayList<>(currentBatch), root));
            currentBatch = new ArrayList<>();
        }
        return idx;
    }

    private long totalEntriesLocked() {
        return batches.stream().mapToLong(b -> b.entries().size()).sum() + currentBatch.size();
    }

    private List<byte[]> batchRoots() {
        List<byte[]> roots = new ArrayList<>();
        for (Batch b : batches) roots.add(b.root());
        if (!currentBatch.isEmpty()) {
            roots.add(merkleRoot(currentBatch.stream().map(LogEntry::entryHash).toList()));
        }
        return roots;
    }

    private CompletableFuture<Void> publishCheckpoint() {
        List<byte[]> bRoots;
        long treeSize;
        synchronized (lock) {
            bRoots   = batchRoots();
            treeSize = totalEntriesLocked();
        }
        byte[] parentRoot = merkleRoot(bRoots);
        byte[] plainBody = checkpointBody(origin, treeSize, parentRoot);
        // Build revocation artifact first; commit its hash in the checkpoint body.
        String revocSnap;
        synchronized (lock) { revocSnap = latestRevArtifact; }
        byte[] body = (revocSnap != null)
            ? checkpointBodyWithRevoc(origin, treeSize, parentRoot,
                revocSnap.getBytes(java.nio.charset.StandardCharsets.UTF_8))
            : plainBody;
        final byte[] finalBody = body, finalPlainBody = plainBody;

        return signer.sign(body).thenCompose(issuerSig ->
            signer.sign(plainBody).thenAccept(plainSig -> {
            long ts = Instant.now().getEpochSecond();
            List<WitnessCosig> cosigs = new ArrayList<>();
            List<WitnessCosig> plainCosigs = new ArrayList<>();
            boolean same = java.util.Arrays.equals(finalBody, finalPlainBody);
            for (WitnessKey w : witnesses) {
                byte[] msg = cosignatureMessage(finalBody, ts);
                Ed25519Signer sv = new Ed25519Signer();
                sv.init(true, w.priv()); sv.update(msg, 0, msg.length);
                byte[] sig = sv.generateSignature();
                cosigs.add(new WitnessCosig(w.keyId(), ts, sig));
                if (same) { plainCosigs.add(new WitnessCosig(w.keyId(), ts, sig)); }
                else {
                    byte[] pmsg = cosignatureMessage(finalPlainBody, ts);
                    Ed25519Signer pv = new Ed25519Signer();
                    pv.init(true, w.priv()); pv.update(pmsg, 0, pmsg.length);
                    plainCosigs.add(new WitnessCosig(w.keyId(), ts, pv.generateSignature()));
                }
            }
            synchronized (lock) {
                latestCkpt = new SignedCheckpoint(
                    treeSize, parentRoot, finalBody, issuerSig, cosigs,
                    finalPlainBody, plainSig, plainCosigs);
                latestRevArtifact = buildRevocationArtifact(treeSize);
            }
        }));
    }

    private byte[] buildPayload(long globalIdx, byte[] tbs) {
        SignedCheckpoint ckpt = latestCkpt;

        // Mode 0: embed proof + signed checkpoint.
        if (mode == MODE_EMBEDDED) {
            int batchIdx0 = (int)(globalIdx / batchSize);
            int innerIdx0 = (int)(globalIdx % batchSize);
            List<byte[]> batchHashes0;
            int batchSz0;
            synchronized (lock) {
                if (batchIdx0 < batches.size()) {
                    List<LogEntry> b = batches.get(batchIdx0).entries();
                    batchHashes0 = b.stream().map(LogEntry::entryHash).toList();
                    batchSz0     = b.size();
                } else {
                    batchHashes0 = currentBatch.stream().map(LogEntry::entryHash).toList();
                    batchSz0     = currentBatch.size();
                }
            }
            List<byte[]> innerProof0 = inclusionProof(batchHashes0, innerIdx0, batchSz0);
            List<byte[]> allRoots0   = batchRoots();
            List<byte[]> outerProof0 = inclusionProof(allRoots0, batchIdx0, allRoots0.size());
            List<byte[]> allProof0   = new ArrayList<>(innerProof0);
            allProof0.addAll(outerProof0);

            // Use the issuer sig and witness cosigs from the stored checkpoint.
            byte[] payload = encodePayload(globalIdx, ckpt.treeSize(), allProof0,
                                           innerProof0.size(), tbs, MODE_EMBEDDED);
            // Append embedded checkpoint fields.
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            try { out.write(payload); } catch (Exception ignored) {}
            // root_hash (32 bytes)
            out.writeBytes(ckpt.rootHash());
            // issuer_sig_len (2 bytes big-endian) + issuer_sig
            int slen = ckpt.plainSig().length;
            out.write((slen >> 8) & 0xff); out.write(slen & 0xff);
            out.writeBytes(ckpt.plainSig());
            // witness_count (1 byte) + cosigs
            List<WitnessCosig> cosigs0 = ckpt.plainCosigs();
            out.write(cosigs0.size() & 0xff);
            for (WitnessCosig c : cosigs0) {
                out.writeBytes(c.keyId());
                long ts0 = c.timestamp();
                for (int bi = 7; bi >= 0; bi--) out.write((int)((ts0 >> (bi*8)) & 0xff));
                out.writeBytes(c.signature());
            }
            return out.toByteArray();
        }

        // Mode 2: no proof embedded.
        if (mode == MODE_ONLINE)
            return encodePayload(globalIdx, ckpt.treeSize(), List.of(), 0, tbs, MODE_ONLINE);

        // Mode 1: embed two-phase tiled Merkle proof.
        int batchIdx  = (int) (globalIdx / batchSize);
        int innerIdx  = (int) (globalIdx % batchSize);

        List<byte[]> batchHashes;
        int batchSz;
        synchronized (lock) {
            if (batchIdx < batches.size()) {
                List<LogEntry> bEntries = batches.get(batchIdx).entries();
                batchHashes = bEntries.stream().map(LogEntry::entryHash).toList();
                batchSz     = bEntries.size();
            } else {
                batchHashes = currentBatch.stream().map(LogEntry::entryHash).toList();
                batchSz     = currentBatch.size();
            }
        }

        List<byte[]> innerProof = inclusionProof(batchHashes, innerIdx, batchSz);
        List<byte[]> allRoots   = batchRoots();
        List<byte[]> outerProof = inclusionProof(allRoots, batchIdx, allRoots.size());

        List<byte[]> allProof = new ArrayList<>(innerProof);
        allProof.addAll(outerProof);

        return encodePayload(globalIdx, ckpt.treeSize(), allProof, innerProof.size(), tbs, MODE_CACHED);
    }

    // --- Merkle tree ---

    // Test-accessible primitive helpers.
    // These methods are package-private to keep them out of the public API.
    // Tests in the same package (src/test/...) can call them directly.
    public static byte[] hashLeafForTest(byte[] data)  { return hashLeaf(data); }
    public static byte[] hashNodeForTest(byte[] l, byte[] r) { return hashNode(l, r); }
    public static byte[] entryHashForTest(byte[] tbs) { return entryHash(tbs); }
    public static byte[] encodeTbsForTest(long issuedAt, long expiresAt, long schemaId, Map<String, Object> claims) {
        // Temporarily swap schemaId since encodeTbs uses the instance field
        // We need a standalone version — delegate to the internal CBOR logic.
        return encodeTbsStatic(issuedAt, expiresAt, schemaId, claims);
    }

    public void revoke(long entryIndex) {
        synchronized (lock) {
            if (entryIndex == 0)
                throw new IllegalArgumentException("entry_index=0 is the null entry");
            if (entryIndex >= totalEntriesLocked())
                throw new IllegalArgumentException("entry_index " + entryIndex + " not yet issued");
            revokedIndices.add(entryIndex);
            if (latestCkpt != null)
                latestRevArtifact = buildRevocationArtifact(latestCkpt.treeSize());
        }
    }

    public String revocationArtifact() { return latestRevArtifact; }

    private static String revocationUrlFrom(String checkpointUrl) {
        return checkpointUrl.endsWith("/checkpoint")
            ? checkpointUrl.substring(0, checkpointUrl.length() - 11) + "/revoked"
            : checkpointUrl.replace("checkpoint", "revoked");
    }

    private String buildRevocationArtifact(long treeSize) {
        long now = Instant.now().getEpochSecond();
        List<Long> revoked = new ArrayList<>(), valid = new ArrayList<>();
        List<LogEntry> all = new ArrayList<>();
        synchronized (lock) {
            for (Batch b : batches) all.addAll(b.entries());
            all.addAll(currentBatch);
        }
        for (LogEntry e : all) {
            if (e.index() == 0) continue;
            if (revokedIndices.contains(e.index())) { revoked.add(e.index()); continue; }
            long exp = entryExpiryTimestamp(e.tbs());
            if (exp > 0 && exp < now) continue;
            valid.add(e.index());
        }
        long[] r = revoked.stream().mapToLong(Long::longValue).toArray();
        long[] v = valid.stream().mapToLong(Long::longValue).toArray();
        Cascade casc = Cascade.build(r, v);
        String cascB64 = Base64.getEncoder().encodeToString(casc.encode());
        String body = origin + "\n" + treeSize + "\nmta-qr-revocation-v1\n" + cascB64 + "\n";
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        byte[] sig;
        try { sig = signer.sign(bodyBytes).get(); }
        catch (Exception e) { throw new RuntimeException("revocation sign failed", e); }
        byte[] keyId = witnessKeyId(signer.getKeyName(), issuerPub);
        byte[] payload = new byte[4 + sig.length];
        System.arraycopy(keyId, 0, payload, 0, 4);
        System.arraycopy(sig,   0, payload, 4, sig.length);
        String sigLine = "\n\u2014 " + signer.getKeyName() + " " +
            Base64.getEncoder().encodeToString(payload) + "\n";
        return body + sigLine;
    }

    private static long entryExpiryTimestamp(byte[] tbs) {
        if (tbs == null || tbs.length < 2 || tbs[0] != ENTRY_TYPE_DATA) return 0;
        try {
            var obj = com.upokecenter.cbor.CBORObject.DecodeFromBytes(
                java.util.Arrays.copyOfRange(tbs, 1, tbs.length));
            var times = obj.get(com.upokecenter.cbor.CBORObject.FromObject(2));
            return (times != null && times.size() >= 2) ? times.get(1).AsInt64Value() : 0;
        } catch (Exception e) { return 0; }
    }

    private static byte[] entryHash(byte[] tbs) {
        return hashLeaf(tbs);
    }

    private static byte[] hashLeaf(byte[] data) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update((byte) 0x00);
            return sha.digest(data);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static byte[] hashNode(byte[] left, byte[] right) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update((byte) 0x01);
            sha.update(left);
            return sha.digest(right);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public static byte[] merkleRoot(List<byte[]> leaves) {
        if (leaves.isEmpty()) throw new IllegalArgumentException("merkle: empty");
        return reduceLevel(new ArrayList<>(leaves));
    }

    private static byte[] reduceLevel(List<byte[]> nodes) {
        if (nodes.size() == 1) return nodes.get(0);
        List<byte[]> next = new ArrayList<>();
        for (int i = 0; i < nodes.size() - 1; i += 2)
            next.add(hashNode(nodes.get(i), nodes.get(i + 1)));
        if (nodes.size() % 2 == 1) next.add(nodes.get(nodes.size() - 1));
        return reduceLevel(next);
    }

    public static List<byte[]> inclusionProof(List<byte[]> leaves, int idx, int treeSize) {
        if (treeSize == 0 || idx < 0 || idx >= treeSize)
            throw new IllegalArgumentException("merkle: invalid index " + idx);
        List<byte[]> proof = new ArrayList<>();
        List<byte[]> current = new ArrayList<>(leaves);
        while (current.size() > 1) {
            int sib = idx % 2 == 0 ? idx + 1 : idx - 1;
            proof.add(sib < current.size() ? current.get(sib) : current.get(idx));
            List<byte[]> next = new ArrayList<>();
            for (int i = 0; i < current.size() - 1; i += 2)
                next.add(hashNode(current.get(i), current.get(i + 1)));
            if (current.size() % 2 == 1) next.add(current.get(current.size() - 1));
            idx = idx / 2;
            current = next;
        }
        return proof;
    }

    public static void verifyInclusion(byte[] leafHash, int idx, int treeSize,
                                List<byte[]> proof, byte[] expectedRoot) {
        byte[] node = leafHash;
        int size = treeSize;
        for (byte[] sib : proof) {
            if (idx % 2 == 0) {
                if (idx + 1 == size && size % 2 == 1) { idx /= 2; size = (size + 1) / 2; continue; }
                node = hashNode(node, sib);
            } else {
                node = hashNode(sib, node);
            }
            idx  = idx / 2;
            size = (size + 1) / 2;
        }
        // MessageDigest.isEqual is constant-time — prevents timing side-channels
        // on the Merkle root comparison.
        if (!java.security.MessageDigest.isEqual(node, expectedRoot))
            throw new RuntimeException("merkle: root mismatch");
    }

    public static byte[] computeRootFromProof(byte[] start, int idx, int treeSize, List<byte[]> proof) {
        byte[] node = start;
        int size = treeSize;
        for (byte[] sib : proof) {
            if (idx % 2 == 0) {
                if (idx + 1 == size && size % 2 == 1) { idx /= 2; size = (size + 1) / 2; continue; }
                node = hashNode(node, sib);
            } else {
                node = hashNode(sib, node);
            }
            idx  = idx / 2;
            size = (size + 1) / 2;
        }
        return node;
    }

    // --- Checkpoint ---

    /** Checkpoint body with 4th extension line: revoc:<hex(SHA-256(artifact))>\n */
    public static byte[] checkpointBodyWithRevoc(
            String origin, long treeSize, byte[] rootHash, byte[] revocArtifact) {
        byte[] base = checkpointBody(origin, treeSize, rootHash);
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(revocArtifact);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b & 0xff));
            byte[] ext = ("revoc:" + hex + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] combined = new byte[base.length + ext.length];
            System.arraycopy(base, 0, combined, 0, base.length);
            System.arraycopy(ext, 0, combined, base.length, ext.length);
            return combined;
        } catch (java.security.NoSuchAlgorithmException e) { throw new RuntimeException(e); }
    }

    public static byte[] checkpointBody(String origin, long treeSize, byte[] rootHash) {
        String b64 = Base64.getEncoder().encodeToString(rootHash);
        return (origin + "\n" + treeSize + "\n" + b64 + "\n").getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] cosignatureMessage(byte[] body, long timestamp) {
        byte[] header = ("cosignature/v1\ntime " + timestamp + "\n").getBytes(StandardCharsets.UTF_8);
        byte[] msg = new byte[header.length + body.length];
        System.arraycopy(header, 0, msg, 0, header.length);
        System.arraycopy(body, 0, msg, header.length, body.length);
        return msg;
    }

    /**
     * Derives the 4-byte key ID per c2sp.org/signed-note:
     *   key_id = SHA-256(name || 0x0A || 0x01 || raw_pubkey)[0:4]
     * where 0x0A is newline and 0x01 is the Ed25519 signature type identifier byte.
     */
    public static byte[] witnessKeyId(String name, byte[] pub) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(name.getBytes(StandardCharsets.UTF_8));
            sha.update(new byte[]{0x0a, 0x01}); // newline + Ed25519 type byte
            sha.update(pub);
            return Arrays.copyOf(sha.digest(), 4);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static long computeOriginId(String origin) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256")
                .digest(origin.getBytes(StandardCharsets.UTF_8));
            long id = 0;
            for (int i = 0; i < 8; i++) id = (id << 8) | (h[i] & 0xffL);
            return id;
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    // --- CBOR TBS encoding ---
    // Minimal deterministic CBOR: map with integer keys 2, 3, 4

    // Static version for test helpers (takes explicit schemaId).
    public static byte[] encodeTbsStatic(long issuedAt, long expiresAt, long schemaId, Map<String, Object> claims) {
        com.upokecenter.cbor.CBORObject map = com.upokecenter.cbor.CBORObject.NewOrderedMap();
        com.upokecenter.cbor.CBORObject times = com.upokecenter.cbor.CBORObject.NewArray();
        times.Add(issuedAt); times.Add(expiresAt);
        map.set(com.upokecenter.cbor.CBORObject.FromObject(2), times);
        map.set(com.upokecenter.cbor.CBORObject.FromObject(3), com.upokecenter.cbor.CBORObject.FromObject(schemaId));
        com.upokecenter.cbor.CBORObject claimsMap = com.upokecenter.cbor.CBORObject.NewOrderedMap();
        for (Map.Entry<String, Object> e : claims.entrySet()) {
            claimsMap.set(com.upokecenter.cbor.CBORObject.FromObject(e.getKey()),
                com.upokecenter.cbor.CBORObject.FromObject(e.getValue()));
        }
        map.set(com.upokecenter.cbor.CBORObject.FromObject(4), claimsMap);
        byte[] cborBytes = map.EncodeToBytes();
        byte[] tbs = new byte[1 + cborBytes.length];
        tbs[0] = ENTRY_TYPE_DATA;
        System.arraycopy(cborBytes, 0, tbs, 1, cborBytes.length);
        return tbs;
    }

    private byte[] encodeTbs(long issuedAt, long expiresAt, Map<String, Object> claims) {
        // entry_type_byte(0x01) || CBOR map {2: [issuedAt, expiresAt], 3: schemaId, 4: claims}
        // We use com.upokecenter.cbor for canonical encoding
        com.upokecenter.cbor.CBORObject map = com.upokecenter.cbor.CBORObject.NewOrderedMap();
        com.upokecenter.cbor.CBORObject times = com.upokecenter.cbor.CBORObject.NewArray();
        times.Add(issuedAt);
        times.Add(expiresAt);
        map.set(com.upokecenter.cbor.CBORObject.FromObject(2), times);
        map.set(com.upokecenter.cbor.CBORObject.FromObject(3),
            com.upokecenter.cbor.CBORObject.FromObject(schemaId));
        com.upokecenter.cbor.CBORObject claimsMap = com.upokecenter.cbor.CBORObject.NewOrderedMap();
        for (Map.Entry<String, Object> e : claims.entrySet()) {
            claimsMap.set(com.upokecenter.cbor.CBORObject.FromObject(e.getKey()),
                com.upokecenter.cbor.CBORObject.FromObject(e.getValue()));
        }
        map.set(com.upokecenter.cbor.CBORObject.FromObject(4), claimsMap);
        byte[] cborBytes = map.EncodeToBytes();
        byte[] tbs = new byte[1 + cborBytes.length];
        tbs[0] = ENTRY_TYPE_DATA;
        System.arraycopy(cborBytes, 0, tbs, 1, cborBytes.length);
        return tbs;
    }

    // --- Payload binary encoding ---

    private byte[] encodePayload(long entryIdx, long treeSize,
                                 List<byte[]> proofHashes, int innerCount, byte[] tbs, int mode) {
        byte[] originBytes = origin.getBytes(StandardCharsets.UTF_8);
        int sigAlg = signer.getAlg();
        int cap = 2 + 24 + 2 + originBytes.length + 2 + proofHashes.size() * 32 + 2 + tbs.length;
        ByteBuffer buf = ByteBuffer.allocate(cap + 64);

        buf.put((byte) 0x01); // version
        byte flags = (byte) (mode & 0x03);
        flags |= (byte) ((sigAlg & 0x07) << 2);
        flags |= (byte) 0x80; // self-describing
        buf.put(flags);
        buf.putLong(originId);
        buf.putLong(treeSize);
        buf.putLong(entryIdx);
        buf.putShort((short) originBytes.length);
        buf.put(originBytes);
        buf.put((byte) proofHashes.size());
        buf.put((byte) innerCount);
        for (byte[] h : proofHashes) buf.put(h);
        buf.putShort((short) tbs.length);
        buf.put(tbs);

        byte[] out = new byte[buf.position()];
        buf.flip();
        buf.get(out);
        return out;
    }
}

package com.peculiarventures.mtaqr.verifier;

import com.peculiarventures.mtaqr.issuer.Issuer;
import com.peculiarventures.mtaqr.signing.Signer;
import com.peculiarventures.mtaqr.signing.SignatureVerifier;
import com.peculiarventures.mtaqr.trust.TrustConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Collections;

/**
 * MTA-QR Verifier.
 *
 * <p>Verifies QR code payloads against a loaded {@link TrustConfig}. No key
 * custody required — verification is pure crypto.
 *
 * <p>Checkpoint responses are cached by (origin, treeSize). The cache is
 * thread-safe.
 *
 * <p><strong>Mode 2 limitation:</strong> For Mode 2 (online) payloads this
 * verifier does NOT verify Merkle inclusion. Mode 2 payloads carry no embedded
 * proof — inclusion is meant to be verified at scan time by fetching proof tiles
 * from a tile server. This SDK has no tile server. {@link #verify} on a Mode 2
 * payload validates everything else (checkpoint, witnesses, TBS, expiry) but
 * returns a result without cryptographic proof that the entry is in the log.
 * Use Mode 1, or implement tile fetching on top of this library, if you need
 * that guarantee.
 *
 * <p>Usage:
 * <pre>{@code
 * TrustConfig trust = TrustConfig.loadFile(Path.of("trust.json"));
 * Verifier verifier = Verifier.builder().trust(trust).build();
 * verifier.verify(payloadBytes)
 *         .thenAccept(ok -> System.out.println(ok.claims()));
 * }</pre>
 */
public final class Verifier {

    // --- result types ---

    /** Result of a successful verification. */
    /**
     * Result of a successful verification.
     * @param mode Payload mode: 1 = Mode 1 (inclusion proof verified),
     *             2 = Mode 2 (inclusion NOT verified — proof must be fetched
     *             from a tile server).
     */
    public record VerifyOk(
        int               mode,
        long              entryIndex,
        long              treeSize,
        String            origin,
        long              schemaId,
        long              issuedAt,
        long              expiresAt,
        Map<String, Object> claims
    ) {}

    /** Reason a verification failed. */
    public record VerifyFail(
        String failedStep,
        String reason
    ) {
        @Override public String toString() {
            return "verify: " + failedStep + ": " + reason;
        }
    }

    /** A single step in a verification trace. */
    public record Step(String name, boolean ok, String detail) {}

    /** Full trace result — always has steps; exactly one of ok/fail is non-null. */
    public record TraceResult(
        VerifyOk   ok,
        VerifyFail fail,
        List<Step> steps
    ) {
        public boolean isValid() { return ok != null; }
    }

    // --- builder ---

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private TrustConfig   trust;
        private HttpClient    httpClient;
        private NoteProvider  noteProvider;

        public Builder trust(TrustConfig v)       { trust = v; return this; }
        public Builder httpClient(HttpClient v)    { httpClient = v; return this; }
        /** Inject a note provider for testing — bypasses HTTP. */
        public Builder noteProvider(NoteProvider v){ noteProvider = v; return this; }

        public Verifier build() {
            Objects.requireNonNull(trust, "trust is required");
            return new Verifier(trust,
                httpClient != null ? httpClient : HttpClient.newHttpClient(),
                noteProvider);
        }
    }

    /** Provides checkpoint notes without HTTP. Used in tests. */
    @FunctionalInterface
    public interface NoteProvider {
        CompletableFuture<String> fetchNote(String url);
    }

    // --- internals ---

    private static final int BATCH_SIZE = 16;
    private static final int GRACE      = 600; // seconds

    private final TrustConfig  trust;
    private final HttpClient   httpClient;
    private final NoteProvider noteProvider;
    private static final int MAX_CACHE_ENTRIES = 1000;
    // Bounded insertion-order cache — evicts oldest entry when full.
    // Prevents memory exhaustion from payloads with rapidly incrementing tree_size.
    private final Map<String, byte[]> checkpointCache = Collections.synchronizedMap(
        new LinkedHashMap<>(MAX_CACHE_ENTRIES + 1, 0.75f, false) {
            @Override protected boolean removeEldestEntry(Map.Entry<String, byte[]> eldest) {
                return size() > MAX_CACHE_ENTRIES;
            }
        }
    );

    private Verifier(TrustConfig trust, HttpClient httpClient, NoteProvider noteProvider) {
        this.trust        = trust;
        this.httpClient   = httpClient;
        this.noteProvider = noteProvider;
    }

    /**
     * Verifies a QR code payload. Returns a future that resolves to
     * {@link VerifyOk} on success or fails exceptionally with a
     * {@link VerificationException} on failure.
     */
    public CompletableFuture<VerifyOk> verify(byte[] payload) {
        return verifyWithTrace(payload).thenApply(tr -> {
            if (tr.fail() != null) throw new VerificationException(tr.fail());
            return tr.ok();
        });
    }

    /**
     * Verifies a QR code payload and returns the full step trace.
     * The future always resolves successfully; check {@link TraceResult#isValid()}.
     */
    public CompletableFuture<TraceResult> verifyWithTrace(byte[] payloadBytes) {
        List<Step> steps = new ArrayList<>();

        // We accumulate steps synchronously and return a future only when
        // checkpoint fetching is needed.

        TraceResult syncFail = runSyncChecks(payloadBytes, steps);
        if (syncFail != null) return CompletableFuture.completedFuture(syncFail);

        // Parse again for async phase
        DecodedPayload p = decodePayload(payloadBytes);
        String cacheKey = trust.origin + ":" + p.treeSize;
        byte[] cached   = checkpointCache.get(cacheKey);

        CompletableFuture<byte[]> rootHashFuture;
        if (cached != null) {
            steps.add(new Step("checkpoint", true, "cache hit · tree_size=" + p.treeSize));
            rootHashFuture = CompletableFuture.completedFuture(cached);
        } else {
            steps.add(new Step("checkpoint", false, "cache miss · fetching " + trust.checkpointUrl));
            rootHashFuture = fetchAndVerifyCheckpoint(p.treeSize).thenApply(result -> {
                steps.add(new Step("checkpoint fetch", true,
                    "issuer sig ✓ · " + trust.witnessQuorum + "/" + trust.witnessQuorum +
                    " witnesses ✓ · tree_size=" + result.treeSize));
                checkpointCache.put(cacheKey, result.rootHash);
                return result.rootHash;
            });
        }

        return rootHashFuture.thenApply(rootHash ->
            runProofAndClaimsChecks(p, rootHash, steps)
        ).exceptionally(e -> {
            steps.add(new Step("checkpoint fetch", false, e.getMessage()));
            return new TraceResult(null, new VerifyFail("checkpoint fetch", e.getMessage()), steps);
        });
    }

    // --- sync checks (up to checkpoint resolution) ---

    private TraceResult runSyncChecks(byte[] payloadBytes, List<Step> steps) {
        DecodedPayload p;
        try {
            p = decodePayload(payloadBytes);
        } catch (Exception e) {
            return fail(steps, "decode payload", "malformed: " + e.getMessage());
        }
        steps.add(new Step("decode payload", true,
            "mode=" + p.mode + " sig_alg=" + p.sigAlg +
            " entry_index=" + p.entryIndex + " tree_size=" + p.treeSize));

        if (p.entryIndex == 0)
            return fail(steps, "entry index", "entry_index=0 is reserved for null_entry");
        steps.add(new Step("entry index", true, "entry_index=" + p.entryIndex + " valid"));

        if (p.originId != trust.originId)
            return fail(steps, "origin id", "payload origin_id does not match trust config");
        steps.add(new Step("origin id", true, "matches trust config: " + trust.origin));

        if (p.selfDescrib && p.origin != null && !p.origin.equals(trust.origin))
            return fail(steps, "origin consistency",
                "envelope origin " + p.origin + " != trust config " + trust.origin);
        if (p.selfDescrib) steps.add(new Step("origin consistency", true, "envelope matches trust config"));

        if (p.sigAlg != trust.sigAlg)
            return fail(steps, "algorithm binding",
                "payload sig_alg=" + p.sigAlg + " but trust config requires " + trust.sigAlg);
        steps.add(new Step("algorithm binding", true, "sig_alg=" + p.sigAlg + " matches trust config"));

        return null; // all sync checks passed
    }

    // --- proof + claims checks (after checkpoint) ---

    private TraceResult runProofAndClaimsChecks(DecodedPayload p, byte[] rootHash, List<Step> steps) {
        // Entry hash
        byte[] eHash = hashLeaf(p.tbs);
        steps.add(new Step("entry hash", true, "SHA-256(0x00 || tbs) computed"));

        // Merkle inclusion proof — behaviour depends on mode.
        if (p.mode == 2) {
            // Mode 2 (online): NO INCLUSION PROOF IS VERIFIED HERE.
            // The payload carries no proof hashes. A production scanner fetches
            // proof tiles from a tile server and verifies inclusion at scan time.
            // This SDK has no tile server — it only validates entry_index < tree_size.
            // Do not treat a Mode 2 VerifyResult as proof of inclusion.
            if (p.entryIndex >= p.treeSize)
                return fail(steps, "inclusion proof",
                    "mode=2: entry_index=" + p.entryIndex + " >= tree_size=" + p.treeSize);
            steps.add(new Step("inclusion proof", true,
                "mode=2 (online): entry_index=" + p.entryIndex +
                " < tree_size=" + p.treeSize + " · proof fetched at scan time"));
        } else {
            // Mode 1 (cached): two-phase tiled Merkle proof embedded.
            int globalIdx   = (int) p.entryIndex;
            int innerIdx    = globalIdx % BATCH_SIZE;
            int batchIdx    = globalIdx / BATCH_SIZE;
            int numBatches  = ((int) p.treeSize + BATCH_SIZE - 1) / BATCH_SIZE;
            int batchStart  = batchIdx * BATCH_SIZE;
            int thisBatchSz = Math.min(BATCH_SIZE, (int) p.treeSize - batchStart);

            List<byte[]> innerProof = p.proofHashes.subList(0, p.innerCount);
            List<byte[]> outerProof = p.proofHashes.subList(p.innerCount, p.proofHashes.size());

            byte[] batchRoot;
            try {
                batchRoot = Issuer.computeRootFromProof(eHash, innerIdx, thisBatchSz, innerProof);
            } catch (Exception e) {
                return fail(steps, "inclusion proof", "phase A (inner) failed: " + e.getMessage());
            }
            try {
                Issuer.verifyInclusion(batchRoot, batchIdx, numBatches, outerProof, rootHash);
            } catch (Exception e) {
                return fail(steps, "inclusion proof", "phase B (outer) failed: " + e.getMessage());
            }
            steps.add(new Step("inclusion proof", true,
                "phase A: " + innerProof.size() + " hashes → batch root ✓ · " +
                "phase B: " + outerProof.size() + " hashes → parent root ✓"));
        }

        // TBS decode
        if (p.tbs.length < 2 || p.tbs[0] != 0x01)
            return fail(steps, "tbs decode", "entry_type must be 0x01 (data_assertion)");
        steps.add(new Step("tbs decode", true, "entry_type=data_assertion"));

        // CBOR decode
        long issuedAt, expiresAt, schemaId;
        Map<String, Object> claims;
        try {
            com.upokecenter.cbor.CBORObject map =
                com.upokecenter.cbor.CBORObject.DecodeFromBytes(java.util.Arrays.copyOfRange(p.tbs, 1, p.tbs.length));
            com.upokecenter.cbor.CBORObject times = map.get(com.upokecenter.cbor.CBORObject.FromObject(2));
            issuedAt  = times.get(0).AsInt64();
            expiresAt = times.get(1).AsInt64();
            schemaId  = map.get(com.upokecenter.cbor.CBORObject.FromObject(3)).AsInt64();
            com.upokecenter.cbor.CBORObject rawClaims =
                map.get(com.upokecenter.cbor.CBORObject.FromObject(4));
            claims = new LinkedHashMap<>();
            for (com.upokecenter.cbor.CBORObject key : rawClaims.getKeys()) {
                com.upokecenter.cbor.CBORObject val = rawClaims.get(key);
                // Claim values may be strings or numbers — convert to String for the map.
                Object javaVal = val.isNumber() ? val.AsInt64Value() : val.AsString();
                claims.put(key.AsString(), javaVal);
            }
        } catch (Exception e) {
            return fail(steps, "cbor decode", e.getMessage());
        }
        steps.add(new Step("cbor decode", true,
            "schema_id=" + schemaId + " issued=" + issuedAt + " expires=" + expiresAt));

        // Revocation check — not yet implemented.
        // The spec defines revocation by index range but GET /revoked format
        // and authentication are not yet defined. Documented stub.
        steps.add(new Step("revocation check", true, "not implemented — no revocation list defined yet"));

        // Expiry
        long now = Instant.now().getEpochSecond();
        if (expiresAt + GRACE < now)
            return fail(steps, "expiry", "expired: expiry=" + expiresAt + " now=" + now);
        steps.add(new Step("expiry", true, "valid · " + (expiresAt - now) + "s remaining"));

        steps.add(new Step("complete", true,
            "all checks passed · entry_index=" + p.entryIndex + " · origin=" + trust.origin));

        return new TraceResult(
            new VerifyOk(p.mode, p.entryIndex, p.treeSize, trust.origin,
                schemaId, issuedAt, expiresAt, Collections.unmodifiableMap(claims)),
            null, steps);
    }

    // --- checkpoint fetch and note verification ---

    private record CheckpointResult(byte[] rootHash, long treeSize) {}

    private CompletableFuture<CheckpointResult> fetchAndVerifyCheckpoint(long requiredSize) {
        CompletableFuture<String> noteFuture;
        if (noteProvider != null) {
            noteFuture = noteProvider.fetchNote(trust.checkpointUrl);
        } else {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(trust.checkpointUrl))
                .GET().build();
            noteFuture = httpClient.sendAsync(req, HttpResponse.BodyHandlers.ofString())
                .thenApply(HttpResponse::body);
        }
        return noteFuture.thenApply(note -> verifyNote(note, requiredSize));
    }

    private CheckpointResult verifyNote(String note, long requiredSize) {
        int blankIdx = note.indexOf("\n\n");
        if (blankIdx < 0) throw new RuntimeException("note missing blank-line separator");
        byte[] body = (note.substring(0, blankIdx) + "\n").getBytes(StandardCharsets.UTF_8);
        String rest = note.substring(blankIdx + 2);

        // Parse body
        String[] lines = new String(body, StandardCharsets.UTF_8)
            .stripTrailing().split("\n");
        // Per c2sp.org/tlog-checkpoint: three mandatory lines plus optional extension lines.
        if (lines.length < 3) throw new RuntimeException("checkpoint body must have at least 3 lines, got " + lines.length);
        String bodyOrigin = lines[0];
        long treeSize     = Long.parseUnsignedLong(lines[1]);
        byte[] rootHash   = Base64.getDecoder().decode(lines[2]);

        if (!bodyOrigin.equals(trust.origin))
            throw new RuntimeException("origin mismatch: " + bodyOrigin);
        if (treeSize < requiredSize)
            throw new RuntimeException("tree_size " + treeSize + " < required " + requiredSize);

        List<String> sigLines = Arrays.stream(rest.split("\n"))
            .filter(l -> !l.isBlank()).toList();

        // Issuer sig — dispatch by key name, not byte length
        boolean issuerOk = false;
        for (String line : sigLines) {
            if (!line.contains(trust.issuerKeyName)) continue;
            byte[] raw = lastFieldBase64(line);
            if (raw == null || raw.length < 4) continue;
            // Per c2sp.org/signed-note: first 4 bytes are key_hash; rest is the sig.
            byte[] rawSig = Arrays.copyOfRange(raw, 4, raw.length);
            if (SignatureVerifier.verify(trust.sigAlg, body, rawSig, trust.issuerPubKey)) {
                issuerOk = true;
                break;
            }
        }
        if (!issuerOk) throw new RuntimeException("issuer signature not found or invalid");

        // Witness cosigs — always Ed25519, 72-byte timestamped_signature
        Set<String> verified = new HashSet<>();
        for (String line : sigLines) {
            byte[] raw = lastFieldBase64(line);
            // Per c2sp.org/signed-note + tlog-cosignature:
            //   4-byte key_hash || 8-byte timestamp || 64-byte Ed25519 sig = 76 bytes
            if (raw == null || raw.length != 76) continue;
            byte[] keyHash = Arrays.copyOfRange(raw, 0, 4);
            long ts = ByteBuffer.wrap(raw, 4, 8).getLong();
            byte[] wsig = Arrays.copyOfRange(raw, 12, 76);
            byte[] msg  = Issuer.cosignatureMessage(body, ts);
            for (TrustConfig.WitnessEntry w : trust.witnesses) {
                if (!Arrays.equals(keyHash, w.keyId())) continue;
                if (SignatureVerifier.verify(Signer.ALG_ED25519, msg, wsig, w.pubKey()))
                    verified.add(w.name());
            }
        }
        if (verified.size() < trust.witnessQuorum)
            throw new RuntimeException("witness quorum not met: " + verified.size() + "/" + trust.witnessQuorum);

        return new CheckpointResult(rootHash, treeSize);
    }

    // --- payload decoding ---

    private record DecodedPayload(
        int mode, int sigAlg, boolean selfDescrib,
        long originId, long treeSize, long entryIndex,
        String origin, List<byte[]> proofHashes, int innerCount, byte[] tbs
    ) {}

    private static DecodedPayload decodePayload(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        byte version = buf.get();
        if (version != 0x01) throw new IllegalArgumentException("unsupported version 0x" + Integer.toHexString(version));
        byte flags       = buf.get();
        int mode         = flags & 0x03;
        int sigAlg       = (flags >> 2) & 0x07;
        boolean selfDesc = (flags & 0x80) != 0;
        long originId    = buf.getLong();
        long treeSize    = buf.getLong();
        long entryIndex  = buf.getLong();
        String origin    = null;
        if (selfDesc) {
            int originLen = buf.getShort() & 0xffff;
            byte[] originBytes = new byte[originLen];
            buf.get(originBytes);
            origin = new String(originBytes, StandardCharsets.UTF_8);
        }
        int numProof   = buf.get() & 0xff;
        int innerCount = buf.get() & 0xff;
        List<byte[]> proofHashes = new ArrayList<>();
        for (int i = 0; i < numProof; i++) {
            byte[] h = new byte[32];
            buf.get(h);
            proofHashes.add(h);
        }
        int tbsLen = buf.getShort() & 0xffff;
        byte[] tbs = new byte[tbsLen];
        buf.get(tbs);
        if (buf.hasRemaining())
            throw new IllegalArgumentException(
                "payload: " + buf.remaining() + " trailing bytes after TBS");
        return new DecodedPayload(mode, sigAlg, selfDesc, originId, treeSize,
            entryIndex, origin, proofHashes, innerCount, tbs);
    }

    // --- helpers ---

    private static TraceResult fail(List<Step> steps, String step, String reason) {
        steps.add(new Step(step, false, reason));
        return new TraceResult(null, new VerifyFail(step, reason), steps);
    }

    private static byte[] hashLeaf(byte[] data) {
        try {
            java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
            sha.update((byte) 0x00);
            return sha.digest(data);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static byte[] lastFieldBase64(String line) {
        int idx = line.lastIndexOf(' ');
        if (idx < 0) return null;
        try { return Base64.getDecoder().decode(line.substring(idx + 1).trim()); }
        catch (Exception e) { return null; }
    }

    /** Thrown by {@link #verify} when verification fails. */
    public static final class VerificationException extends RuntimeException {
        private final VerifyFail fail;
        VerificationException(VerifyFail fail) {
            super(fail.toString());
            this.fail = fail;
        }
        public VerifyFail getFail() { return fail; }
    }
}

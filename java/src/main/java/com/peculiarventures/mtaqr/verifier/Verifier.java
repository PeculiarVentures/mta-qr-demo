package com.peculiarventures.mtaqr.verifier;

import com.peculiarventures.mtaqr.issuer.Issuer;
import com.peculiarventures.mtaqr.signing.Signer;
import com.peculiarventures.mtaqr.signing.SignatureVerifier;
import com.peculiarventures.mtaqr.cascade.Cascade;
import com.peculiarventures.mtaqr.trust.TrustConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
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
 * Verifier verifier = Verifier.builder().build().addAnchor(trust);
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
        private HttpClient          httpClient;
        private NoteProvider        noteProvider;
        private RevocationProvider  revocationProvider;

        public Builder httpClient(HttpClient v)    { httpClient = v; return this; }
        /** Inject a note provider for testing — bypasses HTTP. */
        public Builder noteProvider(NoteProvider v){ noteProvider = v; return this; }
        /** Inject a revocation provider for testing — bypasses HTTP. */
        public Builder revocationProvider(RevocationProvider v){ revocationProvider = v; return this; }

        /** Build an empty Verifier. Call {@link Verifier#addAnchor} to register issuers. */
        public Verifier build() {
            return new Verifier(
                httpClient != null ? httpClient :
                    HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(10))
                        .build(),
                noteProvider,
                revocationProvider);
        }
    }

    /** Provides checkpoint notes without HTTP. Used in tests. */
    @FunctionalInterface
    public interface NoteProvider {
        CompletableFuture<String> fetchNote(String url);
    }

    /** Provides revocation artifacts without HTTP. Used in tests. */
    @FunctionalInterface
    public interface RevocationProvider {
        CompletableFuture<String> fetchArtifact(String url);
    }

    // --- internals ---

    private static final int GRACE      = 600; // seconds

    private final ConcurrentHashMap<Long, TrustConfig> anchors = new ConcurrentHashMap<>();
    private final HttpClient           httpClient;
    private final NoteProvider         noteProvider;
    private final RevocationProvider   revocationProvider;
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

    private record CachedRevocation(Cascade cascade, long treeSize) {}
    private final Map<String, CachedRevocation> revocCache = new java.util.concurrent.ConcurrentHashMap<>();

    private Verifier(HttpClient httpClient,
                     NoteProvider noteProvider, RevocationProvider revocationProvider) {
        this.httpClient          = httpClient;
        this.noteProvider        = noteProvider;
        this.revocationProvider  = revocationProvider;
    }

    /**
     * Register a trusted issuer. Returns {@code this} for chaining.
     * @throws IllegalArgumentException on origin_id collision.
     */
    public Verifier addAnchor(TrustConfig trust) {
        TrustConfig existing = anchors.get(trust.originId);
        if (existing != null && !existing.origin.equals(trust.origin))
            throw new IllegalArgumentException(
                "origin_id collision: 0x" + Long.toHexString(trust.originId) +
                " shared by \"" + existing.origin + "\" and \"" + trust.origin + "\"");
        anchors.put(trust.originId, trust);
        return this;
    }

    /** All registered anchors. */
    public Collection<TrustConfig> anchors() { return anchors.values(); }

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
        TrustConfig trust = anchors.get(p.originId);
        if (trust == null)
            return CompletableFuture.completedFuture(
                fail(steps, "trust anchor", "no anchor for origin_id 0x" + Long.toHexString(p.originId)));
        final TrustConfig trustFinal = trust;
        String cacheKey = trust.origin + ":" + p.treeSize;
        byte[] cached   = checkpointCache.get(cacheKey);

        CompletableFuture<byte[]> rootHashFuture;
        if (cached != null) {
            steps.add(new Step("checkpoint", true, "cache hit · tree_size=" + p.treeSize));
            rootHashFuture = CompletableFuture.completedFuture(cached);
        } else {
            steps.add(new Step("checkpoint", false, "cache miss · fetching " + trustFinal.checkpointUrl));
            rootHashFuture = fetchAndVerifyCheckpoint(p.treeSize, trustFinal).thenApply(result -> {
                steps.add(new Step("checkpoint fetch", true,
                    "issuer sig ✓ · " + trustFinal.witnessQuorum + "/" + trustFinal.witnessQuorum +
                    " witnesses ✓ · tree_size=" + result.treeSize));
                checkpointCache.put(cacheKey, result.rootHash);
                return result.rootHash;
            });
        }

        return rootHashFuture.thenApply(rootHash ->
            runProofAndClaimsChecks(p, rootHash, steps, trustFinal)
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

        // Trust anchor lookup — multi-anchor routing by origin_id.
        TrustConfig trust = anchors.get(p.originId);
        if (trust == null)
            return fail(steps, "trust anchor",
                "no anchor for origin_id 0x" + Long.toHexString(p.originId) +
                " — call addAnchor() with the issuer trust config first");
        steps.add(new Step("trust anchor", true, "found: " + trust.origin));

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

    private TraceResult runProofAndClaimsChecks(DecodedPayload p, byte[] rootHash, List<Step> steps, TrustConfig trust) {
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
            int batchSize   = trust.batchSize > 0 ? trust.batchSize : 16;
            int globalIdx   = (int) p.entryIndex;
            int innerIdx    = globalIdx % batchSize;
            int batchIdx    = globalIdx / batchSize;
            int numBatches  = ((int) p.treeSize + batchSize - 1) / batchSize;
            int batchStart  = batchIdx * batchSize;
            int thisBatchSz = Math.min(batchSize, (int) p.treeSize - batchStart);

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

        // 10. Revocation check — SPEC.md §Revocation.
        try {
            String revocMsg = checkRevocation(p.entryIndex, p.treeSize, trust).get();
            steps.add(new Step("revocation check", true, revocMsg));
        } catch (Exception e) {
            String reason = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
            return fail(steps, "revocation check", reason);
        }

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

    // --- Revocation ---

    private static final long STALE_THRESHOLD = 32L;

    private CompletableFuture<String> checkRevocation(long entryIndex, long checkpointTreeSize, TrustConfig trust) {
        if (trust.revocationUrl == null || trust.revocationUrl.isEmpty())
            return CompletableFuture.completedFuture(
                "skipped — no revocation_url in trust config (fail-open)");

        CachedRevocation cached = revocCache.get(trust.origin);
        if (cached != null && checkpointTreeSize > cached.treeSize() &&
                checkpointTreeSize - cached.treeSize() > STALE_THRESHOLD)
            cached = null;

        final CachedRevocation fresh = cached;
        if (fresh == null) {
            return fetchRevocationArtifact(trust).thenApply(art -> {
                revocCache.put(trust.origin, art);
                return queryRevocation(art, entryIndex);
            });
        }
        return CompletableFuture.completedFuture(queryRevocation(fresh, entryIndex));
    }

    private String queryRevocation(CachedRevocation art, long entryIndex) {
        if (art.treeSize() <= entryIndex)
            throw new IllegalStateException("entry_index=" + entryIndex +
                " not covered by artifact (tree_size=" + art.treeSize() + ") — fail-closed");
        if (art.cascade().query(entryIndex))
            throw new IllegalStateException("entry_index=" + entryIndex + " is revoked");
        return "entry_index=" + entryIndex + " not revoked (cascade checked, artifact tree_size=" +
            art.treeSize() + ")";
    }

    private CompletableFuture<CachedRevocation> fetchRevocationArtifact(TrustConfig trust) {
        String url = trust.revocationUrl;
        final TrustConfig t = trust; // effectively final for lambda capture
        if (revocationProvider != null)
            return revocationProvider.fetchArtifact(url)
                .thenApply(body -> this.parseRevocationArtifact(body, t));
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(10))
            .GET().build();
        return httpClient.sendAsync(req, HttpResponse.BodyHandlers.ofString())
            .thenApply(resp -> {
                if (resp.statusCode() != 200)
                    throw new IllegalStateException("GET " + url + " → " + resp.statusCode());
                if (resp.body().length() > 64 * 1024)
                    throw new IllegalStateException("revocation artifact too large");
                return parseRevocationArtifact(resp.body(), trust);
            });
    }

    private CachedRevocation parseRevocationArtifact(String text, TrustConfig trust) {
        int sep = text.indexOf("\n\n");
        if (sep < 0) throw new IllegalArgumentException("revocation artifact: missing blank line");
        String bodyPart = text.substring(0, sep);
        String sigPart  = text.substring(sep + 2);
        String body     = bodyPart + "\n";

        String[] lines = bodyPart.split("\n", -1);
        if (lines.length != 4)
            throw new IllegalArgumentException("revocation artifact: expected 4 body lines, got " + lines.length);
        if (!lines[0].equals(trust.origin))
            throw new IllegalArgumentException("revocation artifact: origin mismatch");
        if (!"mta-qr-revocation-v1".equals(lines[2]))
            throw new IllegalArgumentException("revocation artifact: unknown type: " + lines[2]);
        long treeSize = Long.parseLong(lines[1]);
        if (treeSize <= 0)
            throw new IllegalArgumentException("revocation artifact: tree_size must be > 0");

        byte[] cascBytes = Base64.getDecoder().decode(lines[3]);
        Cascade cascade  = Cascade.decode(cascBytes);

        // Verify signature — algorithm binding per SPEC.md.
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        String keyPrefix = "\u2014 " + trust.issuerKeyName + " ";
        boolean sigOk = false;
        for (String line : sigPart.split("\n")) {
            if (!line.startsWith(keyPrefix)) continue;
            byte[] sigPayload = Base64.getDecoder().decode(line.substring(keyPrefix.length()).trim());
            if (sigPayload.length < 4) continue;
            byte[] sig = Arrays.copyOfRange(sigPayload, 4, sigPayload.length);
            if (SignatureVerifier.verify(trust.sigAlg, bodyBytes, sig, trust.issuerPubKey)) {
                sigOk = true; break;
            }
        }
        if (!sigOk) throw new IllegalArgumentException("revocation artifact: signature verification failed");

        return new CachedRevocation(cascade, treeSize);
    }

    private record CheckpointResult(byte[] rootHash, long treeSize) {}

    private CompletableFuture<CheckpointResult> fetchAndVerifyCheckpoint(long requiredSize, TrustConfig trust) {
        CompletableFuture<String> noteFuture;
        if (noteProvider != null) {
            noteFuture = noteProvider.fetchNote(trust.checkpointUrl);
        } else {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(trust.checkpointUrl))
                .GET().build();
            // Cap to 64 KB — a valid checkpoint is ~200 bytes.
            // ofByteArray() buffers the full response; we check length before use.
            noteFuture = httpClient.sendAsync(req, HttpResponse.BodyHandlers.ofByteArray())
                .thenApply(resp -> {
                    byte[] bytes = resp.body();
                    if (bytes.length > 64 * 1024)
                        throw new RuntimeException(
                            "checkpoint response too large (" + bytes.length + " bytes)");
                    return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                });
        }
        return noteFuture.thenApply(note -> verifyNote(note, requiredSize, trust));
    }

    private CheckpointResult verifyNote(String note, long requiredSize, TrustConfig trust) {
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

    // Public for vector tests.
    public record DecodedPayload(
        int mode, int sigAlg, boolean selfDescrib,
        long originId, long treeSize, long entryIndex,
        String origin, List<byte[]> proofHashes, int innerCount, byte[] tbs
    ) {}

    // Package-private test accessor.
    public static DecodedPayload decodePayloadForTest(byte[] data) { return decodePayload(data); }

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
        final int MAX_PROOF_HASHES = 64;
        if (numProof > MAX_PROOF_HASHES)
            throw new IllegalArgumentException(
                "payload: proof_count " + numProof + " exceeds maximum " + MAX_PROOF_HASHES);
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

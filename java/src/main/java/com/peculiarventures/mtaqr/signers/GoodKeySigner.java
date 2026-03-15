package com.peculiarventures.mtaqr.signers;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.peculiarventures.mtaqr.signing.Signer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

/**
 * GoodKeySigner delegates signing to GoodKey via the key operation workflow:
 *
 * <ol>
 *   <li>POST /key/{id}/operation — create sign operation</li>
 *   <li>GET  /key/{id}/operation/{opId} — poll until status = "ready"</li>
 *   <li>PATCH /key/{id}/operation/{opId}/finalize — submit hash, receive signature</li>
 * </ol>
 *
 * <p>Public key: {@code GET /key/{id}/public} returns SPKI PEM.
 *
 * <p>Keys are referenced by UUID. Algorithm is specified by GoodKey name
 * (e.g. {@code "ECDSA_P256_SHA256"}, {@code "ED_25519"}, {@code "ML_DSA_44"}).
 */
public final class GoodKeySigner implements Signer {

    /** Configuration for a GoodKey-backed signer. */
    public record GoodKeyConfig(
        /** GoodKey API root, e.g. {@code "https://api.goodkey.io"}. */
        String  baseUrl,
        /** UUID of the signing key in GoodKey. */
        String  keyId,
        /** Bearer token for API authentication. */
        String  apiKey,
        /**
         * GoodKey algorithm name, e.g. {@code "ECDSA_P256_SHA256"}, {@code "ED_25519"},
         * {@code "ML_DSA_44"}. Must be in the key's supported algorithms list.
         */
        String  algorithmName,
        /** How long to wait for human approval. Default: 5 minutes. */
        Duration approvalTimeout,
        /** How often to poll for operation status. Default: 3 seconds. */
        Duration pollInterval
    ) {
        public GoodKeyConfig(String baseUrl, String keyId, String apiKey, String algorithmName) {
            this(baseUrl, keyId, apiKey, algorithmName, Duration.ofMinutes(5), Duration.ofSeconds(3));
        }
    }

    // --- JSON response types ---

    private record KeyOperationResponse(
        @JsonProperty("id")     String id,
        @JsonProperty("status") String status, // "pending" | "ready" | "invalid"
        @JsonProperty("error")  String error
    ) {}

    private record KeyOperationFinalizeResponse(
        @JsonProperty("data") String data  // base64url encoded signature
    ) {}

    // --- fields ---

    private final GoodKeyConfig cfg;
    private final HttpClient    http;
    private final ObjectMapper  mapper;
    private final int           alg;
    private final String        keyName;
    private final byte[]        pubKey;

    private GoodKeySigner(GoodKeyConfig cfg, HttpClient http, ObjectMapper mapper,
                          int alg, String keyName, byte[] pubKey) {
        this.cfg     = cfg;
        this.http    = http;
        this.mapper  = mapper;
        this.alg     = alg;
        this.keyName = keyName;
        this.pubKey  = pubKey.clone();
    }

    /**
     * Creates a GoodKeySigner, fetching the public key from GoodKey.
     *
     * @param cfg configuration including key ID and algorithm name
     * @return a future that resolves to a ready-to-use GoodKeySigner
     */
    public static CompletableFuture<GoodKeySigner> create(GoodKeyConfig cfg) {
        return create(cfg, HttpClient.newHttpClient(), new ObjectMapper());
    }

    static CompletableFuture<GoodKeySigner> create(GoodKeyConfig cfg, HttpClient http, ObjectMapper mapper) {
        int alg = algNameToSigAlg(cfg.algorithmName());

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(cfg.baseUrl() + "/key/" + cfg.keyId() + "/public"))
            .header("Authorization", "Bearer " + cfg.apiKey())
            .GET().build();

        return http.sendAsync(req, HttpResponse.BodyHandlers.ofString())
            .thenApply(resp -> {
                if (resp.statusCode() != 200)
                    throw new RuntimeException("GoodKey: GET public key: " + resp.statusCode());
                try {
                    byte[] pubKey = spkiPemToRawPubKey(resp.body(), alg);
                    String b64    = Base64.getEncoder().encodeToString(pubKey);
                    String keyName = "goodkey-" + cfg.algorithmName() + "+" + b64;
                    return new GoodKeySigner(cfg, http, mapper, alg, keyName, pubKey);
                } catch (Exception e) {
                    throw new RuntimeException("GoodKey: parse public key: " + e.getMessage(), e);
                }
            });
    }

    @Override public int    getAlg()     { return alg; }
    @Override public String getKeyName() { return keyName; }

    @Override
    public CompletableFuture<byte[]> publicKeyBytes() {
        return CompletableFuture.completedFuture(pubKey.clone());
    }

    @Override
    public CompletableFuture<byte[]> sign(byte[] message) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                byte[] hash   = computeHash(message, cfg.algorithmName());
                String hashB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

                // 1. Create sign operation
                String createBody = mapper.writeValueAsString(
                    java.util.Map.of("type", "sign", "name", cfg.algorithmName()));
                KeyOperationResponse op = postJson(
                    cfg.baseUrl() + "/key/" + cfg.keyId() + "/operation",
                    createBody, KeyOperationResponse.class);

                // 2. Poll until ready
                Instant deadline = Instant.now().plus(cfg.approvalTimeout());
                while ("pending".equals(op.status())) {
                    if (Instant.now().isAfter(deadline))
                        throw new RuntimeException("GoodKey: operation " + op.id() + " timed out");
                    Thread.sleep(cfg.pollInterval().toMillis());
                    op = getJson(cfg.baseUrl() + "/key/" + cfg.keyId() + "/operation/" + op.id(),
                        KeyOperationResponse.class);
                }

                if (!"ready".equals(op.status()))
                    throw new RuntimeException("GoodKey: operation " + op.id() +
                        " ended with status " + op.status() + ": " + op.error());

                // 3. Finalize
                String finalBody = mapper.writeValueAsString(java.util.Map.of("data", hashB64));
                KeyOperationFinalizeResponse finalResp = patchJson(
                    cfg.baseUrl() + "/key/" + cfg.keyId() + "/operation/" + op.id() + "/finalize",
                    finalBody, KeyOperationFinalizeResponse.class);

                return Base64.getUrlDecoder().decode(finalResp.data());
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException("GoodKey: sign failed", e);
            }
        });
    }

    // --- HTTP helpers ---

    private <T> T postJson(String url, String body, Class<T> type) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Authorization", "Bearer " + cfg.apiKey())
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() > 299)
            throw new RuntimeException("HTTP " + resp.statusCode() + ": " + resp.body());
        return mapper.readValue(resp.body(), type);
    }

    private <T> T getJson(String url, Class<T> type) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Authorization", "Bearer " + cfg.apiKey())
            .GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() > 299)
            throw new RuntimeException("HTTP " + resp.statusCode() + ": " + resp.body());
        return mapper.readValue(resp.body(), type);
    }

    private <T> T patchJson(String url, String body, Class<T> type) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Authorization", "Bearer " + cfg.apiKey())
            .header("Content-Type", "application/json")
            .method("PATCH", HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() > 299)
            throw new RuntimeException("HTTP " + resp.statusCode() + ": " + resp.body());
        return mapper.readValue(resp.body(), type);
    }

    // --- algorithm mapping ---

    static int algNameToSigAlg(String name) {
        String upper = name.toUpperCase();
        if (upper.contains("ED_25519") || upper.equals("ED25519")) return ALG_ED25519;
        if (upper.contains("ECDSA_P256"))                          return ALG_ECDSA_P256;
        if (upper.contains("ML_DSA_44") || upper.contains("MLDSA44")) return ALG_ML_DSA_44;
        throw new IllegalArgumentException("GoodKey: cannot map algorithm \"" + name + "\" to MTA-QR sig_alg");
    }

    static byte[] computeHash(byte[] message, String algName) throws Exception {
        String upper = algName.toUpperCase();
        if (upper.contains("SHA256")) {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            return md.digest(message);
        }
        if (upper.contains("SHA384")) {
            var md = java.security.MessageDigest.getInstance("SHA-384");
            return md.digest(message);
        }
        if (upper.contains("SHA512")) {
            var md = java.security.MessageDigest.getInstance("SHA-512");
            return md.digest(message);
        }
        // Ed25519, ML-DSA: raw message
        return message;
    }

    static byte[] spkiPemToRawPubKey(String pem, int alg) throws Exception {
        String b64 = pem
            .replaceAll("-----BEGIN PUBLIC KEY-----", "")
            .replaceAll("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(b64);

        return switch (alg) {
            case ALG_ED25519    -> java.util.Arrays.copyOfRange(der, der.length - 32,  der.length);
            case ALG_ECDSA_P256 -> java.util.Arrays.copyOfRange(der, der.length - 65,  der.length);
            case ALG_ML_DSA_44  -> java.util.Arrays.copyOfRange(der, der.length - 1312, der.length);
            default -> throw new IllegalArgumentException("unsupported alg " + alg);
        };
    }
}

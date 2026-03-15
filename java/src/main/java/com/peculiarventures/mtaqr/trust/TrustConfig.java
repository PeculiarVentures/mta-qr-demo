package com.peculiarventures.mtaqr.trust;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

/**
 * Trust configuration for MTA-QR verifiers.
 *
 * <p>Loaded from a JSON file at startup. The format matches the issuer's
 * {@code /trust-config} endpoint response, so configs can be captured from a
 * running issuer and deployed to verifiers.
 */
public final class TrustConfig {

    /** A single trusted witness key. */
    public record WitnessEntry(
        String name,
        byte[] keyId,   // 4 bytes
        byte[] pubKey
    ) {}

    public final String origin;
    public final long   originId;       // first 8 bytes of SHA-256(origin) as unsigned long
    public final String issuerKeyName;
    public final byte[] issuerPubKey;
    public final int    sigAlg;
    public final int    witnessQuorum;
    public final List<WitnessEntry> witnesses;
    public final String checkpointUrl;

    private TrustConfig(
            String origin, long originId, String issuerKeyName,
            byte[] issuerPubKey, int sigAlg, int witnessQuorum,
            List<WitnessEntry> witnesses, String checkpointUrl) {
        this.origin        = origin;
        this.originId      = originId;
        this.issuerKeyName = issuerKeyName;
        this.issuerPubKey  = issuerPubKey;
        this.sigAlg        = sigAlg;
        this.witnessQuorum = witnessQuorum;
        this.witnesses     = List.copyOf(witnesses);
        this.checkpointUrl = checkpointUrl;
    }

    // --- raw JSON shape ---

    private record WitnessJSON(
        @JsonProperty("name")        String name,
        @JsonProperty("key_id_hex")  String keyIdHex,
        @JsonProperty("pub_key_hex") String pubKeyHex
    ) {}

    private record TrustConfigJSON(
        @JsonProperty("origin")            String origin,
        @JsonProperty("origin_id")         String originId,
        @JsonProperty("issuer_key_name")   String issuerKeyName,
        @JsonProperty("issuer_pub_key_hex") String issuerPubKeyHex,
        @JsonProperty("sig_alg")           int    sigAlg,
        @JsonProperty("witness_quorum")    int    witnessQuorum,
        @JsonProperty("checkpoint_url")    String checkpointUrl,
        @JsonProperty("witnesses")         List<WitnessJSON> witnesses
    ) {}

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    /**
     * Loads a TrustConfig from a JSON file.
     *
     * @param path path to the trust config JSON file
     * @return the parsed TrustConfig
     * @throws IOException if the file cannot be read or parsed
     */
    public static TrustConfig loadFile(Path path) throws IOException {
        return parse(Files.readAllBytes(path));
    }

    /**
     * Parses a TrustConfig from JSON bytes.
     *
     * @param json raw JSON bytes
     * @return the parsed TrustConfig
     * @throws IOException if the JSON is invalid
     */
    public static TrustConfig parse(byte[] json) throws IOException {
        TrustConfigJSON raw = MAPPER.readValue(json, TrustConfigJSON.class);
        return fromJSON(raw);
    }

    /**
     * Parses a TrustConfig from a JSON string.
     */
    public static TrustConfig parse(String json) throws IOException {
        return parse(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static TrustConfig fromJSON(TrustConfigJSON raw) {
        long originId = Long.parseUnsignedLong(raw.originId(), 16);
        byte[] issuerPubKey = HEX.parseHex(raw.issuerPubKeyHex());

        List<WitnessEntry> witnesses = raw.witnesses().stream().map(w -> {
            byte[] kid = HEX.parseHex(w.keyIdHex());
            byte[] pub = HEX.parseHex(w.pubKeyHex());
            return new WitnessEntry(w.name(), kid, pub);
        }).toList();

        int witnessQuorum = raw.witnessQuorum();
        if (witnessQuorum < 1)
            throw new IllegalArgumentException(
                "trust config: witness_quorum must be >= 1, got " + witnessQuorum);
        if (witnessQuorum > witnesses.size())
            throw new IllegalArgumentException(
                "trust config: witness_quorum (" + witnessQuorum +
                ") exceeds witness count (" + witnesses.size() + ")");

        return new TrustConfig(
            raw.origin(), originId, raw.issuerKeyName(),
            issuerPubKey, raw.sigAlg(), witnessQuorum,
            witnesses, raw.checkpointUrl()
        );
    }
}

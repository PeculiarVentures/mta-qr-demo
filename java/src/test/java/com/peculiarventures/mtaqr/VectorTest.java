package com.peculiarventures.mtaqr;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.peculiarventures.mtaqr.issuer.Issuer;
import com.peculiarventures.mtaqr.signers.LocalSigner;
import com.peculiarventures.mtaqr.cascade.Cascade;
import com.peculiarventures.mtaqr.signing.SignatureVerifier;
import com.peculiarventures.mtaqr.verifier.Verifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Canonical test vector suite for the Java SDK.
 *
 * Loads test-vectors/vectors.json and exercises every layer independently:
 * checkpoint body serialization, entry hash, CBOR encoding, Merkle tree,
 * signing (Ed25519 / ECDSA P-256 / ML-DSA-44), and four parser rejection cases.
 *
 * A failure here isolates a layer disagreement with the Go/TypeScript/Rust
 * implementations before the interop matrix catches it.
 */
class VectorTest {

    private static Map<String, JsonNode> vectors;

    @BeforeAll
    static void loadVectors() throws Exception {
        // vectors.json is at repo-root/test-vectors/vectors.json.
        // Maven runs tests from the java/ directory, so go up two levels.
        Path path = Path.of("../test-vectors/vectors.json");
        byte[] data = Files.readAllBytes(path);
        JsonNode root = new ObjectMapper().readTree(data);
        vectors = new HashMap<>();
        for (JsonNode v : root.get("vectors")) {
            vectors.put(v.get("id").asText(), v);
        }
    }

    private static byte[] fromHex(String hex) { return HexFormat.of().parseHex(hex); }
    private static String hex(byte[] b) { return HexFormat.of().formatHex(b); }

    // --- Vector: checkpoint-body-v1 ---

    @Test
    void testCheckpointBody() {
        JsonNode v = vectors.get("checkpoint-body-v1");
        String origin    = v.get("input").get("origin").asText();
        long   treeSize  = v.get("input").get("tree_size").asLong();
        byte[] rootHash  = fromHex(v.get("input").get("root_hash_hex").asText());

        byte[] body = Issuer.checkpointBody(origin, treeSize, rootHash);

        assertEquals(v.get("expected").get("byte_length").asInt(), body.length, "byte_length");
        assertEquals(v.get("expected").get("checkpoint_body_hex").asText(), hex(body), "hex");
        assertEquals('\n', (char) body[body.length - 1], "must end with \\n");
    }

    // --- Vector: null-entry-hash ---

    @Test
    void testNullEntryHash() {
        JsonNode v = vectors.get("null-entry-hash");
        byte[] tbs = fromHex(v.get("input").get("tbs_hex").asText());
        byte[] got = Issuer.hashLeafForTest(tbs);
        assertEquals(v.get("expected").get("entry_hash_hex").asText(), hex(got), "null entry hash");
    }

    // --- Vector: data-assertion-cbor ---

    @Test
    void testDataAssertionCbor() {
        JsonNode v = vectors.get("data-assertion-cbor");
        JsonNode inp = v.get("input");

        long issuanceTime = inp.get("issuance_time").asLong();
        long expiryTime   = inp.get("expiry_time").asLong();
        long schemaId     = inp.get("schema_id").asLong();

        // Build claims map sorted by key (canonical ordering).
        TreeMap<String, Object> claims = new TreeMap<>();
        inp.get("claims").fields().forEachRemaining(e -> claims.put(e.getKey(), e.getValue().asText()));

        byte[] tbs = Issuer.encodeTbsForTest(issuanceTime, expiryTime, schemaId, claims);

        assertEquals(v.get("expected").get("tbs_hex").asText(), hex(tbs), "TBS hex");

        byte[] entryHash = Issuer.entryHashForTest(tbs);
        assertEquals(v.get("expected").get("entry_hash_hex").asText(), hex(entryHash), "entry hash");
    }

    // --- Vector: merkle-four-entry-tree ---

    @Test
    void testMerkleFourEntryTree() throws Exception {
        JsonNode v = vectors.get("merkle-four-entry-tree");
        JsonNode leavesInput = v.get("input").get("leaves");

        List<byte[]> leaves = new ArrayList<>();
        for (JsonNode l : leavesInput) {
            leaves.add(Issuer.hashLeafForTest(fromHex(l.get("data_hex").asText())));
        }

        // Check leaf hashes.
        JsonNode expectedLeaves = v.get("expected").get("leaf_hashes");
        for (int i = 0; i < leaves.size(); i++) {
            assertEquals(expectedLeaves.get(i).asText(), hex(leaves.get(i)), "leaf[" + i + "]");
        }

        // Check internal nodes.
        JsonNode nodes = v.get("expected").get("internal_nodes");
        byte[] h01 = Issuer.hashNodeForTest(leaves.get(0), leaves.get(1));
        byte[] h23 = Issuer.hashNodeForTest(leaves.get(2), leaves.get(3));
        assertEquals(nodes.get("H01").asText(), hex(h01), "H01");
        assertEquals(nodes.get("H23").asText(), hex(h23), "H23");

        // Check root.
        byte[] root = Issuer.merkleRoot(leaves);
        assertEquals(v.get("expected").get("root").asText(), hex(root), "root");

        // Check inclusion proof for index 2.
        JsonNode ip = v.get("expected").get("inclusion_proof_index2");
        List<byte[]> proof = Issuer.inclusionProof(leaves, 2, 4);
        JsonNode expProof = ip.get("proof");
        assertEquals(expProof.size(), proof.size(), "proof length");
        for (int i = 0; i < proof.size(); i++) {
            assertEquals(expProof.get(i).asText(), hex(proof.get(i)), "proof[" + i + "]");
        }

        // Verify round-trip.
        assertDoesNotThrow(() -> Issuer.verifyInclusion(leaves.get(2), 2, 4, proof, root),
                "inclusion proof round-trip");
    }

    // --- Vector: signing-ed25519 ---

    @Test
    void testSigningEd25519() throws Exception {
        JsonNode v = vectors.get("signing-ed25519");
        byte[] seed    = fromHex(v.get("input").get("private_seed_hex").asText());
        byte[] message = fromHex(v.get("input").get("message_hex").asText());

        LocalSigner signer = LocalSigner.ed25519(seed);
        byte[] pubKey = signer.publicKeyBytes().get();
        assertEquals(v.get("expected").get("public_key_hex").asText(), hex(pubKey), "Ed25519 pubkey");

        byte[] sig = signer.sign(message).get();
        assertEquals(v.get("expected").get("signature_hex").asText(), hex(sig), "Ed25519 sig deterministic");

        assertTrue(SignatureVerifier.verify(6, message, sig, pubKey), "Ed25519 verify");
    }

    // --- Vector: signing-ecdsa-p256 ---

    @Test
    void testSigningEcdsaP256() throws Exception {
        JsonNode v = vectors.get("signing-ecdsa-p256");
        byte[] scalar  = fromHex(v.get("input").get("scalar_hex").asText());
        byte[] message = fromHex(v.get("input").get("message_hex").asText());

        LocalSigner signer = LocalSigner.ecdsaP256(scalar);
        byte[] pubKey = signer.publicKeyBytes().get();
        assertEquals(v.get("expected").get("public_key_hex").asText(), hex(pubKey), "ECDSA P-256 pubkey");

        byte[] preSig = fromHex(v.get("input").get("pre_recorded_sig").asText());
        assertTrue(SignatureVerifier.verify(4, message, preSig, pubKey), "ECDSA P-256 verify pre-recorded");

        byte[] sig = signer.sign(message).get();
        assertTrue(SignatureVerifier.verify(4, message, sig, pubKey), "ECDSA P-256 round-trip");
    }

    // --- Vector: signing-mldsa44 ---

    @Test
    void testSigningMlDsa44() throws Exception {
        JsonNode v = vectors.get("signing-mldsa44");
        byte[] seed    = fromHex(v.get("input").get("seed_hex").asText());
        byte[] message = fromHex(v.get("input").get("message_hex").asText());

        LocalSigner signer = LocalSigner.mlDsa44(seed);
        byte[] pubKey = signer.publicKeyBytes().get();
        assertEquals(v.get("expected").get("public_key_hex").asText(), hex(pubKey), "ML-DSA-44 pubkey");

        byte[] preSig = fromHex(v.get("input").get("pre_recorded_sig").asText());
        assertTrue(SignatureVerifier.verify(1, message, preSig, pubKey), "ML-DSA-44 verify pre-recorded");

        byte[] sig = signer.sign(message).get();
        assertTrue(SignatureVerifier.verify(1, message, sig, pubKey), "ML-DSA-44 round-trip");
    }

    // --- Vector: reject-truncated-payload ---

    @Test
    void testRejectTruncatedPayload() {
        JsonNode v = vectors.get("reject-truncated-payload");
        byte[] data = fromHex(v.get("input").get("payload_hex").asText());
        // Truncated payload must throw at parse time.
        assertThrows(Exception.class,
                () -> Verifier.decodePayloadForTest(data),
                "truncated payload must fail decode");
    }

    // --- Vector: reject-entry-index-zero ---

    @Test
    void testRejectEntryIndexZero() {
        JsonNode v = vectors.get("reject-entry-index-zero");
        byte[] data = fromHex(v.get("input").get("payload_hex").asText());
        // entry_index=0 is structurally valid — parser succeeds, verifier rejects.
        Verifier.DecodedPayload p = Verifier.decodePayloadForTest(data);
        assertEquals(0L, p.entryIndex(), "entry_index must be 0 in this vector");
    }

    // --- Vector: reject-tampered-tbs ---

    @Test
    void testRejectTamperedTbs() {
        JsonNode v = vectors.get("reject-tampered-tbs");
        byte[] data = fromHex(v.get("input").get("payload_hex").asText());
        byte[] root = fromHex(v.get("input").get("root_hex").asText());

        Verifier.DecodedPayload p = Verifier.decodePayloadForTest(data);
        byte[] entryHash = Issuer.entryHashForTest(p.tbs());

        // Inclusion proof must fail — tampered TBS produces wrong entry hash.
        assertThrows(Exception.class, () ->
                Issuer.verifyInclusion(entryHash, (int) p.entryIndex(), (int) p.treeSize(),
                        p.proofHashes(), root),
                "tampered TBS must fail inclusion proof");
    }

    // --- Vector: reject-wrong-sig-alg ---

    @Test
    void testRejectWrongSigAlg() {
        JsonNode v = vectors.get("reject-wrong-sig-alg");
        byte[] data = fromHex(v.get("input").get("payload_hex").asText());
        int trustSigAlg = v.get("input").get("trust_config").get("sig_alg").asInt();

        Verifier.DecodedPayload p = Verifier.decodePayloadForTest(data);

        // Payload claims ECDSA P-256 (4), trust config expects Ed25519 (6).
        assertNotEquals(trustSigAlg, p.sigAlg(), "sig_alg mismatch must be detectable");
        assertEquals(4, p.sigAlg(), "payload claims ECDSA P-256 (4)");
        assertEquals(6, trustSigAlg, "trust config expects Ed25519 (6)");
    }
    // --- revocation-cascade-r1 ---

    @Test
    void testCascadeVectorR1() throws Exception {
        JsonNode v = vectors.get("revocation-cascade-r1");
        JsonNode inp = v.get("input");
        JsonNode exp = v.get("expected");

        long[] revoked = toArray(inp.get("revoked_indices"));
        long[] valid   = toArray(inp.get("valid_indices"));

        Cascade c = Cascade.build(revoked, valid);
        assertEquals(exp.get("cascade_hex").asText(), hex(c.encode()), "R1 cascade_hex");

        Cascade c2 = Cascade.decode(fromHex(exp.get("cascade_hex").asText()));
        for (JsonNode q : exp.get("queries")) {
            long idx = q.get("index").asLong();
            boolean want = q.get("revoked").asBoolean();
            assertEquals(want, c.query(idx),  "build.query(" + idx + ")");
            assertEquals(want, c2.query(idx), "decode.query(" + idx + ")");
        }
    }

    // --- revocation-cascade-r2 ---

    @Test
    void testCascadeVectorR2() throws Exception {
        JsonNode v = vectors.get("revocation-cascade-r2");
        JsonNode exp = v.get("expected");

        Cascade c = Cascade.build(new long[0], new long[0]);
        assertEquals(exp.get("cascade_hex").asText(), hex(c.encode()), "R2 cascade_hex");

        for (JsonNode q : exp.get("queries")) {
            assertFalse(c.query(q.get("index").asLong()), "R2 must never revoke");
        }
    }

    // --- checkpoint-body-with-revoc ---

    @Test
    void testCheckpointBodyWithRevoc() throws Exception {
        JsonNode v = vectors.get("checkpoint-body-with-revoc");
        assertNotNull(v, "vector checkpoint-body-with-revoc not found");
        JsonNode inp = v.get("input");
        JsonNode exp = v.get("expected");

        byte[] rootHash = fromHex(inp.get("root_hash_hex").asText());
        byte[] artifact = fromHex(inp.get("revoc_artifact_hex").asText());
        byte[] body = Issuer.checkpointBodyWithRevoc(
            inp.get("origin").asText(), inp.get("tree_size").asLong(), rootHash, artifact);

        assertEquals(exp.get("body_hex").asText(), hex(body), "body_hex");
        assertEquals(exp.get("byte_length").asInt(), body.length, "byte_length");

        String bodyStr = new String(body, java.nio.charset.StandardCharsets.UTF_8);
        String[] lines = bodyStr.stripTrailing().split("\n");
        assertTrue(lines.length >= 4, "expected 4+ lines, got " + lines.length);
        assertEquals(exp.get("fourth_line").asText(), lines[3], "fourth_line");
    }

    // --- mode2-payload-encode ---

    @Test
    void testMode2PayloadEncode() throws Exception {
        JsonNode v = vectors.get("mode2-payload-encode");
        assertNotNull(v, "vector mode2-payload-encode not found");
        JsonNode inp = v.get("input");
        JsonNode exp = v.get("expected");

        byte[] payloadBytes = fromHex(exp.get("payload_hex").asText());
        var decoded = com.peculiarventures.mtaqr.verifier.Verifier.decodePayloadForTest(payloadBytes);

        assertEquals(2, decoded.mode(), "mode");
        assertEquals(exp.get("proof_count").asInt(), decoded.proofHashes().size(), "proof_count");
        assertEquals(inp.get("tree_size").asLong(), decoded.treeSize(), "tree_size");
        assertEquals(inp.get("entry_index").asLong(), decoded.entryIndex(), "entry_index");
    }

    // --- revoc-checkpoint-commitment ---

    @Test
    void testRevocCheckpointCommitment() throws Exception {
        JsonNode v = vectors.get("revoc-checkpoint-commitment");
        assertNotNull(v, "vector revoc-checkpoint-commitment not found");
        JsonNode inp = v.get("input");
        JsonNode exp = v.get("expected");

        byte[] rootHash  = fromHex(inp.get("root_hash_hex").asText());
        byte[] artifact  = fromHex(inp.get("revoc_artifact_hex").asText());
        byte[] seed      = fromHex(inp.get("private_seed_hex").asText());
        var signer = LocalSigner.ed25519(seed);

        byte[] plain     = Issuer.checkpointBody(inp.get("origin").asText(),
                               inp.get("tree_size").asLong(), rootHash);
        byte[] withRevoc = Issuer.checkpointBodyWithRevoc(inp.get("origin").asText(),
                               inp.get("tree_size").asLong(), rootHash, artifact);

        assertEquals(exp.get("plain_body_hex").asText(),      hex(plain),     "plain_body_hex");
        assertEquals(exp.get("body_with_revoc_hex").asText(), hex(withRevoc), "body_with_revoc_hex");

        byte[] plainSig = signer.sign(plain).get();
        byte[] revocSig = signer.sign(withRevoc).get();

        assertEquals(exp.get("plain_sig_hex").asText(), hex(plainSig), "plain_sig_hex");
        assertEquals(exp.get("revoc_sig_hex").asText(), hex(revocSig), "revoc_sig_hex");
        assertEquals(exp.get("sigs_differ").asBoolean(),
            !java.util.Arrays.equals(plainSig, revocSig), "sigs_differ");
    }

    // --- reject-revoc-hash-mismatch ---

    @Test
    void testRejectRevocHashMismatch() throws Exception {
        JsonNode v = vectors.get("reject-revoc-hash-mismatch");
        assertNotNull(v, "vector reject-revoc-hash-mismatch not found");
        JsonNode inp = v.get("input");
        JsonNode exp = v.get("expected");

        byte[] served = fromHex(inp.get("served_revoc_artifact_hex").asText());
        java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
        String servedHash = hex(sha.digest(served));
        boolean hashesMatch = servedHash.equals(inp.get("committed_hash_hex").asText());
        assertEquals(exp.get("hashes_match").asBoolean(), hashesMatch, "hashes_match");
    }


    private static long[] toArray(JsonNode arr) {
        long[] a = new long[arr.size()];
        for (int i = 0; i < arr.size(); i++) a[i] = arr.get(i).asLong();
        return a;
    }

}

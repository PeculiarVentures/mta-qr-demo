/**
 * Revocation behavioral tests for the MTA-QR TypeScript SDK.
 *
 * Tests the full issue → revoke → verify flow using the SDK Issuer and Verifier
 * directly, with RevocationProvider and NoteProvider injection to avoid HTTP.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Issuer } from "../issuer.js";
import { Verifier } from "../verifier.js";
import { parseTrustConfig } from "../trust.js";
import { localEd25519 } from "../signers/local.js";

const SEED = Uint8Array.from(Buffer.from(
  "275be85b9aa3357c647700aca548ab3c1b6d917a51f56515956004af2243d75f", "hex"));

/** Build an Issuer+Verifier pair wired via in-process providers. */
async function makeFixture(label: string) {
  const signer = localEd25519(SEED);
  const issuer = new Issuer(
    { origin: `test.revoc/${label}/v1`, schemaId: 1 },
    signer
  );
  await issuer.init();

  function makeVerifier() {
    const trust = parseTrustConfig(
      issuer.trustConfigJson("http://localhost:0/checkpoint")
    );
    return new Verifier(
      () => issuer.checkpointNote(),
      () => issuer.revocationArtifact() ?? ""
    ).addAnchor(trust);
  }

  return { issuer, makeVerifier };
}

describe("revocation", () => {

  it("un-revoked entry verifies", async () => {
    const { issuer, makeVerifier } = await makeFixture("not-revoked");
    const qr = await issuer.issue({ subject: "alice" }, 3600);
    const v  = makeVerifier();
    const result = await v.verify(new Uint8Array(qr.payload));
    assert.equal(result.valid, true);
    assert.equal(result.entryIndex, qr.entryIndex);
  });

  it("revoked entry is rejected", async () => {
    const { issuer, makeVerifier } = await makeFixture("revoked");
    const qr = await issuer.issue({ subject: "bob" }, 3600);
    await issuer.revoke(BigInt(qr.entryIndex));
    const v  = makeVerifier();
    const result = await v.verify(new Uint8Array(qr.payload));
    assert.equal(result.valid, false);
    assert.ok(
      (result as { failedStep?: string }).failedStep?.includes("revocation") ||
      String(result).includes("revoked"),
      `expected revocation failure, got: ${JSON.stringify(result)}`
    );
  });

  it("revocation does not affect other entries", async () => {
    const { issuer } = await makeFixture("selective");
    // Capture checkpoint note immediately after each issue — the embedded Merkle proof
    // is valid only against the checkpoint that existed at issue time.
    const qr1 = await issuer.issue({ subject: "alice" }, 3600);
    const note1 = issuer.checkpointNote();
    const qr2 = await issuer.issue({ subject: "bob"   }, 3600);
    const note2 = issuer.checkpointNote();
    const qr3 = await issuer.issue({ subject: "carol" }, 3600);
    const note3 = issuer.checkpointNote();
    await issuer.revoke(BigInt(qr2.entryIndex));

    const trust = parseTrustConfig(issuer.trustConfigJson("http://localhost:0/checkpoint"));
    const revArt = () => issuer.revocationArtifact() ?? "";

    const r1 = await new Verifier(() => note1, revArt).addAnchor(trust).verify(new Uint8Array(qr1.payload));
    assert.equal(r1.valid, true, "alice must still verify");

    const r3 = await new Verifier(() => note3, revArt).addAnchor(trust).verify(new Uint8Array(qr3.payload));
    assert.equal(r3.valid, true, "carol must still verify");

    const r2 = await new Verifier(() => note2, revArt).addAnchor(trust).verify(new Uint8Array(qr2.payload));
    assert.equal(r2.valid, false, "bob must be rejected");
  });

  it("multiple revocations", async () => {
    const { issuer } = await makeFixture("multi");
    const issued: Array<{ qr: Awaited<ReturnType<typeof issuer.issue>>, note: string }> = [];
    for (let i = 0; i < 4; i++) {
      const qr = await issuer.issue({ i }, 3600);
      issued.push({ qr, note: issuer.checkpointNote() });
    }
    await issuer.revoke(BigInt(issued[1].qr.entryIndex));
    await issuer.revoke(BigInt(issued[3].qr.entryIndex));

    const trust = parseTrustConfig(issuer.trustConfigJson("http://localhost:0/checkpoint"));
    const revArt = () => issuer.revocationArtifact() ?? "";

    for (const [i, { qr, note }] of issued.entries()) {
      const r = await new Verifier(() => note, revArt).addAnchor(trust).verify(new Uint8Array(qr.payload));
      const wantRevoked = (i === 1 || i === 3);
      assert.equal(r.valid, !wantRevoked, `issued[${i}] valid=${r.valid} want ${!wantRevoked}`);
    }
  });

  it("revoke(0n) throws", async () => {
    const { issuer } = await makeFixture("zero");
    await assert.rejects(() => issuer.revoke(0n), /null entry/);
  });

  it("revoke unissued index throws", async () => {
    const { issuer } = await makeFixture("unissued");
    await assert.rejects(() => issuer.revoke(999n), /not yet issued/);
  });

});

// --- Mode 0 rejection ---

describe("mode 0 rejection", () => {
  it("rejects mode=0 payload with clear error", async () => {
    const { issuer } = await makeFixture("mode0-reject");
    const trust = parseTrustConfig(issuer.trustConfigJson("http://localhost:0/checkpoint"));
    const v = new Verifier(() => issuer.checkpointNote()).addAnchor(trust);

    // Build a well-formed mode=0 payload using the SDK encoder.
    // Mode 0 embeds the checkpoint; this verifier does not implement it.
    const { encodePayload, MODE_EMBEDDED } = await import("../payload.js");
    const { encodeTbs } = await import("../cbor.js");
    const now = Math.floor(Date.now() / 1000);
    const tbs = encodeTbs({ times: [now, now + 3600], schemaId: 1, claims: {} });
    const rootHash = new Uint8Array(32); // placeholder
    const issuerSig = new Uint8Array(64); // placeholder
    const payload = encodePayload({
      version: 1,
      mode: MODE_EMBEDDED,
      sigAlg: 6, // Ed25519
      dualSig: false,
      selfDescrib: false,
      originId: trust.originId,
      treeSize: 2n,
      entryIndex: 1n,
      proofHashes: [],
      innerProofCount: 0,
      tbs,
      rootHash,
      issuerSig,
      cosigs: [],
    });

    const result = await v.verify(payload);
    assert.equal(result.valid, false, "mode=0 must be rejected");
    const msg = JSON.stringify(result);
    // Mode 0 is now implemented — a crafted payload with placeholder
    // signatures should fail at embedded checkpoint verification.
    assert.ok(
      msg.includes("embedded checkpoint") || msg.includes("issuer signature"),
      `expected embedded checkpoint failure, got: ${msg}`
    );
  });
});

// --- Mode 0 round-trip ---

describe("mode 0", () => {
  it("issues and verifies a Mode 0 payload without network access", async () => {
    const signer = localEd25519(SEED);
    const issuer = new Issuer(
      { origin: "test.mode0/v1", schemaId: 1, mode: 0 },
      signer,
    );
    await issuer.init();

    const qr = await issuer.issue({ subject: "mode0-test" }, 3600);
    assert.ok(qr.payload.length > 0, "payload must be non-empty");

    const trust = parseTrustConfig(
      issuer.trustConfigJson("http://localhost:0/checkpoint")
    );
    const revArt = issuer.revocationArtifact() ?? "";

    // No noteProvider needed for Mode 0 — checkpoint is embedded in payload.
    const v = new Verifier(undefined, () => revArt).addAnchor(trust);
    const result = await v.verify(new Uint8Array(qr.payload));

    assert.equal(result.valid, true, `Mode 0 must verify: ${JSON.stringify(result)}`);
    assert.equal(result.mode, 0, "mode must be 0 in result");
    assert.deepEqual(result.claims, { subject: "mode0-test" });
  });

  it("Mode 0 payload rejects tampered root_hash", async () => {
    const signer = localEd25519(SEED);
    const issuer = new Issuer(
      { origin: "test.mode0-tamper/v1", schemaId: 1, mode: 0 },
      signer,
    );
    await issuer.init();
    const qr = await issuer.issue({ subject: "tamper-test" }, 3600);

    // Flip one byte in the root_hash region (after TBS, at the start of embedded checkpoint).
    const tampered = new Uint8Array(qr.payload);
    // root_hash starts after the fixed header + proofs + tbs.
    // Just flip a byte near the end — if it's in root_hash, sig or cosig it will fail.
    tampered[tampered.length - 10] ^= 0xff;

    const trust = parseTrustConfig(
      issuer.trustConfigJson("http://localhost:0/checkpoint")
    );
    const v = new Verifier().addAnchor(trust);
    const result = await v.verify(tampered);
    assert.equal(result.valid, false, "tampered Mode 0 payload must be rejected");
  });
});

/**
 * MTA-QR SDK — smoke tests
 *
 * Test seeds are arbitrary fixed bytes generated from /dev/urandom.
 * They are not derived from strings and carry no semantic meaning.
 * Do not use these in production — use GoodKeySigner with hardware-backed keys.
 */
import { Issuer } from "../issuer.js";
import { Verifier } from "../verifier.js";
import { parseTrustConfig } from "../trust.js";
import { Signer } from "../signer.js";
import { localEd25519, localEcdsaP256, localMlDsa44 } from "../signers/local.js";

// Arbitrary fixed test seeds — not derived from any string or passphrase.
const SEED_ED25519    = Uint8Array.from(Buffer.from("275be85b9aa3357c647700aca548ab3c1b6d917a51f56515956004af2243d75f", "hex"));
const SEED_ECDSA_P256 = Uint8Array.from(Buffer.from("4b1477c4270aeb87ed40f222db87c132bf62092ed1ffc153b99729c2fb3c0820", "hex"));
const SEED_ML_DSA_44  = Uint8Array.from(Buffer.from("789753a683f9723c8e88cdf79071e26ebb8025cdca982a7287c5ea1cf1b822b2", "hex"));

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
  if (!cond) { console.log(`  ✗ ${msg}`); failed++; }
  else        { console.log(`  ✓ ${msg}`); passed++; }
}

async function roundTrip(label: string, signer: Signer) {
  const origin = `test.mta-qr.example/${label}/v1`;
  const issuer = new Issuer({ origin, schemaId: 1 }, signer);
  await issuer.init();

  const qr       = await issuer.issue({ subject: "test" }, 3600);
  const trust    = parseTrustConfig(issuer.trustConfigJson("http://localhost:0/checkpoint"));
  const note     = issuer.checkpointNote();
  const revArt = issuer.revocationArtifact() ?? "";
  const verifier = new Verifier(trust, () => note, () => revArt);

  try {
    const result = await verifier.verify(new Uint8Array(qr.payload));
    assert(result.entryIndex === qr.entryIndex, `${label}: issue and verify`);
  } catch (e) {
    assert(false, `${label}: issue and verify (${(e as Error).message})`);
  }
}

async function rejectTampered(label: string, signer: Signer) {
  const origin  = `test.mta-qr.example/${label}-tamper/v1`;
  const issuer  = new Issuer({ origin, schemaId: 1 }, signer);
  await issuer.init();

  const qr      = await issuer.issue({ subject: "legit" }, 3600);
  const tampered = new Uint8Array(qr.payload);
  tampered[tampered.length - 10] ^= 0xff;

  const trust    = parseTrustConfig(issuer.trustConfigJson("http://localhost:0/checkpoint"));
  const note     = issuer.checkpointNote();
  const revArt2 = issuer.revocationArtifact() ?? "";
  const verifier = new Verifier(trust, () => note, () => revArt2);

  const result = await verifier.verify(tampered);
  assert(!result.valid, `${label}: reject tampered payload`);
}

console.log("\nMTA-QR SDK — smoke tests\n");

await roundTrip("ed25519",    localEd25519(SEED_ED25519));
await rejectTampered("ed25519", localEd25519(SEED_ED25519));
await roundTrip("ecdsa-p256", localEcdsaP256(SEED_ECDSA_P256));
await rejectTampered("ecdsa-p256", localEcdsaP256(SEED_ECDSA_P256));
await roundTrip("ml-dsa-44",  localMlDsa44(SEED_ML_DSA_44));
await rejectTampered("ml-dsa-44", localMlDsa44(SEED_ML_DSA_44));

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);

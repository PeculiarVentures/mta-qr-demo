/**
 * Signing self-tests for MTA-QR TypeScript implementation.
 * Loads the shared test-vectors/vectors.json.
 * Key assertions:
 *   - Ed25519: deterministic, same sig as Go reference
 *   - ECDSA P-256: same public key as Go, verify(Go's pre_recorded_sig) == true
 *   - Cross-algorithm isolation: sig for alg A must not verify under alg B
 */
import { readFileSync } from "fs";
import { join } from "path";
import {
  verifySig as verify,
  SIG_ALG_ED25519,
} from "../verify-sig.js";
import {
  ed25519FromSeed,
  ecdsaP256FromScalar,
  SIG_ALG_ECDSA_P256,
  signing,
  js,
} from "../signers/local.js";

const VECTORS_PATH = join(
  new URL(".", import.meta.url).pathname,
  "../../../../test-vectors/vectors.json"
);

interface Vector { id: string; input: Record<string,string|number>; expected: Record<string,string|boolean>; }

function loadVectors(): Map<string, Vector> {
  const raw = JSON.parse(readFileSync(VECTORS_PATH, "utf8")) as { vectors: Vector[] };
  const m = new Map<string, Vector>();
  for (const v of raw.vectors) m.set(v.id, v);
  return m;
}

function hex(b: Uint8Array): string { return Buffer.from(b).toString("hex"); }
function fromHex(s: string): Uint8Array { return new Uint8Array(Buffer.from(s as string, "hex")); }

let passed = 0, failed = 0;

function test(name: string, fn: () => void) {
  try { fn(); console.log(`  ✓ ${name}`); passed++; }
  catch (e: unknown) { console.log(`  ✗ ${name}\n      ${(e as Error).message}`); failed++; }
}

function assert(cond: boolean, msg: string) { if (!cond) throw new Error(msg); }
function assertEqual(got: string, want: string, label: string) {
  if (got !== want) throw new Error(`${label}:\n      got  ${got}\n      want ${want}`);
}

const vs = loadVectors();
console.log("\nMTA-QR TypeScript signing tests\n");

// ---- Ed25519 ----

test("Ed25519: public key derivation from fixed seed", () => {
  const v = vs.get("signing-ed25519")!;
  const signer = ed25519FromSeed(fromHex(v.input.private_seed_hex as string));
  assertEqual(hex(signer.publicKeyBytes()), v.expected.public_key_hex as string, "pubkey");
});

test("Ed25519: signature is deterministic and matches Go reference", () => {
  const v = vs.get("signing-ed25519")!;
  const signer = ed25519FromSeed(fromHex(v.input.private_seed_hex as string));
  const msg = fromHex(v.input.message_hex as string);
  const sig = signer.sign(msg);
  assertEqual(hex(sig), v.expected.signature_hex as string, "signature determinism");
});

test("Ed25519: verify pre-recorded signature", () => {
  const v = vs.get("signing-ed25519")!;
  const pub = fromHex(v.expected.public_key_hex as string);
  const msg = fromHex(v.input.message_hex as string);
  const sig = fromHex(v.expected.signature_hex as string);
  assert(verify(SIG_ALG_ED25519, msg, sig, pub), "verify(pre-recorded) returned false");
});

test("Ed25519: round-trip sign/verify", () => {
  const v = vs.get("signing-ed25519")!;
  const signer = ed25519FromSeed(fromHex(v.input.private_seed_hex as string));
  const msg = fromHex(v.input.message_hex as string);
  const sig = signer.sign(msg);
  assert(verify(SIG_ALG_ED25519, msg, sig, signer.publicKeyBytes()), "round-trip verify failed");
});

test("Ed25519: corrupted sig fails verification", () => {
  const v = vs.get("signing-ed25519")!;
  const pub = fromHex(v.expected.public_key_hex as string);
  const msg = fromHex(v.input.message_hex as string);
  const sig = fromHex(v.expected.signature_hex as string);
  const bad = new Uint8Array(sig); bad[0] ^= 0x01;
  assert(!verify(SIG_ALG_ED25519, msg, bad, pub), "corrupted sig should not verify");
});

// ---- ECDSA P-256 ----

test("ECDSA-P256: public key derivation from fixed scalar", () => {
  const v = vs.get("signing-ecdsa-p256")!;
  const signer = ecdsaP256FromScalar(fromHex(v.input.scalar_hex as string));
  assertEqual(hex(signer.publicKeyBytes()), v.expected.public_key_hex as string, "pubkey");
});

test("ECDSA-P256: verify Go pre-recorded signature", () => {
  const v = vs.get("signing-ecdsa-p256")!;
  const pub = fromHex(v.expected.public_key_hex as string);
  const msg = fromHex(v.input.message_hex as string);
  const sig = fromHex(v.input.pre_recorded_sig as string);
  assert(verify(SIG_ALG_ECDSA_P256, msg, sig, pub), "verify(Go pre-recorded sig) returned false — cross-impl verify broken");
});

test("ECDSA-P256: round-trip sign/verify", () => {
  const v = vs.get("signing-ecdsa-p256")!;
  const signer = ecdsaP256FromScalar(fromHex(v.input.scalar_hex as string));
  const msg = fromHex(v.input.message_hex as string);
  const sig = signer.sign(msg);
  assert(sig.length === 64, `expected 64-byte raw sig, got ${sig.length}`);
  assert(verify(SIG_ALG_ECDSA_P256, msg, sig, signer.publicKeyBytes()), "round-trip verify failed");
});

test("ECDSA-P256: corrupted sig fails verification", () => {
  const v = vs.get("signing-ecdsa-p256")!;
  const signer = ecdsaP256FromScalar(fromHex(v.input.scalar_hex as string));
  const msg = fromHex(v.input.message_hex as string);
  const sig = signer.sign(msg);
  const bad = new Uint8Array(sig); bad[0] ^= 0x01;
  assert(!verify(SIG_ALG_ECDSA_P256, msg, bad, signer.publicKeyBytes()), "corrupted sig should not verify");
});

// ---- Cross-algorithm isolation ----

test("Cross-algorithm: Ed25519 sig rejected by ECDSA-P256 verifier", () => {
  const msg = new TextEncoder().encode("cross-algorithm isolation");
  const edSigner = ed25519FromSeed(new Uint8Array(32).fill(0x01));
  const ecSigner = ecdsaP256FromScalar(new Uint8Array(32).fill(0x02).map((b, i) => i === 31 ? 0x01 : b));
  const edSig = edSigner.sign(msg);
  assert(!verify(SIG_ALG_ECDSA_P256, msg, edSig, ecSigner.publicKeyBytes()),
    "ECDSA-P256 verifier accepted Ed25519 sig");
});

test("Cross-algorithm: ECDSA-P256 sig rejected by Ed25519 verifier", () => {
  const msg = new TextEncoder().encode("cross-algorithm isolation");
  const edSigner = ed25519FromSeed(new Uint8Array(32).fill(0x01));
  const ecSigner = ecdsaP256FromScalar(new Uint8Array(32).fill(0x02).map((b, i) => i === 31 ? 0x01 : b));
  const ecSig = ecSigner.sign(msg);
  assert(!verify(SIG_ALG_ED25519, msg, ecSig, edSigner.publicKeyBytes()),
    "Ed25519 verifier accepted ECDSA-P256 sig");
});

// ---- Summary ----
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);

// ---- ML-DSA-44 ----

import { mlDsa44FromSeed, SIG_ALG_MLDSA44 } from "../signers/local.js";

test("ML-DSA-44: public key derivation from fixed seed matches canonical vector", () => {
  const v = vs.get("signing-mldsa44")!;
  const signer = mlDsa44FromSeed(fromHex(v.input.seed_hex as string));
  assertEqual(hex(signer.publicKeyBytes()), v.expected.public_key_hex as string, "pubkey");
});

test("ML-DSA-44: verify pre_recorded_sig from Go reference implementation", () => {
  const v = vs.get("signing-mldsa44")!;
  const pub = fromHex(v.expected.public_key_hex as string);
  const msg = fromHex(v.input.message_hex as string);
  const sig = fromHex(v.input.pre_recorded_sig as string);
  assert(verify(SIG_ALG_MLDSA44, msg, sig, pub), "pre_recorded_sig should verify");
});

test("ML-DSA-44: sign and verify round-trip", () => {
  const v = vs.get("signing-mldsa44")!;
  const signer = mlDsa44FromSeed(fromHex(v.input.seed_hex as string));
  const msg = fromHex(v.input.message_hex as string);
  const sig = signer.sign(msg);
  assert(sig.length === 2420, `expected 2420-byte sig, got ${sig.length}`);
  assert(verify(SIG_ALG_MLDSA44, msg, sig, signer.publicKeyBytes()), "own sig should verify");
});

test("ML-DSA-44: corrupted signature does not verify", () => {
  const v = vs.get("signing-mldsa44")!;
  const signer = mlDsa44FromSeed(fromHex(v.input.seed_hex as string));
  const msg = fromHex(v.input.message_hex as string);
  const sig = signer.sign(msg);
  const bad = new Uint8Array(sig); bad[0] ^= 0x01;
  assert(!verify(SIG_ALG_MLDSA44, msg, bad, signer.publicKeyBytes()), "corrupted sig should not verify");
});

test("ML-DSA-44: sig rejected by Ed25519 verifier (cross-algorithm isolation)", () => {
  const msg = new TextEncoder().encode("cross-algorithm isolation mldsa44");
  const mlSigner = mlDsa44FromSeed(new Uint8Array(32).fill(0x44));
  const edSigner = ed25519FromSeed(new Uint8Array(32).fill(0x01));
  const mlSig = mlSigner.sign(msg);
  assert(!verify(SIG_ALG_ED25519, msg, mlSig, edSigner.publicKeyBytes()),
    "Ed25519 verifier accepted ML-DSA-44 sig");
});

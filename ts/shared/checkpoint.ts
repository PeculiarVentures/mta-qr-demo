/**
 * c2sp.org/tlog-checkpoint format implementation for MTA-QR.
 * Uses Node.js built-in crypto for Ed25519 — no external dependencies.
 *
 * Checkpoint body (the bytes that are signed):
 *   <origin>\n
 *   <tree_size decimal>\n
 *   <root_hash base64std_padded>\n
 *
 * The trailing \n on the root hash line is part of the authenticated content.
 */
import {
  createHash, randomBytes,
  sign as nodeSign, verify as nodeVerify,
  createPrivateKey, createPublicKey, KeyObject,
} from "crypto";

// PKCS#8 DER prefix for Ed25519 private key (seed only).
// ASN.1: SEQUENCE { INTEGER 0, AlgorithmIdentifier { OID 1.3.101.112 }, OCTET STRING { OCTET STRING seed } }
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

// SubjectPublicKeyInfo DER prefix for Ed25519 public key.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Convert a raw 32-byte Ed25519 seed to a Node KeyObject. */
function seedToPrivKey(seed: Uint8Array): KeyObject {
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Derive the raw 32-byte public key from a 32-byte seed. */
export function pubKeyFromSeed(seed: Uint8Array): Uint8Array {
  const privKey = seedToPrivKey(seed);
  const pubKey  = createPublicKey(privKey);
  const der = pubKey.export({ format: "der", type: "spki" }) as Buffer;
  // Last 32 bytes of SPKI DER are the raw public key.
  return new Uint8Array(der.slice(-32));
}

/** Convert raw 32-byte public key bytes to a Node KeyObject. */
function rawPubToKeyObject(pubBytes: Uint8Array): KeyObject {
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubBytes)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/** Generate a random 32-byte Ed25519 seed. */
export function generateSeed(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

/** Format the checkpoint body bytes that are signed by the issuer. */
export function checkpointBody(
  origin: string,
  treeSize: bigint | number,
  rootHash: Uint8Array,
): Uint8Array {
  const rootHashB64 = Buffer.from(rootHash).toString("base64");
  const body = `${origin}\n${treeSize}\n${rootHashB64}\n`;
  return new TextEncoder().encode(body);
}

/** Sign a checkpoint body. Returns 64-byte Ed25519 signature. */
export function signCheckpoint(body: Uint8Array, privKeySeed: Uint8Array): Uint8Array {
  const privKey = seedToPrivKey(privKeySeed);
  return new Uint8Array(nodeSign(null, Buffer.from(body), privKey));
}

/** Verify an Ed25519 checkpoint signature. */
export function verifyCheckpoint(
  body: Uint8Array,
  sig: Uint8Array,
  pubKeyBytes: Uint8Array,
): boolean {
  try {
    const pubKey = rawPubToKeyObject(pubKeyBytes);
    return nodeVerify(null, Buffer.from(body), pubKey, Buffer.from(sig));
  } catch {
    return false;
  }
}

/**
 * Build the cosignature/v1 signed message:
 *   cosignature/v1\n
 *   time <unix_timestamp_decimal>\n
 *   <checkpoint body>
 */
export function cosignatureV1Message(body: Uint8Array, timestamp: bigint): Uint8Array {
  const header = new TextEncoder().encode(`cosignature/v1\ntime ${timestamp}\n`);
  const msg = new Uint8Array(header.length + body.length);
  msg.set(header);
  msg.set(body, header.length);
  return msg;
}

/** Sign a witness cosignature. Returns 64-byte signature. */
export function signCosignature(
  body: Uint8Array,
  timestamp: bigint,
  privKeySeed: Uint8Array,
): Uint8Array {
  const msg = cosignatureV1Message(body, timestamp);
  const privKey = seedToPrivKey(privKeySeed);
  return new Uint8Array(nodeSign(null, Buffer.from(msg), privKey));
}

/** Verify a witness cosignature. */
export function verifyCosignature(
  body: Uint8Array,
  timestamp: bigint,
  sig: Uint8Array,
  pubKeyBytes: Uint8Array,
): boolean {
  try {
    const msg = cosignatureV1Message(body, timestamp);
    const pubKey = rawPubToKeyObject(pubKeyBytes);
    return nodeVerify(null, Buffer.from(msg), pubKey, Buffer.from(sig));
  } catch {
    return false;
  }
}

/**
 * Derive the 4-byte key ID per c2sp.org/signed-note:
 *   key_id = SHA-256(name || 0x0A || 0x01 || raw_pubkey)[0:4]
 */
export function witnessKeyID(name: string, pubKey: Uint8Array): Uint8Array {
  const h = createHash("sha256");
  h.update(Buffer.from(name, "utf8"));
  h.update(Buffer.from([0x0a, 0x01]));
  h.update(Buffer.from(pubKey));
  return new Uint8Array(h.digest().subarray(0, 4));
}

/**
 * Compute origin_id: first 8 bytes of SHA-256(origin) as big-endian uint64.
 */
export function originID(origin: string): bigint {
  const h = createHash("sha256").update(origin).digest();
  let id = BigInt(0);
  for (let i = 0; i < 8; i++) {
    id = (id << BigInt(8)) | BigInt(h[i]);
  }
  return id;
}

/** Parse a checkpoint body. Returns { origin, treeSize, rootHash }. */
export function parseCheckpointBody(body: Uint8Array): {
  origin: string;
  treeSize: bigint;
  rootHash: Uint8Array;
} {
  const text = new TextDecoder().decode(body);
  if (!text.endsWith("\n")) throw new Error("checkpoint body must end with \\n");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length !== 3) throw new Error(`checkpoint body must have 3 lines, got ${lines.length}`);
  const [origin, treeSizeStr, rootHashB64] = lines;
  const treeSize = BigInt(treeSizeStr);
  const rootHash = new Uint8Array(Buffer.from(rootHashB64, "base64"));
  if (rootHash.length !== 32) throw new Error(`root_hash must be 32 bytes, got ${rootHash.length}`);
  return { origin, treeSize, rootHash };
}

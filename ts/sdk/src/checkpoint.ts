/**
 * c2sp.org/tlog-checkpoint format for MTA-QR.
 *
 * Checkpoint body (the bytes signed by the issuer and witnesses):
 *   <origin>\n
 *   <tree_size decimal>\n
 *   <root_hash base64std_padded>\n
 *
 * Witnesses always use Ed25519 per c2sp.org/tlog-cosignature, regardless
 * of the issuer's sig_alg.
 */

import {
  createHash, randomBytes,
  sign as nodeSign, verify as nodeVerify,
  createPrivateKey, createPublicKey, KeyObject,
} from "crypto";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX  = Buffer.from("302a300506032b6570032100", "hex");

function seedToPrivKey(seed: Uint8Array): KeyObject {
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function rawPubToKeyObject(pubBytes: Uint8Array): KeyObject {
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubBytes)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

export function pubKeyFromSeed(seed: Uint8Array): Uint8Array {
  const priv = seedToPrivKey(seed);
  const pub  = createPublicKey(priv);
  return new Uint8Array((pub.export({ format: "der", type: "spki" }) as Buffer).slice(-32));
}

export function generateSeed(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

/** Build the checkpoint body bytes that are signed. */
export function checkpointBody(
  origin: string,
  treeSize: bigint | number,
  rootHash: Uint8Array,
): Uint8Array {
  const rootHashB64 = Buffer.from(rootHash).toString("base64");
  return new TextEncoder().encode(`${origin}\n${treeSize}\n${rootHashB64}\n`);
}

/** Sign a checkpoint body. Returns 64-byte Ed25519 signature. */
export function signCheckpointBody(body: Uint8Array, privKeySeed: Uint8Array): Uint8Array {
  return new Uint8Array(nodeSign(null, Buffer.from(body), seedToPrivKey(privKeySeed)));
}

/** Verify an Ed25519 checkpoint signature. */
export function verifyCheckpointSig(
  body: Uint8Array,
  sig: Uint8Array,
  pubKeyBytes: Uint8Array,
): boolean {
  try {
    return nodeVerify(null, Buffer.from(body), rawPubToKeyObject(pubKeyBytes), Buffer.from(sig));
  } catch { return false; }
}

/**
 * Build the cosignature/v1 signed message:
 *   cosignature/v1\n
 *   time <unix_timestamp_decimal>\n
 *   <checkpoint body>
 */
export function cosignatureMessage(body: Uint8Array, timestamp: bigint): Uint8Array {
  const header = new TextEncoder().encode(`cosignature/v1\ntime ${timestamp}\n`);
  const msg = new Uint8Array(header.length + body.length);
  msg.set(header);
  msg.set(body, header.length);
  return msg;
}

export function signCosignature(
  body: Uint8Array,
  timestamp: bigint,
  privKeySeed: Uint8Array,
): Uint8Array {
  return new Uint8Array(
    nodeSign(null, Buffer.from(cosignatureMessage(body, timestamp)), seedToPrivKey(privKeySeed))
  );
}

export function verifyCosignature(
  body: Uint8Array,
  timestamp: bigint,
  sig: Uint8Array,
  pubKeyBytes: Uint8Array,
): boolean {
  try {
    return nodeVerify(
      null,
      Buffer.from(cosignatureMessage(body, timestamp)),
      rawPubToKeyObject(pubKeyBytes),
      Buffer.from(sig),
    );
  } catch { return false; }
}

/**
 * Derive the 4-byte key ID per c2sp.org/signed-note:
 *   key_id = SHA-256(name || 0x0A || 0x01 || raw_pubkey)[0:4]
 * where 0x0A is newline and 0x01 is the Ed25519 signature type identifier byte.
 */
export function noteKeyId(name: string, pubKey: Uint8Array): Uint8Array {
  const h = createHash("sha256");
  h.update(Buffer.from(name, "utf8"));
  h.update(Buffer.from([0x0a, 0x01]));
  h.update(Buffer.from(pubKey));
  return new Uint8Array(h.digest().subarray(0, 4));
}

export { noteKeyId as witnessKeyId };

/** Compute origin_id: first 8 bytes of SHA-256(origin) as big-endian uint64. */
export function computeOriginId(origin: string): bigint {
  const h = createHash("sha256").update(origin).digest();
  let id = BigInt(0);
  for (let i = 0; i < 8; i++) id = (id << BigInt(8)) | BigInt(h[i]);
  return id;
}

export function parseCheckpointBody(body: Uint8Array): {
  origin: string;
  treeSize: bigint;
  rootHash: Uint8Array;
} {
  const text = new TextDecoder().decode(body);
  if (!text.endsWith("\n")) throw new Error("checkpoint body must end with \\n");
  const lines = text.slice(0, -1).split("\n");
  // Per c2sp.org/tlog-checkpoint: three mandatory lines plus optional extension lines.
  if (lines.length < 3) throw new Error(`checkpoint body must have at least 3 lines, got ${lines.length}`);
  const [origin, treeSizeStr, rootHashB64] = lines;
  const treeSize = BigInt(treeSizeStr);
  const rootHash = new Uint8Array(Buffer.from(rootHashB64, "base64"));
  if (rootHash.length !== 32) throw new Error(`root_hash must be 32 bytes`);
  return { origin, treeSize, rootHash };
}

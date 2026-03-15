/**
 * GoodKeySigner — delegates signing to the GoodKey REST API.
 *
 * Keys never leave GoodKey. Signing goes through an async approval workflow:
 *   1. POST /key/{id}/operation           — create sign operation
 *   2. GET  /key/{id}/operation/{opId}    — poll until status = "ready"
 *   3. PATCH /key/{id}/operation/{opId}/finalize — submit hash, get signature
 *
 * Public key retrieval:
 *   GET /key/{id}/public                  — returns SPKI PEM
 *
 * Keys are referenced by UUID, not label. The algorithm is specified by name
 * (e.g. "ECDSA_P256_SHA256", "ED_25519", "ML_DSA_44") and must be in the
 * key's supported algorithms list.
 *
 * Authentication is via Bearer token in the Authorization header.
 */

import { createHash } from "crypto";
import { SIG_ALG_ED25519, SIG_ALG_ECDSA_P256, SIG_ALG_ML_DSA_44 } from "../signer.js";
import type { Signer, SigAlg } from "../signer.js";

export interface GoodKeyConfig {
  /** GoodKey API base URL, e.g. "https://api.goodkey.io" */
  baseUrl: string;
  /** UUID of the signing key in GoodKey. */
  keyId: string;
  /** Bearer token for API authentication. */
  apiKey: string;
  /**
   * Algorithm name as GoodKey understands it.
   * Must be in the key's supported algorithms list.
   * e.g. "ECDSA_P256_SHA256", "ED_25519", "ML_DSA_44"
   */
  algorithmName: string;
  /**
   * How long to poll for operation approval (ms). Default: 5 minutes.
   * GoodKey operations may require human approval — this controls the timeout.
   */
  approvalTimeoutMs?: number;
  /** Poll interval (ms). Default: 3000. */
  pollIntervalMs?: number;
}

interface KeyOperationResponse {
  id: string;
  type: string;
  status: string; // "pending" | "ready" | "invalid"
  error?: string;
  approvalsLeft?: number;
}

interface KeyOperationFinalizeResponse {
  operation: KeyOperationResponse;
  data: string; // base64url encoded signature
}

/**
 * Map GoodKey algorithm name to MTA-QR wire sig_alg integer.
 * This is the source of truth for algorithm mapping.
 */
function algNameToSigAlg(algName: string): SigAlg {
  const upper = algName.toUpperCase();
  if (upper.includes("ED_25519") || upper === "ED25519") return SIG_ALG_ED25519;
  if (upper.includes("ECDSA_P256"))                       return SIG_ALG_ECDSA_P256;
  if (upper.includes("ML_DSA_44") || upper.includes("MLDSA44")) return SIG_ALG_ML_DSA_44;
  throw new Error(`GoodKey: cannot map algorithm "${algName}" to a known MTA-QR sig_alg`);
}

/**
 * Compute the hash that GoodKey expects in the finalize step.
 * Ed25519 and ML-DSA-44 sign the raw message (no pre-hashing).
 * ECDSA P-256 expects SHA-256 of the message.
 */
function computeHash(message: Uint8Array, algName: string): Buffer {
  const upper = algName.toUpperCase();
  if (upper.includes("ECDSA_P256") || upper.includes("SHA256")) {
    return createHash("sha256").update(message).digest();
  }
  if (upper.includes("SHA384")) {
    return createHash("sha384").update(message).digest();
  }
  if (upper.includes("SHA512")) {
    return createHash("sha512").update(message).digest();
  }
  // Ed25519 and ML-DSA sign the raw message
  return Buffer.from(message);
}

/**
 * Extract raw public key bytes from SPKI DER (as returned by GoodKey's /public endpoint).
 * GoodKey returns PEM — we strip the PEM wrapper and parse the DER.
 */
function spkiPemToRawPubKey(pem: string, sigAlg: SigAlg): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const der = Buffer.from(b64, "base64");

  switch (sigAlg) {
    case SIG_ALG_ED25519:
      // SPKI for Ed25519: 12-byte header + 32-byte raw key
      return new Uint8Array(der.slice(-32));
    case SIG_ALG_ECDSA_P256:
      // SPKI for P-256: header + 65-byte uncompressed point (0x04 || X || Y)
      return new Uint8Array(der.slice(-65));
    case SIG_ALG_ML_DSA_44:
      // SPKI for ML-DSA-44: header + 1312-byte public key
      return new Uint8Array(der.slice(-1312));
  }
}

/**
 * Create a GoodKeySigner. Calls GoodKey once at construction to resolve
 * the public key and derive the key name.
 */
export async function goodKeySigner(config: GoodKeyConfig): Promise<Signer> {
  const { baseUrl, keyId, apiKey, algorithmName } = config;
  const approvalTimeout = config.approvalTimeoutMs ?? 5 * 60 * 1000;
  const pollInterval    = config.pollIntervalMs    ?? 3000;
  const headers = {
    "Authorization": `Bearer ${apiKey}`,
    "Content-Type":  "application/json",
  };

  const sigAlg = algNameToSigAlg(algorithmName);

  // Fetch public key once — GoodKey returns SPKI PEM
  const pkRes = await fetch(`${baseUrl}/key/${keyId}/public`, { headers });
  if (!pkRes.ok) {
    throw new Error(`GoodKey: GET /key/${keyId}/public: ${pkRes.status} ${pkRes.statusText}`);
  }
  const pkPem   = await pkRes.text();
  const pubBytes = spkiPemToRawPubKey(pkPem, sigAlg);

  // Build key name from public key (standard MTA-QR format)
  const keyName = `goodkey-${algorithmName}+${Buffer.from(pubBytes).toString("base64")}`;

  return {
    sigAlg,
    keyName,

    async sign(message: Uint8Array): Promise<Uint8Array> {
      const hash    = computeHash(message, algorithmName);
      const hashB64 = hash.toString("base64url");

      // 1. Create sign operation
      const createRes = await fetch(`${baseUrl}/key/${keyId}/operation`, {
        method: "POST",
        headers,
        body: JSON.stringify({ type: "sign", name: algorithmName }),
      });
      if (!createRes.ok) {
        throw new Error(`GoodKey: create sign operation: ${createRes.status} ${createRes.statusText}`);
      }
      let operation: KeyOperationResponse = await createRes.json();

      // 2. Poll until ready (handles human approval flows)
      const deadline = Date.now() + approvalTimeout;
      while (operation.status === "pending") {
        if (Date.now() > deadline) {
          throw new Error(`GoodKey: sign operation ${operation.id} timed out after ${approvalTimeout}ms`);
        }
        await new Promise(r => setTimeout(r, pollInterval));
        const pollRes = await fetch(`${baseUrl}/key/${keyId}/operation/${operation.id}`, { headers });
        if (!pollRes.ok) {
          throw new Error(`GoodKey: poll operation: ${pollRes.status}`);
        }
        operation = await pollRes.json();
      }

      if (operation.status !== "ready") {
        throw new Error(`GoodKey: sign operation ${operation.id} ended with status "${operation.status}": ${operation.error ?? ""}`);
      }

      // 3. Finalize — submit hash, receive signature
      const finalRes = await fetch(`${baseUrl}/key/${keyId}/operation/${operation.id}/finalize`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ data: hashB64 }),
      });
      if (!finalRes.ok) {
        throw new Error(`GoodKey: finalize sign operation: ${finalRes.status} ${finalRes.statusText}`);
      }
      const finalData: KeyOperationFinalizeResponse = await finalRes.json();
      return Uint8Array.from(Buffer.from(finalData.data, "base64url"));
    },

    async publicKeyBytes(): Promise<Uint8Array> {
      return pubBytes;
    },
  };
}

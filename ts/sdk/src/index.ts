/**
 * @peculiar/mta-qr
 *
 * MTA-QR SDK — Merkle Tree Assertions for Verifiable QR Codes.
 *
 * Quick start (issuer):
 *
 *   import { Issuer, goodKeySigner } from "@peculiar/mta-qr";
 *
 *   const signer = await goodKeySigner({
 *     baseUrl:  "https://api.goodkey.io/v1",
 *     keyLabel: "mta-qr-issuer",
 *     apiKey:   process.env.GOODKEY_API_KEY!,
 *   });
 *   const issuer = new Issuer({ origin: "example.com/my-log/v1", schemaId: 1 }, signer);
 *   await issuer.init();
 *   const { payload, payloadB64url } = await issuer.issue({ name: "Alice" });
 *
 * Quick start (verifier):
 *
 *   import { Verifier, loadTrustConfigFile } from "@peculiar/mta-qr";
 *
 *   const trust    = loadTrustConfigFile("./trust/my-issuer.json");
 *   const verifier = new Verifier(trust);
 *   const result   = await verifier.verify(payloadBytes);
 *   if (result.valid) console.log(result.claims);
 */

// Core types
export type { Signer, SigAlg } from "./signer.js";
export {
  SIG_ALG_ED25519, SIG_ALG_ECDSA_P256, SIG_ALG_ML_DSA_44,
  sigAlgName, sigAlgSigLen, sigAlgPubKeyLen,
} from "./signer.js";

// Trust config
export type { TrustConfig, WitnessEntry } from "./trust.js";
export { loadTrustConfigFile, parseTrustConfig } from "./trust.js";

// Issuer
export type { IssuerConfig, IssuedQR } from "./issuer.js";
export { Issuer } from "./issuer.js";

// Verifier
export type { VerifyResult, VerifyOk, VerifyFail, VerifyStep, VerifyTraceResult } from "./verifier.js";
export { Verifier } from "./verifier.js";
export type { NoteProvider } from "./verifier.js";

// Signers
export { goodKeySigner } from "./signers/goodkey.js";
export type { GoodKeyConfig } from "./signers/goodkey.js";
export { localEd25519, localEcdsaP256, localMlDsa44 } from "./signers/local.js";

// Claims type
export type { Claims, DataAssertionEntry } from "./cbor.js";

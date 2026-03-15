/**
 * SHA-256 hash abstraction.
 *
 * The default implementation uses Node's `crypto.createHash`.
 * The browser bundle overrides this with `crypto.subtle.digest`.
 *
 * All protocol modules import `sha256` from here — never directly from `crypto`.
 * This is the only file that differs between Node and browser builds.
 */
import { createHash } from "crypto";

/** SHA-256 of data. Returns a fresh 32-byte Uint8Array. */
export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

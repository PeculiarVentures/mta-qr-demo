/**
 * SHA-256 hash abstraction — browser build.
 *
 * esbuild replaces hash.ts with this file when building the browser bundle,
 * using the `--alias:./hash.js=./hash.browser.js` flag.
 * crypto.subtle.digest is synchronous-feeling here because the Merkle
 * functions are already async in the browser bundle.
 */

/** SHA-256 of data using Web Crypto. Returns a Promise<Uint8Array>. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await globalThis.crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return new Uint8Array(buf);
}

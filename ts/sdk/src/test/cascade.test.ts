import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Cascade } from "../cascade.js";

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}
function fromHex(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "hex"));
}

describe("cascade", () => {
  // SPEC.md Vector R1: R={2,5}, S={1,3,4,6,7,8}
  const R1_HEX = "01000000080112";
  const R1_REVOKED = [2n, 5n];
  const R1_VALID   = [1n, 3n, 4n, 6n, 7n, 8n];

  it("R1: build and query", () => {
    const c = Cascade.build(R1_REVOKED, R1_VALID);
    assert.equal(c.query(0n), false); // excluded
    assert.equal(c.query(1n), false);
    assert.equal(c.query(2n), true);
    assert.equal(c.query(3n), false);
    assert.equal(c.query(4n), false);
    assert.equal(c.query(5n), true);
    assert.equal(c.query(6n), false);
    assert.equal(c.query(7n), false);
    assert.equal(c.query(8n), false);
    assert.equal(c.query(99n), false);
  });

  it("R1: locked canonical bytes", () => {
    const c = Cascade.build(R1_REVOKED, R1_VALID);
    assert.equal(hex(c.encode()), R1_HEX,
      "R1 cascade bytes changed — update spec and all cross-language vectors");
  });

  it("R1: decode matches build", () => {
    const c = Cascade.build(R1_REVOKED, R1_VALID);
    const c2 = Cascade.decode(fromHex(R1_HEX));
    for (const x of [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 99n]) {
      assert.equal(c.query(x), c2.query(x), `mismatch at ${x}`);
    }
  });

  // SPEC.md Vector R2: empty revocation set
  it("R2: empty cascade", () => {
    const c = Cascade.build([], [1n, 2n, 3n]);
    const enc = c.encode();
    assert.equal(enc.length, 1);
    assert.equal(enc[0], 0);
    assert.equal(hex(enc), "00");
    assert.equal(c.query(1n), false);
    assert.equal(c.query(99n), false);
  });

  // Rejection cases R-REJ-1 through R-REJ-9
  it("R-REJ-1: truncated header", () => {
    assert.throws(() => Cascade.decode(fromHex("010000000")),
      /truncated/);
  });

  it("R-REJ-2: bit_count=0", () => {
    assert.throws(() => Cascade.decode(fromHex("01000000000100")),
      /bit_count=0/);
  });

  it("R-REJ-3: k!=1", () => {
    assert.throws(() => Cascade.decode(fromHex("010000000802ff")),
      /k=.*MUST be 1/);
  });

  it("R-REJ-9: truncated bit array", () => {
    // num_levels=1, bit_count=8, k=1, but no bit array bytes
    assert.throws(() => Cascade.decode(fromHex("01000000080100".slice(0, -2))),
      /truncated/);
  });

  it("trailing bytes rejected", () => {
    assert.throws(() => Cascade.decode(fromHex("00ff")),
      /trailing bytes/);
  });

  it("determinism", () => {
    const r = [10n, 20n, 30n];
    const s = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 11n];
    const b1 = hex(Cascade.build(r, s).encode());
    const b2 = hex(Cascade.build(r, s).encode());
    assert.equal(b1, b2);
  });
});

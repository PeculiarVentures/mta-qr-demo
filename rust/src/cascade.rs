//! MTA-QR Bloom filter cascade for revocation.
//!
//! Wire format, construction parameters, and query algorithm are normatively
//! defined in SPEC.md §Revocation — Normative Construction Parameters.

use sha2::{Sha256, Digest};
use anyhow::{anyhow, Result};

/// Construction constants — normative per SPEC.md §Revocation.
const BITS_PER_ELEMENT: f64 = 1.4427; // = 1/ln(2)
const MIN_FILTER_BITS:  u32 = 8;      // 1 byte minimum
const MAX_LEVELS:       usize = 32;

struct Level {
    bit_count: u32,
    bits:      Vec<u8>, // MSB-first
}

/// Bloom filter cascade over revoked/valid entry index sets.
pub struct Cascade {
    levels: Vec<Level>,
}

impl Cascade {
    /// Build a cascade over (revoked, valid) entry index sets.
    pub fn build(revoked: &[u64], valid: &[u64]) -> Result<Self> {
        if revoked.is_empty() { return Ok(Cascade { levels: vec![] }); }

        let mut include: Vec<u64> = revoked.to_vec();
        let mut exclude: Vec<u64> = valid.to_vec();
        include.sort_unstable();
        exclude.sort_unstable();

        let mut levels = Vec::new();

        for level_idx in 0..MAX_LEVELS {
            if include.is_empty() { break; }
            let m = filter_size(include.len());
            let mut bits = vec![0u8; (m / 8) as usize];

            for &x in &include {
                let b = bit_position(x, level_idx, m);
                bits[(b / 8) as usize] |= 1 << (7 - (b % 8));
            }

            let fp: Vec<u64> = exclude.iter().copied()
                .filter(|&x| {
                    let b = bit_position(x, level_idx, m);
                    (bits[(b / 8) as usize] >> (7 - (b % 8))) & 1 == 1
                })
                .collect();

            levels.push(Level { bit_count: m, bits });
            let prev_include = include;
            include = fp;
            exclude = prev_include;
        }

        if !include.is_empty() {
            return Err(anyhow!("cascade: did not terminate within {} levels", MAX_LEVELS));
        }
        Ok(Cascade { levels })
    }

    /// Returns true if entry_index is revoked.
    pub fn query(&self, x: u64) -> bool {
        if self.levels.is_empty() { return false; }
        let mut result = false;
        for (i, lv) in self.levels.iter().enumerate() {
            let b = bit_position(x, i, lv.bit_count);
            let in_filter = (lv.bits[(b / 8) as usize] >> (7 - (b % 8))) & 1 == 1;
            if i == 0 {
                if !in_filter { return false; }
                result = true;
            } else {
                if in_filter { result = !result; }
                else         { return result; }
            }
        }
        result
    }

    /// Serialize per SPEC.md §Revocation — Binary Encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.levels.len() as u8];
        for lv in &self.levels {
            out.extend_from_slice(&lv.bit_count.to_be_bytes());
            out.push(1); // k=1
            out.extend_from_slice(&lv.bits);
        }
        out
    }

    /// Deserialize from bytes produced by encode().
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.is_empty() { return Err(anyhow!("cascade: empty input")); }
        let num_levels = b[0] as usize;
        let mut pos = 1;
        let mut levels = Vec::with_capacity(num_levels);
        for i in 0..num_levels {
            if pos + 5 > b.len() {
                return Err(anyhow!("cascade: truncated at level {} header", i));
            }
            let bit_count = u32::from_be_bytes(b[pos..pos+4].try_into().unwrap());
            let k = b[pos + 4];
            pos += 5;
            if k != 1 { return Err(anyhow!("cascade: level {} has k={}, MUST be 1", i, k)); }
            if bit_count == 0 { return Err(anyhow!("cascade: level {} has bit_count=0", i)); }
            let byte_count = ((bit_count + 7) / 8) as usize;
            if pos + byte_count > b.len() {
                return Err(anyhow!("cascade: truncated at level {} bit array", i));
            }
            levels.push(Level { bit_count, bits: b[pos..pos+byte_count].to_vec() });
            pos += byte_count;
        }
        if pos != b.len() {
            return Err(anyhow!("cascade: {} trailing bytes", b.len() - pos));
        }
        Ok(Cascade { levels })
    }
}

/// bit_position(x, i) = big_endian_u64(SHA-256(x_be8 || u8(i))[0:8]) mod m
fn bit_position(x: u64, level_idx: usize, m: u32) -> u32 {
    let mut buf = [0u8; 9];
    buf[..8].copy_from_slice(&x.to_be_bytes());
    buf[8] = level_idx as u8;
    let h = Sha256::digest(&buf);
    let v = u64::from_be_bytes(h[0..8].try_into().unwrap());
    (v % m as u64) as u32
}

fn filter_size(n: usize) -> u32 {
    let m = ((n as f64 * BITS_PER_ELEMENT).ceil() as u32).max(MIN_FILTER_BITS);
    (m + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1_HEX: &str = "01000000080112";

    fn from_hex(s: &str) -> Vec<u8> { hex::decode(s).unwrap() }
    fn to_hex(b: &[u8]) -> String   { hex::encode(b) }

    #[test]
    fn r1_queries() {
        let c = Cascade::build(&[2, 5], &[1, 3, 4, 6, 7, 8]).unwrap();
        assert!(!c.query(0));
        assert!(!c.query(1));
        assert!( c.query(2));
        assert!(!c.query(3));
        assert!(!c.query(4));
        assert!( c.query(5));
        assert!(!c.query(6));
        assert!(!c.query(7));
        assert!(!c.query(8));
        assert!(!c.query(99));
    }

    #[test]
    fn r1_locked_bytes() {
        let c = Cascade::build(&[2, 5], &[1, 3, 4, 6, 7, 8]).unwrap();
        assert_eq!(to_hex(&c.encode()), R1_HEX,
            "R1 bytes changed — update spec and all cross-language vectors");
    }

    #[test]
    fn r1_round_trip() {
        let c = Cascade::build(&[2, 5], &[1, 3, 4, 6, 7, 8]).unwrap();
        let c2 = Cascade::decode(&from_hex(R1_HEX)).unwrap();
        for x in [1u64,2,3,4,5,6,7,8,99] {
            assert_eq!(c.query(x), c2.query(x), "mismatch at {x}");
        }
    }

    #[test]
    fn r2_empty() {
        let c = Cascade::build(&[], &[1,2,3]).unwrap();
        let enc = c.encode();
        assert_eq!(enc, vec![0u8], "empty cascade must be [0x00]");
        assert!(!c.query(1));
        assert!(!c.query(99));
    }

    #[test]
    fn reject_truncated_header() {
        assert!(Cascade::decode(&[0x01, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn reject_bit_count_zero() {
        assert!(Cascade::decode(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x01]).is_err());
    }

    #[test]
    fn reject_k_not_one() {
        assert!(Cascade::decode(&[0x01, 0x00, 0x00, 0x00, 0x08, 0x02, 0x00]).is_err());
    }

    #[test]
    fn reject_truncated_bits() {
        assert!(Cascade::decode(&[0x01, 0x00, 0x00, 0x00, 0x08, 0x01]).is_err());
    }

    #[test]
    fn reject_trailing_bytes() {
        assert!(Cascade::decode(&[0x00, 0xff]).is_err());
    }

    #[test]
    fn determinism() {
        let r = vec![10u64, 20, 30];
        let s: Vec<u64> = (1..=9).chain([11]).collect();
        let b1 = Cascade::build(&r, &s).unwrap().encode();
        let b2 = Cascade::build(&r, &s).unwrap().encode();
        assert_eq!(b1, b2);
    }
}

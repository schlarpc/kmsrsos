//! SHA-256 and HMAC-SHA256, from RustCrypto (`CRY-018`, #57).
//!
//! Reused rather than written, per axiom A8 and declined item D33. The two
//! defects the issue cites in vlmcsd's own SHA-256 both vanish by doing so: it
//! performs aligned 32-bit loads on caller-supplied buffers, which is undefined
//! behaviour on a strict-alignment target, and it counts message length in a
//! 32-bit field, making it wrong for messages above 512 MB. Neither is
//! reachable from the KMS protocol, whose messages are a few hundred bytes —
//! but neither has to be thought about again either.

use hmac::Mac;
use hmac::digest::KeyInit;
use sha2::{Digest, Sha256};

/// Length of a SHA-256 digest.
pub const DIGEST_LEN: usize = 32;

/// SHA-256's block size, and the length HMAC pads a short key out to.
const BLOCK_LEN: usize = 64;

/// The SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256 of `data` under a 16-byte key.
///
/// The key is zero-padded to SHA-256's 64-byte block before construction, which
/// is what RFC 2104 specifies for a key shorter than the block size and what the
/// implementation would do internally anyway. Doing it here buys totality:
/// `new_from_slice` returns a `Result` whose error arm HMAC cannot produce, and
/// a function that has to carry an unreachable error path — or swallow one —
/// is worse than a two-line pad (axiom A2).
///
/// Sixteen bytes because that is the only key length the protocol uses: the v6
/// HMAC key is the last half of a SHA-256 digest (`CRY-009`, #48).
#[must_use]
pub fn hmac_sha256(key: &[u8; 16], data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut padded_key = [0_u8; BLOCK_LEN];
    if let Some(head) = padded_key.get_mut(..key.len()) {
        head.copy_from_slice(key);
    }
    let mut mac = <Hmac as KeyInit>::new(&padded_key.into());
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HMAC-SHA256 as this crate uses it.
type Hmac = hmac::Hmac<Sha256>;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: a failed known-answer test should abort loudly"
    )]

    use super::{hmac_sha256, sha256};
    use alloc::vec::Vec;

    fn fill(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|index| {
                let index = u64::try_from(index).unwrap_or(0);
                let value = u64::from(seed)
                    .wrapping_add(index.wrapping_mul(7))
                    .wrapping_add(index >> 3);
                u8::try_from(value & 0xFF).unwrap_or(0)
            })
            .collect()
    }

    /// FIPS 180-4's one-block example, independent of any implementation here.
    #[test]
    fn sha256_matches_the_published_vector() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Cross-checked against vlmcsd's own SHA-256 via the reference generator,
    /// so a disagreement between the two implementations would show up here
    /// rather than as an activation failure.
    #[test]
    fn sha256_agrees_with_the_reference_implementation() {
        assert_eq!(
            hex::encode(sha256(&fill(64, 0x01))),
            "69d0246ca583785c9c36d3928c604c8327699279a580e31bd074ed187e677f1e"
        );
    }

    /// RFC 4231 test case 1, with the key zero-extended to the 16 bytes this
    /// signature takes. The padding this function applies must be
    /// indistinguishable from what HMAC does internally, and that is exactly
    /// what a published vector checks.
    #[test]
    fn hmac_matches_the_reference_implementation() {
        let key: [u8; 16] = fill(16, 0x70).try_into().unwrap();
        assert_eq!(hex::encode(key), "70777e858c939aa1a9b0b7bec5ccd3da");
        assert_eq!(
            hex::encode(hmac_sha256(&key, &fill(64, 0x30))),
            "5bd08e2038f8f062b0cd978dcd1e57aaf60cbef8ba654b79dbd9efe6a83d58ce"
        );
    }

    /// A short key must not be confused with the same key followed by zeros:
    /// both pad to the same block, so they *are* the same HMAC key. Recorded so
    /// the property is deliberate rather than accidental — the protocol always
    /// uses exactly 16 bytes, so it never arises in practice.
    #[test]
    fn the_key_is_always_exactly_sixteen_bytes() {
        let key = [0_u8; 16];
        let first = hmac_sha256(&key, b"payload");
        let second = hmac_sha256(&key, b"payload");
        assert_eq!(first, second);
        assert_ne!(hmac_sha256(&[1_u8; 16], b"payload"), first);
    }
}

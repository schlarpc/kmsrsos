//! The v4 message authentication code (`CRY-003`, #42; `CRY-004`, #43).
//!
//! # It is not CMAC
//!
//! vlmcsd calls this `AesCmacV4` and py-kms inherited the name, but nothing
//! here is CMAC. There is no subkey derivation, no `K1`/`K2`, and no final
//! conditional XOR. It is a raw CBC-MAC with a zero IV over Rijndael-160, with
//! ISO/IEC 7816-4 padding — `0x80` then zeros — **always** appended, including
//! when the message length is already a multiple of the block size.
//!
//! Both existing implementations reverse-engineered that independently and
//! reached the same answer, so it is what a genuine host does. The name is
//! wrong, though, and a reader who takes it at face value will reach for a CMAC
//! library and get a different tag. Hence [`CbcMacV4`].
//!
//! Raw CBC-MAC with a fixed key is not a secure MAC for variable-length
//! messages — it is existentially forgeable — but the key is published
//! (`CRY-001`, #40), so there is nothing to forge *against*. This is framing,
//! not authentication.

use crate::keys;
use crate::rijndael::{BLOCK_LEN, KeySchedule};

/// The ISO/IEC 7816-4 padding marker.
const PADDING_MARKER: u8 = 0x80;

/// The v4 CBC-MAC, holding its expanded key schedule (`CRY-016`, #55).
///
/// A value rather than a free function so the 160-bit key is expanded once, at
/// start-up, rather than on every request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbcMacV4 {
    schedule: KeySchedule,
}

impl Default for CbcMacV4 {
    fn default() -> Self {
        Self::new()
    }
}

impl CbcMacV4 {
    /// Expand the published v4 key.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schedule: KeySchedule::rijndael160(&keys::V4),
        }
    }

    /// Compute the tag over `message`.
    ///
    /// # Not writing past the message (`CRY-004`, #43)
    ///
    /// vlmcsd's version takes a mutable pointer and writes the padding *into the
    /// caller's buffer*, past the end of the message — sixteen bytes of slack
    /// that every call site has to remember to reserve. That is a memory-safety
    /// obligation carried in a comment. Here the message is a `&[u8]`, the
    /// padding block is a local, and the tag comes back by value, so the
    /// obligation does not exist.
    #[must_use]
    pub fn tag(&self, message: &[u8]) -> [u8; BLOCK_LEN] {
        let mut mac = [0_u8; BLOCK_LEN];

        let blocks = message.chunks_exact(BLOCK_LEN);
        let tail = blocks.remainder();

        for block in blocks {
            if let Ok(block) = <[u8; BLOCK_LEN]>::try_from(block) {
                xor_into(&mut mac, &block);
                self.schedule.encrypt_block(&mut mac);
            }
        }

        // The padding block is unconditional. When `tail` is empty — that is,
        // when the message length was already a multiple of 16 — this is a whole
        // extra block of `0x80` followed by fifteen zeros, and omitting it gives
        // a different tag for every aligned message.
        let mut final_block = [0_u8; BLOCK_LEN];
        if let Some(head) = final_block.get_mut(..tail.len()) {
            head.copy_from_slice(tail);
        }
        if let Some(marker) = final_block.get_mut(tail.len()) {
            *marker = PADDING_MARKER;
        }
        xor_into(&mut mac, &final_block);
        self.schedule.encrypt_block(&mut mac);

        mac
    }
}

/// XOR `source` into `target`, byte for byte.
fn xor_into(target: &mut [u8; BLOCK_LEN], source: &[u8; BLOCK_LEN]) {
    for (byte, mask) in target.iter_mut().zip(source.iter()) {
        *byte ^= *mask;
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: a failed known-answer test should abort loudly"
    )]

    use super::CbcMacV4;
    use alloc::vec::Vec;

    /// The generator's deterministic filler; see
    /// `crates/kmsrs-vectors/tools/vlmcsd_crypto_vectors.c`.
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

    /// Pinned against the vlmcsd reference at `70e0357`. The aligned lengths —
    /// 16, 32, 64 — are the ones that distinguish inclusive padding from the
    /// conditional kind, and 236 is `sizeof(REQUEST)`, the real v4 case.
    #[test]
    fn tags_match_the_reference_at_every_interesting_length() {
        let mac = CbcMacV4::new();
        for (len, expected) in [
            (0_usize, "d144963029e2bd12f9970c9f52b27f09"),
            (1, "8da56a4af5d5b69678c416232c96ba3b"),
            (15, "ec48ad9b4cd5e085edf6e928b63e2c33"),
            (16, "cf3c4c360d782dbc4144228b5d8b0b31"),
            (17, "2febe62404eb0a2975d81e6347badbc6"),
            (31, "bf1497dd037646c5b25129182cb4701f"),
            (32, "2cce2d78deaad7bd59606690323e228f"),
            (33, "f5c99987cb1f7cc092c27b5e50c075a0"),
            (64, "6a41216698f97e0902367e70385ddf01"),
            (236, "adf75b470cd6e8ed8b36bd3d5fae7554"),
        ] {
            let message = fill(len, 0x20);
            assert_eq!(hex::encode(mac.tag(&message)), expected, "length {len}");
        }
    }

    /// `CRY-003` (#42): the padding is unconditional. A 16-byte message and a
    /// 16-byte message followed by a full padding block must give the same tag —
    /// which is the same as saying the implementation appends that block itself.
    #[test]
    fn padding_is_appended_even_when_the_length_is_already_aligned() {
        let mac = CbcMacV4::new();
        let message = fill(16, 0x20);

        let mut explicitly_padded = message.clone();
        explicitly_padded.push(0x80);
        explicitly_padded.resize(32, 0);

        // The explicit form gets a *second* padding block of its own, so the
        // tags differ — but the aligned message's tag must not equal the tag of
        // the bare 16 bytes treated as one block, which is what a conditional
        // implementation would produce.
        assert_ne!(mac.tag(&message), mac.tag(&explicitly_padded));
        assert_eq!(
            hex::encode(mac.tag(&message)),
            "cf3c4c360d782dbc4144228b5d8b0b31"
        );
    }

    /// `CRY-004` (#43): the message is borrowed immutably, so there is nothing
    /// to write past. Stated as a test because the property is what the API
    /// shape buys, and an API change is what would lose it.
    #[test]
    fn the_message_is_not_modified_and_needs_no_slack() {
        let mac = CbcMacV4::new();
        // Exactly `sizeof(REQUEST)` bytes with nothing after them: under
        // vlmcsd's signature this call would write sixteen bytes past the end.
        let message = fill(236, 0x20);
        let original = message.clone();
        let tag = mac.tag(&message);
        assert_eq!(message, original);
        assert_eq!(hex::encode(tag), "adf75b470cd6e8ed8b36bd3d5fae7554");
    }

    /// Distinct messages give distinct tags at the boundaries where an
    /// off-by-one in the block loop would collide them.
    #[test]
    fn neighbouring_lengths_do_not_collide() {
        let mac = CbcMacV4::new();
        let mut seen = Vec::new();
        for len in 0_usize..64 {
            let tag = mac.tag(&fill(len, 0x20));
            assert!(
                !seen.contains(&tag),
                "length {len} collides with a shorter one"
            );
            seen.push(tag);
        }
    }
}

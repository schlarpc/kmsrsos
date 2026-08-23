//! CBC mode, the protocol's inclusive padding, and padding validation
//! (`CRY-005`, #44; `CRY-011`, #50; `CRY-012`, #51; `CRY-014`, #53).
//!
//! Three things here are not what a general-purpose CBC implementation would
//! do, and each is a protocol requirement rather than a shortcut.

use crate::rijndael::{BLOCK_LEN, KeySchedule};

/// Something was wrong with a buffer before any block was processed.
///
/// Every variant is reachable from the wire, which is the point: py-kms reaches
/// its AES implementation with attacker-chosen lengths and raises `IndexError`
/// from deep inside it, because `RequestV5`'s trailing field absorbs arbitrary
/// trailing bytes and hands them to the CBC decryptor (`CRY-014`, #53). Here the
/// lengths are checked before the cipher sees anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    /// The ciphertext was empty. CBC has nothing to do and the caller's framing
    /// is wrong.
    Empty,

    /// The ciphertext was not a whole number of blocks.
    NotBlockAligned {
        /// The offending length.
        len: usize,
    },

    /// The destination buffer could not hold the result.
    BufferTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },

    /// The padding on a decrypted plaintext was not well formed
    /// (`CRY-012`, #51).
    InvalidPadding,
}

impl core::fmt::Display for CipherError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("empty ciphertext"),
            Self::NotBlockAligned { len } => {
                write!(
                    f,
                    "ciphertext of {len} bytes is not a whole number of blocks"
                )
            }
            Self::BufferTooSmall { needed, available } => {
                write!(f, "buffer holds {available} bytes, needs {needed}")
            }
            Self::InvalidPadding => f.write_str("malformed padding"),
        }
    }
}

/// The initialisation vector for a CBC operation (`CRY-005`, #44).
///
/// A named type rather than an `Option<&[u8; 16]>` because [`Iv::Null`] is not
/// an absent IV — it is a deliberate protocol trick with a name, and the name
/// should appear at every call site that uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iv<'a> {
    /// A zero IV.
    ///
    /// The KMS server decrypts a v5/v6 request by starting *at the request's IV
    /// field* with a zero IV, over a 256-byte region. CBC chaining then makes
    /// blocks 2..16 — the `REQUEST` and its padding — come out correctly, while
    /// block 1 comes out as `D_k(IV_req)`. That value is not garbage to be
    /// discarded: it is the shared secret the salt proof and the response IV are
    /// built from, and recovering it is what proves to the client that the
    /// responder could decrypt the request (`CRY-008`, #47).
    ///
    /// The same trick runs in reverse on the way out. For v5 the server places
    /// the already-decrypted request IV at the front of the response and
    /// encrypts with a zero IV, so the first ciphertext block is
    /// `E_k(D_k(IV_req)) = IV_req` — the wire response IV is byte-identical to
    /// the request's, which is exactly what a genuine v5 client checks.
    Null,

    /// An explicit initialisation vector.
    Block(&'a [u8; BLOCK_LEN]),
}

impl Iv<'_> {
    /// The 16 bytes this IV contributes to the first block.
    const fn bytes(self) -> [u8; BLOCK_LEN] {
        match self {
            Self::Null => [0; BLOCK_LEN],
            Self::Block(block) => *block,
        }
    }
}

/// How many padding bytes a plaintext of `plaintext_len` bytes receives
/// (`CRY-011`, #50).
///
/// `pad = (!len & 15) + 1`, which is **inclusive**: a length that is already a
/// multiple of 16 gets a whole extra block of `0x10` rather than no padding.
/// That is not a quirk to be tolerated — the client computes the expected wire
/// size from it, and `vlmcs` prints `Size of RPC payload should be %u but is %u`
/// when a response disagrees.
#[must_use]
pub const fn padding_len(plaintext_len: usize) -> usize {
    // `!plaintext_len & 15` is at most 15, so the increment cannot overflow.
    ((!plaintext_len) & 15).saturating_add(1)
}

/// The ciphertext length a plaintext of `plaintext_len` bytes produces.
///
/// `None` only if the sum overflows `usize`, which no wire-derived length can
/// reach — but the check is here rather than an addition, because "cannot
/// happen" is not something this codebase asserts at runtime.
#[must_use]
pub const fn padded_len(plaintext_len: usize) -> Option<usize> {
    plaintext_len.checked_add(padding_len(plaintext_len))
}

/// CBC-decrypt `ciphertext` into `plaintext`.
///
/// The input is never modified (`ARCH-013`, #13). Decrypting in place would mean
/// mutating a buffer that arrived from the network, which destroys the original
/// bytes needed for a golden-vector comparison, for a log line, or for the
/// second parse attempt that a protocol-version fallback needs.
///
/// # Errors
///
/// Returns [`CipherError`] if the ciphertext is empty, is not a whole number of
/// blocks, or does not fit in `plaintext`. All three are checked before any
/// block reaches the cipher (`CRY-014`, #53).
pub fn decrypt(
    schedule: &KeySchedule,
    iv: Iv<'_>,
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<(), CipherError> {
    let blocks = ciphertext.chunks_exact(BLOCK_LEN);
    if !blocks.remainder().is_empty() {
        return Err(CipherError::NotBlockAligned {
            len: ciphertext.len(),
        });
    }
    if ciphertext.is_empty() {
        return Err(CipherError::Empty);
    }
    if plaintext.len() < ciphertext.len() {
        return Err(CipherError::BufferTooSmall {
            needed: ciphertext.len(),
            available: plaintext.len(),
        });
    }

    let mut chain = iv.bytes();
    for (cipher_block, plain_block) in blocks.zip(plaintext.chunks_exact_mut(BLOCK_LEN)) {
        let Ok(mut working) = <[u8; BLOCK_LEN]>::try_from(cipher_block) else {
            return Err(CipherError::NotBlockAligned {
                len: ciphertext.len(),
            });
        };
        let next_chain = working;
        schedule.decrypt_block(&mut working);
        xor_into(&mut working, &chain);
        if let Some(destination) = plain_block.first_chunk_mut::<BLOCK_LEN>() {
            *destination = working;
        }
        chain = next_chain;
    }
    Ok(())
}

/// Append inclusive padding to the first `plaintext_len` bytes of `buffer` and
/// CBC-encrypt the result in place, returning the ciphertext length.
///
/// In place is correct here and not a contradiction of `ARCH-013` (#13): the
/// buffer is the response the server is building, which it owns outright. The
/// rule is about not destroying bytes that arrived from somewhere else.
///
/// # Errors
///
/// Returns [`CipherError::BufferTooSmall`] if `buffer` cannot hold the plaintext
/// plus its padding.
pub fn encrypt_in_place(
    schedule: &KeySchedule,
    iv: Iv<'_>,
    buffer: &mut [u8],
    plaintext_len: usize,
) -> Result<usize, CipherError> {
    let needed = padded_len(plaintext_len).ok_or(CipherError::BufferTooSmall {
        needed: usize::MAX,
        available: buffer.len(),
    })?;
    let Some(region) = buffer.get_mut(..needed) else {
        return Err(CipherError::BufferTooSmall {
            needed,
            available: buffer.len(),
        });
    };

    // `padding_len` is in 1..=16, so the conversion cannot fail.
    let Ok(pad_byte) = u8::try_from(padding_len(plaintext_len)) else {
        return Err(CipherError::InvalidPadding);
    };
    for byte in region.get_mut(plaintext_len..).into_iter().flatten() {
        *byte = pad_byte;
    }

    let mut chain = iv.bytes();
    for chunk in region.chunks_exact_mut(BLOCK_LEN) {
        let Some(block) = chunk.first_chunk_mut::<BLOCK_LEN>() else {
            continue;
        };
        xor_into(block, &chain);
        schedule.encrypt_block(block);
        chain = *block;
    }
    Ok(needed)
}

/// Remove inclusive padding from a decrypted plaintext (`CRY-012`, #51).
///
/// Neither existing implementation checks inbound padding at all. py-kms's
/// stripper tests only `len % 16` and `numpads <= 16`, so a plaintext ending in
/// `0x00` makes its `val[:-0]` return an **empty** buffer — the entire plaintext
/// silently discarded, with no error anywhere. Requiring the final byte to be in
/// `1..=16` and every padding byte to equal it costs one pass and closes both
/// that and the general oracle of accepting arbitrary trailing bytes.
///
/// # Errors
///
/// Returns [`CipherError::InvalidPadding`] if the final byte is outside
/// `1..=16`, if it exceeds the plaintext length, or if the padding bytes are not
/// all equal to it. Returns [`CipherError::Empty`] for an empty plaintext.
pub fn strip_padding(plaintext: &[u8]) -> Result<&[u8], CipherError> {
    let Some(&declared) = plaintext.last() else {
        return Err(CipherError::Empty);
    };
    let pad = usize::from(declared);
    if pad == 0 || pad > BLOCK_LEN {
        return Err(CipherError::InvalidPadding);
    }
    let Some(body_len) = plaintext.len().checked_sub(pad) else {
        return Err(CipherError::InvalidPadding);
    };
    let Some((body, padding)) = plaintext.split_at_checked(body_len) else {
        return Err(CipherError::InvalidPadding);
    };
    if padding.iter().any(|byte| *byte != declared) {
        return Err(CipherError::InvalidPadding);
    }
    Ok(body)
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

    use super::{
        CipherError, Iv, decrypt, encrypt_in_place, padded_len, padding_len, strip_padding,
    };
    use crate::keys;
    use crate::rijndael::{BLOCK_LEN, KeySchedule};
    use alloc::vec;
    use alloc::vec::Vec;

    fn v5() -> KeySchedule {
        KeySchedule::aes128(&keys::V5)
    }

    /// The generator's deterministic filler, so the vectors below can be
    /// reproduced from `crates/kmsrs-vectors/tools/vlmcsd_crypto_vectors.c`.
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

    /// `CRY-011` (#50): the padding is inclusive, so an already-aligned length
    /// gains a whole extra block. Getting this wrong produces a response one
    /// block short, and `vlmcs` reports it as a size mismatch rather than as a
    /// crypto failure — which is a hard trail to follow.
    #[test]
    fn padding_is_inclusive() {
        assert_eq!(padding_len(0), 16);
        assert_eq!(padding_len(1), 15);
        assert_eq!(padding_len(15), 1);
        assert_eq!(padding_len(16), 16, "an aligned length gains a full block");
        assert_eq!(padding_len(17), 15);
        assert_eq!(padding_len(31), 1);
        assert_eq!(padding_len(32), 16);
        assert_eq!(
            padding_len(236),
            4,
            "sizeof(REQUEST) is 236 and 236 mod 16 = 12"
        );

        for len in 0_usize..200 {
            let padded = padded_len(len).unwrap();
            assert_eq!(padded.checked_rem(BLOCK_LEN), Some(0));
            assert!(padded > len, "padding is always at least one byte");
            assert!(padded.saturating_sub(len) <= BLOCK_LEN);
        }
    }

    /// Pinned against the vlmcsd reference, including the aligned case that
    /// gains a block and the unaligned one that does not.
    #[test]
    fn cbc_encryption_matches_the_reference() {
        let schedule = v5();
        let iv_bytes: [u8; BLOCK_LEN] = fill(BLOCK_LEN, 0x90).try_into().unwrap();

        for (iv, len, expected) in [
            (Iv::Null, 1_usize, "883d9b626b071d3d095c79e243e16042"),
            (
                Iv::Null,
                16,
                "f6d306b0ab65dc9ed86d752d8a9fd6e8521abde3fe1818a32711d018f0d5a638",
            ),
            (
                Iv::Null,
                20,
                "f6d306b0ab65dc9ed86d752d8a9fd6e8f42b75232fd8b894b6d3e62ab3ad9640",
            ),
            (Iv::Block(&iv_bytes), 1, "8af33d537dc5d4941f5ae32dcf8a2093"),
            (
                Iv::Block(&iv_bytes),
                16,
                "9e0db2c32cc1678bdbaa3c71431f729b3e33cb34db04f65c84f32b6dd9ebd17b",
            ),
            (
                Iv::Block(&iv_bytes),
                20,
                "9e0db2c32cc1678bdbaa3c71431f729bbb905dda0c761b07d193688094950245",
            ),
        ] {
            let mut buffer = vec![0_u8; 64];
            let plaintext = fill(len, 0x40);
            buffer.get_mut(..len).unwrap().copy_from_slice(&plaintext);

            let ciphertext_len = encrypt_in_place(&schedule, iv, &mut buffer, len).unwrap();
            assert_eq!(ciphertext_len, padded_len(len).unwrap());
            assert_eq!(
                hex::encode(buffer.get(..ciphertext_len).unwrap()),
                expected,
                "iv={iv:?} len={len}"
            );
        }
    }

    /// `CRY-005` (#44), the trick this whole module is shaped around: decrypting
    /// a 256-byte region with a null IV yields `D_k(IV_req)` in block 1 and the
    /// correct plaintext in blocks 2..16.
    #[test]
    fn null_iv_decryption_matches_the_reference() {
        let schedule = KeySchedule::aes128_tweaked_for_v6(&keys::V6);
        let ciphertext = fill(256, 0x55);
        assert_eq!(
            hex::encode(ciphertext.get(..32).unwrap()),
            "555c636a71787f868e959ca3aab1b8bfc7ced5dce3eaf1f800070e151c232a31"
        );

        let mut plaintext = vec![0_u8; 256];
        decrypt(&schedule, Iv::Null, &ciphertext, &mut plaintext).unwrap();

        assert_eq!(
            hex::encode(plaintext.get(..32).unwrap()),
            "eaf991cd9caf785096661dc03b222f5af90528264449fed0d93e9955a77a3c5d"
        );
        assert_eq!(
            hex::encode(plaintext.get(240..).unwrap()),
            "5aa0944ab7b89edccb421289db494c78"
        );
    }

    /// The v5 IV identity: with a null IV, `E_k(D_k(IV_req)) == IV_req`. This is
    /// what makes the wire response IV byte-identical to the request's, which is
    /// exactly what a genuine v5 client checks.
    #[test]
    fn the_null_iv_round_trip_reproduces_the_request_iv() {
        let schedule = v5();
        let request_iv: [u8; BLOCK_LEN] = fill(BLOCK_LEN, 0xA3).try_into().unwrap();

        // What the server recovers when it decrypts starting at the IV field.
        let mut recovered = vec![0_u8; BLOCK_LEN];
        decrypt(&schedule, Iv::Null, &request_iv, &mut recovered).unwrap();

        // Placing that at the front of the response and encrypting with a null
        // IV must reproduce the request IV byte for byte.
        let mut response = vec![0_u8; 64];
        response
            .get_mut(..BLOCK_LEN)
            .unwrap()
            .copy_from_slice(&recovered);
        encrypt_in_place(&schedule, Iv::Null, &mut response, BLOCK_LEN).unwrap();

        assert_eq!(response.get(..BLOCK_LEN).unwrap(), request_iv.as_slice());
    }

    /// `CRY-014` (#53): an attacker-chosen length must be refused before the
    /// cipher sees it. py-kms raises `IndexError` from inside its AES here.
    #[test]
    fn misaligned_and_empty_ciphertexts_are_refused_not_processed() {
        let schedule = v5();
        let mut plaintext = vec![0_u8; 64];

        assert_eq!(
            decrypt(&schedule, Iv::Null, &[], &mut plaintext),
            Err(CipherError::Empty)
        );
        for len in [1_usize, 15, 17, 31, 33, 63] {
            let ciphertext = vec![0_u8; len];
            assert_eq!(
                decrypt(&schedule, Iv::Null, &ciphertext, &mut plaintext),
                Err(CipherError::NotBlockAligned { len }),
                "a {len}-byte ciphertext must be refused"
            );
        }
    }

    #[test]
    fn an_undersized_destination_is_refused() {
        let schedule = v5();
        let ciphertext = vec![0_u8; 32];
        let mut plaintext = vec![0_u8; 16];
        assert_eq!(
            decrypt(&schedule, Iv::Null, &ciphertext, &mut plaintext),
            Err(CipherError::BufferTooSmall {
                needed: 32,
                available: 16
            })
        );

        let mut buffer = vec![0_u8; 20];
        assert_eq!(
            encrypt_in_place(&schedule, Iv::Null, &mut buffer, 20),
            Err(CipherError::BufferTooSmall {
                needed: 32,
                available: 20
            })
        );
    }

    /// `CRY-012` (#51). The first case is py-kms's exact bug: a plaintext ending
    /// in `0x00` makes its `val[:-0]` return an empty buffer, discarding
    /// everything with no error raised anywhere.
    #[test]
    fn padding_validation_rejects_what_py_kms_accepts() {
        let mut trailing_zero = vec![0xAB_u8; 32];
        *trailing_zero.last_mut().unwrap() = 0x00;
        assert_eq!(
            strip_padding(&trailing_zero),
            Err(CipherError::InvalidPadding),
            "a trailing 0x00 must be refused, not treated as zero padding"
        );

        // A declared length above the block size.
        let mut too_long = vec![0xAB_u8; 32];
        *too_long.last_mut().unwrap() = 17;
        assert_eq!(strip_padding(&too_long), Err(CipherError::InvalidPadding));

        // Padding bytes that disagree with the declared length.
        let mut inconsistent = vec![0xAB_u8; 32];
        for byte in inconsistent.get_mut(28..).unwrap() {
            *byte = 4;
        }
        *inconsistent.get_mut(29).unwrap() = 3;
        assert_eq!(
            strip_padding(&inconsistent),
            Err(CipherError::InvalidPadding)
        );

        // A declared length longer than the plaintext.
        assert_eq!(strip_padding(&[16_u8]), Err(CipherError::InvalidPadding));
        assert_eq!(strip_padding(&[]), Err(CipherError::Empty));
    }

    #[test]
    fn padding_validation_accepts_what_the_protocol_produces() {
        let schedule = v5();
        for len in 0_usize..48 {
            let mut buffer = vec![0_u8; 96];
            let plaintext = fill(len, 0x40);
            buffer.get_mut(..len).unwrap().copy_from_slice(&plaintext);

            let ciphertext_len = encrypt_in_place(&schedule, Iv::Null, &mut buffer, len).unwrap();
            let mut recovered = vec![0_u8; ciphertext_len];
            decrypt(
                &schedule,
                Iv::Null,
                buffer.get(..ciphertext_len).unwrap(),
                &mut recovered,
            )
            .unwrap();

            assert_eq!(strip_padding(&recovered).unwrap(), plaintext.as_slice());
        }
    }

    /// The input buffer must survive decryption unchanged (`ARCH-013`, #13).
    #[test]
    fn decryption_does_not_touch_its_input() {
        let schedule = v5();
        let ciphertext = fill(64, 0x11);
        let original = ciphertext.clone();
        let mut plaintext = vec![0_u8; 64];
        decrypt(&schedule, Iv::Null, &ciphertext, &mut plaintext).unwrap();
        assert_eq!(ciphertext, original);
    }
}

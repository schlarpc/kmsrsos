//! Rijndael with a 128-bit block and a 128- or 160-bit key, plus the tampered
//! key schedule the v6 protocol uses (`CRY-002`, #41).
//!
//! # The A8 exception
//!
//! Axiom A8 says reuse crates rather than reimplementing. This module and the
//! v4 MAC are the entire list of exceptions, and both are here because no
//! maintained Rust crate can do what the protocol requires:
//!
//! * **A 160-bit key.** Twenty key bytes gives `Nk = 5` and eleven rounds. AES
//!   standardised the three 128/192/256 cases and dropped the rest of Rijndael's
//!   parameter space; the `aes` crate implements AES, so it cannot do this.
//! * **A tampered schedule.** After a standard 128-bit expansion, the v6 variant
//!   XORs three bytes of the *expanded* key: `0x73` into the first byte of round
//!   key 4, `0x09` into round key 6, `0xE4` into round key 8. The result is not
//!   AES and no conforming implementation will produce it.
//!
//! radawson's fork is the cautionary tale the issue cites: it swapped in a real
//! crypto library, silently dropped the v6 tweaks, and nothing caught it —
//! because there were no tests. Hence the vector suite at the bottom of this
//! file, which pins all three schedules against the vlmcsd reference and pins
//! the untweaked case separately, so that "the tweak stopped being applied"
//! fails a test rather than producing plausible ciphertext.
//!
//! # About the lint relaxation below
//!
//! `ARCH-008` (#8) denies indexing and unchecked arithmetic workspace-wide,
//! because a length that came off the wire is the thing that panics or wraps.
//! Inside a block permutation there is no such length: every index is bounded by
//! a 16-byte state, by a 256-entry table indexed with a `u8`, or by a loop bound
//! derived from this module's own fixed-size arrays. Nothing here is
//! attacker-controlled — `cbc.rs` and `mac.rs` are where wire lengths arrive,
//! and the denials stay in force there.
//!
//! Written with `get(..).unwrap_or(0)` throughout, this code would trade a
//! compile-time-obvious bound for a silently wrong answer, and would stop
//! reading like FIPS-197 §5 — which is how it is checked.
//! The same applies to the two narrow casts in the compile-time table builders:
//! `TryFrom` and `From` are not usable in a `const fn`, and both casts are
//! between a `u8` and an index into a 256-entry array.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    reason = "no attacker-controlled index or length exists inside the block permutation; see the module docs"
)]

/// The block size. Rijndael allows others; every KMS use is 128-bit.
pub const BLOCK_LEN: usize = 16;

/// Words in the state, i.e. `BLOCK_LEN / 4`. Called `Nb` in FIPS-197.
const STATE_WORDS: usize = BLOCK_LEN / 4;

/// The largest number of rounds any schedule here uses: `Nk = 5` gives
/// `Nr = Nk + 6 = 11`.
const MAX_ROUNDS: usize = 11;

/// Round constants, `x^(i-1)` in GF(2^8), indexed from 1.
///
/// Index 0 is never used; it is present so the array is indexed by the round
/// number rather than by the round number minus one.
const ROUND_CONSTANTS: [u32; MAX_ROUNDS] = [
    0x0000_0000,
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1B00_0000,
    0x3600_0000,
];

/// Multiply by `x` in GF(2^8) modulo the AES polynomial `x^8 + x^4 + x^3 + x + 1`.
const fn xtime(byte: u8) -> u8 {
    // The shift is deliberately truncating: the bit shifted out is the one the
    // reduction puts back via 0x1B.
    let doubled = byte.wrapping_shl(1);
    if byte & 0x80 == 0 {
        doubled
    } else {
        doubled ^ 0x1B
    }
}

/// Multiply two elements of GF(2^8).
///
/// Used only to build the S-box at compile time, so its shape is chosen for
/// readability rather than for speed.
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0_u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    product
}

/// The multiplicative inverse in GF(2^8), with zero mapped to zero.
///
/// Found by search. This runs at compile time, so 65,536 steps cost nothing at
/// runtime, and a search is much harder to get subtly wrong than a transcribed
/// 256-entry table would be.
const fn gf_inverse(value: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    let mut candidate = 1_u8;
    while candidate != 0 {
        if gf_mul(value, candidate) == 1 {
            return candidate;
        }
        candidate += 1;
    }
    0
}

/// Build the AES substitution box from its definition: multiplicative inverse
/// followed by the FIPS-197 §5.1.1 affine transformation.
///
/// Generated rather than transcribed. 512 hand-copied hex bytes is 512 chances
/// to introduce a typo, and while the vector suite would catch one, not having
/// to rely on that is better.
const fn build_sbox() -> [u8; 256] {
    let mut table = [0_u8; 256];
    let mut index = 0_usize;
    while index < 256 {
        let inverse = gf_inverse(index as u8);
        table[index] = inverse
            ^ inverse.rotate_left(1)
            ^ inverse.rotate_left(2)
            ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4)
            ^ 0x63;
        index += 1;
    }
    table
}

/// Invert a permutation of the byte range.
const fn invert_permutation(forward: &[u8; 256]) -> [u8; 256] {
    let mut table = [0_u8; 256];
    let mut index = 0_usize;
    while index < 256 {
        table[forward[index] as usize] = index as u8;
        index += 1;
    }
    table
}

/// The AES substitution box.
const SBOX: [u8; 256] = build_sbox();

/// The inverse substitution box.
const INVERSE_SBOX: [u8; 256] = invert_permutation(&SBOX);

/// Apply the substitution box to each byte of a word.
const fn sub_word(word: u32) -> u32 {
    let bytes = word.to_be_bytes();
    u32::from_be_bytes([
        SBOX[bytes[0] as usize],
        SBOX[bytes[1] as usize],
        SBOX[bytes[2] as usize],
        SBOX[bytes[3] as usize],
    ])
}

/// An expanded Rijndael key (`CRY-016`, #55).
///
/// Expansion happens once, when the schedule is built, and never again. py-kms
/// recomputes it for every 16-byte block, which costs roughly 13 ms per 256-byte
/// CBC operation.
///
/// Every method takes `&self`. There is no interior mutability and no shared
/// cipher state to corrupt (`CRY-015`, #54) — py-kms's `AESModeOfOperation.aes`
/// is a *class* attribute, so a concurrent v5 request can flip its `v6` flag
/// mid-v6-encryption and emit ciphertext that mixes tweaked and untweaked
/// rounds. That failure is intermittent, load-dependent, and looks like a
/// flaky client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySchedule {
    /// One 16-byte round key per round, plus the initial whitening key.
    round_keys: [[u8; BLOCK_LEN]; MAX_ROUNDS + 1],
    /// Number of rounds: 10 for a 128-bit key, 11 for a 160-bit key.
    rounds: usize,
}

impl KeySchedule {
    /// Expand a 128-bit key, exactly as AES-128 does.
    #[must_use]
    pub fn aes128(key: &[u8; 16]) -> Self {
        Self::expand(key, 4)
    }

    /// Expand a 160-bit key: `Nk = 5`, eleven rounds.
    ///
    /// This is the case that puts the module outside what any AES library can
    /// do. The expansion itself is the ordinary Rijndael one — FIPS-197's extra
    /// `SubWord` step applies only when `Nk > 6`, so `Nk = 5` never reaches it.
    #[must_use]
    pub fn rijndael160(key: &[u8; 20]) -> Self {
        Self::expand(key, 5)
    }

    /// Expand a 128-bit key and then tamper with three bytes of the result, as
    /// the v6 protocol requires (`CRY-002`, #41).
    ///
    /// The three XORs land on the first byte of round keys 4, 6 and 8 — byte
    /// offsets 64, 96 and 128 of the expanded key. They are applied *after* a
    /// complete standard expansion, so they do not propagate: only those three
    /// round keys differ from AES-128's.
    #[must_use]
    pub fn aes128_tweaked_for_v6(key: &[u8; 16]) -> Self {
        let mut schedule = Self::expand(key, 4);
        schedule.round_keys[4][0] ^= 0x73;
        schedule.round_keys[6][0] ^= 0x09;
        schedule.round_keys[8][0] ^= 0xE4;
        schedule
    }

    /// The number of rounds this schedule performs.
    #[must_use]
    pub const fn rounds(&self) -> usize {
        self.rounds
    }

    /// The standard Rijndael key expansion (FIPS-197 §5.2).
    ///
    /// Private, and reachable only through the three constructors above, so a
    /// key length Rijndael does not define is unrepresentable rather than
    /// rejected at runtime (axiom A2).
    fn expand(key: &[u8], key_words: usize) -> Self {
        let rounds = key_words + 6;
        let total_words = STATE_WORDS * (rounds + 1);

        let mut words = [0_u32; STATE_WORDS * (MAX_ROUNDS + 1)];
        for (index, chunk) in key.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        for index in key_words..total_words {
            let mut temp = words[index - 1];
            if index % key_words == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ ROUND_CONSTANTS[index / key_words];
            }
            words[index] = words[index - key_words] ^ temp;
        }

        let mut round_keys = [[0_u8; BLOCK_LEN]; MAX_ROUNDS + 1];
        for round in 0..=rounds {
            for column in 0..STATE_WORDS {
                let bytes = words[round * STATE_WORDS + column].to_be_bytes();
                round_keys[round][column * 4..column * 4 + 4].copy_from_slice(&bytes);
            }
        }

        Self { round_keys, rounds }
    }

    /// Encrypt one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        add_round_key(block, &self.round_keys[0]);

        for round in 1..self.rounds {
            substitute(block, &SBOX);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.round_keys[round]);
        }

        substitute(block, &SBOX);
        shift_rows(block);
        add_round_key(block, &self.round_keys[self.rounds]);
    }

    /// Decrypt one block in place.
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        add_round_key(block, &self.round_keys[self.rounds]);

        for round in (1..self.rounds).rev() {
            inverse_shift_rows(block);
            substitute(block, &INVERSE_SBOX);
            add_round_key(block, &self.round_keys[round]);
            inverse_mix_columns(block);
        }

        inverse_shift_rows(block);
        substitute(block, &INVERSE_SBOX);
        add_round_key(block, &self.round_keys[0]);
    }
}

/// XOR a round key into the state (FIPS-197 §5.1.4).
fn add_round_key(state: &mut [u8; BLOCK_LEN], round_key: &[u8; BLOCK_LEN]) {
    for (byte, key_byte) in state.iter_mut().zip(round_key.iter()) {
        *byte ^= *key_byte;
    }
}

/// Apply a substitution box to every byte of the state.
fn substitute(state: &mut [u8; BLOCK_LEN], table: &[u8; 256]) {
    for byte in state.iter_mut() {
        *byte = table[*byte as usize];
    }
}

/// Cyclically shift row `r` left by `r` columns (FIPS-197 §5.1.2).
///
/// The state is column-major: byte `4c + r` is row `r` of column `c`.
fn shift_rows(state: &mut [u8; BLOCK_LEN]) {
    let source = *state;
    for (index, byte) in state.iter_mut().enumerate() {
        let row = index & 3;
        let column = index >> 2;
        *byte = source[(((column + row) & 3) << 2) | row];
    }
}

/// The inverse of [`shift_rows`].
fn inverse_shift_rows(state: &mut [u8; BLOCK_LEN]) {
    let source = *state;
    for (index, byte) in state.iter_mut().enumerate() {
        let row = index & 3;
        let column = index >> 2;
        *byte = source[((((column + 4) - row) & 3) << 2) | row];
    }
}

/// Treat each column as a polynomial over GF(2^8) and multiply by the fixed
/// polynomial `{03}x^3 + {01}x^2 + {01}x + {02}` (FIPS-197 §5.1.3).
fn mix_columns(state: &mut [u8; BLOCK_LEN]) {
    for column in state.chunks_exact_mut(4) {
        let [a0, a1, a2, a3] = [column[0], column[1], column[2], column[3]];
        column[0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        column[1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        column[2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        column[3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

/// The inverse of [`mix_columns`]: multiply by `{0b}x^3 + {0d}x^2 + {09}x + {0e}`.
fn inverse_mix_columns(state: &mut [u8; BLOCK_LEN]) {
    for column in state.chunks_exact_mut(4) {
        let [a0, a1, a2, a3] = [column[0], column[1], column[2], column[3]];
        column[0] = gf_mul(a0, 0x0E) ^ gf_mul(a1, 0x0B) ^ gf_mul(a2, 0x0D) ^ gf_mul(a3, 0x09);
        column[1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0E) ^ gf_mul(a2, 0x0B) ^ gf_mul(a3, 0x0D);
        column[2] = gf_mul(a0, 0x0D) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0E) ^ gf_mul(a3, 0x0B);
        column[3] = gf_mul(a0, 0x0B) ^ gf_mul(a1, 0x0D) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0E);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: a failed known-answer test should abort loudly"
    )]

    use super::{BLOCK_LEN, INVERSE_SBOX, KeySchedule, SBOX};
    use crate::keys;

    /// Parse a hex literal into a block. Vectors are written as hex so they can
    /// be compared against the generator's output by eye.
    fn block(hex_text: &str) -> [u8; BLOCK_LEN] {
        let mut bytes = [0_u8; BLOCK_LEN];
        hex::decode_to_slice(hex_text, &mut bytes).unwrap();
        bytes
    }

    fn to_hex(bytes: &[u8]) -> alloc::string::String {
        hex::encode(bytes)
    }

    /// The generated S-box must match the published table. Four spot values
    /// from FIPS-197 §5.1.1, plus the two structural properties that pin the
    /// whole table: it is a permutation, and it inverts.
    #[test]
    fn the_generated_sbox_matches_the_published_one() {
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x01], 0x7C);
        assert_eq!(SBOX[0x53], 0xED);
        assert_eq!(SBOX[0xFF], 0x16);

        let mut seen = [false; 256];
        for value in SBOX {
            assert!(!seen[value as usize], "{value:#04x} appears twice");
            seen[value as usize] = true;
        }

        for input in 0..=255_u8 {
            assert_eq!(INVERSE_SBOX[SBOX[input as usize] as usize], input);
        }
    }

    /// FIPS-197 §C.1, the canonical AES-128 vector. This one is independent of
    /// the reference implementation, so it validates the vector generator as
    /// much as it validates this code.
    #[test]
    fn fips197_c1_aes128() {
        let key: [u8; 16] = core::array::from_fn(|index| u8::try_from(index).unwrap_or(0));
        let schedule = KeySchedule::aes128(&key);
        assert_eq!(schedule.rounds(), 10);

        let mut state = block("00112233445566778899aabbccddeeff");
        schedule.encrypt_block(&mut state);
        assert_eq!(to_hex(&state), "69c4e0d86a7b0430d8cdb78070b4c55a");

        schedule.decrypt_block(&mut state);
        assert_eq!(to_hex(&state), "00112233445566778899aabbccddeeff");
    }

    /// FIPS-197 §B, the worked example with a different key.
    #[test]
    fn fips197_appendix_b_aes128() {
        let key = block("2b7e151628aed2a6abf7158809cf4f3c");
        let schedule = KeySchedule::aes128(&key);
        let mut state = block("3243f6a8885a308d313198a2e0370734");
        schedule.encrypt_block(&mut state);
        assert_eq!(to_hex(&state), "3925841d02dc09fbdc118597196a0b32");
    }

    /// The 160-bit case, which no AES library can perform and for which no FIPS
    /// vector exists. Pinned against the vlmcsd reference at 70e0357 via
    /// `crates/kmsrs-vectors/tools/vlmcsd_crypto_vectors.c`, whose build is
    /// validated by the FIPS-197 vector above.
    #[test]
    fn rijndael160_matches_the_reference() {
        let schedule = KeySchedule::rijndael160(&keys::V4);
        assert_eq!(schedule.rounds(), 11, "Nk = 5 gives Nr = 11");

        let mut state = [0_u8; BLOCK_LEN];
        schedule.encrypt_block(&mut state);
        assert_eq!(to_hex(&state), "933030f10e2e7782b80915d5778a4957");

        let mut state = [0_u8; BLOCK_LEN];
        schedule.decrypt_block(&mut state);
        assert_eq!(to_hex(&state), "ed598a4eb5901e33dd8ca442e4eb4b06");

        let mut state = block("11181f262d343b424a51585f666d747b");
        schedule.encrypt_block(&mut state);
        assert_eq!(to_hex(&state), "30ee0b97ee536dd00d33028f4980f75f");
        schedule.decrypt_block(&mut state);
        assert_eq!(to_hex(&state), "11181f262d343b424a51585f666d747b");
    }

    /// The v5 key with a standard schedule.
    #[test]
    fn aes128_v5_matches_the_reference() {
        let schedule = KeySchedule::aes128(&keys::V5);
        assert_eq!(schedule.rounds(), 10);

        let mut state = [0_u8; BLOCK_LEN];
        schedule.encrypt_block(&mut state);
        assert_eq!(to_hex(&state), "ec7c7e75b1923978eac4b2d2260235d5");

        let mut state = [0_u8; BLOCK_LEN];
        schedule.decrypt_block(&mut state);
        assert_eq!(to_hex(&state), "9f1680f29feed1274e875c9d86d107af");
    }

    /// The tweaked v6 schedule, and — separately — the same key *without* the
    /// tweak. The second half is the test radawson's fork did not have: a
    /// silently dropped tweak still produces plausible ciphertext, so only a
    /// vector distinguishes them.
    #[test]
    fn the_v6_tweak_changes_the_ciphertext_and_is_pinned() {
        let tweaked = KeySchedule::aes128_tweaked_for_v6(&keys::V6);
        let untweaked = KeySchedule::aes128(&keys::V6);
        assert_ne!(tweaked, untweaked, "the tweak must alter the schedule");

        let mut state = [0_u8; BLOCK_LEN];
        tweaked.encrypt_block(&mut state);
        assert_eq!(to_hex(&state), "8ca59de0c483c04aa7026a22d6dd208e");

        let mut state = [0_u8; BLOCK_LEN];
        untweaked.encrypt_block(&mut state);
        assert_eq!(to_hex(&state), "b4c3c015f6fb320c9b64aecd52fa58c8");

        let mut state = block("11181f262d343b424a51585f666d747b");
        tweaked.encrypt_block(&mut state);
        assert_eq!(to_hex(&state), "212fa596e6c0b23f075c652fb8c71d65");
        tweaked.decrypt_block(&mut state);
        assert_eq!(to_hex(&state), "11181f262d343b424a51585f666d747b");
    }

    /// The tweak lands on exactly three bytes of the expanded key, and on the
    /// first byte of round keys 4, 6 and 8 specifically. Stated as a test
    /// because "three bytes somewhere" would still pass the vector above if the
    /// offsets were computed differently but happened to coincide.
    #[test]
    fn the_v6_tweak_touches_only_round_keys_four_six_and_eight() {
        let tweaked = KeySchedule::aes128_tweaked_for_v6(&keys::V6);
        let untweaked = KeySchedule::aes128(&keys::V6);

        let differing: alloc::vec::Vec<usize> = (0..=untweaked.rounds())
            .filter(|round| tweaked.round_keys[*round] != untweaked.round_keys[*round])
            .collect();
        assert_eq!(differing, alloc::vec![4, 6, 8]);

        for (round, delta) in [(4_usize, 0x73_u8), (6, 0x09), (8, 0xE4)] {
            assert_eq!(
                tweaked.round_keys[round][0] ^ untweaked.round_keys[round][0],
                delta
            );
            assert_eq!(
                tweaked.round_keys[round][1..],
                untweaked.round_keys[round][1..],
                "only the first byte of round key {round} may change"
            );
        }
    }

    /// Every schedule must round-trip every block. Cheap, and it catches the
    /// class of bug where encryption is right and the inverse cipher is not.
    #[test]
    fn every_schedule_round_trips() {
        let schedules = [
            KeySchedule::aes128(&keys::V5),
            KeySchedule::aes128_tweaked_for_v6(&keys::V6),
            KeySchedule::rijndael160(&keys::V4),
        ];
        for schedule in &schedules {
            for seed in 0..64_u8 {
                let original: [u8; BLOCK_LEN] = core::array::from_fn(|index| {
                    seed.wrapping_mul(31)
                        .wrapping_add(u8::try_from(index).unwrap_or(0).wrapping_mul(7))
                });
                let mut state = original;
                schedule.encrypt_block(&mut state);
                assert_ne!(state, original, "encryption must change the block");
                schedule.decrypt_block(&mut state);
                assert_eq!(state, original);
            }
        }
    }

    /// `CRY-015` (#54): interleaving v5 and v6 work through two schedules must
    /// give each the same answer it would have got alone.
    ///
    /// This is py-kms's failure shape written down. Its `AESModeOfOperation.aes`
    /// is a *class* attribute, so a concurrent v5 request flips the `v6` flag
    /// part-way through a v6 encryption and the output mixes tweaked and
    /// untweaked rounds — an intermittent, load-dependent activation failure
    /// that only appears on mixed workloads. Here the schedules are separate
    /// immutable values, so the interleaving is a no-op; the test exists so it
    /// stays that way.
    #[test]
    fn interleaved_use_of_two_schedules_does_not_contaminate_either() {
        let v5 = KeySchedule::aes128(&keys::V5);
        let v6 = KeySchedule::aes128_tweaked_for_v6(&keys::V6);
        let sample = block("11181f262d343b424a51585f666d747b");

        let mut alone_v5 = sample;
        v5.encrypt_block(&mut alone_v5);
        let mut alone_v6 = sample;
        v6.encrypt_block(&mut alone_v6);

        for _ in 0..32 {
            let mut interleaved_v6 = sample;
            v6.encrypt_block(&mut interleaved_v6);
            let mut interleaved_v5 = sample;
            v5.encrypt_block(&mut interleaved_v5);
            assert_eq!(interleaved_v5, alone_v5);
            assert_eq!(interleaved_v6, alone_v6);
        }
    }

    /// `CRY-015` (#54), the structural half: a schedule with interior mutability
    /// would not be `Sync`, so this fails to compile rather than fails a run.
    const _: () = {
        const fn assert_shareable<T: Sync + Send>() {}
        assert_shareable::<KeySchedule>();
    };

    /// The last round key differs from the first: a schedule that silently
    /// failed to expand would repeat the key and still round-trip.
    #[test]
    fn expansion_actually_expands() {
        for schedule in [
            KeySchedule::aes128(&keys::V5),
            KeySchedule::rijndael160(&keys::V4),
        ] {
            let last = schedule.round_keys[schedule.rounds()];
            assert_ne!(last, schedule.round_keys[0]);
            assert_ne!(last, [0_u8; BLOCK_LEN]);
        }
        // Pinned against the reference so a wrong Rcon index or a wrong
        // `Nk` would be caught at the schedule rather than only at the block.
        assert_eq!(
            to_hex(&KeySchedule::rijndael160(&keys::V4).round_keys[11]),
            "4a7d08d621ed8fd1454df13ba968579d"
        );
        assert_eq!(
            to_hex(&KeySchedule::aes128(&keys::V5).round_keys[10]),
            "aa20a23d6a7693cd0c7eb589e541336f"
        );
    }
}

//! The v6 time-slot key derivation and HMAC truncation (`CRY-009`, #48;
//! `CRY-010`, #49).
//!
//! v6 adds a keyed tag to the response, and the key is derived from a
//! timestamp. Two properties of that derivation matter more than the arithmetic:
//!
//! * **The timestamp is the client's**, taken from the request and echoed into
//!   the response, not read from the server's clock. A correct host therefore
//!   needs no accurate real-time clock, which is what makes the Hermit target
//!   viable at one-second RTC granularity with no NTP (`ARCH-004`, #4).
//! * **The slot is coarse.** `TIME_C1` is about 4.11 hours. It is obfuscation,
//!   not authentication — the key is derived from a value the client already
//!   knows, under an algorithm compiled into every client.
//!
//! Hashing the slot with SHA-256 before use is what stops the timestamp being
//! obvious in the key; it adds nothing cryptographically.
//!
//! # The tolerance retries are vestigial
//!
//! vlmcsd's comment says "request and response time must match +/- 1 slot", and
//! its verifier retries with tolerances -1, 0 and +1. Neither statement survives
//! reading the arithmetic:
//!
//! * The offset adds `tolerance * TIME_C1` to a value that has already been
//!   scaled by `TIME_C2`. One slot apart differs by `TIME_C2`, not by `TIME_C1`,
//!   and the two constants are different numbers — so an offset of +1 does not
//!   produce the neighbouring slot's key. It produces an unrelated one.
//! * It would not matter if it did. `CreateV6Hmac` reads the timestamp out of
//!   the **response** buffer in both roles, and the response echoes the
//!   request's timestamp verbatim (`KMS-012`, #28). Client and server therefore
//!   always derive from the same 64-bit value, tolerance 0 always matches, and
//!   the retries never fire.
//!
//! [`verify`] tries all three anyway, because a diagnostic client should behave
//! the way the reference does rather than the way the reference documents.
//! [`SlotOffset`]'s variant names describe the intent; the tests pin the
//! behaviour.

use crate::hash::{hmac_sha256, sha256};

/// One time slot, in `FILETIME` ticks: about 4.11 hours.
const TIME_C1: u64 = 0x0000_0022_8168_89BD;

/// Multiplier applied to the slot number.
const TIME_C2: u64 = 0x0000_0020_8CBA_B5ED;

/// Additive constant.
const TIME_C3: u64 = 0x3156_CD5A_C628_477A;

/// Length of the tag that goes on the wire: the *last* half of the digest.
pub const TAG_LEN: usize = 16;

// A zero here would make the slot division a panic. It is a literal constant, so
// this is settled at compile time rather than checked at run time
// (`ID-015`, #120).
const _: () = assert!(TIME_C1 != 0);

/// Which of the three acceptable slots to derive a key for (`CRY-009`, #48).
///
/// An enum rather than an `i8` because only three values are meaningful and the
/// two roles are asymmetric: a server *creating* a response always uses
/// [`SlotOffset::Current`], while a client *verifying* one tries all three. A
/// numeric parameter invites a fourth value that no counterpart would accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotOffset {
    /// The intended meaning is "one slot earlier". See the module docs: the
    /// arithmetic does not actually produce the previous slot's key.
    Previous,
    /// The slot the timestamp falls in. The only offset used when creating a
    /// response, and — because the response echoes the request timestamp — the
    /// only one that ever matches.
    Current,
    /// The intended meaning is "one slot later". See [`SlotOffset::Previous`].
    Next,
}

impl SlotOffset {
    /// Every offset a verifier must try, in the order vlmcsd tries them.
    pub const ALL: [Self; 3] = [Self::Previous, Self::Current, Self::Next];

    /// The tick adjustment this offset applies.
    ///
    /// The negative case wraps, matching the reference exactly: in C the
    /// `int_fast8_t` tolerance is converted to `unsigned long long` before the
    /// multiply, so `-1 * TIME_C1` is `TIME_C1`'s two's-complement negation.
    const fn tick_adjustment(self) -> u64 {
        match self {
            Self::Previous => TIME_C1.wrapping_neg(),
            Self::Current => 0,
            Self::Next => TIME_C1,
        }
    }
}

/// The slot value a timestamp falls in.
///
/// `slot = client_time / TIME_C1 * TIME_C2 + TIME_C3 + offset * TIME_C1`,
/// evaluated left to right and wrapping at 64 bits, as the reference does.
#[must_use]
pub fn time_slot(client_time_ticks: u64, offset: SlotOffset) -> u64 {
    // `TIME_C1` is a non-zero constant — asserted above — so the fallback is
    // unreachable. `checked_div` rather than `/` because ARCH-008 (#8) denies
    // the operator outright, and a divisor that is only *usually* non-zero is
    // exactly the bug that denial exists to prevent.
    let slot_number = client_time_ticks.checked_div(TIME_C1).unwrap_or(0);
    slot_number
        .wrapping_mul(TIME_C2)
        .wrapping_add(TIME_C3)
        .wrapping_add(offset.tick_adjustment())
}

/// The HMAC key for a timestamp's slot: the **last** 16 bytes of the SHA-256 of
/// the slot value, little-endian.
#[must_use]
pub fn time_slot_key(client_time_ticks: u64, offset: SlotOffset) -> [u8; TAG_LEN] {
    last_half(&sha256(&time_slot(client_time_ticks, offset).to_le_bytes()))
}

/// The last 16 bytes of a 32-byte digest.
///
/// Both the key derivation and the tag take the *second* half, which is the
/// unusual choice and the one an implementation drifts away from. Naming it once
/// means there is one place to be wrong rather than two.
fn last_half(digest: &[u8; crate::hash::DIGEST_LEN]) -> [u8; TAG_LEN] {
    digest
        .last_chunk::<TAG_LEN>()
        .copied()
        .unwrap_or([0_u8; TAG_LEN])
}

/// The v6 response tag over `message` (`CRY-010`, #49).
///
/// `message` is the part of the response that is about to be encrypted, from the
/// response IV up to but not including the tag field itself. The tag is the
/// **last** 16 bytes of the HMAC-SHA256 result — not the first, which is the
/// natural truncation and the wrong one.
#[must_use]
pub fn tag(client_time_ticks: u64, offset: SlotOffset, message: &[u8]) -> [u8; TAG_LEN] {
    let key = time_slot_key(client_time_ticks, offset);
    last_half(&hmac_sha256(&key, message))
}

/// Whether `candidate` is the tag over `message` for any acceptable slot.
///
/// Used by the diagnostic client (`CLI-003`, #209). Returns which offset
/// matched, because "it verified, but only against the previous slot" is a
/// clock-skew observation worth logging (`POL-011`, #99).
#[must_use]
pub fn verify(
    client_time_ticks: u64,
    message: &[u8],
    candidate: &[u8; TAG_LEN],
) -> Option<SlotOffset> {
    SlotOffset::ALL
        .into_iter()
        .find(|offset| tag(client_time_ticks, *offset, message) == *candidate)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: a failed known-answer test should abort loudly"
    )]

    use super::{SlotOffset, TAG_LEN, TIME_C1, tag, time_slot, time_slot_key, verify};
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

    /// `CRY-019` (#58) asks specifically for the derivation *across slot
    /// boundaries*, because an off-by-one there is invisible for four hours at a
    /// time and then produces a tag the client rejects.
    ///
    /// `TIME_C1 - 1` and `TIME_C1` straddle the first boundary. Values computed
    /// independently with Python's `hashlib`, so this checks the arithmetic and
    /// the digest against something that shares no code with the crate.
    #[test]
    fn the_slot_changes_exactly_at_the_boundary() {
        assert_eq!(time_slot(0, SlotOffset::Current), 0x3156_cd5a_c628_477a);
        assert_eq!(time_slot(1, SlotOffset::Current), 0x3156_cd5a_c628_477a);
        assert_eq!(
            time_slot(TIME_C1 - 1, SlotOffset::Current),
            0x3156_cd5a_c628_477a,
            "the last tick of slot 0 is still slot 0"
        );
        assert_eq!(
            time_slot(TIME_C1, SlotOffset::Current),
            0x3156_cd7b_52e2_fd67,
            "the first tick of slot 1 must move"
        );
        assert_eq!(
            time_slot(TIME_C1 + 1, SlotOffset::Current),
            0x3156_cd7b_52e2_fd67
        );
    }

    /// The tolerance offsets do **not** produce neighbouring slots' keys, and
    /// this test says so deliberately rather than by omission.
    ///
    /// vlmcsd's comment claims request and response times must match within one
    /// slot, and its verifier retries -1/0/+1 on that basis. But the offset adds
    /// `tolerance * TIME_C1` to a value already scaled by `TIME_C2`, and one
    /// slot apart differs by `TIME_C2`. Reproducing the arithmetic exactly is
    /// what matters for compatibility; reproducing the belief about it is not.
    #[test]
    fn tolerance_offsets_are_not_neighbouring_slots() {
        let in_slot_zero = TIME_C1 - 1;
        let in_slot_one = TIME_C1;

        assert_ne!(
            time_slot(in_slot_zero, SlotOffset::Next),
            time_slot(in_slot_one, SlotOffset::Current),
            "if these were ever equal, TIME_C1 and TIME_C2 would have to match"
        );
        assert_ne!(
            time_slot(in_slot_one, SlotOffset::Previous),
            time_slot(in_slot_zero, SlotOffset::Current)
        );

        // What the offsets actually do: shift by TIME_C1 in the scaled space.
        assert_eq!(
            time_slot(in_slot_zero, SlotOffset::Next),
            time_slot(in_slot_zero, SlotOffset::Current).wrapping_add(TIME_C1)
        );
        assert_eq!(
            time_slot(in_slot_zero, SlotOffset::Previous),
            time_slot(in_slot_zero, SlotOffset::Current).wrapping_sub(TIME_C1)
        );

        // And the three keys are distinct, so a verifier that tries all three is
        // trying three different things rather than the same one three times.
        let keys = SlotOffset::ALL.map(|offset| time_slot_key(in_slot_zero, offset));
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    /// The consequence of the above: because the response echoes the request
    /// timestamp verbatim, both sides derive from the same value and tolerance 0
    /// always matches. This is the case that actually happens on every request.
    #[test]
    fn the_echoed_timestamp_makes_the_current_slot_always_match() {
        let message = fill(148, 0x60);
        for ticks in [0_u64, 1, TIME_C1 - 1, TIME_C1, 133_000_000_000_000_000] {
            let created = tag(ticks, SlotOffset::Current, &message);
            assert_eq!(
                verify(ticks, &message, &created),
                Some(SlotOffset::Current),
                "at {ticks} the current slot must be the one that matches"
            );
        }
    }

    /// Keys pinned against an independent computation.
    #[test]
    fn derived_keys_match_the_reference() {
        for (ticks, offset, expected) in [
            (
                0_u64,
                SlotOffset::Previous,
                "1aa9b36f2b1063e4bda3de2e21a87cd2",
            ),
            (0, SlotOffset::Current, "ac0c6f55aa8cabc264c0642eb961540a"),
            (0, SlotOffset::Next, "1c72d81b00a9c71d384841db28741721"),
            (
                TIME_C1,
                SlotOffset::Current,
                "0ddcef9198c7944acdd48f5dbbb4df48",
            ),
            (
                133_000_000_000_000_000,
                SlotOffset::Current,
                "1c798822069eb63898005602d3d7f538",
            ),
            (
                133_000_000_000_000_000,
                SlotOffset::Previous,
                "8d7923cc74499b5178577398887d528e",
            ),
            (
                133_000_000_000_000_000,
                SlotOffset::Next,
                "1c3a25a7a5d3bcf1cd8cdbec15cdd65f",
            ),
        ] {
            assert_eq!(
                hex::encode(time_slot_key(ticks, offset)),
                expected,
                "ticks={ticks} offset={offset:?}"
            );
        }
    }

    /// `CRY-010` (#49): the tag is the **last** 16 bytes of the HMAC, not the
    /// first. Truncating from the wrong end produces a tag of the right length
    /// that every client rejects, and nothing in the exchange says why.
    #[test]
    fn the_tag_is_the_last_half_of_the_digest() {
        let message = fill(148, 0x60);
        let ticks = 133_000_000_000_000_000_u64;
        assert_eq!(
            hex::encode(tag(ticks, SlotOffset::Current, &message)),
            "99e576f4327df13ed9e546f96388931b"
        );
        // The full digest, for contrast: the first half must not be what ships.
        let key = time_slot_key(ticks, SlotOffset::Current);
        let full = crate::hash::hmac_sha256(&key, &message);
        assert_eq!(
            hex::encode(full),
            "de5c1b3e6dd9b724dde745f5fef4fe5e99e576f4327df13ed9e546f96388931b"
        );
        assert_ne!(
            tag(ticks, SlotOffset::Current, &message).as_slice(),
            full.get(..TAG_LEN).unwrap()
        );
    }

    /// A server creates with `Current`; a verifier accepts any of the three.
    #[test]
    fn verification_accepts_all_three_slots_and_reports_which() {
        let message = fill(64, 0x11);
        let ticks = 133_000_000_000_000_000_u64;

        for offset in SlotOffset::ALL {
            let candidate = tag(ticks, offset, &message);
            assert_eq!(verify(ticks, &message, &candidate), Some(offset));
        }

        assert_eq!(verify(ticks, &message, &[0_u8; TAG_LEN]), None);

        // A timestamp two slots away must not verify: the window is one slot
        // either side, not "close enough".
        let far = ticks.wrapping_add(TIME_C1.wrapping_mul(3));
        let candidate = tag(ticks, SlotOffset::Current, &message);
        assert_eq!(verify(far, &message, &candidate), None);
    }

    /// A different message under the same key must give a different tag —
    /// otherwise the tag is not a function of the response at all.
    #[test]
    fn the_tag_covers_the_message() {
        let ticks = 133_000_000_000_000_000_u64;
        let first = tag(ticks, SlotOffset::Current, &fill(64, 0x11));
        let second = tag(ticks, SlotOffset::Current, &fill(64, 0x12));
        assert_ne!(first, second);
        // ...and so does the length.
        assert_ne!(first, tag(ticks, SlotOffset::Current, &fill(65, 0x11)));
    }

    /// Extreme timestamps arrive from the wire and must not panic
    /// (`SEC-003`, #195).
    #[test]
    fn extreme_timestamps_do_not_panic() {
        for ticks in [0_u64, 1, u64::MAX, u64::MAX - 1, TIME_C1, TIME_C1 - 1] {
            for offset in SlotOffset::ALL {
                let _ = time_slot(ticks, offset);
                let _ = time_slot_key(ticks, offset);
                let _ = tag(ticks, offset, b"message");
            }
        }
    }
}

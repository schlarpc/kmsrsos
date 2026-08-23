//! Time as a value, not as something the core is allowed to read
//! (`ARCH-004`, #4).
//!
//! Two clocks exist here and they are deliberately different types, because
//! they answer different questions and one of them is untrustworthy:
//!
//! * [`Instant`] is a monotonic tick count. Timeouts, rate-limit buckets and
//!   CMID expiry are measured with it. It never goes backwards.
//! * [`FileTime`] is a wall-clock reading in the encoding the KMS protocol
//!   uses — 100-nanosecond ticks since 1601-01-01 UTC, which is Windows'
//!   `FILETIME`. It can jump in either direction, so nothing may *depend* on it
//!   for correctness.
//!
//! The second point is load-bearing rather than fastidious. The v6 HMAC key
//! derives from the FILETIME the *client* sent, not from one the server reads
//! (`CRY-009`, #48), so a correct host needs no accurate real-time clock at
//! all. That is what makes Hermit viable, where `SystemTime` is a single CMOS
//! read plus local ticks: one-second granularity, no NTP, no slew, and it
//! drifts (`OS-007`, #258). A design that authenticated against the server's
//! own clock would fail there and nowhere else.
//!
//! Every conversion is checked. `FILETIME` spans about 58,000 years and Unix
//! time is signed, so the interesting values are reachable from the wire, and
//! an unchecked conversion is a panic a client can request (`KMS-020`, #36).

use core::time::Duration;

/// Ticks per second in the `FILETIME` encoding: one tick is 100 nanoseconds.
const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;

/// Nanoseconds per `FILETIME` tick.
const NANOS_PER_FILETIME_TICK: u64 = 100;

/// `FILETIME` value of the Unix epoch, 1970-01-01T00:00:00Z.
///
/// 369 years, of which 89 are leap years, at 10,000,000 ticks per second.
const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

/// A reading from a monotonic clock (`ARCH-004`, #4).
///
/// Opaque on purpose: the epoch is whatever the platform's monotonic source
/// uses, so an absolute value means nothing and only differences do. That is
/// also why there is no `now()` — a reading is produced by the platform layer
/// and handed to the core as an argument (axiom A7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    nanos: u64,
}

impl Instant {
    /// The zero reading. Useful as a test origin; it is not "the beginning of
    /// time" in any platform's sense.
    pub const ZERO: Self = Self { nanos: 0 };

    /// Construct a reading from a nanosecond tick count.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    /// The reading as a nanosecond tick count.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.nanos
    }

    /// How long has passed since `earlier`, saturating at zero.
    ///
    /// Saturating rather than checked because a monotonic clock that appears to
    /// run backwards is a platform bug, not a protocol event: treating the gap
    /// as zero degrades a timeout into "expires immediately", which is safe,
    /// whereas an `Option` here would push a decision onto every caller that
    /// none of them could make better.
    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }

    /// Add a duration, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let nanos = u64::try_from(duration.as_nanos()).ok()?;
        Some(Self {
            nanos: self.nanos.checked_add(nanos)?,
        })
    }

    /// Add a duration, saturating at the maximum representable reading.
    ///
    /// A saturated deadline is one that never fires, which is the correct
    /// reading of "this far in the future" for every caller here.
    #[must_use]
    pub fn saturating_add(self, duration: Duration) -> Self {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        Self {
            nanos: self.nanos.saturating_add(nanos),
        }
    }
}

/// A wall-clock reading in the KMS protocol's encoding: 100-nanosecond ticks
/// since 1601-01-01T00:00:00Z (`ARCH-004`, #4; `KMS-020`, #36).
///
/// This is Windows' `FILETIME`, and it appears on the wire in three places: the
/// request time a client sends, the same value echoed back verbatim
/// (`KMS-012`, #28), and the input to the v6 time-slot key derivation
/// (`CRY-009`, #48).
///
/// Note what is *not* here: any notion of "the current time". A `FileTime` is
/// a value that arrived from somewhere — usually a client — and every operation
/// on it is total or returns `Option`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileTime {
    ticks: u64,
}

impl FileTime {
    /// The Unix epoch, 1970-01-01T00:00:00Z.
    pub const UNIX_EPOCH: Self = Self {
        ticks: UNIX_EPOCH_AS_FILETIME,
    };

    /// The zero value, 1601-01-01T00:00:00Z.
    pub const ZERO: Self = Self { ticks: 0 };

    /// Construct from a raw tick count, as read from the wire.
    #[must_use]
    pub const fn from_ticks(ticks: u64) -> Self {
        Self { ticks }
    }

    /// The raw tick count, as written to the wire.
    #[must_use]
    pub const fn as_ticks(self) -> u64 {
        self.ticks
    }

    /// Construct from a Unix timestamp in seconds.
    ///
    /// Returns `None` for instants before 1601 or beyond the `FILETIME` range.
    /// Both bounds are reachable: the parameter is signed, and a client is free
    /// to claim any time it likes.
    #[must_use]
    pub fn from_unix_seconds(seconds: i64) -> Option<Self> {
        let ticks = i128::from(seconds).checked_mul(i128::from(FILETIME_TICKS_PER_SECOND))?;
        let ticks = ticks.checked_add(i128::from(UNIX_EPOCH_AS_FILETIME))?;
        u64::try_from(ticks).ok().map(Self::from_ticks)
    }

    /// Convert to a Unix timestamp in seconds, truncating sub-second ticks
    /// towards 1601.
    ///
    /// Returns `None` only if the result does not fit an `i64`, which no value
    /// representable in a `u64` of ticks can produce — but the check is here
    /// rather than an unwrap, because "cannot happen" is not a thing this
    /// codebase asserts at runtime (axiom A2).
    #[must_use]
    pub fn to_unix_seconds(self) -> Option<i64> {
        let ticks = i128::from(self.ticks).checked_sub(i128::from(UNIX_EPOCH_AS_FILETIME))?;
        let seconds = ticks.checked_div(i128::from(FILETIME_TICKS_PER_SECOND))?;
        i64::try_from(seconds).ok()
    }

    /// Add a duration, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        Some(Self {
            ticks: self.ticks.checked_add(duration_to_ticks(duration)?)?,
        })
    }

    /// Subtract a duration, returning `None` if it would fall before 1601.
    #[must_use]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        Some(Self {
            ticks: self.ticks.checked_sub(duration_to_ticks(duration)?)?,
        })
    }

    /// The absolute difference between two readings.
    ///
    /// Absolute rather than signed because the one caller that matters is the
    /// clock-skew check, which cares about magnitude in either direction and
    /// never rejects on the answer — it only logs (`POL-011`, #99).
    #[must_use]
    pub fn abs_difference(self, other: Self) -> Duration {
        let ticks = self.ticks.abs_diff(other.ticks);
        // A `u64` of 100 ns ticks is ~58,000 years, which a `Duration` holds
        // comfortably: its seconds field is a `u64` too, and dividing by
        // 10,000,000 first cannot overflow it.
        let seconds = ticks.checked_div(FILETIME_TICKS_PER_SECOND).unwrap_or(0);
        let remainder = ticks.checked_rem(FILETIME_TICKS_PER_SECOND).unwrap_or(0);
        let subsec_nanos = u32::try_from(remainder.saturating_mul(NANOS_PER_FILETIME_TICK))
            .unwrap_or(0)
            .min(999_999_999);
        Duration::new(seconds, subsec_nanos)
    }
}

/// Convert a [`Duration`] to `FILETIME` ticks, returning `None` if it does not
/// fit.
fn duration_to_ticks(duration: Duration) -> Option<u64> {
    let nanos = duration.as_nanos();
    let ticks = nanos.checked_div(u128::from(NANOS_PER_FILETIME_TICK))?;
    u64::try_from(ticks).ok()
}

/// A source of time, implemented once per platform (`ARCH-004`, #4).
///
/// The core never holds one of these. The platform driver reads the clock and
/// passes the readings in, which is what lets a fuzzer or a differential test
/// replay a session at a time of its choosing.
pub trait Clock {
    /// A monotonic reading, for timeouts and expiry.
    fn monotonic(&self) -> Instant;

    /// A wall-clock reading, for the event log and for the randomised
    /// activation date in a generated ePID (`ID-007`, #112).
    ///
    /// Nothing on the wire depends on this being accurate. On Hermit it has
    /// one-second granularity and drifts (`OS-007`, #258).
    fn wall_clock(&self) -> FileTime;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::duration_suboptimal_units,
        reason = "test code: durations read better in the unit the assertion is about"
    )]

    use super::*;

    #[test]
    fn unix_epoch_constant_is_the_documented_value() {
        // 1970-01-01 is 369 years after 1601-01-01, 89 of which are leap years
        // under the proleptic Gregorian calendar the encoding assumes.
        let days: u64 = 369 * 365 + 89;
        let expected = days * 86_400 * FILETIME_TICKS_PER_SECOND;
        assert_eq!(FileTime::UNIX_EPOCH.as_ticks(), expected);
        assert_eq!(FileTime::UNIX_EPOCH.to_unix_seconds(), Some(0));
    }

    #[test]
    fn unix_conversion_round_trips_across_the_representable_range() {
        for seconds in [
            i64::from(i32::MIN),
            -1,
            0,
            1,
            1_000_000_000,
            1_755_000_000,
            i64::from(i32::MAX),
        ] {
            let file_time = FileTime::from_unix_seconds(seconds).unwrap();
            assert_eq!(file_time.to_unix_seconds(), Some(seconds), "at {seconds}");
        }
    }

    #[test]
    fn unix_conversion_refuses_instants_outside_the_filetime_range() {
        // Before 1601: not representable, and reachable from a client that
        // sends a plausible-looking negative timestamp.
        assert_eq!(FileTime::from_unix_seconds(-12_000_000_000), None);
        // Beyond the u64 tick range.
        assert_eq!(FileTime::from_unix_seconds(i64::MAX), None);
        assert_eq!(FileTime::from_unix_seconds(i64::MIN), None);
    }

    #[test]
    fn extreme_wire_values_do_not_panic() {
        // Every one of these is a `u64` a client can put on the wire, so every
        // one of them reaches this code (SEC-003, #195).
        for ticks in [0, 1, u64::MAX, u64::MAX - 1, UNIX_EPOCH_AS_FILETIME] {
            let value = FileTime::from_ticks(ticks);
            let _: Option<i64> = value.to_unix_seconds();
            let _: Option<FileTime> = value.checked_add(Duration::from_secs(1));
            let _: Option<FileTime> = value.checked_sub(Duration::from_secs(1));
            let _: Duration = value.abs_difference(FileTime::ZERO);
            let _: Duration = value.abs_difference(FileTime::from_ticks(u64::MAX));
        }
    }

    #[test]
    fn abs_difference_is_symmetric_and_correct() {
        let early = FileTime::from_unix_seconds(1_000_000_000).unwrap();
        let late = FileTime::from_unix_seconds(1_000_000_600).unwrap();
        assert_eq!(early.abs_difference(late), Duration::from_secs(600));
        assert_eq!(late.abs_difference(early), Duration::from_secs(600));
        assert_eq!(early.abs_difference(early), Duration::ZERO);
    }

    #[test]
    fn abs_difference_of_the_extremes_is_the_full_range() {
        let span = FileTime::ZERO.abs_difference(FileTime::from_ticks(u64::MAX));
        // ~58,494 years, which must not overflow the Duration.
        assert!(span.as_secs() > 1_800_000_000_000, "{span:?}");
    }

    #[test]
    fn filetime_arithmetic_is_checked_at_both_ends() {
        assert_eq!(
            FileTime::from_ticks(u64::MAX).checked_add(Duration::from_secs(1)),
            None
        );
        assert_eq!(FileTime::ZERO.checked_sub(Duration::from_secs(1)), None);
        assert_eq!(
            FileTime::ZERO.checked_add(Duration::from_secs(1)),
            Some(FileTime::from_ticks(FILETIME_TICKS_PER_SECOND))
        );
    }

    #[test]
    fn monotonic_difference_saturates_rather_than_wrapping() {
        let early = Instant::from_nanos(100);
        let late = Instant::from_nanos(900);
        assert_eq!(
            late.saturating_duration_since(early),
            Duration::from_nanos(800)
        );
        // A backwards-running monotonic clock is a platform bug; the timeout it
        // feeds must degrade to "expired", not to a 584-year wait.
        assert_eq!(early.saturating_duration_since(late), Duration::ZERO);
    }

    #[test]
    fn monotonic_addition_is_checked_and_saturating_as_documented() {
        let late = Instant::from_nanos(u64::MAX);
        assert_eq!(late.checked_add(Duration::from_nanos(1)), None);
        assert_eq!(late.saturating_add(Duration::from_nanos(1)), late);
        assert_eq!(
            Instant::ZERO.checked_add(Duration::from_secs(1)),
            Some(Instant::from_nanos(1_000_000_000))
        );
        // A duration too large for the nanosecond representation saturates
        // rather than silently truncating to its low 64 bits.
        assert_eq!(Instant::ZERO.saturating_add(Duration::MAX), late);
    }
}

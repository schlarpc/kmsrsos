//! The host's wall clock, carried forward from one reading (`POL-020`, #346;
//! `OS-007`, #258).
//!
//! # The problem this type exists to solve
//!
//! Two rules in this program pull in opposite directions.
//!
//! * `POL-011` (#99) wants the host's wall clock per request, because the skew
//!   between it and the client's timestamp is a protocol-visible property: a
//!   genuine KMS host validates the client's `FILETIME` against a ±4 hour band,
//!   so a host that never looks is distinguishable from one that does.
//! * `OS-007` (#258) forbids reading a wall clock in the request path.
//!   `platform_invariants.rs` fails the build if a second `SystemTime::now()`
//!   appears anywhere in a shipped crate, because Hermit's `SystemTime` is one
//!   CMOS read at boot plus local ticks and a design that depended on it would
//!   fail there and nowhere else.
//!
//! Before this type, the conflict was resolved by not resolving it:
//! `driver.rs` passed `host_time: None` and the whole skew path was dead. The
//! `strict-clock-skew` feature compiled, its tests passed, and the running
//! server behaved identically with and without it.
//!
//! # What it does instead
//!
//! One wall-clock reading is taken at start-up, *paired with* the monotonic
//! reading from the same moment. Every later wall-clock value is that pair plus
//! the monotonic distance travelled since. Reading the host time for a request
//! is then arithmetic on a number the driver already has, not a syscall — so
//! both rules hold at once, and they hold on Hermit for the same reason they
//! hold on Linux.
//!
//! # What it deliberately does not do
//!
//! It does not track the system clock. A host that steps its clock after
//! start-up — NTP landing, an operator correcting a CMOS error, a live
//! migration — keeps serving the old one plus elapsed monotonic time, and the
//! skew it measures is off by the size of the step.
//!
//! That is the correct trade here rather than a limitation worth fixing:
//!
//! * The value is used for one thing, measuring skew against a ±4 hour band. A
//!   step large enough to matter is a step of hours, which on this host means
//!   the clock was wrong by hours at start-up — and then the ePID's randomised
//!   activation date (`ID-007`, #112), drawn from the *same* reading, was
//!   already drawn wrong. Tracking the clock afterwards would not repair that;
//!   `ID-001` (#106) requires the ePID to be stable for the process lifetime,
//!   so the ePID must keep the old reading either way.
//! * Consistency between the two is worth more than accuracy in one of them. A
//!   host whose ePID claims one date while its skew measurement implies another
//!   is a host with an internal contradiction an observer can read; a host that
//!   is uniformly a few hours off is a host with a bad clock, which is
//!   ordinary.
//!
//! So the two derive from one reading on purpose, and `OS-020` (#336)'s clock
//! discipline is about the clock being right *at start-up*. Restarting is the
//! supported way to pick up a corrected clock.

use kmsrs_proto::time::{FileTime, Instant};

/// The host's wall clock, projected forward from a single reading.
///
/// [`WallClock::UNKNOWN`] is the honest value for a platform without a usable
/// wall clock, and is what the type defaults to: it makes
/// [`WallClock::at`] return `None`, which is exactly what
/// `kmsrs_policy::gate::evaluate` documents as "pass `None` on a platform
/// without one".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WallClock {
    /// The reading taken at start-up, and the monotonic instant it was taken
    /// at. `None` when no usable wall clock exists.
    origin: Option<(FileTime, Instant)>,
}

impl WallClock {
    /// No usable wall clock. [`WallClock::at`] returns `None`.
    pub const UNKNOWN: Self = Self { origin: None };

    /// Pair a wall-clock reading with the monotonic reading from the same
    /// moment.
    ///
    /// The two must be taken as close together as the platform allows: the gap
    /// between them is a fixed error in every value this type ever produces.
    #[must_use]
    pub const fn anchored(wall: FileTime, monotonic: Instant) -> Self {
        Self {
            origin: Some((wall, monotonic)),
        }
    }

    /// The host's wall clock at monotonic reading `now`.
    ///
    /// `None` if there is no usable wall clock, or if the projection would
    /// overflow the `FILETIME` range — which is not reachable from a real
    /// clock, but is reachable from a test that hands in `Instant::MAX`, and a
    /// wrong answer is worse than no answer for a value whose only use is
    /// deciding whether a client is lying about the time.
    #[must_use]
    pub fn at(self, now: Instant) -> Option<FileTime> {
        let (wall, monotonic) = self.origin?;
        wall.checked_add(now.saturating_duration_since(monotonic))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::WallClock;
    use core::time::Duration;
    use kmsrs_proto::time::{FileTime, Instant};

    /// The default is the honest one: a server nobody gave a clock to reports
    /// no host time rather than a fabricated one.
    #[test]
    fn the_default_is_unknown() {
        assert_eq!(WallClock::default(), WallClock::UNKNOWN);
        assert_eq!(WallClock::UNKNOWN.at(Instant::from_nanos(1_000)), None);
    }

    /// The whole point of the type: the wall clock advances with the monotonic
    /// clock, without a second reading.
    #[test]
    fn it_advances_with_the_monotonic_clock() {
        let wall = FileTime::from_unix_seconds(1_700_000_000).unwrap();
        let origin = Instant::from_nanos(5_000_000_000);
        let clock = WallClock::anchored(wall, origin);

        assert_eq!(clock.at(origin), Some(wall));

        let hour = Duration::from_hours(1);
        let later = origin.checked_add(hour).unwrap();
        assert_eq!(clock.at(later), wall.checked_add(hour));
    }

    /// A monotonic clock that appears to run backwards is a platform bug, not a
    /// protocol event. Saturating at the origin keeps the answer inside the
    /// tolerance band rather than reporting a wild skew for every client.
    #[test]
    fn a_backwards_reading_saturates_at_the_origin() {
        let wall = FileTime::from_unix_seconds(1_700_000_000).unwrap();
        let origin = Instant::from_nanos(5_000_000_000);
        let clock = WallClock::anchored(wall, origin);

        assert_eq!(clock.at(Instant::ZERO), Some(wall));
    }

    /// A projection that would leave the `FILETIME` range answers `None`
    /// rather than wrapping into a value that would read as an enormous skew.
    #[test]
    fn an_overflowing_projection_is_none() {
        let clock = WallClock::anchored(FileTime::from_ticks(u64::MAX), Instant::ZERO);
        assert_eq!(clock.at(Instant::from_nanos(u64::MAX)), None);
    }
}

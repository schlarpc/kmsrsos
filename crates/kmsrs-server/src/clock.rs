//! The host's wall clock, projected forward and re-anchored when it is
//! corrected (`POL-020`, #346; `OS-007`, #258; `OS-020`, #336).
//!
//! # The problem this type exists to solve
//!
//! Two rules in this program pull in opposite directions.
//!
//! * `POL-011` (#99) wants the host's wall clock per request. The skew between
//!   it and the client's timestamp is protocol-visible: a genuine KMS host
//!   checks the client's `FILETIME` against a ±4 hour band, so a host that
//!   never looks is distinguishable from one that does.
//! * `OS-007` (#258) permits the wall clock to be read in exactly two files —
//!   `entry.rs`, once at start-up, and `net/sntp.rs`, whose job it is.
//!   `workspace_invariants.rs` fails the build on a third. The reason is not
//!   fastidiousness: every deadline in this program is monotonic, which is what
//!   lets `OS-020` (#336) *step* `CLOCK_REALTIME` without `kmsrs-policy` ever
//!   observing time run backwards. One `SystemTime::now()` in the request path
//!   would break that silently.
//!
//! Before this type the conflict was settled by not settling it: `driver.rs`
//! passed `host_time: None`, so `clock_skew` never appeared in the event log
//! and `REFUSE_CLOCK_SKEW` was unreachable. A build with `strict-clock-skew`
//! behaved identically to one without it.
//!
//! # What it does instead
//!
//! It holds a wall-clock reading paired with the *monotonic* reading from the
//! same moment, and answers [`WallClock::now`] by adding the monotonic distance
//! travelled since. The request path therefore reads `CLOCK_MONOTONIC` — which
//! the driver already does once per request to produce the reading every
//! deadline is measured against — and never `CLOCK_REALTIME`. Both rules hold.
//!
//! # Why it can be re-anchored, and why that is not a second clock read
//!
//! On the bare-metal target the clock is disciplined: `OS-020` (#336) polls
//! SNTP and steps `CLOCK_REALTIME` when the offset is worth stepping. A design
//! that projected forever from one start-up reading would keep serving the
//! pre-correction value, so a host that booted with a hypervisor clock six
//! hours out would report six hours of skew against every correctly-set client
//! for the life of the process — and under `strict-clock-skew` would refuse
//! them all. That is precisely the failure `OS-020` exists to prevent, so the
//! correction has to reach here.
//!
//! [`WallClock::discipline`] is how. It takes the corrected reading from the
//! one file already permitted to know it, so nothing new reads a wall clock;
//! the value crosses the boundary as an argument.
//!
//! # What deliberately does *not* move when the clock is corrected
//!
//! The ePID's randomised activation date (`ID-007`, #112). It is drawn once at
//! start-up from the pre-correction reading and stays there, because `ID-001`
//! (#106) requires the ePID to be stable for the life of the process — a host
//! whose ePID changed mid-flight would fail the canonical detection test.
//!
//! So after a large correction the two are, briefly, drawn from different
//! clocks. That is the right way round: the activation date is a *year* and a
//! day-of-year buried in an ePID, and a correction big enough to move it is one
//! this host would have to restart to reflect anyway; the skew measurement is
//! compared against a four-hour band on every request. Making the accurate
//! thing accurate, and leaving the stable thing stable, beats keeping two
//! values consistent and both wrong.

use std::sync::{Arc, RwLock};
use std::time::Instant as Monotonic;

/// Re-exported because it is in this module's public API: [`WallClock::discipline`]
/// takes one and [`WallClock::now`] returns one.
///
/// `kmsrs-os` is the caller that needs it, and it depends on this crate and not
/// on `kmsrs-proto`. Making it add that dependency to name one type would widen
/// the graph `workspace_invariants.rs` checks for the sake of an import.
pub use kmsrs_proto::time::FileTime;

/// A wall-clock reading and the monotonic reading taken with it.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    /// What the wall clock said.
    wall: FileTime,
    /// The monotonic reading from the same moment. The gap between the two
    /// reads is a fixed error in every value projected from this anchor, so
    /// they are taken as close together as the caller can manage.
    monotonic: Monotonic,
}

/// The host's wall clock, projected from its most recent anchor.
///
/// Cloning shares the anchor: the driver reads it on every request while the
/// SNTP task re-anchors it, and both hold the same slot. A lock rather than a
/// channel, for the same reason as [`crate::facts::Facts`] — one writer, many
/// readers, and the readers want the current value rather than the history.
///
/// The default is the honest "no usable wall clock", which makes
/// [`WallClock::now`] return `None` — exactly what `kmsrs_policy::gate::evaluate`
/// documents as the value to pass on a platform without one. Every test that
/// does not care what time it is gets that.
#[derive(Debug, Clone, Default)]
pub struct WallClock {
    anchor: Arc<RwLock<Option<Anchor>>>,
}

impl WallClock {
    /// A clock with no reading behind it. [`WallClock::now`] answers `None`.
    #[must_use]
    pub fn unknown() -> Self {
        Self::default()
    }

    /// A clock anchored to `wall`, read now.
    ///
    /// The caller must have read the wall clock immediately before calling
    /// this: the monotonic half of the anchor is taken here.
    #[must_use]
    pub fn anchored(wall: FileTime) -> Self {
        let clock = Self::unknown();
        clock.discipline(wall);
        clock
    }

    /// Re-anchor to a corrected reading (`OS-020`, #336).
    ///
    /// Called after `clock_settime` has moved `CLOCK_REALTIME`, from the one
    /// file permitted to read it. Everything projected from here on uses the
    /// corrected value; nothing already decided is revisited, and no deadline
    /// anywhere in the program is affected, because every deadline is
    /// monotonic.
    pub fn discipline(&self, wall: FileTime) {
        let anchor = Anchor {
            wall,
            monotonic: Monotonic::now(),
        };
        // A poisoned lock means a reader panicked while holding it. What is
        // behind it is two numbers with no invariant between them, so there is
        // nothing to have been broken and nothing to recover: taking it back is
        // strictly better than a host that stops measuring skew because
        // something else panicked. `panic = "abort"` means a release build
        // cannot reach this at all.
        match self.anchor.write() {
            Ok(mut slot) => *slot = Some(anchor),
            Err(poisoned) => *poisoned.into_inner() = Some(anchor),
        }
    }

    /// The host's wall clock now, or `None` if there is no reading behind it.
    ///
    /// `None` also when the projection would leave the `FILETIME` range, which
    /// no real clock reaches. A wrong answer is worse than no answer for a
    /// value whose only use is deciding whether a client is lying about the
    /// time.
    #[must_use]
    pub fn now(&self) -> Option<FileTime> {
        let anchor = match self.anchor.read() {
            Ok(slot) => (*slot)?,
            Err(poisoned) => (*poisoned.into_inner())?,
        };
        anchor.wall.checked_add(anchor.monotonic.elapsed())
    }

    /// Whether a reading has ever been taken.
    ///
    /// Used by the web UI and by tests; not by the request path, which wants
    /// the value or nothing and gets that from [`WallClock::now`].
    #[must_use]
    pub fn is_known(&self) -> bool {
        match self.anchor.read() {
            Ok(slot) => slot.is_some(),
            Err(poisoned) => poisoned.into_inner().is_some(),
        }
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
    use kmsrs_proto::time::FileTime;

    /// Projection over the microseconds a test takes is not zero, so equality
    /// is asserted to a tolerance far below anything this value is used for —
    /// the tolerance it feeds is four hours.
    fn assert_close(actual: FileTime, expected: FileTime) {
        let apart = actual.abs_difference(expected);
        assert!(
            apart < Duration::from_mins(1),
            "{actual:?} and {expected:?} are {apart:?} apart"
        );
    }

    /// The default is the honest one: a server nobody gave a clock to reports
    /// no host time rather than a fabricated one.
    #[test]
    fn the_default_is_unknown() {
        let clock = WallClock::unknown();
        assert!(!clock.is_known());
        assert_eq!(clock.now(), None);
    }

    /// An anchored clock answers with the reading it was given.
    #[test]
    fn it_answers_from_its_anchor() {
        let wall = FileTime::from_unix_seconds(1_700_000_000).unwrap();
        let clock = WallClock::anchored(wall);
        assert!(clock.is_known());
        assert_close(clock.now().unwrap(), wall);
    }

    /// The clock advances on its own, without a second wall-clock read
    /// (`OS-007`, #258).
    #[test]
    fn it_advances_with_the_monotonic_clock() {
        let wall = FileTime::from_unix_seconds(1_700_000_000).unwrap();
        let clock = WallClock::anchored(wall);

        let first = clock.now().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let second = clock.now().unwrap();

        assert!(second > first, "{second:?} should be after {first:?}");
    }

    /// **The `OS-020` (#336) case.** A correction reaches the value the request
    /// path reads, rather than being applied to `CLOCK_REALTIME` and ignored
    /// here.
    #[test]
    fn a_correction_moves_what_the_request_path_sees() {
        let booted_wrong = FileTime::from_unix_seconds(1_700_000_000).unwrap();
        let clock = WallClock::anchored(booted_wrong);

        let corrected = booted_wrong.checked_add(Duration::from_hours(6)).unwrap();
        clock.discipline(corrected);

        assert_close(clock.now().unwrap(), corrected);
    }

    /// Disciplining a clock that never had a reading gives it one. On the
    /// bare-metal target this cannot happen — start-up refuses to serve on an
    /// unusable clock — but a type whose behaviour depends on which order two
    /// callers ran is a type nobody can reason about.
    #[test]
    fn disciplining_an_unknown_clock_makes_it_known() {
        let clock = WallClock::unknown();
        let wall = FileTime::from_unix_seconds(1_700_000_000).unwrap();

        clock.discipline(wall);

        assert!(clock.is_known());
        assert_close(clock.now().unwrap(), wall);
    }

    /// Clones share one anchor, which is what lets the SNTP task correct the
    /// clock the driver is reading.
    #[test]
    fn clones_share_the_anchor() {
        let wall = FileTime::from_unix_seconds(1_700_000_000).unwrap();
        let held_by_the_driver = WallClock::anchored(wall);
        let held_by_sntp = held_by_the_driver.clone();

        let corrected = wall.checked_add(Duration::from_hours(3)).unwrap();
        held_by_sntp.discipline(corrected);

        assert_close(held_by_the_driver.now().unwrap(), corrected);
    }
}

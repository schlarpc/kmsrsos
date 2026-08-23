//! Category 3: settings decided when the binary is built (`CFG-001`, #166).
//!
//! Anything that can change a byte on the wire lives here, and nothing here can
//! be changed without rebuilding. There is deliberately no constructor that
//! takes runtime input — [`Compiled::BUILD`] is the only value of this type any
//! shipped code path can obtain (`ARCH-003`, #3).
//!
//! # Overriding at build time
//!
//! Through `option_env!`, so an override is a compile-time constant and an
//! invalid one is a **compile error** rather than a start-up failure
//! (`CFG-004`, #169). Setting `KMSRSOS_ACTIVATION_INTERVAL=0` does not produce
//! a server that starts and behaves oddly; it produces a build that stops.

#![allow(
    clippy::panic,
    clippy::manual_assert,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "this module's parser runs only in const context, where a panic \
              is a compile error rather than a runtime one — which is the \
              entire mechanism CFG-004 (#169) asks for. The index is bounded \
              by the loop condition and the subtraction by the digit check \
              immediately above it, and neither `get` nor `checked_sub` is \
              usable in a const fn returning a value"
)]

use core::time::Duration;
use kmsrs_policy::access::AccessList;
use kmsrs_proto::types::Intervals;

/// Microsoft's documented default activation interval, in minutes.
///
/// The one genuine three-way agreement between Microsoft's documentation,
/// vlmcsd and py-kms. Modern clients (8.1 and later) ignore both intervals
/// entirely, which is why getting them wrong is survivable and why sending an
/// implausible value is nonetheless a fingerprint.
pub const DEFAULT_ACTIVATION_MINUTES: u32 = 120;

/// Microsoft's documented default renewal interval, in minutes. Seven days.
pub const DEFAULT_RENEWAL_MINUTES: u32 = 10_080;

/// The narrowest interval this build will accept, in minutes.
///
/// Zero is refused outright: py-kms lets a negative value reach a `'<I'` pack
/// and raise `struct.error` at response time, which is a runtime failure for
/// something knowable at build time.
pub const MIN_INTERVAL_MINUTES: u32 = 1;

/// The widest interval this build will accept, in minutes. Roughly a year.
pub const MAX_INTERVAL_MINUTES: u32 = 525_600;

/// The client count below which a build-time override is implausible
/// (`POL-008`, #96).
pub const PLAUSIBLE_CLIENT_COUNT: core::ops::RangeInclusive<u32> = 5..=50;

/// Parse a build-time override, at compile time.
///
/// # Panics
///
/// At **compile time**, if the value is not a decimal number. That is the
/// point: a typo in a build variable must not produce a running binary
/// (`CFG-004`, #169).
const fn parse_minutes(value: Option<&str>, fallback: u32) -> u32 {
    let Some(text) = value else {
        return fallback;
    };
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        panic!("a build-time interval override must not be empty");
    }

    let mut total: u32 = 0;
    let mut index = 0;
    while index < bytes.len() {
        let digit = bytes[index];
        if digit < b'0' || digit > b'9' {
            panic!("a build-time interval override must be a decimal number of minutes");
        }
        let Some(scaled) = total.checked_mul(10) else {
            panic!("a build-time interval override is too large");
        };
        let Some(next) = scaled.checked_add((digit - b'0') as u32) else {
            panic!("a build-time interval override is too large");
        };
        total = next;
        index += 1;
    }
    total
}

/// Check an interval, at compile time.
const fn checked_interval(minutes: u32, name: &str) -> u32 {
    if minutes < MIN_INTERVAL_MINUTES {
        panic!("an interval of zero minutes would tell clients to retry forever");
    }
    if minutes > MAX_INTERVAL_MINUTES {
        panic!("an interval longer than a year is not a value a genuine host sends");
    }
    let _ = name;
    minutes
}

/// The activation interval this build reports (`KMS-021`, #37).
pub const ACTIVATION_MINUTES: u32 = checked_interval(
    parse_minutes(
        option_env!("KMSRSOS_ACTIVATION_INTERVAL"),
        DEFAULT_ACTIVATION_MINUTES,
    ),
    "activation",
);

/// The renewal interval this build reports (`KMS-021`, #37).
pub const RENEWAL_MINUTES: u32 = checked_interval(
    parse_minutes(
        option_env!("KMSRSOS_RENEWAL_INTERVAL"),
        DEFAULT_RENEWAL_MINUTES,
    ),
    "renewal",
);

/// How long a connection may sit idle before the state machine closes it.
///
/// In the state machine rather than in a socket option (`NET-004`, #153):
/// `SO_RCVTIMEO` is a silent no-op on one of the three target platforms and
/// returns `EINVAL` on it, which is the worst possible failure shape for
/// something load-bearing.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Settings that may change a byte on the wire.
///
/// Deliberately not `Deserialize`. There is no code path from a runtime
/// document to a value of this type, which is how `CFG-001` (#166) is enforced
/// rather than merely documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compiled {
    /// What to tell clients about retrying and renewing (`KMS-021`, #37).
    pub intervals: Intervals,
    /// How long an idle connection lives (`NET-004`, #153).
    pub idle_timeout: Duration,
    /// Whether retail, OEM and evaluation SKUs are refused (`POL-010`, #98).
    pub refuse_non_volume: bool,
    /// Whether pre-release SKUs are refused (`POL-010`, #98).
    pub refuse_preview: bool,
    /// Whether a clock-skewed request is refused (`POL-011`, #99).
    pub refuse_clock_skew: bool,
    /// Who may connect at all (`POL-013`, #101).
    ///
    /// Compiled rather than runtime because whether this host answers is
    /// observable to whoever asked, which is the test `CFG-001` (#166) applies.
    /// Empty by default, which permits everything.
    pub access: AccessList,
}

impl Compiled {
    /// What this binary was built with.
    ///
    /// The only value of this type a shipped code path can obtain.
    pub const BUILD: Self = Self {
        intervals: Intervals {
            activation: ACTIVATION_MINUTES,
            renewal: RENEWAL_MINUTES,
        },
        idle_timeout: IDLE_TIMEOUT,
        refuse_non_volume: kmsrs_policy::gate::REFUSE_NON_VOLUME,
        refuse_preview: kmsrs_policy::gate::REFUSE_PREVIEW,
        refuse_clock_skew: kmsrs_policy::gate::REFUSE_CLOCK_SKEW,
        access: AccessList::OPEN,
    };

    /// Whether this build's client-count behaviour is plausible
    /// (`POL-008`, #96).
    ///
    /// py-kms's one genuine policy win, moved to build time because there is no
    /// runtime knob to warn about. The count this host reports is *derived*
    /// from observed clients rather than configured (`POL-001`, #89), so the
    /// value being checked is the saturation the model can actually produce.
    ///
    /// Worth recording why the check exists at all: py-kms's Docker image
    /// defaults to `CLIENT_COUNT=26`, which is **worse than omitting it** — it
    /// lands in the band that makes py-kms log a genuineness warning on every
    /// single activation.
    #[must_use]
    pub fn client_count_is_plausible(saturation: u32) -> bool {
        PLAUSIBLE_CLIENT_COUNT.contains(&saturation)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        ACTIVATION_MINUTES, Compiled, DEFAULT_ACTIVATION_MINUTES, DEFAULT_RENEWAL_MINUTES,
        MAX_INTERVAL_MINUTES, MIN_INTERVAL_MINUTES, RENEWAL_MINUTES,
    };

    /// `KMS-021` (#37): Microsoft's documented defaults, and the one genuine
    /// three-way agreement in the whole feature matrix.
    #[test]
    fn the_defaults_are_microsofts() {
        assert_eq!(DEFAULT_ACTIVATION_MINUTES, 120);
        assert_eq!(DEFAULT_RENEWAL_MINUTES, 10_080, "seven days");
        assert_eq!(Compiled::BUILD.intervals.activation, ACTIVATION_MINUTES);
        assert_eq!(Compiled::BUILD.intervals.renewal, RENEWAL_MINUTES);
    }

    /// The range check is real, and it ran at compile time to produce these
    /// constants. A value outside it does not build.
    #[test]
    fn the_shipped_intervals_are_inside_the_permitted_range() {
        for minutes in [ACTIVATION_MINUTES, RENEWAL_MINUTES] {
            assert!(minutes >= MIN_INTERVAL_MINUTES, "{minutes}");
            assert!(minutes <= MAX_INTERVAL_MINUTES, "{minutes}");
        }
        assert!(
            MIN_INTERVAL_MINUTES >= 1,
            "zero would tell clients to retry forever"
        );
    }

    /// `POL-008` (#96). py-kms's Docker default of 26 is inside the plausible
    /// band; what makes it bad is that py-kms *warns* on it, which this
    /// documents by pinning the band.
    #[test]
    fn the_genuineness_band_matches_what_a_real_host_reports() {
        // A server or Office host saturates at 10, a client host at 50.
        assert!(Compiled::client_count_is_plausible(10));
        assert!(Compiled::client_count_is_plausible(50));
        assert!(Compiled::client_count_is_plausible(25));

        // Values a genuine host never reports.
        assert!(!Compiled::client_count_is_plausible(0));
        assert!(!Compiled::client_count_is_plausible(1));
        assert!(!Compiled::client_count_is_plausible(51));
        assert!(!Compiled::client_count_is_plausible(10_000));
    }

    /// The build's gate flags come from the policy crate rather than being a
    /// second copy that could disagree with it.
    #[test]
    fn the_gate_flags_are_the_policy_crates() {
        assert_eq!(
            Compiled::BUILD.refuse_non_volume,
            kmsrs_policy::gate::REFUSE_NON_VOLUME
        );
        assert_eq!(
            Compiled::BUILD.refuse_preview,
            kmsrs_policy::gate::REFUSE_PREVIEW
        );
        assert_eq!(
            Compiled::BUILD.refuse_clock_skew,
            kmsrs_policy::gate::REFUSE_CLOCK_SKEW
        );
    }
}

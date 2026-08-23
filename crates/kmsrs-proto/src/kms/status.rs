//! The client's self-reported licence status (`KMS-016`, #32).
//!
//! A client tells the host what state it thinks it is in. The host records it
//! and answers the same way regardless — the field exists so an operator can
//! see *why* a machine is asking, which is the difference between "twelve
//! machines renewing" and "twelve machines out of tolerance".
//!
//! Values above 6 are logged, never fatal. A future Windows release that adds a
//! state must not make this host refuse it.

/// What a client says its licensing state is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LicenseStatus {
    /// 0 — unlicensed.
    Unlicensed,
    /// 1 — licensed, i.e. already activated.
    Licensed,
    /// 2 — out-of-box grace period.
    OutOfBoxGrace,
    /// 3 — out-of-tolerance grace period, after a KMS activation expired.
    OutOfToleranceGrace,
    /// 4 — non-genuine grace period.
    NonGenuineGrace,
    /// 5 — notification mode.
    Notification,
    /// 6 — extended grace period.
    ExtendedGrace,
    /// A value this vocabulary does not name.
    ///
    /// Kept rather than rejected. The alternative — refusing an unrecognised
    /// state — would make this host distinguishable from a genuine one the
    /// first time Microsoft added a value.
    Unrecognised(u32),
}

impl LicenseStatus {
    /// Decode the wire value.
    #[must_use]
    pub const fn from_wire(raw: u32) -> Self {
        match raw {
            0 => Self::Unlicensed,
            1 => Self::Licensed,
            2 => Self::OutOfBoxGrace,
            3 => Self::OutOfToleranceGrace,
            4 => Self::NonGenuineGrace,
            5 => Self::Notification,
            6 => Self::ExtendedGrace,
            other => Self::Unrecognised(other),
        }
    }

    /// Encode to the wire value.
    #[must_use]
    pub const fn to_wire(self) -> u32 {
        match self {
            Self::Unlicensed => 0,
            Self::Licensed => 1,
            Self::OutOfBoxGrace => 2,
            Self::OutOfToleranceGrace => 3,
            Self::NonGenuineGrace => 4,
            Self::Notification => 5,
            Self::ExtendedGrace => 6,
            Self::Unrecognised(raw) => raw,
        }
    }

    /// Text for the event log.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Unlicensed => "unlicensed",
            Self::Licensed => "licensed",
            Self::OutOfBoxGrace => "out-of-box grace",
            Self::OutOfToleranceGrace => "out-of-tolerance grace",
            Self::NonGenuineGrace => "non-genuine grace",
            Self::Notification => "notification",
            Self::ExtendedGrace => "extended grace",
            Self::Unrecognised(_) => "unrecognised",
        }
    }
}

impl core::fmt::Display for LicenseStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unrecognised(raw) => write!(f, "unrecognised ({raw})"),
            named => f.write_str(named.description()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::LicenseStatus;

    #[test]
    fn the_seven_named_states_round_trip() {
        for raw in 0..=6_u32 {
            let status = LicenseStatus::from_wire(raw);
            assert_ne!(status, LicenseStatus::Unrecognised(raw), "{raw}");
            assert_eq!(status.to_wire(), raw);
            assert!(!status.description().is_empty());
        }
    }

    /// `KMS-016` (#32): a value above 6 is logged, never fatal. This is the
    /// forward-compatibility property — a new Windows state must not make this
    /// host behave differently from a genuine one.
    #[test]
    fn an_unrecognised_state_is_kept_and_reported() {
        for raw in [7_u32, 42, u32::MAX] {
            let status = LicenseStatus::from_wire(raw);
            assert_eq!(status, LicenseStatus::Unrecognised(raw));
            assert_eq!(status.to_wire(), raw);
            assert_eq!(
                alloc::format!("{status}"),
                alloc::format!("unrecognised ({raw})")
            );
        }
    }

    #[test]
    fn display_names_the_state() {
        assert_eq!(
            alloc::format!("{}", LicenseStatus::OutOfToleranceGrace),
            "out-of-tolerance grace"
        );
        assert_eq!(alloc::format!("{}", LicenseStatus::Licensed), "licensed");
    }
}

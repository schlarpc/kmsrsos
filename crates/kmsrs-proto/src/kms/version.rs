//! Protocol version dispatch (`KMS-008`, #24).
//!
//! The version field is one `u32` holding two 16-bit halves: minor in the low
//! bits, major in the high ones. Three major versions exist, all with minor 0.
//!
//! # Why "v6.1" is refused rather than treated as v6
//!
//! py-kms dispatches on the major half alone, so a request claiming version 6.1
//! is serviced as v6. That is wrong in a way that matters: a genuine host
//! refuses it, so a client can distinguish the two by asking. It is also the
//! shape of bug that turns a future protocol revision into a silent
//! misinterpretation rather than a clean refusal.
//!
//! An unsupported version is answered with a **well-formed response carrying
//! `0x8007000D`** (`KMS-014`, #30) — not a connection drop, and not
//! `0xC004F042`.

/// A protocol version as it appears on the wire.
///
/// Kept as both halves rather than normalised, so that the exact value a client
/// sent can be echoed back and logged (`KMS-012`, #28).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    /// The high 16 bits.
    pub major: u16,
    /// The low 16 bits.
    pub minor: u16,
}

impl ProtocolVersion {
    /// Decode the wire `u32`.
    #[must_use]
    pub const fn from_wire(raw: u32) -> Self {
        // The field is a union of a `DWORD` and `{ WORD minor; WORD major; }`
        // on a little-endian machine, so minor occupies the low half.
        let [low, high] = split_halves(raw);
        Self {
            major: high,
            minor: low,
        }
    }

    /// Encode back to the wire `u32`.
    #[must_use]
    pub const fn to_wire(self) -> u32 {
        let [minor_low, minor_high] = self.minor.to_le_bytes();
        let [major_low, major_high] = self.major.to_le_bytes();
        u32::from_le_bytes([minor_low, minor_high, major_low, major_high])
    }

    /// The supported version this is, if it is one.
    ///
    /// Both halves are checked. Accepting any minor would service "v6.1" as v6,
    /// which is py-kms's defect.
    #[must_use]
    pub const fn supported(self) -> Option<Version> {
        if self.minor != 0 {
            return None;
        }
        match self.major {
            4 => Some(Version::V4),
            5 => Some(Version::V5),
            6 => Some(Version::V6),
            _ => None,
        }
    }
}

impl core::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Split a `u32` into its two 16-bit halves, low first.
///
/// A helper rather than two shifts inline because `as` is denied in this crate
/// and the `const` context rules out `TryFrom`.
const fn split_halves(raw: u32) -> [u16; 2] {
    let [b0, b1, b2, b3] = raw.to_le_bytes();
    [u16::from_le_bytes([b0, b1]), u16::from_le_bytes([b2, b3])]
}

/// A KMS protocol version this host implements.
///
/// Exhaustive (`ARCH-010`, #10): a fourth version would have to be handled
/// everywhere it is matched, rather than falling into a default arm that does
/// something plausible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Version {
    /// Plaintext request with a Rijndael-160 CBC-MAC.
    V4,
    /// AES-128-CBC, with the response IV equal to the request IV.
    V5,
    /// AES-128-CBC with a tampered key schedule, a fresh response IV, a
    /// hardware ID and an HMAC.
    V6,
}

impl Version {
    /// Every version, in order.
    pub const ALL: [Self; 3] = [Self::V4, Self::V5, Self::V6];

    /// The wire version this corresponds to.
    #[must_use]
    pub const fn to_protocol_version(self) -> ProtocolVersion {
        ProtocolVersion {
            major: match self {
                Self::V4 => 4,
                Self::V5 => 5,
                Self::V6 => 6,
            },
            minor: 0,
        }
    }

    /// Whether this version uses the tampered v6 key schedule.
    ///
    /// vlmcsd writes this as `major > 5`, and stating it the same way here
    /// keeps the two comparable when a fourth version appears.
    #[must_use]
    pub const fn uses_tweaked_cipher(self) -> bool {
        matches!(self, Self::V6)
    }

    /// Whether this version encrypts its payload at all.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::V5 | Self::V6)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{ProtocolVersion, Version};

    #[test]
    fn the_wire_encoding_puts_minor_in_the_low_half() {
        // The three real values, as they appear in a capture.
        assert_eq!(
            ProtocolVersion::from_wire(0x0004_0000),
            ProtocolVersion { major: 4, minor: 0 }
        );
        assert_eq!(
            ProtocolVersion::from_wire(0x0005_0000),
            ProtocolVersion { major: 5, minor: 0 }
        );
        assert_eq!(
            ProtocolVersion::from_wire(0x0006_0000),
            ProtocolVersion { major: 6, minor: 0 }
        );
        // And a minor version, to show which half is which.
        assert_eq!(
            ProtocolVersion::from_wire(0x0006_0001),
            ProtocolVersion { major: 6, minor: 1 }
        );
    }

    #[test]
    fn the_encoding_round_trips_over_the_whole_range() {
        for raw in [0_u32, 1, 0x0004_0000, 0x0006_0001, 0xFFFF_FFFF, 0x1234_5678] {
            assert_eq!(ProtocolVersion::from_wire(raw).to_wire(), raw);
        }
        for version in Version::ALL {
            let wire = version.to_protocol_version();
            assert_eq!(ProtocolVersion::from_wire(wire.to_wire()), wire);
            assert_eq!(wire.supported(), Some(version));
        }
    }

    /// `KMS-008` (#24). The minor half is checked, so "v6.1" is refused rather
    /// than serviced as v6 — which is what py-kms does, and what makes it
    /// distinguishable from a genuine host by asking.
    #[test]
    fn a_non_zero_minor_version_is_not_supported() {
        for minor in [1_u16, 2, 0xFFFF] {
            for major in [4_u16, 5, 6] {
                assert_eq!(
                    ProtocolVersion { major, minor }.supported(),
                    None,
                    "{major}.{minor} must not be serviced"
                );
            }
        }
    }

    #[test]
    fn only_four_five_and_six_are_supported() {
        for major in 0..=16_u16 {
            let version = ProtocolVersion { major, minor: 0 };
            let expected = match major {
                4 => Some(Version::V4),
                5 => Some(Version::V5),
                6 => Some(Version::V6),
                _ => None,
            };
            assert_eq!(version.supported(), expected, "major {major}");
        }
        // Every u32 must produce an answer rather than a panic: the field is
        // attacker-controlled and unvalidated until here (`SEC-003`, #195).
        for raw in [0_u32, u32::MAX, 0x0007_0000, 0xFFFF_0000] {
            let _ = ProtocolVersion::from_wire(raw).supported();
        }
    }

    #[test]
    fn only_v6_uses_the_tweaked_cipher_and_only_v4_is_plaintext() {
        assert!(!Version::V4.uses_tweaked_cipher());
        assert!(!Version::V5.uses_tweaked_cipher());
        assert!(Version::V6.uses_tweaked_cipher());

        assert!(!Version::V4.is_encrypted());
        assert!(Version::V5.is_encrypted());
        assert!(Version::V6.is_encrypted());
    }

    #[test]
    fn display_reads_as_a_version_number() {
        assert_eq!(
            alloc::format!("{}", ProtocolVersion { major: 6, minor: 0 }),
            "6.0"
        );
    }
}

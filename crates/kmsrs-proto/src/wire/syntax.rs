//! Interface and transfer-syntax identities (`WIRE-004`, #62;
//! `WIRE-007`, #65).
//!
//! Three GUIDs and one prefix. The prefix is the interesting one: bind-time
//! feature negotiation is not a transfer syntax at all, it is a **pseudo-GUID**
//! whose first eight bytes are a fixed marker and whose next two carry the
//! feature bits the client is asking about. Matching it as a whole GUID, which
//! is what py-kms does, means it only ever recognises the one combination of
//! feature bits it happens to have hardcoded.

use kmsrs_db::Guid;

/// The KMS activation interface: `51c82175-844e-4750-b0d8-ec255555bc06`,
/// version 1.0.
pub const KMS_INTERFACE: Guid = Guid::from_bytes([
    0x51, 0xc8, 0x21, 0x75, 0x84, 0x4e, 0x47, 0x50, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06,
]);

/// The KMS interface's major version.
pub const KMS_INTERFACE_VERSION_MAJOR: u16 = 1;

/// The KMS interface's minor version.
pub const KMS_INTERFACE_VERSION_MINOR: u16 = 0;

/// NDR32: `8a885d04-1ceb-11c9-9fe8-08002b104860`, syntax version 2.
pub const NDR32: Guid = Guid::from_bytes([
    0x8a, 0x88, 0x5d, 0x04, 0x1c, 0xeb, 0x11, 0xc9, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
]);

/// NDR32's syntax version.
pub const NDR32_VERSION: u32 = 2;

/// NDR64: `71710533-beba-4937-8319-b5dbef9ccc36`, syntax version 1.
pub const NDR64: Guid = Guid::from_bytes([
    0x71, 0x71, 0x05, 0x33, 0xbe, 0xba, 0x49, 0x37, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
]);

/// NDR64's syntax version.
pub const NDR64_VERSION: u32 = 1;

/// The fixed prefix of the bind-time feature negotiation pseudo-GUID
/// (`WIRE-007`, #65).
///
/// Eight bytes as they appear **on the wire**. The remaining eight are not an
/// identity: bytes 8 and 9 carry the requested feature bits and the rest are
/// unspecified, so only this prefix may be compared.
pub const BTFN_WIRE_PREFIX: [u8; 8] = [0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45];

/// Which transfer syntax a context item is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferSyntax {
    /// NDR32, the syntax every client can speak.
    Ndr32,
    /// NDR64, offered by Windows 8 and Server 2012 and later.
    Ndr64,
    /// Bind-time feature negotiation, with the bits the client requested.
    FeatureNegotiation(FeatureBits),
    /// Something else entirely.
    ///
    /// Answered with a per-item NACK rather than by dropping the connection
    /// (`WIRE-006`, #64).
    Unknown,
}

impl TransferSyntax {
    /// Classify a context item's transfer syntax from its raw wire bytes.
    ///
    /// Takes wire bytes rather than a [`Guid`] because the feature-negotiation
    /// case is not a GUID and cannot be compared as one.
    #[must_use]
    pub fn classify(wire: &[u8; 16]) -> Self {
        if let Some(prefix) = wire.first_chunk::<8>()
            && *prefix == BTFN_WIRE_PREFIX
        {
            let requested = wire.get(8).copied().unwrap_or(0);
            return Self::FeatureNegotiation(FeatureBits::from_bits(requested));
        }

        // A real transfer syntax is a GUID, so compare it as one.
        let canonical = crate::kms::layout::WireGuid {
            data1: u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]).into(),
            data2: u16::from_le_bytes([wire[4], wire[5]]).into(),
            data3: u16::from_le_bytes([wire[6], wire[7]]).into(),
            data4: [
                wire[8], wire[9], wire[10], wire[11], wire[12], wire[13], wire[14], wire[15],
            ],
        }
        .to_guid();

        if canonical == NDR32 {
            Self::Ndr32
        } else if canonical == NDR64 {
            Self::Ndr64
        } else {
            Self::Unknown
        }
    }

    /// The syntax version a context item should declare for this syntax.
    #[must_use]
    pub const fn expected_version(self) -> Option<u32> {
        match self {
            Self::Ndr32 => Some(NDR32_VERSION),
            Self::Ndr64 => Some(NDR64_VERSION),
            // The negotiation item's version is 1 on the way in and **0** on the
            // way out, which is why this is not a single constant.
            Self::FeatureNegotiation(_) | Self::Unknown => None,
        }
    }
}

/// The MS-RPCE bind-time feature bits (`WIRE-007`, #65).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FeatureBits(u8);

impl FeatureBits {
    /// The peer supports security-context multiplexing.
    pub const SECURITY_CONTEXT_MULTIPLEX: Self = Self(0x01);

    /// The peer wants the connection kept when a call is orphaned.
    pub const KEEP_CONNECTION_ON_ORPHAN: Self = Self(0x02);

    /// The bits a server may acknowledge.
    ///
    /// A server acknowledges the intersection of what was asked for and what it
    /// supports, and no more. py-kms hardcodes the reason field to 3 regardless
    /// of what the client requested, which answers a question nobody asked.
    pub const SUPPORTED: Self = Self(0x03);

    /// Build from a raw byte.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// The raw byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// The bits this host will acknowledge, given what was requested.
    #[must_use]
    pub const fn acknowledged(self) -> Self {
        Self(self.0 & Self::SUPPORTED.0)
    }

    /// Whether every bit in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        BTFN_WIRE_PREFIX, FeatureBits, KMS_INTERFACE, NDR32, NDR32_VERSION, NDR64, NDR64_VERSION,
        TransferSyntax,
    };
    use alloc::format;

    /// The wire bytes vlmcsd carries, which are the bytes on the network.
    const NDR32_WIRE: [u8; 16] = [
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48,
        0x60,
    ];
    const NDR64_WIRE: [u8; 16] = [
        0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc,
        0x36,
    ];
    const INTERFACE_WIRE: [u8; 16] = [
        0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC,
        0x06,
    ];

    /// `WIRE-004` (#62): the three GUIDs, checked in both directions —
    /// canonical text and the bytes that actually appear on the wire.
    #[test]
    fn the_three_identities_match_their_wire_bytes() {
        assert_eq!(
            format!("{KMS_INTERFACE}"),
            "51c82175-844e-4750-b0d8-ec255555bc06"
        );
        assert_eq!(format!("{NDR32}"), "8a885d04-1ceb-11c9-9fe8-08002b104860");
        assert_eq!(format!("{NDR64}"), "71710533-beba-4937-8319-b5dbef9ccc36");

        assert_eq!(TransferSyntax::classify(&NDR32_WIRE), TransferSyntax::Ndr32);
        assert_eq!(TransferSyntax::classify(&NDR64_WIRE), TransferSyntax::Ndr64);

        // The interface UUID is not a transfer syntax, and must not classify as
        // one.
        assert_eq!(
            TransferSyntax::classify(&INTERFACE_WIRE),
            TransferSyntax::Unknown
        );

        assert_eq!(NDR32_VERSION, 2);
        assert_eq!(NDR64_VERSION, 1);
    }

    /// `WIRE-007` (#65): only the first eight bytes identify the negotiation
    /// item. The next two carry the feature bits, so a whole-GUID comparison
    /// recognises exactly one request and misses every other.
    #[test]
    fn feature_negotiation_is_matched_on_its_prefix_only() {
        for requested in 0..=255_u8 {
            let mut wire = [0_u8; 16];
            wire[..8].copy_from_slice(&BTFN_WIRE_PREFIX);
            wire[8] = requested;
            // Byte 9 onwards is unspecified; vary it to prove it is ignored.
            wire[9] = requested ^ 0xFF;
            wire[15] = 0x5A;

            assert_eq!(
                TransferSyntax::classify(&wire),
                TransferSyntax::FeatureNegotiation(FeatureBits::from_bits(requested)),
                "requested bits {requested:#04x}"
            );
        }

        // One byte off the prefix and it is not a negotiation item at all.
        let mut wrong = [0_u8; 16];
        wrong[..8].copy_from_slice(&BTFN_WIRE_PREFIX);
        wrong[0] ^= 0x01;
        assert_eq!(TransferSyntax::classify(&wrong), TransferSyntax::Unknown);
    }

    /// A server acknowledges the intersection of requested and supported, and
    /// no more. py-kms hardcodes the answer.
    #[test]
    fn only_requested_and_supported_bits_are_acknowledged() {
        assert_eq!(FeatureBits::from_bits(0).acknowledged().bits(), 0);
        assert_eq!(
            FeatureBits::SECURITY_CONTEXT_MULTIPLEX
                .acknowledged()
                .bits(),
            0x01
        );
        assert_eq!(FeatureBits::from_bits(0x03).acknowledged().bits(), 0x03);
        // Bits outside the supported set are dropped rather than reflected.
        assert_eq!(FeatureBits::from_bits(0xFF).acknowledged().bits(), 0x03);
        assert_eq!(FeatureBits::from_bits(0xFC).acknowledged().bits(), 0x00);

        assert!(FeatureBits::from_bits(0x03).contains(FeatureBits::KEEP_CONNECTION_ON_ORPHAN));
        assert!(!FeatureBits::from_bits(0x01).contains(FeatureBits::KEEP_CONNECTION_ON_ORPHAN));
    }

    #[test]
    fn an_unknown_syntax_classifies_rather_than_failing() {
        assert_eq!(
            TransferSyntax::classify(&[0_u8; 16]),
            TransferSyntax::Unknown
        );
        assert_eq!(
            TransferSyntax::classify(&[0xFF_u8; 16]),
            TransferSyntax::Unknown
        );
        assert_eq!(TransferSyntax::Unknown.expected_version(), None);
        assert_eq!(TransferSyntax::Ndr32.expected_version(), Some(2));
        assert_eq!(TransferSyntax::Ndr64.expected_version(), Some(1));
    }
}

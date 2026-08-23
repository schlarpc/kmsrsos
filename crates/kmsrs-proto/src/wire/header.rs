//! The DCE/RPC common header, and the PDU types either side may send
//! (`WIRE-001`, #59; `WIRE-002`, #60).
//!
//! Sixteen bytes at the front of every PDU in both directions. Everything else
//! in this module is about deciding what to do with the rest.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Bytes in the common header.
pub const HEADER_LEN: usize = 16;

/// The connection-oriented DCE/RPC version this protocol uses.
pub const RPC_VERSION_MAJOR: u8 = 5;

/// The minor version.
pub const RPC_VERSION_MINOR: u8 = 0;

/// The data representation this host emits: little-endian integers, ASCII
/// characters, IEEE floats (`WIRE-014`, #72).
///
/// Four independent bytes rather than one integer, which is what they are:
/// the high nibble of the first is the integer representation and the low
/// nibble the character set, the second byte is the float format, and the last
/// two are reserved. Modelling it as a `u32` is how implementations end up
/// unsure whether it is big- or little-endian — vlmcsd writes `BE32(0x10000000)`
/// to produce these same four bytes.
///
/// This is **ours**, not the client's. vlmcsd `memcpy`s the whole request header
/// into its response, so it would answer a big-endian client with little-endian
/// data and claim otherwise. That is MM17, one of only three places py-kms
/// beats it.
pub const DATA_REPRESENTATION: [u8; 4] = [0x10, 0x00, 0x00, 0x00];

/// The DCE/RPC common header.
#[derive(
    FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy, PartialEq, Eq,
)]
#[repr(C)]
pub struct RpcHeader {
    /// Always 5.
    pub version_major: u8,
    /// Always 0.
    pub version_minor: u8,
    /// See [`PacketType`].
    pub packet_type: u8,
    /// See [`PacketFlags`].
    pub packet_flags: u8,
    /// See [`DATA_REPRESENTATION`].
    pub data_representation: [u8; 4],
    /// Total PDU length including this header.
    pub frag_length: U16,
    /// Length of the authentication trailer. Always zero in both directions
    /// here (`WIRE-026`, #84).
    pub auth_length: U16,
    /// The call this PDU belongs to. Echoed on every reply, including faults
    /// (`WIRE-015`, #73).
    pub call_id: U32,
}

const _: () = assert!(size_of::<RpcHeader>() == HEADER_LEN);
const _: () = assert!(align_of::<RpcHeader>() == 1);

impl RpcHeader {
    /// Build a header for a PDU this host is emitting.
    ///
    /// The version and the call ID are the *only* things taken from the
    /// request. Everything else is constructed (`WIRE-014`, #72).
    #[must_use]
    pub fn for_reply(
        packet_type: PacketType,
        flags: PacketFlags,
        call_id: u32,
        frag_length: u16,
    ) -> Self {
        Self {
            version_major: RPC_VERSION_MAJOR,
            version_minor: RPC_VERSION_MINOR,
            packet_type: packet_type.to_wire(),
            packet_flags: flags.bits(),
            data_representation: DATA_REPRESENTATION,
            frag_length: frag_length.into(),
            // Never echoed. py-kms reflects a client's `AuthLength` into a
            // `bind_ack` that carries no trailer, which is a malformed packet
            // whenever a client attempts an authenticated bind (`WIRE-026`, #84).
            auth_length: 0.into(),
            call_id: call_id.into(),
        }
    }

    /// The packet type, if it is one this protocol defines.
    #[must_use]
    pub const fn packet_type(&self) -> Option<PacketType> {
        PacketType::from_wire(self.packet_type)
    }

    /// The packet flags.
    #[must_use]
    pub const fn flags(&self) -> PacketFlags {
        PacketFlags::from_bits(self.packet_flags)
    }

    /// Whether the header names the DCE/RPC version this protocol uses.
    #[must_use]
    pub const fn version_is_supported(&self) -> bool {
        self.version_major == RPC_VERSION_MAJOR && self.version_minor == RPC_VERSION_MINOR
    }
}

/// A DCE/RPC PDU type (`WIRE-002`, #60).
///
/// Only the eight this protocol uses. A type outside the set is not decoded
/// into an `Unrecognised` variant, because unlike a licence status there is
/// nothing useful to do with one: it is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketType {
    /// 0 — a call. Accepted.
    Request,
    /// 2 — a reply. Emitted.
    Response,
    /// 3 — a call-level failure. Emitted (`WIRE-016`, #74).
    Fault,
    /// 11 — establish an association. Accepted.
    Bind,
    /// 12 — association established. Emitted.
    BindAck,
    /// 13 — association refused. Emitted.
    ///
    /// py-kms emits neither this nor a fault: an unrecognised transfer syntax
    /// is a `KeyError` swallowed by a no-op handler, and the client gets a
    /// silent RST (`WIRE-006`, #64).
    BindNak,
    /// 14 — renegotiate on an existing association. Accepted.
    ///
    /// Windows 8 and Server 2012 and later send this after an NDR64 bind. py-kms
    /// does not accept it, and disconnects (`WIRE-003`, #61).
    AlterContext,
    /// 15 — renegotiation result. Emitted.
    AlterContextResponse,
}

impl PacketType {
    /// The types a server accepts.
    ///
    /// py-kms accepts only `Bind` and `Request`, which is why a client that
    /// sends `AlterContext` — every Windows 8 or later client, after an NDR64
    /// bind — gets disconnected.
    pub const ACCEPTED: [Self; 3] = [Self::Bind, Self::AlterContext, Self::Request];

    /// The types a server emits.
    ///
    /// py-kms emits only `BindAck` and `Response`, so it has no way to refuse
    /// anything except by hanging up.
    pub const EMITTED: [Self; 5] = [
        Self::BindAck,
        Self::AlterContextResponse,
        Self::Response,
        Self::Fault,
        Self::BindNak,
    ];

    /// Decode a wire value.
    #[must_use]
    pub const fn from_wire(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Fault),
            11 => Some(Self::Bind),
            12 => Some(Self::BindAck),
            13 => Some(Self::BindNak),
            14 => Some(Self::AlterContext),
            15 => Some(Self::AlterContextResponse),
            _ => None,
        }
    }

    /// Encode to a wire value.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Response => 2,
            Self::Fault => 3,
            Self::Bind => 11,
            Self::BindAck => 12,
            Self::BindNak => 13,
            Self::AlterContext => 14,
            Self::AlterContextResponse => 15,
        }
    }

    /// Whether a server accepts this type from a client.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Bind | Self::AlterContext | Self::Request)
    }
}

/// The `PFC_*` flag byte.
///
/// A newtype rather than a bare `u8` so that echoing a client's flags back is
/// something you have to write out rather than something that happens by
/// default (`WIRE-014`, #72).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PacketFlags(u8);

impl PacketFlags {
    /// `PFC_FIRST_FRAG` — this PDU begins a message.
    pub const FIRST_FRAG: Self = Self(0x01);
    /// `PFC_LAST_FRAG` — this PDU ends a message.
    pub const LAST_FRAG: Self = Self(0x02);
    /// `PFC_PENDING_CANCEL`.
    ///
    /// vlmcsd copies the whole request header into its reply, so it reflects
    /// this back — announcing a cancellation the server was never asked for.
    pub const PENDING_CANCEL: Self = Self(0x04);
    /// `PFC_CONC_MPX` — the peer supports concurrent multiplexing.
    ///
    /// **Echoed, never asserted unrequested** (`WIRE-028`, #86). py-kms sets it
    /// unconditionally, claiming a capability the client never asked about.
    pub const CONC_MPX: Self = Self(0x10);
    /// `PFC_DID_NOT_EXECUTE` — the call had no side effects.
    pub const DID_NOT_EXECUTE: Self = Self(0x20);

    /// A complete, unfragmented message.
    pub const COMPLETE: Self = Self(0x03);

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

    /// Whether every flag in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union of two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The flags in both sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Whether no flag is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
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

    use super::{DATA_REPRESENTATION, HEADER_LEN, PacketFlags, PacketType, RpcHeader};
    use zerocopy::{FromBytes, IntoBytes};

    /// `WIRE-001` (#59): every field at its documented offset, read out of a
    /// header whose bytes are all distinct.
    #[test]
    fn every_header_field_is_at_its_documented_offset() {
        let bytes: [u8; HEADER_LEN] =
            core::array::from_fn(|index| u8::try_from(index).unwrap_or(0));
        let header = RpcHeader::read_from_bytes(&bytes).unwrap();

        assert_eq!(header.version_major, 0);
        assert_eq!(header.version_minor, 1);
        assert_eq!(header.packet_type, 2);
        assert_eq!(header.packet_flags, 3);
        assert_eq!(header.data_representation, [4, 5, 6, 7]);
        assert_eq!(header.frag_length.get(), u16::from_le_bytes([8, 9]));
        assert_eq!(header.auth_length.get(), u16::from_le_bytes([10, 11]));
        assert_eq!(header.call_id.get(), u32::from_le_bytes([12, 13, 14, 15]));
        assert_eq!(header.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn a_header_shorter_or_longer_than_sixteen_bytes_does_not_parse() {
        for len in [0_usize, 15, 17] {
            assert!(RpcHeader::read_from_bytes(&alloc::vec![0_u8; len]).is_err());
        }
    }

    /// `WIRE-002` (#60). The two sets py-kms is missing entries from are the
    /// point: it accepts only 11 and 0, so an `alter_context` disconnects the
    /// client, and it emits only 12 and 2, so it has no way to refuse anything
    /// except by hanging up.
    #[test]
    fn the_accepted_and_emitted_sets_are_the_documented_ones() {
        assert_eq!(
            PacketType::ACCEPTED.map(PacketType::to_wire),
            [11, 14, 0],
            "bind, alter_context, request"
        );
        assert_eq!(
            PacketType::EMITTED.map(PacketType::to_wire),
            [12, 15, 2, 3, 13],
            "bind_ack, alter_context_response, response, fault, bind_nak"
        );

        for accepted in PacketType::ACCEPTED {
            assert!(accepted.is_accepted(), "{accepted:?}");
        }
        for emitted in PacketType::EMITTED {
            assert!(!emitted.is_accepted(), "{emitted:?} is a reply, not a call");
        }
    }

    #[test]
    fn every_packet_type_round_trips_and_unknown_ones_do_not_decode() {
        for raw in 0..=255_u8 {
            match PacketType::from_wire(raw) {
                Some(kind) => assert_eq!(kind.to_wire(), raw),
                None => assert!(!matches!(raw, 0 | 2 | 3 | 11..=15), "{raw} should decode"),
            }
        }
    }

    /// `WIRE-014` (#72): a reply's header is constructed. Only the call ID and
    /// the RPC version come from the request.
    #[test]
    fn a_reply_header_is_constructed_not_echoed() {
        let header = RpcHeader::for_reply(
            PacketType::Response,
            PacketFlags::COMPLETE,
            0x1234_5678,
            172,
        );

        assert_eq!(header.version_major, 5);
        assert_eq!(header.version_minor, 0);
        assert_eq!(header.packet_type, 2);
        assert_eq!(header.data_representation, DATA_REPRESENTATION);
        assert_eq!(header.frag_length.get(), 172);
        assert_eq!(header.call_id.get(), 0x1234_5678);

        // `WIRE-026` (#84): never echoed. py-kms reflects a client's
        // `AuthLength` into a `bind_ack` that carries no trailer.
        assert_eq!(header.auth_length.get(), 0);
    }

    /// The data representation bytes are ours and say what we actually do.
    #[test]
    fn the_data_representation_is_little_endian_ascii_ieee() {
        assert_eq!(DATA_REPRESENTATION[0] >> 4, 1, "little-endian integers");
        assert_eq!(DATA_REPRESENTATION[0] & 0x0F, 0, "ASCII characters");
        assert_eq!(DATA_REPRESENTATION[1], 0, "IEEE floats");
        assert_eq!(&DATA_REPRESENTATION[2..], &[0, 0], "reserved");
    }

    #[test]
    fn flags_compose_and_decompose() {
        let complete = PacketFlags::COMPLETE;
        assert!(complete.contains(PacketFlags::FIRST_FRAG));
        assert!(complete.contains(PacketFlags::LAST_FRAG));
        assert!(!complete.contains(PacketFlags::CONC_MPX));
        assert_eq!(
            PacketFlags::FIRST_FRAG.union(PacketFlags::LAST_FRAG),
            complete
        );

        // The two flags that must never be set unrequested.
        let client_flags = PacketFlags::from_bits(0x07);
        assert!(client_flags.contains(PacketFlags::PENDING_CANCEL));
        assert_eq!(
            client_flags.intersection(PacketFlags::CONC_MPX),
            PacketFlags::default(),
            "a client that did not ask for multiplexing must not be told it has it"
        );
        assert!(PacketFlags::default().is_empty());
    }
}

//! Fault PDUs (`WIRE-015`, #73; `WIRE-016`, #74).
//!
//! A fault says "this call failed" at the RPC layer, as distinct from a
//! response carrying a non-zero `HRESULT`, which says "the call succeeded and
//! the answer is an error". Both exist and they are not interchangeable.
//!
//! # Two things vlmcsd gets wrong here
//!
//! * Its `SendError()` builds its header through `createRpcHeader`, which
//!   hardcodes `CallId = 2` — so every error it emits carries the same call ID
//!   regardless of which call failed. That is trivially fingerprintable, and it
//!   also makes the reply unmatchable by a client with more than one call
//!   outstanding.
//! * It identifies a fault by *body length == 32*. Length is not a
//!   discriminator: a response can be 32 bytes, and a future fault carrying
//!   stub data would not be.
//!
//! `SendError()` also declares an `AllocHint` of 32 while initialising 16
//! bytes, so it emits two `DWORD`s of uninitialised stack. Safe Rust cannot,
//! and this fault is fully written.

use crate::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
use zerocopy::IntoBytes;

/// Bytes in a fault PDU: the common header plus a fixed body.
pub const FAULT_LEN: usize = HEADER_LEN + 16;

/// An NCA status code carried by a fault (`WIRE-016`, #74).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NcaStatus {
    /// `nca_s_unk_if` — the context ID names no accepted presentation context,
    /// or the operation is not one this interface implements
    /// (`WIRE-009`, #67).
    UnknownInterface,

    /// `nca_s_proto_error` — the PDU was structurally wrong: an authentication
    /// trailer where none can be handled, or NDR lengths that disagree with the
    /// bytes present.
    ProtocolError,
}

impl NcaStatus {
    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> u32 {
        match self {
            Self::UnknownInterface => 0x1c01_0003,
            Self::ProtocolError => 0x1c01_000b,
        }
    }

    /// Text for the event log.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::UnknownInterface => "nca_s_unk_if",
            Self::ProtocolError => "nca_s_proto_error",
        }
    }
}

impl core::fmt::Display for NcaStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} (0x{:08X})", self.description(), self.to_wire())
    }
}

/// Write a fault PDU.
///
/// `call_id` is the request's, echoed (`WIRE-015`, #73). `context_id` is the
/// request's too, or zero when the request named one that does not exist.
///
/// Returns the number of bytes written.
///
/// # Errors
///
/// Returns `None` if `out` cannot hold [`FAULT_LEN`] bytes.
#[must_use]
pub fn write(out: &mut [u8], call_id: u32, context_id: u16, status: NcaStatus) -> Option<usize> {
    let region = out.get_mut(..FAULT_LEN)?;

    // `PFC_DID_NOT_EXECUTE` is the part that matters to a client: it says the
    // call had no side effects, so retrying is safe.
    let flags = PacketFlags::COMPLETE.union(PacketFlags::DID_NOT_EXECUTE);
    let frag_length = u16::try_from(FAULT_LEN).ok()?;
    let header = RpcHeader::for_reply(PacketType::Fault, flags, call_id, frag_length);
    region
        .get_mut(..HEADER_LEN)?
        .copy_from_slice(header.as_bytes());

    let body = region.get_mut(HEADER_LEN..)?;
    // `AllocHint` counts the body from the NDR fields onwards, as in a
    // response: status and its reserved word.
    body.get_mut(0..4)?.copy_from_slice(&8_u32.to_le_bytes());
    body.get_mut(4..6)?
        .copy_from_slice(&context_id.to_le_bytes());
    // Cancel count and its reserved byte.
    body.get_mut(6..8)?.copy_from_slice(&0_u16.to_le_bytes());
    body.get_mut(8..12)?
        .copy_from_slice(&status.to_wire().to_le_bytes());
    // Reserved. Written rather than left alone: vlmcsd declares 32 bytes and
    // initialises 16, emitting two DWORDs of uninitialised stack.
    body.get_mut(12..16)?.copy_from_slice(&0_u32.to_le_bytes());

    Some(FAULT_LEN)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{FAULT_LEN, NcaStatus, write};
    use crate::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
    use alloc::vec;
    use zerocopy::FromBytes;

    /// `WIRE-016` (#74): both status codes, and the flags a fault carries.
    #[test]
    fn a_fault_carries_the_status_and_the_did_not_execute_flag() {
        for (status, expected) in [
            (NcaStatus::UnknownInterface, 0x1c01_0003_u32),
            (NcaStatus::ProtocolError, 0x1c01_000b),
        ] {
            let mut out = vec![0xAA_u8; 64];
            let written = write(&mut out, 0x1234_5678, 7, status).unwrap();
            assert_eq!(written, FAULT_LEN);
            assert_eq!(status.to_wire(), expected);

            let header = RpcHeader::read_from_bytes(&out[..HEADER_LEN]).unwrap();
            assert_eq!(header.packet_type, PacketType::Fault.to_wire());
            assert_eq!(usize::from(header.frag_length.get()), FAULT_LEN);

            let flags = header.flags();
            assert!(flags.contains(PacketFlags::FIRST_FRAG));
            assert!(flags.contains(PacketFlags::LAST_FRAG));
            assert!(
                flags.contains(PacketFlags::DID_NOT_EXECUTE),
                "a client must be told the call had no side effects"
            );

            assert_eq!(
                u32::from_le_bytes(out[24..28].try_into().unwrap()),
                expected
            );
        }
    }

    /// `WIRE-015` (#73). vlmcsd's `SendError()` goes through `createRpcHeader`,
    /// which hardcodes `CallId = 2`, so every error it emits carries the same
    /// call ID whatever call actually failed.
    #[test]
    fn the_call_id_is_echoed_rather_than_constant() {
        let mut seen = alloc::vec::Vec::new();
        for call_id in [0_u32, 1, 2, 3, 0xFFFF_FFFF] {
            let mut out = vec![0_u8; FAULT_LEN];
            write(&mut out, call_id, 0, NcaStatus::ProtocolError).unwrap();
            let header = RpcHeader::read_from_bytes(&out[..HEADER_LEN]).unwrap();
            assert_eq!(header.call_id.get(), call_id);
            seen.push(header.call_id.get());
        }
        assert!(
            seen.iter().any(|id| *id != 2),
            "a constant call id would be a fingerprint"
        );
    }

    /// vlmcsd declares an `AllocHint` of 32 while initialising 16 bytes, so it
    /// emits two `DWORD`s of uninitialised stack. Every byte here is written.
    #[test]
    fn every_byte_of_the_fault_is_written() {
        let mut out = vec![0xAA_u8; FAULT_LEN * 2];
        write(&mut out, 9, 3, NcaStatus::UnknownInterface).unwrap();

        // The reserved word after the status is zero, not whatever was there.
        assert_eq!(u32::from_le_bytes(out[28..32].try_into().unwrap()), 0);
        // The context id is echoed, and the cancel count is zero.
        assert_eq!(u16::from_le_bytes(out[20..22].try_into().unwrap()), 3);
        assert_eq!(u16::from_le_bytes(out[22..24].try_into().unwrap()), 0);
        // Nothing past the fault was touched.
        assert!(out[FAULT_LEN..].iter().all(|byte| *byte == 0xAA));
    }

    /// A fault is identified by its packet type, never by its length. vlmcsd
    /// tests `body length == 32`, and length is not a discriminator.
    #[test]
    fn a_fault_is_identified_by_its_packet_type() {
        let mut out = vec![0_u8; FAULT_LEN];
        write(&mut out, 1, 0, NcaStatus::ProtocolError).unwrap();
        let header = RpcHeader::read_from_bytes(&out[..HEADER_LEN]).unwrap();
        assert_eq!(header.packet_type(), Some(PacketType::Fault));
        assert_ne!(header.packet_type(), Some(PacketType::Response));
    }

    #[test]
    fn an_undersized_buffer_is_refused() {
        for len in 0..FAULT_LEN {
            let mut out = vec![0_u8; len];
            assert_eq!(write(&mut out, 1, 0, NcaStatus::ProtocolError), None);
        }
    }

    #[test]
    fn statuses_have_text_for_the_log() {
        assert_eq!(NcaStatus::UnknownInterface.description(), "nca_s_unk_if");
        assert_eq!(NcaStatus::ProtocolError.description(), "nca_s_proto_error");
        assert_eq!(
            alloc::format!("{}", NcaStatus::UnknownInterface),
            "nca_s_unk_if (0x1C010003)"
        );
    }
}

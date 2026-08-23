//! Building the client side of a DCE/RPC conversation
//! (`WIRE-027`, #85; `CLI-001`, #207).
//!
//! The server's half is [`crate::wire::connection`]. This is what a client
//! sends, and it lives here for the same reason
//! [`crate::kms::framing::encode_request`] does: a diagnostic client with its
//! own copy of the framing would be testing itself rather than the protocol.
//!
//! # Call IDs start at 2
//!
//! Microsoft's client does, so this does. There is no documented reason for it
//! — it is simply what the thing being emulated does, and a host that only ever
//! sees call ID 2 from real clients is a host where 1 is an anomaly worth not
//! producing (`WIRE-027`, #85).
//!
//! # Wine answers every call with call ID 1
//!
//! Wine's `rpcrt4` does not echo the call ID; it replies 1 to everything. A
//! client that treated a mismatched call ID as fatal would refuse to talk to
//! anything running under Wine, which is a real deployment. So a mismatch is a
//! warning, raised **once** per association rather than per request — a warning
//! repeated on every exchange is one an operator learns to ignore.

use crate::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
use crate::wire::syntax::{self, TransferSyntax};
use zerocopy::{FromBytes, IntoBytes};

/// The first call ID a client sends (`WIRE-027`, #85).
pub const FIRST_CALL_ID: u32 = 2;

/// The KMS interface UUID, on the wire.
///
/// Derived from [`syntax::KMS_INTERFACE`] rather than written out, so the two
/// cannot drift and so the byte order is converted by the one function that
/// knows how (`WIRE-007`, #65).
#[must_use]
pub fn kms_interface_wire() -> [u8; 16] {
    syntax::guid_to_wire(syntax::KMS_INTERFACE)
}

/// The maximum transmit and receive fragment size a client offers.
///
/// 5840 is what Microsoft's client sends. It is not a round number and it is
/// not derived from anything; it is simply the value, and a host that only sees
/// 5840 is a host where anything else is worth not producing.
pub const FRAGMENT_SIZE: u16 = 5840;

/// Why a client could not read a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    /// The reply is shorter than the common header.
    TooShort {
        /// Bytes available.
        available: usize,
    },
    /// The reply's fragment length disagrees with how many bytes arrived.
    LengthMismatch {
        /// What the header declared.
        declared: usize,
        /// What arrived.
        available: usize,
    },
    /// The reply was a packet type a client does not expect here.
    UnexpectedPacketType {
        /// The raw type byte.
        raw: u8,
    },
    /// The server refused the bind.
    BindRejected,
    /// The server faulted the call.
    Faulted {
        /// The NCA status it reported.
        status: u32,
    },
    /// The output buffer was too small.
    BufferTooSmall {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { available } => {
                write!(f, "a reply needs {HEADER_LEN} bytes, got {available}")
            }
            Self::LengthMismatch {
                declared,
                available,
            } => write!(
                f,
                "the reply declared {declared} bytes but {available} arrived"
            ),
            Self::UnexpectedPacketType { raw } => {
                write!(f, "the server replied with packet type {raw}")
            }
            Self::BindRejected => f.write_str("the server rejected the bind"),
            Self::Faulted { status } => write!(f, "the server faulted the call: 0x{status:08X}"),
            Self::BufferTooSmall { needed, available } => {
                write!(f, "need {needed} bytes, have {available}")
            }
        }
    }
}

impl core::error::Error for ClientError {}

/// Something about the conversation worth telling an operator
/// (`CLI-002`, #208).
///
/// Each is a property a genuine exchange has. A warning is not a failure — the
/// activation may still work — but every one of them is a way to tell an
/// emulator from a real host, which is why the client raises them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Warning {
    /// The reply's call ID did not match the request's.
    ///
    /// Wine's `rpcrt4` answers 1 to everything (`WIRE-027`, #85). Raised once
    /// per association, not per request.
    CallIdNotEchoed {
        /// What was sent.
        sent: u32,
        /// What came back.
        received: u32,
    },
    /// The server did not accept NDR32.
    ///
    /// Every real host does. A host offering only NDR64 is not one Microsoft
    /// shipped.
    Ndr32NotAccepted,
    /// The server accepted NDR64 but did not acknowledge the bind-time feature
    /// negotiation.
    ///
    /// A genuine host that speaks NDR64 speaks BTFN, because the same code
    /// added both.
    Ndr64WithoutFeatureNegotiation,
    /// The stub padding was not zero.
    ///
    /// A real host zeroes it. Non-zero padding is uninitialised memory, which
    /// is both a leak and a tell.
    NonZeroPadding,
    /// The declared allocation hint disagreed with the stub length.
    AllocHintMismatch {
        /// What the header declared.
        declared: u32,
        /// The actual stub length.
        actual: u32,
    },
    /// The server closed the connection instead of keeping it open.
    ///
    /// A genuine host keeps the association open for reuse.
    ConnectionClosedEarly,
}

impl core::fmt::Display for Warning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CallIdNotEchoed { sent, received } => write!(
                f,
                "the server answered call {sent} with call ID {received} \
                 (Wine's rpcrt4 answers 1 to everything)"
            ),
            Self::Ndr32NotAccepted => {
                f.write_str("the server did not accept NDR32, which every real host does")
            }
            Self::Ndr64WithoutFeatureNegotiation => f.write_str(
                "the server accepted NDR64 but not bind-time feature negotiation; \
                 a genuine host that speaks one speaks both",
            ),
            Self::NonZeroPadding => {
                f.write_str("the stub padding was not zero, which leaks memory contents")
            }
            Self::AllocHintMismatch { declared, actual } => write!(
                f,
                "the allocation hint said {declared} but the stub was {actual} bytes"
            ),
            Self::ConnectionClosedEarly => {
                f.write_str("the server closed the association instead of keeping it open")
            }
        }
    }
}

/// A client's side of one association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAssociation {
    next_call_id: u32,
    /// Whether a call-ID mismatch has already been reported.
    call_id_warned: bool,
}

impl Default for ClientAssociation {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientAssociation {
    /// A fresh association, ready to bind.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            // `WIRE-027` (#85): Microsoft starts at 2, so we do.
            next_call_id: FIRST_CALL_ID,
            call_id_warned: false,
        }
    }

    /// The call ID the next PDU will carry.
    #[must_use]
    pub const fn next_call_id(self) -> u32 {
        self.next_call_id
    }

    /// Take the next call ID and advance.
    fn take_call_id(&mut self) -> u32 {
        let id = self.next_call_id;
        // Wrapping rather than saturating: a client that made four billion
        // calls on one association should keep working, and the server does not
        // require monotonicity.
        self.next_call_id = self.next_call_id.wrapping_add(1);
        id
    }

    /// Build a bind PDU offering both transfer syntaxes.
    ///
    /// Returns the bytes written and the call ID used.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::BufferTooSmall`] if `out` cannot hold the PDU.
    pub fn bind(&mut self, out: &mut [u8], offer_ndr64: bool) -> Result<(usize, u32), ClientError> {
        let call_id = self.take_call_id();
        let mut body = [0_u8; 200];
        let body_len = write_bind_body(&mut body, offer_ndr64).ok_or({
            ClientError::BufferTooSmall {
                needed: 200,
                available: body.len(),
            }
        })?;
        let len = frame(
            out,
            PacketType::Bind,
            call_id,
            body.get(..body_len).unwrap_or(&[]),
        )?;
        Ok((len, call_id))
    }

    /// Build a request PDU carrying a KMS stub.
    ///
    /// Returns the bytes written and the call ID used.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::BufferTooSmall`] if `out` cannot hold the PDU.
    pub fn request(
        &mut self,
        out: &mut [u8],
        context_id: u16,
        syntax: TransferSyntax,
        payload: &[u8],
    ) -> Result<(usize, u32), ClientError> {
        let call_id = self.take_call_id();
        let header_len = request_stub_header_len(syntax);
        let body_len = header_len.saturating_add(payload.len());
        let total = HEADER_LEN.saturating_add(body_len);
        let available = out.len();
        let too_small = ClientError::BufferTooSmall {
            needed: total,
            available,
        };
        if available < total {
            return Err(too_small);
        }
        let frag_length = u16::try_from(total).map_err(|_| too_small)?;

        let header = RpcHeader::for_reply(
            PacketType::Request,
            PacketFlags::COMPLETE,
            call_id,
            frag_length,
        );
        out.get_mut(..HEADER_LEN)
            .ok_or(too_small)?
            .copy_from_slice(header.as_bytes());

        let stub = out.get_mut(HEADER_LEN..total).ok_or(too_small)?;
        write_request_stub_header(stub, context_id, syntax, payload.len());
        stub.get_mut(header_len..)
            .ok_or(too_small)?
            .copy_from_slice(payload);

        Ok((total, call_id))
    }

    /// Read a reply, checking the properties a genuine exchange has.
    ///
    /// `syntax` is the transfer syntax the association settled on, which
    /// decides how wide the NDR length fields are. For a `bind_ack` it is
    /// unused; pass [`TransferSyntax::Ndr32`].
    ///
    /// `warnings` receives anything worth telling an operator; the return value
    /// is the payload, if the reply carried one.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the reply cannot be read, was a rejection, or
    /// was a fault.
    pub fn read_reply<'a>(
        &mut self,
        reply: &'a [u8],
        sent_call_id: u32,
        syntax: TransferSyntax,
        warnings: &mut dyn FnMut(Warning),
    ) -> Result<Reply<'a>, ClientError> {
        let (header, body) =
            RpcHeader::read_from_prefix(reply).map_err(|_| ClientError::TooShort {
                available: reply.len(),
            })?;

        let declared = usize::from(header.frag_length.get());
        if declared != reply.len() {
            return Err(ClientError::LengthMismatch {
                declared,
                available: reply.len(),
            });
        }

        // `WIRE-027` (#85): Wine answers 1 to everything. Warn once, not per
        // request — a warning repeated on every exchange is one an operator
        // learns to ignore.
        let received = header.call_id.get();
        if received != sent_call_id && !self.call_id_warned {
            self.call_id_warned = true;
            warnings(Warning::CallIdNotEchoed {
                sent: sent_call_id,
                received,
            });
        }

        match header.packet_type() {
            Some(PacketType::BindAck) => {
                let accepted = read_bind_ack(body, warnings);
                Ok(Reply::BindAck { body, accepted })
            }
            Some(PacketType::BindNak) => Err(ClientError::BindRejected),
            Some(PacketType::Fault) => {
                let status = body
                    .get(8..12)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map_or(0, u32::from_le_bytes);
                Err(ClientError::Faulted { status })
            }
            Some(PacketType::Response) => {
                let parsed = crate::wire::stub::parse_response(body, syntax).map_err(|_| {
                    ClientError::TooShort {
                        available: body.len(),
                    }
                })?;

                // `CLI-002` (#208): the allocation hint counts from the NDR
                // fields onwards, matching what the peer measures
                // (`WIRE-020`, #78).
                let measured = u32::try_from(body.len().saturating_sub(8)).unwrap_or(u32::MAX);
                if parsed.alloc_hint != measured {
                    warnings(Warning::AllocHintMismatch {
                        declared: parsed.alloc_hint,
                        actual: measured,
                    });
                }

                // `CLI-002` (#208): a real host zeroes its NDR padding.
                // Non-zero padding is uninitialised memory — a leak, and a way
                // to identify the sender.
                if parsed.padding.iter().any(|byte| *byte != 0) {
                    warnings(Warning::NonZeroPadding);
                }

                Ok(Reply::Response {
                    stub: parsed.payload,
                    result: parsed.result,
                })
            }
            _ => Err(ClientError::UnexpectedPacketType {
                raw: header.packet_type,
            }),
        }
    }
}

/// What a reply was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply<'a> {
    /// A bind was accepted; the body is the `bind_ack`.
    BindAck {
        /// The `bind_ack` body, after the common header.
        body: &'a [u8],
        /// The context the server accepted, if any.
        ///
        /// A client **must** use this rather than assuming context 0. A host
        /// accepts exactly one transfer syntax, and when NDR64 is offered it is
        /// the one accepted — so a client that offered both and then sent on
        /// context 0 would be sending on a context the server refused
        /// (`WIRE-005`, #63; `WIRE-029`, #87).
        accepted: Option<Accepted>,
    },
    /// A call was answered.
    Response {
        /// The KMS payload, with the NDR framing stripped.
        stub: &'a [u8],
        /// The HRESULT the call returned (`CLI-014`, #220).
        result: u32,
    },
}

/// The context a server accepted, and what to frame stubs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// The context ID to send requests on.
    pub context_id: u16,
    /// The syntax to frame stubs in.
    pub syntax: TransferSyntax,
}

/// Read a `bind_ack`'s results and work out which context was accepted.
///
/// Also raises the negotiation warning `CLI-002` (#208) asks for: NDR64
/// accepted without bind-time feature negotiation being acknowledged.
///
/// Returns `None` if the acknowledgement is malformed or accepted nothing. A
/// client with no accepted context has nothing to send on, which the caller
/// treats as a failure rather than guessing at context 0.
fn read_bind_ack(body: &[u8], warnings: &mut dyn FnMut(Warning)) -> Option<Accepted> {
    // max_xmit u16, max_recv u16, assoc_group u32, then a counted secondary
    // address, then padding to a 4-byte boundary, then the result count.
    let address_len = usize::from(u16::from_le_bytes([*body.get(8)?, *body.get(9)?]));
    let after_address = 10_usize.checked_add(address_len)?;
    // The results array starts on a 4-byte boundary relative to the **PDU**,
    // and the PDU began `HEADER_LEN` bytes before this body (`WIRE-013`, #71).
    let absolute = HEADER_LEN.checked_add(after_address)?;
    let padding = absolute.wrapping_neg() & 3;
    let results_at = after_address.checked_add(padding)?;

    let count = usize::from(*body.get(results_at)?);
    let mut cursor = results_at.checked_add(4)?;

    let mut accepted: Option<Accepted> = None;
    let mut saw_feature_ack = false;

    for index in 0..count {
        let next = cursor.checked_add(1)?;
        let ack_result = u16::from_le_bytes([*body.get(cursor)?, *body.get(next)?]);

        match ack_result {
            // `negotiate_ack`: the feature-negotiation acknowledgement, which
            // is not a context to send calls on.
            3 => saw_feature_ack = true,
            0 if accepted.is_none() => {
                let syntax_start = cursor.checked_add(4)?;
                let syntax_end = syntax_start.checked_add(16)?;
                let syntax_bytes: [u8; 16] = body.get(syntax_start..syntax_end)?.try_into().ok()?;
                // Results come back in the order the contexts were offered, so
                // the accepted context is the one at this index — which is the
                // client's own numbering.
                accepted = Some(Accepted {
                    context_id: u16::try_from(index).ok()?,
                    syntax: TransferSyntax::classify(&syntax_bytes),
                });
            }
            _ => {}
        }
        cursor = cursor.checked_add(RESULT_LEN)?;
    }

    let accepted = accepted?;
    if accepted.syntax == TransferSyntax::Ndr64 && !saw_feature_ack {
        warnings(Warning::Ndr64WithoutFeatureNegotiation);
    }
    Some(accepted)
}

/// Bytes in one `p_result_t`.
const RESULT_LEN: usize = 24;

/// Wrap a body in an RPC header.
fn frame(
    out: &mut [u8],
    packet_type: PacketType,
    call_id: u32,
    body: &[u8],
) -> Result<usize, ClientError> {
    let total = HEADER_LEN.saturating_add(body.len());
    if out.len() < total {
        return Err(ClientError::BufferTooSmall {
            needed: total,
            available: out.len(),
        });
    }
    let available = out.len();
    let too_small = ClientError::BufferTooSmall {
        needed: total,
        available,
    };
    let frag_length = u16::try_from(total).map_err(|_| too_small)?;
    let header = RpcHeader::for_reply(packet_type, PacketFlags::COMPLETE, call_id, frag_length);
    out.get_mut(..HEADER_LEN)
        .ok_or(too_small)?
        .copy_from_slice(header.as_bytes());
    out.get_mut(HEADER_LEN..total)
        .ok_or(too_small)?
        .copy_from_slice(body);
    Ok(total)
}

/// Write a bind body offering NDR32, and optionally NDR64 plus feature
/// negotiation, the way a real client does.
fn write_bind_body(out: &mut [u8], offer_ndr64: bool) -> Option<usize> {
    let contexts: usize = if offer_ndr64 { 3 } else { 1 };
    let mut cursor = 0_usize;

    let mut put = |bytes: &[u8], cursor: &mut usize| -> Option<()> {
        let end = cursor.checked_add(bytes.len())?;
        out.get_mut(*cursor..end)?.copy_from_slice(bytes);
        *cursor = end;
        Some(())
    };

    put(&FRAGMENT_SIZE.to_le_bytes(), &mut cursor)?;
    put(&FRAGMENT_SIZE.to_le_bytes(), &mut cursor)?;
    put(&0_u32.to_le_bytes(), &mut cursor)?;
    put(&[u8::try_from(contexts).ok()?, 0, 0, 0], &mut cursor)?;

    // Bind-time feature negotiation is offered as a third context whose
    // "syntax" is the BTFN prefix plus the features the client wants. A genuine
    // client that offers NDR64 offers this too, because the same Windows
    // release added both.
    let mut btfn = [0_u8; 16];
    btfn.get_mut(..8)?
        .copy_from_slice(&syntax::BTFN_WIRE_PREFIX);
    *btfn.get_mut(8)? = syntax::FeatureBits::SUPPORTED.bits();

    let offers: [(u16, [u8; 16], u32); 3] = [
        (
            0,
            syntax::guid_to_wire(syntax::NDR32),
            syntax::NDR32_VERSION,
        ),
        (
            1,
            syntax::guid_to_wire(syntax::NDR64),
            syntax::NDR64_VERSION,
        ),
        (2, btfn, 1),
    ];
    for (context_id, wire, version) in offers.iter().take(contexts) {
        put(&context_id.to_le_bytes(), &mut cursor)?;
        put(&[1, 0], &mut cursor)?;
        put(&kms_interface_wire(), &mut cursor)?;
        put(&0x0000_0001_u32.to_le_bytes(), &mut cursor)?;
        put(wire, &mut cursor)?;
        put(&version.to_le_bytes(), &mut cursor)?;
    }
    Some(cursor)
}

/// How long a request stub header is for a syntax.
///
/// NDR64 widens the two conformant-array counts from 4 bytes to 8.
const fn request_stub_header_len(syntax: TransferSyntax) -> usize {
    match syntax {
        TransferSyntax::Ndr64 => 8 + 16,
        _ => 8 + 8,
    }
}

/// Write a request stub header: allocation hint, context ID, opnum, then the
/// two conformant-array counts.
fn write_request_stub_header(
    out: &mut [u8],
    context_id: u16,
    syntax: TransferSyntax,
    payload_len: usize,
) {
    let alloc_hint = u32::try_from(payload_len).unwrap_or(u32::MAX);
    let mut cursor = 0_usize;
    let mut put = |bytes: &[u8], cursor: &mut usize| {
        if let Some(end) = cursor.checked_add(bytes.len())
            && let Some(slot) = out.get_mut(*cursor..end)
        {
            slot.copy_from_slice(bytes);
            *cursor = end;
        }
    };

    put(&alloc_hint.to_le_bytes(), &mut cursor);
    put(&context_id.to_le_bytes(), &mut cursor);
    put(&0_u16.to_le_bytes(), &mut cursor);

    if syntax == TransferSyntax::Ndr64 {
        let count = u64::try_from(payload_len).unwrap_or(u64::MAX);
        put(&count.to_le_bytes(), &mut cursor);
        put(&count.to_le_bytes(), &mut cursor);
    } else {
        put(&alloc_hint.to_le_bytes(), &mut cursor);
        put(&alloc_hint.to_le_bytes(), &mut cursor);
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
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{ClientAssociation, FIRST_CALL_ID, HEADER_LEN, Reply, Warning};
    use crate::wire::header::PacketFlags;
    use crate::wire::syntax::TransferSyntax;
    use alloc::vec;
    use alloc::vec::Vec;

    /// `WIRE-027` (#85): Microsoft's client starts at 2, so this does.
    #[test]
    fn call_ids_start_at_two_and_increment() {
        let mut association = ClientAssociation::new();
        assert_eq!(association.next_call_id(), FIRST_CALL_ID);
        assert_eq!(FIRST_CALL_ID, 2);

        let mut out = [0_u8; 512];
        let (_, first) = association.bind(&mut out, true).unwrap();
        assert_eq!(first, 2);

        let (_, second) = association
            .request(
                &mut out,
                0,
                crate::wire::syntax::TransferSyntax::Ndr32,
                &[0; 8],
            )
            .unwrap();
        assert_eq!(second, 3, "the next call is 3, not 2 again");

        let (_, third) = association
            .request(
                &mut out,
                0,
                crate::wire::syntax::TransferSyntax::Ndr32,
                &[0; 8],
            )
            .unwrap();
        assert_eq!(third, 4);
    }

    /// `WIRE-027` (#85): Wine's `rpcrt4` answers 1 to everything. That must be
    /// a warning rather than a refusal — Wine is a real deployment — and it
    /// must be raised **once**, because a warning repeated on every exchange is
    /// one an operator learns to ignore.
    #[test]
    fn the_wine_call_id_bug_warns_once_not_per_request() {
        let mut association = ClientAssociation::new();
        let mut out = [0_u8; 512];
        let mut seen: Vec<Warning> = Vec::new();

        for _ in 0..5 {
            let (_, sent) = association
                .request(
                    &mut out,
                    0,
                    crate::wire::syntax::TransferSyntax::Ndr32,
                    &[0; 8],
                )
                .unwrap();
            // A reply that always says call ID 1, as Wine does.
            let reply = wine_response(1);
            let outcome =
                association.read_reply(&reply, sent, TransferSyntax::Ndr32, &mut |warning| {
                    seen.push(warning);
                });
            assert!(outcome.is_ok(), "a Wine reply must not be fatal");
        }

        assert_eq!(
            seen.len(),
            1,
            "the call-ID warning was raised {} times",
            seen.len()
        );
        assert!(matches!(
            seen.first(),
            Some(Warning::CallIdNotEchoed { received: 1, .. })
        ));
    }

    /// A correctly echoed call ID produces no warning at all.
    #[test]
    fn an_echoed_call_id_is_silent() {
        let mut association = ClientAssociation::new();
        let mut out = [0_u8; 512];
        let mut seen: Vec<Warning> = Vec::new();

        for _ in 0..5 {
            let (_, sent) = association
                .request(
                    &mut out,
                    0,
                    crate::wire::syntax::TransferSyntax::Ndr32,
                    &[0; 8],
                )
                .unwrap();
            let reply = wine_response(sent);
            association
                .read_reply(&reply, sent, TransferSyntax::Ndr32, &mut |warning| {
                    seen.push(warning);
                })
                .unwrap();
        }
        assert!(seen.is_empty(), "{seen:?}");
    }

    /// A response PDU with the given call ID, framed by the **server's own**
    /// writer.
    ///
    /// Built with `stub::write_response` rather than by hand, so the test
    /// cannot drift from the layout the server actually emits — which is
    /// exactly how the client's first response parser came to read from the
    /// wrong offset and go unnoticed.
    fn wine_response(call_id: u32) -> Vec<u8> {
        use crate::wire::header::{PacketFlags, PacketType, RpcHeader};
        use crate::wire::stub;
        use zerocopy::IntoBytes;

        let payload = [0_u8; 8];
        let stub_len = stub::response_stub_len(TransferSyntax::Ndr32, payload.len());
        let frag = u16::try_from(super::HEADER_LEN + stub_len).unwrap();
        let header =
            RpcHeader::for_reply(PacketType::Response, PacketFlags::COMPLETE, call_id, frag);

        let mut out = vec![0_u8; super::HEADER_LEN + stub_len];
        out[..super::HEADER_LEN].copy_from_slice(header.as_bytes());
        stub::write_response(
            &mut out[super::HEADER_LEN..],
            TransferSyntax::Ndr32,
            0,
            0,
            &payload,
        )
        .unwrap();
        out
    }

    /// `CLI-002` (#208): a mismatched allocation hint is reported.
    #[test]
    fn a_mismatched_alloc_hint_warns() {
        let mut association = ClientAssociation::new();
        let mut reply = wine_response(2);
        // Claim a longer stub than was sent. The hint is the first field of
        // the stub, immediately after the RPC header.
        reply[super::HEADER_LEN..super::HEADER_LEN + 4].copy_from_slice(&999_u32.to_le_bytes());

        let mut seen: Vec<Warning> = Vec::new();
        association
            .read_reply(&reply, 2, TransferSyntax::Ndr32, &mut |warning| {
                seen.push(warning);
            })
            .unwrap();
        assert!(
            seen.iter()
                .any(|warning| matches!(warning, Warning::AllocHintMismatch { declared: 999, .. })),
            "{seen:?}"
        );
    }

    /// A reply whose declared length disagrees with what arrived is an error,
    /// not a warning: nothing after it can be trusted.
    #[test]
    fn a_length_mismatch_is_fatal() {
        let mut association = ClientAssociation::new();
        let mut reply = wine_response(2);
        reply.push(0);
        let outcome = association.read_reply(&reply, 2, TransferSyntax::Ndr32, &mut |_| {});
        assert!(matches!(
            outcome,
            Err(super::ClientError::LengthMismatch { .. })
        ));
    }

    /// `WIRE-005` (#63) and `WIRE-029` (#87): a host accepts exactly one
    /// transfer syntax, and when NDR64 is offered that is the one accepted.
    ///
    /// So a client that offered both and then sent on context 0 would be
    /// sending on a context the server refused — which is a hang, not an
    /// error, because a refused context produces no reply. Reading the accepted
    /// context out of the `bind_ack` is not optional.
    #[test]
    fn the_client_uses_the_context_the_server_accepted() {
        use crate::entropy::testing::DeterministicEntropy;
        use crate::wire::bind::{self, AckParameters};
        use crate::wire::header::PacketType;

        let mut association = ClientAssociation::new();
        let mut out = [0_u8; 512];
        let (len, call_id) = association.bind(&mut out, true).unwrap();

        // The server's side, for real.
        let request = bind::parse(&out[HEADER_LEN..len]).unwrap();
        let decision = bind::decide(&request, true);
        let server_choice = decision.accepted_context.unwrap();
        assert_eq!(
            server_choice.syntax,
            crate::wire::syntax::TransferSyntax::Ndr64,
            "NDR64 wins when both are offered"
        );
        assert_ne!(
            server_choice.context_id, 0,
            "and it is not context 0, which is the NDR32 offer"
        );

        let mut entropy = DeterministicEntropy::from_seed(1);
        let mut ack = [0_u8; 512];
        let ack_len = bind::write_ack(
            &AckParameters {
                packet_type: PacketType::BindAck,
                call_id,
                assoc_group: 0x1234,
                max_xmit_frag: 5840,
                max_recv_frag: 5840,
                secondary_address: b"1688",
                client_flags: PacketFlags::COMPLETE,
            },
            &decision,
            &mut entropy,
            &mut ack,
        )
        .unwrap();

        let mut seen: Vec<Warning> = Vec::new();
        let reply = association
            .read_reply(
                &ack[..ack_len],
                call_id,
                TransferSyntax::Ndr32,
                &mut |warning| seen.push(warning),
            )
            .unwrap();
        let Reply::BindAck { accepted, .. } = reply else {
            panic!("expected a bind_ack, got {reply:?}");
        };
        let accepted = accepted.expect("the server accepted a context");

        assert_eq!(
            accepted.context_id, server_choice.context_id,
            "the client must agree with the server about which context to use"
        );
        assert_eq!(accepted.syntax, server_choice.syntax);

        // `CLI-002` (#208): our own server acknowledges feature negotiation
        // alongside NDR64, so there is nothing to warn about.
        assert!(seen.is_empty(), "{seen:?}");
    }

    /// `CLI-002` (#208): NDR64 accepted without bind-time feature negotiation
    /// being acknowledged is a tell — a genuine host that speaks one speaks
    /// both, because the same Windows release added them.
    #[test]
    fn ndr64_without_feature_negotiation_warns() {
        use crate::entropy::testing::DeterministicEntropy;
        use crate::wire::bind::{self, AckParameters};
        use crate::wire::header::PacketType;

        let mut association = ClientAssociation::new();
        let mut out = [0_u8; 512];
        // Offer NDR64 but no feature-negotiation context, so the ack cannot
        // carry the acknowledgement.
        let (len, call_id) = association.bind(&mut out, true).unwrap();
        let request = bind::parse(&out[HEADER_LEN..len]).unwrap();
        let mut decision = bind::decide(&request, true);
        // Drop the negotiate_ack result, as a host that does not speak BTFN
        // would.
        decision.results.retain(|result| result.ack_result != 3);

        let mut entropy = DeterministicEntropy::from_seed(1);
        let mut ack = [0_u8; 512];
        let ack_len = bind::write_ack(
            &AckParameters {
                packet_type: PacketType::BindAck,
                call_id,
                assoc_group: 0x1234,
                max_xmit_frag: 5840,
                max_recv_frag: 5840,
                secondary_address: b"1688",
                client_flags: PacketFlags::COMPLETE,
            },
            &decision,
            &mut entropy,
            &mut ack,
        )
        .unwrap();

        let mut seen: Vec<Warning> = Vec::new();
        association
            .read_reply(
                &ack[..ack_len],
                call_id,
                TransferSyntax::Ndr32,
                &mut |warning| seen.push(warning),
            )
            .unwrap();
        assert!(
            seen.contains(&Warning::Ndr64WithoutFeatureNegotiation),
            "{seen:?}"
        );
    }
}

//! Establishing an association: `bind`, `alter_context` and the acknowledgement
//! (`WIRE-003`, #61; `WIRE-005`, #63; `WIRE-006`, #64; `WIRE-008`, #66).
//!
//! Almost everything that makes a KMS emulator identifiable happens here rather
//! than in the activation itself, because the bind exchange is where a host
//! reveals what it is before it has been asked anything.
//!
//! * The association group is a **random 32-bit value drawn once per process**
//!   and incremented per connection (`WIRE-010`, #68). py-kms's is
//!   `0x1063BF3F` on every installation in the world; one `bind_ack` identifies
//!   the software with no active probing at all.
//! * The secondary address is the port of the socket that **actually accepted**
//!   (`WIRE-011`, #69), and `frag_length` is computed from what was written
//!   (`WIRE-012`, #70). py-kms's `36 + ctx_num * 24` is right only for a
//!   2-to-6-digit port; a single-digit port produces a 32-byte packet
//!   advertising itself as 36.
//! * The alignment padding after the secondary address is filled from the
//!   CSPRNG (`WIRE-017`, #75). vlmcsd *deliberately* leaks uninitialised stack
//!   there, with the comment "M$ RPC does not do this. Pad bytes contain
//!   apparently random data" — so zero-filling would itself be a fingerprint,
//!   and safe Rust cannot leak stack.
//! * A context item we cannot accept gets a **NACK**, never a dropped
//!   connection (`WIRE-006`, #64).

use crate::entropy::Entropy;
use crate::kms::layout::WireGuid;
use crate::wire::header::{
    HEADER_LEN, PacketFlags, PacketType, RPC_VERSION_MAJOR, RPC_VERSION_MINOR, RpcHeader,
};
use crate::wire::syntax::{
    FeatureBits, KMS_INTERFACE, KMS_INTERFACE_VERSION_MAJOR, KMS_INTERFACE_VERSION_MINOR, NDR32,
    NDR64, TransferSyntax,
};
use arrayvec::ArrayVec;
use kmsrs_db::Guid;
use zerocopy::IntoBytes;

/// The most context items this host will consider in one bind.
///
/// A real client sends one to three. The cap exists so a hostile bind cannot
/// make the server allocate or loop proportionally to a client-chosen count;
/// items beyond it are refused individually rather than making the whole bind
/// fail (`WIRE-006`, #64).
pub const MAX_CONTEXT_ITEMS: usize = 16;

/// The most transfer syntaxes a single context item may offer.
pub const MAX_TRANSFER_SYNTAXES: usize = 4;

/// Bytes of fixed fields at the front of a bind body, before the context items.
const BIND_PREFIX_LEN: usize = 12;

/// Bytes in a `p_syntax_id_t`: a GUID and a version.
const SYNTAX_ID_LEN: usize = 20;

/// Bytes of fixed fields in a context item, before its transfer syntaxes.
const CONTEXT_ITEM_PREFIX_LEN: usize = 4 + SYNTAX_ID_LEN;

/// Bytes in one result entry of a `bind_ack`.
const RESULT_LEN: usize = 24;

/// Bytes of fixed fields at the front of a `bind_ack` body, before the
/// secondary address.
const ACK_PREFIX_LEN: usize = 10;

/// One transfer syntax a context item offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferedSyntax {
    /// What the syntax is.
    pub syntax: TransferSyntax,
    /// The version the client declared for it.
    pub version: u32,
}

/// One presentation context a client is proposing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextItem {
    /// The identifier the client will use in its request PDUs.
    pub context_id: u16,
    /// The interface the client wants to talk to.
    pub abstract_syntax: Guid,
    /// The interface's major version.
    pub abstract_version_major: u16,
    /// The interface's minor version.
    pub abstract_version_minor: u16,
    /// The transfer syntaxes offered, in the order offered.
    pub offered: ArrayVec<OfferedSyntax, MAX_TRANSFER_SYNTAXES>,
}

impl ContextItem {
    /// Whether this item names the KMS interface at the version we implement.
    ///
    /// py-kms ACKs a bind for **any** interface that offers NDR32, so it would
    /// accept a context for an interface it has never implemented and then
    /// fault on the first call (`WIRE-008`, #66).
    #[must_use]
    pub fn names_kms_interface(&self) -> bool {
        self.abstract_syntax == KMS_INTERFACE
            && self.abstract_version_major == KMS_INTERFACE_VERSION_MAJOR
            && self.abstract_version_minor == KMS_INTERFACE_VERSION_MINOR
    }

    /// The offered entry for a given syntax, if the client offered it.
    #[must_use]
    pub fn offer_for(&self, syntax: TransferSyntax) -> Option<OfferedSyntax> {
        self.offered
            .iter()
            .copied()
            .find(|offered| offered.syntax == syntax)
    }

    /// The feature bits this item requests, if it is a negotiation item.
    #[must_use]
    pub fn feature_bits(&self) -> Option<FeatureBits> {
        self.offered
            .iter()
            .find_map(|offered| match offered.syntax {
                TransferSyntax::FeatureNegotiation(bits) => Some(bits),
                _ => None,
            })
    }
}

/// A parsed `bind` or `alter_context` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    /// The largest PDU the client will accept.
    pub max_xmit_frag: u16,
    /// The largest PDU the client will send.
    pub max_recv_frag: u16,
    /// The association group the client is asking to join, or 0 for a new one.
    pub assoc_group: u32,
    /// How many context items the client declared, before capping.
    pub declared_items: usize,
    /// The items, up to [`MAX_CONTEXT_ITEMS`].
    pub items: ArrayVec<ContextItem, MAX_CONTEXT_ITEMS>,
}

/// Why a bind body could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    /// The body ended before a field it declared.
    Truncated {
        /// Byte offset the parser had reached.
        at: usize,
    },
    /// A context item offered more transfer syntaxes than this host will hold.
    TooManySyntaxes {
        /// What the item declared.
        declared: usize,
    },
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { at } => write!(f, "bind body truncated at offset {at}"),
            Self::TooManySyntaxes { declared } => {
                write!(f, "a context item offered {declared} transfer syntaxes")
            }
        }
    }
}

/// Parse the body of a `bind` or `alter_context` PDU.
///
/// # Errors
///
/// Returns [`BindError`] if the body is truncated or a context item declares
/// more transfer syntaxes than this host will hold.
pub fn parse(body: &[u8]) -> Result<BindRequest, BindError> {
    let mut reader = Reader::new(body);

    let max_xmit_frag = reader.u16()?;
    let max_recv_frag = reader.u16()?;
    let assoc_group = reader.u32()?;
    // `p_cont_list_t` is a count byte followed by three reserved bytes. Reading
    // the whole thing as a `u32` — which is what vlmcsd's `DWORD NumCtxItems`
    // does — gives the same answer only while the reserved bytes are zero.
    let declared_items = usize::from(reader.u8()?);
    reader.skip(3)?;

    let mut items = ArrayVec::new();
    for _ in 0..declared_items {
        if items.is_full() {
            break;
        }
        let context_id = reader.u16()?;
        let syntax_count = usize::from(reader.u8()?);
        reader.skip(1)?;

        let abstract_syntax = reader.guid()?;
        let abstract_version = reader.u32()?;
        let [major_low, major_high, minor_low, minor_high] = abstract_version.to_le_bytes();

        if syntax_count > MAX_TRANSFER_SYNTAXES {
            return Err(BindError::TooManySyntaxes {
                declared: syntax_count,
            });
        }

        let mut offered = ArrayVec::new();
        for _ in 0..syntax_count {
            let wire = reader.bytes16()?;
            let version = reader.u32()?;
            // `syntax_count` was checked against the capacity above, so this
            // cannot fail — and refusing rather than discarding is what makes
            // it possible to forbid the discarded form outright
            // (`SEC-012`, #204).
            if offered
                .try_push(OfferedSyntax {
                    syntax: TransferSyntax::classify(&wire),
                    version,
                })
                .is_err()
            {
                return Err(BindError::TooManySyntaxes {
                    declared: syntax_count,
                });
            }
        }

        // Guarded by the `is_full` break at the top of the loop, so the error
        // is unreachable; stopping is the same outcome that guard produces,
        // and `declared_items` already records that there was more
        // (`SEC-012`, #204).
        if items
            .try_push(ContextItem {
                context_id,
                abstract_syntax,
                abstract_version_major: u16::from_le_bytes([major_low, major_high]),
                abstract_version_minor: u16::from_le_bytes([minor_low, minor_high]),
                offered,
            })
            .is_err()
        {
            break;
        }
    }

    Ok(BindRequest {
        max_xmit_frag,
        max_recv_frag,
        assoc_group,
        declared_items,
        items,
    })
}

/// The outcome for one proposed context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextResult {
    /// 0 acceptance, 1 user rejection, 2 provider rejection, 3 negotiate ack.
    pub ack_result: u16,
    /// The reason, meaningful when the result is a rejection or a negotiate
    /// acknowledgement.
    pub ack_reason: u16,
    /// The syntax being acknowledged, or all zeros for a rejection.
    pub transfer_syntax: Guid,
    /// The syntax version being acknowledged.
    pub syntax_version: u32,
}

impl ContextResult {
    /// `acceptance`.
    pub const ACCEPTANCE: u16 = 0;
    /// `provider_rejection`.
    pub const PROVIDER_REJECTION: u16 = 2;
    /// `negotiate_ack`, used for bind-time feature negotiation.
    pub const NEGOTIATE_ACK: u16 = 3;

    /// `abstract_syntax_not_supported`.
    pub const REASON_ABSTRACT_SYNTAX: u16 = 1;
    /// `proposed_transfer_syntaxes_not_supported`.
    pub const REASON_TRANSFER_SYNTAX: u16 = 2;

    /// Accept a transfer syntax.
    #[must_use]
    pub const fn accept(transfer_syntax: Guid, syntax_version: u32) -> Self {
        Self {
            ack_result: Self::ACCEPTANCE,
            ack_reason: 0,
            transfer_syntax,
            syntax_version,
        }
    }

    /// Refuse a context, naming why.
    #[must_use]
    pub const fn reject(reason: u16) -> Self {
        Self {
            ack_result: Self::PROVIDER_REJECTION,
            ack_reason: reason,
            transfer_syntax: Guid::ZERO,
            syntax_version: 0,
        }
    }

    /// Acknowledge bind-time feature negotiation (`WIRE-007`, #65).
    ///
    /// Syntax version **0** on the way out, and the reason field carries the
    /// bits actually acknowledged — the intersection of what was asked for and
    /// what this host supports. py-kms hardcodes the reason to 3, answering a
    /// question nobody asked.
    #[must_use]
    pub fn negotiate(bits: FeatureBits) -> Self {
        Self {
            ack_result: Self::NEGOTIATE_ACK,
            ack_reason: u16::from(bits.acknowledged().bits()),
            transfer_syntax: Guid::ZERO,
            syntax_version: 0,
        }
    }
}

/// What this host will answer a bind with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDecision {
    /// One result per proposed context, in the order proposed.
    pub results: ArrayVec<ContextResult, MAX_CONTEXT_ITEMS>,
    /// The context this host will service requests on, if any was accepted.
    pub accepted_context: Option<AcceptedContext>,
}

/// The context a client may then send requests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedContext {
    /// The identifier the client will use.
    pub context_id: u16,
    /// The syntax the request stubs will be framed in.
    pub syntax: TransferSyntax,
}

/// Decide how to answer a bind (`WIRE-005`, #63).
///
/// A real host accepts **exactly one** transfer syntax. If NDR64 is offered and
/// this build supports it, NDR64 is acknowledged and NDR32 is refused; a client
/// that offered both then uses NDR64 for everything after its first request
/// (`WIRE-029`, #87).
///
/// The rejection reason distinguishes the two cases the issue names: reason 2
/// when the interface matched but no offered syntax was usable, reason 1 when
/// the interface itself was wrong.
#[must_use]
pub fn decide(request: &BindRequest, ndr64_enabled: bool) -> BindDecision {
    let offers_ndr64 = ndr64_enabled
        && request.items.iter().any(|item| {
            item.names_kms_interface() && item.offer_for(TransferSyntax::Ndr64).is_some()
        });

    let preferred = if offers_ndr64 {
        TransferSyntax::Ndr64
    } else {
        TransferSyntax::Ndr32
    };
    let preferred_guid = if offers_ndr64 { NDR64 } else { NDR32 };

    let mut results = ArrayVec::new();
    let mut accepted_context = None;

    for item in &request.items {
        // Feature negotiation is acknowledged regardless of the abstract
        // syntax, per MS-RPCE. It is not a context to service calls on.
        // `results` and `request.items` have the same capacity and this loop
        // walks the latter, so none of these three can fail. A result list
        // shorter than the context list would be a malformed `bind_ack`, so
        // stopping is the only honest response if one ever does
        // (`SEC-012`, #204).
        if let Some(bits) = item.feature_bits() {
            if results.try_push(ContextResult::negotiate(bits)).is_err() {
                break;
            }
            continue;
        }

        if !item.names_kms_interface() {
            if results
                .try_push(ContextResult::reject(ContextResult::REASON_ABSTRACT_SYNTAX))
                .is_err()
            {
                break;
            }
            continue;
        }

        match item.offer_for(preferred) {
            Some(offered) if accepted_context.is_none() => {
                if results
                    .try_push(ContextResult::accept(preferred_guid, offered.version))
                    .is_err()
                {
                    break;
                }
                accepted_context = Some(AcceptedContext {
                    context_id: item.context_id,
                    syntax: preferred,
                });
            }
            _ => {
                if results
                    .try_push(ContextResult::reject(ContextResult::REASON_TRANSFER_SYNTAX))
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    // Items past the cap are refused individually rather than silently dropped:
    // a client that gets fewer results than it sent contexts cannot tell which
    // of its contexts were considered.
    let refused = request.declared_items.saturating_sub(request.items.len());
    for _ in 0..refused {
        if results
            .try_push(ContextResult::reject(ContextResult::REASON_TRANSFER_SYNTAX))
            .is_err()
        {
            break;
        }
    }

    BindDecision {
        results,
        accepted_context,
    }
}

/// Why a bind was refused outright (`WIRE-006`, #64).
///
/// Distinct from a per-context rejection, which travels *inside* a `bind_ack`:
/// these are reasons the whole association cannot exist, so there is no
/// acknowledgement to put a result in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NakReason {
    /// `REASON_NOT_SPECIFIED`.
    NotSpecified,
    /// The RPC version the client spoke is not one this host implements.
    ProtocolVersionNotSupported,
}

impl NakReason {
    /// The wire value.
    ///
    /// A method rather than a `#[repr(u16)]` discriminant cast: `ARCH-007` (#7)
    /// forbids `as` in wire handling, and an exhaustive `match` is what makes
    /// adding a variant a compile error rather than a silent zero.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        match self {
            Self::NotSpecified => 0,
            Self::ProtocolVersionNotSupported => 2,
        }
    }
}

/// The RPC versions this host implements, for a `bind_nak`'s version list.
const SUPPORTED_VERSIONS: [(u8, u8); 1] = [(RPC_VERSION_MAJOR, RPC_VERSION_MINOR)];

/// Write a `bind_nak`.
///
/// A `bind_nak` carries the reason and the list of RPC versions the host does
/// support, so a client that spoke the wrong one learns which to use rather
/// than being left to guess from a closed socket.
///
/// This is the case DCE/RPC defines `bind_nak` for, and emitting it is the
/// difference between "this host refused, here is why" and a bare RST. py-kms
/// emits only `bind_ack` and `response`, so it has no way to refuse anything
/// except by hanging up (`SEC-012`, #204).
///
/// Returns the number of bytes written.
///
/// # Errors
///
/// Returns [`AckError::BufferTooSmall`] if `out` cannot hold the PDU.
pub fn write_nak(call_id: u32, reason: NakReason, out: &mut [u8]) -> Result<usize, AckError> {
    // reason u16, then a counted list of (major, minor) pairs.
    let body_len = 2_usize
        .saturating_add(1)
        .saturating_add(SUPPORTED_VERSIONS.len().saturating_mul(2));
    let needed = HEADER_LEN.saturating_add(body_len);
    let available = out.len();
    if available < needed {
        return Err(AckError::BufferTooSmall { needed, available });
    }

    let frag_length =
        u16::try_from(needed).map_err(|_| AckError::BufferTooSmall { needed, available })?;
    let header = RpcHeader::for_reply(
        PacketType::BindNak,
        PacketFlags::COMPLETE,
        call_id,
        frag_length,
    );
    out.get_mut(..HEADER_LEN)
        .ok_or(AckError::BufferTooSmall { needed, available })?
        .copy_from_slice(header.as_bytes());

    let mut cursor = HEADER_LEN;
    let reason_bytes = reason.to_wire().to_le_bytes();
    out.get_mut(cursor..cursor.saturating_add(2))
        .ok_or(AckError::BufferTooSmall { needed, available })?
        .copy_from_slice(&reason_bytes);
    cursor = cursor.saturating_add(2);

    let count = u8::try_from(SUPPORTED_VERSIONS.len())
        .map_err(|_| AckError::BufferTooSmall { needed, available })?;
    *out.get_mut(cursor)
        .ok_or(AckError::BufferTooSmall { needed, available })? = count;
    cursor = cursor.saturating_add(1);

    for (major, minor) in SUPPORTED_VERSIONS {
        *out.get_mut(cursor)
            .ok_or(AckError::BufferTooSmall { needed, available })? = major;
        cursor = cursor.saturating_add(1);
        *out.get_mut(cursor)
            .ok_or(AckError::BufferTooSmall { needed, available })? = minor;
        cursor = cursor.saturating_add(1);
    }

    Ok(needed)
}

/// Why a `bind_ack` could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckError {
    /// The output buffer was too small.
    BufferTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// The entropy source failed, so the alignment padding would have been
    /// predictable (`WIRE-017`, #75).
    EntropyUnavailable,
    /// The secondary address did not fit its field.
    SecondaryAddressTooLong {
        /// Bytes the address needs, including its NUL.
        len: usize,
    },
}

impl core::fmt::Display for AckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall { needed, available } => {
                write!(
                    f,
                    "a bind_ack needs {needed} bytes, buffer holds {available}"
                )
            }
            Self::EntropyUnavailable => f.write_str("the entropy source failed"),
            Self::SecondaryAddressTooLong { len } => {
                write!(f, "a secondary address of {len} bytes does not fit")
            }
        }
    }
}

/// The most bytes a secondary address may occupy, including its NUL.
///
/// A port is at most five digits.
pub const MAX_SECONDARY_ADDRESS_LEN: usize = 6;

/// The fields of a `bind_ack` that come from the connection rather than from
/// the bind itself.
///
/// Grouped because they travel together: they are all properties of *this*
/// association on *this* socket, and passing them individually is how a
/// secondary address ends up describing a different listener than the one that
/// accepted (`WIRE-011`, #69).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckParameters<'a> {
    /// `BindAck` or `AlterContextResponse`.
    pub packet_type: PacketType,
    /// Echoed from the request (`WIRE-015`, #73).
    pub call_id: u32,
    /// This connection's association group (`WIRE-010`, #68).
    pub assoc_group: u32,
    /// The largest PDU this host will accept.
    pub max_xmit_frag: u16,
    /// The largest PDU this host will send.
    pub max_recv_frag: u16,
    /// The ASCII port of the socket that accepted, without a NUL. Empty for an
    /// `alter_context_response`.
    pub secondary_address: &'a [u8],
    /// The flags the client set on its `bind` (`WIRE-028`, #86).
    ///
    /// Only `PFC_CONC_MPX` is echoed from these, and only if the client set it.
    /// py-kms sets it unconditionally, telling every client it has a capability
    /// the client never asked about.
    pub client_flags: PacketFlags,
}

impl AckParameters<'_> {
    /// The flags this acknowledgement will carry.
    ///
    /// `FIRST_FRAG | LAST_FRAG` always, plus `PFC_CONC_MPX` if and only if the
    /// client asked for it. Nothing else from the client's header survives —
    /// vlmcsd `memcpy`s the whole request header, so it would reflect
    /// `PFC_PENDING_CANCEL` back as well (`WIRE-014`, #72).
    #[must_use]
    pub fn reply_flags(&self) -> PacketFlags {
        PacketFlags::COMPLETE.union(self.client_flags.intersection(PacketFlags::CONC_MPX))
    }
}

/// Write a `bind_ack` or `alter_context_response`.
///
/// `secondary_address` is the ASCII port of the socket that **actually
/// accepted**, without its terminating NUL — which this function adds
/// (`WIRE-011`, #69). For an `alter_context_response` it is empty, because the
/// association already exists and there is nothing to advertise.
///
/// Returns the number of bytes written.
///
/// # Errors
///
/// Returns [`AckError`] if the buffer is too small, the address does not fit, or
/// the entropy source failed.
pub fn write_ack(
    parameters: &AckParameters<'_>,
    decision: &BindDecision,
    entropy: &mut dyn Entropy,
    out: &mut [u8],
) -> Result<usize, AckError> {
    let secondary_address = parameters.secondary_address;
    let address_len = if secondary_address.is_empty() {
        0
    } else {
        secondary_address.len().saturating_add(1)
    };
    if address_len > MAX_SECONDARY_ADDRESS_LEN {
        return Err(AckError::SecondaryAddressTooLong { len: address_len });
    }

    // The results array must start on a 4-byte boundary relative to the PDU
    // (`WIRE-013`, #71). vlmcsd calls its version of this "really ugly (but
    // efficient)"; computing the padding from the offset actually reached is
    // neither.
    let before_padding = HEADER_LEN
        .saturating_add(ACK_PREFIX_LEN)
        .saturating_add(address_len);
    let padding = before_padding.wrapping_neg() & 3;
    let needed = before_padding
        .saturating_add(padding)
        .saturating_add(4)
        .saturating_add(decision.results.len().saturating_mul(RESULT_LEN));

    let available = out.len();
    if available < needed {
        return Err(AckError::BufferTooSmall { needed, available });
    }

    // `frag_length` is computed from what will actually be written, never from
    // a formula that assumes an address length (`WIRE-012`, #70).
    let frag_length =
        u16::try_from(needed).map_err(|_| AckError::BufferTooSmall { needed, available })?;
    let header = RpcHeader::for_reply(
        parameters.packet_type,
        parameters.reply_flags(),
        parameters.call_id,
        frag_length,
    );

    let mut writer = Writer::new(out);
    let too_small = AckError::BufferTooSmall { needed, available };
    writer.bytes(header.as_bytes()).ok_or(too_small)?;
    writer.u16(parameters.max_xmit_frag).ok_or(too_small)?;
    writer.u16(parameters.max_recv_frag).ok_or(too_small)?;
    writer.u32(parameters.assoc_group).ok_or(too_small)?;

    writer
        .u16(u16::try_from(address_len).unwrap_or(0))
        .ok_or(too_small)?;
    if address_len > 0 {
        writer.bytes(secondary_address).ok_or(too_small)?;
        writer.bytes(&[0]).ok_or(too_small)?;
    }

    // Random rather than zero. Windows leaves whatever was on its stack here,
    // so a run of zeros is itself a signature — and safe Rust has no stack to
    // leak, which is why this has to be done deliberately.
    if padding > 0 {
        let mut noise = [0_u8; 4];
        entropy
            .fill(noise.get_mut(..padding).unwrap_or(&mut []))
            .map_err(|_| AckError::EntropyUnavailable)?;
        writer
            .bytes(noise.get(..padding).unwrap_or(&[]))
            .ok_or(too_small)?;
    }

    writer
        .bytes(&[u8::try_from(decision.results.len()).unwrap_or(0), 0, 0, 0])
        .ok_or(too_small)?;

    for result in &decision.results {
        writer.u16(result.ack_result).ok_or(too_small)?;
        writer.u16(result.ack_reason).ok_or(too_small)?;
        writer
            .bytes(WireGuid::from_guid(result.transfer_syntax).as_bytes())
            .ok_or(too_small)?;
        writer.u32(result.syntax_version).ok_or(too_small)?;
    }

    Ok(writer.position())
}

/// A checked forward reader over a PDU body.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], BindError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(BindError::Truncated { at: self.offset })?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(BindError::Truncated { at: self.offset })?;
        self.offset = end;
        Ok(slice)
    }

    fn skip(&mut self, len: usize) -> Result<(), BindError> {
        self.take(len).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8, BindError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(BindError::Truncated { at: self.offset })
    }

    fn u16(&mut self) -> Result<u16, BindError> {
        let bytes = self.take(2)?;
        bytes
            .first_chunk::<2>()
            .map(|pair| u16::from_le_bytes(*pair))
            .ok_or(BindError::Truncated { at: self.offset })
    }

    fn u32(&mut self) -> Result<u32, BindError> {
        let bytes = self.take(4)?;
        bytes
            .first_chunk::<4>()
            .map(|quad| u32::from_le_bytes(*quad))
            .ok_or(BindError::Truncated { at: self.offset })
    }

    fn bytes16(&mut self) -> Result<[u8; 16], BindError> {
        let bytes = self.take(16)?;
        bytes
            .first_chunk::<16>()
            .copied()
            .ok_or(BindError::Truncated { at: self.offset })
    }

    fn guid(&mut self) -> Result<Guid, BindError> {
        let wire = self.bytes16()?;
        Ok(WireGuid {
            data1: u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]).into(),
            data2: u16::from_le_bytes([wire[4], wire[5]]).into(),
            data3: u16::from_le_bytes([wire[6], wire[7]]).into(),
            data4: [
                wire[8], wire[9], wire[10], wire[11], wire[12], wire[13], wire[14], wire[15],
            ],
        }
        .to_guid())
    }
}

/// A checked forward writer over an output buffer.
struct Writer<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}

impl<'a> Writer<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn position(&self) -> usize {
        self.offset
    }

    fn bytes(&mut self, source: &[u8]) -> Option<()> {
        let end = self.offset.checked_add(source.len())?;
        self.bytes
            .get_mut(self.offset..end)?
            .copy_from_slice(source);
        self.offset = end;
        Some(())
    }

    fn u16(&mut self, value: u16) -> Option<()> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Option<()> {
        self.bytes(&value.to_le_bytes())
    }
}

/// Bytes a bind body needs for `count` context items each offering one syntax.
///
/// Exposed for tests and for the client, which builds binds.
#[must_use]
pub const fn bind_body_len(count: usize) -> usize {
    BIND_PREFIX_LEN
        .saturating_add(count.saturating_mul(CONTEXT_ITEM_PREFIX_LEN.saturating_add(SYNTAX_ID_LEN)))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        AckError, AckParameters, BindError, ContextResult, MAX_CONTEXT_ITEMS, RESULT_LEN, decide,
        parse, write_ack,
    };
    use crate::entropy::testing::{DeterministicEntropy, FailingEntropy};
    use crate::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
    use crate::wire::syntax::{BTFN_WIRE_PREFIX, FeatureBits, TransferSyntax};
    use alloc::vec;
    use alloc::vec::Vec;
    use zerocopy::FromBytes;

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

    /// Build a bind body the way a Windows client does.
    fn bind_body(items: &[(u16, [u8; 16], [u8; 16], u32)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&5840_u16.to_le_bytes());
        body.extend_from_slice(&5840_u16.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.push(u8::try_from(items.len()).unwrap());
        body.extend_from_slice(&[0, 0, 0]);

        for (context_id, interface, transfer, version) in items {
            body.extend_from_slice(&context_id.to_le_bytes());
            body.push(1);
            body.push(0);
            body.extend_from_slice(interface);
            // Interface version 1.0: major in the low half, minor in the high.
            body.extend_from_slice(&0x0000_0001_u32.to_le_bytes());
            body.extend_from_slice(transfer);
            body.extend_from_slice(&version.to_le_bytes());
        }
        body
    }

    fn btfn_wire(bits: u8) -> [u8; 16] {
        let mut wire = [0_u8; 16];
        wire[..8].copy_from_slice(&BTFN_WIRE_PREFIX);
        wire[8] = bits;
        wire
    }

    fn ack_parameters(secondary_address: &[u8]) -> AckParameters<'_> {
        AckParameters {
            packet_type: PacketType::BindAck,
            call_id: 2,
            assoc_group: 0xDEAD_BEEF,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            secondary_address,
            client_flags: PacketFlags::COMPLETE,
        }
    }

    #[test]
    fn a_windows_style_bind_parses() {
        let body = bind_body(&[
            (0, INTERFACE_WIRE, NDR32_WIRE, 2),
            (1, INTERFACE_WIRE, NDR64_WIRE, 1),
            (2, INTERFACE_WIRE, btfn_wire(0x03), 1),
        ]);
        assert_eq!(body.len(), super::bind_body_len(3));

        let request = parse(&body).unwrap();
        assert_eq!(request.max_xmit_frag, 5840);
        assert_eq!(request.declared_items, 3);
        assert_eq!(request.items.len(), 3);

        assert!(request.items[0].names_kms_interface());
        assert_eq!(request.items[0].offered[0].syntax, TransferSyntax::Ndr32);
        assert_eq!(request.items[1].offered[0].syntax, TransferSyntax::Ndr64);
        assert_eq!(
            request.items[2].feature_bits(),
            Some(FeatureBits::from_bits(0x03))
        );
    }

    /// `WIRE-005` (#63): a real host accepts exactly one transfer syntax. When
    /// NDR64 is offered and enabled it wins, and the NDR32 context is refused.
    #[test]
    fn ndr64_wins_when_offered_and_ndr32_is_refused() {
        let body = bind_body(&[
            (0, INTERFACE_WIRE, NDR32_WIRE, 2),
            (1, INTERFACE_WIRE, NDR64_WIRE, 1),
        ]);
        let request = parse(&body).unwrap();

        let decision = decide(&request, true);
        assert_eq!(decision.results.len(), 2);
        assert_eq!(
            decision.results[0].ack_result,
            ContextResult::PROVIDER_REJECTION,
            "NDR32 is refused when NDR64 was accepted"
        );
        assert_eq!(
            decision.results[0].ack_reason,
            ContextResult::REASON_TRANSFER_SYNTAX
        );
        assert_eq!(decision.results[1].ack_result, ContextResult::ACCEPTANCE);
        assert_eq!(
            decision.accepted_context.unwrap().syntax,
            TransferSyntax::Ndr64
        );
        assert_eq!(decision.accepted_context.unwrap().context_id, 1);

        // With NDR64 disabled at build time, the same bind takes the NDR32
        // context instead.
        let decision = decide(&request, false);
        assert_eq!(decision.results[0].ack_result, ContextResult::ACCEPTANCE);
        assert_eq!(
            decision.results[1].ack_result,
            ContextResult::PROVIDER_REJECTION
        );
        assert_eq!(
            decision.accepted_context.unwrap().syntax,
            TransferSyntax::Ndr32
        );
    }

    /// `WIRE-008` (#66): py-kms ACKs a bind for *any* interface that offers
    /// NDR32, so it accepts a context for an interface it never implemented and
    /// then faults on the first call.
    #[test]
    fn a_bind_for_another_interface_is_refused_with_the_right_reason() {
        let mut wrong = INTERFACE_WIRE;
        wrong[0] ^= 0xFF;
        let body = bind_body(&[(0, wrong, NDR32_WIRE, 2)]);
        let request = parse(&body).unwrap();

        let decision = decide(&request, false);
        assert_eq!(decision.results.len(), 1);
        assert_eq!(
            decision.results[0].ack_result,
            ContextResult::PROVIDER_REJECTION
        );
        assert_eq!(
            decision.results[0].ack_reason,
            ContextResult::REASON_ABSTRACT_SYNTAX,
            "reason 1 when the interface did not match, not reason 2"
        );
        assert!(decision.accepted_context.is_none());
    }

    /// `WIRE-006` (#64): an unrecognised transfer syntax gets a NACK, not a
    /// dropped connection. py-kms indexes a bare dict here, so the `KeyError`
    /// is swallowed by a no-op handler and the client gets a silent RST with no
    /// `bind_ack`, no `bind_nak` and no log line.
    #[test]
    fn an_unrecognised_transfer_syntax_is_nacked_per_item() {
        let body = bind_body(&[
            (0, INTERFACE_WIRE, [0x5A; 16], 7),
            (1, INTERFACE_WIRE, NDR32_WIRE, 2),
        ]);
        let request = parse(&body).unwrap();
        let decision = decide(&request, false);

        assert_eq!(decision.results.len(), 2, "one result per proposed context");
        assert_eq!(
            decision.results[0].ack_result,
            ContextResult::PROVIDER_REJECTION
        );
        assert_eq!(
            decision.results[1].ack_result,
            ContextResult::ACCEPTANCE,
            "the usable context is still accepted"
        );
    }

    /// `WIRE-007` (#65): acknowledged regardless of abstract syntax, result 3,
    /// syntax version 0, reason carrying the bits actually acknowledged.
    #[test]
    fn feature_negotiation_is_acknowledged_with_the_requested_bits() {
        for (requested, expected) in [(0x00_u8, 0_u16), (0x01, 1), (0x02, 2), (0x03, 3), (0xFF, 3)]
        {
            // Deliberately with the *wrong* interface, to show the
            // acknowledgement does not depend on it.
            let mut wrong = INTERFACE_WIRE;
            wrong[0] ^= 0xFF;
            let body = bind_body(&[(0, wrong, btfn_wire(requested), 1)]);
            let request = parse(&body).unwrap();
            let decision = decide(&request, false);

            assert_eq!(decision.results[0].ack_result, ContextResult::NEGOTIATE_ACK);
            assert_eq!(
                decision.results[0].ack_reason, expected,
                "requested {requested:#04x}"
            );
            assert_eq!(decision.results[0].syntax_version, 0);
            assert!(
                decision.accepted_context.is_none(),
                "negotiation is not a context to service calls on"
            );
        }
    }

    /// `WIRE-012` (#70) and `WIRE-013` (#71). The single-digit port is the case
    /// py-kms gets wrong: its `36 + ctx_num * 24` produces a 32-byte packet
    /// advertising itself as 36.
    #[test]
    fn frag_length_is_computed_and_the_results_stay_aligned() {
        let body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        let request = parse(&body).unwrap();
        let decision = decide(&request, false);
        let mut entropy = DeterministicEntropy::from_seed(1);

        for port in [b"5".as_slice(), b"55", b"555", b"1688", b"65535"] {
            let mut out = vec![0_u8; 128];
            let written =
                write_ack(&ack_parameters(port), &decision, &mut entropy, &mut out).unwrap();

            let header = RpcHeader::read_from_bytes(&out[..HEADER_LEN]).unwrap();
            assert_eq!(
                usize::from(header.frag_length.get()),
                written,
                "port {port:?}: frag_length must equal what was written"
            );

            // The results array must begin on a 4-byte boundary.
            let results_start = written - decision.results.len() * RESULT_LEN;
            assert_eq!(
                results_start % 4,
                0,
                "port {port:?}: results at {results_start} are not 4-byte aligned"
            );

            // And the count byte precedes them.
            assert_eq!(out[results_start - 4], 1);
        }
    }

    /// `WIRE-017` (#75). vlmcsd deliberately leaks uninitialised stack into
    /// these bytes because Windows leaves "apparently random data" there, so
    /// zero-filling would itself be a fingerprint. Safe Rust cannot leak stack,
    /// which is why the fill has to be deliberate.
    #[test]
    fn the_alignment_padding_is_random_rather_than_zero() {
        let body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        let request = parse(&body).unwrap();
        let decision = decide(&request, false);

        // A 4-digit port leaves five bytes of address and one of padding.
        let mut seen = Vec::new();
        for seed in 0..32_u64 {
            let mut entropy = DeterministicEntropy::from_seed(seed);
            let mut out = vec![0_u8; 128];
            let written =
                write_ack(&ack_parameters(b"1688"), &decision, &mut entropy, &mut out).unwrap();
            let results_start = written - decision.results.len() * RESULT_LEN;
            // One padding byte, immediately before the four count bytes.
            seen.push(out[results_start - 5]);
        }
        assert!(
            seen.iter().any(|byte| *byte != 0),
            "padding must not be constant zero"
        );
        assert!(
            seen.iter()
                .collect::<alloc::collections::BTreeSet<_>>()
                .len()
                > 1,
            "padding must vary with the entropy stream"
        );
    }

    /// A padding failure must not produce a predictable `bind_ack`.
    #[test]
    fn a_failing_entropy_source_refuses_to_write_padding() {
        let body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        let request = parse(&body).unwrap();
        let decision = decide(&request, false);
        let mut out = vec![0_u8; 128];

        assert_eq!(
            write_ack(
                &ack_parameters(b"1688"),
                &decision,
                &mut FailingEntropy,
                &mut out
            ),
            Err(AckError::EntropyUnavailable)
        );

        // A single-digit port needs no padding — the header and prefix are 26
        // bytes, and a two-byte address lands the results on 28 — so it must
        // still succeed. The refusal is about the padding, not the whole path.
        assert!(
            write_ack(
                &ack_parameters(b"5"),
                &decision,
                &mut FailingEntropy,
                &mut out
            )
            .is_ok()
        );
    }

    /// `WIRE-026` (#84): the acknowledgement carries no auth trailer, so its
    /// `AuthLength` is zero regardless of what the client sent. py-kms echoes
    /// the client's value into a trailer-less `bind_ack`, which is a malformed
    /// packet whenever a client attempts an authenticated bind.
    #[test]
    fn the_acknowledgement_never_claims_an_auth_trailer() {
        let body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        let request = parse(&body).unwrap();
        let decision = decide(&request, false);
        let mut entropy = DeterministicEntropy::from_seed(2);
        let mut out = vec![0_u8; 128];
        write_ack(&ack_parameters(b"1688"), &decision, &mut entropy, &mut out).unwrap();

        let header = RpcHeader::read_from_bytes(&out[..HEADER_LEN]).unwrap();
        assert_eq!(header.auth_length.get(), 0);
        assert_eq!(header.call_id.get(), 2, "the call id is echoed");
        assert_eq!(header.packet_type, PacketType::BindAck.to_wire());
    }

    /// `WIRE-028` (#86): `PFC_CONC_MPX` is echoed and never asserted
    /// unrequested. py-kms sets it on every acknowledgement, telling clients
    /// they have a capability they never asked about — and vlmcsd copies the
    /// whole request header, so it would reflect `PFC_PENDING_CANCEL` too.
    #[test]
    fn multiplexing_is_echoed_rather_than_asserted() {
        let body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        let request = parse(&body).unwrap();
        let decision = decide(&request, false);
        let mut entropy = DeterministicEntropy::from_seed(7);

        for (client_flags, expects_multiplex) in [
            (PacketFlags::COMPLETE, false),
            (PacketFlags::COMPLETE.union(PacketFlags::CONC_MPX), true),
            // A client asking to cancel must not have that reflected back.
            (
                PacketFlags::COMPLETE.union(PacketFlags::PENDING_CANCEL),
                false,
            ),
        ] {
            let mut parameters = ack_parameters(b"1688");
            parameters.client_flags = client_flags;
            let mut out = vec![0_u8; 128];
            write_ack(&parameters, &decision, &mut entropy, &mut out).unwrap();

            let header = RpcHeader::read_from_bytes(&out[..HEADER_LEN]).unwrap();
            let flags = header.flags();
            assert!(flags.contains(PacketFlags::COMPLETE));
            assert_eq!(
                flags.contains(PacketFlags::CONC_MPX),
                expects_multiplex,
                "client flags {client_flags:?}"
            );
            assert!(
                !flags.contains(PacketFlags::PENDING_CANCEL),
                "a cancellation request must not be reflected"
            );
        }
    }

    /// `WIRE-003` (#61): an `alter_context_response` carries an empty secondary
    /// address, because the association already exists.
    #[test]
    fn an_alter_context_response_advertises_no_secondary_address() {
        let body = bind_body(&[(1, INTERFACE_WIRE, NDR64_WIRE, 1)]);
        let request = parse(&body).unwrap();
        let decision = decide(&request, true);
        let mut entropy = DeterministicEntropy::from_seed(3);
        let mut out = vec![0_u8; 128];

        let mut parameters = ack_parameters(b"");
        parameters.packet_type = PacketType::AlterContextResponse;
        let written = write_ack(&parameters, &decision, &mut entropy, &mut out).unwrap();

        let header = RpcHeader::read_from_bytes(&out[..HEADER_LEN]).unwrap();
        assert_eq!(
            header.packet_type,
            PacketType::AlterContextResponse.to_wire()
        );
        // Address length zero, and the results land aligned without padding.
        assert_eq!(u16::from_le_bytes([out[24], out[25]]), 0);
        assert_eq!((written - RESULT_LEN) % 4, 0);
    }

    /// A truncated body must be refused rather than read past.
    #[test]
    fn a_truncated_bind_body_is_refused() {
        let body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        for len in 0..body.len() {
            assert!(
                matches!(parse(&body[..len]), Err(BindError::Truncated { .. })),
                "{len} bytes must not parse"
            );
        }
        assert!(parse(&body).is_ok());
    }

    /// A bind claiming more contexts than it carries is refused, and one
    /// claiming more than the cap gets results for the ones it can be given —
    /// never a dropped connection.
    #[test]
    fn a_hostile_context_count_is_bounded_rather_than_trusted() {
        // Claims 255 items, carries one.
        let mut body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        body[8] = 255;
        assert!(matches!(parse(&body), Err(BindError::Truncated { .. })));

        // Carries more items than the cap: parsing stops at the cap and the
        // declared count is retained so the decision can refuse the rest.
        let items: Vec<_> = (0..MAX_CONTEXT_ITEMS + 4)
            .map(|index| {
                (
                    u16::try_from(index).unwrap(),
                    INTERFACE_WIRE,
                    NDR32_WIRE,
                    2_u32,
                )
            })
            .collect();
        let body = bind_body(&items);
        let request = parse(&body).unwrap();
        assert_eq!(request.declared_items, MAX_CONTEXT_ITEMS + 4);
        assert_eq!(request.items.len(), MAX_CONTEXT_ITEMS);

        let decision = decide(&request, false);
        assert_eq!(decision.results.len(), MAX_CONTEXT_ITEMS);
        assert!(decision.accepted_context.is_some());
    }

    /// An item offering more transfer syntaxes than this host will hold is a
    /// hard refusal rather than a partial read.
    #[test]
    fn too_many_offered_syntaxes_is_an_error() {
        let mut body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        body[14] = 99;
        assert!(matches!(
            parse(&body),
            Err(BindError::TooManySyntaxes { declared: 99 })
        ));
    }

    #[test]
    fn an_undersized_output_buffer_is_refused() {
        let body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        let request = parse(&body).unwrap();
        let decision = decide(&request, false);
        let mut entropy = DeterministicEntropy::from_seed(4);

        let mut sized = vec![0_u8; 128];
        let needed = write_ack(
            &ack_parameters(b"1688"),
            &decision,
            &mut entropy,
            &mut sized,
        )
        .unwrap();
        for len in [0_usize, HEADER_LEN, needed - 1] {
            let mut small = vec![0_u8; len];
            assert!(
                matches!(
                    write_ack(
                        &ack_parameters(b"1688"),
                        &decision,
                        &mut entropy,
                        &mut small
                    ),
                    Err(AckError::BufferTooSmall { .. })
                ),
                "{len} bytes must not suffice"
            );
        }
    }

    #[test]
    fn an_over_long_secondary_address_is_refused() {
        let body = bind_body(&[(0, INTERFACE_WIRE, NDR32_WIRE, 2)]);
        let request = parse(&body).unwrap();
        let decision = decide(&request, false);
        let mut entropy = DeterministicEntropy::from_seed(5);
        let mut out = vec![0_u8; 128];
        assert!(matches!(
            write_ack(
                &ack_parameters(b"123456"),
                &decision,
                &mut entropy,
                &mut out
            ),
            Err(AckError::SecondaryAddressTooLong { len: 7 })
        ));
    }
}

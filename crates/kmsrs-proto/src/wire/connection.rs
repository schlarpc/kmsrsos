//! The per-connection state machine (`ARCH-006`, #6; `ARCH-002`, #2).
//!
//! # The association is a typestate
//!
//! [`Association<Unbound>`] has no method that services a call, and
//! [`Association::service`] exists only on [`Association<Bound>`]. Servicing a
//! request on a context that was never accepted is therefore a compile error
//! rather than a runtime check that somebody might forget.
//!
//! That is the structural answer to vlmcsd's pre-bind defect: a request PDU
//! with `ContextId = 0xffff` sent **before any bind** satisfies both of its
//! `RPC_INVALID_CTX` sentinels at once, and it then indexes
//! `_Versions[arbitrary - 4].CreateResponse(...)` — an indirect call through a
//! wild function pointer, reachable with no authentication and one packet
//! (`SEC-001`, #193). Here there is no `_Versions` array to index and no
//! unbound state that has a `service` method.
//!
//! # Everything the wire can make us allocate is bounded first
//!
//! A PDU shorter than the 16-byte common header is rejected before anything is
//! parsed (`WIRE-025`, #83). `FragLength` is checked against a fixed ceiling
//! before a single byte is buffered (`WIRE-023`, #81). Exactly
//! `FragLength - 16` bytes are consumed as the body (`WIRE-024`, #82).
//! Reassembly accumulates into a fixed-capacity buffer and faults rather than
//! growing (`WIRE-022`, #80).
//!
//! # The association stays open
//!
//! A KMS host does not hang up after an activation (`WIRE-021`, #79). py-kms
//! disconnects unconditionally, which `vlmcs` reports as "probably
//! non-multitasked KMS emulator" and which `man vlmcsd.8` calls a direct
//! violation of DCE RPC.

use crate::entropy::{Entropy, EntropyExt as _};
use crate::kms::epid::EPid;
use crate::kms::framing::{self, Ciphers, ResponsePlan};
use crate::kms::hresult::HResult;
use crate::kms::layout::MAX_RESPONSE_LEN;
use crate::kms::request::{Request, RequestError};
use crate::sansio::CloseReason;
use crate::time::Instant;
use crate::types::{HardwareId, Intervals};
use crate::wire::bind::{self, AckParameters, BindDecision};
use crate::wire::fault::{self, FAULT_LEN, NcaStatus};
use crate::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
use crate::wire::stub::{self, StubError};
use crate::wire::syntax::TransferSyntax;
use arrayvec::ArrayVec;
use core::time::Duration;
use zerocopy::{FromBytes, IntoBytes};

/// The largest single PDU this host will accept (`WIRE-023`, #81).
///
/// Sized for the largest legitimate bind — [`crate::wire::bind::MAX_CONTEXT_ITEMS`]
/// contexts each offering the maximum number of transfer syntaxes — which is far larger than
/// any real client sends and still small enough that the buffer is a fixed
/// field rather than an allocation.
pub const MAX_PDU_LEN: usize = 2048;

/// The largest stub this host will reassemble across fragments
/// (`WIRE-022`, #80).
pub const MAX_STUB_LEN: usize = MAX_PDU_LEN - HEADER_LEN;

/// How long the machine waits for the next PDU before giving up
/// (`NET-004`, #153).
///
/// Rearmed on every PDU, so a slow-loris client that dribbles a byte at a time
/// does not get an unbounded extension. Unlike py-kms's, this is per
/// connection rather than a process-lifetime cap computed before the accept
/// loop (declined item D23).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// What this host will answer an activation request with.
///
/// Produced by the policy layer, which this crate does not depend on. Keeping
/// the decision an input is what lets the whole exchange be replayed
/// deterministically (`TEST-004`, #225).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Activate, with the identity and count to report.
    Grant(Grant),
    /// Refuse, with the result code to report.
    ///
    /// Still a well-formed response, never a dropped connection
    /// (`KMS-014`, #30).
    Refuse(HResult),
}

/// The parts of a response the policy layer decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The host identity for this product's host key (`ID-001`, #106).
    pub epid: EPid,
    /// The count to report (`POL-001`, #89).
    pub count: u32,
    /// What to tell the client about retrying and renewing (`KMS-021`, #37).
    pub intervals: Intervals,
    /// The host's hardware ID, emitted for v6 only (`ID-012`, #117).
    pub hardware_id: HardwareId,
}

/// Something the connection did, for the event log (`OBS-003`, #179).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// An association was established.
    Bound {
        /// The syntax that was accepted.
        syntax: TransferSyntax,
        /// The context the client will use.
        context_id: u16,
    },
    /// An existing association gained a context.
    ContextAdded {
        /// The syntax that was accepted.
        syntax: TransferSyntax,
        /// The context the client will use.
        context_id: u16,
    },
    /// A request was serviced.
    Activated {
        /// Which protocol version the client used.
        version: crate::kms::version::Version,
        /// Whether the v4 MAC matched, where there was one.
        mac_verified: Option<bool>,
    },
    /// A request was refused with a result code.
    Refused {
        /// The code sent.
        result: HResult,
    },
    /// A fault was emitted.
    Faulted {
        /// The status sent.
        status: NcaStatus,
    },
    /// A PDU was rejected before it could be parsed.
    Rejected {
        /// Why.
        reason: RejectReason,
    },
}

/// Why a PDU was rejected outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// `FragLength` above the ceiling (`WIRE-023`, #81).
    FragmentTooLong {
        /// What the client declared.
        declared: usize,
    },
    /// `FragLength` below the common header, so the body length would be
    /// negative (`WIRE-025`, #83).
    ///
    /// This is the rejection the issue is about. A short *buffer* is not a
    /// short PDU — it is a partial read, and the answer to it is to wait
    /// (`NET-007`, #156). A PDU that *declares* itself shorter than its own
    /// header is malformed, and no amount of waiting fixes it.
    FragmentTooShort {
        /// What the client declared.
        declared: usize,
    },
    /// A PDU type this host does not accept (`WIRE-002`, #60).
    UnexpectedPacketType,
    /// The DCE/RPC version was not 5.0.
    UnsupportedRpcVersion,
    /// An authentication trailer, which this host cannot process
    /// (`WIRE-026`, #84; declined item D4).
    AuthenticationAttempted,
    /// Reassembly would exceed the fixed buffer (`WIRE-022`, #80).
    ReassemblyOverflow,
}

/// The state of an association that has not been bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Unbound;

/// The state of an association that has at least one accepted context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// The accepted contexts, at most one per transfer syntax.
    ///
    /// More than one because a Windows 8 or later client binds NDR32, sends its
    /// **first** request over it, and then adds NDR64 by `alter_context` — both
    /// paths must work on one association (`WIRE-029`, #87).
    contexts: ArrayVec<bind::AcceptedContext, 2>,
}

/// A DCE/RPC association, in a state that determines what can be done with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association<S> {
    assoc_group: u32,
    state: S,
}

impl Association<Unbound> {
    /// A fresh, unbound association.
    #[must_use]
    pub const fn new(assoc_group: u32) -> Self {
        Self {
            assoc_group,
            state: Unbound,
        }
    }

    /// Answer a bind.
    ///
    /// Consumes the unbound association: on success there is no longer an
    /// unbound value to service a request against, which is the typestate doing
    /// its job.
    pub fn bind(
        self,
        request: &bind::BindRequest,
        ndr64_enabled: bool,
    ) -> (BindDecision, Result<Association<Bound>, Self>) {
        let decision = bind::decide(request, ndr64_enabled);
        let Some(accepted) = decision.accepted_context else {
            return (decision, Err(self));
        };
        let mut contexts = ArrayVec::new();
        let _ = contexts.try_push(accepted);
        (
            decision,
            Ok(Association {
                assoc_group: self.assoc_group,
                state: Bound { contexts },
            }),
        )
    }
}

impl Association<Bound> {
    /// Add a context to an established association (`WIRE-003`, #61).
    #[must_use]
    pub fn alter_context(
        &mut self,
        request: &bind::BindRequest,
        ndr64_enabled: bool,
    ) -> BindDecision {
        let decision = bind::decide(request, ndr64_enabled);
        if let Some(accepted) = decision.accepted_context {
            // Replace an existing context with the same syntax rather than
            // accumulating duplicates.
            self.state
                .contexts
                .retain(|existing| existing.syntax != accepted.syntax);
            let _ = self.state.contexts.try_push(accepted);
        }
        decision
    }

    /// The syntax a context ID was accepted for, if it was accepted at all.
    ///
    /// This is the check vlmcsd's pre-bind defect fails: it compares against
    /// two sentinel values that an unbound connection leaves equal to
    /// `0xffff`, so a request naming `0xffff` matches both.
    #[must_use]
    pub fn syntax_for(&self, context_id: u16) -> Option<TransferSyntax> {
        self.state
            .contexts
            .iter()
            .find(|context| context.context_id == context_id)
            .map(|context| context.syntax)
    }

    /// Service a call on an accepted context.
    ///
    /// Exists only on `Association<Bound>`. There is no way to reach it from an
    /// unbound association, because there is no such method to call.
    ///
    /// # Errors
    ///
    /// Returns the status to fault with if the context is not one this
    /// association accepted (`WIRE-009`, #67).
    pub fn service(&self, context_id: u16) -> Result<TransferSyntax, NcaStatus> {
        self.syntax_for(context_id)
            .ok_or(NcaStatus::UnknownInterface)
    }
}

/// Which state the association is in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Unbound(Association<Unbound>),
    Bound(Association<Bound>),
    /// Momentarily absent while a transition is in flight.
    ///
    /// Never observable: it exists so a `bind` can consume the unbound value
    /// and put back a bound one without the association needing to be `Copy` or
    /// the transition needing a clone.
    Transitioning,
}

/// What the driver should do after a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// No complete PDU is buffered. Read more.
    NeedMore,
    /// Send the first `len` bytes of the output buffer and keep the connection
    /// open (`WIRE-021`, #79).
    Send {
        /// Bytes written.
        len: usize,
    },
    /// Send, then close.
    SendThenClose {
        /// Bytes written.
        len: usize,
        /// Why.
        reason: CloseReason,
    },
    /// Close without sending.
    Close {
        /// Why.
        reason: CloseReason,
    },
}

/// The receive buffer overflowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow;

/// A KMS connection: DCE/RPC framing, an association, and a reassembly buffer.
#[derive(Debug)]
pub struct Connection {
    phase: Phase,
    ciphers: Ciphers,
    ndr64_enabled: bool,
    inbound: ArrayVec<u8, MAX_PDU_LEN>,
    reassembly: ArrayVec<u8, MAX_STUB_LEN>,
    reassembling_context: Option<u16>,
    deadline: Option<Instant>,
    events: ArrayVec<ConnectionEvent, 8>,
}

impl Connection {
    /// Open a connection with a given association group (`WIRE-010`, #68).
    ///
    /// The group comes from the caller because it must be a random value drawn
    /// once per process and incremented per connection — which is process
    /// state, not connection state. py-kms's is `0x1063BF3F` on every
    /// installation in the world, so one `bind_ack` identifies the software
    /// with no active probing at all.
    #[must_use]
    pub fn new(assoc_group: u32, ndr64_enabled: bool) -> Self {
        Self {
            phase: Phase::Unbound(Association::new(assoc_group)),
            ciphers: Ciphers::new(),
            ndr64_enabled,
            inbound: ArrayVec::new(),
            reassembly: ArrayVec::new(),
            reassembling_context: None,
            deadline: None,
            events: ArrayVec::new(),
        }
    }

    /// Append received bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Overflow`] if the bytes would exceed [`MAX_PDU_LEN`]. That can
    /// only happen after `FragLength` has already been accepted, so it means
    /// the peer sent more than it declared.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<(), Overflow> {
        self.inbound
            .try_extend_from_slice(bytes)
            .map_err(|_| Overflow)
    }

    /// Take the next event this connection produced.
    pub fn next_event(&mut self) -> Option<ConnectionEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }

    /// When the driver should stop waiting for more input.
    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Whether a complete PDU is buffered and ready to process.
    #[must_use]
    pub fn has_complete_pdu(&self) -> bool {
        self.pdu_len().is_some_and(|len| self.inbound.len() >= len)
    }

    /// The declared length of the buffered PDU, if its header has arrived.
    fn pdu_len(&self) -> Option<usize> {
        let header = RpcHeader::read_from_prefix(&self.inbound).ok()?.0;
        Some(usize::from(header.frag_length.get()))
    }

    /// Process at most one buffered PDU.
    ///
    /// One per call, so a driver that received several in one read loops until
    /// this returns [`Step::NeedMore`]. That keeps the output buffer a single
    /// caller-owned slice (`KMS-023`, #39).
    pub fn step(
        &mut self,
        now: Instant,
        entropy: &mut dyn Entropy,
        activate: &mut dyn FnMut(&Request) -> Decision,
        out: &mut [u8],
    ) -> Step {
        self.deadline = now.checked_add(IDLE_TIMEOUT);

        // `WIRE-025` (#83): a PDU shorter than the common header is rejected
        // before anything is parsed. There is nothing to parse.
        if self.inbound.len() < HEADER_LEN {
            return Step::NeedMore;
        }
        let Ok((header, _)) = RpcHeader::read_from_prefix(&self.inbound) else {
            return Step::NeedMore;
        };

        let declared = usize::from(header.frag_length.get());
        if declared < HEADER_LEN {
            return self.reject(RejectReason::FragmentTooShort { declared });
        }
        // `WIRE-023` (#81): bound the length before buffering, not after.
        if declared > MAX_PDU_LEN {
            return self.reject(RejectReason::FragmentTooLong { declared });
        }
        if self.inbound.len() < declared {
            return Step::NeedMore;
        }

        // `WIRE-024` (#82): exactly `FragLength - 16` bytes are the body.
        // Consuming more or fewer is how a stream gets out of frame and stays
        // there.
        let pdu: ArrayVec<u8, MAX_PDU_LEN> = self.inbound.drain(..declared).collect();
        let body = pdu.get(HEADER_LEN..declared).unwrap_or(&[]);

        if !header.version_is_supported() {
            return self.reject(RejectReason::UnsupportedRpcVersion);
        }
        // Declined item D4: real KMS clients never authenticate. An inbound
        // trailer is faulted rather than being treated as stub data, which is
        // what vlmcsd does.
        if header.auth_length.get() != 0 {
            let _ = self.events.try_push(ConnectionEvent::Rejected {
                reason: RejectReason::AuthenticationAttempted,
            });
            return self.fault(out, header.call_id.get(), 0, NcaStatus::ProtocolError);
        }

        match header.packet_type() {
            Some(PacketType::Bind) => self.handle_bind(&header, body, entropy, out, false),
            Some(PacketType::AlterContext) => self.handle_bind(&header, body, entropy, out, true),
            Some(PacketType::Request) => self.handle_request(&header, body, entropy, activate, out),
            _ => self.reject(RejectReason::UnexpectedPacketType),
        }
    }

    /// Record a rejection and close.
    fn reject(&mut self, reason: RejectReason) -> Step {
        let _ = self.events.try_push(ConnectionEvent::Rejected { reason });
        self.inbound.clear();
        Step::Close {
            reason: CloseReason::Malformed,
        }
    }

    /// Emit a fault, and keep the association open.
    fn fault(&mut self, out: &mut [u8], call_id: u32, context_id: u16, status: NcaStatus) -> Step {
        let _ = self.events.try_push(ConnectionEvent::Faulted { status });
        match fault::write(out, call_id, context_id, status) {
            // A fault is a call-level failure, not a connection-level one, so
            // the association survives it (`WIRE-021`, #79).
            Some(len) => Step::Send { len },
            None => Step::Close {
                reason: CloseReason::Faulted,
            },
        }
    }

    fn handle_bind(
        &mut self,
        header: &RpcHeader,
        body: &[u8],
        entropy: &mut dyn Entropy,
        out: &mut [u8],
        is_alter: bool,
    ) -> Step {
        let Ok(request) = bind::parse(body) else {
            return self.reject(RejectReason::UnexpectedPacketType);
        };

        let (decision, assoc_group) =
            match core::mem::replace(&mut self.phase, Phase::Transitioning) {
                Phase::Unbound(association) => {
                    let group = association.assoc_group;
                    let (decision, outcome) = association.bind(&request, self.ndr64_enabled);
                    self.phase = match outcome {
                        Ok(bound) => {
                            if let Some(accepted) = decision.accepted_context {
                                let _ = self.events.try_push(ConnectionEvent::Bound {
                                    syntax: accepted.syntax,
                                    context_id: accepted.context_id,
                                });
                            }
                            Phase::Bound(bound)
                        }
                        Err(unbound) => Phase::Unbound(unbound),
                    };
                    (decision, group)
                }
                Phase::Bound(mut association) => {
                    let group = association.assoc_group;
                    let decision = association.alter_context(&request, self.ndr64_enabled);
                    if let Some(accepted) = decision.accepted_context {
                        let _ = self.events.try_push(ConnectionEvent::ContextAdded {
                            syntax: accepted.syntax,
                            context_id: accepted.context_id,
                        });
                    }
                    self.phase = Phase::Bound(association);
                    (decision, group)
                }
                Phase::Transitioning => {
                    self.phase = Phase::Transitioning;
                    return Step::Close {
                        reason: CloseReason::Malformed,
                    };
                }
            };

        let parameters = AckParameters {
            packet_type: if is_alter {
                PacketType::AlterContextResponse
            } else {
                PacketType::BindAck
            },
            call_id: header.call_id.get(),
            assoc_group,
            max_xmit_frag: request.max_xmit_frag,
            max_recv_frag: request.max_recv_frag,
            // An `alter_context_response` advertises no endpoint: the
            // association already exists (`WIRE-011`, #69).
            secondary_address: if is_alter {
                &[]
            } else {
                Self::secondary_address()
            },
            client_flags: header.flags(),
        };

        match bind::write_ack(&parameters, &decision, entropy, out) {
            Ok(len) => Step::Send { len },
            Err(_) => Step::Close {
                reason: CloseReason::Refused,
            },
        }
    }

    /// The endpoint this host advertises.
    ///
    /// A placeholder until the platform layer supplies the port of the socket
    /// that actually accepted (`WIRE-011`, #69, and `NET-001`, #150). It is a
    /// function rather than an inline constant so that wiring it up is one
    /// change here rather than a search through call sites.
    const fn secondary_address() -> &'static [u8] {
        b"1688"
    }

    fn handle_request(
        &mut self,
        header: &RpcHeader,
        body: &[u8],
        entropy: &mut dyn Entropy,
        activate: &mut dyn FnMut(&Request) -> Decision,
        out: &mut [u8],
    ) -> Step {
        let call_id = header.call_id.get();

        // The typestate: there is no `service` on an unbound association, so
        // the pre-bind path cannot reach the request handler at all.
        let Phase::Bound(association) = &self.phase else {
            return self.fault(out, call_id, 0, NcaStatus::UnknownInterface);
        };

        // The context ID lives at a fixed offset in every syntax, so it can be
        // read before the syntax is known — but only in a *first* fragment. In
        // a continuation those bytes are payload, so the context comes from
        // what the first fragment established (`WIRE-022`, #80).
        let flags = header.flags();
        let context_id = if flags.contains(PacketFlags::FIRST_FRAG) {
            body.get(4..6)
                .and_then(|pair| pair.first_chunk::<2>())
                .map_or(0, |pair| u16::from_le_bytes(*pair))
        } else {
            match self.reassembling_context {
                Some(context_id) => context_id,
                // A continuation with nothing to continue.
                None => {
                    return self.fault(out, call_id, 0, NcaStatus::ProtocolError);
                }
            }
        };

        let syntax = match association.service(context_id) {
            Ok(syntax) => syntax,
            Err(status) => return self.fault(out, call_id, context_id, status),
        };

        // `WIRE-022` (#80): accumulate fragments into a fixed buffer.
        if flags.contains(PacketFlags::FIRST_FRAG) {
            self.reassembly.clear();
            self.reassembling_context = Some(context_id);
        }
        if self.reassembly.try_extend_from_slice(body).is_err() {
            self.reassembly.clear();
            self.reassembling_context = None;
            let _ = self.events.try_push(ConnectionEvent::Rejected {
                reason: RejectReason::ReassemblyOverflow,
            });
            return self.fault(out, call_id, context_id, NcaStatus::ProtocolError);
        }
        if !flags.contains(PacketFlags::LAST_FRAG) {
            return Step::NeedMore;
        }

        let assembled: ArrayVec<u8, MAX_STUB_LEN> = self.reassembly.drain(..).collect();
        self.reassembling_context = None;

        let parsed = match stub::parse_request(&assembled, syntax) {
            Ok(parsed) => parsed,
            Err(StubError::UnknownOperation { .. }) => {
                return self.fault(out, call_id, context_id, NcaStatus::UnknownInterface);
            }
            Err(_) => {
                return self.fault(out, call_id, context_id, NcaStatus::ProtocolError);
            }
        };

        self.answer(
            call_id,
            context_id,
            syntax,
            parsed.data,
            entropy,
            activate,
            out,
        )
    }

    /// Decode the KMS payload, ask the policy layer, and frame the answer.
    #[expect(
        clippy::too_many_arguments,
        reason = "every argument is a distinct input to one wire-format decision"
    )]
    fn answer(
        &mut self,
        call_id: u32,
        context_id: u16,
        syntax: TransferSyntax,
        payload: &[u8],
        entropy: &mut dyn Entropy,
        activate: &mut dyn FnMut(&Request) -> Decision,
        out: &mut [u8],
    ) -> Step {
        let decoded = match framing::decode(payload, &self.ciphers) {
            Ok(decoded) => decoded,
            // `KMS-014` (#30): an unsupported version is a well-formed response
            // carrying 0x8007000D — not 0xC004F042, and not a dropped
            // connection. py-kms's equivalent path calls `.decode('utf-8')` on
            // bytes beginning 42 F0 04 C0 and has never once executed
            // successfully.
            Err(crate::kms::framing::DecodeError::Request(
                RequestError::UnsupportedVersion { .. } | RequestError::WrongLength { .. },
            )) => {
                return self.refuse(call_id, context_id, syntax, HResult::InvalidData, out);
            }
            Err(_) => {
                return self.fault(out, call_id, context_id, NcaStatus::ProtocolError);
            }
        };

        match activate(&decoded.request) {
            Decision::Grant(grant) => {
                let plan = ResponsePlan {
                    epid: &grant.epid,
                    client_machine_id: decoded.request.client_machine_id,
                    client_time: decoded.request.client_time,
                    count: grant.count,
                    intervals: grant.intervals,
                    hardware_id: grant.hardware_id,
                };

                let mut payload = [0_u8; MAX_RESPONSE_LEN];
                let Ok(payload_len) =
                    framing::encode(&decoded, &plan, &self.ciphers, entropy, &mut payload)
                else {
                    // The only reachable cause is a failed entropy source, and
                    // the right answer to that is to stop serving rather than
                    // to send something predictable (`OS-012`, #263).
                    return Step::Close {
                        reason: CloseReason::Refused,
                    };
                };

                let Some(len) = write_response_pdu(
                    out,
                    call_id,
                    context_id,
                    syntax,
                    HResult::Ok,
                    payload.get(..payload_len).unwrap_or(&[]),
                ) else {
                    return Step::Close {
                        reason: CloseReason::Refused,
                    };
                };

                let _ = self.events.try_push(ConnectionEvent::Activated {
                    version: decoded.version,
                    mac_verified: decoded.mac_verified,
                });
                Step::Send { len }
            }
            Decision::Refuse(result) => self.refuse(call_id, context_id, syntax, result, out),
        }
    }

    /// Emit a well-formed response carrying a non-zero result.
    fn refuse(
        &mut self,
        call_id: u32,
        context_id: u16,
        syntax: TransferSyntax,
        result: HResult,
        out: &mut [u8],
    ) -> Step {
        let _ = self.events.try_push(ConnectionEvent::Refused { result });
        match write_response_pdu(out, call_id, context_id, syntax, result, &[]) {
            Some(len) => Step::Send { len },
            None => Step::Close {
                reason: CloseReason::Faulted,
            },
        }
    }
}

/// Write a complete response PDU: the common header, then the stub.
///
/// Outbound PDUs are never fragmented (`WIRE-022`, #80): the widest response
/// this protocol produces is under 400 bytes and every client offers a
/// `MaxXmitFrag` of 5840, so `FIRST_FRAG | LAST_FRAG` is always right and
/// there is no outbound fragmentation state to get wrong.
fn write_response_pdu(
    out: &mut [u8],
    call_id: u32,
    context_id: u16,
    syntax: TransferSyntax,
    result: HResult,
    payload: &[u8],
) -> Option<usize> {
    let stub_len = if result.is_ok() {
        stub::response_stub_len(syntax, payload.len())
    } else {
        stub::error_stub_len(syntax)
    };
    let total = HEADER_LEN.checked_add(stub_len)?;
    let frag_length = u16::try_from(total).ok()?;

    let header = RpcHeader::for_reply(
        PacketType::Response,
        PacketFlags::COMPLETE,
        call_id,
        frag_length,
    );
    out.get_mut(..HEADER_LEN)?
        .copy_from_slice(header.as_bytes());

    let written = stub::write_response(
        out.get_mut(HEADER_LEN..)?,
        syntax,
        context_id,
        result.to_wire(),
        payload,
    )?;
    HEADER_LEN.checked_add(written)
}

/// The per-process source of association groups (`WIRE-010`, #68).
///
/// One random 32-bit value drawn at start-up, incremented per accepted
/// connection. A constant here is the most reliable passive fingerprint in the
/// class: py-kms hands out `0x1063BF3F` everywhere, so one `bind_ack`
/// identifies the software without any active probing.
#[derive(Debug)]
pub struct AssociationGroups {
    next: u32,
}

impl AssociationGroups {
    /// Draw the starting value from the entropy source.
    ///
    /// # Errors
    ///
    /// Returns `None` if the entropy source failed, in which case the host must
    /// not serve (`OS-012`, #263) — a predictable association group is exactly
    /// the property this exists to avoid.
    #[must_use]
    pub fn new(entropy: &mut dyn Entropy) -> Option<Self> {
        entropy.array::<4>().ok().map(|bytes| Self {
            next: u32::from_le_bytes(bytes),
        })
    }

    /// The group for the next accepted connection.
    pub fn take(&mut self) -> u32 {
        let current = self.next;
        // Wrapping rather than saturating: the sequence is an identifier, not a
        // count, and stalling at `u32::MAX` would make every later connection
        // share a group.
        self.next = self.next.wrapping_add(1);
        current
    }
}

/// The size of the fault PDU, re-exported so a driver can size its buffer.
pub const MIN_OUTPUT_LEN: usize = FAULT_LEN;

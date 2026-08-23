//! One conversation with a KMS host: connect, bind, activate (`CLI-001`, #207).
//!
//! Extracted from [`crate::probe`] because it is no longer only the probe that
//! needs it. The detection suite, the health check, the load generator
//! (`CLI-006`, #212) and the charging mode (`CLI-007`, #213) all do the same
//! three things and differ only in what they conclude from the answer.
//!
//! # What belongs here and what does not
//!
//! This module speaks the protocol. It does **not** judge: nothing here decides
//! that a response property makes a host distinguishable, and nothing here
//! knows what a `Finding` is. It hands back an [`Exchange`] carrying every
//! check's outcome and lets the caller decide what that means — which is what
//! lets a health check and a detection probe share one implementation while
//! disagreeing completely about what "healthy" means.
//!
//! # One connection, many requests
//!
//! A [`Session`] holds its association open across activations, because a
//! genuine client does and because two requests on one association is the only
//! way to observe a *stable* ePID (`ID-001`, #106). A caller that wants a fresh
//! connection per request opens a fresh session, which is exactly what
//! `--reconnect` does in the load generator.

use crate::request::{RequestError, RequestFields};
use core::net::SocketAddr;
use core::time::Duration;
use kmsrs_proto::entropy::Entropy;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::response::{self, DecodedResponse};
use kmsrs_proto::kms::validate::{self, Checks, MacCheck, Sent};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::FileTime;
use kmsrs_proto::types::{ClientMachineId, ClientTime};
use kmsrs_proto::wire::client::{Accepted, ClientAssociation, ClientError, Reply, Warning};
use kmsrs_proto::wire::header::HEADER_LEN;
use kmsrs_proto::wire::syntax::TransferSyntax;
use std::io::{Read, Write};
use std::net::TcpStream;

/// Why a conversation could not be completed.
///
/// Named `ProbeError` for the whole crate's history: every mode of the client
/// fails the same five ways, and splitting it per mode would produce five
/// enumerations with identical variants.
#[derive(Debug)]
pub enum ProbeError {
    /// The request could not be built.
    Request(RequestError),
    /// The conversation failed.
    Protocol(ClientError),
    /// The socket failed.
    Io(std::io::Error),
    /// The response could not be decoded.
    Decode(response::ResponseError),
    /// The entropy source failed, so the request would have carried predictable
    /// values (`OS-012`, #263).
    EntropyUnavailable,
}

impl core::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Request(error) => write!(f, "{error}"),
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Decode(error) => write!(f, "{error}"),
            Self::EntropyUnavailable => f.write_str("the entropy source failed"),
        }
    }
}

impl core::error::Error for ProbeError {}

impl From<std::io::Error> for ProbeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ClientError> for ProbeError {
    fn from(error: ClientError) -> Self {
        Self::Protocol(error)
    }
}

/// What one activation produced.
#[derive(Debug, Clone)]
pub struct Exchange {
    /// The version spoken.
    pub version: Version,
    /// Every response property, checked. What the caller *does* with a failure
    /// is the caller's business.
    pub checks: Checks,
    /// The ePID the host reported.
    pub epid: String,
    /// The count it reported.
    pub count: u32,
    /// The hardware ID, for v6.
    pub hardware_id: Option<[u8; 8]>,
    /// The association group this connection was given.
    pub assoc_group: u32,
}

/// An open conversation with a host.
#[derive(Debug)]
pub struct Session {
    stream: TcpStream,
    association: ClientAssociation,
    accepted: Accepted,
    /// The association group the host chose for this connection.
    ///
    /// A genuine host draws a fresh one per connection, so comparing it across
    /// sessions is a detection check the caller may want to make.
    pub assoc_group: u32,
}

impl Session {
    /// Connect and bind.
    ///
    /// `offer_ndr64` decides whether the bind offers both transfer syntaxes or
    /// NDR32 alone. Both are legitimate: a real client offers both, and
    /// offering NDR32 alone is how you ask whether a host supports it at all
    /// (`WIRE-029`, #87).
    ///
    /// `on_warning` receives anything the RPC layer noticed about the reply.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError`] if the host could not be reached, hung up, or
    /// refused the bind.
    pub fn open(
        target: SocketAddr,
        timeout: Duration,
        offer_ndr64: bool,
        on_warning: &mut dyn FnMut(Warning),
    ) -> Result<Self, ProbeError> {
        // `CLI-012` (#218): every wait is bounded. `vlmcs` hardcodes ten
        // seconds and offers no option, which makes it unusable both across a
        // slow link and in a soak test that wants to fail fast.
        let stream = TcpStream::connect_timeout(&target, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut association = ClientAssociation::new();
        let mut out = vec![0_u8; 4096];

        let (len, call_id) = association.bind(&mut out, offer_ndr64)?;
        let mut stream = stream;
        stream.write_all(out.get(..len).unwrap_or(&[]))?;
        let reply = read_pdu(&mut stream)?;

        let assoc_group = assoc_group_of(&reply);
        let accepted =
            match association.read_reply(&reply, call_id, TransferSyntax::Ndr32, on_warning)? {
                Reply::BindAck { accepted, .. } => accepted,
                Reply::Response { .. } => None,
            };
        let Some(accepted) = accepted else {
            return Err(ProbeError::Protocol(ClientError::BindRejected));
        };

        Ok(Self {
            stream,
            association,
            accepted,
            assoc_group,
        })
    }

    /// Send one activation request and decode the answer.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError`] if the request could not be built, the host hung
    /// up, or the response did not decode.
    pub fn activate(
        &mut self,
        fields: &RequestFields,
        entropy: &mut dyn Entropy,
        on_warning: &mut dyn FnMut(Warning),
    ) -> Result<Exchange, ProbeError> {
        let body = fields.to_body().map_err(ProbeError::Request)?;
        let ciphers = Ciphers::new();

        let mut stub = vec![0_u8; 1024];
        // `CLI-005` (#211): what goes in the version *word* is not necessarily
        // the version this request is framed and encrypted as. A probe that
        // could not separate the two could not ask "what does this host do with
        // a v7.0 request", which is the question that distinguishes a host
        // dispatching on both halves from one dispatching on the major alone.
        let declared = fields.declared_version();
        let stub_len = framing::encode_request_declaring(
            fields.version,
            declared,
            &body,
            &ciphers,
            entropy,
            &mut stub,
        )
        .map_err(|_| ProbeError::EntropyUnavailable)?;
        stub.truncate(stub_len);

        // The IV the client sent, which v5 echoes on the wire and v6 must not.
        let request_iv: Option<[u8; 16]> = if fields.version == Version::V4 {
            None
        } else {
            stub.get(4..20).and_then(|bytes| bytes.try_into().ok())
        };
        // Both sides derive `D_k(IV_request)`; the client recomputes it the
        // same way the server does.
        let shared_secret =
            ciphers
                .schedule(fields.version)
                .zip(request_iv)
                .and_then(|(schedule, iv)| {
                    let mut plain = [0_u8; 16];
                    kmsrs_crypto::cbc::decrypt(
                        schedule,
                        kmsrs_crypto::cbc::Iv::Null,
                        &iv,
                        &mut plain,
                    )
                    .ok()?;
                    Some(plain)
                });

        let mut out = vec![0_u8; 4096];
        let (len, call_id) = self.association.request(
            &mut out,
            self.accepted.context_id,
            self.accepted.syntax,
            &stub,
        )?;
        self.stream.write_all(out.get(..len).unwrap_or(&[]))?;

        let reply = read_pdu(&mut self.stream)?;
        let response_stub =
            match self
                .association
                .read_reply(&reply, call_id, self.accepted.syntax, on_warning)?
            {
                Reply::Response { stub, .. } => stub.to_vec(),
                Reply::BindAck { .. } => {
                    return Err(ProbeError::Protocol(ClientError::UnexpectedPacketType {
                        raw: 12,
                    }));
                }
            };

        let mut scratch = vec![0_u8; response_stub.len().max(64)];
        let decoded = response::decode(
            fields.version,
            &response_stub,
            ciphers.schedule(fields.version),
            &mut scratch,
        )
        .map_err(ProbeError::Decode)?;

        let wire = declared.to_wire();
        let sent = Sent {
            version: fields.version,
            client_machine_id: ClientMachineId(fields.client_machine_id),
            client_time: ClientTime(FileTime::from_ticks(fields.client_time)),
            request_iv,
            shared_secret,
            header_version: wire,
            response_header_version: wire,
        };
        let checks = validate::check(&sent, &decoded, Some(&MacCheck { tag: v4_tag }));

        Ok(Exchange {
            version: fields.version,
            checks,
            epid: epid_text(&decoded),
            count: decoded.count,
            hardware_id: decoded.hardware_id.map(|id| id.0),
            assoc_group: self.assoc_group,
        })
    }

    /// Which transfer syntax the host accepted.
    #[must_use]
    pub const fn syntax(&self) -> TransferSyntax {
        self.accepted.syntax
    }
}

/// A v4 MAC over a message, using the shipped key.
fn v4_tag(message: &[u8]) -> [u8; 16] {
    Ciphers::new().mac().tag(message)
}

/// The ePID as text, for comparison and for the report.
fn epid_text(decoded: &DecodedResponse<'_>) -> String {
    let units: Vec<u16> = decoded
        .pid_bytes
        .chunks_exact(2)
        .map(|pair| {
            u16::from_le_bytes([
                pair.first().copied().unwrap_or(0),
                pair.get(1).copied().unwrap_or(0),
            ])
        })
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// The association group from a `bind_ack` body.
fn assoc_group_of(reply: &[u8]) -> u32 {
    // The bind_ack body is max_xmit, max_recv, assoc_group — three fields, the
    // third at offset 4 past the header.
    reply
        .get(HEADER_LEN.saturating_add(4)..HEADER_LEN.saturating_add(8))
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// Read one whole RPC PDU: the common header, then `frag_length - 16` more.
///
/// # Errors
///
/// Returns [`ProbeError::Io`] if the host hung up mid-PDU.
pub fn read_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, ProbeError> {
    let mut header = [0_u8; HEADER_LEN];
    stream.read_exact(&mut header)?;

    let frag_len = usize::from(u16::from_le_bytes([
        *header.get(8).unwrap_or(&0),
        *header.get(9).unwrap_or(&0),
    ]));
    let rest = frag_len.saturating_sub(HEADER_LEN);

    let mut pdu = header.to_vec();
    pdu.resize(HEADER_LEN.saturating_add(rest), 0);
    if let Some(tail) = pdu.get_mut(HEADER_LEN..) {
        stream.read_exact(tail)?;
    }
    Ok(pdu)
}

//! The detection-resistance regression suite (`CLI-002`, #208).
//!
//! This is the module the whole crate exists for. Every [`Finding`] is a way to
//! tell an emulator from a genuine KMS host, and per the audit **none of the
//! three existing implementations survives this probe unreconfigured** — so a
//! test that only asked "did it activate?" would pass on all of them.
//!
//! Run against our own server it must produce **nothing**. That assertion is
//! what makes the anti-fingerprinting claims in this project checkable rather
//! than aspirational, and it is why the client is a first-class artifact
//! instead of a convenience script.
//!
//! # Two kinds of check
//!
//! Some properties live inside one exchange — the v6 IV rule, the allocation
//! hint, the padding. Those come from [`kmsrs_proto::kms::validate`] and
//! [`kmsrs_proto::wire::client`].
//!
//! Others only exist *across* exchanges, and they are the ones nobody checks:
//! whether the ePID is stable between two requests on one connection, and
//! whether the association group differs between two connections. Both are
//! properties of a *host*, not of a response, so a single-exchange client
//! cannot see them however carefully it reads the bytes.

use crate::request::{DEFAULT_TIMEOUT, RequestError, RequestFields};
use core::net::SocketAddr;
use core::time::Duration;
use kmsrs_proto::entropy::Entropy;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::response::{self, DecodedResponse};
use kmsrs_proto::kms::validate::{self, Check, Checks, MacCheck, Outcome, Sent};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::FileTime;
use kmsrs_proto::types::{ClientMachineId, ClientTime};
use kmsrs_proto::wire::client::{ClientAssociation, ClientError, Reply, Warning};
use kmsrs_proto::wire::header::HEADER_LEN;
use kmsrs_proto::wire::syntax::TransferSyntax;
use std::io::{Read, Write};
use std::net::TcpStream;

/// The `N_Policy` the count probe declares (`POL-019`, #313).
///
/// Two orders of magnitude past anything Microsoft ships — the real values are
/// 25 for Windows client SKUs and 5 for server and Office — so no honest client
/// can be mistaken for this one, and any host that answers with the number is
/// answering a question no real client asks.
pub const ABSURD_REQUIRED_CLIENTS: u32 = 5_000;

/// Hardware IDs that identify a stock emulator deployment.
///
/// `364F463A8863D35F` is py-kms's default, shared by every stock deployment of
/// it — a static value on the wire that says which program answered.
pub const SUSPICIOUS_HARDWARE_IDS: [[u8; 8]; 3] = [
    // py-kms's default.
    [0x36, 0x4F, 0x46, 0x3A, 0x88, 0x63, 0xD3, 0x5F],
    // All zeros: an implementation that never set one.
    [0; 8],
    // All ones: the other thing an unset field tends to be.
    [0xFF; 8],
];

/// Something about a host that distinguishes it from a genuine one.
///
/// Every variant is a *finding*, not an error: the activation may well have
/// succeeded. What it means is that an observer could tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A response property a genuine host always has was wrong.
    ResponseCheckFailed {
        /// Which property.
        check: Check,
        /// Which protocol version it was seen on.
        version: Version,
    },
    /// Something about the RPC conversation was wrong.
    Conversation(Warning),
    /// The host does not accept NDR32.
    ///
    /// Probed by binding with NDR32 as the **only** offer. A host that accepts
    /// NDR64 when both are offered is behaving correctly (`WIRE-029`, #87);
    /// one that cannot speak NDR32 at all is not one Microsoft shipped.
    Ndr32NotSupported,
    /// The ePID changed between two requests on one connection.
    ///
    /// A genuine host has **one** ePID for its lifetime. py-kms generates a
    /// fresh one for every single response unless `-e` is given, which is the
    /// single loudest tell in the entire ecosystem.
    EpidNotStable {
        /// What the first request was told.
        first: String,
        /// What the second was told.
        second: String,
    },
    /// The association group was identical across two separate connections.
    ///
    /// A genuine host draws a fresh one per connection. A constant means the
    /// value is hardcoded, which is both a tell and a sign that nothing else
    /// on that path is random either.
    AssociationGroupConstant {
        /// The repeated value.
        value: u32,
    },
    /// The hardware ID is a known stock constant.
    SuspiciousHardwareId {
        /// The value seen.
        hardware_id: [u8; 8],
    },
    /// The host closed the association instead of keeping it open.
    ConnectionClosedEarly,
    /// An absurd `N_Policy` came back as the reported count (`POL-019`, #313).
    ///
    /// A genuine host reports how many machine IDs it is *holding*, so a
    /// machine it has never seen that asks for five thousand is told a small
    /// number and does not activate. py-kms answers `2N`; an emulator flooring
    /// the count at the demand answers `N`. Both are statements no real host
    /// makes, and one packet reads them.
    AbsurdCountReflected {
        /// What the probe declared.
        demanded: u32,
        /// What came back.
        reported: u32,
    },
}

impl core::fmt::Display for Finding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ResponseCheckFailed { check, version } => write!(
                f,
                "{:?}: the response failed {}, which a genuine host always passes",
                version,
                check.name()
            ),
            Self::Conversation(warning) => write!(f, "{warning}"),
            Self::Ndr32NotSupported => f.write_str(
                "the host refused a bind offering only NDR32; every real host accepts it",
            ),
            Self::EpidNotStable { first, second } => write!(
                f,
                "the ePID changed between two requests on one connection: \
                 {first} then {second}. A genuine host has one ePID for its \
                 lifetime; py-kms generates a fresh one per response"
            ),
            Self::AssociationGroupConstant { value } => write!(
                f,
                "two separate connections were given the same association group \
                 0x{value:08X}; a genuine host draws a fresh one"
            ),
            Self::SuspiciousHardwareId { hardware_id } => write!(
                f,
                "the hardware ID {hardware_id:02X?} is a known stock constant"
            ),
            Self::ConnectionClosedEarly => {
                f.write_str("the host closed the association instead of keeping it open")
            }
            Self::AbsurdCountReflected { demanded, reported } => write!(
                f,
                "a machine this host had never seen declared N_Policy = \
                 {demanded} and was told {reported}; a genuine host reports \
                 how many machines it is holding, which is a small number"
            ),
        }
    }
}

/// Why a probe could not be completed.
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
    /// The entropy source failed, so the probe would have sent predictable
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
    /// Every response property, checked.
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

/// The result of probing one host.
#[derive(Debug, Default)]
pub struct Report {
    /// Every activation performed.
    pub exchanges: Vec<Exchange>,
    /// Everything that distinguishes this host from a genuine one.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Whether the host is indistinguishable from a genuine one, as far as
    /// this probe can tell.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// How to probe a host.
#[derive(Debug, Clone)]
pub struct Probe {
    /// Where to connect.
    pub target: SocketAddr,
    /// How long to wait for each reply (`CLI-012`, #218).
    pub timeout: Duration,
    /// What to send.
    pub fields: RequestFields,
    /// Which versions to exercise.
    pub versions: Vec<Version>,
}

impl Probe {
    /// A probe of one host with the defaults a real client would use.
    #[must_use]
    pub fn new(target: SocketAddr) -> Self {
        Self {
            target,
            timeout: DEFAULT_TIMEOUT,
            fields: RequestFields::default(),
            versions: Version::ALL.to_vec(),
        }
    }

    /// Run the full suite.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError`] if the host could not be reached or spoke
    /// something unparseable. A host that is merely *distinguishable* is not an
    /// error — that is what [`Report::findings`] is for.
    pub fn run(&self, entropy: &mut dyn Entropy) -> Result<Report, ProbeError> {
        let mut report = Report::default();

        // One connection per version, each doing two activations so the ePID
        // can be compared across requests.
        for version in &self.versions {
            let assoc_group = self.exchange_pair(*version, entropy, &mut report)?;
            // Both exchanges on that connection share its association group.
            if let Some(exchange) = report.exchanges.last_mut() {
                exchange.assoc_group = assoc_group;
            }
        }

        // Across connections: the association group must differ.
        let groups: Vec<u32> = report
            .exchanges
            .iter()
            .map(|exchange| exchange.assoc_group)
            .collect();
        if groups.len() > 1
            && groups.windows(2).all(|pair| pair.first() == pair.get(1))
            && let Some(value) = groups.first()
        {
            report
                .findings
                .push(Finding::AssociationGroupConstant { value: *value });
        }

        // A host that cannot speak NDR32 at all is not one Microsoft shipped.
        if !self.accepts_ndr32_alone()? {
            report.findings.push(Finding::Ndr32NotSupported);
        }

        // `POL-019` (#313): and one that answers an absurd demand with the
        // demand has said something no real host says.
        if let Some(reported) = self.reflects_an_absurd_required_count(entropy, &mut report)? {
            report.findings.push(Finding::AbsurdCountReflected {
                demanded: ABSURD_REQUIRED_CLIENTS,
                reported,
            });
        }

        Ok(report)
    }

    /// One connection, two activations, comparing the ePID between them.
    fn exchange_pair(
        &self,
        version: Version,
        entropy: &mut dyn Entropy,
        report: &mut Report,
    ) -> Result<u32, ProbeError> {
        let mut stream = self.connect()?;
        let mut association = ClientAssociation::new();
        let mut out = vec![0_u8; 4096];

        let (len, call_id) = association.bind(&mut out, true)?;
        stream.write_all(out.get(..len).unwrap_or(&[]))?;
        let reply = read_pdu(&mut stream)?;

        let assoc_group = assoc_group_of(&reply);
        let accepted = {
            let mut findings = Vec::new();
            let parsed =
                association.read_reply(&reply, call_id, TransferSyntax::Ndr32, &mut |warning| {
                    findings.push(Finding::Conversation(warning));
                })?;
            report.findings.extend(findings);
            match parsed {
                Reply::BindAck { accepted, .. } => accepted,
                Reply::Response { .. } => None,
            }
        };
        let Some(accepted) = accepted else {
            return Err(ProbeError::Protocol(ClientError::BindRejected));
        };

        let mut epids = Vec::new();
        for round in 0..2_u32 {
            let mut fields = self.fields.clone();
            fields.version = version;
            // A different machine each round, so the second request is a new
            // client rather than a renewal — which is what makes a *stable*
            // ePID meaningful.
            let mut machine = fields.client_machine_id.to_bytes();
            if let Some(slot) = machine.first_mut() {
                *slot = u8::try_from(round).unwrap_or(0);
            }
            fields.client_machine_id = kmsrs_db::Guid::from_bytes(machine);

            let exchange = Self::activate(
                &mut stream,
                &mut association,
                accepted,
                &fields,
                entropy,
                report,
            )?;
            epids.push(exchange.epid.clone());
            report.exchanges.push(exchange);
        }

        // `CLI-002` (#208): a genuine host has one ePID for its lifetime.
        // py-kms generates a fresh one per response unless `-e` is given.
        if let (Some(first), Some(second)) = (epids.first(), epids.get(1))
            && first != second
        {
            report.findings.push(Finding::EpidNotStable {
                first: first.clone(),
                second: second.clone(),
            });
        }

        Ok(assoc_group)
    }

    /// One activation on an established association.
    ///
    /// An associated function rather than a method: the socket's timeouts were
    /// set once in [`Probe::connect`], so everything this needs arrives as a
    /// parameter.
    fn activate(
        stream: &mut TcpStream,
        association: &mut ClientAssociation,
        accepted: kmsrs_proto::wire::client::Accepted,
        fields: &RequestFields,
        entropy: &mut dyn Entropy,
        report: &mut Report,
    ) -> Result<Exchange, ProbeError> {
        let body = fields.to_body().map_err(ProbeError::Request)?;
        let ciphers = Ciphers::new();

        let mut stub = vec![0_u8; 1024];
        let stub_len = framing::encode_request(fields.version, &body, &ciphers, entropy, &mut stub)
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
        let (len, call_id) =
            association.request(&mut out, accepted.context_id, accepted.syntax, &stub)?;
        stream.write_all(out.get(..len).unwrap_or(&[]))?;

        let reply = read_pdu(stream)?;
        let response_stub = {
            let mut findings = Vec::new();
            let parsed =
                association.read_reply(&reply, call_id, accepted.syntax, &mut |warning| {
                    findings.push(Finding::Conversation(warning));
                })?;
            report.findings.extend(findings);
            match parsed {
                Reply::Response { stub, .. } => stub.to_vec(),
                Reply::BindAck { .. } => {
                    return Err(ProbeError::Protocol(ClientError::UnexpectedPacketType {
                        raw: 12,
                    }));
                }
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

        let wire = fields.version.to_protocol_version().to_wire();
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

        for (check, outcome) in checks.iter() {
            if outcome == Outcome::Fail {
                report.findings.push(Finding::ResponseCheckFailed {
                    check,
                    version: fields.version,
                });
            }
        }

        if let Some(hardware_id) = decoded.hardware_id.map(|id| id.0)
            && SUSPICIOUS_HARDWARE_IDS.contains(&hardware_id)
        {
            report
                .findings
                .push(Finding::SuspiciousHardwareId { hardware_id });
        }

        Ok(Exchange {
            version: fields.version,
            checks,
            epid: epid_text(&decoded),
            count: decoded.count,
            hardware_id: decoded.hardware_id.map(|id| id.0),
            assoc_group: 0,
        })
    }

    /// Whether the host reflects an absurd `N_Policy` back (`POL-019`, #313).
    ///
    /// A genuine KMS host caches `2N` client machine IDs and reports how many
    /// it is *holding*. Asked for [`ABSURD_REQUIRED_CLIENTS`] by a machine it
    /// has never seen, it therefore answers with a small number and the client
    /// does not activate. py-kms answers `2N` — ten thousand for a demand of
    /// five thousand — and this host used to answer `N`.
    ///
    /// All three are distinguishable, and only the first is what a real host
    /// says. One packet reads the answer, which is why this is a probe rather
    /// than a note in a document.
    fn reflects_an_absurd_required_count(
        &self,
        entropy: &mut dyn Entropy,
        report: &mut Report,
    ) -> Result<Option<u32>, ProbeError> {
        let mut stream = self.connect()?;
        let mut association = ClientAssociation::new();
        let mut out = vec![0_u8; 4096];

        let (len, call_id) = association.bind(&mut out, true)?;
        stream.write_all(out.get(..len).unwrap_or(&[]))?;
        let reply = read_pdu(&mut stream)?;

        let accepted =
            match association.read_reply(&reply, call_id, TransferSyntax::Ndr32, &mut |_| {})? {
                Reply::BindAck { accepted, .. } => accepted,
                Reply::Response { .. } => None,
            };
        let Some(accepted) = accepted else {
            return Err(ProbeError::Protocol(ClientError::BindRejected));
        };

        // A machine identity this host has certainly not seen, so the honest
        // answer is "one" and anything large is the demand coming back.
        let mut fields = self.fields.clone();
        fields.required_clients = ABSURD_REQUIRED_CLIENTS;
        fields.client_machine_id = kmsrs_db::Guid::from_bytes([0xA5; 16]);

        let exchange = Self::activate(
            &mut stream,
            &mut association,
            accepted,
            &fields,
            entropy,
            report,
        )?;

        Ok((exchange.count >= ABSURD_REQUIRED_CLIENTS).then_some(exchange.count))
    }

    /// Whether the host accepts a bind offering NDR32 and nothing else.
    ///
    /// Distinct from "did it accept NDR32 when NDR64 was also offered" — a host
    /// that prefers NDR64 there is behaving correctly (`WIRE-029`, #87). What
    /// this asks is whether NDR32 is supported *at all*.
    fn accepts_ndr32_alone(&self) -> Result<bool, ProbeError> {
        let mut stream = self.connect()?;
        let mut association = ClientAssociation::new();
        let mut out = vec![0_u8; 4096];

        let (len, call_id) = association.bind(&mut out, false)?;
        stream.write_all(out.get(..len).unwrap_or(&[]))?;
        // A host that hangs up on an NDR32-only bind has answered the question.
        let Ok(reply) = read_pdu(&mut stream) else {
            return Ok(false);
        };

        match association.read_reply(&reply, call_id, TransferSyntax::Ndr32, &mut |_| {}) {
            Ok(Reply::BindAck { accepted, .. }) => {
                Ok(accepted.is_some_and(|context| context.syntax == TransferSyntax::Ndr32))
            }
            Ok(Reply::Response { .. }) | Err(_) => Ok(false),
        }
    }

    /// Connect, honouring the configured timeout (`CLI-012`, #218).
    fn connect(&self) -> Result<TcpStream, ProbeError> {
        let stream = TcpStream::connect_timeout(&self.target, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        Ok(stream)
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
    reply
        .get(HEADER_LEN.saturating_add(4)..HEADER_LEN.saturating_add(8))
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Read one whole RPC PDU: the common header, then `frag_length - 16` more.
fn read_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, ProbeError> {
    let mut header = [0_u8; HEADER_LEN];
    stream.read_exact(&mut header)?;
    let frag_length = usize::from(u16::from_le_bytes([
        header.get(8).copied().unwrap_or(0),
        header.get(9).copied().unwrap_or(0),
    ]));
    let remaining = frag_length.saturating_sub(HEADER_LEN);
    let mut rest = vec![0_u8; remaining];
    stream.read_exact(&mut rest)?;

    let mut pdu = header.to_vec();
    pdu.extend_from_slice(&rest);
    Ok(pdu)
}

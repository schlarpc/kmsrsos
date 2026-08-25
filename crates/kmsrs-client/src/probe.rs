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

use crate::request::{DEFAULT_TIMEOUT, RequestFields};
use crate::session::{Exchange, ProbeError, Session, read_pdu};
use core::net::SocketAddr;
use core::time::Duration;
use kmsrs_proto::entropy::Entropy;
use kmsrs_proto::kms::validate::{Check, Outcome};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::wire::client::{ClientAssociation, Reply, Warning};
use kmsrs_proto::wire::syntax::TransferSyntax;
use std::io::Write;
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
    /// The host refused a probe rather than answering it (`CLI-016`, #360).
    ///
    /// **Recorded, not fatal.** A refusal is an answer: vlmcsd meets the
    /// absurd-`N_Policy` probe with an `E_INVALIDARG` payload rather than an
    /// activation, which is a perfectly reasonable thing for a host to do and
    /// is exactly the sort of observation this suite exists to make. Ending the
    /// run on it would mean one host's one refusal cost every check after it.
    ProbeRefused {
        /// What the probe was asking.
        about: &'static str,
        /// What reading the reply produced.
        detail: String,
    },
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
            Self::ProbeRefused { about, detail } => write!(
                f,
                "the host refused the probe for {about}: {detail}. That is an \
                 answer rather than a failure — it is recorded and the run \
                 continues (CLI-016, #360)"
            ),
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
        let mut groups = Vec::new();
        for version in &self.versions {
            groups.push(self.exchange_pair(*version, entropy, &mut report)?);
        }

        // `WIRE-010` (#68): a genuine host draws a fresh association group per
        // connection. One value repeated across two connections means it is
        // hardcoded — which is both a tell in itself and a sign that nothing
        // else on that path is random either.
        //
        // Compared per *connection* rather than per exchange. Two activations
        // on one association legitimately share a group, so a check over the
        // exchange list is answering a different question and passes whatever
        // the host does.
        for (index, group) in groups.iter().enumerate() {
            if groups
                .get(index.saturating_add(1)..)
                .is_some_and(|rest| rest.contains(group))
            {
                report
                    .findings
                    .push(Finding::AssociationGroupConstant { value: *group });
                break;
            }
        }

        // A host that cannot speak NDR32 at all is not one Microsoft shipped.
        if !self.accepts_ndr32_alone()? {
            report.findings.push(Finding::Ndr32NotSupported);
        }

        // `POL-019` (#313): and one that answers an absurd demand with the
        // demand has said something no real host says.
        //
        // A host that *refuses* the demand is recorded rather than fatal
        // (`CLI-016`, #360). vlmcsd answers with an `E_INVALIDARG` payload, and
        // treating that as the end of the run would mean one host's one refusal
        // cost every check that comes after — the opposite of what a detection
        // suite is for.
        match self.reflects_an_absurd_required_count(entropy, &mut report) {
            Ok(Some(reported)) => report.findings.push(Finding::AbsurdCountReflected {
                demanded: ABSURD_REQUIRED_CLIENTS,
                reported,
            }),
            Ok(None) => {}
            Err(error) => report.findings.push(Finding::ProbeRefused {
                about: "an absurd required-client count",
                detail: format!("{error}"),
            }),
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
        let mut warnings = Vec::new();
        let mut session = Session::open(self.target, self.timeout, true, &mut |warning| {
            warnings.push(warning);
        })?;
        report
            .findings
            .extend(warnings.drain(..).map(Finding::Conversation));

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

            let exchange = Self::judge(&mut session, &fields, entropy, report)?;
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

        Ok(session.assoc_group)
    }

    /// One activation, with every response property turned into a finding.
    ///
    /// [`Session::activate`] speaks the protocol and does not judge; this is
    /// where the judging happens. Keeping them apart is what lets the health
    /// check (`SEC-008`, #200) and the load generator (`CLI-006`, #212) run the
    /// same exchange and disagree about what a failed check means.
    fn judge(
        session: &mut Session,
        fields: &RequestFields,
        entropy: &mut dyn Entropy,
        report: &mut Report,
    ) -> Result<Exchange, ProbeError> {
        let mut warnings = Vec::new();
        let exchange = session.activate(fields, entropy, &mut |warning| warnings.push(warning))?;
        report
            .findings
            .extend(warnings.into_iter().map(Finding::Conversation));

        for (check, outcome) in exchange.checks.iter() {
            if outcome == Outcome::Fail {
                report.findings.push(Finding::ResponseCheckFailed {
                    check,
                    version: fields.version,
                });
            }
        }

        if let Some(hardware_id) = exchange.hardware_id
            && SUSPICIOUS_HARDWARE_IDS.contains(&hardware_id)
        {
            report
                .findings
                .push(Finding::SuspiciousHardwareId { hardware_id });
        }

        Ok(exchange)
    }

    /// One activation, for a container HEALTHCHECK (`SEC-008`, #200;
    /// `PKG-004`, #241).
    ///
    /// Deliberately **not** the full probe. A health check answers one
    /// question — is the KMS port serving activations — and it answers it by
    /// doing what a client does: connect, bind, activate, decode. A host that
    /// is merely *distinguishable* is healthy, which is why nothing here looks
    /// at a finding.
    ///
    /// The Organization fork's `readyz` is the counter-example (`OBS-008`,
    /// #184): it proves its own HTTP handler is alive, which is the one fact a
    /// caller already had by getting a reply, so it reports healthy while the
    /// service it fronts is down.
    ///
    /// It also exists because a scratch container has no shell, no `curl` and
    /// no `nc`. The check has to be a binary, and the smallest honest one is a
    /// KMS client.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError`] if the host could not be reached, refused the
    /// bind, or answered with something that did not decode.
    pub fn health_check(&self, entropy: &mut dyn Entropy) -> Result<Exchange, ProbeError> {
        let mut session = Session::open(self.target, self.timeout, true, &mut |_| {})?;
        session.activate(&self.fields, entropy, &mut |_| {})
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
        let mut session = Session::open(self.target, self.timeout, true, &mut |_| {})?;

        // A machine identity this host has certainly not seen, so the honest
        // answer is "one" and anything large is the demand coming back.
        let mut fields = self.fields.clone();
        fields.required_clients = ABSURD_REQUIRED_CLIENTS;
        fields.client_machine_id = kmsrs_db::Guid::from_bytes([0xA5; 16]);

        let exchange = Self::judge(&mut session, &fields, entropy, report)?;
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

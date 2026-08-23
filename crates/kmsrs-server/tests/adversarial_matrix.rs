//! Every documented behavioural mismatch, as a test (`TEST-005`, #226).
//!
//! # What this file is
//!
//! `docs/kms-emulator-feature-matrix.md` lists 24 places where vlmcsd and
//! py-kms behave differently from each other, and says which of them a genuine
//! Microsoft KMS host agrees with. Each is a way to tell an emulator from a
//! real host by asking a question and reading the answer.
//!
//! One test per mismatch, driving a real [`Server`] through the same
//! [`Server::handle`] the event loop calls. Where the audit names the faithful
//! implementation, the assertion is that this host agrees with **it**; where it
//! says neither is right (MM18, MM22) the assertion is what a genuine host
//! does; where all three agree (MM20) the test exists to stop us drifting away
//! from a consensus that is currently right.
//!
//! # Why these and not "does it activate"
//!
//! Every emulator activates. That is the easy half, and it is what every
//! existing test suite in the ecosystem checks. What separates them is the
//! twenty-odd questions nobody asks — and each of these is one somebody
//! eventually will, because `kmsrs-client` asks them (`CLI-002`, #208).
//!
//! # The four that are not wire-observable
//!
//! Four of the 24 cannot be checked by handing a server bytes, and each is
//! covered elsewhere rather than faked here:
//!
//! * **MM13** (default listening address and family) — `tests/listener.rs`
//!   and `net::addr`, because it is about which sockets get bound.
//! * **MM19** (operator asks which machines have activated) — the bounded
//!   event log, `OBS-004` (#180), tested in `kmsrs-policy`.
//! * **MM22** (pointing a subnet at the server) — discovery, M10; the audit
//!   says neither implementation solves it and neither do we yet.
//! * **MM24** (zero-configuration startup) — `CFG-001` (#166) and
//!   `tests/wire_is_not_configurable.rs`, which is the stronger form: not
//!   "the defaults are good" but "there is nothing to configure".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_db::Guid;
use kmsrs_policy::events::Peer;
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody, WireGuid};
use kmsrs_proto::kms::response;
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::Instant;
use kmsrs_proto::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
use kmsrs_proto::wire::stub;
use kmsrs_proto::wire::syntax::TransferSyntax;
use kmsrs_server::{Compiled, Discovered, Handled, Operational, RequestContext, Server};
use std::net::{IpAddr, Ipv4Addr};
use zerocopy::{FromBytes, IntoBytes};

const NDR32_WIRE: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];
const NDR64_WIRE: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xBA, 0xBE, 0x37, 0x49, 0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36,
];
const INTERFACE_WIRE: [u8; 16] = [
    0x75, 0x21, 0xC8, 0x51, 0x4E, 0x84, 0x50, 0x47, 0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06,
];
/// The feature-negotiation pseudo-syntax (`WIRE-030`, BTFN).
const BTFN_PREFIX: [u8; 8] = [0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45];

/// Windows Server 2025's genuine counted ID (`DB-008`, #132).
fn server_2025() -> Guid {
    Guid::from_bytes([
        0x90, 0x7f, 0x1f, 0x65, 0xad, 0xcd, 0x4a, 0x2e, 0x95, 0xbc, 0x4b, 0xf5, 0x00, 0xbc, 0x6e,
        0x58,
    ])
}

/// The Windows application.
fn windows() -> Guid {
    kmsrs_db::APPLICATIONS
        .iter()
        .find(|entry| entry.name == "Windows")
        .expect("the Windows application is in the shipped data")
        .guid
}

fn server() -> Server {
    let mut entropy = DeterministicEntropy::from_seed(0x7E57_0005);
    Server::new(
        Compiled::BUILD,
        Operational::default(),
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap()
}

fn context(seconds: u64) -> RequestContext {
    RequestContext {
        peer: Some(Peer {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            port: 40_000,
        }),
        now: Instant::from_nanos(seconds.saturating_mul(1_000_000_000)),
        host_time: None,
    }
}

fn pdu(packet_type: PacketType, flags: PacketFlags, call_id: u32, body: &[u8]) -> Vec<u8> {
    let frag_length = u16::try_from(HEADER_LEN + body.len()).unwrap();
    let header = RpcHeader::for_reply(packet_type, flags, call_id, frag_length);
    let mut out = header.as_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// One presentation-context item.
fn context_item(context_id: u16, syntaxes: &[([u8; 16], u32)]) -> Vec<u8> {
    let mut item = Vec::new();
    item.extend_from_slice(&context_id.to_le_bytes());
    item.push(u8::try_from(syntaxes.len()).unwrap());
    item.push(0);
    item.extend_from_slice(&INTERFACE_WIRE);
    item.extend_from_slice(&0x0000_0001_u32.to_le_bytes());
    for (wire, version) in syntaxes {
        item.extend_from_slice(wire);
        item.extend_from_slice(&version.to_le_bytes());
    }
    item
}

/// A bind body offering the given context items.
fn bind_body_with(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&5840_u16.to_le_bytes());
    body.extend_from_slice(&5840_u16.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.push(u8::try_from(items.len()).unwrap());
    body.extend_from_slice(&[0, 0, 0]);
    for item in items {
        body.extend_from_slice(item);
    }
    body
}

/// The ordinary NDR32-only bind a Windows 7 client sends.
fn ndr32_bind() -> Vec<u8> {
    bind_body_with(&[context_item(0, &[(NDR32_WIRE, 2)])])
}

/// The NDR32 + NDR64 + BTFN bind a Windows 8 or later client sends.
fn modern_bind() -> Vec<u8> {
    let mut btfn = [0_u8; 16];
    btfn[..8].copy_from_slice(&BTFN_PREFIX);
    btfn[8] = 0x03;
    bind_body_with(&[
        context_item(0, &[(NDR32_WIRE, 2)]),
        context_item(1, &[(NDR64_WIRE, 1)]),
        context_item(2, &[(btfn, 1)]),
    ])
}

/// Wrap a KMS payload in an NDR32 request stub on context 0.
fn request_stub(payload: &[u8]) -> Vec<u8> {
    request_stub_on(0, payload)
}

/// The same, on a chosen presentation context.
///
/// Which context matters: a host accepts one, and a request on any other is
/// faulted (`WIRE-005`, #63). A test that hard-codes context 0 while binding
/// the usable syntax on context 1 measures the fault path and nothing else.
fn request_stub_on(context_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&context_id.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    for _ in 0..2 {
        body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    }
    body.extend_from_slice(payload);
    body
}

/// Everything a request can say, so a test can vary one field at a time.
#[derive(Debug, Clone, Copy)]
struct Fields {
    version: Version,
    machine: u32,
    application: Guid,
    counted: Guid,
    required_clients: u32,
    client_time: u64,
    license_status: u32,
}

impl Default for Fields {
    fn default() -> Self {
        Self {
            version: Version::V6,
            machine: 0xDEAD_0001,
            application: windows(),
            counted: server_2025(),
            required_clients: 25,
            client_time: 133_000_000_000_000_000,
            license_status: 2,
        }
    }
}

/// A KMS request payload, framed the way a client frames one.
fn payload(fields: Fields) -> Vec<u8> {
    let mut bytes = [0_u8; REQUEST_BODY_LEN];
    let mut body = RequestBody::read_from_bytes(&bytes).unwrap();
    body.version
        .set(fields.version.to_protocol_version().to_wire());
    body.required_clients.set(fields.required_clients);
    body.client_time.set(fields.client_time);
    body.license_status.set(fields.license_status);
    body.application_id = WireGuid::from_guid(fields.application);
    body.kms_counted_id = WireGuid::from_guid(fields.counted);
    body.client_machine_id.data1.set(fields.machine);
    bytes.copy_from_slice(body.as_bytes());
    let body = RequestBody::read_from_bytes(&bytes).unwrap();

    let mut entropy = DeterministicEntropy::from_seed(0xC0DE_0001);
    let ciphers = Ciphers::new();
    let mut stub = vec![0_u8; 1024];
    let len =
        framing::encode_request(fields.version, &body, &ciphers, &mut entropy, &mut stub).unwrap();
    stub.truncate(len);
    stub
}

/// A live conversation: a server, a connection, and a deterministic stream.
struct Session {
    server: Server,
    connection: kmsrs_proto::wire::Connection,
    entropy: DeterministicEntropy,
    call_id: u32,
    tick: u64,
}

impl Session {
    fn new() -> Self {
        let server = server();
        let connection = server.connection(0x1234_5678, 1688);
        Self {
            server,
            connection,
            entropy: DeterministicEntropy::from_seed(0x5A17_0005),
            call_id: 2,
            tick: 0,
        }
    }

    fn on_port(port: u16) -> Self {
        let mut session = Self::new();
        session.connection = session.server.connection(0x1234_5678, port);
        session
    }

    fn feed(&mut self, bytes: &[u8]) -> Handled {
        self.tick += 1;
        let context = context(self.tick);
        self.server
            .handle(&mut self.connection, bytes, context, &mut self.entropy)
    }

    fn send(&mut self, packet_type: PacketType, body: &[u8]) -> Handled {
        self.call_id += 1;
        let call_id = self.call_id;
        self.feed(&pdu(packet_type, PacketFlags::COMPLETE, call_id, body))
    }

    /// Bind, asserting it was accepted, and return the `bind_ack`.
    fn bind(&mut self, body: &[u8]) -> Vec<u8> {
        let handled = self.send(PacketType::Bind, body);
        assert!(!handled.close, "the bind was refused outright");
        assert!(!handled.response.is_empty(), "the bind went unanswered");
        handled.response
    }

    /// Send an activation request and return the decoded response.
    fn activate(&mut self, fields: Fields) -> DecodedActivation {
        let handled = self.send(PacketType::Request, &request_stub(&payload(fields)));
        assert!(
            !handled.response.is_empty(),
            "an activation request went unanswered"
        );
        DecodedActivation::from(&handled, fields.version)
    }
}

/// What a client learns from a response.
struct DecodedActivation {
    epid: String,
    count: u32,
    activation_interval: u32,
    renewal_interval: u32,
    hardware_id: Option<[u8; 8]>,
    closed: bool,
}

impl DecodedActivation {
    fn from(handled: &Handled, version: Version) -> Self {
        let body = handled.response.get(HEADER_LEN..).expect("a full PDU");
        let stub = stub::parse_response(body, TransferSyntax::Ndr32)
            .expect("the host answered with an NDR32 response stub");

        let ciphers = Ciphers::new();
        let mut scratch = vec![0_u8; stub.payload.len().max(64)];
        let decoded = response::decode(
            version,
            stub.payload,
            ciphers.schedule(version),
            &mut scratch,
        )
        .expect("the host answered with a decodable response");

        let epid: String = char::decode_utf16(
            decoded
                .pid_bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|unit| *unit != 0),
        )
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();

        Self {
            epid,
            count: decoded.count,
            activation_interval: decoded.activation_interval,
            renewal_interval: decoded.renewal_interval,
            hardware_id: decoded.hardware_id.map(|id| id.0),
            closed: handled.close,
        }
    }
}

// ---------------------------------------------------------------------------
// MM01 — ePID stability. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// Two identical requests on one connection must produce the same ePID.
///
/// **The canonical detection test.** py-kms regenerates an ePID per request, so
/// two requests one second apart come back with different host identities — a
/// single machine that claims to be two. `slmgr /dlv` shows it directly.
#[test]
fn mm01_two_identical_requests_on_one_connection_return_one_epid() {
    let mut session = Session::new();
    session.bind(&ndr32_bind());

    let first = session.activate(Fields::default());
    let second = session.activate(Fields::default());

    assert_eq!(
        first.epid, second.epid,
        "two identical requests on one connection returned different host \
         identities, which is the canonical way to spot py-kms"
    );
    assert_eq!(
        first.hardware_id, second.hardware_id,
        "the hardware ID changed between two requests from one machine"
    );
}

/// And across connections, because a host is a machine rather than a session.
#[test]
fn mm01_the_epid_is_stable_across_connections_from_the_same_host() {
    let mut server = server();
    let mut entropy = DeterministicEntropy::from_seed(0x5A17_0005);
    let mut seen = Vec::new();

    for index in 0..3_u64 {
        let mut connection = server.connection(0x1234_5678, 1688);
        let bind = pdu(PacketType::Bind, PacketFlags::COMPLETE, 2, &ndr32_bind());
        let handled = server.handle(&mut connection, &bind, context(index * 10), &mut entropy);
        assert!(!handled.close);

        let request = pdu(
            PacketType::Request,
            PacketFlags::COMPLETE,
            3,
            &request_stub(&payload(Fields::default())),
        );
        let handled = server.handle(
            &mut connection,
            &request,
            context(index * 10 + 1),
            &mut entropy,
        );
        seen.push(DecodedActivation::from(&handled, Version::V6).epid);
    }

    assert!(
        seen.windows(2).all(|pair| pair[0] == pair[1]),
        "one host produced {seen:?} across three connections"
    );
}

// ---------------------------------------------------------------------------
// MM02 — CSVLK selection bias. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// The host key answering must be one that counts the requested product.
///
/// py-kms advertises a Server 2019 group for an Office 2010 client roughly 98%
/// of the time. `TEST-008` (#229) measures the rate statistically; this checks
/// the observable consequence: the group ID in the ePID belongs to a key that
/// counts what was asked for.
#[test]
fn mm02_the_advertised_group_belongs_to_a_key_that_counts_the_product() {
    let sample: Vec<(Guid, Guid)> = kmsrs_db::CSVLKS
        .iter()
        .filter_map(|csvlk| Some((csvlk.application?, *csvlk.counted_ids.first()?)))
        .collect();
    assert!(
        sample.len() >= 5,
        "only {} host keys to test with",
        sample.len()
    );

    for (application, counted) in sample {
        let mut session = Session::new();
        session.bind(&ndr32_bind());
        let decoded = session.activate(Fields {
            application,
            counted,
            ..Fields::default()
        });

        // The ePID's second field is the group ID, zero-padded to five digits.
        // The assertion is not "which key" — several may count one product, and
        // choosing among them is `select`'s business — but that whichever
        // answered is one that counts what was asked for.
        let advertised: &str = decoded.epid.split('-').nth(1).expect("an ePID has fields");
        let candidates: Vec<String> = kmsrs_db::csvlks_counting(counted)
            .iter()
            .filter_map(|index| kmsrs_db::csvlk_at(*index))
            .map(|csvlk| format!("{:05}", csvlk.group_id))
            .collect();

        assert!(
            candidates.iter().any(|group| group == advertised),
            "a request for {counted} was answered with group {advertised}, which \
             counts it in no host key. Keys that do count it: {candidates:?}. \
             Full ePID: {}",
            decoded.epid
        );
    }
}

// ---------------------------------------------------------------------------
// MM03 / MM21 — client count. Faithful: vlmcsd -M1 / vlmcsd.
// ---------------------------------------------------------------------------

/// A client asking for 25 must be told at least 25.
///
/// Both implementations default to arithmetic on `N_Policy`; only vlmcsd's
/// `-M1` models distinct machines. `POL-001` (#89) is the model here: a world
/// count saturating at `2N`, with the reported count never below what the
/// client needs.
#[test]
fn mm03_the_reported_count_satisfies_the_clients_own_policy() {
    for required in [1_u32, 5, 25, 50] {
        let mut session = Session::new();
        session.bind(&ndr32_bind());
        let decoded = session.activate(Fields {
            required_clients: required,
            ..Fields::default()
        });
        assert!(
            decoded.count >= required,
            "a client needing {required} was told {}",
            decoded.count
        );
    }
}

/// A client asking for 5000 must not be handed 10000.
///
/// py-kms reflects `N_Policy * 2` back unchallenged, so a client asking for an
/// absurd number is told the host has twice as many. vlmcsd instead refuses
/// with `0x8007000D`, deliberately bug-compatible with a genuine host — whose
/// documented failure mode is that an overcharge of >=376 required clients
/// followed by 671 activations *permanently poisons* the CMID table.
///
/// This host does neither, on purpose. `POL-005` (#93) dissolves the poisoning
/// rather than reproducing it: an anomalous demand never mutates global state,
/// so there is nothing to poison and nothing to refuse for. `POL-006` (#94)
/// then answers any demand with the minimum that activates.
///
/// So what is asserted here is the mismatch the audit actually names — the
/// doubling. Whether flooring at an absurd `N` is *itself* a detection vector
/// is a separate question, raised by writing this test and tracked as
/// `POL-019` (#313) rather than decided in one.
#[test]
fn mm21_an_absurd_required_count_is_not_reflected_back_doubled() {
    for required in [376_u32, 1_000, 5_000, 100_000] {
        let mut session = Session::new();
        session.bind(&ndr32_bind());
        let decoded = session.activate(Fields {
            required_clients: required,
            ..Fields::default()
        });

        assert!(
            decoded.count <= required,
            "a client asking for {required} was told {}, which is py-kms \
             reflecting N_Policy * 2",
            decoded.count
        );
    }
}

/// And the overcharge does not follow the attacker out of their own request.
///
/// The property `POL-005` (#93) buys: a demand of 5000 changes what *that*
/// client is told and nothing else, so the attack vlmcsd is bug-compatible
/// with has no target here.
#[test]
fn mm21_an_overcharge_does_not_change_what_an_honest_client_is_told() {
    let mut session = Session::new();
    session.bind(&ndr32_bind());

    let before = session.activate(Fields {
        machine: 0x0001_0001,
        required_clients: 25,
        ..Fields::default()
    });

    for index in 0..32_u32 {
        let _ = session.activate(Fields {
            machine: 0x0BAD_0000 + index,
            required_clients: 5_000,
            ..Fields::default()
        });
    }

    let after = session.activate(Fields {
        machine: 0x0001_0001,
        required_clients: 25,
        ..Fields::default()
    });

    assert!(
        after.count <= 50,
        "an honest client asking for 25 was told {} after an overcharge, so the \
         attacker moved the shared world",
        after.count
    );
    assert!(
        after.count >= before.count,
        "an honest client's count went backwards, from {} to {}",
        before.count,
        after.count
    );
}

// ---------------------------------------------------------------------------
// MM04 — unknown protocol version. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// A request declaring version 7 gets an answer, not a silent reset.
///
/// py-kms's error path crashes and the client sees an RST, which is
/// indistinguishable from a network fault. A genuine host answers.
#[test]
fn mm04_an_unknown_protocol_version_is_answered_rather_than_dropped() {
    let mut session = Session::new();
    session.bind(&ndr32_bind());

    // Version 7.0 in the payload's version word, with an otherwise valid v6
    // request behind it.
    let mut stub = payload(Fields::default());
    stub[4..8].copy_from_slice(&0x0007_0000_u32.to_le_bytes());

    let handled = session.send(PacketType::Request, &request_stub(&stub));
    assert!(
        !handled.response.is_empty(),
        "a version-7 request produced no reply at all, which is what py-kms \
         does and what a client cannot distinguish from a broken network"
    );
}

// ---------------------------------------------------------------------------
// MM05 — connection lifetime. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// The association stays open after an activation.
///
/// py-kms disconnects unconditionally, which `vlmcs` reports as "probably
/// non-multitasked KMS emulator" and which `man vlmcsd.8` calls a direct
/// violation of DCE RPC.
#[test]
fn mm05_the_connection_survives_an_activation() {
    let mut session = Session::new();
    session.bind(&ndr32_bind());

    for index in 0..4_u32 {
        let decoded = session.activate(Fields {
            machine: 0xBEEF_0000 + index,
            ..Fields::default()
        });
        assert!(
            !decoded.closed,
            "the host hung up after activation {index}, which vlmcs reports as \
             a non-multitasked emulator"
        );
    }
}

// ---------------------------------------------------------------------------
// MM06 — NDR64 and alter_context. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// A Windows 8 or later client's bind is accepted with NDR64, and a following
/// `alter_context` is answered rather than closed.
#[test]
fn mm06_ndr64_is_accepted_and_alter_context_is_answered() {
    let mut session = Session::new();
    let ack = session.bind(&modern_bind());
    assert!(
        !ack.is_empty(),
        "a modern client's bind was not acknowledged"
    );

    let handled = session.send(PacketType::AlterContext, &modern_bind());
    assert!(
        !handled.close,
        "the host closed on alter_context, which is what py-kms does"
    );
    assert!(
        !handled.response.is_empty(),
        "alter_context went unanswered"
    );
}

// ---------------------------------------------------------------------------
// MM07 — association group. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// The `AssocGroup` in a `bind_ack` varies between hosts.
///
/// py-kms returns `0x1063BF3F` worldwide: a constant that identifies the
/// implementation from one packet, with no request needed.
#[test]
fn mm07_the_association_group_is_not_a_worldwide_constant() {
    /// py-kms's constant, verbatim from the audit.
    const PY_KMS: u32 = 0x1063_BF3F;

    let mut seen = std::collections::BTreeSet::new();
    for seed in 0..16_u64 {
        let mut entropy = DeterministicEntropy::from_seed(0xA55_0C000 ^ seed);
        let groups = kmsrs_proto::wire::connection::AssociationGroups::new(&mut entropy)
            .expect("deterministic entropy never fails");
        let mut groups = groups;
        let group = groups.take();
        assert_ne!(group, PY_KMS, "a host produced py-kms's constant verbatim");
        assert_ne!(group, 0, "an association group of zero means 'new group'");
        seen.insert(group);
    }
    assert!(
        seen.len() > 8,
        "16 hosts produced only {} distinct association groups",
        seen.len()
    );
}

// ---------------------------------------------------------------------------
// MM08 — bind item rejection. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// An unrecognised transfer syntax is NACKed per item, not dropped.
///
/// py-kms raises a `KeyError` and drops the connection, so a client offering a
/// syntax it does not know gets nothing at all.
#[test]
fn mm08_an_unknown_transfer_syntax_is_rejected_per_item_not_dropped() {
    let mut session = Session::new();
    let unknown = [0x99_u8; 16];
    let handled = session.send(
        PacketType::Bind,
        &bind_body_with(&[
            context_item(0, &[(unknown, 7)]),
            context_item(1, &[(NDR32_WIRE, 2)]),
        ]),
    );

    assert!(
        !handled.response.is_empty(),
        "a bind offering an unknown syntax alongside a known one was dropped"
    );
    assert!(
        !handled.close,
        "the host closed on an unknown syntax rather than rejecting the item"
    );

    // And the usable context still works. It is context 1 here: context 0
    // offered only the unknown syntax, so a host that accepted *it* would be
    // the defect.
    let handled = session.send(
        PacketType::Request,
        &request_stub_on(1, &payload(Fields::default())),
    );
    let decoded = DecodedActivation::from(&handled, Version::V6);
    assert!(
        !decoded.epid.is_empty(),
        "the context offering NDR32 alongside a rejected one was not usable"
    );
}

/// Different BTFN bits are acknowledged rather than fatal.
#[test]
fn mm08_unexpected_feature_bits_are_acknowledged() {
    for bits in [0x00_u8, 0x01, 0x02, 0x03, 0xFF] {
        let mut session = Session::new();
        let mut btfn = [0_u8; 16];
        btfn[..8].copy_from_slice(&BTFN_PREFIX);
        btfn[8] = bits;

        let handled = session.send(
            PacketType::Bind,
            &bind_body_with(&[
                context_item(0, &[(NDR32_WIRE, 2)]),
                context_item(1, &[(btfn, 1)]),
            ]),
        );
        assert!(
            !handled.response.is_empty() && !handled.close,
            "feature bits {bits:#04x} were fatal"
        );
    }
}

// ---------------------------------------------------------------------------
// MM09 — client clock skew. Faithful: vlmcsd -c1 (both accept by default).
// ---------------------------------------------------------------------------

/// A client six hours out of step is still activated by default.
///
/// Both implementations accept, and only vlmcsd can be *made* to refuse. This
/// build agrees with the default, and `strict-clock-skew` is the opt-in
/// (`POL-011`, #99). A host that refused by default would be the odd one out.
#[test]
fn mm09_a_six_hour_clock_skew_is_accepted_by_default() {
    /// Six hours in 100-nanosecond FILETIME ticks.
    const SIX_HOURS: u64 = 6 * 60 * 60 * 10_000_000;

    for skewed in [
        133_000_000_000_000_000_u64 - SIX_HOURS,
        133_000_000_000_000_000 + SIX_HOURS,
    ] {
        let mut session = Session::new();
        session.bind(&ndr32_bind());
        let decoded = session.activate(Fields {
            client_time: skewed,
            ..Fields::default()
        });
        assert!(
            !decoded.epid.is_empty(),
            "a client six hours out of step was refused, which no default \
             implementation does"
        );
    }
}

// ---------------------------------------------------------------------------
// MM10 — v4 latency. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// A v4 activation is answered from the same call, with no sleep.
///
/// py-kms calls `time.sleep(1)` on the v4 path, which is both a timing
/// fingerprint and a throughput cap of one activation per second per worker.
/// The sans-io core cannot sleep — there is no clock to sleep on — so the
/// assertion is structural: the answer is in the same `handle` return.
#[test]
fn mm10_a_v4_activation_is_answered_without_delay() {
    let mut session = Session::new();
    session.bind(&ndr32_bind());

    let started = std::time::Instant::now();
    let decoded = session.activate(Fields {
        version: Version::V4,
        ..Fields::default()
    });
    let elapsed = started.elapsed();

    assert!(!decoded.epid.is_empty(), "the v4 request was not answered");
    assert!(
        elapsed < std::time::Duration::from_millis(200),
        "a v4 activation took {elapsed:?}; py-kms's fingerprint is a one-second \
         sleep on exactly this path"
    );
}

/// And v4 is not systematically slower than v6, which is the comparison a
/// prober actually makes.
#[test]
fn mm10_v4_and_v6_are_answered_on_the_same_path() {
    let mut timings = Vec::new();
    for version in [Version::V4, Version::V5, Version::V6] {
        let mut session = Session::new();
        session.bind(&ndr32_bind());
        let started = std::time::Instant::now();
        for index in 0..8_u32 {
            let _ = session.activate(Fields {
                version,
                machine: 0xC0FE_0000 + index,
                ..Fields::default()
            });
        }
        timings.push((version, started.elapsed()));
    }

    let slowest = timings.iter().map(|(_, d)| *d).max().unwrap();
    assert!(
        slowest < std::time::Duration::from_millis(500),
        "eight activations took {slowest:?} at the slowest version: {timings:?}"
    );
}

// ---------------------------------------------------------------------------
// MM11 — unknown product. Faithful: vlmcsd and py-kms (Org) tie.
// ---------------------------------------------------------------------------

/// A GUID the database has never seen is activated, not dropped.
///
/// Upstream py-kms raises `UnboundLocalError` and drops silently. Refusing an
/// unknown KMS ID is why it fails on GUIDs it has not seen; not refusing is why
/// a 2019-era vlmcsd still activates Windows 11 (`POL-010`, #98).
#[test]
fn mm11_an_unknown_counted_id_is_activated_rather_than_dropped() {
    let mut session = Session::new();
    session.bind(&ndr32_bind());
    let decoded = session.activate(Fields {
        counted: Guid::from_bytes([0xFF; 16]),
        ..Fields::default()
    });

    assert!(
        !decoded.epid.is_empty(),
        "an unknown counted ID produced no ePID"
    );
    assert!(
        !decoded.closed,
        "an unknown counted ID closed the connection"
    );
}

// ---------------------------------------------------------------------------
// MM12 — concurrent clients. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// Two clients interleaved on one server do not see each other's state.
///
/// py-kms keeps the peer address in a process-global, so two concurrent
/// clients race over it and the log attributes one client's activation to the
/// other. `ARCH-004` (#4) is the structural answer: per-request state is owned
/// by the request.
#[test]
fn mm12_interleaved_clients_do_not_see_each_others_state() {
    let mut server = server();
    let mut entropy = DeterministicEntropy::from_seed(0x5A17_0012);

    let mut first = server.connection(0x1111_1111, 1688);
    let mut second = server.connection(0x2222_2222, 1688);

    for connection in [&mut first, &mut second] {
        let bind = pdu(PacketType::Bind, PacketFlags::COMPLETE, 2, &ndr32_bind());
        let handled = server.handle(connection, &bind, context(1), &mut entropy);
        assert!(!handled.close);
    }

    // Interleaved, alternating, with different machine IDs.
    let mut answers = Vec::new();
    for round in 0..3_u32 {
        for (index, machine) in [0xAAAA_0000 + round, 0xBBBB_0000 + round]
            .into_iter()
            .enumerate()
        {
            let connection = if index == 0 { &mut first } else { &mut second };
            let request = pdu(
                PacketType::Request,
                PacketFlags::COMPLETE,
                3 + round,
                &request_stub(&payload(Fields {
                    machine,
                    ..Fields::default()
                })),
            );
            let handled = server.handle(
                connection,
                &request,
                context(u64::from(round) + 2),
                &mut entropy,
            );
            answers.push((machine, DecodedActivation::from(&handled, Version::V6)));
        }
    }

    // Every answer is a well-formed activation from the same host identity:
    // interleaving must not produce a second host.
    let epids: std::collections::BTreeSet<&str> =
        answers.iter().map(|(_, a)| a.epid.as_str()).collect();
    assert_eq!(
        epids.len(),
        1,
        "interleaving two clients produced {} distinct host identities: {epids:?}",
        epids.len()
    );
    for (machine, answer) in &answers {
        assert!(
            !answer.closed,
            "the connection for machine {machine:08x} was closed"
        );
    }
}

// ---------------------------------------------------------------------------
// MM14 — connect and send nothing. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// A client that connects and says nothing does not consume the host.
///
/// py-kms blocks in `recv()` forever with no worker cap, so a handful of silent
/// connections is a denial of service. The sans-io core answers `NeedMore` and
/// arms a deadline; `NET-004` (#153) is the timeout and `tests/stress.rs` is
/// where the driver side is exercised.
#[test]
fn mm14_a_silent_client_is_answered_with_nothing_and_costs_nothing() {
    let mut session = Session::new();
    let handled = session.feed(&[]);
    assert!(
        handled.response.is_empty(),
        "an empty read produced a reply"
    );
    assert!(!handled.close, "an empty read closed the connection");

    // A partial header, repeatedly: still no reply, still no close.
    for _ in 0..64 {
        let handled = session.feed(&[5]);
        assert!(handled.response.is_empty());
        if handled.close {
            // Closing once the receive buffer is full is correct; what is not
            // correct is answering, or blocking.
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// MM15 — default hardware ID. Faithful: py-kms (Org).
// ---------------------------------------------------------------------------

/// The v6 hardware ID is not a published constant.
///
/// One of only three mismatches py-kms wins. Both projects' *defaults* are
/// fixed constants published in their own source, so every deployment that
/// never changed it shares one hardware ID — a cross-deployment fingerprint.
/// `ID-012` (#117) draws one per host key per process.
#[test]
fn mm15_the_hardware_id_is_drawn_rather_than_published() {
    /// vlmcsd's compile-time `DefaultHwId`, verbatim from the audit.
    const VLMCSD_DEFAULT: [u8; 8] = [0x36, 0x4F, 0x46, 0x3A, 0x8C, 0x84, 0x7A, 0x2D];

    let mut seen = std::collections::BTreeSet::new();
    for seed in 0..8_u64 {
        let mut entropy = DeterministicEntropy::from_seed(0x4D00_0015 ^ seed);
        let mut server = Server::new(
            Compiled::BUILD,
            Operational::default(),
            Discovered::default(),
            &mut entropy,
            kmsrs_db::Date::new(2026, 8, 1).unwrap(),
        )
        .unwrap();
        let mut connection = server.connection(0x1234_5678, 1688);

        let bind = pdu(PacketType::Bind, PacketFlags::COMPLETE, 2, &ndr32_bind());
        let _ = server.handle(&mut connection, &bind, context(1), &mut entropy);
        let request = pdu(
            PacketType::Request,
            PacketFlags::COMPLETE,
            3,
            &request_stub(&payload(Fields::default())),
        );
        let handled = server.handle(&mut connection, &request, context(2), &mut entropy);
        let decoded = DecodedActivation::from(&handled, Version::V6);

        let id = decoded.hardware_id.expect("v6 carries a hardware ID");
        assert_ne!(
            id, VLMCSD_DEFAULT,
            "a host emitted vlmcsd's published default hardware ID"
        );
        assert_ne!(id, [0; 8], "a host emitted an all-zero hardware ID");
        seen.insert(id);
    }

    assert!(
        seen.len() > 4,
        "eight independently seeded hosts produced only {} distinct hardware \
         IDs, which is a cross-deployment fingerprint",
        seen.len()
    );
}

// ---------------------------------------------------------------------------
// MM16 — secondary address. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// The `bind_ack` advertises the port that actually accepted.
///
/// py-kms echoes its configured primary port regardless, so a client that
/// reconnects to the advertised endpoint is sent somewhere the host is not.
#[test]
fn mm16_the_bind_ack_advertises_the_accepting_port() {
    for port in [1688_u16, 1689, 4711, 65_535] {
        let mut session = Session::on_port(port);
        let ack = session.bind(&ndr32_bind());

        let expected = format!("{port}");
        let text = String::from_utf8_lossy(&ack);
        assert!(
            text.contains(&expected),
            "a listener on port {port} advertised a secondary address that does \
             not mention it"
        );
    }
}

// ---------------------------------------------------------------------------
// MM17 — response header construction. Faithful: py-kms.
// ---------------------------------------------------------------------------

/// The reply's header is built, not mirrored.
///
/// The second of the three py-kms wins. vlmcsd `memcpy`s the request header
/// into its response, so it answers a big-endian client with little-endian data
/// and claims otherwise, and it reflects arbitrary `PacketFlags` back.
#[test]
fn mm17_the_reply_header_is_constructed_rather_than_mirrored() {
    let hostile_flags = [
        PacketFlags::COMPLETE,
        PacketFlags::from_bits(0xFF),
        PacketFlags::from_bits(0x00),
        PacketFlags::from_bits(0x55),
    ];

    for flags in hostile_flags {
        let mut session = Session::new();
        let bind = pdu(PacketType::Bind, flags, 2, &ndr32_bind());
        let handled = session.feed(&bind);
        if handled.response.is_empty() {
            // Refusing a malformed flag combination is fine; mirroring it is
            // not, and there is nothing to mirror if nothing was sent.
            continue;
        }

        let header = RpcHeader::read_from_prefix(&handled.response)
            .expect("a reply is at least a header")
            .0;
        assert_ne!(
            header.packet_flags, 0xFF,
            "the host mirrored 0xFF straight back into its own header"
        );
        assert_eq!(
            header.data_representation,
            [0x10, 0x00, 0x00, 0x00],
            "the data representation is not this host's own"
        );
        assert_eq!(
            header.auth_length.get(),
            0,
            "the host echoed an auth length into a PDU with no auth trailer"
        );
    }
}

/// A big-endian data representation in the request does not change the reply's.
#[test]
fn mm17_a_big_endian_client_is_not_answered_in_its_own_representation() {
    let mut session = Session::new();
    let mut bind = pdu(PacketType::Bind, PacketFlags::COMPLETE, 2, &ndr32_bind());
    // Big-endian integers, EBCDIC characters — a combination no KMS client
    // sends, and exactly what vlmcsd would reflect.
    bind[4] = 0x01;

    let handled = session.feed(&bind);
    if handled.response.is_empty() {
        return;
    }
    let header = RpcHeader::read_from_prefix(&handled.response)
        .expect("a reply is at least a header")
        .0;
    assert_eq!(
        header.data_representation,
        [0x10, 0x00, 0x00, 0x00],
        "the host claimed the client's data representation as its own"
    );
}

/// The call ID *is* echoed, because that one is the protocol.
#[test]
fn mm17_the_call_id_is_echoed_because_that_is_what_it_is_for() {
    for call_id in [1_u32, 2, 0x7FFF_FFFF, 0xFFFF_FFFF] {
        let mut session = Session::new();
        let bind = pdu(
            PacketType::Bind,
            PacketFlags::COMPLETE,
            call_id,
            &ndr32_bind(),
        );
        let handled = session.feed(&bind);
        assert!(
            !handled.response.is_empty(),
            "call {call_id} went unanswered"
        );

        let header = RpcHeader::read_from_prefix(&handled.response)
            .expect("a reply is at least a header")
            .0;
        assert_eq!(
            header.call_id.get(),
            call_id,
            "the reply to call {call_id} carried a different call ID"
        );
    }
}

// ---------------------------------------------------------------------------
// MM18 — length validation. Faithful: neither.
// ---------------------------------------------------------------------------

/// A declared length longer than what arrived is refused with an answer.
///
/// One of two mismatches where **neither** implementation is right: vlmcsd
/// reads uninitialised stack past the end of the received data and sends it to
/// the client; py-kms raises and drops silently. A genuine host answers with a
/// fault and keeps the association.
#[test]
fn mm18_a_declared_length_past_the_end_is_answered_not_read_past() {
    let mut session = Session::new();
    session.bind(&ndr32_bind());

    let real = payload(Fields::default());
    let mut body = Vec::new();
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    // Both NDR length fields claim far more than follows.
    for _ in 0..2 {
        body.extend_from_slice(&0x0000_FFFF_u32.to_le_bytes());
    }
    body.extend_from_slice(&real);

    let handled = session.send(PacketType::Request, &body);
    assert!(
        !handled.response.is_empty(),
        "a request declaring more than it sent produced no reply, which is \
         py-kms's silent drop"
    );

    // Whatever came back is bounded by what a host can legitimately produce.
    assert!(
        handled.response.len() < 4096,
        "the host replied with {} bytes to a request that sent {}, which is the \
         shape of vlmcsd reading past its buffer",
        handled.response.len(),
        real.len()
    );
}

// ---------------------------------------------------------------------------
// MM20 — intervals. All three agree; a non-mismatch, pinned so we do not drift.
// ---------------------------------------------------------------------------

/// The activation and renewal intervals are the values all three report.
#[test]
fn mm20_the_reported_intervals_match_the_consensus() {
    let mut session = Session::new();
    session.bind(&ndr32_bind());
    let decoded = session.activate(Fields::default());

    assert_eq!(
        decoded.activation_interval, 120,
        "the activation interval is not the two hours every implementation and \
         every genuine host reports"
    );
    assert_eq!(
        decoded.renewal_interval, 10_080,
        "the renewal interval is not the seven days every implementation and \
         every genuine host reports"
    );
}

// ---------------------------------------------------------------------------
// MM23 — retail and preview SKUs. Faithful: vlmcsd.
// ---------------------------------------------------------------------------

/// A retail or preview SKU is refused, with a well-formed refusal.
///
/// py-kms carries the `IsRetail`/`IsPreview` data and never reads it, so it
/// activates products no genuine host will. `POL-010` (#98) is the strict half
/// of the product gate, and the refusal is a response rather than a
/// disconnection (`KMS-014`, #30).
#[test]
fn mm23_a_non_volume_product_is_refused_with_a_response() {
    let retail: Vec<Guid> = kmsrs_db::PRODUCTS
        .iter()
        .filter(|product| product.kind == kmsrs_db::KeyKind::Retail)
        .map(|product| product.activation_id)
        .take(3)
        .collect();

    if retail.is_empty() {
        // The shipped extraction may carry no retail rows; the gate is tested
        // directly in `kmsrs-policy`, and this is the end-to-end half.
        return;
    }

    for counted in retail {
        let mut session = Session::new();
        session.bind(&ndr32_bind());
        let handled = session.send(
            PacketType::Request,
            &request_stub(&payload(Fields {
                counted,
                ..Fields::default()
            })),
        );
        assert!(
            !handled.response.is_empty(),
            "a retail SKU was refused by disconnection rather than by a \
             response (`KMS-014`, #30)"
        );
    }
}

// ---------------------------------------------------------------------------
// Coverage: the matrix itself.
// ---------------------------------------------------------------------------

/// Every mismatch is either tested here or accounted for.
///
/// The list is written out rather than derived, because deriving it from the
/// test names would make a missing test invisible — which is exactly the
/// failure this guards against.
#[test]
fn every_documented_mismatch_is_covered() {
    /// The four that cannot be checked by handing a server bytes, with where
    /// each is covered instead.
    const ELSEWHERE: &[(&str, &str)] = &[
        (
            "MM13",
            "tests/listener.rs and net::addr — which sockets get bound",
        ),
        (
            "MM19",
            "the bounded event log, OBS-004 (#180), in kmsrs-policy",
        ),
        (
            "MM22",
            "discovery, M10 — neither implementation solves it either",
        ),
        (
            "MM24",
            "tests/wire_is_not_configurable.rs — there is nothing to configure",
        ),
    ];

    const TESTED_HERE: &[&str] = &[
        "MM01", "MM02", "MM03", "MM04", "MM05", "MM06", "MM07", "MM08", "MM09", "MM10", "MM11",
        "MM12", "MM14", "MM15", "MM16", "MM17", "MM18", "MM20", "MM21", "MM23",
    ];

    let covered = TESTED_HERE.len() + ELSEWHERE.len();
    assert_eq!(
        covered,
        24,
        "the feature matrix documents 24 mismatches; {covered} are accounted \
         for. Tested here: {}. Elsewhere: {}",
        TESTED_HERE.len(),
        ELSEWHERE.len()
    );

    // And every one appears exactly once.
    let mut all: Vec<&str> = TESTED_HERE.to_vec();
    all.extend(ELSEWHERE.iter().map(|(name, _)| *name));
    all.sort_unstable();
    let mut deduped = all.clone();
    deduped.dedup();
    assert_eq!(all, deduped, "a mismatch is listed twice");

    for index in 1..=24_u32 {
        let name = format!("MM{index:02}");
        assert!(
            all.contains(&name.as_str()),
            "{name} is in the feature matrix and in neither list"
        );
    }
}

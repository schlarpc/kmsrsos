//! Byte-exact golden vectors (`TEST-002`, #223).
//!
//! Every PDU family is built from a fixed deterministic entropy stream and
//! compared against a committed file. A change that alters any byte on the wire
//! fails here rather than shipping.
//!
//! # Blessing
//!
//! `KMSRSOS_BLESS=1 cargo test -p kmsrs-proto --test golden_vectors`
//!
//! Deliberately a separate, explicit step: a test that rewrote its own
//! expectations on failure would assert nothing at all. When a diff is
//! intentional, blessing it and reading the diff in review is the point.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::epid::EPid;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody, WireGuid};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::Instant;
use kmsrs_proto::types::{HardwareId, Intervals};
use kmsrs_proto::wire::client::ClientAssociation;
use kmsrs_proto::wire::connection::{Connection, Decision, Grant, Step};
use kmsrs_proto::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
use kmsrs_proto::wire::syntax::TransferSyntax;
use std::path::PathBuf;
use zerocopy::{FromBytes, IntoBytes};

/// The ePID every response vector carries.
const EPID: &str = "03612-00206-591-000000-03-1033-26100.0000-2412024";

/// The machine ID every request vector carries.
const MACHINE: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
];

/// The timestamp every request vector carries.
const CLIENT_TICKS: u64 = 133_000_000_000_000_000;

/// A fixed association group, so `bind_ack` vectors are reproducible.
const ASSOC_GROUP: u32 = 0x1234_5678;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../kmsrs-vectors/vectors")
}

/// A KMS request body with fixed contents.
fn request_body(version: Version) -> RequestBody {
    let mut bytes = [0_u8; REQUEST_BODY_LEN];
    let mut body = RequestBody::read_from_bytes(&bytes).unwrap();
    body.version.set(version.to_protocol_version().to_wire());
    body.required_clients.set(25);
    body.client_time.set(CLIENT_TICKS);
    body.application_id.data1.set(0x55c9_2734);
    body.kms_counted_id.data1.set(0x907f_1f65);
    body.client_machine_id = WireGuid::from_guid(kmsrs_db::Guid::from_bytes(MACHINE));
    for (slot, unit) in body
        .workstation_name
        .iter_mut()
        .zip("golden".encode_utf16())
    {
        slot.set(unit);
    }
    bytes.copy_from_slice(body.as_bytes());
    RequestBody::read_from_bytes(&bytes).unwrap()
}

/// The decision every response vector is built from.
fn grant() -> Decision {
    Decision::Grant(Grant {
        epid: EPid::parse(EPID).unwrap(),
        count: 50,
        intervals: Intervals::DEFAULT,
        hardware_id: HardwareId([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
    })
}

/// Drive one PDU through a server connection and return what it sent.
fn server_reply(connection: &mut Connection, input: &[u8], seed: u64) -> Vec<u8> {
    let mut entropy = DeterministicEntropy::from_seed(seed);
    let mut out = vec![0_u8; 4096];
    connection.receive(input).unwrap();
    let decision = grant();
    let step = connection.step(
        Instant::from_nanos(1_000),
        &mut entropy,
        &mut |_request| decision.clone(),
        &mut out,
    );
    let len = match step {
        Step::Send { len } | Step::SendThenClose { len, .. } => len,
        Step::NeedMore | Step::Close { .. } => 0,
    };
    out.truncate(len);
    out
}

/// Build every vector, in the order `kmsrs_vectors::VECTORS` lists them.
fn build_all() -> Vec<(&'static str, Vec<u8>)> {
    let mut built: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // --- bind, both offer shapes -------------------------------------------
    let mut client32 = ClientAssociation::new();
    let mut out = vec![0_u8; 4096];
    let (len, _) = client32.bind(&mut out, false).unwrap();
    let bind_ndr32 = out[..len].to_vec();
    built.push(("bind-ndr32", bind_ndr32.clone()));

    let mut client64 = ClientAssociation::new();
    let (len, _) = client64.bind(&mut out, true).unwrap();
    let bind_ndr64 = out[..len].to_vec();
    built.push(("bind-ndr64", bind_ndr64.clone()));

    // --- bind_ack for each ---------------------------------------------------
    let mut server = Connection::new(ASSOC_GROUP, true);
    built.push((
        "bind-ack-ndr32",
        server_reply(&mut server, &bind_ndr32, 0x0A11),
    ));

    let mut server64 = Connection::new(ASSOC_GROUP, true);
    let ack64 = server_reply(&mut server64, &bind_ndr64, 0x0A12);
    built.push(("bind-ack-ndr64", ack64));

    // --- alter_context and its response --------------------------------------
    // An alter_context is a bind body under a different packet type, sent on an
    // association that already exists.
    let mut alter = bind_ndr64.clone();
    alter[2] = PacketType::AlterContext.to_wire();
    built.push(("alter-context", alter.clone()));
    built.push((
        "alter-context-response",
        server_reply(&mut server64, &alter, 0x0A13),
    ));

    // --- request and response, per version -----------------------------------
    for (version, name_request, name_response, seed) in [
        (Version::V4, "request-v4", "response-v4", 0x0B04_u64),
        (Version::V5, "request-v5", "response-v5", 0x0B05),
        (Version::V6, "request-v6", "response-v6", 0x0B06),
    ] {
        let ciphers = Ciphers::new();
        let mut entropy = DeterministicEntropy::from_seed(seed);
        let mut stub = vec![0_u8; 1024];
        let stub_len = framing::encode_request(
            version,
            &request_body(version),
            &ciphers,
            &mut entropy,
            &mut stub,
        )
        .unwrap();
        stub.truncate(stub_len);

        let mut client = ClientAssociation::new();
        let mut out = vec![0_u8; 4096];
        // Context 1 with NDR64, which is what the ndr64 bind_ack accepted.
        let (len, _) = client
            .request(&mut out, 1, TransferSyntax::Ndr64, &stub)
            .unwrap();
        let request_pdu = out[..len].to_vec();
        built.push((name_request, request_pdu.clone()));

        // A fresh association per version, so each response vector stands alone.
        let mut host = Connection::new(ASSOC_GROUP, true);
        let _ = server_reply(&mut host, &bind_ndr64, 0x0A12);
        built.push((
            name_response,
            server_reply(&mut host, &request_pdu, seed.wrapping_add(1)),
        ));
    }

    // --- fault: a call on a context the host never accepted -------------------
    let mut host = Connection::new(ASSOC_GROUP, true);
    let _ = server_reply(&mut host, &bind_ndr64, 0x0A12);
    let ciphers = Ciphers::new();
    let mut entropy = DeterministicEntropy::from_seed(0x0C01);
    let mut stub = vec![0_u8; 1024];
    let stub_len = framing::encode_request(
        Version::V6,
        &request_body(Version::V6),
        &ciphers,
        &mut entropy,
        &mut stub,
    )
    .unwrap();
    stub.truncate(stub_len);
    let mut client = ClientAssociation::new();
    let mut out = vec![0_u8; 4096];
    // Context 9 was never offered, so it cannot have been accepted.
    let (len, _) = client
        .request(&mut out, 9, TransferSyntax::Ndr64, &stub)
        .unwrap();
    built.push(("fault", server_reply(&mut host, &out[..len], 0x0C02)));

    // --- bind_nak: an unsupported RPC version --------------------------------
    let mut nak_input = bind_ndr64.clone();
    // The major RPC version is byte 0; 5 is the only one that exists.
    nak_input[0] = 6;
    let mut host = Connection::new(ASSOC_GROUP, true);
    built.push(("bind-nak", server_reply(&mut host, &nak_input, 0x0C03)));

    built
}

/// `TEST-002` (#223): every family is committed and matches, byte for byte.
#[test]
fn every_vector_matches_its_committed_bytes() {
    let bless = std::env::var("KMSRSOS_BLESS").is_ok();
    let built = build_all();

    if bless {
        std::fs::create_dir_all(vectors_dir()).expect("the vectors directory");
        for (name, bytes) in &built {
            std::fs::write(vectors_dir().join(format!("{name}.bin")), bytes)
                .expect("writing a vector");
        }
        eprintln!("blessed {} vectors", built.len());
        return;
    }

    let mut mismatched = Vec::new();
    for (name, bytes) in &built {
        let Some(vector) = kmsrs_vectors::find(name) else {
            mismatched.push(format!("{name}: no committed vector"));
            continue;
        };
        if vector.bytes != bytes.as_slice() {
            mismatched.push(format!(
                "{name} ({}): committed {} bytes, built {} bytes\n  committed: {:02x?}\n  built:     {:02x?}",
                vector.description,
                vector.bytes.len(),
                bytes.len(),
                &vector.bytes[..vector.bytes.len().min(48)],
                &bytes[..bytes.len().min(48)],
            ));
        }
    }

    assert!(
        mismatched.is_empty(),
        "the wire format changed. If that was intended, re-bless with \
         KMSRSOS_BLESS=1 and read the diff in review:\n\n{}",
        mismatched.join("\n\n")
    );
}

/// Every committed vector is built by the generator, and vice versa — so a
/// family cannot be quietly dropped from one side.
#[test]
fn the_committed_set_and_the_built_set_agree() {
    let built: Vec<&str> = build_all().into_iter().map(|(name, _)| name).collect();
    let committed: Vec<&str> = kmsrs_vectors::VECTORS
        .iter()
        .map(|vector| vector.name)
        .collect();

    for name in &built {
        assert!(
            committed.contains(name),
            "{name} is built but not committed"
        );
    }
    for name in &committed {
        assert!(built.contains(name), "{name} is committed but not built");
    }
    assert_eq!(
        built.len(),
        committed.len(),
        "the two sets should be the same size"
    );
}

/// `TEST-002` (#223) asks for all twelve families. Named individually so a
/// missing one is a named failure rather than a count that quietly drifted.
#[test]
fn all_twelve_families_are_present() {
    for family in [
        "bind-ndr32",
        "bind-ndr64",
        "bind-ack-ndr32",
        "bind-ack-ndr64",
        "alter-context",
        "alter-context-response",
        "request-v4",
        "response-v4",
        "request-v5",
        "response-v5",
        "request-v6",
        "response-v6",
        "fault",
        "bind-nak",
    ] {
        let vector = kmsrs_vectors::find(family)
            .unwrap_or_else(|| panic!("{family} is missing from the committed set"));
        assert!(!vector.bytes.is_empty(), "{family} is empty");
        assert!(
            vector.bytes.len() >= HEADER_LEN,
            "{family} is shorter than an RPC header"
        );
    }
}

/// Every vector is a well-formed PDU whose declared length matches its size.
///
/// A vector that is not a valid PDU would still "match its committed bytes"
/// forever, so this is what stops a blessed mistake from becoming permanent.
#[test]
fn every_vector_is_a_well_formed_pdu() {
    for vector in kmsrs_vectors::VECTORS {
        let (header, _) = RpcHeader::read_from_prefix(vector.bytes)
            .unwrap_or_else(|_| panic!("{} is not a PDU", vector.name));
        assert_eq!(
            usize::from(header.frag_length.get()),
            vector.bytes.len(),
            "{}: frag_length disagrees with the file's size",
            vector.name
        );
        assert!(
            header.packet_type().is_some(),
            "{} has packet type {}, which is not one this protocol has",
            vector.name,
            header.packet_type
        );
        assert!(
            header.flags().contains(PacketFlags::LAST_FRAG),
            "{} is not a complete message",
            vector.name
        );
    }
}

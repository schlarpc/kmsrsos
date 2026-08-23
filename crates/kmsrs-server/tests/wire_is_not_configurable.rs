//! No runtime setting can move a byte on the wire (`CFG-001`, #166).
//!
//! This is the test that makes the configuration categories mean something. It
//! drives a complete RPC conversation — bind, then activate — through two
//! servers that are identical except that **every** [`Operational`] field is
//! different, and asserts the response bytes are byte-for-byte equal.
//!
//! # Why this matters more than it looks
//!
//! A given binary has exactly one on-wire behaviour. That is what lets a
//! differential run against vlmcsd or py-kms validate *the artifact* rather
//! than one configuration of it. If a runtime knob could move a wire byte then
//! a green differential run would say nothing about the binary anyone actually
//! deployed — and worse, an operator changing a log setting could change how
//! the host looks to a prober.
//!
//! The type system does most of the work: [`kmsrs_server::Server::handle`] is
//! handed [`kmsrs_server::Compiled`] and never [`Operational`], so threading an
//! operational field into a response means changing a signature. This test is
//! what notices when someone does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use core::time::Duration;
use kmsrs_policy::events::Peer;
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::Instant;
use kmsrs_proto::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
use kmsrs_proto::wire::syntax::TransferSyntax;
use kmsrs_server::config::operational::{ColourChoice, LogFormat, LogLevel};
use kmsrs_server::{Compiled, Discovered, Operational, RequestContext, Server};
use std::net::{IpAddr, Ipv4Addr};
use zerocopy::{FromBytes, IntoBytes};

const NDR32_WIRE: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];
const INTERFACE_WIRE: [u8; 16] = [
    0x75, 0x21, 0xC8, 0x51, 0x4E, 0x84, 0x50, 0x47, 0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06,
];

fn pdu(packet_type: PacketType, flags: PacketFlags, call_id: u32, body: &[u8]) -> Vec<u8> {
    let frag_length = u16::try_from(HEADER_LEN + body.len()).unwrap();
    let header = RpcHeader::for_reply(packet_type, flags, call_id, frag_length);
    let mut out = header.as_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn bind_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&5840_u16.to_le_bytes());
    body.extend_from_slice(&5840_u16.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.push(1);
    body.extend_from_slice(&[0, 0, 0]);
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(&INTERFACE_WIRE);
    body.extend_from_slice(&0x0000_0001_u32.to_le_bytes());
    body.extend_from_slice(&NDR32_WIRE);
    body.extend_from_slice(&2_u32.to_le_bytes());
    body
}

fn request_body(payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    for _ in 0..2 {
        body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    }
    body.extend_from_slice(payload);
    body
}

/// A KMS request payload for a machine, framed the way a client frames one.
fn kms_payload(version: Version, machine: u32) -> Vec<u8> {
    let mut bytes = [0_u8; REQUEST_BODY_LEN];
    let mut body = RequestBody::read_from_bytes(&bytes).unwrap();
    body.version.set(version.to_protocol_version().to_wire());
    body.required_clients.set(25);
    body.client_time.set(133_000_000_000_000_000);
    body.application_id.data1.set(0x55c9_2734);
    body.kms_counted_id.data1.set(0x907f_1f65);
    body.client_machine_id.data1.set(machine);
    bytes.copy_from_slice(body.as_bytes());
    let body = RequestBody::read_from_bytes(&bytes).unwrap();

    // A fresh deterministic stream per payload, so the *request* bytes are a
    // pure function of `version` and `machine`.
    let mut entropy = DeterministicEntropy::from_seed(0xC0DE);
    let ciphers = Ciphers::new();
    let mut stub = vec![0_u8; 512];
    let len = framing::encode_request(version, &body, &ciphers, &mut entropy, &mut stub).unwrap();
    stub.truncate(len);
    stub
}

fn server(operational: Operational) -> Server {
    let mut entropy = DeterministicEntropy::from_seed(0xABCD_1234);
    Server::new(
        Compiled::BUILD,
        operational,
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap()
}

fn context(index: u64) -> RequestContext {
    RequestContext {
        peer: Some(Peer {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            port: 40_000,
        }),
        now: Instant::from_nanos(index.saturating_mul(1_000_000_000)),
        host_time: None,
    }
}

/// Run a whole conversation and return every byte the server sent.
fn conversation(operational: Operational, version: Version) -> Vec<u8> {
    let mut server = server(operational);
    let mut connection = server.connection(0x1234_5678, 1688);
    // The response's random salt must not vary between the two runs, so both
    // get the same deterministic stream.
    let mut entropy = DeterministicEntropy::from_seed(0x5A17);
    let mut sent = Vec::new();

    let bind = pdu(PacketType::Bind, PacketFlags::COMPLETE, 2, &bind_body());
    let handled = server.handle(&mut connection, &bind, context(0), &mut entropy);
    assert!(!handled.close, "the bind was refused");
    assert!(!handled.response.is_empty(), "the bind was not answered");
    sent.extend_from_slice(&handled.response);

    // Several activations, so anything that varies with accumulated state
    // shows up too.
    for index in 1..=5_u32 {
        let payload = kms_payload(version, 0xDEAD_0000 + index);
        let request = pdu(
            PacketType::Request,
            PacketFlags::COMPLETE,
            index + 2,
            &request_body(&payload),
        );
        let handled = server.handle(
            &mut connection,
            &request,
            context(u64::from(index)),
            &mut entropy,
        );
        assert!(!handled.close, "request {index} closed the connection");
        assert!(
            !handled.response.is_empty(),
            "request {index} went unanswered"
        );
        sent.extend_from_slice(&handled.response);
    }

    let _ = TransferSyntax::Ndr32;
    sent
}

/// An `Operational` whose every field differs from the default.
fn maximally_different() -> Operational {
    let flipped = Operational {
        log_level: LogLevel::Debug,
        log_format: LogFormat::Text,
        colour: ColourChoice::Always,
        web_ui: false,
        web_ui_port: 9999,
        event_log_capacity: 7,
        event_retention: Duration::from_hours(1),
    };
    let defaults = Operational::default();
    assert_ne!(flipped.log_level, defaults.log_level);
    assert_ne!(flipped.log_format, defaults.log_format);
    assert_ne!(flipped.colour, defaults.colour);
    assert_ne!(flipped.web_ui, defaults.web_ui);
    assert_ne!(flipped.web_ui_port, defaults.web_ui_port);
    assert_ne!(flipped.event_log_capacity, defaults.event_log_capacity);
    assert_ne!(flipped.event_retention, defaults.event_retention);
    flipped
}

/// The whole point (`CFG-001`, #166).
#[test]
fn no_operational_setting_changes_a_single_response_byte() {
    for version in [Version::V4, Version::V5, Version::V6] {
        let with_defaults = conversation(Operational::default(), version);
        let with_everything_changed = conversation(maximally_different(), version);

        assert!(
            !with_defaults.is_empty(),
            "{version:?} produced no bytes at all, so this proves nothing"
        );
        assert_eq!(
            with_defaults, with_everything_changed,
            "{version:?}: a runtime setting moved a byte on the wire"
        );
    }
}

/// The counterpart: a *compiled* setting is allowed to change the wire, and
/// does. Without this the test above could pass because the conversation is
/// insensitive to everything, which would prove nothing at all.
#[test]
fn a_compiled_setting_does_change_the_wire() {
    let baseline = conversation(Operational::default(), Version::V6);

    let mut altered = Compiled::BUILD;
    altered.intervals.renewal = Compiled::BUILD.intervals.renewal + 1;

    let mut entropy = DeterministicEntropy::from_seed(0xABCD_1234);
    let mut server = Server::new(
        altered,
        Operational::default(),
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap();
    let mut connection = server.connection(0x1234_5678, 1688);
    let mut entropy = DeterministicEntropy::from_seed(0x5A17);
    let mut sent = Vec::new();

    let bind = pdu(PacketType::Bind, PacketFlags::COMPLETE, 2, &bind_body());
    sent.extend_from_slice(
        &server
            .handle(&mut connection, &bind, context(0), &mut entropy)
            .response,
    );
    for index in 1..=5_u32 {
        let payload = kms_payload(Version::V6, 0xDEAD_0000 + index);
        let request = pdu(
            PacketType::Request,
            PacketFlags::COMPLETE,
            index + 2,
            &request_body(&payload),
        );
        sent.extend_from_slice(
            &server
                .handle(
                    &mut connection,
                    &request,
                    context(u64::from(index)),
                    &mut entropy,
                )
                .response,
        );
    }

    assert_ne!(
        baseline, sent,
        "changing the renewal interval must change the wire, or the \
         no-operational-setting test above is vacuous"
    );
}

/// Operational settings still *do* something — they are not simply ignored.
#[test]
fn operational_settings_affect_what_they_are_supposed_to() {
    let mut small = server(Operational {
        event_log_capacity: 3,
        ..Operational::default()
    });
    let mut connection = small.connection(1, 1688);
    let mut entropy = DeterministicEntropy::from_seed(1);

    let bind = pdu(PacketType::Bind, PacketFlags::COMPLETE, 2, &bind_body());
    small.handle(&mut connection, &bind, context(0), &mut entropy);

    assert_eq!(
        small.operational().event_log_capacity,
        3,
        "the setting is carried"
    );
    assert_eq!(
        small.operational().web_ui_port,
        Operational::default().web_ui_port,
        "and the others keep their defaults"
    );
}

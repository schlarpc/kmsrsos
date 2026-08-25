//! The host's clock reaches a request (`POL-020`, #346; `POL-011`, #99).
//!
//! # Why this file exists rather than more cases in `gate.rs`
//!
//! `kmsrs-policy`'s own tests already prove that `gate::evaluate` measures skew
//! correctly and that `strict-clock-skew` refuses on it. They passed for the
//! whole time the feature was inert, because they call `evaluate` directly and
//! pass a `host_time` in by hand — and `driver.rs` passed `None`, so the only
//! caller that mattered never exercised the path.
//!
//! Everything here therefore goes through a **real socket and the real driver**.
//! That is the difference that makes these tests able to fail: a regression to
//! `host_time: None` is invisible from inside the policy crate and is the first
//! thing this file notices.
//!
//! # What is deliberately not tested here
//!
//! That the host's wall clock is *accurate*. It is projected from one reading
//! taken at start-up (`OS-007`, #258 permits no second read), so a clock that
//! steps afterwards is not tracked — a documented consequence, argued in
//! `kmsrs_server::clock`, not an accident.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use kmsrs_policy::gate::CLOCK_SKEW_TOLERANCE;
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::{FileTime, Instant};
use kmsrs_proto::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
use kmsrs_server::config::operational::LogLevel;
use kmsrs_server::net::driver::Driver;
use kmsrs_server::net::listener::bind_each;
use kmsrs_server::{Compiled, Discovered, Operational, Server, WallClock};
use std::io::{Read, Write};
use std::net::TcpStream;
use zerocopy::{FromBytes, IntoBytes};

/// The timestamp every request in this file claims: 2022-06-18T04:26:40Z.
///
/// A fixed value rather than "now", because the whole subject is the distance
/// between this and the host's clock, and a test whose subject moves is a test
/// that fails on a Tuesday.
const CLIENT_TIME_TICKS: u64 = 133_000_000_000_000_000;

/// The monotonic reading the driver's clock is pinned at.
const PINNED: Instant = Instant::from_nanos(1_000_000);

const NDR32_WIRE: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];
const INTERFACE_WIRE: [u8; 16] = [
    0x75, 0x21, 0xC8, 0x51, 0x4E, 0x84, 0x50, 0x47, 0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06,
];

fn pdu(packet_type: PacketType, call_id: u32, body: &[u8]) -> Vec<u8> {
    let frag_length = u16::try_from(HEADER_LEN + body.len()).unwrap();
    let header = RpcHeader::for_reply(packet_type, PacketFlags::COMPLETE, call_id, frag_length);
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

/// A v6 activation request claiming [`CLIENT_TIME_TICKS`].
fn kms_payload() -> Vec<u8> {
    let mut bytes = [0_u8; REQUEST_BODY_LEN];
    let mut body = RequestBody::read_from_bytes(&bytes).unwrap();
    body.version
        .set(Version::V6.to_protocol_version().to_wire());
    body.required_clients.set(25);
    body.client_time.set(CLIENT_TIME_TICKS);
    body.application_id.data1.set(0x55c9_2734);
    body.kms_counted_id.data1.set(0x907f_1f65);
    body.client_machine_id.data1.set(0x0102_0304);
    bytes.copy_from_slice(body.as_bytes());
    let body = RequestBody::read_from_bytes(&bytes).unwrap();

    let mut entropy = DeterministicEntropy::from_seed(0xC0DE);
    let mut stub = vec![0_u8; 512];
    let len = framing::encode_request(Version::V6, &body, &Ciphers::new(), &mut entropy, &mut stub)
        .unwrap();
    stub.truncate(len);
    stub
}

fn quiet() -> Operational {
    Operational {
        log_level: LogLevel::Error,
        ..Operational::default()
    }
}

/// A server whose wall clock reads `offset` away from the client's timestamp.
///
/// `None` builds one with no wall clock at all — the honest state for a
/// platform without one, and the state the whole program was accidentally in
/// before `POL-020`.
fn server_offset_from_client(offset: Option<i64>) -> Server {
    let mut entropy = DeterministicEntropy::from_seed(0x11_22_33_44);
    let server = Server::new(
        Compiled::BUILD,
        quiet(),
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap();

    match offset {
        None => server,
        Some(seconds) => {
            let client = FileTime::from_ticks(CLIENT_TIME_TICKS);
            let magnitude = Duration::from_secs(seconds.unsigned_abs());
            let host = if seconds >= 0 {
                client.checked_add(magnitude).unwrap()
            } else {
                client.checked_sub(magnitude).unwrap()
            };
            // Anchored at the same reading the driver's clock is pinned to, so
            // the projection contributes nothing and the offset under test is
            // exactly the one asked for.
            server.with_wall_clock(WallClock::anchored(host, PINNED))
        }
    }
}

/// Run one activation against a driver on loopback and return the server.
fn activate_against(server: Server) -> Driver {
    let (bound, _) = bind_each(&[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)]).unwrap();
    let address = bound[0].address;
    let mut driver = Driver::new(server, bound, 8).unwrap();
    let shutdown = driver.shutdown_handle();

    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let mut entropy = DeterministicEntropy::from_seed(0x5A17);
            driver.run(&mut entropy, &|| PINNED).unwrap();
            driver
        });

        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .write_all(&pdu(PacketType::Bind, 1, &bind_body()))
            .unwrap();
        read_pdu(&mut stream);
        stream
            .write_all(&pdu(PacketType::Request, 2, &request_body(&kms_payload())))
            .unwrap();
        read_pdu(&mut stream);
        drop(stream);

        shutdown.request();
        handle.join().expect("the loop stopped cleanly")
    })
}

fn read_pdu(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0_u8; HEADER_LEN];
    stream.read_exact(&mut header).expect("a response header");
    let frag_length = usize::from(u16::from_le_bytes([header[8], header[9]]));
    let mut rest = vec![0_u8; frag_length - HEADER_LEN];
    stream.read_exact(&mut rest).expect("a response body");
    let mut out = header.to_vec();
    out.extend_from_slice(&rest);
    out
}

/// The skew recorded for the single event a run produced.
fn recorded_skew(driver: &Driver) -> Option<Duration> {
    let events = driver.server().host().events();
    assert_eq!(events.len(), 1, "one request, one event");
    events.iter().next().unwrap().clock_skew
}

/// **The regression test for `POL-020`.**
///
/// If `driver.rs` goes back to `host_time: None`, `clock_skew` goes back to
/// `None` and this fails. Nothing in `kmsrs-policy` can notice that, which is
/// why the check lives here.
#[test]
fn the_driver_gives_the_gate_a_host_clock() {
    let driver = activate_against(server_offset_from_client(Some(0)));
    assert_eq!(
        recorded_skew(&driver),
        Some(Duration::ZERO),
        "the event log must carry a measured skew, not a missing one — a `None` \
         here means driver.rs stopped passing the host's wall clock (POL-020, #346)"
    );
}

/// A host with no wall clock reports no skew rather than a fabricated zero.
///
/// The other half of the same property: `None` must still be reachable and must
/// still mean "this platform has no clock", or the field would be untrustworthy
/// on the target it exists for (`OS-007`, #258).
#[test]
fn a_host_without_a_wall_clock_records_no_skew() {
    let driver = activate_against(server_offset_from_client(None));
    assert_eq!(recorded_skew(&driver), None);
}

/// A clock inside the tolerance is measured and reported all the same
/// (`POL-011`, #99: "logged either way").
#[test]
fn a_skew_inside_the_tolerance_is_still_measured() {
    let inside = i64::try_from(CLOCK_SKEW_TOLERANCE.as_secs()).unwrap() - 60;
    let driver = activate_against(server_offset_from_client(Some(inside)));
    assert_eq!(
        recorded_skew(&driver),
        Some(Duration::from_secs(inside.unsigned_abs()))
    );
}

/// Skew is a distance, so a client in the past and a client in the future the
/// same way out are the same measurement.
#[test]
fn skew_is_symmetric_about_the_host_clock() {
    let hour = 3_600;
    let ahead = activate_against(server_offset_from_client(Some(hour)));
    let behind = activate_against(server_offset_from_client(Some(-hour)));
    assert_eq!(recorded_skew(&ahead), Some(Duration::from_hours(1)));
    assert_eq!(recorded_skew(&behind), recorded_skew(&ahead));
}

/// **The build flag decides what a badly skewed client gets** (`POL-011`, #99).
///
/// One test rather than a `cfg` pair, and deliberately so. A `#[cfg(feature)]`
/// test only exists in the build that enables the feature, which means the
/// *other* build proves nothing — and proving nothing is exactly the state
/// `POL-020` found this in. Branching on `REFUSE_CLOCK_SKEW` instead means both
/// halves of the powerset run this body and each asserts its own outcome, so
/// the two builds are shown to differ rather than assumed to.
///
/// It also means `kmsrs-server` needs no pass-through feature. The flag belongs
/// to `kmsrs-policy`; a second declaration of it here would be a second knob
/// (`CFG-009`, #174).
#[test]
fn the_build_flag_decides_what_a_badly_skewed_client_gets() {
    use kmsrs_policy::events::Outcome;
    use kmsrs_policy::gate::{REFUSE_CLOCK_SKEW, Refusal};

    let outside = i64::try_from(CLOCK_SKEW_TOLERANCE.as_secs()).unwrap() + 3_600;
    let driver = activate_against(server_offset_from_client(Some(outside)));
    let events = driver.server().host().events();
    let event = events.iter().next().unwrap();

    // `POL-011` (#99): "logged either way". True in both builds, and the part
    // that was silently false while the driver passed `None`.
    assert!(
        event.clock_skew.unwrap() > CLOCK_SKEW_TOLERANCE,
        "the skew is measured and outside the band in either build"
    );

    if REFUSE_CLOCK_SKEW {
        assert!(
            matches!(event.outcome, Outcome::Refused(Refusal::ClockSkew { .. })),
            "the strict build refuses it: {:?}",
            event.outcome
        );
    } else {
        // Refusing is the opt-in, because the tolerance band is itself a
        // detection oracle: a host that refuses at exactly ±4 hours tells a
        // prober where the edge is in two packets.
        assert!(
            matches!(event.outcome, Outcome::Activated(_)),
            "the default build activates it anyway: {:?}",
            event.outcome
        );
    }
}

/// Both builds activate a client inside the band, so `strict-clock-skew` is a
/// tolerance and not a switch that turns activation off.
#[test]
fn either_build_activates_a_client_inside_the_band() {
    use kmsrs_policy::events::Outcome;

    let inside = i64::try_from(CLOCK_SKEW_TOLERANCE.as_secs()).unwrap() - 60;
    let driver = activate_against(server_offset_from_client(Some(inside)));
    let events = driver.server().host().events();
    let event = events.iter().next().unwrap();

    assert!(
        matches!(event.outcome, Outcome::Activated(_)),
        "inside the band is still an activation: {:?}",
        event.outcome
    );
}

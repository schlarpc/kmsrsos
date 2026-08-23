//! The driver, over real sockets (`NET-004`…`NET-008`, `NET-012`).
//!
//! Everything here binds a real ephemeral port on loopback and speaks to it
//! with a real `TcpStream`, because the properties under test — that a refused
//! connection closes rather than queues, that a partial write is completed,
//! that shutdown drains — are properties of the socket layer and cannot be
//! observed from above it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_pass_by_value,
    reason = "test code: a failed expectation should abort loudly"
)]

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use kmsrs_policy::access::{AccessList, RateLimiter, Rule};
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::Instant;
use kmsrs_proto::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
use kmsrs_server::config::operational::LogLevel;
use kmsrs_server::net::driver::Driver;
use kmsrs_server::net::listener::bind_each;
use kmsrs_server::{Compiled, Discovered, Operational, Server};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use zerocopy::{FromBytes, IntoBytes};

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

fn kms_payload(machine: u32) -> Vec<u8> {
    let mut bytes = [0_u8; REQUEST_BODY_LEN];
    let mut body = RequestBody::read_from_bytes(&bytes).unwrap();
    body.version
        .set(Version::V6.to_protocol_version().to_wire());
    body.required_clients.set(25);
    body.client_time.set(133_000_000_000_000_000);
    body.application_id.data1.set(0x55c9_2734);
    body.kms_counted_id.data1.set(0x907f_1f65);
    body.client_machine_id.data1.set(machine);
    bytes.copy_from_slice(body.as_bytes());
    let body = RequestBody::read_from_bytes(&bytes).unwrap();

    let mut entropy = DeterministicEntropy::from_seed(0xC0DE);
    let mut stub = vec![0_u8; 512];
    let len = framing::encode_request(Version::V6, &body, &Ciphers::new(), &mut entropy, &mut stub)
        .unwrap();
    stub.truncate(len);
    stub
}

/// A clock the test drives, so deadlines are reachable.
///
/// Every reading advances by `step`, which is what makes `READ_TIMEOUT` and
/// `CONNECTION_DEADLINE` testable at all: under the previous 1 ms-per-call
/// clock neither was reachable, so both were entirely uncovered
/// (`OS-014`, #297).
struct TestClock {
    nanos: AtomicU64,
    step: u64,
}

impl TestClock {
    /// A clock that barely moves, for tests that are not about deadlines.
    fn still() -> Self {
        Self {
            nanos: AtomicU64::new(1_000_000),
            step: 0,
        }
    }

    /// A clock that advances `seconds` per reading.
    fn stepping(seconds: u64) -> Self {
        Self {
            nanos: AtomicU64::new(1_000_000),
            step: seconds.saturating_mul(1_000_000_000),
        }
    }

    fn now(&self) -> Instant {
        Instant::from_nanos(self.nanos.fetch_add(self.step, Ordering::AcqRel))
    }
}

fn test_server() -> Server {
    let mut entropy = DeterministicEntropy::from_seed(0x11_22_33_44);
    Server::new(
        Compiled::BUILD,
        quiet(),
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap()
}

/// A server that does not log, so the test output stays readable. The logging
/// itself is covered in `tests/logging.rs`.
fn quiet() -> Operational {
    Operational {
        log_level: LogLevel::Error,
        ..Operational::default()
    }
}

/// Run a driver on loopback for the duration of `body`, then stop it.
///
/// Returns the driver, so a test can inspect the server afterwards.
fn with_driver<T>(
    limit: usize,
    server: Server,
    clock: TestClock,
    body: impl FnOnce(SocketAddr) -> T,
) -> (T, Driver) {
    let (bound, _) = bind_each(&[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)]).unwrap();
    let address = bound[0].address;
    let mut driver = Driver::new(server, bound, limit).unwrap();
    let shutdown = driver.shutdown_handle();

    std::thread::scope(|scope| {
        let clock_ref = &clock;
        let handle = scope.spawn(move || {
            let mut entropy = DeterministicEntropy::from_seed(0x5A17);
            driver.run(&mut entropy, &|| clock_ref.now()).unwrap();
            driver
        });

        let result = body(address);
        shutdown.request();
        let driver = handle.join().expect("the loop stopped cleanly");
        (result, driver)
    })
}

/// The common case: a default server, a clock that does not move.
fn with_server<T>(limit: usize, body: impl FnOnce(SocketAddr) -> T) -> T {
    with_driver(limit, test_server(), TestClock::still(), body).0
}

/// Read a whole RPC PDU: the 16-byte header, then `frag_length - 16` more.
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

/// The headline: a real client over a real socket binds and activates.
#[test]
fn a_real_client_binds_and_activates_over_tcp() {
    with_server(8, |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

        stream
            .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
            .unwrap();
        let bind_ack = read_pdu(&mut stream);
        assert_eq!(
            bind_ack[2], 12,
            "the reply to a bind is a bind_ack, not {}",
            bind_ack[2]
        );

        stream
            .write_all(&pdu(PacketType::Request, 3, &request_body(&kms_payload(1))))
            .unwrap();
        let response = read_pdu(&mut stream);
        assert_eq!(response[2], 2, "the reply to a request is a response");
        assert!(
            response.len() > HEADER_LEN + 100,
            "a v6 response carries an ePID and a trailer, got {} bytes",
            response.len()
        );
    });
}

/// Several clients at once, each getting its own answer.
#[test]
fn concurrent_clients_are_all_served() {
    with_server(16, |address| {
        std::thread::scope(|scope| {
            for machine in 1..=8_u32 {
                scope.spawn(move || {
                    let mut stream = TcpStream::connect(address).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    stream
                        .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
                        .unwrap();
                    read_pdu(&mut stream);
                    stream
                        .write_all(&pdu(
                            PacketType::Request,
                            3,
                            &request_body(&kms_payload(machine)),
                        ))
                        .unwrap();
                    let response = read_pdu(&mut stream);
                    assert_eq!(response[2], 2, "client {machine} got no response");
                });
            }
        });
    });
}

/// `NET-006` (#156): a request delivered one byte at a time is still answered.
/// A driver that assumed one read per PDU would hang here.
#[test]
fn a_request_dribbled_one_byte_at_a_time_is_answered() {
    with_server(8, |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

        for byte in pdu(PacketType::Bind, 2, &bind_body()) {
            stream.write_all(&[byte]).unwrap();
            stream.flush().unwrap();
        }
        let bind_ack = read_pdu(&mut stream);
        assert_eq!(bind_ack[2], 12);

        for byte in pdu(PacketType::Request, 3, &request_body(&kms_payload(2))) {
            stream.write_all(&[byte]).unwrap();
            stream.flush().unwrap();
        }
        let response = read_pdu(&mut stream);
        assert_eq!(response[2], 2, "a dribbled request went unanswered");
    });
}

/// Two PDUs arriving in one read must both be handled — the driver loops until
/// the state machine says it needs more, rather than assuming one per read.
#[test]
fn two_pdus_in_one_write_are_both_answered() {
    with_server(8, |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

        let mut both = pdu(PacketType::Bind, 2, &bind_body());
        both.extend_from_slice(&pdu(PacketType::Request, 3, &request_body(&kms_payload(3))));
        stream.write_all(&both).unwrap();

        let bind_ack = read_pdu(&mut stream);
        assert_eq!(bind_ack[2], 12);
        let response = read_pdu(&mut stream);
        assert_eq!(response[2], 2, "the second PDU was dropped");
    });
}

/// `NET-005` (#154): beyond the pool, a connection is closed at once rather
/// than queued. The test holds every slot open, then asserts a further
/// connection gets end-of-stream instead of waiting out a timeout.
#[test]
fn a_connection_beyond_the_pool_is_closed_not_queued() {
    with_server(2, |address| {
        // Two connections that bind and then hold, occupying both slots.
        let mut held = Vec::new();
        for _ in 0..2 {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream
                .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
                .unwrap();
            read_pdu(&mut stream);
            held.push(stream);
        }

        // The third gets accepted and immediately closed. A queueing server
        // would leave this read blocking until a slot freed.
        let mut extra = TcpStream::connect(address).unwrap();
        extra
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        extra
            .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
            .ok();

        let mut buffer = [0_u8; 64];
        let outcome = extra.read(&mut buffer);
        match outcome {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("expected an immediate close, got {other:?}"),
        }

        // And the held connections still work, so refusing the third did not
        // disturb them.
        for (index, stream) in held.iter_mut().enumerate() {
            stream
                .write_all(&pdu(
                    PacketType::Request,
                    4,
                    &request_body(&kms_payload(100 + u32::try_from(index).unwrap())),
                ))
                .unwrap();
            let response = read_pdu(stream);
            assert_eq!(response[2], 2, "held connection {index} broke");
        }
    });
}

/// `NET-007` (#157): shutdown wakes a blocked accept and drains. `with_server`
/// asserts the join succeeds for every test in this file; this one makes the
/// property the subject rather than a side effect.
#[test]
fn shutdown_wakes_a_blocked_poll() {
    // Nothing ever connects, so the loop is parked in `poll` with no
    // connections and a full-length timeout. Shutdown must still return
    // promptly — which is what `mio`'s `Waker` is for (`NET-008`, #158). The
    // previous design woke a blocked `accept()` by connecting to its own
    // listener, which assumed a loopback route (`OS-015`, #298).
    let ((), driver) = with_driver(8, test_server(), TestClock::still(), |_address| {});
    assert_eq!(driver.in_flight(), 0);
}

#[test]
fn the_recorded_peer_is_normalised() {
    let ((), driver) = with_driver(8, test_server(), TestClock::still(), |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream
            .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
            .unwrap();
        read_pdu(&mut stream);
        stream
            .write_all(&pdu(PacketType::Request, 3, &request_body(&kms_payload(7))))
            .unwrap();
        read_pdu(&mut stream);
    });

    let event = driver
        .server()
        .host()
        .events()
        .iter()
        .next_back()
        .expect("the activation was logged");
    let peer = event.peer.expect("with its peer");
    assert_eq!(
        peer.address,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "a loopback client must be recorded as 127.0.0.1"
    );
    assert!(peer.address.is_ipv4(), "not as an IPv4-mapped IPv6 address");
}

/// `POL-012` (#100): a slowloris does not exhaust capacity.
///
/// The attack is connections that open and then never send a complete request,
/// each holding a worker for as long as the server will wait. vlmcsd is
/// vulnerable to it by design — its `-m` queues rather than refuses, so its own
/// manual recommends a short timeout as the entire mitigation. py-kms has no
/// worker cap and no timeout at all.
///
/// Here the pool refuses at accept, so a slowloris can occupy at most the pool
/// and no more — and the connections it does hold are bounded by the
/// connection deadline. What this test proves is the part that matters
/// operationally: **the server stays responsive to everything except the
/// attacker's own share.**
#[test]
fn a_slowloris_cannot_take_more_than_its_share() {
    with_server(4, |address| {
        // Three connections that open, send one byte of a PDU header, and then
        // go quiet. A complete PDU never arrives, so the state machine keeps
        // waiting for more.
        let mut attackers = Vec::new();
        for _ in 0..3 {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&[0x05]).unwrap();
            stream.flush().unwrap();
            attackers.push(stream);
        }

        // The fourth slot is still there, and a real client gets a real answer
        // through it while all three attackers are still connected.
        let mut honest = TcpStream::connect(address).unwrap();
        honest.set_read_timeout(Some(Duration::from_secs(10))).ok();
        honest
            .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
            .unwrap();
        let bind_ack = read_pdu(&mut honest);
        assert_eq!(bind_ack[2], 12, "the honest client could not bind");

        honest
            .write_all(&pdu(
                PacketType::Request,
                3,
                &request_body(&kms_payload(42)),
            ))
            .unwrap();
        let response = read_pdu(&mut honest);
        assert_eq!(
            response[2], 2,
            "the honest client was starved by the slowloris"
        );

        // The attackers are still holding their sockets — the point is that it
        // did not matter.
        assert_eq!(attackers.len(), 3);
    });
}

/// `POL-013` (#101): a denied peer is closed before the RPC handshake, so it
/// never reaches the parser.
#[test]
fn a_denied_peer_never_reaches_the_protocol() {
    // Deny loopback, which is where the test client connects from.
    const DENY: &[Rule] = &[
        Rule::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Rule::Address(IpAddr::V6(core::net::Ipv6Addr::LOCALHOST)),
    ];
    let mut compiled = Compiled::BUILD;
    compiled.access = AccessList {
        allow: &[],
        deny: DENY,
    };

    let mut entropy = DeterministicEntropy::from_seed(0x11_22_33_44);
    let server = Server::new(
        compiled,
        quiet(),
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap();

    let ((), driver) = with_driver(8, server, TestClock::still(), |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // The bind may or may not reach the socket buffer before the close;
        // either way there must be no reply.
        let _ = stream.write_all(&pdu(PacketType::Bind, 2, &bind_body()));

        let mut buffer = [0_u8; 64];
        match stream.read(&mut buffer) {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("a denied peer got a reply: {other:?}"),
        }
    });

    // Nothing reached the protocol, so nothing was activated or refused — a
    // denial happens before there is a request to have an opinion about.
    assert_eq!(
        driver.server().host().events().len(),
        0,
        "a denied peer produced a protocol-level event"
    );
}

/// And the default build lets that same client straight through, so the test
/// above is about the rule rather than about loopback being special.
#[test]
fn the_default_build_admits_everyone() {
    assert!(
        Compiled::BUILD.access.is_open(),
        "the shipped build must permit everything"
    );
    with_server(4, |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream
            .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
            .unwrap();
        assert_eq!(read_pdu(&mut stream)[2], 12);
    });
}

/// `POL-014` (#102): a source that exceeds its budget is cut off, and the
/// connections it already had keep working until then.
///
/// The burst is set to two here; the shipped value is 240, because a whole
/// site behind NAT is one source address and a limit tuned for one machine
/// would refuse a legitimate office (see `access::BURST`).
#[test]
fn a_source_over_its_budget_is_rate_limited() {
    let server = test_server().with_limiter(RateLimiter::with(2, 1));
    // A clock that does not advance, so no tokens are earned back mid-test.
    let (counts, driver) = with_driver(8, server, TestClock::still(), |address| {
        let mut answered = 0_u32;
        let mut cut_off = 0_u32;
        for _ in 0..6 {
            let Ok(mut stream) = TcpStream::connect(address) else {
                continue;
            };
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            if stream
                .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
                .is_err()
            {
                cut_off += 1;
                continue;
            }
            let mut header = [0_u8; HEADER_LEN];
            match stream.read_exact(&mut header) {
                Ok(()) => answered += 1,
                Err(_) => cut_off += 1,
            }
        }
        (answered, cut_off)
    });

    assert_eq!(counts.0, 2, "exactly the budget was served");
    assert!(counts.1 >= 1, "and the rest were cut off");

    // One source, since every connection came from loopback.
    assert_eq!(driver.server().limiter().tracked(), 1);
}

/// The client-side framing in `kmsrs-proto` talks to this server
/// (`WIRE-027`, #85; `CLI-001`, #207).
///
/// The other tests in this file build PDUs by hand, which proves the server
/// accepts *those* bytes. This proves the two halves of the protocol crate
/// agree with each other, which is the thing a diagnostic client depends on.
#[test]
fn the_protocol_crates_own_client_can_activate() {
    use kmsrs_proto::wire::client::{ClientAssociation, Reply};
    use kmsrs_proto::wire::syntax::TransferSyntax;

    with_server(8, |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

        let mut association = ClientAssociation::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut out = [0_u8; 4096];

        // Bind, offering both syntaxes and feature negotiation.
        let (len, call_id) = association.bind(&mut out, true).unwrap();
        assert_eq!(call_id, 2, "Microsoft's client starts at 2");
        stream.write_all(&out[..len]).unwrap();

        let reply = read_pdu(&mut stream);
        let parsed = association
            .read_reply(&reply, call_id, TransferSyntax::Ndr32, &mut |warning| {
                warnings.push(warning.to_string());
            })
            .expect("the bind was accepted");
        let Reply::BindAck { accepted, .. } = parsed else {
            panic!("expected a bind_ack, got {parsed:?}");
        };
        // A host accepts exactly one syntax, and NDR64 wins when both are
        // offered (`WIRE-029`, #87) — so the context to use comes from the
        // acknowledgement, never from an assumption.
        let accepted = accepted.expect("the server accepted a context");
        assert_eq!(accepted.syntax, TransferSyntax::Ndr64);

        // Activate, on the context the server actually accepted.
        let (len, call_id) = association
            .request(
                &mut out,
                accepted.context_id,
                accepted.syntax,
                &kms_payload(77),
            )
            .unwrap();
        assert_eq!(call_id, 3, "and increments");
        stream.write_all(&out[..len]).unwrap();

        let reply = read_pdu(&mut stream);
        let parsed = association
            .read_reply(&reply, call_id, accepted.syntax, &mut |warning| {
                warnings.push(warning.to_string());
            })
            .expect("the request was answered");
        let Reply::Response { stub, result } = parsed else {
            panic!("expected a response, got {parsed:?}");
        };
        assert_eq!(result, 0, "the call returned an error HRESULT");
        assert!(
            stub.len() > 100,
            "a v6 response carries an ePID and a trailer, got {} bytes",
            stub.len()
        );

        // `CLI-002` (#208): our own server must produce no warnings at all.
        // That is the whole point of the client being the regression suite.
        assert!(
            warnings.is_empty(),
            "our own server tripped detection warnings: {warnings:?}"
        );
    });
}

/// `NET-004` (#153) and `OS-014` (#297): a connection that goes quiet is
/// closed when its read deadline passes.
///
/// **This is the test that could not exist before.** The deadline used to be
/// enforced by `SO_RCVTIMEO` where that worked and by a hand-written polling
/// fallback where it did not — and the fallback branch was never executed by
/// any test, on any platform, despite existing solely for the one platform
/// where the socket option fails. With the poller there is one path, and the
/// deadline is a pure function of the injected clock, so a test can simply
/// drive the clock to it.
#[test]
fn a_quiet_connection_is_closed_when_its_read_deadline_passes() {
    // Each clock reading advances 20 seconds, so `READ_TIMEOUT` (30 s) is
    // crossed within a couple of poll wakeups.
    let (outcome, driver) = with_driver(8, test_server(), TestClock::stepping(20), |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        // Say nothing at all, and wait to be hung up on.
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut buffer = [0_u8; 16];
        stream.read(&mut buffer)
    });

    match outcome {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("the connection was not closed on its deadline: {other:?}"),
    }
    assert_eq!(
        driver.in_flight(),
        0,
        "the expired connection was not forgotten"
    );
}

/// `NET-004` (#153): the total deadline bounds a connection that *is* making
/// progress, which the read deadline alone cannot.
///
/// A slowloris that sends one byte just inside every read timeout resets the
/// idle deadline forever. Here the client dribbles bytes steadily while the
/// clock advances, and the connection is closed anyway once
/// `CONNECTION_DEADLINE` passes.
#[test]
fn a_dribbling_connection_is_closed_when_its_total_deadline_passes() {
    // 10 seconds per reading: under `READ_TIMEOUT` each time, so the idle
    // deadline keeps being reset, but past `CONNECTION_DEADLINE` (2 min) within
    // a dozen or so wakeups.
    let (outcome, driver) = with_driver(8, test_server(), TestClock::stepping(10), |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        // Dribble one byte at a time, never completing a PDU, until the server
        // hangs up.
        for _ in 0..2_000 {
            if stream.write_all(&[0x05]).is_err() {
                return Ok(0);
            }
            let mut buffer = [0_u8; 16];
            match stream.read(&mut buffer) {
                Ok(0) => return Ok(0),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
                other => return other,
            }
        }
        Err(std::io::Error::other("never closed"))
    });

    match outcome {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("a dribbling connection outlived its total deadline: {other:?}"),
    }
    assert_eq!(driver.in_flight(), 0);
}

/// A connection that is doing real work is *not* closed while it works — the
/// deadline tests above would pass trivially if the loop simply hung up on
/// everything.
#[test]
fn an_active_connection_survives_a_moving_clock() {
    with_driver(8, test_server(), TestClock::stepping(5), |address| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

        stream
            .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
            .unwrap();
        assert_eq!(read_pdu(&mut stream)[2], 12);

        // Several activations, each well inside the read deadline.
        for machine in 1..=4_u32 {
            stream
                .write_all(&pdu(
                    PacketType::Request,
                    machine + 2,
                    &request_body(&kms_payload(machine)),
                ))
                .unwrap();
            assert_eq!(
                read_pdu(&mut stream)[2],
                2,
                "request {machine} was cut off while active"
            );
        }
    });
}

/// `WIRE-011` (#69): with two listeners, each `bind_ack` advertises the port of
/// the socket that **actually accepted** — not a configured constant.
///
/// py-kms echoes its configured primary port regardless of which listener took
/// the connection, so a client that reconnects to the advertised endpoint can
/// be sent somewhere the host is not listening.
#[test]
fn each_listener_advertises_its_own_port() {
    // Two listeners on two ephemeral ports, so the ports genuinely differ and
    // neither is the compiled-in 1688.
    let (bound, _) = bind_each(&[
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    ])
    .unwrap();
    assert_eq!(bound.len(), 2, "two listeners were needed");
    let first = bound[0].address;
    let second = bound[1].address;
    assert_ne!(first.port(), second.port());

    let mut driver = Driver::new(test_server(), bound, 8).unwrap();
    let shutdown = driver.shutdown_handle();
    let clock = TestClock::still();

    std::thread::scope(|scope| {
        let clock_ref = &clock;
        let handle = scope.spawn(move || {
            let mut entropy = DeterministicEntropy::from_seed(0x5A17);
            driver.run(&mut entropy, &|| clock_ref.now()).unwrap();
        });

        let result = std::panic::catch_unwind(|| {
            for address in [first, second] {
                let advertised = advertised_endpoint(address);
                assert_eq!(
                    advertised,
                    address.port().to_string(),
                    "the listener on {} advertised {advertised}",
                    address.port()
                );
            }
        });

        shutdown.request();
        handle.join().unwrap();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    });
}

/// Bind to `address` and read back the secondary address from the `bind_ack`.
fn advertised_endpoint(address: SocketAddr) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream
        .write_all(&pdu(PacketType::Bind, 2, &bind_body()))
        .unwrap();
    let reply = read_pdu(&mut stream);

    // The bind_ack body is: max_xmit u16, max_recv u16, assoc_group u32, then a
    // counted secondary address including its terminating NUL.
    let body = &reply[HEADER_LEN..];
    let len = usize::from(u16::from_le_bytes([body[8], body[9]]));
    assert!(len > 0, "a bind_ack must advertise an endpoint");
    let text = &body[10..10 + len];
    assert_eq!(
        text.last(),
        Some(&0),
        "the advertised port is NUL-terminated"
    );
    String::from_utf8_lossy(&text[..len - 1]).into_owned()
}

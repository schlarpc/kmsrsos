//! The web UI, served over a real socket, from the same loop as KMS
//! (`OBS-014`, #190; `OBS-008`, #184).
//!
//! # Why this exists alongside the in-module tests
//!
//! `web::routes` renders pages and `web::request` parses requests, and both are
//! tested where they live. Neither says anything about whether a browser gets a
//! page — for that, the listener has to be bound with the right role, the
//! driver has to recognise it, and the same flush loop that writes a KMS
//! response has to write an HTTP one.
//!
//! That wiring is where a second server would have gone. There isn't one: the
//! web UI is another listener on the one mio loop, so the deadline, the
//! capacity check, the outbound ceiling and the shutdown are each written once
//! and apply to both. Two loops would mean two places for each of those to be
//! got right, which is the argument `ARCH-005` (#5) already settled once.
//!
//! # And why the budget is shared
//!
//! `OBS-014` says the web server must never be able to starve the KMS listener.
//! Two independent limits would make the host's real ceiling their sum — a
//! number nobody wrote down. One budget with a share means the ceiling is
//! `MAX_CONNECTIONS` whatever arrives, and the web UI can hold at most a
//! quarter of it.

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
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::time::Instant;
use kmsrs_server::config::operational::{LogFormat, LogLevel};
use kmsrs_server::net::driver::{Driver, MAX_CONNECTIONS, Role};
use kmsrs_server::net::listener::bind_each;
use kmsrs_server::{Compiled, Discovered, Operational, Server};
use std::io::{Read as _, Write as _};
use std::net::TcpStream;

/// A logger that says nothing, so a test run is readable.
fn quiet() -> Operational {
    Operational {
        log_level: LogLevel::Error,
        log_format: LogFormat::Text,
        ..Operational::default()
    }
}

fn test_server() -> Server {
    let mut entropy = DeterministicEntropy::from_seed(0x0B5_0190);
    Server::new(
        Compiled::BUILD,
        quiet(),
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap()
}

/// Run a loop with one KMS listener and one web listener, and hand both
/// addresses to the body.
fn with_web<T>(limit: usize, body: impl FnOnce(SocketAddr, SocketAddr) -> T) -> T {
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (kms_bound, _) = bind_each(&[loopback]).unwrap();
    let (web_bound, _) = bind_each(&[loopback]).unwrap();
    let kms_address = kms_bound[0].address;
    let web_address = web_bound[0].address;

    let listeners: Vec<_> = kms_bound
        .into_iter()
        .map(|entry| (entry, Role::Kms))
        .chain(web_bound.into_iter().map(|entry| (entry, Role::Web)))
        .collect();

    let mut driver = Driver::with_roles(test_server(), listeners, limit, true).unwrap();
    let shutdown = driver.shutdown_handle();

    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let mut entropy = DeterministicEntropy::from_seed(0x5A17_0190);
            driver
                .run(&mut entropy, &|| Instant::from_nanos(0))
                .unwrap();
        });

        // A panic inside a scope deadlocks the join, turning a failed
        // assertion into a silent hang. Catching and re-raising keeps the
        // failure legible.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            body(kms_address, web_address)
        }));
        shutdown.request();
        handle.join().expect("the loop stopped cleanly");
        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

/// Fetch a path and return the whole response as text.
fn fetch(address: SocketAddr, target: &str) -> String {
    fetch_raw(
        address,
        &format!("GET {target} HTTP/1.1\r\nHost: k\r\n\r\n"),
    )
}

/// Send an arbitrary request and read until the peer closes.
fn fetch_raw(address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();

    let mut out = Vec::new();
    // Every response says `Connection: close`, so reading to EOF is the whole
    // response and needs no length parsing.
    stream.read_to_end(&mut out).unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn every_route_is_served_over_a_socket() {
    with_web(16, |_kms, web| {
        for target in [
            "/",
            "/events",
            "/instructions",
            "/products",
            "/healthz",
            "/metrics",
        ] {
            let response = fetch(web, target);
            assert!(
                response.starts_with("HTTP/1.1 200 OK\r\n"),
                "{target} answered:\n{}",
                response.lines().next().unwrap_or("nothing at all")
            );
            assert!(
                response.contains("\r\n\r\n"),
                "{target} sent no complete head"
            );
        }
    });
}

#[test]
fn an_unknown_path_is_404_over_a_socket() {
    with_web(16, |_kms, web| {
        let response = fetch(web, "/wp-admin");
        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
    });
}

/// The refusal reaches the wire as a constant, and the reason reaches the log
/// (`OBS-009`, #185).
#[test]
fn a_refused_request_is_answered_with_a_status_and_nothing_else() {
    with_web(16, |_kms, web| {
        for (request, expected) in [
            ("POST / HTTP/1.1\r\nHost: k\r\n\r\n", "405"),
            ("GET / HTTP/9.9\r\nHost: k\r\n\r\n", "505"),
            (
                "GET / HTTP/1.1\r\nHost: k\r\nContent-Length: 9\r\n\r\n",
                "413",
            ),
            ("GET http://x/ HTTP/1.1\r\nHost: k\r\n\r\n", "400"),
        ] {
            let response = fetch_raw(web, request);
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected} ")),
                "expected {expected}, got:\n{}",
                response.lines().next().unwrap_or("nothing")
            );
            for secret in ["/nix/store", "/home/", ".rs:", "panicked"] {
                assert!(!response.contains(secret), "{expected} leaked {secret}");
            }
        }
    });
}

/// A request split across several writes is assembled, not answered early.
#[test]
fn a_request_arriving_in_pieces_is_assembled() {
    with_web(16, |_kms, web| {
        let mut stream = TcpStream::connect(web).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        for piece in ["GET /heal", "thz HTTP/1.1\r\n", "Host: k\r\n", "\r\n"] {
            stream.write_all(piece.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
        let mut out = Vec::new();
        stream.read_to_end(&mut out).unwrap();
        let response = String::from_utf8_lossy(&out);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.ends_with("ok\n"), "{response}");
    });
}

/// `OBS-012` (#188): a client that never finishes its head is closed rather
/// than buffered.
#[test]
fn a_head_that_never_ends_is_closed_rather_than_buffered() {
    with_web(16, |_kms, web| {
        let mut stream = TcpStream::connect(web).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\n").unwrap();

        // More than the head limit, in chunks, with no blank line ever.
        let chunk = vec![b'x'; 1024];
        let mut written = 0_usize;
        for _ in 0..64 {
            match stream.write_all(&chunk) {
                Ok(()) => written += chunk.len(),
                // The host closed, which is the point.
                Err(_) => break,
            }
        }
        assert!(written > 0, "nothing was sent at all");

        let mut out = Vec::new();
        // Either a 431 or a reset; both are refusals, and neither is the host
        // still holding the bytes.
        let _ = stream.read_to_end(&mut out);
        let response = String::from_utf8_lossy(&out);
        assert!(
            response.is_empty() || response.starts_with("HTTP/1.1 431 "),
            "a client that never finished its head got:\n{response}"
        );
    });
}

/// `OBS-014` (#190): both listeners are the same loop, so both work at once.
#[test]
fn the_kms_listener_still_answers_while_the_web_ui_is_being_used() {
    use kmsrs_proto::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
    use zerocopy::IntoBytes as _;

    const NDR32_WIRE: [u8; 16] = [
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48,
        0x60,
    ];
    const INTERFACE_WIRE: [u8; 16] = [
        0x75, 0x21, 0xC8, 0x51, 0x4E, 0x84, 0x50, 0x47, 0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC,
        0x06,
    ];

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

    with_web(16, |kms, web| {
        // A web request first, so the loop has definitely served one.
        assert!(fetch(web, "/healthz").starts_with("HTTP/1.1 200"));

        let mut stream = TcpStream::connect(kms).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let body = bind_body();
        let frag = u16::try_from(HEADER_LEN + body.len()).unwrap();
        let header = RpcHeader::for_reply(PacketType::Bind, PacketFlags::COMPLETE, 2, frag);
        let mut pdu = header.as_bytes().to_vec();
        pdu.extend_from_slice(&body);
        stream.write_all(&pdu).unwrap();

        let mut reply = [0_u8; HEADER_LEN];
        stream.read_exact(&mut reply).expect("a bind_ack");
        assert_eq!(
            reply[2], 12,
            "the KMS listener did not answer with a bind_ack"
        );

        // And the web UI still works afterwards.
        assert!(fetch(web, "/").starts_with("HTTP/1.1 200"));
    });
}

/// The share, checked as arithmetic rather than by opening a thousand sockets.
#[test]
fn the_web_ui_gets_a_share_of_the_budget_and_never_all_of_it() {
    for limit in [1_usize, 2, 4, 8, 100, MAX_CONNECTIONS] {
        let share = Driver::web_limit(limit);
        assert!(share >= 1, "a budget of {limit} left the web UI no slots");
        assert!(
            share <= limit,
            "the web share ({share}) exceeds the whole budget ({limit})"
        );
        // Three quarters is reserved for the thing this program is for. The
        // exception is a budget too small to divide, where one slot each is the
        // only sensible answer.
        assert!(
            limit < 4 || share * 4 <= limit,
            "a budget of {limit} gave the web UI {share}, which is more than a \
             quarter — a browser tab left open could cost a client its \
             activation"
        );
    }
}

/// `POL-013` (#101) applies to both listeners: the ACL is checked on accept,
/// before either protocol exists.
#[test]
fn the_access_list_is_checked_before_the_role_is_consulted() {
    use kmsrs_policy::access::{AccessList, Rule};

    const DENY: &[Rule] = &[
        Rule::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Rule::Address(IpAddr::V6(core::net::Ipv6Addr::LOCALHOST)),
    ];

    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (web_bound, _) = bind_each(&[loopback]).unwrap();
    let web_address = web_bound[0].address;

    let mut compiled = Compiled::BUILD;
    compiled.access = AccessList {
        allow: &[],
        deny: DENY,
    };
    let mut entropy = DeterministicEntropy::from_seed(0x0B5_0191);
    let server = Server::new(
        compiled,
        quiet(),
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap();

    let listeners: Vec<_> = web_bound.into_iter().map(|e| (e, Role::Web)).collect();
    let mut driver = Driver::with_roles(server, listeners, 8, true).unwrap();
    let shutdown = driver.shutdown_handle();

    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let mut entropy = DeterministicEntropy::from_seed(0x5A17_0191);
            driver
                .run(&mut entropy, &|| Instant::from_nanos(0))
                .unwrap();
        });

        let result = std::panic::catch_unwind(|| {
            let mut stream = TcpStream::connect(web_address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _ = stream.write_all(b"GET / HTTP/1.1\r\nHost: k\r\n\r\n");

            let mut out = Vec::new();
            let _ = stream.read_to_end(&mut out);
            assert!(
                out.is_empty(),
                "a denied peer was served a page: {}",
                String::from_utf8_lossy(&out)
            );
        });
        shutdown.request();
        handle.join().expect("the loop stopped cleanly");
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    });
}

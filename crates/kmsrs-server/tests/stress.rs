//! Concurrency and exhaustion, under load (`TEST-010`, #231; `TEST-011`, #232).
//!
//! # What changed about "concurrency" here
//!
//! `TEST-010` was written when the plan was thread-per-connection, and asks for
//! a thread sanitizer. The driver is now a **single mio event loop**
//! (`ARCH-005`, #5), so there is no concurrency inside the request path at all
//! — no locks, no shared mutable state between requests, nothing for a data
//! race to happen to.
//!
//! That does not make the issue moot; it relocates it. Two real questions
//! remain, and both are exercised here:
//!
//! * **Cross-*connection* leakage.** The loop multiplexes many connections
//!   through one `Server`, so a value belonging to one connection reaching
//!   another is still entirely possible — it is now an aliasing bug in a map
//!   rather than a data race, which no sanitizer would catch anyway.
//! * **The one genuine cross-thread edge**: `ShutdownHandle` is an `AtomicBool`
//!   plus a `mio::Waker`, touched from a signal handler or another thread while
//!   the loop is parked in `poll`.
//!
//! A thread sanitizer is not run: `-Zsanitizer=thread` needs nightly and the
//! toolchain is pinned to stable 1.96.1 (`ARCH-016`). The substitute is volume
//! — many interleaved clients whose every field identifies its sender, so a
//! leak is *detected* rather than merely improbable.

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
use kmsrs_db::Guid;
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody, WireGuid};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::wire::client::{ClientAssociation, Reply};
use kmsrs_proto::wire::header::HEADER_LEN;
use kmsrs_proto::wire::syntax::TransferSyntax;
use kmsrs_server::config::operational::LogLevel;
use kmsrs_server::net::driver::{Driver, MAX_CONNECTIONS};
use kmsrs_server::net::listener::bind_each;
use kmsrs_server::{Compiled, Discovered, Operational, Server};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use zerocopy::{FromBytes, IntoBytes};

fn test_server() -> Server {
    let mut entropy = DeterministicEntropy::from_seed(0x5735_5555);
    Server::new(
        Compiled::BUILD,
        Operational {
            log_level: LogLevel::Error,
            ..Operational::default()
        },
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap()
}

/// Run the driver for the duration of `body`, panic-safely.
fn with_driver<T>(limit: usize, body: impl FnOnce(SocketAddr) -> T) -> (T, Driver) {
    let (bound, _) = bind_each(&[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)]).unwrap();
    let address = bound[0].address;
    let mut driver = Driver::new(
        test_server(),
        bound,
        limit,
        Box::new(DeterministicEntropy::from_seed(0x5A17)),
    )
    .unwrap();
    let shutdown = driver.shutdown_handle();

    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            // The driver is async now (`OS-024`, #340), but everything a test
            // body does is blocking loopback I/O. So the driver gets a
            // current-thread runtime of its own on this thread and the bodies
            // below are unchanged.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime for the driver thread");
            runtime.block_on(driver.run()).unwrap();
            driver
        });

        // A panic in the body must not leave the loop running, or the scope
        // deadlocks on join and a failed assertion becomes a silent hang.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(address)));
        shutdown.request();
        let driver = handle.join().expect("the loop stopped cleanly");

        match result {
            Ok(value) => (value, driver),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

/// A KMS payload whose machine ID and workstation name both encode `client`.
fn payload(client: u32) -> Vec<u8> {
    let mut bytes = [0_u8; REQUEST_BODY_LEN];
    let mut body = RequestBody::read_from_bytes(&bytes).unwrap();
    body.version
        .set(Version::V6.to_protocol_version().to_wire());
    body.required_clients.set(25);
    body.client_time.set(133_000_000_000_000_000);
    body.application_id.data1.set(0x55c9_2734);
    body.kms_counted_id.data1.set(0x907f_1f65);
    // The machine ID is the whole identity, so a leak is unambiguous.
    let mut machine = [0_u8; 16];
    machine[..4].copy_from_slice(&client.to_be_bytes());
    body.client_machine_id = WireGuid::from_guid(Guid::from_bytes(machine));

    let name = format!("client-{client}");
    for (slot, unit) in body.workstation_name.iter_mut().zip(name.encode_utf16()) {
        slot.set(unit);
    }
    bytes.copy_from_slice(body.as_bytes());
    let body = RequestBody::read_from_bytes(&bytes).unwrap();

    let mut entropy = DeterministicEntropy::from_seed(u64::from(client).wrapping_add(1));
    let mut stub = vec![0_u8; 1024];
    let len = framing::encode_request(Version::V6, &body, &Ciphers::new(), &mut entropy, &mut stub)
        .unwrap();
    stub.truncate(len);
    stub
}

/// One client: connect, bind, activate, and check its own answer.
fn activate_once(address: SocketAddr, client: u32) -> Result<(), String> {
    let mut stream =
        TcpStream::connect(address).map_err(|error| format!("client {client}: {error}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();

    let mut association = ClientAssociation::new();
    let mut out = vec![0_u8; 4096];

    let (len, call_id) = association
        .bind(&mut out, true)
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&out[..len])
        .map_err(|error| format!("client {client}: {error}"))?;
    let reply = read_pdu(&mut stream).map_err(|error| format!("client {client}: {error}"))?;
    let Reply::BindAck { accepted, .. } = association
        .read_reply(&reply, call_id, TransferSyntax::Ndr32, &mut |_| {})
        .map_err(|e| e.to_string())?
    else {
        return Err(format!("client {client}: expected a bind_ack"));
    };
    let accepted = accepted.ok_or_else(|| format!("client {client}: no context accepted"))?;

    let (len, call_id) = association
        .request(
            &mut out,
            accepted.context_id,
            accepted.syntax,
            &payload(client),
        )
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&out[..len])
        .map_err(|error| format!("client {client}: {error}"))?;
    let reply = read_pdu(&mut stream).map_err(|error| format!("client {client}: {error}"))?;
    let Reply::Response { result, .. } = association
        .read_reply(&reply, call_id, accepted.syntax, &mut |_| {})
        .map_err(|e| e.to_string())?
    else {
        return Err(format!("client {client}: expected a response"));
    };
    if result != 0 {
        return Err(format!("client {client}: HRESULT 0x{result:08X}"));
    }
    Ok(())
}

fn read_pdu(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0_u8; HEADER_LEN];
    stream.read_exact(&mut header)?;
    let frag = usize::from(u16::from_le_bytes([header[8], header[9]]));
    let mut rest = vec![0_u8; frag - HEADER_LEN];
    stream.read_exact(&mut rest)?;
    let mut pdu = header.to_vec();
    pdu.extend_from_slice(&rest);
    Ok(pdu)
}

/// `TEST-010` (#231): no cross-request state leakage, and the event log's
/// ordering survives the load.
///
/// Every client's machine ID and workstation name encode its own number, so a
/// value belonging to one connection reaching another is *detected* rather than
/// merely improbable.
#[test]
fn many_interleaved_clients_do_not_leak_into_each_other() {
    const CLIENTS: u32 = 120;

    let ((), driver) = with_driver(MAX_CONNECTIONS, |address| {
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for client in 1..=CLIENTS {
                handles.push(scope.spawn(move || activate_once(address, client)));
            }
            for handle in handles {
                handle
                    .join()
                    .expect("no client panicked")
                    .expect("activated");
            }
        });
    });

    // `server()` hands back a guard now (`OS-024`, #340): the server lives
    // behind the mutex the driver's tasks share, so the borrow has to be named
    // rather than left as a temporary in the same expression.
    let server = driver.server();
    let events: Vec<_> = server.host().events().iter().collect();
    assert_eq!(
        events.len(),
        usize::try_from(CLIENTS).unwrap(),
        "every client should have produced exactly one event"
    );

    // Each event's machine ID and workstation name must agree with each other.
    // A leak pairs one client's identity with another's name.
    let mut seen = HashSet::new();
    for event in &events {
        let machine = event.client_machine_id.0.to_bytes();
        let client = u32::from_be_bytes([machine[0], machine[1], machine[2], machine[3]]);
        assert_eq!(
            event.workstation_name.as_str(),
            format!("client-{client}"),
            "machine {client} was paired with another client's name"
        );
        assert!(seen.insert(client), "client {client} was recorded twice");
        assert!((1..=CLIENTS).contains(&client), "unknown client {client}");
    }
    assert_eq!(seen.len(), usize::try_from(CLIENTS).unwrap());

    // `OBS-004` (#180): sequence numbers are dense, unique and in insertion
    // order, however the connections interleaved.
    let sequences: Vec<u64> = events.iter().map(|event| event.sequence).collect();
    let expected: Vec<u64> = (0..u64::from(CLIENTS)).collect();
    assert_eq!(sequences, expected, "the log lost its ordering under load");
}

/// `TEST-010` (#231): there is no shared cipher state to corrupt.
///
/// `Ciphers` expands its three key schedules once and is then immutable, so
/// encrypting is a pure function of its inputs. Checked by encrypting the same
/// request through one shared instance from many threads and asserting every
/// result is byte-identical to the single-threaded one.
#[test]
fn the_cipher_state_is_immutable_and_shared_safely() {
    let ciphers = Ciphers::new();
    let body = RequestBody::read_from_bytes(&[0_u8; REQUEST_BODY_LEN]).unwrap();

    let reference = {
        let mut entropy = DeterministicEntropy::from_seed(7);
        let mut out = vec![0_u8; 1024];
        let len =
            framing::encode_request(Version::V6, &body, &ciphers, &mut entropy, &mut out).unwrap();
        out.truncate(len);
        out
    };

    std::thread::scope(|scope| {
        for _ in 0..16 {
            let ciphers = &ciphers;
            let body = &body;
            let reference = &reference;
            scope.spawn(move || {
                for _ in 0..200 {
                    let mut entropy = DeterministicEntropy::from_seed(7);
                    let mut out = vec![0_u8; 1024];
                    let len =
                        framing::encode_request(Version::V6, body, ciphers, &mut entropy, &mut out)
                            .unwrap();
                    out.truncate(len);
                    assert_eq!(
                        &out, reference,
                        "the shared cipher produced a different result"
                    );
                }
            });
        }
    });
}

/// `TEST-011` (#232): idle connections must not exhaust capacity permanently.
///
/// The pool is filled entirely with connections that open and say nothing —
/// the slowloris shape. Capacity must come back once their deadlines pass, and
/// a legitimate client must then be served.
#[test]
fn idle_connections_do_not_exhaust_capacity_permanently() {
    const LIMIT: usize = 8;

    // This one waits out a real `READ_TIMEOUT` (`OS-024`, #340). It used to
    // drive a fake clock, but deadlines are tokio's now, and the paused clock
    // the other deadline tests use cannot help here: auto-advance fires
    // whenever the runtime is idle, and this test's client is blocking socket
    // I/O on another thread — so the jump that expires the idle connections
    // would expire the legitimate one too. Thirty seconds, honestly spent.
    let (served, driver) = with_driver(LIMIT, |address| {
        // Fill every slot with a connection that never sends anything.
        let mut idle = Vec::new();
        for _ in 0..LIMIT {
            if let Ok(stream) = TcpStream::connect(address) {
                idle.push(stream);
            }
        }
        assert_eq!(idle.len(), LIMIT, "the pool should have accepted them all");

        // Wait for the server to hang up on them, which is what proves the
        // capacity was reclaimed rather than merely never taken.
        for stream in &mut idle {
            stream.set_read_timeout(Some(Duration::from_secs(45))).ok();
            let mut buffer = [0_u8; 8];
            let _ = stream.read(&mut buffer);
        }
        drop(idle);

        activate_once(address, 1)
    });

    served.expect("a legitimate client was refused after the idle ones expired");
    assert_eq!(
        driver.in_flight(),
        0,
        "connections were still held after the test"
    );
}

/// `TEST-011` (#232): while the pool *is* full, a further connection is refused
/// promptly rather than queued — the client learns at once instead of waiting
/// out a timeout to discover it.
#[test]
fn a_full_pool_refuses_promptly_rather_than_queueing() {
    const LIMIT: usize = 4;

    let ((), _driver) = with_driver(LIMIT, |address| {
        let mut held = Vec::new();
        for _ in 0..LIMIT {
            held.push(TcpStream::connect(address).unwrap());
        }
        // Give the loop a moment to accept them all.
        std::thread::sleep(Duration::from_millis(50));

        let mut extra = TcpStream::connect(address).unwrap();
        extra
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buffer = [0_u8; 8];
        match extra.read(&mut buffer) {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("expected an immediate close, got {other:?}"),
        }
    });
}

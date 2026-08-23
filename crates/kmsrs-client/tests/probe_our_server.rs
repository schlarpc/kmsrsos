//! The probe, run against our own server (`CLI-002`, #208).
//!
//! This is the assertion the project's anti-fingerprinting claims rest on: the
//! full detection-resistance suite, run against the thing this repository
//! builds, must produce **no findings at all**.
//!
//! Per the audit, none of the three existing implementations survives this
//! probe unreconfigured — so a test that only asked "did it activate?" would
//! pass on all of them, and would tell us nothing.

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
use kmsrs_client::probe::{Finding, Probe};
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::Instant;
use kmsrs_server::config::operational::LogLevel;
use kmsrs_server::net::driver::Driver;
use kmsrs_server::net::listener::bind_each;
use kmsrs_server::{Compiled, Discovered, Operational, Server};
use std::sync::atomic::{AtomicU64, Ordering};

/// A clock that advances a little per reading, so nothing hits a deadline.
struct TestClock(AtomicU64);

impl TestClock {
    fn now(&self) -> Instant {
        Instant::from_nanos(self.0.fetch_add(1_000_000, Ordering::AcqRel))
    }
}

/// Run our own server on loopback for the duration of `body`.
fn with_server<T>(body: impl FnOnce(SocketAddr) -> T) -> T {
    let mut entropy = DeterministicEntropy::from_seed(0xA5A5_1234);
    let server = Server::new(
        Compiled::BUILD,
        Operational {
            log_level: LogLevel::Error,
            ..Operational::default()
        },
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap();

    let (bound, _) = bind_each(&[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)]).unwrap();
    let address = bound[0].address;
    let mut driver = Driver::new(server, bound, 64).unwrap();
    let shutdown = driver.shutdown_handle();
    let clock = TestClock(AtomicU64::new(1_000_000));

    std::thread::scope(|scope| {
        let clock_ref = &clock;
        let handle = scope.spawn(move || {
            // The *server's* entropy must vary, since the probe checks that its
            // association groups differ between connections.
            let mut entropy = DeterministicEntropy::from_seed(0x5A17);
            driver.run(&mut entropy, &|| clock_ref.now()).unwrap();
        });

        // The body must not be able to leave the driver running. A panic here
        // would otherwise deadlock the scope on `join`, turning a failed
        // assertion into a hang with no message — which is exactly what the
        // first version of this test did.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(address)));
        shutdown.request();
        handle.join().expect("the loop stopped cleanly");

        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

/// **The headline assertion.** Our own server produces no findings.
#[test]
fn our_own_server_survives_the_full_probe() {
    let findings = with_server(|address| {
        let mut entropy = DeterministicEntropy::from_seed(0xC0FF_EE01);
        let probe = Probe::new(address);
        let report = probe.run(&mut entropy).expect("the probe completes");

        // Every version was exercised, twice each.
        assert_eq!(
            report.exchanges.len(),
            Version::ALL.len() * 2,
            "each version should have produced two activations"
        );
        for exchange in &report.exchanges {
            assert!(
                exchange.checks.all_passed(),
                "{:?} failed: {:?}",
                exchange.version,
                exchange.checks.failures().collect::<Vec<_>>()
            );
            assert!(!exchange.epid.is_empty(), "an ePID was reported");
            assert!(exchange.count >= 25, "a count was reported");
        }

        report.findings
    });

    assert!(
        findings.is_empty(),
        "our own server is distinguishable from a genuine host: {findings:#?}"
    );
}

/// The probe is not vacuous: it *can* report findings.
///
/// Without this, `our_own_server_survives_the_full_probe` would pass equally
/// well against a probe that checked nothing. The cheapest way to prove the
/// machinery works is to lie to it about what was sent — the response is then
/// genuinely wrong *for that request*, and the checks must say so.
#[test]
fn the_probe_reports_findings_when_there_are_some() {
    use kmsrs_proto::kms::epid::EPid;
    use kmsrs_proto::kms::framing::{Ciphers, ResponsePlan};
    use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody};
    use kmsrs_proto::kms::response;
    use kmsrs_proto::kms::validate::{self, Check, MacCheck, Outcome, Sent};
    use kmsrs_proto::time::FileTime;
    use kmsrs_proto::types::{ClientMachineId, ClientTime, HardwareId, Intervals};
    use zerocopy::FromBytes;

    // Build a genuine v6 exchange.
    let ciphers = Ciphers::new();
    let body = RequestBody::read_from_bytes(&[0_u8; REQUEST_BODY_LEN]).unwrap();
    let mut entropy = DeterministicEntropy::from_seed(1);
    let mut request = vec![0_u8; 1024];
    let len = kmsrs_proto::kms::framing::encode_request(
        Version::V6,
        &body,
        &ciphers,
        &mut entropy,
        &mut request,
    )
    .unwrap();
    request.truncate(len);
    let decoded_request = kmsrs_proto::kms::framing::decode(&request, &ciphers).unwrap();

    let epid = EPid::parse("03612-00206-591-000000-03-1033-26100.0000-2412024").unwrap();
    let plan = ResponsePlan {
        epid: &epid,
        client_machine_id: ClientMachineId(kmsrs_db::Guid::ZERO),
        client_time: ClientTime(FileTime::from_ticks(0)),
        count: 50,
        intervals: Intervals::DEFAULT,
        hardware_id: HardwareId([1, 2, 3, 4, 5, 6, 7, 8]),
    };
    let mut entropy = DeterministicEntropy::from_seed(2);
    let mut response_bytes = vec![0_u8; 1024];
    let len = kmsrs_proto::kms::framing::encode(
        &decoded_request,
        &plan,
        &ciphers,
        &mut entropy,
        &mut response_bytes,
    )
    .unwrap();
    response_bytes.truncate(len);

    let mut scratch = vec![0_u8; response_bytes.len()];
    let decoded = response::decode(
        Version::V6,
        &response_bytes,
        ciphers.schedule(Version::V6),
        &mut scratch,
    )
    .unwrap();

    // Claim the request IV was whatever the response carried — which is what a
    // v6 host applying v5's IV rule would produce.
    let echoed = decoded.response_iv.unwrap();
    let sent = Sent {
        version: Version::V6,
        client_machine_id: ClientMachineId(kmsrs_db::Guid::ZERO),
        client_time: ClientTime(FileTime::from_ticks(0)),
        request_iv: Some(echoed),
        shared_secret: decoded_request.shared_secret,
        header_version: Version::V6.to_protocol_version().to_wire(),
        response_header_version: Version::V6.to_protocol_version().to_wire(),
    };
    let checks = validate::check(
        &sent,
        &decoded,
        Some(&MacCheck {
            tag: |m| Ciphers::new().mac().tag(m),
        }),
    );

    assert_eq!(
        checks.outcome(Check::IvsOk),
        Outcome::Fail,
        "the v6 IV rule must be checkable"
    );

    // And a `Finding` renders something an operator can act on.
    let finding = Finding::ResponseCheckFailed {
        check: Check::IvsOk,
        version: Version::V6,
    };
    let text = finding.to_string();
    assert!(text.contains("IVsOK"), "{text}");
    assert!(text.contains("genuine host"), "{text}");
}

/// `CLI-002` (#208): a stock py-kms hardware ID is recognised.
#[test]
fn the_stock_pykms_hardware_id_is_recognised() {
    use kmsrs_client::probe::SUSPICIOUS_HARDWARE_IDS;

    // py-kms's default, shared by every stock deployment.
    assert!(SUSPICIOUS_HARDWARE_IDS.contains(&[0x36, 0x4F, 0x46, 0x3A, 0x88, 0x63, 0xD3, 0x5F]));
    // An unset field, in both directions.
    assert!(SUSPICIOUS_HARDWARE_IDS.contains(&[0; 8]));
    assert!(SUSPICIOUS_HARDWARE_IDS.contains(&[0xFF; 8]));

    let finding = Finding::SuspiciousHardwareId {
        hardware_id: [0x36, 0x4F, 0x46, 0x3A, 0x88, 0x63, 0xD3, 0x5F],
    };
    assert!(finding.to_string().contains("stock constant"));
}

/// `CLI-012` (#218): the timeout is honoured, unlike `vlmcs`'s hardcoded ten
/// seconds.
#[test]
fn the_configured_timeout_is_honoured() {
    // 203.0.113.1 is TEST-NET-3: routable nowhere, so the connect hangs until
    // it times out.
    let unreachable = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 1688);
    let probe = Probe {
        timeout: Duration::from_millis(250),
        ..Probe::new(unreachable)
    };

    let started = std::time::Instant::now();
    let mut entropy = DeterministicEntropy::from_seed(1);
    let outcome = probe.run(&mut entropy);
    let elapsed = started.elapsed();

    assert!(outcome.is_err(), "an unreachable host should fail");
    assert!(
        elapsed < Duration::from_secs(5),
        "the timeout was not honoured: {elapsed:?}"
    );
}

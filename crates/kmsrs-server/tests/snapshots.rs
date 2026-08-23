//! Snapshots of the operator-facing contract (`TEST-016`, #237).
//!
//! Every page the web UI serves and every shape the log emits, committed as
//! text and compared byte for byte. A change to either fails here rather than
//! reaching an operator's dashboard or somebody's log parser.
//!
//! # Why this and not more unit tests
//!
//! Because the failure being prevented is *drift*, and drift is invisible to a
//! test that asserts a property. `the_metrics_page_is_well_formed_exposition`
//! keeps passing when a metric is renamed; `healthz_is_503_when_entropy_is_failing`
//! keeps passing when the body it returns changes. Both are worth having and
//! neither notices that the thing an operator scripted against moved.
//!
//! Both audited projects have pages of verified doc-versus-code drift. vlmcsd's
//! man pages document seven options that do not exist in its own optstring;
//! py-kms's documented timeout is a total-process-lifetime cap rather than a
//! per-client one, its log-size claim is in megabytes when the code uses half a
//! mebibyte, and its dual-stack claim is simply false. In every case the code
//! moved and nothing compared it to what had been promised.
//!
//! # Blessing
//!
//! `KMSRSOS_BLESS=1 cargo test -p kmsrs-server --test snapshots`
//!
//! Deliberately a separate, explicit step, exactly as the golden wire vectors
//! are (`TEST-002`, #223): a test that rewrote its own expectations on failure
//! would assert nothing at all. When a diff is intentional, blessing it and
//! reading the diff in review is the point.
//!
//! # What is *not* snapshotted
//!
//! Anything that varies per process. The ePID, the hardware ID and the
//! association group are drawn from entropy; the build stamp is whatever built
//! the binary. Snapshotting those would produce a test that fails on every
//! machine, so [`redact`] replaces them with a marker — and the marker's
//! presence is itself asserted, so a page that stopped rendering an ePID would
//! fail rather than quietly matching.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed expectation should abort loudly"
)]

use core::fmt::Write as _;
use kmsrs_policy::events::EventLog;
use kmsrs_policy::identity::HostIdentity;
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_server::config::operational::{LogFormat, LogLevel};
use kmsrs_server::log::{Logger, Severity};
use kmsrs_server::web::request::{Parsed, parse};
use kmsrs_server::web::routes;
use kmsrs_server::web::routes::Snapshot;
use std::path::PathBuf;

fn snapshots_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("snapshots")
}

/// What a per-process value is replaced by.
///
/// Marked rather than deleted, so a page that stopped rendering one fails
/// instead of quietly matching a snapshot with a hole in it.
const REDACTED: &str = "«redacted»";

/// Replace everything that legitimately varies between processes.
///
/// Deliberately narrow. Each pattern is a value drawn from entropy or from the
/// build, and anything not listed here is part of the contract.
fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    // An ePID: five hyphen-separated groups with a build number in the middle.
    // Matched structurally rather than by regex, because the crate has no regex
    // and this is the only shape that needs finding.
    while let Some(start) = rest.find("03612-") {
        out.push_str(&rest[..start]);
        out.push_str(REDACTED);
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);

    // The build stamp, redacted **structurally** rather than by value.
    //
    // By value is the obvious way and it is wrong, which took two goes to
    // establish. `nix develop` exports `SOURCE_DATE_EPOCH` for
    // reproducibility, so a `cargo test` inside the dev shell compiles a binary
    // carrying a real source date while CI compiles one carrying `unknown` —
    // and a rule that replaces "whatever this build's stamp says" blesses a
    // snapshot that only matches builds made the same way. Replacing what is
    // *between the delimiters* does not care.
    //
    // The version is deliberately left alone: it comes from `Cargo.toml`, it is
    // the same everywhere, and it is part of the contract.
    out = redact_between(&out, "revision=\"", "\"");
    out = redact_between(&out, "source_date_epoch=\"", "\"");
    // The status page's build cell, which renders the whole stamp as prose.
    out = redact_between(&out, "<th>Build</th><td><code>", "</code>");
    out
}

/// Replace everything between `prefix` and the next `suffix` after it.
///
/// Every occurrence, because a page may render the stamp more than once.
fn redact_between(text: &str, prefix: &str, suffix: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(at) = rest.find(prefix) {
        let (before, after) = rest.split_at(at.saturating_add(prefix.len()));
        out.push_str(before);
        out.push_str(REDACTED);
        match after.find(suffix) {
            Some(end) => rest = after.split_at(end).1,
            // No closing delimiter: the rest of the document is inside the
            // value, which cannot happen for any of the three patterns above
            // and would be a rendering bug if it did.
            None => return out,
        }
    }

    out.push_str(rest);
    out
}

/// Line endings are a property of the checkout, not of the contract.
///
/// A Windows runner with git's default `core.autocrlf` rewrites every `\n` in a
/// text file to `\r\n` on checkout, so a snapshot committed with Unix endings
/// arrives with Windows ones and every comparison fails — reported as "the
/// status page has drifted at line 1", which is a true statement about the
/// bytes and a useless one about the program.
///
/// `.gitattributes` pins these files to `lf` so the working tree stays
/// canonical; this is the belt to that pair of braces, because a checkout made
/// before the attribute existed is still out there.
fn canonical(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// Compare against the committed snapshot, or write it under `KMSRSOS_BLESS`.
fn assert_snapshot(name: &str, actual: &str) {
    let path = snapshots_dir().join(format!("{name}.txt"));
    let actual = &canonical(actual);

    if std::env::var("KMSRSOS_BLESS").is_ok() {
        std::fs::create_dir_all(snapshots_dir()).expect("the snapshots directory");
        std::fs::write(&path, actual).expect("writing a snapshot");
        eprintln!("blessed {name}");
        return;
    }

    let expected = canonical(&std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{} is missing ({error}). If this is a new snapshot, run\n  \
             KMSRSOS_BLESS=1 cargo test -p kmsrs-server --test snapshots",
            path.display()
        )
    }));

    if &expected != actual {
        // The first differing line, because a whole-page diff in a panic
        // message is unreadable and the line number is what a person needs.
        let at = expected
            .lines()
            .zip(actual.lines())
            .position(|(left, right)| left != right)
            .unwrap_or_else(|| expected.lines().count().min(actual.lines().count()));
        panic!(
            "{name} has drifted at line {}.\n  expected: {:?}\n  actual:   {:?}\n\n\
             If the change is intentional, run\n  \
             KMSRSOS_BLESS=1 cargo test -p kmsrs-server --test snapshots\n\
             and read the diff in review.",
            at.saturating_add(1),
            expected.lines().nth(at),
            actual.lines().nth(at),
        );
    }
}

/// A host with a fixed identity and a fixed event, so a page is a pure function
/// of things this test chose.
struct Fixture {
    identity: HostIdentity,
    events: EventLog,
}

impl Fixture {
    fn new() -> Self {
        let mut entropy = DeterministicEntropy::from_seed(0x5EED_0016);
        let mut events = EventLog::new(4096, core::time::Duration::from_hours(24));
        record(&mut events);
        Self {
            identity: HostIdentity::generate(
                &mut entropy,
                kmsrs_db::Date::new(2026, 8, 23).unwrap(),
            )
            .unwrap(),
            events,
        }
    }

    fn snapshot(&self) -> Snapshot<'_> {
        Snapshot {
            listening: true,
            entropy_healthy: true,
            kms_ports: &[1688],
            identity: &self.identity,
            events: &self.events,
        }
    }
}

/// One activated request and one refused one, so every branch of a row renders.
fn record(log: &mut EventLog) {
    use kmsrs_policy::events::Outcome;
    use kmsrs_policy::gate::{Observations, Refusal};
    use kmsrs_proto::kms::request::Request;
    use kmsrs_proto::kms::status::LicenseStatus;
    use kmsrs_proto::kms::version::ProtocolVersion;
    use kmsrs_proto::time::{FileTime, Instant};
    use kmsrs_proto::types::{
        ApplicationId, ClientKind, ClientMachineId, ClientTime, CsvlkSelection, GraceMinutes,
        KmsCountedId, RequiredClients, SkuId, WorkstationName,
    };

    let mut units = [0_u16; kmsrs_proto::types::WORKSTATION_NAME_UNITS];
    for (slot, unit) in units.iter_mut().zip("WKS-4J2QZ8".encode_utf16()) {
        *slot = unit;
    }

    let request = Request {
        version: ProtocolVersion::from_wire(0x0006_0000),
        client_kind: ClientKind::BareMetal,
        license_status: LicenseStatus::from_wire(2),
        grace: GraceMinutes(43_200),
        application: ApplicationId(kmsrs_db::Guid::from_bytes([0x55; 16])),
        sku: SkuId(kmsrs_db::Guid::from_bytes([0x22; 16])),
        counted: KmsCountedId(kmsrs_db::Guid::from_bytes([0x33; 16])),
        client_machine_id: ClientMachineId(kmsrs_db::Guid::from_bytes([0x44; 16])),
        previous_client_machine_id: None,
        client_time: ClientTime(FileTime::from_ticks(133_000_000_000_000_000)),
        required_clients: RequiredClients(25),
        workstation_name: WorkstationName::decode(&units),
    };
    let observations = Observations {
        known_product: false,
        clock_skew: None,
        clock_skewed: false,
    };

    log.record(
        &request,
        None,
        Instant::from_nanos(1),
        Outcome::Activated(kmsrs_policy::events::Activation {
            selection: CsvlkSelection::Fallback { index: 0 },
            reported_count: 25,
            cached_count: 1,
            outcome: kmsrs_policy::counting::CountOutcome::Inserted,
            expired: 0,
            anomalous_demand: false,
        }),
        observations,
    );
    log.record(
        &request,
        None,
        Instant::from_nanos(2),
        Outcome::Refused(Refusal::PreviewProduct),
        observations,
    );
}

/// Render one route.
fn render(fixture: &Fixture, target: &str) -> String {
    let raw = format!("GET {target} HTTP/1.1\r\nHost: kms.example.net:8080\r\n\r\n").into_bytes();
    let Parsed::Complete(request) = parse(&raw) else {
        panic!("{target} did not parse");
    };
    let response = routes::route(&request, &fixture.snapshot());
    format!(
        "status: {}\ncontent-type: {:?}\n\n{}",
        response.status.code(),
        response.content_type,
        redact(&response.body)
    )
}

/// `TEST-016` (#237): every page, committed.
///
/// All six routes, because the contract is the whole surface and a snapshot of
/// four of them is a contract with two holes in it.
#[test]
fn every_page_matches_its_committed_snapshot() {
    let fixture = Fixture::new();
    for target in [
        "/",
        "/events",
        "/instructions",
        "/products",
        "/healthz",
        "/metrics",
    ] {
        let name = match target {
            "/" => "page-status",
            other => &format!("page-{}", other.trim_start_matches('/')),
        };
        assert_snapshot(name, &render(&fixture, target));
    }
}

/// The unhealthy pages too, because they are the ones an operator reads under
/// pressure and the ones nobody looks at until then.
#[test]
fn the_unhealthy_pages_match_their_committed_snapshots() {
    let fixture = Fixture::new();
    let mut snapshot = fixture.snapshot();
    snapshot.listening = false;
    snapshot.entropy_healthy = false;
    snapshot.kms_ports = &[];

    for (name, target) in [("unhealthy-healthz", "/healthz"), ("unhealthy-status", "/")] {
        let raw = format!("GET {target} HTTP/1.1\r\nHost: kms\r\n\r\n").into_bytes();
        let Parsed::Complete(request) = parse(&raw) else {
            panic!("{target} did not parse");
        };
        let response = routes::route(&request, &snapshot);
        assert_snapshot(
            name,
            &format!(
                "status: {}\n\n{}",
                response.status.code(),
                redact(&response.body)
            ),
        );
    }
}

/// Every refusal the HTTP parser can produce, committed.
///
/// `OBS-009` (#185) says a refusal reveals nothing the caller did not already
/// know, and this is what stops that eroding one helpful message at a time.
#[test]
fn every_refusal_matches_its_committed_snapshot() {
    let mut out = String::new();
    for (name, request) in [
        ("post", "POST / HTTP/1.1\r\nHost: k\r\n\r\n"),
        ("unknown-method", "FROBNICATE / HTTP/1.1\r\nHost: k\r\n\r\n"),
        ("http-2", "GET / HTTP/2.0\r\nHost: k\r\n\r\n"),
        ("no-colon", "GET / HTTP/1.1\r\nHost k\r\n\r\n"),
        ("space-before-colon", "GET / HTTP/1.1\r\nHost : k\r\n\r\n"),
        (
            "declared-body",
            "GET / HTTP/1.1\r\nHost: k\r\nContent-Length: 4\r\n\r\nabcd",
        ),
        ("absolute-form", "GET http://x/ HTTP/1.1\r\nHost: k\r\n\r\n"),
        ("unknown-route", "GET /nope HTTP/1.1\r\nHost: k\r\n\r\n"),
    ] {
        let fixture = Fixture::new();
        let answered = kmsrs_server::web::answer(request.as_bytes(), &mut |parsed| {
            routes::route(parsed, &fixture.snapshot())
        });
        let kmsrs_server::web::Answered::Reply { bytes, .. } = answered else {
            panic!("{name} was not answered");
        };
        let text = String::from_utf8_lossy(&bytes);
        let status = text.lines().next().unwrap_or_default();
        let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        let _: core::fmt::Result = writeln!(out, "{name}\n  {status}\n  {body}");
    }
    assert_snapshot("refusals", &out);
}

/// `TEST-016` (#237): the log format, committed, in both shapes.
///
/// JSON Lines is the one somebody scripts against, so a renamed field there is
/// a broken pipeline. The text form is the one somebody reads, so a changed
/// column order is a person who has to relearn it.
#[test]
fn the_log_lines_match_their_committed_snapshots() {
    let fixture = Fixture::new();
    let mut out = String::new();

    for (label, format) in [("json", LogFormat::Json), ("text", LogFormat::Text)] {
        // Colour off: whether stderr is a terminal is a property of the machine
        // running this, not of the format.
        let logger = Logger::with(LogLevel::Debug, format, false);
        let _: core::fmt::Result = writeln!(out, "--- {label} ---");

        for severity in [
            Severity::Debug,
            Severity::Info,
            Severity::Warn,
            Severity::Error,
        ] {
            if let Some(line) = logger.format_message(severity, "listening", "0.0.0.0:1688") {
                out.push_str(&line);
                out.push('\n');
            }
        }
        for event in fixture.events.iter() {
            if let Some(line) = logger.format_request(event) {
                out.push_str(&redact(&line));
                out.push('\n');
            }
        }
    }

    assert_snapshot("log-lines", &out);
}

/// The redaction is doing something, so a snapshot cannot pass by having had
/// its variable parts silently vanish.
#[test]
fn the_redaction_replaces_what_it_claims_to() {
    let fixture = Fixture::new();
    let status = render(&fixture, "/");
    assert!(
        status.contains(REDACTED),
        "the status page rendered no ePID and no build stamp, so the snapshot \
         is of a page with holes in it:\n{status}"
    );
    // And an ePID really is what was replaced.
    assert!(
        !status.contains("03612-"),
        "an ePID survived redaction, so this snapshot will fail on the next \
         machine that runs it"
    );
}

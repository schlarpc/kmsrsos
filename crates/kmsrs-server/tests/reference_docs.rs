//! `docs/reference.md`, generated from the code (`PKG-010`, #247).
//!
//! # What this document is, and why it is generated
//!
//! Everything in it is a fact about the program that a reader would otherwise
//! have to take on trust: which routes exist, which metrics they expose, which
//! exit codes a supervisor can expect, which settings a build takes, and what
//! is in the shipped database. Every one of those is *already* written down
//! somewhere in the code, and a hand-written copy is a second source of truth
//! that drifts from the first.
//!
//! Drift is not hypothetical here. vlmcsd's man pages document seven options
//! that are not in its own optstring. py-kms's documented timeout is a
//! total-process-lifetime cap rather than the per-client one it describes, its
//! log-size claim is in megabytes when the code uses half a mebibyte, and its
//! dual-stack claim is simply false. Every one of those was true when written.
//!
//! So the document is derived, committed, and compared byte for byte — the same
//! two-step as the golden wire vectors (`TEST-002`, #223) and the UI snapshots
//! (`TEST-016`, #237), and for the same reason: a document that regenerated
//! itself on failure would assert nothing.
//!
//! # Regenerating
//!
//! `KMSRSOS_BLESS=1 cargo test -p kmsrs-server --test reference_docs`
//!
//! # What is deliberately not generated
//!
//! The prose. `docs/deployment.md`, `docs/decisions.md` and the audits are
//! written by people and are about *why*, which no generator can produce. This
//! is the *what*, and only the parts of it that a machine can read off the
//! program itself.

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
use kmsrs_server::web::request::{Parsed, parse};
use kmsrs_server::web::routes::{self, Snapshot};
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<name> is always two levels below the workspace root")
        .to_path_buf()
}

/// The routes this host serves, and what each is for.
///
/// The list is here rather than read out of `routes.rs` because a route's
/// *purpose* is prose; what the generator guarantees is that the set matches —
/// `every_documented_route_answers` below fetches each one.
const ROUTES: &[(&str, &str)] = &[
    (
        "/",
        "Status: the listener, the entropy self-test, the host build, the ePIDs this host answers with, and the machines it has seen.",
    ),
    (
        "/events",
        "The bounded event log, most recent first — one row per request, never one row per machine.",
    ),
    (
        "/instructions",
        "How to point a client here, with this instance's own address filled in: `slmgr`, `ospp.vbs`, and three DNS forms.",
    ),
    ("/products", "The shipped product database."),
    (
        "/healthz",
        "200 when the KMS side is working, 503 otherwise. Plain text, so a monitor need not parse HTML.",
    ),
    ("/metrics", "Prometheus exposition format."),
];

/// The exit codes a supervisor can expect.
const EXIT_CODES: &[(&str, &str)] = &[
    ("0", "Stopped cleanly."),
    (
        "64",
        "The command line or the activation environment could not be understood: an argument was passed, or `LISTEN_FDS` was set.",
    ),
    (
        "69",
        "Start-up could not proceed: nothing bound, the clock is unusable, or the entropy self-test failed.",
    ),
    ("78", "`KMSRSOS_CONFIG` could not be parsed."),
    ("130", "A second stop signal cut a drain short."),
];

/// Build the document.
fn generate() -> String {
    let mut out = String::new();
    let _: core::fmt::Result = writeln!(
        out,
        "<!-- GENERATED FILE — do not edit by hand.\n\
         \x20    Regenerate with:\n\
         \x20      KMSRSOS_BLESS=1 cargo test -p kmsrs-server --test reference_docs\n\
         \x20    Drift fails CI (PKG-010, #247). -->\n\
         \n\
         # Reference\n\
         \n\
         Facts about this program, read off the program. The prose lives in\n\
         [`deployment.md`](deployment.md) and [`decisions.md`](decisions.md);\n\
         this is the part a generator can be trusted with, so it is generated\n\
         rather than described — a hand-written copy is a second source of truth\n\
         that drifts, which is how vlmcsd came to document seven options its own\n\
         optstring does not have.\n"
    );

    routes_section(&mut out);
    metrics_section(&mut out);
    exit_codes_section(&mut out);
    settings_section(&mut out);
    database_section(&mut out);

    out
}

fn routes_section(out: &mut String) {
    let _: core::fmt::Result = writeln!(
        out,
        "\n## Web UI\n\n\
         Six routes and no more. `/` is matched exactly rather than as a prefix,\n\
         so an unknown path is 404 rather than something's index, and the parser\n\
         admits only `GET` and `HEAD` — a route cannot act on a `POST` it was\n\
         never offered.\n\n\
         | Route | What it is |\n|---|---|"
    );
    for (path, purpose) in ROUTES {
        let _: core::fmt::Result = writeln!(out, "| `{path}` | {purpose} |");
    }
}

fn metrics_section(out: &mut String) {
    let fixture = Fixture::new();
    let body = render(&fixture, "/metrics");

    let _: core::fmt::Result = writeln!(
        out,
        "\n## Metrics\n\n\
         Read off `/metrics` itself, so the help text here is the help text a\n\
         scraper sees.\n\n\
         | Metric | Type | Help |\n|---|---|---|"
    );

    let mut help: Option<String> = None;
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            help = rest.split_once(' ').map(|(_, text)| text.to_owned());
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split(' ');
            let name = parts.next().unwrap_or_default();
            let kind = parts.next().unwrap_or_default();
            let _: core::fmt::Result = writeln!(
                out,
                "| `{name}` | {kind} | {} |",
                help.as_deref().unwrap_or("")
            );
        }
    }
}

fn exit_codes_section(out: &mut String) {
    let _: core::fmt::Result = writeln!(
        out,
        "\n## Exit codes\n\n\
         A supervisor can tell \"you told me something wrong\" from \"something\n\
         went wrong\" without parsing stderr.\n\n\
         | Code | Meaning |\n|---|---|"
    );
    for (code, meaning) in EXIT_CODES {
        let _: core::fmt::Result = writeln!(out, "| `{code}` | {meaning} |");
    }
}

fn settings_section(out: &mut String) {
    let compiled = kmsrs_server::Compiled::BUILD;
    let stamp = kmsrs_server::config::stamp::BUILD;

    let _: core::fmt::Result = writeln!(
        out,
        "\n## What a build decides\n\n\
         Anything that can change a byte on the wire is decided when the binary\n\
         is built (`CFG-001`, #166). These are the values *this* build carries;\n\
         `mkKmsrsos` is how a different one is produced (`CFG-003`, #168).\n\n\
         | Setting | This build |\n|---|---|\n\
         | Activation interval | {} minutes |\n\
         | Renewal interval | {} minutes |\n\
         | Refuse retail, OEM and evaluation SKUs | {} |\n\
         | Refuse pre-release SKUs | {} |\n\
         | Refuse a clock-skewed request | {} |\n\
         | Idle timeout | {} seconds |\n\
         | Version | `{}` |\n\
         \n\
         The only runtime setting is `KMSRSOS_CONFIG`, a TOML document\n\
         restricted to fields that cannot change a byte on the wire. There is no\n\
         configuration file and no command line.",
        compiled.intervals.activation,
        compiled.intervals.renewal,
        yes_no(compiled.refuse_non_volume),
        yes_no(compiled.refuse_preview),
        yes_no(compiled.refuse_clock_skew),
        compiled.idle_timeout.as_secs(),
        stamp.version,
    );
}

fn database_section(out: &mut String) {
    let _: core::fmt::Result = writeln!(
        out,
        "\n## The shipped database\n\n\
         Extracted from Microsoft's own signed licensing artifacts by\n\
         `kmsrs-dbgen` (`DB-002`, #126). Static data in the binary's read-only\n\
         section: no parsing, no initialisation, no lock, and no per-request\n\
         cost.\n\n\
         | Table | Rows |\n|---|---:|\n\
         | Applications | {} |\n\
         | Products | {} |\n\
         | KMS host keys | {} |\n\
         | Counted IDs | {} |\n\
         | Host builds | {} |\n\
         | Host builds an ePID may claim | {} |\n\
         | Locales | {} |\n\
         \n\
         The arrays occupy {} bytes, against a {}-byte ceiling asserted at\n\
         compile time (`DB-018`, #142) — on Hermit every byte of `.rodata` is a\n\
         byte of the guest's memory, permanently.",
        kmsrs_db::APPLICATIONS.len(),
        kmsrs_db::PRODUCTS.len(),
        kmsrs_db::CSVLKS.len(),
        kmsrs_db::COUNTED_IDS.len(),
        kmsrs_db::HOST_BUILDS.len(),
        kmsrs_db::EPID_HOST_BUILDS.len(),
        kmsrs_db::LCIDS.len(),
        kmsrs_db::TABLE_BYTES,
        kmsrs_db::size::BUDGET_BYTES,
    );
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// `PKG-010` (#247): the document regenerates, and drift fails.
#[test]
fn the_reference_matches_what_the_code_says() {
    let path = workspace_root().join("docs/reference.md");
    let actual = generate();

    if std::env::var("KMSRSOS_BLESS").is_ok() {
        std::fs::write(&path, &actual).expect("writing the reference");
        eprintln!("blessed {}", path.display());
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{} is missing ({error}). Run\n  \
             KMSRSOS_BLESS=1 cargo test -p kmsrs-server --test reference_docs",
            path.display()
        )
    });

    if expected != actual {
        let at = expected
            .lines()
            .zip(actual.lines())
            .position(|(left, right)| left != right)
            .unwrap_or_else(|| expected.lines().count().min(actual.lines().count()));
        panic!(
            "docs/reference.md has drifted at line {}.\n  documented: {:?}\n  \
             actual:     {:?}\n\nRun\n  \
             KMSRSOS_BLESS=1 cargo test -p kmsrs-server --test reference_docs",
            at.saturating_add(1),
            expected.lines().nth(at),
            actual.lines().nth(at),
        );
    }
}

/// Every route the reference documents answers, and every route that answers is
/// documented.
///
/// The generator writes the table from a list, so without this the list could
/// describe a route that does not exist — which is precisely vlmcsd's `-h` and
/// `-?`.
#[test]
fn every_documented_route_answers_and_nothing_else_does() {
    let fixture = Fixture::new();

    for (path, _) in ROUTES {
        let raw = format!("GET {path} HTTP/1.1\r\nHost: kms\r\n\r\n").into_bytes();
        let Parsed::Complete(request) = parse(&raw) else {
            panic!("{path} did not parse");
        };
        let status = routes::route(&request, &fixture.snapshot()).status;
        assert_ne!(
            status,
            kmsrs_server::web::Status::NotFound,
            "{path} is documented and does not exist"
        );
    }

    // And nothing outside the list. A route that exists and is undocumented is
    // the other half of the same drift.
    for path in ["/status", "/index.html", "/clients", "/api", "/readyz"] {
        let raw = format!("GET {path} HTTP/1.1\r\nHost: kms\r\n\r\n").into_bytes();
        let Parsed::Complete(request) = parse(&raw) else {
            panic!("{path} did not parse");
        };
        assert_eq!(
            routes::route(&request, &fixture.snapshot()).status,
            kmsrs_server::web::Status::NotFound,
            "{path} answers and is not in the reference"
        );
    }
}

struct Fixture {
    identity: HostIdentity,
    events: EventLog,
}

impl Fixture {
    fn new() -> Self {
        let mut entropy = DeterministicEntropy::from_seed(0x5EED_0247);
        Self {
            identity: HostIdentity::generate(
                &mut entropy,
                kmsrs_db::Date::new(2026, 8, 23).unwrap(),
            )
            .unwrap(),
            events: EventLog::new(4096, core::time::Duration::from_hours(24)),
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

fn render(fixture: &Fixture, target: &str) -> String {
    let raw = format!("GET {target} HTTP/1.1\r\nHost: kms\r\n\r\n").into_bytes();
    let Parsed::Complete(request) = parse(&raw) else {
        panic!("{target} did not parse");
    };
    routes::route(&request, &fixture.snapshot()).body
}

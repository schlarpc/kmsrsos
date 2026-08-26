//! The sandbox is applied, and it is not decorative (`SEC-005`, #197).
//!
//! # Why every case here re-executes this binary
//!
//! Landlock and `no_new_privs` are **irreversible**. A process that applies
//! them keeps them for its lifetime, and a test harness runs every test in one
//! process — so a test that sandboxed itself would silently break every test
//! that ran after it, including ones in other files sharing the binary.
//!
//! So each case spawns a copy of this test binary with `KMSRSOS_SANDBOX_CHILD`
//! set, the child does the sandboxing and reports on stdout, and the parent
//! reads the report. That is more machinery than a unit test, and it buys the
//! only thing worth having here: the assertions are about a **real process that
//! really applied the policy**, not about a struct describing one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_server::sandbox::{self, Applied, FILESYSTEM_CAN_BE_DENIED};
use std::process::Command;

/// Set on the child, so it sandboxes itself instead of spawning again.
const CHILD: &str = "KMSRSOS_SANDBOX_CHILD";

/// Run `name` in a fresh copy of this binary and return its stdout.
fn in_a_child(name: &str) -> String {
    let exe = std::env::current_exe().expect("the test binary's own path");
    let output = Command::new(exe)
        .args(["--exact", name, "--nocapture", "--test-threads", "1"])
        .env(CHILD, "1")
        .output()
        .expect("the child ran");

    assert!(
        output.status.success(),
        "the child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn is_the_child() -> bool {
    std::env::var_os(CHILD).is_some()
}

/// **The headline: after the sandbox, a file that was readable is not.**
///
/// The before-and-after in one process is what makes this a test of the
/// sandbox rather than of the filesystem's permissions — if `/proc/self/cmdline`
/// were unreadable for some other reason, the "before" would fail too and the
/// child would say so.
#[test]
fn the_filesystem_is_denied_after_the_sandbox_is_applied() {
    if is_the_child() {
        // This binary's own path: it exists on every platform, is readable
        // without privileges, and is guaranteed to be there because something
        // is currently executing it. `/proc/self/cmdline` was the obvious
        // choice and is Linux-only, which made this fail on the Windows runner
        // at the *before* assertion rather than at the one it is about.
        let path = std::env::current_exe().expect("this binary's own path");
        // `File::open`, not `read`: opening is precisely what Landlock
        // governs, and reading the whole binary to learn that would be several
        // megabytes to answer a yes/no question.
        let before = std::fs::File::open(&path).is_ok();
        let report = sandbox::apply();
        let after = std::fs::read(path).is_ok();

        println!(
            "BEFORE={before} AFTER={after} FILESYSTEM={:?}",
            report.filesystem
        );
        return;
    }

    let output = in_a_child("the_filesystem_is_denied_after_the_sandbox_is_applied");
    assert!(
        output.contains("BEFORE=true"),
        "the child could not read the file even before sandboxing, so this \
         test proves nothing: {output}"
    );

    if FILESYSTEM_CAN_BE_DENIED {
        assert!(
            output.contains("FILESYSTEM=Yes"),
            "the sandbox did not report applying the filesystem denial: {output}"
        );
        assert!(
            output.contains("AFTER=false"),
            "the file was still readable after the sandbox said it had denied \
             the filesystem, which means the policy is decorative: {output}"
        );
    } else {
        assert!(
            output.contains("FILESYSTEM=NotOnThisTarget"),
            "a target without filesystem denial must say so rather than claim \
             it: {output}"
        );
    }
}

/// A sandboxed process cannot open a new socket either.
///
/// Not an accident of the filesystem policy: Landlock ABI 4 added `BindTcp` and
/// `ConnectTcp`, and the ruleset handles both without granting either. A KMS
/// host needs neither once its listeners are up — `NET-001` (#150) says it does
/// not even read its own address — so this is free hardening, and it is the
/// difference between a compromised request path that can phone home and one
/// that cannot.
#[test]
fn no_new_socket_can_be_opened_after_the_sandbox_is_applied() {
    if is_the_child() {
        let before = std::net::TcpListener::bind("127.0.0.1:0").is_ok();
        let report = sandbox::apply();
        let after = std::net::TcpListener::bind("127.0.0.1:0").is_ok();

        println!(
            "BEFORE={before} AFTER={after} FILESYSTEM={:?}",
            report.filesystem
        );
        return;
    }

    let output = in_a_child("no_new_socket_can_be_opened_after_the_sandbox_is_applied");
    assert!(
        output.contains("BEFORE=true"),
        "the child could not bind even before sandboxing: {output}"
    );

    if FILESYSTEM_CAN_BE_DENIED && output.contains("FILESYSTEM=Yes") {
        assert!(
            output.contains("AFTER=false"),
            "a new listener could still be bound after the sandbox was applied. \
             The ruleset handles AccessNet and grants nothing, so this means the \
             running kernel's Landlock is older than ABI 4 — or the ruleset \
             stopped handling network access: {output}"
        );
    }
}

/// Sockets **already open** keep working, which is why the sandbox is applied
/// after binding rather than before.
///
/// This is the property the whole ordering rests on. If Landlock governed an
/// established connection rather than the act of opening one, applying it after
/// `bind` would still break the server on its first request.
///
/// The connection is established *before* `apply`, and deliberately so: the
/// sandbox denies `connect` as well as `bind`, so a client that dialled
/// afterwards would hang — which is exactly what an earlier version of this
/// test did, and is itself evidence the network rules bite.
#[test]
fn a_connection_opened_before_the_sandbox_still_carries_data() {
    if is_the_child() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        // Everything that opens a socket happens first.
        let mut client = std::net::TcpStream::connect(address).unwrap();
        let (mut served, _) = listener.accept().unwrap();

        let report = sandbox::apply();

        // ...and everything that *uses* one happens after.
        let written = client.write_all(b"ping").is_ok();
        let mut buffer = [0_u8; 4];
        let read = served.read_exact(&mut buffer).is_ok() && &buffer == b"ping";
        let replied = served.write_all(b"pong").is_ok();
        let mut back = [0_u8; 4];
        let round_trip = client.read_exact(&mut back).is_ok() && &back == b"pong";

        println!(
            "WROTE={written} READ={read} REPLIED={replied} ROUNDTRIP={round_trip} \
             FILESYSTEM={:?}",
            report.filesystem
        );
        return;
    }

    let output = in_a_child("a_connection_opened_before_the_sandbox_still_carries_data");
    for claim in ["WROTE=true", "READ=true", "REPLIED=true", "ROUNDTRIP=true"] {
        assert!(
            output.contains(claim),
            "an established connection stopped working after the sandbox was \
             applied, which would make the after-binding ordering unworkable \
             ({claim} missing): {output}"
        );
    }
}

/// The report is honest about what it did not do.
///
/// A sandbox that reported success for a measure it skipped would be worse than
/// no sandbox: an operator reading the log would believe a restriction was in
/// place that was not.
#[test]
fn the_report_never_claims_more_than_it_applied() {
    if is_the_child() {
        let report = sandbox::apply();
        for (name, applied) in report.each() {
            println!("MEASURE {name}={applied:?}");
        }
        return;
    }

    let output = in_a_child("the_report_never_claims_more_than_it_applied");
    for (name, _) in kmsrs_server::sandbox::Report::NOTHING.each() {
        assert!(
            output.contains(&format!("MEASURE {name}=")),
            "the report does not mention {name}: {output}"
        );
    }

    // `syscalls` is the one deliberately not implemented — `SEC-018` (#355) —
    // and it must report a failure rather than a success, because an operator
    // reading "applied" would believe a filter was in place that is not.
    if kmsrs_server::sandbox::SYSCALLS_CAN_BE_RESTRICTED {
        assert!(
            output.contains("MEASURE syscalls=Failed"),
            "the syscall filter is not implemented yet and the report must say \
             so; if it has been implemented, this assertion is what needs \
             updating: {output}"
        );
    }
}

/// **The bare-metal target is not sandboxed, and that is asserted rather than
/// inferred** (`SEC-005`, #197).
///
/// `serve` opts in and `serve_with` does not, because pid 1 mounts, speaks
/// netlink, steps the clock and calls `reboot(2)` for the life of the machine.
/// The distinction is one boolean two functions apart, which is exactly the
/// kind that gets flipped by a refactor nobody thought was about sandboxing —
/// so it is checked in the source, in the same style as the wall-clock and
/// socket-option invariants.
#[test]
fn the_bare_metal_entry_point_does_not_sandbox_itself() {
    let entry = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/entry.rs");
    let source = std::fs::read_to_string(&entry)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", entry.display()))
        .replace("\r\n", "\n");

    let calls: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .filter(|line| line.contains("serve_inner("))
        .collect();

    // Counting callers was the original form of this check, and `PKG-008`
    // (#245) added a third — `serve_reporting_ready`, the Windows service
    // path — which made the count fail for a change that was correct. The
    // count was never the invariant. *Which* callers opt out is.
    let unsandboxed: Vec<&&str> = calls.iter().filter(|line| line.contains("false")).collect();
    let sandboxed: Vec<&&str> = calls.iter().filter(|line| line.contains("true")).collect();

    assert!(
        !calls.is_empty(),
        "no calls to `serve_inner` at all, so this test is not looking at the \
         right file and would pass if the sandbox were removed"
    );
    assert_eq!(
        unsandboxed.len(),
        1,
        "exactly one entry point may decline the sandbox: `serve_with`, which \
         is pid 1 on the bare-metal target and needs mounts, netlink and \
         `reboot(2)` for the life of the machine. Any other opt-out is a \
         hosted build quietly giving up `SEC-005` (#197) and `SEC-019` \
         (#356): {calls:#?}"
    );
    assert!(
        !sandboxed.is_empty(),
        "no entry point asks to be sandboxed, so `SEC-005` (#197) applies to \
         nothing: {calls:#?}"
    );
    assert_eq!(
        sandboxed.len().saturating_add(unsandboxed.len()),
        calls.len(),
        "a call to `serve_inner` passes neither `true` nor `false` on its own \
         line, so this test cannot tell whether it sandboxes: {calls:#?}"
    );
}

/// Both branches of every capability constant compile and are reachable.
///
/// The rule this workspace keeps is `const bool` over `cfg` on an item, so that
/// a platform difference is a value rather than code that only exists where
/// nobody can test it. This is that rule applied to itself.
#[test]
fn both_branches_of_every_capability_constant_are_live() {
    let report = if FILESYSTEM_CAN_BE_DENIED {
        // Not applied here — this process must stay unsandboxed for the other
        // tests in this binary — so only the shape is exercised.
        kmsrs_server::sandbox::Report::NOTHING
    } else {
        kmsrs_server::sandbox::Report::NOTHING
    };
    assert!(report.complete());
    assert_eq!(report.filesystem, Applied::NotOnThisTarget);
}

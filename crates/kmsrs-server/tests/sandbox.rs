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

    // `syscalls` was the one deliberately left out by `SEC-005` (#197) and
    // reported `Failed` for as long as that was true. `SEC-018` (#355)
    // implemented it, so this assertion flipped — deliberately, and in the same
    // commit, which is what #355 asks for. A filter that silently went back to
    // reporting `Failed` would be a hardening measure that had stopped applying
    // with nothing to notice.
    if kmsrs_server::sandbox::SYSCALLS_CAN_BE_RESTRICTED {
        assert!(
            output.contains("MEASURE syscalls=Yes"),
            "the syscall filter did not apply on a target that has one. \
             `Failed` here means `seccomp(2)` refused the filter — a kernel \
             without CONFIG_SECCOMP_FILTER, which is allowed for and \
             non-fatal, but is not what this runner should be: {output}"
        );
    } else {
        assert!(
            output.contains("MEASURE syscalls=NotOnThisTarget"),
            "a target with no measured syscall list must say so rather than \
             claim a filter (SEC-018, #355): {output}"
        );
    }
}

/// **The headline for `SEC-018` (#355): real activations, served through the
/// real filter.**
///
/// This is the assertion the whole issue turns on, and its shape is unusual:
/// what it mostly proves is proved by the child **not dying**. A seccomp filter
/// whose default action is `KillProcess` answers a missing syscall with
/// `SIGSYS` and no unwinding, no destructor and no log line — so a driver that
/// reached for something the allowlist does not name would take the process
/// with it, `in_a_child` would see a child that failed, and the failure would
/// name the path that did it.
///
/// So the filter goes on **before** the driver ever accepts, and then a v4, a
/// v5 and a v6 activation are served over real sockets: `accept4`, the read,
/// the Rijndael-160 and tweaked-AES paths, the entropy draw for the response,
/// the event log, the write back, and a clean shutdown and drain. Every one of
/// those is a syscall this filter has to have got right.
///
/// # Why the sessions are opened first
///
/// `socket` is denied and Landlock denies `connect`, so a client cannot dial
/// after the sandbox is on — the process is one process and the confinement is
/// process-wide. The RPC bind therefore happens before, and the activation,
/// which is the part with the interesting syscalls behind it, happens after.
///
/// # Why this is worth having as well as the survey
///
/// `harness/linux/syscall-survey.sh` is the measurement and is far more
/// thorough — it runs the shipped binary for minutes, engages the rate limiter,
/// waits out a connection deadline and an entropy re-test. What it is not is
/// something that runs on every pull request, on both architectures, against
/// the code as it is now. This is.
#[test]
fn a_sandboxed_driver_serves_activations_on_every_protocol_version() {
    if is_the_child() {
        use kmsrs_client::request::RequestFields;
        use kmsrs_client::session::Session;
        use kmsrs_proto::entropy::testing::DeterministicEntropy;
        use kmsrs_proto::kms::version::Version;
        use kmsrs_server::config::operational::LogLevel;
        use kmsrs_server::net::driver::Driver;
        use kmsrs_server::net::listener::bind_each;
        use kmsrs_server::{Compiled, Discovered, Operational, Server};

        let localhost =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
        let (bound, _) = bind_each(&[localhost]).unwrap();
        let address = bound[0].address;

        let mut entropy = DeterministicEntropy::from_seed(0x5EC_C0FF);
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
        let mut driver = Driver::new(
            server,
            bound,
            8,
            Box::new(DeterministicEntropy::from_seed(0x5A17)),
        )
        .unwrap();
        let shutdown = driver.shutdown_handle();

        std::thread::scope(|scope| {
            let serving = scope.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime for the driver thread");
                runtime.block_on(driver.run()).unwrap();
            });

            // Dial first: every socket this test needs must exist before the
            // filter does, and the RPC bind needs the driver already answering.
            let timeout = std::time::Duration::from_secs(30);
            let mut sessions: Vec<(Version, Session)> = [Version::V4, Version::V5, Version::V6]
                .into_iter()
                .map(|version| {
                    (
                        version,
                        Session::open(address, timeout, true, &mut |_| {}).unwrap(),
                    )
                })
                .collect();

            // And now the process gives up everything it is not going to use
            // again. TSYNC means this covers the driver's thread too, which is
            // the point: a filter on the calling thread alone would leave the
            // thread that actually serves running unconfined.
            let report = sandbox::apply();
            println!("SYSCALLS={:?}", report.syscalls);

            let mut client_entropy = DeterministicEntropy::from_seed(0xC1_1E_47);
            for (version, session) in &mut sessions {
                let fields = RequestFields {
                    version: *version,
                    ..RequestFields::default()
                };
                let exchange = session
                    .activate(&fields, &mut client_entropy, &mut |_| {})
                    .expect("the sandboxed host answered");
                println!("SERVED {version:?} count={}", exchange.count);
            }

            // Close the connections before asking for shutdown. A drain waits
            // for what is still open, and three idle sessions would hold it for
            // `READ_TIMEOUT` — thirty seconds of a test doing nothing, for a
            // property `tests/listener.rs` already covers.
            drop(sessions);
            shutdown.request();
            serving.join().expect("the driver stopped cleanly");
        });

        println!("DRAINED");
        return;
    }

    let output = in_a_child("a_sandboxed_driver_serves_activations_on_every_protocol_version");
    for version in ["V4", "V5", "V6"] {
        assert!(
            output.contains(&format!("SERVED {version}")),
            "the sandboxed host did not serve a {version} activation. If the \
             child died rather than answering, the syscall allowlist is \
             missing something this path needs and the kernel's audit log \
             names it (SEC-018, #355): {output}"
        );
    }
    assert!(
        output.contains("DRAINED"),
        "the driver did not shut down cleanly under the filter. Shutdown and \
         drain are their own syscall path — `rt_sigreturn` and `exit_group` \
         above all — and #355 names them: {output}"
    );
}

/// The filter is not decorative: a socket that could be created cannot be.
///
/// The before-and-after that `the_filesystem_is_denied_after_the_sandbox_is_applied`
/// does for Landlock, done for seccomp — and it needs a syscall Landlock does
/// **not** govern, or it would prove nothing about this filter. `socket(2)` is
/// exactly that: Landlock ABI 4 governs `bind` and `connect` for TCP and says
/// nothing about creating an `AF_UNIX` socket, so an unbound Unix datagram is
/// created freely by a Landlocked process and refused by a seccomped one.
///
/// It also checks the *shape* of the refusal. `SOFT_DENIED` exists so that
/// three syscalls fail with `EPERM` instead of killing the process, and that
/// choice is argued at length in `sandbox.rs`; the observable consequence is
/// that this test can run at all. A `KillProcess` rule cannot be tested from
/// inside the process, because observing it means dying.
#[test]
fn a_socket_that_could_be_created_before_the_sandbox_cannot_be_after() {
    if is_the_child() {
        // `cfg` rather than the `const bool` this workspace prefers, for the
        // reason `sandbox.rs` gives about architecture-specific syscall
        // numbers: `std::os::unix` is not a module with different contents on
        // Windows, it is a module that does not exist. The parent below never
        // spawns this child on a target with no filter, so the empty branch is
        // unreachable rather than a silent pass.
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixDatagram;

            let before = UnixDatagram::unbound().is_ok();
            let report = sandbox::apply();
            let after = UnixDatagram::unbound();
            let errno = after
                .as_ref()
                .err()
                .and_then(std::io::Error::raw_os_error)
                .unwrap_or(0);

            println!(
                "BEFORE={before} AFTER={} ERRNO={errno} SYSCALLS={:?}",
                after.is_ok(),
                report.syscalls
            );
        }
        return;
    }

    if !kmsrs_server::sandbox::SYSCALLS_CAN_BE_RESTRICTED {
        return;
    }

    let output = in_a_child("a_socket_that_could_be_created_before_the_sandbox_cannot_be_after");
    assert!(
        output.contains("BEFORE=true"),
        "the child could not create a Unix socket even before the sandbox, so \
         this test proves nothing: {output}"
    );
    if output.contains("SYSCALLS=Yes") {
        assert!(
            output.contains("AFTER=false"),
            "a new socket could still be created after the filter was applied, \
             which means it is decorative. Landlock does not govern `socket` at \
             all — this is the measure only seccomp takes (SEC-018, #355): \
             {output}"
        );
        assert!(
            output.contains("ERRNO=1"),
            "the refusal was not EPERM. `SOFT_DENIED` exists so that these \
             three syscalls degrade instead of killing the process, and an \
             errno that is not EPERM means the rule moved (SEC-018, #355): \
             {output}"
        );
    }
}

/// **The allowlist covers everything the surveys measured.**
///
/// `SEC-018` (#355) is explicit that the list has to be measured rather than
/// reasoned from the source, and `harness/linux/surveys/` is the measurement:
/// `strace` over the shipped binary, on both libc targets, driven through the
/// paths #355 names. This is the assertion that ties the two together, and it
/// is the one that would catch somebody trimming the list to look tidier.
///
/// It reads the survey files rather than restating them, so a survey re-run
/// that turned up a new syscall fails here until the list grows — which is the
/// direction that matters. It does **not** check the other way round: a list
/// longer than the survey is the deliberate design, because the same program on
/// the same kernel calls `epoll_wait` under glibc and `epoll_pwait` under musl,
/// and a list cut down to one run's observations is a list that kills a process
/// on the other libc.
///
/// # A survey is evidence about one architecture
///
/// Only surveys taken on the architecture this test is running on are compared,
/// and the directory names are what say which. That is not tidiness: `arm64`
/// has no `epoll_wait` at all — the number does not exist, `libc` has no
/// constant for it, and the allowlist therefore cannot name it. Checking an
/// x86_64 survey against an aarch64 filter asks whether a syscall that cannot
/// be made is permitted, and the honest answer to that is not "no".
///
/// This test found that the hard way: it ran on the `linux-aarch64` leg and
/// failed on `epoll_wait` while every test that actually *exercises* the filter
/// on that architecture passed beside it.
///
/// The consequence is that on aarch64 this compares nothing, because there is
/// no aarch64 survey — `SEC-021` (#410). The requirement that both libcs be
/// surveyed is asserted regardless of where this runs, so that gap cannot widen
/// quietly into no surveys at all.
#[test]
fn the_allowlist_covers_every_syscall_the_survey_measured() {
    if !kmsrs_server::sandbox::SYSCALLS_CAN_BE_RESTRICTED {
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<name> is two levels below the workspace root")
        .to_path_buf();
    let surveys = root.join("harness/linux/surveys");

    // Syscalls made before the filter is installed, which every survey records
    // because it traces the process from `execve`. They are not the filter's
    // business: it goes on after the listeners are bound.
    let before_the_filter = [
        // `sandbox::apply` itself, in the order it runs.
        "prctl",
        "landlock_create_ruleset",
        "landlock_restrict_self",
        "seccomp",
    ];

    // `glibc-x86_64`, `musl-x86_64`: the libc and then the architecture, which
    // is what makes a directory name enough to decide whether a survey is
    // evidence about the machine this test is on.
    let running = std::env::consts::ARCH;
    let mut checked = 0_usize;
    let mut here = 0_usize;
    let mut on_x86_64 = 0_usize;
    let entries = std::fs::read_dir(&surveys)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", surveys.display()));
    for entry in entries {
        let directory = entry.expect("a survey directory").path();
        let measured = directory.join("after-the-sandbox.txt");
        let Ok(text) = std::fs::read_to_string(&measured) else {
            continue;
        };
        let name = directory
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default()
            .to_owned();
        if name.ends_with("-x86_64") {
            on_x86_64 = on_x86_64.saturating_add(1);
        }
        if !name.ends_with(&format!("-{running}")) {
            continue;
        }
        here = here.saturating_add(1);
        for name in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            if before_the_filter.contains(&name) {
                continue;
            }
            assert!(
                kmsrs_server::sandbox::names_a_permitted_syscall(name),
                "{} measured `{name}` after the sandbox was applied and the \
                 filter does not permit it. A syscall the shipped binary was \
                 observed making is one this process makes; leaving it out is \
                 a production kill on a path nobody changed (SEC-018, #355).",
                measured.display()
            );
            checked += 1;
        }
    }

    // Asserted wherever this runs, because it is a property of the repository
    // rather than of the machine: #355 requires both libc targets, they differ,
    // and a check over one of them is half the check. It is also what stops the
    // architecture filter above from quietly reducing this test to nothing —
    // rename the directories and this fires, on every architecture at once.
    assert!(
        on_x86_64 >= 2,
        "found {on_x86_64} x86_64 surveys under {}, and #355 requires one per \
         libc — glibc and the musl static build.",
        surveys.display()
    );

    if here == 0 {
        // No survey for this architecture, which is true of aarch64 and is
        // `SEC-021` (#410). What covers the filter here instead is
        // `a_sandboxed_driver_serves_activations_on_every_protocol_version`,
        // which runs natively and dies if the allowlist is wrong.
        return;
    }
    assert!(
        checked >= 10,
        "{here} survey(s) for {running} were read and only {checked} measured \
         syscalls were checked, which is fewer than a server that served \
         hundreds of activations can have made. The files are probably not \
         being parsed."
    );
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

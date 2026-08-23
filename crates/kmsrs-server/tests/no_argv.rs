//! The binary takes no arguments (`CFG-007`, #172), and refuses a
//! configuration it does not understand (`CFG-002`, #167).
//!
//! Run against the real executable rather than against a function, because the
//! property is about the program's contract with whoever starts it — an exit
//! code and a message on stderr — and that is not observable from inside.
//!
//! Both existing projects show what happens when argv handling is an
//! afterthought rather than absent: vlmcsd's man page documents `-h` and `-?`
//! that are not in its own optstring, and py-kms has no `--version` at all
//! while carrying a custom `argv` pre-validator in front of `argparse`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use core::time::Duration;
use std::io::Read;
use std::process::{Child, Command, Stdio};

/// Exit code for arguments that should not have been passed.
const EXIT_BAD_USAGE: i32 = 64;
/// Exit code for a configuration the binary could not understand.
const EXIT_BAD_CONFIG: i32 = 78;

/// What the binary did when it was started.
#[derive(Debug)]
struct Started {
    /// Its exit code, or `None` if it was still running when we gave up
    /// waiting — which for this binary means it got as far as serving.
    code: Option<i32>,
    /// Everything it wrote to stderr before then.
    stderr: String,
}

impl Started {
    /// Whether it rejected its input rather than starting up.
    fn rejected(&self) -> bool {
        matches!(self.code, Some(EXIT_BAD_USAGE | EXIT_BAD_CONFIG))
    }
}

/// `NET-016` (#165), declined as D40: an inherited socket is refused, not
/// ignored.
///
/// The failure this prevents is silence. A `.socket` unit holds 1688 and passes
/// it in; a process that ignored `LISTEN_FDS` would try to bind the port itself
/// and fail with `EADDRINUSE`, or — under `Accept=yes` — be handed a *connection*
/// and run one process per client, which destroys both the stable ePID and the
/// CMID table while continuing to answer. That is how vlmcsd-under-systemd
/// degrades without telling anybody (declined item D20).
#[test]
fn an_inherited_socket_is_refused_rather_than_ignored() {
    let started = start_with(&[], None, &[("LISTEN_FDS", "1"), ("LISTEN_PID", "1")]);
    assert_eq!(
        started.code,
        Some(EXIT_BAD_USAGE),
        "LISTEN_FDS was not refused: {}",
        started.stderr
    );
    assert!(
        started.stderr.contains("LISTEN_FDS"),
        "the refusal does not name what it refused: {}",
        started.stderr
    );
    assert!(
        started.stderr.contains(".socket"),
        "the refusal does not say what to do about it: {}",
        started.stderr
    );
}

/// And without it the binary gets as far as serving, so the refusal above is
/// about the variable rather than about the environment these tests run in.
#[test]
fn no_inherited_socket_is_the_ordinary_case() {
    let started = start_with(&[], None, &[("LISTEN_FDS", "0")]);
    assert_ne!(
        started.code,
        Some(EXIT_BAD_USAGE),
        "LISTEN_FDS=0 was treated as an inherited socket: {}",
        started.stderr
    );
}

/// Start the binary and see what it does.
///
/// The binary **serves until signalled**, so waiting for it to exit is not an
/// option: a successful start-up never returns. Instead it is given a short
/// window to reject its input, and killed if it does not — reaching the point
/// of serving *is* the success condition.
///
/// Note what is deliberately not asserted: that it bound a port. Several of
/// these tests run in parallel and would contend for 1688, and binding is not
/// what `CFG-002` (#167) or `CFG-007` (#172) are about. A bind failure exits
/// with a third code, which `rejected` does not count.
fn start(args: &[&str], config: Option<&str>) -> Started {
    start_with(args, config, &[])
}

/// The same, with extra environment variables.
fn start_with(args: &[&str], config: Option<&str>, environment: &[(&str, &str)]) -> Started {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kmsrsos"));
    command.args(args);
    // Never inherit an activation manager's variables from whatever ran the
    // tests, so each case says what it means.
    command.env_remove("LISTEN_FDS");
    command.env_remove("LISTEN_PID");
    for (name, value) in environment {
        command.env(name, value);
    }
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    // Never inherit the caller's setting, so the test says what it means.
    command.env_remove("KMSRSOS_CONFIG");
    if let Some(document) = config {
        command.env("KMSRSOS_CONFIG", document);
    }

    let mut child = command.spawn().expect("the binary runs");
    let mut stderr = child.stderr.take().expect("stderr was piped");

    // Drain stderr on another thread: a binary that keeps running would
    // otherwise be able to fill the pipe buffer and block.
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });

    let code = wait_briefly(&mut child);
    if code.is_none() {
        // Still running, which means it got past configuration and is serving.
        let _ = child.kill();
        let _ = child.wait();
    }
    let stderr = reader.join().unwrap_or_default();
    Started { code, stderr }
}

/// Wait a short while for the process to exit.
///
/// Three seconds, because the two outcomes are not symmetric: configuration is
/// parsed before anything slow happens, so a rejection is immediate, while
/// "still running" is the success condition and waiting longer cannot change
/// it. A short window can only ever cost a false *success*, and there is no
/// path on which rejection takes seconds.
fn wait_briefly(child: &mut Child) -> Option<i32> {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
    None
}

/// `CFG-007` (#172): any argument at all is an error, and the error names what
/// was passed. Silently ignoring it is worse — an operator who typed something
/// expects it to have had an effect.
#[test]
fn any_argument_is_refused_and_named() {
    for args in [
        vec!["--help"],
        vec!["-h"],
        vec!["--version"],
        vec!["-p", "1688"],
        vec!["/etc/kmsrsos.ini"],
        vec!["--log-level", "debug"],
        vec![""],
    ] {
        let started = start(&args, None);
        assert_eq!(
            started.code,
            Some(EXIT_BAD_USAGE),
            "{args:?} was not refused as a usage error: {}",
            started.stderr
        );
        assert!(
            started.stderr.contains("takes no arguments"),
            "{args:?} produced an unhelpful message: {}",
            started.stderr
        );
        // The message points at the one thing that *is* settable, so the
        // operator is not left guessing.
        assert!(
            started.stderr.contains("KMSRSOS_CONFIG"),
            "{args:?} did not say what is settable: {}",
            started.stderr
        );
    }
}

/// No arguments is the supported invocation, and `CFG-002` (#167): an unset
/// variable means the compiled-in defaults rather than an error.
#[test]
fn no_arguments_and_no_configuration_is_the_supported_invocation() {
    let started = start(&[], None);
    assert!(
        !started.rejected(),
        "the supported invocation was refused ({:?}): {}",
        started.code,
        started.stderr
    );
}

/// `CFG-002` (#167) and `CFG-005` (#170): malformed or unknown is fatal,
/// immediately, with a message that names the problem. Never start degraded.
#[test]
fn a_bad_configuration_exits_non_zero_and_says_why() {
    for (document, expected) in [
        ("this is not toml", "KMSRSOS_CONFIG"),
        // The vlmcsd `Portable`/`Port` prefix-matching shape.
        (r#"log-levels = "debug""#, "log-levels"),
        (r#"log_level = "debug""#, "log_level"),
        (r#"log-level = "shouting""#, "KMSRSOS_CONFIG"),
        ("event-log-capacity = 0", "event-log-capacity"),
        ("event-retention-days = 4000", "event-retention-days"),
    ] {
        let started = start(&[], Some(document));
        assert_eq!(
            started.code,
            Some(EXIT_BAD_CONFIG),
            "{document:?} did not exit as a configuration error: {}",
            started.stderr
        );
        assert!(
            started.stderr.contains(expected),
            "{document:?} produced {}, which does not mention {expected}",
            started.stderr
        );
    }
}

/// A valid document starts, so the test above is not passing by rejecting
/// everything.
#[test]
fn a_good_configuration_is_accepted() {
    let started = start(
        &[],
        Some(
            r#"
            log-level = "debug"
            log-format = "text"
            web-ui = false
            event-log-capacity = 64
            "#,
        ),
    );
    assert!(
        !started.rejected(),
        "a valid document was refused ({:?}): {}",
        started.code,
        started.stderr
    );
}

/// The two failure modes have distinct exit codes, so a supervisor can tell
/// "you told me something wrong" from "something went wrong".
#[test]
fn usage_and_configuration_failures_are_distinguishable() {
    let usage = start(&["--help"], None).code;
    let config = start(&[], Some("nonsense")).code;
    assert_eq!(usage, Some(EXIT_BAD_USAGE));
    assert_eq!(config, Some(EXIT_BAD_CONFIG));
    assert_ne!(usage, config);
}

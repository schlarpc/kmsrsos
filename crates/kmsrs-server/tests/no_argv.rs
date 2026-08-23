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
    reason = "test code: a failed expectation should abort loudly"
)]

use std::process::{Command, Output};

/// Run the binary with the given arguments and environment.
fn run(args: &[&str], config: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kmsrsos"));
    command.args(args);
    // Never inherit the caller's setting, so the test says what it means.
    command.env_remove("KMSRSOS_CONFIG");
    if let Some(document) = config {
        command.env("KMSRSOS_CONFIG", document);
    }
    command.output().expect("the binary runs")
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
        let output = run(&args, None);
        assert!(
            !output.status.success(),
            "{args:?} was accepted, which means it was silently ignored"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("takes no arguments"),
            "{args:?} produced an unhelpful message: {stderr}"
        );
        // The message points at the one thing that *is* settable, so the
        // operator is not left guessing.
        assert!(
            stderr.contains("KMSRSOS_CONFIG"),
            "{args:?} did not say what is settable: {stderr}"
        );
    }
}

/// No arguments is the supported invocation.
#[test]
fn no_arguments_is_accepted() {
    let output = run(&[], None);
    assert!(
        output.status.success(),
        "the supported invocation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `CFG-002` (#167): unset means compiled-in defaults.
#[test]
fn an_unset_config_variable_is_not_an_error() {
    let output = run(&[], None);
    assert!(output.status.success());
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
        let output = run(&[], Some(document));
        assert!(
            !output.status.success(),
            "{document:?} started the server anyway"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "{document:?} produced {stderr}, which does not mention {expected}"
        );
    }
}

/// A valid document starts, so the test above is not passing by rejecting
/// everything.
#[test]
fn a_good_configuration_is_accepted() {
    let output = run(
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
        output.status.success(),
        "a valid document was refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Debug"),
        "the setting took effect: {stderr}"
    );
}

/// The two failure modes have distinct exit codes, so a supervisor can tell
/// "you told me something wrong" from "something went wrong".
#[test]
fn usage_and_configuration_failures_are_distinguishable() {
    let usage = run(&["--help"], None).status.code();
    let config = run(&[], Some("nonsense")).status.code();
    assert_eq!(usage, Some(64));
    assert_eq!(config, Some(78));
    assert_ne!(usage, config);
}

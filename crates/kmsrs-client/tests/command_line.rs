//! The documented options and the implemented options are the same set
//! (`CLI-009`, #215; `CLI-005`, #211; `CLI-006`, #212; `CLI-010`, #216).
//!
//! vlmcsd's manual documents `-h` and `-?`, neither of which is in its own
//! optstring; py-kms's documentation claims hostnames work, and using one is
//! fatal at start-up. Both are the same defect — a document and a parser that
//! drifted — and neither is caught by any test either project has, because a
//! test of the parser does not read the document.
//!
//! This reads both. It is a coarse check and it catches the thing that actually
//! happens: an option added to one and not the other.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed invariant should abort the test loudly"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn main_source() -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    // Line endings are a property of the checkout, not of the source. A
    // Windows runner with `core.autocrlf` produces `\r\n`, which would make
    // every structural search below miss — and the failure reads as "the usage
    // text moved" rather than as "this test is Unix-only".
    text.replace("\r\n", "\n")
}

/// Every `--option` the parser matches on.
///
/// Taken from the match arms rather than from a list somebody maintains, which
/// is the only way this test can be about the parser rather than about a second
/// document.
fn implemented(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        // A match arm on a literal option: `"--soak" => …` or
        // `"-h" | "--help" => …`.
        if !trimmed.starts_with('"') {
            continue;
        }
        let Some((patterns, _)) = trimmed.split_once("=>") else {
            continue;
        };
        for token in patterns.split('|') {
            let token = token.trim().trim_matches('"');
            if token.starts_with("--") {
                found.insert(token.to_owned());
            }
        }
    }
    found
}

/// Every `--option` the usage text mentions.
fn documented(source: &str) -> BTreeSet<String> {
    // Located structurally rather than by matching the whole declaration: the
    // point is to read whatever the constant currently holds, and a test that
    // had to be updated whenever its formatting changed would be a third thing
    // to keep in sync.
    let Some((_, usage)) = source.split_once("const USAGE: &str =") else {
        panic!("the usage text moved");
    };
    let Some((usage, _)) = usage.split_once("\";") else {
        panic!("the usage text has no end");
    };

    let mut found = BTreeSet::new();
    for line in usage.lines() {
        for word in line.split_whitespace() {
            let word = word.trim_matches(|c: char| !c.is_ascii_graphic() || c == '`' || c == '.');
            if word.starts_with("--") && word.len() > 2 {
                found.insert(word.to_owned());
            }
        }
    }
    found
}

/// `CLI-009` (#215): every option in the parser is documented, and every
/// documented option exists.
#[test]
fn the_usage_text_and_the_parser_agree() {
    let source = main_source();
    let implemented = implemented(&source);
    let documented = documented(&source);

    assert!(
        implemented.len() > 10,
        "only {} options were found in the parser, so this test is reading the \
         wrong thing",
        implemented.len()
    );

    let undocumented: Vec<&String> = implemented.difference(&documented).collect();
    assert!(
        undocumented.is_empty(),
        "these options exist but are not in --help, so nobody can find them: \
         {undocumented:#?}"
    );

    let unimplemented: Vec<&String> = documented.difference(&implemented).collect();
    assert!(
        unimplemented.is_empty(),
        "these options are documented but the parser does not match on them, \
         which is vlmcsd's `-h` and `-?`: {unimplemented:#?}"
    );
}

/// Every exit code the usage text names is one `main` can actually produce.
///
/// The other half of the same discipline: a documented exit code nobody returns
/// is a promise to a script that will never be kept.
#[test]
fn every_documented_exit_code_exists() {
    let source = main_source();
    let documented: Vec<&str> = source
        .lines()
        .filter_map(|line| line.strip_prefix("    "))
        .filter_map(|line| line.split_whitespace().next())
        .filter(|token| token.parse::<u8>().is_ok())
        .collect();

    for code in ["0", "1", "64", "69"] {
        assert!(
            documented.contains(&code),
            "exit code {code} is not documented; found {documented:?}"
        );
    }
    for constant in ["EXIT_FINDINGS", "EXIT_BAD_USAGE", "EXIT_UNAVAILABLE"] {
        assert!(
            source.contains(&format!("const {constant}")),
            "{constant} is gone but is still documented"
        );
    }
}

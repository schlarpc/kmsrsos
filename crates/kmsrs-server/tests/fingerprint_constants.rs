//! FP-026: nothing an observer can read is a constant (#265).
//!
//! # The row this implements, and the bug that made it worth implementing
//!
//! The anti-fingerprinting checklist's last row is *"no constant shared across
//! deployments anywhere — audit every `const`"*, and it was the only row with no
//! check behind it. Then `WIRE-010` (#68) turned out to be broken: the driver
//! passed a hardcoded `0x1234_5678` as the association group to every KMS
//! connection, so every `bind_ack` this host had ever sent carried the same
//! value. One packet reads it; two connections prove it (#321).
//!
//! That is exactly the shape of defect this row describes, and it survived
//! because *nothing looked*. The protocol layer took the group as a parameter,
//! which was correct; the platform layer supplied a literal, which nobody
//! grepped for.
//!
//! # What is checked
//!
//! Every field that goes on the wire and must differ between two deployments —
//! or, in some cases, between two connections of one deployment — is assigned
//! from something drawn at runtime rather than from a literal. There are two
//! halves, because there are two ways to get it wrong:
//!
//! * **Assignment.** A literal on the right-hand side of one of these fields is
//!   a finding. That is what #321 was.
//! * **Provenance.** The functions that produce these values take an entropy
//!   source. A field assigned from a *variable* whose value is itself a
//!   constant would pass the first check and fail this one.
//!
//! # Why a source grep rather than a runtime test
//!
//! Because the runtime test exists and did not catch it. `kmsrs-client`'s probe
//! compares association groups across connections, and the comparison was
//! vacuous — it read a field that only the last exchange of each connection
//! ever had written to it. A behavioural check and a structural one fail
//! independently, which is the argument for having both.
//!
//! Test modules are excluded throughout: a fixture asserting that `0xDEAD_BEEF`
//! round-trips is testing the codec, not shipping a constant.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed invariant should abort the test loudly"
)]

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<name> is always two levels below the workspace root")
        .to_path_buf()
}

/// The crates whose code can put a byte on the wire.
const WIRE_CRATES: &[&str] = &["kmsrs-server", "kmsrs-proto", "kmsrs-policy"];

/// Every `.rs` file in those crates, with its path, above the test module.
///
/// Split at `#[cfg(test)]` rather than filtered afterwards: a fixture asserting
/// that `0xDEAD_BEEF` round-trips through the codec is testing the codec, and
/// counting it as a shipped constant would make this test unusable.
fn wire_sources(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for crate_name in WIRE_CRATES {
        let mut stack = vec![root.join("crates").join(crate_name).join("src")];
        while let Some(current) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs")
                    && let Ok(text) = std::fs::read_to_string(&path)
                {
                    let shipped = text
                        .split("#[cfg(test)]")
                        .next()
                        .unwrap_or(&text)
                        .to_owned();
                    out.push((path, shipped));
                }
            }
        }
    }
    assert!(!out.is_empty(), "no wire sources were found");
    out
}

/// Strip `//` comments, so the prose explaining a constant does not read as one.
fn without_comments(text: &str) -> String {
    text.lines()
        .map(|line| match line.find("//") {
            Some(at) => line.split_at(at).0,
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The fields an observer can read and which must not be the same twice.
///
/// Each is a row of the checklist. The comment says what reading a constant
/// there would tell somebody.
const OBSERVABLE_FIELDS: &[(&str, &str)] = &[
    // FP-007 (#68): a genuine host draws one per connection. This is the one
    // that was broken (#321).
    (
        "assoc_group",
        "two connections would be given the same RPC association group",
    ),
    // FP-006 (#118): py-kms's default `364F463A8863D35F` is on the wire of
    // every stock deployment of it, and says which program answered.
    (
        "hardware_id",
        "every deployment would answer with the same hardware ID",
    ),
    // FP-011 (#75): vlmcsd leaks uninitialised stack here; a constant is the
    // other failure, and is a deployment-wide tell.
    (
        "padding",
        "bind_ack and fault padding would be identical everywhere",
    ),
];

/// `FP-026` (#265): no observable field is assigned from a literal.
///
/// The literal `0x1234_5678` in `Driver::register` is what this exists to
/// catch. It was in shipped code, on the wire of every connection, for as long
/// as the driver existed.
#[test]
fn no_observable_field_is_assigned_a_literal() {
    let root = workspace_root();
    let mut findings = Vec::new();

    for (path, text) in wire_sources(&root) {
        for (number, line) in without_comments(&text).lines().enumerate() {
            for (field, consequence) in OBSERVABLE_FIELDS {
                // `field: <value>` in a struct literal, or `field = <value>`.
                let Some((before, after)) = line
                    .split_once(&format!("{field}: "))
                    .or_else(|| line.split_once(&format!("{field} = ")))
                    .map(|(before, after)| (before, after.trim()))
                else {
                    continue;
                };

                // A struct *field declaration* is not an assignment, and its
                // type looks like a value: `pub hardware_id: [u8; 8]`. The
                // `pub` is the tell.
                if before.trim_end().ends_with("pub") {
                    continue;
                }

                // A literal is a number, a character, or an array of them. A
                // path, a call or an identifier is something drawn elsewhere,
                // and `bool`/`u32` are a type in a field declaration.
                // An array *type* is `[u8; 8]` and an array *value* is
                // `[0xA1, 0xB2, …]`: the type has a semicolon inside the
                // brackets and no comma, and the value is the other way round.
                let array_value = after.starts_with('[')
                    && after
                        .split_once(']')
                        .is_some_and(|(inside, _)| inside.contains(','));
                let literal = after.starts_with(|c: char| c.is_ascii_digit()) || array_value;
                if !literal {
                    continue;
                }
                // `0` is the honest answer for a field that is *absent* — the
                // web UI's connections have no association group at all — and
                // is not a value an observer reads off a KMS response.
                if after.starts_with("0,") || after.starts_with("0;") || after == "0" {
                    continue;
                }

                findings.push(format!(
                    "{}:{}: {field} is a literal — {consequence} (FP-026, #265)",
                    path.display(),
                    number.saturating_add(1)
                ));
            }
        }
    }

    assert!(
        findings.is_empty(),
        "these fields are observable on the wire and must differ between \
         deployments, and each is assigned a constant:\n{}",
        findings.join("\n")
    );
}

/// The same rule, for values passed **positionally** (`FP-026`, #265).
///
/// This is the half that matters, and it is the half the field-name check
/// misses. The `WIRE-010` defect was not `assoc_group: 0x1234_5678` — it was
/// `self.server.connection(0x1234_5678, accepting_port)`, a literal handed to a
/// parameter whose *name* is nowhere on that line. Written the obvious way,
/// this test would have passed on the bug it exists for; that was checked by
/// reintroducing it.
///
/// So the sinks are named. There are few of them, they change rarely, and a new
/// one is a deliberate act by somebody who should have read this list.
#[test]
fn no_observable_value_is_passed_positionally_as_a_literal() {
    /// (call, what its first argument is)
    const SINKS: &[(&str, &str)] = &[
        (
            ".connection(",
            "the per-connection association group (FP-007, #68)",
        ),
        (
            "Connection::new(",
            "the per-connection association group (FP-007, #68)",
        ),
        ("HardwareId(", "the per-process hardware ID (FP-006, #118)"),
    ];

    let root = workspace_root();
    let mut findings = Vec::new();

    for (path, text) in wire_sources(&root) {
        for (number, line) in without_comments(&text).lines().enumerate() {
            for (sink, produces) in SINKS {
                let Some((_, after)) = line.split_once(sink) else {
                    continue;
                };
                let argument = after.trim_start();
                let array_value = argument.starts_with('[')
                    && argument
                        .split_once(']')
                        .is_some_and(|(inside, _)| inside.contains(','));
                if argument.starts_with(|c: char| c.is_ascii_digit()) || array_value {
                    findings.push(format!(
                        "{}:{}: `{sink}` is given a literal, and its first \
                         argument is {produces}",
                        path.display(),
                        number.saturating_add(1)
                    ));
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "these calls hand a constant to something an observer reads \
         (FP-026, #265):\n{}",
        findings.join("\n")
    );
}

/// The values behind those fields come from an entropy source.
///
/// The other half. A field assigned from a *variable* passes the check above
/// whatever the variable holds, so this asserts that the four functions which
/// produce observable values take a source — which is what makes the value
/// vary, and what makes a degraded source refusable (`OS-012`, #263).
#[test]
fn every_observable_value_is_drawn_from_an_entropy_source() {
    let root = workspace_root();

    // (file, function, what it produces)
    let producers = [
        (
            "crates/kmsrs-server/src/net/driver.rs",
            "fn association_group",
            "the per-connection association group (FP-007, #68)",
        ),
        (
            "crates/kmsrs-policy/src/identity.rs",
            "fn generate",
            "the ePID and the hardware ID (FP-001, FP-006)",
        ),
        (
            "crates/kmsrs-proto/src/kms/framing.rs",
            "pub fn encode",
            "the response IV and salt (FP-023, #23)",
        ),
        (
            "crates/kmsrs-proto/src/wire/bind.rs",
            "pub fn write_ack",
            "the bind_ack padding (FP-011, #75)",
        ),
    ];

    for (file, function, produces) in producers {
        let text = std::fs::read_to_string(root.join(file))
            .unwrap_or_else(|error| panic!("cannot read {file}: {error}"));
        let at = text
            .find(function)
            .unwrap_or_else(|| panic!("{file} no longer defines `{function}`"));

        // The signature, which is everything up to the opening brace of the
        // body. A generous window rather than a parser: what is being asked is
        // whether an entropy source is among the parameters.
        let signature = text
            .get(at..)
            .and_then(|rest| rest.split_once(" {"))
            .map(|(signature, _)| signature)
            .unwrap_or_default();

        assert!(
            signature.contains("Entropy"),
            "{function} in {file} produces {produces} and does not take an \
             entropy source, so whatever it produces is decided somewhere \
             else (FP-026, #265):\n{signature}"
        );
    }
}

/// The audit is looking at code that contains the shape it forbids.
///
/// Without this the greps above pass on an empty set — including if the field
/// names are renamed, which is the way a structural check silently stops
/// checking.
#[test]
fn the_audit_is_looking_at_the_right_fields() {
    let root = workspace_root();
    let all: String = wire_sources(&root)
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join("\n");

    for (field, _) in OBSERVABLE_FIELDS {
        assert!(
            all.contains(field),
            "no shipped source mentions `{field}`, so the audit for it proves \
             nothing and would keep passing if it came back"
        );
    }
}

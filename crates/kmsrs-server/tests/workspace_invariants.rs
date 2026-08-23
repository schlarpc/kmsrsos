//! Structural invariants of the workspace, checked as tests.
//!
//! The four properties here are the ones that are cheap to state, expensive to
//! rediscover, and silently lost the first time somebody adds a dependency in a
//! hurry:
//!
//! * `ARCH-001` (#1) — `kmsrs-dbgen` is unreachable from anything that ships.
//! * `ARCH-008` (#8) / `SEC-001` (#193) — every crate is under the workspace
//!   lint table, with exactly one documented exception.
//! * `ARCH-016` (#16) — one pinned MSRV, and it matches the pinned toolchain.
//!
//! They live in `kmsrs-server` because a virtual workspace root cannot hold
//! tests and because the server binary is the artifact whose dependency closure
//! the first of them is about.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed invariant should abort the test loudly"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The crate whose dependencies must never be reachable from a shipped binary
/// (`ARCH-001`, #1).
const QUARANTINED_CRATE: &str = "kmsrs-dbgen";

/// The binaries whose dependency closure is audited. `kmsrs-vectors` is test
/// infrastructure and `kmsrs-dbgen` is the quarantine subject, so neither is a
/// shipped artifact.
const SHIPPED_BINARIES: &[&str] = &["kmsrs-server", "kmsrs-client", "kmsrs-os"];

/// The one crate permitted to define its own lint table instead of inheriting
/// the workspace's, because it holds the single documented unsafe boundary
/// (`SEC-001`, #193; `OS-013`, #264).
const UNSAFE_BOUNDARY_CRATE: &str = "kmsrs-os";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<name> is always two levels below the workspace root")
        .to_path_buf()
}

fn read_toml(path: &Path) -> toml::Table {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    toml::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

/// Every `[[package]]` in `Cargo.lock`, mapped to the names it depends on.
///
/// `Cargo.lock` merges normal, build and dev dependencies into one list, so this
/// graph is an over-approximation of what actually links into a binary. For an
/// assertion of the form "this name must not appear", over-approximating is the
/// safe direction: a test built on it cannot pass when the real closure is
/// contaminated.
fn lockfile_graph(root: &Path) -> BTreeMap<String, Vec<String>> {
    let lock = read_toml(&root.join("Cargo.lock"));
    let packages = lock["package"]
        .as_array()
        .expect("Cargo.lock always has a package array");

    let mut graph = BTreeMap::new();
    for package in packages {
        let name = package["name"]
            .as_str()
            .expect("every locked package is named")
            .to_owned();
        let deps = package
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .map(|deps| {
                deps.iter()
                    .filter_map(toml::Value::as_str)
                    // Lock entries disambiguate duplicate versions as
                    // "name version"; only the name matters here.
                    .map(|dep| dep.split_whitespace().next().unwrap_or(dep).to_owned())
                    .collect()
            })
            .unwrap_or_default();
        graph.insert(name, deps);
    }
    graph
}

fn reachable_from(graph: &BTreeMap<String, Vec<String>>, roots: &[&str]) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut queue: Vec<String> = roots.iter().map(|r| (*r).to_owned()).collect();
    while let Some(name) = queue.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if let Some(deps) = graph.get(&name) {
            queue.extend(deps.iter().cloned());
        }
    }
    seen
}

fn crate_manifests(root: &Path) -> Vec<(String, PathBuf)> {
    let mut found: Vec<(String, PathBuf)> = std::fs::read_dir(root.join("crates"))
        .expect("the crates/ directory exists")
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| path.is_dir())
        .map(|path| {
            let name = path
                .file_name()
                .expect("a directory always has a final component")
                .to_string_lossy()
                .into_owned();
            (name, path.join("Cargo.toml"))
        })
        .collect();
    found.sort();
    found
}

/// `ARCH-001` (#1): the extractor's dependencies — XML, gzip, HTTP — must not be
/// reachable from a binary that has no disk I/O and parses nothing but its own
/// wire protocol. That is the entire reason `kmsrs-dbgen` is a separate crate,
/// and it is a property of the dependency graph rather than a claim in a
/// comment, so it can be checked.
#[test]
fn dbgen_is_unreachable_from_every_shipped_binary() {
    let root = workspace_root();
    let graph = lockfile_graph(&root);

    assert!(
        graph.contains_key(QUARANTINED_CRATE),
        "{QUARANTINED_CRATE} is missing from Cargo.lock; this test would pass vacuously"
    );

    for binary in SHIPPED_BINARIES {
        assert!(
            graph.contains_key(*binary),
            "{binary} is missing from Cargo.lock; this test would pass vacuously"
        );
        let closure = reachable_from(&graph, &[binary]);
        assert!(
            !closure.contains(QUARANTINED_CRATE),
            "{QUARANTINED_CRATE} is reachable from {binary}. The crate split exists to make \
             its XML/gzip/HTTP dependencies unreachable from the runtime binary (ARCH-001, #1); \
             if the binary genuinely needs something from it, move that thing into kmsrs-db \
             and let build.rs generate it."
        );
    }
}

/// `ARCH-008` (#8) and `SEC-001` (#193): a crate that forgets `[lints] workspace
/// = true` opts silently out of the deny list *and* out of `forbid(unsafe_code)`
/// — and nothing else in the build would notice.
#[test]
fn every_crate_inherits_the_workspace_lint_table() {
    let root = workspace_root();

    let workspace = read_toml(&root.join("Cargo.toml"));
    assert_eq!(
        workspace["workspace"]["lints"]["rust"]["unsafe_code"].as_str(),
        Some("forbid"),
        "the workspace lint table must forbid unsafe_code (SEC-001, #193). `forbid` rather \
         than `deny` is deliberate: it cannot be lifted by an inner `allow`."
    );

    for (name, manifest_path) in crate_manifests(&root) {
        let manifest = read_toml(&manifest_path);
        let lints = manifest
            .get("lints")
            .unwrap_or_else(|| panic!("{name} has no [lints] table (ARCH-008, #8)"));

        if name == UNSAFE_BOUNDARY_CRATE {
            assert_eq!(
                lints["rust"]["unsafe_code"].as_str(),
                Some("deny"),
                "{name} holds the single documented unsafe boundary (OS-013, #264), so it \
                 defines its own lint table — but unsafe_code must still be denied, so that \
                 the boundary has to name itself with an explicit expect and a safety comment."
            );

            // Its table is a copy, so it can drift. Every lint the workspace
            // sets must be set here to at least the same severity; otherwise
            // adding a deny to the workspace would silently exempt this crate,
            // which is the one crate where that matters most.
            for table in ["rust", "clippy"] {
                let workspace_lints = workspace["workspace"]["lints"][table]
                    .as_table()
                    .expect("the workspace lint table has rust and clippy sections");
                for (lint, level) in workspace_lints {
                    // The one deliberate difference, asserted separately above.
                    if lint == "unsafe_code" {
                        continue;
                    }
                    assert_eq!(
                        lints[table].get(lint.as_str()),
                        Some(level),
                        "{name}'s copied lint table has drifted: {table}::{lint} is set to \
                         {level:?} at the workspace level but not here (ARCH-008, #8)"
                    );
                }
            }
        } else {
            assert_eq!(
                lints.get("workspace").and_then(toml::Value::as_bool),
                Some(true),
                "{name} must say `[lints] workspace = true`. Only {UNSAFE_BOUNDARY_CRATE} may \
                 define its own table (SEC-001, #193)."
            );
        }
    }
}

/// `ARCH-002` (#2) and axiom A7: the sans-io crates must stay `no_std`.
///
/// This is the cheapest possible enforcement of "the core performs no I/O" —
/// with `std` unavailable there is no socket type to reach for, so the property
/// is checked by the compiler on every build rather than by review. Deleting
/// the attribute is the one edit that would quietly give it all back, so that
/// is what this test watches for.
#[test]
fn the_sans_io_crates_are_no_std() {
    let root = workspace_root();
    for crate_name in ["kmsrs-proto", "kmsrs-policy", "kmsrs-crypto", "kmsrs-db"] {
        let lib = root.join("crates").join(crate_name).join("src/lib.rs");
        let source = std::fs::read_to_string(&lib)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", lib.display()));
        assert!(
            source.lines().any(|line| line.trim() == "#![no_std]"),
            "{crate_name} has lost its #![no_std] attribute. The core crates take bytes and a \
             clock reading and return events; with std available, nothing stops a socket \
             appearing inside one (ARCH-002, #2)."
        );
    }
}

/// `ARCH-016` (#16): two files name a Rust version, and a build where they
/// disagree is one where the MSRV claim is untested — Nix would use one and a
/// rustup user the other.
#[test]
fn msrv_matches_the_pinned_toolchain() {
    let root = workspace_root();

    let workspace = read_toml(&root.join("Cargo.toml"));
    let msrv = workspace["workspace"]["package"]["rust-version"]
        .as_str()
        .expect("the workspace pins rust-version");

    let toolchain = read_toml(&root.join("rust-toolchain.toml"));
    let channel = toolchain["toolchain"]["channel"]
        .as_str()
        .expect("rust-toolchain.toml pins a channel");

    assert_eq!(
        msrv, channel,
        "workspace.package.rust-version and rust-toolchain.toml's channel must match \
         (ARCH-016, #16)"
    );
}

/// `ARCH-001` (#1): a crate directory that is not a workspace member still
/// compiles when something depends on it, but escapes `--workspace` — so it is
/// never linted, never tested and never covered.
#[test]
fn every_crate_directory_is_a_workspace_member() {
    let root = workspace_root();
    let workspace = read_toml(&root.join("Cargo.toml"));
    let members: BTreeSet<&str> = workspace["workspace"]["members"]
        .as_array()
        .expect("the workspace lists members")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();

    for (name, _) in crate_manifests(&root) {
        let path = format!("crates/{name}");
        assert!(
            members.contains(path.as_str()),
            "{path} exists but is not a workspace member, so --workspace skips it"
        );
    }
}

/// `CFG-009` (#174): every feature a crate declares must be referenced by some
/// source file, or it is a knob that does nothing.
///
/// vlmcsd is the cautionary example, and the list is long: make variables that
/// emit macros no source file reads; a `CAT=1` flag adding `-DONE_FILE` that
/// nothing tests; an `INCLUDE_BETAS` flag that `-V` *prints* but that changes
/// no behaviour; and `_CRYPTO_INTERNAL`, defined but never tested. Each is a
/// configuration surface an operator can set, reason about, and be wrong about.
///
/// Checked as a property of the tree rather than trusted, because the compiler
/// has no opinion: an unused feature is not a warning in Cargo, only a lie in
/// the manifest.
#[test]
fn every_declared_feature_is_referenced_in_source() {
    let root = workspace_root();
    let mut unreferenced = Vec::new();

    for (name, manifest_path) in crate_manifests(&root) {
        let manifest = read_toml(&manifest_path);
        let Some(features) = manifest.get("features").and_then(toml::Value::as_table) else {
            continue;
        };
        let Some(crate_dir) = manifest_path.parent() else {
            continue;
        };
        let sources = rust_sources(crate_dir);

        for feature in features.keys() {
            // `default` is Cargo's own, and is referenced by Cargo rather than
            // by any source file.
            if feature == "default" {
                continue;
            }
            let needle_a = format!("feature = \"{feature}\"");
            let needle_b = format!("feature=\"{feature}\"");
            let referenced = sources
                .iter()
                .any(|text| text.contains(&needle_a) || text.contains(&needle_b));
            if !referenced {
                unreferenced.push(format!("{name}/{feature}"));
            }
        }
    }

    assert!(
        unreferenced.is_empty(),
        "these features are declared but referenced by no source file, so \
         setting them does nothing: {unreferenced:?}"
    );
}

/// `SEC-011` (#203): exactly one type in the shipped tree can be built from a
/// serialised document, and it is the one the escape hatch names.
///
/// py-kms unpickles a configuration from a world-writable temp directory on
/// `stop` and `status`. That is local arbitrary code execution as whoever runs
/// the command, and it is not a bug in the pickle call — it is the consequence
/// of there being *any* deserialisation of *anything* that did not come off the
/// wire. The defence is structural: if `Deserialize` appears on one type in one
/// file, there is nowhere else for such a path to hide.
///
/// Checked by reading the source rather than by reflection, because the
/// property is "no such code exists" and only the source can answer that. Its
/// other half — that there is nothing to deserialise *from* — is
/// `no_shipped_crate_touches_the_filesystem` below: a deserialiser with no
/// input is inert, so the two together leave the escape hatch's environment
/// variable as the only way in, and a local attacker who can set that can
/// already do worse than change a log format.
#[test]
fn only_the_operational_config_can_be_deserialised() {
    let root = workspace_root();
    let mut offenders: Vec<String> = Vec::new();

    for (name, manifest) in crate_manifests(&root) {
        if name == QUARANTINED_CRATE {
            continue;
        }
        let Some(source) = manifest.parent().map(|dir| dir.join("src")) else {
            continue;
        };
        for (path, text) in rust_sources_with_paths(&source) {
            // The doc comments in `config/` discuss `Deserialize` at length,
            // which is the point of them; what matters is the derive.
            let derives_it = text.lines().any(|line| {
                let line = line.trim();
                !line.starts_with("//")
                    && (line.contains("derive(") && line.contains("Deserialize")
                        || line.contains("impl") && line.contains("Deserialize for"))
            });
            if derives_it {
                offenders.push(path.display().to_string());
            }
        }
    }

    let expected = ["operational.rs"];
    let unexpected: Vec<&String> = offenders
        .iter()
        .filter(|path| !expected.iter().any(|allowed| path.ends_with(allowed)))
        .collect();

    assert!(
        unexpected.is_empty(),
        "these files derive `Deserialize` outside the one type the escape hatch          names (`CFG-002`, #167). Every one is a path from a document to a          program state, which is the shape of the py-kms unpickle: {unexpected:?}"
    );
    assert!(
        !offenders.is_empty(),
        "no file derives `Deserialize` at all, so this test is not looking at          the right tree and would pass if one were added"
    );
}

/// Every `.rs` file under a directory, read into memory.
fn rust_sources(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // `target` is build output, not source.
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                out.push(text);
            }
        }
    }
    out
}

/// Axiom A5, `OBS-001` (#177) and `OBS-015` (#191): a shipped binary performs
/// no filesystem I/O at all.
///
/// No file sink, no rotation, no pidfile, no temp files — so there is nothing
/// to configure a path for, nothing to run out of disk, and nothing for two
/// instances on one host to collide over. py-kms's pretty-printer is the
/// counter-example: it keeps newline bookkeeping in fixed paths under the
/// system temp directory, so two instances silently corrupt each other's
/// output.
///
/// Checked by naming the APIs rather than by reading a comment, because the
/// property is easy to lose one call at a time. `kmsrs-dbgen` is exempt: it is
/// a host-only tool whose entire job is reading artifacts, and
/// `dbgen_is_unreachable_from_every_shipped_binary` is what keeps it out of the
/// shipped closure.
#[test]
fn no_shipped_crate_touches_the_filesystem() {
    /// Names that mean "this code opens something".
    const FORBIDDEN: &[&str] = &[
        "std::fs",
        "File::open",
        "File::create",
        "OpenOptions",
        "temp_dir",
        "TempDir",
        "NamedTempFile",
        "read_to_string(",
        "write(&path",
    ];

    let root = workspace_root();
    let mut offences = Vec::new();

    for (name, manifest_path) in crate_manifests(&root) {
        if name == QUARANTINED_CRATE {
            continue;
        }
        let Some(source_dir) = manifest_path.parent().map(|dir| dir.join("src")) else {
            continue;
        };
        if !source_dir.is_dir() {
            continue;
        }

        for (path, text) in rust_sources_with_paths(&source_dir) {
            for needle in FORBIDDEN {
                if text.contains(needle) {
                    offences.push(format!("{}: {needle}", path.display()));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "these shipped sources reach for the filesystem, which axiom A5 \
         forbids: {offences:#?}"
    );
}

/// `SEC-013` (#205): nothing secret is embedded in the shipped artifact.
///
/// Not "the secrets are well protected" — there are none. The three protocol
/// keys are published constants compiled into every genuine KMS host and both
/// existing emulators (`CRY-001`, #40); RFC 2136 dynamic DNS update is declined
/// partly because it would have needed the first real one (declined item D15);
/// the web UI is read-only so there is no credential to hold (D27); and axiom
/// A5 forbids the disk a key file would live on.
///
/// Three checks, because "no secrets" fails in three ways: a credential-shaped
/// name is how one gets added deliberately, a PEM block is how one gets pasted
/// in, and a fourth constant in `kmsrs-crypto::keys` is how one gets added
/// while looking like it belongs.
///
/// Deliberately *not* checked: every `[u8; N]` constant in the tree. The
/// protocol is made of published GUIDs — transfer syntaxes, interface IDs,
/// application IDs — so that test is all noise and its failures would be
/// silenced rather than read.
#[test]
fn no_secret_material_is_embedded() {
    /// Names that mean "this is a credential".
    const CREDENTIAL_SHAPED: &[&str] = &[
        "password",
        "passphrase",
        "secret_key",
        "api_key",
        "private_key",
        "tsig",
        "bearer",
        "credential",
    ];

    /// Text that means somebody pasted key material in.
    const PASTED_KEY_MATERIAL: &[&str] = &["-----BEGIN", "PRIVATE KEY", "ssh-rsa", "AKIA"];

    let root = workspace_root();
    let mut offences = Vec::new();

    for (name, manifest_path) in crate_manifests(&root) {
        if name == QUARANTINED_CRATE {
            continue;
        }
        let Some(source_dir) = manifest_path.parent().map(|dir| dir.join("src")) else {
            continue;
        };
        if !source_dir.is_dir() {
            continue;
        }

        for (path, text) in rust_sources_with_paths(&source_dir) {
            for (number, line) in text.lines().enumerate() {
                // Comments are stripped: this file's own prose says
                // "password", and so does the doc comment above.
                let code = match line.find("//") {
                    Some(comment) => line.split_at(comment).0,
                    None => line,
                };
                let lowered = code.to_ascii_lowercase();

                let hit = CREDENTIAL_SHAPED
                    .iter()
                    .find(|needle| lowered.contains(*needle))
                    .or_else(|| {
                        PASTED_KEY_MATERIAL
                            .iter()
                            .find(|needle| code.contains(*needle))
                    });

                if let Some(needle) = hit {
                    offences.push(format!(
                        "{}:{}: {needle}",
                        path.display(),
                        number.saturating_add(1)
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "these shipped sources look like they carry a secret, and there is \
         nothing in this program that should have one (SEC-013, #205): \
         {offences:#?}"
    );

    // The crypto crate holds exactly three key constants, all published, all
    // Microsoft's. A fourth is how key material would arrive looking like it
    // belonged, and it is the one place in the tree where it would.
    let keys = std::fs::read_to_string(root.join("crates/kmsrs-crypto/src/keys.rs"))
        .expect("the published key constants live here");
    let declared: Vec<&str> = keys
        .lines()
        .filter(|line| line.trim_start().starts_with("pub const "))
        .collect();
    assert_eq!(
        declared.len(),
        3,
        "kmsrs-crypto::keys declares {} constants; it holds the three published \
         Microsoft keys and nothing else (SEC-013, #205): {declared:#?}",
        declared.len()
    );
    for key in ["pub const V4:", "pub const V5:", "pub const V6:"] {
        assert!(keys.contains(key), "{key} is no longer where it was");
    }
}

/// Every `.rs` file under a directory, with its path.
fn rust_sources_with_paths(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                out.push((path, text));
            }
        }
    }
    out
}

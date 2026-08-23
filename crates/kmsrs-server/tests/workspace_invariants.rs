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

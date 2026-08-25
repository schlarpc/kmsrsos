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

/// The crate that is process 1 on the bare-metal target, and so the one crate
/// that must open paths (`OS-021`, #337). It answers to
/// `pid1_opens_nothing_but_pseudo_filesystems` instead of to
/// `no_shipped_crate_touches_the_filesystem`.
const PID1_CRATE: &str = "kmsrs-os";

/// Names that mean "this code opens something".
///
/// `rustix::fs::open` is on the list because `OS-021` (#337) brought rustix
/// into the tree for `mount(2)`, and a safe binding to `openat(2)` arrived in
/// the same crate. Axiom A5 is about what the program reaches for, not about
/// which crate spells the syscall, so leaving it off would have made the ban
/// avoidable by import.
const OPENS_SOMETHING: &[&str] = &[
    "std::fs",
    "File::open",
    "File::create",
    "OpenOptions",
    "temp_dir",
    "TempDir",
    "NamedTempFile",
    "read_to_string(",
    "write(&path",
    "rustix::fs::open",
];

// No crate is permitted to define its own lint table any more. `kmsrs-os` held
// the single documented unsafe boundary (`SEC-001`, #193; `OS-013`, #264) and
// set `deny` where the workspace sets `forbid`, so a boundary would have had to
// name itself. `OS-018` (#334) removed that crate with Hermit, and the boundary
// went with it — never having contained any `unsafe` at all. The workspace
// `forbid` is now absolute, which is a stronger statement than this test was
// originally written to make.

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

        assert_eq!(
            lints.get("workspace").and_then(toml::Value::as_bool),
            Some(true),
            "{name} must say `[lints] workspace = true`. No crate defines its own \
             table any more (SEC-001, #193; OS-018, #334)."
        );
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

/// A copy of `text` with `//` line comments removed.
///
/// Doc comments start with `//` too, so this takes those as well, which is what
/// is wanted: a `///` block is prose about the code, not code.
fn without_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| match line.find("//") {
            Some(at) => line.split_at(at).0,
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
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

/// `OS-013` (#264): the unsafe boundary is empty, and there is exactly one
/// place it could ever be.
///
/// `SEC-001` (#193), `OS-013` (#264): no `unsafe` anywhere, at all.
///
/// The workspace lint table sets `unsafe_code = "forbid"`, and `forbid` cannot
/// be lifted by an inner `allow` — which is the property that makes it worth
/// setting there. `kmsrs-os` used to be the single crate permitted to override
/// it with the weaker `deny`, so that the documented boundary would have to
/// name itself with an explicit `#[expect(unsafe_code)]` and a safety comment.
///
/// It never contained any. `OS-018` (#334) removed that crate along with
/// Hermit, so the exception is gone and the statement is now the simple one:
/// no shipped crate contains the word, not even in a comment. The over-reach is
/// deliberate — a reader grepping this tree for `unsafe` should find nothing
/// and never have to decide which hits are real.
///
/// The `OS-021` (#337) pid-1 work is where this would come under pressure,
/// since `mount(2)` and `waitpid(2)` are syscalls. `rustix` is the answer and
/// the reason it was chosen: safe bindings mean the boundary stays empty rather
/// than reopening.
#[test]
fn no_shipped_crate_contains_unsafe() {
    let root = workspace_root();

    let mut found = Vec::new();
    for (name, manifest_path) in crate_manifests(&root) {
        let Some(source_dir) = manifest_path.parent().map(|dir| dir.join("src")) else {
            continue;
        };
        if !source_dir.is_dir() {
            continue;
        }
        for (path, text) in rust_sources_with_paths(&source_dir) {
            for (number, line) in text.lines().enumerate() {
                // `unsafe_code` is the lint's name and appears in the prose that
                // explains the policy; `unsafe` as a keyword is what matters.
                let code = match line.find("//") {
                    Some(comment) => line.split_at(comment).0,
                    None => line,
                };
                if code.contains("unsafe ") || code.contains("unsafe(") {
                    found.push(format!(
                        "{name} {}:{}",
                        path.display(),
                        number.saturating_add(1)
                    ));
                }
            }
        }
    }

    assert!(
        found.is_empty(),
        "no crate in this workspace may contain `unsafe` (SEC-001, #193; \
         OS-013, #264). If a boundary is genuinely needed, reopening it is a \
         decision for a review and this test is what should be updated in the \
         same commit: {found:#?}"
    );
}

/// `ARCH-005` (#5): one driver, and no `[patch.crates-io]` anywhere.
///
/// The issue originally called for tokio on Linux and Windows and a blocking
/// `std::net` driver on Hermit. The superseding decision is one `mio` loop on
/// all three (see `docs/decisions.md`), and two of the three properties it
/// asked for survive that change unchanged — they were always the point:
///
/// * **No async abstraction layer.** There is one loop, so there is nothing for
///   an async trait to abstract over.
/// * **No `[patch.crates-io]`.** Adopting `hermit-os/tokio` would have needed
///   one, and a patch table is workspace-*global*: pinning Hermit to a
///   four-commit fork of tokio 1.45.0 would have pinned Linux and Windows to it
///   too. That is the decision this assertion protects, and it protects it from
///   any future dependency, not only from that one.
#[test]
fn there_is_one_driver_and_no_patched_dependencies() {
    let root = workspace_root();

    let workspace = std::fs::read_to_string(root.join("Cargo.toml")).expect("the manifest");
    assert!(
        !workspace.contains("[patch."),
        "a [patch] table appeared. It is workspace-global, so patching one \
         target's dependency pins every target to the same fork (ARCH-005, #5)."
    );
    for (_, manifest_path) in crate_manifests(&root) {
        let text = std::fs::read_to_string(&manifest_path).unwrap_or_default();
        assert!(
            !text.contains("[patch."),
            "{} declares a [patch] table",
            manifest_path.display()
        );
    }

    // One driver module, not one per platform. The platform differences that
    // remain are named capabilities in `platform.rs` whose branches all compile
    // everywhere — never a `cfg` on an item, which only ever compiles on the
    // platform that cannot be tested.
    let net = root.join("crates/kmsrs-server/src/net");
    let drivers: Vec<String> = std::fs::read_dir(&net)
        .expect("the net module exists")
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.contains("driver"))
        .collect();
    assert_eq!(
        drivers.len(),
        1,
        "there should be exactly one driver, and there are {drivers:?}"
    );

    // Exactly one async runtime, and it is tokio (`OS-024`, #340). The ban on
    // tokio was for Hermit, which needed a four-commit fork; that target is
    // gone (`OS-018`, #334) and `kmsrs-server` is pid 1 on its replacement,
    // which means DHCP renewal, SNTP polling and a reaper all want timers that
    // mio does not have.
    //
    // The other two stay out. The reason was never "async is bad", it is that a
    // second runtime is a second scheduler with its own idea of when work runs.
    // `deny.toml` bans them by name (`SEC-009`, #201); this catches the case
    // where somebody adds one and updates the ban list in the same breath.
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("the lockfile");
    assert!(
        lock.contains("name = \"tokio\""),
        "tokio is not in the lockfile, so this test would pass vacuously"
    );
    // `mio` is not in this list: it is tokio's own reactor and arrives as a
    // transitive dependency. Banning it would be banning tokio's insides.
    for runtime in ["name = \"async-std\"", "name = \"smol\""] {
        assert!(
            !lock.contains(runtime),
            "{runtime} is in the lockfile; there is one runtime and it is tokio \
             (ARCH-005, #5; OS-024, #340)"
        );
    }
}

/// `OS-007` (#258), and what makes `OS-020` (#336) safe: the wall clock is read
/// in exactly two places, and neither is on the request path.
///
/// The rule is usually stated as an efficiency one — a syscall per request that
/// answers a question nothing needs. It is really a correctness one, and
/// `OS-020` is where that becomes visible. That issue's definition of done says
/// **"a step is applied in a way `kmsrs-policy` cannot observe as time
/// reversal"**, and the reason it is satisfied is not that the SNTP client is
/// careful:
///
/// * `clock_settime(CLOCK_REALTIME)` does not move `CLOCK_MONOTONIC`.
/// * Every deadline in this program is monotonic — tokio's for connections, an
///   injected reading for the activation interval (`ARCH-004`, #4).
/// * So there is no path by which a step can be seen as time going backwards.
///
/// That property survives only while the second bullet holds. One
/// `SystemTime::now()` in the request path would break it silently, and the
/// symptom would be a host that miscounts activations for a few hours after a
/// clock correction — which is not a symptom anybody traces back to here. So it
/// is asserted rather than left to the comment above.
///
/// The two permitted readers, and why each is not the request path:
///
/// | Where | Why |
/// |---|---|
/// | `entry.rs` | once at start-up, to bound the randomised activation date in the ePID (`ID-007`, #112). Stable for the life of the process, which `ID-001` (#106) requires |
/// | `net/sntp.rs` | the thing whose job is the clock (`OS-020`, #336) |
#[test]
fn the_wall_clock_is_read_in_exactly_two_places() {
    /// Names that mean "this reads or writes the wall clock".
    ///
    /// `FileTime::UNIX_EPOCH` in `kmsrs-proto` is a constant, not a read — the
    /// needle is the `std` path and the `rustix` realtime clock, not the words.
    const READS_THE_WALL_CLOCK: &[&str] = &[
        "SystemTime::now",
        "std::time::UNIX_EPOCH",
        "ClockId::Realtime",
    ];

    /// The files that may. Everything else in every shipped crate may not.
    const PERMITTED: &[&str] = &["entry.rs", "sntp.rs"];

    let root = workspace_root();
    let mut offences = Vec::new();
    let mut found = Vec::new();

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
            // Comments stripped first (`POL-020`, #346). The rule is about what
            // the program *does*, and a module that explains why it may not
            // read the wall clock has to be able to name the call it is not
            // making. `platform_invariants.rs`'s sibling check has always done
            // this; matching raw text here meant the prose was linted instead
            // of the code.
            let code = without_line_comments(&text);
            for needle in READS_THE_WALL_CLOCK {
                if !code.contains(needle) {
                    continue;
                }
                let file = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                found.push(file.to_owned());
                if !PERMITTED.contains(&file) {
                    offences.push(format!("{}: {needle}", path.display()));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "these read the wall clock, and only {PERMITTED:?} may (`OS-007`, #258). \
         Every deadline in this program is monotonic, which is the whole reason \
         `OS-020` (#336) can step the clock without `kmsrs-policy` observing \
         time reversal: {offences:#?}"
    );
    for permitted in PERMITTED {
        assert!(
            found.iter().any(|file| file == permitted),
            "{permitted} no longer reads the wall clock, so this test is not \
             looking at the right tree and would pass if the request path grew a \
             `SystemTime::now()`"
        );
    }
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
/// shipped closure. `kmsrs-os` is exempt for a different reason and under a
/// narrower rule — see [`pid1_opens_nothing_but_pseudo_filesystems`].
#[test]
fn no_shipped_crate_touches_the_filesystem() {
    let root = workspace_root();
    let mut offences = Vec::new();

    for (name, manifest_path) in crate_manifests(&root) {
        if name == QUARANTINED_CRATE || name == PID1_CRATE {
            continue;
        }
        let Some(source_dir) = manifest_path.parent().map(|dir| dir.join("src")) else {
            continue;
        };
        if !source_dir.is_dir() {
            continue;
        }

        for (path, text) in rust_sources_with_paths(&source_dir) {
            for needle in OPENS_SOMETHING {
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

/// Axiom A5 for pid 1, which cannot be the blanket ban and is not weaker for it
/// (`OS-021`, #337; `OS-028`, #345).
///
/// `kmsrs-os` is the one shipped crate that must open paths. Mounting `/proc`
/// is an open; finding the consoles the kernel registered is a read of
/// `/proc/consoles`; writing to them is an open of a node under `/dev`. None of
/// that is storage, and on this target it *cannot* become storage: the kernel is
/// built with `CONFIG_BLOCK` unset, so there is no block layer for a real
/// filesystem to be mounted from.
///
/// So the rule for this crate is a whitelist of prefixes rather than a ban, and
/// it is checked the same way — by reading the source for the paths it names.
/// The failure this prevents is the one the blanket ban prevents everywhere
/// else: a configuration file, a state file, a log file, arriving one call at a
/// time in the only crate where `open` is unremarkable.
#[test]
fn pid1_opens_nothing_but_pseudo_filesystems() {
    /// The only trees pid 1 may name. Every one is a kernel interface that
    /// exists in RAM.
    const PSEUDO: &[&str] = &["/proc/", "/sys/", "/dev/"];

    /// Bare mount points, which are paths without a trailing separator and so
    /// are not matched by the prefixes above.
    const MOUNT_POINTS: &[&str] = &["/proc", "/sys", "/dev"];

    let root = workspace_root();
    let source_dir = root.join("crates").join(PID1_CRATE).join("src");
    assert!(
        source_dir.is_dir(),
        "{PID1_CRATE} has no src/; this test would pass vacuously"
    );

    let mut named = Vec::new();
    let mut offences = Vec::new();
    for (path, text) in rust_sources_with_paths(&source_dir) {
        for literal in absolute_path_literals(&text) {
            named.push(literal.clone());
            let allowed = PSEUDO.iter().any(|prefix| literal.starts_with(prefix))
                || MOUNT_POINTS.contains(&literal.as_str());
            if !allowed {
                offences.push(format!("{}: {literal}", path.display()));
            }
        }
    }

    assert!(
        !named.is_empty(),
        "no absolute path literal was found in {PID1_CRATE}; this test is not \
         looking at the right tree and would pass if a state file were added"
    );
    assert!(
        offences.is_empty(),
        "pid 1 named a path outside /proc, /sys and /dev. Axiom A5 says this \
         machine has no storage, and the kernel it runs on has no block layer \
         to give it any (`OS-021`, #337): {offences:#?}"
    );
}

/// Every double-quoted string literal in `text` that looks like an absolute
/// Unix path.
///
/// Crude on purpose. It over-collects — a doc comment's example path is a
/// string to nobody — and over-collecting is the safe direction, because a
/// false positive is an argument at review and a false negative is the state
/// file this is here to catch. Doc comments are excluded for exactly that
/// reason: this tree's prose is full of `/dev/console` and `/nix/store`.
fn absolute_path_literals(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        // Splitting on the quote character puts the quoted pieces at the odd
        // indices, which is the whole parser. An escaped quote inside a literal
        // shifts that parity and yields nonsense pieces; none of them starts
        // with a separator, so they fall out below rather than needing a real
        // lexer here.
        for literal in line.split('"').skip(1).step_by(2) {
            if literal.starts_with('/') && literal.len() > 1 {
                found.push(literal.to_owned());
            }
        }
    }
    found
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

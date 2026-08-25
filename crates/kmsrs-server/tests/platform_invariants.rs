//! Per-target invariants, checked against the source rather than against a
//! comment (`OS-007`, #258; `ARCH-015`, #15).
//!
//! This file was mostly about Hermit — a target with no CI runner, where a
//! wrong assumption surfaced as a hang in a VM rather than as a failing
//! assertion, so the properties that kept it working were stated as facts about
//! the tree and checked on every host. `OS-018` (#334) removed that target and
//! most of this went with it: the `OS-010` (#261) socket-option audit existed
//! because Hermit's `setsockopt` was a stub, and there is no longer a platform
//! where a `set_*` call silently does nothing.
//!
//! What survives is the one invariant that was never really about Hermit. The
//! wall clock is read exactly once, and that is a property of the *design* —
//! it is what lets this host serve correctly with a clock nobody has
//! disciplined, which on the `OS-017` (#333) target is still the situation
//! until `OS-020` (#336) lands.

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

/// Every `.rs` file under a directory, with its path.
fn rust_sources(dir: &Path) -> Vec<(PathBuf, String)> {
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

/// The crates that end up inside a shipped binary.
///
/// `kmsrs-dbgen` is the quarantined host-only tool and `kmsrs-vectors` is test
/// infrastructure, so neither ships. `kmsrs-client` is a diagnostic tool that
/// is never part of the served binary.
const SHIPPED_CRATES: &[&str] = &[
    "kmsrs-server",
    "kmsrs-proto",
    "kmsrs-policy",
    "kmsrs-crypto",
    "kmsrs-db",
    "kmsrs-os",
];

/// Source text of every shipped crate, excluding its tests directory.
fn shipped_sources(root: &Path) -> Vec<(PathBuf, String)> {
    SHIPPED_CRATES
        .iter()
        .map(|name| root.join("crates").join(name).join("src"))
        .filter(|dir| dir.is_dir())
        .flat_map(|dir| rust_sources(&dir))
        .collect()
}

/// Strip `//` and `//!` comment text, so a grep for an API name does not match
/// the paragraph explaining why the API is not used.
///
/// Deliberately crude: it does not understand block comments or string
/// literals, and it does not need to. Over-matching is the safe direction for
/// a test of the form "this name must not appear".
fn without_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| match line.find("//") {
            Some(at) => line.split_at(at).0,
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `OS-007` (#258): the wall clock is read exactly once, at start-up.
///
/// Nothing here may depend on the wall clock's accuracy, and the way that is
/// guaranteed is by there being only one read: `main`'s, which bounds the
/// randomised activation date inside the ePID (`ID-007`, #112).
///
/// This mattered on Hermit, whose `SystemTime` was one CMOS RTC read plus local
/// ticks. It still matters: on the `OS-017` (#333) target the clock comes from
/// kvmclock and nothing disciplines it until `OS-020` (#336), so a host with a
/// wrong hypervisor clock is a guest with a confidently wrong clock.
///
/// Every deadline in the driver is measured against the injected monotonic
/// clock (`ARCH-004`, #4), and the v6 response key derives from the *client's*
/// timestamp rather than ours (`CRY-007`, #46) — so a host whose clock is a
/// year out still activates every client that reaches it.
#[test]
fn the_wall_clock_is_read_exactly_once() {
    let root = workspace_root();
    let mut reads = Vec::new();

    for (path, text) in shipped_sources(&root) {
        for (number, line) in without_line_comments(&text).lines().enumerate() {
            // `SystemTime::now` is the only way to read a wall clock in this
            // tree. `FileTime::UNIX_EPOCH` and `UNIX_EPOCH_AS_FILETIME` are
            // constants in the protocol's own time module, not clock reads, so
            // matching on the epoch name would be matching on arithmetic.
            if line.contains("SystemTime::now") {
                reads.push(format!("{}:{}", path.display(), number.saturating_add(1)));
            }
        }
    }

    assert_eq!(
        reads.len(),
        1,
        "the wall clock must be read in exactly one place — `today()` in \
         kmsrs-server/src/entry.rs. Anything else is a dependency on a clock \
         no NTP has disciplined (OS-007, #258). Found: {reads:#?}"
    );
    assert!(
        reads.iter().all(|at| at.contains("entry.rs")),
        "the one wall-clock read moved out of the shared entry point: \
         {reads:#?}"
    );
}

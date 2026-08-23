//! Per-target invariants, checked against the source rather than against a
//! comment (`OS-007`, #258; `OS-010`, #261; `ARCH-015`, #15).
//!
//! Everything here is about the target this test suite **cannot** run on.
//! Hermit is a unikernel: there is no CI runner for it, no debugger to attach,
//! and a wrong assumption surfaces as a hang in a VM rather than as a failing
//! assertion. So the properties that keep it working are stated as facts about
//! the tree — which option is set where, how many wall-clock reads exist, which
//! `cfg` predicates are relied on — and checked on every host.
//!
//! That is a weaker guarantee than running the code, and it is the strongest
//! one available until `OS-001` (#252) can boot. It catches the failure that
//! actually happens: somebody adds a `setsockopt` call, or a second
//! `SystemTime::now()`, on a Linux box where both work perfectly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed invariant should abort the test loudly"
)]

use kmsrs_server::platform::{HermitBehaviour, SOCKET_OPTIONS};
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
/// infrastructure, so neither is subject to a platform rule about what runs on
/// Hermit. `kmsrs-client` is a diagnostic tool that is never built for Hermit.
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

/// `OS-010` (#261): every socket option the server sets has an audit row.
///
/// The audit's value is that it is complete. A `set_*` call that nobody
/// classified is exactly the shape of the defect this issue exists to prevent —
/// a call that succeeds on Linux and Windows and is a silent no-op on the
/// target nobody can watch.
#[test]
fn every_socket_option_the_server_sets_is_audited() {
    let root = workspace_root();
    let net = root.join("crates/kmsrs-server/src/net");
    assert!(net.is_dir(), "the net module is where sockets are made");

    let audited: Vec<&str> = SOCKET_OPTIONS
        .iter()
        .filter_map(|use_| use_.setter)
        .collect();

    let mut unaudited = Vec::new();
    for (path, text) in rust_sources(&net) {
        for line in without_line_comments(&text).lines() {
            // `socket2` and `std` both spell their setters `set_<option>`, and
            // the ones that matter are always called on a socket.
            let Some(at) = line.find("socket.set_") else {
                continue;
            };
            let call = line.split_at(at).1.trim_start_matches("socket.");
            let name: String = call
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !audited.contains(&name.as_str()) {
                unaudited.push(format!("{}: {name}", path.display()));
            }
        }
    }

    assert!(
        unaudited.is_empty(),
        "these socket options are set without an OS-010 audit row in \
         kmsrs-server/src/platform.rs, so nobody has said what Hermit does \
         with them: {unaudited:#?}"
    );
}

/// The audit is not stale in the other direction either: a row claiming the
/// server sets an option must correspond to a call that exists.
///
/// Without this, deleting a `setsockopt` leaves behind a row asserting a
/// property about code that is gone — and the next reader believes it.
#[test]
fn every_audited_setter_is_actually_called() {
    let root = workspace_root();
    let net = root.join("crates/kmsrs-server/src/net");
    let sources: String = rust_sources(&net)
        .into_iter()
        .map(|(_, text)| without_line_comments(&text))
        .collect::<Vec<_>>()
        .join("\n");

    for use_ in SOCKET_OPTIONS {
        if let Some(setter) = use_.setter {
            assert!(
                sources.contains(setter),
                "the audit says {} is set via {setter}, but no call exists",
                use_.option
            );
        }
    }
}

/// A row for an option the server does not set must not claim to be reached.
///
/// `Unreachable` means "the code exists but Hermit never runs it", which is a
/// claim about a call. An option with no call at all is not unreachable, it is
/// absent, and conflating the two hides the day somebody adds the call.
#[test]
fn unreachable_is_only_claimed_for_options_that_are_set() {
    for use_ in SOCKET_OPTIONS {
        if use_.hermit == HermitBehaviour::Unreachable {
            assert!(
                use_.setter.is_some(),
                "{} is recorded as unreachable on Hermit but is never set \
                 anywhere, which is a different thing",
                use_.option
            );
        }
    }
}

/// `OS-007` (#258): the wall clock is read exactly once, at start-up.
///
/// Hermit's `SystemTime` is one CMOS RTC read plus local ticks — one-second
/// granularity, no pvclock, no NTP, no slew, and it drifts. Nothing here may
/// depend on its accuracy, and the way that is guaranteed is by there being
/// only one read: `main`'s, which bounds the randomised activation date inside
/// the ePID (`ID-007`, #112).
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
         Hermit does not have (OS-007, #258). Found: {reads:#?}"
    );
    assert!(
        reads.iter().all(|at| at.contains("entry.rs")),
        "the one wall-clock read moved out of the shared entry point: \
         {reads:#?}"
    );
}

/// `ARCH-015` (#15): every `cfg(unix)` in our own code says which branch
/// Hermit takes.
///
/// Hermit is not `target_family = "unix"`, so a `#[cfg(unix)]` silently takes
/// the *non*-Unix branch there — which is sometimes right and sometimes a bug,
/// and looks identical either way. Most of the hermit-os/tokio fork's diff is
/// this one mistake repeated.
///
/// The rule is not "do not use `cfg(unix)`", which would be unenforceable and
/// wrong; it is that a use must be accompanied by a note saying which branch
/// Hermit lands in and whether that was intended. Checked by requiring the word
/// `Hermit` within a few lines of the predicate.
#[test]
fn every_cfg_unix_says_what_hermit_does() {
    /// How many lines around the predicate count as "accompanied".
    const WINDOW: usize = 16;

    let root = workspace_root();
    let mut silent = Vec::new();

    for (path, text) in shipped_sources(&root) {
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.contains("cfg(unix)") && !line.contains("cfg(target_family = \"unix\")") {
                continue;
            }
            let from = index.saturating_sub(WINDOW);
            let to = index.saturating_add(WINDOW).min(lines.len());
            let context = lines[from..to].join("\n");
            if !context.contains("Hermit") {
                silent.push(format!("{}:{}", path.display(), index.saturating_add(1)));
            }
        }
    }

    assert!(
        silent.is_empty(),
        "these uses of cfg(unix) do not say which branch Hermit takes, and \
         Hermit is not target_family = \"unix\" (ARCH-015, #15): {silent:#?}"
    );
}

/// The `cfg(unix)` audit is looking at a tree that contains one.
///
/// A test that greps for a pattern passes vacuously the moment the pattern
/// stops occurring — including when the test is pointed at the wrong
/// directory. This fails in that case instead.
#[test]
fn the_cfg_unix_audit_has_something_to_audit() {
    let root = workspace_root();
    let uses = shipped_sources(&root)
        .iter()
        .filter(|(_, text)| text.contains("cfg(unix)"))
        .count();
    assert!(
        uses > 0,
        "no shipped source uses cfg(unix), so every_cfg_unix_says_what_hermit_does \
         proves nothing and would keep passing if one were added"
    );
}

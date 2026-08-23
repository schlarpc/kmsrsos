//! What the Hermit build is pinned to, and what it must never grow back
//! (`PKG-013`, #250; `PKG-014`, #251).
//!
//! Hermit is the target nothing in this test suite can execute, so every
//! property that would otherwise be checked by running it has to be checked
//! against the files that describe the build. Three of them are worth naming,
//! because each was a live failure before it was a pin:
//!
//! * All Hermit targets are **Tier 3**. There is no rustup `rust-std`, so the
//!   build takes `hermit-os/rust-std-hermit`, which is rebuilt per *exact*
//!   stable release. A component built for 1.96.1 does not work with 1.96.2,
//!   and the failure is `can't find crate for core` at the bottom of a
//!   dependency tree rather than anything that names a version.
//! * The `hermit` crate is not a library. Its `lib.rs` is empty for every
//!   configuration this project would use, and its `build.rs` shells out to a
//!   nested `cargo run --package=xtask` that builds the kernel from a git
//!   submodule against its own lockfile and its own nightly. Nothing crane
//!   vendors, and a build script that runs `cargo` is a build script that wants
//!   the network. So the crate is not a dependency, and the two link flags it
//!   would have emitted are injected by the flake instead.
//! * Those flags are `-L native=…` and `-l static:-bundle=hermit`. The
//!   `-bundle` is not what upstream's build script emits and is not optional
//!   here: without it `rustc` adopts every member of `libhermit.a` as one of
//!   its own objects, the kernel's compiled-C intrinsics have no `.llvmbc`
//!   section, and `lto = "fat"` fails with "failed to get bitcode from object
//!   file". That is a link error in a *release* build of a target CI does not
//!   run, i.e. the last place anybody looks.

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

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// The `url = "…";` a flake input declares, read out of `flake.nix`.
///
/// Read rather than evaluated because a test that ran `nix eval` would need Nix
/// on the machine running it, and the property being checked is a property of
/// the text: that two files agree about a version number.
fn input_url(name: &str) -> String {
    let flake = read("flake.nix");
    let mut lines = flake.lines().skip_while(|line| {
        let trimmed = line.trim_start();
        !(trimmed.starts_with(&format!("{name} =")) || trimmed.starts_with(&format!("{name}.url")))
    });
    let block: String = lines
        .by_ref()
        .take_while(|line| !line.trim_start().starts_with("};"))
        .chain(std::iter::once("};"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !block.trim().is_empty(),
        "flake.nix declares no input named `{name}` (PKG-014, #251)"
    );

    let url_line = block
        .lines()
        .find(|line| line.trim_start().starts_with("url ="))
        .unwrap_or_else(|| panic!("the `{name}` flake input has no url"));

    url_line
        .split('"')
        .nth(1)
        .unwrap_or_else(|| panic!("the `{name}` url is not a quoted string: {url_line}"))
        .to_owned()
}

fn toolchain_channel() -> String {
    let toolchain = read("rust-toolchain.toml")
        .parse::<toml::Table>()
        .expect("rust-toolchain.toml is not valid TOML");
    toolchain["toolchain"]["channel"]
        .as_str()
        .expect("the toolchain channel is a string")
        .to_owned()
}

/// `PKG-014` (#251): the Tier 3 `rust-std` matches the toolchain exactly.
///
/// One version, in two files, that must be the same version. The component is
/// built per exact stable release, so a bump to `rust-toolchain.toml` that does
/// not bump the flake input produces a `rust-std` for a compiler that no longer
/// exists — and the error rustc gives names neither file.
#[test]
fn the_hermit_rust_std_matches_the_pinned_toolchain() {
    let channel = toolchain_channel();
    let url = input_url("rust-std-hermit");

    assert!(
        url.contains(&format!("/download/{channel}/")),
        "the rust-std-hermit input is not release {channel}, which is what \
         rust-toolchain.toml pins. rust-std-hermit is built per exact stable \
         release; the two must be bumped together (PKG-014, #251).\n  {url}"
    );
    assert!(
        url.ends_with(&format!("rust-std-{channel}-x86_64-unknown-hermit.tar.gz")),
        "the rust-std-hermit input names a release directory and an artefact \
         that disagree, so the fetched component is not the one the URL \
         claims (PKG-014, #251).\n  {url}"
    );
}

/// The kernel is pinned to a commit, not a branch.
///
/// A branch is a moving target, and this one moves: the kernel's tags stopped
/// tracking releases at 0.8.0 while its `Cargo.toml` went on to 0.13, so
/// neither `main` nor a tag would name the revision that upstream CI actually
/// runs in QEMU. The one that does is `hermit-rs`'s `kernel` submodule.
#[test]
fn the_hermit_kernel_is_pinned_to_a_revision() {
    let url = input_url("hermit-kernel");
    let rev = url
        .rsplit('/')
        .next()
        .expect("a github: url has path components");

    assert_eq!(
        rev.len(),
        40,
        "the kernel input ends in `{rev}`, which is not a full commit hash. A \
         branch or a tag is a moving target (PKG-014, #251)."
    );
    assert!(
        rev.chars().all(|c| c.is_ascii_hexdigit()),
        "the kernel revision is not hexadecimal: {rev}"
    );
}

/// Both Hermit inputs are locked, like everything else this build fetches.
///
/// `PKG-006` (#243) is the general rule and `packaging_invariants.rs` enforces
/// its other half — that `flake.nix` calls no fetcher. The two are the same
/// property from opposite ends: an input is pinned by `flake.lock`, and a
/// fetcher inside the build is not.
#[test]
fn both_hermit_inputs_are_locked() {
    let lock = read("flake.lock");

    for input in ["hermit-kernel", "rust-std-hermit"] {
        let key = format!("\"{input}\": {{");
        let start = lock.find(&key).unwrap_or_else(|| {
            panic!("flake.lock has no node for `{input}` (PKG-014, #251)");
        });
        // A locked node is a few hundred bytes; a window is enough to tell
        // "locked with a hash" from "declared and never resolved" without
        // pulling a JSON parser into a crate that ships.
        let window = &lock[start..lock.len().min(start.saturating_add(1024))];
        assert!(
            window.contains("\"narHash\""),
            "the `{input}` node in flake.lock has no narHash, so nothing pins \
             its contents (PKG-006, #243)"
        );
    }

    // And the locked kernel is the revision the flake asked for, rather than
    // whatever a `nix flake update` last happened to resolve.
    let url = input_url("hermit-kernel");
    let rev = url.rsplit('/').next().unwrap();
    assert!(
        lock.contains(&format!("\"rev\": \"{rev}\"")),
        "flake.lock does not pin the kernel at {rev}; run `nix flake lock`"
    );
}

/// `PKG-014` (#251): the workspace itself stays on stable.
///
/// The alternative to the `rust-std-hermit` component is
/// `-Z build-std=std,panic_abort`, which would put every crate that ships on
/// nightly to gain nothing the pinned component does not already give. The
/// kernel's own nightly is a different thing — a build input for one
/// derivation, like the pinned MSVC CRT — and is named once, in the flake.
#[test]
fn nothing_that_ships_is_built_on_nightly() {
    let toolchain = read("rust-toolchain.toml");
    assert!(
        !toolchain.contains("nightly"),
        "rust-toolchain.toml names a nightly; the Hermit target is served by \
         the pinned rust-std-hermit component precisely so that it does not \
         have to (PKG-014, #251)"
    );

    // Comments are allowed to say the words — the kernel derivation's do, and
    // explaining why the workspace does not use `build-std` requires naming it.
    // What must not exist is a line of Nix that passes it.
    let flake = read("flake.nix");
    for line in flake.lines() {
        let trimmed = line.trim_start();
        assert!(
            !trimmed.contains("build-std") || trimmed.starts_with('#'),
            "flake.nix passes build-std to a workspace build:\n  {trimmed}\n\
             Only the kernel derivation may, and it does that through the \
             kernel's own xtask (PKG-014, #251)."
        );
    }
}

/// `PKG-013` (#250): the `hermit` crate is not, and must not become, a
/// dependency of anything that ships.
///
/// It is not a library — it is a build script that runs `cargo` — and adopting
/// it would drag a second lockfile, a second toolchain and a network fetch into
/// the middle of a crane build. Whatever it would have emitted, the flake
/// injects; see [`the_kernel_is_linked_without_being_bundled`].
///
/// The same argument as `kmsrs-dbgen`'s (`ARCH-001`, #1): the way to keep a
/// dependency out of the runtime binary is for nothing the binary depends on to
/// name it.
#[test]
fn the_hermit_crate_is_not_a_dependency() {
    let lock = read("Cargo.lock")
        .parse::<toml::Table>()
        .expect("Cargo.lock is not valid TOML");
    let packages = lock["package"].as_array().unwrap();

    for package in packages {
        let name = package["name"].as_str().unwrap();
        assert!(
            !matches!(name, "hermit" | "hermit-abi" | "hermit-kernel"),
            "`{name}` is in the lockfile. The Hermit kernel is a separate Nix \
             derivation and its link flags are injected by the flake; a crate \
             that builds it from a build script is what PKG-013 (#250) exists \
             to avoid."
        );
    }
}

/// `PKG-013` (#250): the kernel archive reaches the linker, not `rustc`'s LTO.
///
/// `-l static=hermit` — which is what the upstream build script emits — makes
/// `rustc` bundle the archive's members as its own objects. The kernel's
/// `compiler-builtins` intrinsics are compiled C with no `.llvmbc` section, so
/// `lto = "fat"` then fails outright. `-bundle` says what was meant: this is a
/// foreign static library.
///
/// The trap is that the failure needs a *release* build of a target CI does not
/// run, so the debug build everybody tries first works fine.
#[test]
fn the_kernel_is_linked_without_being_bundled() {
    let flake = read("flake.nix");

    assert!(
        flake.contains("-l static:-bundle=hermit"),
        "the Hermit link flags no longer say -bundle. With `lto = \"fat\"` in \
         the release profile, bundling libhermit.a fails with \"failed to get \
         bitcode from object file\" (PKG-013, #250)."
    );
    assert!(
        flake.contains("--sysroot="),
        "the Hermit build no longer names a sysroot explicitly. rustc derives \
         its sysroot from the resolved path of its own executable, so a joined \
         toolchain reached through a symlink finds the original one and cannot \
         see the Tier 3 rust-std (PKG-014, #251)."
    );

    // The release profile is what makes the above load-bearing. If fat LTO
    // ever goes away, this test should be reconsidered rather than silently
    // kept passing by a flag that no longer matters.
    let manifest = read("Cargo.toml");
    assert!(
        manifest.contains(r#"lto = "fat""#),
        "the release profile no longer uses fat LTO; re-check whether the \
         Hermit -bundle modifier is still the right answer (PKG-013, #250)"
    );
}

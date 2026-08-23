//! The unikernel's feature set, and the disk it therefore cannot reach
//! (`OS-006`, #257).
//!
//! Axiom A5 says no disk I/O: no files, no temp files, no databases, no log
//! files. On Linux and Windows that is a promise this program keeps, and
//! `workspace_invariants.rs` checks it by grepping for the APIs that would
//! break it. On Hermit it can be something better than a promise.
//!
//! Hermit has no block device driver of any kind. What it has instead are two
//! optional ways for a guest to reach storage, and both are Cargo features of
//! the kernel:
//!
//! * **`virtio-fs`**, a device — the one an operator would attach in a
//!   hypervisor GUI.
//! * **`uhyve`**, a *hypercall* interface with `open`/`read`/`write`/`close`
//!   and a `UHYVE_MOUNT` path map. This one is easy to miss, because an audit
//!   that goes looking for drivers does not find it.
//!
//! Neither is compiled in, so on that target A5 is enforced by the absence of
//! the code rather than by our policy about it. `write-pcap-file` is out for
//! the same reason from the other end: it writes capture files to a guest path.
//!
//! This is checked against `flake.nix` because that is where the list lives and
//! there is nowhere else it could be checked from — the kernel is a separate
//! program built by a separate derivation, and the feature set is the only part
//! of it this repository decides.

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

fn flake() -> String {
    let path = workspace_root().join("flake.nix");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// The kernel features the flake enables, read out of the list it declares.
fn kernel_features() -> Vec<String> {
    let flake = flake();
    let list = flake
        .split_once("hermitKernelFeatures = [")
        .expect("flake.nix no longer declares hermitKernelFeatures (OS-006, #257)")
        .1
        .split_once("];")
        .expect("the hermitKernelFeatures list is not terminated")
        .0;

    let features: Vec<String> = list
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix('"')?.strip_suffix('"').map(str::to_owned)
        })
        .collect();

    assert!(
        !features.is_empty(),
        "the kernel feature list parsed as empty, so every assertion about it \
         would pass vacuously (OS-006, #257)"
    );
    features
}

/// `OS-006` (#257): nothing that can open a file is compiled into the kernel.
///
/// The two that matter are `virtio-fs` and `uhyve`; the rest are here because
/// an audit narrowed to the features that exist today says nothing about the
/// next one somebody enables while chasing an unrelated problem.
#[test]
fn no_filesystem_transport_is_compiled_in() {
    let features = kernel_features();

    for forbidden in [
        // A filesystem, as a device.
        "virtio-fs",
        "fs",
        "fuse",
        // A filesystem, as a hypercall — the one a driver audit misses.
        "uhyve",
        // Host file access through the debug channel.
        "semihosting",
        // An image the loader would hand the guest as a root filesystem.
        "initramfs",
        // Writes packet captures to a guest path.
        "write-pcap-file",
        // Newlib brings a C library with a `fopen` in it.
        "newlib",
    ] {
        assert!(
            !features.iter().any(|feature| feature == forbidden),
            "the Hermit kernel is built with `{forbidden}`, which gives the \
             guest a way to reach storage. Axiom A5 is structural on this \
             target precisely because no such feature is enabled \
             (OS-006, #257)."
        );
    }
}

/// The set is *pinned*, not merely trimmed, and unconditionally so.
///
/// A list of features means nothing if the kernel's defaults are also on: the
/// default set contains `virtio-fs`, `uhyve` and `fsgsbase`, so a feature list
/// passed without `--no-default-features` turns them all back on and every
/// assertion above still passes.
///
/// Which is not hypothetical. The kernel derivation used to take a `features`
/// parameter, one caller defaulted it to `null`, and `null` meant "pass no
/// feature flags at all" — so `packages.hermit-kernel` had the trimmed set
/// while every artefact that ships was built from upstream's defaults. The
/// tests in this file all passed, because they read this list rather than the
/// flags the build ran.
///
/// So there are two guards now. This one is that the flags are unconditional:
/// no `features == null`, no `optionalString`, nothing that can evaluate to an
/// empty string. The other is `checks.hermit-kernel-features`, which reads the
/// compiled archive.
#[test]
fn the_feature_set_replaces_the_kernel_defaults() {
    let flake = flake();

    assert!(
        flake.contains("--no-default-features \\"),
        "the kernel build no longer passes --no-default-features, so the \
         kernel's own defaults — which include virtio-fs, uhyve and fsgsbase — \
         are back (OS-006, #257)"
    );

    // The kernel derivation takes no `features` argument. One feature set, one
    // call path, nothing for two callers to disagree about.
    assert!(
        !flake.contains("hermitKernelFor = { system, features"),
        "the kernel derivation has grown a `features` parameter again. It had \
         one, a caller defaulted it to null, and the shipped kernel was built \
         from upstream's defaults for six commits (OS-006, #257)."
    );
}

/// The trimming stopped short of the features the host needs to work.
///
/// The failure this prevents is quiet: a kernel without `dhcpv4` boots, prints
/// nothing unusual, and never gets an address. `hermit-boot` would catch it,
/// but this says which line is wrong.
#[test]
fn the_features_the_host_actually_needs_are_present() {
    let features = kernel_features();

    for (required, why) in [
        ("loader", "the hermit-loader is what boots the application"),
        ("tcp", "a KMS host is a TCP server"),
        (
            "dhcpv4",
            "the guest has no other way to get an address (OS-003)",
        ),
        ("virtio-net", "the only network device this deployment has"),
        ("pci", "virtio-net is a PCI device on QEMU"),
    ] {
        assert!(
            features.iter().any(|feature| feature == required),
            "the Hermit kernel is built without `{required}`: {why}"
        );
    }
}

/// No feature is listed twice.
///
/// Harmless to cargo, and not harmless to read: a duplicate is how a list gets
/// edited in two places and agrees with itself in neither.
#[test]
fn the_feature_list_has_no_duplicates() {
    let mut features = kernel_features();
    let before = features.len();
    features.sort_unstable();
    features.dedup();
    assert_eq!(
        features.len(),
        before,
        "a kernel feature is listed twice (OS-006, #257)"
    );
}

/// The kernel does not demand a CPU feature a hypervisor may not expose
/// (`OS-006`, #257).
///
/// A separate concern from A5, and the one that was found by booting the image
/// rather than by reading anything. With `fsgsbase` on, the kernel *refuses to
/// run* on a processor without the FSGSBASE instruction family — and that is
/// every one of Proxmox's stock CPU models. What an operator sees is a reset
/// loop; the single line explaining it scrolls past before the machine reboots,
/// so the symptom carries no information at all.
///
/// Without the feature the kernel uses RDMSR/WRMSR, which costs an amount of
/// time per thread switch that a host answering one 384-byte request per client
/// per few hours will never measure.
///
/// `checks.hermit-kernel-features` asserts the same thing against the compiled
/// archive, which is the half that would have caught the build ignoring this
/// list.
#[test]
fn the_kernel_needs_no_cpu_feature_a_stock_model_lacks() {
    let features = kernel_features();

    // Absent from kvm64, qemu64 and x86-64-v2; present in `host` on any Ivy
    // Bridge or EPYC. Not worth a boot failure.
    assert!(
        !features.iter().any(|feature| feature == "fsgsbase"),
        "the Hermit kernel is built with `fsgsbase`, which makes it refuse to \
         run — as a reset loop, with no readable diagnostic — on a CPU model \
         that does not expose the instruction family (OS-006, #257)"
    );
}

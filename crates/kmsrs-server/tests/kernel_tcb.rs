//! What is in the bare-metal machine's TCB, asserted against the **built**
//! kernel configuration (`OS-023`, #339; `OS-025`, #342).
//!
//! # Why the built config and not the allowlist
//!
//! `os/linux/config.nix` holds a list of symbols to enable and a list to
//! disable. `os/linux/kernel.config` is what `make olddefconfig` produced from
//! them, and **the two are not the same statement**. `olddefconfig` answers for
//! every symbol nobody named, and it answers `y` far more often than one would
//! guess:
//!
//! * `OS-006` (#257) is the original lesson — a test that read the list rather
//!   than the kernel.
//! * `OS-026` (#343) is the same lesson recurring. `CONFIG_INPUT` and
//!   `CONFIG_ACPI_BUTTON` were already on, as dependencies of the console, and
//!   so were `CONFIG_KEYBOARD_ATKBD`, all of `CONFIG_MOUSE_PS2` and
//!   `CONFIG_SERIO`. None of them appeared in the allowlist. This machine had
//!   an AT keyboard driver in its TCB for two issues before anybody noticed.
//!
//! So this reads the generated file. It is checked in precisely so that it can
//! be read — by a reviewer in a diff, and by this.
//!
//! # Two directions, and both matter
//!
//! [`the_subsystems_that_must_stay_out_are_out`] is the security half: axiom A5
//! and the small-TCB claim.
//!
//! [`every_driver_the_platform_matrix_needs_is_in`] is the other half, and it
//! exists because `OS-023` (#339) is a pare-back and `OS-025` (#342) is a
//! matrix, and they pull in opposite directions on the same file. Removing a
//! driver the matrix promises is how a supported platform silently becomes an
//! unsupported one — which is exactly the failure #342 was filed about, since
//! a missing NIC driver produces a machine that boots, reports `listening`, and
//! serves nobody forever.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
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

/// The generated configuration, as text.
fn built_config() -> String {
    let path = workspace_root().join("os/linux/kernel.config");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    // A guard against the whole file being the wrong thing. `make
    // olddefconfig` writes this banner; the allowlist in `config.nix` does not,
    // and reading that by mistake is the failure this test exists to prevent.
    assert!(
        text.contains("Automatically generated file"),
        "{} is not a generated kernel configuration. This test must read what \
         the kernel was *built* with, not the list that was supposed to produce \
         it (`OS-006`, #257)",
        path.display()
    );
    text
}

/// Whether a symbol is set to `y` in the built configuration.
fn enabled(config: &str, symbol: &str) -> bool {
    config
        .lines()
        .any(|line| line.trim() == format!("CONFIG_{symbol}=y"))
}

/// Whether the configuration mentions a symbol at all, on or off.
///
/// `# CONFIG_X is not set` is how the generated file records an option that
/// exists and is off, which is what distinguishes "off" from "misspelled".
fn mentioned(config: &str, symbol: &str) -> bool {
    config.lines().any(|line| {
        let line = line.trim();
        line.starts_with(&format!("CONFIG_{symbol}="))
            || line == format!("# CONFIG_{symbol} is not set")
    })
}

/// Whether a symbol is a module. Should never be true — `CONFIG_MODULES` is
/// off — but a symbol set to `m` is neither `y` nor absent, and a test that
/// only looked for `=y` would read it as absent.
fn a_module(config: &str, symbol: &str) -> bool {
    config
        .lines()
        .any(|line| line.trim() == format!("CONFIG_{symbol}=m"))
}

/// How a symbol is expected to be absent.
///
/// The distinction is not pedantry. `# CONFIG_X is not set` means the option
/// exists, is reachable, and somebody turned it off; **no line at all** means
/// Kconfig never even considered it, because whatever gates it is off. The
/// second is the stronger statement, and it is what "axiom A5 is structural on
/// this target" actually means — `CONFIG_EXT4_FS` is not merely off, it cannot
/// be turned on while `CONFIG_BLOCK` is unset.
///
/// Asserting which one applies catches both directions. A typo in a symbol name
/// reads as "off" to a test that only looks for `=y`, and would pass forever;
/// and a symbol that moves from unreachable to merely-off means something
/// turned its gate on, which is a change to the TCB nobody asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Absence {
    /// The configuration says `# CONFIG_X is not set`.
    TurnedOff,
    /// The configuration does not mention it, because its gate is off.
    Unreachable,
}

/// Axiom A5 and the small-TCB claim, read off the built kernel.
///
/// Each entry names why it is out, because "we do not need it" is not a reason
/// anybody can weigh against "this platform needs it" when `OS-023` (#339)
/// comes to pare the file back.
#[expect(
    clippy::too_many_lines,
    reason = "the length is the table, and the table is the point: every entry \
              names why it is out, so the list reads as a statement rather than \
              a set of symbols"
)]
#[test]
fn the_subsystems_that_must_stay_out_are_out() {
    /// `(symbol, how it is absent, why it must be)`.
    const MUST_BE_ABSENT: &[(&str, Absence, &str)] = &[
        // Axiom A5, structurally. Not "no block drivers" — no block *layer*,
        // so disk I/O is a syscall with nothing behind it, and every one of
        // these is `Unreachable` rather than merely off. That is the claim
        // `docs/deployment.md` makes, checked.
        (
            "BLOCK",
            Absence::TurnedOff,
            "axiom A5: this machine has no storage",
        ),
        ("SCSI", Absence::Unreachable, "gated by BLOCK"),
        ("ATA", Absence::Unreachable, "gated by BLOCK"),
        ("NVME_CORE", Absence::Unreachable, "gated by BLOCK"),
        ("VIRTIO_BLK", Absence::Unreachable, "gated by BLOCK"),
        ("MD", Absence::Unreachable, "gated by BLOCK"),
        ("EXT4_FS", Absence::Unreachable, "gated by BLOCK"),
        ("VFAT_FS", Absence::Unreachable, "gated by BLOCK"),
        // The interesting one: the machine boots from a CD-ROM and cannot read
        // it. Firmware reads the ESP and the image runs from RAM thereafter.
        ("ISO9660_FS", Absence::Unreachable, "gated by BLOCK"),
        (
            "NFS_FS",
            Absence::Unreachable,
            "gated by NETWORK_FILESYSTEMS",
        ),
        ("9P_FS", Absence::Unreachable, "gated by NET_9P"),
        ("VIRTIO_FS", Absence::Unreachable, "gated by FUSE_FS"),
        ("OVERLAY_FS", Absence::TurnedOff, "axiom A5"),
        ("FUSE_FS", Absence::TurnedOff, "axiom A5"),
        // A machine with one program in it does not load code at runtime.
        (
            "MODULES",
            Absence::TurnedOff,
            "nothing may be loaded at runtime",
        ),
        (
            "KEXEC",
            Absence::TurnedOff,
            "nothing may replace this kernel",
        ),
        // Attack surface with no user here.
        (
            "NETFILTER",
            Absence::TurnedOff,
            "no firewall, and no configurator",
        ),
        (
            "BPF_SYSCALL",
            Absence::TurnedOff,
            "a JIT reachable from userland",
        ),
        ("FTRACE", Absence::TurnedOff, "tracing nothing here reads"),
        ("KPROBES", Absence::TurnedOff, "the same"),
        // `CONFIG_DEBUG_KERNEL` is deliberately *not* on this list, and the
        // reason is worth writing down because it looks like an omission.
        //
        // It is on in the built kernel and cannot be turned off: `tinyconfig`
        // requires `CONFIG_EXPERT`, and `EXPERT` *selects* `DEBUG_KERNEL` — see
        // `init/Kconfig`, whose comment reads "Unhide debug options, to make the
        // on-by-default options visible". It is a menu gate, not code. Every
        // option it unhides is off, `CONFIG_DEBUG_INFO_NONE=y`, and the kernel
        // is not one byte larger for it.
        //
        // It sat on the disable list in `config.nix` for two issues doing
        // nothing. What is asserted instead is what that gate unhides:
        (
            "DEBUG_MISC",
            Absence::TurnedOff,
            "debug code with no better home",
        ),
        ("DYNAMIC_DEBUG", Absence::TurnedOff, "a runtime log surface"),
        (
            "DEBUG_FS",
            Absence::TurnedOff,
            "a filesystem; A5 twice over",
        ),
        (
            "KGDB",
            Absence::TurnedOff,
            "a debugger on a network service",
        ),
        ("KASAN", Absence::Unreachable, "gated by its own arch menu"),
        (
            "KCSAN",
            Absence::TurnedOff,
            "instrumentation in a shipped kernel",
        ),
        ("UBSAN", Absence::TurnedOff, "the same"),
        ("DEBUG_KMEMLEAK", Absence::TurnedOff, "the same"),
        ("GDB_SCRIPTS", Absence::Unreachable, "gated by DEBUG_INFO"),
        (
            "MAGIC_SYSRQ",
            Absence::TurnedOff,
            "a console that can panic the host",
        ),
        ("USB_SUPPORT", Absence::TurnedOff, "no USB is attached"),
        ("SOUND", Absence::TurnedOff, "no"),
        (
            "WLAN",
            Absence::TurnedOff,
            "a hypervisor emulates no wireless",
        ),
        ("BT", Absence::TurnedOff, "the same"),
        ("KVM", Absence::Unreachable, "gated by VIRTUALIZATION"),
        ("VFIO", Absence::TurnedOff, "nothing is passed through"),
        // One program, one user, no isolation to configure — and no daemon
        // that would configure it.
        ("NAMESPACES", Absence::TurnedOff, "there is one process"),
        ("CGROUPS", Absence::TurnedOff, "there is one process"),
        (
            "SECURITY",
            Absence::TurnedOff,
            "no LSM is or could be configured",
        ),
        // `OS-026` (#343): the power button needs the event layer and nothing
        // else. Every one of these was on, unasked, until that issue.
        (
            "INPUT_KEYBOARD",
            Absence::TurnedOff,
            "OS-026: not a keyboard",
        ),
        ("INPUT_MOUSE", Absence::TurnedOff, "OS-026 (#343)"),
        ("INPUT_MOUSEDEV", Absence::TurnedOff, "OS-026 (#343)"),
        ("INPUT_JOYDEV", Absence::TurnedOff, "OS-026 (#343)"),
        (
            "SERIO",
            Absence::TurnedOff,
            "OS-026: nothing sits on a PS/2 bus",
        ),
        // `OS-025` (#342): the Xen paravirt path, declined on the measurement
        // — 148 KiB against RTL8139's 12 KiB, for throughput a host answering
        // one request per client per few hours does not need.
        ("XEN", Absence::TurnedOff, "OS-025: XCP-ng works on 8139cp"),
        ("XEN_NETDEV_FRONTEND", Absence::Unreachable, "gated by XEN"),
        // `OS-023` (#339): four drivers nobody asked for, present since
        // `OS-017` (#333) and found by reading the built config.
        (
            "INTEL_MEI",
            Absence::TurnedOff,
            "a guest has no Management Engine",
        ),
        ("INTEL_MEI_ME", Absence::Unreachable, "gated by INTEL_MEI"),
        // Unreachable rather than off, and only since `HID` above went: this
        // test reported the change rather than passing through it, which is
        // what the distinction is for.
        ("I2C_HID", Absence::Unreachable, "gated by HID"),
        // `CONFIG_THERMAL` is deliberately absent from this list. It is on,
        // because `CONFIG_ACPI_PROCESSOR` selects it, and that one earns its
        // place: ACPI idle states are what stop a host that is idle 99.99 % of
        // the time from burning a core on the hypervisor. What *is* asserted is
        // the ACPI thermal-zone driver, which a guest has no zones for.
        (
            "ACPI_THERMAL",
            Absence::TurnedOff,
            "a guest has no thermal zones",
        ),
        (
            "HID",
            Absence::TurnedOff,
            "the button is ACPI, read through evdev",
        ),
        ("HID_GENERIC", Absence::Unreachable, "gated by HID"),
        // `OS-019` (#335): one DHCP client, in the program.
        (
            "IP_PNP",
            Absence::TurnedOff,
            "OS-019: kmsrs-os speaks DHCP itself",
        ),
        ("IP_PNP_DHCP", Absence::Unreachable, "gated by IP_PNP"),
        // Power management this machine has no use for, and which would let a
        // hypervisor suspend a host that is meant to answer.
        (
            "SUSPEND",
            Absence::TurnedOff,
            "a host that suspends is a host down",
        ),
        (
            "HIBERNATION",
            Absence::Unreachable,
            "gated by SWAP and BLOCK",
        ),
    ];

    let config = built_config();
    let mut present = Vec::new();
    let mut misclassified = Vec::new();

    for (symbol, absence, why) in MUST_BE_ABSENT {
        if enabled(&config, symbol) || a_module(&config, symbol) {
            present.push(format!("CONFIG_{symbol} — {why}"));
            continue;
        }
        match (absence, mentioned(&config, symbol)) {
            (Absence::TurnedOff, false) => misclassified.push(format!(
                "CONFIG_{symbol} is marked TurnedOff and appears nowhere. \
                 Either the name is misspelled — in which case this entry has \
                 been asserting nothing — or its gate went off, and it is now \
                 Unreachable"
            )),
            (Absence::Unreachable, true) => misclassified.push(format!(
                "CONFIG_{symbol} is marked Unreachable ({why}) and the \
                 configuration mentions it, so its gate is now on. That is a \
                 change to what this machine could be built with"
            )),
            _ => {}
        }
    }

    assert!(
        present.is_empty(),
        "these are in the built kernel and must not be. If one is genuinely \
         needed, adding it changes what is in this machine's TCB and belongs \
         in a commit that says so: {present:#?}"
    );
    assert!(
        misclassified.is_empty(),
        "these are absent, but not in the way this test claims. A misspelled \
         symbol reads as 'off' forever, which is why the distinction is \
         asserted rather than assumed: {misclassified:#?}"
    );
}

/// `OS-025` (#342): the pare-back may not remove what the matrix promises.
///
/// Every entry names the platform that needs it. A driver whose platform is no
/// longer claimed should be removed from *both* this list and
/// `docs/deployment.md` in the same commit — which is the point of naming them
/// here rather than keeping a bare list of symbols.
#[test]
fn every_driver_the_platform_matrix_needs_is_in() {
    /// `(symbol, the platform that would stop working without it)`.
    const MUST_BE_PRESENT: &[(&str, &str)] = &[
        // The console, which is how every one of the failures on this target
        // has been diagnosed.
        ("SERIAL_8250_CONSOLE", "every platform with a serial port"),
        ("FRAMEBUFFER_CONSOLE", "Proxmox's noVNC window"),
        ("VT_CONSOLE", "the same"),
        // Boot.
        ("EFI_STUB", "every UEFI platform, which is most of them"),
        ("BLK_DEV_INITRD", "the initramfs is the whole userland"),
        // Networking, which is the entire point of the matrix.
        (
            "VIRTIO_NET",
            "Proxmox, Nutanix AHV, bhyve, Cloud Hypervisor",
        ),
        (
            "E1000",
            "VirtualBox's default, and Proxmox's E1000 dropdown",
        ),
        ("E1000E", "VMware Workstation, Proxmox's E1000E dropdown"),
        // `OS-025` (#342). Each of these is a row in the matrix in
        // `docs/deployment.md`; removing one silently turns a supported
        // platform into an unsupported one.
        (
            "VMXNET3",
            "VMware ESXi and Workstation, Proxmox's vmxnet3 dropdown",
        ),
        (
            "8139CP",
            "Proxmox's RTL8139 dropdown, and Xen HVM's default NIC",
        ),
        ("PCNET32", "VirtualBox's older adapter choices"),
        (
            "TULIP",
            "Hyper-V Gen 1's Legacy Network Adapter, a DEC 21140",
        ),
        ("ENA_ETHERNET", "OS-027 (#344): EC2 Nitro"),
        (
            "HYPERV",
            "Hyper-V Gen 2 and Azure, which have no emulated NIC",
        ),
        ("HYPERV_NET", "the same — this *is* the NIC there"),
        (
            "HYPERV_TIMER",
            "the reference TSC, which keeps the clock close",
        ),
        // `OS-026` (#343): a hypervisor's polite stop.
        (
            "INPUT_EVDEV",
            "OS-026 (#343): reading the ACPI power button",
        ),
        ("ACPI_BUTTON", "OS-026 (#343): generating the event to read"),
        // `OS-022` (#338).
        ("VIRTIO_CONSOLE", "OS-022 (#338): the guest-agent channel"),
        ("VIRTIO_BALLOON", "OS-022 (#338): memory statistics"),
        // Boot time, and the reason the machine does not block in getrandom.
        ("HW_RANDOM_VIRTIO", "OS-023 (#339): worth ~2.3 s of boot"),
        // What pid 1 needs to exist at all.
        ("DEVTMPFS", "OS-021 (#337): /dev has one node without it"),
        ("PROC_FS", "OS-028 (#345): /proc/consoles"),
        ("SYSFS", "OS-026 (#343) and OS-022 (#338) both read it"),
    ];

    let config = built_config();
    let mut missing = Vec::new();
    for (symbol, platform) in MUST_BE_PRESENT {
        if !enabled(&config, symbol) {
            missing.push(format!("CONFIG_{symbol} — needed by {platform}"));
        }
    }

    assert!(
        missing.is_empty(),
        "these are gone from the built kernel and something depends on each. \
         `OS-023` (#339) may pare this file back and may not remove anything \
         `OS-025` (#342)'s matrix promises — a missing NIC driver produces a \
         machine that boots, reports `listening`, and serves nobody forever: \
         {missing:#?}"
    );
}

/// Nothing is a module, because `CONFIG_MODULES` is off.
///
/// A separate assertion from the one above because the failure is different in
/// kind: `=m` in a kernel with no module loader is a driver that is compiled,
/// costs size, and does not exist at runtime. That is the worst of both, and it
/// would pass a test that only looked for the symbol's presence.
#[test]
fn nothing_is_built_as_a_module() {
    let config = built_config();
    let modules: Vec<&str> = config
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with("=m"))
        .collect();

    assert!(
        modules.is_empty(),
        "these are built as modules in a kernel with no module loader, so they \
         cost size and do not exist at runtime: {modules:#?}"
    );
}

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
//!
//! # And one question about the allowlist itself
//!
//! [`every_symbol_the_allowlist_enables_is_one_the_kernel_knows`] is the
//! exception to everything above, and it is a narrow one (`OS-034`, #382). It
//! reads `config.nix` as well, because the thing it is *about* is the
//! allowlist: an entry asking to enable a symbol Kconfig has never heard of
//! does nothing, and reads as a decision while doing it. Four of those had been
//! found by then, each by somebody looking at something else, so the shape was
//! established well enough to test for. The generated file is still what
//! answers — the question is only which side the failure is on.
//!
//! # One target today, and the shape that survives a second
//!
//! `OS-031` (#375) turned this from a file that reads one path into a loop over
//! [`TARGETS`]. That is not speculative generality: this file's whole subject is
//! that a statement about a kernel has to be read off the kernel it is about,
//! and a second architecture means a second generated file that the *same*
//! assertions would happily read the first of. A test that reads the wrong file
//! passes while asserting nothing, which is `OS-006` (#257) exactly.
//!
//! Each target carries **its own two lists**, not a shared one with exceptions.
//! An architecture's TCB is not the other's plus a delta — the interrupt
//! controller, the timer, the console and the power-off mechanism have no
//! counterpart across the boundary — so a shared list with per-architecture
//! overrides would be a statement neither target actually makes.

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

/// One bare-metal target: what `linuxArches` in `flake.nix` calls it, the
/// generated configuration it produced, and the two lists that are this file's
/// statement about it.
///
/// Adding an architecture is an entry here plus its two lists (`OS-031`, #375).
struct Target {
    /// The architecture's name, as `flake.nix` and the artifact spell it. It
    /// appears in every failure message, because "CONFIG_X is missing" is not
    /// actionable when there is more than one file it could be missing from.
    arch: &'static str,
    /// The generated configuration, relative to the workspace root.
    config: &'static str,
    /// `(symbol, how it is absent, why it must be)`.
    absent: &'static [(&'static str, Absence, &'static str)],
    /// `(symbol, the platform that would stop working without it)`.
    present: &'static [(&'static str, &'static str)],
}

/// Every bare-metal target, and the only place this file names one.
const TARGETS: &[Target] = &[
    Target {
        arch: "x86_64",
        config: "os/linux/kernel.config",
        absent: X86_64_MUST_BE_ABSENT,
        present: X86_64_MUST_BE_PRESENT,
    },
    Target {
        arch: "aarch64",
        config: "os/linux/kernel.config.aarch64",
        absent: AARCH64_MUST_BE_ABSENT,
        present: AARCH64_MUST_BE_PRESENT,
    },
];

/// The generated configuration, as text.
fn built_config(target: &Target) -> String {
    let path = workspace_root().join(target.config);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read {} for {}: {error}. A target whose configuration is \
             missing is a target this file asserts nothing about (`OS-031`, \
             #375)",
            path.display(),
            target.arch
        )
    });

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

/// Every target is a distinct file, and there is at least one.
///
/// Both halves are the `OS-006` (#257) failure in the form this file could take
/// it. An empty [`TARGETS`] makes every assertion below vacuous; two targets
/// pointing at one file makes the second one's list an assertion about the
/// first one's kernel, which passes and means nothing.
#[test]
fn every_target_has_a_configuration_of_its_own() {
    assert!(
        !TARGETS.is_empty(),
        "no bare-metal target is listed, so every assertion in this file is \
         vacuous (`OS-031`, #375)"
    );

    let mut seen: Vec<&str> = Vec::new();
    for target in TARGETS {
        assert!(
            !seen.contains(&target.config),
            "{} reads {}, which another target already claims. Its list would \
             then be an assertion about a different architecture's kernel — \
             which passes, and says nothing (`OS-031`, #375)",
            target.arch,
            target.config
        );
        seen.push(target.config);
        // Read for its side effect: the banner check above is what proves the
        // path is a *generated* config rather than the allowlist.
        let _: String = built_config(target);
    }
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

/// Axiom A5 and the small-TCB claim on **x86_64**, read off the built kernel.
///
/// Each entry names why it is out, because "we do not need it" is not a reason
/// anybody can weigh against "this platform needs it" when `OS-023` (#339)
/// comes to pare the file back.
///
/// The length is the table, and the table is the point: every entry names why
/// it is out, so the list reads as a statement rather than a set of symbols.
const X86_64_MUST_BE_ABSENT: &[(&str, Absence, &str)] = &[
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
    // `OS-035` (#383): the 8250 driver's variants, every one of which was
    // `default SERIAL_8250` and arrived with the console rather than being
    // asked for. Two PCIe card families, the PnP bus, and two Intel SoC
    // UARTs; no hypervisor in the matrix emulates any of them.
    //
    // `SERIAL_8250_CONSOLE` is untouched and is asserted present below, which
    // is the pair that matters: this machine keeps the driver that finds a
    // PC's serial port at 0x3F8 and a Graviton's over PCI, and loses the five
    // that find hardware no guest has.
    (
        "SERIAL_8250_EXAR",
        Absence::TurnedOff,
        "Exar and Commtech multiport PCIe cards",
    ),
    (
        "SERIAL_8250_PERICOM",
        Absence::TurnedOff,
        "Pericom and Acces I/O PCIe UARTs",
    ),
    (
        "SERIAL_8250_PNP",
        Absence::TurnedOff,
        "OS-035: ttyS0 comes from SERIAL_PORT_DFNS here, not the PnP bus",
    ),
    // `OS-037` (#390). The bus itself cannot go — see
    // `the_pnp_bus_stays_because_acpi_selects_it` — but its debugging messages
    // are a plain `default y` bool, and a debug-message option compiled into a
    // shipped kernel needs no further argument. The same reason `DEBUG_MISC`
    // and `DYNAMIC_DEBUG` are on this list; this one slipped through because
    // nobody was looking at PnP. Both tables carry this row since `OS-039`
    // (#397), which is what a shared disable-list entry should look like.
    (
        "PNP_DEBUG_MESSAGES",
        Absence::TurnedOff,
        "OS-037: a debug-message option in a shipped kernel",
    ),
    // `OS-036` (#389). Off here because Kconfig's default is `!X86` rather
    // than because anybody said so, which is why it is asserted: this is the
    // half of the symmetry that costs nothing to keep and would otherwise go
    // unnoticed if a future kernel changed that default. The aarch64 table
    // above carries the same row for the opposite reason — there it took a
    // decision and a Graviton instance.
    (
        "SERIAL_8250_16550A_VARIANTS",
        Absence::TurnedOff,
        "OS-036: both kernels agree, and now say so",
    ),
    (
        "SERIAL_8250_LPSS",
        Absence::TurnedOff,
        "Intel Baytrail, Braswell and Quark SoC UARTs",
    ),
    (
        "SERIAL_8250_MID",
        Absence::TurnedOff,
        "Intel Medfield SoC UARTs",
    ),
    // Unreachable rather than off, and that is the interesting half: it has no
    // prompt of its own and exists only to be `select`ed by the two above, so
    // disabling them removes it from the configuration entirely.
    (
        "SERIAL_8250_DWLIB",
        Absence::Unreachable,
        "selected by LPSS and MID, both of which are off",
    ),
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

/// Axiom A5 and the small-TCB claim on **aarch64** (`OS-032`, #376).
///
/// Not the x86 list with substitutions. Six entries at the end have no x86
/// counterpart at all, and four x86 entries are missing because the symbols
/// they name do not exist on this architecture — `INTEL_MEI` and
/// `HYPERV_TIMER` among them. Copying the other list would have produced
/// entries that read as assertions and check nothing, which is what
/// [`Absence::Unreachable`] cannot distinguish from a misspelling.
const AARCH64_MUST_BE_ABSENT: &[(&str, Absence, &str)] = &[
    // Axiom A5, structurally, exactly as on x86: no block *layer*.
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
    // The machine's kernel lives in a FAT filesystem it cannot read, and
    // boots from a CD-ROM it cannot read either. Firmware reads both.
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
    (
        "MODULES",
        Absence::TurnedOff,
        "nothing may be loaded at runtime",
    ),
    (
        "KEXEC",
        Absence::Unreachable,
        "nothing may replace this kernel",
    ),
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
    ("NAMESPACES", Absence::TurnedOff, "there is one process"),
    ("CGROUPS", Absence::TurnedOff, "there is one process"),
    (
        "SECURITY",
        Absence::TurnedOff,
        "no LSM is or could be configured",
    ),
    // `OS-026` (#343): the power button needs the event layer and nothing
    // else, here as much as on x86.
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
    (
        "HID",
        Absence::TurnedOff,
        "the button is ACPI, read through evdev",
    ),
    ("HID_GENERIC", Absence::Unreachable, "gated by HID"),
    ("I2C_HID", Absence::Unreachable, "gated by HID"),
    (
        "ACPI_THERMAL",
        Absence::TurnedOff,
        "a guest has no thermal zones",
    ),
    (
        "XEN",
        Absence::TurnedOff,
        "OS-025: declined on the measurement",
    ),
    ("XEN_NETDEV_FRONTEND", Absence::Unreachable, "gated by XEN"),
    (
        "IP_PNP",
        Absence::TurnedOff,
        "OS-019: kmsrs-os speaks DHCP itself",
    ),
    ("IP_PNP_DHCP", Absence::Unreachable, "gated by IP_PNP"),
    // `OS-035` (#383). The same three as x86, disabled on the same shared
    // list, because both architectures had answered `y` unasked and neither
    // had said so.
    (
        "SERIAL_8250_EXAR",
        Absence::TurnedOff,
        "Exar and Commtech multiport PCIe cards",
    ),
    (
        "SERIAL_8250_PERICOM",
        Absence::TurnedOff,
        "Pericom and Acces I/O PCIe UARTs",
    ),
    // The one that needed an argument rather than a reading. There is no
    // `arch/arm64/include/asm/serial.h`, so the ISA table x86 gets its ttyS0
    // from is empty here and every port arrives over PCI, ACPI or DT. On the
    // one machine in the matrix whose console is a 16550A — an EC2 Graviton
    // instance — the kernel says `pci 0000:00:01.0: [1d0f:8250]` and then
    // `ttyS0 at MMIO 0x80000000 … is a 16550A`. A PCI device, bound by
    // `SERIAL_8250_PCI`, which stays.
    (
        "SERIAL_8250_PNP",
        Absence::TurnedOff,
        "OS-035: Graviton's 16550A is a PCI device, not a PnP one",
    ),
    // `OS-036` (#389). The probe for 16550A *variants*, whose Kconfig default
    // is `!X86` — so it was on here, off there, and neither was a decision.
    // Nothing in this architecture's matrix is a variant: QEMU `virt` and
    // Proxmox VE for arm64 present a PL011, and Graviton's port is a plain
    // 16550A, confirmed on an instance with this option off.
    (
        "SERIAL_8250_16550A_VARIANTS",
        Absence::TurnedOff,
        "OS-036: nothing in the arm matrix is a 16550A variant",
    ),
    // `OS-037` (#390), on the shared disable list since `OS-039` (#397). The
    // bus itself cannot go — see `the_pnp_bus_stays_because_acpi_selects_it`
    // — but its debugging messages are a plain `default y` bool, and a
    // debug-message option compiled into a shipped kernel needs no further
    // argument.
    (
        "PNP_DEBUG_MESSAGES",
        Absence::TurnedOff,
        "OS-037: a debug-message option in a shipped kernel",
    ),
    // Unreachable here rather than merely off, and for a different reason than
    // on x86: the two symbols that `select` it are `depends on X86`, so this
    // architecture never had it to turn off.
    (
        "SERIAL_8250_DWLIB",
        Absence::Unreachable,
        "selected only by the x86-only LPSS and MID drivers",
    ),
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
    // --- from here down there is no x86 counterpart ---
    //
    // These are what makes this a list rather than a copy, and each one is a
    // fact about this architecture that has no analogue on the other.
    //
    // The four NIC drivers are the interesting group: they are *absent by
    // decision*, not by accident. `OS-025` (#342)'s matrix is a claim about
    // products, and every product behind these four is x86-only — VirtualBox
    // has no aarch64 guests, Hyper-V Generation 1 is x86, Xen HVM does not run
    // aarch64 guests, and VMware's aarch64 products offer no vmxnet3. Asserting
    // their absence is what stops the arm allowlist quietly growing into a copy
    // of the x86 one.
    (
        "COMPAT",
        Absence::TurnedOff,
        "OS-032: a second syscall table for a userland of one aarch64 binary",
    ),
    (
        "PERF_EVENTS",
        Absence::TurnedOff,
        "OS-032: perf_event_open(2) has no user in a one-program image",
    ),
    // Deliberately *not* paired with an entry on the x86 list, which would be
    // an assertion that cannot hold — see
    // [`perf_events_is_absent_on_one_target_and_forced_on_the_other`].
    (
        "THERMAL_OF",
        Absence::TurnedOff,
        "OS-032: the device-tree twin of ACPI_THERMAL; no zones either way",
    ),
    (
        "ARM64_VA_BITS_52",
        Absence::TurnedOff,
        "OS-032: 48-bit, which is what every distribution ships",
    ),
    (
        "ARM64_LPA2",
        Absence::Unreachable,
        "gated by the 52-bit choice above",
    ),
    (
        "ARM64_64K_PAGES",
        Absence::TurnedOff,
        "OS-032: 4K, for the same reason as the VA size",
    ),
    (
        "VMXNET3",
        Absence::TurnedOff,
        "OS-032: Fusion on Apple Silicon offers no vmxnet3",
    ),
    (
        "PCNET32",
        Absence::TurnedOff,
        "OS-032: VirtualBox has no aarch64 guests",
    ),
    (
        "8139CP",
        Absence::TurnedOff,
        "OS-032: Xen HVM does not run aarch64 guests",
    ),
    (
        "TULIP",
        Absence::Unreachable,
        "OS-032: Hyper-V Generation 1 is x86; Arm Azure is Gen 2, so VMBus",
    ),
];

/// `OS-025` (#342) on **aarch64**: every driver the arm matrix promises.
///
/// Half of this list has no x86 counterpart, and that half is the reason
/// `OS-032` (#376) says the two files are not ports of each other. On x86 the
/// interrupt controller, the timer, the PCI host bridge and the power-off
/// mechanism are all implicit; here every one of them is a driver that can be
/// left out, and leaving any of them out produces a machine that does not boot
/// at all rather than one that boots and serves nobody.
const AARCH64_MUST_BE_PRESENT: &[(&str, &str)] = &[
    // --- the platform, none of which x86 has to name ---
    (
        "ARM_GIC_V3",
        "every server-class Arm machine: QEMU virt, and Graviton",
    ),
    (
        "ARM_GIC_V3_ITS",
        "PCIe MSI, which is how a virtio NIC raises an interrupt at all",
    ),
    (
        "ARM_ARCH_TIMER",
        "the clock source; the counterpart of x86's kvmclock",
    ),
    (
        "ARM_PSCI_FW",
        "OS-026 (#343): SYSTEM_OFF, which is how this machine powers down",
    ),
    (
        "PCI_HOST_GENERIC",
        "the ECAM host bridge QEMU virt and the Arm SBSA describe",
    ),
    ("PCI_ECAM", "the same bridge's configuration space"),
    (
        "ARM64_4K_PAGES",
        "what Amazon Linux, Debian and every other aarch64 distribution ship",
    ),
    (
        "ARM64_VA_BITS_48",
        "the same; 52-bit VA drags in LPA2, which nobody ships",
    ),
    // --- the console, which is two drivers here and one on x86 ---
    (
        "SERIAL_AMBA_PL011_CONSOLE",
        "QEMU virt and Proxmox VE for arm64, whose UART is a PL011",
    ),
    (
        "SERIAL_8250_CONSOLE",
        "EC2 Graviton, whose UART is a 16550A — observed, not assumed",
    ),
    ("FRAMEBUFFER_CONSOLE", "Proxmox's noVNC window"),
    ("VT_CONSOLE", "the same"),
    // Boot.
    (
        "EFI_STUB",
        "every aarch64 platform, since every one of them is UEFI",
    ),
    ("BLK_DEV_INITRD", "the initramfs is the whole userland"),
    (
        "RANDOMIZE_BASE",
        "OS-032 (#376): KASLR, which x86 had and this silently did not",
    ),
    // Networking.
    (
        "VIRTIO_NET",
        "Proxmox VE for arm64, and every other KVM-derived hypervisor",
    ),
    (
        "E1000",
        "Proxmox's E1000 entry, whose model list is one list for all arches",
    ),
    ("E1000E", "Parallels and VMware Fusion on Apple Silicon"),
    (
        "ENA_ETHERNET",
        "EC2 Graviton, which is Nitro and therefore ENA",
    ),
    (
        "HYPERV",
        "Azure's Cobalt 100 instances, which are Hyper-V Generation 2",
    ),
    ("HYPERV_NET", "the same — this *is* the NIC there"),
    // `OS-026` (#343): the polite stop, which arrives through the ACPI
    // Generic Event Device here rather than a fixed-hardware button.
    (
        "INPUT_EVDEV",
        "OS-026 (#343): reading the power key the GED raises",
    ),
    (
        "ACPI_BUTTON",
        "OS-026 (#343): the device the GED raises it on",
    ),
    // `OS-022` (#338).
    ("VIRTIO_CONSOLE", "OS-022 (#338): the guest-agent channel"),
    ("VIRTIO_BALLOON", "OS-022 (#338): memory statistics"),
    // Entropy, of which this machine has two sources and x86 has one.
    ("HW_RANDOM_VIRTIO", "OS-023 (#339): worth ~2.3 s of boot"),
    (
        "HW_RANDOM_ARM_SMCCC_TRNG",
        "OS-032 (#376): the architected firmware TRNG, which needs no device",
    ),
    // What pid 1 needs to exist at all.
    ("DEVTMPFS", "OS-021 (#337): /dev has one node without it"),
    ("PROC_FS", "OS-028 (#345): /proc/consoles"),
    ("SYSFS", "OS-026 (#343) and OS-022 (#338) both read it"),
];

/// Every target's must-stay-out list, against that target's own kernel.
#[test]
fn the_subsystems_that_must_stay_out_are_out() {
    for target in TARGETS {
        let config = built_config(target);
        let mut present = Vec::new();
        let mut misclassified = Vec::new();

        for (symbol, absence, why) in target.absent {
            if enabled(&config, symbol) || a_module(&config, symbol) {
                present.push(format!("CONFIG_{symbol} — {why}"));
                continue;
            }
            match (absence, mentioned(&config, symbol)) {
                (Absence::TurnedOff, false) => misclassified.push(format!(
                    "CONFIG_{symbol} is marked TurnedOff and appears nowhere. \
                     Either the name is misspelled — in which case this entry \
                     has been asserting nothing — or its gate went off, and it \
                     is now Unreachable"
                )),
                (Absence::Unreachable, true) => misclassified.push(format!(
                    "CONFIG_{symbol} is marked Unreachable ({why}) and the \
                     configuration mentions it, so its gate is now on. That is \
                     a change to what this machine could be built with"
                )),
                _ => {}
            }
        }

        assert!(
            present.is_empty(),
            "these are in the built {} kernel and must not be. If one is \
             genuinely needed, adding it changes what is in this machine's TCB \
             and belongs in a commit that says so: {present:#?}",
            target.arch
        );
        assert!(
            misclassified.is_empty(),
            "these are absent from the {} kernel, but not in the way this test \
             claims. A misspelled symbol reads as 'off' forever, which is why \
             the distinction is asserted rather than assumed: {misclassified:#?}",
            target.arch
        );
    }
}

/// `OS-025` (#342) on **x86_64**: the pare-back may not remove what the matrix
/// promises.
///
/// Every entry names the platform that needs it. A driver whose platform is no
/// longer claimed should be removed from *both* this list and
/// `docs/deployment.md` in the same commit — which is the point of naming them
/// here rather than keeping a bare list of symbols.
const X86_64_MUST_BE_PRESENT: &[(&str, &str)] = &[
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

/// Every target's must-be-present list, against that target's own kernel.
#[test]
fn every_driver_the_platform_matrix_needs_is_in() {
    for target in TARGETS {
        let config = built_config(target);
        let mut missing = Vec::new();
        for (symbol, platform) in target.present {
            if !enabled(&config, symbol) {
                missing.push(format!("CONFIG_{symbol} — needed by {platform}"));
            }
        }

        assert!(
            missing.is_empty(),
            "these are gone from the built {} kernel and something depends on \
             each. `OS-023` (#339) may pare this file back and may not remove \
             anything `OS-025` (#342)'s matrix promises — a missing NIC driver \
             produces a machine that boots, reports `listening`, and serves \
             nobody forever: {missing:#?}",
            target.arch
        );
    }
}

/// **`OS-035` (#383): the one asymmetry between the two kernels, stated.**
///
/// `perf_event_open(2)` exists on the x86_64 machine and not on the aarch64
/// one. #383 filed that as a gap to close, on the reasonable grounds that a
/// large syscall with a JIT-adjacent history has no user in an image
/// containing one program, and that nobody had *chosen* the difference —
/// each architecture's `tinyconfig` had simply answered differently.
///
/// It cannot be closed. `arch/x86/Kconfig` gives `config X86` an unconditional
/// `select PERF_EVENTS`, so there is no x86 kernel without it at any Kconfig
/// setting; disabling it and running `olddefconfig` produces a byte-identical
/// configuration. Naming it on the shared disable list would therefore have
/// been an entry that cannot be honoured — precisely the thing `OS-034` (#382)
/// had just finished removing three of.
///
/// So what is asserted is the *fact*, per target, rather than a wish. This is
/// the only place in this file where a symbol's presence is asserted for a
/// reason that is not "a platform needs it", which is why it is a test of its
/// own rather than a row in [`X86_64_MUST_BE_PRESENT`]: nothing needs perf
/// here, and the day x86 stops forcing it — or aarch64 starts acquiring it as
/// somebody's dependency — this fails and the statement gets revisited instead
/// of quietly going stale.
#[test]
fn perf_events_is_absent_on_one_target_and_forced_on_the_other() {
    let of = |arch: &str| -> String {
        let target = TARGETS
            .iter()
            .find(|target| target.arch == arch)
            .unwrap_or_else(|| panic!("no {arch} target"));
        built_config(target)
    };

    assert!(
        enabled(&of("x86_64"), "PERF_EVENTS"),
        "CONFIG_PERF_EVENTS is off in the x86_64 kernel. That is a better          answer than the one `OS-035` (#383) had to settle for — but it means          `config X86` no longer carries an unconditional `select PERF_EVENTS`,          so the reasoning written into `os/linux/config.nix` is now wrong.          Put it on the shared disable list and delete this half of the test"
    );

    let arm = of("aarch64");
    assert!(
        mentioned(&arm, "PERF_EVENTS") && !enabled(&arm, "PERF_EVENTS"),
        "CONFIG_PERF_EVENTS is on in the aarch64 kernel, so both targets now          have `perf_event_open(2)` and the one architecture that could refuse          it has stopped (`OS-032`, #376; `OS-035`, #383)"
    );
}

/// `OS-037` (#390): the PnP bus is in both kernels and cannot be taken out.
///
/// It enumerates nothing worth having. `SERIAL_8250_PNP` was the only driver on
/// either kernel that bound to the PnP bus and `OS-035` (#383) removed it; on
/// an EC2 Graviton instance `/sys/bus/pnp/devices/` holds exactly one entry,
/// the ACPI motherboard-resources pseudo-device, and on x86 the console comes
/// from `SERIAL_PORT_DFNS` in `arch/x86/include/asm/serial.h`.
///
/// It still cannot be removed: `drivers/acpi/Kconfig` gives `menuconfig ACPI`
/// an unconditional `select PNP`, so Kconfig forces the symbol back on and
/// `olddefconfig` overwrites the entry — observed, by putting `PNP` on the
/// disable list and reading the generated file, which still said
/// `CONFIG_PNP=y`. `PNPACPI` follows: `bool` with no prompt and
/// `default (PNP && ACPI)`, so it is not settable at all.
///
/// Naming either on the disable list would be an entry that cannot be
/// honoured, which is what `OS-034` (#382) exists to keep out. So the fact is
/// asserted per target instead — the same shape, and for the same reason, as
/// [`perf_events_is_absent_on_one_target_and_forced_on_the_other`]. The day
/// ACPI stops selecting PNP this fails, and the pare-back #390 asked for
/// becomes possible.
#[test]
fn the_pnp_bus_stays_because_acpi_selects_it() {
    for target in TARGETS {
        let config = built_config(target);
        assert!(
            enabled(&config, "ACPI"),
            "CONFIG_ACPI is off on {}, so the reasoning below does not apply",
            target.arch
        );
        assert!(
            enabled(&config, "PNP"),
            "CONFIG_PNP is off in the {} kernel. That is a better answer than              the one `OS-037` (#390) had to settle for — but it means              `menuconfig ACPI` no longer carries `select PNP`, so the bus can              now be pared back. Put PNP on the disable list, regenerate, and              delete this test",
            target.arch
        );
        assert!(
            enabled(&config, "PNPACPI"),
            "CONFIG_PNPACPI is off in the {} kernel while PNP is on, which              `default (PNP && ACPI)` says cannot happen (`OS-037`, #390)",
            target.arch
        );
    }
}

/// Nothing is a module, because `CONFIG_MODULES` is off.
///
/// A separate assertion from the one above because the failure is different in
/// kind: `=m` in a kernel with no module loader is a driver that is compiled,
/// costs size, and does not exist at runtime. That is the worst of both, and it
/// would pass a test that only looked for the symbol's presence.
#[test]
fn nothing_is_built_as_a_module() {
    for target in TARGETS {
        let config = built_config(target);
        let modules: Vec<&str> = config
            .lines()
            .map(str::trim)
            .filter(|line| line.ends_with("=m"))
            .collect();

        assert!(
            modules.is_empty(),
            "these are built as modules in the {} kernel, which has no module \
             loader, so they cost size and do not exist at runtime: \
             {modules:#?}",
            target.arch
        );
    }
}

/// The allowlist in `os/linux/config.nix`, as the symbols it asks to **enable**
/// for one architecture: `common.enable` plus that architecture's own list.
///
/// This is the one question in this file where the allowlist is the *subject*
/// rather than the thing not to be trusted, so it is the one place that reads
/// it. Everything else here reads the generated configuration, for the reason
/// the module comment gives.
///
/// A hand-rolled scan rather than a Nix evaluation, because the alternative is
/// running `nix` from a test — which would make this file's answer depend on a
/// toolchain no other test here needs. The shape it depends on is small and is
/// asserted: an attribute set per architecture, each with an `enable = [ … ];`
/// whose entries are quoted symbols. If `config.nix` is ever restructured out
/// from under this, [`the_allowlist_is_still_shaped_the_way_this_reads_it`]
/// fails rather than this quietly returning nothing (`OS-034`, #382).
fn allowlist_enables(arch: &str) -> Vec<String> {
    let path = workspace_root().join("os/linux/config.nix");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    let mut symbols = Vec::new();
    let mut section: Option<&str> = None;
    let mut collecting = false;

    for line in text.lines() {
        let trimmed = line.trim();

        // `common = {`, `x86_64 = {`, `aarch64 = {`. Two of the three are this
        // architecture's statement and the third is the other architecture's,
        // so entering one clears whatever was open — a scan that only
        // recognised the sections it wanted would read the aarch64 list as part
        // of the x86 one.
        for name in ["common", "x86_64", "aarch64"] {
            if trimmed.starts_with(&format!("{name} = {{")) {
                section = (name == "common" || name == arch).then_some(name);
                collecting = false;
            }
        }

        if trimmed.starts_with("enable = [") {
            collecting = section.is_some();
            continue;
        }
        if trimmed.starts_with("disable = [") {
            collecting = false;
            continue;
        }
        if trimmed == "];" {
            collecting = false;
            continue;
        }
        if !collecting {
            continue;
        }

        // Comments first. Everything after a `#` is prose, and the prose here
        // quotes things — `"we do not need it"` is a comment in this very file.
        let code = line.split('#').next().unwrap_or_default();
        for piece in code.split('"').skip(1).step_by(2) {
            if !piece.is_empty()
                && piece
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                symbols.push(piece.to_string());
            }
        }
    }
    symbols
}

/// The scan above still finds a list, for every target.
///
/// Its own test because the failure it catches is silence: a `config.nix`
/// reorganised into a shape this does not recognise makes
/// [`every_symbol_the_allowlist_enables_is_one_the_kernel_knows`] iterate an
/// empty list and pass, which is the `OS-006` (#257) failure wearing this
/// file's clothes.
#[test]
fn the_allowlist_is_still_shaped_the_way_this_reads_it() {
    for target in TARGETS {
        let enables = allowlist_enables(target.arch);
        assert!(
            enables.len() > 50,
            "only {} enable entries were found for {} in os/linux/config.nix. \
             The file has been reshaped and this scan no longer reads it, so \
             the test that depends on it is asserting nothing (`OS-034`, #382)",
            enables.len(),
            target.arch
        );
        // Every target's list has entries the other's does not; a scan that
        // returned the same symbols for both would have missed the split.
        assert!(
            enables.iter().any(|symbol| symbol == "SERIAL_8250"),
            "the shared half of the allowlist was not read for {}",
            target.arch
        );
    }

    let x86: Vec<String> = allowlist_enables("x86_64");
    let arm: Vec<String> = allowlist_enables("aarch64");
    assert!(
        x86.iter().any(|symbol| symbol == "KVM_GUEST")
            && arm.iter().any(|symbol| symbol == "ARM_GIC_V3"),
        "the per-architecture half of the allowlist was not read: x86 should \
         name KVM_GUEST and aarch64 should name ARM_GIC_V3 (`OS-034`, #382)"
    );
}

/// **`OS-034` (#382): an entry that enables nothing is not a decision.**
///
/// Four findings of one shape came before this test, and every one was a line
/// in the allowlist that read as a choice and was in fact a no-op — found by
/// somebody looking at something else. `DEBUG_KERNEL`, `ELF_CORE` and the
/// `IP_PNP` group in `OS-023` (#339); then `NET_VENDOR_VMWARE` and both
/// `RANDOM_TRUST_*` here.
///
/// The check is that Kconfig **mentions** each symbol for that architecture —
/// `=y`, `=m`, or `# … is not set`. That is the line between "off" and
/// "misspelled", and it is the same distinction [`Absence`] draws on the other
/// side of the file.
///
/// # Why only the enable half
///
/// The disable list must not be caught by this net, and that is not an
/// exemption but a difference in kind. Two dozen of its entries are mentioned
/// nowhere either, and every one of them is *correct*: `EXT4_FS` is
/// unreachable because `BLOCK` is off, which is the strongest form of the claim
/// axiom A5 makes and is exactly what [`Absence::Unreachable`] asserts. Asking
/// to disable something already unreachable says something true. Asking to
/// **enable** a symbol Kconfig has never heard of cannot be anything but a
/// mistake.
///
/// # Why `=y` is asserted too
///
/// A symbol that exists, was asked for, and came out `# … is not set` is a
/// second failure with the same visible shape and a different cause:
/// `olddefconfig` declined it, because something it depends on is off. The
/// allowlist then still reads as a decision the kernel did not take. Both are
/// reported, separately, because the fix differs — one is a line to delete and
/// the other is a dependency to name.
#[test]
fn every_symbol_the_allowlist_enables_is_one_the_kernel_knows() {
    for target in TARGETS {
        let config = built_config(target);
        let mut unknown = Vec::new();
        let mut declined = Vec::new();

        for symbol in allowlist_enables(target.arch) {
            if !mentioned(&config, &symbol) {
                unknown.push(format!("CONFIG_{symbol}"));
            } else if !enabled(&config, &symbol) && !a_module(&config, &symbol) {
                declined.push(format!("CONFIG_{symbol}"));
            }
        }

        assert!(
            unknown.is_empty(),
            "os/linux/config.nix asks to enable these for {}, and the built \
             configuration does not mention them at all — so Kconfig has never \
             heard of them on this architecture and the entries do nothing. An \
             entry that enables nothing reads as a decision and is a no-op, \
             which is the fourth finding of this shape (`OS-034`, #382): \
             {unknown:#?}",
            target.arch
        );
        assert!(
            declined.is_empty(),
            "os/linux/config.nix asks to enable these for {}, they exist, and \
             `olddefconfig` turned them back off — so something each depends on \
             is not on. Unlike the list above these are not lines to delete: \
             the dependency has to be named, or the entry is a claim this \
             kernel does not honour (`OS-034`, #382): {declined:#?}",
            target.arch
        );
    }
}

// --- The measured kernel deltas, which live in three files (`OS-040`, #401) ---

/// A signed KiB figure and the variant it prices.
///
/// `.#linux-deltas` is the instrument; `flake.nix` holds the variants it
/// measures; `os/linux/config.nix` and `docs/deployment.md` each quote the
/// results in prose. Two hand-written copies of a measured number is two
/// chances to correct one of them — which is precisely what happened:
/// `OS-038` (#391) found every driver delta in `config.nix` taken in the enable
/// direction at the moment the driver was added, fixed that file, and left
/// `docs/deployment.md` as the stale copy for an issue. The operator-facing
/// document is the worse of the two to be wrong in.
///
/// Nothing a host test can do reproduces these numbers — they come from
/// building two kernels — so what is asserted is that the copies agree, and
/// that both are talking about variants that exist.
type Delta = (String, i64);

/// Whether `needle` occurs in `haystack` as a whole word.
///
/// `-` and `_` count as word characters, because variant names contain them:
/// without that, `kaslr` would match inside `no-kaslr` and price the wrong
/// question. It is also what keeps `ena` out of `enable` and `e1000` out of
/// `e1000e`.
fn mentions(haystack: &str, needle: &str) -> bool {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_')
        .any(|word| word == needle)
}

/// Every signed KiB figure on a line: `-20 KiB`, `+140 KiB`, `**-36 KiB**`.
///
/// Unsigned figures are ignored on purpose. A magnitude with an implied sign is
/// the defect `OS-038` (#391) is about, so this reads only numbers that state
/// their direction, and a row that stops stating it stops being compared —
/// which the completeness check below then catches.
fn kib_figures(line: &str) -> Vec<i64> {
    // Prose uses U+2212 for a minus in places and the tables use ASCII; both
    // mean the same thing to a reader and must mean the same thing here. The
    // byte counts are written with U+00A0 thin gaps in one file and commas in
    // the other, but those carry no unit and are never read as a delta.
    let line = line.replace('\u{2212}', "-").replace('\u{00a0}', " ");
    let tokens: Vec<&str> = line.split_whitespace().collect();
    tokens
        .windows(2)
        .filter_map(|pair| {
            let [number, unit] = pair else { return None };
            // `**` is markdown's bold, which lands between the number and the
            // unit's own markers rather than around the pair.
            if !unit.trim_start_matches('*').starts_with("KiB") {
                return None;
            }
            let number = number.trim_start_matches('*');
            if !number.starts_with(['-', '+']) {
                return None;
            }
            number.trim_start_matches('+').parse::<i64>().ok()
        })
        .collect()
}

/// The delta each variant is quoted at in one region of one file.
fn quoted_deltas(region: &str, variants: &[String]) -> Vec<Delta> {
    let mut quoted: Vec<Delta> = Vec::new();
    for line in region.lines() {
        let figures = kib_figures(line);
        if figures.len() != 1 {
            // Zero figures is prose; more than one is a sentence comparing two
            // numbers ("-120 KiB … the sum, which is -112 KiB"), and guessing
            // which belongs to the variant would be the kind of cleverness that
            // makes a failure unreadable.
            continue;
        }
        for variant in variants {
            if let (true, Some(figure)) = (mentions(line, variant), figures.first()) {
                quoted.push((variant.clone(), *figure));
            }
        }
    }
    quoted
}

/// The `.#linux-deltas` variant names `flake.nix` defines, per architecture.
fn delta_variants(root: &Path) -> Vec<(String, Vec<String>)> {
    let flake = std::fs::read_to_string(root.join("flake.nix")).expect("flake.nix is readable");
    let block = flake
        .split_once("linuxDeltaVariants = {")
        .expect("flake.nix defines linuxDeltaVariants")
        .1;
    let mut arches: Vec<(String, Vec<String>)> = Vec::new();
    for line in block.lines() {
        // Eight spaces is an architecture, ten is a variant inside it. The
        // shape rather than a parser, for the reason `packaging_invariants.rs`
        // gives: this workspace has no Nix parser and reading two lists is not
        // a reason to acquire one.
        if let Some(rest) = line.strip_prefix("        ")
            && !rest.starts_with(' ')
            && rest.ends_with(" = {")
        {
            arches.push((rest.trim_end_matches(" = {").to_owned(), Vec::new()));
            continue;
        }
        if let Some(rest) = line.strip_prefix("          ")
            && !rest.starts_with(' ')
            && let Some((name, _)) = rest.split_once(" = ")
            && !name.is_empty()
            && name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
            && let Some(arch) = arches.last_mut()
        {
            arch.1.push(name.to_owned());
        }
        // The closing brace of the whole attribute set, at six spaces.
        if line == "      };" {
            break;
        }
    }
    assert_eq!(
        arches.len(),
        2,
        "linuxDeltaVariants should name one list per bare-metal architecture, \
         found {arches:?}"
    );
    arches
}

/// Cut a file into one region per architecture at a named marker.
fn region<'a>(text: &'a str, from: &str, to: Option<&str>) -> &'a str {
    let (_, rest) = text
        .split_once(from)
        .unwrap_or_else(|| panic!("{from:?} is not in this file — the section was renamed"));
    match to.and_then(|marker| rest.split_once(marker)) {
        Some((inside, _)) => inside,
        None => rest,
    }
}

/// `OS-040` (#401): `docs/deployment.md` and `os/linux/config.nix` quote the
/// same delta for the same variant.
///
/// The failure this catches is not a wrong number — no test here can know what
/// the right one is, since it comes from building two kernels — it is the two
/// copies **disagreeing**, which is the state #401 reports and the state that
/// tells a reader one of them is stale. `OS-038` (#391) corrected one file; the
/// other went on saying the reverse of it, in the document an operator reads to
/// decide whether to deploy.
#[test]
fn the_delta_tables_in_the_docs_and_the_kernel_config_agree() {
    let root = workspace_root();
    let variants = delta_variants(&root);
    let config = std::fs::read_to_string(root.join("os/linux/config.nix")).expect("config.nix");
    let docs = std::fs::read_to_string(root.join("docs/deployment.md")).expect("deployment.md");

    // `config.nix`'s aarch64 table is the doc comment *above* `aarch64 = {`, so
    // the x86 region ends where that comment begins rather than at the brace.
    let arm_preamble = "# # What the shared drivers cost *here*";
    let regions: &[(&str, &str, &str)] = &[
        (
            "x86_64",
            region(&config, "    x86_64 = {", Some(arm_preamble)),
            region(
                &docs,
                "### Which hypervisors this runs on — x86_64",
                Some("### Which hypervisors this runs on — aarch64"),
            ),
        ),
        (
            "aarch64",
            region(&config, arm_preamble, None),
            region(
                &docs,
                "### Which hypervisors this runs on — aarch64",
                Some("### The console (`OS-028`"),
            ),
        ),
    ];

    let mut compared: Vec<(String, String)> = Vec::new();
    for (arch, config_region, docs_region) in regions {
        let names = &variants
            .iter()
            .find(|(name, _)| name == arch)
            .unwrap_or_else(|| panic!("flake.nix has no delta variants for {arch}"))
            .1;

        let from_config = quoted_deltas(config_region, names);
        let from_docs = quoted_deltas(docs_region, names);

        for (variant, documented) in &from_docs {
            for (other, measured) in &from_config {
                if other == variant {
                    assert_eq!(
                        documented, measured,
                        "docs/deployment.md prices the {arch} `{variant}` variant at \
                         {documented} KiB and os/linux/config.nix at {measured} KiB. One of \
                         them was corrected and the other was not — re-run \
                         `nix build .#linux-deltas && cat result/report` and make both say \
                         what it says (OS-040, #401)."
                    );
                    compared.push(((*arch).to_owned(), variant.clone()));
                }
            }
        }

        // A table that quotes no variant at all would pass everything above
        // vacuously, which is how a check stops being one.
        assert!(
            !from_docs.is_empty(),
            "the {arch} section of docs/deployment.md prices no `.#linux-deltas` \
             variant. Its table is keyed by variant name so that it can be \
             checked against os/linux/config.nix one row at a time (OS-040, #401)."
        );
    }

    assert!(
        compared.len() >= 8,
        "only {} delta rows are quoted in both docs/deployment.md and \
         os/linux/config.nix. Both files carried a full table when this was \
         written; a row that stops naming its variant, or stops stating the \
         sign of its delta, silently drops out of this comparison (OS-040, #401).",
        compared.len()
    );
}

/// `OS-040` (#401): every variant the documents name is one that exists.
///
/// The other half of keying the tables by variant name: a row that names a
/// variant `.#linux-deltas` does not have is a row nobody can reproduce, which
/// is the property #401 is really about — the tables told a reader to run a
/// command that printed something else.
#[test]
fn every_delta_variant_the_docs_name_exists() {
    let root = workspace_root();
    let variants = delta_variants(&root);
    let docs = std::fs::read_to_string(root.join("docs/deployment.md")).expect("deployment.md");

    let known: Vec<&String> = variants.iter().flat_map(|(_, names)| names).collect();
    for line in docs.lines() {
        // Only the delta tables, which are the rows whose first cell is a
        // single backticked token.
        let Some(cell) = line.strip_prefix("| `") else {
            continue;
        };
        let Some((name, _)) = cell.split_once('`') else {
            continue;
        };
        if !name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            continue;
        }
        // A backticked lower-case token in the first cell of a table row that
        // also quotes a KiB figure or a byte count is a delta row.
        if kib_figures(line).is_empty() && !line.contains(" bytes") && !line.contains('→') {
            continue;
        }
        assert!(
            known.iter().any(|variant| *variant == name),
            "docs/deployment.md quotes a delta for `{name}`, which is not a \
             `.#linux-deltas` variant in flake.nix. A row a reader cannot \
             reproduce with the command the section names is the defect \
             OS-040 (#401) was filed about."
        );
    }
}

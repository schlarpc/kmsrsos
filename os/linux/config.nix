# Regenerates `kernel.config` (`OS-017`, #333).
#
# `kernel.config` is checked in rather than generated at build time, because
# `buildLinux` reads it at *evaluation* time and because the file is the point:
# it is the statement of what is in this machine's TCB, and a statement nobody
# can read in a diff is not one. Regenerate with:
#
#     nix build .#linux-config && cp result os/linux/kernel.config
#
# Through the flake, not `nix build -f os/linux/config.nix`, which is what this
# said until `OS-026` (#343). That form reads `<nixpkgs>` from whoever runs it
# and regenerates this file against a *different kernel version* than the flake
# pins — observed producing a 6.12.91 config for a tree that ships 6.12.94, as a
# 54-line deletion that looked like a legitimate pare-back.
#
# The base is `make tinyconfig`, which is `allnoconfig` plus a few size tweaks.
# So the default for every subsystem is *off*, and each line below is a
# deliberate addition that has to justify itself. Growing the list is how this
# file should change; nothing should ever be enabled to "see if it helps".
#
# There is one generated file per architecture and one invocation of this per
# file (`OS-031`, #375). `arch.config` names which one the caller means, and
# `arch.kernelArch` is the kernel's own spelling of the target — which agrees
# with neither the Nix system nor the name in an artifact.
#
# `pkgs` lost its `import <nixpkgs> { }` default with the same issue. That
# default was the `OS-026` (#343) footgun in the parameter list rather than in
# the documentation: it made `nix build -f os/linux/config.nix` *work*, against
# whatever channel the caller had, and quietly produce a TCB statement for a
# different kernel version than the flake pins.
{ pkgs
, arch
, base ? pkgs.linux_6_12
}:

let
  # The allowlist is in two halves, and which half a symbol belongs in is a
  # question with an answer (`OS-032`, #376).
  #
  # `common` is what is true of every machine this runs on: the syscalls the
  # program makes, the devices every hypervisor in the matrix presents, and the
  # subsystems axiom A5 keeps out. `byArch` is what a *platform is* — its
  # interrupt controller, its timer, its console device, the way it turns
  # itself off. Those have no counterpart across the boundary, which is why
  # this is a split and not one list with exceptions: an aarch64 TCB is not an
  # x86 one plus a delta.
  #
  # The rule for a new entry: if the reason names a hypervisor or a syscall it
  # is `common`; if the reason names an instruction set it is `byArch`. A
  # driver for a device that only an x86 hypervisor emulates is `byArch` even
  # though the driver itself would compile anywhere — the claim being made is
  # about a platform, not about a compiler.
  common = {
    enable = [
      # --- core ---
      # `OS-023` (#339) says every entry here is justified or removed. One line
      # per group, and where a group has an entry that is not obvious it is
      # named.
      #
      #   EPOLL, EVENTFD  tokio's reactor and its Waker (`OS-024`, #340). This
      #                   comment used to say "mio is the one event loop", which
      #                   was true until that issue replaced it — mio is still
      #                   here, as tokio's insides, and is no longer the thing to
      #                   name.
      #   TIMERFD         tokio's timers, which is what `OS-024` was about: DHCP
      #                   at T1 and T2 (#335), SNTP polling (#336) and connection
      #                   deadlines all want one.
      #   SIGNALFD        `ctrlc`'s handler, and therefore the drain that
      #                   `OS-026` (#343)'s power button reaches.
      #   FUTEX           any `std::sync` primitive, of which the console pump and
      #                   the reaper both use several.
      #   MULTIUSER       `std` will not build without the uid/gid syscalls.
      #   BINFMT_ELF      how the kernel executes `/init`. Nothing else runs, and
      #                   nothing else needs a loader.
      #   PRINTK_TIME     the timestamps every diagnosis on this target has used.
      #
      # `ELF_CORE` was in this group and is gone. It is gated by `CONFIG_COREDUMP`,
      # which `tinyconfig` turns off, so enabling it changed nothing — removing it
      # produced a byte-identical `kernel.config`. There is nowhere to write a core
      # dump to anyway (axiom A5), and pid 1 dying is a kernel panic rather than a
      # dump. Third inert entry found by `OS-023` (#339), after `DEBUG_KERNEL` and
      # the `IP_PNP` group.
      "64BIT" "SMP" "MULTIUSER" "POSIX_TIMERS" "FUTEX" "EPOLL" "EVENTFD"
      "SIGNALFD" "TIMERFD" "BINFMT_ELF" "PRINTK" "PRINTK_TIME" "BUG"

      # Kept for `SEC-005` (#197), which is not written yet — so this is a
      # *reservation*, and saying so is the point. The comment here used to read
      # as though the mitigation were already applied; nothing in this tree calls
      # `seccomp(2)` today. Measured cost of keeping it: see `.#linux-deltas`.
      "SECCOMP" "SECCOMP_FILTER"

      # A relocatable kernel and a randomised base, stated rather than inherited
      # (`OS-032`, #376).
      #
      # x86's `tinyconfig` answers `y` to both without being asked and aarch64's
      # does not, so until this was named the two kernels differed on KASLR and
      # nothing said so. That is the `OS-006` (#257) shape again, in the one
      # direction that matters most: a mitigation the older target had and the
      # newer one silently did not.
      "RELOCATABLE" "RANDOMIZE_BASE"

      # --- no block layer at all ---
      # Not "no block drivers": CONFIG_BLOCK is unset, so axiom A5 is a syscall
      # with nothing behind it rather than a promise under test. The boot medium
      # is invisible to the kernel — firmware reads the ESP and the image runs
      # from RAM thereafter — so no ATAPI, no SCSI and no ISO9660 are needed
      # either.
      "BLK_DEV_INITRD" "RD_GZIP" "RD_ZSTD"

      # --- boot ---
      # EFI_STUB is what makes the kernel image simultaneously a PE/COFF
      # executable and a bootable kernel, which is what lets one file serve as
      # both the removable-media EFI path and — where there is a BIOS at all —
      # an isolinux KERNEL line.
      "EFI" "EFI_STUB" "ACPI" "PCI" "PCI_MSI"

      # --- console: serial AND framebuffer ---
      # The framebuffer is not a luxury. A VM created from the Proxmox web UI has
      # no serial port, and `OS-005` (#256) exists because on Hermit that meant a
      # machine that booted in complete silence. fbcon means the noVNC console
      # shows the boot and the panic without anyone configuring anything.
      #
      # The 8250 is in `common` and not in `byArch`, and that is a measurement
      # rather than a guess. EC2's aarch64 instances present a **16550A**, not a
      # PL011 — observed on a Graviton host, where ACPI SPCR reads
      # `console: uart,mmio,0x90a0000,115200` and the kernel says
      # `0000:00:01.0: ttyS0 at MMIO 0x80000000 … is a 16550A`. So both
      # architectures need this driver and only one of them also needs a PL011.
      "TTY" "VT" "VT_CONSOLE" "UNIX98_PTYS"
      "SERIAL_8250" "SERIAL_8250_CONSOLE" "SERIAL_8250_PCI"
      "SYSFB_SIMPLEFB" "DRM" "DRM_SIMPLEDRM"
      "DRM_FBDEV_EMULATION" "FB_CORE" "FRAMEBUFFER_CONSOLE"

      # --- net ---
      # `IP_PNP` and `IP_PNP_DHCP` are gone as of `OS-019` (#335). The kernel's
      # built-in client took a lease and never renewed it, and it discarded
      # options 15, 42 and 119 — which are the ones this host most needs, since
      # they are the domain the SRV record goes in (`DISC-007`, #149) and the time
      # servers `OS-020` (#336) prefers. `kmsrs-os` speaks DHCP itself now, so
      # there is one implementation rather than two that can disagree.
      #
      # PACKET stays: a DHCP client that has no address yet is the classic user of
      # a packet socket. This one does not need it — every message it sends before
      # it is bound sets the broadcast flag, so an ordinary UDP socket on
      # 0.0.0.0:68 receives the reply — but `OS-023` (#339) is where removing it
      # gets argued and measured, not here.
      #
      # E1000 is one driver for very broad reach: every hypervisor can emulate an
      # Intel NIC, so it is the difference between "boots on Proxmox" and "boots
      # wherever someone tries it". That holds on aarch64 too — Proxmox's model
      # list is one static list for every architecture, and VMware Fusion and
      # Parallels on Apple Silicon both offer an emulated Intel adapter.
      "NET" "INET" "IPV6" "PACKET" "UNIX" "SYSVIPC"
      "NETDEVICES" "ETHERNET" "NET_CORE"
      "VIRTIO_NET" "NET_VENDOR_INTEL" "E1000" "E1000E"

      # EC2 Nitro (`OS-027`, #344), on both architectures. This one moved out of
      # the x86 platform matrix in `OS-032` (#376), because Graviton is Nitro
      # too: an `ena` interface is exactly what a `c8g` instance shows, observed
      # on one.
      "NET_VENDOR_AMAZON" "ENA_ETHERNET"

      # --- VMBus (`OS-025`, #342) ---
      #
      # This list used to say hv_netvsc "drags in the whole VMBus stack, which is
      # not a driver-sized cost". That comment is superseded twice over.
      #
      # It is wrong on the facts. Measured: **-36 KiB** to keep on x86, less than
      # twice a plain PCI driver and a quarter of what the Xen paravirt stack
      # costs. The estimate was never taken on a built image, which is what
      # `.#linux-deltas` now exists to prevent — and the number is negative
      # because the variant that produces it asks what this costs to keep
      # (`OS-038`, #391), which is the only direction a driver already in the
      # list can be priced in.
      #
      # And it was answering the wrong question. Hyper-V Generation 2 has **no
      # emulated NIC at all** — there is no PCI device to fall back to — so on
      # that platform this is not a driver, it is the difference between supported
      # and unsupported. Azure is Generation 2, and arrives with it — including
      # its Cobalt 100 aarch64 instances, which is why this is `common`.
      "HYPERV" "HYPERV_NET"

      # --- virtio ---
      # VIRTIO_CONSOLE and VIRTIO_BALLOON are for `OS-022` (#338). The balloon is
      # one of the devices Hermit rejected as transitional (0x1002, #255); it
      # works here for the same reason virtio-net does.
      # HW_RANDOM_VIRTIO is worth ~2.3s of boot — see `OS-023` (#339).
      "VIRTIO" "VIRTIO_MENU" "VIRTIO_PCI" "VIRTIO_PCI_LEGACY"
      "VIRTIO_BALLOON" "VIRTIO_CONSOLE"
      "HW_RANDOM" "HW_RANDOM_VIRTIO"

      # --- filesystems: ram only ---
      "PROC_FS" "PROC_SYSCTL" "SYSFS" "TMPFS" "SHMEM"
      "DEVTMPFS" "DEVTMPFS_MOUNT"

      # --- the power button ---
      # `OS-026` (#343). `qm shutdown` — and every other hypervisor's polite stop
      # — is an ACPI power-button event, which the kernel delivers as an *input*
      # event and nothing else. Nothing was reading it, so the press was
      # discarded, an operator watched the web UI's Shutdown button do nothing,
      # and the VM eventually got `qm stop`: the hypervisor pulling the power on a
      # host with connections in flight.
      #
      # Two of these three were already on and neither was in this list.
      # `olddefconfig` had answered `y` to CONFIG_INPUT and CONFIG_ACPI_BUTTON as
      # dependencies of the console, and to CONFIG_INPUT_KEYBOARD,
      # CONFIG_KEYBOARD_ATKBD, CONFIG_INPUT_MOUSE, the whole of CONFIG_MOUSE_PS2
      # and CONFIG_SERIO along with them. So the machine has had an AT keyboard
      # driver and PS/2 mouse support in its TCB since `OS-017` (#333), and the
      # only thing missing was the userland interface that would let this program
      # read the button.
      #
      # That is the `OS-006` (#257) lesson again: this list is what was *asked
      # for*, and the built config is what was *got*. Naming all three here — and
      # naming everything they drag in on the disable side — makes this change a
      # net removal of about fifty lines from the built config rather than an
      # addition. Measured on the built bzImage with the initramfs held constant:
      # 2 405 376 -> 2 368 512 bytes, so handling the power button *saves* 36 KiB.
      #
      # The same three carry the aarch64 press. There the button is a `-machine
      # virt` ACPI **GED** event rather than a fixed-hardware power button, and
      # `OS-032` (#376) had it down as the thing most likely to need a fourth
      # symbol. It does not: `evged.c` is in `acpi-y` unconditionally, so ACPI
      # brings it, and the GED handler raises the same `ACPI_BUTTON` device that
      # surfaces as `KEY_POWER` on evdev. Observed, not reasoned — see the
      # `linux-boot` check.
      "INPUT" "INPUT_EVDEV" "ACPI_BUTTON"
    ];

    # Asserted, not assumed. `make olddefconfig` can re-enable something as a
    # dependency of an entry above, so these are stated explicitly and the built
    # artefact is checked separately — the lesson of `OS-006` (#257), where a
    # test read the list that was supposed to produce the kernel rather than the
    # kernel.
    disable = [
      "BLOCK" "MODULES" "NETFILTER" "BPF_SYSCALL" "FTRACE" "KPROBES"
      "SUSPEND" "HIBERNATION" "ACPI_AC" "ACPI_BATTERY"
      "SOUND" "USB_SUPPORT" "WLAN" "BT"
      # `olddefconfig` answers `y` to most of what hangs off CONFIG_INPUT — the AT
      # keyboard, PS/2 mice, the SERIO bus they sit on — and it had already done
      # so, unasked, since `OS-017` (#333). The power button needs the event layer
      # and nothing else, so every one of them is named here. Asserted rather than
      # assumed, per the `OS-006` (#257) lesson (`OS-026`, #343).
      "INPUT_MOUSEDEV" "INPUT_JOYDEV" "INPUT_KEYBOARD" "INPUT_MOUSE"
      "INPUT_JOYSTICK" "INPUT_TABLET" "INPUT_TOUCHSCREEN" "INPUT_MISC"
      "INPUT_FF_MEMLESS" "INPUT_LEDS" "SERIO"
      "NAMESPACES" "CGROUPS" "SECURITY" "KVM" "VFIO"
      "SCSI" "ATA" "NVME_CORE" "MD" "BLK_DEV"
      "EXT4_FS" "OVERLAY_FS" "FUSE_FS" "ISO9660_FS" "VFAT_FS" "NFS_FS"
      "9P_FS" "VIRTIO_FS" "VIRTIO_BLK"

      # `OS-023` (#339): drivers nobody asked for, on since `OS-017` (#333).
      # Found by reading the *built* config rather than this list, which is the
      # whole lesson of `OS-006` (#257) and is now `kernel_tcb.rs`'s job.
      #
      #   I2C_HID        HID over I2C — a laptop touchpad transport. Arrived with
      #                  the input subsystem; a hypervisor emulates no such bus.
      #   THERMAL        thermal zones and governors. A VM has no temperature to
      #                  govern, and could do nothing about it if it had.
      #   HID            the human-interface-device stack, and HID_GENERIC with
      #                  it. The power button is an ACPI device read through
      #                  evdev; nothing here is a HID.
      #
      # ACPI_THERMAL goes with them: it is the ACPI thermal-zone driver, and a
      # guest has no zones. `CONFIG_THERMAL` itself stays and is deliberately
      # *not* on this list — `CONFIG_ACPI_PROCESSOR` selects it, and that one
      # earns its place, since ACPI idle states are what let a host that is idle
      # 99.99 % of the time stop burning a core on the hypervisor. Chasing
      # THERMAL out would mean giving that up for a few kilobytes. That holds on
      # both architectures: `ACPI_PROCESSOR` is `depends on X86 || ARM64 || …`,
      # `default y`, and selects THERMAL on either.
      #
      # Same shape as the `DEBUG_KERNEL` finding below: an entry that cannot be
      # honoured is worse than no entry, so the reason is written down instead.
      "I2C_HID" "ACPI_THERMAL"
      "HID" "HID_GENERIC"

      # `DEBUG_KERNEL` was here and has been removed, because it is a statement
      # this build cannot make. `tinyconfig` requires `CONFIG_EXPERT`, and EXPERT
      # *selects* DEBUG_KERNEL — init/Kconfig says so, with the comment "Unhide
      # debug options, to make the on-by-default options visible". So it is a menu
      # gate rather than code, `olddefconfig` turns it back on every time, and it
      # sat on this list for two issues doing nothing.
      #
      # What it unhides is what actually costs something, so that is what is named
      # instead. `kernel_tcb.rs` asserts all of it against the *built* config.
      "DEBUG_MISC" "DYNAMIC_DEBUG" "DEBUG_FS" "KGDB" "MAGIC_SYSRQ"
      "KASAN" "KCSAN" "UBSAN" "DEBUG_KMEMLEAK" "GDB_SCRIPTS"
      # `OS-019` (#335). Asserted rather than merely omitted: `olddefconfig`
      # answers `y` to IP_PNP as a dependency of things that have nothing to do
      # with it, and two DHCP clients in one machine is exactly the disagreement
      # this issue removed.
      "IP_PNP" "IP_PNP_DHCP" "IP_PNP_BOOTP" "IP_PNP_RARP"

      # `OS-035` (#383): the 8250 driver's PCI-card and PnP variants. Every one
      # of them is `default SERIAL_8250` or `default y`, so all three arrived
      # with the console driver and none was ever asked for — `OS-006` (#257)
      # again, and shared rather than per-architecture because both answered the
      # same way and neither had said so.
      #
      #   SERIAL_8250_EXAR      Exar XR17C/XR17V and Commtech multiport PCIe
      #                         serial cards
      #   SERIAL_8250_PERICOM   Pericom and Acces I/O PCIe UARTs
      #   SERIAL_8250_PNP       ports enumerated on the PnP bus
      #
      # The first two are cards; no hypervisor in the matrix emulates one. The
      # PnP entry is the only one that needed an argument rather than a reading,
      # because it is the one that could plausibly be how a console appears —
      # and on neither architecture is it:
      #
      #   * on x86 the port is found because it is where every PC's port is.
      #     `arch/x86/include/asm/serial.h` defines `SERIAL_PORT_DFNS` as ttyS0
      #     at 0x3F8 on IRQ 4, and the table it builds is in `8250_platform.o`,
      #     which is `8250-y` and therefore unconditional.
      #   * on aarch64 there is no `asm/serial.h` at all, so that table is empty
      #     and every port arrives over PCI, ACPI or DT. Observed on the one
      #     machine in the matrix whose console is a 16550A rather than a
      #     PL011 — an EC2 Graviton instance, where the kernel says
      #     `pci 0000:00:01.0: [1d0f:8250]` and then `0000:00:01.0: ttyS0 at
      #     MMIO 0x80000000 (irq = 14, base_baud = 115200) is a 16550A`. A PCI
      #     device, bound by `SERIAL_8250_PCI`, which stays.
      #
      # Kconfig's own help says the same thing: "You may be able to disable this
      # feature if you only need legacy serial support."
      #
      # Worth **8 KiB** on each architecture — `serial-8250-variants` in
      # `.#linux-deltas`, which is five symbols on x86 (the two below go with
      # them) and three here, and lands on the same number both times. Asked in
      # the enable direction, because they are off in the checked-in
      # configuration and a delta has to be taken against a baseline that does
      # not already contain what is being priced.
      "SERIAL_8250_EXAR" "SERIAL_8250_PERICOM" "SERIAL_8250_PNP"

      # About seventy `NET_VENDOR_*` menus are `y` in both generated files with
      # no driver enabled under any of them, and none is named here. That is a
      # decision rather than an oversight (`OS-035`, #383; declined item D45).
      #
      # Measured before it was argued about: `.#linux-deltas` has a
      # `no-vendor-menus` variant that turns off every one, and the delta is
      # **0 bytes on both architectures**. A vendor menu is a `bool … default y`
      # whose only effect is that `drivers/net/ethernet/Makefile` descends into
      # that vendor's directory, where every object is gated by a driver symbol
      # of its own — all of which are off.
      #
      # So it would be seventy lines here against zero bytes and no behaviour
      # change, in a file whose whole purpose is to be read as a statement. What
      # actually guards against a driver arriving unasked is that
      # `kernel.config` is checked in: a new `=y` shows up in a diff, which is
      # how every finding in `OS-023` (#339), `OS-026` (#343) and `OS-034`
      # (#382) was made.

      # `OS-025` (#342): the Xen *paravirt* path, declined on the measurement.
      #
      # `XEN` + `XEN_NETDEV_FRONTEND` costs **+140 KiB** — 6 % of the whole
      # kernel, and 3.9 times what VMBus costs — because it is xenbus, grant
      # tables and event channels rather than a driver. This is one of the two
      # driver variants still asked in the *enable* direction, and legitimately
      # so: it is not in the list, so what there is to price is what putting it
      # back would cost (`OS-038`, #391). What it buys is better throughput on
      # XCP-ng and Citrix Hypervisor, whose *default* emulated NIC is RTL8139 and
      # therefore already works for the 8 KiB that driver costs to keep.
      #
      # A host that answers one 384-byte request per client per few hours does not
      # need the faster path, so this is the one row of the matrix taken by the
      # emulated device rather than the paravirtual one. Named here rather than
      # merely omitted, so the trade is visible when somebody proposes it again.
      "XEN" "XEN_NETDEV_FRONTEND"
    ];
  };

  byArch = {
    x86_64 = {
      enable = [
        # --- paravirt guest ---
        # KVM_GUEST brings kvmclock, which is doing NTP's job until `OS-020`
        # (#336) lands: this host validates client timestamps against a band.
        #
        # All three are x86 symbols. aarch64 has no `KVM_GUEST` and needs none:
        # the architected timer is the clock source there, and it is not a
        # paravirt device.
        "HYPERVISOR_GUEST" "PARAVIRT" "KVM_GUEST"

        # HYPERV_TIMER is here for the same reason `KVM_GUEST` is: the reference
        # TSC keeps the clock close between the SNTP polls of `OS-020` (#336).
        # It is `def_bool HYPERV && X86` in `drivers/hv/Kconfig`, which is why it
        # is in this half and not beside `HYPERV` in `common`.
        "HYPERV_TIMER"

        # --- the rest of the platform matrix (`OS-025`, #342) ---
        #
        # Two of the four NIC models the Proxmox web UI offers used to produce a
        # machine that booted to completion, printed `listening`, and served nobody
        # forever. No driver, so no interface, so no address, and nothing said so.
        # Every driver below is a row in the matrix in `docs/deployment.md`, and
        # every one has a measured cost rather than an estimated one — run
        # `nix build .#linux-deltas` to reproduce the numbers, which are taken on
        # the built bzImage with the initramfs held constant.
        #
        # **Negative, and that is the direction the command asks in** (`OS-038`,
        # #391). These drivers are in this list, so the question a shipped
        # configuration can act on is what each costs to *keep*, and a variant
        # that enabled what is already enabled produced a config identical to the
        # baseline and a delta of exactly zero. The numbers here used to be
        # positive because `OS-025` (#342) took them at the moment each driver was
        # added, when the baseline did not contain it — right when written, and
        # not reproducible by running the command this comment names.
        #
        #   vmxnet3   -20 KiB   VMware ESXi and Workstation's default for a modern
        #                       Linux guest; Proxmox's "VMware vmxnet3" entry
        #   8139cp    -8 KiB    Proxmox's "Realtek RTL8139" entry, and the default
        #   8139too             emulated NIC on Xen HVM (XCP-ng, Citrix)
        #   pcnet32   -8 KiB    VirtualBox's older adapter choices
        #   tulip     -12 KiB   Hyper-V Generation 1's "Legacy Network Adapter",
        #                       which is a DEC 21140
        #   ena       -24 KiB   EC2 Nitro (`OS-027`, #344); in `common`, priced
        #                       here because this is where the table is
        #   hv_netvsc -36 KiB   Hyper-V and Azure; likewise `common`
        #
        # All six together — `no-emulated-nics` — **-116 KiB**,
        # 2 442 240 -> 2 323 456. *More* than the sum of the rows, which is -108
        # KiB, and the asymmetry is the reason the aggregate is measured rather
        # than added up: removing the last user of a shared helper takes the
        # helper with it, and no single row can show that. Asked in the enable
        # direction the same set gave a number smaller than its sum, for the
        # mirror-image reason — two drivers sharing a vendor gate paid for it
        # once.
        #
        # This whole group is x86 as of `OS-032` (#376), and the reason is the
        # platform rather than the driver. Every product in it either does not
        # exist on aarch64 (VirtualBox's pcnet, Hyper-V Generation 1's DEC 21140,
        # Xen HVM's RTL8139) or does not offer that adapter there (VMware Fusion
        # on Apple Silicon has no vmxnet3). `ena` went the other way, into
        # `common`, because Graviton is Nitro.
        #
        # No `NET_VENDOR_VMWARE` beside `VMXNET3`, and its absence is a
        # correction rather than an oversight (`OS-034`, #382). Every other
        # driver here sits under a vendor menu; this one does not. `VMXNET3` is
        # declared straight in `drivers/net/Kconfig` and the code lives in
        # `drivers/net/vmxnet3/` rather than under `drivers/net/ethernet/`, so
        # there is no gate to open and the entry that named one was inert.
        "VMXNET3"
        "NET_VENDOR_REALTEK" "8139CP" "8139TOO"
        "NET_VENDOR_AMD" "PCNET32"
        "NET_VENDOR_DEC" "NET_TULIP" "TULIP"

        # --- entropy, which is not a setting here ---
        #
        # `RANDOM_TRUST_CPU` and `RANDOM_TRUST_BOOTLOADER` were named here and
        # are gone (`OS-034`, #382). Not because the behaviour they asked for
        # was declined — it is what this kernel does — but because neither is a
        # Kconfig symbol any more. `drivers/char/random.c` carries
        # `static bool trust_cpu __initdata = true;` and a `random.trust_cpu=`
        # boot parameter, and the bootloader seed is `random.trust_bootloader=`
        # the same way.
        #
        # So the guarantee is a **default**, and the only way to change it is a
        # command line this image does not pass. There is nothing to enable, and
        # an entry that enables nothing reads as a decision while being a no-op.
        # `kernel_tcb.rs` now fails on one rather than letting the next person
        # find it while looking at something else, so re-adding either of these
        # is a test failure rather than a line that quietly does nothing.
      ];

      disable = [
        # `OS-023` (#339). The Intel Management Engine interface: a guest has no
        # ME, and nothing here would talk to one if it did. x86 only, since the
        # symbol does not exist elsewhere.
        "INTEL_MEI" "INTEL_MEI_ME"

        # The Intel SoC UARTs (`OS-035`, #383). Both are `default SERIAL_8250`
        # like the group in `common`, and both are `depends on X86`, which is
        # why they are here and not there: LPSS is Baytrail, Braswell and Quark,
        # MID is Medfield. No hypervisor emulates an Intel SoC.
        #
        # `SERIAL_8250_DWLIB` is deliberately not named beside them. It has no
        # prompt and exists only to be `select`ed by these two, so disabling
        # them makes it *unreachable* rather than merely off — which is a
        # stronger statement, and one `kernel_tcb.rs` asserts as such.
        # `CONFIG_RATIONAL` goes the same way for the same reason.
        "SERIAL_8250_LPSS" "SERIAL_8250_MID"

        # `PERF_EVENTS` is deliberately **not** on this list, and its absence is
        # the answer to `OS-035` (#383) rather than an oversight.
        #
        # #383 filed the asymmetry: aarch64 disables `perf_event_open(2)` and
        # x86 does not, so the two kernels this project ships differ on whether
        # a large syscall with a JIT-adjacent history exists, and nobody chose
        # that. It is real, and it cannot be fixed here. `arch/x86/Kconfig`
        # gives `config X86` an unconditional `select PERF_EVENTS`: there is no
        # x86 kernel without it, at any Kconfig setting.
        #
        # Measured rather than read, because that is this file's rule —
        # disabling it and running `olddefconfig` produces a byte-identical
        # configuration. That is also why `linuxDeltaVariants` has no
        # `no-perf-events` for this architecture: the delta would be exactly
        # zero, and a zero here reads as "perf costs nothing" when it means "the
        # question could not be asked". The same trap as `no-smp` on aarch64,
        # which the flake declines for the same reason.
        #
        # What can still be said is what each kernel actually contains, and
        # `perf_events_is_absent_on_one_target_and_forced_on_the_other` in
        # `kernel_tcb.rs` says it per target — so the day this stops being
        # forced, a test fails rather than a comment quietly going stale.
      ];
    };

    # `OS-032` (#376). Not a port of the list above — several of these groups
    # have no x86 counterpart at all, and two of the x86 groups have none here.
    #
    # # What the shared drivers cost *here*
    #
    # `OS-025` (#342) requires a measured number per driver, and a number taken
    # on the other architecture is not one. Everything below is
    # `.#linux-deltas` on aarch64 with the initramfs held constant, against a
    # 2 740 736-byte `vmlinuz.efi` baseline — so these are the costs of the
    # entries that live in `common` above, priced on this target.
    #
    # The three driver rows are **magnitudes**, and the command prints them as
    # negative deltas: those variants are `{ disable = … }`, because the drivers
    # are in the list and the answerable question is what each costs to keep
    # (`OS-023`, #339). The two rows below them that are marked `+` are the
    # enable direction, because those symbols are *not* in the list. `OS-038`
    # (#391) is where reading a sign as a direction stopped being optional.
    #
    #   e1000 + e1000e   +100 KiB   Proxmox's Intel entries, and what Parallels
    #                               and Fusion present on Apple Silicon
    #   hv_netvsc        +40 KiB    Azure's Cobalt 100 instances
    #   ena              +32 KiB    EC2 Graviton
    #   KASLR            +4 KiB     the `RANDOMIZE_BASE` entry in `common`
    #
    # And two numbers that decided something rather than merely reporting:
    #
    #   virtio-gpu       +12 KiB    **not taken.** A `virt` machine with a
    #                               virtio GPU instead of a `ramfb` loses the
    #                               EFI framebuffer at ExitBootServices, and
    #                               `simpledrm` has nothing to take over. Cheap,
    #                               but nothing observed needs it yet; the
    #                               measurement is kept so the question can be
    #                               settled with a number when it is asked.
    #   no IPv6          -156 KiB   the largest saving available and still
    #                               declined, for the reason `OS-023` (#339)
    #                               declines it on x86: clients reach this host
    #                               over whatever the network gives them.
    #
    # Compare the x86 table above and the shape is different: there the NIC
    # drivers are the interesting numbers, and here the interesting number is
    # the **image format**, which is 30 times any driver.
    aarch64 = {
      enable = [
        # --- the memory map ---
        #
        # 4 KiB pages and a 48-bit virtual address space, both stated rather
        # than defaulted. `olddefconfig` chooses `ARM64_VA_BITS_52` and with it
        # `ARM64_LPA2`, which is correct code and is not what anybody ships:
        # Amazon Linux 2023's aarch64 kernel is 4K/48/48, and so is Debian's.
        # A host whose whole pitch is "attach the ISO and boot it" is the wrong
        # place to be the one machine running the less-travelled page-table
        # format, so the choice is pinned and `ARM64_VA_BITS_52` is named on the
        # disable side — which is how a Kconfig `choice` is pinned at all.
        "ARM64_4K_PAGES" "ARM64_VA_BITS_48"

        # --- interrupts, timer, and turning the machine off ---
        #
        # Every one of these is implicit on x86 and explicit here, which is the
        # single biggest reason `OS-032` (#376) says the aarch64 file is not a
        # port of the x86 one.
        #
        #   ARM_GIC_V3      the interrupt controller. QEMU's `virt` and every
        #                   server-class Arm machine present GICv3; Graviton
        #                   reports `GICv3: 96 SPIs implemented`.
        #   ARM_GIC_V3_ITS  message-signalled interrupts, which is what
        #                   virtio-pci and every other PCIe device uses. Without
        #                   it a PCIe NIC attaches and never raises an interrupt.
        #   ARM_ARCH_TIMER  the architected timer — the counterpart of kvmclock,
        #                   except that it is in the architecture rather than in
        #                   a paravirt device.
        #   ARM_PSCI_FW     the firmware interface that powers the machine off.
        #                   x86 reaches ACPI S5 through `reboot()`; here the same
        #                   syscall ends in an SMC to firmware.
        #
        # `ACPI_GED` is deliberately absent, and that is a measurement rather
        # than an omission. `OS-032` had it down as a required symbol; there is
        # no such Kconfig option in 6.12. `drivers/acpi/Makefile` puts `evged.o`
        # in `acpi-y` unconditionally, so the Generic Event Device arrives with
        # `CONFIG_ACPI` and there is nothing to enable.
        "ARM_GIC_V3" "ARM_GIC_V3_ITS" "ARM_ARCH_TIMER" "ARM_PSCI_FW"

        # --- PCI, stated ---
        #
        # x86 gets its host bridge from `CONFIG_PCI` and legacy port I/O. On
        # aarch64 the bridge is a device like any other: `PCI_HOST_GENERIC`
        # drives the one QEMU's `virt` and the Arm SBSA describe, and `PCI_ECAM`
        # is how its configuration space is reached. Without both, a machine
        # with a virtio NIC on PCIe has no bus to find it on.
        "PCI_HOST_GENERIC" "PCI_ECAM"

        # --- the console the other architecture does not have ---
        #
        # QEMU's `virt` machine puts a PL011 at the low end of the MMIO map and
        # the kernel calls it `ttyAMA0`. It is an AMBA peripheral, so there is
        # no counterpart on x86 at all.
        #
        # Note what is *not* here: the 8250. That is in `common`, because EC2's
        # aarch64 instances present a 16550A rather than a PL011 — measured on a
        # Graviton host. An aarch64 machine therefore needs both drivers and
        # both `console=` arguments, which is what `arch.consoles` carries.
        "SERIAL_AMBA_PL011" "SERIAL_AMBA_PL011_CONSOLE"

        # --- the image format ---
        #
        # `CONFIG_EFI_ZBOOT` replaces the uncompressed `Image` with
        # `vmlinuz.efi`, a compressed PE that firmware runs directly. Measured
        # with `.#linux-deltas`, initramfs held constant: **6 611 456 ->
        # 2 740 736 bytes**, a saving of **3.69 MiB and 58 %**. On the shipped
        # kernel, with the real initramfs inside it, 7 660 032 -> 3 760 640 —
        # which is what brings this image within 300 KiB of the x86 one instead
        # of twice its size. arm64 has no self-decompressing counterpart of
        # `bzImage`, so without this there is nothing else to reach for.
        #
        # It costs nothing here, because this target is EFI-only anyway — there
        # is no BIOS to want a raw `Image` (`OS-033`, #377).
        #
        # It also makes the measurements honest. `Image` is padded, so its size
        # is a coarse instrument: enabling `DRM_VIRTIO_GPU` changes the file's
        # contents and not its length, and a driver that reports a delta of
        # zero is a driver nobody can price. A compressed image moves for every
        # byte, which is why x86's numbers have always meant something.
        #
        # Amazon Linux 2023's aarch64 kernel is built with it, so this is not a
        # path only this image takes.
        "EFI_ZBOOT"

        # --- entropy ---
        #
        # `OS-032` (#376) expected this to be the awkward group, since
        # `RANDOM_TRUST_CPU` is x86-flavoured. It is not awkward, and not for
        # the expected reason: that symbol no longer exists on any architecture
        # (`OS-034`, #382).
        #
        # What is here instead is real. `HW_RANDOM_ARM_SMCCC_TRNG` is the
        # architected SMCCC TRNG call — an entropy source in firmware, which
        # every KVM host and AAVMF build provides, and which needs no device.
        # `virtio-rng` is in `common` and is the other source; the machine has
        # two, and `getrandom(2)` blocks on neither.
        "HW_RANDOM_ARM_SMCCC_TRNG"
      ];

      disable = [
        # 32-bit Arm userspace. There is one binary in this image and it is
        # aarch64, so `COMPAT` is a second syscall table, a second signal-frame
        # layout and a second set of `compat_` entry points with nothing to
        # call them. x86's `IA32_EMULATION` is off for the same reason, and
        # `tinyconfig` had already answered `n` there; here `olddefconfig`
        # answers `y`, so it has to be said.
        "COMPAT"

        # The device-tree thermal framework, which is the aarch64 counterpart of
        # the `ACPI_THERMAL` entry in `common` — `default y if OF`, and a guest
        # has no thermal zones to govern either way.
        "THERMAL_OF"

        # `perf_event_open(2)` is a large syscall with a JIT-adjacent history
        # and no user in an image that contains one program. aarch64's
        # `tinyconfig` leaves it off; this says so, so that a future dependency
        # cannot turn it on quietly.
        #
        # x86 has it **on** and cannot have it off: `config X86` carries an
        # unconditional `select PERF_EVENTS`. So this is not the asymmetry #383
        # thought it was — it is not a decision one architecture took and the
        # other did not, it is a decision only one architecture is allowed to
        # take. The x86 disable list above is where that is written down.
        #
        # Keeping it out is worth **56 KiB** here, which is the one side of the
        # question that has a number: `perf-events` in `.#linux-deltas`, asked
        # in the enable direction because it is off in this baseline.
        "PERF_EVENTS"

        # Not a security decision: this is how a Kconfig `choice` is pinned.
        # `ARM64_VA_BITS_48` above cannot win the choice while the default
        # member is still set, so the default member is cleared here.
        "ARM64_VA_BITS_52"
      ];
    };
  };

  selected = byArch.${arch.name} or (throw
    "no kernel allowlist for ${arch.name}. A target with no list of its own \
     would be built from another architecture's TCB statement, which is the \
     `OS-006` (#257) failure `OS-031` (#375) exists to prevent");

  enable = common.enable ++ selected.enable;
  disable = common.disable ++ selected.disable;
in
pkgs.runCommand "kmsrsos-kernel-config-${arch.name}"
{
  nativeBuildInputs = with pkgs; [
    bison flex bc perl gnumake gcc pkg-config ncurses openssl elfutils
    python3Minimal
  ];
} ''
  tar xf ${base.src}
  cd linux-*
  patchShebangs scripts/

  make ARCH=${arch.kernelArch} tinyconfig

  for opt in ${builtins.concatStringsSep " " enable}; do
    ./scripts/config --enable "$opt"
  done
  for opt in ${builtins.concatStringsSep " " disable}; do
    ./scripts/config --disable "$opt"
  done

  make ARCH=${arch.kernelArch} olddefconfig

  # The initramfs and command line are appended by `default.nix` at build time,
  # because both reference store paths. Strip any that survived so the checked-in
  # file never carries a stale one.
  sed -e '/^CONFIG_INITRAMFS_SOURCE/d' -e '/^CONFIG_CMDLINE/d' \
      -e '/^# CONFIG_CMDLINE/d' .config > $out
''

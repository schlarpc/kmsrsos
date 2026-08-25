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
{ pkgs ? import <nixpkgs> { }
, base ? pkgs.linux_6_12
}:

let
  enable = [
    # --- core ---
    # `OS-023` (#339) says every entry here is justified or removed. One line
    # per group, and where a group has an entry that is not obvious it is named.
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

    # --- no block layer at all ---
    # Not "no block drivers": CONFIG_BLOCK is unset, so axiom A5 is a syscall
    # with nothing behind it rather than a promise under test. The boot medium
    # is invisible to the kernel — UEFI reads the ESP and the image runs from
    # RAM thereafter — so no ATAPI, no SCSI and no ISO9660 are needed either.
    "BLK_DEV_INITRD" "RD_GZIP" "RD_ZSTD"

    # --- boot ---
    # EFI_STUB is what makes the bzImage simultaneously a PE/COFF executable
    # and a Linux boot image, which is what lets one file serve as both
    # \EFI\BOOT\BOOTX64.EFI and an isolinux KERNEL line.
    "EFI" "EFI_STUB" "ACPI" "PCI" "PCI_MSI"

    # --- paravirt guest ---
    # KVM_GUEST brings kvmclock, which is doing NTP's job until `OS-020`
    # (#336) lands: this host validates client timestamps against a band.
    "HYPERVISOR_GUEST" "PARAVIRT" "KVM_GUEST"

    # --- console: serial AND framebuffer ---
    # The framebuffer is not a luxury. A VM created from the Proxmox web UI has
    # no serial port, and `OS-005` (#256) exists because on Hermit that meant a
    # machine that booted in complete silence. fbcon means the noVNC console
    # shows the boot and the panic without anyone configuring anything.
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
    # wherever someone tries it".
    "NET" "INET" "IPV6" "PACKET" "UNIX" "SYSVIPC"
    "NETDEVICES" "ETHERNET" "NET_CORE"
    "VIRTIO_NET" "NET_VENDOR_INTEL" "E1000" "E1000E"

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
    #   vmxnet3   +24 KiB   VMware ESXi and Workstation's default for a modern
    #                       Linux guest; Proxmox's "VMware vmxnet3" entry
    #   8139cp    +12 KiB   Proxmox's "Realtek RTL8139" entry, and the default
    #   8139too             emulated NIC on Xen HVM (XCP-ng, Citrix)
    #   pcnet32   +12 KiB   VirtualBox's older adapter choices
    #   tulip     +16 KiB   Hyper-V Generation 1's "Legacy Network Adapter",
    #                       which is a DEC 21140
    #   ena       +24 KiB   EC2 Nitro (`OS-027`, #344)
    #
    # All of them together: **+120 KiB**, 2 364 416 -> 2 487 296. Less than the
    # sum, because two drivers sharing a vendor gate pay for it once.
    "NET_VENDOR_VMWARE" "VMXNET3"
    "NET_VENDOR_REALTEK" "8139CP" "8139TOO"
    "NET_VENDOR_AMD" "PCNET32"
    "NET_VENDOR_DEC" "NET_TULIP" "TULIP"
    "NET_VENDOR_AMAZON" "ENA_ETHERNET"

    # --- VMBus (`OS-025`, #342) ---
    #
    # This list used to say hv_netvsc "drags in the whole VMBus stack, which is
    # not a driver-sized cost". That comment is superseded twice over.
    #
    # It is wrong on the facts. Measured: **+40 KiB**, less than twice a plain
    # PCI driver and a sixth of what the Xen paravirt stack costs. The estimate
    # was never taken on a built image, which is what `.#linux-deltas` now
    # exists to prevent.
    #
    # And it was answering the wrong question. Hyper-V Generation 2 has **no
    # emulated NIC at all** — there is no PCI device to fall back to — so on
    # that platform this is not a driver, it is the difference between supported
    # and unsupported. Azure is Generation 2, and arrives with it.
    #
    # HYPERV_TIMER is here for the same reason `KVM_GUEST` is: the reference
    # TSC keeps the clock close between the SNTP polls of `OS-020` (#336).
    "HYPERV" "HYPERV_NET" "HYPERV_TIMER"

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
    "INPUT" "INPUT_EVDEV" "ACPI_BUTTON"

    "RANDOM_TRUST_CPU" "RANDOM_TRUST_BOOTLOADER"
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

    # `OS-023` (#339): four drivers nobody asked for, on since `OS-017` (#333).
    # Found by reading the *built* config rather than this list, which is the
    # whole lesson of `OS-006` (#257) and is now `kernel_tcb.rs`'s job.
    #
    #   INTEL_MEI      the Intel Management Engine interface. A guest has no ME,
    #   INTEL_MEI_ME   and nothing here would talk to one if it did.
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
    # THERMAL out would mean giving that up for a few kilobytes.
    #
    # Same shape as the `DEBUG_KERNEL` finding above: an entry that cannot be
    # honoured is worse than no entry, so the reason is written down instead.
    "INTEL_MEI" "INTEL_MEI_ME" "I2C_HID" "ACPI_THERMAL"
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

    # `OS-025` (#342): the Xen *paravirt* path, declined on the measurement.
    #
    # `XEN` + `XEN_NETDEV_FRONTEND` costs **+148 KiB** — 6 % of the whole
    # kernel, and 3.7 times what VMBus costs — because it is xenbus, grant
    # tables and event channels rather than a driver. What it buys is better
    # throughput on XCP-ng and Citrix Hypervisor, whose *default* emulated NIC
    # is RTL8139 and therefore already works for +12 KiB.
    #
    # A host that answers one 384-byte request per client per few hours does not
    # need the faster path, so this is the one row of the matrix taken by the
    # emulated device rather than the paravirtual one. Named here rather than
    # merely omitted, so the trade is visible when somebody proposes it again.
    "XEN" "XEN_NETDEV_FRONTEND"
  ];
in
pkgs.runCommand "kmsrsos-kernel-config"
{
  nativeBuildInputs = with pkgs; [
    bison flex bc perl gnumake gcc pkg-config ncurses openssl elfutils
    python3Minimal
  ];
} ''
  tar xf ${base.src}
  cd linux-*
  patchShebangs scripts/

  make ARCH=x86_64 tinyconfig

  for opt in ${builtins.concatStringsSep " " enable}; do
    ./scripts/config --enable "$opt"
  done
  for opt in ${builtins.concatStringsSep " " disable}; do
    ./scripts/config --disable "$opt"
  done

  make ARCH=x86_64 olddefconfig

  # The initramfs and command line are appended by `default.nix` at build time,
  # because both reference store paths. Strip any that survived so the checked-in
  # file never carries a stale one.
  sed -e '/^CONFIG_INITRAMFS_SOURCE/d' -e '/^CONFIG_CMDLINE/d' \
      -e '/^# CONFIG_CMDLINE/d' .config > $out
''

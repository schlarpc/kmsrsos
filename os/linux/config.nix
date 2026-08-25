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
    # EPOLL and EVENTFD are not optional: mio is the one event loop on every
    # target (`ARCH-005`), and its Waker is an eventfd.
    "64BIT" "SMP" "MULTIUSER" "POSIX_TIMERS" "FUTEX" "EPOLL" "EVENTFD"
    "SIGNALFD" "TIMERFD" "BINFMT_ELF" "PRINTK" "PRINTK_TIME" "BUG" "ELF_CORE"

    # Retained deliberately. A unikernel has no privilege separation at all;
    # this is the one mitigation that lets a network-facing pid 1 running as
    # root give up everything but its event loop once it has bound.
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
    # wherever someone tries it". hv_netvsc is deliberately absent — it drags in
    # the whole VMBus stack, which is not a driver-sized cost.
    "NET" "INET" "IPV6" "PACKET" "UNIX" "SYSVIPC"
    "NETDEVICES" "ETHERNET" "NET_CORE"
    "VIRTIO_NET" "NET_VENDOR_INTEL" "E1000" "E1000E"

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
    "9P_FS" "VIRTIO_FS" "VIRTIO_BLK" "DEBUG_KERNEL"
    # `OS-019` (#335). Asserted rather than merely omitted: `olddefconfig`
    # answers `y` to IP_PNP as a dependency of things that have nothing to do
    # with it, and two DHCP clients in one machine is exactly the disagreement
    # this issue removed.
    "IP_PNP" "IP_PNP_DHCP" "IP_PNP_BOOTP" "IP_PNP_RARP"
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

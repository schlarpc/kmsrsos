# Regenerates `kernel.config` (`OS-017`, #333).
#
# `kernel.config` is checked in rather than generated at build time, because
# `buildLinux` reads it at *evaluation* time and because the file is the point:
# it is the statement of what is in this machine's TCB, and a statement nobody
# can read in a diff is not one. Regenerate with:
#
#     nix build -f os/linux/config.nix && cp result os/linux/kernel.config
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
    # PACKET is for the DHCP client of `OS-019` (#335), which needs raw sockets.
    # E1000 is one driver for very broad reach: every hypervisor can emulate an
    # Intel NIC, so it is the difference between "boots on Proxmox" and "boots
    # wherever someone tries it". hv_netvsc is deliberately absent — it drags in
    # the whole VMBus stack, which is not a driver-sized cost.
    "NET" "INET" "IPV6" "PACKET" "UNIX" "SYSVIPC"
    "IP_PNP" "IP_PNP_DHCP"
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
    "SOUND" "USB_SUPPORT" "WLAN" "BT" "INPUT_MOUSEDEV"
    "NAMESPACES" "CGROUPS" "SECURITY" "KVM" "VFIO"
    "SCSI" "ATA" "NVME_CORE" "MD" "BLK_DEV"
    "EXT4_FS" "OVERLAY_FS" "FUSE_FS" "ISO9660_FS" "VFAT_FS" "NFS_FS"
    "9P_FS" "VIRTIO_FS" "VIRTIO_BLK" "DEBUG_KERNEL"
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

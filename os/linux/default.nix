# The Linux-as-PID-1 bare-metal target (`OS-017`, #333).
#
# One machine, one program: a kernel built from `kernel.config` with
# `kmsrs-server` as pid 1 and no other userland at all. No init system, no
# shell, no libc on disk — the initramfs is the binary and one device node.
#
# The artefact is a single `bzImage`, and it is deliberately *self-contained*:
#
#   - `CONFIG_INITRAMFS_SOURCE` puts the initramfs inside it, so there is no
#     separate initrd to load or lose.
#   - `CONFIG_CMDLINE` + `CONFIG_CMDLINE_OVERRIDE` put the command line inside
#     it, so a bootloader that passes a different one is *ignored*. That is
#     axiom A3 rather than a convenience: the kernel command line stops being a
#     runtime surface (`CFG-001`, #166).
#
# `CONFIG_EFI_STUB` makes that file simultaneously a PE/COFF executable and a
# Linux boot image — `MZ` at 0 and `HdrS` at 0x202 — so the *same bytes* are
# both `\EFI\BOOT\BOOTX64.EFI` for firmware and an isolinux `KERNEL` line for
# BIOS. That is why the ISO boots on a Proxmox VM with nothing changed from the
# defaults, which the Hermit image cannot do (`OS-004`, #255).
{ pkgs
  # `kmsrs-os` (`OS-021`, #337), not `kmsrs-server`: pid 1 mounts devtmpfs,
  # `/proc` and `/sys` and installs a reaper before handing over to the same
  # `serve` the Linux and Windows builds run.
, init
  # `ip=dhcp` is the kernel's built-in client and is a stopgap: it takes a lease
  # and never renews it. `OS-019` (#335) replaces it with a real client in
  # `kmsrs-os` and drops `CONFIG_IP_PNP_DHCP`.
  #
  # `console=` order no longer decides anything (`OS-028`, #345).
  #
  # It used to. Kernel messages go to every console listed, but /dev/console —
  # which the kernel hands init as fds 0/1/2 — resolves to the LAST one, so
  # whichever console came last got the program's own log lines and the other
  # showed a clean boot followed by silence. That reads exactly like a program
  # that never started (`OS-005`, #256), and which console it happened to was a
  # property of the platform: the framebuffer is what a Proxmox operator has,
  # `ttyS0` is all EC2's `GetConsoleOutput` can read.
  #
  # Pid 1 now reads /proc/consoles and writes to all of them, so there is no
  # ordering left to get wrong. `tty0` is last deliberately anyway, for two
  # reasons that agree: it is the better fallback if the tee ever fails to
  # install, since Proxmox is the supported platform and noVNC is the console
  # its operator has; and it is the ordering that would silence the serial log
  # without the tee, which is what makes the boot check in `nix flake check` a
  # real regression test rather than a formality.
, cmdline ? "console=ttyS0,115200 console=tty0 ip=dhcp panic=-1 loglevel=6"
, base ? pkgs.linux_6_12
}:

let
  # A gen_init_cpio manifest, not a cpio archive. `usr/Makefile` treats
  # CONFIG_INITRAMFS_SOURCE as a ready-made archive only when the filename ends
  # in `.cpio`; anything else it feeds to its own gen_init_cpio as a file list.
  # Handing it the manifest is the better half of that deal — the kernel builds
  # the archive, so nothing here compiles gen_init_cpio or has to agree with it
  # about cpio format.
  #
  # The /dev/console node is NOT redundant, though an *external* initrd would
  # get it for free. The kernel links in its own `usr/default_cpio_list` — which
  # carries exactly this node — and falls back to it only when
  # CONFIG_INITRAMFS_SOURCE is empty. Setting it *replaces* the built-in rather
  # than adding to it, and without the node `console_on_rootfs()` cannot give
  # init fds 0/1/2:
  #
  #   Warning: unable to open an initial console.
  #   Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b
  #
  # Everything else /dev should hold comes from devtmpfs, which pid 1 mounts
  # itself (`OS-021`, #337).
  manifest = pkgs.writeText "kmsrsos-initramfs-manifest" ''
    dir /dev 0755 0 0
    nod /dev/console 0600 0 0 c 5 1
    file /init ${init}/bin/kmsrs-os 0755 0 0
  '';

  configfile = pkgs.runCommand "kmsrsos-linux-config" { } ''
    cp ${./kernel.config} $out
    chmod +w $out
    cat >> $out <<EOF
    CONFIG_INITRAMFS_SOURCE="${manifest}"
    CONFIG_INITRAMFS_ROOT_UID=0
    CONFIG_INITRAMFS_ROOT_GID=0
    CONFIG_INITRAMFS_COMPRESSION_ZSTD=y
    CONFIG_CMDLINE_BOOL=y
    CONFIG_CMDLINE="${cmdline}"
    CONFIG_CMDLINE_OVERRIDE=y
    EOF
    sed -i 's/^ *//' $out
  '';

  kernel = pkgs.linuxKernel.manualConfig {
    inherit (base) version src;
    pname = "kmsrsos-linux";
    inherit configfile;
    allowImportFromDerivation = true;
  };

  # UEFI reads only FAT, so the firmware path needs the image in an ESP.
  esp = pkgs.runCommand "kmsrsos-linux-esp"
    { nativeBuildInputs = [ pkgs.dosfstools pkgs.mtools ]; } ''
    sz=$(( ( $(stat -Lc %s ${kernel}/bzImage) / 1048576 + 3 ) ))
    truncate -s "''${sz}M" esp.img
    mkfs.vfat -n ESP esp.img
    mmd -i esp.img ::/EFI ::/EFI/BOOT
    mcopy -i esp.img ${kernel}/bzImage ::/EFI/BOOT/BOOTX64.EFI
    cp esp.img $out
  '';

  # The bzImage appears twice — once in ISO9660 for isolinux, once in the FAT
  # ESP for firmware — because the two read different filesystems and neither
  # reads the other's. `OS-023` (#339) holds the decision about whether to spend
  # a GRUB to recover the ~2.7 MB.
  iso = pkgs.runCommand "kmsrsos-linux.iso"
    { nativeBuildInputs = [ pkgs.xorriso pkgs.syslinux ]; } ''
    mkdir -p iso/isolinux
    cp ${kernel}/bzImage iso/bzImage
    cp ${pkgs.syslinux}/share/syslinux/isolinux.bin iso/isolinux/
    cp ${pkgs.syslinux}/share/syslinux/ldlinux.c32 iso/isolinux/
    chmod +w iso/isolinux/isolinux.bin

    # No APPEND and no INITRD: both are inside the image, and CMDLINE_OVERRIDE
    # means anything written here would be ignored anyway.
    cat > iso/isolinux/isolinux.cfg <<EOF
    DEFAULT kmsrsos
    PROMPT 0
    TIMEOUT 1
    LABEL kmsrsos
      KERNEL /bzImage
    EOF
    sed -i 's/^ *//' iso/isolinux/isolinux.cfg

    cp ${esp} iso/efi.img

    xorriso -as mkisofs -V KMSRSOS \
      -b isolinux/isolinux.bin -c isolinux/boot.cat \
      -no-emul-boot -boot-load-size 4 -boot-info-table \
      -eltorito-alt-boot -e efi.img -no-emul-boot \
      -isohybrid-gpt-basdat \
      -append_partition 2 0xef iso/efi.img \
      -o $out iso/
  '';
in
{ inherit kernel esp iso configfile; }

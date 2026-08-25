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
  # `ip=dhcp` is gone with `CONFIG_IP_PNP_DHCP` (`OS-019`, #335): `kmsrs-os`
  # speaks DHCP itself now. It was left here after that change and the kernel
  # said so on every boot —
  #
  #     Unknown kernel command line parameters "ip=dhcp", will be passed to
  #     user space.
  #
  # — which is harmless and is exactly the kind of line that teaches an operator
  # to stop reading the console.
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
, cmdline ? "console=ttyS0,115200 console=tty0 panic=-1 loglevel=6"
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
  #
  # Sized from the kernel plus a measured margin, not a round number. This used
  # to be `bzImage / 1 MiB + 3`, which had two problems (`OS-029`, #347):
  #
  #   * **The 3 MiB was 85 times what FAT needs.** Measured by binary search on
  #     the real kernel: the smallest image `mkfs.vfat` will take the file in is
  #     3488 KiB against a 3457 KiB kernel, so the overhead is **31 KiB**.
  #   * **The division truncated**, so the margin shrank as the kernel grew
  #     towards the next megabyte. Harmless at +3 and a latent failure at +1,
  #     which is where this is going.
  #
  # So: round the kernel up to a megabyte having first added 256 KiB, which is
  # eight times the measured overhead and leaves the result monotonic in the
  # kernel size. Today that is 4 MiB for a 3.38 MiB kernel, against 6 MiB before.
  #
  # The filesystem is **FAT12** either way — checked, because the obvious worry
  # is that shrinking crosses a FAT12/16 boundary and changes what firmware will
  # accept. It does not: `mkfs.vfat` picks FAT12 for everything up to 8 MiB, so
  # 6 MiB was already FAT12 and this changes no compatibility variable. (The
  # UEFI specification asks for FAT32 on a *fixed* system partition and FAT12 or
  # FAT16 on removable media; this image has been FAT12 since `OS-017` (#333)
  # and boots OVMF, but see #347 for the note that EC2's fixed-disk path is
  # still unobserved.)
  esp = pkgs.runCommand "kmsrsos-linux-esp"
    { nativeBuildInputs = [ pkgs.dosfstools pkgs.mtools ]; } ''
    bytes=$(stat -Lc %s ${kernel}/bzImage)
    sz=$(( (bytes + 262144 + 1048575) / 1048576 ))
    truncate -s "''${sz}M" esp.img
    mkfs.vfat -n ESP esp.img
    mmd -i esp.img ::/EFI ::/EFI/BOOT
    mcopy -i esp.img ${kernel}/bzImage ::/EFI/BOOT/BOOTX64.EFI
    cp esp.img $out
  '';

  # The bzImage appears **twice**, and that is now the floor without a
  # bootloader (`OS-029`, #347):
  #
  #   1. `/bzImage` in ISO9660, which isolinux boots — BIOS, from a CD.
  #   2. inside the appended FAT ESP, which serves *both* remaining firmware
  #      paths: El Torito for UEFI-from-CD, and the GPT EFI System Partition
  #      for UEFI-from-disk that `OS-027` (#344) needs.
  #
  # It used to appear three times. `-e efi.img` pointed El Torito at a copy of
  # the ESP inside the ISO9660 tree while `-append_partition` appended a second,
  # byte-identical copy for the GPT — six megabytes of the same kernel twice, in
  # a 16.3 MB image. `-e --interval:appended_partition_2:all::` points El Torito
  # at the appended partition instead, so the file in the tree is not needed at
  # all. This is the recipe Debian and Arch build with.
  #
  # 1 and 2 cannot be collapsed without a bootloader that reads ISO9660: the two
  # firmware paths read different filesystems and neither reads the other's.
  # `OS-023` (#339) declined to spend a GRUB on that, and #348 re-examines the
  # decision against the corrected numbers. See `docs/decisions.md`.
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

    # No `cp ${esp} iso/efi.img`: the ESP is *appended* below and El Torito is
    # pointed at the appended partition, so a copy in the tree would be six
    # megabytes nothing reads (`OS-029`, #347).

    # `-isohybrid-mbr` and `-appended_part_as_gpt` are `OS-027` (#344), and
    # they fix something that was silently doing nothing.
    #
    # `-isohybrid-gpt-basdat` on its own is **inert**: it is a modifier to the
    # isohybrid MBR, and without `-isohybrid-mbr` there is no isohybrid MBR to
    # modify. Measured on the shipped file before this change — no `EFI PART`
    # anywhere in it, and offsets 0..445 all zero, so no GPT and no boot code
    # either. What it produced was a plain MBR label with a type-0x83 entry over
    # the ISO9660 area.
    #
    # With all three, the same file is additionally a real GPT disk with a
    # protective MBR and a properly typed EFI System Partition
    # (`C12A7328-F81F-11D2-BA4B-00A0C93EC93B`) — which is what UEFI firmware
    # looks for when the file is presented as a *disk* rather than a CD, and
    # therefore what makes the EC2 pipeline possible.
    #
    # Observed, on all four combinations that matter:
    #
    #              | disk/BIOS | disk/UEFI | cdrom/BIOS | cdrom/UEFI
    #     before   |     no    |    yes    |    yes     |    yes
    #     after    |    yes    |    yes    |    yes     |    yes
    #
    # So it strictly adds BIOS-from-a-disk and loses nothing — which also
    # settles the open question on #344: **syslinux's MBR code does still
    # chainload under a protective MBR**, so the conformant layout is available
    # rather than the hybrid one being forced.
    #
    # Cost: 145 408 bytes, from 13 826 048 to 13 971 456. Almost none of that is
    # the 446-byte bootstrap — it is the two GPT tables plus the ESP moving to a
    # 2048-sector boundary.
    xorriso -as mkisofs -V KMSRSOS \
      -b isolinux/isolinux.bin -c isolinux/boot.cat \
      -no-emul-boot -boot-load-size 4 -boot-info-table \
      -eltorito-alt-boot \
      -e --interval:appended_partition_2:all:: -no-emul-boot \
      -isohybrid-mbr ${pkgs.syslinux}/share/syslinux/isohdpfx.bin \
      -isohybrid-gpt-basdat \
      -appended_part_as_gpt \
      -append_partition 2 0xef ${esp} \
      -o $out iso/
  '';
in
{ inherit kernel esp iso configfile; }

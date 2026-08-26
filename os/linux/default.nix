# The Linux-as-PID-1 bare-metal target (`OS-017`, #333).
#
# One machine, one program: a kernel built from `kernel.config` with
# `kmsrs-server` as pid 1 and no other userland at all. No init system, no
# shell, no libc on disk — the initramfs is the binary and one device node.
#
# The artefact is a single kernel image — `arch.image`, which is `bzImage` on
# x86 — and it is deliberately *self-contained*:
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
# both the removable-media EFI path for firmware and an isolinux `KERNEL` line
# for BIOS. That is why the ISO boots on a Proxmox VM with nothing changed from
# the defaults, which the Hermit image cannot do (`OS-004`, #255).
{ pkgs
  # The target architecture (`OS-031`, #375), as `linuxArches` in `flake.nix`
  # describes it. Every architecture literal this file used to hold — the
  # kernel's `ARCH=`, the image filename, the EFI boot filename, the console
  # device, and which `kernel.config` is the right one — is a field on it.
  #
  # No default. A default would be the thing this issue exists to remove: one
  # architecture that is "the" architecture, silently correct for the caller
  # who forgot to say and silently wrong for the one who meant the other.
, arch
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
  #
  # Which devices those consoles *are* is the architecture's (`OS-031`, #375;
  # `OS-032`, #376). `ttyS0` is an 8250 at a legacy I/O port, which is a fact
  # about x86 and not about Linux — and aarch64 needs two serial entries, not
  # one, because QEMU's `virt` has a PL011 and EC2's Graviton has a 16550A.
  # `tty0` is last on every architecture, for the `OS-028` (#345) reason.
, cmdline ? builtins.concatStringsSep " "
    ((map (device: "console=${device}") arch.consoles)
      ++ [ "panic=-1" "loglevel=6" ])
, base ? pkgs.linux_6_12
  # `PKG-016` (#366): what every timestamp in the ISO is set to.
  #
  # Without it the image is **not reproducible**, and the failure is invisible:
  # two builds of one revision differed by 74 bytes, every one of them a date in
  # the volume descriptor or a directory record, with no content difference at
  # all. `nix build .#linuxIso --rebuild` said so on the same machine.
  #
  # Two sources of drift, and both need closing:
  #
  #   * `cp` gives every file in the staging tree the mtime of *now*, and
  #     xorriso copies those into the directory records.
  #   * xorriso stamps the volume descriptor with the current time unless told
  #     otherwise.
  #
  # The default is the Unix epoch so that a direct `import` of this file is
  # reproducible too; the flake passes `self.lastModified`, which is the same
  # stamp `SOURCE_DATE_EPOCH` gives the Rust builds.
, sourceDateEpoch ? "0"
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

  configfile = pkgs.runCommand "kmsrsos-linux-${arch.name}-config" { } ''
    cp ${arch.config} $out
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

  # `target` is what `make` is asked for and what lands in `$out`. nixpkgs
  # picks it from the host platform — `bzImage` on x86, `Image` on aarch64 —
  # and that default is wrong for a target using `CONFIG_EFI_ZBOOT`, which
  # produces `vmlinuz.efi` and leaves `Image` where it was (`OS-032`, #376).
  # The descriptor already names the file, so it names it here too.
  kernel = pkgs.linuxKernel.manualConfig {
    inherit (base) version src;
    pname = "kmsrsos-linux-${arch.name}";
    inherit configfile;
    allowImportFromDerivation = true;
    target = arch.image;
  };

  # The UEFI bootloader (`OS-030`, #348).
  #
  # # Why there is one at all, when there was none
  #
  # `CONFIG_EFI_STUB` makes the `bzImage` its own EFI executable, so until now
  # the UEFI path had *no bootloader*: the ESP held the kernel as
  # `\EFI\BOOT\BOOTX64.EFI` and firmware ran it directly. That is the cleanest
  # thing this image ever did, and it cost a whole second copy of the kernel —
  # UEFI reads only FAT and isolinux reads only ISO9660, so each firmware path
  # needed the kernel in its own filesystem.
  #
  # `OS-023` (#339) declined to spend a bootloader on collapsing that, against a
  # saving recorded as "~2.7 MB" which was arithmetic on a three-copy image.
  # `OS-029` (#347) removed the third copy for free, and `OS-030` (#348)
  # re-took the decision against the measured number. See `docs/decisions.md`.
  #
  # # What makes this one acceptable
  #
  # The objection to GRUB was never its size — it was that GRUB is a program
  # with a configuration language, a module loader and a filesystem stack, in an
  # image whose contents are otherwise enumerable in a sentence. Every part of
  # that is answered by *how* this is built rather than by accepting it:
  #
  #   * **`grub-mkimage`, not `grub-mkrescue` or `grub-install`.** The module
  #     list below is the complete set of modules that exist in the artefact.
  #     There is no `/boot/grub/x86_64-efi` directory in the ESP and no module
  #     path to load from, so the module loader has nothing it *can* load. A
  #     module that is not named here is not present.
  #   * **The configuration is inside the image, not on the filesystem.** `-c`
  #     embeds it in the PE file. There is no `grub.cfg` in the ESP to edit,
  #     which is axiom A3 — the build decides — applied to the bootloader in the
  #     same way `CONFIG_CMDLINE_OVERRIDE` applies it to the kernel command
  #     line.
  #   * **No `normal` module, so there is no menu and no scripting.** The
  #     embedded config is executed by the rescue parser, which runs a list of
  #     commands and has no `if`, no functions and no `menuentry`. The
  #     "configuration language" objection is answered by not shipping the
  #     interpreter for it.
  #   * **No `configfile`, and no shell.** Nothing here can be talked into
  #     reading a config from disk, and there is no interactive path: the last
  #     command boots, and the one after it halts.
  #
  # So what is added is a fixed, auditable blob that runs four commands. That is
  # a larger trusted computing base than "none", which is the honest cost, and
  # it is a much smaller one than the word "GRUB" implies.
  #
  # # The modules, and why each is here
  #
  # | module | why |
  # |---|---|
  # | `part_gpt`, `part_msdos` | find the partitions on a raw-disk import (`OS-027`, #344); the image is both |
  # | `iso9660` | read the one copy of the kernel, which is what this is all for |
  # | `search`, `search_label` | find the ISO9660 volume by its label instead of guessing a device name |
  # | `linux` | load a `bzImage` through the EFI handover protocol |
  # | `halt` | stop, rather than fall through to a rescue prompt, if the search fails |
  #
  # Notably absent: `fat`. The ESP holds this file and nothing else, so nothing
  # ever reads it — firmware loads `BOOTX64.EFI` itself, and everything after
  # that is in ISO9660.
  grubModules = [
    "part_gpt"
    "part_msdos"
    "iso9660"
    "search"
    "search_label"
    "linux"
    "halt"
  ];

  # Four commands, and the last two are the failure path.
  #
  # `--set=root` rather than a hardcoded `(cd0)` or `(hd0)`: the same file boots
  # as a CD-ROM and as a raw disk, and the device name differs between them.
  # Searching by the volume label is the one form that is correct for both.
  #
  # No `APPEND` and no `initrd`, for the same reason isolinux has neither: both
  # are inside the `bzImage`, and `CONFIG_CMDLINE_OVERRIDE` means a command line
  # passed here would be ignored.
  grubCfg = pkgs.writeText "kmsrsos-grub.cfg" ''
    search --no-floppy --set=root --label KMSRSOS
    linux /${arch.image}
    boot
    halt
  '';

  # An empty `--prefix` is deliberate and is the last part of the argument
  # above. The prefix is where GRUB looks for modules and for a `grub.cfg` at
  # run time; leaving it empty means there is nowhere for it to look, so the
  # only modules that can ever be loaded are the ones linked in here and the
  # only configuration is the one embedded by `--config`.
  grub = pkgs.runCommand "kmsrsos-grub-${arch.name}.efi"
    { nativeBuildInputs = [ pkgs.grub2_efi ]; } ''
    grub-mkimage \
      --format=${arch.grubFormat} \
      --output=$out \
      --config=${grubCfg} \
      --prefix="" \
      ${pkgs.lib.concatStringsSep " " grubModules}
  '';

  # UEFI reads only FAT, so the firmware path needs its loader in an ESP.
  #
  # Sized from the loader plus a measured margin, not a round number
  # (`OS-029`, #347): round up to a megabyte having first added 256 KiB, which
  # is eight times the 31 KiB `mkfs.vfat` was measured to need and leaves the
  # result monotonic in the file size.
  #
  # Since `OS-030` (#348) what goes in is a ~1 MiB `grubx64.efi` rather than a
  # 3.4 MiB kernel, so this is 2 MiB rather than 4 MiB — and the kernel is no
  # longer in here at all.
  #
  # The filesystem is FAT12 either way, which is what the UEFI specification
  # asks for on removable media and what this image has been since `OS-017`
  # (#333). `mkfs.vfat` picks FAT12 for everything up to 8 MiB, so shrinking
  # does not cross a boundary and changes no compatibility variable.
  esp = pkgs.runCommand "kmsrsos-linux-${arch.name}-esp"
    { nativeBuildInputs = [ pkgs.dosfstools pkgs.mtools ]; } ''
    bytes=$(stat -Lc %s ${grub})
    sz=$(( (bytes + 262144 + 1048575) / 1048576 ))
    truncate -s "''${sz}M" esp.img
    mkfs.vfat -n ESP esp.img
    mmd -i esp.img ::/EFI ::/EFI/BOOT
    mcopy -i esp.img ${grub} ::/EFI/BOOT/${arch.efiFile}
    cp esp.img $out
  '';

  # The bzImage appears **once** (`OS-030`, #348).
  #
  # `/bzImage` in ISO9660 is the only copy, and all four boot combinations reach
  # it there:
  #
  #   | | BIOS | UEFI |
  #   |---|---|---|
  #   | **CD-ROM** | isolinux, El Torito no-emul | `grubx64.efi`, El Torito pointed at the appended ESP |
  #   | **raw disk** | isolinux via the isohybrid MBR | `grubx64.efi` from the GPT EFI System Partition |
  #
  # Both bootloaders read ISO9660, so neither needs its own copy. The ESP now
  # holds a ~1 MiB loader instead of a 3.4 MiB kernel, which is where the saving
  # comes from — not from removing a partition, since `OS-027` (#344) needs the
  # ESP to exist for the raw-disk import either way.
  #
  # The count has gone 3 → 2 → 1 across three issues, and each step was a
  # different mistake or trade:
  #
  #   * **Three** was a bug. `-e efi.img` pointed El Torito at a copy of the ESP
  #     inside the ISO9660 tree while `-append_partition` appended a second,
  #     byte-identical copy for the GPT — the same kernel twice over, 10.6 MB of
  #     a 16.3 MB image. `OS-029` (#347) fixed it with
  #     `-e --interval:appended_partition_2:all::`, which is the recipe Debian
  #     and Arch build with, and cost nothing.
  #   * **Two** was the floor without a bootloader that reads ISO9660, because
  #     UEFI reads only FAT and isolinux reads only ISO9660.
  #   * **One** is what `OS-030` (#348) bought, by putting a deliberately
  #     minimal GRUB in the ESP. See the `grub` derivation above for what makes
  #     it minimal, and `docs/decisions.md` for the argument.
  #
  # `linux-iso-layout` counts the copies in the bytes rather than reading them
  # off this recipe, which is the only form of the claim that cannot drift —
  # the comment here said "twice" for the whole time it was three.
  iso = pkgs.runCommand "kmsrsos-linux-${arch.name}.iso"
    { nativeBuildInputs = [ pkgs.xorriso pkgs.syslinux ]; } ''
    mkdir -p iso/isolinux
    cp ${kernel}/${arch.image} iso/${arch.image}
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
      KERNEL /${arch.image}
    EOF
    sed -i 's/^ *//' iso/isolinux/isolinux.cfg

    # No `cp ${esp} iso/efi.img`: the ESP is *appended* below and El Torito is
    # pointed at the appended partition, so a copy in the tree would be a
    # megabyte nothing reads (`OS-029`, #347).

    # `PKG-016` (#366): every file's mtime, before xorriso reads them into the
    # directory records. `cp` above set them all to the moment this ran.
    find iso -exec touch -h -d "@${sourceDateEpoch}" {} +

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
    # `--modification-date` is the volume descriptor's own timestamp, which is
    # separate from the file dates above and drifts on its own
    # (`PKG-016`, #366). `date -u` because the field has no zone.
    stamp=$(date -u -d "@${sourceDateEpoch}" +%Y%m%d%H%M%S00)

    xorriso -as mkisofs -V KMSRSOS \
      --modification-date="$stamp" \
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
{ inherit kernel esp iso configfile grub; }

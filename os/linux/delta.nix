# Measure what a kernel-config change costs, on the built bzImage
# (`OS-025`, #342; `OS-023`, #339).
#
# `OS-025` says every driver added to `config.nix` must carry "its measured
# `bzImage` delta", and `OS-023` says the pare-back may not remove anything the
# matrix needs. Both are arguments about numbers, and both are easy to get
# wrong by measuring the wrong thing:
#
#   * **The initramfs is inside the bzImage.** `CONFIG_INITRAMFS_SOURCE` embeds
#     it, so any change to the `kmsrs-os` binary moves the total by more than a
#     40 kB driver does. Measuring a driver against the shipped kernel compares
#     two numbers that differ for two reasons.
#   * **`olddefconfig` answers for the entries you did not name.** Enabling one
#     symbol can turn on a subsystem, which is exactly what `OS-026` (#343)
#     found. So the comparison has to be between two *built* configs, not
#     between two allowlists.
#
# So this builds a kernel per named config with **one fixed, minimal
# initramfs**, and the difference between two of its outputs is the config
# change and nothing else.
#
# Usage — the flake exposes it as `.#linux-deltas`, which measures the checked-in
# config against each variant `variants` describes:
#
#     nix build .#linux-deltas && cat result/report
#
# To measure a change you are making, build it before and after:
#
#     nix build .#linux-deltas && cp result/baseline/bzImage /tmp/before
#     # …edit config.nix, regenerate kernel.config…
#     nix build .#linux-deltas && stat -Lc %s /tmp/before result/baseline/bzImage
{ pkgs
  # The checked-in allowlist, as the thing every variant is measured against.
, base ? ./kernel.config
  # `{ name = [ "SYMBOL" … ]; }` — each becomes a kernel with those symbols
  # enabled on top of `base`, and a line in the report.
, variants ? { }
, kernel ? pkgs.linux_6_12
}:

let
  # One line, identical for every kernel here. The real manifest embeds the
  # `kmsrs-os` binary, whose size changes on every code change and would swamp
  # a driver-sized delta.
  manifest = pkgs.writeText "kmsrsos-delta-manifest" ''
    dir /dev 0755 0 0
    nod /dev/console 0600 0 0 c 5 1
  '';

  # The command line is fixed too, and short: it is inside the image, so a
  # longer one is a bigger image.
  cmdline = "console=ttyS0,115200 panic=-1";

  configFor = name: symbols: pkgs.runCommand "kmsrsos-delta-${name}-config"
    {
      nativeBuildInputs = with pkgs; [
        bison flex bc perl gnumake gcc pkg-config ncurses openssl elfutils
        python3Minimal
      ];
    } ''
    tar xf ${kernel.src}
    cd linux-*
    patchShebangs scripts/
    cp ${base} .config

    for opt in ${builtins.concatStringsSep " " symbols}; do
      ./scripts/config --enable "$opt"
    done

    # The same `olddefconfig` the real build runs, so a symbol that drags a
    # subsystem in is measured with the subsystem.
    make ARCH=x86_64 olddefconfig

    sed -e '/^CONFIG_INITRAMFS_SOURCE/d' -e '/^CONFIG_CMDLINE/d' \
        -e '/^# CONFIG_CMDLINE/d' .config > stripped
    cat stripped > $out
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

  buildFor = name: symbols: pkgs.linuxKernel.manualConfig {
    inherit (kernel) version src;
    pname = "kmsrsos-delta-${name}";
    configfile = configFor name symbols;
    allowImportFromDerivation = true;
  };

  built = { baseline = buildFor "baseline" [ ]; }
    // builtins.mapAttrs buildFor variants;

  names = builtins.attrNames built;
in
pkgs.runCommand "kmsrsos-kernel-deltas" { } ''
  mkdir -p $out
  ${builtins.concatStringsSep "\n" (map
    (name: "ln -s ${built.${name}} $out/${name}")
    names)}

  baseline=$(stat -Lc %s ${built.baseline}/bzImage)
  {
    echo "bzImage sizes, initramfs held constant (OS-025, #342)"
    echo
    printf '%-24s %10s %10s\n' variant bytes delta
    printf '%-24s %10s %10s\n' ------- ----- -----
    ${builtins.concatStringsSep "\n" (map
      (name: ''
        size=$(stat -Lc %s ${built.${name}}/bzImage)
        printf '%-24s %10s %+10s\n' ${name} "$size" "$((size - baseline))"
      '')
      names)}
  } > $out/report
  cat $out/report
''

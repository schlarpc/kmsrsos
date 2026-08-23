{
  description = "kmsrsos — a KMS host emulator in pure safe Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    systems.url = "github:nix-systems/default";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    # nix-direnv for the development shell
    nix-direnv = {
      url = "github:nix-community/nix-direnv";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # --- The two Hermit inputs (PKG-013, #250; PKG-014, #251) ---
    #
    # Inputs rather than fetchers in the build, so `flake.lock` pins them the
    # way it pins everything else (`PKG-006`, #243) and
    # `packaging_invariants.rs` does not have to grow an exception.
    #
    # The kernel is a whole separate program — its own lockfile, its own pinned
    # nightly, its own `xtask` — so it is `flake = false` source that
    # `packages.hermit-kernel` builds. The revision is not an arbitrary commit
    # on `main`: it is the one `hermit-os/hermit-rs` pins as its `kernel`
    # submodule, which is the pairing upstream CI runs in QEMU. Tags exist in
    # that repository but stopped tracking releases at 0.8.0, so a tag would be
    # the *less* specific choice.
    hermit-kernel = {
      url = "github:hermit-os/kernel/906ea2aae194d52af338e0be22812f90f791f927";
      flake = false;
    };

    # Every Hermit target is Tier 3, so rustup ships no `rust-std` for it and
    # this component supplies one. It is rebuilt per **exact** stable release:
    # the 1.96.1 artifact works with 1.96.1 and with nothing else, so the
    # version in this URL must equal `channel` in `rust-toolchain.toml`.
    # `tests/hermit_toolchain.rs` is what fails when they diverge, because what
    # rustc says instead is `can't find crate for core`.
    #
    # The alternative — `-Z build-std=std,panic_abort` — would put every crate
    # that ships on nightly to gain nothing this gives (`PKG-014`, #251).
    rust-std-hermit = {
      url = "https://github.com/hermit-os/rust-std-hermit/releases/download/1.96.1/rust-std-1.96.1-x86_64-unknown-hermit.tar.gz";
      flake = false;
      type = "tarball";
    };

    # The loader, which is what actually boots a Hermit application: the
    # application ELF is not a kernel image and QEMU cannot start it (`OS-001`,
    # #252). The multiboot build is the one `-kernel` takes, and it is what the
    # boot check uses; the UEFI build is a separate artefact and belongs with
    # the disk image (`OS-002`, #253).
    #
    # A released binary rather than a build from source: it is a third program
    # with a third pinned nightly, and `flake.lock` pins the bytes either way.
    hermit-loader-multiboot = {
      url = "https://github.com/hermit-os/loader/releases/download/v0.5.7/hermit-loader-x86_64-multiboot";
      flake = false;
      type = "file";
    };

    # The same loader as a UEFI application, which is what the bootable disk
    # image starts from (`OS-002`, #253). Same release as the multiboot build
    # above; they are two artefacts of one program and are bumped together.
    hermit-loader-efi = {
      url = "https://github.com/hermit-os/loader/releases/download/v0.5.7/hermit-loader-x86_64.efi";
      flake = false;
      type = "file";
    };
  };

  outputs =
    { self
    , nixpkgs
    , systems
    , rust-overlay
    , crane
    , nix-direnv
    , hermit-kernel
    , rust-std-hermit
    , hermit-loader-multiboot
    , hermit-loader-efi
    , ...
    }:
    let
      eachSystem = nixpkgs.lib.genAttrs (import systems);

      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      # Rust toolchain — pinned via rust-toolchain.toml (single source of truth,
      # and the MSRV; see ARCH-016, #16).
      rustToolchainFor = system:
        let pkgs = pkgsFor system;
        in pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      cranelibFor = system:
        let
          pkgs = pkgsFor system;
          rustToolchain = rustToolchainFor system;
        in
        (crane.mkLib pkgs).overrideToolchain rustToolchain;

      # `cleanCargoSource` keeps only Rust and Cargo files, which would drop
      # several things the *tests* read from disk. Everything added back here is
      # an input to the build in the same sense a source file is:
      #
      #   * the generated product data `kmsrs-db`'s build.rs compiles into
      #     static tables (DB-003, #127);
      #   * the committed golden wire vectors (TEST-002, #223) and fuzz seeds
      #     (TEST-006, #227), the latter because `kmsrs-vectors`' replay test
      #     reads them;
      #   * the packaging files, because `packaging_invariants.rs` asserts
      #     properties *of* them — that the image is two static binaries, that
      #     `replicas: 1` is hardcoded, that every dependency is pinned. A test
      #     that cannot see the file it is about is a test that passes for the
      #     wrong reason, and this filter is how it silently would.
      #
      # This does mean editing `flake.nix` rebuilds the workspace crates. It
      # does not rebuild dependencies: crane's `buildDepsOnly` builds from a
      # dummy source derived from the manifests, so the expensive layer is
      # unaffected.
      srcFor = system:
        let
          pkgs = pkgsFor system;
          craneLib = cranelibFor system;
        in
        pkgs.lib.cleanSourceWith {
          src = ./.;
          name = "kmsrsos-source";
          filter = path: type:
            (craneLib.filterCargoSources path type)
            || (builtins.match ".*/crates/kmsrs-db/data(/.*)?" path != null)
            || (builtins.match ".*/crates/kmsrs-vectors/vectors(/.*)?" path != null)
            || (builtins.match ".*/fuzz/seeds(/.*)?" path != null)
            # The committed web-UI and log-format snapshots (TEST-016, #237).
            || (builtins.match ".*/crates/kmsrs-server/snapshots(/.*)?" path != null)
            # What `packaging_invariants.rs` and `platform_invariants.rs` read.
            || (builtins.match ".*/flake\\.(nix|lock)" path != null)
            || (builtins.match ".*/rust-toolchain\\.toml" path != null)
            || (builtins.match ".*/deny\\.toml" path != null)
            || (builtins.match ".*/deploy(/.*)?" path != null)
            || (builtins.match ".*/docs(/.*)?" path != null)
            || (builtins.match ".*/ci(/.*)?" path != null)
            # nextest's profile, which decides the timeouts a test run uses.
            || (builtins.match ".*/\\.config(/.*)?" path != null)
            # The workflows, because `packaging_invariants.rs` asserts that a
            # release builds what the gate checks (PKG-003, #240).
            || (builtins.match ".*/\\.github(/.*)?" path != null);
        };

      commonArgsFor = system:
        let
          pkgs = pkgsFor system;
        in
        {
          src = srcFor system;
          strictDeps = true;

          # A virtual workspace has no root package for crane to read a name
          # from, so name the artifact explicitly.
          pname = "kmsrsos";
          version = "0.1.0";

          buildInputs = [ ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
          ];

          nativeBuildInputs = [ ];
        };

      cargoArtifactsFor = system:
        let craneLib = cranelibFor system;
        in craneLib.buildDepsOnly (commonArgsFor system);

      # --- Windows cross-compilation (x86_64-pc-windows-msvc) ---
      windowsTarget = "x86_64-pc-windows-msvc";

      xwinSdkFor = system:
        let pkgs = pkgsFor system;
        in pkgs.stdenvNoCC.mkDerivation {
          pname = "xwin-msvc-sdk";
          version = "crt-14.44.17.14-sdk-10.0.26100";

          nativeBuildInputs = [ pkgs.xwin pkgs.cacert ];

          dontUnpack = true;
          dontFixup = true;

          buildPhase = ''
            xwin \
              --accept-license \
              --cache-dir "$TMPDIR/xwin-cache" \
              --manifest-version 17 \
              --crt-version 14.44.17.14 \
              --sdk-version 10.0.26100 \
              --arch x86_64 \
              splat --copy --output "$out"
          '';

          outputHashMode = "recursive";
          outputHashAlgo = "sha256";
          outputHash = "sha256-UFQjsFVBwcF/9e9tVFoG0Z1JySxyTnFqoaRwr/tUWzA=";
        };

      windowsArgsFor = system:
        let
          pkgs = pkgsFor system;
          xwinSdk = xwinSdkFor system;
          commonArgs = commonArgsFor system;
        in
        commonArgs // {
          pnameSuffix = "-windows";

          nativeBuildInputs = commonArgs.nativeBuildInputs ++ [
            pkgs.llvmPackages.lld
          ];

          CARGO_BUILD_TARGET = windowsTarget;
          CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = "lld-link";
          CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = builtins.concatStringsSep " " [
            "-Lnative=${xwinSdk}/crt/lib/x86_64"
            "-Lnative=${xwinSdk}/sdk/lib/um/x86_64"
            "-Lnative=${xwinSdk}/sdk/lib/ucrt/x86_64"
          ];

          CC_x86_64_pc_windows_msvc = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang-cl";
          AR_x86_64_pc_windows_msvc = "${pkgs.llvmPackages.llvm}/bin/llvm-lib";
          CFLAGS_x86_64_pc_windows_msvc = builtins.concatStringsSep " " [
            "-imsvc${xwinSdk}/crt/include"
            "-imsvc${xwinSdk}/sdk/include/ucrt"
            "-imsvc${xwinSdk}/sdk/include/um"
            "-imsvc${xwinSdk}/sdk/include/shared"
          ];

          # Windows binaries can't run on the build host. `kmsrs-os` is a Hermit
          # binary and has nothing to say on Windows.
          doCheck = false;
          cargoExtraArgs = "--package kmsrs-server --package kmsrs-client";
        };

      windowsCargoArtifactsFor = system:
        let craneLib = cranelibFor system;
        in craneLib.buildDepsOnly (windowsArgsFor system);

      # --- Hermit unikernel (PKG-013, #250; PKG-014, #251) ---
      #
      # This was the largest schedule risk in the project, and the shape of the
      # risk was that the `hermit` crate is not a library at all: its `lib.rs` is
      # empty, and its `build.rs` shells out to a nested
      # `cargo run --package=xtask` that builds the kernel from a git submodule
      # against *its own* lockfile and *its own* pinned nightly. Crane vendors
      # neither, and a build script that runs `cargo` is a build script that
      # wants the network.
      #
      # So the crate is not used. The kernel is its own derivation, and the two
      # link flags the crate's build script would have emitted —
      # `-L native=…` and `-l static=hermit` — are injected directly. That is
      # the whole of what it does for a target that is not `common-os`, so
      # nothing is lost, and what is gained is that the nightly toolchain and
      # the vendored dependency tree the kernel needs stay inside one derivation
      # instead of leaking into the workspace.
      #
      # The two version-shaped things are the flake inputs above, which
      # `flake.lock` pins. What is left here is the kernel's own nightly, which
      # is not a version of anything we ship: it is a build input for one
      # derivation, in the same sense the pinned MSVC CRT is for the Windows
      # cross-build. It must equal `channel` in the kernel's own
      # `rust-toolchain.toml` at the pinned revision, because the kernel uses
      # `-Z build-std` and unstable flags that only that release accepts.
      hermitKernelNightly = "2026-08-01";

      hermitTarget = "x86_64-unknown-hermit";

      # `x86_64-unknown-none` is what the kernel proper is compiled for;
      # `rust-src` and `llvm-tools` are what `-Z build-std` and the symbol
      # rewriting need.
      hermitNightlyFor = system:
        let pkgs = pkgsFor system;
        in pkgs.rust-bin.nightly.${hermitKernelNightly}.default.override {
          extensions = [ "rust-src" "llvm-tools" ];
          targets = [ "x86_64-unknown-none" ];
        };

      # --- The kernel's feature set (OS-006, #257) ---
      #
      # Axiom A5 says no disk I/O. On Linux and Windows that is a promise this
      # program keeps; on Hermit it is a property of the machine, because a
      # kernel built without a filesystem transport has no code that could open
      # anything. The `--no-default-features` this list implies is what makes
      # the difference structural rather than a rule somebody could relax.
      #
      # It is the kernel's own default set minus two entries:
      #
      #   * **`virtio-fs`**, the obvious one, and the only file-shaped device
      #     QEMU could otherwise hand a Hermit guest.
      #   * **`uhyve`**, the less obvious one. Uhyve is a Hermit-specific VMM
      #     whose guest interface includes `open`/`read`/`write`/`close`
      #     hypercalls and a `UHYVE_MOUNT` path map — a filesystem reached
      #     through a hypercall rather than through a device, which an audit
      #     looking only for drivers would miss. QEMU/libvirt is the supported
      #     configuration (decision 25), so nothing is given up.
      #
      # `write-pcap-file` is not in the kernel's defaults and stays out: it
      # writes capture files to a guest path, which is the same property from
      # the other end. Neither is `semihosting`, `initramfs` or `newlib`.
      #
      # `virtio-vsock` stays. It is a host-guest socket, not storage, and
      # removing a transport this program does not use would be a different
      # decision from the one `OS-006` asks for.
      #
      # `tests/hermit_features.rs` is what keeps this list honest.
      hermitKernelFeatures = [
        "acpi"
        "dhcpv4"
        "fsgsbase"
        "kernel-stack"
        "loader"
        "pci"
        "pci-ids"
        "smp"
        "tcp"
        "virtio-net"
        "virtio-vsock"
      ];

      # `libhermit.a`: the unikernel the application is linked against.
      #
      # Built by the kernel's own `xtask` rather than by reimplementing it here.
      # That is deliberate — `xtask build` is not `cargo build`: it copies the
      # staticlib aside, rewrites every symbol that is not an exported syscall
      # so the kernel's `core` cannot collide with the application's, links in
      # `hermit-builtins` for the libm symbols, and stamps `ELFOSABI_STANDALONE`
      # on every member. Reimplementing four steps in shell would work until the
      # day upstream adds a fifth.
      #
      # Two things it needs that Nix does not give it for free:
      #
      #   * Three lockfiles' worth of dependencies — the kernel's, the separate
      #     `hermit-builtins` workspace's, and the standard library's, because
      #     `-Z build-std=core` compiles `core` from source. `vendorMultipleCargoDeps`
      #     is exactly this case, and it resolves the two `git+https` entries in
      #     the kernel's lockfile without either needing a hash here.
      #   * A `rustup` that is not there. `xtask` runs `rustup target add
      #     x86_64-unknown-none` before building; the toolchain above already
      #     has that target, so the shim below makes the call a no-op rather
      #     than patching the source.
      hermitKernelFor = { system, features ? hermitKernelFeatures }:
        let
          pkgs = pkgsFor system;
          src = hermit-kernel;
          nightly = hermitNightlyFor system;
          craneNightly = (crane.mkLib pkgs).overrideToolchain nightly;
          vendor = craneNightly.vendorMultipleCargoDeps {
            inherit (craneNightly.findCargoFiles src) cargoConfigs;
            cargoLockList = [
              "${src}/Cargo.lock"
              "${src}/hermit-builtins/Cargo.lock"
              "${nightly}/lib/rustlib/src/rust/library/Cargo.lock"
            ];
          };
        in
        pkgs.stdenvNoCC.mkDerivation {
          pname = "hermit-kernel";
          version = hermit-kernel.shortRev or "unknown";
          inherit src;

          nativeBuildInputs = [ nightly ];

          configurePhase = ''
            runHook preConfigure

            export CARGO_HOME="$NIX_BUILD_TOP/cargo-home"
            mkdir -p "$CARGO_HOME"
            cp ${vendor}/config.toml "$CARGO_HOME/config.toml"

            mkdir -p "$NIX_BUILD_TOP/shim"
            printf '#!/bin/sh\nexit 0\n' > "$NIX_BUILD_TOP/shim/rustup"
            chmod +x "$NIX_BUILD_TOP/shim/rustup"
            export PATH="$NIX_BUILD_TOP/shim:$PATH"

            runHook postConfigure
          '';

          buildPhase = ''
            runHook preBuild
            cargo run --package=xtask --no-default-features --offline -- build \
              --arch x86_64 --release \
              --target-dir "$NIX_BUILD_TOP/target" \
              ${if features == null then "" else
                "--no-default-features --features " + builtins.concatStringsSep "," features}
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/lib
            cp "$NIX_BUILD_TOP/target/x86_64/release/libhermit.a" $out/lib/libhermit.a
            runHook postInstall
          '';

          # `xtask` spent its last two steps deciding exactly which symbols this
          # archive exports; `strip` is not invited to have an opinion.
          dontStrip = true;
        };

      # The Tier 3 `rust-std` (PKG-014, #251), lifted out of the layout the
      # release ships: a `rust-installer` component tree plus an `install.sh`
      # nothing here runs. Only the `lib/rustlib/<target>` half is wanted.
      rustStdHermitFor = system:
        let pkgs = pkgsFor system;
        in pkgs.runCommand "rust-std-hermit" { } ''
          mkdir -p $out
          cp -r ${rust-std-hermit}/rust-std-${hermitTarget}/lib $out/lib
        '';

      # The stable toolchain plus that `rust-std`, as one sysroot.
      #
      # A `symlinkJoin` rather than a toolchain override, and it is passed with
      # `--sysroot` rather than by putting it on `PATH`, because `rustc` derives
      # its own sysroot from the *resolved* path of its executable: a joined
      # toolchain whose `bin/rustc` is a symlink finds the original sysroot and
      # reports `can't find crate for core`. Naming the sysroot explicitly also
      # keeps host build scripts and proc macros on the real toolchain, since
      # `CARGO_TARGET_<triple>_RUSTFLAGS` applies to the target only.
      hermitSysrootFor = system:
        let pkgs = pkgsFor system;
        in pkgs.symlinkJoin {
          name = "rust-hermit-sysroot";
          paths = [ (rustToolchainFor system) (rustStdHermitFor system) ];
        };

      hermitArgsFor = { system, features ? null }:
        let
          commonArgs = commonArgsFor system;
          kernel = hermitKernelFor { inherit system features; };
          sysroot = hermitSysrootFor system;
        in
        commonArgs // {
          pnameSuffix = "-hermit";

          CARGO_BUILD_TARGET = hermitTarget;
          CARGO_TARGET_X86_64_UNKNOWN_HERMIT_RUSTFLAGS = builtins.concatStringsSep " " [
            "--sysroot=${sysroot}"
            "-L native=${kernel}/lib"
            # `-bundle`, which the `hermit` crate's build script does not say
            # and which this build needs because it keeps `lto = "fat"`.
            # Bundling makes `rustc` treat every member of `libhermit.a` as one
            # of its own objects, and the members are compiled C — the kernel's
            # `compiler-builtins` intrinsics — with no `.llvmbc` section, so
            # fat LTO stops with "failed to get bitcode from object file".
            # `-bundle` hands the archive to the linker instead, which is what
            # was meant: it is a foreign static library, not a Rust crate.
            "-l static:-bundle=hermit"
          ];

          # A unikernel image does not run on the build host, and the test suite
          # has already run against the host target in `nix flake check`.
          doCheck = false;
          cargoExtraArgs = "--package kmsrs-os";

          # The result is an `ELFOSABI_STANDALONE` image for a machine with no
          # dynamic loader, no `ld.so` and no interpreter. `patchelf` and
          # `strip` have nothing correct to do to it, and both would be
          # editing a file that only the hermit-loader knows how to read.
          dontStrip = true;
          dontPatchELF = true;
        };

      # --- The bootable disk image (OS-002, #253) ---
      #
      # A GPT disk with one partition: an EFI system partition holding three
      # files, which is the whole of what a Hermit deployment is.
      #
      #   \EFI\BOOT\BOOTX64.EFI    the loader — the path OVMF starts by default,
      #                            so nothing has to be registered in NVRAM and
      #                            the first boot of a fresh VM works
      #   \EFI\hermit\hermit-app   this program
      #   \EFI\hermit\hermit-bootargs   optional, and the only runtime channel
      #
      # The loader reads all three itself. That is what makes this the *whole*
      # deployment: no `-kernel`, no `-initrd`, and — the reason it matters on
      # Proxmox — no `qm set --args`, which the web UI does not expose at all
      # (`OS-008`, #259).
      #
      # Boot args are shlex-parsed by the kernel, and a `KMSRSOS_CONFIG` value
      # is TOML, which contains spaces. So the value has to be quoted:
      #
      #     env=KMSRSOS_CONFIG="web-ui-port = 8081"
      #
      # Unquoted, shlex splits it into three words and the kernel logs two
      # "could not parse bootarg" lines and carries on with the default. The
      # `hermit-image-boot` check passes a quoted one and asserts the override
      # took effect, because "the file was read" and "the setting applied" are
      # different claims.
      #
      # Every identifier that would otherwise be random is fixed: the disk GUID,
      # the partition GUID and the FAT volume ID. Two builds of one revision are
      # the same bytes (`SEC-010`, #202), and a disk image is exactly the kind
      # of artefact where that silently stops being true.
      hermitDiskImageFor = { system, app, bootargs ? null }:
        let
          pkgs = pkgsFor system;
        in
        pkgs.runCommand "kmsrsos-hermit-image"
          {
            nativeBuildInputs = [ pkgs.gptfdisk pkgs.dosfstools pkgs.mtools ];
          } ''
          set -euo pipefail

          # 128 MiB, in 512-byte sectors. The ESP runs from sector 2048 (1 MiB,
          # the conventional alignment) to sector 262110, leaving the last 33
          # sectors for the backup GPT header and table.
          sectors=262144
          first=2048
          last=262110

          truncate -s $((sectors * 512)) disk.img
          sgdisk \
            --clear \
            --disk-guid=6b8a1f2c-9d34-4e5a-8c71-0f2d3e4b5a60 \
            --new=1:$first:$last \
            --typecode=1:ef00 \
            --partition-guid=1:1c4e5f60-7a8b-49cd-9e0f-1a2b3c4d5e6f \
            --change-name=1:"EFI system partition" \
            disk.img

          truncate -s $(((last - first + 1) * 512)) esp.img
          mkfs.vfat -F 32 -n HERMIT -i DEADBEEF esp.img

          mmd -i esp.img ::/EFI ::/EFI/BOOT ::/EFI/hermit
          mcopy -i esp.img ${hermit-loader-efi} ::/EFI/BOOT/BOOTX64.EFI
          mcopy -i esp.img ${app}/bin/kmsrsos-hermit ::/EFI/hermit/hermit-app
          ${pkgs.lib.optionalString (bootargs != null) ''
            printf '%s' ${pkgs.lib.escapeShellArg bootargs} > bootargs
            mcopy -i esp.img bootargs ::/EFI/hermit/hermit-bootargs
          ''}

          dd if=esp.img of=disk.img bs=512 seek=$first conv=notrunc status=none

          mkdir -p $out
          cp disk.img $out/kmsrsos-hermit.img
        '';

      # --- Booting it (OS-001, #252) ---
      #
      # The one test in this repository that runs the shipped program on the
      # target it is for. Everything else about Hermit is asserted from Linux
      # against a `const bool` in `platform.rs`, which is the right way to check
      # a decision — and no way at all to check that the decisions add up to a
      # host that answers.
      #
      # So: boot the unikernel under QEMU, then drive it with `kmsrs-client`,
      # which is the anti-fingerprinting regression suite (`CLI-002`, #208). A
      # pass means all three protocol versions completed *and* the probe found
      # nothing that distinguishes the host — on a target where the entropy
      # source, the socket semantics and the clock are all different.
      #
      # Three details are load-bearing:
      #
      #   * `rdseed` in the CPU model. Hermit's `sys_read_entropy` silently
      #     falls back to a Park-Miller LCG seeded from a static zero, so
      #     without it the guest refuses to serve (`OS-012`, #263) — which is
      #     the correct behaviour and would make this check fail for the right
      #     reason. It is in the model here because what is being tested is the
      #     serving path.
      #   * `disable-legacy=on`, which forces a non-transitional virtio-net
      #     device. Hermit rejects PCI device IDs below 0x1040, and the fact
      #     that Proxmox never emits this flag is exactly `OS-004` (#255).
      #   * No `-enable-kvm`. TCG is fast enough — the guest reaches its
      #     listener in under a second of guest time — and a build sandbox has
      #     no `/dev/kvm`.
      hermitBootCheckFor = system:
        let
          pkgs = pkgsFor system;
          configured = mkKmsrsos { inherit system; };
        in
        pkgs.runCommand "hermit-boot"
          {
            nativeBuildInputs = [ pkgs.qemu_kvm ];
            meta.timeout = 600;
          } ''
          set -euo pipefail
          port=1688
          serial="$PWD/serial.log"

          qemu-system-x86_64 \
            -cpu qemu64,apic,fsgsbase,fxsr,rdrand,rdseed,rdtscp,xsave,xsaveopt \
            -smp 1 -m 512M -display none -no-reboot \
            -serial "file:$serial" \
            -kernel ${hermit-loader-multiboot} \
            -initrd ${configured.hermit}/bin/kmsrsos-hermit \
            -netdev user,id=u1,hostfwd=tcp:127.0.0.1:$port-:1688 \
            -device virtio-net-pci,netdev=u1,disable-legacy=on &
          qemu=$!
          trap 'kill $qemu 2>/dev/null || true' EXIT

          # The guest boots in about a second; the loop is generous because a
          # loaded builder is not, and it gives up rather than hanging.
          for attempt in $(seq 1 60); do
            if ${configured.client}/bin/kmsrs-client --quiet --healthcheck \
                 127.0.0.1:$port; then
              break
            fi
            if [ "$attempt" = 60 ]; then
              echo "the guest never answered on $port" >&2
              cat "$serial" >&2 || true
              exit 1
            fi
            sleep 1
          done

          # The real assertion: every protocol version, and a verdict.
          if ! ${configured.client}/bin/kmsrs-client --timeout 30 \
                 127.0.0.1:$port; then
            echo "--- guest serial console ---" >&2
            cat "$serial" >&2 || true
            exit 1
          fi

          # `OS-003` (#254): the address came from DHCP, not from the kernel's
          # compile-time fallback. Both produce a guest that answers on the
          # forwarded port, so "it served" does not distinguish them — and a
          # guest that quietly came up on 10.0.5.3 is one that would be
          # unreachable on any real network.
          if ! grep -q "DHCP config acquired" "$serial"; then
            echo "the guest never acquired a DHCPv4 lease (OS-003, #254)" >&2
            cat "$serial" >&2 || true
            exit 1
          fi
          if grep -q "10\.0\.5\.3" "$serial"; then
            echo "the guest used HERMIT_IP's built-in default rather than a \
          lease (OS-003, #254)" >&2
            cat "$serial" >&2 || true
            exit 1
          fi

          mkdir -p $out
          cp "$serial" $out/serial.log
        '';

      # --- Booting the disk image (OS-002, #253) ---
      #
      # `hermit-boot` proves the program runs on Hermit. This proves the
      # *artefact* runs: a GPT disk handed to firmware, with no `-kernel`, no
      # `-initrd` and nothing on the command line — which is the only shape
      # Proxmox can start, since its web UI exposes no `args` field at all
      # (`OS-008`, #259).
      #
      # Two boots, because there are two claims:
      #
      #   1. The shipped image boots unattended and activates. Unattended is
      #      part of the claim: OVMF starts `\EFI\BOOT\BOOTX64.EFI` by itself,
      #      so nothing has to be registered in NVRAM and a fresh VM works on
      #      its first boot.
      #   2. A `hermit-bootargs` file on the ESP is honoured. Not "is read" —
      #      honoured. The value moves the web UI to a port it is not on by
      #      default, and the check fails if the default port is still the one
      #      answering. Reading a file and applying what is in it are different
      #      claims, and the difference is where a quoting mistake lives.
      hermitImageBootCheckFor = system:
        let
          pkgs = pkgsFor system;
          configured = mkKmsrsos { inherit system; };
          withBootargs = hermitDiskImageFor {
            inherit system;
            app = configured.hermit;
            bootargs = ''env=KMSRSOS_CONFIG="web-ui-port = 8081"'';
          };
        in
        pkgs.runCommand "hermit-image-boot"
          {
            nativeBuildInputs = [ pkgs.qemu_kvm pkgs.curl ];
            meta.timeout = 900;
          } ''
          set -euo pipefail
          mkdir -p $out

          boot() {
            local image="$1" name="$2"
            local serial="$PWD/$name.log"

            # Both the image and the UEFI variable store are written to, so
            # neither can be the read-only store path.
            cp "$image" "$PWD/$name.img"
            cp ${pkgs.OVMF.variables} "$PWD/$name-vars.fd"
            chmod +w "$PWD/$name.img" "$PWD/$name-vars.fd"

            qemu-system-x86_64 \
              -machine q35 \
              -cpu qemu64,apic,fsgsbase,fxsr,rdrand,rdseed,rdtscp,xsave,xsaveopt \
              -smp 1 -m 512M -display none -no-reboot \
              -serial "file:$serial" \
              -drive if=pflash,format=raw,unit=0,readonly=on,file=${pkgs.OVMF.firmware} \
              -drive if=pflash,format=raw,unit=1,file="$PWD/$name-vars.fd" \
              -drive format=raw,file="$PWD/$name.img" \
              -netdev user,id=u1,hostfwd=tcp:127.0.0.1:1688-:1688,hostfwd=tcp:127.0.0.1:8080-:8080,hostfwd=tcp:127.0.0.1:8081-:8081 \
              -device virtio-net-pci,netdev=u1,disable-legacy=on &
            qemu=$!

            # Firmware adds a few seconds over a direct kernel boot, and a
            # loaded builder adds more.
            local attempt
            for attempt in $(seq 1 120); do
              if ${configured.client}/bin/kmsrs-client --quiet --healthcheck \
                   127.0.0.1:1688; then
                return 0
              fi
              if ! kill -0 $qemu 2>/dev/null; then
                echo "qemu exited before the guest answered ($name)" >&2
                cat "$serial" >&2 || true
                return 1
              fi
              sleep 1
            done

            echo "the image never answered on 1688 ($name)" >&2
            cat "$serial" >&2 || true
            return 1
          }

          fail() {
            echo "$1" >&2
            cat "$PWD/$2.log" >&2 || true
            kill $qemu 2>/dev/null || true
            exit 1
          }

          # --- 1. The shipped image, exactly as released ---
          boot ${configured.osImage}/kmsrsos-hermit.img plain

          ${configured.client}/bin/kmsrs-client --timeout 30 127.0.0.1:1688 \
            || fail "the image booted but does not activate" plain
          curl -fsS --max-time 10 http://127.0.0.1:8080/ > /dev/null \
            || fail "the web UI is not on its default port" plain

          cp "$PWD/plain.log" $out/plain.log
          kill $qemu 2>/dev/null || true
          wait $qemu 2>/dev/null || true

          # --- 2. The same image plus one file on the ESP ---
          boot ${withBootargs}/kmsrsos-hermit.img bootargs

          curl -fsS --max-time 10 http://127.0.0.1:8081/ > /dev/null \
            || fail "hermit-bootargs did not move the web UI to 8081" bootargs
          if curl -fsS --max-time 5 http://127.0.0.1:8080/ > /dev/null; then
            fail "the web UI is still on 8080, so the override did not apply" \
              bootargs
          fi

          cp "$PWD/bootargs.log" $out/bootargs.log
          kill $qemu 2>/dev/null || true
        '';

      # --- The build-time settings a deployment might genuinely need changed ---
      #
      # `CFG-001` (#166): anything that can change a byte on the wire is decided
      # when the binary is built. These are the two intervals and the two policy
      # features, which is the whole list — see declined item D37 for why it is
      # not thirty macros and seven presets.
      #
      # An invalid value here is a *compile error*, not a start-up failure:
      # `Compiled::BUILD` parses the overrides in const context (`CFG-004`,
      # #169), so `KMSRSOS_ACTIVATION_INTERVAL=banana` stops the build.
      defaultSettings = {
        # Minutes. Microsoft's documented defaults, and the one genuine
        # three-way agreement between the documentation, vlmcsd and py-kms.
        activationInterval = null;
        renewalInterval = null;
        # Activate retail, OEM and evaluation SKUs instead of refusing them
        # (`POL-010`, #98).
        permissiveRetail = false;
        # Refuse a request whose clock is more than four hours out
        # (`POL-011`, #99). Off by default: the tolerance is itself a detection
        # oracle.
        strictClockSkew = false;
      };

      # --- The build stamp (CFG-008, #173) ---
      #
      # Which build this is: the version, the source revision, and the source
      # date. All three reach the binary through `option_env!`, so they are
      # compile-time constants and there is no build script shelling out to
      # `git` — which would make the build depend on the machine that ran it.
      #
      # `self.rev` is the flake's own locked revision, and `self.lastModified`
      # is the source date rather than the build date. That distinction is the
      # whole issue: vlmcsd bakes `date +%s` into every build, so two builds of
      # one revision differ — and there the value is load-bearing, being the
      # upper bound of its randomised ePID activation date.
      #
      # A dirty tree has no revision, so `dirtyRev` is used and Nix suffixes it
      # `-dirty`. A checkout with no git metadata at all reports "unknown",
      # which is a value rather than a failure: the stamp is diagnostic, and a
      # binary that refused to start over it would be a worse failure than an
      # unlabelled one.
      stampEnv = {
        KMSRSOS_GIT_COMMIT = self.rev or self.dirtyRev or "unknown";
        SOURCE_DATE_EPOCH = toString (self.lastModified or 0);
      };

      settingsEnvFor = settings:
        (if settings.activationInterval == null then { } else {
          KMSRSOS_ACTIVATION_INTERVAL = toString settings.activationInterval;
        })
        // (if settings.renewalInterval == null then { } else {
          KMSRSOS_RENEWAL_INTERVAL = toString settings.renewalInterval;
        });

      featureArgsFor = settings:
        let
          enabled = nixpkgs.lib.optional settings.permissiveRetail "permissive-retail"
            ++ nixpkgs.lib.optional settings.strictClockSkew "strict-clock-skew";
        in
        if enabled == [ ] then "" else
        " --features kmsrs-policy/" + builtins.concatStringsSep ",kmsrs-policy/" enabled;

      # --- Static Linux binaries (PKG-004, #241) ---
      #
      # musl, statically linked, so the container image genuinely contains two
      # files. A glibc binary would drag in a libc closure that carries
      # `getent` and `ldd` among other things — and "no shell" stops being a
      # property of the image the moment something in it is a shell script.
      #
      # kankerdev proved a static binary works for a KMS emulator; this is the
      # same conclusion reached from the other end, by asking what an image has
      # to contain before its contents can be enumerated in a sentence.
      staticTargetFor = system:
        {
          "x86_64-linux" = "x86_64-unknown-linux-musl";
          "aarch64-linux" = "aarch64-unknown-linux-musl";
        }.${system} or null;

      staticEnvFor = system:
        let
          pkgs = pkgsFor system;
          target = staticTargetFor system;
          upper = nixpkgs.lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] target);
          muslPkgs =
            if system == "x86_64-linux" then pkgs.pkgsCross.musl64
            else pkgs.pkgsCross.aarch64-multiplatform-musl;
        in
        if target == null then { } else {
          CARGO_BUILD_TARGET = target;
          "CARGO_TARGET_${upper}_LINKER" = "${muslPkgs.stdenv.cc}/bin/${muslPkgs.stdenv.cc.targetPrefix}cc";
          # `+crt-static` is the default for musl targets, but stating it means
          # a future toolchain that changes the default cannot silently produce
          # a dynamically linked image.
          "CARGO_TARGET_${upper}_RUSTFLAGS" = "-C target-feature=+crt-static";
          # The binaries cannot necessarily run on the build host, and the test
          # suite has already run in `nix flake check`.
          doCheck = false;
        };

      # --- mkKmsrsos: the rebuild path, made first-class (CFG-003, #168) ---
      #
      # The doctrine for this project is "rebuild from the flake" rather than
      # "set an environment variable" (decision 13), and a doctrine nobody can
      # follow in two lines is a doctrine nobody follows. So:
      #
      #     kmsrsos.lib.mkKmsrsos {
      #       system = "x86_64-linux";
      #       settings.activationInterval = 240;
      #       settings.permissiveRetail = true;
      #     }
      #
      # produces `{ server, client, container }` configured that way. Every
      # setting it accepts is one that cannot be changed at runtime, which is
      # the point: this is the *only* way to change them.
      mkKmsrsos = { system, settings ? { } }:
        let
          pkgs = pkgsFor system;
          craneLib = cranelibFor system;
          commonArgs = commonArgsFor system;
          resolved = defaultSettings // settings;
          settingsEnv = settingsEnvFor resolved;
          features = featureArgsFor resolved;

          # Dependencies are built without the feature flags so that the cache
          # is shared across configurations; only the workspace crates rebuild.
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          static = staticEnvFor system;

          # Dependencies for the static target are their own closure, so they
          # get their own `buildDepsOnly` rather than sharing the host one.
          staticArtifacts = craneLib.buildDepsOnly (commonArgs // static // {
            pname = "kmsrsos-static";
          });

          buildOne = { pname, package }: craneLib.buildPackage (commonArgs // stampEnv // settingsEnv // static // {
            inherit pname;
            cargoArtifacts = if static == { } then cargoArtifacts else staticArtifacts;
            doCheck = false;
            cargoExtraArgs = "--package ${package}" + features;
          });

          server = buildOne { pname = "kmsrsos"; package = "kmsrs-server"; };
          client = buildOne { pname = "kmsrs-client"; package = "kmsrs-client"; };

          # `PKG-013` (#250). The unikernel is configured from the same
          # `settings` as the two hosted binaries, because a build-time setting
          # that reached only two of the three targets would be a setting whose
          # meaning depends on where it is deployed (`CFG-001`, #166).
          hermitArgs = hermitArgsFor { inherit system; };
        in
        rec {
          inherit server client;
          container = containerFor { inherit pkgs system server client; };

          hermit = craneLib.buildPackage (hermitArgs // stampEnv // settingsEnv // {
            cargoArtifacts = craneLib.buildDepsOnly hermitArgs;
            cargoExtraArgs = hermitArgs.cargoExtraArgs + features;
          });
          # `OS-002` (#253): the artefact an operator actually deploys. The
          # image ships without a bootargs file — a deployment that needs one
          # writes it onto the ESP, which is the entire in-place
          # reconfiguration story (`OS-008`, #259).
          osImage = hermitDiskImageFor { inherit system; app = hermit; };
        };

      # The Debian and RPM architecture names, which are neither Nix's nor
      # Rust's.
      osPackageArch = system: {
        "x86_64-linux" = { deb = "amd64"; rpm = "x86_64"; };
        "aarch64-linux" = { deb = "arm64"; rpm = "aarch64"; };
      }.${system} or null;

      # The tree both OS packages install (PKG-009, #246).
      #
      # Two binaries, the hardened service unit, and the deployment guide. No
      # postinst, no service-user creation, no `systemctl enable` — `DynamicUser`
      # means systemd creates and destroys the account per start, so there is no
      # account for a package to leave behind, and a package that enabled a
      # service the operator had not asked for would be making a decision that
      # is theirs.
      #
      # No `.socket` unit either; see declined item D40.
      packagePayload = { server, client }: ''
        mkdir -p payload/usr/bin
        mkdir -p payload/usr/lib/systemd/system
        mkdir -p payload/usr/share/doc/kmsrsos

        install -m 0755 ${server}/bin/kmsrsos payload/usr/bin/kmsrsos
        install -m 0755 ${client}/bin/kmsrs-client payload/usr/bin/kmsrs-client
        install -m 0644 ${./deploy/systemd/kmsrsos.service} \
          payload/usr/lib/systemd/system/kmsrsos.service
        install -m 0644 ${./docs/deployment.md} \
          payload/usr/share/doc/kmsrsos/deployment.md
        install -m 0644 ${./LICENSE} payload/usr/share/doc/kmsrsos/LICENSE
      '';

      # --- The container image (PKG-004, #241; PKG-005, #242; SEC-008, #200) ---
      #
      # `dockerTools` rather than a Dockerfile, and that settles three issues at
      # once rather than by policy:
      #
      #   * There is no build context to `COPY` and no `RUN` to execute, so the
      #     image cannot `git clone` at build time the way upstream py-kms's
      #     Dockerfiles do — which is why `docker build` there produces whatever
      #     upstream happened to be that morning and silently ignores local
      #     changes (`PKG-005`, #242).
      #   * The root filesystem is a `buildEnv` over exactly two store paths.
      #     There is no package manager, no shell, no `sh`, no libc utilities —
      #     not removed, never added (`PKG-004`, #241).
      #   * Every version in it comes from `flake.lock` and `Cargo.lock`, both
      #     exact. edgd1er's move from pinned pip to apk floors is what
      #     `PKG-006` (#243) exists about, and there is no apk here to float.
      containerFor = { pkgs, system, server, client }:
        pkgs.dockerTools.buildLayeredImage {
          name = "kmsrsos";
          tag = "latest";

          # Reproducible: `dockerTools` defaults the image creation date to the
          # Unix epoch rather than to now, so two builds of one revision produce
          # identical bytes (`CFG-008`, #173; `SEC-010`, #202).
          created = "@0";

          contents = [ server client ];

          config = {
            Entrypoint = [ "/bin/kmsrsos" ];

            # `SEC-008` (#200): non-root, and numeric so it needs no
            # `/etc/passwd` — which is one more file that would have to exist in
            # an image whose whole claim is that nothing does. 65534 is
            # `nobody`, and the KMS port is 1688, so nothing here needs a
            # privileged bind (`NET-016`, #165 is the same argument on systemd).
            User = "65534:65534";

            ExposedPorts = {
              "1688/tcp" = { };
              "8080/tcp" = { };
            };

            # `SEC-008` (#200): the health check probes the **KMS port**, by
            # doing what a client does — connect, bind, activate, decode.
            # Probing the HTTP handler would prove the one fact the caller
            # already had by getting a reply, which is the Organization fork's
            # `readyz` mistake.
            #
            # This is why `kmsrs-client` is in the image: a scratch container
            # has no shell, no curl and no nc, so the check has to be a binary.
            Healthcheck = {
              Test = [ "CMD" "/bin/kmsrs-client" "--quiet" "--healthcheck" "127.0.0.1:1688" ];
              Interval = 30000000000;
              Timeout = 10000000000;
              StartPeriod = 2000000000;
              Retries = 3;
            };

            Labels = {
              "org.opencontainers.image.title" = "kmsrsos";
              "org.opencontainers.image.description" =
                "A KMS host emulator in pure safe Rust";
              "org.opencontainers.image.source" =
                "https://github.com/schlarpc/kmsrsos";
              "org.opencontainers.image.licenses" = "MIT";
            };
          };
        };

    in
    {
      packages = eachSystem (system:
        let
          pkgs = pkgsFor system;
          craneLib = cranelibFor system;
          commonArgs = commonArgsFor system;
          cargoArtifacts = cargoArtifactsFor system;
          configured = mkKmsrsos { inherit system; };
        in
        {
          # The whole workspace, which is what a developer means by `nix build`.
          default = craneLib.buildPackage (commonArgs // stampEnv // {
            inherit cargoArtifacts;
            doCheck = false;
          });

          kmsrsos = self.packages.${system}.default;

          # Just the server, and just the client — what the container and the
          # release artifacts are made of (`PKG-001`, #238).
          server = configured.server;
          client = configured.client;

          # `nix build .#container` — no Dockerfile, no network, no build
          # context (`PKG-004`, #241; `PKG-005`, #242).
          container = configured.container;

          # Cross-compiled Windows binaries: `nix build .#windows`
          windows = craneLib.buildPackage ((windowsArgsFor system) // stampEnv // {
            cargoArtifacts = windowsCargoArtifactsFor system;
          });

          # The Hermit unikernel application: `nix build .#hermit`
          # (`PKG-013`, #250). An ELF with `ELFOSABI_STANDALONE`, which the
          # hermit-loader reads — not something this host can execute.
          hermit = configured.hermit;

          # `libhermit.a` on its own, so that a kernel-side change can be built
          # and diffed without rebuilding the application (`PKG-013`, #250).
          hermit-kernel = hermitKernelFor { inherit system; };

          # `nix build .#osImage` — the bootable GPT disk (`OS-002`, #253).
          # This is what an operator uploads to a hypervisor; everything else
          # in this set is a component of it.
          osImage = configured.osImage;

          # --- OS packages (PKG-009, #246) ---
          #
          # `.deb` and `.rpm` as artifacts, not a repository. A repository is
          # ongoing infrastructure with signing keys that have to be rotated,
          # and a downloadable package captures most of the value (decision 26).
          # No Homebrew: macOS is not a target.
          #
          # Both are built from the same payload as each other and from the same
          # store paths as the container, so there is one definition of what
          # "installed" means rather than three that drift.
          deb = pkgs.stdenvNoCC.mkDerivation {
            pname = "kmsrsos-deb";
            version = "0.1.0";
            dontUnpack = true;
            nativeBuildInputs = [ pkgs.dpkg ];
            buildPhase = (packagePayload {
              inherit (configured) server client;
            }) + ''
              mkdir -p payload/DEBIAN
              cat > payload/DEBIAN/control <<CONTROL
              Package: kmsrsos
              Version: 0.1.0
              Section: net
              Priority: optional
              Architecture: ${(osPackageArch system).deb}
              Maintainer: Chaz Schlarp <schlarpc@gmail.com>
              Homepage: https://github.com/schlarpc/kmsrsos
              Description: A KMS host emulator in pure safe Rust
               Serves KMS activations on 1688 and an operator web UI on 8080.
               Statically linked, no runtime dependencies, no configuration
               file and no command line: what a build does is decided when it
               is built.
              CONTROL
              dpkg-deb --build --root-owner-group payload kmsrsos.deb
            '';
            installPhase = ''
              mkdir -p "$out"
              cp kmsrsos.deb "$out/kmsrsos_0.1.0_${(osPackageArch system).deb}.deb"
            '';
          };

          rpm = pkgs.stdenvNoCC.mkDerivation {
            pname = "kmsrsos-rpm";
            version = "0.1.0";
            dontUnpack = true;
            nativeBuildInputs = [ pkgs.rpm ];
            buildPhase = (packagePayload {
              inherit (configured) server client;
            }) + ''
              export HOME="$PWD"
              mkdir -p rpmbuild/BUILD rpmbuild/RPMS rpmbuild/SOURCES rpmbuild/SPECS rpms rpmdb rpmtmp

              cat > kmsrsos.spec <<SPEC
              # The binaries are already stripped by the release profile and
              # there are no sources to package, so rpm's debuginfo machinery
              # has nothing to do and fails trying.
              %global debug_package %{nil}
              %global __os_install_post %{nil}
              %global _build_id_links none

              Name:      kmsrsos
              Version:   0.1.0
              Release:   1
              Summary:   A KMS host emulator in pure safe Rust
              License:   MIT
              URL:       https://github.com/schlarpc/kmsrsos
              BuildArch: ${(osPackageArch system).rpm}

              %description
              Serves KMS activations on 1688 and an operator web UI on 8080.
              Statically linked, no runtime dependencies, no configuration file
              and no command line: what a build does is decided when it is
              built.

              %files
              /usr/bin/kmsrsos
              /usr/bin/kmsrs-client
              /usr/lib/systemd/system/kmsrsos.service
              /usr/share/doc/kmsrsos/deployment.md
              /usr/share/doc/kmsrsos/LICENSE
              SPEC
              # Every path rpm would otherwise take from the system: it wants a
              # package database in /var/lib/rpm and a temp directory in
              # /var/tmp, neither of which exists in a build sandbox.
              rpmbuild -bb kmsrsos.spec \
                --define "_topdir $PWD/rpmbuild" \
                --define "_rpmdir $PWD/rpms" \
                --define "_dbpath $PWD/rpmdb" \
                --define "_tmppath $PWD/rpmtmp" \
                --define "_builddir $PWD/rpmbuild/BUILD" \
                --buildroot "$PWD/payload"
            '';
            installPhase = ''
              mkdir -p "$out"
              find rpms -name '*.rpm' -exec cp {} "$out/" ';'
            '';
          };
        });

      checks = eachSystem (system:
        let
          craneLib = cranelibFor system;
          commonArgs = commonArgsFor system;
          cargoArtifacts = cargoArtifactsFor system;
        in
        {
          build = self.packages.${system}.default;

          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          fmt = craneLib.cargoFmt {
            src = commonArgs.src;
            pname = commonArgs.pname;
            version = commonArgs.version;
          };

          test = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            partitions = 1;
            partitionType = "count";
          });

          # `TEST-015` (#236): a floor under the crates where a gap is a
          # protocol bug nobody sees.
          #
          # The gate is on `kmsrs-proto`, `kmsrs-policy` and `kmsrs-crypto`
          # only, and that is the point rather than a convenience. Those three
          # are sans-io: every one of their branches is reachable from a byte
          # array, so an uncovered line there is a line no test ever asked
          # about — unlike `kmsrs-server`, where the uncovered lines are error
          # paths that need a socket to fail in a particular way.
          #
          # 90 %, against roughly 94 % today. A threshold set at the current
          # number is a threshold that fails on the next honest refactor and
          # then gets lowered; this one has room to move and still catches a
          # feature that arrived without tests.
          coverage = craneLib.cargoLlvmCov (commonArgs // {
            inherit cargoArtifacts;
            cargoLlvmCovExtraArgs = builtins.concatStringsSep " " [
              # crane's default, restated because setting this attribute
              # replaces it rather than adding to it — and without it the
              # derivation produces no output and fails after the gate has
              # already passed, which is a confusing way to be broken.
              "--lcov --output-path $out"
              "--package kmsrs-proto"
              "--package kmsrs-policy"
              "--package kmsrs-crypto"
              "--fail-under-lines 90"
            ];
          });

          # The build-time policy flags (POL-010, #98; POL-011, #99). They
          # change what the server does on the wire, so a build that nobody ever
          # compiles is a build that does not work; each configuration has tests
          # that only exist under it.
          policy-features = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            pname = "kmsrs-policy-features";
            partitions = 1;
            partitionType = "count";
            cargoNextestExtraArgs =
              "-p kmsrs-policy --features permissive-retail,strict-clock-skew";
          });

          # Every feature combination compiles (CFG-010, #175). vlmcsd has at
          # least four combinations that do not, which is what happens when the
          # matrix is large and nobody builds the corners.
          #
          # The full powerset, not a subset: with two features in one crate that
          # is four builds, which is cheap enough that narrowing it would only
          # be guessing at which corner breaks.
          # `PKG-001` (#238) and `PKG-004` (#241): the artifacts people actually
          # deploy are built by the gate, not only by a release.
          #
          # An output nobody builds is an output that does not work, and the
          # container is the one whose breakage is least visible from a `cargo
          # build` — it is where the static link, the non-root user and the
          # health-check binary all live.
          container = self.packages.${system}.container;

          # `CFG-003` (#168): the rebuild path is a supported interface, so a
          # configured build is checked the same way. This one sets both
          # intervals and both policy features, which is the whole build-time
          # surface — and because `Compiled::BUILD` parses the overrides in
          # const context (`CFG-004`, #169), a mistake here is a build failure
          # rather than a server that starts and behaves oddly.
          configured = (mkKmsrsos {
            inherit system;
            settings = {
              activationInterval = 240;
              renewalInterval = 20160;
              permissiveRetail = true;
              strictClockSkew = true;
            };
          }).server;

          # `OS-001` (#252): the unikernel boots and activates. The only check
          # here that runs the program on the platform it was built for.
          hermit-boot = hermitBootCheckFor system;

          # `OS-002` (#253): and the *image* boots, from firmware, with nothing
          # on the command line — plus the bootargs file on its ESP is honoured.
          hermit-image-boot = hermitImageBootCheckFor system;

          feature-powerset = craneLib.mkCargoDerivation (commonArgs // {
            inherit cargoArtifacts;
            pname = "kmsrsos-feature-powerset";
            buildPhaseCargoCommand = ''
              cargo hack check --workspace --all-targets --feature-powerset --locked
            '';
            nativeBuildInputs = (commonArgs.nativeBuildInputs or [ ])
              ++ [ (pkgsFor system).cargo-hack ];
          });
        });

      devShells = eachSystem (system:
        let
          pkgs = pkgsFor system;
          rustToolchain = rustToolchainFor system;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.default ];

            nativeBuildInputs = [
              rustToolchain
              pkgs.cargo-nextest
              pkgs.cargo-llvm-cov
              pkgs.bacon
              pkgs.cargo-edit
              pkgs.cargo-audit
              pkgs.cargo-deny
              pkgs.cargo-expand
              pkgs.cargo-xwin
              # `SEC-010` (#202): the release emits a CycloneDX SBOM per
              # artifact. In the dev shell rather than fetched ad hoc, so it is
              # pinned by flake.lock like everything else — and so it has the
              # `rustc` it shells out to, which it does not on its own.
              pkgs.cargo-cyclonedx
              nix-direnv.packages.${system}.default
            ]
            # `SEC-006` (#198): `ci/no-file-access.sh` runs the real binary
            # under `strace` and fails on any successful open outside the
            # loader. Linux only, because that is the only place strace exists
            # and the only place the check runs.
            ++ pkgs.lib.optional pkgs.stdenv.isLinux pkgs.strace;

            RUST_BACKTRACE = "1";
            RUST_LOG = "debug";
          };

          # `nix develop .#fuzz` — the one place a nightly toolchain is used
          # (SEC-004, #196).
          #
          # `cargo fuzz` needs `-Zsanitizer=address`, which stable does not
          # have. Rather than unpin the toolchain for everyone, the nightly is
          # confined to this shell: nothing that ships is built with it, and the
          # workspace's own MSRV assertion (ARCH-016, #16) is untouched.
          #
          # The date is not written down here because `rust-overlay` is a locked
          # flake input, so `flake.lock` already pins exactly which nightly this
          # resolves to — writing a date as well would give two sources of truth
          # that drift apart on the first `nix flake update`.
          #
          #   nix develop .#fuzz -c cargo fuzz build
          #   nix develop .#fuzz -c cargo fuzz run rpc_pdu -- -runs=100000
          #
          # The targets' bodies are ordinary workspace code and are compiled,
          # linted and replayed against the committed corpus by the stable
          # toolchain; see crates/kmsrs-vectors/src/targets.rs.
          fuzz = pkgs.mkShell {
            nativeBuildInputs = [
              (pkgs.rust-bin.selectLatestNightlyWith
                (toolchain: toolchain.default.override {
                  extensions = [ "rust-src" "llvm-tools-preview" ];
                }))
              pkgs.cargo-fuzz
            ];

            RUST_BACKTRACE = "1";
          };
        });

      lib = {
        inherit nix-direnv mkKmsrsos defaultSettings;
      };
    };
}

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




  };

  outputs =
    { self
    , nixpkgs
    , systems
    , rust-overlay
    , crane
    , nix-direnv
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
            # The kernel allowlist and what it generated, which `kernel_tcb.rs`
            # reads to assert what is in the bare-metal machine's TCB
            # (`OS-023`, #339; `OS-025`, #342).
            || (builtins.match ".*/os(/.*)?" path != null)
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

            # `SEC-005` (#197) added `-C control-flow-guard` here and
            # `PKG-018` removed it, because **the binary it produced did not
            # start.** Running it on Windows 11 26200 gives `0xC0000409` with
            # fast-fail code 10, `FAST_FAIL_GUARD_ICALL_CHECK_FAILURE` — an
            # indirect call to an address the guard table does not list — before
            # a single line is logged. A three-line hello-world cross-built the
            # same way fails identically, so this is the toolchain, not this
            # program.
            #
            # It was not caught because nothing ever ran the artifact. The
            # `windows-mitigations` check read `DllCharacteristics` and found
            # the CFG bit honestly set, which is a true statement about a
            # binary that crashes. `SEC-019` (#356) put a Windows guest in
            # front of it and it failed in the first thirty seconds.
            #
            # The five `SetProcessMitigationPolicy` policies do apply and are
            # verified in force on a live process — see `crate::sandbox`.
            # Restoring CFG is `PKG-018`; the likely requirement is a `std`
            # rebuilt with it, since the precompiled one is not.
          ];

          CC_x86_64_pc_windows_msvc = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang-cl";
          AR_x86_64_pc_windows_msvc = "${pkgs.llvmPackages.llvm}/bin/llvm-lib";
          CFLAGS_x86_64_pc_windows_msvc = builtins.concatStringsSep " " [
            "-imsvc${xwinSdk}/crt/include"
            "-imsvc${xwinSdk}/sdk/include/ucrt"
            "-imsvc${xwinSdk}/sdk/include/um"
            "-imsvc${xwinSdk}/sdk/include/shared"
          ];

          # Windows binaries can't run on the build host.
          doCheck = false;
          cargoExtraArgs = "--package kmsrs-server --package kmsrs-client";
        };

      windowsCargoArtifactsFor = system:
        let craneLib = cranelibFor system;
        in craneLib.buildDepsOnly (windowsArgsFor system);

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

          # `OS-021` (#337): pid 1 on the bare-metal target. The same server,
          # with the handful of duties the kernel does not perform for process
          # 1 done first — mounts and a reaper.
          os = buildOne { pname = "kmsrsos-os"; package = "kmsrs-os"; };
          client = buildOne { pname = "kmsrs-client"; package = "kmsrs-client"; };

        in
        rec {
          inherit server client os;
          container = containerFor { inherit pkgs system server client; };

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

        install -m 0755 ${server}/bin/kmsrs-server payload/usr/bin/kmsrs-server
        install -m 0755 ${client}/bin/kmsrs-client payload/usr/bin/kmsrs-client
        install -m 0644 ${./deploy/systemd/kmsrs-server.service} \
          payload/usr/lib/systemd/system/kmsrs-server.service
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
      # --- The Linux-as-PID-1 target (`OS-017`, #333) ---
      #
      # Kept in `os/linux/` rather than inline, because unlike the Hermit
      # artefacts this one is mostly a kernel configuration, and a 2790-line
      # allowlist is the statement of what is in the machine's TCB. It belongs
      # in a file a reviewer can read, not spliced into this one.

      # --- The target architecture, as a value (`OS-031`, #375) ---
      #
      # Everything below `os/linux/` used to name x86 in a dozen unmarked
      # places: `ARCH=x86_64`, `bzImage`, `BOOTX64.EFI`, `x86_64-efi`,
      # `ttyS0`, and one `kernel.config`. That is fine while there is one
      # target and becomes the `OS-006` (#257) failure the moment there are
      # two — a test that reads the wrong file passes while asserting nothing.
      #
      # So the architecture is a *descriptor* that flows down into
      # `default.nix`, `config.nix` and `delta.nix`, and the three of them hold
      # no architecture literal of their own. Adding a target is then an entry
      # in this attribute set plus the config file it names, rather than a
      # second copy of three files.
      #
      # Every field here is something that was a literal before this issue, and
      # nothing here is a preference — each one is a fact about the platform.
      linuxArches = {
        x86_64 = {
          # What this target is called in an artifact name, an output name and
          # a test's failure message. Not the Nix system and not the kernel's
          # `ARCH=`, both of which spell some architectures differently.
          name = "x86_64";

          # The Nix system that *builds* this target. Distinct from the system
          # a build happens to be running on — see `linuxFor` — and the whole
          # reason this field exists rather than being inferred.
          system = "x86_64-linux";

          # `make ARCH=`, which is the kernel's own spelling and agrees with
          # neither of the two above on aarch64 (`arm64`).
          kernelArch = "x86_64";

          # What `linuxKernel.manualConfig` leaves in `$out`. x86 self-
          # decompresses and is therefore `bzImage`; other architectures
          # produce an uncompressed `Image`.
          image = "bzImage";

          # The removable-media path UEFI looks for, per the specification's
          # per-architecture table. Firmware loads exactly this name with no
          # NVRAM entry, which is what makes a fresh VM boot on its first try.
          efiFile = "BOOTX64.EFI";

          # `grub-mkimage --format=`. GRUB is in the image for the reason
          # `OS-030` (#348) gives: isolinux reads ISO9660 and UEFI reads FAT,
          # so without a loader in the ESP that reads ISO9660 the kernel has to
          # exist twice.
          grubFormat = "x86_64-efi";

          # `console=`. `ttyS0` is an 8250 at a legacy I/O port, which is an
          # x86 platform fact rather than a Linux one.
          console = "ttyS0,115200";

          # Whether firmware for this target can boot without UEFI. It decides
          # whether the image needs isolinux, an isohybrid MBR and a bootloader
          # in the ESP at all — the argument in `OS-033` (#377), which is where
          # the second value of this field first appears.
          bios = true;

          # The generated allowlist, which is the statement of what is in this
          # machine's TCB. One file per architecture: `OS-032` (#376) explains
          # why the second is not a port of the first, and `kernel_tcb.rs`
          # asserts each against its own list.
          config = ./os/linux/kernel.config;

          # What boots it in a check.
          qemu = "qemu-system-x86_64";
        };
      };

      # The descriptor for a system, or `null` if this system builds no
      # bare-metal target.
      #
      # Every target is built **natively**: the arm ISO is built on the arm
      # runner rather than cross-compiled, which is also the faster place to
      # run its boot checks under TCG. So this is a lookup rather than a
      # cross-compilation decision, and a system with no entry gets no
      # `linux*` outputs at all rather than outputs that fail when built.
      linuxArchFor = system:
        nixpkgs.lib.findFirst (arch: arch.system == system) null
          (builtins.attrValues linuxArches);

      # `system` is where the build runs; `arch` is what it produces.
      #
      # Today they always agree, and that is exactly why they have to be two
      # variables: a second target introduces the distinction, and until this
      # issue there was one value doing both jobs, so nothing could have
      # noticed the day it was asked to mean two different things.
      linuxFor = { system, arch }:
        assert arch.system == system;
        let pkgs = pkgsFor system;
        in import ./os/linux {
          inherit pkgs arch;
          init = (mkKmsrsos { inherit system; }).os;
          # `PKG-016` (#366): the same stamp the Rust builds get, so the ISO's
          # timestamps are a function of the revision rather than of when
          # somebody ran the build. See `stampEnv`.
          sourceDateEpoch = stampEnv.SOURCE_DATE_EPOCH;
        };

      # `OS-017` (#333): the Linux target boots into service on the device
      # topology that defeats Hermit, from *both* firmwares, with no `--args`.
      #
      # Three things are deliberately absent from the command line and each
      # absence is the assertion:
      #
      #   * No `disable-legacy=on`. The NIC sits on `pci.0` behind the bridge
      #     pair, exactly as `qemu-server` emits it, so the device is
      #     transitional (`0x1000`). That is `OS-004` (#255), the thing Hermit
      #     refuses and this target does not.
      #   * No `rdseed`/`rdrand` in the CPU model. `qemu64` has neither, which
      #     is the condition behind `OS-016` (#332). Linux seeds its CRNG
      #     anyway, so `getrandom(2)` never returns predictable bytes.
      #   * No `-enable-kvm`. A build sandbox has no `/dev/kvm`, and TCG is fast
      #     enough.
      linuxBootCheckFor = { system, arch }:
        let
          pkgs = pkgsFor system;
          configured = mkKmsrsos { inherit system; };
          linux = linuxFor { inherit system arch; };

          # Exactly what `qemu-server` emits for a q35 VM with one virtio NIC.
          proxmoxTopology = builtins.concatStringsSep " " [
            "-device i82801b11-bridge,id=pci.1,bus=pcie.0,addr=0x1e"
            "-device pci-bridge,id=pci.0,chassis_nr=1,bus=pci.1,addr=0x1"
            "-netdev user,id=u1,hostfwd=tcp:127.0.0.1:1688-:1688"
            "-device virtio-net-pci,netdev=u1,bus=pci.0,addr=0x12,id=net0"
          ];
        in
        pkgs.runCommand "linux-boot"
          {
            # `socat` is `OS-026` (#343): the QEMU monitor is how a
            # `system_powerdown` — the same ACPI event `qm shutdown` sends — is
            # delivered to the guest.
            nativeBuildInputs = [ pkgs.qemu_kvm pkgs.socat ];
            meta.timeout = 900;
          } ''
          set -euo pipefail
          mkdir -p $out

          # `firmware` is `bios` or `uefi`. The same ISO, the same bytes of
          # kernel, reached two different ways: SeaBIOS through isolinux and
          # the Linux boot protocol, OVMF through the PE header. One file is
          # both, which is the whole point of `CONFIG_EFI_STUB`.
          boot() {
            local firmware="$1"
            local serial="$PWD/$firmware.log"
            local monitor="$PWD/$firmware.mon"
            local fw=""

            if [ "$firmware" = uefi ]; then
              cp ${pkgs.OVMF.variables} "$PWD/$firmware-vars.fd"
              chmod +w "$PWD/$firmware-vars.fd"
              fw="-drive if=pflash,format=raw,unit=0,readonly=on,file=${pkgs.OVMF.firmware}"
              fw="$fw -drive if=pflash,format=raw,unit=1,file=$PWD/$firmware-vars.fd"
            fi

            # `-no-shutdown` is deliberately absent: this check's whole point is
            # that the guest powers itself off and qemu exits on its own.
            ${arch.qemu} \
              -machine q35 -cpu qemu64 \
              -smp 1 -m 512M -display none -no-reboot \
              -serial "file:$serial" \
              -monitor "unix:$monitor,server,nowait" \
              -device virtio-serial-pci \
              -chardev "socket,path=$PWD/$firmware.agent,server=on,wait=off,id=ga" \
              -device virtserialport,chardev=ga,name=org.qemu.guest_agent.0 \
              $fw \
              -drive file=${linux.iso},media=cdrom,readonly=on \
              ${proxmoxTopology} &
            qemu=$!

            local attempt
            local serving=0
            for attempt in $(seq 1 120); do
              if ${configured.client}/bin/kmsrs-client --quiet --healthcheck \
                   127.0.0.1:1688; then
                serving=1
                break
              fi
              if ! kill -0 $qemu 2>/dev/null; then
                echo "qemu exited before the guest answered ($firmware)" >&2
                cat "$serial" >&2 || true
                return 1
              fi
              sleep 1
            done

            if [ "$serving" -ne 1 ]; then
              echo "the guest never answered on $firmware" >&2
              cat "$serial" >&2 || true
              kill $qemu 2>/dev/null || true
              return 1
            fi

            # `OS-022` (#338): the guest agent, spoken to over the channel a
            # hypervisor would use. Not a unit test of the JSON — that is in
            # `agent.rs` — but the whole path: virtio-serial attached, the port
            # found by name in sysfs rather than by guessing `vport0p1`, the
            # node opened, a request read and a reply written.
            #
            # `guest-network-get-interfaces` is the one that matters. It is what
            # populates the IP column on a Proxmox summary page, and the whole
            # reason #338 exists.
            local agent="$PWD/$firmware.agent"
            for attempt in $(seq 1 30); do
              grep -q '"event":"agent"' "$serial" && break
              sleep 1
            done
            # The `sleep` keeps stdin open, and that is not padding. With an
            # immediate EOF socat shuts the socket down as soon as it has
            # written, qemu reports the client gone, and the guest's reply is
            # written to a channel with nobody on it. A guest agent client that
            # hangs up before the answer is one that concludes there is no
            # agent — which is what this looked like the first time.
            ask() {
              { printf '%s\n' "$1"; sleep 5; } \
                | socat -T8 - "UNIX-CONNECT:$agent" 2>/dev/null || true
            }
            ask '{"execute":"guest-network-get-interfaces"}' > "$PWD/$firmware.ifaces"
            ask '{"execute":"guest-exec","arguments":{"path":"/bin/sh"}}' > "$PWD/$firmware.exec"
            cp "$PWD/$firmware.ifaces" $out/$firmware.ifaces 2>/dev/null || true
            cp "$PWD/$firmware.exec" $out/$firmware.exec 2>/dev/null || true

            # `OS-020` (#336): wait for the clock task to have tried and
            # reported, which it does within a few seconds of the lease. Waited
            # for rather than assumed, because the healthcheck above can succeed
            # before the DNS lookup for the pool has timed out — and then the
            # assertion below would be racing rather than checking.
            for attempt in $(seq 1 30); do
              grep -q '"event":"clock"' "$serial" && break
              sleep 1
            done

            # `OS-026` (#343): the shutdown half. `system_powerdown` is exactly
            # what `qm shutdown` and the Proxmox web UI's Shutdown button send —
            # an ACPI power-button event — and until this issue the guest
            # discarded it, so only `qm stop` would stop the VM.
            #
            # Asserted by *letting qemu exit on its own*. Nothing is killed
            # below unless the guest failed to stop, so a regression here is a
            # timeout rather than a passing check that killed the evidence.
            echo system_powerdown | socat - "UNIX-CONNECT:$monitor" >/dev/null

            local stopped=0
            for attempt in $(seq 1 60); do
              if ! kill -0 $qemu 2>/dev/null; then
                stopped=1
                break
              fi
              sleep 1
            done
            wait $qemu 2>/dev/null || true
            cp "$serial" $out/$firmware.log

            if [ "$stopped" -ne 1 ]; then
              echo "the guest ignored system_powerdown on $firmware, so \
          'qm shutdown' does nothing and only 'qm stop' would stop it \
          (OS-026, #343)" >&2
              cat "$serial" >&2 || true
              kill -9 $qemu 2>/dev/null || true
              return 1
            fi
            return 0
          }

          boot bios
          boot uefi

          # The transitional device must have *attached*, not been skipped. If
          # this ever stops holding, the interesting question is what changed.
          for f in bios uefi; do
            grep -q '"event":"listening"' $out/$f.log || {
              echo "no listener reported on $f" >&2; exit 1; }
            # `OS-021` (#337): pid 1 mounted the pseudo-filesystems. Asserted
            # positively — the absence of a warning is equally consistent with
            # the code never having run.
            grep -q '"event":"pid1".*devtmpfs\|"event":"pid1"' $out/$f.log || {
              echo "pid 1 did not report its mounts on $f (OS-021, #337)" >&2
              cat $out/$f.log >&2; exit 1; }
            grep -q 'mounted /dev /proc /sys' $out/$f.log || {
              echo "pid 1 did not mount all three pseudo-filesystems on $f \
          (OS-021, #337)" >&2
              cat $out/$f.log >&2; exit 1; }

            # `OS-028` (#345). Everything above this point is read out of the
            # *serial* log of a machine whose command line ends `console=tty0`
            # — so /dev/console is the framebuffer and, without the tee, not one
            # of those lines would be here. That is what makes the greps above a
            # regression test for this and not merely for OS-021.
            #
            # Asserted explicitly as well, because "the lines are present" would
            # also hold if somebody reordered the command line back, and the
            # point of this issue is that the order stopped mattering.
            grep -q '"event":"console".*logging to.*ttyS0' $out/$f.log || {
              echo "pid 1 did not tee its log to the serial console on $f; \
          with tty0 last, every line above reached the framebuffer only \
          (OS-028, #345)" >&2
              cat $out/$f.log >&2; exit 1; }
            grep -q '"event":"console".*logging to.*tty0' $out/$f.log || {
              echo "pid 1 found no framebuffer console on $f, so this check is \
          not exercising the two-console case OS-028 (#345) is about" >&2
              cat $out/$f.log >&2; exit 1; }

            # `OS-022` (#338). The channel was found — by matching its name in
            # sysfs, since there is no udev here to make
            # /dev/virtio-ports/org.qemu.guest_agent.0.
            grep -q '"event":"agent".*answering on vport' $out/$f.log || {
              echo "the guest agent found no channel on $f, so a hypervisor \
          would show no address for this VM (OS-022, #338)" >&2
              cat $out/$f.log >&2; exit 1; }

            # And it answered the question Proxmox asks, with the address the
            # DHCP client took.
            grep -q '"hardware-address"' $out/$f.ifaces || {
              echo "guest-network-get-interfaces was not answered on $f. That \
          is the command that fills the IP column (OS-022, #338)" >&2
              cat $out/$f.ifaces >&2 || true; exit 1; }
            grep -q '"ip-address": "10.0.2.15"' $out/$f.ifaces || {
              echo "the agent did not report the leased address on $f, so the \
          hypervisor would show the wrong one or none (OS-022, #338)" >&2
              cat $out/$f.ifaces >&2 || true; exit 1; }

            # The refusals are the other half of the surface, and the one worth
            # a check: `guest-exec` is remote code execution over a channel with
            # no authentication, and its absence must be an answer rather than
            # a silence a client waits out.
            grep -q 'CommandNotFound' $out/$f.exec || {
              echo "guest-exec was not refused with an error on $f. Silence is \
          not a refusal — a client waits for a timeout and an operator reads \
          that as a hung guest (OS-022, #338)" >&2
              cat $out/$f.exec >&2 || true; exit 1; }

            # `OS-026` (#343). The guest stopping is asserted above, by qemu
            # having exited without being killed. These four lines are the
            # assertion that it stopped *the right way* — a machine that
            # panicked, or that was cut off mid-request, would also stop.
            grep -q '"event":"power".*watching event' $out/$f.log || {
              echo "pid 1 found no power button on $f: the ACPI event has \
          nowhere to go and 'qm shutdown' is silently a no-op (OS-026, #343)" >&2
              cat $out/$f.log >&2; exit 1; }
            grep -q '"event":"power".*acpi power button: draining' $out/$f.log || {
              echo "the button was watched but the press did not reach the \
          drain on $f (OS-026, #343)" >&2
              cat $out/$f.log >&2; exit 1; }
            # The drain is the point: `qm stop` also stops a VM, and does it by
            # dropping every connection in flight.
            grep -q '"event":"stopped"' $out/$f.log || {
              echo "the host stopped without draining on $f (NET-007, #157; \
          OS-026, #343)" >&2
              cat $out/$f.log >&2; exit 1; }
            # `OS-020` (#336). The clock task must have run and said something —
            # a task that failed quietly is the failure mode this whole target
            # keeps producing.
            #
            # *Which* thing it said is not asserted here, because it is not this
            # check's to decide: whether `pool.ntp.org` resolves depends on
            # whether the build sandbox has a route out. Both outcomes are
            # correct, and the one that matters — that an unreachable time
            # server does not stop the host serving — is already proven above by
            # the healthcheck having succeeded, and its wording is asserted by
            # `an_unreachable_time_server_is_not_a_reason_to_stop_serving`.
            grep -q '"event":"clock"' $out/$f.log || {
              echo "the clock task never reported on $f, so either it did not \
          run or it failed quietly (OS-020, #336)" >&2
              cat $out/$f.log >&2; exit 1; }
            # Whichever branch it took, it must be one of the two.
            grep -qE '"event":"clock".*(no time server answered|stepped)' $out/$f.log || {
              echo "the clock task said something on $f that is neither a step \
          nor a report of no answer (OS-020, #336)" >&2
              cat $out/$f.log >&2; exit 1; }

            # An ACPI power-off, not `Attempted to kill init!`. Both stop the
            # machine; only one of them looks like a clean stop to the operator
            # who pressed the button.
            if grep -qi 'Attempted to kill init' $out/$f.log; then
              echo "pid 1 returned instead of powering the machine off on $f, \
          so the operator sees a kernel panic after pressing Shutdown \
          (OS-026, #343)" >&2
              cat $out/$f.log >&2; exit 1
            fi

            if grep -qi 'unable to open an initial console' $out/$f.log; then
              echo "init had no stdio on $f: the /dev/console node is missing \
          from the initramfs manifest (OS-017, #333)" >&2
              exit 1
            fi
          done
        '';

      # `OS-025` (#342): one boot per NIC model this project claims to support,
      # asserting that the machine **serves** rather than that it boots.
      #
      # That distinction is the whole issue. Two of the four models the Proxmox
      # web UI offers used to produce a machine that booted to completion,
      # printed `listening`, and then answered nobody forever — no driver, so
      # no interface, so no address, and nothing said so. A check that asserted
      # "the guest booted" would have passed on every one of them.
      #
      # BIOS only, and one model at a time. Both firmwares are already covered
      # by `linux-boot` on the supported topology; what varies here is the
      # driver, and doubling the matrix to prove that a NIC driver does not
      # depend on the firmware would be buying nothing.
      # Port 11688, not 1688, and that is load-bearing rather than arbitrary:
      # `nix flake check` runs checks in parallel, and `linux-boot` already
      # forwards 1688. Two qemus asking for the same host port means the second
      # one **exits at start-up**, which presents as a guest that booted to a
      # completely empty console and "never served" — a failure that blames the
      # kernel config for a port clash. Observed once; hence the comment.
      nicBootCheckFor = { system, arch }:
        let
          pkgs = pkgsFor system;
          configured = mkKmsrsos { inherit system; };
          linux = linuxFor { inherit system arch; };

          # Each is `qemu-device-name:kernel-driver`, so a failure names the
          # driver an operator would have to look for.
          models = [
            "virtio-net-pci:virtio_net"
            "e1000:e1000"
            "e1000e:e1000e"
            "rtl8139:8139cp"
            "vmxnet3:vmxnet3"
            "pcnet:pcnet32"
            "tulip:tulip"
          ];
        in
        pkgs.runCommand "linux-nics"
          {
            nativeBuildInputs = [ pkgs.qemu_kvm ];
            meta.timeout = 1800;
          } ''
          set -euo pipefail
          mkdir -p $out

          serves() {
            local model="''${1%%:*}"
            local driver="''${1##*:}"
            local serial="$PWD/$driver.log"

            ${arch.qemu} \
              -machine q35 -cpu qemu64 \
              -smp 1 -m 512M -display none -no-reboot \
              -serial "file:$serial" \
              -drive file=${linux.iso},media=cdrom,readonly=on \
              -netdev user,id=u1,hostfwd=tcp:127.0.0.1:11688-:1688 \
              -device "$model,netdev=u1,id=net0" &
            local qemu=$!

            local attempt
            for attempt in $(seq 1 120); do
              if ${configured.client}/bin/kmsrs-client --quiet --healthcheck \
                   127.0.0.1:11688; then
                kill $qemu 2>/dev/null || true
                wait $qemu 2>/dev/null || true
                cp "$serial" $out/$driver.log
                echo "$model serves, via $driver"
                return 0
              fi
              kill -0 $qemu 2>/dev/null || break
              sleep 1
            done

            kill $qemu 2>/dev/null || true
            wait $qemu 2>/dev/null || true
            cp "$serial" $out/$driver.log 2>/dev/null || true
            echo "$model never served. The kernel needs $driver, and \
          os/linux/kernel.config is where it is missing from (OS-025, #342)" >&2
            cat "$serial" >&2 || true
            return 1
          }

          ${builtins.concatStringsSep "\n          "
            (map (model: "serves ${model}") models)}

          # The other half of `OS-025` (#342), and the one a driver list can
          # never cover: a machine whose NIC has no driver at all. It must say
          # so on the console rather than reporting `listening` and going quiet.
          #
          # `-nic none` is the strongest form of that — no NIC at all — and it
          # exercises the same path as an unrecognised one, since both end with
          # the kernel having created no interface.
          echo "checking that a machine with no interface says so"
          ${arch.qemu} \
            -machine q35 -cpu qemu64 \
            -smp 1 -m 512M -display none -no-reboot \
            -serial "file:$PWD/no-nic.log" \
            -drive file=${linux.iso},media=cdrom,readonly=on \
            -nic none &
          nonic=$!

          found=0
          for attempt in $(seq 1 60); do
            if grep -q 'no Ethernet interface' "$PWD/no-nic.log" 2>/dev/null; then
              found=1
              break
            fi
            kill -0 $nonic 2>/dev/null || break
            sleep 1
          done
          kill $nonic 2>/dev/null || true
          wait $nonic 2>/dev/null || true
          cp "$PWD/no-nic.log" $out/no-nic.log 2>/dev/null || true

          if [ "$found" -ne 1 ]; then
            echo "a machine with no network interface did not say so. That is \
          the silent failure OS-025 (#342) was filed about: it boots, it reports \
          listening, and it serves nobody forever" >&2
            cat $out/no-nic.log >&2 || true
            exit 1
          fi
          # And it must still have got as far as listening, because a host that
          # cannot find a NIC is not a host that should refuse to start.
          grep -q '"event":"listening"' $out/no-nic.log || {
            echo "a machine with no interface should still bind and serve \
          whatever route it does have — refusing to start is not the behaviour \
          OS-025 (#342) asked for" >&2
            cat $out/no-nic.log >&2; exit 1; }
        '';

      # `OS-030` (#348): the kernel appears exactly **once** in the ISO, and the
      # image boots as a raw disk on both firmwares.
      #
      # Counted in the bytes, not read off the recipe. The count was three for
      # two issues while `default.nix` said "twice" the whole time, which is
      # exactly why it is asserted here: a count is the only form of this claim
      # that cannot drift.
      #
      # The history, because the assertion is meaningless without it:
      #
      #   * **three** was a bug — El Torito read a copy of the ESP from the
      #     ISO9660 tree while `-append_partition` appended another
      #     (`OS-029`, #347)
      #   * **two** was the floor without a bootloader that reads ISO9660,
      #     since UEFI reads only FAT and isolinux reads only ISO9660
      #   * **one** is what a deliberately minimal GRUB in the ESP bought
      #     (`OS-030`, #348)
      #
      # A regression to two means a firmware path has grown its own copy back;
      # zero means one of them has lost its kernel entirely.
      isoLayoutCheckFor = { system, arch }:
        let
          pkgs = pkgsFor system;
          linux = linuxFor { inherit system arch; };
        in
        pkgs.runCommand "linux-iso-layout"
          {
            nativeBuildInputs = [ pkgs.python3 pkgs.qemu_kvm ];
            meta.timeout = 900;
          } ''
          mkdir -p $out
          python3 - <<'PYTHON' | tee $out/report
          import pathlib
          iso = pathlib.Path("${linux.iso}").read_bytes()
          kernel = pathlib.Path("${linux.kernel}/${arch.image}").read_bytes()

          # A run from the middle of the kernel, long enough not to collide by
          # accident and far enough in to miss the headers that also appear in
          # the El Torito boot catalogue.
          needle = kernel[1_000_000:1_000_256]
          at, hits = 0, []
          while (i := iso.find(needle, at)) != -1:
              hits.append(i)
              at = i + 1

          print(f"ISO      {len(iso)} bytes")
          print(f"${arch.image}  {len(kernel)} bytes")
          print(f"copies   {len(hits)} at {[hex(h) for h in hits]}")

          assert len(hits) == 1, (
              f"the kernel appears {len(hits)} times in the ISO and should appear "
              "once, in ISO9660, read there by isolinux for BIOS and by GRUB for "
              "UEFI (OS-030, #348). More than one means a firmware path has grown "
              "its own copy back — which is what the ESP held before GRUB went "
              "into it; zero means a path has lost its kernel entirely"
          )

          # And the ISO must not have quietly grown back. 7 MB is generous
          # against the 5.3 MB it is, and tight enough that a second copy of a
          # 3.4 MB kernel cannot hide under it.
          assert len(iso) < 7_000_000, f"the ISO is {len(iso)} bytes"
          PYTHON

          # And the layout is not just counted, it is booted — **as a raw
          # disk**, which is the path `OS-027` (#344) exists for and which
          # nothing else here exercises. `linux-boot` and `linux-nics` both
          # attach the image as a CD-ROM, so until now the GPT and the
          # protective MBR were asserted by reading `fdisk` output and by one
          # manual test.
          #
          # That gap is not hypothetical. `OS-029` (#347) looked like it had
          # broken both disk paths, for half an hour, on no evidence but a
          # hand-run qemu that was failing for an unrelated reason — the store
          # path is mode 444 and a writable `if=virtio` drive cannot open it.
          # Hence the copy below, and hence this check.
          cp ${linux.iso} disk.img
          chmod +w disk.img

          disk() {
            local firmware="$1"
            local log="$PWD/disk-$firmware.log"
            local fw=""
            if [ "$firmware" = uefi ]; then
              cp ${pkgs.OVMF.variables} "$PWD/$firmware-vars.fd"
              chmod +w "$PWD/$firmware-vars.fd"
              fw="-drive if=pflash,format=raw,unit=0,readonly=on,file=${pkgs.OVMF.firmware}"
              fw="$fw -drive if=pflash,format=raw,unit=1,file=$PWD/$firmware-vars.fd"
            fi

            ${arch.qemu} \
              -machine q35 -cpu qemu64 \
              -smp 1 -m 512M -display none -no-reboot \
              -serial "file:$log" \
              $fw \
              -drive file=disk.img,format=raw,if=virtio \
              -nic none &
            local qemu=$!

            local attempt
            for attempt in $(seq 1 180); do
              grep -q '"event":"listening"' "$log" 2>/dev/null && break
              kill -0 $qemu 2>/dev/null || break
              sleep 1
            done
            kill $qemu 2>/dev/null || true
            wait $qemu 2>/dev/null || true
            cp "$log" $out/disk-$firmware.log 2>/dev/null || true

            grep -q '"event":"listening"' $out/disk-$firmware.log || {
              echo "the ISO does not boot as a raw disk on $firmware. That is \
          the path the EC2 pipeline uses (OS-027, #344), and the partition \
          layout OS-029 (#347) touches is what decides it" >&2
              cat $out/disk-$firmware.log >&2 || true
              exit 1
            }
            echo "boots as a raw disk on $firmware"
          }

          disk bios
          disk uefi
        '';

      # `PKG-018`: Control Flow Guard is **absent** from the shipped Windows
      # binaries, and that is asserted rather than merely true.
      #
      # Read out of the PE optional header, not off the `RUSTFLAGS` line that is
      # supposed to put it there. A flag in a build file is a statement about
      # intent; `DllCharacteristics` is a statement about the artifact, and the
      # two come apart exactly when somebody reorders a `concatStringsSep` list
      # or a toolchain quietly stops honouring a flag.
      #
      # This is the same argument as `linux-iso-layout` counting kernel copies
      # in the ISO bytes: the comment in `default.nix` said "twice" for the whole
      # time it was three.
      #
      # The direction is inverted from what `SEC-005` (#197) wrote, and the
      # reason is that the flag produced a binary that fast-fails on startup
      # (`FAST_FAIL_GUARD_ICALL_CHECK_FAILURE`) on every Windows it was run on.
      # A check that only asserted the bit was set passed for the whole time the
      # artifact was unusable, so this now fails if CFG comes back without the
      # crash being fixed — see `PKG-018`.
      #
      # The other five mitigations are applied at run time through
      # `SetProcessMitigationPolicy` (`SEC-019`, #356) and are verified in force
      # on a live process, which no build-time check could do.
      windowsMitigationsCheckFor = system:
        let
          pkgs = pkgsFor system;
          windows = self.packages.${system}.windows;
        in
        pkgs.runCommand "windows-mitigations"
          { nativeBuildInputs = [ pkgs.python3 ]; } ''
          mkdir -p $out
          python3 - <<'PYTHON' | tee $out/report
          import pathlib, struct, sys

          # Bit 0x4000 of DllCharacteristics: IMAGE_DLLCHARACTERISTICS_GUARD_CF.
          GUARD_CF = 0x4000
          # Offset of DllCharacteristics inside the optional header. The field
          # sits at the same place for PE32 and PE32+, because everything that
          # differs in size comes after it.
          DLL_CHARACTERISTICS = 70

          binaries = sorted(pathlib.Path("${windows}/bin").glob("*.exe"))
          assert binaries, "the Windows build produced no .exe, so this checks nothing"

          for path in binaries:
              data = path.read_bytes()
              pe = struct.unpack_from("<I", data, 0x3C)[0]
              assert data[pe:pe + 4] == b"PE\0\0", f"{path.name} is not a PE file"
              flags = struct.unpack_from("<H", data, pe + 24 + DLL_CHARACTERISTICS)[0]
              guarded = bool(flags & GUARD_CF)
              print(f"{path.name:20} DllCharacteristics=0x{flags:04x} GUARD_CF={guarded}")
              assert not guarded, (
                  f"{path.name} was built with Control Flow Guard. On this "
                  "toolchain that produces a binary that dies at startup with "
                  "0xC0000409 / FAST_FAIL_GUARD_ICALL_CHECK_FAILURE before it "
                  "logs anything, which is strictly worse than the mitigation "
                  "is worth (PKG-018). If this is being re-enabled, run the "
                  "artifact on a Windows guest first - harness/windows/ exists "
                  "for that and is how this was found"
              )
          PYTHON
        '';

      # `PKG-016` (#366): the ISO is bit-reproducible.
      #
      # `reproducible` already checks `.#server` and has since `SEC-010` (#202).
      # The ISO was never checked, and was not reproducible: two builds of one
      # revision differed by 74 bytes — every one of them a date in the volume
      # descriptor or a directory record, no content difference at all. `cp`
      # stamps each staged file with the moment it ran and xorriso stamps the
      # volume with its own clock, so the drift was pure timestamp.
      #
      # It matters more than it did before `PKG-015` (#364), which put this file
      # behind a stable download URL. An artifact somebody else can rebuild and
      # compare byte for byte needs no trust in the machine that built it; one
      # they cannot leaves the signature as the only assurance.
      #
      # `--rebuild` builds it again and makes Nix compare, which is the same
      # mechanism the `reproducible` check uses rather than a second way of
      # asking.
      reproducibleIsoCheckFor = { system, arch }:
        let
          pkgs = pkgsFor system;
          linux = linuxFor { inherit system arch; };
        in
        pkgs.runCommand "reproducible-iso"
          {
            nativeBuildInputs = [ pkgs.python3 ];
            meta.timeout = 1800;
          } ''
          mkdir -p $out
          # The ISO is an input to this derivation, so building it is what put
          # it in the store; what is asserted here is the property Nix checked
          # when `--rebuild` was asked for. Recording the digest is what makes a
          # change visible in a diff.
          python3 - <<'PYTHON' | tee $out/report
          import hashlib, pathlib
          iso = pathlib.Path("${linux.iso}")
          data = iso.read_bytes()
          print(f"ISO     {len(data)} bytes")
          print(f"sha256  {hashlib.sha256(data).hexdigest()}")

          # Timestamps are what made this file irreproducible, and the volume
          # descriptor is where the first one lives. A PVD whose creation date
          # is not the pinned one means `--modification-date` stopped being
          # passed, which `--rebuild` would only catch on a machine whose clock
          # had moved between the two builds.
          pvd = data[0x8000:0x8800]
          assert pvd[1:6] == b"CD001", "no primary volume descriptor at 0x8000"
          created = pvd[813:830].decode("ascii", "replace")
          print(f"created {created}")
          assert not created.startswith("0000"), "the volume has no creation date"
          PYTHON
        '';

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
            Entrypoint = [ "/bin/kmsrs-server" ];

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
          linuxArch = linuxArchFor system;
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
              /usr/bin/kmsrs-server
              /usr/bin/kmsrs-client
              /usr/lib/systemd/system/kmsrs-server.service
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
        }
        # The gate is "this system builds a bare-metal target", not "this
        # system is x86_64" (`OS-031`, #375). The two coincide today, and the
        # distinction is the point: `linuxArches` is the one place that decides
        # which systems those are, so a target added there appears here without
        # this line being touched.
        #
        # It has to be a gate at all because `nix flake check` on aarch64 used
        # to evaluate every output, reach `pkgs.syslinux` — which nixpkgs marks
        # unavailable off x86 — and fail there rather than anywhere informative
        # (`OS-017`, #333).
        #
        # An `optionalAttrs` rather than a `meta.platforms`: the point is that
        # the attribute should not *exist* on a system that cannot build it, so
        # `nix flake show` on a system with no target says so instead of
        # erroring.
        // pkgs.lib.optionalAttrs (linuxArch != null) {
          # --- The Linux-as-PID-1 target (`OS-017`, #333) ---
          #
          # The second bare-metal target: the same `kmsrs-server` binary as pid
          # 1 on a `tinyconfig`-derived kernel, with no other userland. It exists
          # because the Hermit image does not boot into service on a stock
          # Proxmox VM — `OS-004` (#255) needs `qm set --args`, which has no GUI
          # field — and this one does, from BIOS or UEFI, unmodified.
          #
          # Which of the two ships is `OS-018` (#334), and is not decided here.
          linuxIso = (linuxFor { inherit system; arch = linuxArch; }).iso;
          linux-kernel = (linuxFor { inherit system; arch = linuxArch; }).kernel;

          # `nix build .#linux-config` — regenerate `os/linux/kernel.config`.
          #
          # An output rather than `nix build -f os/linux/config.nix`, which is
          # what this used to be and which reads `<nixpkgs>` from the caller's
          # channel. That silently regenerates the file against *a different
          # kernel version* than the one the flake pins and the ISO is built
          # from — observed on `OS-026` (#343), where it produced a 6.12.91
          # config for a tree that ships 6.12.94, as a 54-line deletion that
          # looked like a pare-back. The file is the statement of what is in
          # this machine's TCB; generating it from an unpinned input is exactly
          # the `OS-006` (#257) mistake in a new place.
          linux-config = import ./os/linux/config.nix {
            inherit pkgs;
            arch = linuxArch;
          };

          # `nix build .#linux-deltas && cat result/report` — what each driver
          # in the `OS-025` (#342) matrix costs, measured on the built bzImage
          # with the initramfs held constant. That last part is the whole
          # point: the initramfs is *inside* the bzImage, so measuring a 40 kB
          # driver against the shipped kernel compares two numbers that differ
          # for two reasons.
          #
          # Each variant is the checked-in allowlist plus the symbols named,
          # run through the same `olddefconfig` the real build uses — so a
          # symbol that drags a subsystem in is measured with the subsystem,
          # which is the mistake `OS-026` (#343) found the hard way.
          linux-deltas = import ./os/linux/delta.nix {
            inherit pkgs;
            arch = linuxArch;
            variants = {
              # Proxmox's "VMware vmxnet3" dropdown entry, and the default NIC
              # for a modern Linux guest on ESXi and Workstation.
              vmxnet3 = [ "NET_VENDOR_VMWARE" "VMXNET3" ];
              # Proxmox's "Realtek RTL8139" entry, and Xen HVM's default.
              rtl8139 = [ "NET_VENDOR_REALTEK" "8139CP" "8139TOO" ];
              # VirtualBox's older adapter choices.
              pcnet32 = [ "NET_VENDOR_AMD" "PCNET32" ];
              # Hyper-V Generation 1's "Legacy Network Adapter", a DEC 21140.
              tulip = [ "NET_VENDOR_DEC" "NET_TULIP" "TULIP" ];
              # EC2 Nitro (`OS-027`, #344).
              ena = [ "NET_VENDOR_AMAZON" "ENA_ETHERNET" ];
              # Hyper-V and Azure. The one item `OS-025` calls "genuinely
              # large", and the reason this output exists rather than an
              # estimate in a comment.
              hyperv = [ "HYPERV" "HYPERV_NET" "HYPERV_TIMER" ];
              # Xen PV networking on XCP-ng and Citrix Hypervisor.
              xen = [ "XEN" "XEN_NETDEV_FRONTEND" ];
              # `OS-023` (#339) asks in the other direction: what does something
              # already in the allowlist cost to *keep*? A negative delta is the
              # saving available if it were removed.
              no-smp = { disable = [ "SMP" ]; };
              no-elf-core = { disable = [ "ELF_CORE" ]; };
              no-seccomp = { disable = [ "SECCOMP" ]; };
              no-ipv6 = { disable = [ "IPV6" ]; };
              no-packet = { disable = [ "PACKET" ]; };
            };
          };
        });

      checks = eachSystem (system:
        let
          craneLib = cranelibFor system;
          commonArgs = commonArgsFor system;
          cargoArtifacts = cargoArtifactsFor system;
          linuxArch = linuxArchFor system;
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
            # `kmsrs-server` as well as `kmsrs-policy` (`POL-020`, #346). The
            # difference `strict-clock-skew` makes is only observable
            # end-to-end: the policy crate's tests hand `evaluate` a host clock
            # directly and passed for the whole time `driver.rs` supplied
            # `None` and the refusal was unreachable. `tests/clock_skew.rs`
            # drives a real socket, so it is the test that can tell the two
            # builds apart — and it only runs if this job selects the crate.
            cargoNextestExtraArgs =
              "-p kmsrs-policy -p kmsrs-server "
              + "--features kmsrs-policy/permissive-retail,kmsrs-policy/strict-clock-skew";
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





          feature-powerset = craneLib.mkCargoDerivation (commonArgs // {
            inherit cargoArtifacts;
            pname = "kmsrsos-feature-powerset";
            buildPhaseCargoCommand = ''
              cargo hack check --workspace --all-targets --feature-powerset --locked
            '';
            nativeBuildInputs = (commonArgs.nativeBuildInputs or [ ])
              ++ [ (pkgsFor system).cargo-hack ];
          });
        }
        # Gated the same way the packages above are, and for the same reason:
        # these boot the artifact this system builds, and a system that builds
        # no bare-metal target has nothing here to check (`OS-031`, #375).
        # Before the gate existed, `nix flake check` on aarch64 failed
        # evaluating them rather than skipping them (`OS-017`, #333).
        #
        # `nixpkgs.lib` rather than `pkgs.lib`: `pkgs` is bound inside this
        # check set's `let`, and this splice is outside it.
        // nixpkgs.lib.optionalAttrs (linuxArch != null) {
          # `OS-017` (#333): boots and serves on the topology Hermit cannot,
          # from BIOS and UEFI, with no `--args`.
          linux-boot = linuxBootCheckFor {
            inherit system;
            arch = linuxArch;
          };

          # `OS-025` (#342): one boot per supported NIC model, each asserting
          # that the machine *serves* — plus the machine with no NIC at all,
          # which must say so rather than reporting `listening` and going quiet.
          linux-nics = nicBootCheckFor {
            inherit system;
            arch = linuxArch;
          };

          # `SEC-005` (#197): the Windows binaries are built with Control Flow
          # Guard, read off the PE header rather than off the recipe.
          windows-mitigations = windowsMitigationsCheckFor system;

          # `PKG-016` (#366): two builds of the ISO are the same bytes.
          reproducible-iso = reproducibleIsoCheckFor {
            inherit system;
            arch = linuxArch;
          };

          # `OS-030` (#348): the kernel is in the ISO exactly once, counted,
          # and it boots as a raw disk on both firmwares.
          linux-iso-layout = isoLayoutCheckFor {
            inherit system;
            arch = linuxArch;
          };
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

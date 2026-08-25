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
      # --- The Linux-as-PID-1 target (`OS-017`, #333) ---
      #
      # Kept in `os/linux/` rather than inline, because unlike the Hermit
      # artefacts this one is mostly a kernel configuration, and a 2790-line
      # allowlist is the statement of what is in the machine's TCB. It belongs
      # in a file a reviewer can read, not spliced into this one.
      linuxFor = system:
        let pkgs = pkgsFor system;
        in import ./os/linux {
          inherit pkgs;
          init = (mkKmsrsos { inherit system; }).os;
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
      linuxBootCheckFor = system:
        let
          pkgs = pkgsFor system;
          configured = mkKmsrsos { inherit system; };
          linux = linuxFor system;

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
            qemu-system-x86_64 \
              -machine q35 -cpu qemu64 \
              -smp 1 -m 512M -display none -no-reboot \
              -serial "file:$serial" \
              -monitor "unix:$monitor,server,nowait" \
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




          # --- The Linux-as-PID-1 target (`OS-017`, #333) ---
          #
          # The second bare-metal target: the same `kmsrs-server` binary as pid
          # 1 on a `tinyconfig`-derived kernel, with no other userland. It exists
          # because the Hermit image does not boot into service on a stock
          # Proxmox VM — `OS-004` (#255) needs `qm set --args`, which has no GUI
          # field — and this one does, from BIOS or UEFI, unmodified.
          #
          # Which of the two ships is `OS-018` (#334), and is not decided here.
          linuxIso = (linuxFor system).iso;
          linux-kernel = (linuxFor system).kernel;

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
          linux-config = import ./os/linux/config.nix { inherit pkgs; };

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



          # `OS-017` (#333): boots and serves on the topology Hermit cannot,
          # from BIOS and UEFI, with no `--args`.
          linux-boot = linuxBootCheckFor system;



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

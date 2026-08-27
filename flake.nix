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
            || (builtins.match ".*/\\.github(/.*)?" path != null)
            # The measured syscall surveys, which `tests/sandbox.rs` reads back
            # to assert that the seccomp allowlist covers every syscall the
            # shipped binary was observed making (`SEC-018`, #355). Note the
            # `harness` directory itself: a filter that excludes a directory
            # never visits its children, which is why every rule above ends in
            # `(/.*)?` rather than naming files. `harness/windows/captures` is
            # deliberately left out — it is a megabyte of `.pcap` that nothing
            # in the build reads.
            || (builtins.match ".*/harness" path != null)
            || (builtins.match ".*/harness/linux(/.*)?" path != null);
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

      # --- Windows cross-compilation (`PKG-020`, #379) ---
      #
      # **Two targets, and neither is "the" Windows build.** The client
      # population that needs this is going Arm: Snapdragon X and Windows Dev
      # Kit machines run Windows 11 on Arm natively, and on Apple Silicon it is
      # the only Windows there is. Before this, such a user could run
      # `kmsrs-server` on Windows only under the x86 emulation layer — which is
      # worse than it sounds for this program in particular, because `SEC-019`
      # (#356) verifies its mitigations **on a live process**, and under
      # emulation what that verifies is a property of the emulator's process.
      #
      # Every field below was a literal before this issue. The two that are not
      # obvious:
      #
      #   * `xwin` is what `xwin splat` calls the architecture, and therefore
      #     the directory the import libraries land in. It happens to agree
      #     with `name` for both of these and is a separate field because
      #     nothing guarantees that — `xwin` also knows `x86` and `aarch`.
      #   * `machine` is `IMAGE_FILE_MACHINE_*` from the PE header, which is
      #     the only architecture statement that is a property of the
      #     *artifact* rather than of the recipe. `windows-mitigations` reads
      #     it, so that a check cannot pass by having read the binary it
      #     already knew about (`PKG-018`).
      windowsArches = {
        x86_64 = {
          name = "x86_64";
          target = "x86_64-pc-windows-msvc";
          xwin = "x86_64";
          machine = 34404; # 0x8664, IMAGE_FILE_MACHINE_AMD64
        };
        aarch64 = {
          name = "aarch64";
          target = "aarch64-pc-windows-msvc";
          xwin = "aarch64";
          machine = 43620; # 0xAA64, IMAGE_FILE_MACHINE_ARM64
        };
      };

      # Cargo and `cc` spell one triple two different ways, and getting either
      # wrong fails **silently**: an unrecognised `CARGO_TARGET_…` variable is
      # ignored rather than rejected, so the linker would quietly revert to the
      # default and the flag it was carrying would vanish. Derived from the
      # triple rather than written twice.
      cargoTargetVar = arch:
        nixpkgs.lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] arch.target);
      ccTargetVar = arch: builtins.replaceStrings [ "-" ] [ "_" ] arch.target;

      # One fixed-output derivation, both architectures (`PKG-020`, #379).
      #
      # Not one per architecture, and that is the point of the issue's "bumping
      # it stays a one-place change": two FODs would be two hashes to update
      # and two chances to update one of them. `xwin` fetches the same manifest
      # either way; only the import libraries differ, and they land in
      # per-architecture directories.
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
              ${builtins.concatStringsSep " "
                (map (arch: "--arch ${arch.xwin}")
                  (builtins.attrValues windowsArches))} \
              splat --copy --output "$out"
          '';

          outputHashMode = "recursive";
          outputHashAlgo = "sha256";
          outputHash = "sha256-22dqk0tKSbC4bnfsnhhsG0aEJfUHb3JJNL3TnZGFVa0=";
        };

      windowsArgsFor = { system, arch }:
        let
          pkgs = pkgsFor system;
          xwinSdk = xwinSdkFor system;
          commonArgs = commonArgsFor system;
          cargoVar = cargoTargetVar arch;
          ccVar = ccTargetVar arch;
        in
        commonArgs // {
          pnameSuffix = "-windows-${arch.name}";

          nativeBuildInputs = commonArgs.nativeBuildInputs ++ [
            pkgs.llvmPackages.lld
          ];

          CARGO_BUILD_TARGET = arch.target;
          "CARGO_TARGET_${cargoVar}_LINKER" = "lld-link";
          "CARGO_TARGET_${cargoVar}_RUSTFLAGS" = builtins.concatStringsSep " " [
            "-Lnative=${xwinSdk}/crt/lib/${arch.xwin}"
            "-Lnative=${xwinSdk}/sdk/lib/um/${arch.xwin}"
            "-Lnative=${xwinSdk}/sdk/lib/ucrt/${arch.xwin}"

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
            # verified in force on a live process — see `crate::sandbox`. On
            # **x86_64**: nobody has run the ARM64 binary on an ARM64 Windows
            # machine, and `PKG-020` (#379) says so rather than assuming the
            # kernel answers the same way. See `docs/decisions.md`.
            # Restoring CFG is `PKG-018`; the likely requirement is a `std`
            # rebuilt with it, since the precompiled one is not.
          ];

          "CC_${ccVar}" = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang-cl";
          "AR_${ccVar}" = "${pkgs.llvmPackages.llvm}/bin/llvm-lib";
          "CFLAGS_${ccVar}" = builtins.concatStringsSep " " [
            # Stated rather than inferred (`PKG-020`, #379). `clang-cl` takes
            # its default triple from the *build host*, so on an aarch64 Linux
            # runner it would compile for ARM64 Windows whichever target cargo
            # was asked for. Nothing in this workspace compiles C today, so
            # this changes no byte of either artifact; it is here so that the
            # day something does, it is not a bug that depends on which runner
            # picked up the job.
            "--target=${arch.target}"
            "-imsvc${xwinSdk}/crt/include"
            "-imsvc${xwinSdk}/sdk/include/ucrt"
            "-imsvc${xwinSdk}/sdk/include/um"
            "-imsvc${xwinSdk}/sdk/include/shared"
          ];

          # Windows binaries can't run on the build host.
          doCheck = false;
          cargoExtraArgs = "--package kmsrs-server --package kmsrs-client";
        };

      windowsCargoArtifactsFor = { system, arch }:
        let craneLib = cranelibFor system;
        in craneLib.buildDepsOnly ((windowsArgsFor { inherit system arch; }) // {
          pname = "kmsrsos-windows-${arch.name}";
        });

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
        # A Linux system with no static target is an error rather than an
        # ordinary dynamically linked build (`PKG-023`, #395). It used to be
        # the latter, and the failure was silent in exactly the way that
        # matters: delete `aarch64-unknown-linux-musl` from
        # `rust-toolchain.toml` and the arm leg would go on producing a
        # glibc-linked binary, shipped under a `docs/releasing.md` row that
        # says "statically linked against musl; no runtime dependencies".
        # Darwin still gets `{ }`, because there is nothing to ship there.
        if target == null then
          (if nixpkgs.lib.hasSuffix "-linux" system
          then throw "no static target for ${system}, which is a Linux system             that ships binaries. `staticTargetFor` has to name one, or the             artifact is dynamically linked against a claim that says it is not             (`PKG-023`, #395)"
          else { })
        else {
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

          # Every `console=` the kernel command line carries, in order.
          #
          # A list rather than one device, because an architecture can have
          # more than one plausible serial port and the kernel simply ignores a
          # `console=` naming a device that is not there. Order stopped
          # deciding anything in `OS-028` (#345) — pid 1 reads `/proc/consoles`
          # and tees to all of them — but `/dev/console` still resolves to the
          # last one, so `tty0` stays last for the reason that issue gives.
          #
          # `ttyS0` is an 8250 at a legacy I/O port, which is an x86 platform
          # fact rather than a Linux one.
          consoles = [ "ttyS0,115200" "tty0" ];

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

          # How `readelf -h` spells this machine, for the check that reads the
          # shipped binaries rather than the expression that built them
          # (`PKG-023`, #395). Here rather than derived from the Nix system,
          # because the two spell it differently and a check comparing the
          # wrong pair of strings would pass on every artifact.
          elfMachine = "Advanced Micro Devices X86-64";

          # What boots it in a check.
          qemu = "qemu-system-x86_64";
        };

        # `OS-032` (#376). Proxmox VE 9.2 for arm64 shipped on 5 August 2026,
        # and KVM is same-architecture: an operator on one of those hosts can
        # run aarch64 guests and nothing else. The audience is the clients
        # rather than the hosts, and on Apple Silicon the entire lab is
        # aarch64.
        #
        # Almost every field below differs from the one above, and the ones
        # that differ most are the ones that look like they should not.
        aarch64 = {
          name = "aarch64";
          system = "aarch64-linux";

          # `arm64`, which is neither `aarch64` nor `aarch64-linux`. Three
          # spellings of one architecture is exactly why this is a field.
          kernelArch = "arm64";

          # `vmlinuz.efi`, not `Image`, and the difference is 3.87 MB.
          #
          # arm64 has no self-decompressing counterpart of `bzImage`: `Image`
          # is the kernel uncompressed, 6 611 456 bytes here.
          # `CONFIG_EFI_ZBOOT` produces a compressed PE instead — 2 740 736
          # bytes, 58 % smaller — which firmware runs directly through the same
          # EFI stub. Measured with `.#linux-deltas`; it matters most in
          # `OS-033` (#377), where the kernel goes back into a FAT filesystem.
          #
          # It is EFI-only, and that costs nothing on a target where every
          # firmware is UEFI.
          image = "vmlinuz.efi";

          # The removable-media path for AArch64, from the same UEFI
          # specification table `BOOTX64.EFI` comes from.
          efiFile = "BOOTAA64.EFI";

          # Unused while `bios` is false — there is no bootloader in the arm
          # image, because there is no second firmware to share a kernel with
          # (`OS-033`, #377). Stated so the descriptor has no hole in it.
          grubFormat = "arm64-efi";

          # Two serial ports and a framebuffer, and the first two are not
          # interchangeable. QEMU's `virt` machine has a PL011 (`ttyAMA0`);
          # **EC2's aarch64 instances have a 16550A** (`ttyS0`) — observed on a
          # Graviton host, where ACPI SPCR reads `uart,mmio,0x90a0000` and the
          # kernel reports `ttyS0 … is a 16550A`. A machine that named only one
          # of them would boot silently on the other platform, which is
          # `OS-005` (#256) all over again.
          consoles = [ "ttyAMA0,115200" "ttyS0,115200" "tty0" ];

          # **No BIOS anywhere.** Proxmox VE for arm64 boots every VM through
          # AAVMF and SeaBIOS is not available; nor is there a legacy firmware
          # on any other Arm hypervisor. So there is no second reader of the
          # image, no sharing problem, and nothing for a bootloader to solve
          # (`OS-033`, #377).
          bios = false;

          config = ./os/linux/kernel.config.aarch64;

          # `PKG-023` (#395). Not "aarch64" and not "arm64": this is
          # `readelf`'s spelling, and it is the third one this architecture has
          # in this file.
          elfMachine = "AArch64";

          qemu = "qemu-system-aarch64";
        };
      };

      # Every ethernet vendor menu that gates nothing either image enables
      # (`OS-035`, #383).
      #
      # These are menus, not drivers: `NET_VENDOR_X` is a `bool … default y`
      # whose only effect is that `drivers/net/ethernet/Makefile` descends into
      # that vendor's directory, where every object is gated by a driver symbol
      # of its own — all of which are off. So the expected delta is zero, and
      # this variant exists to say that with a number rather than an argument,
      # because "harmless" is the word every inert entry in `config.nix` was
      # described with before somebody measured it.
      #
      # The four the aarch64 list adds are the vendors whose drivers are x86
      # rows of the `OS-025` (#342) matrix — Realtek, AMD, DEC — plus HiSilicon,
      # which only exists on arm.
      idleVendorMenus = [
        "NET_VENDOR_3COM" "NET_VENDOR_8390" "NET_VENDOR_ADAPTEC"
        "NET_VENDOR_AGERE" "NET_VENDOR_ALACRITECH" "NET_VENDOR_ALTEON"
        "NET_VENDOR_AQUANTIA" "NET_VENDOR_ARC" "NET_VENDOR_ASIX"
        "NET_VENDOR_ATHEROS" "NET_VENDOR_BROADCOM" "NET_VENDOR_BROCADE"
        "NET_VENDOR_CADENCE" "NET_VENDOR_CAVIUM" "NET_VENDOR_CHELSIO"
        "NET_VENDOR_CISCO" "NET_VENDOR_CORTINA" "NET_VENDOR_DAVICOM"
        "NET_VENDOR_DLINK" "NET_VENDOR_EMULEX" "NET_VENDOR_ENGLEDER"
        "NET_VENDOR_EZCHIP" "NET_VENDOR_FUNGIBLE" "NET_VENDOR_GOOGLE"
        "NET_VENDOR_HUAWEI" "NET_VENDOR_I825XX" "NET_VENDOR_LITEX"
        "NET_VENDOR_MARVELL" "NET_VENDOR_MELLANOX" "NET_VENDOR_META"
        "NET_VENDOR_MICREL" "NET_VENDOR_MICROCHIP" "NET_VENDOR_MICROSEMI"
        "NET_VENDOR_MICROSOFT" "NET_VENDOR_MYRI" "NET_VENDOR_NATSEMI"
        "NET_VENDOR_NETERION" "NET_VENDOR_NETRONOME" "NET_VENDOR_NI"
        "NET_VENDOR_NVIDIA" "NET_VENDOR_OKI" "NET_VENDOR_PACKET_ENGINES"
        "NET_VENDOR_PENSANDO" "NET_VENDOR_QLOGIC" "NET_VENDOR_QUALCOMM"
        "NET_VENDOR_RDC" "NET_VENDOR_RENESAS" "NET_VENDOR_ROCKER"
        "NET_VENDOR_SAMSUNG" "NET_VENDOR_SEEQ" "NET_VENDOR_SILAN"
        "NET_VENDOR_SIS" "NET_VENDOR_SMSC" "NET_VENDOR_SOCIONEXT"
        "NET_VENDOR_SOLARFLARE" "NET_VENDOR_STMICRO" "NET_VENDOR_SUN"
        "NET_VENDOR_SYNOPSYS" "NET_VENDOR_TEHUTI" "NET_VENDOR_TI"
        "NET_VENDOR_VERTEXCOM" "NET_VENDOR_VIA" "NET_VENDOR_WANGXUN"
        "NET_VENDOR_WIZNET" "NET_VENDOR_XILINX"
      ];

      # What `.#linux-deltas` measures, per architecture.
      #
      # Two lists rather than one, because a delta is only meaningful against a
      # question somebody is asking, and the questions differ: on x86 they are
      # about NIC drivers for hypervisors that exist there, and on aarch64 the
      # expensive question is the *image format* rather than any driver
      # (`OS-032`, #376).
      linuxDeltaVariants = {
        x86_64 = {
          # The NIC drivers the `OS-025` (#342) matrix claims on this
          # architecture, every one of them asked in the **disable**
          # direction — which is `OS-038` (#391), and is not a style choice.
          #
          # These are all in the checked-in allowlist, so an `enable` variant
          # turns on what is already on: `olddefconfig` produces a
          # configuration byte-identical to the baseline and the report prints
          # a delta of exactly zero. Six of them sat here doing that, next to
          # comments in `os/linux/config.nix` quoting real positive numbers
          # taken by `OS-025` at the moment each driver was *added*, when the
          # baseline did not contain it. The numbers were right and
          # unreproducible: running the command the file tells you to run
          # printed zeros that contradicted them.
          #
          # Asked this way the delta is negative and is the thing a shipped
          # configuration can act on — what this driver costs to keep, the
          # `OS-023` (#339) direction the aarch64 list below already used.
          #
          # Each list is the enable list reversed rather than the vendor gate
          # alone. `olddefconfig` would drop a driver whose vendor menu went
          # away, but naming both makes the variant say what it prices without
          # depending on that.

          # Proxmox's "VMware vmxnet3" dropdown entry, and the default NIC
          # for a modern Linux guest on ESXi and Workstation.
          # One symbol, not two: there is no `NET_VENDOR_VMWARE` gate
          # (`OS-034`, #382).
          vmxnet3 = { disable = [ "VMXNET3" ]; };
          # Proxmox's "Realtek RTL8139" entry, and Xen HVM's default.
          rtl8139 = { disable = [ "8139CP" "8139TOO" "NET_VENDOR_REALTEK" ]; };
          # VirtualBox's older adapter choices.
          pcnet32 = { disable = [ "PCNET32" "NET_VENDOR_AMD" ]; };
          # Hyper-V Generation 1's "Legacy Network Adapter", a DEC 21140.
          tulip = { disable = [ "TULIP" "NET_TULIP" "NET_VENDOR_DEC" ]; };
          # EC2 Nitro (`OS-027`, #344).
          ena = { disable = [ "ENA_ETHERNET" "NET_VENDOR_AMAZON" ]; };
          # Hyper-V and Azure. The one item `OS-025` calls "genuinely
          # large", and the reason this output exists rather than an
          # estimate in a comment.
          hyperv = { disable = [ "HYPERV_NET" "HYPERV_TIMER" "HYPERV" ]; };
          # All six at once, because two drivers sharing a vendor gate pay for
          # it once and the total is therefore not the sum of the rows above.
          # `os/linux/config.nix` quotes that aggregate, so it has to be
          # reproducible rather than arithmetic somebody did by hand.
          no-emulated-nics = {
            disable = [
              "VMXNET3"
              "8139CP" "8139TOO" "NET_VENDOR_REALTEK"
              "PCNET32" "NET_VENDOR_AMD"
              "TULIP" "NET_TULIP" "NET_VENDOR_DEC"
              "ENA_ETHERNET" "NET_VENDOR_AMAZON"
              "HYPERV_NET" "HYPERV_TIMER" "HYPERV"
            ];
          };

          # Xen PV networking on XCP-ng and Citrix Hypervisor. The one driver
          # variant here still asked in the enable direction, and the reason is
          # that it is the only one **not** in the allowlist: `OS-025` declined
          # it on this measurement, so what there is to price is what putting
          # it back would cost. A `disable` variant would turn off what is
          # already off and report zero.
          xen = [ "XEN" "XEN_NETDEV_FRONTEND" ];

          # `OS-023` (#339) asks in the other direction: what does something
          # already in the allowlist cost to *keep*? A negative delta is the
          # saving available if it were removed.
          no-smp = { disable = [ "SMP" ]; };
          no-seccomp = { disable = [ "SECCOMP" ]; };
          no-ipv6 = { disable = [ "IPV6" ]; };
          no-packet = { disable = [ "PACKET" ]; };

          # There is no `no-elf-core`. `ELF_CORE` was inert and `OS-034` (#382)
          # took it out of the allowlist, so disabling it disabled nothing and
          # the row read zero — the same "the question was not asked" zero as
          # `no-smp` on aarch64 (`OS-038`, #391).

          # `OS-035` (#383): the 8250 variants this kernel no longer builds —
          # the two PCIe card families and the PnP bus named in `common`, plus
          # the two Intel SoC UARTs that are x86-only symbols.
          #
          # Asked in the *enable* direction, and that is not a style choice.
          # They are off in the checked-in configuration, so a `disable`
          # variant would turn off what is already off and report a delta of
          # exactly zero — the `no-smp` trap below, and the trap `OS-035` found
          # six x86 variants already sitting in: a driver that is in the
          # baseline cannot be priced by adding it. What this measures is what
          # they would cost to put back, which is the same number in the other
          # sign.
          serial-8250-variants = [
            "SERIAL_8250_EXAR" "SERIAL_8250_PERICOM" "SERIAL_8250_PNP"
            "SERIAL_8250_LPSS" "SERIAL_8250_MID"
          ];

          # `OS-037` (#390): what the PnP layer's debugging messages cost to put
          # back. The enable direction, because `PNP_DEBUG_MESSAGES` is off in
          # the checked-in configuration as of that issue — the `OS-038` (#391)
          # rule, applied the first time it was needed.
          #
          # There is no `no-pnp` beside it. `menuconfig ACPI` carries
          # `select PNP`, so the symbol cannot be turned off while ACPI is on
          # and the variant would report exactly zero — "the question could not
          # be asked" rather than "the PnP bus is free". `os/linux/config.nix`
          # is where that is written down.
          #
          # Measured: **0**, and that zero is a measurement rather than an
          # unasked question. The variant does turn a symbol on that the
          # baseline has off — `olddefconfig` produces a genuinely different
          # configuration — and the image comes out the same size, because a
          # `bzImage` is page-aligned and this measurement's resolution is
          # therefore 4 KiB. So what it says is "the PnP debugging messages
          # cost less than this instrument can see", which is a different and
          # much weaker fact than `no-smp`'s zero on aarch64, and is why it is
          # still worth having a row. `OS-037` disabled them on the argument
          # rather than on the number.
          pnp-debug = [ "PNP_DEBUG_MESSAGES" ];

          # There is no `no-perf-events` here, and its absence is a finding
          # rather than an omission (`OS-035`, #383). `config X86` carries an
          # unconditional `select PERF_EVENTS`, so the variant would produce a
          # configuration identical to the baseline and a delta of exactly
          # zero — a number that reads as "perf is free" and means "the
          # question could not be asked". Same shape as `no-smp` on aarch64
          # below. `os/linux/config.nix` is where the reason is written down.

          # What the idle vendor menus cost to keep, all sixty-five of them.
          no-vendor-menus = { disable = idleVendorMenus; };
        };

        aarch64 = {
          # What the compressed image is worth, asked in the `OS-023` (#339)
          # direction: this is the *cost of not having it*.
          #
          # `CONFIG_EFI_ZBOOT` is in the allowlist, so the baseline is already
          # `vmlinuz.efi`. Turning it off produces a different file rather than
          # a bigger one — the uncompressed `Image` — which is what the `image`
          # override is for. Measuring `Image` on both sides would report no
          # change and be wrong twice.
          no-efi-zboot = { disable = [ "EFI_ZBOOT" ]; image = "Image"; };

          # The three drivers the arm matrix claims beyond virtio, each priced
          # the way `OS-025` (#342) requires.
          ena = { disable = [ "ENA_ETHERNET" ]; };
          e1000 = { disable = [ "NET_VENDOR_INTEL" ]; };
          hyperv = { disable = [ "HYPERV" ]; };

          # A virtio-gpu console. `virt` machines with a virtio GPU rather than
          # a `ramfb` lose the EFI framebuffer at `ExitBootServices`, so
          # `simpledrm` has nothing to take over and the noVNC window freezes
          # on the firmware logo. Not in the allowlist; this is what adding it
          # would cost if that turns out to be what Proxmox VE for arm64
          # attaches.
          virtio-gpu = [ "DRM_VIRTIO_GPU" ];

          # KASLR is the one mitigation this architecture had to be *told* to
          # have (`OS-032`, #376), so what it costs is worth knowing.
          no-kaslr = { disable = [ "RANDOMIZE_BASE" ]; };

          # The same "cost to keep" questions `OS-023` (#339) asks on x86.
          #
          # There is no `no-smp` here, and the reason is worth writing down
          # because its absence looks like an oversight. `arch/arm64/Kconfig`
          # has `config SMP` / `def_bool y`: it cannot be turned off, so the
          # variant produced a config identical to the baseline and a delta of
          # exactly zero — a number that reads as "SMP is free" and means "the
          # question was not asked". Same shape as the `DEBUG_KERNEL` finding
          # in `OS-023`.
          no-seccomp = { disable = [ "SECCOMP" ]; };
          no-ipv6 = { disable = [ "IPV6" ]; };
          no-packet = { disable = [ "PACKET" ]; };

          # `OS-036` (#389): what the 16550A variant probe costs to keep.
          #
          # The disable direction, because it is in this architecture's
          # allowlist and off on x86 — the asymmetry #389 was filed about. It
          # measures **0**, which is this instrument's 4 KiB floor rather than
          # "the probe is free": the question it was settled on is the console
          # it produces, checked on an EC2 Graviton instance, and
          # `os/linux/config.nix` is where that is written down.
          no-16550a-variants = { disable = [ "SERIAL_8250_16550A_VARIANTS" ]; };

          # `OS-035` (#383). Two of the three questions #383 asks have a number
          # on this architecture and one of them has a number *only* here.
          #
          # `perf-events` is asked in the opposite direction from everything
          # else in this list: it is off in the baseline, so this is what
          # `perf_event_open(2)` would cost to *add*. x86 has no counterpart,
          # because there the symbol cannot be turned off at all.
          perf-events = [ "PERF_EVENTS" ];
          # Three here rather than five: `SERIAL_8250_LPSS` and
          # `SERIAL_8250_MID` are `depends on X86`. In the enable direction for
          # the reason the x86 list gives.
          serial-8250-variants = [
            "SERIAL_8250_EXAR" "SERIAL_8250_PERICOM" "SERIAL_8250_PNP"
          ];
          no-vendor-menus = {
            disable = idleVendorMenus ++ [
              "NET_VENDOR_AMD" "NET_VENDOR_DEC" "NET_VENDOR_HISILICON"
              "NET_VENDOR_REALTEK"
            ];
          };
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

      # `OS-032` (#376): the same claims as `linuxBootCheckFor`, on the machine
      # where none of the answers carry over.
      #
      # A twin rather than a parameter, and that is the point of the issue. What
      # `linux-boot` varies across its two runs is the *firmware*; what varies
      # here is the interrupt controller, the timer, the console device, the way
      # the machine powers off and the shape of the PCI topology. A check
      # parametrised over all of that would be two checks sharing a `for` loop.
      #
      # Three things this does not have, each because the platform does not:
      #
      #   * **No BIOS run.** Arm64 guests boot UEFI through AAVMF; SeaBIOS does
      #     not exist for them. The firmware axis of the x86 check halves, which
      #     is the same fact that removes the bootloader in `OS-033` (#377).
      #   * **No bridge pair.** `qemu-server` emits `i82801b11-bridge` +
      #     `pci-bridge` for a q35 machine so that a transitional virtio device
      #     lands on a legacy bus — `OS-004` (#255), the thing Hermit refuses.
      #     `virt` has a single PCIe root, and the NIC goes on it.
      #   * **No bootloader in the medium.** Since `OS-033` (#377) the arm
      #     image holds the kernel in its ESP as `\EFI\BOOT\BOOTAA64.EFI`
      #     and firmware runs it through the EFI stub. So what this attaches is
      #     the shipped ISO, exactly as the x86 twin does, and what is being
      #     exercised is the whole path an operator's VM takes.
      #
      # `gic-version=3` is stated rather than left to `max`. The kernel has both
      # GICv2 and GICv3 — `ARM_GIC` arrives with the architecture — so a machine
      # that silently chose v2 would boot, and the `ARM_GIC_V3_ITS` entry that
      # the allowlist claims is load-bearing for PCIe MSI would go unexercised.
      #
      # `ramfb` is the framebuffer. `virt` has no display device at all by
      # default, and without one `/proc/consoles` has a single entry — which
      # would make the `OS-028` (#345) tee assertions below vacuous rather than
      # false.
      armBootCheckFor = { system, arch }:
        let
          pkgs = pkgsFor system;
          configured = mkKmsrsos { inherit system; };
          linux = linuxFor { inherit system arch; };

          virtTopology = builtins.concatStringsSep " " [
            "-netdev user,id=u1,hostfwd=tcp:127.0.0.1:1688-:1688"
            "-device virtio-net-pci,netdev=u1,bus=pcie.0,id=net0"
          ];
        in
        pkgs.runCommand "linux-boot"
          {
            nativeBuildInputs = [ pkgs.qemu_kvm pkgs.socat ];
            meta.timeout = 900;
          } ''
          set -euo pipefail
          mkdir -p $out

          serial="$PWD/uefi.log"
          monitor="$PWD/uefi.mon"
          agent="$PWD/uefi.agent"

          cp ${pkgs.OVMF.variables} "$PWD/vars.fd"
          chmod +w "$PWD/vars.fd"

          # `-no-shutdown` is deliberately absent, for the same reason as on
          # x86: this check's point is that the guest powers *itself* off and
          # qemu exits on its own. On arm64 that path ends in PSCI SYSTEM_OFF
          # rather than an ACPI write, which is the half of `OS-026` (#343) that
          # had never been run on this architecture.
          ${arch.qemu} \
            -machine virt,gic-version=3 -cpu cortex-a57 \
            -smp 1 -m 512M -display none -no-reboot \
            -serial "file:$serial" \
            -monitor "unix:$monitor,server,nowait" \
            -drive if=pflash,format=raw,unit=0,readonly=on,file=${pkgs.OVMF.firmware} \
            -drive if=pflash,format=raw,unit=1,file=$PWD/vars.fd \
            -device ramfb \
            -drive file=${linux.iso},media=cdrom,readonly=on \
            -device virtio-serial-pci \
            -chardev "socket,path=$agent,server=on,wait=off,id=ga" \
            -device virtserialport,chardev=ga,name=org.qemu.guest_agent.0 \
            ${virtTopology} &
          qemu=$!

          serving=0
          for attempt in $(seq 1 240); do
            if ${configured.client}/bin/kmsrs-client --quiet --healthcheck \
                 127.0.0.1:1688; then
              serving=1
              break
            fi
            if ! kill -0 $qemu 2>/dev/null; then
              echo "qemu exited before the guest answered" >&2
              cat "$serial" >&2 || true
              exit 1
            fi
            sleep 1
          done

          if [ "$serving" -ne 1 ]; then
            echo "the aarch64 guest never answered" >&2
            cat "$serial" >&2 || true
            kill $qemu 2>/dev/null || true
            exit 1
          fi

          for attempt in $(seq 1 60); do
            grep -q '"event":"agent"' "$serial" && break
            sleep 1
          done

          # The `sleep` keeps stdin open; see `linuxBootCheckFor` for why an
          # immediate EOF reads as "there is no agent".
          ask() {
            { printf '%s\n' "$1"; sleep 5; } \
              | socat -T8 - "UNIX-CONNECT:$agent" 2>/dev/null || true
          }
          ask '{"execute":"guest-network-get-interfaces"}' > $out/uefi.ifaces
          ask '{"execute":"guest-get-osinfo"}' > $out/uefi.osinfo
          ask '{"execute":"guest-exec","arguments":{"path":"/bin/sh"}}' > $out/uefi.exec

          for attempt in $(seq 1 60); do
            grep -q '"event":"clock"' "$serial" && break
            sleep 1
          done

          # `OS-026` (#343) on a machine that has no ACPI fixed-hardware power
          # button. On `virt` the press arrives through the ACPI **Generic Event
          # Device**, and whether it surfaces as the same evdev `KEY_POWER` is
          # exactly the thing #376 said had to be observed rather than reasoned
          # about. This is the observation.
          echo system_powerdown | socat - "UNIX-CONNECT:$monitor" >/dev/null

          stopped=0
          for attempt in $(seq 1 90); do
            if ! kill -0 $qemu 2>/dev/null; then
              stopped=1
              break
            fi
            sleep 1
          done
          wait $qemu 2>/dev/null || true
          cp "$serial" $out/uefi.log

          if [ "$stopped" -ne 1 ]; then
            echo "the aarch64 guest ignored system_powerdown, so 'qm shutdown' \
        does nothing and only 'qm stop' would stop it. On this machine the \
        press comes through the ACPI Generic Event Device rather than a fixed \
        power button (OS-026, #343; OS-032, #376)" >&2
            cat "$serial" >&2 || true
            kill -9 $qemu 2>/dev/null || true
            exit 1
          fi

          # Everything below is the same set of claims `linux-boot` makes on
          # x86. They are repeated rather than shared because each one is about
          # a different mechanism here, and a shared helper would hide that.
          grep -q '"event":"listening"' $out/uefi.log || {
            echo "no listener reported" >&2; exit 1; }

          # `OS-021` (#337).
          grep -q 'mounted /dev /proc /sys' $out/uefi.log || {
            echo "pid 1 did not mount all three pseudo-filesystems (OS-021, \
        #337)" >&2
            cat $out/uefi.log >&2; exit 1; }

          # `OS-028` (#345). The reasoning there was that ordering stopped
          # deciding anything because pid 1 reads /proc/consoles and tees. That
          # was a claim about an 8250; this is the same claim on a PL011, which
          # is a different driver reached through a different bus.
          grep -q '"event":"console".*logging to.*ttyAMA0' $out/uefi.log || {
            echo "pid 1 did not tee its log to the PL011. With tty0 last, every \
        line above reached the framebuffer only (OS-028, #345; OS-032, #376)" >&2
            cat $out/uefi.log >&2; exit 1; }
          grep -q '"event":"console".*logging to.*tty0' $out/uefi.log || {
            echo "pid 1 found no framebuffer console, so this check is not \
        exercising the two-console case OS-028 (#345) is about — which on this \
        machine needs a ramfb, since virt has no display device" >&2
            cat $out/uefi.log >&2; exit 1; }

          # `OS-022` (#338).
          grep -q '"event":"agent".*answering on vport' $out/uefi.log || {
            echo "the guest agent found no channel (OS-022, #338)" >&2
            cat $out/uefi.log >&2; exit 1; }
          grep -q '"hardware-address"' $out/uefi.ifaces || {
            echo "guest-network-get-interfaces was not answered (OS-022, #338)" >&2
            cat $out/uefi.ifaces >&2 || true; exit 1; }
          grep -q '"ip-address": "10.0.2.15"' $out/uefi.ifaces || {
            echo "the agent did not report the leased address (OS-022, #338)" >&2
            cat $out/uefi.ifaces >&2 || true; exit 1; }
          grep -q 'CommandNotFound' $out/uefi.exec || {
            echo "guest-exec was not refused with an error (OS-022, #338)" >&2
            cat $out/uefi.exec >&2 || true; exit 1; }

          # `OS-032` (#376): the agent stopped hardcoding `x86_64`. Asserted on
          # the *answer*, because that is what a hypervisor UI displays, and a
          # host that reports the wrong architecture is worse than one that
          # reports none.
          grep -q '"machine": "aarch64"' $out/uefi.osinfo || {
            echo "guest-get-osinfo reports the wrong machine on aarch64. It \
        hardcoded x86_64 until OS-032 (#376), which is a false statement a \
        management tool would believe" >&2
            cat $out/uefi.osinfo >&2 || true; exit 1; }

          # `OS-026` (#343): stopped, and stopped the right way.
          grep -q '"event":"power".*watching event' $out/uefi.log || {
            echo "pid 1 found no power button: the GED event has nowhere to go \
        and 'qm shutdown' is silently a no-op (OS-026, #343; OS-032, #376)" >&2
            cat $out/uefi.log >&2; exit 1; }
          grep -q '"event":"power".*acpi power button: draining' $out/uefi.log || {
            echo "the button was watched but the press did not reach the drain" >&2
            cat $out/uefi.log >&2; exit 1; }
          grep -q '"event":"stopped"' $out/uefi.log || {
            echo "the host stopped without draining (NET-007, #157; OS-026, \
        #343)" >&2
            cat $out/uefi.log >&2; exit 1; }

          # `OS-020` (#336).
          grep -qE '"event":"clock".*(no time server answered|stepped)' $out/uefi.log || {
            echo "the clock task said something that is neither a step nor a \
        report of no answer (OS-020, #336)" >&2
            cat $out/uefi.log >&2; exit 1; }

          if grep -qi 'Attempted to kill init' $out/uefi.log; then
            echo "pid 1 returned instead of powering the machine off, so the \
        operator sees a kernel panic after pressing Shutdown. On aarch64 that \
        power-off is PSCI SYSTEM_OFF (OS-026, #343)" >&2
            cat $out/uefi.log >&2; exit 1
          fi

          if grep -qi 'unable to open an initial console' $out/uefi.log; then
            echo "init had no stdio: the /dev/console node is missing from the \
        initramfs manifest (OS-017, #333)" >&2
            exit 1
          fi
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

      # `OS-025` (#342) on aarch64, where the matrix is a third of the size and
      # the reason is the platform rather than the driver (`OS-032`, #376).
      #
      # Four of the seven x86 rows have no arm counterpart at all, and dropping
      # them is a claim about products rather than about kernels:
      #
      #   * **pcnet32** is VirtualBox's older adapter list. VirtualBox has no
      #     aarch64 guest support to offer it from.
      #   * **tulip** is Hyper-V Generation 1's "Legacy Network Adapter".
      #     Generation 1 is x86 only; Azure's Arm instances are Generation 2 and
      #     therefore VMBus, which is `hv_netvsc` and is in the allowlist.
      #   * **8139cp** is Xen HVM's default emulated NIC on XCP-ng and Citrix,
      #     neither of which runs aarch64 guests.
      #   * **vmxnet3** is VMware's. Fusion on Apple Silicon offers virtio-net
      #     and an emulated Intel adapter, not vmxnet3; ESXi-on-Arm was a fling
      #     and is discontinued.
      #
      # What is left is virtio-net, which is every KVM-derived hypervisor's
      # default, and the Intel pair — kept because Proxmox's model list is one
      # static list for every architecture, so the dropdown that offered E1000
      # on x86 offers it here too, and because Parallels and Fusion on Apple
      # Silicon both present an emulated Intel adapter.
      #
      # `ena` is in the allowlist and is **not** a row here, and the distinction
      # matters: QEMU has no ENA device model, so there is nothing to boot
      # against. It is claimed on the strength of a Graviton instance reporting
      # an `ena` interface, which is an observation of the platform rather than
      # of this kernel — `docs/deployment.md` says so in the row.
      #
      # Port 11688 for the same reason the x86 twin uses it: `nix flake check`
      # runs checks in parallel and `linux-boot` already forwards 1688.
      armNicBootCheckFor = { system, arch }:
        let
          pkgs = pkgsFor system;
          configured = mkKmsrsos { inherit system; };
          linux = linuxFor { inherit system arch; };

          models = [
            "virtio-net-pci:virtio_net"
            "e1000:e1000"
            "e1000e:e1000e"
          ];
        in
        pkgs.runCommand "linux-nics"
          {
            nativeBuildInputs = [ pkgs.qemu_kvm ];
            meta.timeout = 1800;
          } ''
          set -euo pipefail
          mkdir -p $out

          cp ${pkgs.OVMF.variables} "$PWD/vars.fd"
          chmod +w "$PWD/vars.fd"

          firmware="-drive if=pflash,format=raw,unit=0,readonly=on,file=${pkgs.OVMF.firmware}"
          firmware="$firmware -drive if=pflash,format=raw,unit=1,file=$PWD/vars.fd"

          serves() {
            local model="''${1%%:*}"
            local driver="''${1##*:}"
            local serial="$PWD/$driver.log"

            ${arch.qemu} \
              -machine virt,gic-version=3 -cpu cortex-a57 \
              -smp 1 -m 512M -display none -no-reboot \
              -serial "file:$serial" \
              $firmware \
              -kernel ${linux.kernel}/${arch.image} \
              -netdev user,id=u1,hostfwd=tcp:127.0.0.1:11688-:1688 \
              -device "$model,netdev=u1,bus=pcie.0,id=net0" &
            local qemu=$!

            local attempt
            for attempt in $(seq 1 240); do
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
        os/linux/kernel.config.aarch64 is where it is missing from (OS-025, \
        #342; OS-032, #376)" >&2
            cat "$serial" >&2 || true
            return 1
          }

          ${builtins.concatStringsSep "\n          "
            (map (model: "serves ${model}") models)}

          # The other half of `OS-025` (#342), and the one a driver list can
          # never cover: a machine whose NIC has no driver at all must say so on
          # the console rather than reporting `listening` and going quiet.
          echo "checking that a machine with no interface says so"
          ${arch.qemu} \
            -machine virt,gic-version=3 -cpu cortex-a57 \
            -smp 1 -m 512M -display none -no-reboot \
            -serial "file:$PWD/no-nic.log" \
            $firmware \
            -kernel ${linux.kernel}/${arch.image} \
            -nic none &
          nonic=$!

          found=0
          for attempt in $(seq 1 120); do
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

      # `OS-033` (#377): the same count and the same two disk paths, on the
      # image that has no bootloader in it.
      #
      # A twin rather than a parameter for the reason the boot check is one:
      # what varies is not a firmware but everything a firmware implies. The x86
      # twin boots each disk on SeaBIOS *and* OVMF; here there is only AAVMF,
      # so the loop that halves is the interesting difference rather than a
      # detail to abstract over.
      #
      # The count is the point that carries across. It has gone 3 -> 2 -> 1 on
      # x86 across three issues, and the arm image is 1 from the start — but at
      # a *different offset*, because the one copy lives in the appended ESP
      # rather than in ISO9660. A regression to 2 would mean the ISO9660 tree
      # has grown a copy back, which is precisely the `OS-029` (#347) bug; 0
      # means the ESP lost its kernel and the image boots nothing.
      #
      # Three absences are asserted as well, and they are the whole of
      # `OS-033`'s claim that this image is *simpler* rather than differently
      # arranged. Asserted in the bytes rather than read off the recipe, for the
      # reason the count is: the comment in `default.nix` said "twice" for the
      # whole time it was three.
      armIsoLayoutCheckFor = { system, arch }:
        let
          pkgs = pkgsFor system;
          linux = linuxFor { inherit system arch; };
        in
        pkgs.runCommand "linux-iso-layout"
          {
            nativeBuildInputs = [ pkgs.python3 pkgs.qemu_kvm ];
            meta.timeout = 1800;
          } ''
          mkdir -p $out
          python3 - <<'PYTHON' | tee $out/report
          import pathlib
          iso = pathlib.Path("${linux.iso}").read_bytes()
          kernel = pathlib.Path("${linux.kernel}/${arch.image}").read_bytes()

          # A run from the middle of the kernel, long enough not to collide by
          # accident and far enough in to miss the PE headers, which also
          # appear in the El Torito boot catalogue's neighbourhood.
          needle = kernel[1_000_000:1_000_256]
          at, hits = 0, []
          while (i := iso.find(needle, at)) != -1:
              hits.append(i)
              at = i + 1

          print(f"ISO          {len(iso)} bytes")
          print(f"${arch.image}  {len(kernel)} bytes")
          print(f"copies       {len(hits)} at {[hex(h) for h in hits]}")

          assert len(hits) == 1, (
              f"the kernel appears {len(hits)} times in the arm image and should "
              "appear once, in the appended ESP, read there by firmware through "
              "the EFI stub (OS-033, #377). More than one means the ISO9660 tree "
              "has grown a copy back — which is the OS-029 (#347) bug — and zero "
              "means the ESP has lost its kernel and the image boots nothing"
          )

          # `OS-033` (#377): what this image does *not* contain. Each of these
          # is a thing the x86 image needs and this one has no firmware for.
          for marker, why in [
              (b"isolinux", "isolinux, which only a BIOS could run"),
              (b"ISOLINUX", "the same, as the loader stamps its own name"),
              (b"GRUB", "a bootloader; there is no second reader to share with"),
          ]:
              assert marker not in iso, (
                  f"the arm image contains {marker!r}: {why}. OS-033 (#377) is "
                  "the claim that this image is strictly simpler than the x86 "
                  "one, and that claim is asserted here rather than assumed"
              )

          # And no MBR boot code. `-isohybrid-mbr` splices x86 instructions into
          # the first 446 bytes; a protective MBR from `-appended_part_as_gpt`
          # leaves them zero. Anything else here is code no firmware on this
          # architecture can execute.
          assert iso[:446] == b"\0" * 446, (
              "the arm image has boot code in its MBR bootstrap area. Nothing "
              "on this architecture can execute it, and OS-033 (#377) removed "
              "the isohybrid MBR that puts it there"
          )
          # The GPT must still be there: it is what `OS-027` (#344)'s raw-disk
          # path is read through, and it is the half of the x86 recipe this
          # image keeps.
          assert iso[512:520] == b"EFI PART", (
              "the arm image has no GPT, so a hypervisor importing it as a disk "
              "finds no EFI System Partition (OS-027, #344)"
          )
          PYTHON

          # Booted as a **raw disk**, which is the path `OS-027` (#344) exists
          # for, and as a CD-ROM, which is what an operator attaches. The store
          # path is mode 444 and a writable `if=virtio` drive cannot open it,
          # hence the copy — a lesson from `OS-029` (#347), where a hand-run
          # qemu failing for that reason looked like a broken disk path for half
          # an hour.
          cp ${linux.iso} disk.img
          chmod +w disk.img

          boots() {
            local how="$1"
            local log="$PWD/$how.log"
            local media=""

            case "$how" in
              cdrom) media="-drive file=${linux.iso},media=cdrom,readonly=on" ;;
              disk)  media="-drive file=disk.img,format=raw,if=virtio" ;;
            esac

            cp ${pkgs.OVMF.variables} "$PWD/$how-vars.fd"
            chmod +w "$PWD/$how-vars.fd"

            ${arch.qemu} \
              -machine virt,gic-version=3 -cpu cortex-a57 \
              -smp 1 -m 512M -display none -no-reboot \
              -serial "file:$log" \
              -drive if=pflash,format=raw,unit=0,readonly=on,file=${pkgs.OVMF.firmware} \
              -drive if=pflash,format=raw,unit=1,file=$PWD/$how-vars.fd \
              $media \
              -nic none &
            local qemu=$!

            local attempt
            for attempt in $(seq 1 300); do
              grep -q '"event":"listening"' "$log" 2>/dev/null && break
              kill -0 $qemu 2>/dev/null || break
              sleep 1
            done
            kill $qemu 2>/dev/null || true
            wait $qemu 2>/dev/null || true
            cp "$log" $out/$how.log 2>/dev/null || true

            grep -q '"event":"listening"' $out/$how.log || {
              echo "the arm image does not boot as a $how under AAVMF. There is \
          no bootloader in it: firmware loads \\EFI\\BOOT\\${arch.efiFile} from \
          the ESP and runs the kernel through the EFI stub, so a failure here is \
          the ESP, El Torito or the GPT rather than a configuration file \
          (OS-033, #377)" >&2
              cat $out/$how.log >&2 || true
              exit 1
            }
            echo "boots as a $how under AAVMF"
          }

          # Both are asserted by reaching `listening`, not by the guest merely
          # starting: firmware that fails to find a boot option also "starts",
          # and sits at a shell.
          boots cdrom
          boots disk

          # `\EFI\BOOT\<file>` is the removable-media path, so no NVRAM entry is
          # written and none is needed. The variable store above is a fresh copy
          # of the template on every run and is thrown away, which is the same
          # thing as a Proxmox VM with no `efidisk0` — the question
          # `docs/deployment.md` cannot answer for arm until it is observed.
          echo "booted twice from a variable store that was new both times"
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

          # `(directory, expected IMAGE_FILE_MACHINE)` per architecture. The
          # second half is `PKG-020` (#379): a check that reads only the
          # artifact it already knew about passes for the whole time the other
          # one is unbuilt or wrong, which is the same failure `PKG-018` was
          # created by in a different place.
          targets = map
            (arch: {
              inherit (arch) name machine;
              path = self.packages.${system}."windows-${arch.name}";
            })
            (builtins.attrValues windowsArches);
        in
        pkgs.runCommand "windows-mitigations"
          { nativeBuildInputs = [ pkgs.python3 ]; } ''
          mkdir -p $out
          python3 - <<'PYTHON' | tee $out/report
          import pathlib, struct

          # Bit 0x4000 of DllCharacteristics: IMAGE_DLLCHARACTERISTICS_GUARD_CF.
          GUARD_CF = 0x4000
          # Offset of DllCharacteristics inside the optional header. The field
          # sits at the same place for PE32 and PE32+, because everything that
          # differs in size comes after it.
          DLL_CHARACTERISTICS = 70

          # `(architecture, directory, expected IMAGE_FILE_MACHINE)`.
          TARGETS = [
          ${builtins.concatStringsSep "\n          " (map
            (t: "    (\"${t.name}\", \"${t.path}/bin\", ${toString t.machine}),")
            targets)}
          ]
          assert TARGETS, "no Windows artifact is checked, so this asserts nothing"

          for arch, directory, machine in TARGETS:
              binaries = sorted(pathlib.Path(directory).glob("*.exe"))
              assert binaries, (
                  f"the {arch} Windows build produced no .exe, so this checks "
                  "nothing about it (PKG-020, #379)"
              )

              for path in binaries:
                  data = path.read_bytes()
                  pe = struct.unpack_from("<I", data, 0x3C)[0]
                  assert data[pe:pe + 4] == b"PE\0\0", f"{path.name} is not a PE file"

                  # Read *before* anything else, because it is what makes every
                  # statement below a statement about the right file. The
                  # machine type is two bytes after the signature.
                  found = struct.unpack_from("<H", data, pe + 4)[0]
                  assert found == machine, (
                      f"{arch}/{path.name} reports machine 0x{found:04x} and "
                      f"should report 0x{machine:04x}. Every other assertion "
                      "here would still have passed, about the wrong binary "
                      "(PKG-020, #379)"
                  )

                  flags = struct.unpack_from("<H", data, pe + 24 + DLL_CHARACTERISTICS)[0]
                  guarded = bool(flags & GUARD_CF)
                  print(
                      f"{arch:8} {path.name:20} machine=0x{found:04x} "
                      f"DllCharacteristics=0x{flags:04x} GUARD_CF={guarded}"
                  )
                  assert not guarded, (
                      f"{arch}/{path.name} was built with Control Flow Guard. "
                      "On this toolchain that produces a binary that dies at "
                      "startup with 0xC0000409 / "
                      "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE before it logs "
                      "anything, which is strictly worse than the mitigation "
                      "is worth (PKG-018). If this is being re-enabled, run the "
                      "artifact on a Windows guest first - harness/windows/ "
                      "exists for that and is how this was found"
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

          # Cross-compiled Windows binaries, one attribute per architecture:
          # `nix build .#windows-x86_64`, `nix build .#windows-aarch64`.
          #
          # There is deliberately **no bare `.#windows`** (`PKG-020`, #379). It
          # used to mean "the x86_64 one", which is the kind of default that is
          # right until the day it is silently wrong — and a release artifact
          # named after a default is one nobody can tell apart from the other.
          # Both are named; neither is the Windows build.
        }
        // builtins.listToAttrs (map
          (arch: {
            name = "windows-${arch.name}";
            value = craneLib.buildPackage
              ((windowsArgsFor { inherit system arch; }) // stampEnv // {
                cargoArtifacts = windowsCargoArtifactsFor { inherit system arch; };
              });
          })
          (builtins.attrValues windowsArches))
        // {
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
            variants = linuxDeltaVariants.${linuxArch.name};
          };
          # The bootable image. Two recipes, one attribute: `OS-033` (#377)
          # gives the architecture with no BIOS an image with no bootloader,
          # because there is no second firmware for it to share a kernel with.
          linuxIso = (linuxFor { inherit system; arch = linuxArch; }).iso;
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

          # `PKG-018`: Control Flow Guard is **absent** from the shipped
          # Windows binaries, and each artifact is the architecture it claims
          # to be (`PKG-020`, #379).
          #
          # Not in the x86-only group below, and it was there by accident
          # rather than by argument: it was grouped with the checks that boot a
          # kernel built with `pkgs.syslinux`, and it has nothing to do with
          # either. The Windows binaries cross-compile from any Linux, so this
          # runs wherever the flake does — which is also the only way the
          # aarch64 leg of CI checks the artifact it builds.
          windows-mitigations = windowsMitigationsCheckFor system;
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
          # with no `--args`. Two firmwares on x86; one on aarch64, because
          # there is only one (`OS-032`, #376).
          #
          # Selected by name rather than by a feature flag, and deliberately
          # with no fallback: a new architecture must decide which boot check
          # is right for it, and the failure for one that has not is an
          # evaluation error naming it rather than a check that quietly runs
          # the wrong machine's topology.
          linux-boot =
            {
              x86_64 = linuxBootCheckFor;
              aarch64 = armBootCheckFor;
            }.${linuxArch.name} {
              inherit system;
              arch = linuxArch;
            };

          # `OS-025` (#342): one boot per supported NIC model, each asserting
          # that the machine *serves* — plus the machine with no NIC at all,
          # which must say so rather than reporting `listening` and going quiet.
          linux-nics =
            {
              x86_64 = nicBootCheckFor;
              aarch64 = armNicBootCheckFor;
            }.${linuxArch.name} {
              inherit system;
              arch = linuxArch;
            };

          # `PKG-023` (#395): the shipped binaries are statically linked, read
          # off the binaries.
          #
          # `docs/releasing.md` claims this of both architectures and until this
          # check nothing read an artifact to establish it — the claim rested on
          # two greps over `flake.nix` and `rust-toolchain.toml`, one of which
          # names `x86_64-unknown-linux-musl` literally, so the aarch64 leg
          # `PKG-019` (#378) added was asserted nowhere at all.
          #
          # A check rather than a test, because a Rust test cannot see the
          # artifact: `packaging_invariants.rs` reads source files out of the
          # workspace, and what has to be inspected here is the output of a
          # build. `ci/static-binaries.sh` is shared with `release.yml`, which
          # runs it over the files it is about to upload — the `PKG-022` (#385)
          # rule that the artifact under test is the one an operator downloads.
          static-binaries =
            let
              pkgs = pkgsFor system;
              inherit (mkKmsrsos { inherit system; }) server client;
            in
            pkgs.runCommand "static-binaries"
              { nativeBuildInputs = [ pkgs.binutils ]; } ''
              bash ${./ci/static-binaries.sh} '${linuxArch.elfMachine}' \
                ${server}/bin/kmsrs-server \
                ${client}/bin/kmsrs-client
              touch $out
            '';

          # `PKG-016` (#366): two builds of the ISO are the same bytes.
          reproducible-iso = reproducibleIsoCheckFor {
            inherit system;
            arch = linuxArch;
          };

          # `OS-030` (#348): the kernel is in the image exactly once, counted
          # in the bytes, and the image boots as a raw disk on every firmware
          # the architecture has.
          linux-iso-layout =
            {
              x86_64 = isoLayoutCheckFor;
              aarch64 = armIsoLayoutCheckFor;
            }.${linuxArch.name} {
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

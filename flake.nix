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

  outputs = { self, nixpkgs, systems, rust-overlay, crane, nix-direnv, ... }:
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

      # `cleanCargoSource` keeps only Rust and Cargo files, which would drop the
      # generated product data that `kmsrs-db`'s build.rs compiles into static
      # tables (DB-003, #127), the committed golden wire vectors (TEST-002,
      # #223) and the committed fuzz seeds (TEST-006, #227). All three are
      # inputs to the build — the seeds because `kmsrs-vectors`' replay test
      # reads them from disk — so all three have to survive the filter.
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
            || (builtins.match ".*/fuzz/seeds(/.*)?" path != null);
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
        in
        rec {
          inherit server client;
          container = containerFor { inherit pkgs system server client; };
          # `osImage` and `hermit` join this set once PKG-013 (#250) has a
          # hermetic Hermit build. Named here rather than stubbed, because an
          # output that exists and does not work is worse than one that does
          # not exist.
        };

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

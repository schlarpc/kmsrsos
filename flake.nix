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

    in
    {
      packages = eachSystem (system:
        let
          craneLib = cranelibFor system;
          commonArgs = commonArgsFor system;
          cargoArtifacts = cargoArtifactsFor system;
        in
        {
          default = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            doCheck = false;
          });

          kmsrsos = self.packages.${system}.default;

          # Cross-compiled Windows binaries: `nix build .#windows`
          windows = craneLib.buildPackage ((windowsArgsFor system) // {
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

          coverage = craneLib.cargoLlvmCov (commonArgs // {
            inherit cargoArtifacts;
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
            ];

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
        inherit nix-direnv;
      };
    };
}

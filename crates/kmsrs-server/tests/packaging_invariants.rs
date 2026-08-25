//! Properties of what ships, checked as tests (`PKG-004`, #241;
//! `PKG-005`, #242; `PKG-006`, #243; `PKG-011`, #248; `SEC-008`, #200).
//!
//! Every one of these is a defect the audits found in a real project, and every
//! one of them is invisible until somebody deploys the result:
//!
//! * Upstream py-kms's Dockerfiles `git clone` GitHub master rather than
//!   copying the build context, so `docker build` produces whatever upstream
//!   happened to be that morning and silently ignores local changes.
//! * edgd1er's fork replaced pinned pip requirements with apk version *floors*,
//!   which made builds non-reproducible and shipped a linter inside the runtime
//!   image.
//! * The Organization fork's Helm chart exposes `replicaCount` as a top-level
//!   value, and raising it gives every pod its own ePID — the canonical
//!   emulator detection test, reintroduced by a config value.
//!
//! None of the three is a bug in a line of code, which is why none of them is
//! caught by a test of a line of code. They are properties of the packaging,
//! so they are asserted against the packaging files.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed invariant should abort the test loudly"
)]

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<name> is always two levels below the workspace root")
        .to_path_buf()
}

fn read(root: &Path, relative: &str) -> String {
    let path = root.join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// `PKG-005` (#242): the image is built from the local tree and nothing else.
///
/// Structural rather than enforced. `dockerTools.buildLayeredImage` takes store
/// paths, so there is no build context to `COPY`, no `RUN` to execute a
/// `git clone` in, and no network at image-build time at all — the image is a
/// pure function of the flake inputs, which `flake.lock` pins exactly.
///
/// This test is what stops somebody reintroducing a Dockerfile "just for local
/// development", which is how the property is lost: once one exists, it is what
/// people build.
#[test]
fn no_dockerfile_exists_and_the_image_comes_from_the_flake() {
    let root = workspace_root();

    for name in [
        "Dockerfile",
        "Containerfile",
        "docker/Dockerfile",
        "deploy/Dockerfile",
    ] {
        assert!(
            !root.join(name).exists(),
            "{name} exists. The container image is built by dockerTools from \
             store paths, which is what makes it impossible for the build to \
             reach the network (PKG-005, #242)."
        );
    }

    let flake = read(&root, "flake.nix");
    assert!(
        flake.contains("dockerTools.buildLayeredImage"),
        "the container image is no longer built by dockerTools"
    );
    // The image's contents are the packages this flake built, not something
    // fetched. A fetcher naming our own source would be the `git clone`
    // upstream py-kms performs, spelled in Nix.
    assert!(
        flake.contains("contents = [ server client ]"),
        "the image contents are no longer the locally built binaries"
    );
    for fetcher in [
        "fetchFromGitHub",
        "fetchgit",
        "fetchTarball",
        "builtins.fetchurl",
    ] {
        assert!(
            !flake.contains(fetcher),
            "flake.nix uses {fetcher}; every input belongs in `inputs`, where \
             flake.lock pins it (PKG-006, #243)"
        );
    }
}

/// `PKG-006` (#243): every dependency is pinned exactly, with no floors.
///
/// A floor-versioned dependency makes two builds of one revision different
/// programs, which is the thing `SEC-010` (#202) is about and the thing
/// edgd1er's fork lost by moving from pinned pip to apk floors.
///
/// Cargo's default `"1.2"` *is* a floor — it means `>=1.2, <2` — so the check
/// is that every version requirement starts with `=`.
#[test]
fn every_dependency_is_pinned_to_an_exact_version() {
    let root = workspace_root();
    let manifest: toml::Table =
        toml::from_str(&read(&root, "Cargo.toml")).expect("the workspace manifest parses");

    let dependencies = manifest["workspace"]["dependencies"]
        .as_table()
        .expect("the workspace declares dependencies");

    let mut floating = Vec::new();
    for (name, value) in dependencies {
        // A path dependency is this workspace's own code and has no version to
        // float.
        let version = match value {
            toml::Value::String(version) => Some(version.as_str()),
            toml::Value::Table(table) => {
                if table.contains_key("path") {
                    continue;
                }
                table.get("version").and_then(toml::Value::as_str)
            }
            _ => None,
        };

        match version {
            Some(version) if version.starts_with('=') => {}
            Some(version) => floating.push(format!("{name} = {version}")),
            None => floating.push(format!("{name} declares no version")),
        }
    }

    assert!(
        floating.is_empty(),
        "these dependencies are not pinned to an exact version, so two builds \
         of one revision can be different programs (PKG-006, #243): \
         {floating:#?}"
    );
    assert!(
        dependencies.len() > 5,
        "this test is not looking at the dependency table"
    );

    // And the lockfile pins the Nix side the same way: every flake input is
    // recorded with a `narHash` and a revision, so `nix build` at this revision
    // resolves to the same nixpkgs it did today.
    let lock = read(&root, "flake.lock");
    assert!(
        lock.contains("\"narHash\""),
        "flake.lock does not pin its inputs by hash"
    );
    assert!(
        lock.contains("\"rev\""),
        "flake.lock does not pin its inputs by revision"
    );
}

/// `PKG-011` (#248): `replicas: 1`, hardcoded, with no template over it.
///
/// The number is not a tuning parameter. Every replica draws its own ePID
/// (`ID-001`, #106), so a client that reaches pod A and then pod B is told two
/// different host identities by one host name — MM01, the canonical detection
/// test, arriving through a config value rather than through the code.
#[test]
fn the_kubernetes_manifests_pin_one_replica_and_are_not_a_helm_chart() {
    let root = workspace_root();
    let full = read(&root, "deploy/kubernetes/kmsrsos.yaml");
    // Comments are stripped for the "must not appear" checks: the header
    // explains at length why `replicaCount` must not exist, and a test that
    // matched its own rationale would be unwritable.
    let manifest: String = full
        .lines()
        .map(|line| match line.find('#') {
            Some(at) => line.split_at(at).0,
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        manifest.contains("replicas: 1"),
        "the deployment does not pin one replica"
    );
    assert!(
        !manifest.contains("replicaCount"),
        "`replicaCount` appears, which is the Helm value that must not exist \
         (declined item D17)"
    );
    // Go template syntax anywhere means this became a chart.
    assert!(
        !manifest.contains("{{"),
        "the manifest contains template syntax, so it is a chart now"
    );
    // A rolling update runs two pods at once, which is the same two-ePID
    // problem for the length of the rollout.
    assert!(
        manifest.contains("type: Recreate"),
        "the update strategy is not Recreate, so a rollout runs two ePIDs"
    );

    for chart_file in [
        "deploy/kubernetes/Chart.yaml",
        "deploy/kubernetes/values.yaml",
        "chart/Chart.yaml",
        "Chart.yaml",
    ] {
        assert!(
            !root.join(chart_file).exists(),
            "{chart_file} exists; Helm is declined as D17"
        );
    }

    // `SEC-008` (#200): the probes ask about the KMS side, not about whether
    // the HTTP handler ran.
    assert!(manifest.contains("path: /healthz"), "no health probe");
    assert!(
        manifest.contains("readOnlyRootFilesystem: true"),
        "the root filesystem is writable, and nothing here writes"
    );
    assert!(
        manifest.contains("runAsNonRoot: true"),
        "the pod may run as root"
    );
    assert!(
        manifest.contains("drop: [\"ALL\"]"),
        "capabilities are not dropped"
    );
}

/// `PKG-004` (#241) and `SEC-008` (#200): the image is two static binaries and
/// says so in its own config.
///
/// Checked against `flake.nix` rather than against a built image, because
/// building one takes minutes and the properties that get lost are all
/// properties of the expression: somebody adds `pkgs.bash` to `contents` for a
/// debugging session, or drops `User` while chasing a permissions problem.
#[test]
fn the_container_image_is_non_root_static_and_probes_the_kms_port() {
    let root = workspace_root();
    let flake = read(&root, "flake.nix");
    let toolchain = read(&root, "rust-toolchain.toml");

    assert!(
        toolchain.contains("x86_64-unknown-linux-musl"),
        "the static target is gone, so the image would carry a libc closure"
    );
    assert!(
        flake.contains("crt-static"),
        "the static link is no longer stated, so a toolchain default change \
         would quietly produce a dynamically linked image"
    );

    assert!(
        flake.contains("User = \"65534:65534\""),
        "the image no longer runs as a non-root numeric user (SEC-008, #200)"
    );
    assert!(
        flake.contains("\"1688/tcp\"") && flake.contains("\"8080/tcp\""),
        "the image does not declare both ports"
    );

    // The health check probes the **KMS port**, by doing what a client does.
    // Probing the HTTP handler would prove the one fact the caller already had
    // by getting a reply, which is the Organization fork's `readyz` mistake.
    assert!(
        flake.contains("Healthcheck"),
        "the image has no health check"
    );
    assert!(
        flake.contains("--healthcheck") && flake.contains("127.0.0.1:1688"),
        "the health check does not probe the KMS port (SEC-008, #200)"
    );

    // Nothing that is a shell, and nothing that could run one.
    for forbidden in [
        "pkgs.bash",
        "pkgs.busybox",
        "pkgs.coreutils",
        "binSh",
        "pkgs.dockerTools.usrBinEnv",
    ] {
        assert!(
            !flake.contains(forbidden),
            "{forbidden} is in the flake; the image's claim is that it holds \
             two files (PKG-004, #241)"
        );
    }
}

/// `PKG-003` (#240), `PKG-009` (#246) and `SEC-010` (#202): a tag produces
/// every artifact, and produces it the way a developer would.
///
/// The property that matters is that there is **no release-only build path**.
/// A release built differently from the thing that was tested is a release
/// nobody tested, and the way that happens is one `cargo build --release` in a
/// workflow that nothing else runs.
#[test]
fn the_release_workflow_builds_what_the_gate_checks() {
    let root = workspace_root();
    let workflow = read(&root, ".github/workflows/release.yml");

    // Every artifact `PKG-003` (#240) names.
    for output in [
        ".#server",
        ".#client",
        ".#deb",
        ".#rpm",
        ".#container",
        ".#windows",
        // The bootable bare-metal ISO (`OS-017`, #333). x86_64 only — the
        // flake gates it by system, because `pkgs.syslinux` is unavailable
        // elsewhere — and built on the leg that is already x86_64 rather than
        // in a job of its own.
        //
        // This said `.#osImage` and `.#osIso` until `OS-029` (#347). Those
        // were the Hermit artifacts, removed by `OS-018` (#334); the workflow
        // still named them too, so this assertion passed while describing a
        // release that could not have run. Two stale statements agreeing with
        // each other is the failure mode a test like this is supposed to
        // prevent, so it is worth the comment.
        ".#linuxIso",
    ] {
        assert!(
            workflow.contains(output),
            "the release does not build {output} (PKG-003, #240)"
        );
    }

    // And nothing bypasses the flake. A `cargo build` here would be a second
    // build path, which is the whole thing this test is about.
    for bypass in ["cargo build --release", "cargo install", "docker build"] {
        assert!(
            !workflow.contains(bypass),
            "the release workflow uses {bypass}, which is a build path nothing \
             else exercises"
        );
    }

    // `SEC-010` (#202): an SBOM, checksums, a signature, and a rebuild.
    assert!(workflow.contains("cyclonedx"), "no SBOM is produced");
    assert!(workflow.contains("sha256sum"), "no checksums are produced");
    assert!(workflow.contains("cosign sign-blob"), "nothing is signed");
    assert!(
        workflow.contains("--rebuild"),
        "the release does not prove its own build is reproducible"
    );

    // Keyless signing: there is no private key anywhere, which is the only way
    // to sign from CI without the artifact SEC-013 (#205) says does not exist.
    assert!(
        !workflow.contains("--key ") && !workflow.contains("COSIGN_PRIVATE_KEY"),
        "the release signs with a key, and this project has no secrets"
    );

    // The gate runs on the exact revision being released. A tag pushed without
    // its branch having been merged is a tag nothing has checked.
    assert!(
        workflow.contains("nix flake check"),
        "the release does not re-run the gate"
    );
}

/// `PKG-012` (#249): the release template exists, and its first section is the
/// one nothing else in this ecosystem has.
///
/// The Organization fork changed a flag's arity, a path's meaning, its schema
/// keys and its default bind address in one release with no note, and three
/// downstream forks each rediscovered a different subset by running into it.
/// A template whose protocol-visible section is optional would not have helped
/// any of them.
#[test]
fn the_release_notes_template_leads_with_protocol_visible_changes() {
    let root = workspace_root();
    let releasing = read(&root, "docs/releasing.md");

    assert!(
        releasing.contains("## Protocol-visible changes"),
        "the template has no protocol-visible section"
    );
    assert!(
        releasing.contains("never omitted"),
        "the protocol-visible section is not stated to be mandatory"
    );
    // It comes first, because a section at the bottom is a section nobody
    // fills in.
    let protocol = releasing
        .find("## Protocol-visible changes")
        .expect("the section exists");
    for later in ["## Operator-visible changes", "## Build-time settings"] {
        let at = releasing.find(later).unwrap_or(usize::MAX);
        assert!(at > protocol, "{later} comes before the protocol section");
    }
}

/// The OS packages carry the unit and the guide, not just a binary.
///
/// Both audited projects ship a documentation snippet for systemd and nothing
/// else, and py-kms's is `User=root` with no hardening whatever. A package that
/// installed a binary and left the operator to write their own unit would be
/// the same gap with extra steps.
#[test]
fn the_os_packages_carry_the_unit_and_the_guide() {
    let root = workspace_root();
    let full = read(&root, "flake.nix");
    // Comments stripped for the "must not appear" checks below: the payload's
    // own comment explains at length why there is no postinst.
    let flake: String = full
        .lines()
        .map(|line| match line.find('#') {
            Some(at) => line.split_at(at).0,
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");

    for path in ["deploy/systemd/kmsrsos.service", "docs/deployment.md"] {
        assert!(
            flake.contains(path),
            "the OS packages do not install {path} (PKG-009, #246)"
        );
    }

    // One payload for both, so `.deb` and `.rpm` cannot disagree about what
    // "installed" means.
    assert_eq!(
        flake.matches("packagePayload {").count(),
        2,
        "the two packages no longer share one payload definition"
    );

    // No postinst, no service-user creation, no `systemctl enable`. DynamicUser
    // means there is no account to create, and a package that enabled a service
    // nobody asked for would be making a decision that is the operator's.
    for script in ["postinst", "%post", "systemctl enable", "useradd"] {
        assert!(
            !flake.contains(script),
            "the packages run {script}, which they have nothing to do"
        );
    }
}

/// `PKG-007` (#244): the unit is hardened, and there is no socket unit
/// (declined item D40).
#[test]
fn the_systemd_unit_is_hardened_and_stands_alone() {
    let root = workspace_root();
    let full = read(&root, "deploy/systemd/kmsrsos.service");
    // Comments stripped for the "must not appear" checks: the header explains
    // why CAP_NET_BIND_SERVICE is not needed, and a test that matched its own
    // rationale would be unwritable.
    let unit: String = full
        .lines()
        .map(|line| match line.find('#') {
            Some(at) => line.split_at(at).0,
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Every one of these is free rather than aspirational: it forbids something
    // the program genuinely does not do.
    for setting in [
        "DynamicUser=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "NoNewPrivileges=yes",
        "SystemCallFilter=@system-service",
        "RestrictAddressFamilies=AF_INET AF_INET6",
        "MemoryDenyWriteExecute=yes",
    ] {
        assert!(unit.contains(setting), "the unit does not set {setting}");
    }

    // `SEC-007` (#199), declined as D41: no capabilities at all, rather than
    // capabilities that are dropped. 1688 is unprivileged, so there is nothing
    // to bind that would have needed one.
    assert!(
        unit.contains("CapabilityBoundingSet=\n") || unit.contains("CapabilityBoundingSet=\r\n"),
        "the capability bounding set is not empty"
    );
    assert!(
        unit.contains("AmbientCapabilities=\n") || unit.contains("AmbientCapabilities=\r\n"),
        "ambient capabilities are not empty"
    );
    assert!(
        !unit.contains("CAP_NET_BIND_SERVICE"),
        "the unit grants a capability for a port that does not need one"
    );

    // `NET-016` (#165), declined as D40.
    assert!(
        !root.join("deploy/systemd/kmsrsos.socket").exists(),
        "a .socket unit exists, and this build refuses to start with LISTEN_FDS \
         set (declined item D40)"
    );
}

/// `CFG-003` (#168): the rebuild path is a function, and it takes exactly the
/// settings that cannot be changed at runtime.
///
/// The doctrine is "rebuild from the flake" rather than "set an environment
/// variable" (decision 13), and a doctrine nobody can follow in two lines is a
/// doctrine nobody follows.
#[test]
fn the_rebuild_path_is_a_function_over_the_build_time_settings() {
    let root = workspace_root();
    let flake = read(&root, "flake.nix");

    assert!(flake.contains("mkKmsrsos ="), "mkKmsrsos is gone");
    assert!(
        flake.contains("inherit nix-direnv mkKmsrsos defaultSettings;"),
        "mkKmsrsos is not exported from `lib`, so nobody outside can call it"
    );

    // Every setting it accepts must be one the runtime cannot change. These
    // four are the whole list — see declined item D37 for why it is not thirty
    // macros and seven presets.
    for setting in [
        "activationInterval",
        "renewalInterval",
        "permissiveRetail",
        "strictClockSkew",
    ] {
        assert!(
            flake.contains(setting),
            "{setting} is not a build-time setting of mkKmsrsos"
        );
    }

    // And they reach the compiler the way `CFG-004` (#169) requires: through
    // `option_env!`, so a bad value is a compile error rather than a start-up
    // failure.
    let compiled = read(&root, "crates/kmsrs-server/src/config/compiled.rs");
    for variable in ["KMSRSOS_ACTIVATION_INTERVAL", "KMSRSOS_RENEWAL_INTERVAL"] {
        assert!(
            flake.contains(variable),
            "{variable} is not set by the flake"
        );
        assert!(
            compiled.contains(&format!("option_env!(\"{variable}\")")),
            "{variable} does not reach the build as a compile-time constant"
        );
    }
}

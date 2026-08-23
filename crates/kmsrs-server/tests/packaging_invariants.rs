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

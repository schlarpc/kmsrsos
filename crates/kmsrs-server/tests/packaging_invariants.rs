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
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    // Line endings are a property of the checkout, not of the file. A Windows
    // runner with `core.autocrlf` produces `\r\n`, which makes every
    // structural search below miss — and the failure reads as "the workflow
    // moved" rather than as "this test is Unix-only". `command_line.rs` does
    // the same for the same reason.
    text.replace("\r\n", "\n")
}

/// Every job in the gate, by name.
///
/// A two-space-indented `name:` under `jobs:`. Structural rather than a parsed
/// document because this workspace has no YAML dependency and adding one to
/// read two lists would be a strange thing to pay for — but structural enough
/// that adding a job cannot slip past it, which is the whole point.
fn workflow_jobs(workflow: &str) -> Vec<String> {
    let mut inside_jobs = false;
    let mut jobs = Vec::new();

    for line in workflow.lines() {
        if line.starts_with("jobs:") {
            inside_jobs = true;
            continue;
        }
        // A top-level key ends the `jobs:` mapping.
        if inside_jobs && !line.starts_with(' ') && !line.trim().is_empty() {
            break;
        }
        if !inside_jobs {
            continue;
        }
        let Some(rest) = line.strip_prefix("  ") else {
            continue;
        };
        if rest.starts_with(' ') || rest.starts_with('#') {
            continue;
        }
        if let Some(name) = rest.strip_suffix(':')
            && !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            jobs.push(name.to_owned());
        }
    }
    jobs
}

/// The `needs:` list of one job.
fn job_needs(workflow: &str, job: &str) -> Vec<String> {
    let mut lines = workflow
        .lines()
        .skip_while(|line| *line != format!("  {job}:"));
    let mut needs = Vec::new();
    let mut inside_needs = false;

    for line in lines.by_ref().skip(1) {
        // The next job ends this one.
        if line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':') {
            break;
        }
        if line.trim() == "needs:" {
            inside_needs = true;
            continue;
        }
        if inside_needs {
            match line.trim().strip_prefix("- ") {
                Some(name) => needs.push(name.trim().to_owned()),
                None => inside_needs = false,
            }
        }
    }
    needs
}

/// **`PKG-015` (#364): "all green" means *all*.**
///
/// The `latest` job moves a pointer that people download from, so it must wait
/// for every other job in the gate. Actions has no way to say "everything" —
/// `needs` is a list of names — so a job added later and not added to that list
/// would leave the pointer moving on a build that job had failed.
///
/// That failure is silent and the artifact looks blessed, which is worse than
/// having no pointer at all. So the two lists are compared here rather than
/// trusted to stay in step.
#[test]
fn the_latest_pointer_waits_for_every_job() {
    let root = workspace_root();
    let workflow = read(&root, ".github/workflows/test.yml");

    let jobs = workflow_jobs(&workflow);
    assert!(
        jobs.len() >= 5,
        "only found {jobs:?} in test.yml, so this test is not reading the \
         workflow it thinks it is"
    );
    assert!(
        jobs.iter().any(|job| job == "latest"),
        "test.yml has no `latest` job, so nothing moves the pointer: {jobs:?}"
    );

    let needs = job_needs(&workflow, "latest");
    assert!(
        !needs.is_empty(),
        "the `latest` job needs nothing, so it runs whatever else happened"
    );

    let missing: Vec<&String> = jobs
        .iter()
        .filter(|job| *job != "latest" && !needs.contains(job))
        .collect();
    assert!(
        missing.is_empty(),
        "the `latest` job does not wait for {missing:?}. It moves a pointer \
         people download from, so every job in the gate has to be in its \
         `needs` list — otherwise the pointer moves on a build one of them \
         failed, silently, and the artifact looks blessed (PKG-015, #364)"
    );

    // And the reverse: a name in `needs` that is not a job is a typo Actions
    // reports as a skipped workflow rather than an error, which is the same
    // failure wearing a different hat.
    let unknown: Vec<&String> = needs.iter().filter(|need| !jobs.contains(need)).collect();
    assert!(
        unknown.is_empty(),
        "the `latest` job waits for {unknown:?}, which are not jobs in this \
         workflow"
    );
}

/// `PKG-015` (#364): a pull request cannot move the pointer.
///
/// The artifacts are built on every run, including from forks, and that is
/// deliberate — a workflow artifact on a pull request is how somebody boots the
/// change before it merges. Publishing one is a different thing, and a fork's
/// branch must not be able to do it.
#[test]
fn only_a_push_to_main_moves_the_pointer() {
    let root = workspace_root();
    let workflow = read(&root, ".github/workflows/test.yml");

    let start = workflow
        .find("\n  latest:\n")
        .expect("test.yml has a `latest` job");
    let job = &workflow[start..];

    assert!(
        job.contains("github.event_name == 'push'"),
        "the `latest` job is not gated to a push, so a pull request would move \
         the pointer"
    );
    assert!(
        job.contains("github.ref == 'refs/heads/main'"),
        "the `latest` job is not gated to main, so any branch would move the \
         pointer"
    );
}

/// `PKG-015` (#364): the snapshot is built by the flake, like everything else.
///
/// The same assertion `the_release_workflow_builds_what_the_gate_checks` makes
/// about a tag, for the same reason: an artifact built by a path nothing else
/// exercises is an artifact nothing has tested. A snapshot is downloaded and
/// booted, so it earns the same rule.
#[test]
fn the_snapshot_is_built_by_the_flake() {
    let root = workspace_root();
    let workflow = read(&root, ".github/workflows/test.yml");

    for output in [".#linuxIso", ".#windows-x86_64", ".#windows-aarch64"] {
        assert!(
            workflow.contains(output),
            "the snapshot does not build {output} (PKG-015, #364; PKG-020, \
             #379)"
        );
    }

    // `PKG-021` (#384): **both** ISOs reach the snapshot, each built on its own
    // architecture's runner.
    //
    // The same assertion `the_release_workflow_builds_what_the_gate_checks`
    // makes about a tag, and it is here because the two channels drifted: a tag
    // has produced both images since `PKG-019` (#378) and this one produced the
    // x86 image alone for two issues after that. It matters more here than it
    // sounds, because this is the channel whose entire purpose is booting a
    // change before it is tagged — and an operator on arm64 could not.
    let iso = "kmsrsos-${{ matrix.arch }}.iso";
    assert!(
        workflow.contains(iso),
        "the snapshot does not name its ISO {iso}, so either it ships one \
         image under a name that claims to be both or it ships one \
         architecture (PKG-021, #384)"
    );
    for (arch, runner) in [("x86_64", "ubuntu-latest"), ("aarch64", "ubuntu-24.04-arm")] {
        let leg = format!("- arch: {arch}\n            runner: {runner}");
        assert!(
            workflow.contains(&leg),
            "the snapshot has no {arch} leg on {runner}. Each image is built \
             natively, with no snapshot-only build path (PKG-021, #384)"
        );
    }
    // And the x86-only name is gone rather than merely joined by a second one.
    // A leftover `out/kmsrsos-x86_64.iso` would ship the arm leg's image under
    // the x86 name and every assertion above would still pass.
    assert!(
        !workflow.contains("out/kmsrsos-x86_64.iso"),
        "the snapshot still hard-codes the x86_64 ISO name, which on the arm \
         leg would name the wrong image (PKG-021, #384)"
    );
    for bypass in [
        "cargo build --release",
        "cargo install --path",
        "docker build",
    ] {
        assert!(
            !workflow.contains(bypass),
            "test.yml uses {bypass}, which is a build path nothing else \
             exercises"
        );
    }
    // Checksums are produced beside the build rather than centrally, so they
    // are a statement by the machine that made the bytes (`SEC-010`, #202).
    // One file per leg since `PKG-021` (#384), because there is more than one
    // machine now.
    assert!(
        workflow.contains(r#"sha256sum * > "SHA256SUMS-${{ matrix.arch }}""#),
        "the snapshot legs carry no per-leg checksums (PKG-021, #384)"
    );
    // Merged after the round trip through the artifact store and before the
    // signature, which is the only place it can go: the signature is over one
    // file, and what it has to attest is what came back out of the store.
    // Character for character what `release.yml`'s `publish` job does.
    assert!(
        workflow.contains("sha256sum -c SHA256SUMS-* && sha256sum * > SHA256SUMS"),
        "the snapshot legs' checksums are not verified after the artifact \
         round trip and merged into the one file that gets signed (PKG-021, \
         #384)"
    );
    // By pattern, never by "everything": `no-file-access` uploads `strace.log`
    // on every run and `fuzz` uploads reproducers, and publishing either under
    // a stable download URL is not something to discover after the fact.
    assert!(
        workflow.contains("pattern: snapshot-*"),
        "the `latest` job does not select the snapshot artifacts by pattern, \
         so it either misses a leg or publishes artifacts that are not \
         snapshots (PKG-021, #384)"
    );
    assert!(
        workflow.contains("cosign sign-blob"),
        "the snapshot checksums are not signed, so a downloaded ISO cannot be \
         verified at all"
    );
}

/// **`PKG-017` (#368): the server executable is `kmsrs-server`.**
///
/// `kmsrsos` is the project and the bare-metal image it produces. It was also
/// the name of this binary, which made one word mean three things — and the one
/// it fitted worst was the executable, a plain Linux and Windows service with
/// no OS in it.
///
/// Asserted rather than left to the manifest, because a rename like this leaks:
/// every path that installs, launches or documents the binary has to move with
/// it, and the ones that do not fail at deploy time rather than at build time.
/// A `.deb` that installs `/usr/bin/kmsrs-server` under a unit whose
/// `ExecStart` still says `/usr/local/bin/kmsrsos` builds perfectly.
#[test]
fn the_server_executable_is_named_kmsrs_server() {
    let root = workspace_root();

    let manifest = read(&root, "crates/kmsrs-server/Cargo.toml");
    assert!(
        manifest.contains("name = \"kmsrs-server\""),
        "kmsrs-server's [[bin]] is not called kmsrs-server"
    );

    // Every place that installs or launches it.
    let flake = read(&root, "flake.nix");
    for expected in [
        "${server}/bin/kmsrs-server",
        "payload/usr/bin/kmsrs-server",
        "Entrypoint = [ \"/bin/kmsrs-server\" ]",
        "/usr/lib/systemd/system/kmsrs-server.service",
    ] {
        assert!(
            flake.contains(expected),
            "flake.nix does not install or launch the binary as {expected:?}"
        );
    }

    let unit = read(&root, "deploy/systemd/kmsrs-server.service");
    assert!(
        unit.contains("ExecStart=/usr/local/bin/kmsrs-server"),
        "the unit launches something other than kmsrs-server"
    );

    // And nothing anywhere still installs, launches or copies an executable by
    // the old name. Deliberately a search for the *paths*, not for the word:
    // `kmsrsos` is still correct for the project, the container image, the ISO
    // and the metric namespace, and a test that banned the string outright
    // would be asserting something false.
    //
    // The list of files is **walked**, not enumerated. The first version of
    // this test named six files and missed `ci/no-file-access.sh`, which runs
    // the built binary under strace — so the rename it exists to police leaked
    // straight past it and failed in CI. A test that has to be told where to
    // look is a test that finds what somebody already thought of.
    for (relative, text) in shipped_text_files(&root) {
        let file = relative.as_str();
        for stale in [
            "bin/kmsrsos",
            "/usr/bin/kmsrsos",
            "kmsrsos.exe",
            "kmsrsos.service",
            "enable --now kmsrsos",
            "journalctl -u kmsrsos",
        ] {
            assert!(
                !text.contains(stale),
                "{file} still refers to the executable as {stale:?} \
                 (PKG-017, #368)"
            );
        }
    }
}

/// Every text file in the tree that ships or describes what ships.
///
/// Walked rather than listed, and filtered by what is *not* interesting rather
/// than by what is: `target/`, `.git/`, and the generated product data. A test
/// that enumerates the files it checks can only catch the ones whoever wrote it
/// remembered.
fn shipped_text_files(root: &Path) -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            // Hidden directories are caches and checkouts rather than the
            // tree — `.direnv` holds whole copies of previous revisions of
            // this repository, which match everything. `.github` is the one
            // that is genuinely ours.
            let skip = name.starts_with("result-")
                || matches!(
                    name.as_str(),
                    "target" | "result" | "node_modules" | "vectors" | "seeds"
                )
                || (name.starts_with('.') && name != ".github");
            if skip {
                continue;
            }
            if path.is_dir() {
                walk(&path, root, out);
            } else if let Ok(text) = std::fs::read_to_string(&path) {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                // This file is the one naming the stale paths, so it would
                // match every one of them.
                if relative.ends_with("packaging_invariants.rs") {
                    continue;
                }
                out.push((relative, text.replace("\r\n", "\n")));
            }
        }
    }

    let mut out = Vec::new();
    walk(root, root, &mut out);
    assert!(
        out.len() > 50,
        "only found {} text files, so this is not walking the tree",
        out.len()
    );
    out
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
        // The Windows targets (`PKG-020`, #379). There is no bare `.#windows`
        // any more: it meant the x86_64 one, and a release artifact named
        // after a default is one nobody can tell apart from the other. The
        // client population that needs the second is going Arm — Snapdragon X
        // and Windows Dev Kit natively, Apple Silicon by way of every
        // hypervisor on it.
        //
        // Which architectures that expands to is asserted below, on the
        // matrix, because the attribute here is parametrised.
        ".#windows-${{ matrix.arch }}",
        // The bootable bare-metal ISO (`OS-017`, #333), on **both**
        // architectures since `PKG-019` (#378) — one attribute, built on each
        // leg, because a system's `linuxIso` is the image for that system.
        //
        // This comment used to say "x86_64 only — the flake gates it by
        // system, because `pkgs.syslinux` is unavailable elsewhere". That was
        // true and is now irrelevant: the arm image has no BIOS path, so it
        // never reaches syslinux (`OS-033`, #377). The gate is "this system
        // builds a bare-metal target" (`OS-031`, #375), and `linuxArches` in
        // the flake is where that is decided.
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

    // `PKG-019` (#378): **both** ISOs are attached, named by architecture.
    //
    // Asserted on the artifact names rather than on the build command, and the
    // difference is the whole point of this test: `.#linuxIso` above proves a
    // build happens, and these prove the result is *shipped* under a name an
    // operator can tell apart. The x86 ISO was built and copied inside an
    // `if [ "$matrix.name" = "x86_64-linux" ]` for two issues, and nothing here
    // would have noticed the day that condition stopped being what was meant.
    let iso = "kmsrsos-${{ matrix.arch }}.iso";
    assert!(
        workflow.contains(iso),
        "the release does not attach the ISO as {iso}, so either it ships \
         under one name for two architectures or it does not ship \
         (PKG-019, #378)"
    );
    for arch in ["x86_64", "aarch64"] {
        assert!(
            workflow.contains(&format!("arch: {arch}")),
            "the release matrix has no {arch} leg, so no ISO is built for it. \
             Each image is built natively on its own runner (PKG-019, #378)"
        );
    }

    // And the ISO is proved reproducible the way the binary is (`PKG-016`,
    // #366). `reproducible-iso` runs in the gate; this is the same claim about
    // the file somebody downloads.
    assert!(
        workflow.contains(".#linuxIso --rebuild"),
        "the release does not prove the ISO it ships is reproducible \
         (PKG-016, #366; PKG-019, #378)"
    );

    // The old gate must be gone rather than merely bypassed. A leftover
    // `if [ "$matrix.name" = "x86_64-linux" ]` would silently ship one ISO
    // while every assertion above still passed.
    assert!(
        !workflow.contains("= \"x86_64-linux\" ]"),
        "the release still gates something on being the x86_64 leg. Since \
         `OS-033` (#377) there is an image for each architecture and the flake \
         decides which systems have one (PKG-019, #378)"
    );

    // `PKG-020` (#379): both Windows artifacts ship, named by architecture.
    //
    // Asserted on the names for the same reason the ISO's is: `.#windows-…`
    // above proves a build, and a name proves what an operator downloads. The
    // artifact used to be a bare `kmsrs-server.exe` from the x86_64 build, and
    // a name that does not say which architecture it is is one nobody can act
    // on the day there are two.
    for name in [
        "kmsrs-server-windows-${{ matrix.arch }}.exe",
        "kmsrs-client-windows-${{ matrix.arch }}.exe",
    ] {
        assert!(
            workflow.contains(name),
            "the release does not attach {name}, so a Windows binary ships \
             under a name that does not say which machine it runs on \
             (PKG-020, #379)"
        );
    }
    assert!(
        workflow.contains("arch: [x86_64, aarch64]"),
        "the Windows job is not matrixed over both architectures, so only one \
         of them is built (PKG-020, #379)"
    );

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

    for path in ["deploy/systemd/kmsrs-server.service", "docs/deployment.md"] {
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
    let full = read(&root, "deploy/systemd/kmsrs-server.service");
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
        !root.join("deploy/systemd/kmsrs-server.socket").exists(),
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

/// `PKG-008` (#245): the binary's entry point goes through the service router.
///
/// Windows service support is invisible from Linux: it compiles, it is never
/// exercised, and nothing about a Linux test run would notice if `main` went
/// back to calling `entry::serve` directly. That change would leave the service
/// module present, tested and unreachable — the process would start under the
/// SCM, never call `StartServiceCtrlDispatcher`, and be killed after 30 seconds
/// for failing to report `Running`.
///
/// So the wiring is asserted as text, which is the only thing a host-side test
/// can see. `service::run` is `entry::serve` on every non-Windows target, so
/// this costs those targets nothing.
#[test]
fn the_binary_starts_through_the_service_router() {
    let root = workspace_root();
    let main = read(&root, "crates/kmsrs-server/src/main.rs");

    assert!(
        main.contains("service::run()"),
        "main must call `service::run()`, not `entry::serve()` directly \
         (PKG-008, #245). Without it a Windows service start-up hangs and is \
         killed by the SCM, and no Linux test would fail."
    );

    let service = read(&root, "crates/kmsrs-server/src/service.rs");
    assert!(
        service.contains("ERROR_FAILED_SERVICE_CONTROLLER_CONNECT") && service.contains("1063"),
        "console-vs-service detection must stay keyed on \
         ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (PKG-008, #245): asking the \
         operating system is the only way that cannot disagree with reality."
    );

    // `PKG-008` is explicit that there is no installer, because an installer is
    // what produced both of vlmcsd's service bugs.
    for forbidden in ["CreateServiceW", "CreateServiceA", "DeleteService"] {
        assert!(
            !service.contains(forbidden),
            "{forbidden} means an install verb crept in. Installation is one \
             documented `sc.exe create` line; an in-binary installer \
             reintroduces the ImagePath password leak and the strcat overflow \
             (PKG-008, #245)."
        );
    }
}

#!/usr/bin/env bash
# Every Linux artifact for one architecture, for both channels (`PKG-025`,
# #411).
#
# `release.yml` builds these on a tag and `test.yml`'s `snapshot` job builds
# them on every push and pull request. Before this script they were two lists,
# and the shorter one was `test.yml`: the snapshot shipped the ISO and nothing
# else, so `.#deb` and `.#rpm` were built by no gate at all — not `nix flake
# check`, not a pull request — and a tag was the first thing that ever ran them.
#
# That is a failure this repository has already had. `release.yml` went on
# building `.#osImage` and `.#osIso` for two issues after `OS-018` (#334)
# deleted them, and the test asserting the release builds what the gate checks
# asserted the same stale names, so it passed while describing a release that
# could not run. Two statements agreeing with each other and neither of them
# built. The fix that lasts is not a third statement — it is one script, so that
# "the two channels build the same artifacts" stops being a claim and becomes
# the same code running twice.
#
# What this deliberately does *not* do:
#
#   * **checksums** — each caller writes its own `SHA256SUMS-<leg>`, because the
#     leg names differ between the channels and the file is a statement by the
#     machine that made the bytes (`SEC-010`, #202), not by this script
#   * **`--rebuild`** — reproducibility is a property to verify, not an artifact
#     to produce. `release.yml` proves it on the file it uploads and `test.yml`
#     has a `reproducible` job
#   * **anything to do with ghcr** — the snapshot attaches the container tarball
#     and pushes no image, so the registry only ever gains real versions
#
# Usage:  ci/build-artifacts.sh <arch> <outdir>
#
# where <arch> is `x86_64` or `aarch64`, and must be the architecture of the
# machine running it: every target below is the one *for this system*, and
# nothing here cross-compiles.
set -euo pipefail

arch="${1:?usage: build-artifacts.sh <arch> <outdir>}"
out="${2:?usage: build-artifacts.sh <arch> <outdir>}"

# The suffix the binaries, the SBOMs and the container tarball carry. It is not
# decoration: `release.yml` reads the architecture back out of the tarball's
# name to tag the per-arch images that `docker manifest create` then names, so
# `kmsrsos-container-x86_64-linux.tar.gz` is load-bearing on both ends.
name="${arch}-linux"

# `readelf -h`'s spelling, for `static-binaries.sh` below. Selected by name with
# no fallback, so a third architecture is an error that names itself rather than
# a check that quietly asserts the wrong machine.
case "$arch" in
    x86_64) machine='Advanced Micro Devices X86-64' ;;
    aarch64) machine='AArch64' ;;
    *)
        echo "build-artifacts.sh: unknown architecture '$arch'. Add it here" \
             "and to \`linuxArches\` in flake.nix, which is where a system" \
             "decides whether it builds a bare-metal target at all" >&2
        exit 1
        ;;
esac

mkdir -p "$out"

nix build .#server    --print-build-logs --out-link result-server
nix build .#client    --print-build-logs --out-link result-client
nix build .#deb       --print-build-logs --out-link result-deb
nix build .#rpm       --print-build-logs --out-link result-rpm
nix build .#container --print-build-logs --out-link result-container

cp "result-server/bin/kmsrs-server" "$out/kmsrs-server-${name}"
cp "result-client/bin/kmsrs-client" "$out/kmsrs-client-${name}"
cp result-deb/*.deb "$out/"
cp result-rpm/*.rpm "$out/"
cp result-container "$out/kmsrsos-container-${name}.tar.gz"

# One bare-metal ISO per architecture, each built on its own leg (`PKG-019`,
# #378). There is no `if` on the architecture here and the one that used to be
# in `release.yml` is worth remembering: it tested for the x86 leg, because
# `pkgs.syslinux` is unavailable elsewhere and the whole target was gated by
# system. That reasoning is now correct and irrelevant — the arm recipe has no
# BIOS path, so it never reaches syslinux (`OS-033`, #377) — and the gate that
# remains lives in the flake, where `linuxArches` decides which systems build a
# target at all.
#
# Shipped uncompressed: 5.3 MiB on x86_64 and 4.4 MiB on aarch64, and a
# `.iso.gz` is one more step between an operator and a running host when the
# whole procedure is "upload it, attach it, boot it".
nix build .#linuxIso --print-build-logs --out-link result-iso
cp result-iso "$out/kmsrsos-${arch}.iso"

# `PKG-023` (#395): read the artifacts that are about to be uploaded, not the
# store paths a check happened to build. `nix flake check` runs the same script
# over the same binaries, and this runs it again over `$out/` anyway, because
# `PKG-022` (#385) is the standing rule that the artifact under test is the one
# an operator downloads. It is also the only thing that catches a `cp` above
# copying the wrong leg's binary, which no check inside the flake can see.
ci/static-binaries.sh "$machine" \
    "$out/kmsrs-server-${name}" \
    "$out/kmsrs-client-${name}"

# `SEC-010` (#202): the binaries are static, so "what is in this" is a question
# the file itself has to answer. An SBOM derived from the lockfile is that
# answer, and it is exact rather than inferred — every version in it is pinned
# with `=` (`PKG-006`, #243).
#
# Through the dev shell: `cargo-cyclonedx` shells out to `rustc` for the target
# triple, so it needs the toolchain on PATH, and running it from the shell means
# `flake.lock` pins the version.
nix develop -c cargo cyclonedx --format json --describe crate

# One SBOM per crate is emitted; the two that ship are the two that are
# attached, named after the binary rather than after the crate so that a reader
# can match them to what they downloaded.
cp "crates/kmsrs-server/kmsrs-server.cdx.json" \
   "$out/sbom-kmsrs-server-${name}.cdx.json"
cp "crates/kmsrs-client/kmsrs-client.cdx.json" \
   "$out/sbom-kmsrs-client-${name}.cdx.json"
test -s "$out/sbom-kmsrs-server-${name}.cdx.json"
test -s "$out/sbom-kmsrs-client-${name}.cdx.json"

echo "ok: built every Linux artifact for ${name}:"
ls -la "$out"

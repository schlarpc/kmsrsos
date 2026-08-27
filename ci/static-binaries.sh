#!/usr/bin/env bash
# The shipped Linux binaries are statically linked, read off the binary
# (`PKG-023`, #395).
#
# `docs/releasing.md` says of both artifacts "statically linked against musl; no
# runtime dependencies". Until this script that claim rested on two greps over
# `flake.nix` and `rust-toolchain.toml` — statements about the *expression*, and
# `PKG-018` (#374) is the standing precedent against those: Control Flow Guard
# produced a binary whose header made an honest claim and which died at start-up
# before logging a line. Every build-time check passed.
#
# The way this one would fail is quieter and worse. A dynamically linked
# artifact builds, installs, runs on the machine that built it, and then does
# not start on a host whose libc is not the builder's — and the container image,
# whose whole claim is that it contains two files, would need a libc closure
# nobody put there.
#
# Three questions, all answered by the ELF header and program headers:
#
#   * **no `PT_INTERP`** — nothing asks a dynamic loader to run this
#   * **no `DT_NEEDED`** — nothing is required from a shared library. A
#     `static-pie` binary still has a `.dynamic` section, for its own
#     relocations, so "has a dynamic section" is *not* the question and a check
#     that asked it would fail on a correct artifact
#   * **the machine is the one expected** — because the reason this runs per
#     architecture is that aarch64 was asserted nowhere. `PKG-019` (#378) added
#     the second Linux leg and the invariant, which names
#     `x86_64-unknown-linux-musl` literally, was never widened
#
# Usage:  ci/static-binaries.sh <expected machine> <binary>...
#
# where <expected machine> is `readelf -h`'s spelling of it: `AArch64`, or
# `Advanced Micro Devices X86-64`.
set -euo pipefail

expected="${1:?usage: static-binaries.sh <expected machine> <binary>...}"
shift
if [ "$#" -eq 0 ]; then
    echo "static-binaries.sh: no binaries given, so nothing was checked" >&2
    exit 1
fi

failed=0
for binary in "$@"; do
    if [ ! -f "$binary" ]; then
        echo "FAIL: $binary: no such file" >&2
        failed=1
        continue
    fi

    if readelf -lW "$binary" | grep -q 'INTERP'; then
        echo "FAIL: $binary has a PT_INTERP segment, so it is dynamically" \
             "linked and wants a loader that a scratch image does not have" \
             "(PKG-004, #241):" >&2
        readelf -lW "$binary" | grep -A1 'INTERP' >&2
        failed=1
    fi

    if readelf -dW "$binary" 2>/dev/null | grep -q '(NEEDED)'; then
        echo "FAIL: $binary has DT_NEEDED entries, so it depends on shared" \
             "libraries this artifact does not ship:" >&2
        readelf -dW "$binary" | grep '(NEEDED)' >&2
        failed=1
    fi

    machine=$(readelf -hW "$binary" | sed -n 's/^ *Machine: *//p')
    if [ "$machine" != "$expected" ]; then
        echo "FAIL: $binary is machine '$machine', expected '$expected'." \
             "A leg that checked the other architecture's artifact would pass" \
             "for the whole time this one was wrong (PKG-023, #395)" >&2
        failed=1
    fi

    if [ "$failed" -eq 0 ]; then
        echo "ok: $binary is a static $machine ELF with no shared-library dependency"
    fi
done

exit "$failed"

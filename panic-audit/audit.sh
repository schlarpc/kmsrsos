#!/usr/bin/env bash
# Verify that the sans-io core cannot panic (ARCH-009, #9).
#
# Builds panic-audit/ for a bare-metal target with the release profile's
# settings, then reads the symbol table. Any reference to `core::panicking` from
# the linked binary means some call in kmsrs-proto or kmsrs-crypto can still
# reach a panic that LLVM could not prove away — a bounds check it could not
# eliminate, a `copy_from_slice` whose two lengths are not visibly equal, a
# slice range where `start <= end` is not provable. Those are exactly the
# panics ARCH-008's deny list cannot see, because nobody wrote them.
#
# The script also builds with `--features inject-panic`, which calls one thing
# that genuinely panics, and *requires* that build to be dirty. A check that has
# never been observed to fail is a check nobody should trust: without the second
# build, a toolchain that renamed or stripped the symbols would leave this
# passing forever while measuring nothing.
#
# Usage:
#   nix develop .#fuzz -c ./panic-audit/audit.sh
#
# Nightly is required for -Zbuild-std, which is what makes a core built with the
# same profile as our own code available for the bare-metal target. That is the
# same nightly the fuzzers use (SEC-004, #196); nothing that ships is built
# with it.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="x86_64-unknown-none"
artifact="target/${target}/release/kmsrs-panic-audit"

cd "$here"

# Returns the panic references in a build, one per line.
panic_references() {
    local features=("$@")
    local args=(build --release --quiet --target "$target" -Z build-std=core)
    if [ ${#features[@]} -gt 0 ]; then
        args+=(--features "$(
            IFS=,
            echo "${features[*]}"
        )")
    fi

    rm -f "$artifact"
    if ! cargo "${args[@]}" >&2; then
        echo "FAIL: the audit binary did not build" >&2
        exit 1
    fi
    if [ ! -f "$artifact" ]; then
        echo "FAIL: cargo reported success but produced no $artifact" >&2
        exit 1
    fi
    # `nm -C` demangles, so this matches the readable name rather than a
    # mangling scheme that changes between toolchains.
    nm -C "$artifact" | grep -o 'core::panicking::[a-z_0-9]*' | sort -u || true
}

echo "=== audit: the core as it ships ==="
clean="$(panic_references)"

if [ -n "$clean" ]; then
    echo
    echo "FAIL: the core can still reach a panic:"
    echo "$clean" | sed 's/^/    /'
    echo
    echo "Find the source lines with (the profile carries line tables for this):"
    echo "    cd panic-audit && objdump -dl -C $artifact |"
    echo "        grep -B20 'call.*core::panicking' | grep -E '^/'"
    echo
    echo "Find the enclosing functions with:"
    echo "    cd panic-audit && objdump -d -C $artifact |"
    echo "        awk '/^[0-9a-f]+ </ {fn=\$0} /call.*core::panicking/ {print fn}' | sort -u"
    exit 1
fi
echo "clean: no reference to core::panicking"

# The detector has to be seen failing, or it is not a detector.
echo
echo "=== audit: with a panic deliberately introduced ==="
# The two builds differ only by a feature, so cargo rebuilds rather than
# reusing the clean artifact.
injected="$(panic_references inject-panic)"

if [ -z "$injected" ]; then
    echo
    echo "FAIL: a build containing a real panic showed no reference to"
    echo "core::panicking, so this audit is not measuring anything. The symbol"
    echo "names or the mangling probably changed with the toolchain; fix the"
    echo "grep in this script before trusting a clean run."
    exit 1
fi
echo "detector works: injected build references"
echo "$injected" | sed 's/^/    /'

echo
echo "PASS: kmsrs-proto and kmsrs-crypto are panic-free, and the check that"
echo "says so has been observed to fail."

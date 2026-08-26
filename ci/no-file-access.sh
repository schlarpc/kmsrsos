#!/usr/bin/env bash
# Axiom A5, asserted against the binary rather than against the source
# (SEC-006, #198).
#
# `no_shipped_crate_touches_the_filesystem` in workspace_invariants.rs checks
# that no source names an API that opens a file. That is a real check and it is
# not the whole claim: it cannot see a *dependency* that opens something, or a
# libc that reads a configuration file behind our back. This is the other end —
# run the real binary and watch every syscall it makes.
#
# Linux only: it needs strace, and it reads /proc.
#
# Usage:  ci/no-file-access.sh <directory containing bin/kmsrs-server and bin/kmsrs-client>
set -euo pipefail

package="${1:?usage: no-file-access.sh <nix build result directory>}"
server="$package/bin/kmsrs-server"
client="$package/bin/kmsrs-client"
log="${STRACE_LOG:-strace.log}"

[ -x "$server" ] || { echo "no server binary at $server" >&2; exit 2; }
[ -x "$client" ] || { echo "no client binary at $client" >&2; exit 2; }

# Every path a start-up is allowed to touch, and why.
#
#   /nix/store       the binary itself and its shared libraries — the loader's
#                    work, not the program's. A static musl build has neither,
#                    but `nix build .#default` is dynamically linked.
#   /proc/self       what the Rust runtime reads to find its own stack guard;
#                    not a file the program chose.
#   /sys/kernel      the same, for CPU topology.
#   /dev/urandom     the entropy source (`CRY-013`, #52) on a kernel too old for
#                    the getrandom syscall. That is the fallback path rather
#                    than the normal one, and forbidding it here would make this
#                    check fail on an old kernel for a good reason.
#
# Overridable so the check can be observed *failing*: a check nobody has seen
# fail is not a check. `ALLOWED_PATHS='' ci/no-file-access.sh ./result` should
# report the loader's own opens as offences.
allowed="${ALLOWED_PATHS-/nix/store/|/proc/self/|/sys/kernel/|/dev/urandom}"

# Nothing else may be on 1688, or the readiness check below would be answered by
# somebody else's server and this would pass without having tested anything.
if "$client" --quiet --healthcheck 127.0.0.1:1688 >/dev/null 2>&1; then
  echo "something is already serving KMS on 1688; this check needs the port" >&2
  exit 2
fi

echo "tracing $server"
strace -f -e trace=openat,open,creat,openat2 -o "$log" "$server" &
tracer=$!

# The traced process, which is strace's only child. Stopping *it* rather than
# stopping strace matters: strace detaches on SIGTERM rather than killing what
# it traced, so signalling the wrong one leaves a server running, holding this
# script's stdout open, forever.
#
# Stopping it by SIGTERM also exercises the drain path (`NET-007`, #157), which
# is the shutdown a supervisor performs.
traced=""
for _ in $(seq 1 50); do
  traced=$(cat "/proc/$tracer/task/$tracer/children" 2>/dev/null | tr -d ' ' || true)
  [ -n "$traced" ] && break
  sleep 0.1
done

# Wait for the KMS port to serve an activation, which is what "start-up
# finished" means. Everything a program that reads files reads, it reads before
# then.
ready=0
for _ in $(seq 1 30); do
  # A dead tracer means the server exited — a bind failure, a bad config, a
  # panic. Whatever it was, there is nothing to trace and nothing to conclude.
  kill -0 "$tracer" 2>/dev/null || break
  if "$client" --quiet --healthcheck 127.0.0.1:1688 >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

alive=0
kill -0 "$tracer" 2>/dev/null && alive=1
[ -n "$traced" ] && kill -TERM "$traced" 2>/dev/null
wait "$tracer" 2>/dev/null || true

if [ "$ready" -ne 1 ] || [ "$alive" -ne 1 ]; then
  echo "the server never served an activation on 1688, so this proves nothing" >&2
  echo "--- the trace so far ---" >&2
  cat "$log" >&2
  exit 1
fi

echo "--- every open() the server made ---"
cat "$log"

# A *failed* open is a probe that found nothing — glibc probes for locale and
# NSS files it never gets — so `-1 ENOENT` lines are reported but not failed on.
# What must not happen is a successful one.
opens=$(grep -E '^[0-9]+ +open(at|at2)?\(' "$log" | grep -v -- '-1 ENOENT' || true)
if [ -n "$allowed" ]; then
  # Not folded into the pipeline above: `grep -vE ""` drops every line, because
  # an empty pattern matches everything — so an empty allow-list would silently
  # make this check pass rather than fail everything, which is the opposite of
  # what it is for.
  offenders=$(printf '%s\n' "$opens" | grep -vE "$allowed" || true)
else
  offenders="$opens"
fi

if [ -n "$offenders" ]; then
  echo "::error::the server opened files, which axiom A5 forbids"
  echo "$offenders"
  exit 1
fi

echo "no file was opened outside the loader"

#!/usr/bin/env bash
# Record every syscall a running server makes (`SEC-018`, #355).
#
# # Why this exists
#
# A seccomp allowlist is a claim about *every syscall this process will ever
# make*, across every libc, allocator, kernel and tokio version it ships
# against. The failure mode of getting it wrong is the process being killed on
# a syscall nobody predicted, under load, in production. #355 is explicit that
# a list written from a reading of what the code appears to call is not the
# same as knowing:
#
#   > The list has to be *measured*.
#
# This is the instrument. It starts the server under `strace`, drives it
# through the paths #355 names — idle, a v4/v5/v6 activation, a web request,
# the rate limiter engaging, a connection hitting its deadline, the entropy
# re-test, shutdown and drain — and prints the set of syscalls that were
# actually made. `crates/kmsrs-server/src/sandbox.rs` quotes the result and
# `harness/linux/surveys/` holds the raw output of the runs the shipped list
# was built from.
#
# # What it deliberately does not do
#
# It does not generate the allowlist. Two of the paths take minutes of
# wall-clock (`CONNECTION_DEADLINE` is 2 minutes, `ENTROPY_RECHECK_INTERVAL` is
# 5), a survey is one kernel and one libc, and a syscall that happens to go
# unmade in one run is not a syscall the program cannot make. The list is
# written by hand *from* this, family by family, and the thing that keeps it
# honest at run time is `tests/sandbox.rs` — which installs the real filter and
# serves real requests through it, on whichever architecture CI is running.
#
# Usage, from the repository root:
#
#     harness/linux/syscall-survey.sh \
#         --server target/release/kmsrs-server \
#         --client target/release/kmsrs-client \
#         --out harness/linux/surveys/glibc-x86_64
#
# 1688 is compiled in (`NET-002`, #151), so this needs a network namespace of
# its own if anything else on the machine is already serving. `bwrap
# --unshare-net` is enough and needs no privileges.
set -euo pipefail

server=""
client=""
out=""
# Long enough to cross ENTROPY_RECHECK_INTERVAL (5 minutes) and
# CONNECTION_DEADLINE (2 minutes), which overlap.
soak_seconds="${SURVEY_SOAK_SECONDS:-330}"

while [ $# -gt 0 ]; do
    case "$1" in
        --server) server="$2"; shift 2 ;;
        --client) client="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$server" ] && [ -n "$client" ] && [ -n "$out" ] || {
    echo "usage: $0 --server PATH --client PATH --out DIR" >&2
    exit 2
}

mkdir -p "$out"
trace="$out/strace.log"
rm -f "$trace" "$trace".*

# `-f` because the runtime is one thread per core plus the reaper: a syscall
# made on a worker is one this process makes. `-qq` suppresses the exit-status
# chatter. `-e trace=all` is the point — a survey that filtered would only ever
# confirm what it was told to look for.
strace -f -qq -e trace=all -o "$trace" -- "$server" 2> "$out/server.log" &
strace_pid=$!

cleanup() { kill "$strace_pid" 2>/dev/null || true; }
trap cleanup EXIT

# --- Wait for the listener, not for a log line ---------------------------
for _ in $(seq 1 100); do
    if (exec 3<>/dev/tcp/127.0.0.1/1688) 2>/dev/null; then exec 3>&- 3<&-; break; fi
    sleep 0.1
done

echo "== idle =="
sleep 2

echo "== activations, one per protocol version =="
for version in 4 5 6; do
    "$client" --version "$version" --quiet 127.0.0.1:1688 || true
done

echo "== a reconnecting client, so the accept path runs more than once =="
"$client" --soak 20 --quiet 127.0.0.1:1688 || true
"$client" --soak 20 --reconnect --quiet 127.0.0.1:1688 || true

echo "== every web route =="
for route in / /events /instructions /products /healthz /metrics; do
    exec 3<>/dev/tcp/127.0.0.1/8080
    printf 'GET %s HTTP/1.0\r\n\r\n' "$route" >&3
    cat <&3 > /dev/null
    exec 3>&- 3<&-
done

echo "== the rate limiter, engaged =="
"$client" --soak 400 --concurrency 16 --quiet 127.0.0.1:1688 || true

echo "== a connection that says nothing, so its deadline fires =="
(exec 3<>/dev/tcp/127.0.0.1/1688; sleep "$soak_seconds") &
idle_pid=$!

echo "== waiting out the entropy re-test and the connection deadline =="
sleep "$soak_seconds"
kill "$idle_pid" 2>/dev/null || true

echo "== shutdown and drain =="
# SIGTERM to the server, which is `strace`'s child rather than `strace`.
pkill -TERM -P "$strace_pid" -f "$(basename "$server")" 2>/dev/null \
    || kill -TERM "$strace_pid" 2>/dev/null || true
wait "$strace_pid" 2>/dev/null || true
trap - EXIT

# --- What was made ---------------------------------------------------------
#
# `strace` writes `pid  name(args) = ret`, plus resumption lines for calls
# interrupted by another thread and `--- SIGx ---` for signals. The name is the
# token before the first `(` on any line that has one.
names() {
    { grep -oE '^[0-9]* *[a-z_0-9]+\(' | tr -d '(' | awk '{print $NF}'; } < /dev/stdin
}
resumed() {
    { grep -oE '<\.\.\. [a-z_0-9]+ resumed' | awk '{print $2}'; } < /dev/stdin
}
{ names < "$trace"; resumed < "$trace"; } | sort -u > "$out/syscalls.txt"

# --- And the half that matters --------------------------------------------
#
# The filter is installed *after* the listeners are bound, so what it has to
# permit is everything from that moment on — not the dynamic loader's `openat`
# of libc, not `execve`, not the `bind` and `listen` that are already done.
# `landlock_restrict_self` is the last call `sandbox::apply` makes before
# `restrict_syscalls`, so it is the marker, and taking everything at or after
# it errs towards a longer list rather than a shorter one.
after="$out/after-the-sandbox.txt"
if grep -q landlock_restrict_self "$trace"; then
    sed -n '/landlock_restrict_self/,$p' "$trace" > "$trace.after"
    { names < "$trace.after"; resumed < "$trace.after"; } | sort -u > "$after"
    rm -f "$trace.after"
else
    echo "no landlock_restrict_self in the trace: this build did not sandbox itself" >&2
    cp "$out/syscalls.txt" "$after"
fi

{
    echo "# Provenance, so a list can be traced back to a run."
    echo "kernel:  $(uname -srm)"
    echo "server:  $server"
    echo "libc:    $(file -b "$server" | grep -oE 'dynamically linked|statically linked|static-pie linked')"
    echo "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "syscalls:            $(wc -l < "$out/syscalls.txt")"
    echo "after the sandbox:   $(wc -l < "$after")"
} > "$out/provenance.txt"

cat "$out/provenance.txt"
echo
cat "$after"

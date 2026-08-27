# The Linux syscall survey (`SEC-018`, #355)

`syscall-survey.sh` records every syscall a running server makes. It exists because a seccomp
allowlist is a claim about **every syscall this process will ever make**, and #355 is explicit that
a list written from a reading of what the code appears to call is not the same as knowing.

```sh
harness/linux/syscall-survey.sh \
    --server target/release/kmsrs-server \
    --client target/release/kmsrs-client \
    --out harness/linux/surveys/glibc-x86_64
```

1688 is compiled in (`NET-002`, #151), so this wants a network namespace of its own if anything else
on the machine is already serving. `bwrap --dev-bind / / --unshare-net` is enough and needs no
privileges. A run takes about six minutes: `CONNECTION_DEADLINE` is two and
`ENTROPY_RECHECK_INTERVAL` is five, and a survey that did not outlast both would be a survey of
start-up.

## What is checked in, and what is not

`surveys/<target>/` holds `syscalls.txt` (everything the process made, `execve` onwards),
`after-the-sandbox.txt` (everything from `landlock_restrict_self` on, which is what the filter has to
permit) and `provenance.txt` (kernel, binary, date). The raw `strace` log and the server's own log are
regenerated rather than committed — see `surveys/.gitignore`.

`tests/sandbox.rs` reads `after-the-sandbox.txt` back and fails if the shipped allowlist does not
cover it. So a re-run that turns up something new is a failing test rather than a note somebody has to
remember to act on.

## What the surveys are, and what they are not

They are a **floor**. The two checked in are the same program, driven through the same requests, on
the same kernel — and they disagree: glibc calls `epoll_wait`, musl calls `epoll_pwait`, and glibc
alone reaches for `brk`, `gettid`, `mprotect` and `sched_getaffinity`. None of that is visible in this
workspace's source, which is the entire argument for measuring. It is also the argument for **not**
shipping the measurement as the list: a list cut down to one run's observations kills a process on the
other libc. `crates/kmsrs-server/src/sandbox.rs` writes it a family at a time above this floor and
says so.

They are also taken with the filter **off**, which is what makes them evidence rather than a tautology
— a survey of a filtered process can only ever record syscalls the filter already allows. Re-running
against a *filtered* build is the other half of the check, and it is worth doing after any change to
the list: on both libc targets the filtered server serves the same 241 activations, sheds the same 208
over the rate limit, waits out the same deadline and entropy re-test, and stops cleanly. The only
syscalls the filtered runs add are `prctl` and `seccomp`, which are how the filter is installed and
happen before it takes effect.

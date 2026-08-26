# kmsrsos

A KMS host emulator in pure safe Rust — correct by construction, zero runtime configuration, no
disk I/O. Targets Linux, Windows, and bare metal (a [Linux] kernel with this program as PID 1).

> **Status: design complete, implementation not started.** The plan of record is the
> [issue tracker](https://github.com/schlarpc/kmsrsos/issues) — 264 items across 11 milestones,
> each with a definition of done and explicit dependency links.

## What and why

Microsoft's Key Management Service is a volume-activation mechanism: a licensed KMS host answers
DCE/RPC requests on TCP 1688, and volume-licensed Windows and Office clients activate against it.
Two open-source emulator families exist — [vlmcsd] (C, archived 2023) and [py-kms] (Python) — and
between them they cover most of the problem, but the union is not available in any single program
and the intersection of what both miss is large.

`docs/` contains an exhaustive audit of both families: 119 features compared, 23 that **nobody**
implements, and 24 situations where the two disagree about what a KMS host should do. Planning
turned that into 264 issues, 35 recorded design decisions and 33 explicitly declined ones.

Design goals, in the order that shapes the code:

- **Pure safe Rust.** `#![forbid(unsafe_code)]` throughout. The audited C implementation has a
  remote out-of-bounds read and an indirect call through a wild function pointer in its
  pre-authentication request path.
- **Correct by construction.** Illegal protocol states are unrepresentable, not merely checked.
- **Zero runtime configuration.** Everything is decided at build time; the single runtime escape
  hatch cannot change a byte on the wire.
- **No disk I/O.** No database, no log files, no config files. State is a bounded in-memory ring
  buffer; logs go to stderr; the event log is served over HTTP by the same process.
- **Sans-io core.** The protocol crates take bytes and return events, which is what makes fuzzing,
  differential testing against both other implementations, and the bare-metal target tractable.
- **Anti-fingerprinting.** The ways existing emulators are detectable are treated as a test suite.
  Per the audit, none of the three existing implementations survives an adversarial detection probe
  without being reconfigured.

## Documentation

| Document | Contents |
|---|---|
| [`docs/decisions.md`](docs/decisions.md) | Axioms, the 36 decisions taken, and 41 things deliberately not built |
| [`docs/reference.md`](docs/reference.md) | Generated from the code: routes, metrics, exit codes, what a build decides, what is in the database |
| [`docs/releasing.md`](docs/releasing.md) | What a tag produces, how to verify it, and the release-notes template |
| [`docs/deployment.md`](docs/deployment.md) | Where the host has to live, the SRV record, the container and Kubernetes manifests, the bare-metal ISO on Proxmox, and what is not in the artifact |
| [`docs/research-findings.md`](docs/research-findings.md) | Microsoft-sourced product data, hypervisor platform constraints, coverage map |
| [`docs/kms-emulator-feature-matrix.md`](docs/kms-emulator-feature-matrix.md) | Cross-implementation synthesis and the 24 behavioural mismatches |
| [`docs/vlmcsd-features.md`](docs/vlmcsd-features.md) | Complete vlmcsd audit |
| [`docs/py-kms-features.md`](docs/py-kms-features.md) | Complete py-kms audit |
| [`docs/vlmcsd-forks.md`](docs/vlmcsd-forks.md) | vlmcsd fork survey (2,523 forks; 16 touch code) |
| [`docs/py-kms-forks.md`](docs/py-kms-forks.md) | py-kms fork survey (32 code-touching forks) |

## Development

This project uses [rust-flake] as its foundation, providing a pinned Rust toolchain and
reproducible builds via [Nix] and [Crane].

### Setting up the development environment

The project uses [direnv] to automatically load the development environment. When you enter
the project directory, direnv activates a shell with the pinned toolchain and dev tools
available, refreshing automatically when you change the flake or `Cargo.toml`.

```shell
$ direnv allow
```

Without direnv, enter the shell manually:

```shell
$ nix develop
```

### Building and running

```shell
$ cargo run                                      # debug build + run
$ cargo build --release                          # optimized build
$ nix run                                        # build and run via Nix
$ ./result/bin/kmsrs-server   # the nix-built binary
```

### Testing, linting, and formatting

```shell
$ cargo nextest run          # fast parallel test runner
$ cargo llvm-cov nextest     # tests with coverage
$ cargo clippy --all-targets # lint
$ cargo fmt                  # format
```

### Working with Nix

```shell
$ nix build          # build the package
$ nix build .#windows-x86_64  # cross-compile for Windows (x86_64-pc-windows-msvc)
$ nix build .#windows-aarch64 # and for Windows on Arm (PKG-020, #379)
$ nix build .#linux-kernel # the bare-metal kernel on its own
$ nix build .#linuxIso     # a bootable ISO: BIOS or UEFI, 14 MiB
$ nix flake check    # run all checks (build, clippy, fmt, test, coverage)
$ nix flake update   # update flake inputs
```

Windows cross-compilation also works from the dev shell without Nix sandboxing:

```shell
$ cargo xwin build --release --target x86_64-pc-windows-msvc
$ cargo xwin build --release --target aarch64-pc-windows-msvc
```

The Rust toolchain is pinned in `rust-toolchain.toml` (single source of truth); Nix reads it
via `rust-bin.fromRustupToolchainFile`, so builds stay reproducible. To upgrade Rust, bump
`channel` there.

## Keeping in sync with the base template

This project was generated from [rust-flake] and can receive updates from the upstream
template using [cruft]:

```shell
$ cruft update --checkout template
```

## Licence

MIT.

[Crane]: https://crane.dev/
[cruft]: https://cruft.github.io/cruft/
[direnv]: https://direnv.net/
[Linux]: https://kernel.org
[Nix]: https://nixos.org/
[py-kms]: https://github.com/Py-KMS-Organization/py-kms
[rust-flake]: https://github.com/schlarpc/rust-flake
[vlmcsd]: https://github.com/Wind4/vlmcsd

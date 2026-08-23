# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A KMS (Key Management Service) host emulator in pure safe Rust, targeting Linux, Windows and bare
metal (Hermit unikernel with virtio-net). Design goals: correct by construction, zero runtime
configuration, no disk I/O, maximal client compatibility, and anti-fingerprinting parity with a
genuine Microsoft KMS host.

**[`docs/punchlist.md`](docs/punchlist.md) is the plan of record.** Every work item has a stable ID
(`ARCH-001`, `WIRE-022`, `POL-010`, …) and a matching GitHub issue. Read the relevant section before
implementing anything in that area — the audits behind it caught a large number of non-obvious
protocol and behavioural details that are easy to get wrong and hard to notice when wrong.

Supporting research, all in `docs/`: `kms-emulator-feature-matrix.md` (cross-implementation
synthesis), `vlmcsd-features.md`, `py-kms-features.md`, `vlmcsd-forks.md`, `py-kms-forks.md`.

---

## Workflow rules

These are mandatory, not suggestions.

### Commits

- **One commit per coherent unit of work.** A coherent unit is one that leaves the tree building and
  testing green and that a reviewer can evaluate on its own. Usually that is one punch-list item;
  sometimes it is a small cluster that genuinely cannot be separated.
- **Commit automatically when a unit is complete.** Do not wait to be asked, and do not batch
  unrelated changes into one commit.
- Never mix refactoring with behaviour change in the same commit. Split them.
- Never commit on the default branch. Branch first, then open a PR if the change warrants review.
- Commit message format:

  ```
  <area>: <imperative summary>

  <why this change, not what — the diff shows what>

  Closes #<issue>
  ```

  where `<area>` is the punch-list prefix in lower case (`arch`, `kms`, `cry`, `wire`, `pol`, `id`,
  `db`, `disc`, `net`, `cfg`, `obs`, `sec`, `cli`, `test`, `pkg`, `os`).

### Issues

- **Comment on and close the issue when the commit lands and is pushed** — not when the code is
  written, not when it is staged. The comment states what was done, names the commit, and notes any
  deviation from the punch-list item's stated approach.
- **File new issues for residuals rather than keeping an omnibus issue open.** If an issue is
  principally solved but leaves follow-up work behind, close it and open fresh, specific issues for
  what remains, cross-referencing the closed one. An issue that stays open for a trailing 10 % is an
  issue nobody can reason about.
- File a new issue for anything discovered mid-work that is out of scope for the current unit. Do not
  silently expand scope.
- If an item turns out to be wrong, infeasible, or unnecessary, close it with the reasoning and
  update `docs/punchlist.md` in the same commit. **The punch list and the issue tracker must not
  drift.** Appendix A is where declined items go, with rationale.

### Definition of done

An item is done when all of these hold:

1. The behaviour described in the punch-list item is implemented.
2. Tests exist that would fail if it regressed — not merely tests that pass.
3. `cargo clippy --all-targets` is clean and `cargo fmt` has been run.
4. Anything protocol-visible has a golden wire vector or a differential test against vlmcsd/py-kms.
5. The doc comment on the relevant type or function cites the punch-list ID.
6. The commit is pushed and the issue is closed with a comment.

---

## Development commands

Rust project using Nix flakes with a pinned toolchain. Load the environment first:

- `direnv allow` — load the development environment (or `nix develop`)

### Build & run

- `cargo run` — build (debug) and run
- `cargo build --release` — optimized build
- `nix run` — build and run via Nix
- `./result/bin/kmsrsos` — the nix-built binary

### Test, lint, format

- `cargo nextest run` — fast parallel test runner
- `cargo llvm-cov nextest` — tests with coverage
- `cargo clippy --all-targets` — lint
- `cargo fmt` — format

### Nix

- `nix build` — build the package
- `nix build .#windows` — cross-compile for Windows (x86_64-pc-windows-msvc)
- `nix flake check` — run all checks (build, clippy, fmt, test, coverage)
- `nix flake update` — update flake inputs

### Windows cross-compilation

- `cargo xwin build --release --target x86_64-pc-windows-msvc` — cross-compile from the dev shell
- The pure Nix build gets the MSVC CRT/SDK from a pinned `xwin` fixed-output derivation in
  `flake.nix`; to bump the pinned versions, update them there, set `outputHash = pkgs.lib.fakeHash`,
  build, and copy the real hash from the mismatch error.

---

## Architecture

Eight crates in one workspace. The split is load-bearing, not cosmetic — see `ARCH-001`.

| Crate | `no_std`? | Contents |
|---|---|---|
| `kmsrs-proto` | `no_std + alloc` | KMS v4/v5/v6 payloads, DCE/RPC codec + connection state machine. Pure sans-io. |
| `kmsrs-crypto` | `no_std` | Rijndael-160 CBC-MAC, tweaked-AES-128 for v6, wrappers over `sha2`/`hmac` |
| `kmsrs-db` | `no_std` | `build.rs`-generated `static` product tables + query API |
| `kmsrs-dbgen` | std, host-only | Extracts product data from Microsoft `pkeyconfig` artifacts |
| `kmsrs-policy` | `no_std + alloc` | Activation policy, host-state model, identity, event log. Sans-io. |
| `kmsrs-server` | std | Platform layer, listeners, concurrency, HTTP responder, wiring |
| `kmsrs-client` | std | Diagnostic / validation / soak client |
| `kmsrs-os` | std (hermit) | Hermit unikernel binary |

Plus `kmsrs-fuzz` and `kmsrs-vectors` for test infrastructure.

### Invariants that must not be violated

- **`#![forbid(unsafe_code)]` everywhere** except a single documented boundary in `kmsrs-os`.
- **The core is sans-io.** `kmsrs-proto` and `kmsrs-policy` take bytes and a clock reading and return
  events. No sockets, no clock reads, no RNG inside them — time and entropy are *inputs*. This is what
  makes fuzzing, differential testing and the Hermit platform split possible.
- **No runtime configuration** beyond the single `KMSRSOS_CONFIG` env var, which may only touch
  settings that cannot change a byte on the wire. See `CFG-001`.
- **No disk I/O.** No files, no temp files, no databases, no log files. Logs go to stderr; state
  lives in a bounded in-memory ring buffer.
- **`kmsrs-dbgen` dependencies must never be reachable from the runtime binary.** That is the entire
  reason it is a separate crate.
- **Product data ships through the `kmsrs-dbgen` pipeline or it does not ship.** Never hand-copy
  values from another emulator's catalog — that practice produced every fabricated GUID found in the
  audits.
- **No `as` casts in wire handling**; `TryFrom` and `checked_*` only.
- **Per-request state is owned by the request**, never a shared mutable map.

### Anti-fingerprinting

`docs/punchlist.md` §17 (`FP-001`..`FP-027`) is a checklist, and `kmsrs-client` is its regression
suite. Any change that touches the wire format, identity generation, timing or randomness must be
checked against it. Several properties are load-bearing in non-obvious ways — for example, multiple
server replicas each generate their own ePID, which reintroduces the canonical detection test at the
infrastructure layer.

---

## Keeping in sync with the base template

Pull upstream template updates with [cruft](https://cruft.github.io/cruft/):

- `cruft update --checkout template`

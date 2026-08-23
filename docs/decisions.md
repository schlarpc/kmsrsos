# Design decisions

**Work items live in [GitHub issues](https://github.com/schlarpc/kmsrsos/issues), not here.** This
document records the things a tracker holds badly: the axioms that constrain every item, the
decisions taken and why, and the things deliberately *not* built — which by definition have no issue.

Issue IDs (`ARCH-001`, `WIRE-022`, …) are stable identifiers. Cite them in commits and doc comments.

---

## Axioms

These constrain everything. A proposal that violates one is wrong by default, not merely unusual.

| # | Axiom | Consequence |
|---|---|---|
| A1 | Pure safe Rust | `#![forbid(unsafe_code)]` in every crate except a documented `kmsrs-os` boundary |
| A2 | Correct by construction | Illegal states unrepresentable; no runtime panics; no runtime validation of what a type could carry |
| A3 | Configuration is compile-time | One narrow runtime escape hatch, restricted to settings that cannot change a byte on the wire |
| A4 | Linux + Windows + bare metal (Hermit, virtio-net) | Thin swappable platform layer; core builds for `no_std + alloc` |
| A5 | No disk I/O; logs to stderr | One narrow exception: six lifecycle events to the Windows Event Log (#192) |
| A6 | Maximal client compatibility, permissive time band | Defaults say *yes*; strictness is opt-in at build time |
| A7 | Sans-io core | Protocol crates take `&[u8]` → events; sockets live at the edges; fuzzable and cross-testable |
| A8 | Reuse crates, don't reimplement | Exactly two justified exceptions, both in #41 |
| A9 | Anti-fingerprinting | The 24 documented behavioural mismatches are a *test suite*, not a wish list |
| A10 | Cross-validate against other implementations | Differential CI against vlmcsd and py-kms is a build gate |
| A11 | Event log + instructions on an in-process web server | Bounded in-memory ring buffer; the primary operator surface |
| A12 | Docker + Nix flake + OS image as GHA artifacts | Reproducible, provenance-stamped |

---

## Decisions taken

| # | Decision | Outcome |
|---|---|---|
| 1 | Crate split | 8 crates; `web` folded into `server`; `dbgen` and `crypto` separate for dependency isolation and audit boundary (#1) |
| 2 | Framing | `zerocopy` end to end, including checked prefix-splitting for variable DCE/RPC sections (#11) |
| 3 | Panic-freedom | Lints everywhere + a symbol-level CI gate on `proto`/`crypto` + `panic = "abort"` (#9) |
| 4 | Concurrency | tokio on Linux/Windows; blocking `std::net` + `std::thread` on Hermit (#5) |
| 5 | Crypto | One minimal Rijndael in `kmsrs-crypto` with exhaustive KATs, quarantined as the A8 exception (#41) |
| 6 | Product-data source | Microsoft `pkeyconfig` artifacts, extracted by `kmsrs-dbgen` (#125, #126) |
| 7 | Product gate | **Split**: permissive on unknown KMS IDs; strict on retail/preview and AppID mismatch (#98) |
| 8 | Reported client count | Per-client views over a saturating shared world model (#89) |
| 9 | Overcharge poisoning | Dissolved — no longer representable (#93) |
| 10 | Per-SKU quotas | Declined → [D14](#d14) |
| 11 | RPC fragmentation | Implement, **inbound reassembly only** (#80) |
| 12 | Source-IP ACL | Default allow-all; CIDR allow/deny lists available (#101) |
| 13 | Runtime config | Doctrine: rebuild from the flake. Escape hatch: one env var, wire-invisible fields only (#167) |
| 14 | Log format | JSON Lines; ANSI only when stderr is a TTY and `NO_COLOR` unset (#178) |
| 15 | Windows Event Log | Narrow exception: six lifecycle/fatal events only (#192). Linux syslog declined → [D7](#d7) |
| 16 | Metrics | `/metrics` in Prometheus text format, including an entropy-health gauge (#189) |
| 17 | Web UI | Read-only — under A5 there is nothing durable to mutate (#186) |
| 18 | Socket activation | Supported, `Accept=no` only, hard refusal on `Accept=yes` (#165) |
| 19 | Linux hardening | Privilege drop + Landlock + seccomp; socket activation makes privileges unnecessary (#197, #199) |
| 20 | Windows hardening | Self-applicable process mitigations only; AppContainer skipped, asymmetry documented (#197) |
| 21 | Windows service | Dispatcher + control handler; **no installer**; web UI mandatory in service mode (#245) |
| 22 | SRV publishing | RFC 2136 dropped → [D15](#d15). Instructions page emits zone snippet, `nsupdate` **and** `dnscmd`/PowerShell (#148) |
| 23 | mDNS | Measurement harness first, as a standalone deliverable (#146) |
| 24 | `TCP_NODELAY` | OS default; measured in the harness (#164) |
| 25 | Proxmox | Nice-to-have. QEMU/libvirt is the supported configuration (#255) |
| 26 | OS packages | `.deb`/`.rpm` as CI artifacts; no repo, no Homebrew (#246) |
| 27 | Kubernetes | Plain manifests, `replicas: 1` hardcoded. No Helm → [D17](#d17) |
| 28 | Linux appliance image | Skipped → [D16](#d16) |
| 29 | Upstream proxy / chaining | Declined → [D12](#d12) |
| 30 | Build-time identity harvesting | Out of scope → [D13](#d13) |
| 31 | C library API | Declined → [D8](#d8) |
| 32 | Hermit addressing | DHCPv4, on by default (#254) |
| 33 | ePID day-of-year / LCID / channel | 1-based / unpadded / always `03` (#109–#111) |
| 34 | Win 11 build 28000 | Real, ships 2026-02-10 — include (#135) |
| 35 | Licence | MIT (#206) |

### Notes on the three decisions that took the most argument

**Reported client count (#89).** A real host caches *2N* CMIDs and reports how many are cached, so it
saturates at 50 (client) / 10 (server and Office) — the same number both existing emulators emit by
arithmetic. Our model computes `world = min(P_app + R_app, 2 * NCountPolicy_app)` from real observed
CMIDs, then `reported = max(world, client_N_Policy)` **per request, never written back**. The last
clause is what matters: an anomalous demand is satisfied for that client alone. The detection surface
is nil, because every honest client with the same `N_Policy` sees the same number.

**Overcharge poisoning (#93).** A genuine KMS host can be permanently disabled by an overcharge
request of ≥376 required clients followed by 671 activations, and vlmcsd is deliberately
bug-compatible with only a restart to recover. Under the per-client view model an anomalous demand
never mutates global state, so the attack has no target. This is not a mitigation — the attack
becomes unrepresentable.

**Product gate (#98).** Three gates with opposite risk profiles, which is why lumping them into one
bitmask (vlmcsd) or ignoring them entirely (py-kms) are both wrong. Refusing an *unknown* KMS ID must
never happen — it is why a 2019-era vlmcsd still activates Windows 11, and py-kms's crash on an
unknown GUID is the mechanism behind the "Server 2022 doesn't work" reports. Refusing
*retail/preview* costs nothing, because retail SKUs have no GVLK and no legitimate client can send
one, and it closes a cheap probe. Only viable because our data source gives accurate flags.

---

## Declined, with rationale

Nothing here has an issue. That is the point — these are recorded so they are not rediscovered and
re-proposed.

<a id="d1"></a>**D1 — Active Directory-Based Activation (ADBA).** A different mechanism entirely
(LDAP activation objects, no SRV, no port, no threshold). Out of scope for a KMS RPC emulator, while
noting its existence caps how much a perfect KMS emulator is worth.

**D2 — Multi-tenancy (per-listener or per-peer identity).** Nobody implements it; no coherent use
case when identity is baked in at build time.

**D3 — High availability / shared client-count state.** Requires shared external state, which A5
forbids. See also #248: multi-replica breaks the stable-ePID property outright.

**D4 — RPC authentication (sec_trailer / SPNEGO / NTLM).** Real KMS clients never authenticate. We
still handle an inbound `AuthLength` safely (#84) rather than echoing it into a trailer-less
bind_ack the way py-kms does.

**D5 — Runtime configuration beyond the single env var**: CLI options, per-knob env vars, config
files, SIGHUP reload, re-exec restart. Removes vlmcsd's entire ini surface (prefix matching, trailing
spaces, three-pass parsing, reversed ePID precedence, an undocumented restart flag), py-kms's custom
argv pre-validator, and radawson's YAML layering.

**D6 — Disk persistence**: SQLite, log files, rotation, pidfiles, external data files, temp files,
config pickles. Removes py-kms's whole SQL layer and its TOCTOU races, its log rotation (documented
in MB, actually 0.5 MiB per unit), and its pickle-from-a-world-writable-tempdir RCE. Replaced by the
in-memory event log (#180).

<a id="d7"></a>**D7 — Linux syslog, and general-purpose Windows Event Log streaming.** systemd
already captures stderr into the journal, so the Linux gap does not exist. On Windows a *narrow*
six-event exception is made (#192) because a service has no stderr; the request stream is still not
sent to the Event Log. Note vlmcsd's syslog opens and closes the log per message and emits everything
at `LOG_INFO`, and its event-log code is entirely commented out.

<a id="d8"></a>**D8 — `libkms`-style C ABI embedding library.** Not thread-safe by construction in
the original (nine mutable globals), strips the product database so the embedder must synthesize the
ePID, and leaks `#define client_main main` into every consumer's translation unit. A Rust library API
falls out of the crate split for free; a C ABI does not.

**D9 — Desktop GUI.** The web UI supersedes it. Upstream py-kms's GUI auto-launches whenever stdout
is not a TTY, so redirecting output on a desktop opens a window instead of running headless.

**D10 — Pluggable crypto backends and hardware-AES hacks.** vlmcsd's OpenSSL binding targets the dead
1.0 API, its PolarSSL backend cannot use mbed TLS, and its AES-NI path builds a tweaked round key and
pokes it into OpenSSL's private `AES_KEY` struct — which its own header calls "DANGEROUS". An
independent fork deleted all of it with no functional consequence.

**D11 — vlmcsd-scale compile-time feature stripping** (~30 macros, 7 presets) and the multi-call
binary. Exists for OpenWrt-class targets we do not have, and is why 21 of vlmcsd's 119 audited
features are build-gated rather than simply present.

<a id="d12"></a>**D12 — Request-time upstream forwarding / caching proxy.**

<a id="d13"></a>**D13 — Build-time ePID/HwId harvesting from a genuine KMS host.** Out of scope.
Random-per-process HwId (#118) is the floor instead.

<a id="d14"></a>**D14 — Per-SKU activation quotas.** The exact inverse of the per-client view model
(#89), which guarantees one client's request never constrains another's, while a quota makes every
grant mutate shared state so it can deny a later client. Contradictory principles in one layer. It
also cannot work: the only available key is the CMID, a client-chosen UUID that clients regenerate
freely — vlmcs makes a fresh one per request by default — so the cap is bypassed by normal behaviour,
not by attack. The underlying want is better served by rate limiting keyed on `(source IP, app)`,
i.e. on something the client cannot choose.

<a id="d15"></a>**D15 — SRV publishing via RFC 2136 dynamic DNS update.** AD DNS defaults to
secure-updates-only and real hosts use **GSS-TSIG** with machine-account Kerberos credentials, so
shared-key TSIG does not serve the primary use case, and GSS-TSIG needs runtime secrets. For
BIND-style managed DNS, a static record added once is equally easy and more auditable. It would also
embed a secret in the shipped artifact, so the published container could never enable it. The
instructions page (#148) delivers the value instead.

<a id="d16"></a>**D16 — Linux appliance image (kernel + initramfs).** Not the hedge it appeared to be:
if Hermit-on-Proxmox fails, the fallback is a normal Linux VM running the container or the `.deb`,
which needs nothing from us. Its only unique property is minimalism, which is Hermit's entire reason
for existing. Revisit only if Hermit is abandoned, at which point it replaces rather than supplements
the OS image.

<a id="d17"></a>**D17 — Helm chart.** Helm's value is parameterization, and the parameter operators
would reach for first — `replicaCount` — is the one that must never change, because multi-replica
gives each pod its own ePID and reintroduces the canonical detection test at the infrastructure
layer. Plain manifests with `replicas: 1` hardcoded (#248).

**D18 — Non-Windows/Office product entries** (Visual Studio, SQL Server, SCCM). Not covered by the
extraction pipeline, and hand-copying fork data is the practice that produced every fabricated GUID
found in the audits. The cost of omission is small: those clients still activate, they simply log as
a raw GUID and receive a Windows-group ePID. Two of the four entries are flagged "can only be applied
manually", hinting they may not use the KMS RPC path at all. Revisit if a Microsoft artifact surfaces.

**D19 — Hand-curated product data from fork catalogs.** Data ships through the extraction pipeline
(#126) or it does not ship.

**D20 — inetd / xinetd mode, and systemd `Accept=yes`.** One process per connection destroys both the
CMID table and the stable ePID. #165 detects and refuses it rather than degrading silently.

**D21 — Windows TAP/TeamViewer-VPN adapter mirroring.** 370 lines of driver IOCTLs, an internal DHCP
server and a packet-rewriting thread, all to work around Windows clients refusing to activate against
127.0.0.1. The constraint is documented instead (#163).

**D22 — Free-binding (`IP_FREEBIND`/`IP_BINDANY`).** Niche, and vlmcsd's IPv6 path sets it at the
wrong socket level so it can never work — a failure hidden behind a debug-only build flag.

**D23 — Server idle-lifetime timeout.** py-kms's is documented as per-client inactivity but is
actually a total-process-lifetime cap, computed once before the accept loop and never rearmed, whose
expiry terminates the whole server.

**D24 — Background daemonization in-process.** Supervisors do this. vlmcsd's `daemon(nochdir=1, …)`
does not even `chdir` to `/`; py-kms's vendored daemonizer has a no-op `reload`, a Linux-only
`status`, a `chdir('/')` that breaks every relative path, and the pickle RCE.

**D25 — GeoIP enrichment.** Ships client IPs to a third-party HTTP API over plain `urllib`, on by
default in the fork that added it. Privacy-hostile and A5-violating.

**D26 — Docker self-update from the web UI.** Requires mounting the Docker socket, making any web-UI
compromise equivalent to host root.

**D27 — Web UI authentication, CSRF, rate limiting, sessions.** Unnecessary while the UI is read-only
(#186). Reopens the moment mutation is added.

**D28 — Client allowlist keyed on `WorkstationName`.** Client-supplied and trivially spoofable. The
two forks that tried produced a V6-bypassable gate and a `sys.exit(0)` from inside a request handler
that takes the whole server down with a log line blaming a bind failure.

**D29 — Bootable 1.44 MB floppy.** Superseded by the UEFI disk image (#253). vlmcsd documented one but
never committed the image or its build scripts.

**D30 — Microsoft `rpcrt4` RPC backend on Windows.** Delegating to the OS removes control over exactly
the fields that matter for detection resistance, caps requests at 384 bytes, and weakens peer
filtering because RPC negotiation completes before the server sees the client.

**D31 — Unbounded history and reporting.** The event log is a bounded ring buffer with retention.

**D32 — LLMNR, NetBIOS and WPAD-style discovery.** LLMNR carries no SRV records at all, so it cannot
express a KMS host. Ruled out on paper, not by experiment.

**D33 — Reimplementing DNS, standard AES, SHA-256, HMAC, HTTP, TLS or binary framing by hand.**
Two exceptions, both in #41.

### Superseding decision — one mio event loop, not two drivers (`ARCH-005`, #5)

`ARCH-005` originally specified **tokio on Linux and Windows, blocking `std::net` + `std::thread` on
Hermit** — two drivers, on the reasoning that tokio has no usable Hermit support. The first half of
that reasoning is right and the conclusion was wrong: the alternative to tokio is not threads, it is
**mio**, which is the layer tokio itself uses.

Per `docs/research-findings.md` §R2, mio has first-class Hermit support in the stock crates.io
release and hermit's own CI exercises it on every pull request; its backends are epoll on Linux, IOCP
on Windows and `poll(2)` on Hermit. tokio, by contrast, works there only through a four-commit fork
of 1.45.0 whose substantive patch is a level-triggered selector workaround — and tokio's readiness
caching assumes edge-triggered semantics, so getting it wrong produces *hangs, not errors*. Adopting
that fork would need a workspace-global `[patch.crates-io]`, pinning Linux and Windows to it too.

One loop removed three hand-built mechanisms, two of which were untestable:

- **Timeouts.** There is no `SO_RCVTIMEO` anywhere. A deadline is the poll timeout, computed from the
  injected clock, so it behaves identically on every target — including Hermit, whose `setsockopt` is
  a stub returning `EINVAL` for exactly that option. The previous design chose between a socket
  timeout and a hand-written polling fallback *at runtime*, and no test ever executed the fallback
  branch despite it existing solely for Hermit (`OS-014`, #297).
- **The shutdown wakeup.** `mio::Waker` is an eventfd on Linux and Hermit and a posted IOCP
  completion on Windows. The previous design woke a blocked `accept()` by connecting to its own
  listener, which assumed a loopback route Hermit may not have (`OS-015`, #298).
- **Thread-per-connection.** A connection is a few kilobytes in a map rather than an OS thread, which
  is what makes the connection ceiling derivable rather than picked (`NET-014`, #296).

What one loop does *not* solve is the reason the platform split existed at all: Hermit's socket
**semantics**. No readiness abstraction models "this platform's `setsockopt` is a stub", that `bind()`
ignores the address, that there is never an IPv6 address, or that `cfg(unix)` is false. Those remain
per-target facts, and the pattern for them is `SINGLE_SOCKET_ONLY` — a named capability whose *both*
branches compile and are tested on every host, rather than a `cfg` on an item, which only ever
compiles on the platform that cannot be tested.


**D34 — A `MinActiveClients` field per host key (`POL-009`, #97).** The field is inert in both
existing implementations, for opposite reasons. vlmcsd declares it in `KmsData->CsvlkData` and reads
it in `kms.c` to floor the reported count, but nothing ever writes it and it is 0 for every CSVLK in
the shipped blob, so the floor does nothing. py-kms carries it in `KmsDataBase.xml` with real-looking
values — 50 for Windows, 10 for each Office application — and no code path anywhere reads it. Those
two numbers are exactly the saturation values the client-count model computes from `2N`, so the
concept is subsumed rather than dropped: `POL-001` (#89) produces them from observed clients instead
of from a constant nobody populated. Carrying a dead column would invite someone to populate it later
with a value that fights the model.

**D35 — A build-time flag reproducing a genuine host's `0xC004D104` client-table refusal
(`POL-007`, #95).** The issue proposed keeping the refuse path behind a strict flag. Its own reasoning
rules it out: with per-client views (`POL-001`, #89) the 671-entry cap is never reached in a way that
matters, and evicting the oldest entry is strictly more compatible than refusing. A flag whose only
effect is to make the server refuse a request it could have answered is a fingerprint, not a
hardening measure — the same shape of mistake as `POL-011`'s clock-skew tolerance, which is itself a
detection oracle. `HResult::InvalidActivationData` remains in the vocabulary so `kmsrs-client` can
name the code when a *real* host sends one. The neighbouring question for `N_Policy` is left open as
#283 rather than declined, because a differential test against a genuine host could still turn up a
divergence there.

**D36 — Honouring py-kms's `InvalidWinBuild` per CSVLK (`ID-017`, #122).** The *intent* is sound — a
host key should not be paired with a host build that could not have had it installed — but the field
itself cannot be adopted. It exists only in py-kms's `KmsDataBase.xml`, it is hand-entered, and its
values are **indices into py-kms's own `WinBuild` table** (`[0,1,2]`, `[0]`, `[]`), so they carry no
meaning outside that file's row order. No Microsoft artifact contains it, or anything equivalent:
`pkeyconfig` gives `ActConfigId`, `RefGroupId`, `EditionId`, `ProductDescription`, `ProductKeyType`
and `IsRandomized`, and nothing about host builds. Copying the values would be exactly the practice
that produced every fabricated GUID the audits found. The constraint is worth enforcing, so it is
reopened as #286 in the form that has a real data source — deriving each host key's earliest build
from the images its `pkeyconfig` appears in — rather than closed outright.

**D37 — vlmcsd-scale feature stripping (`CFG-011`, #176).** vlmcsd carries roughly 30 preprocessor
macros and 7 build presets whose purpose is to shrink the binary for OpenWrt-class embedded targets —
`NO_LOG`, `NO_CLIENT_LIST`, `NO_STRICT_MODES`, `NO_HELP`, `NO_TIMEOUT`, `ONE_FILE` and the rest. They
are why 21 of the 119 rows in its feature matrix are build-gated rather than simply present, so a
statement about "what vlmcsd does" is really a statement about one of 2^n vlmcsd builds.

The targets that motivated them are not targets here (axiom A4: Linux, Windows, and Hermit on
x86-64). Buying a smaller binary with a combinatorial explosion of behaviours is a bad trade when
every build has to be differentially tested against a reference — the number of artifacts to test
would grow faster than confidence in any of them. The two build-time flags that do exist
(`permissive-retail`, `strict-clock-skew`) each change behaviour a deployment might genuinely need
changed, and CI builds the **whole powerset** rather than a sampled subset (`CFG-010`, #175).

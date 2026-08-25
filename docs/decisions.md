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
| A1 | Pure safe Rust | `#![forbid(unsafe_code)]` in every crate, with no exception — the one documented boundary went with Hermit (#334) |
| A2 | Correct by construction | Illegal states unrepresentable; no runtime panics; no runtime validation of what a type could carry |
| A3 | Configuration is compile-time | One narrow runtime escape hatch, restricted to settings that cannot change a byte on the wire |
| A4 | Linux + Windows + bare metal (Linux as PID 1, virtio-net) | Thin swappable platform layer; core builds for `no_std + alloc` |
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
| 1 | Crate split | 7 crates; `web` folded into `server`; `dbgen` and `crypto` separate for dependency isolation and audit boundary. Was 8 until `kmsrs-os` went with Hermit (#1, #334) |
| 2 | Framing | `zerocopy` end to end, including checked prefix-splitting for variable DCE/RPC sections (#11) |
| 3 | Panic-freedom | Lints everywhere + a symbol-level CI gate on `proto`/`crypto` + `panic = "abort"`; [what the gate found](#what-the-panic-freedom-gate-actually-found-arch-009-9) (#9) |
| 4 | Concurrency | One `tokio` runtime, one task per connection. Superseded mio, which had superseded a two-driver plan, [see below](#superseding-decision--one-tokio-runtime-arch-005-5-os-024-340) (#5, #340) |
| 5 | Crypto | One minimal Rijndael in `kmsrs-crypto` with exhaustive KATs, quarantined as the A8 exception (#41) |
| 6 | Product-data source | Microsoft `pkeyconfig` artifacts, extracted by `kmsrs-dbgen` (#125, #126) |
| 7 | Product gate | **Split**: permissive on unknown KMS IDs; strict on retail/preview and AppID mismatch (#98) |
| 8 | Reported client count | Per-client views over a saturating shared world model (#89) |
| 9 | Overcharge poisoning | Dissolved — no longer representable (#93) |
| 10 | Per-SKU quotas | Declined → [D14](#d14) |
| 11 | RPC fragmentation | Implement, **inbound reassembly only** (#80) |
| 12 | Source-IP ACL | Default allow-all; CIDR allow/deny lists available (#101) |
| 13 | Runtime config | Doctrine: rebuild from the flake. Escape hatch: one env var, wire-invisible fields only (#167) |
| 14 | Log format | JSON Lines; ANSI only when stderr is a TTY, the terminal understands it, and `NO_COLOR` is unset (#178, #162) |
| 15 | Windows Event Log | Narrow exception: six lifecycle/fatal events only (#192). Linux syslog declined → [D7](#d7) |
| 16 | Metrics | `/metrics` in Prometheus text format, including an entropy-health gauge (#189) |
| 17 | Web UI | Read-only — under A5 there is nothing durable to mutate (#186) |
| 18 | Socket activation | Declined → [D40](#d40). The binary refuses to start if `LISTEN_FDS` is set, rather than degrading |
| 19 | Linux hardening | Landlock + seccomp (#197); privilege drop declined → [D41](#d41), because there is never a privilege to drop |
| 20 | Windows hardening | Self-applicable process mitigations only; AppContainer skipped, asymmetry documented (#197) |
| 21 | Windows service | Dispatcher + control handler; **no installer**; web UI mandatory in service mode (#245) |
| 22 | SRV publishing | RFC 2136 dropped → [D15](#d15). Instructions page emits zone snippet, `nsupdate` **and** `dnscmd`/PowerShell (#148) |
| 23 | mDNS | Measurement harness first, as a standalone deliverable (#146) |
| 24 | `TCP_NODELAY` | OS default; measured in the harness (#164) |
| 25 | Supported hypervisors | Proxmox is the reason the bare-metal target changed, and is no longer the whole answer: a stated matrix, one boot check per NIC model, [see below](#vmbus-is-in-and-firecracker-is-out-os-025-342) (#255, #333, #334, #342) |
| 26 | OS packages | `.deb`/`.rpm` as CI artifacts; no repo, no Homebrew (#246) |
| 27 | Kubernetes | Plain manifests, `replicas: 1` hardcoded. No Helm → [D17](#d17) |
| 28 | Linux appliance image | **Built** — reverses [D16](#d16); it is now the bare-metal target (#333) |
| 29 | Upstream proxy / chaining | Declined → [D12](#d12) |
| 30 | Build-time identity harvesting | Out of scope → [D13](#d13) |
| 31 | C library API | Declined → [D8](#d8) |
| 32 | Bare-metal addressing | DHCPv4, spoken by `kmsrs-os` itself. `CONFIG_IP_PNP_DHCP` removed, so one implementation rather than two, [see below](#the-bare-metal-target-speaks-dhcp-and-dns-itself-os-019-335-os-020-336) (#254, #335) |
| 33 | ePID day-of-year / LCID / channel | 1-based / unpadded / always `03` (#109–#111) |
| 34 | Win 11 build 28000 | Real, ships 2026-02-10 — include (#135) |
| 35 | Licence | MIT (#206) |
| 36 | Absurd `N_Policy` | Floor the reported count at the demand only up to 100; past that report the world, [see below](#absurd-n_policy-pol-019-313) (#313) |
| 37 | ~~Hermit build~~ | Removed with the target (#334). Kept in history because `PKG-013`/`PKG-014` (#250, #251) are cited in commits |
| 38 | Bare-metal target | Linux with `kmsrs-server` as PID 1. Reverses [D16](#d16); **replaced** Hermit rather than joining it, [see below](#hermit-was-removed-rather-than-kept-os-018-334) (#333, #334) |

### The bare-metal target speaks DHCP and DNS itself (`OS-019`, #335; `OS-020`, #336)

The kernel's `ip=dhcp` was a stopgap for one stated reason — it takes a lease and never renews it —
and for a second that turned out to matter more: **it discards every option this host actually
wants.** Option 15 and option 119 are the domain the clients search, which is the zone an SRV record
has to go in and which `/instructions` had no way to know (`DISC-007`, #149). Option 42 is the time
source `OS-020` prefers over anything on the internet.

So `kmsrs-os` owns the client, `CONFIG_IP_PNP_DHCP` is gone, and there is one implementation rather
than two that can disagree.

**The crate choices changed during the work, and the reason is worth recording.** `OS-019` nominated
`dhcproto` — correctly: it is a sans-io parser and encoder, actively maintained, and nothing else in
the field is both. What the issue did not check is that it depends on `hickory-proto`
**unconditionally**, for the DNS name type option 119 is made of. That is a complete DNS protocol
implementation, and `url`, `idna` and the ICU data crates arrive with it: about forty crates for a
236-byte header and a TLV list, in the boot path of a machine whose TCB claim is a checked-in
config a reviewer can read. One of them is `tracing`, which `deny.toml` bans.

That very nearly settled it against `dhcproto`. What reversed it was noticing that **`OS-020` needs
a resolver anyway**. Its pool fallback is a *hostname*, this machine has no `/etc/resolv.conf` for a
libc resolver to read (axiom A5), and nothing in the tree resolved a name before this. So the choice
was never "a DNS library or not" — it was "one, or two implementations of half of one". The library
is paid for once and both issues spend it.

Consequences worth stating:

- **`hickory-resolver`'s `system-config` feature is off.** That feature is what reads
  `/etc/resolv.conf`. The resolver is configured from DHCP option 6 instead, in memory, which is an
  observation about the network rather than configuration (`CFG-001`, #166). Turning it off also
  drops the macOS and Windows system-configuration crates.
- **The `tracing` ban gains a `wrappers` list**, as `log` right above it already had. The stated
  reason for both — stop a facade with a pluggable file sink appearing in *our* code, because axiom
  A5 forbids the file — applies identically, and a transitive `tracing` with no subscriber installed
  is as inert as a transitive `log` with no logger. The asymmetry was an oversight. It did useful
  work while it lasted: the ban is what forced the look at the dependency tree that found the DNS
  library in the first place.
- **None of this is reachable from `kmsrsos` or `kmsrs-client`.** Nothing they depend on names
  `kmsrs-os`, which is the same property the `kmsrs-dbgen` split relies on and which
  `dbgen_is_unreachable_from_every_shipped_binary` is the pattern for.

**The lease state machine is still written out**, because no crate offers RFC 2131 §4.4 separately —
every existing Rust client welds INIT/SELECTING/REQUESTING/BOUND/RENEWING/REBINDING to sockets or to
netlink. That is the part axiom A7 wants sans-io anyway, so it takes a `Duration` and a message and
returns actions, and the whole of it is exercised against captured exchanges with no network.

### VMBus is in, and Firecracker is out (`OS-025`, #342)

Decision 25 said "Proxmox is supported". What the rest of the world got was "whatever happens to
work", and measuring it turned out worse than "untested": of the four NIC models the Proxmox web UI
itself offers, two produced a machine that booted to completion, printed `listening`, and then served
nobody forever. No driver, so no interface, so no address, and nothing said so. That is the failure
class Hermit was removed for (`OS-018`, #334), reachable from a dropdown on the supported path.

**VMBus is accepted.** Hyper-V Generation 2 has *no emulated NIC at all* — there is no PCI device to
fall back to — so `CONFIG_HYPERV` and `CONFIG_HYPERV_NET` are not a nice-to-have on that platform,
they are the difference between supported and unsupported. Hyper-V and Azure are targets, so the bus
is in, and the comment in `os/linux/config.nix` that called it "not a driver-sized cost" is replaced
rather than left to contradict this. The cost is measured rather than argued: see the table in that
file, produced by `nix build .#linux-deltas`.

**Firecracker is declined**, and as [D42](#d42) rather than left unscoped, because the reason is
structural rather than a matter of effort.

**Two things this changed about how the file is maintained.** Both came out of the work rather than
going into it:

- **`nix build .#linux-deltas`** measures a config change on the built `bzImage` with the initramfs
  held constant. The initramfs is *inside* the image, so measuring a 40 kB driver against the shipped
  kernel compares two numbers that differ for two reasons — which is how a driver's cost gets
  estimated instead of measured.
- **`kernel_tcb.rs`** asserts what is in the machine's TCB against the **generated** config rather
  than the allowlist, in both directions: the subsystems that must stay out, and the drivers this
  matrix promises. The second half exists because `OS-023` (#339) is a pare-back and this is a
  matrix, and they pull on the same file in opposite directions.

That test found the `OS-006` (#257) lesson recurring a third time. `CONFIG_DEBUG_KERNEL` had been on
the *disable* list for two issues and was on in every build, because `tinyconfig` requires
`CONFIG_EXPERT` and `EXPERT` selects it. It is a menu gate rather than code and costs nothing, so the
entry was a statement the build could not make; it is replaced by the ten options underneath it that
would cost something.

### The kernel is in the ISO twice, and stays there (`OS-023`, #339)

The `bzImage` appears once in the ISO9660 filesystem for isolinux and once inside the FAT ESP for
firmware, because the two read different filesystems and neither reads the other's.

**It also appears a third time**, which was not noticed while this decision was being taken: `-e
efi.img` boots the ESP as a file in the ISO tree, and `-append_partition` appends a *second copy* of
that same ESP to serve as the GPT partition `OS-027` (#344) needs. Three kernels is 10.6 MB of a
16.3 MB image. That duplicate is a separate question with a different answer — it needs no
bootloader, only a different xorriso incantation — and is #347. What follows is about the first two
only. `OS-023` asks whether to spend a GRUB to recover it — grub-efi reads ISO9660, so
only a ~1 MB `grubx64.efi` would need to live in the ESP.

**Keep the duplication.** Four reasons, in the order they matter:

1. **It would put a bootloader in an image whose contents are enumerable in a sentence.** GRUB is a
   program with a configuration language, a module loader and a filesystem stack. Today the UEFI
   path has *no bootloader at all* — `CONFIG_EFI_STUB` makes the kernel the EFI executable — and
   that is a TCB statement, not a size one.
2. **It would give the UEFI path something to go wrong.** Nothing is registered in NVRAM and nothing
   is chainloaded, which is why a fresh Proxmox VM boots on its first try and `OS-004` (#255) is not
   a problem here. Adding a stage between firmware and kernel adds a stage that can fail.
3. **The ESP is load-bearing now.** `OS-027` (#344) makes the same file a GPT disk with a typed EFI
   System Partition, which is what the EC2 pipeline imports. Replacing the kernel in the ESP with a
   bootloader that reads ISO9660 works for a CD and not for a raw disk import.
4. **Nothing is paying for it at runtime.** The machine runs from RAM; the ISO is downloaded once and
   attached. 2.7 MB is a transfer cost, not a memory or a boot cost.

The related proposal on the same issue — dropping `-append_partition` to recover ~5 MB — is declined
for reason 3 alone: that partition *is* the EFI System Partition, and `OS-027` (#344) needs it.

### SNTP, not NTP, and the host serves without it (`OS-020`, #336)

Two decisions this issue asked to be made explicitly rather than by default.

**Why SNTP.** The difference that matters is the discipline loop: full NTP estimates the local
oscillator's frequency error and *slews* continuously, so the clock stays right between polls and
never jumps. Three things rule it out here, in descending order of finality.

1. **There is nothing to slew with.** `adjtimex` has no safe binding in rustix, so axiom A1 leaves
   `clock_settime` as the only move available. "SNTP with slewing" is not on the menu, and a
   discipline loop with nothing to drive is not a discipline loop.
2. **There is nothing to reuse.** `ntpd-rs` is a daemon, not a crate to embed. A hand-written PLL
   would be a far larger A8 exception than the lease state machine, for a clock that feeds a ±4 hour
   tolerance.
3. **The platform already handles drift.** Every hypervisor in `OS-025` (#342)'s matrix gives the
   guest kvmclock, the Hyper-V reference TSC or an equivalent that tracks the host continuously. The
   case SNTP helps is the RTC-only one, where a step every seventeen minutes is ample.

What is given up, stated rather than glossed: **falseticker rejection**. The first usable answer is
taken rather than several compared, so a lying option-42 server is believed. Acceptable because the
DHCP server that named it already controls this host's address and routing.

**Why an unreachable time server is not fatal.** The issue asks for "serve with the unsynchronised
clock, or refuse — decided explicitly". It serves, because the clock turns out to reach almost
nothing: nothing in a response derives from it, every deadline is monotonic, and the one wall-clock
read happens once at start-up. A KMS host that refused to activate anything because it could not
reach an NTP server would be trading its whole function for a log field.

That last point deserves an asterisk found while doing the work: **the skew check does not run at
all today**, because `driver.rs` passes `host_time: None` on every request. `POL-011` (#99) is inert
and `strict-clock-skew` changes nothing. Filed as #346 (`POL-020`) rather than fixed here.

### Hermit was removed rather than kept (`OS-018`, #334)

Both targets worked. The question was never which one *ran*, it was which one an operator could
deploy without being told three things first, and Hermit needed all of: `qm set --args
'-set device.net0.disable-legacy=on'` for a NIC that would otherwise not attach at all (`OS-004`,
#255), a CPU-model change away from the Proxmox default or the CSPRNG silently fell back to a
31-bit LCG (`OS-016`, #332), and a serial port added before first boot, because it is the only
console Hermit has and without it the other two failures are invisible. The web UI can express one
of those three.

Worse, the failure was quiet. QEMU runs with `-no-shutdown`, so when the guest exited 69 the process
stayed and the run state parked at `prelaunch` — `qm status` said so, but the API's `status` field,
which is what the green dot in the web UI reads, still said `running` and the uptime kept climbing.

The Linux target needs none of the three, boots from SeaBIOS or OVMF, and is smaller (14 MB against
17 MB). Keeping both would have meant two bare-metal targets with their own boot checks, their own
differential runs and their own section of the deployment guide, for one deployment story — and the
one being kept for interest's sake would be the one nobody could deploy.

**What was actually lost.** A5 was *inexpressible* on Hermit rather than merely absent: there was no
syscall to reach a disk. On Linux with `CONFIG_BLOCK` unset it is a syscall with nothing behind it,
which is very close and not identical. That is the whole cost, and it is worth naming rather than
pretending the two were equivalent.

**What was not the argument.** TCB size. It does not survive `SEC-013` (#205): nothing secret ships,
so the blast radius of either kernel is a box that answers KMS on a LAN. A unikernel also has no
privilege separation at all — the application runs in ring 0 with the kernel — so "fewer lines" and
"smaller attack surface" were never the same claim, and the network-reachable surface was smoltcp
against the most heavily fuzzed TCP stack in existence. This decision went the way it did on
deployability, and it should not be re-litigated on TCB grounds.

### Notes on the three decisions that took the most argument

**Reported client count (#89).** A real host caches *2N* CMIDs and reports how many are cached, so it
saturates at 50 (client) / 10 (server and Office) — the same number both existing emulators emit by
arithmetic. Our model computes `world = min(P_app + R_app, 2 * NCountPolicy_app)` from real observed
CMIDs, then `reported = max(world, client_N_Policy)` **per request, never written back**. The last
clause is what matters: an unusual demand is satisfied for that client alone. The detection surface
is nil, because every honest client with the same `N_Policy` sees the same number. The floor stops at
100 — see [decision 36](#absurd-n_policy-pol-019-313), which is where the *absurd* demands go.

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

### Absurd `N_Policy` (`POL-019`, #313)

`POL-006` (#94) answered any declared `N_Policy` with `max(world, N)`, so a client declaring 5000 was
told 5000. That is safe — under `POL-005` (#93) an anomalous demand cannot reach shared state — and
it is nonetheless **a one-packet emulator test**, which is a different question and was not asked
when #94 closed. A genuine host caches `2N` machine IDs and reports how many it is *holding*, so a
machine it has never seen that asks for 5000 is told a small number and does not activate. py-kms
answers `2N`. vlmcsd refuses with `0x8007000D`. All three answers are distinct, and only the first is
what Microsoft's host says.

So the floor now stops at `MAX_TRACKED_REQUIRED_CLIENTS`, which is 100 — four times the largest value
any Microsoft product declares, `N_Policy` being 25 for Windows client SKUs and 5 for server and
Office. Below it nothing changes. Above it the answer is the world: how many machines are cached.

**The compatibility objection does not survive contact with the arithmetic.** Axiom A6 says defaults
say yes, and the fear is a real client failing to activate for a reason nobody can see. But a client
declaring `N_Policy > 100` could never activate against a genuine host either — the host would report
its cache size and the client would compare and fail — so answering it is not compatibility, it is a
lie no real host tells. The clients affected are diagnostic tools and probes, which is exactly the set
that should see the honest answer.

Two things are deliberately *not* done. The count is not floored at 100 for absurd demands, as #313's
own sketch suggested: reporting a plausible-looking 100 to a fresh host holding one machine is still
a sentence no genuine host says, and `world` is simply the true one. And the request is not refused —
that is #283, declined as [D38](#d38).

### The Hermit build does not use the `hermit` crate (`PKG-013`, #250)

`PKG-013` was filed as the largest schedule risk in the project, and it was correct about the shape
of the risk. The documented way to build a Hermit application is to depend on the `hermit` crate.
That crate is not a library: its `lib.rs` is empty for every configuration this project would use,
and its `build.rs` shells out to a nested `cargo run --package=xtask` that builds the kernel from a
git submodule against *its own* lockfile and *its own* pinned nightly. Crane vendors neither. A build
script that runs `cargo` is a build script that wants the network, which is the one thing a Nix build
does not have.

Both options the issue sketched were tried on paper. Carrying two vendored dependency trees and two
toolchains inside one derivation makes the workspace's own build depend on the kernel's nightly. The
other option is what shipped:

* **The kernel is its own derivation.** It builds through the kernel's own `xtask`, not through a
  reimplementation of it, because `xtask build` is not `cargo build` — it rewrites every symbol that
  is not an exported syscall so the kernel's `core` cannot collide with the application's, links in
  `hermit-builtins` for the libm symbols, and stamps `ELFOSABI_STANDALONE` on every archive member.
  Four steps that a shell script could reproduce, until the day upstream adds a fifth.
* **The two link flags are injected directly.** `-L native=…` and `-l static:-bundle=hermit` are the
  whole of what the crate's build script emits for a non-`common-os` target, so nothing is lost by
  not having it — and `tests/hermit_toolchain.rs` fails if the crate ever reappears in the lockfile.
* **The workspace stays on stable.** `hermit-os/rust-std-hermit` is built per exact stable release,
  so pinning it to `rust-toolchain.toml`'s channel avoids `-Z build-std=std,panic_abort`, which would
  have put every crate that ships on nightly.

Two details cost more time than the design did, and both are recorded in tests rather than only here.
`rustc` derives its sysroot from the *resolved* path of its own executable, so a `symlinkJoin`
toolchain finds the original sysroot and reports `can't find crate for core`; the sysroot has to be
named with `--sysroot`. And `-l static=hermit`, which is what upstream emits, makes `rustc` adopt
every member of `libhermit.a` as one of its own objects — the kernel's compiled-C intrinsics have no
`.llvmbc` section, so `lto = "fat"` fails with "failed to get bitcode from object file". `-bundle`
says what was meant. Neither failure appears in a debug build.

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

<a id="d16"></a>**D16 — Linux appliance image (kernel + initramfs). ~~Declined~~ — reopened, see
`OS-017` (#333).** The original reasoning was: if Hermit-on-Proxmox fails, the fallback is a normal
Linux VM running the container or the `.deb`, which needs nothing from us; its only unique property
is minimalism, which is Hermit's entire reason for existing.

The premise did not survive being built. Minimalism is not where a Linux appliance loses — a
`tinyconfig`-derived kernel with `kmsrs-server` as PID 1 and no other userland produces a *smaller*
ISO than the Hermit image (14 MB against 17 MB) and a *stronger* version of axiom A5, because
`CONFIG_BLOCK` is unset: there is no block layer, not merely no block drivers. What it actually has
that Hermit does not is that it boots into service on a Proxmox VM with nothing changed from the
defaults, where the Hermit image needs `qm set --args` (`OS-004`, #255) and a CPU-model change
(`OS-016`, #332), neither of which the web UI can express.

Also wrong: "it replaces rather than supplements the OS image" assumed the choice would be forced by
Hermit failing. It was not — Hermit works, on a VM configured for it. So the disposition is a real
decision rather than a fallback, and it is `OS-018` (#334).

Note what is *not* the argument. The TCB case for either kernel does not survive `SEC-013` (#205):
nothing secret ships, so the blast radius of a compromise is a box that answers KMS on a LAN. A
unikernel also has no privilege separation at all, so "fewer lines" and "smaller attack surface" are
not the same claim. Whichever way #334 goes, it should not go that way because of TCB size.

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
CMID table and the stable ePID. The binary refuses to start on *any* `LISTEN_FDS`, which covers this
and [D40](#d40) with one check — a manager that passes a connection and a manager that passes a
listening socket are both told to stop.

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

<a id="d42"></a>**D42 — Firecracker.** Declined for reasons that are properties of the formats and
the product rather than of effort available (`OS-025`, #342):

- On x86_64 Firecracker boots an uncompressed **ELF `vmlinux`**. `\x7fELF` at offset 0 and the `MZ`
  of a PE/COFF EFI stub at offset 0 are mutually exclusive, so **no single artifact can serve both
  Firecracker and UEFI**. That is arithmetic, not a build problem.
- Device discovery is virtio-**mmio**. Before Firecracker gained ACPI support the
  `virtio_mmio.device=` command-line parameters were mandatory — and `CONFIG_CMDLINE_OVERRIDE`
  (axiom A3, `CFG-001` #166) makes them unreachable by construction. Supporting older Firecracker
  means giving up A3, which is a worse trade than not supporting Firecracker.
- Product fit. Firecracker exists to run short-lived multi-tenant sandboxes; a KMS host is a
  long-lived LAN service with a stable address and an SRV record pointing at it.

If it is ever wanted anyway the answer is a *second output* — the kernel build already produces
`vmlinux` — and not a cleverer ISO.

**Numbering note.** The decisions table links `D34`–`D41`, and no such entries were ever written; the
list runs D1–D33. This one is D42 to avoid colliding with whatever those were meant to be.

### Superseding decision — one `tokio` runtime (`ARCH-005`, #5; `OS-024`, #340)

This has been settled twice, and the second time reversed the first.

`ARCH-005` originally specified **tokio on Linux and Windows, blocking `std::net` +
`std::thread` on Hermit** — two drivers, on the reasoning that tokio has no usable Hermit support.
The first half of that was right and the conclusion was wrong: the alternative to tokio is not
threads, it is **mio**, which is the layer tokio itself uses. So it became one mio loop on all three
targets, and the argument was portability.

`OS-018` (#334) removed Hermit, which removed the only reason mio was chosen. That alone would have
justified rewriting the paragraph rather than the code — mio is a perfectly good event loop for a
server that is only a server. What changed the answer is that `kmsrs-server` stopped being only a
server.

It is **pid 1** on the bare-metal target (`OS-017`, #333): the entire userland. What a userland does
is run several things on timers at once — DHCP renewal at T1 and T2 (#335), SNTP polling (#336),
`SIGCHLD` reaping and an ACPI power-button watch (#337), a virtio-serial guest-agent channel (#338),
and the entropy re-test that was already there. **mio has no timers.** Every one of those deadlines
would have been hand-rolled bookkeeping against a `poll()` timeout, which is the code that is tedious
to write, easy to get subtly wrong, and unpleasant to test.

What the migration actually cost, and what it did not:

- **The sans-io core did not change at all.** `kmsrs-proto` and `kmsrs-policy` still take `&[u8]` and
  a clock reading (axiom A7). This is the second time that split has paid for itself in one week —
  the bare-metal target changed operating system and then changed I/O driver, and neither crate
  noticed.
- **Connection deadlines moved to tokio's clock.** They were computed against an injected closure
  (`ARCH-004`, #4), which made timeout tests deterministic; they now use `tokio::time`, and the tests
  use `#[tokio::test(start_paused = true)]`. That is strictly better than it sounds: the two deadline
  tests went from 62 seconds of real waiting to 0.05 seconds, because a paused clock jumps to the
  next timer instead of sleeping. The injected clock survives where it was always load-bearing — a
  request is still *handed* the instant it happened.
- **`Server::handle` takes `&mut self`**, so the server and the entropy source sit behind one mutex,
  taken per request and never held across an `await`. That is what the single-threaded mio loop did
  anyway; the difference is that reading, writing and waiting now overlap.
- **A current-thread runtime, not a worker pool.** This host answers one 384-byte request per client
  per few hours, and the shared state is serialised regardless, so threads would contend and gain
  nothing — and on a one-vCPU guest a thread-per-core scheduler is a scheduler arguing with itself.

`deny.toml` still bans `async-std` and `smol`. The reason was never "async is bad", it is that a
second runtime is a second scheduler with its own idea of when work runs.

### What the panic-freedom gate actually found (`ARCH-009`, #9)

Decision 3 pairs a lint policy with a symbol-level gate, and the pairing is the point: they catch
disjoint sets of defects, and the second set is the one that reaches production.

`ARCH-008` (#8) denies `unwrap`, `expect`, `panic`, `indexing_slicing` and unchecked arithmetic in
the core crates. That is a policy about panics somebody **writes**. `panic-audit/` links
`kmsrs-proto` and `kmsrs-crypto` into a freestanding `x86_64-unknown-none` binary with the release
profile's own settings and then reads its symbol table, which is a question about panics the
**compiler inserts** — and with the deny list already clean, it found six:

| Where | What | Why the lint could not see it |
|---|---|---|
| `KeySchedule::expand` ×3 | Bounds checks on the key-word loop and the round-constant index | The module deliberately allows indexing, on the sound argument that no attacker-controlled index exists inside the block permutation. True, and irrelevant to whether the check is *elided* |
| `KeySchedule::{encrypt_block, decrypt_block}` | `self.round_keys[self.rounds]` | `rounds` is 10 or 11 by construction, but it is a plain `usize` field and a caller holding `&KeySchedule` gives the optimiser no range to work with |
| `EPid::clone` | `ArrayVec`'s `Clone` collects through `Extend`, which panics on overflow | Source and destination have identical capacity, so overflow is impossible — and invisible to LLVM. Fixed by storing an array and a length, which makes `Clone` a memcpy |
| `Connection::step` | `inbound.drain(..declared).collect()` — `drain` panics past the end, `Extend` panics on overflow | `declared` had just been checked against both bounds three lines earlier |
| `Connection::handle_request` | `reassembly.drain(..).collect()` | Same shape |
| `Connection::next_event` | `events.remove(0)` behind an `is_empty()` guard | The guard makes it unreachable; the optimiser could not put the two facts together |

None of these was a bug — every one was genuinely unreachable, and the tests, the fuzzers and the
golden vectors all passed with them present. That is precisely why the gate is worth having. The
release profile sets `panic = "abort"`, and on Hermit an abort kills the VM with only the hypervisor
able to restart it (`OS-013`, #264): the cost of being wrong about "unreachable" is highest on the
platform with the least ability to recover, and "unreachable" was being asserted by review rather
than by the compiler.

The fixes share a shape. Where the impossibility is real, it is *stated* so the optimiser can use it
— a `min` on a field whose range is known, one extra unread round constant so a quotient is provably
in range — rather than asserted at runtime. Where a panicking API had a `try_` sibling, the sibling
is used and its error branch reports rather than truncates (`SEC-012`, #204). Nothing was silenced
with `unwrap_or`, which would have traded a compile-time-obvious bound for a silently wrong answer.

The check runs on every PR and is self-validating: a second build with `--features inject-panic`
must **fail** the audit, because a check that has never been observed failing is not a check. Both
builds need nightly for `-Zbuild-std`, which is confined to `nix develop .#fuzz` and is the same
nightly the fuzzers use; nothing that ships is built with it.

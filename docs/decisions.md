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
| 39 | Host clock in the request path | One start-up reading, projected by the monotonic clock and re-anchored when SNTP corrects it, [see below](#the-host-clock-is-projected-and-re-anchored-pol-020-346) (#346) |
| 40 | GRUB in the ISO | **Supersedes `OS-023`**: a six-module GRUB with an embedded config takes the kernel to one copy, 8.32 → 5.32 MiB. FAT-only priced and declined, [see below](#the-kernel-is-in-the-iso-once-os-023-339-os-030-348) (#348) |
| 41 | SRV weighting | RFC 2782's running-sum selection, **not** the `isqrt` formula `DISC-001` quoted from vlmcsd, [see below](#the-srv-weighting-is-the-specifications-not-vlmcsds-disc-001-143) (#143) |
| 42 | Self-sandboxing | Landlock and `no_new_privs` after binding, on the hosted build only. seccomp and the Windows mitigations split out, [see below](#the-sandbox-is-what-could-be-verified-sec-005-197) (#197) |
| 43 | `TCP_NODELAY` | Left at the OS default, having been **measured** rather than assumed: Nagle cannot engage in this protocol, so the option is unobservable, [see below](#tcp_nodelay-is-unobservable-so-it-is-not-set-net-015-164) (#164) |
| 44 | Windows mitigations | Five applied through `SetProcessMitigationPolicy`, reopening the unsafe boundary for one call, [see below](#the-unsafe-boundary-was-reopened-for-five-calls-sec-019-356). CFG removed: it produced a binary that did not start (#356) |
| 45 | A second architecture is supported | aarch64, because Proxmox VE for arm64 shipped and KVM is same-architecture — and because on Apple Silicon the whole lab is Arm, [see below](#a-second-architecture-is-supported-os-032-376-pkg-019-378) (#376, #378) |
| 46 | The arm image has no bootloader | `OS-030`'s GRUB solves two firmwares sharing one kernel; aarch64 has one firmware, so the kernel goes in the ESP and nothing loads it, [see below](#the-arm-image-has-no-bootloader-os-033-377) (#377) |
| 47 | Windows on Arm is built and shipped | `aarch64-pc-windows-msvc`, and **neither Windows target is the default** — both are named. It shipped unverified and said so; it is verified now, on a hosted ARM64 runner, and takes all five mitigations, [see below](#the-arm64-binary-runs-and-takes-all-five-mitigations-pkg-022-385) (#379, #385) |

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

### The kernel is in the ISO once (`OS-023`, #339; `OS-030`, #348)

**Superseded.** `OS-023` declined GRUB and kept the kernel in the image twice. `OS-030` re-took that
decision against measured numbers and **took GRUB**. What follows is the decision as it now stands,
with the reasoning that changed.

#### Why it was declined, and what was wrong with the arithmetic

`OS-023` recorded the saving as **"~2.7 MB"**, which was wrong twice over. It counted two kernel
copies where there were three — `-e efi.img` pointed El Torito at a copy of the ESP inside the ISO9660
tree while `-append_partition` appended a byte-identical second copy for the GPT — and it predated the
kernel reaching 3.4 MB. `OS-029` (#347) removed the third copy for nothing, taking the image 16.3 MB →
8.3 MB, so the question had to be asked again against a different number.

#### The measured numbers

| layout | kernel copies | ISO | vs. before |
|---|---|---|---|
| before `OS-029` | 3 | 16.3 MiB | |
| after `OS-029` | 2 | **8.32 MiB** | baseline |
| **with GRUB (shipping)** | **1** | **5.32 MiB** | **−3.00 MiB, −36 %** |

The saving is exactly one copy of the kernel, less the loader that replaced it: the ESP went from
4 MiB holding a 3.38 MiB kernel to 1 MiB holding a **278 KiB** `grubx64.efi`.

That 278 KiB is the number that actually decided this, and it is a quarter of the ~1 MB the issue
estimated. It is small because of *how* the loader is built, which is the same thing that answers the
objection below.

#### What changed the TCB argument

`OS-023`'s two real reasons were never about size, and they were right:

1. It puts a bootloader in an image whose contents are enumerable in a sentence. GRUB has a
   configuration language, a module loader and a filesystem stack.
2. It gives the UEFI path something to go wrong. `CONFIG_EFI_STUB` makes the kernel *itself* the EFI
   executable, so nothing is chainloaded and nothing is registered in NVRAM.

What changed is that reason 1 is a statement about *a* GRUB, not about GRUB. The one in this image is
built with `grub-mkimage` and:

- **six modules, enumerated in the build** — `part_gpt`, `part_msdos`, `iso9660`, `search`,
  `search_label`, `linux`, plus `halt` for the failure path. There is no module directory in the ESP,
  so the module loader has nothing it *can* load.
- **an empty `--prefix`**, so there is nowhere to look for modules or for a `grub.cfg` at run time.
- **the configuration embedded in the PE file**, not on the filesystem. There is no `grub.cfg` in the
  ESP to edit. That is axiom A3 applied to the bootloader exactly as `CONFIG_CMDLINE_OVERRIDE` applies
  it to the kernel command line.
- **no `normal` module**, so the embedded config runs under the rescue parser: a list of commands, no
  `if`, no functions, no `menuentry`. The configuration-language objection is answered by not shipping
  the interpreter for it.

The whole configuration is four commands, and two of them are the failure path:

```
search --no-floppy --set=root --label KMSRSOS
linux /bzImage
boot
halt
```

Reason 2 stands and is the honest cost: the UEFI path now has a stage between firmware and kernel that
it did not have. It is paid for by `linux-iso-layout` and `linux-boot` between them observing **all
four** combinations — `{CD-ROM, raw disk} × {SeaBIOS, OVMF}` — on every `nix flake check`, which is
more than the EFI-stub path ever had asserted about it.

Reason 3 from `OS-023`, "the ESP is load-bearing for EC2", survives and is no longer an argument
either way: the ESP still exists and is still a typed EFI System Partition, it just holds a loader
instead of a kernel, so `OS-027` (#344)'s raw-disk import is unaffected — and is observed.

#### The FAT-only alternative, priced

`OS-030` asked for this to be dispositioned rather than left as a footnote. Drop ISO9660 entirely and
ship a hybrid image whose single FAT partition holds the kernel once, at `/EFI/BOOT/BOOTX64.EFI`,
loaded directly by firmware through `CONFIG_EFI_STUB` and by syslinux for BIOS. No GRUB, no second
filesystem, and the EFI-stub property preserved — on the face of it the best option available.

Built and booted rather than estimated:

| | size | disk/BIOS | disk/UEFI | CD/BIOS | CD/UEFI |
|---|---|---|---|---|---|
| GRUB ISO (shipping) | 5.32 MiB | yes | yes | yes | yes |
| FAT-only `.img` | **4.69 MiB** | yes | yes | **cannot** | **cannot** |

**Declined, on a structural fact rather than a preference.** An `.iso` that boots BIOS from a FAT
partition needs El Torito *hard-disk emulation*, and `xorriso` refuses:

```
libisofs: FAILURE : Appended partition cannot serve as El Torito boot image with FD/HD emulation
```

An HD-emulation boot image has to be a **file in the ISO9660 tree**, not an appended partition. So a
FAT-only ISO must carry the FAT image once in the tree for El Torito and once appended for the GPT
that `OS-027` (#344) needs — which is two copies of the kernel again, and is precisely the bug shape
`OS-029` (#347) removed. FAT-only can be one copy, or it can be an `.iso`. Not both.

Shipping it as a raw `.img` instead would trade 0.64 MiB for the deployment procedure:
`docs/deployment.md` says "upload it to your ISO storage, attach it to the CD-ROM drive, and boot it.
That is the whole procedure", and CD-ROM-from-SeaBIOS is the *default* path on the supported platform.
Twelve per cent is not worth the supported platform's default path, and the size argument is weak
anyway: de-duplicating the kernel is worth 3.00 MiB and both options get that; the choice between them
is worth 0.64 MiB.

### A second architecture is supported (`OS-032`, #376; `PKG-019`, #378)

Decision 25 said "Proxmox is the supported platform", and Proxmox was x86-only. **Proxmox VE 9.2 for
arm64 shipped on 5 August 2026**, same codebase, full parity, and KVM is same-architecture — so an
operator on one of those hosts can run aarch64 guests and nothing else. For them this appliance did
not exist.

**The audience is the clients, not the hosts, and that is the stronger half of the argument.** On
Apple Silicon the entire lab is aarch64: Parallels and Fusion run Arm guests only and UTM's x86_64
path is TCG, so someone with a Windows 11 on Arm VM had no way to run this beside it except emulating
an x86 kernel — for a program whose pitch is that you attach the ISO and it boots. Snapdragon X and
Windows Dev Kit machines are the same case without the hypervisor.

**What "supported" is taken to mean here**, because a second architecture is easy to claim and hard
to keep:

- **Its own TCB statement.** `os/linux/kernel.config.aarch64` is generated the same way and asserted
  by the same test, against **its own two lists** rather than the x86 ones with substitutions
  (`OS-031`, #375). An architecture's TCB is not the other's plus a delta.
- **Its own boot check, not a parameter of the x86 one.** What differs is the interrupt controller,
  the timer, the console device, the PCI topology and the way the machine powers off; a check
  parametrised over all of that would be two checks sharing a `for` loop.
- **Built natively.** The arm ISO is built and booted on the arm runner, never cross-compiled. Same
  build path as x86, on its own hardware.
- **Its own row in the platform matrix, honestly marked.** The arm matrix is a third of the size,
  because four x86 rows name products that have no aarch64 guests at all.

**What it cost to find out.** Four of the things the issue predicted would be needed were wrong, and
every one of them was wrong in the direction of an allowlist entry that reads as a decision and does
nothing: `ACPI_GED` is not a Kconfig option, `RANDOM_TRUST_*` no longer exists on any architecture
(`OS-034`, #382), `olddefconfig` picks a page-table format nobody ships, and the console is **not**
`ttyAMA0` alone — EC2's aarch64 instances have a 16550A. And one thing nobody predicted: x86 had
KASLR and aarch64 silently did not, because `tinyconfig` answers `y` to `RANDOMIZE_BASE` on one and
not the other.

That last pair is the general lesson, and it is `OS-006` (#257) again in its most expensive form: a
second target inherits none of the first one's *defaults*, so anything the first one got without
asking is something the second one silently does without.

### The arm image has no bootloader (`OS-033`, #377)

**Two images, and the arm one is strictly simpler.** Not a stripped-down variant of the x86 one: a
different recipe, arrived at by asking the same question and getting a different answer.

#### The question `OS-030` answered, and why aarch64 does not have to

The GRUB in the x86 ESP exists for exactly one reason: **isolinux reads ISO9660 and UEFI reads FAT**.
Without something in the ESP that can read ISO9660, each firmware needs the kernel in its own
filesystem, and the kernel exists twice. That was a close decision — GRUB was declined once, in
`OS-023` (#339), on arithmetic that turned out to be wrong — and the whole of it is an argument about
*two firmwares sharing one kernel*.

**Arm64 guests have no BIOS.** Proxmox VE for arm64 boots every VM through AAVMF and SeaBIOS is not
available for them; no other Arm hypervisor has a legacy firmware either. One reader, no sharing
problem, nothing for a bootloader to solve. So the kernel goes in the ESP as
`\EFI\BOOT\BOOTAA64.EFI` and firmware runs it through `CONFIG_EFI_STUB` — which is what the x86
image did before `OS-030`, and which that issue called "the cleanest thing this image ever did".

| | BIOS | UEFI |
|---|---|---|
| **CD-ROM** | *no such firmware* | EFI stub, El Torito pointed at the appended ESP |
| **raw disk** | *no such firmware* | EFI stub, from the GPT EFI System Partition |

What that deletes from the arm path: isolinux, `ldlinux.c32`, `isolinux.cfg`, `isohdpfx.bin`,
`-isohybrid-mbr`, `-isohybrid-gpt-basdat`, `grub-mkimage`, the six-module list and the embedded
`grub.cfg`. `linux-iso-layout` asserts the absence of the first two and of any MBR boot code **in the
bytes**, because "this image is simpler" is the kind of claim that rots quietly.

#### The cost, measured

The ESP has to hold a kernel again, so it grows. The numbers, which are the whole trade:

| | x86_64 | aarch64 |
|---|---|---|
| in the ESP | `grubx64.efi`, ~278 KiB | the kernel, 3 760 640 B |
| ESP size | 2 MiB | **4 MiB** |
| kernel copies in the image | 1, in ISO9660 | 1, in the ESP |
| whole image | 5 582 848 B | **4 603 904 B** |

So the arm image pays **2 MiB more of ESP, and is 0.93 MiB smaller overall** — because what it saves
is not only the bootloader but the ISO9660 tree the bootloader existed to read. The ISO9660
filesystem in the arm image is empty.

**`CONFIG_EFI_ZBOOT` is what makes that arithmetic work** (`OS-032`, #376). arm64's `Image` is
uncompressed — 7 660 032 bytes — and would have needed an **8 MiB** ESP, which is exactly where
`mkfs.vfat` stops choosing FAT12 and the removable-media guarantee the UEFI specification gives stops
applying. The compressed `vmlinuz.efi` is 3 760 640 bytes and keeps the ESP at 4 MiB and the
filesystem at FAT12.

#### Observed, including on hardware

`nix flake check` on `aarch64-linux` boots the image as a **CD-ROM** and as a **raw disk** under
AAVMF, both asserted by reaching `"event":"listening"` rather than by the guest starting — firmware
that finds no boot option also starts, and sits at a shell. Both boots use a variable store that is a
fresh copy of the template, which is the same thing as a Proxmox VM with no `efidisk0`: `\EFI\BOOT`
is the removable-media path and needs no NVRAM entry.

And once outside QEMU. The same image was uploaded with `coldsnap`, registered as an arm64 UEFI AMI
and booted on a `t4g.nano`, where it took a DHCP lease, stepped its clock off SNTP and served a real
activation. Its console shows `EFI stub: Decompressing Linux Kernel...`, `ena … eth0` and
`{"event":"console","detail":"logging to tty0 ttyS0"}` — the last of which is the `OS-032` (#376)
finding in its consequence: **EC2's aarch64 instances have a 16550A and no PL011**, so an arm kernel
that named only `ttyAMA0` would boot correctly there and say nothing at all.

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

### The host clock is projected, and re-anchored (`POL-020`, #346)

Two rules pulled in opposite directions and the conflict had been settled by not settling it.

`POL-011` (#99) wants the host's wall clock on every request: a genuine KMS host checks the client's
`FILETIME` against a ±4 hour band, so a host that never looks is distinguishable from one that does.
`OS-007` (#258) permits the wall clock to be read in exactly two files — `entry.rs` once at start-up
and `net/sntp.rs`, whose job it is — because every deadline in this program is monotonic, and that is
what lets `OS-020` (#336) *step* `CLOCK_REALTIME` without `kmsrs-policy` ever seeing time run
backwards.

What was actually shipping: `driver.rs` passed `host_time: None`. So `clock_skew` never appeared in
the event log, `POL-011`'s "logged either way" was false, and `REFUSE_CLOCK_SKEW` was unreachable — a
build with `strict-clock-skew` behaved identically to one without it, and the feature-powerset job
was proving only that the flag compiled. `kmsrs-policy`'s own tests passed throughout, because they
hand `evaluate` a clock directly and the broken layer is below them.

**The decision: a `WallClock` holding a wall reading paired with the monotonic reading from the same
moment, projected forward, and re-anchored when the clock is corrected.**

The request path reads `CLOCK_MONOTONIC` — which the driver already does once per request to produce
the reading every deadline is measured against — and never `CLOCK_REALTIME`. Both rules hold, on
every target.

**Why it is re-anchored rather than projected forever from one reading.** On the bare-metal target
the clock is disciplined: `OS-020` polls SNTP and steps `CLOCK_REALTIME` when the offset is worth
stepping. A host that booted six hours out and projected forever from that would report six hours of
skew against every correctly-set client for the life of the process — and under `strict-clock-skew`
refuse them all, which is precisely the failure `OS-020` exists to prevent. So `sntp::apply` hands
the corrected reading across as an argument. Nothing new reads a wall clock; the one file already
permitted to know it passes it on.

**What deliberately does not move with it: the ePID's randomised activation date** (`ID-007`, #112).
It is drawn once at start-up and stays there, because `ID-001` (#106) requires the ePID to be stable
for the process lifetime — a host whose ePID changed mid-flight would fail the canonical detection
test. So after a large correction the two are drawn from different clocks, and that is the right way
round: the activation date is a year and a day-of-year buried in an ePID, and a correction big enough
to move it is one this host would have to restart to reflect anyway, while the skew measurement is
compared against a four-hour band on every request. Make the accurate thing accurate and leave the
stable thing stable, rather than keeping two values consistent and both wrong.

### The SRV weighting is the specification's, not vlmcsd's (`DISC-001`, #143)

`DISC-001` specifies the ordering as `random_weight = (rand % 256) * isqrt(weight * 1000)`, sorted
descending. That is vlmcsd's formula, and the same issue's definition of done says "ordering matches
RFC 2782". **Those are two different things**, so the code implements the second and this records
why.

RFC 2782 asks for a *selection probability proportional to the weight*, achieved by a running sum:
add up the weights in a priority, draw uniformly from `0..=total`, take the first record whose
running sum reaches the draw, remove it, repeat.

vlmcsd's formula gives each record a sort key of `uniform(0, 255) × sqrt(1000w)`, so its expected key
is proportional to **`sqrt(w)`** rather than to `w`. With records weighted 1 and 100 the
specification picks the heavy one about 99 % of the time; the formula picks it about 91 %.

Two reasons to prefer the specification here rather than matching the incumbent:

- **The client is a conformance tool.** Its purpose is to answer "would a real client find this
  host?", and a real client is Windows' resolver following RFC 2782 — not vlmcsd. Reproducing
  vlmcsd's approximation would make the tool agree with the wrong reference.
- **Nothing is lost.** The two agree exactly for one host and for equal weights, which is every
  deployment `docs/deployment.md` describes: the instructions page tells operators to publish
  `0 0 1688`, because a single host needs neither priority nor weight.

The weight-zero case is also the specification's rather than the common shortcut. RFC 2782 gives a
zero-weight record "a small chance of being selected", which the running-sum method produces for
free; implementations that sort zero-weight records last never try them first, and since the
recommended zone has *every* record at weight zero, that difference is the whole ordering.

### `TCP_NODELAY` is unobservable, so it is not set (`NET-015`, #164)

`NET-015` guessed that "Nagle likely never engages and the setting is probably unobservable", and
declined to act on the guess. It is now measured, against Windows 11 Enterprise 25H2 through the
harness in `harness/windows/`, and the guess was right for a reason worth writing down.

**Nagle needs a second small write with the first still unacknowledged.** This protocol never
produces one. The driver does exactly one `write_all` per request it has read (`NET-006`, #156), and
a client's next request always carries the ACK for the previous response — so at the moment the
server writes, there is never unacknowledged data outstanding.

The obvious objection is pipelining, where two requests arrive in one segment and the driver answers
with two writes back to back. That was tested directly, by replaying two complete request PDUs in a
single write from the guest:

| | server response segments | turnaround |
|---|---|---|
| OS default (Nagle on) | `[108, 56, 600]` | 0.135 / 0.089 / 0.224 ms |
| `TCP_NODELAY` set | `[108, 56, 600]` | 0.143 / 0.095 / 0.227 ms |

Identical segmentation, and turnarounds separated by microseconds of noise. The two 300-byte
responses leave as **one 600-byte segment either way**, because both writes complete within the same
event-loop turn and the socket buffer coalesces them before anything is transmitted. Nagle does the
coalescing it exists to do and costs nothing, because there was never a round trip to wait for.

So the option is not "off because we prefer it off". It is *not set*, because setting it would be a
syscall per connection and a line of code claiming to prevent a stall that cannot occur — and a
reader would reasonably infer from its presence that one could.

This also settles the anti-fingerprinting half, which is the part `FP-027` (#265) cares about:
whatever a genuine Microsoft host does with `TCP_NODELAY` is equally unobservable, so parity is
automatic rather than something to maintain. The measurable TCP-layer differences are the ones
`FP-027` already names — they are properties of the host OS stack, not of this program.

One limit on the above: it was measured over QEMU user-mode networking, where the round trip is
sub-millisecond. That does not weaken it, because the argument is structural — the write pattern is
fixed by the protocol and does not change with latency — but a capture across a real network has not
been taken.

### The unsafe boundary was reopened, for five calls (`SEC-019`, #356)

The workspace forbade `unsafe` with no exception, and the test enforcing it over-reached on purpose:
it failed on the word appearing anywhere in a shipped crate, so *"a reader grepping this tree for
`unsafe` should find nothing and never have to decide which hits are real."* That property is real
and was worth something. It has been given up, deliberately, for
`SetProcessMitigationPolicy` — the only thing that has ever needed it.

**What was bought.** All five policies apply, and they were verified in force on a live process
rather than assumed from a return value — `Get-ProcessMitigation` on the running server reports
`DisableWin32kSystemCalls: ON`, `BlockDynamicCode: ON`, `DisableExtensionPoints: ON`,
`BlockRemoteImageLoads: ON`, `BlockLowLabelImageLoads: ON`, `StrictHandle.Enable: ON`. The server
runs normally with all six in force, including the win32k one, which was the likeliest to break
something in a process that writes to a console.

**What it cost, and why it is bounded.** One `unsafe` block, in one function, in one file. The
workspace lint stays at `forbid`; only `kmsrs-server` sets `deny`, which is the weaker level an
`#[expect(unsafe_code)]` can lift. Two tests keep it from spreading:

* `no_shipped_crate_contains_unsafe` no longer merely forbids — it *counts*. `unsafe` outside
  `crates/kmsrs-server/src/sandbox.rs` fails, and more than one occurrence inside it fails too, so
  the boundary cannot grow quietly.
* `server_lints_match_the_workspace` compares that crate's duplicated lint tables against
  `[workspace.lints]` in both directions. Duplicating a table is how it drifts; this makes drift a
  test failure rather than a discovery.

The buffer width is asserted rather than commented: each `PROCESS_MITIGATION_*` structure is a union
of a `DWORD Flags` and a bitfield, so [`set`] passes a `u32`, and a test fails if any of the five
ever grows past four bytes — which is the only way that call could quietly start passing a short
buffer to something that reads `dwlength` bytes.

The alternative was option 4 in #356: declare the asymmetry permanent. That was rejected because
`DisallowWin32kSystemCalls` is worth more than the grep property, and because the grep property was
only ever a proxy for "the unsafe in this tree is auditable" — which one call site with a safety
comment satisfies directly.

### Windows on Arm is built, named, and now tested (`PKG-020`, #379; `PKG-022`, #385)

The Windows build was x86_64 and nothing else, and the client population that needs it is going Arm:
Snapdragon X and Windows Dev Kit machines run Windows 11 on Arm natively, and on Apple Silicon it is
the only Windows there is — Parallels and Fusion run Arm guests only. Such a user could run
`kmsrs-server` on Windows only under the x86 emulation layer.

**That is worse for this program than for most**, and the reason is the decision immediately above:
`SEC-019` verifies its mitigations *on a live process*. Under emulation, what that verifies is a
property of the emulator's process.

So there is an `aarch64-pc-windows-msvc` build, through the same `cargo xwin` path, from the same
fixed-output MSVC SDK — which now carries both architectures, so bumping the pinned CRT and SDK is
still one hash in one place. `.#windows` is gone: it meant "the x86_64 one", and a release artifact
named after a default is one nobody can tell apart from the other. Both are named.

**It shipped never having been executed, and now it has been** (`PKG-022`, #385). At the time there
was nowhere to run it — no hosted ARM64 Windows runner, no Windows on Graviton, and emulating ARM64
Windows to test a *process mitigation* would answer a question about the emulator, which is the
objection that made the status quo unacceptable in the first place. The first of those three stopped
being true: `windows-11-arm` is a standard GitHub-hosted runner and is free on public repositories.

What it found is in [its own section below](#the-arm64-binary-runs-and-takes-all-five-mitigations-pkg-022-385).
What made shipping it defensible in the meantime is that the failure mode is **visible rather than
silent**, which is precisely what `PKG-018` below found to be missing:

- `refused()` attributes a declined policy to a policy *by name*, and `apply()` reports `Failed`
  rather than aborting — because "this kernel declined a mitigation" already happens on older
  Windows builds and is not a reason to stop serving. A host that gets fewer mitigations than it
  asked for says so on its console at start-up.
- The `windows-mitigations` check now reads `IMAGE_FILE_MACHINE` off each artifact **before** it
  asserts anything else about it. Without that, a check reading only the binary it knew about would
  pass for the whole time the other was unbuilt or wrong — the same shape of hole `PKG-018` was
  created by, in a different place.

The `SetProcessMitigationPolicy` surface is architecture-independent — every structure involved is a
flag word rather than anything with a register layout, and the width assertion below compiles for
whichever target it is built for. That is a reason to expect it to work; it is not a test, and the
distinction is the whole of `PKG-018`.

### The ARM64 binary runs, and takes all five mitigations (`PKG-022`, #385)

`PKG-020` shipped an `aarch64-pc-windows-msvc` build that nothing had ever started. The build-time
checks passed — the PE machine type is read off each artifact and Control Flow Guard is asserted
absent — and `PKG-018` below is the standing proof that a build-time check can be a true statement
about an unusable binary.

**Observed, on Windows 11 build 26200 on ARM64:** the process starts, binds 1688 and 8080 on both
address families, serves a V6 activation to `kmsrs-client`, and reports `process-mitigations:
applied` — which means all five `SetProcessMitigationPolicy` policies were accepted, none refused.
`ProcessSystemCallDisablePolicy` is the one that was in doubt, since it removes the `win32k.sys`
surface and `win32k` on ARM64 is a different build of a driver with its own history of what is
filterable. It takes it.

So the Windows security posture is the same on both architectures, and this document does not have to
state it per architecture after all — which is the outcome #385 asked for and not the one it expected.

**Two jobs, because there were two questions.** A `platforms` leg builds and tests natively on
`windows-11-arm`, which is what covers the service router of `PKG-017` (#368), the Event Log source
registration and the width assertion compiled for this target. `windows-aarch64-smoke` runs the
**cross-compiled artifact** from the snapshot — the binary an operator downloads, not one rebuilt on
the test machine — because the whole lesson of `PKG-018` is that the artifact and a statement about
the artifact are different things.

**It is CI rather than a machine somebody owns.** #385 listed the plausible ways to get an ARM64
Windows: a Snapdragon X laptop, a Windows 11 ARM VM on Apple Silicon, or Azure's Cobalt 100
instances — all of which would have answered the question *once*, by hand, with a note in the issue
saying who ran it. A hosted runner answers it again on every pull request, and the expected outcome is
a parameter of the harness that is asserted, so a Windows that starts refusing one of the five fails a
job instead of changing a log line nobody is reading.

**What it did not establish**, and is now `SEC-020` (#392): a refusal still reports *that* one of the
five was declined without saying *which*. `refused()` knows the name and `apply()` discards it. That
is latent rather than live — nothing has refused one yet — but it is the exact property this decision
rests on, so it is filed rather than noted.

### Control Flow Guard produced a binary that did not start (`PKG-018`)

`SEC-005` turned on `-C control-flow-guard` for the Windows target and added a check that reads
`DllCharacteristics` out of the PE optional header to prove the bit was set. The check was right, the
bit was set, and **the binary died on startup on every Windows it was run on**: `0xC0000409` with
fast-fail code 10, `FAST_FAIL_GUARD_ICALL_CHECK_FAILURE`, before a single line reached stderr.

The load-config table is populated — 337 entries, `GuardFlags = 0x10500` — so this is not a missing
table but an incomplete one: an indirect call to a target the table does not list. A three-line
hello-world cross-built the same way fails identically, and `lto = "fat"`, `thin` and `off` all fail,
so it is neither this program nor an LTO interaction. The likeliest cause is that the precompiled
`std` for `x86_64-pc-windows-msvc` is not built with CFG, which would need `-Zbuild-std` to fix and
that is confined to the fuzzing shell.

So CFG is off, and `windows-mitigations` now asserts it is **absent** rather than present — a check
that fails if it comes back without the crash being fixed.

The lesson is the one worth keeping. `DllCharacteristics` is a statement about the artifact and that
is why the check was written that way, but it is a statement about the artifact's *header*. Nothing
in the tree had ever executed the artifact. `SEC-019` put a Windows guest in front of it
(`harness/windows/`) and it failed inside thirty seconds.

### The sandbox is what could be verified (`SEC-005`, #197)

`SEC-005` asks for three Linux measures and five Windows ones. **Two shipped.** The rest were split
into `SEC-018` (#355) and `SEC-019` (#356) rather than approximated, and the split is the decision
worth recording.

**What ships:** Landlock with an empty ruleset and `no_new_privs`, applied after the listeners are
bound and before the first connection is accepted. Binding a port is the last thing this program does
that a sandbox would have to permit, so that is the first moment there is nothing left to give up.

The Landlock ruleset handles the newest ABI's rights and grants none of them, which denies opening
any path **and** opening any socket — ABI 4 added `BindTcp` and `ConnectTcp`, and a KMS host needs
neither once it is listening (`NET-001`, #150 says it does not even read its own address). Best-effort
compatibility means an older kernel denies what it can rather than refusing to start.

**Why Landlock is worth having when `no-file-access` already exists.** That invariant proves no
shipped crate *calls* `open`. Landlock decides what happens when something else does — a dependency, a
panic handler writing a core file, a future change nobody reviewed against axiom A5. One is a
statement about the source; the other is a statement about the process.

**Why the bare-metal target is deliberately not sandboxed.** There this process *is* the userland: it
mounts `devtmpfs`, `/proc` and `/sys`, speaks netlink, steps `CLOCK_REALTIME`, reaps orphans and calls
`reboot(2)`. A policy permissive enough for all of that permits most of what a policy is for, and one
that is not kills pid 1 — a kernel panic, not a failed request. The value is also lower: a sandbox
limits what a compromised process can reach, and on a machine whose entire userland is this process
there is nothing else to reach. So `sandbox::apply` is called from `serve` and not from `serve_with`.

#### Why seccomp was split out rather than written

The two that shipped are verifiable in a way a syscall filter is not. Landlock either denies
`/proc/self/cmdline` or it does not, and `tests/sandbox.rs` checks exactly that in a real sandboxed
subprocess. A seccomp allowlist is a claim about *every syscall this process will ever make*, across
every libc, allocator, kernel and tokio version it ships against — and the cost of getting it wrong is
the process being killed on something nobody predicted, under load, in production, with no log line
because the process is gone. That list has to be measured, on both libc targets, which is #355.

#### Why the Windows mitigations were split out, and how it was settled

`SetProcessMitigationPolicy` is self-applicable and closes a great deal —
`DisallowWin32kSystemCalls` alone removes the largest source of Windows kernel escalations, and this
is a console service with no GUI. It was not called at first because **it could not be**: every
binding is raw FFI, and this workspace sets `unsafe_code = "forbid"` at the root with a test that
fails on the word appearing anywhere in a shipped crate. That was a real conflict between two things
the project wants, and `SEC-019` (#356) is where it was taken — see
[decision 44](#the-unsafe-boundary-was-reopened-for-five-calls-sec-019-356).

Control Flow Guard was described here as the sixth mitigation, "purely a compile flag" and therefore
free. It was neither: the binary it produced did not start. See
[below](#control-flow-guard-produced-a-binary-that-did-not-start-pkg-018).

#### Reporting

`Applied::Failed` and `Applied::NotOnThisTarget` are separate variants because they are different
facts — "Windows has no Landlock" and "Landlock is here and refused" call for different responses, and
collapsing them would hide the second. Windows reports `process_mitigations: Failed` rather than
`NotOnThisTarget`, because the capability exists on that platform and is not being used.

A measure that cannot be applied is never fatal. A host that refused to activate anything because it
could not sandbox itself would be trading its entire function for a hardening measure — the same shape
of mistake as [D35], and as `POL-011`'s clock-skew tolerance.

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

<a id="d43"></a>**D43 — An mDNS responder for `_vlmcs._tcp.local` (`DISC-005`, #147).** Declined on
measurement, not on taste. `DISC-003` (#145) asked whether SPP's SRV lookup goes through the generic
Windows DNS Client path, which handles `.local` via mDNS. It does — and **that path has no code for
SRV.** Using plain `Resolve-DnsName` on Windows 11 25H2, with no licensing involved, `A` and `AAAA`
for a `.local` name go to unicast *and* to `224.0.0.251`/`ff02::fb`; `SRV` and `PTR` for one never
leave unicast. The DNS Client's mDNS support is an address-record resolver, and DNS-SD on Windows
lives in a separate WinRT stack (`Windows.Networking.ServiceDiscovery.Dnssd`) that SPP does not
call.

A responder would therefore answer a question Windows never asks, and no configuration on either
side changes that. This is the sibling of **D32**: LLMNR cannot carry SRV at all, and mDNS can but
will not be asked. Evidence and captures: `docs/discovery-findings.md`, scenarios `H-dhcp15-local`
and `W-why-mdns`.

What survives is the *hostname* half, which does work: `slmgr /skms kmsrsos.local` resolves by mDNS,
giving a name that survives DHCP address changes with no DNS server and no hosts file. Shipping a
hostname-only mDNS responder for that is a different proposition from this one and is not declined
here — it simply has no issue yet.

<a id="d44"></a>**D44 — A single dual-architecture ISO (`OS-033`, #377).** Technically routine: the
ESP gains a second file and the tree gains a second kernel, which is how Debian ships installer
media. Declined on what it costs everybody else.

It **doubles the download for every operator** — 4.4 MiB of aarch64 that an x86 user will never
execute, and 5.3 MiB the other way — and it means shipping x86 BIOS boot code and an isohybrid MBR on
media whose arm audience has no firmware that can run them. The arm image's claim is that it is
*strictly simpler* than the x86 one, and merging them gives that up in exchange for one filename.

Two images, named by architecture. If this is ever revisited it should be as its own issue with the
sizes measured, and this paragraph is the reason it was not done in #377.

<a id="d45"></a>**D45 — Naming the idle ethernet vendor menus on the disable list (`OS-035`,
#383).** Both kernels carry about seventy `CONFIG_NET_VENDOR_*=y` entries with no driver enabled
under any of them. They read like seventy decisions nobody took, and #383 raised them as "how a
driver arrives later without anybody asking".

Measured before being argued about, which is the point: `.#linux-deltas` has a `no-vendor-menus`
variant that turns off every one of them, and the delta is **0 bytes on both architectures**. A
`NET_VENDOR_X` is a `bool … default y` whose only effect is that `drivers/net/ethernet/Makefile`
descends into that vendor's directory, where every object is gated by a driver symbol of its own —
all of which are off. Nothing is compiled either way.

So the choice is seventy lines of allowlist against zero bytes and no behaviour change, and seventy
lines that change nothing make the file *harder* to read as a statement — which is what it is for.
The guard against a driver arriving unasked is not this list: it is that `kernel.config` is checked
in, so a new `=y` line appears in a diff somebody reviews. That is the same mechanism that caught
every finding in `OS-023` (#339), `OS-026` (#343) and `OS-034` (#382).

The variant stays, so the number can be taken again rather than trusted from this paragraph. What
`OS-035` *did* remove from the same file is worth 8 KiB on each architecture — five 8250 driver
variants for hardware no hypervisor emulates — which is the shape of pare-back this list is for.

<a id="d46"></a>**D46 — `PERF_EVENTS` off on x86_64 (`OS-035`, #383).** Not declined on a judgement:
it cannot be done. `arch/x86/Kconfig` gives `config X86` an unconditional `select PERF_EVENTS`, so
there is no x86 kernel without `perf_event_open(2)` at any Kconfig setting — disabling it and
running `olddefconfig` produces a byte-identical configuration.

#383 filed it as a real gap, and it was: aarch64 disables it and x86 does not, so the two kernels
this project ships differ on whether a large syscall with a JIT-adjacent history exists, and nobody
chose that. Naming it on the shared disable list would have produced an entry that cannot be
honoured — the exact thing `OS-034` (#382) had just removed three of, and had just built a test
against.

What is done instead is that the fact is asserted per target:
`perf_events_is_absent_on_one_target_and_forced_on_the_other` in `kernel_tcb.rs`. If x86 ever stops
forcing it, that test fails and this paragraph gets revisited rather than quietly going stale. On
aarch64, where the question can be asked, keeping it out is worth **56 KiB** — `perf-events` in
`.#linux-deltas`.

<a id="d47"></a>**D47 — Removing the PnP bus (`OS-037`, #390).** Not declined on a judgement either:
it cannot be done, and this is the second entry in a row with that shape. `drivers/acpi/Kconfig`
gives `menuconfig ACPI` an unconditional `select PNP`, so Kconfig forces the symbol back on and
`olddefconfig` overwrites the entry. `PNPACPI` follows, being `bool` with no prompt and
`default (PNP && ACPI)` — it is not settable at all.

The case for removing it was good. `SERIAL_8250_PNP` left with `OS-035` (#383) and was the only
driver on either kernel that bound to the bus; on an EC2 Graviton instance `/sys/bus/pnp/devices/`
holds exactly one entry, `00:00`, the ACPI motherboard-resources pseudo-device; and on x86 the
console comes from `SERIAL_PORT_DFNS` in `arch/x86/include/asm/serial.h` rather than from
enumeration. So the bus enumerates nothing this machine uses, on either architecture.

It stays anyway, and nothing about enumeration changes — which incidentally disposes of the risk
#390 was written around, that a VM whose serial port comes from firmware rather than the ISA table
would boot in silence (`OS-005`, #256). What *was* removed is `PNP_DEBUG_MESSAGES`, a `default y`
debug-message option that had been compiled into every kernel this project has shipped.

Read off the kernel rather than argued, per `OS-006` (#257): with `PNP` on the disable list the
generated file still said `CONFIG_PNP=y`, and the only line that changed was the debug one. The fact
is asserted per target in `the_pnp_bus_stays_because_acpi_selects_it`, so the day ACPI stops
selecting PNP this fails and the pare-back becomes possible rather than this paragraph going stale.

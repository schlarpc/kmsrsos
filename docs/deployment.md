# Deployment

What an operator needs to know that the binary cannot tell them. The running server's own
`/instructions` page covers the per-client half — `slmgr /skms`, the SRV record, the GVLKs — with its
real address and port filled in. This document is the part that is about *where to put it*.

Work items live in [GitHub issues](https://github.com/schlarpc/kmsrsos/issues); the decisions behind
any of this are in [`decisions.md`](decisions.md).

- [Where the host has to live](#where-the-host-has-to-live) — the loopback constraint
- [DNS: the `_vlmcs._tcp` SRV record](#dns-the-_vlmcs_tcp-srv-record)
- [Building it, and configuring it](#building-it-and-configuring-it)
- [systemd](#systemd)
- [Containers and Kubernetes](#containers-and-kubernetes)
- [Bare metal: Linux, on QEMU or Proxmox](#bare-metal-linux-on-qemu-or-proxmox)
- [What is not in the artifact](#what-is-not-in-the-artifact)

---

## Where the host has to live

**A Windows client will not activate against `127.0.0.1` or `::1`.** Software Protection Platform
refuses a KMS host on the loopback interface whatever the port, and reports a generic failure rather
than saying why. This is not our behaviour and there is nothing to configure — it is the client side
of the protocol.

It is also not folklore. It is the entire reason vlmcsd carries a 370-line TAP/TUN driver that swaps
`ip_src` and `ip_dst` on every packet, together with an internal DHCP server and a packet-rewriting
thread, so that a loopback conversation arrives looking like a LAN one. That is declined here as
[D21](decisions.md#declined-with-rationale): it is a large amount of privileged, platform-specific
code to work around a constraint that has four ordinary answers.

So give the clients a non-loopback address. Any of these is one:

| Situation | What to point clients at |
|---|---|
| Server on a LAN machine | that machine's LAN address |
| Server in a container | the container's bridge address, or a published port on the host's LAN address |
| Server on the same machine as a Hyper-V or WSL2 client | the host-side address of the virtual switch (`vEthernet (WSL)`, typically `172.x`) |
| Server on the same machine as a VirtualBox/VMware client | the host-only adapter's address |
| One physical machine, no VMs, nothing else | a second NIC, or a loopback *alias* that is not in `127.0.0.0/8` |

The `/instructions` page detects this case: browse to the web UI over loopback and it says so at the
top of the page, because an operator who has just typed `localhost:8080` is about to spend an
afternoon on it.

`NET-014` (#163) is the issue; `D21` is the declined workaround.

---

## DNS: the `_vlmcs._tcp` SRV record

A Windows client with no explicit host configured looks up `_vlmcs._tcp` in the domains it searches.
That is how a real KMS deployment is found, and it is strictly better than `slmgr /skms` on every
client: the address can change without touching any of them.

The record shape (`DISC-007`, #149):

```
_vlmcs._tcp.EXAMPLE.COM.  3600  IN  SRV  0 0 1688  kms.example.com.
```

The four values after `SRV` are **priority, weight, port, target**.

- **Priority** — ascending. Clients try the lowest-numbered priority first and only fall through to
  the next if every host in that band fails.
- **Weight** — a proportional share *within* one priority, chosen randomly per lookup (RFC 2782).
  `kmsrs-client` implements the ordering exactly, including the `(rand % 256) * isqrt(weight * 1000)`
  form the reference implementations use.
- **Port** — 1688, and not configurable at either end (`NET-002`, #151). A client discovers the port
  from the record; a host listening elsewhere is a host nobody finds.
- **Target** — a name, with a trailing dot, that resolves to an address. Not an IP literal: SRV
  targets are names.

**Zero for both priority and weight is the convention** for a single host, and is what Microsoft's
own KMS host publishes. Multiple hosts only need them if the shares should be unequal.

Note the domain. Clients look up `_vlmcs._tcp` under their **primary DNS suffix** and under the
domains in their search list — in an Active Directory domain that is the domain itself, and on a
workgroup machine it is often nothing at all, in which case there is no SRV lookup to answer and
`slmgr /skms` is the only route. `DISC-004` (#146) is the harness that measures which of those cases
actually fire.

### Publishing it

The running server's `/instructions` page renders all three of these with its own address and port
substituted; they are repeated here so the shape is legible without a server to hand.

BIND-style zone file:

```
_vlmcs._tcp  IN  SRV  0 0 1688  kms.example.com.
```

`nsupdate`, against a zone that accepts dynamic updates:

```sh
nsupdate <<'EOF'
update add _vlmcs._tcp.EXAMPLE.COM. 3600 SRV 0 0 1688 kms.example.com.
send
EOF
```

Windows DNS in an Active Directory domain:

```powershell
Add-DnsServerResourceRecord -ZoneName EXAMPLE.COM `
  -Name _vlmcs._tcp -Srv -Priority 0 -Weight 0 `
  -Port 1688 -DomainName kms.example.com
```

**The server never publishes this itself.** Dynamic DNS update via RFC 2136 is declined as
[D15](decisions.md#d15): AD DNS defaults to secure-updates-only and real hosts register with
**GSS-TSIG** using machine-account Kerberos credentials, so a shared-key TSIG does not serve the
primary use case at all — and either mechanism would mean a secret inside the shipped artifact, which
is the one thing [there is not](#what-is-not-in-the-artifact).

### Checking it

```
nslookup -type=srv _vlmcs._tcp.EXAMPLE.COM
slmgr /dlv
```

`/dlv` prints the host the client used and its activation interval, which is the quickest way to tell
*"the client never found a host"* from *"the client found one and did not like the answer"*.

---

## Building it, and configuring it

There is no configuration file, no command line and no per-knob environment variable
([D5](decisions.md#declined-with-rationale)). Anything that can change a byte on the wire is decided
when the binary is built (`CFG-001`, #166), and the way to change it is to build a different binary.

That doctrine is only usable if the rebuild is two lines, so it is a function (`CFG-003`, #168):

```nix
# flake.nix
{
  inputs.kmsrsos.url = "github:schlarpc/kmsrsos";
  outputs = { self, kmsrsos, ... }: {
    packages.x86_64-linux = kmsrsos.lib.mkKmsrsos {
      system = "x86_64-linux";
      settings = {
        activationInterval = 240;      # minutes; Microsoft's default is 120
        renewalInterval = 20160;       # minutes; Microsoft's default is 10080
        permissiveRetail = true;       # activate retail/OEM/eval SKUs too (POL-010, #98)
        strictClockSkew = false;       # refuse a clock more than four hours out (POL-011, #99)
      };
    };
  };
}
```

It returns `{ server, client, container }`.

Those four settings are the entire build-time surface — see [D37](decisions.md#d37) for why it is not
thirty preprocessor macros and seven presets. A bad value is a **compile error** rather than a
start-up failure, because `Compiled::BUILD` parses the overrides in const context (`CFG-004`, #169):
`activationInterval = 0` produces a build that stops, not a server that starts and behaves oddly.

The flake's own outputs, without configuring anything:

| `nix build .#…` | What it is |
|---|---|
| `default` | the whole workspace |
| `server` | the server binary, statically linked against musl on Linux |
| `client` | the diagnostic and detection-resistance client |
| `container` | the container image, as a `tar.gz` ready for `docker load` |
| `windows` | `kmsrsos.exe` and `kmsrs-client.exe`, cross-compiled |

`nix flake check` runs the whole gate: build, clippy, fmt, tests, coverage with a floor under the
sans-io crates, the data-integrity check, the feature powerset, a configured build through
`mkKmsrsos`, and the container image (`PKG-002`, #239).

### Which build is running

There is no `--version` flag, because the server takes no arguments at all (`CFG-007`, #172). The
build stamp is on the status page and in `/metrics` instead (`CFG-008`, #173):

```
kmsrsos_build_info{version="0.1.0",revision="…",source_date_epoch="…"} 1
```

The revision and the date come from the flake, and the date is the **source** date rather than the
build date — which is what makes two builds of one revision identical, and is checked by
`nix build --rebuild` in CI. A `cargo build` in a checkout reports `unknown` rather than guessing.

---

## systemd

```sh
sudo install -m 0755 result/bin/kmsrsos /usr/local/bin/
sudo install -m 0644 deploy/systemd/kmsrsos.service /etc/systemd/system/
sudo systemctl enable --now kmsrsos
journalctl -u kmsrsos -f
```

Both audited projects have only a documentation snippet for this, and py-kms's is `User=root` with no
hardening whatever. `deploy/systemd/kmsrsos.service` is a real unit (`PKG-007`, #244), and almost
every line of its hardening is **free** rather than aspirational — it forbids things the program
genuinely does not do:

| Setting | Why it costs nothing |
|---|---|
| `DynamicUser=yes` | there is no state to own: no data directory, no cache, no files at all (axiom A5) |
| `ProtectSystem=strict`, `ReadOnlyPaths=/` | no filesystem I/O, proven in CI by running the binary under `strace` (`SEC-006`, #198) |
| `CapabilityBoundingSet=`, `AmbientCapabilities=` | 1688 is unprivileged, so nothing needs one |
| `RestrictAddressFamilies=AF_INET AF_INET6` | TCP only; no Unix socket, no netlink, no UDP |
| `MemoryDenyWriteExecute=yes` | no JIT, no dynamic code |
| `MemoryMax=128M` | the heap ceiling is 8 MiB and asserted at compile time (`OS-011`, #262) |

**Privileges are never dropped, because they never exist** ([D41](decisions.md#d41)). The issue that
proposed `setuid`/`setgid` named this path as the preferred one itself; with `DynamicUser` and an
unprivileged port there is nothing left for the drop to remove, and three `unsafe` libc calls in a
specific order is a large amount of famous footgun to add for it.

### There is no `.socket` unit

Deliberately ([D40](decisions.md#d40)). Socket activation was wanted so that systemd would bind 1688
and the service would never need `CAP_NET_BIND_SERVICE` — but **1688 is unprivileged**, so that
benefit is a restatement of something already true. What is left is zero-downtime restarts, which for
a service whose clients retry and whose activations last 180 days is worth nothing.

Against it: adopting an inherited file descriptor means `FromRawFd`, which is `unsafe` in every
spelling, in a project whose first axiom is pure safe Rust with exactly one permitted boundary
elsewhere.

So the binary **refuses to start** if `LISTEN_FDS` is set, rather than binding its own socket
alongside a manager's:

```
kmsrsos: started with LISTEN_FDS=1, but this build does not adopt inherited sockets.
```

That is not fussiness. Ignoring it under `Accept=yes` would mean one process per connection, which
destroys both the stable ePID and the CMID table **while continuing to answer** — the way
vlmcsd-under-systemd degrades without telling anybody ([D20](decisions.md#declined-with-rationale)).

---

## Containers and Kubernetes

```sh
nix build .#container
docker load < result
docker run --rm --read-only -p 1688:1688 -p 8080:8080 kmsrsos:latest
```

The image is **two statically linked binaries and nothing else** (`PKG-004`, #241) — the server and
the client. Not "a minimal base image": there is no libc, no package manager, no shell, no
`/etc/passwd`. `packaging_invariants.rs` fails if anything that is a shell, or could run one, appears
in the expression.

It runs as `65534:65534` and needs no capabilities, because 1688 is unprivileged. `--read-only` is
free rather than aspirational: the program performs no filesystem I/O at all (axiom A5), and CI
proves it by running the real binary under `strace` (`SEC-006`, #198).

The `HEALTHCHECK` probes the **KMS port** by doing what a client does — connect, bind, activate,
decode — via `kmsrs-client --healthcheck`. That is why the client is in the image at all: a scratch
container has no shell, no `curl` and no `nc`, so the check has to be a binary. Probing the HTTP
handler instead would prove the one fact the caller already had by getting a reply, which is the
Organization fork's `readyz` mistake (`OBS-008`, #184). A host that is merely *distinguishable* from a
genuine one is still healthy — a check that failed on a detection finding would take a working service
out of rotation for a cosmetic reason.

There is no `Dockerfile` and there never will be. The image is built by `dockerTools` from store
paths, so there is no build context to `COPY` and no `RUN` to execute — which is what makes it
impossible for the build to reach the network (`PKG-005`, #242). Upstream py-kms's Dockerfiles
`git clone` GitHub master instead of copying the build context, so `docker build` there produces
whatever upstream happened to be that morning and silently ignores local changes.

### Kubernetes

```sh
kubectl apply -f deploy/kubernetes/kmsrsos.yaml
```

Plain manifests, and **no Helm chart** ([D17](decisions.md#d17)).

> **`replicas: 1` is not a tuning parameter.** This host's state is in memory and per-pod, so two
> replicas means two CMID tables, two event logs and — the part that matters — **two ePIDs**. A client
> that reaches pod A and then pod B is told two different host identities by one host name. That is
> MM01, the single loudest emulator tell in the ecosystem and the canonical detection test,
> reintroduced at the infrastructure layer by a config value. The update strategy is `Recreate` for
> the same reason: a rolling update runs two pods at once.

Helm's value is parameterization, and `replicaCount` is the parameter people would reach for first —
which is exactly the one that must never change. The Organization fork's chart exposes it as a
top-level value.

The probes hit `/healthz`, which answers 200 only when the KMS side is working: an identity was drawn,
the listener is bound, and the entropy self-test still passes (`OS-012`, #263).

The Service is `ClusterIP` by default. Clients live outside the cluster, so this normally wants a
`LoadBalancer` or a `NodePort` — left to be chosen deliberately rather than defaulted into, because
exposing 1688 is a decision about the network. And remember the
[loopback constraint](#where-the-host-has-to-live): the address the clients get must be one they can
route to.

---

## Bare metal: Linux, on QEMU or Proxmox

The bare-metal target is one binary that is the whole userland: a Linux kernel built from an
explicit allowlist, with `kmsrs-server` as **PID 1** and nothing else in the image. No init system,
no shell, no libc on disk.

This used to be a [Hermit](https://github.com/hermit-os) unikernel. `OS-018` (#334) replaced it, and
[`decisions.md`](decisions.md#hermit-was-removed-rather-than-kept-os-018-334) is why: the unikernel
needed three non-default VM settings, only one of which the Proxmox web UI can express, and failed
quietly when they were missing.

### The artifact (`OS-017`, #333)

```shell
$ nix build .#linuxIso        # kmsrsos-linux.iso, 14 MiB
$ nix build .#linux-kernel    # the bzImage on its own
```

**One ISO, both firmwares.** `CONFIG_EFI_STUB` makes a `bzImage` simultaneously a PE/COFF executable
and a Linux boot image — `MZ` at offset 0 and `HdrS` at 0x202 — so the same 2.7 MiB file is both
`\EFI\BOOT\BOOTX64.EFI` for UEFI and an isolinux `KERNEL` line for BIOS. There is no bootloader on
the UEFI path and nothing to register in NVRAM, so a fresh VM boots on its first try.

The initramfs and the kernel command line are *inside* that file
(`CONFIG_INITRAMFS_SOURCE`, `CONFIG_CMDLINE_OVERRIDE`). The second is not a convenience: it means a
bootloader passing a different command line is **ignored**, so the kernel command line is a
build-time decision like every other setting here (axiom A3, `CFG-001` #166).

#### On Proxmox

Create a VM with **no disk**, upload `kmsrsos-linux.iso` to your ISO storage, attach it to the
CD-ROM drive, and boot it. That is the whole procedure. SeaBIOS or OVMF both work, so the default
BIOS setting is fine and an EFI disk is only needed if you choose OVMF.

Two things are worth adding, neither of which is required for it to serve:

| | Why |
|---|---|
| **Hardware → Add → virtio-rng** | Cuts time-to-serving from ~4.7 s to ~2.4 s. The program blocks in `getrandom(2)` until the kernel's CRNG is seeded, and on a CPU model without RDRAND that takes seconds of jitter entropy |
| **Hardware → Add → Serial Port** `0`, then **Options → Display → Serial terminal 0** | Convenience, not necessity — the framebuffer console already shows the boot in the noVNC window |

**`cpu: host` is not needed.** It was mandatory on Hermit, whose only seed source was RDSEED. Linux
seeds its CRNG on any CPU model; with virtio-rng attached, `host` and the default `kvm64` differ by
noise.

**`qm set --args` is not needed.** Proxmox puts NICs on a conventional PCI bus and never emits
`disable-legacy=on`, so the virtio-net device is *transitional* — PCI ID `0x1000` rather than
`0x1041`. Hermit refused anything below `0x1040`, which is `OS-004` (#255) and is why that target
needed a CLI-only workaround. Linux has driven transitional virtio devices for fifteen years.

#### Locally

```shell
$ qemu-system-x86_64 -machine q35 -cpu qemu64 -enable-kvm \
    -smp 1 -m 512M -display none -serial stdio -no-reboot \
    -drive file=result/kmsrsos-linux.iso,media=cdrom,readonly=on \
    -netdev user,id=u1,hostfwd=tcp:127.0.0.1:1688-:1688 \
    -device virtio-net-pci,netdev=u1 \
    -device virtio-rng-pci
```

`kmsrs-client 127.0.0.1:1688` is the check that it answers *correctly*. The `linux-boot` check in
`nix flake check` runs exactly this on both firmwares, on the PCI topology `qemu-server` emits, with
no `--args` — so the two conditions that defeated the unikernel are exercised on every change.

### What is in the kernel, and what is not

`os/linux/kernel.config` is checked in and is meant to be read. The base is `make tinyconfig`, so
every subsystem defaults to **off** and each of the ~90 enabled entries is a deliberate line — the
file is the statement of what is in this machine's TCB. `os/linux/config.nix` regenerates it and
carries the reasoning per group.

**Axiom A5 is structural here.** `CONFIG_BLOCK` is unset: there is no block *layer*, not merely no
block drivers, so disk I/O is a syscall with nothing behind it. The boot medium is invisible to the
kernel — firmware reads the ESP and the image runs from RAM thereafter — so no ATAPI, no SCSI and no
ISO9660 are compiled in either. After boot the CD-ROM could be ejected.

Also absent, deliberately: modules, netfilter, BPF, tracing, cgroups, namespaces, USB, sound, and
every filesystem but ramfs, tmpfs, proc and sysfs.

Present because something needs them: PCI and ACPI (the NIC is on a PCI bus), the 8250 UART **and** a
framebuffer console, virtio-net plus `e1000`/`e1000e` for hypervisors that do not offer virtio,
`seccomp`, and `kvmclock` — which is doing NTP's job until `OS-020` (#336) lands, and matters because
this host validates client timestamps against a band.

### Addressing (`OS-003`, #254)

The guest takes its address from DHCP and there is nothing to configure. The server binds `0.0.0.0`
and `[::]`, and no part of this program reads its own IP to decide anything.

**Today that is the kernel's built-in client (`ip=dhcp`), which takes a lease and never renews it.**
That is a stopgap, not a design — `OS-019` (#335) replaces it with a real client in the program.
Until then, reserve the address on your DHCP server. You want to anyway: the SRV record has to point
somewhere.

### Memory (`OS-011`, #262)

`crates/kmsrs-server/src/budget.rs` adds up the CMID table, the event-log ring buffer and the
connection state budget, and asserts the total at **compile time**, so a build that would exceed the
ceiling does not link. The current ceiling is 8 MiB of heap; 512 MiB is a comfortable VM size.

The failure mode is worth knowing: this program is PID 1, the kernel refuses to OOM-kill PID 1, and
`panic = "abort"` means a panic ends the machine. So an allocation failure is a kernel panic on the
console rather than a silent restart — loud, which is the right direction, and the reason the budget
is a compile-time assertion rather than a runtime check.

### What still needs doing

The userland is one program, and several things a normal userland provides are not there yet:

| | |
|---|---|
| DHCP lease renewal | `OS-019` (#335) |
| Clock discipline (NTP) | `OS-020` (#336) — kvmclock only, today |
| Reporting the guest's address and memory to the hypervisor | `OS-022` (#338) |

**`qm shutdown` does nothing; use `qm stop`.** The button sends an ACPI event, which the kernel turns
into an input event on `/dev/input/eventN` that `acpid` would normally consume. There is no userland
here to consume it. Fixing that means adding the input subsystem to the kernel's allowlist as well as
code, so it is `OS-025` (#343) rather than something done quietly.

What *is* done (`OS-021`, #337): pid 1 mounts devtmpfs, `/proc` and `/sys`, and runs a reaper for
orphaned children. It reports what it mounted on the console at boot —
`{"event":"pid1","detail":"mounted /dev /proc /sys"}` — which is the line to look for if a guest
misbehaves.

## What is not in the artifact

**No secrets, of any kind** (`SEC-013`, #205). Not "the secrets are well protected" — there are none
to protect, and this is a property of the design rather than of care taken.

- **The three protocol keys are published constants.** They are compiled into every genuine KMS host,
  every KMS client, and both open-source emulators; recovering them takes a disassembler and an
  afternoon. The protocol uses them for framing and for proof-of-decryption, not for
  confidentiality — a KMS activation exchange protects nothing, because there is nothing in it worth
  protecting. That is also why `kmsrs-crypto` skips constant-time discipline entirely
  (`CRY-017`, #56).
- **No DNS update credential.** RFC 2136 is declined ([D15](decisions.md#d15)), and the reason given
  there is partly this one: a shared TSIG key in a published container image is a secret in name
  only.
- **No authentication anywhere.** The web UI is read-only ([D27](decisions.md#declined-with-rationale)),
  so there is no password, no session, no token and no cookie. RPC authentication is declined
  ([D4](decisions.md#declined-with-rationale)) because real KMS clients never authenticate.
- **No disk I/O at all** (axiom A5), so there is no key file, no credential file and no database
  connection string — nor anywhere to put one.
- **No configuration that could carry one.** The single runtime setting is a TOML document restricted
  to fields that cannot change a byte on the wire (`CFG-001`, #166), and
  `wire_is_not_configurable.rs` is the test that keeps it that way.

Checked rather than asserted: `no_secret_material_is_embedded` in
`crates/kmsrs-server/tests/workspace_invariants.rs` fails if a shipped source names anything
credential-shaped, if a PEM block or an access-key prefix appears anywhere, or if `kmsrs-crypto`'s key
module grows a fourth constant — which is the one place in the tree where key material would arrive
looking like it belonged.

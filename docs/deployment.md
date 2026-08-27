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
- [Windows, as a service](#windows-as-a-service)
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
| `windows-x86_64`, `windows-aarch64` | `kmsrs-server.exe` and `kmsrs-client.exe`, cross-compiled. Both are named; neither is the default (`PKG-020`, #379) |

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
sudo install -m 0755 result/bin/kmsrs-server /usr/local/bin/
sudo install -m 0644 deploy/systemd/kmsrs-server.service /etc/systemd/system/
sudo systemctl enable --now kmsrs-server
journalctl -u kmsrs-server -f
```

Both audited projects have only a documentation snippet for this, and py-kms's is `User=root` with no
hardening whatever. `deploy/systemd/kmsrs-server.service` is a real unit (`PKG-007`, #244), and almost
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
kmsrs-server: started with LISTEN_FDS=1, but this build does not adopt inherited sockets.
```

That is not fussiness. Ignoring it under `Accept=yes` would mean one process per connection, which
destroys both the stable ePID and the CMID table **while continuing to answer** — the way
vlmcsd-under-systemd degrades without telling anybody ([D20](decisions.md#declined-with-rationale)).

---

## Windows, as a service

**Two binaries since `PKG-020` (#379): `kmsrs-server-windows-x86_64.exe` and
`kmsrs-server-windows-aarch64.exe`.** Take the one that matches the machine — Snapdragon X, a Windows
Dev Kit, or a Windows 11 on Arm VM on Apple Silicon all want the second — and rename it to
`kmsrs-server.exe` if you are following the `sc.exe` line below literally.

**This section applies to both architectures.** The ARM64 binary is started on real ARM64 Windows on
every pull request (`PKG-022`, #385), and on Windows 11 build 26200 it serves an activation and takes
all five process mitigations of `SEC-019` (#356) — `ProcessSystemCallDisablePolicy` included. There is
nothing to read differently here for Arm. If some future Windows declines one of the five, the host
reports which, by name, at start-up (`SEC-020`, #392) rather than claiming a mitigation it does not
have, and goes on serving.

`PKG-008` (#245). The binary detects for itself whether it was started by the Service Control
Manager — `StartServiceCtrlDispatcher` fails with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` when it
was not — so the same `.exe` is both a console program and a service with no switch to get wrong.

Installation is one line, and there is deliberately no `--install` verb:

```
sc.exe create kmsrsos binPath= "C:\Program Files\kmsrsos\kmsrs-server.exe" start= auto DisplayName= "kmsrsos KMS host"
sc.exe start kmsrsos
```

The spaces after `binPath=`, `start=` and `DisplayName=` are `sc.exe`'s syntax, not typos.

**Why there is no installer.** An in-binary installer is the code that produced both of vlmcsd's
service bugs — a password embedded in the `ImagePath` where any user can read it out of the
registry, and a `strcat` overflow building that command line. This program takes no arguments at all
(`CFG-007`, #172), so there is no argv to embed and no argv to concatenate: both bugs are
unrepresentable rather than fixed. The cost is that you type the line above.

### The web UI is not optional here

**A Windows service has no stderr.** This program writes its log to stderr and nowhere else — no
files, no Event Log for the request stream (axiom A5) — so under the SCM that output goes nowhere.
In service mode the request log is readable **only** through the web UI on port 8080.

That is a real constraint, not a preference. If you firewall off 8080 on a Windows service
installation, you have a KMS host you cannot observe at all.

Start-up failures are the sharper edge, because a bind failure or a failed entropy self-test means
the web listener never comes up either — there is nothing to browse to and nothing on stderr.
`OBS-016` (#192) is the six-event Windows Event Log that exists for exactly that window.

### Registering the Event Log source

`OBS-016` (#192). Do this next to the `sc.exe create` above, and for the same reason there is no
installer — it is one line, and a line you can read:

```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\kmsrsos" /v EventMessageFile /t REG_SZ /d "C:\Program Files\kmsrsos\kmsrs-server.exe" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\kmsrsos" /v TypesSupported /t REG_DWORD /d 7 /f
```

The binary is its own message file, which is what the first line says. Skip it and the events still
arrive, but Event Viewer renders every one of them as *"The description for Event ID 1 cannot be
found"* — which looks like a broken program rather than a missing registry value.

**Six events, and the request stream is not among them:**

| Id | Level | When |
|---:|---|---|
| 1 | Information | Listeners bound and serving |
| 2 | Information | Drain finished, stopping cleanly |
| 3 | Error | Nothing could be bound |
| 4 | Error | The entropy self-test failed |
| 5 | Error | `KMSRSOS_CONFIG` could not be parsed |
| 6 | Error | The process panicked |

Every one carries the underlying error as its message. Activations are **not** logged here and will
not be: the Event Log is shared, size-limited and administrator-visible, and a KMS host filling it
with one record per request would be a denial of service against everything else that logs there.
The request stream stays on stderr and the web UI.

Events 3, 4 and 5 are the ones this exists for — each happens before any listener is up, so the web
UI cannot report them and, under the SCM, neither can stderr.

### What the service does and does not accept

| Control | Behaviour |
|---|---|
| `STOP` | Stop accepting, drain in-flight connections, then report `STOPPED` |
| `SHUTDOWN` | The same — the machine going down is not a different question |
| `INTERROGATE` | Answered |
| `PAUSE` / `CONTINUE` | Not implemented. A paused KMS host is a KMS host that fails activations while claiming to be installed |

The state transitions are the honest ones. `START_PENDING` is reported while the entropy self-test
runs and the listeners bind, accepting no controls, with a 30-second wait hint; `RUNNING` is reported
**at the moment the listeners are bound and before the first connection is accepted**, not when the
process started. Anything with a service dependency on this one therefore starts after there is
something to talk to.

If start-up never gets that far, the service reports `STOPPED` with `ERROR_PROCESS_ABORTED` rather
than a clean exit, so the SCM and any recovery policy can tell a failed start from a normal stop.

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

### The artifact (`OS-017`, #333; `PKG-019`, #378)

**Two images, one per architecture**, each built on its own architecture's runner and each named for
it. `.#linuxIso` on a system is the image *for* that system; there is no cross-compiled image and no
dual-architecture one (declined as [D44](decisions.md#d44)).

```shell
$ nix build .#linuxIso        # kmsrsos-x86_64.iso 5.3 MiB, kmsrsos-aarch64.iso 4.4 MiB
$ nix build .#linux-kernel    # the kernel on its own
```

| | x86_64 | aarch64 |
|---|---|---|
| firmware | SeaBIOS **or** UEFI | UEFI only — arm64 guests have no BIOS |
| kernel file | `bzImage`, 3 560 448 B | `vmlinuz.efi`, 3 760 640 B — `CONFIG_EFI_ZBOOT`, against 7 660 032 B uncompressed |
| bootloader | isolinux for BIOS, a six-module GRUB in the ESP for UEFI | **none** |
| kernel lives in | ISO9660 | the EFI System Partition |
| ESP | 2 MiB | 4 MiB |
| whole image | 5 582 848 B | 4 603 904 B |

The arm image is **strictly simpler and slightly smaller**, and the reason is that `OS-030`'s GRUB
solves a problem it does not have: isolinux reads ISO9660, UEFI reads FAT, and a bootloader in the
ESP is what lets one kernel serve both. With one firmware there is nothing to bridge, so the kernel
is the EFI executable and firmware runs it directly. The full argument and the measurements are in
[`decisions.md`](decisions.md#the-arm-image-has-no-bootloader-os-033-377).

Everything below this line describes the x86_64 image unless it says otherwise; the arm one has its
own section further down.

**One ISO, both firmwares, and one copy of the kernel** (`OS-030`, #348). The 3.4 MiB `bzImage` lives
in the ISO9660 filesystem and nowhere else. isolinux reads it there for BIOS; a small `grubx64.efi` in
the EFI System Partition reads it there for UEFI. All four combinations —
`{CD-ROM, raw disk} × {SeaBIOS, OVMF}` — are booted on every `nix flake check`.

The image carried the kernel three times until `OS-029` (#347) and twice until `OS-030`, because UEFI
reads only FAT and isolinux reads only ISO9660. Putting a bootloader that reads ISO9660 in the ESP
took it to one and the ISO from 8.3 MiB to 5.3 MiB.

**The GRUB in the ESP is 278 KiB and runs four commands.** It is built with `grub-mkimage` from six
named modules, with an empty prefix and its configuration embedded in the executable — so there is no
`grub.cfg` in the ESP to edit, no module directory to load from, and no `normal` module, which means
no menu and no scripting. The whole of it:

```
search --no-floppy --set=root --label KMSRSOS
linux /bzImage
boot
halt
```

`CONFIG_EFI_STUB` still makes the `bzImage` a PE/COFF executable as well as a Linux boot image — `MZ`
at offset 0 and `HdrS` at 0x202 — and that is what GRUB's `linux` command uses to hand over. Nothing
is registered in NVRAM, so a fresh VM still boots on its first try.

The initramfs and the kernel command line are *inside* that file
(`CONFIG_INITRAMFS_SOURCE`, `CONFIG_CMDLINE_OVERRIDE`). The second is not a convenience: it means a
bootloader passing a different command line is **ignored**, so the kernel command line is a
build-time decision like every other setting here (axiom A3, `CFG-001` #166).

### Which hypervisors this runs on — x86_64 (`OS-025`, #342)

**The column that matters is the last one.** A driver list is never complete, and the failure this
matrix exists to prevent is not "it did not boot" — it is a machine that boots to completion, prints
`listening`, and then answers nobody forever because no driver claimed its NIC. So every row says
how it was checked, and "reasoned" means exactly that: read from documentation, never observed.

| Platform | Firmware | Default NIC | Driver | Checked how |
|---|---|---|---|---|
| **Proxmox VE / QEMU-KVM** | SeaBIOS or OVMF | virtio-net | `virtio_net` | **Observed**: boots and serves on both firmwares, on the exact PCI topology `qemu-server` emits |
| Proxmox — *Intel E1000* | either | e1000 | `e1000` | **Observed** |
| Proxmox — *Intel E1000E* | either | e1000e | `e1000e` | **Observed** |
| Proxmox — *Realtek RTL8139* | either | rtl8139 | `8139cp` | **Observed** |
| Proxmox — *VMware vmxnet3* | either | vmxnet3 | `vmxnet3` | **Observed** |
| **Nutanix AHV** | UEFI or legacy | virtio-net | `virtio_net` | Reasoned — it is KVM, and the device model is the one above |
| **VMware ESXi / vSphere** | EFI on 7.x+ | vmxnet3 | `vmxnet3` | Device model observed in QEMU; **ESXi itself not booted** |
| **VMware Workstation / Fusion** | BIOS or EFI | e1000e | `e1000e` | Device model observed; the product not booted |
| **VirtualBox** | BIOS or EFI | Intel 82540EM | `e1000` | Device model observed; the product not booted. `pcnet32` is in for the older adapter choices |
| **Hyper-V Gen 1** | BIOS | synthetic (VMBus) | `hv_netvsc` | **Not observed.** VMBus cannot be exercised in QEMU at all |
| Hyper-V Gen 1 — *Legacy Network Adapter* | BIOS | DEC 21140 | `tulip` | Device model observed in QEMU |
| **Hyper-V Gen 2 / Azure** | UEFI | synthetic only — no emulated NIC exists | `hv_netvsc` | **Not observed.** Secure Boot must be turned off: the EFI stub is unsigned |
| **Xen — XCP-ng / Citrix** | HVM | rtl8139 | `8139cp` | Device model observed |
| Xen — PV path | HVM | xen-netfront | `xen_netfront` | **Not observed** |
| **bhyve** | UEFI only | virtio-net | `virtio_net` | Reasoned. The console path is unverified — there is no VGA unless `fbuf` is configured |
| **Cloud Hypervisor** | direct kernel boot | virtio-**pci** | `virtio_net` | Reasoned |
| **Parallels Desktop** | EFI | e1000 or virtio | both | Reasoned |
| **EC2** | UEFI | ENA | `ena` | **Not observed** — `OS-027` (#344) |

`nix flake check` runs `linux-nics`, which boots the shipped ISO once per QEMU device model in that
table and asserts the machine **serves an activation**, not that it booted. Everything marked
"observed" is that check; everything else is a claim.

#### What each row costs

Measured on the built `bzImage` with the initramfs held constant, which is the only way the number
means anything — the initramfs is *inside* the image, so a change to the program moves the total by
more than a driver does. Reproduce with `nix build .#linux-deltas && cat result/report`.

| Driver | Cost | For |
|---|---|---|
| `8139cp` + `8139too` | +12 KiB | Proxmox's RTL8139 entry; Xen HVM's default |
| `pcnet32` | +12 KiB | VirtualBox's older adapters |
| `tulip` | +16 KiB | Hyper-V Gen 1's Legacy Network Adapter |
| `vmxnet3` | +24 KiB | VMware, and Proxmox's vmxnet3 entry |
| `ena` | +24 KiB | EC2 Nitro |
| **VMBus** (`hv_netvsc` + timer) | **+40 KiB** | Hyper-V Gen 1 and 2, Azure |
| ~~Xen PV~~ (`xen-netfront`) | ~~+148 KiB~~ | **declined** — see below |
| **all of the above, as shipped** | **+120 KiB** | 2,364,416 → 2,487,296 bytes |

The total is less than the sum, because drivers sharing a vendor gate pay for it once. Taking Xen on
top of this would add a further **140 KiB**.

**For scale, the drivers are the small part.** The whole `bzImage` went from 2,814,976 to 3,539,968
bytes across this round of work, and the kernel configuration is a rounding error in that:

| | |
|---|---|
| `OS-026` (#343) — the power button, net of what it let go | −36 KiB |
| `OS-025` (#342) — the platform matrix | +120 KiB |
| `OS-023` (#339) — the pare-back | −36 KiB |
| **the initramfs** | **≈ +660 KiB** |
| | **+708 KiB** |

The initramfs is inside the `bzImage`, and it grew because the DHCP and SNTP clients of `OS-019`
(#335) and `OS-020` (#336) brought a DNS library with them. That was a deliberate trade — the
reasoning is in [`decisions.md`](decisions.md) — and this is what it weighs. Anyone wanting a
smaller image should start there and not with the drivers.

**VMBus was expected to be the expensive one and is not.** The kernel config used to say `hv_netvsc`
"drags in the whole VMBus stack, which is not a driver-sized cost". Measured, it is 40 KiB — less
than twice a plain PCI driver. The estimate had never been taken on a built image.

### Which hypervisors this runs on — aarch64 (`OS-032`, #376)

**Proxmox VE 9.2 for arm64 shipped on 5 August 2026** — Debian 13.5, Linux 7.0, the same codebase as
the x86-64 edition, with parity across KVM, LXC, ZFS and Ceph. NVIDIA Grace and Vera are fully
supported; other UEFI Armv8-A/Armv9-A hardware is best-effort. Device-tree-only boards such as the
Raspberry Pi are **not** supported, because the host must boot through UEFI and describe its hardware
through ACPI.

KVM is same-architecture, so an operator on one of those hosts can run aarch64 guests and nothing
else. The audience is wider than the hosts, though: on Apple Silicon the entire lab is aarch64 —
Parallels and Fusion run Arm guests only, and UTM's x86_64 path is TCG — and Snapdragon X and Windows
Dev Kit machines are Arm Windows clients that want a KMS host on the same LAN.

**The matrix is a third of the size, and that is a claim about products rather than about kernels.**

| Platform | Firmware | Default NIC | Driver | Checked how |
|---|---|---|---|---|
| **Proxmox VE for arm64 / QEMU-KVM** | UEFI (AAVMF) only | virtio-net | `virtio_net` | **Observed**: boots and serves under `qemu-system-aarch64 -machine virt` |
| Proxmox — *Intel E1000* | UEFI | e1000 | `e1000` | **Observed** in QEMU. Whether the arm64 web UI still offers the model is *not* observed |
| Proxmox — *Intel E1000E* | UEFI | e1000e | `e1000e` | **Observed** in QEMU; same caveat |
| **EC2 Graviton** | UEFI | ENA | `ena` | **Observed on a real instance** — see [On EC2](#on-ec2-os-027-344) |
| **Apple Silicon: Parallels, VMware Fusion** | UEFI | virtio-net or an emulated Intel adapter | `virtio_net`, `e1000e` | Device models observed in QEMU; the products not booted |
| **UTM** (Apple Virtualization or QEMU) | UEFI | virtio-net | `virtio_net` | Reasoned — it is the same device model |
| **Azure Cobalt 100** | UEFI | synthetic only (VMBus) | `hv_netvsc` | **Not observed.** VMBus cannot be exercised in QEMU at all |
| ~~VirtualBox~~ | — | — | — | no aarch64 guests exist to support |
| ~~Hyper-V Generation 1~~ | — | — | — | Generation 1 is x86; Arm Azure is Generation 2, so VMBus |
| ~~Xen HVM (XCP-ng, Citrix)~~ | — | — | — | no aarch64 guests |
| ~~VMware ESXi~~ | — | — | — | ESXi-on-Arm was a fling and is discontinued |

`vmxnet3`, `8139cp`, `pcnet32` and `tulip` are therefore **absent from the arm kernel**, and
`kernel_tcb.rs` asserts their absence — which is what stops the arm allowlist quietly growing into a
copy of the x86 one.

#### What each row costs

`nix build .#linux-deltas && cat result/report` on an aarch64 machine, initramfs held constant,
against a 2 740 736-byte `vmlinuz.efi` baseline:

| Driver | Cost | For |
|---|---|---|
| `e1000` + `e1000e` | +100 KiB | Proxmox's Intel entries; Parallels and Fusion on Apple Silicon |
| `hv_netvsc` | +40 KiB | Azure Cobalt 100 |
| `ena` | +32 KiB | EC2 Graviton |
| KASLR | +4 KiB | `RANDOMIZE_BASE`, which x86 had by default and this did not |
| ~~`virtio-gpu`~~ | ~~+12 KiB~~ | **not taken** — see the console note below |

**The image format dominates every driver.** `CONFIG_EFI_ZBOOT` is worth **3.69 MiB**, thirty times
the largest driver: arm64's `Image` is uncompressed and there is no self-decompressing counterpart of
`bzImage`.

#### The console is two devices, not one

**QEMU's `virt` machine has a PL011 (`ttyAMA0`). EC2's aarch64 instances have a 16550A (`ttyS0`).**
Both are in the kernel and both are on the command line, because a kernel naming only the first would
boot correctly on EC2 and print nothing at all — `OS-005` (#256) with no symptom. Observed on a
Graviton host, where ACPI SPCR reads `uart,mmio,0x90a0000,115200` and the kernel reports
`ttyS0 … is a 16550A`.

The framebuffer half is less settled. `-machine virt` has **no display device by default**; a `ramfb`
gives an EFI GOP that `simpledrm` takes over, and a `virtio-gpu` does not — the EFI framebuffer stops
being scanned out at `ExitBootServices` and the window freezes on the firmware logo. `DRM_VIRTIO_GPU`
would cost 12 KiB and is not in the kernel, because nothing observed needs it yet. If a Proxmox arm64
VM shows a frozen console, that is the reason and the fix is measured.

#### Powering it off

`qm shutdown` works, and the mechanism is different: on `-machine virt` the press arrives through the
ACPI **Generic Event Device** rather than a fixed-hardware power button, and the machine powers down
through **PSCI `SYSTEM_OFF`** rather than an ACPI register write. It surfaces as the same evdev
`KEY_POWER`, so `OS-026` (#343)'s drain runs unchanged. Observed on every `nix flake check`.

#### KASLR needs an RNG the firmware can offer

`CONFIG_RANDOMIZE_BASE` is compiled in, and arm64 takes its seed from `EFI_RNG_PROTOCOL`. Under a
plain AAVMF with no RNG source the boot log says `KASLR disabled due to lack of seed` and the kernel
runs at its link address; on EC2, where firmware has one, it is seeded and that line is absent.
**Attach `virtio-rng`** — it is the same checkbox that is worth a second of boot time on x86.

**The Xen paravirtual path is the expensive one, and is declined.** 148 KiB is 6 % of the whole
kernel, because it is xenbus, grant tables and event channels rather than a driver. What it buys is
throughput on XCP-ng and Citrix Hypervisor — whose *default* emulated NIC is RTL8139 and therefore
already works for 12 KiB. A host that answers one 384-byte request per client per few hours does not
need the faster path.

**A machine with no usable interface says so.** That is the other half of this, and the half no
driver list can cover:

```
{"level":"error","event":"dhcp","detail":"this machine has no Ethernet interface, so it
 will never have an address and no client will ever reach it. The usual cause is a NIC
 model with no driver in this kernel — see the supported list in docs/deployment.md"}
```

It keeps retrying rather than giving up, because a hypervisor that attaches the NIC a moment late
looks identical at boot. The `linux-nics` check boots a machine with `-nic none` and asserts that
sentence appears — and that the host still binds its port, because a host that cannot find a NIC is
not a host that should refuse to start.

#### On Proxmox

Create a VM with **no disk**, upload `kmsrsos-x86_64.iso` to your ISO storage, attach it to the
CD-ROM drive, and boot it. That is the whole procedure. SeaBIOS or OVMF both work, so the default
BIOS setting is fine and an EFI disk is only needed if you choose OVMF.

**On Proxmox VE for arm64 the procedure is the same, with `kmsrsos-aarch64.iso`**, and there is no
BIOS setting to leave alone because there is no BIOS. **No EFI disk is needed either**: the kernel
sits at `\EFI\BOOT\BOOTAA64.EFI`, which is the UEFI specification's removable-media path, so
firmware runs it with nothing registered in NVRAM. That is checked rather than assumed — the arm
`linux-iso-layout` boots the image twice from a variable store that is a fresh copy of the template
both times, which is exactly a VM with no `efidisk0`.

Two things are worth adding, neither of which is required for it to serve:

| | Why |
|---|---|
| **Hardware → Add → virtio-rng** | Cuts time-to-serving by **more than half** — see the numbers below. The program blocks in `getrandom(2)` until the kernel's CRNG is seeded, and on a CPU model without RDRAND that takes seconds of jitter entropy |
| **Hardware → Add → Serial Port** `0`, then **Options → Display → Serial terminal 0** | Convenience, not necessity — the framebuffer console already shows the boot in the noVNC window |

#### How long it takes to start

Measured on the shipped ISO, `-machine q35 -cpu qemu64 -enable-kvm -smp 1 -m 512M`, best of three,
from the QEMU process starting to the guest printing `listening`:

| Firmware | virtio-rng | Seconds |
|---|---|---|
| SeaBIOS | no | 1.70 |
| SeaBIOS | **yes** | **0.71** |
| OVMF | no | 3.33 |
| OVMF | **yes** | 1.86 |

So **attach virtio-rng**: it is worth a second on BIOS and a second and a half on UEFI, and it is one
checkbox. Firmware is what is left — OVMF costs about 1.1 s more than SeaBIOS before Linux starts,
and that is PE loading and relocation rather than I/O (CD-ROM and SATA measure identically).

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
    -drive file=result/kmsrsos-linux-x86_64.iso,media=cdrom,readonly=on \
    -netdev user,id=u1,hostfwd=tcp:127.0.0.1:1688-:1688 \
    -device virtio-net-pci,netdev=u1 \
    -device virtio-rng-pci
```

The aarch64 image, which needs firmware because there is no other way to start it:

```shell
$ cp $(nix eval --raw nixpkgs#OVMF.variables) vars.fd && chmod +w vars.fd
$ qemu-system-aarch64 -machine virt,gic-version=3 -cpu host -enable-kvm \
    -smp 1 -m 512M -display none -serial stdio -no-reboot \
    -drive if=pflash,format=raw,unit=0,readonly=on,file=$(nix eval --raw nixpkgs#OVMF.firmware) \
    -drive if=pflash,format=raw,unit=1,file=vars.fd \
    -device ramfb \
    -drive file=result/kmsrsos-linux-aarch64.iso,media=cdrom,readonly=on \
    -netdev user,id=u1,hostfwd=tcp:127.0.0.1:1688-:1688 \
    -device virtio-net-pci,netdev=u1,bus=pcie.0 \
    -device virtio-rng-pci
```

`-cpu host -enable-kvm` only on an aarch64 host; drop both for TCG and use `-cpu cortex-a57`.
`vars.fd` is a scratch copy that is thrown away — nothing is written to NVRAM, which is the same
reason a Proxmox VM needs no `efidisk0`.

`kmsrs-client 127.0.0.1:1688` is the check that it answers *correctly*. The `linux-boot` check in
`nix flake check` runs exactly this on both firmwares on x86_64 — on the PCI topology `qemu-server`
emits, with no `--args`, so the two conditions that defeated the unikernel are exercised on every
change — and its arm twin runs the second block above.

### The console (`OS-028`, #345)

**Every line this program writes goes to every console the kernel registered.** Not to one of them.
Pid 1 reads `/proc/consoles` at boot, opens each console's device node, and tees its own stdout and
stderr — which is also the KMS host's log, and a panic message — to all of them.

That is worth stating because the consequence is visible: **an operator watching both the noVNC
window and a serial port sees the same JSON twice.** That is correct, not a bug, and there is no
setting to turn it off.

The line that says which consoles were found comes first in the boot:

```
{"level":"info","event":"console","detail":"logging to tty0 ttyS0"}
```

If that says `inherited stderr: …` instead, the tee could not be installed and output goes to
`/dev/console` alone, as it did before this change. The machine still serves; you may just be
looking at the wrong console.

Why it works this way: `/dev/console` — which the kernel hands pid 1 as fds 0, 1 and 2 — resolves to
the **last** `console=` entry on the command line, while kernel messages go to all of them. So
before this, whichever console came last got the program's log and the other showed a clean boot
followed by silence, which reads exactly like a program that never started (`OS-005`, #256). Which
console an operator can actually read is a property of the platform — the framebuffer on Proxmox,
`ttyS0` and nothing else on EC2 (`OS-027`, #344) — so there was no ordering that was right
everywhere. Now the ordering decides nothing.

### What is in the kernel, and what is not

`os/linux/kernel.config` is checked in and is meant to be read. The base is `make tinyconfig`, so
every subsystem defaults to **off** and each of the ~90 enabled entries is a deliberate line — the
file is the statement of what is in this machine's TCB. `os/linux/config.nix` regenerates it and
carries the reasoning per group.

**Axiom A5 is structural here.** `CONFIG_BLOCK` is unset: there is no block *layer*, not merely no
block drivers, so disk I/O is a syscall with nothing behind it. The boot medium is invisible to the
kernel — the bootloader reads the image and it runs from RAM thereafter — so no ATAPI, no SCSI and no
ISO9660 are compiled in either. After boot the CD-ROM could be ejected.

The ISO9660 reader that finds the kernel is **in the bootloader, not in the kernel**: isolinux's for
BIOS and GRUB's `iso9660` module for UEFI (`OS-030`, #348). Neither is running by the time pid 1
starts, so this changes nothing about what is in the machine's TCB once it is up.

Also absent, deliberately: modules, netfilter, BPF, tracing, cgroups, namespaces, USB, sound, and
every filesystem but ramfs, tmpfs, proc and sysfs.

Present because something needs them: PCI and ACPI (the NIC is on a PCI bus), the 8250 UART **and** a
framebuffer console, virtio-net plus `e1000`/`e1000e` for hypervisors that do not offer virtio,
`seccomp`, and `kvmclock` — which keeps the clock close between the SNTP polls of `OS-020` (#336).

### Addressing (`OS-003`, #254; `OS-019`, #335)

The guest takes its address from DHCP and there is nothing to configure. The server binds `0.0.0.0`
and `[::]`, and no part of this program reads its own IP to decide anything.

**The DHCP client is part of the program.** `CONFIG_IP_PNP_DHCP` — the kernel's built-in client — is
gone, because it took a lease and never renewed it, and because it discarded the three options this
host most wants. What it does now:

| | |
|---|---|
| Renews at T1 and rebinds at T2 | So a lease that expires does not silently take the host off the network hours after a boot that looked fine |
| Reads **option 15** and **option 119** | The domain your clients search, which is the zone the `_vlmcs._tcp` SRV record has to go in. The `/instructions` page fills it in for you instead of printing `EXAMPLE.COM` |
| Reads **option 42** | The NTP servers, which the clock discipline below prefers over anything on the internet |
| Says so when there is no interface | A NIC model with no driver in this kernel used to produce a machine that booted, reported `listening`, and served nobody forever. It now says that on the console |

The client's whole conversation is on the console, at `"event":"dhcp"`:

```
{"level":"info","event":"dhcp","detail":"using eth0 (52:54:00:12:34:56)"}
{"level":"info","event":"dhcp","detail":"Init -> Selecting"}
{"level":"info","event":"dhcp","detail":"192.168.1.1 offered 192.168.1.50"}
{"level":"info","event":"dhcp","detail":"192.168.1.50/24 on eth0, lease 3600s"}
{"level":"info","event":"dhcp","detail":"Requesting -> Bound"}
```

Every RFC 2131 state transition appears once, which is the trace to look at when a lease is not
being renewed — the alternative symptom is an address that stops working in the middle of the night.

**Reserve the address on your DHCP server anyway.** Not because the lease will lapse — it will not —
but because the SRV record and every `slmgr /skms` your clients hold have to point somewhere stable.
If a renewal ever comes back with a *different* address, the host takes the old one off, uses the new
one, and says this on the console:

```
{"level":"info","event":"dhcp","detail":"the lease moved from 192.168.1.50 to 192.168.1.77;
 anything pointing at 192.168.1.50 — an SRV record, a client's slmgr /skms — is now wrong"}
```

**A machine with more than one NIC takes a lease on the lowest-numbered one and says which.** The KMS
port is bound on all of them regardless; the choice only decides where the DHCP conversation happens
and which address the page suggests you publish.

### Memory (`OS-011`, #262)

`crates/kmsrs-server/src/budget.rs` adds up the CMID table, the event-log ring buffer and the
connection state budget, and asserts the total at **compile time**, so a build that would exceed the
ceiling does not link. The current ceiling is 8 MiB of heap; 512 MiB is a comfortable VM size.

The failure mode is worth knowing: this program is PID 1, the kernel refuses to OOM-kill PID 1, and
`panic = "abort"` means a panic ends the machine. So an allocation failure is a kernel panic on the
console rather than a silent restart — loud, which is the right direction, and the reason the budget
is a compile-time assertion rather than a runtime check.

### The clock (`OS-020`, #336)

**Nothing in a KMS response derives from this host's clock.** The v6 key schedule derives from the
*client's* timestamp, every deadline in the program is monotonic, and the wall clock is read exactly
once at start-up. So the clock matters for the log, and for the ±4 hour skew band a future strict
build would compare a client against — not for whether anything activates.

That decides the two questions an operator would ask:

- **Where the time comes from.** DHCP option 42 if the lease supplies it, because that is your own
  infrastructure and on an isolated LAN the only thing reachable. Otherwise `pool.ntp.org`, resolved
  through the lease's own DNS servers — there is no `/etc/resolv.conf` here to configure, and no
  resolver that would read one. The pool hostname is a build-time constant like every other setting
  (`CFG-001`, #166).
- **What happens when nothing answers.** **The host serves anyway, with the clock it booted with**,
  and says so once. Refusing to activate because an NTP server was unreachable would trade this
  machine's entire function for a log field. On every platform in the matrix above the clock is
  already close — kvmclock, the Hyper-V reference TSC, or a real RTC.

It steps rather than slews, once every seventeen minutes, when the offset exceeds a second:

```
{"level":"info","event":"clock","detail":"stepped -3s from a stratum 2 server (round trip 4ms)."}
```

A correction larger than a day is logged at `warn` — that is a VM restored from a snapshot or a dead
RTC battery, not drift.

**A step cannot disturb anything in flight**, and not because this code is careful about it:
`clock_settime` moves `CLOCK_REALTIME` and never `CLOCK_MONOTONIC`, and every deadline this program
has is monotonic. `the_wall_clock_is_read_in_exactly_two_places` in
`crates/kmsrs-server/tests/workspace_invariants.rs` is what keeps that true — it fails if the request
path ever grows a `SystemTime::now()`.

This is SNTP (RFC 4330), not NTP. No discipline loop, no peer selection: a `pool.ntp.org` answer is
taken from the first server that gives a usable one, so a lying time server is believed. That is
acceptable only because the DHCP server that named it already controls this host's address and
routing and can do considerably worse — it is a property, not an oversight.

### On EC2 (`OS-027`, #344)

**This target is for an operator who already has a VPN or a site-to-site link into the VPC.** The
loopback constraint at the top of this document applies here with more force, not less: an EC2
instance is the easiest possible place to give clients an address they cannot route to, and exposing
1688 to the internet is not the intended deployment — see the source-IP ACL decision
([12](decisions.md)) for why there is no ACL to lean on either.

Nothing here needs a different artifact. The same ISO is already a GPT disk with a typed EFI System
Partition (`OS-027`, #344 changed one xorriso flag to make that true), and `aws ec2 import-image` —
which would refuse it, since a kernel with no distribution underneath is not a guest OS it
recognises — is not on the path. `coldsnap` writes raw bytes to an EBS snapshot through the EBS
direct APIs with no inspection at all.

```shell
# 1. A snapshot of the ISO, byte for byte. Nothing inspects it.
$ nix build .#linuxIso
$ coldsnap upload --region eu-west-1 result > snapshot-id

# 2. An AMI over that snapshot.
$ aws ec2 register-image --region eu-west-1 \
    --name kmsrsos \
    --description "kmsrsos KMS host" \
    --architecture x86_64 \
    --root-device-name /dev/xvda \
    --boot-mode uefi \
    --ena-support \
    --virtualization-type hvm \
    --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=$(cat snapshot-id),VolumeSize=1,DeleteOnTermination=true}"
```

For the arm image, `--architecture arm64`; everything else is identical, and `--boot-mode uefi` is
not optional there because nothing else exists.

`--boot-mode uefi` is the load-bearing one: firmware reads the ESP off the volume and Linux never
touches a block layer, exactly as it does from a CD-ROM, so axiom A5 is untroubled.
`--ena-support` matches `CONFIG_ENA_ETHERNET` in the kernel — without it a Nitro instance lands in
precisely the silent no-address failure the [matrix](#which-hypervisors-this-runs-on-os-025-342)
exists to eliminate. Secure Boot is off on EC2 unless keys are enrolled, so the unsigned EFI stub is
fine.

Read the log with `aws ec2 get-console-output`, which reads `ttyS0` and nothing else. That works
because pid 1 writes to every registered console (`OS-028`, #345) rather than to whichever one the
command line ended with.

**Verified on a real instance — on aarch64** (`OS-033`, #377). The arm image was uploaded with
`coldsnap`, registered as an arm64 UEFI AMI and booted on a `t4g.nano`. It took a DHCP lease, stepped
its clock off SNTP and served a real activation to a client outside the VPC:

```
EFI stub: Decompressing Linux Kernel...
[    0.102548] ena 0000:00:05.0: LLQ is not supported Fallback to host mode policy.
[    0.107906] ena 0000:00:05.0 eth0: no PCI slot information
{"level":"info","event":"console","detail":"logging to tty0 ttyS0"}
{"level":"info","event":"listening","detail":"0.0.0.0:1688"}
```

That settles the two claims this section used to list as untested, and one it did not:

- **The backup GPT header is not at the volume's last LBA**, and it does not matter. The upload is
  4.4 MB into a volume that rounds up to 1 GiB, so the backup header sits 4.4 MB in. It booted.
- **`ena` binds on real Nitro hardware.** The line above is the driver claiming the device.
- **`get-console-output` works, and it reads `ttyS0`.** The tee (`OS-028`, #345) is what makes that
  true: the command line names `ttyAMA0` first, and EC2 has no PL011, so a program that wrote only to
  `/dev/console` might still have been readable — but a kernel that named *only* `ttyAMA0` would have
  produced an empty console log on a machine that was working perfectly. Expect roughly five minutes
  before the output appears; that is EC2's buffering, not the guest's.

**The x86_64 image is still unverified on EC2.** Nothing above depends on the architecture except the
`ena` binding and the console device, and both are shared — but that is an argument, not a test.

### Telling the hypervisor about itself (`OS-022`, #338)

**Memory** needs nothing: `virtio-balloon` reports statistics with no guest userland at all, and
`CONFIG_VIRTIO_BALLOON` is in the kernel. Attach the device and the hypervisor sees them.

**The address** needs an agent, and there is one. On Proxmox: **Hardware → Add → QEMU Agent**, or
`qm set <id> --agent 1`. The console says whether it found the channel:

```
{"level":"info","event":"agent","detail":"answering on vport0p1"}
```

or, on a VM without it:

```
{"level":"info","event":"agent","detail":"no org.qemu.guest_agent.0 channel is attached
 to this VM, so the hypervisor will show no address for it. On Proxmox: Hardware -> Add ->
 QEMU Agent, or `qm set <id> --agent 1`"}
```

**Seven commands are implemented and everything else is refused**, which is the more interesting
half of the surface. `qemu-ga` has about forty; most of them are things this program must not do:

| Command | |
|---|---|
| `guest-ping`, `guest-sync`, `guest-sync-delimited` | liveness, and the handshake libvirt and Proxmox send before anything else |
| `guest-info` | what a client asks before deciding which commands to offer |
| `guest-network-get-interfaces` | the one that fills the IP column |
| `guest-get-osinfo` | so the summary page says `kmsrsos` rather than `unknown`. Honest rather than flattering: claiming to be a distribution would invite a management tool to try running a package manager |
| `guest-shutdown` | the same drain the ACPI power button reaches (`OS-026`, #343), not a second one |
| **`guest-exec`, `guest-exec-status`** | **refused.** Remote code execution by design, over a channel with no authentication. There is no shell here to exec into, and `qm guest exec` failing should be a decision rather than an accident of packaging |
| **`guest-file-*`** | **refused.** Disk I/O, which axiom A5 forbids and this kernel has no block layer for |
| **`guest-fsfreeze-*`** | **refused.** Meaningless without a filesystem — and worth knowing before you schedule a backup that expects a quiesced guest |
| **`guest-suspend-*`** | **refused.** `CONFIG_SUSPEND` is unset; a KMS host that suspends is a KMS host that is down |
| everything else | **refused**, with `CommandNotFound` and a reason |

Every refusal is a *reply*. A hypervisor that gets silence waits for a timeout and an operator reads
that as a hung guest, so "not supported" is said rather than implied.

### What still needs doing

Everything a normal userland provides that this host needs, it now has. What is left is
platform reach rather than function — see [the hypervisor matrix](#which-hypervisors-this-runs-on-os-025-342)
for what has been observed and what has only been reasoned about, and `OS-027` (#344) for EC2.

What *is* done (`OS-021`, #337): pid 1 mounts devtmpfs, `/proc` and `/sys`, and runs a reaper for
orphaned children. It reports what it mounted on the console at boot —
`{"event":"pid1","detail":"mounted /dev /proc /sys"}` — which is the line to look for if a guest
misbehaves.

### Stopping it (`OS-026`, #343)

**`qm shutdown` works, and drains.** So does the Shutdown button in the web UI, `virsh shutdown`, and
anything else that sends an ACPI power-button event. What happens is:

```
{"level":"info","event":"power","detail":"acpi power button: draining"}
{"level":"info","event":"stopped","detail":"kmsrs-server"}
{"level":"info","event":"power","detail":"serve returned: powering off"}
```

In-flight connections finish, the listeners close, and the machine powers itself off — the same drain
`SIGTERM` gets on the Linux and Windows builds (`NET-007`, #157), reached through the same code
rather than a parallel one.

Three details worth knowing:

- **The button is found by capability, not by name.** Pid 1 looks through `/sys/class/input` for a
  device claiming `KEY_POWER` rather than assuming `event0`, because which node it lands on depends
  on what else the hypervisor attached — Proxmox adds a USB tablet by default on some machine types.
  The console says which node it found: `{"event":"power","detail":"watching event0"}`.
- **A press during the first fraction of a second is ignored.** The kernel discards signals that pid 1
  has no handler for, and the handler is installed as the host starts serving. Press again.
- **`qm stop` is still there and still drops everything in flight.** It is the hypervisor pulling the
  power; nothing in the guest can make that graceful.

This needed the kernel's evdev interface, which was the one part of the input subsystem that was
missing — `CONFIG_INPUT` and `CONFIG_ACPI_BUTTON` were already on, having arrived as dependencies of
the console rather than as a decision. Naming all three in `os/linux/config.nix` and naming what they
drag in made the change a net *removal* of about fifty lines from the built config: the AT keyboard
driver, PS/2 mouse support and the SERIO bus had been in this machine's TCB since `OS-017` (#333)
without anybody asking for them. Measured on the built `bzImage` with the initramfs held constant,
**2,405,376 → 2,368,512 bytes** — handling the power button makes the kernel 36 KiB smaller.

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

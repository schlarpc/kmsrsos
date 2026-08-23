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
- [Hermit on QEMU and Proxmox](#hermit-on-qemu-and-proxmox)
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

It returns `{ server, client, container }`. `osImage` joins that set once #250 has a hermetic Hermit
build.

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

## Hermit on QEMU and Proxmox

The bare-metal target is a [Hermit](https://github.com/hermit-os) unikernel: one binary that is the
whole operating system, booted by a UEFI loader, talking to virtio-net. QEMU/libvirt is the supported
configuration, because that is what hermit's own CI exercises on every pull request. Proxmox is a
nice-to-have (decision 25), and the constraints below are why.

The findings this section rests on are in
[`research-findings.md` §R2](research-findings.md#r2--hermit-and-proxmox-feasibility), taken from the
kernel and `qemu-server` sources rather than from documentation.

### A serial port is mandatory (`OS-005`, #256)

**Hermit's only console is the 16550 UART at `0x3F8`.** There is no VGA text mode, no framebuffer
console, and no kernel-side logging to anywhere else. A VM without a serial port is a VM that boots
in complete silence — including when it panics, which on a unikernel means the guest simply stops.

In the Proxmox web UI, on the VM:

1. **Hardware → Add → Serial Port**, port number `0`.
2. **Options → Display → Serial terminal 0**.

Then `qm terminal <vmid>` from the Proxmox host attaches to it. Under plain QEMU the equivalent is
`-serial stdio` or `-nographic`.

Do this **before** the first boot. Adding it afterwards works, but the first boot is the one whose
output decides whether virtio-net attached at all, and that output is gone.

### The configuration channel (`OS-008`, #259)

There is exactly one runtime setting (`KMSRSOS_CONFIG`, `CFG-002` #167) and it reaches a Hermit guest
through the loader's boot-arguments file, not through anything the hypervisor offers. What a Proxmox
admin can set from the GUI, and whether it arrives:

| Setting | GUI-settable | Reaches a Hermit guest |
|---|:---:|---|
| DHCP, via the network | yes | **yes** — the sanctioned path, and how the guest gets its address (#254) |
| MAC address | yes | yes — readable by the guest, so it is a per-VM identifier if one is needed |
| Serial port | yes | yes, and mandatory — see above |
| CPU type (`host`) | yes | yes, and **required** — see entropy below |
| SMBIOS type 1 fields | yes | **no** — the kernel has no DMI code and the loader discards the pointer |
| Cloud-init drive | yes | **no** — it arrives as an ISO9660 block device, and there is no block driver |
| `args` / kernel command line | **no** (CLI only) | would work, but Proxmox does not expose it in the web UI |

So the whole GUI-settable channel is **DHCP plus the MAC address**. Everything else comes from the
ESP: a GPT disk whose EFI system partition holds `\EFI\BOOT\BOOTX64.EFI` (the hermit loader),
`\EFI\hermit\hermit-app` (this binary) and optionally `\EFI\hermit\hermit-bootargs`, a plain text file
the loader reads. Boot args accept `env=KEY=VALUE` tokens, which is how `KMSRSOS_CONFIG` is set.

Worked example — serve the web UI on 8081 instead of 8080:

```
# \EFI\hermit\hermit-bootargs on the image's ESP
env=KMSRSOS_CONFIG=web_ui_port = 8081
```

Editing that file is the entire in-place reconfiguration story, and it is deliberately small: the
doctrine is to rebuild the image from the flake (decision 13), and the escape hatch may only touch
settings that cannot change a byte on the wire (`CFG-001`, #166).

### Set the CPU type to `host`

Not cosmetic, and not about speed. Hermit's CSPRNG seeds from **RDSEED** or from virtio-rng, and on a
seeding failure `sys_read_entropy` *silently succeeds* — filling the buffer from a Park–Miller–Lehmer
LCG seeded with a static zero, a stream that is identical across boots, and emitting only a warning
the guest never sees. `getrandom` sees an ordinary success and hands it on.

Proxmox's default `kvm64` CPU model **does not expose RDSEED**, and Proxmox's `virtio-rng-pci` lands
on the same conventional PCI bus Hermit rejects. So on a default Proxmox VM this is the likely path
rather than the edge case, and every value this host draws — the RPC association group, response IVs
and salts, the hardware ID, the randomised ePID fields — would quietly become a constant while the
service kept working perfectly.

**Options → Processors → Type: `host`.** The self-test at start-up (`OS-012`, #263) **refuses to
serve** rather than serving a predictable identity: the process exits 69 and says so, naming RDSEED,
because the operator who reads that line is one hypervisor setting away from the fix. The source is
re-tested every five minutes thereafter — Hermit reseeds every second and a failed reseed is
silent — and a source that starts repeating takes `/healthz` to 503 and
`kmsrsos_entropy_healthy` to 0.

So the mistake is loud rather than silent. It is still a mistake, and this is how not to make it.

### Memory (`OS-011`, #262)

A unikernel has a fixed memory budget decided when the VM is created, no swap, and no OOM killer to
pick a victim: a failed allocation in a program compiled with `panic = "abort"` stops the machine, and
only the hypervisor can restart it. So the number that matters is not how much this host uses but how
much it *can* use, and that is bounded by constants rather than by traffic.

`crates/kmsrs-server/src/budget.rs` adds them up — the CMID table, the event-log ring buffer and the
connection state budget — and asserts the total at **compile time**, so a build that would exceed the
ceiling does not link. The product database is not in that sum: it is `static` data in `.rodata`
(`DB-003`, #127), part of the image rather than of the heap, and `DB-018` (#142) is where it is
measured.

The current ceiling is 8 MiB of heap. A Hermit guest is normally given 64 MiB or more, which leaves
the kernel, the stacks and the network buffers an order of magnitude more room than this takes.

### virtio-net may not attach at all (`OS-004`, #255)

Proxmox always places NICs on a conventional PCI bus — `pci.0` is a `pci-bridge` behind an i82801b11
bridge even on q35 — and **never** emits `disable-legacy=on`; there are zero occurrences of it in
`qemu-server`. QEMU therefore presents a *transitional* virtio-net device with PCI ID `0x1000`, and
Hermit refuses anything below `0x1040`.

That chain is solid link-by-link from the sources and has **never been observed**, which is what #255
is for. If it does fail, the serial console will say so on the first boot — which is the other reason
to attach one before that boot rather than after.

---

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

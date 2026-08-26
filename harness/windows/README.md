# The Windows measurement harness

`DISC-004` (#146). A real Windows client, driven from a shell, with a packet
capture around every scenario. The findings it produced are in
[`docs/discovery-findings.md`](../../docs/discovery-findings.md); this is how to
reproduce or extend them.

## Why it is built this way

The constraint that shaped everything: **no root**. A tap device, `tcpdump` and
a privileged DNS server are the obvious way to do this and all three need
privilege the harness should not ask for. Each has an unprivileged replacement
inside QEMU itself:

| Wanted | Used instead |
|---|---|
| `tcpdump` on a tap device | `filter-dump`, attachable and detachable at runtime through the monitor, so captures are per-scenario without restarting anything |
| A clean machine per scenario | `savevm`/`loadvm` — SPP caches discovery results and backs off after failures, so reverting is what makes scenarios independent rather than order-dependent |
| A DHCP server with option 15 | SLIRP's `domainname=`, which is exactly option 15 |
| Console access before any remoting exists | `sendkey` through the monitor (`type.py`), and `screendump` (`shot.sh`) to see what happened |

The one thing this cannot do is answer a query: SLIRP's DNS forwards to the
host resolver and carries no multicast. That is why the findings are scoped to
what the client *asks*. Answering needs a real L2 segment — reachable
unprivileged with `-netdev socket` between two guests, but not built here.

## Setup

```sh
export KMSRSOS_WIN_ISO=/path/to/windows_11_business_editions.iso
./setup.sh
```

Installs unattended and leaves a `clean` snapshot. Roughly 20–40 minutes, most
of it Windows Update fetching the OpenSSH Server feature-on-demand — which is
also the step most likely to be slow, since it is a real download.

Defaults worth knowing: image index 3, which is **Enterprise** on a business
ISO — index 1 is Education, so do not assume. Override with
`KMSRSOS_WIN_IMAGE_INDEX`. Read the index list off the ISO rather than guessing;
`install.wim`'s XML block lists them.

Enterprise ships with the GVLK already installed, so the guest is a KMS client
in `Notification` state immediately and no `/ipk` is needed.

## Running scenarios

```sh
./scenario.sh <name> [suffix=<domain>] [lookup=<domain>] [skms=<host>] [renew=yes]
```

Each run reverts to `clean`, applies the requested state, attaches a capture,
runs `slmgr /ato`, detaches, and writes `<name>.pcap`, `.state`, `.ato` and
`.txt` into `$KMSRSOS_VM_DIR/captures/`.

The DHCP option 15 axis is not a scenario key, because it is a property of
QEMU's DHCP server rather than of the guest:

```sh
./restart-vm.sh dhcp.example    # option 15 = dhcp.example
./restart-vm.sh                 # option 15 unset
```

then pass `renew=yes` so the guest drops the lease the snapshot restored and
picks up the one the current QEMU is offering. Without `renew=yes` on a VM
started with a domain, the scenario silently measures the *old* lease — which is
why every scenario records the state actually in effect in `<name>.state`
rather than the state requested.

## Driving the guest directly

```sh
./win.sh 'Get-Service sppsvc'          # PowerShell over SSH
./qm.sh "info snapshots"               # QEMU monitor
./shot.sh myshot                       # screenshot to PNG
./type.py 'text to type' --enter       # keystrokes, when SSH is not up yet
python3 analyze.py captures/foo.pcap   # what was asked, on which channel
```

## Known rough edges

- `scenario.sh` applies `skms=` *before* the reboot that a `suffix=` change
  forces, so SPP can auto-activate on boot and the capture then starts
  mid-association. Harmless for the discovery scenarios; it must be fixed
  before the harness is used to measure connection setup.
- The guest clock lags after `loadvm`, since the snapshot restores its
  wall-clock reading. Requests carry a visible skew — a few hundred seconds in
  practice. Irrelevant unless the build refuses skewed requests.
- `analyze.py` reports questions only. Responses are in the pcap and are not
  summarised.

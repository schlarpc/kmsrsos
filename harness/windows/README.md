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

## The pipelining probe (`NET-015`, #164)

`pipeline-probe.ps1` replays a captured bind / alter_context / request sequence
and then sends **two complete request PDUs in one write**, which is the only
shape in this protocol that gives Nagle a second small write to hold. Copy it in
and run it:

```sh
scp -i "$KMSRSOS_VM_DIR/id_vm" -P 2222 pipeline-probe.ps1 kms@127.0.0.1:C:/probe.ps1
./win.sh 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\probe.ps1'
```

Wrap it in a `filter-dump` the way `scenario.sh` does; the client-side read
timings it prints are far less trustworthy than the capture, because PowerShell
adds tens of milliseconds of its own between steps. The finding is in
`docs/decisions.md` under decision 43.

The PDUs are hard-coded from a real client capture rather than generated,
because the point is to replay exactly what Windows sent.

## Answering the queries (`srv-responder`)

`srv-responder/` is a small DNS server that answers `_vlmcs._tcp` and forwards
everything else upstream, so the guest's other name resolution keeps working.

It runs **on the guest**, not the host, for two reasons that are not obvious:
binding port 53 on the host needs privilege this harness will not ask for, and
QEMU user-mode networking forwards no UDP from guest to host. The loopback
constraint (`NET-014`, #163) is no obstacle — that is about the KMS *host*, and
the records handed back point at a non-loopback address.

```sh
cd srv-responder && cargo xwin build --release --target x86_64-pc-windows-msvc
scp -i "$KMSRSOS_VM_DIR/id_vm" -P 2222 \
    target/x86_64-pc-windows-msvc/release/srv-responder.exe kms@127.0.0.1:C:/srv.exe
```

In the guest, as administrator:

```powershell
$idx = (Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1).InterfaceIndex
# BOTH families. With no IPv6 resolver set, Windows sends the SRV query to
# fec0:0:0:ffff::3 — a remote address — and an IPv4-only responder never sees it.
Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ("127.0.0.1","::1")
Start-Process C:\srv.exe -ArgumentList "10.0.2.3","10.0.2.2" -NoNewWindow
```

One record at priority 0 by default. To test RFC 2782 ordering, pass
`priority,weight,port,target` specs — a dead one first and a live one second is
how the fallback in `docs/discovery-findings.md` was measured:

```powershell
Start-Process C:\srv.exe -ArgumentList "10.0.2.3","10.0.2.2","0,100,1699,dead","10,100,1688,live" -NoNewWindow
```

It is outside the cargo workspace on purpose: it runs on the guest, ships
nothing, and should not appear in the workspace's lockfile or lint policy.

### Measuring SRV weight (`DISC-009`, #381)

`KMSRSOS_NO_INLINE_A=1` makes the responder withhold the A records it would
otherwise put in the SRV answer. The client must then look up whichever target
it selected, and that lookup names the selection in the responder's log — which
is how the weight distribution was measured without parsing a pcap per trial.

Point every record at a port nothing listens on, so each trial makes a fresh
choice and falls through:

```powershell
$env:KMSRSOS_NO_INLINE_A = "1"
Start-Process C:\srv.exe -ArgumentList "10.0.2.3","10.0.2.2","0,1,1701,a","0,1,1702,b","0,98,1703,c" -NoNewWindow
for ($i = 1; $i -le 20; $i++) {
  cscript //nologo C:\Windows\System32\slmgr.vbs /ckms | Out-Null
  Restart-Service sppsvc -Force            # SPP caches the host it found
  ipconfig /flushdns | Out-Null            # and the resolver caches the answer
  cscript //nologo C:\Windows\System32\slmgr.vbs /ato | Out-Null
}
```

Both resets matter: without `/ckms` and the `sppsvc` restart the client reuses
its previous choice and every trial after the first measures nothing. About
seven seconds per trial.

Tally the first A lookup after each SRV:

```sh
awk '/^SRV/{e=1;next} /^A /{if(e){split($2,p,".");print p[1];e=0}}' wA.log | sort | uniq -c
```

The committed runs are `captures/DISC-009-w{A,B,C}.log`.

## The ARM64 smoke run (`PKG-022`, #385)

`arm64-smoke.ps1` is in this directory and is not part of the harness above. It
needs no VM, no capture and no Windows ISO: it starts the **shipped**
`kmsrs-server.exe` on an ARM64 Windows machine, serves an activation through
`kmsrs-client.exe`, and captures the sandbox report — which is where the five
`SetProcessMitigationPolicy` outcomes of `SEC-019` (#356) are stated.

```powershell
pwsh harness/windows/arm64-smoke.ps1 `
  -Server out/kmsrs-server-windows-aarch64.exe `
  -Client out/kmsrs-client-windows-aarch64.exe
```

It refuses to run on anything but ARM64 and reads `IMAGE_FILE_MACHINE` off both
binaries before trusting either, because the whole question is *which machine
executed this*. `PKG-020` (#379) shipped the ARM64 build never having run it,
and `PKG-018` (#374) is why that mattered: a binary whose every build-time check
passes can still die before it logs a line.

CI runs it on `windows-11-arm` against the artifact from `snapshot-windows`, so
it is the cross-compiled binary an operator downloads rather than one rebuilt on
the test machine. Run it by hand on a Snapdragon X laptop or a Windows 11 ARM
guest on Apple Silicon and it answers the same question about that machine.

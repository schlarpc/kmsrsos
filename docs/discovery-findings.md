# What a Windows client actually asks for

`DISC-004` (#146). Measured, not inferred. Every row below comes from a packet
capture of a real Windows client; the harness that produced them is in
[`harness/windows/`](../harness/windows/) and the scenario names match the
capture files it writes.

The question this answers is deliberately narrow: **what does the client ask,
and on which channel**. That is separable from whether anything answers, and it
is the half that can be established without building a responder first — so it
was established first.

## The client under test

| | |
|---|---|
| Edition | Windows 11 Enterprise, image index 3 of the 25H2 business ISO |
| Build | 26200.9168 (`DisplayVersion` 25H2) |
| Licensing | `VOLUME_KMSCLIENT`, `Volume:GVLK`, partial key `2YT43` |
| Membership | Workgroup `WORKGROUP`, not domain-joined |

The edition ships with the GVLK already installed, so it is a KMS client in
`Notification` state out of the box and needs no `/ipk` to start discovering.
The partial key `2YT43` is the tail of the `Windows 10 Enterprise` client setup
key in our own shipped database — the one whose host group covers "Windows 11
and Windows 10 Semi-Annual Channel". Microsoft reuses that key for Windows 11
Enterprise, and this is a direct confirmation of the database row rather than a
reading of someone else's catalogue.

## What the client asks

SPP is the Software Protection Platform — `sppsvc`, the service that holds the
key and speaks the client half of the protocol. `slmgr.vbs` only drives it over
WMI, so every observation below is SPP's behaviour, not slmgr's.

| Scenario | Primary DNS suffix | DHCP option 15 | `KeyManagementServiceLookupDomain` | `/skms` | What SPP queried |
|---|---|---|---|---|---|
| `A-baseline` | — | — | — | — | **nothing** |
| `B-suffix-example` | `example.com` | — | — | — | `_VLMCS._TCP.example.com` |
| `C-lookup-only` | — | — | `example.com` | — | `_VLMCS._TCP.example.com` |
| `D-dhcp15-only` | — | `dhcp.example` | — | — | `_VLMCS._TCP.dhcp.example` |
| `E-suffix-and-lookup` | `suffix.example` | — | `lookup.example` | — | `_VLMCS._TCP.lookup.example` only |
| `G-skms-wins` | `suffix.example` | — | — | `10.0.2.2:1688` | **nothing** — connected directly |
| `H-dhcp15-local` | — | `local` | — | — | `_VLMCS._TCP.local`, **unicast DNS only** |
| `I-skms-dotlocal` | — | — | — | `kmsrsos.local:1688` | `kmsrsos.local` A/AAAA on unicast **and** mDNS |
| `W-why-mdns` | — | — | — | — | `Resolve-DnsName` control: A/AAAA reach mDNS, SRV and PTR do not |

### DHCP option 15 is sufficient on its own

`D-dhcp15-only` is the result worth having. With no primary DNS suffix, no
registry value and no `/skms`, a domain name learned from DHCP option 15 alone
is enough for SPP to emit `_VLMCS._TCP.<that domain>`. The option arrives as the
*connection-specific* DNS suffix — the primary suffix stays empty — and SPP uses
it anyway.

This matters for deployment because it is the only one of the three name sources
that needs nothing configured on the client: a DHCP server that already exists
can advertise the domain, and a KMS host becomes discoverable without touching a
single machine.

### With no suffix from anywhere, there is no query at all

`A-baseline` does not fail to find a host. It fails *earlier* than that: SPP
emits no `_vlmcs` query on any channel, and `/ato` returns `0x8007007B`
(`ERROR_INVALID_NAME`). There is no name to build a query from, and SPP does not
fall back to a bare `_vlmcs._tcp` or to any link-local mechanism.

So DNS-based discovery has a precondition, and the precondition is a domain
suffix from one of the three sources above.

### The registry lookup domain overrides the DNS suffix, with no fallback

In `E-suffix-and-lookup` both are set to different values, and SPP queries
`_VLMCS._TCP.lookup.example` and nothing else. It does not also try the primary
suffix, and it does not fall back to it when the lookup domain yields nothing.
`KeyManagementServiceLookupDomain` replaces the suffix rather than being tried
before it.

`C-lookup-only` also skips a step that `B` and `D` both perform: those two probe
`_ldap._tcp.dc._msdcs.WORKGROUP.<domain>` immediately before the `_vlmcs` query,
and the lookup-domain path does not. Consistent with that, `C` reached its
`_vlmcs` query at 3.60 s against `B`'s 6.36 s.

### `/skms` suppresses discovery entirely

`G-skms-wins` had a primary DNS suffix set and still emitted no `_vlmcs` query.
A configured host is not a preference applied after a lookup; it replaces the
lookup.

### The name is uppercase on the wire

Every observed query is `_VLMCS._TCP.<domain>`, not `_vlmcs._tcp.<domain>`. DNS
comparisons are case-insensitive so this changes no correct implementation, but
a responder that matches bytes, or a capture filter that greps for the lowercase
form, will silently see nothing.

## mDNS: the answer is no for SRV, yes for A/AAAA

This is the crux `DISC-003` (#145) asks about, and both halves fall out of the
same two captures.

`H-dhcp15-local` gave SPP a `.local` domain and it sent
`_VLMCS._TCP.local` **SRV to the configured unicast DNS server only**. No packet
went to `224.0.0.251:5353` or `ff02::fb`. The capture is taken at the guest's
own netdev, before any host-side networking sees it, so an absent packet is a
packet the client never sent — not one that was dropped in transit.

`I-skms-dotlocal` shows the client is perfectly willing to use mDNS otherwise.
Asked to resolve the *host name* `kmsrsos.local`, it queried A and AAAA on
unicast DNS **and** on mDNS over both IPv4 and IPv6 multicast, three attempts
each.

So the Windows DNS Client's `.local` handling is live and working; SPP's SRV
lookup simply does not go through the path that would use it.

### Why — and it is not SPP's doing

`W-why-mdns` asks the same questions through `Resolve-DnsName`, which is the
plain DNS Client with no licensing involved:

| name | type | channels used |
|---|---|---|
| `probe-a.local` | A | unicast **+ mDNS** |
| `probe-aaaa.local` | AAAA | unicast **+ mDNS** |
| `_probe-srv._tcp.local` | SRV | unicast only |
| `_probe-ptr._tcp.local` | PTR | unicast only |

The Windows DNS Client's mDNS support is an **address-record resolver**. A and
AAAA go to multicast; SRV and PTR never enter that path at all. DNS-SD on
Windows lives in a separate stack — the WinRT
`Windows.Networking.ServiceDiscovery.Dnssd` APIs — which SPP does not use.

So SPP is not declining to use mDNS. It calls the ordinary resolver, and the
ordinary resolver will not put a SRV question on multicast. That is worth
stating precisely because it changes the strength of the conclusion: this is not
"SPP happens not to", which a future Windows version might change, but "the
resolver SPP uses has no code path for it".

**Recommendation for #145: no-go on SRV-over-mDNS**, and the reason is
structural rather than incidental. The de-risking fallback
that issue describes survives intact and is now measured rather than assumed —
`slmgr /skms kmsrsos.local` will resolve by mDNS, which delivers a name that
survives DHCP address changes with no DNS server and no hosts file.

## A real client activates against this server

`TEST-013` (#234) in its narrowest form. With `/skms` pointed at a
`kmsrs-server` build and `/ato` run, the guest reported *Product activated
successfully* and `slmgr /dlv` then reported `License Status: Licensed`.

The captured exchange is the full DCE/RPC sequence, protocol 6.0:

```
C->S  160  05000b13…  bind
S->C  108  05000c13…  bind_ack
C->S   72  05000e13…  alter_context
S->C   56  05000f03…  alter_context_resp
C->S  292  05000003…  request
S->C  300  05000203…  response
```

Two things in that are worth naming. A real Windows client **does** issue
`alter_context`, which is the behaviour `FP-009` requires the server to service.
And in `G-skms-wins` the activation carried no bind at all — SPP had bound
earlier and reused the association for a later request, which is the client-side
counterpart of `FP-008`. That second observation was incidental to how the
scenario was ordered, so it is recorded here as observed, not as established;
a deliberate test belongs with `FP-008`.

## Caveats, so these are not read for more than they say

- **The `/ato` error codes vary for reasons outside Windows.** `B` and `C`
  returned `0x8007251D`; `D`, `E` and `H` returned `0x8007232B`. `example.com`
  resolves and has no SRV record while `dhcp.example` does not resolve at all,
  so this is NODATA versus NXDOMAIN from the real upstream resolver, not a
  difference in SPP. An earlier `H` run returned `0xC004F074` instead. None of
  these codes is load-bearing for anything above — the queries are.
- **Nothing answered the SRV queries.** Every scenario except the two `/skms`
  ones measures the question, not the round trip. Whether SPP correctly follows
  RFC 2782 priority and weight across multiple SRV records is untested and needs
  a responder.
- **Domain-joined is not covered.** Every scenario above is workgroup. The
  `_ldap._tcp.dc._msdcs.WORKGROUP.<domain>` probe seen in `B` and `D` is what a
  *non*-joined machine does, and a joined one may well differ.
- **One client, one build.** 26200.9168 only. Older SPP versions are not
  covered by anything here.

## About the committed captures

The pcaps in [`harness/windows/captures/`](../harness/windows/captures/) are
filtered to DNS, mDNS, LLMNR, NBNS, DHCP and TCP 1688. The unfiltered captures
are roughly twenty times larger and the difference is entirely the guest
talking to Windows Update, MSN and the telemetry endpoints — traffic that is
not evidence for anything here and that carries device identifiers there is no
reason to commit.

## Reproducing

See [`harness/windows/README.md`](../harness/windows/README.md). The harness
needs no root: QEMU's `filter-dump` provides the captures, `savevm`/`loadvm`
provides a clean starting state per scenario, and the guest is driven over SSH.

# Research findings

Reference material produced while planning, kept because it is expensive to re-derive and because
some of it is load-bearing data rather than prose. Work items live in
[GitHub issues](https://github.com/schlarpc/kmsrsos/issues).

- [R1 — product data from Microsoft primary sources](#r1--product-data-from-microsoft-primary-sources)
- [R2 — Hermit and Proxmox feasibility](#r2--hermit-and-proxmox-feasibility)
- [Coverage map](#coverage-map) — how the audits' findings map onto issues

---

# R1 — product data from Microsoft primary sources

The CSVLK data disputed between vlmcsd, License Manager and py-kms was resolved **above** all three,
by reading Microsoft's own signed artifacts:

- `pkeyconfig-office-kmshost.xrm-ms` and four `kmshost2024vl_kms_host-*.xrm-ms` files from the
  official **Office LTSC 2024 Volume License Pack**.
- `pkeyconfig-csvlk.xrm-ms` and the `spp\tokens\skus` tree from **Windows Server 2025 (26100)**,
  streamed out of `mcr.microsoft.com/windows/servercore:ltsc2025`.

Both contain `RefGroupId`, `Start`, `End` and `PartNumber` per CSVLK, base64+gzip'd inside an XrML
wrapper; the accompanying licence files carry `Security-SPP-KmsCountedIdList`.

> **This contradicts the common assumption that Microsoft does not publish CSVLK group IDs or key
> ranges. It does — just not in prose.** Decoding is: base64-decode the `<tm:infoBin
> name="pkeyConfigData">` element, gunzip, parse the XML. That is what the extraction pipeline
> (#125, #126) is built on, and it is why hand-copying fork catalogs is prohibited.

## CSVLK table

All entries confirmed from Microsoft `pkeyconfig`.

| DisplayName | GroupId | Key range | Activation ID |
|---|---:|---|---|
| Windows Server 2025 | **4919** | 20000–20019999 (also 0–19999) | `84e331f6-4279-48c4-ab10-b75139181351` |
| Windows Server 2025 (Azure only) | **4918** | 0–49999 | `82fcf64d-f9dd-4411-9c79-f2eed16d4eb8` |
| Windows Server 2025 (Internal Lab) | 4920 | 0–49999 | `6bad0243-1c35-46b2-b8e6-7a853e37413f` |
| Windows Server 2022 | 4573 | **30000**–20029999 | `661f7658-7035-4b4c-9f35-010682943ec2` |
| Windows Server 2022 (Azure only) | 4574 | 0–49999 | `e73aabfa-12bc-4705-b551-2dd076bebc7d` |
| Windows Server 2022 (Internal Lab) | 4575 | 0–49999 | `22105925-48c3-4ff4-a294-f654bb27e390` |
| Windows Server 2019 | 206 | 551000000–570999999 | `2e7a9ad1-a849-4b56-babe-17d5a29fe4b4` |
| Windows Server 2019 (Azure only) | 206 | **2865000–2874999** | `3c006fa7-3b03-45a4-93da-63ddc1bdce11` |
| Windows Server 2019 (Internal Lab) | 206 | 2835000–2854999 | `9db83b52-9904-4326-8957-ebe6feedf37c` |
| Windows Server 2016 | 206 | 491000000–530999999 | `d6992aac-29e7-452a-bf10-bbfb8ccabe59` |
| Windows 10 2019 | 206 | 256000000–265999999 | `90da7373-1c51-430b-bf26-c97e9c5cdc31` |
| Windows 10 2016 | 206 | 531000000–545999999 | `30a42c86-b7a0-4a34-8c90-ff177cb2acb7` |
| Windows 10 2015 | 206 | 390000000–404999999 | `0724cb7d-3437-4cb7-93cb-830375d0079d` |
| Windows 10 China Government | 3858 | 15000000–999999999 | `ecc0774a-aed3-4e1a-b815-2b31781adfea` |
| **Office LTSC 2024** | 206 | **591000000–610999999** | `f3d89bbf-c0ec-47ce-a8fa-e5a5f97e447f` |
| Office LTSC 2021 | 206 | 571000000–590999999 | `47f3b983-7c53-4d45-abc6-bcd91e2dd90a` |
| Office 2019 VL | 206 | 666000000–685999999 | `70512334-47b4-44db-a233-be5ea33b914c` |
| Office 2016 VL | 206 | 437000000–458999999 | `98ebfe73-2084-4c97-932c-c0cd1643bea7` |
| Office 2013 VL | 206 | 234000000–255999999 | `2e28138a-847f-42bc-9752-61b03fff33cd` |
| Office 2010 VL | 96 | 199000000–217999999 | `bfe7a195-4f8f-4f0b-a622-cf13c7d16864` |

Release dates, used only as the lower bound for the randomized activation date: WS2025 2024-11-01,
WS2022 2021-08-18, WS2019 2018-10-02, Office LTSC 2024 2024-09-16, Office LTSC 2021 2021-09-16.

**Note the Server 2022 gap.** That CSVLK has two valid blocks — `0–19999` and `30000–20029999` —
with an **invalid hole at 20000–29999**. Key ranges must therefore be modelled as a *set of blocks*,
not a min/max pair (#124); py-kms's `MinKeyId=0, MaxKeyId=20029999` can emit a key ID in the hole.

## KMS counted IDs

From Microsoft's `Security-SPP-KmsCountedIdList`.

| Product | Counted ID |
|---|---|
| Windows Server 2022 | `b74263e4-0f92-46c6-bcf8-c11d5efe2959` |
| **Windows Server 2025** | **`907f1f65-adcd-4a2e-95bc-4bf500bc6e58`** |
| Office LTSC 2021 | `86d50b16-4808-41af-b83b-b338274318b2` |
| **Office LTSC 2024** | **`a8973cb5-bf03-0a4c-9cef-703099645ab3`** |
| Windows 10/11 2021 LTSC volume | `3b576817-7b75-4362-9e13-223f2d9e9c97` |
| Windows 10/11 2024 LTSC volume | `e85ee727-69c4-4528-99d2-216b0f065e38` |

py-kms's Server 2025 (`4b83307d-…`) and Office LTSC 2024 (`1b4db7eb-…`) values appear in no Microsoft
artifact and are **valid UUIDv5** — i.e. synthesized. The last two rows are missing from py-kms
entirely.

> **Do not validate the UUID version nibble** (#129). Office LTSC 2024's genuine counted ID is
> `a8973cb5-bf03-**0**a4c-…` — an invalid version nibble, yet it is what Microsoft ships, and
> vlmcsd's `CheckVersion4Uuid()` emits a spurious warning for it. The heuristic works only in
> reverse: the two *fabricated* values are the well-formed ones.

## GVLK corrections

| Product | Correct GVLK | Wrong value in circulation |
|---|---|---|
| Office LTSC Professional Plus 2024 | `XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB` | `CW94N-K6GJH-9CTXY-MG2VC-FYCWP` (that is PowerPoint LTSC 2024) |
| Windows Server 2025 Datacenter | `D764K-2NDRG-47T6Q-P8T8W-YP6DF` | `CNFDQ-2BW8H-9V4WM-TKCPD-MD2QF` (License Manager) |
| Server 2025 Datacenter Azure Edition | `XGN3F-F394H-FD2MY-PP6FD-8MCRC` | `NQ8HH-FTDTM-6VGY7-TQ3DV-XFBV2` (py-kms) |

## Host build table

**PlatformId is 3612 for every build ≥ 10240**, corroborated by two genuine ePIDs from real machines.
`UseForEpid` rows in bold.

| Build | PlatformId | Release | ePID host |
|---|---:|---|:---:|
| **6002** | 55041 | 2009-05-26 | yes |
| **7601** | 55041 | 2011-02-22 | yes |
| **9200** | 5426 | 2012-10-26 | yes (first NDR64) |
| **9600** | 6401 | 2013-10-18 | yes |
| 10240 | 3612 | 2015-07-29 | no |
| **14393** | 3612 | 2016-08-02 | yes |
| 15063 / 16299 / 17134 | 3612 | 2017-04-05 / 2017-10-17 / 2018-04-30 | no |
| **17763** | 3612 | 2018-10-02 | yes |
| 18362 / 18363 / 19041 / 19042 / 19043 / 19044 | 3612 | — | no |
| **20348** | 3612 | 2021-08-18 | yes (Server 2022) |
| 22000 | 3612 | 2021-10-04 | no |
| 22621 | 3612 | 2022-09-20 | no |
| 22631 | 3612 | 2023-10-31 | no |
| **26100** | 3612 | 2024-10-01 | yes (Win 11 24H2 / Server 2025) |
| 26200 | 3612 | 2025-09-30 | no (Win 11 25H2 GA) |
| 28000 | 3612 | 2026-02-10 | no (Win 11 26H1) |

Build 28000 is **real**, not speculation — KB5077179, OS Build 28000.1575, 2026-02-10, a scoped 26H1
release for Snapdragon X2 / NVIDIA N1X devices, still being serviced.

## ePID field semantics

- **Day-of-year is 1-based.** vlmcsd emits `tm_yday + 1`; License Manager's ePID *validator* does
  `date.AddDays(dayOfYear - 1)` and rejects anything that does not round-trip against .NET's 1-based
  `DayOfYear`, so `000` would be treated as malformed. py-kms is the outlier and is wrong.
- **LCID is unpadded.** Three implementations agree; License Manager's parser accepts `^[0-9]{1,5}$`.
  Practically moot since every LCID a real host can report is ≥ 1025.
- **License channel is always `03`** (`00`/`01` Retail, `02` OEM, `03` Volume GVLK/MAK).
- Field widths: PlatformId `%05u`, GroupId `%05u`, `keyId/1000000` `%03u`, `keyId%1000000` `%06u`,
  channel literal `03`, LCID unpadded, build unpadded + `.0000`, day `%03u`, year `%04u`.

## Corrected assumption: the "20-million-scale range" pattern does not exist

An earlier draft claimed newer products moved to ~20M-scale key ranges. That is wrong. It is a
**GroupId-namespace effect**, not a chronological one: GroupId 206 is a crowded shared namespace
where new blocks get carved at ever-higher bases, while products granted a *fresh* GroupId start near
zero. Block width is ~20,000,000 in both eras. Windows Server 2022 was the first product with a
dedicated group; **Office LTSC 2021 and 2024 are counterexamples that stayed on 206.**

Corollary worth keeping: any new CSVLK entry reusing `551000000–570999999` (Server 2019's range) was
copied, not researched. That is exactly what four separate forks did.

## Known-bad data in the maintained catalogs

`Py-KMS-Organization/py-kms@main`: Office LTSC 2024 key range (it is Office 2019's verbatim); Server
2025 GroupIds swapped; Server 2025 key range (it is Server 2022's — its git history shows the 2025
entry was cloned from the 2022 one); Server 2019 Azure-only range missing; Server 2025 and Office
2024 counted IDs fabricated; Server 2025 Datacenter Azure Edition GVLK wrong; the Windows 10/11 2021
and 2024 LTSC KMS IDs missing entirely; 0-based day-of-year.

License Manager: the Server 2025 Datacenter GVLK, and a missing `UseForEpid` on build 26100.

---

# R2 — Hermit and Proxmox feasibility

Verified by cloning `hermit-os/kernel`, `hermit-os/hermit-rs`, `hermit-os/loader`, `tokio-rs/mio` and
`proxmox/qemu-server` and reading the sources rather than the documentation.

## Toolchain

All Hermit targets are **Tier 3** — rustup ships no `rust-std`. Either `-Z build-std=std,panic_abort`
on nightly, or the `hermit-os/rust-std-hermit` component, which is built per *exact* stable version
and must be matched precisely. The `hermit` crate must be a **git** dependency; the crates.io copy is
a `compile_error!` stub.

**The Nix build is the largest schedule risk in the project** (#250). The `hermit` crate's `build.rs`
shells out to a nested `cargo run --package=xtask` that builds the kernel from a git submodule
against its *own* lockfile and *own* pinned nightly, which crane will not vendor. Two toolchains are
required either way, plus a fixed-output derivation for the `rust-std-hermit` tarball.

## Async runtime

**mio has first-class, unpatched Hermit support**; **tokio has none.**

| | Hermit support | Backend | Run in QEMU CI |
|---|---|---|---|
| mio | first-class, stock crates.io | `poll(2)`, level-triggered, eventfd waker | yes, every PR |
| tokio | **zero upstream** (0 grep hits) | via mio | no — compiled only |

The kernel has `sys_poll` and `sys_eventfd` and **no epoll at all**. tokio works only through
`hermit-os/tokio`, a four-commit fork of 1.45.0 (upstream is 1.53.1) with Hermit commits from
February 2024, plus a forked `socket2`. Its substantive patch is a **level-triggered selector
workaround** in `poll_evented.rs` putting Hermit in the same branch as Windows — tokio's readiness
caching assumes edge-triggered semantics, and getting it wrong produces hangs, not errors.
`[patch.crates-io]` is workspace-global, so adopting it would pin Linux and Windows to the same stale
fork. Hence #5: blocking `std::net` + `std::thread` on Hermit, which is the model hermit's own CI
actually exercises.

Hermit's `std::thread` is **real preemptive OS threading** — `sys_clone`/`sys_spawn2`, futexes, an
SMP scheduler on an APIC timer, `smp` on by default.

## Platform constraints

- **No IPv6 address, ever.** smoltcp has v6 compiled in, but the kernel only assigns IPv4 and speaks
  DHCPv4 only — no SLAAC, no RA, no DHCPv6.
- **`bind()` records the address and ignores it.** `listen()` passes only the port to smoltcp, so one
  `0.0.0.0` socket already accepts on every local address, and two sockets on one port would race
  with no defined dispatch. Hence one socket on Hermit (#260).
- **`setsockopt` is a stub.** Only `TCP_NODELAY` works; `SO_REUSEADDR` is a silent no-op;
  `SO_RCVTIMEO`, `SO_SNDTIMEO`, `IPV6_V6ONLY`, `SO_KEEPALIVE` and `SO_LINGER` all return `EINVAL`.
  These succeed on Linux and Windows and fail only here — the worst failure shape.
- **No block device driver of any kind**, and no SMBIOS/DMI code. Zero-disk-I/O is enforced by the
  absence of drivers rather than by our policy.
- **No signals.** Shutdown is normal control flow.
- **`cfg(unix)` is false.** Hermit is not `target_family = "unix"`, so every `#[cfg(unix)]` in our
  code and in every dependency silently takes the wrong branch.
- **Clock**: monotonic is solid (TSC/APIC, microsecond resolution); `SystemTime` is one CMOS RTC read
  plus local ticks — 1-second granularity, no pvclock, no NTP, no slew, and it drifts.
- **Console** is the 16550 UART at 0x3F8, and nothing else.
- **DHCPv4 is on by default**; the `HERMIT_IP` family is only a pre-DHCP fallback.

## Entropy — the most dangerous finding

Hermit's CSPRNG is properly built: ChaCha20, fast-key-erasure, reseeding every second, seeded from
RDSEED or virtio-rng. **But on seeding failure `sys_read_entropy` silently succeeds**, filling the
buffer from a Park–Miller–Lehmer LCG seeded from a static `0` — a deterministic, identical-across-boots
stream — and emits only a `warn!`. `getrandom` sees a normal success and hands it on.

On Proxmox this is the *likely* path, not the edge case: the default `kvm64` CPU does not expose
RDSEED, and Proxmox's `virtio-rng-pci` lands on the same conventional PCI bus Hermit rejects. That
stream feeds the association group, response IVs, salts and HwId — so every anti-fingerprinting
property would silently become a constant while the service kept working perfectly. Hence the
startup self-test that **refuses to serve** (#263).

## Boot and Proxmox

A self-contained bootable UEFI image needs no `-kernel` and no `qm set --args`: a GPT disk whose ESP
holds `\EFI\BOOT\BOOTX64.EFI` (the hermit loader), `\EFI\hermit\hermit-app`, and optionally
`\EFI\hermit\hermit-bootargs` — a plain text file the loader reads. Boot args accept `env=KEY=VALUE`
tokens, which is how the single runtime config variable reaches a Hermit guest.

**Proxmox may not give a Hermit guest a NIC at all.** Proxmox always places NICs on a conventional
PCI bus (`pci.0` is a `pci-bridge` behind an i82801b11 bridge even on q35) and **never** emits
`disable-legacy=on` — zero occurrences in `qemu-server`. QEMU therefore presents a *transitional*
virtio-net device (PCI ID 0x1000), and Hermit refuses anything below 0x1040. The chain is solid
link-by-link from source but **never observed** — that is #255.

What a Proxmox admin can set from the GUI, and whether it reaches the guest:

| Setting | GUI-settable | Reaches a Hermit guest |
|---|:---:|---|
| DHCP (via the network) | yes | **yes** — the sanctioned path |
| MAC address | yes | yes |
| Serial port | yes | yes — and **mandatory**, or the VM is silent |
| CPU type (`host` for RDSEED) | yes | yes — and required, see entropy above |
| SMBIOS type 1 fields | yes | **no** — no DMI code in the kernel; the loader discards the pointer |
| Cloud-init drive | yes | **no** — arrives as ISO9660; there is no block driver |
| `args` / kernel cmdline | **no** (CLI only) | would work, but is not exposed in the web UI |

---

# Coverage map

How the audits' findings map onto issues. Useful for answering "did we actually cover that?"

## The 24 behavioural mismatches

MM01 → #106 · MM02 → #107 · MM03 → #89 · MM04 → #30 · MM05 → #79 · MM06 → #61, #63, #115 ·
MM07 → #68 · MM08 → #64 · MM09 → #99 · MM10 → #38 · MM11 → #105 · MM12 → #14 · MM13 → #150 ·
MM14 → #153, #100 · MM15 → #118 · MM16 → #69 · MM17 → #72 · MM18 → #25 · MM19 → #180 ·
MM20 → #37 · MM21 → #94 · MM22 → #145–#148 · MM23 → #98 · MM24 → the detection-resistance
checklist as a whole.

## The 23 features nobody implements

DNS SRV publishing → #145–#148 · CMID 30-day decay → #91 · rate limiting → #100, #102 ·
activation history → #180 · fuzzing → #196 · CSPRNG → #52, #263 · RPC fragmentation → #80 ·
structured logs → #178 · reproducible builds / SBOM / signing → #202 · sandboxing → #197 ·
systemd unit and OS packages → #244, #246 · socket activation → #165 · Windows Event Log → #192 ·
Prometheus → #189 · constant-time crypto → #56 · HA shared state → D3 · upstream proxy → D12 ·
multi-tenancy → D2 · per-product quota → D14 · per-client quota → D14 · client allowlist → #101, D28 ·
ADBA → D1 · RPC auth → D4.

## Fork contributions carried forward

kotfenix's Office LTSC 2024 range (since confirmed against Microsoft) → R1 above; its `uint16_t`
SKU-counter fix → #214. kankerdev's Visual Studio / SQL / SCCM data → D18. cnzhangquan's OpenVPN
adapter ID → D21. KptCheeseWhiz's CIDR allowlist *idea* → #101. The `getEpid()` dangling-pointer fix
(five independent discoverers) → #193, #194. Hamad3bdulla's ePID fallback fix → #107, RPC-bind
`KeyError` guard → #64, client short-read reassembly → #82, pickle→JSON → #203.
GuillaumeDescombes's receive-loop hardening → #83, #153, and the `RequestUnknown` bytes fix → #30.
MelroyB's per-request config copy → #14, blacklist grammar → #101, WinBuild 26200/28000 rows → #135.
mcrook250's retention idea → #180, #91. OzanHazar's quota idea → D14.
Neon-Cyber-Crutches's metric taxonomy → #189, shell-less spawn → #200. konk22's offline products
page → #184. Rubberverse's Server 2019 CSVLK ePID correction and Azure-only key range → R1 above,
health-endpoint leak fix → #185. edgd1er's null-guard and logged healthcheck → #188, #204.
zeevro's installable-package layout → #246. GhostNaix's Windows console lesson → #162.
dummervogel's self-pipe-on-Windows lesson → #158. radawson's YAML and GUID-keyed-DB *ideas* →
#167, #127. HAmamiya's composite-key insight → #182.

# KMS emulator feature matrix and cross-implementation synthesis

A cross-implementation audit of the two families of open-source Microsoft KMS host emulators, the
119 features that define the category, the 23 features **nobody** implements, and the 24 situations
where the implementations **disagree** about what a KMS host should do.

Companion documents, each an exhaustive single-project audit:

- [vlmcsd feature audit](./vlmcsd-features.md)
- [py-kms feature audit](./py-kms-features.md)
- [vlmcsd fork survey](./vlmcsd-forks.md)
- [py-kms fork survey](./py-kms-forks.md)

---

## What this class of software is

Microsoft's Key Management Service is a volume-activation mechanism. A licensed *KMS host* runs a
DCE/RPC service on TCP 1688 exposing a single-operation interface
(`51c82175-844e-4750-b0d8-ec255555bc06`, opnum 0). A volume-licensed Windows or Office client
installs a public *GVLK* setup key, discovers the host (usually via a `_VLMCS._TCP` DNS SRV record
the host publishes at install time), and sends an encrypted `REQUEST` carrying its Client Machine
ID (CMID), the application/SKU/KMS GUIDs identifying what it wants activated, a FILETIME timestamp,
its machine name, and `N_Policy` — the minimum number of distinct clients its edition requires the
host to have seen. The host answers with an `ePID` (a structured, human-readable string encoding
the host's CSVLK group, key ID, build number and activation date), the current count of cached
CMIDs, and activation/renewal intervals. The client activates for 180 days if the reported count
meets its threshold, and renews every 7 days.

An emulator answers those requests without a licensed CSVLK. Three properties define whether one is
any good:

1. **Protocol correctness.** The v4/v5/v6 crypto and the DCE/RPC framing must be byte-exact, or
   nothing activates.
2. **Behavioral authenticity.** A real host has *one* ePID for its lifetime, holds RPC associations
   open, negotiates NDR64, enforces a ±4-hour clock window, tracks distinct CMIDs with 30-day
   aging, and refuses retail SKUs. Every place an emulator shortcuts one of these is a detection
   vector and, in aggregate, is the difference between "works" and "indistinguishable".
3. **Operability.** Deployment, discovery, logging, state, and the ability to run unattended on
   untrusted networks.

A *complete* implementation would be correct on all three axes: wire-exact on v4/v5/v6 and on
DCE/RPC (including `alter_context`, NDR64, per-item bind NACKs, and fault PDUs); model host state
rather than arithmetic (a real CMID table with 30-day expiry, so the reported count is a function
of distinct machines seen); present a stable, product-correct, harvestable identity; publish its own
SRV record so clients need no configuration; persist an auditable activation history; and survive
an internet-facing deployment (bounded workers, timeouts, rate limits, memory-safe parsing of
pre-authentication bytes).

Neither existing family is that. Between them they cover most of it — but the union is not
available in any single program, and the intersection of what *both* miss is large enough to be the
most interesting part of this document.

---

## Legend and columns

| Symbol | Meaning |
| :---: | --- |
| `●` | **full** — present and usable at runtime |
| `◐` | **partial** — half-works, has wrong semantics, or is severely limited (see Notes) |
| `⚙` | **build-gated** — governed by a compile-time macro or `FEATURES=` preset. Covers two cases, distinguished in the Notes column: (a) the feature exists *only* in a non-default build (e.g. `MSRPC=1`, `CRYPTO=openssl`, `THREADS=1`, `libkms`); (b) the feature is an ordinary runtime CLI/ini option in the stock `FEATURES=full` build but a `NO_*`/`SIMPLE_*` macro can strip it out entirely |
| `○` | **absent** — not implemented |
| `–` | **n/a** — the feature is meaningless for that implementation's language/platform |

The three implementations audited:

| Column | Project | State |
| --- | --- | --- |
| **vlmcsd** | [Wind4/vlmcsd](https://github.com/Wind4/vlmcsd) `master` @ `70e0357` | C, ~22k LOC, **archived 2023-07-28**. 8846 stars, 2486 forks (16 touch code). |
| **py-kms (SR)** | [SystemRage/py-kms](https://github.com/SystemRage/py-kms) `master` @ `a3b0c85` | Python, ~8k LOC, **dormant since 2021-01-24**. 2190 stars. Does not run on Python 3.10+. |
| **py-kms (Org)** | [Py-KMS-Organization/py-kms](https://github.com/Py-KMS-Organization/py-kms) `main` @ `b0e1615` | The active successor. 786 stars, last push 2026-05. |

Citations are repo-relative. `pykmsorg` prefixes a path that differs from SystemRage upstream;
an unprefixed `py-kms` path is identical in both unless stated.

**Summary of coverage** (119 features). Note that `⚙` is *not* an ordinal step between `◐` and `○`:
most of vlmcsd's 21 `⚙` cells — `-L`, `-m`, `-t`, `-F`, `-M`, `-E`, `-K`, `-i`, `-u`/`-g`, `-O`,
SIGHUP reload, daemonization — are fully runtime-configurable in the default build and would score
`●` if the column measured only the shipped binary. They are marked `⚙` because vlmcsd's build
system can remove them, which is a portability property, not a limitation of the default build.
Where the Notes column compares defaults (e.g. socket timeout: vlmcsd 30 s vs py-kms `None`), the
default, not the symbol, is the thing to read.

| | `●` full | `◐` partial | `⚙` build-gated | `○` absent | `–` n/a |
| --- | ---: | ---: | ---: | ---: | ---: |
| vlmcsd | 45 | 8 | 21 | 45 | 0 |
| py-kms (SystemRage) | 24 | 12 | 0 | 81 | 2 |
| py-kms (Organization) | 35 | 14 | 0 | 68 | 2 |

23 features are `○` in **all three** columns.

The shapes are different in kind, not just degree. vlmcsd's strength is protocol and behavioral
fidelity plus extreme portability, delivered through a build-time configuration surface so large
that "what vlmcsd does" is not a well-defined question without knowing the `FEATURES=` preset.
py-kms's strength is operability — database currency, persistence, containers, a web UI — on top of
a protocol implementation that is correct enough to activate and wrong in a dozen observable ways.

---

# The feature matrix

## 1. KMS protocol core

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| KMS v4 payload (plaintext + 160-bit Rijndael CBC-MAC) | Vista/7/2008/Office 2010 clients | `●` | `●` | `●` | Algebraically identical on both sides |
| KMS v5 payload (AES-128-CBC, request IV echoed) | Windows 8 / Office 2013 era | `●` | `●` | `●` | Both use the NULL-IV decryption trick |
| KMS v6 payload (random response IV, XoredIVs, HwId, truncated HMAC) | Windows 8.1+ / everything modern | `●` | `●` | `●` | Different parameterisations, identical wire bytes |
| Protocol version dispatch and validation strictness | Rejecting nonsense before parsing it | `●` | `◐` | `◐` | py-kms never validates `versionMinor` or minimum length |
| Error response for an unsupported KMS version | Answering instead of dropping the TCP connection | `●` | `◐` | `◐` | py-kms's error path always raises `UnicodeDecodeError` |
| Client clock-skew validation (±4 hours) | Documented Microsoft behaviour; detection vector | `●` | `○` | `○` | vlmcsd `-c1`, **default off**; py-kms has a `TODO` comment |
| Overcharge rejection (`N_Policy` > 1000) | A real host's CMID table is poisonable this way | `⚙` | `○` | `○` | vlmcsd rejects >2000 required clients; removable via `-DNO_STRICT_MODES` |
| Request size limits and buffer bounds | Bounding attacker-controlled length before parsing | `●` | `◐` | `◐` | py-kms does one fixed `recv(1024)`, no reassembly |
| Response ePID length validation | `PIDSize <= 128`, NUL-terminated UCS-2 | `◐` | `○` | `○` | vlmcsd validates client-side only; server never bounds what it emits |
| RPC return-code DWORD emitted separately from NDR padding | Being *able* to return a non-zero HRESULT | `●` | `◐` | `◐` | py-kms folds it into `getPadding()`, so it structurally cannot |

All three implement the three payload versions correctly, and that is the floor: get any of it
wrong and nothing activates at all. The interesting detail is that vlmcsd's `AesCmacV4` and
py-kms's `generateHash` are the *same wrong thing* — a zero-IV CBC-MAC with an unconditionally
appended `0x80` padding block (even when the length is already a multiple of 16) and no CMAC subkey
XOR (`vlmcsd src/crypto.c:194-213`, `vlmcsd src/kms.c:761-776`, `py-kms/pykms_RequestV4.py:17-98`).
That is not a bug in either; it is what Microsoft's v4 does, and both projects reverse-engineered
it independently to the same answer. Similarly, v6's HMAC is parameterised differently — vlmcsd
HMACs `response->IV || body` with the plaintext `SaltS` and emits `E_null(SaltS)`, py-kms emits
`SaltS` in the clear and prefixes `D(SaltS)` (`vlmcsd src/kms.c:792-825, 859-871` vs
`py-kms/pykms_RequestV6.py:33-96`) — and the bytes on the wire are identical.

Validation is where they diverge sharply. vlmcsd requires `minor == 0`, `major` in 4..6, and
`requestSize >= ` the per-version minimum (`src/rpc.c:180-227`). py-kms switches on `versionMajor`
alone (`py-kms/pykms_Base.py:245-266`); `versionMinor` is parsed, never checked, and echoed back,
so a "v6.1" request is serviced as v6, and a truncated v6 request is handed to the v6 handler.

The unsupported-version path is worth calling out because it is *dead code that has never
executed successfully in either py-kms version*. `pykms_RequestUnknown.py:16` builds the correct
12-byte `0xC004F042` envelope and then does
`finalResponse.decode('utf-8').encode('utf-8')` on a buffer that begins `42 F0 04 C0` — not valid
UTF-8, guaranteed `UnicodeDecodeError`. Still present unfixed on `pykmsorg/main`. vlmcsd returns
`0x8007000D` (`src/rpc.c:281`).

---

## 2. Cryptography

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| Pluggable crypto backend (OpenSSL / PolarSSL / Windows CryptoAPI) | Reuse audited code instead of bundling AES | `⚙` | `○` | `○` | vlmcsd `CRYPTO=`; its OpenSSL backend targets the 1.0 API only |
| Hardware AES acceleration (AES-NI) | Throughput | `⚙` | `○` | `○` | vlmcsd's only HW path is documented as "DANGEROUS"; py-kms is pure-Python AES |
| CSPRNG for IVs, salts and CMIDs | Correctness hygiene | `○` | `○` | `○` | **Nobody.** `rand()` / Mersenne Twister |
| Constant-time cipher implementation | Reusability of the primitives | `○` | `○` | `○` | **Nobody.** Table lookups and data-dependent branches |
| PKCS#7 padding content validation on decrypt | Rejecting malformed ciphertext | `◐` | `○` | `○` | vlmcsd validates client-side only; py-kms's stripper is broken |

vlmcsd's `CRYPTO={internal,openssl,openssl_with_aes,openssl_with_aes_soft,polarssl,windows}`
(`src/GNUmakefile:455-476`, `src/crypto_openssl.c:14-59`) is a real portability feature, but the
OpenSSL binding is stale: it targets the 1.0 API and will not build against 1.1+/3.x, and the
PolarSSL backend cannot use mbed TLS. The AES-NI path is worse than stale — it builds the tweaked
round key itself and pokes it into OpenSSL's private `AES_KEY` struct, which `src/config.h:295-310`
itself calls "DANGEROUS" and version/platform specific (`src/crypto_openssl.c:116-267`).

py-kms unconditionally uses a vendored SlowAES fork (`py-kms/pykms_Aes.py:19`) that recomputes the
full key schedule per 16-byte block (`pykms_Aes.py:398,448`) — roughly 13 ms per 256-byte CBC
operation. Only SHA-256/HMAC come from stdlib `hashlib`/`hmac`.

Neither has a CSPRNG. vlmcsd calls `srand(tv_sec ^ tv_usec)` at the start of **every connection**
(`src/helpers.c:343-352`, `src/rpc.c:618`); py-kms uses `random.getrandbits(8)`
(`py-kms/pykms_RequestV5.py:129`) and its single `os.urandom` call in `pykms_Aes.encryptData` is
dead code (`pykms_Aes.py:675`). This has no activation impact — both KMS keys are published
Microsoft constants and there is no secret to protect — but it is a defect a rewrite should not
inherit.

py-kms's `strip_PKCS7_padding` (`pykms_Aes.py:28`) checks only `len % 16` and `numpads <= 16`. A
trailing `0x00` makes `numpads = 0`, so `val[:-0]` is `val[:0]` — it returns an *empty* buffer,
silently discarding the entire plaintext. vlmcsd's client-side
`DecryptResponseV6` does check that the last byte is in 1..16 and that all pad bytes match
(`src/kms.c:1176-1198`) — but that is the client. Server-side, **neither implementation performs
any integrity check on inbound ciphertext.**

---

## 3. DCE/RPC transport

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| `alter_context` PDU handling | Win8+/2012+ clients send it after an NDR64 bind | `●` | `○` | `○` | py-kms logs "Invalid RPC request type" and closes |
| RPC fault PDU emission (`nca_s_unk_if` / `nca_s_proto_error`) | Signalling an RPC error instead of dropping | `●` | `○` | `○` | py-kms defines `MSRPCBindNak` but only its client parses it |
| NDR64 transfer syntax support | What modern Windows clients advertise | `●` | `○` | `○` | py-kms hardcodes a provider rejection |
| Bind-Time Feature Negotiation with correct bit echo | MS-RPCE encodes requested bits in the pseudo-GUID | `●` | `◐` | `◐` | py-kms demands an exact GUID and hardcodes `Reason=3` |
| Abstract syntax (KMS interface UUID) validation at bind | Not ACKing a bind for some other interface | `●` | `○` | `○` | py-kms reads only the transfer syntax |
| Context-id and opnum validation on the request PDU | Not servicing a context that was never accepted | `●` | `○` | `○` | py-kms echoes `ctx_id` unvalidated, never reads `op_num` |
| Per-connection association group id | A real RPC runtime never uses a constant | `●` | `○` | `○` | py-kms: `0x1063BF3F` worldwide — the best passive fingerprint |
| bind_ack SecondaryAddr derived from the accepting socket | Correct behind port-forwarding / multiple listeners | `●` | `◐` | `◐` | py-kms echoes the configured primary port |
| Keep the RPC association open after an activation | Genuine hosts do not disconnect | `●` | `○` | `○` | py-kms unconditionally closes; vlmcsd's `-d` opts into that |
| RPC PDU fragmentation and reassembly | `PFC_FIRST_FRAG`/`LAST_FRAG`, MaxXmit/MaxRecvFrag | `○` | `○` | `○` | **Nobody.** Both work only because the largest PDU is ~292 bytes |
| RPC authentication (sec_trailer / SPNEGO / NTLM) | Authenticated binds | `○` | `○` | `○` | **Nobody.** Unreachable in practice — KMS clients do not authenticate |
| Alternative RPC runtime backend (Microsoft `rpcrt4`) | Delegate the whole stack to the OS | `⚙` | `○` | `○` | vlmcsd `MSRPC=1`, Windows/Cygwin only |

This dimension is the widest gap in the whole audit, and it is entirely one-directional. vlmcsd
implements a credible DCE/RPC server; py-kms implements the minimum subset that a compliant Windows
client happens to exercise, and falls over on anything else.

**`alter_context`.** vlmcsd routes it through `rpcBind` and answers type 15
(`src/rpc.c:409-422, 585-587`). py-kms accepts PDU types 11 and 0 only
(`py-kms/pykms_Server.py:596-609`; `pykmsorg py-kms/pykms_Server.py:500-512`) and closes the
connection on anything else. This defect is normally masked by the NDR64 rejection — clients only
send `alter_context` after a bind that accepted NDR64 — but the two bugs are independent.

**Bind-item handling.** vlmcsd NACKs individual context items with `AckResult 2` and a specific
reason (`RPC_SYNTAX_UNSUPPORTED`, `RPC_ABSTRACTSYNTAX_UNSUPPORTED`) and still returns a valid
bind_ack (`src/rpc.c:475-552`). py-kms indexes a bare dict:
`preparedResponses[ts_uuid]` (`py-kms/pykms_RpcBind.py:119`). An unrecognised transfer syntax is a
`KeyError`, swallowed by `handle_error`, and the client gets a silent RST. Its BTFN matching is
also over-strict: MS-RPCE puts the requested feature bits in bytes 8-9 of the BTFN pseudo-GUID, so
vlmcsd matches the first 8 bytes and echoes `requested & (SEC_CONTEXT_MULTIPLEX|KEEP_ORPHAN)`
(`src/rpc.c:536-552`), whereas py-kms requires an exact match on
`6cb71c2c-9812-4540-0300-000000000000` (`pykms_RpcBind.py:18`) and hardcodes `Reason=3`.

**The association group.** `response['assoc_group'] = 0x1063bf3f` (`py-kms/pykms_RpcBind.py:104`,
verbatim on `pykmsorg/main`). Every py-kms deployment on earth returns the same value. vlmcsd draws
`RpcAssocGroup = rand32()` at startup and increments per accepted connection
(`src/network.c:1014,1053`). No active probing is needed to fingerprint py-kms — one bind_ack does it.

**Neither** implements PDU fragmentation. vlmcsd's own `_PEDANTIC` checker contains the comment
"vlmcsd does not support fragmented packets (not yet neccassary)" (`src/rpc.c:704-749`); py-kms
never inspects the flags at all. Neither implements RPC authentication, though py-kms goes further
in the wrong direction: it blindly echoes `auth_len` into a bind_ack that contains no trailer
(`pykms_RpcBind.py:99`), producing a malformed packet whenever a client sends one.

---

## 4. Activation policy and state

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| CMID list / real active-client tracking | The count a real host reports comes from *this* | `⚙` | `○` | `○` | vlmcsd `-M1`, **default off**, max 671 CMIDs; py-kms has no count state |
| CMID 30-day expiry / count decay | Real hosts age entries out and decrement | `○` | `○` | `○` | **Nobody.** Nothing in either project has a time dimension |
| Pre-charged client list | So the first genuine client already sees the threshold | `⚙` | `○` | `○` | vlmcsd `-E0` (default) seeds `(N>>1)-1` GUIDs |
| Product whitelisting / refusing unknown KMS IDs | A real host cannot activate what it has no CSVLK for | `⚙` | `○` | `○` | vlmcsd `-K` bitmask, **default 0** = activate everything |
| Reported count clamping with genuineness warnings | Stops an operator configuring a detectable count | `○` | `●` | `●` | py-kms clamps `-c` into `[N+1, 2N]` and warns |
| Per-client or per-product activation quota | Capping distinct machines per SKU | `○` | `○` | `○` | **Nobody.** Fork prior art only |
| Client allowlist / authorization gate | Refusing unapproved machines | `○` | `○` | `○` | **Nobody.** Fork prior art only |
| Source-IP access control (CIDR allow/deny) | Restricting which networks may activate | `◐` | `○` | `○` | vlmcsd `-o` only distinguishes RFC1918 from public |
| Connection rate limiting / DoS throttling | Internet-facing survivability | `○` | `○` | `○` | **Nobody.** vlmcsd's `-m` queues rather than rejects |

This is where the two projects make genuinely different *design* choices rather than one simply
lacking the other's work.

vlmcsd's `-M1` (`src/kms.c:167-262, 661-715`) is the only real modelling of KMS host state in the
class: a per-AppID list of up to `MAX_CLIENTS = 671` CMIDs (`src/kms.h:57`) in SysV shared memory
(fork mode) or heap (thread mode) behind a `PTHREAD_PROCESS_SHARED` mutex, growing `MaxCount`
toward the request's `required_clients` and returning `0xC004D104` above 671. `-E0` (default)
pre-charges each list with `(NCountPolicy >> 1) - 1` random GUIDs — 24 for Windows, 4 for Office —
so the first genuine client sees exactly 25 or 5 (`src/kms.c:245-260`, `src/vlmcsd.c:1279-1288`).
It is removable at build time (`-DNO_CLIENT_LIST`, `-DNO_STRICT_MODES`), forced off in inetd mode,
and **off by default**.

py-kms keeps no state usable for counting at all. Its SQLite table is write-only telemetry;
`requestCount` is incremented and never read back (`py-kms/pykms_Base.py:136-159`,
`py-kms/pykms_Sql.py`). It computes `currentClientCount = 2 * N_Policy` from the client's own
field. What it *does* have that vlmcsd lacks is a guard on operator misconfiguration: a user-supplied
`-c` is clamped into `[MinClients+1, 2*MinClients]` with the warning "activated client could be
detected as not genuine" (`pykms_Base.py:140-159`). vlmcsd has no equivalent; without `-M1` it
emits `max(2*N_Policy, MinActiveClients)` (`src/kms.c:719-723`), and `MinActiveClients` is 0 in
every shipped `.kmd`, so that floor is inert.

`-K` (`src/kms.c:622-659`, `src/vlmcsd.c:1268-1271`) is vlmcsd's product gate: bit 0 refuses unknown
KMS IDs *and* cross-checks the request's AppID against the database's `AppIndex`; bit 1 refuses
`IsRetail`/`IsPreview` products. Both return `0xC004F042`. Default `-K0` activates everything.
py-kms's `KmsDataBase.xml` carries `IsRetail`, `IsPreview` and `CanMapToDefaultCsvlk` attributes
that are parsed into the runtime dicts and read by **zero** lines of Python in either version.

Access control is thin everywhere. vlmcsd's `-o` (`src/network.c:170-225, 806-820`) distinguishes
only "private" (RFC1918-class) from "public" — bit 0 listens only on private addresses, bit 1
rejects public peers — and is defeated by NAT port-forwarding. Note `100.64.0.0/10` (CGNAT) is
deliberately classified public. Neither project has an arbitrary CIDR list, a client allowlist, or
any rate limiting. vlmcsd's `-m` is a counting semaphore that **queues** rather than rejects, so a
set of slowloris connections holds every worker for `-t` seconds each; `man/vlmcsd.8` recommends
`-m` plus a short `-t` plus `-d` as the entire mitigation strategy. py-kms spawns one unbounded OS
thread per connection (`py-kms/pykms_Server.py:37`) with no cap at all.

---

## 5. ePID and HWID identity

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| Per-process stable ePID across requests | **The** canonical emulator-detection test | `●` | `○` | `○` | vlmcsd `-r1` default; py-kms regenerates per response |
| Product-correct CSVLK selection for ePID synthesis | GroupId/key range must match the product family | `●` | `○` | `◐` | py-kms's loop biases ~98% toward a Server 2019 fallback |
| Per-CSVLK-group ePID configuration | One ePID per product family, as a real host has | `●` | `○` | `○` | vlmcsd `-a <CSVLK>=<ePID>`; py-kms has one global `-e` |
| KMS host build number control | The ePID claims a Windows build; it should be yours | `●` | `○` | `○` | vlmcsd `-H`; py-kms has no knob — SR skews ~86 % to 17763, Org is pinned to 17763 in 100 % of ePIDs |
| ePID / NDR64 self-consistency coupling | Advertised build must match RPC features offered | `●` | `○` | `○` | Unique to vlmcsd; pure anti-detection |
| Per-CSVLK HWID configuration | Distinct 8-byte HwId per product family | `●` | `○` | `○` | py-kms has one global `-w` |
| Randomized HWID | Not shipping a globally-shared constant | `○` | `●` | `●` | Org made `RANDOM` the **default**; vlmcsd's is compile-time |
| ePID/HWID harvesting from a genuine KMS host | The only way to get a *real* identity | `●` | `○` | `○` | `vlmcs -G` — the best anti-detection tool in the class |

This dimension is vlmcsd's strongest and py-kms's weakest, with one clean exception.

**Stable ePID.** vlmcsd `-r1` (default) generates one ePID per CSVLK at startup and reuses it for
the process lifetime; `-r0` uses the database default; only `-r2` regenerates per request
(`src/kms.c:361-406`). `man/vlmcsd.8:192-208` names the two-requests-one-connection test explicitly
as the reason. py-kms calls `epidGenerator()` on **every** response (`py-kms/pykms_Base.py:221-225`)
with an unseeded global `random`, so two byte-identical requests on one TCP connection return
different ePIDs. Unchanged in the Organization fork.

**CSVLK selection.** vlmcsd maps `KMSID -> EPidIndex -> CsvlkData` directly (`src/kms.c:266-358`).
py-kms's `pykms_PidGenerator.py:20-32` loops over `CsvlkItem`s and, for every item that *does not*
match, appends a Windows-Server-2019 fallback tuple `('206','551000000','570999999')` to the
candidate list — then does `random.choice` over all 49 entries (47 on `pykmsorg/main`). Measured on Office 2010: the
fallback wins 4887 times out of 5000. The Organization fork added an `except KeyError: pass` for
malformed entries; the fallback-in-loop bias itself is **unfixed on `pykmsorg/main`**.

**Host build.** vlmcsd `-H <build>` / ini `HostBuild` (0 = random from the database's
`HostBuildList`) also drives the 5-digit PlatformId prefix and the lower bound of the randomized
activation date (`src/kms.c:90-119`, `src/vlmcsd.c:1331-1334`). py-kms offers no knob, and its
build loop keys on `WinBuildIndex`, falling back to a hardcoded
`{'BuildNumber':'17763','PlatformId':'3612'}` on `KeyError` (`pykms_PidGenerator.py:36-45`):

- **py-kms (SR):** 12 of 18 `WinBuild` rows lack `WinBuildIndex`, so the fallback is appended 12
  times out of 18 — 17763 wins ~86 % of the time (13/15 for `InvalidWinBuild=[0,1,2]`).
- **py-kms (Org):** the v2.0 database dropped `WinBuildIndex` entirely in favour of `UseForEpid`,
  but `pykms_PidGenerator.py:42` was not updated. **All 30 rows raise `KeyError`**, `hosts` becomes
  30 copies of the same fallback dict, and the fork emits build 17763 / platform 3612 in **100 %**
  of generated ePIDs (measured: 2000/2000). Its 30-row catalog through 26100 is dead data.

**Self-consistency.** `getRandomServerType()` loops until it draws a host build whose `UseNdr64`
flag matches the configured `-N`, or derives `-N` from the drawn build (`src/kms.c:285-302, 377-396`,
`src/vlmcsd.c:1770-1785`). py-kms will happily claim build 26100 while rejecting NDR64 — a
combination no real host produces.

**The exception is HWID.** vlmcsd's default is a compile-time constant
`0x3A1C049600B60076`, commented "HwId from the Ratiborus VM" (`src/config.h:35-37`), overridable
only per-CSVLK and only when an explicit ePID is also given — the `memcpy` sits inside the
`Epid != NULL` branch (`src/kms.c:490-500`). Every stock vlmcsd shares it. py-kms upstream's
`364F463A8863D35F` was equally fixed, but the Organization fork made `-w RANDOM` the **default**
(`pykmsorg py-kms/pykms_Server.py:205-207`), which is the better posture of the three.

The genuinely correct answer is neither: `vlmcs -G <file>` walks every CSVLK group against a real
KMS host, steps the protocol version 6→5→4 on error, and merges `<GroupName> = <ePID> / <HwId>`
lines into a `vlmcsd.ini` with a `~` backup (`src/vlmcs.c:939-1083, 1086-1203`). Harvest, then pin.
py-kms has no analogue.

---

## 6. Product database

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| External database loadable without recompiling | Update products without a new binary | `●` | `◐` | `◐` | vlmcsd `-j`; py-kms's XML path is hardcoded, no flag |
| Database integrity / bounds validation on load | Refusing a hostile data file | `⚙` | `○` | `○` | vlmcsd's checks are removable and still incomplete |
| Database parsed once and cached | Not re-reading the DB per request | `●` | `○` | `○` | py-kms parses the 88 KB XML ~2× per activation |
| Current product coverage (Win 11 / Server 2022-2025 / Office LTSC 2021-2024) | Post-2019 products | `○` | `○` | `●` | Both upstreams frozen at Win10 1809 / Office 2019 |
| Graceful handling of products newer than the database | Activating unknown GUIDs anyway | `●` | `◐` | `●` | Upstream py-kms raises `UnboundLocalError` and drops |
| GVLK (setup key) table shipped with the project | Users need the key to `slmgr /ipk` | `○` | `●` | `●` | The KMS protocol never carries the key, so vlmcsd never needed it |
| Human-readable product names in logs by default | Diagnosability out of the box | `⚙` | `●` | `●` | Stock vlmcsd logs every SKU as "Unknown" |

vlmcsd's `-j <file>` / ini `KmsData` loads a "KMD" v2 binary blob, defaulting to
`<exedir>/vlmcsd.kmd`, with `-j -` forcing the internal database (`src/helpers.c:553-686`,
`src/vlmcsd.c:1136-1145`). Offsets are relocated to pointers once at startup. Validation — magic
`KMD`, `MajorVer == 2`, terminating NUL, every pointer inside the file, `AppIndex`/`KmsIndex`
ranges — is real but removable via `-DUNSAFE_DATA_LOAD` (and implicitly by `-DNO_EXTERNAL_DATA`),
and still incomplete: `EPidIndex` is never bounded, and a wrapped 64-bit offset passes the
upper-bound-only test.

py-kms's `KmsDataBase.xml` is a separate file, which is why it scores `◐` rather than `○`, but the
path is `dirname(pykms_DB2Dict.py)` — hardcoded, with no CLI flag, no override and no environment
variable (`py-kms/pykms_DB2Dict.py:9`, identical in both). Worse, `kmsDB2Dict()` is called on
**every request** from `serverLogic()` (`pykms_Base.py:163`) and a **second time** inside
`epidGenerator()` when no `-e` is set (`pykms_PidGenerator.py:14`). At a measured ~1.75 ms per
parse, that is ~4 ms of pure XML parsing per activation. Unchanged in the Organization fork; its
WebUI caches, but only for its own product page (`pykmsorg py-kms/pykms_WebUI.py:19-44`).

**Currency is the single feature where the Organization fork stands alone.** Both upstreams are
frozen at Windows 10 1809 / Server 2019 / Office 2019 with a newest host build of 17763.
`pykmsorg py-kms/KmsDataBase.xml` carries 30 WinBuilds through 26100 (Win11 24H2 / Server 2025) —
none of which its ePID generator can actually select, see §"Host build" above —
Server 2022 and 2025 `KmsItem`s with real GVLKs, the Office 2021 and 2024 families, Win11 SE, IoT
LTSC 2021-2024, Enterprise multi-session, and Server 2022/2025 Azure-only and Internal-Lab CSVLKs.
(Caveat: its Office 2024 `KmsItem` has the attribute typo `DefaultKmsprotocol`.)

That said, database staleness matters less than it looks, because of graceful degradation.
vlmcsd's `getProductIndex` returns -1, names the product "Unknown", and falls back to CSVLK 0
(Windows) (`src/kms.c:46-63, 644-649`), so a 2019-era vlmcsd still activates Windows 11. Upstream
py-kms assigns `skuName`/`appName` only inside the matching branch (`pykms_Base.py:170-186`), so an
unlisted GUID leaves them unbound, `serverLogic` raises `UnboundLocalError` inside the handler
thread, `handle_error` swallows it, and the client gets a dropped connection with nothing logged.
That is the actual mechanism behind the "Server 2022 doesn't work" reports. The Organization fork
fixed it by pre-seeding `appName, skuName = str(applicationId), str(skuId)`
(`pykmsorg py-kms/pykms_Base.py:167`).

The GVLK asymmetry is structural, not an oversight: the KMS protocol carries only GUIDs, never the
setup key, so vlmcsd's `.kmd` format has no key field at all (`src/kms.h:256-279`) and the project
leaves key lookup to the user. py-kms carries a `Gvlk` attribute on every `SkuItem` (~230 distinct
keys) plus a maintained `docs/Keys.md`, and the Organization fork surfaces them in the WebUI
`/products` page (`pykmsorg py-kms/pykms_WebUI.py:129-149`).

One under-appreciated vlmcsd wart: a **stock** build links the 1858-byte compact database with
`SkuItemCount = 0` and every name pointing at one shared "Unknown" string
(`src/kmsdata.c:1036-1157`, `src/GNUmakefile:382-388`). Every SKU logs as "Unknown" unless you
build `-DFULL_INTERNAL_DATA` or supply an external `.kmd`.

---

## 7. Discovery and integration

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| DNS SRV client-side discovery (`_vlmcs._tcp`) | Finding a host without `slmgr /skms` | `●` | `○` | `●` | vlmcsd does full RFC 2782 ordering; Org takes the first answer |
| DNS SRV publishing (dynamic DNS registration) | **How real hosts are found at all** | `○` | `○` | `○` | **Nobody.** The largest deployment gap in the class |
| Active Directory-Based Activation (ADBA) | Microsoft's preferred domain mechanism | `○` | `○` | `○` | **Nobody.** Arguably out of scope |
| KMS host chaining / upstream forwarding / proxy | Relay to a real host; harvest genuine identity | `○` | `○` | `○` | **Nobody.** `vlmcs -G` is the closest, and it is offline |
| Multi-tenancy (per-listener / per-network identity) | Serving several orgs from one process | `○` | `○` | `○` | **Nobody.** No config is associated with a socket or peer |
| High availability: shared client-count state | A load-balanced pair reporting a consistent count | `○` | `○` | `○` | **Nobody.** vlmcsd's list is per-process and dies on restart |

Five of six are unanimous absences; see [Gaps](#gaps-what-nobody-implements).

The one that exists is client-side only. `vlmcs` supports a target of `-` (own domain) or `.domain`,
using `res_querydomain`/`DnsQuery_UTF8`, RFC 2782 randomized-weight sorting, `-P` to disable
sorting, and a bundled BIND parser (`DNS_PARSER=internal`) (`src/dns_srv.c:141-320`,
`src/vlmcs.c:760-831`). The Organization fork added `-D/--discovery` via dnspython, taking the
first SRV answer with no priority/weight handling (`pykmsorg py-kms/pykms_Client.py:80, 195-208`).
Upstream py-kms has nothing.

Critically, **`dns_srv.c` is compiled into the vlmcs client only** — `src/vlmcs.c:763,771` are its
only callers. The vlmcsd *server* publishes nothing.

---

## 8. Networking and concurrency

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| IPv4 / IPv6 dual-stack listening | Serving both families | `●` | `◐` | `●` | vlmcsd binds two sockets; Org flipped the default to `::` |
| Multiple listening addresses | Several `ip:port` in one process | `⚙` | `●` | `●` | vlmcsd `-L` is numeric-IP-only and capped by `FD_SETSIZE` |
| Configurable listen backlog | Accept-queue tuning | `○` | `●` | `●` | vlmcsd hardcodes `SOMAXCONN` |
| Bind to non-local addresses (`IP_FREEBIND`) | Binding an address that does not exist yet | `⚙` | `○` | `○` | vlmcsd's IPv6 path uses the wrong socket level and cannot work |
| Process-per-connection (fork) concurrency | Crash isolation | `⚙` | `○` | `○` | vlmcsd's POSIX default; `THREADS=1` switches |
| Concurrent worker limit | Bounding in-flight clients | `⚙` | `○` | `○` | vlmcsd `-m`, default `SEM_VALUE_MAX` = unlimited |
| Per-connection send/receive timeout | A peer must not hold a worker forever | `⚙` | `●` | `●` | vlmcsd `-t` / ini `ConnectionTimeout`, **default 30 s**, removable with `-DNO_TIMEOUT`; py-kms `-t1/--timeout-sndrcv`, **default `None`** = never. vlmcsd has the better posture despite the symbol |
| Server idle-lifetime timeout | Shutting down when unused | `○` | `◐` | `◐` | py-kms's `-t0` is a total-lifetime cap, not an idle timer |
| inetd / xinetd socket activation | Per-connection launch with the socket on stdin | `●` | `○` | `○` | vlmcsd auto-detects; `-DNO_SOCKETS` builds inetd-only |
| Native systemd socket activation (`LISTEN_FDS`) | Supervisor-managed sockets | `○` | `○` | `○` | **Nobody.** Neither reads `LISTEN_FDS`/`LISTEN_PID` |
| Graceful shutdown | Clean SIGTERM/SIGINT handling | `●` | `◐` | `●` | vlmcsd calls `logger()` from signal context |
| Windows TAP/VPN adapter mirroring | Making a local machine look remote | `⚙` | `○` | `○` | vlmcsd `-O`; exists because clients refuse 127.0.0.1 |

Note the mirror-image compile-time/runtime split here: vlmcsd's fork model, worker limit, socket
timeout, multiple listeners and free-binding are **all** compile-time-gated (`SIMPLE_SOCKETS`,
`NO_LIMIT`, `NO_TIMEOUT`, `NO_SOCKETS`, `USE_MSRPC` variously remove them), so "does vlmcsd have a
worker limit" depends on the `FEATURES=` preset the binary was built with. py-kms has none of that
ambiguity and correspondingly fewer features.

**Timeouts are the one place where a default is a genuine availability difference.** vlmcsd's
`ServerTimeout` defaults to 30 seconds (`src/shared_globals.c:57`, confirmed;
`-t <1..600>`, and the 600 ceiling is undocumented), applied as `SO_RCVTIMEO`/`SO_SNDTIMEO`
(`src/network.c:748-775`). py-kms's `-t1/--timeout-sndrcv` defaults to `None` — no timeout at all
(`py-kms/pykms_Server.py:208-209`, identical on `pykmsorg/main`, verified). Combined with no worker
cap and one unbounded thread per connection, a trivial slowloris is fatal.

py-kms's `-t0` is documented as "inactivity time after which the connection with the client is
closed" but is actually `KeyServer.timeout`, with a deadline computed **once** before the accept
loop and never rearmed on activity; expiry calls `sys.exit(1)`, killing the whole process
(`py-kms/pykms_Server.py:81,87,100,125-127`). It is an upper bound on total server lifetime.
vlmcsd has no equivalent.

Dual-stack: vlmcsd binds **separate** `::` (with `IPV6_V6ONLY=TRUE`) and `0.0.0.0` sockets
(`src/network.c:562`), each guarded by a stack-existence probe — `SIMPLE_SOCKETS` builds do the
opposite, one socket with `V6ONLY=0` (`src/network.c:339`). Upstream py-kms defaults to
`ip=0.0.0.0` with `connect -d` as a `store_true` that is **off** by default, and explicitly sets
`IPV6_V6ONLY=1` when it is not passed — so the README's "a dual-stack socket is created" claim is
false by default. The Organization fork flipped the listen default to `::` and made `-d` a
true/false-valued flag defaulting to `True` (`pykmsorg py-kms/pykms_Server.py:183`,
`pykmsorg py-kms/pykms_Connect.py:41-72`).

Gotchas worth recording: vlmcsd's `-L` accept loop always takes the **first** ready descriptor, so
a saturated early listener starves later ones (`src/network.c:706-719`). Its `-m` semaphore is a
POSIX named semaphore hardcoded to `/vlmcsd`, so two instances corrupt each other's limit, and a
`fork()` failure leaks both the fd and the semaphore count (`src/vlmcsd.c:1514-1580`). Its inetd
auto-detection `fstat()`s stdin without checking the return value, and the ini file is read *after*
the forced `MaintainClients = FALSE`, so an ini `MaintainClients = true` re-enables it
(`src/vlmcsd.c:1734-1754`). Its `IPV6_BINDANY` is set with level `IPPROTO_IP` instead of
`IPPROTO_IPV6`, so FreeBSD IPv6 free-binding can never work and the failure is hidden behind
`_PEDANTIC` (`src/network.c:581-620`, `src/types.h:78`). And `cleanup()` calls `logger()` —
`fopen`/`fprintf` — from signal context, which is not async-signal-safe, while in-flight children
are neither signalled nor waited for (`src/vlmcsd.c:1464-1492`).

vlmcsd's `-O <adapter>[=ip][/cidr][:lease]` (`src/wintap.c:75-370`) is the most unusual feature in
either project: it configures an OpenVPN-TAP or TeamViewer VPN adapter in TUN mode, runs an
internal DHCP server, and spawns a thread that reads each IP packet, swaps `ip_src`/`ip_dst` and
writes it back — so a local machine appears as a remote KMS client. It exists purely because
Microsoft clients refuse to activate against 127.0.0.1.

---

## 9. Configuration surface

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| Configuration file | Persisting settings outside argv | `⚙` | `○` | `○` | vlmcsd `-i`; py-kms is argv-only, Docker synthesizes argv |
| Environment-variable configuration | Container-native config | `○` | `○` | `◐` | Neither **server** reads `getenv`; Org's WebUI and launcher do |
| Config reload without dropping the listener (SIGHUP) | Rotating identity without downtime | `⚙` | `○` | `○` | vlmcsd re-execs itself; it is a restart, not a hot reload |
| Compile-time feature stripping | OpenWrt-class targets | `●` | `–` | `–` | ~30 macros + 7 `FEATURES=` presets; meaningless for Python |
| Strict argv validation (no abbreviations, no duplicates) | Failing loudly on a typo'd flag | `○` | `●` | `●` | py-kms pre-screens `sys.argv`; vlmcsd uses stock `getopt` |

vlmcsd's `-i <file>` is a flat `keyword = argument` ini read in up to three passes (general
parameters, per-CSVLK ePID/HwId, `Listen` sockets), with the CLI winning via
`ignoreIniFileParameter()` (`src/vlmcsd.c:860-937, 828-843`). Two gotchas: keyword matching is
**prefix-based** (`strncasecmp` over `strlen`), so `Portable = 5` silently sets the TCP port; and
only CR/LF are trimmed, so trailing blanks become part of the value. Removable with
`-DNO_INI_FILE`.

The environment-variable row is the most commonly misunderstood fact about py-kms. **Neither
server reads `os.environ` for KMS settings** — grep confirms zero hits in vlmcsd's `src/` and in
py-kms's server path. All the documented `IP`/`PORT`/`EPID`/`LCID`/`CLIENT_COUNT`/`HWID`/`LOGLEVEL`
variables live only in Docker shell wrappers (`py-kms docker/docker-py3-kms/start.sh`). The
Organization fork scores `◐` because `docker/start.py` is now a first-class in-tree Python launcher
that maps environment to argv (`pykmsorg docker/start.py:10-27`) **and** `pykms_WebUI` reads
`PYKMS_SQLITE_DB_PATH` / `PYKMS_LICENSE_PATH` / `PYKMS_VERSION_PATH` directly
(`pykmsorg py-kms/pykms_WebUI.py:52,63`).

vlmcsd's SIGHUP handler (`src/vlmcsd.c:944-987, 1111-1116`) rebuilds argv, appends an undocumented
`-Z` marker, and re-execs itself (`getauxval` / `/proc/self/exe` / `sysctl`, falling back to
`execvp`), so the ini file is genuinely re-read and `-r1` ePIDs regenerate. `-Z` suppresses
re-daemonizing, pid-file rewriting and the privilege drop. Listeners are `FD_CLOEXEC`'d
(`src/network.c:542`), so this is a restart rather than a hot reload, and `malloc()` inside a
signal handler is not async-signal-safe. Auto-disabled on Cygwin/Windows/`NO_SOCKETS`.

`FEATURES={full,most,autostart,embedded,inetd,minimum,fixedepids}` plus ~30 `NO_*`/`SIMPLE_*`/
`USE_*` macros (`src/config.h:331-667`, `src/GNUmakefile:262-274`) let you drop logging, the ini
parser, DNS, the client list, whitelisting, random ePIDs, the user switch, the pid file, timeouts,
private-IP detection and the external data loader. This is the mechanism that makes vlmcsd viable
on a router — and simultaneously the reason so many rows in this matrix are `⚙` rather than `●`.

py-kms's `kms_parser_check_optionals` (`py-kms/pykms_Misc.py:382-412`) makes unknown options,
GNU-style abbreviations (`--logf`), repeated options and over-long values all fatal with a specific
message. Side effect: any value beginning with `-` (e.g. `-c -1`) is rejected as an unknown option.
vlmcsd uses stock `getopt`, where the last occurrence wins, and both `-h` and `-?` are documented
but absent from the optstring (`src/vlmcsd.c:87`, `man/vlmcsd.8:37`), so help appears only via the
unknown-option path and exits `EINVAL`.

---

## 10. Logging and observability

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| syslog output | Standard system logging | `●` | `○` | `○` | vlmcsd opens/closes per message and logs everything at `LOG_INFO` |
| Windows Event Log integration | Native platform logging | `○` | `○` | `○` | **Nobody.** vlmcsd's is entirely commented out |
| Built-in log rotation | Bounded disk without an external rotator | `○` | `●` | `●` | py-kms `-S`; documented in MB, actually 0.5 MiB per unit |
| Graduated log levels | Verbosity control | `◐` | `●` | `●` | vlmcsd has only `-v`/`-q`; conformance warnings need `_PEDANTIC` |
| Structured / machine-readable output (JSON) | Log pipelines without regex | `○` | `○` | `○` | **Nobody.** Both hardcode human format strings |
| Prometheus / statsd metrics endpoint | Scrapeable counters | `○` | `○` | `○` | **Nobody.** One fork attempt, architecturally broken |
| HTTP health / readiness endpoints | Orchestrator probes | `○` | `○` | `●` | Org's `/readyz` and `/livez` — but they do not probe the KMS port |
| Web dashboard / management UI | State visibility for non-CLI operators | `○` | `○` | `●` | Org's Flask app; upstream had a Tkinter GUI instead |
| Persistent activation record store | Knowing which machines activated | `○` | `●` | `●` | py-kms SQLite; vlmcsd persists nothing |
| Client source IP recorded in the store | Where the request came from | `○` | `○` | `●` | Org added `lastRequestIP` — from a racy process-global |
| Activation history / append-only audit trail | Chronology, not a mutable snapshot | `○` | `○` | `○` | **Nobody.** One mutable row per (CMID, app) |
| Query / reporting interface over recorded activations | Reading the store back | `○` | `○` | `◐` | Upstream's "web interface" is a third-party `sqlite-web` clone |
| Request-handler exceptions surfaced rather than swallowed | Diagnosability of malformed requests | `◐` | `○` | `●` | Upstream's `handle_error` is literally `pass` |

The `handle_error` row deserves emphasis because it silently amplifies every other py-kms defect.
`py-kms/pykms_Server.py:129-130` overrides `handle_error()` to `pass`. Every parsing failure — a
truncated header, the unknown-transfer-syntax `KeyError`, the `-c 0` `UnboundLocalError`, a `tzlocal`
`AttributeError`, an out-of-range FILETIME, the `UnicodeDecodeError` in the unsupported-version
path — is invisible at every log level, and the client just sees a reset. The Organization fork logs
the client address and `traceback.format_exc()` (`pykmsorg py-kms/pykms_Server.py:126-128`). vlmcsd
scores `◐` only because it is C and there is nothing to catch; its own protocol-conformance warnings
are compiled out unless `_PEDANTIC`.

vlmcsd's `-l syslog` (`src/output.c:35-41`) uses `openlog`/`vsyslog(LOG_INFO, LOG_USER,
LOG_CONS|LOG_PID)` — opening and closing the log per message and emitting *everything* at
`LOG_INFO`, so warnings and fatal errors never reach `LOG_WARNING`/`LOG_ERR`. For file logging it
reopens in append mode for every line, which makes external `logrotate` work with no reopen signal
at the cost of an `open()`/`close()` pair per record. py-kms's `-S` uses `RotatingFileHandler` with
`backupCount=1` and computes the size as `int(logsize * 1024 * 512)` = 0.5 MiB per unit
(`py-kms/pykms_Misc.py:169`) — so `-S 2` rotates at 1 MiB, a doc/code mismatch present in both
versions.

py-kms's levels are `CRITICAL/ERROR/WARNING/INFO/DEBUG` plus a custom `MININFO` registered at
numeric 25 (`pykms_Misc.py:155-157`). Note `MININFO` sits **above** `INFO`, so selecting it
suppresses the startup banner. Default level: upstream `ERROR`, Organization `WARNING` (verified at
`pykmsorg py-kms/pykms_Server.py:212`).

The persistence story is entirely py-kms's. `-s [path]` writes a `clients` table
(`clientMachineId`, `machineName`, `applicationId`, `skuId`, `licenseStatus`, `lastRequestTime`,
`kmsEpid`, `requestCount`). Upstream calls `sql_initialize` on **every** request and stores
*display names* in columns named `applicationId`/`skuId` (`py-kms/pykms_Sql.py:18-101`). The
Organization fork moved initialization to startup, added `PRIMARY KEY(clientMachineId,
applicationId)`, a `metadata`/`schema_version` table with automatic `ALTER TABLE` migration,
named-column access via `sqlite3.Row`, context-managed connections, and a `lastRequestIP` column
(`pykmsorg py-kms/pykms_Sql.py:20-131`). vlmcsd persists nothing whatsoever; its `-M1` CMID list is
in-memory and dies with the process.

Two caveats on that store. First, `lastRequestIP` comes from `srv_config['raddr'][0]`, and
`raddr` is a **process-global** set in `setup()` — under `ThreadingMixIn` a concurrent connection
can overwrite it, so the Organization fork's improvement also persists a racy value. Second, it is
one mutable row per (CMID, application): each request overwrites the timestamp, machine name, SKU,
status and ePID. There is no history, no retention policy, no aging — which is also why none of
these implementations can derive a genuine client count from their own records.

The Organization WebUI (`pykmsorg py-kms/pykms_WebUI.py:65-149`, gunicorn on 8080, `WEBUI=1`) serves
`/`, `/clients`, `/products` (all KMS products with GVLKs, grouped, plus a count of GVLK-less
entries) and `/license`, using vendored Bulma so it works offline. It has **no authentication and no
CSRF protection**, and its `/readyz`/`/livez` error strings echo raw exception text. `/readyz`
checks that `PYKMS_SQLITE_DB_PATH` is set and gates on a 10-second warmup; `/livez` is trivial.
Neither probes the KMS TCP listener — they only prove the Flask process is alive. The container
`HEALTHCHECK` is a separate TCP probe in `docker/healthcheck.py`.

---

## 11. Security posture

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| Memory safety of the request path | Attacker bytes reach a hand-written C parser | `○` | `●` | `●` | The strongest single argument for the Python side |
| Privilege drop (setuid/setgid + setgroups) | Not running as root after binding 1688 | `⚙` | `○` | `◐` | vlmcsd `-u`/`-g`; Org drops in the container entrypoint only |
| chroot / jail / seccomp / pledge sandboxing | Confinement beyond dropping uid | `○` | `○` | `○` | **Nobody.** Grep-confirmed absence in both |
| Container hardening (non-root, read-only app files) | Not shipping a root image | `○` | `○` | `●` | vlmcsd ships no image at all |
| Minimal runtime dependency footprint | Attack surface | `●` | `●` | `◐` | Org adds dnspython (hard import), Flask, gunicorn |
| Automated test suite | Any executable verification | `○` | `○` | `◐` | Org has one smoke-test workflow, no unit suite |
| Fuzzing harness for the RPC parser | The parser eats pre-auth attacker bytes | `○` | `○` | `○` | **Nobody.** Highest-value missing QA capability |
| Reproducible builds / SBOM / signed artifacts | Supply-chain integrity | `○` | `○` | `○` | **Nobody.** Org's `BUILD_COMMIT` stamp is the closest |

The memory-safety row is not a stylistic preference. vlmcsd's audit found, in the pre-bind request
path:

- A **remote out-of-bounds array read plus an indirect call through a wild function pointer**. A
  `ContextId` of `0xffff` makes `Ctx` match *both* `RPC_INVALID_CTX` sentinels, yielding
  `majorIndex = arbitrary - 4` and an unchecked `_Versions[majorIndex].CreateResponse` call
  (`src/rpc.c:189-226` vs `src/rpc.c:257-287`).
- A `>=` rather than `==` size check that lets a v6 request read past what was actually received
  (`src/rpc.c:189,226`; see MM18).
- A bind_ack that **deliberately** leaks uninitialised stack in the `SecondaryAddress` padding, to
  mimic Microsoft (`src/rpc.c:229-237`, `src/rpc.c:442-443`).

Against that, py-kms's failure modes are unhandled exceptions.

Privilege handling: vlmcsd's `-u`/`-g` (ini `user`/`group`) resolves names or numeric ids and drops
**after** the listeners are created — `setgid`, then `setgroups(1,&gid)` to shed supplementary
groups, then `setuid` (`src/vlmcsd.c:1861-1891`). Deliberately skipped after a SIGHUP re-exec
(`-Z`). Removable with `-DNO_USER_SWITCH`, unavailable on native Windows. py-kms has no in-process
drop; the Organization fork does it in `docker/entrypoint.py:32-60` (chown the app dir and db, fix
0700/0600 modes, `os.setgid`/`os.setuid`, skip if not root) — container-only, hence `◐`.

Beyond that there is nothing. An exhaustive grep of vlmcsd's `src/` finds no `chroot`, no `umask`,
no `setsid` of its own, no capability manipulation, no seccomp and no pledge. It calls
`daemon(nochdir=1, ...)` (`src/vlmcsd.c:1012`), so it does not even `chdir` to `/`, and its log and
pid files are created with the inherited umask. Nothing in py-kms either.

Dependency footprint is the one row where the *active* fork is worst. vlmcsd needs libc only in a
default build — its own AES/SHA-256, its own DCE/RPC, its own DNS parser optional — with every
external library opt-in (`src/GNUmakefile:455-476`). Upstream py-kms is stdlib-only with
`tzlocal`/`pytz`/`sqlite3` optional and degrading gracefully. The Organization fork makes dnspython
a **hard import at module top** of `pykms_Client.py` (`pykmsorg py-kms/pykms_Client.py:16-20`) and
adds Flask + gunicorn for the WebUI (dnspython 2.8.0, tzlocal 5.3.1, Flask 3.1.2, gunicorn 23.0.0).

Testing: vlmcsd has no tests, no CI config and no `.github` directory. Upstream py-kms likewise. The
Organization fork's `.github/workflows/test_basic_client.yml` starts the server under `timeout 30`
with `-s` and runs `pykms_Client` three times (random CMID once, then a fixed CMID twice) to
exercise both the INSERT and UPDATE paths. That is a smoke test; it covers no protocol edge case.

---

## 12. Client tooling and diagnostics

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| Bundled test client | Driving the server end-to-end | `●` | `●` | `●` | `vlmcs` is a diagnostic tool; `pykms_Client` is a self-test |
| Response cryptographic validation suite | Proving a response is well-formed | `●` | `○` | `○` | py-kms's client logs the V4 CMAC check **only on success** |
| Active emulator-detection warnings | Telling the operator the server looks fake | `●` | `○` | `○` | Unique to vlmcsd |
| Product / GVLK enumeration for the operator | What can be activated, with which key | `◐` | `◐` | `●` | `vlmcs -x` lists names only; its counter is `uint8_t` |
| Arbitrary / invalid protocol version generation | Probing server strictness | `●` | `○` | `○` | `vlmcs -K <major>.<minor>` accepts any 0..65535 pair |
| Load / soak testing capability | Finding leaks and concurrency bugs | `●` | `○` | `○` | `vlmcs -n <count>` plus `-T` for a fresh connection each time |
| Adaptive charging mode | Auto-satisfying a real host's threshold | `●` | `○` | `○` | What makes plain `vlmcs <host>` charge a genuine host to 25 |
| Embeddable library / programmatic API | Using the KMS engine from another program | `⚙` | `○` | `○` | vlmcsd builds `libkms`; not thread-safe |
| Desktop GUI | Non-CLI operators | `○` | `●` | `○` | Upstream's Tkinter GUI; the Org fork deleted it |

`vlmcs` is a substantially more capable program than the py-kms client, and much of it exists
specifically to test *emulators*. Its `RESPONSE_RESULT` bitfield (`src/kms.h:204-227`,
`src/kms.c:983-1201`) checks `HashOK`, `TimeStampOK`, `ClientMachineIDOK`, `VersionOK`, `IVsOK`,
`DecryptSuccess`, `HmacSha256OK`, `PidLengthOK`, `RpcOK`, and effective-versus-correct response
size, under the source comment "we want to use vlmcs as a debug tool for KMS emulators". It prints
active detection warnings — "WARNING: The KMS server is an emulator because the response uses an IV
following KMSv5 rules in KMSv6 protocol" (`result.IVnotSuspicious`), warnings when the server offers
no NDR32 or NDR64-without-BTFN, warnings on non-zero NDR padding and AllocHint mismatch, and
detection of the Wine constant-CallId bug (`src/vlmcs.c:663-687`, `src/rpc.c:764-795`).

Without `-n`, `vlmcs` starts at `NCountPolicy - 1` requests, recomputes
`RequestsToGo = NCountPolicy - response.Count` after each success, and aborts with "The KMS server
does not increment it's active clients" if the count fails to rise (`src/vlmcs.c:1288-1328`). With
`-n <count>` (its own examples suggest 100000) plus `-T` to force a fresh TCP connection and rebind
per request, it is an explicit leak-testing harness for emulators (`man/vlmcs.1:145-158`).

py-kms's `pykms_Client` verifies the V4 CMAC but **logs only on success** — a mismatch is silent
(`py-kms/pykms_Client.py:346-360`) — and never checks the V5 IV-equality rule, the SHA-256 salt
proof, or the V6 HMAC. It uses a fixed `licenseStatus = 2` and `graceTime = 43200`, derives the
protocol version solely from the selected SKU's `DefaultKmsProtocol` with no override (so its own
`kmsRequestUnknown` path is unreachable from its own client), and offers only 9 `-m` product
modes — none of them Windows Server, Windows 11 or Office 2021/2024, even in the Organization fork
**whose database has all of them** (`pykmsorg py-kms/pykms_Client.py:59-61`).

`vlmcs -x` lists all 202 SKU names in a column-major table sized to the terminal
(`src/vlmcs.c:235-282`) — names only, no GVLKs, and the counter is `uint8_t`, so a database above
255 SKUs mis-renders. `libkms` (`src/libkms.c:49-207`, `src/GNUmakefile:537-563`) exports ten
`__cdecl` entry points including `StartKmsServer(port, callback)` with a caller-supplied
`CreateResponseBase`; it is **not** thread-safe (`ErrorMessage`, `CreateResponseBase`, the three RPC
flags, `CallId` and `firstPacketSent` are all globals), `IS_LIBRARY` strips the product database
entirely so the embedder must synthesize the ePID, and `libkms.h` leaks `#define client_main main`.

Upstream py-kms's ~1465-line Tkinter GUI is auto-launched whenever `sys.stdout` is not a tty
(`py-kms/pykms_Server.py:638-645`) — so `pykms_Server.py > log.txt` on a desktop opens a window
instead of running headless. The Organization fork deleted it (`pykms_GuiBase.py`,
`pykms_GuiMisc.py`, `graphics/`, `LICENSE.gui.md`) in favour of the web UI.

---

## 13. Packaging and deployment

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| Container image published by the project | The default way people run this | `○` | `●` | `●` | vlmcsd's `docker/` is an **empty submodule** |
| Multi-architecture images | ARM SBCs and NAS boxes | `○` | `●` | `●` | Upstream used qemu-static + autobuild hooks; Org uses buildx bake |
| Kubernetes deployment (Helm chart) | Orchestrated deployment | `○` | `○` | `●` | Why `/readyz` and `/livez` exist |
| systemd unit / init script shipped in-tree | A supported service definition | `○` | `○` | `○` | **Nobody.** Docs snippets only; forks supply real units |
| OS package (deb / rpm / pip) | Native package manager install | `○` | `○` | `○` | **Nobody.** No `setup.py`, no `pyproject.toml`, empty `debian/` |
| Background daemonization | Detaching without a supervisor | `⚙` | `●` | `○` | Org **deleted** Etrigan; now always foreground |
| Windows service integration | Install/remove/run as an NT service | `●` | `○` | `○` | py-kms offers a pywin32 doc template with Python 2.7 paths |
| Bootable appliance image | Turnkey VM that is nothing but the KMS host | `◐` | `○` | `○` | vlmcsd documents a 1.44 MB floppy; the image is gitignored |

vlmcsd ships **no** deployment artifacts. `docker/` and `debian/` are git submodules pointing at
`Wind4/vlmcsd-docker` and `Wind4/vlmcsd-debian` and are empty in the repository (`.gitmodules`), so
there is no Dockerfile, init script or unit file in-tree, and the top-level GNUmakefile has no
`install` target. Its README describes a hand-curated `binaries/<os>/<cpu>/<endianness>/<libc>` tree
that is not present in the repository either.

Upstream py-kms shipped four per-architecture Dockerfiles per variant on Docker Hub, using a
two-stage build that copies a balena qemu-4.0.0 static binary per arch plus Docker Hub autobuild
hooks and `manifest-tool` — a pipeline predating buildx whose autobuild service has since been
retired. The Organization fork consolidated to one Dockerfile per variant, built with `buildx bake`
and published to ghcr.io (`pykmsorg .github/workflows/bake_to_latest.yml`,
`bake_to_next.yml`, `bake_to_version.yml`).

Its Helm chart (`pykmsorg charts/py-kms/`) has `replicaCount`, `image`, `imagePullSecrets`, a
`py-kms.environment` map, a ClusterIP service exposing `httpPort` 80 and `kmsPort` 1688, optional
ingress and HPA, `serviceAccount`, `nodeSelector`/`tolerations`/`affinity`, a test-connection hook,
and startup (30 failures, 1 s period) and liveness (20 s period) probes against `/readyz` and
`/livez` (`charts/py-kms/templates/deployment.yaml:44-60`).

Daemonization went backwards. vlmcsd calls libc `daemon(nochdir=1, noclose=logstdout)` by default on
POSIX (`-D` for foreground), after binding and after the privilege drop (`src/vlmcsd.c:1006-1019`).
Upstream py-kms vendors **Etrigan**, a double-fork daemonizer with start/stop/restart/status/reload,
pidfile handling and a separate daemon log (`py-kms/Etrigan.py:184-467`) — though `reload` is a
literal no-op, `status` is Linux-only (`/proc`), and stop/status unpickle a config from a
world-writable temp dir. The Organization fork deleted Etrigan entirely and now always runs in the
foreground, expecting systemd or Docker.

vlmcsd's Windows service support (`src/ntservice.c:175-305`) is real: `-s` installs
(`SERVICE_AUTO_START`, dependency `tcpip`, `-U user` with `/l` and `/n` shortcuts, `-W password`
`SecureZeroMemory`'d after `CreateService`), `-S` removes, with `StartServiceCtrlDispatcher` and a
stop/shutdown control handler. Two flaws: `ServiceInstaller` `strcat()`s every argv element into a
fixed `MAX_PATH` buffer, and a combined `-W<password>` is not stripped, so it lands in the registry
`ImagePath`. py-kms offers only a pywin32 template in `docs/Getting Started.md:123-166` — which
hardcodes Python 2.7 paths for a Python-3-only project.

`man/vlmcsd-floppy.7` documents a 1.44 MB FAT12 bootable floppy (16 MB RAM;
VMware/VirtualBox/Hyper-V/QEMU) configured entirely through syslinux kernel command-line parameters
(`LISTEN`, `IPV4_CONFIG`, `NTP_SERVER`, `INETD`, `WINDOWS`, `OFFICE2010`, …, `HWID`). It scores
`◐` because only the man page is in the repository; the image and its build scripts are gitignored
and absent.

---

## 14. Build, portability and QA

| Feature | Why it matters | vlmcsd | py-kms (SR) | py-kms (Org) | Notes |
| --- | --- | :---: | :---: | :---: | --- |
| Platform breadth | Where the server can actually run | `●` | `●` | `●` | vlmcsd: 12+ OSes incl. Minix and Hurd; py-kms: wherever CPython runs |
| Endianness and unaligned-access portability | Big-endian and strict-alignment targets | `●` | `●` | `●` | vlmcsd routes every wire field through LE macros |
| Small-footprint / embedded router build | OpenWrt-class hardware | `●` | `○` | `○` | `FEATURES=minimum` + `SMALL_AES` + a 1122-byte database |
| Reference documentation (man pages / docs site) | Operator documentation | `●` | `●` | `●` | Both are maintained and both have real drift |
| CI / automated build pipeline | Machine-verified builds | `○` | `○` | `●` | Neither upstream has a `.github` directory |
| Multi-call / single-binary deployment | Server + client in one executable | `⚙` | `–` | `–` | `vlmcsdmulti`, busybox-style; irrelevant for Python |
| Modern-interpreter / modern-toolchain compatibility | Running today without patches | `◐` | `○` | `●` | **Upstream py-kms does not run on Python 3.10+ at all** |

vlmcsd cross-compiles to Linux, Windows (MinGW and MSVC), Cygwin, macOS/iOS, FreeBSD, NetBSD,
OpenBSD, DragonFly, Solaris/OpenIndiana, Minix, Android and Hurd, sniffing the target from `CC -v`
with per-platform `getExeName`/`getifaddrs`/byteswap paths (`src/GNUmakefile:72-159`,
`src/helpers.c:449-519`). Every wire field goes through `LE16/32/64` macros resolving to compiler
builtins (clang `__has_builtin`, GCC ≥ 4.3, `byteswap.h`, `sys/byteorder.h`, `sys/endian.h`,
`OSByteOrder.h`, MSVC `_byteswap_*`) with a portable byte-at-a-time fallback (`NO_COMPILER_UAA`)
(`src/endian.h:19-292`), and the KMS structs are deliberately kept **unpacked**, with the response
built in a fixed-size struct first to avoid unaligned access on RISC (`src/kms.c:832-838`). One
remaining wart: its internal SHA-256 still does aligned 32-bit loads on caller buffers
(`src/crypto_internal.c:60-62`), which is UB on strict-alignment targets.

`FEATURES=minimum` strips to `SIMPLE_RPC` + `SIMPLE_SOCKETS` + no logging + no ini + no random
ePIDs + `SMALL_AES` (drops the 256-byte inverse S-box for a linear search, `src/crypto.c:218-255`)
+ a 1122-byte internal database, and `README.compile` documents building against Buildroot/OpenWrt
toolchains. Python cannot compete here and should not try.

**Upstream py-kms does not run on Python 3.10 or later.** `pykms_Server.py` imports Etrigan at
module load, and `Etrigan.py:12` does `from collections import Sequence`, removed in 3.10. Also
downstream: `inspect.getargspec` (removed in 3.11), `random.randint(float)` in `epidGenerator`
(`TypeError` from 3.11/3.12, `pykms_PidGenerator.py:62`), `datetime.utcnow`, and `tz.localize` on a
`zoneinfo` object. The Organization fork fixed every one (`pykmsorg py-kms/pykms_PidGenerator.py:66`,
`pykmsorg py-kms/pykms_Base.py:119-138`). vlmcsd scores `◐` for the mirror-image reason: it
compiles, but its OpenSSL backend targets the 1.0 API and will not build against 1.1+/3.x, and its
PolarSSL backend cannot use mbed TLS.

Documentation drift is real on both sides. vlmcsd ships six roff man pages (`vlmcs.1`,
`vlmcsd.7`/`.8`, `vlmcsdmulti.1`, `vlmcsd.ini.5`, `vlmcsd-floppy.7`) with pdf/html/txt targets, but
they document `-h`/`-?`, `-f`, `-w`, `-G`, `-0`, `-3`, `-6` and lowercase `-n`/`-b`, none of which
exist in the server. py-kms uses Sphinx/readthedocs with its own drift: the `-t0` description, the
`-S` megabyte claim and the README's dual-stack claim are all wrong. The Organization fork migrated
to myst-parser, but its GUI removal and WebUI addition are documented nowhere.

---

# Gaps: what nobody implements

Twenty-three of the 119 features are absent from all three implementations. They are not
equally important, so they are grouped by how much the gap actually costs.

## Tier 1 — costs real users something today

### DNS SRV publishing (dynamic DNS registration)

**The single largest deployment-usability gap in the class.** A genuine KMS host performs a dynamic
DNS update at install time creating `_VLMCS._TCP.<domain>` SRV on port 1688; that is the mechanism
by which domain-joined clients activate with **zero per-client configuration**. Every emulator here
requires either `slmgr /skms <host>` on each machine or a hand-created DNS record. vlmcsd has a
complete SRV implementation — `src/dns_srv.c`, with RFC 2782 priority/weight ordering and a bundled
BIND parser — but it is compiled into the **client** only (`src/vlmcs.c:763,771` are its only
callers), and `man/vlmcsd.8` simply directs users to `slmgr /skms`. py-kms has no SRV code at all
server-side; the Organization fork added SRV *resolution* to its test client.

Closing this does not require GSS-TSIG. Emitting a ready-to-paste zone snippet, or shelling to
`nsupdate`, covers most of the value.

### CMID 30-day expiry / count decay

Microsoft's KMS host removes a CMID after 30 days without renewal and **decrements** the reported
count; on renewal the cached CMID is deleted and re-inserted. Nothing in either project has a time
dimension. vlmcsd's `-M1` list only ever grows or round-robins (`src/kms.c:661-715`); py-kms has no
count state at all. This is the missing half of the only feature (`-M1`) that models real host
behaviour, and it is the reason no implementation's persisted records can be used to derive a
genuine count. Closest fork work is OzanHazar's per-SKU quota and MelroyB's `AUTO_PURGE`, neither of
which implements the real semantics.

### Connection rate limiting / DoS throttling

Neither has any per-IP connection or request cap. vlmcsd's `-m` **queues** rather than rejects, so a
set of slowloris connections holds every worker for `-t` seconds each; `man/vlmcsd.8` explicitly
recommends `-m` plus a short `-t` plus `-d` as the *entire* mitigation strategy. py-kms spawns one
unbounded OS thread per connection (`py-kms/pykms_Server.py:37`) with no worker limit and, by
default, **no socket timeout** — the combination is trivially fatal. Both of these services are
routinely exposed to the internet. The only fork prior art is MelroyB's WebUI login rate limiter,
which keys on a spoofable `X-Forwarded-For`.

### Activation history / append-only audit trail

py-kms keeps exactly one mutable row per (CMID, application) with a single `lastRequestTime` and a
monotonic `requestCount`; each request overwrites the timestamp, machine name, SKU, status and ePID
(`pykmsorg py-kms/pykms_Sql.py:74-131`). There is no retention policy, no pruning tool and no aging.
vlmcsd persists nothing. The only chronological record anywhere in the class is the rotating text
log, and only at INFO/DEBUG/MININFO. Any operator asking "what activated last Tuesday" has nothing
to query.

## Tier 2 — correctness, safety and hygiene debt

### Fuzzing harness for the RPC parser

**The highest-value missing QA capability.** vlmcsd's hand-written DCE/RPC parser is C, reachable
pre-authentication, and the audit found a wild-function-pointer call and an out-of-bounds read in
it. py-kms's `Structure` DSL uses `eval()` for pack/unpack codes inside bare `except` blocks
(`py-kms/pykms_Structure.py:221,310`). Neither project has ever fed a malformed PDU at either.

### CSPRNG for IVs, salts and CMIDs

vlmcsd uses libc `rand()` reseeded with `srand(tv_sec ^ tv_usec)` at the start of **every**
connection (`src/helpers.c:343-352`, `src/rpc.c:618`); py-kms uses `random.getrandbits(8)`
(Mersenne Twister) and its one `os.urandom` call is dead code. No activation impact — the keys are
published Microsoft constants — but a rewrite has no reason to inherit it.

### RPC PDU fragmentation and reassembly

Neither honours `PFC_FIRST_FRAG`/`PFC_LAST_FRAG` or MaxXmit/MaxRecvFrag. vlmcsd reads `FragLength`
and always emits single-fragment replies, with the source comment "vlmcsd does not support
fragmented packets (not yet neccassary)" (`src/rpc.c:704-749`). py-kms does one fixed `recv(1024)`
and never inspects the flags. Both work **only** because the largest KMS PDU is ~292 bytes; both
break under any client or middlebox that fragments.

### Structured / machine-readable log output

Both hardcode human format strings with no knob: vlmcsd `'%Y-%m-%d %X: '` plus free text
(`src/output.c:60`), py-kms `'%(asctime)s %(levelname)-8s %(message)s'` with a locale-dependent
`'%a, %d %b %Y'` date (`py-kms/pykms_Misc.py:191-196`). py-kms's MININFO level with its
host/status/product extras is the closest thing to a parseable per-activation record, and it is
still free text.

### Reproducible builds / SBOM / signed release artifacts

vlmcsd bakes `BUILD_TIME=$(date +%s)` into every build (`src/GNUmakefile:161`). Upstream py-kms's
own Dockerfiles `git clone SystemRage/py-kms master` **at build time** rather than COPYing the build
context, so `docker build` produces whatever upstream happens to be at that moment. The
Organization fork fixed the clone (it COPYs `py-kms/`) and stamps `BUILD_COMMIT`/`BUILD_REFERENCE`
into `/VERSION` — the closest anyone gets to provenance, and still not an SBOM or a signature.

### chroot / jail / seccomp / pledge sandboxing

Grep-confirmed absent from both. vlmcsd calls `daemon(nochdir=1, ...)` so it does not even `chdir`
to `/`, and its log and pid files are created with the inherited umask. Isolation must come entirely
from the supervisor.

### systemd unit / init script shipped in-tree, and OS packages

vlmcsd's unit lives in the empty `debian/` submodule; `-DNO_PID_FILE` exists specifically for init
systems that do not need a pidfile, which shows the intent. py-kms's systemd unit and Upstart conf
are copy-paste snippets in `docs/Getting Started.md:80-121` only, and the Upstart one is explicitly
labelled deprecated. py-kms has no `setup.py`, no `pyproject.toml`, no `MANIFEST.in` — only
PyInstaller boilerplate in `.gitignore` that is never exercised. Multiple forks add both, so the
work is small.

### Native systemd socket activation (`sd_listen_fds` / `LISTEN_FDS`)

Neither links libsystemd or reads `LISTEN_FDS`/`LISTEN_PID`. vlmcsd works under systemd only via the
inetd convention (`Accept=yes` + `StandardInput=socket`), which means **one process per connection**
and therefore breaks `-M1` and silently degrades `-r1` to `-r2` behaviour — the stable-ePID property
is lost. launchd sockets are likewise unsupported.

## Tier 3 — would matter at scale, nobody is there yet

### High availability: shared client-count state across instances

vlmcsd's CMID list lives in a per-process SysV shm segment or heap and is destroyed on restart;
the man page notes only that a restart resets it. py-kms has no count state, and its SQLite file is
single-node with no locking discipline (a TOCTOU SELECT-then-INSERT under `ThreadingMixIn`). A
load-balanced pair cannot report a consistent count.

### KMS host chaining / upstream forwarding / proxy mode

`vlmcs -G` is the closest thing — it harvests a genuine ePID once, offline — but there is no
request-time forwarding, no caching proxy and no fallback-to-upstream anywhere. This would be the
natural way to obtain perfectly genuine ePID/HwId pairs without synthesizing them.

### Multi-tenancy (per-listener or per-client-network identity)

vlmcsd's ePID varies by product family, never by listener or peer (`src/kms.c:464-513`). Nothing in
either project associates configuration with a listening socket or a client subnet.

### Per-client or per-product activation quota, and client allowlists

vlmcsd's `-K` is product-level, not client-level. The only prior art is forks: OzanHazar's per-skuId
limit (whose quota logic has three unconditional `NameError` paths), GuillaumeDescombes's DB
allowlist (which applies **only to protocol V5**, so V6 bypasses it entirely) and KptCheeseWhiz's
hostname allowlist (which matches on the client-supplied `WorkstationName` — trivially spoofable).

### Prometheus / statsd metrics endpoint

Grep for `prometheus`/`/metrics` finds nothing in either tree. The one fork attempt,
`Neon-Cyber-Crutches/py-kms-metrics`, is architecturally broken: the exporter runs in the
`docker/start.py` parent while every `record_kms_*` call lives in the `pykms_Server.py` child, so
the two processes have independent registries and the exported counters are always zero.

## Tier 4 — correctly out of scope, or unreachable in practice

### Active Directory-Based Activation (ADBA)

A different Microsoft volume-activation mechanism using the same CSVLK: clients query activation
objects in the AD schema over LDAP, eliminating the SRV record, the dedicated port and the
activation threshold entirely. Microsoft increasingly prefers it in domain environments. It is
genuinely out of scope for a KMS RPC emulator, but it belongs in the feature universe of "volume
activation server", and its existence caps how much a perfect KMS emulator is worth.

### RPC authentication (sec_trailer / SPNEGO / NTLM)

Real KMS clients do not authenticate, so this is unreachable in practice. vlmcsd always writes
`AuthLength = 0` (`src/rpc.c:602`) and never acts on an inbound one — under `_PEDANTIC && !NO_LOG`
it is read and logged as "Fatal: RPC response requests authentication" (`src/rpc.c:723`), but
`rpcServer()` discards that status and services the PDU anyway (`src/rpc.c:627`). Under MSRPC it
registers `RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH`.
py-kms defines `SEC_TRAILER` and every `RPC_C_AUTHN_*` constant and references none of them — but it
*does* blindly echo `auth_len` into a bind_ack that contains no trailer, which is a malformed packet
and worth fixing regardless.

### Constant-time cipher implementation

vlmcsd's internal AES uses 32-bit Galois-multiply macros and S-box table lookups; py-kms's
`galois_multiplication` branches on `a & 0x80`. Not exploitable here — both KMS keys are published
constants — but it means neither implementation's primitives are reusable for anything with a real
secret. A rewrite gets this for free by using a maintained AES library.

### Windows Event Log integration

vlmcsd's `ServiceReportEvent` (`RegisterEventSource`/`ReportEvent`) is entirely commented out
(`src/ntservice.c:93-120`), with the consequence that a Windows service started without `-l`
produces **no output at all**: `vlogger` returns immediately when `fn_log` is NULL and `IsNTService`
suppresses the stdout path (`src/output.c:26-33`). py-kms has no Windows service story to integrate
with.

---

# Mismatches: where implementations disagree

Twenty-four situations where the implementations behave differently and one of them is more faithful
to a genuine Microsoft KMS host. MM20 is included deliberately as a *non*-mismatch, and MM18 and
MM22 are cases where **none** of them is right.

| ID | Situation | More faithful | Practical consequence of getting it wrong |
| --- | --- | --- | --- |
| MM01 | Two identical requests on one TCP connection | vlmcsd | py-kms returns two different ePIDs — the canonical detection test |
| MM02 | Synthesizing an ePID for an Office 2010 client | vlmcsd | py-kms advertises a Server 2019 CSVLK group ~98% of the time |
| MM03 | Client sends `N_Policy = 25`, no override configured | vlmcsd `-M1` | Both default to arithmetic; only `-M1` models distinct machines |
| MM04 | Request with `versionMajor = 7` | vlmcsd | py-kms's error path crashes; client gets a silent RST |
| MM05 | After answering one activation | vlmcsd | py-kms always disconnects — an observable RPC violation |
| MM06 | Win8+ client offers NDR64, then `alter_context` | vlmcsd | py-kms rejects NDR64 and closes on `alter_context` |
| MM07 | Any client reads `AssocGroup` from the bind_ack | vlmcsd | py-kms returns `0x1063BF3F` worldwide — a passive fingerprint |
| MM08 | Unrecognised transfer syntax or different BTFN bits | vlmcsd | py-kms `KeyError`s and drops instead of NACKing the item |
| MM09 | ClientTime six hours from server time | vlmcsd `-c1` | Both accept by default; only vlmcsd can be made to refuse |
| MM10 | A KMS v4 client activates | vlmcsd | py-kms `time.sleep(1)` — timing fingerprint + throughput cap |
| MM11 | GUID not in the shipped database | vlmcsd **and** Org (tie) | Upstream py-kms raises `UnboundLocalError` and drops silently |
| MM12 | Two clients connect concurrently | vlmcsd | py-kms's peer address is a process-global; Org persists the race |
| MM13 | Default listening address and family | vlmcsd | Upstream py-kms is IPv4-only despite a README claiming otherwise |
| MM14 | Client connects and sends nothing | vlmcsd | py-kms blocks in `recv()` forever with no worker cap |
| MM15 | Default HwId in every v6 response | **py-kms (Org)** | Both fixed constants are published cross-deployment fingerprints |
| MM16 | Several listeners; client binds on the second | vlmcsd | py-kms advertises the primary port regardless |
| MM17 | Unusual `PacketFlags` / big-endian representation | **py-kms (both)** | vlmcsd mirrors arbitrary client flags back |
| MM18 | Declared v6 length exceeds what was received | **neither** | vlmcsd reads uninitialised stack; py-kms raises silently |
| MM19 | Operator asks which machines have activated | **py-kms (Org)** | vlmcsd persists nothing; nobody has real history |
| MM20 | Activation / renewal intervals reported | *all three agree* | (Non-mismatch, included for completeness) |
| MM21 | Client sends `N_Policy = 5000` | vlmcsd | py-kms reflects a count of 10000 back unchallenged |
| MM22 | Pointing a whole subnet at the server | **neither** | Manual `slmgr /skms` or a hand-made DNS record, always |
| MM23 | Activating a product flagged `IsRetail`/`IsPreview` | vlmcsd | py-kms carries the data and never reads it |
| MM24 | Zero-configuration startup, then a Win10 client | vlmcsd | See below — all three defaults are detectable |

Verdict tally: vlmcsd is more faithful in 17, py-kms in 3 (MM15, MM17, MM19), they tie in 1 (MM11),
agree in 1 (MM20), and neither is right in 2 (MM18, MM22).

## The identity mismatches

### MM01 — ePID stability

**Situation:** two byte-identical activation requests sent over one TCP connection.
**vlmcsd:** returns the **same** ePID both times. `-r1` (default) synthesizes one ePID per CSVLK at
process start and reuses it; `-r0` uses the database default; only `-r2` regenerates per request
(`src/kms.c:361-406`).
**py-kms (both):** returns a **different** ePID each time — `createKmsResponse` calls
`epidGenerator()` on every response with an unseeded global `random` (`py-kms/pykms_Base.py:221-225`).
**More faithful:** vlmcsd.
**Why:** a genuine KMS host has one ePID derived from its installed CSVLK and never varies it.
`man/vlmcsd.8:192-208` names this exact test as the canonical emulator-detection vector; `-r1`
exists solely to defeat it.
**Consequence:** py-kms fails the easiest possible detection probe unconditionally, unless the
operator supplies a fixed `-e`. Two requests, one connection, compare the strings.

### MM02 — CSVLK selection bias

**Situation:** an Office 2010 client (KMS ID `e85af946-…`) requests activation.
**vlmcsd:** maps `KMSID -> EPidIndex -> CsvlkData[1]`, emitting GroupId 96 with the Office 2010 key
range 199000000-217999999 (`src/kms.c:266-358`).
**py-kms (both):** emits the Windows Server 2019 fallback GroupId 206 / range 551000000-570999999
about **98%** of the time (measured 4887 of 5000). `pykms_PidGenerator.py:20-32` appends that
fallback tuple to the candidate list for every *non*-matching `CsvlkItem`, then `random.choice`s
over all 49 (47 on `pykmsorg/main`). The Organization fork added only an `except KeyError: pass`;
the bias is unfixed.
**More faithful:** vlmcsd.
**Why:** the GroupId and key-ID range in an ePID identify the CSVLK actually installed for that
product family.
**Consequence:** py-kms routinely advertises a Server 2019 group for Office 2010, Vista and
Windows 7, and can emit impossible combinations such as GroupId `00096` with BuildNumber 17763.
This is a loop bug, not a design choice, and it is a one-line fix.

### MM15 — default hardware ID

**Situation:** the HwId returned in every v6 response.
**vlmcsd:** the compile-time constant `3A 1C 04 96 00 B6 00 76`, commented "HwId from the Ratiborus
VM" (`src/config.h:35-37`). Runtime override is per-CSVLK only, and only when an explicit ePID is
also set (`src/kms.c:490-500`).
**py-kms (SR):** the fixed constant `364F463A8863D35F`; `-w RANDOM` exists but is not the default.
**py-kms (Org):** `-w` defaults to `RANDOM`, so each instance generates its own at startup
(verified at `pykmsorg py-kms/pykms_Server.py:205-207`).
**More faithful:** py-kms (Organization) — one of only three rows where py-kms wins.
**Why:** both fixed constants are static cross-deployment fingerprints, and both are widely
published.
**Consequence:** a random HwId is at least internally consistent and not shared, but it is still not
a value a real KMS host would produce. The genuinely correct answer is neither: harvest a real HwId
from a licensed host with `vlmcs -G` and pin it.

## The RPC mismatches

### MM07 — association group

`response['assoc_group'] = 0x1063bf3f` (`py-kms/pykms_RpcBind.py:104`, verbatim on `pykmsorg/main`).
vlmcsd draws a random 32-bit value once per process and increments it per accepted connection
(`src/network.c:1014,1053`). An association group id identifies a group of related connections in a
real RPC runtime and is never a global constant. **This is the single most reliable passive network
fingerprint for py-kms and requires no active probing at all** — one bind_ack identifies the
software.

### MM05 — connection lifetime

vlmcsd keeps the association open by default; `-d` makes it disconnect, and `man/vlmcsd.8:126-130`
calls that "a direct violation of DCE RPC" while explicitly noting that py-kms behaves that way.
py-kms unconditionally breaks out of the handler loop after a request PDU
(`py-kms/pykms_Server.py:621`; `pykmsorg py-kms/pykms_Server.py:526`). Windows KMS hosts hold the
association open. This is also what makes vlmcsd's own client print "Warning: Server closed RPC
connection (probably non-multitasked KMS emulator)". py-kms's behaviour is a DoS mitigation bought
with authenticity — a reasonable trade given it has *no other* DoS mitigation, but it should be a
flag, not a hardcode.

### MM06 — NDR64 and `alter_context`

vlmcsd ACKs NDR64 and NACKs the NDR32 item (matching Microsoft, which accepts exactly one transfer
syntax), then services the follow-up `alter_context` with an `alter_context_ack`
(`src/rpc.c:475-534, 585-587`). py-kms hardcodes a provider rejection for NDR64 (result 2, reason 2)
so clients fall back to NDR32, then treats PDU type 14 as "Invalid RPC request type 14" and closes.
The NDR64 rejection masks the `alter_context` defect in normal operation, but a client that sends
one for any other reason is disconnected. vlmcsd additionally **couples** the NDR64 setting to the
host build claimed in the ePID (`src/kms.c:285-302`), so the two stories agree; py-kms has no such
coupling — it rejects NDR64 unconditionally while its ePID build number is drawn independently.
(In practice neither py-kms version can claim a post-9600 NDR64-era build anyway: SR's database
stops at 17763 and the Organization fork's generator is pinned to 17763 by the `WinBuildIndex`
defect above. The inconsistency is latent, not observable.)

### MM08 — bind item rejection

vlmcsd NACKs the offending ctx item with `AckResult 2` and a specific reason and still returns a
valid bind_ack (`src/rpc.c:475-552`). py-kms's `preparedResponses[ts_uuid]` is a bare dict index —
`KeyError`, swallowed by `handle_error`, connection dropped with no bind_ack, no bind_nak and no log
line. Per-context-item NACK is exactly what DCE RPC specifies and what Windows does. py-kms's BTFN
matching is separately over-strict, demanding an exact GUID rather than matching the first 8 bytes
and echoing the granted bit subset.

### MM16 — secondary address

vlmcsd derives bind_ack `SecondaryAddr` from `getsockname()` + `getnameinfo(NI_NUMERICSERV)` on the
**accepting** socket (`src/rpc.c:432-465`). py-kms uses `str(srv_config['port'])` — the primary
port — regardless of which listener accepted, and its `frag_len` is the constant
`36 + ctx_num * 24`, correct only for a 2-to-6 digit port (verified at
`py-kms/pykms_RpcBind.py:98,106`). The secondary address is meant to tell the client where the
endpoint actually lives, which matters behind a port-forwarder or with multiple `-n` listeners; a
single-digit port produces a 32-byte packet advertised as 36.

### MM17 — response header construction (py-kms wins)

vlmcsd `memcpy`s the **whole** request header into the response and overwrites only `PacketType` and
`FragLength` (`src/rpc.c:667-687`), so `PacketFlags`, `DataRepresentation` and `CallId` are echoed
verbatim — it would happily reflect `RPC_PF_CANCEL_PENDING` back and answer a big-endian client with
little-endian data. py-kms hardcodes response flags to `firstFrag|lastFrag` and constructs the
header fresh, echoing only ver/representation/call_id/ctx_id (`py-kms/pykms_RpcRequest.py:25`).
**py-kms is closer to Microsoft here.** A real server always sets FIRST|LAST and its own data
representation on a response. Note the reverse holds for FAULT PDUs: vlmcsd's `SendError()` goes
through `createRpcHeader` and therefore always carries the static `CallId` 2 instead of the
request's (`src/rpc.c:74, 670-674`) — trivially fingerprintable. Neither gets header handling fully
right.

### MM18 — length validation (neither is right)

**Situation:** a request declares 260-byte v6 KMS data (`sizeof(REQUEST_V6)`) but the RPC stub
carries only part of it.
**vlmcsd:** `checkRpcRequestSize` uses `>=` rather than `==` — deliberately, "to support buggy RPC
clients (e.g. wine)" — and compares the whole stub length, which *includes* the 16-byte
`RPC_REQUEST` prologue, against the bare KMS payload *minimum*
(`src/rpc.c:189,226`, `src/kms.h:174-178`). The binding floor is therefore
`252 + 16 = 268` bytes, while `CreateResponseV6` decrypts `V6_DECRYPT_SIZE` = 256 bytes from stub
offset 20 and so needs 276. A v6 request of **268-275 bytes** (NDR32) or **276-283** (NDR64) passes
both checks, **reading up to 8 bytes of uninitialised stack**.
**py-kms (both):** no length check at all; a single `recv(1024)` goes straight to the `Structure`
parser, which raises `struct.error` on short data — swallowed silently upstream, logged by the
Organization fork.
**More faithful:** neither. The correct behaviour is to validate that the received stub length
**exactly** matches the declared version's fixed request size and return an RPC fault or
`0x8007000D` otherwise.
**Consequence:** vlmcsd's laxity is a memory-disclosure bug in C; py-kms's is an unhandled exception.
This is the clearest single case where a rewrite should be **stricter than both**.

## The policy mismatches

### MM03 — client count

**vlmcsd `-M0` (default):** `Count = max(2 * N_Policy, MinActiveClients)`, purely arithmetic.
**vlmcsd `-M1`:** a count derived from a real per-application CMID table pre-charged with 24 random
GUIDs, so the first genuine client sees exactly 25 and each new distinct CMID increments it
(`src/kms.c:245-260, 661-723`).
**py-kms (both):** `currentClientCount = 2 * N_Policy` with no state; `-c` clamps into
`[N+1, 2N]` with a genuineness warning (`py-kms/pykms_Base.py:136-159`).
**More faithful:** vlmcsd with `-M1` — and *only* with `-M1`. A real KMS host caches twice the
threshold in CMIDs (50 for client SKUs, 10 for server and Office), so the count it reports is a
function of **distinct machines seen**, not of the asking client's own field.
**Consequence:** a single machine can activate against either emulator's default, where a genuine
host would refuse until 25 distinct CMIDs had registered. Note that vlmcsd's *default* takes exactly
py-kms's shortcut, so out of the box the two agree — the mismatch is between py-kms and a vlmcsd
that has been configured, not between the projects as shipped.

### MM21 — overcharge

`N_Policy = 5000` → vlmcsd computes `required_clients = 10000 > 2000` and rejects with `0x8007000D`,
logging "Rejecting request with more than 1000 minimum clients" (`src/kms.c:592-606`). py-kms
accepts and reports `currentClientCount = 10000`. vlmcsd is deliberately bug-compatible with a real
KMS host here, whose documented failure mode is that an overcharge request of ≥376 required clients
followed by 671 activations **permanently poisons** the CMID table (`man/vlmcsd.8:243-252`).
Reflecting an absurd count back unchallenged is neither realistic nor safe.

### MM23 — retail and preview SKUs

With `-K2`/`-K3` vlmcsd refuses with `0xC004F042`; its shipped database flags 3 retail and 3 preview
KMS IDs. Default `-K0` activates. py-kms **always** activates: `IsRetail`, `IsPreview` and
`CanMapToDefaultCsvlk` are parsed into the runtime dicts by `kmsDB2Dict()` and read by zero lines of
Python. A genuine KMS host cannot activate a retail SKU at all — the client would never have a GVLK
for one. py-kms carries the data needed to model this and never consults it. That said, both default
to permissive, which is the right default for a program whose purpose is to say yes.

### MM09 — clock skew

vlmcsd `-c1` rejects with `0xC004F06C` ("the time stamp differs too much from the KMS server time");
default `-c0` accepts (`src/kms.c:608-620`). py-kms always accepts — the rule is a literal
`# rule: timeserver - 4h <= timeclient <= timeserver + 4h, check if is satisfied (TODO)` comment at
`py-kms/pykms_Base.py:228` and the server never reads its own clock. Because the v6 HMAC key is
derived from the **client-supplied** FILETIME, a badly skewed client still receives a
self-consistent response. Microsoft's tolerance is ±4 hours, and enforcing it is a documented
anti-detection measure: a probing client can send two requests more than four hours apart and
conclude the server is an emulator if both succeed. Both are wrong by default; only vlmcsd can be
made right.

### MM11 — unknown products (a tie)

vlmcsd's `getProductIndex` returns -1, the name resolves to "Unknown", `ePidIndex`/`appIndex` fall
back to 0 (Windows), and the client **activates** (`src/kms.c:46-63, 644-649`); `-K1`/`-K3` opts
into refusal. Upstream py-kms raises `UnboundLocalError` and drops the connection with nothing
logged. The Organization fork pre-seeds `appName, skuName = str(applicationId), str(skuId)`
(`pykmsorg py-kms/pykms_Base.py:167`), so unknown products log by raw GUID and activate.
**vlmcsd and the Organization fork tie.** Graceful degradation is the right default for an emulator
whose database will always lag Microsoft's releases — it is why a 2019-era vlmcsd still activates
Windows 11 — and upstream py-kms turning an unknown GUID into a silent crash is the worst of the
three. It is precisely the failure users reported as "Server 2022 doesn't work". vlmcsd
additionally offers `-K` to opt *into* strictness, which py-kms cannot.

### MM04 — unsupported protocol version

vlmcsd logs "Fatal: KMSv%hu.%hu unsupported" and returns `0x8007000D`
(`HRESULT_FROM_WIN32(ERROR_INVALID_DATA)`, commented "// Invalid Data") in a well-formed RPC
response (`src/rpc.c:281`). py-kms builds the correct `0xC004F042` envelope and
then raises `UnicodeDecodeError` on `finalResponse.decode('utf-8')` — bytes `42 F0 04 C0` are not
valid UTF-8. Upstream swallows it in `handle_error`; the Organization fork at least logs the
traceback. A real KMS host answers with an HRESULT; dropping the TCP connection is both wrong and a
fingerprint. vlmcsd's choice of error code is also better: `0xC004F042` means "the specified KMS
cannot be used", which describes a product mismatch, not an unparseable protocol version.

## The operational mismatches

### MM10 — the one-second sleep

`py-kms/pykms_RequestV4.py:54` contains `time.sleep(1) # request sent back too quick for Windows
2008 R2, slow it down.` (verified present verbatim on `pykmsorg/main`). vlmcsd answers as fast as it
can compute the CBC-MAC — single-digit milliseconds. A real KMS host answers in milliseconds, so a
**deterministic one-second floor** on every v4 response is both a timing fingerprint and a
per-thread throughput cap. If the underlying Windows 2008 R2 problem is real, it should be fixed at
its cause, not papered over with a fixed sleep in the hot path.

### MM14 — idle connections

vlmcsd's `SO_RCVTIMEO` fires after `ServerTimeout`, **default 30 seconds** (verified,
`src/shared_globals.c:57`). py-kms's `-t1/--timeout-sndrcv` defaults to `None`, so the thread blocks
in `recv()` forever (verified, `pykmsorg py-kms/pykms_Server.py` option table). There is no worker
cap either. An unauthenticated internet-facing service must bound how long a peer can hold a worker.
vlmcsd pairs its 30-second default with `-m` and `-d` as an explicitly documented DoS posture;
py-kms's combination of no timeout, no worker limit, and one unbounded thread per connection makes a
trivial slowloris fatal.

### MM12 — the per-request state race

vlmcsd serves each client in its own forked process (or thread) with the peer address as a local
(`src/network.c:805-828`). py-kms's `kmsServerHandler.setup()` stores the peer in the
**process-global** `srv_config['raddr']`, read later when emitting the MININFO record — under
`ThreadingMixIn` a second connection can overwrite it first. The Organization fork made the
consequence worse by making that racy value the source of the persisted `lastRequestIP` column. Per-
request state must not live in shared mutable configuration. MelroyB's fork shows the correct fix:
`srv_config.copy()` per packet.

### MM13 — default bind address

vlmcsd binds **both** `::` (`IPV6_V6ONLY=1`) and `0.0.0.0` as separate sockets, each guarded by a
stack-existence probe. Upstream py-kms is `0.0.0.0` only, with `connect -d` a `store_true` defaulting
**off** and `IPV6_V6ONLY=1` explicitly set when it is not passed — so the README claim that "a
dual-stack socket is created when using a IPv6 address" is false by default. The Organization fork
switched to `::` with dual-stack on by default. vlmcsd's two-socket approach is more portable: it
serves both families with no dependency on the platform supporting `IPV6_V6ONLY=0`, which OpenBSD's
kernel refuses outright. The Organization fork's change is a clear improvement on upstream but
silently changes the default bind address, and its fallback path triggers only on one exact
exception string.

### MM19 — fleet visibility (py-kms wins)

vlmcsd persists nothing; with `-M1` an in-memory CMID table exists but is unreadable from outside
the process and dies on restart. Upstream py-kms writes one mutable SQLite row per
(CMID, application) but has **no in-tree way to read it back** — the documented port-8080 viewer is
an externally `git clone`d third-party `sqlite-web`, and PID 1 in that container is `sqlite_web`
rather than the KMS server, so the container stays "healthy" after the server dies. The Organization
fork's `/clients` page (`sql_get_all`) is the first in-tree reader, alongside `lastRequestIP`, a
schema-version/migration table and a proper `PRIMARY KEY`. **py-kms (Organization) wins** — fleet
visibility is a legitimate operational requirement and only py-kms addresses it. All three still
fall short of a real audit trail (see Tier 1 gaps).

### MM20 — activation and renewal intervals (a genuine agreement)

Included deliberately as a **non**-mismatch. vlmcsd: `VLActivationInterval` 120 minutes,
`VLRenewalInterval` 10080 minutes (7 days), configurable with `-A`/`-R` using a number plus an
optional `s`/`m`/`h`/`d`/`w` suffix (verified, `src/shared_globals.c:11-12`, `src/helpers.c:233-259`).
py-kms: identical values (`120` and `1440*7`), configurable with `-a`/`-r` as plain minutes
(verified, `pykmsorg py-kms/pykms_Server.py` option table). Both match Microsoft's documented
defaults exactly. The only differences are cosmetic — vlmcsd's suffix syntax has per-minute
granularity, so any value under 60 seconds evaluates to 0 and is rejected — and neither validates
the range: a negative `-a` in py-kms reaches a `'<I'` pack and raises `struct.error`. Modern clients
(Windows 8.1+) ignore these values anyway, which `man/vlmcsd.8` notes.

### MM22 — client-side discovery (nobody is right)

**Situation:** an operator wants to point a whole subnet at the server without touching every client.
**All three:** not possible from the server. vlmcsd's `dns_srv.c` is compiled into the **client**
only; py-kms upstream has no SRV code; the Organization fork's *client* can now resolve
`_vlmcs._tcp` via `-D/--discovery`.
**More faithful:** none of them. A genuine KMS host performs a dynamic DNS update creating
`_VLMCS._TCP` on port 1688 at install time; that is how domain clients activate with zero
configuration.
**Consequence:** every emulator in this class requires manual `slmgr /skms` on each client or a
hand-created DNS record. See Tier 1 gaps.

### MM24 — the zero-configuration posture

The composite mismatch: what each looks like with **no options at all**, and a Windows 10 client
activating.

| | vlmcsd | py-kms (SR) | py-kms (Org) |
| --- | --- | --- | --- |
| Listen | `::` + `0.0.0.0`:1688 (two sockets) | `0.0.0.0`:1688, IPv4 only | `::`:1688 dual-stack |
| Connection after activation | held open | **closed** | **closed** |
| Socket timeout | 30 s | **none** | **none** |
| Worker cap | none | none | none |
| ePID | one per CSVLK, held for process lifetime | **fresh per request**, ~98% wrong CSVLK | **fresh per request**, same bias |
| HwId | Ratiborus constant | `364F463A8863D35F` | **random per start** |
| Reported count | 50 | 50 | 50 |
| Product gate | activates anything | activates anything | activates anything |
| Logging | **nothing** (`fn_log` is NULL) | ERROR to `./pykms_logserver.log` | WARNING |
| Surprise | — | may open a **Tkinter window** if stdout is not a tty | — |

**More faithful:** vlmcsd, on the three things that matter. The postures differ most in the two
properties that determine authenticity — ePID stability and connection lifetime — and in the one
that determines availability, the socket timeout, and vlmcsd wins all three. The counts agree only
because vlmcsd's `-M0` default takes exactly py-kms's shortcut. Two observations worth keeping:
**all three** default to logging essentially nothing useful, and **none of the three** would survive
an adversarial detection probe without being reconfigured.

---

# Fork-only capabilities

Features that exist in no upstream and no active successor, only in a fork. See
[vlmcsd-forks.md](./vlmcsd-forks.md) and [py-kms-forks.md](./py-kms-forks.md) for full treatment.
Almost every one of these is flawed in a way worth knowing before copying it.

| Capability | Fork(s) | State of the implementation |
| --- | --- | --- |
| Post-2019 product data for vlmcsd | `kotfenix/vlmcsd`, `redneckdba/vlmcsd` (Win11 24H2 / Server 2025 / Office LTSC 2024 `.kmd`); `kankerdev`+`alexax66/vlmcsd` (Office LTSC 2021 / Server 2022) | Data-only; the mainstream way to keep an archived vlmcsd current |
| GVLK key list for vlmcsd | `redneckdba/vlmcsd`, `yammelvin/vlmcsd` | Plain-text `keys`/`windows-keys.md` files |
| Per-product activation quota | `OzanHazar/py-kms` | `activations` + `config` SQLite tables, per-`skuId` limit — **three unconditional `NameError` paths**, broken indentation |
| Client allowlist / authorization gate | `GuillaumeDescombes/py-kms`; `KptCheeseWhiz/vlmcsd` | GuillaumeDescombes gates **protocol V5 only** — V6 bypasses it entirely. KptCheeseWhiz matches the client-supplied `WorkstationName`, trivially spoofable |
| Source-IP CIDR access control | `KptCheeseWhiz/vlmcsd` (`-Y` CIDR list); `MelroyB/py-kms` (persistent blacklist file enforced in the TCP handler) | The only real allow/deny lists in the class |
| CMID auto-purge | `MelroyB/py-kms` (`AUTO_PURGE`) | Not the real 30-day decay semantics, but the only aging anywhere |
| Prometheus metrics | `Neon-Cyber-Crutches/py-kms-metrics` | `kms_requests_total`, `kms_activations_total`, `kms_errors_total`, `kms_request_duration_seconds` — **exporter and recorders live in different processes; counters are always zero** |
| WebUI hardening and features | `MelroyB/py-kms` (login, CSRF, rate limiting, GeoIP, pagination, Docker self-update); `konk22/py-kms` (activation Instructions page, GVLK copy-to-clipboard) | MelroyB's rate limiter keys on a spoofable `X-Forwarded-For` |
| Per-request config isolation | `MelroyB/py-kms` | `srv_config.copy()` per packet — the correct fix for the MM12 race |
| YAML configuration file for py-kms | `radawson/py-kms-1` | Three-path search with CLI override; the only config file in the Python line |
| pytest suite | `Hamad3bdulla/py-kms` | 3 of its 4 headline modules are **never imported by the running server** |
| systemd / rc.d / installer units | `redneckdba`, `lizhizhuanshu`, `simaek`, `alexax66` (FreeBSD rc.d), `gilberth` (Ubuntu installer), `radawson` (systemd + OpenWrt + Ubuntu) | Straightforward; shows how small the upstream gap is |
| OS packaging | `simaek/vlmcsd` (RPM spec); `zeevro/py-kms` (hatchling src-layout with `pykms-server`/`pykms-client` console entry points) | Both clean |
| `vlmcs -x` SKU counter fix | `kotfenix/vlmcsd` | `uint8_t` → `uint16_t`, so a >255-SKU database renders |

The pattern is consistent: forks add operational and policy features that upstreams declined, and
almost none of them are correct. Treat this table as a list of *ideas that have been tried*, not of
code to vendor.

---

# Implications for a new implementation

Grounded strictly in the findings above.

**1. Be stricter than both on parsing, and never trust a declared length.** MM18 is the one place
where both implementations are wrong in opposite directions. Validate that the received stub length
**exactly** matches the declared version's fixed request size; validate `versionMinor`; bound
`FragLength` before allocating; return `0x8007000D` or an RPC fault rather than dropping the
connection. vlmcsd's `>=` cost it a memory disclosure and a wild function-pointer call; py-kms's
absent checks cost it a silent RST on every malformed input. Neither failure mode is acceptable.

**2. Get identity right, because it is free and it is what gets emulators detected.** One ePID per
CSVLK per process lifetime (MM01). Product-correct CSVLK selection (MM02) — this is a loop bug in
py-kms, not a hard problem. Per-connection association group (MM07). No `time.sleep(1)` (MM10). No
constant HwId (MM15). Keep the association open (MM05). Couple the claimed host build to the RPC
features actually offered (vlmcsd is the only implementation that does this). None of these cost
performance or complexity; all of them are currently wrong somewhere.

**3. Implement `alter_context`, NDR64 and per-item bind NACKs.** These are the three RPC features
that separate "activates a compliant client" from "behaves like an RPC server". vlmcsd shows they
are not hard. py-kms's `KeyError` on an unexpected transfer syntax (MM08) is the failure mode to
avoid.

**4. Model host state, or be honest that you are not.** `-M1`-style CMID tracking with **30-day
expiry and decay** is the only way the reported count means anything, and the expiry half exists
nowhere (Tier 1 gap). If a rewrite implements CMID tracking, it should implement the aging too —
otherwise it is vlmcsd's `-M0` arithmetic with extra steps. If it does not implement tracking, it
should at least keep py-kms's clamping-with-a-warning guard, which vlmcsd lacks.

**5. Publish the SRV record.** This is the highest-value missing feature for real deployment
(Tier 1, MM22) and does not require GSS-TSIG to be useful: shelling to `nsupdate`, or emitting a
ready-to-paste zone snippet at startup, captures most of the benefit. Every client-side `slmgr
/skms` invocation in the world exists because no emulator does this.

**6. Bound the untrusted side of the socket.** A read/write timeout with a **non-None default**
(MM14), a worker cap that **rejects** rather than queues, and per-IP rate limiting (Tier 1 gap).
This class of software is routinely internet-facing and neither implementation is currently safe
there.

**7. Keep per-request state per-request.** py-kms's process-global `srv_config['raddr']` (MM12) is a
concurrency bug the Organization fork made worse by persisting its output. This is a structural
choice a rewrite makes once, at the beginning.

**8. Persist an append-only activation history, not a mutable snapshot.** py-kms's one-row-per-
machine table (MM19) cannot answer any question about the past, and its absence of retention or
aging is also why it cannot derive a count. An event log with a retention policy solves fleet
visibility and CMID decay with the same data structure.

**9. Ship the product database as a real, swappable, path-overridable file, parsed once.** vlmcsd's
`-j` is right; py-kms's hardcoded path and per-request re-parse (~4 ms per activation) are wrong.
Include GVLKs — py-kms is right that users need them even though the protocol never carries them.
Degrade gracefully on unknown GUIDs by default, with an opt-in strict mode (MM11, `-K`).

**10. Ship deployment artifacts.** A container image, a systemd unit, and a package — all three are
Tier 1/2 gaps or fork-only, and none is technically difficult. Health endpoints should probe the
**KMS listener**, not just an HTTP process, which is the flaw in the Organization fork's `/readyz`.

**11. Do not reimplement AES.** vlmcsd's hand-rolled cipher, py-kms's SlowAES fork with per-block
key scheduling, vlmcsd's OpenSSL-internals poking — all three are avoidable. Use a maintained
library, use a CSPRNG (Tier 2 gap), and validate padding.

**12. Fuzz the PDU parser.** It is the highest-value missing QA capability in the class (Tier 2), it
is the code path that eats pre-authentication attacker bytes, and neither project has ever done it.

Two things to explicitly *not* prioritize: ADBA, which is a different protocol family and genuinely
out of scope, and RPC authentication, which real KMS clients never use. And one thing to note as a
non-goal rather than a gap: vlmcsd's compile-time feature stripping and multi-call binary exist for
OpenWrt-class targets, and are the reason 21 of its 119 rows are `⚙` rather than `●`. A rewrite
that does not target routers should not inherit that configuration surface — but it should be
explicit that it is choosing not to, because "vlmcsd has feature X" is a statement about a
particular build: for roughly half of those rows the feature is a plain CLI flag in the stock
`FEATURES=full` binary that a stripped build removes, and for the other half it exists only if you
set a non-default `make` variable in the first place.

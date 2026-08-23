# vlmcsd — Complete Feature Reference

**Subject:** Wind4/vlmcsd, master `70e0357` (2023-07-28, 31 commits, repository archived).
All citations are relative to the repository root.

---

## 1. What vlmcsd is

vlmcsd is a KMS (Key Management Service) emulator: a server that speaks Microsoft's Software
Protection Platform activation protocol over DCE/RPC and issues activation grants to Windows and
Office volume-license clients. It ships four link targets built from one shared source pool:

| Target | Source entry | Purpose |
|---|---|---|
| `vlmcsd` | `src/vlmcsd.c` | The KMS server / emulator |
| `vlmcs` | `src/vlmcs.c` | KMS test, charging and emulator-debugging client |
| `vlmcsdmulti` | `src/vlmcsdmulti.c` | Busybox-style multi-call binary containing both |
| `libkms` | `src/libkms.c` | Shared (`.so`/`.dylib`/`.dll`) + static (`.a`) embedding library |

### Provenance

The project originated as Hotbird64's SVN project (the man pages are still authored
"Hotbird64" — `man/vlmcsd.7:1`, `man/vlmcsd.7:143`) and was mirrored to GitHub as `Wind4/vlmcsd`.
Internal version numbering still refers to SVN revisions: the binary product database format
changed at `svn1113` from C tables to the relocatable "KMD" v2 blob described in §7.

The GitHub repository is **archived**. Its last commit is `70e0357`
("Merge pull request #41 from gnaggnoyil/master", 2023-07-28) and the whole mirror contains only
31 commits — it is a squashed import plus a handful of fixes, not the full SVN history.

### Size and language

Plain C99 with heavy preprocessor use. `wc -l src/*.c src/*.h` totals **22,116 lines**, of which
roughly 15 KB is the compiled-in binary product database (`src/kmsdata.c`,
`src/kmsdata-full.c`) rather than logic. There is no C++ anywhere, though the makefile can build
the whole tree as C++ via `COMPILER_LANGUAGE=c++` (`src/GNUmakefile:11`).

### License

**There is no license file and no SPDX header anywhere in the tree.** The upstream project never
declared a license for its own code. Only vendored third-party files carry notices:

| File | Origin / license |
|---|---|
| `src/ns_name.c`, `src/ns_parse.c` | ISC (Internet Software Consortium 1996,1999), "Modified by Hotbird64 for use with vlmcs" — `src/ns_name.c:1-21` |
| `src/wingetopt.c`, `src/wingetopt.h` | AT&T Public License, 1985 UNIFORUM conference code — `src/wingetopt.c:1-8` |
| `src/tap-windows.h` | OpenVPN Technologies 2002-2014, GPLv2 with an MIT alternative for this file — `src/tap-windows.h:1-12` |
| `src/ifaddrs-android.c` | Kenneth MacKay 2013, 2-clause BSD — `src/ifaddrs-android.c:1-6` |
| `src/getifaddrs-musl.c`, `src/ifaddrs-musl.h`, `src/netlink-musl.h` | musl libc (MIT) |

### Design philosophy

Four commitments explain the shape of nearly every design decision in the codebase:

1. **Portability to tiny embedded targets.** Documented target platforms span Linux, Windows
   (MinGW/MSVC), Cygwin, macOS/iOS, FreeBSD, NetBSD, OpenBSD, DragonFly, Minix, Solaris/OpenIndiana,
   Android and GNU Hurd (`README.compile-and-pre-built-binaries:27-63`). Endianness and unaligned
   access are abstracted through macro families with portable out-of-line fallbacks
   (`src/endian.h:19-292`, `src/endian.c:1-176`, `src/types.h:160-173`). The KMS wire structs are
   deliberately *not* `__attribute__((packed))` — the code relies on natural alignment producing
   exactly the wire layout, and only switches to unaligned macros when compacting the
   variable-length response (`src/kms.h:59-160`, `src/kms.c:832-838`).

2. **Zero mandatory dependencies.** The default build links only libc. AES, SHA-256 and HMAC-SHA256
   are all implemented in-tree (`src/crypto.c`, `src/crypto_internal.c`). OpenSSL, PolarSSL and
   Windows CryptoAPI are opt-in and are only ever used for SHA-256/HMAC unless an explicitly
   "DANGEROUS" hack is enabled (`src/config.h:274-326`). `README.openssl` argues against using
   OpenSSL at all, because KMSv6 needs a *modified* AES and KMSv4 needs 160-bit Rijndael, neither
   of which any stock library can do.

3. **Compile-time feature stripping.** Roughly 30 `NO_*` / `SIMPLE_*` / `USE_*` macros documented in
   `src/config.h` let the binary be reduced to an inetd-only, log-less, database-less core. Seven
   named presets bundle them (`FEATURES=full|most|autostart|embedded|inetd|minimum|fixedepids`,
   `src/GNUmakefile:262-274`). Every macro in `config.h` is wrapped in `#ifndef X ... #endif` so an
   equivalent `-DX` on the command line always wins (`src/config.h:6-11`).

4. **Anti-detection through bug-compatibility with Microsoft.** vlmcsd deliberately mimics genuine
   KMS behaviour down to defects: it leaves RPC padding bytes uninitialized because "M$ RPC does not
   do this. Pad bytes contain apparently random data" (`src/rpc.c:442-443`); it pads responses to a
   32-bit boundary because "Windows RPC does it this way" even though it is unnecessary
   (`src/rpc.c:331`); it starts RPC call IDs at 2 "M$ starts with CallId 2. So we do the same"
   (`src/rpc.c:74`); and its CMID list reproduces the genuine KMS host's permanent-overcharge defect
   (`man/vlmcsd.8:243-252`). Random ePIDs are stable per process specifically so a client cannot
   send two requests over one TCP connection and compare the answers (`man/vlmcsd.8:192-208`).

### What vlmcsd is not

There is no authentication of any kind, no rate limiting, no IP allow/deny list, no ACL file and no
connection accounting. The MS-RPC backend explicitly registers its interface with
`RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH` (`src/msrpc-server.c:91-100`); the native server never acts on
the RPC `AuthLength` field — it always writes 0 outbound (`src/rpc.c:602`), and the only inbound read
is a `_PEDANTIC`-only log line whose status code is thrown away (`src/rpc.c:723`, `src/rpc.c:627`).
The only admission controls are the `-m` worker
semaphore (which queues rather than rejects), `-o` public/private IP classification, `-K` product
whitelisting, `-c` client-clock sanity, a hard rejection above 1000 minimum clients and the
671-client CMID cap. `man/vlmcsd.8` recommends `-m` plus a short `-t` and `-d` as the DoS mitigation
strategy and warns against running unlimited on the internet.

There is also no `chroot()`, no `umask()`, no `setsid()` of its own, no capability manipulation and
no seccomp/pledge (verified by exhaustive grep over `src/`). Isolation must come from the
supervisor.

---

## 2. Source map

| File | Role |
|---|---|
| `src/vlmcsd.c` | Server: argument + ini parsing, daemonization, signals, privilege drop, semaphore, pid file |
| `src/vlmcs.c` | Client: three-pass option parsing, request construction, response validation, `-G` harvesting |
| `src/vlmcsdmulti.c` | Multi-call dispatcher |
| `src/libkms.c`, `src/libkms.h` | Shared-library API surface |
| `src/kms.c`, `src/kms.h` | KMS payload construction/parsing, ePID synthesis, CMID list, policy |
| `src/rpc.c`, `src/rpc.h` | Hand-written DCE/RPC 5.0 connection-oriented implementation (both directions) |
| `src/network.c` | Listening sockets, accept loop, concurrency backends, private-IP checks |
| `src/crypto.c` | AES (128-bit CBC and 160-bit CBC-MAC), backend dispatch |
| `src/crypto_internal.c/.h` | In-tree SHA-256 + HMAC-SHA256 |
| `src/crypto_openssl.c/.h`, `src/crypto_polarssl.h`, `src/crypto_windows.c/.h` | Optional backends |
| `src/kmsdata.c`, `src/kmsdata-full.c`, `src/kmsdata.h` | Compiled-in KMD v2 product databases |
| `src/helpers.c` | KMD loader, string/time/hex parsing, `getExeName()`, PRNG seeding |
| `src/output.c` | Entire logging subsystem, verbose dumps, `-V` flag reporting |
| `src/shared_globals.c/.h` | All runtime defaults live here |
| `src/config.h` | Compile-time feature macros and their documentation |
| `src/types.h` | Platform detection, macro derivation (`HAVE_*`, forced `NO_*`) |
| `src/endian.c/.h` | Byte-swap and unaligned-access abstraction |
| `src/ntservice.c` | Windows service install/remove/dispatch |
| `src/wintap.c`, `src/tap-windows.h` | Windows TAP/VPN adapter driving |
| `src/dns_srv.c`, `src/ns_name.c`, `src/ns_parse.c` | `_vlmcs._tcp` SRV discovery — **client only** |
| `src/msrpc-server.c`, `src/msrpc-client.c`, `src/KMSServer.idl` | Microsoft RPC runtime backend |
| `src/getifaddrs-musl.c`, `src/ifaddrs-android.c` | Bundled interface enumeration |
| `etc/vlmcsd.ini`, `etc/vlmcsd.kmd` | Sample ini and sample external product database |
| `man/` | Six man pages: `vlmcs.1`, `vlmcsdmulti.1`, `vlmcsd.ini.5`, `vlmcsd.7`, `vlmcsd.8`, `vlmcsd-floppy.7` |

`debian/` and `docker/` are git submodules (`Wind4/vlmcsd-debian` @ `96200e41`,
`Wind4/vlmcsd-docker` @ `4195d04f`, `.gitmodules:1-6`) and are empty directories in a plain clone.
**No init script, systemd unit, Dockerfile or `install` make target exists in this repository.**

---

## 3. KMS protocol implementation

### 3.1 Request and response layout

The KMS payload is a fixed 236-byte `REQUEST` struct (`src/kms.h:67-80`), wrapped differently per
protocol version:

| Version | Request struct | Size | Wrapping |
|---|---|---|---|
| v4 | `REQUEST_V4` (`src/kms.h:107-115`) | 252 | 236-byte plaintext `REQUEST` + 16-byte CBC-MAC |
| v5 | `REQUEST_V5` (`src/kms.h:118-125`) | 260 | 4-byte cleartext Version + 16-byte IV + AES-CBC(236 + 4 pad) |
| v6 | `REQUEST_V6` | 260 | identical wire layout to v5 |

All sizes in this section are measured, not inferred — `WCHAR` is `uint16_t` (`src/types.h:302`),
every member is naturally aligned and no struct needs tail padding, so the compiler's `sizeof()`
matches the wire layout exactly:

| Symbol | Bytes | Symbol | Bytes |
|---|---|---|---|
| `sizeof(REQUEST)` | 236 | `sizeof(RESPONSE)` | 172 |
| `sizeof(REQUEST_V4)` | 252 | `sizeof(RESPONSE_V4)` | 188 |
| `sizeof(REQUEST_V5)` = `sizeof(REQUEST_V6)` = `MAX_REQUEST_SIZE` | 260 | `sizeof(RESPONSE_V5)` / `sizeof(RESPONSE_V6)` | 240 / 280 |
| `V4_PRE_EPID_SIZE` / `V4_POST_EPID_SIZE` | 8 / 36 | `V6_UNENCRYPTED_SIZE` / `V6_PRE_EPID_SIZE` | 20 / 28 |
| `V5_POST_EPID_SIZE` / `V6_POST_EPID_SIZE` | 84 / 124 | `V6_DECRYPT_SIZE` | 256 |

Request fields, in wire order:

| Off | Size | Field | Server behaviour | Client control |
|---|---|---|---|---|
| 0 | 4 | `Version` (`{WORD MinorVer; WORD MajorVer}`) | dispatch; echoed unchanged into the response (`src/kms.c:727`) | `-4`/`-5`/`-6`, `-K <maj>.<min>` |
| 4 | 4 | `VMInfo` / `IsClientVM` (0 = metal, 1 = VM) | ignored, logged only; `_PEDANTIC` warns if >1 | `-m` |
| 8 | 4 | `LicenseStatus` (0..6) | ignored, logged only; `_PEDANTIC` warns if >6 | `-t <n>` |
| 12 | 4 | `BindingExpiration` / `GraceTime` (minutes) | ignored, logged as "Remaining time (0 = forever)" | `-g <minutes>` |
| 16 | 16 | `AppID` GUID | selects the CMID counting bucket; cross-checked under `-K1`/`-K3` | `-a <guid>` |
| 32 | 16 | `ActID` / `SkuId` GUID | **never used for a policy decision** — log text only | `-s <guid>` |
| 48 | 16 | `KMSID` GUID | the only field driving grant/refuse and ePID selection | `-k <guid>` |
| 64 | 16 | `CMID` | copied verbatim into the response; keys the CMID list under `-M1` | `-c <guid>` |
| 80 | 4 | `N_Policy` (minimum clients) | `required_clients = N<1 ? 1 : N<<1`; >2000 rejected | `-r <n>` |
| 84 | 8 | `ClientTime` (FILETIME) | echoed; keys the v6 HMAC time slot; validated under `-c1` | system clock |
| 92 | 16 | `CMID_prev` | ignored | `-o <guid>` |
| 108 | 128 | `WorkstationName` (64 UCS-2) | converted to UTF-8 for logging only | `-w <name>`, `-d` |

Offsets are relative to the start of `REQUEST` and were confirmed with `offsetof()`; `CMID_prev`
precedes `WorkstationName` on the wire (`src/kms.h:78-79`).

Response fields (`src/kms.h:84-90`): `PIDSize`, `KmsPID[64]` (UCS-2), `CMID`, `ClientTime`,
`Count`, `VLActivationInterval`, `VLRenewalInterval`. `PIDSize` is
`(ucs2_length + 1) << 1`, capped at 128 (`PID_BUFFER_SIZE` = 64 WCHARs, `src/kms.h:22`). The
response is assembled in a fixed-size struct and then compacted: everything after the ePID is
`memmove`d to `V4_PRE_EPID_SIZE`(8) or `V6_PRE_EPID_SIZE` plus `pidSize` (`src/kms.c:768-772`,
`src/kms.c:886-898`). `src/kms.c` explains the design — the fixed-size intermediate exists "to avoid
unaligned access macros and packed structs on RISC systems which largely increase code size".

### 3.2 Version detection and dispatch (native RPC path)

`checkRpcRequestSize()` reads the 4-byte little-endian VERSION_INFO DWORD from the NDR stub,
computes `majorIndex = (version >> 16) - 4` and `minor = version & 0xffff`, and rejects anything with
`majorIndex >= 3` or `minor != 0`, logging `Fatal: KMSv%hu.%hu unsupported` (`src/rpc.c:212-222`).
It then requires `requestSize >= _Versions[majorIndex].RequestSize` — deliberately `>=`, not `==`,
with the comment "allow bigger requests to support buggy RPC clients (e.g. wine)"
(`src/rpc.c:224-226`).

Dispatch goes through a 3-entry table (`src/rpc.c:61-70`):

```
_Versions[0] = { sizeof(REQUEST_V4) /* 252 */, CreateResponseV4 }
_Versions[1] = { sizeof(REQUEST_V6) /* 260 */, CreateResponseV6 }
_Versions[2] = { sizeof(REQUEST_V6) /* 260 */, CreateResponseV6 }
```

Inside `CreateResponseV6`, v5 versus v6 behaviour is chosen by `v6 = LE16(MajorVer) > 5`
(`src/kms.c:849`). Minor version must be exactly 0 — there is no support for a hypothetical v6.1.

Under `MSRPC=1` the logic differs: `ProcessActivationRequest()` discards anything smaller than
`sizeof(REQUEST_V4)` with HRESULT `0x8007000D`, then switches on the *exact* value of
`LE32(Version)` — `0x40000` → V4, `0x50000` and `0x60000` → V6, anything else logs
`Fatal: KMSv%u.%u unsupported` (`src/msrpc-server.c:220-293`). There is no per-version minimum-size
check on this path. `MAX_RESPONSE_SIZE` (384) is passed as the `MaxRpcSize` argument of
`RpcServerRegisterIf2`, so MS RPC caps *incoming* requests at 384 bytes.

### 3.3 KMSv4 — plaintext plus 160-bit CBC-MAC

The response is built at fixed size, compacted, then MAC'd over
`8 + pidSize + V4_POST_EPID_SIZE(36)` bytes and the 16-byte tag appended (`src/kms.c:761-776`).

`AesCmacV4()` (`src/crypto.c:194-213`) is **not** CMAC despite the name. It is a raw CBC-MAC with a
zero IV and ISO/IEC 7816-4 padding (`0x80` then zeros, always appended even when the length is
already a multiple of 16 — the loop condition is `i <= MessageSize`), using Rijndael with a
**160-bit key** (`V4_KEY_BYTES` = 20, `rounds = 20/4 + 6 = 11`). That key size lies outside the AES
standard, which is precisely why no external library can perform it.

```
AesKeyV4 = 05 3D 83 07 F9 E5 F0 88 EB 5E A6 68 6C F0 37 C7 E4 EF D2 D6   (src/crypto.c:10-11)
```

`AesCtx.Key` is `DWORD[48]`, sized for the 160-bit case (11 rounds × 4 words + 4).

### 3.4 KMSv5/v6 — AES-128-CBC with a tampered key schedule

```
AesKeyV5 = CD 7E 79 6F 2A B2 5D CB 55 FF C8 EF 83 64 C4 70   (src/crypto.c:13-15)
AesKeyV6 = A9 4A 41 95 E2 01 43 2D 9B CB 46 04 05 D8 4A 21   (src/crypto.c:16-17)
```

`AesInitKey(ctx, key, IsV6, 16)` performs a standard 128-bit Rijndael expansion (10 rounds, 44
round-key words) and then, **only when `IsV6`**, XORs three bytes of the *expanded* key
(`src/crypto.c:132-138`):

```
Key[4*16] ^= 0x73;   Key[6*16] ^= 0x09;   Key[8*16] ^= 0xE4;
```

That is, the first byte of round keys 4, 6 and 8. This makes v6 a non-standard AES variant that no
stock crypto library can perform — the stated reason vlmcsd carries its own AES.

**The NULL-IV decryption trick.** The client encrypts with the IV as a genuine CBC IV
(`CreateRequestV6`, `src/kms.c:933-958`). The server does not: it calls
`AesDecryptCbc(ctx, NULL, request->IV, V6_DECRYPT_SIZE = 256)` — decrypting 16 blocks starting *at
the IV itself* with a NULL IV (`src/kms.c:831-857`). CBC chaining means blocks 2..16 (the `REQUEST`
plus padding) come out correctly while block 1 becomes `D_k(IV_req)`, which vlmcsd then uses as the
shared secret for the salt and IV fields. `Pad[4]` is a fixed four bytes of `0x04` because
`sizeof(REQUEST)` is 236 and 236 mod 16 = 12.

**v5 IV rule.** For v5 the server copies `V6_UNENCRYPTED_SIZE` bytes — Version plus the
*already-decrypted* request IV — into the response, then encrypts the whole thing with a NULL IV, so
the first ciphertext block is `E_k(D_k(IV_req)) = IV_req` (`src/kms.c:872-906`). The wire response IV
is byte-identical to the request IV, which is what a genuine Microsoft v5 client checks.
`VerifyResponseV5()` asserts exactly this and hardcodes `HmacSha256OK = TRUE` because v5 has no HMAC
(`src/kms.c:1073-1082`).

**v6 IV rule.** For v6 the server draws a fresh random 16-byte block into `response->IV` and puts
`D_k(IV_req)` into the `XoredIVs` field (`src/kms.c:859-871`). After NULL-IV encryption the wire IV
is `E_k(random)`, so request and response IVs differ. The client recomputes `D_k(IV_req)` and
compares (`result.IVsOK`), and separately raises `IVnotSuspicious = FALSE` if the raw IVs match,
printing `WARNING: The KMS server is an emulator because the response uses an IV following KMSv5
rules in KMSv6 protocol` (`src/vlmcs.c:673`).

**Salt proof.** Both v5 and v6 carry a 16-byte `RandomXoredIVs` and a 32-byte `Hash`. The server
draws a random salt `S`, sets `Hash = SHA256(S)`, then XORs `D_k(IV_req)` into the salt in place, so
the transmitted field is `S XOR D_k(IV_req)` (`src/kms.c:855-880`). The client recovers `S` and
verifies the hash (`result.HashOK`, `src/kms.c:1166-1174`). This proves the responder could decrypt
the request IV.

**v6 HMAC.** `CreateV6Hmac()` (`src/kms.c:792-825`) derives a key from the response timestamp:

```
timeSlot = LE64(GET_UA64LE(ClientTime) / TIME_C1 * TIME_C2 + TIME_C3 + tolerance * TIME_C1)
TIME_C1 = 0x00000022816889BD   (~4.11 h in 100 ns units)   src/kms.h:27
TIME_C2 = 0x000000208CBAB5ED                               src/kms.h:28
TIME_C3 = 0x3156CD5AC628477A                               src/kms.h:29
hash    = SHA256(timeSlot, 8);  HMAC key = last 16 bytes of hash
```

HMAC-SHA256 is computed over the response region starting at `response->IV` for
`encryptSize - 16` bytes (the soon-to-be-encrypted plaintext, excluding the HMAC field itself), and
the **last 16 bytes** of the 32-byte result go into the trailing `HMAC[16]` field. Creation always
uses tolerance 0; verification retries −1, 0, +1, so request and response time slots must agree
within one ~4.11-hour slot (`src/kms.c:1018-1070`).

**Padding.** `AesEncryptCbc()` applies inclusive PKCS#7-style padding: `pad = (~len & 15) + 1`, so a
length already a multiple of 16 gets a whole extra block of `0x10` (`src/crypto.c:281-303`). Wire
response size is therefore `4 + roundup16(148 + pidSize)` for v6 and `4 + roundup16(108 + pidSize)`
for v5. The client recomputes the expected size with the identical formula and validates that the
last byte is 1..16 and all pad bytes are identical (`src/kms.c:1107-1198`). A GCC 4.8 `memset`
codegen bug (PR56977) is worked around with an explicit byte loop in both `crypto.c` and
`crypto_openssl.c`.

### 3.5 Activation policy

| Policy | Effect | HRESULT on refusal | Knob |
|---|---|---|---|
| Overcharge guard | `required_clients > 2000` (i.e. `N_Policy > 1000`) rejected; logs "Rejecting request with more than 1000 minimum clients" | `0x8007000D` | none (removed by `NO_STRICT_MODES`), `src/kms.c:597-606` |
| Client clock check | `llabs(clientTime - now) > 14400` (4 h) | `0xC004F06C` | `-c1` / `CheckClientTime`, `src/kms.c:608-620` |
| Whitelist bit 1 | KMS ID flagged `IsRetail` or `IsPreview` | `0xC004F042` | `-K2`/`-K3`, `src/kms.c:622-632` |
| Whitelist bit 0 | KMS ID not in the database | `0xC004F042` | `-K1`/`-K3`, `src/kms.c:634-641` |
| Whitelist bit 0 (cont.) | known KMS ID but request `AppID` ≠ database `AppIndex` GUID | `0xC004F042` | `-K1`/`-K3`, `src/kms.c:653-659` |
| CMID list cap | more than `MAX_CLIENTS` = 671 distinct CMIDs | `0xC004D104` | `-M1`, `src/kms.c:690` |
| Public-IP rejection | peer IP is not private | connection dropped (native) / `0x80070005` (MSRPC) | `-o2`/`-o3`, `src/network.c:806-820` |

The SKU / Activation ID is **never** validated at any whitelisting level — mirroring a genuine KMS
host, which activates unknown SKUs. `getProductIndex()` returns −1 on an unknown KMS ID, sets the
name to the literal `"Unknown"` and falls back to CSVLK index 0 (Windows) (`src/kms.c:46-63`), which
is why the default `-K0` build "never refuses activation" (`man/vlmcsd.7:17`).

### 3.6 Reported client count and intervals

Without a CMID list the answer is `Count = max(required_clients, CsvlkData[ePidIndex].MinActiveClients)`
(`src/kms.c:719-723`). `MinActiveClients` is **0 for every CSVLK in every shipped database**
(verified by decoding `src/kmsdata-full.c` and `etc/vlmcsd.kmd`), so the floor is inert and the
server simply answers twice the client's own requested minimum (or 1 when `N_Policy` is 0).

`VLActivationInterval` (retry after failure) and `VLRenewalInterval` (renew when activated) are
global, **not** per-product, and are set on every response from `src/shared_globals.c:11-12` via
`src/kms.c:732-733`. Defaults are 120 minutes and 10080 minutes (7 days). `man/vlmcsd.8` notes that
modern clients (Windows 8.1 and later) ignore these values.

### 3.7 CMID list / active-client emulation

With `-M1`, `InitializeClientLists()` allocates one `ClientList_t` **per application** (three lists)
holding up to `MAX_CLIENTS` = 671 GUIDs (`src/kms.h:57-65`). Under the fork model it lives in a SysV
shared-memory segment (`shmget(IPC_PRIVATE, ..., 0600)`) guarded by a `PTHREAD_PROCESS_SHARED` mutex;
under threads it is plain `malloc` plus a normal mutex / `CRITICAL_SECTION` (`src/kms.c:202-243`).
`CleanUpClientLists()` issues `shmctl(IPC_RMID)` at shutdown.

Per request (`src/kms.c:661-715`): a known CMID returns the current count unchanged; an unknown CMID
fills the first free slot and increments; a full list overwrites round-robin at `CurrentPosition`
*without* incrementing. `MaxCount` grows to `required_clients` when a request demands more.

Unless `-E1` is given, each list is pre-charged with `(AppItemList[i].NCountPolicy >> 1) - 1` random
GUIDs (`src/kms.c:245-260`) — 24 for Windows (`NCountPolicy` 50) and 4 for each Office application
(`NCountPolicy` 10) — so the first real client sees exactly the required count. This is deliberately
bug-compatible: `man/vlmcsd.8:243-252` states you can permanently "kill" a genuine KMS host with an
overcharge request of ≥ 376 required clients followed by 671 activations, and vlmcsd reproduces the
defect. Only a restart resets it.

Shared-memory allocation failure downgrades `MaintainClients` to `FALSE` with a warning rather than
aborting (`src/kms.c:212-218`). The feature is forced off in inetd mode (`src/vlmcsd.c:1743`).

---

## 4. Cryptography backends

All AES work — the 160-bit v4 CBC-MAC and the modified-schedule v5/v6 CBC — is always done by
vlmcsd's own code. Only SHA-256 and HMAC-SHA256 are ever delegated, and only the experimental
`_USE_AES_FROM_OPENSSL` hack changes that. The backend is chosen **at build time only**, via
`CRYPTO=` in `src/GNUmakefile:455-476`.

| `CRYPTO=` | Macros | Source | What is delegated | Platform limits |
|---|---|---|---|---|
| `internal` (default) | `-D_CRYPTO_INTERNAL` | `src/crypto_internal.c` | nothing | all |
| `openssl` | `-D_CRYPTO_OPENSSL`, `-lcrypto` | `src/crypto_openssl.c` | SHA-256, HMAC | not native Windows (Cygwin OK) |
| `openssl_with_aes` | `+ -D_USE_AES_FROM_OPENSSL` | same | SHA-256, HMAC, **AES** | x86/x86_64 benefit (AES-NI) |
| `openssl_with_aes_soft` | `+ -D_OPENSSL_SOFTWARE` | same | AES decrypt + CBC encrypt only | all OpenSSL platforms |
| `polarssl` | `-D_CRYPTO_POLARSSL`, `-lpolarssl` | header-only `src/crypto_polarssl.h` | SHA-256, HMAC | not native Windows |
| `windows` | `-D_CRYPTO_WINDOWS` | `src/crypto_windows.c` | SHA-256, HMAC | Windows/Cygwin only (`#error` otherwise) |

**Internal** (`src/crypto_internal.c:1-211`): byte-oriented AES via 32-bit Galois-multiply macros,
CBC wrappers, the 160-bit CBC-MAC, plus from-scratch SHA-256 and HMAC-SHA256. `Sha256Hmac()`
hardcodes a 16-byte key length. Note that `_CRYPTO_INTERNAL` is defined by the makefile but is
**never tested anywhere in the source** — selection is by *absence* of the other three macros
(`src/crypto.h:44-56`).

**OpenSSL** (`src/crypto_openssl.c:6-59`): `Sha256` becomes a macro for `SHA256()`; `Sha256Hmac`
uses `HMAC_CTX`/`HMAC_Init_ex(EVP_sha256())`. Separate paths exist for OpenSSL ≥ 1.0.0 and 0.9.x.
`OPENSSL_HMAC=0` adds `-D_OPENSSL_NO_HMAC`, replacing the `HMAC_CTX` path with a hand-rolled
ipad/opad HMAC on `SHA256_Init/Update/Final` for embedded OpenSSL builds compiled without HMAC
(`src/crypto_openssl.c:61-114`).

**`_USE_AES_FROM_OPENSSL`** (`src/crypto_openssl.c:116-267`): vlmcsd builds the expanded round key
itself — *including* the v6 tweak — and pokes it directly into OpenSSL's `AES_KEY` struct so that
`AES_encrypt`/`AES_decrypt`/`AES_cbc_encrypt` perform the *modified* cipher. This is how hardware
acceleration is obtained for a non-standard AES. `TransformOpenSslEncryptKey()` copies round-key
words with `LE32` (hardware/AES-NI layout) or `BE32` under `_OPENSSL_SOFTWARE`;
`TransformOpenSslDecryptKey()` additionally reverses round-key block order and applies
`MixColumnsR()` to all but the first and last round key, synthesizing OpenSSL's
equivalent-inverse-cipher schedule by hand. `src/config.h:295-310` calls this "DANGEROUS" and notes
it depends on OpenSSL internals that are version- and platform-specific. **This is the only
hardware-acceleration path in the entire project** — there is no AES-NI, ARM crypto-extension,
SHA-NI or assembly code anywhere in vlmcsd itself.

**`_OPENSSL_SOFTWARE`** additionally excludes `AesEncryptBlock` and `AesCmacV4` from the OpenSSL file
so they are taken from the internal implementation (`src/crypto.c:84-90`).

**PolarSSL** (`src/crypto_polarssl.h:1-38`): macros only, no `.c` file. Two API generations are
handled — PolarSSL ≥ 1.3.0 (`polarssl/sha256.h`) and older (`polarssl/sha2.h`). Key length is
hardcoded to 16 in the `Sha256Hmac` macro.

**Windows CryptoAPI** (`src/crypto_windows.c:1-170`): one process-wide
`CryptAcquireContextW(PROV_RSA_AES, CRYPT_VERIFYCONTEXT)` handle, `CryptCreateHash(CALG_SHA_256)`,
and for HMAC a `PLAINTEXTKEYBLOB` declared as `CALG_RC2` with a 16-byte key, imported with
`CryptImportKey`, then `CryptCreateHash(CALG_HMAC)` + `CryptSetHashParam(HP_HMAC_INFO, {CALG_SHA_256})`.
This is legacy CryptoAPI, **not** CNG/bcrypt — there is no `BCryptOpenAlgorithmProvider` anywhere in
the tree.

**`SMALL_AES`** (`src/crypto.c:218-255`): drops the 256-byte inverse S-box and makes `SBoxR()` a
linear search through the forward S-box, trading ~256 bytes of rodata for CPU time in AES
decryption. No makefile switch exposes it directly; `FEATURES=minimum` sets it.

### Randomness

**There is no CSPRNG anywhere in the tree.** Every random value — v6 response IVs, the SHA-256 salt,
CMID list pre-charge GUIDs, ePID key IDs / LCIDs / dates, the RPC association group, client CMIDs and
workstation names — comes from `rand32()`, a macro stitching together libc `rand()` calls
(`(rand() << 17) | (rand() << 2) | (rand() & 3)` when `RAND_MAX < 2^31`, `src/types.h:219-226`).

The generator is seeded by `randomNumberInit()` with `srand(tv_sec ^ tv_usec)` — or
`srand(GetTickCount())` under MSVC (`src/helpers.c:343-352`) — once in `main()` **and again at the
start of every RPC connection** (`src/rpc.c:618`, `src/network.c:1014`). `/dev/urandom`,
`getrandom(2)`, `arc4random`, `RtlGenRandom`/`CryptGenRandom` and OpenSSL `RAND_bytes` are never used
(verified by grep). The practical seed entropy is roughly 20 bits, and re-seeding per connection lets
an attacker who can time connections narrow the state. This has no effect on activation success — the
keys are public — but it is a real weakness for anything derived from it.

---

## 5. DCE/RPC layer

vlmcsd implements DCE/RPC 5.0 connection-oriented (`ncacn_ip_tcp`) by hand in `src/rpc.c`, for both
the server and the client. A compile-time alternative (`MSRPC=1`) replaces the whole stack with
Microsoft's `rpcrt4` via MIDL-generated stubs for `src/KMSServer.idl`.

### 5.1 Interface

`src/KMSServer.idl:1-14` declares one method at opnum 0:

```
HRESULT RequestActivation([in] int requestSize,
                          [in, size_is(requestSize)] unsigned char* request,
                          [out] int* responseSize,
                          [out, size_is(,*responseSize)] unsigned char** response);
```

NDR32 stub layout: request `{DWORD DataLength; DWORD DataSizeIs; BYTE Data[]}` (data at offset 16),
response `{DWORD DataLength; DWORD DataSizeMax(=0x00020000 referent id); DWORD DataSizeIs; BYTE Data[]}`
(data at offset 20) followed by the 4-byte HRESULT and zero padding to a 4-byte boundary. NDR64 uses
64-bit versions of those fields, moving the data to offsets 24 and 32
(`src/rpc.h:189-264`, `src/rpc.c:289-341`). On error (`ResponseSize < 0`) the length fields are
zeroed, the `size_is` field is omitted, and the HRESULT is written in its place. The zero padding is
explicitly cosmetic MS mimicry (`src/rpc.c:331`); the client warns if the server omits it or if
`AllocHint` disagrees.

### 5.2 Header handling and packet types

`RPC_HEADER` is 16 bytes: `{VersionMajor, VersionMinor, PacketType, PacketFlags, DataRepresentation,
FragLength, AuthLength, CallId}` (`src/rpc.h:145-154`). The server accepts only packet types 11
(bind), 0 (request) and 14 (alter_context); anything else terminates the connection. It emits 12
(bind_ack), 2 (response), 15 (alter_context_ack) or 3 (fault).

`createRpcHeader()` sets version 5.0, flags `FIRST|LAST`, `AuthLength` 0 and
`DataRepresentation = BE32(0x10000000)` — a big-endian-encoded constant meaning "little-endian data,
ASCII, IEEE float" (`src/rpc.c:596-606`). For *normal replies*, however, the server does
`memcpy(rpcResponseHeader, &rpcRequestHeader, sizeof(RPC_HEADER))` and overwrites only `PacketType`
and `FragLength` (`src/rpc.c:667-687`) — so `PacketFlags`, `DataRepresentation` and `CallId` are
echoed verbatim from the client.

### 5.3 Bind and transfer-syntax negotiation

`rpcBind()` services both bind and alter_context (`src/rpc.c:432-569`). It echoes
`MaxXmitFrag`/`MaxRecvFrag`, sets `AssocGroup`, and fills `SecondaryAddress` from
`getsockname()` + `getnameinfo(NI_NUMERICSERV)` — the ASCII TCP port plus NUL. For alter_context (or
if either call fails) `SecondaryAddressLength` is 0. If the secondary address is shorter than 3 bytes
the response pointer is moved back 4 bytes, described in the source as "really ugly (but efficient)
code to support padding after the secondary address field", so the results array lands at the correct
4-byte-aligned offset.

| Syntax | GUID | Version | Behaviour |
|---|---|---|---|
| NDR32 | `8a885d04-1ceb-11c9-9fe8-08002b104860` | 2 | ACKed only if the abstract syntax is the KMS interface **and** NDR64 was not also offered. Otherwise NACKed (`AckResult` 2) with reason 2 (`RPC_SYNTAX_UNSUPPORTED`) if the interface matched, 1 (`RPC_ABSTRACTSYNTAX_UNSUPPORTED`) if not (`src/rpc.c:475-519`) |
| NDR64 | `71710533-beba-4937-8319-b5dbef9ccc36` | 1 | If enabled, ACKed while NDR32 is NACKed — matching Microsoft, which accepts exactly one transfer syntax (`src/rpc.c:521-534`) |
| BTFN | pseudo-GUID starting `2c 1c b7 6c 12 98 40 45` | 1 | Feature bits in bytes 8-9. Replies `AckResult = 3` (negotiate_ack), `SyntaxVersion` 0, `AckReason = requested & (SEC_CONTEXT_MULTIPLEX \| KEEP_ORPHAN)`. ACKed regardless of the abstract syntax (`src/rpc.c:536-552`) |

Unlike Microsoft, vlmcsd supports NDR64 on 32-bit systems (`man/vlmcsd.8`).

The vlmcs client sends a bind with ctx 0 = NDR32, optional ctx 1 = NDR64, optional ctx 2 = BTFN,
`MaxXmit`/`MaxRecvFrag` = 5840, `AssocGroup` = 0, interface version 1.0 (`src/rpc.c:1003-1253`). If
the server accepted NDR64 (and therefore NACKed NDR32), the client follows up with an alter_context
carrying only NDR32 as ctx 0 so both contexts become usable — exactly what a Windows client does.
`rpcSendRequest()` then uses NDR32 for the **first** request on any connection and NDR64 for every
subsequent one (`RpcFlags.HasNDR64 && UseClientRpcNDR64 && firstPacketSent`, `src/rpc.c:812`).

### 5.4 Other RPC behaviours

| Behaviour | Detail |
|---|---|
| `RPC_PF_MULTIPLEX` | The client ORs flag 16 into bind/alter_context when `UseMultiplexedRpc` is set (`src/rpc.c:1020`). The server never inspects it but echoes the request's flags, so multiplex is implicitly mirrored. The client's checker warns on a mismatch and on MULTIPLEX appearing in any non-bind response (`src/rpc.c:764-777`) |
| Fragmentation | **Unsupported.** The server refuses `FragLength > MAX_REQUEST_SIZE + sizeof(RPC_REQUEST64)` by closing the connection and always emits single-fragment replies. `MaxXmitFrag`/`MaxRecvFrag` are echoed but never enforced. The client's `_PEDANTIC`-only checker reports "Fatal: RPC packet flags RPC_PF_FIRST and RPC_PF_LAST are not both set" with the comment "vlmcsd does not support fragmented packets (not yet neccassary)" (`src/rpc.c:729-734`, `src/rpc.c:638-650`) |
| Authentication | **None.** Outgoing headers always set `AuthLength = 0` (`src/rpc.c:602`), and the server never *acts* on an inbound `AuthLength`: it never parses an auth trailer, so an authenticated PDU would have its sec_trailer treated as stub data. Under `_PEDANTIC && !NO_LOG` the field is read and logged — `checkRpcHeader()` prints "Fatal: RPC response requests authentication" (`src/rpc.c:723`) — but `rpcServer()` discards the return value (`src/rpc.c:627`), so the PDU is serviced anyway |
| Call ID | Static `CallId` starts at 2 "M$ starts with CallId 2. So we do the same" (`src/rpc.c:74`) and is incremented by the client per request. The client tolerates a constant CallId of 1, printing "Warning: Buggy RPC of Wine detected. Call Id of Response is always 1" once (`src/rpc.c:779-795`) |
| Association group | `RpcAssocGroup = rand32()` once at startup, incremented per accepted connection (`src/network.c:1014`, `src/network.c:1053`). The client always sends 0 and never validates the returned value |
| Fault PDUs | `SendError()` builds a 32-byte body carrying an NCA status: `RPC_NCA_UNK_IF` (0x1c010003) when the context id is bound to neither syntax, `RPC_NCA_PROTO_ERROR` (0x1c01000b) for a non-5.0 RPC version on a request PDU (`_PEDANTIC` only). The caller recognises a fault purely by `response_len == 32` and rewrites the header as type 3 with flags `FIRST\|LAST\|NOT_EXEC` (`src/rpc.c:229-238`, `src/rpc.c:652-674`) |
| Request size limits | `MAX_REQUEST_SIZE = sizeof(REQUEST_V6)` (260), `MAX_RESPONSE_SIZE = 384` (`src/kms.h:21-23`). Buffers are fixed-size stack arrays |

**`SIMPLE_RPC`** (`src/config.h:646-654`) compiles out NDR64, BTFN, the NCA fault path and
context-id demultiplexing entirely: the server always reads/writes the NDR32 stub layout, always
answers NDR32-or-NACK with reason `RPC_SYNTAX_UNSUPPORTED`, and never emits fault PDUs. It produces
smaller binaries "but makes emulator detection easier".

---

## 6. ePID and HWID emulation

### 6.1 ePID format

`generateRandomPid()` (`src/kms.c:308-358`) composes:

```
PPPPP-GGGGG-KKK-KKKKKK-03-LLLL-BBBBB.0000-DDDYYYY
```

| Part | Source |
|---|---|
| `PPPPP` | 5-digit host platform id from `getPlatformId(hostBuild)` — the first host-build entry whose `BuildNumber <= hostBuild` (`src/kms.c:90-119`) |
| `GGGGG` | 5-digit `CsvlkData[index].GroupId` |
| `KKK-KKKKKK` | `keyId = rand32() % (MaxKeyId - MinKeyId) + MinKeyId`, split as `keyId/1000000` (3 digits) and `keyId%1000000` (6 digits) |
| `-03-` | License channel — a **hard-coded literal** (`src/kms.c:331`) meaning Volume/GVLK. vlmcsd never emits any other channel |
| `LLLL` | LCID, printed unpadded: `Lcid` if non-zero, else a random pick from `LcidList` |
| `BBBBB.0000` | KMS host build number plus a literal minor version |
| `DDDYYYY` | 3-digit day-of-year (`tm_yday + 1`) and 4-digit year of `kmsTime = rand32() % (maxTime - minTime) + minTime` |

`minTime = max(CSVLK ReleaseDate, host-build ReleaseDate)`;
`maxTime = max(now, BUILD_TIME)` where `BUILD_TIME` defaults to 1538922811 (2018-10-07) if the
makefile did not inject one (`src/kms.c:346-353`).

`LcidList` (`src/kms.c:79-88`) holds **158 entries, all unique** (verified by counting the array
literal three ways). The comment says they are the LCIDs valid for .NET 4.0.

### 6.2 Randomization levels

| Level | Behaviour | `EpidSource` string |
|---|---|---|
| `-r0` | Always use the fixed default ePID embedded per CSVLK in the database | `vlmcsd default` |
| `-r1` (default) | `randomPidInit()` runs once at startup (and again after a SIGHUP restart), filling one ePID per CSVLK; **all CSVLKs share one LCID and one host build** so the set looks self-consistent | `randomized at program start` |
| `-r2` | `generateRandomPid()` runs on every single request | `randomized on every request` |

Explicit ePIDs from `-a` or the ini file always win and disable randomization **for that CSVLK only**
(`src/kms.c:464-513`). Under an inetd-style superserver `-r1` degenerates to almost `-r2` because the
process exits after each connection (`man/vlmcsd.8:206`).

### 6.3 ePID host build / NDR64 coupling (anti-detection)

The advertised OS build in the ePID is kept consistent with the RPC features on the wire:

* If `-N` was not given, `UseServerRpcNDR64` is taken from the KMS data file flag
  `KMS_OPTIONS_USENDR64` (bit 0 of the header `Flags` byte, `src/kms.h:290`, value `1` in every
  shipped database).
* If a fixed `-H HostBuild` was given with randomization on, `UseServerRpcNDR64` is forced to
  `HostBuild > 7601` (`src/vlmcsd.c:1770-1785`).
* Conversely, when generating random ePIDs with no fixed build: if NDR64 was explicitly configured,
  `getRandomServerType()` loops until it draws a host build whose `UseNdr64` flag matches; otherwise a
  build is drawn at random and NDR64 is set from that build's flag (`src/kms.c:285-302`,
  `src/kms.c:377-396`).

In the shipped database, builds 17763/14393/9600/9200 have the NDR64 flag set (flags value 7) and
7601/6002 do not (flags value 6).

### 6.4 HWID

The 8-byte `HwId` field exists only in a v6 response (`src/kms.h:133`). `CreateResponseV6` pre-fills
it with the compile-time `DefaultHwId` and passes it to `CreateResponseBase`, where `getEpid()` may
overwrite it with a per-CSVLK value (`src/kms.c:848`, `src/kms.c:866`, `src/kms.c:884`).

```
HWID default = 3A 1C 04 96 00 B6 00 76      // "HwId from the Ratiborus VM", src/config.h:35-37
```

A custom HwId is applied **only if an explicit ePID is also configured** for that CSVLK — the
`memcpy(HwId, KmsResponseParameters[index].HwId, 8)` sits inside the
`KmsResponseParameters[index].Epid != NULL` branch (`src/kms.c:490-500`). The client prints the value
as a 16-digit big-endian hex number (`src/output.c:231-236`).

### 6.5 Fixed ePID / HwId configuration

`-a <CSVLK>=<ePID>[/<HwId>]` on the command line, or a bare `<csvlk-name> = <ePID>[ / <HwId>]` line in
the ini file. Details:

* CSVLK name resolution is **case-insensitive prefix matching** of the database keyword against the
  argument: `strncasecmp(csvlkName, s, strlen(csvlkName))` (`src/vlmcsd.c:764-777`).
* The ePID text is terminated by any character `< '!'` (including space) or by `/`, must be 1..63
  UCS-2 characters, and must be valid UTF-8 (`src/vlmcsd.c:452-482`).
* The HwId is 16 hex digits parsed big-endian by `hex2bin()`, which silently skips any non-hex
  character, so `01 02 03 ...` is accepted (`src/helpers.c:387-405`).
* `-a` is parsed in a **dedicated second getopt pass after the KMS database is loaded**
  (`src/vlmcsd.c:1792-1810`), with `overwrite = TRUE`, so a later `-a` for the same CSVLK overwrites
  an earlier one and the command line beats the ini file.
* The ini form runs in ini pass 2 with `overwrite = FALSE`, so within the ini the **first**
  occurrence of a given CSVLK wins.

Valid keywords with the shipped database: `Windows`, `Office2010`, `Office2013`, `Office2016`,
`Office2019`, `WinChinaGov`.

---

## 7. Product and activation database

Since svn1113 the entire product database lives in a single relocatable binary blob ("KMD" v2.0),
either compiled in or loaded from an external `.kmd` file.

### 7.1 KMD v2 file format

All multi-byte fields are little-endian on disk and are byte-swapped at load.

| Off | Size | Field |
|---|---|---|
| 0 | 4 | `Magic[4]` = `"KMD\0"` |
| 4 | 2 | `MinorVer` |
| 6 | 2 | `MajorVer` (must be 2) |
| 8 | 1 | `CsvlkCount` |
| 9 | 1 | `Flags` — bit 0 = `KMS_OPTIONS_USENDR64` |
| 10 | 2 | reserved |
| 12 | 20 | `Counts[5]` (int32) = {AppItemCount, KmsItemCount, SkuItemCount, HostBuildCount, reserved} |
| 32 | 40 | `Datapointers[5]` (uint64 offsets) = {AppItemOffset, KmsItemOffset, SkuItemOffset, HostBuildOffset, reserved} |
| 72 | 32×N | `CsvlkData[CsvlkCount]` |

Real header size is `72 + 32*CsvlkCount` (264 for the shipped files), but `sizeof(VlmcsdHeader_t)` is
104 because `CsvlkData` is declared as a 1-element array (`src/kms.h:308-370`).

`CsvlkData_t` (32 bytes, `src/kms.h:239-254`): `EPidOffset` u64 @0 (→ `char* EPid`); `ReleaseDate`
i64 @8 (Unix time); `GroupId` u32 @16; `MinKeyId` u32 @20; `MaxKeyId` u32 @24; `MinActiveClients` u8
@28; `Reserved[3]` @29. Each `EPid` string is followed in the pool by two more NUL-terminated
strings reached with `getNextString()`: the ini/CLI keyword and a human-readable description.

`VlmcsdData_t` (32 bytes, `src/kms.h:256-279`): `GUID[16]` @0 (raw little-endian bytes, compared by
`memcmp` via `IsEqualGUID`, `src/types.h:362-363`); `NameOffset` u64 @16 (→ `char* Name`);
`AppIndex` u8 @24; `KmsIndex` u8 @25; `ProtocolVersion` u8 @26; `NCountPolicy` u8 @27; `IsRetail` u8
@28; `IsPreview` u8 @29; `EPidIndex` u8 @30; reserved u8 @31.

Field usage is asymmetric:

| Field | Read from |
|---|---|
| `IsRetail`, `IsPreview`, `AppIndex`, `EPidIndex` | `KmsItemList` only (server) |
| `ProtocolVersion`, `NCountPolicy`, `AppIndex`, `KmsIndex` | `SkuItemList` only (vlmcs) |
| `NCountPolicy` | `AppItemList` only (CMID list pre-charge) |
| `SkuItemList.EPidIndex`, `AppItemList.EPidIndex`, `KmsItemList.ProtocolVersion`/`NCountPolicy`, all `reserved` | **never read — dead** |

`HostBuild_t` (32 bytes, `src/kms.h:292-306`): `DisplayNameOffset` u64 @0; `ReleaseDate` i64 @8;
`BuildNumber` i32 @16; `PlatformId` i32 @20; `Flags` u32 @24 (`UseNdr64`=1, `UseForEpid`=2,
`MayBeServer`=4); reserved @28. **Only `UseNdr64` is ever read** (`src/kms.c:296`, `src/kms.c:391`);
`UseForEpid` and `MayBeServer` are declared but referenced nowhere, and `DisplayName` is resolved and
bounds-checked at load (`src/helpers.c:648-651`) but never printed.

The three item arrays **must** be laid out contiguously in App → Kms → Sku order: `src/kms.c:414`
iterates `AppItemList` with `count = App + Kms + Sku`, and `src/helpers.c:670-685` validates all
three by walking `AppItemList` for `totalItemCount` entries. The format never states this and the
loader never verifies it.

### 7.2 Loading and validation

`loadKmsData()` (`src/helpers.c:553-686`) starts from the built-in `DefaultKmsData`, then optionally
reads an external file wholesale and mutates the buffer **in place**: `LE16` on the versions, `LE32`
on the four counts, `LE64` on the five data pointers (converted to absolute pointers), then per-CSVLK
`EPidOffset` → pointer, `ReleaseDate`, and `GroupId`/`MinKeyId`/`MaxKeyId` (the last three only when
`NO_RANDOM_EPID` is undefined); then per host build `BuildNumber`/`Flags`/`PlatformId`/`ReleaseDate`
and `DisplayNameOffset` → pointer; then per product record `NameOffset` → pointer. **GUIDs are never
swapped** — they are raw little-endian bytes, so `.kmd` files are portable across endianness.

Two fatal handlers exist: `dataFileReadError()` prints errno and exits with it
(`src/helpers.c:435-439`); `dataFileFormatError()` prints
`Fatal: <file> is not a KMS data file version 2.x` and exits `VLMCSD_EINVAL` (22)
(`src/helpers.c:442-446`).

Validation gates, unless `UNSAFE_DATA_LOAD` is defined:

| Check | Location |
|---|---|
| Last byte of the file must be `\0` | `src/helpers.c:605` |
| Each of the 5 data pointers must not be `> KmsData + size` | `src/helpers.c:621` |
| Each CSVLK `EPid` pointer likewise | `src/helpers.c:631` |
| Each HostBuild `DisplayName` likewise | `src/helpers.c:650` |
| `memcmp(Magic,"KMD",4) == 0` and `MajorVer == 2` and `sizeof(VlmcsdHeader_t) + totalItemCount*32 < size` | `src/helpers.c:657-667` |
| Per record: `Name < KmsData + size`, `AppIndex < AppItemCount`, `KmsIndex < KmsItemCount` | `src/helpers.c:676-683` |

`EPidIndex` is **never** validated against `CsvlkCount`. See §17.1 for the consequences and for the
ordering defect (the magic/version check runs *after* the pointer loops have already dereferenced).

A read error is fatal only when the file was requested explicitly (`ExplicitDataLoad`, set by `-j` or
ini `KmsData`); a missing *default* `vlmcsd.kmd` silently falls back to the internal database
(`src/helpers.c:569-599`).

### 7.3 Default search path

If no `-j`/`KmsData` was given and `DATA_FILE` was not compiled in, `getDefaultDataFile()`
(`src/helpers.c:521-551`) derives `<directory of the running executable>/vlmcsd.kmd` — POSIX uses
`dirname` of the resolved exe path, Windows uses `PathRemoveFileSpec(GetModuleFileName(...))`. If the
executable path cannot be determined at all, it falls back to the literal `/etc/vlmcsd.kmd`. When
`DATA_FILE` *is* compiled in, this auto-detection is skipped entirely.

Executable-path resolution (`getExeName()`, `src/helpers.c:449-519`) is per-platform:
`getauxval(AT_EXECFN)` under `USE_AUXV`; `realpath("/proc/self/exe")` on Linux/Cygwin (with an
older-uClibc/Android<16 stack-buffer variant); `sysctl KERN_PROC_PATHNAME` on FreeBSD;
`/proc/curproc/file` on DragonFly; `/proc/curproc/exe` on NetBSD; `getexecname()` on Solaris;
`_NSGetExecutablePath` on Apple; `GetModuleFileName` on Windows. Minix and OpenBSD always fall back
to `argv[0]`.

### 7.4 The four database variants

| Variant | Selected by | Size | Apps / KMS / SKU / HostBuild / CSVLK | Names |
|---|---|---|---|---|
| Full (`src/kmsdata.c:10`) | `-DFULL_INTERNAL_DATA` | 15085 B | 3 / 29 / 202 / 6 / 6 | complete |
| Default (`src/kmsdata.c:1036`) | neither macro | 1858 B | 3 / 29 / 0 / 6 / 6 | **every name points at one shared `"Unknown"` string**; CSVLK descriptions empty |
| Minimal (`src/kmsdata.c:959`) | `-DNO_STRICT_MODES` | 1122 B | 3 / 6 / 0 / 6 / 6 | as above |
| `src/kmsdata-full.c` | always linked into `vlmcs` and `vlmcsdmulti` | 15085 B | identical to Full | complete |

`src/kmsdata-full.c` is byte-for-byte identical to the `FULL_INTERNAL_DATA` blob in `kmsdata.c`
(verified). The six KMS IDs retained in the minimal variant are exactly those that map to a
non-default ePID group: `7ba0bf23` (China Gov → 4), `e85af946` (Office2010 → 1), `e6a6f1bf`
(Office2013 → 2), `aa4c7968` (Office2013 preview → 0), `85b5f61b` (Office2016 → 3), `617d9eb1`
(Office2019 → 5). The `aa4c7968` entry is redundant, since index 0 is also the unknown-product
fallback.

The library targets link **neither** file: `loadKmsData()`, `getProductIndex()` and the whole
database consumer path are compiled out under `IS_LIBRARY` (`src/GNUmakefile:391-393`,
`src/helpers.c:433`, `src/kms.c:38`, `src/kms.c:72`).

### 7.5 CSVLK / ePID groups (decoded from `src/kmsdata-full.c`)

| # | Keyword | Description | GroupId | Key-ID range | Release | MinActiveClients | Built-in ePID |
|---|---|---|---|---|---|---|---|
| 0 | `Windows` | Windows Server 2019 | 206 | 551000000–570999999 | 2018-10-02 | 0 | `03612-00206-556-123727-03-1033-17763.0000-2972018` |
| 1 | `Office2010` | Office 2010 | 96 | 199000000–217999999 | 2010-07-15 | 0 | `03612-00096-199-799188-03-1033-17763.0000-2972018` |
| 2 | `Office2013` | Office 2013 | 206 | 234000000–255999999 | 2013-01-29 | 0 | `03612-00206-240-719639-03-1033-17763.0000-2972018` |
| 3 | `Office2016` | Office 2016 | 206 | 437000000–458999999 | 2015-09-22 | 0 | `03612-00206-438-004532-03-1033-17763.0000-2972018` |
| 4 | `WinChinaGov` | Windows 10 China Government | 3858 | 15000000–999999999 | 2017-04-05 | 0 | `03612-03858-053-089516-03-1033-17763.0000-2972018` |
| 5 | `Office2019` | Office 2019 | 206 | 666000000–685999999 | 2018-09-24 | 0 | `03612-00206-684-137669-03-1033-17763.0000-2972018` |

### 7.6 Host builds (decoded)

| BuildNumber | PlatformId | Flags | ReleaseDate | DisplayName | NDR64 |
|---|---|---|---|---|---|
| 17763 | 3612 | 7 | 2018-10-02 | Windows 10 1809 / Server 2019 | yes |
| 14393 | 3612 | 7 | 2016-08-02 | Windows 10 1607 / Server 2016 | yes |
| 9600 | 6401 | 7 | 2013-10-18 | Windows 8.1 / Server 2012 R2 | yes |
| 9200 | 5426 | 7 | 2012-10-26 | Windows 8 / Server 2012 | yes |
| 7601 | 55041 | 6 | 2011-02-22 | Windows 7 / Server 2008 R2 SP1 | no |
| 6002 | 55041 | 6 | 2009-05-26 | Windows Vista / Server 2008 SP2 | no |

The list is sorted descending. `getPlatformId()` returns the `PlatformId` of the first entry whose
`BuildNumber <= hostBuild` (falling back to the last entry); `getReleaseDate()` scans from the end
for the first `BuildNumber >= hostBuild` (falling back to entry 0) (`src/kms.c:90-119`,
`src/kms.c:308-318`).

### 7.7 Application IDs

| # | Keyword | GUID | `NCountPolicy` (CMID pre-charge base) |
|---|---|---|---|
| 0 | `Windows` | `55c92734-d682-4d71-983e-d6ec3f16059f` | 50 |
| 1 | `Office2010` | `59a52881-a989-479d-af46-f275c6370663` | 10 |
| 2 | `Office2013+` | `0ff1ce15-a989-479d-af46-f275c6370663` | 10 |

Office 2013, 2016 and 2019 all share Application ID 2, so they share one CMID counting bucket
(friendly name `FRIENDLY_NAME_OFFICE2013` = "Office 2013+", `src/kms.c:36`).

### 7.8 The shipped `etc/vlmcsd.kmd`

15079 bytes, version 2.0. Its App/KMS/SKU tables are equivalent to the compiled-in full database (the
size difference is string-pool packing), but two things differ:

* All six default ePID strings use platform `06401` / host build `9600` / date `296-2018` instead of
  `03612` / `17763` / `297-2018` — i.e. **loading it with `-j` is a downgrade** relative to a current
  build's built-in data.
* Four HostBuild release dates differ: 9600 = 2013-10-17 (vs 10-18), **9200 = 2001-10-26** (vs
  2012-10-26), **7601 = 2001-02-16** (vs 2011-02-22), 6002 = 2009-04-28 (vs 2009-05-26). The 9200 and
  7601 dates are eleven and ten years too early.

---

## 8. Product coverage

The full database contains 3 Application IDs, 29 KMS IDs, 202 SKU / Activation IDs and 6 host builds.
All counts below were decoded directly from `src/kmsdata-full.c`.

### 8.1 Per-KMS-ID SKU counts

| KMS GUID | Name | App | Proto | N | Retail | Preview | ePID group | SKUs |
|---|---|---|---|---|---|---|---|---|
| `8449b1fb-f0ea-497a-99ab-66ca96e9a0f5` | Windows Server 2019 | 0 | 6 | 5 | | | 0 | 7 |
| `11b15659-e603-4cf1-9c1f-f0ec01b81888` | Windows 10 2019 (Volume) | 0 | 6 | 25 | | | 0 | 2 |
| `d27cd636-1962-44e9-8b4f-27b6c23efb85` | Windows 10 Unknown (Volume) | 0 | 6 | 25 | | | 0 | 0 |
| `7ba0bf23-d0f5-4072-91d9-d55af5a481b6` | Windows 10 China Government | 0 | 6 | 25 | | | **4** | 2 |
| `969fe3c0-a3ec-491a-9f25-423605deb365` | Windows 10 2016 (Volume) | 0 | 6 | 25 | | | 0 | 2 |
| `e1c51358-fe3e-4203-a4a2-3b6b20c9734e` | Windows 10 (Retail) | 0 | 6 | 25 | **yes** | | 0 | 4 |
| `58e2134f-8e11-4d17-9cb2-91069c151148` | Windows 10 2015 (Volume) | 0 | 6 | 25 | | | 0 | 17 |
| `7fde5219-fbfa-484a-82c9-34d1ad53e856` | Windows 7 | 0 | 4 | 25 | | | 0 | 9 |
| `bbb97b3b-8ca4-4a28-9717-89fabd42c4ac` | Windows 8 (Retail) | 0 | 5 | 25 | **yes** | | 0 | 5 |
| `3c40b358-5948-45af-923b-53d21fcc7e79` | Windows 8 (Volume) | 0 | 5 | 25 | | | 0 | 6 |
| `6d646890-3606-461a-86ab-598bb84ace82` | Windows 8.1 (Retail) | 0 | 6 | 25 | **yes** | | 0 | 8 |
| `cb8fc780-2c05-495a-9710-85afffc904d7` | Windows 8.1 (Volume) | 0 | 6 | 25 | | | 0 | 11 |
| `5f94a0bb-d5a0-4081-a685-5819418b2fe0` | Windows Preview | 0 | 5 | 25 | | **yes** | 0 | 5 |
| `33e156e4-b76f-4a52-9f91-f641dd95ac48` | Windows Server 2008 A (Web and HPC) | 0 | 4 | 5 | | | 0 | 2 |
| `8fe53387-3087-4447-8985-f75132215ac9` | Windows Server 2008 B (Standard and Enterprise) | 0 | 4 | 5 | | | 0 | 4 |
| `8a21fdf3-cbc5-44eb-83f3-fe284e6680a7` | Windows Server 2008 C (Datacenter) | 0 | 4 | 5 | | | 0 | 3 |
| `0fc6ccaf-ff0e-4fae-9d08-4370785bf7ed` | Windows Server 2008 R2 A (Web and HPC) | 0 | 4 | 5 | | | 0 | 3 |
| `ca87f5b6-cd46-40c0-b06d-8ecd57a4373f` | Windows Server 2008 R2 B (Standard and Enterprise) | 0 | 4 | 5 | | | 0 | 2 |
| `b2ca2689-a9a8-42d7-938d-cf8e9f201958` | Windows Server 2008 R2 C (Datacenter) | 0 | 4 | 5 | | | 0 | 2 |
| `8665cb71-468c-4aa3-a337-cb9bc9d5eaac` | Windows Server 2012 | 0 | 5 | 5 | | | 0 | 4 |
| `8456efd3-0c04-4089-8740-5b7238535a65` | Windows Server 2012 R2 | 0 | 6 | 5 | | | 0 | 4 |
| `6e9fc069-257d-4bc4-b4a7-750514d32743` | Windows Server 2016 | 0 | 6 | 5 | | | 0 | 8 |
| `6d5f5270-31ac-433e-b90a-39892923c657` | Windows Server Preview | 0 | 6 | 5 | | **yes** | 0 | 1 |
| `212a64dc-43b1-4d3d-a30c-2fc69d2095c6` | Windows Vista | 0 | 4 | 25 | | | 0 | 4 |
| `e85af946-2e25-47b7-83e1-bebcebeac611` | Office 2010 | 1 | 4 | 5 | | | 1 | 19 |
| `e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0` | Office 2013 | 2 | 5 | 5 | | | 2 | 16 |
| `aa4c7968-b9da-4680-92b6-acb25e2f866c` | Office 2013 (Pre-Release) | 2 | 5 | 5 | | **yes** | **0** | 16 |
| `85b5f61b-320b-4be3-814a-b76b2bfafc82` | Office 2016 | 2 | 6 | 5 | | | 3 | 23 |
| `617d9eb1-ef36-4f82-86e0-a65ae07b96c6` | Office 2019 | 2 | 6 | 5 | | | 5 | 13 |

Totals: 115 Windows SKUs (App 0), 19 Office 2010 SKUs (App 1), 68 Office 2013+ SKUs (App 2) = 202.

Three KMS IDs are flagged `IsRetail` and three are flagged `IsPreview` — exactly the set refused by
`-K2` / `-K3`.

Note the quirk: **Office 2013 (Pre-Release) has `EPidIndex` 0**, so an Office request matching that
KMS ID is answered with the *Windows* CSVLK ePID. Note also that `Windows 10 Unknown (Volume)`
(`d27cd636`) has zero SKUs attached — a KMS ID with no product key mapped to it.

### 8.2 Notable SKU details

* Windows 10 2015 (Volume) covers 17 SKUs including Enterprise for Virtual Desktops, Professional
  Workstation (+N), Professional Education (+N), Remote Server and "Windows 10 S (Lean)".
* Windows Server 2016 (8 SKUs) and 2019 (7 SKUs) include Datacenter, Standard, Essentials, Cloud
  Storage / Azure Core, ARM64 and the Semi-Annual Channel Datacenter/Standard variants.
* Office 2016 (23 SKUs) includes Click-to-Run variants of Project and Visio and Skype for Business
  2016, **plus three "Office Professional Plus / Project Pro / Visio Pro 2019 C2R Preview" SKUs that
  are attached to the 2016 KMS ID**, not the 2019 one.
* `SkuItemList[0]` is **"Windows Server 2019 ARM64"** (App 0, KMS 0, protocol 6, N = 5). This is
  `vlmcs`'s default product when `-l` is not given. The last entry (index 201) is "Office Word 2019".

### 8.3 Coverage cutoff

The newest things described anywhere are **Windows 10 1809 / Enterprise LTSC 2019 (build 17763,
platform id 3612), Windows Server 2019 including the 1809 SAC SKUs, and Office / Project / Visio
2019**. The newest CSVLK release date is 2018-10-02 and the newest host build is 17763 (2018-10-02).

**Not present, at any level of the database:**

* Windows 11 — any release
* Windows 10 21H2 / 22H2 and Enterprise LTSC 2021
* Windows 11 Enterprise LTSC 2024
* Windows 10/11 IoT Enterprise LTSC
* Windows Server 2022, Windows Server 2025
* Azure Stack HCI and Azure Edition SKUs
* Office LTSC 2021, Office LTSC 2024 (and their Project/Visio LTSC counterparts)

Because no host build newer than 17763 exists, **a synthesized ePID can never claim a KMS host newer
than Windows Server 2019**.

**Practical consequence:** with the default `-K0`, post-2019 clients still activate. Their KMS ID is
simply unknown, so `getProductIndex()` falls back to CSVLK group 0 (Windows) and the server answers
normally (`src/kms.c:46-63`, `src/kms.c:644-649`). They log as "Unknown", receive a Windows-group
ePID with platform id 03612 and a host build no newer than 17763, and cannot be selected with
`vlmcs -l`. Under `-K1` or `-K3` they are refused outright with `0xC004F042`.

---

## 9. Server runtime

### 9.1 Concurrency models

| Model | Selected by | Mechanism |
|---|---|---|
| fork-per-connection | default on POSIX (absence of `USE_THREADS`) | `ServeClientAsyncFork()` takes the semaphore, `fork()`s; the parent closes the client socket and returns; the child installs handlers for SIGHUP/INT/TERM/SEGV/ILL/FPE/BUS, serves, posts the semaphore and `exit(0)` (`src/network.c:925-984`) |
| POSIX threads | `THREADS=1` → `-DUSE_THREADS` | per-connection `CLDATA` struct, semaphore wait, then a **detached** `pthread_create` running `serveClientThreadProc()` (`src/network.c:858-915`) |
| Win32 threads | forced on `_WIN32` (`src/types.h:240`); opt-in on Cygwin | `serveClientAsyncWinThreads()` waits the semaphore and calls `CreateThread()`, closing the handle immediately (`src/network.c:878`) |
| inetd / superserver | auto-detected | one connection served on `STDIN_FILENO`, then return (`src/network.c:1022`) |
| Microsoft RPC | `MSRPC=1` | dispatch delegated entirely to `rpcrt4` |

The child SIGHUP handler returns without action; any other listed signal posts the semaphore, logs
`Warning: Child killed/crashed by <signal>` and `exit(ECHILD)`. Threads are created
`PTHREAD_CREATE_DETACHED` specifically to avoid a leak; there is no thread pool and no upper bound
other than the `-m` semaphore. `src/config.h` explicitly recommends `THREADS=1` for Cygwin because
Cygwin `fork()` is slow and unreliable.

### 9.2 Listening sockets

The default full build uses a `select()`-driven accept loop. `network_accept_any()` builds an
`fd_set` from all listening sockets, blocks in `select()` with a NULL timeout, then scans
`SocketList` in order and `accept()`s the **first** ready socket (`src/network.c:690-719`). `EINTR`
and `ECONNABORTED` are retried; any other error is logged `Fatal: <err>` and terminates the server
(or returns 0 if `ServiceShutdown` is set).

Socket setup details:

| Aspect | Behaviour |
|---|---|
| Backlog | Always `listen(s, SOMAXCONN)` (`src/network.c:621`, `src/network.c:346`, `src/network.c:361`) |
| Dual stack | Full build: every AF_INET6 socket gets `IPV6_V6ONLY = TRUE`, with IPv4 served by a separate `0.0.0.0` socket. `SIMPLE_SOCKETS` build: `IPV6_V6ONLY = FALSE` on a single dual-stack socket, falling back to AF_INET (`src/network.c:562`, `src/network.c:339`). A missing constant on old Linux toolchains is worked around with `#define IPV6_V6ONLY 26` (`src/network.c:287`) |
| Address reuse | `SO_REUSEADDR = TRUE` on POSIX, `SO_EXCLUSIVEADDRUSE = TRUE` on `_WIN32`, and **nothing at all on Cygwin** (the whole function body is inside `#if !__CYGWIN__`, `src/network.c:294-314`). `SO_REUSEPORT`, `TCP_NODELAY`, `SO_KEEPALIVE` and `SO_LINGER` are never used anywhere |
| Free binding | With `-F1`: `IP_FREEBIND` (Linux, both families), `IP_BINDANY` (FreeBSD IPv4), `IPV6_BINDANY` (FreeBSD IPv6, locally `#define`d to 64 when missing), `IP_NONLOCALOK` (FreeBSD-with-GNU-userspace IPv4, only when `IP_BINDANY` is absent) (`src/network.c:581-620`) |
| `FD_CLOEXEC` | Set on each listening socket on POSIX with SIGHUP support, so the exec-based restart does not inherit stale listeners (`src/network.c:542`). **Not** applied to accepted client sockets |
| Socket count cap | `addListeningSocket()` refuses once `numsockets >= FD_SETSIZE`, silently unless `_PEDANTIC` (`src/network.c:651`). Typical `FD_SETSIZE` is 64 on Windows, 1024 on most Unixes |
| Stack probing | `checkProtocolStack(af)` creates and closes a throwaway socket to decide whether the implicit `::` / `0.0.0.0` defaults should be attempted; not used for explicit `-L` (`src/network.c:677`) |
| Per-connection timeouts | `SO_RCVTIMEO` and `SO_SNDTIMEO` set to `ServerTimeout` seconds on the accepted socket (`timeval` on POSIX, DWORD ms on Windows) (`src/network.c:751-775`). This is the **only** idle-disconnect mechanism |
| Partial IO | All socket IO goes through `sendrecv()`, which loops retrying on `SOCKET_EINTR` and advancing on partial transfers until `len` reaches 0 (`src/network.c:56`) |

`-L` parsing is two-pass: pass 1 in `parseGeneralArguments()` only *counts* occurrences into
`maxsockets` and marks the ini `Listen` directive ignored; pass 2 in `setupListeningSockets()`
re-runs getopt after `optReset()` and actually creates each socket in command-line order, honouring
any preceding `-P` (`src/vlmcsd.c:1584-1666`). If `-L` was given but no socket succeeded, ini pass 3
is attempted. Address parsing passes `AI_NUMERICHOST`, so **hostnames are rejected** with a
`gai_strerror` warning.

If no socket at all can be created, vlmcsd exits fatally with `Fatal: Could not listen on any
socket.` regardless of `-x` (`src/vlmcsd.c:1659-1663`).

### 9.3 Alternate socket backends

**`SIMPLE_SOCKETS`** (`src/network.c:320-375`): replaces the entire `-L` machinery with
`listenOnAllAddresses()` — parse `defaultport` with `stringToInt(1, 65535)`, create an AF_INET6
socket with `IPV6_V6ONLY = FALSE` bound to `in6addr_any`, `listen(SOMAXCONN)`; on any failure fall
back to a single AF_INET socket on `INADDR_ANY`. Logs `Listening on TCP port %u`. Mutually exclusive
with `USE_MSRPC` (compile error at `src/vlmcsd.h:14`). Always defined for `libkms`.

**`USE_MSRPC`** (`src/msrpc-server.c:53-119`): `RpcServerUseProtseqEpA("ncacn_ip_tcp",
RPC_C_PROTSEQ_MAX_REQS_DEFAULT, defaultport, NULL)` then `RpcServerRegisterIf2` with
`RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH | RPC_IF_AUTOLISTEN`, max calls = `MaxTasks`, max RPC size =
`MAX_RESPONSE_SIZE` (384). `runServer()` then loops `sleep(86400)` forever so a Cygwin signal can
interrupt it. Removes `-L`, `-t`, `-d`/`-k`, `-N`/`-B`; caps `MaxTasks` at
`RPC_C_LISTEN_MAX_CALLS_DEFAULT`; downgrades `-o2` to near-useless because RPC negotiation completes
before vlmcsd sees the client (a startup warning is printed, `src/vlmcsd.c:1828-1833`). Windows and
Cygwin only.

**`NO_SOCKETS`** (`src/network.c:1017`, `src/shared_globals.c:84`): inetd-only build. `InetdMode` and
`nodaemon` are hardcoded to 1, `runServer()` unconditionally serves `STDIN_FILENO`, `cleanup()`
becomes a no-op, and `-L/-P/-m/-t/-e/-D/-x` plus the NT service code fall through to `usage()`. Also
forces `NO_SIGHUP` and `NO_TAP` and disables `_NTSERVICE` (`src/types.h:228-238`).

### 9.4 inetd / socket activation

After argument parsing, vlmcsd `fstat()`s `STDIN_FILENO` and, if `S_ISSOCK`, sets `InetdMode = 1`,
forces `MaintainClients = FALSE`, `nodaemon = 1`, `maxsockets = 0` and `logstdout = 0`
(`src/vlmcsd.c:1734-1754`). No listening sockets are created, no pid file is written, no signal
handlers are installed, no semaphore is allocated, TAP startup is skipped, the startup/shutdown log
lines are suppressed, and `cleanup()` does nothing.

**There is no systemd `sd_listen_fds()` / `LISTEN_FDS` support and no launchd API use.** "Socket
activation" works only through the inetd convention — systemd `Accept=yes` with
`StandardInput=socket`, i.e. one process per connection, at which point `-M1` and `-r1` stop working
as documented.

### 9.5 Public / private IP protection

`PublicIPProtectionLevel` is a bitmask (`src/network.c:170-225`, `src/network.c:806-820`):

* **Bit 0 (`-o1`)**: at startup, `getPrivateIPAddresses()` enumerates interfaces (`getifaddrs` on
  POSIX, `GetAdaptersAddresses` filtered to `IfOperStatusUp` on Windows) and adds a listening socket
  per private address, suppressing the implicit `::`/`0.0.0.0` defaults.
* **Bit 1 (`-o2`)**: in `serveClient()`, after logging "connection accepted", the peer is tested and,
  if public, the connection is closed with **zero bytes sent** and `Client with public IP address
  rejected` is logged.

"Private" means 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, `::1`, and any IPv6 address outside
`2000::/3`. **100.64.0.0/10 (CGNAT) is deliberately treated as public.** Failure to determine the
client IP is also a rejection. Both bits are defeated by NAT port-forwarding or a TCP relay.

Interface enumeration has three implementations: the platform `getifaddrs()` by default;
`GETIFADDRS=musl` compiling `src/getifaddrs-musl.c` (an rtnetlink `RTM_GETLINK` + `RTM_GETADDR` dump
over `PF_NETLINK/SOCK_RAW`); and `src/ifaddrs-android.c` (Kenneth MacKay's netlink implementation)
compiled automatically for Android. `NO_GETIFADDRS=1` removes the capability, undefining
`HAVE_GETIFADDR` and making odd `-o` values a usage error ("Must be 0 or 2" in the ini).
uClibc/Hurd get a workaround appending `%ifname` to link-local IPv6 addresses (`src/network.c:484`).

### 9.6 Worker limit

`MaxTasks` defaults to `SEM_VALUE_MAX`, which is the sentinel meaning **"no limit"** and suppresses
semaphore creation entirely. When set lower (and not in inetd mode), `allocateSemaphore()`
(`src/vlmcsd.c:1514-1580`) creates a counting semaphore:

| Configuration | Strategy |
|---|---|
| POSIX + fork | `sem_unlink("/vlmcsd")` then `sem_open("/vlmcsd", O_CREAT, 0700, MaxTasks)`; on failure `shmget(IPC_PRIVATE, sizeof(sem_t), IPC_CREAT\|0600)` + `shmat` + `sem_init(pshared=1)` |
| POSIX + threads / Cygwin | `malloc` + `sem_init(pshared=0)`, falling back to `sem_open` |
| Windows | `CreateSemaphoreA` |

Any failure warns and reverts to "no limit". `sem_open` is deliberately called **without** `O_EXCL`
(commented out in source). `SEM_VALUE_MAX` is faked as `0x3fffffff` on Android, `0x7fffffff` on
Windows and `0x7fff` on unknown platforms (`src/shared_globals.h:70`).

### 9.7 Process lifecycle

| Event | Behaviour |
|---|---|
| Daemonization | `daemon(nochdir = 1, noclose = logstdout)` — the working directory is deliberately **not** changed to `/`, and stdio is redirected to `/dev/null` unless `-e` was given (`src/vlmcsd.c:1006-1019`). Skipped under `-D`, in inetd mode, and when running as an NT service. Happens **after** sockets are bound and **after** the uid/gid switch. There is no `setsid()` of its own |
| SIGTERM / SIGINT | `terminationHandler()` calls `cleanup()` then `exit(0)`. `cleanup()` (non-inetd only): `CleanUpClientLists()`, unlink the pid file, `closeAllListeningSockets()`, `sem_unlink("/vlmcsd")`, `shmdt` + `shmctl(IPC_RMID)` of the fallback semaphore page, and log `vlmcsd <version> was shutdown` (`src/vlmcsd.c:991`, `src/vlmcsd.c:1464-1492`). In-flight children/threads are neither signalled nor waited for |
| SIGHUP | `HangupHandler()` rebuilds argv, appends `-Z` unless already present, then re-execs via `getExeName()` + `execv`, falling back to `execvp(argv[0], argv)`. `-Z` sets `IsRestarted` and `nodaemon` in the new image, suppressing re-daemonization, pid-file rewriting and the setuid/setgid switch entirely. If exec fails: `Fatal: Unable to restart on SIGHUP`, unlink the pid file, exit with errno. Installed with `SA_NODEFER` (`src/vlmcsd.c:944-987`, `src/vlmcsd.c:1112`). Because the process image is replaced, the ini file is genuinely re-read and listeners (being `FD_CLOEXEC`) are closed and rebound |
| SIGCHLD | Set to `SIG_IGN` with `SA_NOCLDWAIT` in fork mode. `CHILD_HANDLER=1` (automatic on Minix) instead compiles in `childHandler()`, calling `waitpid(-1, NULL, WNOHANG)` once per signal. `SA_NOCLDWAIT` is `#define`d to 0 when missing (Cygwin). Not installed under `USE_THREADS` (`src/vlmcsd.c:998-1025`) |
| Windows console | `SetConsoleCtrlHandler` installs `terminationHandler` for `CTRL_C_EVENT`, `CTRL_CLOSE_EVENT`, `CTRL_BREAK_EVENT`, `CTRL_LOGOFF_EVENT`, `CTRL_SHUTDOWN_EVENT`; not installed when `IsNTService` (`src/vlmcsd.c:1056-1074`) |
| PID file | `writePidFile()` writes the decimal pid with `fopen("w")`; failure only warns. Skipped in inetd mode and when `IsRestarted`. Written **after** the privilege drop and **after** daemonization, so the target directory must be writable by the unprivileged user. No locking, no stale-pid detection, no `O_EXCL` (`src/vlmcsd.c:1429-1460`) |
| Exit-on-warning | `exitOnWarningLevel(level)` exits with status −1 when `ExitLevel >= level`. Invoked with level 1 when a listening socket fails to bind/listen and when the Windows TAP mirror thread hits an error (`src/helpers.c:688-697`, `src/network.c:660-668`, `src/wintap.c:300`) |

### 9.8 Privilege drop

`-u`/`-g` (or ini `user`/`group`) resolve names via `getpwnam`/`getgrnam`, falling back to a numeric
id parsed by `GetNumericId()` (which rejects `(uid_t)-1` and trailing garbage). The actual switch
happens in `newmain()` **after** TAP startup and after all listening sockets are created — so
privileged ports work — and **before** `randomNumberInit()` and pid-file writing:
`setgid(gid)`, then `setgroups(1, &gid)` to drop supplementary groups, then `setuid(uid)`
(`src/vlmcsd.c:1861-1891`). Any failure is fatal.

The switch is deliberately skipped when `IsRestarted` (i.e. after a SIGHUP re-exec), both at parse
time (`src/vlmcsd.c:1338`) and at apply time — documented as intentional. Never available on native
Windows; on Cygwin it needs `cyglsa-config` plus the "Act as part of the OS" and "Replace a process
level token" privileges.

### 9.9 Windows service integration

| Operation | Behaviour |
|---|---|
| Dispatch | `server_main()` calls `StartServiceCtrlDispatcher(NTServiceDispatchTable)` first; `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` means it is a console app (`IsNTService = FALSE`) and `newmain()` runs. `IsNTService` defaults to TRUE (`src/vlmcsd.c:1675`, `src/ntservice.c:39-57`) |
| Control handling | Accepts `SERVICE_CONTROL_STOP` and `SERVICE_CONTROL_SHUTDOWN`: sets `ServiceShutdown`, reports `SERVICE_STOP_PENDING`, calls `cleanup()` (closing listeners so the blocked `accept()` fails and `runServer()` returns 0), and on Cygwin/MSRPC reports `SERVICE_STOPPED` immediately. **No** `SERVICE_ACCEPT_PAUSE_CONTINUE` and **no** `SERVICE_CONTROL_INTERROGATE` handling (`src/ntservice.c:17-68`) |
| Install (`-s`) | Image path = quoted `GetModuleFileName` plus the original command line with `-s`, `-U <arg>` and `-W <arg>` stripped (args containing spaces are re-quoted). Any existing service is removed first (stop + up to 10×100 ms poll + `DeleteService`), then `CreateService` with `NT_SERVICE_NAME`, `SERVICE_WIN32_OWN_PROCESS`, `SERVICE_AUTO_START`, `SERVICE_ERROR_NORMAL` and a dependency on `"tcpip"`. `-U` shortcuts: `/l` → `NT AUTHORITY\LocalService`, `/n` → `NT AUTHORITY\NetworkService`; bare names get `.\` prefixed. `-W` supplies the password, which is `SecureZeroMemory`d after `CreateService` (`src/ntservice.c:175-270`) |
| Remove (`-S`) | `OpenSCManager(SC_MANAGER_ALL_ACCESS)`, `OpenService`, `ControlService(SERVICE_CONTROL_STOP)`, poll up to 10×100 ms, `DeleteService`. All other options are ignored (`src/ntservice.c:125`, `src/ntservice.c:305`) |
| Start/stop | **No CLI verbs.** `man/vlmcsd.8` directs users to `net start vlmcsd` |

### 9.10 Windows TAP / VPN adapter (`-O`)

`startTap()` (`src/wintap.c:305-370`) parses `<name>[=<ipv4>][/<cidr>][:<lease>]` (defaults
10.10.10.9, `/30`, lease `1d`; CIDR must be 8..30), enumerates
`HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-...}` for adapters with `ComponentId`
`tap0801`, `tap0901` or `TEAMVIEWERVPN`, maps `NetCfgInstanceId` to the friendly connection name, and
`CreateFile`s `\\.\Global\<guid>.tap` (or `.dgt` for TeamViewer). It issues
`TAP_WIN_IOCTL_GET_MTU`, `GET_VERSION`, `CONFIG_TUN`, `CONFIG_DHCP_MASQ` (DHCP server = ip+1) and
`SET_MEDIA_STATUS`, then spawns a `TapMirror` thread that reads each IP packet, swaps `ip_src` and
`ip_dst` and writes it back — making the local machine appear as a remote KMS client. It then polls
`GetIpAddrTable` for up to 4 s (20×200 ms) before listening sockets are created.

`.` picks the first compatible adapter; `-` disables a VPN configured in the ini file. Skipped in
inetd mode. Registry errors are fatal. On mirror-thread read/write failure the thread warns and calls
`exitOnWarningLevel(1)`, so `-x1` kills the whole server.

---

## 10. Logging

The entire subsystem is `src/output.c`. Three sinks exist and **that is all**: a file, stdout, and
syslog.

| Sink | Behaviour |
|---|---|
| File (`-l <path>`) | `vlogger()` does `fopen(fn_log, "a")` on **every log line**, writes, `fflush()`s and `fclose()`s. If the file cannot be opened the message is silently dropped (`src/output.c:22-89`). Open-append-close per line means external rotation (logrotate) works with no reopen signal — there is no built-in rotation, size cap or retention, and it costs one `open()`/`close()` pair per line |
| stdout (`-e`) | Routes all output to stdout and makes `daemon()` keep the standard descriptors open. Checked **before** `fn_log`, so it overrides `-l`. Forced to 0 in inetd mode (stdout is the client socket) and ignored while running as an NT service (`src/output.c:26-31`) |
| syslog (`-l syslog`) | If `fn_log` is exactly the string `"syslog"`: `openlog("vlmcsd", LOG_CONS\|LOG_PID, LOG_USER)`, `vsyslog(LOG_INFO, ...)`, `closelog()` **per message**. `LOG_CONS` sends messages to `/dev/console` when no syslogd is listening. The date/time prefix code is never reached on this path. **All levels are `LOG_INFO`** — warnings and fatal errors are not raised (`src/output.c:35-41`). POSIX/Cygwin only |

**Windows event log: not implemented.** The only event-log code (`ServiceReportEvent` using
`RegisterEventSource`/`ReportEvent`) is entirely commented out (`src/ntservice.c:93-120`). A Windows
service started without `-l` therefore produces **no output at all**.

**Timestamps** (`-T0`/`-T1`, default TRUE): prefix `strftime("%Y-%m-%d %X: ")` of `localtime()`
(`src/output.c:59-62`). `%X` is locale-dependent, so the time portion changes format with `LC_TIME`
while the date portion is fixed ISO. `localtime()` is not thread-safe and is called without a lock in
the threads build — the mutex only guards the `fprintf`.

**Serialization**: in `USE_THREADS` builds the message is formatted into a 2048-byte stack buffer
*outside* the lock, then `fprintf` + `fflush` happen inside a `pthread_mutex_t` / `CRITICAL_SECTION`
(`src/output.c:54-83`). Lines longer than 2048 bytes are truncated. **In fork builds no locking is
used at all**, so verbose multi-line bursts from concurrent workers can interleave.

**`printerrorf()` routing** (`src/output.c:108-145`): writes to stderr normally, but redirects to the
log when `InetdMode` or `IsNTService` is set (stderr is the client socket or nonexistent).
`errorout()` always writes to stderr. `errno` is preserved. Under `IS_LIBRARY` the message is
appended to a global `ErrorMessage` buffer instead.

### 10.1 What is logged per request

Non-verbose steady state, in order:

```
IPv4 connection accepted: <ip>:<port>.          (or  IPv6 connection accepted: [<ip>]:<port>.)
KMS v<maj>.<min> request from <workstation-name> for <product>
Sending ePID (<source>): <epid>
IPv4 connection closed: <ip>.
```

`<workstation-name>` comes from the request — **there is no reverse DNS**. `<source>` is one of
`vlmcsd default`, `randomized at program start`, `randomized on every request`, `command line`, or
the ini file path. Rejection lines: `Client with public IP address rejected`, `Rejecting request with
more than 1000 minimum clients (0x8007000D)`, `Client time differs more than 4 hours from system time
(0xC004F06C)`, `Refusing retail or beta product (0xC004F042)`, `Refusing unknown product
(0xC004F042)`, `Refusing product with incorrect Application ID (0xC004F042)`, `Rejecting more than
671 clients (0xC004D104)`.

Under `USE_MSRPC` the connection line is instead `RPC connection accepted: <ip>` with no "closed"
counterpart (`src/msrpc-server.c:230`). Detailed RPC conformance warnings in `rpc.c` (bad context id,
wrong OpNum, wrong alloc hint, NDR length mismatches, excess bytes, non-1.0 interface version) are
compiled only with `_PEDANTIC`.

### 10.2 Verbose logging (`-v`)

`logRequestVerbose()` (`src/output.c:183-224`) dumps: protocol version; is-VM flag; licensing status
with text (Unlicensed / Licensed / OOB grace / OOT grace / Non-Genuine / Notification / Extended
grace); remaining binding time in minutes; Application ID plus resolved name; SKU / Activation ID plus
name; KMS ID plus name; client machine ID; previous client machine ID; client request timestamp
(UTC); workstation name (UTF-8); N-count policy.

`logResponseVerbose()` (`src/output.c:225-251`) dumps: protocol version; KMS host extended PID; KMS
host Hardware ID (16 hex digits, only when major > 5); client machine ID; client request timestamp
(UTC); current active client count; renewal interval policy; activation interval policy.

Verbose also logs one `Using CSVLK <name> (<full name>) with random|fixed ePID <epid>` line per CSVLK
at startup (`src/vlmcsd.c:1900-1915`).

### 10.3 Startup / shutdown lines

`Read ini file <path>` (pass 1 only, non-inetd, not while installing a service); `Read KMS data file
version x.y <path>`; one `Listening on <ip:port>` per socket (or `Listening on TCP port <n>` under
`SIMPLE_SOCKETS`, `Listening on port <p>` under MSRPC); the optional verbose CSVLK lines;
`vlmcsd <version> started successfully`; `vlmcsd <version> was shutdown`. **None** are emitted in
inetd mode.

---

## 11. Complete `vlmcsd` CLI reference

The single getopt option string (`src/vlmcsd.c:87`) is:

```
a:N:B:m:t:A:R:u:g:L:p:i:H:P:l:r:U:W:C:c:F:O:o:x:T:K:E:M:j:SseDdVvqkZ
```

There are **no long options** and vlmcsd reads **no environment variables at all** (`grep getenv`
over `src/` finds nothing). Any non-option argument (`optind != argc`) triggers `usage()`
(`src/vlmcsd.c:1419`). Unknown options fall through `default:` to `usage()`, which prints the
built-in help on stderr and exits `VLMCSD_EINVAL`.

The option string is parsed up to three times using `optReset()` — `optind = 0` on glibc/uClibc,
`optind = 1` + `optreset = 1` on BSD/Darwin/Minix, `optind = 1` elsewhere (`src/helpers.c:278`).

Options that carry `:` **require** an argument even when documentation writes them as `-M0`/`-M1`.
Options combined without a dash (`-De`) work only for argument-less flags; a space between an option
and its argument is optional.

| Flag | Argument | Default | ini twin | Availability | Effect |
|---|---|---|---|---|---|
| `-a` | `<CSVLK>=<ePID>[/<HwId>]` | none | bare `<csvlk-name> = ...` (reversed overwrite semantics) | `!NO_CL_PIDS` | Pin ePID (and optionally 8-byte HwId) for one CSVLK group. Parsed in a dedicated pass after the database loads. Unknown CSVLK ⇒ help + exit |
| `-A` | timespan | `120` (2 h) | `ActivationInterval` | `!NO_CUSTOM_INTERVALS` | `VLActivationInterval` sent in every response |
| `-B` | bool | `TRUE` | `UseBTFN` | `!USE_MSRPC && !SIMPLE_RPC` | Offer/accept bind-time feature negotiation |
| `-c` | bool | `FALSE` | `CheckClientTime` | `!NO_STRICT_MODES` | Reject requests whose `ClientTime` differs by >4 h with `0xC004F06C` |
| `-C` | `0..32767` | `0` (random) | `LCID` | `!NO_RANDOM_EPID` | Pin the LCID field of generated ePIDs. 0 = pick from the 158-entry `LcidList` |
| `-d` | — | (off) | `DisconnectClientsImmediately = true` | `!USE_MSRPC` | Close the TCP connection right after the RPC response/fault. Documented as "a direct violation of DCE RPC" |
| `-D` | — | daemonize (POSIX) | none | `!NO_SOCKETS` | Run in the foreground. No-op on native Windows (warns only under `_PEDANTIC`) |
| `-e` | — | off | **none** | `!NO_LOG && !NO_SOCKETS` | Log to stdout; overrides `-l`. Forced off in inetd mode and ignored as an NT service |
| `-E` | bool | `FALSE` | `StartEmpty` | `!NO_CLIENT_LIST` | Start the CMID lists empty instead of pre-charged |
| `-F` | bool | `FALSE` | `FreeBind` | `HAVE_FREEBIND` | Bind to non-local addresses (`IP_FREEBIND`/`IP_BINDANY`/`IP_NONLOCALOK`) |
| `-g` | `<group>` | no switch | `group` | `!NO_USER_SWITCH && !_WIN32` | `setgid` target: name or numeric gid. Failure is fatal at parse time. Skipped when `IsRestarted` |
| `-H` | `0..65535` | `0` (random) | `HostBuild` | `!NO_RANDOM_EPID` | Pin the KMS host build in generated ePIDs. **Side effect:** with randomization on and no explicit `-N`, forces `UseServerRpcNDR64 = (HostBuild > 7601)` |
| `-i` | `<file>` or `-` | `INI_FILE` or none | **none** | `!NO_INI_FILE` | Select the ini file. `-i -` disables a compiled-in default |
| `-j` | `<file>` or `-` | `<exedir>/vlmcsd.kmd` | `KmsData` | `!NO_EXTERNAL_DATA` | External KMS data file. `-j -` keeps the internal database. Sets `ExplicitDataLoad`, making a read failure fatal |
| `-k` | — | (default) | `DisconnectClientsImmediately = false` | `!USE_MSRPC` | Inverse of `-d`: keep the connection open |
| `-K` | `0..3` | `0` | `WhiteListingLevel` | `!NO_STRICT_MODES` | Product whitelisting bitmask (see §3.5) |
| `-l` | `<file>` or `syslog` | none | `LogFile` | `!NO_LOG` | Log destination |
| `-L` | `<ip>[:<port>]` | `::` and `0.0.0.0` | `Listen` (repeatable) | `!NO_SOCKETS && !USE_MSRPC && !SIMPLE_SOCKETS` | Add a listening socket. Repeatable. Numeric IPs only (`AI_NUMERICHOST`). IPv6 with a port must be bracketed |
| `-m` | `1..SEM_VALUE_MAX` | `SEM_VALUE_MAX` = no limit | `MaxWorkers` | `!NO_LIMIT && !NO_SOCKETS && !__minix__` | Concurrent worker cap via semaphore. MSRPC upper bound is `RPC_C_LISTEN_MAX_CALLS_DEFAULT`. Ignored in inetd mode |
| `-M` | bool | `FALSE` | `MaintainClients` | `!NO_CLIENT_LIST` | Maintain per-application CMID lists (max 671) |
| `-N` | bool | `TRUE`, then overridden from the `.kmd` flag / host build | `UseNDR64` | `!USE_MSRPC && !SIMPLE_RPC` | Accept the NDR64 transfer syntax. Setting it pins the value via `IsNDR64Defined` |
| `-o` | `0..3` | `0` | `PublicIPProtectionLevel` | `!NO_PRIVATE_IP_DETECT`; odd values need `HAVE_GETIFADDR` | Public-IP protection bitmask (see §9.5) |
| `-O` | `<adapter>[=<ip>][/<cidr>][:<lease>]` | off; defaults 10.10.10.9 `/30` `1d` | `VPN` | `!NO_TAP` (Windows/Cygwin) | Open and configure a TAP/TeamViewer VPN adapter. `.` = first compatible, `-` = disable an ini `VPN` |
| `-p` | `<file>` | none | `PIDFile` | `!NO_PID_FILE` | Write the pid after daemonizing; unlinked by `cleanup()` |
| `-P` | `<port>` | `1688` | `Port` | always | Default port. In full-socket builds it applies to all **subsequent** `-L` statements and **also disables every ini `Listen` line** |
| `-q` | — | (default) | `LogVerbose = false` | `!NO_VERBOSE_LOG` | Quiet (non-verbose) logging |
| `-r` | `0..2` | `1` | `RandomizationLevel` | `!NO_RANDOM_EPID` | ePID randomization level (see §6.2) |
| `-R` | timespan | `10080` (7 d) | `RenewalInterval` | `!NO_CUSTOM_INTERVALS` | `VLRenewalInterval` sent in every response |
| `-s` | — | — | none | `_NTSERVICE` | Install the Windows service. Rejected in inetd mode |
| `-S` | — | — | none | `_NTSERVICE` | Remove the Windows service. All other options ignored |
| `-t` | `1..600` seconds | `30` | `ConnectionTimeout` | `!NO_TIMEOUT && !__minix__ && !USE_MSRPC` | `SO_RCVTIMEO`/`SO_SNDTIMEO` on accepted sockets |
| `-T` | bool | `TRUE` | `LogDateAndTime` | `!NO_LOG` | Prefix log lines with date and time |
| `-u` | `<user>` | no switch | `user` | `!NO_USER_SWITCH && !_WIN32` | `setuid` target: name or numeric uid. Skipped when `IsRestarted` |
| `-U` | `<user>` | LocalSystem | none | `_NTSERVICE` | Service account. `/l` = LocalService, `/n` = NetworkService. Rejected without `-s` |
| `-v` | — | off | `LogVerbose = true` | `!NO_VERBOSE_LOG` | Verbose per-request field dumps |
| `-V` | — | — | none | `!NO_VERSION_INFORMATION` | Print version + platform + compile-time flags, exit 0. Ignored as an NT service |
| `-W` | `<password>` | empty | none | `_NTSERVICE` | Service account password. `SecureZeroMemory`d after `CreateService`. Rejected without `-s` |
| `-x` | `0..1` | `0` | `ExitLevel` | `!NO_SOCKETS` | Warning level at which vlmcsd exits with status −1 |
| `-Z` | — | off | none | **undocumented**; POSIX with sockets and SIGHUP only | SIGHUP restart marker: sets `IsRestarted` and `nodaemon`, suppressing re-daemonization, pid-file rewriting and the privilege drop. Appended automatically by the SIGHUP handler |

**Documented but not implemented:** `-h` and `-?` (`man/vlmcsd.8:37`). Neither letter is in the
option string; they reach `default:` and call `usage()`, so help *is* printed — on stderr, with exit
status `VLMCSD_EINVAL`, and degraded to "Incorrect parameters" under `-DNO_HELP`.

### 11.1 Argument syntax details

**Booleans** (`-c`, `-M`, `-E`, `-T`, `-F`, `-N`, `-B` and all ini booleans) are parsed by
`getArgumentBool()` (`src/helpers.c:407-431`), which accepts — case-insensitively and by **prefix** —
`true`/`on`/`yes`/`1` as TRUE and `false`/`off`/`no`/`0` as FALSE. Because the comparison is
`strncasecmp` over the keyword length, `-Myes`, `-c true`, `online`, `yesterday` and `0x10` are all
accepted. On the CLI a non-matching value calls `usage()`; in the ini it warns
`Argument must be true/on/yes/1 or false/off/no/0`.

**Time spans** (`-A`, `-R`, and the `:lease` part of `-O`) are a decimal number optionally followed
by one of `s`/`m`/`h`/`d`/`w`, case-insensitive; no suffix means minutes. `timeSpanString2Seconds()`
uses deliberate switch fall-through for the multipliers (`src/helpers.c:233-259`). For `-A`/`-R` the
value is converted to seconds and then integer-divided by 60 (`src/helpers.h:24`), so **any value
below 60 seconds becomes 0 and is rejected** as `Fatal: No valid time span specified in option -A`
(CLI) or `Incorrect time span.` (ini). An unrecognized suffix, or a suffix longer than one character,
also returns 0.

**Addresses**: `parseAddress()` (`src/helpers.c:312-339`) splits `host[:port]`, honouring
`[v6]:port` bracket syntax, and substitutes `defaultport` when no port is present. Because
`getaddrinfo` resolves the service string, an `/etc/services` name is accepted in the full-socket
build. `SIMPLE_SOCKETS` requires a numeric port 1..65535; MSRPC passes the string straight to
`RpcServerUseProtseqEpA`.

**HwId**: 16 hex digits after `/`, parsed by `hex2bin()` (`src/helpers.c:387-405`), which silently
skips non-hex characters — so `01 02 03 04 05 06 07 08` is valid.

---

## 12. Complete `vlmcsd.ini` reference

The ini file has **no sections** — `[Section]` produces `Unknown keyword.`. Syntax is flat
`keyword = argument` lines, UTF-8, **max 255 characters per line** (longer lines are split and the
tail parsed as a new line). Leading whitespace is skipped; lines starting with `#` or `;` and empty
lines are ignored. Only CR/LF are stripped from the end, so **trailing spaces stay part of the
argument** (`src/vlmcsd.c:860-937`).

A line matches a directive when the directive name is a case-insensitive **prefix** of the line
(`strncasecmp(name, line, strlen(name))`, `src/vlmcsd.c:834`), then whitespace and a mandatory `=`
must follow, then the argument with leading blanks skipped.

Errors print `Warning: <file> line N: "<line>". <message>` and skip the line. **vlmcsd never aborts
on an ini error** — deliberately, so a bad ini cannot brick a SIGHUP restart. This is the opposite of
CLI errors, which print help and exit.

The file is read in **up to three passes** (`src/vlmcsd.c:1756-1766`, `src/vlmcsd.c:1812-1822`,
`src/vlmcsd.c:1619-1630`):

1. General directives, plus counting `Listen` occurrences.
2. Per-CSVLK ePID/HwId lines, after the KMS database is loaded.
3. `Listen` lines only, inside `setupListeningSockets()`, and only if `-L`/`Listen` were counted but
   no socket exists yet.

**Precedence.** Compile-time defaults (`src/shared_globals.c`, `-DINI_FILE`, `-DDATA_FILE`, `-DHWID`)
< ini file < command line. The CLI wins structurally: every option with an ini twin calls
`ignoreIniFileParameter()`, which zeroes that directive's `Id` so `handleIniFileParameter()` returns
early without applying it (`src/vlmcsd.c:812-822`). Within the ini, the last occurrence of a general
directive wins (each simply overwrites the global), `Listen` accumulates, and **CSVLK ePID lines take
the first occurrence** because pass 2 uses `overwrite = FALSE`.

The complete directive table (`src/vlmcsd.c:122-190`) is 27 entries:

| Directive | Argument | Default | CLI twin | Compiled when |
|---|---|---|---|---|
| `ExitLevel` | `0..1` | `0` | `-x` | `!NO_SOCKETS` |
| `VPN` | `<adapter>[=<ip>][/<cidr>][:<lease>]` | off | `-O` | `!NO_TAP` |
| `KmsData` | `<file>` or `-` | `<exedir>/vlmcsd.kmd` | `-j` | `!NO_EXTERNAL_DATA` |
| `WhiteListingLevel` | `0..3` | `0` | `-K` | `!NO_STRICT_MODES` |
| `CheckClientTime` | bool | `false` | `-c` | `!NO_STRICT_MODES` |
| `StartEmpty` | bool | `false` | `-E` | `!NO_STRICT_MODES && !NO_CLIENT_LIST` |
| `MaintainClients` | bool | `false` | `-M` | `!NO_STRICT_MODES && !NO_CLIENT_LIST` |
| `RandomizationLevel` | `0..2` | `1` | `-r` | `!NO_RANDOM_EPID` |
| `LCID` | `0..32767` | `0` | `-C` | `!NO_RANDOM_EPID` |
| `HostBuild` | `0..65535` | `0` | `-H` | `!NO_RANDOM_EPID` |
| `Port` | port name or number | `1688` | `-P` | `!NO_SOCKETS && (USE_MSRPC \|\| SIMPLE_SOCKETS \|\| HAVE_GETIFADDR)` |
| `Listen` | `<ip>[:<port>]`, **repeatable** | `::` and `0.0.0.0` | `-L` | `!NO_SOCKETS && !USE_MSRPC && !SIMPLE_SOCKETS` |
| `FreeBind` | bool | `false` | `-F` | `HAVE_FREEBIND` |
| `MaxWorkers` | `1..SEM_VALUE_MAX` | no limit | `-m` | `!NO_LIMIT && !__minix__` |
| `ConnectionTimeout` | `1..600` | `30` | `-t` | `!NO_TIMEOUT && !__minix__ && !USE_MSRPC` |
| `DisconnectClientsImmediately` | bool | `false` | `-d` / `-k` | `!USE_MSRPC` |
| `UseNDR64` | bool | `true`, then overridden | `-N` | `!USE_MSRPC && !SIMPLE_RPC` |
| `UseBTFN` | bool | `true` | `-B` | `!USE_MSRPC && !SIMPLE_RPC` |
| `PIDFile` | `<file>` | none | `-p` | `!NO_PID_FILE` |
| `LogDateAndTime` | bool | `true` | `-T` | `!NO_LOG` |
| `LogFile` | `<file>` or `syslog` | none | `-l` | `!NO_LOG` |
| `LogVerbose` | bool | `false` | `-v` / `-q` | `!NO_LOG && !NO_VERBOSE_LOG` |
| `ActivationInterval` | timespan | `120` | `-A` | `!NO_CUSTOM_INTERVALS` |
| `RenewalInterval` | timespan | `10080` | `-R` | `!NO_CUSTOM_INTERVALS` |
| `user` | name or uid | no switch | `-u` | `!NO_USER_SWITCH && !_WIN32` |
| `group` | name or gid | no switch | `-g` | `!NO_USER_SWITCH && !_WIN32` |
| `PublicIPProtectionLevel` | `0..3` | `0` | `-o` | `!NO_PRIVATE_IP_DETECT` |

Plus the ePID lines handled in pass 2, one per CSVLK keyword from the database:

```
Windows      = <ePID> [ / <HwId> ]
Office2010   = <ePID> [ / <HwId> ]
Office2013   = <ePID> [ / <HwId> ]
Office2016   = <ePID> [ / <HwId> ]
Office2019   = <ePID> [ / <HwId> ]
WinChinaGov  = <ePID> [ / <HwId> ]
```

ePID and HwId are stored independently, so a later line can supply a HwId if an earlier line only
gave an ePID.

**CLI options with no ini twin:** `-e`, `-D`, `-i`, `-s`, `-S`, `-U`, `-W`, `-V`, `-Z`. So
`vlmcsd.ini.5:13`'s claim that "everything that can be configured in the ini file may also be
specified on the command line" holds — but the converse does not.

---

## 13. Complete `vlmcs` (client) CLI reference

The client option string (`src/vlmcs.c:363`) is:

```
+N:B:i:j:l:a:s:k:c:w:r:n:t:g:G:o:K:pPTv456mexdV
```

The leading `+` forces POSIXLY_CORRECT scanning, so parsing stops at the first non-option (the
target). vlmcs therefore runs each of its three parse passes **twice** — once over the whole argv,
once over `argv + hostportarg` — so `vlmcs -v host -n 5` works
(`src/vlmcs.c:1245-1273`, `man/vlmcs.1:9`). Passes are: pass 0 = `-j` only (the database must load
before anything else), pass 1 = `-l` only, pass 2 = everything else.

vlmcs reads **no ini file and no environment variables**. If an option is given twice the last
occurrence wins.

**Target:** the first non-option argument, `host[:port]`. A bare `host` or `ipv4:port` works; IPv6
must be bracketed (`[::1]:1688`). A single colon is treated as host:port, so an unbracketed IPv6
literal with more than one colon is passed whole to `getaddrinfo`. Default is `127.0.0.1:1688`, or
`[::1]:1688` when `-i6` was used (MSRPC builds always default to 127.0.0.1). Only **one** non-option
argument is accepted; a second triggers `clientUsage()` (`src/vlmcs.c:1247-1253`). A target of `-` or
one starting with `.` triggers DNS SRV discovery (§13.2).

| Flag | Argument | Default | Availability | Effect |
|---|---|---|---|---|
| `-4` | — | from `-l` | always | Force protocol major version 4, minor 0. Sets `VLMCS_OPTION_NO_GRAB_INI` |
| `-5` | — | from `-l` | always | Force version 5.0 |
| `-6` | — | from `-l` | always | Force version 6.0 |
| `-a` | `<AppGUID>` | from the selected SKU | always | Override the Application ID. Must be exactly 36 chars and parse via `string2UuidLE`, else `Fatal: Command line contains an invalid GUID.` |
| `-B` | `0\|1` | `1` | `!USE_MSRPC` | Offer BTFN as a third bind context item |
| `-c` | `<ClientGUID>` | random v4 UUID per request | always | Pin the CMID. **Side effect:** if `-n` was not already given, `FixedRequests` is forced to 1 |
| `-d` | — | off (DNS-style names) | always | Use NetBIOS-style random workstation names (1..14 chars from `0-9A-Z`) instead of DNS-style. No effect with `-w` |
| `-e` | — | — | `!NO_HELP` | Print 5 hard-coded usage examples and exit 0 |
| `-g` | `<minutes>` | `43200` (30 days) | always | `BindingExpiration` / remaining minutes in the current licensing status. Range `0..INT_MAX` |
| `-G` | `<file>` or `-` | disabled | always | Harvest ePID/HwId per CSVLK group from a (typically genuine) server into a vlmcsd ini file. `-` prints to stdout |
| `-i` | `4\|6` | `AF_UNSPEC` | `!USE_MSRPC` | Force the address family. `-i5` produces the joke error `IPv5 does not exist.` and exits EINVAL |
| `-j` | `<file>` | `<exedir>/vlmcsd.kmd` | `!NO_EXTERNAL_DATA` | External KMS data file (parse pass 0) |
| `-k` | `<KmsGUID>` | from the selected SKU | always | Override the KMS ID — the GUID a real host actually uses for grant/deny and counting |
| `-K` | `<major>.<minor>` | from `-l` / `-4-6` | always | Arbitrary, possibly invalid protocol version. Must contain a period; both parts `0..65535`; trailing garbage, a leading period or an empty minor part are rejected. Wire encoding still follows `<5 ? V4 : V6` |
| `-l` | `<name>` or `<1..SkuItemCount>` | index 0 = **"Windows Server 2019 ARM64"** | always | Select a SKU. Sets protocol version, N-count, SKU GUID, KMS GUID and App GUID in one shot (parse pass 1) |
| `-m` | — | 0 (bare metal) | always | Claim the client is a virtual machine |
| `-n` | `1..INT_MAX` | adaptive loop | always | Send exactly N requests regardless of the server's reported count |
| `-N` | `0\|1` | `1` | `!USE_MSRPC` | Offer NDR64 as a second bind context item |
| `-o` | `<PreviousClientGUID>` | all zeros | always | Set the "previous client machine ID" field |
| `-p` | — | multiplex on | `!USE_MSRPC` | Clear `RPC_PF_MULTIPLEX` in the bind, to test whether the server echoes it correctly |
| `-P` | — | sorting on | `!NO_DNS` | Skip RFC 2782 SRV priority/weight sorting; use DNS answer order |
| `-r` | `0..INT_MAX` | SKU `NCountPolicy` (25 client / 5 server & Office) | always | N-count policy sent in the request. Also becomes the target of the adaptive charging loop |
| `-s` | `<ActGUID>` | from the selected SKU | always | Override the SKU / Activation ID. Neither real nor emulated servers validate it |
| `-t` | `<status>` | `2` (OOB grace) | always | `LicenseStatus`. Documented range 0..6; the parser accepts `0..0x7fffffff` and only warns above 6 |
| `-T` | — | single reused connection | `!USE_MSRPC` | New TCP connection (close + reconnect + rebind) per request |
| `-v` | — | off | `!NO_VERBOSE_LOG` | Full request and response dumps, SRV candidate list, RPC bind progress |
| `-V` | — | — | `!NO_VERSION_INFORMATION` | Version + platform + common/client flags, exit 0 |
| `-w` | `<Workstation>` | random generated name | always | Fixed workstation name (UTF-8 → UCS-2LE into a 64-WCHAR buffer). Names >63 chars print a BEL-prefixed warning and are **silently truncated** |
| `-x` | — | — | `!NO_HELP` | List all SKU names with 1-based numbers in a column-major layout, exit 0 |

**Documented but not implemented:** `-h` and `-?` (`man/vlmcs.1:44`) — same `default:` fallthrough as
vlmcsd. There is also no `-q`, `-f` or `-D`.

`-G` is mutually exclusive with `-l`, `-4`, `-5`, `-6`, `-a`, `-s`, `-k`, `-r` and `-n`, enforced by
the `VLMCS_OPTION_GRAB_INI` / `VLMCS_OPTION_NO_GRAB_INI` bitmask check at `src/vlmcs.c:630-631`.
**`-K` is not in that exclusion set** even though it defeats the `-G` version-stepping loop.

### 13.1 Request loop behaviour

Without `-n`, the loop is adaptive (`src/vlmcs.c:1288-1328`): `RequestsToGo` starts at
`NCountPolicy == 1 ? 1 : NCountPolicy - 1` and after each successful response is recomputed as
`NCountPolicy - response.Count` (clamped at 0). If after the first request the count has not risen
enough (`NCountPolicy - Count >= RequestsToGo`), vlmcs prints `The KMS server does not increment it's
active clients. Aborting...` and stops. Progress is printed as `<i> of <total>`. This is what makes a
plain `vlmcs <host>` "charge" a server: 24 requests for a Windows client SKU, 4 for a server/Office
SKU.

vlmcs is strictly **sequential and single-threaded** — one connection, one request at a time. There
is no fan-out option; `USE_THREADS` affects only the server side. Load testing is done with a large
`-n` (the built-in examples suggest 100000) and optionally `-T`.

Socket timeouts are a **hard-coded 10 seconds** (`SO_RCVTIMEO`/`SO_SNDTIMEO`) set in
`connectToAddress()`; vlmcs has no timeout option at all. `EINPROGRESS` is rendered as `Timed out`.
vlmcs also auto-reconnects if `isDisconnected()` sees the peer went away, printing
`Warning: Server closed RPC connection (probably non-multitasked KMS emulator)`.

### 13.2 DNS SRV discovery

If the target is `-` (own domain) or begins with `.` (an explicit domain), vlmcs queries SRV records
for `_vlmcs._tcp[.domain]` (`src/dns_srv.c:141-320`, `src/vlmcs.c:760-831`):

* Unix: `res_init` + `res_querydomain("_vlmcs._tcp", domain+1, ns_c_in, ns_t_srv)` on
  glibc/uClibc/Android/Apple/Cygwin/BSD/Solaris, `res_query` on other libcs, and
  `res_search("_vlmcs._tcp")` for the `-` case.
* Windows: `DnsQuery_UTF8` with `DNS_TYPE_SRV`; for `-` the domain comes from
  `GetComputerNameExA(ComputerNamePhysicalDnsDomain)`.

Answers are parsed into `{priority, weight, port, name}`, the port is appended as `name:port`, and
non-SRV / non-IN records are warned about and skipped. The receive buffer is a fixed 2048 bytes. By
default records are sorted RFC 2782-style — each gets
`random_weight = (rand32() % 256) * isqrt(weight * 1000)`, ordered by ascending priority then
descending random weight (`src/dns_srv.c:79-131`) — unless `-P` is given. vlmcs then tries each
candidate until connect + RPC bind succeeds; if none works it exits `SOCKET_ECONNABORTED` with
`Fatal: Could not connect to any KMS server`. The list is resolved once and cached in a
function-static.

**vlmcsd never publishes, registers or looks up SRV records.** `src/dns_srv.c`, `src/ns_name.c` and
`src/ns_parse.c` are compiled into the **client only** (`src/vlmcs.c:763`, `src/vlmcs.c:771`). A real
KMS host registers `_vlmcs._tcp` via dynamic DNS; vlmcsd does not, so clients must be pointed at it
explicitly (`slmgr /skms`) or an SRV record must be created out of band.

### 13.3 Random workstation names

With no `-w`, vlmcs synthesises a name per request (`src/vlmcs.c:107-112`, `src/vlmcs.c:1385-1409`).
DNS mode concatenates one random pick from each of three tables:

* `first[16]` = `www, ftp, kms, hack-me, smtp, ns1, mx1, ns1, pop3, imap, mail, dns, headquarter,
  we-love, _vlmcs._tcp, ceo-laptop` (note `ns1` appears **twice**)
* `second[16]` = `.microsoft, .apple, .amazon, .samsung, .adobe, .google, .yahoo, .facebook,
  .ubuntu, .oracle, .borland, .htc, .acer, .windows, .linux, .sony`
* `tld[22]` = `.com, .net, .org, .cn, .co.uk, .de, .com.tw, .us, .fr, .it, .me, .info, .biz, .co.jp,
  .ua, .at, .es, .pro, .by, .ru, .pl, .kr`

NetBIOS mode (`-d`) emits 1..14 characters from `0-9A-Z`. The lowercase alphabet is present in the
source but commented out of the alphanumeric table.

### 13.4 Response validation and emulator detection

A 32-bit `RESPONSE_RESULT` bitfield (`src/kms.h:204-227`) records `HashOK`, `TimeStampOK`,
`ClientMachineIDOK`, `VersionOK`, `IVsOK`, `DecryptSuccess`, `HmacSha256OK`, `PidLengthOK`, `RpcOK`
and `IVnotSuspicious`, plus 9-bit `effectiveResponseSize` and `correctResponseSize`.

`DecryptResponseV4` recomputes the CBC-MAC and compares version/time/CMID. `DecryptResponseV6`
validates padding, checks that **all four** version fields agree (request base, request header,
response base, response header), verifies the SHA-256 salt proof, and applies the version-specific IV
and HMAC rules. `checkPidLength()` requires `PIDSize <= 128`, a final zero WCHAR, and no interior
zeros (`src/kms.c:964-977`).

Each failure prints its own BEL-prefixed line (`src/vlmcs.c:663-687`): non-zero RPC result code, V5/V6
decryption failure, AES-CBC IV mismatch, invalid PID length, hash mismatch, CMID mismatch, timestamp
mismatch, protocol version mismatch, HMAC-SHA256 mismatch, `Size of RPC payload (KMS Message) should
be %u but is %u`, and the emulator warning described in §3.4. `checkRpcLevel()` additionally warns if
the server has no NDR32, or has NDR64 but no BTFN (compiled out under `USE_MSRPC`).

The source is explicit about the purpose: "A basic client doesn't need the stuff below this comment
but we want to use vlmcs as a debug tool for KMS emulators."

Known-HRESULT decoding (`src/vlmcs.c:903-937`): `0xC004F042` "The KMS server has declined to activate
the requested product"; `0x8007000D` "The KMS host you are using is unable to handle your product. It
only supports legacy versions"; `0xC004F06C` "The time stamp differs too much from the KMS server
time"; `0xC004D104` "The security processor reported that invalid data was used"; `1` = RPC protocol
error, which triggers an automatic close and reconnect. On Windows anything else uses
`win_strerror()`.

### 13.5 `-G` ini harvesting

`grabServerData()` (`src/vlmcs.c:1086-1203`) queries once per CSVLK/ePID group. It starts at protocol
v6 and, on any `0x8xxxxxxx` error, decrements the major version and retries the same group (walking
6 → 5 → 4); an RPC protocol error (status 1) aborts. For each group it picks the first KMS item whose
`EPidIndex` matches, then the last SKU item using that KMS index, and builds
`<GroupName> = <ePID>` plus ` / XX XX XX XX XX XX XX XX` when the response was v6.

`updateIniFile()` (`src/vlmcs.c:939-1083`) renames the existing target to `<file>~` (creating an empty
backup first if the file did not exist), then streams the old file line by line: any line whose
prefix case-insensitively matches a known group key is replaced by the freshly grabbed line (first
match only, tracked by a `lineWritten[]` array); all other lines pass through unchanged; unmatched new
lines are appended. Progress is echoed as `line NN: <content>`. Any I/O failure is fatal. On Windows
the backup is unlinked before rename because `rename()` will not overwrite. If the file did not exist
before, the empty backup is unlinked at the end.

---

## 14. libkms

### 14.1 Exported API

Ten `__cdecl` entry points (`src/libkms.h:21-31`, `src/libkms.c:49-207`):

| Function | Signature / returns |
|---|---|
| `GetLibKmsVersion()` | `int` — currently `0x40000` (4.0) |
| `GetEmulatorVersion()` | `const char*` — the `VERSION` string |
| `GetErrorMessage()` | `char*` — pointer to the accumulated error buffer |
| `ConnectToServer(host, port, addressFamily)` | `SOCKET` — formats `"[host]:port"` and calls `connectToAddress`; initialises Winsock on demand |
| `BindRpc(sock, useMultiplexedRpc, useRpcNDR64, useRpcBTFN, PRpcDiag_t)` | `RpcStatus` — sets the three globals then calls `rpcBindClient(verbose=FALSE)` |
| `IsDisconnected(sock)` | `int_fast8_t` |
| `SendKMSRequest(sock, RESPONSE*, REQUEST*, RESPONSE_RESULT*, BYTE* hwid)` | `DWORD` — thin wrapper over `SendActivationRequest`, the only piece of `vlmcs.c` compiled into the library |
| `CloseConnection(sock)` | — |
| `StartKmsServer(port, RequestCallback_t)` | `DWORD` — **blocks** |
| `StopKmsServer()` | `DWORD` |

### 14.2 Server embedding model

An embedder supplies
`HRESULT __stdcall (*RequestCallback_t)(REQUEST* baseRequest, RESPONSE* const baseResponse, BYTE* const hwId, const char* const ipstr)`
(`src/kms.h:378`) and calls `StartKmsServer(port, cb)`, which stores it in the global
`CreateResponseBase`, initialises Winsock on Windows, opens listening sockets and then calls
`runServer()` — which **blocks in an accept loop until the sockets are closed**. `IsServerStarted`
guards against a second concurrent start (returns `SOCKET_EALREADY`). `StopKmsServer()` returns
`VLMCSD_EPERM` if not started, otherwise calls `closeAllListeningSockets()` so the accept loop fails
and `runServer()` returns.

In library builds `CreateResponseBase` is initialised to **NULL** (`src/kms.c:746`), so a NULL
callback dereferences on the first request. Because `IS_LIBRARY` strips `loadKmsData()`, libkms has
**no product database at all** — the embedder's callback must produce the ePID itself.

Two socket backends exist (`src/libkms.c:106-181`). The non-`SIMPLE_SOCKETS` one probes
`checkProtocolStack()`, allocates `SocketList` and calls `addListeningSocket("0.0.0.0:<port>")` and/or
`addListeningSocket("[::]:<port>")`, returning `SOCKET_EAFNOSUPPORT` or `SOCKET_EADDRNOTAVAIL` on
failure. The `SIMPLE_SOCKETS` one — **the one the shipped `LIBRARY_CFLAGS` actually build** — writes
the port into the global `defaultport` and calls `listenOnAllAddresses()`.

### 14.3 Thread safety

**libkms is not thread-safe.** It relies on process-global mutable state: `ErrorMessage` (one
4096-byte buffer that `printerrorf` appends to and only some entry points reset),
`CreateResponseBase`, `UseMultiplexedRpc` / `UseClientRpcNDR64` / `UseClientRpcBTFN` (set by
`BindRpc` for **all** connections), `RpcFlags`, `CallId` and `firstPacketSent` in `rpc.c`,
`IsServerStarted`, `s_server` / `SocketList`, and `defaultport`. Concurrent `BindRpc` /
`SendKMSRequest` calls on different sockets will interfere. There is no documented threading
contract; the man pages do not cover libkms at all.

The embedder's callback, by contrast, is invoked from a forked child or a worker thread per
connection depending on `USE_THREADS`.

### 14.4 Build flags and export mechanism

`LIBRARY_CFLAGS` (`src/GNUmakefile:260`, `src/GNUmakefile:537-563`) compiles both the shared and
static objects with `-DIS_LIBRARY=1 -fvisibility=hidden` plus a fixed stripping set:

```
-DSIMPLE_SOCKETS -DNO_TIMEOUT -DNO_SIGHUP -DNO_CL_PIDS -DNO_LOG -DNO_RANDOM_EPID -DNO_INI_FILE
-DNO_HELP -DNO_CUSTOM_INTERVALS -DNO_PID_FILE -DNO_USER_SWITCH -DNO_VERBOSE_LOG -DNO_LIMIT
-DNO_VERSION_INFORMATION -DNO_PRIVATE_IP_DETECT -DNO_STRICT_MODES -DNO_CLIENT_LIST -DNO_TAP
-UNO_SOCKETS -USIMPLE_RPC -UUSE_MSRPC
```

`IS_LIBRARY` also makes `printerrorf` append to `ErrorMessage` instead of writing stderr/log, removes
`getProductIndex`/`getNextString`/`loadKmsData`/`exitOnWarningLevel`/`getOptionArgumentInt`/`optReset`,
and reduces `vlmcs.c` to just `SendActivationRequest`.

`DLL_SRCS` = `libkms.c vlmcs.c crypto.c kms.c endian.c output.c shared_globals.c helpers.c network.c
rpc.c crypto_internal.c`, compiled through the `../build/%-l.o` rule with `$(PICFLAGS)` (`-fPIC` on
ELF) and linked `-shared`. `make libkms-static` uses the `%-a.o` rule and `$(AR) rcs`. Output names:
`lib/libkms.so`, `lib/libkms.dylib` (Darwin), `lib/libkms.dll` (MinGW), `lib/cygkms.dll` (Cygwin),
`lib/libkms.a` — all overridable via `DLL_NAME` / `A_NAME`. `OBJ_NAME` (a single combined `.o`) can
only be built with `CAT` defined.

Export mechanism: `src/types.h:33-50` maps `__declspec(x)` to
`__attribute__((__visibility__("default")))` on non-Windows and defaults `EXTERNAL` to `dllimport`.
`libkms.c` `#undef`s and redefines `EXTERNAL` to `dllexport` before including `libkms.h`, so one
header serves both the library build and its consumers, and only the ten API symbols are exported.
On MSVC/MinGW this becomes a real `__declspec` pair, so the Windows DLL works without a `.def` file.

`src/libkms-test.c` is a ~40-line sample embedder with **no build rule in any makefile** — you must
compile it by hand. Its callback signature does not match `RequestCallback_t` (see §17.4).

---

## 15. vlmcsdmulti

`main()` stores `argv`/`argc` into the globals `multi_argv`/`multi_argc` (so the SIGHUP re-exec
handler can rebuild the original command line), then dispatches on `basename(argv[0])`:
`vlmcsd` → `server_main(argc, argv)`, `vlmcs` → `client_main(argc, argv)`. On `_WIN32` it also
accepts `vlmcsd.exe` and `vlmcs.exe`. If neither matches and `argc > 1`, it dispatches on `argv[1]`:
`vlmcsd` → `server_main(argc-1, argv+1)`, `vlmcs` → `client_main(argc-1, argv+1)`. Otherwise it prints
a two-line usage to stderr and returns `VLMCSD_EINVAL` (`src/vlmcsdmulti.c:62-99`).

The name-comparison macro is `strcasecmp` on Windows/Cygwin and `strcmp` on native Unix
(`src/vlmcsdmulti.c:29-33`). Only two applets exist — there is no third applet and no built-in
"install symlinks" helper.

Build mechanics: the target-specific rule `$(REAL_MULTI_NAME): BASECFLAGS += -DMULTI_CALL_BINARY=1`
(`src/GNUmakefile:350`) turns `#define client_main main` / `#define server_main main`
(`src/vlmcs.h:20-24`, `src/vlmcsd.h:21-25`) into real function declarations so both mains coexist.
`MULTI_OBJS` uses a separate `%-m.o` object rule for `vlmcsd.c`, `vlmcs.c` and `vlmcsdmulti.c`.
`MULTI_CALL_BINARY` also suppresses the duplicate `midl_user_allocate`/`midl_user_free` definitions in
`msrpc-client.c` and the MSVC `WinStartUp` entry point. Compiling `vlmcsdmulti.c` without
`MULTI_CALL_BINARY >= 1` is a hard `#error`.

vlmcsdmulti always links the **full** `kmsdata-full.c` (`src/GNUmakefile:388-389`).

`man/vlmcsdmulti.1:40-42` notes that vlmcsdmulti saves disk space but costs RAM when run as a daemon,
and recommends running it from inetd/xinetd instead.

---

## 16. Build system

Two-level recursive GNU make. There is no autoconf, no cmake, and **no `install`, `uninstall`, `dist`
or `test` target anywhere**.

The top-level `GNUmakefile` is a dispatcher: `.DEFAULT` and `all` create `bin/`, `lib/` and `build/`
then re-invoke `$(MAKE) -j$(MAX_THREADS) -C src <target> FROM_PARENT=1 PROGRAM_NAME=... ...`
(`GNUmakefile:105-131`). Doc targets are forwarded to `man/`. `.NOTPARALLEL:` prevents the dispatcher
itself running in parallel. `src/GNUmakefile` rewrites relative output names with a `../` prefix when
`FROM_PARENT=1`. A top-level `Makefile` exists solely to tell BSD make users to run `gmake`.

**Target platform detection** is scraped from `$(CC) -v 2>&1 | grep '^Target: '`
(`src/GNUmakefile:72-73`). Substring matches set `DARWIN`, `ANDROID`, `MINIX`, `MINGW`, `CYGWIN`
(from both `cygwin` and `cygnus`), `FREEBSD`, `NETBSD`, `OPENBSD`, `SOLARIS`, `LINUX` or `HURD`, plus
the umbrella flags `UNIX`, `WIN`, `PE`, `BSD`, `ELF`. Cross-compilation is done purely by pointing
`CC` at a cross toolchain — everything else follows. Whenever a make variable changes you must
`make clean` or add `-B`.

**Base flags.** `BASECFLAGS` always contains `-DVLMCSD_COMPILER`, `-DVLMCSD_PLATFORM`,
`-DCONFIG="<config.h>"`, `-DBUILD_TIME=$(date +%s)`, `-g -Os -fno-strict-aliasing
-fomit-frame-pointer -ffunction-sections -fdata-sections`, and (unless `CAT=2`) `-Wall`. Unless
`SAFE_MODE` is defined it adds `-fvisibility=hidden -pipe -fno-common -fno-exceptions
-fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -fmerge-all-constants`, plus
`-Wl,-z,norelro` on ELF and `-flto` when the compiler basename contains `gcc`
(`src/GNUmakefile:161-182`). Linking adds `-Wl,--gc-sections` (except when `CC` is literally `tcc`),
`-Wl,-S -Wl,-x` on Darwin and `-s` elsewhere unless `STRIP=0`.

**Documentation targets** (`man/GNUmakefile:1-40`): `alldocs`, `pdfdocs` (groff `-Tpdf`, or
`-Tps | pstopdf` on Darwin), `htmldocs` (`-Thtml`), `unixdocs` (`-Tascii | col -bx`), `dosdocs` (awk
CRLF conversion), `clean`. Generated `.txt`/`.html`/`.pdf` are gitignored.

**Bootable floppy** (`man/vlmcsd-floppy.7`): a documented 1.44 MB FAT12 bootable image containing a
minimal Linux plus vlmcsd, needing 16 MB RAM, configured entirely through `syslinux.cfg` kernel
command-line parameters (`LISTEN=`, `IPV4_CONFIG=`, `TZ=`, `NTP_SERVER=`, `HOST_NAME=`,
`ROOT_PASSWORD=`, `INETD=`, `WINDOWS=`, `OFFICE2010=`, `OFFICE2013=`, `OFFICE2016=`, `OFFICE2019=`,
`WINCHINAGOV=`, `HWID=`, …). Supported NICs: Intel PRO/1000, AMD PCNET III/32, VMware vmxnet3, virtio.
**Only the man page is in this repository** — the image and its build scripts are not (`floppy/` is
gitignored). There is no DOS/FreeDOS build; the only "DOS" in the tree is the CRLF text-doc target.

### 16.1 Make variable reference

| Variable | Effect | Default |
|---|---|---|
| `CONFIG=<header>` | Alternative config header (`-DCONFIG="x"`); every source includes it | `config.h` |
| `FEATURES=` | Preset macro bundles (below) | `full` |
| `CRYPTO=` | `internal` \| `openssl` \| `openssl_with_aes` \| `openssl_with_aes_soft` \| `polarssl` \| `windows` | `internal` |
| `OPENSSL_HMAC=0` | `-D_OPENSSL_NO_HMAC` for OpenSSL builds lacking HMAC | unset |
| `MSRPC=1` | `-DUSE_MSRPC -Wno-unknown-pragmas -lrpcrt4`, swaps in `msrpc-*.c` and the MIDL stubs | unset |
| `THREADS=1` | `-DUSE_THREADS` plus `-lpthread` | unset (forced on `_WIN32`) |
| `NO_DNS=1` | Drops `dns_srv.c`, `-P` and SRV targets from vlmcs | unset |
| `DNS_PARSER=OS\|internal` | `internal` adds `ns_parse.c`/`ns_name.c` and `-DDNS_PARSER_INTERNAL`; forced internal on Cygwin and OpenBSD; irrelevant on MinGW | `OS` |
| `GETIFADDRS=musl` | Compiles `getifaddrs-musl.c` with `-DGETIFADDRS_MUSL` | platform `getifaddrs()` |
| `NO_GETIFADDRS=1` | `-DNO_GETIFADDRS`; kills `-o1`/`-o3` | unset |
| `NOLIBS=1` / `NOLRESOLV=1` / `NOLPTHREAD=1` | Suppress automatic `-lresolv`/`-ldnsapi` and `-lpthread` detection (needed for the Android NDK) | autodetect |
| `NO_TIMEOUT=1` | `-DNO_TIMEOUT`; removes all socket timeouts and `-t` | unset (implied on Minix) |
| `CHILD_HANDLER=1` | `-DCHILD_HANDLER`; explicit SIGCHLD reaper | unset (implied on Minix) |
| `NOPROCFS=1` / `AUXV=1` | `-DNO_PROCFS` / `-DUSE_AUXV`; select the `getExeName()` strategy | procfs where available |
| `INI=<path>` | `-DINI_FILE` — default ini path | unset |
| `DATA=<path>` | `-DDATA_FILE` — default `.kmd` path; disables the exe-relative auto-detection | unset |
| `HWID=<bytes>` | `-DHWID` — the KMSv6 fallback hardware id | `0x3A,0x1C,0x04,0x96,0x00,0xB6,0x00,0x76` |
| `TERMINAL_WIDTH=<n>` | `-DTERMINAL_FIXED_WIDTH` + `-DDISPLAY_WIDTH` for `vlmcs -x` | auto-detected (TIOCGWINSZ / GetConsoleScreenBufferInfo / 80) |
| `FD_SETSIZE=<n>` | Caps the number of `-L` sockets (the accept loop uses `select()`) | 64 Windows / 1024 most Unixes |
| `VLMCSD_VERSION=<x>` | Baked into `-DVERSION` with the UTC build timestamp | `git describe`, else `"private build"` |
| `PROGRAM_NAME` / `CLIENT_NAME` / `MULTI_NAME` / `DLL_NAME` / `A_NAME` / `OBJ_NAME` | Output paths | `bin/vlmcsd`, `bin/vlmcs`, `bin/vlmcsdmulti`, `lib/libkms.*`, `lib/libkms.a`, `build/libkms-static.o` |
| `CC` / `AR` / `COMPILER_LANGUAGE` | Compiler (also the cross-compile mechanism and platform-detection source), archiver (use `gcc-ar` for LTO), `-x` language | `gcc`, `ar`, `c` |
| `CFLAGS` / `LDFLAGS` / `PLATFORMFLAGS` | Append; `PLATFORMFLAGS` is passed to both compiler and linker | empty |
| `BASECFLAGS` / `BASELDFLAGS` | **Replace** the built-in flag sets entirely | see above |
| `SAFE_MODE` | **Undocumented.** Removes `-fvisibility=hidden -pipe -fno-common -fno-exceptions -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -fmerge-all-constants`, `-Wl,-z,norelro` and `-flto` | unset |
| `STRIP=0` | Keep debug information | unset (stripped) |
| `VERBOSE=1\|3` | `1` echoes real commands; `3` pads the compiler/archiver name to 40 columns | terse labelled output |
| `DEPENDENCIES=1\|2` | `1` emits `.d` files via a second `-MM` pass; `2` uses `-MMD` (**undocumented**) | unset |
| `CAT=1\|2` | Concatenate all sources into one translation unit (`cat $^ \| $(CC) -x c -o $@ -`), a poor-man's LTO; `2` also drops `-Wall`. Also adds `-DONE_FILE`, which no source tests | unset |
| `MAX_THREADS` | `-j` level of the recursive make | 16 |
| `WINDOWS=` / `OFFICE2010=` / `OFFICE2013=` / `OFFICE2016=` | Emit `-DEPID_WINDOWS` / `-DEPID_OFFICE20xx`. **No source file reads these — dead knobs** | unset |

Default build output is one line per step: `<compiler>\tCC\t<obj> <- <src>`,
`<compiler>\tLD\t<target> <- <objs>`, `<archiver>\tAR\t<lib> <. <objs>`, `<compiler>\tDEP\t<file>.d <- <src>`.

### 16.2 `FEATURES=` presets

| Preset | Expands to |
|---|---|
| `full` (default) | nothing |
| `most` | `NO_SIGHUP NO_PID_FILE NO_LIMIT` |
| `autostart` | `NO_HELP NO_VERSION_INFORMATION` |
| `embedded` | `NO_HELP NO_USER_SWITCH NO_CUSTOM_INTERVALS NO_PID_FILE NO_VERBOSE_LOG NO_VERSION_INFORMATION` |
| `inetd` | `NO_SIGHUP NO_SOCKETS NO_PID_FILE NO_LIMIT NO_VERSION_INFORMATION` |
| `fixedepids` | `NO_SIGHUP NO_CL_PIDS NO_RANDOM_EPID NO_INI_FILE` |
| `minimum` | `SIMPLE_RPC SIMPLE_SOCKETS NO_TIMEOUT NO_SIGHUP NO_CL_PIDS NO_LOG NO_RANDOM_EPID NO_INI_FILE NO_HELP NO_CUSTOM_INTERVALS NO_PID_FILE NO_USER_SWITCH NO_VERBOSE_LOG NO_LIMIT NO_VERSION_INFORMATION NO_PRIVATE_IP_DETECT SMALL_AES NO_STRICT_MODES NO_TAP NO_CLIENT_LIST UNSAFE_DATA_LOAD NO_EXTERNAL_DATA -UFULL_INTERNAL_DATA -U_PEDANTIC` |

### 16.3 Compile-time feature macros

| Macro | Effect | Default | Evidence |
|---|---|---|---|
| `USE_THREADS` | Threads instead of `fork()`; process-local semaphore; heap CMID lists; log mutex + 2048-byte format buffer; no SIGCHLD handler | unset; **forced on `_WIN32`** | `src/config.h:226-248`, `src/types.h:240` |
| `USE_MSRPC` | Delegate to the Windows RPC runtime; removes `-L`, `-t`, `-d`/`-k`, `-N`/`-B` and their ini twins; caps `MaxTasks`; weakens `-o2`. Incompatible with `NO_SOCKETS`/`SIMPLE_SOCKETS` | unset | `src/vlmcsd.h:10-18`, `src/msrpc-server.c:41-90` |
| `SIMPLE_RPC` | Remove NDR64/BTFN, fault PDUs and context-id demultiplexing from the server; removes `-N`/`-B` | unset | `src/config.h:646-654`, `src/rpc.c:473-563` |
| `SIMPLE_SOCKETS` | Single dual-stack wildcard socket; removes `-L`/`Listen`, keeps `-P`/`Port` | unset (**on for libkms**) | `src/config.h:659-667`, `src/network.c:320-375` |
| `NO_SOCKETS` | inetd-only build; hardcodes `InetdMode`/`nodaemon`; removes `-L -P -m -t -e -D -x -s -S` and the NT service code; implies `NO_SIGHUP`, `NO_TAP`, `NO_CLIENT_LIST` | unset | `src/config.h:580-589`, `src/types.h:228-238` |
| `NO_LIMIT` | Remove `-m`/`MaxWorkers` and all semaphore/shm code; also suppresses automatic `-lpthread`. Auto-defined when `_POSIX_THREADS` is unavailable | unset | `src/config.h:607-621`, `src/types.h:102` |
| `NO_SIGHUP` | Remove the exec-self restart, `-Z`, `IsRestarted` and `FD_CLOEXEC` on listeners. Auto-defined for Cygwin, Windows and `NO_SOCKETS` | unset on POSIX | `src/config.h:626-641`, `src/types.h:236` |
| `NO_TIMEOUT` | Remove `SO_RCVTIMEO`/`SO_SNDTIMEO` and `-t`/`ConnectionTimeout`. Implied on Minix | unset | `src/config.h:107-115` |
| `CHILD_HANDLER` | Explicit `SIGCHLD` `waitpid(WNOHANG)` handler for platforms where `SA_NOCLDWAIT` does not reap | unset | `src/config.h:93-104` |
| `NO_FREEBIND` / `HAVE_FREEBIND` | `HAVE_FREEBIND` is derived from the presence of `IP_BINDANY`/`IP_FREEBIND`/`IPV6_BINDANY`/`IP_NONLOCALOK` and the absence of `NO_FREEBIND`, `USE_MSRPC`, `SIMPLE_SOCKETS`; gates `-F`/`FreeBind` | enabled on Linux/FreeBSD | `src/types.h:78`, `src/config.h:350-359` |
| `NO_GETIFADDRS` / `HAVE_GETIFADDR` | Gates `-o1`/`-o3` and the ini `Port` key in non-MSRPC builds | `HAVE_GETIFADDR` on unless excluded | `src/types.h:82-84` |
| `NO_PRIVATE_IP_DETECT` | Remove `-o`/`PublicIPProtectionLevel` entirely | unset | `src/config.h:567-575` |
| `NO_LOG` | Remove `logger()`, file, syslog, `-l -e -v -q -T` and the `LogFile`/`LogVerbose`/`LogDateAndTime` keys; `printerrorf` always uses stderr | unset | `src/config.h:401-410` |
| `NO_VERBOSE_LOG` | Remove `-v`/`-q` and the verbose dumps only | unset | `src/config.h:388-396` |
| `NO_VERSION_INFORMATION` | Remove `-V` from both binaries and all the `print*Flags` functions | unset | `src/config.h:376-383` |
| `NO_HELP` | Remove the option lists, `vlmcs -x` and `vlmcs -e`; usage degrades to "Incorrect parameters" | unset | `src/config.h:540-548` |
| `NO_USER_SWITCH` | Remove `-u`/`-g` and the `user`/`group` keys | unset | `src/config.h:522-535` |
| `NO_PID_FILE` | `writePidFile()` becomes an empty macro; removes `-p`/`PIDFile` | unset | `src/config.h:468-477` |
| `NO_TAP` | Remove `-O`/`VPN`. Auto-defined off Windows/Cygwin and with `NO_SOCKETS` | auto | `src/config.h:364-371`, `src/types.h:231` |
| `NO_INI_FILE` / `INI_FILE` | Remove `-i` and all ini parsing / compile in a default ini path | no default ini | `src/config.h:58-66`, `src/config.h:456-463` |
| `NO_STRICT_MODES` | Remove `-K -c -M -E` and their ini keys (behaves as `-K0 -M0`); also removes the >1000-client rejection; selects the 1122-byte database. Implies `NO_CLIENT_LIST` | unset | `src/config.h:415-424` |
| `NO_CLIENT_LIST` | Remove `-M`/`-E` and the CMID list. Auto-defined by `NO_STRICT_MODES`, `NO_SOCKETS`, or missing `_POSIX_THREADS`/`_POSIX_THREAD_PROCESS_SHARED` | unset | `src/config.h:430-438`, `src/types.h:90-100` |
| `NO_RANDOM_EPID` | Remove `-r -C -H` and their ini keys; level hardcoded to 0 | unset | `src/config.h:442-451` |
| `NO_CL_PIDS` | Remove `-a` (the ini form still works) | unset | `src/config.h:594-602` |
| `NO_CUSTOM_INTERVALS` | Remove `-A`/`-R` and their ini keys; hard-coded 120/10080 still sent | unset | `src/config.h:553-562` |
| `NO_EXTERNAL_DATA` | Remove `-j`/`KmsData` and the whole file loader. **Implies `UNSAFE_DATA_LOAD`** | unset | `src/config.h:482-490`, `src/types.h:72-76` |
| `NO_INTERNAL_DATA` | No compiled-in database; an external file becomes mandatory. Mutually exclusive with `NO_EXTERNAL_DATA` (`#error`) | unset | `src/config.h:495-504`, `src/types.h:17-19` |
| `UNSAFE_DATA_LOAD` | Skip every integrity check on an external `.kmd` | unset (checks on) | `src/config.h:509-517` |
| `FULL_INTERNAL_DATA` | Embed the 15085-byte 202-SKU database in vlmcsd instead of the 1858-byte one | unset | `src/config.h:331-337` |
| `_PEDANTIC` | Extra validation and warnings: RPC bind/request field checks, RFC 4122 v4 UUID checks on request GUIDs, license-status/VM range checks, LCID and host-build validation, NCA protocol-error faults, socket-option failure warnings, `FD_SETSIZE` overflow warnings, the `-D`-on-Windows warning | unset | `src/config.h:144-153` |
| `SMALL_AES` | Drop the 256-byte inverse S-box; compute it by searching the forward S-box | unset | `src/crypto.c:218-255` |
| `NO_COMPILER_UAA` | Disable compiler byte-swap/unaligned-access builtins; force the portable `endian.c` paths | unset | `src/endian.h:13-59` |
| `USE_AUXV` / `NO_PROCFS` | `getExeName()` strategy. `USE_AUXV` needs glibc ≥ 2.16 or musl — it does **not** work on uClibc or older glibc | procfs | `src/config.h:158-199` |
| `SUPPORT_WINE` | Adds code so a Windows MSRPC build runs under Wine | unset | `src/msrpc-server.c:136-145` |
| `INCLUDE_BETAS` | Printed as a flag by `-V`; **no source changes behaviour based on it — vestigial** | unset | `src/output.c:516-518` |
| `MULTI_CALL_BINARY` | `=1` turns `client_main`/`server_main` into real functions; required to compile `vlmcsdmulti.c` | 0 | `src/vlmcs.h:20-24`, `src/vlmcsdmulti.c:10-12` |
| `IS_LIBRARY` | libkms flavour (see §14.4) | unset | `src/GNUmakefile:537-563` |
| `HWID` / `VERSION` / `BUILD_TIME` / `DATA_FILE` | Compile-time constants | see §16.1 | `src/config.h:22-80` |

There is **no macro named `SMALL_BUILD`** anywhere in the tree; size reduction is done via `FEATURES=`
presets and the individual `NO_*` macros.

`-V` is the reliable way to determine which of these mutually-exclusive runtime models a given binary
actually implements: `printPlatform()`, `printCommonFlags()`, `printServerFlags()` and
`printClientFlags()` enumerate the exact compile-time feature set built in (`src/output.c:256-600`).

---

## 17. Gaps, quirks, and doc/code mismatches

### 17.1 Memory safety

**Remote OOB array read plus indirect call through a wild function pointer (server).**
`checkRpcRequestSize()` reads the KMS version from `Request->Ndr64.Data` (stub offset 24) whenever
`Ctx == *Ndr64Ctx` — it tests `Ctx != *Ndr64Ctx` first (`src/rpc.c:197-205`). `rpcRequest()` tests
`Ctx == *NdrCtx` **first** and would then read from `Request->Ndr.Data` (stub offset 16)
(`src/rpc.c:257-272`). Both context variables are initialised to `RPC_INVALID_CTX` = `0xffff`
(`src/rpc.c:616`, `src/rpc.h:271`). A client that sends an RPC *request* PDU with ContextId `0xffff`
**before any bind** therefore satisfies `Ctx == *Ndr64Ctx` during validation and `Ctx == *NdrCtx`
during dispatch. Putting a valid version (e.g. `0x00060000`) at offset 24 passes validation, while an
arbitrary WORD at offset 18 becomes `majorIndex = arbitrary - 4` in the unchecked
`_Versions[majorIndex].CreateResponse(...)` call at `src/rpc.c:285-286`. There is no bounds check on
that index on the dispatch path.

**Client stack overflow from a malicious server.** `DecryptResponseV4()` does
`memcpy(&response_v4->ResponseBase.CMID, rawResponse + copySize, responseSize - copySize)` with **no
bound on `responseSize`**, into a 188-byte `RESPONSE_V4` on the caller's stack
(`src/kms.c:983-994`, `src/vlmcs.c:854-861`). A server declaring a large NDR `DataLength` overflows it.

**Client heap underflow / wild pointer from a malicious server.** `DecryptResponseV6()` subtracts 4
from `responseSize` and passes it to `AesDecryptCbc()` without checking it is ≥ 4 or a multiple of 16
(`src/kms.c:1095-1105`). With a non-multiple-of-16 length the loop
`for (cc = data + len - 16; cc > data; cc -= 16)` walks off the front of the buffer and writes a
decrypted block before it (`src/crypto.c:325-337`); with `responseSize < 4` the length underflows to a
huge `size_t`.

**Client OOB read in `checkPidLength()`.** With `PIDSize == 0`, `KmsPID[(0>>1)-1]` indexes −1 and the
loop bound `(PIDSize >> 1) - 2` underflows to `0xFFFFFFFE`, scanning until it happens to hit a zero
WCHAR (`src/kms.c:964-977`).

**Use-after-scope with `-r2`.** In `getEpid()` the buffer `char ePid[PID_BUFFER_SIZE]` is declared
inside the `if (RandomizationLevel == 2)` block at `src/kms.c:473`, `pid` is set to it, and
`getEpidFromString(baseResponse, pid)` is called at `src/kms.c:502` **after that block has ended**. It
works only because the stack slot happens to survive. GCC 15 emits `-Wdangling-pointer` and ASan
reports stack-use-after-scope on every `-r2` request.

**KMD loader: unbounded pointer arithmetic.** `loadKmsData()` validates pointers only against the
upper bound and only with `>`, never against a lower bound, and computes them by unchecked 64-bit
addition (`src/helpers.c:617-623`, `src/helpers.c:641-652`, `src/helpers.c:670-685`). A `.kmd` whose
`AppItemOffset` is `0xFFFFFFFFFFFFFF00` wraps below the buffer, passes `ptr > KmsData + size`, and
yields a heap-buffer-overflow read at `src/helpers.c:673`; a wrapped `HostBuildOffset` yields a SEGV
at `src/helpers.c:644`.

**KMD loader: `EPidIndex` is never validated** against `CsvlkCount` (`src/helpers.c:676-683` checks
only `Name`, `AppIndex` and `KmsIndex`). Setting `EPidIndex = 250` on a KMS record in an otherwise
valid file produces a heap-buffer-overflow at `src/kms.c:468` and `src/kms.c:720` the first time a
matching request arrives — i.e. remotely triggerable once the file is loaded.

**KMD loader: validation order is wrong.** The magic/version/size check lives at
`src/helpers.c:657-667`, **after** the loops at 617-652 have already dereferenced and byte-swapped
`Datapointers`, `CsvlkData[0..CsvlkCount-1]` and `HostBuildList[0..HostBuildCount-1]`. `CsvlkCount`
(u8, up to 255) and `HostBuildCount` (i32, arbitrary) are never sanity-checked against the file size.

**KMD loader: the size check is 160 bytes too permissive.** `src/helpers.c:662` uses
`sizeof(VlmcsdHeader_t)` = 104, which assumes `CsvlkCount == 1`. For the shipped `CsvlkCount = 6` the
real header is 264 bytes.

**Heap corruption risk in `addListeningSocket()`.** `SOCKET *s = SocketList + numsockets;` is computed
once, but the loop over the `getaddrinfo` result list writes to `*s` for every entry while
incrementing `numsockets` without advancing `s` (`src/network.c:642-668`). More than one addrinfo per
`-L` overwrites the same slot and leaves an **uninitialized `SocketList` entry** that `select()`/
`FD_SET` later consumes.

**`ServiceInstaller()` stack buffer overflow.** Every `argv` element is `strcat`ed into a fixed
`char szPath[MAX_PATH]` with no bounds checking (`src/ntservice.c:179-212`). A long install command
line overflows it.

**Unchecked `fstat` for inetd detection.** `struct stat statbuf; fstat(STDIN_FILENO, &statbuf); if
(S_ISSOCK(statbuf.st_mode))` reads uninitialized memory when `fstat` fails
(`src/vlmcsd.c:1736-1739`), yielding undefined `InetdMode`.

**`getifaddrs-musl.c` unconditional dereference.** `*ifap = &ctx->first->ifa` and, on the error path,
`freeifaddrs(&ctx->first->ifa)` with no NULL check on `ctx->first` (`src/getifaddrs-musl.c:260-261`) —
UB when no interfaces were returned, benign only because `ifa` is the first struct member.

**`hex2bin()` defects.** It ignores its `maxbin` argument for the loop bound (hardcoded `i < 16`) and
treats the string terminator as a valid hex digit (`strchr(hexdigits, '\0')` returns the terminator),
so it reads past NUL-terminated substrings (`src/helpers.c:387-405`). `string2UuidLE()` only produces
correct GUIDs because each subsequent call overwrites the garbage the previous one wrote
(`src/helpers.c:200-230`). It also **never zero-fills**: a HwId with fewer than 16 hex digits leaves
the tail of the freshly `malloc`'d 8-byte buffer uninitialized, and those bytes are sent to clients
(`src/vlmcsd.c:443-445`).

**Internal SHA-256 alignment UB.** `w[i] = BE32(((DWORD*)block)[i])` performs aligned 32-bit loads on
a caller-supplied pointer, and `((uint64_t*)Ctx->Buffer)[7] = BE64(...)` performs an 8-byte store into
a buffer whose struct alignment is only 4 (`src/crypto_internal.c:60-62`,
`src/crypto_internal.c:114-135`). Both can fault on strict-alignment architectures.
`Sha256Ctx.Len` is also a 32-bit `unsigned int`, so the implementation is wrong for messages ≥ 512 MB
(irrelevant for KMS, a landmine if reused).

**Function-pointer type punning.** Both `_Versions[]` (`src/rpc.c:61-70`) and `_Actions[]`
(`src/rpc.c:578-589`) are built with pointers cast through incompatible prototypes
(`// ReSharper disable CppIncompatiblePointerConversion`), which is UB and would break under CFI or
strict prototype checking.

**`AesCmacV4()` writes past the message.** It always writes 16 bytes past `MessageSize` (zero fill
plus the `0x80` marker, `src/crypto.c:202-204`). Every caller must guarantee that slack; in
`DecryptResponseV4` this exactly consumes the 16 `MAX_EXCESS_BYTES` that `rpcSendRequest` over-allocates
(`src/rpc.c:933-939`).

**Division by zero in random-ePID generation.** `rand32() % (MaxKeyId - MinKeyId)`
(`src/kms.c:327`) crashes if a `.kmd` has `MinKeyId == MaxKeyId`, and
`rand32() % (maxTime - minTime)` (`src/kms.c:353`) crashes if the release date equals "now" and
misbehaves if `minTime > maxTime`.

**Infinite loops.** `getRandomServerType()` spins in `while (TRUE)` until it finds a host build whose
`UseNdr64` flag matches the current setting (`src/kms.c:292-300`) — a custom `.kmd` whose builds are
all NDR64 (or all not), combined with the opposite `-N`, hangs vlmcsd at startup.
`GetCsvlkIndexFromName()` loops with an `int8_t` counter (`src/vlmcsd.c:766-768`), so a database with
`CsvlkCount > 127` loops forever.

**Null/uninitialized dereferences.** `-DNO_INTERNAL_DATA` plus `-j -` leaves `KmsData == NULL` and
`size` uninitialized, both dereferenced at `src/helpers.c:605` (GCC warns
"`size` may be used uninitialized"). `grabServerData` leaves `kmsGuids[i]` uninitialized
(`vlmcsd_malloc`, not zeroed) if no KMS item has `EPidIndex == i`, then looks that garbage GUID up.
`GetNumericId()` tests `*id` (the possibly-unset output) rather than the parsed temp value on parse
failure (`src/vlmcsd.c:213`).

### 17.2 Information leaks and fingerprintability

* **Bind-ack `SecondaryAddress` padding is intentionally left uninitialized** — "M$ RPC does not do
  this. Pad bytes contain apparently random data" (`src/rpc.c:442-443`). Deliberate MS mimicry that is
  also a stack-content leak.
* **`SendError()` never initialises `CancelCount`/`Pad1`**, so the 32-byte fault PDU leaks 2 bytes of
  uninitialised stack (`src/rpc.c:230-237`). The normal response path *does* clear them
  (`src/rpc.c:339`).
* **Server FAULT PDUs always carry CallId 2.** `createRpcHeader()` uses the module-static `CallId`,
  which is only ever incremented by the *client* (`src/rpc.c:74`, `src/rpc.c:604`,
  `src/rpc.c:670-674`, `src/rpc.c:826`). A real MS server echoes the request's call id, so every
  vlmcsd fault is trivially fingerprintable.
* **Requests are size-checked with `>=`, not `==`,** and the per-version minimum does not include the
  RPC stub header — `requestSize >= _Versions[majorIndex].RequestSize` compares the *whole stub
  length* (which includes the 16-byte `RPC_REQUEST` / 24-byte `RPC_REQUEST64` prologue) to the bare
  KMS payload length. The binding check is therefore the v4 floor at `src/rpc.c:189`,
  `requestSize >= 252 + 16 = 268` on NDR32. But `CreateResponseV6` decrypts `V6_DECRYPT_SIZE` = 256
  bytes starting 4 bytes into the KMS payload, i.e. at stub offset 20, which needs 276 bytes. **A v6
  request of 268-275 bytes (NDR32) or 276-283 bytes (NDR64) passes both checks and reads up to 8
  bytes of uninitialised stack past what was received** (`src/rpc.c:189`, `src/rpc.c:226`,
  `src/kms.h:174-178`).
* **Normal replies echo the request header wholesale**, so `PacketFlags` and `DataRepresentation` come
  from the client (`src/rpc.c:667-687`). Microsoft always sets `FIRST|LAST` and its own data
  representation on responses; vlmcsd would happily reflect `RPC_PF_CANCEL_PENDING`/`RESERVED`/
  `MAYBE`/`OBJECT`, and would answer a big-endian client with little-endian data.
* **Fault detection by magic length.** `if (response_len == 32)` is the only thing that turns a reply
  into an RPC fault (`src/rpc.c:669-676`). Any future 32-byte response body would be misrendered.
* **No CSPRNG.** See §4. `randomNumberInit()` re-seeds the global libc PRNG with
  `srand(tv_sec ^ tv_usec)` at the start of **every** RPC connection (`src/rpc.c:618`,
  `src/helpers.c:343-352`), so IVs, salts and `-r2` ePIDs are drawn from a freshly low-entropy-seeded
  non-cryptographic generator.
* **The Windows service installer stores passwords in the registry.** It strips only exactly `-s`,
  `-U <arg>` and `-W <arg>` as separate `argv` elements (`src/ntservice.c:190-200`), so a combined
  `-W<password>` is copied verbatim into the service `ImagePath`.

### 17.3 Resource and correctness defects

* **Fork failure leaks.** `ServeClientAsyncFork()` returns `errno` without closing `s_client` and
  without `post_sem()` (`src/network.c:944-947`), so repeated fork failures leak both descriptors and
  semaphore counts. The thread paths do clean up (`src/network.c:892`, `src/network.c:915`). Children
  killed by SIGKILL also leak a semaphore count permanently.
* **Hardcoded global semaphore name `"/vlmcsd"`.** Two vlmcsd instances on one host share the same
  POSIX named semaphore, and `allocateSemaphore()`/`cleanup()` `sem_unlink()` it unconditionally
  (`src/vlmcsd.c:1525`, `src/vlmcsd.c:1534`, `src/vlmcsd.c:1478`), so starting or stopping one
  instance corrupts the other's worker limit.
* **Signal handlers are not async-signal-safe.** `terminationHandler` → `cleanup()` → `logger()` does
  `fopen`/`fprintf`/`fclose` or `openlog`/`vsyslog`; `HangupHandler` `malloc`s argv before `execv`
  (`src/vlmcsd.c:965`, `src/vlmcsd.c:991`, `src/output.c:48`).
* **`childHandler` reaps at most one child per delivered signal**, so coalesced SIGCHLDs can still
  leave zombies on the `CHILD_HANDLER` path (`src/vlmcsd.c:998`).
* **`select()`-based accept always takes the first ready descriptor** in `SocketList` order
  (`src/network.c:712-719`), so a saturated early listener starves later `-L` addresses.
* **`IPV6_BINDANY` is set with level `IPPROTO_IP`** instead of `IPPROTO_IPV6` (`src/network.c:603`),
  so FreeBSD IPv6 free-binding can never work; the failure is hidden behind `_PEDANTIC`.
* **On Windows the "reuse" option is `SO_EXCLUSIVEADDRUSE`** — the semantic *opposite* of
  `SO_REUSEADDR` — yet the `_PEDANTIC` diagnostic still says "Socket option SO_REUSEADDR unsupported".
  On Cygwin no reuse option is set at all (`src/network.c:294-314`).
* **On OpenBSD, `SIMPLE_SOCKETS` builds silently become IPv4-only** because the kernel refuses
  `IPV6_V6ONLY = 0` and the code falls through to the AF_INET fallback (`src/network.c:342-348`).
  `socketclose(s_server)` is also called even when `s_server == INVALID_SOCKET`.
* **`daemon(nochdir = 1, ...)`** means vlmcsd never `chdir()`s to `/` and keeps its start-up cwd busy
  after daemonizing (`src/vlmcsd.c:1012`).
* **A Windows service with no `-l`/`LogFile` produces no output at all**: `logstdout` is ignored when
  `IsNTService` and `vlogger()` returns immediately when `fn_log` is NULL; the event-log code is
  entirely commented out (`src/output.c:26-33`, `src/ntservice.c:93-120`).
* **`-o1`/`-o3` are unreliable for 32-bit binaries on a 64-bit FreeBSD kernel** due to an unfixed
  32-bit ABI bug in the interface-enumeration path (`man/vlmcsd.8`, FreeBSD PR 178881).
* **libkms `SIMPLE_SOCKETS` path leaves `defaultport` dangling.** It `malloc`s a 16-byte buffer,
  assigns it to the global, calls `listenOnAllAddresses()`, then `free()`s it
  (`src/libkms.c:165-171`) — any later `parseAddress()` reads freed memory.
* **libkms `StartKmsServer` discards `runServer()`'s return value** and unconditionally returns 0
  (`src/libkms.c:150-153`), so an embedder cannot distinguish a clean stop from a fatal `accept()`
  failure.
* **libkms `StopKmsServer` frees `SocketList`** (non-`SIMPLE_SOCKETS` build) while `runServer` may
  still be inside `network_accept_any()` referencing that array (`src/libkms.c:188-192`).
* **`libkms.h` includes `vlmcs.h`, which does `#define client_main main`** when
  `MULTI_CALL_BINARY < 1` (`src/vlmcs.h:20-24`) — a macro that leaks into every embedder's
  translation unit.
* **`isDisconnected()` is dead code in the vlmcsd binary** — present in `src/network.c:153` but only
  called by libkms and the client.
* **The dead `rand32` macro variants** for `RAND_MAX >= 0x7fffffff` are written with a parameter
  (`#define rand32(x) ...`, `src/types.h:222-226`) and only compile because every call site writes
  `rand32()` with an empty argument.

### 17.4 Build breaks and dead knobs

* **`NO_HELP` breaks `vlmcs -j`.** In parse pass 2 the harmless `case 'j': break;` sits inside
  `#ifndef NO_HELP` (`src/vlmcs.c:437-450`). Any `NO_HELP` build that still has external data enabled
  — notably `FEATURES=embedded` and `FEATURES=autostart` — rejects `-j <file>` as an invalid option.
* **`NO_DNS` + `NO_VERBOSE_LOG` does not compile.** The `#ifdef NO_DNS` branch of `connectRpc` uses
  `verbose` unguarded (`src/vlmcs.c:741`, `:745`, `:751`) while `verbose` only exists when
  `NO_VERBOSE_LOG` is undefined (`src/vlmcs.c:62-64`). `make NO_DNS=1 FEATURES=embedded` fails.
* **`NO_LOG` alone breaks `vlmcs`.** `src/config.h:406` states that `NO_LOG` "Implies
  `NO_VERBOSE_LOG`", but nothing actually defines it. `logRequestVerbose`/`logResponseVerbose` are
  guarded by `!NO_VERBOSE_LOG && !NO_LOG` (`src/output.c:158`) while their callers are guarded only by
  `!NO_VERBOSE_LOG` (`src/vlmcs.c:721`, `src/vlmcs.c:1411`), producing undefined references.
* **`NO_EXTERNAL_DATA` + `NO_INTERNAL_DATA`** is documented as mutually exclusive
  (`src/GNUmakefile:208-209`); nothing enforces it, but defining both makes `long size;` disappear
  while it is still referenced, so the build simply fails.
* **`WINDOWS=` / `OFFICE2010=` / `OFFICE2013=` / `OFFICE2016=` are dead.** They emit
  `-DEPID_WINDOWS` / `-DEPID_OFFICE20xx` (`src/GNUmakefile:299-315`) but **no source file reads those
  macros**. The same names live on as documented kernel-command-line parameters of the floppy image
  (`man/vlmcsd-floppy.7:98-116`), where an init script turns them into `-a` arguments. vlmcsd itself
  reads no environment variables whatsoever.
* **`CAT=1` adds `-DONE_FILE`; no source tests `ONE_FILE`.**
* **`INCLUDE_BETAS` is printed by `-V` but changes nothing** (`src/output.c:516-518`).
* **`_CRYPTO_INTERNAL` is defined by the makefile but never tested anywhere** — the internal backend
  is selected by *absence* of the other three macros (`src/crypto.h:44-56`).
* **`SAFE_MODE` and `DEPENDENCIES=2` are functional but absent from `make help`**
  (`src/GNUmakefile:167`, `src/GNUmakefile:486-488` vs `GNUmakefile:149-232`).
* **Locale-detection fix applied to only one file.** Commit `db75edf` added `LANGUAGE=en_US` alongside
  `LANG=en_US.UTF-8` at `src/GNUmakefile:73`, but `GNUmakefile:17` still sets only `LANG`, so the
  top-level `DLL_NAME` defaulting can still mis-detect the platform where `LANGUAGE` overrides `LANG`.
* **The tcc special case compares `$(CC)` literally** against `tcc` (`src/GNUmakefile:254`), so
  `/usr/bin/tcc` still gets `-Wl,--gc-sections`; conversely `-flto` is added whenever the `CC`
  basename merely *contains* `gcc` (`src/GNUmakefile:174`).
* **`src/libkms-test.c` has no build rule** in any makefile, and its callback
  `__stdcall BOOL KmsCallBack(const REQUEST *const, RESPONSE *const, BYTE *const, const char *const)`
  does not match `RequestCallback_t` (`HRESULT __stdcall (*)(REQUEST*, RESPONSE* const, BYTE* const,
  const char* const)`, `src/kms.h:378`). Its version check prints an error and then proceeds anyway
  (`src/libkms-test.c:34-37`).
* **`vlmcsdmulti` name dispatch is inconsistent.** `basename` dispatch uses `strcasecmp` on
  Windows/Cygwin but the `argv[1]` dispatch uses plain `strcmp` on every platform
  (`src/vlmcsdmulti.c:29-33` vs `:83-87`), so `vlmcsdmulti VLMCSD` fails on Windows while a
  `VLMCSD.EXE` symlink works. Under MSVC, `basename()` is reimplemented to keep the extension, returns
  a **static 64-byte buffer**, and yields an empty string for names longer than 63 characters
  (`src/vlmcsdmulti.c:36-59`).
* **`.gitignore` excludes referenced trees.** `VisualStudio/`, `buildroot-configs/`,
  `hotbird64-mass-build/`, `floppy/` and `src/VisualStudio-Linux-Remote/` — the Visual Studio
  projects, buildroot configurations and mass cross-build harness referenced by the READMEs are all
  absent from this repository.

### 17.5 Dependency rot

* **The OpenSSL backend targets the OpenSSL 1.0 API** (`HMAC_CTX` by value, `HMAC_CTX_init`,
  `HMAC_CTX_cleanup`, `src/crypto_openssl.c:14-59`) and **will not compile against 1.1+ or 3.x**,
  where `HMAC_CTX` is opaque.
* **Only PolarSSL is supported** — mbed TLS, the renamed successor with `mbedtls/` headers and
  `mbedtls_sha256*` functions, will not build (`src/crypto_polarssl.h:9-36`). This backend is
  effectively dead for any modern system.
* **`_USE_AES_FROM_OPENSSL` writes directly into OpenSSL's `AES_KEY` struct** and is described by
  `src/config.h:295-310` itself as DANGEROUS and version/platform dependent. If the assumed layout is
  wrong, the binary silently produces only valid KMSv5 traffic.
* **The Windows backend is legacy CryptoAPI, not CNG/bcrypt.** The streaming
  `Sha256HmacInit/Update/Finish` declared in `src/crypto_windows.h` are commented out; only the
  one-shot form exists. `Sha256` there returns `int_fast8_t` whereas the internal one returns `void` —
  callers ignore the result either way.
* **`USE_AUXV` does not work on uClibc or glibc < 2.16** (Debian 7, RHEL 6) per `src/config.h`.

### 17.6 Configuration footguns

* **Ini keyword matching is prefix-based** (`strncasecmp(name, line, strlen(name))`) in
  `handleIniFileParameter` (`src/vlmcsd.c:834`), `handleIniFileEpidParameter` (`src/vlmcsd.c:788`) and
  `GetCsvlkIndexFromName` (`src/vlmcsd.c:771`). So `Portable = 5` silently sets the TCP port,
  `ListenAddress = ...` is treated as a `Listen` line, and `Windows10 = <epid>` is applied to the CSVLK
  `Windows`. A future database keyword that is a prefix of another would silently shadow it.
* **Only CR/LF are trimmed from ini lines** (`src/vlmcsd.c:878-886`); trailing spaces stay in the
  argument. The shipped `etc/vlmcsd.ini:141` has a trailing blank after `vlmcsdgroup`, so uncommenting
  that line yields `Invalid group id or name`.
* **Inetd mode forces `MaintainClients = FALSE` at `src/vlmcsd.c:1743`, but the ini file is read
  afterwards at `src/vlmcsd.c:1758`** — an ini `MaintainClients = true` therefore re-enables the CMID
  list under an internet superserver, contradicting `man/vlmcsd.8:244` and `man/vlmcsd.ini.5:167`. The
  CLI `-M1` *is* correctly suppressed (parsed before), so CLI and ini behave differently for the same
  setting.
* **`-P` with no `-L` silently disables every ini `Listen` line**, because `case 'P'` calls
  `ignoreIniFileParameter(INI_PARAM_LISTEN)` in non-`SIMPLE_SOCKETS` builds
  (`src/vlmcsd.c:1153-1159`). Documented in `vlmcsd.ini.5:40` but **not** in the `-P` description at
  `man/vlmcsd.8:79-80`.
* **`-H 7601` silently turns NDR64 off.** If neither `-N` nor `UseNDR64` was specified, vlmcsd
  overwrites the documented default (TRUE) at startup with the `.kmd` `KMS_OPTIONS_USENDR64` flag and
  then with `(HostBuild > 7601)` whenever a host build is pinned and randomization is on
  (`src/vlmcsd.c:1770-1785`) — the reverse of what `man/vlmcsd.8:133` describes.
* **`-a`/ini CSVLK ePID lines have reversed precedence from every other directive.** The CLI uses
  `overwrite = TRUE` (last `-a` wins, and beats the ini), but ini pass 2 uses `overwrite = FALSE`, so
  the **first** occurrence in the ini wins (`src/vlmcsd.c:800-801`, `src/vlmcsd.c:441`,
  `src/vlmcsd.c:467`).
* **A custom HwId cannot be set without also setting an ePID** — the
  `memcpy(HwId, KmsResponseParameters[index].HwId, 8)` lives inside the branch taken only when
  `KmsResponseParameters[index].Epid != NULL` (`src/kms.c:490-500`).
* **When `setEpidFromIniFileLine` fails** (bad UTF-8 or >63 chars) the warning is printed with a
  stale/empty `IniFileErrorMessage`.
* **`-x1` does not cover all VPN problems.** "No compatible VPN adapter available" is an unconditional
  `exit(ERROR_DEVICE_NOT_AVAILABLE)` regardless of `ExitLevel` (`src/wintap.c:240-256`); only
  mirror-thread errors honour `exitOnWarningLevel` (`src/wintap.c:300`).
* **`-e` overrides `-l`/`LogFile` at runtime** (`src/output.c:26-33`) and is silently disabled in
  inetd mode and as an NT service — none of which is stated in the man pages.
* **`MaxWorkers == SEM_VALUE_MAX` means "unlimited", not "maximum"** (`src/shared_globals.c:60-66`,
  `src/vlmcsd.c:1528`), which is undocumented; `man/vlmcsd.ini.5:120` only says the maximum is "at
  least 32767".
* **`ePID` length is checked in UCS-2 characters, not bytes** (`src/vlmcsd.c:458-466`), so a
  multi-byte UTF-8 ePID may exceed the 63 bytes `vlmcsd.ini.5:188` claims.
* **`vlmcs -w` silently truncates** names longer than 63 characters after a BEL-prefixed warning; it
  does not abort (`src/vlmcs.c:582-591`).
* **`vlmcs -t` accepts `0..0x7fffffff`** and merely warns for values > 6 before sending them
  (`src/vlmcs.c:593-597`); values > 6 print as "Unknown" because `LicenseStatusText[]` has 7 entries.
* **`vlmcs -N1` alone cannot verify NDR64**: the first request on any connection is always NDR32
  (`... && firstPacketSent`, `src/rpc.c:812`), so at least `-n 2` is required. Documented at
  `man/vlmcs.1:222` but easy to miss.
* **`vlmcs` has no timeout option at all** — the 10-second `SO_RCVTIMEO`/`SO_SNDTIMEO` in
  `connectToAddress()` can only be changed by editing the source or removed entirely with
  `NO_TIMEOUT`.
* **`vlmcsd`'s compact default database has `SkuItemCount = 0`**, so a stock server resolves every
  Activation ID to "Unknown" in its logs unless built with `-DFULL_INTERNAL_DATA` or given an external
  `.kmd`. `vlmcs` refuses to run on it at all (`Fatal: Incomplete KMS data file`,
  `src/vlmcs.c:1257-1261`), which is why `vlmcs` and `vlmcsdmulti` always link `kmsdata-full.c`.
* **The shipped `etc/vlmcsd.kmd` is a downgrade** relative to the compiled-in data, and its HostBuild
  release dates for builds 9200 and 7601 are eleven and ten years too early (2001), so
  `-j etc/vlmcsd.kmd -H 9200` can produce ePIDs claiming a KMS host activated before that build
  existed (see §7.8).
* **`MinActiveClients` is 0 for every CSVLK in every shipped database**, so the documented "minimum
  answer clients" floor is inert (`src/kms.c:719-723`). The per-KMS-ID `NCountPolicy` field is likewise
  never read by the server — only the per-App one. **There is no CLI or ini knob for the N-count at
  all, and none for a grace period.**

### 17.7 Documentation versus code

| Claim | Where | Reality |
|---|---|---|
| `-h` / `-?` displays help | `man/vlmcsd.8:37`, `man/vlmcs.1:44` | Neither letter is in either option string (`src/vlmcsd.c:87`, `src/vlmcs.c:363`). Help appears only via the unknown-option `default:` path, on stderr, with exit status `VLMCSD_EINVAL` |
| Use `-w`, `-G`, `-0`, `-3` and `-6` for custom ePIDs | `man/vlmcsd.8:30`, `man/vlmcsd.8:206` | None of those options exist. The replacement is `-a <csvlk>=<epid>[/<hwid>]` (`src/vlmcsd.c:1129`, `src/vlmcsd.c:1792-1810`) |
| "`-l`, `-e` or `-f`"; "`-s` … Ignores `-e`, `-f` and `-D`" | `man/vlmcsd.8:158`, `src/vlmcsd.c:312-316`, `src/config.h:404` | There is no `-f`; it was replaced by `-D` long ago |
| `NO_CL_PIDS` removes `-0`, `-3`, `-w` and `-H` | `src/config.h:597` | It removes only `-a`; `-H` belongs to `NO_RANDOM_EPID` |
| `NO_SOCKETS` removes `-4`, `-6`, `-f` | `src/config.h:583` | Those options do not exist in vlmcsd |
| NDR64/BTFN flags are `-n0`/`-n1` and `-b0`/`-b1` | `man/vlmcsd.ini.5:105`, `:108` | The real flags are uppercase `-N` and `-B`; lowercase produce a usage error |
| `LCID` must be 1..32767; `HostBuild` must be 1..65535 | `man/vlmcsd.ini.5:114`, `:117` | Both accept **0**, and 0 is the meaningful value ("randomize this field") — `src/vlmcsd.c:555`, `src/vlmcsd.c:565` |
| `Port` "only works if compiled to use MS RPC or simple sockets" | `man/vlmcsd.ini.5:51`, `etc/vlmcsd.ini:40-41` | It is also compiled in whenever `HAVE_GETIFADDR` is defined — the default on Linux/glibc (`src/vlmcsd.c:146-148`, `src/types.h:82-84`) — and it does take effect via `defaultport` |
| For a repeated keyword, the last occurrence wins | `man/vlmcsd.ini.5:32`, `etc/vlmcsd.ini:10-11` | True only for general directives. Per-CSVLK ePID lines take the **first** occurrence |
| `-r0` issues "default ePIDs built into the binary at compile time" | `man/vlmcsd.8:202` | Since v1.1x they come from the KMS data file, so `-j` changes them (`src/kms.c:55`, `src/kms.c:484`) |
| `-j-` "ignores the default configuration file" | `man/vlmcsd.8:189` | It means the default *KMS data* file |
| Random ePIDs use builds 9200/9600 with NDR64 and 6002/7601 without; `-r1` "ensures that all three ePIDs" match | `man/vlmcsd.8:133`, `:202` | The shipped table's NDR64 set is {17763, 14393, 9600, 9200}, and there are now **six** CSVLKs |
| `-a`/`<csvlk-name>` "requires database version 1.6 or later"; "vlmcsd is compatible with older databases" | `man/vlmcsd.8:176-178`, `man/vlmcsd.ini.5:185` | `src/helpers.c:659` rejects anything whose `MajorVer != 2`; the 1.x header layout is structurally different, so **no 1.x file can be loaded at all** |
| An ini HwId "follows the same syntax as in the `-H` option" | `man/vlmcsd.ini.5:194` | `-H` is the host-build option; HwId syntax is defined under `-a` (`man/vlmcsd.8:179`) |
| Seconds are "rounded down to the next multiple of 60" | `man/vlmcsd.8:256` | Any `-A`/`-R` value below 60 seconds becomes 0 and is **rejected** as "No valid time span" |
| Whitelisting directive is `WhitelistingLevel` | `man/vlmcsd.ini.5:144` | The table registers `WhiteListingLevel` (capital L, `src/vlmcsd.c:133`, `etc/vlmcsd.ini:107`). Only case-insensitive prefix matching makes both work |
| SUPPORTED PRODUCTS stops at Windows Server 2016 | `man/vlmcsd.8:311` | The database has a dedicated Server 2019 KMS ID and 7 Server 2019 SKUs |
| Default `vlmcs -l` product is "Windows Vista Business"; `vlmcs kms.example.com` requests Vista over v4 | `man/vlmcs.1:68-70`, `:236-244` | `ActiveProductIndex` defaults to 0 (`src/vlmcs.c:85`), which is **"Windows Server 2019 ARM64"** over protocol v6 |
| KMS/Activation GUIDs are listed in "kms.c (tables `KmsIdList`, `ExtendedProductList`, `AppList`, `BasicProductList`)" | `man/vlmcs.1:127`, `:134-135`, `src/kms.h:72-74` | Those tables were removed with the KMD v2 format. The data lives in the opaque binary blob, readable only via `vlmcs -x` |
| `TERMINAL_WIDTH` affects `vlmcsd -x` | `src/config.h:135`, `GNUmakefile:166` | vlmcsd has no product-listing `-x`; the affected code is `vlmcs -x` (`src/vlmcs.c:201-233`) |
| `NO_LOG` "implies `NO_VERBOSE_LOG`" | `src/config.h:406` | Nothing defines it; see §17.4 |
| `-t`/`ConnectionTimeout` maximum | not documented | Silently limited to 1..600 seconds in both CLI and ini paths (`src/vlmcsd.c:675`, `src/vlmcsd.c:1178`) |
| `-Z` | not in any man page or help output | A real, functional option (`src/vlmcsd.c:1111-1116`) |

### 17.8 Absent by design or omission

| Capability | Status |
|---|---|
| systemd `sd_listen_fds()` / `LISTEN_FDS`, launchd API | **Absent.** Socket activation works only via the inetd convention (`Accept=yes`), at which point `-M1` and `-r1` stop working |
| DNS SRV publication or lookup by the *server* | **Absent.** `dns_srv.c` is client-only |
| Windows event log | **Absent.** The only code is commented out (`src/ntservice.c:93-120`) |
| Log rotation, size caps, retention, log levels | **Absent.** Open-append-close per line; all syslog messages are `LOG_INFO` |
| Rate limiting, IP allow/deny lists, ACLs, authentication, connection accounting | **Absent** |
| `chroot`, `umask`, `setsid`, capabilities, seccomp, pledge | **Absent** |
| `SO_REUSEPORT`, `TCP_NODELAY`, `SO_KEEPALIVE`, `SO_LINGER` | **Never used anywhere** |
| RPC fragmentation | **Unsupported** in both directions |
| Client-side parallelism in `vlmcs` | **Absent.** Strictly sequential, single-threaded |
| Hardware crypto acceleration | Only via the `_USE_AES_FROM_OPENSSL` hack. No AES-NI, ARM crypto extensions, SHA-NI or assembly in-tree |
| CSPRNG | **Absent.** libc `rand()` only |
| `install` / `uninstall` / `dist` / `test` make targets | **Absent** |
| Init scripts, systemd units, Dockerfiles | **Not in this repository** — external `debian/` and `docker/` submodules, empty in a plain clone |
| Products newer than Windows 10 1809 / Server 2019 / Office 2019 | **Not in the database** (see §8.3) |

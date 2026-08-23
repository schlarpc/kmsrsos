# kmsrsos — maximalist implementation punch list

Derived exhaustively from the five audits in `docs/`:
[`kms-emulator-feature-matrix.md`](./kms-emulator-feature-matrix.md) (`matrix`),
[`vlmcsd-features.md`](./vlmcsd-features.md) (`V`),
[`py-kms-features.md`](./py-kms-features.md) (`P`),
[`vlmcsd-forks.md`](./vlmcsd-forks.md) (`VF`),
[`py-kms-forks.md`](./py-kms-forks.md) (`PF`),
plus two commissioned research passes recorded in [Appendix C](#appendix-c--research-findings)
(`R1` = product data from Microsoft primary sources, `R2` = Hermit/Proxmox feasibility).

Every nuance flagged anywhere in those documents appears below exactly once, either as a work item
or in [Appendix A — declined](#appendix-a--declined-with-rationale). Nothing was dropped silently.

## Project axioms

| # | Axiom | Consequence that shapes almost every item below |
|---|---|---|
| A1 | Pure safe Rust | `#![forbid(unsafe_code)]` in every crate except a documented `kmsrs-os` boundary |
| A2 | Correct by construction | Illegal states unrepresentable; no runtime panics; no runtime validation of what a type could carry |
| A3 | Configuration is compile-time | One narrow runtime escape hatch, defined in CFG-002, restricted to settings that cannot change a byte on the wire |
| A4 | Linux + Windows + bare metal (Hermit, virtio-net) | Thin swappable platform layer; core builds for `no_std + alloc` |
| A5 | No disk I/O; logs to stderr | One narrow exception: six lifecycle events to the Windows Event Log (OBS-016) |
| A6 | Maximal client compatibility, permissive time band | Defaults say *yes*; strictness is opt-in at build time |
| A7 | Sans-io core | Protocol crates take `&[u8]` → events; sockets live at the edges; fuzzable and cross-testable |
| A8 | Reuse crates, don't reimplement | Exactly two justified exceptions, both in CRY-002 |
| A9 | Anti-fingerprinting | MM01–MM24 are a *test suite*, not a wish list |
| A10 | Cross-validate against other implementations | Differential CI against vlmcsd and py-kms is a build gate |
| A11 | Event log + instructions on an in-process web server | Bounded in-memory ring buffer; the primary operator surface |
| A12 | Docker + Nix flake + OS image as GHA artifacts | Reproducible, provenance-stamped |

**Legend.** `⚑` = needs verification against a real client, a real KMS host, or hands-on hardware.
`→A#` = declined, see Appendix A. `[R1]`/`[R2]` = settled by research.
**All design decisions are closed**; what remains are experiments, listed in
[Remaining unknowns](#remaining-unknowns--experiments-not-decisions).

## Decision log

| # | Decision | Outcome |
|---|---|---|
| 1 | Crate split | 8 crates; `web` folded into `server`; `dbgen` and `crypto` separate for dependency isolation and audit boundary (ARCH-001) |
| 2 | Framing | `zerocopy` end to end, including checked prefix-splitting for variable DCE/RPC sections (ARCH-011) |
| 3 | Panic-freedom | Lints everywhere + a symbol-level CI gate on `proto`/`crypto` + `panic = "abort"` (ARCH-009) |
| 4 | Concurrency | tokio on Linux/Windows; blocking `std::net` + `std::thread` on Hermit (ARCH-005) `[R2]` |
| 5 | Crypto | One minimal Rijndael in `kmsrs-crypto` with exhaustive KATs, quarantined as the A8 exception (CRY-002) |
| 6 | Product-data source | Microsoft `pkeyconfig` artifacts, extracted by `kmsrs-dbgen` (DB-001) `[R1]` |
| 7 | Product gate | **Split**: permissive on unknown KMS IDs; strict on retail/preview and AppID mismatch (POL-010) |
| 8 | Reported client count | Per-client views over a saturating shared world model (POL-001) |
| 9 | Overcharge poisoning | Dissolved — no longer representable (POL-005) |
| 10 | Per-SKU quotas | Declined — the inverse of POL-001, and keys on a spoofable CMID → A29 |
| 11 | RPC fragmentation | Implement, **inbound reassembly only** (WIRE-022) |
| 12 | Source-IP ACL | Default allow-all; CIDR allow/deny lists available (POL-013) |
| 13 | Runtime config | Doctrine: rebuild from the flake. Escape hatch: one env var, wire-invisible fields only (CFG-002) |
| 14 | Log format | JSON Lines; ANSI only when stderr is a TTY and `NO_COLOR` unset (OBS-002) |
| 15 | Windows Event Log | Narrow exception: six lifecycle/fatal events only (OBS-016). Linux syslog stays declined → A7 |
| 16 | Metrics | `/metrics` in Prometheus text format, including an entropy-health gauge (OBS-013) |
| 17 | Web UI | Read-only — under A5 there is nothing durable to mutate (OBS-010) |
| 18 | Socket activation | Supported, `Accept=no` only, hard refusal on `Accept=yes` (NET-016) |
| 19 | Linux hardening | Privilege drop + Landlock + seccomp; socket activation makes privileges unnecessary (SEC-005/007) |
| 20 | Windows hardening | Self-applicable process mitigations only; AppContainer skipped, asymmetry documented (SEC-005) |
| 21 | Windows service | Dispatcher + control handler; **no installer**; web UI mandatory in service mode (PKG-008) |
| 22 | SRV publishing | RFC 2136 dropped → A31. Instructions page emits zone snippet, `nsupdate` **and** `dnscmd`/PowerShell (DISC-006) |
| 23 | mDNS | Measurement harness first, as a standalone deliverable (DISC-004) |
| 24 | `TCP_NODELAY` | OS default; measured in the DISC-004 harness (NET-015) |
| 25 | Proxmox | Nice-to-have. QEMU/libvirt is the supported configuration (OS-004) |
| 26 | OS packages | `.deb`/`.rpm` as CI artifacts; no repo, no Homebrew (PKG-009) |
| 27 | Kubernetes | Plain manifests, `replicas: 1` hardcoded. No Helm → A33 |
| 28 | Linux appliance image | Skipped → A32 |
| 29 | Upstream proxy / chaining | Declined → A27 |
| 30 | Build-time identity harvesting | Out of scope → A28 |
| 31 | C library API | Declined → A12 |
| 32 | Hermit addressing | DHCPv4, on by default (OS-003) |
| 33 | ePID day-of-year / LCID / channel | 1-based / unpadded / always `03` (ID-004..006) `[R1]` |
| 34 | Win 11 build 28000 | Real, ships 2026-02-10 — include (DB-011) `[R1]` |
| 35 | Licence | MIT (SEC-014) |

---

# 1. ARCH — architecture and crate layout

- **ARCH-001** — Eight crates. `dbgen` is separate because it needs gzip, XML and HTTP to chew
  through Microsoft's artifacts and none of that may be reachable from the runtime binary's
  dependency graph. `crypto` is separate because it is where A8 gets violated — quarantining the
  hand-written Rijndael makes it independently auditable and makes "did anyone touch the cipher?" a
  one-line diff filter. `db` is separate so the generated static tables don't recompile when policy
  changes. The sans-io HTTP responder folds into `server`.

  | Crate | `no_std`? | Contents |
  |---|---|---|
  | `kmsrs-proto` | `no_std + alloc` | KMS v4/v5/v6 payloads, DCE/RPC codec + connection state machine. Pure sans-io. |
  | `kmsrs-crypto` | `no_std` | Rijndael-160 CBC-MAC, tweaked-AES-128 for v6, wrappers over `sha2`/`hmac` |
  | `kmsrs-db` | `no_std` | `build.rs`-generated `static` product tables + query API |
  | `kmsrs-dbgen` | std, host-only | Extracts product data from Microsoft `pkeyconfig` artifacts (DB-001) |
  | `kmsrs-policy` | `no_std + alloc` | Activation policy, host-state model, identity, event log. Sans-io. |
  | `kmsrs-server` | std | Platform layer, listeners, concurrency, HTTP responder, wiring |
  | `kmsrs-client` | std | Diagnostic / validation / soak client |
  | `kmsrs-os` | std (hermit) | Hermit unikernel binary |

  Plus `kmsrs-fuzz` and `kmsrs-vectors` as test infrastructure.

- **ARCH-002** — Sans-io shape: `Server::handle_input(&mut self, now: Instant, bytes: &[u8]) -> Outcome`
  where `Outcome` is an enum of `{ Send(..), Close, KeepOpen, Event(..), Deadline(..) }`. No
  `std::io`, no clock, no RNG inside the core — time and entropy are *inputs*.
- **ARCH-003** — Entropy is an injected trait, so Linux, Windows, Hermit and the fuzzer each supply
  their own. Also what makes OS-012's self-test possible.
- **ARCH-004** — Clock is an injected trait: monotonic ticks for timeouts, wall-clock FILETIME only
  where required. The v6 HMAC key derives from the **client-supplied** FILETIME, so a correct server
  needs no RTC — which matters on Hermit, where `SystemTime` is one CMOS read plus local ticks with
  no NTP, no slew and 1-second granularity `[R2]`.
- **ARCH-005** — **Platform trait** (`Transport`: bind → accept → read/write/deadline/shutdown) with
  two implementations: tokio on Linux and Windows, blocking `std::net` + `std::thread` on Hermit.
  Forced by `[R2]`: upstream tokio has zero Hermit support, the `hermit-os/tokio` fork is pinned at
  1.45.0 with commits from Feb 2024, and `[patch.crates-io]` is workspace-global — adopting it would
  pin the Linux and Windows builds to the same stale fork. Hermit's `std::thread` is real preemptive
  OS threading with an SMP scheduler and futexes, and the blocking `tiny_http` example is what
  hermit's CI actually runs in QEMU; the tokio examples are only *compiled*. **Because the core is
  sans-io there is no async abstraction layer** — two small driver modules each own their loop and
  call the same `handle_input`.
- **ARCH-006** — Typestate for the RPC association: `Conn<Unbound> → Conn<Bound<Ndr32>> |
  Conn<Bound<Ndr64>>`. Servicing a request on a context that was never accepted becomes a compile
  error — the structural answer to vlmcsd's wild-function-pointer bug and py-kms's unvalidated
  `ctx_id` echo.
- **ARCH-007** — Parse-don't-validate newtypes: `Cmid`, `AppGuid`, `SkuGuid`, `KmsGuid`, `NPolicy`,
  `Lcid`, `BuildNumber`, `GroupId`, `KeyId`, `EPid` (≤63 UCS-2, no interior NUL), `HwId([u8;8])`,
  `PidSize` (≤128, even). Constructors are the only validation site.
  **`CsvlkSelection` must distinguish `Resolved(index)` from `Fallback` as separate variants**, never
  by "index 0 means both". vlmcsd conflates them — its unknown-product fallback *is* CSVLK index 0,
  which is why nobody can tell whether its Office-2013-Preview mapping is deliberate or vestigial
  (DB-016). The ambiguity should be unrepresentable.
- **ARCH-008** — No `as` casts in wire handling; `TryFrom` + `checked_*` only.
  `#![deny(clippy::arithmetic_side_effects, clippy::cast_possible_truncation, clippy::indexing_slicing,
  clippy::unwrap_used, clippy::expect_used, clippy::panic)]` workspace-wide.
- **ARCH-009** — Panic-freedom is **verified, not just linted**: build `kmsrs-proto` and
  `kmsrs-crypto` for a `no_std` target with `panic_immediate_abort` and fail CI on any reference to
  `core::panicking::panic_fmt`. Tractable precisely because those crates are sans-io; proving it for
  the whole `std` binary is not worth the fight, since allocation failure aborts regardless. Fuzzing
  (SEC-004) is the empirical half. Release profile uses `panic = "abort"`.

  **Accepted trade-off:** on Linux and Windows a panic kills the process and the supervisor restarts
  it — correct, and more honest than limping on with broken invariants. **On Hermit it kills the
  VM**, and restart requires the hypervisor. Deliberate, not a default taken silently.
- **ARCH-010** — Exhaustive enums for protocol version, PDU type, ack result, reject reason, HRESULT.
  No catch-all arms in dispatch; a new variant must be handled to compile.
- **ARCH-011** — **`zerocopy` end to end.** The KMS payloads are fixed-size, naturally aligned and
  little-endian — derive `FromBytes`/`IntoBytes` with `little_endian::U32` newtypes so endianness
  lives in the type (ARCH-012). The variable DCE/RPC sections use `zerocopy`'s checked
  prefix-splitting rather than a second parsing crate: `binrw` would add a proc-macro to the `no_std`
  core for ~200 lines, and derive macros express DCE/RPC badly anyway because parsing and *policy*
  are intertwined there (WIRE-006's per-item NACK decision is made mid-parse). `bytes::Buf` is
  rejected because it panics on underflow, which fights ARCH-008. A checked cursor is not
  "reimplementing framing" in the sense A8 prohibits — A8 is about not writing our own AES, DNS or
  HTTP.
- **ARCH-012** — Endianness lives in the *type*, not in a macro applied at every field — the failure
  mode vlmcsd works around with 292 lines of `LE16/32/64` macros.
- **ARCH-013** — Never mutate an input buffer in place. vlmcsd's KMD loader byte-swaps the loaded
  file in situ and its response builder `memmove`s within a fixed struct.
- **ARCH-014** — Per-request state is *owned by the request*, never a shared mutable config map.
  This is MM12 — py-kms's process-global `srv_config['raddr']`, which the Organization fork then
  persisted as `lastRequestIP`, and which MelroyB fixed with `srv_config.copy()`.
- **ARCH-015** — **`cfg(unix)` is false on Hermit** `[R2]` — it is not `target_family = "unix"`.
  Every `#[cfg(unix)]` in our code *and in every dependency* silently takes the wrong branch. Audit
  the dependency tree; this is most of what the `hermit-os/tokio` fork's diff consists of.
- **ARCH-016** — One workspace, one `Cargo.lock`, pinned MSRV. See PKG-013 for the Hermit toolchain
  complication.

---

# 2. KMS — protocol payload core

Sizes and offsets are the measured values from `V §3.1`; encode them as `const` assertions.

- **KMS-001** — `REQUEST` = 236 bytes. Offsets: `Version` 0(4), `IsClientVM` 4(4), `LicenseStatus`
  8(4), `GraceTime` 12(4), `AppID` 16(16), `SkuId/ActID` 32(16), `KMSID` 48(16), `CMID` 64(16),
  `N_Policy` 80(4), `ClientTime` FILETIME 84(8), `CMID_prev` 92(16), `WorkstationName` 108(128 = 64
  UCS-2). `CMID_prev` **precedes** the workstation name.
- **KMS-002** — `RESPONSE` = 172 bytes: `PIDSize`, `KmsPID[64]` UCS-2, `CMID`, `ClientTime`, `Count`,
  `VLActivationInterval`, `VLRenewalInterval`.
- **KMS-003** — Wrappers: `REQUEST_V4` 252 / `RESPONSE_V4` 188; `REQUEST_V5` = `REQUEST_V6` = 260
  (`MAX_REQUEST_SIZE`); `RESPONSE_V5` 240; `RESPONSE_V6` 280; `MAX_RESPONSE_SIZE` 384.
- **KMS-004** — Derived: `V4_PRE_EPID_SIZE` 8, `V4_POST_EPID_SIZE` 36, `V6_UNENCRYPTED_SIZE` 20,
  `V6_PRE_EPID_SIZE` 28, `V5_POST_EPID_SIZE` 84, `V6_POST_EPID_SIZE` 124, `V6_DECRYPT_SIZE` 256,
  `PID_BUFFER_SIZE` 64 WCHAR.
- **KMS-005** — v4 framing: plaintext `REQUEST` + 16-byte CBC-MAC. The response field py-kms calls
  `unknown` is not unknown — big-endian `0x00000200` is the NDR conformant-array `MaximumCount`
  (`LE32 0x00020000`).
- **KMS-006** — v5 framing: `Version(4) ‖ IV(16) ‖ AES-CBC(REQUEST + 4 pad)`. Response IV **must be
  byte-identical to the request IV** — genuine v5 clients check this.
- **KMS-007** — v6 framing: same request layout; response body adds
  `keys(16) ‖ hash(32) ‖ hwid(8) ‖ xorSalts(16)` plus outer `hmac(16)`. Response IV is fresh random
  and must differ from the request IV; reusing the v5 rule is the loudest emulator tell in the class.
- **KMS-008** — Version dispatch: `major ∈ {4,5,6}` **and** `minor == 0` only. Reject "v6.1" rather
  than servicing it as v6. `v6 = major > 5` selects the tweaked cipher.
- **KMS-009** — **Exact** length validation, not `>=`. MM18 is the one case where *neither*
  implementation is right: vlmcsd's `>=` plus a floor that wrongly includes the RPC prologue lets a
  268–275-byte (NDR32) or 276–283-byte (NDR64) v6 request read up to 8 bytes of uninitialised stack.
  Require the stub length to equal the declared version's fixed size exactly; else `0x8007000D`.
- **KMS-010** ⚑ — Do **not** copy vlmcsd's "allow bigger requests to support buggy RPC clients
  (e.g. wine)" laxity. Verify with a Wine client whether over-long requests occur (TEST-014); if so,
  accept trailing bytes but never *read* them.
- **KMS-011** — `PIDSize = (ucs2_len + 1) << 1`, capped 128; NUL-terminated UCS-2; **no interior
  NUL**. vlmcsd validates client-side only and never bounds what it emits.
- **KMS-012** — Echo `versionMinor`/`versionMajor`, `CMID`, `responseTime = requestTime` verbatim.
- **KMS-013** — Emit the RPC HRESULT DWORD as a *separate field*, never folded into NDR padding.
  py-kms structurally cannot return a non-zero HRESULT because `getPadding()` returns `4 + align`
  and those four bytes are always zero.
- **KMS-014** — Unsupported-version path returns a well-formed RPC response carrying `0x8007000D`,
  not `0xC004F042` and not a TCP reset. py-kms's `finalResponse.decode('utf-8').encode('utf-8')` on
  bytes beginning `42 F0 04 C0` raises `UnicodeDecodeError` 100 % of the time — the error path has
  never once executed successfully in either version. GuillaumeDescombes's `bytes()` fix is correct.
- **KMS-015** — HRESULT vocabulary as typed constants with client-facing text: `0xC004F042` declined
  / `0x8007000D` invalid data / `0xC004F06C` timestamp differs / `0xC004D104` invalid data used /
  `0x80070005` access denied / `0xC004B005` authorization failed / `0xC004F050` invalid key.
  `1` = RPC protocol error.
- **KMS-016** — License-status table for logging: 0 Unlicensed, 1 Licensed, 2 OOB grace, 3 OOT grace,
  4 non-genuine grace, 5 notification, 6 extended grace. Values > 6 logged, never fatal.
- **KMS-017** — `IsClientVM` and `GraceTime`: parsed, logged, never a decision input.
- **KMS-018** — `SkuId`/`ActID` is **never** a policy input, mirroring a genuine host. Only `KMSID`
  drives grant/refuse and ePID selection; `AppID` selects the counting bucket.
- **KMS-019** — Workstation name: 64 UCS-2 max, decoded lossily for logging, never trusted. Reject
  cleanly rather than py-kms's negative-length unpack past 126 bytes.
- **KMS-020** — FILETIME with `EPOCH_AS_FILETIME = 116444736000000000`, via a checked conversion that
  cannot panic on an out-of-range client value. Use `time`/`jiff`, not hand arithmetic.
- **KMS-021** — `VLActivationInterval` 120 min, `VLRenewalInterval` 10080 min. MM20 is the one
  genuine three-way agreement and matches Microsoft's documented defaults. Modern clients (8.1+)
  ignore both. Build-time overridable, range-validated at compile time.
- **KMS-022** — **No artificial delay anywhere.** py-kms's `time.sleep(1)` in the v4 path is both a
  deterministic timing fingerprint and a per-thread throughput cap.
- **KMS-023** — Bounded response builder: one fixed-capacity `MAX_RESPONSE_SIZE` buffer, written
  forward. No `memmove` compaction.

---

# 3. CRY — cryptography

- **CRY-001** — Published Microsoft constants:
  - v4 Rijndael-160 key (20 B) `05 3D 83 07 F9 E5 F0 88 EB 5E A6 68 6C F0 37 C7 E4 EF D2 D6`
  - v5 AES-128 key `CD 7E 79 6F 2A B2 5D CB 55 FF C8 EF 83 64 C4 70`
  - v6 AES-128 key `A9 4A 41 95 E2 01 43 2D 9B CB 46 04 05 D8 4A 21`
- **CRY-002** — **The A8 exception.** Stock `aes` can do neither primitive: v4 needs **Rijndael with
  a 160-bit key** (11 rounds), outside the AES standard; v6 needs a **tampered key schedule** —
  after normal expansion, `Key[4*16] ^= 0x73`, `Key[6*16] ^= 0x09`, `Key[8*16] ^= 0xE4` (py-kms
  reaches the same bytes by XORing `state[0]` after MixColumns at rounds 4/6/8 — algebraically
  identical). **Decision: one minimal Rijndael implementation in `kmsrs-crypto`** with exhaustive
  KATs and an `// A8 exception` module doc — one implementation, one test surface.
  **radawson's fork is the cautionary tale**: it swapped in python-`cryptography`, silently dropped
  the v6 round tweaks, and nothing caught it because there were no tests.
- **CRY-003** — `AesCmacV4` is *not* CMAC: raw CBC-MAC, zero IV, ISO/IEC 7816-4 padding (`0x80` then
  zeros) **always appended even at a multiple of 16**, no subkey XOR. Name it accurately.
- **CRY-004** — Never write past the message (vlmcsd's version always writes 16 bytes of slack every
  caller must guarantee). Take a slice, return a tag.
- **CRY-005** — The **NULL-IV decryption trick**: decrypt 16 blocks starting *at the IV itself* with
  a NULL IV, so blocks 2..16 come out correct and block 1 becomes `D_k(IV_req)` — the shared secret
  for the salt and IV fields. `Pad[4]` is four `0x04` bytes because 236 mod 16 = 12.
- **CRY-006** — v5 response: copy 20 bytes (Version + decrypted request IV), encrypt with a NULL IV,
  so the first ciphertext block is `E_k(D_k(IV_req)) = IV_req`.
- **CRY-007** — v6 response: fresh random `response->IV`; `D_k(IV_req)` into `XoredIVs`; after
  NULL-IV encryption the wire IV is `E_k(random)`.
- **CRY-008** — Salt proof (v5 and v6): random `S`, `Hash = SHA256(S)`, transmit `S XOR D_k(IV_req)`.
- **CRY-009** — v6 HMAC key: `timeSlot = ClientTime / TIME_C1 * TIME_C2 + TIME_C3 + tolerance * TIME_C1`
  with `TIME_C1 = 0x00000022816889BD` (≈4.11 h in 100 ns units), `TIME_C2 = 0x000000208CBAB5ED`,
  `TIME_C3 = 0x3156CD5AC628477A`; `key = SHA256(LE64(timeSlot))[16..]`.
- **CRY-010** — HMAC-SHA256 from `response->IV` for `encryptSize - 16` bytes; transmit the **last 16
  bytes**. Creation tolerance 0; client verification retries −1, 0, +1.
- **CRY-011** — Padding: inclusive PKCS#7-style, `pad = (~len & 15) + 1`, so a multiple of 16 gets a
  whole extra `0x10` block. Wire size `4 + roundup16(148 + pidSize)` (v6) / `4 + roundup16(108 +
  pidSize)` (v5) — compute and assert; the client checks it.
- **CRY-012** — **Validate padding on decrypt, server-side.** Neither implementation performs any
  integrity check on inbound ciphertext. py-kms's stripper checks only `len % 16` and
  `numpads <= 16`, so a trailing `0x00` makes `val[:-0]` return an **empty** buffer, silently
  discarding the plaintext. Require last byte ∈ 1..=16, all pad bytes equal.
- **CRY-013** — CSPRNG for every random value: v6 IV, salt, pre-charge GUIDs, ePID key IDs/LCID/date,
  association group, bind_ack pad bytes, client CMIDs and workstation names. **Nobody does this** —
  vlmcsd reseeds libc `rand()` with `srand(tv_sec ^ tv_usec)` at the start of *every connection*
  (~20 bits of seed entropy); py-kms uses Mersenne Twister and its one `os.urandom` call is dead
  code. See OS-012 for the Hermit trap.
- **CRY-014** — Ciphertext length validated *before* it reaches the cipher (py-kms raises `IndexError`
  from deep inside AES because a trailing `':'` field absorbs arbitrary bytes and feeds them to CBC).
- **CRY-015** — No shared mutable cipher state. py-kms's `AESModeOfOperation.aes = AES()` is a
  **class** attribute, so a concurrent v5 request can flip `v6 = False` mid-v6-encryption and emit
  ciphertext mixing tweaked and untweaked rounds — an intermittent, load-dependent activation failure.
- **CRY-016** — Key schedule computed once per key, not per block (py-kms recomputes it every 16
  bytes: ~13 ms per 256-byte CBC op).
- **CRY-017** — Constant-time is **not required** (both keys are published) but is free with a
  bitsliced backend. Document that `kmsrs-crypto` is not reusable for real secrets.
- **CRY-018** — SHA-256 and HMAC from `sha2` + `hmac`. vlmcsd's internal SHA-256 does aligned 32-bit
  loads on caller buffers (UB on strict-alignment targets) and uses a 32-bit length counter.
- **CRY-019** — KATs: AES-128 FIPS-197; Rijndael-160; the v6 tweaked schedule against captured
  vlmcsd/py-kms output; CBC-MAC-160 against both; the v6 time-slot derivation across slot boundaries.

---

# 4. WIRE — DCE/RPC transport

Interface `51c82175-844e-4750-b0d8-ec255555bc06` v1.0, opnum 0, `ncacn_ip_tcp`.

- **WIRE-001** — 16-byte header: `{VerMajor, VerMinor, PacketType, PacketFlags, DataRepresentation,
  FragLength, AuthLength, CallId}`.
- **WIRE-002** — Accept PDU types 11 (bind), 14 (alter_context), 0 (request). Emit 12, 15, 2, 3, 13.
  py-kms accepts only 11 and 0 and emits only 12 and 2.
- **WIRE-003** — **`alter_context` support.** Win8+/2012+ clients send it after an NDR64 bind. In
  py-kms this is masked by its NDR64 rejection, but the two bugs are independent.
- **WIRE-004** — NDR32 `8a885d04-1ceb-11c9-9fe8-08002b104860` v2; NDR64
  `71710533-beba-4937-8319-b5dbef9ccc36` v1; BTFN pseudo-GUID prefix `2c 1c b7 6c 12 98 40 45`.
- **WIRE-005** — Negotiation exactly as Microsoft: if NDR64 is offered and enabled, ACK NDR64 and
  NACK NDR32 (a real host accepts exactly one syntax); else ACK NDR32. NACK reason
  `2 = RPC_SYNTAX_UNSUPPORTED` when the interface matched, `1 = RPC_ABSTRACTSYNTAX_UNSUPPORTED`
  when it did not.
- **WIRE-006** — **Per-context-item NACK, never a connection drop.** py-kms indexes a bare dict, so
  an unrecognised transfer syntax is a `KeyError` swallowed by a no-op `handle_error` and the client
  gets a silent RST with no bind_ack, no bind_nak and no log line.
- **WIRE-007** — BTFN: match the **first 8 bytes** (bytes 8–9 carry requested feature bits per
  MS-RPCE), reply `AckResult = 3`, `SyntaxVersion = 0`,
  `AckReason = requested & (SEC_CONTEXT_MULTIPLEX | KEEP_ORPHAN)`, ACKed regardless of abstract
  syntax. py-kms demands an exact GUID match and hardcodes `Reason=3`.
- **WIRE-008** — Validate the **abstract syntax** at bind. py-kms ACKs a bind for *any* interface
  offering NDR32.
- **WIRE-009** — Validate `ctx_id` against accepted contexts and `op_num == 0`; else `nca_s_unk_if`
  (`0x1c010003`). Enforced by ARCH-006's typestate.
- **WIRE-010** — **Per-connection association group.** Random 32-bit drawn once per process,
  incremented per accepted connection. `0x1063BF3F` — py-kms's worldwide constant — is *the* most
  reliable passive fingerprint in the class: one bind_ack identifies the software.
- **WIRE-011** — `SecondaryAddress` from `getsockname()` on the **accepting** socket
  (`NI_NUMERICSERV`), NUL-terminated ASCII port; length 0 for alter_context. py-kms echoes the
  configured primary port regardless of which listener accepted.
- **WIRE-012** — `frag_len` **computed**, never constant. py-kms's `36 + ctx_num*24` is correct only
  for a 2–6-digit port; a single-digit port produces a 32-byte packet advertised as 36.
- **WIRE-013** — Reproduce the 4-byte-alignment shuffle when the secondary address is under 3 bytes,
  via an alignment-aware writer rather than vlmcsd's self-described "really ugly" pointer maths.
- **WIRE-014** — **Response headers are constructed, not echoed.** Set `FIRST|LAST`, our own
  `DataRepresentation` (`BE32(0x10000000)`), `AuthLength = 0`; echo only `CallId` and version.
  MM17 is one of only three rows where py-kms beats vlmcsd, which `memcpy`s the whole request header
  and would reflect `RPC_PF_CANCEL_PENDING` back or answer a big-endian client with little-endian data.
- **WIRE-015** — **Fault PDUs echo the request's CallId.** vlmcsd's `SendError()` always carries the
  static `CallId 2` — trivially fingerprintable. Never identify a fault by "body length == 32".
- **WIRE-016** — Fault statuses `nca_s_unk_if` `0x1c010003`, `nca_s_proto_error` `0x1c01000b`; flags
  `FIRST|LAST|NOT_EXEC`.
- **WIRE-017** — Never leave padding uninitialised. vlmcsd *deliberately* leaks uninitialised stack
  in the bind_ack `SecondaryAddress` padding because "M$ RPC does not do this. Pad bytes contain
  apparently random data", and `SendError()` leaks 2 more via `CancelCount`/`Pad1`. **Safe Rust
  cannot leak stack — so fill those bytes from the CSPRNG.** Zero-filling would itself be a
  fingerprint. (FP-011.)
- **WIRE-018** — Emit the cosmetic 4-byte zero pad to a 32-bit boundary after the HRESULT; vlmcs
  warns when a server omits it.
- **WIRE-019** — NDR stub layouts: NDR32 request `{DataLength, DataSizeIs, Data[]}` (data at 16),
  response `{DataLength, DataSizeMax = 0x00020000 referent id, DataSizeIs, Data[]}` (data at 20).
  NDR64 moves these to 24 and 32. On error, zero the length fields, omit `size_is`, write the HRESULT
  in its place.
- **WIRE-020** — Cross-check `AllocHint` and NDR lengths; vlmcs warns on a mismatch.
- **WIRE-021** — **Keep the association open after an activation** (MM05). py-kms unconditionally
  disconnects, which vlmcs reports as "probably non-multitasked KMS emulator" and `man/vlmcsd.8`
  calls "a direct violation of DCE RPC". Build-time opt-out only.
- **WIRE-022** — **Fragmentation: inbound reassembly only.** Our responses top out at 384 bytes, far
  under the 5840 `MaxXmitFrag` clients offer, so we never need to emit a fragmented PDU. Inbound:
  honour `PFC_FIRST_FRAG`/`PFC_LAST_FRAG`, accumulate into a per-connection buffer capped at
  `MAX_REQUEST_SIZE`, fault if it would exceed. Roughly 40 lines and one bounded buffer, and we must
  parse and bound `FragLength` regardless (WIRE-023). Calibration: vlmcsd's own checker carries the
  comment *"vlmcsd does not support fragmented packets (not yet neccassary)"* and in twenty years
  nobody hit it — this is insurance against a middlebox or non-Microsoft client, not a known
  requirement. The alternative (refuse fragments) is only acceptable with clean detection, and once
  you have the detection you are most of the way to the reassembly.
- **WIRE-023** — Bound `FragLength` **before** allocating.
- **WIRE-024** — Read the header, then exactly `FragLength − 16` bytes. py-kms does one fixed
  `recv(1024)` with no reassembly and replies with `send()` not `sendall()` — both corrupt under
  fragmented TCP.
- **WIRE-025** — Reject any PDU shorter than 16 bytes before parsing (GuillaumeDescombes's hardening,
  the best single change in the py-kms fork network).
- **WIRE-026** — RPC authentication → A4, but **never echo a non-zero `auth_len` into a bind_ack that
  carries no trailer** — py-kms emits a malformed packet whenever a client sends one. Always write
  `AuthLength = 0`; fault on an inbound trailer rather than treating it as stub data.
- **WIRE-027** — Client `CallId` starts at 2 ("M$ starts with CallId 2. So we do the same") and
  increments. Tolerate Wine's always-1 response CallId, warn once.
- **WIRE-028** — `RPC_PF_MULTIPLEX` (0x10): echo the client's request; never set `PFC_CONC_MPX`
  unrequested the way py-kms does.
- **WIRE-029** — On NDR64 connections the **first** request is NDR32 and subsequent ones NDR64; both
  paths must work on one association.
- **WIRE-030** — Support NDR64 on 32-bit systems (vlmcsd does, Microsoft does not) — free in Rust.

---

# 5. POL — activation policy and host state

- **POL-001** — **Reported count: per-client views over a saturating shared world model.**

  ```
  R_app     = distinct CMIDs actually observed for this AppID (decaying, bounded)
  P_app     = pre-charge constant, build-time
  world     = min(P_app + R_app, 2 * NCountPolicy_app)   ← shared, materialized, saturating
  reported  = max(world, client_N_Policy)                ← per-request, never written back
  ```

  A real host caches *2N* CMIDs and reports how many are cached, so it saturates at 50 (client) /
  10 (server & Office) — the number both emulators already emit by arithmetic. The modelled table
  therefore buys authenticity in three specific places: keeping the Windows and Office buckets
  correctly distinct, genuine slow-growth when built with pre-charge off, and not reflecting absurd
  demands globally. Its real justification is the event log (OBS-004), so materialize once and use
  twice. Detection surface is nil: every honest client with the same `N_Policy` sees the same number,
  and a Windows client seeing 50 while an Office client sees 10 is correct, not a tell.
- **POL-002** — CMID table: one bucket per **AppID** (Windows, Office 2010, Office 2013+ — note
  Office 2013/2016/2019/LTSC share a bucket). Bounded capacity, LRU eviction.
- **POL-003** — **30-day expiry and decay.** Microsoft's host removes a CMID after 30 days without
  renewal and *decrements*; on renewal the entry is deleted and re-inserted. This exists nowhere.
  Same data structure as the event log — implement once.
- **POL-004** — A known CMID returns the current count unchanged; an unknown CMID is inserted; a full
  table evicts oldest.
- **POL-005** — **The overcharge poisoning defect is dissolved, not mitigated.** A genuine host can
  be permanently "killed" by an overcharge request of ≥376 required clients followed by 671
  activations, and vlmcsd is deliberately bug-compatible with only a restart to recover. Under
  POL-001 an anomalous demand is satisfied **for that client only and never mutates global state**,
  so the attack has no target: no bounds, no restart, no authenticity/availability trade-off.
- **POL-006** — `required_clients = N < 1 ? 1 : N << 1`. Under A6 we accept and answer any `N_Policy`
  including > 1000, clamping what enters the table and logging a warning; the client's bespoke view
  is floored at `N_Policy` — the minimum that activates, not `2 × N_Policy`. py-kms reflecting 10000
  back for a demand of 5000 is "neither realistic nor safe". Build-time strict mode returns
  `0x8007000D`.
- **POL-007** — With per-client views we never need to return `0xC004D104` (the 671-cap refusal);
  eviction is strictly more compatible under A6. Keep the refuse path behind a build-time strict flag.
- **POL-008** — Keep py-kms's one genuine policy win: a **clamp with a genuineness warning** — but
  emit it at *build* time, since there is no runtime `-c`. Note the Docker default `CLIENT_COUNT=26`
  is *worse* than omitting it.
- **POL-009** — `MinActiveClients` is 0 for every CSVLK in every shipped database of both projects,
  so the documented floor is inert everywhere. Populate it meaningfully or delete the concept.
- **POL-010** — **The product gate is three gates, not one.** vlmcsd's `-K` is an all-or-nothing
  bitmask and py-kms reads the flags from zero lines of code; both are wrong because the three checks
  have opposite risk profiles:

  | Gate | Compatibility cost of refusing | Authenticity gain | Decision |
  |---|---|---|---|
  | Unknown KMS ID | **High** — the database will always lag Microsoft | none | **permissive** |
  | `IsRetail` / `IsPreview` | ~zero — retail SKUs have no GVLK, so no legitimate client can send one | real — a genuine host *cannot* activate these | **strict** |
  | `AppID` ≠ the KMS ID's app | ~zero — that is a malformed request | real | **strict** |

  Refusing unknown products must never happen: it is why a 2019-era vlmcsd still activates Windows 11,
  and py-kms's crash on an unknown GUID is literally the mechanism behind the "Server 2022 doesn't
  work" reports. Refusing a retail SKU costs nothing and closes a cheap probe. This only works
  because DB-001 gives us *accurate* flags from Microsoft's own artifacts; a wrong flag would refuse
  a legitimate client, so the retail/preview gate is a build-time flag that can be flipped without a
  code change.
- **POL-011** — **Clock skew: never reject.** Microsoft's ±4 h tolerance is a documented
  anti-detection measure — a prober sends two requests four hours apart and concludes "emulator" if
  both succeed. Per A6: log the skew, surface it in the event log, offer a build-time strict mode
  returning `0xC004F06C`. Permissiveness costs nothing functionally because the v6 HMAC key derives
  from the *client's* FILETIME, so a skewed client still gets a self-consistent response.
- **POL-012** — Admission control that **rejects rather than queues**. vlmcsd's `-m` is a counting
  semaphore that queues, so slowloris connections hold every worker for `-t` seconds each; py-kms
  spawns one unbounded thread per connection with no timeout by default.
- **POL-013** — Source-IP ACL: **default allow-all**, with CIDR allow/deny lists available.
  IPv6-native with IPv4-mapped normalisation, enforced at **accept** time. vlmcsd's `-o` only
  distinguishes RFC1918-class "private" from "public", is defeated by NAT, and deliberately
  classifies `100.64.0.0/10` (CGNAT) as public. Fork prior art: KptCheeseWhiz's `-Y` (IPv4-only,
  memory-unsafe, denies **all** IPv6 including loopback once enabled, enforced after the RPC
  handshake) and MelroyB's blacklist file — the only sane rule grammar in the network: addresses,
  CIDRs, `start-end` ranges, `#` comments, IPv4-mapped normalisation.
- **POL-014** — Token-bucket rate limit per source IP plus a global in-flight cap. Blocked attempts
  are *events* (OBS-004), not silent drops. Note this is the correct home for "stop one product being
  hammered" — keyed on `(source IP, app)`, i.e. on something the client cannot choose, unlike a
  CMID-keyed quota (A29).
- **POL-015** — Allowlists keyed on `WorkstationName` are **not** authentication — the field is
  client-supplied. The two forks that tried produced a V6-bypassable gate and a `sys.exit(0)` from
  inside a request handler that takes the whole server down with a log line blaming a bind failure.
- **POL-016** — The policy layer returns a total `enum { Grant(..), Refuse(Hresult) }` — never an
  unanswered request. OzanHazar's quota denial propagates `None` through the encrypt path.
- **POL-017** — Graceful degradation on unknown products is the **default** (MM11): unknown `KMSID`
  → raw GUID name, fall back to the `CsvlkSelection::Fallback` variant (ARCH-007), **activate**.

---

# 6. ID — ePID and HWID identity

- **ID-001** — **One ePID per CSVLK group, stable for the process lifetime** (MM01, "the canonical
  emulator-detection test"). py-kms regenerates on every response, so two byte-identical requests on
  one connection return different ePIDs. See PKG-011 — this property is also what forbids multi-replica
  deployment.
- **ID-002** — **Product-correct CSVLK selection**: `KMSID → EPidIndex → CsvlkData`, direct mapping.
  py-kms's loop appends a Server-2019 fallback for every *non*-matching item then `random.choice`s
  over the whole list — measured 4887/5000 (97.7 %) wrong for Office 2010, and it can emit impossible
  combinations like GroupId `00096` with build 17763. Hamad3bdulla's fork is the only place this was
  ever fixed and it remains unfixed upstream; the audit calls it "the highest-value single finding in
  the network".
- **ID-003** — ePID format `PPPPP-GGGGG-KKK-KKKKKK-CC-LLLL-BBBBB.0000-DDDYYYY`. Widths `[R1]`:
  PlatformId `%05u`, GroupId `%05u`, `keyId/1000000` `%03u`, `keyId%1000000` `%06u`, channel literal
  `03`, LCID **unpadded**, build unpadded + `.0000`, day `%03u`, year `%04u`.
- **ID-004** — **Day-of-year is 1-based** `[R1]`. vlmcsd emits `tm_yday + 1`; License Manager's ePID
  *validator* does `date.AddDays(dayOfYear - 1)` and rejects unless it round-trips against .NET's
  1-based `DayOfYear`, so `000` would be treated as malformed. **py-kms is the outlier and is wrong.**
- **ID-005** — **LCID is unpadded** `[R1]` — three implementations agree and License Manager's parser
  accepts `^[0-9]{1,5}$`. Practically moot: every LCID a real host can report is ≥ 1025.
- **ID-006** — **License channel is always `03`** `[R1]` (`00`/`01` Retail, `02` OEM, `03` Volume
  GVLK/MAK).
- **ID-007** — Compute the activation date in UTC. py-kms uses `time.mktime` on local time, making it
  DST-sensitive.
- **ID-008** — 158-entry `LcidList` (valid for .NET 4.0, all unique). Drawn once per process and
  **shared by all CSVLK groups**, as vlmcsd's `-r1` does, so the set looks self-consistent.
- **ID-009** — Host build drawn once at startup, **shared across groups**; PlatformId and the
  activation-date lower bound both derive from it. `getPlatformId` returns the PlatformId of the
  first entry with `BuildNumber <= hostBuild`; `getReleaseDate` scans from the end for the first
  `BuildNumber >= hostBuild`.
- **ID-010** — **ePID ↔ NDR64 self-consistency.** Unique to vlmcsd and purely anti-detection: the
  advertised build's `UseNdr64` flag must match the RPC features offered. 9200/9600/14393/17763/
  20348/26100 are NDR64; 6002/7601 are not. py-kms will claim build 26100 while rejecting NDR64 — a
  combination no real host produces. Model as a *type-level* pairing so an inconsistent configuration
  cannot be constructed.
- **ID-011** — vlmcsd achieves ID-010 with `while (TRUE)` loops that **hang at startup** if no build
  matches. Use a compile-time-validated, non-empty-by-construction filtered set.
- **ID-012** — Per-CSVLK-group HWID (8 bytes, v6 only). vlmcsd can only apply a custom HwId when an
  explicit ePID is *also* set, because the `memcpy` sits inside the `Epid != NULL` branch.
- **ID-013** — **Never ship a constant HWID.** `3A1C049600B60076` ("HwId from the Ratiborus VM") and
  `364F463A8863D35F` are both published cross-deployment fingerprints. Random-per-process is the
  floor; harvesting is out of scope (→A28).
- **ID-014** — ePID length bounded in **UCS-2 characters**, not bytes (vlmcsd's check is in chars
  while its docs claim 63 bytes) — encode the unit in the type.
- **ID-015** — The arithmetic vlmcsd divides by zero on — `rand % (MaxKeyId − MinKeyId)` when a CSVLK
  has `MinKeyId == MaxKeyId`, and `rand % (maxTime − minTime)` when a release date equals "now" — is
  non-empty by construction under ARCH-007 and DB-006.
- **ID-016** — The `int('')` class of failure is impossible: py-kms has 13 `CsvlkItem`s with empty
  `GroupId`/`MinKeyId`/`MaxKeyId` and 3 with empty `InvalidWinBuild`, and picking one raises at rates
  measured up to 8.2 % for some products. Rejected at build time (DB-004).
- **ID-017** — Honour `InvalidWinBuild` per CSVLK when choosing a host build.
- **ID-018** — Emit the HWID field only for v6.
- **ID-019** — **Key ranges are a set of blocks, not a min/max.** Server 2022's CSVLK has two valid
  blocks — `0–19999` and `30000–20029999` — with an **invalid gap at 20000–29999** `[R1]`. py-kms's
  `MinKeyId=0, MaxKeyId=20029999` can emit a key ID in the hole.

---

# 7. DB — product database

- **DB-001** — **Source of truth is Microsoft's `pkeyconfig`** `[R1]`. `pkeyconfig-csvlk.xrm-ms`
  (present in every Windows install and in the public `mcr.microsoft.com/windows/servercore` images)
  and `pkeyconfig-office-kmshost.xrm-ms` (inside the freely downloadable Office Volume License Packs)
  carry `RefGroupId`, `Start`, `End` and `PartNumber` for every CSVLK, base64+gzip'd inside an XrML
  wrapper. `Security-SPP-KmsCountedIdList` in the accompanying licence files carries the real KMS
  counted IDs. GVLKs come from Microsoft's published tables on learn.microsoft.com. **This makes the
  vlmcsd / License Manager / py-kms hierarchy unnecessary for these fields.**
- **DB-002** — `kmsrs-dbgen`: a host-side tool that extracts, cross-checks and emits the reviewable
  data file. Run manually or on a schedule, **not** during the build — the extracted TOML is
  committed with per-row provenance (source artifact, SHA-256, product) so builds stay hermetic and
  Nix-friendly, and a data change is reviewable in a pull request. Closes the audit's "no fork
  produced tooling to regenerate from a readable source" *and* "no fork verifies GVLKs against an
  authoritative source". **Rule: data ships through this pipeline or it does not ship** (A26, A30).
- **DB-003** — `build.rs` generates `static` Rust tables from the committed file. No runtime parsing
  (py-kms parses its 88 KB XML **twice per activation**).
- **DB-004** — Compile-time invariants — the class of bug behind *every* data defect in the audits:
  every GUID parses; `EPidIndex < CsvlkCount` (vlmcsd **never** checks this, and `EPidIndex = 250`
  yields a remotely-triggerable heap overflow once loaded); `AppIndex`/`KmsIndex` in range; key-ID
  blocks non-empty and non-overlapping (ID-019); `GroupId` non-empty; `InvalidWinBuild` parses; every
  referenced item exists (Rubberverse ships an `<Activate>` pointing at a non-existent
  `00000000-…`); `ReleaseDate` valid ISO 8601 (upstream shipped `2023-10-31:00:00:00Z`); attribute
  names spelled correctly (upstream shipped `DefaultKmsprotocol`); `HostBuildCount ≥ 1` with a
  non-empty NDR64-consistent subset (ID-011); no duplicate SKU IDs (py-kms has 296 SkuItems with 287
  unique IDs). *"A 20-line schema check run in CI would have caught every one of these."*
- **DB-005** — **Do not validate the UUID version nibble** `[R1]`. Office LTSC 2024's genuine
  `kmsCountedId` is `a8973cb5-bf03-**0**a4c-9cef-703099645ab3` — an invalid version nibble, yet it is
  what Microsoft ships. vlmcsd's `CheckVersion4Uuid()` emits a spurious warning for it. The heuristic
  works only in reverse: the two *fabricated* IDs in py-kms are valid UUIDv5.
- **DB-006** — Reject rather than skip. Where py-kms's fixes were `except KeyError: pass`, ours is a
  build failure.
- **DB-007** — **CSVLK table** `[R1]`, all CONFIRMED from Microsoft `pkeyconfig`:

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

  Release dates (lower bound for the random activation date): WS2025 2024-11-01, WS2022 2021-08-18,
  WS2019 2018-10-02, Office LTSC 2024 2024-09-16, Office LTSC 2021 2021-09-16.
- **DB-008** — **KMS counted IDs** `[R1]`, from Microsoft's `Security-SPP-KmsCountedIdList`:
  Windows Server 2022 `b74263e4-0f92-46c6-bcf8-c11d5efe2959`;
  **Windows Server 2025 `907f1f65-adcd-4a2e-95bc-4bf500bc6e58`** (py-kms's `4b83307d-…` is a
  fabricated UUIDv5); Office LTSC 2021 `86d50b16-4808-41af-b83b-b338274318b2`;
  **Office LTSC 2024 `a8973cb5-bf03-0a4c-9cef-703099645ab3`** (py-kms's `1b4db7eb-…` likewise
  fabricated). Plus two KMS IDs py-kms lacks entirely: Windows 10/11 **2021** LTSC volume
  `3b576817-7b75-4362-9e13-223f2d9e9c97` and **2024** LTSC volume
  `e85ee727-69c4-4528-99d2-216b0f065e38`.
- **DB-009** — **GVLK corrections** `[R1]`: Office LTSC Professional Plus 2024 =
  `XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB` (the source that assigned `CW94N-K6GJH-9CTXY-MG2VC-FYCWP` confused
  it with PowerPoint LTSC 2024). Windows Server 2025 Datacenter = `D764K-2NDRG-47T6Q-P8T8W-YP6DF`
  (License Manager's `CNFDQ-…` is wrong). Server 2025 Datacenter Azure Edition =
  `XGN3F-F394H-FD2MY-PP6FD-8MCRC` (py-kms's `NQ8HH-…` is wrong).
- **DB-010** — **Product coverage target**: Windows client Vista → 11 24H2/25H2 including all Win 10
  feature updates, Enterprise LTSC 2019/2021/2024, IoT Enterprise LTSC 2021/2024, Enterprise
  multi-session (`ServerRdsh`), Windows 11 SE / SE N, China Government; Windows Server 2008 A/B/C
  through 2025 with Azure Edition / Azure Core variants; Office 2010 → LTSC 2024 with Project and
  Visio counterparts.
- **DB-011** — **Host build table** `[R1]` — PlatformId is **3612 for every build ≥ 10240**,
  corroborated by two genuine ePIDs from real machines. `UseForEpid` rows in bold:

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

  **Build 28000 is real** `[R1]` — KB5077179, OS Build 28000.1575, 2026-02-10, a scoped 26H1 release
  for Snapdragon X2 / NVIDIA N1X devices, still being serviced.
- **DB-012** — Flags per build: `UseNdr64`, `UseForEpid`, `MayBeServer`. **All three must actually be
  read.** vlmcsd reads only `UseNdr64`; py-kms reads none and keys its host-build loop on a
  `WinBuildIndex` attribute its own v2.0 database deleted, so **100 %** of Organization-fork ePIDs
  claim build 17763 and its entire 30-row modern catalog is dead data.
- **DB-013** — **Ship the GVLK table** even though the protocol never carries a key; it feeds the web
  instructions page (OBS-008).
- **DB-014** — Ship human-readable product names by default. Stock vlmcsd links a compact database
  with `SkuItemCount = 0` where every name points at one shared "Unknown" string.
- **DB-015** — Per-KMS-ID metadata: `AppIndex`, `EPidIndex`, `ProtocolVersion`, `NCountPolicy`,
  `IsRetail`, `IsPreview` (the last two are now load-bearing — POL-010). Note vlmcsd's *server* reads
  `NCountPolicy` only from the AppItem while its *client* reads it from the SkuItem, and the
  per-KmsItem copy is dead — pick one.
- **DB-016** — The `Office 2013 (Pre-Release) → EPidIndex 0` question **dissolves**. vlmcsd maps that
  KMS ID to the *Windows* CSVLK group, and the audit notes the entry is "redundant, since index 0 is
  also the unknown-product fallback" — which is the tell: a record set to 0 is indistinguishable from
  a record nobody set, so it is almost certainly vestigial. Three reasons it stops mattering: it is a
  preview product and DB-017 drops those; our data comes from Microsoft `pkeyconfig`, so if it is not
  in a Microsoft artifact it does not ship; and ARCH-007 makes `Fallback` a distinct variant from
  `Resolved(0)`, so the ambiguity that generated the question cannot be expressed.
- **DB-017** — Drop the empty-GVLK preview placeholders (Py-KMS-Organization's cleanup took 296 → 257
  SKUs while *raising* the number of usable GVLKs).
- **DB-018** — Size discipline: ~15–20 KB of data. Verify it fits the Hermit image budget; make the
  GVLK/instructions payload a separately feature-gated section if not.

---

# 8. DISC — discovery

**"The single largest deployment-usability gap in the class."** A genuine KMS host performs a dynamic
DNS update at install time creating `_VLMCS._TCP.<domain>` SRV on port 1688 — that is how
domain-joined clients activate with *zero per-client configuration*. Nobody publishes anything;
vlmcsd's complete RFC 2782 implementation is compiled into the **client only**.

- **DISC-001** — Client-side SRV resolution: `_vlmcs._tcp[.domain]`, full RFC 2782 ordering
  (`random_weight = (rand % 256) * isqrt(weight * 1000)`, ascending priority then descending random
  weight), trying each candidate until connect + bind succeeds. Use `hickory-*` (A8) — vlmcsd bundles
  a whole BIND parser for this.
- **DISC-002** — **Server-side SRV publishing via RFC 2136 is declined** → A31. The reasoning:
  in an AD domain — the primary use case — real hosts register via **GSS-TSIG** using the machine
  account's Kerberos credentials, because AD DNS defaults to secure-updates-only; shared-key TSIG
  does not help there, and GSS-TSIG needs runtime secrets far outside A3/A5. That leaves BIND-style
  managed DNS, where **adding a static SRV record once is equally easy and more auditable**. RFC 2136
  occupies a narrow middle where neither applies, while costing a new outbound protocol, re-registration
  logic on DHCP lease change, and a **secret embedded in the shipped artifact** — which would mean the
  published container could never enable it anyway.
- **DISC-003** ⚑ — **mDNS autoconfiguration for `.local`.** The crux is one question: does SPP's SRV
  lookup go through the generic Windows DNS Client path (which handles `.local` via mDNS) or through
  something narrower? Everything else follows. **LLMNR is ruled out on paper** — it carries A/AAAA/PTR
  only, no SRV.

  **The de-risking point:** even if SPP refuses SRV-over-mDNS, the responder is still worth shipping,
  because Windows definitely resolves `.local` A/AAAA via mDNS. Worst case we deliver
  `slmgr /skms kmsrsos.local` instead of an IP address — no DNS server, no hosts file, and it survives
  our address changing under DHCP. The work is therefore not all-or-nothing on an unverified assumption.
- **DISC-004** ⚑ — **The measurement harness is a standalone deliverable, built before any responder
  code**, with a written findings note in `docs/`. It needs a matrix, not a single test, because the
  query SPP emits depends entirely on suffix configuration:

  | Variable | Values |
  |---|---|
  | Machine | workgroup / domain-joined |
  | Primary DNS suffix | unset / `local` / `example.com` |
  | **DHCP option 15** (connection-specific suffix) | unset / **`local`** |
  | `/skms` | configured / not |
  | Registry | default / `KeyManagementServiceLookupDomain` set |

  DHCP option 15 is the first thing to try and the one nobody seems to have considered: if the DHCP
  server hands out `local` as the domain, the client's connection-specific suffix becomes `local` and
  SPP should query `_vlmcs._tcp.local` — answerable by an mDNS responder, and a setting a homelab
  admin can actually make. Capture on **both 53 and 5353**, record query order and suffixes, and check
  whether SPP follows the SRV target through an mDNS A/AAAA answer. Also measure `TCP_NODELAY`
  behaviour (NET-015) while the VM is up. Same VM serves TEST-013 and TEST-014.
- **DISC-005** — If viable: an mDNS responder answering `_vlmcs._tcp.local` SRV + A/AAAA, using an
  existing crate (`mdns-sd`/`simple-mdns`) rather than hand-rolled multicast DNS (A8). Feature-gated
  off on Hermit.
- **DISC-006** — The instructions page emits, filled in with the running instance's actual address
  and port: a **ready-to-paste zone snippet**, an **`nsupdate` script**, and the **`dnscmd`/PowerShell
  equivalent for AD**, plus the `slmgr /skms` fallback. This is the "covers most of the value" path
  and costs nothing.
- **DISC-007** — Document the shape: `_VLMCS._TCP.<domain>` SRV → port 1688, priority 0, weight 0 by
  convention; multiple hosts via RFC 2782 ordering.

---

# 9. NET — networking and platform layer

- **NET-001** — **Two listening sockets on Linux/Windows**: `[::]` with `IPV6_V6ONLY = 1` **and**
  `0.0.0.0`, each guarded by a stack-existence probe — more portable than one dual-stack socket
  (OpenBSD refuses `IPV6_V6ONLY = 0`; py-kms's fallback triggers on one exact exception string).
  **On Hermit: one socket on `0.0.0.0`** — see OS-009.
- **NET-002** — Port 1688. Multiple listen addresses at build time.
- **NET-003** — Backlog configurable at build time (vlmcsd hardcodes `SOMAXCONN`).
- **NET-004** — **Timeouts live in the sans-io state machine, not in socket options.** A non-infinite
  default (30 s read/write plus a total-connection deadline) is required — vlmcsd's 30 s is the
  better posture, and py-kms's `None` plus no worker cap plus unbounded threads makes a trivial
  slowloris fatal. Hermit forces the design anyway: its `setsockopt` handles only `TCP_NODELAY` and a
  no-op `SO_REUSEADDR`, returning `EINVAL` for `SO_RCVTIMEO`/`SO_SNDTIMEO`/`IPV6_V6ONLY` `[R2]`.
- **NET-005** — Bounded concurrency that **rejects** at accept time when full (POL-012).
- **NET-006** — Accept fairness across listeners. vlmcsd's `select()` loop always takes the *first*
  ready descriptor, so a saturated early listener starves later ones.
- **NET-007** — Partial-IO correctness: loop on short reads/writes, retry on `EINTR`. py-kms uses
  `send()` not `sendall()`.
- **NET-008** — Graceful shutdown: SIGTERM/SIGINT on Unix, `SetConsoleCtrlHandler` on Windows plus
  the service control handler (PKG-008); stop accepting, drain, exit. vlmcsd calls `logger()`
  (`fopen`/`fprintf`) from signal context and neither signals nor waits for in-flight children.
  **Hermit has no signals at all** `[R2]`, so shutdown there is a normal control-flow path.
- **NET-009** — Wakeups must not use an `os.pipe()`-style construct: on Windows a pipe fd cannot be
  registered with a socket selector, which is exactly what breaks py-kms there. Use a socketpair or
  the runtime's notify primitive.
- **NET-010** — Socket options: `SO_REUSEADDR` on Unix, `SO_EXCLUSIVEADDRUSE` on Windows (semantic
  *opposites*; vlmcsd's diagnostic text confuses them). `SO_REUSEPORT` must never be fatal when
  unsupported — it kills py-kms startup on Windows.
- **NET-011** — Bind addresses are compile-time literals, parsed at compile time. Both existing
  implementations use `AI_NUMERICHOST`; py-kms's docs claim hostnames work and it is fatal.
- **NET-012** — Peer addresses are IPv6-native with IPv4-mapped normalisation on the storage path, so
  the same client never appears as both `1.2.3.4` and `::ffff:1.2.3.4`.
- **NET-013** — Windows: no `SO_REUSEPORT`; no Windows-Sandbox hack needed; enable ANSI explicitly
  via `SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING)` rather than a colorama-equivalent shim.
- **NET-014** ⚑ — **Windows clients refuse to activate against 127.0.0.1.** This is the entire reason
  vlmcsd contains a 370-line TAP/TUN driver that swaps `ip_src`/`ip_dst` on every packet. We decline
  the TAP hack (→A13) but the constraint must be documented in the instructions page: use a
  non-loopback address, a second NIC, a container bridge, or a Hyper-V/WSL address.
- **NET-015** — `TCP_NODELAY` **left at the OS default.** Our exchange is one request → one response,
  a single write of ≤384 bytes, with no pipelining, so Nagle likely never engages — the setting is
  probably unobservable either way. Rather than guess what Microsoft's RPC runtime does, measure it
  in the DISC-004 harness while the VM is already set up. Cheap to change later.
- **NET-016** — **systemd socket activation, supported.** `LISTEN_FDS`/`LISTEN_PID` are
  *environment discovery* (CFG-001 category 1), not configuration — the socket is handed to us and we
  choose nothing. **`Accept=no` only.** systemd's `Accept=yes` is the inetd convention — one process
  per connection — which silently destroys both the stable ePID (ID-001) and the CMID table
  (POL-002), the same trap that makes vlmcsd-under-systemd degrade without telling anyone. The two
  are distinguishable at runtime via `getsockopt(SO_ACCEPTCONN)`, so **refuse to start** with a clear
  message rather than degrade.

  The payoff: with socket activation systemd binds 1688 and we never need `CAP_NET_BIND_SERVICE` at
  all — **a process that never had privileges beats one that dropped them**. Combined with
  `DynamicUser=`, Landlock and seccomp, the Linux deployment ends with no capabilities, no user, no
  filesystem access and no syscalls beyond sockets and clocks.

---

# 10. CFG — configuration

- **CFG-001** — Three categories, and only the middle one is ever runtime-settable:
  1. **Environment discovery** — DHCP lease, the address a listener actually bound to (feeds
     WIRE-011), hostname, `isatty(stderr)`, `NO_COLOR`, `LISTEN_FDS`. Observations, not policy.
  2. **Operational settings** — log level and format, listen addresses, web UI on/off and port,
     CIDR lists. **Defined as: cannot change a single byte on the wire.**
  3. **Everything else** — product data, protocol strictness, intervals, identity, table sizes,
     anti-fingerprint behaviour. Build-time only, always.

  The category-2 restriction is load-bearing: a given binary has exactly one on-wire behaviour, so
  TEST-004 validates *the artifact* rather than a configuration of it, reproducibility means
  something, and the surface physically cannot grow into vlmcsd's 27 ini directives × 40 flags — a
  knob that would change wire behaviour is disqualified by definition.
- **CFG-002** — **Doctrine: rebuild from the flake. Escape hatch: one env var.**
  `KMSRSOS_CONFIG` holds a whole TOML document with the same schema `build.rs` consumes. Unset →
  compiled-in defaults. Present → fields override, `deny_unknown_fields`, category-2 only.
  Malformed → exit non-zero immediately with a precise message; never start degraded. One variable,
  one schema, one parser, one validator, two layers, **no per-directive precedence matrix**.

  Works identically on all three platforms `[R2]`: `-e` in Docker, `Environment=` in systemd, and on
  Hermit via a boot-arg `env=KMSRSOS_CONFIG=…` token, which the UEFI loader reads from a plain text
  file `\EFI\hermit\hermit-bootargs` on the image's ESP. Reconfiguring the appliance is therefore
  "rewrite one text file in the image", not "rebuild the binary".
- **CFG-003** — Make the Nix path first-class: a flake function `mkKmsrsos { listen = …; identity =
  …; }` producing a configured package, container image and OS image, so "build your own" is a
  two-line expression.
- **CFG-004** — Invalid combinations fail the **build**, not the run. Runtime footguns in vlmcsd this
  eliminates: `-H 7601` silently turning NDR64 off (the reverse of its man page); `-P` with no `-L`
  silently disabling every ini `Listen` line; inetd mode forcing `MaintainClients = FALSE` *before*
  the ini is read so an ini setting re-enables it; a custom HwId ignored unless an ePID is also set.
- **CFG-005** — No prefix matching. vlmcsd's ini matcher is `strncasecmp(name, line, strlen(name))`,
  so `Portable = 5` silently sets the TCP port and `Windows10 = <epid>` is applied to the CSVLK named
  `Windows`. `deny_unknown_fields` gives this for free.
- **CFG-006** — No trailing-whitespace foot-guns (vlmcsd trims only CR/LF, and its own shipped
  example ini has a trailing blank that makes the line fail).
- **CFG-007** — No argv. Note vlmcsd documents `-h`/`-?` that do not exist in its optstring, and
  py-kms has no `--version` at all.
- **CFG-008** — Build stamp: version + git commit + `SOURCE_DATE_EPOCH`-derived timestamp. vlmcsd
  bakes `BUILD_TIME=$(date +%s)` into every build, defeating reproducibility — and it is *also*
  load-bearing, being the upper bound of the randomized ePID activation date, defaulting to
  2018-10-07 when not injected.
- **CFG-009** — No dead knobs. vlmcsd ships `WINDOWS=`/`OFFICE20xx=` make variables emitting macros
  **no source file reads**, `CAT=1` adding `-DONE_FILE` that nothing tests, `INCLUDE_BETAS` printed
  by `-V` that changes nothing, and `_CRYPTO_INTERNAL` defined but never tested. CI check: every
  generated cfg is referenced.
- **CFG-010** — No combination that fails to compile. vlmcsd has at least four. CI builds the feature
  powerset via `cargo-hack`.
- **CFG-011** — Deliberately **do not** inherit vlmcsd's ~30-macro / 7-preset surface. It exists for
  OpenWrt-class targets and is why 21 of its 119 matrix rows are `⚙` rather than `●`.

---

# 11. OBS — logging, event log, web server

- **OBS-001** — stderr, plus the narrow Windows Event Log exception (OBS-016). No file sink, no
  syslog, no rotation, no async queue handler. On Hermit, stderr is the 16550 UART at 0x3F8 — the
  *only* console `[R2]`.
- **OBS-002** — **JSON Lines**, with ANSI colour only when stderr is a TTY and `NO_COLOR` is unset.
  Structured output is a "nobody" gap: both projects hardcode human format strings, and every fork
  that wanted machine-readable activation data ended up scraping its own log format. py-kms emits raw
  escape codes when stdout is not a TTY because it has no TTY detection and no `--no-color`.
  Use `tracing` + `tracing-subscriber` (A8).
- **OBS-003** — Per-request content matching vlmcsd's verbose dump: protocol version, is-VM,
  licensing status with text, remaining binding time, AppID + name, SKU/ActID + name, KMS ID + name,
  CMID, previous CMID, client request timestamp (UTC), workstation name, N-count policy; response
  side ePID, HwId (v6 only), CMID, count, intervals. Plus source IP and the ePID source.
- **OBS-004** — **In-memory append-only event log** — closes three Tier-1 gaps at once ("an event log
  with a retention policy solves fleet visibility and CMID decay with the same data structure"):
  - one record per *request*, not one mutable row per machine (py-kms overwrites timestamp, machine
    name, SKU, status and ePID on every request, so "what activated last Tuesday" is unanswerable);
  - bounded ring buffer with a fixed capacity **and** a time-based retention window;
  - records: timestamp, source IP, CMID, workstation name, app/sku/kms GUIDs + names, license status,
    protocol version, N-policy, reported count, ePID, HwId, outcome + HRESULT, handling latency;
  - derived views: distinct CMIDs per app (feeds POL-001/POL-003), per-product counts, rejects.
- **OBS-005** — Client source IP recorded **per event**, from per-request state (ARCH-014).
  Convergently reinvented by six separate forks — "the most-wanted missing feature in the entire
  ecosystem".
- **OBS-006** — Composite identity in the derived client view. py-kms keyed on `clientMachineId`
  alone (2019 fork), then `(cmid, applicationId)` (upstream), then `(cmid, skuId)` (2025 fork) —
  rediscovered three times, six years apart. Use `(cmid, skuId)` for the view and `(cmid, appId)` for
  the count bucket.
- **OBS-007** — In-process HTTP server (sans-io, minimal parser; vendored CSS, no CDN — the
  offline-capable choice konk22 and Py-KMS-Organization both got right).
- **OBS-008** — Routes:
  - `/` — status: version/build, uptime, listen addresses, ePID(s), HwId(s), host build, NDR64 state,
    count strategy, distinct CMIDs per app, request/grant/refuse counters, entropy self-test result.
  - `/events` — the event log, newest first, paginated, filterable.
  - `/instructions` — GVLK table with copy-to-clipboard, `slmgr /ipk` + `/skms <host>:1688` + `/ato`
    + `/dlv`, `ospp.vbs` equivalents, the DNS material from DISC-006, the "clients refuse 127.0.0.1"
    caveat (NET-014), and the mDNS story if DISC-003 lands.
  - `/products` — full catalog with GVLKs, grouped, live client-side filter.
  - `/healthz` — **probes the KMS listener**, not just the HTTP process.
  - `/metrics` — Prometheus text format (OBS-013).
- **OBS-009** — Health/error endpoints must **not** echo raw exception text. The Organization fork's
  `/readyz` returns `f'Whooops! {e}'` including filesystem paths to any unauthenticated caller;
  Rubberverse's fix (log server-side, return a constant) is correct.
- **OBS-010** — The web UI is strictly **read-only**. Under A5 there is nothing durable to mutate:
  the event log is a bounded ring buffer that ages out on its own and the CMID table decays, so a
  "delete this row" action would be meaningless — the row either reappears on the next request or
  expires anyway. Read-only is therefore the only coherent design, not a restriction accepted to
  avoid building auth, and it deletes an entire vulnerability class (no CSRF tokens, no sessions, no
  login rate limiting, no password handling — all of which MelroyB had to build and mcrook250 and
  radawson shipped without).
- **OBS-011** — Never trust `X-Forwarded-For` for anything security-relevant; MelroyB's login rate
  limiter keys on it and is therefore bypassable.
- **OBS-012** — Bound everything: fixed max request line/header sizes, a page-size cap, no unbounded
  sorting over the whole event log per render (MelroyB's dashboard is O(all rows) per view).
- **OBS-013** — **`/metrics` in Prometheus text format**, emitted by hand — no dependency needed.
  Design point: **counters cannot be derived from the event log**, because Prometheus counters must
  be monotonic and a ring buffer with retention is not. Metrics are a small set of atomic `u64`s
  alongside the log; gauges are computed at scrape time.

  ```
  kms_requests_total{type="bind"|"activation"}
  kms_activations_total{product}
  kms_errors_total{type}
  kms_request_duration_seconds        # histogram, 12 buckets 1ms..10s
  kms_cmids_active{app}               # gauge
  connections_active                  # gauge
  uptime_seconds
  kmsrsos_entropy_healthy             # gauge, 0/1 — see OS-012
  ```

  The last line is the most valuable in the set: a degraded CSPRNG is invisible by construction — the
  service keeps working perfectly, it just stops being unpredictable, and every anti-fingerprinting
  property quietly becomes a constant. That is a thing to alert on, not to log.
- **OBS-014** — The web server shares the bounded worker budget and can never starve the KMS listener.
- **OBS-015** — No temp files, ever. py-kms's pretty-printer keeps newline bookkeeping in fixed paths
  under the system temp dir, so two instances on one host stomp on each other.
- **OBS-016** — **Windows Event Log: a narrow, bounded exception to "stderr only".** A Windows
  service has no stderr, so without this a service-mode startup failure is completely silent — which
  is exactly vlmcsd's documented failure ("a Windows service started without `-l` produces no output
  at all"), and the web UI cannot cover it because a bind failure or a failed entropy self-test means
  the HTTP listener never comes up.

  Scope: **six lifecycle/fatal events only** — clean start, clean stop, bind failure, entropy
  self-test failure, config parse failure, panic. **The request stream stays stderr and web-UI only.**
  Our own binary is the registered message file (an embedded message-table resource), so events
  render properly instead of as *"The description for Event ID X cannot be found"* — which looks
  broken and would be worse than silence. Registration piggybacks on the documented `sc.exe create`
  install step. Keeping it to six IDs keeps the event-ID contract small enough to version honestly.

  Linux syslog stays declined (A7): systemd already captures stderr into the journal, so the gap does
  not exist. **ETW with TraceLogging** is the right mechanism if Windows monitoring integration is
  ever wanted — structured, maps onto OBS-002, and self-describing providers need no registration at
  all — but it is not where an admin looks when something will not start, so it complements rather
  than replaces this.

---

# 12. SEC — security posture

- **SEC-001** — `#![forbid(unsafe_code)]` workspace-wide. Not stylistic: vlmcsd's pre-bind path
  contains a **remote out-of-bounds read plus an indirect call through a wild function pointer** — a
  request PDU with `ContextId = 0xffff` sent *before any bind* satisfies both `RPC_INVALID_CTX`
  sentinels and yields an unchecked `_Versions[arbitrary − 4].CreateResponse(...)` call — plus the
  MM18 over-read and the deliberate stack leak. ARCH-006 makes the first unrepresentable.
- **SEC-002** — Regression targets, structurally absent here but present in the audited C: client
  stack overflow from a malicious server; client heap underflow from a non-multiple-of-16 response
  length; `checkPidLength()` OOB read at `PIDSize == 0`; use-after-scope in `getEpid()` under `-r2`
  (rediscovered independently by **five** forks); `addListeningSocket()` writing every `getaddrinfo`
  result to one slot and leaving an uninitialised entry that `select()` consumes; `ServiceInstaller()`
  `strcat`ing argv into a fixed `MAX_PATH` buffer; unchecked `fstat` leaving `InetdMode` undefined;
  `hex2bin()` ignoring its bound, treating NUL as a hex digit, and never zero-filling — so a short
  HwId sends uninitialised heap bytes to clients.
- **SEC-003** — All attacker-controlled lengths checked. The KMD-loader bug class (pointers validated
  only against an upper bound via unchecked 64-bit addition, validation running *after* the loops that
  already dereferenced, a size check 160 bytes too permissive) has no analogue once data is compiled in.
- **SEC-004** — **Fuzzing — "the highest-value missing QA capability" and a "nobody" gap.**
  `cargo-fuzz` targets, trivial under A7: RPC PDU decoder; full connection state machine (PDU
  sequences); KMS payload decoder per version; v5/v6 decrypt + unpad; ePID formatter/parser; HTTP
  request parser. Smoke in PR CI, continuous out of band.
- **SEC-005** — **Sandboxing, with an honest platform asymmetry.**

  *Linux:* after binding, apply a **Landlock** policy denying all filesystem access and a **seccomp**
  filter allowing only socket/poll/clock/getrandom syscalls, plus `no_new_privs`. Absent from both
  audited implementations ("no `chroot`, no `umask`, no `setsid`, no capability manipulation, no
  seccomp, no pledge"). With NET-016's socket activation the process never holds privileges at all.

  *Windows:* there is **no self-applicable filesystem sandbox** — AppContainer and restricted tokens
  are launch-time constructs, so using either means shipping a launcher process that spawns the real
  binary into the sandbox, contradicting the single-binary story for a secondary target. **Skip
  AppContainer; document the asymmetry rather than claiming parity.** What *is* self-applicable, and
  cheap (~30 lines of `SetProcessMitigationPolicy` at startup): `DisallowWin32kSystemCalls` (we are a
  console service with no GUI, so this closes the largest Windows kernel attack surface outright),
  `ProhibitDynamicCode` (we JIT nothing, so free), `ExtensionPointDisablePolicy` (blocks `AppInit_DLLs`
  and legacy hook injection), `ProcessImageLoadPolicy` (no remote images, prefer System32),
  `StrictHandleCheckPolicy` — plus `-C control-flow-guard` at compile time on the MSVC target, and a
  low-privilege service account.
- **SEC-006** — CI assertion that the release binary opens no files: run under seccomp/strace in a
  test and fail on any `openat` outside the loader.
- **SEC-007** — **Privilege drop** on Linux: `setgid` → `setgroups(1,&gid)` → `setuid` after binding
  so privileged ports work, to a build-time uid/gid, skipped when already unprivileged. Preferred
  path is NET-016 + `DynamicUser=`, where privileges never exist to drop.
- **SEC-008** — Container hardening: non-root, read-only rootfs, no shell, `scratch`/distroless,
  `HEALTHCHECK` probing the **KMS port**, proper PID 1 signal handling. Do **not** copy edgd1er's
  removal of the upstream permission-hardening block.
- **SEC-009** — Minimal dependencies; `cargo-deny` and `cargo-audit` in CI. Note the trajectory to
  avoid: vlmcsd needs libc only, upstream py-kms is stdlib-only, and the *active* fork added
  dnspython as a hard top-level import plus Flask and gunicorn.
- **SEC-010** — Reproducible builds + SBOM + signed artifacts — another "nobody" gap.
  `cargo-auditable`, CycloneDX/SPDX SBOM, `cosign`, SLSA provenance.
- **SEC-011** — No deserialisation of anything not on the wire. py-kms unpickles a config from a
  world-writable temp dir on `stop`/`status` — local arbitrary code execution.
- **SEC-012** — Exceptions never swallowed. `handle_error() → pass` converts a dozen distinct crash
  paths into indistinguishable connection resets, invisible at every log level. No `let _ =` on a
  `Result` in the request path; every error is an event with a discriminant.
- **SEC-013** — There are no protocol secrets (both keys are published). With DISC-002 declined,
  nothing secret is embedded in the artifact at all.
- **SEC-014** — **Licence: MIT.** Note the audited upstream has none: "There is no license file and
  no SPDX header anywhere" in vlmcsd's tree.

---

# 13. CLI — client tooling and diagnostics

`kmsrs-client` is a diagnostic tool, not a self-test — vlmcs is the model: *"we want to use vlmcs as
a debug tool for KMS emulators."*

- **CLI-001** — Full response-validation bitfield matching vlmcs's `RESPONSE_RESULT`: `HashOK`,
  `TimeStampOK`, `ClientMachineIDOK`, `VersionOK`, `IVsOK`, `DecryptSuccess`, `HmacSha256OK`,
  `PidLengthOK`, `RpcOK`, `IVnotSuspicious`, plus effective-vs-correct response size. **Fail loudly
  on mismatch** — py-kms's client verifies the v4 CMAC and logs *only on success*, and verifies
  nothing at all for v5/v6.
- **CLI-002** — Active emulator-detection warnings: v6 response using a v5 IV rule; no NDR32; NDR64
  without BTFN; non-zero NDR padding; AllocHint mismatch; constant CallId (the Wine bug); server
  closed the RPC connection; ePID instability across two requests on one connection; constant
  assoc_group across connections; suspicious HwId constants. **This is our own regression suite for
  FP-\*.**
- **CLI-003** — v6 validation depth: padding (last byte 1..16, all equal), **all four** version
  fields agreeing (request base, request header, response base, response header), the SHA-256 salt
  proof, and the version-specific IV and HMAC rules.
- **CLI-004** — `checkPidLength`: `PIDSize <= 128`, final zero WCHAR, **no interior zeros**.
- **CLI-005** — Arbitrary/invalid protocol-version generation (any 0..65535 pair) to probe server
  strictness — feeds TEST-005.
- **CLI-006** — Load/soak mode: N requests, optionally a fresh connection + rebind per request
  (vlmcs's examples suggest 100000). Add concurrency, which vlmcs lacks entirely.
- **CLI-007** — Adaptive charging mode: start at `NCountPolicy − 1`, recompute
  `RequestsToGo = NCountPolicy − response.Count`, abort with "the KMS server does not increment its
  active clients" if the count fails to rise. Note this correctly reports no-increment against a
  *saturated* host, which under POL-001 is our steady state.
- **CLI-008** — Product/GVLK enumeration with keys. vlmcs lists names only and its counter is
  `uint8_t`, so a >255-SKU database mis-renders — a latent bug kotfenix hit and fixed.
- **CLI-009** — Request-field overrides: AppID, SkuId, KMSID, CMID, previous CMID, N-policy, license
  status, grace time, is-VM, workstation name, protocol version.
- **CLI-010** — Random workstation names in both flavours: DNS-style (vlmcsd concatenates three
  tables, one containing `hack-me`, `_vlmcs._tcp` and `ceo-laptop`) and NetBIOS-style (1..14 chars of
  `0-9A-Z`).
- **CLI-011** — SRV discovery target syntax (DISC-001).
- **CLI-012** — **Configurable timeouts.** vlmcs hardcodes 10 s and has no option at all.
- **CLI-013** — Client-side warnings must not truncate silently: vlmcs truncates workstation names
  over 63 chars after a BEL-prefixed warning, and accepts license-status values 0..0x7fffffff with
  only a warning above 6.
- **CLI-014** — HRESULT decoding with human text (KMS-015), including `1` → "RPC protocol error,
  reconnect".
- **CLI-015** — Client and server share one logger namespace. py-kms's client configures `logclt`
  while its RPC modules log to `logsrv`, so `-V DEBUG -F file.log` silently captures nothing.

---

# 14. TEST — testing, fuzzing, cross-validation

*"No fork has a single test vector captured from a real Windows client or a real KMS host. There is
no cross-validation against vlmcsd. A wire-format regression would be invisible."*

- **TEST-001** — Crypto KATs (CRY-019).
- **TEST-002** — Golden wire vectors as committed files: bind, bind_ack, alter_context,
  alter_context_ack, request/response for v4/v5/v6, fault, bind_nak — NDR32 and NDR64.
- **TEST-003** — Round-trip property tests; encoded length matches the computed expected size
  (CRY-011).
- **TEST-004** — **Differential testing in CI against vlmcsd and py-kms**, both directions: our
  client → their servers, their clients → our server. Byte-compare where determinism allows — v4 is
  fully deterministic given a fixed ePID; v5/v6 given a fixed IV/salt, which ARCH-003 makes
  injectable.
- **TEST-005** — Adversarial matrix: every MM becomes a test. Two identical requests on one
  connection (MM01); Office 2010 ePID group (MM02); `versionMajor = 7` (MM04); connection held open
  (MM05); NDR64 + alter_context (MM06); assoc_group varies (MM07); unknown transfer syntax (MM08);
  ClientTime +6 h (MM09); v4 latency (MM10); unknown GUID (MM11); concurrent clients (MM12); bind
  family (MM13); connect-and-send-nothing (MM14); HwId not constant (MM15); second listener's
  SecondaryAddr (MM16); odd PacketFlags / big-endian (MM17); declared length > received (MM18);
  `N_Policy = 5000` (MM21); retail/preview SKU (MM23).
- **TEST-006** — Fuzz targets (SEC-004) seeded from TEST-002.
- **TEST-007** — Product-database schema validation as a build step **and** a test (DB-004), plus a
  `kmsrs-dbgen` re-extraction diff check so data drift is visible in CI.
- **TEST-008** — ePID statistical tests: CSVLK group matches the requested product 100 % of the time
  (py-kms: 2.3 %); host-build distribution not degenerate (Organization fork: 17763 in 2000/2000).
- **TEST-009** — Host-state tests: pre-charge; saturation at 2N; per-client views never mutating
  global state (POL-005); 30-day decay decrementing; renewal deleting-and-reinserting; eviction.
- **TEST-010** — Concurrency: no cross-request state leakage (MM12), no shared cipher state
  (CRY-015), event-log ordering under load.
- **TEST-011** — Timeout/slowloris: N idle connections must not exhaust capacity.
- **TEST-012** — Platform matrix: Linux x86_64/aarch64, Windows x86_64, Hermit x86_64. Nobody in
  either ecosystem tests on Windows at all.
- **TEST-013** ⚑ — **Real-client acceptance test**: a Windows VM doing `slmgr /ipk` + `/skms` +
  `/ato` + `/dlv` against our server for a v4-era, v5-era and v6-era product plus one Office product,
  with captured pcaps checked in as vectors. Shares the harness with DISC-004.
- **TEST-014** ⚑ — Wine/Samba/third-party client compatibility probe (KMS-010, WIRE-027).
- **TEST-015** — Coverage gate on `kmsrs-proto`/`kmsrs-policy`/`kmsrs-crypto`.
- **TEST-016** — Snapshot tests for the web UI HTML and the JSON log format, so the operator-facing
  contract cannot drift. Both audited projects have pages of verified doc-vs-code drift — vlmcsd's
  man pages document `-h`, `-f`, `-w`, `-G`, `-0`, `-3`, `-6` and lowercase `-n`/`-b`, none of which
  exist; py-kms's `-t0` description, `-S` MB claim and README dual-stack claim are all false.

---

# 15. PKG — packaging, CI, artifacts

- **PKG-001** — Nix flake: `packages.default` (server), `.client`, `.windows` (scaffolded),
  `.hermit`, `.dockerImage` (via `dockerTools.buildLayeredImage` from the Nix-built binary — no
  Dockerfile, no network at build time), `.osImage`, plus the `mkKmsrsos` function (CFG-003).
- **PKG-002** — `nix flake check` runs build + clippy + fmt + tests + coverage, plus the DB schema
  check, feature-powerset build, and fuzz smoke.
- **PKG-003** — GHA artifacts per tag: Linux static binaries (x86_64, aarch64), `.deb`/`.rpm`,
  Windows `.exe`, Hermit OS image, multi-arch container image to GHCR, SBOM, signatures, checksums.
- **PKG-004** — Container: `FROM scratch` over a static binary (kankerdev proved this works for a KMS
  emulator), non-root, read-only, no shell, `HEALTHCHECK` probing 1688, `EXPOSE 1688 8080`.
- **PKG-005** — **Never `git clone` at image build time.** Upstream py-kms's Dockerfiles clone GitHub
  master rather than copying the build context, so `docker build` produces whatever upstream happened
  to be at that moment and silently ignores local changes.
- **PKG-006** — Pin everything; no floor-versioned distro packages (edgd1er's move from pinned pip to
  `apk add py3-x>=y` made builds non-reproducible and shipped pylint inside the runtime image).
- **PKG-007** — systemd unit shipped **in-tree** (a "nobody" gap; both projects have only doc
  snippets and py-kms's is `User=root` with no hardening): socket unit + service unit with
  `DynamicUser=`, `ProtectSystem=strict`, `ProtectHome=`, `PrivateTmp=`, `NoNewPrivileges=`,
  `SystemCallFilter=`, `RestrictAddressFamilies=AF_INET AF_INET6`, and **no** `AmbientCapabilities`
  (NET-016 makes it unnecessary).
- **PKG-008** — **Windows service: minimal.** `StartServiceCtrlDispatcher`, a control handler for
  `STOP`/`SHUTDOWN`, correct `SetServiceStatus` transitions. Console-vs-service auto-detected by the
  standard trick — call the dispatcher first, treat `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` as
  "console app". **No install/uninstall verbs** — under A3 installation is one documented `sc.exe
  create` command, so an in-binary installer buys nothing and reintroduces exactly the code that
  broke vlmcsd. Both vlmcsd bugs become unrepresentable: there is no argv to embed in the service
  `ImagePath`, so a password cannot land in the registry, and there is no argv concatenation, so the
  `strcat`-into-`MAX_PATH` overflow cannot happen.

  **Consequence:** a service has no stderr, so in service mode the web UI event log plus OBS-016's
  six Event Log entries are the *only* observability. The web UI is therefore **non-optional on that
  target**, and the docs must say so.
- **PKG-009** — **`.deb` and `.rpm` as CI artifacts** (via `cargo-deb`/`cargo-generate-rpm` or Nix),
  because they bundle the three things a Linux host deployment needs — binary, hardened unit, service
  user. **No apt/yum repository** (ongoing infrastructure with signing keys; a downloadable package
  captures most of the benefit). **No Homebrew** — macOS is not a target and shipping for an untested
  platform is a support liability. `cargo install` kept *working* but not promoted; it yields the
  default build only, which is a confusing entry point when configuration means rebuilding.
  Calibration: Docker and the Nix flake probably cover the real audience — py-kms's entire deployment
  story being Docker is not an accident — so these are conveniences, not a tier-one channel.
- **PKG-010** — Documentation generated where possible and CI-checked against the code (TEST-016).
- **PKG-011** — **Kubernetes: plain manifests, `replicas: 1` hardcoded. No Helm** (→A33).

  The reason is a finding, not a preference. **Our state is in-memory and per-pod.** With more than
  one replica each pod has its own CMID table, its own event log and — critically — **its own ePID**.
  A client that hits pod A and then pod B receives two different ePIDs from what it believes is one
  KMS host. That is **MM01, the canonical emulator-detection test, reintroduced at the infrastructure
  layer by a config value.** The Organization fork's chart exposes `replicaCount` as a top-level Helm
  value; scaling it looks like the obvious thing to do and silently destroys the single most important
  anti-fingerprinting property we have. Helm's entire value is parameterization, and the one parameter
  people would reach for is the one that must never change. Ship a Deployment with `replicas: 1` and
  a comment explaining why, a Service exposing 1688 and 8080, and probes against `/healthz`.
- **PKG-012** — Release notes enumerate protocol-visible changes explicitly. *"Nobody deprecated or
  versioned anything"* — the Organization fork changed `-d` from a flag to a value-taking option,
  `-s` from a directory to a file, renamed schema keys and flipped the default bind address, and
  three downstream forks each rediscovered a different subset of the breakage.
- **PKG-013** ⚑ — **The Hermit Nix build is the largest schedule risk in the project** `[R2]`. The
  `hermit` crate's `build.rs` shells out to a nested `cargo run --package=xtask` that builds the
  kernel from a **git submodule** against its **own lockfile** and **own pinned nightly**
  (`nightly-2026-08-01`), which crane will not vendor. Options: build the kernel as a separate
  derivation producing `libhermit.a` and patch out the nested cargo invocation, injecting
  `cargo:rustc-link-search` / `-l static=hermit` directly; or carry two vendored dependency trees and
  two toolchains in one derivation. Either way two toolchains are required, plus a fixed-output
  derivation for the `rust-std-hermit` release tarball (same pattern as the existing pinned `xwin`
  FOD). **Prototype this before it is load-bearing.**
- **PKG-014** — Hermit targets are all **Tier 3** `[R2]` — no rustup `rust-std`. Either
  `-Z build-std=std,panic_abort` on nightly, or the `hermit-os/rust-std-hermit` component, which is
  built per *exact* stable version (currently 1.94.0) and must be matched precisely. The `hermit`
  crate must be a **git** dependency; the crates.io copy is a `compile_error!` stub.

---

# 16. OS — Hermit / bare-metal target

- **OS-001** — `kmsrs-os` links the same core crates with the Hermit platform layer (ARCH-005):
  blocking `std::net::TcpListener` + `std::thread`, the model hermit's own CI actually validates.
- **OS-002** — Boot as an **ordinary VM**: a GPT disk whose ESP contains
  `\EFI\BOOT\BOOTX64.EFI` (hermit-loader), `\EFI\hermit\hermit-app` (our unikernel) and
  `\EFI\hermit\hermit-bootargs` (optional text). The UEFI loader reads all three itself — **no
  `-kernel`, no `qm set --args`** `[R2]`. This is both the OS-image artifact and CFG-002's config
  channel.
- **OS-003** — **DHCPv4**, on by default (`dhcpv4` is in Hermit's default feature set). `HERMIT_IP`,
  `HERMIT_GATEWAY`, `HERMIT_MASK`, `HERMIT_DNS1/2` exist only as a pre-DHCP fallback, and boot args
  override compile-time values `[R2]`.
- **OS-004** ⚑ — **QEMU/libvirt is the supported configuration; Proxmox is nice-to-have.** That is
  the setup hermit's own CI exercises on every PR (`-machine q35`, `virtio-net-pci,disable-legacy=on`,
  DHCPv4), so the OS image inherits their coverage instead of blazing a trail.

  On Proxmox specifically, **virtio-net may not attach at all** `[R2]`: Proxmox always places NICs on
  a conventional PCI bus (`pci.0` is a `pci-bridge` behind an i82801b11 bridge even on q35) and
  **never** emits `disable-legacy=on` — zero occurrences in `qemu-server`. QEMU therefore presents a
  *transitional* virtio-net device (PCI ID 0x1000), and Hermit refuses anything below 0x1040:
  *"Legacy/transitional Virtio device … NOT supported, skipping!"* The chain is solid link-by-link
  from source but never observed. Run the experiment early — it is cheap and it changes the docs
  either way — but it does not gate the target. Documented fallbacks: switch the NIC model to
  **RTL8139** in the GUI and build the kernel with that feature (the only pure-GUI fix, but that
  905-line driver is never run in hermit's QEMU CI), or `qm set --args` once from the CLI.
- **OS-005** — Serial console is mandatory on Proxmox: add a Serial Port and set Display = serial0,
  or the VM is completely silent — Hermit's only console is the 16550 UART at 0x3F8 `[R2]`.
- **OS-006** — No SMBIOS and no block device driver of any kind `[R2]`, so neither the GUI-settable
  SMBIOS type-1 fields nor a cloud-init CD-ROM is readable. A5's zero-disk-I/O is enforced by the
  *absence of drivers*, not by our policy — build with `--no-default-features` omitting `virtio-fs`
  to make it structural, and leave `write-pcap-file` off.
- **OS-007** — Time: monotonic is solid (TSC/APIC, microsecond resolution). `SystemTime` is one CMOS
  RTC read plus local ticks — 1-second granularity, no pvclock, no NTP, no slew, and it drifts `[R2]`.
  Fine given ARCH-004; do not treat it as an authority and do not live-migrate.
- **OS-008** — MAC address is GUI-settable and guest-readable; that plus DHCP is the entire
  configuration channel Proxmox actually offers (CFG-002 supplies the rest via the ESP file).
- **OS-009** — **Hermit never gets an IPv6 address** `[R2]`: smoltcp has v6 compiled in, but the
  kernel only ever assigns IPv4 and speaks DHCPv4 only — no SLAAC, no RA, no DHCPv6. Additionally
  `bind()` records the address and then **ignores it** — `listen()` passes only the port to smoltcp —
  so a single `0.0.0.0` socket already accepts on every local address, and two sockets on the same
  port would race with no defined dispatch. So: **one socket, `0.0.0.0`, on Hermit**; NET-001's
  two-socket dual-stack is Linux/Windows only.
- **OS-010** — `setsockopt` is a stub `[R2]`: only `TCP_NODELAY` works; `SO_REUSEADDR` is a silent
  no-op; `SO_RCVTIMEO`/`SO_SNDTIMEO`/`IPV6_V6ONLY`/`SO_KEEPALIVE`/`SO_LINGER` all return `EINVAL`.
  Audit whatever socket code we use for calls that succeed on Linux and Windows and fail only here —
  the worst failure shape.
- **OS-011** — Memory budget: the CMID table, the event-log ring buffer and the ~15–20 KB product
  database are the only significant allocations. Compile-time constants, with the total asserted.
- **OS-012** — **Entropy self-test — critical** `[R2]`. Hermit's CSPRNG is properly built (ChaCha20,
  fast-key-erasure, reseeding every second, seeded from RDSEED or virtio-rng), **but on seeding
  failure `sys_read_entropy` silently succeeds**, filling the buffer from a Park–Miller–Lehmer LCG
  seeded from a static `0` — a deterministic, identical-across-boots stream — and only emits a
  `warn!`. `getrandom` sees a normal success. On Proxmox this is the *likely* path, not the edge
  case: the default `kvm64` CPU does not expose RDSEED, and Proxmox's `virtio-rng-pci` lands on the
  same conventional bus Hermit rejects (OS-004). That stream feeds the association group, response
  IVs, salts and HwId, so every FP-007 / FP-011 / FP-026 property would silently become a constant.
  **Run a startup self-test that detects the degraded state and refuses to serve**, surface the
  result on `/` (OBS-008) and as a metric (OBS-013), and document CPU type `host` as a requirement.
- **OS-013** — The `unsafe` boundary, if any, lives here and only here, documented, with an explicit
  crate-level allow and a rationale.

---

# 17. FP — anti-fingerprinting checklist (cross-cutting)

Every row is an item above; this exists so it can be run as a checklist. The audit's verdict on the
incumbents: *"none of the three would survive an adversarial detection probe without being
reconfigured."*

| # | Property | Item |
|---|---|---|
| FP-001 | Stable ePID per CSVLK for process lifetime | ID-001, PKG-011 |
| FP-002 | ePID CSVLK group matches the requested product | ID-002 |
| FP-003 | ePID host build ↔ NDR64 offered are consistent | ID-010 |
| FP-004 | ePID internally consistent (LCID/build/platform/date shared across groups) | ID-008, ID-009 |
| FP-005 | Key ID never lands in an invalid range hole | ID-019 |
| FP-006 | No published-constant HwId | ID-013 |
| FP-007 | Per-connection, per-process association group | WIRE-010 |
| FP-008 | Association held open after activation | WIRE-021 |
| FP-009 | NDR64 accepted, NDR32 NACKed, alter_context serviced | WIRE-003, WIRE-005 |
| FP-010 | Per-item bind NACK instead of RST | WIRE-006 |
| FP-011 | bind_ack/fault padding is random, not zero and not leaked | WIRE-017 |
| FP-012 | `SecondaryAddr` from the accepting socket; `frag_len` computed | WIRE-011, WIRE-012 |
| FP-013 | Fault PDUs echo the request CallId | WIRE-015 |
| FP-014 | Responses set FIRST\|LAST + own DataRepresentation; client flags not mirrored | WIRE-014, WIRE-028 |
| FP-015 | Cosmetic 4-byte NDR pad emitted | WIRE-018 |
| FP-016 | No artificial latency | KMS-022 |
| FP-017 | Correct HRESULTs on error, never a dropped connection | KMS-014, KMS-015 |
| FP-018 | Reported count saturates like a real host; anomalies stay per-client | POL-001 |
| FP-019 | Absurd `N_Policy` not reflected back unchallenged | POL-006 |
| FP-020 | Clock-skew behaviour is a deliberate, documented choice | POL-011 |
| FP-021 | Retail/preview refused; unknown products still activate | POL-010 |
| FP-022 | Response sizes exactly match the computed expected size | CRY-011 |
| FP-023 | v6 IV rule not degraded to v5's | KMS-007 |
| FP-024 | Never ACK a bind for a non-KMS interface | WIRE-008 |
| FP-025 | **Entropy is real** — a degraded CSPRNG silently constant-ifies FP-006/007/011 | OS-012 |
| FP-026 | No constant across deployments anywhere (audit every `const`) | all |
| FP-027 | TCP-layer fingerprints are OS-level; the Hermit build has a distinctive smoltcp stack. Measured in DISC-004; residual risk documented. | NET-015, OS-009 |

---

# Remaining unknowns — experiments, not decisions

All design decisions are closed. What is left needs hands-on work:

1. **OS-004** ⚑ — does virtio-net actually fail on a stock Proxmox VM? Reasoned from source at every
   link, never observed. One boot with a serial log answers it.
2. **PKG-013** ⚑ — the Hermit Nix build: two lockfiles, two toolchains, a nested cargo invocation
   inside a build script, and a tarball that is not in nixpkgs. Prototype before it is load-bearing.
3. **DISC-003/004** ⚑ — does SPP do SRV-over-mDNS for `.local`, and does DHCP option 15 steer it?
4. **OS-012** ⚑ — RDSEED availability under Proxmox's default `kvm64` versus `host`, and whether the
   degraded entropy state is detectable from inside the guest. Build the self-test before it is needed.
5. **TEST-013 / TEST-014** ⚑ — real Windows client acceptance; Wine/Samba compatibility.
6. **KMS-010** ⚑ — do over-long requests from real clients actually occur?
7. **NET-014** ⚑ — confirm the loopback refusal behaviour and document the workarounds precisely.
8. **RTL8139 under load** ⚑ — only relevant if OS-004 fails and Proxmox matters; the driver is never
   run in hermit's QEMU CI.
9. **Long-uptime clock drift** on Hermit, given `SystemTime` = one CMOS read plus local ticks.

---

# Suggested sequencing

1. **Skeleton + data pipeline** — workspace, lints, ARCH-009's symbol gate, `kmsrs-dbgen` extraction,
   committed data file, DB-004 validation. Nothing else can be tested without correct data.
2. **Crypto + KATs** (CRY-001..019, TEST-001).
3. **`kmsrs-proto` sans-io** — KMS payloads, then DCE/RPC, then the connection state machine, with
   golden vectors and fuzz targets landing alongside.
4. **`kmsrs-policy`** — identity, host-state model, event log (ID-*, POL-*, OBS-004).
5. **`kmsrs-server` on Linux** + `kmsrs-client` — first end-to-end activation.
6. **Differential CI** against vlmcsd and py-kms (TEST-004, TEST-005). *Gate everything after this on
   it staying green.*
7. **Web UI + instructions** (OBS-007..013).
8. **Windows target** — service, Event Log, process mitigations.
9. **Hermit spikes first**: PKG-013 (Nix) and OS-004 (Proxmox NIC) **before** writing the platform
   layer; either can reshape or kill the target.
10. **Measurement harness** → mDNS go/no-go → responder (DISC-003..006).
11. **Packaging, artifacts, provenance** (PKG-*).

---

# Appendix A — declined, with rationale

| # | Declined | Why |
|---|---|---|
| **A1** | Active Directory-Based Activation (ADBA) | A different mechanism (LDAP activation objects, no SRV, no port, no threshold). The audit calls it out of scope while noting its existence caps how much a perfect KMS emulator is worth. |
| **A2** | Multi-tenancy (per-listener / per-peer identity) | Nobody implements it; no coherent use case when identity is baked in. |
| **A3** | High availability / shared client-count state | Requires shared external state, which A5 forbids. See also PKG-011: multi-replica breaks ID-001 outright. |
| **A4** | RPC authentication (sec_trailer / SPNEGO / NTLM) | Real KMS clients never authenticate. We still handle an inbound `AuthLength` safely (WIRE-026). |
| **A5** | Runtime configuration beyond CFG-002: CLI options, per-knob env vars, config files, SIGHUP reload, re-exec restart | A3. Removes vlmcsd's entire ini surface (prefix matching, trailing spaces, three-pass parsing, reversed ePID precedence, `-Z`), py-kms's custom argv pre-validator, and radawson's YAML layering. |
| **A6** | Disk persistence: SQLite, log files, rotation, pidfiles, external data files, temp files, config pickles | A5. Removes py-kms's whole SQL layer and its TOCTOU races, `-S` rotation (documented in MB, actually 0.5 MiB/unit), and the pickle RCE. Replaced by OBS-004. |
| **A7** | Linux syslog; general-purpose Windows Event Log streaming | systemd already captures stderr into the journal, so the Linux gap does not exist. On Windows a *narrow* six-event exception is made (OBS-016) because a service has no stderr; the request stream is still not sent to the Event Log. Note vlmcsd's syslog opens/closes per message and logs everything at `LOG_INFO`, and its event-log code is entirely commented out. |
| **A8** | Desktop GUI | The web UI supersedes it. Upstream py-kms's GUI auto-launches whenever stdout is not a TTY — `pykms_Server.py > log.txt` opens a window instead of running headless. |
| **A9** | Pluggable crypto backends and hardware-AES hacks | vlmcsd's OpenSSL binding targets the dead 1.0 API, PolarSSL cannot use mbed TLS, and the AES-NI path pokes a tweaked round key into OpenSSL's private `AES_KEY` struct — which its own header calls "DANGEROUS". An independent fork deleted all of it with no functional consequence. |
| **A10** | vlmcsd-scale compile-time stripping (~30 macros, 7 presets) and the multi-call binary | For OpenWrt-class targets we don't have; the reason 21/119 rows are `⚙`. Deliberate non-goal. |
| **A11** | inetd / xinetd mode, and systemd `Accept=yes` | One process per connection destroys both the CMID table and the stable ePID. NET-016 detects and refuses it rather than degrading. |
| **A12** | `libkms`-style C ABI embedding library | Not thread-safe by construction in the original (nine globals), strips the product database, and leaks `#define client_main main` into consumers. A Rust library API is free; a C ABI is not. |
| **A13** | Windows TAP/TeamViewer-VPN adapter mirroring | 370 lines of driver IOCTLs, an internal DHCP server and a packet-rewriting thread, all to work around clients refusing 127.0.0.1. Documented as a constraint instead (NET-014). |
| **A14** | Free-binding (`IP_FREEBIND`/`IP_BINDANY`) | Niche; vlmcsd's IPv6 path uses the wrong socket level so it can never work, and the failure is hidden behind `_PEDANTIC`. |
| **A15** | Server idle-lifetime timeout | py-kms's `-t0` is documented as per-client inactivity but is a total-process-lifetime cap computed once before the accept loop whose expiry `sys.exit(1)`s the server. |
| **A16** | Background daemonization in-process | Supervisors do this. vlmcsd's `daemon(nochdir=1, …)` doesn't even `chdir` to `/`; py-kms's Etrigan has a no-op `reload`, a Linux-only `status`, a `chdir('/')` that breaks relative paths, and the pickle RCE. |
| **A17** | GeoIP enrichment | Ships client IPs to a third-party HTTP API over plain `urllib`, on by default in the fork that added it. Privacy-hostile and A5-violating. |
| **A18** | Docker self-update from the web UI | Requires mounting the Docker socket, making any web-UI compromise equivalent to host root. |
| **A19** | Web UI authentication, CSRF, rate limiting, sessions | Unnecessary while the UI is read-only (OBS-010). Reopens if mutation is ever added. |
| **A20** | Client allowlist keyed on `WorkstationName` | Client-supplied and trivially spoofable; the two forks that tried produced a V6-bypassable gate and a server-killing `sys.exit(0)`. |
| **A21** | Bootable 1.44 MB floppy | Superseded by OS-002. vlmcsd documented one but never committed the image or its build scripts. |
| **A22** | Microsoft `rpcrt4` RPC backend on Windows | Delegating to the OS removes control over exactly the fields that matter for FP-007..015, caps requests at 384 bytes, and weakens peer filtering because negotiation completes before the server sees the client. |
| **A23** | Unbounded history / reporting | The event log is a bounded ring buffer with retention. |
| **A24** | LLMNR, NetBIOS, WPAD-style discovery | LLMNR carries no SRV records at all, so it cannot express a KMS host. Ruled out on paper. |
| **A25** | Reimplementing DNS, standard AES, SHA-256, HMAC, HTTP, TLS or binary framing by hand | A8. Two exceptions, both in CRY-002. |
| **A26** | Hand-curated product data from fork catalogs | Superseded by DB-001's extraction from Microsoft primary sources. Data ships through that pipeline or it does not ship. |
| **A27** | Request-time upstream forwarding / caching proxy | Declined per direction. |
| **A28** | Build-time ePID/HwId harvesting from a genuine KMS host | Out of scope per direction. ID-013's random-per-process HwId is the floor instead. |
| **A29** | Per-SKU activation quotas | **The exact inverse of POL-001** — that design guarantees one client's request never constrains another's, while a quota makes every grant mutate shared state so it can deny a later client. Contradictory principles in one layer. It also cannot work: the only key available is the CMID, a client-chosen UUID that clients regenerate freely (vlmcs makes a fresh one per request by default), so the cap is bypassed by normal behaviour, not by attack. It bounds nothing the table and log don't already bound, and invents a refusal no real host makes. The underlying want is better served by POL-014 keyed on `(source IP, app)`. |
| **A30** | Visual Studio / SQL Server / SCCM product entries | Not covered by DB-001's pipeline, and A26 forbids hand-copying fork data — the practice that produced every fabricated GUID in the audit. The cost of omission is small: under POL-017 those clients still activate, they simply log as a raw GUID and receive a Windows-group ePID. Two of the four entries are also flagged "(Can only be applied manually)", hinting they may not use the KMS RPC path at all. Revisit if a Microsoft artifact surfaces. |
| **A31** | SRV publishing via RFC 2136 dynamic DNS update | AD DNS defaults to secure-updates-only and real hosts use **GSS-TSIG** with machine-account Kerberos credentials, so shared-key TSIG does not serve the primary use case, and GSS-TSIG needs runtime secrets. For BIND-style managed DNS, a static record added once is equally easy and more auditable. It would also embed a secret in the shipped artifact, so the published container could never enable it. DISC-006 delivers the value instead. |
| **A32** | Linux appliance image (kernel + initramfs) | Not the hedge it appeared to be: if Hermit-on-Proxmox fails, the fallback is a normal Linux VM running the container or the `.deb`, which needs nothing from us. Its only unique property is minimalism, which is Hermit's entire reason for existing — a second, larger minimal image duplicates the target while discarding what makes it interesting. Revisit only if Hermit is abandoned, at which point it replaces rather than supplements the OS image. |
| **A33** | Helm chart | Helm's value is parameterization, and the parameter operators would reach for first — `replicaCount` — is the one that must never change, because multi-replica gives each pod its own ePID and reintroduces MM01 at the infrastructure layer. Plain manifests with `replicas: 1` hardcoded and a comment (PKG-011). |

---

# Appendix B — traceability

**Mismatches MM01–MM24**: MM01→ID-001 + PKG-011; MM02→ID-002; MM03→POL-001; MM04→KMS-014;
MM05→WIRE-021; MM06→WIRE-003/005 + ID-010; MM07→WIRE-010; MM08→WIRE-006; MM09→POL-011; MM10→KMS-022;
MM11→POL-017; MM12→ARCH-014; MM13→NET-001; MM14→NET-004/POL-012; MM15→ID-013; MM16→WIRE-011;
MM17→WIRE-014; MM18→KMS-009; MM19→OBS-004; MM20→KMS-021; MM21→POL-006; MM22→DISC-003..006;
MM23→POL-010; MM24→FP checklist.

**The 23 "nobody implements" gaps**: DNS SRV publishing→DISC-003..006; CMID 30-day decay→POL-003;
rate limiting→POL-012/014; activation history→OBS-004; fuzzing→SEC-004; CSPRNG→CRY-013 + OS-012;
RPC fragmentation→WIRE-022; structured logs→OBS-002; reproducible builds/SBOM/signing→SEC-010;
sandboxing→SEC-005; systemd unit + OS packages→PKG-007/009; socket activation→NET-016;
HA shared state→A3; upstream proxy→A27; multi-tenancy→A2; per-product quota→A29;
client allowlist→POL-013/A20; Prometheus→OBS-013; ADBA→A1; RPC auth→A4; constant-time crypto→CRY-017;
Windows Event Log→OBS-016; per-client quota→A29.

**Fork items carried forward**: kotfenix's Office LTSC 2024 range (confirmed against Microsoft)
→DB-007 and its `uint16_t` SKU-counter lesson→CLI-008; kankerdev's VS/SQL/SCCM data→A30;
cnzhangquan's OpenVPN adapter ID→A13; KptCheeseWhiz's CIDR allowlist *idea*→POL-013; the `getEpid()`
dangling-pointer fix (five independent discoverers)→SEC-001/002; Hamad3bdulla's ePID fallback
fix→ID-002, RPC-bind `KeyError` guard→WIRE-006, client short-read reassembly→WIRE-024, pickle→JSON
→SEC-011; GuillaumeDescombes's receive-loop hardening→WIRE-025/NET-004 and `RequestUnknown` bytes
fix→KMS-014; MelroyB's per-request config copy→ARCH-014, blacklist grammar→POL-013, and his
WinBuild 26200/28000 rows→DB-011; mcrook250's retention idea→OBS-004/POL-003; OzanHazar's quota
idea→A29; Neon-Cyber-Crutches's metric taxonomy→OBS-013 and shell-less spawn→SEC-008; konk22's
offline products page→OBS-008; Rubberverse's Server 2019 CSVLK ePID correction and Azure-only key
range→DB-007, health-endpoint leak fix→OBS-009; edgd1er's null-guard and logged healthcheck
→OBS-012/SEC-012; zeevro's installable-package layout→PKG-009; GhostNaix's Windows console
lesson→NET-013; dummervogel's self-pipe-on-Windows lesson→NET-009; radawson's YAML/GUID-keyed-DB
*ideas*→CFG-002/DB-003; HAmamiya's composite-key insight→OBS-006.

---

# Appendix C — research findings

## R1 — product data, from Microsoft primary sources

The disputed CSVLK data was resolved **above** the vlmcsd / License Manager / py-kms hierarchy, by
reading Microsoft's own signed artifacts:

- `pkeyconfig-office-kmshost.xrm-ms` and four `kmshost2024vl_kms_host-*.xrm-ms` files from the
  official **Office LTSC 2024 Volume License Pack**.
- `pkeyconfig-csvlk.xrm-ms` and the `spp\tokens\skus` tree from **Windows Server 2025 (26100)**,
  streamed out of `mcr.microsoft.com/windows/servercore:ltsc2025`.

Both contain `RefGroupId`, `Start`, `End` and `PartNumber` per CSVLK, base64+gzip'd inside an XrML
wrapper; the accompanying licence files carry `Security-SPP-KmsCountedIdList`. **This contradicts the
common assumption that Microsoft does not publish CSVLK group IDs or key ranges — it does, just not
in prose.** That is what DB-001/DB-002 are built on.

Resolutions: Office LTSC 2024 = 591000000–610999999 (py-kms's 666000000–685999999 is Office 2019's
range verbatim, provably wrong because the same file assigns that block to Office 2019); Office LTSC
2021 = 206 / 571000000–590999999 confirmed, with contiguous blocks and consecutive part numbers
X22-38547 / X22-38548 corroborating; Server 2025 = **4919 general, 4918 Azure-only** (py-kms has them
swapped, and its range is Server 2022's — its own history shows the 2025 entry was cloned from the
2022 one); Server 2022 = 4573 / 30000–20029999, corroborated by a genuine harvested ePID
`03612-04573-000-204477-03-1033-14393.0000-1972021`.

**The "20-million-scale range" premise in the earlier draft was wrong.** It is not chronological but
a GroupId-namespace effect: GroupId 206 is a crowded shared namespace where new blocks get carved at
ever-higher bases, while products granted a *fresh* GroupId start near zero. Block width is
~20 000 000 in both eras. Windows Server 2022 was the first product with a dedicated group; Office
LTSC 2021 and 2024 are counterexamples that stayed on 206.

Also settled: PlatformId is 3612 for every build ≥ 10240 (two genuine ePIDs corroborate); build 28000
/ Win 11 26H1 is real (KB5077179, 2026-02-10); ePID day-of-year is 1-based and py-kms is the outlier;
LCID is unpadded; the channel is always `03`; and a real Microsoft GUID in this space is *not*
necessarily UUIDv4 — Office LTSC 2024's genuine counted ID has an invalid version nibble, while the
two *fabricated* py-kms IDs are valid UUIDv5 (DB-005).

Known-bad in `Py-KMS-Organization/py-kms@main`, beyond the two errors the audit already listed:
Office LTSC 2024 key range; Server 2025 GroupIds swapped; Server 2025 key range; Server 2019
Azure-only range missing; Server 2025 and Office 2024 counted IDs fabricated; Server 2025 Datacenter
Azure Edition GVLK wrong; the Windows 10/11 2021 and 2024 LTSC KMS IDs missing; 0-based day-of-year.
Known-bad in License Manager: the Server 2025 Datacenter GVLK, and a missing `UseForEpid` on 26100.

## R2 — Hermit and Proxmox feasibility

Verified by cloning `hermit-os/kernel`, `hermit-os/hermit-rs`, `hermit-os/loader`, `tokio-rs/mio` and
`proxmox/qemu-server` and reading the sources rather than the documentation.

Headline results are folded into ARCH-005 (tokio only via a stale fork; platform trait required),
ARCH-015 (`cfg(unix)` false), PKG-013/014 (Tier 3, two toolchains, nested kernel build), OS-002
(bootable ESP image, no `-kernel`), OS-003 (DHCPv4 default), OS-004 (Proxmox transitional-virtio
rejection), OS-006 (no block driver, no SMBIOS), OS-009 (no IPv6, port-only listen), OS-010
(`setsockopt` stub) and OS-012 (silent LCG entropy fallback).

One further detail worth recording: **mio has first-class, unpatched Hermit support** — it groups
`target_os = "hermit"` into its unix arm and selects the `poll(2)` selector with an eventfd waker,
and the kernel provides `sys_poll` and `sys_eventfd` but no epoll. So if async on Hermit is ever
wanted, a hand-rolled mio loop is a far lower-risk path than a forked tokio: stock mio needs no
patches and hermit's CI runs mio TCP and UDP examples in QEMU on every PR.

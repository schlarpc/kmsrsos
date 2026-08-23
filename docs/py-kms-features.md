# py-kms (SystemRage/py-kms) — Complete Feature Reference

> Audited against upstream `SystemRage/py-kms`, branch `master`, commit `a3b0c85` (2021-01-24).
> All line citations are relative to the repository root (e.g. `py-kms/pykms_Server.py:123`
> means the file `py-kms/pykms_Server.py` inside the repo, at line 123).

---

## 1. What py-kms is

py-kms is a **KMS (Key Management Service) emulator** — a userspace server that impersonates a
Microsoft Volume Activation KMS host. Windows and Office clients configured with a GVLK
(Generic Volume License Key) contact it over TCP/1688, speak MS-KMS over DCE/RPC, and receive a
signed activation response granting a 180-day activation lease.

It implements the KMS protocol in **three versions** — v4, v5 and v6 — with the corresponding
CMAC / AES-CBC / AES-CBC+HMAC response constructions, entirely in pure Python with **no compiled
extension and no external cryptography library**.

### 1.1 Provenance

The in-repo history statement is short and unambiguous (`README.md:11`):

> _py-kms_ is a port of node-kms created by [cyrozap](http://forums.mydigitallife.info/members/183074-markedsword),
> which is a port of either the C#, C++, or .NET implementations of KMS Emulator. The original version
> was written by [CODYQX4](http://forums.mydigitallife.info/members/89933-CODYQX4) and is derived from
> the reverse-engineered code of Microsoft's official KMS.

So the chain recorded in the repository is: **Microsoft KMS → reverse-engineered C#/C++/.NET
"KMS Emulator" (CODYQX4) → node-kms (cyrozap / "markedsword") → py-kms**. The wider lineage
usually cited outside the repo — an early Python `py-kms` circulated in the MDL/Black Hat-era
KMS-emulator scene, later picked up by ZeroTaper and markedsword — is *not* documented anywhere in
this tree; the only names present in the repo are cyrozap/markedsword and CODYQX4.

The current tree is a **full rewrite by Matteo ℱan (SystemRage)**. Every module is prefixed
`pykms_`, the Python 2 fork was merged away in release `py-kms_2019-05-15` (`CHANGELOG.md:23`), and
the module authorship markers throughout name SystemRage (`py-kms/pykms_Server.py:32`,
`py-kms/pykms_Client.py:32`, `py-kms/pykms_GuiBase.py:21`).

Vendored third-party code inside the tree:

| Vendored component | Origin | Location |
| --- | --- | --- |
| DCE/RPC structures + `Structure` binary-struct DSL | impacket | `py-kms/pykms_Dcerpc.py`, `py-kms/pykms_Structure.py` |
| SlowAES (pure-Python AES) | SlowAES project, modified for KMS v6 | `py-kms/pykms_Aes.py:19` |
| Etrigan daemonizer | SystemRage/Etrigan | `py-kms/Etrigan.py` |
| `MultiProcessingLogHandler` | jruere/multiprocessing-logging (LGPL-3.0) | `py-kms/pykms_Misc.py:89` |
| FILETIME helpers | David Buxton (BSD) | `py-kms/pykms_Filetimes.py` |
| `MultipleListener` | Giampaolo Rodolà recipe (MIT) | `py-kms/pykms_Connect.py:83` |
| `KmsDataBase.xml` schema + data | Hotbird64's vlmcsd `KmsData` v1.7 | `py-kms/KmsDataBase.xml:74` |

### 1.2 Language, size, license

| Property | Value |
| --- | --- |
| Language | Python 3 only (no `setup.py`, no `pyproject.toml`, no version guard) |
| Size | 8,235 lines across 23 `.py` files in `py-kms/`; ~10,060 lines counting docs and Docker |
| Largest modules | `pykms_GuiBase.py` (948), `pykms_Misc.py` (930), `pykms_Structure.py` (763), `pykms_Aes.py` (739), `pykms_Dcerpc.py` (731), `pykms_Server.py` (645), `Etrigan.py` (609) |
| Product database | `py-kms/KmsDataBase.xml`, 991 lines / ~88 KB |
| License (emulator) | The Unlicense — `LICENSE`, `py-kms/pykms_Server.py:31`, `py-kms/pykms_Client.py:31` |
| License (GUI) | MIT © 2020 Matteo ℱan — `LICENSE.gui.md`, `py-kms/pykms_GuiBase.py:20` |
| Runtime deps | **None required.** `sqlite3`, `tzlocal`+`pytz`, `tkinter`, `Pillow` are all optional |
| Version banners | server `py-kms_2020-10-01` (`py-kms/pykms_Server.py:30`), client `py-kms_2020-07-01` (`py-kms/pykms_Client.py:30`), GUI `py-kms_gui_v3.0` (`py-kms/pykms_GuiBase.py:19`) |

There is **no `--version` flag** — the version string appears only in the `-h` epilog.

### 1.3 Status: dormant

- Upstream `SystemRage/py-kms` last commit: **`a3b0c85`, 2021-01-24** ("Merge pull request #125 from
  Simonmicro/master"). Nothing since.
- The product database `py-kms/KmsDataBase.xml` is even older — last touched 2019-05-14 (release
  `py-kms_2019-05-15`), so it is roughly two years stale relative to HEAD and roughly seven years
  stale today.
- Active development moved to **`Py-KMS-Organization/py-kms`**, whose `main` branch is **276 commits
  ahead** of `SystemRage/py-kms@master` (head `b0e1615`, 2026-05-01). Anything in this document
  describing a bug or a missing product is a statement about the *dormant* upstream, not about the
  successor fork.
- There is **no test suite, no CI configuration and no `.github/` directory** anywhere in the tree.
  Nothing automatically verifies any behaviour described below.
- `README.md:5` still renders a `docker/cloud/build` badge for a Docker Hub autobuild service that
  has since been retired.

### 1.4 Design philosophy (why it looks the way it does)

Four deliberate choices explain almost every structural quirk in the codebase:

1. **Pure Python, zero compiled dependencies.** AES is hand-rolled (`py-kms/pykms_Aes.py`); only
   SHA-256 and HMAC come from the stdlib. There is not even an *optional* PyCryptodome/OpenSSL
   path. This makes the program runnable by dropping a folder anywhere with a `python3` binary —
   and makes it ~1000× slower per activation than a native implementation
   (`py-kms/pykms_Aes.py:398`, `:448`).
2. **Data-driven product knowledge.** All product GUIDs, SKUs, GVLKs, protocol versions and client
   count policies come from an XML file borrowed from vlmcsd, not from code. Updating for a new
   Windows release should be a data edit — except that nothing caches or validates it, and half the
   attributes are read by no code at all (§7.5).
3. **GUI-first friendliness.** A Tkinter GUI is a first-class front end that shares the exact same
   option dictionaries as the CLI (`py-kms/pykms_GuiBase.py:14`), and the program auto-selects the
   GUI when stdout is not a tty (`py-kms/pykms_Server.py:639`) so a double-click in a file manager
   "just works".
4. **Container-friendly single process.** One threaded TCP server, one config dict, no state
   outside an optional SQLite file. Everything an operator would tune is a CLI flag, and the Docker
   images map environment variables onto those flags in a shell wrapper.

The costs of (1)–(4) are enumerated in §7.

---

## 2. Repository layout and module map

```
README.md              CHANGELOG.md   LICENSE   LICENSE.gui.md   .gitignore
docs/                  Sphinx/recommonmark documentation set (8 pages + 6 screenshots)
docker/
  docker-py3-kms/          "full" image: 4 Dockerfiles, start.sh, hooks/, manifests
  docker-py3-kms-minimal/  "minimal"/"latest" image: 4 Dockerfiles, hooks/, manifests
py-kms/
  pykms_Server.py        entry point, CLI parsing, KeyServer, request handler   (645)
  pykms_Client.py        built-in KMS test client                               (364)
  pykms_Base.py          KMS envelope structs, dispatch, serverLogic            (262)
  pykms_RequestV4.py     v4 request/response + modified AES-CMAC                (132)
  pykms_RequestV5.py     v5 request/response + AES-128-CBC                      (180)
  pykms_RequestV6.py     v6 response + HWID/XorSalts/HMAC-SHA256                (108)
  pykms_RequestUnknown.py error envelope for unknown KMS versions                (16)
  pykms_RpcBase.py       PDU type / flag constants, populate()                   (45)
  pykms_RpcBind.py       bind / bind_ack + transfer-syntax negotiation          (175)
  pykms_RpcRequest.py    RPC request / response                                  (70)
  pykms_Dcerpc.py        impacket-derived DCE/RPC structures                    (731)
  pykms_Structure.py     impacket-derived binary-struct DSL                     (763)
  pykms_Aes.py           SlowAES fork, Rijndael-128/160 + KMS v6 tweak          (739)
  pykms_PidGenerator.py  random ePID synthesis                                   (85)
  pykms_DB2Dict.py       KmsDataBase.xml -> python dicts                          (47)
  pykms_Sql.py           optional SQLite client log                             (101)
  pykms_Misc.py          logging setup, argv validation, LCID table             (930)
  pykms_Format.py        ANSI pretty-printer channel, byterize/enco/deco        (448)
  pykms_Filetimes.py     FILETIME <-> datetime                                  (105)
  pykms_Connect.py       MultipleListener, create_server_sock                   (215)
  pykms_GuiBase.py       Tkinter GUI main window                                (948)
  pykms_GuiMisc.py       GUI widgets, text redirection, animations              (517)
  Etrigan.py             vendored double-fork daemonizer                        (609)
  KmsDataBase.xml        product database                                       (991)
  graphics/              5 GIFs used by the GUI
```

---

## 3. Architecture and request lifecycle

```
TCP accept (KeyServer / ThreadingMixIn, daemon threads)
  └─ kmsServerHandler.setup()        py-kms/pykms_Server.py:577   logs peer, stores srv_config['raddr']
     └─ handle() loop                py-kms/pykms_Server.py:581
        ├─ recv(1024)  (single fixed-size read, no reassembly)   :586
        ├─ MSRPCHeader(data)['type']                              :596
        │   ├─ 11 bind      -> pykms_RpcBind.handler              :597
        │   ├─  0 request   -> pykms_RpcRequest.handler           :601
        │   └─ anything else-> log "Invalid RPC request type", close :605
        ├─ handler.populate() = generateResponse(parseRequest())  py-kms/pykms_RpcBase.py:41
        │     for a request PDU:
        │       generateKmsResponseData(pduData, srv_config)      py-kms/pykms_Base.py:245
        │         switch on versionMajor -> V4 / V5 / V6 / Unknown  :249
        │           kmsBase.serverLogic()                          py-kms/pykms_Base.py:109
        │             - parse CMID / appId / skuId / requestTime
        │             - localize time (optional tzlocal)           :120
        │             - synthesize currentClientCount              :136
        │             - resolve product display names from XML     :163
        │             - optional MININFO log record                :205
        │             - optional SQLite insert/update              :210
        │           kmsBase.createKmsResponse()                    py-kms/pykms_Base.py:216
        │             - echo version / CMID / requestTime
        │             - ePID: -e literal, else epidGenerator()     :221
        │             - clientCount, activation, renewal intervals :230
        │             - optional SQLite ePID write-back            :235
        │           per-version encryption / MAC
        ├─ send(res)   (send(), not sendall())                     :620
        └─ break after answering ONE activation request            :621
     └─ finish() closes socket                                     :628
```

Key structural facts:

- **One activation per TCP connection.** After answering a `request` PDU the loop breaks
  unconditionally (`py-kms/pykms_Server.py:621`). Any number of `bind` PDUs may precede it. This is
  not configurable. (vlmcsd makes the equivalent behaviour opt-in via `-d` and defaults it off.)
- **All exceptions in request handling are swallowed.** `KeyServer.handle_error()` is overridden to
  `pass` (`py-kms/pykms_Server.py:129`). Every crash path in §7 therefore manifests only as a
  dropped connection with no log line at any level.
- **The server never emits an RPC fault or a bind_nak.** `MSRPCBindNak` is defined
  (`py-kms/pykms_Dcerpc.py`) but is only ever *parsed* by the client.

---

## 4. Feature inventory

### 4.1 KMS protocol

| Feature | Configurability | Notes | Evidence |
| --- | --- | --- | --- |
| Version dispatch v4 / v5 / v6 | always on | switch on `versionMajor` only | `py-kms/pykms_Base.py:245`, `:249` |
| `versionMinor` handling | always on | parsed, **never validated**, echoed verbatim into the response | `py-kms/pykms_Base.py:246`, `:218` |
| Unknown-version error envelope | always on | builds `SL_E_VL_KEY_MANAGEMENT_SERVICE_ID_MISMATCH` (0xC004F042) — **then always raises** (§7.1) | `py-kms/pykms_RequestUnknown.py:11` |
| `kmsRequestStruct` (236 bytes fixed) | parsed from client | versionMinor/Major, isClientVm, licenseStatus, graceTime, appId/skuId/kmsCountedId/CMID GUIDs, requiredClientCount, requestTime FILETIME, previousCMID, machineName (UTF-16, 126-byte padded field) | `py-kms/pykms_Base.py:34` |
| `kmsResponseStruct` (46 + ePID bytes) | see below | versionMinor/Major, epidLen, kmsEpid (UTF-16LE, NUL-NUL terminated), CMID, responseTime, currentClientCount, vLActivationInterval, vLRenewalInterval | `py-kms/pykms_Base.py:60` |
| Response field echo | always on | versionMinor/Major, CMID and `responseTime = requestTime` copied verbatim | `py-kms/pykms_Base.py:216`, `:227`, `:229` |
| Clock-skew validation (±4 h rule) | **absent** | present only as a TODO comment; the server never reads its own clock | `py-kms/pykms_Base.py:228` |
| NDR conformant-array wrapper | always on | `DataLength`, `DataSizeMax=0x00020000`, `DataSizeIs`, body, then `getPadding()` | `py-kms/pykms_Base.py:105` |
| RPC/HRESULT return code | **conflated with padding** | `getPadding()` returns `4 + align`, and those 4 bytes are always zero — a non-zero HRESULT can never be returned on the success path | `py-kms/pykms_Base.py:107` |
| Licence-status decode table | always on | 0 Unlicensed, 1 Licensed, 2 oobGrace, 3 ootGrace, 4 nonGenuineGrace, 5 notification, 6 extendedGrace | `py-kms/pykms_Base.py:84`–`:102` |
| FILETIME conversion | always on (logging only) | `EPOCH_AS_FILETIME = 116444736000000000` | `py-kms/pykms_Filetimes.py:35` |
| Deliberate 1-second V4 delay | **not configurable** | `time.sleep(1)` — "request sent back too quick for Windows 2008 R2" | `py-kms/pykms_RequestV4.py:54` |

**V4 framing.** `RequestV4 = bodyLength1 '<I', bodyLength2 '<I', request(kmsRequestStruct), hash '16s', padding`.
`ResponseV4 = bodyLength1, unknown '!I=0x00000200', bodyLength2, response, hash '16s', padding`
(`py-kms/pykms_RequestV4.py:25`, `:35`). The field named `unknown` is not unknown — packed
big-endian it is `00 00 02 00`, i.e. the NDR conformant-array `MaximumCount` (`LE32 0x00020000`).

**V5 framing.** `Message = salt '16s', encrypted '240s', padding ':'`
(`py-kms/pykms_RequestV5.py:18`). The response salt on the wire is the *client's* SaltC — V5
requires request and response IVs to be identical.

**V6 framing.** The decrypted response body carries four extra fields beyond V5:
`response, keys '16s', hash '32s', hwid '8s', xorSalts '16s'`, plus an outer `hmac '16s'`
(`py-kms/pykms_RequestV6.py:16`–`:31`).

### 4.2 Cryptography

All KMS AES keys are the well-known published Microsoft constants:

| Version | Key | Location |
| --- | --- | --- |
| v4 (Rijndael-160 CMAC) | `05 3D 83 07 F9 E5 F0 88 EB 5E A6 68 6C F0 37 C7 E4 EF D2 D6` (20 bytes) | `py-kms/pykms_RequestV4.py:17` |
| v5 (AES-128) | `CD 7E 79 6F 2A B2 5D CB 55 FF C8 EF 83 64 C4 70` | `py-kms/pykms_RequestV5.py:64` |
| v6 (AES-128, tweaked rounds) | `A9 4A 41 95 E2 01 43 2D 9B CB 46 04 05 D8 4A 21` | `py-kms/pykms_RequestV6.py:33` |

| Feature | Availability | Description | Evidence |
| --- | --- | --- | --- |
| Pure-Python AES (SlowAES fork) | always | key sizes 16/24/32 (10/12/14 rounds) plus KMS Rijndael-160 (11 rounds). Modes: OFB=0, CFB=1, CBC=2 only. Only CBC is used | `py-kms/pykms_Aes.py:39`, `:461` |
| KMS v6 modified round tweak | per-request flag | XORs `state[0]` with `0x73` at round 4, `0x09` at round 6, `0xE4` at round 8, after MixColumns; inverse applies the same after AddRoundKey | `py-kms/pykms_Aes.py:43`, `:297`, `:315` |
| V4 modified AES-CMAC | always | 160-bit-key CBC-MAC with `0x80` bit padding and **no CMAC subkey XOR**; emits a full extra `80 00…` block when the message length is a multiple of 16 | `py-kms/pykms_RequestV4.py:58` |
| V5 request decryption | always | whole `SaltC ‖ ciphertext` fed to CBC with `IV = SaltC`, so block 0 yields `D(SaltC) ^ SaltC` (stored as `DSaltC`) | `py-kms/pykms_RequestV5.py:64` |
| V5 response key material | always | `hash = SHA256(randomSalt)`; `keys[i] = DSaltC[i] ^ SaltC[i] ^ randomSalt[i]` (= `D(SaltC) ^ random`) | `py-kms/pykms_RequestV5.py:39`–`:48` |
| V6 XorSalts / HMAC | always | `XorSalts = SaltC ^ DSaltC`; fresh random `SaltS` as response IV; `HMacMsg = D(SaltS) ‖ Message`; only `HMAC-SHA256(...)[16:]` (low 16 bytes) is transmitted | `py-kms/pykms_RequestV6.py:39`–`:86` |
| V6 time-slot HMAC key derivation | always | `seed = ((t // 0x22816889BD) * 0x208CBAB5ED + 0x3156CD5AC628477A) mod 2^64`; `key = SHA256(pack('<Q', seed))[16:]`. Time source is the **client-supplied** `requestTime` | `py-kms/pykms_RequestV6.py:94`, `:79` |
| PKCS7 padding | always | `append_PKCS7_padding` is correct; `strip_PKCS7_padding` checks only length and `numpads > 16` — it does **not** verify padding bytes and does not reject `numpads == 0` | `py-kms/pykms_Aes.py:23`, `:28` |
| Salt / IV randomness | not configurable | `random.getrandbits(8)` (Mersenne Twister), **not** `os.urandom` | `py-kms/pykms_RequestV5.py:130` |
| Hardware/OpenSSL AES | **absent** | no import of PyCryptodome, `cryptography`, M2Crypto or OpenSSL bindings anywhere; no build-time or run-time switch. Only `hashlib`/`hmac` come from the stdlib | `py-kms/pykms_RequestV5.py:5`, `py-kms/pykms_Aes.py:19` |

The V4/V5/V6 constructions are algebraically identical to vlmcsd's — a real Windows client cannot
tell them apart on cryptographic grounds. The implementation issues (timing, RNG quality, key
schedule recomputation, thread-shared cipher state) are catalogued in §7.2.

### 4.3 DCE/RPC transport layer

| Feature | Availability | Description | Evidence |
| --- | --- | --- | --- |
| PDU types accepted | always | **only** 11 (`bind`) and 0 (`request`). No `alter_context` (14), no `auth3`, no `ping`, no `co_cancel`, no `orphaned` | `py-kms/pykms_Server.py:596`–`:608` |
| PDU types emitted | always | **only** 12 (`bind_ack`) and 2 (`response`). Never `bind_nak` (13), never `fault` (3), never `alter_context_resp` (15) | `py-kms/pykms_RpcBase.py:4` |
| bind_ack construction | mostly hardcoded | ver/representation/call_id/max_tfrag/max_rfrag/auth_len echoed; `type=12`; `flags = firstFrag\|lastFrag\|multiplex` (0x13) forced; `frag_len = 36 + ctx_num*24` hardcoded; `assoc_group = 0x1063bf3f` hardcoded; `SecondaryAddr = str(srv_config['port'])` | `py-kms/pykms_RpcBind.py:88`–`:111` |
| Transfer-syntax negotiation | fixed 3-entry table | NDR32 `8a885d04-…` → accept (Result 0, Reason 0, ver 2); NDR64 `71710533-…` → provider_rejection (2,2, NULL GUID); BTFN `6cb71c2c-9812-4540-0300-000000000000` → negotiate_ack (3,3) | `py-kms/pykms_RpcBind.py:16`–`:19`, `:113`–`:122` |
| Abstract syntax (interface UUID) validation | **absent** | `AbstractSyntaxUUID`/`Ver` are declared in `CtxItem` but never compared against the KMS interface UUID `51c82175-844e-4750-b0d8-ec255555bc06` — the server ACKs a bind for *any* interface offering NDR32 | `py-kms/pykms_RpcBind.py:21`–`:33`, `:119` |
| `ctx_id` / `op_num` / `alloc_hint` validation | **absent** | `ctx_id` is echoed without checking it corresponds to an accepted context; `op_num` is never checked to be 0; NDR lengths are never cross-checked | `py-kms/pykms_RpcRequest.py:16`–`:38` |
| RPC authentication | **absent** | `SEC_TRAILER`, all `RPC_C_AUTHN_*`/`RPC_C_AUTHN_LEVEL_*`, `rpc_status_codes`, `rpc_provider_reason`, `rpc_cont_def_result` are defined but referenced nowhere. An authenticated bind gets a bind_ack with non-zero `auth_len` but no trailer — a malformed packet | `py-kms/pykms_Dcerpc.py:554`, `py-kms/pykms_RpcBind.py:99` |
| Fragmentation / reassembly | **absent** | one fixed `recv(1024)` per PDU; `frag_len` is never used to size the read; `PFC_FIRST_FRAG`/`PFC_LAST_FRAG` are never inspected; replies use `send()` not `sendall()` | `py-kms/pykms_Server.py:586`, `:620` |
| Connection lifetime | not configurable | forced disconnect after one activation | `py-kms/pykms_Server.py:621` |
| `Structure` binary-struct DSL | n/a | impacket-derived; format codes include all `struct` codes, `':'` raw, `'z'` NUL-terminated, `'u'` UTF-16 double-NUL, `'w'` NDR string, `'?-field'` length-of, `'?=expr'` computed via `eval()`, `'_'` not-packed | `py-kms/pykms_Structure.py:38`, `:131`, `:196` |
| Duplicated/dead structure definitions | vestigial | `pykms_Dcerpc.py` defines `CtxItem`/`CtxItemResult`/`MSRPCBind`; `pykms_RpcBind.py` defines its own differently-shaped versions and uses those. `MSRPCBindAck._CTX_ITEM_LEN` resolves to the `pykms_Dcerpc` one and works only because both are coincidentally 24 bytes | `py-kms/pykms_Dcerpc.py:538`, `py-kms/pykms_RpcBind.py:21`, `:35` |

### 4.4 Server runtime

| Feature | Availability | Description | Evidence |
| --- | --- | --- | --- |
| Threading model | always | `KeyServer(socketserver.ThreadingMixIn, socketserver.TCPServer)`, `daemon_threads = True`, one OS thread per connection. **No thread cap, no connection cap, no rate limiting** | `py-kms/pykms_Server.py:37`–`:38` |
| Socket creation | always | `socketserver.BaseServer.__init__` is called directly, bypassing `TCPServer.__init__`; sockets come from `MultipleListener` | `py-kms/pykms_Server.py:41`, `py-kms/pykms_Connect.py:85` |
| Hand-rolled serve loop | always | `pykms_serve()` merges `serve_forever`/`handle_request`: a `PollSelector` (falling back to `SelectSelector`) watches all listener fds plus a self-pipe | `py-kms/pykms_Server.py:75`–`:117` |
| Self-pipe eject channel | always | `socket.socketpair()`; `terminate_eject()` writes a UTF-8 skull, the loop reads 8 bytes and `sys.exit(0)` — used by the GUI STOP button | `py-kms/pykms_Server.py:44`, `:112`, `:152` |
| Multi-socket listener | via `connect -n` | `MultipleListener` broadcasts `settimeout`/`setsockopt`/`setblocking`/`shutdown`/`close` to all sockets; `gettimeout`/`getsockname`/`getsockopt` refer to the first | `py-kms/pykms_Connect.py:85` |
| `SO_REUSEADDR` | automatic | set unconditionally on non-Windows (`os.name not in ('nt','cygwin')`), **regardless of `-u`** | `py-kms/pykms_Connect.py:54` |
| `SO_REUSEPORT` | `connect -u` disables | default ON; raises `ValueError("SO_REUSEPORT not supported on this platform")` when unavailable | `py-kms/pykms_Connect.py:34`, `:61` |
| IPv6 `IPV6_V6ONLY` | `connect -d` | with `-d`: cleared (dual-stack). **Without `-d`: explicitly set to 1**, defeating the Linux default | `py-kms/pykms_Connect.py:63`–`:67` |
| Dual-stack fallback | automatic | if the platform reports `dualstack_ipv6 not supported`, `KeyServer.__init__` retries with `want_dual=False` and warns | `py-kms/pykms_Server.py:53`–`:58` |
| Windows Sandbox port-reuse workaround | automatic | if `getpass.getuser() == 'WDAGUtilityAccount'`, port reuse is forced off for the main address and every `-n` address | `py-kms/pykms_Server.py:498`, `:505` |
| Terminal vs GUI auto-selection | automatic | `if sys.stdout.isatty(): server_main_terminal() else: try GUI except: terminal` — a bare `except:` | `py-kms/pykms_Server.py:638`–`:645` |
| Error handling | not configurable | `handle_error()` → `pass` | `py-kms/pykms_Server.py:129` |
| Idle timeout behaviour | `-t0` | `handle_timeout()` logs "Server connection timed out. Exiting..." and `sys.exit(1)` — kills the **process**, not a connection (§7.6) | `py-kms/pykms_Server.py:125`, `:87`, `:101`–`:105` |
| Startup banner | INFO level | `TCP server listening at <ip> on port <port>` plus `HWID: <hex>` | `py-kms/pykms_Server.py:501`, `:513` |
| HTTP / health / metrics endpoints | **absent** | py-kms speaks only MS-KMS over TCP. No HTTP listener, no `/health`, no Prometheus/statsd, no admin socket. The only status command is the Etrigan pidfile check | (grep for flask/http/health/metric over `py-kms/*.py` yields only comment URLs) |

### 4.5 ePID and HWID generation

**ePID format** (8 fields, `PPPPP-GGGGG-KKK-KKKKKK-CC-LLLL-BBBB.0000-DDDYYYY`), assembled at
`py-kms/pykms_PidGenerator.py:66`–`:85`:

| Part | Content | Source |
| --- | --- | --- |
| 1 | PlatformId, 5 digits | chosen `WinBuild`'s `PlatformId` |
| 2 | GroupId, 5 digits | chosen `CsvlkItem`'s `GroupId` |
| 3 | `productKeyID // 1000000`, 3 digits | `random.randint(MinKeyId, MaxKeyId)` |
| 4 | `productKeyID % 1000000`, 6 digits | same |
| 5 | licenseChannel, 2 digits | **hardcoded to 3** (Volume: GVLK/MAK) — `py-kms/pykms_PidGenerator.py:52` |
| 6 | LCID | the `-l/--lcid` value, **unpadded** (`str(languageCode)`) — `:78` |
| 7 | BuildNumber + `.0000`, 4 digits | chosen `WinBuild`'s `BuildNumber` |
| 8 | day-of-year (3, **zero-based**) + year (4) | uniform random date between the build's `MinDate` and now — `:62`–`:64` |

Example output: `03612-00206-568-504964-03-1033-17763.0000-2872019`.

Selection logic:
- **CSVLK**: scans all 49 `CsvlkItem`s asking whether the request's `kmsCountedId` is in that item's
  `Activate` list; on match appends the real tuple, **on non-match appends a Windows Server 2019
  fallback** `('206','551000000','570999999','[0,1,2]')`, then `random.choice` over the whole list
  (`py-kms/pykms_PidGenerator.py:20`–`:31`). See §7.4 for the resulting bias.
- **Host build**: scans all 18 `WinBuild`s, keeping those whose `int(WinBuildIndex)` is not in the
  chosen CSVLK's `InvalidWinBuild` list; the 12 records with no `WinBuildIndex` attribute raise
  `KeyError` and append a hardcoded build-17763 fallback (`:36`–`:45`).
- The `version` parameter (`kmsRequest['versionMajor']`) is accepted and **never used**
  (`py-kms/pykms_PidGenerator.py:13`).
- A fresh ePID is generated for **every single response** — a real KMS host has one stable ePID.
  `-e/--epid` is the only way to get a stable identity.

**HWID** (V6 responses only, 8 bytes). Accepted forms: a 16-character hex string, optionally
`0x`-prefixed; or the literal `RANDOM` (case-sensitive) which takes `uuid.uuid4().hex[:16]` **once
at server start**, not per client. Validation rejects, in order: non-hex characters (naming the
offending digits), odd length, `< 16`, `> 16`; then `binascii.a2b_hex` (`py-kms/pykms_Server.py:412`–`:442`).
Default `364F463A8863D35F`, a static fingerprint shared by every stock deployment.
V4/V5 clients never see a HWID, which is why the test client wraps the read in `try/except KeyError`.

### 4.6 Client-count synthesis

py-kms keeps **no client list at all**. The `currentClientCount` returned to the client is derived
per request from the *client's own* `requiredClientCount` field (`py-kms/pykms_Base.py:136`–`:159`):

Let `MinClients = kmsRequest['requiredClientCount']` (25 for desktop Windows, 5 for server/Office —
the `NCountPolicy` attribute in the XML) and `RequiredClients = 2 * MinClients`.

| `-c` value | Reported count | Warning logged |
| --- | --- | --- |
| not given (`None`) | `RequiredClients` (50 desktop / 10 server-Office) | none |
| `0 < c < MinClients` | `MinClients + 1` (26 / 6) | "Not enough clients ! Fixed with N, but activated client could be detected as not genuine !" |
| `MinClients <= c < RequiredClients` | `c` verbatim | "With count = N, activated client could be detected as not genuine !" |
| `c >= RequiredClients` | `RequiredClients` | "Too many clients ! Fixed with N" (only when strictly greater) |
| `c == 0` | **crash** — `UnboundLocalError` (§7.3) | none |

The `requestCount` column in the SQLite database and the number of distinct CMIDs seen are **never
read back**. There is no 30-day CMID aging as a genuine KMS host performs.

### 4.7 Logging and observability

| Feature | Availability | Description | Evidence |
| --- | --- | --- | --- |
| Log levels | `-V` | CRITICAL, ERROR, WARNING, INFO, DEBUG, **MININFO**. MININFO is a custom level registered at numeric **25** (above INFO=20) by `add_logging_level('MININFO', 25)` | `py-kms/pykms_Misc.py:156` |
| MININFO record | `-V MININFO` only | one compact line per activation carrying `host` (peer address), `status` (licence status string), `product` (SKU display name); emitted only when `srv_config['loglevel'] == 'MININFO'` (string compare) | `py-kms/pykms_Base.py:205`–`:208` |
| Log targets | `-F` | see the `-F` table in §5.1 | `py-kms/pykms_Misc.py:161`–`:182` |
| Rotation | `-S` | `RotatingFileHandler(maxBytes = int(logsize * 1024 * 512), backupCount = 1)`. `0` (default) means `maxBytes=0`, i.e. never rotates. Exactly one backup is kept | `py-kms/pykms_Misc.py:169`, `:179` |
| Log formats | **not configurable** | general/file and stdout: `'%(asctime)s %(levelname)-8s %(message)s'`; MININFO: `'%(asctime)s %(levelname)-8s %(host)s   %(status)s   %(product)s  %(message)s'`; a `'%(name)s '` prefix is prepended under the GUI. `datefmt` is `'%a, %d %b %Y %H:%M:%S'` | `py-kms/pykms_Misc.py:191`–`:199` |
| Colour | automatic, stdout handler only | MININFO orange, CRITICAL magenta+bold, ERROR red+bold, WARNING yellow+bold, INFO cyan, DEBUG green. **No TTY detection, no `--no-color`** — piping `-F STDOUT` to a file yields raw ANSI | `py-kms/pykms_Misc.py:217` |
| Asynchronous emission | `-y` | wraps every handler in `MultiProcessingLogHandler` — a `multiprocessing.Queue(-1)` plus a daemon receiver thread named `Thread-AsyncMsg<HandlerName>` | `py-kms/pykms_Misc.py:94`, `:222` |
| Pretty-printer channel | implicit via `-F` | a *second*, non-logging output channel printing numbered ASCII-art protocol-trace messages ("Server received RPC Bind Request !!!", arrows) with ANSI colour. Enabled only when the `-F` target is a plain file or `FILEOFF`; honours `sys.stdout.isatty()` | `py-kms/pykms_Format.py:85`, `:318`, `py-kms/pykms_Misc.py:542` |
| Request-time localization | optional `tzlocal`+`pytz` | `filetime_to_dt()` gives naive UTC; if importable, `tz.localize(dt)` is applied and formatted `'%Y-%m-%d %H:%M:%S %Z (UTC%z)'`. Absent → WARNING on **every request** and naive UTC | `py-kms/pykms_Base.py:118`–`:134` |
| Product name resolution for logs | always on | walks AppItems → KmsItems → SkuItems comparing UUIDs to resolve display names | `py-kms/pykms_Base.py:163`–`:186` |

### 4.8 SQLite persistence

Enabled with `-s/--sqlite`. Schema — **exactly one table**, created only if the file does not
already exist (`py-kms/pykms_Sql.py:18`–`:26`):

```sql
CREATE TABLE clients(clientMachineId TEXT, machineName TEXT, applicationId TEXT, skuId TEXT,
                     licenseStatus TEXT, lastRequestTime INTEGER, kmsEpid TEXT, requestCount INTEGER)
```

No PRIMARY KEY, no UNIQUE constraint, no index, no foreign keys, no schema-version table.

Write path, per activation:

1. `sql_initialize(dbName)` — `os.path.isfile()` check + `CREATE TABLE` if absent. Runs on **every
   request**, not once at startup (`py-kms/pykms_Base.py:211`).
2. `sql_update(dbName, infoDict)` — `SELECT … WHERE clientMachineId=? AND applicationId=?`; on miss
   `INSERT` with `requestCount = 1` (and **no `kmsEpid` column in the INSERT list**, so it starts
   NULL); on hit, up to five conditional `UPDATE`s (machineName, applicationId, skuId,
   licenseStatus, lastRequestTime) then an unconditional `requestCount = requestCount + 1`
   (`py-kms/pykms_Sql.py:36`–`:78`).
3. `sql_update_epid(...)` — reopens the DB after the response is built and writes the ePID
   (`py-kms/pykms_Sql.py:80`–`:101`).

That is **three separate `connect`/`commit`/`close` cycles per request**.

Column-name caveats: `applicationId` stores the AppItem **display name** ("Windows",
"Office 14 (2010)", "Office 15 (2013) / 16 (2016) / 17 (2019)"), not a GUID; `skuId` stores the
SkuItem display name ("Windows 10 Enterprise"); `licenseStatus` stores the human string
("Grace Period"); `lastRequestTime` is `int(time.time())` — the **server's** clock at processing
time, not the client's `requestTime` FILETIME.

Row identity is `(clientMachineId, applicationId-display-name)`. One CMID gets one row per
application *family*, not per SKU — activating Word 2016 then Project 2016 just overwrites `skuId`
on the same row. There is **no activation history**: one mutable row, a single `lastRequestTime`, a
monotonic `requestCount`, no per-request rows, no retention/aging, no pruning tool. The only
chronological record is the text log.

**No read/report path ships with py-kms** — no CLI subcommand, no GUI view, no export, no query
helper. The only viewer is external: the full Docker image git-clones `coleifer/sqlite-web` at build
time and, with `SQLITE` enabled, runs `sqlite_web.py -H ${IP} -x ${PWD}/pykms_database.db --read-only`
as the container's foreground process (`docker/docker-py3-kms/start.sh:29`).

Concurrency: each `sql_*` function opens its own connection (default 5 s busy timeout, deferred
rollback-journal isolation). No `threading.Lock`, no `BEGIN IMMEDIATE`, no retry loop, no WAL. See
§7.7.

### 4.9 Built-in test client (`pykms_Client.py`)

| Aspect | Behaviour | Evidence |
| --- | --- | --- |
| Request fields | `versionMinor=0`, `isClientVm=0`, `licenseStatus=2` (oobGrace / "Grace Period"), `graceTime=43200` (minutes), `previousClientMachineId` = 16 NUL bytes, `requestTime = dt_to_filetime(datetime.utcnow())` | `py-kms/pykms_Client.py:288`–`:311` |
| Hardcoded, no flag | `licenseStatus`, `graceTime`, `isClientVm`, `previousClientMachineId` | same |
| Protocol version | never chosen directly; taken from the selected KmsItem's `DefaultKmsProtocol` attribute (`int(float("4.0"\|"5.0"\|"6.0"))`) | `py-kms/pykms_Client.py:173`, `:313`–`:328` |
| Bind offered | exactly two ctx items: ctx 0 = KMS abstract syntax `51c82175-844e-4750-b0d8-ec255555bc06` v1 + NDR32 v2; ctx 1 = same abstract syntax + BTFN v1. `max_tfrag`/`max_rfrag` 5840, `assoc_group` 0, `call_id` starts at 1 and increments (bind=1, activation=2) | `py-kms/pykms_RpcBind.py:131`–`:172`, `py-kms/pykms_Client.py:149` |
| NDR64 | **never offered**, so the server's NDR64-rejection path can never be exercised by the shipped client | `py-kms/pykms_RpcBind.py:131` |
| Mode resolution | `name = re.sub('\(.*\)','',DisplayName).replace('2015','').replace(' ','')` matched against `-m`; SKU picked as `name + 'Enterprise'` (Windows) or `name[:6] + 'ProfessionalPlus' + name[6:]` (Office) | `py-kms/pykms_Client.py:156`–`:178` |
| Output (INFO) | KMS Host HWID (v6 only), KMS Host ePID, Current Client Count, VL Activation Interval, VL Renewal Interval, plus DEBUG hexdumps | `py-kms/pykms_Client.py:239`–`:259` |
| Response verification | v4 recomputes the CMAC and logs **only on match** (a mismatch is silent). v5/v6 verify **nothing**: not `SHA256(randomSalt)`, not that the v5 response IV equals the request IV, not the v6 HMAC | `py-kms/pykms_Client.py:345`–`:360` |
| GUI entry | `client_thread(threading.Thread)`; with `with_gui=True`, `client_options()` (argparse) is skipped entirely and `clt_config` is filled from Tk widgets | `py-kms/pykms_Client.py:38`–`:45`, `:268`–`:286` |

Resolved mode → product mapping (computed by replaying `client_update()` against the shipped XML):

| `-m` value | KmsItem (counted ID) | SKU ID | Proto | N |
| --- | --- | --- | --- | --- |
| WindowsVista | `212a64dc-43b1-4d3d-a30c-2fc69d2095c6` | `cfd8ff08-c0d7-452b-9f60-ef5c70c32094` | 4 | 25 |
| Windows7 | `7fde5219-fbfa-484a-82c9-34d1ad53e856` | `ae2ee509-1b34-41c0-acb7-6d4650168915` | 4 | 25 |
| Windows8 | `3c40b358-5948-45af-923b-53d21fcc7e79` (Volume) | `458e1bec-837a-45f6-b9d5-925ed5d299de` | 5 | 25 |
| Windows8.1 (**default**) | `cb8fc780-2c05-495a-9710-85afffc904d7` (Volume) | `81671aaf-79d1-4eb1-b004-8cbbe173afea` | 6 | 25 |
| Windows10 | `58e2134f-8e11-4d17-9cb2-91069c151148` ("Windows 10 2015 (Volume)") | `73111121-5638-40f6-bc11-f1d7b0d64300` | 6 | 25 |
| Office2010 | `e85af946-2e25-47b7-83e1-bebcebeac611` | `6f327760-8c5c-417c-9b61-836a98287e0c` | 4 | 5 |
| Office2013 | `e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0` | `b322da9c-a2e2-4058-9e4e-f59a6970bd69` | 5 | 5 |
| Office2016 | `85b5f61b-320b-4be3-814a-b76b2bfafc82` | `d450596f-894d-49e0-966a-fd39ed4c4c64` | 6 | 5 |
| Office2019 | `617d9eb1-ef36-4f82-86e0-a65ae07b96c6` | `85dd8b5f-eaa4-4af3-a628-cce9e77c9a03` | 6 | 5 |

Limitations: no mode selects any **Windows Server** product; only Enterprise / Professional Plus
SKUs are reachable; `Windows10` always resolves to the 2015-era counted ID (never `969fe3c0…` for
2016 or `11b15659…` for 2019, because the `.replace('2015','')` hack exists precisely to make
"Windows 10 2015 (Volume)" normalize to `Windows10`).

### 4.10 GUI (Tkinter)

Launched implicitly when `sys.stdout.isatty()` is false (`py-kms/pykms_Server.py:639`) or explicitly
with `etrigan start -g` (`py-kms/pykms_Server.py:265`). ~1,465 lines across
`py-kms/pykms_GuiBase.py` and `py-kms/pykms_GuiMisc.py`.

| Feature | Description | Evidence |
| --- | --- | --- |
| Server control column | `Server/State: Stopped/Serving` label; START/STOP SERVER toggle; SHOW/HIDE CLIENT toggle; DEFAULTS; CLEAR; EXIT | `py-kms/pykms_GuiBase.py:273`–`:297` |
| Server options, page 1 | IP, Port (digits-only), EPID, LCID (digits-only), HWID (editable combobox `364F463A8863D35F` / `RANDOM`), Client Count (**no validation**), Activation Interval, Renewal Interval, Logfile Path + Browse, 5-way logfile-mode radio listbox, Async Msg checkbox, Loglevel combobox, Logsize (float). Static red labels show the server version and `get_ip_address()` | `py-kms/pykms_GuiBase.py:299`–`:415` |
| Server options, page 2 | Timeout connection (`-t0`), Timeout send-recv (`-t1`), "Create Sqlite Database" checkbox + path entry | `py-kms/pykms_GuiBase.py:417`–`:450` |
| Client panel | all 11 `clt_options`: IP, Port, Mode combobox (9 choices), CMID, Machine Name, Logfile + Browse, radio listbox, Async Msg, Loglevel, Logsize, and a PageEnd with both timeouts. START CLIENT button | `py-kms/pykms_GuiBase.py:513`–`:669` |
| Preferences menu | "Enable server-side mode" / "Enable client-side mode", mutually exclusive, both refused while the server runs. Client-side mode hides the server panels and re-points stderr redirection — this is how you use the GUI purely as a remote KMS client. **Undocumented everywhere** | `py-kms/pykms_GuiBase.py:106`–`:146` |
| Flippable option sub-pages | `PageStart`/`PageEnd` canvases lifted by Left/Right buttons; with Pillow they are skinned with animated GIFs from `py-kms/graphics/`, otherwise plain `<<`/`>>` text buttons on lavender | `py-kms/pykms_GuiBase.py:163`–`:236`, `py-kms/pykms_GuiMisc.py:337`–`:449` |
| Keys background image | `graphics/pykms_Keys.gif` cropped per widget, alpha 36 / 96 / 128; flat lavender fill without Pillow | `py-kms/pykms_GuiMisc.py:285`–`:334` |
| Dual output panes | two `TextDoubleScroll` widgets (black, `wrap='none'`, scrollbars + sizegrip). `TextRedirect.Pretty` replaces `sys.stdout` and translates ANSI into Tk tags; routing to the server vs client pane is decided by whether the record starts with `logsrv` or `logclt` | `py-kms/pykms_GuiMisc.py:116`–`:282` |
| Window behaviour | `-topmost True`, `resizable(False, False)`, `WM_DELETE_WINDOW` bound to `lambda: 0` (the close button is a no-op — you must use EXIT), and a `self.after(200, …)` loop that keeps re-centering the window | `py-kms/pykms_GuiBase.py:469`–`:506` |
| Server start/stop | START pushes `'start'` onto a `queue.Queue` consumed by the module-level `server_thread` created at import; STOP calls `terminate_eject()` (self-pipe). A daemon `Thread-SrvEjt` polls `serverthread.eject` every 0.1 s | `py-kms/pykms_GuiBase.py:721`–`:776`, `py-kms/pykms_Server.py:133`–`:180` |
| Browse button | opens `filedialog.askdirectory()` and always forces the basename to the default log filename | `py-kms/pykms_GuiBase.py:861`–`:865` |
| "Your IP address is" | `subprocess.getoutput('hostname -I')` on posix, `socket.gethostbyname(socket.gethostname())` on nt, literal `'Unknown'` otherwise | `py-kms/pykms_GuiBase.py:27`–`:36` |
| Options NOT in the GUI | the entire `connect` subparser (`-n`, `-b`, `-u`, `-d`) and every `etrigan` option. 15 of 19 `srv_options` entries are exposed; all 11 `clt_options` are | `py-kms/pykms_Server.py:219`–`:224`, `:269`–`:281` |

### 4.11 Daemonization (Etrigan)

A vendored copy of SystemRage/Etrigan, reachable only through the `etrigan` subcommand
(POSIX only — `os.fork`, `os.setsid`, `SIGHUP`).

| Aspect | Behaviour | Evidence |
| --- | --- | --- |
| `daemonize()` | fork #1 → `os.chdir('/')` + `os.setsid()` + `os.umask(0o22)` → fork #2 → write pidfile → `os.dup2` stdio onto `os.devnull` → install SIGINT/SIGTERM → `handle_terminate`, SIGHUP → `handle_reload` | `py-kms/Etrigan.py:184`, `:214`, `:230`, `:108`–`:116` |
| Headless daemon target | `funcs_to_daemonize = [ServerWithoutGui().start, ServerWithoutGui().join]`, `pause_loop = None` (one-shot) | `py-kms/pykms_Server.py:399`–`:402` |
| GUI daemon target | with `-g`, `funcs_to_daemonize = [server_with_gui]` and the config pickle is skipped | `py-kms/pykms_Server.py:396`–`:397` |
| `start` | pickles the whole `srv_config` to `<tempdir>/pykms_config.pickle` | `py-kms/pykms_Server.py:381`–`:383` |
| `stop` | unpickles and merges the config back, deletes the pickle, then loops `os.kill(pid, SIGTERM); sleep(0.1)` until ESRCH | `py-kms/pykms_Server.py:384`–`:388`, `:404`, `py-kms/Etrigan.py:343` |
| `restart` | stop, `sleep(pause_restart)` = 5 s, start | `py-kms/Etrigan.py:371`, `:115` |
| `status` | reads the pidfile then opens `/proc/<pid>/status` — **Linux-only** | `py-kms/Etrigan.py:384`, `:396` |
| `reload` | accepted choice, **literal no-op** (`def reload(self): pass`); the SIGHUP handler only sets `self.etrigan_reload = True`, which nothing reads | `py-kms/Etrigan.py:381`, `:136` |
| Stale-PID detection | `os.kill(pid, 0)` with ESRCH/EPERM handling; deletes the stale file | `py-kms/Etrigan.py:284` |
| Argument guard | for stop/restart/status, `len(sys.argv[1:]) > 2` is fatal — so exactly `pykms_Server.py etrigan stop` is allowed and all paths must come from the pickle | `py-kms/pykms_Server.py:370`–`:372` |
| Dead demo code | `jasonblood_func()` appends to `./etrigan_test.txt`; `main()` is unreachable when imported | `py-kms/Etrigan.py:518`, `:589` |

### 4.12 Custom argv validator

Before argparse runs, `kms_parser_check_optionals` pre-screens `sys.argv`
(`py-kms/pykms_Misc.py:382`, `py-kms/pykms_Server.py:301`). It rejects:

- unknown `-x` tokens → "unrecognized optional/positional py-kms server arguments";
- **GNU-style abbreviations** (`--logf` for `--logfile`) → "abbreviation not allowed for `--logfile`";
- **repeated options** (`-V INFO -V DEBUG`) → "`-V` appears several times";
- options given too many values.

Exemptions: `-F/--logfile` is exempt from the length check (`exclude_kms`); `-n`, `--listen`, `-b`,
`--backlog`, `-u`, `--no-reuse` are exempt from the duplicate check (`exclude_dup`)
(`py-kms/pykms_Server.py:301`–`:302`).

Side effect: **any value starting with `-` is rejected as an unknown option**, so `-c -1` fails with
"unrecognized optional py-kms server arguments: `-1`".

Custom help: `add_help=False` on the real parsers; a manual `-h/--help` action plus a pre-scan of
argv means `-h` anywhere prints the main help, then the `etrigan` sub-help, then the `connect`
sub-help, separated by 80 asterisks (`py-kms/pykms_Server.py:286`, `py-kms/pykms_Misc.py:328`).
So `pykms_Server.py etrigan -h` prints the entire combined help.

### 4.13 Packaging and deployment

| Artefact | Status | Notes |
| --- | --- | --- |
| `setup.py` / `pyproject.toml` / wheel | **absent** | no packaging metadata of any kind |
| PyInstaller / py2exe / cx_Freeze | **absent** | only `.gitignore` boilerplate reserving `*.spec`/`*.manifest` (`.gitignore:16`–`:38`) |
| Docker "full" image (`python3` tag) | **shipped** | Alpine 3.12; 4 Dockerfiles (amd64, arm32v6, arm32v7, arm64v8) + `start.sh` (`docker/docker-py3-kms/Dockerfile.amd64:1`–`:41`) |
| Docker "minimal" image (`minimal` **and** `latest` tags) | **shipped** | Alpine 3.12; shell-form ENTRYPOINT, no `start.sh` (`docker/docker-py3-kms-minimal/Dockerfile.amd64:1`–`:36`) |
| Docker Compose file | **absent from the tree** | documentation-only example at `docs/Getting Started.md:38`–`:59` |
| systemd unit | **absent from the tree** | copy-paste recipe at `docs/Getting Started.md:80`–`:101` (`Type=simple`, `Restart=always`, `RestartSec=1`, `KillMode=process`, `User=root`, `After=network.target`, `StartLimitIntervalSec=0`, `-V DEBUG`) |
| Upstart `.conf` | **absent from the tree**, marked deprecated | recipe at `docs/Getting Started.md:107`–`:121` |
| Windows service wrapper | **absent from the tree** | pywin32 `kms-winservice.py` template at `docs/Getting Started.md:123`–`:166`, plus NSSM / Task Scheduler suggestions |
| `HEALTHCHECK` / `USER` / `VOLUME` / `LABEL` | **absent from every Dockerfile** | everything runs as root; the SQLite DB path is covered by no documented volume |

**Multi-arch build mechanism.** Non-amd64 Dockerfiles use a two-stage build: stage 1
(`FROM alpine AS builder`) downloads a balena `qemu-4.0.0.balena2` static tarball; stage 2
(`FROM arm32v6|arm32v7|arm64v8/alpine:3.12`) does `COPY --from=builder qemu-*-static /usr/bin`.
Docker Hub autobuild hooks register binfmt (`hooks/pre_build`) and publish manifests with
`estesp/manifest-tool` v1.0.2 (`hooks/post_push`). Both images build **from a `git clone` of GitHub
master at build time**, not from the local build context (`docker/docker-py3-kms/Dockerfile.amd64:27`).

**Documentation set.** Sphinx 3.1.2 + recommonmark + sphinx_markdown_tables (`docs/conf.py:31`),
`html_theme = 'default'`, published to readthedocs. Pages: `index.rst`, `readme.md` and
`changelog.md` (symlinks to the root files), `Getting Started.md` (226 lines),
`Usage.md` (294 lines — the full CLI reference and Docker ENV table), `Documentation.md` (173 lines
— KMS theory, `slmgr.vbs`/`ospp.vbs` tables), `Keys.md` (389 lines of GVLKs),
`Troubleshooting.md` (26 lines), `Contributing.md`. Six screenshots in `docs/img` — all of
slmgr/ospp, **none of the GUI**. `docs/requirements.txt` is a 44-package pip-freeze of the doc-build
venv, unrelated to py-kms's own runtime.

---

## 5. Complete option reference

### 5.1 `pykms_Server.py` — main parser

Defaults come from the `srv_options` dictionary at `py-kms/pykms_Server.py:187`–`:225`; the argparse
declarations are at `py-kms/pykms_Server.py:229`–`:258`.

| Option | argparse | Type / choices | Default | Semantics |
| --- | --- | --- | --- | --- |
| `ip` (positional 1) | `nargs='?'`, `store` | `str` | `0.0.0.0` | Bind address of the primary listener. **Must be an IPv4 or IPv6 literal** — `MultipleListener` calls `ipaddress.ip_address()` to choose the address family (`py-kms/pykms_Connect.py:102`), so hostnames are fatal ("… does not appear to be an IPv4 or IPv6 address. Exiting..."). |
| `port` (positional 2) | `nargs='?'`, `store` | `int` | `1688` | TCP port of the primary listener. Validated 1..65535 by `check_setup` (`py-kms/pykms_Misc.py:554`). Also what `bind_ack` advertises as `SecondaryAddr`. |
| `-e`, `--epid` | `store` | `str` | `None` | Literal ePID returned in every response, encoded UTF-16LE. **No length, field-count or charset validation.** When unset an ePID is synthesized per request (`py-kms/pykms_Base.py:221`). |
| `-l`, `--lcid` | `store` | `int` | `1033` | LCID used as part 6 of generated ePIDs. Validated against a **158-entry** `ValidLcid` allowlist copied from vlmcsd's `kms.c` (`py-kms/pykms_Misc.py:279`–`:297`); an invalid or falsy value is auto-fixed with a WARNING. Ignored entirely when `-e` is given. |
| `-c`, `--client-count` | `store` | **`type=str`**, int-coerced later by `check_other` | `None` | Reported KMS client count; semantics table in §4.6. Negative values are rejected by the custom argv pre-parser; **`0` crashes the handler** (§7.3). The literal string `None` is mapped back to `None` by `proper_none()` (`py-kms/pykms_Misc.py:516`). |
| `-a`, `--activation-interval` | `store` | `int` | `120` | `vLActivationInterval` in minutes. **No range validation** in terminal mode (only int-coerced under the GUI — `py-kms/pykms_Server.py:465`). |
| `-r`, `--renewal-interval` | `store` | `int` | `10080` (`1440 * 7`) | `vLRenewalInterval` in minutes. Same lack of validation. |
| `-s`, `--sqlite` | `nargs='?'`, `const=True` | `str` | `False` (disabled); bare `-s` → `./pykms_database.db` | Per-client request logging into SQLite. A supplied path must have a `.db` extension **and an existing directory component** (`check_dir`, `py-kms/pykms_Misc.py:230`). Silently downgraded to `False` with a WARNING if the `sqlite3` module is missing (`py-kms/pykms_Server.py:454`). |
| `-w`, `--hwid` | `store` | `str` | `364F463A8863D35F` | 8-byte HWID for V6 responses. 16 hex chars, optional lowercase `0x` prefix, or the literal `RANDOM` (case-sensitive) → `uuid.uuid4().hex[:16]` chosen once at start. Validation at `py-kms/pykms_Server.py:412`–`:442`. |
| `-t0`, `--timeout-idle` | `store` | `str`, int-coerced | `None` | Documented as a per-client inactivity timeout; **actually a server lifetime timer that exits the process** (§7.6). |
| `-t1`, `--timeout-sndrcv` | `store` | `str`, int-coerced | `None` | Genuine per-connection `settimeout()` applied to each accepted socket (`py-kms/pykms_Server.py:582`). On expiry, `socket.timeout` is caught as `socket.error`, logged "While receiving: timed out" at ERROR, and the connection closes. |
| `-y`, `--async-msg` | `store_true` | flag | `False` | Wraps every log handler in `MultiProcessingLogHandler` and sets `ShellMessage.asyncmsgsrv`. |
| `-V`, `--loglevel` | `store`, `choices` | `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`, `MININFO` | `ERROR` | Sets the level on the logger and every handler. MININFO = 25, i.e. **above** INFO. |
| `-F`, `--logfile` | `nargs='+'` (1 or 2; >2 fatal) | magic token and/or path | `./pykms_logserver.log` | See the token table below. |
| `-S`, `--logsize` | `store` | `float` | `0` (rotation disabled) | `maxBytes = int(logsize * 1024 * 512)`, `backupCount = 1`. Documented as MB, **actually 0.5 MiB per unit** (§7.6). |
| `-h`, `--help` | manual `help` action + argv pre-scan | flag | — | Prints main + `etrigan` + `connect` help, separated by 80 asterisks, then exits. |

`-F` / `--logfile` token semantics (`py-kms/pykms_Misc.py:161`–`:182`, `py-kms/pykms_Misc.py:542`;
mirrors the table at `docs/Usage.md:97`–`:104`):

| Invocation | Colorized stdout handler | Rotating file handler | Pretty-printer channel |
| --- | --- | --- | --- |
| `-F <path>` (anything not a magic token) | off | on (`<path>`) | **on** |
| `-F STDOUT` | on | off | off |
| `-F FILESTDOUT [<path>]` | on | on | off |
| `-F STDOUTOFF [<path>]` | off | on | off |
| `-F FILEOFF` | off | `FileHandler(os.devnull)` | **on** |

For `FILESTDOUT` and `STDOUTOFF`, if only the token is given the default `./pykms_logserver.log` is
appended automatically. The **token must come first** — `logger_create` indexes `config['logfile'][1]`
for the path, so `-F ./mylog.log FILESTDOUT` fails with "invalid directory: 'FILESTDOUT'".

### 5.2 `connect` subparser

Enabled by the literal word `connect` in argv, after the positionals and main options
(`py-kms/pykms_Server.py:270`–`:281`). `srv_config['mode']` becomes `connect`, or
`etrigan+connect` / `connect+etrigan` when both subcommands are used.

| Option | argparse | Default | Semantics |
| --- | --- | --- | --- |
| `-n`, `--listen <IP,PORT>` | `action='append'`, `type=str` | `[]` | Adds an extra listening socket. Format is a single comma-separated string, no space. A missing comma → "not well defined"; a non-integer or out-of-range port → "port number … is invalid. Enter between 1 - 65535" (`py-kms/pykms_Server.py:470`–`:490`). Like `ip`, must be a numeric literal. Repeatable. |
| `-b`, `--backlog <N>` | `action='append'`, `type=int` | `5` | `socket.listen()` backlog. **Positionally associated** with the `-n` couples: a `-b` placed immediately after `connect` (before any `-n`) sets `backlog_main` for the primary address and becomes the default for every subsequent `-n` without its own `-b`; a `-b` after a given `-n` applies to that couple (`py-kms/pykms_Misc.py:452`–`:512`). The worked examples at `docs/Usage.md:128`–`:137` were verified accurate. |
| `-u`, `--no-reuse` | `action='append_const'`, `const=False` | reuse **True** | Presence **disables** `SO_REUSEPORT` for the address it is positionally attached to (same pairing rules as `-b`). Note `SO_REUSEADDR` is still set unconditionally on non-Windows (`py-kms/pykms_Connect.py:54`), so `-u` does not prevent rebinding on Linux. |
| `-d`, `--dual` | `store_true` | `False` | Applies **globally** to every address. On an AF_INET6 socket, clears `IPV6_V6ONLY`. Without it, `IPV6_V6ONLY` is explicitly **set to 1**. IPv4 addresses are collected into `cant_dual` and reported. |

`socketserver`'s own `request_queue_size` is never used — `listen()` is called inside
`create_server_sock` (`py-kms/pykms_Connect.py:74`–`:77`).

### 5.3 `etrigan` subparser

Enabled by the literal word `etrigan` (`py-kms/pykms_Server.py:261`–`:267`,
`py-kms/Etrigan.py:522`–`:546`). POSIX only.

| Option | argparse | Type / choices | Default | Semantics |
| --- | --- | --- | --- | --- |
| `operation` (positional, **required**) | `store`, `choices` | `start`, `stop`, `restart`, `status`, `reload` | — | Dispatched by `Etrigan_job()`, which always ends in `sys.exit(0)` (`py-kms/Etrigan.py:574`–`:587`). `reload` is a no-op; `status` is Linux-only. |
| `-g`, `--gui` | `store_const`, `const=True` | flag | `False` | Runs the Tkinter GUI as the daemonized function and skips the config-pickle round-trip. **Only exists under `etrigan`** — there is no `-g` on the plain server parser. |
| `--etrigan-pid <PATH>` | `store` | `str` | `/tmp/etrigan.pid` | PID file. Must end in `.pid` and live in an existing directory (`Etrigan_check.checkfile`, `py-kms/Etrigan.py:553`). Made absolute; removal registered with `atexit`. A commented-out `/var/run/etrigan.pid` sits beside the default (`py-kms/Etrigan.py:535`). |
| `--etrigan-log <PATH>` | `store` | `str` | `./etrigan.log` | Daemon-side log (separate logger `logdaemon`, format `[%(asctime)s] [%(levelname)8s] --- %(message)s`, datefmt `%Y-%m-%d %H:%M:%S`, `py-kms/Etrigan.py:142`). Must end in `.log`. Contains fork/pidfile tracing only — the KMS request log still goes to `-F`. |
| `--etrigan-lev <LEVEL>` | `store`, `choices` | `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG` (**no MININFO**) | `DEBUG` | Level for the daemon logger. |
| `--etrigan-mute` | `store_const`, `const=True` | flag | `False` | Suppresses all stdout/stderr from the daemonizer (messages still reach the etrigan log). See §7.8 for its interaction bug with `emit_error`. |

Non-CLI Etrigan constants: `pause_restart = 5` s, `umask = 0o22`, `homedir = '/'`
(`py-kms/Etrigan.py:108`–`:116`) — none exposed.

### 5.4 `pykms_Client.py`

Defaults from `clt_options` at `py-kms/pykms_Client.py:52`–`:75`; argparse at `:78`–`:103`.

| Option | argparse | Type / choices | Default | Semantics |
| --- | --- | --- | --- | --- |
| `ip` (positional 1) | `nargs='?'`, `store` | `str` | `0.0.0.0` | KMS server to connect to. Passed to `socket.create_connection()`. Hostnames **are** accepted here (unlike the server's bind address). |
| `port` (positional 2) | `nargs='?'`, `store` | `int` | `1688` | Validated 1..65535 by `check_setup`. |
| `-m`, `--mode` | `store`, `choices` | `WindowsVista`, `Windows7`, `Windows8`, `Windows8.1`, `Windows10`, `Office2010`, `Office2013`, `Office2016`, `Office2019` | `Windows8.1` | Product to impersonate; resolution table in §4.9. |
| `-c`, `--cmid` | `store` | `str` | `None` | Client Machine ID GUID. Validated with `uuid.UUID()` (lenient — accepts `urn:`, braces, undashed hex). If unset, a fresh `uuid.uuid4()` is generated per run (`py-kms/pykms_Client.py:126`–`:132`). |
| `-n`, `--name` | `store` | `str` | `None` | Machine name. Must be UTF-16LE-encodable and 2..63 characters (the help says "ASCII", the check does not). If unset, a random name of `random.randint(2,63)` characters from `ascii_letters + digits` (`py-kms/pykms_Client.py:134`–`:147`). |
| `-t0`, `--timeout-idle` | `store` | `str`, int-coerced | `None` | Connect timeout for `socket.create_connection()`. On expiry: "Client connection timed out. Exiting..." |
| `-t1`, `--timeout-sndrcv` | `store` | `str`, int-coerced | `None` | `clt_sock.settimeout()` after connect. |
| `-y`, `--async-msg` | `store_true` | flag | `False` | Sets `ShellMessage.asyncmsgclt` and wraps log handlers. |
| `-V`, `--loglevel` | `store`, `choices` | same six as the server | `ERROR` | Logger name is `logclt`. At the default, essentially nothing is printed except the pretty-printer arrows — ePID/HWID/count/intervals are INFO. |
| `-F`, `--logfile` | `nargs='+'` | same tokens as the server | `./pykms_logclient.log` | Same semantics. |
| `-S`, `--logsize` | `store` | `float` | `0` | Same 0.5-MiB-per-unit bug. |
| `-h`, `--help` | manual + argv pre-scan | flag | — | Prints the client help and exits. |

### 5.5 Docker environment variables

**No Python code reads `os.environ` anywhere.** The environment layer exists only in the Docker
shell wrappers.

| ENV | Full image (`python3`) default | Minimal image (`minimal`/`latest`) default | Mapped to | Evidence |
| --- | --- | --- | --- | --- |
| `IP` | `0.0.0.0` | `0.0.0.0` | positional 1; also `sqlite_web -H` and the self-activation client target | `docker/docker-py3-kms/Dockerfile.amd64:3`, `docker/docker-py3-kms/start.sh:9` |
| `PORT` | `1688` | `1688` | positional 2; also baked into `EXPOSE ${PORT}/tcp` at **build** time | `docker/docker-py3-kms/Dockerfile.amd64:4`, `:39` |
| `EPID` | `""` | `""` (**declared but never referenced**) | `-e ${EPID}`, only when non-empty | `docker/docker-py3-kms/start.sh:5`, `docker/docker-py3-kms-minimal/Dockerfile.amd64:7`, `:36` |
| `LCID` | `1033` | `1033` | `-l ${LCID}` (always) | `docker/docker-py3-kms/Dockerfile.amd64:6` |
| `CLIENT_COUNT` | `26` | `26` | `-c ${CLIENT_COUNT}` (always) | `docker/docker-py3-kms/Dockerfile.amd64:7` |
| `ACTIVATION_INTERVAL` | `120` | `120` | `-a ${ACTIVATION_INTERVAL}` | `docker/docker-py3-kms/Dockerfile.amd64:8` |
| `RENEWAL_INTERVAL` | `10080` | `10080` | `-r ${RENEWAL_INTERVAL}` | `docker/docker-py3-kms/Dockerfile.amd64:9` |
| `SQLITE` | `false` | **not declared** | if `!= "false"` exactly: adds `-s ${PWD}/pykms_database.db`, backgrounds the server, `sleep 5`, fires one `pykms_Client.py -m Windows10`, then runs `sqlite_web` in the foreground | `docker/docker-py3-kms/Dockerfile.amd64:10`, `docker/docker-py3-kms/start.sh:3`, `:26`–`:29` |
| `HWID` | `"364F463A8863D35F"` | **`"RANDOM"`** | `-w ${HWID}` | `docker/docker-py3-kms/Dockerfile.amd64:11`, `docker/docker-py3-kms-minimal/Dockerfile.amd64:12` |
| `LOGLEVEL` | `ERROR` | **`INFO`** | `-V ${LOGLEVEL}` | `docker/docker-py3-kms/Dockerfile.amd64:12`, `docker/docker-py3-kms-minimal/Dockerfile.amd64:13` |
| `LOGFILE` | `/var/log/pykms_logserver.log` | same | `-F ${LOGFILE}` | `docker/docker-py3-kms/Dockerfile.amd64:13` |
| `LOGSIZE` | `""` | `""` (**declared but never referenced**) | `-S ${LOGSIZE}`, only when non-empty | `docker/docker-py3-kms/start.sh:7`, `docker/docker-py3-kms-minimal/Dockerfile.amd64:15` |

**No ENV exists** for `-t0`, `-t1`, `-y`, or any `connect` (`-n`/`-b`/`-u`/`-d`) or `etrigan`
option — those are unreachable from a stock container without overriding the entrypoint.

Volumes are by convention only (no `VOLUME` instruction anywhere):
`-v /etc/localtime:/etc/localtime:ro` and `-v /var/log:/var/log:rw`
(`docker/docker-py3-kms/run-py3-kms.sh:13`–`:14`, `docs/Getting Started.md:56`–`:58`).

### 5.6 Optional module dependencies

| Module | Effect when present | Effect when absent | Evidence |
| --- | --- | --- | --- |
| `sqlite3` (stdlib) | `-s/--sqlite` works | `-s` is downgraded to `False` with a WARNING at startup | `py-kms/pykms_Sql.py:6`–`:10`, `py-kms/pykms_Server.py:454` |
| `tzlocal` + `pytz` | logged "Request Time" is localized (incorrectly — §7.9) | WARNING "Module 'tzlocal' not available !" on **every request**, naive UTC | `py-kms/pykms_Base.py:120`–`:134` |
| `tkinter` | GUI available (auto-selected on non-TTY stdout, or `etrigan start -g`) | ImportError caught by the bare `except:` → silent fallback to the CLI | `py-kms/pykms_Server.py:565`, `:641` |
| `Pillow` (PIL) | keys background image + four animated GIF navigation widgets | `except ImportError` fallback: flat lavender fill, plain `<<`/`>>` text buttons. **Documented nowhere and installed by no Dockerfile** | `py-kms/pykms_GuiMisc.py:298`–`:334`, `:441`–`:449` |

---

## 6. Product coverage (`py-kms/KmsDataBase.xml`)

### 6.1 Database shape

Root: `<KmsData Version="1.7" Author="Hotbird64" xsi:noNamespaceSchemaLocation="KmsDataBase.xsd">`
(`py-kms/KmsDataBase.xml:74`) with exactly three children: `<WinBuilds>`, `<CsvlkItems>`,
`<AppItems>`. Lines 1–71 are a documentation comment block (containing sample elements that
ElementTree never sees). The referenced `KmsDataBase.xsd` is **not shipped**. The file path is
hardcoded to `os.path.join(os.path.dirname(__file__), 'KmsDataBase.xml')` — no CLI flag, no
environment variable, no override hook (`py-kms/pykms_DB2Dict.py:9`).

Verified counts (parsed directly from the shipped file):

| Section | Count |
| --- | --- |
| `WinBuild` records | 18 live (2 more, NT 3.1 build 528 and NT 3.5 build 807, commented out with "LM refuses 3-digit build numbers") |
| `CsvlkItem` records | 49, with 308 `<Activate>` children total |
| `AppItem` records | 3 |
| `KmsItem` records | 40 |
| `SkuItem` records | 296 (**287 unique Ids**) |
| SkuItems with `Gvlk=""` | 66 (230 distinct GVLKs) |
| SkuItems with `IsGeneratedGvlk="true"` | 8 |
| CsvlkItems with `GroupId=""`/`MinKeyId=""`/`MaxKeyId=""` | **13** (all `[Pre-Release]`) |
| CsvlkItems with `InvalidWinBuild=""` | 3 |
| CsvlkItems with a pre-baked `EPid=` attribute | 6 |
| CsvlkItems with `VlmcsdIndex` | 6 |

### 6.2 WinBuilds

| Build | DisplayName | PlatformId | `WinBuildIndex` | `MinDate` | `UsesNDR64` |
| --- | --- | --- | --- | --- | --- |
| 1057 | Windows NT 3.51 | 55041 | — | — | — |
| 1381 | Windows NT 4.0 | 55041 | — | — | — |
| 2195 | Windows 2000 | 55041 | — | — | — |
| 2600 | Windows XP 32-bit | 55041 | — | — | — |
| 3790 | Windows Server 2003 / XP 64-bit | 55041 | — | — | — |
| 6000 | Vista / Server 2008 (no SP) | 55041 | — | — | — |
| 6001 | Vista / Server 2008 SP1 | 55041 | — | — | — |
| **6002** | Vista / Server 2008 SP2 | 55041 | **0** | 26/5/2009 | — |
| 7600 | Windows 7 / 2008 R2 (no SP) | 55041 | — | — | — |
| **7601** | Windows 7 / 2008 R2 SP1 | 55041 | **1** | 22/02/2011 | — |
| **9200** | Windows 8 / Server 2012 | 5426 | **2** | 04/09/2012 | true |
| **9600** | Windows 8.1 / Server 2012 R2 | 6401 | **3** | 17/10/2013 | true |
| 10240 | Windows 10 1507 | 3612 | — | — | true |
| **14393** | Windows 10 1607 / Server 2016 | 3612 | **4** | 12/10/2016 | true |
| 15063 | Windows 10 1703 | 3612 | — | 11/04/2017 | true |
| 16299 | Windows 10 1709 | 3612 | — | — | true |
| 17134 | Windows 10 1803 | 3612 | — | — | true |
| **17763** | Windows 10 1809 / Server 2019 | 3612 | **5** | 02/10/2018 | true |

Only the six bold rows can be selected as an ePID host build. Build 15063 has a `MinDate` but no
`WinBuildIndex`, so it can never be picked by index. `UseForEpid` is present on exactly those six
rows and is **never read by any code** — `pykms_PidGenerator` keys off the presence of
`WinBuildIndex` instead (they happen to coincide).

### 6.3 AppItems / KmsItems

| AppItem | Id | `MinActiveClients` | KmsItems |
| --- | --- | --- | --- |
| Windows | `55c92734-d682-4d71-983e-d6ec3f16059f` | 50 | 35 |
| Office 14 (2010) | `59a52881-a989-479d-af46-f275c6370663` | 10 | 1 (21 SKUs) |
| Office 15 (2013) / 16 (2016) / 17 (2019) | `0ff1ce15-a989-479d-af46-f275c6370663` | 10 | 4 |

Production (non-preview) KmsItems, with protocol version and `NCountPolicy`:

| KmsItem | Id | Proto | N | SKUs |
| --- | --- | --- | --- | --- |
| Windows Vista | `212a64dc-43b1-4d3d-a30c-2fc69d2095c6` | 4.0 | 25 | 4 |
| Windows 7 | `7fde5219-fbfa-484a-82c9-34d1ad53e856` | 4.0 | 25 | 9 |
| Windows Server 2008 A (Web and HPC) | `33e156e4-b76f-4a52-9f91-f641dd95ac48` | 4.0 | 5 | 2 |
| Windows Server 2008 B (Std and Ent) | `8fe53387-3087-4447-8985-f75132215ac9` | 4.0 | 5 | 4 |
| Windows Server 2008 C (DC and Itanium) | `8a21fdf3-cbc5-44eb-83f3-fe284e6680a7` | 4.0 | 5 | 3 |
| Windows Server 2008 R2 A | `0fc6ccaf-ff0e-4fae-9d08-4370785bf7ed` | 4.0 | 5 | 3 |
| Windows Server 2008 R2 B | `ca87f5b6-cd46-40c0-b06d-8ecd57a4373f` | 4.0 | 5 | 2 |
| Windows Server 2008 R2 C | `b2ca2689-a9a8-42d7-938d-cf8e9f201958` | 4.0 | 5 | 2 |
| Windows 8 (Volume) | `3c40b358-5948-45af-923b-53d21fcc7e79` | 5.0 | 25 | 8 |
| Windows 8 (Retail) | `bbb97b3b-8ca4-4a28-9717-89fabd42c4ac` | 5.0 | 25 | 11 |
| Windows Server 2012 | `8665cb71-468c-4aa3-a337-cb9bc9d5eaac` | 5.0 | 5 | 4 |
| Windows 8.1 (Volume) | `cb8fc780-2c05-495a-9710-85afffc904d7` | 6.0 | 25 | 11 |
| Windows 8.1 (Retail) | `6d646890-3606-461a-86ab-598bb84ace82` | 6.0 | 25 | 8 |
| Windows Server 2012 R2 | `8456efd3-0c04-4089-8740-5b7238535a65` | 6.0 | 5 | 5 |
| Windows 10 2015 (Volume) | `58e2134f-8e11-4d17-9cb2-91069c151148` | 6.0 | 25 | **36** |
| Windows 10 (Retail) | `e1c51358-fe3e-4203-a4a2-3b6b20c9734e` | 6.0 | 25 | 9 |
| Windows 10 2016 (Volume) | `969fe3c0-a3ec-491a-9f25-423605deb365` | 6.0 | 25 | 2 |
| Windows 10 2019 (Volume) | `11b15659-e603-4cf1-9c1f-f0ec01b81888` | 6.0 | 25 | 2 |
| Windows 10 Unknown (Volume) | `d27cd636-1962-44e9-8b4f-27b6c23efb85` | 6.0 | 25 | **0** |
| Windows 10 China Government | `7ba0bf23-d0f5-4072-91d9-d55af5a481b6` | 6.0 | 25 | 2 |
| Windows Server 2016 | `6e9fc069-257d-4bc4-b4a7-750514d32743` | 6.0 | 5 | 10 |
| Windows Server 2019 | `8449b1fb-f0ea-497a-99ab-66ca96e9a0f5` | 6.0 | 5 | 9 |
| Office 2010 | `e85af946-2e25-47b7-83e1-bebcebeac611` | 4.0 | 5 | 21 |
| Office 2013 | `e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0` | 5.0 | 5 | 19 |
| Office 2016 | `85b5f61b-320b-4be3-814a-b76b2bfafc82` | 6.0 | 5 | 23 |
| Office 2019 | `617d9eb1-ef36-4f82-86e0-a65ae07b96c6` | 6.0 | 5 | 13 |

Plus **14** preview/pre-release KmsItems (Windows Preview, Windows Server Preview, Windows Vista
Preview, three Longhorn Server Preview groups, Windows 7 Client Preview, three Windows 7 Server
Preview groups, Windows Next Education Preview, Windows Next Preview 1, Windows Next Preview 2,
Office 2013 Preview), most with placeholder GUIDs of the form
`0N000000-0000-0000-0000-000000000000`. 26 + 14 = the 40 `KmsItem` records counted above.

CSVLKs carrying a `VlmcsdIndex` (the six "canonical" host keys):

| Index | DisplayName | GroupId | Key range | `InvalidWinBuild` |
| --- | --- | --- | --- | --- |
| 0 | Windows Server 2019 | 206 | 551000000–570999999 | `[0,1,2]` |
| 1 | Office 2010 | 96 | 199000000–217999999 | `[]` |
| 2 | Office 2013 | 206 | 234000000–255999999 | `[]` |
| 3 | Office 2016 | 206 | 437000000–458999999 | `[0]` |
| 4 | Windows 10 China Government | 3858 | 15000000–999999999 | `[0,1,2]` |
| 5 | Office 2019 | 206 | 666000000–685999999 | `[0,1]` |

### 6.4 Newest products covered

| Family | Newest entry present |
| --- | --- |
| Windows client | **Windows 10 1809** (build 17763) — KmsItem "Windows 10 2019 (Volume)", CSVLK "Windows 10 2019" (GroupId 206, 256000000–265999999) |
| Windows server | **Windows Server 2019** (`8449b1fb-…`, 9 SKUs) |
| Office | **Office 2019** (`617d9eb1-…`, 13 SKUs) |
| LTSC | **Windows 10 Enterprise LTSC 2019** and **LTSC 2019 N** only (`py-kms/KmsDataBase.xml:576`–`:577`) |

### 6.5 What is NOT supported

Verified by grepping both `py-kms/KmsDataBase.xml` and `docs/Keys.md` for the product names
*Windows 11*, *Server 2022*, *Server 2025*, *Office 2021*, *Office 2024*, *LTSC 2021*, *LTSC 2024*
and for the build numbers *22000*, *22621*, *22631*, *26100*, *20348* — **zero hits in either file**:

- Windows 11 — **all** versions, all builds (21H2 through 24H2 and later)
- Windows Server 2022 (build 20348)
- Windows Server 2025 (build 26100)
- Windows 10 1903, 1909, 2004, 20H2, 21H1, 21H2, 22H2 and their CSVLKs
- Windows 10/11 Enterprise LTSC 2021 and LTSC 2024
- Windows 11 IoT Enterprise
- Office 2021 / Office LTSC 2021
- Office 2024 / Office LTSC 2024
- Windows Server Azure Editions

Consequence for a Windows 11 or Server 2022 client: it sends an unknown `skuId` and an unknown
`kmsCountedId`. The SKU/App name lookup at `py-kms/pykms_Base.py:170`–`:186` leaves `skuName` or
`appName` **unbound** → `UnboundLocalError` → the connection is silently dropped by the no-op
`handle_error` (§7.3). The `epidGenerator` fallback would otherwise have produced a Windows Server
2019 ePID anyway.

Note that `README.md:19`–`:20` claims support for "Windows 10 ( 1903 / 1909 / 20H1 )". There is no
data for those releases in `KmsDataBase.xml` (newest build 17763); in practice 1903+ clients still
activate because they reuse the Windows 10 2019 counted ID, but the claim is not backed by database
entries.

### 6.6 GVLK keys

GVLK data lives in **two places that are never cross-checked**:

1. `py-kms/KmsDataBase.xml` — a `Gvlk` attribute on all 296 SkuItems (66 empty, 230 distinct keys),
   8 flagged `IsGeneratedGvlk="true"` (Windows 10 Enterprise/Professional [Preview], Windows 8.1
   Professional Student and Student N, and the four Windows 8.1 Core Connected variants).
   **No Python code ever reads the `Gvlk` attribute** — it is inert data.
2. `docs/Keys.md` — a hand-maintained 389-line Markdown table, ~300 product rows under 18 headings
   (Windows Server 2019/2016, Windows 10, Server 2012 R2, Windows 8.1, Server 2012, Windows 8,
   Server 2008 R2, Windows 7, Server 2008, Windows Vista, Windows Previews; then Office 2019, 2016,
   2013, 2010). Rows are `| Product | \`KEY\` |` with alternatives separated by `<br>`.

The user workflow is entirely manual: read `docs/Keys.md`, copy the key, run `slmgr /ipk <key>` or
`ospp.vbs` on the target as described in `docs/Documentation.md:54`–`:66`. `docs/Keys.md` explicitly
warns that "py-kms will not reject any of your keys" — correct, because the KMS protocol carries
only the `skuId`/`appId`/`kmsCountedId` GUIDs, never the key itself.

### 6.7 Data in the XML that no code reads

Parsed into the runtime dicts by `kmsDB2Dict()` and referenced by **zero lines of Python**:
`Gvlk`, `IsGeneratedGvlk`, `IsRetail`, `IsPreview`, `CanMapToDefaultCsvlk`, `MinActiveClients`,
`VlmcsdIndex`, `IniFileName`, `IsLab`, `EPid`, `UseForEpid`, `MayBeServer`, `UsesNDR64`.
In particular the six pre-baked `EPid=` values (e.g.
`06401-00206-566-174993-03-1033-9600.0000-2802018`) are never used — py-kms always synthesizes or
takes `-e`; and the `IsPreview`/`IsRetail` flags that would let the server refuse non-KMS-activatable
products are ignored.

---

## 7. Gaps, quirks, and doc/code mismatches

### 7.1 Guaranteed crash: unknown KMS protocol version

`kmsRequestUnknown.executeRequestLogic()` builds the correct MS error envelope — NDR
`DataLength=0`, `DataSizeMax=0`, then `SL_E_VL_KEY_MANAGEMENT_SERVICE_ID_MISMATCH` (0xC004F042) —
and then does `finalResponse.decode('utf-8').encode('utf-8')` (`py-kms/pykms_RequestUnknown.py:16`).

The 12 raw bytes are `00 00 00 00 00 00 00 00 42 F0 04 C0`. `0xF0 0x04` is not valid UTF-8, so this
line raises `UnicodeDecodeError` **100 % of the time** (verified: "'utf-8' codec can't decode byte
0xf0 in position 9: invalid continuation byte"). The exception reaches the no-op `handle_error`, so
any request with `versionMajor ∉ {4,5,6}` yields a dropped connection with **no response and no log
entry** instead of the intended error envelope.

### 7.2 Cryptography implementation issues

| Issue | Detail | Evidence |
| --- | --- | --- |
| **Thread-shared mutable AES instance** | `AESModeOfOperation.aes = AES()` is a **class** attribute evaluated once at import, so every instance in the process shares one cipher object. V5 and V6 handlers mutate it with `moo.aes.v6 = self.v6` on every request. Under `ThreadingMixIn`, a concurrent V5 request can flip `v6` to `False` mid-V6-encryption, producing ciphertext with a mix of tweaked and untweaked rounds. Symptom: intermittent activation failures on mixed-version workloads (Office 2010 = v4/v5, Windows 8+/Office 2013+ = v6). `kmsRequestV4.generateHash` is immune because it constructs a fresh `AES()`. | `py-kms/pykms_Aes.py:461`, `py-kms/pykms_RequestV5.py:88`, `py-kms/pykms_RequestV6.py:66`, `py-kms/pykms_RequestV4.py:69` |
| **Key schedule recomputed per block** | `AES.encrypt()`/`AES.decrypt()` call `expandKey()` on **every** 16-byte block. A 256-byte CBC operation performs 16 full key expansions plus 16 block operations. Measured ≈ 12.9 ms to decrypt and ≈ 12.6 ms to encrypt 256 bytes; a full V5/V6 exchange costs ~25–30 ms of pure-Python CPU. With the GIL this serialises to tens of activations per second per core. | `py-kms/pykms_Aes.py:398`, `:448` |
| **Not constant time** | `galois_multiplication` branches on `hi_bit_set = a & 0x80` with data-dependent `a`; SubBytes/InvSubBytes are data-indexed table lookups. Harmless here because both KMS keys are published Microsoft constants, but the module must not be reused for real secrets. | `py-kms/pykms_Aes.py:211` |
| **Non-CSPRNG salts** | `getRandomSalt()` uses `random.getrandbits(8)` (Mersenne Twister) for both the V5/V6 `randomSalt` (whose SHA-256 is *published* in every response) and the V6 response IV `SaltS`. The one place `os.urandom(16)` appears (`py-kms/pykms_Aes.py:675`) is dead code never reached from a KMS path. | `py-kms/pykms_RequestV5.py:130` |
| **Unvalidated PKCS7 strip** | `strip_PKCS7_padding` never checks that the padding bytes equal the pad length, and a trailing `0x00` makes `val[:-0]` return an **empty** result rather than the full plaintext (verified: `b'A'*15 + b'\x00'` → `b''`). `b'A'*13 + b'\x01\x02\x03'` returns 13 bytes with no error. There is no integrity check on inbound V5/V6 data at all — V6's HMAC is response-only. | `py-kms/pykms_Aes.py:28` |
| **No length check in the cipher** | `AES.decrypt`/`encrypt` index `iput[i*4+j]` with no bounds check, so ciphertext whose length is not a multiple of 16 raises `IndexError` deep inside the cipher. Reachable via `RequestV5.Message`'s trailing `':'` padding field, which absorbs any trailing bytes and feeds them to the CBC decryptor. | `py-kms/pykms_Aes.py:445` |
| **No crypto backend choice** | Not a bug per se, but note vlmcsd has three interchangeable compile-time backends (OpenSSL, Windows CNG, internal) and can use AES-NI; py-kms has exactly one, always. | `py-kms/pykms_Aes.py:19` |

### 7.3 Crash paths that produce silent connection drops

All of these are invisible at every log level because `handle_error()` is `pass`
(`py-kms/pykms_Server.py:129`).

| Trigger | Failure | Evidence |
| --- | --- | --- |
| `versionMajor ∉ {4,5,6}` | `UnicodeDecodeError` (§7.1) | `py-kms/pykms_RequestUnknown.py:16` |
| `-c 0` (and only 0) | `currentClientCount` never bound → `UnboundLocalError`. `0` fails `0 < cc`, fails `MinClients <= cc`, and fails `cc >= RequiredClients`. `check_other()` only verifies the value is int-able and does **not** reject 0 | `py-kms/pykms_Base.py:140`–`:159`, `py-kms/pykms_Misc.py:559` |
| `skuId` or `applicationId` that is a valid GUID but absent from the XML | `skuName`/`appName` never bound → `UnboundLocalError` at `infoDict` construction. The `except:` fallbacks are unreachable because `uuid.UUID()` never raises for the well-formed GUIDs in the file. **This is exactly the path a Windows 11 / Server 2022 / Office 2021 client takes** | `py-kms/pykms_Base.py:170`–`:188` |
| Any transfer syntax not in the 3-entry `preparedResponses` dict | bare `KeyError` on the dict index; there is no `bind_nak` path at all | `py-kms/pykms_RpcBind.py:121` |
| BTFN GUID with different feature bits | per MS-RPCE only the first 8 bytes identify BTFN and the remainder encodes requested features; py-kms requires an **exact** GUID match, so any other feature combination is a `KeyError` | `py-kms/pykms_RpcBind.py:18`, `:116`, `:121` |
| Truncated / garbage PDU | `struct.error` from `MSRPCHeader` or the KMS structs. There is no minimum-length check on the KMS envelope, so anything shorter than 12 bytes raises before dispatch | `py-kms/pykms_Base.py:246` |
| Client FILETIME out of range | `datetime.utcfromtimestamp` raises `OSError`/`ValueError`/`OverflowError` | `py-kms/pykms_Filetimes.py:96` |
| `tzlocal >= 3` installed | `AttributeError` (§7.9) | `py-kms/pykms_Base.py:126` |
| Machine name longer than 126 bytes | `_mnPad` computes `'126-len(machineName)'` → negative unpack size → silent mis-parse rather than a clean rejection | `py-kms/pykms_Base.py:50` |
| Ciphertext not a multiple of 16 | `IndexError` inside AES (§7.2) | `py-kms/pykms_Aes.py:445` |
| Any `sqlite3.Error` | `pretty_printer(to_exit=True)` → `sys.exit(1)` **from inside a worker thread**, which kills only that thread and silently drops that client's activation while the server keeps running | `py-kms/pykms_Sql.py:29`, `:70`, `:93` |

### 7.4 ePID generator: fallback-in-loop bias, and a hard Python-3.12 failure

**Bias.** The CSVLK loop appends the Windows Server 2019 fallback tuple
`('206','551000000','570999999','[0,1,2]')` for **every non-matching** `CsvlkItem`, then does
`random.choice` over the whole 49-entry list (`py-kms/pykms_PidGenerator.py:20`–`:31`). With
typically 1–3 real matches, the fallback wins overwhelmingly. Measured over 5,000 generations for
Office 2010: the correct GroupId 96 appeared **113 times (2.3 %)**; GroupId 206 (Server 2019)
appeared 4,887 times (97.7 %). The build loop has the same shape — 12 of 18 `WinBuild`s lack
`WinBuildIndex` and hit the `KeyError` fallback — so build 17763 appears in ~86 % of ePIDs
(exact odds for `InvalidWinBuild=[0,1,2]`: 13/15 = 86.7 %). **The successor fork made this worse,
not better:** its v2.0 database dropped `WinBuildIndex` from all 30 `WinBuild` rows while
`pykms_PidGenerator.py:42` still keys on it, so every row hits the fallback and the Organization
fork emits 17763 in 100 % of ePIDs (see `py-kms-forks.md` §8). Net effect: py-kms advertises a Windows
Server 2019 group-206 ePID with a Server 2019 build for essentially every product, **including
Office 2010 and Windows Vista**, and can emit impossible combinations (GroupId 00096 with
BuildNumber 17763 was observed 35/5000 times). vlmcsd picks the CSVLK that actually activates the
requested product.

**Latent `ValueError`.** 13 CsvlkItems have `GroupId=""`/`MinKeyId=""`/`MaxKeyId=""`. If the
requested `kmsCountedId` is activated by one of them and `random.choice` picks it,
`int('')` at `py-kms/pykms_PidGenerator.py:32` raises `ValueError`. Measured failure rates over
3,000 runs each: Windows Vista Preview 8.2 %, Windows 7 Server Preview (Web) 6.7 %, Office 2013
Preview 2.0 %. Three CsvlkItems also have `InvalidWinBuild=""`, on which `literal_eval('')` raises
`SyntaxError` on the same line. The `except IndexError` at `:27` catches neither and is dead code.

**Python ≥ 3.12 hard failure.** `py-kms/pykms_PidGenerator.py:62` calls
`random.randint(time.mktime(...), time.mktime(...))`. `time.mktime()` returns a **float**, and
`random.randrange` stopped accepting non-integers in Python 3.12 →
`TypeError: 'float' object cannot be interpreted as an integer`. Reproduced on CPython 3.13. Because
this runs inside the request thread and `handle_error` is a no-op, **every activation silently
fails unless `-e/--epid` is supplied**. Works on ≤ 3.9; 3.10/3.11 emit a DeprecationWarning.

**Other ePID quirks**: the day-of-year is computed with `time.mktime` on **local** time (DST-sensitive)
and is **zero-based** (Jan 1 → `000`); Part 6 (LCID) is emitted **unpadded** via `str(languageCode)`,
unlike every other field; `licenseChannel` is hardcoded to 3; the `version` argument is ignored.

### 7.5 Performance

- `kmsDB2Dict()` re-parses the 88 KB `KmsDataBase.xml` **from disk on every request** — once in
  `serverLogic()` (`py-kms/pykms_Base.py:163`) and a second time inside `epidGenerator()`
  (`py-kms/pykms_PidGenerator.py:14`) when no `-e` is set. Measured ≈ 1.75 ms per parse on CPython
  3.13, so ≈ 4 ms of pure XML parsing per activation, with zero caching. Setting `-e` halves it.
- `sql_initialize()` runs its `isfile()` + `CREATE TABLE` check on every request rather than once at
  startup (`py-kms/pykms_Base.py:211`), and each activation opens three separate SQLite connections.
- Pure-Python AES adds ~25–30 ms per V5/V6 exchange (§7.2); V4 additionally sleeps a full second.
- The `Structure` DSL's `__len__` re-serialises the whole structure via `getData()`, giving
  quadratic behaviour on nested structures (`py-kms/pykms_Structure.py:295`).

### 7.6 Documentation vs code mismatches

| Doc claim | Reality | Evidence |
| --- | --- | --- |
| `docs/Usage.md:10` — "`ip <IPADDRESS>` … (can be an hostname too)" | **False.** The address goes to `ipaddress.ip_address()` to pick the address family, so a hostname is fatal: "'localhost' does not appear to be an IPv4 or IPv6 address. Exiting..." Same restriction on `connect -n HOST,PORT`. (The *client* `ip` positional does accept hostnames.) | `py-kms/pykms_Connect.py:102`, `py-kms/pykms_Server.py:64` |
| `docs/Usage.md:61` — `-t0` is a "maximum inactivity time … after which the connection with the client is closed" | **False on two counts.** It is `KeyServer.timeout`; the deadline is computed **once** before the accept loop and is **never rearmed on activity**; and expiry calls `handle_timeout()` which logs "Server connection timed out. Exiting..." and **terminates the whole process**. Reproduced with `-t0 6` plus a client at t+3 s: the server still exited. It is effectively an upper bound on total server lifetime. | `py-kms/pykms_Server.py:87`, `:101`–`:105`, `:125`–`:127` |
| `docs/Usage.md:107`, `:195`, `:248` and the `-S` help — "maximum size (in MB)" | **False.** `maxBytes = int(logsize * 1024 * 512)` = 524,288 bytes = **0.5 MiB per unit**. `-S 2` rotates at 1 MiB. `backupCount` is fixed at 1. Same on the client. | `py-kms/pykms_Misc.py:169`, `:179` |
| `README.md:41` — "If you have a IPv6-capable dual-stack OS, a dual-stack socket is created when using a IPv6 address" | **False for the default invocation.** `dual` defaults to `False`, and the code then explicitly sets `IPV6_V6ONLY = 1`, defeating even the Linux default. Dual-stack requires `connect -d`, which `README.md` never mentions. | `py-kms/pykms_Connect.py:63`–`:67`, `py-kms/pykms_Server.py:223` |
| `docs/Usage.md:97`–`:104` `-F` table, "logging msg" column | Ambiguous — the column means "logging **to stdout**". With a plain `-F <logfile>`, logging *is* active, it just goes to the file. The table also omits that `-F STDOUT` emits raw ANSI escapes even when stdout is not a TTY. | `py-kms/pykms_Misc.py:161`–`:182`, `:217` |
| `docs/Usage.md:197`–`:249` presents one ENV block for "the Dockerfile(s)" | The minimal/`latest` image has **different defaults** (`HWID=RANDOM`, `LOGLEVEL=INFO`), does not declare `SQLITE` at all, and its shell-form ENTRYPOINT never passes `-e`, `-s` or `-S` — so `EPID`, `SQLITE` and `LOGSIZE` are silently ignored there. `docs/Usage.md:239` also omits `MININFO` from the valid loglevel list although the code accepts it. | `docker/docker-py3-kms-minimal/Dockerfile.amd64:5`–`:15`, `:36` |
| `docs/Getting Started.md:38`–`:59` compose example sets `SQLITE=true` and `LOGSIZE=2` on `pykmsorg/py-kms:latest` | `latest` **is** the minimal image, which understands neither variable. The example silently does nothing for both. | `docker/docker-py3-kms-minimal/multi-arch-manifest-latest.yaml:1` |
| `docs/Usage.md:154` — the client `ip` parameter "is always required" | It is `nargs='?'` with default `0.0.0.0` — optional. (On Linux, connecting to `0.0.0.0` resolves to loopback, so the default happens to work for a local server.) | `py-kms/pykms_Client.py:53`, `:79` |
| `CHANGELOG.md:10` — "py-kms Gui: now matches all cli options" | It does not. The GUI has no control for `-n/--listen`, `-b/--backlog`, `-u/--no-reuse` or `-d/--dual` (the whole `connect` subparser, which landed one release *later* in `py-kms_2020-10-01`), nor for any `etrigan` option. 15 of 19 `srv_options`; all 11 `clt_options`. | `py-kms/pykms_Server.py:219`–`:224`, `:269`–`:281` |
| `README.md:32`–`:35` feature list | "tested with Python 3.6.9" — no CI, no test suite, no `.github/` to verify. "Supports execution by Docker, systemd, Upstart and many more" — only Docker is implemented; systemd and Upstart are documentation snippets with no shipped unit/conf files. "Windows 10 ( 1903 / 1909 / 20H1 )" — not present as data anywhere. | `README.md`, `docs/Getting Started.md:80`, `:107` |
| `docs/Getting Started.md:137`, `:165` Windows service recipe | Hardcodes `C:\Windows\Python27\python.exe` and `C:\Windows\Python27\py-kms\pykms_Server.py` — **Python 2.7 paths** — for a project that is Python 3 only and whose CHANGELOG records the split away from py2-kms. | `docs/Getting Started.md:123`–`:166` |
| `docs/Getting Started.md:27` — "make sure to expose port 8080" | Port 8080 is never `EXPOSE`d in any Dockerfile; only `EXPOSE ${PORT}/tcp` (evaluated at build time, so always 1688) exists. | `docker/docker-py3-kms/Dockerfile.amd64:38` |

### 7.7 Undocumented constraints and UX surprises

- **File-path options are extension- and directory-checked.** `-F` must end in `.log`, `-s` in
  `.db`, `--etrigan-pid` in `.pid`, `--etrigan-log` in `.log`. A **bare filename with no directory
  component is rejected**, because `os.path.dirname('mylog.log') == ''` and `os.path.isdir('')` is
  `False`. So `-F mylog.log` fails with "argument `-F/--logfile`: invalid directory: mylog.log"
  while `-F ./mylog.log` works. Likewise `-s pykms_database.db` fails but `-s ./pykms_database.db`
  works — the bare `-s` default only works because it goes through `os.path.join('.', ...)`.
  (`py-kms/pykms_Misc.py:230`–`:248`, `py-kms/Etrigan.py:553`–`:561`)
- **`-F` magic tokens must come first** — see §5.1.
- **Any value beginning with `-` is rejected** by the custom pre-parser (`-c -1` →
  "unrecognized optional py-kms server arguments: `-1`"), and **abbreviations and duplicate options
  are hard errors** — behaviour that differs from stock argparse and is documented nowhere.
  (`py-kms/pykms_Misc.py:382`)
- **`-V MININFO` suppresses the startup banner.** MININFO is numerically 25, i.e. above INFO, so
  selecting it hides `TCP server listening at …` and `HWID: …` along with all other INFO output.
- **The Docker default `CLIENT_COUNT=26` is worse than omitting `-c`.** For a desktop product
  (MinClients = 25) it lands in the `MinClients <= count < 2*MinClients` band and logs
  "With count = 26, activated client could be detected as not genuine !" on **every** activation,
  whereas omitting `-c` reports 50 silently. (`py-kms/pykms_Base.py:147`)
- **Global peer address.** `setup()` stashes the peer in the process-global `srv_config['raddr']`
  (`py-kms/pykms_Server.py:579`), read later when emitting the MININFO record
  (`py-kms/pykms_Base.py:206`). Under concurrency the MININFO `host` column can name the wrong client.
- **Shared temp files.** The pretty-printer keeps newline bookkeeping in the fixed paths
  `<tempdir>/pykms_newlines.txt` and `<tempdir>/pykms_clean_newlines.txt`
  (`py-kms/pykms_Format.py:196`–`:197`) — two py-kms processes on the same host stomp on each other.
- **SQLite races.** `sql_initialize()`'s `isfile()` + `CREATE TABLE` and `sql_update()`'s
  SELECT-then-INSERT are both TOCTOU under the threading server. Two concurrent first-requests from
  the same CMID insert **two duplicate rows** (there is no PRIMARY KEY or UNIQUE constraint), or one
  gets "table clients already exists". If the DB file exists but lacks the `clients` table (a
  zero-byte file from a shell redirect or a Docker bind-mount), `sql_initialize()` skips creation and
  every request dies on "no such table: clients". (`py-kms/pykms_Sql.py:18`–`:41`)
- **`sql_update_epid()` dead code and no-op path**: it does `data = cur.fetchone()` and never uses
  the result, and it runs the UPDATE even when no matching row exists (`py-kms/pykms_Sql.py:88`).
  The conditional UPDATE of `applicationId` in `sql_update()` is a no-op by construction — the WHERE
  clause already pins `applicationId` to the new value (`py-kms/pykms_Sql.py:53`–`:55`).
- **Client logger cross-wiring.** `pykms_Client.py` configures the logger `logclt`, but
  `pykms_RpcBind.py`, `pykms_RpcRequest.py` and `pykms_RequestV4/V5/V6.py` all log through
  `logging.getLogger('logsrv')`. In the client process `logsrv` has no handlers, so
  `pykms_Client.py -V DEBUG -F file.log` does **not** capture the RPC bind / request-structure dumps
  into that file. (`py-kms/pykms_Client.py:49`, `py-kms/pykms_RpcBind.py:14`)

### 7.8 Etrigan / daemon issues

| Issue | Detail | Evidence |
| --- | --- | --- |
| **Unguarded `pickle.load` of a world-writable path** | `etrigan stop/status/restart` unpickles `<tempdir>/pykms_config.pickle` with no ownership or integrity check. On a shared host, any local user who can create that file gets **arbitrary code execution** as whoever runs the stop command. | `py-kms/pykms_Server.py:385`–`:386` |
| Missing-pickle traceback | `etrigan status`/`stop` with no prior `start` — or after a `stop`, which deletes the pickle — dies with a raw `FileNotFoundError` traceback. | `py-kms/pykms_Server.py:385`, `:404` |
| `-g` start breaks stop/status | With `-g`, `server_daemon()` skips the `pickle.dump` entirely, so a later `etrigan stop` tries to load a file that was never written. | `py-kms/pykms_Server.py:378`–`:388` |
| `emit_error` override bug | The py-kms subclass puts the `sys.exit` **inside** the `if not self.mute` block and hardcodes `to_exit=True` in the `pretty_printer` call. Consequences: (a) callers that request a *non-fatal* error — notably "A previous daemon process … Daemon already running ?" (`py-kms/Etrigan.py:330`) — exit(1) anyway; (b) `--etrigan-mute` turns every fatal error into a silent no-op that keeps going. | `py-kms/pykms_Server.py:362`–`:365` |
| `os.chdir('/')` after fork | Every relative path given to `-F ./x.log` or `-s ./x.db` (and relative paths are the only form that passes validation short of absolute ones) resolves against `/` after daemonizing, not the invocation directory. | `py-kms/Etrigan.py:233` |
| `reload` is a no-op | Accepted as a choice; `def reload(self): pass`. The SIGHUP handler only sets `self.etrigan_reload = True`, which nothing reads. | `py-kms/Etrigan.py:381`, `:136` |
| `status` is Linux-only | Stats `/proc/<pid>/status`; on macOS/FreeBSD it reports "There is not a process with the PIDFILE …" even for a live daemon. | `py-kms/Etrigan.py:396` |
| "too much arguments" guard | For stop/restart/status, more than two argv entries is fatal — so `etrigan status --etrigan-pid ./e.pid` is rejected and all paths must come from the pickle. | `py-kms/pykms_Server.py:370` |

### 7.9 Python and dependency version breakage

| Issue | Detail | Evidence |
| --- | --- | --- |
| **Python ≥ 3.10: total import failure** | `from collections import Sequence` (removed in 3.10). `pykms_Server.py:27` imports `Etrigan` unconditionally at module scope, so even `python3 pykms_Server.py -h` dies with `ImportError`. Verified against CPython 3.13. | `py-kms/Etrigan.py:12`, `py-kms/pykms_Server.py:27` |
| **Python ≥ 3.11** | `Etrigan.py:412` uses `inspect.getargspec` (removed in 3.11). `pykms_Server.py:635` uses the deprecated `setDaemon()`. | `py-kms/Etrigan.py:412`, `py-kms/pykms_Server.py:635` |
| **Python ≥ 3.12: every auto-ePID activation fails** | See §7.4. `-e` is the only workaround. | `py-kms/pykms_PidGenerator.py:62` |
| **Python ≥ 3.12 deprecations** | `datetime.utcfromtimestamp` (`py-kms/pykms_Filetimes.py:96`) and `datetime.utcnow()` (`py-kms/pykms_Client.py:307`) are deprecated. | as cited |
| **`tzlocal` ≥ 3: every activation fails** | `py-kms/pykms_Base.py:126` calls `tz.localize(dt)`, a **pytz-only** API. `tzlocal` ≥ 3 returns a `zoneinfo.ZoneInfo`, which has no `.localize()`. The resulting `AttributeError` is caught by neither the `except UnknownTimeZoneError` nor the `except ImportError` around it — so the request thread dies silently. Both Docker images `pip3 install tzlocal` unpinned. | `py-kms/pykms_Base.py:120`–`:134`, `docker/docker-py3-kms/Dockerfile.amd64:33` |
| **`tzlocal` localization is wrong even when it works** | `filetime_to_dt()` returns a **naive UTC** datetime; pytz's `localize()` attaches the local zone to the same wall-clock digits, so the logged "Request Time" is the UTC instant mislabelled with the local offset. | `py-kms/pykms_Base.py:118`, `:126` |
| **Pillow ≥ 10: GUI startup broken** | `py-kms/pykms_GuiMisc.py:305` calls `Image.ANTIALIAS`, removed in Pillow 10, and the surrounding `try` catches only `ImportError` (`:327`), so the `AttributeError` escapes `custom_background()` and kills `gui_complete()`. Combined with the bare `except:` at `py-kms/pykms_Server.py:644`, the observable symptom is "the GUI silently doesn't appear and the CLI starts instead". Separately, that same line's `img.resize(...)` return value is **discarded**, so the resize was always a no-op. | `py-kms/pykms_GuiMisc.py:305`, `:327` |
| **Windows startup likely broken** | Port reuse defaults to ON and is implemented with `SO_REUSEPORT`, which CPython does not expose on Windows. `create_server_sock` raises `ValueError('SO_REUSEPORT not supported on this platform')` before `bind()`, which `KeyServer.__init__` turns into a fatal exit. Starting on Windows appears to require `connect -u`. (Deduced from the code path; not executed on Windows.) | `py-kms/pykms_Connect.py:34`–`:35`, `py-kms/pykms_Server.py:53` |

### 7.10 GUI issues

- **Two unbounded busy-wait loops on the Tk main thread**: `while not serverthread.is_running_server: pass`
  (`py-kms/pykms_GuiBase.py:726`) and `while serverthread.is_running_server: pass` (`:771`). If the
  server thread raises before flipping the flag — which is what `server_thread.run` does when it
  re-raises a non-`SystemExit` exception (`py-kms/pykms_Server.py:176`–`:180`) — the GUI spins at
  100 % CPU forever. Two more `pass` spin loops exist in the animation code
  (`py-kms/pykms_GuiMisc.py:367`, `:419`).
- **stderr redirection targets the wrong widget.** `TextRedirect.Stderr.write` picks a widget via
  `textbox_choose()` but then unconditionally writes into `self.srv_text_space`
  (`py-kms/pykms_GuiMisc.py:227`–`:233`). In client-side mode the server pane is `grid_remove()`d, so
  tracebacks go to an invisible widget.
- **SQLite path entry self-concatenates.** `sql_status()` inserts the default path at `'end'` with
  no preceding `delete` (`py-kms/pykms_GuiBase.py:465`). Ticking and unticking the checkbox N times
  yields `./pykms_database.db` repeated N times, passed verbatim to `-s` on the next start.
- **Fields display the literal string `'None'`** — EPID, Client Count, both server timeouts, client
  CMID, client Machine Name, both client timeouts are inserted as `str(None)`. This only works
  because `proper_none()` maps the string `'None'` back to Python `None` during `check_setup`
  (`py-kms/pykms_Misc.py:516`). Client Count and CMID have **no input validation at all**, unlike
  Port/LCID/Activation/Renewal (digits) and Logsize (float).
- **Hardcoded font names.** The layout assumes `'Fixedsys'`, `'Times'`, `'Monospace'`
  (`py-kms/pykms_GuiBase.py:75`–`:80`), and `TextRedirect.Pretty.textbox_format` computes padding
  from `xfont.measure('0')` assuming fixed width — alignment degrades silently under a proportional
  substitute.
- **The GUI is undocumented.** `docs/` contains no GUI page, no GUI screenshot (`docs/img` holds only
  slmgr/ospp images), and no mention of the Preferences server-side/client-side modes, the page-flip
  navigation, the DEFAULTS/CLEAR buttons, the disabled window close button, or the Pillow dependency.
  `README.md:44` ("chmod +x and double-click") is the only GUI instruction in the project.

### 7.11 Docker and packaging issues

- **The SQLite check is an exact string comparison**: `[ "$SQLITE" == false ]`
  (`docker/docker-py3-kms/start.sh:3`). Any other value — `False`, `FALSE`, `0`, `no`, unset, or a
  typo — enables SQLite mode, starts sqlite-web on 8080 and fires a self-activation client.
- **In SQLite mode the container's foreground process is sqlite-web, not the KMS server.** The server
  is launched detached inside `bash -c '… &'`, so if it crashes PID 1 keeps running, `docker ps` still
  shows the container up, and `--restart unless-stopped` never triggers. With no `HEALTHCHECK` in any
  Dockerfile, nothing catches this. (`docker/docker-py3-kms/start.sh:26`–`:29`)
- **The image self-seeds its database.** Every `SQLITE=true` branch runs
  `pykms_Client.py ${IP} ${PORT} -m Windows10 &` five seconds after boot, so a fresh container always
  contains one synthetic Windows 10 Enterprise activation row that no real client produced.
- **The database is at `${PWD}/pykms_database.db` = `/home/py-kms/pykms_database.db`**, which no
  documented volume covers (the docs mount only `/etc/localtime` and `/var/log`). Recreating the
  container loses all activation history — defeating the point of enabling SQLite.
- **The Dockerfiles `git clone` GitHub master at build time** instead of `COPY`ing the local build
  context (`docker/docker-py3-kms/Dockerfile.amd64:27`–`:28`). Building this repo's Dockerfile does
  not build this repo's code; builds are non-reproducible and silently ignore local changes. Same for
  the vendored `coleifer/sqlite-web` clone, which is pinned to nothing.
- **`start.sh`'s eight branches have drifted.** Three use `/bin/bash -c`, the fourth (`SQLITE` on,
  `EPID` set, `LOGSIZE` set) uses `/bin/sh -c` (`docker/docker-py3-kms/start.sh:44`). All variable
  expansions are unquoted throughout, so any value containing whitespace word-splits into extra argv
  entries — and py-kms's own `kms_parser_check_optionals` treats unrecognized extra words as **fatal**.
- **The minimal image installs what it doesn't use.** Its stated premise is "without SQLite support
  to further reduce image size" (`docker/docker-py3-kms-minimal/Dockerfile.amd64:1`), yet it installs
  `python3-tkinter`, `sqlite-libs`, `py3-flask`, `py3-pygments` and pip-installs `peewee` — none of
  which it uses. It also installs `py3-argparse`, redundant since argparse entered the stdlib in 3.2.
- **Build-helper / manifest naming mismatch.** `docker/docker-py3-kms/build-py3-kms.sh` tags the
  image `pykms/pykms:py3-kms`, which does not match the `pykmsorg/py-kms:python3-*` names the
  multi-arch manifests expect (`docker/docker-py3-kms/multi-arch-manifest-python3.yaml`).
- **The publishing pipeline is dead.** `hooks/pre_build` and `hooks/post_push` depend on Docker Hub's
  automated-build service (retired), on `multiarch/qemu-user-static:register`, and on a
  network-downloaded `manifest-tool` v1.0.2 at push time. They predate `docker buildx`.
- **The systemd recipe runs as root with no hardening directives** and uses `-V DEBUG` rather than the
  code default `ERROR` (`docs/Getting Started.md:80`–`:101`).

### 7.12 Behavioural fingerprints (how py-kms is distinguishable from a real KMS host)

| Fingerprint | Detail | Evidence |
| --- | --- | --- |
| **Fixed `assoc_group`** | `0x1063bf3f` in every `bind_ack` from every deployment. vlmcsd randomises it per process and increments per connection; Windows uses a real association-group id. This is the single most reliable network fingerprint. | `py-kms/pykms_RpcBind.py:104` |
| `PFC_CONC_MPX` always set | Flag 0x10 is set unconditionally even when the client never requested multiplexing, and `PFC_SUPPORT_HEADER_SIGN` is never echoed. vlmcsd copies the client's header flags verbatim. | `py-kms/pykms_RpcBind.py:96` |
| Forced disconnect after one activation | A real Windows KMS host keeps the connection open. | `py-kms/pykms_Server.py:621` |
| 1-second V4 delay | A real KMS host answers in single-digit milliseconds. | `py-kms/pykms_RequestV4.py:54` |
| Static default HWID | `364F463A8863D35F` on every stock deployment. (vlmcsd's default `3A1C049600B60076` is an equally static but *different* fingerprint, and vlmcsd additionally supports per-CSVLK HwIds.) | `py-kms/pykms_Server.py:205` |
| Unstable ePID | A new random ePID every response; real hosts have exactly one, stable for the host's lifetime. | `py-kms/pykms_Base.py:221` |
| Implausible ePIDs | Server-2019 group/build for Office 2010 and Vista (§7.4). | `py-kms/pykms_PidGenerator.py:20` |
| Hardcoded `frag_len` | `36 + ctx_num*24` is correct only for `SecondaryAddrLen` 3..6, i.e. ports 10..99999. A single-digit port produces a 32-byte packet advertised as 36. | `py-kms/pykms_RpcBind.py:98` |
| Wrong `SecondaryAddr` with multiple listeners | Always advertises the primary `port`, never the port the client actually connected to. vlmcsd derives it from `getsockname()`. | `py-kms/pykms_RpcBind.py:106` |
| Never rejects a bad interface | Any bind offering NDR32 is ACKed regardless of abstract syntax (§4.3). | `py-kms/pykms_RpcBind.py:119` |
| Never returns a fault or a non-zero HRESULT | §4.1, §7.1. | `py-kms/pykms_Base.py:107` |

### 7.13 `Structure` DSL limitations that bite in this codebase

1. **Two consecutive `':'` fields cannot both be unpacked** — the first swallows everything.
   `ResponseV5` declares both `encrypted ':'` and `padding ':'`, which is why the client strips
   padding by hand using `getPadding()` (`py-kms/pykms_RequestV5.py:120`, `py-kms/pykms_Structure.py:536`).
2. **`'u'` (UTF-16) lengths are inferred** by searching for `'\x00\x00'` and using the parity of the
   index. This only works because machine names and ePIDs are ASCII; a BMP character whose low byte
   is `0x00` mis-parses (`py-kms/pykms_Structure.py:526`).
3. **No bounds checking anywhere** — short data raises `struct.error`/`ValueError` rather than a
   clean rejection.
4. **`eval()` is used for both pack codes and unpack length codes** (`py-kms/pykms_Structure.py:221`,
   `:310`). The expressions are code literals, not attacker-controlled, but bare `except:` blocks
   around them silently mask type errors.
5. **Everything is carried as latin-1 `str`**, requiring `enco()`/`deco()`/`byterize()` conversions
   at every boundary (`py-kms/pykms_Format.py:14`–`:36`).
6. **`findLengthFieldFor`/`findAddressFieldFor` match by string *suffix***, so a field named `x`
   would collide with any format ending in `-x`.

### 7.14 Dead and vestigial code

- `pykms_Dcerpc.py`'s `SEC_TRAILER`, all `RPC_C_AUTHN_*` / `RPC_C_AUTHN_LEVEL_*` constants,
  `rpc_status_codes`, `rpc_provider_reason`, `rpc_cont_def_result`, and its own
  `CtxItem`/`CtxItemResult`/`MSRPCBind` (shadowed by different definitions in `pykms_RpcBind.py`).
- `MSRPCBindNak` — defined, parsed by the client, **never emitted by the server**.
- `pykms_Aes.encryptData()`/`decryptData()` and `generateRandomKey()` (`py-kms/pykms_Aes.py:675`,
  `:709`) — the only `os.urandom` users, never called from a KMS path.
- `Etrigan.jasonblood_func()` and `Etrigan.main()` (`py-kms/Etrigan.py:518`, `:589`) — demo code that
  appends to `./etrigan_test.txt`.
- `check_lcid`'s Windows `GetUserDefaultUILanguage()` and POSIX `locale.windows_locale` branches:
  the first test is `sys.implementation.name == 'cpython'` returning a hardcoded 1033, which
  short-circuits before either. The documented "use system default language" behaviour never happens
  on any normal interpreter (`py-kms/pykms_Misc.py:300`–`:317`).
- The `except IndexError` in the ePID CSVLK loop (`py-kms/pykms_PidGenerator.py:27`) catches nothing
  that can occur.
- `tkinter.messagebox` is imported by the GUI and never used.
- The `try/except` "Can't find a name for this product/application" fallbacks in `serverLogic()` are
  unreachable (§7.3).
- The 13 XML attribute families listed in §6.7.

---

## 8. Quick comparison to vlmcsd

Where the audits cross-checked py-kms behaviour against Wind4/vlmcsd (the C implementation), the
material differences are:

| Aspect | py-kms | vlmcsd |
| --- | --- | --- |
| Crypto backends | one, pure Python | three compile-time backends (OpenSSL / Windows CNG / internal), AES-NI capable |
| KMS minor-version check | none; echoed | rejects `minor != 0` (`src/rpc.c:216`) |
| Minimum request size check | none | per-version (`src/rpc.c:229`) |
| Unknown version HRESULT | `0xC004F042` (and crashes anyway) | `0x8007000D` = `HRESULT_FROM_WIN32(ERROR_INVALID_DATA)` (`src/rpc.c:281`) |
| `alter_context` | dropped as "Invalid RPC request type 14" | routed through rpcBind, replies `alter_context_resp` (`src/rpc.c:585`) |
| RPC faults / bind_nak | never emitted | `SendError()` with `nca_s_unk_if` / `nca_s_proto_error` (`src/rpc.c:230`) |
| Abstract syntax check | none | `IsEqualGUID(...)`, nacks with `RPC_ABSTRACTSYNTAX_UNSUPPORTED` (`src/rpc.c:507`) |
| `ctx_id` tracking | echoed unvalidated | per-connection NdrCtx/Ndr64Ctx, `nca_s_unk_if` otherwise (`src/rpc.c:259`) |
| BTFN feature bits | exact GUID match, hardcoded ack | compares first 8 bytes, echoes `requested & (MULTIPLEX\|KEEP_ORPHAN)` (`src/rpc.c:536`) |
| `assoc_group` | fixed `0x1063bf3f` | `rand32()` per process, incremented per connection (`src/network.c:1014`) |
| `SecondaryAddr` | always the primary configured port | derived from `getsockname()` (`src/rpc.c:450`) |
| Disconnect after activation | always | opt-in via `-d`, **default off** (`src/shared_globals.c:13`) |
| PDU reassembly | fixed `recv(1024)` | reads the 16-byte header, then exactly `FragLength-16` (`src/rpc.c:620`) |
| RPC return code | conflated with padding, always 0 | written explicitly (`src/rpc.c:327`) |
| Client counting | synthesized from the client's own field | can track up to 671 real CMIDs and return `0xC004D104` when exceeded (`src/kms.c:690`) |
| ePID CSVLK selection | biased fallback (~98 % Server 2019) | picks the CSVLK that actually activates the product |
| ePID length validation | none on `-e` | explicit `checkPidLength()` |
| V4 response latency | `sleep(1)` | none |
| Client-side verification | v4 MAC checked but silent on mismatch; v5/v6 unverified | `vlmcs` checks the MAC, the v5 IV equality and the v6 HMAC (`src/kms.c:1018`) |

---

## 9. Summary judgement

py-kms is a correct-on-the-wire, feature-rich KMS emulator with an unusually broad operator surface
for a single-file-per-concern Python project: three protocol versions, a threaded multi-listener TCP
server with IPv6/dual-stack control, six log levels with a custom compact activation record, an
optional SQLite client log, a full Tkinter GUI sharing the CLI's option model, a POSIX daemonizer, a
built-in protocol test client, and eight Docker images across two variants and four architectures.

Its practical problems are not protocol problems — the crypto is byte-for-byte compatible with
vlmcsd — but **operational** ones: a `handle_error` that is `pass` converts a dozen distinct crash
paths into indistinguishable connection resets; the product database has been frozen since 2019, so
every product from Windows 10 1903 / Windows 11 onward hits an `UnboundLocalError` in the SKU-name
lookup; the ePID generator emits a Windows Server 2019 identity ~98 % of the time regardless of
product and raises `TypeError` outright on Python ≥ 3.12; and the whole program fails to import on
Python ≥ 3.10. Anyone deploying this today should use
[`Py-KMS-Organization/py-kms`](https://github.com/Py-KMS-Organization/py-kms) (276 commits ahead)
rather than `SystemRage/py-kms@a3b0c85`.

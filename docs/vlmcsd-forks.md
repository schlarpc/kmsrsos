# vlmcsd — Fork Landscape

**Subject:** the fork network of `Wind4/vlmcsd`, compared against master `70e0357`
(2023-07-28, 31 commits, repository **archived**).
Citations of the form `src/kms.c:473` are relative to the vlmcsd repository root; the file is
upstream's unless a fork is named. Fork git refs use the convention `<owner>_<repo>/<branch>`.

---

## 1. Methodology

The full fork network was enumerated through the GitHub API rather than sampled:

| Step | Count |
|---|---|
| Forks reported by the API for `Wind4/vlmcsd` | **2486** |
| Forks actually listable | **2523** |
| Forks with *any* push after the fork point | **293** |
| Forks ahead of `Wind4/vlmcsd@master` by ≥ 1 commit | **92** |
| Forks whose commits touch source code at all | **16** |

Those 16 were added as remotes to a local clone of upstream, fetched in full, and diffed
against `origin/master`. Every branch of every one of the 16 was enumerated with
`git for-each-ref refs/remotes/<remote>` and examined, not just the default branch; `gh-pages`
branches were checked for merge base and content. Diffs were read at the hunk level, and every
binary `etc/vlmcsd.kmd` was decoded field-by-field against the on-disk structures in
`src/kms.h:239` (`CsvlkData`), `src/kms.h:281` (`VlmcsdData`), `src/kms.h:292` (`HostBuild`) and
`src/kms.h:308` (`VlmcsdHeader`) rather than judged by `strings` alone.

Two measurement caveats that materially change the numbers, and which this document applies
throughout:

- **Three-dot vs two-dot diffs.** `git diff A...B` shows the fork's work *plus* anything upstream
  merged after the fork's merge base. Three forks branched at `65228e5` (two commits behind
  `70e0357`): `LuoSimba/vlmcsd`, `simaek/vlmcsd`, `cnzhangquan/vlmcsd`. For those, the three-dot
  diff over-reports. All claims below use the two-dot tree difference (`git diff origin/master..<fork>`).
  This is not academic: it removes the *entire* headline change from one fork (§6.3).
- **Whitespace and file moves.** Several forks show thousands of changed lines that are pure
  CRLF→LF conversion, `#\t`→`#` preprocessor reindentation, or directory renames. Every diffstat
  below was re-run with `--ignore-all-space` before being called a change.

Fork positions relative to upstream:

| Fork | Merge base | Ahead | Behind | Branches |
|---|---|---|---|---|
| Mo7amedMostafa/vlmcsd | `70e0357` | 1 | 0 | master |
| kotfenix/vlmcsd | `70e0357` | 6 | 0 | master |
| LuoSimba/vlmcsd | `65228e5` | 75 (`dev`) | 2 | dev, master, gh-pages |
| gilberth/kmsvlmcsd | `70e0357` | 29 | 0 | master |
| jackyjkchen/vlmcsd | `70e0357` | 3 | 0 | master, gh-pages |
| KptCheeseWhiz/vlmcsd | `70e0357` | 2 | 0 | master |
| redneckdba/vlmcsd | `70e0357` | 2 | 0 | master |
| alexax66/vlmcsd | `70e0357` | 26 | 0 | master |
| lizhizhuanshu/vlmcsd | `70e0357` | 1 | 0 | master |
| yammelvin/vlmcsd | `70e0357` | 4 | 0 | master |
| yuri1313/vlmcsd | `70e0357` | 2 | 0 | master |
| simaek/vlmcsd | `65228e5` | 1 | 2 | master, gh-pages |
| TokyoBlackHole/vlmcsd | `70e0357` | 1 | 0 | master |
| dm764/vlmcsd | `70e0357` | 1 | 0 | master |
| kankerdev/vlmcsd | `70e0357` | 10 | 0 | master, gh-pages |
| cnzhangquan/vlmcsd | `65228e5` | 2 | 2 | master, gh-pages |

---

## 2. Headline finding

**This ecosystem is dead upstream and, in substance, unforked.**

Roughly 2500 of ~2520 forks are untouched snapshots — GitHub stars-with-extra-steps. Of the 293
that received any push at all, 92 diverge from upstream, and only **16** contain a change to any
file under `src/`, `etc/`, or the build system. Within those 16:

- **6 forks** contribute anything a reimplementation should care about.
- **The single most-copied change in the entire network is one line** — hoisting a stack buffer out
  of an `if` block in `getEpid()` (§7). Four unrelated forks re-derived it independently, none
  citing the others, none opening a pull request (upstream was archived before three of them
  existed).
- **One fork** (`kotfenix/vlmcsd`) is the only one that regenerated the *compiled-in* product
  database rather than just the loose `etc/vlmcsd.kmd` file, which is the difference between a
  binary that knows about Windows 11 24H2 and a binary that needs a data file deployed next to it.
- **Two forks** ship changes that are outright regressions presented as improvements
  (`redneckdba` §5.2, `gilberth` §6.1).
- **Zero forks** updated the man pages, and zero touched the protocol, the crypto, the RPC layer,
  or the client-count/HWID logic.

There is no maintained successor. The most recently active fork (`gilberth/kmsvlmcsd`,
2026-03-14) contains no working code change — its only C-level contribution is broken. The most
*useful* recent fork (`kotfenix/vlmcsd`, 2025-11-15) is a data drop by an author who has made six
commits total, four of which are "upload"/"remove submodules".

---

## 3. Summary of all 16 code-touching forks

Ordered by value to a reimplementation, most valuable first.

| Fork | Last push | Ahead | Verdict | What it is |
|---|---|---|---|---|
| [kotfenix/vlmcsd](#51-kotfenixvlmcsd--the-only-complete-database-refresh) | 2025-11-15 | 6 | substantive | The only complete modern KMS database refresh (Server 2022/2025, Win 11 24H2, Office LTSC 2021/2024) — external **and** embedded — plus two real C fixes |
| [redneckdba/vlmcsd](#52-redneckdbavlmcsd--newest-epids-broken-internal-fallback) | 2025-02-22 | 2 | substantive | Newest ePID set of any fork (host build 26100, day 321 of 2024) — but retypes the embedded database and breaks the internal fallback |
| [KptCheeseWhiz/vlmcsd](#53-kptcheesewhizvlmcsd--client-whitelisting-good-idea-unsafe-code) | 2023-12-01 | 2 | substantive | The only genuinely new *feature* in the network: `-Y` CIDR / `-y` hostname client whitelisting. Good idea, memory-unsafe implementation, IPv4-only |
| [kankerdev/vlmcsd](#54-kankerdevvlmcsd-and-alexax66vlmcsd--the-same-blob-twice) | 2024-04-19 | 10 | substantive | Origin of the "Visual Studio / SQL Server 2022 / SCCM / Office LTSC 2021" database blob; static link; scratch Docker image |
| [alexax66/vlmcsd](#54-kankerdevvlmcsd-and-alexax66vlmcsd--the-same-blob-twice) | 2024-09-16 | 26 | substantive | Same author re-committing kankerdev's exact `.kmd` bytes 8 months later, plus FreeBSD `rc.d` packaging and hardcoded `/usr/local/etc` paths |
| [yuri1313/vlmcsd](#55-yuri1313vlmcsd--earliest-office-ltsc-2021--server-2022-data) | 2023-11-29 | 2 | substantive | Earliest Office LTSC 2021 / Server 2022 data (2023); superseded by both later catalogs, and it drops four host-build names |
| [cnzhangquan/vlmcsd](#63-cnzhangquanvlmcsd--one-line-that-survives-scrutiny) | 2025-10-13 | 2 | substantive (1 line) | Adds the OpenVPN `root\tap0901` adapter ID to the Windows TAP whitelist. Its second commit is already upstream |
| [TokyoBlackHole/vlmcsd](#7-the-one-real-upstream-bug-fix-and-its-four-independent-discoverers) | 2024-05-16 | 1 | bugfix-only | First publication of the `getEpid()` dangling-pointer fix |
| [yammelvin/vlmcsd](#7-the-one-real-upstream-bug-fix-and-its-four-independent-discoverers) | 2024-09-19 | 4 | bugfix-only | Same one-line fix, re-derived; plus two GVLK text files and a 3-line run script |
| [dm764/vlmcsd](#7-the-one-real-upstream-bug-fix-and-its-four-independent-discoverers) | 2024-12-21 | 1 | bugfix-only | Byte-identical copy of the same one-line fix. Nothing else |
| [gilberth/kmsvlmcsd](#61-gilberthkmsvlmcsd--security-hardening-that-truncates-every-generated-epid) | 2026-03-14 | 29 | substantive but harmful | 4800 lines of Docker/Ubuntu/Spanish-docs packaging around a "security hardening" header whose macros take `sizeof()` of a pointer, truncating every randomized ePID to 7 characters |
| [LuoSimba/vlmcsd](#62-luosimbavlmcsd--subtractive-linux-only-rewrite) | 2021-03-14 | 75 | substantive but subtractive | Strips every non-Linux port, most compile-time switches, `vlmcsdmulti`, and `-V` platform output. −1827 net lines. No new capability |
| [jackyjkchen/vlmcsd](#64-jackyjkchenvlmcsd--deletes-the-openssl-backend-changes--os-to--o2) | 2024-05-01 | 3 | build-only | Deletes the OpenSSL/PolarSSL crypto backends; changes `-Os` → `-O2` for i686 gcc 3.x |
| [Mo7amedMostafa/vlmcsd](#8-nothing-of-substance) | 2024-09-06 | 1 | packaging-only | Whole tree moved into `vlmcsd/`, submodules flattened, plus an nginx TCP-stream sidecar with a hardcoded IP allowlist. 0 lines of C changed |
| [simaek/vlmcsd](#8-nothing-of-substance) | 2023-05-09 | 1 | packaging-only | RPM spec + systemd unit. Its `src/GNUmakefile` "change" is just being 2 commits behind |
| [lizhizhuanshu/vlmcsd](#8-nothing-of-substance) | 2024-11-13 | 1 | packaging-only | A 12-line systemd unit and a 6-line install script |

---

## 4. The KMS product database: what each catalog actually contains

Four forks ship a regenerated `etc/vlmcsd.kmd`. Because that file is a binary blob, the only
honest way to compare them is to decode the header (`src/kms.h:308`) and the arrays it points at.
Header layout: magic `KMD\0` at 0, version at 4, `CsvlkCount` at 8, `Counts[5]` at 12
(`AppItemCount`, `KmsItemCount`, `SkuItemCount`, `HostBuildCount`), `Datapointers[5]` at 32,
`CsvlkData[]` at 72 (32 bytes/entry).

| Source | Size | CSVLK groups | Apps | KMS IDs | SKUs | Host builds | Newest host build | ePID base | Embedded copy regenerated? |
|---|---|---|---|---|---|---|---|---|---|
| upstream `70e0357` | 15079 | 6 | 3 | 29 | 202 | 6 | 17763 | `9600.0000-2962018` | n/a |
| kotfenix | 19491 | **8** | 3 | **36** | **261** | **8** | **26100** | `17763.0000-2622024` | **yes** |
| redneckdba | 17646 | 8 | 3 | 35 | 234 | 8 | 26100 | **`26100.0000-3212024`** | no — and broken (§5.2) |
| kankerdev = alexax66 | 17651 | 7 | **6** | 36 | 233 | **3** ⚠ | 20348 | mixed 2021 | no |
| yuri1313 | 16419 | 8 | 3 | 32 | 219 | **5** ⚠ | 20348 | mixed 2021 | no |

⚠ = fewer host builds than upstream, i.e. a regression (see §5.4, §5.5).

**What a data update actually buys you, precisely.** It is easy to overstate this. Upstream's
default whitelisting level is `0` (`src/shared_globals.c:22`; `-K0`, `src/vlmcsd.c:1268`), and on
an unknown KMS ID `getProductIndex()` falls back to `KmsData->CsvlkData->EPid` — CSVLK group 0 —
and returns success (`src/kms.c:61`, `src/kms.c:594`, `src/kms.c:649`). So a stock, unmodified
vlmcsd **already activates** Windows 11 24H2 / Server 2025 / Office LTSC 2024 clients; it simply
answers with an ePID claiming to be a Server 2012 R2 KMS host from 2018 and logs the product as
`Unknown`. A refreshed database changes four things and no more:

1. The ePID handed back is plausible for the product and era (matters against emulator detection
   and against admins reading logs, not against the activation check itself).
2. `-K1`/`-K3` strict modes (`src/vlmcsd.c:1268`, `src/kms.c:622-640`) start working for new
   products instead of refusing them; likewise `-K2`'s retail/preview rejection.
3. Logs and `vlmcs -x` name the product instead of printing `Unknown`.
4. `HostBuildCount` feeds ePID randomization (`src/kms.c:289`, `src/kms.c:294`, `src/kms.c:390`),
   so a longer host-build list means more plausible variety — and a *shorter* one means less.

**Deployment nuance nobody but kotfenix handled.** `loadKmsData()` (`src/helpers.c:554`) points
`KmsData` at the compiled-in `DefaultKmsData[]` and only overwrites it if an external file is
found — by default `vlmcsd.kmd` next to the executable, or `/etc/vlmcsd.kmd` when the executable
path cannot be determined (`src/helpers.c:538-548`). A fork that updates only `etc/vlmcsd.kmd`
has changed nothing about the binary; the file must be installed next to the binary or passed
with `-j`. Only kotfenix regenerated `src/kmsdata.c` / `src/kmsdata-full.c` so that the binary
itself carries the new catalog.

---

## 5. Forks with substantive, useful changes

### 5.1 `kotfenix/vlmcsd` — the only complete database refresh

**Last push 2025-11-15 · 6 commits ahead · files touched: `etc/vlmcsd.kmd`, `src/kmsdata.c`,
`src/kmsdata-full.c`, `src/kms.c`, `src/vlmcs.c`, `src/GNUmakefile`**

The most valuable fork in the network, and the only one where the C changes and the data changes
were made by someone who understood how they interact.

**Database (commits `6f8a4b0`, `a53c8bc`).** `etc/vlmcsd.kmd` grows 15079 → 19491 bytes and both
embedded copies are regenerated to match — the embedded header now reads `CsvlkCount 0x08`,
`KmsItemCount 0x24` (36), `SkuItemCount 0x105` (261), `HostBuildCount 8`
(`kotfenix src/kmsdata.c:14-15`). Seven new KMS IDs: `Windows Server 2025`, `Windows Server 2022`,
`Windows 10 2024 (Volume)`, `Windows 10 2021 (Volume)`, `Windows 10 ServerRdsh (Volume)`,
`Office 2021`, `Office 2024`; `Windows 10 Unknown (Volume)` is renamed `Windows 10 (Volume)`.
The SKU table grows 202 → 261, adding the `Windows 10/11 …` unified naming, Enterprise LTSC
2019-2021-2024, IoT Enterprise LTSC 2021-2024, Enterprise multi-session, Windows 11 SE, the
Server 2022 and Server 2025 SKU families, and the complete Office LTSC 2021 and Office LTSC 2024
families.

**Two new CSVLK groups.** `CsvlkCount` 6 → 8. Group 6 (`Office2021`) covers key IDs
571000000-590999999 with default ePID `03612-00206-574-011017-03-1033-17763.0000-2622024`;
group 7 (`Office2024`) covers 591000000-610999999. Because CSVLK group names are the ini keys
enumerated when parsing per-product ePIDs, `Office2021 = <epid>` and `Office2024 = <epid>` become
valid `vlmcsd.ini` lines. Group 0 ("Windows") is also re-keyed: `GroupId` 206 → **4919**, key-ID
range 551000000-570999999 → **20000-20019999**, and every default ePID moves from platform
`06401` / build `9600.0000-2962018` to `03612` / `17763.0000-2622024`.

**Two new emulated host builds.** `HostBuildCount` 6 → 8, prepending
`Windows 11 24H2 / Server 2025` (build 26100, platform 3612, flags 7 = `UseNdr64|UseForEpid|MayBeServer`)
and `Windows Server 2022` (build 20348, platform 3612, flags 7). This is runtime-visible: the
default `HostBuild` is 0 (`src/shared_globals.c:107`), so vlmcsd picks a build at random per the
randomization level (`src/kms.c:289-296`, `src/kms.c:390-395`), and it widens what
`-H <build>` (`src/vlmcsd.c:1331`) / ini `HostBuild` accept under `_PEDANTIC`
(`IsValidHostBuild`, `src/kms.c:136`).

**Bug fix 1 — `getEpid()` use-after-scope (`0f0ffbb`).** The same one-line hoist described in §7.

**Bug fix 2 — `uint8_t` overflow in `vlmcs -x` (`a53c8bc`).** `showProducts()` computes
`int32_t items = KmsData->SkuItemCount` but stores the row count in `uint8_t lines` and iterates
with `uint8_t i` / `uint8_t j` (`src/vlmcs.c:239`, `src/vlmcs.c:256`, `src/vlmcs.c:263`). With 261
SKUs on a narrow terminal (`itemsPerLine == 1`), `lines = 261` truncates to 5 and the product
listing prints a handful of entries with wrong indices. Changed to `uint16_t`. This is latent in
upstream too — it only bites once `SkuItemCount` exceeds 255, which no upstream database does,
which is exactly why nobody else noticed it while shipping 233-SKU and 234-SKU catalogs.

**Build (`41bfcb3`).** `SERVERLDFLAGS` `` → `-static` (`src/GNUmakefile:165`), unconditionally.
Under glibc this breaks NSS, so DNS/`-L hostname` paths degrade. Not a default worth copying.

**Judgement: carry forward.** The database content, the CSVLK group definitions, the two new host
builds, and both C fixes are all correct and all worth having. This is the reference catalog for
SKU breadth. Take `redneckdba`'s ePID base (§5.2) if you want the newest-looking host build.
Do not copy the `-static` link flag.

### 5.2 `redneckdba/vlmcsd` — newest ePIDs, broken internal fallback

**Last push 2025-02-22 · 2 commits ahead**

**The good part (`75710a0`).** `etc/vlmcsd.kmd` 15079 → 17646 bytes with all eight CSVLK groups
re-based on host build **26100** released day **321 of 2024** — e.g.
`03612-04919-011-939794-03-1033-26100.0000-3212024`. That is the freshest ePID set in the entire
network; kotfenix's larger catalog still claims build 17763 in its stored defaults. 35 KMS IDs,
234 SKUs, 8 host builds including `Windows 11 24H2 / Server 2025` (26100) and
`Windows Server 2022` (20348). It also drops the stale `Office 2013 (Pre-Release)` KMS ID and
restores names upstream had lost.

**The bad part (`0c7a8cc`) — do not port.** `src/kmsdata.h:13`, all three `#ifdef` variants in
`src/kmsdata.c` (lines 12, 961, 1038) and `src/kmsdata-full.c:10` change
`uint8_t DefaultKmsData[]` to `uint16_t DefaultKmsData[]` while leaving the byte-valued
initializer list untouched. This does not fix alignment (the header cast needs 8-byte alignment
for its `uint64_t` members). It doubles the array in memory, interleaving a zero byte after every
data byte, and doubles `getDefaultKmsDataSize()`. Since `loadKmsData()` does
`KmsData = (PVlmcsdHeader_t)DefaultKmsData` (`src/helpers.c:556`) and validation does
`memcmp(KmsData->Magic, "KMD", …)` (`src/helpers.c:658`), the magic now reads `K\0M` and
`dataFileFormatError()` fires. A vlmcsd built from this tree **cannot fall back to its internal
catalog** and hard-requires an external `.kmd`. `src/kmsdata.c` is compiled into `vlmcsd`
unconditionally and `src/kmsdata-full.c` into `vlmcs`/`vlmcsdmulti`. To compound it, the embedded
arrays were never regenerated: they still contain the *old* 29-KMS-ID / 202-SKU data
(`KmsItemCount 0x1D`, `SkuItemCount 0xCA` at `redneckdba src/kmsdata.c:15`). So the fork
simultaneously left the internal database stale and made it unusable.

**Also present.** The `getEpid()` fix (§7); 96 lines of `src/helpers.c` churn that
`git diff -w` reduces to nothing (removal of the tab in `#\tifndef`); a *commented-out*
`INI_FILE`/`DATA_FILE` path edit at `src/config.h:64` and `src/config.h:78` that compiles to
nothing; a systemd unit; a 13-line `install.sh`; and two plain-text GVLK reference lists under
`keys/` that no code reads (`keys/windows-keys.md` is byte-identical to yammelvin's copy,
md5 `463eb2557dad382a87341ecd88436572` — a third-party list circulating between forks).

**Judgement: take the `.kmd` blob and the `getEpid()` fix; discard everything else.** In
particular the `uint16_t` retype is a functional regression dressed as a cleanup, and it is the
clearest example in this survey of why "the fork is newer" is not evidence of "the fork is better".

### 5.3 `KptCheeseWhiz/vlmcsd` — client whitelisting: good idea, unsafe code

**Last push 2023-12-01 · 2 commits ahead (`90ccf11`, `4b391a7`) · +222 lines**

The only fork that adds a *feature*. vlmcsd has no client access control of any kind — its
`PublicIPProtectionLevel` (`src/vlmcsd.c:1222`, default 0 at `src/shared_globals.c:45`) only
controls which local addresses it binds, not who may activate. This fork adds both an IPv4 CIDR
allowlist and a client-hostname allowlist.

**Surface.** `optstring` gains `Y:` and `y:` (`KptCheeseWhiz src/vlmcsd.c:87`):

- `-Y <CIDRs>` — comma-separated IPv4 CIDRs, parsed with
  `sscanf("%hhu.%hhu.%hhu.%hhu/%hhu")`; a malformed entry or prefix > 32 logs
  `Error: Invalid CIDR '<x>' in options.` and calls `exit(1)`. Stored as
  `{ip, mask, first_ip, final_ip}` in `WhitelistIP_t whitelist_ips[32]`
  (`src/types.h:395-400`, `src/shared_globals.c:154`).
- `-y <file>` — one hostname per line, read once at parse time into
  `char whitelist_hosts[32][128]` (`src/shared_globals.c:153`). A missing file only warns.
- ini equivalents `WhitelistIPs` and `WhitelistHostsFile` (`src/vlmcsd.c:192-193`) with the normal
  `ignoreIniFileParameter()` precedence (CLI beats ini). The parsing code is duplicated verbatim
  between the CLI case labels (`src/vlmcsd.c:1479`, `src/vlmcsd.c:1506`) and the ini handlers
  (`src/vlmcsd.c:739-790`).
- Cap `MAX_WHITELIST_SIZE` = 32 (`src/config.h:670`). Compile-time kill switch `NO_WHITELISTING`.
  The whole feature is inside `#ifndef IS_LIBRARY`, so `libkms` is unaffected.

**Enforcement** is `clientWhitelist()` (`KptCheeseWhiz src/kms.c:588`), called at the top of
`CreateResponseBaseCallback` (`src/kms.c:651`) — i.e. *after* the TCP and RPC handshakes complete
and after the request is logged. A denial returns `0x80070005` (E_ACCESSDENIED). Logic: if the IP
table is non-empty, parse the client address out of the `"ip:port"` string and return success on
the first CIDR containing it (**skipping the hostname check entirely**); if no CIDR matches and no
hostname list exists, deny; otherwise compare the client's `WorkstationName` with `strcmp`.
Defaults are unchanged — both tables are zeroed globals, so with no `-Y`/`-y` every request is
allowed.

**Defects, all on attacker-reachable input:**

1. **One-byte heap overflow per request.** `char* ipstr_cpy = malloc(strlen(ipportstr)); strcpy(ipstr_cpy, ipportstr);`
   (`src/kms.c:593`) — one byte short for the NUL.
2. **Unbounded `strcpy` into a 128-byte global row** from a `getline` buffer
   (`src/vlmcsd.c:785` and `src/vlmcsd.c:1526`, both copies of the loop). A hosts-file line longer
   than 127 bytes smashes the adjacent global. Config-controlled, so low severity, but unchecked.
3. **Bounds check after dereference.** Both scan loops test the array element *before* checking
   the index: `while (!(whitelist_ips[i].first_ip == 0 && …) && i < MAX_WHITELIST_SIZE)`
   (`src/kms.c:607`, `src/kms.c:621`). A full 32-entry table reads one element past the end.
4. **`strtok` in a request handler** (`src/kms.c:595`) — shared static state, and vlmcsd forks or
   threads per connection depending on build.
5. **Declarations directly after `case` labels** (`case 'Y': char* whitelist_ips_str = …`) — a
   constraint violation before C23. **`getline` is POSIX-only** and appears nowhere else in
   vlmcsd, so this breaks the MSVC/Windows build outright.
6. **`/0` shifts by the full width**: `mask = 0xFFFFFFFFUL << (32UL - bits)` with `bits == 0` is
   undefined on ILP32 (defined-by-accident on LP64, where it happens to yield "allow all").
7. **IPv4-only ⇒ every IPv6 client is denied.** `ip2str()` formats IPv6 peers as `[addr]:port`
   (`src/network.c:73-93`, format string at `src/network.c:76`). `clientWhitelist` does
   `strtok(ipstr_cpy, ":")`, which for `[::1]:1688` yields the token `"["`; parsing fails, and the
   code logs *"failed to parse IP … access denied"*. Enabling `WhitelistIPs` at all therefore
   locks out every IPv6 client including loopback on the default dual-stack listener, with no
   CIDR syntax available to permit them. IPv4-mapped `::ffff:10.0.0.5` fails the same way.
8. **The hostname list is not authentication.** `WorkstationName` is a client-supplied field of
   the KMS request; anyone can send any name.

**Neither man page was updated** — `man/vlmcsd.8` and `man/vlmcsd.ini.5` do not mention `-Y`,
`-y`, `WhitelistIPs` or `WhitelistHostsFile`, so the shipped documentation disagrees with the
binary. The second commit (`4b391a7`) is itself a fix for the first: the initial version
`fopen`/`getline`/`fclose`'d the hosts file **on every single activation request** and silently
allowed the client if the file could not be opened.

**Judgement: port the idea, not the code.** A client allowlist is the single most-requested
capability this codebase lacks, and doing it at the socket-accept layer with proper IPv6 support
(and, ideally, at the listener rather than inside the KMS handler) is a clean win. Every line of
this particular implementation should be rewritten.

### 5.4 `kankerdev/vlmcsd` and `alexax66/vlmcsd` — the same blob twice

These are one contribution, committed twice by the same person ("Tyrone Faulhaber"). `kankerdev`
`8881895` (2024-01-18) and `alexax66` `5c6ac42` (2024-09-13) contain `etc/vlmcsd.kmd` with
**identical bytes** (17651, md5 `3ca15ac3899fcac64df4362f6fb4cf24`). Their merge base is upstream
`70e0357`, so this is a re-commit in a second repository, not a merge. Attribute the work to
`kankerdev`.

**The catalog.** 6 applications (up from 3 — it adds Visual Studio, SQL Server and SCCM as
top-level apps), 36 KMS IDs, 233 SKUs, 7 CSVLK groups. New KMS IDs include
`Microsoft Visual Studio 2019`, `Microsoft Visual Studio 2022`, `Microsoft SQL Server 2022`,
`Microsoft SCCM 2022` (the latter two flagged "(Can only be applied manually)"),
`Windows Server 2022`, `Windows ServerRdsh (Volume)` and `Office 2021`, plus the full Office LTSC
2021 family, Office/Project/Visio LTSC 2024 Preview SKUs, Server 2021 SAC, Win 11 RTM IoT
Enterprise LTSC, Windows 10/11 SE, and unified `Windows 10/11 …` SKU naming.

**⚠ The regression nobody flagged.** `HostBuildCount` drops from **6 to 3**: only
`Windows Server 2022` (20348), `Windows 10 1809 / Server 2019` (17763) and
`Windows 10 1607 / Server 2016` (14393) survive. The Vista / 7 / 8 / 8.1 / 2012 R2 host builds are
gone. Since `getRandomServerType()` picks uniformly from this list (`src/kms.c:289`) and
`getPlatformId()` / `getReleaseDate()` walk it (`src/kms.c:94-118`), the emulator can no longer
present itself as any pre-2016 KMS host, and `-H 9600` becomes an invalid host build under
`_PEDANTIC`. For a fork whose selling point is "more products", losing half the host-build table
is a real cost.

**kankerdev's other changes.** `SERVERLDFLAGS = -static` (`src/GNUmakefile:165`, `dc76a44`) —
unconditional, which is what makes its `FROM scratch` image work and what disables glibc NSS
lookups; `VERSION "private build"` → `"kankerdev build"` (`src/config.h:27`, `91f5303`); a 5-line
Dockerfile (`FROM scratch`, `EXPOSE 1688/tcp`, `CMD ["-vedD"]`); a 106-line GitHub Actions
workflow cross-building amd64/arm64 under `qemu-user-static` and pushing to GHCR; deletion of all
three READMEs; submodule removal. Its `gh-pages` is the shared third-party "vlmcsd one-line
installer" website, not code.

**alexax66's other changes.** 20 of its 26 commits are `README.md` edits. Two real ones:
`src/config.h:64` and `src/config.h:78` are **uncommented** to
`#define INI_FILE "/usr/local/etc/vlmcsd.ini"` and `#define DATA_FILE "/usr/local/etc/vlmcsd.kmd"`.
That is not merely a path change — defining `DATA_FILE` compiles out `getDefaultDataFile()`
entirely (`src/helpers.c:551`), removing the executable-relative auto-detection. Amusingly, the
same commit *also* edits the fallback inside `getDefaultDataFile()` (`src/helpers.c:540`) from
`/etc/vlmcsd.kmd` to `/usr/local/etc/vlmcsd.kmd` — dead code in its own build. It adds a 27-line
FreeBSD `rc.subr` script (`etc/vlmcsd`), an `/etc/rc.conf.d` snippet, and an `install.sh`
targeting `/usr/local`. Its 298-line `etc/vlmcsd.ini` diff is pure CRLF→LF; a "branding"
version-string commit (`bd61170`) was reverted by `7d26187`.

**Judgement: the catalog is superseded.** Everything in it except the Visual Studio / SQL Server
2022 / SCCM 2022 entries appears in kotfenix's and redneckdba's newer, larger catalogs — and
those keep all eight host builds. The Visual Studio/SQL/SCCM entries are the one genuinely unique
piece of data in the network and are worth extracting. The `/usr/local` hardcoding is a
distribution decision, correct as a build option, wrong as a default.

### 5.5 `yuri1313/vlmcsd` — earliest Office LTSC 2021 / Server 2022 data

**Last push 2023-11-29 · 2 commits ahead**

`ac9f19b` updates `etc/vlmcsd.kmd` to 16419 bytes (32 KMS IDs, 219 SKUs, 8 CSVLK groups): the
`Office 2021` application and the Office LTSC 2021 SKU family (with a typo,
`Office Skype for Business LRSC 2021`, corrected in the later kankerdev catalog),
`Windows Server 2022` with Azure Core/Datacenter/Standard, `Windows Server 2019 RTM ServerTurbine`,
`Windows ServerRdsh (Volume)`, `Windows 10 2004`, `Windows 10 20H2`. Chronologically it is the
first fork to ship Office LTSC 2021 + Server 2022, which is worth noting for attribution.

**⚠ Same class of regression:** `HostBuildCount` 6 → 5, and the surviving entries are all ≥ 14393
(`Windows Server 2022` 20348, `Windows 10 20H2` 19042, `Windows 10 2004` 19041, 17763, 14393).
The human-readable `Windows Vista / Server 2008 SP2`, `Windows 7 / Server 2008 R2 SP1`,
`Windows 8 / Server 2012` and `Windows 8.1 / Server 2012 R2` host builds are gone, degrading
log/`vlmcs` output and ePID variety for those eras.

The other commit (`fbb60fe`) is a 5-line `podman build/tag/login/push` script targeting
`ghcr.io/yuri1313/vlmcsd`.

**Judgement: fully superseded.** Historically first, but there is no reason to prefer it over
kotfenix or redneckdba today.

---

## 6. Forks whose "improvements" are neutral or harmful

### 6.1 `gilberth/kmsvlmcsd` — "security hardening" that truncates every generated ePID

**Last push 2026-03-14 (most recent fork in the network) · 29 commits · +4841 / −73 lines across
32 files — of which ~120 lines touch C.**

Commit `8cba429` adds `src/secure_helpers.h` (152 lines): header-only `static inline`
`secure_strlcpy` / `secure_strlcat` (correct BSD implementations), a NUL-forcing
`secure_snprintf`, `secure_malloc` (aborts on OOM, zero-fills, returns NULL for size 0),
`secure_realloc`, `secure_free`, and `validate_string_input`. **The helper functions are fine.
The macros that wrap them are not** (`gilberth src/secure_helpers.h:148-150`):

```c
#define SECURE_STRCPY(dst, src)       secure_strlcpy(dst, src, sizeof(dst))
#define SECURE_STRCAT(dst, src)       secure_strlcat(dst, src, sizeof(dst))
#define SECURE_SNPRINTF(dst, fmt, ...) secure_snprintf(dst, sizeof(dst), fmt, __VA_ARGS__)
```

`sizeof(dst)` is only meaningful when `dst` is an array *in the current scope*. It was then
applied throughout `generateRandomPid`, whose signature is
`static void generateRandomPid(const int index, char *const szPid, int16_t lang, int32_t hostBuild)`
(`gilberth src/kms.c:307`) — `szPid` is a **pointer**. Every `strcpy`/`strcat` that assembles the
ePID became `SECURE_STRCPY(szPid, …)` / `SECURE_STRCAT(szPid, …)`, i.e.
`secure_strlcpy(szPid, src, 8)` on LP64. The caller passes a `char ePid[PID_BUFFER_SIZE]` with
`PID_BUFFER_SIZE == 64` (`src/kms.h:22`).

**Result: every randomized ePID is clamped to 7 characters plus NUL** (3 plus NUL on 32-bit)
instead of a full `06401-00206-560-594696-03-1033-9600.0000-2962018`-style string. The
`SECURE_SNPRINTF(c, formatString, i)` in `itoc` (`gilberth src/kms.c:281`) has the same defect on
its `char *const c` parameter, and additionally passes a runtime-built format string through a
`__VA_ARGS__` macro, which breaks `-Wformat-security` and requires at least one variadic argument.
The only correctly handled buffer in the file is the local `char formatString[8]`, which really is
an array. The path is reached whenever ePIDs are randomized (no configured ePID), which is the
default configuration for any product without an ini entry.

Two further behavioural changes:

- `vlmcsd_malloc` now tail-calls `secure_malloc` (`gilberth src/helpers.c:363-366`), so every
  allocation is zero-filled (a cost on hot paths that also masks uninitialized-memory bugs), and
  `secure_malloc(0)` returns **NULL** instead of a valid pointer — upstream callers do not check.
  OOM now prints to stderr and `exit(EXIT_FAILURE)` rather than going through vlmcsd's
  `OutOfMemory()` logging path.
- `readIniFile` gained a per-line `validate_string_input(line, sizeof(line) - 1)` gate
  (`gilberth src/vlmcsd.c:875-882`; the buffer is `char line[256]`, `src/vlmcsd.c:862`). Since
  `fgets` already bounds the line and a bare `"\n"` passes the length checks, the real effect is
  that any ini line containing a control byte other than TAB/CR/LF is silently dropped with
  `Warning: <file> line <n>: Invalid characters detected. Line skipped.` Always on, no opt-out.

Everything else is packaging: `Dockerfile` and `Dockerfile.secure` (Alpine 3.22 multi-stage,
dedicated uid/gid 1688, `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE`, `-pie -Wl,-z,relro
-Wl,-z,now -Wl,-z,noexecstack`, `HEALTHCHECK` running `vlmcs -l 3 127.0.0.1`), two compose files,
`scripts/install-ubuntu.sh` (688 lines: builds, installs a systemd unit, writes `/etc/vlmcsd.ini`,
auto-detects and configures ufw/firewalld), uninstall and status scripts, a 532-line Ubuntu build
workflow, a GHCR publish workflow, `etc/vlmcsd-ubuntu.ini` (all stock upstream options), ~2000
lines of Markdown (README rewritten in Spanish, plus `PROBLEM-SOLVED.md`,
`IMPLEMENTATION-SUMMARY.md`, `SECURITY-ANALYSIS.md`, `RECOMENDACIONES.md`, `CLAUDE.md`, …), and a
committed macOS `.DS_Store`. `SECURITY-ANALYSIS.md` claims hardening the code does not deliver.

**Judgement: nothing to port.** The container/systemd packaging is competent and entirely
reproducible from scratch; the C changes are a net regression. This fork is the strongest argument
in the survey for reading diffs rather than trusting commit messages, README claims, or recency.

### 6.2 `LuoSimba/vlmcsd` — subtractive Linux-only rewrite

**Last push 2021-03-14 · 75 commits on `dev` · +908 / −2735 across 43 files.** `master` (`65228e5`)
is an *ancestor* of `origin/master` with zero unique commits; `gh-pages` shares no merge base.

Everything here is removal:

- **All non-Linux ports deleted.** Code guarded by `_WIN32`, `__CYGWIN__`, `__MINGW__`,
  `__APPLE__`/`__MACH__`, the BSDs, `__sun__`, `__minix__`, `__gnu_hurd__`, `__ANDROID__`,
  ARM/`__ia64__`, `SUPPORT_WINE`, `USE_MSRPC` and `_NTSERVICE` is stripped;
  `msrpc-client.*`, `msrpc-server.*`, `crypto_windows.*`, `ntservice.*` are gutted rather than
  deleted. In `src/dns_srv.c` the multi-libc resolver selection collapses to an unconditional
  `res_querydomain("_vlmcs._tcp", …)` / `res_search` pair (`LuoSimba src/dns_srv.c:149-160`),
  dropping the non-glibc fallback.
- **Compile-time switches removed, several features forced on.** `src/config.h` loses `NO_LIMIT`,
  `NO_HELP`, `NO_VERSION_INFORMATION`, `USE_AUXV`, `TERMINAL_FIXED_WIDTH`, `HWID` as a make
  variable, `INI_FILE`, and the `CONFIG=<file>` indirection (every `#include CONFIG` becomes
  `#include "config.h"`). Make flags `DATA=`, `INI=`, `CONFIG=`, `HWID=` are dropped, as are the
  `NO_VERBOSE_LOG`/`NO_LOG` guards. **No runtime CLI or ini option changes.**
- **`DATA_FILE` hardcoded to `/vlmcsd.kmd`** — the filesystem root, not `/etc` — while the embedded
  arrays stay byte-identical to upstream (the `src/kmsdata.c` diff is fold markers and include
  style; the header still reads 6 CSVLK / 29 KMS / 202 SKU / 6 host builds).
- **`vlmcsdmulti` deleted** (`src/vlmcsdmulti.c`, 121 lines) along with the `vlmcsd_main`/
  `vlmcs_main` entry-point indirection: no more busybox-style single binary.
- **`-V` output reduced** to `vlmcsd <version> <n>-bit`; the ~29-line `printPlatform()` compiler and
  target detection is deleted from `src/output.c` and all call sites. User-visible.
- **`optReset()` inlined** to a literal `optind = 0;` at seven call sites (behaviour-identical —
  upstream's body was already that).
- **Build/docs.** `src/GNUmakefile` shrinks ~700 → ~200 lines (cross-compile targets, `-flto`,
  strip, pdf/html doc targets gone), `README.compile-and-pre-built-binaries` is merged into a
  partly-Chinese README, several source comments are rewritten in Chinese, and `make` no longer
  strips the binary.

The four commits titled "bugfix" fix breakage the author's own `#ifdef` removal introduced.

**Judgement: nothing to port.** This is somebody's personal exercise in deleting portability
code. It adds no capability, no data, and no upstream fix, and it has been untouched since 2021.
Its only informational value is as an inventory of which `#ifdef` families in vlmcsd are dead
weight for a Linux-only target.

### 6.3 `cnzhangquan/vlmcsd` — one line that survives scrutiny

**Last push 2025-10-13 · reported 2 commits ahead — but only one is real.**

This fork branched at `65228e5`. Its commit `cb6cbb7` ("Fix bug in GCC's target platform detection
under some non-English locales", authored by **gnaggnoyil**, 2020-05-12) is the *same patch* that
upstream merged as `db75edf` via PR #41 — identical author, identical timestamp, identical
content. `origin/master` (`70e0357`) already contains it: `src/GNUmakefile:73` reads
`LANG=en_US.UTF-8 LANGUAGE=en_US $(CC) -v …`. The three-dot diff shows it as an addition purely
because the merge base predates the merge. **The two-dot tree difference against `origin/master`
is one line in one file.**

That line (`3ed95a1`) adds `!strncmp(regData, "root\\tap0901", sizeof(regData))` to the
ComponentId whitelist in `OpenTapHandle()` (`src/wintap.c:191`), alongside the existing
`tap0801`, `tap0901` and `TEAMVIEWERVPN` entries. Newer OpenVPN installers register the adapter
with the root-enumerated ComponentId `root\tap0901`, so without this vlmcsd's Windows TAP/VPN
mode cannot find the adapter. The `sizeof(regData)` length argument is upstream's existing idiom
in that function, retained for consistency. The commit message credits `xwang1498/vlmcsd`, which
is where the change originated.

`gh-pages` is the shared third-party installer website, not code.

**Judgement: correct and worth carrying, if you implement Windows TAP support at all.** Also a
useful lesson about `...` diffs: this fork is widely described as carrying a makefile fix it does
not, in fact, uniquely carry.

### 6.4 `jackyjkchen/vlmcsd` — deletes the OpenSSL backend, changes `-Os` to `-O2`

**Last push 2024-05-01 · 3 commits ahead (one is a merge of upstream `master`) · −444 lines**

- **`8c3f4a5`**: `BASECFLAGS` `-Os` → `-O2` (`src/GNUmakefile:161` upstream; :159 in the fork after
  the deletions). Commit message: "changed Os to O2, for i686 gcc3". This applies to every target,
  not just i686, and there is no way to select `-Os` back short of overriding `BASECFLAGS`. It is
  the only change here that affects the emitted binary in a default build.
- **`66b53f4`**: deletes `src/crypto_openssl.c` (269 lines), `src/crypto_openssl.h`,
  `src/crypto_polarssl.h`, `README.openssl`, and the `CRYPTO=openssl`, `CRYPTO=openssl_with_aes`,
  `CRYPTO=openssl_with_aes_soft`, `CRYPTO=polarssl` branches plus `-lcrypto`/`-lpolarssl` and the
  `OPENSSL_HMAC=0` knob. `CRYPTO ?= internal` remains the default and `CRYPTO=windows` still works,
  so a stock build is behaviourally unaffected. **The removal is incomplete**: `src/config.h` still
  documents `_CRYPTO_OPENSSL`, `_CRYPTO_POLARSSL`, `_USE_AES_FROM_OPENSSL`, `_OPENSSL_SOFTWARE`
  and `_OPENSSL_NO_HMAC`, and the corresponding `#ifdef` branches remain in `src/crypto.c`,
  `src/crypto.h`, `src/crypto_internal.c`, `src/output.c` and `src/types.h` — so hand-defining
  `_CRYPTO_OPENSSL` now produces a link failure rather than an OpenSSL build.

`gh-pages` shares no merge base with `origin/master` (unrelated static site).

**Judgement: nothing to port, but one useful data point** — an independent maintainer concluded
the OpenSSL/PolarSSL backends were dead weight and removed them with no functional consequence.
That corroborates treating the internal AES/SHA implementation as the only backend that matters.

---

## 7. The one real upstream bug fix, and its four independent discoverers

**The bug.** In `getEpid()`, `char ePid[PID_BUFFER_SIZE]` is declared *inside* the
`if (RandomizationLevel == 2)` block at `src/kms.c:473`, `pid = ePid` escapes that block, and
`getEpidFromString(baseResponse, pid)` at `src/kms.c:502` reads through `pid` after the buffer's
lifetime has ended. That is undefined behaviour; in practice the buffer can be clobbered before
the ePID is converted to UCS-2 into the response (`getEpidFromString` →
`utf8_to_ucs2(Response->KmsPID, pid, …)`, `src/kms.c:456`).

**The fix**, in every case, is the identical one-line hoist of the declaration to function scope.

**Reachability.** Only with randomization level 2 — `-r 2` (`src/vlmcsd.c:1313`) or
`RandomizationLevel = 2` in the ini. The default is **1** (`src/shared_globals.c:105`), where the
other branch (`pid = defaultEPid`) is taken and the bug is unreachable. So this is a real
correctness defect in a non-default but documented configuration, not a live exploit.

**Who published it, in order:**

| Date | Fork | Commit | Notes |
|---|---|---|---|
| 2024-05-16 | **TokyoBlackHole/vlmcsd** | `e181a5d` "Fix dangling pointer" | **Earliest. Credit belongs here.** The fork's only commit. |
| 2024-09-18 | yammelvin/vlmcsd | `d400b4a` "fix dangling pointer" | Independently re-derived, 4 months later |
| 2024-12-21 | dm764/vlmcsd | `8cbcafb` "Update kms.c" | Byte-identical; the fork's only commit |
| 2025-02-22 | redneckdba/vlmcsd | `0c7a8cc` | Bundled with the catalog update and the `uint16_t` regression |
| 2025-11-15 | kotfenix/vlmcsd | `0f0ffbb` "fix dangling pointer" | Bundled with the catalog update |

Five forks, five independent rediscoveries of the same three-word change, zero coordination, zero
upstream pull requests — because upstream was archived in July 2023, before four of the five
existed. That, more than any diffstat, is what this fork network is.

yammelvin's other content: `runkms.sh` (3 lines, `bin/vlmcsd -evD`) and the same two GVLK
reference text files that appear in redneckdba (`keys/windows-keys.md`, md5
`463eb2557dad382a87341ecd88436572`; `keys/Windows 10 Keys.txt`) — reference lists consumed by no
code.

---

## 8. Nothing of substance

These forks changed no behaviour. They are listed for completeness so that "16 code-touching
forks" is not mistaken for "16 forks worth reading".

| Fork | Last push | What it actually is | Notes |
|---|---|---|---|
| Mo7amedMostafa/vlmcsd | 2024-09-06 | Deployment wrapper, 1 commit (`dded051`) | The entire tree was moved into `vlmcsd/`, and the `debian`/`docker` submodules were flattened into vendored directories (that content is Wind4's own `vlmcsd-debian`/`vlmcsd-docker`, not the author's). The ~6686-line diffstat across `kms.c`, the four `KMSServer_*` stubs, `KMSServer_h.h`, `KMSServer.idl`, `wingetopt.h` and `etc/vlmcsd.ini` is **entirely CRLF→LF**: the same diff with `--ignore-all-space` over `'*.c' '*.h' '*.idl'` yields *69 files changed, 0 insertions(+), 0 deletions(-)*. Every other path is a pure rename. Three real new files: `Dockerfile` (a copy of Wind4's, which `git clone`s upstream from GitHub — so none of the fork's own tree is ever compiled), `docker-compose.yaml`, and `nginx.conf`. The moved `vlmcsd/.gitmodules` still declares root-level `debian`/`docker` paths that no longer exist. |
| simaek/vlmcsd | 2023-05-09 | RPM packaging, 1 commit (`4b86251`) | `rpms/vlmcsd.spec` (110 lines, `Version: svn1113`, binaries to `/usr/sbin`, config to `/etc/vlmcsd`, gzipped man pages), `rpms/build.sh`, `systemd/vlmcsd.service`. Two defects: `%pre` greps for group/user **`vlmcs`** but creates **`vlmcsd`**; and the unit's `ExecStart=/usr/sbin/vlmcsd -l /etc/vlmcsd/vlmcsd.ini` uses `-l` (log file, `man/vlmcsd.8`) where `-i` (ini file) was meant, so it would write its log over the config path. Its `src/GNUmakefile` "change" is an artifact of being 2 commits behind upstream, not an edit. `gh-pages` is the shared installer website. |
| lizhizhuanshu/vlmcsd | 2024-11-13 | systemd unit, 1 commit (`e4ee1b7`) | `vlmcsd.service` (12 lines: `Type=simple`, `User=root`, `ExecStart=/usr/local/bin/vlmcsd -D`, `Restart=on-failure`) and a 6-line `install.sh` (whose shebang is `#/bin/bash`, missing the `!`). Zero changes under `src/`. |

Also in this category but covered above because they carry the one-line fix:
`TokyoBlackHole/vlmcsd`, `dm764/vlmcsd`, `yammelvin/vlmcsd` (§7).

---

## 9. What the forks collectively add

The union of everything genuinely novel across all 2500 forks, deduplicated:

**Data (the bulk of the value).**

1. Modern KMS IDs and SKUs: Windows Server 2022 and 2025; Windows 11 including 24H2; Windows
   10/11 Enterprise LTSC 2019-2021-2024; IoT Enterprise LTSC 2021-2024; Enterprise multi-session;
   Windows 11 SE; Office LTSC 2021 and Office LTSC 2024 complete families
   (kotfenix > redneckdba > kankerdev/alexax66 > yuri1313, in that order of completeness).
2. Two new CSVLK ePID groups — `Office2021` (key IDs 571000000-590999999) and `Office2024`
   (591000000-610999999) — which also become valid `vlmcsd.ini` keys (kotfenix, redneckdba).
3. Re-keying of the "Windows" CSVLK group to GroupId 4919 / key IDs 20000-20019999, and a
   wholesale re-basing of default ePIDs from platform `06401` / build `9600.0000-2962018` to
   `03612` / `17763.0000-2622024` (kotfenix) or `26100.0000-3212024` (redneckdba).
4. Two new emulated KMS host builds: 20348 (Server 2022) and 26100 (Win 11 24H2 / Server 2025),
   platform 3612, flags `UseNdr64|UseForEpid|MayBeServer` (kotfenix, redneckdba).
5. Non-Windows/Office KMS products: Visual Studio 2019/2022, SQL Server 2022, SCCM 2022 as
   first-class applications (kankerdev only — unique in the entire network).

**Code.**

6. Client access control: IPv4 CIDR allowlist plus client-hostname allowlist, with CLI (`-Y`/`-y`)
   and ini (`WhitelistIPs`/`WhitelistHostsFile`) surfaces (KptCheeseWhiz). The only new *feature*
   anyone wrote. Implementation is unsafe; the concept is sound.
7. `getEpid()` use-after-scope fix for `RandomizationLevel = 2` (TokyoBlackHole, four others).
8. `uint8_t` → `uint16_t` in `showProducts()`, required once a catalog exceeds 255 SKUs
   (kotfenix).
9. OpenVPN `root\tap0901` ComponentId recognition for the Windows TAP path (cnzhangquan, from
   xwang1498).

**Deployment patterns (no code value, but the pattern is informative).**

10. nginx `stream` TCP proxy sidecar performing source-IP filtering in front of vlmcsd —
    somebody's workaround for the missing feature in item 6 (Mo7amedMostafa).
11. `FROM scratch` container built on a static link (kankerdev), multi-arch GHCR CI
    (kankerdev, gilberth), RPM spec (simaek), FreeBSD `rc.d` (alexax66), systemd units
    (lizhizhuanshu, redneckdba, simaek, gilberth), Debian packaging (upstream's own submodule).

That is the complete list. Nine items, four of which are the same database refresh at different
levels of completeness.

---

## 10. What nobody fixed

Everything below is absent from upstream **and** from all 2523 forks. With the upstream archived
since 2023-07-28 and no maintained successor, none of it is going to be fixed by waiting.

**Data and documentation**

- **The compiled-in database is stale in 15 of 16 forks.** Only kotfenix regenerated
  `src/kmsdata.c` / `src/kmsdata-full.c`. Every other data fork ships a binary that still knows
  only 29 KMS IDs and 202 SKUs unless an external `.kmd` is deployed alongside it
  (`src/helpers.c:538-556`). redneckdba's build cannot use the internal catalog at all.
- **No man page anywhere was updated.** `man/vlmcsd.8`'s SUPPORTED PRODUCTS section still reads
  "Windows 10 (up to 1809) … Office 2019, Project 2019, Visio 2019". `man/vlmcsd.ini.5` documents
  no new keys. KptCheeseWhiz's `-Y`/`-y` exist in the binary and in `usage()` but in no man page.
  Zero forks touched `man/` except to move or delete it.
- **No fork produced tooling to regenerate `.kmd` from a readable source.** Every catalog in this
  survey is a hand-edited binary blob of unknown provenance, committed with a message like
  "Upload" or "Fix". There is no way to review a data change in a pull request, which is precisely
  why nobody reviewed these.
- **Host-build tables regressed silently.** Three of the four data forks *shrank* `HostBuildCount`
  (6 → 3 in kankerdev/alexax66, 6 → 5 in yuri1313) while advertising themselves as additions.

**Security and operations**

- **No authentication, no transport security, anywhere.** The KMS protocol has none, vlmcsd adds
  none, and no fork proposed any. The one access-control attempt (KptCheeseWhiz) is IPv4-only,
  memory-unsafe, enforced after the RPC handshake, and keys off a client-supplied hostname.
- **No IPv6-capable access control.** vlmcsd binds dual-stack by default
  (`src/vlmcsd.c:1651`); every filtering attempt in the network operates on IPv4 dotted quads,
  and the only in-tree one denies all IPv6 peers outright once enabled.
- **The HWID is a hardcoded constant nobody changed.** `#define HWID 0x3A, 0x1C, 0x04, 0x96, 0x00,
  0xB6, 0x00, 0x76` (`src/config.h:36`, "HwId from the Ratiborus VM") is returned by every vlmcsd
  and every fork of it in KMS v6 responses — a perfect fingerprint for anyone enumerating
  emulators. Configurable per-product via the ini (`src/vlmcsd.c:435`), but the default is
  universal and unchanged since 2016.
- **No fork addressed emulator-detectability generally.** `-c1` client-time checking is still
  off by default (`src/shared_globals.c:23`), and the ePID randomization ranges, the
  `MayBeServer`/`UseNdr64` flag consistency, and the response timing are all as shipped.
- **No memory-safety work on the request path.** The single fork that touched the request handler
  introduced a heap overflow, an out-of-bounds read and a `strtok` race. Nobody ran a sanitizer,
  and there is no test suite in upstream or in any fork.

**Portability and build**

- **The MSVC/Windows build was never touched by anyone.** No fork modified any Windows project
  file, and the one fork that added C code to the shared path (KptCheeseWhiz) used POSIX-only
  `getline`, breaking that build.
- **Nobody fixed a latent overflow they were actively triggering.** `showProducts()`'s `uint8_t`
  counters (`src/vlmcs.c:239`) would corrupt the product listing for three of the four data forks'
  catalogs on a narrow terminal. Only kotfenix noticed.
- **No fork rebased, merged, or coordinated with any other fork.** The same one-line fix was
  written five times; the same `.kmd` blob was committed twice by the same person in two repos;
  the same GVLK text file propagated between two unrelated forks. There is no shared branch, no
  cross-fork PR, and no fork that aggregates the others.

**What this means for anyone depending on vlmcsd.** There is no upstream to report a bug to and
no fork with enough activity, review, or breadth to be called a successor. The best available
"current" build is a hand-assembly job: upstream `70e0357`, plus kotfenix's regenerated catalog
and its two C fixes, plus (optionally) redneckdba's fresher ePID base and kankerdev's Visual
Studio/SQL/SCCM entries — a combination that exists in no repository on GitHub, and which nobody
has published. Anything beyond that — access control, IPv6-aware filtering, a reviewable data
pipeline, tests, a non-fingerprintable HWID — has to be written from scratch, which is a
reasonable argument for reimplementing rather than forking.

---

## 11. Appendix: verification commands

Every claim above is reproducible against the local clone with the fork remotes fetched.

```sh
# fork position (never trust a three-dot diffstat alone)
git merge-base origin/master <remote>/<branch>
git rev-list --count origin/master..<remote>/<branch>
git diff origin/master..<remote>/<branch> --stat        # two-dot: the fork's real tree delta

# separate real edits from whitespace/renames
git diff --ignore-all-space origin/master..<remote>/<branch> -- '*.c' '*.h' '*.idl'

# decode a fork's product database header
#   magic@0 version@4 CsvlkCount@8 Counts[5]@12 Datapointers[5]@32 CsvlkData[]@72 (32 B/entry)
#   HostBuild entries are 32 bytes: nameOffset(8) releaseDate(8) build(4) platform(4) flags(4) reserved(4)
git show <remote>/<branch>:etc/vlmcsd.kmd | xxd | head

# confirm the embedded copy matches the external file
git show <remote>/<branch>:src/kmsdata.c | sed -n '12,16p'
```

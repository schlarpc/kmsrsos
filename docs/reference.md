<!-- GENERATED FILE — do not edit by hand.
     Regenerate with:
       KMSRSOS_BLESS=1 cargo test -p kmsrs-server --test reference_docs
     Drift fails CI (PKG-010, #247). -->

# Reference

Facts about this program, read off the program. The prose lives in
[`deployment.md`](deployment.md) and [`decisions.md`](decisions.md);
this is the part a generator can be trusted with, so it is generated
rather than described — a hand-written copy is a second source of truth
that drifts, which is how vlmcsd came to document seven options its own
optstring does not have.


## Web UI

Six routes and no more. `/` is matched exactly rather than as a prefix,
so an unknown path is 404 rather than something's index, and the parser
admits only `GET` and `HEAD` — a route cannot act on a `POST` it was
never offered.

| Route | What it is |
|---|---|
| `/` | Status: the listener, the entropy self-test, the host build, the ePIDs this host answers with, and the machines it has seen. |
| `/events` | The bounded event log, most recent first — one row per request, never one row per machine. |
| `/instructions` | How to point a client here, with this instance's own address filled in: `slmgr`, `ospp.vbs`, and three DNS forms. |
| `/products` | The shipped product database. |
| `/healthz` | 200 when the KMS side is working, 503 otherwise. Plain text, so a monitor need not parse HTML. |
| `/metrics` | Prometheus exposition format. |

## Metrics

Read off `/metrics` itself, so the help text here is the help text a
scraper sees.

| Metric | Type | Help |
|---|---|---|
| `kmsrsos_requests_total` | counter | Requests recorded since start. |
| `kmsrsos_activations_total` | gauge | Requests in the retained window that were activated. |
| `kmsrsos_events_held` | gauge | Events currently in the bounded log. |
| `kmsrsos_events_dropped_by_capacity_total` | counter | Events evicted because the log was full. |
| `kmsrsos_events_dropped_by_retention_total` | counter | Events removed because they aged out. |
| `kmsrsos_listener_up` | gauge | 1 when the KMS listener is accepting. |
| `kmsrsos_entropy_healthy` | gauge | 1 when the entropy source passes its self-test. |
| `kmsrsos_build_info` | gauge | Which build this is; the value is always 1. |

## Exit codes

A supervisor can tell "you told me something wrong" from "something
went wrong" without parsing stderr.

| Code | Meaning |
|---|---|
| `0` | Stopped cleanly. |
| `64` | The command line or the activation environment could not be understood: an argument was passed, or `LISTEN_FDS` was set. |
| `69` | Start-up could not proceed: nothing bound, the clock is unusable, or the entropy self-test failed. |
| `78` | `KMSRSOS_CONFIG` could not be parsed. |
| `130` | A second stop signal cut a drain short. |

## What a build decides

Anything that can change a byte on the wire is decided when the binary
is built (`CFG-001`, #166). These are the values *this* build carries;
`mkKmsrsos` is how a different one is produced (`CFG-003`, #168).

| Setting | This build |
|---|---|
| Activation interval | 120 minutes |
| Renewal interval | 10080 minutes |
| Refuse retail, OEM and evaluation SKUs | yes |
| Refuse pre-release SKUs | yes |
| Refuse a clock-skewed request | no |
| Idle timeout | 30 seconds |
| Version | `0.1.0` |

The only runtime setting is `KMSRSOS_CONFIG`, a TOML document
restricted to fields that cannot change a byte on the wire. There is no
configuration file and no command line.

## The shipped database

Extracted from Microsoft's own signed licensing artifacts by
`kmsrs-dbgen` (`DB-002`, #126). Static data in the binary's read-only
section: no parsing, no initialisation, no lock, and no per-request
cost.

| Table | Rows |
|---|---:|
| Applications | 2 |
| Products | 273 |
| KMS host keys | 14 |
| Counted IDs | 27 |
| Host builds | 23 |
| Host builds an ePID may claim | 8 |
| Locales | 252 |

The arrays occupy 41232 bytes, against a 262144-byte ceiling asserted at
compile time (`DB-018`, #142) — on the bare-metal target every byte
of `.rodata` is a byte of the guest's memory, permanently.

//! The six routes (`OBS-008`, #184).
//!
//! `/` status, `/events`, `/instructions`, `/products`, `/healthz`,
//! `/metrics`. Nothing else exists, and `/` is not a prefix — an unknown path
//! is 404 rather than something's index.
//!
//! # Strictly read-only, and not as a shortcut
//!
//! `OBS-010` (#186) is the design rather than an omission. Under axiom A5 there
//! is nothing durable to mutate: the event log ages out and the CMID table
//! decays, so a "delete this machine" button would remove something that was
//! about to remove itself. Read-only is therefore the only *coherent* design,
//! and it happens to delete an entire vulnerability class — no CSRF, no
//! authentication to bypass, no privileged action to confuse.
//!
//! The parser makes it structural: only `GET` and `HEAD` reach here at all
//! (`OBS-007`, #183), so a route cannot accidentally act on a `POST` it was
//! never offered.
//!
//! # Health is about the KMS listener, not this process
//!
//! `/healthz` answers 200 only when the thing an operator cares about is
//! working. The Organization fork's `readyz` proves its own HTTP handler is
//! alive, which is the one fact a caller already knew by getting a reply — so
//! it reports healthy while the service it fronts is down.
//!
//! Here the check is the KMS side: an identity was drawn (`OS-012`, #263 — a
//! host that cannot draw one refuses to start rather than serving a predictable
//! one), the listener is bound, and the entropy source still passes its
//! self-test.
//!
//! # Bounded per render
//!
//! MelroyB's dashboard sorts the whole event log per view. `/events` renders at
//! most [`EVENTS_PER_PAGE`] events, taken from the end of a log that is already
//! bounded and already in order, so a render is O(page) and not O(log)
//! (`OBS-012`, #188). `/products` is bounded by the shipped table, which is a
//! compile-time constant.
//!
//! # `X-Forwarded-For` is never read
//!
//! Not "validated", not "trusted from a configured proxy" — never read. It is
//! a header any client can set, and MelroyB's login rate limiter keys on it and
//! is therefore bypassable by anyone who reads its source (`OBS-011`, #187).
//! There is no login here to rate-limit, and the peer address the event log
//! records is the one the socket reports.

use crate::net::addr::KMS_PORT;
use crate::web::request::{Method, Request};
use crate::web::response::{Response, Status};
use core::fmt::Write as _;

/// How many events one render of `/events` shows.
///
/// A page rather than the log, because the cost of a render must not grow with
/// how long the host has been up (`OBS-012`, #188).
pub const EVENTS_PER_PAGE: usize = 100;

/// The vendored stylesheet.
///
/// Inline and tiny, because the alternative is a request to a CDN — which is a
/// dependency on the public internet for a page whose entire audience is an
/// operator on the same network, and a beacon telling that CDN where every
/// KMS host is. konk22 and Py-KMS-Organization both got this right and it is
/// worth keeping right (`OBS-007`, #183).
///
/// The response's Content-Security-Policy allows `style-src 'unsafe-inline'`
/// and nothing else, so this is the only styling the page can ever have.
const STYLE: &str = "\
body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem}\
h1{font-size:1.3rem}h2{font-size:1.05rem;margin-top:2rem}\
nav a{margin-right:1rem}\
table{border-collapse:collapse;width:100%;font-size:13px}\
th,td{text-align:left;padding:.25rem .5rem;border-bottom:1px solid #8884}\
th{font-weight:600}\
code{font-family:ui-monospace,monospace}\
.ok{color:#2a7}.no{color:#c33}\
@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}}";

/// What a route needs to know that is not in the server's own state.
///
/// Passed in rather than read, so a page is a pure function of it and can be
/// rendered in a test without a socket, a clock or a listener.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot<'a> {
    /// Whether the KMS listener is accepting.
    pub listening: bool,
    /// Whether the entropy source still passes its self-test
    /// (`ARCH-003`, #3; `OS-012`, #263).
    pub entropy_healthy: bool,
    /// The ports the KMS listener is bound to.
    pub kms_ports: &'a [u16],
    /// The host identity this process drew.
    pub identity: &'a kmsrs_policy::identity::HostIdentity,
    /// The event log.
    pub events: &'a kmsrs_policy::events::EventLog,
}

impl Snapshot<'_> {
    /// Whether `/healthz` should answer 200.
    ///
    /// Every condition is about serving KMS. None of them is "this HTTP
    /// handler ran", which is the one fact a caller already has
    /// (`OBS-008`, #184).
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.listening && self.entropy_healthy && !self.kms_ports.is_empty()
    }
}

/// Answer one request.
///
/// Exhaustive over the routes that exist; everything else is 404. `/` is
/// matched exactly rather than as a prefix, so there is no path under which an
/// unknown route becomes an index.
#[must_use]
pub fn route(request: &Request<'_>, snapshot: &Snapshot<'_>) -> Response {
    match request.path {
        "/" => Response::html(status_page(snapshot)),
        "/events" => Response::html(events_page(snapshot)),
        "/instructions" => Response::html(instructions_page(snapshot, request.host)),
        "/products" => Response::html(products_page()),
        "/healthz" => health(snapshot),
        "/metrics" => Response::metrics(metrics(snapshot)),
        _ => Response::error(Status::NotFound),
    }
}

/// `/healthz`, which is plain text so a monitor does not have to parse HTML.
///
/// The body says which condition failed. That is not an information leak: a
/// caller who can reach this port can already tell whether the KMS port answers
/// by connecting to it, and an unexplained 503 is the kind of thing that gets
/// diagnosed by guessing (`SEC-012`, #204). What is *not* here is any exception
/// text, path or internal name (`OBS-009`, #185).
fn health(snapshot: &Snapshot<'_>) -> Response {
    if snapshot.healthy() {
        return Response::text(String::from("ok\n"));
    }

    let mut body = String::new();
    if !snapshot.listening || snapshot.kms_ports.is_empty() {
        body.push_str("kms listener not accepting\n");
    }
    if !snapshot.entropy_healthy {
        body.push_str("entropy self-test failing\n");
    }
    Response {
        status: Status::ServiceUnavailable,
        content_type: crate::web::response::ContentType::Text,
        body,
    }
}

/// Wrap a body in the page chrome.
fn page(title: &str, body: &str) -> String {
    let mut out = String::with_capacity(body.len().saturating_add(STYLE.len()).saturating_add(512));
    let _: core::fmt::Result = write!(
        out,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{} — kmsrsos</title><style>{STYLE}</style></head><body>\
         <nav><a href=\"/\">status</a><a href=\"/events\">events</a>\
         <a href=\"/instructions\">instructions</a><a href=\"/products\">products</a></nav>\
         <h1>{}</h1>{body}</body></html>",
        escape(title),
        escape(title)
    );
    out
}

/// HTML-escape untrusted text.
///
/// Everything a client sends is untrusted, and a workstation name is text a
/// client chose (`POL-015`, #103). Escaping at the point of rendering rather
/// than at the point of storage means the log keeps what was actually sent —
/// which is what makes it evidence.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            // Control characters have no business in a page and are how a
            // terminal-based log reader gets attacked instead.
            c if c.is_control() => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

/// `/` — what this host is and whether it is working.
fn status_page(snapshot: &Snapshot<'_>) -> String {
    let identity = snapshot.identity;
    let build = identity.host_build();
    let mut body = String::new();

    let _: core::fmt::Result = write!(
        body,
        "<table>\
         <tr><th>KMS listener</th><td class=\"{}\">{}</td></tr>\
         <tr><th>Ports</th><td><code>{}</code></td></tr>\
         <tr><th>Entropy self-test</th><td class=\"{}\">{}</td></tr>\
         <tr><th>Host build</th><td>{} <code>{}</code></td></tr>\
         <tr><th>Locale</th><td>{} <code>{}</code></td></tr>\
         <tr><th>NDR64</th><td>{}</td></tr>\
         <tr><th>Requests seen</th><td>{}</td></tr>\
         <tr><th>Events held</th><td>{}</td></tr>\
         <tr><th>Build</th><td><code>{}</code></td></tr>\
         </table>",
        if snapshot.listening { "ok" } else { "no" },
        if snapshot.listening {
            "accepting"
        } else {
            "not accepting"
        },
        escape(&join_ports(snapshot.kms_ports)),
        if snapshot.entropy_healthy { "ok" } else { "no" },
        if snapshot.entropy_healthy {
            "passing"
        } else {
            "FAILING"
        },
        escape(build.description),
        build.build,
        escape(identity.lcid().language),
        identity.lcid().value,
        if identity.advertises_ndr64() {
            "yes"
        } else {
            "no"
        },
        snapshot.events.recorded(),
        snapshot.events.len(),
        // `CFG-008` (#173): which binary this is, so a bug report and a running
        // process can be matched up. There is no `--version` flag to ask —
        // this program takes no arguments at all (`CFG-007`, #172) — so the
        // answer has to be somewhere an operator already is.
        escape(&crate::config::stamp::BUILD.to_string()),
    );

    // The ePIDs this host answers with, which is what an operator compares
    // against `slmgr /dlv` on a client.
    //
    // Grouped by the host key that *answers*, not by the host key that lists a
    // product. Several keys can count one product and
    // `HostIdentity::select` chooses among them (`ID-004`, #109), so a table
    // keyed the other way shows one key's description beside another key's
    // ePID — which is the confusion MM02 is about.
    //
    // A counted ID has no name of its own: it is not an activation ID, so
    // `kmsrs_db::product` does not know it (`DB-008`, #132). The host key's
    // description is the name that exists, and it is the one an operator sees
    // in the ePID anyway.
    body.push_str(
        "<h2>What this host answers with</h2>\
         <table><tr><th>Host key</th><th>Products</th><th>ePID</th></tr>",
    );

    let mut answered: Vec<(u16, String, usize)> = Vec::new();
    for counted in kmsrs_db::COUNTED_IDS {
        let Some(application) = counted
            .csvlks
            .first()
            .and_then(|index| kmsrs_db::csvlk_at(*index))
            .and_then(|csvlk| csvlk.application)
        else {
            continue;
        };
        let (selection, group) = identity.select(
            kmsrs_proto::types::ApplicationId(application),
            kmsrs_proto::types::KmsCountedId(counted.guid),
        );
        let index = match selection {
            kmsrs_proto::types::CsvlkSelection::Resolved { index }
            | kmsrs_proto::types::CsvlkSelection::Fallback { index } => index,
        };
        match answered.iter_mut().find(|(seen, _, _)| *seen == index) {
            Some((_, _, count)) => *count = count.saturating_add(1),
            None => answered.push((index, group.epid.to_string(), 1)),
        }
    }

    for (index, epid, count) in answered {
        let description = kmsrs_db::csvlk_at(index).map_or("unknown", |csvlk| csvlk.description);
        let _: core::fmt::Result = write!(
            body,
            "<tr><td>{}</td><td>{count}</td><td><code>{}</code></td></tr>",
            escape(description),
            escape(&epid)
        );
    }
    body.push_str("</table>");

    body.push_str(&machines_table(snapshot));
    page("Status", &body)
}

/// How many rows the fleet view shows.
///
/// A page rather than the fleet, for the same reason `/events` shows a page:
/// the cost of a render must not grow with how long the host has been up
/// (`OBS-012`, #188).
pub const MACHINES_PER_PAGE: usize = 50;

/// The fleet, one row per `(machine, SKU)` (`OBS-006`, #182).
///
/// py-kms has keyed this three times, six years apart, and got a different
/// answer each time: the machine alone, then `(machine, application)`, then
/// `(machine, SKU)`. The reason it keeps being rediscovered is that the right
/// key depends on what the row is *for*, and there are two different things:
/// the **count** a client is told is per `(machine, application)`, because that
/// is what a genuine host caches; the **fleet view** an operator reads is per
/// `(machine, SKU)`, because a box running Windows Enterprise and Office LTSC
/// is two things they maintain.
///
/// So one machine activating Windows and Office is two rows here and one entry
/// in each of two count buckets, and neither number is derived from the other.
fn machines_table(snapshot: &Snapshot<'_>) -> String {
    let rows = snapshot.events.clients(MACHINES_PER_PAGE);

    let mut out = String::new();
    let _: core::fmt::Result = write!(
        out,
        "<h2>Machines seen</h2>\
         <p>One row per machine and product. A machine activating Windows and \
         Office is two rows here and one entry in each of two counts.</p>\
         <table><tr><th>Name</th><th>Machine</th><th>Product</th>\
         <th>Requests</th><th>Activated</th><th>From</th></tr>"
    );

    if rows.is_empty() {
        out.push_str("<tr><td colspan=\"6\">nothing yet</td></tr>");
    }

    for row in &rows {
        // The SKU is what a client claimed, and a host reads and ignores it
        // (`KMS-018`, #34) — so it is shown as the raw GUID rather than looked
        // up, because a name here would suggest this host acted on it.
        let _: core::fmt::Result = write!(
            out,
            "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td>\
             <td>{}</td><td class=\"{}\">{} / {}</td><td><code>{}</code></td></tr>",
            escape(row.workstation_name.as_str()),
            escape(&row.client_machine_id.0.to_string()),
            escape(&row.sku.0.to_string()),
            row.requests,
            if row.activated_last { "ok" } else { "no" },
            row.activations,
            row.requests,
            escape(
                &row.peer
                    .map_or_else(|| String::from("—"), |peer| peer.address.to_string())
            ),
        );
    }
    out.push_str("</table>");
    out
}

/// Join the bound ports for display.
fn join_ports(ports: &[u16]) -> String {
    let mut out = String::new();
    for (index, port) in ports.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        let _: core::fmt::Result = write!(out, "{port}");
    }
    if out.is_empty() {
        out.push_str("none");
    }
    out
}

/// `/events` — the most recent page of the bounded log.
///
/// `recent` takes from the end of a log that is already in sequence order, so
/// this is O(page). MelroyB's dashboard sorts every row per view
/// (`OBS-012`, #188).
fn events_page(snapshot: &Snapshot<'_>) -> String {
    let log = snapshot.events;
    let mut body = String::new();

    let dropped = log.dropped();
    let _: core::fmt::Result = write!(
        body,
        "<p>{} of {} recorded, showing the most recent {}. \
         {} aged out, {} evicted for capacity.</p>",
        log.len(),
        log.recorded(),
        EVENTS_PER_PAGE.min(log.len()),
        dropped.by_retention,
        dropped.by_capacity
    );

    body.push_str(
        "<table><tr><th>#</th><th>From</th><th>Ver</th><th>Product</th>\
         <th>Machine</th><th>Name</th><th>Outcome</th></tr>",
    );

    // Collected so the newest is first; bounded by `recent`, so the vector is
    // at most one page.
    let mut recent: Vec<&kmsrs_policy::events::Event> = log.recent(EVENTS_PER_PAGE).collect();
    recent.reverse();

    for event in recent {
        let product = kmsrs_db::product(event.counted.0)
            .map_or_else(|| event.counted.0.to_string(), |p| p.description.to_owned());
        let _: core::fmt::Result = write!(
            body,
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td>\
             <td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            event.sequence,
            escape(
                &event
                    .peer
                    .map_or_else(|| String::from("—"), |peer| format!("{}", peer.address))
            ),
            escape(&format!("{}", event.version)),
            escape(&product),
            escape(&event.client_machine_id.0.to_string()),
            escape(event.workstation_name.as_str()),
            escape(&describe_outcome(&event.outcome)),
        );
    }
    body.push_str("</table>");
    page("Events", &body)
}

/// One line for an outcome.
fn describe_outcome(outcome: &kmsrs_policy::events::Outcome) -> String {
    use kmsrs_policy::events::Outcome;
    match outcome {
        Outcome::Activated(activation) => {
            format!("activated, count {}", activation.reported_count)
        }
        Outcome::Refused(refusal) => format!("refused: {refusal:?}"),
    }
}

/// `/instructions` — how to point a client here.
///
/// The audit's MM22: neither implementation tells an operator what to do, and
/// the answer is always a manual `slmgr /skms` or a hand-made DNS record. The
/// least this host can do is say so, with its own ports filled in.
fn instructions_page(snapshot: &Snapshot<'_>, host: Option<&str>) -> String {
    let port = snapshot.kms_ports.first().copied().unwrap_or(KMS_PORT);
    // The address the operator's own browser reached this server on. Escaped
    // here rather than trusted: the `Host` header is client-controlled, and
    // `plausible_host` has already reduced it to a hostname or an IP literal.
    let address = host.map_or_else(|| String::from(HOST_PLACEHOLDER), escape);
    let loopback = is_loopback_text(&address);

    let mut body = String::new();

    if loopback {
        // `NET-014` (#163). The most expensive way to learn this is to spend an
        // afternoon on it; the second most expensive is vlmcsd's, which is a
        // 370-line TAP driver that swaps ip_src and ip_dst on every packet
        // (declined item D21).
        let _: core::fmt::Result = write!(
            body,
            "<h2 class=\"no\">This page was reached over loopback</h2>\
             <p><strong>A Windows client will not activate against \
             <code>127.0.0.1</code> or <code>::1</code>.</strong> Software \
             Protection Platform refuses a KMS host on the loopback interface, \
             whatever the port, and reports a generic failure rather than \
             saying so.</p>\
             <p>Give the clients an address that is not loopback: this \
             machine's LAN address, a second interface, a container bridge \
             address, or the host-side address of a Hyper-V or WSL virtual \
             switch. The commands below will work once <code>{HOST_PLACEHOLDER}</code> \
             is one of those.</p>"
        );
    }

    let _: core::fmt::Result = write!(
        body,
        "<h2>On each client</h2>\
         <p>Run as administrator:</p>\
         <pre><code>slmgr /skms {address}:{port}\nslmgr /ato</code></pre>\
         <p>For Office, run the same two steps against <code>ospp.vbs</code> in \
         the Office installation directory:</p>\
         <pre><code>cscript ospp.vbs /sethst:{address}\ncscript ospp.vbs /act</code></pre>\
         <p>A client must already be installed with the generic volume licence \
         key for its edition, or it will not contact a KMS host at all. \
         <a href=\"/products\">The product list</a> has them.</p>\
         \
         <h2>Or by DNS, so no client needs configuring</h2>\
         <p>A client with no explicit host looks up \
         <code>_vlmcs._tcp</code> in the domains it searches, which is how a \
         real KMS deployment is found. Publish one of these; all three say the \
         same thing.</p>\
         \
         <h3>BIND-style zone file</h3>\
         <pre><code>_vlmcs._tcp  IN  SRV  0 0 {port}  {address}.</code></pre>\
         <p>The four numbers are priority, weight, port and target. Clients \
         order by ascending priority, then by weighted random choice within a \
         priority (RFC 2782), so a single host needs neither and zero for both \
         is the convention.</p>\
         \
         <h3>nsupdate</h3>\
         <pre><code>nsupdate &lt;&lt;'EOF'\n\
         update add _vlmcs._tcp.EXAMPLE.COM. 3600 SRV 0 0 {port} {address}.\n\
         send\n\
         EOF</code></pre>\
         \
         <h3>Windows DNS, in an Active Directory domain</h3>\
         <pre><code>dnscmd . /RecordAdd EXAMPLE.COM _vlmcs._tcp SRV 0 0 {port} {address}</code></pre>\
         <p>or the PowerShell equivalent:</p>\
         <pre><code>Add-DnsServerResourceRecord -ZoneName EXAMPLE.COM ``\n\
         &nbsp; -Name _vlmcs._tcp -Srv -Priority 0 -Weight 0 ``\n\
         &nbsp; -Port {port} -DomainName {address}</code></pre>\
         <p>Replace <code>EXAMPLE.COM</code> with the domain the clients \
         search — their primary DNS suffix, which in a domain is the domain \
         itself.</p>\
         \
         <h2>Checking it</h2>\
         <pre><code>nslookup -type=srv _vlmcs._tcp.EXAMPLE.COM\nslmgr /dlv</code></pre>\
         <p><code>/dlv</code> prints the host it used and the activation \
         interval, which is the quickest way to tell &lsquo;the client never \
         found a host&rsquo; from &lsquo;the client found one and did not like \
         the answer&rsquo;.</p>"
    );

    page("Instructions", &body)
}

/// What the instructions say when the `Host` header did not survive filtering.
///
/// A placeholder rather than a guess. A host with several interfaces cannot
/// know which one its clients route to, and on Hermit `bind()` does not record
/// an address at all (`OS-009`, #260), so there is nothing honest to print.
const HOST_PLACEHOLDER: &str = "KMS-HOST";

/// Whether an address is one Windows clients refuse to activate against
/// (`NET-014`, #163).
///
/// Text rather than a parsed address, because this is the string that came out
/// of a `Host` header and it may be a name. `localhost` counts: it resolves to
/// loopback everywhere that matters, and an operator who typed it is in exactly
/// the situation this warning is for.
fn is_loopback_text(address: &str) -> bool {
    let bare = address.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare == "::1"
        || bare
            .parse::<core::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `/products` — what this host knows how to activate (`DB-013`, #137).
fn products_page() -> String {
    let mut body = String::new();
    let _: core::fmt::Result = write!(
        body,
        "<p>{} products from {} host keys, extracted from Microsoft's own \
         licensing artifacts. A client needs the generic volume licence key \
         for its edition; the protocol never carries one.</p>",
        kmsrs_db::PRODUCTS.len(),
        kmsrs_db::CSVLKS.len()
    );

    body.push_str("<table><tr><th>Product</th><th>Edition</th><th>Kind</th></tr>");
    // Bounded by the shipped table, which is a compile-time constant, so this
    // render cannot grow with uptime (`OBS-012`, #188).
    for product in kmsrs_db::PRODUCTS {
        if product.kind != kmsrs_db::KeyKind::KmsClient {
            continue;
        }
        let _: core::fmt::Result = write!(
            body,
            "<tr><td>{}</td><td><code>{}</code></td><td>{:?}</td></tr>",
            escape(product.description),
            escape(product.edition_id),
            product.kind
        );
    }
    body.push_str("</table>");
    page("Products", &body)
}

/// `/metrics` — the Prometheus exposition format (`OBS-013`, #189).
///
/// Counters only, and every one of them is something already counted for
/// another reason. A metric that needs its own bookkeeping is a second place
/// for the number to be wrong.
fn metrics(snapshot: &Snapshot<'_>) -> String {
    let log = snapshot.events;
    let dropped = log.dropped();
    let activated = log.iter().filter(|event| event.activated()).count();

    let mut out = String::with_capacity(1024);
    for (name, help, kind, value) in [
        (
            "kmsrsos_requests_total",
            "Requests recorded since start.",
            "counter",
            log.recorded(),
        ),
        (
            "kmsrsos_activations_total",
            "Requests in the retained window that were activated.",
            "gauge",
            activated as u64,
        ),
        (
            "kmsrsos_events_held",
            "Events currently in the bounded log.",
            "gauge",
            log.len() as u64,
        ),
        (
            "kmsrsos_events_dropped_by_capacity_total",
            "Events evicted because the log was full.",
            "counter",
            dropped.by_capacity,
        ),
        (
            "kmsrsos_events_dropped_by_retention_total",
            "Events removed because they aged out.",
            "counter",
            dropped.by_retention,
        ),
        (
            "kmsrsos_listener_up",
            "1 when the KMS listener is accepting.",
            "gauge",
            u64::from(snapshot.listening),
        ),
        (
            "kmsrsos_entropy_healthy",
            "1 when the entropy source passes its self-test.",
            "gauge",
            u64::from(snapshot.entropy_healthy),
        ),
    ] {
        let _: core::fmt::Result = write!(
            out,
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        );
    }

    // `CFG-008` (#173). The conventional shape for build metadata in Prometheus
    // is a constant-1 gauge carrying labels, because a version is not a number
    // and pretending otherwise makes it unqueryable. Full revision here rather
    // than the shortened one: this reader is a machine.
    //
    // The label values are compile-time constants from `option_env!`, so
    // nothing a client sends can reach them — but they are escaped anyway,
    // because the day one of them becomes dynamic is the day nobody remembers
    // this sentence.
    let stamp = crate::config::stamp::BUILD;
    let _: core::fmt::Result = write!(
        out,
        "# HELP kmsrsos_build_info Which build this is; the value is always 1.\n\
         # TYPE kmsrsos_build_info gauge\n\
         kmsrsos_build_info{{version=\"{}\",revision=\"{}\",source_date_epoch=\"{}\"}} 1\n",
        escape_label(stamp.version),
        escape_label(stamp.revision),
        escape_label(stamp.source_date_epoch),
    );
    out
}

/// Escape a Prometheus label value.
///
/// Backslash, double quote and newline are the three characters the exposition
/// format gives meaning to inside a label value.
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Whether a method reaches a route at all.
///
/// Only `GET` and `HEAD` exist in [`Method`], so this is total by
/// construction — the assertion `OBS-010` (#186) needs is that no fourth
/// variant appears without somebody deciding what it does.
#[must_use]
pub const fn is_read_only(method: Method) -> bool {
    match method {
        Method::Get | Method::Head => true,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{EVENTS_PER_PAGE, Snapshot, route};
    use crate::web::request::{Method, Parsed, parse};
    use crate::web::response::Status;
    use kmsrs_policy::events::EventLog;
    use kmsrs_policy::identity::HostIdentity;
    use kmsrs_proto::entropy::testing::DeterministicEntropy;

    /// Every route this host serves.
    const ROUTES: &[&str] = &[
        "/",
        "/events",
        "/instructions",
        "/products",
        "/healthz",
        "/metrics",
    ];

    struct Fixture {
        identity: HostIdentity,
        events: EventLog,
    }

    impl Fixture {
        fn new() -> Self {
            let mut entropy = DeterministicEntropy::from_seed(0x0B5_0008);
            Self {
                identity: HostIdentity::generate(
                    &mut entropy,
                    kmsrs_db::Date::new(2026, 8, 23).unwrap(),
                )
                .unwrap(),
                events: EventLog::new(4096, core::time::Duration::from_hours(24)),
            }
        }

        fn snapshot(&self) -> Snapshot<'_> {
            Snapshot {
                listening: true,
                entropy_healthy: true,
                kms_ports: &[1688],
                identity: &self.identity,
                events: &self.events,
            }
        }
    }

    /// Render one page and hand back its body.
    fn body_of(fixture: &Fixture, target: &str) -> String {
        let raw = request(target);
        let Parsed::Complete(parsed) = parse(&raw) else {
            panic!("{target} did not parse");
        };
        route(&parsed, &fixture.snapshot()).body
    }

    fn request(target: &str) -> Vec<u8> {
        format!("GET {target} HTTP/1.1\r\nHost: k\r\n\r\n").into_bytes()
    }

    /// A request that names a particular `Host`, which is what the
    /// instructions page renders its addresses from (`DISC-006`, #148).
    fn request_from(target: &str, host: &str) -> Vec<u8> {
        format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
    }

    /// Render one page and hand back its body.
    fn render(fixture: &Fixture, target: &str, host: &str) -> String {
        let raw = request_from(target, host);
        let Parsed::Complete(parsed) = parse(&raw) else {
            panic!("{target} did not parse");
        };
        route(&parsed, &fixture.snapshot()).body
    }

    /// `DISC-006` (#148): all three DNS forms are rendered, with this
    /// instance's real address and port in them.
    ///
    /// The address is the one the operator's own browser reached the server
    /// on, which is the only address this host can honestly claim its clients
    /// can route to — a machine with three interfaces does not know which, and
    /// on Hermit `bind()` records no address at all.
    #[test]
    fn the_instructions_render_every_dns_form_with_live_values() {
        let fixture = Fixture::new();
        let body = render(&fixture, "/instructions", "kms.example.net:8080");

        // The web UI's port must not leak into instructions about the KMS one.
        assert!(
            body.contains("slmgr /skms kms.example.net:1688"),
            "the slmgr line is missing or has the wrong port:\n{body}"
        );
        assert!(
            !body.contains(":8080"),
            "the web port reached the KMS advice"
        );

        // `DISC-007` (#149): the record shape, with priority and weight zero
        // by convention and the port this host actually listens on.
        assert!(
            body.contains("_vlmcs._tcp  IN  SRV  0 0 1688  kms.example.net."),
            "the zone snippet is missing:\n{body}"
        );
        assert!(body.contains("nsupdate"), "the nsupdate form is missing");
        assert!(body.contains("dnscmd"), "the dnscmd form is missing");
        assert!(
            body.contains("Add-DnsServerResourceRecord"),
            "the PowerShell form is missing"
        );
        // And the `slmgr /skms` fallback for a client that cannot use DNS.
        assert!(body.contains("ospp.vbs"), "Office is not covered");
    }

    /// `NET-014` (#163): a page reached over loopback says so, loudly.
    ///
    /// Windows clients refuse to activate against 127.0.0.1 whatever the port.
    /// That is the entire reason vlmcsd carries a 370-line TAP driver that
    /// rewrites ip_src and ip_dst on every packet (declined item D21), and an
    /// operator who has just browsed to localhost is about to spend an
    /// afternoon on it.
    #[test]
    fn the_instructions_warn_when_reached_over_loopback() {
        let fixture = Fixture::new();

        for host in [
            "127.0.0.1:8080",
            "localhost:8080",
            "[::1]:8080",
            "127.9.9.9",
        ] {
            let body = render(&fixture, "/instructions", host);
            assert!(
                body.contains("will not activate against"),
                "{host} produced no loopback warning:\n{body}"
            );
        }

        for host in ["kms.example.net:8080", "10.0.0.5", "[2001:db8::1]:8080"] {
            let body = render(&fixture, "/instructions", host);
            assert!(
                !body.contains("will not activate against"),
                "{host} produced a loopback warning it should not have"
            );
        }
    }

    /// The `Host` header is client-controlled, so a hostile one produces a
    /// placeholder rather than reaching the page.
    ///
    /// Two independent defences and this is the first: the value is filtered
    /// down to a hostname or an IP literal before anything renders it, and
    /// whatever survives is HTML-escaped. The page's
    /// Content-Security-Policy has no `script-src` at all, which is the third.
    #[test]
    fn a_hostile_host_header_never_reaches_the_page() {
        let fixture = Fixture::new();
        for host in [
            "<script>alert(1)</script>",
            "a\"onmouseover=\"x",
            "exa mple.net",
            "kms.example.net/../..",
        ] {
            let body = render(&fixture, "/instructions", host);
            assert!(
                body.contains("KMS-HOST"),
                "{host} did not fall back to the placeholder:\n{body}"
            );
            assert!(!body.contains("<script>"), "{host} reached the page");
            assert!(!body.contains("onmouseover"), "{host} reached the page");
        }
    }

    /// An absent `Host` is not an error — HTTP/1.0 does not require one — and
    /// the page still renders, with the placeholder.
    #[test]
    fn the_instructions_render_without_a_host_header() {
        let fixture = Fixture::new();
        let raw = b"GET /instructions HTTP/1.0\r\n\r\n";
        let Parsed::Complete(parsed) = parse(raw) else {
            panic!("a HTTP/1.0 request without a Host did not parse");
        };
        assert_eq!(parsed.host, None);
        let body = route(&parsed, &fixture.snapshot()).body;
        assert!(body.contains("KMS-HOST"));
        assert!(body.contains("1688"));
    }

    #[test]
    fn every_route_answers_200() {
        let fixture = Fixture::new();
        for target in ROUTES {
            let raw = request(target);
            let Parsed::Complete(parsed) = parse(&raw) else {
                panic!("{target} did not parse");
            };
            let response = route(&parsed, &fixture.snapshot());
            assert_eq!(response.status, Status::Ok, "{target}");
            assert!(!response.body.is_empty(), "{target} rendered nothing");
        }
    }

    /// `/` is matched exactly, so there is no path under which an unknown
    /// route becomes an index.
    #[test]
    fn an_unknown_route_is_404_and_not_an_index() {
        let fixture = Fixture::new();
        for target in [
            "/nope",
            "/events/",
            "/events/1",
            "/..",
            "/%2e%2e/",
            "//",
            "/index.html",
            "/favicon.ico",
        ] {
            let raw = request(target);
            let Parsed::Complete(parsed) = parse(&raw) else {
                continue;
            };
            let response = route(&parsed, &fixture.snapshot());
            assert_eq!(response.status, Status::NotFound, "{target}");
        }
    }

    /// `OBS-008` (#184): health is about the KMS listener, not this handler.
    #[test]
    fn healthz_is_503_when_the_kms_listener_is_down() {
        let fixture = Fixture::new();
        let raw = request("/healthz");
        let Parsed::Complete(parsed) = parse(&raw) else {
            panic!("/healthz did not parse");
        };

        let mut snapshot = fixture.snapshot();
        snapshot.listening = false;
        let response = route(&parsed, &snapshot);
        assert_eq!(
            response.status,
            Status::ServiceUnavailable,
            "the health endpoint reported healthy while the KMS listener was \
             down, which is the Organization fork's readyz"
        );
        assert!(response.body.contains("listener"));
    }

    #[test]
    fn healthz_is_503_when_entropy_is_failing() {
        let fixture = Fixture::new();
        let raw = request("/healthz");
        let Parsed::Complete(parsed) = parse(&raw) else {
            panic!("/healthz did not parse");
        };

        let mut snapshot = fixture.snapshot();
        snapshot.entropy_healthy = false;
        assert_eq!(
            route(&parsed, &snapshot).status,
            Status::ServiceUnavailable,
            "a host that cannot draw entropy reported healthy"
        );
    }

    #[test]
    fn healthz_is_503_when_nothing_is_bound() {
        let fixture = Fixture::new();
        let raw = request("/healthz");
        let Parsed::Complete(parsed) = parse(&raw) else {
            panic!("/healthz did not parse");
        };
        let mut snapshot = fixture.snapshot();
        snapshot.kms_ports = &[];
        assert_eq!(route(&parsed, &snapshot).status, Status::ServiceUnavailable);
    }

    /// `OBS-009` (#185): a failing health check says which condition failed and
    /// nothing else.
    #[test]
    fn no_page_leaks_an_internal_name() {
        let fixture = Fixture::new();
        let mut snapshot = fixture.snapshot();
        snapshot.listening = false;
        snapshot.entropy_healthy = false;

        for target in ROUTES {
            let raw = request(target);
            let Parsed::Complete(parsed) = parse(&raw) else {
                continue;
            };
            let body = route(&parsed, &snapshot).body;
            for secret in ["/nix/store", "/home/", "src/", "panicked", ".rs:", "Err("] {
                assert!(
                    !body.contains(secret),
                    "{target} leaked {secret:?}:\n{body}"
                );
            }
        }
    }

    /// `OBS-011` (#187): the header is never read, so there is nothing to
    /// bypass.
    #[test]
    fn x_forwarded_for_appears_nowhere_in_the_web_module() {
        let sources = [
            include_str!("routes.rs"),
            include_str!("request.rs"),
            include_str!("response.rs"),
            include_str!("mod.rs"),
        ];
        for source in sources {
            // Only the shipped half: the test module below necessarily names
            // the header, and a scan that included itself would be checking
            // that this test does not exist.
            let shipped = source.split("#[cfg(test)]").next().unwrap_or(source);
            for line in shipped.lines() {
                let lowered = line.to_ascii_lowercase();
                if !lowered.contains("x-forwarded-for") && !lowered.contains("x_forwarded_for") {
                    continue;
                }
                // A mention in a comment is the point; a mention in code is the
                // defect. Comment lines start with `//` after trimming.
                let trimmed = line.trim_start();
                assert!(
                    trimmed.starts_with("//") || trimmed.starts_with("/// "),
                    "the web module reads X-Forwarded-For, which any client can \
                     set: {line}"
                );
            }
        }
    }

    /// `OBS-012` (#188): a render is bounded by the page, not by the log.
    #[test]
    fn the_events_page_is_bounded_by_the_page_size() {
        let mut fixture = Fixture::new();
        for index in 0..(EVENTS_PER_PAGE * 3) {
            record(&mut fixture.events, index);
        }

        let raw = request("/events");
        let Parsed::Complete(parsed) = parse(&raw) else {
            panic!("/events did not parse");
        };
        let body = route(&parsed, &fixture.snapshot()).body;

        let rows = body.matches("<tr>").count();
        assert!(
            rows <= EVENTS_PER_PAGE + 1,
            "a log of {} events rendered {rows} rows",
            fixture.events.len()
        );
        assert!(rows > 1, "the page rendered no events at all");
    }

    /// A workstation name is text a client chose (`POL-015`, #103).
    #[test]
    fn a_hostile_workstation_name_cannot_break_the_page() {
        let mut fixture = Fixture::new();
        record_named(&mut fixture.events, "<script>alert(1)</script>");
        record_named(&mut fixture.events, "\"' onload=x");

        let raw = request("/events");
        let Parsed::Complete(parsed) = parse(&raw) else {
            panic!("/events did not parse");
        };
        let body = route(&parsed, &fixture.snapshot()).body;

        assert!(
            !body.contains("<script>"),
            "a client's name reached the page unescaped:\n{body}"
        );
        assert!(
            body.contains("&lt;script&gt;"),
            "the name was dropped rather than escaped"
        );
    }

    /// `OBS-013` (#189): a Prometheus scrape has to parse.
    #[test]
    fn the_metrics_page_is_well_formed_exposition() {
        let fixture = Fixture::new();
        let raw = request("/metrics");
        let Parsed::Complete(parsed) = parse(&raw) else {
            panic!("/metrics did not parse");
        };
        let body = route(&parsed, &fixture.snapshot()).body;

        let mut names = Vec::new();
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let mut parts = rest.split(' ');
                let name = parts.next().expect("a TYPE line names a metric");
                let kind = parts.next().expect("a TYPE line states a type");
                assert!(
                    ["counter", "gauge"].contains(&kind),
                    "{name} has type {kind}"
                );
                names.push(name.to_owned());
            } else if !line.starts_with('#') && !line.is_empty() {
                let mut parts = line.split(' ');
                let sample = parts.next().expect("a sample names a metric");
                let value = parts.next().expect("a sample has a value");
                // A sample may carry labels — `name{a="b"} 1` — and the metric
                // is the part before the brace.
                let name = sample.split_once('{').map_or(sample, |(name, _)| name);
                assert!(
                    names.iter().any(|declared| declared == name),
                    "{name} has a sample with no TYPE"
                );
                assert!(
                    value.parse::<f64>().is_ok(),
                    "{name} has the unparseable value {value:?}"
                );
            }
        }
        assert!(names.len() >= 5, "only {} metrics", names.len());
        assert!(names.iter().all(|name| name.starts_with("kmsrsos_")));
    }

    /// `OBS-006` (#182): one machine with two products is two rows.
    ///
    /// The status page's fleet view is keyed on `(machine, SKU)`, because a box
    /// running Windows Enterprise and Office LTSC is two things an operator
    /// maintains. The *count* a client is told is keyed differently and is not
    /// derived from this — see `EventLog::clients`.
    #[test]
    fn the_status_page_shows_one_row_per_machine_and_product() {
        let mut fixture = Fixture::new();
        let machine = kmsrs_db::Guid::from_bytes([0xAB; 16]);
        record_request(&mut fixture.events, machine, [0x01; 16], [0x55; 16]);
        record_request(&mut fixture.events, machine, [0x02; 16], [0x0F; 16]);
        // And the same machine and SKU again, which must not add a third row.
        record_request(&mut fixture.events, machine, [0x01; 16], [0x55; 16]);

        let body = body_of(&fixture, "/");
        assert!(body.contains("Machines seen"), "{body}");

        let rows = body.matches(&machine.to_string()).count();
        assert_eq!(
            rows, 2,
            "one machine with two products should be two rows:\n{body}"
        );
        assert!(
            body.contains(&kmsrs_db::Guid::from_bytes([0x01; 16]).to_string()),
            "the first SKU is missing"
        );
        assert!(
            body.contains(&kmsrs_db::Guid::from_bytes([0x02; 16]).to_string()),
            "the second SKU is missing"
        );
    }

    /// A host that has seen nobody says so, rather than rendering an empty
    /// table an operator has to interpret.
    #[test]
    fn the_fleet_view_says_when_it_is_empty() {
        let fixture = Fixture::new();
        assert!(body_of(&fixture, "/").contains("nothing yet"));
    }

    /// `CFG-008` (#173): which build this is, in both places an operator looks.
    ///
    /// A constant-1 gauge with labels is the conventional shape for build
    /// metadata, because a version is not a number and pretending otherwise
    /// makes it unqueryable.
    #[test]
    fn the_build_stamp_appears_on_the_status_page_and_in_metrics() {
        let fixture = Fixture::new();
        let stamp = crate::config::stamp::BUILD;

        let metrics = body_of(&fixture, "/metrics");
        assert!(
            metrics.contains(&format!("version=\"{}\"", stamp.version)),
            "the build version is not in /metrics:\n{metrics}"
        );
        assert!(
            metrics.contains(&format!("revision=\"{}\"", stamp.revision)),
            "the full revision is not in /metrics — a machine reads this one"
        );
        assert!(metrics.contains("kmsrsos_build_info"));

        // The status page carries the shortened form, because a person reads
        // that one.
        let status = body_of(&fixture, "/");
        assert!(
            status.contains(stamp.short_revision()),
            "the build stamp is not on the status page:\n{status}"
        );
        assert!(status.contains(stamp.version));
    }

    #[test]
    fn every_metric_declares_help_and_type_before_its_sample() {
        let fixture = Fixture::new();
        let raw = request("/metrics");
        let Parsed::Complete(parsed) = parse(&raw) else {
            panic!("/metrics did not parse");
        };
        let body = route(&parsed, &fixture.snapshot()).body;
        let mut lines = body.lines();
        while let Some(help) = lines.next() {
            if help.is_empty() {
                continue;
            }
            assert!(help.starts_with("# HELP "), "expected HELP, got {help:?}");
            let kind = lines.next().expect("HELP is followed by TYPE");
            assert!(kind.starts_with("# TYPE "), "expected TYPE, got {kind:?}");
            let sample = lines.next().expect("TYPE is followed by a sample");
            assert!(
                !sample.starts_with('#'),
                "expected a sample, got {sample:?}"
            );
        }
    }

    /// The structural half of `OBS-010` (#186).
    #[test]
    fn only_read_only_methods_exist() {
        assert!(super::is_read_only(Method::Get));
        assert!(super::is_read_only(Method::Head));
        assert!(Method::parse("POST").is_none());
        assert!(Method::parse("DELETE").is_none());
    }

    /// No page offers a control, because there is nothing durable to mutate.
    #[test]
    fn no_page_contains_a_form_or_a_script() {
        let fixture = Fixture::new();
        for target in ROUTES {
            let raw = request(target);
            let Parsed::Complete(parsed) = parse(&raw) else {
                continue;
            };
            let body = route(&parsed, &fixture.snapshot())
                .body
                .to_ascii_lowercase();
            for forbidden in ["<form", "<script", "<button", "onclick", "method=\"post\""] {
                assert!(
                    !body.contains(forbidden),
                    "{target} contains {forbidden:?}, which a read-only UI has \
                     no use for"
                );
            }
        }
    }

    /// The stylesheet is inline, so there is no CDN to be offline from.
    #[test]
    fn no_page_fetches_anything_from_the_network() {
        let fixture = Fixture::new();
        for target in ROUTES {
            let raw = request(target);
            let Parsed::Complete(parsed) = parse(&raw) else {
                continue;
            };
            let body = route(&parsed, &fixture.snapshot())
                .body
                .to_ascii_lowercase();
            for forbidden in ["http://", "https://", "//cdn", "<link", "<img", "@import"] {
                assert!(
                    !body.contains(forbidden),
                    "{target} reaches the network via {forbidden:?}"
                );
            }
        }
    }

    // -- fixtures ----------------------------------------------------------

    fn record(log: &mut EventLog, index: usize) {
        record_named(log, &format!("host-{index}"));
    }

    fn record_named(log: &mut EventLog, name: &str) {
        record_full(log, name, [0x44; 16], [0x22; 16], [0x11; 16]);
    }

    /// One request from a named machine, for a named SKU and application.
    ///
    /// The three GUIDs are what `OBS-006` (#182) is about: the fleet view keys
    /// on `(machine, SKU)` and the count keys on `(machine, application)`, so a
    /// fixture that could only vary one of them could not tell the two apart.
    fn record_request(
        log: &mut EventLog,
        machine: kmsrs_db::Guid,
        sku: [u8; 16],
        application: [u8; 16],
    ) {
        record_full(log, "WKS-000001", machine.to_bytes(), sku, application);
    }

    fn record_full(
        log: &mut EventLog,
        name: &str,
        machine: [u8; 16],
        sku: [u8; 16],
        application: [u8; 16],
    ) {
        use kmsrs_proto::kms::request::Request as KmsRequest;
        use kmsrs_proto::kms::status::LicenseStatus;
        use kmsrs_proto::kms::version::ProtocolVersion;
        use kmsrs_proto::time::{FileTime, Instant};
        use kmsrs_proto::types::{
            ApplicationId, ClientKind, ClientMachineId, ClientTime, GraceMinutes, KmsCountedId,
            RequiredClients, SkuId, WorkstationName,
        };

        let mut units = [0_u16; kmsrs_proto::types::WORKSTATION_NAME_UNITS];
        for (slot, unit) in units.iter_mut().zip(name.encode_utf16()) {
            *slot = unit;
        }

        let request = KmsRequest {
            version: ProtocolVersion::from_wire(0x0006_0000),
            client_kind: ClientKind::BareMetal,
            license_status: LicenseStatus::from_wire(2),
            grace: GraceMinutes(0),
            application: ApplicationId(kmsrs_db::Guid::from_bytes(application)),
            sku: SkuId(kmsrs_db::Guid::from_bytes(sku)),
            counted: KmsCountedId(kmsrs_db::Guid::from_bytes([0x33; 16])),
            client_machine_id: ClientMachineId(kmsrs_db::Guid::from_bytes(machine)),
            previous_client_machine_id: None,
            client_time: ClientTime(FileTime::from_ticks(133_000_000_000_000_000)),
            required_clients: RequiredClients(25),
            workstation_name: WorkstationName::decode(&units),
        };
        log.record(
            &request,
            None,
            Instant::from_nanos(1),
            kmsrs_policy::events::Outcome::Refused(kmsrs_policy::gate::Refusal::PreviewProduct),
            kmsrs_policy::gate::Observations {
                known_product: false,
                clock_skew: None,
                clock_skewed: false,
            },
        );
    }
}

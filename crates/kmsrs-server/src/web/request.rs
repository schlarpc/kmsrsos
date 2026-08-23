//! A bounded HTTP/1.1 request parser (`OBS-007`, #183; `OBS-012`, #188).
//!
//! # Sans-io, like everything else that sees a byte from a socket
//!
//! Bytes in, a decision out. No socket, no clock, no allocation beyond what the
//! caller supplies. That is what lets the whole parser be fuzzed
//! (`SEC-013`, #306) and tested without binding a port, and it is the same
//! discipline `kmsrs-proto` is built on (axiom A7).
//!
//! # Everything is bounded before it is read
//!
//! This parser is the most exposed surface in the tree once it is listening: it
//! reads variable-length text off a socket with no fixed frame in front of it,
//! and it is reachable by anything that can open a TCP connection — not only by
//! a KMS client. So every limit is a constant here, checked before the bytes it
//! guards are looked at:
//!
//! * [`MAX_REQUEST_LINE`] — the method, target and version.
//! * [`MAX_HEADER_LINE`] — one header.
//! * [`MAX_HEADERS`] — how many.
//! * [`MAX_REQUEST`] — the whole head, which is the only thing that is read at
//!   all.
//!
//! MelroyB's dashboard is the counter-example the issue names: its login rate
//! limiter keys on `X-Forwarded-For`, and its event view sorts the whole log
//! per render. Neither is possible here, because neither the header nor an
//! unbounded read is available to reach for.
//!
//! # What is deliberately not implemented
//!
//! No request body, no chunked transfer, no keep-alive, no compression, no
//! ranges, no conditional requests. The web UI is strictly read-only
//! (`OBS-010`, #186), so a body is something no legitimate client sends — and
//! every one of those features is a parser somebody has to get right. A
//! `Content-Length` above zero is refused rather than skipped, because reading
//! and discarding a body is exactly the unbounded read this module exists
//! without.

use core::fmt;

/// The longest request line this host will read, including the method and the
/// HTTP version.
///
/// Generous for a UI whose longest path is `/instructions`, and far below what
/// a header-smuggling probe needs.
pub const MAX_REQUEST_LINE: usize = 2048;

/// The longest single header line.
pub const MAX_HEADER_LINE: usize = 1024;

/// How many headers are read before the request is refused.
///
/// Nothing here reads more than `Host`, so the limit exists to bound work
/// rather than to accommodate anything.
pub const MAX_HEADERS: usize = 64;

/// The longest complete request head — everything up to the blank line.
///
/// The buffer a driver reserves per web connection, and the point past which
/// more bytes are refused rather than buffered (`OBS-012`, #188).
pub const MAX_REQUEST: usize = 8192;

/// The methods this host answers.
///
/// A read-only UI has no use for anything else, and a method it does not
/// implement is answered with 405 rather than treated as a path
/// (`OBS-010`, #186).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// The only method that returns a body.
    Get,
    /// The same, without the body — so a monitor can check a page exists
    /// without paying for it.
    Head,
}

impl Method {
    /// Parse a method token.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "GET" => Some(Self::Get),
            "HEAD" => Some(Self::Head),
            _ => None,
        }
    }

    /// Whether a response to this method carries its body.
    #[must_use]
    pub const fn wants_body(self) -> bool {
        matches!(self, Self::Get)
    }
}

/// A parsed request head.
///
/// Borrows from the caller's buffer. Nothing is copied and nothing is
/// allocated, which is also why the lifetime is visible: a caller cannot keep
/// this past the bytes it describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    /// The method.
    pub method: Method,
    /// The path, with any query string removed and no percent-decoding.
    ///
    /// Not decoded on purpose. Every route this host serves is a fixed string,
    /// so a decoder would exist only to make `/%65vents` work — which is to say
    /// only to make two spellings of one route, which is how path-traversal
    /// bugs are written. An encoded path simply matches nothing.
    pub path: &'a str,
    /// The query string, if any, undecoded and unparsed.
    pub query: Option<&'a str>,
    /// How many bytes of the buffer the head occupied, including the blank
    /// line. A driver consumes exactly this many.
    pub head_len: usize,
    /// The `Host` header, if it is one this host will repeat back
    /// (`DISC-006`, #148).
    ///
    /// The one header that is read at all, and it exists for one page: the
    /// instructions render `slmgr /skms` and a DNS zone snippet, and the
    /// address that belongs in them is *the address that reached this server* —
    /// which the operator's own browser has just demonstrated. Enumerating
    /// interfaces would be a worse answer as well as a syscall: a host with
    /// three NICs has no way to know which one its clients route to, and on
    /// Hermit `bind()` does not record an address at all (`OS-009`, #260).
    ///
    /// **Client-controlled**, so it is filtered rather than trusted: see
    /// [`plausible_host`]. Everything downstream also HTML-escapes it, and the
    /// page's Content-Security-Policy has no `script-src` at all.
    pub host: Option<&'a str>,
}

/// Why a request could not be answered as asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// The request line was longer than [`MAX_REQUEST_LINE`].
    RequestLineTooLong,
    /// A header line was longer than [`MAX_HEADER_LINE`].
    HeaderTooLong,
    /// More than [`MAX_HEADERS`] headers.
    TooManyHeaders,
    /// The head was longer than [`MAX_REQUEST`], or is still incomplete at
    /// that length.
    HeadTooLong,
    /// The request line was not `METHOD TARGET HTTP/1.x`.
    MalformedRequestLine,
    /// A method this host does not implement.
    UnsupportedMethod,
    /// An HTTP version this host does not speak.
    UnsupportedVersion,
    /// A header line with no colon.
    MalformedHeader,
    /// A request declaring a body, which a read-only UI never needs
    /// (`OBS-010`, #186).
    BodyNotAllowed,
    /// Bytes that are not UTF-8. A request line is ASCII by specification.
    NotText,
}

impl RequestError {
    /// The status code this refusal is answered with.
    ///
    /// Named here rather than at the call site so the mapping is one table
    /// rather than a `match` somebody can get half-right.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::RequestLineTooLong => 414,
            Self::HeaderTooLong | Self::TooManyHeaders | Self::HeadTooLong => 431,
            Self::UnsupportedMethod => 405,
            Self::UnsupportedVersion => 505,
            Self::BodyNotAllowed => 413,
            Self::MalformedRequestLine | Self::MalformedHeader | Self::NotText => 400,
        }
    }
}

impl fmt::Display for RequestError {
    /// Deliberately terse and constant.
    ///
    /// These strings can reach an unauthenticated caller, so none of them
    /// contains anything the caller did not already know — no echoed path, no
    /// length, no internal name. The Organization fork's `/readyz` returns
    /// `Whooops! {e}` including filesystem paths (`OBS-009`, #185).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RequestLineTooLong => "request line too long",
            Self::HeaderTooLong => "header too long",
            Self::TooManyHeaders => "too many headers",
            Self::HeadTooLong => "request head too long",
            Self::MalformedRequestLine => "malformed request line",
            Self::UnsupportedMethod => "unsupported method",
            Self::UnsupportedVersion => "unsupported HTTP version",
            Self::MalformedHeader => "malformed header",
            Self::BodyNotAllowed => "request body not allowed",
            Self::NotText => "malformed request",
        })
    }
}

/// What a driver should do with the bytes it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed<'a> {
    /// No blank line yet. Read more — unless the buffer is already at
    /// [`MAX_REQUEST`], which is [`RequestError::HeadTooLong`].
    Incomplete,
    /// A complete, answerable request.
    Complete(Request<'a>),
    /// A complete request that will not be answered as asked.
    Refused(RequestError),
}

/// Parse a request head.
///
/// Returns [`Parsed::Incomplete`] until the blank line arrives, so a driver
/// loops on it the way the KMS state machine loops on `Step::NeedMore`.
///
/// # The order of the checks
///
/// Length first, then shape, then meaning. A request that is too long is
/// refused before its request line is searched for spaces, and the header count
/// is bounded before the headers are walked. Doing it the other way round is
/// the shape of the KMD-loader defects (`SEC-003`, #195): validation that runs
/// after the loop that already read.
#[must_use]
pub fn parse(buffer: &[u8]) -> Parsed<'_> {
    let Some(head_len) = head_end(buffer) else {
        return if buffer.len() >= MAX_REQUEST {
            Parsed::Refused(RequestError::HeadTooLong)
        } else {
            Parsed::Incomplete
        };
    };
    if head_len > MAX_REQUEST {
        return Parsed::Refused(RequestError::HeadTooLong);
    }

    let Some(head) = buffer.get(..head_len) else {
        return Parsed::Refused(RequestError::HeadTooLong);
    };
    // A request line is ASCII by specification. Refusing non-UTF-8 outright
    // means nothing below has to reason about encodings.
    let Ok(text) = core::str::from_utf8(head) else {
        return Parsed::Refused(RequestError::NotText);
    };

    let mut lines = text.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Parsed::Refused(RequestError::MalformedRequestLine);
    };
    if request_line.len() > MAX_REQUEST_LINE {
        return Parsed::Refused(RequestError::RequestLineTooLong);
    }

    let (method, target) = match parse_request_line(request_line) {
        Ok(parts) => parts,
        Err(error) => return Parsed::Refused(error),
    };

    let mut count = 0_usize;
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        count = count.saturating_add(1);
        if count > MAX_HEADERS {
            return Parsed::Refused(RequestError::TooManyHeaders);
        }
        if line.len() > MAX_HEADER_LINE {
            return Parsed::Refused(RequestError::HeaderTooLong);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Parsed::Refused(RequestError::MalformedHeader);
        };
        if name.is_empty() || name.trim_end() != name {
            // A space before the colon is request smuggling's oldest trick.
            return Parsed::Refused(RequestError::MalformedHeader);
        }
        if declares_a_body(name, value) {
            return Parsed::Refused(RequestError::BodyNotAllowed);
        }
        // The first `Host` wins. A second one is not refused — this is not a
        // proxy and there is nothing downstream to disagree with — but neither
        // is it allowed to overwrite the first, which is the half of request
        // smuggling that is about *which* value gets used.
        if host.is_none() && name.eq_ignore_ascii_case("Host") {
            host = plausible_host(value.trim());
        }
    }

    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };

    Parsed::Complete(Request {
        method,
        path,
        query,
        head_len,
        host,
    })
}

/// The host part of a `Host` header, if it is one worth repeating back
/// (`DISC-006`, #148).
///
/// The port is dropped — the instructions are about the **KMS** port, and the
/// one in the header is the web UI's. An IPv6 literal keeps its brackets,
/// because that is how it has to appear in `slmgr /skms`.
///
/// The filter is an allow-list of the characters a hostname or an IP literal
/// can contain, and it is deliberately narrower than the specification: a
/// `Host` this host does not recognise produces `None` and the page renders a
/// placeholder rather than an attacker's string. Nothing is lost by being
/// strict, because the only reader is an operator looking at their own server.
#[must_use]
pub fn plausible_host(value: &str) -> Option<&str> {
    /// The longest host worth rendering. Longer than any real name and far
    /// shorter than a header line, so this cannot become a way to inflate a
    /// page.
    const MAX_HOST: usize = 255;

    let host = if let Some(rest) = value.strip_prefix('[') {
        // `[::1]:8080` — the brackets are part of the address, the port is not.
        let end = rest.find(']')?;
        value.get(..end.checked_add(2)?)?
    } else {
        match value.split_once(':') {
            Some((host, _port)) => host,
            None => value,
        }
    };

    if host.is_empty() || host.len() > MAX_HOST {
        return None;
    }
    let acceptable = host.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']' | b'_')
    });
    acceptable.then_some(host)
}

/// Split `METHOD TARGET HTTP/1.x` into the two parts that matter.
fn parse_request_line(line: &str) -> Result<(Method, &str), RequestError> {
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(RequestError::MalformedRequestLine);
    };
    if parts.next().is_some() {
        // A space inside the target, which a fixed-route UI never needs and
        // which is how two parsers disagree about where a path ends.
        return Err(RequestError::MalformedRequestLine);
    }
    if target.is_empty() || !target.starts_with('/') {
        // No absolute-form targets and no `*`: this host is not a proxy.
        return Err(RequestError::MalformedRequestLine);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(RequestError::UnsupportedVersion);
    }
    let method = Method::parse(method).ok_or(RequestError::UnsupportedMethod)?;
    Ok((method, target))
}

/// Whether a header announces a body.
///
/// `Content-Length: 0` is allowed, because some clients send it on a GET and
/// refusing would be pedantry. Anything else — a non-zero length, any
/// `Transfer-Encoding` at all — is refused rather than read.
fn declares_a_body(name: &str, value: &str) -> bool {
    if name.eq_ignore_ascii_case("transfer-encoding") {
        return true;
    }
    if name.eq_ignore_ascii_case("content-length") {
        return value.trim() != "0";
    }
    false
}

/// Where the head ends, including the terminating blank line.
///
/// Only `\r\n\r\n` counts. Accepting a bare `\n\n` as well would mean this
/// parser and any proxy in front of it could disagree about where the head
/// ends, which is request smuggling.
fn head_end(buffer: &[u8]) -> Option<usize> {
    let limit = buffer.len().min(MAX_REQUEST);
    let window = buffer.get(..limit)?;
    window
        .windows(4)
        .position(|four| four == b"\r\n\r\n")
        .and_then(|start| start.checked_add(4))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{MAX_HEADERS, MAX_REQUEST, Method, Parsed, RequestError, parse};

    fn get(target: &str) -> Vec<u8> {
        format!("GET {target} HTTP/1.1\r\nHost: kms\r\n\r\n").into_bytes()
    }

    #[test]
    fn an_ordinary_get_parses() {
        let raw = get("/events");
        let Parsed::Complete(request) = parse(&raw) else {
            panic!("an ordinary GET was not parsed");
        };
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.path, "/events");
        assert_eq!(request.query, None);
        assert_eq!(request.head_len, raw.len());
    }

    #[test]
    fn a_query_string_is_split_off_and_left_alone() {
        let raw = get("/events?page=2&x=%20");
        let Parsed::Complete(request) = parse(&raw) else {
            panic!("a query string was not parsed");
        };
        assert_eq!(request.path, "/events");
        assert_eq!(request.query, Some("page=2&x=%20"));
    }

    /// Every route is a fixed string, so an encoded path matches nothing rather
    /// than matching a second spelling of something.
    #[test]
    fn a_percent_encoded_path_is_not_decoded() {
        let raw = get("/%65vents");
        let Parsed::Complete(request) = parse(&raw) else {
            panic!("an encoded path was not parsed");
        };
        assert_eq!(request.path, "/%65vents");
        assert_ne!(request.path, "/events");
    }

    #[test]
    fn traversal_is_not_resolved_either() {
        for target in ["/../etc/passwd", "/events/../..", "/./events"] {
            let raw = get(target);
            let Parsed::Complete(request) = parse(&raw) else {
                panic!("{target} was not parsed");
            };
            assert_eq!(
                request.path, target,
                "the parser normalised a path, which is how one route acquires \
                 two spellings"
            );
        }
    }

    #[test]
    fn an_incomplete_head_asks_for_more() {
        assert_eq!(parse(b""), Parsed::Incomplete);
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Parsed::Incomplete);
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\nHost: kms\r\n"),
            Parsed::Incomplete
        );
    }

    #[test]
    fn a_head_that_never_ends_is_refused_rather_than_buffered_forever() {
        let flood = vec![b'x'; MAX_REQUEST];
        assert_eq!(
            parse(&flood),
            Parsed::Refused(RequestError::HeadTooLong),
            "a client that never sends a blank line was still being read"
        );
    }

    /// `DISC-006` (#148): the `Host` header is captured, and only the host
    /// part of it.
    ///
    /// The port in that header is the *web UI's*; the instructions page is
    /// about the KMS port, so carrying it through would put the wrong number
    /// in an `slmgr /skms` line an operator is about to paste.
    #[test]
    fn the_host_header_is_captured_without_its_port() {
        for (header, expected) in [
            ("kms.example.net", Some("kms.example.net")),
            ("kms.example.net:8080", Some("kms.example.net")),
            ("10.0.0.5:8080", Some("10.0.0.5")),
            ("[2001:db8::1]:8080", Some("[2001:db8::1]")),
            ("[::1]", Some("[::1]")),
        ] {
            let raw = format!("GET / HTTP/1.1\r\nHost: {header}\r\n\r\n");
            let Parsed::Complete(request) = parse(raw.as_bytes()) else {
                panic!("{header} did not parse");
            };
            assert_eq!(request.host, expected, "{header}");
        }
    }

    /// A `Host` this host does not recognise produces `None`, so the page
    /// renders a placeholder rather than whatever a client sent.
    ///
    /// The filter is an allow-list and deliberately narrower than the
    /// specification permits. Nothing is lost: the only reader is an operator
    /// looking at their own server.
    #[test]
    fn an_implausible_host_header_is_dropped_rather_than_carried() {
        for header in [
            "<script>alert(1)</script>",
            "exa mple.net",
            "kms.example.net/../..",
            "",
        ] {
            let raw = format!("GET / HTTP/1.1\r\nHost: {header}\r\n\r\n");
            match parse(raw.as_bytes()) {
                Parsed::Complete(request) => {
                    assert_eq!(request.host, None, "{header:?} survived the filter");
                }
                // Refused outright is a stronger answer than dropped.
                Parsed::Refused(_) | Parsed::Incomplete => {}
            }
        }
    }

    /// The first `Host` wins. A second cannot overwrite the first, which is the
    /// half of request smuggling that is about *which* value a server uses.
    #[test]
    fn a_second_host_header_cannot_overwrite_the_first() {
        let raw = b"GET / HTTP/1.1\r\nHost: first.example\r\nHost: second.example\r\n\r\n";
        let Parsed::Complete(request) = parse(raw) else {
            panic!("it did not parse");
        };
        assert_eq!(request.host, Some("first.example"));
    }

    #[test]
    fn an_over_long_request_line_is_refused_with_414() {
        let mut request = b"GET /".to_vec();
        request.extend(std::iter::repeat_n(b'a', 4096));
        request.extend_from_slice(b" HTTP/1.1\r\n\r\n");

        let Parsed::Refused(error) = parse(&request) else {
            panic!("a 4 KiB request line was accepted");
        };
        assert_eq!(error, RequestError::RequestLineTooLong);
        assert_eq!(error.status(), 414);
    }

    #[test]
    fn too_many_headers_are_refused_with_431() {
        let mut request = b"GET / HTTP/1.1\r\n".to_vec();
        for index in 0..=MAX_HEADERS {
            request.extend_from_slice(format!("X-{index}: v\r\n").as_bytes());
        }
        request.extend_from_slice(b"\r\n");

        let Parsed::Refused(error) = parse(&request) else {
            panic!("{} headers were accepted", MAX_HEADERS + 1);
        };
        assert_eq!(error, RequestError::TooManyHeaders);
        assert_eq!(error.status(), 431);
    }

    #[test]
    fn an_over_long_header_is_refused() {
        let mut request = b"GET / HTTP/1.1\r\nX-Big: ".to_vec();
        request.extend(std::iter::repeat_n(b'v', 2048));
        request.extend_from_slice(b"\r\n\r\n");

        let Parsed::Refused(error) = parse(&request) else {
            panic!("a 2 KiB header was accepted");
        };
        assert_eq!(error, RequestError::HeaderTooLong);
    }

    /// A read-only UI never needs one, and reading a body to discard it is
    /// exactly the unbounded read this module exists without.
    #[test]
    fn a_declared_body_is_refused_rather_than_read() {
        for header in [
            "Content-Length: 1",
            "Content-Length: 999999999",
            "content-length: 42",
            "Transfer-Encoding: chunked",
            "transfer-encoding: identity",
        ] {
            let request = format!("GET / HTTP/1.1\r\nHost: k\r\n{header}\r\n\r\n");
            let Parsed::Refused(error) = parse(request.as_bytes()) else {
                panic!("{header} was accepted");
            };
            assert_eq!(error, RequestError::BodyNotAllowed, "{header}");
            assert_eq!(error.status(), 413);
        }
    }

    #[test]
    fn a_zero_content_length_is_tolerated() {
        let request = "GET / HTTP/1.1\r\nHost: k\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(parse(request.as_bytes()), Parsed::Complete(_)));
    }

    #[test]
    fn only_get_and_head_are_implemented() {
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "gEt"] {
            let request = format!("{method} / HTTP/1.1\r\nHost: k\r\n\r\n");
            let Parsed::Refused(error) = parse(request.as_bytes()) else {
                panic!("{method} was accepted");
            };
            assert_eq!(error, RequestError::UnsupportedMethod, "{method}");
            assert_eq!(error.status(), 405);
        }
        assert!(matches!(
            parse(b"HEAD / HTTP/1.1\r\nHost: k\r\n\r\n"),
            Parsed::Complete(_)
        ));
    }

    #[test]
    fn an_unknown_http_version_is_refused_with_505() {
        for version in ["HTTP/2.0", "HTTP/0.9", "HTTP/1.2", "RTSP/1.0", ""] {
            let request = format!("GET / {version}\r\nHost: k\r\n\r\n");
            let Parsed::Refused(error) = parse(request.as_bytes()) else {
                panic!("{version:?} was accepted");
            };
            assert!(
                matches!(
                    error,
                    RequestError::UnsupportedVersion | RequestError::MalformedRequestLine
                ),
                "{version:?} produced {error:?}"
            );
        }
    }

    /// A bare `\n\n` must not end the head, or this parser and a proxy in front
    /// of it can disagree about where the request stops.
    #[test]
    fn a_bare_newline_does_not_terminate_the_head() {
        assert_eq!(parse(b"GET / HTTP/1.1\nHost: k\n\n"), Parsed::Incomplete);
    }

    /// A space before the colon is request smuggling's oldest trick.
    #[test]
    fn a_space_before_a_header_colon_is_refused() {
        let request = "GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n";
        assert_eq!(
            parse(request.as_bytes()),
            Parsed::Refused(RequestError::MalformedHeader)
        );
    }

    #[test]
    fn a_proxy_style_absolute_target_is_refused() {
        for target in ["http://elsewhere/", "*", "elsewhere", ""] {
            let request = format!("GET {target} HTTP/1.1\r\nHost: k\r\n\r\n");
            let Parsed::Refused(error) = parse(request.as_bytes()) else {
                panic!("{target:?} was accepted");
            };
            assert_eq!(error, RequestError::MalformedRequestLine, "{target:?}");
        }
    }

    #[test]
    fn non_utf8_is_refused_rather_than_interpreted() {
        let mut request = b"GET /".to_vec();
        request.extend_from_slice(&[0xFF, 0xFE, 0x80]);
        request.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        assert_eq!(parse(&request), Parsed::Refused(RequestError::NotText));
    }

    /// The head length is what a driver consumes, so a second request behind
    /// the first must be left exactly where it is.
    #[test]
    fn the_head_length_leaves_a_pipelined_request_untouched() {
        let mut buffer = get("/first");
        let second = get("/second");
        buffer.extend_from_slice(&second);

        let Parsed::Complete(request) = parse(&buffer) else {
            panic!("the first request was not parsed");
        };
        assert_eq!(request.path, "/first");
        assert_eq!(&buffer[request.head_len..], &second[..]);
    }

    /// No error text may carry anything the caller did not send
    /// (`OBS-009`, #185).
    #[test]
    fn no_refusal_message_echoes_the_request() {
        let secrets = ["/etc/passwd", "kmsrsos", "products.toml", "1688"];
        for error in [
            RequestError::RequestLineTooLong,
            RequestError::HeaderTooLong,
            RequestError::TooManyHeaders,
            RequestError::HeadTooLong,
            RequestError::MalformedRequestLine,
            RequestError::UnsupportedMethod,
            RequestError::UnsupportedVersion,
            RequestError::MalformedHeader,
            RequestError::BodyNotAllowed,
            RequestError::NotText,
        ] {
            let text = error.to_string();
            assert!(!text.is_empty(), "{error:?} has no message");
            for secret in secrets {
                assert!(!text.contains(secret), "{error:?} leaks {secret:?}: {text}");
            }
            assert!(
                (400..=599).contains(&error.status()),
                "{error:?} maps to status {}",
                error.status()
            );
        }
    }
}

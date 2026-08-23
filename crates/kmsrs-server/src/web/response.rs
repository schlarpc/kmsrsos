//! Building an HTTP response (`OBS-007`, #183; `OBS-009`, #185).
//!
//! # Constant text, never a formatted exception
//!
//! The Organization fork's `/readyz` returns `Whooops! {e}` — including
//! filesystem paths — to any unauthenticated caller. Rubberverse's fix, which
//! the issue calls correct, is to log server-side and return a constant.
//!
//! That is enforced structurally here rather than by remembering:
//! [`Response::error`] takes a [`Status`] and nothing else, so there is no
//! parameter for a caller to thread a message through. A caller that wants the
//! detail recorded logs it (`SEC-012`, #204); what goes on the wire is the
//! status's own fixed reason phrase.
//!
//! # No keep-alive
//!
//! Every response says `Connection: close`. A read-only UI serving a handful of
//! pages gains nothing from persistent connections, and keep-alive is what
//! makes a slow client hold a slot indefinitely — which under `OBS-014` (#190)
//! is a slot the KMS listener could have had.

use core::fmt::Write as _;

/// The status codes this host emits.
///
/// A closed set, because each carries a fixed reason phrase and a fixed body
/// and adding one should mean deciding both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The page.
    Ok,
    /// A route this host does not serve.
    NotFound,
    /// A method it does not implement (`OBS-010`, #186).
    MethodNotAllowed,
    /// A malformed request.
    BadRequest,
    /// A request line past [`super::request::MAX_REQUEST_LINE`].
    UriTooLong,
    /// Headers past their limits.
    HeadersTooLarge,
    /// A request declaring a body.
    PayloadTooLarge,
    /// An HTTP version this host does not speak.
    VersionNotSupported,
    /// The host is up but not ready to serve KMS (`OBS-008`, #184).
    ServiceUnavailable,
}

impl Status {
    /// The numeric code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::PayloadTooLarge => 413,
            Self::UriTooLong => 414,
            Self::HeadersTooLarge => 431,
            Self::ServiceUnavailable => 503,
            Self::VersionNotSupported => 505,
        }
    }

    /// The reason phrase, which is also the whole of the error body.
    ///
    /// Fixed strings. There is nowhere for a caller-supplied value to appear,
    /// which is the point (`OBS-009`, #185).
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::BadRequest => "Bad Request",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UriTooLong => "URI Too Long",
            Self::HeadersTooLarge => "Request Header Fields Too Large",
            Self::ServiceUnavailable => "Service Unavailable",
            Self::VersionNotSupported => "HTTP Version Not Supported",
        }
    }

    /// The status a request-parsing refusal maps to.
    #[must_use]
    pub const fn for_request_error(error: super::request::RequestError) -> Self {
        use super::request::RequestError;
        match error {
            RequestError::RequestLineTooLong => Self::UriTooLong,
            RequestError::HeaderTooLong
            | RequestError::TooManyHeaders
            | RequestError::HeadTooLong => Self::HeadersTooLarge,
            RequestError::UnsupportedMethod => Self::MethodNotAllowed,
            RequestError::UnsupportedVersion => Self::VersionNotSupported,
            RequestError::BodyNotAllowed => Self::PayloadTooLarge,
            RequestError::MalformedRequestLine
            | RequestError::MalformedHeader
            | RequestError::NotText => Self::BadRequest,
        }
    }
}

/// What a body is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// A rendered page.
    Html,
    /// A fixed error body, or `/healthz`.
    Text,
    /// The Prometheus exposition format (`OBS-013`, #189).
    Metrics,
}

impl ContentType {
    /// The header value, including the charset where one applies.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Html => "text/html; charset=utf-8",
            Self::Text => "text/plain; charset=utf-8",
            Self::Metrics => "text/plain; version=0.0.4; charset=utf-8",
        }
    }
}

/// A response, ready to serialise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status.
    pub status: Status,
    /// What the body is.
    pub content_type: ContentType,
    /// The body. Empty for a `HEAD`, which still declares the length it would
    /// have had.
    pub body: String,
}

impl Response {
    /// A page.
    #[must_use]
    pub fn html(body: String) -> Self {
        Self {
            status: Status::Ok,
            content_type: ContentType::Html,
            body,
        }
    }

    /// Plain text at 200.
    #[must_use]
    pub fn text(body: String) -> Self {
        Self {
            status: Status::Ok,
            content_type: ContentType::Text,
            body,
        }
    }

    /// The Prometheus exposition format.
    #[must_use]
    pub fn metrics(body: String) -> Self {
        Self {
            status: Status::Ok,
            content_type: ContentType::Metrics,
            body,
        }
    }

    /// An error, whose body is the status's own reason phrase.
    ///
    /// There is deliberately no parameter for a message. A caller with detail
    /// worth keeping logs it; what reaches an unauthenticated caller is a
    /// constant (`OBS-009`, #185).
    #[must_use]
    pub fn error(status: Status) -> Self {
        Self {
            status,
            content_type: ContentType::Text,
            body: String::from(status.reason()),
        }
    }

    /// Serialise, including the body unless the request was a `HEAD`.
    ///
    /// `Content-Length` is the length the body *would* have, which is what
    /// makes `HEAD` useful to a monitor: it learns the page exists and how big
    /// it is without paying for it.
    #[must_use]
    pub fn write(&self, include_body: bool) -> Vec<u8> {
        let mut head = String::with_capacity(256);
        // Writing into a `String` cannot fail, and the discarded value is an
        // infallible `fmt::Result` — typed, so it reads as a decision
        // (`SEC-012`, #204).
        let _: core::fmt::Result = write!(
            head,
            "HTTP/1.1 {} {}\r\n",
            self.status.code(),
            self.status.reason()
        );
        let _: core::fmt::Result = write!(head, "Content-Type: {}\r\n", self.content_type.as_str());
        let _: core::fmt::Result = write!(head, "Content-Length: {}\r\n", self.body.len());

        for (name, value) in HEADERS {
            let _: core::fmt::Result = write!(head, "{name}: {value}\r\n");
        }
        head.push_str("\r\n");

        let mut out = head.into_bytes();
        if include_body {
            out.extend_from_slice(self.body.as_bytes());
        }
        out
    }
}

/// Headers every response carries.
///
/// # Why these and not others
///
/// * `Connection: close` — no keep-alive, so a slow client cannot hold a slot
///   (`OBS-014`, #190).
/// * `Cache-Control: no-store` — every page is live state. A cached `/events`
///   is a lie, and a cached `/healthz` is a dangerous one.
/// * `Content-Security-Policy` — the CSS is vendored and inlined and there is
///   no script at all, so the policy that describes this UI is the one that
///   forbids everything except the inline style it actually uses. A UI with no
///   CDN is the offline-capable choice `OBS-007` (#183) asks for; a CSP is what
///   stops one creeping in later.
/// * `X-Content-Type-Options: nosniff` — the bodies are fixed types.
/// * `Referrer-Policy: no-referrer` — nothing here should travel outward, and
///   there is nowhere for it to travel to.
/// * `X-Frame-Options: DENY` — a read-only page has no action to clickjack
///   (`OBS-010`, #186), which makes this cheap rather than unnecessary.
///
/// No `Server` header. It would say nothing a client needs and one more thing a
/// prober can read; the KMS port is the one that has to look like Microsoft's
/// (axiom A9), and this one simply declines to introduce itself.
const HEADERS: &[(&str, &str)] = &[
    ("Connection", "close"),
    ("Cache-Control", "no-store"),
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
];

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{ContentType, Response, Status};
    use crate::web::request::RequestError;

    fn text_of(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("a response is UTF-8")
    }

    #[test]
    fn a_page_declares_its_length_and_type() {
        let response = Response::html(String::from("<p>hello</p>"));
        let text = text_of(&response.write(true));
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(text.contains("Content-Length: 12\r\n"));
        assert!(text.ends_with("\r\n\r\n<p>hello</p>"));
    }

    /// A `HEAD` learns the size without paying for it.
    #[test]
    fn a_head_response_declares_the_length_it_omits() {
        let response = Response::html(String::from("<p>hello</p>"));
        let text = text_of(&response.write(false));
        assert!(text.contains("Content-Length: 12\r\n"));
        assert!(text.ends_with("\r\n\r\n"), "a HEAD response carried a body");
    }

    /// The property `OBS-009` (#185) is about, enforced by there being no
    /// parameter to leak through.
    #[test]
    fn an_error_body_is_the_reason_phrase_and_nothing_else() {
        for status in [
            Status::BadRequest,
            Status::NotFound,
            Status::MethodNotAllowed,
            Status::PayloadTooLarge,
            Status::UriTooLong,
            Status::HeadersTooLarge,
            Status::ServiceUnavailable,
            Status::VersionNotSupported,
        ] {
            let response = Response::error(status);
            assert_eq!(response.body, status.reason());
            assert_eq!(response.content_type, ContentType::Text);

            let text = text_of(&response.write(true));
            for secret in ["/nix/store", "/home/", "products.toml", "panicked", "src/"] {
                assert!(
                    !text.contains(secret),
                    "{status:?} leaked {secret:?}:\n{text}"
                );
            }
        }
    }

    #[test]
    fn every_request_error_maps_to_a_status_that_agrees_with_it() {
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
            let status = Status::for_request_error(error);
            assert_eq!(
                status.code(),
                error.status(),
                "{error:?} maps to {status:?} ({}) but reports {}",
                status.code(),
                error.status()
            );
        }
    }

    #[test]
    fn every_response_closes_and_is_never_cached() {
        let text = text_of(&Response::text(String::from("ok")).write(true));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.contains("Cache-Control: no-store\r\n"));
    }

    /// The UI vendors its CSS and has no script, so the policy that describes
    /// it is the one forbidding everything else.
    #[test]
    fn the_content_security_policy_forbids_scripts_and_remote_anything() {
        let text = text_of(&Response::html(String::new()).write(true));
        let policy = text
            .lines()
            .find(|line| line.starts_with("Content-Security-Policy:"))
            .expect("every response carries a policy");
        assert!(policy.contains("default-src 'none'"));
        assert!(
            !policy.contains("script-src"),
            "the policy grants scripts a source: {policy}"
        );
        assert!(
            !policy.contains("http:") && !policy.contains("https:"),
            "the policy allows a remote origin, so a CDN could creep in: {policy}"
        );
    }

    /// One more thing a prober can read, for nothing a client needs.
    #[test]
    fn no_response_introduces_itself() {
        let text = text_of(&Response::html(String::new()).write(true));
        for header in ["Server:", "X-Powered-By:", "Via:"] {
            assert!(!text.contains(header), "a response carried {header}");
        }
        assert!(!text.to_lowercase().contains("kmsrs"));
    }

    #[test]
    fn a_body_containing_crlf_cannot_forge_a_header() {
        // Header injection would need the *head* to contain caller text; it
        // does not, so this checks the property rather than a sanitiser.
        let hostile = String::from("x\r\nX-Injected: yes\r\n\r\n");
        let response = Response::text(hostile.clone());
        let bytes = response.write(true);
        let head_end = bytes
            .windows(4)
            .position(|four| four == b"\r\n\r\n")
            .expect("a response has a head");
        let head = String::from_utf8(bytes[..head_end].to_vec()).unwrap();
        assert!(
            !head.contains("X-Injected"),
            "a body forged a header:\n{head}"
        );
        assert!(head.contains(&format!("Content-Length: {}", hostile.len())));
    }
}

//! The in-process web UI (`ARCH-011`, axiom A11; `OBS-007`, #183).
//!
//! # Sans-io, in a crate that is not
//!
//! `kmsrs-server` owns the sockets, and this module owns none of them. It takes
//! bytes and returns bytes, exactly like `kmsrs-proto` does for the KMS
//! protocol, and for the same three reasons: it is fuzzed (`SEC-013`, #306 —
//! the `http_request` target in `crates/kmsrs-vectors/src/targets.rs`), it can
//! be tested without binding a port, and it works unchanged on Hermit.
//!
//! It lives here rather than in a crate of its own because `ARCH-001` (#1)
//! folded the web UI into the server: it renders this server's state, so a
//! separate crate would need every type this one has.
//!
//! # Why an HTTP parser at all
//!
//! Because the alternatives are worse. A dependency would be a large parser
//! with a large attack surface reachable by anything that can open a socket,
//! and the whole of what this host needs is: read a request line, read some
//! headers, refuse everything unusual. Five hundred lines that do exactly that,
//! with every limit a constant, is a smaller thing to be sure of than a general
//! HTTP implementation configured down.
//!
//! It is also the one place where being *strict* costs nothing. There is no
//! third-party client to keep working — the consumer is a browser fetching six
//! fixed routes — so anything ambiguous is refused rather than guessed at.

pub mod request;
pub mod response;
pub mod routes;

pub use request::{Method, Parsed, Request, RequestError};
pub use response::{ContentType, Response, Status};

/// Answer one request, or say why not.
///
/// The whole of the protocol layer's interface: bytes in, a decision out. A
/// driver loops on [`Parsed::Incomplete`], writes what a [`Response`]
/// serialises to, and closes — every response says `Connection: close`.
///
/// `route` is supplied by the caller rather than being a `match` here, so the
/// routes (`OBS-008`, #184) and the protocol (`OBS-007`, #183) can be wrong
/// independently of each other.
pub fn answer(buffer: &[u8], route: &mut dyn FnMut(&Request<'_>) -> Response) -> Answered {
    match request::parse(buffer) {
        Parsed::Incomplete => Answered::NeedMore,
        Parsed::Refused(error) => {
            let response = Response::error(Status::for_request_error(error));
            Answered::Reply {
                // A refusal is answered in full even to a `HEAD`, because the
                // method is one of the things that may have been unreadable.
                bytes: response.write(true),
                consumed: buffer.len(),
                error: Some(error),
            }
        }
        Parsed::Complete(parsed) => {
            let response = route(&parsed);
            Answered::Reply {
                bytes: response.write(parsed.method.wants_body()),
                consumed: parsed.head_len,
                error: None,
            }
        }
    }
}

/// What [`answer`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answered {
    /// No complete request head yet. Read more.
    NeedMore,
    /// Write these bytes and close.
    Reply {
        /// The serialised response.
        bytes: Vec<u8>,
        /// How many input bytes were consumed.
        consumed: usize,
        /// The refusal, if the request was one — for the log, never for the
        /// wire (`OBS-009`, #185; `SEC-012`, #204).
        error: Option<RequestError>,
    },
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

    use super::{Answered, Response, answer};

    fn answer_to(request: &str) -> Answered {
        answer(request.as_bytes(), &mut |parsed| {
            Response::html(format!("<p>{}</p>", parsed.path))
        })
    }

    #[test]
    fn a_complete_request_is_answered_and_consumed() {
        let request = "GET /events HTTP/1.1\r\nHost: k\r\n\r\n";
        let Answered::Reply {
            bytes,
            consumed,
            error,
        } = answer_to(request)
        else {
            panic!("a complete request was not answered");
        };
        assert_eq!(consumed, request.len());
        assert_eq!(error, None);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.ends_with("<p>/events</p>"));
    }

    #[test]
    fn a_head_request_is_answered_without_its_body() {
        let Answered::Reply { bytes, .. } = answer_to("HEAD /events HTTP/1.1\r\nHost: k\r\n\r\n")
        else {
            panic!("a HEAD was not answered");
        };
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Content-Length: 14\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\n"), "a HEAD carried a body:\n{text}");
    }

    #[test]
    fn an_incomplete_request_asks_for_more() {
        assert_eq!(answer_to("GET / HTTP/1.1\r\n"), Answered::NeedMore);
    }

    /// The router is never called for a request that did not parse, so a route
    /// cannot be reached by a malformed request.
    #[test]
    fn the_router_never_sees_a_refused_request() {
        let mut called = 0_usize;
        let outcome = answer(b"POST / HTTP/1.1\r\n\r\n", &mut |_| {
            called += 1;
            Response::html(String::new())
        });
        assert_eq!(called, 0, "the router ran for a request that was refused");

        let Answered::Reply { bytes, error, .. } = outcome else {
            panic!("a refusal produced no reply");
        };
        assert!(error.is_some(), "a refusal was not reported for the log");
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .starts_with("HTTP/1.1 405"),
            "a POST was not answered with 405"
        );
    }
}

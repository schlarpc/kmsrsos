//! One readiness-driven event loop, for all three platforms
//! (`ARCH-005`, #5; `NET-004`…`NET-008`).
//!
//! # Why one loop and not two drivers
//!
//! `ARCH-005` originally called for tokio on Linux and Windows and a blocking
//! `std::net` driver on Hermit. Both halves of that turned out to be avoidable.
//!
//! tokio has **zero upstream Hermit support**. It works there only through a
//! four-commit fork of 1.45.0 whose substantive patch is a level-triggered
//! selector workaround — and tokio's readiness caching assumes edge-triggered
//! semantics, so getting it wrong produces *hangs, not errors*. Adopting that
//! fork would mean a workspace-global `[patch.crates-io]`, pinning Linux and
//! Windows to it as well.
//!
//! `mio` — the layer tokio would have used anyway — has first-class Hermit
//! support in the stock crates.io release, and hermit's own CI exercises it on
//! every pull request. Its backends are epoll on Linux, IOCP on Windows, and
//! `poll(2)` on Hermit, where the kernel has `sys_poll` and `sys_eventfd` and no
//! epoll at all.
//!
//! So there is one driver, and the platform differences that remain are facts
//! about socket *semantics* rather than about I/O plumbing — see
//! [`crate::net::addr::SINGLE_SOCKET_ONLY`] for the one that survives.
//!
//! # What using a poller removes
//!
//! Three things that were previously hand-built and, in two cases, untestable:
//!
//! * **Timeouts.** There is no `SO_RCVTIMEO` anywhere. A deadline is the poll
//!   timeout, computed from the injected clock, so it behaves identically on
//!   every target — including Hermit, whose `setsockopt` is a stub returning
//!   `EINVAL` for exactly that option (`NET-004`, #153; `OS-014`, #297).
//! * **The shutdown wakeup.** [`mio::Waker`] is an eventfd on Linux and Hermit
//!   and a posted IOCP completion on Windows. The previous design woke a
//!   blocked `accept()` by connecting to its own listener, which assumed a
//!   loopback route Hermit may not have (`NET-008`, #158; `OS-015`, #298).
//! * **Thread-per-connection.** A connection is now a few kilobytes in a map
//!   rather than an OS thread, which is what makes the connection ceiling
//!   derivable rather than picked (`NET-014`, #296).
//!
//! # Fairness
//!
//! vlmcsd runs a `select()` loop that always services the first ready
//! descriptor in list order, so a saturated early listener starves later ones.
//! Here **every** event in a batch is processed before polling again, and
//! accepting is bounded by the free capacity — so no source can monopolise the
//! loop (`NET-006`, #155).

use crate::host::RequestContext;
use crate::net::addr::normalise_socket;
use crate::net::listener::Bound;
use crate::server::Server;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use kmsrs_policy::access::Admission;
use kmsrs_policy::events::Peer;
use kmsrs_proto::entropy::Entropy;
use kmsrs_proto::time::Instant;
use kmsrs_proto::wire::connection::Connection;
use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token, Waker};
use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::sync::Arc;

/// How much memory this host will hold in connection state.
///
/// The basis for [`MAX_CONNECTIONS`]. Four mebibytes is a rounding error on
/// Linux and Windows; the binding constraint is Hermit, a unikernel with a
/// fixed memory budget and no swap, where it is still comfortable.
pub const CONNECTION_STATE_BUDGET: usize = 4 * 1024 * 1024;

/// Bytes of state one connection occupies.
///
/// A [`Connection`] holds a `MAX_PDU_LEN` inbound buffer — 2048 bytes — plus the
/// association state; the outbound buffer is bounded by [`MAX_OUTBOUND`]; the
/// rest is the socket, the map entry and the per-request bookkeeping. Rounded
/// up generously, because the point of this number is to bound the ceiling, not
/// to predict an allocator.
pub const CONNECTION_STATE_BYTES: usize = 4096;

/// How many connections may be in flight at once (`NET-005`, #154;
/// `NET-014`, #296).
///
/// **Derived, not chosen**: [`CONNECTION_STATE_BUDGET`] divided by
/// [`CONNECTION_STATE_BYTES`]. That is only meaningful because a connection is
/// now a map entry rather than an OS thread — under thread-per-connection the
/// ceiling was a thread count, and 8 MiB of default stack reservation each made
/// any generous number look reckless.
///
/// Generosity is the right direction, and the argument is `POL-014`'s (#102)
/// applied to the same traffic: refusing a legitimate client is both a broken
/// client *and* a fingerprint, because a genuine KMS host does not refuse. A
/// limit a real fleet can reach is a worse failure than one only an attacker
/// reaches.
pub const MAX_CONNECTIONS: usize = {
    // `checked_div` rather than `/`, because the workspace forbids raw integer
    // division and a `const` is the one place a divisor typo cannot be caught
    // by a test. A zero here is a build failure, not a server that accepts
    // nobody.
    let Some(count) = CONNECTION_STATE_BUDGET.checked_div(CONNECTION_STATE_BYTES) else {
        panic!("the per-connection budget must not be zero")
    };
    count
};

/// The most unsent response bytes one connection may accumulate.
///
/// A response is at most `MAX_RESPONSE_LEN` plus its RPC header, so this is
/// several PDUs of slack for a peer that has stopped reading. Beyond it the
/// connection is closed rather than buffered indefinitely — an unbounded write
/// queue is how a slow reader becomes a memory leak.
pub const MAX_OUTBOUND: usize = 8 * 1024;

/// How long a connection may sit without making progress.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a connection may live in total, however slowly it feeds us.
///
/// The read timeout bounds one quiet period; this bounds the whole
/// conversation, which is what a slowloris actually attacks — a peer sending
/// one byte just inside every read timeout resets the idle deadline forever.
pub const CONNECTION_DEADLINE: Duration = Duration::from_mins(2);

/// The longest a single poll will block.
///
/// Deadlines are evaluated against the *injected* clock, which need not advance
/// with real time — under a test clock it may not advance at all between
/// wakeups. Capping the poll bounds how stale a deadline check can get and makes
/// the loop's liveness independent of what the clock does.
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The token the shutdown waker uses.
const WAKER_TOKEN: Token = Token(0);

/// The first token a listener may use. Connections take everything above.
const FIRST_LISTENER_TOKEN: usize = 1;

/// Ask a running [`Driver`] to stop, from anywhere (`NET-007`, #157).
///
/// Cloneable and safe to call from a signal handler: it sets a flag and posts to
/// the poller's waker, which allocates nothing and takes no lock.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    requested: Arc<AtomicBool>,
    waker: Arc<Waker>,
    /// Whether the last shutdown request reached the poller (`SEC-012`, #204).
    woke: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Ask the loop to stop accepting and drain.
    ///
    /// Idempotent. In-flight connections are finished rather than cut off, so a
    /// client mid-activation still gets its answer.
    pub fn request(&self) {
        self.requested.store(true, Ordering::Release);
        // A failed wake means the poller is already gone, which is the outcome
        // being asked for — so it is reported rather than discarded, and the
        // caller decides whether it matters (`SEC-012`, #204). `ShutdownHandle`
        // has no logger of its own by design: it is called from a signal
        // handler, where allocating to format a message is not allowed.
        self.woke
            .store(self.waker.wake().is_ok(), Ordering::Release);
    }

    /// Whether the last [`Self::request`] managed to wake the poller.
    ///
    /// `false` means the loop was already gone. That is normal on a second
    /// shutdown request and abnormal on the first, and only the caller has the
    /// context to tell those apart.
    #[must_use]
    pub fn woke(&self) -> bool {
        self.woke.load(Ordering::Acquire)
    }

    /// Whether shutdown has been asked for.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

/// A bound listener and the port it is on.
///
/// The port is kept beside the socket because a `bind_ack` must advertise the
/// endpoint that *actually accepted* (`WIRE-011`, #69), and asking the socket
/// again per accept would be a syscall for an answer that cannot change.
#[derive(Debug)]
struct Listener {
    token: Token,
    socket: TcpListener,
    port: u16,
}

/// One client's connection.
#[derive(Debug)]
struct Conn {
    stream: TcpStream,
    connection: Connection,
    peer: SocketAddr,
    /// Response bytes not yet written.
    outbound: Vec<u8>,
    /// How much of `outbound` has been written.
    written: usize,
    /// Whether `WRITABLE` interest is currently registered.
    watching_writable: bool,
    /// When it was accepted.
    started: Instant,
    /// When it last made progress.
    last_progress: Instant,
    /// Close once `outbound` has drained.
    closing: bool,
    /// The application the last request named, for the rate-limit key
    /// (`POL-014`, #102).
    last_application: kmsrs_db::Guid,
}

impl Conn {
    /// When this connection must be closed if nothing changes.
    fn deadline(&self) -> Instant {
        let by_idle = self
            .last_progress
            .checked_add(READ_TIMEOUT)
            .unwrap_or(self.last_progress);
        let by_total = self
            .started
            .checked_add(CONNECTION_DEADLINE)
            .unwrap_or(self.started);
        if by_idle < by_total {
            by_idle
        } else {
            by_total
        }
    }

    /// Whether this connection has outlived one of its deadlines.
    fn expired(&self, now: Instant) -> bool {
        now >= self.deadline()
    }
}

/// The event loop.
#[derive(Debug)]
pub struct Driver {
    poll: Poll,
    events: Events,
    listeners: Vec<Listener>,
    connections: HashMap<Token, Conn>,
    next_token: usize,
    limit: usize,
    requested: Arc<AtomicBool>,
    waker: Arc<Waker>,
    server: Server,
}

impl Driver {
    /// Build a loop over the given listeners.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the poller could not be created or a listener
    /// could not be registered.
    pub fn new(server: Server, listeners: Vec<Bound>, limit: usize) -> io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKER_TOKEN)?);

        let mut registered = Vec::with_capacity(listeners.len());
        for (index, bound) in listeners.into_iter().enumerate() {
            // mio requires a non-blocking listener.
            bound.listener.set_nonblocking(true)?;
            let port = bound.address.port();
            let mut listener = TcpListener::from_std(bound.listener);
            let token = Token(FIRST_LISTENER_TOKEN.saturating_add(index));
            poll.registry()
                .register(&mut listener, token, Interest::READABLE)?;
            registered.push(Listener {
                token,
                socket: listener,
                port,
            });
        }

        let next_token = FIRST_LISTENER_TOKEN.saturating_add(registered.len());
        Ok(Self {
            poll,
            events: Events::with_capacity(256),
            listeners: registered,
            connections: HashMap::new(),
            next_token,
            limit: limit.max(1),
            requested: Arc::new(AtomicBool::new(false)),
            waker,
            server,
        })
    }

    /// A handle that can stop this loop from another thread.
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            requested: Arc::clone(&self.requested),
            waker: Arc::clone(&self.waker),
            woke: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The server this loop is driving.
    #[must_use]
    pub const fn server(&self) -> &Server {
        &self.server
    }

    /// How many connections are in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.connections.len()
    }

    /// Serve until [`ShutdownHandle::request`] is called and every in-flight
    /// connection has finished.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] only if polling itself fails. A failure on one
    /// connection closes that connection; one client's broken socket is not the
    /// server's problem.
    pub fn run(
        &mut self,
        entropy: &mut dyn Entropy,
        clock: &dyn Fn() -> Instant,
    ) -> io::Result<()> {
        loop {
            if self.requested.load(Ordering::Acquire) && self.connections.is_empty() {
                return Ok(());
            }

            let timeout = self.poll_timeout(clock());
            match self.poll.poll(&mut self.events, Some(timeout)) {
                Ok(()) => {}
                // A signal interrupted the wait. Not an error; go round again.
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }

            // `NET-006` (#155): every event in the batch is handled before the
            // next poll, so no source can be starved by an earlier one.
            let batch: Vec<(Token, bool, bool)> = self
                .events
                .iter()
                .map(|event| (event.token(), is_readable(event), is_writable(event)))
                .collect();

            for (token, readable, writable) in batch {
                if token == WAKER_TOKEN {
                    continue;
                }
                if self.listeners.iter().any(|entry| entry.token == token) {
                    self.accept_from(token, clock());
                } else {
                    self.service(token, readable, writable, entropy, clock);
                }
            }

            self.expire(clock());
        }
    }

    /// How long the next poll may block.
    fn poll_timeout(&self, now: Instant) -> Duration {
        let soonest = self.connections.values().map(Conn::deadline).min();
        match soonest {
            Some(deadline) if deadline > now => deadline
                .saturating_duration_since(now)
                .min(MAX_POLL_INTERVAL),
            // A deadline has already passed: do not block.
            Some(_) => Duration::ZERO,
            None => MAX_POLL_INTERVAL,
        }
    }

    /// Accept everything queued on one listener, up to the free capacity.
    fn accept_from(&mut self, token: Token, now: Instant) {
        loop {
            if self.requested.load(Ordering::Acquire) {
                return;
            }
            let Some(entry) = self.listeners.iter().find(|entry| entry.token == token) else {
                return;
            };
            let accepting_port = entry.port;

            let (stream, peer) = match entry.socket.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return,
                // `EINTR`: nothing was accepted, so go round again.
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                // An accept failure is a fact about one connection, not about
                // the listener. vlmcsd treats several of these as fatal.
                Err(_) => return,
            };

            // `NET-012` (#161): one client, one identity, from the moment it
            // arrives.
            let peer = normalise_socket(peer);

            // `NET-005` (#154): beyond the ceiling, close now rather than
            // queue. Closing at once is the honest signal — the client learns
            // immediately that this host is full instead of waiting out a
            // timeout to discover it.
            if self.connections.len() >= self.limit {
                drop(stream);
                self.server.logger().message(
                    crate::log::Severity::Warn,
                    "at-capacity",
                    &peer.ip().to_string(),
                );
                continue;
            }

            // `POL-013` (#101): checked here, before any RPC state exists, so a
            // refused peer never reaches the parser.
            if let Err(denial) = self.server.compiled().access.check(peer.ip()) {
                drop(stream);
                self.server.logger().message(
                    crate::log::Severity::Warn,
                    "blocked",
                    &format!("{}: {denial:?}", peer.ip()),
                );
                continue;
            }

            // A registration failure drops the connection and moves on — the
            // listener is still fine — but it is said out loud. An accept that
            // silently goes nowhere is indistinguishable from a client that
            // never connected, which is the class of invisibility `SEC-012`
            // (#204) exists to prevent.
            if let Err(error) = self.register(stream, peer, now, accepting_port) {
                self.server.logger().message(
                    crate::log::Severity::Warn,
                    "register",
                    &format!("{peer}: {error}"),
                );
            }
        }
    }

    /// Register an accepted stream with the poller.
    fn register(
        &mut self,
        stream: TcpStream,
        peer: SocketAddr,
        now: Instant,
        accepting_port: u16,
    ) -> io::Result<()> {
        let mut stream = stream;
        let token = Token(self.next_token);
        self.next_token = self.next_token.saturating_add(1);
        self.poll
            .registry()
            .register(&mut stream, token, Interest::READABLE)?;

        let connection = self.server.connection(0x1234_5678, accepting_port);
        self.connections.insert(
            token,
            Conn {
                stream,
                connection,
                peer,
                outbound: Vec::new(),
                written: 0,
                watching_writable: false,
                started: now,
                last_progress: now,
                closing: false,
                last_application: kmsrs_db::Guid::ZERO,
            },
        );
        Ok(())
    }

    /// Handle readiness on one connection.
    fn service(
        &mut self,
        token: Token,
        readable: bool,
        writable: bool,
        entropy: &mut dyn Entropy,
        clock: &dyn Fn() -> Instant,
    ) {
        if writable && self.flush(token).is_err() {
            self.close(token);
            return;
        }
        if readable && self.read_and_answer(token, entropy, clock).is_err() {
            self.close(token);
            return;
        }
        self.finish(token);
    }

    /// Read what is available and answer it.
    fn read_and_answer(
        &mut self,
        token: Token,
        entropy: &mut dyn Entropy,
        clock: &dyn Fn() -> Instant,
    ) -> io::Result<()> {
        let mut buffer = [0_u8; 8192];
        loop {
            let read = {
                let Some(conn) = self.connections.get_mut(&token) else {
                    return Ok(());
                };
                match conn.stream.read(&mut buffer) {
                    // The peer closed its side.
                    Ok(0) => {
                        conn.closing = true;
                        return Ok(());
                    }
                    Ok(count) => count,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            };

            let now = clock();
            let Some(peer) = self.connections.get(&token).map(|conn| conn.peer) else {
                return Ok(());
            };

            // `POL-014` (#102): one token per read that carries work, keyed on
            // (source, application). The application is not known until the
            // request is decoded, so the key uses the *previous* request's —
            // fixed before this client chose its fields, so varying them cannot
            // move it to a fresh bucket.
            let application = self
                .connections
                .get(&token)
                .map_or(kmsrs_db::Guid::ZERO, |conn| conn.last_application);
            if let Admission::Limited { retry_after } =
                self.server.limiter_mut().admit(peer.ip(), application, now)
            {
                self.server.logger().message(
                    crate::log::Severity::Warn,
                    "rate-limited",
                    &format!("{}: retry in {}s", peer.ip(), retry_after.as_secs()),
                );
                if let Some(conn) = self.connections.get_mut(&token) {
                    conn.closing = true;
                }
                return Ok(());
            }

            let context = RequestContext {
                peer: Some(Peer {
                    address: peer.ip(),
                    port: peer.port(),
                }),
                now,
                host_time: None,
            };

            let handled = {
                let Some(conn) = self.connections.remove(&token) else {
                    return Ok(());
                };
                let mut conn = conn;
                let input = buffer.get(..read).unwrap_or(&[]);
                let handled = self
                    .server
                    .handle(&mut conn.connection, input, context, entropy);
                self.connections.insert(token, conn);
                handled
            };

            // Remember what this connection is about, for the next request's
            // rate-limit key.
            let latest = self
                .server
                .host()
                .events()
                .iter()
                .next_back()
                .map(|event| event.application.0);

            let Some(conn) = self.connections.get_mut(&token) else {
                return Ok(());
            };
            conn.last_progress = now;
            if let Some(application) = latest {
                conn.last_application = application;
            }
            if conn.outbound.len().saturating_add(handled.response.len()) > MAX_OUTBOUND {
                // A peer that has stopped reading must not become a memory leak.
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "the peer is not reading its responses",
                ));
            }
            conn.outbound.extend_from_slice(&handled.response);
            if handled.close {
                conn.closing = true;
            }

            self.flush(token)?;
            if self
                .connections
                .get(&token)
                .is_some_and(|conn| conn.closing)
            {
                return Ok(());
            }
        }
    }

    /// Write as much of the outbound buffer as the socket will take.
    ///
    /// Loops on short writes and retries on `EINTR` (`NET-006`, #156). py-kms
    /// uses `send()` rather than `sendall()`, so a partial write silently
    /// truncates a response and the client blames the protocol.
    fn flush(&mut self, token: Token) -> io::Result<()> {
        let Some(conn) = self.connections.get_mut(&token) else {
            return Ok(());
        };
        while conn.written < conn.outbound.len() {
            let pending = conn.outbound.get(conn.written..).unwrap_or(&[]);
            match conn.stream.write(pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "the peer stopped accepting bytes",
                    ));
                }
                Ok(count) => conn.written = conn.written.saturating_add(count),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        if conn.written >= conn.outbound.len() {
            conn.outbound.clear();
            conn.written = 0;
        }
        Ok(())
    }

    /// Adjust interest, and close if there is nothing left to do.
    fn finish(&mut self, token: Token) {
        let (wants_writable, done) = {
            let Some(conn) = self.connections.get(&token) else {
                return;
            };
            let pending = conn.written < conn.outbound.len();
            (pending, conn.closing && !pending)
        };

        if done {
            self.close(token);
            return;
        }

        let Some(conn) = self.connections.get_mut(&token) else {
            return;
        };
        if wants_writable != conn.watching_writable {
            let interest = if wants_writable {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            if self
                .poll
                .registry()
                .reregister(&mut conn.stream, token, interest)
                .is_ok()
            {
                conn.watching_writable = wants_writable;
            }
        }
    }

    /// Close and forget one connection.
    fn close(&mut self, token: Token) {
        if let Some(mut conn) = self.connections.remove(&token) {
            // Deregistration failing means the poller has already forgotten
            // this socket, which is the state being asked for; dropping the
            // stream below closes it either way. Reported at debug because it
            // is expected on a peer that reset, and unexplained silence is
            // what `SEC-012` (#204) forbids — not noise.
            if let Err(error) = self.poll.registry().deregister(&mut conn.stream) {
                self.server.logger().message(
                    crate::log::Severity::Debug,
                    "deregister",
                    &format!("{}: {error}", conn.peer),
                );
            }
        }
    }

    /// Close every connection that has outlived a deadline (`NET-004`, #153).
    fn expire(&mut self, now: Instant) {
        let expired: Vec<Token> = self
            .connections
            .iter()
            .filter(|(_, conn)| conn.expired(now))
            .map(|(token, _)| *token)
            .collect();
        for token in expired {
            self.close(token);
        }
    }
}

/// Whether an event says the source is readable.
///
/// A hangup counts: there may be buffered bytes to read before the close, and
/// treating it as not-readable is how a final request gets dropped.
fn is_readable(event: &Event) -> bool {
    event.is_readable() || event.is_read_closed()
}

/// Whether an event says the source is writable.
fn is_writable(event: &Event) -> bool {
    event.is_writable()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        CONNECTION_DEADLINE, CONNECTION_STATE_BUDGET, CONNECTION_STATE_BYTES, MAX_CONNECTIONS,
        MAX_OUTBOUND, READ_TIMEOUT,
    };

    /// `NET-014` (#296): the ceiling is derived from a memory budget rather than
    /// picked. This is what makes that claim checkable — replace the constant
    /// with a literal and the arithmetic stops holding.
    #[test]
    fn the_connection_ceiling_is_derived_from_the_memory_budget() {
        assert_eq!(
            MAX_CONNECTIONS,
            CONNECTION_STATE_BUDGET / CONNECTION_STATE_BYTES
        );
        assert_eq!(MAX_CONNECTIONS, 1024);

        // The per-connection figure must cover what a connection actually
        // holds: a `MAX_PDU_LEN` inbound buffer plus association state.
        assert!(
            CONNECTION_STATE_BYTES > kmsrs_proto::wire::connection::MAX_PDU_LEN,
            "the budget must cover the inbound buffer"
        );

        // And the whole thing must fit somewhere a unikernel can live.
        assert!(
            CONNECTION_STATE_BUDGET <= 64 * 1024 * 1024,
            "Hermit has a fixed memory budget and no swap"
        );
    }

    /// The ceiling must be far above what a real fleet produces, because
    /// refusing a legitimate client is both a broken client and a fingerprint —
    /// `POL-014`'s (#102) argument applied to the same traffic.
    #[test]
    fn the_ceiling_is_far_above_what_a_real_fleet_produces() {
        // A KMS client renews on a seven-day interval, and a request is
        // sub-millisecond, so concurrent connections are dominated by arrival
        // burstiness rather than by fleet size.
        let fleet = 50_000_u64;
        let renewal_seconds = 7 * 24 * 60 * 60_u64;
        assert!(fleet / renewal_seconds < 1, "under one request per second");
        assert!(
            MAX_CONNECTIONS >= 1024,
            "a ceiling a real fleet can reach is a fingerprint"
        );
    }

    /// Two deadlines, and the shorter one is not the interesting one: a peer
    /// sending one byte just inside every read timeout resets the idle deadline
    /// forever, which is why the total exists.
    #[test]
    fn the_total_deadline_is_longer_than_the_idle_one() {
        assert!(CONNECTION_DEADLINE > READ_TIMEOUT);
        assert_eq!(READ_TIMEOUT.as_secs(), 30);
        assert_eq!(CONNECTION_DEADLINE.as_secs(), 120);
    }

    /// The outbound buffer is bounded, so a peer that stops reading cannot turn
    /// into a memory leak.
    #[test]
    fn the_outbound_buffer_is_bounded_but_holds_several_responses() {
        assert!(MAX_OUTBOUND > kmsrs_proto::kms::layout::MAX_RESPONSE_LEN * 4);
        assert!(MAX_OUTBOUND <= 64 * 1024);
    }
}

//! The blocking driver: one thread per listener, a bounded worker pool
//! (`ARCH-005`, #5; `NET-004`…`NET-008`).
//!
//! Because the core is sans-io there is no async abstraction layer to write.
//! This driver owns its loop, reads bytes, hands them to
//! [`Server::handle`](crate::Server::handle), and writes back whatever comes
//! out. It is `std::net` and `std::thread` only, so it is also the Hermit
//! driver (`ARCH-005`, #5).
//!
//! # Fairness comes from the structure, not from a policy
//!
//! One accept thread per listener (`NET-006`, #155). vlmcsd runs a single
//! `select()` loop that always takes the first ready descriptor in list order,
//! so a saturated early listener starves every later one. With a thread each,
//! the OS scheduler decides, and there is no ordering to be unfair about.
//!
//! # Rejecting at accept, never queueing
//!
//! A connection that cannot get a worker permit is accepted and **closed**
//! immediately (`NET-005`, #154). vlmcsd's `-m` is a counting semaphore that
//! *queues*, so slowloris connections hold every worker for the full timeout
//! each; its own manual page recommends that plus a short timeout as the entire
//! mitigation strategy. py-kms spawns one unbounded thread per connection with
//! no timeout at all.
//!
//! Closing immediately is also the honest signal: the client learns at once
//! that this host is full, instead of waiting out a timeout to discover it.
//!
//! # Timeouts live in the state machine
//!
//! `SO_RCVTIMEO` is not portable in the way it looks: on Hermit `setsockopt`
//! returns `EINVAL` for it (`NET-004`, #153). So the deadline is the state
//! machine's, and the socket timeout is only an *optimisation* — where it
//! works, the thread sleeps; where it does not, [`ReadStrategy::Polled`] falls
//! back to a non-blocking socket and a short sleep. Both enforce the same
//! deadline, which is the point: the timeout is a property of the protocol
//! driver, not of a socket option that may silently do nothing.

use crate::host::RequestContext;
use crate::net::addr::normalise_socket;
use crate::net::listener::Bound;
use crate::server::Server;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::time::Duration;
use kmsrs_policy::access::{Admission, RateLimiter};
use kmsrs_policy::events::Peer;
use kmsrs_proto::entropy::Entropy;
use kmsrs_proto::time::Instant;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

/// How many connections may be in flight at once (`NET-005`, #154).
pub const MAX_CONNECTIONS: usize = 64;

/// How long a connection may take in total, however slowly it feeds us.
///
/// The read timeout bounds one read; this bounds the whole conversation, which
/// is what a slowloris actually attacks — a peer that sends one byte just
/// inside every read timeout can hold a worker indefinitely otherwise.
pub const CONNECTION_DEADLINE: Duration = Duration::from_mins(2);

/// How long a single read may block.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the polling fallback sleeps between attempts.
///
/// Only reached on a platform whose `SO_RCVTIMEO` does not work. Short enough
/// that a request is not noticeably delayed, long enough that an idle
/// connection is not a spin loop.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// The largest request this driver will buffer before giving up.
///
/// The protocol crate bounds a single PDU; this bounds the total a peer may
/// send on one connection without producing a complete one.
const MAX_INBOUND: usize = 1 << 20;

/// How a connection waits for bytes.
///
/// Decided per connection by *trying* to set the socket timeout, because that
/// is the only reliable way to know whether it works — Hermit's `setsockopt`
/// returns `EINVAL` here, and a platform check would be a guess about a
/// platform this code may not have been tested on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadStrategy {
    /// The socket enforces the timeout. The thread sleeps until data arrives.
    Blocking,
    /// The socket is non-blocking and the driver enforces the timeout by
    /// checking the clock between short sleeps (`NET-004`, #153).
    Polled,
}

impl ReadStrategy {
    /// Choose a strategy by trying the efficient one.
    fn choose(stream: &TcpStream) -> io::Result<Self> {
        if stream.set_read_timeout(Some(READ_TIMEOUT)).is_ok() {
            stream.set_write_timeout(Some(READ_TIMEOUT)).ok();
            return Ok(Self::Blocking);
        }
        stream.set_nonblocking(true)?;
        Ok(Self::Polled)
    }
}

/// A shared count of in-flight connections, with a hard ceiling.
///
/// Deliberately not a queueing semaphore. [`Permit::try_acquire`] either
/// succeeds now or fails now; there is no waiting, because waiting is what
/// makes a bounded pool behave like an unbounded one under attack
/// (`NET-005`, #154).
#[derive(Debug, Default)]
pub struct Capacity {
    in_flight: AtomicUsize,
    limit: usize,
}

/// Proof that a connection holds one of the pool's slots.
#[derive(Debug)]
pub struct Permit<'a> {
    capacity: &'a Capacity,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.capacity.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Capacity {
    /// A pool of the given size.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            limit,
        }
    }

    /// Take a slot if one is free, without waiting.
    pub fn try_acquire(&self) -> Option<Permit<'_>> {
        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Permit { capacity: self }),
                Err(actual) => current = actual,
            }
        }
    }

    /// How many connections are in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// The ceiling.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

/// The signal that stops the accept loops (`NET-007`, #157; `NET-008`, #158).
///
/// # Why this is not a pipe
///
/// The obvious portable wakeup is a self-pipe, and it is what py-kms uses. It
/// does not work on Windows, where a pipe handle cannot be registered with a
/// socket selector — which is precisely what breaks py-kms there
/// (`NET-008`, #158).
///
/// This wakes a blocked `accept()` by **connecting to the listener**, which
/// needs nothing but a TCP stack and therefore works identically on Linux,
/// Windows and Hermit. The flag is checked before the connection is served, so
/// the wakeup connection is accepted and dropped rather than handled.
#[derive(Debug)]
pub struct Shutdown {
    requested: AtomicBool,
    /// The addresses to poke, one per accept loop.
    listeners: Mutex<Vec<SocketAddr>>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    /// A signal nobody has raised.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Register a listener address so shutdown can wake its accept loop.
    pub fn register(&self, address: SocketAddr) {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(address);
        }
    }

    /// Whether shutdown has been requested.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    /// Ask every accept loop to stop, and wake them.
    ///
    /// Safe to call more than once and from any thread — which matters because
    /// on Unix it is called from a signal-handling thread. vlmcsd calls its
    /// `logger()` — `fopen` and `fprintf` — directly from signal context, and
    /// neither signals nor waits for its in-flight children.
    pub fn request(&self) {
        self.requested.store(true, Ordering::Release);
        let addresses = self
            .listeners
            .lock()
            .map(|listeners| listeners.clone())
            .unwrap_or_default();
        for address in addresses {
            // A connect that fails is fine: it means the loop is already gone.
            // The timeout stops a wedged listener from wedging shutdown too.
            let _ = TcpStream::connect_timeout(&address, Duration::from_millis(250));
        }
    }
}

/// Read until the server produces a response or the connection ends.
///
/// Handles short reads and writes and retries on `EINTR` (`NET-006`, #156).
/// py-kms uses `send()` rather than `sendall()`, so a partial write silently
/// truncates a response — the client then sees a malformed PDU and blames the
/// protocol.
fn serve_connection(
    runtime: &Runtime,
    stream: &mut TcpStream,
    peer: SocketAddr,
    strategy: ReadStrategy,
    entropy: &Mutex<Box<dyn Entropy + Send>>,
    started: Instant,
    clock: &dyn Fn() -> Instant,
) -> io::Result<()> {
    let server = &runtime.server;
    let mut connection = {
        let guard = server.lock().map_err(poisoned)?;
        guard.connection(0x1234_5678)
    };

    let mut buffer = [0_u8; 8192];
    let mut consumed = 0_usize;
    let mut last_progress = clock();
    // The application this connection last asked about, for the rate-limit
    // key. Zero until the first request has been decoded.
    let mut last_application = kmsrs_db::Guid::ZERO;

    loop {
        let now = clock();
        // The total-connection deadline. A peer feeding one byte per read
        // timeout would otherwise hold this worker forever.
        if now.saturating_duration_since(started) > CONNECTION_DEADLINE {
            return Ok(());
        }

        let read = match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error)
                if strategy == ReadStrategy::Polled
                    && matches!(error.kind(), ErrorKind::WouldBlock) =>
            {
                // `NET-004` (#153): the deadline is enforced here rather than
                // by a socket option that may silently do nothing.
                if now.saturating_duration_since(last_progress) > READ_TIMEOUT {
                    return Ok(());
                }
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                // The socket enforced the timeout for us.
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        last_progress = now;
        consumed = consumed.saturating_add(read);
        if consumed > MAX_INBOUND {
            return Ok(());
        }

        // `POL-014` (#102): one token per read that carries work, keyed on
        // (source, application). Checked here rather than at accept because a
        // connection is not the unit of abuse — a single connection can carry
        // any number of requests.
        //
        // The application is not known until the request is decoded, so the
        // bucket is keyed on the *previous* request's application on this
        // connection, or the zero GUID for the first. That is deliberate: a
        // client cannot game it by varying the field, because the key it lands
        // in was fixed before it chose.
        {
            let mut limiter = runtime.limiter.lock().map_err(poisoned)?;
            if let Admission::Limited { retry_after } =
                limiter.admit(peer.ip(), last_application, now)
            {
                if let Ok(guard) = server.lock() {
                    guard.logger().message(
                        crate::log::Severity::Warn,
                        "rate-limited",
                        &format!("{}: retry in {}s", peer.ip(), retry_after.as_secs()),
                    );
                }
                return Ok(());
            }
        }

        let handled = {
            let mut guard = server.lock().map_err(poisoned)?;
            let mut entropy = entropy.lock().map_err(poisoned)?;
            let context = RequestContext {
                peer: Some(Peer {
                    address: peer.ip(),
                    port: peer.port(),
                }),
                now,
                host_time: None,
            };
            guard.handle(
                &mut connection,
                buffer.get(..read).unwrap_or(&[]),
                context,
                entropy.as_mut(),
            )
        };

        if !handled.response.is_empty() {
            write_all(stream, &handled.response, strategy, clock, started)?;
        }
        // Remember what this connection is about, for the next request's
        // rate-limit key.
        if let Ok(guard) = server.lock()
            && let Some(event) = guard.host().events().iter().next_back()
        {
            last_application = event.application.0;
        }

        if handled.close {
            return Ok(());
        }
    }
}

/// Write every byte, looping on short writes and retrying on `EINTR`.
fn write_all(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    strategy: ReadStrategy,
    clock: &dyn Fn() -> Instant,
    started: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if clock().saturating_duration_since(started) > CONNECTION_DEADLINE {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "the connection deadline passed mid-write",
            ));
        }
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "the peer stopped accepting bytes",
                ));
            }
            Ok(count) => bytes = bytes.get(count..).unwrap_or(&[]),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error)
                if strategy == ReadStrategy::Polled && error.kind() == ErrorKind::WouldBlock =>
            {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    stream.flush()
}

/// A poisoned lock, as an I/O error.
///
/// Reached only if a worker panicked while holding the server lock. Treating it
/// as an I/O error closes the one connection rather than propagating a panic
/// into every other worker.
fn poisoned<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("a worker panicked while holding the host lock")
}

/// Everything the accept loops share.
#[derive(Debug)]
pub struct Runtime {
    /// The host, its configuration and its state.
    pub server: Mutex<Server>,
    /// The pool ceiling (`NET-005`, #154).
    pub capacity: Capacity,
    /// The stop signal (`NET-007`, #157).
    pub shutdown: Shutdown,
    /// Per-source token buckets (`POL-014`, #102).
    pub limiter: Mutex<RateLimiter>,
}

impl Runtime {
    /// Wrap a server in the shared state the driver needs.
    #[must_use]
    pub fn new(server: Server, limit: usize) -> Self {
        Self {
            server: Mutex::new(server),
            capacity: Capacity::new(limit),
            shutdown: Shutdown::new(),
            limiter: Mutex::new(RateLimiter::new()),
        }
    }

    /// The same, with an explicit rate limiter.
    ///
    /// For tests, which need a burst small enough to reach in a few requests —
    /// the shipped burst is deliberately large enough that a NAT-ted site does
    /// not trip it (`POL-014`, #102).
    #[must_use]
    pub fn with_limiter(server: Server, limit: usize, limiter: RateLimiter) -> Self {
        Self {
            server: Mutex::new(server),
            capacity: Capacity::new(limit),
            shutdown: Shutdown::new(),
            limiter: Mutex::new(limiter),
        }
    }
}

/// Serve until [`Shutdown::request`] is called.
///
/// # Errors
///
/// Returns an [`io::Error`] only if the accept loops could not be started at
/// all. A failure on an individual connection closes that connection and is
/// not propagated — one client's broken socket is not the server's problem.
///
/// One thread per listener (`NET-006`, #155), plus one per in-flight
/// connection up to the pool ceiling. Returns once every accept loop has
/// stopped and every in-flight connection has drained (`NET-007`, #157) —
/// draining rather than killing, because a client mid-activation deserves its
/// answer.
pub fn serve(
    runtime: &Runtime,
    listeners: Vec<Bound>,
    entropy: Box<dyn Entropy + Send>,
    clock: &(dyn Fn() -> Instant + Sync),
) -> io::Result<()> {
    let entropy = Mutex::new(entropy);
    for bound in &listeners {
        runtime.shutdown.register(bound.address);
    }

    std::thread::scope(|scope| {
        for bound in listeners {
            let runtime = &runtime;
            let entropy = &entropy;
            scope.spawn(move || {
                accept_loop(runtime, &bound.listener, entropy, clock);
            });
        }
    });

    Ok(())
}

/// Accept and dispatch until asked to stop.
fn accept_loop(
    runtime: &Runtime,
    listener: &TcpListener,
    entropy: &Mutex<Box<dyn Entropy + Send>>,
    clock: &(dyn Fn() -> Instant + Sync),
) {
    // In-flight connections are joined before this returns, which is what makes
    // shutdown a drain rather than a kill.
    std::thread::scope(|scope| {
        loop {
            if runtime.shutdown.requested() {
                return;
            }
            let (stream, peer) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                // An accept failure is a fact about one connection, not about
                // the listener. vlmcsd treats several of these as fatal.
                Err(_) => continue,
            };

            // Re-checked after accept, because the wakeup connection arrives
            // here (`NET-008`, #158).
            if runtime.shutdown.requested() {
                return;
            }

            // `NET-005` (#154): no permit means close now, not queue.
            let Some(permit) = runtime.capacity.try_acquire() else {
                drop(stream);
                continue;
            };

            // `NET-012` (#161): one client, one identity, from the moment it
            // arrives.
            let peer = normalise_socket(peer);

            // `POL-013` (#101): the access list is checked here, before any RPC
            // state exists — so a refused peer never reaches the parser, and
            // the gate cannot be bypassed by anything in the protocol.
            //
            // A blocked attempt is an event, not a silent drop (`POL-014`,
            // #102): the connection is closed and the reason is logged, so an
            // operator debugging "why can this client not activate" has an
            // answer.
            {
                let access = runtime
                    .server
                    .lock()
                    .map(|server| server.compiled().access)
                    .unwrap_or_default();
                if let Err(denial) = access.check(peer.ip()) {
                    if let Ok(server) = runtime.server.lock() {
                        server.logger().message(
                            crate::log::Severity::Warn,
                            "blocked",
                            &format!("{}: {denial:?}", peer.ip()),
                        );
                    }
                    drop(stream);
                    continue;
                }
            }
            scope.spawn(move || {
                let _permit = permit;
                let mut stream = stream;
                let Ok(strategy) = ReadStrategy::choose(&stream) else {
                    return;
                };
                let started = clock();
                let _ = serve_connection(
                    runtime,
                    &mut stream,
                    peer,
                    strategy,
                    entropy,
                    started,
                    clock,
                );
            });
        }
    });
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
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{Capacity, MAX_CONNECTIONS, Shutdown};

    /// `NET-005` (#154): the pool refuses rather than waits. vlmcsd's `-m` is a
    /// counting semaphore that queues, which is why its own manual recommends
    /// a short timeout as the entire slowloris mitigation.
    #[test]
    fn capacity_refuses_immediately_rather_than_queueing() {
        let capacity = Capacity::new(2);
        let first = capacity.try_acquire().expect("one");
        let second = capacity.try_acquire().expect("two");
        assert_eq!(capacity.in_flight(), 2);

        assert!(
            capacity.try_acquire().is_none(),
            "a third must be refused, not queued"
        );

        drop(second);
        assert_eq!(capacity.in_flight(), 1);
        let third = capacity.try_acquire();
        assert!(third.is_some(), "a slot frees when one is released");

        drop(first);
        drop(third);
        assert_eq!(capacity.in_flight(), 0);
    }

    /// The ceiling holds under contention, which is the only condition that
    /// matters for it.
    #[test]
    fn the_ceiling_holds_under_concurrent_acquisition() {
        let capacity = Capacity::new(8);
        let peak = std::sync::atomic::AtomicUsize::new(0);

        std::thread::scope(|scope| {
            for _ in 0..32 {
                scope.spawn(|| {
                    for _ in 0..200 {
                        if let Some(permit) = capacity.try_acquire() {
                            let now = capacity.in_flight();
                            peak.fetch_max(now, std::sync::atomic::Ordering::AcqRel);
                            drop(permit);
                        }
                    }
                });
            }
        });

        assert_eq!(capacity.in_flight(), 0, "every permit was returned");
        assert!(
            peak.load(std::sync::atomic::Ordering::Acquire) <= 8,
            "the ceiling was exceeded: {}",
            peak.load(std::sync::atomic::Ordering::Acquire)
        );
    }

    #[test]
    fn shutdown_is_idempotent_and_observable() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.requested());
        shutdown.request();
        assert!(shutdown.requested());
        // Called again from anywhere, including a signal-handling thread.
        shutdown.request();
        assert!(shutdown.requested());
    }

    #[test]
    fn the_default_pool_is_bounded() {
        assert!(MAX_CONNECTIONS > 0);
        assert!(
            MAX_CONNECTIONS <= 1024,
            "an unbounded pool is py-kms's thread-per-connection failure"
        );
    }
}

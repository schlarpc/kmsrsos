//! The connection driver (`ARCH-005`, #5; `OS-024`, #340).
//!
//! One tokio runtime, one task per connection, on Linux, Windows and the
//! bare-metal target alike.
//!
//! # Why this is tokio and not mio
//!
//! It was mio until `OS-024` (#340), and the reason was Hermit: tokio worked
//! there only through a four-commit fork of 1.45.0. `OS-018` (#334) removed
//! that target, which took away the whole justification — but the argument for
//! changing is not merely that the old one expired.
//!
//! `kmsrs-server` is pid 1 on the bare-metal target. It is not a KMS listener
//! any more, it is the entire userland, and what a userland does is run several
//! things on timers at once: DHCP renewal at T1 and T2 (`OS-019`, #335), SNTP
//! polling (`OS-020`, #336), `SIGCHLD` reaping and an ACPI power-button watch
//! (`OS-021`, #337), a virtio-serial guest-agent channel (`OS-022`, #338), and
//! the entropy re-test that was already here. **mio has no timers.** Every one
//! of those deadlines would have been hand-rolled bookkeeping against a
//! `poll()` timeout, which is the code that is tedious to write, easy to get
//! subtly wrong, and unpleasant to test.
//!
//! # What that changed, and what it did not
//!
//! The sans-io core did not change at all. `kmsrs-proto` and `kmsrs-policy`
//! still take `&[u8]` and a clock reading and return events (axiom A7); this
//! module is the only thing that knows a socket exists. That property is what
//! made both this migration and the Hermit removal cheap, and it is the second
//! time it has paid for itself.
//!
//! Time did change, deliberately. Connection deadlines are now tokio's, so a
//! test drives them with `#[tokio::test(start_paused = true)]` and
//! `time::advance` rather than with an injected closure. The injected clock
//! survives where it was always load-bearing — a request is still *handed* the
//! instant it happened, so `kmsrs-proto` never reads a clock — but there are no
//! longer two notions of time in one loop, and `poll_timeout` and its
//! hand-rolled `min`-over-deadlines are gone.
//!
//! # Concurrency shape
//!
//! [`Server::handle`] takes `&mut self`: it mutates the CMID table, the event
//! log and the rate limiter, which are the host's state and must be serialised.
//! So the server and the entropy source sit behind one [`Mutex`], taken for the
//! duration of a single request and never held across an `await`. That is
//! exactly what the single-threaded mio loop did — one request at a time — with
//! the difference that reading, writing and waiting now overlap.
//!
//! Per-request state is still owned by the request (`ARCH-006`, #6): each
//! connection's task owns its own [`Connection`] and its own buffers, and no
//! shared map is indexed by a peer-controlled key.
//!
//! # Capacity
//!
//! [`MAX_CONNECTIONS`] is a [`Semaphore`], and the web UI's share
//! ([`Driver::web_limit`]) is a second one that a web connection must also
//! hold. A permit is taken before the task is spawned, so the ceiling is a
//! property of admission rather than something counted after the fact.

use kmsrs_proto::time::Instant;
use kmsrs_proto::wire::connection::Connection;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant as Deadline;

use crate::host::RequestContext;
use crate::net::addr::normalise_socket;
use crate::net::listener::Bound;
use crate::server::Server;
use kmsrs_policy::access::Admission;
use kmsrs_policy::events::Peer;
use kmsrs_proto::entropy::{Entropy, EntropyExt as _};

/// The memory the whole connection table may occupy (`OS-011`, #262).
pub const CONNECTION_STATE_BUDGET: usize = 4 * 1024 * 1024;

/// What one connection's state is assumed to cost, rounded up generously,
/// because the point of this number is to bound the ceiling, not to predict an
/// allocation.
pub const CONNECTION_STATE_BYTES: usize = 4096;

/// The most connections that may be in flight at once.
///
/// Derived from [`CONNECTION_STATE_BUDGET`] and [`CONNECTION_STATE_BYTES`].
/// That is only meaningful because a connection is bounded in what it can hold.
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

/// How often the entropy source is re-tested (`OS-012`, #263).
///
/// Not per request: the test draws 64 bytes and compares them, which is cheap
/// but not free, and a source that degrades does not degrade between two
/// packets in a way five minutes would miss.
pub const ENTROPY_RECHECK_INTERVAL: Duration = Duration::from_mins(5);

/// Ask a running [`Driver`] to stop, from anywhere (`NET-007`, #157).
///
/// Cloneable and safe to call from a signal handler: it sets a flag and wakes
/// every waiter, which allocates nothing and takes no lock.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    requested: Arc<AtomicBool>,
    /// A `watch` rather than a `Notify`, and the difference is a bug that was
    /// briefly real: `Notify::notify_waiters` wakes only the tasks *already
    /// registered*, so an accept loop sitting between two iterations when the
    /// request arrives misses it and blocks in `accept()` for ever. A `watch`
    /// receiver reports a change that happened before it looked.
    tx: watch::Sender<bool>,
    /// Whether the last shutdown request reached the driver (`SEC-012`, #204).
    woke: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Ask the loop to stop accepting and drain what is in flight.
    pub fn request(&self) {
        self.requested.store(true, Ordering::Release);
        // Ignored deliberately: an error means every receiver is gone, which
        // means the driver has already stopped.
        // `send_replace`, not `send`: `send` fails when no receiver exists and
        // then does not update the value at all, so a request that arrives
        // before the driver has subscribed would be lost entirely.
        self.tx.send_replace(true);
        self.woke.store(true, Ordering::Release);
    }

    /// Whether the last [`request`](Self::request) reached the driver.
    #[must_use]
    pub fn woke(&self) -> bool {
        self.woke.load(Ordering::Acquire)
    }

    /// Whether a shutdown has been asked for.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

/// What a listener, and the connections it accepts, are for.
///
/// One driver serves both (`OBS-014`, #190). Two would mean two places where a
/// deadline, a capacity check or a shutdown has to be got right, and the whole
/// reason `ARCH-005` (#5) collapsed to one loop was that the second copy is the
/// one that drifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The KMS protocol.
    Kms,
    /// The read-only web UI (`OBS-008`, #184).
    Web,
}

/// The protocol state one connection is in the middle of.
#[derive(Debug)]
enum Session {
    /// A KMS conversation, in the sans-io state machine.
    ///
    /// Boxed because it is far larger than the web variant — it carries the
    /// reassembly and receive buffers — and an unboxed enum would make every
    /// web connection pay for a KMS one it is not.
    Kms(Box<Connection>),
    /// A web request being accumulated until its head is complete.
    ///
    /// The buffer is bounded at [`crate::web::request::MAX_REQUEST`]: a client
    /// that never sends a blank line is closed rather than buffered
    /// (`OBS-012`, #188).
    Web { inbound: Vec<u8> },
}

/// The server and the entropy source, serialised.
///
/// One mutex rather than two, because a request needs both and taking them
/// separately is a lock ordering nobody would remember. Held for the duration
/// of one `handle` call and never across an `await`.
struct Shared {
    server: Server,
    entropy: Box<dyn Entropy + Send>,
    /// Whether the entropy source still passes its self-test (`OS-012`, #263).
    ///
    /// Start-up already refused to serve on a source that was broken then, so
    /// this is about a source that breaks *later*. What it changes is
    /// `/healthz` and `/metrics`, not whether a request is answered: the
    /// identity was drawn at start-up from a source that worked, and taking a
    /// host out of rotation mid-request would trade a visible failure for an
    /// invisible one.
    entropy_healthy: bool,
}

/// A borrowed [`Server`], for tests and callers that want to read host state.
///
/// A wrapper rather than a bare [`MutexGuard`] because the guard's target is
/// [`Shared`], and every caller wants the server inside it.
#[derive(Debug)]
pub struct ServerRef<'a> {
    guard: MutexGuard<'a, Shared>,
}

impl Deref for ServerRef<'_> {
    type Target = Server;

    fn deref(&self) -> &Server {
        &self.guard.server
    }
}

impl core::fmt::Debug for Shared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Shared")
            .field("entropy_healthy", &self.entropy_healthy)
            .finish_non_exhaustive()
    }
}

/// The driver.
#[derive(Debug)]
pub struct Driver {
    shared: Arc<Mutex<Shared>>,
    listeners: Vec<(std::net::TcpListener, Role, u16)>,
    /// The ports the KMS listeners are on, for the web UI to report.
    kms_ports: Arc<Vec<u16>>,
    /// The slot pid 1 publishes lease facts into (`OS-019`, #335).
    facts: crate::facts::Facts,
    permits: Arc<Semaphore>,
    web_permits: Arc<Semaphore>,
    in_flight: Arc<AtomicUsize>,
    limit: usize,
    requested: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    /// Held only so the channel never closes. Every other receiver belongs to
    /// a task that ends; without this the last one to finish would close the
    /// channel behind the others.
    _shutdown_rx: watch::Receiver<bool>,
    /// When the driver started, so a proto [`Instant`] can be derived from
    /// tokio's monotonic clock.
    origin: Deadline,
}

impl Driver {
    /// Build a driver over the given listeners.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if a listener could not be adopted.
    pub fn new(
        server: Server,
        listeners: Vec<Bound>,
        limit: usize,
        entropy: Box<dyn Entropy + Send>,
    ) -> io::Result<Self> {
        Self::with_roles(
            server,
            listeners
                .into_iter()
                .map(|bound| (bound, Role::Kms))
                .collect(),
            limit,
            true,
            entropy,
        )
    }

    /// The same, with a role per listener (`OBS-014`, #190).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if a listener could not be adopted.
    pub fn with_roles(
        server: Server,
        listeners: Vec<(Bound, Role)>,
        limit: usize,
        entropy_healthy: bool,
        entropy: Box<dyn Entropy + Send>,
    ) -> io::Result<Self> {
        let limit = limit.max(1);
        // The sockets stay `std` until `run`. `TcpListener::from_std` registers
        // with tokio's reactor and panics outside a runtime, and a driver is
        // routinely built before one exists — `entry::serve` binds its ports,
        // decides whether to serve at all, and only then enters `block_on`.
        // Adopting here would make construction order load-bearing for no gain.
        let mut adopted = Vec::with_capacity(listeners.len());
        let mut kms_ports = Vec::new();
        for (bound, role) in listeners {
            // tokio requires a non-blocking listener.
            bound.listener.set_nonblocking(true)?;
            let port = bound.address.port();
            if role == Role::Kms && !kms_ports.contains(&port) {
                kms_ports.push(port);
            }
            adopted.push((bound.listener, role, port));
        }

        let (shutdown_tx, _) = watch::channel(false);
        Ok(Self {
            shared: Arc::new(Mutex::new(Shared {
                server,
                entropy,
                entropy_healthy,
            })),
            listeners: adopted,
            kms_ports: Arc::new(kms_ports),
            facts: crate::facts::Facts::new(),
            permits: Arc::new(Semaphore::new(limit)),
            web_permits: Arc::new(Semaphore::new(Self::web_limit(limit))),
            in_flight: Arc::new(AtomicUsize::new(0)),
            limit,
            requested: Arc::new(AtomicBool::new(false)),
            shutdown_tx: shutdown_tx.clone(),
            _shutdown_rx: shutdown_tx.subscribe(),
            origin: Deadline::now(),
        })
    }

    /// The most connection slots the web UI may hold at once.
    ///
    /// A share of the same budget, not a budget of its own (`OBS-014`, #190).
    /// Two independent limits would mean the host's real ceiling is their sum,
    /// which is a number nobody wrote down; one budget with a share means the
    /// ceiling is [`MAX_CONNECTIONS`] no matter what arrives.
    ///
    /// A quarter, because the web UI must never be able to starve the KMS
    /// listener — a browser tab left open, or a monitor polling `/healthz`
    /// every second, must not cost a client its activation.
    #[must_use]
    pub const fn web_limit(limit: usize) -> usize {
        // `checked_div` rather than `/`: the workspace deny list applies here
        // too, and the fallback is the honest one — a budget too small to
        // divide has room for exactly one.
        match limit.checked_div(4) {
            Some(0) | None => 1,
            Some(share) => share,
        }
    }

    /// A handle that can stop this driver from anywhere.
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            requested: Arc::clone(&self.requested),
            tx: self.shutdown_tx.clone(),
            woke: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The server this driver is driving.
    ///
    /// # Panics
    ///
    /// Panics if the shared mutex was poisoned, which can only happen if a
    /// request handler panicked — and `panic = "abort"` means it did not.
    #[must_use]
    pub fn server(&self) -> ServerRef<'_> {
        ServerRef {
            guard: self
                .shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        }
    }

    /// How many connections are in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// The slot pid 1 publishes lease facts into (`OS-019`, #335).
    ///
    /// Handed out rather than passed in: on the two hosted targets nothing ever
    /// writes it, and a parameter would make every caller state that.
    #[must_use]
    pub fn facts(&self) -> crate::facts::Facts {
        self.facts.clone()
    }

    /// Serve until [`ShutdownHandle::request`] is called and every in-flight
    /// connection has finished.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] only if a listener fails irrecoverably. A
    /// failure on one connection closes that connection; one client's broken
    /// socket is not the server's problem.
    pub async fn run(&mut self) -> io::Result<()> {
        let mut tasks = Vec::new();

        for (listener, role, port) in std::mem::take(&mut self.listeners) {
            let listener = TcpListener::from_std(listener)?;
            let ctx = Context {
                shared: Arc::clone(&self.shared),
                kms_ports: Arc::clone(&self.kms_ports),
                facts: self.facts.clone(),
                permits: Arc::clone(&self.permits),
                web_permits: Arc::clone(&self.web_permits),
                in_flight: Arc::clone(&self.in_flight),
                requested: Arc::clone(&self.requested),
                origin: self.origin,
            };
            // Subscribed here, before the task starts, and moved in whole.
            // Cloning a `watch::Receiver` marks the current value as *seen*, so
            // a receiver made inside the loop would miss a shutdown that landed
            // between the atomic check and the clone — which presents as a
            // driver that never returns from `run`.
            let shutdown = self.shutdown_tx.subscribe();
            tasks.push(tokio::spawn(accept_loop(
                listener, role, port, ctx, shutdown,
            )));
        }

        let entropy = tokio::spawn(entropy_watch(
            Arc::clone(&self.shared),
            self.shutdown_tx.subscribe(),
        ));

        // Subscribe *before* testing the flag, so a request landing between
        // the two is still delivered by `changed()`.
        let mut shutdown = self.shutdown_tx.subscribe();
        while !self.requested.load(Ordering::Acquire) {
            if shutdown.changed().await.is_err() {
                break;
            }
        }

        // A join error means the task panicked, and `panic = "abort"` means it
        // did not. Dropped rather than bound, because there is nothing to do
        // with it either way.
        for task in tasks {
            drop(task.await);
        }
        drop(entropy.await);

        // Drain: every accepted connection gets to finish what it was doing.
        //
        // Acquiring the whole budget rather than polling `in_flight`: a permit
        // comes back when a connection task ends, so holding all of them means
        // none is left. That is a wait rather than a spin, which matters under
        // a paused clock — a poll loop with a sleep in it never makes progress
        // when time only moves on demand.
        let all = u32::try_from(self.limit).unwrap_or(u32::MAX);
        drop(self.permits.acquire_many(all).await);
        Ok(())
    }
}

/// Everything a connection task needs that outlives the [`Driver`] borrow.
#[derive(Clone)]
struct Context {
    shared: Arc<Mutex<Shared>>,
    kms_ports: Arc<Vec<u16>>,
    /// What pid 1 has learned about this machine's network (`OS-019`, #335).
    /// Empty on every target but bare metal.
    facts: crate::facts::Facts,
    permits: Arc<Semaphore>,
    web_permits: Arc<Semaphore>,
    in_flight: Arc<AtomicUsize>,
    requested: Arc<AtomicBool>,
    origin: Deadline,
}

impl Context {
    fn now(&self) -> Instant {
        let nanos = self.origin.elapsed().as_nanos();
        Instant::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn shutting_down(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

/// Accept everything one listener offers, until shutdown.
/// `tokio::select!` picks its starting branch with a modulo over the branch
/// count, which trips `integer-division-remainder-used`. The arithmetic is the
/// macro's, not this program's.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select! expands to a modulo over its own branch count"
)]
async fn accept_loop(
    listener: TcpListener,
    role: Role,
    port: u16,
    ctx: Context,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if ctx.shutting_down() {
            return;
        }

        let accepted = tokio::select! {
            _ = shutdown.changed() => return,
            result = listener.accept() => result,
        };

        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => {
                ctx.lock().server.logger().message(
                    crate::log::Severity::Warn,
                    "accept",
                    &format!("{error}"),
                );
                continue;
            }
        };
        let peer = normalise_socket(peer);

        // `NET-013` (#162): the ACL is checked before anything is read, so a
        // denied peer costs one accept and nothing else.
        //
        // One lock, not two. `if let Err(_) = ctx.lock()...` would hold the
        // guard for the whole body, and `std::sync::Mutex` is not reentrant —
        // logging the denial inside that body deadlocks the driver against
        // itself, which presents as a client that connects and then hangs for
        // ever rather than as a panic.
        let denied = {
            let shared = ctx.lock();
            match shared.server.compiled().access.check(peer.ip()) {
                Ok(()) => None,
                Err(denial) => {
                    shared.server.logger().message(
                        crate::log::Severity::Warn,
                        "blocked",
                        &format!("{}: {denial:?}", peer.ip()),
                    );
                    Some(())
                }
            }
        };
        if denied.is_some() {
            drop(stream);
            continue;
        }

        // A permit before a task, so the ceiling is a property of admission.
        let Ok(permit) = Arc::clone(&ctx.permits).try_acquire_owned() else {
            continue;
        };
        let web_permit = if role == Role::Web {
            match Arc::clone(&ctx.web_permits).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => continue,
            }
        } else {
            None
        };

        let session = match role {
            Role::Kms => {
                let mut shared = ctx.lock();
                let group = association_group(shared.entropy.as_mut());
                Session::Kms(Box::new(shared.server.connection(group, port)))
            }
            Role::Web => Session::Web {
                inbound: Vec::new(),
            },
        };

        ctx.in_flight.fetch_add(1, Ordering::AcqRel);
        let task_ctx = ctx.clone();
        tokio::spawn(async move {
            serve(stream, peer, session, task_ctx.clone()).await;
            task_ctx.in_flight.fetch_sub(1, Ordering::AcqRel);
            drop(permit);
            drop(web_permit);
        });
    }
}

/// Draw one connection's RPC association group (`FP-007`, #68).
///
/// A named function taking an entropy source, rather than four inline bytes,
/// because `FP-026` (#265) audits exactly this: every value a client can
/// observe must be *drawn*, and the way that is checked is by looking at
/// whether the thing producing it was handed a source. A genuine host's
/// association group is unpredictable; a constant one is a fingerprint.
fn association_group(entropy: &mut dyn Entropy) -> u32 {
    entropy.array::<4>().map_or(0, u32::from_le_bytes)
}

/// One connection, from accept to close.
/// `tokio::select!` picks its starting branch with a modulo over the branch
/// count, which trips `integer-division-remainder-used`. The arithmetic is the
/// macro's, not this program's.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select! expands to a modulo over its own branch count"
)]
async fn serve(mut stream: TcpStream, peer: SocketAddr, mut session: Session, ctx: Context) {
    // `checked_add`, because the workspace denies bare arithmetic. A clock at
    // the end of time is not a case this has to serve well, only one it must
    // not wrap on.
    let total = Deadline::now()
        .checked_add(CONNECTION_DEADLINE)
        .unwrap_or_else(Deadline::now);
    let mut last_application = kmsrs_db::Guid::ZERO;
    let mut buffer = [0_u8; 8192];

    loop {
        let idle = Deadline::now()
            .checked_add(READ_TIMEOUT)
            .unwrap_or_else(Deadline::now);
        let deadline = idle.min(total);

        let read = tokio::select! {
            () = tokio::time::sleep_until(deadline) => return,
            result = stream.read(&mut buffer) => result,
        };

        let count = match read {
            // The peer closed its side.
            Ok(0) => return,
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return,
        };

        let now = ctx.now();
        let input = buffer.get(..count).unwrap_or(&[]);

        // `POL-014` (#102): one token per read that carries work, keyed on
        // (source, application). The application is not known until the request
        // is decoded, so the key uses the *previous* request's — fixed before
        // this client chose its fields, so varying them cannot move it to a
        // fresh bucket.
        let handled = {
            let mut shared = ctx.lock();
            if let Admission::Limited { retry_after } =
                shared
                    .server
                    .limiter_mut()
                    .admit(peer.ip(), last_application, now)
            {
                shared.server.logger().message(
                    crate::log::Severity::Warn,
                    "rate-limited",
                    &format!("{}: retry in {}s", peer.ip(), retry_after.as_secs()),
                );
                return;
            }

            let context = RequestContext {
                peer: Some(Peer {
                    address: peer.ip(),
                    port: peer.port(),
                }),
                now,
                host_time: None,
            };

            let handled = match &mut session {
                Session::Kms(connection) => {
                    let Shared {
                        server, entropy, ..
                    } = &mut *shared;
                    server.handle(connection, input, context, entropy.as_mut())
                }
                Session::Web { inbound } => serve_web(&shared, inbound, input, peer, &ctx),
            };

            // Remember what this connection is about, for the next request's
            // rate-limit key.
            if let Some(application) = shared
                .server
                .host()
                .events()
                .iter()
                .next_back()
                .map(|event| event.application.0)
            {
                last_application = application;
            }
            handled
        };

        if handled.response.len() > MAX_OUTBOUND {
            // A peer that has stopped reading must not become a memory leak.
            return;
        }

        // `NET-006` (#156): a partial write silently truncates a response and
        // the client blames the protocol, which is what py-kms's `send()` does.
        // `write_all` is the loop, done once.
        if stream.write_all(&handled.response).await.is_err() {
            return;
        }

        if handled.close {
            drop(stream.shutdown().await);
            return;
        }
    }
}

/// Accumulate a web request and answer it once its head is complete.
///
/// Returns a [`crate::server::Handled`] so the write path is the same one the
/// KMS side uses — the outbound ceiling and the deadline are written once and
/// apply to both (`OBS-014`, #190).
///
/// Every response closes the connection, because there is no keep-alive
/// (`OBS-007`, #183): a browser fetching six fixed pages gains nothing from
/// one, and a persistent connection is how a slow client holds a slot the KMS
/// listener could have had.
fn serve_web(
    shared: &Shared,
    inbound: &mut Vec<u8>,
    input: &[u8],
    peer: SocketAddr,
    ctx: &Context,
) -> crate::server::Handled {
    // Bounded before the bytes are kept, not after (`OBS-012`, #188).
    if inbound.len().saturating_add(input.len()) > crate::web::request::MAX_REQUEST {
        let response = crate::web::Response::error(crate::web::Status::HeadersTooLarge).write(true);
        shared.server.logger().message(
            crate::log::Severity::Warn,
            "web-refused",
            &format!("{}: request head too long", peer.ip()),
        );
        return crate::server::Handled {
            response,
            close: true,
        };
    }
    inbound.extend_from_slice(input);

    // Read once per request rather than per page: it is a lock, and two
    // sections of one page must not disagree about what the domain is.
    let network = ctx.facts.read();
    let snapshot = crate::web::routes::Snapshot {
        listening: !ctx.kms_ports.is_empty(),
        entropy_healthy: shared.entropy_healthy,
        kms_ports: &ctx.kms_ports,
        network: &network,
        identity: shared.server.host().identity(),
        events: shared.server.host().events(),
    };

    match crate::web::answer(inbound, &mut |request| {
        crate::web::routes::route(request, &snapshot)
    }) {
        crate::web::Answered::NeedMore => crate::server::Handled {
            response: Vec::new(),
            close: false,
        },
        crate::web::Answered::Reply { bytes, error, .. } => {
            // The refusal is logged and never sent (`OBS-009`, #185;
            // `SEC-012`, #204): an operator gets the reason, the caller gets a
            // constant.
            if let Some(error) = error {
                shared.server.logger().message(
                    crate::log::Severity::Warn,
                    "web-refused",
                    &format!("{}: {error}", peer.ip()),
                );
            }
            crate::server::Handled {
                response: bytes,
                close: true,
            }
        }
    }
}

/// Re-test the entropy source every [`ENTROPY_RECHECK_INTERVAL`]
/// (`OS-012`, #263).
///
/// Start-up refused to serve on a source that was already broken. This is the
/// one that breaks later.
///
/// The same two questions the start-up test asks, because they are the two that
/// catch the failure that actually happens — a source that keeps succeeding
/// while repeating itself. This is not a test of randomness *quality*; that
/// belongs to the operating system.
/// `tokio::select!` picks its starting branch with a modulo over the branch
/// count, which trips `integer-division-remainder-used`. The arithmetic is the
/// macro's, not this program's.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select! expands to a modulo over its own branch count"
)]
async fn entropy_watch(shared: Arc<Mutex<Shared>>, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(ENTROPY_RECHECK_INTERVAL);
    // The first tick completes immediately; the start-up test already ran.
    ticker.tick().await;

    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {}
        }

        let mut guard = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let healthy = match (guard.entropy.array::<32>(), guard.entropy.array::<32>()) {
            (Ok(first), Ok(second)) => first != second && !first.iter().all(|byte| *byte == 0),
            _ => false,
        };
        if healthy == guard.entropy_healthy {
            continue;
        }
        guard.entropy_healthy = healthy;
        guard.server.logger().message(
            if healthy {
                crate::log::Severity::Info
            } else {
                crate::log::Severity::Error
            },
            "entropy",
            if healthy {
                "the entropy source passes its self-test again"
            } else {
                "the entropy source has started repeating itself; /healthz now \
                 reports unhealthy. Every value this host draws is predictable \
                 from here — see docs/deployment.md."
            },
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly, and \
                  these constants are exactly what is being asserted"
    )]

    use super::{
        CONNECTION_DEADLINE, CONNECTION_STATE_BUDGET, CONNECTION_STATE_BYTES, Driver,
        MAX_CONNECTIONS, MAX_OUTBOUND, READ_TIMEOUT,
    };

    /// `OS-011` (#262): the ceiling is arithmetic on the budget, not a number
    /// somebody liked.
    #[test]
    fn the_connection_ceiling_is_derived_from_the_memory_budget() {
        assert_eq!(
            MAX_CONNECTIONS,
            CONNECTION_STATE_BUDGET
                .checked_div(CONNECTION_STATE_BYTES)
                .expect("the per-connection cost is not zero")
        );
        assert!(MAX_CONNECTIONS > 0);
    }

    /// The ceiling has to be somewhere a real fleet never reaches, because
    /// refusing a legitimate client is a fingerprint (`POL-014`, #102).
    #[test]
    fn the_ceiling_is_far_above_what_a_real_fleet_produces() {
        assert!(MAX_CONNECTIONS >= 1000, "{MAX_CONNECTIONS}");
    }

    /// The total deadline must outlast one idle period, or a healthy client
    /// that pauses once would be cut off by the wrong limit.
    #[test]
    fn the_total_deadline_is_longer_than_the_idle_one() {
        assert!(CONNECTION_DEADLINE > READ_TIMEOUT);
    }

    /// The outbound ceiling holds several responses, so a client pipelining
    /// legitimately is not mistaken for one that has stopped reading.
    #[test]
    fn the_outbound_buffer_is_bounded_but_holds_several_responses() {
        assert!(MAX_OUTBOUND >= 4096);
    }

    /// The web UI's share is a fraction of one budget, never a second budget.
    #[test]
    fn the_web_share_is_a_fraction_of_the_one_budget() {
        assert_eq!(
            Driver::web_limit(MAX_CONNECTIONS),
            MAX_CONNECTIONS.checked_div(4).expect("four is not zero")
        );
        assert_eq!(Driver::web_limit(1), 1, "a tiny budget still admits one");
        assert!(Driver::web_limit(MAX_CONNECTIONS) < MAX_CONNECTIONS);
    }
}

//! RFC 2131's client state machine, with no socket and no clock
//! (`OS-019`, #335).
//!
//! # Why this part is written out
//!
//! `dhcproto` parses and encodes the messages and is what this builds on
//! (axiom A8). What no crate offers separately is the *lease* — INIT,
//! SELECTING, REQUESTING, BOUND, RENEWING, REBINDING, the retransmission
//! backoff, and the T1/T2 timers — because every existing Rust client welds it
//! to sockets or to netlink. `OS-019` (#335) says so, and the shape it asks for
//! is the shape axiom A7 wants anyway: time and entropy are *inputs*, so the
//! whole of RFC 2131 §4.4 can be exercised against captured exchanges without a
//! network.
//!
//! # Time is a `Duration`, not an `Instant`
//!
//! Everything here is measured from when the client started. That is what makes
//! a test able to say "now it is four hours later" in one line, and it is why
//! this module reads no clock: [`crate::net::client`] holds the origin and
//! passes `elapsed`.
//!
//! # What "a renewal returned a different address" does
//!
//! It is the case `OS-019` calls out and the one a client is most likely to get
//! wrong, because it never happens on a healthy network and then happens on a
//! server that was rebuilt. The machine treats it as a new binding: the caller
//! is told to configure the new address, which means removing the old one, and
//! the change is loud. It is not treated as a NAK — the server said yes.

use core::time::Duration;
use dhcproto::v4::{DhcpOption, Flags, HType, Message, MessageType, OptionCode};
use std::net::Ipv4Addr;

/// The first retransmission interval (RFC 2131 §4.1: four seconds, doubling).
const FIRST_BACKOFF: Duration = Duration::from_secs(4);

/// The retransmission ceiling. RFC 2131 §4.1 suggests 64 seconds.
const MAX_BACKOFF: Duration = Duration::from_secs(64);

/// How long to wait after a NAK before starting again.
///
/// RFC 2131 §3.1 item 5: "the client SHOULD wait a minimum of ten seconds
/// before restarting". Without it, a server that NAKs every request turns this
/// client into a broadcast storm.
const AFTER_NAK: Duration = Duration::from_secs(10);

/// How long to keep asking before giving up on a transaction and starting over.
///
/// Four retransmissions is 4 + 8 + 16 + 32 seconds, so a DHCP server that is
/// merely slow to boot is waited for, and one that is absent is retried from
/// INIT rather than escalated forever.
const MAX_ATTEMPTS: u32 = 5;

/// The floor on how often to retry in RENEWING and REBINDING.
///
/// RFC 2131 §4.4.5: half the remaining time, but never more often than once a
/// minute. On an eight-day lease the difference is hours of nothing.
const MIN_RETRY: Duration = Duration::from_mins(1);

/// A lease with this many seconds never expires (RFC 2131 §3.3).
const INFINITE: u32 = u32::MAX;

/// The default fraction of a lease at which renewal starts, when the server
/// sends no option 58: one half.
const T1_NUMERATOR: u32 = 1;
/// See [`T1_NUMERATOR`].
const T1_DENOMINATOR: u32 = 2;

/// The default fraction at which rebinding starts, when the server sends no
/// option 59: seven eighths.
const T2_NUMERATOR: u32 = 7;
/// See [`T2_NUMERATOR`].
const T2_DENOMINATOR: u32 = 8;

/// Where the client is in RFC 2131 §4.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// No lease, nothing sent yet — or a NAK is being waited out.
    Init,
    /// A DISCOVER is outstanding.
    Selecting,
    /// A REQUEST is outstanding and no lease is held yet.
    Requesting,
    /// A lease is held and nothing is outstanding.
    Bound,
    /// Past T1: renewing with the server that granted the lease.
    Renewing,
    /// Past T2: asking anyone at all.
    Rebinding,
}

/// What a lease says this interface should look like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    /// The address to put on the interface.
    pub(crate) address: Ipv4Addr,
    /// The prefix length, from option 1 or from the classful default.
    pub(crate) prefix: u8,
    /// Option 3, most preferred first. The first is the default route.
    pub(crate) routers: Vec<Ipv4Addr>,
    /// Option 6.
    pub(crate) dns: Vec<Ipv4Addr>,
    /// Option 42 — what `OS-020` (#336) uses in preference to the pool.
    pub(crate) ntp: Vec<Ipv4Addr>,
    /// Options 119 and 15, most specific first, deduplicated.
    ///
    /// The zone the `/instructions` page tells an operator to publish
    /// `_vlmcs._tcp` in (`DISC-007`, #149).
    pub(crate) search: Vec<String>,
    /// Which server granted it.
    pub(crate) server: Ipv4Addr,
    /// How long it lasts. `None` for an infinite lease.
    pub(crate) lease: Option<Duration>,
}

/// What the caller should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Broadcast this message on the interface.
    Broadcast(Box<Message>),
    /// Send this message to one server.
    Unicast(Box<Message>, Ipv4Addr),
    /// Put this configuration on the interface, replacing whatever is there.
    Configure(Box<Config>),
    /// Take the address off: the lease is gone and this machine has no claim
    /// to it.
    Deconfigure,
    /// Something an operator should see. Not an error — the caller logs it.
    Note(String),
}

/// A lease held right now.
#[derive(Debug, Clone)]
struct Held {
    config: Config,
    /// When renewal should start.
    t1: Duration,
    /// When rebinding should start.
    t2: Duration,
    /// When the address must come off, if ever.
    expires: Option<Duration>,
}

/// The client (`OS-019`, #335).
#[derive(Debug)]
pub(crate) struct Lease {
    mac: [u8; 6],
    state: State,
    /// The transaction currently in flight.
    xid: u32,
    /// Jitter, deterministic from the seed so a test is reproducible and two
    /// machines still disagree.
    noise: u32,
    /// When the current transaction started, for `secs` and for the backoff.
    began: Duration,
    /// When to act next if nothing arrives.
    deadline: Duration,
    /// The current retransmission interval.
    backoff: Duration,
    /// How many times the current message has been sent.
    attempts: u32,
    /// The lease in hand, in BOUND, RENEWING and REBINDING.
    held: Option<Held>,
    /// The address to put in `ciaddr` and option 50 while asking for one back.
    wanted: Option<Ipv4Addr>,
    /// The server being asked, in SELECTING and REQUESTING.
    offered_by: Option<Ipv4Addr>,
}

impl Lease {
    /// A client that has not sent anything yet.
    ///
    /// `seed` is entropy, supplied rather than read (axiom A7). It becomes the
    /// first transaction ID and seeds the retransmission jitter, so two hosts
    /// booted from the same image at the same instant do not retransmit in
    /// lockstep.
    pub(crate) fn new(mac: [u8; 6], seed: u32, now: Duration) -> Self {
        Self {
            mac,
            state: State::Init,
            xid: seed,
            noise: seed | 1,
            began: now,
            deadline: now,
            backoff: FIRST_BACKOFF,
            attempts: 0,
            held: None,
            wanted: None,
            offered_by: None,
        }
    }

    /// Where the client is, for the log and for tests.
    pub(crate) const fn state(&self) -> State {
        self.state
    }

    /// When [`Self::on_time`] should next be called.
    pub(crate) const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// The lease currently held, if any.
    ///
    /// Read by the tests rather than by the driver, which learns about a lease
    /// from [`Action::Configure`] instead — a state machine that has to be
    /// polled for its result is one where the caller can forget to.
    #[cfg_attr(not(test), expect(dead_code, reason = "read by tests, not the driver"))]
    pub(crate) fn config(&self) -> Option<&Config> {
        self.held.as_ref().map(|held| &held.config)
    }

    /// Nothing arrived and the deadline passed.
    pub(crate) fn on_time(&mut self, now: Duration) -> Vec<Action> {
        match self.state {
            State::Init => self.discover(now),
            State::Selecting => {
                if self.attempts >= MAX_ATTEMPTS {
                    // Nobody answered. Starting over rather than escalating:
                    // the interval is already at its ceiling, and a fresh xid
                    // is what recovers from a server that saw a request it
                    // decided not to answer.
                    self.state = State::Init;
                    let mut actions =
                        vec![Action::Note("no DHCP server answered; retrying".to_owned())];
                    actions.extend(self.discover(now));
                    return actions;
                }
                self.retransmit(now)
            }
            State::Requesting => {
                if self.attempts >= MAX_ATTEMPTS {
                    self.state = State::Init;
                    self.wanted = None;
                    self.offered_by = None;
                    let mut actions = vec![Action::Note(
                        "the server offered an address and then stopped answering".to_owned(),
                    )];
                    actions.extend(self.discover(now));
                    return actions;
                }
                self.retransmit(now)
            }
            State::Bound => self.begin_renewing(now),
            State::Renewing => {
                if self.past_t2(now) {
                    return self.begin_rebinding(now);
                }
                self.retransmit(now)
            }
            State::Rebinding => {
                if self.expired(now) {
                    return self.give_up(now);
                }
                self.retransmit(now)
            }
        }
    }

    /// A datagram arrived and parsed.
    pub(crate) fn on_message(&mut self, message: &Message, now: Duration) -> Vec<Action> {
        // Not ours. A broadcast reply to another client on the same segment is
        // the normal case for this, not an attack.
        if message.xid() != self.xid {
            return Vec::new();
        }
        // RFC 2131 §4.4.1: a reply whose `chaddr` is not ours is not ours
        // either, whatever its xid says.
        if message.chaddr() != self.mac {
            return Vec::new();
        }

        match (self.state, message.opts().msg_type()) {
            (State::Selecting, Some(MessageType::Offer)) => self.accept_offer(message, now),
            (State::Requesting | State::Renewing | State::Rebinding, Some(MessageType::Ack)) => {
                self.accept_ack(message, now)
            }
            (State::Requesting | State::Renewing | State::Rebinding, Some(MessageType::Nak)) => {
                self.accept_nak(message, now)
            }
            _ => Vec::new(),
        }
    }

    /// Start a fresh transaction and broadcast a DISCOVER.
    fn discover(&mut self, now: Duration) -> Vec<Action> {
        self.xid = self.next_xid();
        self.state = State::Selecting;
        self.began = now;
        self.backoff = FIRST_BACKOFF;
        self.attempts = 1;
        self.wanted = None;
        self.offered_by = None;
        self.deadline = self.jittered(now, FIRST_BACKOFF);

        let mut message = self.blank(MessageType::Discover, Ipv4Addr::UNSPECIFIED, now);
        message.set_flags(Flags::default().set_broadcast());
        vec![Action::Broadcast(Box::new(message))]
    }

    /// Send whatever the current state is sending, again.
    fn retransmit(&mut self, now: Duration) -> Vec<Action> {
        self.attempts = self.attempts.saturating_add(1);

        match self.state {
            State::Selecting => {
                self.backoff = (self.backoff.saturating_mul(2)).min(MAX_BACKOFF);
                self.deadline = self.jittered(now, self.backoff);
                let mut message = self.blank(MessageType::Discover, Ipv4Addr::UNSPECIFIED, now);
                message.set_flags(Flags::default().set_broadcast());
                vec![Action::Broadcast(Box::new(message))]
            }
            State::Requesting => {
                self.backoff = (self.backoff.saturating_mul(2)).min(MAX_BACKOFF);
                self.deadline = self.jittered(now, self.backoff);
                vec![Action::Broadcast(Box::new(self.selecting_request(now)))]
            }
            State::Renewing => {
                let target = self.held.as_ref().map_or(now, |held| held.t2);
                self.deadline = halfway(now, target);
                let server = self.held.as_ref().map(|held| held.config.server);
                let message = self.bound_request(now);
                server.map_or_else(
                    || vec![Action::Broadcast(Box::new(message.clone()))],
                    |server| vec![Action::Unicast(Box::new(message.clone()), server)],
                )
            }
            State::Rebinding => {
                let target = self
                    .held
                    .as_ref()
                    .and_then(|held| held.expires)
                    .unwrap_or(now);
                self.deadline = halfway(now, target);
                let mut message = self.bound_request(now);
                message.set_flags(Flags::default().set_broadcast());
                vec![Action::Broadcast(Box::new(message))]
            }
            // Neither of these has anything outstanding to resend.
            State::Init | State::Bound => Vec::new(),
        }
    }

    /// Take the first offer and ask for it.
    ///
    /// First rather than best. RFC 2131 lets a client collect offers and
    /// choose; there is nothing here to choose *on* — this host wants an
    /// address, not a good one — and waiting for a second offer that will not
    /// come costs a fixed delay on every boot of every single-server network,
    /// which is all of them.
    fn accept_offer(&mut self, message: &Message, now: Duration) -> Vec<Action> {
        let offered = message.yiaddr();
        if offered.is_unspecified() {
            return Vec::new();
        }
        let server = server_identifier(message).unwrap_or_else(|| message.siaddr());

        self.state = State::Requesting;
        self.wanted = Some(offered);
        self.offered_by = Some(server);
        self.backoff = FIRST_BACKOFF;
        self.attempts = 1;
        self.deadline = self.jittered(now, FIRST_BACKOFF);

        vec![
            Action::Note(format!("{server} offered {offered}")),
            Action::Broadcast(Box::new(self.selecting_request(now))),
        ]
    }

    /// The server agreed. Bind, and work out when to renew.
    fn accept_ack(&mut self, message: &Message, now: Duration) -> Vec<Action> {
        let address = if message.yiaddr().is_unspecified() {
            // A renewal ACK may leave `yiaddr` clear and mean "the one you
            // have". Nothing in RFC 2131 requires it to be set on a renewal.
            self.held
                .as_ref()
                .map_or(message.yiaddr(), |held| held.config.address)
        } else {
            message.yiaddr()
        };
        if address.is_unspecified() {
            return Vec::new();
        }

        let previous = self.held.as_ref().map(|held| held.config.address);
        let config = configuration(message, address);
        let lease = config.lease;

        let t1 = fraction(lease, T1_NUMERATOR, T1_DENOMINATOR);
        let t2 = fraction(lease, T2_NUMERATOR, T2_DENOMINATOR);
        let t1 = option_seconds(message, OptionCode::Renewal).or(t1);
        let t2 = option_seconds(message, OptionCode::Rebinding).or(t2);

        let mut actions = Vec::new();

        // The case `OS-019` (#335) singles out. A server that has been rebuilt,
        // or a second server answering a REBINDING broadcast, can hand back a
        // *different* address — and it is an ACK, so it is not a refusal. The
        // old address has to come off the interface or the machine answers on
        // two, and an operator whose SRV record points at the old one needs to
        // know without reading a packet capture.
        if let Some(previous) = previous
            && previous != address
        {
            actions.push(Action::Note(format!(
                "the lease moved from {previous} to {address}; anything \
                 pointing at {previous} — an SRV record, a client's \
                 slmgr /skms — is now wrong"
            )));
        }

        let changed = previous != Some(address)
            || self.held.as_ref().map(|held| &held.config) != Some(&config);

        self.held = Some(Held {
            config: config.clone(),
            t1: now.saturating_add(t1.unwrap_or(Duration::MAX)),
            t2: now.saturating_add(t2.unwrap_or(Duration::MAX)),
            expires: lease.map(|lease| now.saturating_add(lease)),
        });
        self.state = State::Bound;
        self.wanted = None;
        self.offered_by = None;
        self.attempts = 0;
        self.deadline = self.held.as_ref().map_or(now, |held| held.t1);

        if changed {
            actions.push(Action::Configure(Box::new(config)));
        }
        actions
    }

    /// The server refused. Whatever was held is gone.
    fn accept_nak(&mut self, message: &Message, now: Duration) -> Vec<Action> {
        let reason = match message.opts().get(OptionCode::Message) {
            Some(DhcpOption::Message(text)) => format!(": {text}"),
            _ => String::new(),
        };
        let had = self.held.is_some();

        self.held = None;
        self.wanted = None;
        self.offered_by = None;
        self.state = State::Init;
        self.attempts = 0;
        // RFC 2131 §3.1: at least ten seconds, or a server that NAKs
        // everything turns this into a broadcast storm.
        self.deadline = now.saturating_add(AFTER_NAK);

        let mut actions = vec![Action::Note(format!(
            "the server refused the lease{reason}"
        ))];
        if had {
            actions.push(Action::Deconfigure);
        }
        actions
    }

    /// T1 arrived: start renewing with the server that granted the lease.
    fn begin_renewing(&mut self, now: Duration) -> Vec<Action> {
        let Some(held) = self.held.as_ref() else {
            // BOUND with nothing held cannot happen, and if it does the useful
            // response is to go and get a lease rather than to assert.
            return self.discover(now);
        };
        let server = held.config.server;
        let t2 = held.t2;

        self.state = State::Renewing;
        self.xid = self.next_xid();
        self.began = now;
        self.attempts = 1;
        self.deadline = halfway(now, t2);

        vec![
            Action::Note("renewing".to_owned()),
            Action::Unicast(Box::new(self.bound_request(now)), server),
        ]
    }

    /// T2 arrived: the granting server is not answering, so ask anybody.
    fn begin_rebinding(&mut self, now: Duration) -> Vec<Action> {
        let expires = self.held.as_ref().and_then(|held| held.expires);
        self.state = State::Rebinding;
        self.xid = self.next_xid();
        self.began = now;
        self.attempts = 1;
        self.deadline = halfway(now, expires.unwrap_or(now));

        let mut message = self.bound_request(now);
        message.set_flags(Flags::default().set_broadcast());
        vec![
            Action::Note(
                "the server that granted this lease has stopped answering; \
                 asking any server on this segment"
                    .to_owned(),
            ),
            Action::Broadcast(Box::new(message)),
        ]
    }

    /// The lease ran out with nobody willing to renew it.
    ///
    /// The address comes off. That is the unpleasant answer and it is the
    /// correct one: the machine has no claim to it, the DHCP server may have
    /// given it to somebody else, and two hosts answering on one address is
    /// worse for the operator than one host answering on none. It is said
    /// loudly, and the client goes straight back to DISCOVER.
    fn give_up(&mut self, now: Duration) -> Vec<Action> {
        let address = self.held.as_ref().map(|held| held.config.address);
        self.held = None;

        let mut actions = vec![Action::Note(match address {
            Some(address) => format!(
                "the lease on {address} expired and no server renewed it; \
                 giving the address up and starting again"
            ),
            None => "the lease expired".to_owned(),
        })];
        actions.push(Action::Deconfigure);
        actions.extend(self.discover(now));
        actions
    }

    /// A REQUEST that answers an OFFER (RFC 2131 §4.3.2, the SELECTING form).
    ///
    /// `ciaddr` clear, option 50 carrying the address, option 54 naming the
    /// server. Broadcast, because the client still has no address to be
    /// unicast to.
    fn selecting_request(&mut self, now: Duration) -> Message {
        let wanted = self.wanted;
        let offered_by = self.offered_by;
        let mut message = self.blank(MessageType::Request, Ipv4Addr::UNSPECIFIED, now);
        message.set_flags(Flags::default().set_broadcast());
        if let Some(wanted) = wanted {
            message
                .opts_mut()
                .insert(DhcpOption::RequestedIpAddress(wanted));
        }
        if let Some(server) = offered_by {
            message
                .opts_mut()
                .insert(DhcpOption::ServerIdentifier(server));
        }
        message
    }

    /// A REQUEST that renews or rebinds (RFC 2131 §4.3.2, the BOUND form).
    ///
    /// The inverse of the above, and the pair of mistakes here is what produces
    /// a server that NAKs every renewal: `ciaddr` **must** carry the address and
    /// options 50 and 54 **must** be absent.
    fn bound_request(&mut self, now: Duration) -> Message {
        let address = self
            .held
            .as_ref()
            .map_or(Ipv4Addr::UNSPECIFIED, |held| held.config.address);
        self.blank(MessageType::Request, address, now)
    }

    /// The fields every message this client sends has in common.
    fn blank(&self, kind: MessageType, ciaddr: Ipv4Addr, now: Duration) -> Message {
        // `new_with_id` rather than `Message::new`, which reads the thread RNG
        // for a transaction ID. Axiom A7 says entropy is an input to this
        // module, and the one that matters is the xid.
        let mut message = Message::new_with_id(
            self.xid,
            ciaddr,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &self.mac,
        );
        message.set_htype(HType::Eth);
        // Seconds since this transaction began. Relay agents and backup servers
        // read it to decide whether the primary has failed, so a client that
        // always sends zero is one a failover pair never helps.
        message
            .set_secs(u16::try_from(now.saturating_sub(self.began).as_secs()).unwrap_or(u16::MAX));

        let opts = message.opts_mut();
        opts.insert(DhcpOption::MessageType(kind));
        // RFC 2132 §9.14: type 1 is a hardware address, and it must agree with
        // `chaddr` or a server may hand out two leases for one machine.
        let mut identifier = Vec::with_capacity(7);
        identifier.push(1);
        identifier.extend_from_slice(&self.mac);
        opts.insert(DhcpOption::ClientIdentifier(identifier));
        // 1500 less the IPv4 and UDP headers, so a reply carrying a long option
        // 119 still arrives in one frame.
        opts.insert(DhcpOption::MaxMessageSize(1472));
        opts.insert(DhcpOption::ParameterRequestList(vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
            OptionCode::DomainNameServer,
            OptionCode::DomainName,
            OptionCode::BroadcastAddr,
            OptionCode::NtpServers,
            OptionCode::AddressLeaseTime,
            OptionCode::Renewal,
            OptionCode::Rebinding,
            OptionCode::DomainSearch,
        ]));
        message
    }

    /// Whether T2 has arrived.
    fn past_t2(&self, now: Duration) -> bool {
        self.held.as_ref().is_some_and(|held| now >= held.t2)
    }

    /// Whether the lease has run out.
    fn expired(&self, now: Duration) -> bool {
        self.held
            .as_ref()
            .and_then(|held| held.expires)
            .is_some_and(|expires| now >= expires)
    }

    /// A deadline `after` from now, with RFC 2131 §4.1's randomisation.
    ///
    /// "randomized by the value of a uniform random number chosen from the
    /// range -1 to +1". Without it, every machine booted from one image at one
    /// instant retransmits together forever.
    fn jittered(&mut self, now: Duration, after: Duration) -> Duration {
        let noise = self.next_noise();
        // A signed second, expressed as an unsigned range so nothing here has
        // to be careful about subtracting past zero. `checked_rem` rather than
        // `%`, which axiom A2's lint table disallows because `% 0` panics —
        // the divisor is a literal here, but the rule is not worth an exception.
        let offset = Duration::from_millis(u64::from(noise.checked_rem(2000).unwrap_or(0)));
        now.saturating_add(after)
            .saturating_add(offset)
            .saturating_sub(Duration::from_secs(1))
    }

    /// The next transaction ID.
    fn next_xid(&mut self) -> u32 {
        self.next_noise()
    }

    /// One step of an xorshift, which is all the randomness a retransmission
    /// interval needs.
    ///
    /// Not a cryptographic generator and not pretending to be one. The entropy
    /// that matters in this program is the identity material, which comes from
    /// [`kmsrs_server::OsEntropy`] and its self-test (`OS-012`, #263). What this
    /// protects against is two identical machines being in lockstep.
    fn next_noise(&mut self) -> u32 {
        let mut state = self.noise;
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        self.noise = state | 1;
        self.noise
    }
}

/// The midpoint between now and `target`, floored at [`MIN_RETRY`].
///
/// RFC 2131 §4.4.5: retransmit at "one-half of the remaining time", down to a
/// minimum of sixty seconds.
fn halfway(now: Duration, target: Duration) -> Duration {
    let remaining = target.saturating_sub(now);
    let half = remaining
        .checked_div(2)
        .unwrap_or(MIN_RETRY)
        .max(MIN_RETRY)
        .min(remaining.max(MIN_RETRY));
    now.saturating_add(half)
}

/// A fraction of a lease, or `None` for an infinite one.
fn fraction(lease: Option<Duration>, numerator: u32, denominator: u32) -> Option<Duration> {
    let lease = lease?;
    let seconds = lease.as_secs().checked_mul(u64::from(numerator))?;
    let seconds = seconds.checked_div(u64::from(denominator))?;
    Some(Duration::from_secs(seconds))
}

/// Option 54, if the server sent one.
fn server_identifier(message: &Message) -> Option<Ipv4Addr> {
    match message.opts().get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(address)) => Some(*address),
        _ => None,
    }
}

/// A `u32`-seconds option, as a `Duration`.
fn option_seconds(message: &Message, code: OptionCode) -> Option<Duration> {
    let seconds = match (code, message.opts().get(code)) {
        (OptionCode::AddressLeaseTime, Some(DhcpOption::AddressLeaseTime(seconds)))
        | (OptionCode::Renewal, Some(DhcpOption::Renewal(seconds)))
        | (OptionCode::Rebinding, Some(DhcpOption::Rebinding(seconds))) => *seconds,
        _ => return None,
    };
    if seconds == INFINITE {
        return None;
    }
    Some(Duration::from_secs(u64::from(seconds)))
}

/// Everything the interface should be configured with, out of one reply.
fn configuration(message: &Message, address: Ipv4Addr) -> Config {
    let opts = message.opts();

    let mask = match opts.get(OptionCode::SubnetMask) {
        Some(DhcpOption::SubnetMask(mask)) => Some(*mask),
        _ => None,
    };
    let routers = match opts.get(OptionCode::Router) {
        Some(DhcpOption::Router(addresses)) => addresses.clone(),
        _ => Vec::new(),
    };
    let dns = match opts.get(OptionCode::DomainNameServer) {
        Some(DhcpOption::DomainNameServer(addresses)) => addresses.clone(),
        _ => Vec::new(),
    };
    let ntp = match opts.get(OptionCode::NtpServers) {
        Some(DhcpOption::NtpServers(addresses)) => addresses.clone(),
        _ => Vec::new(),
    };

    // Option 119 first, because RFC 3397 §1 says it supersedes option 15 where
    // both are present — and both usually are. Option 15's single domain is
    // appended rather than dropped, since a server that sends only 15 is the
    // common case and a server that sends both may disagree with itself.
    let mut search: Vec<String> = match opts.get(OptionCode::DomainSearch) {
        Some(DhcpOption::DomainSearch(names)) => names
            .iter()
            .map(|name| name.to_string().trim_end_matches('.').to_owned())
            .filter(|name| !name.is_empty())
            .collect(),
        _ => Vec::new(),
    };
    if let Some(DhcpOption::DomainName(domain)) = opts.get(OptionCode::DomainName) {
        let domain = domain.trim().trim_end_matches('.');
        if !domain.is_empty() && !search.iter().any(|seen| seen == domain) {
            search.push(domain.to_owned());
        }
    }

    Config {
        address,
        prefix: mask.map_or_else(|| classful_prefix(address), prefix_of),
        routers,
        dns,
        ntp,
        search,
        server: server_identifier(message).unwrap_or_else(|| message.siaddr()),
        lease: option_seconds(message, OptionCode::AddressLeaseTime),
    }
}

/// The prefix length of a netmask.
///
/// `leading_ones` rather than counting set bits, so a non-contiguous mask —
/// which is illegal and which some appliances still emit — yields the sane
/// prefix rather than a wider one.
fn prefix_of(mask: Ipv4Addr) -> u8 {
    u8::try_from(u32::from_be_bytes(mask.octets()).leading_ones()).unwrap_or(32)
}

/// The classful prefix for an address, for a server that sent no option 1.
///
/// RFC 2131 §4.4.1 leaves the client to work it out, and classful addressing
/// has been obsolete since 1993 — but "the server sent no netmask" has to
/// produce *something*, and a /24 guess would be wrong on the /16 private
/// ranges where this is most likely to happen.
fn classful_prefix(address: Ipv4Addr) -> u8 {
    match address.octets().first() {
        Some(&first) if first < 128 => 8,
        Some(&first) if first < 192 => 16,
        _ => 24,
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

    use super::{Action, Config, Lease, State, classful_prefix, prefix_of};
    use core::time::Duration;
    use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
    use std::net::Ipv4Addr;

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const OFFERED: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

    fn seconds(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Within a second either side, which is the randomisation RFC 2131 §4.1
    /// asks for.
    fn about(interval: Duration, expected: u64) -> bool {
        interval >= seconds(expected).saturating_sub(seconds(1))
            && interval <= seconds(expected).saturating_add(seconds(1))
    }

    /// A reply from the server, of the kind and with the options given.
    fn reply(kind: MessageType, xid: u32, yiaddr: Ipv4Addr, options: Vec<DhcpOption>) -> Message {
        let mut message = Message::new_with_id(
            xid,
            Ipv4Addr::UNSPECIFIED,
            yiaddr,
            SERVER,
            Ipv4Addr::UNSPECIFIED,
            &MAC,
        );
        message.set_opcode(dhcproto::v4::Opcode::BootReply);
        message.opts_mut().insert(DhcpOption::MessageType(kind));
        message
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(SERVER));
        for option in options {
            message.opts_mut().insert(option);
        }
        message
    }

    /// The options a normal server sends with an ACK.
    fn normal_lease(lease: u32) -> Vec<DhcpOption> {
        vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![SERVER]),
            DhcpOption::DomainNameServer(vec![SERVER]),
            DhcpOption::DomainName("corp.example.net".to_owned()),
            DhcpOption::NtpServers(vec![Ipv4Addr::new(10, 0, 0, 1)]),
            DhcpOption::AddressLeaseTime(lease),
        ]
    }

    /// Drive a client from nothing to BOUND, returning it and the lease's xid.
    fn bind(lease_seconds: u32) -> Lease {
        let mut client = Lease::new(MAC, 0x1234_5678, seconds(0));
        let actions = client.on_time(seconds(0));
        assert!(matches!(actions.as_slice(), [Action::Broadcast(_)]));
        assert_eq!(client.state(), State::Selecting);

        let offer = reply(MessageType::Offer, client.xid, OFFERED, Vec::new());
        client.on_message(&offer, seconds(0));
        assert_eq!(client.state(), State::Requesting);

        let ack = reply(
            MessageType::Ack,
            client.xid,
            OFFERED,
            normal_lease(lease_seconds),
        );
        client.on_message(&ack, seconds(0));
        assert_eq!(client.state(), State::Bound);
        client
    }

    /// The whole of the happy path, which is the exchange every boot performs.
    #[test]
    fn discover_offer_request_ack_binds() {
        let client = bind(3600);
        let config = client.config().unwrap();

        assert_eq!(config.address, OFFERED);
        assert_eq!(config.prefix, 24);
        assert_eq!(config.routers, [SERVER]);
        assert_eq!(config.server, SERVER);
        assert_eq!(config.lease, Some(seconds(3600)));
        assert_eq!(config.ntp, [Ipv4Addr::new(10, 0, 0, 1)]);
        assert_eq!(config.search, ["corp.example.net"]);
    }

    /// RFC 2131 §4.3.2: the SELECTING form of REQUEST carries option 50 and
    /// option 54 and leaves `ciaddr` clear.
    #[test]
    fn the_request_that_answers_an_offer_carries_option_50() {
        let mut client = Lease::new(MAC, 1, seconds(0));
        client.on_time(seconds(0));
        let offer = reply(MessageType::Offer, client.xid, OFFERED, Vec::new());
        let actions = client.on_message(&offer, seconds(0));

        let Some(Action::Broadcast(request)) = actions
            .iter()
            .find(|action| matches!(action, Action::Broadcast(_)))
        else {
            panic!("no REQUEST was sent: {actions:?}");
        };
        assert!(request.ciaddr().is_unspecified(), "ciaddr must be clear");
        assert!(matches!(
            request.opts().get(OptionCode::RequestedIpAddress),
            Some(DhcpOption::RequestedIpAddress(address)) if *address == OFFERED
        ));
        assert!(matches!(
            request.opts().get(OptionCode::ServerIdentifier),
            Some(DhcpOption::ServerIdentifier(address)) if *address == SERVER
        ));
    }

    /// And the inverse, which is where a client that renews badly goes wrong:
    /// the BOUND form must use `ciaddr` and must **not** carry option 50 or 54.
    #[test]
    fn the_renewal_request_uses_ciaddr_and_omits_options_50_and_54() {
        let mut client = bind(3600);
        // T1 for a 3600 s lease is 1800 s.
        let actions = client.on_time(seconds(1800));
        assert_eq!(client.state(), State::Renewing);

        let Some(Action::Unicast(request, to)) = actions
            .iter()
            .find(|action| matches!(action, Action::Unicast(..)))
        else {
            panic!("a renewal is unicast to the granting server: {actions:?}");
        };
        assert_eq!(*to, SERVER);
        assert_eq!(request.ciaddr(), OFFERED);
        assert!(request.opts().get(OptionCode::RequestedIpAddress).is_none());
        assert!(request.opts().get(OptionCode::ServerIdentifier).is_none());
        assert!(!request.flags().broadcast(), "a renewal is not broadcast");
    }

    /// T1 and T2 default to one half and seven eighths of the lease.
    #[test]
    fn renewal_starts_at_half_the_lease_and_rebinding_at_seven_eighths() {
        let mut client = bind(800);
        assert_eq!(client.deadline(), seconds(400), "T1");

        client.on_time(seconds(400));
        assert_eq!(client.state(), State::Renewing);

        // Nothing answers. At T2 = 700 the client starts asking everybody.
        client.on_time(seconds(700));
        assert_eq!(client.state(), State::Rebinding);
    }

    /// Options 58 and 59 override the defaults, and transposing them is the
    /// mistake this catches.
    #[test]
    fn options_58_and_59_override_the_default_timers() {
        let mut client = Lease::new(MAC, 1, seconds(0));
        client.on_time(seconds(0));
        let offer = reply(MessageType::Offer, client.xid, OFFERED, Vec::new());
        client.on_message(&offer, seconds(0));

        let mut options = normal_lease(3600);
        options.push(DhcpOption::Renewal(100));
        options.push(DhcpOption::Rebinding(200));
        let ack = reply(MessageType::Ack, client.xid, OFFERED, options);
        client.on_message(&ack, seconds(0));

        assert_eq!(client.deadline(), seconds(100), "T1 is option 58, not 1800");
        client.on_time(seconds(100));
        assert_eq!(client.state(), State::Renewing);
        client.on_time(seconds(200));
        assert_eq!(client.state(), State::Rebinding, "T2 is option 59");
    }

    /// The case `OS-019` (#335) singles out: a renewal that comes back with a
    /// different address. It is an ACK, so it is not a refusal — the interface
    /// is reconfigured and the change is said out loud, because anything
    /// pointing at the old address is now wrong.
    #[test]
    fn a_renewal_that_returns_a_different_address_reconfigures_and_says_so() {
        let mut client = bind(3600);
        client.on_time(seconds(1800));

        let moved = Ipv4Addr::new(192, 168, 1, 77);
        let ack = reply(MessageType::Ack, client.xid, moved, normal_lease(3600));
        let actions = client.on_message(&ack, seconds(1800));

        assert_eq!(client.state(), State::Bound);
        assert_eq!(client.config().unwrap().address, moved);
        assert!(
            actions.iter().any(|action| matches!(
                action,
                Action::Configure(config) if config.address == moved
            )),
            "the new address must reach the interface: {actions:?}"
        );
        assert!(
            actions.iter().any(|action| matches!(
                action,
                Action::Note(text) if text.contains("192.168.1.50") && text.contains("SRV")
            )),
            "an address change has to be loud: {actions:?}"
        );
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, Action::Deconfigure)),
            "an ACK is not a refusal, so nothing is torn down: {actions:?}"
        );
    }

    /// A renewal that returns the *same* everything does not churn the
    /// interface. Reconfiguring on every renewal would drop the address and
    /// put it back, which on a busy host is a connection reset every few hours.
    #[test]
    fn an_unchanged_renewal_does_not_reconfigure() {
        let mut client = bind(3600);
        client.on_time(seconds(1800));
        let ack = reply(MessageType::Ack, client.xid, OFFERED, normal_lease(3600));
        let actions = client.on_message(&ack, seconds(1800));

        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, Action::Configure(_))),
            "nothing changed, so nothing should be applied: {actions:?}"
        );
        assert_eq!(client.state(), State::Bound);
        assert_eq!(client.deadline(), seconds(1800 + 1800), "T1 moved forward");
    }

    /// A NAK gives the address up and waits before trying again.
    #[test]
    fn a_nak_deconfigures_and_backs_off() {
        let mut client = bind(3600);
        client.on_time(seconds(1800));

        let nak = reply(
            MessageType::Nak,
            client.xid,
            Ipv4Addr::UNSPECIFIED,
            vec![DhcpOption::Message("lease not found".to_owned())],
        );
        let actions = client.on_message(&nak, seconds(1800));

        assert_eq!(client.state(), State::Init);
        assert!(client.config().is_none());
        assert!(actions.contains(&Action::Deconfigure));
        assert!(
            actions.iter().any(|action| matches!(
                action, Action::Note(text) if text.contains("lease not found")
            )),
            "the server's reason is worth repeating: {actions:?}"
        );
        assert_eq!(
            client.deadline(),
            seconds(1810),
            "RFC 2131 §3.1: at least ten seconds before restarting"
        );
    }

    /// The lease runs out with nobody answering. The address must come off —
    /// the server may have given it to someone else, and two hosts on one
    /// address is worse than none.
    #[test]
    fn an_expired_lease_gives_the_address_up_and_starts_again() {
        let mut client = bind(800);
        client.on_time(seconds(400));
        client.on_time(seconds(700));
        assert_eq!(client.state(), State::Rebinding);

        let actions = client.on_time(seconds(800));

        assert!(actions.contains(&Action::Deconfigure));
        assert!(client.config().is_none());
        assert_eq!(
            client.state(),
            State::Selecting,
            "straight back to DISCOVER"
        );
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::Broadcast(_))),
            "a new DISCOVER goes out at once: {actions:?}"
        );
    }

    /// An infinite lease is never renewed and never expires.
    #[test]
    fn an_infinite_lease_is_never_renewed() {
        let client = bind(u32::MAX);
        assert_eq!(client.config().unwrap().lease, None);
        assert_eq!(client.deadline(), Duration::MAX);
    }

    /// A reply for somebody else's transaction is ignored, which on a segment
    /// with several clients is most of the broadcast traffic.
    #[test]
    fn another_clients_reply_is_ignored() {
        let mut client = Lease::new(MAC, 1, seconds(0));
        client.on_time(seconds(0));

        let wrong_xid = reply(
            MessageType::Offer,
            client.xid.wrapping_add(1),
            OFFERED,
            Vec::new(),
        );
        assert!(client.on_message(&wrong_xid, seconds(0)).is_empty());
        assert_eq!(client.state(), State::Selecting);

        let mut wrong_mac = reply(MessageType::Offer, client.xid, OFFERED, Vec::new());
        wrong_mac.set_chaddr(&[0xAA; 6]);
        assert!(client.on_message(&wrong_mac, seconds(0)).is_empty());
        assert_eq!(client.state(), State::Selecting);
    }

    /// Retransmission doubles and is jittered, and the jitter keeps two
    /// identical machines out of lockstep.
    #[test]
    fn retransmission_backs_off_and_is_jittered() {
        let mut first = Lease::new(MAC, 0xAAAA_AAAA, seconds(0));
        let mut second = Lease::new(MAC, 0x5555_5555, seconds(0));
        first.on_time(seconds(0));
        second.on_time(seconds(0));

        assert_ne!(
            first.deadline(),
            second.deadline(),
            "two hosts booted together must not retransmit together"
        );

        // The DISCOVER itself is due four seconds after it was sent.
        assert!(
            about(first.deadline(), 4),
            "the first retransmission is at 4s: {:?}",
            first.deadline()
        );

        // Then doubling, to a ceiling of 64.
        let mut previous = Duration::ZERO;
        for expected in [8_u64, 16, 32, 64] {
            let now = first.deadline();
            first.on_time(now);
            let interval = first.deadline().saturating_sub(now);
            assert!(
                about(interval, expected),
                "interval {interval:?} is not {expected}s ± 1s"
            );
            assert!(now > previous, "time only moves forwards");
            previous = now;
        }

        // The fifth attempt gives up on the transaction and starts a fresh one
        // rather than escalating past the ceiling — a new xid is what recovers
        // from a server that saw a request and decided not to answer it.
        let now = first.deadline();
        let before = first.xid;
        first.on_time(now);
        assert!(
            about(first.deadline().saturating_sub(now), 4),
            "a restart is back at the first interval"
        );
        assert_ne!(first.xid, before, "and it is a new transaction");
    }

    /// Nobody answers at all. The client keeps trying rather than stopping,
    /// and says so — a machine that silently never gets an address is the
    /// failure #342 is about.
    #[test]
    fn a_silent_network_is_retried_and_reported() {
        let mut client = Lease::new(MAC, 7, seconds(0));
        client.on_time(seconds(0));

        let mut said_something = false;
        for _ in 0..8 {
            let now = client.deadline();
            let actions = client.on_time(now);
            assert!(
                actions
                    .iter()
                    .any(|action| matches!(action, Action::Broadcast(_))),
                "the client must keep asking"
            );
            said_something |= actions
                .iter()
                .any(|action| matches!(action, Action::Note(_)));
        }
        assert!(said_something, "silence has to be reported at least once");
    }

    /// A server that sends no option 1. Classful, because a /24 guess is wrong
    /// on exactly the private ranges where this happens.
    #[test]
    fn a_missing_netmask_falls_back_to_the_classful_prefix() {
        assert_eq!(classful_prefix(Ipv4Addr::new(10, 0, 0, 5)), 8);
        assert_eq!(classful_prefix(Ipv4Addr::new(172, 16, 0, 5)), 16);
        assert_eq!(classful_prefix(Ipv4Addr::new(192, 168, 0, 5)), 24);
    }

    #[test]
    fn a_netmask_becomes_a_prefix() {
        assert_eq!(prefix_of(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(prefix_of(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(prefix_of(Ipv4Addr::new(255, 255, 255, 252)), 30);
        assert_eq!(prefix_of(Ipv4Addr::UNSPECIFIED), 0);
        // Illegal, and some appliances emit it anyway.
        assert_eq!(prefix_of(Ipv4Addr::new(255, 0, 255, 0)), 8);
    }

    /// Option 119 supersedes option 15 and comes first, which is what decides
    /// the zone `/instructions` suggests (`DISC-007`, #149).
    #[test]
    fn the_search_list_puts_option_119_before_option_15() {
        let mut client = Lease::new(MAC, 1, seconds(0));
        client.on_time(seconds(0));
        let offer = reply(MessageType::Offer, client.xid, OFFERED, Vec::new());
        client.on_message(&offer, seconds(0));

        let mut options = normal_lease(3600);
        options.push(DhcpOption::DomainSearch(vec![
            "corp.example.net.".parse().unwrap(),
            "example.net.".parse().unwrap(),
        ]));
        let ack = reply(MessageType::Ack, client.xid, OFFERED, options);
        client.on_message(&ack, seconds(0));

        assert_eq!(
            client.config().unwrap().search,
            ["corp.example.net", "example.net"],
            "option 119 first, and option 15's duplicate not repeated"
        );
    }

    /// A `Config` compares by value, which is what makes
    /// `an_unchanged_renewal_does_not_reconfigure` mean anything.
    #[test]
    fn two_identical_configurations_are_equal() {
        let one = Config {
            address: OFFERED,
            prefix: 24,
            routers: vec![SERVER],
            dns: vec![SERVER],
            ntp: Vec::new(),
            search: vec!["example.net".to_owned()],
            server: SERVER,
            lease: Some(seconds(3600)),
        };
        assert_eq!(one, one.clone());
    }
}

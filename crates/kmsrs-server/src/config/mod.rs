//! The three configuration categories (`CFG-001`, #166).
//!
//! Every setting this program has belongs to exactly one of three categories,
//! and which one it belongs to is decided by a single question: **can it change
//! a byte on the wire?**
//!
//! | Category | Type | Source | May change the wire |
//! |---|---|---|---|
//! | 1. Environment discovery | [`Discovered`] | observed at start-up | no — it is *observation*, not policy |
//! | 2. Operational | [`Operational`] | `KMSRSOS_CONFIG`, at runtime | **no, by definition** |
//! | 3. Everything else | [`Compiled`] | decided when the binary is built | yes |
//!
//! # Why the restriction is load-bearing
//!
//! A given binary has exactly one on-wire behaviour. That is what makes a
//! differential test against vlmcsd or py-kms meaningful: it validates *the
//! artifact*, not one configuration of it. If a runtime knob could move a wire
//! byte, then a passing differential run would say nothing about the binary
//! anyone actually deployed.
//!
//! It also removes an entire class of operational surprise. vlmcsd's runtime
//! surface produces, among others: `-H 7601` silently turning NDR64 *off*,
//! which is the reverse of what its own man page says; `-P` with no `-L`
//! silently disabling every `Listen` line in the ini; inetd mode forcing
//! `MaintainClients=FALSE` before the ini is read, so an ini setting silently
//! re-enables it; and a custom `HwId` being ignored unless an ePID is also set.
//! Every one of those is a runtime knob reaching something it should not
//! (`CFG-004`, #169).
//!
//! # How the categories are enforced
//!
//! Not by convention. [`Operational`] is the only one of the three that
//! implements `Deserialize`, so it is the only one a runtime document can
//! produce — there is no code path from `KMSRSOS_CONFIG` to a [`Compiled`].
//! In the other direction, [`crate::Server`] hands the wire path a
//! `&'static Compiled` and never an [`Operational`], so an operational field
//! cannot reach a response without changing a function signature.
//!
//! `tests/wire_is_not_configurable.rs` is what keeps that true: it drives a
//! complete RPC exchange through two servers whose [`Operational`] settings
//! differ in every field, and asserts the response bytes are identical.

//! # The footgun classes, as compile-fail tests
//!
//! `CFG-004` (#169) asks that each class of vlmcsd runtime footgun be made a
//! *build* failure rather than a runtime surprise. Each of the four below is a
//! `compile_fail` doctest, so `cargo test` fails if any of them starts
//! compiling — that is, if the property it describes is ever weakened.
//!
//! **1. A runtime document cannot produce wire-visible settings.** vlmcsd's
//! `-H 7601` silently turns NDR64 *off*, the reverse of what its own man page
//! says, because a runtime flag reaches a wire-negotiation field.
//! [`Compiled`] does not implement `Deserialize`, so there is no such path:
//!
//! ```compile_fail
//! # use kmsrs_server::config::Compiled;
//! let _: Compiled = toml::from_str("intervals = {}").unwrap();
//! ```
//!
//! **2. An operational value cannot be used where a compiled one is required.**
//! This is the general form of the same mistake — vlmcsd's `-P` with no `-L`
//! silently disabling every ini `Listen` line, one setting reaching another's
//! domain. The two types are unrelated, so substitution does not compile:
//!
//! ```compile_fail
//! # use kmsrs_server::config::{Compiled, Operational};
//! fn wants_wire_settings(_: &Compiled) {}
//! wants_wire_settings(&Operational::default());
//! ```
//!
//! **3. Discovered facts are not settings.** [`Discovered`] is observation, and
//! observation has no document: writing one is a compile error rather than a
//! silently ignored key.
//!
//! ```compile_fail
//! # use kmsrs_server::config::Discovered;
//! let _: Discovered = toml::from_str("hostname = \"example\"").unwrap();
//! ```
//!
//! **4. A compiled setting cannot be mutated through a shared reference.**
//! vlmcsd's inetd mode forces `MaintainClients=FALSE` *before* the ini is read,
//! so an ini setting silently re-enables it — a wire-visible value written
//! after the decision that depended on it. [`crate::Server`] hands out
//! `&Compiled`, so there is no later write:
//!
//! ```compile_fail
//! # use kmsrs_server::Server;
//! fn tamper(server: &Server) {
//!     server.compiled().intervals.renewal = 1;
//! }
//! ```
//!
//! For contrast, the same shape *does* compile against a local value, which is
//! what shows the four above fail for the stated reason rather than because of
//! a typo:
//!
//! ```
//! # use kmsrs_server::config::Compiled;
//! let mut local = Compiled::BUILD;
//! local.intervals.renewal = 1;
//! assert_eq!(local.intervals.renewal, 1);
//! ```

pub mod compiled;
pub mod discovered;
pub mod operational;
pub mod stamp;

pub use compiled::Compiled;
pub use discovered::Discovered;
pub use operational::{ConfigError, LogFormat, LogLevel, Operational};
pub use stamp::BuildStamp;

//! Category 1: what the environment tells us about itself (`CFG-001`, #166).
//!
//! This is **observation, not policy**. Every field here answers a question of
//! fact about the machine the process is running on, and none of them is a
//! decision anybody made about how this host should behave. The distinction
//! matters because it is what keeps the category list at three rather than
//! collapsing into "things that vary": a discovered value cannot be *wrong* in
//! the way a configured one can, only stale.
//!
//! Nothing discovered here reaches the wire. The hostname in particular is not
//! sent anywhere — the only identity a KMS exchange carries is the ePID
//! (`ID-001`, #106), and a genuine host's ePID says nothing about its name.

/// What the environment says about itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Discovered {
    /// This machine's name, for the log and the web UI only.
    ///
    /// Never sent on the wire. vlmcsd has a `-w` option that puts a
    /// *client-supplied* workstation name into its own responses; there is no
    /// equivalent here in either direction.
    pub hostname: Option<String>,
    /// Whether stderr is a terminal.
    ///
    /// Decides colour when the operational setting is `auto` (`OBS-002`, #178).
    pub stderr_is_terminal: bool,
    /// Whether `NO_COLOR` is set to anything at all.
    ///
    /// Per the `NO_COLOR` convention, the variable's *presence* is the signal
    /// and its value is not consulted — a common mistake is treating
    /// `NO_COLOR=0` as "colour please", which the convention does not say.
    pub no_color: bool,
    /// How many pre-opened sockets an activation manager passed in, if any.
    ///
    /// systemd's `LISTEN_FDS` protocol. Zero means none were passed, which is
    /// the ordinary case.
    pub listen_fds: u32,
}

impl Discovered {
    /// Observe the environment.
    ///
    /// Total: every question has an answer, and a question that cannot be
    /// answered gets the answer that assumes least. There is no failure mode,
    /// because there is no decision here to get wrong.
    #[must_use]
    pub fn observe() -> Self {
        Self {
            hostname: hostname(),
            stderr_is_terminal: stderr_is_terminal(),
            // Presence, not value.
            no_color: std::env::var_os("NO_COLOR").is_some(),
            listen_fds: std::env::var("LISTEN_FDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        }
    }

    /// Whether the log should be coloured, given the operational choice.
    #[must_use]
    pub fn should_colour(&self, choice: super::operational::ColourChoice) -> bool {
        match choice {
            super::operational::ColourChoice::Always => true,
            super::operational::ColourChoice::Never => false,
            super::operational::ColourChoice::Auto => self.stderr_is_terminal && !self.no_color,
        }
    }
}

/// This machine's name.
///
/// Read from the environment rather than from a system call, because a system
/// call means a per-platform implementation for something that is only ever
/// printed. `HOSTNAME` is set by most shells on Linux; `COMPUTERNAME` is set by
/// Windows. Hermit has neither and gets `None`, which is correct — a unikernel
/// with one process has no meaningful hostname.
fn hostname() -> Option<String> {
    ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|value| !value.is_empty())
}

/// Whether stderr is a terminal.
///
/// `std::io::IsTerminal` is in the standard library, so this needs no
/// dependency and no `unsafe` — which the older `isatty` crates all required.
fn stderr_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::Discovered;
    use crate::config::operational::ColourChoice;

    /// Observation cannot fail. Whatever the environment looks like, there is
    /// an answer — that is what distinguishes this category from the other two.
    #[test]
    fn observation_is_total() {
        let observed = Discovered::observe();
        // Every field has a value; the assertions are about shape, not content,
        // because the content is whatever the test machine happens to be.
        assert!(
            observed
                .hostname
                .as_ref()
                .is_none_or(|name| !name.is_empty())
        );
        let _ = observed.stderr_is_terminal;
        let _ = observed.no_color;
    }

    /// The explicit choices ignore the environment entirely; only `auto`
    /// consults it. This is the whole interface between categories 1 and 2.
    #[test]
    fn explicit_colour_choices_ignore_the_environment() {
        for terminal in [true, false] {
            for no_color in [true, false] {
                let observed = Discovered {
                    hostname: None,
                    stderr_is_terminal: terminal,
                    no_color,
                    listen_fds: 0,
                };
                assert!(observed.should_colour(ColourChoice::Always));
                assert!(!observed.should_colour(ColourChoice::Never));
                assert_eq!(
                    observed.should_colour(ColourChoice::Auto),
                    terminal && !no_color,
                    "terminal={terminal} no_color={no_color}"
                );
            }
        }
    }

    /// `NO_COLOR`'s presence is the signal. Treating `NO_COLOR=0` as "colour
    /// please" is a common misreading the convention does not support.
    #[test]
    fn no_color_is_about_presence_not_value() {
        let observed = Discovered {
            hostname: None,
            stderr_is_terminal: true,
            no_color: true,
            listen_fds: 0,
        };
        assert!(
            !observed.should_colour(ColourChoice::Auto),
            "any NO_COLOR at all disables colour"
        );
    }
}

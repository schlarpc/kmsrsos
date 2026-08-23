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
    /// Whether this terminal understands ANSI escape sequences
    /// (`NET-013`, #162).
    ///
    /// On Unix, a terminal is an ANSI terminal; the question does not arise.
    /// On Windows it does: `conhost.exe` has understood virtual-terminal
    /// sequences since Windows 10 1511, but **only when a process turns them
    /// on** with `SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING)`. Windows
    /// Terminal turns them on for its own console; a bare `cmd.exe` window does
    /// not. Colouring unconditionally there prints `←[32m` in front of every
    /// line, which is worse than no colour at all.
    ///
    /// So this is read from the environment rather than set by a system call.
    /// See [`terminal_understands_ansi`] for why that is a deliberate choice
    /// and not a limitation.
    pub ansi_capable: bool,
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
            ansi_capable: terminal_understands_ansi(),
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
            // `NET-013` (#162): a terminal that would print the escape
            // sequences rather than act on them is not one to colour for.
            super::operational::ColourChoice::Auto => {
                self.stderr_is_terminal && self.ansi_capable && !self.no_color
            }
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

/// Whether the terminal will act on ANSI escape sequences rather than print
/// them (`NET-013`, #162).
///
/// # Why the environment and not `SetConsoleMode`
///
/// The issue proposes calling
/// `SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING)` explicitly, which is
/// the right answer for a program that may use `unsafe`. This one may not
/// (axiom A1): the call needs `windows-sys` or `winapi`, both of which are
/// `unsafe` at the call site, and the single permitted boundary is in
/// `kmsrs-os` for a different target and a different reason (`OS-013`, #264).
///
/// A crate that performs the `unsafe` on our behalf moves the code without
/// moving the risk, and adds a dependency to a program whose whole dependency
/// posture is the point of `SEC-009` (#201) — for **colour in a log**.
///
/// So the question is answered by asking rather than by arranging. That is
/// strictly less capable: a bare `cmd.exe` gets no colour where
/// `SetConsoleMode` would have given it some. It is also never *wrong*, which
/// matters more — GhostNaix's fork needed `colorama`'s `init(convert=True)`
/// unconditionally, and the failure it was working around is escape sequences
/// printed as text, which is the failure this cannot produce.
///
/// The variables, and who sets them:
///
/// * `WT_SESSION` — Windows Terminal, which enables VT for its own console.
/// * `TERM` — any Unix-derived shell, and MSYS2, Cygwin and Git Bash on
///   Windows. `dumb` is the conventional "no capabilities" value.
/// * `ANSICON`, `ConEmuANSI` — the two long-standing conhost wrappers.
/// * `TERM_PROGRAM` — VS Code's integrated terminal, among others.
///
/// On Unix this is `true` whenever `TERM` is set to anything but `dumb`, which
/// is the same answer every terminal library gives.
fn terminal_understands_ansi() -> bool {
    ansi_from(&|name| std::env::var(name).ok(), cfg!(windows))
}

/// The decision, over a supplied environment.
///
/// Split out so it can be tested. The alternative — a test that sets `TERM` and
/// puts it back — needs `std::env::set_var`, which is `unsafe` in edition 2024
/// and which this crate forbids outright (axiom A1). Taking the lookup as a
/// parameter is the same trick the whole core is built on: the environment is
/// an *input*, and a function over its input is one a test can ask anything.
///
/// `windows` is a parameter for the same reason `SINGLE_SOCKET_ONLY` is a
/// `bool` — both branches compile everywhere, so the one this host does not
/// take is still checked (`OS-009`, #260).
fn ansi_from(lookup: &dyn Fn(&str) -> Option<String>, windows: bool) -> bool {
    // The conventional signal for "this terminal has no capabilities", and the
    // one value of `TERM` that means no colour on any platform.
    if lookup("TERM").is_some_and(|term| term == "dumb") {
        return false;
    }

    if !windows {
        // Every Unix terminal understands ANSI. `stderr_is_terminal` has
        // already answered whether there is one at all.
        return true;
    }

    [
        "WT_SESSION",
        "TERM",
        "ANSICON",
        "ConEmuANSI",
        "TERM_PROGRAM",
    ]
    .iter()
    .any(|name| lookup(name).is_some())
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
        let _: bool = observed.stderr_is_terminal;
        let _: bool = observed.no_color;
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
                    ansi_capable: true,
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

    /// `NET-013` (#162): a terminal that would print the escape sequences
    /// rather than act on them gets no colour.
    ///
    /// On Windows a bare `cmd.exe` has virtual-terminal processing *off* until
    /// a process turns it on, so colouring unconditionally there prints
    /// `←[32m` in front of every line — which is worse than no colour, and is
    /// the failure GhostNaix's fork needed `colorama`'s `init(convert=True)`
    /// for. Answering the question by asking rather than by arranging is
    /// strictly less capable and never wrong, and this is the difference.
    #[test]
    fn a_terminal_that_cannot_render_ansi_gets_no_colour() {
        let capable = Discovered {
            hostname: None,
            stderr_is_terminal: true,
            ansi_capable: true,
            no_color: false,
            listen_fds: 0,
        };
        assert!(capable.should_colour(ColourChoice::Auto));

        let incapable = Discovered {
            ansi_capable: false,
            ..capable.clone()
        };
        assert!(
            !incapable.should_colour(ColourChoice::Auto),
            "a console that would print the escapes was coloured anyway"
        );

        // And an explicit choice still overrides both, because an operator who
        // asked for colour has a reason — piping into something that renders
        // it, most likely (`OBS-002`, #178).
        assert!(incapable.should_colour(ColourChoice::Always));
        assert!(!capable.should_colour(ColourChoice::Never));
    }

    /// `NET-013` (#162): the Windows branch is checked on every host, which is
    /// the point of taking the platform as a parameter rather than reading a
    /// `cfg`. A `cfg`-selected branch is only ever compiled on the platform
    /// that selects it, which is the one this test suite mostly does not run
    /// on.
    #[test]
    fn ansi_capability_is_read_from_the_environment_on_both_platforms() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            }
        };

        // Unix: any terminal at all understands ANSI.
        assert!(super::ansi_from(&env(&[]), false));
        assert!(super::ansi_from(&env(&[("TERM", "xterm-256color")]), false));

        // `TERM=dumb` is the one value that means "no capabilities" anywhere,
        // and is what a caller sets when it wants plain text.
        assert!(!super::ansi_from(&env(&[("TERM", "dumb")]), false));
        assert!(!super::ansi_from(&env(&[("TERM", "dumb")]), true));

        // Windows: a bare cmd.exe sets none of these, and gets no colour —
        // because colouring it would print the escapes rather than act on
        // them, which is worse than plain text.
        assert!(!super::ansi_from(&env(&[]), true));
        assert!(!super::ansi_from(&env(&[("COMPUTERNAME", "PC")]), true));

        // And each of the five signals is enough on its own.
        for name in [
            "WT_SESSION",
            "TERM",
            "ANSICON",
            "ConEmuANSI",
            "TERM_PROGRAM",
        ] {
            let present: &'static [(&'static str, &'static str)] = match name {
                "WT_SESSION" => &[("WT_SESSION", "x")],
                "TERM" => &[("TERM", "xterm")],
                "ANSICON" => &[("ANSICON", "x")],
                "ConEmuANSI" => &[("ConEmuANSI", "ON")],
                _ => &[("TERM_PROGRAM", "vscode")],
            };
            assert!(
                super::ansi_from(&env(present), true),
                "{name} alone should be enough"
            );
        }
    }

    /// `NO_COLOR`'s presence is the signal. Treating `NO_COLOR=0` as "colour
    /// please" is a common misreading the convention does not support.
    #[test]
    fn no_color_is_about_presence_not_value() {
        let observed = Discovered {
            hostname: None,
            stderr_is_terminal: true,
            ansi_capable: true,
            no_color: true,
            listen_fds: 0,
        };
        assert!(
            !observed.should_colour(ColourChoice::Auto),
            "any NO_COLOR at all disables colour"
        );
    }
}

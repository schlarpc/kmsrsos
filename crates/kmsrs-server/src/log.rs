//! Logging to stderr, as JSON Lines or as text (`OBS-001`, #177;
//! `OBS-002`, #178; `OBS-003`, #179).
//!
//! # stderr, and nothing else
//!
//! No file sink, no syslog, no rotation, no async queue handler, no temp files
//! (`OBS-015`, #191). There is nothing to configure a path for and nothing to
//! run out of disk. On Hermit stderr is the 16550 UART at `0x3F8`, which is the
//! only console there is, so anything else would need a second implementation
//! for a platform that cannot support it.
//!
//! py-kms's pretty-printer is the counter-example: it keeps newline bookkeeping
//! in fixed paths under the system temp directory, so two instances on one host
//! silently corrupt each other's output.
//!
//! # Structured output is the gap nobody filled
//!
//! Both existing projects hardcode human format strings, and every fork that
//! wanted machine-readable activation data ended up scraping its own log
//! output. [`LogFormat::Json`] emits one JSON object per line — the default,
//! because a log that a program can read is also one a person can read, and the
//! reverse is not true.
//!
//! # Colour
//!
//! Only when stderr is a terminal and `NO_COLOR` is unset, decided by
//! [`Discovered`](crate::config::Discovered) once at start-up. py-kms emits raw
//! escape codes into a pipe because it has neither terminal detection nor a way
//! to turn colour off.

use crate::config::discovered::Discovered;
use crate::config::operational::{LogFormat, LogLevel, Operational};
use core::fmt::Write as _;
use kmsrs_policy::events::{Event, Outcome};
use kmsrs_policy::gate::CLOCK_SKEW_TOLERANCE;
use kmsrs_proto::types::ClientKind;
use std::io::Write as _;

/// How severe a line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Something an operator must act on.
    Error,
    /// Unexpected but survivable.
    Warn,
    /// The ordinary one line per request.
    Info,
    /// Protocol-level detail.
    Debug,
}

impl Severity {
    /// The lowercase name used in both formats.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// The ANSI colour for this severity, if colour is on.
    const fn colour(self) -> &'static str {
        match self {
            Self::Error => "\u{1b}[31m",
            Self::Warn => "\u{1b}[33m",
            Self::Info => "\u{1b}[32m",
            Self::Debug => "\u{1b}[36m",
        }
    }

    /// Whether a line of this severity is emitted at the configured level.
    const fn enabled_at(self, level: LogLevel) -> bool {
        let configured = match level {
            LogLevel::Error => 0_u8,
            LogLevel::Warn => 1,
            LogLevel::Info => 2,
            LogLevel::Debug => 3,
        };
        let wanted = match self {
            Self::Error => 0_u8,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
        };
        wanted <= configured
    }
}

/// Where log lines go and how they are shaped.
#[derive(Debug, Clone, Copy)]
pub struct Logger {
    level: LogLevel,
    format: LogFormat,
    colour: bool,
}

impl Logger {
    /// Build a logger from the configuration and the environment.
    ///
    /// Colour is decided **once**, here, rather than per line: whether stderr is
    /// a terminal cannot change while the process runs, and asking per line
    /// would be a syscall per line for an answer that never changes.
    #[must_use]
    pub fn new(operational: &Operational, discovered: &Discovered) -> Self {
        Self {
            level: operational.log_level,
            format: operational.log_format,
            colour: discovered.should_colour(operational.colour),
        }
    }

    /// A logger with explicit settings, for tests and for the client
    /// (`CLI-015`, #221).
    #[must_use]
    pub const fn with(level: LogLevel, format: LogFormat, colour: bool) -> Self {
        Self {
            level,
            format,
            colour,
        }
    }

    /// Whether anything at this severity would be emitted.
    #[must_use]
    pub const fn enabled(self, severity: Severity) -> bool {
        severity.enabled_at(self.level)
    }

    /// Write one line about something that is not a request.
    pub fn message(self, severity: Severity, event: &str, detail: &str) {
        if let Some(line) = self.format_message(severity, event, detail) {
            Self::emit(&line);
        }
    }

    /// Shape one non-request line, or `None` if it is filtered out.
    ///
    /// Separated from [`Logger::message`] so the format can be tested without
    /// spawning a process and capturing a pipe. Everything about a line except
    /// *where it goes* is decided here.
    #[must_use]
    pub fn format_message(self, severity: Severity, event: &str, detail: &str) -> Option<String> {
        if !self.enabled(severity) {
            return None;
        }
        let mut line = String::new();
        match self.format {
            LogFormat::Json => {
                line.push('{');
                write_json_field(&mut line, "level", severity.name(), true);
                write_json_field(&mut line, "event", event, false);
                write_json_field(&mut line, "detail", detail, false);
                line.push('}');
            }
            LogFormat::Text => {
                self.write_text_prefix(&mut line, severity);
                let _ = write!(line, "{event}: {detail}");
            }
        }
        Some(line)
    }

    /// Write one line about a handled request (`OBS-003`, #179).
    ///
    /// The field list is vlmcsd's verbose dump plus the two things it does not
    /// record: where the request came from, and which host key answered.
    pub fn request(self, event: &Event) {
        if let Some(line) = self.format_request(event) {
            Self::emit(&line);
        }
    }

    /// Shape one request line, or `None` if it is filtered out.
    ///
    /// Pure: no I/O, no clock, no allocation beyond the line itself. That is
    /// what lets the whole field list be checked in-process rather than by
    /// starting a server, binding a port and scraping a pipe — which several
    /// tests would then contend over.
    #[must_use]
    pub fn format_request(self, event: &Event) -> Option<String> {
        if !self.enabled(Severity::Info) {
            return None;
        }
        Some(match self.format {
            LogFormat::Json => Self::request_json(event),
            LogFormat::Text => self.request_text(event),
        })
    }

    /// One JSON object for a request.
    fn request_json(event: &Event) -> String {
        let mut line = String::from("{");
        write_json_field(&mut line, "level", Severity::Info.name(), true);
        write_json_field(
            &mut line,
            "event",
            if event.activated() {
                "activation"
            } else {
                "refusal"
            },
            false,
        );
        write_json_number(&mut line, "sequence", event.sequence);

        // Request side, in vlmcsd's order.
        let _ = write!(
            line,
            ",\"protocol\":\"{}.{}\"",
            event.version.major, event.version.minor
        );
        // Recorded, never acted on (`KMS-017`, #33): a host that refused
        // virtual machines would be trivially distinguishable from one that
        // did not. `Unrecognised` is logged as its raw value rather than
        // forced into one of the two.
        match event.client_kind {
            ClientKind::VirtualMachine => write_json_bool(&mut line, "virtual_machine", true),
            ClientKind::BareMetal => write_json_bool(&mut line, "virtual_machine", false),
            ClientKind::Unrecognised(raw) => {
                write_json_number(&mut line, "client_kind_raw", u64::from(raw));
            }
        }
        write_json_field(
            &mut line,
            "license_status",
            event.license_status.description(),
            false,
        );
        write_json_field(
            &mut line,
            "application",
            &event.application.0.to_string(),
            false,
        );
        write_json_field(
            &mut line,
            "application_name",
            application_name(event),
            false,
        );
        write_json_field(&mut line, "kms_id", &event.counted.0.to_string(), false);
        write_json_field(&mut line, "product", product_name(event), false);
        write_json_bool(&mut line, "known_product", event.known_product);
        write_json_field(
            &mut line,
            "client_machine_id",
            &event.client_machine_id.0.to_string(),
            false,
        );
        write_json_field(
            &mut line,
            "workstation_name",
            event.workstation_name.as_str(),
            false,
        );
        match event.peer {
            Some(peer) => {
                write_json_field(
                    &mut line,
                    "source_address",
                    &peer.address.to_string(),
                    false,
                );
                write_json_number(&mut line, "source_port", u64::from(peer.port));
            }
            None => {
                let _ = write!(line, ",\"source_address\":null");
            }
        }
        if let Some(skew) = event.clock_skew {
            write_json_number(&mut line, "clock_skew_seconds", skew.as_secs());
            write_json_bool(&mut line, "clock_skewed", skew > CLOCK_SKEW_TOLERANCE);
        }

        write_outcome_json(&mut line, event);
        line.push('}');
        line
    }

    /// One human-readable line for a request.
    ///
    /// Deliberately narrower than the JSON form. A person reading a terminal
    /// wants the few fields that identify the client and say what happened;
    /// everything else is in the JSON form and in the event log, which is what
    /// the web UI reads.
    fn request_text(self, event: &Event) -> String {
        let mut line = String::new();
        self.write_text_prefix(&mut line, Severity::Info);

        let source = event
            .peer
            .map_or_else(|| "-".to_owned(), |peer| peer.address.to_string());
        let _ = write!(
            line,
            "{source} v{}.{} {} {} \"{}\"",
            event.version.major,
            event.version.minor,
            product_name(event),
            event.license_status.description(),
            event.workstation_name
        );
        match &event.outcome {
            Outcome::Activated(activation) => {
                let _ = write!(
                    line,
                    " -> activated, count {} of {} cached",
                    activation.reported_count, activation.cached_count
                );
                if !activation.selection.was_resolved() {
                    let _ = write!(line, " (fallback host key)");
                }
            }
            Outcome::Refused(refusal) => {
                let _ = write!(
                    line,
                    " -> refused 0x{:08X} ({refusal:?})",
                    refusal.hresult().to_wire()
                );
            }
        }
        line
    }

    /// The `level` prefix a text line carries, coloured or not.
    fn write_text_prefix(self, line: &mut String, severity: Severity) {
        if self.colour {
            let _ = write!(line, "{}{}\u{1b}[0m ", severity.colour(), severity.name());
        } else {
            let _ = write!(line, "{} ", severity.name());
        }
    }

    /// Write one line to stderr.
    ///
    /// A single `write_all` of the line and its newline together, so two
    /// threads cannot interleave halves of a line. There is no buffering and no
    /// queue: a log line that is still in a buffer when the process dies is a
    /// log line that was not written.
    fn emit(line: &str) {
        let mut bytes = Vec::with_capacity(line.len().saturating_add(1));
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        let _ = std::io::stderr().write_all(&bytes);
    }
}

/// Append the response-side fields, which differ by outcome.
fn write_outcome_json(line: &mut String, event: &Event) {
    match &event.outcome {
        Outcome::Activated(activation) => {
            write_json_number(line, "count", u64::from(activation.reported_count));
            write_json_number(line, "cached", u64::from(activation.cached_count));
            write_json_bool(
                line,
                "host_key_resolved",
                activation.selection.was_resolved(),
            );
            write_json_number(
                line,
                "host_key_index",
                u64::from(activation.selection.index()),
            );
            if activation.anomalous_demand {
                write_json_bool(line, "anomalous_demand", true);
            }
            if activation.expired > 0 {
                write_json_number(line, "expired", u64::from(activation.expired));
            }
        }
        Outcome::Refused(refusal) => {
            write_json_field(line, "refusal", &format!("{refusal:?}"), false);
            let _ = write!(
                line,
                ",\"hresult\":\"0x{:08X}\"",
                refusal.hresult().to_wire()
            );
        }
    }
}

/// The application's human name, or a placeholder.
fn application_name(event: &Event) -> &'static str {
    kmsrs_db::application(event.application.0).map_or("unknown", |entry| entry.name)
}

/// The product's human name (`POL-017`, #105).
///
/// Two lookups, because a KMS ID is not always a product row. The value a
/// client sends is a *counted* ID, and for most products that is also the
/// activation ID of a `pkeyconfig` row — but not for all of them. Server 2025's
/// counted ID is one that is not, so looking only in `PRODUCTS` logged
/// `product: "unknown"` beside `known_product: true`, which is a contradiction
/// an operator would rightly not trust.
///
/// The fallback names the host key that counts it, which is the most specific
/// true thing available. A genuinely unknown product logs as `unknown` with the
/// raw GUID in its own field rather than lost — the operator-facing half of
/// activating products this build has never heard of.
fn product_name(event: &Event) -> &'static str {
    if let Some(entry) = kmsrs_db::product(event.counted.0) {
        return entry.description;
    }
    kmsrs_db::csvlks_counting(event.counted.0)
        .first()
        .and_then(|index| kmsrs_db::csvlk_at(*index))
        .map_or("unknown", |csvlk| csvlk.description)
}

/// Append `"name":"value"` with the value escaped.
fn write_json_field(line: &mut String, name: &str, value: &str, first: bool) {
    if !first {
        line.push(',');
    }
    let _ = write!(line, "\"{name}\":\"");
    escape_json_into(line, value);
    line.push('"');
}

/// Append `,"name":value` for a number.
fn write_json_number(line: &mut String, name: &str, value: u64) {
    let _ = write!(line, ",\"{name}\":{value}");
}

/// Append `,"name":true|false`.
fn write_json_bool(line: &mut String, name: &str, value: bool) {
    let _ = write!(line, ",\"{name}\":{value}");
}

/// Escape a string into a JSON string body.
///
/// Written out rather than pulled from a serialiser because the log path must
/// not allocate a serialiser per line, and because the input includes
/// `WorkstationName` — client-supplied text that may contain anything at all,
/// including control characters and quotes. A log format a client can break out
/// of is a log format that cannot be parsed.
fn escape_json_into(out: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Everything below 0x20 must be escaped; JSON has no literal
            // control characters.
            control if control < '\u{20}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(control));
            }
            other => out.push(other),
        }
    }
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

    use super::{Logger, Severity, escape_json_into};
    use crate::config::discovered::Discovered;
    use crate::config::operational::{ColourChoice, LogFormat, LogLevel, Operational};

    #[test]
    fn severity_filtering_follows_the_configured_level() {
        let quiet = Logger::with(LogLevel::Error, LogFormat::Json, false);
        assert!(quiet.enabled(Severity::Error));
        assert!(!quiet.enabled(Severity::Warn));
        assert!(!quiet.enabled(Severity::Info));

        let loud = Logger::with(LogLevel::Debug, LogFormat::Json, false);
        for severity in [
            Severity::Error,
            Severity::Warn,
            Severity::Info,
            Severity::Debug,
        ] {
            assert!(loud.enabled(severity), "{severity:?}");
        }
    }

    /// `OBS-002` (#178): colour is decided once, from the environment, and the
    /// explicit choices ignore it.
    #[test]
    fn colour_follows_the_terminal_and_no_color() {
        let piped = Discovered {
            hostname: None,
            stderr_is_terminal: false,
            no_color: false,
            listen_fds: 0,
        };
        let terminal = Discovered {
            stderr_is_terminal: true,
            ..piped.clone()
        };
        let terminal_but_no_color = Discovered {
            stderr_is_terminal: true,
            no_color: true,
            ..piped.clone()
        };

        let auto = Operational {
            colour: ColourChoice::Auto,
            ..Operational::default()
        };
        assert!(!Logger::new(&auto, &piped).colour, "piped: no colour");
        assert!(Logger::new(&auto, &terminal).colour, "terminal: colour");
        assert!(
            !Logger::new(&auto, &terminal_but_no_color).colour,
            "NO_COLOR wins over a terminal"
        );

        let never = Operational {
            colour: ColourChoice::Never,
            ..Operational::default()
        };
        assert!(!Logger::new(&never, &terminal).colour);

        let always = Operational {
            colour: ColourChoice::Always,
            ..Operational::default()
        };
        assert!(Logger::new(&always, &piped).colour);
    }

    /// Client-supplied text cannot break the format. `WorkstationName` is
    /// whatever the client sent, so a log format it can escape from is a log
    /// format nothing can parse.
    #[test]
    fn json_escaping_handles_everything_a_client_can_send() {
        let mut out = String::new();
        escape_json_into(&mut out, "plain");
        assert_eq!(out, "plain");

        let mut out = String::new();
        escape_json_into(&mut out, "he said \"hi\"");
        assert_eq!(out, "he said \\\"hi\\\"");

        let mut out = String::new();
        escape_json_into(&mut out, "back\\slash");
        assert_eq!(out, "back\\\\slash");

        let mut out = String::new();
        escape_json_into(&mut out, "line\nbreak\ttab\rreturn");
        assert_eq!(out, "line\\nbreak\\ttab\\rreturn");

        // A control character with no short escape.
        let mut out = String::new();
        escape_json_into(&mut out, "bell\u{7}");
        assert_eq!(out, "bell\\u0007");

        // An attempt to close the object early.
        let mut out = String::new();
        escape_json_into(&mut out, "\",\"level\":\"error");
        assert!(!out.contains("\":\""), "the injection survived: {out}");
    }

    /// Non-ASCII text is passed through rather than escaped, which is valid
    /// JSON and keeps a name legible.
    #[test]
    fn non_ascii_is_not_mangled() {
        let mut out = String::new();
        escape_json_into(&mut out, "büro-pc");
        assert_eq!(out, "büro-pc");
    }
}

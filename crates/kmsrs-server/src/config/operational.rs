//! Category 2: settings a running host may be told (`CFG-002`, #167).
//!
//! One environment variable, one schema, one parser. `KMSRSOS_CONFIG` holds a
//! whole TOML document rather than a value:
//!
//! * **Unset** — compiled-in defaults.
//! * **Present** — field overrides, with `deny_unknown_fields`.
//! * **Malformed** — exit non-zero immediately, naming the problem. Never start
//!   degraded.
//!
//! There is no per-directive precedence matrix, because there is one source.
//! vlmcsd needs three parsing passes, and its ini/CLI precedence is reversed
//! for ePIDs relative to everything else; py-kms has a custom `argv`
//! pre-validator in front of `argparse`; radawson's fork layers YAML on top of
//! both. All of that is precedence between sources, and there is only one here.
//!
//! # What `deny_unknown_fields` buys, for free
//!
//! **`CFG-005` (#170), no prefix matching.** vlmcsd's ini matcher is
//! `strncasecmp` over the *directive's* length, so `Portable = 5` silently sets
//! the TCP port — `Port` is a prefix of `Portable` — and `Windows10 = <epid>`
//! is applied to the CSVLK named `Windows`. A near-miss key here is an error
//! that names the key.
//!
//! **`CFG-006` (#171), no whitespace foot-guns.** vlmcsd trims only CR and LF,
//! so a trailing space becomes part of the value; its own shipped example ini
//! contains a trailing blank that makes the line fail. TOML has a grammar, so
//! `level = "info"` and `level = "info"   ` are the same document.
//!
//! # Nothing here can change a byte on the wire
//!
//! That is the *definition* of this category, not an observation about the
//! current field list (`CFG-001`, #166). A setting that would move a wire byte
//! belongs in [`crate::config::Compiled`] instead, and
//! `tests/wire_is_not_configurable.rs` is what stops one arriving here by
//! accident.

use core::time::Duration;
use serde::Deserialize;

/// The environment variable that holds the whole document (`CFG-002`, #167).
pub const ENV_VAR: &str = "KMSRSOS_CONFIG";

/// How much a log line says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum LogLevel {
    /// Only what an operator must act on.
    Error,
    /// Anything unexpected but survivable.
    Warn,
    /// One line per request. The default.
    #[default]
    Info,
    /// Protocol-level detail.
    Debug,
}

/// How a log line is shaped (`OBS-002`, #178).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum LogFormat {
    /// JSON Lines, one object per line.
    #[default]
    Json,
    /// Human-readable text.
    Text,
}

/// Whether to colour the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum ColourChoice {
    /// Colour when stderr is a terminal and `NO_COLOR` is unset. The default,
    /// and the only one that reads the environment (`CFG-001`, #166 category 1).
    #[default]
    Auto,
    /// Always.
    Always,
    /// Never.
    Never,
}

/// Settings a running host may be told (`CFG-002`, #167).
///
/// Every field is `Option` in the document and concrete here: an absent field
/// means the compiled-in default, which is what makes "unset means defaults"
/// and "present means overrides" the same code path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operational {
    /// How much the log says.
    pub log_level: LogLevel,
    /// How the log is shaped (`OBS-002`, #178).
    pub log_format: LogFormat,
    /// Whether to colour it.
    pub colour: ColourChoice,
    /// Whether the in-process web UI is served at all (`OBS-011`, #187).
    pub web_ui: bool,
    /// The port the web UI listens on.
    ///
    /// Not the KMS port. The KMS port is 1688 and is compiled in
    /// (`NET-002`, #151) — a client cannot be told to look elsewhere, so making
    /// it settable would only ever break things.
    pub web_ui_port: u16,
    /// How many events the log holds (`OBS-004`, #180).
    pub event_log_capacity: usize,
    /// How long an event is kept.
    pub event_retention: Duration,
}

impl Default for Operational {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            log_format: LogFormat::Json,
            colour: ColourChoice::Auto,
            web_ui: true,
            web_ui_port: 8080,
            event_log_capacity: kmsrs_policy::events::DEFAULT_CAPACITY,
            event_retention: kmsrs_policy::events::DEFAULT_RETENTION,
        }
    }
}

/// The document as it appears in the environment variable.
///
/// Separate from [`Operational`] so that "absent" and "set to the default
/// value" are distinguishable while parsing, and so `deny_unknown_fields`
/// applies to exactly the surface a user can type.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Document {
    log_level: Option<LogLevel>,
    log_format: Option<LogFormat>,
    colour: Option<ColourChoice>,
    web_ui: Option<bool>,
    web_ui_port: Option<u16>,
    event_log_capacity: Option<usize>,
    event_retention_days: Option<u32>,
}

/// Why a configuration document was refused.
///
/// Every variant is fatal. A host that started with a configuration it did not
/// understand would be a host whose behaviour nobody can predict from its
/// configuration, which is worse than one that did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The variable did not hold valid TOML, or held a key or value the schema
    /// does not have (`CFG-005`, #170).
    Malformed(String),
    /// A field parsed but its value is out of range.
    OutOfRange {
        /// Which field.
        field: &'static str,
        /// What was wrong with it.
        problem: String,
    },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(detail) => {
                write!(f, "{ENV_VAR} is not a valid configuration: {detail}")
            }
            Self::OutOfRange { field, problem } => {
                write!(f, "{ENV_VAR}: {field} {problem}")
            }
        }
    }
}

impl core::error::Error for ConfigError {}

/// The largest event-log capacity a configuration may ask for.
///
/// Bounded because the log is in memory and there is no disk to spill to
/// (axiom A5).
const MAX_EVENT_LOG_CAPACITY: usize = 1_000_000;

/// The longest retention a configuration may ask for, in days.
const MAX_RETENTION_DAYS: u32 = 365;

impl Operational {
    /// Read the configuration from the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the variable is present and does not hold a
    /// valid document. An absent variable is not an error — it means the
    /// compiled-in defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        match std::env::var(ENV_VAR) {
            Ok(document) => Self::parse(&document),
            // A variable that is not valid Unicode is malformed, not absent.
            Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::Malformed(
                "the variable does not hold valid Unicode".to_owned(),
            )),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
        }
    }

    /// Parse a document.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for invalid TOML, an unknown or near-miss key,
    /// or a value out of range.
    pub fn parse(document: &str) -> Result<Self, ConfigError> {
        let parsed: Document =
            toml::from_str(document).map_err(|error| ConfigError::Malformed(error.to_string()))?;

        let defaults = Self::default();

        let event_log_capacity = parsed
            .event_log_capacity
            .unwrap_or(defaults.event_log_capacity);
        if event_log_capacity == 0 || event_log_capacity > MAX_EVENT_LOG_CAPACITY {
            return Err(ConfigError::OutOfRange {
                field: "event-log-capacity",
                problem: format!("must be between 1 and {MAX_EVENT_LOG_CAPACITY}"),
            });
        }

        let event_retention = match parsed.event_retention_days {
            None => defaults.event_retention,
            Some(days) if (1..=MAX_RETENTION_DAYS).contains(&days) => {
                Duration::from_secs(u64::from(days).saturating_mul(24 * 60 * 60))
            }
            Some(_) => {
                return Err(ConfigError::OutOfRange {
                    field: "event-retention-days",
                    problem: format!("must be between 1 and {MAX_RETENTION_DAYS}"),
                });
            }
        };

        let web_ui_port = parsed.web_ui_port.unwrap_or(defaults.web_ui_port);
        if web_ui_port == 0 {
            return Err(ConfigError::OutOfRange {
                field: "web-ui-port",
                problem: "must not be zero".to_owned(),
            });
        }

        Ok(Self {
            log_level: parsed.log_level.unwrap_or(defaults.log_level),
            log_format: parsed.log_format.unwrap_or(defaults.log_format),
            colour: parsed.colour.unwrap_or(defaults.colour),
            web_ui: parsed.web_ui.unwrap_or(defaults.web_ui),
            web_ui_port,
            event_log_capacity,
            event_retention,
        })
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
        clippy::duration_suboptimal_units,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{ColourChoice, ConfigError, LogFormat, LogLevel, Operational};
    use core::time::Duration;

    /// Unset means compiled-in defaults, and an empty document means the same.
    #[test]
    fn an_empty_document_is_the_defaults() {
        assert_eq!(Operational::parse("").unwrap(), Operational::default());
        assert_eq!(
            Operational::parse("\n\n  \n").unwrap(),
            Operational::default()
        );
    }

    #[test]
    fn fields_override_individually() {
        let parsed = Operational::parse(r#"log-level = "debug""#).unwrap();
        assert_eq!(parsed.log_level, LogLevel::Debug);
        assert_eq!(
            parsed.log_format,
            LogFormat::Json,
            "an unmentioned field keeps its default"
        );

        let parsed = Operational::parse(
            r#"
            log-level = "error"
            log-format = "text"
            colour = "never"
            web-ui = false
            web-ui-port = 9000
            event-log-capacity = 128
            event-retention-days = 7
            "#,
        )
        .unwrap();
        assert_eq!(parsed.log_level, LogLevel::Error);
        assert_eq!(parsed.log_format, LogFormat::Text);
        assert_eq!(parsed.colour, ColourChoice::Never);
        assert!(!parsed.web_ui);
        assert_eq!(parsed.web_ui_port, 9000);
        assert_eq!(parsed.event_log_capacity, 128);
        assert_eq!(parsed.event_retention, Duration::from_hours(7 * 24));
    }

    /// `CFG-005` (#170). vlmcsd's `strncasecmp` matcher silently sets the TCP
    /// port from `Portable = 5`, because `Port` is a prefix of `Portable`.
    /// A near-miss must be an error that names the key.
    #[test]
    fn a_near_miss_key_is_refused_and_named() {
        for key in [
            "log-levels",   // trailing character
            "log-leve",     // truncated
            "log_level",    // wrong separator
            "Log-Level",    // wrong case
            "loglevel",     // run together
            "web-ui-ports", // the Portable/Port shape exactly
        ] {
            let document = format!("{key} = \"debug\"");
            let failure = Operational::parse(&document).unwrap_err();
            assert!(
                matches!(failure, ConfigError::Malformed(_)),
                "{key} was accepted"
            );
            assert!(
                failure.to_string().contains(key),
                "the error for {key} does not name it: {failure}"
            );
        }

        // And the exact key still works, so the test is not passing by
        // rejecting everything.
        assert!(Operational::parse(r#"log-level = "debug""#).is_ok());
    }

    /// `CFG-006` (#171). vlmcsd trims only CR and LF, so a trailing space
    /// becomes part of the value — its own shipped example ini has a trailing
    /// blank that makes the line fail. TOML has a grammar.
    #[test]
    fn whitespace_is_not_a_foot_gun() {
        let canonical = Operational::parse(r#"log-level = "debug""#).unwrap();
        for document in [
            "log-level = \"debug\"   ",
            "log-level = \"debug\"\t",
            "   log-level   =   \"debug\"   ",
            "log-level = \"debug\"\r\n",
            "\n\nlog-level = \"debug\"\n\n",
            "log-level = \"debug\" # a comment",
        ] {
            assert_eq!(
                Operational::parse(document).unwrap(),
                canonical,
                "{document:?} parsed differently"
            );
        }

        // Whitespace *inside* the value is part of the value, and there is no
        // such level, so it is refused rather than silently trimmed.
        assert!(Operational::parse("log-level = \"debug \"").is_err());
    }

    /// `CFG-002` (#167): malformed means refuse, never start degraded.
    #[test]
    fn a_malformed_document_is_fatal_and_says_why() {
        for document in [
            "this is not toml",
            "log-level =",
            "log-level = \"shouting\"",
            "web-ui = \"yes\"",
            "web-ui-port = -1",
            "[section]\nlog-level = \"debug\"",
        ] {
            let failure = Operational::parse(document).unwrap_err();
            let text = failure.to_string();
            assert!(
                text.contains("KMSRSOS_CONFIG"),
                "{document:?} produced {text}"
            );
            assert!(text.len() > 30, "{document:?} produced a useless message");
        }
    }

    /// A field that parses but is out of range is refused with the field named,
    /// rather than clamped. Clamping means the running configuration is not the
    /// configuration anybody wrote down.
    #[test]
    fn out_of_range_values_are_refused_by_name() {
        for (document, field) in [
            ("event-log-capacity = 0", "event-log-capacity"),
            ("event-log-capacity = 100000000", "event-log-capacity"),
            ("event-retention-days = 0", "event-retention-days"),
            ("event-retention-days = 4000", "event-retention-days"),
            ("web-ui-port = 0", "web-ui-port"),
        ] {
            let failure = Operational::parse(document).unwrap_err();
            assert!(
                matches!(failure, ConfigError::OutOfRange { .. }),
                "{document} was accepted"
            );
            assert!(
                failure.to_string().contains(field),
                "{document} produced {failure}"
            );
        }
    }

    /// The event-log defaults are the policy crate's, not a second copy that
    /// could drift from it.
    #[test]
    fn the_event_log_defaults_come_from_the_policy_crate() {
        let defaults = Operational::default();
        assert_eq!(
            defaults.event_log_capacity,
            kmsrs_policy::events::DEFAULT_CAPACITY
        );
        assert_eq!(
            defaults.event_retention,
            kmsrs_policy::events::DEFAULT_RETENTION
        );
    }
}

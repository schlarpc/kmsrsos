//! `kmsrs-client` entry point.
//!
//! Unlike the server, this program **does** take arguments (`CFG-007`, #172 is
//! about the server binary). A diagnostic tool whose whole purpose is asking
//! unusual questions of a host cannot have its questions compiled in.

use core::net::SocketAddr;
use core::time::Duration;
use kmsrs_client::probe::Probe;
use kmsrs_client::request::{RequestFields, parse_guid};
use kmsrs_proto::kms::hresult::HResult;
use kmsrs_proto::kms::validate::{Check, Outcome};
use kmsrs_proto::kms::version::Version;
use kmsrs_server::config::operational::{LogFormat, LogLevel};
use kmsrs_server::log::{Logger, Severity};
use kmsrs_server::{Discovered, OsEntropy};

/// Exit code when the host was reachable but is distinguishable from a genuine
/// one (`CLI-001`, #207).
const EXIT_FINDINGS: i32 = 1;

/// Exit code for arguments that could not be understood.
const EXIT_BAD_USAGE: i32 = 64;

/// Exit code when the host could not be probed at all.
const EXIT_UNAVAILABLE: i32 = 69;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match Arguments::parse(&arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            eprintln!();
            eprintln!("{USAGE}");
            std::process::exit(EXIT_BAD_USAGE);
        }
    };

    if parsed.help {
        println!("{USAGE}");
        return;
    }

    let code = run(&parsed);
    if code != 0 {
        std::process::exit(code);
    }
}

/// Probe the host and report.
fn run(arguments: &Arguments) -> i32 {
    // `CLI-015` (#221): the client and the server share one logger, so client
    // debug output includes protocol-layer detail. py-kms configures one logger
    // while its RPC modules log to another, so its client debug logging
    // silently captures nothing at all.
    let logger = Logger::with(arguments.level, arguments.format, false);
    let discovered = Discovered::observe();
    let logger = if arguments.format == LogFormat::Text {
        Logger::with(
            arguments.level,
            arguments.format,
            discovered.should_colour(kmsrs_server::config::operational::ColourChoice::Auto),
        )
    } else {
        logger
    };

    let Some(target) = arguments.target else {
        logger.message(Severity::Error, "usage", "no target given");
        return EXIT_BAD_USAGE;
    };

    let probe = Probe {
        target,
        timeout: arguments.timeout,
        fields: arguments.fields.clone(),
        versions: arguments.versions.clone(),
    };

    let mut entropy = OsEntropy;
    let report = match probe.run(&mut entropy) {
        Ok(report) => report,
        Err(error) => {
            logger.message(Severity::Error, "probe", &error.to_string());
            return EXIT_UNAVAILABLE;
        }
    };

    for exchange in &report.exchanges {
        let checks: Vec<String> = exchange
            .checks
            .iter()
            .map(|(check, outcome)| format!("{}={}", check.name(), describe(outcome)))
            .collect();
        logger.message(
            Severity::Info,
            "exchange",
            &format!(
                "{:?} epid={} count={} {}",
                exchange.version,
                exchange.epid,
                exchange.count,
                checks.join(" ")
            ),
        );
    }

    // `CLI-014` (#220): every HRESULT renders human text, including 1, which is
    // not really an HRESULT at all but an RPC protocol error.
    for finding in &report.findings {
        logger.message(Severity::Warn, "finding", &finding.to_string());
    }

    if report.is_clean() {
        logger.message(
            Severity::Info,
            "verdict",
            "no findings: indistinguishable from a genuine host, as far as this probe can tell",
        );
        0
    } else {
        logger.message(
            Severity::Error,
            "verdict",
            &format!("{} finding(s)", report.findings.len()),
        );
        EXIT_FINDINGS
    }
}

/// How to render a check outcome.
const fn describe(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "ok",
        Outcome::Fail => "FAIL",
        Outcome::NotApplicable => "n/a",
    }
}

/// What the command line asked for.
#[derive(Debug, Clone)]
struct Arguments {
    help: bool,
    target: Option<SocketAddr>,
    timeout: Duration,
    level: LogLevel,
    format: LogFormat,
    versions: Vec<Version>,
    fields: RequestFields,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            help: false,
            target: None,
            timeout: kmsrs_client::request::DEFAULT_TIMEOUT,
            level: LogLevel::Info,
            format: LogFormat::Text,
            versions: Version::ALL.to_vec(),
            fields: RequestFields::default(),
        }
    }
}

impl Arguments {
    /// Parse the command line.
    ///
    /// Every request field is settable (`CLI-009`, #215), and an unrecognised
    /// option is an error rather than something silently ignored.
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut parsed = Self::default();
        let mut index = 0_usize;

        while let Some(argument) = arguments.get(index) {
            let mut take = |name: &str| -> Result<String, String> {
                index = index.saturating_add(1);
                arguments
                    .get(index)
                    .cloned()
                    .ok_or_else(|| format!("{name} needs a value"))
            };

            match argument.as_str() {
                "-h" | "--help" => parsed.help = true,
                "--timeout" => {
                    let value = take("--timeout")?;
                    let seconds: u64 = value
                        .parse()
                        .map_err(|_| format!("--timeout wants a number of seconds, got {value}"))?;
                    parsed.timeout = Duration::from_secs(seconds);
                }
                "--version" => {
                    let value = take("--version")?;
                    parsed.versions = vec![match value.as_str() {
                        "4" => Version::V4,
                        "5" => Version::V5,
                        "6" => Version::V6,
                        other => return Err(format!("--version wants 4, 5 or 6, got {other}")),
                    }];
                }
                "--json" => parsed.format = LogFormat::Json,
                "--debug" => parsed.level = LogLevel::Debug,
                "--quiet" => parsed.level = LogLevel::Error,
                "--app-id" => parsed.fields.application = guid("--app-id", &take("--app-id")?)?,
                "--sku-id" => parsed.fields.sku = guid("--sku-id", &take("--sku-id")?)?,
                "--kms-id" => parsed.fields.kms_id = guid("--kms-id", &take("--kms-id")?)?,
                "--cmid" => {
                    parsed.fields.client_machine_id = guid("--cmid", &take("--cmid")?)?;
                }
                "--previous-cmid" => {
                    parsed.fields.previous_client_machine_id =
                        guid("--previous-cmid", &take("--previous-cmid")?)?;
                }
                "--n-policy" => {
                    let value = take("--n-policy")?;
                    parsed.fields.required_clients = value
                        .parse()
                        .map_err(|_| format!("--n-policy wants a number, got {value}"))?;
                }
                "--license-status" => {
                    let value = take("--license-status")?;
                    parsed.fields.license_status = value
                        .parse()
                        .map_err(|_| format!("--license-status wants a number, got {value}"))?;
                }
                "--grace-minutes" => {
                    let value = take("--grace-minutes")?;
                    parsed.fields.grace_minutes = value
                        .parse()
                        .map_err(|_| format!("--grace-minutes wants a number, got {value}"))?;
                }
                "--virtual-machine" => parsed.fields.virtual_machine = true,
                "--workstation-name" => {
                    parsed.fields.workstation_name = take("--workstation-name")?;
                }
                "--client-time" => {
                    let value = take("--client-time")?;
                    parsed.fields.client_time = value
                        .parse()
                        .map_err(|_| format!("--client-time wants a FILETIME, got {value}"))?;
                }
                other if other.starts_with('-') => {
                    return Err(format!("unknown option {other}"));
                }
                other => {
                    if parsed.target.is_some() {
                        return Err(format!("more than one target given: {other}"));
                    }
                    parsed.target = Some(parse_target(other)?);
                }
            }
            index = index.saturating_add(1);
        }

        if parsed.target.is_none() && !parsed.help {
            return Err(String::from("no target given"));
        }
        Ok(parsed)
    }
}

/// Parse a GUID argument.
fn guid(name: &str, value: &str) -> Result<kmsrs_db::Guid, String> {
    parse_guid(value).ok_or_else(|| format!("{name} wants a GUID, got {value}"))
}

/// Parse a `host:port` target, defaulting to the KMS port.
fn parse_target(value: &str) -> Result<SocketAddr, String> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    // A bare address gets the KMS port. Note there is deliberately no name
    // resolution: py-kms's documentation claims hostnames work and using one is
    // fatal at start-up, which is worse than not offering it (`NET-011`, #160).
    if let Ok(ip) = value.parse::<core::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, kmsrs_server::net::KMS_PORT));
    }
    Err(format!(
        "{value} is not an address; hostnames are not resolved, give an IP"
    ))
}

/// What `--help` prints.
///
/// Every option here exists in the parser, and every option in the parser is
/// here. vlmcsd's manual documents `-h` and `-?` that are not in its own
/// optstring, which is the failure this pairing exists to avoid.
const USAGE: &str = "\
kmsrs-client — KMS host diagnostic and detection-resistance probe

USAGE:
    kmsrs-client [OPTIONS] <ADDRESS>

The address is an IP, optionally with :port (default 1688). Hostnames are not
resolved: partial support is worse than none.

OPTIONS:
    -h, --help                 Print this and exit
        --timeout <SECONDS>    How long to wait for each reply (default 10)
        --version <4|5|6>      Probe one protocol version (default: all three)
        --json                 Emit JSON Lines instead of text
        --debug                Include protocol-layer detail
        --quiet                Errors only

REQUEST FIELDS:
        --app-id <GUID>            The application
        --sku-id <GUID>            The SKU, which a host reads and ignores
        --kms-id <GUID>            The counted ID, which a host decides on
        --cmid <GUID>              This machine's identity
        --previous-cmid <GUID>     The machine ID before this one
        --n-policy <N>             Required client count
        --license-status <N>       Self-reported licensing state
        --grace-minutes <N>        Minutes remaining in that state
        --virtual-machine          Claim to be a VM
        --workstation-name <NAME>  At most 63 UTF-16 code units; over-long is
                                   an error, never a silent truncation
        --client-time <FILETIME>   Timestamp to send

EXIT STATUS:
    0   No findings: indistinguishable from a genuine host
    1   The host is distinguishable; see the findings
    64  The command line could not be understood
    69  The host could not be probed
";

/// Render an HRESULT with its text (`CLI-014`, #220).
///
/// Unused by the probe path today, but part of the crate's public reporting
/// vocabulary — a diagnostic client that printed a bare hexadecimal number
/// would be making the operator look it up.
#[expect(dead_code, reason = "reporting vocabulary; see CLI-014 (#220)")]
fn hresult_text(raw: u32) -> String {
    let result = HResult::from_wire(raw);
    format!("0x{raw:08X} ({})", result.description())
}

/// Every check name, for the report header.
#[expect(dead_code, reason = "reporting vocabulary")]
fn check_names() -> Vec<&'static str> {
    Check::ALL.iter().map(|check| check.name()).collect()
}

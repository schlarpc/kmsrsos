//! `kmsrs-client` entry point.
//!
//! Unlike the server, this program **does** take arguments (`CFG-007`, #172 is
//! about the server binary). A diagnostic tool whose whole purpose is asking
//! unusual questions of a host cannot have its questions compiled in.

use core::net::SocketAddr;
use core::time::Duration;
use kmsrs_client::load::{Charge, Charged, Soak, Vary};
use kmsrs_client::names::Flavour;
use kmsrs_client::probe::Probe;
use kmsrs_client::request::{RequestFields, parse_guid};
use kmsrs_proto::kms::hresult::HResult;
use kmsrs_proto::kms::validate::{Check, Outcome};
use kmsrs_proto::kms::version::{ProtocolVersion, Version};
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

    // `CLI-008` (#214): before the target is required, because this mode has no
    // host to talk to. Everything it prints is a `static` in this binary, which
    // is what makes it answer "what would this activate" rather than "what did
    // that host do".
    if let Mode::List(listing) = arguments.mode {
        let rendered = if arguments.format == LogFormat::Json {
            kmsrs_client::catalog::render_json(listing)
        } else {
            kmsrs_client::catalog::render_text(listing)
        };
        print!("{rendered}");
        return 0;
    }

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

    // `SEC-008` (#200): a scratch container has no shell, no curl and no nc, so
    // the HEALTHCHECK has to be a binary — and the smallest honest one is a KMS
    // client doing what a client does. One activation, one exit code, and no
    // opinion about whether the host is *distinguishable*: a health check that
    // failed on a finding would take a working service out of rotation for a
    // cosmetic reason.
    match arguments.mode {
        // Handled above, before a target was required, because it needs no
        // host (`CLI-008`, #214). Named here rather than caught by a wildcard
        // so that a new mode is a compile error in both places.
        Mode::List(_) => return 0,
        Mode::HealthCheck => {
            return match probe.health_check(&mut entropy) {
                Ok(exchange) => {
                    logger.message(
                        Severity::Info,
                        "healthy",
                        &format!("epid={} count={}", exchange.epid, exchange.count),
                    );
                    0
                }
                Err(error) => {
                    logger.message(Severity::Error, "unhealthy", &error.to_string());
                    EXIT_UNAVAILABLE
                }
            };
        }
        Mode::Soak => return soak(arguments, target, logger, &mut entropy),
        Mode::Charge => return charge(arguments, target, logger, &mut entropy),
        Mode::Probe => {}
    }
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

/// `CLI-006` (#212): N requests, optionally concurrent, and a report.
///
/// A load run is not a pass/fail question, so the exit code says whether every
/// request completed rather than whether the host is distinguishable. A host
/// that refused half of them is a finding an operator reads in the summary.
fn soak(
    arguments: &Arguments,
    target: SocketAddr,
    logger: Logger,
    entropy: &mut kmsrs_server::OsEntropy,
) -> i32 {
    let plan = Soak {
        target,
        timeout: arguments.timeout,
        fields: arguments.fields.clone(),
        requests: arguments.requests,
        concurrency: arguments.concurrency,
        reconnect: arguments.reconnect,
        vary: arguments.vary,
    };

    let report = match plan.run(entropy) {
        Ok(report) => report,
        Err(error) => {
            logger.message(Severity::Error, "soak", &error.to_string());
            return EXIT_UNAVAILABLE;
        }
    };

    logger.message(
        Severity::Info,
        "soak",
        &format!(
            "{} completed, {} failed, highest count {}, {} distinct ePID(s)",
            report.completed, report.failed, report.highest_count, report.distinct_epids
        ),
    );

    // `ID-001` (#106): a genuine host has one ePID for its lifetime, and a soak
    // run is where a per-response generator shows up most clearly — py-kms
    // produces a fresh one for every single response unless `-e` is given.
    if report.distinct_epids > 1 {
        logger.message(
            Severity::Warn,
            "finding",
            &format!(
                "{} distinct ePIDs from one host; a genuine host has one for \
                 its lifetime",
                report.distinct_epids
            ),
        );
    }

    if let Some(failure) = &report.first_failure {
        logger.message(Severity::Error, "soak-failure", failure);
        return EXIT_FINDINGS;
    }
    0
}

/// `CLI-007` (#213): charge a host towards its activation threshold.
///
/// Saturation is reported, not treated as a failure. `vlmcs` aborts with *"the
/// KMS server does not increment its active clients"*, which is the right
/// diagnosis for a real host and the wrong one here: under `POL-001` (#89) the
/// count saturates at `2N`, so a host that is already serving everybody
/// correctly reports a count that does not move.
fn charge(
    arguments: &Arguments,
    target: SocketAddr,
    logger: Logger,
    entropy: &mut kmsrs_server::OsEntropy,
) -> i32 {
    let plan = Charge {
        target,
        timeout: arguments.timeout,
        fields: arguments.fields.clone(),
        limit: arguments.charge_limit,
    };

    match plan.run(entropy) {
        Ok(Charged::Reached { count, requests }) => {
            logger.message(
                Severity::Info,
                "charged",
                &format!("the host reports {count} after {requests} request(s)"),
            );
            0
        }
        Ok(Charged::Saturated { count, threshold }) => {
            logger.message(
                Severity::Info,
                "saturated",
                &format!(
                    "the count settled at {count} below the threshold of \
                     {threshold}; this is a host reporting all it will, not a \
                     host that failed to count"
                ),
            );
            0
        }
        Err(error) => {
            logger.message(Severity::Error, "charge", &error.to_string());
            EXIT_UNAVAILABLE
        }
    }
}

/// Parse a `major.minor` protocol version (`CLI-005`, #211).
///
/// Any pair in `0..=65535` each, because the whole point is to send what no
/// real client sends. `6` alone means `6.0`, since that is what an operator
/// typing a major version means.
fn parse_raw_version(value: &str) -> Result<ProtocolVersion, String> {
    let (major, minor) = match value.split_once('.') {
        Some((major, minor)) => (major, minor),
        None => (value, "0"),
    };
    let parse = |part: &str, which: &str| -> Result<u16, String> {
        part.parse::<u16>()
            .map_err(|_| format!("--raw-version wants a {which} in 0..=65535, got {part:?}"))
    };
    Ok(ProtocolVersion {
        major: parse(major, "major")?,
        minor: parse(minor, "minor")?,
    })
}

/// How to render a check outcome.
const fn describe(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "ok",
        Outcome::Fail => "FAIL",
        Outcome::NotApplicable => "n/a",
    }
}

/// What the client was asked to do.
///
/// One mode per invocation, and an explicit one: a tool that inferred "you set
/// --soak so you must mean soak" is a tool that silently does something else
/// when two flags are given (`CLI-009`, #215).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The detection-resistance suite (`CLI-002`, #208). The default.
    Probe,
    /// One activation and an exit code, for a container HEALTHCHECK
    /// (`SEC-008`, #200).
    HealthCheck,
    /// N requests, optionally concurrent (`CLI-006`, #212).
    Soak,
    /// Activations from fresh machines until the count reaches the threshold
    /// (`CLI-007`, #213).
    Charge,
    /// List what this build knows about, and exit (`CLI-008`, #214).
    ///
    /// The only mode that needs no host: everything it prints is compiled in.
    List(kmsrs_client::Listing),
}

/// What the command line asked for.
#[derive(Debug, Clone)]
struct Arguments {
    help: bool,
    mode: Mode,
    target: Option<SocketAddr>,
    timeout: Duration,
    level: LogLevel,
    format: LogFormat,
    versions: Vec<Version>,
    fields: RequestFields,
    /// How many requests a soak run sends (`CLI-006`, #212).
    requests: u64,
    /// How many workers send them.
    concurrency: usize,
    /// Whether a soak run rebinds per request.
    reconnect: bool,
    /// What a soak run varies per request.
    vary: Vary,
    /// How many requests a charging run will send before giving up
    /// (`CLI-007`, #213).
    charge_limit: u32,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            help: false,
            mode: Mode::Probe,
            target: None,
            timeout: kmsrs_client::request::DEFAULT_TIMEOUT,
            level: LogLevel::Info,
            format: LogFormat::Text,
            versions: Version::ALL.to_vec(),
            fields: RequestFields::default(),
            // `vlmcs`'s own examples suggest 100000; this is a number somebody
            // can type without meaning to run for an hour.
            requests: 1_000,
            concurrency: 1,
            reconnect: false,
            vary: Vary::default(),
            // Generous: a host being charged from cold needs `N_Policy`
            // distinct machines, and the largest any Microsoft product declares
            // is 25.
            charge_limit: 200,
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
                "--healthcheck" => parsed.mode = Mode::HealthCheck,
                "--soak" => {
                    parsed.mode = Mode::Soak;
                    let value = take("--soak")?;
                    parsed.requests = value
                        .parse()
                        .map_err(|_| format!("--soak wants a request count, got {value}"))?;
                }
                "--charge" => parsed.mode = Mode::Charge,
                // `CLI-008` (#214). Three spellings rather than one flag with a
                // value, because each is a whole answer to a different question
                // and an operator should not have to learn a vocabulary to ask
                // "what keys do you have".
                "--products" => parsed.mode = Mode::List(kmsrs_client::Listing::Products),
                "--keys" => parsed.mode = Mode::List(kmsrs_client::Listing::Keys),
                // One spelling, not two. An undocumented alias is exactly
                // vlmcsd's `-h`/`-?` — an option that exists, works, and is in
                // no manual (`CLI-009`, #215).
                "--catalog" => parsed.mode = Mode::List(kmsrs_client::Listing::Both),
                "--charge-limit" => {
                    let value = take("--charge-limit")?;
                    parsed.charge_limit = value
                        .parse()
                        .map_err(|_| format!("--charge-limit wants a number, got {value}"))?;
                }
                "--concurrency" => {
                    let value = take("--concurrency")?;
                    let workers: usize = value
                        .parse()
                        .map_err(|_| format!("--concurrency wants a number, got {value}"))?;
                    if workers == 0 {
                        return Err(String::from("--concurrency must be at least 1"));
                    }
                    parsed.concurrency = workers;
                }
                "--reconnect" => parsed.reconnect = true,
                "--same-machine" => parsed.vary.machine_id = false,
                "--random-workstation" => {
                    let value = take("--random-workstation")?;
                    parsed.vary.workstation_name =
                        Some(Flavour::parse(&value).ok_or_else(|| {
                            format!("--random-workstation wants dns or netbios, got {value}")
                        })?);
                }
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
                other if request_field(&mut parsed.fields, other, &mut take)? => {}
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

        // `--help` and the listing modes are the two kinds of run that have no
        // host to talk to (`CLI-008`, #214). Every other mode needs one, and
        // saying so here rather than at the point of use is what keeps the
        // error a usage error rather than a failed connection.
        let needs_a_target = !parsed.help && !matches!(parsed.mode, Mode::List(_));
        if parsed.target.is_none() && needs_a_target {
            return Err(String::from("no target given"));
        }
        Ok(parsed)
    }
}

/// The options that set a request field (`CLI-009`, #215).
///
/// Split out of [`Arguments::parse`] because they are a different kind of
/// option: every one of them sets a byte a client puts on the wire, and the
/// list grows with the protocol rather than with the tool.
///
/// Returns whether `option` was one of them.
fn request_field(
    fields: &mut RequestFields,
    option: &str,
    take: &mut dyn FnMut(&str) -> Result<String, String>,
) -> Result<bool, String> {
    match option {
        "--app-id" => fields.application = guid("--app-id", &take("--app-id")?)?,
        "--sku-id" => fields.sku = guid("--sku-id", &take("--sku-id")?)?,
        "--kms-id" => fields.kms_id = guid("--kms-id", &take("--kms-id")?)?,
        "--cmid" => fields.client_machine_id = guid("--cmid", &take("--cmid")?)?,
        "--previous-cmid" => {
            fields.previous_client_machine_id = guid("--previous-cmid", &take("--previous-cmid")?)?;
        }
        "--n-policy" => {
            let value = take("--n-policy")?;
            fields.required_clients = value
                .parse()
                .map_err(|_| format!("--n-policy wants a number, got {value}"))?;
        }
        "--license-status" => {
            let value = take("--license-status")?;
            fields.license_status = value
                .parse()
                .map_err(|_| format!("--license-status wants a number, got {value}"))?;
        }
        "--grace-minutes" => {
            let value = take("--grace-minutes")?;
            fields.grace_minutes = value
                .parse()
                .map_err(|_| format!("--grace-minutes wants a number, got {value}"))?;
        }
        "--virtual-machine" => fields.virtual_machine = true,
        "--workstation-name" => fields.workstation_name = take("--workstation-name")?,
        "--client-time" => {
            let value = take("--client-time")?;
            fields.client_time = value
                .parse()
                .map_err(|_| format!("--client-time wants a FILETIME, got {value}"))?;
        }
        "--raw-version" => {
            let value = take("--raw-version")?;
            fields.declared_version = Some(parse_raw_version(&value)?);
        }
        _ => return Ok(false),
    }
    Ok(true)
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
        --healthcheck          One activation, then exit 0 or 69. For a
                               container HEALTHCHECK: liveness only, so a
                               distinguishable host still counts as healthy
        --soak <N>             Send N requests and report what happened
        --charge               Activate from fresh machines until the reported
                               count reaches --n-policy
        --products             List the product key configurations this build
                               knows about, then exit. Needs no address
        --keys                 List the KMS client setup keys, then exit. These
                               never travel over the wire; they are what an
                               operator types into slmgr /ipk
        --catalog              Both of the above

SOAK OPTIONS:
        --concurrency <N>      Workers sending them (default 1). vlmcs has none
        --reconnect            A fresh connection and bind per request, which
                               exercises the accept path instead of the request
                               path
        --same-machine         Reuse one machine ID, so the run measures
                               renewals rather than activations
        --random-workstation <dns|netbios>
                               A fresh workstation name per request

CHARGE OPTIONS:
        --charge-limit <N>     Give up after N requests (default 200)

EVERYWHERE:
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
        --raw-version <M.m>        Declare this version on the wire while
                                   framing the request as --version.
                                   `--raw-version 6.1` asks whether the host
                                   dispatches on both halves of the version
                                   word or only on the major

EXIT STATUS:
    0   The run succeeded: no findings, or a soak in which nothing failed, or
        a charge that reached its threshold or found the host saturated
    1   The host is distinguishable, or a soak run had failures
    64  The command line could not be understood
    69  The host could not be reached at all
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

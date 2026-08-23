//! What a handled request looks like in the log (`OBS-003`, #179;
//! `OBS-002`, #178; `OBS-001`, #177).
//!
//! The field list is the one `OBS-003` asks for — vlmcsd's verbose dump — plus
//! the two things vlmcsd does not record: where the request came from, and
//! which host key answered.
//!
//! The events under test are produced by driving requests through
//! [`Host::activate`], so what is formatted is what the server really builds.
//! The formatting itself is checked in-process: `Logger::format_request` is
//! pure, so there is no need to start a server, bind a port and scrape a pipe —
//! which would make several tests contend for port 1688 and quietly skip.
//!
//! Only the two properties that are genuinely about *where output goes* run the
//! real binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;
use kmsrs_db::Guid;
use kmsrs_policy::events::{Event, Peer};
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::request::Request;
use kmsrs_proto::kms::status::LicenseStatus;
use kmsrs_proto::kms::version::ProtocolVersion;
use kmsrs_proto::time::{FileTime, Instant};
use kmsrs_proto::types::{
    ApplicationId, ClientKind, ClientMachineId, ClientTime, GraceMinutes, KmsCountedId,
    RequiredClients, SkuId, WorkstationName,
};
use kmsrs_server::config::operational::{LogFormat, LogLevel};
use kmsrs_server::log::Logger;
use kmsrs_server::{Host, RequestContext};
use std::process::{Command, Stdio};

/// Windows Server 2025's genuine counted ID — the value `DB-008` (#132)
/// established against py-kms's fabricated one.
const SERVER_2025: &str = "907f1f65-adcd-4a2e-95bc-4bf500bc6e58";

/// Parse a canonical GUID string.
///
/// Test-only, and deliberately not a `FromStr` impl on `Guid`: the shipped code
/// never parses a GUID from text, because nothing on the wire is text.
fn guid(text: &str) -> Guid {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(|byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            other => panic!("not hex: {other}"),
        })
        .collect();
    assert_eq!(digits.len(), 32, "not a GUID: {text}");
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (digits[index * 2] << 4) | digits[index * 2 + 1];
    }
    Guid::from_bytes(bytes)
}

fn workstation(name: &str) -> WorkstationName {
    let mut field = [0_u16; kmsrs_proto::types::WORKSTATION_NAME_UNITS];
    for (slot, unit) in field.iter_mut().zip(name.encode_utf16()) {
        *slot = unit;
    }
    WorkstationName::decode(&field)
}

fn windows() -> Guid {
    kmsrs_db::APPLICATIONS
        .iter()
        .find(|entry| entry.name == "Windows")
        .expect("Windows is in the shipped data")
        .guid
}

fn request(counted: Guid, name: &str) -> Request {
    Request {
        version: ProtocolVersion { major: 6, minor: 0 },
        client_kind: ClientKind::VirtualMachine,
        license_status: LicenseStatus::Unlicensed,
        grace: GraceMinutes(0),
        application: ApplicationId(windows()),
        sku: SkuId(counted),
        counted: KmsCountedId(counted),
        client_machine_id: ClientMachineId(Guid::from_bytes([0xDE; 16])),
        required_clients: RequiredClients(25),
        client_time: ClientTime(FileTime::from_ticks(133_000_000_000_000_000)),
        previous_client_machine_id: None,
        workstation_name: workstation(name),
    }
}

/// Drive one request through a host and return the event it produced.
fn event_for(counted: Guid, name: &str) -> Event {
    let mut entropy = DeterministicEntropy::from_seed(0x10_9E);
    let mut host = Host::new(&mut entropy, kmsrs_db::Date::new(2026, 8, 1).unwrap()).unwrap();
    host.activate(
        &request(counted, name),
        RequestContext {
            peer: Some(Peer {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
                port: 51_000,
            }),
            now: Instant::from_nanos(0),
            host_time: None,
        },
    );
    host.events()
        .iter()
        .next_back()
        .expect("the request was logged")
        .clone()
}

fn json_logger() -> Logger {
    Logger::with(LogLevel::Info, LogFormat::Json, false)
}

/// `OBS-003` (#179): every field the issue lists is present, and the line is
/// valid JSON.
#[test]
fn an_activation_logs_every_field() {
    let event = event_for(guid(SERVER_2025), "office-pc");
    let line = json_logger()
        .format_request(&event)
        .expect("info is enabled");

    for field in [
        // Request side — vlmcsd's verbose dump.
        "\"protocol\":\"6.0\"",
        "\"virtual_machine\":true",
        "\"license_status\":\"unlicensed\"",
        "\"application\":",
        "\"application_name\":\"Windows\"",
        "\"kms_id\":",
        "\"product\":",
        "\"known_product\":true",
        "\"client_machine_id\":",
        "\"workstation_name\":\"office-pc\"",
        // Response side.
        "\"count\":25",
        "\"cached\":1",
        "\"host_key_resolved\":true",
        "\"host_key_index\":",
        // The two vlmcsd does not record.
        "\"source_address\":\"192.0.2.44\"",
        "\"source_port\":51000",
    ] {
        assert!(field_present(&line, field), "{field} missing from: {line}");
    }

    assert!(line.contains(SERVER_2025), "the raw KMS ID: {line}");
    assert!(is_balanced_json_object(&line), "not a JSON object: {line}");
}

/// `POL-017` (#105) in the log: an unknown product activates, and the raw GUID
/// is what tells an operator which one it was.
#[test]
fn an_unknown_product_logs_its_raw_guid() {
    let unknown = Guid::from_bytes([0xAB; 16]);
    let event = event_for(unknown, "new-pc");
    let line = json_logger().format_request(&event).unwrap();

    assert!(line.contains("\"event\":\"activation\""), "{line}");
    assert!(line.contains("\"known_product\":false"), "{line}");
    assert!(line.contains("\"product\":\"unknown\""), "{line}");
    assert!(
        line.contains(&unknown.to_string()),
        "the raw GUID must survive: {line}"
    );
    assert!(
        line.contains("\"host_key_resolved\":false"),
        "and it fell back: {line}"
    );
}

/// `OBS-002` (#178): a client-supplied workstation name cannot break the
/// format. This is the one field an attacker controls entirely.
#[test]
fn a_hostile_workstation_name_cannot_break_the_json() {
    for name in [
        r#"we"ird\name"#,
        r#"","level":"error","x":""#,
        "tab\there",
        "null\u{0}byte",
        "bell\u{7}",
        "büro-pc",
    ] {
        let event = event_for(guid(SERVER_2025), name);
        let line = json_logger().format_request(&event).unwrap();

        assert!(
            is_balanced_json_object(&line),
            "{name:?} broke the object: {line}"
        );
        assert_eq!(
            line.matches("\"level\":").count(),
            1,
            "{name:?} injected a key: {line}"
        );
        assert!(
            !line.contains('\u{0}') && !line.contains('\u{7}'),
            "{name:?} left a raw control character in: {line:?}"
        );
    }

    // And the escaping is correct, not merely safe.
    let event = event_for(guid(SERVER_2025), r#"we"ird\name"#);
    let line = json_logger().format_request(&event).unwrap();
    assert!(
        line.contains(r#""workstation_name":"we\"ird\\name""#),
        "{line}"
    );
}

/// A refusal is logged with its HRESULT, so an operator can tell *why* a client
/// is not activating rather than only that it is not.
#[test]
fn a_refusal_logs_its_hresult() {
    let mut entropy = DeterministicEntropy::from_seed(0x10_9E);
    let mut host = Host::new(&mut entropy, kmsrs_db::Date::new(2026, 8, 1).unwrap()).unwrap();

    // An application mismatch, which is refused in every build.
    let product = kmsrs_db::PRODUCTS
        .iter()
        .find(|entry| entry.kind == kmsrs_db::KeyKind::KmsClient && entry.application.is_some())
        .unwrap();
    let other = kmsrs_db::APPLICATIONS
        .iter()
        .find(|entry| Some(entry.guid) != product.application)
        .unwrap();
    let mut request = request(product.activation_id, "probe");
    request.application = ApplicationId(other.guid);

    host.activate(
        &request,
        RequestContext {
            peer: Some(Peer {
                address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
                port: 40_000,
            }),
            now: Instant::from_nanos(0),
            host_time: None,
        },
    );

    let event = host.events().iter().next_back().unwrap();
    let line = json_logger().format_request(event).unwrap();
    assert!(line.contains("\"event\":\"refusal\""), "{line}");
    assert!(
        line.contains("\"refusal\":\"ApplicationMismatch\""),
        "{line}"
    );
    assert!(line.contains("\"hresult\":\"0xC004F042\""), "{line}");
    assert!(
        line.contains("\"source_address\":\"198.51.100.9\""),
        "{line}"
    );
    assert!(is_balanced_json_object(&line), "{line}");
}

/// The text format is for people and says the same things.
#[test]
fn the_text_format_is_readable_and_uncoloured_by_default() {
    let event = event_for(guid(SERVER_2025), "office-pc");
    let line = Logger::with(LogLevel::Info, LogFormat::Text, false)
        .format_request(&event)
        .unwrap();

    assert!(!line.contains('\u{1b}'), "no colour was asked for: {line}");
    assert!(line.starts_with("info "), "{line}");
    assert!(line.contains("192.0.2.44"), "{line}");
    assert!(line.contains("v6.0"), "{line}");
    assert!(line.contains("unlicensed"), "{line}");
    assert!(line.contains("office-pc"), "{line}");
    assert!(line.contains("activated"), "{line}");
    assert!(line.contains("count 25"), "{line}");

    let coloured = Logger::with(LogLevel::Info, LogFormat::Text, true)
        .format_request(&event)
        .unwrap();
    assert!(
        coloured.contains('\u{1b}'),
        "colour was asked for: {coloured}"
    );
}

/// Filtering applies to request lines too, not only to messages.
#[test]
fn a_quiet_logger_emits_no_request_lines() {
    let event = event_for(guid(SERVER_2025), "office-pc");
    for level in [LogLevel::Error, LogLevel::Warn] {
        assert!(
            Logger::with(level, LogFormat::Json, false)
                .format_request(&event)
                .is_none(),
            "{level:?} should suppress request lines"
        );
    }
    assert!(
        Logger::with(LogLevel::Info, LogFormat::Json, false)
            .format_request(&event)
            .is_some()
    );
}

/// `OBS-001` (#177): the log goes to stderr and nowhere else.
///
/// One of the two properties that genuinely needs the real process, since it is
/// about which file descriptor the output lands on.
#[test]
fn nothing_is_written_to_stdout() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kmsrsos"))
        .env("KMSRSOS_CONFIG", r#"log-format = "json""#)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the binary runs");

    std::thread::sleep(Duration::from_millis(500));
    let _ = child.kill();
    let output = child.wait_with_output().expect("collected");
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty, got {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// `OBS-002` (#178): no escape codes when stderr is a pipe. py-kms emits them
/// regardless, because it has neither terminal detection nor a way to turn
/// colour off.
///
/// The other property that needs the real process: whether stderr is a terminal
/// is not observable from inside a unit test.
#[test]
fn no_ansi_escapes_when_stderr_is_a_pipe() {
    let output = Command::new(env!("CARGO_BIN_EXE_kmsrsos"))
        .env("KMSRSOS_CONFIG", "this is not valid toml")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("the binary runs");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.is_empty(), "the failure should have been reported");
    assert!(
        !stderr.contains('\u{1b}'),
        "an escape code reached a pipe: {stderr:?}"
    );
}

/// Whether a `"key":` appears at the top level of the object, rather than
/// inside a string value — so a workstation name containing `"count":25`
/// cannot satisfy an assertion about the real field.
fn field_present(line: &str, field: &str) -> bool {
    let Some(key_end) = field.find("\":") else {
        return line.contains(field);
    };
    let key = field.get(..=key_end).unwrap_or(field);
    top_level_positions(line, key)
        .into_iter()
        .any(|at| line.get(at..).is_some_and(|rest| rest.starts_with(field)))
}

/// Byte offsets at which `key` appears outside any string value.
fn top_level_positions(line: &str, key: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut key_start: Option<usize> = None;

    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_string => escaped = true,
            '"' => {
                if in_string {
                    // A string just ended; if it started where a key would and
                    // matches, record it.
                    if let Some(start) = key_start
                        && line.get(start..).is_some_and(|rest| rest.starts_with(key))
                    {
                        found.push(start);
                    }
                    key_start = None;
                } else {
                    key_start = Some(index);
                }
                in_string = !in_string;
            }
            _ => {}
        }
    }
    found
}

/// A balance check: enough to catch an unescaped quote splitting the object.
fn is_balanced_json_object(line: &str) -> bool {
    if !line.starts_with('{') || !line.ends_with('}') {
        return false;
    }
    let mut in_string = false;
    let mut escaped = false;
    let mut depth = 0_i32;
    for character in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0 && !in_string
}

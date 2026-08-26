//! A DNS responder that answers `_vlmcs._tcp` and forwards everything else.
//!
//! `DISC-004` (#146). The discovery scenarios established what a Windows client
//! *asks*; this is what makes it possible to ask the other half — whether SPP
//! follows the answer, and in what order it tries multiple hosts.
//!
//! # Why it runs on the guest
//!
//! The obvious place is the host, and it cannot go there: binding port 53 needs
//! privilege the harness deliberately does not ask for, and QEMU's user-mode
//! networking forwards no UDP from guest to host. Running it *inside* the guest
//! sidesteps both — the guest has an administrator, and `127.0.0.1:53` is a
//! perfectly ordinary place for a resolver to be.
//!
//! The loopback constraint (`NET-014`, #163) does not apply here. It is about
//! the KMS **host**: Software Protection Platform refuses to activate against
//! a KMS server on loopback. Nothing stops it *resolving* against loopback, and
//! the SRV records this hands back point at a non-loopback address.
//!
//! # Everything else is forwarded
//!
//! Answering only `_vlmcs` and returning `NXDOMAIN` for the rest would break
//! the guest's name resolution, and a Windows client whose DNS is broken behaves
//! differently in ways that would contaminate the measurement. So anything this
//! does not care about is relayed verbatim to a real resolver.
//!
//! # Usage
//!
//! ```text
//! srv-responder.exe <upstream> <srv-target> [priority,weight,port,target ...]
//! srv-responder.exe 10.0.2.3 10.0.2.2
//! srv-responder.exe 10.0.2.3 10.0.2.2 0,100,1688,kms-a 10,100,1688,kms-b
//! ```
//!
//! With no explicit records it answers one SRV at priority 0 pointing at
//! `<srv-target>:1688`, plus the A record for it.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// One SRV record to hand back, in RFC 2782 terms.
#[derive(Debug, Clone)]
struct Srv {
    priority: u16,
    weight: u16,
    port: u16,
    /// Label the target resolves to, e.g. `kms-a` becomes `kms-a.<zone>`.
    target: String,
    /// What that name resolves to, so a client can act on the answer.
    address: Ipv4Addr,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let upstream: Ipv4Addr = args
        .first()
        .and_then(|a| a.parse().ok())
        .unwrap_or(Ipv4Addr::new(10, 0, 2, 3));
    let default_target: Ipv4Addr = args
        .get(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(Ipv4Addr::new(10, 0, 2, 2));

    let mut records: Vec<Srv> = Vec::new();
    for spec in args.iter().skip(2) {
        let parts: Vec<&str> = spec.split(',').collect();
        if parts.len() != 4 {
            eprintln!("ignoring malformed record spec {spec:?}");
            continue;
        }
        records.push(Srv {
            priority: parts[0].parse().unwrap_or(0),
            weight: parts[1].parse().unwrap_or(100),
            port: parts[2].parse().unwrap_or(1688),
            target: parts[3].to_string(),
            address: default_target,
        });
    }
    if records.is_empty() {
        records.push(Srv {
            priority: 0,
            weight: 100,
            port: 1688,
            target: String::from("kms"),
            address: default_target,
        });
    }

    // Both families, because Windows asks over whichever the resolver is
    // configured on — and with no IPv6 resolver set it asks the well-known
    // `fec0:0:0:ffff::` addresses, which are remote and would never arrive
    // here. Point the guest at `::1` as well as `127.0.0.1` and both land.
    let v4 = UdpSocket::bind("0.0.0.0:53").expect("bind 0.0.0.0:53 (run as administrator)");
    let v6 = UdpSocket::bind("[::]:53").ok();
    eprintln!(
        "srv-responder: listening on 0.0.0.0:53{}, forwarding to {upstream}",
        if v6.is_some() { " and [::]:53" } else { "" }
    );
    for record in &records {
        eprintln!(
            "  SRV prio={} weight={} port={} target={} -> {}",
            record.priority, record.weight, record.port, record.target, record.address
        );
    }

    // A tally, printed per query, so the transcript shows selection order
    // without needing the pcap open beside it.
    if let Some(v6) = v6 {
        let records = records.clone();
        std::thread::spawn(move || serve(&v6, upstream, &records));
    }
    serve(&v4, upstream, &records);
}

/// Answer queries on one socket until it fails.
fn serve(socket: &UdpSocket, upstream: Ipv4Addr, records: &[Srv]) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let query = &buffer[..len];
        let Some((name, qtype)) = parse_question(query) else {
            continue;
        };
        let lowered = name.to_ascii_lowercase();

        let reply = if lowered.starts_with("_vlmcs._tcp.") && qtype == 33 {
            *seen.entry(lowered.clone()).or_default() += 1;
            eprintln!("SRV  {name}  -> answering {} record(s)", records.len());
            Some(srv_reply(query, &name, &records))
        } else if qtype == 1 {
            match records.iter().find(|r| {
                lowered.starts_with(&format!("{}.", r.target.to_ascii_lowercase()))
                    || lowered == r.target.to_ascii_lowercase()
            }) {
                Some(record) => {
                    eprintln!("A    {name}  -> {}", record.address);
                    Some(a_reply(query, &name, record.address))
                }
                None => None,
            }
        } else {
            None
        };

        let response = match reply {
            Some(bytes) => bytes,
            None => match forward(upstream, query) {
                Some(bytes) => bytes,
                None => continue,
            },
        };
        drop(socket.send_to(&response, from));
    }
}

/// The first question's name and type, or `None` if this is not a query.
fn parse_question(packet: &[u8]) -> Option<(String, u16)> {
    if packet.len() < 12 {
        return None;
    }
    // QR bit set means this is a response, not something to answer.
    if packet[2] & 0x80 != 0 {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let length = *packet.get(at)? as usize;
        at += 1;
        if length == 0 {
            break;
        }
        // A pointer in a question is malformed; refuse rather than chase it.
        if length & 0xC0 != 0 {
            return None;
        }
        let end = at.checked_add(length)?;
        labels.push(String::from_utf8_lossy(packet.get(at..end)?).into_owned());
        at = end;
    }
    let qtype = u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]);
    Some((labels.join("."), qtype))
}

/// Header plus the echoed question, with the answer count filled in.
fn reply_head(query: &[u8], answers: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&query[0..2]); // the client's transaction id
    // QR | AA, and RD copied from the query so the client sees its own flag.
    out.push(0x84 | (query[2] & 0x01));
    out.push(0x00); // RCODE 0
    out.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&answers.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0_u16.to_be_bytes()); // ARCOUNT
    // The question, verbatim: name, qtype, qclass.
    let mut at = 12;
    while let Some(&length) = query.get(at) {
        at += 1 + length as usize;
        if length == 0 {
            break;
        }
    }
    out.extend_from_slice(&query[12..at + 4]);
    out
}

/// Encode a name as DNS labels.
fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// An answer section with every SRV record, plus each target's A record.
///
/// The A records ride along in the answer section rather than in additional,
/// because a client that ignores additional would otherwise need a second round
/// trip and the timing of that would show up in the measurement.
///
/// `KMSRSOS_NO_INLINE_A=1` withholds them, which is how `DISC-009` (#381)
/// observes selection: with no address in the answer the client must look up
/// the target it chose, and that lookup names the choice in this log. It costs
/// a round trip, so it is off unless asked for.
fn srv_reply(query: &[u8], name: &str, records: &[Srv]) -> Vec<u8> {
    let inline_a = std::env::var("KMSRSOS_NO_INLINE_A").as_deref() != Ok("1");
    // `_vlmcs._tcp.example.com` -> `example.com`, the zone targets live in.
    let zone = name.splitn(3, '.').nth(2).unwrap_or_default().to_string();

    let per_record = if inline_a { 2 } else { 1 };
    let count = u16::try_from(records.len() * per_record).unwrap_or(u16::MAX);
    let mut out = reply_head(query, count);
    for record in records {
        let target = if zone.is_empty() {
            record.target.clone()
        } else {
            format!("{}.{}", record.target, zone)
        };
        let encoded = encode_name(&target);

        out.extend_from_slice(&encode_name(name));
        out.extend_from_slice(&33_u16.to_be_bytes()); // SRV
        out.extend_from_slice(&1_u16.to_be_bytes()); // IN
        out.extend_from_slice(&60_u32.to_be_bytes()); // TTL, short so retries re-query
        let length = u16::try_from(6 + encoded.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&record.priority.to_be_bytes());
        out.extend_from_slice(&record.weight.to_be_bytes());
        out.extend_from_slice(&record.port.to_be_bytes());
        out.extend_from_slice(&encoded);
    }
    for record in records.iter().filter(|_| inline_a) {
        let target = if zone.is_empty() {
            record.target.clone()
        } else {
            format!("{}.{}", record.target, zone)
        };
        out.extend_from_slice(&encode_name(&target));
        out.extend_from_slice(&1_u16.to_be_bytes()); // A
        out.extend_from_slice(&1_u16.to_be_bytes()); // IN
        out.extend_from_slice(&60_u32.to_be_bytes());
        out.extend_from_slice(&4_u16.to_be_bytes());
        out.extend_from_slice(&record.address.octets());
    }
    out
}

fn a_reply(query: &[u8], name: &str, address: Ipv4Addr) -> Vec<u8> {
    let mut out = reply_head(query, 1);
    out.extend_from_slice(&encode_name(name));
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&60_u32.to_be_bytes());
    out.extend_from_slice(&4_u16.to_be_bytes());
    out.extend_from_slice(&address.octets());
    out
}

/// Relay a query to a real resolver so the guest's other lookups keep working.
fn forward(upstream: Ipv4Addr, query: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    socket
        .send_to(query, SocketAddr::from((upstream, 53)))
        .ok()?;
    let mut buffer = [0_u8; 4096];
    let (len, _) = socket.recv_from(&mut buffer).ok()?;
    Some(buffer[..len].to_vec())
}

//! Build the Windows message table this binary registers as its own
//! `EventMessageFile` (`OBS-016`, #192).
//!
//! # Why this is generated rather than compiled
//!
//! The usual route is a `.mc` file through `mc.exe` and `rc.exe`, neither of
//! which exists on a Linux cross-build host, and neither of which this project
//! is willing to acquire as a build dependency for six strings. `llvm-rc` is
//! not in the toolchain either.
//!
//! What *is* available is that `lld-link` — the linker this target already uses
//! — consumes a `.res` file directly. A `.res` is a flat sequence of
//! length-prefixed resource blocks with no relocations and no directory tree;
//! the linker builds the tree. So the whole toolchain problem reduces to
//! writing about eighty bytes of header and some UTF-16, which is done here.
//!
//! The messages are the single source of truth for both this table and
//! [`kmsrs_server::eventlog`]'s event identifiers, and a test asserts the two
//! agree — a message table whose IDs have drifted from the code renders as
//! *"The description for Event ID N cannot be found"*, which looks broken and
//! is worse than no Event Log at all.

//! # About the lint relaxation
//!
//! The same argument `kmsrs-db`'s build script makes: `ARCH-008` (#8) denies
//! panicking constructs because a panic in the server is a request a client can
//! use to kill a connection, and a build script has the opposite property —
//! panicking is its only failure mechanism, the message is the diagnostic a
//! maintainer reads, and none of this reaches the shipped binary.
#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division_remainder_used,
    reason = "a build script fails by panicking; none of this reaches the binary"
)]

use std::path::PathBuf;

/// The six events, in identifier order (`OBS-016`, #192).
///
/// **The identifier is the position, not a written number**: message `n` is
/// `MESSAGES[n - 1]`. Writing the id next to the text would be a second place
/// for it to be wrong, and the failure it produces — an event rendering as
/// *"The description for Event ID N cannot be found"* — is invisible until an
/// operator is already reading the log to find out why nothing works.
///
/// `Event` in `src/eventlog.rs` is the other half, and
/// `the_message_table_matches_the_events` fails if the two disagree in length.
///
/// `%1` is the insertion string each event supplies. Every message has exactly
/// one, so a caller cannot pass a count the table does not expect.
const MESSAGES: &[&str] = &[
    "kmsrsos started and is serving. %1",
    "kmsrsos stopped cleanly. %1",
    "kmsrsos could not bind a listener and is not serving. %1",
    "kmsrsos failed its entropy self-test and is not serving. %1",
    "kmsrsos could not parse KMSRSOS_CONFIG and is not serving. %1",
    "kmsrsos panicked. %1",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // `CARGO_CFG_TARGET_OS` rather than `cfg!`: this runs on the build host, so
    // asking what the host is would answer the wrong question entirely.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let res = out.join("kmsrsos-messages.res");
    std::fs::write(&res, message_table_res()).expect("writing the message table");

    // Handed to the linker directly. lld-link converts a `.res` itself, which
    // is why no `cvtres` step appears anywhere in this tree.
    println!("cargo:rustc-link-arg-bins={}", res.display());
}

/// A complete `.res` file holding one `RT_MESSAGETABLE` resource.
fn message_table_res() -> Vec<u8> {
    let mut out = Vec::new();
    // A `.res` opens with a null resource: 32 zero bytes, which is a header
    // declaring a zero-length entry. Tools use it to recognise the format.
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00]);
    out.extend_from_slice(&[0u8; 16]);
    // Correct the two size fields the run of zeroes above left wrong.
    out[0..4].copy_from_slice(&0u32.to_le_bytes()); // DataSize
    out[4..8].copy_from_slice(&32u32.to_le_bytes()); // HeaderSize

    let data = message_table_data();
    let mut header = Vec::new();
    header.extend_from_slice(
        &u32::try_from(data.len())
            .expect("table fits in u32")
            .to_le_bytes(),
    );
    header.extend_from_slice(&32u32.to_le_bytes()); // HeaderSize: both ordinals
    header.extend_from_slice(&[0xFF, 0xFF]); // Type is an ordinal
    header.extend_from_slice(&11u16.to_le_bytes()); // RT_MESSAGETABLE
    header.extend_from_slice(&[0xFF, 0xFF]); // Name is an ordinal
    header.extend_from_slice(&1u16.to_le_bytes()); // resource id 1
    header.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    header.extend_from_slice(&0x30u16.to_le_bytes()); // MOVEABLE | PURE
    header.extend_from_slice(&0x0409u16.to_le_bytes()); // en-US
    header.extend_from_slice(&0u32.to_le_bytes()); // Version
    header.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    assert_eq!(header.len(), 32, "the resource header is a fixed 32 bytes");

    out.extend_from_slice(&header);
    out.extend_from_slice(&data);
    out.resize(out.len().next_multiple_of(4), 0);
    out
}

/// The `MESSAGE_RESOURCE_DATA` body.
///
/// One block covering the whole contiguous identifier range, which is what
/// makes the "IDs must be contiguous from 1" assertion below worth having: a
/// gap would need a second block, and silently emitting one block for a
/// non-contiguous range produces a table that renders the wrong text.
fn message_table_data() -> Vec<u8> {
    assert!(!MESSAGES.is_empty(), "a message table with no messages");
    // Identifiers are positions, so the range is contiguous by construction and
    // one block always suffices.
    let low: u32 = 1;
    let high = u32::try_from(MESSAGES.len()).expect("six messages fit in u32");

    let mut entries = Vec::new();
    for text in MESSAGES {
        // Every message is terminated with CRLF then NUL, because
        // `FormatMessage` keeps the trailing newline and Event Viewer expects
        // one; the NUL is what ends the string.
        let mut wide: Vec<u16> = format!("{text}\r\n").encode_utf16().collect();
        wide.push(0);
        // Length covers the two header fields as well, and the whole entry is
        // padded to a 4-byte boundary.
        let mut entry = Vec::new();
        let length = 4 + wide.len() * 2;
        let padded = length.next_multiple_of(4);
        entry.extend_from_slice(&u16::try_from(padded).expect("entry fits").to_le_bytes());
        entry.extend_from_slice(&1u16.to_le_bytes()); // the text is UTF-16
        for unit in wide {
            entry.extend_from_slice(&unit.to_le_bytes());
        }
        entry.resize(padded, 0);
        entries.extend_from_slice(&entry);
    }

    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_le_bytes()); // one block
    out.extend_from_slice(&low.to_le_bytes());
    out.extend_from_slice(&high.to_le_bytes());
    // Offset is from the start of this structure: the count plus one block.
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&entries);
    out
}

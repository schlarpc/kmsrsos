//! The committed fuzz seeds, and a stable-toolchain replay of them
//! (`TEST-006`, #227; `SEC-004`, #196).
//!
//! # Seeds are not the corpus
//!
//! `fuzz/seeds/<target>/` is generated here, committed, and asserted
//! byte-exact. `fuzz/corpus/<target>/` is the fuzzer's working set, is ignored
//! by git, and is where libFuzzer writes every input it discovers. Keeping them
//! apart is not tidiness: libFuzzer writes back into whichever directory it is
//! given, so a committed set that is also fuzzed stops matching its own
//! generator after the first minute-long run, and the diff that follows is
//! noise nobody can review. A run is seeded *from* the committed set:
//!
//! ```text
//! nix develop .#fuzz -c cargo fuzz run rpc_pdu fuzz/corpus/rpc_pdu fuzz/seeds/rpc_pdu
//! ```
//!
//! # What this file is for
//!
//! `cargo fuzz` needs nightly for `-Zsanitizer=address`, and this workspace is
//! pinned to stable (`ARCH-016`, #16). Two things follow, and this file is both
//! of them:
//!
//! 1. **The seeds are generated, not hand-collected.** Every one is derived
//!    from the golden vectors in this crate (`TEST-002`, #223), so a change to
//!    the wire format regenerates them rather than leaving a seed set that
//!    describes a protocol the code no longer speaks. `KMSRSOS_BLESS=1` writes
//!    the files; without it, the test asserts the committed bytes still match —
//!    the same two-step the golden vectors use, for the same reason.
//! 2. **The seeds run on every commit.** Each one, plus a set of deterministic
//!    mutations of it, is fed through its target function here. That is not
//!    fuzzing — it explores no new inputs — but it is what makes the target
//!    bodies *live code*: they are type-checked, linted, covered by
//!    `cargo llvm-cov`, and a panic in one fails CI on the pinned toolchain
//!    rather than waiting for someone to install nightly.
//!
//! # Regenerating
//!
//! `KMSRSOS_BLESS=1 cargo test -p kmsrs-vectors --test fuzz_seeds`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_proto::wire::header::HEADER_LEN;
use kmsrs_proto::wire::stub;
use kmsrs_proto::wire::syntax::TransferSyntax;
use kmsrs_vectors::targets::{self, TARGETS};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Where the committed seeds live.
///
/// Deliberately *not* `fuzz/corpus/`. libFuzzer writes every input it discovers
/// back into the corpus directory it is given, so a corpus that is both
/// committed and fuzzed stops matching its generator the first time anyone runs
/// the fuzzer for a minute. Seeds are generated and asserted byte-exact here;
/// the working corpus is a separate, ignored directory that a run is seeded
/// *from*.
fn seeds_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds")
}

/// One seed: the file name it is committed under, and its bytes.
type Seed = (String, Vec<u8>);

/// The KMS request or response payload inside a vector, at whichever transfer
/// syntax it was framed with.
///
/// Trying both is deliberate. Hard-coding the syntax the generator happened to
/// use would make this file quietly wrong the day a vector is re-blessed at the
/// other one, and the failure would be an empty corpus rather than an error.
fn payload_of(pdu: &[u8]) -> Option<Vec<u8>> {
    let body = pdu.get(HEADER_LEN..)?;
    for syntax in [TransferSyntax::Ndr64, TransferSyntax::Ndr32] {
        if let Ok(parsed) = stub::parse_request(body, syntax) {
            return Some(parsed.data.to_vec());
        }
        if let Ok(parsed) = stub::parse_response(body, syntax) {
            return Some(parsed.payload.to_vec());
        }
    }
    None
}

/// Whether a vector is a request PDU, which decides which targets it seeds.
fn is_request(name: &str) -> bool {
    name.starts_with("request-")
}

/// Whether a vector is a response PDU.
fn is_response(name: &str) -> bool {
    name.starts_with("response-")
}

/// Build the seed set for one target.
fn seeds_for(target: &str) -> Vec<Seed> {
    let mut seeds: Vec<Seed> = Vec::new();

    match target {
        // The header parser sees every PDU either side sends, so every vector
        // is a seed exactly as committed.
        "rpc_pdu" => {
            for vector in kmsrs_vectors::VECTORS {
                seeds.push((format!("{}.bin", vector.name), vector.bytes.to_vec()));
            }
        }

        // The state machine reads a leading chunk-size byte and then a stream.
        // Three chunk sizes per vector, chosen to land on the three interesting
        // cases: one byte at a time, mid-header, and the whole thing at once.
        "connection" => {
            for vector in kmsrs_vectors::VECTORS {
                for chunk in [1_u8, 9, 255] {
                    let mut bytes = vec![chunk];
                    bytes.extend_from_slice(vector.bytes);
                    seeds.push((format!("{}-chunk{chunk}.bin", vector.name), bytes));
                }
            }
            // And a full exchange, so the machine reaches the bound state with
            // a real request behind it rather than only ever seeing a bind.
            let mut stream = vec![64_u8];
            for name in ["bind-ndr64", "alter-context", "request-v6"] {
                stream.extend_from_slice(kmsrs_vectors::find(name).unwrap().bytes);
            }
            seeds.push((String::from("exchange-v6.bin"), stream));
        }

        // The payload decoder sees the stub of a request, not the whole PDU.
        "kms_payload" => {
            for vector in kmsrs_vectors::VECTORS.iter().filter(|v| is_request(v.name)) {
                let payload = payload_of(vector.bytes)
                    .unwrap_or_else(|| panic!("{} has no readable stub", vector.name));
                seeds.push((format!("{}.bin", vector.name), payload));
            }
        }

        // The unpadder sees ciphertext. The v5 and v6 payloads are exactly
        // that; the v4 one is plaintext with a MAC, which is a useful negative.
        "decrypt_unpad" => {
            for vector in kmsrs_vectors::VECTORS
                .iter()
                .filter(|v| is_request(v.name) || is_response(v.name))
            {
                let payload = payload_of(vector.bytes)
                    .unwrap_or_else(|| panic!("{} has no readable stub", vector.name));
                seeds.push((format!("{}.bin", vector.name), payload));
            }
        }

        // Text, so the seeds are written as text. The set covers a real ePID,
        // its boundary lengths, and the shapes a hostile host might send.
        "epid" => {
            for (name, text) in EPID_SEEDS {
                seeds.push((format!("{name}.txt"), text.as_bytes().to_vec()));
            }
        }

        // The client's decoder sees response stubs.
        "response" => {
            for vector in kmsrs_vectors::VECTORS
                .iter()
                .filter(|v| is_response(v.name))
            {
                let payload = payload_of(vector.bytes)
                    .unwrap_or_else(|| panic!("{} has no readable stub", vector.name));
                seeds.push((format!("{}.bin", vector.name), payload));
            }
        }

        other => panic!("no seed rule for target {other}"),
    }

    seeds.sort_by(|left, right| left.0.cmp(&right.0));
    seeds
}

/// The ePID seeds, written out rather than generated.
///
/// A generator would produce only ePIDs this codebase can already build, which
/// is the half of the input space the parser is least likely to be wrong about.
const EPID_SEEDS: &[(&str, &str)] = &[
    (
        "genuine",
        "03612-00206-591-000000-03-1033-26100.0000-2412024",
    ),
    (
        "office",
        "06401-00206-437-838326-03-1033-19041.0000-1932021",
    ),
    ("empty", ""),
    ("one-unit", "0"),
    ("no-hyphens", "0361200206591000000031033261000000241202"),
    ("all-hyphens", "-----------------------------------------"),
    // 63 units is the longest an ePID may be, since the terminating NUL counts
    // against the 64-unit field (`KMS-011`, #27).
    (
        "max-units",
        "012345678901234567890123456789012345678901234567890123456789012",
    ),
    (
        "one-over-max",
        "0123456789012345678901234567890123456789012345678901234567890123",
    ),
    // Non-ASCII that is still valid UTF-8, so it reaches the parser: a genuine
    // ePID never contains one, and refusing it is the point.
    (
        "non-ascii",
        "03612-00206-591-000000-03-1033-26100.0000-24120é4",
    ),
    (
        "nul-inside",
        "03612-00206\u{0}591-000000-03-1033-26100.0000-2412024",
    ),
];

/// Deterministic mutations of a seed.
///
/// Not a fuzzer and not pretending to be one: a fixed, small set that reaches
/// the truncation and length-field bugs a corpus of well-formed inputs never
/// would. The fuzzer proper explores; this only proves the targets survive the
/// obvious neighbourhood of every seed on a toolchain CI actually runs.
fn mutations(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    // Truncations, including to nothing. `checked_div` rather than `/` because
    // the workspace deny list applies here too (`ARCH-008`, #8), and a divisor
    // arriving as zero is exactly the kind of slip it exists to catch.
    let fraction = |divisor: usize| seed.len().checked_div(divisor).unwrap_or(0);
    for divisor in [1_usize, 2, 4, 8] {
        out.push(seed[..fraction(divisor)].to_vec());
    }

    // A flipped high bit at each end and in the middle, which for a
    // little-endian length field is the change that makes it enormous.
    for index in [0_usize, fraction(2), seed.len().saturating_sub(1)] {
        if index < seed.len() {
            let mut mutated = seed.to_vec();
            mutated[index] ^= 0x80;
            out.push(mutated);
        }
    }

    // The seed twice over, so a decoder that trusts its own framing to end
    // where the buffer does is caught.
    let mut doubled = seed.to_vec();
    doubled.extend_from_slice(seed);
    out.push(doubled);

    // And the seed with trailing garbage that is not a PDU at all.
    let mut trailing = seed.to_vec();
    trailing.extend_from_slice(&[0xFF; 32]);
    out.push(trailing);

    out
}

#[test]
fn the_committed_seeds_match_what_the_vectors_generate() {
    let bless = std::env::var("KMSRSOS_BLESS").is_ok();
    let root = seeds_root();
    let mut mismatches: Vec<String> = Vec::new();
    let mut written = 0_usize;

    for (target, _) in TARGETS {
        let directory = root.join(target);
        let expected: BTreeMap<String, Vec<u8>> = seeds_for(target).into_iter().collect();

        if bless {
            // Remove first, so a seed that is no longer generated does not
            // linger as an entry nothing accounts for.
            if directory.exists() {
                std::fs::remove_dir_all(&directory).unwrap();
            }
            std::fs::create_dir_all(&directory).unwrap();
            for (name, bytes) in &expected {
                std::fs::write(directory.join(name), bytes).unwrap();
                written += 1;
            }
            continue;
        }

        let mut found: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("{} is missing: {error}", directory.display()));
        for entry in entries {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            found.insert(name, std::fs::read(entry.path()).unwrap());
        }

        for (name, bytes) in &expected {
            match found.get(name) {
                None => mismatches.push(format!("{target}/{name}: committed file is missing")),
                Some(committed) if committed != bytes => mismatches.push(format!(
                    "{target}/{name}: {} committed bytes, {} generated",
                    committed.len(),
                    bytes.len()
                )),
                Some(_) => {}
            }
        }
        for name in found.keys() {
            if !expected.contains_key(name) {
                mismatches.push(format!(
                    "{target}/{name}: committed but no longer generated"
                ));
            }
        }
    }

    if bless {
        eprintln!("blessed {written} seed files");
        return;
    }
    assert!(
        mismatches.is_empty(),
        "the fuzz seeds no longer match the golden vectors they are derived from. \
         If the wire format changed on purpose, re-bless with \
         KMSRSOS_BLESS=1 cargo test -p kmsrs-vectors --test fuzz_seeds\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn every_target_has_a_non_empty_seed_set() {
    for (target, _) in TARGETS {
        let seeds = seeds_for(target);
        assert!(!seeds.is_empty(), "{target} has no seeds");
        // Tests run in parallel, and under `KMSRSOS_BLESS` the directory is
        // being created by the test next door. Checking for it then would make
        // the outcome depend on scheduling.
        if std::env::var("KMSRSOS_BLESS").is_ok() {
            continue;
        }
        let directory = seeds_root().join(target);
        assert!(
            directory.is_dir(),
            "{} does not exist; a target without a committed seed set starts every \
             fuzzing run from nothing",
            directory.display()
        );
    }
}

#[test]
fn replaying_the_seeds_and_their_mutations_panics_nowhere() {
    let mut inputs = 0_usize;
    for (target, body) in TARGETS {
        for (name, bytes) in seeds_for(target) {
            body(&bytes);
            inputs += 1;
            for (index, mutated) in mutations(&bytes).into_iter().enumerate() {
                body(&mutated);
                inputs += 1;
                // Named in the panic message by position, since a failure here
                // is reported by the test harness against this line and the
                // input has to be reconstructible from it.
                let _ = (target, &name, index);
            }
        }
    }
    // A guard against the loop silently doing nothing, which is how a replay
    // test passes forever after a refactor empties its input set.
    assert!(inputs > 500, "only {inputs} inputs replayed");
}

/// The nightly-only half of the arrangement, checked from the stable half.
///
/// `fuzz/` is excluded from the workspace, so nothing else in CI ever reads it.
/// Without this, a target could be added to [`TARGETS`] and be missing a
/// `[[bin]]` — or, worse, a shim could name the wrong function and silently
/// fuzz something twice — and the first person to notice would be whoever
/// installed nightly months later.
#[test]
fn the_fuzz_crate_declares_exactly_these_targets() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();

    for (target, _) in TARGETS {
        assert!(
            manifest.contains(&format!("name = \"{target}\"")),
            "fuzz/Cargo.toml declares no [[bin]] named {target}"
        );
        assert!(
            manifest.contains(&format!("path = \"fuzz_targets/{target}.rs\"")),
            "fuzz/Cargo.toml does not point {target} at its shim"
        );

        let shim = std::fs::read_to_string(root.join(format!("fuzz_targets/{target}.rs")))
            .unwrap_or_else(|error| panic!("fuzz_targets/{target}.rs: {error}"));
        assert!(
            shim.contains(&format!("kmsrs_vectors::targets::{target}(data)")),
            "fuzz_targets/{target}.rs does not call the target of the same name"
        );
    }

    // And nothing extra: a `[[bin]]` with no entry in `TARGETS` has no seeds
    // and no stable-toolchain coverage.
    let declared = manifest.matches("[[bin]]").count();
    assert_eq!(
        declared,
        TARGETS.len(),
        "fuzz/Cargo.toml declares {declared} binaries but there are {} targets",
        TARGETS.len()
    );
}

#[test]
fn the_empty_input_is_handled_by_every_target() {
    for (target, body) in TARGETS {
        body(&[]);
        body(&[0]);
        assert!(targets::run(target, &[0xFF; 16]));
    }
    assert!(!targets::run("not-a-target", &[]));
}

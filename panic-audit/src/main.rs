//! Proof, rather than a lint, that the sans-io core cannot panic
//! (`ARCH-009`, #9).
//!
//! # What this is
//!
//! A freestanding `no_std` binary for `x86_64-unknown-none` that calls every
//! entry point of `kmsrs-proto` and `kmsrs-crypto` on bytes it cannot see the
//! provenance of. It is built exactly the way the release binary is — fat LTO,
//! one codegen unit, `panic = "abort"` — and then its symbol table is read: if
//! any call in the core can still reach `core::panicking`, the optimiser will
//! have left a reference to it, and `audit.sh` fails the build.
//!
//! # Why a binary and not a lint
//!
//! `ARCH-008` (#8) denies `unwrap`, `expect`, `panic`, indexing and unchecked
//! arithmetic in these crates, and that catches the panics somebody *wrote*. It
//! says nothing about the ones the compiler inserts: a bounds check LLVM could
//! not prove away, a `copy_from_slice` whose two lengths are not visibly equal,
//! a slice range where the optimiser cannot see that `start <= end`. Those are
//! invisible to clippy and are exactly the ones that survive to run time.
//!
//! This is only tractable because the core is sans-io (axiom A7). There is no
//! socket, no clock and no allocator to stand up, so the whole of both crates
//! links into a freestanding binary with nothing underneath it.
//!
//! # The trade-off this makes explicit
//!
//! The release profile aborts on panic, so on Hermit a panic kills the VM and
//! only the hypervisor can restart it (`OS-013`, #264). That is the reason to
//! want this proof rather than a promise: the cost of being wrong is highest on
//! the platform with the least ability to recover.
//!
//! # Running it
//!
//! `./panic-audit/audit.sh`

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use kmsrs_crypto::cbc::{self, Iv};
use kmsrs_crypto::rijndael::KeySchedule;
use kmsrs_proto::entropy::{Entropy, EntropyUnavailable};
use kmsrs_proto::kms::epid::EPid;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::response;
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::types::{HardwareId, Intervals};
use kmsrs_proto::wire::connection::{Connection, Decision, Grant, Step};
use kmsrs_proto::wire::syntax::TransferSyntax;
use kmsrs_proto::wire::{bind, stub};

/// Aborting rather than unwinding, as the release profile does.
///
/// The loop is not reachable in a build the audit passes; it exists because a
/// `no_std` binary must name a panic handler to link at all, and the handler's
/// *existence* is not what the audit measures — a reference to
/// `core::panicking` from the core's own code is.
#[panic_handler]
fn panicked(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// A source that returns bytes without reading anything.
///
/// The real one draws from the platform (`ARCH-003`, #3); the audit only needs
/// entropy to be *supplied*, since what is being measured is the code that
/// consumes it.
struct Fixed(u8);

impl Entropy for Fixed {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyUnavailable> {
        for byte in destination.iter_mut() {
            self.0 = self.0.wrapping_mul(31).wrapping_add(17);
            *byte = self.0;
        }
        Ok(())
    }
}

/// Somewhere for results to go that the optimiser cannot see through.
///
/// Without it, LLVM is free to delete a call whose result is unused — and a
/// deleted call has no panic paths, so the audit would pass by proving nothing.
static mut SINK: u64 = 0;

/// Consume a value so the call that produced it cannot be optimised away.
fn sink(value: u64) {
    // `read_volatile`/`write_volatile` would need `unsafe`. `black_box` is the
    // safe, stable way to say "pretend this escaped", which is exactly the
    // guarantee needed here.
    let current = core::hint::black_box(value);
    core::hint::black_box(&raw const SINK);
    core::hint::black_box(current);
}

/// The entry point. Everything below it is reachable from a socket.
///
/// `extern "C"` with a raw entry name because there is no runtime to call
/// `main`. The two arguments stand in for "bytes that arrived from somewhere",
/// so the optimiser cannot constant-fold the input and delete the parsers along
/// with it.
#[unsafe(no_mangle)]
pub extern "C" fn _start(length: usize) -> ! {
    // A buffer whose contents the optimiser cannot know: filled from `Fixed`,
    // which it cannot see through because `fill` is behind a trait object.
    let mut buffer = [0_u8; 1024];
    let mut entropy = Fixed(0x5A);
    let source: &mut dyn Entropy = &mut entropy;
    let _ = source.fill(&mut buffer);

    let bytes: &[u8] = buffer.get(..length.min(buffer.len())).unwrap_or(&[]);

    audit_rpc(bytes);
    audit_kms(bytes, &mut entropy);
    audit_crypto(bytes);
    audit_connection(bytes, &mut entropy);

    #[cfg(feature = "inject-panic")]
    audit_injected_panic(bytes);

    loop {
        core::hint::spin_loop();
    }
}

/// The DCE/RPC layer.
///
/// `inline(never)` on each of these four, so a panic reference is attributed to
/// the layer it came from instead of being inlined into `_start` where it says
/// only that something, somewhere, can panic.
#[inline(never)]
fn audit_rpc(bytes: &[u8]) {
    if let Ok(request) = bind::parse(bytes) {
        sink(request.items.len() as u64);
        for enabled in [true, false] {
            let _ = bind::decide(&request, enabled);
        }
    }

    let mut out = [0_u8; 512];
    for reason in [
        bind::NakReason::NotSpecified,
        bind::NakReason::ProtocolVersionNotSupported,
    ] {
        if let Ok(written) = bind::write_nak(7, reason, &mut out) {
            sink(written as u64);
        }
    }

    for syntax in [TransferSyntax::Ndr32, TransferSyntax::Ndr64] {
        if let Ok(parsed) = stub::parse_request(bytes, syntax) {
            sink(parsed.data.len() as u64);
        }
        if let Ok(parsed) = stub::parse_response(bytes, syntax) {
            sink(parsed.payload.len() as u64);
        }
        sink(stub::response_stub_len(syntax, bytes.len()) as u64);
        sink(stub::error_stub_len(syntax) as u64);
    }
}

/// The KMS payload layer, both directions.
#[inline(never)]
fn audit_kms(bytes: &[u8], entropy: &mut dyn Entropy) {
    let ciphers = Ciphers::new();

    if let Ok(request) = framing::decode(bytes, &ciphers) {
        sink(request.version as u64);

        if let Ok(epid) = EPid::parse("03612-00206-591-000000-03-1033-26100.0000-2412024") {
            sink(framing::response_len(request.version, &epid) as u64);

            let mut out = [0_u8; 1024];
            let plan = framing::ResponsePlan {
                epid: &epid,
                client_machine_id: request.request.client_machine_id,
                client_time: request.request.client_time,
                count: 25,
                intervals: Intervals::DEFAULT,
                hardware_id: HardwareId([1, 2, 3, 4, 5, 6, 7, 8]),
            };
            if let Ok(written) = framing::encode(&request, &plan, &ciphers, entropy, &mut out) {
                sink(written as u64);
            }
        }
    }

    let mut scratch = [0_u8; 1024];
    for version in Version::ALL {
        if let Ok(decoded) =
            response::decode(version, bytes, ciphers.schedule(version), &mut scratch)
        {
            sink(decoded.wire_len as u64);
            sink(decoded.pid_bytes.len() as u64);
        }
    }

    // The ePID, which is the one place text meets the wire.
    if let Ok(text) = core::str::from_utf8(bytes)
        && let Ok(epid) = EPid::parse(text)
    {
        let mut out = [0_u8; 256];
        if let Some(written) = epid.encode(&mut out) {
            sink(written as u64);
        }
        sink(u64::from(epid.pid_size().get()));
    }
}

/// The block ciphers and their modes.
#[inline(never)]
fn audit_crypto(bytes: &[u8]) {
    let aes = KeySchedule::aes128(&[0x2A; 16]);
    let wide = KeySchedule::rijndael160(&[0x3B; 20]);
    let tweaked = KeySchedule::aes128_tweaked_for_v6(&[0x4C; 16]);

    for schedule in [&aes, &wide, &tweaked] {
        let mut block = [0_u8; 16];
        for (slot, byte) in block.iter_mut().zip(bytes.iter().copied()) {
            *slot = byte;
        }
        schedule.encrypt_block(&mut block);
        schedule.decrypt_block(&mut block);
        sink(u64::from(block[0]));
        sink(schedule.rounds() as u64);
    }

    let iv = [0x11_u8; 16];
    let mut plaintext = [0_u8; 1024];
    for mode in [Iv::Null, Iv::Block(&iv)] {
        if cbc::decrypt(&aes, mode, bytes, &mut plaintext).is_ok() {
            sink(plaintext[0].into());
        }
    }

    let mut in_place = [0_u8; 256];
    for (slot, byte) in in_place.iter_mut().zip(bytes.iter().copied()) {
        *slot = byte;
    }
    if cbc::encrypt_in_place(&aes, Iv::Null, &mut in_place, bytes.len().min(200)).is_ok() {
        sink(in_place[0].into());
    }

    if let Ok(stripped) = cbc::strip_padding(bytes) {
        sink(stripped.len() as u64);
    }
}

/// The connection state machine, which is the largest single body of code that
/// sees untrusted bytes.
#[inline(never)]
fn audit_connection(bytes: &[u8], entropy: &mut dyn Entropy) {
    let Ok(epid) = EPid::parse("03612-00206-591-000000-03-1033-26100.0000-2412024") else {
        return;
    };
    let decision = Decision::Grant(Grant {
        epid,
        count: 25,
        intervals: Intervals::DEFAULT,
        hardware_id: HardwareId([1, 2, 3, 4, 5, 6, 7, 8]),
    });

    let mut machine = Connection::new(0x1234_5678, true);
    let mut out = [0_u8; 1024];
    if machine.receive(bytes).is_err() {
        return;
    }
    let step = machine.step(
        kmsrs_proto::time::Instant::from_nanos(1),
        entropy,
        &mut |_request| decision.clone(),
        &mut out,
    );
    match step {
        Step::Send { len } | Step::SendThenClose { len, .. } => sink(len as u64),
        Step::NeedMore | Step::Close { .. } => sink(0),
    }
    let mut events = 0_u64;
    while machine.next_event().is_some() {
        events = events.wrapping_add(1);
    }
    sink(events);
}

/// One call that genuinely panics, so the audit can prove its own detector
/// still works.
///
/// A check that has never been seen to fail is a check nobody should trust: if
/// a toolchain upgrade renamed the symbols, stripped them, or inlined them into
/// something the grep does not match, the audit would pass forever while
/// measuring nothing. Building with `--features inject-panic` must *fail* the
/// audit, and `audit.sh` runs both builds for that reason.
#[cfg(feature = "inject-panic")]
#[expect(
    clippy::indexing_slicing,
    reason = "the panic is the point; see ARCH-009 (#9)"
)]
fn audit_injected_panic(bytes: &[u8]) {
    sink(u64::from(bytes[usize::from(bytes.len() > 4)]));
}

//! `kmsrsos` entry point.
//!
//! There is no argv processing here and there never will be (`CFG-007`, #172).
//! Configuration is decided when the binary is built; the single runtime knob
//! is the `KMSRSOS_CONFIG` environment variable, which may only touch settings
//! that cannot change a byte on the wire (`CFG-002`, #167).

fn main() {
    eprintln!(
        "{} — listener not yet implemented (NET-001, #150)",
        kmsrs_server::PRODUCT_NAME
    );
}

//! Failures the policy layer can report.

/// The entropy source failed, so the host must not serve (`OS-012`, #263).
///
/// Carries no detail, for the same reason `kmsrs_proto::entropy`'s equivalent
/// does not: there is no variant of this a caller should recover from and
/// continue, and a reason string would invite a `match` that tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyUnavailable;

impl core::fmt::Display for EntropyUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the entropy source failed; refusing to serve")
    }
}

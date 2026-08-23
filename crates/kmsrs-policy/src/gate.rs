//! The product gate and the activation decision (`POL-010`, #98 …
//! `POL-017`, #105).
//!
//! # Three gates with opposite risk profiles
//!
//! The single most consequential decision in a KMS emulator is what to do with
//! a product it does not recognise, and both existing implementations get it
//! wrong in opposite directions:
//!
//! * **Unknown KMS ID — always activate.** This is why a vlmcsd binary built in
//!   2019 still activates Windows 11: it never asks whether it has heard of the
//!   product. py-kms instead looks the GUID up and crashes when it is missing,
//!   which is the actual mechanism behind every "Server 2022 doesn't work"
//!   report. Refusing here has no upside and breaks every product released
//!   after the build date (`POL-010`, #98; `POL-017`, #105).
//! * **Retail, OEM and evaluation SKUs — refuse.** A retail SKU has no GVLK, so
//!   no legitimate client can present one to a KMS host. Refusing costs
//!   nothing and closes a cheap probe: sending a retail activation ID and
//!   seeing it succeed identifies an emulator in one packet. This is only
//!   viable because the database carries real key types from Microsoft's own
//!   artifacts (`DB-015`, #139) rather than a hand-copied catalogue.
//! * **Application mismatch — refuse.** A client claiming the Windows
//!   application while presenting an Office product is not a client.
//!
//! # What is deliberately not gated here
//!
//! **`WorkstationName` is not authentication** (`POL-015`, #103). It is
//! client-supplied, unvalidated, and trivially forged. Two forks built
//! allowlists on it: one produced a gate that any v6 client bypasses outright,
//! and the other calls `sys.exit(0)` from inside a request handler — taking the
//! whole server down and logging a bind failure as the cause. There is no
//! allowlist here and there will not be one; [`tests::the_workstation_name_is_never_a_gate`]
//! is what keeps it that way.
//!
//! **Clock skew never refuses** (`POL-011`, #99). Microsoft's ±4 hour tolerance
//! is itself a detection oracle: a prober sends two requests four hours apart
//! and concludes "emulator" if both succeed. Permissiveness costs nothing,
//! because the v6 HMAC key derives from the client's own FILETIME — a skewed
//! client still receives a self-consistent response it can verify.
//!
//! # Totality
//!
//! [`evaluate`] returns [`Decision`], which has exactly two variants and no way
//! to spell "no answer" (`POL-016`, #104). One fork's quota check returns
//! `None` into its encrypt path, so a denied request produces no packet at all
//! and the client waits for its timeout instead of being told no.

use crate::counting::{ClientCounts, CountView};
use crate::identity::{GroupIdentity, HostIdentity};
use core::time::Duration;
use kmsrs_db::KeyKind;
use kmsrs_proto::kms::HResult;
use kmsrs_proto::kms::request::Request;
use kmsrs_proto::time::FileTime;
use kmsrs_proto::types::{CsvlkSelection, Intervals};

/// Whether retail, OEM and evaluation SKUs are refused (`POL-010`, #98).
///
/// A build-time flag, not a runtime one — there is no runtime configuration
/// that can change a byte on the wire (`ARCH-003`, #3). On by default: no
/// legitimate client can present a non-volume activation ID, so the gate has no
/// compatibility cost, and leaving it open is a one-packet emulator probe.
pub const REFUSE_NON_VOLUME: bool = !cfg!(feature = "permissive-retail");

/// Whether a clock-skewed request is refused (`POL-011`, #99).
///
/// Off by default, and the default is the anti-fingerprinting choice rather
/// than the lenient one — see the module documentation.
pub const REFUSE_CLOCK_SKEW: bool = cfg!(feature = "strict-clock-skew");

/// How far a client's clock may differ before it is called skewed.
///
/// Microsoft's documented tolerance. Exceeding it is logged either way; whether
/// it is *refused* is [`REFUSE_CLOCK_SKEW`].
pub const CLOCK_SKEW_TOLERANCE: Duration = Duration::from_hours(4);

/// Why a request was refused.
///
/// Every variant names a condition a legitimate client cannot produce. That is
/// the test each one had to pass to exist at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The activation ID names a retail, OEM or evaluation SKU
    /// (`POL-010`, #98).
    ///
    /// Such a SKU has no GVLK, so presenting one is a probe rather than an
    /// activation attempt.
    NonVolumeProduct {
        /// What the database says the key type is.
        kind: KeyKind,
    },

    /// The application GUID does not match the product's (`POL-010`, #98).
    ApplicationMismatch,

    /// The client's clock is outside tolerance and this build refuses that
    /// (`POL-011`, #99).
    ClockSkew {
        /// How far off it is.
        skew: Duration,
    },
}

impl Refusal {
    /// The HRESULT to answer with.
    ///
    /// Always a KMS-level error in a well-formed response, never a dropped
    /// connection: a silent drop is both a worse client experience and a
    /// stronger fingerprint than a refusal (`POL-016`, #104).
    #[must_use]
    pub const fn hresult(self) -> HResult {
        match self {
            Self::NonVolumeProduct { .. } | Self::ApplicationMismatch => {
                HResult::NotSupportedByKmsServer
            }
            Self::ClockSkew { .. } => HResult::TimestampDiffers,
        }
    }
}

/// An activation this host will grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant<'a> {
    /// The identity to answer as — which host key, with its ePID and hardware
    /// ID (`ID-002`, #107).
    pub identity: &'a GroupIdentity,
    /// Which host key was chosen, and whether it was resolved or fallen back to
    /// (`POL-017`, #105).
    pub selection: CsvlkSelection,
    /// What the client-count model computed for this request (`POL-001`, #89).
    pub counts: CountView,
    /// What to tell the client about retrying and renewing (`KMS-021`, #37).
    pub intervals: Intervals,
}

/// What this host will do about a request (`POL-016`, #104).
///
/// Total by construction: two variants, both of which produce a response. There
/// is no `None`, no "drop it", and no path out of [`evaluate`] that does not
/// name one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision<'a> {
    /// Activate.
    Grant(Grant<'a>),
    /// Answer with an error.
    Refuse(Refusal),
}

/// Everything about a request that is worth logging whichever way it went
/// (`POL-011`, #99; `POL-017`, #105).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observations {
    /// Whether the database has heard of this product.
    ///
    /// `false` is normal and is never a refusal — it is a product newer than
    /// this build. What it does mean is that the event log should carry the raw
    /// GUID, so an operator can see which unknown product asked
    /// (`POL-017`, #105).
    pub known_product: bool,
    /// How far the client's clock is from this host's, if a host clock was
    /// supplied.
    pub clock_skew: Option<Duration>,
    /// Whether that skew is outside Microsoft's ±4 hour tolerance.
    pub clock_skewed: bool,
}

/// Decide what to do with a decoded request, and count it.
///
/// `host_time` is the host's wall clock and is used **only** to measure skew
/// for the log. Nothing in the response derives from it — the v6 key schedule
/// derives from the client's own timestamp, which is why this server needs no
/// accurate clock (`ARCH-004`, #4). Pass `None` on a platform without one.
///
/// The counting model is consulted for granted requests only. A refused request
/// is not a client of this host, so admitting it to the table would let a
/// prober inflate the count it is trying to measure.
pub fn evaluate<'a>(
    request: &Request,
    identity: &'a HostIdentity,
    counts: &mut ClientCounts,
    now: kmsrs_proto::time::Instant,
    host_time: Option<FileTime>,
) -> (Decision<'a>, Observations) {
    let product = kmsrs_db::product(request.counted.0);

    let clock_skew = host_time.map(|host| host.abs_difference(request.client_time.0));
    let clock_skewed = clock_skew.is_some_and(|skew| skew > CLOCK_SKEW_TOLERANCE);

    let observations = Observations {
        known_product: product.is_some() || kmsrs_db::is_known_counted_id(request.counted.0),
        clock_skew,
        clock_skewed,
    };

    // Gate one: a non-volume SKU has no GVLK, so no legitimate client can
    // present one (`POL-010`, #98). Unknown products skip this entirely — that
    // is the whole point of the split.
    if REFUSE_NON_VOLUME
        && let Some(entry) = product
        && !entry.kind.is_volume()
    {
        return (
            Decision::Refuse(Refusal::NonVolumeProduct { kind: entry.kind }),
            observations,
        );
    }

    // Gate two: the application must match the product's, when the database
    // knows both. A client claiming Windows while presenting Office is not a
    // client (`POL-010`, #98).
    if let Some(entry) = product
        && let Some(application) = entry.application
        && application != request.application.0
    {
        return (Decision::Refuse(Refusal::ApplicationMismatch), observations);
    }

    // Gate three: skew is logged always and refused only if this build says so
    // (`POL-011`, #99).
    if REFUSE_CLOCK_SKEW
        && let Some(skew) = clock_skew
        && clock_skewed
    {
        return (Decision::Refuse(Refusal::ClockSkew { skew }), observations);
    }

    // Unknown products reach here and activate, resolving to a fallback host
    // key within the application they claimed (`POL-017`, #105).
    let (selection, group) = identity.select(request.application, request.counted);
    let view = counts.observe(
        request.application,
        request.client_machine_id,
        request.required_clients,
        now,
    );

    (
        Decision::Grant(Grant {
            identity: group,
            selection,
            counts: view,
            intervals: Intervals::DEFAULT,
        }),
        observations,
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        clippy::duration_suboptimal_units,
        clippy::expect_used,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        CLOCK_SKEW_TOLERANCE, ClientCounts, Decision, HostIdentity, REFUSE_NON_VOLUME, Refusal,
        evaluate,
    };
    use core::time::Duration;
    use kmsrs_db::{Guid, KeyKind};
    use kmsrs_proto::entropy::testing::DeterministicEntropy;
    use kmsrs_proto::kms::HResult;
    use kmsrs_proto::kms::request::Request;
    use kmsrs_proto::kms::status::LicenseStatus;
    use kmsrs_proto::kms::version::ProtocolVersion;
    use kmsrs_proto::time::{FileTime, Instant};
    use kmsrs_proto::types::{
        ApplicationId, ClientKind, ClientMachineId, ClientTime, CsvlkSelection, GraceMinutes,
        KmsCountedId, RequiredClients, SkuId, WorkstationName,
    };

    fn workstation(name: &str) -> WorkstationName {
        let mut field = [0_u16; kmsrs_proto::types::WORKSTATION_NAME_UNITS];
        for (slot, unit) in field.iter_mut().zip(name.encode_utf16()) {
            *slot = unit;
        }
        WorkstationName::decode(&field)
    }

    fn identity() -> HostIdentity {
        let mut entropy = DeterministicEntropy::from_seed(0x5eed);
        HostIdentity::generate(&mut entropy, kmsrs_db::Date::new(2026, 8, 1).unwrap()).unwrap()
    }

    /// A request for the first product in the database with a given key kind,
    /// so the fixtures track the real data rather than a hand-written GUID.
    fn product_of_kind(kind: KeyKind) -> &'static kmsrs_db::Product {
        kmsrs_db::PRODUCTS
            .iter()
            .find(|entry| entry.kind == kind && entry.application.is_some())
            .unwrap()
    }

    fn request_for(application: Guid, counted: Guid) -> Request {
        Request {
            version: ProtocolVersion { major: 6, minor: 0 },
            client_kind: ClientKind::VirtualMachine,
            license_status: LicenseStatus::Unlicensed,
            grace: GraceMinutes(0),
            application: ApplicationId(application),
            sku: SkuId(counted),
            counted: KmsCountedId(counted),
            client_machine_id: ClientMachineId(Guid::from_bytes([0x11; 16])),
            required_clients: RequiredClients(25),
            client_time: ClientTime(FileTime::from_ticks(133_000_000_000_000_000)),
            previous_client_machine_id: None,
            workstation_name: workstation("host.example"),
        }
    }

    fn at(seconds: u64) -> Instant {
        Instant::from_nanos(seconds * 1_000_000_000)
    }

    /// `POL-010` (#98) and `POL-017` (#105). This is the single most important
    /// behaviour in the file: it is why a 2019-era vlmcsd still activates
    /// Windows 11, and refusing here is what makes py-kms fail on Server 2022.
    #[test]
    fn a_product_this_build_has_never_heard_of_activates() {
        let identity = identity();
        let mut counts = ClientCounts::new();

        // A GUID that is in no table, under a real application.
        let application = kmsrs_db::APPLICATIONS.first().unwrap().guid;
        let unknown = Guid::from_bytes([0xAB; 16]);
        assert!(kmsrs_db::product(unknown).is_none());
        assert!(!kmsrs_db::is_known_counted_id(unknown));

        let request = request_for(application, unknown);
        let (decision, observed) = evaluate(&request, &identity, &mut counts, at(0), None);

        let Decision::Grant(grant) = decision else {
            panic!("an unknown product must activate: {decision:?}");
        };
        assert!(
            matches!(grant.selection, CsvlkSelection::Fallback { .. }),
            "and must fall back rather than resolve"
        );
        assert_eq!(grant.counts.reported, 25);
        assert!(
            !observed.known_product,
            "logged as unknown so the raw GUID reaches the event log"
        );
    }

    /// A product the database does know resolves to a real host key.
    #[test]
    fn a_known_product_resolves_and_activates() {
        let identity = identity();
        let mut counts = ClientCounts::new();

        let counted = kmsrs_db::COUNTED_IDS.first().unwrap().guid;
        let product = kmsrs_db::product(counted);
        let application = product
            .and_then(|entry| entry.application)
            .unwrap_or_else(|| kmsrs_db::APPLICATIONS.first().unwrap().guid);

        let request = request_for(application, counted);
        let (decision, observed) = evaluate(&request, &identity, &mut counts, at(0), None);

        assert!(matches!(decision, Decision::Grant(_)), "{decision:?}");
        assert!(observed.known_product);
        if let Decision::Grant(grant) = decision {
            assert!(matches!(grant.selection, CsvlkSelection::Resolved { .. }));
        }
    }

    /// `POL-010` (#98): a retail SKU has no GVLK, so presenting one is a probe.
    /// Refusing costs nothing and closes it.
    ///
    /// The gate is a build-time flag, so this test describes the default build
    /// and [`a_non_volume_sku_activates_when_the_gate_is_open`] describes the
    /// other one. Both are run in CI.
    #[cfg(not(feature = "permissive-retail"))]
    #[test]
    fn a_non_volume_sku_is_refused() {
        assert!(REFUSE_NON_VOLUME);
        let identity = identity();
        let mut counts = ClientCounts::new();

        for kind in [
            KeyKind::Retail,
            KeyKind::OriginalEquipment,
            KeyKind::Evaluation,
        ] {
            let product = product_of_kind(kind);
            let request = request_for(product.application.unwrap(), product.activation_id);
            let (decision, _) = evaluate(&request, &identity, &mut counts, at(0), None);

            assert_eq!(
                decision,
                Decision::Refuse(Refusal::NonVolumeProduct { kind }),
                "{kind:?} must be refused"
            );
            assert_eq!(
                Refusal::NonVolumeProduct { kind }.hresult(),
                HResult::NotSupportedByKmsServer
            );
        }

        // And a refused probe must not enter the count it is trying to measure.
        assert_eq!(counts.applications().count(), 0);
    }

    /// A GVLK is the only key type a legitimate client has, and it must pass.
    #[test]
    fn a_volume_client_key_is_not_caught_by_the_retail_gate() {
        let identity = identity();
        let mut counts = ClientCounts::new();

        let product = product_of_kind(KeyKind::KmsClient);
        let request = request_for(product.application.unwrap(), product.activation_id);
        let (decision, _) = evaluate(&request, &identity, &mut counts, at(0), None);
        assert!(matches!(decision, Decision::Grant(_)), "{decision:?}");
    }

    /// `POL-010` (#98): a client claiming Windows while presenting Office is
    /// not a client.
    #[test]
    fn an_application_mismatch_is_refused() {
        let identity = identity();
        let mut counts = ClientCounts::new();

        let product = product_of_kind(KeyKind::KmsClient);
        let its_application = product.application.unwrap();
        let other = kmsrs_db::APPLICATIONS
            .iter()
            .find(|entry| entry.guid != its_application)
            .unwrap();

        let request = request_for(other.guid, product.activation_id);
        let (decision, _) = evaluate(&request, &identity, &mut counts, at(0), None);
        assert_eq!(decision, Decision::Refuse(Refusal::ApplicationMismatch));
    }

    /// `POL-011` (#99). Microsoft's ±4h tolerance is itself the detection
    /// oracle: a prober sends two requests four hours apart and concludes
    /// "emulator" if both succeed. The default build activates both and logs.
    #[cfg(not(feature = "strict-clock-skew"))]
    #[test]
    fn a_skewed_clock_activates_and_is_logged() {
        let identity = identity();
        let mut counts = ClientCounts::new();

        let application = kmsrs_db::APPLICATIONS.first().unwrap().guid;
        let request = request_for(application, Guid::from_bytes([0xAB; 16]));

        // Twelve hours out, three times the documented tolerance.
        let host_time = request
            .client_time
            .0
            .checked_add(Duration::from_hours(12))
            .unwrap();
        let (decision, observed) =
            evaluate(&request, &identity, &mut counts, at(0), Some(host_time));

        assert!(
            matches!(decision, Decision::Grant(_)),
            "a skewed client must still activate: {decision:?}"
        );
        assert!(observed.clock_skewed, "and the skew must reach the log");
        assert_eq!(observed.clock_skew, Some(Duration::from_hours(12)));
    }

    /// Skew inside the tolerance is not even flagged.
    #[test]
    fn a_clock_inside_tolerance_is_not_flagged() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let application = kmsrs_db::APPLICATIONS.first().unwrap().guid;
        let request = request_for(application, Guid::from_bytes([0xAB; 16]));

        let host_time = request
            .client_time
            .0
            .checked_add(CLOCK_SKEW_TOLERANCE.saturating_sub(Duration::from_secs(1)))
            .unwrap();
        let (_, observed) = evaluate(&request, &identity, &mut counts, at(0), Some(host_time));
        assert!(!observed.clock_skewed);

        // A platform with no wall clock reports no skew rather than zero skew.
        let (_, observed) = evaluate(&request, &identity, &mut counts, at(0), None);
        assert_eq!(observed.clock_skew, None);
        assert!(!observed.clock_skewed);
    }

    /// `POL-015` (#103). The field is client-supplied and trivially forged. Two
    /// forks built allowlists on it: one is bypassed by any v6 client, the
    /// other calls `sys.exit(0)` from a request handler and blames a bind
    /// failure in the log. This test is the thing that keeps such a gate from
    /// being added later.
    #[test]
    fn the_workstation_name_is_never_a_gate() {
        let identity = identity();
        let application = kmsrs_db::APPLICATIONS.first().unwrap().guid;
        let counted = Guid::from_bytes([0xAB; 16]);

        let mut outcomes = alloc::vec::Vec::new();
        for name in ["", "host.example", "EVIL", "\u{202e}spoofed", "a"] {
            let mut counts = ClientCounts::new();
            let mut request = request_for(application, counted);
            request.workstation_name = workstation(name);
            let (decision, _) = evaluate(&request, &identity, &mut counts, at(0), None);
            outcomes.push(matches!(decision, Decision::Grant(_)));
        }
        assert!(
            outcomes.iter().all(|granted| *granted),
            "no workstation name may change the decision: {outcomes:?}"
        );
    }

    /// `POL-016` (#104): every path out of `evaluate` names a response. One
    /// fork returns `None` into its encrypt path here, so a denied client waits
    /// for a timeout instead of being told no.
    #[test]
    fn every_decision_carries_a_response() {
        let identity = identity();
        let application = kmsrs_db::APPLICATIONS.first().unwrap().guid;

        // A spread of requests that exercise grant, both refusals, and the
        // unknown-product path.
        let cases = [
            Guid::from_bytes([0xAB; 16]),
            product_of_kind(KeyKind::KmsClient).activation_id,
            product_of_kind(KeyKind::Retail).activation_id,
            Guid::ZERO,
        ];
        for counted in cases {
            let mut counts = ClientCounts::new();
            let request = request_for(application, counted);
            let (decision, _) = evaluate(&request, &identity, &mut counts, at(0), None);
            let hresult = match decision {
                Decision::Grant(_) => HResult::Ok,
                Decision::Refuse(refusal) => refusal.hresult(),
            };
            // The point is that the match is exhaustive and every arm produces
            // a value — a refusal is an answer, not a silence.
            assert!(
                hresult == HResult::Ok || !hresult.is_ok(),
                "{counted:?} produced no answer"
            );
        }
    }

    /// The gate and the counting model compose: repeated activations of an
    /// unknown product still saturate, and refusals never contribute.
    #[test]
    fn granted_requests_count_and_refused_ones_do_not() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let application = kmsrs_db::APPLICATIONS.first().unwrap().guid;
        let unknown = Guid::from_bytes([0xAB; 16]);
        let retail = product_of_kind(KeyKind::Retail);

        for number in 0..60_u8 {
            let mut request = request_for(application, unknown);
            request.client_machine_id = ClientMachineId(Guid::from_bytes([number; 16]));
            evaluate(&request, &identity, &mut counts, at(0), None);

            // Interleave probes, which must leave the count alone.
            let mut probe = request_for(retail.application.unwrap(), retail.activation_id);
            probe.client_machine_id = ClientMachineId(Guid::from_bytes([!number; 16]));
            evaluate(&probe, &identity, &mut counts, at(0), None);
        }

        assert_eq!(counts.cached_for(ApplicationId(application)), 60);
        let mut request = request_for(application, unknown);
        request.client_machine_id = ClientMachineId(Guid::from_bytes([0xF0; 16]));
        let (decision, _) = evaluate(&request, &identity, &mut counts, at(0), None);
        let Decision::Grant(grant) = decision else {
            panic!("{decision:?}");
        };
        assert_eq!(grant.counts.reported, 50, "saturated, probes excluded");
    }

    /// The other side of the `POL-010` (#98) build-time flag: with the gate
    /// open a non-volume SKU activates like anything else. Tested so that
    /// flipping the flag is a supported configuration rather than an untried
    /// one.
    #[cfg(feature = "permissive-retail")]
    #[test]
    fn a_non_volume_sku_activates_when_the_gate_is_open() {
        assert!(!REFUSE_NON_VOLUME);
        let identity = identity();
        let mut counts = ClientCounts::new();

        let product = product_of_kind(KeyKind::Retail);
        let request = request_for(product.application.unwrap(), product.activation_id);
        let (decision, _) = evaluate(&request, &identity, &mut counts, at(0), None);
        assert!(matches!(decision, Decision::Grant(_)), "{decision:?}");
    }

    /// `POL-011` (#99) strict mode. Off by default because the tolerance is a
    /// detection oracle, but a deployment that wants Microsoft's behaviour byte
    /// for byte can have it, and that configuration is tested rather than
    /// merely offered.
    #[cfg(feature = "strict-clock-skew")]
    #[test]
    fn strict_mode_refuses_a_skewed_clock() {
        use super::{CLOCK_SKEW_TOLERANCE, REFUSE_CLOCK_SKEW};
        assert!(REFUSE_CLOCK_SKEW);
        let identity = identity();
        let mut counts = ClientCounts::new();

        let application = kmsrs_db::APPLICATIONS.first().unwrap().guid;
        let request = request_for(application, Guid::from_bytes([0xAB; 16]));
        let skew = Duration::from_hours(12);
        let host_time = request.client_time.0.checked_add(skew).unwrap();

        let (decision, observed) =
            evaluate(&request, &identity, &mut counts, at(0), Some(host_time));
        assert_eq!(decision, Decision::Refuse(Refusal::ClockSkew { skew }));
        assert_eq!(
            Refusal::ClockSkew { skew }.hresult(),
            HResult::TimestampDiffers
        );
        assert!(observed.clock_skewed);

        // Inside the tolerance it still activates, even in strict mode.
        let host_time = request
            .client_time
            .0
            .checked_add(CLOCK_SKEW_TOLERANCE.saturating_sub(Duration::from_secs(1)))
            .unwrap();
        let (decision, _) = evaluate(&request, &identity, &mut counts, at(0), Some(host_time));
        assert!(matches!(decision, Decision::Grant(_)), "{decision:?}");
    }
}

//! Extraction of product data from Microsoft `pkeyconfig` artifacts
//! (`ARCH-001`, #1; `DB-001`, #125).
//!
//! # Why this is a separate crate
//!
//! Extraction needs base64, gzip, tar, CAB, an XML parser and an HTTP client.
//! None of that has any business being reachable from a server that has no disk
//! I/O and parses nothing but its own wire protocol. Keeping the extractor in
//! its own crate, depended on by nothing the binary depends on, makes
//! "unreachable" a property of the dependency graph that CI can check rather
//! than a claim in a comment — see `dbgen_is_unreachable_from_every_shipped_binary`
//! in `crates/kmsrs-server/tests/workspace_invariants.rs`.
//!
//! # What it resolves
//!
//! The CSVLK data that vlmcsd, License Manager and py-kms disagree about is not
//! adjudicated here — it is resolved *above* all three, by reading what
//! Microsoft signs and ships. `RefGroupId`, `Start`, `End` and `PartNumber` are
//! all present in `pkeyconfig`, and the real KMS counted IDs are in
//! `Security-SPP-KmsCountedIdList`. The common assumption that Microsoft does
//! not publish this is wrong; it publishes it, just not in prose.
//!
//! The output is a reviewable, provenance-stamped TOML file that is committed to
//! the tree (`DB-002`, #126). `kmsrs-db`'s `build.rs` compiles that file into
//! `static` tables; it does not run this crate, so builds stay hermetic.

pub mod emit;
pub mod error;
pub mod extract;
pub mod fetch;
pub mod guid;
pub mod model;
pub mod xrm;

/// The generator's own version stamp, recorded in every file it emits so that a
/// regenerated data file can be attributed to the code that produced it
/// (`DB-002`, #126).
pub const GENERATOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where an artifact source comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A public container image, streamed from a registry.
    ContainerImage {
        /// `host/repository:tag`.
        reference: &'static str,
    },
    /// A public download, which for the Office packs is a self-extracting
    /// executable wrapped around a CAB.
    Download {
        /// The direct URL.
        url: &'static str,
    },
}

impl Origin {
    /// The origin as it is written into the provenance stamp.
    #[must_use]
    pub fn as_text(self) -> &'static str {
        match self {
            Self::ContainerImage { reference } => reference,
            Self::Download { url } => url,
        }
    }
}

/// One artifact source the pipeline knows how to fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactSource {
    /// Directory name and provenance identifier.
    pub id: &'static str,
    /// What the source is, in prose.
    pub description: &'static str,
    /// Where to get it.
    pub origin: Origin,
}

/// The sources the product database is built from.
///
/// Adding a source is a reviewable change to this list, which is the point: the
/// alternative is a shell script somebody ran once.
pub const SOURCES: &[ArtifactSource] = &[
    ArtifactSource {
        id: "windows-server-2025",
        description: "Windows Server 2025 (build 26100) Software Protection Platform tokens",
        origin: Origin::ContainerImage {
            reference: "mcr.microsoft.com/windows/servercore:ltsc2025",
        },
    },
    ArtifactSource {
        id: "office-ltsc-2024",
        description: "Microsoft Office LTSC 2024 Volume License Pack (16.0.17830.20004)",
        origin: Origin::Download {
            url: "https://download.microsoft.com/download/1/4/0/140c97ae-7360-4dfc-9ba0-5f509600a06e/Office2024VolumeLicensePack_x64.exe",
        },
    },
];

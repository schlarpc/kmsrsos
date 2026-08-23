//! Which build this is (`CFG-008`, #173).
//!
//! Three facts: the version, the revision it was built from, and the source
//! date. Together they answer the only question an operator has when a bug
//! report and a running process have to be matched up — *is this the binary I
//! think it is* — and they answer it without a `--version` flag, because this
//! program takes no arguments (`CFG-007`, #172). They appear on the status page
//! and in `/metrics`, which is where an operator already is.
//!
//! # Why none of them is read at build time
//!
//! There is no build script here, and nothing shells out to `git`. Every value
//! arrives through `option_env!`, so it is a compile-time constant supplied by
//! whatever built the binary — `flake.nix` passes the flake's own revision and
//! `lastModified`, which are already pinned facts about the source rather than
//! facts about the machine that happened to run the build.
//!
//! That is the whole content of `CFG-008`. vlmcsd bakes `date +%s` into every
//! build, so two builds of one revision differ, and no release is reproducible.
//! It is worse than cosmetic there: the timestamp is *load-bearing*, being the
//! upper bound of the randomised ePID activation date, so vlmcsd's identity
//! depends on when it was compiled. Here the equivalent bound is the wall clock
//! read once at start-up (`ID-007`, #112), which is a property of the run rather
//! than of the build.
//!
//! # Unknown is a value
//!
//! A `cargo build` in a checkout has no revision to report and says so, rather
//! than guessing or refusing. The stamp is diagnostic; a binary that will not
//! start because nobody set an environment variable would be a worse failure
//! than an unlabelled one.

/// The crate version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What a field says when whatever built this binary did not supply it.
pub const UNKNOWN: &str = "unknown";

/// The source revision, if the build supplied one.
///
/// `flake.nix` passes `self.rev` — the flake's own locked revision — or
/// `self.dirtyRev` for a working tree with uncommitted changes, which is
/// suffixed `-dirty` by Nix and is worth reporting *as* dirty rather than as
/// the commit it is nearly.
pub const REVISION: &str = match option_env!("KMSRSOS_GIT_COMMIT") {
    Some(revision) => revision,
    None => UNKNOWN,
};

/// The source date as a Unix timestamp, if the build supplied one.
///
/// `SOURCE_DATE_EPOCH` is the reproducible-builds convention, and the flake
/// passes `self.lastModified`. It is deliberately the *source* date and not the
/// build date: the point is that two builds of one revision agree.
pub const SOURCE_DATE_EPOCH: &str = match option_env!("SOURCE_DATE_EPOCH") {
    Some(seconds) => seconds,
    None => UNKNOWN,
};

/// Everything about which build this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildStamp {
    /// The crate version.
    pub version: &'static str,
    /// The source revision, or [`UNKNOWN`].
    pub revision: &'static str,
    /// The source date in seconds since the Unix epoch, or [`UNKNOWN`].
    pub source_date_epoch: &'static str,
}

/// This binary's stamp.
pub const BUILD: BuildStamp = BuildStamp {
    version: VERSION,
    revision: REVISION,
    source_date_epoch: SOURCE_DATE_EPOCH,
};

impl BuildStamp {
    /// The revision, shortened the way a person reads one.
    ///
    /// Full hashes are for machines; `/metrics` carries the whole thing. Twelve
    /// characters is git's own long-form abbreviation and is unambiguous for
    /// any repository this will ever be.
    #[must_use]
    pub fn short_revision(&self) -> &'static str {
        /// How many characters of a revision a person reads.
        const SHORT: usize = 12;

        if self.revision == UNKNOWN {
            return UNKNOWN;
        }
        // A dirty revision is `<hash>-dirty`, and truncating it to twelve
        // characters would silently drop the part that matters most.
        if self.revision.len() > SHORT && !self.revision.contains("dirty") {
            self.revision.get(..SHORT).unwrap_or(self.revision)
        } else {
            self.revision
        }
    }

    /// Whether every field was supplied.
    ///
    /// False for an ordinary `cargo build`, which has no revision to report.
    /// Used by the release check rather than by anything that runs: an
    /// unlabelled binary still serves.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.revision != UNKNOWN && self.source_date_epoch != UNKNOWN
    }
}

impl core::fmt::Display for BuildStamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} ({}, source date {})",
            self.version,
            self.short_revision(),
            self.source_date_epoch
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{BUILD, BuildStamp, UNKNOWN, VERSION};

    #[test]
    fn the_version_is_the_crates_own() {
        assert_eq!(BUILD.version, VERSION);
        assert!(!BUILD.version.is_empty());
        // Not a placeholder: this reaches the status page.
        assert!(BUILD.version.contains('.'), "{}", BUILD.version);
    }

    /// A build that was given nothing says so, rather than guessing.
    ///
    /// This is the ordinary `cargo build` case, which is what CI runs the test
    /// suite under, so it is also the case this test observes.
    #[test]
    fn an_unstamped_build_reports_unknown_rather_than_inventing_one() {
        let stamp = BuildStamp {
            version: "0.1.0",
            revision: UNKNOWN,
            source_date_epoch: UNKNOWN,
        };
        assert_eq!(stamp.short_revision(), UNKNOWN);
        assert!(!stamp.is_complete());
        assert!(stamp.to_string().contains(UNKNOWN));
    }

    /// A revision is shortened for reading, and `/metrics` keeps the whole one.
    #[test]
    fn a_revision_is_shortened_the_way_a_person_reads_one() {
        let stamp = BuildStamp {
            version: "0.1.0",
            revision: "0123456789abcdef0123456789abcdef01234567",
            source_date_epoch: "1700000000",
        };
        assert_eq!(stamp.short_revision(), "0123456789ab");
        assert!(stamp.is_complete());
    }

    /// A dirty revision keeps its suffix. Truncating it would drop the part
    /// that matters most — that this binary was not built from a commit.
    #[test]
    fn a_dirty_revision_is_not_truncated_into_looking_clean() {
        let stamp = BuildStamp {
            version: "0.1.0",
            revision: "0123456789abcdef0123456789abcdef01234567-dirty",
            source_date_epoch: "1700000000",
        };
        assert!(stamp.short_revision().ends_with("-dirty"), "{stamp}");
    }

    /// `CFG-008` (#173): the source date, not the build date.
    ///
    /// vlmcsd bakes `date +%s` into every build, so two builds of one revision
    /// differ — and the value is load-bearing there, being the upper bound of
    /// its randomised ePID activation date. Nothing here reads a clock at
    /// compile time, which is what makes two builds identical.
    #[test]
    fn nothing_here_reads_a_clock() {
        let source = include_str!("stamp.rs");
        // Everything above the test module: this test names the very APIs it
        // forbids, so scanning itself would be scanning the wrong thing.
        let module = source.split("#[cfg(test)]").next().unwrap_or(source);
        let code: String = module
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for reader in [
            "SystemTime",
            "Instant::now",
            "std::process::Command",
            "date +%s",
        ] {
            assert!(
                !code.contains(reader),
                "{reader} would make two builds of one revision differ"
            );
        }
    }
}

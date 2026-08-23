//! The extracted product database, before it is written out (`DB-002`, #126).
//!
//! Every row carries the identifier of the [`Source`] it came from. That is the
//! substance of the "provenance-stamped" requirement: a reviewer looking at a
//! pull request that changes a key range can see which artifact changed, and a
//! row whose source is not a Microsoft artifact is visibly different from one
//! that is.

use crate::guid::Guid;

/// An artifact the data was extracted from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Short identifier, referenced by every row this artifact produced.
    pub id: String,
    /// What the artifact is, in prose.
    pub description: String,
    /// Where it came from, precisely enough to fetch again.
    pub origin: String,
    /// SHA-256 over every artifact in the source, and their relative paths.
    pub sha256: String,
    /// The application every product in this source belongs to.
    ///
    /// A `pkeyconfig` document names no application, so this is the one
    /// inference the pipeline makes: a Windows image's product table is about
    /// Windows and an Office pack's is about Office. It is recorded here, on the
    /// source, rather than copied silently onto each product row — so a reviewer
    /// can see that it was inferred and from what. If a source's licences named
    /// more than one application the inference would be unsound, and extraction
    /// stops instead.
    pub application: Option<Guid>,
}

/// A KMS application: Windows, Office 2010, or Office 2013 and later.
///
/// Three values, fixed for the life of the protocol. They are extracted rather
/// than hardcoded because extracting them costs nothing and proves the artifact
/// says what we think it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    /// The application GUID a client sends.
    pub guid: Guid,
    /// Human-readable name (`DB-014`, #138).
    pub name: String,
    /// Which [`Source`] this came from.
    pub source: String,
}

/// One block of a CSVLK's key range (`ID-019`, #124).
///
/// Ranges are a *set of blocks*, not a minimum and a maximum. Windows Server
/// 2022's CSVLK has two valid blocks — `0..=19999` and `30000..=20029999` — with
/// an invalid hole at `20000..=29999`. py-kms models the same CSVLK as
/// `MinKeyId = 0, MaxKeyId = 20029999`, so it can emit a key ID inside the hole,
/// which is a value no genuine host would ever produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    /// Microsoft's part number for the block, kept for traceability.
    pub part_number: String,
    /// First key ID in the block, inclusive.
    pub start: u32,
    /// Last key ID in the block, inclusive.
    pub end: u32,
}

/// One product key configuration (`DB-007`, #131; `DB-015`, #139).
///
/// This is a faithful transcription of a `pkeyconfig` `<Configuration>`, joined
/// to its KMS host licence where one exists. It covers every key type Microsoft
/// ships — `Volume:CSVLK`, `Volume:GVLK`, `Volume:MAK`, `Retail`, the several
/// `OEM:` kinds, and the evaluation types — not only the CSVLKs, because the
/// distinction between them is what the product gate is built on (`POL-010`,
/// #98) and because a row that exists in the artifact and not here is a row
/// somebody will later re-derive by hand.
///
/// Interpretation happens in `kmsrs-db`'s `build.rs`, which partitions these
/// into the typed tables the server uses. Keeping this file a transcription
/// rather than an interpretation is what makes it reviewable against the
/// artifact it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product {
    /// `ActConfigId`, which is also the licence's `productSkuId`. This is the
    /// join key between the two artifact families, and it is what a client
    /// sends as the request's `ActID` — a field a KMS host reads and then
    /// ignores (`KMS-018`, #34).
    pub activation_id: Guid,
    /// The group ID that appears in a generated ePID (`ID-003`, #108).
    pub group_id: u32,
    /// Microsoft's edition identifier.
    pub edition_id: String,
    /// Microsoft's product description.
    pub description: String,
    /// `Volume:CSVLK`, `Volume:MAK`, `Retail`, and so on. The product gate
    /// treats retail and preview differently from volume (`POL-010`, #98).
    pub key_type: String,
    /// Valid key-ID blocks, sorted and non-overlapping.
    pub key_blocks: Vec<KeyBlock>,
    /// The application this product belongs to.
    ///
    /// Taken from the licence when one names it, and otherwise from the
    /// source's inferred application. See [`Source::application`].
    pub application: Option<Guid>,
    /// The KMS counted IDs a host holding this key will count (`DB-008`, #132).
    ///
    /// Empty for everything that is not a CSVLK. This is the field the server
    /// actually decides on: a request's `KMSID` is what grants or refuses
    /// activation, while its `ActID` is ignored.
    pub counted_ids: Vec<Guid>,
    /// The CMID cache lifetime this product declares, in minutes
    /// (`POL-003`, #91).
    pub cmid_expiration_minutes: Option<u32>,
    /// Which [`Source`] the pkeyconfig half came from.
    pub source: String,
    /// Which [`Source`] the licence half came from, if one was found.
    pub licence_source: Option<String>,
}

/// The whole extracted database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Database {
    /// Artifacts, in the order they were read.
    pub sources: Vec<Source>,
    /// Application GUIDs.
    pub applications: Vec<Application>,
    /// Product key configurations.
    pub products: Vec<Product>,
}

impl Database {
    /// Sort every table into a stable order.
    ///
    /// The output file is committed and reviewed as a diff, so row order must
    /// be a function of the data rather than of directory iteration order. A
    /// regeneration that reorders a hundred rows hides the one row that
    /// actually changed.
    pub fn sort(&mut self) {
        self.sources.sort_by(|a, b| a.id.cmp(&b.id));
        self.applications
            .sort_by_key(|application| application.guid);
        self.products.sort_by(|a, b| {
            a.group_id
                .cmp(&b.group_id)
                .then_with(|| a.activation_id.cmp(&b.activation_id))
        });
        for product in &mut self.products {
            // A Windows image carries the same pkeyconfig document in three
            // places — System32, SysWOW64 and a WinSxS component directory — so
            // every key range is read three times. Identical blocks are the
            // same block; overlapping ones would not be, which is why this
            // deduplicates rather than merges, and why `kmsrs-db`'s build still
            // rejects a genuine overlap.
            product.key_blocks.sort_by(|a, b| {
                a.start
                    .cmp(&b.start)
                    .then_with(|| a.end.cmp(&b.end))
                    .then_with(|| a.part_number.cmp(&b.part_number))
            });
            product.key_blocks.dedup();
            product.counted_ids.sort_unstable();
            product.counted_ids.dedup();
        }
    }
}

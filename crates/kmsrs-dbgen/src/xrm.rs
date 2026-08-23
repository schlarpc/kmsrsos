//! Reading Microsoft's XrML licensing artifacts (`DB-001`, #125).
//!
//! Two artifact families matter, and they join on one field:
//!
//! * **`pkeyconfig*.xrm-ms`** carries a base64-encoded, sometimes gzipped
//!   `ProductKeyConfiguration` document in a `<tm:infoBin name="pkeyConfigData">`
//!   element. That document holds `RefGroupId`, `Start`, `End` and `PartNumber`
//!   per CSVLK.
//! * **Licence files** (`csvlk-pack-volume-csvlk-N-pl-rtm.xrm-ms`,
//!   `kmshost2024vl_kms_host-pl.xrm-ms`, …) carry
//!   `Security-SPP-KmsCountedIdList` and the application GUID.
//!
//! The join key is `<tm:infoStr name="productSkuId">`, which holds the same GUID
//! as the pkeyconfig's `ActConfigId`. Finding it there rather than by matching
//! on file names is what makes the extraction principled: `csvlk-2` means
//! nothing, and the number is not stable between images.
//!
//! This is why the vlmcsd / License Manager / py-kms disagreement over CSVLK
//! data does not have to be adjudicated. It is resolved *above* all three, by
//! reading what Microsoft signs and ships.

use crate::error::{Context, Error, Result};
use crate::guid::Guid;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// An artifact read from disk, with its digest.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// Where it was read from.
    pub path: PathBuf,
    /// SHA-256 of the file's bytes, for the provenance stamp.
    pub sha256: String,
    /// The file decoded as text.
    pub text: String,
}

impl Artifact {
    /// Read and decode an `.xrm-ms` file.
    ///
    /// These are XML, but the encoding varies between UTF-8 and UTF-16LE with a
    /// byte-order mark even within one image, so the encoding is detected rather
    /// than assumed.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or is not valid text in
    /// either encoding.
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).context(format!("reading {}", path.display()))?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let text = decode_text(&bytes).context(format!("decoding {}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            sha256,
            text,
        })
    }

    /// The file's base name, for use in messages.
    #[must_use]
    pub fn name(&self) -> String {
        self.path.file_name().map_or_else(
            || self.path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        )
    }
}

/// Decode bytes that may be UTF-8 or UTF-16LE, with or without a BOM.
fn decode_text(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes
            .get(2..)
            .unwrap_or_default()
            .chunks_exact(2)
            .filter_map(|pair| pair.first_chunk::<2>().map(|two| u16::from_le_bytes(*two)))
            .collect();
        return char::decode_utf16(units)
            .collect::<std::result::Result<String, _>>()
            .context("invalid UTF-16");
    }
    let without_bom = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8(without_bom.to_vec()).context("invalid UTF-8")
}

/// One `<Configuration>` from a pkeyconfig document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkeyConfiguration {
    /// `ActConfigId`, the join key.
    pub activation_id: Guid,
    /// `RefGroupId`, the group number that appears in an ePID.
    pub group_id: u32,
    /// `EditionId`.
    pub edition_id: String,
    /// `ProductDescription`.
    pub description: String,
    /// `ProductKeyType`, e.g. `Volume:CSVLK`.
    pub key_type: String,
}

/// One `<KeyRange>` from a pkeyconfig document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkeyKeyRange {
    /// `RefActConfigId`, pointing at a [`PkeyConfiguration`].
    pub activation_id: Guid,
    /// `PartNumber`.
    pub part_number: String,
    /// `IsValid`. Ranges marked invalid are recorded and then dropped.
    pub is_valid: bool,
    /// `Start`, inclusive.
    pub start: u32,
    /// `End`, inclusive.
    pub end: u32,
}

/// The interesting fields of a licence artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Licence {
    /// `productSkuId` — the CSVLK activation ID this licence belongs to.
    pub product_sku_id: Option<Guid>,
    /// `applicationId` — Windows, Office 2010, or Office 2013 and later.
    pub application_id: Option<Guid>,
    /// `Security-SPP-KmsCountedIdList`.
    pub counted_ids: Vec<Guid>,
    /// `Security-SPP-CMIDExpirationPeriod`, in minutes.
    pub cmid_expiration_minutes: Option<u32>,
}

/// Extract and decode the `pkeyConfigData` payload, if the artifact has one.
///
/// The payload is base64, and then *sometimes* gzip: the Windows artifact ships
/// it as plain XML while the Office one gzips it. Both are handled by looking at
/// the magic rather than by trusting the file name.
///
/// # Errors
///
/// Returns an error if the payload is present but cannot be decoded.
pub fn pkeyconfig_payload(text: &str) -> Result<Option<String>> {
    let document = roxmltree::Document::parse(text).context("parsing XrML wrapper")?;
    let Some(node) = document.descendants().find(|node| {
        node.has_tag_name("infoBin") && node.attribute("name") == Some("pkeyConfigData")
    }) else {
        return Ok(None);
    };
    let encoded: String = node
        .text()
        .context("pkeyConfigData element is empty")?
        .split_whitespace()
        .collect();
    let blob = BASE64
        .decode(encoded.as_bytes())
        .context("base64-decoding pkeyConfigData")?;

    let decoded = if blob.starts_with(&[0x1F, 0x8B]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(blob.as_slice())
            .read_to_end(&mut out)
            .context("gunzipping pkeyConfigData")?;
        out
    } else {
        blob
    };
    Ok(Some(
        String::from_utf8(decoded).context("pkeyConfigData is not UTF-8")?,
    ))
}

/// Parse a decoded `ProductKeyConfiguration` document.
///
/// Element names are matched on their local part, because the Windows artifact
/// uses a default namespace and the Office one uses a `pkc:` prefix for the same
/// schema.
///
/// # Errors
///
/// Returns an error on any malformed element rather than skipping it
/// (`DB-006`, #130).
pub fn parse_pkeyconfig(xml: &str) -> Result<(Vec<PkeyConfiguration>, Vec<PkeyKeyRange>)> {
    let document = roxmltree::Document::parse(xml).context("parsing ProductKeyConfiguration")?;

    let mut configurations = Vec::new();
    for node in document
        .descendants()
        .filter(|node| node.has_tag_name("Configuration"))
    {
        let activation =
            child_text(node, "ActConfigId").context("Configuration without ActConfigId")?;
        configurations.push(PkeyConfiguration {
            activation_id: Guid::parse(&activation)
                .context(format!("ActConfigId {activation:?}"))?,
            group_id: child_number(node, "RefGroupId")
                .context(format!("RefGroupId for {activation}"))?,
            edition_id: child_text(node, "EditionId").unwrap_or_default(),
            description: child_text(node, "ProductDescription").unwrap_or_default(),
            key_type: child_text(node, "ProductKeyType").unwrap_or_default(),
        });
    }

    let mut ranges = Vec::new();
    for node in document
        .descendants()
        .filter(|node| node.has_tag_name("KeyRange"))
    {
        let activation =
            child_text(node, "RefActConfigId").context("KeyRange without RefActConfigId")?;
        let start = child_number(node, "Start").context(format!("Start for {activation}"))?;
        let end = child_number(node, "End").context(format!("End for {activation}"))?;
        if end < start {
            return Err(Error::new(format!(
                "key range for {activation} runs backwards: {start}..={end}"
            )));
        }
        ranges.push(PkeyKeyRange {
            activation_id: Guid::parse(&activation)
                .context(format!("RefActConfigId {activation:?}"))?,
            part_number: child_text(node, "PartNumber").unwrap_or_default(),
            is_valid: child_text(node, "IsValid")
                .as_deref()
                .is_none_or(|value| value.eq_ignore_ascii_case("true")),
            start,
            end,
        });
    }

    Ok((configurations, ranges))
}

/// Parse a licence artifact.
///
/// # Errors
///
/// Returns an error if the document is not XML or a GUID field is malformed.
pub fn parse_licence(text: &str) -> Result<Licence> {
    let document = roxmltree::Document::parse(text).context("parsing licence")?;
    let mut licence = Licence::default();

    for node in document.descendants() {
        let name = node.attribute("name");
        if node.has_tag_name("infoStr") {
            match name {
                Some("productSkuId") => {
                    licence.product_sku_id = Some(parse_guid_text(node, "productSkuId")?);
                }
                Some("applicationId") => {
                    licence.application_id = Some(parse_guid_text(node, "applicationId")?);
                }
                _ => {}
            }
        } else if node.has_tag_name("policyStr") || node.has_tag_name("policyInt") {
            match name {
                Some("Security-SPP-KmsCountedIdList") => {
                    for entry in node.text().unwrap_or_default().split(',') {
                        let entry = entry.trim();
                        if entry.is_empty() {
                            continue;
                        }
                        licence.counted_ids.push(
                            Guid::parse(entry).context("Security-SPP-KmsCountedIdList entry")?,
                        );
                    }
                }
                Some("Security-SPP-CMIDExpirationPeriod") => {
                    licence.cmid_expiration_minutes = node
                        .text()
                        .and_then(|value| value.trim().parse::<u32>().ok());
                }
                _ => {}
            }
        }
    }

    Ok(licence)
}

/// The text of a named child element, matched on its local name.
fn child_text(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|child| child.has_tag_name(name))
        .and_then(|child| child.text())
        .map(|text| text.trim().to_owned())
}

/// The text of a named child element, parsed as a number.
fn child_number(node: roxmltree::Node<'_, '_>, name: &str) -> Option<u32> {
    child_text(node, name)?.parse().ok()
}

/// Parse the text of a node as a GUID.
fn parse_guid_text(node: roxmltree::Node<'_, '_>, field: &str) -> Result<Guid> {
    let text = node.text().context(format!("{field} is empty"))?;
    Guid::parse(text).context(format!("{field} {text:?}"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{decode_text, parse_licence, parse_pkeyconfig, pkeyconfig_payload};

    const WINDOWS_STYLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<ProductKeyConfiguration xmlns="http://www.microsoft.com/DRM/PKEY/Configuration/2.0">
<Configurations>
<Configuration>
<ActConfigId>{84e331f6-4279-48c4-ab10-b75139181351}</ActConfigId>
<RefGroupId>4919</RefGroupId>
<EditionId>ServerDatacenter;ServerStandard</EditionId>
<ProductDescription>Windows Server 2025 RTM Volume:CSVLK</ProductDescription>
<ProductKeyType>Volume:CSVLK</ProductKeyType>
</Configuration>
</Configurations>
<KeyRanges>
<KeyRange>
<RefActConfigId>{84e331f6-4279-48c4-ab10-b75139181351}</RefActConfigId>
<PartNumber>[Ge]X23-56798</PartNumber>
<IsValid>true</IsValid>
<Start>0</Start>
<End>19999</End>
</KeyRange>
<KeyRange>
<RefActConfigId>{84e331f6-4279-48c4-ab10-b75139181351}</RefActConfigId>
<PartNumber>[Ge]X23-56845</PartNumber>
<IsValid>true</IsValid>
<Start>20000</Start>
<End>20019999</End>
</KeyRange>
</KeyRanges>
</ProductKeyConfiguration>"#;

    /// The Office artifact uses a `pkc:` prefix for the identical schema. An
    /// extractor that matched qualified names would silently produce nothing for
    /// one of the two families.
    const OFFICE_STYLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<pkc:ProductKeyConfiguration xmlns:pkc="http://www.microsoft.com/DRM/PKEY/Configuration/2.0">
<pkc:Configurations>
<pkc:Configuration>
<pkc:ActConfigId>{F3D89BBF-C0EC-47CE-A8FA-E5A5F97E447F}</pkc:ActConfigId>
<pkc:RefGroupId>206</pkc:RefGroupId>
<pkc:EditionId>KMSHost2024Volume</pkc:EditionId>
<pkc:ProductDescription>Office24_KMSHost2024VL_KMS_Host</pkc:ProductDescription>
<pkc:ProductKeyType>Volume:CSVLK</pkc:ProductKeyType>
</pkc:Configuration>
</pkc:Configurations>
</pkc:ProductKeyConfiguration>"#;

    #[test]
    fn both_namespace_styles_parse_identically() {
        let (windows, ranges) = parse_pkeyconfig(WINDOWS_STYLE).unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].group_id, 4919);
        assert_eq!(ranges.len(), 2);

        let (office, office_ranges) = parse_pkeyconfig(OFFICE_STYLE).unwrap();
        assert_eq!(office.len(), 1);
        assert_eq!(office[0].group_id, 206);
        assert_eq!(office[0].edition_id, "KMSHost2024Volume");
        assert!(office_ranges.is_empty());
    }

    /// `ID-019` (#124): a CSVLK's key range is a *set of blocks*, and the hole
    /// between two of them is real data rather than a gap in ours.
    ///
    /// Windows Server 2022 is the case that matters: two valid blocks with an
    /// invalid hole at `20000..=29999` between them. py-kms models the same
    /// CSVLK as `MinKeyId = 0, MaxKeyId = 20029999` and can therefore emit a key
    /// ID inside the hole — a value no genuine host would ever produce, and one
    /// a detection probe could look for.
    #[test]
    fn blocks_with_a_hole_between_them_survive_as_two_blocks() {
        let server_2022 = WINDOWS_STYLE
            .replace("<Start>20000</Start>", "<Start>30000</Start>")
            .replace("<End>20019999</End>", "<End>20029999</End>");
        let (_, ranges) = parse_pkeyconfig(&server_2022).unwrap();

        assert_eq!(ranges.len(), 2);
        assert_eq!((ranges[0].start, ranges[0].end), (0, 19999));
        assert_eq!((ranges[1].start, ranges[1].end), (30_000, 20_029_999));
        assert!(
            ranges[0].end + 1 < ranges[1].start,
            "the hole must survive; merging these into one span is the py-kms bug"
        );
    }

    /// Contiguous blocks are also kept apart. Merging them would be harmless
    /// arithmetically and wrong in principle — the part numbers differ, and the
    /// next artifact revision may make the gap real.
    #[test]
    fn contiguous_blocks_are_still_two_blocks() {
        let (_, ranges) = parse_pkeyconfig(WINDOWS_STYLE).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!((ranges[0].start, ranges[0].end), (0, 19999));
        assert_eq!((ranges[1].start, ranges[1].end), (20_000, 20_019_999));
        assert_ne!(ranges[0].part_number, ranges[1].part_number);
    }

    /// `DB-006` (#130): malformed data stops the pipeline.
    #[test]
    fn malformed_input_is_an_error_not_a_skipped_row() {
        let no_group = WINDOWS_STYLE.replace("<RefGroupId>4919</RefGroupId>", "");
        assert!(parse_pkeyconfig(&no_group).is_err());

        let bad_guid = WINDOWS_STYLE.replace("84e331f6-4279-48c4-ab10-b75139181351", "not-a-guid");
        assert!(parse_pkeyconfig(&bad_guid).is_err());

        let backwards = WINDOWS_STYLE.replace("<Start>0</Start>", "<Start>99999</Start>");
        assert!(parse_pkeyconfig(&backwards).is_err());

        assert!(parse_pkeyconfig("<not-xml").is_err());
    }

    #[test]
    fn a_licence_yields_its_join_key_application_and_counted_ids() {
        let licence = r##"<?xml version="1.0" encoding="utf-8"?>
<r:license xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS"
           xmlns:sl="http://www.microsoft.com/DRM/XrML2/SL/v2"
           xmlns:tm="http://www.microsoft.com/DRM/XrML2/TM/v2">
<tm:infoTables><tm:infoList tag="#global">
<tm:infoStr name="productSkuId">{84e331f6-4279-48c4-ab10-b75139181351}</tm:infoStr>
<tm:infoStr name="applicationId">{55c92734-d682-4d71-983e-d6ec3f16059f}</tm:infoStr>
</tm:infoList></tm:infoTables>
<sl:productPolicies>
<sl:policyInt name="Security-SPP-CMIDExpirationPeriod">43200</sl:policyInt>
<sl:policyStr name="Security-SPP-KmsCountedIdList">{907f1f65-adcd-4a2e-95bc-4bf500bc6e58}, {a8973cb5-bf03-0a4c-9cef-703099645ab3}, </sl:policyStr>
</sl:productPolicies>
</r:license>"##;
        let parsed = parse_licence(licence).unwrap();
        assert_eq!(
            parsed.product_sku_id.unwrap().to_string(),
            "84e331f6-4279-48c4-ab10-b75139181351"
        );
        assert_eq!(
            parsed.application_id.unwrap().to_string(),
            "55c92734-d682-4d71-983e-d6ec3f16059f"
        );
        // 30 days, which is where POL-003's expiry comes from.
        assert_eq!(parsed.cmid_expiration_minutes, Some(43200));
        assert_eq!(
            parsed.counted_ids.len(),
            2,
            "the trailing comma is not an entry"
        );
        // The second is Office LTSC 2024's, with its invalid version nibble.
        assert_eq!(
            parsed.counted_ids[1].to_string(),
            "a8973cb5-bf03-0a4c-9cef-703099645ab3"
        );
    }

    #[test]
    fn utf16_and_utf8_artifacts_both_decode() {
        let sample = "<?xml version=\"1.0\"?><r/>";
        let mut utf16 = vec![0xFF_u8, 0xFE];
        for unit in sample.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_text(&utf16).unwrap(), sample);

        let mut utf8 = vec![0xEF_u8, 0xBB, 0xBF];
        utf8.extend_from_slice(sample.as_bytes());
        assert_eq!(decode_text(&utf8).unwrap(), sample);
        assert_eq!(decode_text(sample.as_bytes()).unwrap(), sample);
    }

    #[test]
    fn an_artifact_without_a_payload_is_not_an_error() {
        let wrapper = r#"<r:license xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS"/>"#;
        assert_eq!(pkeyconfig_payload(wrapper).unwrap(), None);
    }

    #[test]
    fn a_base64_payload_decodes_whether_or_not_it_is_gzipped() {
        use base64::Engine as _;
        use std::io::Write as _;

        let inner = "<ProductKeyConfiguration/>";
        let plain = base64::engine::general_purpose::STANDARD.encode(inner);
        let wrapper = format!(
            r#"<r:license xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS" xmlns:tm="http://www.microsoft.com/DRM/XrML2/TM/v2"><tm:infoBin name="pkeyConfigData">{plain}</tm:infoBin></r:license>"#
        );
        assert_eq!(
            pkeyconfig_payload(&wrapper).unwrap().as_deref(),
            Some(inner)
        );

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(inner.as_bytes()).unwrap();
        let gzipped = base64::engine::general_purpose::STANDARD.encode(encoder.finish().unwrap());
        let wrapper = format!(
            r#"<r:license xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS" xmlns:tm="http://www.microsoft.com/DRM/XrML2/TM/v2"><tm:infoBin name="pkeyConfigData">{gzipped}</tm:infoBin></r:license>"#
        );
        assert_eq!(
            pkeyconfig_payload(&wrapper).unwrap().as_deref(),
            Some(inner)
        );
    }
}

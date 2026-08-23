//! Locale identifiers, from Microsoft's own `[MS-LCID]` specification
//! (`ID-008`, #113).
//!
//! A generated ePID carries an LCID, and it is drawn once per process and
//! shared across host-key groups — which is what makes a set of ePIDs from one
//! host look self-consistent rather than like a machine that changes its locale
//! between requests. The pool it is drawn from therefore has to be real
//! locales, not a plausible-looking selection.
//!
//! The source is `[MS-LCID]`'s reference table on Microsoft Learn, which is the
//! authoritative published list. vlmcsd carries 158 entries; the specification
//! has considerably more, and taking them from the specification means the list
//! can be regenerated rather than trusted.
//!
//! # Which rows are kept
//!
//! Only **specific cultures**: an LCID in `0x0401..=0x7FFF` whose language tag
//! ends in a region subtag. Three kinds of row are dropped, each for its own
//! reason:
//!
//! * Below `0x0400` are primary language identifiers rather than locales.
//!   `0x0009` is "English", which is not a locale a machine can be installed
//!   in.
//! * `0x1000` is the placeholder the specification gives to every locale with
//!   no assigned identifier, so it appears hundreds of times and identifies
//!   nothing.
//! * Tags like `az-Cyrl` and `ku-Arab` name a *script*, not a region. They are
//!   neutral cultures, and a machine is installed in `az-Cyrl-AZ` rather than
//!   in `az-Cyrl`. Testing for a hyphen would keep them, so the last subtag is
//!   required to look like a region: two uppercase letters or three digits,
//!   which is BCP 47's own rule.
//!
//! That filter is also why the research note that "every LCID a real host can
//! report is at least 1025" holds: 1025 is `0x0401`, the first specific culture.

use crate::error::{Context, Error, Result};
use crate::model::Lcid;

/// The lowest identifier a specific culture can have: `0x0401`.
const FIRST_SPECIFIC_CULTURE: u32 = 0x0401;

/// The highest identifier this table assigns.
const LAST_SPECIFIC_CULTURE: u32 = 0x7FFF;

/// The placeholder `[MS-LCID]` gives to locales with no assigned identifier.
const UNASSIGNED: u32 = 0x1000;

/// Fetch and parse the `[MS-LCID]` reference table.
///
/// # Errors
///
/// Returns an error if the page cannot be fetched, or if it yields no rows —
/// which is what a changed page layout looks like, and is a loud failure rather
/// than a silently empty table.
pub fn fetch(url: &str) -> Result<Vec<Lcid>> {
    let body = ureq::get(url)
        .header("User-Agent", "kmsrs-dbgen")
        .call()
        .context(format!("fetching {url}"))?
        .into_body()
        .read_to_string()
        .context(format!("reading {url}"))?;

    let locales = parse(&body);
    if locales.is_empty() {
        return Err(Error::new(format!(
            "{url} yielded no locales; the page layout has probably changed"
        )));
    }
    Ok(locales)
}

/// Extract specific cultures from the specification's HTML table.
///
/// Scanned rather than parsed with an HTML library, because the shape being
/// looked for is narrow and the failure mode is loud: a changed layout yields
/// zero rows, which [`fetch`] turns into an error.
#[must_use]
pub fn parse(html: &str) -> Vec<Lcid> {
    let mut locales: Vec<Lcid> = Vec::new();
    for row in split_tags(html, "<tr", "</tr>") {
        let cells: Vec<String> = split_tags(row, "<td", "</td>")
            .into_iter()
            .map(strip_markup)
            .collect();

        let Some(identifier) = cells.iter().find_map(|cell| parse_hex(cell)) else {
            continue;
        };
        if identifier == UNASSIGNED
            || !(FIRST_SPECIFIC_CULTURE..=LAST_SPECIFIC_CULTURE).contains(&identifier)
        {
            continue;
        }

        let language = cells.first().cloned().unwrap_or_default();
        let location = cells.get(1).cloned().unwrap_or_default();
        let tag = cells.get(3).cloned().unwrap_or_default();

        if !names_a_region(&tag) {
            continue;
        }
        if locales.iter().any(|existing| existing.value == identifier) {
            continue;
        }

        locales.push(Lcid {
            value: identifier,
            tag,
            language,
            location,
        });
    }
    locales.sort_by_key(|locale| locale.value);
    locales
}

/// Whether a language tag ends in a region subtag.
///
/// BCP 47's rule: a region is two uppercase ASCII letters or three digits. A
/// four-letter title-case subtag is a *script*, and `az-Cyrl` is a neutral
/// culture rather than a locale — which is why testing for a hyphen is not
/// enough.
fn names_a_region(tag: &str) -> bool {
    let Some(last) = tag.rsplit('-').next() else {
        return false;
    };
    if last == tag {
        // No subtag at all.
        return false;
    }
    let two_letters = last.len() == 2 && last.chars().all(|c| c.is_ascii_uppercase());
    let three_digits = last.len() == 3 && last.chars().all(|c| c.is_ascii_digit());
    two_letters || three_digits
}

/// Every region between an opening tag prefix and its closing tag.
fn split_tags<'a>(html: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    let mut regions = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find(open) {
        let after_open = rest.get(start..).unwrap_or("");
        // Skip past the rest of the opening tag, which may carry attributes.
        let Some(content_start) = after_open.find('>') else {
            break;
        };
        let content = after_open
            .get(content_start.saturating_add(1)..)
            .unwrap_or("");
        let Some(end) = content.find(close) else {
            break;
        };
        if let Some(region) = content.get(..end) {
            regions.push(region);
        }
        rest = content.get(end..).unwrap_or("");
    }
    regions
}

/// Remove tags and decode the few entities this table uses.
fn strip_markup(fragment: &str) -> String {
    let mut out = String::new();
    let mut inside_tag = false;
    for character in fragment.chars() {
        match character {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            other if !inside_tag => out.push(other),
            _ => {}
        }
    }
    out.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse a `0x####` cell.
fn parse_hex(cell: &str) -> Option<u32> {
    let digits = cell
        .strip_prefix("0x")
        .or_else(|| cell.strip_prefix("0X"))?;
    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::parse;

    /// A fragment shaped like the specification's table, including every kind
    /// of row that must be filtered out.
    const SAMPLE: &str = "\
<table>
<tr><th>Language</th><th>Location</th><th>Identifier</th><th>Tag</th></tr>
<tr><td>English</td><td>United States</td><td>0x0409</td><td>en-US</td><td>Release A</td></tr>
<tr><td>German</td><td>Germany</td><td>0x0407</td><td>de-DE</td><td>Release A</td></tr>
<tr><td>English</td><td></td><td>0x0009</td><td>en</td><td>Release A</td></tr>
<tr><td>Afar</td><td>Djibouti</td><td>0x1000</td><td>aa-DJ</td><td>Release 10</td></tr>
<tr><td>Central Kurdish</td><td></td><td>0x7c92</td><td>ku-Arab</td><td>Release 8</td></tr>
<tr><td>Serbian (Cyrillic)</td><td>Serbia</td><td>0x281a</td><td>sr-Cyrl-RS</td><td>Release 7</td></tr>
<tr><td>Spanish</td><td>Latin America</td><td>0x580a</td><td>es-419</td><td>Release 10</td></tr>
<tr><td>English</td><td>United States</td><td>0x0409</td><td>en-US</td><td>duplicate</td></tr>
</table>";

    #[test]
    fn only_specific_cultures_survive_the_filter() {
        let locales = parse(SAMPLE);
        let values: Vec<u32> = locales.iter().map(|locale| locale.value).collect();

        assert_eq!(
            values,
            alloc_vec(&[0x0407, 0x0409, 0x281a, 0x580a]),
            "sorted, deduplicated"
        );
        assert_eq!(locales[1].tag, "en-US");
        assert_eq!(locales[1].language, "English");
        assert_eq!(locales[1].location, "United States");
        assert_eq!(
            locales[2].tag, "sr-Cyrl-RS",
            "a script *and* a region is kept"
        );
        assert_eq!(locales[3].tag, "es-419", "a numeric region is kept");
    }

    fn alloc_vec(values: &[u32]) -> Vec<u32> {
        values.to_vec()
    }

    /// Each exclusion is deliberate and each has a different reason, so each
    /// gets its own assertion.
    #[test]
    fn the_three_excluded_kinds_are_excluded_for_their_own_reasons() {
        let locales = parse(SAMPLE);
        let has = |value: u32| locales.iter().any(|locale| locale.value == value);

        // A primary language identifier, not a locale: "English" is not a
        // machine's install locale.
        assert!(!has(0x0009));
        // The placeholder every unassigned locale shares, so it identifies
        // nothing and appears hundreds of times.
        assert!(!has(0x1000));
        // Assigned and in range, but a neutral culture: `ku-Arab` names a
        // script, not a region, so a hyphen test would wrongly keep it.
        assert!(!has(0x7c92));
    }

    /// The research note that every real LCID is at least 1025 is the same
    /// statement as this filter's lower bound.
    #[test]
    fn every_kept_locale_is_at_least_1025() {
        for locale in parse(SAMPLE) {
            assert!(locale.value >= 1025, "{locale:?}");
        }
    }

    /// A changed page layout must yield nothing rather than yielding garbage.
    #[test]
    fn unrecognisable_html_yields_nothing() {
        assert!(parse("").is_empty());
        assert!(parse("<html><body>no table here</body></html>").is_empty());
        assert!(parse("<tr><td>English</td></tr>").is_empty());
    }

    #[test]
    fn a_region_subtag_is_distinguished_from_a_script_subtag() {
        use super::names_a_region;
        assert!(names_a_region("en-US"));
        assert!(names_a_region("sr-Cyrl-RS"));
        assert!(names_a_region("es-419"));
        assert!(!names_a_region("en"));
        assert!(!names_a_region("az-Cyrl"));
        assert!(!names_a_region("ku-Arab"));
        assert!(!names_a_region("zh-Hans"));
        assert!(!names_a_region(""));
    }

    #[test]
    fn markup_and_entities_inside_cells_are_stripped() {
        let row = "<tr><td><b>English</b></td><td>United&nbsp;States</td>\
                   <td>0x0409</td><td><code>en-US</code></td></tr>";
        let locales = parse(row);
        assert_eq!(locales.len(), 1);
        assert_eq!(locales[0].language, "English");
        assert_eq!(locales[0].location, "United States");
        assert_eq!(locales[0].tag, "en-US");
    }
}

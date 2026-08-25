//! KMS client setup keys, from Microsoft's own published tables
//! (`DB-013`, #137; `DB-009`, #133).
//!
//! # What a GVLK is, and why this table exists at all
//!
//! A GVLK — Generic Volume Licence Key — is what an operator types into
//! `slmgr /ipk` to point a machine at a KMS host. **It never appears on the
//! wire.** The protocol carries an application ID, a KMS-counted ID and a SKU
//! ID; the key itself is consumed entirely by the client's Software Protection
//! Platform before a packet is sent, and a KMS host neither receives nor
//! validates one.
//!
//! So this table is not part of activation. It exists because the operator
//! reading `/instructions` needs the key for their edition, and the alternative
//! to shipping it is telling them to go and find it — which is how people end
//! up pasting keys from forum posts.
//!
//! # Why the source is a web page rather than `pkeyconfig`
//!
//! `pkeyconfig` describes key *configurations*: the ranges a key may fall in,
//! its type (`Volume:GVLK`, `Volume:MAK`, `Retail`, …), its group and its
//! description. It does not contain any actual 25-character key, and could not
//! — the whole point of a key range is that it is a range.
//!
//! Microsoft publishes the keys themselves, in two reference tables on Microsoft
//! Learn. That is the authoritative source, and taking them from it means the
//! table can be *regenerated* rather than trusted — which is the same argument
//! that put `[MS-LCID]` behind [`crate::lcid`] rather than a copied list.
//!
//! This also resolves `DB-009` (#133) by construction rather than by hand. That
//! issue lists three keys other catalogues get wrong, and all three come out of
//! these pages correct:
//!
//! | product | published | what the audits found elsewhere |
//! |---|---|---|
//! | Office LTSC Professional Plus 2024 | `XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB` | `CW94N-…`, which is **PowerPoint LTSC 2024** on the same page |
//! | Windows Server 2025 Datacenter | `D764K-2NDRG-47T6Q-P8T8W-YP6DF` | `CNFDQ-…` (License Manager) |
//! | Windows Server 2025 Datacenter: Azure Edition | `XGN3F-F394H-FD2MY-PP6FD-8MCRC` | `NQ8HH-…` (py-kms) |
//!
//! Nobody applied those three corrections. They are what the source says, and a
//! regeneration would keep them right for the same reason.
//!
//! # Why these rows are not joined to the product table
//!
//! Deliberately, and it is the most important decision in this module.
//!
//! A `pkeyconfig` product row is identified by `EditionId` — `Professional`,
//! `ServerDatacenter`, `EnterpriseS` — and by a description like
//! `Win 10 RTM Professional Volume:GVLK`. Microsoft's key table is written for
//! humans and identifies the same thing as `Windows 11 Pro`. There is no
//! identifier in common, so a join would be a *name mapping somebody authored*,
//! and it would be wrong quietly: one bad row pairs a real edition with a real
//! key belonging to a different edition, which is exactly the failure mode
//! `DB-009` is about.
//!
//! The workspace rule is that product data ships through this pipeline or it
//! does not ship (declined item D19). A hand-written join table is the thing
//! that rule exists to prevent, so the keys ship as what the source publishes —
//! an edition name and a key — and the page renders that. An operator matching
//! "Windows 11 Enterprise" to their own machine is doing something they can do
//! and a name-mapping table cannot.

use crate::error::{Context, Error, Result};
use crate::model::Gvlk;
use std::collections::BTreeMap;

/// The length of a product key, `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.
const KEY_LEN: usize = 29;

/// How many groups a key has.
const GROUPS: usize = 5;

/// How many characters are in each group.
const GROUP_LEN: usize = 5;

/// Stands in for a line break while a cell is being flattened.
///
/// A control character, so it cannot occur in an edition name or a key and
/// needs no escaping. It exists only between [`strip_markup`] and
/// [`split_editions`] and never reaches a [`Gvlk`].
const SEPARATOR: char = '\u{1}';

/// Fetch and parse one of Microsoft's key tables.
///
/// # Errors
///
/// Returns an error if the page cannot be fetched, or if it yields no keys —
/// which is what a changed page layout looks like, and is a loud failure rather
/// than a silently empty table.
pub fn fetch(url: &str, source: &str) -> Result<Vec<Gvlk>> {
    let body = ureq::get(url)
        .header("User-Agent", "kmsrs-dbgen")
        .call()
        .context(format!("fetching {url}"))?
        .into_body()
        .read_to_string()
        .context(format!("reading {url}"))?;

    let keys = parse(&body, source);
    if keys.is_empty() {
        return Err(Error::new(format!(
            "{url} yielded no GVLKs; the page layout has probably changed"
        )));
    }
    Ok(keys)
}

/// Extract `(release, edition, key)` triples from a page's HTML tables.
///
/// Scanned rather than parsed with an HTML library, for the same reason as
/// [`crate::lcid`]: the shape is narrow and the failure mode is loud, because a
/// changed layout yields zero rows and [`fetch`] turns that into an error.
///
/// # Why the release has to be carried
///
/// **An edition name is not unique on the page.** The Windows table has three
/// separate rows reading `Windows Server Datacenter`, with three different
/// keys, because Microsoft puts each release in its own tab and the rows inside
/// only name the edition. Flattening the page throws away the one thing that
/// tells them apart, and the result is three rows an operator cannot choose
/// between.
///
/// The release comes from one of two places, because the two pages are built
/// differently:
///
/// * The Windows page puts each table in a `<section data-tab="server2016">`
///   whose label is in a matching `<a data-tab="server2016">Windows Server
///   2016</a>`. That anchor text is the release.
/// * The Office page has no tabs and uses a heading per table —
///   `GVLKs for Office LTSC 2024`.
///
/// So the release is the tab label where there is one and the nearest preceding
/// heading otherwise, which covers both without either page needing a special
/// case beyond that sentence.
#[must_use]
pub fn parse(html: &str, source: &str) -> Vec<Gvlk> {
    let labels = tab_labels(html);
    let mut keys: Vec<Gvlk> = Vec::new();
    let mut heading = String::new();
    let mut tab: Option<String> = None;

    for event in scan(html) {
        match event {
            Event::Heading(text) => {
                heading = text;
                // A heading ends whatever tab group came before it. Without
                // this a table under a later heading would inherit the last
                // tab on the page.
                tab = None;
            }
            Event::TabPanel(name) => tab = labels.get(&name).cloned(),
            Event::Row(cells) => {
                // Every cell is a list of lines, because a `<br>` inside one is
                // meaningful in both columns: the edition column uses it to
                // share a key between two editions, and the Office page's key
                // column has a trailing one. So each cell is split first and
                // the decisions are made on the segments.
                let cells: Vec<Vec<String>> = cells.iter().map(|cell| segments(cell)).collect();

                let Some(key) = cells
                    .iter()
                    .find_map(|cell| cell.iter().find(|line| is_key(line)))
                else {
                    continue;
                };
                // The name is the first cell that is not the key column and is
                // not empty. Taking the first rather than "the other" tolerates
                // a third column, which these tables have had at times.
                let Some(edition) = cells
                    .iter()
                    .find(|cell| !cell.iter().any(|line| is_key(line)) && !cell.is_empty())
                else {
                    continue;
                };

                let release = tab.clone().unwrap_or_else(|| heading.clone());
                // One cell can name several editions that share a key — the
                // Windows table writes "Windows 11 Pro<br>Windows 10 Pro".
                for name in edition.iter().cloned() {
                    let entry = Gvlk {
                        release: release.clone(),
                        edition: name,
                        key: key.clone(),
                        source: source.to_owned(),
                    };
                    if !keys.contains(&entry) {
                        keys.push(entry);
                    }
                }
            }
        }
    }

    keys.sort_by(|a, b| {
        a.release
            .cmp(&b.release)
            .then_with(|| a.edition.cmp(&b.edition))
            .then_with(|| a.key.cmp(&b.key))
    });
    keys
}

/// What the scanner reports, in document order.
enum Event {
    /// A heading of any level, with its text.
    Heading(String),
    /// The start of a `<section data-tab="…">`, with the tab name.
    TabPanel(String),
    /// A `<tr>`, with its cells flattened.
    Row(Vec<String>),
}

/// Walk the document reporting the three things [`parse`] cares about.
///
/// One pass in document order, because the release a row belongs to is decided
/// by what came *before* it — which is exactly the thing a per-table scan
/// cannot see.
fn scan(html: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let mut rest = html;

    while !rest.is_empty() {
        let Some(at) = rest.find('<') else { break };
        let after = rest.get(at..).unwrap_or("");

        if let Some(name) = section_tab(after) {
            events.push(Event::TabPanel(name));
        } else if let Some((text, consumed)) = heading(after) {
            events.push(Event::Heading(text));
            rest = after.get(consumed..).unwrap_or("");
            continue;
        } else if after.starts_with("<tr")
            && let Some(end) = after.find("</tr>")
        {
            let body = after.get(..end).unwrap_or("");
            events.push(Event::Row(
                split_tags(body, "<td", "</td>")
                    .into_iter()
                    .map(strip_markup)
                    .collect(),
            ));
            rest = after.get(end..).unwrap_or("");
            continue;
        }

        rest = after.get(1..).unwrap_or("");
    }
    events
}

/// The `data-tab` of a `<section …>` opening tag, if this is one.
fn section_tab(fragment: &str) -> Option<String> {
    if !fragment.starts_with("<section") {
        return None;
    }
    let end = fragment.find('>')?;
    attribute(fragment.get(..end)?, "data-tab")
}

/// A heading's text and how many bytes it occupied, if this is one.
fn heading(fragment: &str) -> Option<(String, usize)> {
    let level = ['1', '2', '3', '4', '5', '6']
        .into_iter()
        .find(|digit| fragment.starts_with(&format!("<h{digit}")))?;
    let close = format!("</h{level}>");
    let start = fragment.find('>')?.checked_add(1)?;
    let end = fragment.find(&close)?;
    let text = strip_markup(fragment.get(start..end)?);
    Some((text.replace(SEPARATOR, " ").trim().to_owned(), end))
}

/// Every `data-tab` to its human label, from the tab strip.
///
/// The strip is a list of `<a data-tab="server2016">Windows Server 2016</a>`,
/// and it appears before the panels it labels.
fn tab_labels(html: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    let mut rest = html;
    while let Some(at) = rest.find("<a ") {
        let after = rest.get(at..).unwrap_or("");
        let Some(open_end) = after.find('>') else {
            break;
        };
        if let Some(name) = attribute(after.get(..open_end).unwrap_or(""), "data-tab")
            && let Some(close) = after.find("</a>")
        {
            let text = strip_markup(
                after
                    .get(open_end.saturating_add(1)..close)
                    .unwrap_or_default(),
            );
            let text = text.replace(SEPARATOR, " ").trim().to_owned();
            if !text.is_empty() {
                labels.entry(name).or_insert(text);
            }
        }
        rest = after.get(3..).unwrap_or("");
    }
    labels
}

/// The value of a double-quoted attribute in an opening tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let at = tag.find(&needle)?;
    let value = tag.get(at.checked_add(needle.len())?..)?;
    let end = value.find('"')?;
    Some(value.get(..end)?.to_owned())
}

/// Whether a cell is exactly a product key./// Whether a cell is exactly a product key.
///
/// Strict on purpose: five groups of five, separated by hyphens, uppercase
/// alphanumeric throughout. A loose test would pick up part numbers and build
/// identifiers from neighbouring columns.
#[must_use]
pub fn is_key(cell: &str) -> bool {
    let cell = cell.trim();
    if cell.len() != KEY_LEN {
        return false;
    }
    let groups: Vec<&str> = cell.split('-').collect();
    groups.len() == GROUPS
        && groups.iter().all(|group| {
            group.len() == GROUP_LEN
                && group
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        })
}

/// Split a cell into its lines, trimmed, with the empties dropped.
///
/// A `<br>` inside a cell is meaningful in both columns, which is why this is
/// applied to every cell rather than only to the edition one:
///
/// ```html
/// <td>Windows 11 Pro<br>Windows 10 Pro</td>          <!-- two editions, one key -->
/// <td>NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP <br></td>        <!-- one key, trailing break -->
/// ```
///
/// The Office page has the second shape throughout, and an earlier version of
/// this dropped all 25 of its Office 2019 and 2016 keys by testing the whole
/// cell rather than its lines.
///
/// The split is on **the markup**, recorded by [`strip_markup`] before the tags
/// are removed, rather than on where the text looks like it should break. That
/// distinction is not academic: an earlier version split on a lowercase letter
/// followed by an uppercase one, which is where the `<br>` was — and it also cut
/// `PowerPoint LTSC 2024` into `Power` and `Point LTSC 2024`. Reading the
/// separator that is actually there cannot make either mistake.
fn segments(cell: &str) -> Vec<String> {
    cell.split(SEPARATOR)
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect()
}

/// Every region between an opening tag prefix and its closing tag.
fn split_tags<'a>(html: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    let mut regions = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find(open) {
        let after_open = rest.get(start..).unwrap_or("");
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

/// Remove tags and decode the few entities these tables use.
///
/// A line-breaking tag becomes [`SEPARATOR`] rather than nothing, so that
/// [`split_editions`] can recover a boundary that was in the markup instead of
/// inferring one from the text. Everything else is dropped.
fn strip_markup(fragment: &str) -> String {
    let mut out = String::new();
    let mut tag = String::new();
    let mut inside_tag = false;
    for character in fragment.chars() {
        match character {
            '<' => {
                inside_tag = true;
                tag.clear();
            }
            '>' => {
                inside_tag = false;
                if breaks_a_line(&tag) {
                    out.push(SEPARATOR);
                }
            }
            other if inside_tag => tag.push(other),
            other => out.push(other),
        }
    }
    out.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
        // Collapse runs of whitespace without touching the separator, which is
        // the one character in here that carries meaning.
        .split(SEPARATOR)
        .map(|part| part.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(&SEPARATOR.to_string())
}

/// Whether a tag's body starts a new line in the rendered cell.
///
/// `br`, and the closing half of the block elements these tables use. Matched
/// on the element name only, so attributes and self-closing syntax do not
/// matter.
fn breaks_a_line(tag: &str) -> bool {
    const BREAKS: [&str; 5] = ["br", "/p", "/li", "/div", "/tr"];
    let name: String = tag
        .trim()
        .trim_end_matches('/')
        .chars()
        .take_while(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    BREAKS.contains(&name.as_str())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{is_key, parse};

    /// The strictness that stops a part number or a build being read as a key.
    #[test]
    fn only_a_well_formed_key_is_a_key() {
        assert!(is_key("W269N-WFGWX-YVC9B-4J6C9-T83GX"));
        assert!(is_key("  W269N-WFGWX-YVC9B-4J6C9-T83GX  "));

        assert!(!is_key(""));
        assert!(!is_key("Windows 11 Pro"));
        // Four groups.
        assert!(!is_key("W269N-WFGWX-YVC9B-4J6C9"));
        // Right length, wrong shape.
        assert!(!is_key("W269NWFGWXYVC9B4J6C9T83GXABCDE"));
        // Lowercase.
        assert!(!is_key("w269n-wfgwx-yvc9b-4j6c9-t83gx"));
        // A build number of the same length would not survive either.
        assert!(!is_key("10.0.26100.1-2345-6789-01234"));
    }

    /// The Windows table shares one key between a Windows 11 edition and its
    /// Windows 10 equivalent, separated by a `<br>` inside one cell.
    #[test]
    fn a_cell_naming_two_editions_splits_into_two() {
        let html = "<table><tr><td>Windows 11 Pro<br>Windows 10 Pro</td>\
                    <td>W269N-WFGWX-YVC9B-4J6C9-T83GX</td></tr></table>";
        let keys = parse(html, "test");

        let editions: Vec<&str> = keys.iter().map(|g| g.edition.as_str()).collect();
        assert_eq!(editions, vec!["Windows 10 Pro", "Windows 11 Pro"]);
        assert!(
            keys.iter()
                .all(|g| g.key == "W269N-WFGWX-YVC9B-4J6C9-T83GX")
        );
    }

    /// **A name with an internal capital is one name.**
    ///
    /// This is the regression test for the bug that made splitting on markup
    /// rather than on capitalisation necessary: an earlier version cut
    /// `PowerPoint LTSC 2024` into `Power` and `Point LTSC 2024`, because the
    /// rule it used — a lowercase letter followed by an uppercase one — is also
    /// what CamelCase looks like.
    #[test]
    fn a_single_edition_is_left_whole() {
        for name in [
            "PowerPoint LTSC 2024",
            "SharePoint Server 2019",
            "OneNote LTSC 2024",
            "Windows Server 2025 Datacenter: Azure Edition",
            "Office LTSC Professional Plus 2024",
            "Windows 11 Pro for Workstations N",
        ] {
            let html = format!(
                "<table><tr><td>{name}</td><td>W269N-WFGWX-YVC9B-4J6C9-T83GX</td></tr></table>"
            );
            let keys = parse(&html, "test");
            let editions: Vec<&str> = keys.iter().map(|g| g.edition.as_str()).collect();
            assert_eq!(editions, vec![name], "{name} should stay whole");
        }
    }

    /// A table row yields an edition and a key, and nothing else does.
    #[test]
    fn a_row_with_a_key_and_a_name_is_taken() {
        let html = "\
            <table><tr><th>Operating system edition</th><th>KMS Client Product Key</th></tr>\
            <tr><td>Windows 11 Pro</td><td>W269N-WFGWX-YVC9B-4J6C9-T83GX</td></tr>\
            <tr><td>Windows 11 Enterprise</td><td>NPPR9-FWDCX-D2C8J-H872K-2YT43</td></tr>\
            </table>";
        let keys = parse(html, "test");

        assert_eq!(keys.len(), 2);
        let enterprise = keys.iter().find(|g| g.edition == "Windows 11 Enterprise");
        assert_eq!(
            enterprise.map(|g| g.key.as_str()),
            Some("NPPR9-FWDCX-D2C8J-H872K-2YT43")
        );
        assert!(keys.iter().all(|g| g.source == "test"));
    }

    /// A row with no key is skipped rather than producing an empty entry, and a
    /// row with no name is skipped too.
    #[test]
    fn a_row_missing_either_half_is_skipped() {
        let html = "\
            <table>\
            <tr><td>Some heading with no key at all</td><td>and no key here either</td></tr>\
            <tr><td></td><td>W269N-WFGWX-YVC9B-4J6C9-T83GX</td></tr>\
            </table>";
        assert!(parse(html, "test").is_empty());
    }

    /// **`DB-009` (#133) falls out of the source rather than being applied.**
    ///
    /// The three keys that issue lists are what these pages publish, and the
    /// one it says was confused with PowerPoint is on the same page under
    /// PowerPoint's own name.
    #[test]
    fn the_confirmed_corrections_are_what_the_source_says() {
        let html = "\
            <table>\
            <tr><td>Office LTSC Professional Plus 2024</td>\
                <td>XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB</td></tr>\
            <tr><td>PowerPoint LTSC 2024</td><td>CW94N-K6GJH-9CTXY-MG2VC-FYCWP</td></tr>\
            </table>";
        let keys = parse(html, "test");

        let proplus = keys
            .iter()
            .find(|g| g.edition == "Office LTSC Professional Plus 2024")
            .unwrap();
        assert_eq!(proplus.key, "XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB");

        // And the key the audits found mis-assigned to it belongs to a
        // different product on the same page, which is why the mistake was
        // easy to make and why reading the source rather than a catalogue is
        // the fix.
        let powerpoint = keys.iter().find(|g| g.edition == "PowerPoint LTSC 2024");
        assert_eq!(
            powerpoint.map(|g| g.key.as_str()),
            Some("CW94N-K6GJH-9CTXY-MG2VC-FYCWP")
        );
    }

    /// **The bug that made `release` necessary.**
    ///
    /// Two tables in one tab group, each naming an edition the same way. Without
    /// the tab label these are two rows reading `Windows Server Datacenter`
    /// with different keys and nothing to choose between them.
    #[test]
    fn the_same_edition_in_two_tabs_is_two_distinguishable_rows() {
        let html = "\
            <ul>\
            <li><a data-tab=\"server2016\">Windows Server 2016</a></li>\
            <li><a data-tab=\"server2019\">Windows Server 2019</a></li>\
            </ul>\
            <section data-tab=\"server2016\" role=\"tabpanel\">\
            <table><tr><td>Windows Server Datacenter</td>\
            <td>CB7KF-BWN84-R7R2Y-793K2-8XDDG</td></tr></table></section>\
            <section data-tab=\"server2019\" role=\"tabpanel\">\
            <table><tr><td>Windows Server Datacenter</td>\
            <td>WMDGN-G9PQG-XVVXX-R3X43-63DFG</td></tr></table></section>";
        let keys = parse(html, "test");

        assert_eq!(keys.len(), 2, "two rows, not one deduplicated one");
        let by_release: Vec<(&str, &str)> = keys
            .iter()
            .map(|g| (g.release.as_str(), g.key.as_str()))
            .collect();
        assert_eq!(
            by_release,
            vec![
                ("Windows Server 2016", "CB7KF-BWN84-R7R2Y-793K2-8XDDG"),
                ("Windows Server 2019", "WMDGN-G9PQG-XVVXX-R3X43-63DFG"),
            ]
        );
        assert!(
            keys.iter()
                .all(|g| g.edition == "Windows Server Datacenter")
        );
    }

    /// The Office page has no tabs, so the heading above the table is the
    /// release. One rule, two page layouts.
    #[test]
    fn a_page_without_tabs_takes_its_release_from_the_heading() {
        let html = "\
            <h2>GVLKs for Office LTSC 2024</h2>\
            <table><tr><td>Office LTSC Professional Plus 2024</td>\
            <td>XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB</td></tr></table>";
        let keys = parse(html, "test");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].release, "GVLKs for Office LTSC 2024");
        assert_eq!(keys[0].edition, "Office LTSC Professional Plus 2024");
    }

    /// A heading closes the tab group before it, so a later table does not
    /// inherit a label from a tab strip it has nothing to do with.
    #[test]
    fn a_heading_ends_the_tab_group_above_it() {
        let html = "\
            <ul><li><a data-tab=\"server2016\">Windows Server 2016</a></li></ul>\
            <section data-tab=\"server2016\" role=\"tabpanel\">\
            <table><tr><td>Windows Server Datacenter</td>\
            <td>CB7KF-BWN84-R7R2Y-793K2-8XDDG</td></tr></table></section>\
            <h3>Something else entirely</h3>\
            <table><tr><td>Windows 11 Pro</td>\
            <td>W269N-WFGWX-YVC9B-4J6C9-T83GX</td></tr></table>";
        let keys = parse(html, "test");

        let pro = keys.iter().find(|g| g.edition == "Windows 11 Pro").unwrap();
        assert_eq!(pro.release, "Something else entirely");
    }

    /// **The regression test for the 25 keys that went missing.**
    ///
    /// The Office page writes every cell with a trailing `<br>`. Testing the
    /// whole cell for a key rather than each of its lines dropped every row in
    /// the Office 2019 and Office 2016 sections — silently, because a page that
    /// yields *some* rows does not trip the empty-result check in `fetch`.
    #[test]
    fn a_cell_with_a_trailing_break_still_yields_its_key() {
        let html = "\
            <h2>GVLKs for Office 2019</h2>\
            <table><tr>\
            <td style=\"text-align: left;\">Office Professional Plus 2019  <br></td>\
            <td style=\"text-align: left;\">NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP <br></td>\
            </tr></table>";
        let keys = parse(html, "test");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].edition, "Office Professional Plus 2019");
        assert_eq!(keys[0].key, "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP");
        assert_eq!(keys[0].release, "GVLKs for Office 2019");
    }

    /// The output is sorted, because the file it lands in is reviewed as a
    /// diff and row order must be a function of the data.
    #[test]
    fn the_output_is_sorted_by_edition() {
        let html = "\
            <table>\
            <tr><td>Windows 11 Pro</td><td>W269N-WFGWX-YVC9B-4J6C9-T83GX</td></tr>\
            <tr><td>Access LTSC 2024</td><td>82FTR-NCHR7-W3944-MGRHM-JMCWD</td></tr>\
            </table>";
        let keys = parse(html, "test");
        let ordered: Vec<(&str, &str)> = keys
            .iter()
            .map(|g| (g.release.as_str(), g.edition.as_str()))
            .collect();
        let mut sorted = ordered.clone();
        sorted.sort_unstable();
        assert_eq!(ordered, sorted);
    }
}

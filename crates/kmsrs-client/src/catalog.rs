//! Listing what this build can activate, and the keys for it
//! (`CLI-008`, #214).
//!
//! # Why the client and not the web UI
//!
//! The web UI already renders both tables, and it is the better place for a
//! person. This exists for the two cases the web UI cannot serve: a build whose
//! `web_ui` is off, and a shell script. `--products --json` emits one object per
//! line, which is what makes "does this build know about Server 2025?" a
//! question a pipeline can ask.
//!
//! It also needs **no host**. Everything printed here is compiled into the
//! binary, so it works before anything is deployed and answers "what would this
//! activate" rather than "what did that host do".
//!
//! # The `uint8_t` bug this is written against
//!
//! `vlmcs -l` lists product names and numbers them with a `uint8_t`. A
//! catalogue above 255 entries wraps: the 256th product prints as 0, the 257th
//! as 1, and the list silently misnumbers everything after it. kotfenix's fork
//! hit that and fixed it, which is the only reason it is documented anywhere.
//!
//! This ships **273 products and 151 client setup keys**, so the catalogue is
//! already past that line — the bug would be live rather than latent. The
//! defence is that the counter is a `usize` and that
//! `a_catalogue_over_255_entries_numbers_every_row` renders the real table and
//! checks the row at 256, which is a test that would have failed on vlmcs.
//!
//! # Retail SKUs are listed too
//!
//! Deliberately. A retail SKU has no GVLK and no legitimate client can present
//! one, so `POL-010` (#98) refuses it — and an operator whose activation was
//! refused needs to be able to see *why*, which means seeing that the product
//! exists and what kind of key it takes. A list of only the activatable SKUs
//! would answer "is my product supported?" with silence in exactly the case
//! where the answer is "yes, but not that key".

use core::fmt::Write as _;

/// What to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    /// Product key configurations, from `pkeyconfig`.
    Products,
    /// KMS client setup keys, from Microsoft's published tables
    /// (`DB-013`, #137).
    Keys,
    /// Both, products first.
    Both,
}

/// Render the catalogue as text.
///
/// The numbering is `usize` throughout. See the module documentation for the
/// bug that makes that worth saying.
#[must_use]
pub fn render_text(listing: Listing) -> String {
    let mut out = String::new();

    if matches!(listing, Listing::Products | Listing::Both) {
        let _ = writeln!(
            out,
            "{} products, from {} KMS host keys.",
            kmsrs_db::PRODUCTS.len(),
            kmsrs_db::CSVLKS.len()
        );
        let _ = writeln!(out);
        for (index, product) in kmsrs_db::PRODUCTS.iter().enumerate() {
            let _ = writeln!(
                out,
                "{:>4}  {:<12}  {:<28}  {}",
                index.saturating_add(1),
                format!("{:?}", product.kind),
                product.edition_id,
                product.description
            );
        }
    }

    if listing == Listing::Both {
        let _ = writeln!(out);
    }

    if matches!(listing, Listing::Keys | Listing::Both) {
        let _ = writeln!(
            out,
            "{} client setup keys. These never travel over the wire.",
            kmsrs_db::GVLKS.len()
        );
        let _ = writeln!(out);
        for (index, gvlk) in kmsrs_db::GVLKS.iter().enumerate() {
            let _ = writeln!(
                out,
                "{:>4}  {}  {:<48}  {}",
                index.saturating_add(1),
                gvlk.key,
                gvlk.edition,
                gvlk.release
            );
        }
    }

    out
}

/// Render the catalogue as JSON Lines.
///
/// One object per line, so `grep` and `jq -c` both work and neither has to hold
/// the document. The same shape as the log's (`OBS-002`, #178).
#[must_use]
pub fn render_json(listing: Listing) -> String {
    let mut out = String::new();

    if matches!(listing, Listing::Products | Listing::Both) {
        for (index, product) in kmsrs_db::PRODUCTS.iter().enumerate() {
            let _ = writeln!(
                out,
                "{{\"kind\":\"product\",\"index\":{},\"key_kind\":\"{:?}\",\
                 \"edition\":{},\"description\":{},\"group_id\":{}}}",
                index.saturating_add(1),
                product.kind,
                quote(product.edition_id),
                quote(product.description),
                product.group_id
            );
        }
    }

    if matches!(listing, Listing::Keys | Listing::Both) {
        for (index, gvlk) in kmsrs_db::GVLKS.iter().enumerate() {
            let _ = writeln!(
                out,
                "{{\"kind\":\"gvlk\",\"index\":{},\"release\":{},\"edition\":{},\
                 \"key\":{}}}",
                index.saturating_add(1),
                quote(gvlk.release),
                quote(gvlk.edition),
                quote(gvlk.key)
            );
        }
    }

    out
}

/// A JSON string literal.
///
/// Written out rather than pulled in, because this crate has no JSON
/// dependency and the strings involved are Microsoft's own product
/// descriptions — which do contain quotes and non-ASCII, so escaping is not
/// optional even though it is short.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control < ' ' => {
                let _ = write!(out, "\\u{:04x}", u32::from(control));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
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

    use super::{Listing, quote, render_json, render_text};

    /// The row numbers in a rendering, in order.
    ///
    /// Rows are indented and the summary line is not, which is what
    /// distinguishes them — the summary begins with a count, so a test that
    /// just parsed the first token of every line would count the header as row
    /// 273 and pass for the wrong reason.
    fn row_numbers(rendered: &str) -> Vec<usize> {
        rendered
            .lines()
            .filter(|line| line.starts_with(' '))
            .filter_map(|line| line.split_whitespace().next())
            .filter_map(|first| first.parse().ok())
            .collect()
    }

    /// **The `vlmcs` bug, checked against the real catalogue.**
    ///
    /// `vlmcs -l` numbers its list with a `uint8_t`, so the 256th product
    /// prints as 0 and everything after it is misnumbered. This ships more than
    /// 255 products, so the check is against real data rather than a fixture —
    /// and it would fail on vlmcs today.
    #[test]
    fn a_catalogue_over_255_entries_numbers_every_row() {
        assert!(
            kmsrs_db::PRODUCTS.len() > 255,
            "the catalogue has fallen below 256 entries, so this test no longer \\
             exercises the wrap it exists for. Use a fixture, or raise the \\
             coverage (`DB-010`, #134)"
        );

        let numbered = row_numbers(&render_text(Listing::Products));

        assert_eq!(
            numbered.len(),
            kmsrs_db::PRODUCTS.len(),
            "every product should be numbered exactly once"
        );
        // The row that wraps to 0 in a `uint8_t`.
        assert_eq!(numbered[255], 256, "the 256th row wrapped");
        assert_eq!(
            numbered.last().copied(),
            Some(kmsrs_db::PRODUCTS.len()),
            "the last row is numbered with the table's length"
        );
        // Strictly increasing by one, which no wrap can be.
        for (position, number) in numbered.iter().enumerate() {
            assert_eq!(*number, position.saturating_add(1));
        }
    }

    /// The key listing is numbered the same way, and it is over 100 rows.
    #[test]
    fn the_key_listing_is_numbered_too() {
        let numbered = row_numbers(&render_text(Listing::Keys));
        assert_eq!(numbered.len(), kmsrs_db::GVLKS.len());
        assert_eq!(numbered.last().copied(), Some(kmsrs_db::GVLKS.len()));
    }

    /// Every product and every key appears, and `Both` is the two concatenated
    /// rather than a third rendering that could drift from them.
    #[test]
    fn both_listings_contain_everything() {
        let both = render_text(Listing::Both);

        for product in kmsrs_db::PRODUCTS {
            assert!(
                both.contains(product.description),
                "{} is missing from the listing",
                product.description
            );
        }
        for gvlk in kmsrs_db::GVLKS {
            assert!(both.contains(gvlk.key), "{} is missing", gvlk.key);
        }
    }

    /// One JSON object per line, and one line per row.
    #[test]
    fn the_json_form_is_one_object_per_line() {
        let rendered = render_json(Listing::Both);
        let lines: Vec<&str> = rendered.lines().collect();

        assert_eq!(
            lines.len(),
            kmsrs_db::PRODUCTS
                .len()
                .saturating_add(kmsrs_db::GVLKS.len())
        );
        for line in lines {
            assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
            // Balanced quotes, which is the cheap form of "the escaping did not
            // produce something unparseable".
            let quotes = line
                .chars()
                .zip(core::iter::once(' ').chain(line.chars()))
                .filter(|(character, previous)| *character == '"' && *previous != '\\')
                .count();
            assert_eq!(
                quotes.checked_rem(2),
                Some(0),
                "unbalanced quotes in {line}"
            );
        }
    }

    /// A description containing a quote cannot break the line it is on.
    ///
    /// Not hypothetical for long: these are Microsoft's own strings, and the
    /// pipeline transcribes them rather than sanitising them.
    #[test]
    fn quoting_escapes_what_would_break_a_line() {
        assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote(r"a\b"), r#""a\\b""#);
        assert_eq!(quote("a\nb"), r#""a\nb""#);
        // A control character becomes a `\uXXXX` escape, so it cannot end the
        // string it is inside.
        assert_eq!(quote("a\u{1}b"), "\"a\\u0001b\"");
        assert_eq!(quote("Windows 11 Pro"), r#""Windows 11 Pro""#);
    }
}

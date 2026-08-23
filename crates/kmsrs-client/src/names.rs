//! Random workstation names (`CLI-010`, #216).
//!
//! The workstation name is one of the two client-chosen strings on the wire and
//! the only one a host logs, so a soak run in which ten thousand machines all
//! call themselves `kmsrs-client` produces ten thousand indistinguishable log
//! lines. Generating names is what makes a load test's output legible — and it
//! is what a fleet actually looks like.
//!
//! # Two flavours, because Windows has two
//!
//! A Windows machine has a **NetBIOS** name and a **DNS** name, and they are
//! constrained differently. Which one Software Protection Platform sends depends
//! on how the machine was named, so a client that can only produce one of them
//! can only ever exercise half the field.
//!
//! * [`Flavour::NetBios`] — at most 15 characters of `0-9A-Z` and `-`.
//!   Uppercase, because NetBIOS names are case-insensitive and Windows stores
//!   them uppercase, so a lowercase one is a shape no real client sends.
//! * [`Flavour::Dns`] — a fully qualified name: labels of `a-z0-9-`, each at
//!   most 63 characters, neither starting nor ending with a hyphen, joined by
//!   dots.
//!
//! Both are generated at a **fixed** shape — a prefix and six drawn
//! characters — rather than at a random length. That is what a real fleet looks
//! like, Windows' own default being `DESKTOP-` plus seven characters, and a
//! name that is sometimes one character long would be testing the wire field
//! rather than the host.
//!
//! # The field is 63 UTF-16 code units
//!
//! Both flavours are bounded well inside it, so a generated name never reaches
//! the refusal path in [`crate::request::RequestFields::to_body`]
//! (`CLI-013`, #219). That is deliberate: a load generator that occasionally
//! refused its own request would be reporting its own bug as the host's.

use kmsrs_proto::entropy::{Entropy, EntropyUnavailable};

/// The longest NetBIOS computer name Windows permits.
///
/// Fifteen characters, not sixteen: the sixteenth byte of a NetBIOS name is the
/// service suffix, so the usable part is one shorter than the field.
pub const MAX_NETBIOS: usize = 15;

/// The longest DNS label.
pub const MAX_LABEL: usize = 63;

/// Which kind of name to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// `WKS-4J2QZ8` — uppercase, no dots.
    NetBios,
    /// `host-4j2qz8.example.net` — lowercase, dotted.
    Dns,
}

impl Flavour {
    /// Parse the name of a flavour, as a command line spells it.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "netbios" => Some(Self::NetBios),
            "dns" => Some(Self::Dns),
            _ => None,
        }
    }
}

/// Generate one name.
///
/// # Errors
///
/// Returns [`EntropyUnavailable`] if the source failed. Nothing here falls back
/// to a fixed name: a soak run whose machines quietly stopped being distinct
/// would be measuring renewals rather than activations, and would look like a
/// working test (`OS-012`, #263).
pub fn generate(flavour: Flavour, entropy: &mut dyn Entropy) -> Result<String, EntropyUnavailable> {
    match flavour {
        Flavour::NetBios => netbios(entropy),
        Flavour::Dns => dns(entropy),
    }
}

/// `WKS-4J2QZ8`: a prefix, a hyphen, and six characters of `0-9A-Z`.
///
/// A fixed shape rather than a random length, because that is what a real
/// fleet looks like — Windows' own default is `DESKTOP-` plus seven characters
/// — and because a name that is sometimes one character long tests the wire
/// field rather than the host.
fn netbios(entropy: &mut dyn Entropy) -> Result<String, EntropyUnavailable> {
    /// Uppercase letters and digits, which is the whole of what a NetBIOS name
    /// may contain besides the hyphen.
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    let mut name = String::from("WKS-");
    for _ in 0..6_usize {
        name.push(pick(ALPHABET, entropy)?);
    }
    debug_assert!(name.len() <= MAX_NETBIOS);
    Ok(name)
}

/// `host-4j2qz8.example.net`: a label and a fixed reserved domain.
///
/// `example.net` is reserved by RFC 2606 precisely so it cannot resolve to
/// anybody, which matters more here than it looks: a generated name reaches a
/// host's event log, and a plausible-looking real domain in somebody's logs is
/// a name they will eventually try to look up.
fn dns(entropy: &mut dyn Entropy) -> Result<String, EntropyUnavailable> {
    /// Lowercase letters and digits. The hyphen is placed deliberately rather
    /// than drawn, so a label can never start or end with one.
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    let mut label = String::from("host-");
    for _ in 0..6_usize {
        label.push(pick(ALPHABET, entropy)?);
    }
    debug_assert!(label.len() <= MAX_LABEL);
    Ok(format!("{label}.example.net"))
}

/// One character from an alphabet, drawn without modulo bias.
fn pick(alphabet: &[u8], entropy: &mut dyn Entropy) -> Result<char, EntropyUnavailable> {
    let len = u32::try_from(alphabet.len()).map_err(|_| EntropyUnavailable)?;
    let bound = core::num::NonZeroU32::new(len).ok_or(EntropyUnavailable)?;
    // Rejection sampling rather than a modulo, which is biased towards the low
    // end of any alphabet whose length is not a power of two — and 36 is not.
    let index = entropy.uniform_below(bound)?;
    let byte = alphabet
        .get(usize::try_from(index).map_err(|_| EntropyUnavailable)?)
        .copied()
        .ok_or(EntropyUnavailable)?;
    Ok(char::from(byte))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{Flavour, MAX_NETBIOS, generate};
    use crate::request::RequestFields;
    use kmsrs_proto::entropy::testing::{DeterministicEntropy, FailingEntropy};
    use std::collections::HashSet;

    fn seeded() -> DeterministicEntropy {
        DeterministicEntropy::from_seed(0x0C11_0010)
    }

    /// A NetBIOS name is what Windows would accept: uppercase alphanumerics and
    /// hyphens, and short enough that the service suffix still fits.
    #[test]
    fn netbios_names_are_valid_netbios_names() {
        let mut entropy = seeded();
        for _ in 0..500_usize {
            let name = generate(Flavour::NetBios, &mut entropy).unwrap();
            assert!(!name.is_empty());
            assert!(name.len() <= MAX_NETBIOS, "{name} is {} long", name.len());
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'),
                "{name} has a character NetBIOS does not permit"
            );
            assert!(!name.starts_with('-') && !name.ends_with('-'), "{name}");
            assert!(!name.contains('.'), "a NetBIOS name has no dots: {name}");
        }
    }

    /// A DNS name is a valid fully qualified name: lowercase labels within the
    /// length limit, no leading or trailing hyphen on any of them.
    #[test]
    fn dns_names_are_valid_dns_names() {
        let mut entropy = seeded();
        for _ in 0..500_usize {
            let name = generate(Flavour::Dns, &mut entropy).unwrap();
            assert!(name.contains('.'), "{name} is not qualified");
            for label in name.split('.') {
                assert!(!label.is_empty(), "{name} has an empty label");
                assert!(label.len() <= super::MAX_LABEL, "{name}");
                assert!(
                    label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                    "{label} in {name} has a character DNS does not permit"
                );
                assert!(!label.starts_with('-') && !label.ends_with('-'), "{name}");
            }
            // RFC 2606 reserves this precisely so it cannot resolve to anybody.
            assert!(name.ends_with(".example.net"), "{name}");
        }
    }

    /// The point of generating names at all: a fleet, not one machine repeated.
    #[test]
    fn generated_names_are_actually_distinct() {
        let mut entropy = seeded();
        for flavour in [Flavour::NetBios, Flavour::Dns] {
            let mut seen = HashSet::new();
            for _ in 0..1_000_usize {
                seen.insert(generate(flavour, &mut entropy).unwrap());
            }
            // Six characters from a 36-symbol alphabet is 2^31 possibilities,
            // so a thousand draws colliding more than a handful of times means
            // the generator is not drawing.
            assert!(
                seen.len() > 990,
                "{flavour:?} produced only {} distinct names in 1000",
                seen.len()
            );
        }
    }

    /// Every generated name fits the wire field, so a load generator never
    /// refuses its own request (`CLI-013`, #219).
    #[test]
    fn every_generated_name_fits_the_wire_field() {
        let mut entropy = seeded();
        for flavour in [Flavour::NetBios, Flavour::Dns] {
            for _ in 0..200_usize {
                let fields = RequestFields {
                    workstation_name: generate(flavour, &mut entropy).unwrap(),
                    ..RequestFields::default()
                };
                assert!(
                    fields.to_body().is_ok(),
                    "{flavour:?} produced a name the field cannot hold"
                );
            }
        }
    }

    /// A failed draw is an error, never a fixed name. A soak run whose machines
    /// quietly stopped being distinct would be measuring renewals rather than
    /// activations, and would look like a working test.
    #[test]
    fn a_failed_draw_is_reported_rather_than_papered_over() {
        let mut entropy = FailingEntropy;
        for flavour in [Flavour::NetBios, Flavour::Dns] {
            assert!(generate(flavour, &mut entropy).is_err(), "{flavour:?}");
        }
    }

    #[test]
    fn a_flavour_is_named_the_way_a_command_line_spells_it() {
        assert_eq!(Flavour::parse("dns"), Some(Flavour::Dns));
        assert_eq!(Flavour::parse("netbios"), Some(Flavour::NetBios));
        for bad in ["DNS", "NetBIOS", "", "both"] {
            assert_eq!(Flavour::parse(bad), None, "{bad}");
        }
    }
}

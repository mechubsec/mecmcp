//! Device selectors: attribute-based device grants (mecmcp#400 phase 2).
//!
//! A selector is `key=value` over a closed set of attribute keys. It is parsed once, at
//! config load, into a typed [`Selector`]; an expression that cannot compile never reaches a
//! call. Matching is exact byte comparison: no case folding, no Unicode normalization.
//!
//! The isolation guarantee is structural. Attribute values ([`AttrValue`]) are restricted to
//! `[A-Za-z0-9._-]`, 1-64 bytes, when they are *constructed*, and selector literals use the
//! same alphabet plus `*`. A control, bidi, zero-width, homoglyph or non-ASCII character
//! therefore cannot exist on either side of a comparison, so no lookalike can match a
//! literal and `*` cannot swallow one.
//!
//! `*` matches zero or more characters of the alphabet, including `-`, `.` and `_`. It is
//! never a request for "any value": a device without the attribute matches nothing.

use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

/// Longest attribute value or selector pattern, in bytes.
pub const MAX_ATTR_VALUE: usize = 64;
/// Most tags one device may carry.
pub const MAX_TAGS: usize = 16;

/// Why a selector or attribute was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SelectorError(String);

fn refuse<T>(message: impl Into<String>) -> Result<T, SelectorError> {
    Err(SelectorError(message.into()))
}

fn in_alphabet(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

/// A validated device attribute value: 1-64 bytes of `[A-Za-z0-9._-]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AttrValue(String);

impl AttrValue {
    /// Validate a value.
    ///
    /// # Errors
    /// [`SelectorError`] if it is empty, over 64 bytes, or outside the alphabet.
    pub fn new(value: &str) -> Result<Self, SelectorError> {
        if value.is_empty() || value.len() > MAX_ATTR_VALUE || !value.bytes().all(in_alphabet) {
            return refuse(format!(
                "attribute value {value:?} must be 1-{MAX_ATTR_VALUE} bytes of [A-Za-z0-9._-]"
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// The value text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for AttrValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

/// The attributes of one device that selectors can match. Every field is optional; a device
/// that omits one never matches a selector on it.
///
/// Consumers embed this as an optional `"attributes"` object on a device entry:
/// `{"site": "emea-lon", "vendor": "junos", "tags": ["pci"]}`. Unknown keys and invalid
/// values fail the inventory load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAttrs {
    /// Site the device belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<AttrValue>,
    /// Vendor family (for example `junos`, `panos`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<AttrValue>,
    /// Free-form tags.
    #[serde(
        default,
        deserialize_with = "bounded_tags",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tags: Vec<AttrValue>,
}

fn bounded_tags<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<AttrValue>, D::Error> {
    let tags = Vec::<AttrValue>::deserialize(deserializer)?;
    if tags.len() > MAX_TAGS {
        return Err(serde::de::Error::custom(format!(
            "more than {MAX_TAGS} tags"
        )));
    }
    Ok(tags)
}

/// The closed set of attribute keys a selector may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrKey {
    /// `site=...`
    Site,
    /// `vendor=...`
    Vendor,
    /// `tag=...` (matches if any tag matches)
    Tag,
}

/// A literal, or a glob in which `*` is the only metacharacter.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    /// The text split on `*`: one part is a literal, n+1 parts have n stars.
    parts: Vec<String>,
}

impl Pattern {
    fn parse(text: &str) -> Result<Self, SelectorError> {
        if text.is_empty() || text.len() > MAX_ATTR_VALUE {
            return refuse(format!("selector value must be 1-{MAX_ATTR_VALUE} bytes"));
        }
        if !text.bytes().all(|byte| in_alphabet(byte) || byte == b'*') {
            return refuse(format!(
                "selector value {text:?} may only use [A-Za-z0-9._-] and '*'"
            ));
        }
        if text.contains("**") {
            return refuse(format!("selector value {text:?} has adjacent '*'"));
        }
        Ok(Self {
            parts: text.split('*').map(str::to_owned).collect(),
        })
    }

    fn matches(&self, candidate: &AttrValue) -> bool {
        let text = candidate.as_str();
        let [first, middle @ .., last] = self.parts.as_slice() else {
            return self.parts[0] == text;
        };
        let Some(mut rest) = text.strip_prefix(first.as_str()) else {
            return false;
        };
        for part in middle {
            let Some(found) = rest.find(part.as_str()) else {
                return false;
            };
            rest = &rest[found + part.len()..];
        }
        rest.ends_with(last.as_str())
    }
}

/// One compiled `key=pattern` expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    key: AttrKey,
    pattern: Pattern,
}

impl FromStr for Selector {
    type Err = SelectorError;

    fn from_str(expression: &str) -> Result<Self, Self::Err> {
        let Some((key, value)) = expression.split_once('=') else {
            return refuse(format!("selector {expression:?} is not key=value"));
        };
        let key = match key {
            "site" => AttrKey::Site,
            "vendor" => AttrKey::Vendor,
            "tag" => AttrKey::Tag,
            other => return refuse(format!("unknown selector key {other:?}")),
        };
        Ok(Self {
            key,
            pattern: Pattern::parse(value)?,
        })
    }
}

impl Selector {
    /// Whether a device's attributes satisfy this selector.
    #[must_use]
    pub fn matches(&self, attrs: &DeviceAttrs) -> bool {
        match self.key {
            AttrKey::Site => attrs.site.as_ref().is_some_and(|v| self.pattern.matches(v)),
            AttrKey::Vendor => attrs
                .vendor
                .as_ref()
                .is_some_and(|v| self.pattern.matches(v)),
            AttrKey::Tag => attrs.tags.iter().any(|tag| self.pattern.matches(tag)),
        }
    }
}

/// A non-empty conjunction of selectors: a device matches only if every selector does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorSet(Vec<Selector>);

impl SelectorSet {
    /// Compile expressions; one bad expression refuses the whole set.
    ///
    /// # Errors
    /// [`SelectorError`] for an empty list, more than 8 expressions, or any bad expression.
    pub fn compile(expressions: &[String]) -> Result<Self, SelectorError> {
        if expressions.is_empty() || expressions.len() > 8 {
            return refuse("device_selectors needs 1-8 expressions");
        }
        let selectors = expressions
            .iter()
            .map(|expression| expression.parse())
            .collect::<Result<Vec<Selector>, _>>()?;
        Ok(Self(selectors))
    }

    /// Whether every selector matches.
    #[must_use]
    pub fn matches(&self, attrs: &DeviceAttrs) -> bool {
        self.0.iter().all(|selector| selector.matches(attrs))
    }
}

/// A live view of device attributes. Implemented by a consumer over its inventory; called on
/// each authentication, so a reloaded inventory takes effect on the next request.
pub trait DeviceAttributeSource: Send + Sync {
    /// Every device name with its attributes (devices without attributes may be omitted).
    fn device_attributes(&self) -> Vec<(String, DeviceAttrs)>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn attrs(site: &str) -> DeviceAttrs {
        DeviceAttrs {
            site: Some(AttrValue::new(site).unwrap()),
            ..DeviceAttrs::default()
        }
    }

    fn selector(text: &str) -> Selector {
        text.parse().unwrap()
    }

    #[test]
    fn valid_expressions_compile() {
        for text in [
            "site=emea-*",
            "vendor=panos",
            "tag=pci",
            "site=*",
            "site=a*b*c",
            "site=*-1",
        ] {
            assert!(text.parse::<Selector>().is_ok(), "{text}");
        }
    }

    #[test]
    fn bad_expressions_are_refused() {
        for text in [
            "",
            "site",
            "site=",
            "=x",
            "region=emea",
            "Site=emea",
            " site=emea",
            "site =emea",
            "site=emea-?",
            "site=emea-[a]",
            "site=emea|apac",
            "site=a**b",
            "site=emea\0",
            "site=emea\n",
            "site=emea\u{200b}",
            "site=ém",
            "site=emea=x",
            "site=emea ",
            "site=(emea)",
            "site=emea-\\*",
        ] {
            assert!(text.parse::<Selector>().is_err(), "{text:?}");
        }
        assert!(
            format!("site={}", "a".repeat(65))
                .parse::<Selector>()
                .is_err()
        );
        assert!(SelectorSet::compile(&[]).is_err());
    }

    #[test]
    fn attribute_values_reject_what_selectors_could_not_match_safely() {
        for text in [
            "",
            "emea 1",
            "emea\0",
            "emea\u{2010}1",
            "émea",
            "emea*",
            "a/b",
        ] {
            assert!(AttrValue::new(text).is_err(), "{text:?}");
        }
        let bad = r#"{"site":"emea\u00001"}"#;
        assert!(serde_json::from_str::<DeviceAttrs>(bad).is_err());
        assert!(serde_json::from_str::<DeviceAttrs>(r#"{"region":"x"}"#).is_err());
    }

    /// The multi-tenant boundary: `site=emea-*` against every lookalike we can think of.
    #[test]
    fn emea_selector_cannot_reach_another_site() {
        let emea = selector("site=emea-*");
        for hit in ["emea-1", "emea-lon-2", "emea-"] {
            assert!(emea.matches(&attrs(hit)), "{hit}");
        }
        for miss in [
            "apac-1", "EMEA-1", "emea", "xemea-1", "emea_1", "emea.1", "emea1",
        ] {
            assert!(!emea.matches(&attrs(miss)), "{miss}");
        }
        // Unicode hyphen, NUL, bidi, fullwidth and trailing-space lookalikes cannot even be built.
        for lookalike in [
            "emea\u{2010}1",
            "emea-1\0",
            "emea\u{2212}1",
            "\u{202e}emea-1",
            "ｅｍｅａ-1",
            "emea-1 ",
        ] {
            assert!(AttrValue::new(lookalike).is_err(), "{lookalike:?}");
        }
    }

    #[test]
    fn a_device_without_the_attribute_matches_nothing() {
        assert!(!selector("site=*").matches(&DeviceAttrs::default()));
        assert!(!selector("tag=*").matches(&DeviceAttrs::default()));
        assert!(!selector("vendor=*").matches(&attrs("emea-1")));
    }

    #[test]
    fn glob_shapes() {
        let hit = |pattern: &str, value: &str| {
            selector(&format!("site={pattern}")).matches(&attrs(value))
        };
        assert!(hit("a*b*c", "abc") && hit("a*b*c", "aXXbYYc") && !hit("a*b*c", "acb"));
        assert!(hit("*-1", "emea-1") && !hit("*-1", "emea-12"));
        assert!(
            hit("a*a", "aa") && !hit("a*a", "a"),
            "prefix and suffix may not overlap"
        );
        assert!(hit("emea", "emea") && !hit("emea", "emea-1"));
    }

    #[test]
    fn attrs_round_trip_and_omit_absent_fields() {
        let json = r#"{"site":"lab-1","tags":["pci"]}"#;
        let parsed: DeviceAttrs = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
        assert_eq!(
            serde_json::to_string(&DeviceAttrs::default()).unwrap(),
            "{}"
        );
    }

    #[test]
    fn tags_match_any_and_selectors_conjoin() {
        let device = DeviceAttrs {
            site: Some(AttrValue::new("lab-1").unwrap()),
            vendor: Some(AttrValue::new("junos").unwrap()),
            tags: vec![
                AttrValue::new("pci").unwrap(),
                AttrValue::new("edge").unwrap(),
            ],
        };
        let both = SelectorSet::compile(&["site=lab-*".into(), "tag=pci".into()]).unwrap();
        assert!(both.matches(&device));
        let one_fails =
            SelectorSet::compile(&["site=lab-*".into(), "vendor=panos".into()]).unwrap();
        assert!(!one_fails.matches(&device));
    }
}

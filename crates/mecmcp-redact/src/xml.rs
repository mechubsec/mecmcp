//! Denylist-and-shape redaction over XML: NETCONF `<rpc-reply>` bodies and
//! vendor REST responses that come back as XML rather than JSON.
//!
//! Hand-rolling an XML scanner for this is exactly the trap the
//! parser-differentials lens warns about — two ad hoc scanners disagreeing
//! about where a tag ends is how a secret slips through the gap. This uses
//! `quick-xml`, the same parser family already vetted for this ecosystem
//! (`rustpanosmcp` depends on it), and rejects rather than guesses on
//! malformed input: [`redact`] returns [`crate::RedactError::InvalidXml`]
//! instead of emitting a best-effort partial result.

use crate::RedactError;
use crate::denylist::{
    is_bgp_community_tag, is_bgp_scope_key, is_denylisted_key, is_inert_session_value,
    is_session_config_name, normalize,
};
use crate::profile::Opts;
use crate::shape::looks_like_secret_value;
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesRef, BytesStart, BytesText, Event};
use quick_xml::name::QName;
use quick_xml::{Reader, Writer};
use std::borrow::Cow;
use std::io::Cursor;

const PLACEHOLDER: &[u8] = b"[REDACTED]";

/// Redact secret element text and attribute values out of an XML document.
///
/// # Errors
/// Returns [`RedactError::InvalidXml`] when `input` does not parse as XML —
/// this crate never falls back to returning the input unredacted just
/// because it could not be understood.
pub fn redact(input: &str) -> Result<String, RedactError> {
    redact_impl(
        input,
        &|_| false,
        &|_| false,
        Opts::NONE,
        &crate::text::redact,
        None,
    )
}

/// Same as [`redact`], but `extra_exact_elem` names additional element local
/// names (exact match, namespace-stripped) that are secret-bearing on their
/// own — used by [`crate::junos`] for element names (`value`) that are too
/// generic to add to the shared [`crate::denylist`] without over-redacting
/// every other vendor's XML, but that a vendor-specific profile's own closed
/// element vocabulary can still treat as unconditionally sensitive. An
/// attribute whose local name matches is masked too.
///
/// `exempt_elem` names element local names whose denylist match on the
/// *name* alone is waived when the value under decision is benign (empty or
/// digits only); see [`any_ancestor_secret`]. This is independent of
/// [`crate::Profile::with_session_config_values`], which is opt-in and uses
/// a stricter integer bound.
///
/// `scan` runs over character data, processing instructions and DOCTYPE
/// declarations, and here also over attribute values not otherwise masked
/// and comment bodies. The generic pass leaves those two to its shape
/// checks, because its substring denylist would reach ordinary names such
/// as `session-timeout-profile`.
pub(crate) fn redact_with(
    input: &str,
    extra_exact_elem: &dyn Fn(&str) -> bool,
    exempt_elem: &dyn Fn(&str) -> bool,
    scan: &dyn Fn(&str) -> String,
) -> Result<String, RedactError> {
    redact_impl(
        input,
        extra_exact_elem,
        exempt_elem,
        Opts::NONE,
        scan,
        Some(scan),
    )
}

/// The XML counterpart of [`crate::redact_json_value_with_profile`]: redact
/// `input` the same way [`redact`] does, additionally applying `profile`'s
/// BGP route-community exemption when it opts in via
/// [`crate::Profile::with_bgp_route_communities`] and its session-config
/// exemption when it opts in via
/// [`crate::Profile::with_session_config_values`]. `profile`'s
/// `wholesale_redact_keys` and `key_exemptions` have no XML equivalent yet
/// and are not consulted here.
///
/// # Errors
/// Same as [`redact`].
pub(crate) fn redact_with_profile(
    input: &str,
    profile: &crate::Profile,
) -> Result<String, RedactError> {
    redact_impl(
        input,
        &|_| false,
        &|_| false,
        crate::profile::opts(profile),
        &crate::text::redact,
        None,
    )
}

fn redact_impl(
    input: &str,
    extra_exact_elem: &dyn Fn(&str) -> bool,
    exempt_elem: &dyn Fn(&str) -> bool,
    opts: Opts,
    scan: &dyn Fn(&str) -> String,
    markup_scan: Option<&dyn Fn(&str) -> String>,
) -> Result<String, RedactError> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut tag_stack: Vec<Vec<u8>> = Vec::new();
    // quick-xml chunks element text at every entity/character reference,
    // reporting `&#x73;ecret` as `Text("")`, `GeneralRef("#x73;")`,
    // `Text("ecret")` — three events for one node, split wherever the
    // upstream serializer happened to escape a byte (`&quot;`, `&amp;`,
    // `&lt;`, any numeric reference). Deciding redaction per event lets a
    // reference carry secret bytes past the check on either side of it —
    // `pre-shared-key ascii-text "FAKE"` becomes `&quot;FAKE&quot;` from a
    // spec-compliant serializer and the literal secret text on either side
    // of the quotes was never joined with it for the shape/key scan. A CDATA
    // section is the same character data (`privacy-key <![CDATA[x]]>`), so
    // every contiguous run of `Text`/`GeneralRef`/`CData` events is buffered
    // here and handed to the redaction decision exactly once, when the run
    // ends.
    let mut text_run = CharRun::default();

    loop {
        let event = reader
            .read_event()
            .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
        if !matches!(
            event,
            Event::Text(_) | Event::GeneralRef(_) | Event::CData(_)
        ) {
            flush_text_run(
                &mut writer,
                &mut text_run,
                &tag_stack,
                extra_exact_elem,
                exempt_elem,
                opts,
                scan,
            )?;
        }
        match event {
            Event::Eof => {
                if let Some(unclosed) = tag_stack.last() {
                    return Err(RedactError::InvalidXml(format!(
                        "unclosed element <{}>",
                        String::from_utf8_lossy(unclosed)
                    )));
                }
                break;
            }
            Event::Start(e) => {
                tag_stack.push(local_name(e.name()).to_vec());
                let rewritten = redact_attributes(
                    &e,
                    &tag_stack,
                    extra_exact_elem,
                    exempt_elem,
                    opts,
                    markup_scan,
                )?;
                writer
                    .write_event(Event::Start(rewritten))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::Empty(e) => {
                // An empty element (`<community name="..."/>`) is its own
                // open-and-close in one event — it never reaches the
                // `Event::Start`/`Event::End` pair that pushes its name onto
                // `tag_stack`, so without pushing it here a denylisted
                // element name on the empty form fails to redact its own
                // attributes even though the non-empty `<community
                // name="..."></community>` form does (N4).
                tag_stack.push(local_name(e.name()));
                let rewritten = redact_attributes(
                    &e,
                    &tag_stack,
                    extra_exact_elem,
                    exempt_elem,
                    opts,
                    markup_scan,
                )?;
                tag_stack.pop();
                writer
                    .write_event(Event::Empty(rewritten))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::End(e) => {
                tag_stack.pop();
                writer
                    .write_event(Event::End(e))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::Text(e) => {
                // quick-xml 0.42 stores text as `str`: deref yields the raw,
                // still-escaped content, same as 0.41's `decode()` for a
                // `Reader::from_str` source.
                let raw: &str = &e;
                let decoded = quick_xml::escape::unescape(raw)
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
                text_run.push_text(&decoded);
            }
            // quick-xml emits `&amp;`, `&#x73;`, etc. as their own event
            // rather than folding them into the surrounding `Text` — see the
            // comment on `text_run` above. Resolve it to the literal
            // character(s) it represents and fold it into the same buffer as
            // the text around it, so the redaction decision below sees one
            // joined string instead of pieces split at the reference.
            Event::GeneralRef(e) => text_run.push_text(&resolve_general_ref(&e)?),
            Event::CData(e) => text_run.push_cdata(&e.into_inner()),
            Event::Comment(e) => {
                let redacted = match markup_scan {
                    Some(markup_scan) => markup_scan(&redact_comment(&e)),
                    None => redact_comment(&e),
                };
                writer
                    .write_event(Event::Comment(BytesText::from_escaped(escape_text(
                        &redacted,
                    ))))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            other => {
                if let Some(event) = redact_pi_or_doctype(other, scan) {
                    writer
                        .write_event(event)
                        .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
                }
            }
        }
    }

    String::from_utf8(writer.into_inner().into_inner())
        .map_err(|e| RedactError::InvalidXml(e.to_string()))
}

/// Fail-closed pass over a processing instruction or DOCTYPE, which would
/// otherwise reach the output unscanned. A PI whose text (target included)
/// `scan` would change is dropped. A DOCTYPE always loses its internal
/// subset, whose entity values can hide a key behind a character reference
/// (`pass&#x77;ord`); the rest (root name and external ID) is kept verbatim,
/// unless `scan` would change it, in which case the DOCTYPE is dropped.
/// Dropping either is always well-formed. Every other event (the XML
/// declaration included) passes through.
fn redact_pi_or_doctype<'a>(event: Event<'a>, scan: &dyn Fn(&str) -> String) -> Option<Event<'a>> {
    let (body, subset): (&str, Option<usize>) = match &event {
        Event::PI(e) => (e, None),
        Event::DocType(e) => (e, internal_subset_start(e)),
        _ => return Some(event),
    };
    let Some(subset) = subset else {
        return (scan(body) == body).then_some(event);
    };
    let kept = body.get(..subset)?.trim().to_owned();
    (scan(&kept) == kept).then(|| Event::DocType(BytesText::from_escaped(kept)))
}

/// Byte offset of the `[` that opens a DOCTYPE's internal subset: the first
/// one outside a quoted literal, as quick-xml's DTD parser finds it
/// (`SYSTEM "a[b.dtd"` has no subset).
fn internal_subset_start(doctype: &str) -> Option<usize> {
    let mut quote = None;
    doctype.char_indices().find_map(|(i, c)| {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '[' => return Some(i),
            None => {}
        }
        None
    })
}

fn local_name(name: QName<'_>) -> Vec<u8> {
    name.local_name().as_ref().as_bytes().to_vec()
}

/// Validate that `input` is well-formed XML — every element opened is closed
/// before EOF — without redacting or otherwise transforming it.
///
/// This is the same depth tracking [`redact`] does via `tag_stack`, factored
/// out so `redact_xml_str`'s disabled-policy passthrough (which must not
/// redact, but still must not become a way to skip the "this is valid XML"
/// check every other entry point enforces) can reuse it instead of running a
/// second, easily-drifting scan loop (N7).
///
/// # Errors
/// Returns [`RedactError::InvalidXml`] on a parse error or an element left
/// open at EOF.
pub(crate) fn validate(input: &str) -> Result<(), RedactError> {
    let mut reader = Reader::from_str(input);
    let mut depth: usize = 0;
    loop {
        match reader
            .read_event()
            .map_err(|e| RedactError::InvalidXml(e.to_string()))?
        {
            Event::Eof => {
                return if depth > 0 {
                    Err(RedactError::InvalidXml(
                        "unclosed element at end of input".to_string(),
                    ))
                } else {
                    Ok(())
                };
            }
            Event::Start(_) => depth += 1,
            Event::End(_) => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
}

/// Whether any element currently open (not just the immediate parent) is a
/// denylisted key — a Junos SNMP community landing in `<name>` under
/// `<community>`, or a PSK in `<ascii-text>` under `<pre-shared-key>`, both
/// have a *grandparent*, not a parent, that names the secret — or matches
/// `extra_exact_elem` (see [`redact_with`]).
///
/// The per-ancestor BGP exemption below agrees with
/// `json::looks_like_bgp_community_value`'s scope exactly: it checks that a
/// `bgp` element is strictly above the `community` element, not merely open
/// anywhere in the stack, and only accepts the `member`/`members` child
/// shape rather than any child element name. The exemption only ever
/// applies to a shared-denylist match, never to `extra_exact_elem` — a
/// vendor profile opting an element name into `extra_exact_elem` treats it
/// as unconditionally sensitive.
///
/// `opts` gates which profile exemptions are consulted at all — see
/// [`crate::profile::Profile::with_bgp_route_communities`] and
/// [`crate::profile::Profile::with_session_config_values`].
///
/// `exempt_elem` is the Junos keyword waiver (see [`redact_with`]): an
/// exempt name does not make an empty or numeric value secret. It does not
/// replace the profile session flag, which uses [`is_inert_session_value`]'s
/// 12-digit bound and stays off unless the profile opts in.
fn any_ancestor_secret(
    tag_stack: &[Vec<u8>],
    value: &str,
    extra_exact_elem: &dyn Fn(&str) -> bool,
    exempt_elem: &dyn Fn(&str) -> bool,
    opts: Opts,
) -> bool {
    tag_stack.iter().enumerate().any(|(i, name)| {
        let name = String::from_utf8_lossy(name);
        if extra_exact_elem(&name) {
            return true;
        }
        if !is_denylisted_key(&name) {
            return false;
        }
        if opts.session_config_values
            && is_session_config_name(&name)
            && is_inert_session_value(value)
        {
            return false;
        }
        // Value-aware waiver: an exempt element name (a closed vendor
        // keyword) does not make an empty or numeric value secret, but any
        // other text under it still is.
        if exempt_elem(&name) && is_benign_value(value) {
            return false;
        }
        !(opts.bgp_route_communities && is_bgp_route_community_ancestor(tag_stack, i, value))
    })
}

/// Whether `value` carries no secret-bearing content on its own: empty or
/// whitespace, or ASCII digits only (a counter or limit).
fn is_benign_value(value: &str) -> bool {
    let v = value.trim();
    v.is_empty() || v.bytes().all(|b| b.is_ascii_digit())
}

/// Whether the denylisted ancestor at `tag_stack[i]` is a BGP route-community
/// element exempted from redaction — the XML counterpart of
/// `json::looks_like_bgp_community_value`'s scope.
///
/// Exempt only when all of these hold:
/// - `tag_stack[i]` is a `community` element (the same bare field name an
///   SNMP community string uses — see [`is_bgp_community_tag`]'s doc);
/// - a `bgp` scope element is an ancestor *of that `community` element*
///   (`tag_stack[..i]`, not the whole stack — a `bgp` element nested *inside*
///   `community` does not count);
/// - `value` itself looks like BGP community-tag syntax;
/// - and `value`'s immediate container is either `<community>` directly
///   (`i == tag_stack.len() - 1`), or exactly one `<member>`/`<members>`
///   element nested inside it (`i + 2 == tag_stack.len()`) — any other child
///   element name under `<community>` is not the known BGP shape and must
///   still be redacted.
fn is_bgp_route_community_ancestor(tag_stack: &[Vec<u8>], i: usize, value: &str) -> bool {
    if normalize(&String::from_utf8_lossy(&tag_stack[i])) != "community" {
        return false;
    }
    let under_bgp = tag_stack[..i]
        .iter()
        .any(|name| is_bgp_scope_key(&String::from_utf8_lossy(name)));
    if !under_bgp || !is_bgp_community_tag(value) {
        return false;
    }
    let len = tag_stack.len();
    if i == len - 1 {
        return true;
    }
    i + 2 == len
        && matches!(
            normalize(&String::from_utf8_lossy(&tag_stack[len - 1])).as_str(),
            "member" | "members"
        )
}

fn redact_attributes<'a>(
    start: &BytesStart<'a>,
    tag_stack: &[Vec<u8>],
    extra_exact_elem: &dyn Fn(&str) -> bool,
    exempt_elem: &dyn Fn(&str) -> bool,
    opts: Opts,
    markup_scan: Option<&dyn Fn(&str) -> String>,
) -> Result<BytesStart<'a>, RedactError> {
    let mut out = BytesStart::new(start.name().as_ref().to_owned());
    for attr in start.attributes() {
        let attr = attr.map_err(|e| RedactError::InvalidXml(e.to_string()))?;
        let key = String::from_utf8_lossy(local_name(attr.key).as_slice()).into_owned();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|e| RedactError::InvalidXml(e.to_string()))?
            .into_owned();
        let ancestor_is_secret =
            any_ancestor_secret(tag_stack, &value, extra_exact_elem, exempt_elem, opts);
        let redacted_value = if ancestor_is_secret
            || is_denylisted_key(&key)
            || extra_exact_elem(&key)
            || looks_like_secret_value(&value)
        {
            String::from_utf8_lossy(PLACEHOLDER).into_owned()
        } else if let Some(markup_scan) = markup_scan {
            markup_scan(&value)
        } else {
            value
        };
        // Built directly rather than via `(&str, &str).into()`, which since
        // quick-xml 0.42 also escapes `\r`/`\n`/`\t` — see [`escape_text`].
        out.push_attribute(Attribute {
            key: attr.key,
            value: Cow::Owned(escape_text(&redacted_value)),
        });
    }
    Ok(out)
}

/// A maximal run of adjacent character data (`Text`, `GeneralRef` and
/// `CData` events), resolved and joined in document order.
#[derive(Default)]
struct CharRun {
    /// Every finished piece, joined.
    joined: String,
    /// The `Text`/`GeneralRef` piece still being read.
    text: Option<String>,
    /// Finished pieces: each CDATA section and each text/reference run.
    pieces: usize,
    /// The last finished piece was a CDATA section.
    last_is_cdata: bool,
    /// Some piece has a secret shape on its own (the per-node check), so
    /// joining it to a neighbour (`x` + `$9$...`) cannot hide it.
    piece_is_secret: bool,
}

impl CharRun {
    fn push_text(&mut self, text: &str) {
        self.text.get_or_insert_with(String::new).push_str(text);
    }

    fn push_cdata(&mut self, body: &str) {
        self.end_text();
        self.add_piece(body, true);
    }

    fn end_text(&mut self) {
        if let Some(text) = self.text.take() {
            self.add_piece(&text, false);
        }
    }

    fn add_piece(&mut self, piece: &str, is_cdata: bool) {
        self.pieces += 1;
        self.last_is_cdata = is_cdata;
        self.piece_is_secret |= looks_like_secret_value(piece);
        self.joined.push_str(piece);
    }
}

/// Flush a buffered character-data run as a single redaction decision,
/// writing nothing if the run is empty. A lone CDATA section keeps its CDATA
/// form; any other run is written as one escaped text node.
///
/// `tag_stack` must reflect its state as it was *during* the run — callers
/// flush before mutating `tag_stack` for the event that ended the run, so
/// the stack passed to [`any_ancestor_secret`] still matches.
fn flush_text_run(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    text_run: &mut CharRun,
    tag_stack: &[Vec<u8>],
    extra_exact_elem: &dyn Fn(&str) -> bool,
    exempt_elem: &dyn Fn(&str) -> bool,
    opts: Opts,
    scan: &dyn Fn(&str) -> String,
) -> Result<(), RedactError> {
    let mut run = std::mem::take(text_run);
    run.end_text();
    if run.pieces == 0 {
        return Ok(());
    }
    let joined = &run.joined;
    let body = if run.piece_is_secret
        || looks_like_secret_value(joined)
        || any_ancestor_secret(tag_stack, joined, extra_exact_elem, exempt_elem, opts)
    {
        String::from_utf8_lossy(PLACEHOLDER).into_owned()
    } else {
        // Scan every run, not just ones that already look like a multi-line
        // blob or PEM — a single-line `user login password=X ok` payload (a
        // Mist event, syslog-as-JSON) needs the same `k=v` scan (N5).
        // `text::redact`'s non-forced path only touches known value shapes,
        // so this is a no-op on ordinary text.
        scan(joined)
    };
    if run.pieces == 1 && run.last_is_cdata {
        // A scan can turn `"x"]>` into `[REDACTED]]>`, which would end the
        // section early; split at every `]]>` (`]]]]><![CDATA[>`).
        for section in quick_xml::events::BytesCData::escaped(&body) {
            writer
                .write_event(Event::CData(section))
                .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
        }
        return Ok(());
    }
    writer
        .write_event(Event::Text(BytesText::from_escaped(escape_text(&body))))
        .map_err(|e| RedactError::InvalidXml(e.to_string()))
}

/// Resolve a `GeneralRef` (`&#x..;`, `&amp;`, …) to the literal text it
/// represents, so it can join the same buffer as the surrounding `Text`
/// events instead of being redacted (or not) as an opaque, uninspected
/// fragment. Fails closed on an entity this crate cannot resolve rather
/// than guessing at — or silently dropping — its content.
fn resolve_general_ref(e: &BytesRef<'_>) -> Result<String, RedactError> {
    if let Some(ch) = e
        .resolve_char_ref()
        .map_err(|err| RedactError::InvalidXml(err.to_string()))?
    {
        return Ok(ch.to_string());
    }
    let name: &str = e;
    quick_xml::escape::resolve_predefined_entity(name)
        .map(str::to_string)
        .ok_or_else(|| RedactError::InvalidXml(format!("unresolved entity reference &{name};")))
}

/// Escape `<`, `>`, `&`, `'` and `"` — exactly the set quick-xml 0.41's
/// `escape` (used by `BytesText::new` and `Attribute::from((&str, &str))`)
/// replaced.
///
/// quick-xml 0.42 widened that set to also turn `\r` into `&#13;` (text and
/// attributes) and `\n`/`\t` into `&#10;`/`&#9;` (attributes). Pinning the
/// old set keeps this crate's output byte-identical across the upgrade: a
/// CRLF text node passes through as CRLF rather than gaining `&#13;`, which
/// would change what a downstream parser reads. Only the escaping of
/// *output* is affected; what gets redacted is decided before this runs.
fn escape_text(raw: &str) -> String {
    if !raw.contains(['<', '>', '&', '\'', '"']) {
        return raw.to_owned();
    }
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

fn redact_comment(text: &str) -> String {
    if let Some(idx) = text.find("## SECRET-DATA") {
        let (prefix, suffix) = text.split_at(idx);
        if prefix.trim().is_empty() {
            return text.to_string();
        }
        return format!("{}{suffix}", String::from_utf8_lossy(PLACEHOLDER));
    }
    if looks_like_secret_value(text) {
        return String::from_utf8_lossy(PLACEHOLDER).into_owned();
    }
    text.to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;

    #[test]
    fn denylisted_element_text_is_redacted() {
        let xml = r#"<config><pre-shared-key>FAKEpsk12345</pre-shared-key></config>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKEpsk12345"), "got: {got}");
    }

    #[test]
    fn denylisted_attribute_value_is_redacted() {
        let xml = r#"<user password="FAKEhunter2"/>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKEhunter2"), "got: {got}");
    }

    #[test]
    fn nested_element_under_repeated_sibling_tags_is_redacted() {
        let xml = r#"<peers><peer><name>p1</name><psk>FAKEpsk1</psk></peer><peer><name>p2</name><psk>FAKEpsk2</psk></peer></peers>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKEpsk1"), "got: {got}");
        assert!(!got.contains("FAKEpsk2"), "got: {got}");
        assert!(got.contains("p1") && got.contains("p2"));
    }

    #[test]
    fn value_shape_catch_all_applies_to_unknown_element_names() {
        let xml = r#"<totally-new-vendor-field>$6$fakesaltfakehash</totally-new-vendor-field>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("fakesaltfakehash"), "got: {got}");
    }

    #[test]
    fn unrelated_elements_are_untouched() {
        let xml = r#"<host><name>r1.example.net</name><vlan>100</vlan></host>"#;
        let got = redact(xml).unwrap();
        assert_eq!(got, xml);
    }

    #[test]
    fn malformed_xml_is_rejected_not_passed_through() {
        let err = redact("<unclosed><tag>").unwrap_err();
        assert!(matches!(err, RedactError::InvalidXml(_)));
    }

    #[test]
    fn f4a_denylisted_grandparent_element_redacts_descendant_text() {
        let xml = r#"<snmp><community><name>QQcommunity1</name></community></snmp>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQcommunity1"), "got: {got}");
    }

    #[test]
    fn f4a_denylisted_grandparent_redacts_nested_ascii_text() {
        let xml = r#"<pre-shared-key><ascii-text>QQpsk1</ascii-text></pre-shared-key>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQpsk1"), "got: {got}");
    }

    #[test]
    fn f4b_configuration_text_blob_is_scrubbed_for_embedded_secrets() {
        let xml = r#"<rpc-reply><configuration-text>set interfaces ge-0/0/0 unit 0
set security ike policy p1 pre-shared-key ascii-text "$9$fakehashvalue"; ## SECRET-DATA
</configuration-text></rpc-reply>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("fakehashvalue"), "got: {got}");
        assert!(
            got.contains("set interfaces ge-0/0/0 unit 0"),
            "unrelated config lines must survive: {got}"
        );
    }

    #[test]
    fn f4b_command_output_blob_is_scrubbed() {
        let xml = r#"<output>root:$6$fakesaltfakehash:19000:0:99999:7:::
another line</output>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("fakesaltfakehash"), "got: {got}");
        assert!(got.contains("another line"), "got: {got}");
    }

    // --- N4: a denylisted element name on the self-closing `Empty` form
    // must redact its own attributes exactly like the `Start`/`End` form. ---

    #[test]
    fn n4_denylisted_empty_element_attribute_is_redacted() {
        let xml = r#"<snmp><community name="QQcomm1"/></snmp>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQcomm1"), "got: {got}");
    }

    #[test]
    fn n4_denylisted_empty_element_under_entry_is_redacted() {
        let xml = r#"<entry><password value="QQpw2"/></entry>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQpw2"), "got: {got}");
    }

    // --- N5: a single-line `k=v` secret inside an otherwise ordinary text
    // node must be caught by the text-path scan, not just multi-line blobs
    // or PEM/`SECRET-DATA` markers. ---

    #[test]
    fn n5_single_line_kv_secret_in_text_node_is_redacted() {
        // X1 (mecmcp#386 re-review): the value locator redacts to the end
        // of the text node once the key is found, so trailing text after
        // the secret (`ok`) is swept too — the accepted over-redaction
        // cost; only the text *before* the key is unaffected.
        let xml = "<message>user login password=QQvalue9 ok</message>";
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQvalue9"), "got: {got}");
        assert!(got.contains("user login"), "got: {got}");
    }

    // --- quick-xml 0.42 widened its output escaping (`\r` in text,
    // `\r`/`\n`/`\t` in attributes). Output must stay byte-identical to the
    // 0.41-era behaviour pinned here. ---

    #[test]
    fn crlf_text_and_comment_pass_through_unescaped() {
        let xml = "<?xml version=\"1.0\"?>\r\n<!-- a < b\r\n --><a>line1\r\nline2</a>";
        let got = redact(xml).unwrap();
        assert_eq!(
            got,
            "<?xml version=\"1.0\"?>\r\n<!-- a &lt; b\r\n --><a>line1\r\nline2</a>"
        );
    }

    #[test]
    fn attribute_whitespace_char_refs_are_not_re_escaped() {
        let xml = r#"<a x="v&#10;w" y="t&#9;u" z="c&#13;d" q="&amp;&lt;&gt;&quot;&apos;"/>"#;
        let got = redact(xml).unwrap();
        assert_eq!(
            got,
            "<a x=\"v\nw\" y=\"t\tu\" z=\"c\rd\" q=\"&amp;&lt;&gt;&quot;&apos;\"/>"
        );
    }

    // --- N8: quick-xml reports a character or entity reference (`&#x..;`,
    // `&amp;`) as its own `GeneralRef` event, separate from the surrounding
    // `Text` events. Under a denylisted ancestor these must collapse into
    // the same redaction marker as the text around them, not pass through
    // unredacted. ---

    #[test]
    fn n8_partial_ref_secret_is_fully_redacted() {
        // "s" is written as a character reference, "ecret" as plain text.
        let xml = "<password>&#x73;ecret</password>";
        let got = redact(xml).unwrap();
        assert_eq!(got, "<password>[REDACTED]</password>", "got: {got}");
    }

    #[test]
    fn n8_all_ref_secret_is_fully_redacted() {
        // The whole secret is spelled out as character references.
        let xml = "<password>&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;</password>";
        let got = redact(xml).unwrap();
        assert!(!got.contains('&'), "got: {got}");
        assert!(got.contains("[REDACTED]"), "got: {got}");
    }

    #[test]
    fn n8_named_entity_in_secret_is_redacted() {
        let xml = "<password>sec&amp;ret</password>";
        let got = redact(xml).unwrap();
        assert_eq!(got, "<password>[REDACTED]</password>", "got: {got}");
    }

    #[test]
    fn n8_mixed_text_and_ref_secret_collapses_to_one_marker() {
        let xml = "<password>se&#x63;r&amp;et</password>";
        let got = redact(xml).unwrap();
        assert_eq!(got, "<password>[REDACTED]</password>", "got: {got}");
    }

    #[test]
    fn n8_ref_outside_denylisted_element_is_untouched() {
        let xml = "<host>AT&amp;T</host>";
        let got = redact(xml).unwrap();
        assert_eq!(got, xml, "got: {got}");
    }

    #[test]
    fn n8_denylisted_grandparent_redacts_ref_in_descendant_text() {
        let xml = "<pre-shared-key><ascii-text>&#x70;&#x73;&#x6b;</ascii-text></pre-shared-key>";
        let got = redact(xml).unwrap();
        assert!(!got.contains('&'), "got: {got}");
        assert!(got.contains("[REDACTED]"), "got: {got}");
    }

    // --- F1 (MEC-921 review of this PR): a reference inside plain text
    // (not under a denylisted *element*) must not split the denylisted-key
    // / shape scan that `text::redact` runs over the joined text node —
    // any serializer that escapes `"`, `&`, or `<` in text (quick-xml's own
    // writer among them) would otherwise let the key/value scan see only a
    // fragment on one side of the reference and miss the secret. ---

    #[test]
    fn f1_named_entity_quote_does_not_split_keyed_value() {
        let xml = "<output>security ike policy p1 pre-shared-key ascii-text &quot;FAKEhunter2&quot;</output>";
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKEhunter2"), "got: {got}");
        assert!(got.contains("[REDACTED]"), "got: {got}");
    }

    #[test]
    fn f1_named_entity_amp_does_not_split_keyed_value() {
        let xml = "<output>set snmp community pub&amp;FAKElic read-only</output>";
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKElic"), "got: {got}");
    }

    #[test]
    fn f1_named_entity_lt_does_not_split_keyed_value() {
        let xml = "<output>password: ab&lt;FAKEcd</output>";
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKEcd"), "got: {got}");
    }

    #[test]
    fn f1_named_entity_amp_mid_value_does_not_leak_either_half() {
        let xml = "<output>user login password=FAKE&amp;tail ok</output>";
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKE"), "got: {got}");
        assert!(!got.contains("tail"), "got: {got}");
    }

    // --- #591: adjacent text, references and CDATA are one character-data
    // string, so a key in one piece and its value in the next are scanned
    // together. ---

    #[test]
    fn key_in_text_and_value_in_cdata_are_scanned_as_one_run() {
        let got = redact("<o>user login password=<![CDATA[FAKEsplit]]></o>").unwrap();
        assert_eq!(got, "<o>user login password=[REDACTED]</o>");
    }

    #[test]
    fn secret_shaped_cdata_glued_to_text_is_still_masked() {
        let got = redact("<o>x<![CDATA[$9$FAKEglued]]></o>").unwrap(); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real secret
        assert!(!got.contains("FAKEglued"), "got: {got}");
    }

    #[test]
    fn lone_cdata_keeps_its_form_and_a_comment_ends_a_run() {
        for xml in ["<o><![CDATA[a < b]]></o>", "<o>a<!--c--><![CDATA[b]]></o>"] {
            assert_eq!(redact(xml).unwrap(), xml);
        }
    }

    #[test]
    fn generic_attribute_values_and_comments_keep_shape_checks_only() {
        // The generic denylist matches substrings, so a text scan here would
        // reach ordinary other-vendor names; attributes and comments get shape
        // checks only.
        for xml in [
            r#"<entry name="session-timeout-profile"/>"#,
            r#"<entry name="token-policy"/>"#,
            r#"<x msg="set snmp community c1"><!-- token=t1 --></x>"#,
        ] {
            assert_eq!(crate::redact_xml_str(xml).unwrap(), xml);
            let profile = crate::Profile::new(&[], &[]);
            assert_eq!(
                crate::redact_xml_str_with_profile(xml, &profile).unwrap(),
                xml
            );
        }
    }

    #[test]
    fn secret_pi_is_dropped_and_doctype_keeps_only_its_external_part() {
        for (input, want) in [
            ("<?app password=FAKEpi?><o/>", "<o/>"), // gitleaks:allow -- fabricated fixture, not a real password
            // The secret is in the target itself.
            ("<?password:FAKEdt?><o/>", "<o/>"), // gitleaks:allow -- fabricated fixture, not a real password
            // The subset always goes, even when a character reference hides the key.
            (
                r#"<!DOCTYPE o [<!ENTITY e "password=FAKEdt">]><o/>"#,
                "<!DOCTYPE o><o/>",
            ), // gitleaks:allow -- fabricated fixture, not a real password
            (
                r#"<!DOCTYPE o [<!ENTITY e "pass&#x77;ord=FAKEdt">]><o/>"#,
                "<!DOCTYPE o><o/>",
            ), // gitleaks:allow -- fabricated fixture, not a real password
            (
                "<!DOCTYPE a·b [<!ELEMENT a·b EMPTY>]><a·b/>",
                "<!DOCTYPE a·b><a·b/>",
            ),
            (
                r#"<!DOCTYPE o SYSTEM "o.dtd" [<!ELEMENT o EMPTY>]><o/>"#,
                r#"<!DOCTYPE o SYSTEM "o.dtd"><o/>"#,
            ),
            // The kept part is scanned too.
            (r#"<!DOCTYPE o SYSTEM "password=FAKEsy"><o/>"#, "<o/>"), // gitleaks:allow -- fabricated fixture, not a real password
        ] {
            let out = redact(input).unwrap();
            assert_eq!(out, want);
            let mut reader = Reader::from_str(&out);
            while !matches!(reader.read_event().unwrap(), Event::Eof) {}
        }
        for xml in [
            r#"<?xml version="1.0"?><?xml-stylesheet href="a.xsl"?><!DOCTYPE o SYSTEM "o[1].dtd"><o/>"#,
            "<!DOCTYPE a·b><a·b/>",
        ] {
            assert_eq!(redact(xml).unwrap(), xml);
        }
    }
}

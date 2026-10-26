// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! KYAML output: the estate's YAML dialect (`hyperpolymath/standards`
//! `3-practice/YAML-POLICY.adoc`, D280/D307).
//!
//! The emitter follows the KYAML encoder in mikefarah `yq` v4 (the tool
//! behind the estate's `scripts/kyaml-format.sh`): flow style, two-space
//! indent, a trailing comma after every entry, bare keys only when they
//! match `^[A-Za-z_][A-Za-z0-9_-]*$`, and every string double-quoted. Its
//! output is a fixed point of `yq -p yaml -o kyaml`, which is what
//! `kyaml-format.sh --check` tests.
//!
//! The data is the same as the JCS report's: keys in JCS order (UTF-16
//! code units) and numbers in JCS form, so a KYAML report and a JSON report
//! of the same scan differ only in syntax.
//!
//! One deliberate difference from `yq`: YAML's non-printable characters
//! (U+007F to U+009F, U+FFFE, U+FFFF) are escaped as `\uXXXX`. `yq` writes
//! them raw, which YAML 1.2 does not allow, and U+0085 (NEL) written raw
//! reads back as a line break, corrupting the string. Strings holding one
//! are therefore not a `yq` fixed point; `kyaml-format.sh` refuses such a
//! file instead of judging it.

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

const INDENT: usize = 2;

/// Serialise `value` as a KYAML document followed by one line feed.
///
/// Fails if `value` is not I-JSON, for example an integer beyond ±2^53.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let tree = serde_json::to_value(value).context("serializing to JSON")?;
    let mut out = String::new();
    write_node(&mut out, &tree, 0)?;
    out.push('\n');
    Ok(out)
}

fn write_node(out: &mut String, node: &Value, indent: usize) -> Result<()> {
    match node {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(_) => {
            out.push_str(&ijson_jcs::to_jcs_string(node).context("canonicalizing number (JCS)")?)
        }
        Value::String(text) => write_quoted(out, text),
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Array(items) => {
            out.push_str("[\n");
            for item in items {
                pad(out, indent + INDENT);
                write_node(out, item, indent + INDENT)?;
                out.push_str(",\n");
            }
            pad(out, indent);
            out.push(']');
        }
        Value::Object(map) if map.is_empty() => out.push_str("{}"),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push_str("{\n");
            for (key, value) in entries {
                pad(out, indent + INDENT);
                if is_bare_key(key) {
                    out.push_str(key);
                } else {
                    write_quoted(out, key);
                }
                out.push_str(": ");
                write_node(out, value, indent + INDENT)?;
                out.push_str(",\n");
            }
            pad(out, indent);
            out.push('}');
        }
    }
    Ok(())
}

fn pad(out: &mut String, indent: usize) {
    out.extend(std::iter::repeat_n(' ', indent));
}

/// `^[A-Za-z_][A-Za-z0-9_-]*$`, as in `yq`.
fn is_bare_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn write_quoted(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0'..='\u{1F}' | '\u{7F}'..='\u{9F}' | '\u{FFFE}' | '\u{FFFF}' => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_yq_layout() {
        // Expected text is `yq -p json -o kyaml` (v4.54.1) output for the
        // JCS form of `value`.
        let value = json!({
            "a": {}, "b": [], "c": [{}], "d": null, "e": false,
            "k-1": 1, "_x": 2, "9a": 3, "é": 4, "a.b": 5, "": 6,
            "nested": {"list": [1, 0.5, 1e21, "s"]},
        });
        assert_eq!(
            to_string(&value).unwrap(),
            "{\n  \"\": 6,\n  \"9a\": 3,\n  _x: 2,\n  a: {},\n  \"a.b\": 5,\n  b: [],\n  c: [\n    {},\n  ],\n  d: null,\n  e: false,\n  k-1: 1,\n  nested: {\n    list: [\n      1,\n      0.5,\n      1e+21,\n      \"s\",\n    ],\n  },\n  \"é\": 4,\n}\n"
        );
    }

    #[test]
    fn top_level_scalars_and_lists() {
        assert_eq!(to_string("top").unwrap(), "\"top\"\n");
        assert_eq!(to_string(&[1]).unwrap(), "[\n  1,\n]\n");
        assert_eq!(to_string(&()).unwrap(), "null\n");
    }

    #[test]
    fn escapes_like_yq_for_c0_controls() {
        assert_eq!(
            to_string("\u{1}\u{1F}\t\r\n\\\"").unwrap(),
            "\"\\u0001\\u001F\\t\\r\\n\\\\\\\"\"\n"
        );
    }

    #[test]
    fn escapes_non_printables_that_yq_writes_raw() {
        let text = "a\u{7F}\u{85}\u{9F}\u{FFFE}\u{FFFF}\u{A0}\u{2028}z";
        let out = to_string(text).unwrap();
        assert_eq!(
            out,
            "\"a\\u007F\\u0085\\u009F\\uFFFE\\uFFFF\u{A0}\u{2028}z\"\n"
        );
        // ...and they read back intact, NEL included.
        let back: String = crate::yaml::from_str(&out).unwrap();
        assert_eq!(back, text);
    }

    #[test]
    fn keys_follow_jcs_order() {
        // UTF-16 order puts U+10000 (a surrogate pair) before U+FF61;
        // UTF-8 byte order would not.
        let value = json!({"\u{FF61}": 1, "\u{10000}": 2});
        let out = to_string(&value).unwrap();
        assert!(out.find('\u{10000}') < out.find('\u{FF61}'), "{out}");
        let jcs = crate::json::to_canonical_string(&value).unwrap();
        assert!(jcs.find('\u{10000}') < jcs.find('\u{FF61}'), "{jcs}");
    }

    #[test]
    fn numbers_are_jcs_and_i_json() {
        assert_eq!(
            to_string(&[-0.0, 1e-7, 0.1]).unwrap(),
            "[\n  0,\n  1e-7,\n  0.1,\n]\n"
        );
        assert!(to_string(&(1u64 << 53)).is_err());
    }

    #[test]
    fn real_report_is_byte_identical_to_yq() {
        // `assail-report.kyaml` is `yq -p json -o kyaml` (v4.54.1) of the
        // JCS report next to it, and passes standards'
        // `kyaml-format.sh --check`.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kyaml");
        let json = std::fs::read_to_string(dir.join("assail-report.json")).unwrap();
        let golden = std::fs::read_to_string(dir.join("assail-report.kyaml")).unwrap();
        let report: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(to_string(&report).unwrap(), golden);
        let back: crate::types::AssailReport = crate::yaml::from_report_str(&golden).unwrap();
        assert_eq!(crate::json::to_canonical_string(&back).unwrap(), json);
    }

    #[test]
    fn reports_round_trip_through_the_yaml_loader() {
        let report = crate::assail::analyze(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vulnerable_program.rs"),
        )
        .expect("analysis should succeed");
        let out = to_string(&report).unwrap();
        let back: crate::types::AssailReport = crate::yaml::from_report_str(&out).unwrap();
        assert_eq!(
            serde_json::to_value(&back).unwrap(),
            serde_json::to_value(&report).unwrap()
        );
    }
}

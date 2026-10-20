// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Canonical JSON for report artefacts: I-JSON (RFC 7493) serialised as
//! JCS (RFC 8785) and followed by exactly one line feed, per the estate
//! JSON policy (`hyperpolymath/standards` `3-practice/JSON-POLICY.adoc`,
//! rule J-1).
//!
//! Canonicalisation goes through `ijson-jcs`, the tool behind the estate's
//! JSON gate, so every artefact written here passes `ijson-jcs check` by
//! construction. Equal data always yields equal bytes, which is what makes
//! report hashes reproducible outside this crate.

use anyhow::{Context, Result};
use serde::Serialize;

/// Serialise `value` as canonical JSON (JCS) followed by one line feed.
///
/// Fails if `value` is not I-JSON, for example an integer beyond ±2^53.
pub fn to_canonical_string<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let tree = serde_json::to_value(value).context("serializing to JSON")?;
    let mut out = ijson_jcs::to_jcs_string(&tree).context("canonicalizing JSON (JCS)")?;
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Sample {
        zeta: u32,
        alpha: &'static str,
        nested: Vec<f64>,
        flag: bool,
        none: Option<u8>,
    }

    #[test]
    fn sorts_keys_compacts_and_ends_with_one_lf() {
        let sample = Sample {
            zeta: 1,
            alpha: "a\"b\\c\n\u{1}é",
            nested: vec![1.0, 0.5, 1e21, -0.0],
            flag: true,
            none: None,
        };
        let out = to_canonical_string(&sample).expect("canonical JSON");
        assert_eq!(
            out,
            "{\"alpha\":\"a\\\"b\\\\c\\n\\u0001é\",\"flag\":true,\"nested\":[1,0.5,1e+21,0],\"none\":null,\"zeta\":1}\n"
        );
    }

    #[test]
    fn rejects_integers_outside_i_json_range() {
        // I-JSON safe integers: [-(2^53 - 1), 2^53 - 1].
        assert!(to_canonical_string(&((1u64 << 53) - 1)).is_ok());
        assert!(to_canonical_string(&(1u64 << 53)).is_err());
        assert!(to_canonical_string(&u64::MAX).is_err());
        assert!(to_canonical_string(&i64::MIN).is_err());
    }

    #[test]
    fn is_idempotent_on_its_own_output() {
        let report = crate::assail::analyze(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vulnerable_program.rs"),
        )
        .expect("analysis should succeed");
        let once = to_canonical_string(&report).expect("canonical JSON");
        let parsed: serde_json::Value = serde_json::from_str(&once).expect("parses back");
        assert_eq!(once, to_canonical_string(&parsed).expect("canonical JSON"));
        assert_eq!(parsed, serde_json::to_value(&report).expect("value"));
    }
}

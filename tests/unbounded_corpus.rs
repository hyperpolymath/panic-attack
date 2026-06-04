// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Curated corpus for the UnboundedAllocation detector (PA015).
//!
//! Each case is a minimal Rust source with a pre-declared expected
//! verdict: does the detector correctly fire (or correctly not fire)
//! on this input? These are regression locks — they enforce the
//! detector's "zero-FN on corpus" property (Task #25 of the assail
//! narrow-path plan).
//!
//! When adding a new case, classify it in one of three buckets:
//!
//!   TP  — True Positive: detector SHOULD fire (real unbounded alloc)
//!   TN  — True Negative: detector SHOULD NOT fire (bounded / irrelevant)
//!   FN  — False Negative we explicitly don't yet catch (xfail) —
//!         document the pattern and file an issue; the test is
//!         `#[ignore]` until the detector improves.
//!
//! FP (False Positive) cases do not get their own bucket — they're
//! handled by narrowing the detector and appearing in the TN bucket.

use panic_attack::assail;
use panic_attack::types::WeakPointCategory;
use std::io::Write;

/// Helper: write `src` to a tempdir as `case.rs`, analyse the dir,
/// return the count of UnboundedAllocation findings.
fn unbounded_count_for(src: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("case.rs");
    std::fs::File::create(&file)?.write_all(src.as_bytes())?;
    let report = assail::analyze(dir.path()).expect("analyze");
    Ok(report
        .weak_points
        .iter()
        .filter(|wp| wp.category == WeakPointCategory::UnboundedAllocation)
        .count())
}

fn assert_fires(src: &str, msg: &str) -> Result<(), Box<dyn std::error::Error>> {
    let n = unbounded_count_for(src)?;
    assert!(n >= 1, "TP case must fire {}: got {} findings", msg, n);
    Ok(())
}

fn assert_does_not_fire(src: &str, msg: &str) -> Result<(), Box<dyn std::error::Error>> {
    let n = unbounded_count_for(src)?;
    assert_eq!(n, 0, "TN case must NOT fire {}: got {} findings", msg, n);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// True positive corpus — detector MUST fire on each of these
// ─────────────────────────────────────────────────────────────────────

#[test]
fn tp_unbounded_read_to_string() -> Result<(), Box<dyn std::error::Error>> {
    assert_fires(
        r#"
pub fn slurp(p: &str) -> std::io::Result<String> {
    std::fs::read_to_string(p)
}
"#,
        "unbounded fs::read_to_string",
    )
}

#[test]
fn tp_unbounded_read_to_end() -> Result<(), Box<dyn std::error::Error>> {
    assert_fires(
        r#"
use std::io::Read;
pub fn slurp(p: &str) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::open(p)?.read_to_end(&mut buf)?;
    Ok(buf)
}
"#,
        "unbounded File::read_to_end",
    )
}

#[test]
fn tp_bare_unbounded_identifier() -> Result<(), Box<dyn std::error::Error>> {
    assert_fires(
        r#"
pub fn unbounded() -> Vec<u8> { Vec::new() }
"#,
        "bare fn unbounded()",
    )
}

#[test]
fn tp_with_capacity_tiny() -> Result<(), Box<dyn std::error::Error>> {
    assert_fires(
        r#"
pub fn make() -> Vec<u8> {
    let mut v = Vec::with_capacity(0);
    for i in 0..1_000_000 { v.push(i as u8); }
    v
}
"#,
        "Vec::with_capacity(0) followed by push loop",
    )
}

#[test]
fn tp_infinite_bare_keyword() -> Result<(), Box<dyn std::error::Error>> {
    assert_fires(
        r#"
pub fn run(n: u64) -> u64 {
    let infinite = n;
    infinite
}
"#,
        "bare `infinite` keyword (no is_infinite negation)",
    )
}

// ─────────────────────────────────────────────────────────────────────
// True negative corpus — detector MUST NOT fire
// ─────────────────────────────────────────────────────────────────────

#[test]
fn tn_bounded_take_before_read_to_string() -> Result<(), Box<dyn std::error::Error>> {
    assert_does_not_fire(
        r#"
use std::io::Read;
const LIMIT: u64 = 64 * 1024 * 1024;
pub fn slurp(p: &str) -> std::io::Result<String> {
    let mut buf = String::new();
    std::fs::File::open(p)?.take(LIMIT).read_to_string(&mut buf)?;
    Ok(buf)
}
"#,
        ".take(LIMIT) bound + LIMIT const both disarm",
    )
}

#[test]
fn tn_tokio_unbounded_channel_substring() -> Result<(), Box<dyn std::error::Error>> {
    assert_does_not_fire(
        r#"
pub fn pipe() {
    let (_tx, _rx) = tokio::sync::mpsc::unbounded_channel::<u8>();
}
"#,
        "tokio::mpsc::unbounded_channel (unbounded in identifier)",
    )
}

#[test]
fn tn_has_unbounded_allocations_variable_substring() -> Result<(), Box<dyn std::error::Error>> {
    assert_does_not_fire(
        r#"
pub fn analyze(body: &str) -> bool {
    let has_unbounded_allocations = body.len() > 0;
    let unbounded_vec_patterns = 0usize;
    has_unbounded_allocations && unbounded_vec_patterns == 0
}
"#,
        "detector self-reference (identifier with `unbounded_` prefix)",
    )
}

#[test]
fn tn_f64_is_infinite_negation() -> Result<(), Box<dyn std::error::Error>> {
    assert_does_not_fire(
        r#"
pub fn check(x: f64) -> bool {
    x.is_infinite()
}
"#,
        "f64::is_infinite is benign — negation disarms `infinite` keyword",
    )
}

#[test]
fn tn_delimiter_does_not_disarm_unbounded() -> Result<(), Box<dyn std::error::Error>> {
    // `value_delimiter` CONTAINS the substring "limit" but is NOT a
    // bounded-read marker. The word-boundary regex must not disarm
    // the read_to_string check here — genuine unbounded allocation.
    assert_fires(
        r#"
#[arg(short, long, value_delimiter = ',')]
pub fn fake_clap_arg() {}

pub fn slurp(p: &str) -> std::io::Result<String> {
    std::fs::read_to_string(p)
}
"#,
        "`delimiter` contains 'limit' substring but does NOT disarm — \
         old substring contains(\"limit\") was the FN source; \
         new \\blimit regex correctly still fires",
    )
}

#[test]
fn tn_case_insensitive_uppercase_limit_const_disarms() -> Result<(), Box<dyn std::error::Error>> {
    assert_does_not_fire(
        r#"
use std::io::Read;
const READ_LIMIT: u64 = 4096;
pub fn slurp(p: &str) -> std::io::Result<String> {
    let mut buf = String::new();
    std::fs::File::open(p)?.take(READ_LIMIT).read_to_string(&mut buf)?;
    Ok(buf)
}
"#,
        "uppercase const LIMIT disarms via (?i) flag",
    )
}

#[test]
fn tn_test_module_strip() -> Result<(), Box<dyn std::error::Error>> {
    assert_does_not_fire(
        r#"
pub fn prod() -> i64 { 42 }

#[cfg(test)]
mod tests {
    #[test]
    fn choreography_unbounded_loop() {
        assert_eq!(1, 1);
    }
}
"#,
        "#[cfg(test)] mod tests body is stripped; unbounded keyword \
         inside test identifier must not fire",
    )
}

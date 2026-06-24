// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! End-to-end fixture test for `aggregate`'s prover-output folding.
//!
//! `aggregate` has unit tests for annotation/spec parsing, but no test that
//! folds a *real* prover artifact end to end. This exercises that path against
//! `tests/fixtures/proofs/UnsafeCodeSoundness.idr` — a genuine, `idris2
//! --check`-clean, `%default total` Idris2 proof (no escape hatches) of the
//! UnsafeCode (PA001) detector's soundness, carrying the `@name` / `@covers`
//! annotations the folder reads. It asserts the artifact is recognised as
//! Idris2, classified `Closed` (no holes), hashed, named, and that the
//! `sound:category:UnsafeCode` coverage is parsed.

use panic_attack::aggregate::{
    run, AggregateConfig, CoverageKind, ProofClaim, ProofInput, ProofVerdict, Prover,
};
use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proofs/UnsafeCodeSoundness.idr")
}

#[test]
fn aggregate_folds_idris2_unsafecode_soundness_proof() {
    let path = fixture();
    assert!(path.exists(), "fixture missing: {}", path.display());

    let report = run(AggregateConfig {
        proofs: vec![ProofInput {
            path,
            label: None,
            covers: Vec::new(),
        }],
        base_report: None,
    })
    .expect("aggregate should fold the Idris2 fixture");

    assert_eq!(report.aggregated_proofs.len(), 1);
    let p = &report.aggregated_proofs[0];

    // Recognised as an Idris2 artifact (by `.idr` extension).
    assert!(matches!(p.prover, Prover::Idris2), "prover: {:?}", p.prover);

    // No escape hatches + a closure signal => Closed (not Holes / Indeterminate).
    assert!(
        matches!(p.verdict, ProofVerdict::Closed),
        "verdict: {:?}, holes: {:?}",
        p.verdict,
        p.holes
    );
    assert!(p.holes.is_empty(), "unexpected holes: {:?}", p.holes);

    // Non-repudiation: the whole file was hashed (byte length recorded).
    assert!(p.bytes > 0, "no bytes hashed");

    // Friendly name lifted from the in-file `@name "..."` annotation.
    assert!(
        p.friendly_name.contains("UnsafeCode"),
        "friendly name: {}",
        p.friendly_name
    );

    // Coverage parsed from `@covers sound:category:UnsafeCode`.
    assert!(
        p.covers.iter().any(|c| matches!(c.claim, ProofClaim::Sound)
            && matches!(c.kind, CoverageKind::Category)
            && c.value == "UnsafeCode"),
        "covers: {:?}",
        p.covers
    );
}

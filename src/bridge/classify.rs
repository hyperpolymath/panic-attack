// SPDX-License-Identifier: MPL-2.0

//! Three-way CVE classification engine.
//!
//! Combines vulnerability data with reachability evidence to produce
//! one of three classifications:
//!
//! - **Mitigable**: A fix exists (semver-compatible or manual upgrade)
//! - **Unmitigable**: No fix available and dependency is reachable
//! - **Informational**: Dependency is phantom or unreachable
//!
//! Phase 2 will add **Concatenative** classification for CVE×CVE
//! interactions across shared trust boundaries.

use super::{Classification, ReachabilityEvidence, ReachabilityStatus, Vulnerability};

/// Build-script-only / vendored-pin allowlist (issue #74).
///
/// These crates are commonly declared in `[dependencies]` but have **zero
/// `use` sites by design**: they're used purely from `build.rs`, for their
/// linker side-effects, or as the canonical Rust binding for a native lib
/// (declared via `links = "…"`). A naive `cargo machete --fix` strip
/// breaks cross-compile TLS, native-lib resolution, and build-time codegen.
///
/// Match by crate name. Feature-based detection (e.g. `openssl-sys` with
/// the `vendored` feature) is a planned follow-up requiring feature-set
/// plumbing into the bridge.
fn is_build_script_only_or_vendored_pin(name: &str) -> bool {
    matches!(
        name,
        // Build-script side-effect crates (no `use` site by design).
        "pkg-config"
            | "cc"
            | "bindgen"
            | "cmake"
            | "autocfg"
            | "vcpkg"
            | "winres"
            | "embed-resource"
            // Canonical vendored-pin crate (declares vendored native lib).
            | "openssl-src"
    )
}

/// Dioxus desktop / wry transitive GUI parent set (issue #75).
fn is_dioxus_gui_parent(parent: &str) -> bool {
    matches!(parent, "wry" | "dioxus-desktop" | "dioxus")
}

/// GTK / webkit family crates pulled in transitively by wry / dioxus-desktop.
/// When parent is a Dioxus GUI parent AND the crate is in this family, the
/// vulnerability is a Cohort E-2 informational — the host repo cannot fix it
/// short of swapping out the Dioxus desktop renderer.
fn is_gtk_webkit_family(name: &str) -> bool {
    // Heuristic prefix/exact match across the atk/gdk/gtk/glib/wry transitive
    // surface observed in presswerk (Track E 2026-05-27).
    name.starts_with("atk")
        || name.starts_with("gdk")
        || name.starts_with("gtk")
        || name == "glib"
        || name == "glib-sys"
        || name == "gio"
        || name == "gio-sys"
        || name == "gobject-sys"
        || name == "gtk3-macros"
        || name == "proc-macro-error"
        || name == "paste"
        || name == "fxhash"
        || name == "webkit2gtk"
        || name == "webkit2gtk-sys"
}

/// Classify a vulnerability given its reachability evidence.
///
/// The three-way output (Mitigable / Unmitigable / Informational) is
/// unchanged from #47 — both phantom variants classify as `Informational` —
/// but the rationale and suggested fix differ:
///
/// - [`ReachabilityStatus::PhantomDeclared`] — declared in Cargo.toml but
///   no `use` site. Strip the dep via `cargo machete --fix`. Canonical
///   case: file-soup#50.
/// - [`ReachabilityStatus::PhantomTransitive`] — not declared anywhere in
///   the workspace, pulled in by a parent dep. Local strip is impossible;
///   the fix requires bumping the parent (named in `evidence.parent_dep`
///   when identifiable). Track E found ~26 of 29 issues here.
///
/// Returns (classification, rationale, suggested_action).
pub fn classify(
    vuln: &Vulnerability,
    evidence: &ReachabilityEvidence,
) -> (Classification, String, String) {
    match evidence.status {
        // ─── Phantom + declared: manifest entry is genuinely unused ───
        ReachabilityStatus::PhantomDeclared => {
            // Cohort E-3 override (issue #74): build-script-only / vendored-pin
            // crates have no `use` site BY DESIGN. Stripping them breaks the
            // build inscrutably. Keep Informational classification but flip
            // the action from "strip" to "DO NOT STRIP".
            if is_build_script_only_or_vendored_pin(&vuln.package) {
                return (
                    Classification::Informational,
                    format!(
                        "{} {} is declared in Cargo.toml with no `use` site, but it \
                         is a build-script-only or vendored-pin crate (load-bearing \
                         via build.rs side-effects or native-lib linkage). \
                         The vulnerable code is compiled but never executed at runtime.",
                        vuln.package, vuln.version
                    ),
                    format!(
                        "DO NOT STRIP — `{}` is on the build-script-only / \
                         vendored-pin allowlist. Stripping would break the build \
                         (cross-compile TLS, native-lib resolution, or build-time \
                         codegen). Bump to a patched version when one is available, \
                         or accept as informational.",
                        vuln.package
                    ),
                );
            }
            (
                Classification::Informational,
                format!(
                    "{} {} is declared in Cargo.toml but never imported in any .rs file. \
                     The vulnerable code is compiled but unreachable. \
                     Stripping the dependency eliminates this CVE entirely.",
                    vuln.package, vuln.version
                ),
                format!(
                    "Strip from Cargo.toml — run `cargo machete --fix` (or remove the \
                     dependency line manually) for `{}`.",
                    vuln.package
                ),
            )
        }

        // ─── Phantom + transitive: pulled in by an upstream parent ───
        ReachabilityStatus::PhantomTransitive => {
            let parent_clause = match evidence.parent_dep.as_deref() {
                Some(p) => format!("`{p}`"),
                None => "an upstream parent dependency".to_string(),
            };

            // Cohort E-2 override (issue #75): Dioxus desktop / wry pulls in
            // the entire GTK/webkit family; presswerk-class repos cannot fix
            // these short of swapping the renderer. Annotate the cohort
            // explicitly so triage tooling can batch-suppress.
            if let Some(parent) = evidence.parent_dep.as_deref() {
                if is_dioxus_gui_parent(parent) && is_gtk_webkit_family(&vuln.package) {
                    return (
                        Classification::Informational,
                        format!(
                            "{} {} is a Cohort E-2 transitive: pulled in by {parent_clause}, \
                             part of the GTK/webkit transitive surface that ships with \
                             Dioxus desktop / wry. The vulnerable code is compiled but \
                             not reachable from this project's code paths.",
                            vuln.package, vuln.version
                        ),
                        format!(
                            "Cohort E-2 (Dioxus/GTK transitive): no local fix. Either \
                             (a) wait for `{parent}` to ship a release that bumps the \
                             GTK family past the affected versions, or (b) swap the \
                             Dioxus desktop renderer for an alternative (egui, slint, \
                             gpui). Tracked at hyperpolymath/panic-attack#75."
                        ),
                    );
                }
                // Cohort E-2 sub-rule: printpdf internalises kuchiki as its
                // HTML→PDF parser; not host-exposed.
                if parent == "printpdf" && vuln.package == "kuchiki" {
                    return (
                        Classification::Informational,
                        format!(
                            "{} {} is a Cohort E-2 transitive: printpdf internalises \
                             kuchiki for HTML→PDF parsing. Not exposed on host paths.",
                            vuln.package, vuln.version
                        ),
                        "Cohort E-2 (printpdf-internal): no local fix. Wait for \
                         `printpdf` to swap its HTML parser, or replace `printpdf` \
                         with a non-kuchiki PDF library (e.g. lopdf, pdf-writer). \
                         Tracked at hyperpolymath/panic-attack#75."
                            .to_string(),
                    );
                }
            }

            (
                Classification::Informational,
                format!(
                    "{} {} is a transitive dependency (not declared in this project's \
                     Cargo.toml) and never imported in any .rs file. Pulled in by \
                     {parent_clause}. The vulnerable code is compiled but unreachable \
                     from this project; remediation lives upstream.",
                    vuln.package, vuln.version
                ),
                format!(
                    "Pulled in transitively by {parent_clause} — fix requires bumping \
                     the parent dependency past the affected version of `{}`. No local \
                     strip is possible.",
                    vuln.package
                ),
            )
        }

        // ─── Unreachable: imported but no taint flow (Phase 2) ───
        ReachabilityStatus::Unreachable => (
            Classification::Informational,
            format!(
                "{} {} is imported but no data flow reaches the vulnerable code path. \
                 (Note: Phase 2 kanren taint analysis will provide higher confidence.)",
                vuln.package, vuln.version
            ),
            "Monitor — no immediate action required".to_string(),
        ),

        // ─── Reachable: imported and potentially exploitable ───
        ReachabilityStatus::Reachable => classify_reachable(vuln, evidence),
    }
}

/// Classify a reachable vulnerability as mitigable or unmitigable.
fn classify_reachable(
    vuln: &Vulnerability,
    evidence: &ReachabilityEvidence,
) -> (Classification, String, String) {
    let import_summary = if evidence.import_sites.len() <= 3 {
        evidence
            .import_sites
            .iter()
            .map(|s| format!("{}:{}", s.file.display(), s.line))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        format!(
            "{} and {} more",
            evidence
                .import_sites
                .iter()
                .take(2)
                .map(|s| format!("{}:{}", s.file.display(), s.line))
                .collect::<Vec<_>>()
                .join(", "),
            evidence.import_sites.len() - 2
        )
    };

    if vuln.fixed_versions.is_empty() {
        // No fix available — unmitigable
        (
            Classification::Unmitigable,
            format!(
                "{} {} has {} ({}) with NO upstream fix available. \
                 The dependency is imported at: {}. \
                 The vulnerable code is reachable in this project.",
                vuln.package, vuln.version, vuln.id, vuln.summary, import_summary
            ),
            format!(
                "Replace `{}` with an alternative or accept the risk. \
                 No version upgrade can fix this.",
                vuln.package
            ),
        )
    } else if vuln.semver_fix_available {
        // Semver-compatible fix — easiest mitigation
        let fix_version = vuln
            .fixed_versions
            .first()
            .map(String::as_str)
            .unwrap_or("unknown");
        (
            Classification::Mitigable,
            format!(
                "{} {} has {} ({}). \
                 A semver-compatible fix is available in version {}. \
                 Run `cargo update {}` to apply.",
                vuln.package, vuln.version, vuln.id, vuln.summary, fix_version, vuln.package
            ),
            format!("Run `cargo update {}`", vuln.package),
        )
    } else {
        // Fix exists but requires major version bump
        let fix_versions = vuln.fixed_versions.join(", ");
        (
            Classification::Mitigable,
            format!(
                "{} {} has {} ({}). \
                 Fix available in version(s) {} but requires a breaking upgrade. \
                 The dependency is imported at: {}.",
                vuln.package, vuln.version, vuln.id, vuln.summary, fix_versions, import_summary
            ),
            format!(
                "Upgrade `{}` to {} in Cargo.toml (breaking change — review API differences)",
                vuln.package, fix_versions
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{ImportSite, SeverityLabel, SourceTier};
    use std::path::PathBuf;

    fn mock_vuln(has_fix: bool, semver_fix: bool) -> Vulnerability {
        Vulnerability {
            id: "RUSTSEC-2026-0001".to_string(),
            cve: Some("CVE-2026-00001".to_string()),
            summary: "Test vulnerability".to_string(),
            package: "test-crate".to_string(),
            version: "1.0.0".to_string(),
            severity: Some(7.5),
            severity_label: SeverityLabel::High,
            fixed_versions: if has_fix {
                vec!["1.0.1".to_string()]
            } else {
                vec![]
            },
            semver_fix_available: semver_fix,
            source_tier: SourceTier::Tier1,
            references: vec![],
        }
    }

    fn phantom_declared_evidence() -> ReachabilityEvidence {
        ReachabilityEvidence {
            is_imported: false,
            import_sites: vec![],
            status: ReachabilityStatus::PhantomDeclared,
            parent_dep: None,
        }
    }

    fn phantom_transitive_evidence(parent: Option<&str>) -> ReachabilityEvidence {
        ReachabilityEvidence {
            is_imported: false,
            import_sites: vec![],
            status: ReachabilityStatus::PhantomTransitive,
            parent_dep: parent.map(str::to_string),
        }
    }

    fn reachable_evidence() -> ReachabilityEvidence {
        ReachabilityEvidence {
            is_imported: true,
            import_sites: vec![ImportSite {
                file: PathBuf::from("src/main.rs"),
                line: 5,
                statement: "use test_crate::Thing;".to_string(),
            }],
            status: ReachabilityStatus::Reachable,
            parent_dep: None,
        }
    }

    #[test]
    fn test_phantom_declared_recommends_machete_strip() {
        // file-soup#50 shape: crate declared in Cargo.toml, no `use` site —
        // strip the manifest entry.
        let (cls, rationale, action) = classify(&mock_vuln(false, false), &phantom_declared_evidence());
        assert_eq!(cls, Classification::Informational);
        assert!(
            action.contains("cargo machete --fix") || action.contains("Strip from Cargo.toml"),
            "declared phantom should recommend strip, got: {action}"
        );
        assert!(
            rationale.contains("declared in Cargo.toml"),
            "rationale should explain declared status, got: {rationale}"
        );
    }

    #[test]
    fn test_phantom_transitive_recommends_parent_bump() {
        // Track E shape: ~26 of 29 issues were misclassified as phantom-declared
        // when they're actually transitive. The fix is to bump the parent, NOT
        // to strip the local manifest.
        let (cls, rationale, action) = classify(
            &mock_vuln(false, false),
            &phantom_transitive_evidence(Some("reqwest")),
        );
        assert_eq!(cls, Classification::Informational);
        assert!(
            !action.contains("cargo machete --fix"),
            "transitive phantom must NOT recommend manifest strip, got: {action}"
        );
        assert!(
            action.contains("Pulled in transitively"),
            "transitive phantom action should label itself transitive, got: {action}"
        );
        assert!(
            action.contains("`reqwest`"),
            "transitive phantom action should name the parent dep, got: {action}"
        );
        assert!(
            action.contains("bumping the parent"),
            "transitive phantom action should suggest parent bump, got: {action}"
        );
        assert!(
            rationale.contains("transitive dependency"),
            "rationale should explain transitive status, got: {rationale}"
        );
    }

    #[test]
    fn test_phantom_transitive_unknown_parent_falls_back_gracefully() {
        // Best-effort parent identification: if Cargo.lock didn't reveal one,
        // we still produce useful output.
        let (cls, rationale, action) = classify(
            &mock_vuln(false, false),
            &phantom_transitive_evidence(None),
        );
        assert_eq!(cls, Classification::Informational);
        assert!(
            action.contains("an upstream parent dependency"),
            "unknown-parent transitive should fall back to generic phrasing, got: {action}"
        );
        assert!(rationale.contains("transitive dependency"));
    }

    #[test]
    fn test_reachable_no_fix_is_unmitigable() {
        let (cls, _, _) = classify(&mock_vuln(false, false), &reachable_evidence());
        assert_eq!(cls, Classification::Unmitigable);
    }

    #[test]
    fn test_reachable_semver_fix_is_mitigable() {
        let (cls, _, action) = classify(&mock_vuln(true, true), &reachable_evidence());
        assert_eq!(cls, Classification::Mitigable);
        assert!(action.contains("cargo update"));
    }

    #[test]
    fn test_reachable_breaking_fix_is_mitigable() {
        let (cls, _, action) = classify(&mock_vuln(true, false), &reachable_evidence());
        assert_eq!(cls, Classification::Mitigable);
        assert!(action.contains("breaking change"));
    }

    #[test]
    fn test_phantom_variants_both_classify_informational() {
        // Three-way classifier output is unchanged from #47.
        let (cls_decl, _, _) = classify(&mock_vuln(false, false), &phantom_declared_evidence());
        let (cls_trans, _, _) = classify(&mock_vuln(false, false), &phantom_transitive_evidence(None));
        assert_eq!(cls_decl, Classification::Informational);
        assert_eq!(cls_trans, Classification::Informational);
    }

    // ─── Cohort E-3 — build-script-only / vendored-pin allowlist (#74) ───

    fn vuln_named(name: &str) -> Vulnerability {
        let mut v = mock_vuln(false, false);
        v.package = name.to_string();
        v
    }

    #[test]
    fn test_phantom_declared_build_script_only_says_do_not_strip() {
        // pkg-config / cc / bindgen / etc. have no `use` site by design;
        // a naive strip breaks the build.
        for name in ["pkg-config", "cc", "bindgen", "cmake", "autocfg", "vcpkg"] {
            let (cls, _, action) = classify(&vuln_named(name), &phantom_declared_evidence());
            assert_eq!(cls, Classification::Informational, "`{name}` must classify Informational");
            assert!(
                action.contains("DO NOT STRIP"),
                "`{name}` must NOT recommend strip, got: {action}"
            );
            assert!(
                !action.contains("cargo machete"),
                "`{name}` must NOT mention machete, got: {action}"
            );
        }
    }

    #[test]
    fn test_phantom_declared_openssl_src_says_do_not_strip() {
        // openssl-src is the canonical "vendored OpenSSL" crate — load-bearing
        // even when nothing imports it.
        let (cls, _, action) = classify(&vuln_named("openssl-src"), &phantom_declared_evidence());
        assert_eq!(cls, Classification::Informational);
        assert!(action.contains("DO NOT STRIP"));
        assert!(action.contains("vendored-pin"));
    }

    #[test]
    fn test_phantom_declared_normal_crate_still_recommends_strip() {
        // Regression: the allowlist must not over-fire on ordinary crates.
        let (cls, _, action) = classify(&vuln_named("serde_json"), &phantom_declared_evidence());
        assert_eq!(cls, Classification::Informational);
        assert!(action.contains("cargo machete --fix"));
        assert!(!action.contains("DO NOT STRIP"));
    }

    // ─── Cohort E-2 — Dioxus / GTK transitive (#75) ───

    #[test]
    fn test_phantom_transitive_dioxus_gtk_family_annotates_cohort_e2() {
        // presswerk shape: gtk@0.18 pulled in by wry → dioxus-desktop.
        let (cls, rationale, action) = classify(
            &vuln_named("gtk"),
            &phantom_transitive_evidence(Some("wry")),
        );
        assert_eq!(cls, Classification::Informational);
        assert!(
            rationale.contains("Cohort E-2"),
            "rationale should label as Cohort E-2, got: {rationale}"
        );
        assert!(
            action.contains("Cohort E-2") && action.contains("Dioxus/GTK"),
            "action should describe the cohort + no-local-fix path, got: {action}"
        );
        assert!(
            action.contains("panic-attack#75"),
            "action should reference the tracking issue, got: {action}"
        );
    }

    #[test]
    fn test_phantom_transitive_gtk_family_via_dioxus_parent() {
        // Same family check but parent is dioxus-desktop directly.
        for name in ["atk", "atk-sys", "gdk", "gdk-sys", "glib", "gtk3-macros", "paste", "fxhash"] {
            let (_, rationale, _) = classify(
                &vuln_named(name),
                &phantom_transitive_evidence(Some("dioxus-desktop")),
            );
            assert!(
                rationale.contains("Cohort E-2"),
                "`{name}` via dioxus-desktop should label Cohort E-2, got: {rationale}"
            );
        }
    }

    #[test]
    fn test_phantom_transitive_kuchiki_via_printpdf_annotates_cohort_e2() {
        let (cls, rationale, action) = classify(
            &vuln_named("kuchiki"),
            &phantom_transitive_evidence(Some("printpdf")),
        );
        assert_eq!(cls, Classification::Informational);
        assert!(rationale.contains("Cohort E-2"));
        assert!(action.contains("printpdf-internal"));
        assert!(action.contains("panic-attack#75"));
    }

    #[test]
    fn test_phantom_transitive_non_dioxus_parent_uses_generic_message() {
        // Regression: gtk-family check must only fire when parent is in the
        // Dioxus GUI parent set. gtk pulled in by something else (e.g. an
        // experimental UI lib that happens to use gtk) shouldn't get the
        // Cohort E-2 message.
        let (cls, rationale, action) = classify(
            &vuln_named("gtk"),
            &phantom_transitive_evidence(Some("some-other-gui")),
        );
        assert_eq!(cls, Classification::Informational);
        assert!(
            !rationale.contains("Cohort E-2"),
            "non-Dioxus parent should NOT trigger E-2 cohort, got: {rationale}"
        );
        assert!(action.contains("bumping the parent"));
    }
}

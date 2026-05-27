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
        ReachabilityStatus::PhantomDeclared => (
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
        ),

        // ─── Phantom + transitive: pulled in by an upstream parent ───
        ReachabilityStatus::PhantomTransitive => {
            let parent_clause = match evidence.parent_dep.as_deref() {
                Some(p) => format!("`{p}`"),
                None => "an upstream parent dependency".to_string(),
            };
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
}

// SPDX-License-Identifier: PMPL-1.0-or-later

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
/// Returns (classification, rationale, suggested_action).
pub fn classify(
    vuln: &Vulnerability,
    evidence: &ReachabilityEvidence,
) -> (Classification, String, String) {
    match evidence.status {
        // ─── Phantom dependency: declared but never imported ───
        ReachabilityStatus::Phantom => (
            Classification::Informational,
            format!(
                "{} {} is declared in Cargo.toml but never imported in any .rs file. \
                 The vulnerable code is compiled but unreachable. \
                 Removing the dependency from Cargo.toml eliminates this CVE entirely.",
                vuln.package, vuln.version
            ),
            format!("Remove unused dependency `{}` from Cargo.toml", vuln.package),
        ),

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
                vuln.package,
                vuln.version,
                vuln.id,
                vuln.summary,
                import_summary
            ),
            format!(
                "Replace `{}` with an alternative or accept the risk. \
                 No version upgrade can fix this.",
                vuln.package
            ),
        )
    } else if vuln.semver_fix_available {
        // Semver-compatible fix — easiest mitigation
        let fix_version = vuln.fixed_versions.first().unwrap();
        (
            Classification::Mitigable,
            format!(
                "{} {} has {} ({}). \
                 A semver-compatible fix is available in version {}. \
                 Run `cargo update {}` to apply.",
                vuln.package, vuln.version, vuln.id, vuln.summary,
                fix_version, vuln.package
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
                vuln.package, vuln.version, vuln.id, vuln.summary,
                fix_versions, import_summary
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

    fn phantom_evidence() -> ReachabilityEvidence {
        ReachabilityEvidence {
            is_imported: false,
            import_sites: vec![],
            status: ReachabilityStatus::Phantom,
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
        }
    }

    #[test]
    fn test_phantom_is_informational() {
        let (cls, _, action) = classify(&mock_vuln(false, false), &phantom_evidence());
        assert_eq!(cls, Classification::Informational);
        assert!(action.contains("Remove"));
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
}

// SPDX-License-Identifier: PMPL-1.0-or-later

//! Mitigation registry — tracks active mitigations and their lifecycle.
//!
//! For MVP, the registry is a JSON file at `.machine_readable/patch-bridge/registry.json`.
//! Phase 2 will add VeriSimDB hexad persistence and SCM format.
//!
//! Lifecycle: Applied → Active → Retiring → Retired
//! See docs/patch-bridge-design.md Section 8 for full lifecycle specification.

use super::{AssessedCve, Classification};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A registered mitigation for an active CVE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationEntry {
    /// Unique mitigation ID (e.g., "PB-2026-001")
    pub id: String,
    /// Advisory ID this mitigates
    pub advisory_id: String,
    /// Affected package
    pub package: String,
    /// Affected version
    pub version: String,
    /// Classification at time of registration
    pub classification: Classification,
    /// When this entry was created (ISO 8601)
    pub registered_at: String,
    /// Human-readable rationale
    pub rationale: String,
    /// Suggested action
    pub action: String,
    /// Current lifecycle status
    pub status: MitigationStatus,
}

/// Lifecycle status of a mitigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationStatus {
    /// Just registered, awaiting action
    Pending,
    /// Mitigation applied and active
    Active,
    /// Upstream fix available, mitigation can be retired
    Retiring,
    /// Mitigation removed, upstream fix applied
    Retired,
    /// Accepted risk — no mitigation possible, documented
    AcceptedRisk,
}

/// The full mitigation registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationRegistry {
    /// Schema version
    pub schema_version: String,
    /// All registered mitigations
    pub entries: Vec<MitigationEntry>,
}

impl MitigationRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            schema_version: "0.1.0".to_string(),
            entries: Vec::new(),
        }
    }

    /// Load the registry from disk, or create a new one if it doesn't exist.
    pub fn load(project_dir: &Path) -> Result<Self> {
        let path = registry_path(project_dir);
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self::new())
        }
    }

    /// Save the registry to disk.
    pub fn save(&self, project_dir: &Path) -> Result<()> {
        let path = registry_path(project_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    /// Register assessed CVEs from a triage report.
    ///
    /// Only registers CVEs that aren't already in the registry.
    /// Returns the number of new entries added.
    pub fn register_from_triage(&mut self, assessed: &[AssessedCve]) -> usize {
        let now = chrono::Utc::now().to_rfc3339();
        let mut added = 0;

        for cve in assessed {
            // Skip informational (phantom/unreachable) — no mitigation needed
            if cve.classification == Classification::Informational {
                continue;
            }

            // Skip if already registered
            if self
                .entries
                .iter()
                .any(|e| e.advisory_id == cve.vulnerability.id && e.package == cve.vulnerability.package)
            {
                continue;
            }

            let id = format!("PB-{:04}", self.entries.len() + 1);
            let status = match cve.classification {
                Classification::Unmitigable => MitigationStatus::AcceptedRisk,
                Classification::Mitigable => MitigationStatus::Pending,
                Classification::Informational => continue,
            };

            self.entries.push(MitigationEntry {
                id,
                advisory_id: cve.vulnerability.id.clone(),
                package: cve.vulnerability.package.clone(),
                version: cve.vulnerability.version.clone(),
                classification: cve.classification,
                registered_at: now.clone(),
                rationale: cve.rationale.clone(),
                action: cve.action.clone(),
                status,
            });
            added += 1;
        }

        added
    }

    /// Count entries by status.
    pub fn count_by_status(&self, status: MitigationStatus) -> usize {
        self.entries.iter().filter(|e| e.status == status).count()
    }
}

/// Path to the registry file within a project.
fn registry_path(project_dir: &Path) -> PathBuf {
    project_dir
        .join(".machine_readable")
        .join("patch-bridge")
        .join("registry.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_empty_registry() {
        let reg = MitigationRegistry::new();
        assert!(reg.entries.is_empty());
        assert_eq!(reg.count_by_status(MitigationStatus::Pending), 0);
    }

    #[test]
    fn test_save_and_load() {
        let tmp = TempDir::new().unwrap();
        let mut reg = MitigationRegistry::new();
        reg.entries.push(MitigationEntry {
            id: "PB-0001".to_string(),
            advisory_id: "RUSTSEC-2026-0001".to_string(),
            package: "test-crate".to_string(),
            version: "1.0.0".to_string(),
            classification: Classification::Mitigable,
            registered_at: "2026-03-21T00:00:00Z".to_string(),
            rationale: "Test".to_string(),
            action: "cargo update test-crate".to_string(),
            status: MitigationStatus::Pending,
        });

        reg.save(tmp.path()).unwrap();
        let loaded = MitigationRegistry::load(tmp.path()).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].id, "PB-0001");
    }
}

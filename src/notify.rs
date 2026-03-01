// SPDX-License-Identifier: PMPL-1.0-or-later

//! Designer notification pipeline.
//!
//! Takes an assemblyline report and produces a human-readable annotated summary
//! suitable for sending to project maintainers. Critical and high-severity
//! findings are flagged with plain-language explanations of why they matter.
//!
//! Output formats:
//! - Markdown report (default)
//! - GitHub issues via `gh issue create` (optional)

use crate::assemblyline::AssemblylineReport;
use crate::types::Severity;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Configuration for the notification pipeline
pub struct NotifyConfig {
    /// Create GitHub issues for repos above this severity threshold
    /// (read by CLI handler in main.rs)
    #[allow(dead_code)]
    pub create_issues: bool,
    /// Only notify for repos with at least this many findings
    pub min_findings: usize,
    /// Only notify for repos with critical findings
    pub critical_only: bool,
    /// GitHub owner for issue creation (e.g. "hyperpolymath")
    pub github_owner: Option<String>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            create_issues: false,
            min_findings: 1,
            critical_only: false,
            github_owner: None,
        }
    }
}

/// Severity annotation for human readers — explains why a finding matters
/// in plain language rather than just listing a category code.
fn severity_annotation(severity: &str, category: &str) -> &'static str {
    match (severity, category) {
        ("Critical", "UnsafeCode") => "This is dangerous. Unsafe code can cause memory corruption, segfaults, and security vulnerabilities. It needs review immediately.",
        ("Critical", "CommandInjection") => "This is a security vulnerability. User input may reach shell commands without sanitisation. An attacker could execute arbitrary code.",
        ("Critical", "UnsafeDeserialization") => "This is a security vulnerability. Deserialising untrusted data can lead to remote code execution.",
        ("Critical", "HardcodedSecret") => "This is a security vulnerability. Hardcoded secrets will be exposed in version control and compiled binaries.",
        ("Critical", _) => "This is a critical finding that needs immediate attention.",
        ("High", "PanicPath") => "Unwrap/expect calls will crash the program on unexpected input. Replace with proper error handling.",
        ("High", "RaceCondition") => "Race conditions cause intermittent, hard-to-reproduce bugs. They can lead to data corruption under load.",
        ("High", "DeadlockPotential") => "Deadlocks will hang the program permanently. Review lock ordering.",
        ("High", "ResourceLeak") => "Resource leaks cause gradual memory growth and eventual OOM crashes — exactly what's crashing your system every few hours.",
        ("High", _) => "This is a high-severity finding that should be addressed before release.",
        _ => "",
    }
}

/// Generate a markdown notification report from assemblyline results
pub fn generate_markdown(report: &AssemblylineReport, config: &NotifyConfig) -> String {
    let mut md = String::new();

    md.push_str("# Panic-Attack Assemblyline Findings\n\n");
    md.push_str(&format!(
        "**Scanned:** {} repos | **With findings:** {} | **Total weak points:** {} | **Critical:** {}\n\n",
        report.repos_scanned,
        report.repos_with_findings,
        report.total_weak_points,
        report.total_critical
    ));

    if report.total_critical > 0 {
        md.push_str(
            "> **Warning:** Critical findings detected. These represent security vulnerabilities \
             or memory safety issues that could be exploited or cause crashes in production.\n\n",
        );
    }

    md.push_str("---\n\n");

    let mut repos_notified = 0;

    for result in &report.results {
        if result.weak_point_count < config.min_findings {
            continue;
        }
        if config.critical_only && result.critical_count == 0 {
            continue;
        }
        if result.error.is_some() {
            continue;
        }

        repos_notified += 1;

        // Repo header with severity indicator
        let severity_badge = if result.critical_count > 0 {
            "CRITICAL"
        } else if result.high_count > 0 {
            "HIGH"
        } else {
            "MEDIUM"
        };

        md.push_str(&format!(
            "## {} [{}]\n\n",
            result.repo_name, severity_badge
        ));
        md.push_str(&format!(
            "- **Findings:** {} total ({} critical, {} high)\n",
            result.weak_point_count, result.critical_count, result.high_count
        ));
        md.push_str(&format!(
            "- **Size:** {} files, {} lines\n",
            result.total_files, result.total_lines
        ));

        // Per-finding annotations from the detailed report (if available)
        if let Some(ref assail_report) = result.report {
            let critical_and_high: Vec<_> = assail_report
                .weak_points
                .iter()
                .filter(|wp| wp.severity == Severity::Critical || wp.severity == Severity::High)
                .collect();

            if !critical_and_high.is_empty() {
                md.push_str("\n### Findings requiring attention\n\n");
                for wp in &critical_and_high {
                    let severity_str = format!("{:?}", wp.severity);
                    let category_str = format!("{:?}", wp.category);
                    let annotation =
                        severity_annotation(&severity_str, &category_str);

                    md.push_str(&format!(
                        "- **[{}] {}** — {}\n",
                        severity_str, category_str, wp.description
                    ));
                    if !annotation.is_empty() {
                        md.push_str(&format!("  > {}\n", annotation));
                    }
                }
            }
        }

        md.push_str("\n---\n\n");
    }

    if repos_notified == 0 {
        md.push_str("No repos met the notification threshold.\n");
    }

    md.push_str(&format!(
        "\n*Generated by panic-attack assemblyline on {}*\n",
        report.created_at
    ));

    md
}

/// Write the markdown notification to a file
pub fn write_notification(
    report: &AssemblylineReport,
    config: &NotifyConfig,
    output: &Path,
) -> Result<()> {
    let markdown = generate_markdown(report, config);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, &markdown)
        .with_context(|| format!("writing notification to {}", output.display()))?;
    Ok(())
}

/// Create GitHub issues for repos with critical findings.
///
/// Uses `gh issue create` — requires the `gh` CLI to be installed and authenticated.
/// Only creates issues for repos where the owner matches the configured github_owner.
pub fn create_github_issues(
    report: &AssemblylineReport,
    config: &NotifyConfig,
) -> Result<Vec<String>> {
    let owner = config
        .github_owner
        .as_deref()
        .unwrap_or("hyperpolymath");

    let mut created = Vec::new();

    for result in &report.results {
        if result.critical_count == 0 {
            continue;
        }
        if result.error.is_some() {
            continue;
        }

        let title = format!(
            "panic-attack: {} critical finding{} detected",
            result.critical_count,
            if result.critical_count == 1 { "" } else { "s" }
        );

        let mut body = format!(
            "## Automated Security Scan Results\n\n\
             **Tool:** panic-attack assemblyline\n\
             **Scan date:** {}\n\
             **Findings:** {} total ({} critical, {} high)\n\n",
            report.created_at,
            result.weak_point_count,
            result.critical_count,
            result.high_count
        );

        if let Some(ref assail_report) = result.report {
            let criticals: Vec<_> = assail_report
                .weak_points
                .iter()
                .filter(|wp| wp.severity == Severity::Critical)
                .collect();

            for wp in &criticals {
                body.push_str(&format!(
                    "- **{:?}**: {}\n",
                    wp.category, wp.description
                ));
            }
        }

        body.push_str("\n---\n*Created by panic-attack. Review and close when addressed.*\n");

        let repo_slug = format!("{}/{}", owner, result.repo_name);

        let output = Command::new("gh")
            .args([
                "issue",
                "create",
                "--repo",
                &repo_slug,
                "--title",
                &title,
                "--body",
                &body,
                "--label",
                "security",
            ])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                let url = String::from_utf8_lossy(&o.stdout).trim().to_string();
                created.push(url);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                eprintln!(
                    "Warning: failed to create issue for {}: {}",
                    result.repo_name, stderr
                );
            }
            Err(e) => {
                eprintln!(
                    "Warning: gh not available for {}: {}",
                    result.repo_name, e
                );
            }
        }
    }

    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assemblyline::{AssemblylineReport, RepoResult};
    use std::path::PathBuf;

    fn make_report(results: Vec<RepoResult>) -> AssemblylineReport {
        let repos_with_findings = results.iter().filter(|r| r.weak_point_count > 0).count();
        let total_weak_points: usize = results.iter().map(|r| r.weak_point_count).sum();
        let total_critical: usize = results.iter().map(|r| r.critical_count).sum();
        AssemblylineReport {
            created_at: "2026-03-01T00:00:00Z".to_string(),
            directory: PathBuf::from("/tmp/repos"),
            repos_scanned: results.len(),
            repos_with_findings,
            repos_skipped: 0,
            total_weak_points,
            total_critical,
            results,
        }
    }

    fn make_repo_result(name: &str, total: usize, critical: usize, high: usize) -> RepoResult {
        RepoResult {
            repo_path: PathBuf::from(format!("/tmp/repos/{}", name)),
            repo_name: name.to_string(),
            weak_point_count: total,
            critical_count: critical,
            high_count: high,
            total_files: 10,
            total_lines: 1000,
            error: None,
            fingerprint: None,
            report: None,
        }
    }

    #[test]
    fn test_generate_markdown_empty_report() {
        let report = make_report(vec![]);
        let md = generate_markdown(&report, &NotifyConfig::default());
        assert!(md.contains("Panic-Attack Assemblyline Findings"));
        assert!(md.contains("**Scanned:** 0 repos"));
    }

    #[test]
    fn test_generate_markdown_with_findings() {
        let report = make_report(vec![
            make_repo_result("danger-repo", 15, 3, 5),
            make_repo_result("safe-repo", 0, 0, 0),
        ]);
        let md = generate_markdown(&report, &NotifyConfig::default());
        assert!(md.contains("danger-repo"));
        assert!(md.contains("[CRITICAL]"));
        assert!(!md.contains("safe-repo"), "repos with 0 findings should be excluded");
    }

    #[test]
    fn test_generate_markdown_critical_only() {
        let report = make_report(vec![
            make_repo_result("critical-repo", 10, 2, 3),
            make_repo_result("medium-repo", 5, 0, 2),
        ]);
        let config = NotifyConfig {
            critical_only: true,
            ..Default::default()
        };
        let md = generate_markdown(&report, &config);
        assert!(md.contains("critical-repo"));
        assert!(!md.contains("medium-repo"), "non-critical repos should be excluded");
    }

    #[test]
    fn test_generate_markdown_min_findings_filter() {
        let report = make_report(vec![
            make_repo_result("big-repo", 20, 1, 5),
            make_repo_result("small-repo", 2, 0, 1),
        ]);
        let config = NotifyConfig {
            min_findings: 10,
            ..Default::default()
        };
        let md = generate_markdown(&report, &config);
        assert!(md.contains("big-repo"));
        assert!(!md.contains("small-repo"), "repos below threshold should be excluded");
    }

    #[test]
    fn test_generate_markdown_warning_banner_on_criticals() {
        let report = make_report(vec![make_repo_result("vuln-repo", 5, 1, 2)]);
        let md = generate_markdown(&report, &NotifyConfig::default());
        assert!(md.contains("Warning"), "should include warning banner when criticals present");
    }

    #[test]
    fn test_severity_annotations() {
        assert!(!severity_annotation("Critical", "UnsafeCode").is_empty());
        assert!(!severity_annotation("Critical", "CommandInjection").is_empty());
        assert!(!severity_annotation("High", "PanicPath").is_empty());
        assert!(severity_annotation("Low", "PanicPath").is_empty());
    }

    #[test]
    fn test_write_notification_creates_file() {
        let report = make_report(vec![make_repo_result("test-repo", 5, 1, 2)]);
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("notification.md");
        write_notification(&report, &NotifyConfig::default(), &output).unwrap();
        assert!(output.exists());
        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("test-repo"));
    }
}

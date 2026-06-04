// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Report generation logic

use crate::types::*;
use anyhow::Result;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate(
        &self,
        assail_report: AssailReport,
        attack_results: Vec<AttackResult>,
    ) -> Result<AssaultReport> {
        // Keep top-level counters precomputed so downstream views avoid recomputation.
        let total_crashes = attack_results.iter().map(|r| r.crashes.len()).sum();

        let total_signatures = attack_results
            .iter()
            .map(|r| r.signatures_detected.len())
            .sum();

        let overall_assessment = self.assess_results(&assail_report, &attack_results);

        Ok(AssaultReport {
            schema_version: "2.5".to_string(),
            assail_report,
            attack_results,
            total_crashes,
            total_signatures,
            overall_assessment,
            timeline: None,
        })
    }

    fn assess_results(&self, scan: &AssailReport, results: &[AttackResult]) -> OverallAssessment {
        let mut critical_issues = Vec::new();
        let mut recommendations = Vec::new();

        // Calculate robustness score (0-100)
        let _total_attacks = results.len() as f64;
        let _successful_attacks = results.iter().filter(|r| r.success).count() as f64;
        let crash_count = results.iter().map(|r| r.crashes.len()).sum::<usize>() as f64;

        // Score formula is intentionally transparent so teams can tune it safely.
        // Score formula: higher is better
        // - Subtract 10 points for each crash
        // - Subtract 20 points for critical weak points
        // - Subtract 5 points for unsafe code
        let mut score = 100.0;
        score -= crash_count * 10.0;
        score -= scan
            .weak_points
            .iter()
            .filter(|w| w.severity == Severity::Critical)
            .count() as f64
            * 20.0;
        score -= (scan.statistics.unsafe_blocks as f64) * 5.0;

        score = score.clamp(0.0, 100.0);

        // Identify critical issues
        for result in results {
            if !result.crashes.is_empty() {
                critical_issues.push(format!(
                    "Program crashed under {:?} attack ({} crashes)",
                    result.axis,
                    result.crashes.len()
                ));
            }

            for sig in &result.signatures_detected {
                if sig.confidence > 0.8 {
                    critical_issues.push(format!(
                        "High-confidence {:?} detected (confidence: {:.2})",
                        sig.signature_type, sig.confidence
                    ));
                }
            }
        }

        // Recommendations are additive heuristics keyed to observed risk traits.
        if crash_count > 0.0 {
            recommendations.push("Add comprehensive error handling for edge cases".to_string());
        }

        if scan.statistics.unwrap_calls > 10 {
            recommendations.push("Replace unwrap() calls with proper error handling".to_string());
        }

        if scan.statistics.unsafe_blocks > 0 {
            recommendations.push("Audit unsafe blocks for memory safety violations".to_string());
        }

        if results.iter().any(|r| {
            r.signatures_detected
                .iter()
                .any(|s| matches!(s.signature_type, SignatureType::DataRace))
        }) {
            recommendations
                .push("Add synchronization primitives to prevent data races".to_string());
        }

        if results.iter().any(|r| {
            r.signatures_detected
                .iter()
                .any(|s| matches!(s.signature_type, SignatureType::Deadlock))
        }) {
            recommendations.push("Review lock ordering to prevent deadlocks".to_string());
        }

        if score < 50.0 {
            recommendations.push("Consider comprehensive refactoring for robustness".to_string());
        }

        OverallAssessment {
            robustness_score: score,
            critical_issues,
            recommendations,
        }
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

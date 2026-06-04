// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Adjudicate campaign-wide findings using miniKanren-style rule inference.

use crate::abduct::AbductReport;
use crate::amuck::AmuckReport;
use crate::kanren::core::{FactDB, LogicFact, LogicRule, RuleMetadata, Term};
use crate::report;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Upper bound on report reads during adjudication. Reports are JSON
/// documents emitted by earlier panic-attack phases; 64 MiB is well
/// beyond realistic sizes and prevents a tampered input from exhausting
/// memory before even being parsed.
const REPORT_FILE_READ_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AdjudicateConfig {
    pub reports: Vec<PathBuf>,
}

fn adjudicate_schema_version() -> String {
    "2.5".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjudicateReport {
    #[serde(default = "adjudicate_schema_version")]
    pub schema_version: String,
    pub created_at: String,
    pub reports: Vec<PathBuf>,
    pub processed_reports: usize,
    pub failed_reports: usize,
    pub verdict: String,
    pub totals: AdjudicateTotals,
    #[serde(default)]
    pub rule_hits: Vec<RuleHit>,
    #[serde(default)]
    pub priorities: Vec<PriorityFinding>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdjudicateTotals {
    pub assault_reports: usize,
    pub amuck_reports: usize,
    pub abduct_reports: usize,
    pub total_crashes: usize,
    pub total_signatures: usize,
    pub critical_weak_points: usize,
    pub failed_attacks: usize,
    pub mutation_apply_errors: usize,
    pub mutation_exec_failures: usize,
    pub abduct_exec_failures: usize,
    pub abduct_timeouts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    pub rule: String,
    pub derived: usize,
    pub confidence: f64,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityFinding {
    pub level: String,
    pub message: String,
}

pub fn run(config: AdjudicateConfig) -> Result<AdjudicateReport> {
    if config.reports.is_empty() {
        return Err(anyhow!("provide at least one report path"));
    }

    // Totals keep a deterministic numeric summary independent of rule evolution.
    let mut totals = AdjudicateTotals::default();
    let mut notes = Vec::new();
    let mut db = FactDB::new();
    let mut processed = 0usize;
    let mut failed = 0usize;

    for (idx, path) in config.reports.iter().enumerate() {
        let id = format!("report-{}", idx + 1);
        match parse_input_report(path) {
            Ok(ParsedReport::Assault(assault)) => {
                // Assault reports provide both static and dynamic signal density.
                processed += 1;
                totals.assault_reports += 1;
                totals.total_crashes += assault.total_crashes;
                totals.total_signatures += assault.total_signatures;
                totals.critical_weak_points += assault
                    .assail_report
                    .weak_points
                    .iter()
                    .filter(|wp| matches!(wp.severity, crate::types::Severity::Critical))
                    .count();
                totals.failed_attacks += assault
                    .attack_results
                    .iter()
                    .filter(|r| !r.skipped && !r.success)
                    .count();

                db.assert_fact(LogicFact::new("report", vec![Term::atom(&id)]));
                if assault.total_crashes > 0 {
                    db.assert_fact(LogicFact::new("high_signal", vec![Term::atom(&id)]));
                }
                if assault
                    .assail_report
                    .weak_points
                    .iter()
                    .any(|wp| matches!(wp.severity, crate::types::Severity::Critical))
                {
                    db.assert_fact(LogicFact::new("high_signal", vec![Term::atom(&id)]));
                }
                if assault
                    .attack_results
                    .iter()
                    .any(|r| !r.skipped && !r.success)
                {
                    db.assert_fact(LogicFact::new("medium_signal", vec![Term::atom(&id)]));
                }
            }
            Ok(ParsedReport::Amuck(amuck)) => {
                // Mutation errors/failures are usually medium-signal, but trend across runs matters.
                processed += 1;
                totals.amuck_reports += 1;
                totals.mutation_apply_errors += amuck
                    .outcomes
                    .iter()
                    .filter(|o| o.apply_error.is_some())
                    .count();
                totals.mutation_exec_failures += amuck
                    .outcomes
                    .iter()
                    .filter(|o| o.execution.as_ref().is_some_and(|e| !e.success))
                    .count();

                db.assert_fact(LogicFact::new("report", vec![Term::atom(&id)]));
                if amuck.outcomes.iter().any(|o| o.apply_error.is_some()) {
                    db.assert_fact(LogicFact::new("medium_signal", vec![Term::atom(&id)]));
                }
                if amuck
                    .outcomes
                    .iter()
                    .any(|o| o.execution.as_ref().is_some_and(|e| !e.success))
                {
                    db.assert_fact(LogicFact::new("medium_signal", vec![Term::atom(&id)]));
                }
            }
            Ok(ParsedReport::Abduct(abduct)) => {
                // Abduct timeouts are treated as high-signal due to delayed-trigger hunting semantics.
                processed += 1;
                totals.abduct_reports += 1;
                if let Some(exe) = &abduct.execution {
                    if !exe.success {
                        totals.abduct_exec_failures += 1;
                    }
                    if exe.timed_out {
                        totals.abduct_timeouts += 1;
                    }
                }

                db.assert_fact(LogicFact::new("report", vec![Term::atom(&id)]));
                if abduct.execution.as_ref().is_some_and(|exe| exe.timed_out) {
                    db.assert_fact(LogicFact::new("high_signal", vec![Term::atom(&id)]));
                }
                if abduct.execution.as_ref().is_some_and(|exe| !exe.success) {
                    db.assert_fact(LogicFact::new("medium_signal", vec![Term::atom(&id)]));
                }
            }
            Err(err) => {
                failed += 1;
                notes.push(format!("{}: {}", path.display(), err));
            }
        }
    }

    // Rules are intentionally compact; they provide explainable pass/warn/fail decisions.
    load_rules(&mut db);
    let (_, applications) = db.forward_chain();
    let rule_hits = applications
        .into_iter()
        .map(|app| RuleHit {
            rule: app.name,
            derived: app.derived,
            confidence: app.confidence,
            priority: app.priority,
        })
        .collect::<Vec<_>>();

    let has_fail = !db.get_facts("campaign_fail").is_empty();
    let has_warn = !db.get_facts("campaign_warn").is_empty();
    let verdict = if has_fail {
        "fail"
    } else if has_warn {
        "warn"
    } else {
        "pass"
    };

    let priorities = build_priorities(&totals, verdict);

    Ok(AdjudicateReport {
        schema_version: adjudicate_schema_version(),
        created_at: chrono::Utc::now().to_rfc3339(),
        reports: config.reports,
        processed_reports: processed,
        failed_reports: failed,
        verdict: verdict.to_string(),
        totals,
        rule_hits,
        priorities,
        notes,
    })
}

pub fn write_report(report: &AdjudicateReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating report parent directory {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(report).context("serializing adjudicate report")?;
    fs::write(path, json).with_context(|| format!("writing report {}", path.display()))?;
    Ok(())
}

enum ParsedReport {
    Assault(crate::types::AssaultReport),
    Amuck(AmuckReport),
    Abduct(AbductReport),
}

fn parse_input_report(path: &Path) -> Result<ParsedReport> {
    // Try in order of most structured schema to least constrained JSON payloads.
    if let Ok(assault) = report::load_report(path) {
        return Ok(ParsedReport::Assault(assault));
    }

    let content = {
        let mut buf = String::new();
        File::open(path)
            .with_context(|| format!("opening report {}", path.display()))?
            .take(REPORT_FILE_READ_LIMIT)
            .read_to_string(&mut buf)
            .with_context(|| format!("reading report {}", path.display()))?;
        buf
    };
    if let Ok(amuck) = serde_json::from_str::<AmuckReport>(&content) {
        return Ok(ParsedReport::Amuck(amuck));
    }
    if let Ok(abduct) = serde_json::from_str::<AbductReport>(&content) {
        return Ok(ParsedReport::Abduct(abduct));
    }
    Err(anyhow!("unsupported report format"))
}

fn load_rules(db: &mut FactDB) {
    // campaign_fail(global) :- high_signal(R)
    db.add_rule(LogicRule::with_metadata(
        "campaign_fail_on_high_signal".to_string(),
        LogicFact::new("campaign_fail", vec![Term::atom("global")]),
        vec![LogicFact::new("high_signal", vec![Term::Var(0)])],
        RuleMetadata {
            confidence: 0.95,
            priority: 100,
            tags: vec!["triage".to_string(), "critical".to_string()],
            risk_tier: Some("critical".to_string()),
        },
    ));

    // campaign_warn(global) :- medium_signal(R)
    db.add_rule(LogicRule::with_metadata(
        "campaign_warn_on_medium_signal".to_string(),
        LogicFact::new("campaign_warn", vec![Term::atom("global")]),
        vec![LogicFact::new("medium_signal", vec![Term::Var(1)])],
        RuleMetadata {
            confidence: 0.80,
            priority: 60,
            tags: vec!["triage".to_string(), "warning".to_string()],
            risk_tier: Some("warning".to_string()),
        },
    ));
}

fn build_priorities(totals: &AdjudicateTotals, verdict: &str) -> Vec<PriorityFinding> {
    let mut items = Vec::new();
    if totals.total_crashes > 0 {
        items.push(PriorityFinding {
            level: "high".to_string(),
            message: format!(
                "{} crashes detected across assault reports",
                totals.total_crashes
            ),
        });
    }
    if totals.critical_weak_points > 0 {
        items.push(PriorityFinding {
            level: "high".to_string(),
            message: format!(
                "{} critical weak points detected in assail results",
                totals.critical_weak_points
            ),
        });
    }
    if totals.failed_attacks > 0 {
        items.push(PriorityFinding {
            level: "medium".to_string(),
            message: format!(
                "{} failed attack executions need review",
                totals.failed_attacks
            ),
        });
    }
    if totals.mutation_apply_errors > 0 || totals.mutation_exec_failures > 0 {
        items.push(PriorityFinding {
            level: "medium".to_string(),
            message: format!(
                "amuck produced {} apply errors and {} execution failures",
                totals.mutation_apply_errors, totals.mutation_exec_failures
            ),
        });
    }
    if totals.abduct_timeouts > 0 {
        items.push(PriorityFinding {
            level: "high".to_string(),
            message: format!(
                "{} abduct execution timeouts observed",
                totals.abduct_timeouts
            ),
        });
    }
    if items.is_empty() {
        items.push(PriorityFinding {
            level: "info".to_string(),
            message: format!("campaign verdict is {}", verdict),
        });
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amuck::{AmuckOutcome, AmuckReport};
    use tempfile::TempDir;

    #[test]
    fn adjudicate_parses_amuck_and_warns() {
        let dir = TempDir::new().expect("tempdir should create");
        let report_path = dir.path().join("amuck.json");
        let amuck = AmuckReport {
            schema_version: "2.5".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            target: PathBuf::from("src/main.rs"),
            source_spec: None,
            preset: "dangerous".to_string(),
            max_combinations: 1,
            output_dir: PathBuf::from("runtime/amuck"),
            combinations_planned: 1,
            combinations_run: 1,
            outcomes: vec![AmuckOutcome {
                id: 1,
                name: "test".to_string(),
                operations: vec!["append_text".to_string()],
                applied_changes: 1,
                mutated_file: Some(PathBuf::from("runtime/amuck/main.amuck.001.rs")),
                apply_error: None,
                execution: Some(crate::amuck::ExecutionOutcome {
                    success: false,
                    exit_code: Some(1),
                    duration_ms: 1,
                    stdout: String::new(),
                    stderr: "panic".to_string(),
                    spawn_error: None,
                }),
            }],
        };
        fs::write(
            &report_path,
            serde_json::to_string_pretty(&amuck).expect("serialize should work"),
        )
        .expect("report should write");

        let out = run(AdjudicateConfig {
            reports: vec![report_path],
        })
        .expect("adjudicate should run");
        assert_eq!(out.processed_reports, 1);
        assert_eq!(out.totals.amuck_reports, 1);
        assert_eq!(out.verdict, "warn");
    }
}

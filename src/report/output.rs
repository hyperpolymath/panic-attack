// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Serialization helpers for printed/exported reports

use crate::a2ml::{nickel_let, nickel_record};
use crate::report::formatter::nickel_escape_string;
use crate::types::AssaultReport;
use anyhow::Result;
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportOutputFormat {
    Json,
    Yaml,
    /// KYAML, the estate YAML dialect (D280/D307).
    Kyaml,
    Nickel,
    Sarif,
}

impl ReportOutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Some(ReportOutputFormat::Json),
            "yaml" | "yml" => Some(ReportOutputFormat::Yaml),
            "kyaml" => Some(ReportOutputFormat::Kyaml),
            "nickel" | "ncl" => Some(ReportOutputFormat::Nickel),
            "sarif" => Some(ReportOutputFormat::Sarif),
            _ => None,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            ReportOutputFormat::Json => "json",
            ReportOutputFormat::Yaml => "yaml",
            ReportOutputFormat::Kyaml => "kyaml",
            ReportOutputFormat::Nickel => "ncl",
            ReportOutputFormat::Sarif => "sarif",
        }
    }

    pub fn serialize(&self, report: &AssaultReport) -> Result<String> {
        match self {
            ReportOutputFormat::Json => crate::json::to_canonical_string(report),
            ReportOutputFormat::Yaml => Ok(crate::yaml::to_string(report)?),
            ReportOutputFormat::Kyaml => crate::kyaml::to_string(report),
            // Nickel output is a compact projection for config-centric consumers.
            ReportOutputFormat::Nickel => Ok(format_report_as_nickel(report)),
            // SARIF output targets GitHub Security tab and other SARIF consumers.
            // Uses the assail_report (static findings) since SARIF is for static analysis results.
            ReportOutputFormat::Sarif => crate::report::sarif::to_sarif_json(&report.assail_report),
        }
    }
}

fn format_report_as_nickel(report: &AssaultReport) -> String {
    // The Nickel representation intentionally samples large collections to stay readable.
    let assail = &report.assail_report;
    // Fields are `key = value` lines; `nickel_record` joins them with `,`.
    let mut lines = Vec::new();
    lines.push(format!(
        "program = {}",
        nickel_escape_string(&assail.program_path.to_string_lossy())
    ));
    lines.push(format!(
        "language = {}",
        nickel_escape_string(&format!("{:?}", assail.language))
    ));
    lines.push(format!("framework_count = {}", assail.frameworks.len()));
    lines.push(format!("weak_points = {}", assail.weak_points.len()));
    lines.push(format!("total_crashes = {}", report.total_crashes));
    lines.push(format!("total_signatures = {}", report.total_signatures));
    let axes: Vec<String> = report
        .attack_results
        .iter()
        .map(|r| nickel_escape_string(&format!("{:?}", r.axis)))
        .collect();
    lines.push(format!("attack_axes = [{}]", axes.join(", ")));

    if !assail.weak_points.is_empty() {
        let weak_summary: Vec<String> = assail
            .weak_points
            .iter()
            .take(4)
            .map(|wp| {
                format!(
                    "{{ category = {}, severity = {} }}",
                    nickel_escape_string(&format!("{:?}", wp.category)),
                    nickel_escape_string(&format!("{:?}", wp.severity))
                )
            })
            .collect();
        lines.push(format!(
            "weak_point_samples = [{}]",
            weak_summary.join(", ")
        ));
    }

    let pivot_rows: Vec<String> = assail
        .taint_matrix
        .rows
        .iter()
        .take(3)
        .map(|row| {
            format!(
                "{{ source = {}, sink = {}, severity = {} }}",
                nickel_escape_string(&format!("{:?}", row.source_category)),
                nickel_escape_string(&format!("{:?}", row.sink_axis)),
                nickel_number(row.severity_value, Some(1))
            )
        })
        .collect();
    if !pivot_rows.is_empty() {
        lines.push(format!("pivot_samples = [{}]", pivot_rows.join(", ")));
    }

    if let Some(timeline) = &report.timeline {
        lines.push(format!(
            "timeline_duration = {}",
            nickel_number(timeline.duration.as_secs_f64(), None)
        ));
        lines.push(format!("timeline_events = {}", timeline.events.len()));
        let event_samples: Vec<String> = timeline
            .events
            .iter()
            .take(3)
            .map(|event| {
                format!(
                    "{{ id = {}, axis = {}, start = {}, duration = {}, intensity = {} }}",
                    nickel_escape_string(&event.id),
                    nickel_escape_string(&format!("{:?}", event.axis)),
                    nickel_number(event.start_offset.as_secs_f64(), Some(2)),
                    nickel_number(event.duration.as_secs_f64(), Some(2)),
                    nickel_escape_string(&format!("{:?}", event.intensity))
                )
            })
            .collect();
        if !event_samples.is_empty() {
            lines.push(format!("timeline_samples = [{}]", event_samples.join(", ")));
        }
    }

    lines.push(format!(
        "robustness_score = {}",
        nickel_number(report.overall_assessment.robustness_score, Some(1))
    ));

    if !report.overall_assessment.critical_issues.is_empty() {
        let issue_list: Vec<String> = report
            .overall_assessment
            .critical_issues
            .iter()
            .map(|issue| nickel_escape_string(issue))
            .collect();
        lines.push(format!("critical_issues = [{}]", issue_list.join(", ")));
    }

    if !report.overall_assessment.recommendations.is_empty() {
        let rec_list: Vec<String> = report
            .overall_assessment
            .recommendations
            .iter()
            .map(|rec| nickel_escape_string(rec))
            .collect();
        lines.push(format!("recommendations = [{}]", rec_list.join(", ")));
    }

    nickel_let("assault_report", &nickel_record(lines))
}

/// An `f64` as a Nickel number with `decimals` places (or Rust's shortest
/// form for `None`). NaN and the infinities have no Nickel literal, so they
/// become `null` rather than an unparseable token.
fn nickel_number(value: f64, decimals: Option<usize>) -> String {
    if !value.is_finite() {
        return "null".to_string();
    }
    match decimals {
        Some(places) => format!("{value:.places$}"),
        None => format!("{value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AttackAxis, IntensityLevel, OverallAssessment, TaintMatrixRow, TimelineEventReport,
        TimelineReport, WeakPoint, WeakPointCategory,
    };
    use std::fs;
    use std::time::Duration;
    use tempfile::TempDir;

    /// An assault report with every section the Nickel writer emits: weak
    /// points, a taint row, a timeline, issues and recommendations.
    fn full_report(dir: &TempDir) -> AssaultReport {
        fs::write(dir.path().join("main.rs"), "fn main() {}\n").expect("write");
        let mut assail = crate::assail::analyze(dir.path()).expect("analyze");
        let weak: WeakPoint = serde_json::from_value(serde_json::json!({
            "category": "PanicPath",
            "location": "main.rs:1",
            "severity": "High",
            "description": "unwrap on a None",
            "recommended_attack": ["cpu"],
        }))
        .expect("weak point");
        assail.weak_points.push(weak);
        assail.taint_matrix.rows.push(TaintMatrixRow {
            source_category: WeakPointCategory::PanicPath,
            sink_axis: AttackAxis::Cpu,
            severity_value: 3.25,
            files: vec!["main.rs".to_string()],
            frameworks: Vec::new(),
            relation: "direct".to_string(),
        });
        AssaultReport {
            schema_version: "2.5".to_string(),
            assail_report: assail,
            attack_results: Vec::new(),
            total_crashes: 1,
            total_signatures: 0,
            overall_assessment: OverallAssessment {
                robustness_score: 42.0,
                critical_issues: vec!["crash".to_string()],
                recommendations: vec!["fix it".to_string()],
            },
            timeline: Some(TimelineReport {
                duration: Duration::from_millis(1500),
                events: vec![TimelineEventReport {
                    id: "evt-1".to_string(),
                    axis: AttackAxis::Memory,
                    start_offset: Duration::from_secs(5),
                    duration: Duration::from_secs(10),
                    intensity: IntensityLevel::Medium,
                    args: Vec::new(),
                    peak_memory: None,
                    ran: true,
                }],
            }),
        }
    }

    #[test]
    fn assault_report_nickel_uses_nickel_record_and_let_syntax() {
        // Nickel separates record fields with `,` and binds with `let … in`;
        // the old `field = value;` lines and `};\nassault_report` tail did not
        // parse (`nickel export` 1.18.0: "unexpected token").
        let dir = TempDir::new().expect("tempdir");
        let nickel = format_report_as_nickel(&full_report(&dir));
        assert!(nickel.starts_with("let assault_report = {\n"), "{nickel}");
        assert!(nickel.ends_with("\n} in\nassault_report"), "{nickel}");
        assert!(nickel.contains(",\n    weak_points = 1,\n"), "{nickel}");
        assert!(!nickel.contains(';'), "{nickel}");

        // Where the Nickel CLI is installed, it must accept the output and
        // keep the types: counts and scores are numbers, not strings.
        let file = dir.path().join("report.ncl");
        fs::write(&file, &nickel).expect("write");
        if let Ok(out) = std::process::Command::new("nickel")
            .args(["export", "--format", "json"])
            .arg(&file)
            .output()
        {
            assert!(
                out.status.success(),
                "{nickel}\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let json: serde_json::Value =
                serde_json::from_slice(&out.stdout).expect("nickel export emits JSON");
            assert_eq!(json["weak_points"], 1);
            assert_eq!(json["robustness_score"], 42.0);
            assert_eq!(json["timeline_duration"], 1.5);
            assert_eq!(json["timeline_samples"][0]["start"], 5.0);
            assert_eq!(json["pivot_samples"][0]["severity"], 3.2);
            assert_eq!(json["weak_point_samples"][0]["category"], "PanicPath");
            assert_eq!(json["critical_issues"][0], "crash");
        }
    }

    #[test]
    fn nickel_strings_stay_literal() {
        // `%{…}` is interpolation in Nickel and JSON quoting leaves it alone;
        // JSON's `\b`, `\f` and `\u001f` are not Nickel escapes at all.
        let tricky = [
            "/tmp/%{true}/x",
            "100% sure",
            "a\u{8}b\u{c}c\u{1f}d",
            "tab\tline\nret\r\"q\" back\\slash",
            "plain ünïcode ✓",
        ];
        assert_eq!(nickel_escape_string("/tmp/%{true}"), "\"/tmp/\\%{true}\"");
        assert_eq!(nickel_escape_string("a\u{1f}"), "\"a\\u{1f}\"");
        assert!(!nickel_escape_string("a\u{8}").contains("\\b"));

        let dir = TempDir::new().expect("tempdir");
        let file = dir.path().join("strings.ncl");
        let body = tricky
            .iter()
            .map(|s| nickel_escape_string(s))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(&file, format!("[{body}]")).expect("write");
        if let Ok(out) = std::process::Command::new("nickel")
            .args(["export", "--format", "json"])
            .arg(&file)
            .output()
        {
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let back: Vec<String> =
                serde_json::from_slice(&out.stdout).expect("nickel export emits a JSON array");
            assert_eq!(back, tricky);
        }
    }

    #[test]
    fn non_finite_numbers_become_null() {
        assert_eq!(nickel_number(f64::NAN, Some(1)), "null");
        assert_eq!(nickel_number(f64::INFINITY, None), "null");
        assert_eq!(nickel_number(2.0, Some(1)), "2.0");
        assert_eq!(nickel_number(1.5, None), "1.5");
    }
}

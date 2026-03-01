// SPDX-License-Identifier: PMPL-1.0-or-later

//! Serialization helpers for printed/exported reports

use crate::report::formatter::nickel_escape_string;
use crate::types::AssaultReport;
use anyhow::Result;
use clap::ValueEnum;
use serde_json;
use serde_yaml;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportOutputFormat {
    Json,
    Yaml,
    Nickel,
    Sarif,
}

impl ReportOutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Some(ReportOutputFormat::Json),
            "yaml" | "yml" => Some(ReportOutputFormat::Yaml),
            "nickel" | "ncl" => Some(ReportOutputFormat::Nickel),
            "sarif" => Some(ReportOutputFormat::Sarif),
            _ => None,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            ReportOutputFormat::Json => "json",
            ReportOutputFormat::Yaml => "yaml",
            ReportOutputFormat::Nickel => "ncl",
            ReportOutputFormat::Sarif => "sarif",
        }
    }

    pub fn serialize(&self, report: &AssaultReport) -> Result<String> {
        match self {
            ReportOutputFormat::Json => Ok(serde_json::to_string_pretty(report)?),
            ReportOutputFormat::Yaml => Ok(serde_yaml::to_string(report)?),
            // Nickel output is a compact projection for config-centric consumers.
            ReportOutputFormat::Nickel => Ok(format_report_as_nickel(report)),
            // SARIF output targets GitHub Security tab and other SARIF consumers.
            // Uses the assail_report (static findings) since SARIF is for static analysis results.
            ReportOutputFormat::Sarif => {
                crate::report::sarif::to_sarif_json(&report.assail_report)
            }
        }
    }
}

fn format_report_as_nickel(report: &AssaultReport) -> String {
    // The Nickel representation intentionally samples large collections to stay readable.
    let assail = &report.assail_report;
    let mut lines = Vec::new();
    lines.push("let assault_report = {".to_string());
    lines.push(format!(
        "  program = {};",
        nickel_escape_string(&assail.program_path.to_string_lossy())
    ));
    lines.push(format!(
        "  language = {};",
        nickel_escape_string(&format!("{:?}", assail.language))
    ));
    lines.push(format!("  framework_count = {};", assail.frameworks.len()));
    lines.push(format!("  weak_points = {};", assail.weak_points.len()));
    lines.push(format!("  total_crashes = {};", report.total_crashes));
    lines.push(format!("  total_signatures = {};", report.total_signatures));
    let axes: Vec<String> = report
        .attack_results
        .iter()
        .map(|r| nickel_escape_string(&format!("{:?}", r.axis)))
        .collect();
    lines.push(format!("  attack_axes = [{}];", axes.join(", ")));

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
            "  weak_point_samples = [{}];",
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
                "{{ source = {}, sink = {}, severity = {:.1} }}",
                nickel_escape_string(&format!("{:?}", row.source_category)),
                nickel_escape_string(&format!("{:?}", row.sink_axis)),
                row.severity_value
            )
        })
        .collect();
    if !pivot_rows.is_empty() {
        lines.push(format!("  pivot_samples = [{}];", pivot_rows.join(", ")));
    }

    if let Some(timeline) = &report.timeline {
        lines.push(format!(
            "  timeline_duration = {};",
            timeline.duration.as_secs_f64()
        ));
        lines.push(format!("  timeline_events = {};", timeline.events.len()));
        let event_samples: Vec<String> = timeline
            .events
            .iter()
            .take(3)
            .map(|event| {
                format!(
                    "{{ id = {}, axis = {}, start = {:.2}, duration = {:.2}, intensity = {} }}",
                    nickel_escape_string(&event.id),
                    nickel_escape_string(&format!("{:?}", event.axis)),
                    event.start_offset.as_secs_f64(),
                    event.duration.as_secs_f64(),
                    nickel_escape_string(&format!("{:?}", event.intensity))
                )
            })
            .collect();
        if !event_samples.is_empty() {
            lines.push(format!(
                "  timeline_samples = [{}];",
                event_samples.join(", ")
            ));
        }
    }

    lines.push(format!(
        "  robustness_score = {:.1};",
        report.overall_assessment.robustness_score
    ));

    if !report.overall_assessment.critical_issues.is_empty() {
        let issue_list: Vec<String> = report
            .overall_assessment
            .critical_issues
            .iter()
            .map(|issue| nickel_escape_string(issue))
            .collect();
        lines.push(format!("  critical_issues = [{}];", issue_list.join(", ")));
    }

    if !report.overall_assessment.recommendations.is_empty() {
        let rec_list: Vec<String> = report
            .overall_assessment
            .recommendations
            .iter()
            .map(|rec| nickel_escape_string(rec))
            .collect();
        lines.push(format!("  recommendations = [{}];", rec_list.join(", ")));
    }

    lines.push("};".to_string());
    lines.push("assault_report".to_string());
    lines.join("\n")
}

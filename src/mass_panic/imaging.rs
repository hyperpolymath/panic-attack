// SPDX-License-Identifier: PMPL-1.0-or-later

//! System health imaging — fNIRS-inspired spatial risk mapping.
//!
//! Concept: fNIRS measures blood oxygenation across cortical regions to create
//! a functional map of brain activity. This module measures weak point density,
//! risk intensity, and change velocity across repository topology to create a
//! functional map of codebase health.
//!
//! Terminology mapping:
//!   fNIRS                → panic-attack
//!   Cortical region      → Repository / directory / file
//!   Blood oxygenation    → Health score (inverse of risk)
//!   Neural activation    → Weak point density (findings per KLOC)
//!   Hemodynamic response → Change velocity (fingerprint delta rate)
//!   Optode channel       → Dependency / taint flow edge
//!   Functional map       → SystemImage

use crate::assemblyline::AssemblylineReport;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// A SystemImage is a point-in-time "functional scan" of an entire codebase.
/// Each scan produces one image. Multiple images over time create a navigable
/// timeline of system health evolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemImage {
    pub format: String,
    pub generated_at: String,
    /// Root directory, GitHub account, or org name being scanned
    pub scan_surface: String,
    pub node_count: usize,
    pub edge_count: usize,
    /// Aggregate health: 0.0 (critical) to 1.0 (healthy)
    pub global_health: f64,
    /// Aggregate risk: 0.0 (safe) to 1.0 (critical)
    pub global_risk: f64,
    pub total_weak_points: usize,
    pub total_critical: usize,
    pub total_lines: usize,
    pub total_files: usize,
    pub repos_scanned: usize,
    /// Image nodes — the "voxels" of the scan
    pub nodes: Vec<ImageNode>,
    /// Cross-node edges — functional connectivity
    pub edges: Vec<ImageEdge>,
    /// Risk distribution histogram
    pub risk_distribution: RiskDistribution,
}

/// An ImageNode is one "voxel" — a repository's health reading at scan time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageNode {
    pub id: String,
    pub path: String,
    pub name: String,
    /// Granularity level: repository, directory, or file
    pub level: NodeLevel,
    /// 0.0 = critical, 1.0 = healthy
    pub health_score: f64,
    /// 0.0 = safe, 1.0 = critical (sigmoid-squashed)
    pub risk_intensity: f64,
    /// Findings per 1000 lines of code
    pub weak_point_density: f64,
    pub weak_point_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub total_files: usize,
    pub total_lines: usize,
    /// BLAKE3 fingerprint for temporal diff
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub skipped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Per-category breakdown — the "spectral channels" of the scan
    #[serde(default)]
    pub categories: Vec<CategoryCount>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeLevel {
    Repository,
    Directory,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryCount {
    pub name: String,
    pub count: usize,
}

/// An edge between two nodes representing functional connectivity.
/// Repos with similar risk profiles or shared vulnerability patterns
/// are connected, revealing systemic risk propagation paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageEdge {
    pub from_node: String,
    pub to_node: String,
    pub edge_type: EdgeType,
    pub weight: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    /// Repos with similar risk intensity (within threshold)
    RiskProximity,
    /// Repos sharing the same dominant vulnerability category
    SharedPattern,
    /// Repos with a direct dependency relationship
    Dependency,
}

/// Risk distribution histogram — how many nodes at each risk level.
/// Analogous to an fNIRS activation histogram showing channel distribution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskDistribution {
    /// risk < 0.2
    pub healthy: usize,
    /// 0.2 <= risk < 0.4
    pub low: usize,
    /// 0.4 <= risk < 0.6
    pub moderate: usize,
    /// 0.6 <= risk < 0.8
    pub high: usize,
    /// risk >= 0.8
    pub critical: usize,
}

/// Build a SystemImage from an assemblyline report.
///
/// This is the primary entry point for imaging on the Rust side.
/// The Chapel orchestrator calls this via the panic-attack binary
/// or builds equivalent images directly from distributed results.
pub fn build_image(report: &AssemblylineReport) -> SystemImage {
    let mut nodes = Vec::with_capacity(report.results.len());
    let mut total_lines = 0usize;
    let mut total_files = 0usize;
    let mut health_sum = 0.0f64;
    let mut risk_sum = 0.0f64;
    let mut measured_count = 0usize;
    let mut risk_dist = RiskDistribution::default();

    for result in &report.results {
        let skipped = result
            .error
            .as_ref()
            .map(|e| e.contains("skipped"))
            .unwrap_or(false);

        let (health, risk, density) = if !skipped && result.error.is_none() {
            let kloc = result.total_lines.max(1) as f64 / 1000.0;
            let density = result.weak_point_count as f64 / kloc;

            // Risk intensity: critical 3x, high 2x, others 1x, normalised by KLOC
            let others = result
                .weak_point_count
                .saturating_sub(result.critical_count)
                .saturating_sub(result.high_count);
            let weighted = (result.critical_count * 3 + result.high_count * 2 + others) as f64;
            let raw_risk = weighted / kloc;
            let risk = sigmoid(raw_risk, 5.0, 0.5);
            let health = 1.0 - risk;

            total_lines += result.total_lines;
            total_files += result.total_files;
            health_sum += health;
            risk_sum += risk;
            measured_count += 1;

            classify_risk(&mut risk_dist, risk);

            (health, risk, density)
        } else {
            (1.0, 0.0, 0.0)
        };

        // Build per-category breakdown from the report if available
        let categories = if let Some(ref rpt) = result.report {
            let mut cat_counts: HashMap<String, usize> = HashMap::new();
            for wp in &rpt.weak_points {
                *cat_counts.entry(format!("{:?}", wp.category)).or_insert(0) += 1;
            }
            let mut cats: Vec<CategoryCount> = cat_counts
                .into_iter()
                .map(|(name, count)| CategoryCount { name, count })
                .collect();
            cats.sort_by(|a, b| b.count.cmp(&a.count));
            cats
        } else {
            Vec::new()
        };

        nodes.push(ImageNode {
            id: format!("repo:{}", result.repo_name),
            path: result.repo_path.display().to_string(),
            name: result.repo_name.clone(),
            level: NodeLevel::Repository,
            health_score: health,
            risk_intensity: risk,
            weak_point_density: density,
            weak_point_count: result.weak_point_count,
            critical_count: result.critical_count,
            high_count: result.high_count,
            total_files: result.total_files,
            total_lines: result.total_lines,
            fingerprint: result.fingerprint.clone(),
            skipped,
            error: if skipped { None } else { result.error.clone() },
            categories,
        });
    }

    let edges = build_edges(&nodes);
    let edge_count = edges.len();
    let node_count = nodes.len();

    let (global_health, global_risk) = if measured_count > 0 {
        (
            health_sum / measured_count as f64,
            risk_sum / measured_count as f64,
        )
    } else {
        (1.0, 0.0)
    };

    SystemImage {
        format: "panic-attack.system-image.v1".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        scan_surface: report.directory.display().to_string(),
        node_count,
        edge_count,
        global_health,
        global_risk,
        total_weak_points: report.total_weak_points,
        total_critical: report.total_critical,
        total_lines,
        total_files,
        repos_scanned: report.repos_scanned,
        nodes,
        edges,
        risk_distribution: risk_dist,
    }
}

/// Build functional connectivity edges between nodes.
///
/// Two types of edges:
/// - **Risk proximity**: nodes with similar risk intensity (within 0.15)
///   where both are above 0.3 risk. These reveal systemic risk clusters.
/// - **Shared pattern**: nodes sharing the same dominant vulnerability
///   category with 3+ findings each. These reveal common architectural
///   weaknesses propagating across repos.
fn build_edges(nodes: &[ImageNode]) -> Vec<ImageEdge> {
    let mut edges = Vec::new();

    for (i, a) in nodes.iter().enumerate() {
        if a.skipped || a.error.is_some() {
            continue;
        }
        for b in nodes.iter().skip(i + 1) {
            if b.skipped || b.error.is_some() {
                continue;
            }

            // Risk proximity edge
            let risk_delta = (a.risk_intensity - b.risk_intensity).abs();
            if risk_delta < 0.15 && a.risk_intensity > 0.3 {
                edges.push(ImageEdge {
                    from_node: a.id.clone(),
                    to_node: b.id.clone(),
                    edge_type: EdgeType::RiskProximity,
                    weight: 1.0 - risk_delta / 0.15,
                });
            }

            // Shared pattern edge
            if shares_dominant_category(a, b) {
                edges.push(ImageEdge {
                    from_node: a.id.clone(),
                    to_node: b.id.clone(),
                    edge_type: EdgeType::SharedPattern,
                    weight: 0.8,
                });
            }
        }
    }

    edges
}

fn shares_dominant_category(a: &ImageNode, b: &ImageNode) -> bool {
    if a.categories.is_empty() || b.categories.is_empty() {
        return false;
    }
    // Dominant = highest-count category
    let a_dominant = &a.categories[0]; // already sorted descending
    if a_dominant.count < 3 {
        return false;
    }
    b.categories
        .iter()
        .any(|cat| cat.name == a_dominant.name && cat.count >= 3)
}

/// Sigmoid squash to [0, 1]. Midpoint controls where 0.5 falls,
/// steepness controls transition sharpness.
fn sigmoid(x: f64, midpoint: f64, steepness: f64) -> f64 {
    1.0 / (1.0 + (-(x - midpoint) * steepness).exp())
}

fn classify_risk(dist: &mut RiskDistribution, risk: f64) {
    if risk < 0.2 {
        dist.healthy += 1;
    } else if risk < 0.4 {
        dist.low += 1;
    } else if risk < 0.6 {
        dist.moderate += 1;
    } else if risk < 0.8 {
        dist.high += 1;
    } else {
        dist.critical += 1;
    }
}

/// Write a SystemImage to a JSON file.
pub fn write_image(image: &SystemImage, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating image parent {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(image)?;
    fs::write(path, &json).with_context(|| format!("writing image {}", path.display()))?;
    Ok(())
}

/// Load a SystemImage from a JSON file.
pub fn load_image(path: &Path) -> Result<SystemImage> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading image {}", path.display()))?;
    let image: SystemImage =
        serde_json::from_str(&content).with_context(|| format!("parsing image {}", path.display()))?;
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigmoid_midpoint_gives_half() {
        let v = sigmoid(5.0, 5.0, 0.5);
        assert!((v - 0.5).abs() < 0.001, "sigmoid at midpoint should be 0.5");
    }

    #[test]
    fn sigmoid_extreme_high_approaches_one() {
        let v = sigmoid(20.0, 5.0, 0.5);
        assert!(v > 0.99, "sigmoid at 20 should approach 1.0");
    }

    #[test]
    fn sigmoid_extreme_low_approaches_zero() {
        let v = sigmoid(-10.0, 5.0, 0.5);
        assert!(v < 0.01, "sigmoid at -10 should approach 0.0");
    }

    #[test]
    fn classify_risk_buckets() {
        let mut dist = RiskDistribution::default();
        classify_risk(&mut dist, 0.1);
        classify_risk(&mut dist, 0.3);
        classify_risk(&mut dist, 0.5);
        classify_risk(&mut dist, 0.7);
        classify_risk(&mut dist, 0.9);
        assert_eq!(dist.healthy, 1);
        assert_eq!(dist.low, 1);
        assert_eq!(dist.moderate, 1);
        assert_eq!(dist.high, 1);
        assert_eq!(dist.critical, 1);
    }

    #[test]
    fn empty_report_gives_healthy_image() {
        let report = crate::assemblyline::AssemblylineReport {
            created_at: "2026-03-07T00:00:00Z".to_string(),
            directory: std::path::PathBuf::from("/tmp"),
            repos_scanned: 0,
            repos_with_findings: 0,
            repos_skipped: 0,
            total_weak_points: 0,
            total_critical: 0,
            results: Vec::new(),
        };
        let image = build_image(&report);
        assert_eq!(image.global_health, 1.0);
        assert_eq!(image.global_risk, 0.0);
        assert_eq!(image.node_count, 0);
    }

    #[test]
    fn image_nodes_match_report_results() {
        let report = crate::assemblyline::AssemblylineReport {
            created_at: "2026-03-07T00:00:00Z".to_string(),
            directory: std::path::PathBuf::from("/tmp"),
            repos_scanned: 2,
            repos_with_findings: 1,
            repos_skipped: 0,
            total_weak_points: 5,
            total_critical: 1,
            results: vec![
                crate::assemblyline::RepoResult {
                    repo_path: std::path::PathBuf::from("/tmp/repo-a"),
                    repo_name: "repo-a".to_string(),
                    weak_point_count: 5,
                    critical_count: 1,
                    high_count: 2,
                    total_files: 10,
                    total_lines: 2000,
                    error: None,
                    fingerprint: Some("abc123".to_string()),
                    report: None,
                },
                crate::assemblyline::RepoResult {
                    repo_path: std::path::PathBuf::from("/tmp/repo-b"),
                    repo_name: "repo-b".to_string(),
                    weak_point_count: 0,
                    critical_count: 0,
                    high_count: 0,
                    total_files: 3,
                    total_lines: 500,
                    error: None,
                    fingerprint: Some("def456".to_string()),
                    report: None,
                },
            ],
        };
        let image = build_image(&report);
        assert_eq!(image.node_count, 2);
        assert_eq!(image.nodes[0].name, "repo-a");
        assert!(image.nodes[0].risk_intensity > 0.0);
        assert!(image.nodes[1].risk_intensity < image.nodes[0].risk_intensity);
    }
}

// SPDX-License-Identifier: PMPL-1.0-or-later

//! Temporal navigation — time-series snapshots of system health.
//!
//! Every mass-panic scan produces a SystemImage. This module stores those
//! images as VeriSimDB temporal hexads, creating a navigable timeline.
//!
//! Capabilities:
//! - Take snapshots with optional labels ("pre-refactor", "v2.1.0")
//! - Diff any two snapshots to see what changed
//! - List timeline showing health evolution
//! - Identify trends: improving, degrading, oscillating
//! - Compute impact: what changed between two points

use crate::mass_panic::imaging::SystemImage;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Lightweight summary of a snapshot for the temporal index.
/// Contains enough information for timeline browsing without
/// loading full SystemImage files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub id: String,
    pub timestamp: String,
    #[serde(default)]
    pub label: String,
    pub sequence: usize,
    pub image_path: PathBuf,
    pub global_health: f64,
    pub global_risk: f64,
    pub total_weak_points: usize,
    pub total_critical: usize,
    pub repos_scanned: usize,
    pub node_count: usize,
}

/// The temporal index — a lightweight manifest of all snapshots in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalIndex {
    pub format: String,
    pub last_updated: String,
    pub snapshot_count: usize,
    pub snapshots: Vec<SnapshotEntry>,
}

impl Default for TemporalIndex {
    fn default() -> Self {
        Self {
            format: "panic-attack.temporal-index.v1".to_string(),
            last_updated: String::new(),
            snapshot_count: 0,
            snapshots: Vec::new(),
        }
    }
}

/// Diff between two temporal snapshots — shows what changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalDiff {
    pub format: String,
    pub from_timestamp: String,
    pub to_timestamp: String,
    #[serde(default)]
    pub from_label: String,
    #[serde(default)]
    pub to_label: String,
    /// Positive = system got healthier
    pub health_delta: f64,
    /// Negative = system got safer
    pub risk_delta: f64,
    /// Negative = fewer weak points (improved)
    pub weak_point_delta: i64,
    /// Negative = fewer critical findings (improved)
    pub critical_delta: i64,
    pub new_nodes: Vec<String>,
    pub removed_nodes: Vec<String>,
    pub improved_nodes: Vec<NodeDelta>,
    pub degraded_nodes: Vec<NodeDelta>,
    pub unchanged_count: usize,
    /// Overall trend verdict
    pub trend: Trend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDelta {
    pub node_id: String,
    pub name: String,
    pub health_before: f64,
    pub health_after: f64,
    pub risk_before: f64,
    pub risk_after: f64,
    pub weak_points_before: usize,
    pub weak_points_after: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trend {
    Improving,
    Degrading,
    Stable,
    Mixed,
}

/// Take a temporal snapshot: save a SystemImage to the VeriSimDB directory
/// and update the temporal index.
pub fn take_snapshot(
    image: &SystemImage,
    verisimdb_dir: &Path,
    label: &str,
) -> Result<SnapshotEntry> {
    let index_path = verisimdb_dir.join("temporal-index.json");
    let mut index = load_index(&index_path).unwrap_or_default();

    let seq = index.snapshot_count + 1;
    let snapshot_id = format!("snap-{}", seq);

    // Write the system image
    let images_dir = verisimdb_dir.join("images");
    fs::create_dir_all(&images_dir)
        .with_context(|| format!("creating images dir {}", images_dir.display()))?;
    let image_path = images_dir.join(format!("{}-image.json", snapshot_id));
    let json = serde_json::to_string_pretty(image)?;
    fs::write(&image_path, json)
        .with_context(|| format!("writing image {}", image_path.display()))?;

    // Write VeriSimDB hexad
    let hexad_dir = verisimdb_dir.join("hexads");
    fs::create_dir_all(&hexad_dir)?;
    let hexad_path = hexad_dir.join(format!("{}.json", snapshot_id));
    let hexad = build_temporal_hexad(image, &snapshot_id, seq, label);
    let hexad_json = serde_json::to_string_pretty(&hexad)?;
    fs::write(&hexad_path, hexad_json)?;

    let entry = SnapshotEntry {
        id: snapshot_id,
        timestamp: image.generated_at.clone(),
        label: label.to_string(),
        sequence: seq,
        image_path: image_path.clone(),
        global_health: image.global_health,
        global_risk: image.global_risk,
        total_weak_points: image.total_weak_points,
        total_critical: image.total_critical,
        repos_scanned: image.repos_scanned,
        node_count: image.node_count,
    };

    index.snapshots.push(entry.clone());
    index.snapshot_count = index.snapshots.len();
    index.last_updated = image.generated_at.clone();

    save_index(&index, &index_path)?;

    Ok(entry)
}

/// Diff two system images, producing a detailed change report.
pub fn diff_images(
    older: &SystemImage,
    newer: &SystemImage,
    older_label: &str,
    newer_label: &str,
) -> TemporalDiff {
    let health_delta = newer.global_health - older.global_health;
    let risk_delta = newer.global_risk - older.global_risk;
    let weak_point_delta = newer.total_weak_points as i64 - older.total_weak_points as i64;
    let critical_delta = newer.total_critical as i64 - older.total_critical as i64;

    // Build node lookup maps
    let older_nodes: std::collections::HashMap<&str, &crate::mass_panic::imaging::ImageNode> =
        older.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let newer_nodes: std::collections::HashMap<&str, &crate::mass_panic::imaging::ImageNode> =
        newer.nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    let mut new_nodes = Vec::new();
    let mut removed_nodes = Vec::new();
    let mut improved_nodes = Vec::new();
    let mut degraded_nodes = Vec::new();
    let mut unchanged_count = 0usize;

    // Check newer nodes against older
    for node in &newer.nodes {
        if let Some(old_node) = older_nodes.get(node.id.as_str()) {
            if node.skipped || old_node.skipped {
                continue;
            }
            let change = node.health_score - old_node.health_score;
            if change.abs() < 0.01 {
                unchanged_count += 1;
            } else {
                let delta = NodeDelta {
                    node_id: node.id.clone(),
                    name: node.name.clone(),
                    health_before: old_node.health_score,
                    health_after: node.health_score,
                    risk_before: old_node.risk_intensity,
                    risk_after: node.risk_intensity,
                    weak_points_before: old_node.weak_point_count,
                    weak_points_after: node.weak_point_count,
                };
                if change > 0.0 {
                    improved_nodes.push(delta);
                } else {
                    degraded_nodes.push(delta);
                }
            }
        } else {
            new_nodes.push(node.id.clone());
        }
    }

    // Check for removed nodes
    for node in &older.nodes {
        if !newer_nodes.contains_key(node.id.as_str()) {
            removed_nodes.push(node.id.clone());
        }
    }

    // Determine trend
    let trend = if health_delta > 0.02 && degraded_nodes.is_empty() {
        Trend::Improving
    } else if health_delta < -0.02 && improved_nodes.is_empty() {
        Trend::Degrading
    } else if health_delta.abs() < 0.01 {
        Trend::Stable
    } else {
        Trend::Mixed
    };

    TemporalDiff {
        format: "panic-attack.temporal-diff.v1".to_string(),
        from_timestamp: older.generated_at.clone(),
        to_timestamp: newer.generated_at.clone(),
        from_label: older_label.to_string(),
        to_label: newer_label.to_string(),
        health_delta,
        risk_delta,
        weak_point_delta,
        critical_delta,
        new_nodes,
        removed_nodes,
        improved_nodes,
        degraded_nodes,
        unchanged_count,
        trend,
    }
}

/// Write a temporal diff to a JSON file.
pub fn write_diff(diff: &TemporalDiff, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(diff)?;
    fs::write(path, json).with_context(|| format!("writing diff {}", path.display()))?;
    Ok(())
}

/// List all snapshots in the temporal index.
pub fn list_snapshots(verisimdb_dir: &Path) -> Result<Vec<SnapshotEntry>> {
    let index_path = verisimdb_dir.join("temporal-index.json");
    let index = load_index(&index_path)?;
    Ok(index.snapshots)
}

/// Load a snapshot's SystemImage by its entry.
pub fn load_snapshot_image(entry: &SnapshotEntry) -> Result<SystemImage> {
    crate::mass_panic::imaging::load_image(&entry.image_path)
}

/// Get two snapshots by sequence number for diffing.
pub fn get_snapshot_pair(
    verisimdb_dir: &Path,
    from_seq: usize,
    to_seq: usize,
) -> Result<(SnapshotEntry, SnapshotEntry)> {
    let index_path = verisimdb_dir.join("temporal-index.json");
    let index = load_index(&index_path)?;

    let from = index
        .snapshots
        .iter()
        .find(|s| s.sequence == from_seq)
        .ok_or_else(|| anyhow!("snapshot {} not found", from_seq))?
        .clone();
    let to = index
        .snapshots
        .iter()
        .find(|s| s.sequence == to_seq)
        .ok_or_else(|| anyhow!("snapshot {} not found", to_seq))?
        .clone();

    Ok((from, to))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn load_index(path: &Path) -> Result<TemporalIndex> {
    if !path.exists() {
        return Err(anyhow!("temporal index not found at {}", path.display()));
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading temporal index {}", path.display()))?;
    let index: TemporalIndex = serde_json::from_str(&content)
        .with_context(|| format!("parsing temporal index {}", path.display()))?;
    Ok(index)
}

fn save_index(index: &TemporalIndex, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(index)?;
    fs::write(path, json).with_context(|| format!("writing temporal index {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct TemporalHexad {
    schema: String,
    id: String,
    created_at: String,
    provenance: HexadProvenance,
    temporal: HexadTemporal,
    semantic: HexadSemantic,
    structural: HexadStructural,
}

#[derive(Debug, Serialize)]
struct HexadProvenance {
    tool: String,
    version: String,
    scan_surface: String,
}

#[derive(Debug, Serialize)]
struct HexadTemporal {
    timestamp: String,
    sequence_number: usize,
    label: String,
}

#[derive(Debug, Serialize)]
struct HexadSemantic {
    global_health: f64,
    global_risk: f64,
    total_weak_points: usize,
    total_critical: usize,
    repos_scanned: usize,
    node_count: usize,
    edge_count: usize,
}

#[derive(Debug, Serialize)]
struct HexadStructural {
    total_files: usize,
    total_lines: usize,
    risk_distribution: crate::mass_panic::imaging::RiskDistribution,
}

fn build_temporal_hexad(
    image: &SystemImage,
    snapshot_id: &str,
    seq: usize,
    label: &str,
) -> TemporalHexad {
    TemporalHexad {
        schema: "verisimdb.hexad.v1".to_string(),
        id: snapshot_id.to_string(),
        created_at: image.generated_at.clone(),
        provenance: HexadProvenance {
            tool: "panic-attack".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            scan_surface: image.scan_surface.clone(),
        },
        temporal: HexadTemporal {
            timestamp: image.generated_at.clone(),
            sequence_number: seq,
            label: label.to_string(),
        },
        semantic: HexadSemantic {
            global_health: image.global_health,
            global_risk: image.global_risk,
            total_weak_points: image.total_weak_points,
            total_critical: image.total_critical,
            repos_scanned: image.repos_scanned,
            node_count: image.node_count,
            edge_count: image.edge_count,
        },
        structural: HexadStructural {
            total_files: image.total_files,
            total_lines: image.total_lines,
            risk_distribution: image.risk_distribution.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_image(health: f64, weak_points: usize) -> SystemImage {
        SystemImage {
            format: "panic-attack.system-image.v1".to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            scan_surface: "/tmp/test".to_string(),
            node_count: 1,
            edge_count: 0,
            global_health: health,
            global_risk: 1.0 - health,
            total_weak_points: weak_points,
            total_critical: 0,
            total_lines: 1000,
            total_files: 10,
            repos_scanned: 1,
            nodes: vec![crate::mass_panic::imaging::ImageNode {
                id: "repo:test".to_string(),
                path: "/tmp/test".to_string(),
                name: "test".to_string(),
                level: crate::mass_panic::imaging::NodeLevel::Repository,
                health_score: health,
                risk_intensity: 1.0 - health,
                weak_point_density: weak_points as f64,
                weak_point_count: weak_points,
                critical_count: 0,
                high_count: 0,
                total_files: 10,
                total_lines: 1000,
                fingerprint: None,
                skipped: false,
                error: None,
                categories: Vec::new(),
            }],
            edges: Vec::new(),
            risk_distribution: crate::mass_panic::imaging::RiskDistribution::default(),
        }
    }

    #[test]
    fn diff_detects_improvement() {
        let older = sample_image(0.5, 10);
        let newer = sample_image(0.8, 3);
        let diff = diff_images(&older, &newer, "before", "after");
        assert!(diff.health_delta > 0.0);
        assert!(diff.weak_point_delta < 0);
        assert_eq!(diff.trend, Trend::Improving);
    }

    #[test]
    fn diff_detects_degradation() {
        let older = sample_image(0.9, 2);
        let newer = sample_image(0.4, 15);
        let diff = diff_images(&older, &newer, "before", "after");
        assert!(diff.health_delta < 0.0);
        assert!(diff.weak_point_delta > 0);
        assert_eq!(diff.trend, Trend::Degrading);
    }

    #[test]
    fn diff_detects_stability() {
        let older = sample_image(0.7, 5);
        let newer = sample_image(0.7, 5);
        let diff = diff_images(&older, &newer, "v1", "v2");
        assert!(diff.health_delta.abs() < 0.01);
        assert_eq!(diff.trend, Trend::Stable);
    }

    #[test]
    fn snapshot_round_trip() {
        let dir = TempDir::new().expect("tempdir should create");
        let image = sample_image(0.75, 8);

        let entry = take_snapshot(&image, dir.path(), "test-label")
            .expect("snapshot should succeed");
        assert_eq!(entry.sequence, 1);
        assert_eq!(entry.label, "test-label");
        assert!(entry.image_path.exists());

        // Second snapshot
        let image2 = sample_image(0.85, 4);
        let entry2 = take_snapshot(&image2, dir.path(), "improved")
            .expect("second snapshot should succeed");
        assert_eq!(entry2.sequence, 2);

        // List snapshots
        let snapshots = list_snapshots(dir.path()).expect("list should succeed");
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].label, "test-label");
        assert_eq!(snapshots[1].label, "improved");
    }
}

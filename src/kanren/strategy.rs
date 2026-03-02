// SPDX-License-Identifier: PMPL-1.0-or-later

//! Search strategies for analysis prioritisation
//!
//! Inspired by Mozart/Oz search strategies, this module determines
//! the order in which files and analysis passes are executed.
//! Prioritises high-risk files to find critical issues faster.

use crate::types::*;

/// Search strategy for prioritising analysis order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchStrategy {
    /// Depth-first: follow each file fully before moving on
    DepthFirst,
    /// Breadth-first: scan all files shallowly then deepen
    BreadthFirst,
    /// Risk-weighted: prioritise files with highest risk indicators
    RiskWeighted,
    /// Language-family: group files by language family for batch analysis
    LanguageFamily,
    /// Boundary-first: analyse cross-language boundaries before internals
    BoundaryFirst,
}

/// Risk score for a single file, used for prioritisation
#[derive(Debug, Clone)]
pub struct FileRisk {
    pub file_path: String,
    pub language: Language,
    pub risk_score: f64,
    pub risk_factors: Vec<RiskFactor>,
}

/// Individual risk factor contributing to a file's score
#[derive(Debug, Clone)]
pub struct RiskFactor {
    pub name: String,
    pub weight: f64,
    pub value: f64,
}

impl SearchStrategy {
    /// Choose the best strategy based on project characteristics
    pub fn auto_select(report: &AssailReport) -> Self {
        let file_count = report.file_statistics.len();
        let has_multiple_families = Self::count_language_families(report) > 1;
        let has_high_risk = report
            .weak_points
            .iter()
            .any(|wp| matches!(wp.severity, Severity::Critical | Severity::High));

        if has_multiple_families && has_high_risk {
            // Polyglot project with high-risk findings: prioritise boundaries
            SearchStrategy::BoundaryFirst
        } else if has_high_risk {
            // Single-language with high risk: go to the hotspots first
            SearchStrategy::RiskWeighted
        } else if file_count > 100 {
            // Large project: breadth-first to get overview
            SearchStrategy::BreadthFirst
        } else if has_multiple_families {
            // Polyglot but low risk: group by family for efficient analysis
            SearchStrategy::LanguageFamily
        } else {
            // Small, single-language project: simple depth-first
            SearchStrategy::DepthFirst
        }
    }

    /// Count distinct language families in the report
    fn count_language_families(report: &AssailReport) -> usize {
        let mut families = std::collections::HashSet::new();
        for fs in &report.file_statistics {
            let lang = Language::detect(&fs.file_path);
            if lang != Language::Unknown {
                families.insert(lang.family());
            }
        }
        families.len()
    }
}

/// Compute risk scores for all files and return them in analysis order
pub fn prioritise_files(report: &AssailReport, strategy: SearchStrategy) -> Vec<FileRisk> {
    let mut scored: Vec<FileRisk> = report
        .file_statistics
        .iter()
        .map(|fs| score_file(fs))
        .collect();

    // Sorting policy is strategy-dependent, but all strategies operate on the same base score set.
    match strategy {
        SearchStrategy::RiskWeighted | SearchStrategy::BoundaryFirst => {
            // Highest risk first
            scored.sort_by(|a, b| {
                b.risk_score
                    .partial_cmp(&a.risk_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        SearchStrategy::LanguageFamily => {
            // Group by language family, then by risk within each family
            scored.sort_by(|a, b| {
                let fam_cmp = a.language.family().cmp(b.language.family());
                if fam_cmp == std::cmp::Ordering::Equal {
                    b.risk_score
                        .partial_cmp(&a.risk_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                } else {
                    fam_cmp
                }
            });
        }
        SearchStrategy::BreadthFirst => {
            // Smallest files first (for quick broad coverage)
            scored.sort_by_key(|f| {
                report
                    .file_statistics
                    .iter()
                    .find(|fs| fs.file_path == f.file_path)
                    .map(|fs| fs.lines)
                    .unwrap_or(0)
            });
        }
        SearchStrategy::DepthFirst => {
            // Largest files first (depth-first targets the meatiest files)
            scored.sort_by(|a, b| {
                let a_lines = report
                    .file_statistics
                    .iter()
                    .find(|fs| fs.file_path == a.file_path)
                    .map(|fs| fs.lines)
                    .unwrap_or(0);
                let b_lines = report
                    .file_statistics
                    .iter()
                    .find(|fs| fs.file_path == b.file_path)
                    .map(|fs| fs.lines)
                    .unwrap_or(0);
                b_lines.cmp(&a_lines)
            });
        }
    }

    scored
}

/// Compute a risk score for a single file based on its statistics
fn score_file(fs: &FileStatistics) -> FileRisk {
    let mut factors = Vec::new();
    let mut total = 0.0;

    // This is intentionally linear and explainable, not a black-box risk model.
    // Unsafe blocks are high-risk
    if fs.unsafe_blocks > 0 {
        let weight = 3.0;
        let value = fs.unsafe_blocks as f64;
        total += weight * value;
        factors.push(RiskFactor {
            name: "unsafe_blocks".to_string(),
            weight,
            value,
        });
    }

    // Panic sites indicate crash potential
    if fs.panic_sites > 0 {
        let weight = 2.5;
        let value = fs.panic_sites as f64;
        total += weight * value;
        factors.push(RiskFactor {
            name: "panic_sites".to_string(),
            weight,
            value,
        });
    }

    // Unwrap calls are moderate risk
    if fs.unwrap_calls > 0 {
        let weight = 1.0;
        let value = fs.unwrap_calls as f64;
        total += weight * value;
        factors.push(RiskFactor {
            name: "unwrap_calls".to_string(),
            weight,
            value,
        });
    }

    // Threading constructs increase concurrency risk
    if fs.threading_constructs > 0 {
        let weight = 2.0;
        let value = fs.threading_constructs as f64;
        total += weight * value;
        factors.push(RiskFactor {
            name: "threading".to_string(),
            weight,
            value,
        });
    }

    // IO operations increase attack surface
    if fs.io_operations > 0 {
        let weight = 1.5;
        let value = fs.io_operations as f64;
        total += weight * value;
        factors.push(RiskFactor {
            name: "io_operations".to_string(),
            weight,
            value,
        });
    }

    // Large files are harder to audit
    if fs.lines > 500 {
        let weight = 0.5;
        let value = (fs.lines as f64 / 500.0).min(5.0);
        total += weight * value;
        factors.push(RiskFactor {
            name: "file_size".to_string(),
            weight,
            value,
        });
    }

    // Allocation sites indicate memory management surface
    if fs.allocation_sites > 0 {
        let weight = 1.0;
        let value = fs.allocation_sites as f64;
        total += weight * value;
        factors.push(RiskFactor {
            name: "allocations".to_string(),
            weight,
            value,
        });
    }

    FileRisk {
        file_path: fs.file_path.clone(),
        language: Language::detect(&fs.file_path),
        risk_score: total,
        risk_factors: factors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file_stats(path: &str, unsafe_blocks: usize, panic_sites: usize) -> FileStatistics {
        FileStatistics {
            file_path: path.to_string(),
            lines: 100,
            unsafe_blocks,
            panic_sites,
            unwrap_calls: 0,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        }
    }

    #[test]
    fn test_risk_scoring() {
        let fs = make_file_stats("src/engine.rs", 3, 2);
        let risk = score_file(&fs);
        // 3 unsafe * 3.0 + 2 panic * 2.5 = 14.0
        assert!((risk.risk_score - 14.0).abs() < 0.01);
    }

    #[test]
    fn test_zero_risk() {
        let fs = FileStatistics {
            file_path: "src/types.res".to_string(),
            lines: 50,
            unsafe_blocks: 0,
            panic_sites: 0,
            unwrap_calls: 0,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        };
        let risk = score_file(&fs);
        assert!((risk.risk_score - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_strategy_auto_select() {
        let report = AssailReport {
            program_path: ".".into(),
            language: Language::Rust,
            frameworks: vec![],
            weak_points: vec![],
            statistics: ProgramStatistics {
                total_lines: 100,
                unsafe_blocks: 0,
                panic_sites: 0,
                unwrap_calls: 0,
                allocation_sites: 0,
                io_operations: 0,
                threading_constructs: 0,
            },
            file_statistics: vec![make_file_stats("src/main.rs", 0, 0)],
            recommended_attacks: vec![],
            dependency_graph: Default::default(),
            taint_matrix: Default::default(),
            migration_metrics: None,
        };

        // Small, single-language, no high risk: should be DepthFirst
        assert_eq!(
            SearchStrategy::auto_select(&report),
            SearchStrategy::DepthFirst
        );
    }

    #[test]
    fn test_risk_weighted_ordering() {
        let report = AssailReport {
            program_path: ".".into(),
            language: Language::Rust,
            frameworks: vec![],
            weak_points: vec![],
            statistics: ProgramStatistics {
                total_lines: 300,
                unsafe_blocks: 3,
                panic_sites: 2,
                unwrap_calls: 5,
                allocation_sites: 0,
                io_operations: 0,
                threading_constructs: 0,
            },
            file_statistics: vec![
                make_file_stats("src/safe.rs", 0, 0),
                make_file_stats("src/risky.rs", 3, 2),
                make_file_stats("src/moderate.rs", 1, 0),
            ],
            recommended_attacks: vec![],
            dependency_graph: Default::default(),
            taint_matrix: Default::default(),
            migration_metrics: None,
        };

        let ordered = prioritise_files(&report, SearchStrategy::RiskWeighted);
        assert_eq!(ordered[0].file_path, "src/risky.rs");
        assert_eq!(ordered[1].file_path, "src/moderate.rs");
        assert_eq!(ordered[2].file_path, "src/safe.rs");
    }
}

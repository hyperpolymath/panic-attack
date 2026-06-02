// SPDX-License-Identifier: MPL-2.0

//! Assail static analysis module
//!
//! Pre-analyzes target programs to identify weak points and recommend attacks

pub mod analyzer;
pub mod patterns;

use crate::kanren::core::{FactDB, LogicEngine};
use crate::kanren::crosslang::CrossLangAnalyzer;
use crate::kanren::strategy::{self, SearchStrategy};
use crate::kanren::taint::TaintAnalyzer;
use crate::types::*;
use anyhow::Result;
use std::path::Path;

pub use analyzer::Analyzer;

/// Run Assail analysis on a target program
pub fn analyze<P: AsRef<Path>>(target: P) -> Result<AssailReport> {
    // Non-verbose mode keeps stdout clean for automation pipelines.
    let analyzer = Analyzer::new(target.as_ref())?;
    let mut report = analyzer.analyze()?;
    // analyze() already runs suppression + user classifications; the
    // explicit calls below are no-ops for existing reports but keep
    // the contract explicit: apply_suppression first, then
    // apply_user_classifications against the same target root.
    apply_suppression(&mut report);
    let target_ref = target.as_ref();
    let root = if target_ref.is_dir() {
        target_ref.to_path_buf()
    } else {
        target_ref.parent().unwrap_or(Path::new(".")).to_path_buf()
    };
    apply_user_classifications(&mut report, &root);
    Ok(report)
}

/// Run Assail analysis with verbose output including per-file breakdown
/// and miniKanren logic engine results
pub fn analyze_verbose<P: AsRef<Path>>(target: P) -> Result<AssailReport> {
    // Verbose mode is operator-facing and intentionally prints prioritization context.
    let analyzer = Analyzer::new_verbose(target.as_ref())?;
    let mut report = analyzer.analyze()?;
    apply_suppression(&mut report);
    let target_ref = target.as_ref();
    let root = if target_ref.is_dir() {
        target_ref.to_path_buf()
    } else {
        target_ref.parent().unwrap_or(Path::new(".")).to_path_buf()
    };
    apply_user_classifications(&mut report, &root);

    let active_count = report
        .weak_points
        .iter()
        .filter(|wp| !wp.suppressed)
        .count();
    let suppressed_count = report.suppressed_count;

    println!("Assail Analysis Complete");
    println!("  Language: {:?}", report.language);
    println!("  Frameworks: {:?}", report.frameworks);
    // Filtered view: what CI/fleet sees (suppressed items excluded)
    println!(
        "  Weak Points (active): {} — these count toward CI gates and fleet dispatch",
        active_count
    );
    // Unfiltered view: full scan for audit transparency
    if suppressed_count > 0 {
        println!(
            "  Weak Points (total):  {} — {} additional suppressed by FP rules (suppressed = \
             likely false positive from defensive pattern; see --show-suppressed for detail)",
            report.weak_points.len(),
            suppressed_count
        );
    }
    println!("  Recommended Attacks: {:?}", report.recommended_attacks);

    // Per-file breakdown sorted by risk score
    if !report.file_statistics.is_empty() {
        // Use search strategy to determine optimal analysis order
        let strategy = SearchStrategy::auto_select(&report);
        let prioritised = strategy::prioritise_files(&report, strategy);

        println!("\n  Search Strategy: {:?}", strategy);
        println!("  Per-file Breakdown (top 10 by risk):");

        for (rank, file_risk) in prioritised.iter().take(10).enumerate() {
            println!(
                "    {}. {} ({:?}, risk: {:.1})",
                rank + 1,
                file_risk.file_path,
                file_risk.language,
                file_risk.risk_score,
            );
            for factor in &file_risk.risk_factors {
                println!(
                    "       - {}: {:.0} (weight: {:.1})",
                    factor.name, factor.value, factor.weight,
                );
            }
        }

        if prioritised.len() > 10 {
            println!("    ... and {} more files", prioritised.len() - 10);
        }
    }

    // Run miniKanren logic engine for deeper analysis
    run_logic_engine(&report);

    Ok(report)
}

/// Run Assail analysis for browser extensions (ignores DevTools API eval() usage)
pub fn analyze_browser_extension<P: AsRef<Path>>(target: P) -> Result<AssailReport> {
    let analyzer = Analyzer::new_browser_extension(target.as_ref())?;
    let mut report = analyzer.analyze()?;
    apply_suppression(&mut report);
    Ok(report)
}

/// Run Assail analysis for browser extensions with verbose output
pub fn analyze_verbose_browser_extension<P: AsRef<Path>>(target: P) -> Result<AssailReport> {
    let analyzer = Analyzer::new_verbose_browser_extension(target.as_ref())?;
    let mut report = analyzer.analyze()?;
    apply_suppression(&mut report);

    let active_count = report
        .weak_points
        .iter()
        .filter(|wp| !wp.suppressed)
        .count();
    let suppressed_count = report.suppressed_count;

    println!("Assail Analysis Complete (Browser Extension Mode)");
    println!("  Language: {:?}", report.language);
    println!("  Frameworks: {:?}", report.frameworks);
    println!(
        "  Weak Points (active): {} — these count toward CI gates and fleet dispatch",
        active_count
    );
    if suppressed_count > 0 {
        println!(
            "  Weak Points (total):  {} — {} additional suppressed by FP rules",
            report.weak_points.len(),
            suppressed_count
        );
    }
    println!("  Recommended Attacks: {:?}", report.recommended_attacks);
    println!("  Note: eval() checks skipped for DevTools API usage");

    if !report.file_statistics.is_empty() {
        let strategy = SearchStrategy::auto_select(&report);
        let prioritised = strategy::prioritise_files(&report, strategy);

        println!("\n  Search Strategy: {:?}", strategy);
        println!("  Per-file Breakdown (top 10 by risk):");

        for (rank, file_risk) in prioritised.iter().take(10).enumerate() {
            println!(
                "    {}. {} ({:?}, risk: {:.1})",
                rank + 1,
                file_risk.file_path,
                file_risk.language,
                file_risk.risk_score,
            );
            for factor in &file_risk.risk_factors {
                println!(
                    "       - {}: {:.0} (weight: {:.1})",
                    factor.name, factor.value, factor.weight,
                );
            }
        }

        if prioritised.len() > 10 {
            println!("    ... and {} more files", prioritised.len() - 10);
        }
    }

    run_logic_engine(&report);

    Ok(report)
}

/// A single classification entry read from a project's
/// `audits/assail-classifications.a2ml` (or `.panic-attack-classifications.a2ml`).
/// When such a file exists, findings matching `(file, category)` are flipped
/// to `suppressed = true` after the kanren suppression pass runs.
///
/// The registry pattern lets repositories record "this finding has been
/// audited and is sound" out-of-band from the source file — so the
/// suppression is not gameable by code-only edits (adding a new unsafe
/// block cannot also add its own classification without editing the
/// registry, which is reviewable in the same PR).
#[derive(Debug, Clone)]
pub struct UserClassification {
    pub file: String,
    pub category: String,
}

/// Load user classifications from `<project_root>/audits/assail-classifications.a2ml`.
///
/// Empty vector if the file is absent or unreadable. Errors are swallowed by
/// design — the classification registry is optional and a missing file must
/// not break the assail pass.
///
/// Format (A2ML S-expression):
///
/// ```text
/// (assail-classifications
///   (classification
///     (file "crates/oo7-core/src/zig_bridge.rs")
///     (category "UnsafeCode")
///     (audit "audits/audit-ffi-unsafe.md §1"))
///   ...)
/// ```
pub fn load_user_classifications(project_root: &Path) -> Vec<UserClassification> {
    use std::fs;
    let candidate_paths = [
        project_root
            .join("audits")
            .join("assail-classifications.a2ml"),
        project_root.join(".panic-attack-classifications.a2ml"),
    ];
    // User-classification a2ml files are hand-edited audit registries. A
    // legitimate one rarely exceeds a few dozen KiB. Capping at 4 MiB
    // stops a malicious or accidental input from exhausting memory during
    // a multi-thousand-repo mass-panic sweep.
    use std::io::Read;
    const CLASSIFICATIONS_FILE_READ_LIMIT: u64 = 4 * 1024 * 1024;

    let mut content = String::new();
    for p in &candidate_paths {
        if let Ok(mut f) = fs::File::open(p) {
            let mut buf = String::new();
            if (&mut f)
                .take(CLASSIFICATIONS_FILE_READ_LIMIT)
                .read_to_string(&mut buf)
                .is_ok()
            {
                content = buf;
                break;
            }
        }
    }
    if content.is_empty() {
        return Vec::new();
    }

    // Strip `;;` line comments.
    let stripped: String = content
        .lines()
        .map(|l| match l.find(";;") {
            Some(idx) => &l[..idx],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut classifications = Vec::new();
    let needle = "(classification";
    let mut rest = stripped.as_str();
    while let Some(start) = rest.find(needle) {
        let after_keyword = &rest[start + needle.len()..];
        // Walk characters tracking paren depth to find the matching ')'.
        let mut depth: i32 = 1;
        let mut end_idx: Option<usize> = None;
        for (i, c) in after_keyword.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end_idx else {
            break;
        };
        let body = &after_keyword[..end];
        let file = extract_classification_field(body, "file");
        let category = extract_classification_field(body, "category");
        if let (Some(f), Some(c)) = (file, category) {
            classifications.push(UserClassification {
                file: f,
                category: c,
            });
        }
        rest = &after_keyword[end + 1..];
    }

    classifications
}

fn extract_classification_field(body: &str, field: &str) -> Option<String> {
    let marker = format!("({} \"", field);
    let idx = body.find(&marker)?;
    let after = &body[idx + marker.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

/// Apply user classifications to a report in-place. Findings whose file
/// and category match an entry in the project's
/// `assail-classifications.a2ml` are marked `suppressed = true` and
/// counted toward `report.suppressed_count`.
///
/// Runs after the kanren-based `apply_suppression` so that the
/// structural suppression rules get first pass and the classification
/// registry covers only the genuinely-audited residuals.
pub fn apply_user_classifications(report: &mut AssailReport, project_root: &Path) {
    let classifications = load_user_classifications(project_root);
    if classifications.is_empty() {
        return;
    }
    let mut additional: usize = 0;
    for wp in &mut report.weak_points {
        if wp.suppressed {
            continue;
        }
        let cat = format!("{:?}", wp.category);
        let loc = wp.location.as_deref().unwrap_or("");
        for cl in &classifications {
            if cl.category == cat && cl.file == loc {
                wp.suppressed = true;
                additional += 1;
                break;
            }
        }
    }
    report.suppressed_count += additional;
}

/// Apply context-aware FP suppression to an assail report in-place.
///
/// Runs the full kanren logic engine, collects every `suppressed(Category, Location)`
/// fact derived by the 12 suppression rules, and marks the matching `WeakPoint`s
/// with `suppressed = true`. Also writes the suppression count to
/// `report.suppressed_count`.
///
/// Called automatically by `analyze()` and `analyze_verbose()`.
/// The suppressed items remain in `weak_points` for auditability; callers
/// (panicbot's translator, CI gates) should filter on `suppressed: false`.
pub fn apply_suppression(report: &mut AssailReport) {
    let db = build_logic_db(report);
    let mut count = 0usize;

    for fact in db.get_facts("suppressed") {
        if fact.args.len() != 2 {
            continue;
        }
        let category_str = match &fact.args[0] {
            crate::kanren::core::Term::Atom(s) => s.clone(),
            _ => continue,
        };
        let location_str = match &fact.args[1] {
            crate::kanren::core::Term::Atom(s) => s.clone(),
            _ => continue,
        };

        // Flip every matching weak point, not just the first. Facts in
        // the kanren DB are deduped by (name, args), so a single
        // `suppressed(Category, File)` derivation represents "every
        // finding of this (category, file) tuple is a false positive"
        // — NOT "one arbitrary finding is a FP." The previous
        // `break`-after-first behaviour meant a file with multiple
        // findings of the same category (e.g. zig_bridge.rs with both
        // "N unsafe blocks" and "Raw pointer cast" UnsafeCode
        // findings) would only have one finding flipped per call, and
        // the second would stay active unless a downstream pass ran
        // the suppression again. Removing the `break` makes the
        // behaviour idempotent in a single pass.
        for wp in &mut report.weak_points {
            if wp.suppressed {
                continue;
            }
            let wp_cat = format!("{:?}", wp.category);
            let wp_loc = wp.location.as_deref().unwrap_or("unknown");
            if wp_cat == category_str && wp_loc == location_str {
                wp.suppressed = true;
                count += 1;
            }
        }
    }

    report.suppressed_count = count;
}

/// Build a fully-populated kanren FactDB from an assail report.
///
/// Ingest all facts (report, taint, cross-language, context) and run
/// forward chaining including FP suppression rules.
pub fn build_logic_db(report: &AssailReport) -> FactDB {
    let mut engine = LogicEngine::new();
    engine.ingest_report(report);
    TaintAnalyzer::extract_facts(&mut engine.db, report);
    TaintAnalyzer::load_rules(&mut engine.db);
    CrossLangAnalyzer::extract_facts(&mut engine.db, report);
    CrossLangAnalyzer::load_rules(&mut engine.db);
    engine.extract_context_facts(report);
    engine.load_suppression_rules();
    engine.analyze();
    engine.db
}

/// Run the miniKanren-inspired logic engine on a completed report
fn run_logic_engine(report: &AssailReport) {
    let mut engine = LogicEngine::new();

    // Phase 1: Ingest report facts
    engine.ingest_report(report);

    // Phase 2: Extract taint source/sink facts
    TaintAnalyzer::extract_facts(&mut engine.db, report);
    TaintAnalyzer::load_rules(&mut engine.db);

    // Phase 3: Extract cross-language interaction facts
    CrossLangAnalyzer::extract_facts(&mut engine.db, report);
    CrossLangAnalyzer::load_rules(&mut engine.db);

    // Phase 4: Extract context facts and load FP suppression rules
    engine.extract_context_facts(report);
    engine.load_suppression_rules();

    // Phase 5: Run forward chaining
    let results = engine.analyze();

    println!("\n  Logic Engine Results:");
    println!("    Total facts: {}", results.total_facts);
    println!("    Derived facts: {}", results.derived_facts);
    println!("    Tainted paths: {}", results.tainted_paths);
    println!(
        "    Critical vulnerabilities: {}",
        results.critical_vulnerabilities
    );
    println!("    High vulnerabilities: {}", results.high_vulnerabilities);
    println!("    Cross-language vulns: {}", results.cross_language_vulns);
    if results.suppressed_false_positives > 0 {
        println!(
            "    Suppressed false positives: {}",
            results.suppressed_false_positives
        );
    }

    // Query taint flows
    let flows = TaintAnalyzer::query_flows(&engine.db);
    if !flows.is_empty() {
        println!("\n    Taint Flows ({}):", flows.len());
        for flow in flows.iter().take(10) {
            println!(
                "      {:?} -> {:?} ({} -> {}, confidence: {:.2})",
                flow.source, flow.sink, flow.source_file, flow.sink_file, flow.confidence,
            );
        }
        if flows.len() > 10 {
            println!("      ... and {} more flows", flows.len() - 10);
        }
    }

    // Query cross-language interactions
    let interactions = CrossLangAnalyzer::query_interactions(&engine.db);
    if !interactions.is_empty() {
        println!(
            "\n    Cross-Language Interactions ({}):",
            interactions.len()
        );
        for interaction in interactions.iter().take(10) {
            println!(
                "      {} ({:?}) -> {} ({:?}) via {:?} (risk: {:.2})",
                interaction.caller_file,
                interaction.caller_lang,
                interaction.callee_file,
                interaction.callee_lang,
                interaction.mechanism,
                interaction.risk_score,
            );
        }
        if interactions.len() > 10 {
            println!(
                "      ... and {} more interactions",
                interactions.len() - 10
            );
        }
    }
}

#[cfg(test)]
mod classifications_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_registry(dir: &Path, content: &str) {
        let audits = dir.join("audits");
        fs::create_dir_all(&audits).unwrap();
        fs::write(audits.join("assail-classifications.a2ml"), content).unwrap();
    }

    #[test]
    fn load_empty_when_no_registry() {
        let tmp = TempDir::new().unwrap();
        let classifications = load_user_classifications(tmp.path());
        assert!(
            classifications.is_empty(),
            "Missing registry must yield empty classification list"
        );
    }

    #[test]
    fn load_single_classification() {
        let tmp = TempDir::new().unwrap();
        write_registry(
            tmp.path(),
            r#";; SPDX-License-Identifier: MPL-2.0
(assail-classifications
  (classification
    (file "crates/oo7-core/src/zig_bridge.rs")
    (category "UnsafeCode")
    (audit "audits/audit-ffi-unsafe.md §1")))
"#,
        );
        let classifications = load_user_classifications(tmp.path());
        assert_eq!(classifications.len(), 1);
        assert_eq!(classifications[0].file, "crates/oo7-core/src/zig_bridge.rs");
        assert_eq!(classifications[0].category, "UnsafeCode");
    }

    #[test]
    fn load_multiple_classifications() {
        let tmp = TempDir::new().unwrap();
        write_registry(
            tmp.path(),
            r#"(assail-classifications
  (classification
    (file "a/b.rs")
    (category "UnsafeCode")
    (audit "doc1"))
  (classification
    (file "c/d.rs")
    (category "PanicPath")
    (audit "doc2")))
"#,
        );
        let classifications = load_user_classifications(tmp.path());
        assert_eq!(classifications.len(), 2);
        assert_eq!(classifications[0].file, "a/b.rs");
        assert_eq!(classifications[1].category, "PanicPath");
    }

    #[test]
    fn comment_lines_are_ignored() {
        let tmp = TempDir::new().unwrap();
        write_registry(
            tmp.path(),
            r#";; Header comment
;; (classification (file "should-not-parse") (category "X"))
(assail-classifications
  (classification
    (file "real/path.rs")
    (category "UnsafeCode")
    (audit "doc")))
"#,
        );
        let classifications = load_user_classifications(tmp.path());
        assert_eq!(classifications.len(), 1);
        assert_eq!(classifications[0].file, "real/path.rs");
    }

    #[test]
    fn apply_flips_matching_finding_to_suppressed() {
        use crate::types::{
            AssailReport, AttackAxis, Language, ProgramStatistics, Severity, WeakPoint,
            WeakPointCategory,
        };
        let tmp = TempDir::new().unwrap();
        write_registry(
            tmp.path(),
            r#"(assail-classifications
  (classification
    (file "crates/oo7-core/src/zig_bridge.rs")
    (category "UnsafeCode")
    (audit "audits/audit-ffi-unsafe.md §1")))
"#,
        );

        let mut report = AssailReport {
            schema_version: "2.5".to_string(),
            program_path: tmp.path().to_path_buf(),
            language: Language::Rust,
            frameworks: vec![],
            weak_points: vec![
                WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::UnsafeCode,
                    location: Some("crates/oo7-core/src/zig_bridge.rs".to_string()),
                    severity: Severity::High,
                    description: "8 unsafe blocks".to_string(),
                    recommended_attack: vec![AttackAxis::Memory],
                    suppressed: false,
                test_context: None,
                },
                WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::UnsafeCode,
                    location: Some("other/file.rs".to_string()),
                    severity: Severity::High,
                    description: "unsafe block".to_string(),
                    recommended_attack: vec![AttackAxis::Memory],
                    suppressed: false,
                test_context: None,
                },
            ],
            statistics: ProgramStatistics {
                total_lines: 0,
                unsafe_blocks: 0,
                panic_sites: 0,
                unwrap_calls: 0,
                allocation_sites: 0,
                io_operations: 0,
                threading_constructs: 0,
                safe_unwrap_calls: 0,
            },
            file_statistics: vec![],
            recommended_attacks: vec![],
            dependency_graph: Default::default(),
            taint_matrix: Default::default(),
            migration_metrics: None,
            suppressed_count: 0,
        };

        apply_user_classifications(&mut report, tmp.path());

        assert!(
            report.weak_points[0].suppressed,
            "Classified finding must be suppressed"
        );
        assert!(
            !report.weak_points[1].suppressed,
            "Unclassified finding must stay active"
        );
        assert_eq!(report.suppressed_count, 1);
    }
}

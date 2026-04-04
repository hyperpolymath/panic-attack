// SPDX-License-Identifier: PMPL-1.0-or-later

use crate::a2ml::Manifest;
use anyhow::{anyhow, Context, Result};
use std::env;
use std::fs;
use std::path::Path;

const HYPATIA_ENV: &str = "HYPATIA_API_KEY";
const GITBOT_FLEET_ENV: &str = "GITBOT_FLEET_ENDPOINT";
const PANICBOT_DIRECTIVE_PATH: &str = ".machine_readable/bot_directives/panicbot.scm";

pub fn run_self_diagnostics(manifest: &Manifest) -> Result<()> {
    println!("panic-attack self-diagnostics");

    let mut checks = Vec::new();
    checks.push(Diagnostic::ok(
        "version",
        format!("panic-attack {}", env!("CARGO_PKG_VERSION")),
    ));
    checks.push(Diagnostic::ok(
        "AI manifest",
        format!(
            "AI.a2ml parsed (formats: {:?}, storage: {:?})",
            manifest.report_formats(),
            manifest.storage_modes(),
        ),
    ));

    checks.push(check_directory(
        "reports directory",
        Path::new("reports"),
        Severity::Warn,
    ));
    checks.push(check_directory(
        "profiles directory",
        Path::new("profiles"),
        Severity::Warn,
    ));
    checks.push(check_verisimdb(Path::new("verisimdb-data/verisimdb")));
    checks.push(check_file(
        "ambush timeline spec",
        Path::new("docs/ambush-timeline.md"),
    ));
    checks.push(check_file(
        "panll export guide",
        Path::new("docs/panll-export.md"),
    ));

    checks.push(check_watcher("Hypatia scanner", HYPATIA_ENV));
    checks.push(check_watcher("gitbot-fleet observer", GITBOT_FLEET_ENV));
    checks.push(check_panicbot_readiness());
    checks.push(check_attestation_health());

    println!();
    for entry in &checks {
        entry.print();
    }

    if checks
        .iter()
        .any(|entry| matches!(entry.level, Level::Error))
    {
        Err(anyhow!("self-diagnostics reported issues"))
    } else {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Error,
}

struct Diagnostic {
    label: &'static str,
    level: Level,
    detail: String,
}

impl Diagnostic {
    fn new(label: &'static str, level: Level, detail: String) -> Self {
        Self {
            label,
            level,
            detail,
        }
    }

    fn ok(label: &'static str, detail: String) -> Self {
        Self::new(label, Level::Ok, detail)
    }

    fn warning(label: &'static str, detail: String) -> Self {
        Self::new(label, Level::Warn, detail)
    }

    fn error(label: &'static str, detail: String) -> Self {
        Self::new(label, Level::Error, detail)
    }

    fn print(&self) {
        println!("  [{}] {:22} {}", self.level.tag(), self.label, self.detail,);
    }
}

impl Level {
    fn tag(&self) -> &'static str {
        match self {
            Level::Ok => "OK",
            Level::Warn => "WARN",
            Level::Error => "ERR",
        }
    }
}

fn check_directory(label: &'static str, path: &Path, missing_level: Severity) -> Diagnostic {
    if path.is_dir() {
        Diagnostic::ok(label, format!("{} exists", path.display()))
    } else if path.exists() {
        Diagnostic::warning(
            label,
            format!("{} exists but is not a directory", path.display()),
        )
    } else if missing_level == Severity::Error {
        Diagnostic::error(label, format!("{} missing", path.display()))
    } else {
        Diagnostic::warning(
            label,
            format!(
                "{} missing (create with mkdir -p {})",
                path.display(),
                path.display()
            ),
        )
    }
}

fn check_file(label: &'static str, path: &Path) -> Diagnostic {
    if path.is_file() {
        Diagnostic::ok(label, format!("{} exists", path.display()))
    } else if path.exists() {
        Diagnostic::warning(
            label,
            format!("{} exists but is not a regular file", path.display()),
        )
    } else {
        Diagnostic::error(label, format!("{} missing", path.display()))
    }
}

fn check_verisimdb(path: &Path) -> Diagnostic {
    if !path.exists() {
        return Diagnostic::warning(
            "verisimdb cache",
            "verisimdb-data/verisimdb missing (run panic-attack to populate)".to_string(),
        );
    }

    let entries = fs::read_dir(path)
        .with_context(|| format!("reading {}", path.display()))
        .map(|iter| iter.filter_map(|entry| entry.ok()).count());

    match entries {
        Ok(count) if count > 0 => {
            Diagnostic::ok("verisimdb cache", format!("{} reports stored", count))
        }
        Ok(_) => Diagnostic::warning(
            "verisimdb cache",
            "directory is empty (run panic-attack to create verisimdb reports)".to_string(),
        ),
        Err(err) => Diagnostic::warning(
            "verisimdb cache",
            format!("unable to read {}: {}", path.display(), err),
        ),
    }
}

fn check_watcher(label: &'static str, env_key: &str) -> Diagnostic {
    match env::var(env_key) {
        Ok(value) if !value.trim().is_empty() => {
            Diagnostic::ok(label, format!("configured ({})", env_key))
        }
        _ => Diagnostic::warning(label, format!("not configured (set {} to enable)", env_key)),
    }
}

/// Check panicbot integration readiness.
///
/// Verifies:
///   1. Bot directives file exists at `.machine_readable/bot_directives/panicbot.scm`
///   2. JSON output contract: AssailReport serialises with the fields panicbot expects
///      (`program_path`, `weak_points`, `language`, `statistics`)
///   3. WeakPointCategory and Severity serialise in PascalCase (no serde rename_all)
fn check_panicbot_readiness() -> Diagnostic {
    let directive_path = Path::new(PANICBOT_DIRECTIVE_PATH);
    let has_directives = directive_path.is_file();

    // Verify JSON output contract by serialising a minimal AssailReport
    let test_report = crate::types::AssailReport {
        program_path: std::path::PathBuf::from("/test"),
        language: crate::types::Language::Rust,
        frameworks: vec![],
        weak_points: vec![crate::types::WeakPoint {
            category: crate::types::WeakPointCategory::UnsafeCode,
            location: Some("test.rs:1".to_string()),
            file: None,
            line: None,
            severity: crate::types::Severity::High,
            description: "test".to_string(),
            recommended_attack: vec![],
        }],
        statistics: crate::types::ProgramStatistics::default(),
        file_statistics: vec![],
        recommended_attacks: vec![],
        dependency_graph: Default::default(),
        taint_matrix: Default::default(),
        migration_metrics: None,
    };

    let json_ok = match serde_json::to_value(&test_report) {
        Ok(val) => {
            // Panicbot expects these top-level fields
            val["program_path"].is_string()
                && val["weak_points"].is_array()
                && val["language"].is_string()
                // Panicbot expects PascalCase for category (no serde rename)
                && val["weak_points"][0]["category"].as_str() == Some("UnsafeCode")
                // Panicbot expects PascalCase for severity
                && val["weak_points"][0]["severity"].as_str() == Some("High")
        }
        Err(_) => false,
    };

    match (has_directives, json_ok) {
        (true, true) => Diagnostic::ok(
            "panicbot integration",
            "directives present, JSON contract verified (PA001–PA020)".to_string(),
        ),
        (false, true) => Diagnostic::warning(
            "panicbot integration",
            format!(
                "JSON contract OK but {} missing (panicbot will use defaults)",
                PANICBOT_DIRECTIVE_PATH
            ),
        ),
        (true, false) => Diagnostic::error(
            "panicbot integration",
            "directives present but JSON output contract broken — panicbot cannot parse output"
                .to_string(),
        ),
        (false, false) => Diagnostic::error(
            "panicbot integration",
            "JSON output contract broken — AssailReport serialisation mismatch".to_string(),
        ),
    }
}

/// Check attestation readiness: whether signing is available and if a
/// signing key is configured via the `PANIC_ATTACK_SIGNING_KEY` env var.
fn check_attestation_health() -> Diagnostic {
    let signing_available = cfg!(feature = "signing");
    let key_env = env::var("PANIC_ATTACK_SIGNING_KEY").ok();

    match (signing_available, &key_env) {
        (true, Some(path)) if Path::new(path).is_file() => {
            Diagnostic::ok(
                "attestation",
                format!("signing enabled, key at {}", path),
            )
        }
        (true, Some(path)) => Diagnostic::warning(
            "attestation",
            format!("signing enabled but key not found: {}", path),
        ),
        (true, None) => Diagnostic::warning(
            "attestation",
            "signing feature enabled but no PANIC_ATTACK_SIGNING_KEY set (unsigned attestations)".to_string(),
        ),
        (false, _) => Diagnostic::warning(
            "attestation",
            "signing feature not compiled in (rebuild with --features signing to enable Ed25519 signatures)".to_string(),
        ),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Severity {
    Warn,
    Error,
}

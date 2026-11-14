// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

use crate::a2ml::Manifest;
use anyhow::{anyhow, Context, Result};
use std::env;
use std::fs;
use std::path::Path;

const HYPATIA_ENV: &str = "HYPATIA_API_KEY";
const GITBOT_FLEET_ENV: &str = "GITBOT_FLEET_ENDPOINT";

/// Print readiness checks using `manifest`, paths relative to the current
/// working directory and the configured integration environment variables.
///
/// # Errors
/// Returns an error after printing all results if any check has error severity.
/// Warnings alone do not cause failure.
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
            "{} parsed (formats: {:?}, storage: {:?})",
            manifest
                .path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "no manifest file; built-in defaults".to_string()),
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
        Path::new("docs/ambush-timeline.adoc"),
    ));
    checks.push(check_file(
        "panll export guide",
        Path::new("docs/panll-export.adoc"),
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
///   1. Whether the repo deed (`<repo>_chora.deed` in the current directory)
///      declares `(bot-directives (bot :name panicbot …))` (standards
///      `agentic-neurosym-playbook-to-repo-deed.adoc` §6). No declaration is
///      valid: panicbot then runs the full suite (owner ruling 2026-11-13).
///   2. JSON output contract: AssailReport serialises with the fields panicbot expects
///      (`program_path`, `weak_points`, `language`)
///   3. WeakPointCategory and Severity serialise in PascalCase (no serde rename_all)
///
/// Failed JSON checks, including serialisation errors, yield an error diagnostic;
/// a repo deed that does not parse, a directory with no repo deed, or one
/// that cannot be listed yields a warning.
fn check_panicbot_readiness() -> Diagnostic {
    let directives = panicbot_directives(Path::new("."));

    // Verify JSON output contract by serialising a minimal AssailReport
    let test_report = crate::types::AssailReport {
        coverage: Default::default(),
        schema_version: "2.5".to_string(),
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
            suppressed: false,
            test_context: None,
        }],
        statistics: crate::types::ProgramStatistics::default(),
        file_statistics: vec![],
        recommended_attacks: vec![],
        dependency_graph: Default::default(),
        taint_matrix: Default::default(),
        migration_metrics: None,
        suppressed_count: 0,
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

    if !json_ok {
        return Diagnostic::error(
            "panicbot integration",
            "JSON output contract broken — AssailReport serialisation mismatch".to_string(),
        );
    }
    match directives {
        Ok(PanicbotDirectives::Declared(deed)) => Diagnostic::ok(
            "panicbot integration",
            format!(
                "directives declared in {} (bot-directives), JSON contract verified",
                deed.display()
            ),
        ),
        Ok(PanicbotDirectives::NotDeclared) => Diagnostic::ok(
            "panicbot integration",
            "no panicbot directives declared (panicbot runs the full suite), JSON contract verified"
                .to_string(),
        ),
        Ok(PanicbotDirectives::NoRepoDeed) => Diagnostic::warning(
            "panicbot integration",
            "JSON contract OK but no <repo>_chora.deed found here, so whether panicbot \
             directives are declared is unknown"
                .to_string(),
        ),
        Err(err) => Diagnostic::warning(
            "panicbot integration",
            format!("JSON contract OK but the repo deed could not be read: {err}"),
        ),
    }
}

/// What the repo deeds in a directory say about panicbot directives.
#[derive(Debug, PartialEq, Eq)]
enum PanicbotDirectives {
    /// No `*_chora.deed` is there, so nothing can be said either way.
    NoRepoDeed,
    /// The repo deed parses and declares no panicbot directives.
    NotDeclared,
    /// This repo deed declares `(bot-directives (bot :name panicbot …))`.
    Declared(std::path::PathBuf),
}

/// What the repo deeds in `root` say about panicbot directives. `Err` when
/// the directory or one of its entries cannot be read, or when a
/// `*_chora.deed` there does not parse: none of those shows that no
/// directives are declared.
fn panicbot_directives(root: &Path) -> Result<PanicbotDirectives> {
    use panic_attack::deed::{Item, Value};
    let listing = || format!("listing {}", root.display());
    let paths = fs::read_dir(root)
        .with_context(listing)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(listing)?;
    let mut deeds: Vec<_> = paths
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("_chora.deed"))
        })
        .collect();
    deeds.sort();
    let any_deed = !deeds.is_empty();
    let names_panicbot = |items: &[Item]| {
        items.iter().any(|item| {
            matches!(item, Item::Field { key, value: Value::Symbol(name), .. }
                if key == "name" && name == "panicbot")
        })
    };
    for path in deeds {
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let deed = panic_attack::deed::parse(&text, Some(&path))
            .map_err(|e| anyhow!("{}: {}", path.display(), e))?;
        let declared = deed.items.iter().any(|item| match item {
            Item::Clause { name, items, .. } if name == "bot-directives" => {
                items.iter().any(|bot| {
                    matches!(bot, Item::Clause { name, items, .. }
                        if name == "bot" && names_panicbot(items))
                })
            }
            _ => false,
        });
        if declared {
            return Ok(PanicbotDirectives::Declared(path));
        }
    }
    Ok(if any_deed {
        PanicbotDirectives::NotDeclared
    } else {
        PanicbotDirectives::NoRepoDeed
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn repo_deed(body: &str) -> String {
        format!(
            ";; SPDX-License-Identifier: MPL-2.0\n(repo-deed\n  :schema-version \"1.0.0\"{body})\n"
        )
    }

    #[test]
    fn panicbot_directives_tells_a_missing_repo_deed_from_no_directives() {
        let dir = TempDir::new().expect("tempdir");
        assert_eq!(
            panicbot_directives(dir.path()).expect("empty directory lists"),
            PanicbotDirectives::NoRepoDeed
        );
        let deed = dir.path().join("example_chora.deed");
        fs::write(&deed, repo_deed("")).expect("write");
        assert_eq!(
            panicbot_directives(dir.path()).expect("deed parses"),
            PanicbotDirectives::NotDeclared
        );
        fs::write(
            &deed,
            repo_deed("\n  (bot-directives (bot :name panicbot))"),
        )
        .expect("write");
        assert_eq!(
            panicbot_directives(dir.path()).expect("deed parses"),
            PanicbotDirectives::Declared(deed)
        );
    }

    #[test]
    fn panicbot_directives_propagates_a_listing_error() {
        let dir = TempDir::new().expect("tempdir");
        let missing = dir.path().join("no-such-directory");
        let err = panicbot_directives(&missing).expect_err("listing must fail");
        assert!(err.to_string().contains("listing"), "{err:#}");
    }
}

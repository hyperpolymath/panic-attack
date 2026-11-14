// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! The user-classification registry: audited findings a project records
//! out-of-band from the source under scan.
//!
//! Read order (new input first; the legacy A2ML names are a fallback that the
//! standards A7 migration plan lets a shared reader keep until its callers
//! migrate):
//!
//! 1. `<root>/audits/assail-classifications_praxis.deed`, a DEED praxis
//!    document (see [`DEED_PATH`] for its form). When it exists it is the
//!    registry, and the A2ML files are not read at all.
//! 2. `<root>/audits/assail-classifications.a2ml` (legacy).
//! 3. `<root>/.panic-attack-classifications.a2ml` (legacy).
//!
//! A deed registry is checked in full: a malformed one is an error, never an
//! empty or partial registry. The legacy A2ML reader keeps its historical
//! lenient behaviour unchanged.

use crate::deed::{self, Item, Value};
use crate::types::{AssailReport, WeakPointCategory};
use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::io::Read;
use std::path::Path;

/// Repo-relative path of the deed registry.
///
/// The file name dispatches to the `praxis-deed` head under the standards deed
/// grammar (`deed.abnf` v2.0.0: `<stem>_praxis.deed`); a bare
/// `assail-classifications.deed` matches no dispatch pattern and is not a
/// conforming deed name. Form:
///
/// ```text
/// ;; SPDX-License-Identifier: MPL-2.0
/// (praxis-deed
///   :schema-version "1.0.0"
///   :canonical-name "example-assail-classifications"
///   :beholding-chora #uuid"0889b37b-defb-831f-973c-e119500db00e"
///   :profile assail-classifications
///   (classification
///     :file "crates/foo/src/bar.rs"
///     :category UnsafeCode
///     :audit "audits/audit-ffi-unsafe.md §1"
///     :rationale "one-line summary"))
/// ```
///
/// Top level: `:schema-version`, `:canonical-name` (string),
/// `:beholding-chora` (the estate chora's version 8 id) and
/// `:profile assail-classifications`, each exactly once, and any number of
/// `(classification …)` clauses. In a clause: `:file` (string) and
/// `:category` (a symbol naming a weak-point category) exactly once,
/// `:audit` and `:rationale` (strings) at most once. Nothing else.
pub const DEED_PATH: &str = "audits/assail-classifications_praxis.deed";

/// The `:profile` symbol that marks a praxis deed as this registry.
pub const DEED_PROFILE: &str = "assail-classifications";

/// Legacy A2ML registry paths, in the order they are tried.
pub const LEGACY_A2ML_PATHS: &[&str] = &[
    "audits/assail-classifications.a2ml",
    ".panic-attack-classifications.a2ml",
];

/// Hand-edited audit registries rarely exceed a few dozen KiB. The cap stops
/// a malicious or accidental input from exhausting memory during a
/// multi-thousand-repo mass-panic sweep.
const READ_LIMIT: u64 = 4 * 1024 * 1024;

/// A single classification entry read from a project's registry. When one
/// exists, findings matching `(file, category)` are flipped to
/// `suppressed = true` after the kanren suppression pass runs.
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

/// Load the project's user classifications (see the module docs for the
/// read order).
///
/// `Ok(vec![])` when no registry exists. An unreadable, oversized or
/// malformed deed registry is an `Err` naming the file and line.
pub fn load_user_classifications(project_root: &Path) -> Result<Vec<UserClassification>> {
    let deed_path = project_root.join(DEED_PATH);
    if deed_path.exists() {
        let text = read_capped(&deed_path)?;
        return parse_classification_deed(&text, &deed_path)
            .with_context(|| format!("malformed classification registry {}", deed_path.display()));
    }
    for rel in LEGACY_A2ML_PATHS {
        let p = project_root.join(rel);
        if let Ok(f) = fs::File::open(&p) {
            let mut buf = String::new();
            if f.take(READ_LIMIT).read_to_string(&mut buf).is_ok() {
                return Ok(parse_legacy_a2ml(&buf));
            }
        }
    }
    Ok(Vec::new())
}

/// Read a file whole, refusing one over [`READ_LIMIT`] rather than truncating it.
fn read_capped(path: &Path) -> Result<String> {
    let f = fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut buf = Vec::new();
    f.take(READ_LIMIT + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if buf.len() as u64 > READ_LIMIT {
        bail!(
            "{} exceeds the {} byte registry limit",
            path.display(),
            READ_LIMIT
        );
    }
    String::from_utf8(buf).map_err(|_| anyhow!("{} is not valid UTF-8", path.display()))
}

/// Parse a deed registry (form in [`DEED_PATH`]). `path` supplies the file
/// name for doc-head dispatch.
pub fn parse_classification_deed(text: &str, path: &Path) -> Result<Vec<UserClassification>> {
    let d = deed::parse(text, Some(path)).map_err(|e| anyhow!("{e}"))?;
    if d.head != "praxis-deed" {
        bail!("expected a praxis-deed, found {}", d.head);
    }
    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for item in &d.items {
        match item {
            Item::Field {
                key, value, line, ..
            } => {
                if seen.contains(&key.as_str()) {
                    bail!("line {line}: :{key} appears more than once");
                }
                seen.push(key);
                let ok = match key.as_str() {
                    "schema-version" => true, // checked by the grammar
                    "canonical-name" => matches!(value, Value::Str(s) if !s.trim().is_empty()),
                    "beholding-chora" => matches!(value, Value::Uuid(_) | Value::Uuid8(_)),
                    "profile" => matches!(value, Value::Symbol(s) if s == DEED_PROFILE),
                    _ => bail!("line {line}: unknown top-level field :{key}"),
                };
                if !ok {
                    bail!(
                        "line {line}: invalid :{key} ({}); see the registry form in the panic-attack docs",
                        value.kind()
                    );
                }
            }
            Item::Clause { name, items, line } => {
                if name != "classification" {
                    bail!("line {line}: unexpected clause ({name}); only (classification …) is allowed");
                }
                out.push(classification(items, *line)?);
            }
        }
    }
    for key in ["canonical-name", "beholding-chora", "profile"] {
        if !seen.contains(&key) {
            bail!("missing top-level :{key}");
        }
    }
    Ok(out)
}

fn classification(items: &[Item], at: usize) -> Result<UserClassification> {
    let mut file = None;
    let mut category = None;
    let mut seen: Vec<&str> = Vec::new();
    for item in items {
        let Item::Field {
            key, value, line, ..
        } = item
        else {
            bail!("line {at}: (classification …) holds fields only, no nested clause");
        };
        if seen.contains(&key.as_str()) {
            bail!("line {line}: :{key} appears more than once in (classification …)");
        }
        seen.push(key);
        match (key.as_str(), value) {
            ("file", Value::Str(s)) if !s.trim().is_empty() => file = Some(s.clone()),
            ("category", Value::Symbol(s)) => {
                let known = serde_json::from_value::<WeakPointCategory>(serde_json::Value::String(
                    s.clone(),
                ))
                .is_ok();
                if !known {
                    bail!("line {line}: unknown weak-point category {s}");
                }
                category = Some(s.clone());
            }
            ("audit" | "rationale", Value::Str(_)) => {}
            ("file" | "category" | "audit" | "rationale", v) => bail!(
                "line {line}: :{key} cannot be a {}{}",
                v.kind(),
                if key == "category" {
                    " (a category is a symbol, e.g. :category UnsafeCode)"
                } else {
                    ""
                }
            ),
            _ => bail!("line {line}: unknown field :{key} in (classification …)"),
        }
    }
    match (file, category) {
        (Some(file), Some(category)) => Ok(UserClassification { file, category }),
        _ => bail!("line {at}: (classification …) needs :file and :category"),
    }
}

/// The legacy A2ML reader, unchanged: entries lacking a quoted `file` or
/// `category` are skipped, and nothing is reported.
///
/// ```text
/// (assail-classifications
///   (classification
///     (file "crates/oo7-core/src/zig_bridge.rs")
///     (category "UnsafeCode")
///     (audit "audits/audit-ffi-unsafe.md §1"))
///   ...)
/// ```
fn parse_legacy_a2ml(content: &str) -> Vec<UserClassification> {
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
/// and category match a registry entry are marked `suppressed = true` and
/// counted toward `report.suppressed_count`.
///
/// Runs after the kanren-based `apply_suppression` so that the
/// structural suppression rules get first pass and the classification
/// registry covers only the genuinely-audited residuals.
///
/// # Errors
/// A malformed deed registry (see [`load_user_classifications`]); the report
/// is left unchanged.
pub fn apply_user_classifications(report: &mut AssailReport, project_root: &Path) -> Result<()> {
    let classifications = load_user_classifications(project_root)?;
    if classifications.is_empty() {
        return Ok(());
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
    Ok(())
}

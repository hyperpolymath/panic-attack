// SPDX-License-Identifier: PMPL-1.0-or-later

//! Minimal A2ML parser and Nickel exporter

use crate::report::formatter::nickel_escape_string;
use crate::report::ReportOutputFormat;
use crate::storage::StorageMode;
use crate::types::{AssailReport, AssaultReport, AttackResult};
use crate::{abduct, adjudicate, amuck, axial};
use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};

const REPORT_BUNDLE_SCHEMA: &str = "panic-attack.report-bundle";
const REPORT_BUNDLE_VERSION: u32 = 1;
const REPORT_BUNDLE_ENCODING: &str = "json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportBundleKind {
    Assail,
    Attack,
    Assault,
    Ambush,
    Amuck,
    Abduct,
    Adjudicate,
    Axial,
}

impl ReportBundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assail => "assail",
            Self::Attack => "attack",
            Self::Assault => "assault",
            Self::Ambush => "ambush",
            Self::Amuck => "amuck",
            Self::Abduct => "abduct",
            Self::Adjudicate => "adjudicate",
            Self::Axial => "axial",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "assail" => Some(Self::Assail),
            "attack" => Some(Self::Attack),
            "assault" => Some(Self::Assault),
            "ambush" => Some(Self::Ambush),
            "amuck" => Some(Self::Amuck),
            "abduct" => Some(Self::Abduct),
            "adjudicate" => Some(Self::Adjudicate),
            "axial" => Some(Self::Axial),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum ReportBundlePayload {
    Assail(AssailReport),
    Attack(Vec<AttackResult>),
    Assault(AssaultReport),
    Ambush(AssaultReport),
    Amuck(amuck::AmuckReport),
    Abduct(abduct::AbductReport),
    Adjudicate(adjudicate::AdjudicateReport),
    Axial(axial::AxialReport),
}

impl ReportBundlePayload {
    pub fn kind(&self) -> ReportBundleKind {
        match self {
            Self::Assail(_) => ReportBundleKind::Assail,
            Self::Attack(_) => ReportBundleKind::Attack,
            Self::Assault(_) => ReportBundleKind::Assault,
            Self::Ambush(_) => ReportBundleKind::Ambush,
            Self::Amuck(_) => ReportBundleKind::Amuck,
            Self::Abduct(_) => ReportBundleKind::Abduct,
            Self::Adjudicate(_) => ReportBundleKind::Adjudicate,
            Self::Axial(_) => ReportBundleKind::Axial,
        }
    }

    pub fn to_json_string(&self) -> Result<String> {
        let encoded = match self {
            Self::Assail(v) => serde_json::to_string(v),
            Self::Attack(v) => serde_json::to_string(v),
            Self::Assault(v) => serde_json::to_string(v),
            Self::Ambush(v) => serde_json::to_string(v),
            Self::Amuck(v) => serde_json::to_string(v),
            Self::Abduct(v) => serde_json::to_string(v),
            Self::Adjudicate(v) => serde_json::to_string(v),
            Self::Axial(v) => serde_json::to_string(v),
        }
        .context("serializing report payload as json")?;
        Ok(encoded)
    }
}

#[derive(Clone, Debug)]
pub struct ReportBundle {
    pub schema: String,
    pub version: u32,
    pub exported_at: String,
    pub payload: ReportBundlePayload,
    /// Optional attestation envelope from `--attest` mode.
    /// When present, the report's integrity is cryptographically chained.
    #[allow(dead_code)]
    pub attestation: Option<crate::attestation::A2mlEnvelope>,
}

impl ReportBundle {
    pub fn new(payload: ReportBundlePayload) -> Self {
        Self {
            schema: REPORT_BUNDLE_SCHEMA.to_string(),
            version: REPORT_BUNDLE_VERSION,
            exported_at: chrono::Utc::now().to_rfc3339(),
            payload,
            attestation: None,
        }
    }

    /// Attach an attestation envelope to this report bundle.
    #[allow(dead_code)]
    pub fn with_attestation(mut self, envelope: crate::attestation::A2mlEnvelope) -> Self {
        self.attestation = Some(envelope);
        self
    }

    pub fn kind(&self) -> ReportBundleKind {
        self.payload.kind()
    }
}

#[derive(Clone, Debug)]
pub struct Manifest {
    root_name: String,
    entries: Vec<Sexpr>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            root_name: "manifest".to_string(),
            entries: Vec::new(),
        }
    }
}

impl Manifest {
    pub fn load_default() -> Result<Self> {
        let path = PathBuf::from("AI.a2ml");
        Self::load(&path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading A2ML manifest {}", path.display()))?;
        let mut parser = Parser::new(&raw);
        let tree = parser.parse_all()?;
        if let Sexpr::List(mut items) = tree {
            if let Some(Sexpr::Atom(root)) = items.first() {
                let root_name = root.clone();
                items.remove(0);
                return Ok(Self {
                    root_name,
                    entries: items,
                });
            }
        }
        Err(anyhow!("unexpected A2ML manifest structure"))
    }

    pub fn report_formats(&self) -> Vec<ReportOutputFormat> {
        self.section_entries("reports")
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|(key, _)| key == "formats")
                    .map(|(_, groups)| {
                        groups.iter().flat_map(|values| {
                            values.iter().filter_map(|value| match value {
                                Sexpr::String(text) => ReportOutputFormat::parse(text),
                                Sexpr::Atom(atom) => ReportOutputFormat::parse(atom),
                                _ => None,
                            })
                        })
                    })
                    .map(|iter| iter.collect::<Vec<_>>())
            })
            .filter(|formats: &Vec<ReportOutputFormat>| !formats.is_empty())
            .unwrap_or_else(|| vec![ReportOutputFormat::Json, ReportOutputFormat::Nickel])
    }

    pub fn storage_modes(&self) -> Vec<StorageMode> {
        self.section_entries("reports")
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|(key, _)| key == "storage-targets")
                    .map(|(_, groups)| {
                        groups
                            .iter()
                            .flat_map(|values| {
                                values.iter().filter_map(|value| match value {
                                    Sexpr::String(text) => StorageMode::from_str(text),
                                    Sexpr::Atom(atom) => StorageMode::from_str(atom),
                                    _ => None,
                                })
                            })
                            .collect::<Vec<_>>()
                    })
            })
            .filter(|modes: &Vec<StorageMode>| !modes.is_empty())
            .unwrap_or_else(|| vec![StorageMode::Filesystem])
    }

    pub fn to_nickel(&self) -> String {
        let entries = gather_entries(&self.entries);
        let body = record_to_nickel(&entries);
        format!("let {} = {};\n{}", self.root_name, body, self.root_name)
    }

    fn section_entries(&self, key: &str) -> Option<Vec<(String, Vec<Vec<Sexpr>>)>> {
        self.entries.iter().find_map(|entry| {
            if let Sexpr::List(list) = entry {
                if let Some(Sexpr::Atom(name)) = list.first() {
                    if name == key {
                        return Some(gather_entries(&list[1..]));
                    }
                }
            }
            None
        })
    }
}

pub fn write_report_bundle(bundle: &ReportBundle, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating report-bundle parent {}", parent.display()))?;
    }
    let rendered = render_report_bundle(bundle)?;
    fs::write(path, rendered).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub fn read_report_bundle(path: &Path) -> Result<ReportBundle> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_report_bundle(&raw)
}

pub fn export_report_file(kind: ReportBundleKind, input: &Path, output: &Path) -> Result<()> {
    let payload = load_payload_for_kind(kind, input)?;
    let bundle = ReportBundle::new(payload);
    write_report_bundle(&bundle, output)?;
    Ok(())
}

pub fn import_report_file(input: &Path, output: &Path) -> Result<ReportBundleKind> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating import parent {}", parent.display()))?;
    }
    let bundle = read_report_bundle(input)?;
    let json = match &bundle.payload {
        ReportBundlePayload::Assail(v) => serde_json::to_string_pretty(v),
        ReportBundlePayload::Attack(v) => serde_json::to_string_pretty(v),
        ReportBundlePayload::Assault(v) => serde_json::to_string_pretty(v),
        ReportBundlePayload::Ambush(v) => serde_json::to_string_pretty(v),
        ReportBundlePayload::Amuck(v) => serde_json::to_string_pretty(v),
        ReportBundlePayload::Abduct(v) => serde_json::to_string_pretty(v),
        ReportBundlePayload::Adjudicate(v) => serde_json::to_string_pretty(v),
        ReportBundlePayload::Axial(v) => serde_json::to_string_pretty(v),
    }
    .context("serializing imported report")?;
    fs::write(output, json).with_context(|| format!("writing {}", output.display()))?;
    Ok(bundle.kind())
}

fn load_payload_for_kind(kind: ReportBundleKind, input: &Path) -> Result<ReportBundlePayload> {
    Ok(match kind {
        ReportBundleKind::Assail => {
            ReportBundlePayload::Assail(load_json_or_yaml::<AssailReport>(input)?)
        }
        ReportBundleKind::Attack => ReportBundlePayload::Attack(load_attack_results(input)?),
        ReportBundleKind::Assault => {
            let report = crate::report::load_report(input)?;
            ReportBundlePayload::Assault(report)
        }
        ReportBundleKind::Ambush => {
            let report = crate::report::load_report(input)?;
            ReportBundlePayload::Ambush(report)
        }
        ReportBundleKind::Amuck => {
            ReportBundlePayload::Amuck(load_json_or_yaml::<amuck::AmuckReport>(input)?)
        }
        ReportBundleKind::Abduct => {
            ReportBundlePayload::Abduct(load_json_or_yaml::<abduct::AbductReport>(input)?)
        }
        ReportBundleKind::Adjudicate => ReportBundlePayload::Adjudicate(load_json_or_yaml::<
            adjudicate::AdjudicateReport,
        >(input)?),
        ReportBundleKind::Axial => {
            ReportBundlePayload::Axial(load_json_or_yaml::<axial::AxialReport>(input)?)
        }
    })
}

fn load_json_or_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    match path.extension().and_then(|e| e.to_str()) {
        Some("yaml") | Some("yml") => {
            serde_yaml::from_str::<T>(&raw).with_context(|| format!("parsing {}", path.display()))
        }
        _ => serde_json::from_str::<T>(&raw).with_context(|| format!("parsing {}", path.display())),
    }
}

fn load_attack_results(path: &Path) -> Result<Vec<AttackResult>> {
    #[derive(serde::Deserialize)]
    struct AttackWrapper {
        attack_results: Vec<AttackResult>,
    }

    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if let Ok(results) = serde_json::from_str::<Vec<AttackResult>>(&raw) {
        return Ok(results);
    }
    if let Ok(wrapper) = serde_json::from_str::<AttackWrapper>(&raw) {
        return Ok(wrapper.attack_results);
    }
    if let Ok(results) = serde_yaml::from_str::<Vec<AttackResult>>(&raw) {
        return Ok(results);
    }
    if let Ok(wrapper) = serde_yaml::from_str::<AttackWrapper>(&raw) {
        return Ok(wrapper.attack_results);
    }
    Err(anyhow!(
        "failed to parse {} as attack results array",
        path.display()
    ))
}

fn render_report_bundle(bundle: &ReportBundle) -> Result<String> {
    if bundle.schema != REPORT_BUNDLE_SCHEMA {
        return Err(anyhow!(
            "unsupported report bundle schema: {}",
            bundle.schema
        ));
    }
    let payload_json = bundle.payload.to_json_string()?;
    Ok(format!(
        "(panic_attack_report_bundle\n  (schema {})\n  (version \"{}\")\n  (kind \"{}\")\n  (exported_at {})\n  (encoding \"{}\")\n  (payload {})\n)\n",
        quote_atom(&bundle.schema),
        bundle.version,
        bundle.kind().as_str(),
        quote_atom(&bundle.exported_at),
        REPORT_BUNDLE_ENCODING,
        quote_atom(&payload_json)
    ))
}

fn parse_report_bundle(raw: &str) -> Result<ReportBundle> {
    let mut parser = Parser::new(raw);
    let tree = parser.parse_all()?;
    let (root, entries) = match tree {
        Sexpr::List(items) => {
            if items.is_empty() {
                return Err(anyhow!("empty report bundle"));
            }
            let root = match &items[0] {
                Sexpr::Atom(v) => v.clone(),
                _ => return Err(anyhow!("invalid report bundle root")),
            };
            (root, gather_entries(&items[1..]))
        }
        _ => return Err(anyhow!("invalid report bundle form")),
    };

    if root != "panic_attack_report_bundle" {
        return Err(anyhow!("unsupported report bundle root '{}'", root));
    }
    let schema = entry_string(&entries, "schema")?;
    if schema != REPORT_BUNDLE_SCHEMA {
        return Err(anyhow!("unsupported report bundle schema '{}'", schema));
    }
    let version_raw = entry_string(&entries, "version")?;
    let version = version_raw
        .parse::<u32>()
        .with_context(|| format!("parsing report bundle version '{}'", version_raw))?;
    if version != REPORT_BUNDLE_VERSION {
        return Err(anyhow!(
            "unsupported report bundle version {} (expected {})",
            version,
            REPORT_BUNDLE_VERSION
        ));
    }

    let kind_raw = entry_string(&entries, "kind")?;
    let kind = ReportBundleKind::parse(&kind_raw)
        .ok_or_else(|| anyhow!("unsupported report bundle kind '{}'", kind_raw))?;
    let encoding = entry_string(&entries, "encoding")?;
    if encoding != REPORT_BUNDLE_ENCODING {
        return Err(anyhow!("unsupported report encoding '{}'", encoding));
    }
    let payload_json = entry_string(&entries, "payload")?;
    let payload = parse_payload(kind, &payload_json)?;
    let exported_at =
        entry_string(&entries, "exported_at").unwrap_or_else(|_| chrono::Utc::now().to_rfc3339());

    Ok(ReportBundle {
        schema,
        version,
        exported_at,
        payload,
        attestation: None,
    })
}

fn parse_payload(kind: ReportBundleKind, payload_json: &str) -> Result<ReportBundlePayload> {
    Ok(match kind {
        ReportBundleKind::Assail => {
            ReportBundlePayload::Assail(serde_json::from_str::<AssailReport>(payload_json)?)
        }
        ReportBundleKind::Attack => {
            ReportBundlePayload::Attack(serde_json::from_str::<Vec<AttackResult>>(payload_json)?)
        }
        ReportBundleKind::Assault => {
            ReportBundlePayload::Assault(serde_json::from_str::<AssaultReport>(payload_json)?)
        }
        ReportBundleKind::Ambush => {
            ReportBundlePayload::Ambush(serde_json::from_str::<AssaultReport>(payload_json)?)
        }
        ReportBundleKind::Amuck => {
            ReportBundlePayload::Amuck(serde_json::from_str::<amuck::AmuckReport>(payload_json)?)
        }
        ReportBundleKind::Abduct => {
            ReportBundlePayload::Abduct(serde_json::from_str::<abduct::AbductReport>(payload_json)?)
        }
        ReportBundleKind::Adjudicate => ReportBundlePayload::Adjudicate(serde_json::from_str::<
            adjudicate::AdjudicateReport,
        >(payload_json)?),
        ReportBundleKind::Axial => ReportBundlePayload::Axial(serde_json::from_str::<
            axial::AxialReport,
        >(payload_json)?),
    })
}

fn entry_string(entries: &[(String, Vec<Vec<Sexpr>>)], key: &str) -> Result<String> {
    let groups = entries
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, groups)| groups)
        .ok_or_else(|| anyhow!("missing '{}' entry in report bundle", key))?;
    let values = groups
        .first()
        .ok_or_else(|| anyhow!("empty '{}' entry in report bundle", key))?;
    let first = values
        .first()
        .ok_or_else(|| anyhow!("empty '{}' value in report bundle", key))?;
    match first {
        Sexpr::String(v) | Sexpr::Atom(v) => Ok(v.clone()),
        Sexpr::List(_) => Err(anyhow!("invalid '{}' value in report bundle", key)),
    }
}

fn quote_atom(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("\"{}\"", value))
}

#[derive(Clone, Debug)]
enum Sexpr {
    Atom(String),
    String(String),
    List(Vec<Sexpr>),
}

struct Parser<'a> {
    chars: std::str::Chars<'a>,
    peeked: Option<Option<char>>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars(),
            peeked: None,
        }
    }

    fn peek(&mut self) -> Option<char> {
        if let Some(opt) = self.peeked {
            opt
        } else {
            let opt = self.chars.clone().next();
            self.peeked = Some(opt);
            opt
        }
    }

    fn next(&mut self) -> Option<char> {
        if let Some(opt) = self.peeked.take() {
            if let Some(ch) = opt {
                self.chars.next();
                Some(ch)
            } else {
                None
            }
        } else {
            self.chars.next()
        }
    }

    fn skip_whitespace(&mut self) {
        loop {
            match self.peek() {
                Some(ch) if ch.is_whitespace() => {
                    self.next();
                }
                Some('#') => {
                    while let Some(ch) = self.next() {
                        if ch == '\n' {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }

    fn parse_all(&mut self) -> Result<Sexpr> {
        self.skip_whitespace();
        let expr = self.parse_expr()?;
        self.skip_whitespace();
        if self.peek().is_some() {
            Err(anyhow!("extra tokens after manifest"))
        } else {
            Ok(expr)
        }
    }

    fn parse_expr(&mut self) -> Result<Sexpr> {
        self.skip_whitespace();
        match self.peek() {
            Some('(') => self.parse_list(),
            Some('"') => self.parse_string(),
            Some(ch) => {
                if ch == ')' {
                    Err(anyhow!("unexpected closing parenthesis"))
                } else {
                    self.parse_atom()
                }
            }
            None => Err(anyhow!("unexpected EOF while parsing A2ML")),
        }
    }

    fn parse_list(&mut self) -> Result<Sexpr> {
        self.next(); // consume '('
        let mut items = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                Some(')') => {
                    self.next();
                    break;
                }
                Some(_) => items.push(self.parse_expr()?),
                None => return Err(anyhow!("unterminated list")),
            }
        }
        Ok(Sexpr::List(items))
    }

    fn parse_string(&mut self) -> Result<Sexpr> {
        self.next(); // consume '"'
        let mut value = String::new();
        while let Some(ch) = self.next() {
            match ch {
                '"' => return Ok(Sexpr::String(value)),
                '\\' => {
                    if let Some(esc) = self.next() {
                        let replacement = match esc {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            '"' => '"',
                            '\\' => '\\',
                            other => other,
                        };
                        value.push(replacement);
                    }
                }
                other => value.push(other),
            }
        }
        Err(anyhow!("unterminated string literal"))
    }

    fn parse_atom(&mut self) -> Result<Sexpr> {
        let mut value = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() || ch == '(' || ch == ')' {
                break;
            }
            value.push(ch);
            self.next();
        }
        if value.is_empty() {
            Err(anyhow!("unexpected token"))
        } else {
            Ok(Sexpr::Atom(value))
        }
    }
}

fn gather_entries(entries: &[Sexpr]) -> Vec<(String, Vec<Vec<Sexpr>>)> {
    let mut grouped: Vec<(String, Vec<Vec<Sexpr>>)> = Vec::new();
    for entry in entries {
        if let Sexpr::List(inner) = entry {
            if let Some(Sexpr::Atom(key)) = inner.first() {
                let values = inner[1..].to_vec();
                if let Some((_, bucket)) = grouped.iter_mut().find(|(existing, _)| existing == key)
                {
                    bucket.push(values);
                } else {
                    grouped.push((key.clone(), vec![values]));
                }
            }
        }
    }
    grouped
}

fn record_to_nickel(entries: &[(String, Vec<Vec<Sexpr>>)]) -> String {
    let lines: Vec<String> = entries
        .iter()
        .map(|(key, groups)| {
            let value = if groups.len() == 1 {
                values_to_nickel(&groups[0])
            } else {
                let array = groups
                    .iter()
                    .map(|values| values_to_nickel(values))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}]", array)
            };
            format!("{} = {}", key_to_nickel(key), value)
        })
        .collect();
    format!("{{\n    {}\n}}", lines.join(";\n    "))
}

fn values_to_nickel(values: &[Sexpr]) -> String {
    match values.len() {
        0 => "null".to_string(),
        1 => value_to_nickel(&values[0]),
        _ => {
            if values.iter().all(|v| matches!(v, Sexpr::List(inner) if inner.first().map(|c| matches!(c, Sexpr::Atom(_))).unwrap_or(false))) {
                let nested_entries = gather_entries(values);
                record_to_nickel(&nested_entries)
            } else {
                let list = values
                    .iter()
                    .map(value_to_nickel)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}]", list)
            }
        }
    }
}

fn value_to_nickel(value: &Sexpr) -> String {
    match value {
        Sexpr::String(text) => nickel_escape_string(text),
        Sexpr::Atom(text) => nickel_escape_string(text),
        Sexpr::List(list) => {
            if list.is_empty() {
                "{}".to_string()
            } else if list.iter().all(|entry| {
                matches!(entry, Sexpr::List(inner) if inner.first().map(|c| matches!(c, Sexpr::Atom(_))).unwrap_or(false))
            }) {
                let nested_entries = gather_entries(list);
                record_to_nickel(&nested_entries)
            } else {
                let inner = list
                    .iter()
                    .map(value_to_nickel)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}]", inner)
            }
        }
    }
}

fn key_to_nickel(key: &str) -> String {
    if key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        key.to_string()
    } else {
        serde_json::to_string(key).unwrap_or_else(|_| format!("\"{}\"", key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AttackAxis, BugSignature, CrashReport, DependencyGraph, FileStatistics, Framework,
        Language, OverallAssessment, ProgramStatistics, Severity, SignatureType, TaintMatrix,
        TimelineEventReport, TimelineReport, WeakPoint, WeakPointCategory,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::TempDir;

    fn sample_assail_report() -> AssailReport {
        AssailReport {
            program_path: PathBuf::from("src/main.rs"),
            language: Language::Rust,
            frameworks: vec![Framework::Unknown],
            weak_points: vec![WeakPoint {
                category: WeakPointCategory::UncheckedError,
                location: Some("src/main.rs:10".to_string()),
                severity: Severity::Medium,
                description: "unchecked result".to_string(),
                recommended_attack: vec![AttackAxis::Concurrency],
            }],
            statistics: ProgramStatistics {
                total_lines: 42,
                unsafe_blocks: 0,
                panic_sites: 0,
                unwrap_calls: 0,
                allocation_sites: 0,
                io_operations: 0,
                threading_constructs: 0,
            },
            file_statistics: vec![FileStatistics {
                file_path: "src/main.rs".to_string(),
                lines: 42,
                unsafe_blocks: 0,
                panic_sites: 0,
                unwrap_calls: 0,
                allocation_sites: 0,
                io_operations: 0,
                threading_constructs: 0,
            }],
            recommended_attacks: vec![AttackAxis::Concurrency],
            dependency_graph: DependencyGraph::default(),
            taint_matrix: TaintMatrix::default(),
            migration_metrics: None,
        }
    }

    fn sample_attack_results() -> Vec<AttackResult> {
        vec![AttackResult {
            program: PathBuf::from("./bin/target"),
            axis: AttackAxis::Cpu,
            success: false,
            skipped: false,
            skip_reason: None,
            exit_code: Some(1),
            duration: Duration::from_secs(1),
            peak_memory: 1024,
            crashes: vec![CrashReport {
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                signal: Some("SIGABRT".to_string()),
                backtrace: None,
                stderr: "panic".to_string(),
                stdout: String::new(),
            }],
            signatures_detected: vec![BugSignature {
                signature_type: SignatureType::UnhandledError,
                confidence: 0.5,
                evidence: vec!["stderr panic".to_string()],
                location: Some("main".to_string()),
            }],
        }]
    }

    fn sample_ambush_report() -> AssaultReport {
        AssaultReport {
            assail_report: sample_assail_report(),
            attack_results: sample_attack_results(),
            total_crashes: 1,
            total_signatures: 1,
            overall_assessment: OverallAssessment {
                robustness_score: 25.0,
                critical_issues: vec!["crash".to_string()],
                recommendations: vec!["review time axis".to_string()],
            },
            timeline: Some(TimelineReport {
                duration: Duration::from_secs(30),
                events: vec![TimelineEventReport {
                    id: "evt-1".to_string(),
                    axis: AttackAxis::Memory,
                    start_offset: Duration::from_secs(5),
                    duration: Duration::from_secs(10),
                    intensity: crate::types::IntensityLevel::Medium,
                    args: vec!["--foo".to_string()],
                    peak_memory: Some(1000),
                    ran: true,
                }],
            }),
        }
    }

    fn sample_assault_report() -> AssaultReport {
        let mut report = sample_ambush_report();
        report.timeline = None;
        report
    }

    fn sample_amuck_report() -> amuck::AmuckReport {
        amuck::AmuckReport {
            created_at: chrono::Utc::now().to_rfc3339(),
            target: PathBuf::from("src/main.rs"),
            source_spec: None,
            preset: "dangerous".to_string(),
            max_combinations: 2,
            output_dir: PathBuf::from("runtime/amuck"),
            combinations_planned: 2,
            combinations_run: 1,
            outcomes: vec![amuck::AmuckOutcome {
                id: 1,
                name: "flip".to_string(),
                operations: vec!["replace_first(true->false)".to_string()],
                applied_changes: 1,
                mutated_file: Some(PathBuf::from("runtime/amuck/main.amuck.001.rs")),
                apply_error: None,
                execution: Some(amuck::ExecutionOutcome {
                    success: false,
                    exit_code: Some(1),
                    duration_ms: 12,
                    stdout: String::new(),
                    stderr: "compile error".to_string(),
                    spawn_error: None,
                }),
            }],
        }
    }

    fn sample_abduct_report() -> abduct::AbductReport {
        abduct::AbductReport {
            created_at: chrono::Utc::now().to_rfc3339(),
            target: PathBuf::from("src/main.rs"),
            source_root: PathBuf::from("src"),
            workspace_dir: PathBuf::from("runtime/abduct/abduct-20260101000000"),
            dependency_scope: "direct".to_string(),
            selected_files: 2,
            locked_files: 2,
            mtime_shifted_files: 2,
            mtime_offset_days: 14,
            time_mode: "slow".to_string(),
            time_scale: Some(0.1),
            virtual_now: Some("2026-01-01T00:00:00Z".to_string()),
            notes: vec!["sample abduct note".to_string()],
            files: vec![abduct::AbductFileRecord {
                source: PathBuf::from("src/main.rs"),
                destination: PathBuf::from("runtime/abduct/abduct-20260101000000/src/main.rs"),
                relative_path: "src/main.rs".to_string(),
                locked: true,
                mtime_shifted: true,
            }],
            execution: Some(abduct::ExecutionOutcome {
                success: true,
                exit_code: Some(0),
                duration_ms: 20,
                timed_out: false,
                stdout: "ok".to_string(),
                stderr: String::new(),
                spawn_error: None,
            }),
        }
    }

    fn sample_adjudicate_report() -> adjudicate::AdjudicateReport {
        adjudicate::AdjudicateReport {
            created_at: chrono::Utc::now().to_rfc3339(),
            reports: vec![
                PathBuf::from("reports/a.json"),
                PathBuf::from("reports/b.json"),
            ],
            processed_reports: 2,
            failed_reports: 0,
            verdict: "warn".to_string(),
            totals: adjudicate::AdjudicateTotals {
                assault_reports: 1,
                amuck_reports: 1,
                abduct_reports: 0,
                total_crashes: 1,
                total_signatures: 1,
                critical_weak_points: 0,
                failed_attacks: 1,
                mutation_apply_errors: 0,
                mutation_exec_failures: 1,
                abduct_exec_failures: 0,
                abduct_timeouts: 0,
            },
            rule_hits: vec![adjudicate::RuleHit {
                rule: "campaign_warn_on_medium_signal".to_string(),
                derived: 1,
                confidence: 0.8,
                priority: 60,
            }],
            priorities: vec![adjudicate::PriorityFinding {
                level: "medium".to_string(),
                message: "failed attack execution needs review".to_string(),
            }],
            notes: Vec::new(),
        }
    }

    fn sample_axial_report() -> axial::AxialReport {
        let mut signal_counts = BTreeMap::new();
        signal_counts.insert("panic_signal".to_string(), 1);
        axial::AxialReport {
            created_at: chrono::Utc::now().to_rfc3339(),
            target: PathBuf::from("src/main.rs"),
            executed_program: Some("panic-attack".to_string()),
            repeat: 1,
            observed_runs: 1,
            observed_reports: 0,
            language: "en".to_string(),
            run_observations: vec![axial::RunObservation {
                run_index: 1,
                success: false,
                exit_code: Some(1),
                duration_ms: 15,
                timed_out: false,
                stdout: String::new(),
                stderr: "panic".to_string(),
                stdout_head: Vec::new(),
                stdout_tail: Vec::new(),
                stderr_head: vec!["panic".to_string()],
                stderr_tail: vec!["panic".to_string()],
                matches: vec![axial::PatternMatch {
                    mode: "grep".to_string(),
                    pattern: "panic".to_string(),
                    line_no: 1,
                    line: "panic".to_string(),
                    distance: None,
                }],
                signals: vec![axial::Signal {
                    severity: "high".to_string(),
                    name: "panic_signal".to_string(),
                    evidence: "panic found in stderr".to_string(),
                }],
                spellcheck: None,
            }],
            report_observations: Vec::new(),
            signal_counts,
            recommendations: vec!["review panic path".to_string()],
            aspell: Some(axial::SpellcheckSummary {
                lang: "en".to_string(),
                total_misspellings: 0,
                run_observations_with_misspellings: 0,
                report_observations_with_misspellings: 0,
            }),
        }
    }

    #[test]
    fn report_bundle_roundtrip_assail() {
        let bundle = ReportBundle::new(ReportBundlePayload::Assail(sample_assail_report()));
        let rendered = render_report_bundle(&bundle).expect("render should succeed");
        let parsed = parse_report_bundle(&rendered).expect("parse should succeed");
        assert_eq!(parsed.kind(), ReportBundleKind::Assail);
        let payload = match parsed.payload {
            ReportBundlePayload::Assail(v) => v,
            _ => panic!("wrong payload type"),
        };
        assert_eq!(payload.program_path, PathBuf::from("src/main.rs"));
    }

    #[test]
    fn report_bundle_roundtrip_attack() {
        let bundle = ReportBundle::new(ReportBundlePayload::Attack(sample_attack_results()));
        let rendered = render_report_bundle(&bundle).expect("render should succeed");
        let parsed = parse_report_bundle(&rendered).expect("parse should succeed");
        assert_eq!(parsed.kind(), ReportBundleKind::Attack);
        let payload = match parsed.payload {
            ReportBundlePayload::Attack(v) => v,
            _ => panic!("wrong payload type"),
        };
        assert_eq!(payload.len(), 1);
        assert_eq!(payload[0].axis, AttackAxis::Cpu);
    }

    #[test]
    fn report_bundle_roundtrip_ambush() {
        let bundle = ReportBundle::new(ReportBundlePayload::Ambush(sample_ambush_report()));
        let rendered = render_report_bundle(&bundle).expect("render should succeed");
        let parsed = parse_report_bundle(&rendered).expect("parse should succeed");
        assert_eq!(parsed.kind(), ReportBundleKind::Ambush);
        let payload = match parsed.payload {
            ReportBundlePayload::Ambush(v) => v,
            _ => panic!("wrong payload type"),
        };
        assert!(payload.timeline.is_some());
        assert_eq!(payload.total_crashes, 1);
    }

    #[test]
    fn report_bundle_roundtrip_assault() {
        let bundle = ReportBundle::new(ReportBundlePayload::Assault(sample_assault_report()));
        let rendered = render_report_bundle(&bundle).expect("render should succeed");
        let parsed = parse_report_bundle(&rendered).expect("parse should succeed");
        assert_eq!(parsed.kind(), ReportBundleKind::Assault);
        let payload = match parsed.payload {
            ReportBundlePayload::Assault(v) => v,
            _ => panic!("wrong payload type"),
        };
        assert!(payload.timeline.is_none());
        assert_eq!(payload.total_signatures, 1);
    }

    #[test]
    fn report_bundle_roundtrip_amuck() {
        let bundle = ReportBundle::new(ReportBundlePayload::Amuck(sample_amuck_report()));
        let rendered = render_report_bundle(&bundle).expect("render should succeed");
        let parsed = parse_report_bundle(&rendered).expect("parse should succeed");
        assert_eq!(parsed.kind(), ReportBundleKind::Amuck);
        let payload = match parsed.payload {
            ReportBundlePayload::Amuck(v) => v,
            _ => panic!("wrong payload type"),
        };
        assert_eq!(payload.combinations_planned, 2);
        assert_eq!(payload.combinations_run, 1);
    }

    #[test]
    fn report_bundle_roundtrip_abduct() {
        let bundle = ReportBundle::new(ReportBundlePayload::Abduct(sample_abduct_report()));
        let rendered = render_report_bundle(&bundle).expect("render should succeed");
        let parsed = parse_report_bundle(&rendered).expect("parse should succeed");
        assert_eq!(parsed.kind(), ReportBundleKind::Abduct);
        let payload = match parsed.payload {
            ReportBundlePayload::Abduct(v) => v,
            _ => panic!("wrong payload type"),
        };
        assert_eq!(payload.selected_files, 2);
        assert_eq!(payload.locked_files, 2);
    }

    #[test]
    fn report_bundle_roundtrip_adjudicate() {
        let bundle = ReportBundle::new(ReportBundlePayload::Adjudicate(sample_adjudicate_report()));
        let rendered = render_report_bundle(&bundle).expect("render should succeed");
        let parsed = parse_report_bundle(&rendered).expect("parse should succeed");
        assert_eq!(parsed.kind(), ReportBundleKind::Adjudicate);
        let payload = match parsed.payload {
            ReportBundlePayload::Adjudicate(v) => v,
            _ => panic!("wrong payload type"),
        };
        assert_eq!(payload.verdict, "warn");
        assert_eq!(payload.processed_reports, 2);
    }

    #[test]
    fn report_bundle_roundtrip_axial() {
        let bundle = ReportBundle::new(ReportBundlePayload::Axial(sample_axial_report()));
        let rendered = render_report_bundle(&bundle).expect("render should succeed");
        let parsed = parse_report_bundle(&rendered).expect("parse should succeed");
        assert_eq!(parsed.kind(), ReportBundleKind::Axial);
        let payload = match parsed.payload {
            ReportBundlePayload::Axial(v) => v,
            _ => panic!("wrong payload type"),
        };
        assert_eq!(payload.observed_runs, 1);
        assert_eq!(payload.signal_counts.get("panic_signal"), Some(&1));
    }

    #[test]
    fn export_import_file_roundtrip_all_kinds() {
        let dir = TempDir::new().expect("tempdir should create");

        let cases = vec![
            (
                ReportBundleKind::Assail,
                ReportBundlePayload::Assail(sample_assail_report()),
            ),
            (
                ReportBundleKind::Attack,
                ReportBundlePayload::Attack(sample_attack_results()),
            ),
            (
                ReportBundleKind::Assault,
                ReportBundlePayload::Assault(sample_assault_report()),
            ),
            (
                ReportBundleKind::Ambush,
                ReportBundlePayload::Ambush(sample_ambush_report()),
            ),
            (
                ReportBundleKind::Amuck,
                ReportBundlePayload::Amuck(sample_amuck_report()),
            ),
            (
                ReportBundleKind::Abduct,
                ReportBundlePayload::Abduct(sample_abduct_report()),
            ),
            (
                ReportBundleKind::Adjudicate,
                ReportBundlePayload::Adjudicate(sample_adjudicate_report()),
            ),
            (
                ReportBundleKind::Axial,
                ReportBundlePayload::Axial(sample_axial_report()),
            ),
        ];

        for (idx, (kind, payload)) in cases.into_iter().enumerate() {
            let input = dir
                .path()
                .join(format!("input-{}-{}.json", idx, kind.as_str()));
            let output = dir
                .path()
                .join(format!("output-{}-{}.json", idx, kind.as_str()));
            let bundle_path = dir
                .path()
                .join(format!("bundle-{}-{}.a2ml", idx, kind.as_str()));

            let json = match &payload {
                ReportBundlePayload::Assail(v) => serde_json::to_string_pretty(v),
                ReportBundlePayload::Attack(v) => serde_json::to_string_pretty(v),
                ReportBundlePayload::Assault(v) => serde_json::to_string_pretty(v),
                ReportBundlePayload::Ambush(v) => serde_json::to_string_pretty(v),
                ReportBundlePayload::Amuck(v) => serde_json::to_string_pretty(v),
                ReportBundlePayload::Abduct(v) => serde_json::to_string_pretty(v),
                ReportBundlePayload::Adjudicate(v) => serde_json::to_string_pretty(v),
                ReportBundlePayload::Axial(v) => serde_json::to_string_pretty(v),
            }
            .expect("payload should serialize");
            fs::write(&input, json).expect("input should write");

            export_report_file(kind, &input, &bundle_path).expect("export should succeed");
            let imported = import_report_file(&bundle_path, &output).expect("import should work");
            assert_eq!(imported, kind);

            let output_body = fs::read_to_string(&output).expect("output should read");
            let parse_result = match kind {
                ReportBundleKind::Assail => {
                    serde_json::from_str::<AssailReport>(&output_body).map(|_| ())
                }
                ReportBundleKind::Attack => {
                    serde_json::from_str::<Vec<AttackResult>>(&output_body).map(|_| ())
                }
                ReportBundleKind::Assault | ReportBundleKind::Ambush => {
                    serde_json::from_str::<AssaultReport>(&output_body).map(|_| ())
                }
                ReportBundleKind::Amuck => {
                    serde_json::from_str::<amuck::AmuckReport>(&output_body).map(|_| ())
                }
                ReportBundleKind::Abduct => {
                    serde_json::from_str::<abduct::AbductReport>(&output_body).map(|_| ())
                }
                ReportBundleKind::Adjudicate => {
                    serde_json::from_str::<adjudicate::AdjudicateReport>(&output_body).map(|_| ())
                }
                ReportBundleKind::Axial => {
                    serde_json::from_str::<axial::AxialReport>(&output_body).map(|_| ())
                }
            };
            assert!(
                parse_result.is_ok(),
                "imported json should parse for kind {}",
                kind.as_str()
            );
        }
    }
}

// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Structured configuration analysis. Parsing and checks must both finish before
//! an input can be acknowledged as analysed. These are local configuration
//! checks, not application-schema, deployment, or dataflow proofs.

use super::input_adapters::Analysis;
use crate::types::{AttackAxis, Severity, WeakPoint, WeakPointCategory};
use anyhow::{anyhow, Context, Result};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::fmt;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Format {
    Json,
    Yaml,
    Toml,
}

impl Format {
    /// The same registry is used by discovery and execution. Recognising a
    /// candidate does not acknowledge its bytes: only successful analysis does.
    pub(super) fn detect(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "yaml" | "yml" => Some(Self::Yaml),
            "toml" => Some(Self::Toml),
            _ => None,
        }
    }

    pub(super) fn description(self) -> &'static str {
        match self {
            Self::Json => "JSON parser and recursive configuration security checks; package.json scripts receive POSIX-style shell heuristics; duplicate keys rejected; no platform-shell, application-schema or dataflow proof",
            Self::Yaml => "YAML budgeted parser, recursive configuration security checks and recognized Actions run-step interpreter heuristics; duplicate keys rejected; no expression expansion, application-schema or dataflow proof",
            Self::Toml => "TOML parser and recursive configuration security checks; duplicate keys rejected; no application-schema or dataflow proof",
        }
    }

    /// Return configuration findings, discarding any extracted scripts.
    ///
    /// # Errors
    /// Propagates parsing, conversion and script-extraction errors from
    /// [`Self::analyze_input`].
    pub(super) fn analyze(self, content: &str, file: &str) -> Result<Vec<WeakPoint>> {
        Ok(self.analyze_input(content, file)?.findings)
    }

    /// Parse configuration, check each document and extract recognised scripts.
    /// `file` identifies findings and selects package.json script extraction.
    /// Duplicate mapping keys are rejected; YAML may contain multiple documents.
    ///
    /// # Errors
    /// Returns parsing or value-conversion errors, including duplicate keys and
    /// non-finite numbers, and propagates script-extraction errors.
    pub(super) fn analyze_input(self, content: &str, file: &str) -> Result<Analysis> {
        let documents: Vec<Value> = match self {
            Self::Json => vec![
                serde_json::from_str::<UniqueValue>(content)
                    .context("JSON configuration parse failed")?
                    .0,
            ],
            Self::Yaml => {
                // Keep the parser's default depth, expansion and alias budgets.
                // The custom visitor also prevents duplicate keys being hidden
                // when normalising a mapping to serde_json::Value.
                let documents: Vec<UniqueValue> = serde_saphyr::from_str_multiple(content)
                    .context("YAML configuration parse failed")?;
                documents.into_iter().map(|document| document.0).collect()
            }
            Self::Toml => {
                let document: toml_edit::DocumentMut =
                    content.parse().context("TOML configuration parse failed")?;
                vec![table_value(document.as_table())?]
            }
        };

        let mut analysis = Analysis::default();
        for (index, document) in documents.iter().enumerate() {
            let field = format!("document[{index}]");
            inspect_value(document, &field, file, &mut analysis.findings);
            super::configuration_scripts::extract(
                self,
                document,
                &field,
                file,
                &mut analysis.scripts,
            )?;
        }
        Ok(analysis)
    }
}

/// `serde_json::Value` silently overwrites duplicate object keys. A contradictory
/// first value must not disappear before security checks run, including nested
/// objects and objects inside arrays.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("configuration with unique string mapping keys")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                self.visit_unit()
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(Value::Number)
                    .map(UniqueValue)
                    .ok_or_else(|| E::custom("non-finite configuration number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value.into())))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value)))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate configuration mapping key"));
                    }
                    values.insert(key, map.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn table_value(table: &toml_edit::Table) -> Result<Value> {
    table
        .iter()
        .map(|(key, value)| Ok((key.to_owned(), item_value(value)?)))
        .collect::<Result<Map<String, Value>>>()
        .map(Value::Object)
}

fn item_value(item: &toml_edit::Item) -> Result<Value> {
    match item {
        toml_edit::Item::None => Ok(Value::Null),
        toml_edit::Item::Value(value) => toml_value(value),
        toml_edit::Item::Table(table) => table_value(table),
        toml_edit::Item::ArrayOfTables(tables) => tables
            .iter()
            .map(table_value)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
    }
}

fn toml_value(value: &toml_edit::Value) -> Result<Value> {
    match value {
        toml_edit::Value::String(value) => Ok(Value::String(value.value().clone())),
        toml_edit::Value::Integer(value) => Ok(Value::Number((*value.value()).into())),
        toml_edit::Value::Float(value) => Number::from_f64(*value.value())
            .map(Value::Number)
            .ok_or_else(|| anyhow!("non-finite configuration number")),
        toml_edit::Value::Boolean(value) => Ok(Value::Bool(*value.value())),
        toml_edit::Value::Datetime(value) => Ok(Value::String(value.value().to_string())),
        toml_edit::Value::Array(values) => values
            .iter()
            .map(toml_value)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        toml_edit::Value::InlineTable(table) => table
            .iter()
            .map(|(key, value)| Ok((key.to_owned(), toml_value(value)?)))
            .collect::<Result<Map<String, Value>>>()
            .map(Value::Object),
    }
}

fn finding(
    file: &str,
    field: &str,
    category: WeakPointCategory,
    severity: Severity,
    reason: &str,
) -> WeakPoint {
    WeakPoint {
        file: Some(file.into()),
        line: None,
        category,
        location: Some(file.into()),
        severity,
        description: format!("CONFIG: {reason} at {field} in {file}"),
        recommended_attack: vec![AttackAxis::Network],
        suppressed: false,
        test_context: None,
    }
}

fn key_name(key: &str) -> String {
    key.chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_reference(value: &str) -> bool {
    let value = value.trim();
    (value.starts_with("${") && value.ends_with('}'))
        || (value.starts_with("{{") && value.ends_with("}}"))
}

/// Flag named credential fields with values of at least eight bytes, except
/// values enclosed in `${...}` or `{{...}}` after trimming. Key matching ignores
/// case, underscores and hyphens. The value is absent from the diagnostic.
/// Reused only for actual parsed/declarative literal fields, not comment text.
pub(super) fn literal_credential(
    file: &str,
    field: &str,
    key: &str,
    value: &str,
) -> Option<WeakPoint> {
    let name = key_name(key);
    if matches!(
        name.as_str(),
        "password" | "passwd" | "apikey" | "apisecret" | "secretkey" | "accesstoken" | "privatekey"
    ) && value.len() >= 8
        && !is_reference(value)
    {
        Some(finding(
            file,
            field,
            WeakPointCategory::HardcodedSecret,
            Severity::Critical,
            "literal credential in a named field",
        ))
    } else {
        None
    }
}

fn inspect_value(value: &Value, field: &str, file: &str, findings: &mut Vec<WeakPoint>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let child = format!("{field}/{}", key.replace('~', "~0").replace('/', "~1"));
                let normal = key_name(key);
                if let Some(finding) = value
                    .as_str()
                    .and_then(|secret| literal_credential(file, &child, key, secret))
                {
                    findings.push(finding);
                }
                if matches!(
                    normal.as_str(),
                    "verifyssl"
                        | "sslverify"
                        | "verifytls"
                        | "tlsverify"
                        | "verifycertificates"
                        | "rejectunauthorized"
                ) && value == &Value::Bool(false)
                    || matches!(
                        normal.as_str(),
                        "insecureskipverify" | "trustallcertificates"
                    ) && value == &Value::Bool(true)
                {
                    findings.push(finding(
                        file,
                        &child,
                        WeakPointCategory::InsecureProtocol,
                        Severity::High,
                        "certificate verification is disabled",
                    ));
                }
                if matches!(normal.as_str(), "privileged" | "allowprivilegeescalation")
                    && value == &Value::Bool(true)
                {
                    findings.push(finding(
                        file,
                        &child,
                        WeakPointCategory::ExcessivePermissions,
                        Severity::High,
                        "privileged execution is enabled",
                    ));
                }
                // JSON Schema/JSON-LD identifiers are names, not configured
                // network endpoints. All other nested scalars remain checked.
                if !(value.is_string()
                    && matches!(
                        key.as_str(),
                        "$schema"
                            | "$id"
                            | "$ref"
                            | "@id"
                            | "@type"
                            | "@context"
                            | "@vocab"
                            | "xmlns"
                    ))
                {
                    inspect_value(value, &child, file, findings);
                }
            }
            let immutable_rev = map.get("rev").and_then(Value::as_str).is_some_and(|rev| {
                rev.len() == 40 && rev.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
            if file.ends_with("Cargo.toml") && map.contains_key("git") && !immutable_rev {
                findings.push(finding(
                    file,
                    field,
                    WeakPointCategory::SupplyChain,
                    Severity::High,
                    "git dependency has no immutable revision",
                ));
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                inspect_value(value, &format!("{field}/{index}"), file, findings);
            }
        }
        Value::String(text)
            if text
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://")) =>
        {
            let rest = &text[7..];
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            let authority = authority.to_ascii_lowercase();
            let loopback = matches!(
                authority.split(':').next(),
                Some("localhost" | "127.0.0.1" | "0.0.0.0")
            ) || authority == "[::1]"
                || authority.starts_with("[::1]:");
            if !loopback {
                findings.push(finding(
                    file,
                    field,
                    WeakPointCategory::InsecureProtocol,
                    Severity::Medium,
                    "plaintext HTTP endpoint",
                ));
            }
        }
        _ => {}
    }
}

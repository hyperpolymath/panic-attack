// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Data-driven rule loader for the miniKanren engine

use crate::kanren::core::{LogicEngine, LogicFact, LogicRule, RuleMetadata, Term};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Upper bound on rule-catalog reads. The miniKanren catalog is a
/// curated JSON document; 4 MiB is far beyond any realistic catalog
/// and bounds tampered or malformed input.
const RULE_CATALOG_READ_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct RuleSpec {
    pub name: String,
    pub head: TermSpec,
    pub body: Vec<TermSpec>,
    pub metadata: RuleMetadata,
}

#[derive(Debug, Deserialize)]
pub struct TermSpec {
    pub functor: String,
    pub args: Vec<TermArg>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TermArg {
    Atom { value: String },
    Var { id: u32 },
    Int { value: i64 },
}

impl RuleSpec {
    pub fn to_logic_rule(&self) -> LogicRule {
        // Rule specs are declarative payloads; conversion binds them to engine types.
        let head_fact = LogicFact::new(&self.head.functor, self.head.to_terms());
        let body = self
            .body
            .iter()
            .map(|term| LogicFact::new(&term.functor, term.to_terms()))
            .collect();

        LogicRule::with_metadata(
            self.name.clone(),
            head_fact,
            body,
            self.metadata.clone(),
        )
    }
}

impl TermSpec {
    fn to_terms(&self) -> Vec<Term> {
        self.args.iter().map(|arg| arg.to_term()).collect()
    }
}

impl TermArg {
    fn to_term(&self) -> Term {
        match self {
            TermArg::Atom { value } => Term::atom(value),
            TermArg::Var { id } => Term::Var(*id),
            TermArg::Int { value } => Term::Int(*value),
        }
    }
}

pub struct RuleCatalog {
    pub rules: Vec<LogicRule>,
}

impl RuleCatalog {
    pub fn load_default() -> Self {
        let path = Path::new("rules/a2ml_rules.json");
        if path.exists() {
            match Self::from_file(path) {
                Ok(catalog) => catalog,
                Err(err) => {
                    log::warn!("failed to load rule catalog: {}", err);
                    Self::new()
                }
            }
        } else {
            Self::new()
        }
    }

    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let data = {
            let mut buf = String::new();
            File::open(path)
                .context("opening rule catalog")?
                .take(RULE_CATALOG_READ_LIMIT)
                .read_to_string(&mut buf)
                .context("reading rule catalog")?;
            buf
        };
        let specs: Vec<RuleSpec> = serde_json::from_str(&data).context("parsing rule catalog")?;
        Ok(Self {
            rules: specs.into_iter().map(|spec| spec.to_logic_rule()).collect(),
        })
    }

    pub fn export_nickel(&self) -> String {
        // Nickel export provides lightweight introspection for rule packs in tooling/CI.
        let entries: Vec<String> = self
            .rules
            .iter()
            .map(|rule| {
                let tags = rule
                    .metadata
                    .tags
                    .iter()
                    .map(|tag| format!(r#""{}""#, tag))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "{{ name = \"{}\", confidence = {:.2}, priority = {}, tags = [{}], risk = \"{}\" }}",
                    rule.name,
                    rule.metadata.confidence,
                    rule.metadata.priority,
                    tags,
                    rule.metadata
                        .risk_tier
                        .as_ref()
                        .map(|tier| tier.as_str())
                        .unwrap_or("default")
                )
            })
            .collect();
        format!("let rules = [\n    {}\n]\n", entries.join(",\n    "))
    }

    pub fn apply_to_engine(&self, engine: &mut LogicEngine) {
        // Rules are cloned intentionally to keep catalog reusable across engine instances.
        for rule in &self.rules {
            engine.db.add_rule(rule.clone());
        }
    }
}

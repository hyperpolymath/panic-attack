// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! YAML (de)serialization, backed by `serde-saphyr` (pure safe Rust).
//!
//! `serde-saphyr` enforces resource budgets while parsing. Its defaults
//! suit hand-written configs (attack profiles, timelines, mutation specs),
//! but its 250k-node cap rejects YAML reports from large scans (roughly
//! 15k files). Machine-written reports therefore get a node and event
//! budget proportional to the input length instead: an alias-free document
//! cannot have more nodes than bytes, so the cap still bounds alias
//! expansion while accepting any report the caller's read limit allows.

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_saphyr::budget::Budget;
use serde_saphyr::options::Options;

/// Parse a hand-written YAML config with the default resource budget.
pub fn from_str<T: DeserializeOwned>(input: &str) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str(input)
}

/// Parse a machine-written YAML report with a budget scaled to its length.
pub fn from_report_str<T: DeserializeOwned>(input: &str) -> Result<T, serde_saphyr::Error> {
    let defaults = Budget::default();
    let mut budget = Budget::default();
    budget.max_nodes = defaults.max_nodes.max(input.len());
    budget.max_events = defaults.max_events.max(input.len());
    let mut options = Options::default();
    options.budget = Some(budget);
    serde_saphyr::from_str_with_options(input, options)
}

/// Serialize a value to a YAML document.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, serde_saphyr::ser::Error> {
    serde_saphyr::to_string(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_budget_accepts_documents_past_the_default_node_cap() {
        let items: Vec<u8> = vec![0; 300_000];
        let doc = to_string(&items).expect("serialize");
        assert!(from_str::<Vec<u8>>(&doc).is_err());
        assert_eq!(from_report_str::<Vec<u8>>(&doc).expect("parse"), items);
    }

    #[test]
    fn report_budget_still_rejects_alias_expansion() {
        let mut doc = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..10 {
            let p = i - 1;
            doc.push_str(&format!(
                "a{i}: &a{i} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]\n"
            ));
        }
        assert!(from_report_str::<serde_json::Value>(&doc).is_err());
    }

    #[test]
    fn kyaml_configs_parse() {
        // Shape emitted by `yq -o kyaml` (flow style, double quotes,
        // trailing commas), the estate's YAML policy format.
        let spec = "{\n  combos: [\n    {\n      name: \"c1\",\n      operations: [\n        {\n          op: \"duplicate_lines_containing\",\n          needle: \"x\",\n          times: 3,\n        },\n      ],\n    },\n  ],\n}\n";
        let parsed: crate::amuck::MutationSpecFile = from_str(spec).expect("kyaml spec");
        assert_eq!(parsed.combos[0].name.as_deref(), Some("c1"));
        assert_eq!(parsed.combos[0].operations.len(), 1);

        let profile = "{\n  common_args: [\n    \"--config\",\n    \"cfg.toml\",\n  ],\n  probe_mode: \"always\",\n}\n";
        let parsed: crate::attack::profile::AttackProfile =
            from_str(profile).expect("kyaml profile");
        assert_eq!(parsed.common_args, ["--config", "cfg.toml"]);
    }

    #[test]
    fn reports_written_by_serde_yaml_still_load() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("reports");
        for name in [
            "panic-attack-20260209184444.yaml",
            "panic-attack-20260211180017.yaml",
        ] {
            let raw = std::fs::read_to_string(dir.join(name)).expect("read fixture");
            let report: crate::types::AssaultReport = from_report_str(&raw).expect(name);
            let again: crate::types::AssaultReport =
                from_report_str(&to_string(&report).expect("serialize")).expect("reparse");
            assert_eq!(
                serde_json::to_value(&report).expect("json"),
                serde_json::to_value(&again).expect("json")
            );
        }
    }
}

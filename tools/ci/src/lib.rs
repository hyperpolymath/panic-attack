// SPDX-License-Identifier: MPL-2.0
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Debug)]
pub struct ToolError {
    pub code: i32,
    pub message: String,
}
pub type Result<T> = std::result::Result<T, ToolError>;
pub fn input(message: impl Into<String>) -> ToolError {
    ToolError {
        code: 2,
        message: message.into(),
    }
}
pub fn claim(message: impl Into<String>) -> ToolError {
    ToolError {
        code: 1,
        message: message.into(),
    }
}
impl From<std::io::Error> for ToolError {
    fn from(e: std::io::Error) -> Self {
        input(e.to_string())
    }
}
impl From<serde_json::Error> for ToolError {
    fn from(e: serde_json::Error) -> Self {
        input(e.to_string())
    }
}

#[derive(Deserialize)]
struct Cell {
    category: String,
    aspect: String,
    #[serde(default)]
    bins: Vec<String>,
    #[serde(default, alias = "match")]
    pattern: Option<String>,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    proof_file: Option<String>,
}
#[derive(Default, Deserialize)]
struct Taxonomy {
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    aspects: Vec<String>,
}
#[derive(Deserialize)]
struct Unmapped {
    r#match: String,
}
#[derive(Deserialize)]
struct Absent {
    category: String,
    aspect: String,
}
#[derive(Deserialize)]
struct Ledger {
    #[serde(default)]
    suite: Option<String>,
    #[serde(default)]
    entries: Vec<Cell>,
    #[serde(default)]
    buckets: Vec<Cell>,
    #[serde(default)]
    declared_absent: Vec<Absent>,
    #[serde(default)]
    declared_unmapped: Vec<Unmapped>,
    #[serde(default)]
    max_unmapped: Option<usize>,
    #[serde(default)]
    taxonomy: Taxonomy,
}
fn regex(pattern: Option<&str>) -> Result<Option<Regex>> {
    pattern
        .map(Regex::new)
        .transpose()
        .map_err(|e| input(format!("invalid selection regex: {e}")))
}

type Inventory = BTreeMap<String, BTreeSet<String>>;
type Assignments<'a> = BTreeMap<(String, String), (&'a Cell, bool)>;
type Coordinates = BTreeSet<(String, String)>;

fn parse_inventory(inventory: &Value) -> Result<Inventory> {
    let inventory: BTreeMap<String, BTreeSet<String>> = serde_json::from_value(inventory.clone())?;
    if inventory
        .iter()
        .any(|(binary, names)| binary.is_empty() || names.contains(""))
    {
        return Err(input("inventory binary and test names must be nonempty"));
    }
    if inventory.values().map(BTreeSet::len).sum::<usize>() == 0 {
        return Err(input("inventory contains no executed tests"));
    }
    Ok(inventory)
}

fn check_taxonomy(ledger: &Ledger) -> Result<()> {
    for cell in ledger.entries.iter().chain(&ledger.buckets) {
        if !ledger.taxonomy.categories.contains(&cell.category)
            || !ledger.taxonomy.aspects.contains(&cell.aspect)
        {
            return Err(input("a ledger cell is outside the declared taxonomy"));
        }
    }
    Ok(())
}

fn assign_entries<'a>(ledger: &'a Ledger, inventory: &Inventory) -> Result<Assignments<'a>> {
    let mut assignments = BTreeMap::<(String, String), (&Cell, bool)>::new();
    for cell in &ledger.entries {
        let pattern = regex(cell.pattern.as_deref())?;
        let mut matched = 0;
        for (binary, names) in inventory {
            if !cell.bins.contains(binary) {
                continue;
            }
            for name in names {
                if pattern.as_ref().is_some_and(|p| !p.is_match(name)) {
                    continue;
                }
                matched += 1;
                assignments
                    .entry((binary.clone(), name.clone()))
                    .or_insert((cell, false));
            }
        }
        if matched == 0 {
            return Err(claim(format!(
                "ledger cell {} x {} selects no inventory test",
                cell.category, cell.aspect
            )));
        }
    }
    Ok(assignments)
}

fn assign_buckets<'a>(
    ledger: &'a Ledger,
    inventory: &Inventory,
    assignments: &mut Assignments<'a>,
) -> Result<()> {
    let buckets: Vec<_> = ledger
        .buckets
        .iter()
        .map(|b| Ok((regex(b.pattern.as_deref())?, b)))
        .collect::<Result<_>>()?;
    let unmapped: Vec<_> = ledger
        .declared_unmapped
        .iter()
        .map(|d| Regex::new(&d.r#match).map_err(|e| input(e.to_string())))
        .collect::<Result<_>>()?;
    let mut remainder = 0;
    for (binary, names) in inventory {
        for name in names {
            let key = (binary.clone(), name.clone());
            if assignments.contains_key(&key) {
                continue;
            }
            if let Some((index, (_, cell))) = buckets.iter().enumerate().find(|(_, (p, b))| {
                (b.bins.is_empty() || b.bins.contains(binary))
                    && p.as_ref().is_none_or(|p| p.is_match(name))
            }) {
                assignments.insert(key, (cell, true));
                if index + 1 == buckets.len() {
                    remainder += 1;
                }
            } else if !unmapped.iter().any(|p| p.is_match(name)) {
                return Err(claim(format!(
                    "executed test {binary}::{name} has no coordinate or declared-unmapped rule"
                )));
            }
        }
    }
    if ledger.max_unmapped.is_some_and(|cap| remainder > cap) {
        return Err(claim(format!(
            "{remainder} tests exceed the declared remainder ratchet"
        )));
    }
    Ok(())
}

fn grade(
    assignments: Assignments<'_>,
    root: &Path,
) -> Result<([usize; 3], Coordinates, Vec<Value>)> {
    let mut tiers = [0usize; 3];
    let mut cells = BTreeSet::new();
    let mut entries = Vec::new();
    for ((binary, name), (cell, bucket)) in assignments {
        let tier = match cell.tier.as_deref() {
            Some(t) => t,
            None if bucket => "Provisionally-Proven",
            None => return Err(input("explicit ledger entry has no tier")),
        };
        let index = match tier {
            "Actually-Proven" => 0,
            "Provisionally-Proven" => 1,
            "Unproven" => 2,
            _ => return Err(claim(format!("unknown proof tier: {tier}"))),
        };
        if tier == "Actually-Proven" {
            let proof = cell
                .proof_file
                .as_ref()
                .ok_or_else(|| claim("Actually-Proven requires a proof_file"))?;
            if !root.join(proof).is_file() {
                return Err(claim(format!("cited proof_file does not exist: {proof}")));
            }
        } else if cell.proof_file.is_some() {
            return Err(claim("a weaker tier cannot borrow a proof_file"));
        }
        tiers[index] += 1;
        cells.insert((cell.category.clone(), cell.aspect.clone()));
        entries.push(json!({"test_id":format!("{binary}::{name}"), "category":cell.category, "aspect":cell.aspect, "provenance":tier, "proof_ladder":[], "result":"passed"}));
    }
    Ok((tiers, cells, entries))
}

fn check_absent(ledger: &Ledger, cells: &Coordinates) -> Result<()> {
    for absent in &ledger.declared_absent {
        if cells.contains(&(absent.category.clone(), absent.aspect.clone())) {
            return Err(claim("a coordinate is both declared absent and covered"));
        }
    }
    Ok(())
}

pub fn derive_report(inventory: &Value, ledger: &Value, root: &Path) -> Result<Value> {
    let inventory = parse_inventory(inventory)?;
    let ledger: Ledger = serde_json::from_value(ledger.clone())?;
    check_taxonomy(&ledger)?;
    let mut assignments = assign_entries(&ledger, &inventory)?;
    assign_buckets(&ledger, &inventory, &mut assignments)?;
    let (tiers, cells, entries) = grade(assignments, root)?;
    check_absent(&ledger, &cells)?;
    Ok(
        json!({"schema_version":1, "suite":ledger.suite.as_deref().unwrap_or("unknown"),
        "summary":{"passed":entries.len(), "total":entries.len(), "actually_proven":tiers[0], "provisionally_proven":tiers[1], "unproven":tiers[2], "covered_cells":cells.len(), "cat_aspect_cells":ledger.taxonomy.categories.len()*ledger.taxonomy.aspects.len(), "lattice_covered":cells.len()}, "entries":entries}),
    )
}

pub fn finding_counts(data: &Value, wanted: &[&str]) -> Result<BTreeMap<String, u64>> {
    fn walk(
        data: &Value,
        wanted: &[&str],
        counts: &mut BTreeMap<String, u64>,
        found: &mut bool,
    ) -> Result<()> {
        match data {
            Value::Object(object) => {
                for (key, value) in object {
                    if let Some(array) = value.as_array().filter(|_| wanted.contains(&key.as_str()))
                    {
                        *found = true;
                        for entry in array {
                            let entry = entry
                                .as_object()
                                .ok_or_else(|| input("a finding must be an object"))?;
                            let label = [
                                "category", "rule_id", "ruleId", "rule", "id", "code", "check",
                            ]
                            .iter()
                            .find_map(|key| entry.get(*key).and_then(Value::as_str))
                            .unwrap_or("unknown");
                            *counts.entry(label.into()).or_default() += 1;
                        }
                    }
                    walk(value, wanted, counts, found)?;
                }
            }
            Value::Array(array) => {
                for entry in array {
                    walk(entry, wanted, counts, found)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    let mut counts = BTreeMap::new();
    let mut found = false;
    walk(data, wanted, &mut counts, &mut found)?;
    if !found {
        return Err(input(
            "no recognized findings array; report is unavailable, not clean",
        ));
    }
    Ok(counts)
}

pub fn regression_count(
    observed: &BTreeMap<String, u64>,
    baseline: &BTreeMap<String, u64>,
) -> usize {
    observed
        .iter()
        .filter(|(category, count)| {
            baseline
                .get(*category)
                .map_or(!baseline.is_empty(), |old| *count > old)
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ledger() -> Value {
        json!({"suite":"controls", "entries":[{"category":"Security","aspect":"Unit","tier":"Provisionally-Proven","bins":["a","b"]}],"taxonomy":{"categories":["Security"],"aspects":["Unit"]}})
    }
    #[test]
    fn empty_inventory_and_stale_claims_fail() {
        assert!(derive_report(&json!({}), &ledger(), Path::new(".")).is_err());
        assert!(derive_report(&json!({"a":[]}), &ledger(), Path::new(".")).is_err());
        assert!(derive_report(&json!({"other":["test"]}), &ledger(), Path::new(".")).is_err());
    }
    #[test]
    fn binaries_do_not_collapse_identical_names() -> Result<()> {
        let report = derive_report(
            &json!({"a":["same","same"],"b":["same"]}),
            &ledger(),
            Path::new("."),
        )?;
        assert_eq!(report["summary"]["total"], 2);
        assert_ne!(
            report["entries"][0]["test_id"],
            report["entries"][1]["test_id"]
        );
        Ok(())
    }
    #[test]
    fn absent_conflicts_and_unsupported_proofs_fail() {
        let inventory = json!({"a":["test"]});
        let mut data = ledger();
        data["entries"][0]["tier"] = json!("Actually-Proven");
        assert!(derive_report(&inventory, &data, Path::new(".")).is_err());
        data["entries"][0]["tier"] = json!("Provisionally-Proven");
        data["declared_absent"] = json!([{"category":"Security","aspect":"Unit"}]);
        assert!(derive_report(&inventory, &data, Path::new(".")).is_err());
    }
    #[test]
    fn unaccounted_tests_and_remainder_ratchet_fail() {
        let mut data = ledger();
        data["entries"] = json!([]);
        assert!(derive_report(&json!({"a":["test"]}), &data, Path::new(".")).is_err());
        data["buckets"] = json!([{"category":"Security","aspect":"Unit"}]);
        data["max_unmapped"] = json!(0);
        assert!(derive_report(&json!({"a":["test"]}), &data, Path::new(".")).is_err());
    }
    #[test]
    fn missing_shapes_are_not_empty_findings() -> Result<()> {
        assert!(finding_counts(&json!({"status":"failed"}), &["findings"]).is_err());
        assert!(finding_counts(&json!({"findings":[1]}), &["findings"]).is_err());
        assert!(finding_counts(&json!({"findings":[]}), &["findings"])?.is_empty());
        Ok(())
    }
    #[test]
    fn nested_sarif_and_debt_ratchet_are_preserved() -> Result<()> {
        let observed = finding_counts(
            &json!({"runs":[{"results":[{"ruleId":"A"},{"ruleId":"A"}]}]}),
            &["results"],
        )?;
        assert_eq!(observed["A"], 2);
        assert_eq!(
            regression_count(&observed, &BTreeMap::from([("A".into(), 1)])),
            1
        );
        assert_eq!(
            regression_count(&observed, &BTreeMap::from([("A".into(), 3)])),
            0
        );
        Ok(())
    }
}

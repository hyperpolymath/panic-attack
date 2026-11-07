// SPDX-License-Identifier: MPL-2.0
use serde_json::{json, Value};
use std::{
    error::Error,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
type Result<T> = std::result::Result<T, Box<dyn Error>>;
struct Temp {
    base: PathBuf,
    root: PathBuf,
}
impl Temp {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir().canonicalize()?;
        let root = base.join(format!(
            "panic-ci-contract-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        Ok(Self { base, root })
    }
    fn write(&self, name: &str, data: &Value) -> Result<PathBuf> {
        let path = self.root.join(name);
        fs::write(&path, serde_json::to_vec(data)?)?;
        Ok(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        if self.root != self.base && self.root.starts_with(&self.base) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[test]
fn ledger_cli_does_not_write_empty_or_stale_claims() -> Result<()> {
    let temp = Temp::new()?;
    let inventory = temp.write("inventory.json", &json!({"lib":["control"]}))?;
    let ledger = temp.write("ledger.json", &json!({"entries":[{"category":"Security","aspect":"Unit","tier":"Provisionally-Proven","bins":["lib"]}],"taxonomy":{"categories":["Security"],"aspects":["Unit"]}}))?;
    let out = temp.root.join("report.json");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_verify-ledger"))
            .current_dir(&temp.root)
            .arg("--inventory")
            .arg(&inventory)
            .arg("--ledger")
            .arg(&ledger)
            .arg("--out")
            .arg(&out)
            .output()
    };
    assert!(run()?.status.success());
    let before = fs::read(&out)?;
    let report: Value = serde_json::from_slice(&before)?;
    assert_eq!(report["summary"]["total"], 1);
    temp.write("inventory.json", &json!({"other":["control"]}))?;
    assert_eq!(run()?.status.code(), Some(1));
    assert_eq!(
        before,
        fs::read(&out)?,
        "a failed claim overwrote the successful artifact"
    );
    temp.write("inventory.json", &json!({"lib":[]}))?;
    assert_eq!(run()?.status.code(), Some(2));
    assert_eq!(before, fs::read(&out)?);
    Ok(())
}

#[test]
fn recon_cli_distinguishes_regressions_and_unavailable_reports() -> Result<()> {
    let temp = Temp::new()?;
    let assail = temp.write(
        "assail.json",
        &json!({"weak_points":[{"category":"A"},{"category":"A"}]}),
    )?;
    let pons = temp.write("pons.json", &json!({"findings":[]}))?;
    let baseline = temp.write(
        "baseline.json",
        &json!({"_comment":["metadata is not a scanner"],"assail":{"A":1},"pons":{}}),
    )?;
    let run = |advisory: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_recon-compare"));
        command
            .current_dir(&temp.root)
            .arg("--assail")
            .arg(&assail)
            .arg("--pons")
            .arg(&pons)
            .arg("--baseline")
            .arg(&baseline);
        if advisory {
            command.arg("--no-fail");
        }
        command.output()
    };
    assert_eq!(run(false)?.status.code(), Some(1));
    temp.write("assail.json", &json!({"weak_points":[{"category":"A"}]}))?;
    assert!(run(false)?.status.success());
    fs::remove_file(&pons)?;
    let missing = run(false)?;
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stdout).contains("Baseline proposal withheld"));
    assert!(run(true)?.status.success());
    Ok(())
}

#[test]
fn repository_ledger_taxonomy_and_selectors_are_readable() -> Result<()> {
    let ledger: Value = serde_json::from_str(include_str!("../../../proven/ledger.json"))?;
    for cell in ledger["entries"]
        .as_array()
        .ok_or("missing entries")?
        .iter()
        .chain(ledger["buckets"].as_array().ok_or("missing buckets")?)
    {
        let category = cell["category"].as_str().ok_or("missing category")?;
        let aspect = cell["aspect"].as_str().ok_or("missing aspect")?;
        assert!(ledger["taxonomy"]["categories"]
            .as_array()
            .ok_or("missing categories")?
            .contains(&json!(category)));
        assert!(ledger["taxonomy"]["aspects"]
            .as_array()
            .ok_or("missing aspects")?
            .contains(&json!(aspect)));
        for key in ["pattern", "match"] {
            if let Some(pattern) = cell[key].as_str() {
                regex::Regex::new(pattern)?;
            }
        }
    }
    Ok(())
}

#[test]
fn recon_cli_accepts_the_actual_repository_baseline() -> Result<()> {
    let temp = Temp::new()?;
    let assail = temp.write("assail.json", &json!({"weak_points":[]}))?;
    let pons = temp.write("pons.json", &json!({"findings":[]}))?;
    let baseline: Value = serde_json::from_str(include_str!("../../../recon/baseline.json"))?;
    let baseline = temp.write("baseline.json", &baseline)?;
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_recon-compare"))
            .args([
                "--baseline",
                baseline.to_str().unwrap(),
                "--assail",
                assail.to_str().unwrap(),
                "--pons",
                pons.to_str().unwrap(),
            ])
            .output()
    };
    assert!(run()?.status.success());
    temp.write(
        "baseline.json",
        &json!({"_comment":[], "assail":{"A":"invalid"},"pons":{}}),
    )?;
    assert_eq!(run()?.status.code(), Some(2));
    Ok(())
}

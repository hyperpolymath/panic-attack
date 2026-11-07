// SPDX-License-Identifier: MPL-2.0
use clap::Parser;
use panic_ci_tools::{finding_counts, input, regression_count, Result};
use serde_json::Value;
use std::{collections::BTreeMap, fs, io::Write, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "recon/baseline.json")]
    baseline: PathBuf,
    #[arg(long)]
    assail: PathBuf,
    #[arg(long)]
    pons: PathBuf,
    #[arg(long)]
    summary: Option<PathBuf>,
    #[arg(long)]
    no_fail: bool,
}
fn run() -> Result<()> {
    let args = Args::parse();
    let baseline: BTreeMap<String, BTreeMap<String, u64>> = if args.baseline.exists() {
        serde_json::from_slice(&fs::read(&args.baseline)?)?
    } else {
        BTreeMap::new()
    };
    let mut text = String::from("## Recon: two independent scans\n\n");
    let mut observed = BTreeMap::new();
    let mut regressions = 0;
    let mut unavailable = 0;
    for (name, path, wanted) in [
        ("assail", &args.assail, &["weak_points"][..]),
        ("pons", &args.pons, &["findings", "results"][..]),
    ] {
        text.push_str(&format!("### {name}\n\n"));
        let counts = fs::read(path)
            .map_err(panic_ci_tools::ToolError::from)
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).map_err(Into::into))
            .and_then(|data| finding_counts(&data, wanted));
        let counts = match counts {
            Ok(c) => c,
            Err(error) => {
                unavailable += 1;
                text.push_str(&format!(
                    "- unavailable, not counted as clean: {}\n\n",
                    error.message
                ));
                continue;
            }
        };
        let frozen = baseline.get(name).cloned().unwrap_or_default();
        regressions += regression_count(&counts, &frozen);
        text.push_str("| category | observed | baseline | verdict |\n|---|---|---|---|\n");
        for (category, count) in &counts {
            let old = frozen.get(category);
            let verdict = match old {
                Some(n) if count > n => format!("**+{} (fails)**", count - n),
                Some(n) if count < n => format!("−{} (debt paid; tighten baseline)", n - count),
                Some(_) => "at baseline".into(),
                None if frozen.is_empty() => "new (baseline empty)".into(),
                None => "**NEW (fails)**".into(),
            };
            text.push_str(&format!(
                "| {} | {count} | {} | {verdict} |\n",
                category.replace('|', "\\|").replace(['\r', '\n'], " "),
                old.map_or("—".into(), u64::to_string)
            ));
        }
        if counts.is_empty() {
            text.push_str("- no findings counted\n");
        }
        let missing: Vec<_> = frozen
            .keys()
            .filter(|k| !counts.contains_key(*k))
            .cloned()
            .collect();
        if !missing.is_empty() {
            text.push_str(&format!(
                "\n- baseline categories no longer reported: {}\n",
                missing.join(", ")
            ));
        }
        text.push('\n');
        observed.insert(name, counts);
    }
    if unavailable == 0 {
        text.push_str(&format!(
            "### Freeze or tighten the baseline\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&observed)?
        ));
    } else {
        text.push_str("Baseline proposal withheld: one or more scanner reports are unavailable.\n");
    }
    print!("{text}");
    if let Some(path) = args.summary {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
            .write_all(text.as_bytes())?;
    }
    if args.no_fail {
        eprintln!(
            "recon: --no-fail, reporting only; availability and regressions remain in the report"
        );
        return Ok(());
    }
    if unavailable > 0 {
        return Err(input(format!(
            "{unavailable} scanner report(s) unavailable"
        )));
    }
    if regressions > 0 {
        return Err(panic_ci_tools::claim(format!(
            "{regressions} category regression(s) against {}",
            args.baseline.display()
        )));
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("::error::{}", error.message);
        std::process::exit(error.code);
    }
}

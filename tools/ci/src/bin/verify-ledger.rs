// SPDX-License-Identifier: MPL-2.0
use clap::Parser;
use panic_ci_tools::{derive_report, Result};
use std::{fs, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    inventory: PathBuf,
    #[arg(long, default_value = "proven/ledger.json")]
    ledger: PathBuf,
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long, default_value = "proven-report.json")]
    out: PathBuf,
    /// Compatibility flag; declared absence remains informational unless it conflicts with coverage.
    #[arg(long)]
    allow_absent: bool,
}
fn run() -> Result<()> {
    let args = Args::parse();
    let _ = args.allow_absent;
    let inventory = serde_json::from_slice(&fs::read(args.inventory)?)?;
    let ledger = serde_json::from_slice(&fs::read(args.ledger)?)?;
    let report = derive_report(&inventory, &ledger, &args.root)?;
    let mut text = serde_json::to_string_pretty(&report)?;
    text.push('\n');
    fs::write(&args.out, text)?;
    println!(
        "proven: {} executed test coordinates; wrote {}",
        report["summary"]["total"],
        args.out.display()
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("::error::{}", error.message);
        std::process::exit(error.code);
    }
}

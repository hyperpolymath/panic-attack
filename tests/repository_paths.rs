// SPDX-License-Identifier: MPL-2.0
//! Repository checkout contract; run from the Git source checkout.
use std::process::Command;

fn portable_component(component: &str) -> bool {
    if component.is_empty()
        || component.ends_with(['.', ' '])
        || component
            .chars()
            .any(|c| c.is_control() || "<>:\"\\|?*".contains(c))
    {
        return false;
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

#[test]
fn path_controls_cover_windows_restrictions() {
    for invalid in [
        "report:12.json",
        "CON",
        "nul.txt",
        "com1.log",
        "LPT9",
        "tail.",
        "tail ",
        "a?b",
        "a\\b",
        "line\nbreak",
    ] {
        assert!(!portable_component(invalid), "accepted {invalid:?}");
    }
    for valid in [
        "assemblyline-2026-04-12T11-23-37Z.json",
        ".github",
        "Cargo.toml",
        "com10.txt",
    ] {
        assert!(portable_component(valid), "rejected {valid:?}");
    }
}

#[test]
fn every_tracked_path_can_be_checked_out_on_windows() {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .output()
        .expect("git is required for the source-checkout contract");
    assert!(output.status.success(), "git ls-files failed");
    let paths = std::str::from_utf8(&output.stdout).expect("tracked paths must be UTF-8");
    assert!(
        !paths.is_empty(),
        "an empty inventory cannot establish portability"
    );
    let bad: Vec<_> = paths
        .split('\0')
        .filter(|path| !path.is_empty())
        .filter(|path| !path.split('/').all(portable_component))
        .collect();
    assert!(
        bad.is_empty(),
        "Windows-incompatible tracked paths: {bad:?}"
    );
}

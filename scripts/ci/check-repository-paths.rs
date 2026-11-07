// SPDX-License-Identifier: MPL-2.0
//! Checkout-only CI check; deliberately outside Cargo's integration tests.
use std::{collections::BTreeMap, path::Path, process::Command};

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
    let numbered_device = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"));
    !matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) && !numbered_device.is_some_and(|n| {
        matches!(
            n,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
    })
}

fn inventory_errors(paths: &[&str]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = BTreeMap::<String, (String, bool)>::new();
    for path in paths {
        let components: Vec<_> = path.split('/').collect();
        let mut prefix = String::new();
        for (index, component) in components.iter().enumerate() {
            if !portable_component(component) {
                errors.push(format!("invalid component in {path:?}"));
            }
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            let file = index + 1 == components.len();
            let key = prefix.to_uppercase();
            if let Some((old, old_file)) = seen.get(&key) {
                if old != &prefix || *old_file != file {
                    errors.push(format!(
                        "case or file/directory collision: {old:?} and {prefix:?}"
                    ));
                }
            } else {
                seen.insert(key, (prefix.clone(), file));
            }
        }
    }
    errors
}

fn check_checkout(root: &Path) -> Result<(), String> {
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let top = Command::new("git")
        .current_dir(&root)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| format!("git is required: {e}"))?;
    if !top.status.success() {
        return Err("the requested root is not a Git checkout".into());
    }
    let top = std::str::from_utf8(&top.stdout)
        .map_err(|e| e.to_string())?
        .trim();
    if Path::new(top).canonicalize().map_err(|e| e.to_string())? != root {
        return Err("refusing to inspect an enclosing repository's index".into());
    }
    let output = Command::new("git")
        .current_dir(&root)
        .args(["ls-files", "-z"])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("git ls-files failed".into());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
    let paths: Vec<_> = text.split('\0').filter(|p| !p.is_empty()).collect();
    if paths.is_empty() {
        return Err("empty inventory cannot establish portability".into());
    }
    let errors = inventory_errors(&paths);
    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }
    println!(
        "{} tracked paths passed the portability checks",
        paths.len()
    );
    Ok(())
}

fn main() -> Result<(), String> {
    let root = std::env::args_os()
        .nth(1)
        .ok_or("usage: check-repository-paths REPOSITORY_ROOT")?;
    check_checkout(Path::new(&root))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_device_and_component_controls() {
        for bad in [
            "report:12.json",
            "CON",
            "nul.txt",
            "COM1.log",
            "LPT9",
            "COM¹.txt",
            "COM²",
            "COM³",
            "LPT¹",
            "LPT²",
            "LPT³",
            "CONIN$",
            "CONOUT$",
            "tail.",
            "tail ",
            "a?b",
            "a\\b",
            "line\nbreak",
        ] {
            assert!(!portable_component(bad), "accepted {bad:?}");
        }
        for good in [
            "assemblyline-2026-04-12T11-23-37Z.json",
            ".github",
            "Cargo.toml",
            "com10.txt",
        ] {
            assert!(portable_component(good), "rejected {good:?}");
        }
    }
    #[test]
    fn inventory_detects_case_and_file_directory_collisions() {
        for paths in [
            vec!["reports/Run.json", "reports/run.json"],
            vec!["src/Foo/a.rs", "src/foo/b.rs"],
            vec!["foo", "FOO/bar.rs"],
        ] {
            assert!(
                !inventory_errors(&paths).is_empty(),
                "accepted collision: {paths:?}"
            );
        }
        assert!(inventory_errors(&["src/a.rs", "src/b.rs"]).is_empty());
    }
}

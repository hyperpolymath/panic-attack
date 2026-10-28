// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Tests for language-specific detection patterns.
//!
//! All tests are panic-free: the file-creation helper returns `Result`,
//! and every test propagates errors with `?` instead of calling `.unwrap()`.

use panic_attack::assail;
use panic_attack::types::*;
use std::fs;
use tempfile::TempDir;

/// Write `content` to `dir/name` and return the full path.
fn write_test_file(
    dir: &TempDir,
    name: &str,
    content: &str,
) -> std::io::Result<std::path::PathBuf> {
    let path = dir.path().join(name);
    fs::write(&path, content)?;
    Ok(path)
}

fn has_category(report: &AssailReport, cat: WeakPointCategory) -> bool {
    report.weak_points.iter().any(|wp| wp.category == cat)
}

// === Rust patterns ===

#[test]
fn test_rust_transmute_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.rs",
        r#"
use std::mem;

fn main() {
    let x: u32 = unsafe { mem::transmute(1.0_f32) };
    println!("{}", x);
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "transmute should be detected as UnsafeCode"
    );
    Ok(())
}

#[test]
fn test_rust_mem_forget_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.rs",
        r#"
use std::mem;

fn main() {
    let v = vec![1, 2, 3];
    mem::forget(v);
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::ResourceLeak),
        "mem::forget should be detected as ResourceLeak"
    );
    Ok(())
}

#[test]
fn test_rust_raw_pointer_cast_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.rs",
        r#"
fn main() {
    let x = 42;
    let ptr = &x as *const i32;
    let mptr = &x as *mut i32;
    println!("{:?}", ptr);
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "raw pointer casts should be detected as UnsafeCode"
    );
    Ok(())
}

// === C/C++ patterns ===

#[test]
fn test_c_gets_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.c",
        r#"
#include <stdio.h>

int main() {
    char buffer[256];
    gets(buffer);
    printf("%s\n", buffer);
    return 0;
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "gets() should be detected as UnsafeCode"
    );
    Ok(())
}

#[test]
fn test_c_system_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.c",
        r#"
#include <stdlib.h>

int main() {
    system("ls -la");
    return 0;
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::CommandInjection),
        "system() should be detected as CommandInjection"
    );
    Ok(())
}

#[test]
fn test_c_sprintf_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.c",
        r#"
#include <stdio.h>

int main() {
    char buf[64];
    sprintf(buf, "hello %s", "world");
    return 0;
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "sprintf() should be detected as UnsafeCode"
    );
    Ok(())
}

// === Go patterns ===

#[test]
fn test_go_unsafe_pointer_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.go",
        r#"
package main

import "unsafe"

func main() {
    var x int = 42
    ptr := unsafe.Pointer(&x)
    _ = ptr
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "unsafe.Pointer should be detected as UnsafeCode"
    );
    Ok(())
}

#[test]
fn test_go_exec_command_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.go",
        r#"
package main

import "os/exec"

func main() {
    cmd := exec.Command("ls", "-la")
    cmd.Run()
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::CommandInjection),
        "exec.Command should be detected as CommandInjection"
    );
    Ok(())
}

// === Python patterns ===

#[test]
fn test_python_pickle_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.py",
        r#"
import pickle

with open("data.pkl", "rb") as f:
    data = pickle.load(f)
    items = pickle.loads(raw_bytes)
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::UnsafeDeserialization),
        "pickle.load/loads should be detected as UnsafeDeserialization"
    );
    Ok(())
}

#[test]
fn test_python_os_system_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.py",
        r#"
import os

os.system("rm -rf /tmp/test")
os.popen("ls")
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::CommandInjection),
        "os.system/os.popen should be detected as CommandInjection"
    );
    Ok(())
}

// === JavaScript patterns ===

#[test]
fn test_js_innerhtml_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.js",
        r#"
const el = document.getElementById("app");
el.innerHTML = "<div>" + userInput + "</div>";
document.write("<p>test</p>");
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::DynamicCodeExecution),
        "innerHTML/document.write should be detected as DynamicCodeExecution"
    );
    Ok(())
}

#[test]
fn test_js_dangerously_set_innerhtml_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.js",
        r#"
function App() {
    return <div dangerouslySetInnerHTML={{ __html: userContent }} />;
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        has_category(&report, WeakPointCategory::DynamicCodeExecution),
        "dangerouslySetInnerHTML should be detected as DynamicCodeExecution"
    );
    Ok(())
}

#[test]
fn pa011_semantic_classes_separate_eval_from_dom_sinks() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "sinks.js",
        r#"
eval(userInput);
element.innerHTML = userInput;
document.write(userInput);
const component = <div dangerouslySetInnerHTML={{ __html: userInput }} />;
"#,
    )?;
    let report = assail::analyze(&file)?;
    let table: serde_json::Value =
        serde_json::from_str(include_str!("../data/canonical-rule-ids.json"))?;
    let rule = table["rules"]
        .as_array()
        .ok_or("missing canonical rules array")?
        .iter()
        .find(|rule| rule["rule_id"] == "PA011")
        .ok_or("missing PA011 rule")?;
    let mut classes = Vec::new();
    for finding in report
        .weak_points
        .iter()
        .filter(|wp| wp.category == WeakPointCategory::DynamicCodeExecution)
    {
        assert_eq!(finding.category.rule_id(), "PA011");
        let mut selected = rule;
        for entry in rule["semantic_class_overrides"]
            .as_array()
            .ok_or("missing PA011 overrides")?
        {
            if finding.description.starts_with(
                entry["description_prefix"]
                    .as_str()
                    .ok_or("missing description prefix")?,
            ) {
                selected = entry;
                break;
            }
        }
        classes.push(
            selected["semantic_class"]
                .as_str()
                .ok_or("missing semantic class")?,
        );
        if finding.description.starts_with("eval() usage") {
            assert_eq!(
                selected["semantic_class"],
                "improper-neutralization-of-eval-input"
            );
            assert_eq!(selected["cwe_ids"], serde_json::json!(["CWE-95"]));
        } else {
            assert_eq!(
                selected["semantic_class"],
                "improper-neutralization-of-html-input"
            );
            assert_eq!(selected["cwe_ids"], serde_json::json!(["CWE-79"]));
        }
    }
    assert_eq!(classes.len(), 3);
    assert_eq!(
        classes
            .iter()
            .filter(|c| **c == "improper-neutralization-of-eval-input")
            .count(),
        1
    );
    assert_eq!(
        classes
            .iter()
            .filter(|c| **c == "improper-neutralization-of-html-input")
            .count(),
        2
    );
    Ok(())
}

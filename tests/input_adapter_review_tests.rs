// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Concrete review counterexamples for the declared input-adapter contract.
use panic_attack::{
    assail,
    types::{AssailReport, WeakPointCategory},
};

fn scan(name: &str, source: &str) -> AssailReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, source).unwrap();
    assail::analyze(&path).unwrap()
}

fn category(report: &AssailReport, expected: WeakPointCategory) -> bool {
    report
        .weak_points
        .iter()
        .any(|f| f.category == expected && !f.suppressed)
}

#[test]
fn clustered_shell_flags_reach_the_actual_inline_source() {
    for argv in [
        r#"["bash","-lc","eval \"$INPUT\""]"#,
        r#"["bash","-euo","pipefail","-lc","eval \"$INPUT\""]"#,
    ] {
        let report = scan("Containerfile", &format!("FROM scratch\nRUN {argv}\n"));
        assert_eq!(report.coverage.status, "complete", "{argv}");
        assert!(
            category(&report, WeakPointCategory::CommandInjection),
            "{argv}"
        );
    }
    let report = scan(
        "Containerfile",
        "FROM scratch\nRUN [\"bash\",\"script.sh\",\"-c\",\"eval \\\"$INPUT\\\"\"]\n",
    );
    assert!(
        !category(&report, WeakPointCategory::CommandInjection),
        "script arguments are not inline source"
    );
}

#[test]
fn remote_script_integrity_requires_a_usable_supported_digest_token() {
    for integrity in [
        "".to_owned(),
        "bogus".into(),
        "sha256-short".into(),
        format!("sha256-{}=", "B".repeat(43)),
    ] {
        let report = scan(
            "index.html",
            &format!("<script src='https://cdn.invalid/app.js' integrity='{integrity}'></script>"),
        );
        assert_eq!(report.coverage.status, "complete");
        assert!(
            category(&report, WeakPointCategory::SupplyChain),
            "{integrity}"
        );
    }
    for integrity in [
        format!("sha256-{}=", "A".repeat(43)),
        format!("sha384-{}", "A".repeat(64)),
        format!("sha512-{}==", "A".repeat(86)),
    ] {
        let report = scan(
            "index.html",
            &format!("<script src='https://cdn.invalid/app.js' integrity='{integrity}'></script>"),
        );
        assert!(
            !category(&report, WeakPointCategory::SupplyChain),
            "valid syntax, not a fetched-resource digest proof"
        );
    }
}

#[test]
fn encoded_inline_css_remains_an_explicit_gap() {
    let report = scan(
        "index.html",
        "<p style=\"background:url('http&#58;//remote.invalid/x')\">x</p>",
    );
    assert_eq!(report.coverage.inputs[0].status, "unsupported");
    assert!(report.coverage.incomplete());
}

#[test]
fn plaintext_schemes_are_case_insensitive() {
    for prefix in ["http", "HTTP", "hTtP"] {
        let report = scan(
            "config.json",
            &format!(r#"{{"endpoint":"{prefix}://remote.invalid"}}"#),
        );
        assert!(category(&report, WeakPointCategory::InsecureProtocol));
        let report = scan(
            "config.json",
            &format!(r#"{{"endpoint":"{prefix}://localhost:9099"}}"#),
        );
        assert!(!category(&report, WeakPointCategory::InsecureProtocol));
    }
}

#[test]
fn copy_sources_distinguish_stages_pins_and_unresolved_images() {
    let report = scan(
        "Containerfile",
        "FROM scratch\nCOPY --from=nginx:latest /source /dest\n",
    );
    assert!(category(&report, WeakPointCategory::SupplyChain));
    for source in [
        "builder".to_owned(),
        "0".into(),
        format!("nginx@sha256:{}", "a".repeat(64)),
    ] {
        let report = scan(
            "Containerfile",
            &format!("FROM scratch AS builder\nCOPY --from={source} /source /dest\n"),
        );
        assert_eq!(report.coverage.status, "complete", "{source}");
        assert!(
            !category(&report, WeakPointCategory::SupplyChain),
            "{source}"
        );
    }
    let report = scan(
        "Containerfile",
        "FROM scratch\nCOPY --from=external-context /source /dest\n",
    );
    assert_eq!(
        report.coverage.inputs[0].status, "unsupported",
        "external named context needs resolution"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_filenames_keep_registered_ascii_extensions_in_scope() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    for (suffix, content) in [
        ("htm", "<p>text</p>"),
        ("fth", ": go 1 ;"),
        ("forth", ": go 1 ;"),
        ("4th", ": go 1 ;"),
        ("just", "check:\n    echo safe\n"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = b"input-\xff.".to_vec();
        bytes.extend_from_slice(suffix.as_bytes());
        let path = dir.path().join(OsString::from_vec(bytes));
        std::fs::write(&path, content).unwrap();
        let report = assail::analyze(&path).unwrap();
        assert_eq!(report.coverage.status, "complete", "{suffix}");
        assert_eq!(report.coverage.candidate_files, 1);
        assert_eq!(report.coverage.inputs[0].path, path);
    }
}

#[test]
fn container_variant_dispatch_matches_the_inventory_adapter() {
    for name in ["Dockerfile.d", "Containerfile.sh", "Dockerfile.pl"] {
        let report = scan(name, "FROM scratch\nRUN eval \"$INPUT\"\n");
        assert_eq!(report.coverage.status, "complete");
        assert!(report.coverage.inputs[0]
            .analysis
            .as_ref()
            .unwrap()
            .starts_with("Containerfile"));
        assert!(
            category(&report, WeakPointCategory::CommandInjection),
            "{name}"
        );
    }
}

#[test]
fn non_configuration_literal_credential_fields_are_checked() {
    for (name, content) in [
        (
            "Containerfile",
            "FROM scratch\nENV API_KEY=fixture-literal-value\n",
        ),
        (
            "Dockerfile",
            "FROM scratch\nARG ACCESS_TOKEN=fixture-literal-value\n",
        ),
        (
            "Containerfile.example",
            "FROM scratch\nLABEL api-key=fixture-literal-value\n",
        ),
        (
            "index.html",
            "<p data-api-key='fixture-literal-value'>text</p>",
        ),
        ("style.css", ":root { --api-key: 'fixture-literal-value'; }"),
        (
            "Justfile",
            "api_key := 'fixture-literal-value'\ncheck:\n    echo safe\n",
        ),
        (
            "example.forth",
            "s\" fixture-literal-value\" 2constant api_key\n",
        ),
    ] {
        let report = scan(name, content);
        assert_eq!(
            report.coverage.status, "complete",
            "{name}: {:?}",
            report.coverage.inputs
        );
        assert!(
            category(&report, WeakPointCategory::HardcodedSecret),
            "{name}"
        );
        assert!(report
            .weak_points
            .iter()
            .all(|f| !f.description.contains("fixture-literal-value")));
    }
    for (name,content) in [("Containerfile","FROM scratch\n# ENV API_KEY=fixture-literal-value\n"),("index.html","<!-- data-api-key='fixture-literal-value' --><p xmlns='http://www.w3.org/1999/xhtml'>text</p>"),("style.css","/* --api-key: 'fixture-literal-value' */ p { color: blue; }"),("Justfile","# api_key := 'fixture-literal-value'\ncheck:\n    echo safe\n"),("example.forth","\\ s\" fixture-literal-value\" 2constant api_key\n")] {
        let report=scan(name,content);
        assert!(!category(&report,WeakPointCategory::HardcodedSecret),"{name}");
        assert!(!category(&report,WeakPointCategory::InsecureProtocol),"{name}");
    }
}

#[test]
fn bracket_prefixed_shell_commands_are_not_misparsed_as_exec_json() {
    let report = scan(
        "Containerfile",
        "FROM scratch\nRUN [ -f /etc/config ] && eval \"$INPUT\"\n",
    );
    assert_eq!(report.coverage.status, "complete");
    assert!(category(&report, WeakPointCategory::CommandInjection));
}

#[test]
fn just_shell_settings_do_not_depend_on_canonical_spacing() {
    for line in [
        r#"set shell:=["pwsh","-c"]"#,
        r#"set shell  := ["pwsh","-c"]"#,
        "set\tshell := [\"pwsh\",\"-c\"]",
    ] {
        let report = scan("Justfile", &format!("{line}\ncheck:\n    echo safe\n"));
        assert_eq!(report.coverage.inputs[0].status, "unsupported", "{line}");
    }
}

#[test]
fn cargo_git_revisions_have_one_structured_finding_per_dependency() {
    let report = scan(
        "Cargo.toml",
        "[dependencies.example]\ngit = \"https://example.org/repo\"\n",
    );
    let findings: Vec<_> = report
        .weak_points
        .iter()
        .filter(|f| f.category == WeakPointCategory::SupplyChain)
        .collect();
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn plain_forth_strings_do_not_escape_their_closing_quote() {
    let report = scan(
        "example.forth",
        r#": run s" C:\dir\" system s" trailing" ;"#,
    );
    assert_eq!(report.coverage.status, "complete");
    assert!(category(&report, WeakPointCategory::CommandInjection));
    let report = scan(
        "example.forth",
        r#": run s\" escaped \" system still string" ;"#,
    );
    assert_eq!(report.coverage.status, "complete");
    assert!(!category(&report, WeakPointCategory::CommandInjection));
}

// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
use panic_attack::assail;
use panic_attack::types::{AssailReport, WeakPointCategory};

fn scan(name: &str, content: &str) -> AssailReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, content).unwrap();
    assail::analyze(&path).unwrap()
}

#[test]
fn discovered_configurations_execute_their_declared_adapters() {
    for (name, content, adapter) in [
        (
            "config.json",
            r#"{"enabled":true,"endpoint":"https://example.org"}"#,
            "JSON",
        ),
        (
            "config.YAML",
            "enabled: true\nendpoint: https://example.org\n",
            "YAML",
        ),
        (
            "config.toml",
            "enabled = true\nendpoint = 'https://example.org'\n",
            "TOML",
        ),
    ] {
        let report = scan(name, content);
        assert_eq!(report.coverage.status, "complete", "{name}");
        assert_eq!(report.coverage.candidate_files, 1);
        assert_eq!(report.coverage.analyzed_files, 1);
        let input = &report.coverage.inputs[0];
        assert!(input.analysis.as_deref().unwrap().starts_with(adapter));
        assert_eq!(
            input.content_blake3.as_deref(),
            Some(blake3::hash(content.as_bytes()).to_hex().as_str())
        );
        assert!(
            report.weak_points.is_empty(),
            "{name}: {:?}",
            report.weak_points
        );
    }
}

#[test]
fn malformed_and_duplicate_configurations_remain_coverage_gaps() {
    for (name, content) in [
        ("malformed.json", "{\"enabled\":"),
        (
            "nested.json",
            r#"{"items":[{"verify_ssl":false,"verify_ssl":true}]}"#,
        ),
        ("malformed.yml", "enabled: [\n"),
        (
            "duplicate.yml",
            "nested:\n  verify_ssl: false\n  verify_ssl: true\n",
        ),
        ("malformed.toml", "enabled = [\n"),
        (
            "duplicate.toml",
            "[nested]\nverify_ssl = false\n[nested]\nverify_ssl = true\n",
        ),
    ] {
        let report = scan(name, content);
        assert!(report.coverage.incomplete(), "{name}");
        assert_eq!(report.coverage.candidate_files, 1);
        assert_eq!(report.coverage.analyzed_files, 0);
        assert_eq!(report.coverage.inputs[0].status, "parse_error", "{name}");
        assert!(report.coverage.inputs[0].content_blake3.is_some());
        assert!(report.coverage.inputs[0].reason.is_some());
    }
}

#[test]
fn checks_reach_nested_arrays_and_quoted_configuration_keys() {
    for (name, content) in [
        ("config.json", r#"{"nested":[{"password":"fixture-literal-credential","verify_ssl":false,"privileged":true,"endpoint":"http://remote.invalid"}]}"#),
        ("config.yml", "nested:\n  - password: fixture-literal-credential\n    verify_ssl: false\n    privileged: true\n    endpoint: http://remote.invalid\n"),
        ("config.toml", "[[nested]]\npassword = 'fixture-literal-credential'\nverify_ssl = false\nprivileged = true\nendpoint = 'http://remote.invalid'\n"),
    ] {
        let report = scan(name, content);
        assert_eq!(report.coverage.status, "complete", "{name}");
        for category in [WeakPointCategory::HardcodedSecret, WeakPointCategory::InsecureProtocol, WeakPointCategory::ExcessivePermissions] {
            assert!(report.weak_points.iter().any(|finding| finding.category == category), "{name}: {category:?}");
        }
        assert!(report.weak_points.iter().all(|finding| !finding.description.contains("fixture-literal-credential")));
    }
}

#[test]
fn all_yaml_documents_are_checked() {
    let report = scan("config.yaml", "enabled: true\n---\nverify_tls: false\n");
    assert_eq!(report.coverage.status, "complete");
    assert!(report.weak_points.iter().any(|finding| finding.category
        == WeakPointCategory::InsecureProtocol
        && finding.description.contains("document[1]")));
}

#[test]
fn comments_references_and_scalar_namespace_identifiers_are_not_credentials_or_endpoints() {
    let report = scan("config.yml", "# password: fixture-comment-only\n# url: http://comment.invalid\npassword: '${{ secrets.PASSWORD }}'\n$schema: http://json-schema.org/draft-07/schema#\nendpoint: http://localhost:9099\n");
    assert_eq!(report.coverage.status, "complete");
    assert!(report.weak_points.is_empty(), "{:?}", report.weak_points);
    let report = scan(
        "nested.json",
        r#"{"@context":{"verify_tls":false},"endpoint":"http://localhost.attacker.invalid"}"#,
    );
    assert_eq!(
        report.weak_points.len(),
        2,
        "nested objects and lookalike hosts must remain checked"
    );
}

#[test]
fn plaintext_endpoint_checks_use_the_host_after_userinfo() {
    for (endpoint, insecure) in [
        ("http://localhost@remote.invalid/path", true),
        ("http://localhost:123@remote.invalid?query", true),
        ("http://first@localhost@remote.invalid#fragment", true),
        ("http://user@LOCALHOST:9099/path", false),
        ("http://first@second@127.0.0.1?query", false),
        ("http://user@[::1]:8080#fragment", false),
        ("http://localhost/path@remote.invalid", false),
        ("http://localhost?query=@remote.invalid", false),
        ("http://localhost#fragment@remote.invalid", false),
        ("http://remote.invalid/path@localhost", true),
        ("http://remote.invalid?query=@localhost", true),
        ("http://remote.invalid#fragment@localhost", true),
        ("http://user@localhost.attacker.invalid", true),
    ] {
        let report = scan("config.json", &format!(r#"{{"endpoint":"{endpoint}"}}"#));
        assert_eq!(report.coverage.status, "complete", "{endpoint}");
        assert_eq!(
            report
                .weak_points
                .iter()
                .any(|finding| finding.category == WeakPointCategory::InsecureProtocol),
            insecure,
            "{endpoint}: {:?}",
            report.weak_points
        );
    }
}

#[test]
fn cargo_revision_checks_cover_nested_dependencies_and_reject_fake_pins() {
    for rev in ["", "rev = ''", "rev = 'main'", "rev = false"] {
        let report = scan(
            "Cargo.toml",
            &format!("[workspace.dependencies.example]\ngit = 'https://example.org/repo'\n{rev}\n"),
        );
        assert_eq!(report.coverage.status, "complete");
        assert!(report
            .weak_points
            .iter()
            .any(|finding| finding.category == WeakPointCategory::SupplyChain));
    }
    let report = scan("Cargo.toml", "[workspace.dependencies.example]\ngit = 'https://example.org/repo'\nrev = '0123456789abcdef0123456789abcdef01234567'\n");
    assert!(!report
        .weak_points
        .iter()
        .any(|finding| finding.category == WeakPointCategory::SupplyChain));
}

#[test]
fn supported_configuration_does_not_hide_other_unsupported_candidates() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.json"), "{\"enabled\":true}").unwrap();
    std::fs::write(dir.path().join("unknown.swift"), "let enabled = true").unwrap();
    let report = assail::analyze(dir.path()).unwrap();
    assert_eq!(report.coverage.status, "partial");
    assert_eq!(report.coverage.candidate_files, 2);
    assert_eq!(report.coverage.analyzed_files, 1);
    assert!(report
        .coverage
        .inputs
        .iter()
        .any(|input| input.status == "unsupported"));
}

#[test]
fn executable_configuration_fields_use_existing_interpreter_checks() {
    let report = scan("workflow.yml", "on: push\ndefaults:\n  run:\n    shell: python\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: eval(user_input)\n      - shell: bash\n        run: eval \"$INPUT\"\n");
    assert_eq!(report.coverage.status, "complete");
    for (language, category) in [
        ("Python", WeakPointCategory::DynamicCodeExecution),
        ("Shell", WeakPointCategory::CommandInjection),
    ] {
        assert!(report.weak_points.iter().any(|f| f.category == category
            && f.description.contains(&format!("embedded {language}"))
            && f.description
                .contains("configuration field document[0]/jobs/check/steps/")));
    }
    let report = scan("package.json", r#"{"scripts":{"build":"eval \"$INPUT\""}}"#);
    assert_eq!(report.coverage.status, "complete");
    assert!(report
        .weak_points
        .iter()
        .any(|f| f.category == WeakPointCategory::CommandInjection
            && f.description.contains("runtime shell unresolved")));
    let report = scan(
        "action.yml",
        "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: eval \"$INPUT\"\n",
    );
    assert_eq!(report.coverage.status, "complete");
    assert!(report
        .weak_points
        .iter()
        .any(|f| f.category == WeakPointCategory::CommandInjection));
}

#[test]
fn actions_defaults_obey_scope_and_unknown_interpreters_remain_gaps() {
    let report = scan("workflow.yml", "on: push\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  check:\n    defaults:\n      run:\n        shell: bash\n    runs-on: windows-latest\n    steps:\n      - run: echo safe\n");
    assert_eq!(
        report.coverage.status, "complete",
        "job shell overrides workflow and runner defaults"
    );
    for settings in [
        "runs-on: windows-latest",
        "runs-on: '${{ matrix.os }}'",
        "runs-on: self-hosted",
        "runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: pwsh",
    ] {
        let report = scan(
            "workflow.yml",
            &format!(
                "on: push\njobs:\n  check:\n    {settings}\n    steps:\n      - run: echo safe\n"
            ),
        );
        assert!(report.coverage.incomplete(), "{settings}");
        assert_eq!(report.coverage.inputs[0].status, "unsupported");
    }
    let report = scan("data.yaml", "example:\n  run: eval \"$INPUT\"\n");
    assert_eq!(report.coverage.status, "complete");
    assert!(
        !report
            .weak_points
            .iter()
            .any(|f| f.category == WeakPointCategory::CommandInjection),
        "arbitrary data is not a workflow command"
    );
}

// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
use panic_attack::assail;
use panic_attack::types::{AssailReport, WeakPointCategory};

fn scan(name: &str, source: &str) -> AssailReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, source).unwrap();
    assail::analyze(&path).unwrap()
}

#[test]
fn container_variants_check_image_pins_and_actual_shell_inputs() {
    let report = scan("Containerfile.full", "FROM example.invalid/base:latest AS builder\nRUN chmod 777 /work\nFROM builder\nCMD [\"echo\",\"eval is a literal argument\"]\n");
    assert_eq!(report.coverage.status, "complete");
    assert_eq!(
        report
            .weak_points
            .iter()
            .filter(|finding| finding.category == WeakPointCategory::SupplyChain)
            .count(),
        1
    );
    assert!(report
        .weak_points
        .iter()
        .any(|finding| finding.category == WeakPointCategory::ExcessivePermissions));
    assert!(!report
        .weak_points
        .iter()
        .any(|finding| finding.category == WeakPointCategory::CommandInjection));
    assert!(report.coverage.inputs[0].content_blake3.is_some());
}

#[test]
fn digest_pinned_images_are_not_floating_and_exec_interpreters_are_analyzed() {
    let source = format!(
        "FROM example.invalid/base@sha256:{}\nRUN [\"bash\",\"-c\",\"eval untrusted\"]\n",
        "a".repeat(64)
    );
    let report = scan("Dockerfile", &source);
    assert_eq!(report.coverage.status, "complete");
    assert!(!report
        .weak_points
        .iter()
        .any(|finding| finding.category == WeakPointCategory::SupplyChain));
    assert!(report
        .weak_points
        .iter()
        .any(|finding| finding.category == WeakPointCategory::CommandInjection));
}

#[test]
fn invalid_or_unhandled_build_dialects_remain_gaps() {
    for source in [
        "RUN echo no-base\n",
        "FROM scratch\nRUN [\"bash\",7]\n",
        "FROM scratch\nRUN echo incomplete \\\n",
        "FROM scratch\nRUN <<EOF\necho unhandled\nEOF\n",
        "FROM scratch\nSHELL [\"powershell\",\"-Command\"]\nRUN example\n",
        "FROM scratch\nONBUILD RUN unknown\n",
    ] {
        let report = scan("Containerfile", source);
        assert!(report.coverage.incomplete(), "{source}");
        assert_eq!(report.coverage.analyzed_files, 0);
        assert!(report.coverage.inputs[0].reason.is_some());
        assert!(report.coverage.inputs[0].content_blake3.is_some());
    }
}

#[test]
fn just_recipe_and_shebang_bodies_reach_their_real_detectors() {
    let report = scan("Justfile", "set shell := [\"bash\", \"-uc\"]\n\nfirst:\n    @chmod 777 /work\n\nsecond:\n    #!/usr/bin/env python3\n    if True:\n        eval(user_input)\n");
    assert_eq!(
        report.coverage.status, "complete",
        "{:?}",
        report.coverage.inputs
    );
    assert!(report
        .weak_points
        .iter()
        .any(|finding| finding.category == WeakPointCategory::ExcessivePermissions));
    assert!(report.weak_points.iter().any(|finding| finding.category
        == WeakPointCategory::DynamicCodeExecution
        && finding.description.contains("embedded Python")));
}

#[test]
fn executable_just_declarations_and_unknown_interpreters_are_not_claimed_covered() {
    for source in [
        "value := `echo dynamic`\n",
        "task:\n    #!/usr/bin/env perl\n    system($input)\n",
        "[script('unknown')]\ntask:\n    code\n",
        "    orphan command\n",
    ] {
        let report = scan("contractile.just", source);
        assert!(report.coverage.incomplete(), "{source}");
    }
}

#[test]
fn forth_hazards_are_words_not_comments_string_data_or_definition_names() {
    let report = scan("input.fs", "\\ system evaluate !\n: system ( -- ) ;\n: example s\" system evaluate !\" type ;\n: hazardous evaluate system ! ;\n");
    assert_eq!(
        report.coverage.status, "complete",
        "{:?}",
        report.coverage.inputs
    );
    for category in [
        WeakPointCategory::DynamicCodeExecution,
        WeakPointCategory::CommandInjection,
        WeakPointCategory::UnsafeCode,
    ] {
        assert_eq!(
            report
                .weak_points
                .iter()
                .filter(|finding| finding.category == category)
                .count(),
            1,
            "{category:?}"
        );
    }
}

#[test]
fn ambiguous_fs_and_unterminated_forth_do_not_receive_complete_coverage() {
    for (name, source) in [
        ("sample.fs", "module Sample\nlet x = 1\n"),
        ("sample.FS", "module Sample\nlet x = 1\n"),
        ("sample.fth", ": example s\" unfinished"),
        ("sample.fth", ": example ( unfinished"),
    ] {
        let report = scan(name, source);
        assert!(report.coverage.incomplete(), "{name}: {source}");
        assert_eq!(report.coverage.analyzed_files, 0);
    }
}

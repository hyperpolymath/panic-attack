let assault_report = {
  program = "/var$REPOS_DIR/panic-attacker/target/debug/panic-attack";
  language = "Unknown";
  framework_count = 0;
  weak_points = 1;
  total_crashes = 6;
  total_signatures = 0;
  attack_axes = ["Cpu", "Memory", "Disk", "Network", "Concurrency", "Time"];
  weak_point_samples = [{ category = "UncheckedError", severity = "Low" }];
  pivot_samples = [{ source = "UncheckedError", sink = "Cpu", severity = 1.0 }];
  robustness_score = 40.0;
  critical_issues = ["Program crashed under Cpu attack (1 crashes)", "Program crashed under Memory attack (1 crashes)", "Program crashed under Disk attack (1 crashes)", "Program crashed under Network attack (1 crashes)", "Program crashed under Concurrency attack (1 crashes)", "Program crashed under Time attack (1 crashes)"];
  recommendations = ["Add comprehensive error handling for edge cases", "Consider comprehensive refactoring for robustness"];
};
assault_report
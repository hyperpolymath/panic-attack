// SPDX-License-Identifier: PMPL-1.0-or-later

//! Abduct isolation harness for defensive lock-in and delayed-trigger testing.

use crate::assail;
use anyhow::{anyhow, Context, Result};
use filetime::FileTime;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyScope {
    None,
    Direct,
    TwoHops,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeMode {
    Normal,
    Frozen,
    Slow,
}

#[derive(Debug, Clone)]
pub struct ExecutionCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AbductConfig {
    pub target: PathBuf,
    pub source_root: Option<PathBuf>,
    pub output_root: PathBuf,
    pub dependency_scope: DependencyScope,
    pub lock_files: bool,
    pub mtime_offset_days: i64,
    pub time_mode: TimeMode,
    pub time_scale: f64,
    pub virtual_now: Option<String>,
    pub execute: Option<ExecutionCommand>,
    pub exec_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbductReport {
    pub created_at: String,
    pub target: PathBuf,
    pub source_root: PathBuf,
    pub workspace_dir: PathBuf,
    pub dependency_scope: String,
    pub selected_files: usize,
    pub locked_files: usize,
    pub mtime_shifted_files: usize,
    pub mtime_offset_days: i64,
    pub time_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_scale: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_now: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub files: Vec<AbductFileRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbductFileRecord {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub relative_path: String,
    pub locked: bool,
    pub mtime_shifted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawn_error: Option<String>,
}

pub fn run(config: AbductConfig) -> Result<AbductReport> {
    if !config.target.exists() {
        return Err(anyhow!(
            "target file {} does not exist",
            config.target.display()
        ));
    }
    if !config.target.is_file() {
        return Err(anyhow!(
            "target path {} is not a file",
            config.target.display()
        ));
    }
    if config.exec_timeout_secs == 0 {
        return Err(anyhow!("--exec-timeout must be at least 1 second"));
    }
    if config.time_mode == TimeMode::Slow && config.time_scale <= 0.0 {
        return Err(anyhow!("--time-scale must be > 0 for time-mode=slow"));
    }

    let target = fs::canonicalize(&config.target)
        .with_context(|| format!("canonicalizing target {}", config.target.display()))?;
    let source_root = determine_source_root(&target, config.source_root)?;
    let (selected_sources, mut notes) =
        collect_selected_files(&target, &source_root, config.dependency_scope)?;

    if selected_sources.is_empty() {
        return Err(anyhow!("no files selected for abduct run"));
    }

    fs::create_dir_all(&config.output_root).with_context(|| {
        format!(
            "creating abduct output root {}",
            config.output_root.to_string_lossy()
        )
    })?;
    let workspace_dir = config.output_root.join(format!(
        "abduct-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    ));
    fs::create_dir_all(&workspace_dir).with_context(|| {
        format!(
            "creating abduct workspace {}",
            workspace_dir.to_string_lossy()
        )
    })?;

    // Copy-first strategy ensures all lock/time mutations happen on isolated artifacts only.
    let mut files = Vec::with_capacity(selected_sources.len());
    let mut copied_target: Option<PathBuf> = None;
    for source_path in selected_sources {
        let relative = relative_path(&source_root, &source_path);
        let destination = workspace_dir.join(&relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.to_string_lossy()))?;
        }
        fs::copy(&source_path, &destination).with_context(|| {
            format!(
                "copying {} to {}",
                source_path.to_string_lossy(),
                destination.to_string_lossy()
            )
        })?;
        if source_path == target {
            copied_target = Some(destination.clone());
        }
        files.push(AbductFileRecord {
            source: source_path,
            destination,
            relative_path: relative.to_string_lossy().to_string(),
            locked: false,
            mtime_shifted: false,
        });
    }

    let copied_target = copied_target.ok_or_else(|| {
        anyhow!(
            "internal error: copied target file not found for {}",
            target.display()
        )
    })?;

    // mtime shifting is a cheap delayed-trigger simulation primitive for file-timestamp checks.
    let mtime_shifted = if config.mtime_offset_days != 0 {
        apply_mtime_offset(&mut files, config.mtime_offset_days)?
    } else {
        0
    };

    // Read-only lock-down guards the copied workspace from accidental or malicious self-modification.
    let locked_files = if config.lock_files {
        lock_files_readonly(&mut files)?
    } else {
        0
    };

    let execution = config.execute.as_ref().map(|exec| {
        run_execution(
            exec,
            &copied_target,
            &workspace_dir,
            config.exec_timeout_secs,
            config.time_mode,
            config.time_scale,
            config.virtual_now.as_deref(),
            config.mtime_offset_days,
        )
        .unwrap_or_else(|err| ExecutionOutcome {
            success: false,
            exit_code: None,
            duration_ms: 0,
            timed_out: false,
            stdout: String::new(),
            stderr: String::new(),
            spawn_error: Some(err.to_string()),
        })
    });

    if matches!(
        config.dependency_scope,
        DependencyScope::Direct | DependencyScope::TwoHops
    ) && files.len() == 1
    {
        notes.push("dependency graph did not resolve neighbors; only target copied".to_string());
    }

    Ok(AbductReport {
        created_at: chrono::Utc::now().to_rfc3339(),
        target,
        source_root,
        workspace_dir,
        dependency_scope: dependency_scope_name(config.dependency_scope).to_string(),
        selected_files: files.len(),
        locked_files,
        mtime_shifted_files: mtime_shifted,
        mtime_offset_days: config.mtime_offset_days,
        time_mode: time_mode_name(config.time_mode).to_string(),
        time_scale: if config.time_mode == TimeMode::Slow {
            Some(config.time_scale)
        } else {
            None
        },
        virtual_now: config.virtual_now,
        notes,
        files,
        execution,
    })
}

pub fn write_report(report: &AbductReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating report parent directory {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(report).context("serializing abduct report")?;
    fs::write(path, json).with_context(|| format!("writing report {}", path.display()))?;
    Ok(())
}

fn determine_source_root(target: &Path, source_root: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(root) = source_root {
        let canonical = fs::canonicalize(&root)
            .with_context(|| format!("canonicalizing source root {}", root.display()))?;
        if !canonical.exists() {
            return Err(anyhow!(
                "source root {} does not exist",
                canonical.display()
            ));
        }
        if canonical.is_file() {
            return canonical
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| anyhow!("cannot derive parent from source root file"));
        }
        return Ok(canonical);
    }
    target
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("cannot derive target parent for source root"))
}

fn collect_selected_files(
    target: &Path,
    source_root: &Path,
    scope: DependencyScope,
) -> Result<(Vec<PathBuf>, Vec<String>)> {
    let mut notes = Vec::new();
    let mut selected = BTreeSet::new();
    selected.insert(target.to_path_buf());

    match scope {
        DependencyScope::None => {}
        DependencyScope::Directory => {
            if let Some(parent) = target.parent() {
                for entry in fs::read_dir(parent)
                    .with_context(|| format!("reading directory {}", parent.display()))?
                {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() {
                        selected.insert(path);
                    }
                }
            }
        }
        DependencyScope::Direct | DependencyScope::TwoHops => {
            let maybe_target_rel = target.strip_prefix(source_root).ok();
            if let Some(target_rel_path) = maybe_target_rel {
                if let Ok(report) = assail::analyze(source_root) {
                    let target_rel = target_rel_path
                        .to_string_lossy()
                        .to_string();
                    let depth = if scope == DependencyScope::Direct {
                        1
                    } else {
                        2
                    };
                    let rel_nodes =
                        related_nodes_from_graph(&target_rel, &report.dependency_graph.edges, depth);
                    if rel_nodes.len() <= 1 {
                        notes.push(
                            "no direct dependency neighbors found; falling back to same directory"
                                .to_string(),
                        );
                        if let Some(parent) = target.parent() {
                            for entry in fs::read_dir(parent)
                                .with_context(|| format!("reading directory {}", parent.display()))?
                            {
                                let entry = entry?;
                                let path = entry.path();
                                if path.is_file() {
                                    selected.insert(path);
                                }
                            }
                        }
                    } else {
                        for rel in rel_nodes {
                            let abs = source_root.join(&rel);
                            if abs.is_file() {
                                selected.insert(abs);
                            }
                        }
                    }
                } else {
                    notes.push(
                        "assail dependency analysis failed; fell back to same directory".to_string(),
                    );
                    if let Some(parent) = target.parent() {
                        for entry in fs::read_dir(parent)
                            .with_context(|| format!("reading directory {}", parent.display()))?
                        {
                            let entry = entry?;
                            let path = entry.path();
                            if path.is_file() {
                                selected.insert(path);
                            }
                        }
                    }
                }
            } else {
                notes.push(
                    "target is outside --source-root; dependency scope fell back to target only"
                        .to_string(),
                );
            }
        }
    }

    Ok((selected.into_iter().collect(), notes))
}

fn related_nodes_from_graph(
    target_rel: &str,
    edges: &[crate::types::DependencyEdge],
    depth: usize,
) -> HashSet<String> {
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    for edge in edges {
        if !is_file_like_node(&edge.from) || !is_file_like_node(&edge.to) {
            continue;
        }
        adj.entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
        adj.entry(edge.to.clone())
            .or_default()
            .push(edge.from.clone());
    }

    let mut visited = HashSet::new();
    let mut q = VecDeque::new();
    visited.insert(target_rel.to_string());
    q.push_back((target_rel.to_string(), 0usize));

    while let Some((node, d)) = q.pop_front() {
        if d >= depth {
            continue;
        }
        if let Some(next) = adj.get(&node) {
            for n in next {
                if visited.insert(n.clone()) {
                    q.push_back((n.clone(), d + 1));
                }
            }
        }
    }
    visited
}

fn is_file_like_node(node: &str) -> bool {
    node.contains('/')
        || node.contains('\\')
        || Path::new(node).extension().is_some()
        || node.starts_with('.')
}

fn relative_path(source_root: &Path, source: &Path) -> PathBuf {
    source
        .strip_prefix(source_root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| PathBuf::from(source.file_name().unwrap_or_default()))
}

fn apply_mtime_offset(files: &mut [AbductFileRecord], days: i64) -> Result<usize> {
    let now = chrono::Utc::now();
    let shifted = now + chrono::Duration::days(days);
    let timestamp = shifted.timestamp();
    let ft = FileTime::from_unix_time(timestamp, 0);

    let mut shifted_count = 0usize;
    for file in files {
        filetime::set_file_times(&file.destination, ft, ft)
            .with_context(|| format!("setting mtime for {}", file.destination.display()))?;
        file.mtime_shifted = true;
        shifted_count += 1;
    }
    Ok(shifted_count)
}

fn lock_files_readonly(files: &mut [AbductFileRecord]) -> Result<usize> {
    let mut locked = 0usize;
    for file in files {
        set_readonly_preserve_exec(&file.destination)?;
        file.locked = true;
        locked += 1;
    }
    Ok(locked)
}

#[cfg(unix)]
fn set_readonly_preserve_exec(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let current_mode = metadata.permissions().mode();
    let readonly_mode = current_mode & !0o222;
    let permissions = PermissionsExt::from_mode(readonly_mode);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("setting readonly permissions for {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_readonly_preserve_exec(path: &Path) -> Result<()> {
    let mut permissions = fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("setting readonly permissions for {}", path.display()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_execution(
    command: &ExecutionCommand,
    copied_target: &Path,
    workspace_dir: &Path,
    timeout_secs: u64,
    time_mode: TimeMode,
    time_scale: f64,
    virtual_now: Option<&str>,
    mtime_offset_days: i64,
) -> Result<ExecutionOutcome> {
    let file_token = copied_target.to_string_lossy().to_string();
    let workspace_token = workspace_dir.to_string_lossy().to_string();
    let mut args = command
        .args
        .iter()
        .map(|arg| {
            arg.replace("{file}", &file_token)
                .replace("{workspace}", &workspace_token)
        })
        .collect::<Vec<_>>();
    if args.is_empty() || !args.iter().any(|arg| arg == &file_token) {
        args.push(file_token.clone());
    }

    let virtual_now_value = virtual_now
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let mut child = Command::new(&command.program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("ABDUCT_TARGET_FILE", &file_token)
        .env("ABDUCT_WORKSPACE", &workspace_token)
        .env("ABDUCT_TIME_MODE", time_mode_name(time_mode))
        .env("ABDUCT_VIRTUAL_NOW", &virtual_now_value)
        .env("ABDUCT_MTIME_OFFSET_DAYS", mtime_offset_days.to_string())
        .env("ABDUCT_TIME_SCALE", time_scale.to_string())
        .spawn()
        .with_context(|| format!("executing {}", command.program))?;

    let started = Instant::now();
    let limit = Duration::from_secs(timeout_secs);
    let mut timed_out = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if started.elapsed() >= limit {
            let _ = child.kill();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let output = child.wait_with_output()?;
    Ok(ExecutionOutcome {
        success: output.status.success() && !timed_out,
        exit_code: output.status.code(),
        duration_ms: started.elapsed().as_millis(),
        timed_out,
        stdout: clamp_output(String::from_utf8_lossy(&output.stdout).to_string()),
        stderr: clamp_output(String::from_utf8_lossy(&output.stderr).to_string()),
        spawn_error: None,
    })
}

fn clamp_output(mut value: String) -> String {
    const MAX_LEN: usize = 8192;
    if value.len() > MAX_LEN {
        value.truncate(MAX_LEN);
        value.push_str("\n...<truncated>");
    }
    value
}

fn dependency_scope_name(scope: DependencyScope) -> &'static str {
    match scope {
        DependencyScope::None => "none",
        DependencyScope::Direct => "direct",
        DependencyScope::TwoHops => "two-hops",
        DependencyScope::Directory => "directory",
    }
}

fn time_mode_name(mode: TimeMode) -> &'static str {
    match mode {
        TimeMode::Normal => "normal",
        TimeMode::Frozen => "frozen",
        TimeMode::Slow => "slow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn abduct_none_scope_copies_and_locks_target() {
        let dir = TempDir::new().expect("temp dir should create");
        let src = dir.path().join("src");
        fs::create_dir_all(&src).expect("src dir should create");
        let target = src.join("main.rs");
        fs::write(&target, "fn main() {}\n").expect("target should write");

        let output_root = dir.path().join("runtime-abduct");
        let report = run(AbductConfig {
            target: target.clone(),
            source_root: Some(src.clone()),
            output_root,
            dependency_scope: DependencyScope::None,
            lock_files: true,
            mtime_offset_days: 0,
            time_mode: TimeMode::Normal,
            time_scale: 1.0,
            virtual_now: None,
            execute: None,
            exec_timeout_secs: 30,
        })
        .expect("abduct run should succeed");

        assert_eq!(report.selected_files, 1);
        assert_eq!(report.locked_files, 1);
        assert!(report.files[0].destination.exists());
    }

    #[test]
    fn abduct_directory_scope_includes_siblings() {
        let dir = TempDir::new().expect("temp dir should create");
        let src = dir.path().join("src");
        fs::create_dir_all(&src).expect("src dir should create");
        let target = src.join("a.rs");
        let sibling = src.join("b.rs");
        fs::write(&target, "fn a() {}\n").expect("target should write");
        fs::write(&sibling, "fn b() {}\n").expect("sibling should write");

        let output_root = dir.path().join("runtime-abduct");
        let report = run(AbductConfig {
            target: target.clone(),
            source_root: Some(src.clone()),
            output_root,
            dependency_scope: DependencyScope::Directory,
            lock_files: false,
            mtime_offset_days: 0,
            time_mode: TimeMode::Normal,
            time_scale: 1.0,
            virtual_now: None,
            execute: None,
            exec_timeout_secs: 30,
        })
        .expect("abduct run should succeed");

        assert_eq!(report.selected_files, 2);
    }
}

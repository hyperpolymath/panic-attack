// SPDX-License-Identifier: PMPL-1.0-or-later

//! Execution evidence accumulator.
//!
//! During the scan, the accumulator is wired into the file-reading loop
//! in `analyzer.rs`. Every file that is successfully read has its content
//! hash and path incorporated into a rolling SHA-256 digest. This makes
//! it computationally infeasible to fabricate evidence after the fact
//! without processing the exact same files in the exact same order.
//!
//! The accumulator also records resource usage (wall-clock time, CPU time,
//! peak RSS, files/bytes/directories) and periodic checkpoints for
//! coarse-grained progress verification.

use super::intent::sha256_str;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Instant;

/// Checkpoint interval — one checkpoint per this many files.
const CHECKPOINT_INTERVAL: usize = 100;

/// Runtime-only accumulator that records evidence during scanning.
///
/// This struct is NOT serialised. It lives only during the scan, and
/// is finalised into an [`ExecutionEvidence`] when the scan completes.
pub struct EvidenceAccumulator {
    /// The session nonce, threaded through from the intent phase.
    session_nonce: String,

    /// Rolling SHA-256 hasher. Each file contributes `path || content_hash`.
    rolling_hasher: Sha256,

    /// Total number of files successfully read and hashed.
    files_read: usize,

    /// Total bytes across all files read.
    bytes_read: u64,

    /// Unique directories traversed.
    directories: HashSet<String>,

    /// Periodic snapshots of the rolling hash for progress verification.
    checkpoints: Vec<EvidenceCheckpoint>,

    /// Languages detected across all files.
    languages_detected: HashSet<String>,

    /// Wall-clock start time.
    start: Instant,
}

/// A snapshot of the rolling hash taken every [`CHECKPOINT_INTERVAL`] files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCheckpoint {
    /// How many files had been processed when this checkpoint was taken.
    pub files_at_checkpoint: usize,

    /// The rolling hash at that point (hex).
    pub rolling_hash: String,

    /// ISO 8601 timestamp of the checkpoint.
    pub timestamp: String,
}

/// Serialisable evidence record, produced by [`EvidenceAccumulator::finalize`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvidence {
    /// Same nonce as the intent — ties the phases together.
    pub session_nonce: String,

    /// Total source files processed.
    pub files_read: usize,

    /// Total bytes across all source files.
    pub bytes_read: u64,

    /// Number of unique directories traversed.
    pub directories_traversed: usize,

    /// Final rolling hash over all file contents (hex, 64 chars).
    pub rolling_content_hash: String,

    /// Wall-clock milliseconds from start to finalize.
    pub wall_clock_ms: u64,

    /// CPU time in milliseconds (best-effort; falls back to wall-clock).
    pub cpu_time_ms: u64,

    /// Peak resident set size in bytes (best-effort; 0 if unavailable).
    pub peak_rss: u64,

    /// Periodic checkpoints taken every [`CHECKPOINT_INTERVAL`] files.
    pub checkpoints: Vec<EvidenceCheckpoint>,

    /// Unique programming languages detected.
    pub languages_detected: Vec<String>,

    /// `SHA-256(session_nonce || files_read || bytes_read || rolling_content_hash || wall_clock_ms)`.
    pub evidence_hash: String,
}

impl EvidenceAccumulator {
    /// Create a new accumulator bound to the given session nonce.
    pub fn new(session_nonce: &str) -> Self {
        Self {
            session_nonce: session_nonce.to_string(),
            rolling_hasher: Sha256::new(),
            files_read: 0,
            bytes_read: 0,
            directories: HashSet::new(),
            checkpoints: Vec::new(),
            languages_detected: HashSet::new(),
            start: Instant::now(),
        }
    }

    /// Record a successfully read source file.
    ///
    /// Updates the rolling hash with `path_bytes || content_hash`, increments
    /// counters, records the language, and emits a checkpoint every
    /// [`CHECKPOINT_INTERVAL`] files.
    pub fn record_file(&mut self, path: &str, content: &[u8], language: &str) {
        // Rolling hash: incorporate path and content hash
        let content_hash = sha256_str(content);
        self.rolling_hasher.update(path.as_bytes());
        self.rolling_hasher.update(content_hash.as_bytes());

        self.files_read += 1;
        self.bytes_read += content.len() as u64;

        if !language.is_empty() {
            self.languages_detected.insert(language.to_string());
        }

        // Emit checkpoint every CHECKPOINT_INTERVAL files
        if self.files_read % CHECKPOINT_INTERVAL == 0 {
            let snapshot = self.rolling_hasher.clone().finalize();
            self.checkpoints.push(EvidenceCheckpoint {
                files_at_checkpoint: self.files_read,
                rolling_hash: hex::encode(snapshot),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    /// Record a directory that was traversed during file collection.
    pub fn record_directory(&mut self, dir: &str) {
        self.directories.insert(dir.to_string());
    }

    /// Seal the accumulator into a serialisable [`ExecutionEvidence`].
    ///
    /// Computes the final rolling hash, gathers resource metrics, and
    /// produces the evidence hash that binds everything together.
    pub fn finalize(self) -> ExecutionEvidence {
        let wall_clock_ms = self.start.elapsed().as_millis() as u64;
        let cpu_time_ms = get_cpu_time_ms().unwrap_or(wall_clock_ms);
        let peak_rss = get_peak_rss().unwrap_or(0);

        let rolling_content_hash = hex::encode(self.rolling_hasher.finalize());

        let mut languages: Vec<String> = self.languages_detected.into_iter().collect();
        languages.sort();

        // Evidence hash: binding commitment over the key metrics
        let evidence_hash = {
            let mut hasher = Sha256::new();
            hasher.update(self.session_nonce.as_bytes());
            hasher.update(self.files_read.to_le_bytes());
            hasher.update(self.bytes_read.to_le_bytes());
            hasher.update(rolling_content_hash.as_bytes());
            hasher.update(wall_clock_ms.to_le_bytes());
            hex::encode(hasher.finalize())
        };

        ExecutionEvidence {
            session_nonce: self.session_nonce,
            files_read: self.files_read,
            bytes_read: self.bytes_read,
            directories_traversed: self.directories.len(),
            rolling_content_hash,
            wall_clock_ms,
            cpu_time_ms,
            peak_rss,
            checkpoints: self.checkpoints,
            languages_detected: languages,
            evidence_hash,
        }
    }
}

/// Best-effort CPU time in milliseconds (Linux-only via /proc/self/stat).
fn get_cpu_time_ms() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let fields: Vec<&str> = stat.split_whitespace().collect();
        // Fields 13 (utime) and 14 (stime) are in clock ticks
        if fields.len() > 14 {
            let utime: u64 = fields[13].parse().ok()?;
            let stime: u64 = fields[14].parse().ok()?;
            let ticks_per_sec = 100u64; // sysconf(_SC_CLK_TCK) default
            return Some((utime + stime) * 1000 / ticks_per_sec);
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Best-effort peak RSS in bytes (Linux-only via /proc/self/status).
fn get_peak_rss() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if line.starts_with("VmHWM:") {
                let kb_str = line
                    .trim_start_matches("VmHWM:")
                    .trim()
                    .trim_end_matches("kB")
                    .trim();
                let kb: u64 = kb_str.parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulator_basic_flow() {
        let mut acc = EvidenceAccumulator::new("a".repeat(64).as_str());
        acc.record_directory("/tmp/src");
        acc.record_file("src/main.rs", b"fn main() {}", "Rust");
        acc.record_file("src/lib.rs", b"pub mod foo;", "Rust");

        let evidence = acc.finalize();
        assert_eq!(evidence.files_read, 2);
        assert_eq!(evidence.bytes_read, 24); // 12 + 12
        assert_eq!(evidence.directories_traversed, 1);
        assert_eq!(evidence.languages_detected, vec!["Rust".to_string()]);
        assert_eq!(evidence.rolling_content_hash.len(), 64);
        assert_eq!(evidence.evidence_hash.len(), 64);
    }

    #[test]
    fn test_rolling_hash_is_order_dependent() {
        let nonce = "b".repeat(64);

        let mut a = EvidenceAccumulator::new(&nonce);
        a.record_file("a.rs", b"aaa", "Rust");
        a.record_file("b.rs", b"bbb", "Rust");
        let ea = a.finalize();

        let mut b = EvidenceAccumulator::new(&nonce);
        b.record_file("b.rs", b"bbb", "Rust");
        b.record_file("a.rs", b"aaa", "Rust");
        let eb = b.finalize();

        // Different order → different rolling hash
        assert_ne!(ea.rolling_content_hash, eb.rolling_content_hash);
    }

    #[test]
    fn test_checkpoints_emitted_at_interval() {
        let mut acc = EvidenceAccumulator::new(&"c".repeat(64));
        for i in 0..250 {
            let name = format!("file_{}.rs", i);
            acc.record_file(&name, b"x", "Rust");
        }
        let evidence = acc.finalize();
        // 250 files / 100 interval = 2 checkpoints (at 100 and 200)
        assert_eq!(evidence.checkpoints.len(), 2);
        assert_eq!(evidence.checkpoints[0].files_at_checkpoint, 100);
        assert_eq!(evidence.checkpoints[1].files_at_checkpoint, 200);
    }
}

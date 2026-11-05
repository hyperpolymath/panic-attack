// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Replace a file's contents by renaming a fully written temporary file over
//! it.
//!
//! [`write_replacing`] writes the bytes to a new file in the destination's
//! directory, created with `create_new` so it never opens anything that
//! already exists, flushes it to disk, and renames it onto the destination.
//! The rename replaces the directory entry itself. So, unlike [`std::fs::write`]:
//!
//! - a symbolic link at the destination is replaced, never written through;
//! - a file hard-linked to the destination keeps its old contents;
//! - a reader sees the old file or the new one, never a partial write.
//!
//! A file swapped in at the destination between a caller's checks and the
//! write is therefore replaced rather than followed. The replacement is a new
//! file, so it takes default permissions, not the old file's.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Write `contents` to `path` by renaming a temporary file over it (see the
/// module documentation).
pub fn write_replacing(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let (tmp_path, mut file) = create_temp_beside(path)?;
    let written = file
        .write_all(contents.as_ref())
        .and_then(|()| file.sync_all());
    drop(file);
    match written.and_then(|()| fs::rename(&tmp_path, path)) {
        Ok(()) => Ok(()),
        Err(err) => {
            // Best effort: the temporary file is ours and holds nothing else.
            let _ = fs::remove_file(&tmp_path);
            Err(err)
        }
    }
}

/// The directory `path` lives in: its parent, or `.` for a bare file name
/// (whose parent is the empty path).
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Create a new, uniquely named file in `path`'s directory.
fn create_temp_beside(path: &Path) -> io::Result<(PathBuf, fs::File)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = parent_dir(path);
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_string_lossy();
    let mut last_err = None;
    for _ in 0..16 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".{name}.{}.{n}.tmp", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => last_err = Some(err),
            Err(err) => return Err(err),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("no free temporary name")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_replaces_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        write_replacing(&path, "first").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
        write_replacing(&path, "second").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        // No temporary file is left behind.
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn a_hard_linked_file_keeps_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let other = dir.path().join("other");
        fs::write(&other, "untouched").unwrap();
        fs::hard_link(&other, &path).unwrap();
        write_replacing(&path, "new").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(fs::read_to_string(&other).unwrap(), "untouched");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_replaced_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let target = dir.path().join("target");
        fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        write_replacing(&path, "new").unwrap();
        assert!(!fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_does_not_create_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let target = dir.path().join("report.kyaml");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        write_replacing(&path, "new").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert!(!target.exists());
    }

    #[test]
    fn a_bare_file_name_lives_in_the_working_directory() {
        assert_eq!(parent_dir(Path::new("report.json")), Path::new("."));
        assert_eq!(parent_dir(Path::new("out/report.json")), Path::new("out"));
        assert_eq!(parent_dir(Path::new("/report.json")), Path::new("/"));
    }
}

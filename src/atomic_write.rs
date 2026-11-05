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
//! write is therefore replaced rather than followed.
//!
//! Permissions: on Unix the temporary file is opened with the destination's
//! mode (less the umask) in the `open` call itself, then given that mode
//! exactly, so it is never readable more widely than the file it replaces and
//! replacing a `0600` report never exposes its contents. A new
//! destination gets the same default as `fs::write` (`0666` less the umask).
//! Ownership is not copied, and on other platforms the new file takes the
//! directory's default permissions.
//!
//! The temporary file has a short, unpredictable name (`.pa-tmp.<pid>.<n>.<random>`),
//! so a destination name near the filesystem's length limit still works.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Write `contents` to `path` by renaming a temporary file over it (see the
/// module documentation).
pub fn write_replacing(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    write_replacing_like(path, contents, None)
}

/// [`write_replacing`] for a file that accompanies another: when `path` does
/// not exist yet, it takes the permission bits of the regular file at `like`
/// rather than the default, so a copy of a private report is private too. An
/// existing `path` keeps its own bits.
pub fn write_replacing_like(
    path: &Path,
    contents: impl AsRef<[u8]>,
    like: Option<&Path>,
) -> io::Result<()> {
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path has no file name",
        ));
    }
    let mode = existing_mode(path).or_else(|| like.and_then(existing_mode));
    let (tmp_path, mut file) = create_temp_in(parent_dir(path), mode)?;
    let written = restore_mode(&file, mode)
        .and_then(|()| file.write_all(contents.as_ref()))
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

/// The permission bits of the regular file at `path`, if there is one. A
/// symlink or other non-regular entry lends nothing.
#[cfg(unix)]
fn existing_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path)
        .ok()
        .filter(fs::Metadata::is_file)
        .map(|meta| meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn existing_mode(_path: &Path) -> Option<u32> {
    None
}

/// Set the kept mode exactly. The file was opened with that mode less the
/// umask, so this can only add bits the destination already had.
#[cfg(unix)]
fn restore_mode(file: &fs::File, mode: Option<u32>) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match mode {
        Some(mode) => file.set_permissions(fs::Permissions::from_mode(mode)),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
fn restore_mode(_file: &fs::File, _mode: Option<u32>) -> io::Result<()> {
    Ok(())
}

/// The directory `path` lives in: its parent, or `.` for a bare file name
/// (whose parent is the empty path).
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Create a new file with an unpredictable name in `dir`.
///
/// On Unix it is opened with `mode` (or `0666` for a new destination), less
/// the umask, in the `open` call itself, so it is never readable more widely
/// than the file it replaces, or than `fs::write` would create.
fn create_temp_in(dir: &Path, mode: Option<u32>) -> io::Result<(PathBuf, fs::File)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode.unwrap_or(0o666) & 0o777);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut last_err = None;
    for _ in 0..16 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut random = [0_u8; 8];
        // A predictable name only costs a retry, so a failed RNG is not fatal.
        let _ = getrandom::fill(&mut random);
        let tmp = dir.join(format!(
            ".pa-tmp.{}.{n}.{}",
            std::process::id(),
            hex::encode(random)
        ));
        match options.open(&tmp) {
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

    #[cfg(unix)]
    #[test]
    fn an_existing_files_permissions_are_kept() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o640, 0o644] {
            let path = dir.path().join(format!("report-{mode:o}.json"));
            fs::write(&path, "old").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            write_replacing(&path, "new").unwrap();
            let got = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            assert_eq!(got, mode, "mode {mode:o} not kept");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_new_file_gets_the_fs_write_default() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ours = dir.path().join("ours");
        let theirs = dir.path().join("theirs");
        write_replacing(&ours, "x").unwrap();
        fs::write(&theirs, "x").unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&ours), mode(&theirs));
    }

    #[test]
    fn a_destination_name_near_the_length_limit_works() {
        // 250 bytes leaves room for `.json`/`.kyaml` within a 255-byte
        // component limit; the temporary name must not grow with it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{}.kyaml", "r".repeat(249)));
        assert_eq!(path.file_name().unwrap().len(), 255);
        write_replacing(&path, "ok").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "ok");
    }

    #[cfg(unix)]
    #[test]
    fn the_temporary_file_is_never_wider_than_the_destination() {
        // Checked straight after `open`, before any `set_permissions`: a
        // reader who opens the temporary file early must find it no more
        // readable than the file it will replace.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o640, 0o400] {
            let (tmp, _file) = create_temp_in(dir.path(), Some(mode)).unwrap();
            let got = fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
            assert_eq!(got & !mode, 0, "temp {got:o} wider than {mode:o}");
            fs::remove_file(tmp).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_new_companion_takes_the_mode_of_the_file_it_accompanies() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        fs::write(&report, "{}").unwrap();
        fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).unwrap();
        // A new copy follows the report.
        let copy = dir.path().join("report.kyaml");
        write_replacing_like(&copy, "new", Some(&report)).unwrap();
        assert_eq!(mode(&copy), 0o600);
        // An existing file keeps its own bits.
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o640)).unwrap();
        write_replacing_like(&copy, "again", Some(&report)).unwrap();
        assert_eq!(mode(&copy), 0o640);
    }
}

//! Caller-owned local persistence primitives.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) struct ExclusiveFileLock {
    path: PathBuf,
    token: Vec<u8>,
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        if fs::read(&self.path).is_ok_and(|bytes| bytes == self.token)
            && fs::remove_file(&self.path).is_ok()
        {
            let _ = sync_parent_directory(&self.path);
        }
    }
}

pub(crate) fn acquire_file_lock(path: &Path, purpose: &str) -> Result<ExclusiveFileLock> {
    static NEXT_LOCK_ID: AtomicU64 = AtomicU64::new(0);
    let lock_path = path.with_extension("lock");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let token = format!(
        "{}:{}:{}",
        std::process::id(),
        timestamp,
        NEXT_LOCK_ID.fetch_add(1, Ordering::Relaxed)
    )
    .into_bytes();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    for _ in 0..500 {
        match options.open(&lock_path) {
            Ok(mut file) => {
                let guard = ExclusiveFileLock {
                    path: lock_path,
                    token: token.clone(),
                };
                let written = (|| -> Result<()> {
                    file.write_all(&token)?;
                    file.sync_all()?;
                    drop(file);
                    sync_parent_directory(&guard.path)
                })();
                if let Err(error) = written {
                    drop(guard);
                    return Err(error);
                }
                return Ok(guard);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(Error::Persistence(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("timed out waiting for {purpose} writer lock"),
    )))
}

pub(crate) fn save_atomic_snapshot(path: &Path, bytes: &[u8], purpose: &str) -> Result<()> {
    let _lock = acquire_file_lock(path, purpose)?;
    save_atomic_snapshot_locked(path, bytes)
}

pub(crate) fn read_regular_snapshot(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(Error::Persistence(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot is not a regular file",
        )));
    }
    Ok(fs::read(path)?)
}

/// The caller must hold the lock returned by `acquire_file_lock` for `path`.
pub(crate) fn save_atomic_snapshot_locked(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    sync_parent_directory(path)
}

pub(crate) fn recover_atomic_snapshot<T>(
    path: &Path,
    purpose: &str,
    load: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    let _lock = acquire_file_lock(path, purpose)?;
    let temporary = path.with_extension("tmp");
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.is_file() => {
            let snapshot = load(&temporary)?;
            fs::rename(temporary, path)?;
            sync_parent_directory(path)?;
            Ok(snapshot)
        }
        Ok(_) => Err(Error::Persistence(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{purpose} pending snapshot is not a regular file"),
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => load(path),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn recovery_rejects_pending_symlink_without_replacing_primary() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        let target = directory.path().join("target.json");
        let temporary = path.with_extension("tmp");
        fs::write(&path, b"primary").unwrap();
        fs::write(&target, b"valid pending bytes").unwrap();
        std::os::unix::fs::symlink(&target, &temporary).unwrap();

        let result =
            recover_atomic_snapshot(&path, "test snapshot", |candidate| Ok(fs::read(candidate)?));

        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"primary");
        assert!(fs::symlink_metadata(&temporary)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_read_rejects_primary_symlink() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        let target = directory.path().join("target.json");
        fs::write(&target, b"snapshot bytes").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert!(read_regular_snapshot(&path).is_err());
    }
}

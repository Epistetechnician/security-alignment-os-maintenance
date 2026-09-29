//! Caller-owned custody-root and retention records.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! These records describe caller-owned custody without storing raw bytes or
//! private locators. The registry validates declared lifecycle relationships
//! and canonical persistence. `verify_local_artifact` additionally performs a
//! bounded, read-only local filesystem and digest check. Neither path maps the
//! declared owner identity to an OS UID or enforces deletion.

use crate::persistence::{read_regular_snapshot, recover_atomic_snapshot, save_atomic_snapshot};
use crate::{canonical_bytes, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::{self, File, Metadata};
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::path::Component;
use std::path::Path;

pub const STATE_SLICE: &str = "security-alignment-os-foundation-v1";
pub const MAX_RAW_RETENTION_SECONDS: u64 = 72 * 60 * 60;

/// Transient path inputs for read-only local custody verification.
///
/// These paths are used for one verification and are never persisted in the
/// custody registry.
#[derive(Clone, Copy, Debug)]
pub struct LocalCustodyPaths<'a> {
    pub root_path: &'a Path,
    pub repository_root: &'a Path,
    pub artifact_relative_path: &'a Path,
    pub max_bytes: u64,
}

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(|character| character.is_control())
}

/// A declaration for an owner-only external custody root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodyRoot {
    pub root_id: String,
    pub owner_id: String,
    /// Digest of the root declaration; the locator itself is never retained.
    pub root_digest: String,
    /// Unix mode assertion required by the contract.
    pub mode: u32,
    pub external_to_repository: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub raw_retention_until: u64,
}

impl CustodyRoot {
    pub fn validate(&self) -> Result<()> {
        if !valid_text(&self.root_id, 128)
            || !valid_text(&self.owner_id, 256)
            || !valid_digest(&self.root_digest)
            || self.mode != 0o700
            || !self.external_to_repository
            || self.created_at >= self.expires_at
            || self.raw_retention_until < self.created_at
            || self.raw_retention_until > self.expires_at
            || self.raw_retention_until - self.created_at > MAX_RAW_RETENTION_SECONDS
        {
            return Err(Error::Invalid(
                "custody root declaration is malformed".into(),
            ));
        }
        Ok(())
    }

    pub fn active(&self, now: u64) -> bool {
        self.validate().is_ok() && self.created_at <= now && now < self.expires_at
    }

    pub fn raw_retention_active(&self, now: u64) -> bool {
        self.validate().is_ok() && self.created_at <= now && now < self.raw_retention_until
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CustodyStatus {
    Active,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodyRecord {
    pub custody_id: String,
    pub root: CustodyRoot,
    pub artifact_digest: String,
    /// Owner assertion that declared the record.
    pub declared_by: String,
    /// Separate local validator assertion.
    pub validator_id: String,
    pub status: CustodyStatus,
    pub deleted_at: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodyRegistry {
    records: BTreeMap<String, CustodyRecord>,
}

impl CustodyRegistry {
    fn validate_record(key: &str, record: &CustodyRecord) -> Result<()> {
        if key != record.custody_id
            || !valid_text(&record.custody_id, 128)
            || !valid_digest(&record.artifact_digest)
            || record.declared_by != record.root.owner_id
            || !valid_text(&record.declared_by, 256)
            || !valid_text(&record.validator_id, 256)
            || record.declared_by == record.validator_id
        {
            return Err(Error::Invalid("custody record binding is malformed".into()));
        }
        record.root.validate()?;
        match record.status {
            CustodyStatus::Active if record.deleted_at.is_some() => Err(Error::Invalid(
                "active custody record cannot have a deletion time".into(),
            )),
            CustodyStatus::Deleted => {
                let deleted_at = record.deleted_at.ok_or_else(|| {
                    Error::Invalid("deleted custody record lacks deletion time".into())
                })?;
                if deleted_at < record.root.created_at {
                    return Err(Error::Invalid(
                        "custody deletion predates root creation".into(),
                    ));
                }
                Ok(())
            }
            CustodyStatus::Active => Ok(()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        for (key, record) in &self.records {
            Self::validate_record(key, record)?;
        }
        Ok(())
    }

    /// Declares a record under the root owner identity and a separate
    /// validator assertion.
    pub fn declare(
        &mut self,
        custody_id: impl Into<String>,
        root: CustodyRoot,
        artifact_digest: impl Into<String>,
        declared_by: impl Into<String>,
        validator_id: impl Into<String>,
    ) -> Result<()> {
        root.validate()?;
        let record = CustodyRecord {
            custody_id: custody_id.into(),
            root,
            artifact_digest: artifact_digest.into(),
            declared_by: declared_by.into(),
            validator_id: validator_id.into(),
            status: CustodyStatus::Active,
            deleted_at: None,
        };
        Self::validate_record(&record.custody_id, &record)?;
        if self.records.contains_key(&record.custody_id) {
            return Err(Error::Rejected("custody identity already exists".into()));
        }
        self.records.insert(record.custody_id.clone(), record);
        Ok(())
    }

    pub fn require_active(
        &self,
        custody_id: &str,
        artifact_digest: &str,
        now: u64,
    ) -> Result<&CustodyRecord> {
        if !valid_digest(artifact_digest) {
            return Err(Error::Invalid(
                "custody artifact digest is malformed".into(),
            ));
        }
        let record = self
            .records
            .get(custody_id)
            .ok_or_else(|| Error::Quarantined("custody record is unavailable".into()))?;
        if record.status != CustodyStatus::Active
            || !record.root.active(now)
            || !record.root.raw_retention_active(now)
            || record.artifact_digest != artifact_digest
        {
            return Err(Error::Rejected(
                "custody record is inactive, retention-expired, or digest-mismatched".into(),
            ));
        }
        Ok(record)
    }

    /// Requires an active record bound to the artifact digest and manifest root identifier.
    pub fn require_artifact(
        &self,
        custody_id: &str,
        root_id: &str,
        artifact_digest: &str,
        now: u64,
    ) -> Result<&CustodyRecord> {
        let record = self.require_active(custody_id, artifact_digest, now)?;
        if record.root.root_id != root_id {
            return Err(Error::Rejected("custody root binding mismatch".into()));
        }
        Ok(record)
    }

    /// Verifies a local custody directory and exact artifact bytes before use.
    ///
    /// `repository_root` is a caller-supplied anchor. On Unix, filesystem
    /// ownership is checked against the process effective UID, not a caller
    /// supplied UID. The check rejects symlinks, broad permissions, foreign
    /// ownership, oversized files, and digest mismatches, but cannot map the
    /// declared owner identity to that UID or prevent the same UID from
    /// changing owned files and directories.
    pub fn verify_local_artifact(
        &self,
        custody_id: &str,
        root_id: &str,
        artifact_digest: &str,
        now: u64,
        paths: LocalCustodyPaths<'_>,
    ) -> Result<&CustodyRecord> {
        let record = self.require_artifact(custody_id, root_id, artifact_digest, now)?;
        verify_local_paths(paths, artifact_digest)?;
        Ok(record)
    }

    pub fn mark_deleted(&mut self, custody_id: &str, owner_id: &str, now: u64) -> Result<()> {
        let record = self
            .records
            .get_mut(custody_id)
            .ok_or_else(|| Error::Invalid("custody record is unavailable".into()))?;
        if record.status != CustodyStatus::Active {
            return Err(Error::Rejected("custody record is already deleted".into()));
        }
        if owner_id != record.root.owner_id {
            return Err(Error::Rejected(
                "only the declared owner may delete custody".into(),
            ));
        }
        if now < record.root.created_at {
            return Err(Error::Rejected(
                "custody deletion time is before creation".into(),
            ));
        }
        record.status = CustodyStatus::Deleted;
        record.deleted_at = Some(now);
        Ok(())
    }

    pub fn get(&self, custody_id: &str) -> Option<&CustodyRecord> {
        self.records.get(custody_id)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        save_atomic_snapshot(path, &canonical_bytes(self)?, "custody registry")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_regular_snapshot(path)?;
        let registry: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&registry)? != bytes {
            return Err(Error::Journal(
                "custody bytes are not canonical JSON".into(),
            ));
        }
        registry.validate()?;
        Ok(registry)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        recover_atomic_snapshot(path, "custody registry", Self::load)
    }
}

fn local_custody_rejection(message: &str) -> Error {
    Error::Rejected(format!("local custody verification failed: {message}"))
}

#[cfg(unix)]
fn verify_local_directory_metadata(
    metadata: &Metadata,
    effective_owner_uid: u32,
    custody_root: bool,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    if !metadata.is_dir() || metadata.uid() != effective_owner_uid {
        return Err(local_custody_rejection(
            "custody directory type or owner UID is invalid",
        ));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    let private_directory = mode & 0o077 == 0 && mode & 0o7000 == 0 && mode & 0o500 == 0o500;
    if (custody_root && mode != 0o700) || (!custody_root && !private_directory) {
        return Err(local_custody_rejection(
            "custody directory permissions are not private",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_local_file_metadata(metadata: &Metadata, effective_owner_uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.is_file()
        || metadata.uid() != effective_owner_uid
        || mode & 0o400 == 0
        || mode & 0o077 != 0
        || mode & 0o7000 != 0
    {
        return Err(local_custody_rejection(
            "artifact type, owner UID, or permissions are invalid",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &std::ffi::OsStr) -> Result<File> {
    use rustix::fs::{openat, Mode, OFlags};

    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| local_custody_rejection("directory component could not be opened safely"))?;
    Ok(File::from(descriptor))
}

#[cfg(unix)]
fn open_directory_path_no_symlinks(path: &Path) -> Result<File> {
    let mut current = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => current = open_directory_at(&current, name)?,
            _ => {
                return Err(local_custody_rejection(
                    "canonical directory path is not normalized",
                ));
            }
        }
    }
    Ok(current)
}

#[cfg(unix)]
trait LocalArtifactReader: Read {
    fn metadata(&self) -> std::io::Result<Metadata>;
}

#[cfg(unix)]
impl LocalArtifactReader for File {
    fn metadata(&self) -> std::io::Result<Metadata> {
        File::metadata(self)
    }
}

#[cfg(unix)]
fn verify_open_local_artifact<R: LocalArtifactReader>(
    file: &mut R,
    max_bytes: u64,
    expected_digest: &str,
    effective_owner_uid: u32,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let opened_metadata = file.metadata()?;
    verify_local_file_metadata(&opened_metadata, effective_owner_uid)?;
    if opened_metadata.len() > max_bytes {
        return Err(local_custody_rejection(
            "artifact exceeds the declared byte limit",
        ));
    }
    if opened_metadata.nlink() != 1 {
        return Err(local_custody_rejection("artifact has multiple hard links"));
    }

    let initial_fingerprint = local_file_fingerprint(&opened_metadata);
    let mut hasher = Sha256::new();
    let mut bytes_read = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    {
        let mut limited_reader = (&mut *file).take(max_bytes.saturating_add(1));
        loop {
            let count = limited_reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            bytes_read = bytes_read
                .checked_add(count as u64)
                .ok_or_else(|| local_custody_rejection("artifact size overflow"))?;
            if bytes_read > max_bytes {
                return Err(local_custody_rejection(
                    "artifact exceeds the declared byte limit",
                ));
            }
            hasher.update(&buffer[..count]);
        }
    }

    let final_metadata = file.metadata()?;
    if bytes_read != opened_metadata.len()
        || final_metadata.len() != opened_metadata.len()
        || local_file_fingerprint(&final_metadata) != initial_fingerprint
    {
        return Err(local_custody_rejection(
            "artifact changed while it was read",
        ));
    }
    let actual_digest = format!("{:x}", hasher.finalize());
    if actual_digest != expected_digest {
        return Err(local_custody_rejection("artifact digest mismatch"));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_local_paths(paths: LocalCustodyPaths<'_>, expected_digest: &str) -> Result<()> {
    const MAX_LOCAL_ARTIFACT_COMPONENTS: usize = 128;
    let effective_owner_uid = rustix::process::geteuid().as_raw();

    if paths.max_bytes == 0 {
        return Err(local_custody_rejection("byte limit must be positive"));
    }
    let components: Vec<_> = paths.artifact_relative_path.components().collect();
    if components.is_empty()
        || components.len() > MAX_LOCAL_ARTIFACT_COMPONENTS
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(local_custody_rejection(
            "artifact path must contain only normal relative components",
        ));
    }

    let root_metadata = fs::symlink_metadata(paths.root_path)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(local_custody_rejection(
            "custody root is not a real directory",
        ));
    }
    let canonical_root = fs::canonicalize(paths.root_path)?;
    let canonical_repository = fs::canonicalize(paths.repository_root)?;
    if !fs::metadata(&canonical_repository)?.is_dir() {
        return Err(local_custody_rejection(
            "repository anchor is not a directory",
        ));
    }
    if canonical_root.starts_with(&canonical_repository)
        || canonical_repository.starts_with(&canonical_root)
    {
        return Err(local_custody_rejection(
            "custody root overlaps the repository anchor",
        ));
    }

    let mut custody_directory = open_directory_path_no_symlinks(&canonical_root)?;
    verify_local_directory_metadata(&custody_directory.metadata()?, effective_owner_uid, true)?;

    for component in components.iter().take(components.len() - 1) {
        let Component::Normal(name) = component else {
            return Err(local_custody_rejection("artifact path is not normalized"));
        };
        custody_directory = open_directory_at(&custody_directory, name)?;
        verify_local_directory_metadata(
            &custody_directory.metadata()?,
            effective_owner_uid,
            false,
        )?;
    }

    let Component::Normal(file_name) = components
        .last()
        .ok_or_else(|| local_custody_rejection("artifact path is unavailable"))?
    else {
        return Err(local_custody_rejection("artifact path is not normalized"));
    };
    let mut file = {
        use rustix::fs::{openat, Mode, OFlags};

        let descriptor = openat(
            &custody_directory,
            *file_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| local_custody_rejection("artifact file could not be opened safely"))?;
        File::from(descriptor)
    };
    verify_open_local_artifact(
        &mut file,
        paths.max_bytes,
        expected_digest,
        effective_owner_uid,
    )
}

#[cfg(unix)]
fn local_file_fingerprint(metadata: &Metadata) -> (u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt;

    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

#[cfg(not(unix))]
fn verify_local_paths(_paths: LocalCustodyPaths<'_>, _expected_digest: &str) -> Result<()> {
    Err(local_custody_rejection(
        "descriptor-relative custody verification is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> CustodyRoot {
        CustodyRoot {
            root_id: "root-1".into(),
            owner_id: "owner".into(),
            root_digest: "a".repeat(64),
            mode: 0o700,
            external_to_repository: true,
            created_at: 10,
            expires_at: 100,
            raw_retention_until: 90,
        }
    }

    #[cfg(unix)]
    fn local_registry(artifact_digest: &str) -> CustodyRegistry {
        let mut registry = CustodyRegistry::default();
        registry
            .declare("custody-1", root(), artifact_digest, "owner", "validator")
            .expect("declare local custody");
        registry
    }

    #[cfg(unix)]
    fn local_root(contents: &[u8]) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary parent");
        let root_path = directory.path().join("custody-root");
        fs::create_dir(&root_path).expect("create custody root");
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))
            .expect("set custody root permissions");
        let artifact_path = root_path.join("artifact.bin");
        fs::write(&artifact_path, contents).expect("write artifact");
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o600))
            .expect("set artifact permissions");
        (directory, root_path)
    }

    #[cfg(unix)]
    fn local_paths<'a>(root_path: &'a Path, relative_path: &'a Path) -> LocalCustodyPaths<'a> {
        LocalCustodyPaths {
            root_path,
            repository_root: Path::new(env!("CARGO_MANIFEST_DIR")),
            artifact_relative_path: relative_path,
            max_bytes: 1024,
        }
    }

    #[test]
    fn owner_declared_custody_is_bound_and_deletion_is_terminal() {
        let artifact_digest = "b".repeat(64);
        let mut registry = CustodyRegistry::default();
        registry
            .declare(
                "custody-1",
                root(),
                artifact_digest.clone(),
                "owner",
                "validator",
            )
            .expect("declare");
        assert!(registry
            .require_active("custody-1", &artifact_digest, 20)
            .is_ok());
        assert!(registry
            .require_active("custody-1", &"c".repeat(64), 20)
            .is_err());
        assert!(registry.mark_deleted("custody-1", "other", 30).is_err());
        registry
            .mark_deleted("custody-1", "owner", 30)
            .expect("delete");
        assert!(registry
            .require_active("custody-1", &artifact_digest, 30)
            .is_err());
        assert!(registry.mark_deleted("custody-1", "owner", 31).is_err());
    }

    #[test]
    fn raw_retention_deadline_is_exclusive_for_active_custody() {
        let artifact_digest = "b".repeat(64);
        let mut declaration = root();
        declaration.raw_retention_until = 40;
        let mut registry = CustodyRegistry::default();
        registry
            .declare(
                "custody-1",
                declaration,
                artifact_digest.clone(),
                "owner",
                "validator",
            )
            .expect("declare");

        assert!(registry
            .require_active("custody-1", &artifact_digest, 39)
            .is_ok());
        assert!(registry
            .require_active("custody-1", &artifact_digest, 40)
            .is_err());
    }

    #[test]
    fn artifact_custody_requires_root_and_digest_bindings() {
        let artifact_digest = "b".repeat(64);
        let mut registry = CustodyRegistry::default();
        registry
            .declare(
                "custody-1",
                root(),
                artifact_digest.clone(),
                "owner",
                "validator",
            )
            .expect("declare");

        assert!(registry
            .require_artifact("custody-1", "root-1", &artifact_digest, 20)
            .is_ok());
        assert!(registry
            .require_artifact("custody-1", "other-root", &artifact_digest, 20)
            .is_err());
        assert!(registry
            .require_artifact("custody-1", "root-1", &"c".repeat(64), 20)
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_artifact_verification_binds_exact_bytes_and_root() {
        use std::os::unix::fs::MetadataExt;

        let contents = b"locally retained synthetic artifact";
        let artifact_digest = crate::digest_bytes(contents);
        let registry = local_registry(&artifact_digest);
        let (_directory, root_path) = local_root(contents);
        let relative_path = Path::new("artifact.bin");
        assert_eq!(
            fs::metadata(&root_path)
                .expect("custody root metadata")
                .uid(),
            rustix::process::geteuid().as_raw()
        );

        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &artifact_digest,
                20,
                local_paths(&root_path, relative_path),
            )
            .is_ok());
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "different-root",
                &artifact_digest,
                20,
                local_paths(&root_path, relative_path),
            )
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_directory_owner_check_rejects_a_mismatched_uid() {
        use std::os::unix::fs::MetadataExt;

        let contents = b"locally retained synthetic artifact";
        let (_directory, root_path) = local_root(contents);
        let root_metadata = fs::metadata(&root_path).expect("custody root metadata");
        let actual_uid = root_metadata.uid();
        let wrong_uid = if actual_uid == u32::MAX {
            actual_uid - 1
        } else {
            actual_uid + 1
        };

        assert!(verify_local_directory_metadata(&root_metadata, wrong_uid, true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_artifact_verification_rejects_traversal_symlinks_and_broad_modes() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let contents = b"local artifact";
        let artifact_digest = crate::digest_bytes(contents);
        let registry = local_registry(&artifact_digest);

        let (_directory, root_path) = local_root(contents);
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &artifact_digest,
                20,
                local_paths(&root_path, Path::new("../artifact.bin")),
            )
            .is_err());

        let (directory, nested_symlink_root) = local_root(contents);
        let outside_directory = directory.path().join("outside-directory");
        fs::create_dir(&outside_directory).expect("create outside directory");
        fs::set_permissions(&outside_directory, fs::Permissions::from_mode(0o700))
            .expect("set outside directory permissions");
        let outside_artifact = outside_directory.join("artifact.bin");
        fs::write(&outside_artifact, contents).expect("write outside artifact");
        fs::set_permissions(&outside_artifact, fs::Permissions::from_mode(0o600))
            .expect("set outside artifact permissions");
        symlink(
            &outside_directory,
            nested_symlink_root.join("linked-directory"),
        )
        .expect("create intermediate directory symlink");
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &artifact_digest,
                20,
                local_paths(
                    &nested_symlink_root,
                    Path::new("linked-directory/artifact.bin"),
                ),
            )
            .is_err());

        let (directory, hardlink_root) = local_root(contents);
        fs::hard_link(
            hardlink_root.join("artifact.bin"),
            directory.path().join("second-name.bin"),
        )
        .expect("create second hard link");
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &artifact_digest,
                20,
                local_paths(&hardlink_root, Path::new("artifact.bin")),
            )
            .is_err());

        let (overlap_parent, overlap_root) = local_root(contents);
        let mut overlapping_paths = local_paths(&overlap_root, Path::new("artifact.bin"));
        overlapping_paths.repository_root = overlap_parent.path();
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &artifact_digest,
                20,
                overlapping_paths,
            )
            .is_err());

        let (directory, symlink_root) = local_root(contents);
        let outside_path = directory.path().join("outside.bin");
        fs::write(&outside_path, contents).expect("write outside target");
        fs::set_permissions(&outside_path, fs::Permissions::from_mode(0o600))
            .expect("set outside target permissions");
        let linked_path = symlink_root.join("artifact.bin");
        fs::remove_file(&linked_path).expect("remove original artifact");
        symlink(&outside_path, &linked_path).expect("create artifact symlink");
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &artifact_digest,
                20,
                local_paths(&symlink_root, Path::new("artifact.bin")),
            )
            .is_err());

        let root_alias = directory.path().join("custody-root-link");
        symlink(&symlink_root, &root_alias).expect("create custody root symlink");
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &artifact_digest,
                20,
                local_paths(&root_alias, Path::new("artifact.bin")),
            )
            .is_err());

        let (_directory, broad_root) = local_root(contents);
        let broad_file = broad_root.join("artifact.bin");
        fs::set_permissions(&broad_file, fs::Permissions::from_mode(0o644))
            .expect("broaden artifact permissions");
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &artifact_digest,
                20,
                local_paths(&broad_root, Path::new("artifact.bin")),
            )
            .is_err());

        fs::set_permissions(&broad_file, fs::Permissions::from_mode(0o600))
            .expect("restore artifact permissions");
        fs::set_permissions(&broad_root, fs::Permissions::from_mode(0o755))
            .expect("broaden custody root permissions");
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &artifact_digest,
                20,
                local_paths(&broad_root, Path::new("artifact.bin")),
            )
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_artifact_verification_rejects_wrong_digest_and_oversized_file() {
        use std::os::unix::fs::PermissionsExt;

        let expected = b"expected bytes";
        let expected_digest = crate::digest_bytes(expected);
        let registry = local_registry(&expected_digest);
        let (_directory, root_path) = local_root(b"different bytes");
        let relative_path = Path::new("artifact.bin");
        assert!(registry
            .verify_local_artifact(
                "custody-1",
                "root-1",
                &expected_digest,
                20,
                local_paths(&root_path, relative_path),
            )
            .is_err());

        fs::write(root_path.join("artifact.bin"), expected).expect("write expected artifact");
        fs::set_permissions(
            root_path.join("artifact.bin"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("restore private artifact permissions");
        let mut paths = local_paths(&root_path, relative_path);
        paths.max_bytes = 1;
        assert!(registry
            .verify_local_artifact("custody-1", "root-1", &expected_digest, 20, paths)
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_artifact_verification_detects_mutation_during_read() {
        use std::fs::OpenOptions;
        use std::io::{Seek, SeekFrom, Write};

        struct MutatingReader {
            reader: File,
            writer: File,
            replacement: Vec<u8>,
            changed: bool,
        }

        impl Read for MutatingReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if !self.changed {
                    self.writer.seek(SeekFrom::Start(0))?;
                    self.writer.write_all(&self.replacement)?;
                    self.writer.flush()?;
                    self.changed = true;
                }
                self.reader.read(buffer)
            }
        }

        impl LocalArtifactReader for MutatingReader {
            fn metadata(&self) -> std::io::Result<Metadata> {
                self.reader.metadata()
            }
        }

        let original = vec![b'a'; 64 * 1024];
        let replacement = vec![b'b'; original.len()];
        let expected_digest = crate::digest_bytes(&original);
        let (_directory, root_path) = local_root(&original);
        let artifact_path = root_path.join("artifact.bin");
        let mut reader = MutatingReader {
            reader: File::open(&artifact_path).expect("open artifact for reading"),
            writer: OpenOptions::new()
                .read(true)
                .write(true)
                .open(&artifact_path)
                .expect("open artifact for mutation"),
            replacement,
            changed: false,
        };

        let result = verify_open_local_artifact(
            &mut reader,
            128 * 1024,
            &expected_digest,
            rustix::process::geteuid().as_raw(),
        );

        reader
            .writer
            .seek(SeekFrom::Start(0))
            .expect("rewind artifact");
        reader
            .writer
            .write_all(&original)
            .expect("restore artifact bytes");
        reader.writer.flush().expect("flush restored artifact");

        assert!(matches!(
            result,
            Err(Error::Rejected(message)) if message.contains("artifact changed while it was read")
        ));
        assert_eq!(
            fs::read(artifact_path).expect("read restored artifact"),
            original
        );
    }

    #[test]
    fn malformed_roots_and_duplicate_records_fail_closed() {
        let artifact_digest = "b".repeat(64);
        let mut registry = CustodyRegistry::default();
        let mut invalid = root();
        invalid.mode = 0o755;
        assert!(registry
            .declare(
                "custody-1",
                invalid,
                artifact_digest.clone(),
                "owner",
                "validator",
            )
            .is_err());
        registry
            .declare("custody-1", root(), artifact_digest, "owner", "validator")
            .expect("declare");
        assert!(registry
            .declare("custody-1", root(), "b".repeat(64), "owner", "validator-2",)
            .is_err());
    }

    #[test]
    fn registry_round_trip_and_recovery_are_canonical() {
        let mut registry = CustodyRegistry::default();
        registry
            .declare("custody-1", root(), "b".repeat(64), "owner", "validator")
            .expect("declare");
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("custody.json");
        registry.save(&path).expect("save");
        assert_eq!(CustodyRegistry::load(&path).expect("load"), registry);
        let bytes = crate::canonical_bytes(&registry).expect("canonical");
        std::fs::write(path.with_extension("tmp"), bytes).expect("temp");
        std::fs::remove_file(&path).expect("remove");
        assert_eq!(CustodyRegistry::recover(&path).expect("recover"), registry);
    }
}

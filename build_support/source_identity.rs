#![allow(dead_code)] // This shared module is compiled by build.rs, the identity CLI, and tests.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageBuildIdentity {
    pub implementation_revision: String,
    pub source_tree_sha256: String,
}

pub fn validate_revision(revision: &str) -> Result<(), String> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("revision must be 40 lowercase hexadecimal characters".into());
    }
    Ok(())
}

pub fn validate_sha256(digest: &str) -> Result<(), String> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("source digest must be 64 lowercase hexadecimal characters".into());
    }
    Ok(())
}

pub fn source_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for required in [Path::new("Cargo.toml"), Path::new("Cargo.lock")] {
        let metadata = fs::symlink_metadata(root.join(required)).map_err(|error| {
            format!(
                "required source input is missing: {} ({error})",
                required.display()
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "required source input is not a regular file: {}",
                required.display()
            ));
        }
        files.push(required.to_owned());
    }
    for required in [
        Path::new("build.rs"),
        Path::new("build_support"),
        Path::new("infra/nitro-enclave"),
    ] {
        if !root.join(required).exists() {
            return Err(format!(
                "required source input is missing: {}",
                required.display()
            ));
        }
        collect_files(root, required, &mut files)?;
    }
    collect_files(root, Path::new("src"), &mut files)?;
    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_files(root: &Path, relative: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    reject_symlink_parents(root, relative)?;
    let full = root.join(relative);
    let metadata = fs::symlink_metadata(&full)
        .map_err(|error| format!("could not inspect {}: {error}", relative.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "symlink source inputs are forbidden: {}",
            relative.display()
        ));
    }
    if metadata.is_file() {
        files.push(relative.to_owned());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(format!("unsupported source input: {}", relative.display()));
    }

    let mut children = fs::read_dir(&full)
        .map_err(|error| format!("could not read {}: {error}", relative.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| format!("could not list {}: {error}", relative.display()))?;
    children.sort();
    for child in children {
        let child_relative = child
            .strip_prefix(root)
            .map_err(|_| "source input escaped repository root".to_string())?;
        collect_files(root, child_relative, files)?;
    }
    Ok(())
}

fn reject_symlink_parents(root: &Path, relative: &Path) -> Result<(), String> {
    let components = relative.components().collect::<Vec<_>>();
    let mut parent = PathBuf::new();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        parent.push(component.as_os_str());
        let metadata = fs::symlink_metadata(root.join(&parent))
            .map_err(|error| format!("could not inspect {}: {error}", parent.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "source path has an unsafe parent: {}",
                parent.display()
            ));
        }
    }
    Ok(())
}

pub fn source_tree_sha256(root: &Path) -> Result<String, String> {
    let files = source_files(root)?;
    let mut hasher = Sha256::new();
    for relative in files {
        let relative_text = relative
            .to_str()
            .ok_or_else(|| format!("source path is not UTF-8: {}", relative.display()))?;
        let relative_bytes = relative_text.as_bytes();
        let metadata = fs::metadata(root.join(&relative))
            .map_err(|error| format!("could not stat {}: {error}", relative.display()))?;
        let bytes = fs::read(root.join(&relative))
            .map_err(|error| format!("could not read {}: {error}", relative.display()))?;

        hasher.update((relative_bytes.len() as u64).to_be_bytes());
        hasher.update(relative_bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            hasher.update((metadata.permissions().mode() & 0o7777).to_be_bytes());
        }
        #[cfg(not(unix))]
        hasher.update(0o644_u32.to_be_bytes());
        hasher.update(b"F");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hex(&hasher.finalize()))
}

pub fn verify_source_digest(root: &Path, expected: &str) -> Result<String, String> {
    validate_sha256(expected)?;
    let actual = source_tree_sha256(root)?;
    if actual != expected {
        return Err(format!(
            "source tree digest mismatch: expected {expected}, computed {actual}"
        ));
    }
    Ok(actual)
}

pub fn derive_clean_checkout_identity(root: &Path) -> Result<ImageBuildIdentity, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("could not resolve repository root: {error}"))?;
    let top = git_output(&root, &["rev-parse", "--show-toplevel"])?;
    let top = String::from_utf8(top).map_err(|_| "git root is not UTF-8")?;
    let top = PathBuf::from(top.trim());
    if top
        .canonicalize()
        .map_err(|error| format!("could not resolve git root: {error}"))?
        != root
    {
        return Err("image identity must be derived from the Git repository root".into());
    }

    let status = git_output(
        &root,
        &[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "build_support",
            "infra/nitro-enclave",
            "src",
        ],
    )?;
    if !status.is_empty() {
        return Err("Nitro image source inputs have uncommitted changes".into());
    }

    let tracked = git_output(
        &root,
        &[
            "ls-files",
            "-z",
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "build_support",
            "infra/nitro-enclave",
            "src",
        ],
    )?;
    let tracked = tracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| PathBuf::from(String::from_utf8_lossy(path).into_owned()))
        .collect::<BTreeSet<_>>();
    let present = source_files(&root)?.into_iter().collect::<BTreeSet<_>>();
    if tracked != present {
        return Err("tracked image inputs do not match the source tree on disk".into());
    }

    let revision = String::from_utf8(git_output(&root, &["rev-parse", "HEAD"])?)
        .map_err(|_| "Git revision is not UTF-8")?;
    let revision = revision.trim().to_owned();
    validate_revision(&revision)?;
    let source_tree_sha256 = source_tree_sha256(&root)?;
    Ok(ImageBuildIdentity {
        implementation_revision: revision,
        source_tree_sha256,
    })
}

fn git_output(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .map_err(|error| format!("could not run git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

//! Release-artifact reproducibility checks for the fixed evaluator.
//!
//! State slice: security-alignment-os-foundation-v1.

use security_alignment_os::digest_bytes;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn build_evaluator(target_dir: &Path) -> Vec<u8> {
    let status = Command::new("cargo")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_INCREMENTAL", "0")
        .args([
            "build",
            "--locked",
            "--release",
            "--bin",
            "maintenance_evaluator",
            "--quiet",
        ])
        .status()
        .expect("cargo release build should start");
    assert!(status.success(), "cargo release build failed: {status}");

    let executable = target_dir.join("release").join("maintenance_evaluator");
    fs::read(executable).expect("release evaluator should exist")
}

#[test]
fn evaluator_release_build_is_byte_reproducible() {
    let root = tempdir().expect("reproducibility test tempdir");
    let first_target = root.path().join(PathBuf::from("first-target"));
    let second_target = root.path().join(PathBuf::from("second-target"));

    let first = build_evaluator(&first_target);
    let second = build_evaluator(&second_target);

    assert_eq!(
        first, second,
        "clean evaluator builds must have identical bytes"
    );
    assert_eq!(digest_bytes(&first), digest_bytes(&second));
}

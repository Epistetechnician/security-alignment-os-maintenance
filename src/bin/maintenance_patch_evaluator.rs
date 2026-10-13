//! Pinned local evaluator process for a prepared multi-file candidate.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! This reference evaluator verifies exact request and candidate-manifest
//! bindings. It does not compile or run candidate code or prove semantic patch
//! correctness. Production evaluators must implement their frozen test contract.

use security_alignment_os::maintenance_transaction::{
    evaluate_job, EvaluationJob, MAX_PATCH_REQUEST_JSON_BYTES,
};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2)
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--seed-path")) {
        fail("only --seed-path is accepted");
    }
    let Some(seed_path) = args.next().map(PathBuf::from) else {
        fail("missing evaluator seed path");
    };
    if args.next().is_some() {
        fail("unexpected evaluator argument");
    }
    let metadata = fs::symlink_metadata(&seed_path).unwrap_or_else(|_| fail("seed unavailable"));
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 32 {
        fail("seed must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
        {
            fail("seed must be owner-only");
        }
    }
    let mut seed = Vec::with_capacity(33);
    fs::File::open(seed_path)
        .unwrap_or_else(|_| fail("seed read failed"))
        .take(33)
        .read_to_end(&mut seed)
        .unwrap_or_else(|_| fail("seed read failed"));
    if seed.len() != 32 {
        fail("seed must be exactly 32 bytes");
    }
    let max_job_bytes = MAX_PATCH_REQUEST_JSON_BYTES;
    let mut input = Vec::new();
    io::stdin()
        .take(max_job_bytes + 1)
        .read_to_end(&mut input)
        .unwrap_or_else(|_| fail("evaluation job read failed"));
    if input.len() as u64 > max_job_bytes {
        fail("evaluation job exceeds byte limit");
    }
    let job: EvaluationJob =
        serde_json::from_slice(&input).unwrap_or_else(|_| fail("evaluation job is malformed"));
    let launch_token = std::env::var("PATCH_EVALUATOR_LAUNCH_TOKEN")
        .unwrap_or_else(|_| fail("broker launch token missing"));
    if security_alignment_os::digest_bytes(launch_token.as_bytes()) != job.launch_token_digest {
        fail("broker launch token does not match evaluation job");
    }
    let executable = std::env::current_exe().unwrap_or_else(|_| fail("executable unavailable"));
    let executable_bytes = fs::read(executable).unwrap_or_else(|_| fail("executable unreadable"));
    if security_alignment_os::digest_bytes(&executable_bytes) != job.evaluator_executable_digest {
        fail("evaluator executable digest mismatch");
    }
    let mut receipt = evaluate_job(&job).unwrap_or_else(|error| fail(&error.to_string()));
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&seed);
    receipt
        .sign_with_seed(seed_bytes)
        .unwrap_or_else(|error| fail(&error.to_string()));
    println!(
        "{}",
        serde_json::to_string(&receipt).unwrap_or_else(|_| fail("receipt serialization failed"))
    );
}

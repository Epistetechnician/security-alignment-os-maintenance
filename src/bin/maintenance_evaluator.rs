//! Fixed maintenance evaluator subprocess.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! The seed is supplied only by the operator-controlled broker argument. It is
//! never a member of the proposer request or evaluator JSON job.

use security_alignment_os::maintenance_process::{
    evaluate_job, EvaluatorJob, Receipt, MAX_JOB_BYTES,
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
    let Some(flag) = args.next() else {
        fail("missing --seed-path");
    };
    if flag != "--seed-path" {
        fail("only --seed-path is accepted");
    }
    let Some(seed_path) = args.next().map(PathBuf::from) else {
        fail("missing seed path");
    };
    if args.next().is_some() {
        fail("unexpected evaluator argument");
    }
    let metadata =
        fs::symlink_metadata(&seed_path).unwrap_or_else(|_| fail("seed path unavailable"));
    if !metadata.is_file() {
        fail("seed path is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            fail("seed path is not owner-only");
        }
    }
    let seed = fs::read(seed_path).unwrap_or_else(|_| fail("seed read failed"));
    if seed.len() != 32 {
        fail("seed must be exactly 32 bytes");
    }
    let mut input = Vec::new();
    io::stdin()
        .take((MAX_JOB_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .unwrap_or_else(|_| fail("job read failed"));
    if input.len() > MAX_JOB_BYTES {
        fail("job exceeds byte limit");
    }
    let job: EvaluatorJob =
        serde_json::from_slice(&input).unwrap_or_else(|_| fail("job JSON is invalid"));
    let executable = std::env::current_exe().unwrap_or_else(|_| fail("executable unavailable"));
    let bytes = fs::read(executable).unwrap_or_else(|_| fail("executable unreadable"));
    if security_alignment_os::digest_bytes(&bytes) != job.evaluator_executable_digest {
        fail("evaluator executable binding mismatch");
    }
    let mut receipt: Receipt = evaluate_job(&job).unwrap_or_else(|error| fail(&error.to_string()));
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed);
    receipt
        .sign_with_seed(seed_array)
        .unwrap_or_else(|error| fail(&error.to_string()));
    println!(
        "{}",
        serde_json::to_string(&receipt).unwrap_or_else(|_| fail("receipt serialization failed"))
    );
}

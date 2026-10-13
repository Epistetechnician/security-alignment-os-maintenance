//! Operator CLI for multi-file maintenance candidate preparation and commit.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! Usage: maintenance_patch_broker init SOURCE WORKSPACE
//!        maintenance_patch_broker CONFIG prepare|evaluate|commit|recover ...

use security_alignment_os::maintenance_transaction::{
    active_checkout, commit_candidate, initialize_workspace, prepare_candidate, recover,
    workspace_generation_digest, Config, EvaluationJob, EvaluationReceipt, PatchRequest,
    PreparedCandidate, MAX_PATCH_REQUEST_JSON_BYTES,
};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

fn fail(message: &str, code: i32) -> ! {
    eprintln!("{message}");
    std::process::exit(code)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, max_bytes: u64, what: &str) -> T {
    let metadata =
        fs::symlink_metadata(path).unwrap_or_else(|_| fail(&format!("{what} unavailable"), 2));
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        fail(&format!("{what} is not a bounded regular file"), 2);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
        {
            fail(&format!("{what} must be owner-only and singly linked"), 2);
        }
    }
    let mut file = fs::File::open(path).unwrap_or_else(|_| fail(&format!("{what} read failed"), 2));
    let mut bytes = Vec::new();
    use std::io::Read;
    (&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .unwrap_or_else(|_| fail(&format!("{what} read failed"), 2));
    if bytes.len() as u64 > max_bytes {
        fail(&format!("{what} exceeds byte limit"), 2);
    }
    serde_json::from_slice(&bytes)
        .ok()
        .unwrap_or_else(|| fail(&format!("{what} JSON is invalid"), 2))
}

fn output<T: serde::Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string(value).expect("serialize command result")
    );
}

fn evaluator_seed_path(path: &Path, workspace: &Path) -> std::path::PathBuf {
    let metadata =
        fs::symlink_metadata(path).unwrap_or_else(|_| fail("evaluator seed unavailable", 2));
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 32 {
        fail("evaluator seed must be a 32-byte regular file", 2);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
        {
            fail("evaluator seed must be owner-only and singly linked", 2);
        }
    }
    let canonical = fs::canonicalize(path)
        .unwrap_or_else(|_| fail("evaluator seed path cannot be resolved", 2));
    if canonical.starts_with(workspace) {
        fail("evaluator seed must be outside the managed workspace", 2);
    }
    canonical
}

fn launch_token() -> String {
    let mut bytes = [0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .unwrap_or_else(|_| fail("evaluator launch token unavailable", 1));
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(first) = args.next() else {
        fail(
            "usage: maintenance_patch_broker init SOURCE WORKSPACE | CONFIG prepare|evaluate|commit|recover ...",
            2,
        );
    };
    if first == "init" {
        let (Some(source), Some(workspace)) = (args.next(), args.next()) else {
            fail("init requires source and managed workspace paths", 2);
        };
        if args.next().is_some() {
            fail("unexpected init argument", 2);
        }
        let workspace = std::path::PathBuf::from(workspace);
        if let Err(error) = initialize_workspace(Path::new(&source), &workspace) {
            fail(&format!("workspace initialization failed: {error}"), 1);
        }
        let workspace = fs::canonicalize(workspace)
            .unwrap_or_else(|_| fail("initialized workspace cannot be resolved", 1));
        let active = active_checkout(&workspace)
            .unwrap_or_else(|error| fail(&format!("active generation unavailable: {error}"), 1));
        let baseline_digest = workspace_generation_digest(&active)
            .unwrap_or_else(|error| fail(&format!("baseline digest failed: {error}"), 1));
        output(&serde_json::json!({
            "workspace_root": workspace,
            "baseline_digest": baseline_digest,
        }));
        return;
    }
    let Some(command) = args.next() else {
        fail("configuration path must be followed by a command", 2);
    };
    let config_path = first;
    let config: Config = read_json(Path::new(&config_path), 64 * 1024, "configuration");
    match command.to_str() {
        Some("prepare") => {
            let Some(request_path) = args.next() else {
                fail("prepare requires a request path", 2);
            };
            if args.next().is_some() {
                fail("unexpected prepare argument", 2);
            }
            let request: PatchRequest = read_json(
                Path::new(&request_path),
                MAX_PATCH_REQUEST_JSON_BYTES,
                "patch request",
            );
            match prepare_candidate(&config, &request) {
                Ok(prepared) => output(&prepared),
                Err(error) => fail(&format!("prepare failed: {error}"), 1),
            }
        }
        Some("evaluate") => {
            let (Some(request_path), Some(prepared_path), Some(seed_path)) =
                (args.next(), args.next(), args.next())
            else {
                fail(
                    "evaluate requires request, prepared candidate, and seed paths",
                    2,
                );
            };
            if args.next().is_some() {
                fail("unexpected evaluate argument", 2);
            }
            let request: PatchRequest = read_json(
                Path::new(&request_path),
                MAX_PATCH_REQUEST_JSON_BYTES,
                "patch request",
            );
            let prepared: PreparedCandidate =
                read_json(Path::new(&prepared_path), 64 * 1024, "prepared candidate");
            let seed_path = evaluator_seed_path(Path::new(&seed_path), &config.workspace_root);
            let token = launch_token();
            let job = match EvaluationJob::new(
                &config,
                &request,
                &prepared,
                &security_alignment_os::digest_bytes(token.as_bytes()),
            ) {
                Ok(job) => job,
                Err(error) => fail(&format!("evaluation job failed: {error}"), 1),
            };
            let args = vec![
                std::ffi::OsString::from("--seed-path"),
                seed_path.into_os_string(),
            ];
            let environment = vec![(
                std::ffi::OsString::from("PATCH_EVALUATOR_LAUNCH_TOKEN"),
                std::ffi::OsString::from(token.as_str()),
            )];
            let mut child = security_alignment_os::sandbox::spawn_sandboxed(
                &config.evaluator_executable_path,
                &args,
                &environment,
                &[],
                config.evaluator_max_address_space_bytes,
            )
            .unwrap_or_else(|error| fail(&format!("sandbox launch failed: {error}"), 1));
            let mut stdin = child
                .stdin
                .take()
                .unwrap_or_else(|| fail("evaluator input channel unavailable", 1));
            let job_bytes = serde_json::to_vec(&job)
                .unwrap_or_else(|_| fail("evaluation job encoding failed", 1));
            let writer = std::thread::spawn(move || stdin.write_all(&job_bytes));
            let result = security_alignment_os::sandbox::wait_with_timeout(
                child,
                config.evaluator_timeout_ms,
            );
            let delivered = writer
                .join()
                .unwrap_or_else(|_| fail("evaluator input delivery thread failed", 1));
            let result = result
                .unwrap_or_else(|error| fail(&format!("sandbox evaluator failed: {error}"), 1));
            delivered.unwrap_or_else(|_| fail("evaluation job delivery failed", 1));
            if !result.status.success() {
                let detail = String::from_utf8_lossy(&result.stderr);
                fail(
                    &format!("sandbox evaluator rejected job: {}", detail.trim()),
                    1,
                );
            }
            if result.stdout.len() > 64 * 1024 {
                fail("sandbox evaluator output exceeded the limit", 1);
            }
            let receipt: EvaluationReceipt = serde_json::from_slice(&result.stdout)
                .unwrap_or_else(|_| fail("sandbox evaluator output is invalid", 1));
            output(&receipt);
        }
        Some("commit") => {
            let (Some(request_path), Some(receipt_path)) = (args.next(), args.next()) else {
                fail("commit requires request and evaluation receipt paths", 2);
            };
            if args.next().is_some() {
                fail("unexpected commit argument", 2);
            }
            let request: PatchRequest = read_json(
                Path::new(&request_path),
                MAX_PATCH_REQUEST_JSON_BYTES,
                "patch request",
            );
            let receipt: EvaluationReceipt =
                read_json(Path::new(&receipt_path), 64 * 1024, "evaluation receipt");
            match commit_candidate(&config, &request, &receipt) {
                Ok(result) => output(&result),
                Err(error) => fail(&format!("commit failed: {error}"), 1),
            }
        }
        Some("recover") => {
            if args.next().is_some() {
                fail("unexpected recover argument", 2);
            }
            match recover(&config) {
                Ok(result) => output(&result),
                Err(error) => fail(&format!("recovery failed: {error}"), 1),
            }
        }
        _ => fail("unknown maintenance patch command", 2),
    }
}

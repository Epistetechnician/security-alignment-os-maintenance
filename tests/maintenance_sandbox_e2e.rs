//! macOS host-sandbox conformance checks for the shared launcher.
//!
//! State slice: `security-alignment-os-foundation-v1`.

#![cfg(target_os = "macos")]

use rustix::process::{test_kill_process, Pid};
use security_alignment_os::sandbox::{spawn_sandboxed, wait_with_timeout};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::Duration;

fn sandbox_probe_child() {
    let Ok(mode) = std::env::var("SANDBOX_PROBE_MODE") else {
        return;
    };
    match mode.as_str() {
        "write" => {
            let path = std::env::var_os("SANDBOX_PROBE_PATH").expect("probe path");
            assert!(fs::write(path, b"outside sandbox").is_err());
        }
        "connect" => {
            let address = std::env::var("SANDBOX_PROBE_ADDRESS").expect("probe address");
            assert!(TcpStream::connect(address).is_err());
        }
        "spam" => {
            std::io::stdout()
                .write_all(&vec![b'x'; 128 * 1024])
                .expect("write sandbox probe output");
        }
        "metadata" => {
            let path = std::env::var_os("SANDBOX_PROBE_PATH").expect("probe path");
            let metadata = fs::metadata(&path).expect("probe file metadata");
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            assert!(fs::set_permissions(path, permissions).is_err());
        }
        "sleep" => thread::sleep(Duration::from_secs(30)),
        _ => panic!("unsupported sandbox probe"),
    }
}

fn run_probe(mode: &str, extra: Option<(OsString, OsString)>) -> std::process::Child {
    let executable = std::env::current_exe().expect("integration test executable");
    let args = vec![
        OsString::from("--exact"),
        OsString::from("sandbox_probe_child_test_entry"),
        OsString::from("--nocapture"),
    ];
    let mut environment = vec![(OsString::from("SANDBOX_PROBE_MODE"), OsString::from(mode))];
    if let Some(pair) = extra {
        environment.push(pair);
    }
    spawn_sandboxed(&executable, &args, &environment, &[], None)
        .expect("launch probe under Seatbelt")
}

#[test]
fn seatbelt_denies_filesystem_writes_outside_the_transaction_workspace() {
    let directory = tempfile::tempdir().expect("private probe directory");
    let forbidden = directory.path().join("forbidden.txt");
    let output = wait_with_timeout(
        run_probe(
            "write",
            Some((
                OsString::from("SANDBOX_PROBE_PATH"),
                forbidden.clone().into_os_string(),
            )),
        ),
        5_000,
    )
    .expect("filesystem probe finishes");

    assert!(output.status.success(), "probe output: {:?}", output.stderr);
    assert!(!forbidden.exists());
}

#[test]
fn seatbelt_denies_network_connections_to_a_local_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("synthetic local listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("listener address").to_string();
    let output = wait_with_timeout(
        run_probe(
            "connect",
            Some((
                OsString::from("SANDBOX_PROBE_ADDRESS"),
                OsString::from(address),
            )),
        ),
        5_000,
    )
    .expect("network probe finishes");

    assert!(output.status.success(), "probe output: {:?}", output.stderr);
    assert!(
        listener.accept().is_err(),
        "sandbox connected to the host listener"
    );
}

#[test]
fn timeout_kills_and_reaps_the_sandbox_process_group() {
    let child = run_probe("sleep", None);
    let pid = Pid::from_child(&child);
    let result = wait_with_timeout(child, 100);

    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(
        test_kill_process(pid).is_err(),
        "timed out child is still alive"
    );
}

#[test]
fn captured_child_output_stays_within_the_fixed_byte_budget() {
    let output = wait_with_timeout(run_probe("spam", None), 5_000)
        .expect("output probe finishes or is cut off");

    assert!(output.stdout.len() <= 64 * 1024 + 1);
}

#[test]
fn macos_launcher_rejects_unenforced_address_space_limits() {
    let executable = std::env::current_exe().expect("integration test executable");
    let result = spawn_sandboxed(
        &executable,
        &[],
        &[],
        &[],
        Some(security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES),
    );

    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn seatbelt_denies_filesystem_metadata_changes_outside_the_workspace() {
    let directory = tempfile::tempdir().expect("private probe directory");
    let path = directory.path().join("protected.txt");
    fs::write(&path, b"protected\n").expect("write test fixture");
    let original_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    let output = wait_with_timeout(
        run_probe(
            "metadata",
            Some((
                OsString::from("SANDBOX_PROBE_PATH"),
                path.clone().into_os_string(),
            )),
        ),
        5_000,
    )
    .expect("metadata probe finishes");

    assert!(output.status.success(), "probe output: {:?}", output.stderr);
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        original_mode
    );
}

// Keep the test child visible to the subprocess test harness without adding a
// separate production binary that can exercise sandbox probes.
#[test]
fn sandbox_probe_child_test_entry() {
    sandbox_probe_child();
}

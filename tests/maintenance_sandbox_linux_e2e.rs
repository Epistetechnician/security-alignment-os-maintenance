//! Linux host-sandbox conformance checks for the shared launcher.
//!
//! State slice: `security-alignment-os-foundation-v1`.

#![cfg(target_os = "linux")]

use rustix::process::{test_kill_process, Pid};
use security_alignment_os::sandbox::{spawn_sandboxed, wait_with_timeout};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[cfg(target_arch = "x86_64")]
const SYS_FCHMODAT2: libc::c_long = libc::SYS_fchmodat2;
#[cfg(target_arch = "aarch64")]
const SYS_FCHMODAT2: libc::c_long = 452;

fn sandbox_probe_child() {
    let Ok(mode) = std::env::var("SANDBOX_PROBE_MODE") else {
        return;
    };
    match mode.as_str() {
        "write-outside" => {
            let path = std::env::var_os("SANDBOX_PROBE_PATH").expect("probe path");
            assert!(fs::write(path, b"outside sandbox").is_err());
        }
        "write-inside" => {
            let path = std::env::var_os("SANDBOX_PROBE_PATH").expect("probe path");
            fs::write(path, b"inside sandbox").expect("write allowed workspace file");
        }
        "connect-tcp" => {
            let address = std::env::var("SANDBOX_PROBE_ADDRESS").expect("probe address");
            assert!(TcpStream::connect(address).is_err());
        }
        "connect-unix" => {
            let path = std::env::var_os("SANDBOX_PROBE_PATH").expect("probe path");
            assert!(UnixStream::connect(path).is_err());
        }
        "connect-abstract-unix" => {
            let (address, address_len) = abstract_socket_address(b"security-alignment-os-probe");
            let descriptor =
                unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            assert!(descriptor >= 0, "create abstract-socket probe");
            let result = unsafe {
                libc::connect(
                    descriptor,
                    (&address as *const libc::sockaddr_un).cast(),
                    address_len,
                )
            };
            unsafe { libc::close(descriptor) };
            assert_eq!(result, -1, "sandbox connected to host abstract socket");
        }
        "signal-parent" => {
            let result = unsafe { libc::kill(libc::getppid(), libc::SIGCONT) };
            assert_eq!(result, -1, "sandbox signalled a host process");
        }
        "metadata" => {
            let path = std::env::var_os("SANDBOX_PROBE_PATH").expect("probe path");
            let metadata = fs::metadata(&path).expect("probe file metadata");
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            assert!(fs::set_permissions(&path, permissions).is_err());
            let pathname = std::ffi::CString::new(path.as_os_str().as_bytes())
                .expect("temporary pathname has no NUL");
            let result = unsafe {
                libc::syscall(
                    SYS_FCHMODAT2,
                    libc::AT_FDCWD,
                    pathname.as_ptr(),
                    0o600 as libc::mode_t,
                    0,
                )
            };
            assert_eq!(result, -1, "sandbox allowed fchmodat2");
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM),
                "fchmodat2 must be denied by the seccomp filter"
            );
        }
        "address-space" => {
            let mut allocation = Vec::<u8>::new();
            assert!(
                allocation.try_reserve_exact(512 * 1024 * 1024).is_err(),
                "address-space limit allowed a 512 MiB allocation"
            );
        }
        "inherited-fd" => {
            let descriptor = std::env::var("SANDBOX_PROBE_FD")
                .expect("probe descriptor")
                .parse::<libc::c_int>()
                .expect("numeric probe descriptor");
            assert_eq!(
                unsafe { libc::fcntl(descriptor, libc::F_GETFD) },
                -1,
                "inherited descriptor remained open after exec"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
        }
        "namespace-clone" => {
            let child = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_ulong,
                    std::ptr::null_mut::<libc::c_void>(),
                    0,
                    0,
                    0,
                )
            };
            if child == 0 {
                unsafe { libc::_exit(1) };
            }
            if child > 0 {
                let mut status = 0;
                unsafe { libc::waitpid(child as libc::pid_t, &mut status, 0) };
                panic!("sandbox allowed nested user-namespace creation");
            }
            assert_eq!(child, -1, "sandbox allowed nested user-namespace creation");
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
        "spam" => {
            std::io::stdout()
                .write_all(&vec![b'x'; 128 * 1024])
                .expect("write sandbox probe output");
        }
        "sleep" => thread::sleep(Duration::from_secs(30)),
        _ => panic!("unsupported sandbox probe"),
    }
}

fn run_probe(
    mode: &str,
    extra: Option<(OsString, OsString)>,
    writable_roots: &[PathBuf],
    max_address_space_bytes: u64,
) -> std::process::Child {
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
    spawn_sandboxed(
        &executable,
        &args,
        &environment,
        writable_roots,
        Some(max_address_space_bytes),
    )
    .unwrap_or_else(|error| panic!("Linux sandbox runtime launch failed: {error}"))
}

fn abstract_socket_address(name: &[u8]) -> (libc::sockaddr_un, libc::socklen_t) {
    assert!(!name.is_empty());
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    assert!(name.len() < address.sun_path.len());
    for (destination, source) in address.sun_path[1..].iter_mut().zip(name) {
        *destination = *source as libc::c_char;
    }
    let address_len =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len()) as libc::socklen_t;
    (address, address_len)
}

fn abstract_socket_listener() -> OwnedFd {
    let (address, address_len) = abstract_socket_address(b"security-alignment-os-probe");
    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    assert!(descriptor >= 0, "create abstract-socket listener");
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    assert_eq!(
        unsafe {
            libc::bind(
                descriptor.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                address_len,
            )
        },
        0,
        "bind abstract-socket listener"
    );
    assert_eq!(
        unsafe { libc::listen(descriptor.as_raw_fd(), 1) },
        0,
        "listen on abstract socket"
    );
    descriptor
}

#[test]
fn linux_sandbox_denies_writes_outside_the_allowed_workspace() {
    let directory = tempfile::tempdir().expect("private probe directory");
    let forbidden = directory.path().join("forbidden.txt");
    let child = run_probe(
        "write-outside",
        Some((
            OsString::from("SANDBOX_PROBE_PATH"),
            forbidden.clone().into_os_string(),
        )),
        &[],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("filesystem probe finishes");

    assert!(output.status.success(), "probe output: {:?}", output.stderr);
    assert!(!forbidden.exists());
}

#[test]
fn linux_sandbox_allows_writes_under_an_explicit_workspace_root() {
    let allowed = tempfile::tempdir().expect("allowed workspace");
    let output_path = allowed.path().join("output.txt");
    let child = run_probe(
        "write-inside",
        Some((
            OsString::from("SANDBOX_PROBE_PATH"),
            output_path.clone().into_os_string(),
        )),
        &[allowed.path().to_path_buf()],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("allowed write probe finishes");

    assert!(output.status.success(), "probe output: {:?}", output.stderr);
    assert_eq!(fs::read(output_path).unwrap(), b"inside sandbox");
}

#[test]
fn linux_sandbox_denies_loopback_ip_and_host_unix_socket_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("synthetic local listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("listener address").to_string();
    let child = run_probe(
        "connect-tcp",
        Some((
            OsString::from("SANDBOX_PROBE_ADDRESS"),
            OsString::from(address),
        )),
        &[],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("network probe finishes");
    assert!(output.status.success(), "probe output: {:?}", output.stderr);
    assert!(
        listener.accept().is_err(),
        "sandbox connected to host listener"
    );

    let directory = tempfile::tempdir().expect("private Unix socket directory");
    let socket_path = directory.path().join("host.sock");
    let _unix_listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .expect("synthetic pathname Unix listener");
    let child = run_probe(
        "connect-unix",
        Some((
            OsString::from("SANDBOX_PROBE_PATH"),
            socket_path.into_os_string(),
        )),
        &[],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("Unix socket probe finishes");
    assert!(output.status.success(), "probe output: {:?}", output.stderr);

    let listener = abstract_socket_listener();
    let child = run_probe(
        "connect-abstract-unix",
        None,
        &[],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("abstract Unix socket probe finishes");
    assert!(output.status.success(), "probe output: {:?}", output.stderr);
    let accepted = unsafe {
        libc::accept(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if accepted >= 0 {
        unsafe { libc::close(accepted) };
        panic!("sandbox reached host abstract socket");
    }
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EAGAIN)
    );
}

#[test]
fn linux_sandbox_denies_signals_to_processes_outside_its_landlock_domain() {
    let child = run_probe(
        "signal-parent",
        None,
        &[],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("signal-scope probe finishes");
    assert!(output.status.success(), "probe output: {:?}", output.stderr);
}

#[test]
fn linux_sandbox_denies_filesystem_metadata_changes() {
    let allowed = tempfile::tempdir().expect("allowed workspace");
    let path = allowed.path().join("protected.txt");
    fs::write(&path, b"protected\n").expect("fixture file");
    let original_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    let child = run_probe(
        "metadata",
        Some((
            OsString::from("SANDBOX_PROBE_PATH"),
            path.clone().into_os_string(),
        )),
        &[allowed.path().to_path_buf()],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("metadata probe finishes");

    assert!(output.status.success(), "probe output: {:?}", output.stderr);
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        original_mode
    );
}

#[test]
fn linux_sandbox_enforces_address_space_and_output_budgets() {
    let child = run_probe("address-space", None, &[], 256 * 1024 * 1024);
    let output = wait_with_timeout(child, 5_000).expect("address-space probe finishes");
    assert!(output.status.success(), "probe output: {:?}", output.stderr);

    let child = run_probe(
        "spam",
        None,
        &[],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("output probe finishes or is cut off");
    assert!(output.stdout.len() <= 64 * 1024 + 1);
}

#[test]
fn linux_sandbox_closes_inherited_host_file_descriptors_before_exec() {
    let directory = tempfile::tempdir().expect("private probe directory");
    let path = directory.path().join("inherited.txt");
    fs::write(&path, b"host descriptor").expect("descriptor fixture");
    let file = fs::File::open(path).expect("open host descriptor");
    let descriptor = file.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(descriptor, libc::F_GETFD);
        assert!(flags >= 0, "read descriptor flags");
        assert_eq!(
            libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
            0,
            "make descriptor inheritable before sandbox setup"
        );
    }
    let child = run_probe(
        "inherited-fd",
        Some((
            OsString::from("SANDBOX_PROBE_FD"),
            OsString::from(descriptor.to_string()),
        )),
        &[],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("descriptor probe finishes");
    assert!(output.status.success(), "probe output: {:?}", output.stderr);
}

#[test]
fn linux_sandbox_denies_nested_namespace_creation() {
    let child = run_probe(
        "namespace-clone",
        None,
        &[],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let output = wait_with_timeout(child, 5_000).expect("process creation probe finishes");
    assert!(output.status.success(), "probe output: {:?}", output.stderr);
}

#[test]
fn linux_timeout_kills_and_reaps_the_sandbox_process_group() {
    let child = run_probe(
        "sleep",
        None,
        &[],
        security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES,
    );
    let pid = Pid::from_child(&child);
    let result = wait_with_timeout(child, 100);

    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(
        test_kill_process(pid).is_err(),
        "timed out child is still alive"
    );
}

#[test]
fn sandbox_probe_child_test_entry() {
    sandbox_probe_child();
}

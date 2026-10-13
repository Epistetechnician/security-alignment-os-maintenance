//! Platform sandbox launchers shared by local execution boundaries.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! Unsafe code is limited to this module's OS resource-limit and sandbox syscalls.
#![allow(unsafe_code)]

use std::ffi::OsString;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs;
use std::io::{self, Read};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Output};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::ffi::OsStrExt,
};

const MAX_SANDBOX_TIMEOUT_MS: u64 = 60_000;
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
pub const MIN_ADDRESS_SPACE_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_ADDRESS_SPACE_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ADDRESS_SPACE_LIMIT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MIN_LANDLOCK_ABI: libc::c_long = 9;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const AUDIT_ARCH_CURRENT: u32 = 0xc000_003e;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const AUDIT_ARCH_CURRENT: u32 = 0xc000_00b7;
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
const AUDIT_ARCH_CURRENT: u32 = 0;

/// Launch a pinned program with networking denied and writes limited to the
/// supplied exact directory roots. The process gets a new process group so a
/// timeout can terminate the complete local workload.
pub fn spawn_sandboxed(
    executable: &Path,
    args: &[OsString],
    environment: &[(OsString, OsString)],
    writable_roots: &[PathBuf],
    max_address_space_bytes: Option<u64>,
) -> io::Result<Child> {
    if let Some(limit) = max_address_space_bytes {
        if !(MIN_ADDRESS_SPACE_LIMIT_BYTES..=MAX_ADDRESS_SPACE_LIMIT_BYTES).contains(&limit) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sandbox address-space limit is outside the supported range",
            ));
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (
            executable,
            args,
            environment,
            writable_roots,
            max_address_space_bytes,
        );
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transaction evaluator sandbox is unavailable on this platform",
        ));
    }

    #[cfg(target_os = "macos")]
    {
        if max_address_space_bytes.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "macOS sandbox does not enforce an address-space limit",
            ));
        }
        let executable = fs::canonicalize(executable)?;
        if !fs::metadata(&executable)?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sandbox executable is not a regular file",
            ));
        }
        let writable_roots = canonical_writable_roots(writable_roots)?;
        let executable_rule = sandbox_string(&executable)?;
        let mut profile =
            String::from("(version 1) (allow default) (deny network*) (deny file-write*) ");
        for root in &writable_roots {
            profile.push_str(&format!(
                "(allow file-write* (subpath \"{}\")) ",
                sandbox_string(root)?
            ));
        }
        profile.push_str(&format!(
            "(deny process-exec*) (allow process-exec* (literal \"{executable_rule}\")) (allow process-fork)"
        ));
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-p")
            .arg(profile)
            .arg(executable)
            .args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        for (name, value) in environment {
            command.env(name, value);
        }
        command.spawn()
    }

    #[cfg(target_os = "linux")]
    {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux sandbox supports x86_64 and aarch64 only",
        ));
        let Some(max_address_space_bytes) = max_address_space_bytes else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux sandbox requires an address-space limit",
            ));
        };
        let executable = fs::canonicalize(executable)?;
        if !fs::metadata(&executable)?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sandbox executable is not a regular file",
            ));
        }
        let writable_roots = canonical_writable_roots(writable_roots)?;
        let root_fds = open_writable_roots(&writable_roots)?;
        let raw_root_fds = root_fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let uid_map = CString::new(format!("0 {} 1\n", unsafe { libc::geteuid() }))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid UID mapping"))?;
        let gid_map = CString::new(format!("0 {} 1\n", unsafe { libc::getegid() }))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid GID mapping"))?;
        let metadata_filter = metadata_write_filter();
        let mut command = Command::new(&executable);
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let address_space_limit = max_address_space_bytes;
        unsafe {
            command.pre_exec(move || {
                linux_enter_sandbox(
                    address_space_limit,
                    &uid_map,
                    &gid_map,
                    &raw_root_fds,
                    &metadata_filter,
                )
            });
        }
        for (name, value) in environment {
            command.env(name, value);
        }
        let child = command.spawn()?;
        drop(root_fds);
        Ok(child)
    }
}

#[cfg(target_os = "linux")]
fn set_address_space_limit(max_address_space_bytes: u64) -> io::Result<()> {
    let requested = max_address_space_bytes as libc::rlim_t;
    let mut inherited = unsafe { std::mem::zeroed::<libc::rlimit>() };
    if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut inherited) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let limit = if inherited.rlim_max == libc::RLIM_INFINITY {
        requested
    } else {
        requested.min(inherited.rlim_max)
    };
    let constrained = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &constrained) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_writable_roots(paths: &[PathBuf]) -> io::Result<Vec<OwnedFd>> {
    paths
        .iter()
        .map(|path| {
            let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "sandbox path contains NUL")
            })?;
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn metadata_write_filter() -> Vec<libc::sock_filter> {
    // State slice: `security-alignment-os-foundation-v1`.
    // AArch64 follows asm-generic and omits several legacy x86_64 syscall
    // entry points. fchmodat2 is present in the AArch64 syscall table even
    // though libc does not publish its number yet.
    #[cfg(target_arch = "x86_64")]
    const SYS_FCHMODAT2: libc::c_long = libc::SYS_fchmodat2;
    #[cfg(target_arch = "aarch64")]
    const SYS_FCHMODAT2: libc::c_long = 452;

    #[allow(unused_mut)] // x86_64 adds legacy syscall numbers below.
    let mut denied_syscalls = vec![
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        SYS_FCHMODAT2,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        libc::SYS_utimensat,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_mount_setattr,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_chroot,
        libc::SYS_setpgid,
        libc::SYS_setsid,
        libc::SYS_capset,
        libc::SYS_open_by_handle_at,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_clone3,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_bpf,
    ];
    #[cfg(target_arch = "x86_64")]
    denied_syscalls.extend([
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ]);
    let mut filter = Vec::with_capacity(denied_syscalls.len() * 2 + 9);
    filter.push(libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: 4,
    });
    filter.push(libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH_CURRENT,
    });
    filter.push(libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
    });
    filter.push(libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: 0,
    });
    for syscall_number in denied_syscalls {
        let errno = if syscall_number == libc::SYS_clone3 {
            // ENOSYS lets runtimes fall back to clone(), whose namespace flags
            // are visible to this filter. EPERM prevents Rust's test harness
            // and other thread users from making that safe fallback.
            libc::ENOSYS
        } else {
            libc::EPERM
        };
        filter.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: syscall_number as u32,
        });
        filter.push(libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | errno as u32,
        });
    }
    // Keep ordinary threads and child processes available, but prevent a
    // sandboxed evaluator from creating a nested namespace through clone().
    // clone3() returns ENOSYS above because its flags live behind a user pointer.
    const CLONE_NAMESPACE_FLAGS: u32 = 0x7e02_0080;
    filter.push(libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt: 0,
        jf: 3,
        k: libc::SYS_clone as u32,
    });
    filter.push(libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: 16,
    });
    filter.push(libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16,
        jt: 0,
        jf: 1,
        k: CLONE_NAMESPACE_FLAGS,
    });
    filter.push(libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
    });
    filter.push(libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    });
    filter
}

#[cfg(target_os = "linux")]
unsafe fn linux_enter_sandbox(
    max_address_space_bytes: u64,
    uid_map: &std::ffi::CStr,
    gid_map: &std::ffi::CStr,
    writable_root_fds: &[i32],
    metadata_filter: &[libc::sock_filter],
) -> io::Result<()> {
    set_address_space_limit(max_address_space_bytes)?;
    if libc::unshare(libc::CLONE_NEWUSER) != 0 {
        return Err(io::Error::last_os_error());
    }
    write_proc_map(b"/proc/self/setgroups\0", b"deny\n")?;
    write_proc_map(b"/proc/self/uid_map\0", uid_map.to_bytes())?;
    write_proc_map(b"/proc/self/gid_map\0", gid_map.to_bytes())?;
    if libc::unshare(libc::CLONE_NEWNET) != 0 {
        return Err(io::Error::last_os_error());
    }
    apply_landlock(writable_root_fds)?;
    drop_linux_capabilities()?;
    mark_extra_fds_close_on_exec()?;
    install_seccomp_filter(metadata_filter)?;
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn mark_extra_fds_close_on_exec() -> io::Result<()> {
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn write_proc_map(path: &'static [u8], contents: &[u8]) -> io::Result<()> {
    let fd = libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut offset = 0;
    let result = loop {
        if offset == contents.len() {
            break Ok(());
        }
        let count = libc::write(
            fd,
            contents[offset..].as_ptr().cast(),
            contents.len() - offset,
        );
        if count > 0 {
            offset += count as usize;
        } else if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        } else if count == 0 {
            break Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "namespace mapping write was incomplete",
            ));
        } else {
            break Err(io::Error::last_os_error());
        }
    };
    let close_result = libc::close(fd);
    if close_result != 0 && result.is_ok() {
        return Err(io::Error::last_os_error());
    }
    result
}

#[cfg(target_os = "linux")]
unsafe fn apply_landlock(writable_root_fds: &[i32]) -> io::Result<()> {
    const FS_WRITE_FILE: u64 = 1 << 1;
    const FS_REMOVE_DIR: u64 = 1 << 4;
    const FS_REMOVE_FILE: u64 = 1 << 5;
    const FS_MAKE_CHAR: u64 = 1 << 6;
    const FS_MAKE_DIR: u64 = 1 << 7;
    const FS_MAKE_REG: u64 = 1 << 8;
    const FS_MAKE_SOCK: u64 = 1 << 9;
    const FS_MAKE_FIFO: u64 = 1 << 10;
    const FS_MAKE_BLOCK: u64 = 1 << 11;
    const FS_MAKE_SYM: u64 = 1 << 12;
    const FS_REFER: u64 = 1 << 13;
    const FS_TRUNCATE: u64 = 1 << 14;
    const FS_IOCTL_DEV: u64 = 1 << 15;
    const FS_RESOLVE_UNIX: u64 = 1 << 16;
    const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    const SCOPE_SIGNAL: u64 = 1 << 1;
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    const LANDLOCK_RULE_PATH_BENEATH: libc::c_uint = 1;
    const LANDLOCK_FS_RIGHTS: u64 = FS_WRITE_FILE
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM
        | FS_REFER
        | FS_TRUNCATE
        | FS_IOCTL_DEV
        | FS_RESOLVE_UNIX;
    const WRITABLE_ACCESS: u64 = LANDLOCK_FS_RIGHTS & !(FS_IOCTL_DEV | FS_RESOLVE_UNIX);

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }
    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    let version = libc::syscall(
        libc::SYS_landlock_create_ruleset,
        std::ptr::null::<std::ffi::c_void>(),
        0usize,
        LANDLOCK_CREATE_RULESET_VERSION,
    );
    if version < MIN_LANDLOCK_ABI {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux sandbox requires Landlock ABI 9 or newer",
        ));
    }
    let attributes = RulesetAttr {
        handled_access_fs: LANDLOCK_FS_RIGHTS,
        handled_access_net: 0,
        scoped: SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL,
    };
    let ruleset_fd = libc::syscall(
        libc::SYS_landlock_create_ruleset,
        &attributes,
        std::mem::size_of::<RulesetAttr>(),
        0,
    );
    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    for root_fd in writable_root_fds {
        let rule = PathBeneathAttr {
            allowed_access: WRITABLE_ACCESS,
            parent_fd: *root_fd,
        };
        if libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd as libc::c_int,
            LANDLOCK_RULE_PATH_BENEATH,
            &rule,
            0,
        ) < 0
        {
            let error = io::Error::last_os_error();
            libc::close(ruleset_fd as libc::c_int);
            return Err(error);
        }
    }
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        let error = io::Error::last_os_error();
        libc::close(ruleset_fd as libc::c_int);
        return Err(error);
    }
    if libc::syscall(
        libc::SYS_landlock_restrict_self,
        ruleset_fd as libc::c_int,
        0,
    ) < 0
    {
        let error = io::Error::last_os_error();
        libc::close(ruleset_fd as libc::c_int);
        return Err(error);
    }
    libc::close(ruleset_fd as libc::c_int);
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn drop_linux_capabilities() -> io::Result<()> {
    for capability in 0..=63 {
        if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
        }
    }
    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn install_seccomp_filter(filter: &[libc::sock_filter]) -> io::Result<()> {
    let program = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait for a sandbox child until its wall-clock budget expires.
pub fn wait_with_timeout(mut child: Child, timeout_ms: u64) -> io::Result<Output> {
    if timeout_ms == 0 || timeout_ms > MAX_SANDBOX_TIMEOUT_MS {
        terminate_workload(&mut child);
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandbox timeout is outside the supported range",
        ));
    }
    let stdout = child
        .stdout
        .take()
        .map(|pipe| std::thread::spawn(move || read_bounded(pipe, MAX_CAPTURE_BYTES)));
    let stderr = child
        .stderr
        .take()
        .map(|pipe| std::thread::spawn(move || read_bounded(pipe, MAX_CAPTURE_BYTES)));
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // A workload that leaves descendants behind must not keep its
                // inherited output pipes open after its leader exits.
                let drain_deadline = Instant::now() + Duration::from_millis(20);
                while !output_readers_finished(&stdout, &stderr) && Instant::now() < drain_deadline
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                if !output_readers_finished(&stdout, &stderr) {
                    terminate_workload(&mut child);
                }
                return Ok(Output {
                    status,
                    stdout: join_output_reader(stdout)?,
                    stderr: join_output_reader(stderr)?,
                });
            }
            Err(error) => {
                terminate_workload(&mut child);
                let _ = join_output_reader(stdout);
                let _ = join_output_reader(stderr);
                return Err(error);
            }
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            terminate_workload(&mut child);
            let _ = join_output_reader(stdout);
            let _ = join_output_reader(stderr);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "sandbox process exceeded its wall-clock budget",
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn output_readers_finished(
    stdout: &Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
    stderr: &Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
) -> bool {
    stdout
        .as_ref()
        .map_or(true, std::thread::JoinHandle::is_finished)
        && stderr
            .as_ref()
            .map_or(true, std::thread::JoinHandle::is_finished)
}

fn read_bounded<R: Read>(reader: R, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join_output_reader(
    reader: Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
) -> io::Result<Vec<u8>> {
    match reader {
        Some(reader) => reader
            .join()
            .map_err(|_| io::Error::other("sandbox output reader panicked"))?,
        None => Ok(Vec::new()),
    }
}

/// Terminate and reap the sandbox process group.
pub fn terminate_workload(child: &mut Child) {
    #[cfg(unix)]
    {
        use rustix::process::{kill_process_group, Pid, Signal};
        let pid = Pid::from_child(child);
        let _ = kill_process_group(pid, Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn canonical_writable_roots(paths: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let mut roots = Vec::with_capacity(paths.len());
    for path in paths {
        let canonical = fs::canonicalize(path)?;
        if !fs::metadata(&canonical)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sandbox writable root is not a directory",
            ));
        }
        roots.push(canonical);
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

#[cfg(target_os = "macos")]
fn sandbox_string(path: &Path) -> io::Result<String> {
    use std::os::unix::ffi::OsStrExt;
    if path
        .as_os_str()
        .as_bytes()
        .iter()
        .any(|byte| byte.is_ascii_control())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandbox path contains control characters",
        ));
    }
    let value = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandbox path is not valid UTF-8",
        )
    })?;
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

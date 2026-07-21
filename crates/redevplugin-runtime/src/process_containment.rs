#[cfg(target_os = "linux")]
const PROCESS_CONTAINMENT_SCHEMA_VERSION: &str = "redevplugin.process_containment.v1";
#[cfg(target_os = "linux")]
const PROCESS_CONTAINMENT_PROFILE: &str = "linux-runtime-v1";
#[cfg(target_os = "linux")]
const SECCOMP_POLICY_SHA256: &str =
    "6305735925c1fbacaf4950df2e535d3a11cebec8ab7aa16ce37fca3c31745543";

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        PROCESS_CONTAINMENT_PROFILE, PROCESS_CONTAINMENT_SCHEMA_VERSION, SECCOMP_POLICY_SHA256,
    };

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_ALU_AND_K: u16 = 0x54;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(target_arch = "x86_64")]
    const SYS_EXECVE: u32 = 59;
    #[cfg(target_arch = "aarch64")]
    const SYS_EXECVE: u32 = 221;
    #[cfg(target_arch = "x86_64")]
    const SYS_EXECVEAT: u32 = 322;
    #[cfg(target_arch = "aarch64")]
    const SYS_EXECVEAT: u32 = 281;
    #[cfg(target_arch = "x86_64")]
    const SYS_CLONE: u32 = 56;
    #[cfg(target_arch = "aarch64")]
    const SYS_CLONE: u32 = 220;
    const SYS_CLONE3: u32 = 435;
    #[cfg(target_arch = "x86_64")]
    const SYS_UNSHARE: u32 = 272;
    #[cfg(target_arch = "aarch64")]
    const SYS_UNSHARE: u32 = 97;
    #[cfg(target_arch = "x86_64")]
    const SYS_SETNS: u32 = 308;
    #[cfg(target_arch = "aarch64")]
    const SYS_SETNS: u32 = 268;
    #[cfg(target_arch = "x86_64")]
    const SYS_FORK: u32 = 57;
    #[cfg(target_arch = "x86_64")]
    const SYS_VFORK: u32 = 58;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    impl SockFilter {
        const fn statement(code: u16, k: u32) -> Self {
            Self {
                code,
                jt: 0,
                jf: 0,
                k,
            }
        }

        const fn jump(k: u32, jt: u8, jf: u8) -> Self {
            Self {
                code: BPF_JMP_JEQ_K,
                jt,
                jf,
                k,
            }
        }
    }

    pub(super) fn activate() -> Result<redevplugin_ipc::ProcessContainmentEvidence, String> {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return Err("runtime process containment is unsupported on this architecture".to_string());

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            install_signal_handlers()?;
            set_no_new_privileges()?;
            install_seccomp_filter()?;
            restore_runtime_signal_mask()?;
            Ok(redevplugin_ipc::ProcessContainmentEvidence {
                schema_version: PROCESS_CONTAINMENT_SCHEMA_VERSION.to_string(),
                profile: PROCESS_CONTAINMENT_PROFILE.to_string(),
                seccomp_policy_sha256: SECCOMP_POLICY_SHA256.to_string(),
                no_new_privs: true,
                seccomp_tsync: true,
                process_creation_denied: true,
                reexec_denied: true,
                active: true,
            })
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn install_signal_handlers() -> Result<(), String> {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_IGN;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            return Err("initialize runtime signal handler mask".to_string());
        }
        if unsafe { libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut()) } != 0 {
            return Err(format!(
                "install runtime SIGPIPE handler: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn set_no_new_privileges() -> Result<(), String> {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(format!(
                "set no_new_privs: {}",
                std::io::Error::last_os_error()
            ));
        }
        let active = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        if active != 1 {
            return Err("no_new_privs did not become active".to_string());
        }
        Ok(())
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn install_seccomp_filter() -> Result<(), String> {
        let filter = seccomp_filter()?;
        let program = SockFprog {
            len: u16::try_from(filter.len())
                .map_err(|_| "seccomp filter is too large".to_string())?,
            filter: filter.as_ptr(),
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC,
                &program as *const SockFprog,
            )
        };
        if result != 0 {
            return Err(format!(
                "install seccomp TSYNC policy: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn restore_runtime_signal_mask() -> Result<(), String> {
        let mut empty: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigemptyset(&mut empty) } != 0 {
            return Err("initialize runtime signal mask".to_string());
        }
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) };
        if result != 0 {
            return Err(format!(
                "restore runtime signal mask: {}",
                std::io::Error::from_raw_os_error(result)
            ));
        }
        Ok(())
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn seccomp_filter() -> Result<Vec<SockFilter>, String> {
        let mut filter = vec![
            SockFilter::statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
            SockFilter::jump(AUDIT_ARCH, 1, 0),
            SockFilter::statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            SockFilter::statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        ];
        let denied_syscalls: &[u32] = &[
            SYS_EXECVE,
            SYS_EXECVEAT,
            SYS_UNSHARE,
            SYS_SETNS,
            #[cfg(target_arch = "x86_64")]
            SYS_FORK,
            #[cfg(target_arch = "x86_64")]
            SYS_VFORK,
        ];
        for syscall in denied_syscalls {
            filter.push(SockFilter::jump(*syscall, 0, 1));
            filter.push(SockFilter::statement(
                BPF_RET_K,
                SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1),
            ));
        }
        filter.push(SockFilter::jump(SYS_CLONE3, 0, 1));
        filter.push(SockFilter::statement(
            BPF_RET_K,
            SECCOMP_RET_ERRNO | u32::try_from(libc::ENOSYS).unwrap_or(38),
        ));
        filter.push(SockFilter::jump(SYS_CLONE, 1, 0));
        filter.push(SockFilter::statement(BPF_RET_K, SECCOMP_RET_ALLOW));
        filter.push(SockFilter::statement(
            BPF_LD_W_ABS,
            SECCOMP_DATA_ARG0_OFFSET,
        ));
        let required_thread_flags = u32::try_from(
            libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES
                | libc::CLONE_SIGHAND
                | libc::CLONE_THREAD,
        )
        .map_err(|_| "clone thread flags exceed seccomp word size".to_string())?;
        filter.push(SockFilter::statement(BPF_ALU_AND_K, required_thread_flags));
        filter.push(SockFilter::jump(required_thread_flags, 0, 1));
        filter.push(SockFilter::statement(BPF_RET_K, SECCOMP_RET_ALLOW));
        filter.push(SockFilter::statement(
            BPF_RET_K,
            SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1),
        ));
        Ok(filter)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn containment_policy_identity_is_closed() {
            assert_eq!(PROCESS_CONTAINMENT_PROFILE, "linux-runtime-v1");
            assert_eq!(SECCOMP_POLICY_SHA256.len(), 64);
            assert!(
                SECCOMP_POLICY_SHA256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            );
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        #[test]
        fn seccomp_filter_arch_locks_and_denies_reexec() {
            let filter = seccomp_filter().expect("seccomp filter");
            assert_eq!(filter[0], SockFilter::statement(BPF_LD_W_ABS, 4));
            assert!(
                filter
                    .iter()
                    .any(|instruction| { *instruction == SockFilter::jump(SYS_EXECVEAT, 0, 1,) })
            );
            assert_eq!(
                filter.last().copied(),
                Some(SockFilter::statement(
                    BPF_RET_K,
                    SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1)
                ))
            );
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        #[test]
        fn containment_enforces_reexec_and_process_creation_denial() {
            const CHILD_ENV: &str = "REDEVPLUGIN_CONTAINMENT_TEST_CHILD";
            if std::env::var_os(CHILD_ENV).is_none() {
                let executable = std::env::current_exe().expect("current test executable");
                let status = std::process::Command::new(executable)
                    .args([
                        "--exact",
                        "process_containment::linux::tests::containment_enforces_reexec_and_process_creation_denial",
                        "--nocapture",
                    ])
                    .env(CHILD_ENV, "1")
                    .status()
                    .expect("start containment child test");
                assert!(status.success(), "containment child failed: {status}");
                return;
            }

            let evidence = activate().expect("activate process containment");
            evidence.validate().expect("containment evidence");
            std::thread::spawn(|| 42)
                .join()
                .expect("thread creation remains available");

            let fork_result = unsafe { libc::fork() };
            assert_eq!(fork_result, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );

            let clone3_result = unsafe {
                libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0usize)
            };
            assert_eq!(clone3_result, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOSYS)
            );

            let exec_result = unsafe {
                libc::syscall(
                    libc::SYS_execve,
                    std::ptr::null::<libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                )
            };
            assert_eq!(exec_result, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn activate() -> Result<redevplugin_ipc::ProcessContainmentEvidence, String> {
    Err("runtime process containment is supported only on Linux".to_string())
}

#[cfg(target_os = "linux")]
pub(crate) fn activate() -> Result<redevplugin_ipc::ProcessContainmentEvidence, String> {
    linux::activate()
}

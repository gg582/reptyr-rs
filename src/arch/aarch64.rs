//! aarch64 backend: PTRACE_GETREGSET/SETREGSET with NT_PRSTATUS. The
//! syscall number lives in a dedicated NT_ARM_SYSTEM_CALL regset,
//! arguments in x0-x5, return value in x0. There is no dup2 on aarch64;
//! dup3 with flags 0 is used instead.
//!
//! NOTE: written to the same contract as the x86_64 backend but not yet
//! exercised on hardware.

use super::{Arch, Regs, SyscallStop};

pub struct Aarch64;

pub const ARCH: &dyn Arch = &Aarch64;

pub type RawRegs = libc::user_pt_regs;

/// NT_ARM_SYSTEM_CALL: regset carrying just the syscall number (int).
const NT_ARM_SYSTEM_CALL: libc::c_uint = 0x404;

fn regset(tid: libc::pid_t, request: libc::c_uint, nt: libc::c_uint, regs: &mut RawRegs) -> std::io::Result<()> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: regs as *mut RawRegs as *mut libc::c_void,
            iov_len: std::mem::size_of::<RawRegs>(),
        };
        if libc::ptrace(request, tid, nt as usize as *mut libc::c_void, &mut iov) == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

fn syscall_nr_regset(tid: libc::pid_t, request: libc::c_uint, nr: &mut libc::c_int) -> std::io::Result<()> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: nr as *mut libc::c_int as *mut libc::c_void,
            iov_len: std::mem::size_of::<libc::c_int>(),
        };
        if libc::ptrace(request, tid, NT_ARM_SYSTEM_CALL as usize as *mut libc::c_void, &mut iov) == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

pub fn getregs(tid: libc::pid_t) -> std::io::Result<RawRegs> {
    let mut regs: RawRegs = unsafe { std::mem::zeroed() };
    regset(tid, libc::PTRACE_GETREGSET, libc::NT_PRSTATUS, &mut regs)?;
    Ok(regs)
}

pub fn setregs(tid: libc::pid_t, regs: &RawRegs) -> std::io::Result<()> {
    let mut regs = *regs;
    regset(tid, libc::PTRACE_SETREGSET, libc::NT_PRSTATUS, &mut regs)
}

impl Arch for Aarch64 {
    fn name(&self) -> &'static str {
        "aarch64"
    }

    fn save_fixup(&self, regs: &mut Regs) {
        // At a syscall-entry stop, pc points just past the 4-byte `svc`
        // instruction; rewind it so a full restore re-executes it.
        regs.0.pc -= 4;
    }

    fn get_syscall_nr(&self, tid: libc::pid_t, _regs: &Regs) -> std::io::Result<u64> {
        let mut nr: libc::c_int = 0;
        syscall_nr_regset(tid, libc::PTRACE_GETREGSET, &mut nr)?;
        Ok(nr as u64)
    }

    fn set_syscall_nr(&self, tid: libc::pid_t, _regs: &mut Regs, nr: u64) -> std::io::Result<()> {
        let mut nr = nr as libc::c_int;
        syscall_nr_regset(tid, libc::PTRACE_SETREGSET, &mut nr)
    }

    fn restore_syscall_nr(&self, tid: libc::pid_t, saved_nr: u64) -> std::io::Result<()> {
        let mut nr = saved_nr as libc::c_int;
        syscall_nr_regset(tid, libc::PTRACE_SETREGSET, &mut nr)
    }

    fn set_syscall_args(&self, regs: &mut Regs, args: [u64; 6]) {
        for (i, arg) in args.iter().enumerate() {
            regs.0.regs[i] = *arg;
        }
    }

    fn syscall_result(&self, regs: &Regs) -> i64 {
        regs.0.regs[0] as i64
    }

    fn restore_ip(&self, regs: &mut Regs, saved: &Regs) {
        regs.0.pc = saved.0.pc;
    }

    fn dup_syscall(&self, oldfd: u64, newfd: u64) -> (u64, [u64; 6]) {
        (libc::SYS_dup3 as u64, [oldfd, newfd, 0, 0, 0, 0])
    }

    fn nr_mmap(&self) -> u64 {
        libc::SYS_mmap as u64
    }

    fn nr_munmap(&self) -> u64 {
        libc::SYS_munmap as u64
    }

    fn nr_openat(&self) -> u64 {
        libc::SYS_openat as u64
    }

    fn nr_ioctl(&self) -> u64 {
        libc::SYS_ioctl as u64
    }

    fn nr_setsid(&self) -> u64 {
        libc::SYS_setsid as u64
    }

    fn nr_close(&self) -> u64 {
        libc::SYS_close as u64
    }

    fn nr_clone(&self) -> u64 {
        libc::SYS_clone as u64
    }

    fn nr_setpgid(&self) -> u64 {
        libc::SYS_setpgid as u64
    }

    fn nr_kill(&self) -> u64 {
        libc::SYS_kill as u64
    }

    fn nr_wait4(&self) -> u64 {
        libc::SYS_wait4 as u64
    }

    fn nr_rt_sigaction(&self) -> u64 {
        libc::SYS_rt_sigaction as u64
    }

    fn fallback_syscall_stop(&self, _regs: &Regs) -> SyscallStop {
        // There is no reliable register-level heuristic on aarch64;
        // PTRACE_GET_SYSCALL_INFO (Linux 5.3+) is required.
        SyscallStop::Unknown
    }
}

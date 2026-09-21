//! x86_64 backend: PTRACE_GETREGS/SETREGS. The syscall number lives in
//! `orig_rax`, arguments in rdi/rsi/rdx/r10/r8/r9, return value in `rax`,
//! dup2 for fd redirection.
//!
//! At a syscall-entry stop, `rip` points just past the 2-byte `syscall`
//! instruction and `rax` is -ENOSYS; the fixup rewinds `rip` and moves
//! the syscall number into `rax` so a full restore re-executes the
//! original syscall.

use super::{Arch, Regs, SyscallStop};

pub struct X86_64;

pub const ARCH: &dyn Arch = &X86_64;

pub type RawRegs = libc::user_regs_struct;

pub fn getregs(tid: libc::pid_t) -> std::io::Result<RawRegs> {
    unsafe {
        let mut regs: RawRegs = std::mem::zeroed();
        if libc::ptrace(libc::PTRACE_GETREGS, tid, std::ptr::null_mut::<libc::c_void>(), &mut regs) == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(regs)
    }
}

pub fn setregs(tid: libc::pid_t, regs: &RawRegs) -> std::io::Result<()> {
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            regs as *const _ as *mut libc::c_void,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

impl Arch for X86_64 {
    fn name(&self) -> &'static str {
        "x86_64"
    }

    fn save_fixup(&self, regs: &mut Regs) {
        regs.0.rip -= 2;
        regs.0.rax = regs.0.orig_rax;
    }

    fn get_syscall_nr(&self, _tid: libc::pid_t, regs: &Regs) -> std::io::Result<u64> {
        Ok(regs.0.orig_rax)
    }

    fn set_syscall_nr(&self, _tid: libc::pid_t, regs: &mut Regs, nr: u64) -> std::io::Result<()> {
        regs.0.orig_rax = nr;
        Ok(())
    }

    fn restore_syscall_nr(&self, _tid: libc::pid_t, _saved_nr: u64) -> std::io::Result<()> {
        // The number is part of the general register set (rax/orig_rax),
        // already restored by the full register restore.
        Ok(())
    }

    fn set_syscall_args(&self, regs: &mut Regs, args: [u64; 6]) {
        regs.0.rdi = args[0];
        regs.0.rsi = args[1];
        regs.0.rdx = args[2];
        regs.0.r10 = args[3];
        regs.0.r8 = args[4];
        regs.0.r9 = args[5];
    }

    fn syscall_result(&self, regs: &Regs) -> i64 {
        regs.0.rax as i64
    }

    fn restore_ip(&self, regs: &mut Regs, saved: &Regs) {
        regs.0.rip = saved.0.rip;
    }

    fn dup_syscall(&self, oldfd: u64, newfd: u64) -> (u64, [u64; 6]) {
        (libc::SYS_dup2 as u64, [oldfd, newfd, 0, 0, 0, 0])
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

    fn nr_socket(&self) -> u64 {
        libc::SYS_socket as u64
    }

    fn nr_connect(&self) -> u64 {
        libc::SYS_connect as u64
    }

    fn nr_sendmsg(&self) -> u64 {
        libc::SYS_sendmsg as u64
    }

    fn fallback_syscall_stop(&self, regs: &Regs) -> SyscallStop {
        // On syscall entry the kernel sets rax to -ENOSYS; at exit stops
        // rax holds the return value.
        if regs.0.rax as i64 == -(libc::ENOSYS as i64) {
            SyscallStop::Entry
        } else {
            SyscallStop::Exit
        }
    }
}

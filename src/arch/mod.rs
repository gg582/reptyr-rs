//! Architecture abstraction for ptrace-based syscall injection.
//!
//! The hijack engine and the injection plan are architecture-independent.
//! Everything that touches register layouts, syscall numbers, or calling
//! conventions lives behind this module. Adding a port means adding one
//! file here; nothing above this layer changes.
//!
//! The injection contract (as established by the original reptyr):
//!
//! 1. At a syscall-entry stop we capture the register state and apply
//!    [`Arch::save_fixup`] so that restoring it later re-executes the
//!    original syscall correctly (x86_64: `rip -= 2`, `rax = orig_rax`;
//!    aarch64: `pc -= 4`).
//! 2. Each injected syscall only replaces the syscall number and the
//!    argument registers; after it runs we restore just the instruction
//!    pointer, so the next resume re-enters at the same syscall
//!    instruction. That re-entry is immediately overwritten by the next
//!    injection and never dispatches.
//! 3. At the end the full saved state is restored and the original
//!    syscall finally runs.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64 as imp;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use self::aarch64 as imp;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("reptyr-rs: unsupported architecture (ported: x86_64, aarch64)");

/// What kind of syscall stop a tracee is sitting in, when the kernel can
/// tell us (PTRACE_GET_SYSCALL_INFO) or a heuristic can guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallStop {
    Entry,
    Exit,
    Unknown,
}

/// Opaque wrapper around the raw CPU register state of a tracee.
#[derive(Clone, Copy)]
pub struct Regs(pub(crate) imp::RawRegs);

/// Backend for the build target's architecture.
pub trait Arch {
    fn name(&self) -> &'static str;

    /// Adjust a register state captured at a syscall-entry stop so that
    /// restoring it later re-executes the original syscall.
    fn save_fixup(&self, regs: &mut Regs);

    /// Read the syscall number the tracee is about to execute.
    fn get_syscall_nr(&self, tid: libc::pid_t, regs: &Regs) -> std::io::Result<u64>;

    /// Set the syscall number for the next injected syscall. Some
    /// architectures carry it in the general register set, others in a
    /// dedicated regset.
    fn set_syscall_nr(&self, tid: libc::pid_t, regs: &mut Regs, nr: u64) -> std::io::Result<()>;

    /// Restore the original syscall number captured with [`Arch::get_syscall_nr`].
    fn restore_syscall_nr(&self, tid: libc::pid_t, saved_nr: u64) -> std::io::Result<()>;

    /// Set the syscall argument registers.
    fn set_syscall_args(&self, regs: &mut Regs, args: [u64; 6]);

    /// Extract the return value of the most recently executed syscall.
    fn syscall_result(&self, regs: &Regs) -> i64;

    /// Point the instruction pointer at the saved address, so resuming
    /// re-executes the syscall instruction.
    fn restore_ip(&self, regs: &mut Regs, saved: &Regs);

    /// Syscall number and arguments for dup'ing `oldfd` onto `newfd`
    /// (dup2 where it exists, dup3 elsewhere).
    fn dup_syscall(&self, oldfd: u64, newfd: u64) -> (u64, [u64; 6]);

    fn nr_mmap(&self) -> u64;
    fn nr_munmap(&self) -> u64;
    fn nr_openat(&self) -> u64;
    fn nr_ioctl(&self) -> u64;
    fn nr_setsid(&self) -> u64;
    fn nr_close(&self) -> u64;
    fn nr_clone(&self) -> u64;
    fn nr_setpgid(&self) -> u64;
    fn nr_kill(&self) -> u64;
    fn nr_wait4(&self) -> u64;
    fn nr_rt_sigaction(&self) -> u64;
    fn nr_socket(&self) -> u64;
    fn nr_connect(&self) -> u64;
    fn nr_sendmsg(&self) -> u64;

    /// Best-effort entry/exit classification for kernels that lack
    /// PTRACE_GET_SYSCALL_INFO.
    fn fallback_syscall_stop(&self, regs: &Regs) -> SyscallStop;
}

/// The architecture backend of this build.
pub fn arch() -> &'static dyn Arch {
    imp::ARCH
}

pub fn getregs(tid: libc::pid_t) -> std::io::Result<Regs> {
    imp::getregs(tid).map(Regs)
}

pub fn setregs(tid: libc::pid_t, regs: &Regs) -> std::io::Result<()> {
    imp::setregs(tid, &regs.0)
}

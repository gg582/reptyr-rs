//! Syscall-hijack engine.
//!
//! No tracee memory is patched and no instruction is fabricated. We drive
//! a thread to a natural syscall-entry stop (PTRACE_SYSCALL with
//! TRACESYSGOOD) and temporarily swap the syscall number and arguments.
//! After each injected syscall only the instruction pointer is rewound,
//! so the next resume re-enters at the same syscall instruction; that
//! re-entry is immediately overwritten by the next injection and never
//! dispatches. The original syscall stays saved — with architecture
//! fixups applied — until [`Hijacker::finish`] restores it and lets it
//! run, so no syscall is ever lost. This is the same discipline as the
//! original reptyr.

use std::time::{Duration, Instant};

use crate::arch::{self, Regs};
use crate::error::{msg, Result};
use crate::ptrace::{self, Stop, SyscallStop};
use libc::pid_t;

/// How long to wait for a candidate thread to reach a syscall entry.
const ENTRY_TIMEOUT: Duration = Duration::from_secs(3);
/// Give up on the whole seize after this long.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Hijacker {
    tid: pid_t,
    /// Register state of the pending original syscall, captured at its
    /// entry stop with [`crate::arch::Arch::save_fixup`] applied. It has
    /// not run yet; [`Hijacker::finish`] restores it and lets it run.
    saved: Regs,
    /// The same state without the fixup, for the error path: restoring
    /// it at an entry stop lets the syscall continue cleanly.
    raw_saved: Regs,
    /// The pending original syscall number (kept outside `saved` on
    /// architectures that carry it in a dedicated regset).
    saved_nr: u64,
    /// A signal we swallowed while the thread was under our control;
    /// re-delivered on detach.
    pending_signal: Option<i32>,
    /// Whether the tracee currently sits at a syscall-entry stop.
    /// Injected syscalls leave it at an exit stop; the next injection
    /// first rewinds the instruction pointer to get a fresh entry stop.
    at_entry: bool,
    verbose: bool,
}

impl Hijacker {
    /// Pick a thread and wait until it enters a syscall. Threads blocked
    /// in a syscall re-enter it when resumed (restart semantics), so even
    /// an idle `cat` yields an entry stop immediately.
    pub fn seize(session: &ptrace::Session, verbose: bool) -> Result<Hijacker> {
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        for &tid in session.tids() {
            if Instant::now() >= deadline {
                break;
            }
            match Self::try_tid(tid, verbose) {
                Ok(Some(h)) => return Ok(h),
                Ok(None) => vlog!(verbose, "thread {} made no syscall in time; trying next", tid),
                Err(e) => return Err(e),
            }
        }
        Err(msg(
            "unable to find a syscall to hijack; the target may be stopped (send SIGCONT) or blocked without syscalls",
        ))
    }

    fn try_tid(tid: pid_t, verbose: bool) -> Result<Option<Hijacker>> {
        let mut pending_signal = None;
        ptrace::resume_syscall(tid, 0)?;
        let deadline = Instant::now() + ENTRY_TIMEOUT;
        loop {
            let now = Instant::now();
            if now >= deadline {
                // Stop the thread again; it remains seized in the session.
                // Re-deliver any signal we swallowed on the way out.
                let _ = ptrace::interrupt(tid);
                let _ = ptrace::wait(tid);
                let _ = ptrace::resume_syscall(tid, pending_signal.unwrap_or(0));
                return Ok(None);
            }
            match ptrace::wait_timeout(tid, deadline - now)? {
                Some(Stop::Syscall) => {
                    if ptrace::syscall_stop_kind(tid) == SyscallStop::Entry {
                        let a = arch::arch();
                        let raw_saved = arch::getregs(tid)?;
                        let mut saved = raw_saved;
                        a.save_fixup(&mut saved);
                        let saved_nr = a.get_syscall_nr(tid, &saved)?;
                        vlog!(verbose, "hijacking thread {} at syscall {}", tid, saved_nr);
                        #[cfg(target_arch = "x86_64")]
                        vlog!(verbose, "saved: rip={:#x} rax={:#x} orig_rax={:#x} rdi={:#x} rsi={:#x} rdx={:#x}",
                            saved.0.rip, saved.0.rax, saved.0.orig_rax, saved.0.rdi, saved.0.rsi, saved.0.rdx);
                        return Ok(Some(Hijacker { tid, saved, raw_saved, saved_nr, pending_signal, at_entry: true, verbose }));
                    }
                    // An exit stop: the thread is leaving a syscall it was
                    // already in; let it run on toward the next entry.
                    ptrace::resume_syscall(tid, 0)?;
                }
                Some(Stop::Signal(sig)) => {
                    if sig != libc::SIGTRAP && sig != libc::SIGSTOP {
                        vlog!(verbose, "swallowed signal {} in thread {} while waiting", sig, tid);
                        if pending_signal.is_none() {
                            pending_signal = Some(sig);
                        }
                    }
                    ptrace::resume_syscall(tid, 0)?;
                }
                Some(Stop::Event(ev)) => {
                    vlog!(verbose, "ptrace event {} while waiting for a syscall", ev);
                    ptrace::resume_syscall(tid, 0)?;
                }
                Some(Stop::Exited) => {
                    return Err(msg(format!("thread {} exited while hijacking", tid)));
                }
                None => continue,
            }
        }
    }

    pub fn tid(&self) -> pid_t {
        self.tid
    }

    /// A copy of the pending original register state, for seeding a
    /// forked dummy child.
    pub fn saved_clone(&self) -> Regs {
        self.saved
    }


    pub fn saved_nr(&self) -> u64 {
        self.saved_nr
    }

    pub fn take_signal(&mut self) -> Option<i32> {
        self.pending_signal.take()
    }

    /// Move from the previous syscall's exit stop to a fresh entry stop
    /// by rewinding the instruction pointer. The tracee re-enters at the
    /// same syscall instruction; that re-entry is immediately overwritten
    /// by the next injection and never dispatches.
    fn ensure_entry(&mut self) -> Result<()> {
        if self.at_entry {
            return Ok(());
        }
        let a = arch::arch();
        let mut regs = arch::getregs(self.tid)?;
        a.restore_ip(&mut regs, &self.saved);
        arch::setregs(self.tid, &regs)?;
        self.resume_and_expect(SyscallStop::Entry)?;
        self.at_entry = true;
        Ok(())
    }

    /// Execute `nr(args)` inside the tracee. Returns the raw syscall
    /// return value; negative values are -errno. Leaves the tracee at
    /// the syscall-exit stop.
    pub fn syscall(&mut self, nr: u64, args: [u64; 6]) -> Result<i64> {
        let a = arch::arch();
        self.ensure_entry()?;

        // Replace the syscall number and arguments at the entry stop.
        let mut regs = arch::getregs(self.tid)?;
        a.set_syscall_nr(self.tid, &mut regs, nr)?;
        a.set_syscall_args(&mut regs, args);
        arch::setregs(self.tid, &regs)?;
        self.resume_and_expect(SyscallStop::Exit)?;
        let result = a.syscall_result(&arch::getregs(self.tid)?);
        self.at_entry = false;

        vlog!(self.verbose, "inject nr={} -> {}", nr, result);
        Ok(result)
    }

    /// Inject clone(SIGCHLD) — fork semantics — and return the child's
    /// pid. The child is auto-attached (TRACEFORK) and left in its
    /// initial stop for [`Hijacker::for_dummy`].
    pub fn fork_child(&mut self) -> Result<pid_t> {
        let a = arch::arch();
        ptrace::set_options(self.tid, libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACEFORK)?;
        self.ensure_entry()?;

        let mut regs = arch::getregs(self.tid)?;
        a.set_syscall_nr(self.tid, &mut regs, a.nr_clone())?;
        a.set_syscall_args(&mut regs, [libc::SIGCHLD as u64, 0, 0, 0, 0, 0]);
        arch::setregs(self.tid, &regs)?;
        ptrace::resume_syscall(self.tid, 0)?;

        // The clone's exit surfaces as a PTRACE_EVENT_FORK stop carrying
        // the new child's pid.
        let dummy = loop {
            match ptrace::wait(self.tid)? {
                Stop::Event(libc::PTRACE_EVENT_FORK) => {
                    break ptrace::get_event_msg(self.tid)? as pid_t
                }
                Stop::Event(ev) => {
                    return Err(msg(format!("unexpected ptrace event {} during fork", ev)));
                }
                Stop::Signal(sig) => {
                    self.record_signal(sig);
                    ptrace::resume_syscall(self.tid, 0)?;
                }
                Stop::Syscall | Stop::Exited => {
                    return Err(msg("target did not report a fork event"));
                }
            }
        };
        vlog!(self.verbose, "forked dummy child {} in target", dummy);

        // The fork event stands in for the clone's exit stop; the next
        // injection will rewind to a fresh entry stop on its own.
        ptrace::set_options(self.tid, libc::PTRACE_O_TRACESYSGOOD)?;
        self.at_entry = false;
        Ok(dummy)
    }

    /// Build a remote-syscall handle for a forked dummy child. The child
    /// waits in its initial stop; its register state is replaced with the
    /// pending original syscall state so that, from the ptrace point of
    /// view, it looks just like the parent.
    pub fn for_dummy(tid: pid_t, saved: Regs, saved_nr: u64, verbose: bool) -> Result<Hijacker> {
        match ptrace::wait(tid)? {
            Stop::Signal(libc::SIGSTOP) | Stop::Signal(libc::SIGTRAP) => {}
            other => {
                return Err(msg(format!(
                    "dummy child {} stopped unexpectedly: {:?}",
                    tid, other
                )))
            }
        }
        ptrace::set_syscall_trace(tid)?;
        arch::setregs(tid, &saved)?;
        ptrace::resume_syscall(tid, 0)?;
        loop {
            match ptrace::wait(tid)? {
                Stop::Syscall => {
                    if ptrace::syscall_stop_kind(tid) == SyscallStop::Entry {
                        let raw_saved = saved;
                        return Ok(Hijacker { tid, saved, raw_saved, saved_nr, pending_signal: None, at_entry: true, verbose });
                    }
                    ptrace::resume_syscall(tid, 0)?;
                }
                Stop::Signal(_) | Stop::Event(_) => {
                    ptrace::resume_syscall(tid, 0)?;
                }
                Stop::Exited => return Err(msg("dummy child exited during setup")),
            }
        }
    }

    /// Restore the pending original syscall. Called at the last injected
    /// syscall's exit stop: once the caller detaches, the tracee returns
    /// to the syscall instruction and re-executes it with the original
    /// number and arguments, so it runs exactly once — we deliberately do
    /// not wait for it, since it may block (e.g. a read that only
    /// completes once the proxy is up).
    pub fn finish(self) -> Result<()> {
        if !self.at_entry {
            arch::setregs(self.tid, &self.saved)?;
            arch::arch().restore_syscall_nr(self.tid, self.saved_nr)?;
        }
        // If we are at an entry stop, the live state is already correct:
        // detaching continues the entry path into the original syscall.
        Ok(())
    }

    fn resume_and_expect(&mut self, want: SyscallStop) -> Result<()> {
        ptrace::resume_syscall(self.tid, 0)?;
        loop {
            match ptrace::wait(self.tid)? {
                Stop::Syscall => {
                    let got = ptrace::syscall_stop_kind(self.tid);
                    if got == want || got == SyscallStop::Unknown {
                        return Ok(());
                    }
                    // Unexpected stop kind; let the thread run on until we
                    // see the one we need.
                    ptrace::resume_syscall(self.tid, 0)?;
                }
                Stop::Signal(sig) => {
                    self.record_signal(sig);
                    ptrace::resume_syscall(self.tid, 0)?;
                }
                Stop::Event(ev) => {
                    // Only armed around fork_child; a stray event here
                    // would otherwise leave a child stopped forever.
                    vlog!(self.verbose, "unexpected ptrace event {} during resume", ev);
                    ptrace::resume_syscall(self.tid, 0)?;
                }
                Stop::Exited => {
                    return Err(msg(format!("thread {} exited during hijack", self.tid)));
                }
            }
        }
    }

    fn record_signal(&mut self, sig: i32) {
        if sig == libc::SIGTRAP || sig == libc::SIGSTOP {
            return; // ptrace-internal, not the target's
        }
        vlog!(self.verbose, "deferring signal {} in thread {}", sig, self.tid);
        if self.pending_signal.is_none() {
            self.pending_signal = Some(sig);
        }
    }
}

impl Drop for Hijacker {
    fn drop(&mut self) {
        // Best effort: whatever went wrong, put the original syscall
        // back. The raw state is right for an entry-stop detach, which
        // continues the entry path into the original syscall.
        let state = if self.at_entry { self.raw_saved } else { self.saved };
        let _ = arch::setregs(self.tid, &state);
        let _ = arch::arch().restore_syscall_nr(self.tid, self.saved_nr);
    }
}

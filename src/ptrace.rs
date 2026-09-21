//! Thin wrappers over ptrace(2), scoped to what the hijack engine needs,
//! plus a [`Session`] that owns the attach/detach lifecycle of every
//! thread in the target process.

use std::time::{Duration, Instant};

use crate::arch;
use crate::error::{msg, Error, Result};
use libc::{c_int, c_void, pid_t};

pub use crate::arch::SyscallStop;

/// How a ptrace-stopped thread came to a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// A syscall-entry or syscall-exit stop (PTRACE_O_TRACESYSGOOD).
    Syscall,
    /// A signal-delivery stop; carries the signal number.
    Signal(c_int),
    /// A ptrace event stop (e.g. PTRACE_EVENT_FORK); carries the event.
    Event(c_int),
    /// The thread exited or was killed.
    Exited,
}

fn cvt(ret: libc::c_long) -> Result<()> {
    if ret == -1 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// PTRACE_SEIZE a thread without stopping it.
pub fn seize(tid: pid_t) -> Result<()> {
    let ret = unsafe { libc::ptrace(libc::PTRACE_SEIZE, tid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
    if ret == -1 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EPERM) => msg(format!(
                "cannot attach to {}: permission denied (already traced, or ptrace_scope restrictions)",
                tid
            )),
            Some(libc::ESRCH) => msg(format!("no such process or thread: {}", tid)),
            _ => Error::Io(err),
        });
    }
    Ok(())
}

/// Arm TRACESYSGOOD so syscall stops are distinguishable from SIGTRAP.
pub fn set_syscall_trace(tid: pid_t) -> Result<()> {
    set_options(tid, libc::PTRACE_O_TRACESYSGOOD)
}

/// Replace the ptrace option mask of a stopped tracee.
pub fn set_options(tid: pid_t, options: libc::c_int) -> Result<()> {
    cvt(unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            options as usize as *mut c_void,
        )
    })
}

/// Read the event message of an event stop (e.g. the child pid of a
/// PTRACE_EVENT_FORK).
pub fn get_event_msg(tid: pid_t) -> Result<libc::c_ulong> {
    let mut msg: libc::c_ulong = 0;
    cvt(unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            &mut msg as *mut _ as *mut c_void,
        )
    })?;
    Ok(msg)
}

/// Request a stop of a running seized thread.
pub fn interrupt(tid: pid_t) -> Result<()> {
    cvt(unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, tid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) })
}

/// Resume until the next syscall stop, delivering `sig` (0 to suppress).
pub fn resume_syscall(tid: pid_t, sig: c_int) -> Result<()> {
    cvt(unsafe {
        libc::ptrace(
            libc::PTRACE_SYSCALL,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            sig as usize as *mut c_void,
        )
    })
}

pub fn detach(tid: pid_t, sig: c_int) -> Result<()> {
    cvt(unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            sig as usize as *mut c_void,
        )
    })
}

fn classify(status: c_int) -> Stop {
    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
        return Stop::Exited;
    }
    let sig = libc::WSTOPSIG(status);
    if sig == (libc::SIGTRAP | 0x80) {
        Stop::Syscall
    } else if sig == libc::SIGTRAP && (status >> 16) != 0 {
        Stop::Event(status >> 16)
    } else {
        Stop::Signal(sig)
    }
}

/// Wait for the next event of a specific thread.
pub fn wait(tid: pid_t) -> Result<Stop> {
    loop {
        let mut status: c_int = 0;
        let ret = unsafe { libc::waitpid(tid, &mut status, libc::__WALL) };
        if ret == -1 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Io(e));
        }
        return Ok(classify(status));
    }
}

/// Wait up to `timeout` for the next event of a specific thread.
pub fn wait_timeout(tid: pid_t, timeout: Duration) -> Result<Option<Stop>> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut status: c_int = 0;
        let ret = unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
        if ret == -1 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Io(e));
        }
        if ret == tid {
            return Ok(Some(classify(status)));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Refine a syscall stop into entry/exit using PTRACE_GET_SYSCALL_INFO,
/// falling back to an architecture-level heuristic.
pub fn syscall_stop_kind(tid: pid_t) -> SyscallStop {
    unsafe {
        let mut info: libc::ptrace_syscall_info = std::mem::zeroed();
        let ret = libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            tid,
            std::mem::size_of::<libc::ptrace_syscall_info>() as *mut c_void,
            &mut info as *mut _ as *mut c_void,
        );
        if ret != -1 {
            // op: 0 = none, 1 = entry, 2 = exit, 3 = seccomp (pre-entry).
            return match info.op {
                1 | 3 => SyscallStop::Entry,
                2 => SyscallStop::Exit,
                _ => SyscallStop::Unknown,
            };
        }
    }
    match arch::getregs(tid) {
        Ok(regs) => arch::arch().fallback_syscall_stop(&regs),
        Err(_) => SyscallStop::Unknown,
    }
}

pub fn write_word(tid: pid_t, addr: u64, val: u64) -> Result<()> {
    cvt(unsafe {
        libc::ptrace(
            libc::PTRACE_POKEDATA,
            tid,
            addr as *mut c_void,
            val as usize as *mut c_void,
        )
    })
}

pub fn read_word(tid: pid_t, addr: u64) -> Result<u64> {
    unsafe {
        *libc::__errno_location() = 0;
        let ret = libc::ptrace(libc::PTRACE_PEEKTEXT, tid, addr as *mut c_void, std::ptr::null_mut::<c_void>());
        let err = *libc::__errno_location();
        if ret == -1 && err != 0 {
            return Err(Error::Io(std::io::Error::from_raw_os_error(err)));
        }
        Ok(ret as u64)
    }
}

/// Write bytes into the tracee, word by word. The tail of the last word
/// is zero-padded, which is safe only into scratch memory we own.
pub fn write_bytes(tid: pid_t, mut addr: u64, data: &[u8]) -> Result<()> {
    for chunk in data.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        write_word(tid, addr, u64::from_ne_bytes(word))?;
        addr += 8;
    }
    Ok(())
}

/// How long to wait for a thread to acknowledge an interrupt.
const INTERRUPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Every thread of the target process, seized and stopped; detached on
/// drop. This is the safety net: whatever happens during the hijack,
/// threads never stay ptrace-stopped.
pub struct Session {
    attached: Vec<pid_t>,
}

impl Session {
    pub fn attach_all(pid: pid_t, verbose: bool) -> Result<Session> {
        let mut tids = crate::target::threads(pid)?;
        // Try the main thread first when looking for a syscall to hijack.
        tids.sort_by_key(|&t| (t != pid, t));

        let mut session = Session { attached: Vec::new() };
        let result = (|| {
            for &tid in &tids {
                match seize(tid) {
                    Ok(()) => {
                        session.attached.push(tid);
                    }
                    Err(e) => {
                        if tid == pid {
                            return Err(e);
                        }
                        // Individual threads may vanish between enumeration
                        // and seize; the main thread may not.
                        vlog!(verbose, "skipping thread {}: {}", tid, e);
                    }
                }
            }
            if session.attached.is_empty() {
                return Err(msg("target has no attachable threads"));
            }
            for &tid in &session.attached {
                interrupt(tid)?;
            }
            for &tid in &session.attached.clone() {
                match wait_timeout(tid, INTERRUPT_TIMEOUT)? {
                    Some(Stop::Exited) => {
                        vlog!(verbose, "thread {} exited while attaching", tid);
                        session.attached.retain(|&t| t != tid);
                    }
                    Some(_) => {}
                    None => {
                        return Err(msg(format!(
                            "thread {} did not stop (stuck in uninterruptible sleep?)",
                            tid
                        )));
                    }
                }
            }
            if session.attached.is_empty() {
                return Err(msg("target vanished while attaching"));
            }
            // SETOPTIONS is only accepted on a stopped tracee.
            for &tid in &session.attached {
                set_syscall_trace(tid)?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            session.detach_all(0);
            return Err(e);
        }
        vlog!(verbose, "seized {} thread(s)", session.attached.len());
        Ok(session)
    }

    pub fn tids(&self) -> &[pid_t] {
        &self.attached
    }

    pub fn detach_all(&mut self, sig: c_int) {
        for &tid in &self.attached {
            let _ = detach(tid, sig);
        }
        self.attached.clear();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.detach_all(0);
    }
}

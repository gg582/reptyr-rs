//! The redirection plan, executed inside the tracee through the hijack
//! engine. Architecture-independent: syscall numbers and calling
//! conventions come from `crate::arch`.
//!
//! Sequence (all executed as hijacked syscalls inside the target), the
//! same plan as the original reptyr:
//!   mmap a scratch page -> stage the new pty path and a sigaction ->
//!   rt_sigaction(SIGHUP, SIG_IGN) -> move to a fresh session
//!   (TIOCNOTTY, or the fork/setpgid/setsid dance) -> openat the new pty
//!   slave -> TIOCSCTTY -> dup onto the selected fds -> close -> munmap.

use std::ffi::CString;

use crate::arch;
use crate::error::{msg, Result};
use crate::hijack::Hijacker;
use crate::ptrace;

/// Offsets into the scratch page staged inside the tracee.
const PATH_OFF: u64 = 0x000;
/// A kernel `struct sigaction` with `sa_handler = SIG_IGN`. The handler
/// is the first field on every supported architecture.
const ACT_OFF: u64 = 0x100;

fn sigign_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(&(libc::SIG_IGN as u64).to_ne_bytes());
    b
}

pub struct Plan {
    /// Path of the fresh pty slave the target moves to.
    pub slave_path: CString,
    /// Target file descriptors to redirect onto the new terminal.
    pub fds: Vec<i32>,
    /// Whether the target already leads a session (decides between a
    /// plain TIOCNOTTY and the fork/setpgid/setsid dance).
    pub is_session_leader: bool,
}

/// Allocate an anonymous scratch page inside the tracee.
pub fn mmap_scratch(h: &mut Hijacker, verbose: bool) -> Result<u64> {
    let a = arch::arch();
    let scratch = h.syscall(
        a.nr_mmap(),
        [
            0,
            4096,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            (-1i64) as u64,
            0,
        ],
    )?;
    if scratch < 0 {
        return Err(msg(format!("remote mmap failed (errno {})", -scratch)));
    }
    vlog!(verbose, "scratch page at {:#x} in thread {}", scratch as u64, h.tid());
    Ok(scratch as u64)
}

/// Release a scratch page allocated with [`mmap_scratch`].
pub fn munmap_scratch(h: &mut Hijacker, scratch: u64, verbose: bool) {
    let unmap = h.syscall(arch::arch().nr_munmap(), [scratch, 4096, 0, 0, 0, 0]);
    if let Err(e) = unmap {
        vlog!(verbose, "remote munmap failed: {}", e);
    }
}

/// Make the tracee ignore SIGHUP, so it survives its terminal going
/// away. Stages the sigaction in a scratch page.
pub fn ignore_sighup(h: &mut Hijacker, scratch: u64, verbose: bool) -> Result<()> {
    ptrace::write_bytes(h.tid(), scratch + ACT_OFF, &sigign_bytes())?;
    let r = h.syscall(
        arch::arch().nr_rt_sigaction(),
        [libc::SIGHUP as u64, scratch + ACT_OFF, 0, 8, 0, 0],
    )?;
    if r < 0 {
        return Err(msg(format!(
            "remote rt_sigaction(SIGHUP, SIG_IGN) failed (errno {})",
            -r
        )));
    }
    vlog!(verbose, "target now ignores SIGHUP");
    Ok(())
}

pub fn execute(h: &mut Hijacker, plan: &Plan, verbose: bool) -> Result<()> {
    let scratch = mmap_scratch(h, verbose)?;
    let result = execute_inner(h, plan, scratch, verbose);
    // Always release the scratch page, even on failure.
    munmap_scratch(h, scratch, verbose);
    result
}

fn execute_inner(h: &mut Hijacker, plan: &Plan, scratch: u64, verbose: bool) -> Result<()> {
    let a = arch::arch();
    let tid = h.tid();

    // 2. Stage the pty path into the scratch page.
    ptrace::write_bytes(tid, scratch + PATH_OFF, plan.slave_path.as_bytes_with_nul())?;

    // 3. Ignore SIGHUP, so the target survives its old terminal (and
    //    shell) going away.
    ignore_sighup(h, scratch, verbose)?;

    // 4. Session handling: get into a session of our own with no
    //    controlling terminal, so TIOCSCTTY below can succeed.
    if plan.is_session_leader {
        // Already a session leader: just drop the old controlling tty.
        let _ = h.syscall(
            a.nr_ioctl(),
            [plan.fds[0] as u64, libc::TIOCNOTTY, 0, 0, 0, 0],
        );
    } else {
        do_setsid(h, verbose)?;
    }

    // 5. Open the new pty slave inside the tracee.
    let tty_fd = h.syscall(
        a.nr_openat(),
        [
            libc::AT_FDCWD as i64 as u64,
            scratch + PATH_OFF,
            (libc::O_RDWR | libc::O_NOCTTY) as u64,
            0,
            0,
            0,
        ],
    )?;
    if tty_fd < 0 {
        return Err(msg(format!(
            "remote openat({}) failed (errno {})",
            plan.slave_path.to_string_lossy(),
            -tty_fd
        )));
    }
    vlog!(
        verbose,
        "opened {} in target as fd {}",
        plan.slave_path.to_string_lossy(),
        tty_fd
    );

    // 6. Make it the controlling terminal. The pty is freshly allocated,
    //    so no other session owns it and this cannot fail on privileges.
    let r = h.syscall(
        a.nr_ioctl(),
        [tty_fd as u64, libc::TIOCSCTTY, 1, 0, 0, 0],
    )?;
    if r < 0 {
        return Err(msg(format!("remote TIOCSCTTY failed (errno {})", -r)));
    }
    vlog!(verbose, "set the controlling tty");

    // 7. Redirect the selected fds.
    for &fd in &plan.fds {
        let (nr, args) = a.dup_syscall(tty_fd as u64, fd as u64);
        let r = h.syscall(nr, args)?;
        if r < 0 {
            return Err(msg(format!("remote dup to fd {} failed (errno {})", fd, -r)));
        }
    }
    vlog!(verbose, "redirected fds {:?}", plan.fds);

    // 8. Drop the extra reference.
    let _ = h.syscall(a.nr_close(), [tty_fd as u64, 0, 0, 0, 0, 0]);
    Ok(())
}

/// Move the target into a fresh session, so that it is a session leader
/// free of a controlling terminal. `setsid` fails when the target is a
/// process group leader — the common case for shell jobs — so we fork a
/// dummy child inside the target, make the dummy a group leader, move
/// the target's process group under the dummy, and only then setsid.
/// The dummy is killed and reaped afterwards. (Same dance as reptyr.)
fn do_setsid(h: &mut Hijacker, verbose: bool) -> Result<()> {
    let a = arch::arch();
    let target_pid = h.tid();
    let dummy_pid = h.fork_child()?;
    let mut dummy = Hijacker::for_dummy(dummy_pid, h.saved_clone(), h.saved_nr(), verbose)?;

    let retire = |h: &mut Hijacker| {
        let _ = h.syscall(a.nr_kill(), [dummy_pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0]);
        let _ = ptrace::detach(dummy_pid, 0);
        let _ = ptrace::wait(dummy_pid);
    };

    // The dummy becomes its own process group leader.
    let r = dummy.syscall(a.nr_setpgid(), [0, 0, 0, 0, 0, 0])?;
    if r < 0 {
        retire(h);
        return Err(msg(format!("remote setpgid on dummy failed (errno {})", -r)));
    }

    // Move the target's process group under the dummy's group, so the
    // target is no longer a group leader and may setsid().
    for pid in crate::target::procs_in_pgrp(target_pid)? {
        let r = h.syscall(a.nr_setpgid(), [pid as u64, dummy_pid as u64, 0, 0, 0, 0])?;
        if r < 0 {
            vlog!(verbose, "setpgid({}, {}) failed (errno {})", pid, dummy_pid, -r);
        }
    }

    let r = h.syscall(a.nr_setsid(), [0; 6])?;
    if r < 0 {
        retire(h);
        return Err(msg(format!("remote setsid failed (errno {})", -r)));
    }
    vlog!(verbose, "moved target into a fresh session");

    // Retire the dummy: kill it, detach, and reap it inside the target.
    h.syscall(a.nr_kill(), [dummy_pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0])?;
    let _ = ptrace::detach(dummy_pid, 0);
    let _ = ptrace::wait(dummy_pid);
    h.syscall(a.nr_wait4(), [dummy_pid as u64, 0, libc::WNOHANG as u64, 0, 0, 0])?;
    Ok(())
}

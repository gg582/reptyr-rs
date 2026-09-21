//! /proc inspection of the target process: thread list, controlling
//! terminal device, and which fds sit on it.

use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use crate::cli::Streams;
use crate::error::{msg, Result};

pub fn threads(pid: libc::pid_t) -> Result<Vec<libc::pid_t>> {
    let dir = std::fs::read_dir(format!("/proc/{}/task", pid)).map_err(|e| {
        if e.raw_os_error() == Some(libc::ENOENT) {
            msg(format!("no such process: {}", pid))
        } else {
            crate::error::Error::Io(e)
        }
    })?;
    let mut tids = Vec::new();
    for entry in dir.flatten() {
        if let Ok(tid) = entry.file_name().to_string_lossy().parse::<libc::pid_t>() {
            tids.push(tid);
        }
    }
    if tids.is_empty() {
        return Err(msg(format!("process {} has no threads", pid)));
    }
    Ok(tids)
}

/// Parse the fields after `comm` in /proc/<pid>/stat:
/// (pgrp, session, tty_nr_raw).
fn stat_ids(pid: libc::pid_t) -> Result<(u64, u64, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid))?;
    // comm is wrapped in parentheses and may itself contain spaces or
    // parentheses; the fields resume after the last ')'.
    let rest = stat
        .rsplit(')')
        .next()
        .ok_or_else(|| msg("malformed /proc/<pid>/stat"))?;
    let mut fields = rest.split_whitespace();
    // state ppid pgrp session tty_nr
    let parse = |f: Option<&str>| f.and_then(|x| x.parse().ok());
    let pgrp = parse(fields.nth(2)).ok_or_else(|| msg("malformed /proc/<pid>/stat"))?;
    let session = parse(fields.next()).ok_or_else(|| msg("malformed /proc/<pid>/stat"))?;
    let tty_nr = parse(fields.next()).ok_or_else(|| msg("malformed /proc/<pid>/stat"))?;
    Ok((pgrp, session, tty_nr))
}

/// Device numbers (major, minor) of the target's controlling terminal,
/// or None if it has none.
pub fn controlling_tty(pid: libc::pid_t) -> Result<Option<(u64, u64)>> {
    let (_, _, tty_nr) = stat_ids(pid)?;
    if tty_nr == 0 {
        return Ok(None);
    }
    // Kernel new_decode_dev(): the device number as encoded in /proc.
    let major = (tty_nr >> 8) & 0xfff;
    let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
    Ok(Some((major, minor)))
}

/// Whether the target leads its own session.
pub fn is_session_leader(pid: libc::pid_t) -> Result<bool> {
    let (_, session, _) = stat_ids(pid)?;
    Ok(session == pid as u64)
}

/// The target's session id.
pub fn session_id(pid: libc::pid_t) -> Result<libc::pid_t> {
    let (_, session, _) = stat_ids(pid)?;
    Ok(session as libc::pid_t)
}

/// Parent pid of a process.
pub fn ppid_of(pid: libc::pid_t) -> Result<libc::pid_t> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid))?;
    let rest = stat
        .rsplit(')')
        .next()
        .ok_or_else(|| msg("malformed /proc/<pid>/stat"))?;
    // state ppid
    let ppid = rest
        .split_whitespace()
        .nth(1)
        .and_then(|f| f.parse().ok())
        .ok_or_else(|| msg("malformed /proc/<pid>/stat"))?;
    Ok(ppid)
}

/// Every process whose process group is `pgrp`.
pub fn procs_in_pgrp(pgrp: libc::pid_t) -> Result<Vec<libc::pid_t>> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")?.flatten() {
        if !entry.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<libc::pid_t>() else { continue };
        if let Ok((p, _, _)) = stat_ids(pid) {
            if p == pgrp as u64 {
                pids.push(pid);
            }
        }
    }
    Ok(pids)
}

/// The target's current terminal attributes, read through /proc so the
/// target's own settings can be preserved on its new terminal.
pub fn termios_of(pid: libc::pid_t) -> Result<libc::termios> {
    use std::os::unix::fs::OpenOptionsExt;
    for fd in 0..3 {
        let path = format!("/proc/{}/fd/{}", pid, fd);
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(&path)
        else {
            continue;
        };
        if unsafe { libc::isatty(file.as_raw_fd()) } != 1 {
            continue;
        }
        let mut tio: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(file.as_raw_fd(), &mut tio) } == 0 {
            return Ok(tio);
        }
    }
    Err(msg("target is not connected to a terminal (use -s to force attaching anyways)"))
}

/// Target fds that point at the given terminal device.
pub fn fds_on_tty(pid: libc::pid_t, dev: (u64, u64)) -> Result<Vec<i32>> {
    let mut fds = Vec::new();
    let dir = std::fs::read_dir(format!("/proc/{}/fd", pid))?;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Ok(fd) = name.to_string_lossy().parse::<i32>() else { continue };
        // Fds can vanish between listing and statting; skip those.
        let Ok(meta) = std::fs::metadata(entry.path()) else { continue };
        if !meta.file_type().is_char_device() {
            continue;
        }
        let rdev = meta.rdev();
        if (libc::major(rdev) as u64, libc::minor(rdev) as u64) == dev {
            fds.push(fd);
        }
    }
    fds.sort_unstable();
    Ok(fds)
}

/// Decide which target fds to redirect: everything on the controlling
/// terminal, plus fds 0-2 unconditionally with `-s`, filtered by STREAMS
/// for fds 0-2 only.
pub fn fds_to_redirect(pid: libc::pid_t, streams: Streams, force_stdio: bool) -> Result<Vec<i32>> {
    let mut fds = match controlling_tty(pid)? {
        Some(dev) => fds_on_tty(pid, dev)?,
        None => Vec::new(),
    };
    if force_stdio {
        for fd in 0..3 {
            if !fds.contains(&fd) {
                fds.push(fd);
            }
        }
    }
    fds.retain(|&fd| fd > 2 || streams.includes(fd));
    fds.sort_unstable();
    if fds.is_empty() {
        return Err(msg(
            "target has no file descriptors on a terminal; use -s to force fds 0, 1, 2",
        ));
    }
    Ok(fds)
}

/// Path of the target's controlling terminal, e.g. "/dev/pts/4".
pub fn ctty_path(pid: libc::pid_t) -> Result<String> {
    let dev = controlling_tty(pid)?
        .ok_or_else(|| msg("target has no controlling terminal"))?;
    for fd in fds_on_tty(pid, dev)? {
        if let Ok(path) = std::fs::read_link(format!("/proc/{}/fd/{}", pid, fd)) {
            return Ok(path.to_string_lossy().into_owned());
        }
    }
    Err(msg("cannot determine the target's terminal path"))
}

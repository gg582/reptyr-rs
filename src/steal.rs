//! -T mode: steal the master end of the target's pty from its terminal
//! emulator, then proxy it to the current terminal.
//!
//! The emulator (the parent of the target's session leader) is ptraced,
//! its master fd is located by remotely calling TIOCGPTN on each of its
//! ptmx fds, and the fd is passed back to us over a unix socket with
//! SCM_RIGHTS. The emulator's copy is neutralized with /dev/null and the
//! target's session leader is made immune to SIGHUP. Because the
//! emulator is ptraced, this mode needs the same uid or root — children
//! of sshd can only be stolen by root. (Same mechanism as reptyr -T.)

use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;

use crate::arch;
use crate::error::{msg, Result};
use crate::hijack::Hijacker;
use crate::inject;
use crate::ptrace;
use crate::proxy;
use crate::target;

/// Scratch page offsets for staged structures.
const PATH_OFF: u64 = 0x000;
const MSGHDR_OFF: u64 = 0x100;
const CMSG_OFF: u64 = 0x180;
const SOCKADDR_OFF: u64 = 0x200;
const PTN_OFF: u64 = 0x300;

/// makedev(5, 2): the /dev/ptmx device, as compared against st_rdev.
fn is_ptmx(rdev: u64) -> bool {
    libc::major(rdev) == 5 && libc::minor(rdev) == 2
}

pub fn steal_tty(pid: libc::pid_t, verbose: bool) -> Result<()> {
    // 1. The target must sit on a pty; find its session leader and the
    //    terminal emulator (the session leader's parent).
    let slave = target::ctty_path(pid)?;
    let ptn: u32 = slave
        .rsplit('/')
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| msg(format!("target's terminal is not a pty: {}", slave)))?;
    let sid = target::session_id(pid)?;
    let emulator = target::ppid_of(sid)?;
    vlog!(
        verbose,
        "target pty {} (ptn {}), session leader {}, emulator {}",
        slave, ptn, sid, emulator
    );

    // 2. Enter the emulator and find the master fd of the target's pty.
    let mut session = ptrace::Session::attach_all(emulator, verbose)?;
    let mut h = Hijacker::seize(&session, verbose)?;
    let scratch = inject::mmap_scratch(&mut h, verbose)?;
    let result = steal_inner(&mut h, scratch, ptn, sid, verbose);
    inject::munmap_scratch(&mut h, scratch, verbose);
    let sig = h.take_signal();
    let fin = h.finish();
    session.detach_all(sig.unwrap_or(0));
    let out = result?;
    fin?;
    let (master, master_fds, child_fd) = out;

    // 3. Proxy the stolen master to the current terminal.
    vlog!(verbose, "proxying stolen pty (master fds {:?} neutralized)", master_fds);
    let _ = child_fd;
    proxy::run(master, verbose, true, None)
}

fn steal_inner(
    h: &mut Hijacker,
    scratch: u64,
    ptn: u32,
    sid: libc::pid_t,
    verbose: bool,
) -> Result<(RawFd, Vec<i32>, i32)> {
    let emulator = h.tid();
    let master_fds = find_master_fds(h, emulator, ptn, scratch, verbose)?;
    if master_fds.is_empty() {
        return Err(msg(format!(
            "no master fd for pty {} found in emulator {}",
            ptn, emulator
        )));
    }

    // 3. Pass the master fd to us over a unix socket (SCM_RIGHTS).
    let sock = StealSocket::bind()?;
    let child_fd = remote_socket_connect(h, scratch, &sock)?;
    send_fd(h, scratch, child_fd, master_fds[0])?;
    let master = sock.recv_fd()?;
    vlog!(verbose, "stole pty master fd {}", master);

    // 4. Make the target session immune to the coming hangup.
    {
        let mut s2 = ptrace::Session::attach_all(sid, verbose)?;
        let mut h2 = Hijacker::seize(&s2, verbose)?;
        let scratch2 = inject::mmap_scratch(&mut h2, verbose)?;
        let r = inject::ignore_sighup(&mut h2, scratch2, verbose);
        inject::munmap_scratch(&mut h2, scratch2, verbose);
        let sig = h2.take_signal();
        let fin = h2.finish();
        s2.detach_all(sig.unwrap_or(0));
        r.and(fin)?;
    }

    // 5. Neutralize the emulator's copy of the master so it stops
    //    competing for the pty.
    ptrace::write_bytes(h.tid(), scratch + PATH_OFF, b"/dev/null\0")?;
    let a = arch::arch();
    let nullfd = h.syscall(
        a.nr_openat(),
        [
            libc::AT_FDCWD as i64 as u64,
            scratch + PATH_OFF,
            libc::O_RDWR as u64,
            0,
            0,
            0,
        ],
    )?;
    if nullfd >= 0 {
        for &fd in &master_fds {
            let (nr, args) = a.dup_syscall(nullfd as u64, fd as u64);
            let _ = h.syscall(nr, args);
        }
        let _ = h.syscall(a.nr_close(), [nullfd as u64, 0, 0, 0, 0, 0]);
    } else {
        vlog!(verbose, "could not open /dev/null in emulator (errno {})", -nullfd);
    }
    let _ = h.syscall(a.nr_close(), [child_fd as u64, 0, 0, 0, 0, 0]);

    Ok((master, master_fds, child_fd))
}

/// Every fd in the emulator that refers to a ptmx master whose pty
/// number matches the target's.
fn find_master_fds(
    h: &mut Hijacker,
    emulator: libc::pid_t,
    ptn: u32,
    scratch: u64,
    verbose: bool,
) -> Result<Vec<i32>> {
    use std::os::unix::fs::MetadataExt;
    let a = arch::arch();
    let mut fds = Vec::new();
    let dir = std::fs::read_dir(format!("/proc/{}/fd", emulator))?;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Ok(fd) = name.to_string_lossy().parse::<i32>() else { continue };
        let Ok(meta) = std::fs::metadata(entry.path()) else { continue };
        if !is_ptmx(meta.rdev()) {
            continue;
        }
        let r = h.syscall(
            a.nr_ioctl(),
            [fd as u64, libc::TIOCGPTN, scratch + PTN_OFF, 0, 0, 0],
        )?;
        if r < 0 {
            vlog!(verbose, "TIOCGPTN on emulator fd {} failed (errno {})", fd, -r);
            continue;
        }
        let got = ptrace::read_word(h.tid(), scratch + PTN_OFF)? as u32;
        vlog!(verbose, "emulator fd {} is pty master #{}", fd, got);
        if got == ptn {
            fds.push(fd);
        }
    }
    Ok(fds)
}

/// Create a connected unix socket inside the emulator.
fn remote_socket_connect(h: &mut Hijacker, scratch: u64, sock: &StealSocket) -> Result<i32> {
    let a = arch::arch();
    ptrace::write_bytes(h.tid(), scratch + SOCKADDR_OFF, &sock.sockaddr_bytes())?;
    let fd = h.syscall(
        a.nr_socket(),
        [libc::AF_UNIX as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0],
    )?;
    if fd < 0 {
        return Err(msg(format!("remote socket() failed (errno {})", -fd)));
    }
    let r = h.syscall(
        a.nr_connect(),
        [fd as u64, scratch + SOCKADDR_OFF, 110, 0, 0, 0],
    )?;
    if r < 0 {
        let _ = h.syscall(a.nr_close(), [fd as u64, 0, 0, 0, 0, 0]);
        return Err(msg(format!(
            "remote connect() failed (errno {}); the emulator may run as another user (try sudo)",
            -r
        )));
    }
    Ok(fd as i32)
}

/// Send `master_fd` from the emulator to us via SCM_RIGHTS.
fn send_fd(h: &mut Hijacker, scratch: u64, child_fd: i32, master_fd: i32) -> Result<()> {
    let a = arch::arch();
    let msghdr = {
        let mut b = [0u8; 56];
        b[32..40].copy_from_slice(&(scratch + CMSG_OFF).to_ne_bytes()); // msg_control
        b[40..48].copy_from_slice(&20u64.to_ne_bytes()); // msg_controllen = CMSG_LEN(4)
        b
    };
    let cmsg = {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&20u64.to_ne_bytes()); // cmsg_len = CMSG_LEN(4)
        b[8..12].copy_from_slice(&(libc::SOL_SOCKET as u32).to_ne_bytes());
        b[12..16].copy_from_slice(&(libc::SCM_RIGHTS as u32).to_ne_bytes());
        b[16..20].copy_from_slice(&master_fd.to_ne_bytes());
        b
    };
    ptrace::write_bytes(h.tid(), scratch + MSGHDR_OFF, &msghdr)?;
    ptrace::write_bytes(h.tid(), scratch + CMSG_OFF, &cmsg)?;
    let r = h.syscall(
        a.nr_sendmsg(),
        [child_fd as u64, scratch + MSGHDR_OFF, 0, 0, 0, 0],
    )?;
    if r < 0 {
        return Err(msg(format!("remote sendmsg() failed (errno {})", -r)));
    }
    Ok(())
}

/// Our end of the fd-passing socket.
struct StealSocket {
    fd: RawFd,
    addr: libc::sockaddr_un,
    path: std::path::PathBuf,
}

impl StealSocket {
    fn bind() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("reptyr-rs-{}.sock", unsafe { libc::getpid() }));
        let _ = std::fs::remove_file(&path);
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            return Err(msg("socket path too long"));
        }
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(StealSocket { fd, addr, path })
    }

    fn sockaddr_bytes(&self) -> [u8; 110] {
        let mut b = [0u8; 110];
        b[..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        let bytes = unsafe {
            std::slice::from_raw_parts(
                self.addr.sun_path.as_ptr() as *const u8,
                self.addr.sun_path.len(),
            )
        };
        b[2..2 + bytes.len()].copy_from_slice(bytes);
        let _ = &self.path;
        b
    }

    fn recv_fd(&self) -> Result<RawFd> {
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: &mut byte as *mut _ as *mut libc::c_void,
            iov_len: 1,
        };
        let mut cmsg = [0u8; 24];
        let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
        mhdr.msg_iov = &mut iov;
        mhdr.msg_iovlen = 1;
        mhdr.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        mhdr.msg_controllen = cmsg.len();
        let n = unsafe { libc::recvmsg(self.fd, &mut mhdr, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let hdr = unsafe { &*(cmsg.as_ptr() as *const libc::cmsghdr) };
        if hdr.cmsg_level != libc::SOL_SOCKET || hdr.cmsg_type != libc::SCM_RIGHTS {
            return Err(msg("no fd received from the emulator"));
        }
        let fd = unsafe { *(libc::CMSG_DATA(hdr) as *const i32) };
        Ok(fd)
    }
}

impl Drop for StealSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

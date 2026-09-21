//! Terminal proxy loop used by TTY-stealing (-T) and pty (-l/-L) modes.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::error::{msg, Result};
use crate::tty;

static WINCH: AtomicBool = AtomicBool::new(false);

extern "C" fn on_winch(_: libc::c_int) {
    WINCH.store(true, Ordering::SeqCst);
}

fn install_winch_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_winch as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
}

/// Relay traffic between the current terminal and `master` until the
/// session ends. The terminal is put in raw mode for the duration and
/// restored on the way out.
///
/// `exit_on_eio`: a pty master reports EIO once every slave is closed.
/// In -T mode that means the stolen session is gone and we are done; in
/// -l mode it merely means nobody has opened the slave yet, so we wait
/// (unless the spawned command has exited).
pub fn run(
    master: RawFd,
    verbose: bool,
    exit_on_eio: bool,
    mut child: Option<&mut std::process::Child>,
) -> Result<()> {
    if unsafe { libc::isatty(0) } != 1 {
        return Err(msg("stdin is not a terminal; proxy mode must run from a terminal"));
    }
    let saved = tty::make_raw(0)?;
    let _guard = RawModeGuard { fd: 0, saved };
    install_winch_handler();
    forward_winsize(0, master);
    vlog!(verbose, "proxying terminal <-> pty master fd {}", master);

    let mut fds = [
        libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 },
    ];
    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 500) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if WINCH.swap(false, Ordering::SeqCst) {
            forward_winsize(0, master);
        }
        if fds[1].revents != 0 {
            match read_once(master, &mut buf) {
                ReadOutcome::Data(n) => write_all(libc::STDOUT_FILENO, &buf[..n])?,
                ReadOutcome::Eof => break,
                ReadOutcome::NoSlave => {
                    let child_done = match child.as_deref_mut() {
                        Some(c) => c.try_wait()?.is_some(),
                        None => exit_on_eio,
                    };
                    if child_done {
                        break;
                    }
                    // Nobody holds the slave open yet; wait and retry.
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
        if fds[0].revents != 0 {
            match read_once(libc::STDIN_FILENO, &mut buf) {
                ReadOutcome::Data(n) => write_all(master, &buf[..n])?,
                ReadOutcome::Eof | ReadOutcome::NoSlave => break,
            }
        }
    }
    Ok(())
}

enum ReadOutcome {
    Data(usize),
    Eof,
    /// EIO: the pty currently has no slave open.
    NoSlave,
}

fn read_once(fd: RawFd, buf: &mut [u8]) -> ReadOutcome {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            return ReadOutcome::Data(n as usize);
        }
        if n == 0 {
            return ReadOutcome::Eof;
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EIO) {
            return ReadOutcome::NoSlave;
        }
        if e.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        // A dead stdin (terminal hangup) ends the proxy like EOF.
        return ReadOutcome::Eof;
    }
}

fn write_all(fd: RawFd, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        data = &data[n as usize..];
    }
    Ok(())
}

fn forward_winsize(from: RawFd, to: RawFd) {
    if let Ok(ws) = tty::get_winsize(from) {
        unsafe {
            libc::ioctl(to, libc::TIOCSWINSZ as libc::c_ulong, &ws);
        }
    }
}

struct RawModeGuard {
    fd: RawFd,
    saved: libc::termios,
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

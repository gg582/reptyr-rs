//! Local terminal queries and pty creation.

use std::os::fd::AsRawFd;

use crate::error::Result;

fn ioctl_mut<T>(fd: libc::c_int, request: libc::c_ulong, arg: &mut T) -> Result<()> {
    if unsafe { libc::ioctl(fd, request, arg) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub fn get_winsize(fd: libc::c_int) -> Result<libc::winsize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    ioctl_mut(fd, libc::TIOCGWINSZ as libc::c_ulong, &mut ws)?;
    Ok(ws)
}

pub fn get_termios(fd: libc::c_int) -> Result<libc::termios> {
    let mut tio: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut tio) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(tio)
}

/// Put the terminal into raw mode; returns the saved attributes.
pub fn make_raw(fd: libc::c_int) -> Result<libc::termios> {
    let saved = get_termios(fd)?;
    let mut raw = saved;
    unsafe { libc::cfmakeraw(&mut raw) };
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(saved)
}

/// Open a fresh pty master; returns it with the slave's path.
pub fn open_pty_master() -> Result<(std::fs::File, String)> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
        .open("/dev/ptmx")?;
    let mut unlock: libc::c_int = 0;
    ioctl_mut(file.as_raw_fd(), libc::TIOCSPTLCK as libc::c_ulong, &mut unlock)?;
    let mut num: libc::c_uint = 0;
    ioctl_mut(file.as_raw_fd(), libc::TIOCGPTN as libc::c_ulong, &mut num)?;
    Ok((file, format!("/dev/pts/{}", num)))
}

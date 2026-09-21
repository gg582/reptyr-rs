//! reptyr-rs — reparent a running program to a new terminal.
//!
//! Module map (the jackpr pipeline, generalized):
//!   cli      command line
//!   target   /proc inspection of the target process
//!   tty      local terminal queries and pty creation
//!   ptrace   thin ptrace(2) wrappers + attach/detach session
//!   arch     architecture-specific register/syscall ABI details
//!   hijack   syscall-hijack engine (architecture-free)
//!   inject   the redirection plan executed inside the tracee (arch-free)
//!   proxy    terminal relay for -T and -l/-L modes

#[macro_export]
macro_rules! vlog {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose {
            eprintln!("[reptyr-rs] {}", format_args!($($arg)*));
        }
    };
}

mod arch;
mod cli;
mod error;
mod hijack;
mod inject;
mod proxy;
mod ptrace;
mod steal;
mod target;
mod tty;

use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;

use error::{msg, Result};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(first) = args.first() {
        if first == "-h" || first == "--help" {
            print!("{}", cli::usage());
            return;
        }
        if first == "-v" || first == "--version" {
            println!("reptyr-rs {}", cli::VERSION);
            return;
        }
    }
    match run(&args) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("reptyr-rs: error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run(args: &[String]) -> Result<()> {
    let opts = cli::parse(args)?;
    match opts.mode {
        cli::Mode::Attach { pid, streams, force_stdio } => attach(pid, streams, force_stdio, opts.verbose),
        cli::Mode::StealTty { pid } => steal_tty(pid, opts.verbose),
        cli::Mode::Proxy { login, command } => proxy_mode(login, command, opts.verbose),
    }
}

/// Default mode: ptrace the target and move it to the current terminal.
fn attach(pid: libc::pid_t, streams: cli::Streams, force_stdio: bool, verbose: bool) -> Result<()> {
    if pid == unsafe { libc::getpid() } {
        return Err(msg("refusing to attach to myself"));
    }
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid)).map_err(|e| {
        if e.raw_os_error() == Some(libc::ENOENT) {
            msg(format!("no such process: {}", pid))
        } else {
            error::Error::Io(e)
        }
    })?;
    if cmdline.is_empty() {
        return Err(msg("target has no command line (zombie or kernel thread?)"));
    }

    let fds = target::fds_to_redirect(pid, streams, force_stdio)?;
    let is_session_leader = target::is_session_leader(pid)?;

    // The target moves to a fresh pty, not directly to our terminal:
    // a fresh slave has no owning session, so TIOCSCTTY succeeds without
    // privileges. We then proxy it to this terminal.
    let (master, slave_path) = tty::open_pty_master()?;
    match target::termios_of(pid) {
        Ok(tio) => {
            if unsafe { libc::tcsetattr(master.as_raw_fd(), libc::TCSANOW, &tio) } == -1 {
                vlog!(verbose, "tcsetattr on the new pty failed: {}", std::io::Error::last_os_error());
            }
        }
        Err(e) if !force_stdio => return Err(e),
        Err(e) => vlog!(verbose, "no target termios to preserve: {}", e),
    }
    vlog!(verbose, "arch backend: {}", arch::arch().name());
    vlog!(verbose, "moving {} to {} (fds {:?})", pid, slave_path, fds);

    let mut session = ptrace::Session::attach_all(pid, verbose)?;
    let mut hijacker = hijack::Hijacker::seize(&session, verbose)?;
    let plan = inject::Plan {
        slave_path: std::ffi::CString::new(slave_path.clone())
            .map_err(|_| msg("terminal path contains a NUL byte"))?,
        fds,
        is_session_leader,
    };
    let exec = inject::execute(&mut hijacker, &plan, verbose);
    let sig = hijacker.take_signal();
    let fin = hijacker.finish();
    session.detach_all(sig.unwrap_or(0));
    exec.and(fin)?;
    vlog!(verbose, "attached; proxying {} to this terminal (ctrl-d detaches)", slave_path);
    proxy::run(master.as_raw_fd(), verbose, true, None)
}

/// -T: take over the master end of the target's pty.
fn steal_tty(pid: libc::pid_t, verbose: bool) -> Result<()> {
    steal::steal_tty(pid, verbose)
}

/// -l/-L: fresh pty proxied to this terminal.
fn proxy_mode(login: bool, command: Vec<String>, verbose: bool) -> Result<()> {
    let (master, slave_name) = tty::open_pty_master()?;
    println!("{}", slave_name);
    let mut child = if command.is_empty() {
        None
    } else {
        Some(spawn_with_pty(&command, &slave_name, login)?)
    };
    let res = proxy::run(master.as_raw_fd(), verbose, false, child.as_mut());
    if let Some(mut c) = child {
        let _ = c.wait();
    }
    res
}

fn spawn_with_pty(command: &[String], slave: &str, login: bool) -> Result<std::process::Child> {
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.env("REPTYR_PTY", slave);
    if login {
        use std::os::unix::fs::OpenOptionsExt;
        let slave_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(slave)?;
        let ctty = slave_file.try_clone()?;
        cmd.stdin(std::process::Stdio::from(slave_file.try_clone()?))
            .stdout(std::process::Stdio::from(slave_file.try_clone()?))
            .stderr(std::process::Stdio::from(slave_file));
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(ctty.as_raw_fd(), libc::TIOCSCTTY as libc::c_ulong, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    Ok(cmd.spawn()?)
}

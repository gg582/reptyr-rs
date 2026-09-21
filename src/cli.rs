use crate::error::{msg, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which of the target's standard streams to redirect. Only meaningful
/// for fds 0-2; fds above 2 found on the controlling terminal are always
/// redirected.
#[derive(Debug, Clone, Copy)]
pub struct Streams {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
}

impl Streams {
    fn all() -> Self {
        Streams { stdin: true, stdout: true, stderr: true }
    }

    pub fn includes(&self, fd: i32) -> bool {
        match fd {
            0 => self.stdin,
            1 => self.stdout,
            2 => self.stderr,
            _ => true,
        }
    }
}

#[derive(Debug)]
pub enum Mode {
    /// Default mode: ptrace the target and move it to the current terminal.
    Attach { pid: libc::pid_t, streams: Streams, force_stdio: bool },
    /// -T: steal the master end of the target's pty (no ptrace).
    StealTty { pid: libc::pid_t },
    /// -l/-L: create a fresh pty and proxy it to the current terminal.
    Proxy { login: bool, command: Vec<String> },
}

pub struct Options {
    pub mode: Mode,
    pub verbose: bool,
}

pub fn parse(args: &[String]) -> Result<Options> {
    let mut verbose = false;
    let mut force_stdio = false;
    let mut steal_tty = false;
    let mut pty_mode: Option<bool> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut no_more_flags = false;

    for arg in args {
        if !no_more_flags {
            match arg.as_str() {
                "--" => {
                    no_more_flags = true;
                    continue;
                }
                "-V" | "--verbose" => {
                    verbose = true;
                    continue;
                }
                "-s" => {
                    force_stdio = true;
                    continue;
                }
                "-T" => {
                    steal_tty = true;
                    continue;
                }
                "-l" => {
                    pty_mode = Some(false);
                    continue;
                }
                "-L" => {
                    pty_mode = Some(true);
                    continue;
                }
                _ if arg.starts_with('-') && arg.len() > 1 => {
                    return Err(msg(format!("unknown option: {} (try -h)", arg)));
                }
                _ => {}
            }
        }
        positional.push(arg.clone());
    }

    if let Some(login) = pty_mode {
        if steal_tty || force_stdio {
            return Err(msg("-l/-L cannot be combined with -T or -s"));
        }
        return Ok(Options { mode: Mode::Proxy { login, command: positional }, verbose });
    }
    if steal_tty {
        if force_stdio {
            return Err(msg("-T cannot be combined with -s"));
        }
        let pid = parse_pid(positional.first())?;
        return Ok(Options { mode: Mode::StealTty { pid }, verbose });
    }

    let pid = parse_pid(positional.first())?;
    let streams = match positional.get(1) {
        Some(s) => parse_streams(s)?,
        None => Streams::all(),
    };
    if positional.len() > 2 {
        return Err(msg("too many arguments (try -h)"));
    }
    Ok(Options { mode: Mode::Attach { pid, streams, force_stdio }, verbose })
}

fn parse_pid(arg: Option<&String>) -> Result<libc::pid_t> {
    let s = arg.ok_or_else(|| msg("missing PID (try -h)"))?;
    let pid: i64 = s.parse().map_err(|_| msg(format!("invalid pid: {}", s)))?;
    if pid <= 0 || pid > libc::pid_t::MAX as i64 {
        return Err(msg(format!("invalid pid: {}", s)));
    }
    Ok(pid as libc::pid_t)
}

fn parse_streams(s: &str) -> Result<Streams> {
    let mut streams = Streams { stdin: false, stdout: false, stderr: false };
    for token in s.split('|') {
        match token {
            "stdin" => streams.stdin = true,
            "stdout" => streams.stdout = true,
            "stderr" => streams.stderr = true,
            _ => return Err(msg(format!(
                "invalid stream '{}': expected stdin|stdout|stderr",
                token
            ))),
        }
    }
    if !streams.stdin && !streams.stdout && !streams.stderr {
        return Err(msg("empty stream selection"));
    }
    Ok(streams)
}

pub fn usage() -> &'static str {
    "reptyr-rs — reparent a running program to a new terminal\n\
     \n\
     USAGE:\n\
     \x20   reptyr-rs [-s] [-V] PID [STREAMS]\n\
     \x20   reptyr-rs -T [-V] PID\n\
     \x20   reptyr-rs -l|-L [-V] [COMMAND [ARGS]...]\n\
     \n\
     The target is moved to a freshly allocated pty whose master is\n\
     proxied to this terminal; reptyr-rs stays in the foreground until\n\
     the target's session ends.\n\
     \n\
     OPTIONS:\n\
     \x20   -s   Also redirect fds 0, 1 and 2 unconditionally, even when they\n\
     \x20       are not connected to the target's controlling terminal\n\
     \x20   -T   TTY-stealing mode: take over the master end of the target's\n\
     \x20       pty instead of ptracing a single process (grabs every process\n\
     \x20       on that terminal; may need root)\n\
     \x20   -l   Create a new pty, print its slave path, and proxy it to this\n\
     \x20       terminal. With COMMAND, runs it with REPTYR_PTY set to the\n\
     \x20       slave path\n\
     \x20   -L   Like -l, but runs COMMAND with fds 0-2 on the new pty, in a\n\
     \x20       fresh session with the pty as its controlling terminal\n\
     \x20   -V   Verbose debug output\n\
     \x20   -v   Print version and exit\n\
     \x20   -h   Print this help and exit\n\
     \n\
     STREAMS: 'stdin', 'stdout', 'stderr' joined with '|' (default: all).\n\
     Only fds 0-2 are filtered; other fds on the target's controlling\n\
     terminal are always redirected.\n\
     \n\
     EXAMPLES:\n\
     \x20   reptyr-rs 1234\n\
     \x20   reptyr-rs -s 1234 stdout|stderr\n\
     \x20   reptyr-rs -T 1234\n\
     \x20   reptyr-rs -L tmux new-session\n"
}

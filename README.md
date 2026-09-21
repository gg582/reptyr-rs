# reptyr-rs

Reparent a running program to a new terminal — a Rust rewrite of
[reptyr](https://github.com/nelhage/reptyr).

Started a long-running process over SSH but have to leave and don't want
to interrupt it? Start a `screen`/`tmux` session, use `reptyr-rs` to grab
the process, and kill the SSH session on your way out.

Unlike simpler tools (`retty`), reptyr-rs moves the process's
**controlling terminal**, not just its file descriptors — so job control
(`^C`, `^Z`) and window-size propagation keep working.

## Features

- **Default attach mode** (`reptyr-rs PID`): ptraces the target, moves it
  to a freshly allocated pty, and proxies that pty to your current
  terminal. The fresh pty has no owning session, so the controlling
  terminal can be acquired without privileges.
- **Controlling-terminal move** (`TIOCNOTTY` → fork/`setpgid`/`setsid`
  dance → `TIOCSCTTY`), including the process-group-leader case that
  plain `setsid` can't handle.
- **Target survives its old terminal**: `SIGHUP` is set to `SIG_IGN`
  inside the target before the move.
- **Terminal settings preserved**: the target's current termios is copied
  to the new pty; window size is forwarded continuously (with `SIGWINCH`).
- **`-s`**: unconditionally redirect fds 0–2, even when the target has no
  controlling terminal.
- **`STREAMS` filter**: redirect only `stdin`/`stdout`/`stderr`
  (e.g. `reptyr-rs PID stdout|stderr`).
- **`-T` (tty-stealing)**: instead of ptracing one process, locate the
  terminal emulator that holds the master end of the target's pty, and
  take the master over — grabbing every process on that terminal. The fd
  is passed back over a unix socket (`SCM_RIGHTS`); the emulator's copy is
  neutralized with `/dev/null`.
- **`-l` / `-L`**: allocate a fresh pty, print its slave path, and proxy
  it to the current terminal (with `-L`, run a command on it in a fresh
  session with the pty as its controlling terminal, `REPTYR_PTY` set).
- **Safe by construction**: every thread of the target is seized and
  later detached (guaranteed by a drop guard); registers are always
  restored; swallowed signals are re-delivered on detach; the original
  syscall is never lost, even if the hijack fails midway.

## Usage

```
reptyr-rs [-s] [-V] PID [STREAMS]      attach PID to a fresh pty, proxy it here
reptyr-rs -T [-V] PID                  steal the target's pty master
reptyr-rs -l|-L [-V] [COMMAND ...]     fresh pty proxied to this terminal

  -s   also redirect fds 0, 1, 2 unconditionally
  -T   tty-stealing mode (may need root for processes of other users)
  -l   print the new pty slave path and proxy it
  -L   like -l, but run COMMAND with fds 0-2 on the new pty
  -V   verbose debug output
```

`STREAMS` is any of `stdin`, `stdout`, `stderr` joined with `|`
(default: all). It only filters fds 0–2; other fds found on the target's
controlling terminal are always redirected.

After attaching, the target appears stopped or backgrounded to the shell
it was launched from. For maximal safety, run `bg; disown` in the old
shell — though the target will survive the old shell going away either
way.

## Build

```
cargo build --release
```

The only dependency is `libc`. The binary lands in
`target/release/reptyr-rs`.

## How it works

1. Every thread of the target is seized with `PTRACE_SEIZE` and stopped
   with `PTRACE_INTERRUPT`.
2. One thread is driven to a natural **syscall-entry stop**
   (`PTRACE_SYSCALL` + `PTRACE_O_TRACESYSGOOD`, classified with
   `PTRACE_GET_SYSCALL_INFO`). Threads blocked in a syscall re-enter it
   when resumed, so even an idle `cat` yields an entry stop immediately.
3. The register state at that stop is saved with an architecture fixup
   (x86_64: `rip -= 2`, `rax = orig_rax`; aarch64: `pc -= 4`), so that
   restoring it later re-executes the original syscall correctly.
4. Each injected syscall only replaces the syscall number and argument
   registers at an entry stop. After it runs, only the instruction
   pointer is rewound, so the next resume re-enters at the same syscall
   instruction — an entry that is immediately overwritten by the next
   injection and never dispatches. **No tracee memory is patched and no
   instruction is fabricated.**
5. At the end, the full saved state is restored at the last injected
   syscall's exit stop and the tracer detaches. The tracee returns to the
   syscall instruction and re-executes it with the original number and
   arguments, so the displaced syscall runs exactly once.

The redirection plan executed inside the target (as hijacked syscalls):

```
mmap scratch page → stage pty path + sigaction → rt_sigaction(SIGHUP, SIG_IGN)
→ session move (TIOCNOTTY, or fork/setpgid/setsid) → openat(new pty slave)
→ TIOCSCTTY → dup2 onto selected fds → close → munmap
```

### Architecture-free structure

Everything that touches register layouts, syscall numbers, or calling
conventions lives behind one `Arch` trait (`src/arch/`). The hijack
engine, the injection plan, and all modes are architecture-independent;
porting means adding one file. Backends: `x86_64` (tested) and `aarch64`
(written to the same contract, not yet exercised on hardware).

## Limitations

- Attaching to a process under a seccomp filter may kill it, if the
  filter rejects the injected syscalls (same as reptyr).
- Programs that poll stdin via `epoll` (e.g. rtorrent) keep the old fd
  internally and may not accept input after the move (same as reptyr).
- Attaching to a process with children only moves the one process (same
  as reptyr).
- `-T` requires ptrace access to the terminal emulator: children of
  `sshd` can only be stolen by root (same as reptyr).
- The tool always runs on the host architecture; it does not attach
  across architectures.

## License

MIT

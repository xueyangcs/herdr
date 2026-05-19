//! Background lifecycle control for `herdr ws-server`.
//!
//! Lets the in-app Settings UI start and stop the WebSocket gateway
//! subprocess transparently. State is tracked via a PID file under the
//! session data dir; logs are written next to herdr.log.

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::Engine as _;

const PID_FILE: &str = "ws-server.pid";
const LOG_FILE: &str = "ws-server.log";

/// Generate a fresh random password suitable as the default ws-server
/// `--password` value. 16 bytes of `/dev/urandom` base64-encoded
/// (about 22 characters, ~128 bits of entropy).
pub fn generate_password() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    let mut urandom = fs::File::open("/dev/urandom")?;
    urandom.read_exact(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn pid_path() -> PathBuf {
    crate::session::data_dir().join(PID_FILE)
}

fn log_path() -> PathBuf {
    crate::session::data_dir().join(LOG_FILE)
}

/// Read the recorded PID file and return the PID if a `herdr ws-server`
/// process is still alive.
pub fn current_pid() -> Option<u32> {
    let raw = fs::read_to_string(pid_path()).ok()?;
    let pid: u32 = raw.trim().parse().ok()?;
    if is_alive(pid) {
        Some(pid)
    } else {
        let _ = fs::remove_file(pid_path());
        None
    }
}

pub fn is_running() -> bool {
    current_pid().is_some()
}

/// Stop any running gateway and start a fresh one with the given settings.
pub fn restart(port: u16, password: Option<&str>, tls: bool) -> io::Result<u32> {
    let _ = stop();
    // Give the old process a moment to release the listening port.
    std::thread::sleep(Duration::from_millis(150));
    start(port, password, tls)
}

/// Spawn a detached `herdr ws-server` process logging to `data_dir()/ws-server.log`.
/// Returns an error if a server is already running or the spawn fails.
pub fn start(port: u16, password: Option<&str>, tls: bool) -> io::Result<u32> {
    if is_running() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "ws-server is already running",
        ));
    }

    if password.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ws-server requires a password; configure [server] password or enable from Settings",
        ));
    }

    let exe = std::env::current_exe()?;
    let log = log_path();
    if let Some(parent) = log.parent() {
        fs::create_dir_all(parent)?;
    }
    // Append so previous sessions' logs are preserved across restarts.
    let log_handle = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)?;
    let log_err = log_handle.try_clone()?;

    let mut command = Command::new(&exe);
    command.arg("ws-server").arg("--port").arg(port.to_string());
    if let Some(pw) = password {
        command.arg("--password").arg(pw);
    }
    if tls {
        command.arg("--tls");
    }

    eprintln!(
        "herdr: spawning ws-server (port={port}, tls={tls}, password=configured{})",
        if tls { ", --tls" } else { "" }
    );

    use std::os::unix::process::CommandExt;
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_handle))
        .stderr(Stdio::from(log_err));

    let child = command.spawn()?;
    let pid = child.id();
    fs::write(pid_path(), pid.to_string())?;
    // Forget the child so we don't try to wait on it.
    std::mem::forget(child);
    Ok(pid)
}

/// Stop the running ws-server process if any. Returns true if a process was killed.
pub fn stop() -> io::Result<bool> {
    let Some(pid) = current_pid() else {
        return Ok(false);
    };
    // SAFETY: kill is a syscall that operates on a PID we wrote ourselves.
    // The PID is known-alive from current_pid().
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = fs::remove_file(pid_path());
    Ok(true)
}

fn is_alive(pid: u32) -> bool {
    // Sending signal 0 checks whether the process exists without
    // actually delivering a signal.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

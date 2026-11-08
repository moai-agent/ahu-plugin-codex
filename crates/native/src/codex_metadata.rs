//! Bounded metadata inspection for reviewed Codex profiles, before any thread starts.
//! The native process retains authentication and managed policy. Raw responses
//! and stderr are never persisted or included in diagnostics.
use crate::util::{Error, Result};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const LIMIT: usize = 1024 * 1024;

/// Read the current Codex account through the native app-server without
/// starting a thread or refreshing credentials. Raw account responses are
/// returned only to the in-process identity normalizer and are never logged.
pub fn read_account(
    executable: &Path,
    cwd: &Path,
    home: &Path,
    environment: &crate::Environment,
) -> Result<Value> {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(executable);
    crate::process::configure(&mut command, home, environment);
    command
        .args(["app-server", "--listen", "stdio://"])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| Error::new("cannot start read-only Codex account inspection"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let deadline = Instant::now() + Duration::from_secs(10);
    let outcome = (|| {
        let fd = stdout.as_raw_fd();
        // SAFETY: stdout owns this live fd; fcntl only reads/sets its status flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error::new("cannot bound Codex account reads"));
        }
        let mut reader = BufReader::new(stdout);
        let mut total = 0;
        let send = |stdin: &mut std::process::ChildStdin, value: Value| -> Result<()> {
            let mut bytes = serde_json::to_vec(&value)?;
            bytes.push(b'\n');
            stdin
                .write_all(&bytes)
                .map_err(|_| Error::new("Codex account inspection input closed"))
        };
        send(
            &mut stdin,
            json!({"id":1,"method":"initialize","params":{
                "clientInfo":{"name":"ahu_auth_binding","version":"1.0.0"},
                "capabilities":{"experimentalApi":true}}}),
        )?;
        let mut initialized = false;
        for _ in 0..128 {
            let line = read_metadata_line(&mut reader, &mut total, deadline)?;
            let event: Value = serde_json::from_slice(&line)
                .map_err(|_| Error::new("invalid Codex account response"))?;
            if let Some(error) = event.get("error").filter(|v| !v.is_null()) {
                return Err(Error::new(format!(
                    "Codex account inspection RPC failed (code {:?}); response omitted",
                    error.get("code").and_then(Value::as_i64)
                )));
            }
            match event.get("id").and_then(Value::as_u64) {
                Some(1) if !initialized => {
                    initialized = true;
                    send(&mut stdin, json!({"method":"initialized"}))?;
                    send(
                        &mut stdin,
                        json!({"id":2,"method":"account/read","params":{"refreshToken":false}}),
                    )?;
                }
                Some(2) if initialized => {
                    let result = event
                        .get("result")
                        .filter(|v| v.is_object())
                        .ok_or_else(|| Error::new("Codex returned no account metadata"))?;
                    return Ok(result.clone());
                }
                None if event.get("id").is_none() => (),
                _ => return Err(Error::new("unexpected Codex account response")),
            }
        }
        Err(Error::new("Codex account event limit exceeded"))
    })();
    drop(stdin);
    crate::process::signal_group(child.id(), libc::SIGKILL);
    let _ = child.wait();
    outcome
}

pub fn read_budget(
    executable: &Path,
    cwd: &Path,
    home: &Path,
    environment: &crate::Environment,
) -> Result<(Value, Value)> {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(executable);
    crate::process::configure(&mut command, home, environment);
    command
        .args(["app-server", "--listen", "stdio://"])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| Error::new("cannot start read-only Codex budget inspection"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let deadline = Instant::now() + Duration::from_secs(10);
    let outcome = (|| {
        let fd = stdout.as_raw_fd();
        // SAFETY: stdout owns this live fd; fcntl only reads/sets its status flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error::new("cannot bound Codex budget reads"));
        }
        let mut reader = BufReader::new(stdout);
        let mut total = 0;
        let send = |stdin: &mut std::process::ChildStdin, value: Value| -> Result<()> {
            let mut bytes = serde_json::to_vec(&value)?;
            bytes.push(b'\n');
            stdin
                .write_all(&bytes)
                .map_err(|_| Error::new("Codex budget inspection input closed"))
        };
        send(
            &mut stdin,
            json!({"id":1,"method":"initialize","params":{
                "clientInfo":{"name":"ahu_auth_binding","version":"1.0.0"},
                "capabilities":{"experimentalApi":true}}}),
        )?;
        let mut initialized = false;
        let mut account_meta = None;
        for _ in 0..128 {
            let line = read_metadata_line(&mut reader, &mut total, deadline)?;
            let event: Value = serde_json::from_slice(&line)
                .map_err(|_| Error::new("invalid Codex budget response"))?;
            if let Some(error) = event.get("error").filter(|v| !v.is_null()) {
                return Err(Error::new(format!(
                    "Codex budget inspection RPC failed (code {:?}); response omitted",
                    error.get("code").and_then(Value::as_i64)
                )));
            }
            match event.get("id").and_then(Value::as_u64) {
                Some(1) if !initialized => {
                    initialized = true;
                    send(&mut stdin, json!({"method":"initialized"}))?;
                    send(
                        &mut stdin,
                        json!({"id":2,"method":"account/read","params":{"refreshToken":false}}),
                    )?;
                }
                Some(2) if initialized => {
                    let result = event
                        .get("result")
                        .filter(|v| v.is_object())
                        .ok_or_else(|| Error::new("Codex returned no account metadata"))?;
                    account_meta = Some(result.clone());
                    send(
                        &mut stdin,
                        json!({"id":3,"method":"account/rateLimits/read","params":{}}),
                    )?;
                }
                Some(3) if initialized && account_meta.is_some() => {
                    let result = event
                        .get("result")
                        .filter(|v| v.is_object())
                        .ok_or_else(|| Error::new("Codex returned no rate limits metadata"))?;
                    return Ok((account_meta.unwrap(), result.clone()));
                }
                None if event.get("id").is_none() => (),
                _ => return Err(Error::new("unexpected Codex budget response")),
            }
        }
        Err(Error::new("Codex budget event limit exceeded"))
    })();
    drop(stdin);
    crate::process::signal_group(child.id(), libc::SIGKILL);
    let _ = child.wait();
    outcome
}

/// Uses exactly the executable and isolation switches used by batch execution.
/// Requirements must be absent: a future policy change refuses admission rather
/// than suppressing mandatory plugin hooks or changing the required features.
pub fn inspect(
    executable: &Path,
    cwd: &Path,
    version: &str,
    home: &Path,
    environment: &crate::Environment,
) -> Result<Value> {
    let profile = super::isolation::profile("codex", version).ok_or_else(|| {
        Error::new("no reviewed Codex metadata isolation profile for this version")
    })?;
    let mut command = Command::new(executable);
    crate::process::configure(&mut command, home, environment);
    command
        .args(["app-server", "--listen", "stdio://"])
        .args(profile.args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| Error::new("cannot start native Codex metadata inspection"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let deadline = Instant::now() + Duration::from_secs(30);
    let outcome = (|| {
        // A detached descendant can retain the write end after the owned group
        // dies. Read on this thread with a deadline, never join an EOF reader.
        let fd = stdout.as_raw_fd();
        // SAFETY: stdout owns this live descriptor throughout inspection. These
        // operations only read/set descriptor flags; no ownership is transferred.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error::new("cannot bound native Codex metadata reads"));
        }
        let mut reader = BufReader::new(stdout);
        let mut total = 0;
        let send = |stdin: &mut std::process::ChildStdin, value: Value| -> Result<()> {
            let mut bytes = serde_json::to_vec(&value)?;
            bytes.push(b'\n');
            stdin
                .write_all(&bytes)
                .map_err(|_| Error::new("native Codex metadata input closed"))
        };
        send(
            &mut stdin,
            json!({"id":1,"method":"initialize","params":{
            "clientInfo":{"name":"ahu_headless_inspection","version":"1.0.0"},
            "capabilities":{"experimentalApi":true}}}),
        )?;
        let mut initialized = false;
        let mut hooks = None;
        let mut requirements = false;
        for _ in 0..256 {
            let line = read_metadata_line(&mut reader, &mut total, deadline)?;
            let event: Value = serde_json::from_slice(&line)
                .map_err(|_| Error::new("invalid native Codex metadata response"))?;
            if !event.is_object() {
                return Err(Error::new(
                    "native Codex metadata response is not an object",
                ));
            }
            if let Some(error) = event.get("error").filter(|error| !error.is_null()) {
                return Err(Error::new(format!(
                    "native Codex metadata RPC error (request {:?}, code {:?}); raw native error omitted",
                    event.get("id").and_then(Value::as_u64),
                    error.get("code").and_then(Value::as_i64)
                )));
            }
            if event
                .get("method")
                .and_then(Value::as_str)
                .is_some_and(|m| m.to_ascii_lowercase().contains("warning"))
            {
                return Err(Error::new(format!(
                    "native Codex metadata warning (SHA-256 {}); raw native warning omitted",
                    crate::util::digest_bytes(&serde_json::to_vec(
                        event.get("params").unwrap_or(&Value::Null)
                    )?)
                )));
            }
            match event.get("id").and_then(Value::as_u64) {
                Some(1)
                    if !initialized
                        && event.get("result").is_some_and(Value::is_object)
                        && event.get("method").is_none() =>
                {
                    initialized = true;
                    send(&mut stdin, json!({"method":"initialized"}))?;
                    send(
                        &mut stdin,
                        json!({"id":2,"method":"hooks/list","params":{"cwds":[cwd]}}),
                    )?;
                    send(
                        &mut stdin,
                        json!({"id":3,"method":"configRequirements/read","params":null}),
                    )?;
                }
                Some(2) if initialized && hooks.is_none() => {
                    hooks = Some(
                        event
                            .get("result")
                            .cloned()
                            .ok_or_else(|| Error::new("missing native hook result"))?,
                    );
                }
                Some(3) if initialized && !requirements => {
                    require_no_policy(event.get("result").unwrap_or(&Value::Null))?;
                    requirements = true;
                }
                Some(_) => return Err(Error::new("unexpected native Codex metadata response")),
                None if event.get("id").is_none() => (),
                None => return Err(Error::new("unexpected native Codex metadata request")),
            }
            if requirements && let Some(hooks) = hooks.take() {
                return Ok(hooks);
            }
        }
        Err(Error::new("native Codex metadata event limit exceeded"))
    })();
    drop(stdin);
    // This process is owned exclusively by this inspection, never a daemon or
    // an existing user session. Kill its group even after successful metadata.
    crate::process::signal_group(child.id(), libc::SIGKILL);
    let _ = child.wait();
    outcome
}

fn read_metadata_line<R: Read + AsRawFd>(
    reader: &mut BufReader<R>,
    total: &mut usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::new("native Codex metadata inspection timed out"));
        }
        // read_until preserves partial data on WouldBlock. Include that data in
        // the limit before trying again, even when no newline has arrived.
        let result = reader
            .by_ref()
            .take((LIMIT - *total - line.len() + 1) as u64)
            .read_until(b'\n', &mut line);
        if line.len() > LIMIT - *total {
            return Err(Error::new(
                "native Codex metadata exceeded the inspection bound",
            ));
        }
        match result {
            Ok(0) if line.is_empty() => {
                return Err(Error::new(
                    "native Codex metadata inspection exited before completion",
                ));
            }
            Ok(_) => {
                *total += line.len();
                return Ok(line);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(_) => return Err(Error::new("cannot read native Codex metadata")),
        }
        let mut descriptor = libc::pollfd {
            fd: reader.get_ref().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, i32::MAX as u128) as i32;
        // SAFETY: descriptor points to one initialized pollfd for a live pipe.
        let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if ready < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(Error::new("cannot wait for native Codex metadata"));
        }
    }
}

fn require_no_policy(result: &Value) -> Result<()> {
    if result.get("requirements") != Some(&Value::Null) {
        return Err(Error::new(
            "Codex managed requirements are present or unresolved; the optional-plugin isolation profile is not admitted",
        ));
    }
    Ok(())
}

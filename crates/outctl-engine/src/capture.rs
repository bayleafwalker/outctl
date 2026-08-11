use crate::presentation::{
    render_capture_files, PersistenceMode, PresentationOptions, PresentationResult,
};
use crate::storage::{capture_id, rename_entry, PrivateDir, CHUNK_BYTES};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct CaptureOptions {
    pub argv: Vec<OsString>,
    pub spool_root: PathBuf,
    pub max_bytes: u64,
    pub timeout: Option<Duration>,
    pub cwd: Option<PathBuf>,
    pub workspace_id: Option<String>,
    pub required_capture: bool,
}

pub const MAX_CAPTURE_BYTES: u64 = 268_435_456;

struct Spool {
    partial_root: PrivateDir,
    captures_root: PrivateDir,
    partial: PrivateDir,
    partial_name: String,
    final_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct CommandResult {
    pub started: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub signals_sent: Vec<i32>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct CaptureTiming {
    pub command_ms: u128,
    pub drain_ms: u128,
    pub finalize_ms: u128,
    pub drain_grace_exhausted: bool,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct CaptureResult {
    pub capture_id: String,
    pub path: PathBuf,
    pub command: CommandResult,
    pub capture_status: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub event_sha256: String,
    pub event_count: u64,
    pub timings: CaptureTiming,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation: Option<PresentationResult>,
}

#[derive(Debug)]
pub enum CaptureError {
    InvalidRequest(String),
    CaptureUnavailable(io::Error),
    Spawn {
        capture_id: String,
        path: PathBuf,
        source: io::Error,
    },
    Cancelled {
        capture_id: String,
        path: PathBuf,
    },
    Finalize {
        capture_id: String,
        path: PathBuf,
        source: io::Error,
    },
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) => write!(formatter, "{message}"),
            Self::CaptureUnavailable(error) => write!(formatter, "capture unavailable: {error}"),
            Self::Spawn { source, .. } => write!(formatter, "command spawn failed: {source}"),
            Self::Cancelled { .. } => write!(formatter, "capture caller cancelled"),
            Self::Finalize { source, .. } => {
                write!(formatter, "capture finalization failed: {source}")
            }
        }
    }
}

impl std::error::Error for CaptureError {}

#[derive(Serialize)]
struct Event<'a> {
    seq: u64,
    stream: &'a str,
    monotonic_ns: u128,
    offset: u64,
    length: usize,
}

struct SharedSink {
    retained_total: u64,
    sequence: u64,
    event_file: File,
    event_hash: Sha256,
    capture_failed: bool,
}

struct StreamOutcome {
    retained_bytes: u64,
    sha256: String,
    sync_failed: bool,
}

pub fn capture_command(
    options: &CaptureOptions,
    cancellation: Option<&AtomicBool>,
) -> Result<CaptureResult, CaptureError> {
    validate_options(options)?;
    let command_started = Instant::now();
    let capture_id = capture_id();
    let spool = prepare_spool(&options.spool_root, &capture_id)
        .map_err(CaptureError::CaptureUnavailable)?;
    let partial_path = spool.partial.display_path().to_path_buf();

    let stdout_file = spool
        .partial
        .create_file("stdout.raw")
        .map_err(CaptureError::CaptureUnavailable)?;
    let stderr_file = spool
        .partial
        .create_file("stderr.raw")
        .map_err(CaptureError::CaptureUnavailable)?;
    let event_file = spool
        .partial
        .create_file("events.ndjson")
        .map_err(CaptureError::CaptureUnavailable)?;

    let mut command = Command::new(&options.argv[0]);
    command.args(&options.argv[1..]);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.process_group(0);
    if let Some(cwd) = &options.cwd {
        command.current_dir(cwd);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(source) => {
            let _ = write_incomplete_manifest(
                &spool.partial,
                &capture_id,
                "SPAWN_FAILED",
                Some(false),
                Some(false),
                &[],
            );
            return Err(CaptureError::Spawn {
                capture_id,
                path: partial_path,
                source,
            });
        }
    };
    let child_pid = child.id() as i32;
    let shared = Arc::new(Mutex::new(SharedSink {
        retained_total: 0,
        sequence: 0,
        event_file,
        event_hash: Sha256::new(),
        capture_failed: false,
    }));
    let truncated = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().expect("stdout was configured as piped");
    let stderr = child.stderr.take().expect("stderr was configured as piped");
    if let Err(source) =
        set_nonblocking(stdout.as_raw_fd()).and_then(|()| set_nonblocking(stderr.as_raw_fd()))
    {
        kill_process_group(child_pid);
        let _ = child.wait();
        let _ = write_incomplete_manifest(
            &spool.partial,
            &capture_id,
            "CAPTURE_SETUP_FAILED",
            Some(false),
            Some(false),
            &[libc::SIGKILL],
        );
        return Err(CaptureError::Finalize {
            capture_id,
            path: partial_path,
            source,
        });
    }
    let stop_draining = Arc::new(AtomicBool::new(false));
    let (drained_sender, drained_receiver) = mpsc::channel();
    let stdout_thread = spawn_drain(
        stdout,
        stdout_file,
        "stdout",
        options.max_bytes,
        Arc::clone(&shared),
        Arc::clone(&truncated),
        options.required_capture,
        child_pid,
        Arc::clone(&stop_draining),
        drained_sender.clone(),
    );
    let stderr_thread = spawn_drain(
        stderr,
        stderr_file,
        "stderr",
        options.max_bytes,
        Arc::clone(&shared),
        Arc::clone(&truncated),
        options.required_capture,
        child_pid,
        Arc::clone(&stop_draining),
        drained_sender,
    );

    let (status, timed_out, cancelled, signals_sent) =
        match wait_for_child(&mut child, child_pid, options.timeout, cancellation) {
            Ok(result) => result,
            Err(source) => {
                kill_process_group(child_pid);
                let _ = child.wait();
                stop_draining.store(true, Ordering::Release);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                let _ = write_incomplete_manifest(
                    &spool.partial,
                    &capture_id,
                    "PROCESS_WAIT_FAILED",
                    None,
                    None,
                    &[libc::SIGKILL],
                );
                return Err(CaptureError::Finalize {
                    capture_id,
                    path: partial_path,
                    source,
                });
            }
        };
    let command_ms = command_started.elapsed().as_millis();
    let drain_started = Instant::now();
    let drained = wait_for_drainers(&drained_receiver, 2, Duration::from_millis(250));
    let drain_grace_exhausted = drained != 2;
    if drain_grace_exhausted {
        // A descendant may retain an inherited pipe after the direct child
        // exits. Bound that drain window, terminate the original process
        // group, and stop the nonblocking readers instead of hanging.
        kill_process_group(child_pid);
        stop_draining.store(true, Ordering::Release);
    }
    let stdout_outcome = stdout_thread.join().map_err(|_| CaptureError::Finalize {
        capture_id: capture_id.clone(),
        path: partial_path.clone(),
        source: io::Error::other("stdout drain thread panicked"),
    })?;
    let stderr_outcome = stderr_thread.join().map_err(|_| CaptureError::Finalize {
        capture_id: capture_id.clone(),
        path: partial_path.clone(),
        source: io::Error::other("stderr drain thread panicked"),
    })?;
    let drain_ms = drain_started.elapsed().as_millis();
    let finalize_started = Instant::now();
    let mut state = shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if state.event_file.sync_all().is_err()
        || stdout_outcome.sync_failed
        || stderr_outcome.sync_failed
    {
        state.capture_failed = true;
    }
    let event_sha256 = format!("{:x}", state.event_hash.clone().finalize());
    let event_count = state.sequence;
    let capture_failed = state.capture_failed;
    drop(state);
    let finalize_pre_manifest_ms = finalize_started.elapsed().as_millis();

    if cancelled {
        write_incomplete_manifest(
            &spool.partial,
            &capture_id,
            "CALLER_CANCELLED",
            Some(true),
            Some(false),
            &signals_sent,
        )
        .map_err(|source| CaptureError::Finalize {
            capture_id: capture_id.clone(),
            path: partial_path.clone(),
            source,
        })?;
        return Err(CaptureError::Cancelled {
            capture_id,
            path: partial_path,
        });
    }

    let command_result = command_result(status, timed_out, false, signals_sent);
    let capture_status = if capture_failed {
        "CAPTURE_FAILED"
    } else if truncated.load(Ordering::Acquire) {
        "TRUNCATED"
    } else {
        "COMPLETE"
    };
    let manifest = serde_json::json!({
        "schema_version": "vuoro.outctl.capture-native/w3",
        "capture_id": capture_id,
        "capture_status": capture_status,
        "source": {"workspace_id": options.workspace_id},
        "command": command_result,
        "termination": {
            "reason": if timed_out { "TIMEOUT" } else { "COMPLETED" },
            "caller_cancelled": false,
            "timed_out": timed_out,
            "signals_sent": command_result.signals_sent,
        },
        "streams": {
            "stdout": {"bytes": stdout_outcome.retained_bytes, "sha256": stdout_outcome.sha256},
            "stderr": {"bytes": stderr_outcome.retained_bytes, "sha256": stderr_outcome.sha256},
        },
        "event_index": {"events": event_count, "sha256": event_sha256},
        "compatibility": {
            "v1_reader": "readable",
            "v1_writer": "python-reference-only",
            "v1_stream_bytes_preserved": true,
            "v1_manifest_byte_exact": false,
            "unknown_fields_ignored": true,
        },
        "timings": {
            "command_ms": command_ms,
            "drain_ms": drain_ms,
            "finalize_ms": finalize_pre_manifest_ms,
            "drain_grace_exhausted": drain_grace_exhausted,
        },
        "monotonic_finished_ns": monotonic_ns(),
    });
    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|source| CaptureError::Finalize {
            capture_id: capture_id.clone(),
            path: partial_path.clone(),
            source: io::Error::other(source),
        })?;
    spool
        .partial
        .write_new("manifest.json", &[manifest_bytes, b"\n".to_vec()].concat())
        .map_err(|source| CaptureError::Finalize {
            capture_id: capture_id.clone(),
            path: partial_path.clone(),
            source,
        })?;
    spool
        .partial
        .sync()
        .map_err(|source| CaptureError::Finalize {
            capture_id: capture_id.clone(),
            path: partial_path.clone(),
            source,
        })?;
    rename_entry(
        &spool.partial_root,
        &spool.partial_name,
        &spool.captures_root,
        &capture_id,
    )
    .map_err(|source| CaptureError::Finalize {
        capture_id: capture_id.clone(),
        path: partial_path,
        source,
    })?;
    spool
        .captures_root
        .sync()
        .map_err(|source| CaptureError::Finalize {
            capture_id: capture_id.clone(),
            path: spool.final_path.clone(),
            source,
        })?;
    let finalize_ms = finalize_started.elapsed().as_millis();
    Ok(CaptureResult {
        capture_id,
        path: spool.final_path,
        command: command_result,
        capture_status: capture_status.to_owned(),
        stdout_bytes: stdout_outcome.retained_bytes,
        stderr_bytes: stderr_outcome.retained_bytes,
        stdout_sha256: stdout_outcome.sha256,
        stderr_sha256: stderr_outcome.sha256,
        event_sha256,
        event_count,
        timings: CaptureTiming {
            command_ms,
            drain_ms,
            finalize_ms,
            drain_grace_exhausted,
        },
        presentation: None,
    })
}

/// Capture and render a command result using the native W4 presentation
/// boundary.  The existing `capture_command` remains the compatibility API;
/// callers that do not opt into W4 continue to receive the W3 capture only.
pub fn capture_command_with_presentation(
    options: &CaptureOptions,
    presentation_options: &PresentationOptions,
    cancellation: Option<&AtomicBool>,
) -> Result<CaptureResult, CaptureError> {
    presentation_options
        .validate()
        .map_err(|error| CaptureError::InvalidRequest(error.to_string()))?;
    if options.required_capture
        && matches!(
            presentation_options.persistence,
            PersistenceMode::MemoryOnly | PersistenceMode::ProcessLocal
        )
    {
        return Err(CaptureError::InvalidRequest(
            "required capture cannot use memory-only or process-local persistence".to_owned(),
        ));
    }
    if presentation_options.persistence == PersistenceMode::Replicated {
        return Err(CaptureError::InvalidRequest(
            "replicated persistence requires a configured replica backend; command not started"
                .to_owned(),
        ));
    }
    let mut result = capture_command(options, cancellation)?;
    let stdout = result.path.join("stdout.raw");
    let stderr = result.path.join("stderr.raw");
    let mut presentation =
        render_capture_files(&stdout, &stderr, &result.capture_id, presentation_options).map_err(
            |source| CaptureError::Finalize {
                capture_id: result.capture_id.clone(),
                path: result.path.clone(),
                source,
            },
        )?;
    if matches!(
        presentation_options.persistence,
        PersistenceMode::MemoryOnly | PersistenceMode::ProcessLocal
    ) {
        // These modes are intentionally not represented by a durable capture
        // reference.  Remove the host-local material before returning so a
        // process-local result cannot be mistaken for host persistence.
        if let Err(source) = std::fs::remove_dir_all(&result.path) {
            presentation.persistence.status = "cleanup-failed".to_owned();
            presentation.persistence.honest = false;
            return Err(CaptureError::Finalize {
                capture_id: result.capture_id.clone(),
                path: result.path.clone(),
                source,
            });
        }
        result.path = PathBuf::new();
    }
    result.presentation = Some(presentation);
    Ok(result)
}

fn validate_options(options: &CaptureOptions) -> Result<(), CaptureError> {
    if options.argv.is_empty() {
        return Err(CaptureError::InvalidRequest(
            "argv must be a non-empty direct argument vector".to_owned(),
        ));
    }
    if options.argv.len() > 256 {
        return Err(CaptureError::InvalidRequest(
            "argv exceeds the native limit of 256 items".to_owned(),
        ));
    }
    if options.max_bytes > MAX_CAPTURE_BYTES {
        return Err(CaptureError::InvalidRequest(format!(
            "max_bytes exceeds the native limit of {MAX_CAPTURE_BYTES}"
        )));
    }
    if options
        .argv
        .iter()
        .any(|argument| argument.as_encoded_bytes().contains(&0))
    {
        return Err(CaptureError::InvalidRequest(
            "argv contains a NUL byte".to_owned(),
        ));
    }
    Ok(())
}

fn prepare_spool(root: &Path, capture_id: &str) -> io::Result<Spool> {
    let root = PrivateDir::ensure(root)?;
    let partial_root = root.ensure_dir("partial")?;
    let captures_root = root.ensure_dir("captures")?;
    let partial_name = format!("{capture_id}.partial");
    let partial = partial_root.create_dir(&partial_name)?;
    let final_path = captures_root.display_path().join(capture_id);
    Ok(Spool {
        partial_root,
        captures_root,
        partial,
        partial_name,
        final_path,
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_drain<R: Read + Send + 'static>(
    mut reader: R,
    mut file: File,
    stream: &'static str,
    max_bytes: u64,
    shared: Arc<Mutex<SharedSink>>,
    truncated: Arc<AtomicBool>,
    required_capture: bool,
    child_pid: i32,
    stop_draining: Arc<AtomicBool>,
    drained_sender: mpsc::Sender<()>,
) -> thread::JoinHandle<StreamOutcome> {
    thread::spawn(move || {
        let mut digest = Sha256::new();
        let mut retained_bytes = 0_u64;
        let mut writable = true;
        let mut buffer = [0_u8; CHUNK_BYTES];
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if stop_draining.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(_) => {
                    mark_capture_failed(&shared, required_capture, child_pid);
                    break;
                }
            };
            if !writable {
                continue;
            }
            let mut state = shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let remaining = max_bytes.saturating_sub(state.retained_total);
            let retained = read.min(remaining as usize);
            if retained != read {
                truncated.store(true, Ordering::Release);
            }
            if retained == 0 {
                continue;
            }
            let offset = retained_bytes;
            let write_result = file.write_all(&buffer[..retained]).and_then(|()| {
                let event = Event {
                    seq: state.sequence,
                    stream,
                    monotonic_ns: monotonic_ns(),
                    offset,
                    length: retained,
                };
                let mut encoded = serde_json::to_vec(&event).map_err(io::Error::other)?;
                encoded.push(b'\n');
                state.event_file.write_all(&encoded)?;
                state.event_hash.update(&encoded);
                state.sequence += 1;
                Ok(())
            });
            if write_result.is_err() {
                state.capture_failed = true;
                writable = false;
            } else {
                digest.update(&buffer[..retained]);
                retained_bytes += retained as u64;
                state.retained_total += retained as u64;
            }
            let should_kill = state.capture_failed && required_capture;
            drop(state);
            if should_kill {
                kill_process_group(child_pid);
            }
        }
        let _ = drained_sender.send(());
        let sync_failed = file.sync_all().is_err();
        if sync_failed {
            mark_capture_failed(&shared, required_capture, child_pid);
        }
        StreamOutcome {
            retained_bytes,
            sha256: format!("{:x}", digest.finalize()),
            sync_failed,
        }
    })
}

fn wait_for_drainers(receiver: &mpsc::Receiver<()>, expected: usize, grace: Duration) -> usize {
    let deadline = Instant::now() + grace;
    let mut drained = 0;
    while drained < expected {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || receiver.recv_timeout(remaining).is_err() {
            break;
        }
        drained += 1;
    }
    drained
}

fn set_nonblocking(file_descriptor: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(file_descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(file_descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn mark_capture_failed(shared: &Arc<Mutex<SharedSink>>, required_capture: bool, pid: i32) {
    let mut state = shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.capture_failed = true;
    drop(state);
    if required_capture {
        kill_process_group(pid);
    }
}

fn wait_for_child(
    child: &mut Child,
    child_pid: i32,
    timeout: Option<Duration>,
    cancellation: Option<&AtomicBool>,
) -> io::Result<(ExitStatus, bool, bool, Vec<i32>)> {
    let started = Instant::now();
    loop {
        if cancellation.is_some_and(|token| token.load(Ordering::Acquire)) {
            kill_process_group(child_pid);
            let status = child.wait()?;
            return Ok((status, false, true, vec![libc::SIGKILL]));
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            kill_process_group(child_pid);
            let status = child.wait()?;
            return Ok((status, true, false, vec![libc::SIGKILL]));
        }
        match child.try_wait()? {
            Some(status) => return Ok((status, false, false, Vec::new())),
            None => thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn kill_process_group(pid: i32) {
    // The child is created in a process group whose id is its pid. ESRCH is a
    // harmless race with normal exit; all other errors surface through the
    // child's observed status and capture state.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

fn command_result(
    status: ExitStatus,
    timed_out: bool,
    cancelled: bool,
    signals_sent: Vec<i32>,
) -> CommandResult {
    use std::os::unix::process::ExitStatusExt;
    CommandResult {
        started: true,
        exit_code: status.code(),
        signal: status.signal(),
        timed_out,
        cancelled,
        signals_sent,
    }
}

fn monotonic_ns() -> u128 {
    // Rust's Instant has no portable epoch. W3 needs ordering/timing, not a
    // wall-clock claim, so a process-relative monotonic sample is sufficient.
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos()
}

fn write_incomplete_manifest(
    partial: &PrivateDir,
    capture_id: &str,
    reason: &str,
    caller_cancelled: Option<bool>,
    timed_out: Option<bool>,
    signals_sent: &[i32],
) -> io::Result<()> {
    if partial.try_open_file("manifest.json")?.is_none() {
        let manifest = serde_json::json!({
            "schema_version": "vuoro.outctl.capture-native/w3",
            "capture_id": capture_id,
            "capture_status": "INCOMPLETE",
            "incomplete": true,
            "command": {"final_status": "UNKNOWN", "exit_code": null, "signal": null},
            "termination": {
                "reason": reason,
                "caller_cancelled": caller_cancelled,
                "timed_out": timed_out,
                "signals_sent": signals_sent,
            },
            "compatibility": {
                "v1_reader": "readable",
                "v1_writer": "python-reference-only",
                "v1_stream_bytes_preserved": true,
                "v1_manifest_byte_exact": false,
                "unknown_fields_ignored": true,
            },
        });
        let mut bytes = serde_json::to_vec(&manifest).map_err(io::Error::other)?;
        bytes.push(b'\n');
        partial.write_new("manifest.json", &bytes)?;
    }
    if partial.try_open_file("recovery.json")?.is_none() {
        let record = serde_json::json!({
            "capture_status": "INCOMPLETE",
            "incomplete": true,
            "reason": reason,
        });
        let mut bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        bytes.push(b'\n');
        partial.write_new("recovery.json", &bytes)?;
    }
    partial.sync()
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct RecoveryRecord {
    pub capture_id: String,
    pub path: PathBuf,
    pub status: String,
}

pub fn recover_partials(root: &Path) -> io::Result<Vec<RecoveryRecord>> {
    let root = match PrivateDir::open(root) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let partial_root = match root.try_open_dir("partial")? {
        Some(partial_root) => partial_root,
        None => return Ok(Vec::new()),
    };
    let mut names = partial_root.names()?;
    names.sort();
    let mut records = Vec::new();
    for name in names {
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(capture_id) = name.strip_suffix(".partial") else {
            continue;
        };
        let partial = match partial_root.try_open_dir(name) {
            Ok(Some(partial)) => partial,
            Ok(None) | Err(_) => continue,
        };
        write_incomplete_manifest(
            &partial,
            capture_id,
            "WRAPPER_INTERRUPTED_OR_CRASHED",
            None,
            None,
            &[],
        )?;
        records.push(RecoveryRecord {
            capture_id: capture_id.to_owned(),
            path: partial.display_path().to_path_buf(),
            status: "INCOMPLETE".to_owned(),
        });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::{
        capture_command, capture_command_with_presentation, CaptureError, CaptureOptions,
        MAX_CAPTURE_BYTES,
    };
    use crate::presentation::{PersistenceMode, PresentationOptions};
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("outctl-{label}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn direct_argv_preserves_literal_shell_text() {
        let root = temporary_root("literal");
        let result = capture_command(
            &CaptureOptions {
                argv: vec![
                    OsString::from("python3"),
                    OsString::from("-c"),
                    OsString::from("import sys; print(sys.argv[1])"),
                    OsString::from("$(not-a-shell)"),
                ],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
            },
            None,
        )
        .unwrap();
        assert_eq!(
            fs::read(result.path.join("stdout.raw")).unwrap(),
            b"$(not-a-shell)\n"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_quota_drains_large_mixed_streams() {
        let root = temporary_root("quota");
        let result = capture_command(
            &CaptureOptions {
                argv: vec![
                    OsString::from("python3"),
                    OsString::from("-c"),
                    OsString::from(
                        "import os; [(os.write(1,b'o'*65536),os.write(2,b'e'*65536)) for _ in range(8)]",
                    ),
                ],
                spool_root: root.clone(),
                max_bytes: 4097,
                timeout: Some(Duration::from_secs(5)),
                cwd: None,
                workspace_id: None,
                required_capture: false,
            },
            None,
        )
        .unwrap();
        assert_eq!(result.stdout_bytes + result.stderr_bytes, 4097);
        assert_eq!(result.capture_status, "TRUNCATED");
        assert_eq!(result.command.exit_code, Some(0));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn advertised_quota_boundary_is_enforced_before_spool_creation() {
        let accepted_root = temporary_root("quota-boundary-accepted");
        let result = capture_command(
            &CaptureOptions {
                argv: vec![OsString::from("true")],
                spool_root: accepted_root.clone(),
                max_bytes: MAX_CAPTURE_BYTES,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
            },
            None,
        )
        .unwrap();
        assert_eq!(result.capture_status, "COMPLETE");
        fs::remove_dir_all(accepted_root).unwrap();

        let rejected_root = temporary_root("quota-boundary-rejected");
        let error = capture_command(
            &CaptureOptions {
                argv: vec![OsString::from("true")],
                spool_root: rejected_root.clone(),
                max_bytes: MAX_CAPTURE_BYTES + 1,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::InvalidRequest(_)));
        assert!(!rejected_root.exists());
    }

    #[test]
    fn ephemeral_persistence_is_explicit_and_leaves_no_capture_reference() {
        let root = temporary_root("ephemeral");
        let result = capture_command_with_presentation(
            &CaptureOptions {
                argv: vec![OsString::from("true")],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
            },
            &PresentationOptions {
                persistence: PersistenceMode::ProcessLocal,
                ..PresentationOptions::default()
            },
            None,
        )
        .unwrap();
        assert!(result.path.as_os_str().is_empty());
        let presentation = result.presentation.unwrap();
        assert_eq!(presentation.persistence.durability, "none");
        assert_eq!(presentation.persistence.reference, None);
        assert!(presentation.persistence.honest);
        assert!(!root.join("captures").join(&result.capture_id).exists());
        fs::remove_dir_all(root).unwrap();

        let required_root = temporary_root("required-ephemeral");
        let error = capture_command_with_presentation(
            &CaptureOptions {
                argv: vec![OsString::from("true")],
                spool_root: required_root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: true,
            },
            &PresentationOptions {
                persistence: PersistenceMode::MemoryOnly,
                ..PresentationOptions::default()
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::InvalidRequest(_)));
        assert!(!required_root.exists());

        let rejected_root = temporary_root("replica-unavailable");
        let error = capture_command_with_presentation(
            &CaptureOptions {
                argv: vec![OsString::from("true")],
                spool_root: rejected_root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
            },
            &PresentationOptions {
                persistence: PersistenceMode::Replicated,
                ..PresentationOptions::default()
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::InvalidRequest(_)));
        assert!(!rejected_root.exists());
    }

    #[test]
    fn caller_cancellation_kills_descendants_and_leaves_unknown_partial() {
        let root = temporary_root("cancel");
        fs::create_dir_all(&root).unwrap();
        let marker = root.join("leaked-child");
        let child_code = format!(
            "import pathlib,time; time.sleep(.5); pathlib.Path({:?}).write_text('leaked')",
            marker
        );
        let parent_code = format!(
            "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child_code:?}]); time.sleep(60)"
        );
        let token = Arc::new(AtomicBool::new(false));
        let trigger = Arc::clone(&token);
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            trigger.store(true, Ordering::Release);
        });
        let error = capture_command(
            &CaptureOptions {
                argv: vec![
                    OsString::from("python3"),
                    OsString::from("-c"),
                    OsString::from(parent_code),
                ],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: Some(Duration::from_secs(5)),
                cwd: None,
                workspace_id: None,
                required_capture: false,
            },
            Some(&token),
        )
        .unwrap_err();
        canceller.join().unwrap();
        let partial = match error {
            CaptureError::Cancelled { path, .. } => path,
            other => panic!("unexpected cancellation result: {other:?}"),
        };
        thread::sleep(Duration::from_millis(600));
        assert!(!marker.exists());
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(partial.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["capture_status"], "INCOMPLETE");
        assert_eq!(manifest["command"]["final_status"], "UNKNOWN");
        assert_eq!(manifest["termination"]["caller_cancelled"], true);
        fs::remove_dir_all(root).unwrap();
    }
}

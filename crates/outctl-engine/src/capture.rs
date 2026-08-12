use crate::index::{rebuild_index_in, record_from_bundle, IndexStore, MAX_REBUILD_CAPTURES};
use crate::manifest::{
    read_manifest_bundle, write_v2_sidecar, CompatibilityBinding, DurabilityEvidence,
    EngineBinding, EventIndexBinding, IndexBinding, PolicyBinding, StreamBinding, StreamBindings,
    V2ManifestDelta,
};
use crate::presentation::{
    render_capture_files_from_handles_with_status, PersistenceMode, PresentationOptions,
    PresentationResult,
};
use crate::storage::{capture_id, rename_entry_noreplace, PrivateDir, CHUNK_BYTES};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
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
    pub shell_command: Option<OsString>,
    pub stdin: CommandStdin,
    pub spool_root: PathBuf,
    pub max_bytes: u64,
    pub timeout: Option<Duration>,
    pub cwd: Option<PathBuf>,
    pub workspace_id: Option<String>,
    pub required_capture: bool,
    pub environment: CommandEnvironment,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum CommandEnvironment {
    #[default]
    Inherited,
    Empty,
    Allowlist(Vec<OsString>),
}

#[derive(Clone, Default, Eq, PartialEq)]
pub enum CommandStdin {
    #[default]
    Null,
    Inherited,
    Bytes(Arc<ProtectedStdinValue>),
}

#[derive(Eq, PartialEq)]
pub struct ProtectedStdinValue(Vec<u8>);

impl ProtectedStdinValue {
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for ProtectedStdinValue {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl std::fmt::Debug for CommandStdin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => formatter.write_str("Null"),
            Self::Inherited => formatter.write_str("Inherited"),
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("length", &bytes.len())
                .finish(),
        }
    }
}

pub const MAX_CAPTURE_BYTES: u64 = 268_435_456;
pub const MAX_STDIN_BYTES: usize = 16 * 1024 * 1024;

struct Spool {
    root: PrivateDir,
    partial_root: PrivateDir,
    captures_root: PrivateDir,
    partial: PrivateDir,
    partial_name: String,
    final_path: PathBuf,
    _lease: File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2CaptureMetadata {
    pub request_digest: String,
    pub snapshot_id: String,
    pub policy_ref: String,
    pub policy_digest: String,
}

/// Capture files retained through final presentation.
///
/// Ephemeral captures use unnamed files in the pinned spool root. They never
/// link a capture directory, which closes the W4 empty-tombstone leak without
/// relying on pathname-racy `rmdir` cleanup.
struct PreparedCapture {
    spool: Option<Spool>,
    stdout_writer: File,
    stderr_writer: File,
    event_writer: File,
    stdout_reader: File,
    stderr_reader: File,
    display_path: PathBuf,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_failure_key: Option<String>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub event_sha256: String,
    pub event_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v2_manifest_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_status: Option<String>,
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
    Presentation(Box<PresentationFailure>),
}

#[derive(Debug)]
pub struct PresentationFailure {
    pub capture_id: String,
    pub path: PathBuf,
    pub command: CommandResult,
    pub capture_status: String,
    pub source: io::Error,
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
            Self::Presentation(failure) => {
                write!(
                    formatter,
                    "presentation failed after capture: {}",
                    failure.source
                )
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
    capture_failure_key: Option<String>,
}

struct StreamOutcome {
    retained_bytes: u64,
    sha256: String,
    sync_failed: bool,
}

#[derive(Clone, Debug, Default)]
struct CaptureFaults {
    write_failure: Option<(u64, i32)>,
    manifest_write: bool,
    sidecar_write: bool,
    partial_sync: bool,
    rename: bool,
    parent_sync: bool,
    index_write: bool,
}

fn injected_failure(point: &str) -> io::Error {
    io::Error::other(format!("injected storage failure at {point}"))
}

pub fn capture_command(
    options: &CaptureOptions,
    cancellation: Option<&AtomicBool>,
) -> Result<CaptureResult, CaptureError> {
    let result =
        capture_command_pinned(options, cancellation, None, None, &CaptureFaults::default())?;
    Ok(result)
}

fn capture_command_pinned(
    options: &CaptureOptions,
    cancellation: Option<&AtomicBool>,
    presentation_options: Option<&PresentationOptions>,
    v2_metadata: Option<&V2CaptureMetadata>,
    faults: &CaptureFaults,
) -> Result<CaptureResult, CaptureError> {
    validate_options(options)?;
    let command_started = Instant::now();
    let capture_id = capture_id();
    let ephemeral = presentation_options.is_some_and(|value| value.persistence.is_ephemeral());
    if ephemeral && v2_metadata.is_some() {
        return Err(CaptureError::InvalidRequest(
            "v2 capture metadata requires host-persistent evidence".to_owned(),
        ));
    }
    let prepared = prepare_capture(&options.spool_root, &capture_id, ephemeral)
        .map_err(CaptureError::CaptureUnavailable)?;
    let partial_path = prepared.display_path.clone();
    let PreparedCapture {
        spool,
        stdout_writer: stdout_file,
        stderr_writer: stderr_file,
        event_writer: event_file,
        mut stdout_reader,
        mut stderr_reader,
        display_path: _,
    } = prepared;

    let mut command = Command::new(&options.argv[0]);
    command.args(&options.argv[1..]);
    if let Some(shell_command) = &options.shell_command {
        command.arg(shell_command);
    }
    match &options.environment {
        CommandEnvironment::Inherited => {}
        CommandEnvironment::Empty => {
            command.env_clear();
        }
        CommandEnvironment::Allowlist(names) => {
            let retained = names
                .iter()
                .filter_map(|name| std::env::var_os(name).map(|value| (name, value)))
                .collect::<Vec<_>>();
            command.env_clear();
            command.envs(retained);
        }
    }
    match &options.stdin {
        CommandStdin::Null => command.stdin(Stdio::null()),
        CommandStdin::Inherited => command.stdin(Stdio::inherit()),
        CommandStdin::Bytes(_) => command.stdin(Stdio::piped()),
    };
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.process_group(0);
    if let Some(cwd) = &options.cwd {
        command.current_dir(cwd);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(source) => {
            if let Some(spool) = &spool {
                let _ = write_incomplete_manifest(
                    &spool.partial,
                    &capture_id,
                    "SPAWN_FAILED",
                    Some(false),
                    Some(false),
                    &[],
                    false,
                );
            }
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
        capture_failure_key: None,
    }));
    let truncated = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().expect("stdout was configured as piped");
    let stderr = child.stderr.take().expect("stderr was configured as piped");
    let stdin_pipe = match &options.stdin {
        CommandStdin::Bytes(_) => Some(child.stdin.take().expect("stdin was configured as piped")),
        CommandStdin::Null | CommandStdin::Inherited => None,
    };
    let nonblocking_result = set_nonblocking(stdout.as_raw_fd())
        .and_then(|()| set_nonblocking(stderr.as_raw_fd()))
        .and_then(|()| {
            stdin_pipe
                .as_ref()
                .map_or(Ok(()), |stdin| set_nonblocking(stdin.as_raw_fd()))
        });
    if let Err(source) = nonblocking_result {
        kill_process_group(child_pid);
        let _ = child.wait();
        if let Some(spool) = &spool {
            let _ = write_incomplete_manifest(
                &spool.partial,
                &capture_id,
                "CAPTURE_SETUP_FAILED",
                Some(false),
                Some(false),
                &[libc::SIGKILL],
                false,
            );
        }
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
        faults.write_failure,
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
        faults.write_failure,
    );
    let stop_writing = Arc::new(AtomicBool::new(false));
    let stdin_thread = match (&options.stdin, stdin_pipe) {
        (CommandStdin::Bytes(bytes), Some(stdin)) => {
            let bytes = Arc::clone(bytes);
            let stop_writing = Arc::clone(&stop_writing);
            Some(thread::spawn(move || {
                let mut stdin = stdin;
                let mut offset = 0;
                while offset < bytes.len() {
                    if stop_writing.load(Ordering::Acquire) {
                        break;
                    }
                    match stdin.write(&bytes.as_bytes()[offset..]) {
                        Ok(0) => break,
                        Ok(written) => offset += written,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => break,
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            }))
        }
        (CommandStdin::Null | CommandStdin::Inherited, None) => None,
        _ => unreachable!("stdin pipe matches the selected mode"),
    };

    let (status, timed_out, cancelled, signals_sent) =
        match wait_for_child(&mut child, child_pid, options.timeout, cancellation) {
            Ok(result) => result,
            Err(source) => {
                kill_process_group(child_pid);
                let _ = child.wait();
                stop_writing.store(true, Ordering::Release);
                stop_draining.store(true, Ordering::Release);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                if let Some(stdin_thread) = stdin_thread {
                    let _ = stdin_thread.join();
                }
                if let Some(spool) = &spool {
                    let _ = write_incomplete_manifest(
                        &spool.partial,
                        &capture_id,
                        "PROCESS_WAIT_FAILED",
                        None,
                        None,
                        &[libc::SIGKILL],
                        false,
                    );
                }
                return Err(CaptureError::Finalize {
                    capture_id,
                    path: partial_path,
                    source,
                });
            }
        };
    // A descendant can inherit the pipe after the direct child exits. Stop a
    // nonblocking writer before joining so that such a descendant cannot hold
    // the capture call indefinitely; the drain grace below then kills the
    // original process group if any output descriptors are also retained.
    stop_writing.store(true, Ordering::Release);
    if let Some(stdin_thread) = stdin_thread {
        stdin_thread
            .join()
            .map_err(|_| CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: partial_path.clone(),
                source: io::Error::other("stdin writer thread panicked"),
            })?
            .map_err(|source| CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: partial_path.clone(),
                source,
            })?;
    }
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
        state
            .capture_failure_key
            .get_or_insert_with(|| "STORAGE_SYNC_FAILED".to_owned());
    }
    let event_sha256 = format!("{:x}", state.event_hash.clone().finalize());
    let event_bytes = state
        .event_file
        .metadata()
        .map(|value| value.len())
        .unwrap_or(0);
    let event_count = state.sequence;
    let capture_failed = state.capture_failed;
    let capture_failure_key = state.capture_failure_key.clone();
    drop(state);
    let finalize_pre_manifest_ms = finalize_started.elapsed().as_millis();

    if cancelled {
        if let Some(spool) = &spool {
            write_incomplete_manifest(
                &spool.partial,
                &capture_id,
                "CALLER_CANCELLED",
                Some(true),
                Some(false),
                &signals_sent,
                false,
            )
            .map_err(|source| CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: partial_path.clone(),
                source,
            })?;
        }
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
    let presentation = if let Some(presentation_options) = presentation_options {
        stdout_reader
            .seek(SeekFrom::Start(0))
            .and_then(|_| stderr_reader.seek(SeekFrom::Start(0)))
            .map_err(|source| {
                CaptureError::Presentation(Box::new(PresentationFailure {
                    capture_id: capture_id.clone(),
                    path: partial_path.clone(),
                    command: command_result.clone(),
                    capture_status: capture_status.to_owned(),
                    source,
                }))
            })?;
        let command_success = command_result.exit_code == Some(0)
            && command_result.signal.is_none()
            && !command_result.timed_out
            && !command_result.cancelled;
        Some(
            render_capture_files_from_handles_with_status(
                &stdout_reader,
                &stderr_reader,
                &capture_id,
                presentation_options,
                command_success,
            )
            .map_err(|source| {
                CaptureError::Presentation(Box::new(PresentationFailure {
                    capture_id: capture_id.clone(),
                    path: partial_path.clone(),
                    command: command_result.clone(),
                    capture_status: capture_status.to_owned(),
                    source,
                }))
            })?,
        )
    } else {
        None
    };
    let manifest = serde_json::json!({
        "schema_version": "vuoro.outctl.capture-native/w3",
        "capture_id": capture_id,
        "capture_status": capture_status,
        "capture_failure_key": capture_failure_key,
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
    let mut manifest_digest = None;
    let mut v2_manifest_digest = None;
    let mut capture_ref = None;
    let mut pending_index = None;
    let final_path = if let Some(spool) = &spool {
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|source| CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: partial_path.clone(),
                source: io::Error::other(source),
            })?;
        if faults.manifest_write {
            return Err(CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: partial_path.clone(),
                source: injected_failure("manifest-write"),
            });
        }
        spool
            .partial
            .write_new("manifest.json", &[manifest_bytes, b"\n".to_vec()].concat())
            .map_err(|source| CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: partial_path.clone(),
                source,
            })?;
        if let Some(metadata) = v2_metadata {
            let base = crate::manifest::read_base_manifest(&spool.partial, Some(&capture_id))
                .map_err(|source| CaptureError::Finalize {
                    capture_id: capture_id.clone(),
                    path: partial_path.clone(),
                    source: io::Error::other(source),
                })?;
            let normalized_status = match capture_status {
                "COMPLETE" => "complete",
                "TRUNCATED" => "truncated",
                "CAPTURE_FAILED" if options.required_capture => "failed",
                "CAPTURE_FAILED" => "degraded",
                other => other,
            };
            let artifact_complete = capture_status == "COMPLETE";
            let presentation_kind = presentation
                .as_ref()
                .map(|value| value.kind.as_str())
                .unwrap_or("metadata-only");
            let delta = V2ManifestDelta {
                schema_version: "vuoro.outctl.capture-manifest-delta/v2".to_owned(),
                base_schema_version: base.version.as_str().to_owned(),
                capture_id: capture_id.clone(),
                base_manifest_digest: base.exact_digest.clone(),
                engine: EngineBinding {
                    id: crate::ENGINE_ID.to_owned(),
                    version: crate::ENGINE_VERSION.to_owned(),
                },
                request_digest: metadata.request_digest.clone(),
                policy: PolicyBinding {
                    snapshot_id: metadata.snapshot_id.clone(),
                    reference: metadata.policy_ref.clone(),
                    digest: metadata.policy_digest.clone(),
                },
                capture_status: normalized_status.to_owned(),
                complete: artifact_complete,
                streams: StreamBindings {
                    stdout: StreamBinding {
                        bytes: stdout_outcome.retained_bytes,
                        sha256: format!("sha256:{}", stdout_outcome.sha256),
                        complete: artifact_complete,
                        last_captured_offset: stdout_outcome.retained_bytes,
                    },
                    stderr: StreamBinding {
                        bytes: stderr_outcome.retained_bytes,
                        sha256: format!("sha256:{}", stderr_outcome.sha256),
                        complete: artifact_complete,
                        last_captured_offset: stderr_outcome.retained_bytes,
                    },
                },
                event_index: EventIndexBinding {
                    bytes: event_bytes,
                    events: event_count,
                    sha256: format!("sha256:{event_sha256}"),
                    complete: artifact_complete,
                },
                recovery: None,
                commitment: "host-persistent".to_owned(),
                durability: "host".to_owned(),
                durability_evidence: DurabilityEvidence {
                    artifacts_synced: true,
                    partial_directory_synced: true,
                    atomic_rename: true,
                    capture_parent_synced: true,
                    replica_verified: false,
                },
                retention_record_schema: "vuoro.outctl.capture-retention-tombstone/v2".to_owned(),
                index: IndexBinding {
                    format: "v2".to_owned(),
                    authoritative: false,
                    rebuildable: true,
                },
                presentation: presentation_kind.to_owned(),
                compatibility: CompatibilityBinding::default(),
            };
            if faults.sidecar_write {
                return Err(CaptureError::Finalize {
                    capture_id: capture_id.clone(),
                    path: partial_path.clone(),
                    source: injected_failure("v2-sidecar-write"),
                });
            }
            let sidecar_digest = write_v2_sidecar(&spool.partial, &delta).map_err(|source| {
                CaptureError::Finalize {
                    capture_id: capture_id.clone(),
                    path: partial_path.clone(),
                    source: io::Error::other(source),
                }
            })?;
            let bundle =
                read_manifest_bundle(&spool.partial, Some(&capture_id)).map_err(|source| {
                    CaptureError::Finalize {
                        capture_id: capture_id.clone(),
                        path: partial_path.clone(),
                        source: io::Error::other(source),
                    }
                })?;
            pending_index = record_from_bundle(&bundle).ok();
            manifest_digest = Some(sidecar_digest.clone());
            v2_manifest_digest = Some(sidecar_digest.clone());
            capture_ref = Some(format!(
                "outctl://capture/{capture_id}/manifest/sha256/{}",
                sidecar_digest.trim_start_matches("sha256:")
            ));
        }
        if faults.partial_sync {
            return Err(CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: partial_path.clone(),
                source: injected_failure("partial-directory-sync"),
            });
        }
        spool
            .partial
            .sync()
            .map_err(|source| CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: partial_path.clone(),
                source,
            })?;
        if faults.rename {
            return Err(CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: partial_path.clone(),
                source: injected_failure("atomic-rename"),
            });
        }
        rename_entry_noreplace(
            &spool.partial_root,
            &spool.partial_name,
            &spool.captures_root,
            &capture_id,
        )
        .map_err(|source| CaptureError::Finalize {
            capture_id: capture_id.clone(),
            path: partial_path.clone(),
            source,
        })?;
        if faults.parent_sync {
            return Err(CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: spool.final_path.clone(),
                source: injected_failure("capture-parent-sync"),
            });
        }
        spool
            .captures_root
            .sync()
            .map_err(|source| CaptureError::Finalize {
                capture_id: capture_id.clone(),
                path: spool.final_path.clone(),
                source,
            })?;
        spool.final_path.clone()
    } else {
        PathBuf::new()
    };
    let finalize_ms = finalize_started.elapsed().as_millis();
    let index_status = if let (Some(spool), Some(record)) = (&spool, pending_index.as_ref()) {
        let index_result = if faults.index_write {
            Err(crate::index::IndexError::Io(injected_failure(
                "index-write",
            )))
        } else {
            IndexStore::ensure_in(&spool.root).and_then(|store| store.write(record))
        };
        match index_result {
            Ok(_) => Some("current".to_owned()),
            Err(_) => Some("rebuild-required".to_owned()),
        }
    } else {
        None
    };
    let result = CaptureResult {
        capture_id,
        path: final_path,
        command: command_result,
        capture_status: capture_status.to_owned(),
        capture_failure_key,
        stdout_bytes: stdout_outcome.retained_bytes,
        stderr_bytes: stderr_outcome.retained_bytes,
        stdout_sha256: stdout_outcome.sha256,
        stderr_sha256: stderr_outcome.sha256,
        event_sha256,
        event_count,
        manifest_digest,
        v2_manifest_digest,
        capture_ref,
        index_status,
        timings: CaptureTiming {
            command_ms,
            drain_ms,
            finalize_ms,
            drain_grace_exhausted,
        },
        presentation,
    };
    Ok(result)
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
    capture_command_pinned(
        options,
        cancellation,
        Some(presentation_options),
        None,
        &CaptureFaults::default(),
    )
}

pub fn capture_command_with_v2_presentation(
    options: &CaptureOptions,
    presentation_options: &PresentationOptions,
    metadata: &V2CaptureMetadata,
    cancellation: Option<&AtomicBool>,
) -> Result<CaptureResult, CaptureError> {
    presentation_options
        .validate()
        .map_err(|error| CaptureError::InvalidRequest(error.to_string()))?;
    if presentation_options.persistence != PersistenceMode::HostPersistent {
        return Err(CaptureError::InvalidRequest(
            "v2 storage currently requires host-persistent commitment".to_owned(),
        ));
    }
    for (label, digest) in [
        ("request digest", metadata.request_digest.as_str()),
        ("policy digest", metadata.policy_digest.as_str()),
    ] {
        crate::manifest::validate_prefixed_digest(digest, label)
            .map_err(|error| CaptureError::InvalidRequest(error.to_string()))?;
    }
    if metadata.snapshot_id.is_empty()
        || metadata.snapshot_id.len() > 1024
        || metadata.policy_ref.is_empty()
        || metadata.policy_ref.len() > 1024
    {
        return Err(CaptureError::InvalidRequest(
            "v2 policy identity is empty or oversized".to_owned(),
        ));
    }
    capture_command_pinned(
        options,
        cancellation,
        Some(presentation_options),
        Some(metadata),
        &CaptureFaults::default(),
    )
}

fn validate_options(options: &CaptureOptions) -> Result<(), CaptureError> {
    if options.argv.is_empty() {
        return Err(CaptureError::InvalidRequest(
            "argv must be a non-empty execution argument vector".to_owned(),
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
    if options.shell_command.as_ref().is_some_and(|command| {
        command.is_empty() || command.len() > 65_536 || command.as_encoded_bytes().contains(&0)
    }) {
        return Err(CaptureError::InvalidRequest(
            "explicit shell command is empty, oversized, or contains NUL".to_owned(),
        ));
    }
    if matches!(&options.stdin, CommandStdin::Bytes(bytes) if bytes.len() > MAX_STDIN_BYTES) {
        return Err(CaptureError::InvalidRequest(
            "stdin exceeds the per-value byte limit".to_owned(),
        ));
    }
    if let CommandEnvironment::Allowlist(names) = &options.environment {
        if names.is_empty()
            || names.len() > 256
            || names.iter().collect::<BTreeSet<_>>().len() != names.len()
            || names.iter().any(|name| {
                name.is_empty()
                    || name.len() > 256
                    || name
                        .as_encoded_bytes()
                        .iter()
                        .any(|byte| *byte == 0 || *byte == b'=')
            })
        {
            return Err(CaptureError::InvalidRequest(
                "environment allowlist is empty, duplicated, oversized, or invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn prepare_spool(root: &Path, capture_id: &str) -> io::Result<Spool> {
    let root = PrivateDir::ensure(root)?;
    let partial_root = root.ensure_dir("partial")?;
    let captures_root = root.ensure_dir("captures")?;
    let partial_name = format!("{capture_id}.partial");
    let partial = partial_root.create_dir(&partial_name)?;
    let lease = partial.create_file("lease.lock")?;
    if !PrivateDir::try_lock_exclusive(&lease)? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "new capture lease is unexpectedly held",
        ));
    }
    let final_path = captures_root.display_path().join(capture_id);
    Ok(Spool {
        root,
        partial_root,
        captures_root,
        partial,
        partial_name,
        final_path,
        _lease: lease,
    })
}

fn prepare_capture(root: &Path, capture_id: &str, ephemeral: bool) -> io::Result<PreparedCapture> {
    if ephemeral {
        let root = PrivateDir::ensure(root)?;
        let stdout_writer = root.create_unnamed_file()?;
        let stderr_writer = root.create_unnamed_file()?;
        let event_writer = root.create_unnamed_file()?;
        return Ok(PreparedCapture {
            stdout_reader: stdout_writer.try_clone()?,
            stderr_reader: stderr_writer.try_clone()?,
            stdout_writer,
            stderr_writer,
            event_writer,
            spool: None,
            display_path: PathBuf::new(),
        });
    }
    let spool = prepare_spool(root, capture_id)?;
    let stdout_writer = spool.partial.create_read_write_file("stdout.raw")?;
    let stderr_writer = spool.partial.create_read_write_file("stderr.raw")?;
    let event_writer = spool.partial.create_file("events.ndjson")?;
    Ok(PreparedCapture {
        stdout_reader: stdout_writer.try_clone()?,
        stderr_reader: stderr_writer.try_clone()?,
        stdout_writer,
        stderr_writer,
        event_writer,
        display_path: spool.partial.display_path().to_path_buf(),
        spool: Some(spool),
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
    write_failure: Option<(u64, i32)>,
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
            if let Some((_limit, errno)) =
                write_failure.filter(|(limit, _)| state.retained_total >= *limit)
            {
                state.capture_failed = true;
                state.capture_failure_key = Some(storage_failure_key(errno).to_owned());
                writable = false;
                let should_kill = required_capture;
                drop(state);
                if should_kill {
                    kill_process_group(child_pid);
                }
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
            if let Err(error) = write_result {
                state.capture_failed = true;
                state.capture_failure_key = Some(
                    error
                        .raw_os_error()
                        .map(storage_failure_key)
                        .unwrap_or("STORAGE_WRITE_FAILED")
                        .to_owned(),
                );
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
    state
        .capture_failure_key
        .get_or_insert_with(|| "STORAGE_READ_FAILED".to_owned());
    drop(state);
    if required_capture {
        kill_process_group(pid);
    }
}

fn storage_failure_key(errno: i32) -> &'static str {
    match errno {
        libc::ENOSPC => "STORAGE_NO_SPACE",
        libc::EDQUOT => "STORAGE_QUOTA_EXCEEDED",
        libc::EIO => "STORAGE_IO_FAILED",
        _ => "STORAGE_WRITE_FAILED",
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
    recovered: bool,
) -> io::Result<()> {
    if partial.try_open_file("manifest.json")?.is_none() {
        let mut streams = serde_json::Map::new();
        if let Some(binding) = observed_artifact(partial, "stdout.raw")? {
            streams.insert("stdout".to_owned(), binding);
        }
        if let Some(binding) = observed_artifact(partial, "stderr.raw")? {
            streams.insert("stderr".to_owned(), binding);
        }
        let events = observed_artifact(partial, "events.ndjson")?;
        let manifest = serde_json::json!({
            "schema_version": "vuoro.outctl.capture-native/w3",
            "capture_id": capture_id,
            "capture_status": if recovered { "RECOVERED_INCOMPLETE" } else { "INCOMPLETE" },
            "incomplete": true,
            "command": {"final_status": "UNKNOWN", "exit_code": null, "signal": null},
            "streams": streams,
            "event_index": events,
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

fn observed_artifact(partial: &PrivateDir, name: &str) -> io::Result<Option<serde_json::Value>> {
    let Some(file) = partial.try_open_file(name)? else {
        return Ok(None);
    };
    Ok(Some(serde_json::json!({
        "bytes": crate::storage::file_len(&file)?,
        "sha256": crate::storage::sha256_file(&file)?,
    })))
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct RecoveryRecord {
    pub capture_id: String,
    pub path: PathBuf,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub fn recover_partials(root: &Path) -> io::Result<Vec<RecoveryRecord>> {
    let root = match PrivateDir::open(root) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let partial_root = match root.try_open_dir("partial")? {
        Some(partial_root) => partial_root,
        None => {
            let _ = rebuild_index_in(&root, MAX_REBUILD_CAPTURES).map_err(io::Error::other)?;
            return Ok(Vec::new());
        }
    };
    let captures_root = root.ensure_dir("captures")?;
    let mut names = partial_root.names_bounded(MAX_REBUILD_CAPTURES)?;
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
        if let Some(lease) = partial.try_open_file("lease.lock")? {
            if !PrivateDir::try_lock_exclusive(&lease)? {
                records.push(RecoveryRecord {
                    capture_id: capture_id.to_owned(),
                    path: partial.display_path().to_path_buf(),
                    status: "ACTIVE_SKIPPED".to_owned(),
                    detail: Some("capture lease is active".to_owned()),
                });
                continue;
            }
        }
        if partial.try_open_file("manifest.json")?.is_some() {
            match read_manifest_bundle(&partial, Some(capture_id)) {
                Ok(bundle)
                    if matches!(
                        bundle.base.capture_status.as_str(),
                        "COMPLETE" | "TRUNCATED" | "CAPTURE_FAILED"
                    ) =>
                {
                    if !manifest_artifacts_match(&partial, &bundle.base)? {
                        records.push(RecoveryRecord {
                            capture_id: capture_id.to_owned(),
                            path: partial.display_path().to_path_buf(),
                            status: "TAMPERED_RETAINED".to_owned(),
                            detail: Some(
                                "finalized manifest does not match retained artifacts".to_owned(),
                            ),
                        });
                        continue;
                    }
                    match rename_entry_noreplace(&partial_root, name, &captures_root, capture_id) {
                        Ok(()) => {
                            captures_root.sync()?;
                            let index_status = record_from_bundle(&bundle)
                                .and_then(|record| {
                                    IndexStore::ensure_in(&root)?.write(&record).map(|_| ())
                                })
                                .map(|_| "current")
                                .unwrap_or("rebuild-required");
                            records.push(RecoveryRecord {
                                capture_id: capture_id.to_owned(),
                                path: captures_root.display_path().join(capture_id),
                                status: "RECOVERED_FINALIZED".to_owned(),
                                detail: Some(format!("index:{index_status}")),
                            });
                            continue;
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            records.push(RecoveryRecord {
                                capture_id: capture_id.to_owned(),
                                path: partial.display_path().to_path_buf(),
                                status: "CONFLICT_RETAINED".to_owned(),
                                detail: Some("final capture name already exists".to_owned()),
                            });
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    records.push(RecoveryRecord {
                        capture_id: capture_id.to_owned(),
                        path: partial.display_path().to_path_buf(),
                        status: "UNSAFE_RETAINED".to_owned(),
                        detail: Some(error.to_string()),
                    });
                    continue;
                }
            }
        }
        if let Err(error) = write_incomplete_manifest(
            &partial,
            capture_id,
            "WRAPPER_INTERRUPTED_OR_CRASHED",
            None,
            None,
            &[],
            true,
        ) {
            records.push(RecoveryRecord {
                capture_id: capture_id.to_owned(),
                path: partial.display_path().to_path_buf(),
                status: "UNSAFE_RETAINED".to_owned(),
                detail: Some(format!("recovery evidence is unsafe: {error}")),
            });
            continue;
        }
        records.push(RecoveryRecord {
            capture_id: capture_id.to_owned(),
            path: partial.display_path().to_path_buf(),
            status: "INCOMPLETE".to_owned(),
            detail: None,
        });
    }
    let _ = rebuild_index_in(&root, MAX_REBUILD_CAPTURES).map_err(io::Error::other)?;
    Ok(records)
}

fn manifest_artifacts_match(
    directory: &PrivateDir,
    base: &crate::manifest::BaseManifest,
) -> io::Result<bool> {
    for (name, binding) in [
        ("stdout.raw", base.stdout.as_ref()),
        ("stderr.raw", base.stderr.as_ref()),
        ("events.ndjson", base.events.as_ref()),
    ] {
        let Some(binding) = binding else {
            return Ok(false);
        };
        let Some(expected) = binding.sha256.as_deref() else {
            return Ok(false);
        };
        let file = match directory.open_file(name) {
            Ok(file) => file,
            Err(_) => return Ok(false),
        };
        if crate::storage::file_len(&file)? != binding.bytes
            || crate::storage::sha256_file(&file)? != expected
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        capture_command, capture_command_pinned, capture_command_with_presentation,
        capture_command_with_v2_presentation, CaptureError, CaptureFaults, CaptureOptions,
        CommandEnvironment, CommandStdin, ProtectedStdinValue, V2CaptureMetadata,
        MAX_CAPTURE_BYTES, MAX_STDIN_BYTES,
    };
    use crate::presentation::{PersistenceMode, PresentationMode, PresentationOptions};
    use crate::storage::PrivateDir;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};
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
                shell_command: None,
                stdin: CommandStdin::Null,
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
                environment: CommandEnvironment::Inherited,
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
                shell_command: None,
                stdin: CommandStdin::Null,
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
                environment: CommandEnvironment::Inherited,
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
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("true")],
                spool_root: accepted_root.clone(),
                max_bytes: MAX_CAPTURE_BYTES,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            None,
        )
        .unwrap();
        assert_eq!(result.capture_status, "COMPLETE");
        fs::remove_dir_all(accepted_root).unwrap();

        let rejected_root = temporary_root("quota-boundary-rejected");
        let error = capture_command(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("true")],
                spool_root: rejected_root.clone(),
                max_bytes: MAX_CAPTURE_BYTES + 1,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::InvalidRequest(_)));
        assert!(!rejected_root.exists());
    }

    #[test]
    fn presentation_overflow_is_rejected_before_spawn_or_spool_creation() {
        let root = temporary_root("presentation-overflow");
        let error = capture_command_with_presentation(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("true")],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            &PresentationOptions {
                full_if_bytes: u64::MAX,
                ..PresentationOptions::default()
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::InvalidRequest(_)));
        assert!(!root.exists());
    }

    #[test]
    fn invalid_v2_binding_is_rejected_before_spawn_or_spool_creation() {
        let root = temporary_root("invalid-v2-binding");
        let marker = root.with_extension("executed");
        let error = capture_command_with_v2_presentation(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("touch"), marker.clone().into_os_string()],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: true,
                environment: CommandEnvironment::Inherited,
            },
            &PresentationOptions::default(),
            &V2CaptureMetadata {
                request_digest: "invalid".to_owned(),
                snapshot_id: "snapshot-test".to_owned(),
                policy_ref: "policy://test".to_owned(),
                policy_digest: format!("sha256:{}", "a".repeat(64)),
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::InvalidRequest(_)));
        assert!(!root.exists());
        assert!(!marker.exists());
    }

    #[test]
    fn excessive_redaction_transform_is_rejected_before_spawn_or_spool_creation() {
        let root = temporary_root("redaction-overflow");
        let error = capture_command_with_presentation(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("false")],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            &PresentationOptions {
                exact_redaction_values: vec![vec![b'x'; 64 * 1024]; 5],
                ..PresentationOptions::default()
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::InvalidRequest(_)));
        assert!(!root.exists());
    }

    #[test]
    fn failed_empty_command_has_honest_presentation_kind() {
        let root = temporary_root("empty-command-failure");
        let result = capture_command_with_presentation(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("false")],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            &PresentationOptions::default(),
            None,
        )
        .unwrap();
        assert_eq!(result.command.exit_code, Some(1));
        assert_eq!(result.capture_status, "COMPLETE");
        assert_eq!(result.presentation.unwrap().kind, "empty-command-failure");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ephemeral_persistence_is_explicit_and_leaves_no_capture_reference() {
        let root = temporary_root("ephemeral");
        let result = capture_command_with_presentation(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("true")],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
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
        assert!(!root.join("captures").exists());
        assert!(fs::read_dir(&root).unwrap().next().is_none());
        fs::remove_dir_all(root).unwrap();

        let lossy_root = temporary_root("ephemeral-lossy");
        let lossy_result = capture_command_with_presentation(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![
                    OsString::from("python3"),
                    OsString::from("-c"),
                    OsString::from("print('x' * 10000)"),
                ],
                spool_root: lossy_root.clone(),
                max_bytes: 16 * 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            &PresentationOptions {
                mode: PresentationMode::Safe,
                persistence: PersistenceMode::ProcessLocal,
                full_if_bytes: 1,
                ..PresentationOptions::default()
            },
            None,
        )
        .unwrap();
        let lossy_presentation = lossy_result.presentation.unwrap();
        assert!(lossy_presentation.omission);
        assert_eq!(
            lossy_presentation.persistence.status,
            "lossy-evidence-unavailable"
        );
        assert!(!lossy_presentation.persistence.retrieval_available);
        assert!(!lossy_presentation
            .body
            .as_deref()
            .unwrap_or_default()
            .contains("retrieve the capture"));
        assert!(lossy_result.path.as_os_str().is_empty());
        assert!(!lossy_root.join("captures").exists());
        assert!(fs::read_dir(&lossy_root).unwrap().next().is_none());
        fs::remove_dir_all(lossy_root).unwrap();

        let required_root = temporary_root("required-ephemeral");
        let error = capture_command_with_presentation(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("true")],
                spool_root: required_root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: true,
                environment: CommandEnvironment::Inherited,
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
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("true")],
                spool_root: rejected_root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
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
    fn ephemeral_capture_root_replacement_cannot_redirect_unnamed_files() {
        let root = temporary_root("ephemeral-replacement");
        let pinned = PrivateDir::ensure(&root).unwrap();
        let moved = root.with_extension("moved");
        let attacker = root.with_extension("attacker");
        fs::create_dir(&attacker).unwrap();
        fs::rename(&root, &moved).unwrap();
        std::os::unix::fs::symlink(&attacker, &root).unwrap();

        let file = pinned.create_unnamed_file().unwrap();
        assert!(file.metadata().unwrap().is_file());
        assert!(fs::read_dir(&moved).unwrap().next().is_none());
        assert!(fs::read_dir(&attacker).unwrap().next().is_none());

        fs::remove_file(&root).unwrap();
        fs::remove_dir(moved).unwrap();
        fs::remove_dir(attacker).unwrap();
    }

    #[test]
    fn stdin_writer_does_not_wait_on_a_descendant_held_pipe() {
        let root = temporary_root("stdin-descendant");
        let parent_code = "import os,time; child=os.fork(); time.sleep(10) if child == 0 else None";
        let started = std::time::Instant::now();
        let result = capture_command(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Bytes(Arc::new(ProtectedStdinValue::new(vec![
                    b'x';
                    16 * 1024
                        * 1024
                ]))),
                argv: vec![
                    OsString::from("python3"),
                    OsString::from("-c"),
                    OsString::from(parent_code),
                ],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: Some(Duration::from_secs(2)),
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            None,
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(result.command.exit_code, Some(0));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn direct_stdin_limit_plus_one_is_rejected_before_spool_creation() {
        let root = temporary_root("stdin-overflow");
        let error = capture_command(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Bytes(Arc::new(ProtectedStdinValue::new(vec![
                    b'x';
                    MAX_STDIN_BYTES
                        + 1
                ]))),
                argv: vec![OsString::from("true")],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::InvalidRequest(_)));
        assert!(!root.exists());
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
                shell_command: None,
                stdin: CommandStdin::Null,
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
                environment: CommandEnvironment::Inherited,
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

    #[test]
    fn recovery_skips_active_lease_without_writing_markers() {
        let root = temporary_root("active-recovery");
        let root_dir = PrivateDir::ensure(&root).unwrap();
        let partial_root = root_dir.ensure_dir("partial").unwrap();
        let partial = partial_root.create_dir("active.partial").unwrap();
        let lease = partial.create_file("lease.lock").unwrap();
        assert!(PrivateDir::try_lock_exclusive(&lease).unwrap());

        let records = super::recover_partials(&root).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, "ACTIVE_SKIPPED");
        assert!(partial.try_open_file("manifest.json").unwrap().is_none());
        assert!(partial.try_open_file("recovery.json").unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_hashes_observed_artifacts_and_retains_unsafe_paths() {
        let root = temporary_root("observed-recovery");
        let root_dir = PrivateDir::ensure(&root).unwrap();
        let partial_root = root_dir.ensure_dir("partial").unwrap();
        let partial = partial_root.create_dir("observed.partial").unwrap();
        fs::write(partial.display_path().join("stdout.raw"), b"recovered\n").unwrap();
        fs::write(partial.display_path().join("stderr.raw"), b"").unwrap();
        fs::write(partial.display_path().join("events.ndjson"), b"").unwrap();

        let records = super::recover_partials(&root).unwrap();
        assert_eq!(records[0].status, "INCOMPLETE");
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(partial.display_path().join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["capture_status"], "RECOVERED_INCOMPLETE");
        assert_eq!(manifest["command"]["final_status"], "UNKNOWN");
        assert_eq!(manifest["streams"]["stdout"]["bytes"], 10);
        assert_eq!(
            manifest["streams"]["stdout"]["sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );

        let unsafe_partial = partial_root.create_dir("unsafe.partial").unwrap();
        let outside = root.join("outside");
        fs::write(&outside, b"attacker").unwrap();
        symlink(&outside, unsafe_partial.display_path().join("stdout.raw")).unwrap();
        let records = super::recover_partials(&root).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records
                .iter()
                .find(|record| record.capture_id == "unsafe")
                .unwrap()
                .status,
            "UNSAFE_RETAINED"
        );
        assert!(unsafe_partial
            .try_open_file("manifest.json")
            .unwrap()
            .is_none());
        assert_eq!(fs::read(outside).unwrap(), b"attacker");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_finalizes_verified_pre_rename_window_and_is_idempotent() {
        let root = temporary_root("pre-rename-recovery");
        let result = capture_command(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("printf"), OsString::from("recover-me")],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: Some("workspace-1".to_owned()),
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            None,
        )
        .unwrap();
        let final_path = root.join("captures").join(&result.capture_id);
        let partial_path = root
            .join("partial")
            .join(format!("{}.partial", result.capture_id));
        let manifest_before = fs::read(final_path.join("manifest.json")).unwrap();
        fs::rename(&final_path, &partial_path).unwrap();

        let records = super::recover_partials(&root).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, "RECOVERED_FINALIZED");
        assert_eq!(
            fs::read(final_path.join("manifest.json")).unwrap(),
            manifest_before
        );
        assert_eq!(
            fs::read(final_path.join("stdout.raw")).unwrap(),
            b"recover-me"
        );
        assert!(super::recover_partials(&root).unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_never_promotes_tampered_or_conflicting_partial() {
        let root = temporary_root("recovery-attacks");
        let result = capture_command(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![OsString::from("printf"), OsString::from("trusted")],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: None,
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            None,
        )
        .unwrap();
        let capture_id = result.capture_id;
        let final_path = root.join("captures").join(&capture_id);
        let partial_path = root.join("partial").join(format!("{capture_id}.partial"));
        fs::rename(&final_path, &partial_path).unwrap();
        fs::write(partial_path.join("stdout.raw"), b"attacker").unwrap();
        let records = super::recover_partials(&root).unwrap();
        assert_eq!(records[0].status, "TAMPERED_RETAINED");
        assert!(!final_path.exists());
        assert_eq!(
            fs::read(partial_path.join("stdout.raw")).unwrap(),
            b"attacker"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn injected_stream_failure_fails_open_or_kills_required_child_without_deadlock() {
        let metadata = V2CaptureMetadata {
            request_digest: format!("sha256:{}", "a".repeat(64)),
            snapshot_id: "snapshot-test".to_owned(),
            policy_ref: "policy://test".to_owned(),
            policy_digest: format!("sha256:{}", "b".repeat(64)),
        };
        for (errno, expected) in [
            (libc::ENOSPC, "STORAGE_NO_SPACE"),
            (libc::EDQUOT, "STORAGE_QUOTA_EXCEEDED"),
            (libc::EIO, "STORAGE_IO_FAILED"),
        ] {
            let optional_root = temporary_root(&format!("fault-stream-optional-{errno}"));
            let optional = capture_command_pinned(
                &CaptureOptions {
                    shell_command: None,
                    stdin: CommandStdin::Null,
                    argv: vec![
                        OsString::from("python3"),
                        OsString::from("-c"),
                        OsString::from("import os; os.write(1,b'x'*1048576)"),
                    ],
                    spool_root: optional_root.clone(),
                    max_bytes: 2 * 1024 * 1024,
                    timeout: Some(Duration::from_secs(5)),
                    cwd: None,
                    workspace_id: None,
                    required_capture: false,
                    environment: CommandEnvironment::Inherited,
                },
                None,
                None,
                Some(&metadata),
                &CaptureFaults {
                    write_failure: Some((0, errno)),
                    ..CaptureFaults::default()
                },
            )
            .unwrap();
            assert_eq!(optional.command.exit_code, Some(0));
            assert_eq!(optional.capture_status, "CAPTURE_FAILED");
            assert_eq!(optional.capture_failure_key.as_deref(), Some(expected));
            let delta: serde_json::Value =
                serde_json::from_slice(&fs::read(optional.path.join("manifest.v2.json")).unwrap())
                    .unwrap();
            assert_eq!(delta["capture_status"], "degraded");
            fs::remove_dir_all(optional_root).unwrap();
        }

        let required_root = temporary_root("fault-stream-required");
        let started = Instant::now();
        let required = capture_command_pinned(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![
                    OsString::from("python3"),
                    OsString::from("-c"),
                    OsString::from("import os,time; os.write(1,b'started'); time.sleep(60)"),
                ],
                spool_root: required_root.clone(),
                max_bytes: 1024,
                timeout: Some(Duration::from_secs(5)),
                cwd: None,
                workspace_id: None,
                required_capture: true,
                environment: CommandEnvironment::Inherited,
            },
            None,
            None,
            None,
            &CaptureFaults {
                write_failure: Some((0, libc::EIO)),
                ..CaptureFaults::default()
            },
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(required.command.signal, Some(libc::SIGKILL));
        assert_eq!(required.capture_status, "CAPTURE_FAILED");
        fs::remove_dir_all(required_root).unwrap();
    }

    #[test]
    fn injected_durability_faults_never_return_a_complete_capture() {
        for (label, faults) in [
            (
                "manifest",
                CaptureFaults {
                    manifest_write: true,
                    ..CaptureFaults::default()
                },
            ),
            (
                "partial-sync",
                CaptureFaults {
                    partial_sync: true,
                    ..CaptureFaults::default()
                },
            ),
            (
                "rename",
                CaptureFaults {
                    rename: true,
                    ..CaptureFaults::default()
                },
            ),
            (
                "parent-sync",
                CaptureFaults {
                    parent_sync: true,
                    ..CaptureFaults::default()
                },
            ),
        ] {
            let root = temporary_root(&format!("fault-{label}"));
            let error = capture_command_pinned(
                &CaptureOptions {
                    shell_command: None,
                    stdin: CommandStdin::Null,
                    argv: vec![OsString::from("printf"), OsString::from("durability")],
                    spool_root: root.clone(),
                    max_bytes: 1024,
                    timeout: None,
                    cwd: None,
                    workspace_id: None,
                    required_capture: false,
                    environment: CommandEnvironment::Inherited,
                },
                None,
                None,
                None,
                &faults,
            )
            .unwrap_err();
            assert!(matches!(error, CaptureError::Finalize { .. }), "{label}");
            // Recovery either marks a pre-manifest partial incomplete,
            // finalizes a fully written pre-rename partial, or rebuilds the
            // index after rename. It never reruns the command.
            super::recover_partials(&root).unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn injected_sidecar_and_index_faults_preserve_authority_boundaries() {
        let metadata = V2CaptureMetadata {
            request_digest: format!("sha256:{}", "a".repeat(64)),
            snapshot_id: "snapshot-test".to_owned(),
            policy_ref: "policy://test".to_owned(),
            policy_digest: format!("sha256:{}", "b".repeat(64)),
        };
        let options_for = |root: PathBuf| CaptureOptions {
            shell_command: None,
            stdin: CommandStdin::Null,
            argv: vec![OsString::from("printf"), OsString::from("v2")],
            spool_root: root,
            max_bytes: 1024,
            timeout: None,
            cwd: None,
            workspace_id: Some("workspace-1".to_owned()),
            required_capture: true,
            environment: CommandEnvironment::Inherited,
        };
        let sidecar_root = temporary_root("fault-sidecar");
        let error = capture_command_pinned(
            &options_for(sidecar_root.clone()),
            None,
            Some(&PresentationOptions::default()),
            Some(&metadata),
            &CaptureFaults {
                sidecar_write: true,
                ..CaptureFaults::default()
            },
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::Finalize { .. }));
        assert!(sidecar_root
            .join("captures")
            .read_dir()
            .unwrap()
            .next()
            .is_none());
        fs::remove_dir_all(sidecar_root).unwrap();

        let index_root = temporary_root("fault-index");
        let result = capture_command_pinned(
            &options_for(index_root.clone()),
            None,
            Some(&PresentationOptions::default()),
            Some(&metadata),
            &CaptureFaults {
                index_write: true,
                ..CaptureFaults::default()
            },
        )
        .unwrap();
        assert_eq!(result.capture_status, "COMPLETE");
        assert_eq!(result.index_status.as_deref(), Some("rebuild-required"));
        assert!(result.path.join("manifest.v2.json").is_file());
        super::recover_partials(&index_root).unwrap();
        assert!(index_root
            .join("index-v2")
            .read_dir()
            .unwrap()
            .next()
            .is_some());
        fs::remove_dir_all(index_root).unwrap();
    }
}

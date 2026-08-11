//! Native W3 command-capture CLI. Machine output is bounded metadata JSON;
//! child stdout and stderr are retained only in the private spool.

use outctl_engine::capture::{
    capture_command_with_presentation, recover_partials, CaptureError, CaptureOptions,
};
use outctl_engine::presentation::{PersistenceMode, PresentationMode, PresentationOptions};
use outctl_engine::retrieval::{
    inspect_capture_for_workspace, verify_capture_for_workspace, RetrievalStatus,
};
use serde_json::json;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Eq, PartialEq)]
pub enum Request {
    Capabilities,
    Version,
    Help,
    Run(RunRequest),
    Inspect {
        spool_root: PathBuf,
        capture_id: String,
        workspace_id: Option<String>,
    },
    Verify {
        spool_root: PathBuf,
        capture_id: String,
        workspace_id: Option<String>,
    },
    Recover {
        spool_root: PathBuf,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct RunRequest {
    pub argv: Vec<OsString>,
    pub spool_root: PathBuf,
    pub max_bytes: u64,
    pub timeout: Option<Duration>,
    pub cwd: Option<PathBuf>,
    pub workspace_id: Option<String>,
    pub required_capture: bool,
    pub presentation: PresentationOptions,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CliError {
    message: String,
    exit_code: u8,
}

impl CliError {
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn exit_code(&self) -> u8 {
        self.exit_code
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 2,
        }
    }

    fn wrapper(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 125,
        }
    }
}

pub fn parse_args<I>(arguments: I) -> Result<Request, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let Some(first) = arguments.next() else {
        return Ok(Request::Capabilities);
    };
    let first_text = first.to_string_lossy();
    match first_text.as_ref() {
        "capabilities" | "--capabilities" => parse_capabilities(arguments),
        "version" | "--version" => {
            if arguments.next().is_some() {
                Err(CliError::usage(
                    "version does not accept additional arguments",
                ))
            } else {
                Ok(Request::Version)
            }
        }
        "help" | "--help" => Ok(Request::Help),
        "run" | "exec" => parse_run(arguments),
        "inspect" => parse_capture_read(arguments, "inspect"),
        "verify" => parse_capture_read(arguments, "verify"),
        "recover" => parse_recover(arguments),
        other => Err(CliError::usage(format!(
            "unsupported native command {other:?}"
        ))),
    }
}

fn parse_capabilities<I>(mut arguments: I) -> Result<Request, CliError>
where
    I: Iterator<Item = OsString>,
{
    while let Some(argument) = arguments.next() {
        match argument.to_string_lossy().as_ref() {
            "--json" | "--format=json" => {}
            "--format" if arguments.next().as_deref() == Some(std::ffi::OsStr::new("json")) => {}
            _ => {
                return Err(CliError::usage(
                    "only JSON capabilities output is available",
                ))
            }
        }
    }
    Ok(Request::Capabilities)
}

fn parse_run<I>(arguments: I) -> Result<Request, CliError>
where
    I: Iterator<Item = OsString>,
{
    let mut spool_root = PathBuf::from(".outctl");
    let mut max_bytes = 16 * 1024 * 1024;
    let mut timeout = None;
    let mut cwd = None;
    let mut workspace_id = None;
    let mut required_capture = false;
    let mut presentation = PresentationOptions::default();
    let mut argv = Vec::new();
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            argv.extend(arguments);
            break;
        }
        let option = argument.to_string_lossy();
        match option.as_ref() {
            "--spool-root" => {
                spool_root = PathBuf::from(required_value(&mut arguments, "--spool-root")?)
            }
            "--max-bytes" | "--max-capture-bytes" => {
                max_bytes = parse_u64(
                    required_value(&mut arguments, "--max-bytes")?,
                    "--max-bytes",
                )?
            }
            "--timeout-ms" => {
                timeout = Some(Duration::from_millis(parse_u64(
                    required_value(&mut arguments, "--timeout-ms")?,
                    "--timeout-ms",
                )?))
            }
            "--cwd" => cwd = Some(PathBuf::from(required_value(&mut arguments, "--cwd")?)),
            "--workspace-id" => {
                workspace_id = Some(
                    required_value(&mut arguments, "--workspace-id")?
                        .into_string()
                        .map_err(|_| CliError::wrapper("--workspace-id must be UTF-8"))?,
                )
            }
            "--required-capture" => required_capture = true,
            "--presentation-mode" => {
                let value = required_value(&mut arguments, "--presentation-mode")?;
                presentation.mode = parse_presentation_mode(value)?;
            }
            "--persist" | "--persistence" => {
                let value = required_value(&mut arguments, "--persist")?;
                presentation.persistence = parse_persistence_mode(value)?;
            }
            "--max-projection-bytes" => {
                presentation.max_bytes = parse_usize(
                    required_value(&mut arguments, "--max-projection-bytes")?,
                    "--max-projection-bytes",
                )?;
            }
            "--max-projection-lines" => {
                presentation.max_lines = parse_usize(
                    required_value(&mut arguments, "--max-projection-lines")?,
                    "--max-projection-lines",
                )?;
            }
            "--max-projection-tokens" => {
                presentation.max_estimated_tokens = parse_usize(
                    required_value(&mut arguments, "--max-projection-tokens")?,
                    "--max-projection-tokens",
                )?;
            }
            "--full-if-bytes" => {
                presentation.full_if_bytes = parse_u64(
                    required_value(&mut arguments, "--full-if-bytes")?,
                    "--full-if-bytes",
                )?;
            }
            _ if option.starts_with('-') => {
                return Err(CliError::wrapper(format!(
                    "unsupported run option {option:?}"
                )))
            }
            _ => {
                argv.push(argument);
                argv.extend(arguments);
                break;
            }
        }
    }
    if argv.is_empty() {
        return Err(CliError::wrapper("run requires direct argv after --"));
    }
    Ok(Request::Run(RunRequest {
        argv,
        spool_root,
        max_bytes,
        timeout,
        cwd,
        workspace_id,
        required_capture,
        presentation,
    }))
}

fn parse_presentation_mode(value: OsString) -> Result<PresentationMode, CliError> {
    match value.to_string_lossy().as_ref() {
        "auto" => Ok(PresentationMode::Auto),
        "minimum-savings" | "minimum" => Ok(PresentationMode::MinimumSavings),
        "safe" | "raw-safe" => Ok(PresentationMode::Safe),
        "compact" => Ok(PresentationMode::Compact),
        "projected" | "bounded-projection" => Ok(PresentationMode::Projected),
        "metadata" | "metadata-only" => Ok(PresentationMode::Metadata),
        value => Err(CliError::wrapper(format!(
            "unsupported presentation mode {value:?}"
        ))),
    }
}

fn parse_persistence_mode(value: OsString) -> Result<PersistenceMode, CliError> {
    match value.to_string_lossy().as_ref() {
        "memory-only" => Ok(PersistenceMode::MemoryOnly),
        "process-local" => Ok(PersistenceMode::ProcessLocal),
        "host-persistent" | "host" => Ok(PersistenceMode::HostPersistent),
        "replicated" => Ok(PersistenceMode::Replicated),
        value => Err(CliError::wrapper(format!(
            "unsupported persistence mode {value:?}"
        ))),
    }
}

fn parse_capture_read<I>(arguments: I, operation: &str) -> Result<Request, CliError>
where
    I: Iterator<Item = OsString>,
{
    let mut spool_root = PathBuf::from(".outctl");
    let mut capture_id = None;
    let mut workspace_id = None;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        if argument == "--spool-root" {
            spool_root = PathBuf::from(required_value(&mut arguments, "--spool-root")?);
        } else if argument == "--workspace-id" {
            workspace_id = Some(
                required_value(&mut arguments, "--workspace-id")?
                    .into_string()
                    .map_err(|_| CliError::usage("--workspace-id must be UTF-8"))?,
            );
        } else if capture_id.is_none() {
            capture_id = Some(
                argument
                    .into_string()
                    .map_err(|_| CliError::usage("capture id must be UTF-8"))?,
            );
        } else {
            return Err(CliError::usage(format!(
                "{operation} accepts one capture id"
            )));
        }
    }
    let capture_id =
        capture_id.ok_or_else(|| CliError::usage(format!("{operation} requires a capture id")))?;
    Ok(if operation == "inspect" {
        Request::Inspect {
            spool_root,
            capture_id,
            workspace_id,
        }
    } else {
        Request::Verify {
            spool_root,
            capture_id,
            workspace_id,
        }
    })
}

fn parse_recover<I>(arguments: I) -> Result<Request, CliError>
where
    I: Iterator<Item = OsString>,
{
    let mut spool_root = PathBuf::from(".outctl");
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        if argument == "--spool-root" {
            spool_root = PathBuf::from(required_value(&mut arguments, "--spool-root")?);
        } else {
            return Err(CliError::usage("recover accepts only --spool-root"));
        }
    }
    Ok(Request::Recover { spool_root })
}

fn required_value<I>(arguments: &mut I, option: &str) -> Result<OsString, CliError>
where
    I: Iterator<Item = OsString>,
{
    arguments
        .next()
        .ok_or_else(|| CliError::wrapper(format!("{option} requires a value")))
}

fn parse_u64(value: OsString, option: &str) -> Result<u64, CliError> {
    value
        .to_string_lossy()
        .parse()
        .map_err(|_| CliError::wrapper(format!("{option} requires a non-negative integer")))
}

fn parse_usize(value: OsString, option: &str) -> Result<usize, CliError> {
    value
        .to_string_lossy()
        .parse()
        .map_err(|_| CliError::wrapper(format!("{option} requires a non-negative integer")))
}

pub fn execute(request: Request) -> Result<(String, u8), CliError> {
    match request {
        Request::Capabilities => Ok((capabilities_output(), 0)),
        Request::Version => Ok((version_output().to_owned(), 0)),
        Request::Help => Ok((HELP_OUTPUT.to_owned(), 0)),
        Request::Run(request) => execute_run(request),
        Request::Inspect {
            spool_root,
            capture_id,
            workspace_id,
        } => {
            let result =
                inspect_capture_for_workspace(&spool_root, &capture_id, workspace_id.as_deref());
            let output = json!({
                "status": result.status,
                "capture_id": result.capture_id,
                "capture_status": result.capture_status,
                "detail": result.detail,
            });
            Ok((output.to_string(), retrieval_exit(result.status)))
        }
        Request::Verify {
            spool_root,
            capture_id,
            workspace_id,
        } => {
            let result =
                verify_capture_for_workspace(&spool_root, &capture_id, workspace_id.as_deref());
            let code = retrieval_exit(result.status);
            Ok((
                serde_json::to_string(&result)
                    .map_err(|error| CliError::wrapper(error.to_string()))?,
                code,
            ))
        }
        Request::Recover { spool_root } => {
            let records = recover_partials(&spool_root)
                .map_err(|error| CliError::wrapper(format!("recovery failed: {error}")))?;
            Ok((
                serde_json::to_string(&json!({"records": records})).unwrap(),
                0,
            ))
        }
    }
}

fn execute_run(request: RunRequest) -> Result<(String, u8), CliError> {
    let result = capture_command_with_presentation(
        &CaptureOptions {
            argv: request.argv,
            spool_root: request.spool_root,
            max_bytes: request.max_bytes,
            timeout: request.timeout,
            cwd: request.cwd,
            workspace_id: request.workspace_id,
            required_capture: request.required_capture,
        },
        &request.presentation,
        None,
    )
    .map_err(capture_error)?;
    let exit_code = if result.capture_status == "CAPTURE_FAILED" {
        125
    } else if let Some(code) = result.command.exit_code {
        code.rem_euclid(256) as u8
    } else if let Some(signal) = result.command.signal {
        (128 + signal).rem_euclid(256) as u8
    } else {
        125
    };
    let output = serde_json::to_string(&result)
        .map_err(|error| CliError::wrapper(format!("result serialization failed: {error}")))?;
    Ok((output, exit_code))
}

fn capture_error(error: CaptureError) -> CliError {
    if let CaptureError::Presentation(failure) = &error {
        return CliError::wrapper(
            json!({
                "wrapper_error": {
                    "code": "OUTCTL_POSTSPAWN_PRESENTATION_FAILED",
                    "phase": "post-spawn",
                    "message": error.to_string()
                },
                "capture_id": failure.capture_id,
                "path": failure.path,
                "capture_status": failure.capture_status,
                "command": failure.command,
            })
            .to_string(),
        );
    }
    let (code, phase, capture_id, path) = match &error {
        CaptureError::InvalidRequest(_) => {
            ("OUTCTL_PRESPAWN_INVALID_REQUEST", "pre-spawn", None, None)
        }
        CaptureError::CaptureUnavailable(_) => (
            "OUTCTL_PRESPAWN_CAPTURE_UNAVAILABLE",
            "pre-spawn",
            None,
            None,
        ),
        CaptureError::Spawn {
            capture_id, path, ..
        } => (
            "OUTCTL_PRESPAWN_INVALID_REQUEST",
            "pre-spawn",
            Some(capture_id),
            Some(path),
        ),
        CaptureError::Cancelled { capture_id, path } => (
            "OUTCTL_POSTSPAWN_CANCELLED",
            "post-spawn",
            Some(capture_id),
            Some(path),
        ),
        CaptureError::Finalize {
            capture_id, path, ..
        } => (
            "OUTCTL_POSTSPAWN_CAPTURE_FAILED",
            "post-spawn",
            Some(capture_id),
            Some(path),
        ),
        CaptureError::Presentation(_) => unreachable!("presentation errors are handled above"),
    };
    CliError::wrapper(
        json!({
            "wrapper_error": {"code": code, "phase": phase, "message": error.to_string()},
            "capture_id": capture_id,
            "path": path,
        })
        .to_string(),
    )
}

fn retrieval_exit(status: RetrievalStatus) -> u8 {
    if status == RetrievalStatus::Available {
        0
    } else {
        1
    }
}

pub fn capabilities_output() -> String {
    outctl_engine::capabilities().to_json()
}

pub fn version_output() -> &'static str {
    outctl_engine::ENGINE_VERSION
}

pub const HELP_OUTPUT: &str = "outctl-native capabilities [--json]\noutctl-native version\noutctl-native run [--spool-root PATH] [--max-bytes N] [--timeout-ms N] [--cwd PATH] [--workspace-id ID] [--required-capture] [--presentation-mode auto|minimum-savings|safe|compact|projected|metadata] [--persist memory-only|process-local|host-persistent|replicated] [--max-projection-bytes N] [--max-projection-lines N] [--max-projection-tokens N] [--full-if-bytes N] -- ARGV...\noutctl-native inspect [--spool-root PATH] [--workspace-id ID] CAPTURE_ID\noutctl-native verify [--spool-root PATH] [--workspace-id ID] CAPTURE_ID\noutctl-native recover [--spool-root PATH]\n";

#[cfg(test)]
mod tests {
    use super::{capture_error, parse_args, Request};
    use outctl_engine::capture::{CaptureError, CommandResult};
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn capabilities_is_the_default_metadata_path() {
        assert_eq!(parse_args(args(&[])), Ok(Request::Capabilities));
        assert_eq!(
            parse_args(args(&["capabilities", "--json"])),
            Ok(Request::Capabilities)
        );
    }

    #[test]
    fn run_requires_direct_argv() {
        let error = parse_args(args(&["run", "--"])).unwrap_err();
        assert_eq!(error.exit_code(), 125);
        assert!(error.message().contains("direct argv"));
    }

    #[test]
    fn minimum_savings_presentation_mode_is_parseable() {
        assert!(parse_args(args(&[
            "run",
            "--presentation-mode",
            "minimum-savings",
            "--",
            "true",
        ]))
        .is_ok());
    }

    #[test]
    fn presentation_failure_is_not_labeled_capture_failure() {
        let error = capture_error(CaptureError::Presentation(Box::new(
            outctl_engine::capture::PresentationFailure {
                capture_id: "capture-fault".to_owned(),
                path: PathBuf::from("/private/capture-fault"),
                command: CommandResult {
                    started: true,
                    exit_code: Some(0),
                    signal: None,
                    timed_out: false,
                    cancelled: false,
                    signals_sent: Vec::new(),
                },
                capture_status: "COMPLETE".to_owned(),
                source: std::io::Error::other("injected presentation fault"),
            },
        )));
        let value: serde_json::Value = serde_json::from_str(error.message()).unwrap();
        assert_eq!(
            value["wrapper_error"]["code"],
            "OUTCTL_POSTSPAWN_PRESENTATION_FAILED"
        );
        assert_eq!(value["wrapper_error"]["phase"], "post-spawn");
        assert_eq!(value["capture_status"], "COMPLETE");
        assert_eq!(value["command"]["exit_code"], 0);
        assert_ne!(
            value["wrapper_error"]["code"],
            "OUTCTL_POSTSPAWN_CAPTURE_FAILED"
        );
    }
}

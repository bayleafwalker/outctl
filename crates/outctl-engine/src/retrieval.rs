use crate::manifest::{read_published_manifest_bundle, sha256_prefixed, V2_SIDECAR_NAME};
use crate::retention::{read_retention, retention_binds_bundle};
use crate::storage::{file_len, read_range, sha256_file, PrivateDir, CHUNK_BYTES};
use regex::bytes::Regex;
use serde::Serialize;
use serde_json::Value;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub const DEFAULT_MAX_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: usize = 4 * 1024;
const MAX_MATCHES: usize = 100;

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalStatus {
    Available,
    Incomplete,
    Unavailable,
    Expired,
    Tampered,
    Denied,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectionResult {
    pub status: RetrievalStatus,
    pub capture_id: String,
    pub capture_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Value>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct SliceResult {
    pub status: RetrievalStatus,
    pub capture_id: String,
    pub stream: String,
    pub start: u64,
    pub end: u64,
    #[serde(skip)]
    pub data: Vec<u8>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct TailResult {
    pub status: RetrievalStatus,
    pub capture_id: String,
    pub stream: String,
    #[serde(skip)]
    pub data: Vec<u8>,
    pub truncated: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct SearchMatch {
    pub start: u64,
    pub end: u64,
    #[serde(skip)]
    pub context: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct SearchResult {
    pub status: RetrievalStatus,
    pub capture_id: String,
    pub stream: String,
    pub matches: Vec<SearchMatch>,
    pub limited: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct DigestCheck {
    pub artifact: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
    pub matches: bool,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct VerificationResult {
    pub status: RetrievalStatus,
    pub capture_id: String,
    pub checks: Vec<DigestCheck>,
    pub detail: Option<String>,
}

struct ResolvedCapture {
    status: RetrievalStatus,
    directory: Option<PrivateDir>,
    detail: Option<String>,
}

pub fn inspect_capture(spool_root: &Path, capture_id: &str) -> InspectionResult {
    inspect_capture_for_workspace(spool_root, capture_id, None)
}

pub fn inspect_capture_for_workspace(
    spool_root: &Path,
    capture_id: &str,
    expected_workspace_id: Option<&str>,
) -> InspectionResult {
    let resolved = resolve_capture(spool_root, capture_id);
    let (status, manifest, detail) = authorized_manifest(&resolved, expected_workspace_id);
    let capture_status = manifest
        .as_ref()
        .and_then(|value| value.get("capture_status"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    InspectionResult {
        status,
        capture_id: capture_id.to_owned(),
        capture_status,
        manifest,
        detail,
    }
}

pub fn slice_stream(
    spool_root: &Path,
    capture_id: &str,
    stream: &str,
    start: u64,
    end: u64,
    max_bytes: usize,
) -> Result<SliceResult, String> {
    slice_stream_for_workspace(spool_root, capture_id, stream, start, end, max_bytes, None)
}

#[allow(clippy::too_many_arguments)]
pub fn slice_stream_for_workspace(
    spool_root: &Path,
    capture_id: &str,
    stream: &str,
    start: u64,
    end: u64,
    max_bytes: usize,
    expected_workspace_id: Option<&str>,
) -> Result<SliceResult, String> {
    validate_stream(stream)?;
    if end < start {
        return Err("slice range must be a non-negative half-open range".to_owned());
    }
    if max_bytes == 0 || max_bytes > DEFAULT_MAX_BYTES {
        return Err(format!(
            "max_bytes must be between 1 and {DEFAULT_MAX_BYTES}"
        ));
    }
    if end - start > max_bytes as u64 {
        return Err("slice range exceeds max_bytes".to_owned());
    }
    let resolved = resolve_capture(spool_root, capture_id);
    let (status, file, detail) = stream_file(&resolved, stream, expected_workspace_id);
    let Some(file) = file else {
        return Ok(SliceResult {
            status,
            capture_id: capture_id.to_owned(),
            stream: stream.to_owned(),
            start,
            end,
            data: Vec::new(),
            detail,
        });
    };
    let size = file_len(&file).map_err(|error| error.to_string())?;
    let actual_end = end.min(size);
    let data = if start < actual_end {
        read_range(&file, start, actual_end).map_err(|error| error.to_string())?
    } else {
        Vec::new()
    };
    Ok(SliceResult {
        status: RetrievalStatus::Available,
        capture_id: capture_id.to_owned(),
        stream: stream.to_owned(),
        start,
        end: actual_end,
        data,
        detail: None,
    })
}

pub fn tail_stream(
    spool_root: &Path,
    capture_id: &str,
    stream: &str,
    lines: Option<usize>,
    max_bytes: usize,
) -> Result<TailResult, String> {
    tail_stream_for_workspace(spool_root, capture_id, stream, lines, max_bytes, None)
}

pub fn tail_stream_for_workspace(
    spool_root: &Path,
    capture_id: &str,
    stream: &str,
    lines: Option<usize>,
    max_bytes: usize,
    expected_workspace_id: Option<&str>,
) -> Result<TailResult, String> {
    validate_stream(stream)?;
    if max_bytes == 0 || max_bytes > DEFAULT_MAX_BYTES {
        return Err(format!(
            "max_bytes must be between 1 and {DEFAULT_MAX_BYTES}"
        ));
    }
    let resolved = resolve_capture(spool_root, capture_id);
    let (status, file, detail) = stream_file(&resolved, stream, expected_workspace_id);
    let Some(file) = file else {
        return Ok(TailResult {
            status,
            capture_id: capture_id.to_owned(),
            stream: stream.to_owned(),
            data: Vec::new(),
            truncated: false,
            detail,
        });
    };
    let size = file_len(&file).map_err(|error| error.to_string())?;
    let start = size.saturating_sub(max_bytes as u64);
    let mut data = read_range(&file, start, size).map_err(|error| error.to_string())?;
    if let Some(lines) = lines {
        data = final_lines(&data, lines);
    }
    Ok(TailResult {
        status: RetrievalStatus::Available,
        capture_id: capture_id.to_owned(),
        stream: stream.to_owned(),
        data,
        truncated: start != 0,
        detail: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn search_stream(
    spool_root: &Path,
    capture_id: &str,
    stream: &str,
    pattern: &[u8],
    regex: bool,
    context_bytes: usize,
    max_matches: usize,
) -> Result<SearchResult, String> {
    search_stream_for_workspace(
        spool_root,
        capture_id,
        stream,
        pattern,
        regex,
        context_bytes,
        max_matches,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn search_stream_for_workspace(
    spool_root: &Path,
    capture_id: &str,
    stream: &str,
    pattern: &[u8],
    regex: bool,
    context_bytes: usize,
    max_matches: usize,
    expected_workspace_id: Option<&str>,
) -> Result<SearchResult, String> {
    validate_stream(stream)?;
    if pattern.is_empty() || pattern.len() > CHUNK_BYTES {
        return Err(format!(
            "search pattern must contain 1 to {CHUNK_BYTES} bytes"
        ));
    }
    if context_bytes > MAX_CONTEXT_BYTES {
        return Err(format!("context_bytes must be at most {MAX_CONTEXT_BYTES}"));
    }
    if max_matches == 0 || max_matches > MAX_MATCHES {
        return Err(format!("max_matches must be between 1 and {MAX_MATCHES}"));
    }
    let matcher = if regex {
        Some(
            Regex::new(std::str::from_utf8(pattern).map_err(|_| "regex must be UTF-8")?)
                .map_err(|error| format!("invalid regex: {error}"))?,
        )
    } else {
        None
    };
    let resolved = resolve_capture(spool_root, capture_id);
    let (status, file, detail) = stream_file(&resolved, stream, expected_workspace_id);
    let Some(mut file) = file else {
        return Ok(SearchResult {
            status,
            capture_id: capture_id.to_owned(),
            stream: stream.to_owned(),
            matches: Vec::new(),
            limited: false,
            detail,
        });
    };
    let size = file_len(&file).map_err(|error| error.to_string())?;
    let mut overlap = Vec::new();
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    let mut offset = 0_u64;
    let mut matches = Vec::new();
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        let mut window = Vec::with_capacity(overlap.len() + read);
        window.extend_from_slice(&overlap);
        window.extend_from_slice(&buffer[..read]);
        let window_start = offset.saturating_sub(overlap.len() as u64);
        let positions: Box<dyn Iterator<Item = (usize, usize)> + '_> = match &matcher {
            Some(matcher) => Box::new(
                matcher
                    .find_iter(&window)
                    .map(|item| (item.start(), item.end())),
            ),
            None => Box::new(LiteralMatches::new(&window, pattern)),
        };
        for (local_start, local_end) in positions {
            let start = window_start + local_start as u64;
            let end = window_start + local_end as u64;
            if end <= offset || start == end {
                continue;
            }
            let context_start = start.saturating_sub(context_bytes as u64);
            let context_end = end.saturating_add(context_bytes as u64).min(size);
            let context =
                read_range(&file, context_start, context_end).map_err(|error| error.to_string())?;
            matches.push(SearchMatch {
                start,
                end,
                context,
            });
            if matches.len() == max_matches {
                return Ok(SearchResult {
                    status: RetrievalStatus::Available,
                    capture_id: capture_id.to_owned(),
                    stream: stream.to_owned(),
                    matches,
                    limited: true,
                    detail: None,
                });
            }
        }
        let overlap_start = window.len().saturating_sub(CHUNK_BYTES);
        overlap.clear();
        overlap.extend_from_slice(&window[overlap_start..]);
        offset += read as u64;
    }
    Ok(SearchResult {
        status: RetrievalStatus::Available,
        capture_id: capture_id.to_owned(),
        stream: stream.to_owned(),
        matches,
        limited: false,
        detail: None,
    })
}

pub fn verify_capture(spool_root: &Path, capture_id: &str) -> VerificationResult {
    verify_capture_with_expected(spool_root, capture_id, None, None)
}

pub fn verify_capture_for_workspace(
    spool_root: &Path,
    capture_id: &str,
    expected_workspace_id: Option<&str>,
) -> VerificationResult {
    verify_capture_with_expected(spool_root, capture_id, expected_workspace_id, None)
}

pub fn verify_capture_with_expected(
    spool_root: &Path,
    capture_id: &str,
    expected_workspace_id: Option<&str>,
    expected_manifest_digest: Option<&str>,
) -> VerificationResult {
    let resolved = resolve_capture(spool_root, capture_id);
    let (status, manifest, detail) = authorized_manifest(&resolved, expected_workspace_id);
    let Some(manifest) = manifest else {
        return VerificationResult {
            status,
            capture_id: capture_id.to_owned(),
            checks: Vec::new(),
            detail,
        };
    };
    let Some(directory) = resolved.directory.as_ref() else {
        return VerificationResult {
            status: RetrievalStatus::Unavailable,
            capture_id: capture_id.to_owned(),
            checks: Vec::new(),
            detail: Some("capture unavailable".to_owned()),
        };
    };
    let bundle = match read_published_manifest_bundle(directory, Some(capture_id)) {
        Ok(bundle) => bundle,
        Err(error) => {
            return VerificationResult {
                status: RetrievalStatus::Tampered,
                capture_id: capture_id.to_owned(),
                checks: Vec::new(),
                detail: Some(error.to_string()),
            }
        }
    };
    let pinned_manifest_digest = bundle
        .sidecar_digest
        .as_deref()
        .unwrap_or(&bundle.base.exact_digest)
        .to_owned();
    let mut checks = vec![DigestCheck {
        artifact: "manifest".to_owned(),
        expected: expected_manifest_digest.map(str::to_owned),
        observed: Some(pinned_manifest_digest.clone()),
        matches: expected_manifest_digest.is_none_or(|expected| expected == pinned_manifest_digest),
    }];
    if let Some(delta) = &bundle.delta {
        checks.push(DigestCheck {
            artifact: "base-manifest".to_owned(),
            expected: Some(delta.base_manifest_digest.clone()),
            observed: Some(bundle.base.exact_digest.clone()),
            matches: delta.base_manifest_digest == bundle.base.exact_digest,
        });
        let observed = directory
            .read_bounded(V2_SIDECAR_NAME, crate::manifest::MAX_V2_SIDECAR_BYTES)
            .ok()
            .map(|bytes| sha256_prefixed(&bytes));
        checks.push(DigestCheck {
            artifact: "v2-sidecar".to_owned(),
            expected: bundle.sidecar_digest.clone(),
            matches: observed.is_some() && observed == bundle.sidecar_digest,
            observed,
        });
    }
    if status == RetrievalStatus::Expired {
        return VerificationResult {
            status: if checks.iter().all(|check| check.matches) {
                RetrievalStatus::Expired
            } else {
                RetrievalStatus::Tampered
            },
            capture_id: capture_id.to_owned(),
            checks,
            detail,
        };
    }
    let artifacts = [
        (
            "stdout",
            "stdout.raw",
            manifest.pointer("/streams/stdout/sha256"),
        ),
        (
            "stderr",
            "stderr.raw",
            manifest.pointer("/streams/stderr/sha256"),
        ),
        (
            "events",
            "events.ndjson",
            manifest.pointer("/event_index/sha256"),
        ),
    ];
    checks.extend(
        artifacts
            .into_iter()
            .map(|(artifact, filename, expected)| {
                let expected = expected.and_then(Value::as_str).map(str::to_owned);
                let observed = directory
                    .open_file(filename)
                    .ok()
                    .and_then(|file| sha256_file(&file).ok());
                DigestCheck {
                    artifact: artifact.to_owned(),
                    matches: expected.is_some() && expected == observed,
                    expected,
                    observed,
                }
            })
            .collect::<Vec<_>>(),
    );
    VerificationResult {
        status: if checks.iter().all(|check| check.matches) {
            RetrievalStatus::Available
        } else {
            RetrievalStatus::Tampered
        },
        capture_id: capture_id.to_owned(),
        checks,
        detail: None,
    }
}

fn validate_stream(stream: &str) -> Result<(), String> {
    if matches!(stream, "stdout" | "stderr") {
        Ok(())
    } else {
        Err("stream must be 'stdout' or 'stderr'".to_owned())
    }
}

fn valid_capture_id(capture_id: &str) -> bool {
    !capture_id.is_empty()
        && !matches!(capture_id, "." | "..")
        && !capture_id.contains('/')
        && !capture_id.contains('\\')
        && Path::new(capture_id)
            .file_name()
            .and_then(|name| name.to_str())
            == Some(capture_id)
}

fn resolve_capture(spool_root: &Path, capture_id: &str) -> ResolvedCapture {
    if !valid_capture_id(capture_id) {
        return ResolvedCapture {
            status: RetrievalStatus::Denied,
            directory: None,
            detail: Some("invalid capture id".to_owned()),
        };
    }
    let root = match PrivateDir::open(spool_root) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return ResolvedCapture {
                status: RetrievalStatus::Unavailable,
                directory: None,
                detail: Some("spool unavailable".to_owned()),
            }
        }
        Err(_) => {
            return ResolvedCapture {
                status: RetrievalStatus::Denied,
                directory: None,
                detail: Some("spool unavailable or unsafe".to_owned()),
            }
        }
    };
    for (group_name, status) in [
        ("captures", RetrievalStatus::Available),
        ("partial", RetrievalStatus::Incomplete),
    ] {
        let group = match root.try_open_dir(group_name) {
            Ok(Some(group)) => group,
            Ok(None) => continue,
            Err(_) => {
                return ResolvedCapture {
                    status: RetrievalStatus::Denied,
                    directory: None,
                    detail: Some("unsafe spool group".to_owned()),
                }
            }
        };
        let name = if group_name == "captures" {
            capture_id.to_owned()
        } else {
            format!("{capture_id}.partial")
        };
        match group.try_open_dir(&name) {
            Ok(Some(directory)) => {
                return ResolvedCapture {
                    status,
                    directory: Some(directory),
                    detail: None,
                }
            }
            Ok(None) => continue,
            Err(_) => {
                return ResolvedCapture {
                    status: RetrievalStatus::Denied,
                    directory: None,
                    detail: Some("unsafe capture path".to_owned()),
                }
            }
        }
    }
    ResolvedCapture {
        status: RetrievalStatus::Unavailable,
        directory: None,
        detail: Some("capture unavailable".to_owned()),
    }
}

fn load_manifest(resolved: &ResolvedCapture) -> (RetrievalStatus, Option<Value>, Option<String>) {
    if resolved.status != RetrievalStatus::Available {
        return (resolved.status, None, resolved.detail.clone());
    }
    let Some(directory) = &resolved.directory else {
        return (
            RetrievalStatus::Unavailable,
            None,
            Some("capture unavailable".to_owned()),
        );
    };
    let bundle = match read_published_manifest_bundle(directory, None) {
        Ok(bundle) => bundle,
        Err(crate::manifest::ManifestError::Io(error))
            if error.kind() == io::ErrorKind::NotFound =>
        {
            return (
                RetrievalStatus::Incomplete,
                None,
                Some("finalized capture has no manifest".to_owned()),
            )
        }
        Err(error) => return (RetrievalStatus::Tampered, None, Some(error.to_string())),
    };
    let mut manifest: Value = match serde_json::from_slice(&bundle.base.exact_bytes) {
        Ok(Value::Object(values)) => Value::Object(values),
        _ => {
            return (
                RetrievalStatus::Tampered,
                None,
                Some("manifest is unreadable".to_owned()),
            )
        }
    };
    if let Some(delta) = &bundle.delta {
        manifest["v2_storage"] = match serde_json::to_value(delta) {
            Ok(value) => value,
            Err(_) => {
                return (
                    RetrievalStatus::Tampered,
                    None,
                    Some("v2 sidecar is unreadable".to_owned()),
                )
            }
        };
    }
    match directory.try_open_file("retention.json") {
        Ok(Some(_)) => match read_retention(directory) {
            Ok(retention) if retention_binds_bundle(&retention, &bundle) => (
                RetrievalStatus::Expired,
                Some(manifest),
                Some("raw evidence expired by explicit retention policy".to_owned()),
            ),
            Ok(_) => (
                RetrievalStatus::Tampered,
                None,
                Some("retention record does not bind this manifest".to_owned()),
            ),
            Err(error) => (RetrievalStatus::Tampered, None, Some(error)),
        },
        Ok(None) => (RetrievalStatus::Available, Some(manifest), None),
        Err(_) => (
            RetrievalStatus::Tampered,
            None,
            Some("retention record is unsafe".to_owned()),
        ),
    }
}

fn authorized_manifest(
    resolved: &ResolvedCapture,
    expected_workspace_id: Option<&str>,
) -> (RetrievalStatus, Option<Value>, Option<String>) {
    let (status, manifest, detail) = load_manifest(resolved);
    let Some(expected) = expected_workspace_id else {
        return (status, manifest, detail);
    };
    let Some(manifest) = manifest else {
        return (status, None, detail);
    };
    let observed = manifest
        .pointer("/source/workspace_id")
        .and_then(Value::as_str);
    if observed != Some(expected) {
        return (
            RetrievalStatus::Denied,
            None,
            Some("workspace authorization denied".to_owned()),
        );
    }
    (status, Some(manifest), detail)
}

fn stream_file(
    resolved: &ResolvedCapture,
    stream: &str,
    expected_workspace_id: Option<&str>,
) -> (RetrievalStatus, Option<File>, Option<String>) {
    let (status, manifest, detail) = authorized_manifest(resolved, expected_workspace_id);
    if manifest.is_none() || status != RetrievalStatus::Available {
        return (status, None, detail);
    }
    let Some(directory) = &resolved.directory else {
        return (RetrievalStatus::Unavailable, None, detail);
    };
    match directory.open_file(&format!("{stream}.raw")) {
        Ok(file) => (RetrievalStatus::Available, Some(file), None),
        Err(_) => (
            RetrievalStatus::Tampered,
            None,
            Some("stream is missing or unsafe".to_owned()),
        ),
    }
}

fn final_lines(data: &[u8], lines: usize) -> Vec<u8> {
    if lines == 0 {
        return Vec::new();
    }
    let mut newlines = 0;
    for index in (0..data.len()).rev() {
        if data[index] == b'\n' && index + 1 != data.len() {
            newlines += 1;
            if newlines == lines {
                return data[index + 1..].to_vec();
            }
        }
    }
    data.to_vec()
}

struct LiteralMatches<'a> {
    data: &'a [u8],
    needle: &'a [u8],
    offset: usize,
}

impl<'a> LiteralMatches<'a> {
    fn new(data: &'a [u8], needle: &'a [u8]) -> Self {
        Self {
            data,
            needle,
            offset: 0,
        }
    }
}

impl Iterator for LiteralMatches<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let relative = self
            .data
            .get(self.offset..)?
            .windows(self.needle.len())
            .position(|window| window == self.needle)?;
        let start = self.offset + relative;
        self.offset = start + 1;
        Some((start, start + self.needle.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        inspect_capture, inspect_capture_for_workspace, load_manifest, resolve_capture,
        search_stream, search_stream_for_workspace, slice_stream, slice_stream_for_workspace,
        stream_file, tail_stream, tail_stream_for_workspace, verify_capture,
        verify_capture_for_workspace, verify_capture_with_expected, RetrievalStatus,
    };
    use crate::capture::{capture_command, CaptureOptions, CommandStdin};
    use crate::storage::{file_len, read_range};
    use sha2::{Digest, Sha256};
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn capture(workspace_id: Option<&str>) -> (PathBuf, String) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("outctl-retrieval-{}-{nonce}", std::process::id()));
        let result = capture_command(
            &CaptureOptions {
                shell_command: None,
                stdin: CommandStdin::Null,
                argv: vec![
                    OsString::from("python3"),
                    OsString::from("-c"),
                    OsString::from("import os; os.write(1,b'alpha\\nbeta marker\\nomega\\n')"),
                ],
                spool_root: root.clone(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: workspace_id.map(str::to_owned),
                required_capture: false,
                environment: crate::capture::CommandEnvironment::Inherited,
            },
            None,
        )
        .unwrap();
        (root, result.capture_id)
    }

    #[test]
    fn v1_reads_are_bounded_and_verify_without_rerun() {
        let (root, capture_id) = capture(None);
        assert_eq!(
            inspect_capture(&root, &capture_id).status,
            RetrievalStatus::Available
        );
        assert_eq!(
            slice_stream(&root, &capture_id, "stdout", 6, 17, 64)
                .unwrap()
                .data,
            b"beta marker"
        );
        assert_eq!(
            tail_stream(&root, &capture_id, "stdout", Some(1), 64)
                .unwrap()
                .data,
            b"omega\n"
        );
        let search =
            search_stream(&root, &capture_id, "stdout", b"beta\\s+marker", true, 2, 10).unwrap();
        assert_eq!(search.matches.len(), 1);
        assert_eq!(
            verify_capture(&root, &capture_id).status,
            RetrievalStatus::Available
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampering_and_symlinked_capture_paths_are_denied() {
        let (root, capture_id) = capture(None);
        fs::write(
            root.join("captures").join(&capture_id).join("stdout.raw"),
            b"changed",
        )
        .unwrap();
        assert_eq!(
            verify_capture(&root, &capture_id).status,
            RetrievalStatus::Tampered
        );
        let target = root.join("captures").join(&capture_id);
        symlink(&target, root.join("captures").join("linked")).unwrap();
        assert_eq!(
            inspect_capture(&root, "linked").status,
            RetrievalStatus::Denied
        );
        assert_eq!(
            inspect_capture(&root, "../outside").status,
            RetrievalStatus::Denied
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expected_manifest_digest_detects_coordinated_manifest_and_raw_rewrite() {
        let (root, capture_id) = capture(None);
        let capture_path = root.join("captures").join(&capture_id);
        let original_manifest = fs::read(capture_path.join("manifest.json")).unwrap();
        let expected = format!("sha256:{:x}", Sha256::digest(&original_manifest));
        let replacement = b"coordinated attacker\n";
        fs::write(capture_path.join("stdout.raw"), replacement).unwrap();
        let mut manifest: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
        manifest["streams"]["stdout"]["bytes"] = serde_json::json!(replacement.len());
        manifest["streams"]["stdout"]["sha256"] =
            serde_json::json!(format!("{:x}", Sha256::digest(replacement)));
        let mut bytes = serde_json::to_vec(&manifest).unwrap();
        bytes.push(b'\n');
        fs::write(capture_path.join("manifest.json"), bytes).unwrap();

        assert_eq!(
            verify_capture(&root, &capture_id).status,
            RetrievalStatus::Available
        );
        let verified = verify_capture_with_expected(&root, &capture_id, None, Some(&expected));
        assert_eq!(verified.status, RetrievalStatus::Tampered);
        assert!(verified
            .checks
            .iter()
            .any(|check| check.artifact == "manifest" && !check.matches));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retrieval_uses_pinned_capture_and_file_descriptors_after_replacement() {
        let (root, capture_id) = capture(None);
        let resolved = resolve_capture(&root, &capture_id);
        assert_eq!(resolved.status, RetrievalStatus::Available);

        let capture_path = root.join("captures").join(&capture_id);
        let moved_path = root.join("captures").join(format!("{capture_id}.moved"));
        let attacker_path = root.join("attacker");
        fs::create_dir(&attacker_path).unwrap();
        fs::write(attacker_path.join("manifest.json"), b"{}").unwrap();
        fs::write(attacker_path.join("stdout.raw"), b"attacker").unwrap();
        fs::rename(&capture_path, &moved_path).unwrap();
        symlink(&attacker_path, &capture_path).unwrap();

        let (status, manifest, _) = load_manifest(&resolved);
        assert_eq!(status, RetrievalStatus::Available);
        assert_eq!(manifest.unwrap()["capture_id"], capture_id);
        let (status, file, _) = stream_file(&resolved, "stdout", None);
        assert_eq!(status, RetrievalStatus::Available);
        let file = file.unwrap();
        assert_eq!(
            read_range(&file, 0, file_len(&file).unwrap()).unwrap(),
            b"alpha\nbeta marker\nomega\n"
        );

        fs::remove_file(&capture_path).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retrieval_rejects_artifact_symlink_without_open_race() {
        let (root, capture_id) = capture(None);
        let capture_path = root.join("captures").join(&capture_id);
        let outside = root.join("outside.raw");
        fs::write(&outside, b"outside").unwrap();
        fs::remove_file(capture_path.join("stdout.raw")).unwrap();
        symlink(&outside, capture_path.join("stdout.raw")).unwrap();
        assert_eq!(
            slice_stream(&root, &capture_id, "stdout", 0, 7, 64)
                .unwrap()
                .status,
            RetrievalStatus::Tampered
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_read_can_enforce_workspace_authorization() {
        let (root, capture_id) = capture(Some("workspace-owned"));
        assert_eq!(
            inspect_capture_for_workspace(&root, &capture_id, Some("workspace-other")).status,
            RetrievalStatus::Denied
        );
        assert_eq!(
            slice_stream_for_workspace(
                &root,
                &capture_id,
                "stdout",
                0,
                5,
                64,
                Some("workspace-other"),
            )
            .unwrap()
            .status,
            RetrievalStatus::Denied
        );
        assert_eq!(
            tail_stream_for_workspace(
                &root,
                &capture_id,
                "stdout",
                None,
                64,
                Some("workspace-other"),
            )
            .unwrap()
            .status,
            RetrievalStatus::Denied
        );
        assert_eq!(
            search_stream_for_workspace(
                &root,
                &capture_id,
                "stdout",
                b"alpha",
                false,
                0,
                1,
                Some("workspace-other"),
            )
            .unwrap()
            .status,
            RetrievalStatus::Denied
        );
        assert_eq!(
            verify_capture_for_workspace(&root, &capture_id, Some("workspace-other")).status,
            RetrievalStatus::Denied
        );
        assert_eq!(
            verify_capture_for_workspace(&root, &capture_id, Some("workspace-owned")).status,
            RetrievalStatus::Available
        );
        fs::remove_dir_all(root).unwrap();
    }
}

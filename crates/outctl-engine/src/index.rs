use crate::manifest::{
    parse_unique_json, read_published_manifest_bundle, sha256_prefixed, validate_capture_id,
    validate_prefixed_digest, ManifestBundle, ManifestError,
};
use crate::retention::{read_retention_with_digest, retention_binds_bundle};
use crate::storage::PrivateDir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io;
use std::path::Path;

const INDEX_DIRECTORY: &str = "index-v2";
const INDEX_SCHEMA: &str = "vuoro.outctl.capture-index-record/v2";
const MAX_INDEX_RECORD_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_REBUILD_CAPTURES: usize = 100_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IndexRecord {
    pub(crate) schema_version: String,
    pub(crate) capture_id: String,
    pub(crate) base_schema_version: String,
    pub(crate) base_manifest_digest: String,
    pub(crate) v2_sidecar_digest: Option<String>,
    pub(crate) workspace_id: Option<String>,
    pub(crate) capture_status: String,
    pub(crate) retained_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retention_record_digest: Option<String>,
    pub(crate) authoritative: bool,
    pub(crate) rebuildable: bool,
}

impl IndexRecord {
    fn validate(&self) -> Result<(), IndexError> {
        if self.schema_version != INDEX_SCHEMA {
            return Err(IndexError::Corrupt(
                "index schema version is unsupported".to_owned(),
            ));
        }
        validate_capture_id(&self.capture_id).map_err(IndexError::Manifest)?;
        if !matches!(
            self.base_schema_version.as_str(),
            "vuoro.outctl.capture/v1alpha1" | "vuoro.outctl.capture-native/w3"
        ) {
            return Err(IndexError::Corrupt(
                "base manifest schema version is unsupported".to_owned(),
            ));
        }
        validate_prefixed_digest(&self.base_manifest_digest, "base_manifest_digest")
            .map_err(IndexError::Manifest)?;
        if let Some(digest) = &self.v2_sidecar_digest {
            validate_prefixed_digest(digest, "v2_sidecar_digest").map_err(IndexError::Manifest)?;
        }
        if let Some(digest) = &self.retention_record_digest {
            validate_prefixed_digest(digest, "retention_record_digest")
                .map_err(IndexError::Manifest)?;
        }
        if self.authoritative || !self.rebuildable {
            return Err(IndexError::Corrupt(
                "index record must be non-authoritative and rebuildable".to_owned(),
            ));
        }
        if self
            .workspace_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 1024)
        {
            return Err(IndexError::Corrupt(
                "workspace ID is empty or oversized".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum IndexError {
    Io(io::Error),
    Manifest(ManifestError),
    Corrupt(String),
    Limit(String),
}

impl fmt::Display for IndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "index I/O failed: {error}"),
            Self::Manifest(error) => write!(formatter, "{error}"),
            Self::Corrupt(message) => write!(formatter, "index record is corrupt: {message}"),
            Self::Limit(message) => write!(formatter, "index bound exceeded: {message}"),
        }
    }
}

impl std::error::Error for IndexError {}

impl From<io::Error> for IndexError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ManifestError> for IndexError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

#[derive(Debug)]
pub(crate) struct IndexStore {
    directory: PrivateDir,
}

impl IndexStore {
    pub(crate) fn ensure(spool_root: &Path) -> Result<Self, IndexError> {
        let root = PrivateDir::ensure(spool_root)?;
        Self::ensure_in(&root)
    }

    /// Open the rebuildable index through a spool root already pinned by the
    /// capture transaction. The hot path must use this form so root pathname
    /// replacement cannot redirect an index update after capture allocation.
    pub(crate) fn ensure_in(root: &PrivateDir) -> Result<Self, IndexError> {
        let directory = root.ensure_dir(INDEX_DIRECTORY)?;
        Ok(Self { directory })
    }

    pub(crate) fn write(&self, record: &IndexRecord) -> Result<String, IndexError> {
        record.validate()?;
        let mut bytes =
            serde_json::to_vec(record).map_err(|error| IndexError::Corrupt(error.to_string()))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_INDEX_RECORD_BYTES {
            return Err(IndexError::Limit(
                "serialized record exceeds 64 KiB".to_owned(),
            ));
        }
        self.directory
            .write_atomic_replace(&index_filename(&record.capture_id), &bytes)?;
        Ok(sha256_prefixed(&bytes))
    }

    pub(crate) fn read(&self, capture_id: &str) -> Result<IndexRecord, IndexError> {
        validate_capture_id(capture_id).map_err(IndexError::Manifest)?;
        let bytes = self
            .directory
            .read_bounded(&index_filename(capture_id), MAX_INDEX_RECORD_BYTES)?;
        let value = parse_unique_json(&bytes).map_err(IndexError::Manifest)?;
        let record: IndexRecord = serde_json::from_value(value)
            .map_err(|error| IndexError::Corrupt(error.to_string()))?;
        record.validate()?;
        if record.capture_id != capture_id {
            return Err(IndexError::Corrupt(
                "record capture ID differs from its lookup key".to_owned(),
            ));
        }
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RebuildIssueKind {
    Unsafe,
    Corrupt,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct RebuildIssue {
    pub(crate) capture_id: String,
    pub(crate) kind: RebuildIssueKind,
    pub(crate) detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexRebuild {
    pub(crate) records: Vec<IndexRecord>,
    pub(crate) issues: Vec<RebuildIssue>,
}

pub(crate) fn record_from_bundle(bundle: &ManifestBundle) -> Result<IndexRecord, IndexError> {
    let retained_bytes = match &bundle.delta {
        Some(delta) => delta
            .streams
            .stdout
            .bytes
            .checked_add(delta.streams.stderr.bytes)
            .and_then(|value| value.checked_add(delta.event_index.bytes)),
        None => bundle
            .base
            .stdout
            .as_ref()
            .map(|value| value.bytes)
            .unwrap_or_default()
            .checked_add(
                bundle
                    .base
                    .stderr
                    .as_ref()
                    .map(|value| value.bytes)
                    .unwrap_or_default(),
            )
            .and_then(|value| {
                value.checked_add(
                    bundle
                        .base
                        .events
                        .as_ref()
                        .map(|event| event.bytes)
                        .unwrap_or_default(),
                )
            }),
    }
    .ok_or_else(|| IndexError::Corrupt("retained byte count overflows u64".to_owned()))?;
    let capture_status = bundle
        .delta
        .as_ref()
        .map(|delta| delta.capture_status.clone())
        .unwrap_or_else(|| normalized_status(&bundle.base.capture_status).to_owned());
    let record = IndexRecord {
        schema_version: INDEX_SCHEMA.to_owned(),
        capture_id: bundle.base.capture_id.clone(),
        base_schema_version: bundle.base.version.as_str().to_owned(),
        base_manifest_digest: bundle.base.exact_digest.clone(),
        v2_sidecar_digest: bundle.sidecar_digest.clone(),
        workspace_id: bundle.base.workspace_id.clone(),
        capture_status,
        retained_bytes,
        retention_record_digest: None,
        authoritative: false,
        rebuildable: true,
    };
    record.validate()?;
    Ok(record)
}

/// Rebuild the raw-free index from authoritative capture manifests.
///
/// Capture names are sorted before reading and records are written one at a
/// time through pinned descriptors. A bad capture becomes an explicit issue;
/// it cannot supply an index record. Existing records are merely a cache and
/// may be atomically replaced.
pub(crate) fn rebuild_index(
    spool_root: &Path,
    max_captures: usize,
) -> Result<IndexRebuild, IndexError> {
    if max_captures == 0 || max_captures > MAX_REBUILD_CAPTURES {
        return Err(IndexError::Limit(format!(
            "max_captures must be between 1 and {MAX_REBUILD_CAPTURES}"
        )));
    }
    let root = match PrivateDir::open(spool_root) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(IndexRebuild {
                records: Vec::new(),
                issues: Vec::new(),
            })
        }
        Err(error) => return Err(IndexError::Io(error)),
    };
    rebuild_index_in(&root, max_captures)
}

pub(crate) fn rebuild_index_in(
    root: &PrivateDir,
    max_captures: usize,
) -> Result<IndexRebuild, IndexError> {
    if max_captures == 0 || max_captures > MAX_REBUILD_CAPTURES {
        return Err(IndexError::Limit(format!(
            "max_captures must be between 1 and {MAX_REBUILD_CAPTURES}"
        )));
    }
    let Some(captures) = root.try_open_dir("captures")? else {
        return Ok(IndexRebuild {
            records: Vec::new(),
            issues: Vec::new(),
        });
    };
    let mut names = captures.names_bounded(max_captures)?;
    names.sort();
    let store = IndexStore::ensure_in(root)?;
    let mut records = Vec::new();
    let mut issues = Vec::new();
    for name in names {
        let Some(capture_id) = name.to_str() else {
            issues.push(RebuildIssue {
                capture_id: "<non-utf8>".to_owned(),
                kind: RebuildIssueKind::Unsafe,
                detail: "capture directory name is not UTF-8".to_owned(),
            });
            continue;
        };
        if let Err(error) = validate_capture_id(capture_id) {
            issues.push(issue(capture_id, error));
            continue;
        }
        let directory = match captures.try_open_dir(capture_id) {
            Ok(Some(directory)) => directory,
            Ok(None) => continue,
            Err(error) => {
                issues.push(RebuildIssue {
                    capture_id: capture_id.to_owned(),
                    kind: RebuildIssueKind::Unsafe,
                    detail: format!("capture directory is unsafe: {error}"),
                });
                continue;
            }
        };
        let bundle = match read_published_manifest_bundle(&directory, Some(capture_id)) {
            Ok(bundle) => bundle,
            Err(error) => {
                issues.push(issue(capture_id, error));
                continue;
            }
        };
        let mut record = match record_from_bundle(&bundle) {
            Ok(record) => record,
            Err(error) => {
                issues.push(RebuildIssue {
                    capture_id: capture_id.to_owned(),
                    kind: RebuildIssueKind::Corrupt,
                    detail: error.to_string(),
                });
                continue;
            }
        };
        match directory.try_open_file("retention.json") {
            Ok(Some(_)) => match read_retention_with_digest(&directory) {
                Ok((retention, digest)) if retention_binds_bundle(&retention, &bundle) => {
                    record.capture_status = "expired".to_owned();
                    record.retained_bytes = 0;
                    record.retention_record_digest = Some(digest);
                }
                Ok(_) => {
                    issues.push(RebuildIssue {
                        capture_id: capture_id.to_owned(),
                        kind: RebuildIssueKind::Unsafe,
                        detail: "retention record does not bind this manifest".to_owned(),
                    });
                    continue;
                }
                Err(error) => {
                    issues.push(RebuildIssue {
                        capture_id: capture_id.to_owned(),
                        kind: RebuildIssueKind::Unsafe,
                        detail: format!("retention record is unsafe: {error}"),
                    });
                    continue;
                }
            },
            Ok(None) => {}
            Err(error) => {
                issues.push(RebuildIssue {
                    capture_id: capture_id.to_owned(),
                    kind: RebuildIssueKind::Unsafe,
                    detail: format!("retention record path is unsafe: {error}"),
                });
                continue;
            }
        }
        store.write(&record)?;
        records.push(record);
    }
    Ok(IndexRebuild { records, issues })
}

fn issue(capture_id: &str, error: ManifestError) -> RebuildIssue {
    let kind = match error {
        ManifestError::UnsupportedSchema(_) => RebuildIssueKind::Unsupported,
        ManifestError::Io(_) | ManifestError::Tampered(_) => RebuildIssueKind::Unsafe,
        ManifestError::InvalidJson(_) | ManifestError::InvalidField(_) => RebuildIssueKind::Corrupt,
    };
    RebuildIssue {
        capture_id: capture_id.to_owned(),
        kind,
        detail: error.to_string(),
    }
}

fn index_filename(capture_id: &str) -> String {
    format!("{:x}.json", Sha256::digest(capture_id.as_bytes()))
}

fn normalized_status(value: &str) -> &str {
    match value {
        "COMPLETE" => "complete",
        "TRUNCATED" => "truncated",
        "CAPTURE_FAILED" => "failed",
        "INCOMPLETE" | "RECOVERED_INCOMPLETE" => "recovered-incomplete",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{rebuild_index, IndexError, IndexStore, RebuildIssueKind};
    use crate::storage::PrivateDir;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("outctl-index-{label}-{nonce}"))
    }

    fn legacy_capture(root: &Path, capture_id: &str, stdout: u64) {
        let captures = PrivateDir::ensure(root)
            .unwrap()
            .ensure_dir("captures")
            .unwrap();
        let capture = captures.create_dir(capture_id).unwrap();
        let base = format!(
            r#"{{"schema_version":"vuoro.outctl.capture-native/w3","capture_id":"{capture_id}","capture_status":"COMPLETE","source":{{"workspace_id":"workspace-1"}},"streams":{{"stdout":{{"bytes":{stdout},"sha256":"{}"}},"stderr":{{"bytes":0,"sha256":"{}"}}}},"event_index":{{"events":0,"sha256":"{}"}}}}"#,
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
        );
        capture.write_new("manifest.json", base.as_bytes()).unwrap();
        capture.write_new("events.ndjson", b"").unwrap();
    }

    #[test]
    fn rebuild_is_sorted_raw_free_and_one_back_readable() {
        let root = temporary_root("sorted");
        legacy_capture(&root, "capture-b", 2);
        legacy_capture(&root, "capture-a", 1);
        let rebuilt = rebuild_index(&root, 10).unwrap();
        assert!(rebuilt.issues.is_empty());
        assert_eq!(
            rebuilt
                .records
                .iter()
                .map(|record| record.capture_id.as_str())
                .collect::<Vec<_>>(),
            ["capture-a", "capture-b"]
        );
        let store = IndexStore::ensure(&root).unwrap();
        let record = store.read("capture-a").unwrap();
        assert_eq!(record.retained_bytes, 1);
        let serialized = serde_json::to_string(&record).unwrap();
        assert!(!serialized.contains("stdout.raw"));
        assert!(!serialized.contains("argv"));
        assert!(!serialized.contains("/tmp/"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rebuild_reports_corrupt_and_unsafe_captures_without_indexing_them() {
        let root = temporary_root("issues");
        legacy_capture(&root, "good", 1);
        let captures = PrivateDir::open(&root)
            .unwrap()
            .open_dir("captures")
            .unwrap();
        let bad = captures.create_dir("bad").unwrap();
        bad.write_new(
            "manifest.json",
            br#"{"capture_id":"bad","capture_id":"changed","capture_status":"COMPLETE"}"#,
        )
        .unwrap();
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join("captures/linked")).unwrap();
        let rebuilt = rebuild_index(&root, 10).unwrap();
        assert_eq!(rebuilt.records.len(), 1);
        assert!(rebuilt
            .issues
            .iter()
            .any(|item| item.capture_id == "bad" && item.kind == RebuildIssueKind::Corrupt));
        assert!(rebuilt
            .issues
            .iter()
            .any(|item| item.capture_id == "linked" && item.kind == RebuildIssueKind::Unsafe));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupted_index_record_is_explicit_and_rebuild_replaces_it() {
        let root = temporary_root("replace");
        legacy_capture(&root, "capture-1", 3);
        rebuild_index(&root, 10).unwrap();
        let store = IndexStore::ensure(&root).unwrap();
        let filename = super::index_filename("capture-1");
        fs::write(
            root.join("index-v2").join(&filename),
            br#"{"capture_id":"duplicate","capture_id":"other"}"#,
        )
        .unwrap();
        assert!(matches!(
            store.read("capture-1"),
            Err(IndexError::Manifest(_))
        ));
        rebuild_index(&root, 10).unwrap();
        assert_eq!(store.read("capture-1").unwrap().retained_bytes, 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rebuild_bound_fails_before_partial_index_results() {
        let root = temporary_root("bound");
        legacy_capture(&root, "one", 1);
        legacy_capture(&root, "two", 2);
        let error = rebuild_index(&root, 1).unwrap_err();
        assert!(matches!(error, IndexError::Io(_)));
        assert!(!root.join("index-v2").exists());
        fs::remove_dir_all(root).unwrap();
    }
}

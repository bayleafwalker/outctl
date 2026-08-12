//! Explicit local retention mechanics for immutable capture evidence.
//!
//! The caller supplies the exact capture IDs and policy identity. This module
//! owns bounded, descriptor-relative mechanics only; it does not decide which
//! evidence should expire.

use crate::index::{record_from_bundle, IndexStore};
use crate::manifest::{
    parse_unique_json, read_published_manifest_bundle, sha256_prefixed, validate_capture_id,
    validate_prefixed_digest, ManifestBundle,
};
use crate::storage::PrivateDir;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io;
use std::path::Path;

const RETENTION_NAME: &str = "retention.json";
const RETENTION_SCHEMA: &str = "vuoro.outctl.capture-retention-tombstone/v2";
const RETENTION_RECEIPTS_DIRECTORY: &str = "retention-v2";
const RETENTION_RECEIPT_SCHEMA: &str = "vuoro.outctl.capture-retention-publication/v2";
const MAX_CAPTURE_IDS: usize = 1024;
const MAX_CAPTURE_ENTRIES: usize = 64;
const MAX_RETENTION_BYTES: u64 = 64 * 1024;
const MAX_RETENTION_RECEIPT_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    pub reference: String,
    pub digest: String,
    pub expired_at_unix_ms: u64,
    pub reason_key: String,
    pub workspace_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CollectionAction {
    ExpireRaw,
    RemoveLegacyEmpty,
    AlreadyExpired,
    Unavailable,
    UnsafeRetained,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CollectionRecord {
    pub capture_id: String,
    pub action: CollectionAction,
    pub mutated: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CollectionResult {
    pub dry_run: bool,
    pub records: Vec<CollectionRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetentionTombstone {
    schema_version: String,
    capture_id: String,
    capture_ref: String,
    manifest_digest: String,
    prior_capture_status: String,
    retention_policy: TombstonePolicy,
    expired_at_unix_ms: u64,
    reason_key: String,
    availability: Availability,
    compatibility: RetentionCompatibility,
}

pub(crate) fn retention_binds_bundle(record: &RetentionTombstone, bundle: &ManifestBundle) -> bool {
    let manifest_digest = bundle
        .sidecar_digest
        .as_deref()
        .unwrap_or(&bundle.base.exact_digest);
    let capture_status = bundle
        .delta
        .as_ref()
        .map(|delta| delta.capture_status.as_str())
        .unwrap_or_else(|| normalized_status(&bundle.base.capture_status));
    record.capture_id == bundle.base.capture_id
        && record.manifest_digest == manifest_digest
        && record.prior_capture_status == capture_status
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetentionReceipt {
    schema_version: String,
    capture_id: String,
    manifest_digest: String,
    tombstone_digest: String,
    availability: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TombstonePolicy {
    #[serde(rename = "ref")]
    reference: String,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Availability {
    raw: String,
    manifest: String,
    retrieval: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetentionCompatibility {
    automatic_rerun: bool,
    immutable_manifest_rewritten: bool,
}

pub fn collect_captures(
    spool_root: &Path,
    capture_ids: &[String],
    policy: &RetentionPolicy,
    dry_run: bool,
    exclusive_spool: bool,
) -> Result<CollectionResult, String> {
    validate_request(capture_ids, policy, dry_run, exclusive_spool)?;
    let root = match PrivateDir::open(spool_root) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CollectionResult {
                dry_run,
                records: capture_ids
                    .iter()
                    .map(|capture_id| CollectionRecord {
                        capture_id: capture_id.clone(),
                        action: CollectionAction::Unavailable,
                        mutated: false,
                        detail: Some("spool is unavailable".to_owned()),
                    })
                    .collect(),
            })
        }
        Err(error) => return Err(format!("spool is unavailable or unsafe: {error}")),
    };
    let captures = match root
        .try_open_dir("captures")
        .map_err(|error| error.to_string())?
    {
        Some(captures) => captures,
        None => {
            return Ok(CollectionResult {
                dry_run,
                records: capture_ids
                    .iter()
                    .map(|capture_id| CollectionRecord {
                        capture_id: capture_id.clone(),
                        action: CollectionAction::Unavailable,
                        mutated: false,
                        detail: Some("capture group is unavailable".to_owned()),
                    })
                    .collect(),
            })
        }
    };
    let _lock = if dry_run {
        None
    } else {
        let lock = root
            .open_or_create_file("retention.lock")
            .map_err(|error| format!("retention lock is unavailable: {error}"))?;
        if !PrivateDir::try_lock_exclusive(&lock).map_err(|error| error.to_string())? {
            return Err("another retention collector holds the spool lock".to_owned());
        }
        Some(lock)
    };
    let store = if dry_run {
        None
    } else {
        Some(IndexStore::ensure_in(&root).map_err(|error| error.to_string())?)
    };
    let mut records = Vec::with_capacity(capture_ids.len());
    for capture_id in capture_ids {
        let capture = match captures.try_open_dir(capture_id) {
            Ok(Some(capture)) => capture,
            Ok(None) => {
                records.push(CollectionRecord {
                    capture_id: capture_id.clone(),
                    action: CollectionAction::Unavailable,
                    mutated: false,
                    detail: Some("capture is unavailable".to_owned()),
                });
                continue;
            }
            Err(error) => {
                records.push(CollectionRecord {
                    capture_id: capture_id.clone(),
                    action: CollectionAction::UnsafeRetained,
                    mutated: false,
                    detail: Some(format!("capture path is unsafe: {error}")),
                });
                continue;
            }
        };
        let names = capture
            .names_bounded(MAX_CAPTURE_ENTRIES)
            .map_err(|error| format!("capture entry bound failed: {error}"))?;
        if names.is_empty() {
            if !dry_run {
                // POSIX provides no inode-conditional rmdir. This operation is
                // permitted only under the caller's explicit exclusive-spool
                // contract, validated before any mutation in this call.
                captures.remove_dir(capture_id).map_err(|error| {
                    format!("legacy empty tombstone could not be removed: {error}")
                })?;
                captures.sync().map_err(|error| error.to_string())?;
            }
            records.push(CollectionRecord {
                capture_id: capture_id.clone(),
                action: CollectionAction::RemoveLegacyEmpty,
                mutated: !dry_run,
                detail: None,
            });
            continue;
        }
        let bundle = match read_published_manifest_bundle(&capture, Some(capture_id)) {
            Ok(bundle) => bundle,
            Err(error) => {
                records.push(CollectionRecord {
                    capture_id: capture_id.clone(),
                    action: CollectionAction::UnsafeRetained,
                    mutated: false,
                    detail: Some(error.to_string()),
                });
                continue;
            }
        };
        if policy
            .workspace_id
            .as_deref()
            .is_some_and(|expected| bundle.base.workspace_id.as_deref() != Some(expected))
        {
            records.push(CollectionRecord {
                capture_id: capture_id.clone(),
                action: CollectionAction::UnsafeRetained,
                mutated: false,
                detail: Some("workspace retention binding denied".to_owned()),
            });
            continue;
        }
        let pinned_manifest_digest = bundle
            .sidecar_digest
            .as_deref()
            .unwrap_or(&bundle.base.exact_digest)
            .to_owned();
        let tombstone = RetentionTombstone {
            schema_version: RETENTION_SCHEMA.to_owned(),
            capture_id: capture_id.clone(),
            capture_ref: format!(
                "outctl://capture/{capture_id}/manifest/sha256/{}",
                pinned_manifest_digest.trim_start_matches("sha256:")
            ),
            manifest_digest: pinned_manifest_digest,
            prior_capture_status: normalized_status(
                bundle
                    .delta
                    .as_ref()
                    .map(|delta| delta.capture_status.as_str())
                    .unwrap_or(&bundle.base.capture_status),
            )
            .to_owned(),
            retention_policy: TombstonePolicy {
                reference: policy.reference.clone(),
                digest: policy.digest.clone(),
            },
            expired_at_unix_ms: policy.expired_at_unix_ms,
            reason_key: policy.reason_key.clone(),
            availability: Availability {
                raw: "expired".to_owned(),
                manifest: "retained".to_owned(),
                retrieval: "unavailable".to_owned(),
            },
            compatibility: RetentionCompatibility {
                automatic_rerun: false,
                immutable_manifest_rewritten: false,
            },
        };
        let mut bytes = serde_json::to_vec(&tombstone).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        let retention_digest = sha256_prefixed(&bytes);
        let tombstone_present = match capture.try_open_file(RETENTION_NAME) {
            Ok(Some(_)) => {
                let observed = read_retention(&capture).map_err(|error| error.to_string())?;
                if observed != tombstone {
                    records.push(CollectionRecord {
                        capture_id: capture_id.clone(),
                        action: CollectionAction::UnsafeRetained,
                        mutated: false,
                        detail: Some("existing retention record has different policy".to_owned()),
                    });
                    continue;
                }
                true
            }
            Ok(None) => false,
            Err(error) => {
                records.push(CollectionRecord {
                    capture_id: capture_id.clone(),
                    action: CollectionAction::UnsafeRetained,
                    mutated: false,
                    detail: Some(format!("retention record is unsafe: {error}")),
                });
                continue;
            }
        };
        let expected_receipt = receipt_for(&bundle, &retention_digest)?;
        let expected_receipt_bytes = receipt_bytes(&expected_receipt)?;
        let existing_receipts = match root.try_open_dir(RETENTION_RECEIPTS_DIRECTORY) {
            Ok(receipts) => receipts,
            Err(error) => {
                records.push(CollectionRecord {
                    capture_id: capture_id.clone(),
                    action: CollectionAction::UnsafeRetained,
                    mutated: false,
                    detail: Some(format!("retention receipt directory is unsafe: {error}")),
                });
                continue;
            }
        };
        let receipt_present = match existing_receipts.as_ref() {
            Some(receipts) => match receipts.try_open_file(capture_id) {
                Ok(Some(_)) => match read_retention_receipt(receipts, capture_id) {
                    Ok(receipt) if receipt == expected_receipt => true,
                    Ok(_) => {
                        records.push(CollectionRecord {
                            capture_id: capture_id.clone(),
                            action: CollectionAction::UnsafeRetained,
                            mutated: false,
                            detail: Some(
                                "existing retention receipt binds different evidence".to_owned(),
                            ),
                        });
                        continue;
                    }
                    Err(error) => {
                        records.push(CollectionRecord {
                            capture_id: capture_id.clone(),
                            action: CollectionAction::UnsafeRetained,
                            mutated: false,
                            detail: Some(format!("retention receipt is unsafe: {error}")),
                        });
                        continue;
                    }
                },
                Ok(None) => false,
                Err(error) => {
                    records.push(CollectionRecord {
                        capture_id: capture_id.clone(),
                        action: CollectionAction::UnsafeRetained,
                        mutated: false,
                        detail: Some(format!("retention receipt path is unsafe: {error}")),
                    });
                    continue;
                }
            },
            None => false,
        };
        let mut raw_present = false;
        let mut raw_unsafe = false;
        for name in ["stdout.raw", "stderr.raw", "events.ndjson"] {
            match capture.try_open_file(name) {
                Ok(Some(_)) => raw_present = true,
                Ok(None) => {}
                Err(error) => {
                    records.push(CollectionRecord {
                        capture_id: capture_id.clone(),
                        action: CollectionAction::UnsafeRetained,
                        mutated: false,
                        detail: Some(format!("raw evidence path is unsafe: {error}")),
                    });
                    raw_unsafe = true;
                    break;
                }
            }
        }
        if raw_unsafe {
            continue;
        }
        if !dry_run {
            if !tombstone_present {
                capture
                    .write_atomic_new(RETENTION_NAME, &bytes)
                    .map_err(|error| error.to_string())?;
            }
            if !receipt_present {
                let receipts = root
                    .ensure_dir(RETENTION_RECEIPTS_DIRECTORY)
                    .map_err(|error| error.to_string())?;
                receipts
                    .write_atomic_new(capture_id, &expected_receipt_bytes)
                    .map_err(|error| error.to_string())?;
            }
            for name in ["stdout.raw", "stderr.raw", "events.ndjson"] {
                if let Err(error) = capture.remove_file(name) {
                    if error.kind() != io::ErrorKind::NotFound {
                        return Err(format!("retention unlink failed for {name}: {error}"));
                    }
                }
            }
            capture.sync().map_err(|error| error.to_string())?;
            let mut index = record_from_bundle(&bundle).map_err(|error| error.to_string())?;
            index.capture_status = "expired".to_owned();
            index.retained_bytes = 0;
            index.retention_record_digest = Some(retention_digest);
            store
                .as_ref()
                .expect("mutation has an index store")
                .write(&index)
                .map_err(|error| error.to_string())?;
        }
        records.push(CollectionRecord {
            capture_id: capture_id.clone(),
            action: if tombstone_present && receipt_present {
                CollectionAction::AlreadyExpired
            } else {
                CollectionAction::ExpireRaw
            },
            mutated: !dry_run && (!tombstone_present || !receipt_present || raw_present),
            detail: None,
        });
    }
    Ok(CollectionResult { dry_run, records })
}

pub(crate) fn read_retention(directory: &PrivateDir) -> Result<RetentionTombstone, String> {
    read_retention_with_digest(directory).map(|(record, _)| record)
}

pub(crate) fn read_retention_with_digest(
    directory: &PrivateDir,
) -> Result<(RetentionTombstone, String), String> {
    let bytes = directory
        .read_bounded(RETENTION_NAME, MAX_RETENTION_BYTES)
        .map_err(|error| error.to_string())?;
    let value = parse_unique_json(&bytes).map_err(|error| error.to_string())?;
    let record: RetentionTombstone =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    validate_tombstone(&record)?;
    let digest = sha256_prefixed(&bytes);
    Ok((record, digest))
}

/// Reconcile the capture-local tombstone with its immutable spool-level
/// publication. Neither record is authoritative alone: strict readers require
/// the external receipt to bind the exact tombstone bytes and the immutable
/// capture manifest digest.
pub(crate) fn read_committed_retention(
    root: &PrivateDir,
    capture: &PrivateDir,
    bundle: &ManifestBundle,
) -> Result<Option<RetentionTombstone>, String> {
    let tombstone_present = capture
        .try_open_file(RETENTION_NAME)
        .map_err(|error| format!("retention record path is unsafe: {error}"))?
        .is_some();
    let receipts = root
        .try_open_dir(RETENTION_RECEIPTS_DIRECTORY)
        .map_err(|error| format!("retention receipt directory is unsafe: {error}"))?;
    let receipt_present = match &receipts {
        Some(receipts) => receipts
            .try_open_file(&bundle.base.capture_id)
            .map_err(|error| format!("retention receipt path is unsafe: {error}"))?
            .is_some(),
        None => false,
    };
    match (tombstone_present, receipt_present) {
        (false, false) => return Ok(None),
        (true, false) => return Err("retention tombstone is not externally committed".to_owned()),
        (false, true) => return Err("retention receipt has no capture tombstone".to_owned()),
        (true, true) => {}
    }
    let (tombstone, tombstone_digest) = read_retention_with_digest(capture)?;
    if !retention_binds_bundle(&tombstone, bundle) {
        return Err("retention tombstone does not bind this capture manifest".to_owned());
    }
    let receipt = read_retention_receipt(
        receipts
            .as_ref()
            .expect("receipt presence requires directory"),
        &bundle.base.capture_id,
    )?;
    validate_retention_receipt(&receipt, bundle, &tombstone_digest)?;
    Ok(Some(tombstone))
}

fn receipt_for(
    bundle: &ManifestBundle,
    tombstone_digest: &str,
) -> Result<RetentionReceipt, String> {
    validate_prefixed_digest(tombstone_digest, "retention tombstone digest")
        .map_err(|error| error.to_string())?;
    Ok(RetentionReceipt {
        schema_version: RETENTION_RECEIPT_SCHEMA.to_owned(),
        capture_id: bundle.base.capture_id.clone(),
        manifest_digest: bundle
            .sidecar_digest
            .as_deref()
            .unwrap_or(&bundle.base.exact_digest)
            .to_owned(),
        tombstone_digest: tombstone_digest.to_owned(),
        availability: "expired".to_owned(),
    })
}

fn receipt_bytes(receipt: &RetentionReceipt) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(receipt).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RETENTION_RECEIPT_BYTES {
        return Err("retention receipt exceeds its bounded writer limit".to_owned());
    }
    Ok(bytes)
}

fn read_retention_receipt(
    receipts: &PrivateDir,
    capture_id: &str,
) -> Result<RetentionReceipt, String> {
    let bytes = receipts
        .read_bounded(capture_id, MAX_RETENTION_RECEIPT_BYTES)
        .map_err(|error| error.to_string())?;
    let value = parse_unique_json(&bytes).map_err(|error| error.to_string())?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

fn validate_retention_receipt(
    receipt: &RetentionReceipt,
    bundle: &ManifestBundle,
    tombstone_digest: &str,
) -> Result<(), String> {
    let expected = receipt_for(bundle, tombstone_digest)?;
    if receipt != &expected {
        return Err("retention receipt does not bind exact tombstone bytes".to_owned());
    }
    Ok(())
}

fn validate_request(
    capture_ids: &[String],
    policy: &RetentionPolicy,
    dry_run: bool,
    exclusive_spool: bool,
) -> Result<(), String> {
    if capture_ids.is_empty() || capture_ids.len() > MAX_CAPTURE_IDS {
        return Err(format!(
            "capture ID count must be between 1 and {MAX_CAPTURE_IDS}"
        ));
    }
    if capture_ids.iter().collect::<BTreeSet<_>>().len() != capture_ids.len() {
        return Err("capture IDs must be unique".to_owned());
    }
    for capture_id in capture_ids {
        validate_capture_id(capture_id).map_err(|error| error.to_string())?;
    }
    if !dry_run && !exclusive_spool {
        return Err("retention mutation requires explicit exclusive-spool ownership".to_owned());
    }
    validate_policy_reference(&policy.reference)?;
    validate_prefixed_digest(&policy.digest, "retention policy digest")
        .map_err(|error| error.to_string())?;
    validate_reason_key(&policy.reason_key)?;
    if policy
        .workspace_id
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > 1024)
    {
        return Err("retention workspace binding is invalid".to_owned());
    }
    Ok(())
}

fn validate_tombstone(record: &RetentionTombstone) -> Result<(), String> {
    if record.schema_version != RETENTION_SCHEMA
        || record.availability.raw != "expired"
        || record.availability.manifest != "retained"
        || record.availability.retrieval != "unavailable"
        || record.compatibility.automatic_rerun
        || record.compatibility.immutable_manifest_rewritten
    {
        return Err("retention record has unsupported semantics".to_owned());
    }
    validate_capture_id(&record.capture_id).map_err(|error| error.to_string())?;
    validate_prefixed_digest(&record.manifest_digest, "retention manifest digest")
        .map_err(|error| error.to_string())?;
    validate_prefixed_digest(&record.retention_policy.digest, "retention policy digest")
        .map_err(|error| error.to_string())?;
    if !matches!(
        record.prior_capture_status.as_str(),
        "complete" | "truncated" | "degraded" | "failed" | "recovered-incomplete"
    ) {
        return Err("retention prior capture status is invalid".to_owned());
    }
    validate_policy_reference(&record.retention_policy.reference)?;
    validate_reason_key(&record.reason_key)?;
    let expected_ref = format!(
        "outctl://capture/{}/manifest/sha256/{}",
        record.capture_id,
        record.manifest_digest.trim_start_matches("sha256:")
    );
    if record.capture_ref != expected_ref {
        return Err("retention capture reference does not bind its manifest".to_owned());
    }
    Ok(())
}

fn validate_policy_reference(reference: &str) -> Result<(), String> {
    if reference.is_empty()
        || reference.len() > 2048
        || !reference.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b':'
                        | b'/'
                        | b'?'
                        | b'#'
                        | b'['
                        | b']'
                        | b'@'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b'%'
                )
        })
    {
        return Err("retention policy reference is invalid".to_owned());
    }
    Ok(())
}

fn validate_reason_key(reason_key: &str) -> Result<(), String> {
    if reason_key.is_empty()
        || reason_key.len() > 128
        || !reason_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("retention reason key is invalid".to_owned());
    }
    Ok(())
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
    use super::{collect_captures, CollectionAction, RetentionPolicy, MAX_CAPTURE_IDS};
    use crate::capture::{capture_command, CaptureOptions, CommandEnvironment, CommandStdin};
    use crate::index::{rebuild_index, IndexStore};
    use crate::retrieval::{inspect_capture, slice_stream, RetrievalStatus};
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("outctl-retention-{label}-{nonce}"))
    }

    fn policy() -> RetentionPolicy {
        RetentionPolicy {
            reference: "policy://retention/test".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            expired_at_unix_ms: 1_786_497_600_000,
            reason_key: "explicit-test-expiry".to_owned(),
            workspace_id: Some("workspace-1".to_owned()),
        }
    }

    fn capture(root: &Path) -> String {
        capture_command(
            &CaptureOptions {
                argv: vec![
                    OsString::from("python3"),
                    OsString::from("-c"),
                    OsString::from("print('retained evidence')"),
                ],
                shell_command: None,
                stdin: CommandStdin::Null,
                spool_root: root.to_path_buf(),
                max_bytes: 1024,
                timeout: None,
                cwd: None,
                workspace_id: Some("workspace-1".to_owned()),
                required_capture: false,
                environment: CommandEnvironment::Inherited,
            },
            None,
        )
        .unwrap()
        .capture_id
    }

    #[test]
    fn dry_run_is_exactly_mutation_free_and_mutation_requires_exclusivity() {
        let root = root("dry-run");
        let capture_id = capture(&root);
        let before = tree(&root);
        let result = collect_captures(
            &root,
            std::slice::from_ref(&capture_id),
            &policy(),
            true,
            false,
        )
        .unwrap();
        assert_eq!(result.records[0].action, CollectionAction::ExpireRaw);
        assert!(!result.records[0].mutated);
        assert_eq!(tree(&root), before);
        assert!(collect_captures(
            &root,
            std::slice::from_ref(&capture_id),
            &policy(),
            false,
            false,
        )
        .unwrap_err()
        .contains("exclusive-spool"));
        assert_eq!(tree(&root), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expiration_is_durable_idempotent_and_never_reruns() {
        let root = root("expire");
        let capture_id = capture(&root);
        let capture_path = root.join("captures").join(&capture_id);
        let manifest_before = fs::read(capture_path.join("manifest.json")).unwrap();
        let stdout_before = fs::read(capture_path.join("stdout.raw")).unwrap();
        let result = collect_captures(
            &root,
            std::slice::from_ref(&capture_id),
            &policy(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(result.records[0].action, CollectionAction::ExpireRaw);
        assert!(result.records[0].mutated);
        assert_eq!(
            fs::read(capture_path.join("manifest.json")).unwrap(),
            manifest_before
        );
        assert!(!capture_path.join("stdout.raw").exists());
        assert!(capture_path.join("retention.json").is_file());
        assert_eq!(
            inspect_capture(&root, &capture_id).status,
            RetrievalStatus::Expired
        );
        assert_eq!(
            slice_stream(&root, &capture_id, "stdout", 0, 10, 64)
                .unwrap()
                .status,
            RetrievalStatus::Expired
        );

        let again = collect_captures(
            &root,
            std::slice::from_ref(&capture_id),
            &policy(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(again.records[0].action, CollectionAction::AlreadyExpired);
        assert!(!again.records[0].mutated);

        // Simulate a crash after the durable tombstone was written but before
        // all raw entries were unlinked. A retry completes the mutation and
        // reports that it changed the spool.
        fs::write(capture_path.join("stdout.raw"), stdout_before).unwrap();
        let resumed = collect_captures(
            &root,
            std::slice::from_ref(&capture_id),
            &policy(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(resumed.records[0].action, CollectionAction::AlreadyExpired);
        assert!(resumed.records[0].mutated);
        assert!(!capture_path.join("stdout.raw").exists());
        rebuild_index(&root, 1024).unwrap();
        let rebuilt = IndexStore::ensure(&root)
            .unwrap()
            .read(&capture_id)
            .unwrap();
        assert_eq!(rebuilt.capture_status, "expired");
        assert_eq!(rebuilt.retained_bytes, 0);
        assert!(rebuilt.retention_record_digest.is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_retention_path_and_nonempty_replacement_are_never_deleted() {
        let root = root("attacks");
        fs::create_dir_all(root.join("captures")).unwrap();
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("attacker"), b"keep").unwrap();
        symlink(&outside, root.join("captures/symlinked")).unwrap();
        let result =
            collect_captures(&root, &["symlinked".to_owned()], &policy(), true, false).unwrap();
        assert_eq!(result.records[0].action, CollectionAction::UnsafeRetained);
        assert_eq!(fs::read(outside.join("attacker")).unwrap(), b"keep");

        fs::create_dir(root.join("captures/legacy-empty")).unwrap();
        fs::write(root.join("captures/legacy-empty/attacker"), b"keep").unwrap();
        let result =
            collect_captures(&root, &["legacy-empty".to_owned()], &policy(), false, true).unwrap();
        assert_eq!(result.records[0].action, CollectionAction::UnsafeRetained);
        assert_eq!(
            fs::read(root.join("captures/legacy-empty/attacker")).unwrap(),
            b"keep"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn syntactically_valid_retention_semantic_tampering_is_rejected_everywhere() {
        for (label, needle, replacement, changed_bytes) in [
            (
                "prior-status",
                b"\"prior_capture_status\":\"complete\"".to_vec(),
                b"\"prior_capture_status\":\"degraded\"".to_vec(),
                8,
            ),
            (
                "reason-key",
                b"\"reason_key\":\"explicit-test-expiry\"".to_vec(),
                b"\"reason_key\":\"explicit-test-expirz\"".to_vec(),
                1,
            ),
            (
                "policy-ref",
                b"\"ref\":\"policy://retention/test\"".to_vec(),
                b"\"ref\":\"policy://retention/tess\"".to_vec(),
                1,
            ),
            (
                "policy-digest",
                format!("\"digest\":\"sha256:{}\"", "a".repeat(64)).into_bytes(),
                format!("\"digest\":\"sha256:b{}\"", "a".repeat(63)).into_bytes(),
                1,
            ),
            (
                "expiry",
                b"\"expired_at_unix_ms\":1786497600000".to_vec(),
                b"\"expired_at_unix_ms\":1786497600001".to_vec(),
                1,
            ),
        ] {
            let root = root(label);
            let capture_id = capture(&root);
            collect_captures(
                &root,
                std::slice::from_ref(&capture_id),
                &policy(),
                false,
                true,
            )
            .unwrap();
            let path = root
                .join("captures")
                .join(&capture_id)
                .join("retention.json");
            let mut bytes = fs::read(&path).unwrap();
            assert_eq!(needle.len(), replacement.len());
            let offset = bytes
                .windows(needle.len())
                .position(|window| window == needle)
                .unwrap();
            bytes[offset..offset + needle.len()].copy_from_slice(&replacement);
            assert_eq!(
                bytes[offset..offset + needle.len()]
                    .iter()
                    .zip(&needle)
                    .filter(|(left, right)| left != right)
                    .count(),
                changed_bytes
            );
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
            fs::write(&path, bytes).unwrap();

            assert_eq!(
                inspect_capture(&root, &capture_id).status,
                RetrievalStatus::Tampered,
                "{label}"
            );
            let rebuilt = rebuild_index(&root, 1024).unwrap();
            assert!(rebuilt.records.is_empty(), "{label}");
            assert_eq!(rebuilt.issues.len(), 1, "{label}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn retention_commitment_crash_windows_and_mismatches_fail_closed() {
        // Tombstone durable, receipt not yet published, raw unlink not begun.
        let tombstone_root = root("tombstone-window");
        let capture_id = capture(&tombstone_root);
        let capture_path = tombstone_root.join("captures").join(&capture_id);
        let stdout = fs::read(capture_path.join("stdout.raw")).unwrap();
        collect_captures(
            &tombstone_root,
            std::slice::from_ref(&capture_id),
            &policy(),
            false,
            true,
        )
        .unwrap();
        fs::remove_file(tombstone_root.join("retention-v2").join(&capture_id)).unwrap();
        fs::write(capture_path.join("stdout.raw"), &stdout).unwrap();
        assert_eq!(
            inspect_capture(&tombstone_root, &capture_id).status,
            RetrievalStatus::Tampered
        );
        assert!(rebuild_index(&tombstone_root, 1024)
            .unwrap()
            .records
            .is_empty());
        let resumed = collect_captures(
            &tombstone_root,
            std::slice::from_ref(&capture_id),
            &policy(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(resumed.records[0].action, CollectionAction::ExpireRaw);
        assert!(resumed.records[0].mutated);
        assert!(!capture_path.join("stdout.raw").exists());
        assert_eq!(
            inspect_capture(&tombstone_root, &capture_id).status,
            RetrievalStatus::Expired
        );
        fs::remove_dir_all(tombstone_root).unwrap();

        // Receipt without its exact tombstone is an orphan, never authority.
        let orphan_root = root("orphan-receipt");
        let capture_id = capture(&orphan_root);
        collect_captures(
            &orphan_root,
            std::slice::from_ref(&capture_id),
            &policy(),
            false,
            true,
        )
        .unwrap();
        fs::remove_file(
            orphan_root
                .join("captures")
                .join(&capture_id)
                .join("retention.json"),
        )
        .unwrap();
        assert_eq!(
            inspect_capture(&orphan_root, &capture_id).status,
            RetrievalStatus::Tampered
        );
        assert!(rebuild_index(&orphan_root, 1024)
            .unwrap()
            .records
            .is_empty());
        fs::remove_dir_all(orphan_root).unwrap();

        // A syntactically valid receipt with a one-nibble commitment change is
        // rejected even though the capture-local tombstone is unchanged.
        let root = root("receipt-mismatch");
        let capture_id = capture(&root);
        collect_captures(
            &root,
            std::slice::from_ref(&capture_id),
            &policy(),
            false,
            true,
        )
        .unwrap();
        let receipt_path = root.join("retention-v2").join(&capture_id);
        let mut receipt = fs::read(&receipt_path).unwrap();
        let marker = b"\"tombstone_digest\":\"sha256:";
        let offset = receipt
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap()
            + marker.len();
        receipt[offset] = if receipt[offset] == b'a' { b'b' } else { b'a' };
        serde_json::from_slice::<serde_json::Value>(&receipt).unwrap();
        fs::write(receipt_path, receipt).unwrap();
        assert_eq!(
            inspect_capture(&root, &capture_id).status,
            RetrievalStatus::Tampered
        );
        assert!(rebuild_index(&root, 1024).unwrap().records.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_empty_and_request_count_boundaries_are_explicit() {
        let root = root("legacy");
        fs::create_dir_all(root.join("captures/legacy-empty")).unwrap();
        let result =
            collect_captures(&root, &["legacy-empty".to_owned()], &policy(), false, true).unwrap();
        assert_eq!(
            result.records[0].action,
            CollectionAction::RemoveLegacyEmpty
        );
        assert!(!root.join("captures/legacy-empty").exists());

        let accepted = (0..MAX_CAPTURE_IDS)
            .map(|index| format!("missing-{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            collect_captures(&root, &accepted, &policy(), true, false)
                .unwrap()
                .records
                .len(),
            MAX_CAPTURE_IDS
        );
        let mut rejected = accepted;
        rejected.push("one-too-many".to_owned());
        assert!(collect_captures(&root, &rejected, &policy(), true, false).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn visit(
            root: &std::path::Path,
            path: &std::path::Path,
            out: &mut Vec<(PathBuf, Vec<u8>)>,
        ) {
            let mut entries = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                if entry.file_type().unwrap().is_dir() {
                    out.push((relative.clone(), Vec::new()));
                    visit(root, &path, out);
                } else {
                    out.push((relative, fs::read(path).unwrap()));
                }
            }
        }
        let mut values = Vec::new();
        visit(root, root, &mut values);
        values
    }
}

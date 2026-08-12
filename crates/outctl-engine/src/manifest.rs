use crate::storage::{file_len, PrivateDir};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::io;

pub(crate) const BASE_MANIFEST_NAME: &str = "manifest.json";
pub(crate) const V2_SIDECAR_NAME: &str = "manifest.v2.json";
pub(crate) const V2_PUBLICATION_NAME: &str = "published.v2.json";
pub(crate) const MAX_BASE_MANIFEST_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_V2_SIDECAR_BYTES: u64 = 256 * 1024;
const MAX_V2_PUBLICATION_BYTES: u64 = 16 * 1024;

const V1_SCHEMA: &str = "vuoro.outctl.capture/v1alpha1";
const NATIVE_W3_SCHEMA: &str = "vuoro.outctl.capture-native/w3";
const V2_SCHEMA: &str = "vuoro.outctl.capture-manifest-delta/v2";
const V2_PUBLICATION_SCHEMA: &str = "vuoro.outctl.capture-publication/v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BaseManifestVersion {
    V1Alpha1,
    NativeW3,
    /// The shipped Python reference predates its schema-version field. It is
    /// accepted only through the same required-field checks as v1alpha1.
    UnversionedV1,
}

impl BaseManifestVersion {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::V1Alpha1 | Self::UnversionedV1 => V1_SCHEMA,
            Self::NativeW3 => NATIVE_W3_SCHEMA,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactBinding {
    pub(crate) bytes: u64,
    pub(crate) sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BaseManifest {
    pub(crate) version: BaseManifestVersion,
    pub(crate) capture_id: String,
    pub(crate) capture_status: String,
    pub(crate) workspace_id: Option<String>,
    pub(crate) stdout: Option<ArtifactBinding>,
    pub(crate) stderr: Option<ArtifactBinding>,
    pub(crate) events: Option<ArtifactBinding>,
    pub(crate) event_count: Option<u64>,
    pub(crate) exact_digest: String,
    pub(crate) exact_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineBinding {
    pub(crate) id: String,
    pub(crate) version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyBinding {
    pub(crate) snapshot_id: String,
    #[serde(rename = "ref")]
    pub(crate) reference: String,
    pub(crate) digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatibilityBinding {
    pub(crate) v1_reader: String,
    pub(crate) v1_writer: String,
    pub(crate) v1_stream_bytes_preserved: bool,
    pub(crate) v1_manifest_byte_exact: bool,
    pub(crate) unknown_fields_ignored: bool,
}

impl Default for CompatibilityBinding {
    fn default() -> Self {
        Self {
            v1_reader: "readable".to_owned(),
            v1_writer: "python-reference-only".to_owned(),
            v1_stream_bytes_preserved: true,
            v1_manifest_byte_exact: false,
            unknown_fields_ignored: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryBinding {
    pub(crate) reason_key: String,
    pub(crate) recovered_at_unix_ms: u64,
    pub(crate) command_status_known: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurabilityEvidence {
    pub(crate) artifacts_synced: bool,
    pub(crate) partial_directory_synced: bool,
    pub(crate) atomic_rename: bool,
    pub(crate) capture_parent_synced: bool,
    pub(crate) replica_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StreamBinding {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
    pub(crate) complete: bool,
    pub(crate) last_captured_offset: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StreamBindings {
    pub(crate) stdout: StreamBinding,
    pub(crate) stderr: StreamBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventIndexBinding {
    pub(crate) bytes: u64,
    pub(crate) events: u64,
    pub(crate) sha256: String,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IndexBinding {
    pub(crate) format: String,
    pub(crate) authoritative: bool,
    pub(crate) rebuildable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct V2ManifestDelta {
    pub(crate) schema_version: String,
    pub(crate) base_schema_version: String,
    pub(crate) capture_id: String,
    pub(crate) base_manifest_digest: String,
    pub(crate) engine: EngineBinding,
    pub(crate) request_digest: String,
    pub(crate) policy: PolicyBinding,
    pub(crate) capture_status: String,
    pub(crate) complete: bool,
    pub(crate) streams: StreamBindings,
    pub(crate) event_index: EventIndexBinding,
    pub(crate) recovery: Option<RecoveryBinding>,
    pub(crate) commitment: String,
    pub(crate) durability: String,
    pub(crate) durability_evidence: DurabilityEvidence,
    pub(crate) retention_record_schema: String,
    pub(crate) index: IndexBinding,
    pub(crate) presentation: String,
    pub(crate) compatibility: CompatibilityBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManifestBundle {
    pub(crate) base: BaseManifest,
    pub(crate) delta: Option<V2ManifestDelta>,
    pub(crate) sidecar_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct V2Publication {
    schema_version: String,
    capture_id: String,
    manifest_digest: String,
    durability: String,
    capture_parent_synced: bool,
}

#[derive(Debug)]
pub(crate) enum ManifestError {
    Io(io::Error),
    InvalidJson(String),
    InvalidField(String),
    UnsupportedSchema(String),
    Tampered(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "manifest I/O failed: {error}"),
            Self::InvalidJson(message) => write!(formatter, "manifest JSON is invalid: {message}"),
            Self::InvalidField(message) => {
                write!(formatter, "manifest field is invalid: {message}")
            }
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "manifest schema is unsupported: {schema}")
            }
            Self::Tampered(message) => write!(formatter, "manifest binding failed: {message}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<io::Error> for ManifestError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(crate) fn read_base_manifest(
    directory: &PrivateDir,
    expected_capture_id: Option<&str>,
) -> Result<BaseManifest, ManifestError> {
    let bytes = directory.read_bounded(BASE_MANIFEST_NAME, MAX_BASE_MANIFEST_BYTES)?;
    let mut manifest = parse_base_manifest(bytes, expected_capture_id)?;
    if manifest
        .events
        .as_ref()
        .is_some_and(|events| events.bytes == 0)
    {
        if let Ok(events_file) = directory.open_file("events.ndjson") {
            manifest.events.as_mut().expect("checked above").bytes = file_len(&events_file)?;
        }
    }
    Ok(manifest)
}

pub(crate) fn read_manifest_bundle(
    directory: &PrivateDir,
    expected_capture_id: Option<&str>,
) -> Result<ManifestBundle, ManifestError> {
    let base = read_base_manifest(directory, expected_capture_id)?;
    let sidecar = match directory.try_open_file(V2_SIDECAR_NAME)? {
        None => None,
        Some(_) => Some(directory.read_bounded(V2_SIDECAR_NAME, MAX_V2_SIDECAR_BYTES)?),
    };
    let Some(sidecar_bytes) = sidecar else {
        return Ok(ManifestBundle {
            base,
            delta: None,
            sidecar_digest: None,
        });
    };
    let delta = parse_v2_delta(&sidecar_bytes)?;
    validate_delta_binding(&delta, &base)?;
    Ok(ManifestBundle {
        base,
        delta: Some(delta),
        sidecar_digest: Some(sha256_prefixed(&sidecar_bytes)),
    })
}

/// Read authoritative finalized evidence. A v2 delta is only a prepared
/// durability claim until the exact sidecar digest is bound by a publication
/// record created after the renamed capture's parent directory was synced.
pub(crate) fn read_published_manifest_bundle(
    directory: &PrivateDir,
    expected_capture_id: Option<&str>,
) -> Result<ManifestBundle, ManifestError> {
    let bundle = read_manifest_bundle(directory, expected_capture_id)?;
    if let Some(sidecar_digest) = bundle.sidecar_digest.as_deref() {
        let bytes = directory
            .read_bounded(V2_PUBLICATION_NAME, MAX_V2_PUBLICATION_BYTES)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    ManifestError::Tampered(
                        "v2 capture is prepared but lacks durable publication".to_owned(),
                    )
                } else {
                    ManifestError::Io(error)
                }
            })?;
        let value = parse_unique_json(&bytes)?;
        let publication: V2Publication = serde_json::from_value(value)
            .map_err(|error| ManifestError::InvalidField(error.to_string()))?;
        validate_publication(&publication, &bundle.base.capture_id, sidecar_digest)?;
    }
    Ok(bundle)
}

/// Publish an already-synced and parent-synced v2 capture. The publication
/// entry and containing capture directory are synced by `write_atomic_new`.
pub(crate) fn write_v2_publication(
    directory: &PrivateDir,
    capture_id: &str,
    sidecar_digest: &str,
) -> Result<(), ManifestError> {
    validate_capture_id(capture_id)?;
    validate_prefixed_digest(sidecar_digest, "publication manifest_digest")?;
    let publication = V2Publication {
        schema_version: V2_PUBLICATION_SCHEMA.to_owned(),
        capture_id: capture_id.to_owned(),
        manifest_digest: sidecar_digest.to_owned(),
        durability: "host".to_owned(),
        capture_parent_synced: true,
    };
    let mut bytes = serde_json::to_vec(&publication)
        .map_err(|error| ManifestError::InvalidJson(error.to_string()))?;
    bytes.push(b'\n');
    directory.write_atomic_new(V2_PUBLICATION_NAME, &bytes)?;
    Ok(())
}

fn validate_publication(
    publication: &V2Publication,
    capture_id: &str,
    sidecar_digest: &str,
) -> Result<(), ManifestError> {
    if publication.schema_version != V2_PUBLICATION_SCHEMA
        || publication.capture_id != capture_id
        || publication.manifest_digest != sidecar_digest
        || publication.durability != "host"
        || !publication.capture_parent_synced
    {
        return Err(ManifestError::Tampered(
            "v2 publication does not bind the durable capture".to_owned(),
        ));
    }
    validate_prefixed_digest(&publication.manifest_digest, "publication manifest_digest")?;
    Ok(())
}

/// Add the v2 metadata sidecar without rewriting the one-version-back base.
/// Returns the digest of the exact sidecar bytes written.
pub(crate) fn write_v2_sidecar(
    directory: &PrivateDir,
    delta: &V2ManifestDelta,
) -> Result<String, ManifestError> {
    let base = read_base_manifest(directory, Some(&delta.capture_id))?;
    validate_delta_binding(delta, &base)?;
    let mut bytes =
        serde_json::to_vec(delta).map_err(|error| ManifestError::InvalidJson(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_V2_SIDECAR_BYTES {
        return Err(ManifestError::InvalidField(
            "v2 sidecar exceeds bounded writer limit".to_owned(),
        ));
    }
    directory.write_atomic_new(V2_SIDECAR_NAME, &bytes)?;
    Ok(sha256_prefixed(&bytes))
}

fn parse_base_manifest(
    bytes: Vec<u8>,
    expected_capture_id: Option<&str>,
) -> Result<BaseManifest, ManifestError> {
    let value = parse_unique_json(&bytes)?;
    let object = value
        .as_object()
        .ok_or_else(|| ManifestError::InvalidField("base must be an object".to_owned()))?;
    let version = match object.get("schema_version") {
        Some(Value::String(schema)) if schema == V1_SCHEMA => BaseManifestVersion::V1Alpha1,
        Some(Value::String(schema)) if schema == NATIVE_W3_SCHEMA => BaseManifestVersion::NativeW3,
        Some(Value::String(schema)) => {
            return Err(ManifestError::UnsupportedSchema(schema.clone()))
        }
        Some(_) => {
            return Err(ManifestError::InvalidField(
                "schema_version must be a string".to_owned(),
            ))
        }
        None => BaseManifestVersion::UnversionedV1,
    };
    let capture_id = required_string(object, "capture_id")?;
    validate_capture_id(&capture_id)?;
    if expected_capture_id.is_some_and(|expected| expected != capture_id) {
        return Err(ManifestError::Tampered(
            "capture ID does not match its directory entry".to_owned(),
        ));
    }
    let capture_status = object
        .get("capture_status")
        .and_then(Value::as_str)
        .or_else(|| {
            object
                .get("capture")
                .and_then(Value::as_object)
                .and_then(|capture| capture.get("status"))
                .and_then(Value::as_str)
        })
        .ok_or_else(|| ManifestError::InvalidField("capture status is missing".to_owned()))?
        .to_owned();
    validate_capture_status(&capture_status)?;
    let workspace_id = object
        .get("source")
        .and_then(Value::as_object)
        .and_then(|source| source.get("workspace_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let streams = object.get("streams").and_then(Value::as_object);
    let stdout = artifact(
        streams.and_then(|streams| streams.get("stdout")),
        "stdout",
        true,
    )?;
    let stderr = artifact(
        streams.and_then(|streams| streams.get("stderr")),
        "stderr",
        true,
    )?;
    let events = artifact(object.get("event_index"), "event_index", false)?;
    let event_count = object
        .get("event_index")
        .and_then(Value::as_object)
        .and_then(|events| events.get("events"))
        .and_then(Value::as_u64);
    let incomplete = is_incomplete_status(&capture_status);
    if !incomplete && (stdout.is_none() || stderr.is_none() || events.is_none()) {
        return Err(ManifestError::InvalidField(
            "finalized base manifest is missing artifact bindings".to_owned(),
        ));
    }
    let exact_digest = sha256_prefixed(&bytes);
    Ok(BaseManifest {
        version,
        capture_id,
        capture_status,
        workspace_id,
        stdout,
        stderr,
        events,
        event_count,
        exact_digest,
        exact_bytes: bytes,
    })
}

fn artifact(
    value: Option<&Value>,
    label: &str,
    require_bytes: bool,
) -> Result<Option<ArtifactBinding>, ManifestError> {
    let Some(object) = value.and_then(Value::as_object) else {
        return Ok(None);
    };
    let bytes = match object.get("bytes").and_then(Value::as_u64) {
        Some(bytes) => bytes,
        None if !require_bytes && object.get("events").and_then(Value::as_u64).is_some() => 0,
        None => {
            return Err(ManifestError::InvalidField(format!(
                "{label}.bytes is missing or invalid"
            )))
        }
    };
    let sha256 = match object.get("sha256") {
        Some(Value::String(value)) => {
            validate_unprefixed_digest(value, &format!("{label}.sha256"))?;
            Some(value.clone())
        }
        Some(Value::Null) | None => None,
        Some(_) => {
            return Err(ManifestError::InvalidField(format!(
                "{label}.sha256 is invalid"
            )))
        }
    };
    Ok(Some(ArtifactBinding { bytes, sha256 }))
}

fn parse_v2_delta(bytes: &[u8]) -> Result<V2ManifestDelta, ManifestError> {
    let value = parse_unique_json(bytes)?;
    let delta: V2ManifestDelta = serde_json::from_value(value)
        .map_err(|error| ManifestError::InvalidField(error.to_string()))?;
    validate_delta(&delta)?;
    Ok(delta)
}

fn validate_delta_binding(
    delta: &V2ManifestDelta,
    base: &BaseManifest,
) -> Result<(), ManifestError> {
    validate_delta(delta)?;
    if delta.capture_id != base.capture_id {
        return Err(ManifestError::Tampered(
            "v2 sidecar capture ID differs from base".to_owned(),
        ));
    }
    if delta.base_manifest_digest != base.exact_digest {
        return Err(ManifestError::Tampered(
            "v2 sidecar base-manifest digest differs from exact bytes".to_owned(),
        ));
    }
    if delta.base_schema_version != base.version.as_str() {
        return Err(ManifestError::Tampered(
            "v2 sidecar base schema differs from the parsed base".to_owned(),
        ));
    }
    let status_matches = if base.capture_status == "CAPTURE_FAILED" {
        matches!(delta.capture_status.as_str(), "degraded" | "failed")
    } else {
        delta.capture_status == normalized_capture_status(&base.capture_status)
    };
    if !status_matches {
        return Err(ManifestError::Tampered(
            "v2 sidecar capture status differs from base".to_owned(),
        ));
    }
    for (label, delta_stream, base_stream) in [
        ("stdout", &delta.streams.stdout, base.stdout.as_ref()),
        ("stderr", &delta.streams.stderr, base.stderr.as_ref()),
    ] {
        let Some(base_stream) = base_stream else {
            if delta.capture_status != "recovered-incomplete" {
                return Err(ManifestError::Tampered(format!(
                    "{label} binding is absent from base"
                )));
            }
            continue;
        };
        if delta_stream.bytes != base_stream.bytes
            || delta_stream.last_captured_offset != base_stream.bytes
            || base_stream
                .sha256
                .as_ref()
                .is_some_and(|digest| delta_stream.sha256 != format!("sha256:{digest}"))
        {
            return Err(ManifestError::Tampered(format!(
                "{label} sidecar binding differs from base"
            )));
        }
    }
    if let Some(events) = &base.events {
        if (events.bytes != 0 && delta.event_index.bytes != events.bytes)
            || events
                .sha256
                .as_ref()
                .is_some_and(|digest| delta.event_index.sha256 != format!("sha256:{digest}"))
        {
            return Err(ManifestError::Tampered(
                "event-index sidecar binding differs from base".to_owned(),
            ));
        }
    }
    if base
        .event_count
        .is_some_and(|events| delta.event_index.events != events)
    {
        return Err(ManifestError::Tampered(
            "event count differs from base".to_owned(),
        ));
    }
    Ok(())
}

fn validate_delta(delta: &V2ManifestDelta) -> Result<(), ManifestError> {
    if delta.schema_version != V2_SCHEMA {
        return Err(ManifestError::UnsupportedSchema(
            delta.schema_version.clone(),
        ));
    }
    if !matches!(
        delta.base_schema_version.as_str(),
        V1_SCHEMA | NATIVE_W3_SCHEMA
    ) {
        return Err(ManifestError::UnsupportedSchema(
            delta.base_schema_version.clone(),
        ));
    }
    validate_capture_id(&delta.capture_id)?;
    if !matches!(
        delta.capture_status.as_str(),
        "complete" | "truncated" | "degraded" | "failed" | "recovered-incomplete"
    ) {
        return Err(ManifestError::InvalidField(
            "v2 capture status is not recognized".to_owned(),
        ));
    }
    for (label, value) in [
        ("base_manifest_digest", delta.base_manifest_digest.as_str()),
        ("request_digest", delta.request_digest.as_str()),
        ("policy.digest", delta.policy.digest.as_str()),
        (
            "streams.stdout.sha256",
            delta.streams.stdout.sha256.as_str(),
        ),
        (
            "streams.stderr.sha256",
            delta.streams.stderr.sha256.as_str(),
        ),
        ("event_index.sha256", delta.event_index.sha256.as_str()),
    ] {
        validate_prefixed_digest(value, label)?;
    }
    for (label, value) in [
        ("engine.id", delta.engine.id.as_str()),
        ("engine.version", delta.engine.version.as_str()),
        ("policy.snapshot_id", delta.policy.snapshot_id.as_str()),
        ("policy.ref", delta.policy.reference.as_str()),
    ] {
        if value.is_empty() || value.len() > 1024 {
            return Err(ManifestError::InvalidField(format!(
                "{label} is empty or oversized"
            )));
        }
    }
    let incomplete_status = delta.capture_status == "recovered-incomplete";
    if delta.complete != (delta.capture_status == "complete") {
        return Err(ManifestError::InvalidField(
            "complete flag contradicts capture_status".to_owned(),
        ));
    }
    match (&delta.recovery, incomplete_status) {
        (Some(recovery), true)
            if !recovery.command_status_known
                && !recovery.reason_key.is_empty()
                && recovery.reason_key.len() <= 128 => {}
        (None, false) => {}
        _ => {
            return Err(ManifestError::InvalidField(
                "recovery marker contradicts capture state".to_owned(),
            ))
        }
    }
    let durability_valid = matches!(
        (delta.commitment.as_str(), delta.durability.as_str()),
        ("host-persistent", "host") | ("replicated", "replica" | "authoritative")
    );
    if !durability_valid {
        return Err(ManifestError::InvalidField(
            "commitment and durability contradict".to_owned(),
        ));
    }
    let evidence = &delta.durability_evidence;
    let locally_durable = evidence.artifacts_synced
        && evidence.partial_directory_synced
        && evidence.atomic_rename
        && evidence.capture_parent_synced;
    if !locally_durable
        || (delta.commitment == "host-persistent" && evidence.replica_verified)
        || (delta.commitment == "replicated" && !evidence.replica_verified)
    {
        return Err(ManifestError::InvalidField(
            "durability evidence contradicts commitment".to_owned(),
        ));
    }
    for (label, stream) in [
        ("stdout", &delta.streams.stdout),
        ("stderr", &delta.streams.stderr),
    ] {
        if stream.last_captured_offset != stream.bytes {
            return Err(ManifestError::InvalidField(format!(
                "{label}.last_captured_offset differs from retained bytes"
            )));
        }
    }
    let all_complete = delta.streams.stdout.complete
        && delta.streams.stderr.complete
        && delta.event_index.complete;
    if delta.complete && !all_complete {
        return Err(ManifestError::InvalidField(
            "artifact completeness contradicts capture completeness".to_owned(),
        ));
    }
    if delta.retention_record_schema != "vuoro.outctl.capture-retention-tombstone/v2" {
        return Err(ManifestError::UnsupportedSchema(
            delta.retention_record_schema.clone(),
        ));
    }
    if delta.index.format != "v2" || delta.index.authoritative || !delta.index.rebuildable {
        return Err(ManifestError::InvalidField(
            "index must be v2, non-authoritative, and rebuildable".to_owned(),
        ));
    }
    if !matches!(
        delta.presentation.as_str(),
        "empty-success"
            | "empty-command-failure"
            | "raw-safe"
            | "bounded-projection"
            | "metadata-only"
            | "denied"
    ) {
        return Err(ManifestError::InvalidField(
            "presentation is not recognized".to_owned(),
        ));
    }
    if delta.compatibility != CompatibilityBinding::default() {
        return Err(ManifestError::InvalidField(
            "compatibility claims differ from the frozen v1 stance".to_owned(),
        ));
    }
    Ok(())
}

fn validate_capture_status(value: &str) -> Result<(), ManifestError> {
    if matches!(
        value,
        "COMPLETE"
            | "TRUNCATED"
            | "CAPTURE_FAILED"
            | "INCOMPLETE"
            | "RECOVERED_INCOMPLETE"
            | "complete"
            | "truncated"
            | "degraded"
            | "failed"
            | "recovered-incomplete"
    ) {
        Ok(())
    } else {
        Err(ManifestError::InvalidField(
            "capture status is not recognized".to_owned(),
        ))
    }
}

fn is_incomplete_status(value: &str) -> bool {
    matches!(
        value,
        "INCOMPLETE" | "RECOVERED_INCOMPLETE" | "recovered-incomplete"
    )
}

fn normalized_capture_status(value: &str) -> &str {
    match value {
        "COMPLETE" => "complete",
        "TRUNCATED" => "truncated",
        "CAPTURE_FAILED" => "failed",
        "INCOMPLETE" | "RECOVERED_INCOMPLETE" => "recovered-incomplete",
        other => other,
    }
}

fn required_string(object: &Map<String, Value>, name: &str) -> Result<String, ManifestError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ManifestError::InvalidField(format!("{name} is missing or invalid")))
}

pub(crate) fn validate_capture_id(value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ManifestError::InvalidField(
            "capture_id is not a safe bounded entry name".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_prefixed_digest(value: &str, label: &str) -> Result<(), ManifestError> {
    let Some(value) = value.strip_prefix("sha256:") else {
        return Err(ManifestError::InvalidField(format!(
            "{label} is not a sha256 digest"
        )));
    };
    validate_unprefixed_digest(value, label)
}

fn validate_unprefixed_digest(value: &str, label: &str) -> Result<(), ManifestError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ManifestError::InvalidField(format!(
            "{label} is not a lowercase sha256 digest"
        )));
    }
    Ok(())
}

pub(crate) fn parse_unique_json(bytes: &[u8]) -> Result<Value, ManifestError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|error| ManifestError::InvalidJson(error.to_string()))?
        .0;
    deserializer
        .end()
        .map_err(|error| ManifestError::InvalidJson(error.to_string()))?;
    Ok(value)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate object key: {key}")));
            }
            values.insert(key, map.next_value::<UniqueValue>()?.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        read_manifest_bundle, read_published_manifest_bundle, sha256_prefixed,
        write_v2_publication, write_v2_sidecar, CompatibilityBinding, DurabilityEvidence,
        EngineBinding, EventIndexBinding, IndexBinding, ManifestError, PolicyBinding,
        StreamBinding, StreamBindings, V2ManifestDelta, MAX_BASE_MANIFEST_BYTES,
    };
    use crate::storage::PrivateDir;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("outctl-manifest-{label}-{nonce}"))
    }

    fn base_bytes(capture_id: &str, schema: Option<&str>) -> Vec<u8> {
        let schema = schema
            .map(|value| format!(r#""schema_version":"{value}","#))
            .unwrap_or_default();
        format!(
            r#"{{{schema}"capture_id":"{capture_id}","capture_status":"COMPLETE","source":{{"workspace_id":"workspace-1"}},"streams":{{"stdout":{{"bytes":1,"sha256":"{}"}},"stderr":{{"bytes":0,"sha256":"{}"}}}},"event_index":{{"events":0,"sha256":"{}"}}}}
"#,
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
        )
        .into_bytes()
    }

    fn delta(capture_id: &str, base: &[u8], base_schema: &str) -> V2ManifestDelta {
        V2ManifestDelta {
            schema_version: "vuoro.outctl.capture-manifest-delta/v2".to_owned(),
            base_schema_version: base_schema.to_owned(),
            capture_id: capture_id.to_owned(),
            base_manifest_digest: sha256_prefixed(base),
            engine: EngineBinding {
                id: "rust-w7".to_owned(),
                version: "0.1.0".to_owned(),
            },
            request_digest: format!("sha256:{}", "d".repeat(64)),
            policy: PolicyBinding {
                snapshot_id: "snapshot-1".to_owned(),
                reference: "policy://one".to_owned(),
                digest: format!("sha256:{}", "e".repeat(64)),
            },
            capture_status: "complete".to_owned(),
            complete: true,
            streams: StreamBindings {
                stdout: StreamBinding {
                    bytes: 1,
                    sha256: format!("sha256:{}", "a".repeat(64)),
                    complete: true,
                    last_captured_offset: 1,
                },
                stderr: StreamBinding {
                    bytes: 0,
                    sha256: format!("sha256:{}", "b".repeat(64)),
                    complete: true,
                    last_captured_offset: 0,
                },
            },
            event_index: EventIndexBinding {
                bytes: 0,
                events: 0,
                sha256: format!("sha256:{}", "c".repeat(64)),
                complete: true,
            },
            commitment: "host-persistent".to_owned(),
            durability: "host".to_owned(),
            durability_evidence: DurabilityEvidence {
                artifacts_synced: true,
                partial_directory_synced: true,
                atomic_rename: true,
                capture_parent_synced: true,
                replica_verified: false,
            },
            presentation: "empty-success".to_owned(),
            recovery: None,
            retention_record_schema: "vuoro.outctl.capture-retention-tombstone/v2".to_owned(),
            index: IndexBinding {
                format: "v2".to_owned(),
                authoritative: false,
                rebuildable: true,
            },
            compatibility: CompatibilityBinding::default(),
        }
    }

    #[test]
    fn reads_v1_native_and_unversioned_one_back_manifests() {
        for (label, schema) in [
            ("v1", Some("vuoro.outctl.capture/v1alpha1")),
            ("native", Some("vuoro.outctl.capture-native/w3")),
            ("unversioned", None),
        ] {
            let root = temporary_root(label);
            let directory = PrivateDir::ensure(&root).unwrap();
            directory
                .write_new("manifest.json", &base_bytes("capture-1", schema))
                .unwrap();
            directory.write_new("events.ndjson", b"").unwrap();
            let bundle = read_manifest_bundle(&directory, Some("capture-1")).unwrap();
            assert_eq!(bundle.base.capture_id, "capture-1");
            assert_eq!(bundle.base.workspace_id.as_deref(), Some("workspace-1"));
            assert!(bundle.delta.is_none());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn sidecar_is_additive_exactly_bound_and_never_rewritten() {
        let root = temporary_root("sidecar");
        let directory = PrivateDir::ensure(&root).unwrap();
        let base = base_bytes("capture-1", Some("vuoro.outctl.capture-native/w3"));
        directory.write_new("manifest.json", &base).unwrap();
        directory.write_new("events.ndjson", b"").unwrap();
        let sidecar = delta("capture-1", &base, "vuoro.outctl.capture-native/w3");
        let expected_base = fs::read(root.join("manifest.json")).unwrap();
        let sidecar_digest = write_v2_sidecar(&directory, &sidecar).unwrap();
        assert_eq!(fs::read(root.join("manifest.json")).unwrap(), expected_base);
        let bundle = read_manifest_bundle(&directory, Some("capture-1")).unwrap();
        assert_eq!(
            bundle.sidecar_digest.as_deref(),
            Some(sidecar_digest.as_str())
        );
        assert!(write_v2_sidecar(&directory, &sidecar).is_err());
        assert_eq!(fs::read(root.join("manifest.json")).unwrap(), expected_base);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v2_publication_is_required_and_exactly_binds_the_sidecar() {
        let root = temporary_root("publication");
        let directory = PrivateDir::ensure(&root).unwrap();
        let base = base_bytes("capture-1", Some("vuoro.outctl.capture-native/w3"));
        directory.write_new("manifest.json", &base).unwrap();
        directory.write_new("events.ndjson", b"").unwrap();
        let sidecar = delta("capture-1", &base, "vuoro.outctl.capture-native/w3");
        let sidecar_digest = write_v2_sidecar(&directory, &sidecar).unwrap();
        assert!(matches!(
            read_published_manifest_bundle(&directory, Some("capture-1")),
            Err(ManifestError::Tampered(_))
        ));
        write_v2_publication(&directory, "capture-1", &sidecar_digest).unwrap();
        assert!(read_published_manifest_bundle(&directory, Some("capture-1")).is_ok());

        let path = root.join("published.v2.json");
        let mut bytes = fs::read(&path).unwrap();
        let digest_offset = bytes
            .windows(sidecar_digest.len())
            .position(|window| window == sidecar_digest.as_bytes())
            .unwrap();
        let byte = &mut bytes[digest_offset + "sha256:".len()];
        *byte = if *byte == b'a' { b'b' } else { b'a' };
        fs::write(path, bytes).unwrap();
        assert!(matches!(
            read_published_manifest_bundle(&directory, Some("capture-1")),
            Err(ManifestError::Tampered(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_keys_changed_base_and_unknown_sidecar_fields_fail_closed() {
        let root = temporary_root("duplicate");
        let directory = PrivateDir::ensure(&root).unwrap();
        directory
            .write_new(
                "manifest.json",
                br#"{"capture_id":"one","capture_id":"two","capture_status":"COMPLETE"}"#,
            )
            .unwrap();
        assert!(matches!(
            read_manifest_bundle(&directory, None),
            Err(ManifestError::InvalidJson(_))
        ));
        fs::remove_dir_all(root).unwrap();

        let root = temporary_root("changed");
        let directory = PrivateDir::ensure(&root).unwrap();
        let base = base_bytes("capture-1", Some("vuoro.outctl.capture-native/w3"));
        directory.write_new("manifest.json", &base).unwrap();
        directory.write_new("events.ndjson", b"").unwrap();
        let mut wrong = delta("capture-1", &base, "vuoro.outctl.capture-native/w3");
        wrong.base_manifest_digest = format!("sha256:{}", "f".repeat(64));
        assert!(matches!(
            write_v2_sidecar(&directory, &wrong),
            Err(ManifestError::Tampered(_))
        ));
        assert!(!root.join("manifest.v2.json").exists());

        let mut value =
            serde_json::to_value(delta("capture-1", &base, "vuoro.outctl.capture-native/w3"))
                .unwrap();
        value["unexpected"] = serde_json::json!(true);
        directory
            .write_new("manifest.v2.json", &serde_json::to_vec(&value).unwrap())
            .unwrap();
        assert!(matches!(
            read_manifest_bundle(&directory, Some("capture-1")),
            Err(ManifestError::InvalidField(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn base_reader_rejects_limit_plus_one() {
        let root = temporary_root("oversized");
        let directory = PrivateDir::ensure(&root).unwrap();
        directory
            .write_new(
                "manifest.json",
                &vec![b' '; MAX_BASE_MANIFEST_BYTES as usize + 1],
            )
            .unwrap();
        assert!(matches!(
            read_manifest_bundle(&directory, None),
            Err(ManifestError::Io(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }
}

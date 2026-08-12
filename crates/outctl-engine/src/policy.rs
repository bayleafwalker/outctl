//! Native evaluation of pinned W5 policy snapshots.
//!
//! The Python control plane compiles policy and commissioning evidence.  This
//! module only verifies the resulting immutable snapshot, binds it to a
//! request and selects a sink action.  It deliberately has no operation that
//! can authorize command execution.

use crate::capture::{
    capture_command_with_presentation, CaptureError, CaptureOptions, CaptureResult,
    CommandEnvironment, CommandStdin, ProtectedStdinValue, MAX_STDIN_BYTES,
};
use crate::presentation::{PersistenceMode, PresentationMode, PresentationOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

const SNAPSHOT_SCHEMA: &str = "vuoro.outctl.policy-snapshot/v2";
const REQUEST_SCHEMA: &str = "vuoro.outctl.run-request/v2";
const DIGEST_PREFIX: &str = "sha256:";
const MAX_SECRET_REFS: usize = 64;
const MAX_POLICY_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_REGISTERED_SECRET_BYTES: usize = 256 * 1024;
const MAX_REGISTERED_SECRET_VALUE_BYTES: usize = 64 * 1024;
const MAX_STDIN_REFS: usize = 16;
const MAX_REGISTERED_STDIN_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidDocument(String),
    BindingMismatch(String),
    ContextMismatch(String),
    Expired,
    SinkDenied,
    Unsupported(String),
    SecretUnavailable(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDocument(message) => {
                write!(formatter, "invalid policy document: {message}")
            }
            Self::BindingMismatch(message) => {
                write!(formatter, "policy binding mismatch: {message}")
            }
            Self::ContextMismatch(message) => {
                write!(formatter, "policy context mismatch: {message}")
            }
            Self::Expired => write!(formatter, "policy snapshot is not currently valid"),
            Self::SinkDenied => write!(formatter, "policy denies the requested sink"),
            Self::Unsupported(message) => write!(formatter, "unsupported policy: {message}"),
            Self::SecretUnavailable(reference) => {
                write!(
                    formatter,
                    "protected secret reference is unavailable: {reference}"
                )
            }
        }
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug)]
pub enum PolicyCaptureError {
    MissingExecutionAuthority,
    Policy(PolicyError),
    Capture(CaptureError),
}

impl std::fmt::Display for PolicyCaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingExecutionAuthority => {
                write!(formatter, "external runner did not authorize execution")
            }
            Self::Policy(error) => error.fmt(formatter),
            Self::Capture(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PolicyCaptureError {}

impl From<PolicyError> for PolicyCaptureError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<CaptureError> for PolicyCaptureError {
    fn from(error: CaptureError) -> Self {
        Self::Capture(error)
    }
}

/// Exact values are accepted only through this in-memory API.
///
/// The registry has no serialization implementation and its debug output
/// reports only bounded counts. Values are overwritten when the registry is
/// dropped. Opaque references are safe provenance; exact values are not.
pub struct ProtectedSecretRegistry {
    values: BTreeMap<String, Vec<u8>>,
    total_bytes: usize,
}

impl ProtectedSecretRegistry {
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    pub fn register(&mut self, reference: String, value: Vec<u8>) -> Result<(), PolicyError> {
        if !valid_secret_ref(&reference) {
            return Err(PolicyError::InvalidDocument(
                "secret reference must use the bounded secret:// grammar".to_owned(),
            ));
        }
        if value.is_empty() || value.len() > MAX_REGISTERED_SECRET_VALUE_BYTES {
            return Err(PolicyError::InvalidDocument(
                "protected secret value has an invalid size".to_owned(),
            ));
        }
        if self.values.contains_key(&reference) {
            return Err(PolicyError::InvalidDocument(
                "protected secret reference is already registered".to_owned(),
            ));
        }
        if self.values.len() >= MAX_SECRET_REFS
            || self
                .total_bytes
                .checked_add(value.len())
                .is_none_or(|total| total > MAX_REGISTERED_SECRET_BYTES)
        {
            return Err(PolicyError::InvalidDocument(
                "protected secret registry exceeds its bounded capacity".to_owned(),
            ));
        }
        self.total_bytes += value.len();
        self.values.insert(reference, value);
        Ok(())
    }

    fn resolve(&self, references: &[String]) -> Result<Vec<Vec<u8>>, PolicyError> {
        references
            .iter()
            .map(|reference| {
                self.values
                    .get(reference)
                    .cloned()
                    .ok_or_else(|| PolicyError::SecretUnavailable(reference.clone()))
            })
            .collect()
    }

    fn ensure_registered(&self, references: &[String]) -> Result<(), PolicyError> {
        for reference in references {
            if !self.values.contains_key(reference) {
                return Err(PolicyError::SecretUnavailable(reference.clone()));
            }
        }
        Ok(())
    }
}

impl Default for ProtectedSecretRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ProtectedSecretRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedSecretRegistry")
            .field("reference_count", &self.values.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

impl Drop for ProtectedSecretRegistry {
    fn drop(&mut self) {
        for value in self.values.values_mut() {
            value.fill(0);
        }
    }
}

/// Bounded runner-owned stdin values addressed by opaque request references.
///
/// Values never enter JSON policy/request documents or debug output. The
/// embedding runner resolves any path or stream before registration, so the
/// engine never turns an opaque reference into an arbitrary file read.
pub struct ProtectedStdinRegistry {
    values: BTreeMap<String, Arc<ProtectedStdinValue>>,
    total_bytes: usize,
}

impl ProtectedStdinRegistry {
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    pub fn register(&mut self, reference: String, value: Vec<u8>) -> Result<(), PolicyError> {
        if !valid_stdin_ref(&reference) {
            return Err(PolicyError::InvalidDocument(
                "stdin reference must use the bounded outctl://stdin/ grammar".to_owned(),
            ));
        }
        if value.len() > MAX_STDIN_BYTES {
            return Err(PolicyError::InvalidDocument(
                "registered stdin exceeds the per-value byte limit".to_owned(),
            ));
        }
        if self.values.contains_key(&reference) {
            return Err(PolicyError::InvalidDocument(
                "stdin reference is already registered".to_owned(),
            ));
        }
        if self.values.len() >= MAX_STDIN_REFS
            || self
                .total_bytes
                .checked_add(value.len())
                .is_none_or(|total| total > MAX_REGISTERED_STDIN_BYTES)
        {
            return Err(PolicyError::InvalidDocument(
                "stdin registry exceeds its bounded capacity".to_owned(),
            ));
        }
        self.total_bytes += value.len();
        self.values
            .insert(reference, Arc::new(ProtectedStdinValue::new(value)));
        Ok(())
    }

    fn resolve(&self, reference: &str) -> Result<Arc<ProtectedStdinValue>, PolicyError> {
        self.values
            .get(reference)
            .cloned()
            .ok_or_else(|| PolicyError::Unsupported("registered stdin is unavailable".to_owned()))
    }
}

impl Default for ProtectedStdinRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ProtectedStdinRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedStdinRegistry")
            .field("reference_count", &self.values.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

impl Drop for ProtectedStdinRegistry {
    fn drop(&mut self) {
        self.values.clear();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SinkAction {
    SafeUnredacted,
    Sanitized,
    MetadataOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClaimProvenance {
    pub snapshot_id: String,
    pub policy_ref: String,
    pub policy_digest: String,
    pub source_ref: String,
    pub source_digest: String,
    pub session_id: String,
    pub sink: String,
    pub action: SinkAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationContext {
    pub workspace_id: String,
    pub session_id: String,
    /// Runner-supplied lexical workspace boundary for request cwd validation.
    pub workspace_root: PathBuf,
    pub now_unix_millis: i64,
}

/// A sink decision plus enforced capture/presentation configuration.
///
/// This value is intentionally not serializable because sanitized decisions
/// may contain protected exact-match material inside `presentation`.
pub struct EvaluatedPolicy {
    pub action: SinkAction,
    pub capture_required: bool,
    pub presentation: PresentationOptions,
    pub provenance: ClaimProvenance,
}

/// Inputs owned by an already-authorized external runner.
///
/// `runner_authorized` is an assertion from the execution authority, not a
/// value produced or widened by policy. False always rejects before spool
/// creation or command spawn.
pub struct PolicyCaptureOptions<'a> {
    pub snapshot_json: &'a [u8],
    pub request_json: &'a [u8],
    pub context: &'a EvaluationContext,
    pub secrets: &'a ProtectedSecretRegistry,
    pub stdin: &'a ProtectedStdinRegistry,
    pub spool_root: PathBuf,
    pub max_capture_bytes: u64,
    pub runner_authorized: bool,
}

pub struct PolicyCaptureResult {
    pub capture: CaptureResult,
    pub policy_metadata: Value,
}

impl std::fmt::Debug for EvaluatedPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvaluatedPolicy")
            .field("action", &self.action)
            .field("capture_required", &self.capture_required)
            .field("presentation", &self.presentation)
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl EvaluatedPolicy {
    /// Raw-free metadata suitable for receipts and diagnostics.
    pub fn metadata(&self) -> Value {
        json!({
            "action": self.action,
            "capture_required": self.capture_required,
            "persistence": self.presentation.persistence.as_str(),
            "presentation": self.presentation.mode.as_str(),
            "provenance": self.provenance,
            "execution_authorized": false,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: String,
    snapshot_id: String,
    policy_ref: String,
    policy_digest: String,
    source: Source,
    cache: Cache,
    session: Session,
    sinks: Vec<Sink>,
    capture: Capture,
    command_scope: CommandScope,
    execution_authority: ExecutionAuthority,
    issued_at: String,
    expires_at: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Source {
    r#ref: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    key: String,
    snapshot_id: String,
    owner: String,
    max_age_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Session {
    session_id: String,
    trust_domain: String,
    commissioned: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sink {
    name: String,
    trust_domain: String,
    disclosure: String,
    redaction_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification_ceiling: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    commitment: String,
    durability: String,
    required: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionAuthority {
    owner: String,
    can_authorize_execution: bool,
    can_retry: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommandScope {
    execution_modes: Vec<String>,
    explicit_shell_argv: Vec<Vec<String>>,
    stdin_modes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: String,
    request_id: String,
    command: Command,
    policy: RequestPolicy,
    sink: RequestSink,
    secret_channel: SecretChannel,
    bindings: Bindings,
}

/// Decode an explicitly present value or null without giving the field serde's
/// normal `Option<T>` missing-field default.
fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    argv: Vec<String>,
    execution_mode: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    shell_command: Option<String>,
    cwd: String,
    environment: Environment,
    stdin: Stdin,
    requirements: CommandRequirements,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    mode: String,
    allowlist: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stdin {
    mode: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    r#ref: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandRequirements {
    pty: bool,
    live_output: bool,
    parent_shell_state: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestPolicy {
    snapshot_id: String,
    r#ref: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestSink {
    trust_domain: String,
    target: String,
    disclosure: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretChannel {
    mode: String,
    refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bindings {
    workspace_id: String,
    session_id: String,
    correlation_id: String,
    action_id: Option<u64>,
    attempt_id: Option<String>,
}

/// Verify one compiled snapshot against one request and select its sink action.
pub fn evaluate_policy(
    snapshot_json: &[u8],
    request_json: &[u8],
    context: &EvaluationContext,
    secrets: &ProtectedSecretRegistry,
) -> Result<EvaluatedPolicy, PolicyError> {
    if snapshot_json.len() > MAX_POLICY_DOCUMENT_BYTES
        || request_json.len() > MAX_REQUEST_DOCUMENT_BYTES
    {
        return Err(PolicyError::InvalidDocument(
            "policy/request JSON exceeds the native byte limit".to_owned(),
        ));
    }
    let mut snapshot: Snapshot = serde_json::from_slice(snapshot_json)
        .map_err(|error| PolicyError::InvalidDocument(format!("snapshot JSON: {error}")))?;
    let request = parse_request(request_json)?;
    validate_snapshot(&mut snapshot, context.now_unix_millis)?;
    validate_request(&request)?;
    validate_command_against_scope(&snapshot.command_scope, &request.command)?;

    if request.policy.snapshot_id != snapshot.snapshot_id
        || request.policy.r#ref != snapshot.policy_ref
        || request.policy.digest != snapshot.policy_digest
    {
        return Err(PolicyError::BindingMismatch(
            "request does not carry the exact snapshot id/ref/digest".to_owned(),
        ));
    }
    if request.bindings.workspace_id != context.workspace_id
        || request.bindings.session_id != context.session_id
        || snapshot.session.session_id != context.session_id
    {
        return Err(PolicyError::ContextMismatch(
            "workspace or session binding differs from runner context".to_owned(),
        ));
    }
    if !safe_absolute_path(&context.workspace_root)
        || !Path::new(&request.command.cwd).starts_with(&context.workspace_root)
    {
        return Err(PolicyError::ContextMismatch(
            "request cwd is outside the runner-pinned workspace".to_owned(),
        ));
    }

    let sink = snapshot
        .sinks
        .iter()
        .find(|sink| sink.name == request.sink.target)
        .ok_or_else(|| PolicyError::ContextMismatch("requested sink is absent".to_owned()))?;
    if request.sink.trust_domain != sink.trust_domain || request.sink.disclosure != sink.disclosure
    {
        return Err(PolicyError::ContextMismatch(
            "request cannot alter the compiled sink trust or disclosure".to_owned(),
        ));
    }

    let action = match sink.disclosure.as_str() {
        "safe-unredacted" => SinkAction::SafeUnredacted,
        "sanitized" => SinkAction::Sanitized,
        "metadata-only" => SinkAction::MetadataOnly,
        "deny" => return Err(PolicyError::SinkDenied),
        _ => {
            return Err(PolicyError::InvalidDocument(
                "unknown sink disclosure".to_owned(),
            ))
        }
    };
    secrets.ensure_registered(&request.secret_channel.refs)?;
    let persistence = match snapshot.capture.commitment.as_str() {
        "memory-only" => PersistenceMode::MemoryOnly,
        "process-local" => PersistenceMode::ProcessLocal,
        "host-persistent" => PersistenceMode::HostPersistent,
        "replicated" => {
            return Err(PolicyError::Unsupported(
                "replicated persistence has no native backend".to_owned(),
            ))
        }
        _ => {
            return Err(PolicyError::InvalidDocument(
                "unknown capture commitment".to_owned(),
            ))
        }
    };
    let mut presentation = PresentationOptions {
        persistence,
        mode: match action {
            SinkAction::SafeUnredacted | SinkAction::Sanitized => PresentationMode::Safe,
            SinkAction::MetadataOnly => PresentationMode::Metadata,
        },
        ..PresentationOptions::default()
    };
    if action == SinkAction::Sanitized {
        presentation.exact_redaction_values = secrets.resolve(&request.secret_channel.refs)?;
    }
    presentation
        .validate()
        .map_err(|error| PolicyError::InvalidDocument(error.to_string()))?;

    Ok(EvaluatedPolicy {
        action,
        capture_required: snapshot.capture.required,
        presentation,
        provenance: ClaimProvenance {
            snapshot_id: snapshot.snapshot_id,
            policy_ref: snapshot.policy_ref,
            policy_digest: snapshot.policy_digest,
            source_ref: snapshot.source.r#ref,
            source_digest: snapshot.source.digest,
            session_id: snapshot.session.session_id,
            sink: sink.name.clone(),
            action,
        },
    })
}

/// Atomically bind evaluation inputs to the command and sink configuration
/// used by native capture.
///
/// This is the W5 enforcement entry point. It does not accept caller-supplied
/// argv, cwd, environment, capture requirement, persistence, presentation or
/// redaction options outside the verified request/snapshot pair.
pub fn capture_request_with_policy(
    options: PolicyCaptureOptions<'_>,
    cancellation: Option<&AtomicBool>,
) -> Result<PolicyCaptureResult, PolicyCaptureError> {
    if !options.runner_authorized {
        return Err(PolicyCaptureError::MissingExecutionAuthority);
    }
    let decision = evaluate_policy(
        options.snapshot_json,
        options.request_json,
        options.context,
        options.secrets,
    )?;
    // Evaluation already performed strict, bounded deserialization. Parsing
    // the same immutable byte slice again avoids exposing command fields from
    // EvaluatedPolicy where they could be mixed with another request.
    let request = parse_request(options.request_json)?;
    let environment = match request.command.environment.mode.as_str() {
        "inherited" => CommandEnvironment::Inherited,
        "empty" => CommandEnvironment::Empty,
        "allowlist" => CommandEnvironment::Allowlist(
            request
                .command
                .environment
                .allowlist
                .unwrap_or_default()
                .into_iter()
                .map(OsString::from)
                .collect(),
        ),
        _ => unreachable!("environment mode was validated"),
    };
    let stdin = match request.command.stdin.mode.as_str() {
        "none" => CommandStdin::Null,
        "inherited" => CommandStdin::Inherited,
        "file-ref" => CommandStdin::Bytes(
            options.stdin.resolve(
                request
                    .command
                    .stdin
                    .r#ref
                    .as_deref()
                    .expect("file-ref was validated with a reference"),
            )?,
        ),
        _ => unreachable!("stdin mode was validated"),
    };
    let capture_options = CaptureOptions {
        shell_command: request.command.shell_command.map(OsString::from),
        stdin,
        argv: request
            .command
            .argv
            .into_iter()
            .map(OsString::from)
            .collect(),
        spool_root: options.spool_root,
        max_bytes: options.max_capture_bytes,
        timeout: request.command.timeout_ms.map(Duration::from_millis),
        cwd: Some(PathBuf::from(request.command.cwd)),
        workspace_id: Some(request.bindings.workspace_id),
        required_capture: decision.capture_required,
        environment,
    };
    let policy_metadata = decision.metadata();
    let capture =
        capture_command_with_presentation(&capture_options, &decision.presentation, cancellation)?;
    Ok(PolicyCaptureResult {
        capture,
        policy_metadata,
    })
}

fn parse_request(request_json: &[u8]) -> Result<Request, PolicyError> {
    serde_json::from_slice(request_json)
        .map_err(|error| PolicyError::InvalidDocument(format!("request JSON: {error}")))
}

fn validate_snapshot(snapshot: &mut Snapshot, now_ms: i64) -> Result<(), PolicyError> {
    if snapshot.schema_version != SNAPSHOT_SCHEMA {
        return Err(PolicyError::InvalidDocument(
            "unsupported snapshot schema".to_owned(),
        ));
    }
    if snapshot.snapshot_id.is_empty()
        || snapshot.snapshot_id.len() > 160
        || snapshot.policy_ref.is_empty()
        || snapshot.policy_ref.len() > 1024
        || snapshot.source.r#ref.is_empty()
        || snapshot.source.r#ref.len() > 1024
    {
        return Err(PolicyError::InvalidDocument(
            "snapshot identity/source fields are empty or oversized".to_owned(),
        ));
    }
    validate_digest(&snapshot.source.digest, "source digest")?;
    validate_digest(&snapshot.policy_digest, "policy digest")?;
    if snapshot.cache.owner != "python-policy-control"
        || snapshot.cache.snapshot_id != snapshot.snapshot_id
        || snapshot.cache.key != format!("policy-cache://snapshot/{}", snapshot.snapshot_id)
        || snapshot.cache.max_age_ms == 0
        || snapshot.cache.max_age_ms > 86_400_000
    {
        return Err(PolicyError::BindingMismatch(
            "snapshot cache identity/owner/lifetime is invalid".to_owned(),
        ));
    }
    if snapshot.execution_authority.owner != "external-runner"
        || snapshot.execution_authority.can_authorize_execution
        || snapshot.execution_authority.can_retry
    {
        return Err(PolicyError::InvalidDocument(
            "capture policy cannot grant execution or retry".to_owned(),
        ));
    }
    let issued = parse_utc_timestamp_ms(&snapshot.issued_at)?;
    let expires = parse_utc_timestamp_ms(&snapshot.expires_at)?;
    let cache_expires = issued
        .checked_add(snapshot.cache.max_age_ms as i64)
        .ok_or_else(|| PolicyError::InvalidDocument("cache expiry overflows".to_owned()))?;
    if expires <= issued || now_ms < issued || now_ms >= expires || now_ms >= cache_expires {
        return Err(PolicyError::Expired);
    }
    validate_session(&snapshot.session)?;
    validate_capture(&snapshot.capture)?;
    validate_command_scope(&snapshot.command_scope)?;
    validate_sinks(&mut snapshot.sinks)?;
    validate_contextual_policy(&snapshot.session, &snapshot.sinks, &snapshot.capture)?;

    let expected_digest = digest_value(&policy_material(snapshot))?;
    if snapshot.policy_digest != expected_digest {
        return Err(PolicyError::BindingMismatch(
            "snapshot semantic digest is not canonical".to_owned(),
        ));
    }
    let digest_hex = snapshot
        .policy_digest
        .strip_prefix(DIGEST_PREFIX)
        .expect("validated digest has prefix");
    if snapshot.snapshot_id != format!("snapshot-{}", &digest_hex[..32]) {
        return Err(PolicyError::BindingMismatch(
            "snapshot id is not derived from the semantic digest".to_owned(),
        ));
    }
    Ok(())
}

fn policy_material(snapshot: &Snapshot) -> Value {
    json!({
        "schema_version": snapshot.schema_version,
        "source": snapshot.source,
        "cache": {
            "owner": snapshot.cache.owner,
            "max_age_ms": snapshot.cache.max_age_ms,
        },
        "session": snapshot.session,
        "sinks": snapshot.sinks,
        "capture": snapshot.capture,
        "command_scope": snapshot.command_scope,
        "execution_authority": snapshot.execution_authority,
        "issued_at": snapshot.issued_at,
        "expires_at": snapshot.expires_at,
    })
}

fn digest_value(value: &Value) -> Result<String, PolicyError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| PolicyError::InvalidDocument(format!("canonical JSON: {error}")))?;
    Ok(format!("sha256:{:x}", Sha256::digest(encoded)))
}

fn validate_request(request: &Request) -> Result<(), PolicyError> {
    if request.schema_version != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 160
        || request.command.argv.is_empty()
        || request.command.argv.len() > 256
        || request
            .command
            .argv
            .iter()
            .any(|item| item.is_empty() || item.len() > 4096 || item.contains('\0'))
        || request.command.cwd.is_empty()
        || request.command.timeout_ms == Some(0)
        || request.bindings.workspace_id.is_empty()
        || request.bindings.session_id.is_empty()
        || request.bindings.correlation_id.is_empty()
        || request.bindings.action_id == Some(0)
        || request
            .bindings
            .attempt_id
            .as_ref()
            .is_some_and(String::is_empty)
    {
        return Err(PolicyError::InvalidDocument(
            "request violates the bounded command baseline".to_owned(),
        ));
    }
    match request.command.execution_mode.as_str() {
        "direct-argv" if request.command.shell_command.is_none() => {}
        "explicit-shell"
            if request
                .command
                .shell_command
                .as_ref()
                .is_some_and(|command| {
                    !command.is_empty() && command.len() <= 65_536 && !command.contains('\0')
                }) => {}
        "direct-argv" | "explicit-shell" => {
            return Err(PolicyError::InvalidDocument(
                "execution mode and shell command contradict".to_owned(),
            ))
        }
        _ => {
            return Err(PolicyError::InvalidDocument(
                "request execution mode is unknown".to_owned(),
            ))
        }
    }
    if request.command.requirements.pty {
        return Err(PolicyError::Unsupported("pty".to_owned()));
    }
    if request.command.requirements.live_output {
        return Err(PolicyError::Unsupported("live-output".to_owned()));
    }
    if request.command.requirements.parent_shell_state {
        return Err(PolicyError::Unsupported("parent-shell-state".to_owned()));
    }
    let cwd = Path::new(&request.command.cwd);
    if !safe_absolute_path(cwd) {
        return Err(PolicyError::InvalidDocument(
            "request cwd must be a normalized absolute path".to_owned(),
        ));
    }
    validate_environment(&request.command.environment)?;
    match (
        request.command.stdin.mode.as_str(),
        &request.command.stdin.r#ref,
    ) {
        ("none" | "inherited", None) => {}
        ("file-ref", Some(reference)) if valid_stdin_ref(reference) => {}
        _ => {
            return Err(PolicyError::InvalidDocument(
                "stdin mode and reference contradict".to_owned(),
            ))
        }
    }
    validate_digest(&request.policy.digest, "request policy digest")?;
    if request.secret_channel.refs.len() > MAX_SECRET_REFS
        || request
            .secret_channel
            .refs
            .iter()
            .any(|reference| !valid_secret_ref(reference))
        || request
            .secret_channel
            .refs
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.secret_channel.refs.len()
        || (request.secret_channel.mode == "none" && !request.secret_channel.refs.is_empty())
        || (request.secret_channel.mode == "protected-opaque"
            && request.secret_channel.refs.is_empty())
        || !matches!(
            request.secret_channel.mode.as_str(),
            "none" | "protected-opaque"
        )
    {
        return Err(PolicyError::InvalidDocument(
            "secret channel is contradictory or unbounded".to_owned(),
        ));
    }
    Ok(())
}

fn validate_command_scope(scope: &CommandScope) -> Result<(), PolicyError> {
    if scope.execution_modes.is_empty()
        || scope.execution_modes.len() > 2
        || !scope
            .execution_modes
            .iter()
            .any(|mode| mode == "direct-argv")
        || scope.execution_modes.iter().collect::<BTreeSet<_>>().len()
            != scope.execution_modes.len()
        || scope
            .execution_modes
            .iter()
            .any(|mode| !matches!(mode.as_str(), "direct-argv" | "explicit-shell"))
        || scope.stdin_modes.is_empty()
        || scope.stdin_modes.len() > 3
        || !scope.stdin_modes.iter().any(|mode| mode == "none")
        || scope.stdin_modes.iter().collect::<BTreeSet<_>>().len() != scope.stdin_modes.len()
        || scope
            .stdin_modes
            .iter()
            .any(|mode| !matches!(mode.as_str(), "none" | "inherited" | "file-ref"))
        || scope.explicit_shell_argv.len() > 16
        || scope
            .explicit_shell_argv
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != scope.explicit_shell_argv.len()
    {
        return Err(PolicyError::InvalidDocument(
            "command scope is contradictory or unbounded".to_owned(),
        ));
    }
    for argv in &scope.explicit_shell_argv {
        if !(2..=8).contains(&argv.len())
            || !safe_absolute_path(Path::new(&argv[0]))
            || argv[0].contains("//")
            || !matches!(argv.last().map(String::as_str), Some("-c" | "-lc"))
            || argv.iter().any(|item| {
                item.is_empty()
                    || item.len() > 4096
                    || item.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
            })
        {
            return Err(PolicyError::InvalidDocument(
                "reviewed shell interpreter argv is invalid".to_owned(),
            ));
        }
    }
    if scope
        .execution_modes
        .iter()
        .any(|mode| mode == "explicit-shell")
        != !scope.explicit_shell_argv.is_empty()
    {
        return Err(PolicyError::InvalidDocument(
            "explicit shell mode has no exact reviewed interpreter argv".to_owned(),
        ));
    }
    Ok(())
}

fn validate_command_against_scope(
    scope: &CommandScope,
    command: &Command,
) -> Result<(), PolicyError> {
    if !scope
        .execution_modes
        .iter()
        .any(|mode| mode == &command.execution_mode)
        || !scope
            .stdin_modes
            .iter()
            .any(|mode| mode == &command.stdin.mode)
    {
        return Err(PolicyError::Unsupported(
            "requested command or stdin mode is outside the compiled scope".to_owned(),
        ));
    }
    if command.execution_mode == "explicit-shell"
        && !scope
            .explicit_shell_argv
            .iter()
            .any(|argv| argv == &command.argv)
    {
        return Err(PolicyError::Unsupported(
            "explicit shell interpreter argv was not reviewed exactly".to_owned(),
        ));
    }
    Ok(())
}

fn validate_environment(environment: &Environment) -> Result<(), PolicyError> {
    match environment.mode.as_str() {
        "inherited" | "empty" if environment.allowlist.is_none() => Ok(()),
        "allowlist" => {
            let Some(names) = &environment.allowlist else {
                return Err(PolicyError::InvalidDocument(
                    "allowlist environment requires names".to_owned(),
                ));
            };
            if names.is_empty()
                || names.len() > 256
                || names.iter().collect::<BTreeSet<_>>().len() != names.len()
                || names.iter().any(|name| {
                    name.is_empty()
                        || name.len() > 256
                        || !name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                })
            {
                return Err(PolicyError::InvalidDocument(
                    "environment allowlist is empty, duplicated, or invalid".to_owned(),
                ));
            }
            Ok(())
        }
        "inherited" | "empty" => Err(PolicyError::InvalidDocument(
            "non-allowlist environment cannot carry names".to_owned(),
        )),
        _ => Err(PolicyError::InvalidDocument(
            "unsupported environment mode".to_owned(),
        )),
    }
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn validate_session(session: &Session) -> Result<(), PolicyError> {
    if session.session_id.is_empty()
        || !matches!(
            session.trust_domain.as_str(),
            "trusted-local" | "restricted" | "export" | "metadata-only"
        )
        || (session.trust_domain == "trusted-local" && !session.commissioned)
    {
        return Err(PolicyError::InvalidDocument(
            "session trust commissioning is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sinks(sinks: &mut [Sink]) -> Result<(), PolicyError> {
    sinks.sort_by(|left, right| left.name.cmp(&right.name));
    let mut names = BTreeSet::new();
    if sinks.is_empty() {
        return Err(PolicyError::InvalidDocument(
            "snapshot must define at least one sink".to_owned(),
        ));
    }
    for sink in sinks {
        if !matches!(
            sink.name.as_str(),
            "model" | "runner" | "audit-receipt" | "handoff"
        ) || !names.insert(sink.name.clone())
            || !matches!(
                sink.trust_domain.as_str(),
                "trusted-local" | "restricted" | "export" | "metadata-only"
            )
            || !matches!(
                sink.disclosure.as_str(),
                "safe-unredacted" | "sanitized" | "metadata-only" | "deny"
            )
            || (sink.disclosure == "safe-unredacted"
                && (sink.trust_domain != "trusted-local" || sink.redaction_required))
            || (sink.trust_domain == "metadata-only" && sink.disclosure != "metadata-only")
            || (matches!(sink.trust_domain.as_str(), "restricted" | "export")
                && sink.disclosure == "safe-unredacted")
            || (sink.disclosure == "sanitized" && !sink.redaction_required)
            || sink.classification_ceiling.as_ref().is_some_and(|ceiling| {
                !matches!(
                    ceiling.as_str(),
                    "public" | "internal" | "confidential" | "secret"
                )
            })
        {
            return Err(PolicyError::InvalidDocument(
                "sink lattice contains an invalid or duplicate action".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_capture(capture: &Capture) -> Result<(), PolicyError> {
    let valid = match capture.commitment.as_str() {
        "memory-only" | "process-local" => capture.durability == "none" && !capture.required,
        "host-persistent" => capture.durability == "host",
        "replicated" => matches!(capture.durability.as_str(), "replica" | "authoritative"),
        _ => false,
    };
    if !valid {
        return Err(PolicyError::InvalidDocument(
            "capture commitment, durability and requirement contradict".to_owned(),
        ));
    }
    Ok(())
}

fn validate_contextual_policy(
    session: &Session,
    sinks: &[Sink],
    capture: &Capture,
) -> Result<(), PolicyError> {
    let sink_is_allowed = |sink: &Sink| match session.trust_domain.as_str() {
        "trusted-local" => true,
        "restricted" => matches!(
            sink.trust_domain.as_str(),
            "restricted" | "export" | "metadata-only"
        ),
        "export" => matches!(sink.trust_domain.as_str(), "export" | "metadata-only"),
        "metadata-only" => sink.trust_domain == "metadata-only",
        _ => false,
    };
    if sinks.iter().any(|sink| !sink_is_allowed(sink)) {
        return Err(PolicyError::InvalidDocument(
            "sink widens the commissioned session trust domain".to_owned(),
        ));
    }
    if session.trust_domain == "trusted-local"
        && (!capture.required
            || !matches!(
                capture.commitment.as_str(),
                "host-persistent" | "replicated"
            ))
    {
        return Err(PolicyError::InvalidDocument(
            "trusted-local session requires persistent capture".to_owned(),
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), PolicyError> {
    if value.len() != DIGEST_PREFIX.len() + 64
        || !value.starts_with(DIGEST_PREFIX)
        || !value[DIGEST_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError::InvalidDocument(format!(
            "{label} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn valid_secret_ref(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("secret://") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn valid_stdin_ref(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("outctl://stdin/") else {
        return false;
    };
    !rest.is_empty()
        && rest.len() <= 512
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn parse_utc_timestamp_ms(value: &str) -> Result<i64, PolicyError> {
    let bytes = value.as_bytes();
    let canonical_seconds = bytes.len() == 20 && bytes[19] == b'Z';
    let canonical_millis = bytes.len() == 24
        && bytes[19] == b'.'
        && bytes[23] == b'Z'
        && bytes[20..23].iter().all(u8::is_ascii_digit);
    if (!canonical_seconds && !canonical_millis)
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(PolicyError::InvalidDocument(
            "timestamps must use canonical UTC second precision".to_owned(),
        ));
    }
    let year = digits(bytes, 0, 4)?;
    let month = digits(bytes, 5, 2)?;
    let day = digits(bytes, 8, 2)?;
    let hour = digits(bytes, 11, 2)?;
    let minute = digits(bytes, 14, 2)?;
    let second = digits(bytes, 17, 2)?;
    if year < 1970
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(PolicyError::InvalidDocument(
            "timestamp components are out of range".to_owned(),
        ));
    }
    let milliseconds = if canonical_millis {
        digits(bytes, 20, 3)?
    } else {
        0
    };
    let days = days_from_civil(year, month, day);
    days.checked_mul(86_400_000)
        .and_then(|base| {
            base.checked_add((hour * 3_600 + minute * 60 + second) * 1_000 + milliseconds)
        })
        .ok_or_else(|| PolicyError::InvalidDocument("timestamp overflows".to_owned()))
}

fn digits(bytes: &[u8], start: usize, length: usize) -> Result<i64, PolicyError> {
    let mut value = 0_i64;
    for byte in &bytes[start..start + length] {
        if !byte.is_ascii_digit() {
            return Err(PolicyError::InvalidDocument(
                "timestamp contains non-digits".to_owned(),
            ));
        }
        value = value * 10 + i64::from(byte - b'0');
    }
    Ok(value)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

// Howard Hinnant's civil-date conversion, relative to 1970-01-01.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_spool(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("outctl-w5-{label}-{}-{nonce}", std::process::id()))
    }

    fn resign_snapshot(snapshot: &mut Value) {
        let mut parsed: Snapshot = serde_json::from_value(snapshot.clone()).unwrap();
        parsed
            .sinks
            .sort_by(|left, right| left.name.cmp(&right.name));
        let digest = digest_value(&policy_material(&parsed)).unwrap();
        let snapshot_id = format!(
            "snapshot-{}",
            &digest[DIGEST_PREFIX.len()..DIGEST_PREFIX.len() + 32]
        );
        snapshot["policy_digest"] = json!(digest);
        snapshot["snapshot_id"] = json!(snapshot_id);
        snapshot["cache"]["snapshot_id"] = snapshot["snapshot_id"].clone();
        snapshot["cache"]["key"] = json!(format!(
            "policy-cache://snapshot/{}",
            snapshot["snapshot_id"].as_str().unwrap()
        ));
    }

    fn source_policy() -> (Value, Value, EvaluationContext) {
        let mut snapshot = json!({
            "schema_version": SNAPSHOT_SCHEMA,
            "snapshot_id": "pending",
            "policy_ref": "policy://w5/test",
            "policy_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "source": {"ref": "git:config/w5.yaml", "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            "cache": {"key": "pending", "snapshot_id": "pending", "owner": "python-policy-control", "max_age_ms": 3600000},
            "session": {"session_id": "session-1", "trust_domain": "trusted-local", "commissioned": true},
            "sinks": [
                {"name": "handoff", "trust_domain": "restricted", "disclosure": "sanitized", "redaction_required": true, "classification_ceiling": "confidential"},
                {"name": "model", "trust_domain": "trusted-local", "disclosure": "safe-unredacted", "redaction_required": false, "classification_ceiling": "secret"},
                {"name": "audit-receipt", "trust_domain": "metadata-only", "disclosure": "metadata-only", "redaction_required": true},
                {"name": "runner", "trust_domain": "export", "disclosure": "deny", "redaction_required": true}
            ],
            "capture": {"commitment": "host-persistent", "durability": "host", "required": true},
            "command_scope": {"execution_modes": ["direct-argv"], "explicit_shell_argv": [], "stdin_modes": ["none"]},
            "execution_authority": {"owner": "external-runner", "can_authorize_execution": false, "can_retry": false},
            "issued_at": "2026-08-12T00:00:00Z",
            "expires_at": "2026-08-12T01:00:00Z"
        });
        resign_snapshot(&mut snapshot);
        let request = json!({
            "schema_version": REQUEST_SCHEMA,
            "request_id": "request-1",
            "command": {"argv": ["printf", "data"], "execution_mode": "direct-argv", "shell_command": null, "cwd": "/workspace", "environment": {"mode": "empty"}, "stdin": {"mode": "none", "ref": null}, "requirements": {"pty": false, "live_output": false, "parent_shell_state": false}, "timeout_ms": 1000},
            "policy": {"snapshot_id": snapshot["snapshot_id"], "ref": snapshot["policy_ref"], "digest": snapshot["policy_digest"]},
            "sink": {"trust_domain": "restricted", "target": "handoff", "disclosure": "sanitized"},
            "secret_channel": {"mode": "protected-opaque", "refs": ["secret://test/value"]},
            "bindings": {"workspace_id": "workspace-1", "session_id": "session-1", "correlation_id": "correlation-1", "action_id": 2137, "attempt_id": "attempt-1"}
        });
        (
            snapshot,
            request,
            EvaluationContext {
                workspace_id: "workspace-1".to_owned(),
                session_id: "session-1".to_owned(),
                workspace_root: PathBuf::from("/workspace"),
                now_unix_millis: parse_utc_timestamp_ms("2026-08-12T00:30:00.000Z").unwrap(),
            },
        )
    }

    fn assert_missing_required_nullable_rejected(field: &str) {
        let (snapshot, mut request, context) = source_policy();
        match field {
            "shell_command" | "timeout_ms" => {
                request["command"]
                    .as_object_mut()
                    .unwrap()
                    .remove(field)
                    .unwrap();
            }
            "stdin.ref" => {
                request["command"]["stdin"]
                    .as_object_mut()
                    .unwrap()
                    .remove("ref")
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let mut secrets = ProtectedSecretRegistry::new();
        secrets
            .register("secret://test/value".to_owned(), b"secret".to_vec())
            .unwrap();
        let spool = temporary_spool(&format!("missing-{}", field.replace('.', "-")));
        let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap();
        let request_bytes = serde_json::to_vec(&request).unwrap();

        let result = capture_request_with_policy(
            PolicyCaptureOptions {
                snapshot_json: &snapshot_bytes,
                request_json: &request_bytes,
                context: &context,
                secrets: &secrets,
                stdin: &ProtectedStdinRegistry::new(),
                spool_root: spool.clone(),
                max_capture_bytes: 1024,
                runner_authorized: true,
            },
            None,
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("omitted required nullable field was accepted"),
        };
        assert!(
            matches!(
                error,
                PolicyCaptureError::Policy(PolicyError::InvalidDocument(_))
            ),
            "unexpected omission error: {error:?}"
        );
        assert!(!spool.exists());
    }

    fn assert_duplicate_request_field_rejected(label: &str, needle: &str, replacement: &str) {
        let (snapshot, request, context) = source_policy();
        let request_json = serde_json::to_string(&request).unwrap();
        assert!(request_json.contains(needle));
        let duplicate_request = request_json.replacen(needle, replacement, 1);
        let mut secrets = ProtectedSecretRegistry::new();
        secrets
            .register("secret://test/value".to_owned(), b"secret".to_vec())
            .unwrap();
        let spool = temporary_spool(label);
        let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap();

        assert!(matches!(
            capture_request_with_policy(
                PolicyCaptureOptions {
                    snapshot_json: &snapshot_bytes,
                    request_json: duplicate_request.as_bytes(),
                    context: &context,
                    secrets: &secrets,
                    stdin: &ProtectedStdinRegistry::new(),
                    spool_root: spool.clone(),
                    max_capture_bytes: 1024,
                    runner_authorized: true,
                },
                None,
            ),
            Err(PolicyCaptureError::Policy(PolicyError::InvalidDocument(_)))
        ));
        assert!(!spool.exists());
    }

    #[test]
    fn restricted_sink_uses_only_protected_exact_values() {
        let (snapshot, request, context) = source_policy();
        let secret = b"do-not-print-this-exact-value".to_vec();
        let mut registry = ProtectedSecretRegistry::new();
        registry
            .register("secret://test/value".to_owned(), secret.clone())
            .unwrap();
        let decision = evaluate_policy(
            &serde_json::to_vec(&snapshot).unwrap(),
            &serde_json::to_vec(&request).unwrap(),
            &context,
            &registry,
        )
        .unwrap();
        assert_eq!(decision.action, SinkAction::Sanitized);
        assert_eq!(decision.presentation.exact_redaction_values, vec![secret]);
        assert!(!decision.metadata().to_string().contains("do-not-print"));
        assert!(!format!("{registry:?}").contains("do-not-print"));
        assert!(!format!("{decision:?}").contains("do-not-print"));
    }

    #[test]
    fn trusted_metadata_and_deny_actions_are_enforced() {
        let (snapshot, mut request, context) = source_policy();
        let registry = ProtectedSecretRegistry::new();
        request["sink"] = json!({"trust_domain": "trusted-local", "target": "model", "disclosure": "safe-unredacted"});
        request["secret_channel"] = json!({"mode": "none", "refs": []});
        let trusted = evaluate_policy(
            &serde_json::to_vec(&snapshot).unwrap(),
            &serde_json::to_vec(&request).unwrap(),
            &context,
            &registry,
        )
        .unwrap();
        assert_eq!(trusted.action, SinkAction::SafeUnredacted);

        request["sink"] = json!({"trust_domain": "metadata-only", "target": "audit-receipt", "disclosure": "metadata-only"});
        let metadata = evaluate_policy(
            &serde_json::to_vec(&snapshot).unwrap(),
            &serde_json::to_vec(&request).unwrap(),
            &context,
            &registry,
        )
        .unwrap();
        assert_eq!(metadata.presentation.mode, PresentationMode::Metadata);

        request["sink"] =
            json!({"trust_domain": "export", "target": "runner", "disclosure": "deny"});
        assert_eq!(
            evaluate_policy(
                &serde_json::to_vec(&snapshot).unwrap(),
                &serde_json::to_vec(&request).unwrap(),
                &context,
                &registry,
            )
            .unwrap_err(),
            PolicyError::SinkDenied
        );
    }

    #[test]
    fn digest_context_and_downgrade_attacks_fail_closed() {
        let (snapshot, request, context) = source_policy();
        let mut registry = ProtectedSecretRegistry::new();
        registry
            .register("secret://test/value".to_owned(), b"secret".to_vec())
            .unwrap();
        for mutation in ["digest", "session", "workspace", "disclosure", "cwd"] {
            let mut changed_snapshot = snapshot.clone();
            let mut changed_request = request.clone();
            match mutation {
                "digest" => changed_snapshot["capture"]["required"] = json!(false),
                "session" => changed_request["bindings"]["session_id"] = json!("other"),
                "workspace" => changed_request["bindings"]["workspace_id"] = json!("other"),
                "disclosure" => changed_request["sink"]["disclosure"] = json!("metadata-only"),
                "cwd" => changed_request["command"]["cwd"] = json!("/workspace/../escape"),
                _ => unreachable!(),
            }
            assert!(evaluate_policy(
                &serde_json::to_vec(&changed_snapshot).unwrap(),
                &serde_json::to_vec(&changed_request).unwrap(),
                &context,
                &registry,
            )
            .is_err());
        }
    }

    #[test]
    fn expiry_and_missing_secret_fail_before_execution() {
        let (snapshot, request, mut context) = source_policy();
        context.now_unix_millis = parse_utc_timestamp_ms("2026-08-12T01:00:00.000Z").unwrap();
        assert_eq!(
            evaluate_policy(
                &serde_json::to_vec(&snapshot).unwrap(),
                &serde_json::to_vec(&request).unwrap(),
                &context,
                &ProtectedSecretRegistry::new(),
            )
            .unwrap_err(),
            PolicyError::Expired
        );
        context.now_unix_millis = parse_utc_timestamp_ms("2026-08-12T00:30:00.000Z").unwrap();
        assert!(matches!(
            evaluate_policy(
                &serde_json::to_vec(&snapshot).unwrap(),
                &serde_json::to_vec(&request).unwrap(),
                &context,
                &ProtectedSecretRegistry::new(),
            ),
            Err(PolicyError::SecretUnavailable(_))
        ));
    }

    #[test]
    fn invalid_compiler_outputs_fail_even_with_valid_digest() {
        let (snapshot, request, context) = source_policy();
        let mut registry = ProtectedSecretRegistry::new();
        registry
            .register("secret://test/value".to_owned(), b"secret".to_vec())
            .unwrap();
        for mutation in ["trust-widening", "weak-capture", "redaction-bypass"] {
            let mut changed_snapshot = snapshot.clone();
            match mutation {
                "trust-widening" => {
                    changed_snapshot["session"]["trust_domain"] = json!("restricted");
                    changed_snapshot["session"]["commissioned"] = json!(false);
                }
                "weak-capture" => {
                    changed_snapshot["capture"] = json!({
                        "commitment": "process-local",
                        "durability": "none",
                        "required": false
                    });
                }
                "redaction-bypass" => {
                    changed_snapshot["sinks"][0]["redaction_required"] = json!(false);
                }
                _ => unreachable!(),
            }
            resign_snapshot(&mut changed_snapshot);
            let mut changed_request = request.clone();
            changed_request["policy"] = json!({
                "snapshot_id": changed_snapshot["snapshot_id"],
                "ref": changed_snapshot["policy_ref"],
                "digest": changed_snapshot["policy_digest"]
            });
            assert!(evaluate_policy(
                &serde_json::to_vec(&changed_snapshot).unwrap(),
                &serde_json::to_vec(&changed_request).unwrap(),
                &context,
                &registry,
            )
            .is_err());
        }
    }

    #[test]
    fn timestamp_parser_handles_epoch_and_leap_days() {
        assert_eq!(parse_utc_timestamp_ms("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_utc_timestamp_ms("1970-01-01T00:00:00.123Z").unwrap(),
            123
        );
        assert!(parse_utc_timestamp_ms("2024-02-29T23:59:59.999Z").is_ok());
        assert!(parse_utc_timestamp_ms("2023-02-29T00:00:00.000Z").is_err());
    }

    #[test]
    fn python_compiled_examples_are_native_evaluation_vectors() {
        let snapshot = include_bytes!("../../../examples/v2/policy-snapshot.json");
        let trusted_request = include_bytes!("../../../examples/v2/run-request.trusted.json");
        let restricted_request = include_bytes!("../../../examples/v2/run-request.restricted.json");
        let context = EvaluationContext {
            workspace_id: "workspace-1".to_owned(),
            session_id: "session-1".to_owned(),
            workspace_root: PathBuf::from("/workspace"),
            now_unix_millis: parse_utc_timestamp_ms("2026-08-12T08:30:00.000Z").unwrap(),
        };

        let trusted = evaluate_policy(
            snapshot,
            trusted_request,
            &context,
            &ProtectedSecretRegistry::new(),
        )
        .unwrap();
        assert_eq!(trusted.action, SinkAction::SafeUnredacted);

        let mut secrets = ProtectedSecretRegistry::new();
        secrets
            .register(
                "secret://request/db-token".to_owned(),
                b"cross-language-secret".to_vec(),
            )
            .unwrap();
        let restricted = evaluate_policy(snapshot, restricted_request, &context, &secrets).unwrap();
        assert_eq!(restricted.action, SinkAction::Sanitized);
        assert_eq!(restricted.provenance.sink, "handoff");
    }

    #[test]
    fn policy_bound_capture_cannot_swap_command_or_sink_options() {
        let (snapshot, mut request, mut context) = source_policy();
        let exact = b"atomic-policy-secret".to_vec();
        request["command"]["argv"] = json!([
            "/run/current-system/sw/bin/printf",
            "token=atomic-policy-secret\n"
        ]);
        request["command"]["cwd"] = json!("/tmp");
        request["command"]["environment"] = json!({"mode": "empty"});
        context.workspace_root = PathBuf::from("/tmp");
        let mut secrets = ProtectedSecretRegistry::new();
        secrets
            .register("secret://test/value".to_owned(), exact.clone())
            .unwrap();
        let spool = temporary_spool("atomic");
        let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap();
        let request_bytes = serde_json::to_vec(&request).unwrap();

        let result = capture_request_with_policy(
            PolicyCaptureOptions {
                snapshot_json: &snapshot_bytes,
                request_json: &request_bytes,
                context: &context,
                secrets: &secrets,
                stdin: &ProtectedStdinRegistry::new(),
                spool_root: spool.clone(),
                max_capture_bytes: 1024,
                runner_authorized: true,
            },
            None,
        )
        .unwrap();
        let presentation = result.capture.presentation.unwrap();
        let body = presentation.body.unwrap();
        assert!(body.contains("[REDACTED]"));
        assert!(!body.contains("atomic-policy-secret"));
        assert!(!result
            .policy_metadata
            .to_string()
            .contains("atomic-policy-secret"));
        assert_eq!(result.policy_metadata["execution_authorized"], false);
        assert_eq!(result.policy_metadata["action"], "sanitized");
        std::fs::remove_dir_all(&spool).unwrap();

        let denied_spool = temporary_spool("unauthorized");
        assert!(matches!(
            capture_request_with_policy(
                PolicyCaptureOptions {
                    snapshot_json: &snapshot_bytes,
                    request_json: &request_bytes,
                    context: &context,
                    secrets: &secrets,
                    stdin: &ProtectedStdinRegistry::new(),
                    spool_root: denied_spool.clone(),
                    max_capture_bytes: 1024,
                    runner_authorized: false,
                },
                None,
            ),
            Err(PolicyCaptureError::MissingExecutionAuthority)
        ));
        assert!(!denied_spool.exists());
    }

    #[test]
    fn generic_unknown_commands_need_no_command_specific_registration() {
        let (snapshot, mut request, mut context) = source_policy();
        request["command"]["argv"] = json!(["/run/current-system/sw/bin/printf", "generic-ok"]);
        request["command"]["cwd"] = json!("/tmp");
        request["sink"] = json!({"trust_domain": "trusted-local", "target": "model", "disclosure": "safe-unredacted"});
        request["secret_channel"] = json!({"mode": "none", "refs": []});
        context.workspace_root = PathBuf::from("/tmp");
        let spool = temporary_spool("generic-unknown");
        let result = capture_request_with_policy(
            PolicyCaptureOptions {
                snapshot_json: &serde_json::to_vec(&snapshot).unwrap(),
                request_json: &serde_json::to_vec(&request).unwrap(),
                context: &context,
                secrets: &ProtectedSecretRegistry::new(),
                stdin: &ProtectedStdinRegistry::new(),
                spool_root: spool.clone(),
                max_capture_bytes: 1024,
                runner_authorized: true,
            },
            None,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(result.capture.path.join("stdout.raw")).unwrap(),
            b"generic-ok"
        );
        std::fs::remove_dir_all(spool).unwrap();
    }

    #[test]
    fn reviewed_explicit_shell_is_exact_and_has_no_implicit_fallback() {
        let (mut snapshot, mut request, mut context) = source_policy();
        snapshot["command_scope"] = json!({
            "execution_modes": ["direct-argv", "explicit-shell"],
            "explicit_shell_argv": [["/bin/sh", "-c"]],
            "stdin_modes": ["none"]
        });
        resign_snapshot(&mut snapshot);
        request["policy"] = json!({
            "snapshot_id": snapshot["snapshot_id"],
            "ref": snapshot["policy_ref"],
            "digest": snapshot["policy_digest"]
        });
        request["command"]["argv"] = json!(["/bin/sh", "-c"]);
        request["command"]["execution_mode"] = json!("explicit-shell");
        request["command"]["shell_command"] = json!("printf shell-ok");
        request["command"]["cwd"] = json!("/tmp");
        request["sink"] = json!({"trust_domain": "trusted-local", "target": "model", "disclosure": "safe-unredacted"});
        request["secret_channel"] = json!({"mode": "none", "refs": []});
        context.workspace_root = PathBuf::from("/tmp");
        let spool = temporary_spool("reviewed-shell");
        let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap();
        let mut request_bytes = serde_json::to_vec(&request).unwrap();
        let result = capture_request_with_policy(
            PolicyCaptureOptions {
                snapshot_json: &snapshot_bytes,
                request_json: &request_bytes,
                context: &context,
                secrets: &ProtectedSecretRegistry::new(),
                stdin: &ProtectedStdinRegistry::new(),
                spool_root: spool.clone(),
                max_capture_bytes: 1024,
                runner_authorized: true,
            },
            None,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(result.capture.path.join("stdout.raw")).unwrap(),
            b"shell-ok"
        );
        std::fs::remove_dir_all(&spool).unwrap();

        request["command"]["argv"] = json!(["/bin/bash", "-c"]);
        request_bytes = serde_json::to_vec(&request).unwrap();
        assert!(matches!(
            capture_request_with_policy(
                PolicyCaptureOptions {
                    snapshot_json: &snapshot_bytes,
                    request_json: &request_bytes,
                    context: &context,
                    secrets: &ProtectedSecretRegistry::new(),
                    stdin: &ProtectedStdinRegistry::new(),
                    spool_root: spool.clone(),
                    max_capture_bytes: 1024,
                    runner_authorized: true,
                },
                None,
            ),
            Err(PolicyCaptureError::Policy(PolicyError::Unsupported(_)))
        ));
        assert!(!spool.exists());
    }

    #[test]
    fn bounded_opaque_stdin_is_streamed_without_path_resolution() {
        let (mut snapshot, mut request, mut context) = source_policy();
        snapshot["command_scope"]["stdin_modes"] = json!(["none", "file-ref"]);
        resign_snapshot(&mut snapshot);
        request["policy"] = json!({
            "snapshot_id": snapshot["snapshot_id"],
            "ref": snapshot["policy_ref"],
            "digest": snapshot["policy_digest"]
        });
        request["command"]["argv"] = json!(["/run/current-system/sw/bin/wc", "-c"]);
        request["command"]["stdin"] =
            json!({"mode": "file-ref", "ref": "outctl://stdin/request/body"});
        request["command"]["cwd"] = json!("/tmp");
        request["sink"] = json!({"trust_domain": "trusted-local", "target": "model", "disclosure": "safe-unredacted"});
        request["secret_channel"] = json!({"mode": "none", "refs": []});
        context.workspace_root = PathBuf::from("/tmp");
        let mut stdin = ProtectedStdinRegistry::new();
        stdin
            .register("outctl://stdin/request/body".to_owned(), b"abcde".to_vec())
            .unwrap();
        assert!(!format!("{stdin:?}").contains("abcde"));
        assert!(!format!(
            "{:?}",
            CommandStdin::Bytes(stdin.resolve("outctl://stdin/request/body").unwrap())
        )
        .contains("abcde"));
        let spool = temporary_spool("stdin-ref");
        let result = capture_request_with_policy(
            PolicyCaptureOptions {
                snapshot_json: &serde_json::to_vec(&snapshot).unwrap(),
                request_json: &serde_json::to_vec(&request).unwrap(),
                context: &context,
                secrets: &ProtectedSecretRegistry::new(),
                stdin: &stdin,
                spool_root: spool.clone(),
                max_capture_bytes: 1024,
                runner_authorized: true,
            },
            None,
        )
        .unwrap();
        let stdout = std::fs::read_to_string(result.capture.path.join("stdout.raw")).unwrap();
        assert_eq!(stdout.trim(), "5");
        std::fs::remove_dir_all(spool).unwrap();
    }

    #[test]
    fn stdin_registry_enforces_reference_and_byte_boundaries() {
        let mut exact = ProtectedStdinRegistry::new();
        exact
            .register(
                "outctl://stdin/exact".to_owned(),
                vec![b'x'; MAX_STDIN_BYTES],
            )
            .unwrap();
        let mut oversized = ProtectedStdinRegistry::new();
        assert!(matches!(
            oversized.register(
                "outctl://stdin/oversized".to_owned(),
                vec![b'x'; MAX_STDIN_BYTES + 1]
            ),
            Err(PolicyError::InvalidDocument(_))
        ));
        assert!(matches!(
            oversized.register("file:///tmp/input".to_owned(), Vec::new()),
            Err(PolicyError::InvalidDocument(_))
        ));
    }

    #[test]
    fn interactive_requirements_are_typed_unsupported_before_spool() {
        for requirement in ["pty", "live_output", "parent_shell_state"] {
            let (snapshot, mut request, context) = source_policy();
            request["command"]["requirements"][requirement] = json!(true);
            let mut secrets = ProtectedSecretRegistry::new();
            secrets
                .register("secret://test/value".to_owned(), b"secret".to_vec())
                .unwrap();
            let spool = temporary_spool(requirement);
            assert!(matches!(
                capture_request_with_policy(
                    PolicyCaptureOptions {
                        snapshot_json: &serde_json::to_vec(&snapshot).unwrap(),
                        request_json: &serde_json::to_vec(&request).unwrap(),
                        context: &context,
                        secrets: &secrets,
                        stdin: &ProtectedStdinRegistry::new(),
                        spool_root: spool.clone(),
                        max_capture_bytes: 1024,
                        runner_authorized: true,
                    },
                    None,
                ),
                Err(PolicyCaptureError::Policy(PolicyError::Unsupported(_)))
            ));
            assert!(!spool.exists());
        }
    }

    #[test]
    fn explicit_null_required_request_fields_remain_valid() {
        let (snapshot, mut request, context) = source_policy();
        request["command"]["timeout_ms"] = Value::Null;
        let mut secrets = ProtectedSecretRegistry::new();
        secrets
            .register("secret://test/value".to_owned(), b"secret".to_vec())
            .unwrap();

        evaluate_policy(
            &serde_json::to_vec(&snapshot).unwrap(),
            &serde_json::to_vec(&request).unwrap(),
            &context,
            &secrets,
        )
        .unwrap();
    }

    #[test]
    fn omitted_shell_command_rejects_before_spool_creation() {
        assert_missing_required_nullable_rejected("shell_command");
    }

    #[test]
    fn omitted_timeout_rejects_before_spool_creation() {
        assert_missing_required_nullable_rejected("timeout_ms");
    }

    #[test]
    fn omitted_stdin_ref_rejects_before_spool_creation() {
        assert_missing_required_nullable_rejected("stdin.ref");
    }

    #[test]
    fn duplicate_top_level_sink_rejects_before_spool_creation() {
        let sink =
            r#""sink":{"disclosure":"sanitized","target":"handoff","trust_domain":"restricted"}"#;
        let duplicate = format!("{sink},{sink}");
        assert_duplicate_request_field_rejected("duplicate-sink", sink, &duplicate);
    }

    #[test]
    fn duplicate_command_cwd_rejects_before_spool_creation() {
        assert_duplicate_request_field_rejected(
            "duplicate-cwd",
            r#""cwd":"/workspace""#,
            r#""cwd":"/workspace","cwd":"/workspace""#,
        );
    }

    #[test]
    fn duplicate_stdin_ref_rejects_before_spool_creation() {
        assert_duplicate_request_field_rejected(
            "duplicate-stdin-ref",
            r#""ref":null"#,
            r#""ref":null,"ref":null"#,
        );
    }
}

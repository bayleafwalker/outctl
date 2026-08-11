//! Bounded, deterministic presentation for native captures.
//!
//! The capture engine owns exact bytes.  This module owns only the derived
//! view sent to a sink.  It deliberately reads streams incrementally and
//! keeps candidate records bounded; presentation backpressure can therefore
//! never block the W3 pipe drainers.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const DEFAULT_MAX_PROJECTION_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_PROJECTION_LINES: usize = 1_200;
pub const DEFAULT_MAX_PROJECTION_TOKENS: usize = 12_000;
const READ_BYTES: usize = 16 * 1024;
const DEFAULT_FULL_IF_BYTES: u64 = 16 * 1024;
const DEFAULT_HEAD_LINES: usize = 24;
const DEFAULT_TAIL_LINES: usize = 80;
const DEFAULT_CANDIDATE_LINES: usize = 160;
const DEFAULT_MAX_LOGICAL_LINE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresentationMode {
    Auto,
    Safe,
    Compact,
    Projected,
    Metadata,
}

impl PresentationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Safe => "safe",
            Self::Compact => "compact",
            Self::Projected => "projected",
            Self::Metadata => "metadata",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceMode {
    MemoryOnly,
    ProcessLocal,
    HostPersistent,
    Replicated,
}

impl PersistenceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemoryOnly => "memory-only",
            Self::ProcessLocal => "process-local",
            Self::HostPersistent => "host-persistent",
            Self::Replicated => "replicated",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationOptions {
    pub mode: PresentationMode,
    pub persistence: PersistenceMode,
    pub max_bytes: usize,
    pub max_lines: usize,
    pub max_estimated_tokens: usize,
    pub full_if_bytes: u64,
    pub head_lines: usize,
    pub tail_lines: usize,
    pub candidate_context: usize,
    pub max_logical_line_bytes: usize,
    /// Exact values arrive through the protected runner boundary in library
    /// use.  They are never copied into result metadata or presentation text.
    pub exact_redaction_values: Vec<Vec<u8>>,
}

impl Default for PresentationOptions {
    fn default() -> Self {
        Self {
            mode: PresentationMode::Auto,
            persistence: PersistenceMode::HostPersistent,
            max_bytes: DEFAULT_MAX_PROJECTION_BYTES,
            max_lines: DEFAULT_MAX_PROJECTION_LINES,
            max_estimated_tokens: DEFAULT_MAX_PROJECTION_TOKENS,
            full_if_bytes: DEFAULT_FULL_IF_BYTES,
            head_lines: DEFAULT_HEAD_LINES,
            tail_lines: DEFAULT_TAIL_LINES,
            candidate_context: DEFAULT_CANDIDATE_LINES,
            max_logical_line_bytes: DEFAULT_MAX_LOGICAL_LINE_BYTES,
            exact_redaction_values: Vec::new(),
        }
    }
}

impl PresentationOptions {
    pub fn validate(&self) -> io::Result<()> {
        if self.max_bytes == 0
            || self.max_lines == 0
            || self.max_estimated_tokens == 0
            || self.head_lines == 0
            || self.tail_lines == 0
            || self.max_logical_line_bytes == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "presentation budgets must be positive",
            ));
        }
        if self.max_bytes > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "projection byte budget exceeds the native 1 MiB limit",
            ));
        }
        if self.max_lines > 50_000 || self.max_estimated_tokens > 250_000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "projection budget exceeds the native safety limit",
            ));
        }
        if self.exact_redaction_values.iter().any(Vec::is_empty) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact redaction values must not be empty",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct PersistenceResult {
    pub requested: String,
    pub commitment: String,
    pub durability: String,
    pub status: String,
    pub honest: bool,
    pub reference: Option<String>,
}

impl PersistenceResult {
    pub fn for_capture(mode: PersistenceMode, capture_id: &str) -> Self {
        match mode {
            PersistenceMode::MemoryOnly => Self {
                requested: mode.as_str().to_owned(),
                commitment: mode.as_str().to_owned(),
                durability: "none".to_owned(),
                status: "available-during-call-only".to_owned(),
                honest: true,
                reference: None,
            },
            PersistenceMode::ProcessLocal => Self {
                requested: mode.as_str().to_owned(),
                commitment: mode.as_str().to_owned(),
                durability: "none".to_owned(),
                status: "available-during-call-only".to_owned(),
                honest: true,
                reference: None,
            },
            PersistenceMode::HostPersistent => Self {
                requested: mode.as_str().to_owned(),
                commitment: mode.as_str().to_owned(),
                durability: "host".to_owned(),
                status: "host-persistent".to_owned(),
                honest: true,
                reference: Some(format!("outctl://capture/{capture_id}")),
            },
            PersistenceMode::Replicated => Self {
                requested: mode.as_str().to_owned(),
                commitment: mode.as_str().to_owned(),
                durability: "none".to_owned(),
                status: "unavailable-no-replica-backend".to_owned(),
                honest: true,
                reference: None,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct SavingsDecision {
    pub raw_estimated_tokens: usize,
    pub exposed_estimated_tokens: usize,
    pub estimated_tokens_saved: usize,
    pub exposure_reduced: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct StreamPresentationStats {
    pub stream: String,
    pub raw_bytes: u64,
    pub normalized_bytes: u64,
    pub raw_lines: u64,
    pub candidate_lines: u64,
    pub redacted: bool,
    pub normalized: bool,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct PresentationResult {
    pub kind: String,
    pub body: Option<String>,
    pub lossy: bool,
    pub redacted: bool,
    pub normalized: bool,
    pub digest: Option<String>,
    pub raw_bytes: u64,
    pub raw_lines: u64,
    pub exposed_bytes: usize,
    pub exposed_lines: usize,
    pub estimated_tokens: usize,
    pub omission: bool,
    pub mode: String,
    pub streams: Vec<StreamPresentationStats>,
    pub savings: SavingsDecision,
    pub persistence: PersistenceResult,
}

/// A bounded memory buffer that spills to a private file once its memory
/// threshold is reached.  It is useful for small safe outputs while ensuring
/// a pathological command cannot turn presentation into an in-memory copy of
/// the raw capture.
pub struct SpillBuffer {
    memory_limit: usize,
    memory: Vec<u8>,
    spill: Option<File>,
    spill_path: Option<PathBuf>,
    len: u64,
}

impl SpillBuffer {
    pub fn new(memory_limit: usize, spill_path: Option<&Path>) -> io::Result<Self> {
        if memory_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spill buffer memory limit must be positive",
            ));
        }
        Ok(Self {
            memory_limit,
            memory: Vec::with_capacity(memory_limit.min(READ_BYTES)),
            spill: None,
            spill_path: spill_path.map(Path::to_path_buf),
            len: 0,
        })
    }

    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.len = self.len.saturating_add(bytes.len() as u64);
        if self.spill.is_none() && self.memory.len() + bytes.len() <= self.memory_limit {
            self.memory.extend_from_slice(bytes);
            return Ok(());
        }
        if self.spill.is_none() {
            let path = self.spill_path.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "spill path is required when the memory limit is exceeded",
                )
            })?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&self.memory)?;
            self.memory.clear();
            self.spill = Some(file);
        }
        self.spill
            .as_mut()
            .expect("spill initialized")
            .write_all(bytes)
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn spilled(&self) -> bool {
        self.spill.is_some()
    }

    pub fn read_all(mut self) -> io::Result<Vec<u8>> {
        if let Some(mut file) = self.spill.take() {
            file.flush()?;
            let path = self
                .spill_path
                .take()
                .ok_or_else(|| io::Error::other("spilled buffer lost its backing path"))?;
            drop(file);
            let bytes = fs::read(&path)?;
            let _ = fs::remove_file(path);
            Ok(bytes)
        } else {
            Ok(self.memory)
        }
    }
}

#[derive(Clone, Debug)]
struct LineRecord {
    line: u64,
    text: String,
}

/// Streaming candidate extraction.  Only head, tail, and bounded diagnostic
/// candidates are retained; the complete normalized stream is never held.
pub struct StreamingCandidates {
    head_limit: usize,
    tail_limit: usize,
    candidate_limit: usize,
    max_line_bytes: usize,
    projection_bytes: usize,
    projection_lines: usize,
    pending: Vec<u8>,
    head: Vec<LineRecord>,
    tail: VecDeque<LineRecord>,
    candidates: Vec<LineRecord>,
    line_number: u64,
    normalized_bytes: u64,
    normalized_lines: u64,
    candidate_lines: u64,
    clipped_line: bool,
    small_output: Vec<u8>,
    small_output_limit: usize,
}

impl StreamingCandidates {
    pub fn new(options: &PresentationOptions) -> Self {
        Self {
            head_limit: options.head_lines,
            tail_limit: options.tail_lines,
            candidate_limit: options.candidate_context,
            max_line_bytes: options.max_logical_line_bytes,
            projection_bytes: options.max_bytes,
            projection_lines: options.max_lines,
            pending: Vec::new(),
            head: Vec::new(),
            tail: VecDeque::new(),
            candidates: Vec::new(),
            line_number: 0,
            normalized_bytes: 0,
            normalized_lines: 0,
            candidate_lines: 0,
            clipped_line: false,
            small_output: Vec::new(),
            small_output_limit: options.full_if_bytes.min(usize::MAX as u64) as usize + 1,
        }
    }

    pub fn consume(&mut self, text: &str) {
        let bytes = text.as_bytes();
        self.normalized_bytes = self.normalized_bytes.saturating_add(bytes.len() as u64);
        if self.small_output.len() <= self.small_output_limit {
            let room = self
                .small_output_limit
                .saturating_sub(self.small_output.len());
            self.small_output
                .extend_from_slice(&bytes[..bytes.len().min(room)]);
        }
        self.pending.extend_from_slice(bytes);
        while let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line = self.pending.drain(..=index).collect::<Vec<_>>();
            self.process_line(&line);
        }
        if self.pending.len() > self.max_line_bytes {
            self.pending.truncate(self.max_line_bytes);
            self.clipped_line = true;
        }
    }

    pub fn finish(&mut self) {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            self.process_line(&line);
        }
    }

    fn process_line(&mut self, bytes: &[u8]) {
        self.line_number += 1;
        self.normalized_lines += 1;
        let mut text = String::from_utf8_lossy(bytes).into_owned();
        if text.ends_with('\n') {
            text.pop();
            if text.ends_with('\r') {
                text.pop();
            }
        }
        if self.clipped_line {
            text.push_str(" [... line clipped]");
            self.clipped_line = false;
        }
        let record = LineRecord {
            line: self.line_number,
            text,
        };
        if self.head.len() < self.head_limit {
            self.head.push(record.clone());
        }
        self.tail.push_back(record.clone());
        while self.tail.len() > self.tail_limit {
            self.tail.pop_front();
        }
        if is_candidate(&record.text) && self.candidates.len() < self.candidate_limit {
            self.candidates.push(record);
            self.candidate_lines += 1;
        }
    }

    pub fn normalized_bytes(&self) -> u64 {
        self.normalized_bytes
    }

    pub fn normalized_lines(&self) -> u64 {
        self.normalized_lines
    }

    pub fn candidate_lines(&self) -> u64 {
        self.candidate_lines
    }

    fn full_text(&self) -> Option<String> {
        if self.normalized_bytes > self.small_output_limit.saturating_sub(1) as u64 {
            return None;
        }
        Some(String::from_utf8_lossy(&self.small_output).into_owned())
    }

    fn records_for(&self, mode: PresentationMode) -> Vec<LineRecord> {
        let mut records = match mode {
            PresentationMode::Compact => self.head.clone(),
            PresentationMode::Projected | PresentationMode::Auto => self.projected_records(),
            PresentationMode::Safe | PresentationMode::Metadata => Vec::new(),
        };
        records.sort_by_key(|record| record.line);
        records.dedup_by_key(|record| record.line);
        records
    }

    fn projected_records(&self) -> Vec<LineRecord> {
        // Reserve space for diagnostic candidates before filling ordinary
        // context.  A failure buried after thousands of routine lines must
        // remain reachable even when a caller chooses a very small budget.
        let candidate_budget = usize::max(1, self.projection_bytes / 2);
        let mut candidate_bytes = 0;
        let mut candidates = Vec::new();
        for record in &self.candidates {
            let bytes = record.text.len().saturating_add(1);
            if candidates.is_empty() || candidate_bytes + bytes <= candidate_budget {
                candidates.push(record.clone());
                candidate_bytes += bytes;
            }
        }
        let context_budget = usize::max(1, self.projection_bytes / 4);
        let mut context_bytes = 0;
        let mut context = Vec::new();
        for record in self.head.iter().chain(self.tail.iter()) {
            let bytes = record.text.len().saturating_add(1);
            if context.len() >= self.projection_lines || context_bytes + bytes > context_budget {
                continue;
            }
            context.push(record.clone());
            context_bytes += bytes;
        }
        candidates.extend(context);
        candidates
    }
}

fn is_candidate(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    [
        "error",
        "fatal",
        "failed",
        "failure",
        "traceback",
        "panic",
        "assert",
        "warning",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

struct ExactRedactor {
    patterns: Vec<Vec<u8>>,
    replacement: Vec<u8>,
    pending: Vec<u8>,
    max_pattern: usize,
    redacted: bool,
}

impl ExactRedactor {
    fn new(values: &[Vec<u8>]) -> Self {
        let mut patterns = values.to_vec();
        patterns.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self {
            max_pattern: patterns.iter().map(Vec::len).max().unwrap_or(0),
            patterns,
            replacement: b"[REDACTED]".to_vec(),
            pending: Vec::new(),
            redacted: false,
        }
    }

    fn feed(&mut self, bytes: &[u8], final_chunk: bool) -> Vec<u8> {
        self.pending.extend_from_slice(bytes);
        let mut output = Vec::new();
        loop {
            let found = self
                .patterns
                .iter()
                .filter_map(|pattern| {
                    find_bytes(&self.pending, pattern).map(|index| (index, pattern.len()))
                })
                .min_by_key(|(index, _)| *index);
            if let Some((index, length)) = found {
                output.extend_from_slice(&self.pending[..index]);
                output.extend_from_slice(&self.replacement);
                self.pending.drain(..index + length);
                self.redacted = true;
                continue;
            }
            let keep = if final_chunk {
                0
            } else {
                self.max_pattern.saturating_sub(1)
            };
            if self.pending.len() > keep {
                let split = self.pending.len() - keep;
                output.extend_from_slice(&self.pending[..split]);
                self.pending.drain(..split);
            }
            break;
        }
        output
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct ControlSanitizer {
    escape: Vec<u8>,
    escape_kind: u8,
    in_escape: bool,
    normalized: bool,
}

impl ControlSanitizer {
    fn new() -> Self {
        Self {
            escape: Vec::new(),
            escape_kind: 0,
            in_escape: false,
            normalized: false,
        }
    }

    fn feed(&mut self, bytes: &[u8], final_chunk: bool) -> String {
        let mut output = Vec::new();
        for byte in bytes {
            if self.in_escape {
                self.escape.push(*byte);
                self.normalized = true;
                if self.escape.len() == 1 {
                    self.escape_kind = match *byte {
                        b'[' => 1, // CSI: terminate at a final byte.
                        b']' => 2, // OSC: terminate at BEL or ST.
                        _ => 3,    // Other two-byte escape: consume one byte.
                    };
                    if self.escape_kind == 3 {
                        self.in_escape = false;
                        self.escape.clear();
                    }
                } else if (self.escape_kind == 1 && *byte >= 0x40 && *byte <= 0x7e)
                    || (self.escape_kind == 2 && *byte == 0x07)
                {
                    self.in_escape = false;
                    self.escape.clear();
                }
                continue;
            }
            if *byte == 0x1b {
                self.in_escape = true;
                self.escape.clear();
                self.escape_kind = 0;
                self.normalized = true;
            } else if *byte == b'\n' {
                output.push(*byte);
            } else if *byte == b'\r' {
                output.push(b'\n');
                self.normalized = true;
            } else if *byte == b'\t' {
                output.extend_from_slice(b"    ");
                self.normalized = true;
            } else if *byte < 0x20 || *byte == 0x7f {
                output.extend_from_slice(format!("\\x{byte:02x}").as_bytes());
                self.normalized = true;
            } else {
                output.push(*byte);
            }
        }
        if final_chunk && self.in_escape {
            self.in_escape = false;
            self.escape.clear();
            self.escape_kind = 0;
        }
        String::from_utf8_lossy(&output).into_owned()
    }
}

fn consume_transformed(
    candidates: &mut StreamingCandidates,
    redactor: &mut ExactRedactor,
    sanitizer: &mut ControlSanitizer,
    bytes: &[u8],
    final_chunk: bool,
) {
    let redacted = redactor.feed(bytes, final_chunk);
    if !redacted.is_empty() {
        let text = sanitizer.feed(&redacted, final_chunk);
        candidates.consume(&text);
    }
}

fn read_stream(
    path: &Path,
    name: &str,
    options: &PresentationOptions,
) -> io::Result<(StreamingCandidates, StreamPresentationStats, bool)> {
    let mut file = File::open(path)?;
    let raw_bytes = file.metadata()?.len();
    let mut candidates = StreamingCandidates::new(options);
    let mut redactor = ExactRedactor::new(&options.exact_redaction_values);
    let mut sanitizer = ControlSanitizer::new();
    let mut buffer = [0_u8; READ_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        consume_transformed(
            &mut candidates,
            &mut redactor,
            &mut sanitizer,
            &buffer[..read],
            false,
        );
    }
    let redacted = redactor.feed(&[], true);
    let text = sanitizer.feed(&redacted, true);
    candidates.consume(&text);
    candidates.finish();
    let stats = StreamPresentationStats {
        stream: name.to_owned(),
        raw_bytes,
        normalized_bytes: candidates.normalized_bytes(),
        raw_lines: candidates.normalized_lines(),
        candidate_lines: candidates.candidate_lines(),
        redacted: redactor.redacted,
        normalized: sanitizer.normalized,
    };
    Ok((candidates, stats, redactor.redacted || sanitizer.normalized))
}

struct BoundedWriter<'a> {
    options: &'a PresentationOptions,
    bytes: Vec<u8>,
    lines: usize,
    tokens: usize,
    omitted: bool,
}

impl<'a> BoundedWriter<'a> {
    fn new(options: &'a PresentationOptions) -> Self {
        Self {
            options,
            bytes: Vec::new(),
            lines: 0,
            tokens: 0,
            omitted: false,
        }
    }

    fn add_line(&mut self, line: &str) {
        let mut value = line.as_bytes().to_vec();
        value.push(b'\n');
        if value.len() > self.options.max_bytes {
            value.truncate(self.options.max_bytes);
            self.omitted = true;
        }
        if self.bytes.len() + value.len() > self.options.max_bytes
            || self.lines + 1 > self.options.max_lines
            || estimate_tokens(self.bytes.len() + value.len()) > self.options.max_estimated_tokens
        {
            self.omitted = true;
            return;
        }
        self.bytes.extend_from_slice(&value);
        self.lines += 1;
        self.tokens = estimate_tokens(self.bytes.len());
    }

    fn finish(mut self) -> (Vec<u8>, bool) {
        if self.omitted {
            let marker = b"[... output omitted; retrieve the capture for complete evidence]\n";
            while self.bytes.len() + marker.len() > self.options.max_bytes && !self.bytes.is_empty()
            {
                self.bytes.pop();
            }
            if self.bytes.len() + marker.len() <= self.options.max_bytes
                && self.lines < self.options.max_lines
                && estimate_tokens(self.bytes.len() + marker.len())
                    <= self.options.max_estimated_tokens
            {
                self.bytes.extend_from_slice(marker);
                self.lines += 1;
            } else if self.bytes.is_empty() {
                self.bytes.extend_from_slice(b".");
            }
        }
        (self.bytes, self.omitted)
    }
}

fn render_records(records: &[LineRecord], options: &PresentationOptions) -> (Vec<u8>, bool) {
    let mut writer = BoundedWriter::new(options);
    let mut previous: Option<(&str, u64, u64)> = None;
    for record in records {
        if let Some((text, first, count)) = previous.take() {
            if text == record.text && record.line == first + count {
                previous = Some((text, first, count + 1));
                continue;
            }
            if count > 1 {
                writer.add_line(&format!(
                    "{text} [line repeated {count} times; raw lines {first}-{}]",
                    first + count - 1
                ));
            } else {
                writer.add_line(text);
            }
        }
        previous = Some((&record.text, record.line, 1));
    }
    if let Some((text, first, count)) = previous {
        if count > 1 {
            writer.add_line(&format!(
                "{text} [line repeated {count} times; raw lines {first}-{}]",
                first + count - 1
            ));
        } else {
            writer.add_line(text);
        }
    }
    writer.finish()
}

fn estimate_tokens(bytes: usize) -> usize {
    bytes.div_ceil(4)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Render two already-captured streams without rerunning the command.
pub fn render_capture_files(
    stdout: &Path,
    stderr: &Path,
    capture_id: &str,
    options: &PresentationOptions,
) -> io::Result<PresentationResult> {
    options.validate()?;
    let (stdout_candidates, stdout_stats, stdout_changed) = read_stream(stdout, "stdout", options)?;
    let (stderr_candidates, stderr_stats, stderr_changed) = read_stream(stderr, "stderr", options)?;
    let raw_bytes = stdout_stats.raw_bytes + stderr_stats.raw_bytes;
    let raw_lines = stdout_stats.raw_lines + stderr_stats.raw_lines;
    let normalized = stdout_changed || stderr_changed;
    let redacted = stdout_stats.redacted || stderr_stats.redacted;
    let total_normalized =
        stdout_candidates.normalized_bytes() + stderr_candidates.normalized_bytes();
    let requested = match options.mode {
        PresentationMode::Auto if total_normalized <= options.full_if_bytes => {
            PresentationMode::Safe
        }
        PresentationMode::Auto => PresentationMode::Projected,
        other => other,
    };
    let (mut body_bytes, mut omission, kind) = match requested {
        PresentationMode::Metadata => (None, true, "metadata-only"),
        PresentationMode::Safe => {
            let mut writer = BoundedWriter::new(options);
            let mut omitted = false;
            for (label, candidate) in [
                ("[stdout]", &stdout_candidates),
                ("[stderr]", &stderr_candidates),
            ] {
                if candidate.normalized_bytes() > 0 {
                    writer.add_line(label);
                }
                if let Some(text) = candidate.full_text() {
                    for line in text.lines() {
                        writer.add_line(line);
                    }
                } else {
                    omitted = true;
                }
            }
            let (body, writer_omitted) = writer.finish();
            (Some(body), omitted || writer_omitted, "raw-safe")
        }
        PresentationMode::Compact => {
            let (stdout_body, stdout_omitted) =
                render_records(&stdout_candidates.records_for(requested), options);
            let (stderr_body, stderr_omitted) =
                render_records(&stderr_candidates.records_for(requested), options);
            let body = stream_sections(stdout_body, stderr_body);
            (
                Some(body),
                stdout_omitted || stderr_omitted,
                "bounded-projection",
            )
        }
        PresentationMode::Projected => {
            let (stdout_body, stdout_omitted) =
                render_records(&stdout_candidates.records_for(requested), options);
            let (stderr_body, stderr_omitted) =
                render_records(&stderr_candidates.records_for(requested), options);
            let body = stream_sections(stdout_body, stderr_body);
            (
                Some(body),
                stdout_omitted || stderr_omitted,
                "bounded-projection",
            )
        }
        PresentationMode::Auto => unreachable!("auto is resolved above"),
    };
    omission = omission
        || body_bytes.as_ref().is_some_and(|body| {
            total_normalized > body.len() as u64
                || body.len() > options.max_bytes
                || body.iter().filter(|byte| **byte == b'\n').count() > options.max_lines
                || estimate_tokens(body.len()) > options.max_estimated_tokens
        });
    if let Some(body) = body_bytes.take() {
        let (bounded, bounded_omission) = enforce_body_budget(body, options, omission);
        body_bytes = Some(bounded);
        omission = bounded_omission;
    }
    let (body, exposed_bytes, exposed_lines, exposed_tokens, digest_value) = match body_bytes {
        Some(body) => {
            let lines = body.iter().filter(|byte| **byte == b'\n').count();
            let tokens = estimate_tokens(body.len());
            let digest_value = digest(&body);
            (
                Some(String::from_utf8_lossy(&body).into_owned()),
                body.len(),
                lines,
                tokens,
                Some(digest_value),
            )
        }
        None => (None, 0, 0, 0, None),
    };
    let raw_tokens = estimate_tokens(raw_bytes as usize);
    let savings = SavingsDecision {
        raw_estimated_tokens: raw_tokens,
        exposed_estimated_tokens: exposed_tokens,
        estimated_tokens_saved: raw_tokens.saturating_sub(exposed_tokens),
        exposure_reduced: exposed_tokens < raw_tokens,
        reason: if requested == PresentationMode::Safe && !omission {
            "safe-small-output-is-cheaper".to_owned()
        } else if requested == PresentationMode::Metadata {
            "metadata-only-policy".to_owned()
        } else {
            "bounded-presentation-required".to_owned()
        },
    };
    Ok(PresentationResult {
        kind: kind.to_owned(),
        body,
        lossy: omission || normalized || redacted,
        redacted,
        normalized,
        digest: digest_value,
        raw_bytes,
        raw_lines,
        exposed_bytes,
        exposed_lines,
        estimated_tokens: exposed_tokens,
        omission,
        mode: requested.as_str().to_owned(),
        streams: vec![stdout_stats, stderr_stats],
        savings,
        persistence: PersistenceResult::for_capture(options.persistence, capture_id),
    })
}

fn stream_sections(stdout: Vec<u8>, stderr: Vec<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    if !stdout.is_empty() {
        body.extend_from_slice(b"[stdout]\n");
        body.extend_from_slice(&stdout);
    }
    if !stderr.is_empty() {
        body.extend_from_slice(b"[stderr]\n");
        body.extend_from_slice(&stderr);
    }
    body
}

fn enforce_body_budget(
    body: Vec<u8>,
    options: &PresentationOptions,
    omitted: bool,
) -> (Vec<u8>, bool) {
    let mut writer = BoundedWriter::new(options);
    writer.omitted = omitted;
    for line in String::from_utf8_lossy(&body).lines() {
        writer.add_line(line);
    }
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::{
        render_capture_files, PersistenceMode, PresentationOptions, SpillBuffer,
        StreamingCandidates,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("outctl-w4-{label}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn spill_buffer_keeps_memory_bounded_and_cleans_spill() {
        let directory = root("spill");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("spill.raw");
        let mut buffer = SpillBuffer::new(4, Some(&path)).unwrap();
        buffer.write(b"12345").unwrap();
        assert!(buffer.spilled());
        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.read_all().unwrap(), b"12345");
        assert!(!path.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn streaming_candidates_are_bounded_and_find_failures() {
        let options = PresentationOptions {
            candidate_context: 2,
            head_lines: 1,
            tail_lines: 1,
            ..PresentationOptions::default()
        };
        let mut candidates = StreamingCandidates::new(&options);
        candidates.consume("one\nnoise\nERROR marker\nlast\n");
        candidates.finish();
        assert_eq!(candidates.candidate_lines(), 1);
        assert_eq!(candidates.normalized_lines(), 4);
    }

    #[test]
    fn adaptive_rendering_redacts_across_read_boundaries() {
        let directory = root("render");
        fs::create_dir_all(&directory).unwrap();
        let stdout = directory.join("stdout.raw");
        let stderr = directory.join("stderr.raw");
        let mut stdout_bytes = vec![b'x'; 16_375];
        stdout_bytes.extend_from_slice(b"ERROR secret-value\n");
        fs::write(&stdout, stdout_bytes).unwrap();
        fs::write(&stderr, b"\x1b]0;title\x07warning\x1b[2J\n").unwrap();
        let options = PresentationOptions {
            exact_redaction_values: vec![b"secret-value".to_vec()],
            persistence: PersistenceMode::ProcessLocal,
            ..PresentationOptions::default()
        };
        let result = render_capture_files(&stdout, &stderr, "capture-1", &options).unwrap();
        assert!(result.redacted);
        let body = result.body.unwrap();
        assert!(!body.contains("secret-value"));
        assert!(!body.contains('\u{1b}'));
        assert!(!body.contains("title"));
        assert_eq!(result.persistence.durability, "none");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn oversized_output_uses_projected_candidates_and_explicit_loss() {
        let directory = root("large");
        fs::create_dir_all(&directory).unwrap();
        let stdout = directory.join("stdout.raw");
        let stderr = directory.join("stderr.raw");
        let mut bytes = Vec::new();
        for index in 0..10_000 {
            bytes.extend_from_slice(format!("line-{index}\n").as_bytes());
        }
        bytes.extend_from_slice(b"ERROR unique-marker\n");
        fs::write(&stdout, bytes).unwrap();
        fs::write(&stderr, b"").unwrap();
        let options = PresentationOptions {
            max_bytes: 512,
            max_lines: 32,
            max_estimated_tokens: 128,
            full_if_bytes: 32,
            ..PresentationOptions::default()
        };
        let result = render_capture_files(&stdout, &stderr, "capture-2", &options).unwrap();
        let body = result.body.unwrap();
        assert_eq!(result.mode, "projected");
        assert!(result.lossy);
        assert!(result.omission);
        assert!(body.contains("ERROR unique-marker"));
        assert!(body.contains("omitted"));
        assert!(result.exposed_bytes <= options.max_bytes);
        fs::remove_dir_all(directory).unwrap();
    }
}

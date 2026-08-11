# W5 policy compiler and trust-runtime handoff

**Backlog:** `#2137`
**Baseline:** `91c50c227160a9b1cd98c52b82181b78c4d63f06`
**Scope:** compile commissioned policy into frozen v2 snapshots and fail closed
before a native sink can widen disclosure, weaken capture, or consume an
unregistered exact secret.

## Delivered boundary

- Python loads at most 1 MiB of UTF-8 YAML through descriptor-relative,
  `O_NOFOLLOW` directory and file opens beneath an explicit policy root.
  Absolute paths, `..`, symlink components, non-regular sources, duplicate
  YAML keys, unknown fields, contradictory types, and unbounded lifetimes fail
  closed.
- `CommissioningContext` requires independent, digest-bearing provenance for
  both the trust-domain and commissioned claims. Claim names, issuers, evidence
  references, and evidence digests are sorted and bound into the compiled
  source digest; claim values are represented by the snapshot session fields
  and policy digest. Exact secrets cannot be evidence references.
- Compilation deterministically sorts sink targets, canonicalizes UTC time,
  binds source/session/sinks/capture/external-authority/expiry/cache semantics,
  derives `policy_digest`, then derives `snapshot_id` and its cache key. The
  checked-in W5 snapshot is reproduced byte-semantically by a Python test and
  accepted as a digest/binding vector by Rust.
- The sink lattice has four named request targets. `safe-unredacted` requires a
  commissioned trusted-local sink; `sanitized` requires redaction;
  `metadata-only` exposes no body; `deny` rejects before execution. A request
  must exactly match the compiled target, trust domain, and action, so claiming
  a narrower domain cannot redirect a more permissive compiled sink.
- The Rust evaluator reparses strict snapshot and request documents, verifies
  the canonical semantic digest and derived snapshot/cache identity, enforces
  issue/expiry/cache bounds, binds runner workspace/session/cwd context, and
  selects capture commitment plus presentation action. It preserves the schema
  distinction between omitted and explicit-null required request fields;
  omitted `shell_command`, `timeout_ms`, or `stdin.ref` values fail before
  spool creation. Replicated persistence remains an explicit pre-spawn
  unsupported outcome because no replica backend exists.
- Python and Rust protected-secret registries are bounded, in-memory-only APIs.
  They have no serializer, hide values from debug/errors, reject duplicates,
  and overwrite retained buffers on explicit cleanup/drop where their runtime
  permits. Only a sanitized decision resolves opaque request references into
  the W4 streaming exact-value redactor. Trusted-unredacted and metadata-only
  decisions do not resolve those values.
- Policy lint/explain are available as raw-free control APIs and through
  `outctl policy lint|explain --policy-root ... --context ... SOURCE`. Their
  diagnostics never copy source values or commissioning claim values.
- Native decision metadata echoes only the snapshot/source/session/sink
  provenance and always says `execution_authorized=false`. Policy evaluation
  has no command authorization, retry, lifecycle, audit-judgment, or
  publication operation.
- `capture_request_with_policy` is the policy-bound native execution entry
  point. It requires an external-runner authorization assertion, derives argv,
  cwd, inherited/empty/allowlisted environment, timeout, workspace binding,
  capture requirement, persistence, sink mode, and protected redactions from
  the exact verified documents, and rejects missing authority before spool
  creation. Callers cannot evaluate one request and substitute another command
  or presentation configuration at this boundary.

## Conformance and attacks

The W5 tests cover trusted-local safe-unredacted, restricted and export
sanitized, metadata-only, deny, exact request/snapshot/cache bindings,
millisecond expiry, canonical cross-language digests, claim-evidence changes,
workspace/session/cwd substitution, sink downgrade attempts, symlink and path
traversal, malformed/oversized policy, missing protected refs, bounded secret
registration, and secret-free diagnostics/debug/serialization.

The W3 descriptor-relative capture boundary and W4 descriptor-backed spill and
presentation boundary are unchanged. Ephemeral cleanup therefore retains the
documented empty capture-directory tombstone; W5 neither removes it by path nor
claims W7 retention semantics.

## Intentional limits

- W5 exposes policy-bound capture as a native library boundary; the native CLI
  does not accept snapshots or exact secrets as ordinary argv/environment
  values. Runner integration must use `capture_request_with_policy`, not build
  independent capture options from policy metadata.
- The engine advertises v2 `RunRequest` and `PolicySnapshot` evaluation, but it
  does not advertise a v2 `RunResult` writer. The current structured native
  capture result and v1-readable storage stay intact until the later manifest
  and compatibility waves.
- Cwd validation is lexical against the runner-provided workspace root. The
  embedding runner remains responsible for pinning that directory at spawn;
  W5 does not add a second pathname-based filesystem authority.
- Exact Rust 1.85.1 verification remains unavailable on this host. Native
  gates use the installed Nix Rust 1.97.0 toolchain, matching the W4 host
  limitation.
- There is still no remote replica backend, extension execution, stdin,
  explicit shell, v2 storage migration, retention collector, deployment, or
  policy promotion authority in this wave.

## Verification

The final candidate was checked with the installed Nix Rust 1.97.0 toolchain
and Python 3.12.13:

- `cargo test --workspace --all-targets --no-fail-fast`: 53 Rust tests passed
  (48 engine, 4 CLI, 1 contracts); the presentation benchmark target also ran
  its bounded 3,888,913-byte fixture.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo-fmt --all -- --check`: passed.
- focused W5/v2 Python tests: 33 passed; the post-build packaging/v2/W5 set:
  26 passed.
- `uv run pytest`: 236 passed.
- `uv run ruff check .`: passed. The W5 Python files also pass the formatter;
  repository-wide formatter output identifies older, out-of-scope formatting
  differences and was not applied.
- `uv run mypy src`: passed over 32 source files.
- `uv build`: source distribution and wheel built successfully.
- AgentOps verification-artifact validation and `git diff --check`: passed.

No raw command capture, provider, credential, Sprintctl, ActionQ, audit,
deployment, push, merge, or external publication was accessed or mutated.

Rollback remains the reviewed Python/v1 selection boundary:

```text
OUTCTL_ENABLED=0
OUTCTL_MODE=bypass
```

Rollback does not rewrite snapshots, captures, receipts, or workflow state.

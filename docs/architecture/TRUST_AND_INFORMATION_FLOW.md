# Trust and information flow

Classification, disclosure, persistence, and export are separate policy
dimensions. A commissioned trusted local sink may receive classified material
under an explicit safe-unredacted rule; restricted or export sinks sanitize,
reduce to metadata, or deny it.

Required invariants:

- exact secret values are registered through a protected channel and never
  enter policy snapshots, receipts, telemetry, or digest vectors;
- required transforms run before model/export exposure;
- raw exact, raw sanitized, manifest-only, and projection-only artifacts are
  different classes and hashes;
- policy provenance and digest are pinned to the request and result;
- immutable policy snapshots are cache-owned by Python control, keyed and
  expiry-checked by `snapshot_id`, reference, and digest;
- policy cannot authorize a command, retry, action, audit finding, or
  publication;
- command output remains untrusted data, including prompt-like text and
  terminal control sequences.

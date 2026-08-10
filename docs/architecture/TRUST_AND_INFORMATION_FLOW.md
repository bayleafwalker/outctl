# Trust domains and information flow

## Principle

Outctl separates classification from disclosure. A value can be classified as
secret and still be usable by the commissioned agent inside its originating
trusted domain. What crosses a sink boundary is governed independently.

The policy decision is a lattice over at least:

- actor and commissioner;
- trust domain and session binding;
- workspace and host;
- data claims (credential, identifier, path, operational data, unknown);
- destination sink;
- capture, persistence, durability, and retention commitments;
- allowed transformation (`allow`, `sanitize`, `metadata-only`, `deny`).

Command authorization remains external. Capture is never permission to execute.

## Required scenarios

One policy model must represent all of these without contradictory flags:

1. A trusted commissioned agent receives a known secret unredacted in its active
   session while retention and export stay restricted.
2. A restricted agent receives a sanitized projection of the same output.
3. A public/export sink receives sanitized or metadata-only material.
4. A denied sink receives neither raw nor transformed content.

Exact secret values may be registered through a protected inherited descriptor
or harness API, never a value-bearing command-line flag. Receipts and telemetry
record claims and decisions, never secret values.

## Provenance and downgrade resistance

Every decision records policy schema version, canonical digest, source bundle,
commissioning context, selected rule, claims, sink, transformations, and engine
capabilities. Mutable unpinned policy names are not sufficient for execution.
An unauthorized caller cannot lower the sink or trust requirements. Unknown or
expired context follows an explicit fail mode.

## Persistence

Persistence describes whether bytes survive the invocation; durability
describes the strength and location of that commitment. These are independent
from visibility. A trusted view can be unredacted yet ephemeral, while a
sanitized export can be host-persistent or replicated.

Receipts use the workspace vocabulary: `session-local`, `host-persistent`,
`cross-host-replicated`, and `durable-authoritative`. Outctl capture storage is
not promoted to audit or knowledge authority by naming it durable.

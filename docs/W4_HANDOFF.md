# W4 native adaptive presentation handoff

**Backlog:** `#2136`
**Scope:** native Rust adaptive presentation and honest local persistence on
top of the reviewed W3 capture boundary.

## Delivered boundary

- Incremental exact-value redaction and control/ANSI neutralization happen
  before any presentation body is exposed.
- Streaming candidates retain bounded head, tail, and diagnostic records;
  oversized output selects a projected view with an explicit omission marker.
- `auto` chooses safe output for small normalized results and projected output
  otherwise. Explicit safe, compact, projected, and metadata modes are
  available through the native CLI.
- `SpillBuffer` provides bounded-memory buffering with mode `0600` spill files.
- Persistence is reported independently from presentation. Host-persistent
  captures retain an opaque `outctl://capture/` reference; memory-only and
  process-local captures remove their temporary material before return; a
  replicated request fails before spawn without a configured replica backend.
- The Python engine, v1 manifest writer, direct-argv process semantics,
  concurrent drainers, quota, path, and retrieval safety remain unchanged.

## Focused evidence

- `cargo test --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --all -- --check`
- `cargo bench -p outctl-engine --bench presentation`

The native stress benchmark processes about 3.9 MiB of captured fixture data,
exposes about 2 KiB, and reports omission without storing the complete
normalized stream in memory.

## Intentional W4 limits

There is no remote replica backend, policy compiler, secret-registration
channel, or v2 `RunRequest` adapter in W4. Exact redaction values are accepted
only by the native library boundary; exposing them as ordinary CLI arguments is
intentionally not added. Replication and policy-snapshot evaluation remain
later-wave responsibilities.

Rollback remains the W3/Python boundary:

```text
OUTCTL_ENABLED=0
OUTCTL_MODE=bypass
```

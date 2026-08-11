# W4 native adaptive presentation handoff

**Backlog:** `#2136`
**Scope:** native Rust adaptive presentation and honest local persistence on
top of the reviewed W3 capture boundary.

## Delivered boundary

- Incremental exact-value redaction and control/ANSI neutralization happen
  before any presentation body is exposed.
- Sanitizer state is scalar and bounded: unterminated OSC/CSI/control input is
  discarded incrementally while OSC BEL and ST (`ESC \\`) termination remains
  correct across chunk boundaries.
- Streaming candidates retain bounded head, tail, and diagnostic records;
  oversized output selects a projected view with an explicit omission marker.
  Provisional safe output is a capped `SpillBuffer` (16 KiB memory threshold,
  64 KiB hard ceiling), and spill reads are prefix-bounded.
- Production presentation consumes descriptor-relative handles pinned before
  W3 finalization rename; `openat(O_NOFOLLOW)` plus regular-file `fstat` checks
  prevent capture-root/file pathname replacement from changing rendered bytes.
- `auto` and `minimum-savings` compare final rendered byte/token/line costs,
  including bounded safe bodies carrying omission markers;
  explicit safe, compact, projected, and metadata modes report `raw-safe`,
  `bounded-projection`, and `metadata-only` kinds. Empty successful output is
  explicitly `empty-success` and raw-safe; nonempty content sanitized entirely
  away is lossy and omission-marked rather than empty-success.
- `full-if-bytes` and all presentation budgets are validated before spawn;
  checked arithmetic and bounded record/transform limits prevent overflow or
  unbounded provisional retention. Tiny budgets that cannot represent a loss
  marker are rejected before spawn.
- OSC BEL and ST (`ESC \\`) terminators are sanitized across read boundaries.
- `SpillBuffer` provides bounded-memory buffering with mode `0600` spill files.
- Persistence is reported independently from presentation. Host-persistent
  captures retain an opaque `outctl://capture/` reference; memory-only and
  process-local captures remove their temporary material before return. Lossy
  ephemeral results say evidence is unavailable and do not offer retrieval;
  a replicated request fails before spawn without a configured replica backend.
- The Python engine, v1 manifest writer, direct-argv process semantics,
  concurrent drainers, quota, path, and retrieval safety remain unchanged.

## Final verification evidence

The final candidate was checked with Cargo visible to Python through the Nix
toolchain path (Cargo 1.97.0, rustc/rustfmt/clippy 1.97.0, GCC 15.3.0):

- The repository pins Rust `1.85.1` in `rust-toolchain.toml`, but Rust 1.85.1
  and `rustup` are unavailable on this host. All feasible native gates ran
  with the installed Nix Rust 1.97.0 toolchain; exact 1.85.1 compatibility is
  the remaining environment-dependent limitation.

- `cargo test --workspace --all-targets --no-fail-fast`: 33 Rust tests passed
  (29 engine, 3 CLI, 1 contracts); the benchmark target also ran.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo-fmt --all -- --check`: passed. The host Cargo binary does not expose
  the `fmt` subcommand, so the installed `cargo-fmt` companion was invoked
  directly; this is a command-invocation deviation in addition to the pinned
  Rust 1.85.1 availability limitation above.
- `cargo bench -p outctl-engine --bench presentation`: passed; incremental
  3,888,913-byte fixture, five renders, 186–247 ms optimized render range in
  the final benchmark run, bounded exposure, candidate retention, safe-small,
  explicit-mode, tiny-budget, and spill assertions all passed. The bounded
  sanitizer regression streamed 32 MiB unterminated OSC/CSI input without
  retaining the sequence; the handle regression rendered trusted bytes after
  adversarial capture-root replacement.
- `uv sync --all-extras --dev`: passed.
- `uv run pytest`: **220 passed in 30.31s** with the Cargo/Rust/GCC path
  exported.
- `uv run ruff check .`: **All checks passed!**
- `uv run mypy src`: **Success: no issues found in 31 source files**.
- `uv build`: source distribution and wheel built successfully.
- `python /projects/dev/agentops/templates/dispatch/scripts/validate_verification_artifacts.py --root .`:
  repository dispatch file valid; no verification artifacts found.
- Direct CLI reproduction of `--full-if-bytes 18446744073709551615` returned
  exit 125 with `OUTCTL_PRESPAWN_INVALID_REQUEST` and left the probe spool
  root empty.

The native stress benchmark processes about 3.9 MiB of captured fixture data,
exposes only the configured bounded projection, and reports omission without
constructing the complete fixture in one in-memory buffer.

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

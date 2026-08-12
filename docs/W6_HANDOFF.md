# W6 extensions and command-scope handoff

**Status:** candidate complete on 2026-08-12
**Backlog:** Outctl #2138
**Boundary:** extensions add facts and projections, never authorization

## Delivered command modes

- Direct argv remains generic. No registration or command-name allowlist is
  consulted, and the ordinary native path starts no Python.
- Explicit shell is a policy-bound library mode. A request must match one
  complete reviewed interpreter argv such as `[/bin/sh, -c]`; the engine adds
  the bounded command string. There is no implicit interpreter or fallback.
- Stdin defaults to `/dev/null`. Explicit inheritance is supported by the
  native library and CLI. `file-ref` is an opaque `outctl://stdin/...` handle
  resolved only from a process-memory registry: at most 16 references, 16 MiB
  per value, and 32 MiB aggregate. Values have redacted `Debug` output and are
  zeroized on last release. The CLI deliberately does not accept file paths or
  expose the registry.
- PTY, live output, and parent-shell state are capability fields and explicit
  request requirements. The W6 engine advertises them as unsupported and
  returns a typed pre-capture error without creating a spool.

The compiled `command_scope` is part of canonical policy material. Python and
Rust validate its mode sets, reviewed shell argv, stdin modes, and
contradictions. Example v2 documents carry the new exact snapshot binding.

## Delivered extension path

Discovery reads only installed distribution metadata for the
`outctl.extensions.v1` group. It does not load an entry point. Every selected
extension is pinned by extension ID, distribution, version, target, API
version, and a bounded SHA-256 distribution-manifest fingerprint.

One explicit slow-path invocation uses canonical duplicate-rejecting JSON with
a 64 KiB request ceiling, a caller-selected result ceiling up to 64 KiB, and a
deadline up to five seconds. Commissioning binds an exact context digest;
projection binds the exact snapshot ID, policy reference, and policy digest.

The parent verifies a root-owned executable bubblewrap target that is
executable and not group/world-writable. The worker receives only explicit
read-only runtime and installed-distribution roots, a new `/tmp`, `/proc`, and
`/dev`, no host network namespace, no inherited environment, and no inherited
file descriptors. It applies CPU, address-space, file-size, descriptor,
process-count, and core-dump limits followed by irreversible seccomp denial of
fork/clone, exec, and socket operations. Missing or untrusted isolation fails
closed; extension code is never loaded in the parent.

Only these accepted payloads cross the boundary:

```text
commissioning: {"facts": <bounded JSON object>}
projection:    {"title": <short string>, "lines": <bounded strings>, "lossy": <bool>}
```

Authority, trust, capture, persistence, disclosure, redaction, secret,
command, stdin, lifecycle, and budget-like fields are rejected recursively.
Keys are compared by compact semantic spelling, so separator, compact,
camelCase, and PascalCase variants fail identically. Contribution records take
an immutable deep snapshot and rederive the exact isolated-result digest before
canonicalization; a valid-looking payload change cannot retain stale source
provenance.
Accepted commissioning fact records bind their extension pin, invocation,
result digest, and payload into policy `source_digest`. They are not merged
into commissioning claims, command scope, sink actions, or capture policy.

The Kubernetes and custom examples are independent Python distributions. Both
exercise the same generic entry-point discovery and isolation path; no
extension-specific Rust code exists.

## Verification and limits

Final correction gates pass 282 Python tests, including real bubblewrap and
native-binary coverage, plus 64 Rust unit tests (5 CLI, 1 contracts, 58 engine)
and the presentation bench. Rust fmt/check, Clippy with warnings denied, Ruff,
strict Mypy over 37 source files, wheel/package checks, artifact validation,
and diff validation also pass.

Coverage includes generic unknown direct argv, no-Python native execution,
null and inherited stdin, exact reviewed shell matching, opaque stdin bounds,
unsupported pre-spool requirements, side-effect-free discovery, pin mutation,
duplicate JSON, request/result exact limits and plus-one rejection, exact phase
payloads, deterministic contribution binding, real bubblewrap isolation,
workspace/spool invisibility, cleared secrets, closed descriptors, denied
fork/exec/network, output floods, deadlines, and missing-isolation no-fallback.

The host does not provide Rust 1.85.1. Verification therefore uses the pinned
available Nix Rust 1.97.0 toolchain; release automation must still exercise the
repository's Rust 1.85.1 compatibility gate. The extension worker supports
Linux x86_64 and aarch64 seccomp syscall tables. Other architectures return
an explicit bounded failure rather than running unsandboxed.

W6 does not add a v2 `RunResult` writer or promote v2 storage. W4's empty-input
tombstone caveat remains until W7. It does not implement PTY, live streaming,
parent-shell mutation, path-backed stdin, policy promotion, scheduling,
lifecycle transitions, retries, or deployment.

Rollback remains `OUTCTL_ENABLED=0` and `OUTCTL_MODE=bypass`; engine rollback
does not migrate capture state. Extension callers disable the explicit slow
path by omitting invocation entirely. No-extension compilation preserves the
no-extension source vector.

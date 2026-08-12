# ADR-0005: Generic command baseline and bounded extensions

**Status:** Accepted — W6 implemented 2026-08-12

Direct argv is universal and needs no command-specific parser. Explicit shell
is an exact reviewed interpreter argv plus one bounded command string; there is
no implicit interpreter selection or fallback. Stdin is null by default and is
enabled only as explicit inheritance or an opaque process-memory file reference
within the compiled command scope. PTY, live output, and parent-shell state are
typed unsupported requirements and fail before capture creation.

Python extensions are discovered from installed `outctl.extensions.v1` entry
point metadata without importing their code. Exact distribution fingerprints,
invocation digests, deadlines, and byte budgets are pinned before a single
explicit slow-path call. The isolated worker runs through verified bubblewrap,
a cleared environment, read-only distribution mounts, resource limits, and an
irreversible seccomp deny list for process creation, executable replacement,
and networking. Missing isolation is unavailable, never an in-process fallback.

W6 narrows the earlier candidate list: commissioning accepts only an exact
`{"facts": {...}}` contribution, while projection accepts only bounded title,
lines, and lossy metadata. Commissioning facts may be bound into policy source
identity, but are never merged into trust claims, command scope, capture policy,
or execution authorization. Kubernetes and custom examples are separately
packaged Python distributions and require no Rust core edit.

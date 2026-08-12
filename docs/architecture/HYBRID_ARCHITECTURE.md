# Hybrid Rust and Python architecture

```text
policy + trust commissioning + extensions (Python)
                         |
                         v
                 pinned PolicySnapshot
                         |
runner -> RunRequest -> Rust engine -> RunResult -> sink
                              |
                    capture/retrieval/verification
```

Rust owns direct argv execution, process semantics, bounded capture,
presentation, retrieval, verification, local storage, and capability reporting.
Python owns policy authoring/compilation, trust commissioning, extensions,
studies, analysis, compatibility, and the legacy reference engine.

Generic direct argv is the universal baseline. Explicit shell is a separately
declared, exact reviewed interpreter capability. Stdin is null unless the
compiled scope and request both select inheritance or an opaque in-memory
reference. An adapter may add commissioning facts or bounded projection
candidates but never grants authorization. Extension code is imported only in
the explicit isolated Python slow path; ordinary native command execution does
not start Python. Unsupported behavior is typed and never silently changes
execution semantics.

Presentation is selected after observation. Persistence commitment and
durability are separate dimensions. `OUTCTL_ENABLED=0` and engine selection
provide rollback without workflow or capture migration.

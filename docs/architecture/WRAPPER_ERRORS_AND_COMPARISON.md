# Wrapper errors and cross-engine comparison

The structured result is authoritative; a POSIX status alone cannot represent
both command and capture outcomes. A wrapper error is present only when the
wrapper prevented spawn, post-spawn capture infrastructure failed, or
post-capture presentation failed.

| Code | Phase | Meaning | Command started |
|---|---|---|---|
| `OUTCTL_PRESPAWN_INVALID_REQUEST` | pre-spawn | contract or argument invalid | no |
| `OUTCTL_PRESPAWN_POLICY_REJECTED` | pre-spawn | snapshot denies the sink/capability | no |
| `OUTCTL_PRESPAWN_UNSUPPORTED` | pre-spawn | negotiated engine lacks requested feature | no |
| `OUTCTL_PRESPAWN_CAPTURE_UNAVAILABLE` | pre-spawn | required capture cannot be established | no |
| `OUTCTL_POSTSPAWN_CAPTURE_FAILED` | post-spawn | command ran but capture degraded/failed | yes |
| `OUTCTL_POSTSPAWN_PRESENTATION_FAILED` | post-spawn | command and capture completed but presentation failed | yes |

The child exit code, signal, timeout, cancellation, and wrapper error are
separate fields. A wrapper must not rewrite a child exit code into a policy or
capture result.

The frozen CLI mapping is: return the child status when the child started and
capture/presentation completed; map a signalled child to `128 + signal`; return
`125` for pre-spawn wrapper errors, post-spawn capture failure, or post-capture
presentation failure. A truncated or degraded-but-usable capture preserves the
child status. Presentation failure is not capture failure: the structured
error retains the completed capture status and command result, even when a
wrapper status is `125`.

Comparison oracle:

- **exact:** argv, shell mode, cwd binding, child exit/signal/timeout/
  cancellation, stdout/stderr byte digests, and v1 manifest stream bytes;
- **semantic:** command started, capture completeness, status dimensions,
  retrieval content after redaction, and policy outcome;
- **intentional difference:** engine identity/version, timings, capture ID,
  local path, projection formatting, and native-only optional metrics.

Any exact mismatch fails conformance. A semantic mismatch requires an explicit
fixture-level explanation. Intentional differences must be listed in the
fixture and may not alter command semantics or information-flow guarantees.

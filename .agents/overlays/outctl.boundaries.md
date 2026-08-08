# outctl capture-boundary overlay

- Treat an implicit shell, full-output buffering, or sequential pipe drainage as
  release-blocking process-semantics defects.
- Treat a projection without explicit omission/redaction markers as a
  release-blocking evidence-integrity defect.
- Treat command outcome and capture outcome as independent state dimensions.
- Tests defining the oracle for signals, timeouts, quotas, stream ordering,
  redaction, and recovery remain coordinator-owned.
- Disposable workers receive fixtures only. They receive no provider, queue,
  sprint, cluster, or production credentials.


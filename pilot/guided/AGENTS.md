# Guided outctl health-check pilot

This is a read-only evaluation. Run only the corpus commands supplied by the
launcher. Every Kubernetes invocation must be direct argv through:

`outctl run --mode enforce --spool-root "$OUTCTL_PILOT_SPOOL" -- kubectl ...`

Never invoke `kubectl` directly, use a shell, mutate the cluster, or include
raw command output in a response. The oversized pod inventory must be captured
once and then inspected through outctl retrieval; retrieval must not rerun it.

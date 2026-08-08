# Concurrent Terra A/B pilot

This directory is the checked-in, raw-output-free definition of a local pilot.
It is intentionally not a production integration and never grants mutation
authority. `outctl pilot smoke` validates fixture telemetry without contacting
Codex or Kubernetes. `outctl pilot launch` creates an ignored session-local
directory, preflights an explicit appservice kubeconfig and read-only RBAC, and
then starts the guided and control sessions from one barrier. It fails closed
when the selected namespace permits deployment, pod, or event mutation.

The guided session uses the accompanying skill. Exact command approval is
owned by the app-server client and is not delegated to a static execpolicy
rule; the control session receives the same prompt and corpus but none of
those A-only surfaces.
Codex is sandboxed to each disposable session work directory and receives no
write access to the appservice checkout. Both runs must report all token
counters and a provider-reported cost; pricing is deliberately not estimated.

Pilot result directories contain only JSONL event transcripts, receipts, and a
metadata report. Capture spools are mode `0700`, remain local, and are excluded
from the report. Do not add a result directory to Git or publish it to a served
authority.

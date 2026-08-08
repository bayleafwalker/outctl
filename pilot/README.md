# Concurrent Terra A/B pilot

This directory is the checked-in, raw-output-free definition of a local pilot.
It is intentionally not a production integration and never grants mutation
authority. `outctl pilot smoke` validates fixture telemetry without contacting
Codex or Kubernetes. `outctl pilot launch` creates an ignored session-local
directory, preflights an explicit appservice kubeconfig and read-only RBAC, and
then starts the guided and control sessions from one barrier.

The guided session uses the accompanying skill and execpolicy rule. The control
session receives the same prompt and corpus but none of those A-only surfaces.
Both runs must report all token counters and a provider-reported cost; pricing
is deliberately not estimated.

Pilot result directories contain only JSONL event transcripts, receipts, and a
metadata report. Capture spools are mode `0700`, remain local, and are excluded
from the report. Do not add a result directory to Git or publish it to a served
authority.

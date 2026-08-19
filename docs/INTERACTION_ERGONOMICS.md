# Interaction ergonomics hypothesis

This is a separate hypothesis from projection compression:

> Can outctl reduce model-visible context without increasing the serial
> model–tool decisions required to finish a task?

The primary characterization metric is observable serial tool-round count,
not raw command count. A round is a concurrent wave of command executions
between an empty and non-empty active-command set in the Codex event stream.
The harness also records commands per round, parallelism, sequential
model/tool boundaries, and visible agent-message counts. Codex CLI JSONL does
not currently expose internal model invocation IDs, so
model_invocation_count is explicitly reported as unavailable rather than
silently equated with turn.completed.

Each acceptance arm now includes raw-free follow-up classifications:

- interface_discovery
- confirm_absence
- completeness_uncertainty
- raw_seeking
- repeated_original_command

The classifier records only command digests, bounded-return omission signals,
opaque capture IDs, and categorical judgments. It never copies command output
into the report. Frozen offline fixtures live in
acceptance/codex_appservice_ab/replay-scenarios.json.

## Presentation contracts

Known semantic adapters may return a decision-complete compact result. The
first implementation recognizes large all-namespaces Kubernetes Pod tables
and emits:

- complete scan coverage;
- total row count;
- status counts;
- authoritative zero counts for standard health predicates;
- every retained anomalous row;
- routine-row omission counts.

If the semantic parser cannot confidently recognize the table, outctl falls
back to the generic bounded/retrievable contract. Outputs below the adaptive
semantic threshold are passed through exactly when they contain no
normalization, truncation, or stderr, while capture remains private.

Generic output cannot promise projection sufficiency: an omitted byte may be
needed by an unknown future question. Retrieval remains available without
rerunning the command.

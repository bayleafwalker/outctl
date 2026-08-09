# Wider enablement contract integration

## Released outctl contracts

| Contract | Owner | Purpose |
|---|---|---|
| `logical-command-request/v1` | outctl adapter boundary | Frozen logical argv, mode, policy, identity hashes, timeout, and attempt/session bindings |
| `runner-command-result/v1` | outctl adapter boundary | Separate command/capture outcomes and immutable output attachment reference |
| `kubernetes-execution-receipt/v1` | outctl | Deterministic runner-injected execution identity binding |
| `shadow-observation/v1` | outctl evaluation | Direct/shadow semantic comparison, overhead, recovery, and negative state |
| `study-protocol/v1` | outctl evaluation | Frozen quality margin, sample classes, outcomes, exclusions, and stopping rules |
| `study-analysis/v1` | outctl evaluation | Every pair, paired summaries, secondary pools, and gate results |
| `ux-evidence/v1` | outctl evaluation | Multi-turn adoption, retrieval contribution, reruns, bypasses, and quality |
| `enablement-evidence/v1` | outctl | Provenance-bound metadata packet consumed by ordered stage evaluation |
| `cross-harness-conformance/v1` | outctl | Shared bypass/shadow/enforce/retrieval conformance result |

Readers accept the preceding unversioned enablement packet through an explicit
normalizer. Writers emit only the current version. Existing schemas are never
redefined; a semantic change requires a new schema identifier.

## ActionQ compatibility

ActionQ's released `execution-envelope/v1` remains authoritative and
unchanged. It binds `action_id`, `attempt_id`, source commit, registered
command ID, and allowed paths. It uses exact-field compatibility and forbids
credential/path/receipt-like extensions.

Therefore:

1. ActionQ freezes its ordinary execution envelope.
2. The native runner resolves the registered command ID to a separately
   versioned outctl logical request.
3. The request repeats the public `action_id` and `attempt_id` as correlation
   bindings but carries no claim receipt or runner credential.
4. The runner emits a `runner-command-result/v1` attachment into its owning
   immutable artifact flow.
5. ActionQ stores only the resulting immutable artifact reference/digest in an
   owner-approved terminal attachment or event field.

Do not add outctl fields directly to `execution-envelope/v1`, import ActionQ
internals into outctl, write ActionQ storage directly, or put a local spool
path in an ActionQ record.

## Auditctl mapping proposal

The existing `audit-event.schema.json` defines event categories, but the
publisher/idempotency contract is not yet accepted by auditctl. The proposed
mapping is:

| Outctl event | Metadata only |
|---|---|
| capture completed/degraded/truncated | capture ref, manifest digest, command status, capture status, policy/schema digests |
| projection exposed | projection digest and bounded metrics |
| output retrieved | capture ref, operation, requested range/query digest, result projection digest |
| capture verified | expected/observed digest and verification outcome |
| capture replicated/expired | replica class, replica digest, availability transition |

Publication must use auditctl's documented CLI/API with a deterministic event
ID agreed by auditctl. Failures are visible metadata and do not rewrite the
command or action outcome. No streams, projection bodies, credentials, or
local paths are published.

## kctl and AgentOps mapping

kctl receives a reviewed decision containing policy reference/digest,
redaction/retention/replication intent, accepted limitations, and rollout
state. It never receives command output. AgentOps guidance changes originate
in canonical sources and generated project files are rendered rather than
hand-edited.

## Rollout-stage mapping

The original `docs/ROLLOUT.md` and canonical plan use different numbering:

| Original rollout | Canonical enablement |
|---|---|
| Stage 0 contracts | Stage 0 contracts and gates |
| Stage 1 local shadow | Stage 3 selected shadow |
| Stage 2 bounded pilot | Stages 4–6 controlled study, UX, selected enforcement |
| Stage 3 actionq/audit | Stage 7 authority integration |
| Stage 4 second harness | Stage 7 second-harness conformance |
| Stage 5 hybrid registry | Stage 8 portability |

Canonical numbering is used by `outctl enablement`.

## External acceptance boundary

This repository can validate contract material and deterministic fixtures. It
cannot establish genuine RBAC, owner-API publication, second-harness
exclusivity, cross-host authorization, or replica durability. Those gates
require separately authorized owner-repository work and return only hashed,
metadata-only evidence references.

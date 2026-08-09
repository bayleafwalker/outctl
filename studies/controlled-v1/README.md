# Controlled Kubernetes seeded corpus v1

This corpus contains six deterministic, replayable, normalized Kubernetes
snapshots and their expected-fact denominators. It is model-free fixture truth,
not a claim about a live cluster.

Each manifest binds the exact fixture and expected-facts bytes. `suite.json`
binds exactly one scenario for every class required by `study-suite/v1`.
Mutation authority is not required because replay reads checked-in snapshots.

The controlled-study protocol is generated only after this corpus commit is
selected. It must bind the then-current repository HEAD and the canonical suite
digest. A protocol checked into the same commit it names would be an impossible
self-reference and is therefore intentionally not stored here.

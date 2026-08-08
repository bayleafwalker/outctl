Perform a read-only health check of the appservice Kubernetes cluster using the repository's existing health-check guidance and skills.

Use the canonical appservice environment rooted at `{{CANONICAL_APPSERVICE}}`. Check enough current evidence to distinguish healthy, degraded, and unknown across the cluster/API, nodes, workloads, GitOps reconciliation, storage, and recent warning/error events. Populate every required `coverage` area with bounded evidence. Give each critical or high finding a stable ID so the two arms can be compared deterministically.

Do not modify cluster state or repository files. Do not read Kubernetes Secret objects. Do not use exec, port-forward, debug, or other interactive access. Do not ask follow-up questions. Return the structured health result requested by the supplied output schema.

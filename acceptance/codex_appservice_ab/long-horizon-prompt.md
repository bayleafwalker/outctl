Perform the fixed, read-only long-horizon appservice health assessment using
the local arm instructions and the canonical environment rooted at
`{{CANONICAL_APPSERVICE}}`.

Run the twenty `kubectl` argv vectors from the supplied long-horizon workflow
manifest exactly once, in exactly the listed order, without pipelines,
substitutions, retries, or other commands. The second command is intentionally
the large pod inventory. Continue through all remaining commands after it; the
purpose of this run is to measure whether that early output is carried through
later investigation cycles.

After the large pod inventory, use at most one bounded retrieval from its
existing capture if a specific omitted fact is needed. Retrieval must use the
capture ID returned by the bounded route and must never rerun the inventory.

Use only the route required by the local arm instructions. Do not inspect the
repository, raw capture files, kubeconfig, or credentials. Do not modify
cluster state or repository files. Do not read Kubernetes Secret objects and do
not use exec, port-forward, debug, proxy, or other interactive access.

Populate every required coverage area with bounded evidence. Every check and
finding must include `evidence_refs` identifying the capture ID and projection
or retrieval operation that supports it. Keep the final health result concise,
stable, and schema-conformant. Do not ask follow-up questions.

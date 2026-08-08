Perform the fixed, read-only appservice health-check corpus using the local arm instructions and the canonical environment rooted at `{{CANONICAL_APPSERVICE}}`.

Run each of these six kubectl argv exactly once, without shell pipelines, substitutions, or any other commands:

1. `kubectl version -o json`
2. `kubectl get nodes -o wide`
3. `kubectl get pods -A -o wide`
4. `kubectl -n flux-system get kustomizations`
5. `kubectl -n gatus get deployments,persistentvolumeclaims`
6. `kubectl -n gatus get events --sort-by=.lastTimestamp`

Use only the route required by the local arm instructions. Do not inspect the repository, use any other shell command, or retry a corpus command. Populate every required coverage area with bounded evidence. Give each critical or high finding a stable ID so the two arms can be compared deterministically.

Do not modify cluster state or repository files. Do not read Kubernetes Secret objects. Do not use exec, port-forward, debug, or other interactive access. Do not ask follow-up questions. Return the structured health result requested by the supplied output schema.

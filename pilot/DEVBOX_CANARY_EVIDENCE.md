# Devbox app-server no-cluster canary

Date: 2026-08-08  
Checkout: `482705a` before the local remediation commit

The local pinned Codex CLI was `codex-cli 0.145.0`. Its generated app-server
schema advertised granular approval policy, command-execution approval
requests, item-completed notifications, and `turn/start.outputSchema`.

A no-cluster canary used `approvalPolicy: "untrusted"`, a read-only `/tmp`
working directory, and the sole harmless command `printf outctl-canary`. It
received both of the required runtime notifications:

- `item/commandExecution/requestApproval`
- `item/completed`

No Kubernetes command, kubeconfig, cluster connection, capture spool, model
or tool body, report body, or pilot A/B run was retained or published. This
only establishes that this installed app-server version can request and report
one command approval. The launcher remains fail-closed until its exact corpus
and read-only RBAC preflight pass on the workstation.

Perform an independent, long-form, read-only operational health assessment of
the appservice Kubernetes environment. Work from the canonical environment
rooted at `{{CANONICAL_APPSERVICE}}`.

Choose the commands that best investigate cluster API reachability, nodes,
workloads, GitOps, storage, and recent events. Follow the local arm guidance;
otherwise decide the investigation path yourself. Start broad and drill into
evidence only where it changes the health conclusion. You may use bounded
retrieval of an existing capture instead of rerunning a command when details
are omitted.

Invoke the experiment-provided `kubectl` by name. Do not discover or substitute
an absolute executable and do not override kubeconfig, context, server, user,
or credential flags; the harness pins those identically for both arms.

Do not modify cluster state or repository files. Use read-only kubectl only;
do not read Kubernetes Secret objects and do not use exec, port-forward,
debug, proxy, or other interactive access. Do not ask follow-up questions.
Return the structured health result requested by the supplied output schema,
with clear evidence and limitations for every required coverage area.

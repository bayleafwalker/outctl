# External enablement handoff

The repository-local path ends after selected enforcement is proven. The
following work requires separate authorization and changes in owning systems.
None of it is implied by an outctl implementation pass.

## actionq and auditctl

- Pass output policy and capture bindings through the owning execution API.
- Bind each retry/attempt to a distinct capture.
- Publish compact manifest/projection/verification receipts through auditctl's
  documented API.
- Do not publish raw streams, projection bodies, or spool paths.
- Prove action outcome remains distinct from command and capture outcomes.

## kctl and project guidance

- Promote only policy intent, digest, and enablement decision.
- Add raw-free handoff guidance and evidence classifications.
- Do not store command logs or treat a capture as curated knowledge.

## second harness

- Implement the same direct-argv logical command and result schemas.
- Withhold or constrain alternate execution paths so enforcement does not
  depend on prompt compliance.
- Run bypass/shadow/enforce conformance and document adapter differences.

## registry and replicas

- Select an authorized metadata and artifact backend.
- Preserve exact/sanitized/manifest/projection replica classes.
- Verify opaque-reference retrieval on a receiving host.
- Prove registry/backend outage leaves local inspect, retrieval, and bypass.

## Required evidence returned here

Return metadata-only evidence for `config/enablement-evidence.example.json`:

- action receipt and audit verification booleans plus owning-system references;
- promoted policy reference/digest;
- second-harness conformance result;
- replica-class and cross-host verification result;
- local break-glass result.

Do not return credentials, raw command output, session transcripts, or capture
bodies to this repository.

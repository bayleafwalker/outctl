## Command evidence

- Purpose: verify bounded-output Phase 1 conformance.
- Capture reference: `outctl://capture/01K1CAPTUREEXAMPLE/manifest/sha256/<digest>`
- Capture status: `COMPLETE`
- Command status: exit `0`
- Policy: `interactive-default-v1@sha256:<digest>`
- Source host: `devbox`
- Canonical source path: `/projects/dev/_artifacts/outctl/captures/01K1CAPTUREEXAMPLE`
- Availability: **local-only** — no receiving-host or durable replica exists.
- Manifest SHA-256: `<digest>`
- stdout SHA-256: `<digest>`
- stderr SHA-256: `<digest>`
- Projection SHA-256: `<digest>`
- Raw/exposed estimate: `178.8k / 8.1k tokens`
- Retrieval example: `outctl search <capture-ref> --regex 'FAILED|ERROR|Traceback' --before 10 --after 30`
- auditctl receipt: `auditctl://...` or `not promoted`
- kctl decision/policy reference: `kctl://...`
- Retention deadline: `2026-08-10T18:00:00Z`
- Replica state: none

This evidence must not be described as portable until a replica is created and verified. The path alone is not an authority or durable reference.

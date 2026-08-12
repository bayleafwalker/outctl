# W8 hybrid packaging and staged-rollout handoff

**Status:** local implementation and rehearsal only; no publication or deployment
**Backlog:** Outctl #2140
**Baseline:** `origin/main` at `017f3d2a6bdec77db1a843fc10b13aba3779f97a`

## Boundary

W8 packages the already-gated Python reference and Rust engine, then makes
native selection conditional on exact artifacts, host-class conformance, and
ordered adoption evidence. It adds no command semantics, remote executor,
registry, replica backend, workflow authority, deployment, or publication.

The hybrid bundle is an immutable installation input. It contains:

- the exact source Git commit shared by the release build;
- one PEP 427 Python wheel with exact name, distribution version, digest,
  size, and mode;
- a host-class-specific offline dependency wheelhouse;
- one native executable and canonical capability document per host class;
- a canonical manifest pinning every member and a semantic capability-profile
  digest shared by all native variants.

The bundle release label, Python distribution version, and native engine
version are independent pins. The current migration versions are intentionally
not equal (`0.1.0.dev0` for Python and `0.1.0` for Rust).

## Ordered local stages

1. Build the Python wheel, dependency wheelhouse, and release-mode native
   executable from one reviewed repository commit.
2. Assemble the bundle with `scripts/build_hybrid_bundle.py` and verify it
   read-only with `scripts/check_hybrid_bundle.py`.
3. On every declared host class, install only from the bundle into a fresh
   Python 3.12 environment with indexes disabled. Run the installed Python and
   native capability probes plus the deterministic cross-engine fixture.
4. Rehearse `OUTCTL_ENABLED=0 OUTCTL_MODE=bypass`; the selector must not probe
   native code or create/migrate capture state.
5. Enable native shadow only after clean-install, host-conformance, and rollback
   evidence pass. Shadow is one execution with ordinary-result exposure, not a
   second command invocation.
6. Select a stable canary cohort only after shadow passes. The cohort is the
   SHA-256 mapping of release digest, host class, and a caller-owned stable key;
   no random or mutable global state participates.
7. Set Rust as the default only after the canary gate passes and a deployment
   owner records a separate authorization reference. This repository candidate
   deliberately leaves that setting false.

The metadata-only evidence contract is
`schemas/w8-adoption-evidence.schema.json`; the checked-in example is a
fail-closed template. It requires exact W0-W7 commit/evidence bindings, bundle
and per-host artifact digests, clean-install/conformance/shadow/rollback/canary
booleans, and the external default authorization field. It contains no raw
command output, capture bodies, credentials, or workflow conclusions.

## Selector and inode pinning

`outctl.native.rollout` keeps unsupported or ungated hosts on the Python
reference. Native selection validates the host pin, exact executable digest,
canonical capability digest, platform, requested features, and contract
versions. Every native probe/launch opens the artifact with `O_NOFOLLOW`, hashes
that descriptor, and executes `/proc/self/fd/<n>` with the descriptor inherited.
Replacing the pathname after hashing therefore cannot substitute another
binary. This is a Linux local rollout primitive; other hosts remain on Python
until they have their own reviewed execution mechanism and evidence.

## Deployment-owner handoff

The owner, not this implementation pass, must:

1. repeat the full gate with the pinned Rust 1.85.1 toolchain;
2. run the clean-install/conformance rehearsal on every intended host class;
3. install the verified bundle into a root-owned directory that is not
   group/world writable, retaining the manifest digest in deployment config;
4. begin with Python/default or a bounded native shadow cohort;
5. attach metadata-only evidence IDs to the W8 adoption packet;
6. promote canary/default flags only through the owning configuration path;
7. monitor command/capture separation, deadlocks, overhead, retrieval, and
   bypass pressure without placing raw output in an authority store.

No bundle has been published and no host, service, cluster, Sprintctl, ActionQ,
auditctl, or kctl state is changed by the W8 candidate.

## Local verification on 2026-08-12

The implementation worktree passed:

- 321 Python tests with Cargo available, including the W8 bundle, staged
  selection, import-boundary, packaging, and installed differential paths;
- Rust 1.97.0 format, all-target check, all-target Clippy with warnings denied,
  94 unit tests, and doc tests;
- Ruff, Mypy over 38 source files, wheel/sdist build, package-content checks,
  schema parsing, the AgentOps dispatch-artifact validator, and diff checks;
- a real `linux-x86_64-glibc-cp312` bundle assembled from the built wheel,
  complete downloaded offline wheelhouse, and release-mode native binary;
- read-only manifest verification followed by a fresh Python 3.12 no-index
  install, exact and semantic cross-engine fixture, one-execution native shadow
  fixture, and rollback proof with zero captures and no state migration.

The rehearsal receipt is metadata-only and reported `passed: true`; no bundle
or receipt was published. Rust 1.85.1 is not installed in this local
environment, so the pinned-toolchain rerun remains an explicit integration and
deployment-owner gate rather than a claim made by this candidate.

## Review remediation

An independent review of the packaging/rollout candidate found two selector
fail-closed branches with no test coverage: the native-capabilities digest
mismatch guard (a binary whose SHA-256 pin matches but whose probed
capabilities document does not) and the `OUTCTL_RELEASE_MANIFEST_DIGEST`
caller/evidence mismatch guard, whose own default-value fallback made it
unreachable by any existing test. Both now have dedicated tests in
`tests/test_w8_rollout.py`
(`test_native_capabilities_digest_drift_fails_closed`,
`test_release_manifest_digest_mismatch_fails_closed`); each was confirmed to
fail when its corresponding guard is disabled, so neither is vacuous
coverage.

## Rollback

Break glass remains:

```text
OUTCTL_ENABLED=0
OUTCTL_MODE=bypass
```

The selector applies this before manifest, host, capability, or executable
inspection. Commands use the prior Python/direct runner boundary; existing v1
and v2 captures remain readable and subject to their existing retention rules.
Rollback does not rewrite a capture, result, manifest, index, Sprintctl item,
ActionQ attempt, audit receipt, or policy decision. Removing the installed
bundle is a later ordinary package-cleanup action, not part of rollback.

## Intentional limits

- This pass creates no signed release, package publication, deployment, or
  production/cluster canary.
- Only locally exercised host classes may be marked conformant; a bundle entry
  alone is not conformance evidence.
- Python dependency wheel completeness is proven by the offline clean install,
  not inferred from filenames.
- Remote replicas, portable opaque-reference resolution, and second-harness
  authority integration retain their separate enablement gates.
- PTY, live output, parent-shell state, remote-only capture, and LLM projection
  remain unsupported or out of scope.

# W1 v2 conformance oracle

This directory contains raw-free vectors and comparison rules for the Python
reference engine and future Rust engine. It is a test oracle, not an executor.

The oracle compares one request through both engines. Exact fields must match;
semantic fields must satisfy the same invariant; intentional differences must
be declared in the fixture. A capture ID, local path, engine identity, timing,
or projection formatting difference is never by itself a process-semantic
difference.

The minimum fixture matrix is:

| Case | Required result |
|---|---|
| ordinary direct argv | completed, exact command status and stream digests |
| bypass | explicit `bypassed`, no capture required, no rerun |
| unsupported capability | explicit `unsupported`, no silent fallback |
| trusted sink | representable safe-unredacted disclosure policy |
| restricted sink | representable sanitized/metadata disclosure policy |
| v1 capture | v2 delta retains v1 stream bytes and one-version-back read |

The oracle also rejects cross-contract mismatches for snapshot ID, policy
reference, and policy digest. It treats the structured result as authoritative
for command/capture status and applies the frozen wrapper mapping (`125` for a
wrapper error; child status otherwise). Exact secret values are not fixture
inputs: only opaque `secret://` references may appear.

`digest-vectors.json` pins the canonical JSON algorithm used by both engines:
UTF-8, sorted object keys, compact separators, no ASCII escaping, and omitted
null-valued fields. Contract self-digests omit their declared digest field.

`matrix.json` is consumed by `comparator.py`. It has executable exact-field,
semantic-invariant, declared-intentional-difference, and negative mismatch
cases. The validator rejects raw fields, unclassified differences, missing
intentional differences, and cases whose expected pass/fail result is wrong.

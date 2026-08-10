# ADR-0003: Trust-domain and sink-specific information flow

**Status:** Accepted
**Date:** 2026-08-10

Model classification, trusted disclosure, persistence, and export as separate
policy dimensions. A commissioned trusted agent may receive a classified secret
unredacted while lower-trust or export sinks sanitize, reduce to metadata, or
deny it. Policy decisions are pinned, provenance-bearing, and cannot grant
command authorization. Exact values never enter receipts or telemetry.

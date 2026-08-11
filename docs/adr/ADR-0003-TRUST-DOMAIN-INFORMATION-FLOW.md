# ADR-0003: Trust-domain and sink-specific information flow

**Status:** Accepted — 2026-08-10

Model classification, trusted disclosure, persistence, and export are separate
policy dimensions. A commissioned trusted-local snapshot defaults to required
host-persistent capture; lower-trust or export sinks sanitize, reduce to
metadata, or deny it. Exact secrets cross the boundary only as opaque protected
references. Policy is provenance-bound and cannot grant execution.

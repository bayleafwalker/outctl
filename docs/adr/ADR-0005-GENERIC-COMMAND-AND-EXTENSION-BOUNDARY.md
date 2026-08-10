# ADR-0005: Generic command baseline and bounded extensions

**Status:** Accepted
**Date:** 2026-08-10

Direct argv execution is universal and does not require command-specific
parsing. Explicit shell is a separately reviewed capability. Extensions may add
facts, policy contributions, projection candidates, and sanitizers, but never
authorization. Python extensions run at commissioning time or through an
explicit bounded slow path; unknown commands continue through the generic path.

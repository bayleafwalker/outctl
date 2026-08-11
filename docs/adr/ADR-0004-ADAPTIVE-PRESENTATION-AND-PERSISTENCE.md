# ADR-0004: Adaptive presentation and independent persistence

**Status:** Accepted — 2026-08-10

Choose presentation after observing output under policy. Return safe small
output directly when that is cheaper; otherwise return a bounded explicit
projection with retrieval. Capture commitment and durability are independent,
but the W1 compatibility mapping is explicit (`memory-only/process-local` have
no durability, `host-persistent` maps to host durability, and `replicated`
maps to replica/authoritative). Required transforms precede exposure, and
lossy/unavailable states remain explicit.

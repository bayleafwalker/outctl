# ADR-0004: Adaptive presentation and independent persistence

**Status:** Accepted
**Date:** 2026-08-10

Choose presentation after observing output under policy. Return safe small
output directly when projection plus envelope would be larger; otherwise return
a bounded explicit projection with retrieval. Capture commitment and durability
are independent from presentation and visibility. Required transforms always
precede exposure, and every lossy or unavailable state remains explicit.

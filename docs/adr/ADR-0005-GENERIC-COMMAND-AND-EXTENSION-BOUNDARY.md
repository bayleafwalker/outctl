# ADR-0005: Generic command baseline and bounded extensions

**Status:** Accepted — 2026-08-10

Direct argv is universal and needs no command-specific parser. Explicit shell
is represented but unsupported by the W1 engine: there is no implicit shell,
PTY, parent-shell state, or fallback. Extensions may contribute facts, policy,
projection candidates, and sanitizers, but never authorization. Python
extensions run at commissioning or through an explicit bounded isolated slow
path with no command creation, network, inherited secrets, or spool access.

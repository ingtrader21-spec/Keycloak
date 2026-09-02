# CHECK and APPLY

CHECK is non-mutating and emits deterministic creates, updates, noops and blockers plus a canonical SHA-256. APPLY accepts only the same merged SHA and reviewed artifacts, revalidates live state immediately before writes, preserves rollback exports and reports partial application. A merge never invokes APPLY. See `docs/GITOPS.md` for commands and artifact structure.

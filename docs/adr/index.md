# Architecture Decision Records

Retrospective ADRs for the decisions recorded in
[`docs/architecture-roadmap-2026-11-21/roadmap.md`](../architecture-roadmap-2026-11-21/roadmap.md)
(§2 target architecture, §8 alternatives considered and rejected) and
implemented in `src/attackmap/`. These document decisions **already made and
mostly already implemented** — they are not proposals.

Format: classic ADR (Status / Context / Decision / Consequences).

| ADR | Decision | State |
| --- | --- | --- |
| [0001](0001-layered-monolith.md) | Layered monolith with enforced downward-only layers | Implemented |
| [0002](0002-generations-as-truth.md) | Immutable generations as the only source of truth | Implemented |
| [0003](0003-sqlite-projection.md) | SQLite index is a disposable derived projection | Implemented |
| [0004](0004-rule-registry.md) | Reasoning as a data-driven rule registry | Implemented |
| [0005](0005-union-contract.md) | Extraction contract v2: discriminated observation union | Implemented |
| [0006](0006-no-build-frontend.md) | No-build frontend (static assets, no bundler) | Implemented |
| [0007](0007-ai-as-narrator.md) | AI narrates and triages; deterministic code decides | Decision accepted; EvidenceBundle versioning pending (AR067) |
| [0008](0008-content-addressed-storage.md) | Content-addressed store for incrementality | Decision accepted; implementation pending (AR080) |

Companion tooling: [architecture drift dashboard](../architecture-drift.md)
(`tools/arch_drift.py`) tracks the structural metrics behind ADR-0001 per
release.

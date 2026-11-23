# ADR-0001: Layered monolith with enforced downward-only layers

**Status:** Accepted · Implemented (phases 0–1, AR002/AR030/AR031)
**Date:** 2026-11-23 (retrospective; decision made in roadmap 2026-11-21)

## Context

AttackMap is a local-first, single-process defensive analysis engine. At the
roadmap baseline the package had 44 import cycles and growing, and layer
direction was a convention, not a rule — the codebase visibly fought itself.
The alternative considered was microservices (roadmap §8), which buys nothing
for a tool with no server, no multi-tenancy, and no ops team, at the full
cost of distributed-systems complexity.

## Decision

Keep a **modular monolith** organized into strict, downward-only layers
(roadmap §2.1):

- **L6 Surfaces** (cli, ui server, library API, fleet) → **L5 Orchestration**
  (RunSpec, pipeline, scheduler) → **L4 Reasoning** (rule registry, taint,
  contracts, ranking) → **L3 Extraction** (analyzer host, merge, scanners) →
  **L2 Model** (observation union, findings, snapshot identity) →
  **L1 Foundation** (safe_fs, redact, srcpaths, artifact manifest/publisher).

A layer may import only strictly lower layers. Enforcement is a test gate,
not a hope: `tests/architecture/test_import_boundaries.py` (AR002/AR031),
`tools/layer_report.py` with a shrink-only violation baseline, and
`tests/architecture/test_layer_boundaries.py`. `attackmap.sdk` keeps its
import path and stability promise as the only promised surface; everything
else is free to move.

## Consequences

- Import cycles went 44 → **0** (wave 9, AR030); layer violations 27 → **0**
  and stay gated per layer pair, including `__init__` aggregators (AR031).
- Every future change is measurable: the AR009 ratchet
  (`tools/ratchet_check.py` + `baseline.json`) fails CI on any regression.
- The cost is discipline when adding code: new cross-layer needs go through
  the layer map (`tests/architecture/layer_map.py`), which occasionally slows
  a change by one review round — accepted as the price of compounding.
- Trends are tracked per release by `tools/arch_drift.py`
  (`docs/architecture-drift.md`).

# ADR-0004: Reasoning as a data-driven rule registry

**Status:** Accepted · Implemented (phases 2–3, AR040–AR047; wired in wave 13)
**Date:** 2026-11-23 (retrospective; decision made in roadmap 2026-11-21)

## Context

Detection knowledge lived in an imperative "cascade" inside
`reasoning/threat_model.py` — 2068 lines at its peak, unmeasurable per
detection, undocumented per rule, and impossible to regression-test one
finding kind at a time. The roadmap's pivot (§3 phase 2): "we use heuristics"
had to become "we have N rules, here is the measured precision of each."
The alternative considered was refactoring the cascade in place (roadmap §8),
rejected because the cascade could not be measured or documented no matter
how cleanly it was written.

## Decision

Encode detection knowledge as **data**: a deterministic `RuleRegistry`
(`reasoning/rules/registry.py`) of `Rule` objects with stable snake_case ids,
CWE mappings, and rationale, evaluated over a `ReasoningContext` (AR040).
Rules are ported family by family (AR041–AR045: route/auth, datastore/edge,
secrets/config, taint/flow, supply-chain/workflow), each carrying a focused
test via the AR047 per-rule harness and measured precision/recall via the
AR048 corpus harness. Reports emit registry ids; suppressions and SARIF
accept legacy ids through `rule_id_aliases()` (owner decision 2026-11-23).
Findings formatting lives in one shared module (`reasoning/finding_format.py`).

Wave 13 wired the registry into the scan pipeline and retired the ported
cascade branches: `threat_model.py` 2068 → 1605 lines, `generate_findings`
788 → 417, verified field-for-field equivalent over a 122-repo corpus (1210
findings, 0 divergences).

## Consequences

- Every finding is discussable: stable id, CWE, rationale, evidence chain;
  per-rule precision/recall is published per release
  (`docs/reference/detection-quality.md`).
- Detection quality is a number the project improves, not a claim it asserts.
- The cost is the porting effort itself plus registry-only edge rules awaiting
  a product decision (AR042), and the remaining cascade families listed as
  follow-up debt. `generate_findings` at 417 lines still exceeds the AC-203
  target of ≤ 60 — recorded honestly, not hidden.

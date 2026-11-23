# ADR-0007: AI narrates and triages — deterministic code decides

**Status:** Accepted · EvidenceBundle versioning pending (AR067, open)
**Date:** 2026-11-23 (retrospective; decision made in roadmap 2026-11-21)

## Context

LLM-assisted security review is on the product roadmap, and the tempting
design is to let the model decide what is a finding: point it at the repo,
read the prose, ship the answer. That design directly violates the
evidence-first doctrine (AGENTS.md): ungrounded findings are not auditable,
precision cannot be measured (AR048 exists precisely to measure it), and an
offline local-first tool cannot depend on a remote model for core behavior.

## Decision

**Deterministic code decides; the AI narrates and triages.** The reasoning
pipeline (registry rules, taint, ranking — ADR-0004) produces every finding;
the optional AI layer (`src/attackmap/ai/`) works strictly over a versioned
`EvidenceBundle` containing the findings and their evidence chains: it
explains, groups, and triages; a citation-validation step checks that every
AI claim traces back to a bundle item before it can reach output. AI
spend is capped by a budget (`ai_budget.py`); live integration tests target a
local LM Studio endpoint, keeping the product local-first (AGENTS.md).

The rejected alternative (roadmap §8): "AI decides findings" — violates the
evidence-first doctrine.

## Consequences

- Findings remain reproducible with the AI layer disabled — it is an
  accelerator for humans, not an oracle.
- Measured detection quality (AR048) stays meaningful: the denominator is
  deterministic.
- Implemented today: budget, supply-chain/CVE knowledge, SBOM helpers, and
  local-provider integration. Pending: the versioned `EvidenceBundle`
  container itself (AR067) — until it lands, AI features consume engine
  artifacts directly and this ADR's boundary is enforced by review, not by a
  versioned schema.

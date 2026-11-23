# ADR-0002: Immutable generations as the only source of truth

**Status:** Accepted · Implemented
**Date:** 2026-11-23 (retrospective; decision made in roadmap 2026-11-21)

## Context

AttackMap needs cross-run queries ("what changed between last week's scan and
today's?") and a desktop product that opens instantly. The tempting design is
a database as the source of truth — Postgres or a document DB — which would
make querying natural but breaks local-first operation, adds a daemon or
service to a tool that must run from a laptop, and creates a second,
diverging record of what happened. The evidence-first doctrine (AGENTS.md)
requires that every derived artifact be explainable from recorded inputs.

## Decision

**Generations are authoritative.** Every scan publishes an immutable,
self-describing generation directory under the output base: section files
(findings, routes, evidence), an `artifact-manifest.json`, and an
`events.jsonl` that explains what ran, what was skipped, and why (AR003).
Publication is an atomic pointer swap, so readers never observe a
half-written state, and published generations are never mutated — new state
is a new generation. A generation that fails validation is recorded as
invalid rather than repaired (see `orchestration/derived_index/rebuild.py`).

Explicitly rejected (roadmap §8): any database as a source of truth; the
roadmap "deliberately does not add a database as a source of truth —
generations stay authoritative" (§1.2).

## Consequences

- The whole history is inspectable with plain files: diffing, archiving,
  shipping, and forensic review need no tooling beyond a file browser.
- Every derived structure (SQLite index, GUI state, trends) is reconstructible
  from generations alone — which makes disposal safe and verification cheap
  (AC-302/AC-303: `attackmap index rebuild` + hash equality).
- Local-first stays real: no server, no service account, no network.
- The cost is that ad-hoc queries over many generations walk files; that need
  is served by the derived projection (ADR-0003), not by elevating a database
  to truth.

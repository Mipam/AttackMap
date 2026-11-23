# ADR-0003: SQLite index is a disposable derived projection

**Status:** Accepted · Implemented (AR061)
**Date:** 2026-11-23 (retrospective; decision made in roadmap 2026-11-21)

## Context

Cross-run questions ("what changed?", "show me the history of this finding")
were manual JSON diffs, and the GUI target of < 200 ms state load over 50
generations could not be met by re-reading every generation directory. The
question was where queryability lives. A real database as the primary store
was rejected in ADR-0002; the remaining option was a derived structure, with
the known risk R6 from the roadmap: an index inevitably drifts from the
generations it was built from.

## Decision

Maintain a **derived SQLite index** at `<output base>/index/index.sqlite`
(`orchestration/derived_index/`, schema `SCHEMA_VERSION` 1) that is:

- **Derived, never authoritative** — every row is copied verbatim from a
  generation's manifest or section files; never scored, normalised, or
  invented. The index directory is engine-owned and carries the
  `.attackmap-output` marker so scans never ingest it.
- **Disposable** — nothing is migrated on schema change; an older file is
  unusable and rebuilt from scratch. Rebuild is a first-class command:
  `attackmap index rebuild|status|dump` and `attackmap trends` (AR061).
- **Self-invalidating** — a `fingerprint` (hash over every manifest under
  the base) is stored in the file; readers trust the index only while the
  fingerprint still matches the disk, so a published or deleted generation
  can never leave stale rows answering queries.
- **Deterministic** — one transaction, fixed page size and encoding,
  canonical row order: the same generation set produces a byte-identical
  file, so delete-and-rebuild is verifiable by hash as well as by content
  (AC-302; reconstructible AC-302, disposable AC-303 verified live in AR061).

## Consequences

- `attackmap trends` and sub-second cross-run queries became real, and AR070's
  GUI < 200 ms target became reachable without touching generation storage.
- Drift risk R6 is accepted and mitigated by design: drift is detected
  (fingerprint mismatch) and repair is total (rebuild), never partial.
- The cost is one more artifact to keep honest; the fingerprint plus the
  rebuild acceptance tests are the enforcement.

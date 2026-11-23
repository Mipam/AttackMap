# ADR-0008: Content-addressed store for incrementality

**Status:** Accepted · Implementation pending (AR080, open)
**Date:** 2026-11-23 (records the decision ahead of implementation)

## Context

The roadmap's platform milestone (AC-401) requires a 10k-file repository with
50 changed files to re-scan in under 10 seconds — versus a full re-scan in
minutes today. That is only possible if unchanged work is never repeated:
file content, parse results, and analyzer outputs must be recognized as
"already seen" across runs. The natural mechanism is content identity: store
artifacts under a hash of their content, so equality is a lookup, not a
recomputation.

## Decision

Adopt a **content-addressed store (CAS)** as the incrementality layer:
artifacts (source blobs, intermediate observations, per-file analysis
results) are stored and referenced by content hash, keyed independently of
path or mtime, so a rename or a checkout that preserves bytes is free. A
snapshot walk hashes what it reads; cache hits skip extraction and analysis;
new content flows through the existing pipeline unchanged. The store
leverages the generation model (ADR-0002): cached artifacts remain valid only
within the same analyzer/contract versions, and the generation manifest
records enough identity to invalidate safely on version change.

This ADR records the decision **before** implementation (AR080 is open):
the shape above is the accepted constraint AR080 must satisfy, and deviation
requires updating this record.

## Consequences

- Pre-commit and watch mode become viable (the user-visible point of AC-401),
  and analyzer parallelism (AR027) compounds with cache hits.
- Correctness burden: cache keys must include every input that can change the
  output (analyzer version, contract version, config). Getting the key wrong
  is a silent stale-result bug — the acceptance tests for AR080 must include
  invalidation cases, not only hit cases.
- Interaction with the derived SQLite index (ADR-0003): the index remains a
  projection over generations; the CAS changes how generation content is
  produced, not what generations mean.

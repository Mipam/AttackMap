# ADR-0005: Extraction contract v2 — discriminated observation union

**Status:** Accepted · Implemented (AR060)
**Date:** 2026-11-23 (retrospective; decision made in roadmap 2026-11-21)

## Context

The plugin contract v1 made analyzers return a 33-field aggregate result
object: every new observation kind meant another optional field on a shared
struct, fields interacted silently, and the shape blocked every extension —
the roadmap's reason for calling the plugin surface the platform's
bottleneck. Meanwhile `attackmap.sdk` had a stability promise: its import
path and contract must keep working for existing external analyzers.

## Decision

Define **extraction contract v2** as one discriminated union: `ExtractionResult`
(`sdk/contracts.py`, `EXTRACTION_CONTRACT_VERSION = "2.0"`) carries a single
`observations` list whose members are twelve per-kind variants (Route,
AuthHint, Anomaly, BolaCandidate, CryptoWeakness, DatabaseHint, ExternalCall,
SecretHistoryHit, WebHardeningIssue, SupplyChain, AnalyzerError, …), each
wrapping its protocol-1.0 hint object verbatim. The change is **additive**:
the analyzer wire protocol stays at `EXTRACTION_PROTOCOL_VERSION = "1.0"`
until AR082 migrates the official analyzers, and
`extraction/adapters.py` converts between v1 aggregates and the v2 union in
both directions, so plugins can adopt v2 before core does.

Rejected alternative (roadmap §8): keep extending the 33-field aggregate.

## Consequences

- New observation kinds are new union members — declarative, typed, and
  mergeable by the core pipeline without analyzer-specific branches.
- v1 plugins keep working unchanged; the union is adopted incrementally.
- The model layer (L2) gained the union (`model/observations.py`) without
  disturbing layering: sdk depends on model, adapters live in extraction (L3).
- The cost is the adapter shim, which stays until AR082 flips the official
  analyzers and v1 can be retired.

# ADR-0006: No-build frontend

**Status:** Accepted · Implemented
**Date:** 2026-11-23 (retrospective; decision made in roadmap 2026-11-21)

## Context

The desktop product needs a GUI served from the engine (WebView2 on Windows,
a local HTTP server elsewhere). The default industry answer is React/Vite or
an equivalent framework with a bundler, a node toolchain, a lockfile, and a
build step in CI and in the shipped artifact. For a local-first Python tool
whose distribution is a pip package and a native Windows build, that toolchain
is a large standing cost: supply-chain surface (AR011 posture), release
complexity, and a class of "works before build, breaks after" bugs.

## Decision

Ship the GUI as **static assets with no build step**:
`surfaces/ui/web/` is plain HTML + JavaScript served directly by
`surfaces/ui/server.py`; `index.html` loads `src/*.js` with plain script
tags, there is no bundler, transpiler, or `node_modules`, and the GUI ships
as package data inside the wheel and native package. The roadmap's chosen
style is no-build ES modules (roadmap §8: "Preserves dependency discipline;
WebView2 supports ESM") — the no-build half is fully implemented today; ES
module adoption inside `web/src/` is incremental and optional precisely
because nothing breaks if it never happens.

Rejected alternative (roadmap §8): React/Vite.

## Consequences

- The GUI cannot silently regress at build time: the served bytes are the
  source bytes, reviewable in the same repository and gateable by ordinary
  tests.
- Dependency discipline from ADR-0001 extends to the frontend — there is no
  npm supply chain to audit in the artifact (SBOM stays Python-shaped).
- The desktop packaging (WP/native work) needs no node runtime at all.
- The cost: no component framework or type system on the client. For a
  focused security-report UI this is accepted; if the UI ever outgrows plain
  JS, this ADR is the place to re-litigate, with the supply-chain budget
  stated up front.

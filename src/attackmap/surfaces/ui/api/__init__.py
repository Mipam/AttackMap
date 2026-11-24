"""Declared, schema-gated HTTP API for the loopback GUI server (AR063 / AC-305).

``schemas.py`` holds the Pydantic request/response models for every ``/api/*``
endpoint. ``routes.py`` holds the route registry, the single auth-token gate,
and the dispatcher. ``scans.py``, ``artifacts.py`` and ``settings.py`` hold the
extracted handlers grouped by responsibility:

- ``scans``    — scan lifecycle and app state (state, config, pick, run,
  cancel, watch) plus the scan orchestration helpers they build on.
- ``artifacts``— report artifacts (report, export-source, export, pick-save,
  reveal) plus export/save-dialog helpers.
- ``settings`` — credential storage and suppression (settings, suppress).

Deviations from the card's module bucket names: none structural; ``state`` and
``config`` live in ``scans`` because they read/derive scan run state, and the
three state-returning "artifact" endpoints (reveal/export pick-save) live in
``artifacts``. All 13 endpoints are covered.

``server.py`` stays a thin adapter (static files + token gate + dispatch) and
re-exports the helper names existing tests and callers import from it.
"""

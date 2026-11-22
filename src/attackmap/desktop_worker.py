"""Deprecated -m path (AR029): moved to attackmap.orchestration.desktop_worker.

Kept so native desktop launchers that spawn
``python -m attackmap.desktop_worker`` keep working for one release.
"""

import runpy

if __name__ == "__main__":  # pragma: no cover
    runpy.run_module("attackmap.orchestration.desktop_worker", run_name="__main__", alter_sys=True)

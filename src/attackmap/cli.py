"""Deprecated import path (AR029): the CLI moved to attackmap.surfaces.cli.

Kept for one release so ``python -m attackmap.cli`` and
``from attackmap.cli import app`` keep working.
"""

from attackmap.surfaces.cli import app

if __name__ == "__main__":  # pragma: no cover
    app()

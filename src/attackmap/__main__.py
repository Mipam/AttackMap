"""Allow ``python -m attackmap`` (used by the Windows GUI runner)."""

from attackmap.surfaces.cli import app

if __name__ == "__main__":
    app()

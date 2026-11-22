"""Deprecated -m path (AR029): the analyzer host moved to
attackmap.extraction.analyzer_host.

Kept so external launchers (installer/entry.py, frozen engine) can
still run ``python -m attackmap.analyzer_host --worker`` and import
``_main`` for one release.
"""

import sys

from attackmap.extraction.analyzer_host import _main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main(sys.argv[1:]))

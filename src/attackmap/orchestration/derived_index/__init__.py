"""Derived SQLite index over published generations (AR061).

The index is a disposable projection: every row is copied from a generation
under an output base and nothing else, so deleting ``index/index.sqlite`` and
running ``attackmap index rebuild`` recreates it exactly. It is never a source
of truth — a reader that finds it missing, corrupt, on another schema version,
or built from a different generation set falls back to the generations.

- :mod:`.rows`      the canonical row shapes shared by every route a row takes
- :mod:`.sqlite`    schema, deterministic writer, read-only opener, freshness
- :mod:`.rebuild`   walk generations, validate manifests, extract rows
- :mod:`.query`     load rows through the index with a filesystem fallback

This package stays import-light: import the module you need.
"""

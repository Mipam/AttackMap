"""Schema and file handling of the derived SQLite index (AR061).

Layout: ``<output base>/index/index.sqlite``. The ``index`` directory is
engine-owned and carries the ``.attackmap-output`` marker while never holding
an ``artifact-manifest.json``, so ``walk_repo`` never descends into it — the
same marker rule that keeps ``diagnostics/`` out of scan input. A bare
``index.sqlite`` in the output base would NOT be excluded: a published base
carries a manifest, so the walker descends it and reads any file it does not
recognise, which would change the scan snapshot.

Schema ``SCHEMA_VERSION`` 1:

    index_meta      key/value: schema_version, index_format, fingerprint
    generations     one row per generation directory (validity and errors too)
    runs            one row per valid scan generation; fleet children included
    findings        active findings, verbatim from findings.json
    suppressions    suppressed findings and the suppression that silenced them
    routes          request routes from the scan section
    evidence        evidence lines and locations of active and suppressed findings

``fingerprint`` is the identity of the generation set the rows were read
from (a hash over every manifest under the base, with its checksum). A reader
uses the index only while that still matches the disk, so a published or
deleted generation can never leave it answering from stale rows.

A schema change bumps ``SCHEMA_VERSION``; an older file is then unusable and
is rebuilt from scratch. Nothing is migrated: the generations are the only
source, and guessing a mapping between schemas would be inventing data.

Determinism: one transaction, fixed page size and encoding, canonical row
order. The same generations produce a byte-identical file, so
delete-and-rebuild can be verified by hash as well as by content (AC-302).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any

from attackmap.foundation.safe_fs import MANIFEST_FILENAME
from attackmap.orchestration.derived_index.rows import (
    EvidenceRow,
    FindingRow,
    GenerationRow,
    IndexRows,
    RouteRow,
    RunRow,
    SuppressionRow,
)

__all__ = [
    "INDEX_DIRNAME",
    "INDEX_FILENAME",
    "INDEX_FORMAT",
    "SCHEMA",
    "SCHEMA_VERSION",
    "UNUSABLE_REASONS",
    "dump_tables",
    "index_fingerprint",
    "index_path",
    "manifest_inventory",
    "open_fresh_index",
    "read_index",
    "write_index",
]

SCHEMA_VERSION = 1
INDEX_FORMAT = "attackmap-derived-index/1.0"
INDEX_DIRNAME = "index"
INDEX_FILENAME = "index.sqlite"

# Why a reader did not use the index. Every one of them falls back to the
# generations; none of them is an error for the caller.
UNUSABLE_REASONS: tuple[str, ...] = (
    "missing",  # no index file
    "unreadable",  # exists but cannot be opened
    "corrupt",  # not a readable index: truncated, garbage, foreign, or mid-read failure
    "schema_mismatch",  # written by another schema version or format
    "stale",  # built from a different generation set than is on disk
)

_SCHEMA_VERSION_KEY = "schema_version"
_FORMAT_KEY = "index_format"
_FINGERPRINT_KEY = "fingerprint"

SCHEMA: tuple[str, ...] = (
    "CREATE TABLE index_meta ("
    " key TEXT PRIMARY KEY,"
    " value TEXT NOT NULL"
    ") WITHOUT ROWID",
    "CREATE TABLE generations ("
    " run_id TEXT PRIMARY KEY,"
    " path TEXT NOT NULL,"
    " valid INTEGER NOT NULL,"
    " indexed INTEGER NOT NULL,"
    " parent_run_id TEXT,"
    " manifest_sha256 TEXT,"
    " created_at TEXT,"
    " engine_version TEXT,"
    " profile TEXT,"
    " error TEXT"
    ") WITHOUT ROWID",
    "CREATE TABLE runs ("
    " run_id TEXT PRIMARY KEY,"
    " repo_root TEXT NOT NULL,"
    " repo_name TEXT NOT NULL,"
    " engine_version TEXT NOT NULL,"
    " status TEXT NOT NULL,"
    " exit_code INTEGER NOT NULL,"
    " analyzer_identity TEXT,"
    " snapshot_id TEXT,"
    " snapshot_state TEXT,"
    " files_scanned INTEGER"
    ") WITHOUT ROWID",
    "CREATE TABLE findings ("
    " run_id TEXT NOT NULL,"
    " idx INTEGER NOT NULL,"
    " finding_id TEXT NOT NULL,"
    " title TEXT NOT NULL,"
    " severity TEXT NOT NULL,"
    " confidence TEXT NOT NULL,"
    " identity_scheme TEXT,"
    " rule_id TEXT,"
    " entity_id TEXT,"
    " score INTEGER,"
    " exploitability INTEGER,"
    " exploitability_tier TEXT,"
    " tags TEXT,"
    " cwe TEXT,"
    " PRIMARY KEY (run_id, idx)"
    ") WITHOUT ROWID",
    "CREATE INDEX findings_by_rule ON findings (rule_id, run_id)",
    "CREATE TABLE suppressions ("
    " run_id TEXT NOT NULL,"
    " idx INTEGER NOT NULL,"
    " finding_id TEXT NOT NULL,"
    " title TEXT NOT NULL,"
    " severity TEXT NOT NULL,"
    " rule TEXT NOT NULL,"
    " reason TEXT NOT NULL,"
    " identity_scheme TEXT,"
    " rule_id TEXT,"
    " entity_id TEXT,"
    " suppressed_by TEXT,"
    " PRIMARY KEY (run_id, idx)"
    ") WITHOUT ROWID",
    "CREATE TABLE routes ("
    " run_id TEXT NOT NULL,"
    " idx INTEGER NOT NULL,"
    " method TEXT NOT NULL,"
    " path TEXT NOT NULL,"
    " file TEXT NOT NULL,"
    " auth TEXT,"
    " line INTEGER,"
    " guards TEXT,"
    " PRIMARY KEY (run_id, idx)"
    ") WITHOUT ROWID",
    "CREATE TABLE evidence ("
    " run_id TEXT NOT NULL,"
    " finding_id TEXT NOT NULL,"
    " suppressed INTEGER NOT NULL,"
    " kind TEXT NOT NULL,"
    " idx INTEGER NOT NULL,"
    " text TEXT,"
    " file TEXT,"
    " line INTEGER,"
    " fingerprint TEXT,"
    " PRIMARY KEY (run_id, finding_id, suppressed, kind, idx)"
    ") WITHOUT ROWID",
)

# Table name -> row type. Dataclass field names and order are the column
# names and order, so the writer and reader cannot drift from the schema.
_TABLES: tuple[tuple[str, type], ...] = (
    ("generations", GenerationRow),
    ("runs", RunRow),
    ("findings", FindingRow),
    ("suppressions", SuppressionRow),
    ("routes", RouteRow),
    ("evidence", EvidenceRow),
)
# Columns stored as compact JSON (a published list) and as 0/1 (a bool).
_JSON_FIELDS = frozenset({"tags", "cwe", "guards", "suppressed_by"})
_BOOL_FIELDS = frozenset({"valid", "indexed", "suppressed"})

# A generation's manifest can sit at most three directories below the base:
# <base>/<fleet run>/<repo>/<child>.
_INVENTORY_DEPTH = 3
# Engine-owned directories that never hold generations.
_NOT_GENERATIONS = frozenset({"diagnostics", INDEX_DIRNAME})
# The engine never accepts a manifest larger than this (see safe_fs).
_MANIFEST_MAX_BYTES = 1_000_000


def index_path(base: str | Path) -> Path:
    """Where the derived index for output base *base* lives."""
    return Path(base) / INDEX_DIRNAME / INDEX_FILENAME


# --- freshness -----------------------------------------------------------------
#
# The fingerprint is taken from the manifests only, never from the index, so
# it can be computed before anything is read and again on every later read.


def _is_junction(entry: os.DirEntry) -> bool:
    probe = getattr(entry, "is_junction", None)
    return bool(probe()) if probe is not None else False


def _manifest_digest(path: Path) -> str | None:
    """Checksum of a manifest file, or None when there is no regular file."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with path.open("rb") as handle:
            raw = handle.read(_MANIFEST_MAX_BYTES + 1)
    except OSError:
        return None
    return hashlib.sha256(raw).hexdigest()


def manifest_inventory(base: str | Path) -> tuple[tuple[str, str], ...]:
    """Every manifest under *base*, as ``(directory, checksum)`` pairs.

    Directories are posix paths relative to *base*. Symlinked and junction
    directories are never entered (the engine never recognises them as
    generations), and neither are engine-owned non-generation directories. An
    unreadable base raises ``OSError``; an unreadable directory further down
    is skipped, since no valid generation could be behind it.
    """
    root = Path(base)
    found: list[tuple[str, str]] = []
    pending: list[tuple[Path, str]] = [(root, "")]
    for depth in range(_INVENTORY_DEPTH):
        children: list[tuple[Path, str]] = []
        for folder, relative in pending:
            try:
                with os.scandir(folder) as entries:
                    listing = sorted(entries, key=lambda entry: entry.name)
            except OSError:
                if depth == 0:
                    raise
                continue
            for entry in listing:
                if (entry.name in _NOT_GENERATIONS or entry.is_symlink()
                        or _is_junction(entry) or not entry.is_dir(follow_symlinks=False)):
                    continue
                child = f"{relative}/{entry.name}" if relative else entry.name
                digest = _manifest_digest(Path(entry.path) / MANIFEST_FILENAME)
                if digest is not None:
                    found.append((child, digest))
                children.append((Path(entry.path), child))
        pending = children
    return tuple(sorted(found))


def index_fingerprint(base: str | Path) -> str:
    """Identity of the generation set currently under *base*."""
    return fingerprint_of(manifest_inventory(base))


def fingerprint_of(inventory: Iterable[tuple[str, str]]) -> str:
    """The fingerprint of an already-listed manifest inventory."""
    payload = json.dumps([INDEX_FORMAT, [list(item) for item in inventory]],
                         ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --- writing -------------------------------------------------------------------


def _encode(name: str, value: Any) -> Any:
    if name in _JSON_FIELDS:
        return None if value is None else json.dumps(list(value), ensure_ascii=True, separators=(",", ":"))
    if name in _BOOL_FIELDS:
        return int(value)
    return value


def _decode(name: str, value: Any) -> Any:
    if name in _JSON_FIELDS:
        return None if value is None else tuple(json.loads(value))
    if name in _BOOL_FIELDS:
        return bool(value)
    return value


def _insert(conn: sqlite3.Connection, table: str, row_type: type, rows: Sequence[Any]) -> None:
    if not rows:
        return
    names = [field.name for field in dataclasses.fields(row_type)]
    sql = (f"INSERT INTO {table} ({', '.join(names)}) "
           f"VALUES ({', '.join(':' + name for name in names)})")
    conn.executemany(sql, [{name: _encode(name, getattr(row, name)) for name in names} for row in rows])


def write_index(target: str | Path, rows: IndexRows) -> None:
    """Write *rows* to a new file at *target*, which must not already exist.

    Always build into a fresh path: opening a corrupt file for writing fails
    with "database disk image is malformed" instead of repairing it.
    """
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"refusing to overwrite an existing file: {target}")
    conn = sqlite3.connect(target, isolation_level=None)
    try:
        conn.execute("PRAGMA page_size = 4096")
        conn.execute("PRAGMA encoding = 'UTF-8'")
        conn.execute("PRAGMA journal_mode = DELETE")  # never WAL: no side files to exclude
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        for statement in SCHEMA:
            conn.execute(statement)
        conn.execute("BEGIN")
        conn.executemany("INSERT INTO index_meta (key, value) VALUES (?, ?)", (
            (_SCHEMA_VERSION_KEY, str(SCHEMA_VERSION)),
            (_FORMAT_KEY, INDEX_FORMAT),
            (_FINGERPRINT_KEY, rows.fingerprint),
        ))
        for table, row_type in _TABLES:
            _insert(conn, table, row_type, getattr(rows, table))
        conn.execute("COMMIT")
    finally:
        conn.close()


# --- reading -------------------------------------------------------------------


def _connect_readonly(path: Path) -> sqlite3.Connection:
    # mode=ro never creates the file and never writes a journal, so a reader
    # cannot "repair" the very corruption a later rebuild has to recover from.
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, isolation_level=None)


def _meta(conn: sqlite3.Connection) -> dict[str, str]:
    return dict(conn.execute("SELECT key, value FROM index_meta").fetchall())


def _select(conn: sqlite3.Connection, table: str, row_type: type) -> list[Any]:
    names = [field.name for field in dataclasses.fields(row_type)]
    rows = conn.execute(f"SELECT {', '.join(names)} FROM {table}")
    return [row_type(*[_decode(name, value) for name, value in zip(names, row, strict=True)])
            for row in rows]


def read_index(conn: sqlite3.Connection) -> IndexRows:
    """Every row of the index, in canonical order.

    Raises ``sqlite3.Error`` for any structural damage met on the way —
    including damage that only shows up part-way through a table — and
    ``TypeError``/``ValueError`` when the columns do not match this schema.
    """
    fingerprint = _meta(conn).get(_FINGERPRINT_KEY)
    if fingerprint is None:
        raise sqlite3.DatabaseError("index has no generation fingerprint")
    tables = {table: _select(conn, table, row_type) for table, row_type in _TABLES}
    return IndexRows.canonical(fingerprint=fingerprint, **tables)


def dump_tables(conn: sqlite3.Connection) -> dict[str, list[tuple[Any, ...]]]:
    """Raw stored rows of every table in canonical order, for content diffs."""
    return {"index_meta": conn.execute("SELECT key, value FROM index_meta ORDER BY key").fetchall(),
            **{table: conn.execute(f"SELECT * FROM {table}").fetchall() for table, _ in _TABLES}}


def open_fresh_index(base: str | Path) -> tuple[sqlite3.Connection | None, str | None]:
    """Open the index for *base* read-only when it can be trusted.

    Returns ``(connection, None)``, or ``(None, reason)`` with a reason from
    :data:`UNUSABLE_REASONS` when the index is missing, unreadable, corrupt,
    on another schema version, or built from a different generation set. In
    every such case the caller reads the generations instead.

    The connection is the caller's to close.
    """
    path = index_path(base)
    try:
        present = path.is_file() and not path.is_symlink()
    except OSError:
        present = False
    if not present:
        return None, "missing"
    try:
        conn = _connect_readonly(path)
    except (sqlite3.Error, OSError, ValueError):
        return None, "unreadable"
    try:
        try:
            meta = _meta(conn)
        except sqlite3.Error:
            # A zero-length file is not an error to SQLite: it reads as an
            # empty database. The missing meta is what exposes the truncation.
            return None, "corrupt"
        if (meta.get(_FORMAT_KEY) != INDEX_FORMAT
                or meta.get(_SCHEMA_VERSION_KEY) != str(SCHEMA_VERSION)):
            return None, "schema_mismatch"
        if meta.get(_FINGERPRINT_KEY) != index_fingerprint(Path(base)):
            return None, "stale"
    except (sqlite3.Error, OSError):
        # The freshness check touches the filesystem (manifest inventory), so
        # only the fallback families close-and-raise here; a
        # KeyboardInterrupt or SystemExit propagates untouched.
        conn.close()
        raise
    return conn, None


def _iter_reasons() -> Iterator[str]:
    yield from UNUSABLE_REASONS

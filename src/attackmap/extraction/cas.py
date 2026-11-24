"""Content-addressed incremental store (AR080 / AC-401).

Two layers under one configurable root (default ``~/.attackmap/cas``):

* ``BlobStore`` — content-addressed byte storage. Blobs live at
  ``blobs/<ab>/<cd>/<rest-of-sha256>`` (two-level prefix directories),
  written atomically (temp file + ``os.replace``) and verified by
  re-hashing on read: a tampered blob reads as a miss, never as data.
* ``ExtractionCache`` — the per-analyzer extraction cache keyed by
  ``(analyzer_id, analyzer_version, blob_hash)``. Payloads are stored as
  blobs too, so one content-addressed pool backs both file content and
  analyzer output, and payload integrity reduces to a content-hash check.
  A small JSON index maps keys to blobs and carries the LRU order.

Eviction is LRU under a configurable byte cap (default 2 GiB,
``ATTACKMAP_CAS_MAX_BYTES`` or the ``max_bytes`` parameter); blobs pinned
by the current run are never evicted (``begin_run`` / ``pin`` / ``save``).

Same trust boundary as ``extraction/incremental.py``: integrity checks
catch corruption, not forgery — the store must live outside the scanned
repo, in the trusted compute environment. Everything here is an
optimization: any doubt degrades to a full recompute of the file.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path

# Bump when the index layout or key material changes: existing stores with a
# different schema string are discarded wholesale (safe recompute).
CAS_SCHEMA = "attackmap-cas/1.0"

# Optional knobs. The store is an optimization, never a correctness gate:
# ATTACKMAP_CAS=0 disables it, and any failure to open degrades to no caching.
CAS_ENV = "ATTACKMAP_CAS"
CAS_ROOT_ENV = "ATTACKMAP_CAS_ROOT"
CAS_MAX_BYTES_ENV = "ATTACKMAP_CAS_MAX_BYTES"

DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB — generous default per AC-401

# The built-in per-file pass registers as one analyzer until the analyzer
# SDK v2 (AR082) lets external analyzers plug into this path with their own
# ids and versions. The version material carries everything the per-file
# output depends on beyond blob content (mirrors FileCacheKey in
# incremental.py): engine code identity, source-role policy, rel, suffix and
# pass configuration.
BUILTIN_PASS_ANALYZER = "builtin.per-file-pass"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


class BlobStore:
    """Content-addressed blob storage with hash-verified reads."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root) / "blobs"

    def _path(self, digest: str) -> Path:
        return self.root / digest[:2] / digest[2:4] / digest

    def put(self, data: bytes) -> str:
        """Store bytes once; returns their content hash (dedupe by address).

        An existing address with a wrong size is corruption, not a hit: it
        is rewritten. (Same-size corruption is caught by the hash check on
        read; readers remove the bad file so the next put repairs it.)"""
        digest = _sha256_bytes(data)
        path = self._path(digest)
        try:
            # One stat instead of exists()+stat(): a missing file raises
            # OSError (handled below), a size match means the content-
            # addressed blob is already stored. On the 10k-file cold
            # path this halves the per-blob stat syscalls (AR080/AC-401).
            if path.stat().st_size == len(data):
                return digest
        except OSError:
            pass
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
        return digest

    def get(self, digest: str) -> bytes | None:
        """Blob bytes, or None when missing, unreadable or hash-mismatched."""
        try:
            data = self._path(digest).read_bytes()
        except OSError:
            return None
        if _sha256_bytes(data) != digest:
            return None  # tampered or corrupt blob: a miss, never data
        return data

    def has(self, digest: str) -> bool:
        return self._path(digest).is_file()

    def size(self, digest: str) -> int:
        try:
            return self._path(digest).stat().st_size
        except OSError:
            return 0

    def remove(self, digest: str) -> None:
        with contextlib.suppress(OSError):
            self._path(digest).unlink()
        # Best-effort pruning of now-empty prefix directories.
        leaf = self._path(digest)
        for parent in (leaf.parent, leaf.parent.parent):
            with contextlib.suppress(OSError):
                parent.rmdir()


class ExtractionCache:
    """Per-analyzer extraction cache over a :class:`BlobStore`.

    Index: one JSON document at ``<root>/index.json`` —
    ``{"schema", "seq", "entries": {key: {analyzer, version, blob,
    payload_blob, last_use}}}`` where ``key`` is the sha256 of the canonical
    ``(analyzer_id, analyzer_version, blob_hash)`` triple. The monotonic
    ``seq``/``last_use`` pair is the LRU order and survives reopen.

    Storage choice mirrors ``incremental.PerFileCache``: a single JSON
    document written atomically (temp file + ``os.replace``), stdlib-only
    and trivially inspectable. SQLite stays the documented follow-up if the
    index ever grows large enough that whole-file rewrite costs matter.
    """

    def __init__(self, root: str | Path, *, max_bytes: int | None = None) -> None:
        self.root = Path(root)
        self.blobs = BlobStore(self.root)
        self.index_path = self.root / "index.json"
        if max_bytes is None:
            max_bytes = int(os.environ.get(CAS_MAX_BYTES_ENV, DEFAULT_MAX_BYTES))
        self.max_bytes = max(0, int(max_bytes))
        self._entries: dict[str, dict] = self._load()
        self._seq = max(
            (entry["last_use"] for entry in self._entries.values()
             if isinstance(entry.get("last_use"), int) and entry["last_use"] >= 0),
            default=0,
        )
        self._dirty = False
        self._orphans_possible = False
        # The runtime pin set of the current run; empty while loading.
        self._pinned: set[str] = set()
        # Restoring the bound on reopen, like PerFileCache: a store written
        # under a larger cap gets trimmed to the cap now in effect.
        self._evict_to_cap()

    # -- lifecycle ---------------------------------------------------------

    def _load(self) -> dict[str, dict]:
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict) or raw.get("schema") != CAS_SCHEMA:
            return {}
        entries = raw.get("entries")
        if not isinstance(entries, dict):
            return {}
        # Keep only well-formed entries; anything else is stale by construction.
        return {
            str(key): entry for key, entry in entries.items() if self._entry_ok(entry)
        }

    @staticmethod
    def _entry_ok(entry: object) -> bool:
        return (
            isinstance(entry, dict)
            and isinstance(entry.get("analyzer"), str)
            and isinstance(entry.get("version"), str)
            and isinstance(entry.get("blob"), str)
            and isinstance(entry.get("payload_blob"), str)
        )

    def save(self) -> bool:
        """Evict to the byte cap (pins still active), persist, lapse pins."""
        try:
            self._evict_to_cap()
            if self._dirty:
                document = {
                    "schema": CAS_SCHEMA,
                    "seq": self._seq,
                    "entries": self._entries,
                }
                self.root.mkdir(parents=True, exist_ok=True)
                tmp = self.index_path.with_name(f".{self.index_path.name}.{os.getpid()}.tmp")
                tmp.write_text(
                    json.dumps(document, ensure_ascii=True, sort_keys=True), encoding="utf-8"
                )
                os.replace(tmp, self.index_path)
        except OSError:
            return False
        self._dirty = False
        self._orphans_possible = False
        # Pins protect one run; the next run re-pins what it actually uses.
        self._pinned.clear()
        return True

    # -- entry access ------------------------------------------------------

    @staticmethod
    def _key(analyzer: str, version: str, blob: str) -> str:
        return _sha256_text(_canonical([analyzer, version, blob]))

    def get(self, analyzer: str, version: str, blob: str) -> dict | None:
        """The cached extraction payload for the key triple, or None on any
        doubt (caller recomputes). Updates the LRU touch on a hit."""
        entry = self._entries.get(self._key(analyzer, version, blob))
        if entry is None:
            return None
        if not self.blobs.has(entry["blob"]):
            self._drop(entry)
            return None
        raw = self.blobs.get(entry["payload_blob"])
        if raw is None:
            # Tampered or lost payload blob: quarantine the bad file (the
            # next put rewrites it) and drop the entry.
            self.blobs.remove(entry["payload_blob"])
            self._drop(entry)
            return None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self.blobs.remove(entry["payload_blob"])
            self._drop(entry)
            return None
        if not isinstance(payload, dict):
            self.blobs.remove(entry["payload_blob"])
            self._drop(entry)
            return None
        entry["last_use"] = self._next_seq()
        self._dirty = True
        return payload

    def put(self, analyzer: str, version: str, blob: str,
            source: str, payload: dict) -> bool:
        """Store an analyzer's extraction payload for a blob. Best effort:
        the source content is stored under ``blob`` (dedupe across files and
        repos), the payload as one more blob, and the index entry binds them.
        """
        try:
            source_bytes = source.encode("utf-8")
            if self.blobs.put(source_bytes) != blob:
                return False  # caller's hash does not match its content
            payload_bytes = _canonical(payload).encode("utf-8")
            payload_blob = self.blobs.put(payload_bytes)
            self._entries[self._key(analyzer, version, blob)] = {
                "analyzer": analyzer,
                "version": version,
                "blob": blob,
                "payload_blob": payload_blob,
                # Byte accounting for the eviction cap, recorded at write
                # time so a cap check never has to stat the blob tree.
                "bytes": len(source_bytes) + len(payload_bytes),
                "last_use": self._next_seq(),
            }
            self._dirty = True
            # A blob written this run is pinned: never evicted this run.
            self._pinned.add(blob)
            return True
        except OSError:
            return False

    def _drop(self, entry: dict) -> None:
        key = self._key(entry["analyzer"], entry["version"], entry["blob"])
        if self._entries.pop(key, None) is not None:
            self._dirty = True
            self._orphans_possible = True

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    # -- current-run pinning ------------------------------------------------

    def begin_run(self) -> None:
        """Start a new run: the previous run's pins lapse."""
        self._pinned.clear()

    def pin(self, blob: str) -> None:
        """Pin a blob so LRU eviction skips its entry this run."""
        self._pinned.add(blob)

    # -- eviction ----------------------------------------------------------

    def _refcounts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self._entries.values():
            for digest in (entry["blob"], entry["payload_blob"]):
                counts[digest] = counts.get(digest, 0) + 1
        return counts

    def total_bytes(self) -> int:
        """Bytes the live entries account for (blobs + index file).

        Uses the per-entry size recorded at put time — a deliberate
        overcount when blobs are shared across entries (conservative for a
        cap). Entries written before per-entry accounting fall back to
        stat-ing their blobs."""
        total = 0
        for entry in self._entries.values():
            size = entry.get("bytes")
            if isinstance(size, int) and size >= 0:
                total += size
            else:
                total += self.blobs.size(entry["blob"])
                total += self.blobs.size(entry["payload_blob"])
        with contextlib.suppress(OSError):
            total += self.index_path.stat().st_size
        return total

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def _evict_to_cap(self) -> None:
        """LRU-evict unpinned entries (and their orphaned blobs) while over
        the byte cap. Pinned entries always survive: the cap yields to the
        current run's pin set rather than dropping what this run stored."""
        total = self.total_bytes()
        if total <= self.max_bytes:
            # Under the cap the eviction loop can make no decision; skip the
            # O(n log n) refcount/sort work on the hot 10k-entry warm path
            # (AR080/AC-401). Byte accounting stays the authoritative
            # total_bytes(), so eviction behavior is unchanged.
            if self._orphans_possible:
                self._collect_garbage()
            return
        refcounts = self._refcounts()
        order = sorted(
            self._entries.items(),
            key=lambda kv: kv[1].get("last_use") or 0,
        )
        for key, entry in order:
            if total <= self.max_bytes:
                break
            if entry["blob"] in self._pinned:
                continue  # current-run blob: never evicted
            self._entries.pop(key, None)
            self._dirty = True
            total -= self._entry_bytes(entry)
            for digest in (entry["blob"], entry["payload_blob"]):
                refcounts[digest] -= 1
                if refcounts[digest] <= 0:
                    self.blobs.remove(digest)
        if self._orphans_possible:
            self._collect_garbage()

    @staticmethod
    def _entry_bytes(entry: dict) -> int:
        size = entry.get("bytes")
        if isinstance(size, int) and size >= 0:
            return size
        return 0  # legacy entry without recorded sizes: blobs were stat-ed

    def _collect_garbage(self) -> None:
        """Remove blob files no live entry references (crash leftovers)."""
        referenced = set(self._refcounts())
        blobs_dir = self.blobs.root
        if not blobs_dir.is_dir():
            return
        for path in blobs_dir.rglob("*"):
            if path.is_file() and path.name not in referenced:
                with contextlib.suppress(OSError):
                    path.unlink()


def analyzer_version(*, engine: str, policy: str, rel: str, suffix: str,
                     pass_suffixes: set[str] | None) -> str:
    """The analyzer_version identity for one file's built-in per-file pass.

    Carries every input the per-file output depends on beyond blob content
    (mirrors ``FileCacheKey`` in incremental.py): engine code identity,
    source-role policy, rel, suffix and pass configuration. A future
    content-only analyzer can build its own version from just the fields it
    actually depends on.
    """
    pass_id = None if pass_suffixes is None else sorted(pass_suffixes)
    return _sha256_text(_canonical([CAS_SCHEMA, engine, policy, rel, suffix, pass_id]))


def default_cas_root() -> Path:
    """The documented default store root."""
    return Path.home() / ".attackmap" / "cas"


def resolve_cas_root(cache_dir: str | Path | None = None) -> Path:
    """Where the store lives for a scan.

    Precedence: ``ATTACKMAP_CAS_ROOT`` override; else ``<cache_dir>/cas``
    when the caller pinned the per-file cache to a directory (keeps tests
    and benchmarks hermetic); else the documented default
    ``~/.attackmap/cas`` — always outside the scanned repository.
    """
    override = os.environ.get(CAS_ROOT_ENV)
    if override:
        return Path(override)
    if cache_dir is not None:
        return Path(cache_dir) / "cas"
    return default_cas_root()


def cas_enabled() -> bool:
    """The low-level kill switch (``ATTACKMAP_CAS=0`` disables the store)."""
    return os.environ.get(CAS_ENV, "") != "0"


def open_cas(cache_dir: str | Path | None = None, *,
             max_bytes: int | None = None) -> ExtractionCache | None:
    """Open the store for one scan, or None when disabled/unavailable.

    Optimization only: any failure to open degrades to no caching, exactly
    like the per-file cache in ``scanner._open_incremental_cache``.
    """
    if not cas_enabled():
        return None
    try:
        return ExtractionCache(resolve_cas_root(cache_dir), max_bytes=max_bytes)
    except (OSError, ValueError, RuntimeError):
        # Degrade to no caching: unreadable/missing dirs (OSError), a corrupt
        # or malformed index (ValueError), or an inconsistent store state
        # (RuntimeError) must never fail the scan — the cache is an
        # optimization only.
        return None

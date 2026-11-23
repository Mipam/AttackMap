"""Content-addressed incremental store (AR080/AC-401).

Covers: blob put/get/dedupe and the two-level layout, hash-verified tamper
detection, per-analyzer key stability, persistence across reopen, LRU
byte-cap eviction with current-run pinning, corruption resilience on the
scan path (a tampered CAS payload re-extracts), and end-to-end wiring —
CAS replay across cache directories stays equivalent to a full scan, which
is the hard invariant.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from attackmap.extraction import scanner as scanner_mod
from attackmap.extraction.cas import (
    CAS_ENV,
    CAS_MAX_BYTES_ENV,
    CAS_ROOT_ENV,
    DEFAULT_MAX_BYTES,
    BlobStore,
    ExtractionCache,
    analyzer_version,
    cas_enabled,
    default_cas_root,
    open_cas,
    resolve_cas_root,
)
from attackmap.extraction.incremental import engine_identity, source_policy_identity
from attackmap.extraction.scanner import scan_files


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


# --- blob store -----------------------------------------------------------------


def test_blob_store_put_get_roundtrip_and_layout(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "cas")
    data = b"from flask import Blueprint\n"
    digest = store.put(data)
    assert digest == _digest("from flask import Blueprint\n")
    # Two-level prefix directories: blobs/<ab>/<cd>/<rest>.
    assert store._path(digest) == (
        tmp_path / "cas" / "blobs" / digest[:2] / digest[2:4] / digest
    )
    assert store.get(digest) == data
    assert store.has(digest)
    assert store.get("f" * 64) is None  # unknown digest


def test_blob_store_dedupes_identical_content(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "cas")
    first = store.put(b"same content")
    second = store.put(b"same content")
    assert first == second
    files = [p for p in (tmp_path / "cas" / "blobs").rglob("*") if p.is_file()]
    assert len(files) == 1


def test_blob_store_detects_tampering(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "cas")
    digest = store.put(b"original bytes")
    path = store._path(digest)
    path.write_bytes(b"tampered!bytes")
    assert store.get(digest) is None  # hash mismatch reads as a miss


# --- extraction cache -------------------------------------------------------------


def _put(cache: ExtractionCache, i: int, *, analyzer: str = "analyzer-a",
         version: str = "v1", body: str | None = None) -> str:
    blob = _digest(body if body is not None else f"content-{i}")
    assert cache.put(analyzer, version, blob, body or f"content-{i}", {"i": i})
    return blob


def test_extraction_cache_roundtrip_persists_across_reopen(tmp_path: Path) -> None:
    root = tmp_path / "cas"
    cache = ExtractionCache(root)
    blob = _put(cache, 1)
    assert cache.get("analyzer-a", "v1", blob) == {"i": 1}
    assert cache.save()
    reopened = ExtractionCache(root)
    assert reopened.entry_count == 1
    assert reopened.get("analyzer-a", "v1", blob) == {"i": 1}


def test_extraction_cache_key_stability(tmp_path: Path) -> None:
    cache = ExtractionCache(tmp_path / "cas")
    blob = _put(cache, 1)
    assert cache.get("analyzer-a", "v1", blob) is not None
    # Any key dimension changing means a miss.
    assert cache.get("analyzer-b", "v1", blob) is None
    assert cache.get("analyzer-a", "v2", blob) is None
    assert cache.get("analyzer-a", "v1", _digest("other content")) is None


def test_extraction_cache_detects_tampered_payload_and_recovers(tmp_path: Path) -> None:
    root = tmp_path / "cas"
    cache = ExtractionCache(root)
    blob = _put(cache, 1)
    cache.save()
    # Tamper with the payload blob on disk (flip bytes, keep the address).
    entry = cache._entries[cache._key("analyzer-a", "v1", blob)]
    payload_path = cache.blobs._path(entry["payload_blob"])
    payload_path.write_bytes(b'{"i": 999}')
    # Corrupt payload: a miss, the entry is dropped, and a re-put (the
    # caller's re-extraction) restores a working entry.
    assert cache.get("analyzer-a", "v1", blob) is None
    assert cache._key("analyzer-a", "v1", blob) not in cache._entries
    _put(cache, 1, body="content-1")
    assert cache.get("analyzer-a", "v1", blob) == {"i": 1}


def test_extraction_cache_missing_source_blob_is_a_miss(tmp_path: Path) -> None:
    cache = ExtractionCache(tmp_path / "cas")
    blob = _put(cache, 1)
    cache.save()
    cache.blobs.remove(blob)
    assert cache.get("analyzer-a", "v1", blob) is None


def _entry_bytes(cache: ExtractionCache, analyzer: str, version: str, blob: str) -> int:
    entry = cache._entries[cache._key(analyzer, version, blob)]
    return cache.blobs.size(entry["blob"]) + cache.blobs.size(entry["payload_blob"])


def test_eviction_is_lru_by_last_use(tmp_path: Path) -> None:
    root = tmp_path / "cas"
    cache = ExtractionCache(root, max_bytes=10**9)
    digests = [_put(cache, i) for i in range(4)]
    cache.save()
    first = ExtractionCache(root, max_bytes=10**9)
    one = _entry_bytes(first, "analyzer-a", "v1", digests[0])
    # Touch entry 0: entry 1 becomes the least-recently-used candidate.
    assert first.get("analyzer-a", "v1", digests[0]) is not None
    first.save()
    again = ExtractionCache(root, max_bytes=10**9)
    again.max_bytes = again.total_bytes() - one  # exactly one entry over the cap
    again.save()
    assert again.entry_count == 3
    assert again.get("analyzer-a", "v1", digests[1]) is None  # LRU evicted
    for digest in (digests[0], digests[2], digests[3]):
        assert again.get("analyzer-a", "v1", digest) is not None


def test_eviction_never_drops_current_run_pins(tmp_path: Path) -> None:
    root = tmp_path / "cas"
    cache = ExtractionCache(root, max_bytes=10**9)
    digests = [_put(cache, i) for i in range(3)]
    cache.save()  # laps the implicit put-time pins of that run
    first = ExtractionCache(root, max_bytes=10**9)
    one = _entry_bytes(first, "analyzer-a", "v1", digests[0])
    first.pin(digests[0])  # a hit in the "current run" pins the blob
    first.max_bytes = first.total_bytes() - one
    first.save()
    # The pinned blob survived; the LRU unpinned entry was reclaimed instead.
    assert first._key("analyzer-a", "v1", digests[0]) in first._entries
    assert first.entry_count == 2
    # After the run ends (begin_run) the pin lapses and the cap may reclaim it.
    first.begin_run()
    first.max_bytes = first.total_bytes() - one
    first.save()
    assert first.get("analyzer-a", "v1", digests[0]) is None


def test_max_bytes_env_override_and_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(CAS_MAX_BYTES_ENV, "1234")
    assert ExtractionCache(tmp_path / "cas").max_bytes == 1234
    monkeypatch.delenv(CAS_MAX_BYTES_ENV)
    assert ExtractionCache(tmp_path / "cas").max_bytes == DEFAULT_MAX_BYTES


def test_resolve_cas_root_precedence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(CAS_ROOT_ENV, raising=False)
    assert resolve_cas_root() == default_cas_root()
    assert resolve_cas_root(tmp_path / "cache") == tmp_path / "cache" / "cas"
    monkeypatch.setenv(CAS_ROOT_ENV, str(tmp_path / "env-root"))
    assert resolve_cas_root(tmp_path / "cache") == tmp_path / "env-root"


def test_open_cas_disabled_by_env(tmp_path: Path, monkeypatch) -> None:
    assert cas_enabled()
    monkeypatch.setenv(CAS_ENV, "0")
    assert not cas_enabled()
    assert open_cas(tmp_path / "cache") is None


def test_analyzer_version_tracks_all_output_dimensions() -> None:
    base = analyzer_version(engine="e", policy="p", rel="src/a.py",
                            suffix=".py", pass_suffixes=None)
    assert base == analyzer_version(engine="e", policy="p", rel="src/a.py",
                                    suffix=".py", pass_suffixes=None)
    for mutated in (
        analyzer_version(engine="e2", policy="p", rel="src/a.py",
                         suffix=".py", pass_suffixes=None),
        analyzer_version(engine="e", policy="p2", rel="src/a.py",
                         suffix=".py", pass_suffixes=None),
        analyzer_version(engine="e", policy="p", rel="src/b.py",
                         suffix=".py", pass_suffixes=None),
        analyzer_version(engine="e", policy="p", rel="src/a.py",
                         suffix=".js", pass_suffixes=None),
        analyzer_version(engine="e", policy="p", rel="src/a.py",
                         suffix=".py", pass_suffixes={".py", ".js"}),
    ):
        assert base != mutated


# --- scan-path wiring --------------------------------------------------------------


def _seed_repo(repo: Path) -> None:
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "app.py").write_text(
        "from flask import Blueprint\n"
        "import hashlib\n"
        "bp = Blueprint('api', __name__, url_prefix='/v')\n"
        "@bp.route('/users', methods=['GET'])\n"
        "def users():\n"
        "    digest = hashlib.md5(b'password')\n"
        "    return []\n",
        encoding="utf-8",
    )
    (repo / "src" / "svc.js").write_text(
        "const express = require('express');\n"
        "const router = express.Router();\n"
        "router.get('/items', (req, res) => { res.send([]); });\n",
        encoding="utf-8",
    )


def _counted_analyzer(monkeypatch):
    calls: list[str] = []
    original = scanner_mod._analyze_indexed_file

    def counted(item):
        calls.append(item.rel)
        return original(item)

    monkeypatch.setattr(scanner_mod, "_analyze_indexed_file", counted)
    return calls


def test_incremental_scan_writes_cas_under_cache_dir(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _seed_repo(repo)
    cache_dir = tmp_path / "cache"
    incremental = scan_files(repo, incremental=True, cache_dir=cache_dir)
    cas_root = cache_dir / "cas"
    assert (cas_root / "index.json").is_file()
    store = ExtractionCache(cas_root)
    assert store.entry_count == incremental.files_scanned
    # Blob content is deduped under the two-level layout.
    blobs = [p for p in (cas_root / "blobs").rglob("*") if p.is_file()]
    assert len(blobs) >= incremental.files_scanned  # source + payload blobs


def test_incremental_off_creates_no_cas(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _seed_repo(repo)
    cache_dir = tmp_path / "cache"
    scan_files(repo, cache_dir=cache_dir)  # incremental defaults to False
    assert not cache_dir.exists()


def test_cas_replay_across_cache_dirs_stays_equivalent(tmp_path: Path, monkeypatch) -> None:
    """The CAS value proposition: a per-file cache in a fresh directory
    replays everything from the content-addressed store — zero analyzer
    runs — and the result equals a full scan."""
    repo = tmp_path / "repo"
    _seed_repo(repo)
    cas_root = tmp_path / "cas-root"
    monkeypatch.setenv(CAS_ROOT_ENV, str(cas_root))
    scan_files(repo, incremental=True, cache_dir=tmp_path / "cache-1")  # cold

    calls = _counted_analyzer(monkeypatch)
    replayed = scan_files(repo, incremental=True, cache_dir=tmp_path / "cache-2")
    assert calls == []  # warm CAS: nothing was re-analyzed
    assert replayed.model_dump() == scan_files(repo).model_dump()


def test_cas_replay_after_edit_recomputes_only_changed_file(
    tmp_path: Path, monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    _seed_repo(repo)
    cas_root = tmp_path / "cas-root"
    monkeypatch.setenv(CAS_ROOT_ENV, str(cas_root))
    scan_files(repo, incremental=True, cache_dir=tmp_path / "cache-1")

    calls = _counted_analyzer(monkeypatch)
    (repo / "src" / "app.py").write_text(
        (repo / "src" / "app.py").read_text(encoding="utf-8") + "\nMARKER = 1\n",
        encoding="utf-8",
    )
    incremental = scan_files(repo, incremental=True, cache_dir=tmp_path / "cache-2")
    assert sorted(calls) == ["src/app.py"]  # only the changed blob missed
    assert incremental.model_dump() == scan_files(repo).model_dump()


def test_cas_tampered_payload_recomputes_on_scan(tmp_path: Path, monkeypatch) -> None:
    """A tampered payload blob is detected via its content hash; the scan
    re-extracts that file and stays equivalent to a full scan."""
    repo = tmp_path / "repo"
    _seed_repo(repo)
    cas_root = tmp_path / "cas-root"
    monkeypatch.setenv(CAS_ROOT_ENV, str(cas_root))
    scan_files(repo, incremental=True, cache_dir=tmp_path / "cache-1")

    store = ExtractionCache(cas_root)
    app_body = (repo / "src" / "app.py").read_text(encoding="utf-8")
    key = next(k for k, e in store._entries.items() if e["blob"] == _digest(app_body))
    entry = store._entries[key]
    payload_path = store.blobs._path(entry["payload_blob"])
    payload_path.write_bytes(b'{"routes": [], "forged": true}')
    assert store.get(entry["analyzer"], entry["version"], entry["blob"]) is None

    calls = _counted_analyzer(monkeypatch)
    incremental = scan_files(repo, incremental=True, cache_dir=tmp_path / "cache-2")
    # The tampered entry missed and was re-extracted; the intact entry
    # replayed from the CAS (cache-2's per-file cache was cold).
    assert sorted(calls) == ["src/app.py"]
    assert incremental.model_dump() == scan_files(repo).model_dump()


def test_analyzer_version_tracks_cas_schema(monkeypatch, tmp_path: Path) -> None:
    """The version material is hashed with the CAS schema: a schema bump
    invalidates stored versions exactly like a code upgrade does (the
    engine- and policy-dimension tracking is covered above)."""
    engine = engine_identity()
    policy = source_policy_identity()
    v1 = analyzer_version(engine=engine, policy=policy, rel="src/app.py",
                          suffix=".py", pass_suffixes=None)
    monkeypatch.setattr("attackmap.extraction.cas.CAS_SCHEMA", "attackmap-cas/9.9")
    v2 = analyzer_version(engine=engine, policy=policy, rel="src/app.py",
                          suffix=".py", pass_suffixes=None)
    assert v1 != v2

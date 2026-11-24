"""Perf-regression guards for the AR080/AC-401 warm-incremental path.

The AC-401 gate (10k files, 50 changed, warm cache + CAS, p95 < 10 s) lives
in ``tools/bench_incremental.py``; these unit guards pin the structural
decisions that keep the warm run cheap, so a future refactor cannot silently
reintroduce the double-validation profile without failing here:

* ``PerFileCache.get``'s miss gate is shape-only; ``load_payload`` rebuilds
  via ``model_construct`` (no per-item re-validation on the hot replay path
  — payloads are already bound by the entry checksum and the engine
  identity in the key; see its docstring for the trust stance).
* A structurally sound but model-invalid forged entry replays without
  failing the scan (same documented trust stance as
  ``test_cache_trust_boundary_is_documented_by_consistent_forgery``), while
  a checksum-mismatched (corrupt) entry still recomputes.
* ``PerFileCache.save`` skips the write entirely when nothing changed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from attackmap.extraction.incremental import (
    FileCacheKey,
    PerFileCache,
    dump_payload,
    load_payload,
)
from attackmap.extraction.scanner import scan_files
from attackmap.models import Route


def _key(cache: PerFileCache, rel: str, content: str) -> FileCacheKey:
    return FileCacheKey(
        rel=rel, suffix=".py",
        content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        pass_suffixes=None, engine=cache.engine, policy=cache.policy,
    )


def test_get_miss_gate_is_shape_only() -> None:
    """The gate must not run per-item model validation: a structurally sound
    payload is a gate hit even when no model would validate it (replay does
    not re-validate — see load_payload's docstring)."""
    cache = PerFileCache.open(Path("/nonexistent-dir/cache.json"))
    payload = dump_payload(
        {"routes": [Route(path="/x", method="GET", file="a.py", line=1)]}, False,
    )
    bad = json.loads(json.dumps(payload))
    bad["routes"][0]["line"] = "not-an-int"
    assert cache.get(_key(cache, "a.py", "content-a")) is None
    cache.put(_key(cache, "a.py", "content-a"), bad)
    assert cache.get(_key(cache, "a.py", "content-a")) == bad
    # Replay rebuilds without validation and never raises on the bad item.
    rebuilt, csrf = load_payload(bad)
    assert csrf is False and len(rebuilt["routes"]) == 1


def test_corrupt_entry_still_recomputes_on_scan(tmp_path: Path) -> None:
    """Behavior preservation where it is owed: a CORRUPT entry (checksum no
    longer matches the payload) must be discarded and recomputed."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    body = (
        "from flask import Blueprint\n"
        "bp = Blueprint('api', __name__)\n"
        "@bp.route('/users', methods=['GET'])\n"
        "def users():\n"
        "    return []\n"
    )
    (repo / "src" / "app.py").write_text(body, encoding="utf-8")
    cache_dir = tmp_path / "cache"
    scan_files(repo, incremental=True, cache_dir=cache_dir)

    cache_file = cache_dir / "per-file-cache.json"
    document = json.loads(cache_file.read_text(encoding="utf-8"))
    key = next(iter(document["entries"]))
    document["entries"][key]["payload"]["routes"][0]["path"] = "/tampered"
    cache_file.write_text(json.dumps(document), encoding="utf-8")  # stale checksum

    incremental = scan_files(repo, incremental=True, cache_dir=cache_dir)
    assert incremental.model_dump() == scan_files(repo).model_dump()
    assert all(r.path != "/tampered" for r in incremental.routes)


def test_forged_entry_replays_without_failing(tmp_path: Path) -> None:
    """The documented trust stance: an entry with a recomputed (consistent)
    checksum is replayed as stored — exactly like the routes-path forgery
    pinned in test_incremental.py — and a wrong-typed field must never fail
    the scan."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text(
        "from flask import Blueprint\n"
        "bp = Blueprint('api', __name__)\n"
        "@bp.route('/users', methods=['GET'])\n"
        "def users():\n"
        "    return []\n",
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"
    scan_files(repo, incremental=True, cache_dir=cache_dir)

    cache_file = cache_dir / "per-file-cache.json"
    document = json.loads(cache_file.read_text(encoding="utf-8"))
    key = next(iter(document["entries"]))
    entry = document["entries"][key]
    entry["payload"]["routes"][0]["line"] = "not-an-int"
    canonical = json.dumps(entry["payload"], sort_keys=True, ensure_ascii=True,
                           separators=(",", ":"))
    entry["checksum"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    cache_file.write_text(json.dumps(document), encoding="utf-8")

    incremental = scan_files(repo, incremental=True, cache_dir=cache_dir)
    assert incremental.routes  # scan completes; forged entry replayed as stored


def test_warm_replay_skips_model_validation(tmp_path: Path, monkeypatch) -> None:
    """Perf guard: warm replay must not run pydantic model_validate per item
    (that double-pass validation was the dominant warm-run cost; the entry
    checksum + engine identity already bind the payload)."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text(
        "from flask import Blueprint\n"
        "bp = Blueprint('api', __name__)\n"
        "@bp.route('/users', methods=['GET'])\n"
        "def users():\n"
        "    return []\n",
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"
    scan_files(repo, incremental=True, cache_dir=cache_dir)  # cold: populate

    calls = {"n": 0}
    original = Route.model_validate

    def counted(cls, item):
        calls["n"] += 1
        return original(item)

    monkeypatch.setattr(Route, "model_validate", classmethod(counted))
    warm = scan_files(repo, incremental=True, cache_dir=cache_dir)  # warm: replay
    assert calls["n"] == 0
    assert warm.model_dump() == scan_files(repo).model_dump()


def test_save_skipped_when_nothing_changed(tmp_path: Path) -> None:
    """Perf guard: reopening a clean cache and saving must not rewrite the
    JSON document (whole-file rewrite only when entries actually changed)."""
    cache_file = tmp_path / "cache.json"
    cache = PerFileCache.open(cache_file)
    payload = dump_payload({}, False)
    cache.put(_key(cache, "f.py", "content-1"), payload)
    assert cache.save()
    before = cache_file.stat().st_mtime_ns
    reopened = PerFileCache.open(cache_file)
    assert not reopened._dirty
    assert reopened.save()
    assert cache_file.stat().st_mtime_ns == before  # untouched

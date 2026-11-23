"""AR086 / AC-407: hostile-input hardening integration corpus.

Each hostile input is generated at test time in ``tmp_path``; the committed
fixtures under ``tests/fixtures/hostile/`` stay a few KB total. The contract
for every case: the scan completes, no unhandled exception escapes, and no
case hangs (the suite runs under ``--timeout=300``).

Heavy cases (1 GB single-line file, 100k files in one directory) are opt-in:
they only run when ``ATTACKMAP_STRESS_TESTS=1`` is set, so the default
``pytest -m "not live"`` run stays fast and writes no large data anywhere.
"""

from __future__ import annotations

import os
import random
import shutil
import time
import tracemalloc
import zipfile
from pathlib import Path

import pytest

from attackmap.extraction import config_scanner
from attackmap.extraction.config_scanner import extract_deployment_aliases, scan_config_repo
from attackmap.extraction.index import RepoIndex
from attackmap.extraction.lockfiles import parse_lockfiles
from attackmap.extraction.scanner import extract_routes, iter_secret_matches, scan_files
from attackmap.extraction.workflow_scanner import scan_workflows
from attackmap.models import ScanResult

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "hostile"

STRESS = pytest.mark.skipif(
    os.environ.get("ATTACKMAP_STRESS_TESTS", "") != "1",
    reason="heavy stress case; opt in with ATTACKMAP_STRESS_TESTS=1",
)


def _deep_yaml(depth: int) -> str:
    """A valid, deeply nested YAML document (k8s-prefiltered shape)."""
    return (
        "kind: Service\nx:\n"
        + "".join("  " * (i + 1) + f"n{i}:\n" for i in range(depth))
        + "  " * (depth + 1)
        + "z: 1\n"
    )


def _deep_flow_yaml(depth: int) -> str:
    """A compact flow-style nested mapping: ~4 bytes per level, so a document
    well under every byte cap still exceeds the parser's 8192-event bound
    (block-style nesting hits the per-file byte cap long before the event
    cap, because its size grows quadratically with depth)."""
    return "{k:" * depth + "1" + "}" * depth


def _peak_tracemalloc_mb() -> float:
    _, peak = tracemalloc.get_traced_memory()
    return peak / (1024 * 1024)


def _write_app(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "app.py").write_text(
        "from flask import Flask\n\napp = Flask(__name__)\n\n"
        "@app.route('/health')\ndef health():\n    return 'ok'\n",
        encoding="utf-8",
    )


def _scan_repo(repo: Path):
    """The extraction-level scan a hostile tree must survive: index build,
    per-file source pass, and the config pass."""
    index = RepoIndex.build(repo)
    source = scan_files(repo, index=index)
    config = scan_config_repo(repo, index=index)
    return index, source, config


def _symlink_capable(tmp_path: Path) -> Path:
    """Skip when this host cannot create symlinks (Windows without the
    privilege/Developer Mode raises OSError)."""
    probe = tmp_path / "probe-target"
    probe.mkdir()
    try:
        os.symlink(probe, tmp_path / "probe-link")
    except OSError as exc:
        pytest.skip(f"host cannot create symlinks: {exc}")
    return probe


# ---------------------------------------------------------------------------
# Symlink loops
# ---------------------------------------------------------------------------


def test_symlink_loop_default_mode_skipped(tmp_path):
    _symlink_capable(tmp_path)
    repo = tmp_path / "repo"
    _write_app(repo)
    inner = repo / "pkg"
    inner.mkdir()
    os.symlink(repo, inner / "loop")  # directory loop back to the root
    os.symlink(repo / "app.py", repo / "ghost.py")  # file symlink, not followed

    index, source, _config = _scan_repo(repo)

    assert "app.py" in source.scanned_files
    assert "ghost.py" not in source.scanned_files
    assert any("symlink not followed" in note for note in index.limitations)
    assert any("loop" in note for note in index.limitations)


def test_symlink_loop_follow_mode_terminates(tmp_path, monkeypatch):
    """With ATTACKMAP_FOLLOW_SYMLINKS=1 a loop that stays inside the root is
    followed but the walker's seen-set must keep it finite (pytest-timeout is
    the hang guard)."""
    _symlink_capable(tmp_path)
    monkeypatch.setenv("ATTACKMAP_FOLLOW_SYMLINKS", "1")
    repo = tmp_path / "repo"
    _write_app(repo)
    inner = repo / "pkg"
    inner.mkdir()
    os.symlink(repo, inner / "loop")
    os.symlink(repo / "app.py", repo / "ghost.py")

    _index, source, _config = _scan_repo(repo)

    # The looped copies resolve to the same real files; the scan completes
    # and every scanned path is still inside the repo.
    assert "app.py" in source.scanned_files
    assert all(not p.startswith("..") for p in source.scanned_files)


# ---------------------------------------------------------------------------
# Archives dropped in the tree
# ---------------------------------------------------------------------------


def test_zip_bomb_treated_as_opaque_file(tmp_path):
    """A highly compressible archive dropped in the scanned tree must be an
    opaque file: captured (or size-skipped), never exploded, never scanned
    as code."""
    repo = tmp_path / "repo"
    _write_app(repo)
    bomb = repo / "data.zip"
    chunk = b"A" * 50_000
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        for i in range(4_000):  # ~200 MB logical, < 1 MB physical
            archive.writestr(f"entry-{i}.txt", chunk)
    physical = bomb.stat().st_size
    assert physical < 1_000_000, "test setup: bomb must stay small on disk"

    tracemalloc.start()
    try:
        index, source, _config = _scan_repo(repo)
        peak_mb = _peak_tracemalloc_mb()
    finally:
        tracemalloc.stop()

    assert "data.zip" not in source.scanned_files
    assert "app.py" in source.scanned_files
    # The archive was either rejected as undecodable/binary or never read as
    # text; either way the scan did not materialise its logical size.
    assert index.captured_source_bytes < 2_000_000
    print(f"[memory] zip bomb: physical={physical} B, "
          f"tracemalloc peak={peak_mb:.1f} MB")


# ---------------------------------------------------------------------------
# Binary content masquerading as source
# ---------------------------------------------------------------------------


def test_binary_masquerade_invalid_utf8_skipped(tmp_path):
    repo = tmp_path / "repo"
    _write_app(repo)
    (repo / "evil.py").write_bytes(b"\xff\xfe\x00\x00import os\r\n\x80\x81bad")

    _index, source, _config = _scan_repo(repo)

    # Not UTF-8: the index drops it from the analyzable set without a crash.
    assert "evil.py" not in source.scanned_files
    assert "app.py" in source.scanned_files


def test_binary_masquerade_nul_bytes_scanned(tmp_path):
    """NUL bytes are valid UTF-8, so this file IS scanned; the per-file
    regex passes must tolerate control bytes (committed tiny fixture)."""
    repo = tmp_path / "repo"
    _write_app(repo)
    shutil.copyfile(FIXTURES / "binary_masquerade.py", repo / "binary_masquerade.py")

    _index, source, _config = _scan_repo(repo)

    assert "binary_masquerade.py" in source.scanned_files
    assert "app.py" in source.scanned_files


# ---------------------------------------------------------------------------
# Deeply nested YAML
# ---------------------------------------------------------------------------


def test_deeply_nested_yaml_k8s_manifest(tmp_path):
    repo = tmp_path / "repo"
    _write_app(repo)
    (repo / "deep.yaml").write_text(_deep_yaml(800), encoding="utf-8")

    aliases, notes = extract_deployment_aliases([repo])

    # A document too deep to compose is skipped with a note, never a crash.
    assert any("deep.yaml" in note for note in notes)
    assert "deep.yaml" not in aliases.source_files


def test_deeply_nested_yaml_github_workflow(tmp_path):
    repo = tmp_path / "repo"
    _write_app(repo)
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(_deep_yaml(800), encoding="utf-8")

    assert scan_workflows(repo) == []


def test_deeply_nested_yaml_pnpm_lockfile(tmp_path):
    repo = tmp_path / "repo"
    _write_app(repo)
    (repo / "pnpm-lock.yaml").write_text(_deep_yaml(800), encoding="utf-8")

    hints = parse_lockfiles(repo)

    # The hostile lockfile yields no dependency hints; the scan completes.
    assert all("pnpm-lock" not in str(getattr(h, "file", "")) for h in hints)


def test_deeply_nested_yaml_rails_config_bounded(tmp_path):
    """The Rails database.yml path already bounds events/depth; a document
    past the 8192-event bound is rejected with the standard note, not a
    crash (regression guard for the bounded parser)."""
    repo = tmp_path / "repo"
    _write_app(repo)
    config_dir = repo / "config"
    config_dir.mkdir()
    (config_dir / "database.yml").write_text(_deep_flow_yaml(3_000), encoding="utf-8")

    _index, _source, config = _scan_repo(repo)

    assert any("Rails datastore configuration was not qualified" in note
               for note in config.limitations)


# ---------------------------------------------------------------------------
# Unicode confusables / mixed-direction names (small committed fixture)
# ---------------------------------------------------------------------------


def test_unicode_confusable_and_mixed_direction_names(tmp_path):
    repo = tmp_path / "repo"
    _write_app(repo)
    shutil.copytree(FIXTURES / "unicode_names", repo / "unicode_names")

    index, source, _config = _scan_repo(repo)

    rels = {item.rel for item in index.files}
    # The fixture filename is the Cyrillic look-alike of "app.py" (confusable
    # characters on purpose).
    assert any("арр.py" in rel for rel in rels), rels  # noqa: RUF001
    assert any("app.py" in rel for rel in rels)
    assert source.files_scanned >= 2


# ---------------------------------------------------------------------------
# Opt-in stress cases
# ---------------------------------------------------------------------------


@STRESS
def test_1gb_single_line_file(tmp_path):
    repo = tmp_path / "repo"
    _write_app(repo)
    giant = repo / "giant.py"
    start = time.monotonic()
    with giant.open("wb") as handle:
        handle.write(b"x = '")
        for _ in range(1024):  # 1 GB, one logical line
            handle.write(b"y" * (1024 * 1024))
        handle.write(b"'\n")
    written = time.monotonic() - start

    tracemalloc.start()
    try:
        scan_start = time.monotonic()
        index, source, _config = _scan_repo(repo)
        scan_seconds = time.monotonic() - scan_start
        peak_mb = _peak_tracemalloc_mb()
    finally:
        tracemalloc.stop()

    assert "giant.py" not in source.scanned_files  # oversized: never read
    assert "app.py" in source.scanned_files
    assert any("giant.py" in note for note in index.limitations)
    print(f"[memory] 1GB single line: wrote in {written:.1f}s, "
          f"scanned in {scan_seconds:.1f}s, "
          f"tracemalloc peak={peak_mb:.1f} MB")


@STRESS
@pytest.mark.timeout(900)  # 100k filesystem entries far exceeds the suite's
# 300 s budget on Windows (per-open AV cost dominates the index walk); the
# point of the case is completion without a hang, not sub-300 s speed.
def test_100k_files_in_one_directory(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    repo = tmp_path / "repo"
    _write_app(repo)
    bucket = repo / "bucket"
    bucket.mkdir()

    def make(i: int) -> None:
        with open(bucket / f"mod_{i:06d}.py", "w", encoding="utf-8") as handle:
            handle.write(f"VALUE_{i} = {i}\n")

    create_start = time.monotonic()
    with ThreadPoolExecutor(16) as pool:
        list(pool.map(make, range(100_000)))
    create_seconds = time.monotonic() - create_start

    scan_start = time.monotonic()
    index, source, _config = _scan_repo(repo)
    scan_seconds = time.monotonic() - scan_start

    # The default index file-count cap (C35) engages exactly at 100_000
    # accepted files; the overflow is skipped with an aggregate limitation,
    # never a crash and never an unbounded walk.
    assert len(index.files) == 100_000
    assert any("file count limit exceeded" in note for note in index.limitations)
    assert source.files_scanned == 100_000
    print(f"[memory] 100k files: created in {create_seconds:.1f}s, "
          f"indexed+scanned in {scan_seconds:.1f}s")


# ---------------------------------------------------------------------------
# Bounded fuzz smoke over the regex-heavy extraction parsers
# ---------------------------------------------------------------------------

_FUZZ_TOKENS = [
    "a", "b", "Z", "0", "9", "_", "-", ".", "/", "\\", " ", "\n", "\t",
    "'", '"', "(", ")", "[", "]", "{", "}", "<", ">", "@", "#", "$", "=",
    ":", ";", ",", "?", "*", "+", "^", "`", "~", "%",
    "get", "post", "app", "router", "route", "api", "use", "all", "any",
    "include_router", "register_blueprint", "Blueprint", "APIRouter",
    "Flask", "FastAPI", "express", "kind", "Service", "metadata",
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "Bearer", "authorization", "jwt", "oauth", "session",
    "http://", "https://", "postgres://", "mysql://", "redis://",
    "user:pass@host", "upstream", "server", "proxy_pass", "listen",
    "AKIAIOSFODNN7EXAMPLE", "ghp_" + "a" * 36, "sk-" + "b" * 48,
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "-----BEGIN PRIVATE KEY-----",
    "x" * 64, "sha384-" + "c" * 64,
]


def _fuzz_document(rng: random.Random) -> str:
    return "".join(rng.choice(_FUZZ_TOKENS) for _ in range(rng.randint(1, 400)))


def test_fuzz_extraction_parsers_no_crash_or_hang():
    """Seeded, bounded fuzz over the regex-heavy per-file parsers: random
    malformed documents must never raise and must finish quickly enough for
    the whole loop to stay well inside the suite timeout (catastrophic
    backtracking would trip --timeout=300)."""
    rng = random.Random(20261123)
    iterations = 3_000
    for i in range(iterations):
        document = _fuzz_document(rng)
        relative = "fuzz.py" if i % 3 else "fuzz.js"
        try:
            extract_routes(document, relative, Path(relative).suffix)
            list(iter_secret_matches(document))
            stub = ScanResult(root="", scanned_files=[])
            config_scanner._extract_db_urls(document, "fuzz.yaml", stub)
            config_scanner._extract_http_targets(document, "fuzz.yaml", stub)
            config_scanner._extract_secret_kvs(document, "fuzz.yaml", stub)
            config_scanner._extract_netrc(document, ".netrc", stub)
            if i % 10 == 0:
                config_scanner._extract_rails_datastores(document, "config/database.yml", stub)
            if i % 7 == 0:
                notes: list[str] = []
                config_scanner._extract_nginx_proxies(
                    document, "fuzz.conf",
                    {}, {}, set(), {}, set(), notes)
        except Exception as exc:  # any escape is a failure
            pytest.fail(
                f"fuzz iteration {i} raised {exc!r} for document: {document[:200]!r}"
            )

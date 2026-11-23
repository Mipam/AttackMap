"""Performance regression benchmark driver (AR084 / AC-405).

Measures the engine on tiny synthetic fixture repositories generated under the
scratch directory — the AttackMap repo itself is NEVER the benchmark subject:

  - ``analyzer_wall_s``        median wall time of the per-file analyzer pass
                               (:func:`attackmap.extraction.scanner.scan_files`),
                               i.e. the extraction/analyzer stage alone.
  - ``full_scan_s``            median end-to-end wall time of a complete scan
                               via the public library API
                               (:func:`attackmap.surfaces.api.analyze`), the same
                               pipeline the CLI runs.
  - ``incremental_scan_s``     median wall time of ``scan_files`` with a warm
                               incremental cache after a ~5% source edit, plus
                               the ``incremental_vs_full_ratio``.
  - ``peak_memory_bytes``      peak in-process Python allocation during one full
                               scan, via :mod:`tracemalloc`. This traces the
                               engine's own allocations only; isolated external
                               analyzer subprocesses are not traced.

Wall time uses :func:`time.perf_counter`. Each measured incremental run is
equivalence-checked against the matching full run of the same repetition
(result models compared field-for-field), never assumed.

Intended operation (AC-405):

  * Nightly run on fixed hardware::

        .venv/Scripts/python.exe tools/bench_analyzers.py --json --save perf-baseline.json

    Each ``--save`` appends ``{commit, timestamp_utc, metrics}`` to the trend
    store. When the store already holds a record, the new record is compared
    against the previous one and any metric that regressed by more than 20%
    (``REGRESSION_THRESHOLD``) is reported as a WARNING — the default mode is
    record-and-warn (report-only for one release, per the card's rollback
    note). ``--fail-on-regression`` turns the same comparison into a non-zero
    exit for gated runs. The > 20% rule mirrors AC-405's
    ``--benchmark-compare-fail=mean:20%`` semantics: only metrics present in
    both records are compared, and an exactly-20% change is not a regression.

  * Trend storage: the ``--save`` file is plain JSON
    (``{"schema": ..., "records": [...]}``); append-only, diffable, and safe to
    publish alongside a generated trend page.

  * CI / pytest: ``tests/perf`` holds the hermetic smoke tests (small fixture,
    bounded run time) and the explicit comparison-gate test that fails on a
    synthetic > 20% regression without any timing flakiness.

Fixtures stay small (a few dozen files) so a run finishes in seconds. Use
``--files``/``--reps`` to scale up for a nightly campaign.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from attackmap.extraction.scanner import scan_files  # noqa: E402

SCHEMA = "attackmap-perf-bench/1.0"
DEFAULT_FIXTURES_DIR = Path("C:/tmp/attackmap-scratch/ar084/fixtures")
REGRESSION_THRESHOLD = 0.20
EDIT_PERCENT = 5.0

# Metrics the > 20% gate applies to; all must be present in both records for a
# comparison to fire. Values are seconds or bytes — lower is always better.
GATED_METRICS = (
    "analyzer_wall_s",
    "full_scan_s",
    "incremental_scan_s",
    "peak_memory_bytes",
)


def _py_module(i: int) -> str:
    return (
        "from flask import Blueprint\n"
        "import os\n"
        "import hashlib\n"
        "import requests\n"
        f"bp = Blueprint('mod{i}', __name__, url_prefix='/m{i}')\n"
        f"@bp.route('/resource/{i}', methods=['GET', 'POST'])\n"
        "def resource():\n"
        f"    requests.get('https://internal-{i}.svc.internal/api/{i}')\n"
        "    engine = create_engine('postgresql://u:p@db-host/prod')\n"
        f"    token = os.getenv('SERVICE_TOKEN_{i}')\n"
        f"    digest = hashlib.md5(b'password-{i}')\n"
        "    jwt.decode(token, key)\n"
        "    User.objects.create(**request.json)\n"
        "    session = redis.from_url('redis://cache:6379/0')\n"
        "    return []\n"
        f"@bp.route('/items/{i}/<item_id>', methods=['PUT'])\n"
        "def item(item_id):\n"
        "    cursor.execute('SELECT * FROM items WHERE id = %s' % item_id)\n"
        "    return item_id\n"
    )


def _js_module(i: int) -> str:
    return (
        "const express = require('express');\n"
        "const cors = require('cors');\n"
        "const axios = require('axios');\n"
        "const router = express.Router();\n"
        "router.use(cors({ origin: true, credentials: true }));\n"
        f"router.get('/items/{i}', (req, res) => {{\n"
        f"  axios.post('https://partner-{i}.example.com/sync', {{}});\n"
        "  User.create(req.body);\n"
        "  const db = new PrismaClient();\n"
        f"  const key = process.env.STRIPE_SECRET_KEY_{i};\n"
        "  const crypto = require('crypto');\n"
        "  crypto.createHash('md5').update(password).digest('hex');\n"
        "  res.send([]);\n"
        "});\n"
        f"router.post('/hooks/{i}', (req, res) => {{\n"
        "  Object.assign(config, req.body);\n"
        "  res.end();\n"
        "});\n"
    )


def build_fixture(root: Path, count: int) -> Path:
    """Create a synthetic fixture repo of ``count`` source files; return its path."""
    repo = root / "repo"
    src = repo / "src"
    src.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        if i % 2:
            (src / f"mod{i}.py").write_text(_py_module(i), encoding="utf-8")
        else:
            (src / f"svc{i}.js").write_text(_js_module(i), encoding="utf-8")
    return repo


def apply_edits(root: Path, count: int, percent: float, generation: int) -> int:
    """Rewrite ~percent% of the fixture files with changed content; return count."""
    files = sorted(p for p in root.rglob("*") if p.is_file())
    n = max(1, round(len(files) * percent / 100.0))
    step = max(1, len(files) // n)
    edited = 0
    for offset in range(0, len(files), step):
        if edited >= n:
            break
        path = files[offset]
        index = int("".join(ch for ch in path.stem if ch.isdigit()) or 0)
        body = (
            _py_module(index + generation * 100000)
            if path.suffix == ".py"
            else _js_module(index + generation * 100000)
        )
        path.write_text(body, encoding="utf-8")
        edited += 1
    return edited


def _full_scan(repo: Path, output: Path) -> float:
    """One end-to-end scan via the public library API; returns wall seconds."""
    from attackmap.orchestration.run_spec import RunSpec
    from attackmap.surfaces.api import analyze

    start = time.perf_counter()
    analyze(RunSpec(repos=(repo,), output=output))
    return time.perf_counter() - start


def measure(
    fixtures_dir: Path,
    files: int = 40,
    reps: int = 3,
    edit_percent: float = EDIT_PERCENT,
) -> dict[str, object]:
    """Run the benchmark; return the metrics dict (plus equivalence counters).

    The fixture is built once under ``fixtures_dir``; each repetition applies a
    fresh ~``edit_percent``% edit and measures analyzer/full/incremental wall
    time. Peak memory is measured once via tracemalloc on a dedicated full scan.
    """
    fixtures_dir = Path(fixtures_dir)
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    repo = build_fixture(fixtures_dir, files)
    cache_dir = fixtures_dir / "cache"
    output_root = fixtures_dir / "output"

    analyzer_times: list[float] = []
    full_times: list[float] = []
    incremental_times: list[float] = []
    equivalences_checked = 0

    # Warm the cache so every measured incremental rep is the steady-state
    # "small edit, mostly cached" scenario.
    scan_files(repo, incremental=True, cache_dir=cache_dir)

    for rep in range(reps):
        apply_edits(repo, files, edit_percent, rep)

        start = time.perf_counter()
        scan_result = scan_files(repo)
        analyzer_s = time.perf_counter() - start

        full_s = _full_scan(repo, output_root / f"rep-{rep}")

        start = time.perf_counter()
        incremental = scan_files(repo, incremental=True, cache_dir=cache_dir)
        inc_s = time.perf_counter() - start

        # The measured runs are equivalence-checked, never assumed.
        assert full_scan_equivalent(scan_result, incremental), (
            f"rep {rep}: full and incremental results diverged"
        )
        equivalences_checked += 1
        analyzer_times.append(analyzer_s)
        full_times.append(full_s)
        incremental_times.append(inc_s)

    analyzer_median = statistics.median(analyzer_times)
    full_median = statistics.median(full_times)
    inc_median = statistics.median(incremental_times)

    # Peak in-process allocation during one dedicated full scan. tracemalloc
    # traces this process only; isolated external analyzer subprocesses are
    # out of scope by design (see module docstring).
    tracemalloc.start()
    _full_scan(repo, output_root / "memory")
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "files": files,
        "reps": reps,
        "analyzer_wall_s": round(analyzer_median, 6),
        "full_scan_s": round(full_median, 6),
        "incremental_scan_s": round(inc_median, 6),
        "incremental_vs_full_ratio": round(inc_median / full_median, 4),
        "peak_memory_bytes": int(peak_bytes),
        "equivalences_checked": equivalences_checked,
    }


def full_scan_equivalent(full: object, incremental: object) -> bool:
    """Field-for-field equality of two ScanResult models."""
    return full.model_dump() == incremental.model_dump()


def current_commit() -> str:
    """Commit sha of the tree the benchmark ran on, or ``unknown``."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    sha = out.stdout.strip()
    return sha if out.returncode == 0 and sha else "unknown"


def compare_metrics(
    baseline: dict[str, object],
    current: dict[str, object],
    threshold: float = REGRESSION_THRESHOLD,
) -> list[str]:
    """Metrics in ``current`` that regressed vs ``baseline`` by more than ``threshold``.

    Only :data:`GATED_METRICS` present in BOTH records are compared; an exact
    ``threshold`` change is not a regression (mirrors AC-405's mean:20% rule).
    Returns human-readable violation strings, empty when nothing regressed.
    """
    regressions: list[str] = []
    for key in GATED_METRICS:
        base = baseline.get(key)
        cur = current.get(key)
        if not isinstance(base, (int, float)) or not isinstance(cur, (int, float)):
            continue
        if base <= 0:
            continue
        if cur > base * (1.0 + threshold):
            regressions.append(f"{key}: {cur} regressed > {threshold:.0%} vs baseline {base}")
    return regressions


def load_baseline(path: Path) -> list[dict[str, object]]:
    """Records from a baseline store; empty list when absent or malformed."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    records = data.get("records") if isinstance(data, dict) else None
    return records if isinstance(records, list) else []


def save_baseline(path: Path, record: dict[str, object]) -> None:
    """Append ``record`` to the trend store, creating it when missing."""
    path = Path(path)
    records = load_baseline(path)
    records.append(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"schema": SCHEMA, "records": records}, indent=2) + "\n",
        encoding="utf-8",
    )


def build_record(metrics: dict[str, object]) -> dict[str, object]:
    """The versioned JSON record: commit, timestamp, host, metrics."""
    return {
        "schema": SCHEMA,
        "commit": current_commit(),
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "host": {
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "python": platform.python_version(),
            "cpu_count": __import__("os").cpu_count(),
        },
        "metrics": metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--files", type=int, default=40)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--edit-percent", type=float, default=EDIT_PERCENT)
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=DEFAULT_FIXTURES_DIR,
        help="scratch dir for the synthetic fixture repo (created if missing)",
    )
    parser.add_argument("--json", action="store_true", help="print the record as JSON")
    parser.add_argument(
        "--save",
        type=Path,
        default=None,
        help="append the record to this baseline/trend store, then compare "
        "against the previous record and warn on any > 20% regression",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="exit 1 when the comparison against the previous saved record "
        "finds a > 20% regression (gated/nightly mode; default is warn-only)",
    )
    args = parser.parse_args()

    started = time.perf_counter()
    metrics = measure(
        args.fixtures_dir,
        files=args.files,
        reps=args.reps,
        edit_percent=args.edit_percent,
    )
    run_wall_s = round(time.perf_counter() - started, 3)
    record = build_record(metrics)
    record["run_wall_s"] = run_wall_s

    regressions: list[str] = []
    if args.save is not None:
        prior = load_baseline(args.save)
        save_baseline(args.save, record)
        if prior:
            regressions = compare_metrics(prior[-1].get("metrics", {}), metrics)

    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print(f"analyzer wall (median)     : {metrics['analyzer_wall_s'] * 1000:8.1f} ms")
        print(f"full scan (median)         : {metrics['full_scan_s'] * 1000:8.1f} ms")
        print(
            f"incremental (median, {args.edit_percent:g}% ed): "
            f"{metrics['incremental_scan_s'] * 1000:8.1f} ms  "
            f"(ratio {metrics['incremental_vs_full_ratio']:.3f})"
        )
        print(f"peak memory (tracemalloc)  : {metrics['peak_memory_bytes'] / 1e6:8.1f} MB")
        print(f"equivalence checks passed  : {metrics['equivalences_checked']}/{args.reps} reps")
        print(f"commit {record['commit']}  whole-run wall {run_wall_s:.3f} s")

    for line in regressions:
        print(f"WARNING: perf regression vs previous saved record: {line}", file=sys.stderr)
    if regressions and args.fail_on_regression:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

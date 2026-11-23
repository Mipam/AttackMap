"""Incremental-analysis wall-time benchmark (C34/AM048, first slice).

Generates a synthetic repository, then measures, on this one host:
  - full scan:      scan_files with every file freshly analyzed
  - incremental:    scan_files(incremental=True) after a ~1% source edit,
                    warm cache carried across repetitions
  - cold:           first incremental run against an empty cache directory

Each repetition applies a fresh ~1% edit, runs the full scan, then the
incremental scan on the identical tree, and verifies the two results are
equal — the measured runs are also equivalence-checked, never assumed.

Roadmap C34 wants a 20-repetition campaign on fixed hardware against the
published reference corpus; this tool defaults to 10 repetitions on
whatever host it runs on and states that in its JSON record.

Usage:
    python tools/bench_incremental.py [--files 400] [--reps 10]
                                      [--edit-percent 1.0]
                                      [--changed 50]
                                      [--repeat 5] [--json]
                                      [--scratch DIR]
                                      [--out reports/incremental-bench.json]

AC-401 scenario (10k files, 50 changed, 5 repetitions, JSON on stdout):
    python tools/bench_incremental.py --files 10000 --changed 50 --repeat 5 --json
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import platform
import statistics
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from attackmap.extraction.scanner import scan_files  # noqa: E402

EDIT_PERCENT = 1.0


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
        "}});\n"
        f"router.post('/hooks/{i}', (req, res) => {{\n"
        "  Object.assign(config, req.body);\n"
        "  res.end();\n"
        "}});\n"
    )


def _build_repo(root: Path, count: int) -> None:
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        if i % 2:
            (src / f"mod{i}.py").write_text(_py_module(i), encoding="utf-8")
        else:
            (src / f"svc{i}.js").write_text(_js_module(i), encoding="utf-8")


def _apply_edits(root: Path, count: int | None, percent: float, generation: int) -> int:
    """Rewrite ~percent% (or exactly ``count`` when given) of the files with
    changed content; return how many."""
    files = sorted(p for p in root.rglob("*") if p.is_file())
    n = max(1, min(count, len(files))) if count is not None \
        else max(1, round(len(files) * percent / 100.0))
    step = max(1, len(files) // n)
    edited = 0
    for offset in range(0, len(files), step):
        if edited >= n:
            break
        path = files[offset]
        index = int("".join(ch for ch in path.stem if ch.isdigit()) or 0)
        body = _py_module(index + generation * 100000) if path.suffix == ".py" \
            else _js_module(index + generation * 100000)
        path.write_text(body, encoding="utf-8")
        edited += 1
    return edited


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=400)
    parser.add_argument("--reps", "--repeat", dest="reps", type=int, default=10,
                        help="repetitions per mode (roadmap C34 wants 20 on fixed hardware)")
    parser.add_argument("--edit-percent", type=float, default=EDIT_PERCENT,
                        help="share of files rewritten per rep (ignored when --changed is given)")
    parser.add_argument("--changed", type=int, default=None,
                        help="exact number of files rewritten per rep (AC-401 scenario: 50)")
    parser.add_argument("--json", action="store_true",
                        help="also print the JSON record to stdout")
    parser.add_argument("--scratch", type=Path, default=None,
                        help="keep the generated corpus and caches under this directory "
                             "instead of a fresh temp dir (the AC-401 corpus is generated, "
                             "never committed to the repo)")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "reports" / "incremental-bench.json")
    args = parser.parse_args()

    if args.scratch is not None:
        args.scratch.mkdir(parents=True, exist_ok=True)
        tmp_ctx: object = contextlib.nullcontext(args.scratch)
    else:
        tmp_ctx = tempfile.TemporaryDirectory(prefix="attackmap-bench-")
    with tmp_ctx as tmp:
        tmp_path = Path(tmp)
        repo = tmp_path / "repo"
        cache_dir = tmp_path / "cache"
        _build_repo(repo, args.files)

        full_times: list[float] = []
        inc_times: list[float] = []
        equivalences_checked = 0

        # Warm the cache once so every measured incremental rep is the
        # steady-state "small edit, mostly cached" scenario.
        scan_files(repo, incremental=True, cache_dir=cache_dir)

        for rep in range(args.reps):
            edited = _apply_edits(repo, args.changed, args.edit_percent, rep)

            start = time.perf_counter()
            full = scan_files(repo)
            full_s = time.perf_counter() - start

            start = time.perf_counter()
            incremental = scan_files(repo, incremental=True, cache_dir=cache_dir)
            inc_s = time.perf_counter() - start

            # The measured runs are equivalence-checked, never assumed.
            assert full.model_dump() == incremental.model_dump(), f"rep {rep}: results diverged"
            equivalences_checked += 1
            full_times.append(full_s)
            inc_times.append(inc_s)
            print(f"rep {rep + 1:2d}/{args.reps}: edited={edited} "
                  f"full={full_s * 1000:8.1f}ms incremental={inc_s * 1000:8.1f}ms "
                  f"ratio={inc_s / full_s:.3f}")

        # Cold analysis: first incremental run against a fresh cache dir,
        # repeated on a stable tree (all misses; pays key computation and
        # cache write). Compare against the full median for the ≤1.10 gate.
        cold_times: list[float] = []
        for rep in range(max(3, args.reps // 2)):
            cold_dir = Path(tmp) / f"cold-{rep}"
            start = time.perf_counter()
            scan_files(repo, incremental=True, cache_dir=cold_dir)
            cold_s = time.perf_counter() - start
            cold_times.append(cold_s)

    full_median = statistics.median(full_times)
    inc_median = statistics.median(inc_times)
    cold_median = statistics.median(cold_times)
    ratio = inc_median / full_median
    cold_ratio = cold_median / full_median
    inc_p95 = sorted(inc_times)[min(len(inc_times) - 1, math.ceil(0.95 * len(inc_times)) - 1)]

    cas_state = os.environ.get("ATTACKMAP_CAS", "1") != "0"
    record = {
        "schema": "attackmap-incremental-bench/1.0",
        "generated_utc": datetime.now(UTC).isoformat(),
        "mode": "synthetic-repo, per-file pass only (scan_files; no repo passes, no merge)",
        "host": {
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "python": platform.python_version(),
            "cpu_count": __import__("os").cpu_count(),
        },
        "parameters": {
            "files": args.files,
            "reps": args.reps,
            "changed": args.changed,
            "edit_percent": args.edit_percent if args.changed is None else None,
            "cas_enabled": cas_state,
            "reps_note": (
                f"{args.reps} repetitions on this single non-fixed host; "
                "roadmap C34 requires a 20-repetition campaign on fixed hardware "
                "against the published reference corpus — not run here."
            ),
        },
        "results": {
            "full_median_s": round(full_median, 4),
            "incremental_median_s": round(inc_median, 4),
            "cold_incremental_median_s": round(cold_median, 4),
            "incremental_vs_full_ratio": round(ratio, 3),
            "cold_vs_full_ratio": round(cold_ratio, 3),
            "targets": {"incremental_vs_full_max": 0.5, "cold_vs_full_max": 1.1},
            "incremental_target_met": ratio <= 0.5,
            "cold_target_met": cold_ratio <= 1.1,
            "equivalences_checked": equivalences_checked,
        },
    }
    if args.changed is not None:
        # AC-401: 10k-file repo, 50 modified files, warm store, p95 of 5 reps.
        record["ac401"] = {
            "scenario": f"{args.files} files, {args.changed} changed per rep, "
                        f"warm cache + CAS ({'on' if cas_state else 'OFF'})",
            "target_warm_p95_s": 10.0,
            "warm_p95_s": round(inc_p95, 4),
            "target_met": inc_p95 < 10.0,
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2), encoding="utf-8")

    print()
    print(f"full scan median          : {full_median * 1000:8.1f} ms")
    print(f"incremental median        : {inc_median * 1000:8.1f} ms  "
          f"(ratio {ratio:.3f}, target <= 0.500 : {'MET' if ratio <= 0.5 else 'NOT MET'})")
    if args.changed is not None:
        print(f"incremental p95 ({args.changed} chg): {inc_p95 * 1000:8.1f} ms  "
              f"(AC-401 target < 10.0 s : {'MET' if inc_p95 < 10.0 else 'NOT MET'})")
    print(f"cold incremental median   : {cold_median * 1000:8.1f} ms  "
          f"(ratio {cold_ratio:.3f}, target <= 1.100 : {'MET' if cold_ratio <= 1.1 else 'NOT MET'})")
    print(f"equivalence checks passed : {equivalences_checked}/{args.reps} reps")
    print(f"record written to         : {args.out}")
    if args.json:
        print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

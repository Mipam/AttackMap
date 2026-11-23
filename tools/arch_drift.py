"""Architecture drift report (AR088, AC-409): structural metric trends over history.

Reports, for HEAD and for commits sampled between ``--since`` and HEAD:

- ``import_cycles``        number of import cycles in the internal package graph
- ``fan_in_max``           highest per-module fan-in (distinct internal importers)
- ``longest_function_lines`` longest function span in source lines
- ``broad_excepts``        ``except Exception`` / ``except BaseException`` handlers

Method (documented in docs/architecture-drift.md): each sampled commit is
extracted read-only with ``git archive`` into a scratch directory and measured
with the *same* AST machinery as ``tools/arch_report`` (imported here, not
re-implemented), so drift numbers are definitionally comparable with the
AR009 ratchet gate. Nothing is checked out; the working tree and history are
untouched.

Usage:

    python -m tools.arch_drift --since 5ee4d20
    python -m tools.arch_drift --since 5ee4d20 --json
    python -m tools.arch_drift --since HEAD~5 --max-samples 4 --json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from tools.arch_report import collect as arch_collect

REPO_ROOT = Path(__file__).resolve().parents[1]

METRIC_KEYS = ("import_cycles", "fan_in_max", "longest_function_lines", "broad_excepts")


class DriftError(RuntimeError):
    """Fatal input problem (bad revision, no git repo, missing tar)."""


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise DriftError(
            f"git {' '.join(args)} failed (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return result.stdout


def resolve_commits(repo: Path, since: str, max_samples: int) -> list[tuple[str, str]]:
    """Return [(sha, subject)] oldest-first: ``since`` itself plus sampled descendants."""
    try:
        run_git(repo, "rev-parse", "--verify", "--quiet", f"{since}^{{commit}}")
    except DriftError as exc:
        raise DriftError(f"--since {since!r} is not a commit in {repo}") from exc
    probe = subprocess.run(
        ["git", "merge-base", "--is-ancestor", since, "HEAD"],
        cwd=repo, capture_output=True,
    )
    if probe.returncode != 0:
        raise DriftError(f"--since {since!r} is not an ancestor of HEAD in {repo}")

    out = run_git(repo, "log", "--first-parent", "--format=%H%x00%s", f"{since}..HEAD")
    descendants = [
        tuple(line.split("\x00", 1)) for line in out.splitlines() if line
    ]
    descendants.reverse()  # git log is newest-first; drift reads oldest-first
    subject = run_git(repo, "log", "-1", "--format=%s", since).strip()
    commits = [(run_git(repo, "rev-parse", since).strip(), subject), *descendants]

    if len(commits) > max_samples > 1:
        step = (len(commits) - 1) / (max_samples - 1)
        keep = sorted({round(i * step) for i in range(max_samples)})
        commits = [commits[i] for i in keep]
    return commits


def _rmtree(path: Path) -> None:
    def onerror(func, p, _exc_info):  # pragma: no cover - windows read-only files
        Path(p).chmod(0o666)
        func(p)

    shutil.rmtree(path, onerror=onerror)


def measure_commit(repo: Path, commit: str, root_prefix: str, package: str) -> dict:
    """Extract ``root_prefix`` from ``commit`` into a scratch dir and measure it.

    Returns a dict with the four METRIC_KEYS, or ``None`` values plus a
    ``note`` when the package tree does not exist at that commit.
    """
    dest = Path(tempfile.mkdtemp(prefix=f"arch-drift-{commit[:8]}-"))
    try:
        archive = subprocess.run(
            ["git", "archive", commit, root_prefix],
            cwd=repo, capture_output=True,
        )
        if archive.returncode != 0 or not archive.stdout:
            return {**{key: None for key in METRIC_KEYS},
                    "note": f"{root_prefix}/ not present at this commit"}
        extracted = subprocess.run(
            ["tar", "-x", "-C", str(dest)], input=archive.stdout, capture_output=True,
        )
        if extracted.returncode != 0:
            raise DriftError(f"tar extraction failed for {commit}: "
                             f"{extracted.stderr.decode(errors='replace').strip()}")
        tree = dest / root_prefix
        if not tree.is_dir():
            return {**{key: None for key in METRIC_KEYS},
                    "note": f"{root_prefix}/ not present at this commit"}
        data = arch_collect(
            tree, package,
            cycles=True, fan_in=True, fan_out=False,
            broad_excepts=True, functions=True,
        )
        return {
            "import_cycles": len(data["cycles"]),
            "fan_in_max": max(data["fan_in"].values(), default=0),
            "longest_function_lines": data["longest_function"]["lines"],
            "broad_excepts": sum(data["broad_excepts"].values()),
        }
    finally:
        _rmtree(dest)


def build_report(repo: Path, since: str, root_prefix: str, package: str,
                 max_samples: int) -> dict:
    commits = resolve_commits(repo, since, max_samples)
    samples = []
    for sha, subject in commits:
        samples.append({
            "commit": sha,
            "short": sha[:8],
            "subject": subject,
            **measure_commit(repo, sha, root_prefix, package),
        })

    trend = {}
    measured = [s for s in samples if s["import_cycles"] is not None]
    if len(measured) >= 2:
        for key in METRIC_KEYS:
            trend[key] = {
                "first": measured[0][key],
                "last": measured[-1][key],
                "delta": measured[-1][key] - measured[0][key],
            }
    return {
        "schema": 1,
        "repo": str(repo),
        "since": since,
        "head": samples[-1]["commit"] if samples else None,
        "root": root_prefix,
        "package": package,
        "metric_keys": list(METRIC_KEYS),
        "samples": samples,
        "trend": trend,
    }


def print_human(report: dict) -> None:
    print(f"architecture drift since {report['since']} "
          f"(package {report['package']}, repo {report['repo']})")
    header = f"{'commit':<9} {'cycles':>6} {'fan-in':>7} {'longest':>8} {'broad':>6}  subject"
    print(header)
    print("-" * len(header))
    for s in report["samples"]:
        if s["import_cycles"] is None:
            print(f"{s['short']:<9} {'n/a':>6} {'n/a':>7} {'n/a':>8} {'n/a':>6}  {s.get('note', '')}")
            continue
        print(f"{s['short']:<9} {s['import_cycles']:>6} {s['fan_in_max']:>7} "
              f"{s['longest_function_lines']:>8} {s['broad_excepts']:>6}  {s['subject']}")
    if report["trend"]:
        print("\ntrend (oldest measured -> newest):")
        labels = {
            "import_cycles": "import cycles",
            "fan_in_max": "max module fan-in",
            "longest_function_lines": "longest function lines",
            "broad_excepts": "broad except handlers",
        }
        for key, t in report["trend"].items():
            print(f"  {labels[key]}: {t['first']} -> {t['last']} (delta {t['delta']:+d})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--since", required=True,
                        help="ancestor commit/rev to trend from (inclusive)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit the full report as JSON")
    parser.add_argument("--max-samples", type=int, default=8,
                        help="cap on measured commits (evenly sampled; default 8)")
    parser.add_argument("--repo", default=str(REPO_ROOT),
                        help="git repository to measure (default: this repo)")
    parser.add_argument("--root", default="src/attackmap",
                        help="package tree inside the repo (default: src/attackmap)")
    parser.add_argument("--package", default="attackmap",
                        help="dotted package name (default: attackmap)")
    args = parser.parse_args(argv)

    if shutil.which("tar") is None:
        print("arch_drift: 'tar' is required to extract sampled commits", file=sys.stderr)
        return 2
    if args.max_samples < 2:
        print("arch_drift: --max-samples must be >= 2", file=sys.stderr)
        return 2

    try:
        report = build_report(Path(args.repo), args.since, args.root,
                              args.package, args.max_samples)
    except DriftError as exc:
        print(f"arch_drift: {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())

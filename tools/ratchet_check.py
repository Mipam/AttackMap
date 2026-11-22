"""Ratchet gate: current metrics may not regress past the AR009 baseline.

Compares freshly measured metrics (ruff, mypy, architecture) against
``baseline.json`` and fails on any regression. Improvements are reported but
never fail. Coverage is checked separately in CI via ``--cov-fail-under``.

Usage (see docs/architecture-roadmap-2026-11-21/criteria.md):

    python -m tools.ratchet_check --baseline docs/architecture-roadmap-2026-11-21/baseline.json
    python -m tools.ratchet_check --baseline ... --only cycles,broad_excepts   # quick subset
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    return result.stdout + result.stderr


def measure_ruff() -> int:
    lines = _run([sys.executable, "-m", "ruff", "check", ".", "--output-format", "concise"])
    return sum(1 for line in lines.splitlines() if ": " in line and not line.startswith("warning"))


def measure_mypy() -> tuple[int, int]:
    text = _run([sys.executable, "-m", "mypy", "src/attackmap"])
    errors = files = 0
    for line in text.splitlines():
        if line.startswith("src/attackmap") and ": error:" in line:
            errors += 1
    for line in text.splitlines():
        if "Found" in line and "error" in line:
            parts = line.split()
            with suppress(ValueError, IndexError):
                errors = int(parts[parts.index("Found") + 1])
            if "in" in parts and "files" in line:
                with suppress(ValueError, IndexError):
                    files = int(parts[parts.index("in") + 1])
    return errors, files


def measure_arch() -> dict:
    text = _run([sys.executable, "-m", "tools.arch_report", "--cycles", "--fan-in",
                 "--functions", "--broad-excepts", "--json"])
    data = json.loads(text)
    return {
        "import_cycles": len(data["cycles"]),
        "broad_excepts": sum(data["broad_excepts"].values()),
        "longest_function_lines": data["longest_function"]["lines"],
        "functions_over_80_lines": data["longest_function"]["over_80_lines"],
        "models_fan_in": data["fan_in"].get("attackmap.models", 0),
        "modules": data["modules"],
    }


METRIC_DIRECTIONS = {
    # metric: (higher_is_better, human label)
    "ruff_total": (False, "ruff violations"),
    "mypy_errors": (False, "mypy errors"),
    "mypy_files_with_errors": (False, "mypy files with errors"),
    "import_cycles": (False, "import cycles"),
    "broad_excepts": (False, "broad except handlers"),
    "longest_function_lines": (False, "longest function lines"),
    "functions_over_80_lines": (False, "functions over 80 lines"),
    "models_fan_in": (False, "models fan-in"),
    "modules": (True, "module count"),
    "coverage_floor_pct": (True, "coverage %"),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="path to baseline.json")
    parser.add_argument("--only", default="", help="comma-separated metric subset")
    args = parser.parse_args(argv)

    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    recorded: dict = baseline["metrics"]
    subset = {name.strip() for name in args.only.split(",") if name.strip()} or set(recorded)

    current = dict(measure_arch())
    if "ruff_total" in subset:
        current["ruff_total"] = measure_ruff()
    if {"mypy_errors", "mypy_files_with_errors"} & subset:
        errors, files = measure_mypy()
        current["mypy_errors"] = errors
        current["mypy_files_with_errors"] = files

    regressions: list[str] = []
    improvements: list[str] = []
    for metric, (higher_better, label) in METRIC_DIRECTIONS.items():
        if metric not in subset or metric not in recorded or recorded[metric] is None:
            continue
        now = current.get(metric)
        if now is None:
            continue
        base = recorded[metric]
        if higher_better:
            if now < base:
                regressions.append(f"{label}: {base} -> {now} (regression)")
            elif now > base:
                improvements.append(f"{label}: {base} -> {now} (improved)")
        else:
            if now > base:
                regressions.append(f"{label}: {base} -> {now} (regression)")
            elif now < base:
                improvements.append(f"{label}: {base} -> {now} (improved)")

    for line in improvements:
        print("improved:", line)
    for line in regressions:
        print("REGRESSION:", line)
    if regressions:
        print(f"\nratchet: FAIL ({len(regressions)} regression(s))")
        return 1
    print("\nratchet: PASS (no regressions past the recorded baseline)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

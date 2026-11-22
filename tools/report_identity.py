"""Stable semantic identity for AttackMap report output (AR032 / AC-111).

Computes a sha256 over the *normalised* report of a fixture generation —
sorted keys, volatile fields (timestamps, run ids, generation dirs, temp
paths) removed — so refactors that preserve report semantics keep the hash
while any semantic change breaks the Phase-1 identity gate loudly.

Corpora:
  * default — the deterministic artifact fixture generation built by
    ``tests/artifact_fixture.write_generation`` (hermetic, fast, and what the
    committed baseline in ``tests/contract/data/report_identity_baseline.json``
    is recorded from);
  * ``--corpus REPO`` — a real ``attackmap.pipeline.run_scan`` over a local
    repository, for deeper machine-local gating (never recorded as the
    committed baseline).

Usage::

    python -m tools.report_identity             # print the current identity
    python -m tools.report_identity --record    # write the baseline file
    python -m tools.report_identity --check     # diff against the baseline
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

from attackmap.foundation.safe_fs import MANIFEST_FILENAME

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = REPO_ROOT / "tests" / "contract" / "data" / "report_identity_baseline.json"
CORPUS_LABEL = "artifact-fixture"

# Report keys whose value is a run artifact, never a semantic signal.
VOLATILE_KEYS = frozenset(
    {
        "created_at",
        "updated_at",
        "generated_at",
        "scanned_at",
        "started_at",
        "finished_at",
        "completed_at",
        "ended_at",
        "timestamp",
        "duration",
        "duration_ms",
        "elapsed_ms",
        "milliseconds",
        "run_id",
        "run_ids",
        "generation",
        "generation_id",
        "generation_dir",
        "generation_path",
        # Byte-level integrity fields of exported files; file bytes embed run
        # timings (see the *_duration_ms rule below), so these drift run to run
        # without any semantic change.
        "checksum",
        "size_bytes",
    }
)


def _is_volatile_key(key: str) -> bool:
    return key in VOLATILE_KEYS or key.endswith("_ms")

# Any remaining absolute filesystem path (drive-letter or /tmp) is machine
# local, so it normalises away after the known roots are replaced.
_ABS_PATH = re.compile(r"[A-Za-z]:[\\/]\S*|/tmp/\S*")


def path_replacements(tmp_root: Path, corpus_root: Path | None) -> list[tuple[str, str]]:
    """Literal replacements mapping machine-local roots onto stable labels."""
    tmp = str(Path(tmp_root).resolve())
    pairs = [(tmp, "<tmp>"), (tmp.replace("\\", "/"), "<tmp>")]
    if corpus_root is not None:
        corpus = str(Path(corpus_root).resolve())
        pairs += [(corpus, "<corpus>"), (corpus.replace("\\", "/"), "<corpus>")]
    # Longest first so a corpus nested under the tmp root is labelled precisely.
    pairs.sort(key=lambda pair: len(pair[0]), reverse=True)
    return pairs


def _scrub_text(value: str, replacements: list[tuple[str, str]]) -> str:
    for old, new in replacements:
        if old and old in value:
            value = value.replace(old, new)
    return _ABS_PATH.sub("<abs-path>", value)


def normalize_node(node: object, replacements: list[tuple[str, str]]) -> object:
    """Recursively drop volatile keys, sort dict keys and scrub path strings."""
    if isinstance(node, dict):
        return {
            key: normalize_node(value, replacements)
            for key, value in sorted(node.items())
            if not _is_volatile_key(key)
        }
    if isinstance(node, list):
        return [normalize_node(item, replacements) for item in node]
    if isinstance(node, str):
        return _scrub_text(node, replacements)
    return node


def canonical_identity(report: object, manifest: object) -> str:
    payload = json.dumps([report, manifest], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_fixture_generation(work: Path) -> Path:
    """Deterministic artifact generation from the shared fixture writer."""
    tests_root = REPO_ROOT / "tests"
    if str(tests_root) not in sys.path:
        sys.path.insert(0, str(tests_root))
    from artifact_fixture import write_generation

    generation = work / "generation"  # fixed name so the run id is stable
    write_generation(generation)
    return generation


def identity_doc(generation: Path, *, tmp_root: Path, corpus_root: Path | None) -> dict:
    report = json.loads((generation / "attackmap-report.json").read_text(encoding="utf-8"))
    manifest_path = generation / MANIFEST_FILENAME
    manifest = None
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    replacements = path_replacements(tmp_root, corpus_root)
    normalized_report = normalize_node(report, replacements)
    normalized_manifest = normalize_node(manifest, replacements)
    return {
        "identity": canonical_identity(normalized_report, normalized_manifest),
        "normalized_report": normalized_report,
        "normalized_manifest": normalized_manifest,
    }


def compute_fixture_identity(work: Path) -> dict:
    """Identity of the deterministic fixture corpus; used by the contract test."""
    generation = build_fixture_generation(work)
    doc = identity_doc(generation, tmp_root=work, corpus_root=None)
    doc["generation_dir"] = str(generation)
    return doc


def compute_scan_identity(repo: Path, work: Path) -> dict:
    """Identity of a real pipeline scan over ``repo`` (machine-local gate)."""
    from attackmap.orchestration.pipeline import AnalyzeOptions, run_scan

    repo = Path(repo).resolve()
    output = work / "output"
    options = AnalyzeOptions(
        repo_path=repo,
        output=output,
        no_progress=True,
        run_id="identity",
        echo=lambda *args, **kwargs: None,
    )
    state = run_scan(options)
    if state.exit_code != 0:
        raise RuntimeError(f"identity scan of {repo} failed with exit code {state.exit_code}")
    return identity_doc(output / "identity", tmp_root=work, corpus_root=repo)


def load_baseline(path: Path = BASELINE_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def semantic_diff(baseline: dict, doc: dict) -> str:
    recorded = json.dumps(
        {"report": baseline.get("normalized_report"), "artifact_manifest": baseline.get("normalized_manifest")},
        sort_keys=True,
        indent=2,
    ).splitlines(keepends=True)
    current = json.dumps(
        {"report": doc.get("normalized_report"), "artifact_manifest": doc.get("normalized_manifest")},
        sort_keys=True,
        indent=2,
    ).splitlines(keepends=True)
    return "".join(difflib.unified_diff(recorded, current, fromfile="recorded-baseline", tofile="current", n=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stable semantic identity of report output (AR032).")
    parser.add_argument("--record", action="store_true", help="write the baseline file")
    parser.add_argument("--check", action="store_true", help="compare against the baseline; exit 1 on drift")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="scan a real repository instead of the deterministic artifact fixture",
    )
    parser.add_argument("--output", type=Path, default=None, help="keep scratch output in this directory")
    args = parser.parse_args(argv)

    if args.output is not None:
        args.output.mkdir(parents=True, exist_ok=True)
        work = args.output
        doc = compute_scan_identity(args.corpus, work) if args.corpus else compute_fixture_identity(work)
    else:
        with tempfile.TemporaryDirectory(prefix="attackmap-identity-") as tmp:
            work = Path(tmp)
            doc = compute_scan_identity(args.corpus, work) if args.corpus else compute_fixture_identity(work)

    label = f"scan:{args.corpus.resolve().name}" if args.corpus else CORPUS_LABEL
    print(f"{label} identity: {doc['identity']}")
    if args.record:
        payload = {
            "corpus": label,
            "identity": doc["identity"],
            "normalized_manifest": doc["normalized_manifest"],
            "normalized_report": doc["normalized_report"],
            "schema": 1,
        }
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"recorded baseline -> {BASELINE_PATH.relative_to(REPO_ROOT).as_posix()}")
        return 0
    if args.check:
        try:
            baseline = load_baseline()
        except FileNotFoundError:
            print(f"no baseline at {BASELINE_PATH.relative_to(REPO_ROOT).as_posix()}; run --record first")
            return 2
        if baseline.get("identity") != doc["identity"]:
            print("report semantic identity drifted from the recorded baseline:")
            print(semantic_diff(baseline, doc))
            print("if the change is intentional, re-record with: python -m tools.report_identity --record")
            return 1
        print("identity matches the recorded baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

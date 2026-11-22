"""Filesystem access confined to the scanned repository (#234, #228).

AttackMap scans untrusted checkouts, so a symlink in the repo must never make
it read a file outside the repo (and report or send that file's content
elsewhere), and a symlink planted where a report is about to be written must
never redirect that write.

Read side:
    * :func:`walk_repo` yields the regular files under a root without
      following symlinks — symlinked files are skipped and symlinked
      directories are not descended. Set ``ATTACKMAP_FOLLOW_SYMLINKS=1`` to
      follow symlinks whose target resolves inside the root.
    * :func:`is_contained` / :func:`contained_file` validate a path (or a
      repo-relative path taken from evidence text) before it is read.
    * :func:`read_repo_text` reads a file only if it is contained.

Write side:
    * :func:`safe_write_text` refuses to write through a symlink or outside
      the output directory, and never follows a symlink planted at the target.

Artifact identity (walking support):
    * :func:`generated_artifact_names` recognises AttackMap's own published
      report files so a walk over a repository containing its output skips
      them, and :func:`current_generation` / :func:`validate_generation`
      resolve a published generation fail-closed. These primitives live here
      (below the artifact serializers) so walkers and the artifact layer can
      share them without an import cycle.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

FOLLOW_SYMLINKS_ENV = "ATTACKMAP_FOLLOW_SYMLINKS"
# Written into every report directory (#216). Legacy output directories are
# pruned; manifested output uses per-file identity to preserve replaced sources.
OUTPUT_MARKER = ".attackmap-output"
MAX_FILE_BYTES_ENV = "ATTACKMAP_MAX_FILE_BYTES"
# Files larger than this are not read (#236): a hostile or generated multi-MB
# file must not stall a CI scan. Real source files are far smaller.
DEFAULT_MAX_FILE_BYTES = 2_000_000

# Published-generation file identity. Declared here so walking and generation
# validation can run without importing the artifact serializers above them.
MANIFEST_FILENAME = "artifact-manifest.json"
PINS_FILENAME = "pinned-generations.json"
CURRENT_POINTER = "current-generation.json"
SCHEMA_VERSION = "1.0.0"
ARTIFACT_TYPE = "attackmap_artifact_manifest"
DEFAULT_REQUIRED = ("attackmap-report.json", MANIFEST_FILENAME, "run-manifest.json")
FLEET_REQUIRED = ("fleet-summary.json", MANIFEST_FILENAME, "run-manifest.json")

# Sections extracted from the legacy monolithic report JSON.
SECTION_ORDER: list[tuple[str, str, str]] = [
    ("scan", "scan.json", "structured-scan-result"),
    ("findings", "findings.json", "findings-array"),
    ("attack_paths", "attack_paths.json", "attack-paths-array"),
    ("attack_surfaces", "attack_surfaces.json", "attack-surfaces-array"),
    ("exploitability", "exploitability.json", "exploitability-array"),
    ("suppressed_findings", "suppressed_findings.json", "suppressed-findings-array"),
]

_LEGACY_JSON_FILES = frozenset({
    "attackmap-report.json", "run-manifest.json", "defensive-review.json",
    "review-context-pack.json", "fleet-summary.json",
    "defensive-review-llm.meta.json", "benchmark-results.json",
    "attackmap-diagnostics.json",
})

_MARKDOWN_EXPORTS = (
    "architecture.md", "attack-surface.md", "defensive-review.md",
    "attackmap-exploitability.md", "attackmap-paths.md", "attackmap-topology.md",
    "attackmap-paths.dot", "attackmap-topology.dot",
)

_OPTIONAL_EXPORTS = (
    "attackmap-diff.md", "defensive-review-llm.md", "defensive-review-llm.meta.json",
    "vulnerability-hypotheses.md", "vulnerability-hypotheses.meta.json",
    "remediation.md", "remediation.meta.json", "triage.md", "triage.meta.json",
    "pr-review.md", "pr-review.json",
)

_MANIFEST_OUTPUT_NAMES = frozenset(
    filename for _, filename, _ in SECTION_ORDER
) | frozenset(_MARKDOWN_EXPORTS) | frozenset(_OPTIONAL_EXPORTS) | {
    "defensive-review.json", "review-context-pack.json", "run-manifest.json",
    "attackmap-report.json", "attackmap-report.sarif",
}


class UnsafePathError(OSError):
    """A read or write would escape the repository / output directory."""


def max_file_bytes() -> int:
    raw = os.environ.get(MAX_FILE_BYTES_ENV, "").strip()
    try:
        value = int(raw) if raw else DEFAULT_MAX_FILE_BYTES
    except ValueError:
        value = DEFAULT_MAX_FILE_BYTES
    return value if value > 0 else DEFAULT_MAX_FILE_BYTES


def is_oversized(path: Path) -> bool:
    """True when ``path`` is larger than the per-file read cap."""
    try:
        return path.stat().st_size > max_file_bytes()
    except OSError:
        return False


def follow_symlinks_enabled() -> bool:
    return os.environ.get(FOLLOW_SYMLINKS_ENV, "").strip().lower() in {"1", "true", "yes"}


def _resolved_within(root: Path, path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError):  # RuntimeError: symlink loop on some Pythons
        return False


def is_contained(root: str | Path, path: str | Path) -> bool:
    """True when ``path`` is inside ``root`` and is not reached via a symlink.

    Every component between ``root`` and ``path`` is checked with ``lstat`` —
    a symlinked directory in the middle of the path disqualifies it just like
    a symlinked file. With ``ATTACKMAP_FOLLOW_SYMLINKS=1`` symlinks are allowed
    as long as the fully resolved path stays inside ``root``.
    """
    root_path = Path(root)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root_path / candidate
    try:
        rel = candidate.relative_to(root_path)
    except ValueError:
        try:
            rel = candidate.relative_to(root_path.resolve())
            root_path = root_path.resolve()
        except ValueError:
            return False
    if ".." in rel.parts:
        return False
    if follow_symlinks_enabled():
        return _resolved_within(root_path, candidate)
    current = root_path
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            return False
    return _resolved_within(root_path, candidate)


def is_unsafe_link(root: str | Path, entry: Path) -> bool:
    """For hand-rolled ``iterdir`` walkers: True when ``entry`` is a symlink
    that must be skipped (always, unless follow mode is on and it resolves
    inside ``root``)."""
    if not entry.is_symlink():
        return False
    return not (follow_symlinks_enabled() and _resolved_within(Path(root), entry))


def contained_file(root: str | Path, rel: str | Path) -> Path | None:
    """Resolve a repo-relative path from untrusted text (evidence, plugin
    output) to a regular file inside ``root``, or ``None``.

    Absolute paths and paths with ``..`` components are rejected outright.
    """
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts or str(rel).startswith("~"):
        return None
    candidate = Path(root) / rel_path
    if not is_contained(root, candidate):
        return None
    try:
        return candidate if candidate.is_file() else None
    except OSError:
        return None


def read_repo_text(
    root: str | Path, path: str | Path, *, encoding: str = "utf-8", errors: str = "strict"
) -> str:
    """``Path.read_text`` that refuses paths outside ``root`` or behind a symlink."""
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(root) / candidate
    if not is_contained(root, candidate):
        raise UnsafePathError(f"refusing to read outside the repository: {path}")
    return candidate.read_text(encoding=encoding, errors=errors)


def walk_repo(
    root: str | Path,
    *,
    prune: Callable[[str], bool] | None = None,
    on_symlink: Callable[[Path], None] | None = None,
) -> Iterator[Path]:
    """Yield regular files under ``root`` (depth-first, sorted per directory).

    Symlinks are skipped — symlinked files are not yielded and symlinked
    directories are not descended — and ``on_symlink(path)`` is called for
    each. With ``ATTACKMAP_FOLLOW_SYMLINKS=1`` symlinks whose target resolves
    inside ``root`` are followed (cycle-safe); ones pointing outside are still
    skipped. ``prune(dirname)`` returning True skips descending into a
    directory.
    """
    root_path = Path(root)
    follow = follow_symlinks_enabled()
    seen_dirs: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=follow):
        current = Path(dirpath)
        if follow:
            real = os.path.realpath(dirpath)
            if real in seen_dirs or not _resolved_within(root_path, current):
                dirnames[:] = []
                continue
            seen_dirs.add(real)
        kept_dirs = []
        for name in sorted(dirnames):
            if prune is not None and prune(name):
                continue
            child = current / name
            # Legacy output directories retain their marker-based exclusion.
            # Modern manifests identify individual files below, so replaced
            # artifacts and added user sources remain visible to the scan.
            if ((child / OUTPUT_MARKER).is_file()
                    and not (child / OUTPUT_MARKER).is_symlink()
                    and not (child / MANIFEST_FILENAME).is_file()):
                continue
            if child.is_symlink() and not (follow and _resolved_within(root_path, child)):
                if on_symlink is not None:
                    on_symlink(child)
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        generated = generated_artifact_names(current, filenames)
        for name in sorted(filenames):
            if name in generated or name == OUTPUT_MARKER:
                continue
            child = current / name
            if child.is_symlink() and not (follow and _resolved_within(root_path, child)):
                if on_symlink is not None:
                    on_symlink(child)
                continue
            try:
                if child.is_file():
                    yield child
            except OSError:
                continue


def _artifact_json(path: Path, limit: int) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or path.stat().st_size > limit:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, UnicodeError, ValueError, RecursionError):
        return None


def _is_legacy_artifact(name: str, data: dict[str, Any]) -> bool:
    """Recognize old report structures without reserving their basenames."""
    shapes: dict[str, dict[str, type[Any]]] = {
        "attackmap-report.json": {"scan": dict, "findings": list, "attack_paths": list, "attack_surfaces": list},
        "run-manifest.json": {"engine_version": str, "analyzers": list, "stages": list, "files_scanned": int, "findings_by_severity": dict},
        "defensive-review.json": {"schema_version": str, "target_metadata": dict, "raw_structured_signals": dict, "limitations_meta": dict},
        "fleet-summary.json": {"repo_count": int, "repos": list, "cross_repo_links": list, "total_findings": int},
        "defensive-review-llm.meta.json": {"backend": str, "model": str, "usage": dict},
        "attackmap-diagnostics.json": {"schema_version": str, "export_type": str, "generated_at": str, "generations": list},
    }
    if name == "review-context-pack.json":
        return data.get("artifact_type") == "attackmap_review_context_pack"
    if name == "benchmark-results.json":
        overall = data.get("overall")
        return isinstance(data.get("cases"), list) and isinstance(overall, dict) and bool(overall) and all(
            isinstance(value, dict) and {"tp", "fp", "precision", "recall", "missed_expected"} <= value.keys()
            for value in overall.values()
        )
    required = shapes.get(name)
    if not required:
        return False
    return all(isinstance(data.get(key), kind) for key, kind in required.items())


def _is_pins_payload(data: dict[str, Any]) -> bool:
    """Recognize our pin store structurally; a user file with this name stays input."""
    pinned = data.get("pinned")
    return (data.get("schema_version") == "1.0" and isinstance(pinned, list)
            and len(pinned) <= 10_000 and len(set(pinned)) == len(pinned)
            and all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name)
                    and not name.endswith(".") for name in pinned))


def generated_artifact_names(directory: Path, filenames: list[str]) -> set[str]:
    """Identify local generated files using manifest checksums or legacy shapes.

    Invalid metadata and replaced files remain scan inputs. Only flat paths are
    accepted: current publishers write flat manifests, and a repository-supplied
    manifest must not hide arbitrary files in other directories.
    """
    names = set(filenames)
    generated: set[str] = set()
    claimed: set[str] = set()
    if "current-generation.json" in names and current_generation(directory) is not None:
        generated.add("current-generation.json")
    if PINS_FILENAME in names:
        payload = _artifact_json(directory / PINS_FILENAME, min(max_file_bytes(), 100_000))
        if payload is not None and _is_pins_payload(payload):
            generated.add(PINS_FILENAME)
    manifest = (
        _artifact_json(directory / MANIFEST_FILENAME, min(max_file_bytes(), 1_000_000))
        if MANIFEST_FILENAME in names else None
    )
    if (manifest and manifest.get("artifact_type") == ARTIFACT_TYPE
            and isinstance(manifest.get("generation_id"), str)
            and isinstance(manifest.get("sections"), list)
            and isinstance(manifest.get("compatibility_exports"), list)):
        generated.add(MANIFEST_FILENAME)
        for section in manifest["sections"] + manifest["compatibility_exports"]:
            if not isinstance(section, dict):
                continue
            name = section.get("path")
            if (not isinstance(name, str) or name not in names
                    or name not in _MANIFEST_OUTPUT_NAMES or Path(name).name != name):
                continue
            claimed.add(name)
            path = directory / name
            try:
                if (not path.is_symlink() and path.stat().st_size <= max_file_bytes()
                        and section.get("checksum") == hashlib.sha256(path.read_bytes()).hexdigest()):
                    generated.add(name)
            except (OSError, UnicodeError):
                continue
    for name in sorted((names & _LEGACY_JSON_FILES) - claimed, key=lambda value: (value.endswith(".meta.json"), value)):
        data = _artifact_json(directory / name, max_file_bytes())
        if name == "defensive-review-llm.meta.json" and not generated & {"attackmap-report.json", "run-manifest.json"}:
            continue
        if data is not None and _is_legacy_artifact(name, data):
            generated.add(name)
    return generated


def _component(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) or value.endswith("."):
        raise UnsafePathError("Invalid generation or artifact name")
    if value.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        raise UnsafePathError("Reserved Windows path component")
    return value


def _safe(path: Path) -> Path:
    # lstat flags are available on Python 3.11, unlike Path.is_junction().
    # Check ancestors first so a redirected parent is rejected before traversal.
    for part in reversed((path.absolute(), *path.absolute().parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue  # A not-yet-created destination is allowed.
        except OSError as exc:
            raise UnsafePathError("Cannot verify artifact path") from exc
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or getattr(info, "st_reparse_tag", 0)):
            raise UnsafePathError(f"Refusing redirected artifact path: {part}")
    return path


def _json(path: Path) -> dict:
    _safe(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path.name}")
    return data


def validate_generation(folder: Path, *, required_files: tuple[str, ...] = DEFAULT_REQUIRED) -> dict:
    """Verify manifest version, required section shapes, and every recorded byte hash."""
    folder = _safe(Path(folder))
    manifest = _json(folder / MANIFEST_FILENAME)
    fleet = manifest.get("generation_profile") == "fleet"
    if fleet and required_files == DEFAULT_REQUIRED:
        required_files = FLEET_REQUIRED
    for name in required_files:
        path = _safe(folder / _component(name))
        if not path.is_file():
            raise ValueError(f"Missing required artifact: {name}")
    if (manifest.get("schema_version") != SCHEMA_VERSION
            or manifest.get("artifact_type") != ARTIFACT_TYPE
            or manifest.get("generation_id") != folder.name):
        raise ValueError("Unsupported or foreign artifact manifest")
    identity = manifest.get("run_identity")
    if (not isinstance(manifest.get("engine_version"), str)
            or not isinstance(manifest.get("created_at"), str)
            or not isinstance(identity, dict)
            or not isinstance(identity.get("repo_root"), str)
            or not isinstance(identity.get("repo_name"), str)
            or not isinstance(identity.get("analyzers"), list)):
        raise ValueError("Invalid artifact manifest identity")
    state = manifest.get("exit_state", {})
    if (not isinstance(state, dict) or type(state.get("exit_code")) is not int
            or state.get("status") not in {"completed", "success", "succeeded", "ok", "policy_failed"}):
        raise ValueError("Unsuccessful generation cannot become current")
    sections = manifest.get("sections")
    exports = manifest.get("compatibility_exports")
    if not isinstance(sections, list) or not isinstance(exports, list):
        raise ValueError("Invalid artifact entries")
    paths = set()
    for entry in sections + exports:
        if not isinstance(entry, dict):
            raise ValueError("Invalid artifact entry")
        if not all(isinstance(entry.get(key), str) for key in ("name", "format", "role", "path")):
            raise ValueError("Invalid artifact entry schema")
        name = _component(entry.get("path", ""))
        if name in paths:
            raise ValueError("Duplicate artifact path")
        paths.add(name)
        path = _safe(folder / name)
        raw = path.read_bytes()
        if "size_bytes" in entry and entry["size_bytes"] != len(raw):
            raise ValueError(f"Artifact size mismatch: {name}")
        if hashlib.sha256(raw).hexdigest() != entry.get("checksum"):
            raise ValueError(f"Artifact checksum mismatch: {name}")
        if entry.get("format") == "json":
            json.loads(raw)
    for key, filename, _ in ([] if fleet else SECTION_ORDER):
        if filename not in paths:
            raise ValueError(f"Missing required section: {filename}")
        value = json.loads((folder / filename).read_text(encoding="utf-8"))
        if not isinstance(value, dict if key == "scan" else list):
            raise ValueError(f"Invalid section schema: {filename}")
    if not set(required_files).difference({MANIFEST_FILENAME}) <= paths:
        raise ValueError("Required artifacts must have manifest checksums")
    if fleet:
        summary = _json(folder / "fleet-summary.json")
        if (type(summary.get("repo_count")) is not int or not isinstance(summary.get("repos"), list)
                or not isinstance(summary.get("cross_repo_links"), list)
                or type(summary.get("total_findings")) is not int):
            raise ValueError("Invalid fleet summary schema")
        children = manifest.get("children")
        if not isinstance(children, list) or len(children) != summary["repo_count"]:
            raise ValueError("Missing fleet child generations")
        seen = set()
        for child in children:
            parts = child["path"].split("/")
            if len(parts) != 2 or child["path"] in seen:
                raise ValueError("Invalid fleet child path")
            seen.add(child["path"])
            target = _safe(folder.joinpath(*(_component(part) for part in parts)))
            if hashlib.sha256((target / MANIFEST_FILENAME).read_bytes()).hexdigest() != child["manifest_sha256"]:
                raise ValueError("Fleet child manifest checksum mismatch")
            validate_generation(target)
    else:
        report = _json(folder / "attackmap-report.json")
        if not isinstance(report.get("scan"), dict) or not isinstance(report["scan"].get("root"), str):
            raise ValueError("Invalid report schema")
    timing = _json(folder / "run-manifest.json")
    if not isinstance(timing.get("stages"), list):
        raise ValueError("Invalid run timing schema")
    return manifest


def current_generation(base: Path) -> Path | None:
    """Resolve only a fully validated current generation; corruption fails closed."""
    try:
        base = _safe(Path(base))
        pointer = _json(base / CURRENT_POINTER)
        folder = _safe(base / _component(pointer["generation"]))
        manifest_bytes = (folder / MANIFEST_FILENAME).read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != pointer["manifest_sha256"]:
            return None
        validate_generation(folder)
        return folder
    except (OSError, ValueError, KeyError, TypeError):
        return None


def ensure_output_dir(out_dir: str | Path, *, mark: bool = False) -> Path:
    """Create the report directory, refusing a symlinked one.

    No ancestor inside the current working directory (usually the checkout
    being scanned) may be a symlink that leads outside it — otherwise a
    committed ``reports -> /somewhere`` link would redirect every report write
    (#228). Symlinks that stay inside the cwd are allowed, which also covers
    system links such as macOS's ``/var`` and ``/tmp`` (→ ``/private/...``)
    when the cwd is ``/``, as it is for a GUI-launched or test-runner process.
    """
    out = Path(out_dir)
    absolute = out.absolute()
    cwd = Path.cwd()
    real_cwd = cwd.resolve()
    for candidate in (absolute, *absolute.parents):
        if candidate == cwd or not candidate.is_relative_to(cwd):
            continue
        if candidate.is_symlink() and not candidate.resolve().is_relative_to(real_cwd):
            raise UnsafePathError(f"refusing to write reports through a symlink: {candidate}")
    out.mkdir(parents=True, exist_ok=True)
    if out.is_symlink():
        raise UnsafePathError(f"refusing to write reports into a symlinked directory: {out}")
    if mark:
        marker = out / OUTPUT_MARKER
        if not marker.exists() and not marker.is_symlink():
            safe_write_text(
                out,
                marker,
                "AttackMap report directory. AttackMap never scans a directory containing this file.\n",
            )
    return out


def _check_output_target(out: Path, target: Path) -> None:
    if out.is_symlink():
        raise UnsafePathError(f"refusing to write reports into a symlinked directory: {out}")
    if target.is_symlink():
        raise UnsafePathError(f"refusing to write through a symlink: {target}")
    if not target.parent.resolve().is_relative_to(out.resolve()):
        raise UnsafePathError(f"refusing to write outside the output directory {out}: {target}")


def _open_output_fd(out: Path, target: Path, flags: int) -> int:
    _check_output_target(out, target)
    try:
        return os.open(target, flags, 0o644)
    except OSError as exc:
        if target.is_symlink():
            raise UnsafePathError(f"refusing to write through a symlink: {target}") from exc
        raise


def safe_write_text(out_dir: str | Path, path: str | Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write ``text`` to ``path`` without following symlinks.

    Refuses when ``path`` is (or sits behind) a symlink, or resolves outside
    ``out_dir``. The final open uses ``O_NOFOLLOW`` so a symlink swapped in
    after the check is not followed either.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = _open_output_fd(Path(out_dir), Path(path), flags)
    with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
        handle.write(text)


def safe_write_json_report(out_dir: str | Path, path: str | Path, value: object) -> None:
    """Encode to a held temporary, then exclusively create a new report destination."""
    import json
    import tempfile

    out, target = Path(out_dir), Path(path)
    if target.exists() or target.is_symlink():
        safe_write_text(out, target, json.dumps(value, indent=2) + "\n")
        return
    _check_output_target(out, target)
    with tempfile.TemporaryFile(mode="w+b", dir=target.parent, prefix=".report-stage-") as stage:
        def emit(text):
            stage.write(text.encode("utf-8"))
        if type(value) is dict and all(type(key) is str for key in value):
            if not value:
                emit("{}")
            else:
                emit("{\n")
                first = True
                for key, section in value.items():
                    if not first:
                        emit(",\n")
                    first = False
                    emit("  " + json.dumps(key) + ": ")
                    text = json.dumps(section, indent=2)
                    emit(text.replace("\n", "\n  "))
                    del text
                emit("\n}")
        else:
            emit(json.dumps(value, indent=2))
        emit("\n")
        stage.flush()
        stage.seek(0)
        _check_output_target(out, target)
        if target.exists() or target.is_symlink():
            raise FileExistsError(f"report destination appeared during encoding: {target}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        target_fd = _open_output_fd(out, target, flags)
        try:
            destination = os.fdopen(target_fd, "wb")
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(target_fd)
            raise
        with destination:
            while chunk := stage.read(65536):
                destination.write(chunk)

"""Content-snapshot identity and verification over the accepted file set.

Lives in ``foundation`` (AR030): the snapshot basis is pure filesystem +
hashing policy over the index acceptance limits, needed by foundation
publication gates (artifact_manifest) and the SDK read surface without an
upward import into extraction. ``extraction.index`` builds snapshots with
these primitives and re-exports the names for one release.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

from attackmap.foundation.safe_fs import max_file_bytes, walk_repo
from attackmap.foundation.srcpaths import is_skipped_dir

_SNAPSHOT_SCHEMA = "attackmap-snapshot/1.0"


def content_sha256(text: str) -> str:
    """sha256 of a file's content on the index basis (decoded utf-8 text)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def decode_source_bytes(raw: bytes) -> str | None:
    """SDK-compatible decoding, including legacy text and original newlines."""
    if b"\0" in raw[:8192]:
        return None
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def _snapshot_text(raw: bytes, sdk: bool = False) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        text = decode_source_bytes(raw) if sdk else None
        if text is None:
            raise UnicodeDecodeError("utf-8", raw, 0, min(1, len(raw)), "not captured text") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _snapshot_hash(raw: bytes, sdk: bool = False) -> str:
    try:
        return content_sha256(_snapshot_text(raw, sdk=sdk))
    except UnicodeDecodeError:
        if not sdk:
            raise
        # SDK enumeration can observe binary names even though read_source returns None.
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CapturedSource:
    rel: str
    raw: bytes
    mtime_ns: int

    @property
    def size(self) -> int:
        return len(self.raw)


class ScanSnapshotIdentity(BaseModel):
    """Content identity of the one file snapshot a run analyzed (C33/AM047).

    Built by the repo index at index time; deterministic passes read the
    indexed text, so their evidence references this snapshot. ``files`` maps
    repo-relative paths to the established decoded-content hash (SDK-only binary
    paths use their byte hash). ``raw_files`` additionally binds original input
    bytes, including newlines and encoding. ``index_config`` records the limits
    that decided file acceptance, and ``config_identity`` hashes them.
    """

    snapshot_id: str
    files: dict[str, str] = Field(default_factory=dict)
    # Additive exact-byte basis for SDK inputs. Empty preserves legacy text-only identity.
    raw_files: dict[str, str] = Field(default_factory=dict)
    total_size: int = 0
    index_config: dict[str, int] = Field(default_factory=dict)
    config_identity: str = ""

    @model_validator(mode="after")
    def _validate_raw_snapshot_paths(self):
        for relative, digest in self.raw_files.items():
            path = Path(relative)
            if (relative not in self.files or path.is_absolute() or path.drive
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
                raise ValueError("Raw snapshot hashes require captured relative paths and lowercase SHA-256")
        return self


@dataclass(frozen=True)
class SnapshotVerification:
    """Publication-time re-check of the working tree against one snapshot.

    ``state`` is ``"verified"`` (no drift), ``"drifted"`` (the run analyzed a
    mixture of revisions) or ``"unverified"`` (the check itself could not run).
    """

    state: str
    checked_files: int = 0
    changed: tuple[str, ...] = ()
    deleted: tuple[str, ...] = ()
    added: tuple[str, ...] = ()
    note: str | None = None

    @property
    def drifted(self) -> bool:
        return self.state == "drifted"

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "checked_files": self.checked_files,
            "changed": list(self.changed),
            "deleted": list(self.deleted),
            "added": list(self.added),
            **({"note": self.note} if self.note else {}),
        }

    def limitation(self) -> str | None:
        """Limitations-mechanism string for a drifted snapshot, else None."""
        if not self.drifted:
            return None
        parts = []
        if self.changed:
            parts.append("changed since index: " + ", ".join(self.changed))
        if self.deleted:
            parts.append("deleted since index: " + ", ".join(self.deleted))
        if self.added:
            parts.append("new since index: " + ", ".join(self.added))
        return (
            "incomplete snapshot: repository mutated during scan ("
            + "; ".join(parts)
            + "). Evidence may mix file revisions; re-run for a consistent report."
        )


@dataclass(frozen=True)
class ScanSnapshot:
    """Content identity of every accepted file at index time (C33/AM047).

    One run's deterministic passes read the indexed text, so its evidence is
    tied to this snapshot. ``snapshot_id`` hashes the sorted ``(rel, sha256)``
    set: any accepted-file content change, addition or deletion changes it.
    """

    snapshot_id: str
    files: tuple[tuple[str, str], ...]
    total_size: int
    index_config: tuple[tuple[str, int], ...]
    raw_files: tuple[tuple[str, str], ...] = ()

    @staticmethod
    def _id_for(files: tuple[tuple[str, str], ...], raw_files: tuple[tuple[str, str], ...] = ()) -> str:
        basis: list = [_SNAPSHOT_SCHEMA, list(files)]
        if raw_files:
            basis.append(["raw-bytes/1.0", list(raw_files)])
        payload = json.dumps(basis,
                             ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def from_indexed(cls, files: Iterable[object], index_config: dict[str, int], sources: list[CapturedSource] | None = None) -> ScanSnapshot:
        # ``files`` items are extraction-layer IndexedFile records used
        # structurally (rel/sha256/size); typing them here would need an
        # upward import, so the contract is duck-typed (AR030).
        identities = {f.rel: f.sha256 for f in files}
        sizes = {f.rel: f.size for f in files}
        for source in sources or ():
            if source.rel not in identities:
                identities[source.rel] = _snapshot_hash(source.raw, sdk=True)
                sizes[source.rel] = source.size
        entries = tuple(sorted(identities.items()))
        raw_entries = tuple(sorted((source.rel, hashlib.sha256(source.raw).hexdigest()) for source in sources or ()))
        return cls(cls._id_for(entries, raw_entries), entries, sum(sizes.values()),
                   tuple(sorted(index_config.items())), raw_entries)

    @classmethod
    def from_identity(cls, data: dict) -> ScanSnapshot:
        """Rehydrate from a serialized :class:`ScanSnapshotIdentity`."""
        raw_files = data.get("files")
        entries = tuple(sorted((str(rel), str(sha))
                               for rel, sha in (raw_files or {}).items()))
        raw_config = data.get("index_config")
        config = tuple(sorted((str(name), int(value))
                              for name, value in (raw_config or {}).items()))
        raw_entries = tuple(sorted((str(rel), str(sha)) for rel, sha in (data.get("raw_files") or {}).items()))
        return cls(cls._id_for(entries, raw_entries), entries, int(data.get("total_size") or 0), config, raw_entries)

    @property
    def config_identity(self) -> str:
        payload = json.dumps([_SNAPSHOT_SCHEMA, "config", list(self.index_config)],
                             ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def identity(self) -> ScanSnapshotIdentity:
        """The additive model form carried on ``ScanResult.scan_snapshot``."""
        return ScanSnapshotIdentity(
            snapshot_id=self.snapshot_id,
            files=dict(self.files),
            raw_files=dict(self.raw_files),
            total_size=self.total_size,
            index_config=dict(self.index_config),
            config_identity=self.config_identity,
        )

    def verify(self, root: str | Path, *, exclude: tuple[str | Path, ...] = ()) -> SnapshotVerification:
        """Re-read the working tree and compare it against this snapshot.

        Every snapshot file is re-hashed on the index basis (full content, no
        mtime shortcut — stat timestamps only gate the cheaper mid-scan
        ``RepoIndex.mutation_warnings``), and the tree is re-walked to find
        files that appeared after the index was built. New-file detection
        replays the acceptance limits recorded in ``index_config`` (per-file
        cap, aggregate byte budget, file-count cap) in the build's walk order,
        so a new file the policy would have skipped is not drift: the analyzed
        snapshot is complete without it. Paths under *exclude* (the run's own
        output directory) are not drift.
        """
        root_path = Path(root)
        excluded: list[Path] = []
        for item in exclude:
            try:
                excluded.append(Path(item).resolve())
            except OSError:
                continue
        known = dict(self.files)
        raw_known = dict(self.raw_files)
        changed: list[str] = []
        deleted: list[str] = []
        added: list[str] = []
        checked = 0
        visible: set[str] = set()
        for rel, expected in self.files:
            path = root_path / rel
            try:
                raw = path.read_bytes()
                actual_hash = _snapshot_hash(raw, sdk=bool(dict(self.index_config).get("capture_sdk_sources")))
            except UnicodeDecodeError:
                changed.append(rel)
                continue
            except OSError:
                # A snapshot file that vanished is deleted; one that stat-fails
                # or denies reading is drift of the changed kind either way.
                (deleted if not path.exists() else changed).append(rel)
                continue
            checked += 1
            if actual_hash != expected or (rel in raw_known and hashlib.sha256(raw).hexdigest() != raw_known[rel]):
                changed.append(rel)
        # Charge each snapshot file its (live) size — the build's charge is not
        # recoverable from the hashes; a file whose size also changed is
        # already reported under ``changed``.
        known_sizes: dict[str, int] = {}
        for rel in known:
            try:
                known_sizes[rel] = (root_path / rel).stat().st_size
            except OSError:
                continue  # gone: reported above, occupies no budget now
        added = list(
            _replay_added_files(root_path, known_sizes, dict(self.index_config), exclude=excluded, visible=visible)
        )
        for rel in known:
            path = root_path / rel
            if (rel not in visible and rel not in deleted and rel not in changed
                    and not any(_is_under(path, base) for base in excluded)):
                changed.append(rel)  # e.g. a newly added output marker changed source scope
        state = "drifted" if (changed or deleted or added) else "verified"
        return SnapshotVerification(state, checked, tuple(sorted(changed)),
                                    tuple(sorted(deleted)), tuple(sorted(added)))


def _is_under(path: Path, base: Path) -> bool:
    try:
        return path.resolve().is_relative_to(base)
    except (OSError, RuntimeError):
        return False


def _replay_added_files(
    root: Path,
    known_sizes: dict[str, int],
    config: dict[str, int],
    *,
    exclude: tuple[Path, ...] = (),
    visible: set[str] | None = None,
) -> tuple[str, ...]:
    """New files the index acceptance policy would have captured (C33/AM047).

    Replays the build's gates — per-file byte cap, aggregate byte
    budget, accepted-file count cap, utf-8 decode — in the build's walk order.
    Snapshot files (``known_sizes``) are charged their size and count first,
    exactly as the build accepted them, so a candidate the budget or count cap
    would have skipped is not reported: that file was never part of any
    analyzable snapshot under these limits.
    """
    file_limit = int(config.get("max_file_bytes") or 0) or max_file_bytes()
    budget = int(config.get("index_byte_budget") or 0)
    count_limit = int(config.get("index_file_limit") or 0)
    used = 0
    accepted = 0
    sdk_accepted = 0
    sdk_capture = bool(config.get("capture_sdk_sources"))
    added: list[str] = []
    for path in walk_repo(root, prune=is_skipped_dir):
        try:
            rel = path.relative_to(root).as_posix()
            size = path.stat().st_size
        except (ValueError, OSError):
            continue
        if any(_is_under(path, base) for base in exclude):
            continue
        if visible is not None:
            visible.add(rel)
        if rel in known_sizes and not sdk_capture:
            used += known_sizes[rel]
            accepted += 1
            continue
        # The build's gate order: per-file cap, budget charge, count cap, decode.
        if size > file_limit:
            continue
        if budget > 0:
            if used + size > budget:
                continue
            used += size
        if count_limit > 0 and accepted >= count_limit:
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        core_accepted = False
        try:
            raw.decode("utf-8")
            core_accepted = True
        except UnicodeDecodeError:
            if not sdk_capture:
                continue
        sdk_accepted_here = sdk_capture and (count_limit <= 0 or sdk_accepted < count_limit)
        if rel not in known_sizes and (core_accepted or sdk_accepted_here):
            added.append(rel)
        accepted += int(core_accepted)
        sdk_accepted += int(sdk_accepted_here)
    return tuple(sorted(added))


__all__ = [
    "CapturedSource",
    "ScanSnapshot",
    "ScanSnapshotIdentity",
    "SnapshotVerification",
    "content_sha256",
    "decode_source_bytes",
]

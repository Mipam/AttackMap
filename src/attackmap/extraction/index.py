"""One walk, one read: a per-run file index for built-in scanners and taint."""

from __future__ import annotations

import hashlib
import json
import os
from collections import deque
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from attackmap.extraction.run_budget import active_budget
from attackmap.foundation.errors import BudgetExpired

# AR030 re-exports: the pin and snapshot primitives live in foundation; these
# names stay importable from extraction.index for one release.
from attackmap.foundation.index_pin import (  # noqa: F401
    PinnedIndex,
    active_index_for,
    clear_pinned_index,
    install_process_snapshot,
    pinned_index_scope,
    pinned_repo_index,
    set_pinned_index,
)
from attackmap.foundation.safe_fs import contained_file, is_oversized, max_file_bytes, walk_repo
from attackmap.foundation.snapshot import (  # noqa: F401
    CapturedSource,
    ScanSnapshot,
    ScanSnapshotIdentity,
    SnapshotVerification,
    _replay_added_files,
    _snapshot_hash,
    _snapshot_text,
    content_sha256,
    decode_source_bytes,
)
from attackmap.foundation.srcpaths import is_skipped_dir, line_number
from attackmap.models import ResourceLimitEvent

_NOISY_SYMLINK_PARTS = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"}

# Default accepted-file-count ceiling (C35 engineering target). Same
# acceptance semantics as the byte budget: overflowing files are skipped,
# the scope becomes partial — never a silent drop. ``ATTACKMAP_INDEX_FILE_LIMIT``
# overrides the default; 0 disables the count cap.
DEFAULT_INDEX_FILE_LIMIT = 100_000
_INDEX_FILE_LIMIT_ENV = "ATTACKMAP_INDEX_FILE_LIMIT"


def _read_capture_bytes(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        return stream.read(limit + 1)


def _ordered_capture_inputs(root: Path, limit: int, can_prefetch: Callable[[int], bool]):
    """Overlap bounded reads; caller commits all decisions in original walk order.

    At most eight read results of ``limit + 1`` bytes await consumption. Count
    and byte reservations assume every pending file consumes its worst case.
    Near either admission boundary, reads remain sequential in the caller.
    """
    try:
        workers = max(1, min(4, int(os.environ.get("ATTACKMAP_INDEX_READ_WORKERS", "4"))))
    except ValueError:
        workers = 4
    notes: list[str] = []

    def symlink(path: Path) -> None:
        rel = path.relative_to(root)
        if not any(part in _NOISY_SYMLINK_PARTS for part in rel.parts):
            notes.append(f"symlink not followed: {rel.as_posix()}")

    paths = iter(walk_repo(root, prune=is_skipped_dir, on_symlink=symlink))
    pending = deque()
    exhausted = False
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="attackmap-capture") as pool:
        try:
            while pending or not exhausted:
                while not exhausted and len(pending) < workers * 2:
                    # A queued sequential item must be consumed before walking on.
                    if pending and (pending[-1][3] is None or not can_prefetch(len(pending) + 1)):
                        break
                    try:
                        path = next(paths)
                    except StopIteration:
                        exhausted = True
                        break
                    ordered_notes = tuple(notes)
                    notes.clear()
                    try:
                        stat, error = path.stat(), None
                    except OSError as exc:
                        stat, error = None, exc
                    future = None
                    if workers > 1 and error is None and stat.st_size <= limit and can_prefetch(len(pending) + 1):
                        future = pool.submit(_read_capture_bytes, path, limit)
                    pending.append((path, stat, error, future, ordered_notes))
                    if future is None:
                        break
                if pending:
                    yield pending.popleft()
            if notes:
                yield None, None, None, None, tuple(notes)
        finally:
            for _, _, _, future, _ in pending:
                if future is not None:
                    future.cancel()

# Content basis for snapshot identity: the indexed text, i.e. the utf-8-decoded
# file as the passes saw it (C33/AM047). Verification re-reads with the same
# basis, so a drift verdict never depends on newline or encoding normalization.

# C33/AM047: the index this thread's whole-repo passes resolve content through.
# ``RepoIndex.build`` pins itself so passes invoked later for the same root
# (SBOM, supply-chain, workflows, authz, anomalies, fingerprints) read the
# captured revision even where their call sites thread no index explicitly.
# Lookups are root-gated and per-thread; a newer build for the same root wins.
@dataclass(frozen=True)
class IndexedFile:
    rel: str
    suffix: str
    text: str
    line_starts: tuple[int, ...]
    path: Path
    mtime_ns: int = 0
    size: int = 0
    sha256: str = ""

    def line_of(self, offset: int) -> int:
        return line_number(self.text, offset)


@dataclass(frozen=True)
class RepoIndex:
    root: Path
    files: tuple[IndexedFile, ...]
    limitations: tuple[str, ...]
    resource_limit_events: tuple[ResourceLimitEvent, ...] = ()
    resource_limit_scopes: tuple[str, ...] = ()
    resource_limit_reporting: str = "unknown"
    snapshot: ScanSnapshot | None = None
    sources: tuple[CapturedSource, ...] = ()
    _by_rel: dict[str, IndexedFile] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_by_rel", {f.rel: f for f in self.files})

    @cached_property
    def sources_by_rel(self) -> dict[str, CapturedSource]:
        return {source.rel: source for source in self.sources}

    @property
    def captured_source_bytes(self) -> int:
        return sum(source.size for source in self.sources)

    @cached_property
    def directory_children(self) -> dict[str, tuple[str, ...]]:
        """Captured virtual directories, built only for passes that need children."""
        children: dict[str, dict[str, None]] = {".": {}}
        entries = dict.fromkeys([source.rel for source in self.sources] + [item.rel for item in self.files])
        for relative in entries:
            parent = Path(".")
            for component in Path(relative).parts:
                child = parent / component
                children.setdefault(parent.as_posix(), {})[child.as_posix()] = None
                parent = child
        return {parent: tuple(entries) for parent, entries in children.items()}

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    def with_suffixes(self, suffixes: set[str] | None) -> Iterator[IndexedFile]:
        if suffixes is None:
            yield from self.files
            return
        wanted = {s.lower() for s in suffixes}
        for item in self.files:
            if item.suffix.lower() in wanted:
                yield item

    def get(self, rel: str) -> IndexedFile | None:
        return self._by_rel.get(rel.replace("\\", "/"))

    def as_path_map(self, suffixes: set[str] | None = None) -> dict[str, Path]:
        return {item.rel: item.path for item in self.with_suffixes(suffixes)}

    def text_of(self, rel: str) -> str | None:
        item = self.get(rel)
        return None if item is None else item.text

    def mutation_warnings(self) -> tuple[str, ...]:
        """Return diagnostics for files that changed since the index was built.

        Cheap stat gate first (this runs mid-scan); any stat drift is confirmed
        against the snapshot's content hash, so a touch or in-place rewrite of
        identical text is not reported. New accepted files are detected too —
        they were never part of the analyzed snapshot (C33/AM047) — replaying
        the build's acceptance limits, so a file the byte budget or count cap
        would have skipped is not a mutation warning.
        """
        warnings: list[str] = []
        for item in self.files:
            try:
                stat = item.path.stat()
            except OSError as exc:
                warnings.append(
                    f"repository mutated during scan ({type(exc).__name__}): {item.rel}"
                )
                continue
            if stat.st_size == item.size and stat.st_mtime_ns == item.mtime_ns:
                continue
            try:
                current = content_sha256(item.path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError):
                current = None
            if current != item.sha256:
                warnings.append(f"repository mutated during scan: {item.rel}")
        warnings.extend(
            f"repository mutated during scan: new file: {rel}" for rel in self._new_files()
        )
        for source in self.sources:
            if any(warning.rsplit(": ", 1)[-1] == source.rel for warning in warnings):
                continue
            try:
                stat = (self.root / source.rel).stat()
                if stat.st_size == source.size and stat.st_mtime_ns == source.mtime_ns:
                    continue
                if (self.root / source.rel).read_bytes() == source.raw:
                    continue
            except OSError:
                pass
            warnings.append(f"repository mutated during scan: {source.rel}")
        return tuple(dict.fromkeys(warnings))

    def _new_files(self) -> tuple[str, ...]:
        """Accepted files present now that the index never captured, judged
        under the acceptance limits recorded at build time (budget-faithful:
        a file the byte budget or count cap would have skipped is not new
        drift — no snapshot under those limits could have contained it)."""
        config = dict(self.snapshot.index_config) if self.snapshot is not None else {}
        known = {f.rel: f.size for f in self.files}
        known.update({source.rel: source.size for source in self.sources})
        return _replay_added_files(self.root, known, config)

    @classmethod
    def build(
        cls,
        root: str | Path,
        *,
        max_bytes: int | None = None,
        max_files: int | None = None,
    ) -> RepoIndex:
        root_path = Path(root).resolve()
        limitations: list[str] = []
        files: list[IndexedFile] = []
        sources: list[CapturedSource] = []
        sdk_count_exceeded = False
        resource_events: list[ResourceLimitEvent] = []
        env_budget = int(os.environ.get("ATTACKMAP_INDEX_BYTE_BUDGET", "0") or "0")
        budget = max_bytes if max_bytes is not None and max_bytes > 0 else env_budget
        # Captured once so the snapshot's config identity describes the limits
        # that actually decided which files were accepted.
        file_limit = max_file_bytes()
        try:
            env_file_limit = int(os.environ.get(_INDEX_FILE_LIMIT_ENV, "") or DEFAULT_INDEX_FILE_LIMIT)
        except ValueError:
            env_file_limit = DEFAULT_INDEX_FILE_LIMIT
        if max_files is not None:
            file_count_limit = max_files  # 0 explicitly disables the cap
        else:
            file_count_limit = env_file_limit if env_file_limit > 0 else 0
        used_bytes = 0
        budget_exceeded = False
        count_exceeded = False
        skipped_over_count = 0
        # AR007: intra-stage deadline check for the capture walk. Expiry stops
        # the walk and returns a partial index (limitation recorded below), so
        # select_analyzers still completes and the run still publishes.
        time_budget = active_budget()
        files_since_checkpoint = 0

        def _can_prefetch(pending: int) -> bool:
            return ((file_count_limit <= 0 or file_count_limit - len(files) >= pending)
                    and (budget <= 0 or budget - used_bytes >= pending * (file_limit + 1)))

        capture_inputs = _ordered_capture_inputs(root_path, file_limit, _can_prefetch)
        if time_budget is not None:
            try:
                time_budget.tick("index_build")
            except BudgetExpired:
                time_budget = None  # deadline already gone: stop before the walk
                capture_inputs = iter(())
                limitations.append(
                    "elapsed-time budget expired before indexing; no files were indexed - ANALYSIS IS PARTIAL."
                )
        for path, stat, stat_error, read_future, notes in capture_inputs:
            limitations.extend(notes)
            if time_budget is not None:
                files_since_checkpoint += 1
                if files_since_checkpoint >= max(1, time_budget.checkpoint_interval):
                    files_since_checkpoint = 0
                    try:
                        time_budget.tick("index_build")
                    except BudgetExpired:
                        time_budget = None
                        limitations.append(
                            f"elapsed-time budget expired while indexing after {len(files)} file(s); "
                            "remaining files were not indexed - ANALYSIS IS PARTIAL."
                        )
                        break
            if path is None:
                continue
            try:
                if stat_error is not None:
                    raise stat_error
            except OSError as exc:
                limitations.append(
                    f"unreadable file skipped ({type(exc).__name__}): "
                    f"{path.relative_to(root_path).as_posix()}"
                )
                continue

            size = stat.st_size
            if size > file_limit:
                resource_events.append(ResourceLimitEvent.skipped_file(
                    producer="repo_index", category="file_bytes", relative=path.relative_to(root_path).as_posix(),
                    limit=file_limit, observed_bytes=size))
                limitations.append(
                    f"oversized file skipped (> {file_limit} bytes): "
                    f"{path.relative_to(root_path).as_posix()}"
                )
                continue

            if budget > 0:
                if used_bytes + size > budget:
                    resource_events.append(ResourceLimitEvent.skipped_file(
                        producer="repo_index", category="index_bytes", relative=path.relative_to(root_path).as_posix(),
                        limit=budget, observed_bytes=used_bytes + size))
                    if not budget_exceeded:
                        limitations.append(
                            f"aggregate byte budget exceeded ({budget} bytes); "
                            "files exceeding the remaining budget skipped"
                        )
                        budget_exceeded = True
                    continue
                used_bytes += size

            # Accepted-count cap (C35): same semantics as the byte budget —
            # files beyond the cap are skipped with one aggregate limitation
            # line (never itemized) and one structured event emitted after
            # the walk knows the skipped total.
            if file_count_limit > 0 and len(files) >= file_count_limit:
                if not count_exceeded:
                    limitations.append(
                        f"file count limit exceeded ({file_count_limit} files); "
                        "remaining files skipped"
                    )
                    count_exceeded = True
                skipped_over_count += 1
                continue

            try:
                raw = read_future.result() if read_future is not None else _read_capture_bytes(path, file_limit)
            except OSError as exc:
                limitations.append(
                    f"unreadable file skipped ({type(exc).__name__}): "
                    f"{path.relative_to(root_path).as_posix()}"
                )
                continue
            rel = path.relative_to(root_path).as_posix()
            if len(raw) > file_limit:
                limitations.append(f"file grew beyond capture byte limit during scan: {rel}")
                resource_events.append(ResourceLimitEvent.skipped_file(producer="repo_index", category="file_bytes", relative=rel, limit=file_limit, observed_bytes=len(raw)))
                continue
            extra_bytes = max(0, len(raw) - size)
            if budget > 0 and used_bytes + extra_bytes > budget:
                limitations.append(f"file grew beyond aggregate capture byte budget during scan: {rel}")
                resource_events.append(ResourceLimitEvent.skipped_file(producer="repo_index", category="index_bytes", relative=rel, limit=budget, observed_bytes=used_bytes + extra_bytes))
                continue
            if budget > 0:
                used_bytes += extra_bytes
            size = len(raw)
            # Original bytes are shared with the SDK view, preserving legacy encodings
            # and newlines without changing the existing UTF-8 core text transform.
            if file_count_limit <= 0 or len(sources) < file_count_limit:
                sources.append(CapturedSource(rel, raw, stat.st_mtime_ns))
            elif not sdk_count_exceeded:
                sdk_count_exceeded = True
                limitations.append(f"SDK snapshot file count limit exceeded ({file_count_limit} files); SDK coverage is partial")
            try:
                text = _snapshot_text(raw)
            except UnicodeDecodeError:
                continue
            files.append(
                IndexedFile(
                    rel=rel,
                    suffix=path.suffix,
                    text=text,
                    line_starts=(),
                    path=path,
                    mtime_ns=stat.st_mtime_ns,
                    size=size,
                    sha256=content_sha256(text),
                )
            )
        snapshot = ScanSnapshot.from_indexed(
            files,
            {
                "max_file_bytes": file_limit,
                "index_byte_budget": budget,
                "index_file_limit": file_count_limit,
                "capture_sdk_sources": 1,
                "include_tests": int(bool(os.environ.get("ATTACKMAP_INCLUDE_TESTS"))),
                "include_vendored": int(bool(os.environ.get("ATTACKMAP_INCLUDE_VENDORED"))),
            },
            sources,
        )
        scopes = ["repo_index.file_bytes", "repo_index.index_bytes"]
        if sdk_count_exceeded:
            resource_events.append(ResourceLimitEvent(
                event_id=hashlib.sha256(f"sdk-capture-files:{file_count_limit}".encode()).hexdigest(),
                category="index_files", producer="repo_index", limit=file_count_limit,
                unit="files", action="skipped_remaining_files"))
            scopes.append("repo_index.index_files")
        if count_exceeded:
            identity = ["resource-limit/1.0", "repo_index", "index_files",
                        "aggregate", file_count_limit, None]
            event_id = hashlib.sha256(
                json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()
            ).hexdigest()
            resource_events.append(ResourceLimitEvent(
                event_id=event_id,
                category="index_files",
                producer="repo_index",
                limit=file_count_limit,
                unit="files",
                action="skipped_remaining_files",
                observed_files=skipped_over_count or None,
            ))
            scopes.append("repo_index.index_files")
        repo_index = cls(root=root_path, files=tuple(files), limitations=tuple(limitations),
                         resource_limit_events=tuple(resource_events),
                         resource_limit_scopes=tuple(dict.fromkeys(scopes)),
                         resource_limit_reporting="complete",
                         snapshot=snapshot, sources=tuple(sources))
        # C33/AM047: this thread's whole-repo passes resolve content for this
        # root through the freshest captured snapshot (lookups are root-gated).
        set_pinned_index(repo_index)
        return repo_index


@dataclass(frozen=True)
class PassSources:
    """Snapshot-pinned content view for one whole-repo pass (C33/AM047).

    A pass keeps its depth caps and skip sets, but both enumeration and content
    resolve through the captured index, so a mid-run edit cannot change its
    input. A file the index
    never captured reads as missing (``None``): it is outside the analyzed
    snapshot (added mid-run, or rejected by the index acceptance policy), so
    the pass skips it exactly as it skips an unreadable file today. With no
    index pinned every call falls back to the live read it always did.
    """

    root: Path
    index: RepoIndex | None

    @classmethod
    def for_root(cls, root: str | Path, index: RepoIndex | None = None) -> PassSources:
        """Explicit index when it matches ``root``, else the ambient pin for it."""
        root_path = Path(root).resolve()
        resolved = index if index is not None and Path(index.root) == root_path else None
        if resolved is None:
            resolved = active_index_for(root_path)
        return cls(root=root_path, index=resolved)

    @property
    def pinned(self) -> bool:
        return self.index is not None

    def iter_files(self, *, prune: Callable[[str], bool] | None = None) -> Iterator[Path]:
        """Enumerate captured files in capture order; no live tree reads when pinned."""
        if self.index is None:
            yield from walk_repo(self.root, prune=prune)
            return
        entries = dict.fromkeys([source.rel for source in self.index.sources] + [item.rel for item in self.index.files])
        for relative in entries:
            if prune is None or not any(prune(part) for part in Path(relative).parts[:-1]):
                yield self.root / relative

    def children(self, directory: Path) -> tuple[Path, ...]:
        if self.index is None:
            return tuple(directory.iterdir())
        try:
            prefix = directory.relative_to(self.root)
        except ValueError:
            return ()
        return tuple(self.root / rel for rel in self.index.directory_children.get(prefix.as_posix(), ()))

    def is_dir(self, path: Path) -> bool:
        if self.index is None:
            return path.is_dir()
        if path == self.root:
            return True
        try:
            relative = path.relative_to(self.root).as_posix()
        except ValueError:
            return False
        return relative in self.index.directory_children

    def is_file(self, path: Path) -> bool:
        if self.index is None:
            return path.is_file()
        try:
            relative = path.relative_to(self.root).as_posix()
            return self.index.get(relative) is not None or relative in self.index.sources_by_rel
        except ValueError:
            return False

    def unsafe(self, path: Path) -> bool:
        if self.index is not None:
            return not (self.is_file(path) or self.is_dir(path))
        from attackmap.foundation.safe_fs import is_unsafe_link
        return is_unsafe_link(self.root, path)

    def text(self, path: Path, *, errors: str = "strict") -> str | None:
        """Text for an enumerated absolute path: captured when the file is in
        the snapshot, else the live read (``None`` on OSError / not captured)."""
        if self.index is None:
            try:
                return path.read_text(encoding="utf-8", errors=errors)
            except OSError:
                return None
        try:
            rel = path.relative_to(self.root).as_posix()
        except ValueError:
            return None
        item = self.index.get(rel)
        if item is not None:
            return item.text
        source = self.index.sources_by_rel.get(rel)
        if source is None:
            return None
        return source.raw.decode("utf-8", errors=errors).replace("\r\n", "\n").replace("\r", "\n")

    def gated_text(self, rel: str, *, max_bytes: int, errors: str = "ignore") -> str | None:
        """Size-gated text for a repo-relative path. The size gate uses the
        *captured* size when pinned (IndexedFile.size) and the live stat
        otherwise — metadata stays faithful to whichever basis supplies the
        content."""
        if self.index is not None:
            item = self.index.get(rel)
            if item is not None:
                return item.text if item.size <= max_bytes else None
            source = self.index.sources_by_rel.get(rel)
            if source is None or source.size > max_bytes:
                return None
            return source.raw.decode("utf-8", errors=errors).replace("\r\n", "\n").replace("\r", "\n")
        path = contained_file(self.root, rel)
        if path is None:
            return None
        try:
            if path.stat().st_size > max_bytes:
                return None
            return path.read_text(encoding="utf-8", errors=errors)
        except OSError:
            return None

    def exists(self, rel: str) -> bool:
        """Existence on the same captured basis as content; never discover
        a newly created lockfile through an implicit live fallback."""
        if self.index is not None:
            return self.index.get(rel) is not None or rel in self.index.sources_by_rel
        try:
            return (self.root / rel).is_file()
        except OSError:
            return False

    def oversized(self, path: Path) -> bool:
        """Per-file byte-cap gate: the captured size when the file is part of
        the snapshot, the live size otherwise."""
        if self.index is not None:
            try:
                item = self.index.get(path.relative_to(self.root).as_posix())
            except ValueError:
                return True
            source = self.index.sources_by_rel.get(path.relative_to(self.root).as_posix())
            size = item.size if item is not None else source.size if source is not None else None
            return size is None or size > max_file_bytes()
        return is_oversized(path)

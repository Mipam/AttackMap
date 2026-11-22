"""Ambient pinned repository-index lookups (AR030 foundation home).

AR026/AC-106: this ContextVar is deliberate and documented. The pipeline
threads its own captured index explicitly (``analyze_repository(index=...)``
and translation), but analyzer passes, plugin pass registries and the SDK
surface (``PassSources.for_root``, ``sdk/fs.py``) resolve content through
the ambient pin because their contracts accept no index parameter — a
library boundary that makes removing the ContextVar unavoidable without
redesigning the analyzer pass contract. Lookups are root-gated and
per-thread; a newer build for the same root wins.

The pin lives in ``foundation`` so the SDK read helpers (an import island)
can consult it without reaching into extraction; ``extraction.index``
imports these functions back and re-exports them for one release. The
pinned object is an extraction-layer ``RepoIndex`` used structurally
(``root`` / ``sources``), which is why the annotation is a structural
Protocol rather than a real type.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from threading import Lock
from typing import Protocol


class PinnedIndex(Protocol):
    """Structural view of the pinned index (AR030).

    Foundation must not import the extraction-layer ``RepoIndex`` type, so
    the pin is typed by the attributes its consumers actually read.
    """

    root: Path
    sources: Sequence[object]


_PINNED: ContextVar[PinnedIndex | None] = ContextVar("attackmap_pinned_index", default=None)
_PROCESS_SNAPSHOT: PinnedIndex | None = None
_PROCESS_SNAPSHOT_LOCK = Lock()


def install_process_snapshot(index: PinnedIndex) -> None:
    """Dedicated isolated-worker bootstrap only; pin persists through thread shutdown."""
    global _PROCESS_SNAPSHOT
    with _PROCESS_SNAPSHOT_LOCK:
        if _PROCESS_SNAPSHOT is not None and _PROCESS_SNAPSHOT is not index:
            raise ValueError("An isolated worker cannot replace its installed snapshot")
        _PROCESS_SNAPSHOT = index


def set_pinned_index(index: PinnedIndex) -> None:
    """Install this thread's pin (``RepoIndex.build`` pins what it built)."""
    _PINNED.set(index)


def pinned_repo_index() -> PinnedIndex | None:
    """The index pinned for this thread by the latest repo-index build."""
    return _PROCESS_SNAPSHOT if _PROCESS_SNAPSHOT is not None else _PINNED.get()


def active_index_for(root: str | Path) -> PinnedIndex | None:
    """The pinned index for exactly ``root`` (another repo's pin never applies)."""
    index = pinned_repo_index()
    if index is None:
        return None
    try:
        return index if index.root == Path(root).resolve() else None
    except OSError:
        return None


def clear_pinned_index() -> None:
    """Drop this thread's pin (the pipeline resets it once a run completes)."""
    _PINNED.set(None)


@contextmanager
def pinned_index_scope(index: PinnedIndex):
    """Temporarily install an already verified capture, including during plugin import."""
    token = _PINNED.set(index)
    try:
        yield index
    finally:
        _PINNED.reset(token)


__all__ = [
    "PinnedIndex",
    "active_index_for",
    "clear_pinned_index",
    "install_process_snapshot",
    "pinned_index_scope",
    "pinned_repo_index",
    "set_pinned_index",
]

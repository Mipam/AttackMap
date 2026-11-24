"""PDF export behind an explicit browser backend protocol (AC-312).

The GUI export pipeline renders a tab to HTML and asks a headless browser to
print it to PDF. This module owns that browser invocation as a small protocol
(:class:`PdfBackend`) with Chrome and Edge implementations, availability
detection, and typed errors so callers never see a bare ``FileNotFoundError``
or ``RuntimeError("Chrome or Edge not found")`` leak.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Protocol, runtime_checkable

from attackmap.foundation.errors import AttackMapError

# Mirrors the invocation previously inline in api/artifacts.py so the
# protocol path produces byte-equivalent PDFs once wired in.
_PRINT_FLAGS = ("--headless", "--disable-gpu", "--no-pdf-header-footer")
_RENDER_TIMEOUT_S = 60

# Minimal/embedded environments may not define the PROGRAMFILES variables at
# all; always cover the standard install roots in addition to the env vars.
_STANDARD_ROOTS = (r"C:\Program Files (x86)", r"C:\Program Files")


class PdfUnavailable(AttackMapError, RuntimeError):
    """No supported PDF backend (browser) is available on this host."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class PdfRenderError(AttackMapError, RuntimeError):
    """A backend was selected but the browser invocation failed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@runtime_checkable
class PdfBackend(Protocol):
    """A browser capable of printing HTML to a PDF file."""

    name: str
    executable: Path

    def render(self, html: str, out: Path) -> None:
        """Write ``html`` printed to PDF at ``out``."""
        ...


def _candidate_paths(executable: str, relative: str) -> list[Path]:
    roots = [
        os.environ.get("PROGRAMFILES(X86)", ""),
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("PROGRAMFILES", ""),
        *_STANDARD_ROOTS,
    ]
    seen: set[str] = set()
    paths: list[Path] = []
    for root in roots:
        if root:
            candidate = Path(root) / relative
            key = str(candidate).lower()
            if key not in seen:
                seen.add(key)
                paths.append(candidate)
    on_path = shutil.which(executable)
    if on_path:
        paths.append(Path(on_path))
    return paths


class _HeadlessBrowserBackend:
    """Shared headless ``--print-to-pdf`` implementation."""

    name = "browser"
    _executable_name = ""
    _relative_path = ""

    def __init__(self, executable: Path) -> None:
        self.executable = Path(executable)

    @classmethod
    def candidates(cls) -> list[Path]:
        return _candidate_paths(cls._executable_name, cls._relative_path)

    @classmethod
    def available(cls) -> _HeadlessBrowserBackend | None:
        for candidate in cls.candidates():
            if candidate.is_file():
                return cls(candidate)
        return None

    def render(self, html: str, out: Path) -> None:
        out = Path(out)
        fd, tmp_name = tempfile.mkstemp(
            prefix="._attackmap_export_", suffix=".html", dir=out.parent
        )
        os.close(fd)
        tmp_html = Path(tmp_name)
        try:
            tmp_html.write_text(html, encoding="utf-8")
            self._print(tmp_html, out)
        finally:
            with suppress(OSError):
                tmp_html.unlink()
        if not out.is_file() or out.stat().st_size == 0:
            raise PdfRenderError(
                f"{self.name} ({self.executable}) produced no PDF at {out}"
            )

    def _print(self, tmp_html: Path, out: Path) -> None:
        cmd = [
            str(self.executable),
            *_PRINT_FLAGS,
            f"--print-to-pdf={out}",
            str(tmp_html),
        ]
        try:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_RENDER_TIMEOUT_S,
            )
        except FileNotFoundError as exc:
            raise PdfUnavailable(
                f"{self.name} executable disappeared: {self.executable}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PdfRenderError(
                f"{self.name} did not finish printing within {_RENDER_TIMEOUT_S}s"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise PdfRenderError(
                f"{self.name} exited with code {exc.returncode} while printing {out}"
            ) from exc


class ChromeBackend(_HeadlessBrowserBackend):
    """Google Chrome headless PDF backend."""

    name = "chrome"
    _executable_name = "chrome.exe"
    _relative_path = "Google/Chrome/Application/chrome.exe"


class EdgeBackend(_HeadlessBrowserBackend):
    """Microsoft Edge headless PDF backend."""

    name = "edge"
    _executable_name = "msedge.exe"
    _relative_path = "Microsoft/Edge/Application/msedge.exe"


def detect_backends() -> list[PdfBackend]:
    """Return available backends, Edge first (matches legacy picker order)."""
    found: list[PdfBackend] = []
    for backend_type in (EdgeBackend, ChromeBackend):
        backend = backend_type.available()
        if backend is not None:
            found.append(backend)
    return found


def default_backend() -> PdfBackend | None:
    """Return the preferred available backend, or ``None`` if none exists."""
    backends = detect_backends()
    return backends[0] if backends else None


def render_html_to_pdf(html: str, out: Path, backend: PdfBackend | None = None) -> None:
    """Render ``html`` to a PDF at ``out`` via an explicit backend.

    Raises :class:`PdfUnavailable` with a human-readable reason when no
    supported browser exists, and :class:`PdfRenderError` when a selected
    backend fails. Never leaks a bare ``OSError``/``FileNotFoundError``.
    """
    selected = backend if backend is not None else default_backend()
    if selected is None:
        checked = [str(p) for t in (EdgeBackend, ChromeBackend) for p in t.candidates()]
        raise PdfUnavailable(
            "PDF export needs Google Chrome or Microsoft Edge, but neither was "
            "found. Checked: " + (", ".join(checked) if checked else "no candidate paths")
        )
    selected.render(html, out)

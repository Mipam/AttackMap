"""Tests for the PDF export backend protocol (AC-312)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from attackmap.foundation.errors import AttackMapError
from attackmap.surfaces.ui.export import pdf
from attackmap.surfaces.ui.export.pdf import (
    ChromeBackend,
    PdfBackend,
    PdfRenderError,
    PdfUnavailable,
    default_backend,
    detect_backends,
    render_html_to_pdf,
)
from attackmap.surfaces.ui.export_md import render_pdf, render_view_markdown

HTML = "<!DOCTYPE html><html><body><h1>Report</h1><p>hi</p></body></html>"


def _fake_browser(tmp_path: Path, name: str, relative: str) -> Path:
    exe = tmp_path / relative
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"MZ fake")
    return exe


@pytest.fixture
def only_chrome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point every install-root source at an empty dir; add a fake Chrome."""
    _isolate_browser_roots(tmp_path, monkeypatch)
    return _fake_browser(tmp_path, "chrome", "pf/Google/Chrome/Application/chrome.exe")


@pytest.fixture
def no_browsers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every install-root source at an empty dir so nothing is found."""
    _isolate_browser_roots(tmp_path, monkeypatch)


def _isolate_browser_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "pf"))
    monkeypatch.setenv("PROGRAMFILES(x86)", str(tmp_path / "pf86"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.delenv("PATH", raising=False)  # defeat shutil.which fallback
    monkeypatch.setattr(pdf, "_STANDARD_ROOTS", ())  # and the hardcoded roots


class FakeBackend:
    """In-memory PdfBackend implementation that records its inputs."""

    name = "fake"
    executable = Path("fake-browser")

    def __init__(self) -> None:
        self.calls: list[tuple[str, Path]] = []

    def render(self, html: str, out: Path) -> None:
        self.calls.append((html, Path(out)))
        Path(out).write_bytes(b"%PDF-fake")


# --------------------------------------------------------------------------
# Protocol + detection
# --------------------------------------------------------------------------


def test_pdf_backend_is_a_runtime_checkable_protocol() -> None:
    assert isinstance(FakeBackend(), PdfBackend)


def test_detection_finds_fake_chrome(only_chrome: Path) -> None:
    backends = detect_backends()
    assert [b.name for b in backends] == ["chrome"]
    assert backends[0].executable == only_chrome
    assert default_backend() is not None


def test_detection_prefers_edge_over_chrome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_browser_roots(tmp_path, monkeypatch)
    edge = _fake_browser(tmp_path, "edge", "pf/Microsoft/Edge/Application/msedge.exe")
    chrome = _fake_browser(tmp_path, "chrome", "pf/Google/Chrome/Application/chrome.exe")
    backends = detect_backends()
    assert [b.name for b in backends] == ["edge", "chrome"]
    assert backends[0].executable == edge
    assert backends[1].executable == chrome
    assert default_backend().executable == edge  # matches legacy picker order


def test_no_browser_found_returns_none(no_browsers: None) -> None:
    assert detect_backends() == []
    assert default_backend() is None


# --------------------------------------------------------------------------
# Typed error path (AC-312: never a bare OSError / FileNotFoundError)
# --------------------------------------------------------------------------


def test_unavailable_raises_typed_error_with_reason(no_browsers: None, tmp_path: Path) -> None:
    with pytest.raises(PdfUnavailable) as exc_info:
        render_html_to_pdf(HTML, tmp_path / "out.pdf")
    reason = str(exc_info.value)
    assert "Chrome" in reason and "Edge" in reason
    assert str(exc_info.value) == exc_info.value.reason


def test_unavailable_is_typed_not_bare_oserror(no_browsers: None, tmp_path: Path) -> None:
    with pytest.raises(PdfUnavailable) as exc_info:
        render_html_to_pdf(HTML, tmp_path / "out.pdf")
    err = exc_info.value
    assert isinstance(err, AttackMapError)
    assert isinstance(err, RuntimeError)
    assert not isinstance(err, OSError)
    assert not isinstance(err, FileNotFoundError)


def test_render_pdf_entry_raises_same_typed_error(
    no_browsers: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """export_md.render_pdf must surface the typed error, not a bare crash."""
    monkeypatch.setattr(pdf, "detect_backends", lambda: [])
    with pytest.raises(PdfUnavailable, match="Chrome"):
        render_pdf(HTML, tmp_path / "out.pdf")


# --------------------------------------------------------------------------
# Explicit backend plumbing
# --------------------------------------------------------------------------


def test_explicit_backend_receives_html_and_out(tmp_path: Path) -> None:
    backend = FakeBackend()
    out = tmp_path / "out.pdf"
    render_html_to_pdf(HTML, out, backend=backend)
    assert backend.calls == [(HTML, out)]
    assert out.read_bytes() == b"%PDF-fake"


def test_render_pdf_delegates_to_protocol(tmp_path: Path) -> None:
    backend = FakeBackend()
    out = tmp_path / "out.pdf"
    render_pdf(HTML, out, backend=backend)
    assert backend.calls == [(HTML, out)]


def test_missing_output_raises_render_error(tmp_path: Path) -> None:
    """A backend that exits 0 but writes nothing must raise PdfRenderError."""
    backend = ChromeBackend(Path(sys.executable))
    with pytest.raises(PdfRenderError):
        backend.render(HTML, tmp_path / "out.pdf")


# --------------------------------------------------------------------------
# Real render (skipped when no browser on the host) + markdown path preserved
# --------------------------------------------------------------------------


def _markdown_to_html(markdown: str) -> str:
    from html import escape

    body = "\n".join(
        f"<p>{escape(line)}</p>" if line and not line.startswith("<") else line
        for line in markdown.splitlines()
    )
    return f'<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>{body}</body></html>'


@pytest.mark.skipif(default_backend() is None, reason="no Chrome/Edge on this host")
def test_real_render_produces_readable_pdf(tmp_path: Path) -> None:
    report = {
        "findingCount": 1,
        "severityCounts": {"high": 1},
        "findings": [
            {
                "title": "SQL injection in search",
                "severity": "high",
                "locations": [{"file": "src/app.js", "line": 42}],
                "evidence": ["db.query(userInput)"],
                "mitigation": "Use parameterized queries.",
            }
        ],
    }
    markdown = render_view_markdown("findings", report, repo_name="demo-repo")
    assert markdown.startswith("# Findings")
    out = tmp_path / "attackmap-demo-findings.pdf"
    render_pdf(_markdown_to_html(markdown), out)
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 500
    import re

    page_objects = len(re.findall(rb"/Type\s*/Page[^s]", data))
    assert page_objects > 0, "expected at least one page object in the PDF"


def test_markdown_export_path_untouched(tmp_path: Path) -> None:
    """The .md export contract is unchanged by the PDF protocol work."""
    from attackmap.surfaces.ui.export_md import SUPPORTED_SUFFIXES

    assert {".md", ".pdf"} == SUPPORTED_SUFFIXES
    markdown = render_view_markdown("surface", {"attackSurfaces": []}, repo_name="demo")
    assert "Attack surface" in markdown

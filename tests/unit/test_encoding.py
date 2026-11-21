"""Encoding integrity guard (AR005, AC-008).

No U+FFFD (REPLACEMENT CHARACTER) may appear in shipped source, prompt
templates, or packaging metadata. A U+FFFD there means a mojibake round-trip
happened somewhere — usually a Windows-1252 file was read as UTF-8 or a
copy/paste mangled an en dash. The character never belongs in those files, so
the guard fails loudly instead of letting mangled prose or regex reach
prompts that the LLM layer sends verbatim to the model.
"""

from __future__ import annotations

import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
REPLACEMENT = "\ufffd"


def _candidate_files() -> list[pathlib.Path]:
    files = sorted((REPO_ROOT / "src").rglob("*.py"))
    files.append(REPO_ROOT / "pyproject.toml")
    return files


def test_no_replacement_character_in_source_and_metadata() -> None:
    bad: list[str] = []
    for path in _candidate_files():
        text = path.read_text(encoding="utf-8", errors="strict")
        if REPLACEMENT in text:
            line_no = text.count("\n", 0, text.index(REPLACEMENT)) + 1
            bad.append(f"{path.relative_to(REPO_ROOT)}:{line_no}")
    assert not bad, f"U+FFFD found in {bad}; repair the mojibake at the source"


def test_source_decodes_strictly_as_utf8() -> None:
    """Every shipped .py must be valid UTF-8; no cp1252 round-trip debris."""
    for path in sorted((REPO_ROOT / "src").rglob("*.py")):
        try:
            path.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise AssertionError(f"{path} is not valid UTF-8: {exc}") from exc

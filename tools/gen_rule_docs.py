"""Generate the rule reference docs from the kernel REGISTRY (AR046).

One Markdown page per registered rule under ``docs/reference/rules/<rule_id>.md``
(id, title, CWE, severity, confidence, rationale, tags, taxonomy enrichment and
the legacy detector-id mapping recorded on the rule) plus an ``index.md``
grouped by category (each rule's first ``RuleMeta.tags`` entry). Output is
deterministic — everything is sorted by id — so CI can diff it:

    python tools/gen_rule_docs.py           # (re)write the pages
    python tools/gen_rule_docs.py --check   # exit 1 when pages would change

The pages are generated artifacts: edit ``RuleMeta`` in the rule modules and
re-run the generator, never edit the Markdown by hand.
"""
from __future__ import annotations

import argparse
import inspect
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOCS_DIR = REPO_ROOT / "docs" / "reference" / "rules"


def _load_registry():
    """The populated kernel registry (importing the package registers every rule)."""
    if str(REPO_ROOT / "src") not in sys.path:
        sys.path.insert(0, str(REPO_ROOT / "src"))
    from attackmap.reasoning.rules import REGISTRY

    return REGISTRY


def _or_dash(value: str) -> str:
    return value if value else "-"


def _taxonomy_rows(rule) -> list[str]:
    """Table rows for the CWE/OWASP/ASVS/ATT&CK enrichment that auto-attaches
    to the rule's findings (empty rows for unregistered ids are omitted)."""
    from attackmap.model.taxonomy import attack_url, taxonomy_for

    entry = taxonomy_for(rule.meta.id)
    rows: list[str] = [f"| CWE | {_or_dash(rule.meta.cwe)} |"]
    if entry is None:
        return rows
    owasp_asvs = " · ".join([*entry.owasp, *entry.asvs])
    rows.append(f"| OWASP / ASVS | {owasp_asvs} |")
    attack = ", ".join(f"[{tid}]({attack_url(tid)})" for tid in entry.attack)
    rows.append(f"| ATT&CK | {attack or '-'} |")
    return rows


def render_rule_page(rule) -> str:
    """The Markdown reference page for one registered rule."""
    from attackmap.reasoning.rules.base import confidence_band

    meta = rule.meta
    legacy = tuple(getattr(rule, "legacy_rule_ids", ()))
    lines = [
        f"# `{meta.id}`",
        "",
        meta.title,
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Severity | {meta.severity} |",
        f"| Confidence | {meta.confidence} ({confidence_band(meta.confidence)} band) |",
        *_taxonomy_rows(rule),
        f"| Tags | {_or_dash(', '.join(meta.tags))} |",
        f"| Replaces legacy detector ids | {_or_dash(', '.join(legacy))} |",
        "",
        "## Why this rule fires",
        "",
        meta.rationale,
    ]
    doc = inspect.getdoc(rule)
    if doc:
        lines += ["", "## Evidence expectations", "", doc]
    return "\n".join(lines) + "\n"


def render_index(rules: tuple) -> str:
    """The category-grouped index over all registered rules (sorted)."""
    from attackmap.reasoning.rules.base import confidence_band

    by_category: dict[str, list] = {}
    for rule in rules:
        category = rule.meta.tags[0] if rule.meta.tags else "uncategorized"
        by_category.setdefault(category, []).append(rule)
    lines = [
        "# Rule reference",
        "",
        f"Generated from the kernel rule registry (`attackmap.reasoning.rules.REGISTRY`) by "
        f"`tools/gen_rule_docs.py` — {len(rules)} rules. Generated artifact: do not edit by hand, run",
        "",
        "    python tools/gen_rule_docs.py",
        "",
    ]
    for category in sorted(by_category):
        lines += [f"## {category}", "", "| Rule | Severity | Confidence | Title |", "| --- | --- | --- | --- |"]
        for rule in sorted(by_category[category], key=lambda r: r.meta.id):
            lines.append(
                f"| [`{rule.meta.id}`]({rule.meta.id}.md) | {rule.meta.severity} | "
                f"{confidence_band(rule.meta.confidence)} | {rule.meta.title} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def generate(docs_dir: Path) -> dict[str, str]:
    """Every generated file keyed by its path relative to ``docs_dir``."""
    registry = _load_registry()
    rules = registry.all_rules()
    pages = {f"{rule.meta.id}.md": render_rule_page(rule) for rule in rules}
    pages["index.md"] = render_index(rules)
    return pages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit non-zero when the generated content would differ from disk.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_DOCS_DIR,
        help=f"Target directory (default: {DEFAULT_DOCS_DIR}).",
    )
    args = parser.parse_args()
    docs_dir: Path = args.output_dir
    pages = generate(docs_dir)

    if args.check:
        problems: list[str] = []
        for name, expected in sorted(pages.items()):
            path = docs_dir / name
            if not path.exists():
                problems.append(f"{name}: missing")
                continue
            # Checkouts may carry CRLF (text files, core.autocrlf); the repo
            # content itself is LF, so compare newline-normalized.
            actual = path.read_text(encoding="utf-8").replace("\r\n", "\n")
            if actual != expected:
                problems.append(f"{name}: differs")
        for path in sorted(docs_dir.glob("*.md")):
            if path.name not in pages:
                problems.append(f"{path.name}: not generated by the current registry (stale page)")
        if problems:
            print(f"gen_rule_docs: {len(problems)} file(s) out of date in {docs_dir}:")
            for problem in problems:
                print(f"  {problem}")
            print("Run `python tools/gen_rule_docs.py` to regenerate, then commit.")
            return 1
        print(f"gen_rule_docs: {len(pages)} file(s) up to date in {docs_dir}")
        return 0

    docs_dir.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(pages.items()):
        (docs_dir / name).write_text(content, encoding="utf-8", newline="\n")
    stale = [path.name for path in sorted(docs_dir.glob("*.md")) if path.name not in pages]
    for name in stale:
        (docs_dir / name).unlink()
    print(f"gen_rule_docs: wrote {len(pages)} file(s) to {docs_dir}" + (f" (removed {len(stale)} stale)" if stale else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

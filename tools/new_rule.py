"""Scaffold a new reasoning rule: rule module + focused test file (AR087).

``tools/new_rule.py --id my_new_rule`` creates two files, each full of
placeholders and TODO(author) guidance:

* a rule module under ``src/attackmap/reasoning/rules/`` (default
  ``<id>.py``) with a ``RuleMeta``-carrying class whose ``evaluate()``
  raises ``NotImplementedError`` — the ``REGISTRY.register(...)`` line is
  deliberately commented out so a scaffolded-but-unfinished rule can never
  register and silently ride along in ``evaluate_all`` (where the registry
  would report it as a broken rule on every scan);
* a focused test file (default ``tests/rules/test_<id>.py``) wired for the
  AR047 harness, with the ``@pytest.mark.rule("<id>")`` marks commented out
  until the rule actually registers (an active mark naming an unregistered
  id fails the stale-marker check in ``tests/rules/test_rule_coverage.py``).

The tool is stdlib-only plus the kernel rules package (for the duplicate
check against ``REGISTRY``); it never imports typer or any surface module.
It prints exactly what it created and the next steps.

Validation performed up front, before anything is written:

* ``--id`` must match ``^[a-z][a-z0-9_]*$`` (the ``RuleMeta`` stable-id
  contract in ``src/attackmap/reasoning/rules/base.py``);
* ``--id`` must not already be registered;
* target files must not exist (pass ``--force`` to overwrite).

Examples
--------
Scaffold into the repo (the normal author flow)::

    .venv/Scripts/python.exe tools/new_rule.py --id my_new_rule

Scaffold into a scratch directory (try-it-out flow; nothing in the repo
is touched)::

    .venv/Scripts/python.exe tools/new_rule.py --id demo_rule ^
        --rules-dir C:/tmp/attackmap-scratch/rules ^
        --test C:/tmp/attackmap-scratch/test_demo_rule.py
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
DEFAULT_RULES_DIR = SRC_DIR / "attackmap" / "reasoning" / "rules"
DEFAULT_TESTS_DIR = REPO_ROOT / "tests" / "rules"

RULE_ID_RE = re.compile(r"[a-z][a-z0-9_]*")

RULE_MODULE_TEMPLATE = '''"""Rules for <ID>: <TODO(author): one-line family summary>.

<TODO(author): describe which ReasoningContext slice(s) this family reasons
over and why the signal matters. See docs/contributing/rules.md and the
slice list in src/attackmap/reasoning/context.py.>
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...model import Finding, FindingLocation
from .base import RuleMeta
from .registry import REGISTRY

if TYPE_CHECKING:
    from ..context import ReasoningContext

__all__ = ["<CLASS_NAME>"]


class <CLASS_NAME>:
    """<TODO(author): what the rule detects, stated so a finding is explainable.>"""

    meta = RuleMeta(
        id="<ID>",
        title="<TODO(author): finding title, one sentence, no ids in prose>",
        cwe="<TODO(author): e.g. CWE-798; must agree with the RULE_TAXONOMY entry>",
        severity="medium",  # TODO(author): "high" | "medium" | "low"
        confidence=0.5,  # TODO(author): the rule's trust in its detection, 0.0-1.0
        rationale=(
            "<TODO(author): why the rule exists — this text lands on every "
            "finding the rule emits, so it must explain the risk, not restate "
            "the title.>"
        ),
        tags=("uncategorized",),  # TODO(author): first tag groups the docs index category
    )
    # Porting a legacy cascade branch? Record the dashed id(s) it replaces so
    # the generated docs page shows the mapping:
    # legacy_rule_ids = ("<legacy-dashed-id>",)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        """<TODO(author): evidence expectations — the class docstring and this
        method's docstring render into the generated reference page.>"""
        raise NotImplementedError(
            "<ID>: scaffolded by tools/new_rule.py — implement evaluate() against "
            "ReasoningContext, then uncomment REGISTRY.register below and add the "
            "module import to src/attackmap/reasoning/rules/__init__.py."
        )
        # Findings must carry rule_id=self.meta.id and one FindingLocation per
        # distinct (file, line) behind the evidence; see the Finding contract
        # in docs/contributing/rules.md.


# TODO(author): uncomment once evaluate() is implemented. A rule whose
# evaluate() raises must never register: the registry would then report it as
# a broken rule (RuleEvaluationError) on every scan.
# REGISTRY.register(<CLASS_NAME>())
'''

TEST_MODULE_TEMPLATE = '''"""Focused tests for the ``<ID>`` rule (scaffolded by tools/new_rule.py).

Copy the commented-out ``@pytest.mark.rule("<ID>")`` marks onto the tests once
the rule registers: an active mark naming an unregistered id fails the
stale-marker check (tests/rules/test_rule_coverage.py). Until then these
stubs fail loudly on purpose — a scaffolded rule is work in progress and the
suite must say so.

Fixtures are built in code (ScanResult / ReasoningContext), never read from
disk; see docs/contributing/rules.md and the helpers in tests/rules/_harness.py.
"""

from __future__ import annotations

import pytest

from _harness import assert_rule_negative, assert_rule_positive

pytestmark = [pytest.mark.unit]

# TODO(author): positive fixture — a ScanResult (or ReasoningContext) holding
# exactly the observation records this rule fires on.
# POSITIVE_FIXTURE = ScanResult(root="", ...)
#
# TODO(author): negative fixture — the near-miss that must stay silent.
# NEGATIVE_FIXTURE = ScanResult(root="", ...)


# @pytest.mark.rule("<ID>")
def test_<ID>_fires():
    # TODO(author): rename the test after the signal it pins, then:
    # findings = assert_rule_positive("<ID>", POSITIVE_FIXTURE)
    pytest.fail("TODO(author): implement evaluate(), register the rule, then "
                "assert_rule_positive('<ID>', POSITIVE_FIXTURE)")


# @pytest.mark.rule("<ID>")
def test_<ID>_stays_silent():
    # TODO(author): rename the test after the near-miss it guards, then:
    # assert_rule_negative("<ID>", NEGATIVE_FIXTURE, reason="...")
    pytest.fail("TODO(author): then assert_rule_negative('<ID>', NEGATIVE_FIXTURE, "
                "reason='<why this boundary must not fire>')")
'''


def _load_registry():
    """The populated kernel registry, so ``--id`` can be checked for duplicates."""
    if str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))
    from attackmap.reasoning.rules import REGISTRY

    return REGISTRY


def _class_name(rule_id: str) -> str:
    """``my_new_rule`` -> ``MyNewRule`` (a ``Rule`` suffix reads better in docs)."""
    name = "".join(part.capitalize() for part in rule_id.split("_") if part)
    return name if name.endswith("Rule") else f"{name}Rule"


def _render(template: str, rule_id: str) -> str:
    return template.replace("<ID>", rule_id).replace("<CLASS_NAME>", _class_name(rule_id))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See docs/contributing/rules.md for the full authoring walkthrough.",
    )
    parser.add_argument("--id", required=True, help="stable snake_case rule id (^[a-z][a-z0-9_]*$)")
    parser.add_argument(
        "--module",
        help="rule module name inside the rules package (default: the id); the file <name>.py is created under --rules-dir",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help=f"directory for the rule module (default: {DEFAULT_RULES_DIR})",
    )
    parser.add_argument(
        "--test",
        type=Path,
        help=f"focused test file to create (default: {DEFAULT_TESTS_DIR}/test_<id>.py)",
    )
    parser.add_argument("--force", action="store_true", help="overwrite existing target files")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rule_id = args.id

    if not RULE_ID_RE.fullmatch(rule_id):
        print(
            f"error: rule id {rule_id!r} must match ^[a-z][a-z0-9_]*$ "
            "(stable, suppressible ids: lowercase snake_case, no dashes/uppercase)",
            file=sys.stderr,
        )
        return 2
    registry = _load_registry()
    if rule_id in registry:
        print(f"error: rule id {rule_id!r} is already registered in the kernel REGISTRY", file=sys.stderr)
        return 2

    module_name = args.module or rule_id
    if not module_name.isidentifier():
        print(f"error: --module {module_name!r} is not a valid Python module name", file=sys.stderr)
        return 2

    module_path = args.rules_dir / f"{module_name}.py"
    test_path = args.test or (DEFAULT_TESTS_DIR / f"test_{rule_id}.py")

    targets = {"rule module": module_path, "focused test": test_path}
    if not args.force:
        existing = [f"{label} {path}" for label, path in targets.items() if path.exists()]
        if existing:
            for line in existing:
                print(f"error: {line} already exists (pass --force to overwrite)", file=sys.stderr)
            return 2

    module_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.parent.mkdir(parents=True, exist_ok=True)
    module_path.write_text(_render(RULE_MODULE_TEMPLATE, rule_id), encoding="utf-8", newline="\n")
    test_path.write_text(_render(TEST_MODULE_TEMPLATE, rule_id), encoding="utf-8", newline="\n")

    print(f"created rule module:  {module_path}")
    print(f"created focused test: {test_path}")
    print("next steps:")
    print(f"  1. implement evaluate() in {module_path.name} (the NotImplementedError body lists the contract)")
    print(f"  2. register: uncomment REGISTRY.register(...) in {module_path.name} and import the module")
    print("     from src/attackmap/reasoning/rules/__init__.py")
    print("  3. add the RULE_TAXONOMY entry in src/attackmap/model/taxonomy.py (CWE/OWASP/ATT&CK enrichment)")
    print(f"  4. fill in the tests, activate the @pytest.mark.rule(\"{rule_id}\") marks, then:")
    print(f"       .venv/Scripts/python.exe -m pytest {test_path} -v")
    print("       .venv/Scripts/python.exe -m pytest tests/rules -q")
    print("  5. regenerate the reference docs:")
    print("       .venv/Scripts/python.exe tools/gen_rule_docs.py")
    print("  6. follow docs/contributing/rules.md for the full walkthrough")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

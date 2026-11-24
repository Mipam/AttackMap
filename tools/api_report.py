"""API surface report and gate for the GUI server (AR063 / AC-305).

Verifies, in BOTH directions, that the ``/api/*`` surface is declared:

  * every ``/api/*`` route string literal in the ``surfaces/ui`` Python source
    is a registered route with a declared Pydantic request model (POST) and
    response model (all endpoints), and
  * every Pydantic model declared in ``api/schemas.py`` is referenced by at
    least one live route (no orphan schemas), and
  * the average handler length is <= 20 lines (AC-305).

Usage::

    python -m tools.api_report            # print the route/schema table
    python -m tools.api_report --check    # exit 0 when all checks pass, else 1

Stdlib + Pydantic only.
"""

from __future__ import annotations

import argparse
import inspect
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_DIR = REPO_ROOT / "src" / "attackmap" / "surfaces" / "ui"

EXPECTED_ROUTE_COUNT = 13
HANDLER_LINE_BUDGET = 20

_ROUTE_LITERAL = re.compile(r"""["'](/api/[a-z-]+)["']""")


def _registry() -> list[Any]:
    # Importing the adapter registers every @route handler as a side effect
    # (the api package itself is an acyclic graph: routes never imports the
    # handler modules, so the registry must be populated from the outside).
    import attackmap.surfaces.ui.server  # noqa: F401
    from attackmap.surfaces.ui.api.routes import all_routes

    return all_routes()


def _declared_schemas() -> dict[str, Any]:
    from attackmap.surfaces.ui.api import schemas as api_schemas

    found = {}
    for name, value in vars(api_schemas).items():
        if (
            isinstance(value, type)
            and issubclass(value, api_schemas.ApiModel)
            and value is not api_schemas.ApiModel
        ):
            found[name] = value
    return found


def _source_route_literals() -> set[str]:
    """All /api/* path string literals in the surfaces/ui Python source."""
    literals: set[str] = set()
    for path in sorted(UI_DIR.rglob("*.py")):
        for match in _ROUTE_LITERAL.finditer(path.read_text(encoding="utf-8")):
            literals.add(match.group(1))
    return literals


def handler_line_counts() -> dict[str, int]:
    """Code lines per registered handler (decorators, blanks, comments dropped)."""
    counts: dict[str, int] = {}
    for entry in _registry():
        lines, _ = inspect.getsourcelines(entry.handler)
        while lines and lines[0].lstrip().startswith("@"):
            lines.pop(0)
        code = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
        counts[f"{entry.method} {entry.path}"] = len(code)
    return counts


def collect() -> dict[str, Any]:
    routes = _registry()
    schemas = _declared_schemas()
    referenced = {
        model.__name__
        for entry in routes
        for model in (entry.request_model, entry.response_model)
        if model is not None
    }
    return {
        "routes": routes,
        "schemas": schemas,
        "referenced": referenced,
        "literals": _source_route_literals(),
        "handler_lines": handler_line_counts(),
    }


def check() -> list[str]:
    """Human-readable failure list; empty means the gate passes."""
    data = collect()
    routes = data["routes"]
    schemas = data["schemas"]
    referenced = data["referenced"]
    literals = data["literals"]
    handler_lines = data["handler_lines"]

    failures: list[str] = []
    registered = {(entry.method, entry.path) for entry in routes}
    registered_paths = {entry.path for entry in routes}

    if len(registered) != EXPECTED_ROUTE_COUNT:
        failures.append(f"expected {EXPECTED_ROUTE_COUNT} routes, registry has {len(registered)}")

    for literal in sorted(literals - registered_paths):
        failures.append(f"source literal {literal} has no registered route/schema")
    for path in sorted(registered_paths - literals):
        failures.append(f"registered route {path} has no /api/* literal in the ui source")

    for entry in routes:
        label = f"{entry.method} {entry.path}"
        if entry.response_model is None:
            failures.append(f"{label}: no response model declared")
        elif entry.response_model.__name__ not in schemas:
            failures.append(f"{label}: response model not declared in api/schemas.py")
        if entry.method == "POST" and entry.request_model is None:
            failures.append(f"{label}: no request model declared")
        if entry.request_model is not None and entry.request_model.__name__ not in schemas:
            failures.append(f"{label}: request model not declared in api/schemas.py")

    for name in sorted(set(schemas) - referenced):
        failures.append(f"schema {name} is declared but no route references it")

    if handler_lines:
        average = sum(handler_lines.values()) / len(handler_lines)
        if average > HANDLER_LINE_BUDGET:
            failures.append(
                f"average handler length {average:.1f} lines exceeds {HANDLER_LINE_BUDGET}"
            )
    else:
        failures.append("no handlers registered")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 on any drift")
    args = parser.parse_args(argv)

    data = collect()
    routes = data["routes"]
    schemas = data["schemas"]
    handler_lines = data["handler_lines"]

    request_names = {
        id(entry): (entry.request_model.__name__ if entry.request_model else "-")
        for entry in routes
    }
    for entry in sorted(routes, key=lambda e: (e.path, e.method)):
        label = f"{entry.method} {entry.path}"
        print(
            f"{entry.method:4} {entry.path:20} req={request_names[id(entry)]:16} "
            f"resp={entry.response_model.__name__:20} handler={handler_lines[label]:3} lines  {entry.summary}"
        )
    average = sum(handler_lines.values()) / len(handler_lines) if handler_lines else 0.0
    print(f"\nroutes: {len(routes)} (expected {EXPECTED_ROUTE_COUNT})")
    print(f"schemas declared: {len(schemas)}; referenced: {len(data['referenced'])}")
    print(f"average handler lines: {average:.1f} (budget {HANDLER_LINE_BUDGET})")

    if not args.check:
        return 0
    failures = check()
    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        print(f"\napi_report: FAIL ({len(failures)} problem(s))")
        return 1
    print("\napi_report: OK (every route has a schema; every schema maps to a route)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

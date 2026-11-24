"""Generate JSDoc typedefs for the GUI client from the Pydantic API schemas.

AR065 / AC-307 typed client: ``src/attackmap/surfaces/ui/api/schemas.py`` is
the single source of truth for the ``/api/*`` wire format (AR063). This tool
reflects every ``ApiModel`` subclass into a JSDoc ``@typedef`` block written to
``src/attackmap/surfaces/ui/web/src/api-types.js``, which the ES-module
frontend imports for type annotations only (the file has no runtime code).

The generator itself is stdlib-only (pydantic comes in transitively via the
schemas module, already a project dependency). ``schemas.py`` is loaded
directly by path so no package ``__init__`` side effects run.

Usage::

    python tools/gen_api_types.py            # write api-types.js
    python tools/gen_api_types.py --check    # exit 0 when the file is current

Run with the project interpreter, e.g. ``.venv/Scripts/python.exe``.
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import sys
import types as py_types
import typing
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMAS_PATH = REPO_ROOT / "src" / "attackmap" / "surfaces" / "ui" / "api" / "schemas.py"
OUTPUT_PATH = REPO_ROOT / "src" / "attackmap" / "surfaces" / "ui" / "web" / "src" / "api-types.js"

_HEADER = """/* eslint-disable */
/**
 * GENERATED FILE — do not edit by hand.
 *
 * Source of truth: src/attackmap/surfaces/ui/api/schemas.py (AR063 Pydantic
 * models, one typedef per ApiModel subclass). AR065 typed client: the web
 * modules annotate server payloads with
 * `@param {import("./api-types.js").StateResponse} state` etc.; this file has
 * no runtime exports.
 *
 * All models tolerate extra keys (extra="allow"), so every typedef is an
 * open shape: documented properties plus any additional wire fields.
 *
 * Regenerate: .venv/Scripts/python.exe tools/gen_api_types.py
 * Verify:     .venv/Scripts/python.exe tools/gen_api_types.py --check
 */
"""


def _load_schemas() -> py_types.ModuleType:
    """Import schemas.py directly by path (no package __init__ side effects).

    The module is registered in ``sys.modules`` before execution so pydantic
    can resolve the stringized annotations (``from __future__ import
    annotations`` in schemas.py) against the module namespace.
    """
    spec = importlib.util.spec_from_file_location("attackmap_ui_api_schemas", SCHEMAS_PATH)
    if spec is None or spec.loader is None:  # pragma: no cover - filesystem guard
        raise SystemExit(f"cannot load {SCHEMAS_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _model_classes(module: py_types.ModuleType) -> list[type]:
    """ApiModel subclasses defined in this module, in definition order."""
    base = module.ApiModel
    return [
        value
        for value in vars(module).values()
        if inspect.isclass(value)
        and issubclass(value, base)
        and value is not base
        and value.__module__ == module.__name__
    ]


def _js_type(annotation: Any) -> str:
    """Map a pydantic field annotation to a JSDoc/Closure type string."""
    if annotation is None or annotation is Any:
        return "*"
    if annotation is str:
        return "string"
    if annotation is bool:
        return "boolean"
    if annotation in (int, float):
        return "number"
    if annotation in (dict,):
        return "Object"
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin in (list, set, frozenset, tuple):
        member = _js_type(args[0]) if args else "*"
        return f"{_maybe_paren(member)}[]"
    if origin is dict:
        key_t = _js_type(args[0]) if args else "string"
        val_t = _js_type(args[1]) if len(args) > 1 else "*"
        return f"Object<{key_t},{val_t}>"
    if origin in (py_types.UnionType, typing.Union):
        members = [_js_type(a) for a in args if a is not type(None)]
        nullable = any(a is type(None) for a in args)
        if not members:
            return "null"
        if len(members) == 1:
            single = members[0]
            return f"?{single}" if nullable else single
        union = "|".join(members)
        if nullable:
            union += "|null"
        return f"({union})"
    return "Object"


def _maybe_paren(js_type: str) -> str:
    return f"({js_type})" if ("|" in js_type and not js_type.startswith("(")) else js_type


def _typedef(model: type) -> str:
    summary = (inspect.getdoc(model) or "").splitlines()
    description = summary[0] if summary else model.__name__
    lines = ["/**", f" * {description}", f" * @typedef {{Object}} {model.__name__}"]
    for name, field in model.model_fields.items():
        js = _js_type(field.annotation)
        if js.startswith("?"):
            js = js[1:]
        name_part = name if field.is_required() else f"[{name}]"
        lines.append(f" * @property {{{js}}} {name_part}")
    lines.append(" */")
    return "\n".join(lines)


def generate() -> str:
    module = _load_schemas()
    models = _model_classes(module)
    if not models:  # pragma: no cover - generator guard
        raise SystemExit("no ApiModel subclasses found in schemas.py")
    blocks = [_HEADER]
    blocks.extend(_typedef(model) for model in models)
    return "\n\n".join(blocks) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 0 when api-types.js matches the generator output, 1 on drift",
    )
    args = parser.parse_args(argv)

    text = generate()
    if args.check:
        current = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else None
        if current == text:
            print(f"ok: {OUTPUT_PATH.relative_to(REPO_ROOT)} is up to date")
            return 0
        print(
            f"drift: {OUTPUT_PATH.relative_to(REPO_ROOT)} does not match schemas.py",
            file=sys.stderr,
        )
        print("regenerate with: .venv/Scripts/python.exe tools/gen_api_types.py", file=sys.stderr)
        return 1

    OUTPUT_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {OUTPUT_PATH.relative_to(REPO_ROOT)} ({len(text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

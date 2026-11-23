"""``attackmap rules`` — the rule-catalog surface (AR046).

Backed by the kernel registry (``attackmap.reasoning.rules.REGISTRY``): the
stable, suppressible rule ids this engine's reasoning rules carry, with the
metadata needed to write suppressions and read findings. The sub-app replaces
the old flat ``rules`` command, which listed the legacy cascade catalog; the
cascade stays the report producer until its retirement, and this catalog is
the registry-side contract that wiring lands on.
"""

from __future__ import annotations

import inspect
import json

import typer

rules_app = typer.Typer(
    help="List and inspect the registered reasoning rules (stable ids for SARIF ruleId and `rule:` suppressions).",
)


def _registry():
    """The rule registry, imported lazily so unrelated CLI commands don't pay
    for loading every rule module (same shape as the old rules command)."""
    from attackmap.reasoning.rules import REGISTRY

    return REGISTRY


def _catalog_payload(registry) -> list[dict]:
    """One JSON object per registered rule, sorted by stable id."""
    return [
        {
            "id": rule.meta.id,
            "title": rule.meta.title,
            "cwe": rule.meta.cwe,
            "severity": rule.meta.severity,
            "confidence": rule.meta.confidence,
            "rationale": rule.meta.rationale,
            "tags": list(rule.meta.tags),
        }
        for rule in registry.all_rules()
    ]


@rules_app.command("list")
def list_rules(
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit the rule catalog as a JSON array "
        "(id/title/cwe/severity/confidence/rationale/tags, sorted by id). "
        "Intended for tool / GUI front-ends.",
    ),
) -> None:
    """List every registered rule's stable id, title and severity."""
    registry = _registry()
    if as_json:
        typer.echo(json.dumps(_catalog_payload(registry), indent=2))
        return
    all_rules = registry.all_rules()
    width = max((len(rule.meta.id) for rule in all_rules), default=0)
    for rule in all_rules:
        typer.echo(f"{rule.meta.id.ljust(width)}  {rule.meta.severity:<7}  {rule.meta.title}")


@rules_app.command("show")
def show_rule(
    rule_id: str = typer.Argument(..., help="The stable rule id (`attackmap rules list`)."),
) -> None:
    """Show one rule's full metadata, legacy-id mapping and docstring."""
    rule = _registry().get(rule_id)
    if rule is None:
        typer.echo(f"Error: unknown rule id: {rule_id!r}. Run `attackmap rules list` for the catalog.", err=True)
        raise typer.Exit(code=1)
    meta = rule.meta
    legacy = tuple(getattr(rule, "legacy_rule_ids", ()))
    typer.echo(f"id: {meta.id}")
    typer.echo(f"title: {meta.title}")
    typer.echo(f"cwe: {meta.cwe or '-'}")
    typer.echo(f"severity: {meta.severity}")
    typer.echo(f"confidence: {meta.confidence}")
    typer.echo(f"tags: {', '.join(meta.tags) or '-'}")
    typer.echo(f"replaces legacy detector ids: {', '.join(legacy) or '-'}")
    typer.echo(f"rationale: {meta.rationale}")
    doc = inspect.getdoc(rule)
    if doc:
        typer.echo("")
        typer.echo(doc)

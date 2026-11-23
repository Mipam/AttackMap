"""``attackmap rules`` — the rule-catalog surface (AR046).

Backed by the kernel registry (``attackmap.reasoning.rules.REGISTRY``): the
stable, suppressible rule ids this engine's reasoning rules carry, with the
metadata needed to write suppressions and read findings.

Two surfaces, on purpose (AGENTS.md: preserve CLI behavior):

* ``attackmap rules`` / ``attackmap rules --json`` — the flat form, unchanged.
  It lists the report producer's rule ids: the values ``rule:`` suppressions
  match today. The cascade in ``threat_model`` stays the producer until the
  registry is wired into the pipeline.
* ``attackmap rules list [--json]`` / ``attackmap rules show <id>`` — the
  registered reasoning rules (AR046). Their ids are not in reports yet; they
  become the report ruleIds when the registry takes over.
"""

from __future__ import annotations

import inspect
import json

import typer

rules_app = typer.Typer(
    help="List rule ids: plain `attackmap rules` prints the ids reports carry; `list`/`show` cover the registered reasoning rules.",
)


@rules_app.callback(invoke_without_command=True)
def rules(
    ctx: typer.Context,
    as_json: bool = typer.Option(False, "--json", help="Emit the rule catalog as JSON."),
) -> None:
    """List every core detector's stable rule id (#223) — the SARIF ruleId and
    the value for `rule:` suppressions and `attackmap:ignore[...]`."""
    if ctx.invoked_subcommand is not None:
        return
    from attackmap.reasoning.threat_model import rule_catalog

    catalog = rule_catalog()
    if as_json:
        typer.echo(json.dumps([{"rule_id": r, "title": t, "severity": sev} for r, t, sev in catalog], indent=2))
        return
    width = max(len(r) for r, _, _ in catalog)
    for rule_id, title, severity in catalog:
        typer.echo(f"{rule_id.ljust(width)}  {severity:<7}  {title}")


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
    """List every registered rule's stable id, title and severity.

    These are the kernel reasoning rules (AR040+). Until the registry is wired
    into the scan pipeline, reports still carry the ids printed by plain
    `attackmap rules`."""
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

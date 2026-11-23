"""``attackmap index`` — the derived-index surface (AR061).

The index is a disposable projection of the published generations under an
output base (``--output``, default ``reports`` — the same base ``analyze``
publishes into). Nothing here treats the index as a source of truth:
``status`` and ``dump`` read through :func:`load_rows`, which falls back to
the generations with a warning when the index is missing, corrupt, or stale
(AC-303), and ``rebuild`` always rebuilds from the generations alone (AC-302).
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

index_app = typer.Typer(help="Manage the derived SQLite index over published scan generations.")


def _base(output: str) -> Path:
    base = Path(output)
    if not base.is_dir():
        typer.echo(f"Error: not an AttackMap output base (directory does not exist): {base}", err=True)
        raise typer.Exit(code=2)
    return base


@index_app.command("rebuild")
def rebuild(
    output: str = typer.Option(
        "reports", "--output", "-o",
        help="AttackMap output base containing report generations.",
    ),
) -> None:
    """Rebuild index/index.sqlite from the generations under the output base.

    Deterministic: the same generation set yields a byte-identical index, so
    delete-and-rebuild is verified by content diff (AC-302).
    """
    from attackmap.orchestration.derived_index.rebuild import rebuild_index

    base = _base(output)
    rows, target = rebuild_index(base)
    counts = rows.counts()
    typer.echo(f"index rebuilt: {target}")
    typer.echo(f"generations: {len(rows.generations)} "
               f"({sum(1 for g in rows.generations if g.indexed)} indexed, "
               f"{len(rows.not_indexed())} not indexed)")
    typer.echo("rows: " + ", ".join(f"{table}={count}" for table, count in counts.items()))
    for generation in rows.not_indexed():
        typer.echo(f"note: generation {generation.path} not indexed: {generation.error}", err=True)


@index_app.command("status")
def status(
    output: str = typer.Option(
        "reports", "--output", "-o",
        help="AttackMap output base containing report generations.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit the status as JSON."),
) -> None:
    """Show whether the index is usable and what it holds.

    When the index is missing, corrupt, on another schema version, or stale,
    the generations are read instead and the reason is reported — this
    command never fails because of the index (AC-303).
    """
    from attackmap.orchestration.derived_index.query import load_rows

    base = _base(output)
    loaded = load_rows(base)
    payload = {
        "output_base": str(base),
        "index": {
            "usable": loaded.source == "index",
            "reason": loaded.reason,
        },
        "rows": loaded.rows.counts(),
        "fingerprint": loaded.rows.fingerprint,
    }
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    if loaded.source == "index":
        typer.echo(f"index: usable ({len(loaded.rows.generations)} generations)")
    else:
        typer.echo(f"warning: index unusable ({loaded.reason}); rows read from generations", err=True)
        typer.echo(f"index: unusable ({loaded.reason}); fallback to generations")
    typer.echo("rows: " + ", ".join(f"{table}={count}" for table, count in loaded.rows.counts().items()))


@index_app.command("dump")
def dump(
    output: str = typer.Option(
        "reports", "--output", "-o",
        help="AttackMap output base containing report generations.",
    ),
) -> None:
    """Dump the raw stored tables as JSON, for content diffs (AC-302).

    Reads straight from the index file when it is usable; otherwise says so
    instead of guessing — a diff is only meaningful against actual index
    content.
    """
    from attackmap.orchestration.derived_index.sqlite import dump_tables, open_fresh_index

    base = _base(output)
    conn, reason = open_fresh_index(base)
    if conn is None:
        typer.echo(f"Error: index unusable ({reason}); rebuild it with `attackmap index rebuild`.", err=True)
        raise typer.Exit(code=1)
    try:
        payload = dump_tables(conn)
    finally:
        conn.close()
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))

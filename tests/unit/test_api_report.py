"""AR063 / AC-305: tools.api_report gate behavior."""

from __future__ import annotations

from tools import api_report


def test_check_passes_on_the_declared_surface() -> None:
    assert api_report.main(["--check"]) == 0


def test_report_mode_lists_routes_schemas_and_budget(capsys) -> None:
    assert api_report.main([]) == 0
    out = capsys.readouterr().out
    assert "routes: 13" in out
    assert "average handler lines" in out


def test_check_detects_orphan_schema(monkeypatch) -> None:
    from attackmap.surfaces.ui.api import schemas as api_schemas

    class OrphanTestModel(api_schemas.ApiModel):
        pass

    schemas = api_report._declared_schemas()
    schemas["OrphanTestModel"] = OrphanTestModel
    monkeypatch.setattr(api_report, "_declared_schemas", lambda: schemas)
    failures = api_report.check()
    assert any("OrphanTestModel" in failure for failure in failures)


def test_check_detects_route_without_response_model(monkeypatch) -> None:
    from attackmap.surfaces.ui.api.routes import Route

    routes = list(api_report._registry())
    broken = Route(
        routes[0].method,
        routes[0].path,
        routes[0].handler,
        routes[0].request_model,
        None,  # type: ignore[arg-type]
        routes[0].summary,
    )
    monkeypatch.setattr(api_report, "_registry", lambda: [broken, *routes[1:]])
    failures = api_report.check()
    assert any("no response model declared" in failure for failure in failures)


def test_check_detects_unregistered_source_literal(monkeypatch) -> None:
    monkeypatch.setattr(api_report, "_source_route_literals",
                        lambda: {"/api/ghost-endpoint"})
    failures = api_report.check()
    assert any("/api/ghost-endpoint" in failure for failure in failures)

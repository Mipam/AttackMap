"""AR063 / AC-305: the GUI /api/* surface is declared and stays behavior-stable.

Covers: schema coverage of all 13 routes in both directions, the handler
line budget, the single dispatcher-level auth-token gate (403 without a
token), and the adapter's static index serving.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from pydantic import BaseModel

from attackmap.surfaces.ui.api import routes as api_routes
from attackmap.surfaces.ui.api import schemas as api_schemas
from attackmap.surfaces.ui.server import LoopbackApp, make_server

EXPECTED_ROUTES = {
    ("GET", "/api/state"),
    ("GET", "/api/report"),
    ("GET", "/api/export-source"),
    ("POST", "/api/config"),
    ("POST", "/api/pick"),
    ("POST", "/api/run"),
    ("POST", "/api/cancel"),
    ("POST", "/api/watch"),
    ("POST", "/api/settings"),
    ("POST", "/api/reveal"),
    ("POST", "/api/suppress"),
    ("POST", "/api/export"),
    ("POST", "/api/pick-save"),
}


def _get(url: str, token: str | None = None) -> dict[str, Any]:
    headers = {"X-AttackMap-Token": token} if token else {}
    with urlopen(Request(url, headers=headers), timeout=5) as response:
        return json.load(response)


def _post(url: str, body: dict, token: str) -> dict[str, Any]:
    request = Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-AttackMap-Token": token},
    )
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def test_registry_covers_all_thirteen_api_routes() -> None:
    registered = {(entry.method, entry.path) for entry in api_routes.all_routes()}
    assert registered == EXPECTED_ROUTES


def test_every_route_declares_models_from_schemas_module() -> None:
    for entry in api_routes.all_routes():
        assert issubclass(entry.response_model, BaseModel), entry.path
        assert entry.response_model.__module__ == api_schemas.__name__, entry.path
        if entry.method == "POST":
            assert entry.request_model is not None, entry.path
            assert issubclass(entry.request_model, BaseModel), entry.path
            assert entry.request_model.__module__ == api_schemas.__name__, entry.path


def test_every_declared_schema_maps_to_a_live_route() -> None:
    referenced = {
        model.__name__
        for entry in api_routes.all_routes()
        for model in (entry.request_model, entry.response_model)
        if model is not None
    }
    declared = {
        name
        for name, value in vars(api_schemas).items()
        if isinstance(value, type) and issubclass(value, api_schemas.ApiModel)
        and value is not api_schemas.ApiModel
    }
    assert declared == referenced


def test_handlers_fit_the_line_budget() -> None:
    from tools.api_report import handler_line_counts

    counts = handler_line_counts()
    assert len(counts) == len(EXPECTED_ROUTES)
    assert sum(counts.values()) / len(counts) <= 20


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    app = LoopbackApp()
    httpd = make_server(app)
    yield app, httpd.server_port
    httpd.shutdown()
    httpd.server_close()


def test_static_index_served_without_token(server) -> None:
    _, port = server
    with urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "text/html" in response.headers.get("Content-Type", "")
        assert "<title>" in body or "<html" in body


def test_api_requires_token_and_accepts_query_or_header(server) -> None:
    app, port = server
    with pytest.raises(HTTPError) as err:
        urlopen(f"http://127.0.0.1:{port}/api/state", timeout=5)
    assert err.value.code == 403
    via_header = _get(f"http://127.0.0.1:{port}/api/state", app.token)
    via_query = _get(f"http://127.0.0.1:{port}/api/state?token={app.token}")
    assert via_header["status"] == "idle"
    assert via_query["repositoryKey"] == via_header["repositoryKey"]


def test_post_roundtrip_through_dispatcher(server) -> None:
    app, port = server
    body = _post(f"http://127.0.0.1:{port}/api/watch", {"enabled": True}, app.token)
    assert body["watch"] is True
    body = _post(f"http://127.0.0.1:{port}/api/cancel", {}, app.token)
    assert body["status"] == "idle"


def test_unknown_api_path_is_404_not_403(server) -> None:
    app, port = server
    with pytest.raises(HTTPError) as err:
        _get(f"http://127.0.0.1:{port}/api/nope", app.token)
    assert err.value.code == 404

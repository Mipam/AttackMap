"""Route registry, auth-token gate, and dispatcher for the GUI API (AR063).

Import graph is a strict DAG (enforced by the arch_report cycle gate, which
counts type-only imports too)::

    schemas  <-  routes  <-  scans / artifacts / settings  <-  server

``server.py`` imports the three handler modules for their ``@route``
registration side effect and calls :func:`dispatch` from its request handler;
``tools.api_report`` imports ``surfaces.ui.server`` before reading the
registry.

The dispatcher is the ONE place the auth-token check is applied; handlers
never check tokens themselves. Handlers receive ``(app, body, query)`` —
``body`` is the parsed JSON dict (POST only), ``query`` is ``parse_qs`` of the
URL query — and return :class:`ApiResponse`.

To keep the graph acyclic, the concrete ``LoopbackApp`` type is never imported
here (not even under ``TYPE_CHECKING``): handlers are duck-typed against
:class:`ApiApp`, and the adapter's handler against :class:`HttpResponder`.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from email.message import Message
from typing import Any, Protocol
from urllib.parse import parse_qs, urlparse

from attackmap.surfaces.ui.api.schemas import ApiModel, StateResponse


class ApiApp(Protocol):
    """Structural type of the adapter app (a ``LoopbackApp`` at runtime)."""

    token: str

    def state(self) -> dict[str, Any]: ...


class HttpResponder(Protocol):
    """The adapter handler's response helpers, duck-typed to avoid a cycle."""

    path: str
    headers: Message

    def _json(self, code: int, payload: object) -> None: ...

    def _send(self, code: int, body: bytes, content_type: str) -> None: ...

    def _body(self) -> dict[str, Any]: ...


HandlerFunc = Callable[[Any, dict[str, Any], dict[str, list[str]]], "ApiResponse"]


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    handler: HandlerFunc
    request_model: type[Any] | None
    response_model: type[ApiModel]
    summary: str


@dataclass
class ApiResponse:
    """What a handler returns; ``payload`` bytes are sent with ``content_type``."""

    code: int
    payload: dict[str, Any] | bytes
    content_type: str = "application/json; charset=utf-8"


ROUTES: list[Route] = []


def route(
    method: str,
    path: str,
    *,
    response: type[ApiModel],
    request: type[Any] | None = None,
    summary: str = "",
) -> Callable[[HandlerFunc], HandlerFunc]:
    """Register an API handler; used by the scans/artifacts/settings modules."""

    def register(fn: HandlerFunc) -> HandlerFunc:
        ROUTES.append(Route(method, path, fn, request, response, summary or fn.__name__))
        return fn

    return register


def all_routes() -> list[Route]:
    """The registered routes.

    Registration is a side effect of importing the handler modules, which
    ``surfaces.ui.server`` (and anything importing it) performs.
    """
    return list(ROUTES)


def token_ok(http_handler: HttpResponder, app: ApiApp) -> bool:
    """The single auth-token check, applied by the dispatcher to every /api/* call."""
    q = parse_qs(urlparse(http_handler.path).query)
    header = http_handler.headers.get("X-AttackMap-Token", "")
    token = header or (q.get("token") or [""])[0]
    try:
        return bool(token) and secrets.compare_digest(str(token), app.token)
    except (TypeError, ValueError):
        return False


def state_response(app: ApiApp, model: type[ApiModel] = StateResponse) -> ApiResponse:
    """Shared ``{...app.state()}`` 200 response, validated against ``model``."""
    payload = app.state()
    model.model_validate(payload)
    return ApiResponse(200, payload)


def dispatch(app: ApiApp, http_handler: HttpResponder, method: str, parsed: Any) -> bool:
    """Handle one request if a route matches; the adapter 404s when it returns False."""
    for entry in all_routes():
        if entry.method != method or entry.path != parsed.path:
            continue
        if not token_ok(http_handler, app):
            http_handler._json(403, {"error": "forbidden"})
            return True
        body = http_handler._body() if method == "POST" else {}
        response = entry.handler(app, body, parse_qs(parsed.query))
        if isinstance(response.payload, bytes):
            http_handler._send(response.code, response.payload, response.content_type)
        else:
            http_handler._json(response.code, response.payload)
        return True
    return False

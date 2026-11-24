"""Settings and suppression API handlers (AR063).

Handlers (both registered with ``@route``):

- ``POST /api/settings`` — persist LLM provider API keys in secure storage
- ``POST /api/suppress`` — append a suppression record to the repo file
"""

from __future__ import annotations

from typing import Any

from attackmap.foundation.secrets import save_llm_key
from attackmap.surfaces.ui.api.routes import ApiResponse, route, state_response
from attackmap.surfaces.ui.api.schemas import (
    SettingsRequest,
    SettingsResponse,
    SuppressRequest,
    SuppressResponse,
)
from attackmap.surfaces.ui.suppress_write import append_suppression


# Handlers take ``app: Any`` (the adapter's ``LoopbackApp`` at runtime); see
# api/scans.py for why the concrete type is not imported here.
@route("POST", "/api/settings", request=SettingsRequest, response=SettingsResponse,
       summary="Persist LLM provider API keys in secure storage")
def save_settings(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    request = SettingsRequest.model_validate(body)
    try:
        if request.anthropicKey:
            save_llm_key(str(request.anthropicKey), "claude")
        if request.openaiKey:
            save_llm_key(str(request.openaiKey), "openai")
    except OSError:
        return ApiResponse(503, {"error": "Secure credential storage unavailable; key was not saved."})
    return state_response(app, SettingsResponse)


@route("POST", "/api/suppress", request=SuppressRequest, response=SuppressResponse,
       summary="Append a suppression record to the repo suppress file")
def suppress_record(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    SuppressRequest.model_validate(body)
    if app.repo is None:
        return ApiResponse(400, {"error": "no repo"})
    dest = app.repo / ".attackmap-suppress.yaml"
    try:
        append_suppression(dest, body)
    except ValueError as exc:
        return ApiResponse(400, {"error": str(exc)})
    payload = {"ok": True, "path": str(dest)}
    SuppressResponse.model_validate(payload)
    return ApiResponse(200, payload)

"""Pydantic request/response models for every ``/api/*`` endpoint (AR063 / AC-305).

Response models *validate* the exact payloads the GUI already emits; handlers
return the original dict after ``model_validate``, so wire format, key order,
and explicit ``null`` handling are preserved byte-for-byte. Request models are
deliberately all-optional with ``extra="allow"`` so the historically tolerant
body handling (unknown keys ignored, missing keys defaulted) does not change.

``tools.api_report --check`` verifies both directions: every route declares
models from this module, and every model declared here is referenced by a
route.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field


class ApiModel(BaseModel):
    """Base for endpoint schemas: tolerant of unknown keys, reverse-checkable."""

    model_config = ConfigDict(extra="allow")

    endpoint: ClassVar[bool] = True  # marker collected by tools.api_report


# --------------------------------------------------------------------------
# Request models (POST bodies; GET endpoints take query params only)
# --------------------------------------------------------------------------


class ConfigRequest(ApiModel):
    """POST /api/config and POST /api/run share the same scan options body."""

    repo: str | None = None
    repos: list[str] | None = None
    cve: bool | None = None
    recall: bool | None = None
    llmMode: str | None = None
    llm: str | None = None
    provider: str | None = None
    model: str | None = None
    baseUrl: str | None = None
    modules: str | list[str] | None = None
    noSuppress: bool | None = None
    useBaseline: bool | None = None
    failOnNewHigh: bool | None = None


class RunRequest(ConfigRequest):
    """POST /api/run — same shape as config; scan start reads current settings."""


class PickRequest(ApiModel):
    """POST /api/pick — open the folder picker."""

    multi: bool | None = None


class CancelRequest(ApiModel):
    """POST /api/cancel — no fields; cancellation targets the active run."""


class WatchRequest(ApiModel):
    """POST /api/watch — toggle filesystem watching."""

    enabled: bool | None = None


class SettingsRequest(ApiModel):
    """POST /api/settings — persist provider API keys in secure storage."""

    anthropicKey: str | None = None
    openaiKey: str | None = None


class RevealRequest(ApiModel):
    """POST /api/reveal — open the report folder; no fields."""


class SuppressRequest(ApiModel):
    """POST /api/suppress — suppression record; passed through to the writer."""


class ExportRequest(ApiModel):
    """POST /api/export — write a report view to a .md/.pdf path."""

    view: str | None = None
    path: str | None = None


class PickSaveRequest(ApiModel):
    """POST /api/pick-save — ask for an export destination path."""

    suggestedName: str | None = None


# --------------------------------------------------------------------------
# Response models
# --------------------------------------------------------------------------


class StateResponse(ApiModel):
    """GET /api/state and the state snapshot returned by most POST endpoints."""

    status: str = ""
    progress: dict[str, Any] = Field(default_factory=dict)
    exitCode: int | None = None
    error: str | None = None
    stderrTail: str = ""
    repo: str | None = None
    repos: list[str] = Field(default_factory=list)
    repositoryKey: str = ""
    runId: str | None = None
    reportGeneration: str | None = None
    reportRepositoryKey: str | None = None
    output: str | None = None
    cve: bool = False
    recall: bool = False
    llm: str = ""
    llmMode: str = ""
    provider: str = ""
    model: str | None = None
    baseUrl: str = ""
    modules: list[str] = Field(default_factory=list)
    watch: bool = False
    watchNotice: str | None = None
    running: bool = False
    hasReport: bool = False
    findingCount: int = 0
    newCount: int = 0
    resolvedCount: int = 0
    capabilities: list[str] = Field(default_factory=list)
    availableModules: list[dict[str, Any]] = Field(default_factory=list)
    missingAnalyzers: list[dict[str, Any]] = Field(default_factory=list)
    recents: list[dict[str, Any]] = Field(default_factory=list)
    hasAnthropicKey: bool = False
    hasOpenAIKey: bool = False
    llmOffBoxWarning: str | None = None
    runContract: dict[str, Any] | None = None


class ConfigResponse(StateResponse):
    """POST /api/config — the applied configuration as a state snapshot."""


class RunResponse(StateResponse):
    """POST /api/run — state snapshot taken right after the run was requested."""


class CancelResponse(StateResponse):
    """POST /api/cancel — state snapshot reflecting the cancellation request."""


class WatchResponse(StateResponse):
    """POST /api/watch — state snapshot reflecting the new watch flag."""


class RevealResponse(StateResponse):
    """POST /api/reveal — state snapshot (reveal itself has no payload)."""


class SettingsResponse(StateResponse):
    """POST /api/settings — state snapshot after key storage attempts."""


class PickResponse(StateResponse):
    """POST /api/pick — state snapshot plus the resolved repository paths."""

    picked: list[str] = Field(default_factory=list)


class ReportResponse(ApiModel):
    """GET /api/report — the current report snapshot with identity fields."""

    repositoryKey: str | None = None
    generationId: str | None = None
    error: str | None = None


class ExportSourceResponse(ApiModel):
    """GET /api/export-source — raw Markdown for a report view."""

    markdown: str = ""


class SuppressResponse(ApiModel):
    """POST /api/suppress — the suppression file that was appended."""

    ok: bool | None = None
    path: str | None = None
    error: str | None = None


class ExportResponse(ApiModel):
    """POST /api/export — the written artifact path, or an error body."""

    ok: bool | None = None
    path: str | None = None
    error: str | None = None


class PickSaveResponse(ApiModel):
    """POST /api/pick-save — the chosen path ("" when the dialog was cancelled)."""

    path: str = ""
    error: str | None = None

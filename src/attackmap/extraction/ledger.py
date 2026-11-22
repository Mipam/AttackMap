"""Per-run analyzer decisions and observed outcomes, separate from discovery.

AR030: the run plan and identity observation live in
:mod:`attackmap.orchestration.analyzer_run_plan` (they need the analyzer
registry); this module keeps the persisted record models so every layer can
depend on the data without reaching up into orchestration.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


def safe_error_type(value: str) -> str:
    return value if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", value) else "Exception"


class AnalyzerRunError(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage: Literal["detect", "analysis", "isolated_host", "captured_input"]
    error_type: str


class AnalyzerSignalCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    routes: int = Field(ge=0)
    external_calls: int = Field(ge=0)
    databases: int = Field(ge=0)
    auth_hints: int = Field(ge=0)
    secret_hints: int = Field(ge=0)


class AnalyzerLifecycleEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage: Literal["detect", "selection", "analysis"]
    state: Literal["started", "requested", "applicable", "unmatched", "detect_error", "selected", "skipped", "succeeded", "failed"]
    elapsed_ms: float = Field(ge=0, allow_inf_nan=False)
    error_type: str | None = None


class AnalyzerRunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    version: str | None = None
    priority: int = 100
    origin: Literal["builtin", "plugin", "supplied"]
    implementation: dict[str, str | None]
    implementation_sha256: str
    package: dict[str, str | None] | None = None
    entry_point: dict[str, str | None] | None = None
    provenance: dict[str, object] = Field(default_factory=dict)
    selection: Literal["selected", "skipped"] = "skipped"
    applicability: Literal["not_evaluated", "applicable", "unmatched", "detect_error"] = "not_evaluated"
    execution: Literal["not_started", "succeeded", "failed", "skipped"] = "not_started"
    analysis_started: bool | None = False
    execution_mode: Literal["in_process", "isolated"] | None = None
    skip_reason: Literal["unmatched", "detect_error", "opt_in", "pipeline_deadline"] | None = None
    error: AnalyzerRunError | None = None
    detect_duration_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    analysis_duration_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    signal_counts: AnalyzerSignalCounts | None = None
    lifecycle_events: list[AnalyzerLifecycleEvent] = Field(default_factory=list, max_length=16)

    def failed(self, stage: str, error_type: str) -> None:
        self.execution = "failed"
        self.error = AnalyzerRunError(stage=stage, error_type=safe_error_type(error_type))


class AnalyzerRunLedger(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0", "1.1"] = "1.1"
    scope: Literal["analyzer_selection_and_execution"] = "analyzer_selection_and_execution"
    inventory_scope: Literal["registered_candidates", "supplied_candidates"] = "registered_candidates"
    selection_mode: Literal["automatic", "explicit"]
    profile_id: str | None = None
    resolution_complete: bool = False
    execution_complete: bool = False
    entries: list[AnalyzerRunRecord] = Field(default_factory=list)


__all__ = [
    "AnalyzerLifecycleEvent",
    "AnalyzerRunError",
    "AnalyzerRunLedger",
    "AnalyzerRunRecord",
    "AnalyzerSignalCounts",
    "safe_error_type",
]

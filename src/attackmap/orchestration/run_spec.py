"""Transport-neutral run specification and construction adapters (AR024, AC-105).

``RunSpec`` is the frozen, grouped mirror of one scan's configuration. In this
slice it is a *carrier*: ``execute_scan_request`` builds it from the existing
``ScanRequest`` and threads it onto ``RunState`` so later slices (AR025/AR026)
can retire ``AnalyzeOptions`` and ambient configuration. Until then
``AnalyzeOptions``/``ScanRequest`` remain the source of truth for behavior;
nothing reads ``RunSpec`` to change a scan.

This module is pure configuration data and imports nothing from ``attackmap``
— stdlib only — so the engine's import-cycle set is untouched. The adapters
therefore read the existing option objects (``ScanRequest``, the desktop GUI
``ScanConfig``, raw CLI option values) by duck typing instead of importing
them.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any


@dataclass(frozen=True)
class AnalyzerSelection:
    """Which analyzers run and how they are loaded."""

    modules: tuple[str, ...] = ()
    analyzers: tuple[str, ...] = ()
    profile_id: str | None = None
    install_missing: bool = False
    allow_untrusted: bool = False
    strict: bool = False
    isolated: bool = False


@dataclass(frozen=True)
class FeatureFlags:
    """Analysis widenings, suppression governance and history controls."""

    recall: bool = False
    cve: bool = False
    incremental: bool = False
    no_suppress: bool = False
    suppress_file: str | None = None
    suppress_from_ref: str | None = None
    allow_pr_suppressions: bool = False
    strict_suppressions: bool = False
    secrets_history: int = 0


@dataclass(frozen=True)
class BudgetSpec:
    """Deterministic elapsed ceiling for the pipeline (C35)."""

    time_budget_seconds: int | None = None


@dataclass(frozen=True)
class AiSpec:
    """LLM feature switches, provider controls and the shared scan allowance."""

    enabled: bool = False
    provider: str = "claude"
    model: str | None = None
    effort: str | None = None
    backend: str = "auto"
    speed: str = "standard"
    desktop_mode: str | None = None
    hunt: bool = False
    verify: bool = False
    verify_votes: int = 3
    hunt_lenses: int = 1
    hunt_rounds: int = 1
    hunt_budget: int = 0
    remediate: bool = False
    triage: bool = False
    max_calls: int = 8
    output_tokens: int = 32000
    timeout_seconds: int = 600


@dataclass(frozen=True)
class FleetSpec:
    """Multi-repo worker coordination; child processes rebuild their own spec."""

    max_workers: int = 1
    supervised: bool = False
    timeout_seconds: int = 600
    input_byte_budget: int | None = None


@dataclass(frozen=True)
class RunSpec:
    """One scan's whole configuration, grouped; transport stays on the request.

    Repository paths, the output root, cancel hooks and fleet event callbacks
    remain request-level (AR025 keeps them there); everything that describes
    *how* a scan runs lives here in frozen groups.
    """

    analyzer: AnalyzerSelection = AnalyzerSelection()
    features: FeatureFlags = FeatureFlags()
    budget: BudgetSpec = BudgetSpec()
    ai: AiSpec = AiSpec()
    fleet: FleetSpec = FleetSpec()
    output_format: str = "all"
    progress_format: str = "auto"
    no_progress: bool = False
    atomic_output: bool = True
    run_id: str | None = None
    baseline: str | None = None
    diff_output: str | None = None
    fail_on_new_high: bool = False
    fail_on_new_suppression: bool = False
    pr_comment: str | None = None

    @classmethod
    def from_scan_request(cls, request: Any) -> RunSpec:
        """Mirror a neutral ``ScanRequest`` (duck-typed to keep this module pure).

        The request stays the transport DTO and the behavioral source of truth;
        the returned spec is an equal, immutable description of the same run.
        """
        limits = request.ai_limits
        return cls(
            analyzer=AnalyzerSelection(
                modules=tuple(request.modules),
                analyzers=_analyzer_names(getattr(request, "analyzers", None)),
                profile_id=request.analyzer_profile_id,
                install_missing=request.install_missing,
                allow_untrusted=request.allow_untrusted_analyzers,
                strict=request.strict_analyzers,
                isolated=request.isolated_analyzers,
            ),
            features=FeatureFlags(
                recall=request.recall,
                cve=request.cve,
                incremental=request.incremental,
                no_suppress=request.no_suppress,
                suppress_file=request.suppress_file,
                suppress_from_ref=request.suppress_from_ref,
                allow_pr_suppressions=request.allow_pr_suppressions,
                strict_suppressions=request.strict_suppressions,
                secrets_history=request.secrets_history,
            ),
            budget=BudgetSpec(time_budget_seconds=request.time_budget_seconds),
            ai=AiSpec(
                enabled=request.llm,
                provider=request.llm_provider,
                model=request.llm_model,
                effort=request.llm_effort,
                backend=request.llm_backend,
                speed=request.llm_speed,
                desktop_mode=request.desktop_ai_mode,
                hunt=request.hunt,
                verify=request.verify,
                verify_votes=request.verify_votes,
                hunt_lenses=request.hunt_lenses,
                hunt_rounds=request.hunt_rounds,
                hunt_budget=request.hunt_budget,
                remediate=request.remediate,
                triage=request.triage,
                max_calls=limits.max_calls,
                output_tokens=limits.output_token_limit,
                timeout_seconds=limits.timeout_seconds,
            ),
            fleet=FleetSpec(
                max_workers=request.max_workers,
                supervised=request.fleet_supervised,
                timeout_seconds=request.fleet_timeout_seconds,
                input_byte_budget=request.fleet_input_byte_budget,
            ),
            output_format=request.output_format,
            progress_format=request.progress_format,
            no_progress=request.no_progress,
            atomic_output=request.atomic_output,
            run_id=request.run_id,
            baseline=request.baseline,
            diff_output=request.diff_output,
            fail_on_new_high=request.fail_on_new_high,
            fail_on_new_suppression=request.fail_on_new_suppression,
            pr_comment=request.pr_comment,
        )

    @classmethod
    def from_cli(cls, flags: Mapping[str, Any]) -> RunSpec:
        """Build a spec from CLI option values keyed by their option dest.

        Absent keys keep their defaults; unknown keys raise so this mapping
        cannot silently drift from the CLI surface (AC-105's "one request
        object" requires every flag to have exactly one spec destination).
        """
        spec = cls()
        for key, value in flags.items():
            path = _CLI_FLAG_PATHS.get(key)
            if path is None:
                raise ValueError(f"Unknown CLI option for RunSpec: {key!r}")
            if value is None:
                continue
            if isinstance(value, list):
                value = tuple(value)
            spec = _apply_flag(spec, path, value)
        return spec

    @classmethod
    def from_gui(cls, config: Any) -> RunSpec:
        """Mirror the desktop ``ScanConfig`` that produces the analyze argv.

        Mirrors ``ScanConfig.cli_args``/``_llm_flags`` faithfully: the GUI
        always requests ``--format all --progress-format json``, ``auto``
        modules are dropped there, ``huntVerify`` implies hunt+verify with the
        jury values, and paths arrive as ``Path`` objects while the spec stores
        strings like ``ScanRequest`` does.
        """
        mode = str(config.llm_mode or "none")
        lowered = mode.lower()
        jury = config.jury or {}
        ai_active = mode not in {"none", "None (heuristic only)", ""}
        hunt = ai_active and mode in {"hunt", "huntVerify", "hunt+verify"}
        verify = ai_active and mode in {"huntVerify", "hunt+verify"}
        return cls(
            analyzer=AnalyzerSelection(
                modules=tuple(m for m in config.modules if m and m.lower() != "auto"),
            ),
            features=FeatureFlags(
                recall=config.recall,
                cve=config.run_cve,
                no_suppress=config.no_suppress,
                suppress_file=_optional_str(config.suppress_file),
            ),
            ai=AiSpec(
                enabled=ai_active and (mode == "review" or lowered.startswith(("openai", "anthropic"))),
                provider="openai" if (config.provider == "openai" or lowered.startswith("openai"))
                else config.provider,
                model=config.model,
                effort=config.effort,
                speed="fast" if config.fast else "standard",
                hunt=hunt,
                verify=verify,
                verify_votes=int(jury.get("verifyVotes", 3)),
                hunt_lenses=int(jury.get("lenses", 1)),
                hunt_rounds=int(jury.get("rounds", 1)),
                hunt_budget=int(jury.get("budget", 0)),
                remediate=ai_active and mode == "remediate",
                triage=ai_active and mode == "triage",
            ),
            progress_format="json",
            run_id=config.run_id,
            baseline=_optional_str(config.baseline),
            diff_output=_optional_str(config.diff_output),
            fail_on_new_high=config.fail_on_new_high,
            pr_comment=_optional_str(config.pr_comment),
        )


_CLI_FLAG_PATHS: dict[str, str] = {
    "module": "analyzer.modules",
    "analyzer_profile": "analyzer.profile_id",
    "install_missing": "analyzer.install_missing",
    "allow_untrusted_analyzers": "analyzer.allow_untrusted",
    "strict_analyzers": "analyzer.strict",
    "isolated_analyzers": "analyzer.isolated",
    "recall": "features.recall",
    "cve": "features.cve",
    "incremental": "features.incremental",
    "no_suppress": "features.no_suppress",
    "suppress_file": "features.suppress_file",
    "suppress_from_ref": "features.suppress_from_ref",
    "allow_pr_suppressions": "features.allow_pr_suppressions",
    "strict_suppressions": "features.strict_suppressions",
    "secrets_history": "features.secrets_history",
    "time_budget_seconds": "budget.time_budget_seconds",
    "llm": "ai.enabled",
    "llm_provider": "ai.provider",
    "llm_model": "ai.model",
    "llm_effort": "ai.effort",
    "llm_backend": "ai.backend",
    "llm_speed": "ai.speed",
    "hunt": "ai.hunt",
    "verify": "ai.verify",
    "verify_votes": "ai.verify_votes",
    "hunt_lenses": "ai.hunt_lenses",
    "hunt_rounds": "ai.hunt_rounds",
    "hunt_budget": "ai.hunt_budget",
    "remediate": "ai.remediate",
    "triage": "ai.triage",
    "ai_max_calls": "ai.max_calls",
    "ai_output_tokens": "ai.output_tokens",
    "ai_timeout_seconds": "ai.timeout_seconds",
    "fleet_workers": "fleet.max_workers",
    "format": "output_format",
    "progress_format": "progress_format",
    "no_progress": "no_progress",
    "run_id": "run_id",
    "baseline": "baseline",
    "diff_output": "diff_output",
    "fail_on_new_high": "fail_on_new_high",
    "fail_on_new_suppression": "fail_on_new_suppression",
    "pr_comment": "pr_comment",
}


def _apply_flag(spec: RunSpec, path: str, value: Any) -> RunSpec:
    """Return a copy of ``spec`` with the dotted ``group.field`` path set."""
    group_name, _, leaf = path.rpartition(".")
    if not group_name:
        return replace(spec, **{leaf: value})
    group = replace(getattr(spec, group_name), **{leaf: value})
    return replace(spec, **{group_name: group})


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _analyzer_names(analyzers: Any) -> tuple[str, ...]:
    """Mirror resolved analyzer objects as slugs (same shape as scan_service)."""
    names: list[str] = []
    for analyzer in analyzers or ():
        name = getattr(analyzer, "name", None)
        if not name and hasattr(analyzer, "metadata"):
            name = analyzer.metadata.name
        if name:
            names.append(name)
    return tuple(names)

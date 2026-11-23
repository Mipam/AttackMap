"""AttackMap: a defensive security analysis engine.

Library use (AR062 / AC-304)::

    from pathlib import Path
    from attackmap import analyze, RunSpec

    result = analyze(RunSpec(repos=(Path("."),), output=Path("reports")))
    print(len(result.findings))

Every name in ``__all__`` except ``__version__`` resolves lazily (PEP 562, the
pattern ``attackmap.sdk`` already uses), so ``import attackmap`` loads neither
the engine nor the CLI, and ``RunSpec`` stays importable without either. This
module imports nothing at all: on its own, ``importlib`` roughly doubles the
cost of ``import attackmap``.
"""

__all__ = [
    "AiSpec",
    "AnalysisFailed",
    "AnalysisResult",
    "AnalyzerSelection",
    "AttackMapError",
    "BudgetSpec",
    "FeatureFlags",
    "FleetSpec",
    "RepoResult",
    "RunSpec",
    "SchedulerSpec",
    "__version__",
    "analyze",
]
__version__ = "1.5.1"

# name -> (module, attribute), resolved on first access and then cached.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "AiSpec": ("attackmap.orchestration.run_spec", "AiSpec"),
    "AnalysisFailed": ("attackmap.surfaces.api", "AnalysisFailed"),
    "AnalysisResult": ("attackmap.surfaces.api", "AnalysisResult"),
    "AnalyzerSelection": ("attackmap.orchestration.run_spec", "AnalyzerSelection"),
    "AttackMapError": ("attackmap.foundation.errors", "AttackMapError"),
    "BudgetSpec": ("attackmap.orchestration.run_spec", "BudgetSpec"),
    "FeatureFlags": ("attackmap.orchestration.run_spec", "FeatureFlags"),
    "FleetSpec": ("attackmap.orchestration.run_spec", "FleetSpec"),
    "RepoResult": ("attackmap.surfaces.api", "RepoResult"),
    "RunSpec": ("attackmap.orchestration.run_spec", "RunSpec"),
    "SchedulerSpec": ("attackmap.orchestration.run_spec", "SchedulerSpec"),
    "analyze": ("attackmap.surfaces.api", "analyze"),
}


def __getattr__(name: str) -> object:
    """Resolve a lazy export (PEP 562); the engine loads only when it is named."""
    try:
        module_name, attribute = _LAZY_EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    # ``__import__`` with a fromlist returns the named submodule itself.
    value = getattr(__import__(module_name, fromlist=[attribute]), attribute)
    globals()[name] = value  # cache: later accesses skip this hook
    return value


def __dir__() -> list[str]:
    return list(__all__)

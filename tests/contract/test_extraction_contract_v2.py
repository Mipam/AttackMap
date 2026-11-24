"""Extraction contract v2 + v1 adapter (AR060 / AC-301).

Pins the v2 plugin contract surface: ``EXTRACTION_CONTRACT_VERSION == "2.0"``,
``ExtractionResult`` carrying the discriminated ``observations`` union, and
the v1 adapters. A protocol-1.0 analyzer payload (``ScanResult``) must lift
into v2 and lower back with every payload list preserved exactly, and a v2
result must survive the JSON wire format (the discriminated union has to
re-hydrate), so plugins can adopt v2 without core changing.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from attackmap.extraction.adapters import (
    merge_extraction_results,
    to_extraction_result,
    to_scan_result,
)
from attackmap.model import ScanResult
from attackmap.model.observations import (
    AuthHint,
    CodeWeakness,
    DatabaseHint,
    DependencyHint,
    EdgeHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    ProtocolHint,
    Route,
    SecretHint,
    ServiceHint,
    SupplyChainIssue,
    Vulnerability,
    WorkflowIssue,
)
from attackmap.sdk import (
    EXTRACTION_CONTRACT_VERSION,
    DependencyObservation,
    EdgeObservation,
    EntrypointObservation,
    ExtractionResult,
    FrameworkObservation,
    ProtocolObservation,
    RouteObservation,
    SecretObservation,
    ServiceObservation,
    SupplyChainObservation,
    VulnerabilityObservation,
    WeaknessObservation,
    WorkflowObservation,
)

pytestmark = [pytest.mark.contract]

# Every payload family the AC-301 round trip must preserve verbatim, in
# ScanResult field order.
ROUND_TRIP_FIELDS = (
    "routes",
    "external_calls",
    "databases",
    "auth_hints",
    "service_hints",
    "edge_hints",
    "entrypoint_hints",
    "protocol_hints",
    "framework_hints",
    "secret_hints",
    "dependencies",
    "vulnerabilities",
    "code_weaknesses",
    "workflow_issues",
    "supply_chain_issues",
)


def _v1_scan_result() -> ScanResult:
    """A protocol-1.0 payload exercising every adapter-relevant list."""
    return ScanResult(
        root="C:/tmp/demo",
        languages=["python", "typescript"],
        files_scanned=12,
        scanned_files=["app.py", "client.ts"],
        limitations=["symlink skipped: docs"],
        routes=[
            Route(
                path="/users",
                method="GET",
                file="app.py",
                line=10,
                auth="required",
                guards=["@require_login"],
                guard_evidence="guard: @require_login",
            ),
            Route(path="/health", method="GET", file="app.py", line=22, auth="anonymous"),
        ],
        external_calls=[
            ExternalCall(
                target="https://api.example.com/v1",
                file="client.py",
                line=5,
                method="GET",
                evidence_text="requests.get('https://api.example.com/v1')",
            )
        ],
        databases=[DatabaseHint(kind="sqlite", file="db.py", line=3)],
        auth_hints=[AuthHint(hint="session cookie", file="auth.py", line=8)],
        service_hints=[ServiceHint(hint="worker queue", file="worker.py", line=1)],
        edge_hints=[EdgeHint(hint="web -> api", file="topology.py", line=2)],
        entrypoint_hints=[EntrypointHint(hint="wsgi entrypoint", file="wsgi.py", line=1)],
        protocol_hints=[ProtocolHint(hint="atproto xrpc", file="xrpc.py", line=4)],
        framework_hints=[FrameworkHint(hint="flask", file="requirements.txt", line=1)],
        secret_hints=[
            SecretHint(
                name="API_KEY",
                file="settings.py",
                line=9,
                evidence_text="API_KEY loaded from environment",
                kind="env_reference",
            )
        ],
        dependencies=[
            DependencyHint(
                name="requests", version="^2.31", ecosystem="pypi", file="requirements.txt", line=3
            )
        ],
        vulnerabilities=[
            Vulnerability(
                id="GHSA-test-0000",
                package_name="requests",
                package_version="2.31.0",
                ecosystem="pypi",
                affected_range="affected [2.0, 2.31.0)",
            )
        ],
        code_weaknesses=[CodeWeakness(kind="prototype_pollution", file="merge.js", line=7)],
        workflow_issues=[
            WorkflowIssue(kind="unpinned_action", file=".github/workflows/ci.yml", line=12)
        ],
        supply_chain_issues=[
            SupplyChainIssue(kind="unlocked_manifest", file="requirements.txt", line=1)
        ],
    )


def test_sdk_v2_extraction_contract_version_is_2_0() -> None:
    assert EXTRACTION_CONTRACT_VERSION == "2.0"
    result = ExtractionResult(root="C:/tmp/demo")
    assert result.extraction_version == "2.0"
    assert result.observations == []
    # Natively-built results declare their source protocol; only the adapter
    # tags "1.0".
    assert result.source_protocol_version == "2.0"


def test_sdk_v2_observations_are_discriminated_union() -> None:
    v1 = _v1_scan_result()
    v2 = to_extraction_result(v1)

    kinds = sorted(obs.kind for obs in v2.observations)
    assert kinds == [
        "dependency",
        "edge",
        "entrypoint",
        "framework",
        "protocol",
        "route",
        "route",
        "secret",
        "service",
        "supply_chain",
        "vulnerability",
        "weakness",
        "workflow",
    ]
    # Each element validates to its exact variant class with the v1 payload
    # wrapped verbatim (routes keep their list order).
    assert [o.route for o in v2.observations if isinstance(o, RouteObservation)] == v1.routes
    by_kind: dict[str, object] = {obs.kind: obs for obs in v2.observations}
    assert isinstance(by_kind["service"], ServiceObservation)
    assert isinstance(by_kind["edge"], EdgeObservation)
    assert isinstance(by_kind["entrypoint"], EntrypointObservation)
    assert isinstance(by_kind["protocol"], ProtocolObservation)
    assert isinstance(by_kind["framework"], FrameworkObservation)
    assert isinstance(by_kind["secret"], SecretObservation)
    assert isinstance(by_kind["dependency"], DependencyObservation)
    assert isinstance(by_kind["vulnerability"], VulnerabilityObservation)
    assert isinstance(by_kind["weakness"], WeaknessObservation)
    assert isinstance(by_kind["workflow"], WorkflowObservation)
    assert isinstance(by_kind["supply_chain"], SupplyChainObservation)

    # Unknown discriminators are rejected: the union is closed.
    with pytest.raises(ValidationError):
        ExtractionResult.model_validate(
            {"root": "C:/tmp/demo", "observations": [{"kind": "nope"}]}
        )


def test_v1_adapter_round_trip_preserves_payload_lists() -> None:
    v1 = _v1_scan_result()
    back = to_scan_result(to_extraction_result(v1))

    assert back.root == v1.root
    for field in ROUND_TRIP_FIELDS:
        assert getattr(back, field) == getattr(v1, field), f"round-trip lost {field}"
    assert back.languages == v1.languages
    assert back.limitations == v1.limitations
    assert back.scanned_files == v1.scanned_files
    assert back.files_scanned == v1.files_scanned
    assert back.analyzer_errors == v1.analyzer_errors


def test_v1_adapter_round_trip_identity_on_normalized_dicts() -> None:
    v1 = _v1_scan_result()
    v2 = to_extraction_result(v1)
    back = to_scan_result(v2)

    # Identity assertions on the normalized dicts, not just model equality.
    for field in ROUND_TRIP_FIELDS:
        assert [m.model_dump() for m in getattr(back, field)] == [
            m.model_dump() for m in getattr(v1, field)
        ], f"normalized dicts differ for {field}"

    # And once more through the serialized wire form: the discriminated
    # union must re-hydrate payloads identically.
    wire = ExtractionResult.model_validate_json(v2.model_dump_json())
    assert wire == v2
    assert wire.source_protocol_version == "1.0"
    back_from_wire = to_scan_result(wire)
    for field in ROUND_TRIP_FIELDS:
        assert getattr(back_from_wire, field) == getattr(v1, field)


def test_v1_adapter_wraps_v1_analyzer_output() -> None:
    """A protocol-1.0 analyzer still runs: its ScanResult adapts into v2."""

    class LegacyAnalyzer:
        name = "legacy-demo"

        def analyze(self, root: str) -> ScanResult:
            return ScanResult(
                root=root,
                routes=[Route(path="/ping", method="GET", file="srv.py", line=1)],
                languages=["python"],
            )

    v2 = to_extraction_result(LegacyAnalyzer().analyze("C:/tmp/demo"))
    assert isinstance(v2, ExtractionResult)
    assert v2.source_protocol_version == "1.0"
    assert len(v2.observations) == 1
    assert v2.observations[0].kind == "route"
    assert v2.observations[0].route.path == "/ping"  # type: ignore[union-attr]


def test_v1_adapter_merge_is_first_seen_wins_and_deterministic() -> None:
    v1 = _v1_scan_result()
    a = to_extraction_result(v1)
    duplicate = to_extraction_result(_v1_scan_result())

    merged = merge_extraction_results(a, duplicate)
    assert merged.root == v1.root
    assert merged.observations == a.observations
    merged_v1 = to_scan_result(merged)
    for field in ROUND_TRIP_FIELDS:
        assert getattr(merged_v1, field) == getattr(v1, field)

    extra = to_extraction_result(
        ScanResult(
            root="C:/tmp/demo",
            routes=[Route(path="/extra", method="POST", file="app.py", line=40)],
            languages=["go"],
            files_scanned=3,
            scanned_files=["app.py", "extra.py"],
        )
    )
    combined = merge_extraction_results(a, extra)
    assert len(combined.observations) == len(a.observations) + 1
    assert combined.languages == ["go", "python", "typescript"]
    assert combined.files_scanned == v1.files_scanned + 3
    assert combined.scanned_files == ["app.py", "client.ts", "extra.py"]
    # Extra's differing /extra route joins; nothing from `a` is reordered.
    assert combined.observations[: len(a.observations)] == a.observations
    combined_v1 = to_scan_result(combined)
    assert combined_v1.routes == [*v1.routes, Route(path="/extra", method="POST", file="app.py", line=40)]

    with pytest.raises(ValueError, match="different roots"):
        merge_extraction_results(a, ExtractionResult(root="C:/tmp/other"))
    with pytest.raises(ValueError, match="at least one"):
        merge_extraction_results()

    # Mixed v1-adapted and native v2 inputs degrade the source tag honestly.
    native = ExtractionResult(root="C:/tmp/demo")
    assert merge_extraction_results(a, native).source_protocol_version == "1.0"
    assert merge_extraction_results(native, native).source_protocol_version == "2.0"


def test_ar082_protocol_flip_keeps_v1_adapter_lossless() -> None:
    """AR082 / AC-403: the wire protocol declares "2.0" while the v1
    adapter — the only compatibility path for protocol-1.0 plugins —
    keeps lifting v1 ScanResults and lowering them back losslessly."""
    from attackmap.sdk.analyzer_contracts import EXTRACTION_PROTOCOL_VERSION

    assert EXTRACTION_PROTOCOL_VERSION == "2.0"
    v1 = _v1_scan_result()
    v2 = to_extraction_result(v1)
    # Adapted payloads stay honestly tagged as 1.0-sourced.
    assert v2.source_protocol_version == "1.0"
    assert v2.extraction_version == "2.0"
    back = to_scan_result(v2)
    for field in ROUND_TRIP_FIELDS:
        assert getattr(back, field) == getattr(v1, field), f"round-trip lost {field}"

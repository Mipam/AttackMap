"""AR047: a focused positive and a focused negative case per registered rule.

Every test here runs its rule through the harness (``run_rule`` resolves the
id through the registry), so each rule has a test that fails the moment it is
disabled or stops firing and one that fails the moment it over-fires. Where a
rule must stay silent on a fixture, the sibling rule that should fire on that
same fixture is asserted to fire: the negative fixture is shown to be live,
not empty.

The taint families are spec-driven (one rule per sink kind), so their cases
are parametrized over the registry's own ids and carry the ``rule`` marker per
case; a taint rule added later gets its cases without an edit here.

Fixtures are built in code from the model records the analyzers emit; nothing
is read from disk (``ROOT`` is only a label).
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest
from _harness import assert_rule_negative, assert_rule_positive, resolve_rule

from attackmap.model import (
    AuthHint,
    DatabaseHint,
    ExternalCall,
    Route,
    ScanResult,
    SecretHint,
    SupplyChainIssue,
    TaintChain,
    TaintFlowStep,
    Vulnerability,
    WebHardeningIssue,
    WorkflowIssue,
)
from attackmap.reasoning import REGISTRY, ReasoningContext

pytestmark = [pytest.mark.unit]

ROOT = "C:/tmp/fake-repo"  # a label only: nothing is read from disk

TAINT_SINK_IDS = tuple(rule_id for rule_id in REGISTRY.ids() if rule_id.startswith("taint_sink_"))
TAINT_SPECULATIVE_IDS = tuple(
    rule_id for rule_id in REGISTRY.ids() if rule_id.startswith("taint_speculative_")
)


def _focused(rule_ids: Iterable[str]) -> list[object]:
    """Parametrize entries that carry each case's ``rule`` marker."""
    return [pytest.param(rule_id, id=rule_id, marks=pytest.mark.rule(rule_id)) for rule_id in rule_ids]


def _scan(**slices: object) -> ScanResult:
    """A scan holding exactly the records given, e.g. ``_scan(routes=[...])``."""
    return ScanResult(root=ROOT, **slices)  # type: ignore[arg-type]


# --- every rule ----------------------------------------------------------------


@pytest.mark.parametrize("rule_id", _focused(REGISTRY.ids()))
def test_rule_stays_silent_when_nothing_was_observed(rule_id: str) -> None:
    assert_rule_negative(rule_id, ReasoningContext(), reason="a scan that observed nothing has nothing to report")


# --- demo_weak_default_credentials (the seed rule) -----------------------------


@pytest.mark.rule("demo_weak_default_credentials")
def test_default_credential_rule_fires_for_a_literal_default_credential() -> None:
    scan = _scan(
        secret_hints=[
            SecretHint(
                name="ADMIN_PASSWORD",
                file="app/config.py",
                line=12,
                kind="hardcoded",
                evidence_text="ADMIN_PASSWORD = '...'",
            )
        ]
    )
    findings = assert_rule_positive("demo_weak_default_credentials", scan, expect=1, at="app/config.py")
    assert findings[0].severity == "high"


@pytest.mark.rule("demo_weak_default_credentials")
def test_default_credential_rule_stays_silent_for_runtime_and_unrelated_secrets() -> None:
    runtime = _scan(secret_hints=[SecretHint(name="ADMIN_PASSWORD", file="app/config.py", kind="env_reference")])
    assert_rule_negative(
        "demo_weak_default_credentials",
        runtime,
        reason="an env reference names a value that resolves at runtime; nothing is hard-coded",
    )
    unrelated = _scan(secret_hints=[SecretHint(name="STRIPE_KEY", file="app/pay.py", kind="hardcoded")])
    assert_rule_negative(
        "demo_weak_default_credentials", unrelated, reason="the hint's name is not a default or admin credential"
    )
    assert_rule_positive("hardcoded_secret_literals", unrelated, expect=1)  # the fixture is live


# --- route_public_webhook -------------------------------------------------------


def _webhook_scan(method: str = "POST", *, linked: bool = True, **route_kwargs: object) -> ScanResult:
    route = Route(path="/webhook/payments", method=method, file="app/hooks.py", **route_kwargs)  # type: ignore[arg-type]
    chains = (
        [
            TaintChain(
                route_path=route.path,
                route_method=route.method,
                route_file=route.file,
                sink_kind="ssrf",
                sink_file="app/outbound.py",
                hops=1,
            )
        ]
        if linked
        else []
    )
    return _scan(routes=[route], taint_chains=chains)


@pytest.mark.rule("route_public_webhook")
def test_public_webhook_rule_fires_for_an_unguarded_mutating_webhook_with_an_outbound_call() -> None:
    findings = assert_rule_positive("route_public_webhook", _webhook_scan(), expect=1, at="app/hooks.py")
    assert findings[0].severity == "high"


@pytest.mark.rule("route_public_webhook")
def test_public_webhook_rule_stays_silent_behind_a_declared_guard() -> None:
    guarded = _webhook_scan(auth="required", guards=["requireSignature"])
    assert_rule_negative("route_public_webhook", guarded, reason="a plugin-declared guard protects the route")


@pytest.mark.rule("route_public_webhook")
def test_public_webhook_rule_stays_silent_for_read_only_and_unlinked_webhooks() -> None:
    assert_rule_negative(
        "route_public_webhook", _webhook_scan(method="GET"), reason="GET is not a mutating webhook method"
    )
    assert_rule_negative(
        "route_public_webhook",
        _webhook_scan(linked=False),
        reason="no route-linked datastore or outbound call is observed",
    )


# --- route_exposed_admin --------------------------------------------------------


@pytest.mark.rule("route_exposed_admin")
def test_exposed_admin_rule_fires_for_a_runtime_admin_route() -> None:
    scan = _scan(routes=[Route(path="/admin/users", method="GET", file="app/admin.py", line=10)])
    findings = assert_rule_positive("route_exposed_admin", scan, expect=1, at="app/admin.py")
    assert findings[0].severity == "high"


@pytest.mark.rule("route_exposed_admin")
def test_exposed_admin_rule_stays_silent_for_non_admin_routes() -> None:
    scan = _scan(routes=[Route(path="/api/users", method="GET", file="app/api.py")])
    assert_rule_negative("route_exposed_admin", scan, reason="the route is not an administrative path")


@pytest.mark.rule("route_exposed_admin")
def test_exposed_admin_rule_stays_silent_for_admin_routes_in_test_sources() -> None:
    scan = _scan(routes=[Route(path="/admin/users", method="GET", file="tests/admin_routes.py")])
    assert_rule_negative(
        "route_exposed_admin", scan, reason="routes under tests/ are not runtime surface"
    )


# --- route_upload_import --------------------------------------------------------


@pytest.mark.rule("route_upload_import")
def test_upload_import_rule_fires_for_an_upload_route() -> None:
    scan = _scan(routes=[Route(path="/upload", method="POST", file="app/upload.py", line=5)])
    assert_rule_positive("route_upload_import", scan, expect=1, at="app/upload.py")


@pytest.mark.rule("route_upload_import")
def test_upload_import_rule_stays_silent_for_examples_and_other_categories() -> None:
    example = _scan(routes=[Route(path="/import/data", method="POST", file="examples/upload_demo.py")])
    assert_rule_negative(
        "route_upload_import", example, reason="routes under examples/ are not runtime surface"
    )
    health = _scan(routes=[Route(path="/health", method="GET", file="app/health.py")])
    assert_rule_negative("route_upload_import", health, reason="the route is not an upload or import path")


# --- route_weak_auth_controls ---------------------------------------------------


def _login_scan() -> ScanResult:
    return _scan(routes=[Route(path="/login", method="POST", file="app/web.py", line=30)])


@pytest.mark.rule("route_weak_auth_controls")
def test_weak_auth_rule_fires_for_a_login_route_with_no_auth_indicator() -> None:
    assert_rule_positive("route_weak_auth_controls", _login_scan(), expect=1, at="app/web.py")


@pytest.mark.rule("route_weak_auth_controls")
def test_weak_auth_rule_stays_silent_with_an_auth_indicator_nearby_or_a_declared_guard() -> None:
    near = _login_scan()
    near.auth_hints.append(AuthHint(hint="jwt", file="app/web.py", line=35))
    assert_rule_negative(
        "route_weak_auth_controls",
        near,
        reason="an auth indicator sits inside the route's attribution window",
    )
    guarded = _scan(routes=[Route(path="/login", method="POST", file="app/web.py", line=30, auth="required")])
    assert_rule_negative(
        "route_weak_auth_controls", guarded, reason="a plugin-declared guard protects the route"
    )


# --- same_file_datastore_edge ---------------------------------------------------


@pytest.mark.rule("same_file_datastore_edge")
def test_same_file_datastore_rule_fires_when_a_route_and_a_datastore_share_a_file() -> None:
    scan = _scan(
        routes=[Route(path="/orders", method="POST", file="app/orders.py", line=3)],
        databases=[DatabaseHint(kind="sqlite", file="app/orders.py", line=8)],
    )
    findings = assert_rule_positive("same_file_datastore_edge", scan, expect=1, at="app/orders.py")
    assert findings[0].tags[-1] == "observed"


@pytest.mark.rule("same_file_datastore_edge")
def test_same_file_datastore_rule_stays_silent_when_the_datastore_is_in_another_file_of_the_module() -> None:
    cross_file = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="postgres", file="app/db.py", line=4)],
    )
    assert_rule_negative(
        "same_file_datastore_edge",
        cross_file,
        reason="co-location requires the same file; the module grade is another rule's finding",
    )
    assert_rule_positive("same_module_datastore_edge", cross_file, expect=1)  # the fixture is live


# --- same_file_external_edge ----------------------------------------------------


@pytest.mark.rule("same_file_external_edge")
def test_same_file_external_rule_fires_when_a_route_and_an_outbound_call_share_a_file() -> None:
    scan = _scan(
        routes=[Route(path="/proxy", method="GET", file="app/proxy.py")],
        external_calls=[ExternalCall(target="https://payments.example", file="app/proxy.py", line=12, method="POST")],
    )
    findings = assert_rule_positive("same_file_external_edge", scan, expect=1, at="app/proxy.py")
    assert findings[0].tags[-1] == "observed"


@pytest.mark.rule("same_file_external_edge")
def test_same_file_external_rule_stays_silent_when_the_call_is_in_another_file_of_the_module() -> None:
    cross_file = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        external_calls=[ExternalCall(target="https://api.example", file="app/client.py")],
    )
    assert_rule_negative(
        "same_file_external_edge",
        cross_file,
        reason="co-location requires the same file; the module grade is another rule's finding",
    )
    assert_rule_positive("same_module_external_edge", cross_file, expect=1)  # the fixture is live


# --- same_module_datastore_edge -------------------------------------------------


@pytest.mark.rule("same_module_datastore_edge")
def test_same_module_datastore_rule_fires_for_a_datastore_in_the_routes_module() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="postgres", file="app/db.py", line=4)],
    )
    findings = assert_rule_positive("same_module_datastore_edge", scan, expect=1, at="app/db.py")
    assert findings[0].confidence == "low"


@pytest.mark.rule("same_module_datastore_edge")
def test_same_module_datastore_rule_stays_silent_when_the_datastore_is_in_another_module() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="postgres", file="lib/db.py")],
    )
    assert_rule_negative(
        "same_module_datastore_edge",
        scan,
        reason="the module keys differ (app and lib), so the record is not co-located",
    )


# --- same_module_external_edge --------------------------------------------------


@pytest.mark.rule("same_module_external_edge")
def test_same_module_external_rule_fires_when_no_datastore_answers_for_the_module() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        external_calls=[ExternalCall(target="https://api.example", file="app/client.py")],
    )
    assert_rule_positive("same_module_external_edge", scan, expect=1, at="app/client.py")


@pytest.mark.rule("same_module_external_edge")
def test_same_module_external_rule_stays_silent_where_a_datastore_answers_first() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="postgres", file="app/db.py")],
        external_calls=[ExternalCall(target="https://api.example", file="app/client.py")],
    )
    assert_rule_negative(
        "same_module_external_edge",
        scan,
        reason="the cascade's priority: a same-module datastore answers before an external call",
    )
    assert_rule_positive("same_module_datastore_edge", scan, expect=1)  # the fixture is live


@pytest.mark.rule("same_module_external_edge")
def test_same_module_external_rule_stays_silent_when_the_call_is_in_another_module() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        external_calls=[ExternalCall(target="https://api.example", file="lib/http.py")],
    )
    assert_rule_negative(
        "same_module_external_edge",
        scan,
        reason="the module keys differ (app and lib), so the record is not co-located",
    )


# --- hardcoded_secret_literals / secret_env_references --------------------------


def _literal_hint() -> SecretHint:
    """A literal-secret hint as the scanner emits it: masked name, redacted snippet."""
    return SecretHint(
        name="exam…",
        file="app/settings.py",
        line=12,
        kind="credential_assignment",
        confidence=0.5,
        evidence_text='ADMIN_PASSWORD = "***"',
    )


@pytest.mark.rule("hardcoded_secret_literals")
def test_hardcoded_literal_rule_fires_for_a_literal_secret_hint() -> None:
    findings = assert_rule_positive(
        "hardcoded_secret_literals", _scan(secret_hints=[_literal_hint()]), expect=1, at="app/settings.py"
    )
    assert findings[0].severity == "high"


@pytest.mark.rule("hardcoded_secret_literals")
def test_hardcoded_literal_rule_stays_silent_when_every_hint_only_names_a_secret() -> None:
    named_only = _scan(
        secret_hints=[
            SecretHint(
                name="API_KEY",
                file="app/client.py",
                line=14,
                kind="env_reference",
                evidence_text='os.getenv("API_KEY")',
            ),
            SecretHint(
                name="JWT_SECRET",
                file=".env.example",
                line=2,
                kind="env_template",
                evidence_text="JWT_SECRET=${JWT_SECRET}",
            ),
        ]
    )
    assert_rule_negative(
        "hardcoded_secret_literals",
        named_only,
        reason="env references and templates name a secret without carrying its value",
    )
    assert_rule_positive("secret_env_references", named_only, expect=1)  # the fixture is live


@pytest.mark.rule("secret_env_references")
def test_secret_env_reference_rule_fires_for_an_env_reference_in_executable_code() -> None:
    scan = _scan(
        secret_hints=[
            SecretHint(
                name="API_KEY",
                file="app/client.py",
                line=14,
                kind="env_reference",
                evidence_text='os.getenv("API_KEY")',
            )
        ]
    )
    findings = assert_rule_positive("secret_env_references", scan, expect=1, at="app/client.py")
    assert findings[0].severity == "medium"


@pytest.mark.rule("secret_env_references")
def test_secret_env_reference_rule_stays_silent_for_literal_secrets_only() -> None:
    literals = _scan(secret_hints=[_literal_hint()])
    assert_rule_negative(
        "secret_env_references",
        literals,
        reason="a literal secret is the hardcoded-literal rule's finding, not an env reference",
    )
    assert_rule_positive("hardcoded_secret_literals", literals, expect=1)  # the fixture is live


# --- debug_mode_exposure --------------------------------------------------------


@pytest.mark.rule("debug_mode_exposure")
def test_debug_exposure_rule_fires_for_an_enabled_debug_flag() -> None:
    scan = _scan(
        web_hardening_issues=[
            WebHardeningIssue(
                kind="debug_enabled", file="app/settings.py", line=30, evidence_text="DEBUG = True", severity="medium"
            )
        ]
    )
    findings = assert_rule_positive("debug_mode_exposure", scan, expect=1, at="app/settings.py")
    assert findings[0].severity == "medium"


@pytest.mark.rule("debug_mode_exposure")
def test_debug_exposure_rule_stays_silent_for_other_web_hardening_issues() -> None:
    scan = _scan(
        web_hardening_issues=[
            WebHardeningIssue(
                kind="weak_csp", file="app/middleware.py", line=9, evidence_text="unsafe-inline", severity="medium"
            )
        ]
    )
    assert_rule_negative(
        "debug_mode_exposure", scan, reason="this rule owns only the debug_enabled kind of hardening issue"
    )


# --- vulnerable_dependency / workflow_security / supply_chain_risk --------------


def _advisory() -> Vulnerability:
    return Vulnerability(
        id="CVE-2020-8203",
        summary="Prototype pollution in lodash",
        severity="high",
        package_name="lodash",
        package_version="4.17.20",
        ecosystem="npm",
    )


def _unpinned_action() -> WorkflowIssue:
    return WorkflowIssue(
        kind="unpinned_action",
        file=".github/workflows/ci.yml",
        line=31,
        context="build",
        evidence_text="uses: actions/checkout@v4",
        severity="medium",
    )


def _unlocked_manifest() -> SupplyChainIssue:
    return SupplyChainIssue(
        kind="unlocked_manifest",
        file="package.json",
        ecosystem="npm",
        evidence_text="package.json declares dependencies but no lockfile is committed",
        severity="low",
    )


@pytest.mark.rule("vulnerable_dependency")
def test_vulnerable_dependency_rule_fires_for_an_advisory_on_a_resolved_package() -> None:
    findings = assert_rule_positive("vulnerable_dependency", _scan(vulnerabilities=[_advisory()]), expect=1)
    assert findings[0].title == "Vulnerable dependency: lodash@4.17.20 (npm)"
    assert findings[0].severity == "high"


@pytest.mark.rule("vulnerable_dependency")
def test_vulnerable_dependency_rule_stays_silent_without_advisories() -> None:
    dependency = _scan(supply_chain_issues=[_unlocked_manifest()])
    assert_rule_negative(
        "vulnerable_dependency",
        dependency,
        reason="a missing lockfile is a supply-chain risk, not a known advisory",
    )
    assert_rule_positive("supply_chain_risk", dependency, expect=1, at="package.json")  # the fixture is live


@pytest.mark.rule("workflow_security")
def test_workflow_rule_fires_for_an_unpinned_action() -> None:
    findings = assert_rule_positive("workflow_security", _scan(workflow_issues=[_unpinned_action()]), expect=1, at=".github/workflows/ci.yml")
    assert findings[0].confidence == "high"


@pytest.mark.rule("workflow_security")
def test_workflow_rule_stays_silent_without_workflow_issues() -> None:
    advisory = _scan(vulnerabilities=[_advisory()])
    assert_rule_negative(
        "workflow_security",
        advisory,
        reason="this rule reads workflow issues only; an advisory is the vulnerable-dependency rule's finding",
    )
    assert_rule_positive("vulnerable_dependency", advisory, expect=1)  # the fixture is live


@pytest.mark.rule("supply_chain_risk")
def test_supply_chain_risk_rule_fires_for_a_missing_lockfile() -> None:
    findings = assert_rule_positive("supply_chain_risk", _scan(supply_chain_issues=[_unlocked_manifest()]), expect=1, at="package.json")
    assert findings[0].severity == "low"


@pytest.mark.rule("supply_chain_risk")
def test_supply_chain_risk_rule_stays_silent_for_workflow_issues() -> None:
    ci = _scan(workflow_issues=[_unpinned_action()])
    assert_rule_negative(
        "supply_chain_risk",
        ci,
        reason="this rule reads dependency supply-chain issues only; an unpinned action is the workflow rule's finding",
    )
    assert_rule_positive("workflow_security", ci, expect=1)  # the fixture is live


# --- taint families: one rule per sink kind, parametrized over the registry ------


ROUTE_FILE = "app/web.py"
SINK_FILE = "svc/dynamic.py"


def _chain(sink_kind: str, **overrides: object) -> TaintChain:
    """A request-reachable chain; every field is overridable per fixture."""
    fields: dict[str, object] = {
        "route_path": "/run",
        "route_method": "POST",
        "route_file": ROUTE_FILE,
        "sink_kind": sink_kind,
        "sink_file": SINK_FILE,
        "sink_line": 10,
        "hops": 1,
        "files": [ROUTE_FILE, SINK_FILE],
    }
    fields.update(overrides)
    return TaintChain(**fields)  # type: ignore[arg-type]


def _traced(
    sink_kind: str, sink_file: str, sink_line: int, source_kind: str, **overrides: object
) -> TaintChain:
    """A chain whose request-derived source is traced into the sink's argument."""
    return _chain(
        sink_kind,
        sink_file=sink_file,
        sink_line=sink_line,
        confidence=0.8,
        source_kind=source_kind,
        source_line=sink_line - 1,
        flow=[
            TaintFlowStep(
                file=sink_file, line=sink_line - 1, kind="source", evidence_text="user_input = request.args['q']"
            ),
            TaintFlowStep(file=sink_file, line=sink_line, kind="sink", evidence_text=f"{sink_kind}(user_input)"),
        ],
        **overrides,
    )


def _chained(*chains: TaintChain) -> ScanResult:
    return _scan(taint_chains=list(chains))


def _kind(rule_id: str) -> str:
    """The sink kind a taint rule id names: ``taint_sink_eval`` -> ``eval``."""
    return rule_id.split("_", 2)[2]


def _other_kind(kind: str) -> str:
    """A sibling sink kind, so an "another kind" fixture is never empty."""
    kinds = sorted(_kind(rule_id) for rule_id in TAINT_SINK_IDS)
    return kinds[(kinds.index(kind) + 1) % len(kinds)]


def _unraisable(sink_kind: str, **overrides: object) -> ScanResult:
    """Chains no taint rule may raise: low-quality roots, then a sanitized flow."""
    low_quality = _chain(sink_kind, route_file="tests/test_run.py", **overrides)
    return _chained(
        low_quality,
        _chain(sink_kind, sink_file="fixtures/svc.py", **overrides),
        _chain(sink_kind, route_file="examples/demo.py", sink_file="examples/demo.py", **overrides),
        _chain(sink_kind, sanitized=True, sanitizer_evidence="markupsafe.escape", **overrides),
    )


@pytest.mark.parametrize("rule_id", _focused(TAINT_SINK_IDS))
def test_taint_sink_rule_fires_for_reach_to_its_own_sink_kind(rule_id: str) -> None:
    findings = assert_rule_positive(rule_id, _chained(_chain(_kind(rule_id))), expect=1, at=SINK_FILE)
    meta = resolve_rule(rule_id).meta
    assert (findings[0].title, findings[0].severity) == (meta.title, meta.severity)
    assert findings[0].confidence == "medium"  # the reach band


@pytest.mark.parametrize("rule_id", _focused(TAINT_SINK_IDS))
def test_taint_sink_rule_stays_silent_for_a_speculative_chain(rule_id: str) -> None:
    kind = _kind(rule_id)
    lead = _chained(_chain(kind, speculative=True, confidence=0.3))
    assert_rule_negative(
        rule_id, lead, reason="speculative reach is a recall lead, reported only by the speculative rule"
    )
    assert_rule_positive(f"taint_speculative_{kind}", lead, expect=1)  # the fixture is live


@pytest.mark.parametrize("rule_id", _focused(TAINT_SINK_IDS))
def test_taint_sink_rule_stays_silent_for_another_sink_kind(rule_id: str) -> None:
    other = _other_kind(_kind(rule_id))
    scan = _chained(_chain(other))
    assert_rule_negative(rule_id, scan, reason="a rule answers only its own sink kind")
    assert_rule_positive(f"taint_sink_{other}", scan, expect=1)  # the fixture is live


@pytest.mark.parametrize("rule_id", _focused(TAINT_SINK_IDS))
def test_taint_sink_rule_stays_silent_for_low_quality_roots_and_sanitized_flows(rule_id: str) -> None:
    assert_rule_negative(rule_id, _unraisable(_kind(rule_id)), reason="test/fixture/example evidence is down-ranked; a sanitized flow is never raised")


@pytest.mark.parametrize("rule_id", _focused(TAINT_SPECULATIVE_IDS))
def test_taint_speculative_rule_fires_for_a_speculative_chain_of_its_kind(rule_id: str) -> None:
    lead = _chained(_chain(_kind(rule_id), speculative=True, confidence=0.3))
    findings = assert_rule_positive(rule_id, lead, expect=1, at=SINK_FILE)
    meta = resolve_rule(rule_id).meta
    assert (findings[0].title, findings[0].severity) == (meta.title, "low")
    assert findings[0].confidence == "low"  # a lead, never asserted


@pytest.mark.parametrize("rule_id", _focused(TAINT_SPECULATIVE_IDS))
def test_taint_speculative_rule_stays_silent_for_a_confirmed_chain(rule_id: str) -> None:
    kind = _kind(rule_id)
    confirmed = _chained(_chain(kind))
    assert_rule_negative(
        rule_id, confirmed, reason="a confirmed reach is the sink rule's finding, never downgraded to a lead"
    )
    assert_rule_positive(f"taint_sink_{kind}", confirmed, expect=1)  # the fixture is live


@pytest.mark.parametrize("rule_id", _focused(TAINT_SPECULATIVE_IDS))
def test_taint_speculative_rule_stays_silent_for_another_sink_kind(rule_id: str) -> None:
    other = _other_kind(_kind(rule_id))
    scan = _chained(_chain(other, speculative=True, confidence=0.3))
    assert_rule_negative(rule_id, scan, reason="a rule answers only its own sink kind")
    assert_rule_positive(f"taint_speculative_{other}", scan, expect=1)  # the fixture is live


@pytest.mark.parametrize("rule_id", _focused(TAINT_SPECULATIVE_IDS))
def test_taint_speculative_rule_stays_silent_for_low_quality_roots_and_sanitized_flows(rule_id: str) -> None:
    assert_rule_negative(
        rule_id,
        _unraisable(_kind(rule_id), speculative=True, confidence=0.3),
        reason="test/fixture/example evidence is down-ranked; a sanitized flow is never raised",
    )


# --- taint_flow_sql_execute / taint_flow_path_traversal -------------------------


@pytest.mark.rule("taint_flow_sql_execute")
def test_sql_flow_rule_fires_for_a_traced_request_source() -> None:
    scan = _chained(_traced("sql_execute", "svc/db.py", 31, "query"))
    findings = assert_rule_positive("taint_flow_sql_execute", scan, expect=1, at="svc/db.py")
    assert findings[0].confidence == "high"  # a traced flow clears the high band
    assert findings[0].tags[:2] == ["taint-chain", "taint-flow"]


@pytest.mark.rule("taint_flow_sql_execute")
def test_sql_flow_rule_stays_silent_for_reach_without_a_traced_source() -> None:
    untraced = _chained(_chain("sql_execute", sink_file="svc/db.py", sink_line=31))
    assert_rule_negative(
        "taint_flow_sql_execute",
        untraced,
        reason="SQL reach alone is over-linking: only a traced request-derived source counts",
    )


@pytest.mark.rule("taint_flow_sql_execute")
def test_sql_flow_rule_stays_silent_for_a_sanitized_flow_and_other_kinds() -> None:
    sanitized = _chained(_traced("sql_execute", "svc/db.py", 31, "query", sanitized=True))
    assert_rule_negative(
        "taint_flow_sql_execute", sanitized, reason="a neutralized flow is kept as scan evidence, never raised"
    )
    other = _chained(_chain("eval"))
    assert_rule_negative("taint_flow_sql_execute", other, reason="a rule answers only its own flow kind")
    assert_rule_positive("taint_sink_eval", other, expect=1)  # the fixture is live


@pytest.mark.rule("taint_flow_path_traversal")
def test_path_flow_rule_fires_for_a_traced_dynamic_open() -> None:
    scan = _chained(_traced("dynamic_open", "svc/files.py", 20, "path_param"))
    findings = assert_rule_positive("taint_flow_path_traversal", scan, expect=1, at="svc/files.py")
    assert findings[0].confidence == "high"


@pytest.mark.rule("taint_flow_path_traversal")
def test_path_flow_rule_fires_for_a_request_gated_path_sink_on_reach_alone() -> None:
    gated = _chained(_chain("path_traversal", sink_file="svc/downloads.py", sink_line=5))
    assert_rule_positive("taint_flow_path_traversal", gated, expect=1, at="svc/downloads.py")


@pytest.mark.rule("taint_flow_path_traversal")
def test_path_flow_rule_stays_silent_for_a_speculative_open_and_other_kinds() -> None:
    speculative = _chained(_traced("dynamic_open", "svc/files.py", 20, "path_param", speculative=True))
    assert_rule_negative(
        "taint_flow_path_traversal",
        speculative,
        reason="a speculative chain of a flow kind is dropped at the flow gate, before the speculative bucket",
    )
    other = _chained(_chain("exec"))
    assert_rule_negative("taint_flow_path_traversal", other, reason="a rule answers only its own flow kind")
    assert_rule_positive("taint_sink_exec", other, expect=1)  # the fixture is live

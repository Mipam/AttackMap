"""Route/auth rule port (AR041, lease ``rules-routes``).

The aggregate route/auth finding branches of the legacy cascade
(``threat_model.generate_findings``) become named rules here. The cascade
STAYS the active producer until the wiring task (AR046); these rules must
stay field-for-field equivalent to the branches they port.

Legacy id mapping (roadmap card id -> registry id -> cascade ``rule_id``):

================= ========================== =========================
card id           registry id                cascade rule_id
================= ========================== =========================
``AM-ROUTE-001``  ``route_public_webhook``   ``public-webhook``
``AM-ROUTE-002``  ``route_exposed_admin``    ``exposed-admin-route``
``AM-ROUTE-003``  ``route_upload_import``    ``upload-route``
``AM-ROUTE-004``  ``route_weak_auth_controls`` ``weak-auth-route``
================= ========================== =========================

Branches deliberately NOT ported here (they need a ``ReasoningContext``
slice that :meth:`ReasoningContext.from_scan` deliberately excludes, so
porting them now could not honour the equivalence contract):

- ``unauth-state-change`` + the AM038 webhook-exposure ``public-webhook``
  variant (``route_auth_fusion.synthesize_unauthenticated_routes``):
  their surface predicates read ``category``/``exposure`` values the
  legacy classifier derives from service/edge/entrypoint/protocol/
  framework hints (the internal-handler downgrade), none of which the
  context carries; both also read repo files from disk, which the
  context contract forbids (``source_texts`` is never populated).
- ``unauth-outbound-integration`` and ``public-data-route``: their
  ``exposure == "public"`` predicate depends on that same downgrade.
- ``bola-modify`` / ``bola-read``: consume ``scan.authz_candidates``,
  explicitly excluded from the context (and produced by a pass that
  reads the repo).

Equivalence scope: the four ported predicates read only fields the
legacy internal-handler downgrade never touches (see
:func:`_surfaces_from_context`), so they match the cascade on every
input, not just hint-free fixtures. Findings carry ``rule_id=meta.id``
(kernel contract); their CWE/OWASP/ASVS/ATT&CK enrichment auto-attaches
from ``RULE_TAXONOMY`` by the stable id — AR046 registered each
snake_case id with exactly its legacy entry's data, so the fields stay
byte-identical to what the cascade branch emits. The dashed cascade ids
remain registered for the cascade period; each rule records them as
``legacy_rule_ids``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...model import AttackSurface, Finding
from ...policy import WEBHOOK_MUTATING_METHODS
from ..analyzer import _auth_hints_for_route
from ..threat_model import _finding_evidence, _is_low_quality_source, _locs
from .base import RuleMeta, confidence_band
from .registry import REGISTRY

if TYPE_CHECKING:
    from ...model import AuthHint, Route
    from ..context import ReasoningContext

__all__ = [
    "RouteExposedAdminRule",
    "RoutePublicWebhookRule",
    "RouteUploadImportRule",
    "RouteWeakAuthControlsRule",
]

# --- legacy-classifier reconstruction -----------------------------------------
#
# `identify_attack_surfaces` classifies each route by the first matching path
# segment group, in this order. The four ported predicates consume only
# `category` plus (for the webhook rule) `exposure`, and the legacy
# internal-handler downgrade (fed by the service/edge/entrypoint/protocol/
# framework hints the context deliberately excludes) never applies to the
# webhook/admin/auth categories and never changes the `category == "upload"`
# match — so this hint-free reconstruction is exact for every field these
# rules read.
_PATH_CATEGORY_SEGMENTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("webhook", ("webhook",)),
    ("admin", ("/admin", "/manage", "/root")),
    ("auth", ("/login", "/signin", "/signup", "/auth", "/session", "/token", "/oauth")),
    ("upload", ("/upload", "/import", "/file")),
    ("internal", ("/internal", "/debug")),
    ("health", ("/health", "/ready", "/live", "/metrics")),
)

# Sinks the legacy classifier counts as a route-linked datastore relationship.
_DATASTORE_SINK_KINDS = frozenset({"sql_execute", "nosql_injection"})

# Strong auth signals that disarm the webhook rule (legacy set, verbatim).
_STRONG_WEBHOOK_AUTH_SIGNALS = frozenset({"jwt", "oauth", "authorization", "service_auth"})


def _category_for_path(path_lower: str) -> str:
    """The legacy classifier's category assignment (hint-free subset)."""
    for category, segments in _PATH_CATEGORY_SEGMENTS:
        if any(segment in path_lower for segment in segments):
            return category
    return "public_api"


def _auth_signals_for_route(route: Route, auth_hints: tuple[AuthHint, ...]) -> list[str]:
    """The legacy per-route ``auth_signals`` attribution (verbatim semantics).

    A plugin-declared route auth state beats the file-window hint lookup;
    an explicitly anonymous route has no auth signals.
    """
    if route.auth == "required":
        return sorted(set(route.guards)) or ["plugin_declared_auth"]
    if route.auth == "anonymous":
        return []
    hints_by_file: dict[str, list[AuthHint]] = {}
    for hint in auth_hints:
        hints_by_file.setdefault(hint.file, []).append(hint)
    return _auth_hints_for_route(route, list(auth_hints), hints_by_file)


def _surfaces_from_context(ctx: ReasoningContext) -> list[AttackSurface]:
    """Rebuild the cascade's per-route surfaces from context slices alone.

    Only the fields the ported route/auth predicates (and the legacy
    evidence/locations formatters) consume are reproduced: ``category``,
    ``exposure``, ``auth_signals``, ``auth``, and the route-linked
    datastore/outbound relationship flags from non-speculative taint
    chains. ``risk`` and the hint-derived ``context_signals``/``rationale``
    are not consumed by any ported branch and are left at defaults.
    """
    surfaces: list[AttackSurface] = []
    for route in ctx.routes:
        chains = [
            chain
            for chain in ctx.taint_chains
            if chain.route_file == route.file
            and chain.route_path == route.path
            and chain.route_method == route.method
            and not chain.speculative
        ]
        category = _category_for_path(route.path.lower())
        # Exposure, hint-free: only internal-category paths differ from the
        # "public" default (legacy downgrade behaviour excluded — see module
        # docstring; no ported predicate reads it for those categories).
        surfaces.append(
            AttackSurface(
                route=route.path,
                method=route.method,
                file=route.file,
                line=route.line,
                category=category,  # type: ignore[arg-type]
                exposure="unknown" if category == "internal" else "public",
                risk="low",
                auth_signals=_auth_signals_for_route(route, ctx.auth_hints),
                auth=route.auth,
                data_store_interaction=any(c.sink_kind in _DATASTORE_SINK_KINDS for c in chains),
                outbound_integration=any(c.sink_kind == "ssrf" for c in chains),
            )
        )
    return surfaces


def _runtime_surfaces(ctx: ReasoningContext) -> list[AttackSurface]:
    """Surfaces behind the cascade's low-quality-source filter (verbatim)."""
    return [surface for surface in _surfaces_from_context(ctx) if not _is_low_quality_source(surface.file)]


def _emit(
    meta: RuleMeta,
    surfaces: list[AttackSurface],
    mitigation: str,
) -> list[Finding]:
    """One aggregated Finding, field-for-field the legacy branch's output.

    Evidence and locations reuse the cascade's own formatters so the
    strings match byte-for-byte; taxonomy/ATT&CK auto-attach from the
    registered stable id (``RULE_TAXONOMY``, AR046).
    """
    return [
        Finding(
            title=meta.title,
            rule_id=meta.id,
            severity=meta.severity,
            evidence=[_finding_evidence(surface) for surface in surfaces[:10]],
            locations=_locs(surfaces),
            mitigation=mitigation,
            confidence=confidence_band(meta.confidence),
            tags=list(meta.tags),
        )
    ]


class RoutePublicWebhookRule:
    """``AM-ROUTE-001`` (cascade ``public-webhook``): public webhook endpoints
    that pass attacker-controlled events toward a datastore or outbound call
    without strong auth signals.

    Ported from the ``webhook_surfaces`` branch of
    ``threat_model.generate_findings``. The AM038 per-handler webhook
    exposure variant in ``route_auth_fusion`` is a different producer and
    is NOT ported here (see module docstring).
    """

    meta = RuleMeta(
        id="route_public_webhook",
        title="Public webhook endpoint may trust attacker-controlled events",
        cwe="CWE-345",
        severity="high",
        confidence=0.9,
        rationale=(
            "A public mutating webhook route with a route-linked datastore or outbound "
            "relationship and no jwt/oauth/authorization/service auth signal likely trusts "
            "attacker-controlled events without verifying their origin (CWE-345)."
        ),
        tags=("exposed-endpoint", "auth-missing"),
    )
    legacy_rule_ids = ("public-webhook",)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        surfaces = [
            surface
            for surface in _runtime_surfaces(ctx)
            if surface.category == "webhook"
            and surface.exposure == "public"
            and surface.method in WEBHOOK_MUTATING_METHODS
            and (surface.data_store_interaction or surface.outbound_integration)
            and surface.auth != "required"
            and not any(signal in _STRONG_WEBHOOK_AUTH_SIGNALS for signal in surface.auth_signals)
        ]
        if not surfaces:
            return []
        return _emit(
            self.meta,
            surfaces,
            mitigation=(
                "Require signature verification before processing webhook payloads, "
                "reject replays, and keep any downstream state change behind strict validation."
            ),
        )


class RouteExposedAdminRule:
    """``AM-ROUTE-002`` (cascade ``exposed-admin-route``): administrative
    routes reachable from the main application surface.

    Ported from the ``admin_surfaces`` branch of
    ``threat_model.generate_findings`` (any runtime admin-category route).
    """

    meta = RuleMeta(
        id="route_exposed_admin",
        title="Administrative routes appear reachable from the main application surface",
        cwe="CWE-285",
        severity="high",
        confidence=0.9,
        rationale=(
            "Administrative routes sit on the main application surface where every caller "
            "can reach them; without a narrower boundary each one is a privileged-action "
            "foothold (CWE-285)."
        ),
        tags=("exposed-endpoint", "auth-missing", "privileged"),
    )
    legacy_rule_ids = ("exposed-admin-route",)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        surfaces = [surface for surface in _runtime_surfaces(ctx) if surface.category == "admin"]
        if not surfaces:
            return []
        return _emit(
            self.meta,
            surfaces,
            mitigation=(
                "Require strong authentication and explicit server-side authorization on every "
                "admin action, and move admin routes behind a narrower exposure boundary where "
                "possible."
            ),
        )


class RouteUploadImportRule:
    """``AM-ROUTE-003`` (cascade ``upload-route``): upload/import routes widen
    attacker-controlled input handling.

    Ported from the ``upload_surfaces`` branch of
    ``threat_model.generate_findings`` (any runtime upload-category route).
    """

    meta = RuleMeta(
        id="route_upload_import",
        title="Upload or import routes expand attacker-controlled input handling",
        cwe="CWE-434",
        severity="high",
        confidence=0.6,
        rationale=(
            "Upload and import routes accept attacker-controlled files, so parser abuse and "
            "untrusted-content handling become reachable input paths (CWE-434); the risk "
            "depends on the parsers behind them, hence medium confidence."
        ),
        tags=("exposed-endpoint", "input-handling"),
    )
    legacy_rule_ids = ("upload-route",)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        surfaces = [surface for surface in _runtime_surfaces(ctx) if surface.category == "upload"]
        if not surfaces:
            return []
        return _emit(
            self.meta,
            surfaces,
            mitigation=(
                "Constrain accepted formats, isolate parsers, scan uploaded content, and treat "
                "imported files as untrusted all the way through storage and processing."
            ),
        )


class RouteWeakAuthControlsRule:
    """``AM-ROUTE-004`` (cascade ``weak-auth-route``): authentication routes
    detected with no auth indicators near them.

    Ported from the ``auth_surfaces`` branch of
    ``threat_model.generate_findings`` (fires only when NO auth-category
    surface carries any auth signal).
    """

    meta = RuleMeta(
        id="route_weak_auth_controls",
        title="Authentication routes were detected without strong nearby auth controls",
        cwe="CWE-287",
        severity="medium",
        confidence=0.6,
        rationale=(
            "Authentication endpoints with no observed auth indicators nearby are common brute "
            "force and session-abuse targets; absence of indicators is weak evidence of absence "
            "of controls, hence medium severity and confidence (CWE-287)."
        ),
        tags=("exposed-endpoint", "auth-missing"),
    )
    legacy_rule_ids = ("weak-auth-route",)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        surfaces = [surface for surface in _runtime_surfaces(ctx) if surface.category == "auth"]
        if not surfaces or any(surface.auth_signals for surface in surfaces):
            return []
        return _emit(
            self.meta,
            surfaces,
            mitigation=(
                "Review these routes for rate limiting, credential validation, token or session "
                "handling, and the exact point where trust is established server-side."
            ),
        )


REGISTRY.register(RoutePublicWebhookRule())
REGISTRY.register(RouteExposedAdminRule())
REGISTRY.register(RouteUploadImportRule())
REGISTRY.register(RouteWeakAuthControlsRule())

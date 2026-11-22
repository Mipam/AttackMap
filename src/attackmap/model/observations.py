"""Extraction observations: hints, signals and the attack surface."""


from __future__ import annotations

from typing import Literal, get_args

from pydantic import BaseModel, Field, computed_field, model_validator

from ..redact import redact_text
from .evidence import _PROVENANCE_FIELD, _RedactedEvidence

RouteAuth = Literal["required", "anonymous", "unknown"]


# Package ecosystems a `DependencyHint` / `Vulnerability` may carry (#255).
# Exported from `attackmap.sdk`; `cve.py` maps each to its OSV.dev ecosystem
# (or marks it inventory-only when OSV has none).
DependencyEcosystem = Literal[
    "pypi",
    "npm",
    "go",
    "cargo",
    "composer",
    "swiftpm",
    "maven",
    "nuget",
    "conan",
    "vcpkg",
    "gem",
    "cocoapods",
    "hex",
    "pub",
]
DEPENDENCY_ECOSYSTEMS: tuple[str, ...] = get_args(DependencyEcosystem)


class Route(BaseModel):
    path: str
    method: str = "ANY"
    file: str
    line: int | None = None
    source_analyzer: str | None = _PROVENANCE_FIELD
    # Route-level auth as the plugin resolved it (#256): `required` (a guard
    # such as [Authorize] / @PreAuthorize / an auth middleware applies),
    # `anonymous` (explicitly public, e.g. [AllowAnonymous]), or `unknown`
    # (not determined — core falls back to its own resolution).
    auth: RouteAuth = "unknown"
    # Names of the guards that apply, e.g. ["[Authorize(Policy=Admin)]"].
    guards: list[str] = Field(default_factory=list)
    # Source text that established `auth` (redacted like other evidence).
    guard_evidence: str | None = None

    @model_validator(mode="after")
    def _redact_guard_evidence(self) -> Route:
        if self.guard_evidence:
            object.__setattr__(self, "guard_evidence", redact_text(self.guard_evidence))
        return self


class ExternalCall(_RedactedEvidence):
    target: str
    file: str
    line: int | None = None
    # HTTP verb of the outbound call, upper-cased (GET/POST/…), when the call
    # syntax carries one (`requests.get`, `axios.post`). `None` when unknown
    # (e.g. bare `fetch(url)`). Used by cross-repo contract linking (#146b) to
    # match an outbound call to another repo's route by method + path.
    method: str | None = None
    evidence_text: str | None = None
    source_analyzer: str | None = _PROVENANCE_FIELD


class DatabaseHint(_RedactedEvidence):
    kind: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    source_analyzer: str | None = _PROVENANCE_FIELD


class AuthHint(_RedactedEvidence):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class ServiceHint(_RedactedEvidence):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class EdgeHint(_RedactedEvidence):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class EntrypointHint(_RedactedEvidence):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class ProtocolHint(_RedactedEvidence):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class FrameworkHint(_RedactedEvidence):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class SecretHint(_RedactedEvidence):
    name: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.85
    source_analyzer: str | None = _PROVENANCE_FIELD
    # Optional classification. `env_reference` means we spotted a call
    # like `os.getenv("API_KEY")` — the value is at runtime. Anything
    # else identifies a literal secret pasted directly into code or
    # config (#39). Consumers can elevate hardcoded-literal findings
    # since exposure is broader than env references.
    kind: str = "env_reference"


class SecretHistoryHit(_RedactedEvidence):
    """A hard-coded secret found in git history (#252, ``--secrets-history``).

    ``name`` is the masked value; ``introduced_in`` is the oldest scanned
    commit that added it; ``still_in_head`` is False when a later commit
    removed it from the file (it remains in every clone's history).
    """

    name: str
    kind: str
    file: str
    line: int | None = None
    introduced_in: str
    still_in_head: bool
    evidence_text: str | None = None
    source_analyzer: str | None = _PROVENANCE_FIELD


class DependencyHint(_RedactedEvidence):
    """A single third-party dependency declared in a manifest or lockfile.

    Manifests (#48) carry version *ranges* verbatim (``^4.16.0``, ``>=2,<3``,
    ``latest``) and only direct dependencies. Lockfiles (#143) carry *exact*
    resolved versions and the full transitive tree — those hints set
    ``resolved=True`` and populate ``direct`` / ``via``.
    """

    name: str
    version: str
    ecosystem: DependencyEcosystem
    file: str
    line: int | None = None
    # dev / build-only dependency (``devDependencies``, ``require-dev``,
    # PEP-621 ``optional-dependencies[dev]``). Runtime consumers weight
    # these differently: a dev-time RCE still matters, but a dev-only
    # dep isn't part of the shipped attack surface.
    dev: bool = False
    # Lockfile-sourced provenance (#143). ``resolved`` marks an exact pinned
    # version (skip range-guessing in the CVE lookup). ``direct`` is False for
    # a transitive dependency; ``via`` is its resolution path from a direct
    # dependency, e.g. ``"express > body-parser > qs"``.
    resolved: bool = False
    direct: bool = True
    via: str | None = None
    evidence_text: str | None = None
    source_analyzer: str | None = _PROVENANCE_FIELD


class CodeWeakness(_RedactedEvidence):
    """A novel vulnerability-class weakness in source (#77).

    Emitted by the built-in `weaknesses` finder — bug classes beyond the
    taint/crypto/web-hardening families, detected from concrete risky
    constructs (not absence).
    """

    kind: Literal[
        "prototype_pollution",
        "mass_assignment",
        "jwt_weakness",
        "xxe",
        "redos",
        "insecure_upload",
        "graphql_exposure",
        "graphql_no_query_limits",
        "graphql_batching",
        "prompt_injection_attempt",
    ]
    file: str
    line: int | None = None
    evidence_text: str | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    source_analyzer: str | None = _PROVENANCE_FIELD


class Anomaly(BaseModel):
    """A within-repo consistency outlier — the odd-one-out in a peer group (#78).

    Emitted by the `anomalies` analyzer. Rather than matching a known-bad
    signature, it flags a route that deviates from the norm its siblings
    establish: peers in the same resource cohort carry an auth/validation
    signal (or are read-only) and this one doesn't. The bigger and more
    consistent the peer group, the more likely the deviation is a mistake —
    so `confidence` scales with `consistent_peers`.

    `invariant_violation` (#149a) is the mined-invariant variant: the cohort
    is not a route-path prefix but the set of handlers that reach the same
    dangerous sink kind, and the norm they establish is a *behavioural*
    invariant ("guard the request before the sink") rather than a static
    signal. When set, `invariant` states the mined rule as evidence.
    """

    kind: Literal[
        "auth_outlier",
        "validation_outlier",
        "method_outlier",
        "invariant_violation",
    ]
    route_path: str
    route_method: str
    route_file: str
    route_line: int | None = None
    peer_group: str  # the shared path-prefix cohort key (e.g. "api/users")
    peer_group_size: int  # total sibling routes in the cohort
    consistent_peers: int  # siblings that exhibit the norm this route breaks
    deviation: str  # human-readable description of what is odd
    # The mined invariant the flagged site violates (invariant_violation only) —
    # e.g. "9 of 10 handlers that reach a database (SQL execute) sink apply an
    # auth/validation guard before it". Cited as evidence.
    invariant: str | None = None
    peer_examples: list[str] = Field(default_factory=list)  # sample "METHOD path" peers
    severity: Literal["low", "medium", "high"] = "medium"
    confidence: float = 0.5
    source_analyzer: str | None = _PROVENANCE_FIELD


class WebHardeningIssue(_RedactedEvidence):
    """A web-hardening misconfiguration (#71).

    Emitted by the built-in web-hardening finder. Detects
    positively-present misconfigurations (wildcard CORS with credentials,
    explicit CSRF disable, insecure cookie flags, unsafe-inline/eval CSP,
    debug enabled) rather than hard-to-judge absences.
    """

    kind: Literal[
        "cors_wildcard_credentials",
        "cors_wildcard_origin",
        "cors_untrusted_origin",
        "csrf_disabled",
        "csrf_unprotected_session",
        "insecure_cookie",
        "weak_csp",
        "debug_enabled",
    ]
    file: str
    line: int | None = None
    evidence_text: str | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    source_analyzer: str | None = _PROVENANCE_FIELD


class SupplyChainIssue(_RedactedEvidence):
    """A dependency supply-chain risk beyond CVEs (#247).

    Emitted by the built-in, offline ``supply_chain`` pass over manifests,
    lockfiles and package-manager configs: dependency confusion, typosquat
    candidates, mutable VCS/URL dependencies, install scripts, unlocked
    manifests and insecure registries.
    """

    kind: Literal[
        "dependency_confusion",
        "typosquat_candidate",
        "mutable_vcs_dependency",
        "install_script",
        "unlocked_manifest",
        "insecure_registry",
    ]
    file: str
    line: int | None = None
    package: str | None = None
    ecosystem: str | None = None
    evidence_text: str | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    source_analyzer: str | None = _PROVENANCE_FIELD


class WorkflowIssue(_RedactedEvidence):
    """A CI-workflow security issue in a GitHub Actions file (#142).

    Emitted by the built-in workflow scanner over ``.github/workflows/*.yml``.
    Every issue is a positively-present misconfiguration (an unpinned action,
    an untrusted-code checkout under ``pull_request_target``, a secret or an
    attacker-controlled context interpolated into a shell step, ``write-all``
    permissions, a self-hosted runner on a PR trigger) — a hardened workflow
    produces nothing.
    """

    kind: Literal[
        "unpinned_action",
        "pr_target_checkout",
        "secret_in_run",
        "script_injection",
        "broad_permissions",
        "self_hosted_pr",
        # #246
        "workflow_run_artifact_poisoning",
        "issue_comment_pr_checkout",
        "github_script_injection",
        "github_env_injection",
        "default_token_permissions",
        "oidc_on_untrusted_trigger",
        "secrets_inherit",
        "checkout_persist_credentials",
        "cache_poisoning_pr_target",
        "docker_action_unpinned",
        "curl_pipe_shell",
    ]
    file: str
    line: int | None = None
    # Human-readable location within the workflow (job / step) so evidence
    # points somewhere actionable even when a precise line isn't available.
    context: str | None = None
    evidence_text: str | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    source_analyzer: str | None = _PROVENANCE_FIELD


class CryptoWeakness(_RedactedEvidence):
    """An insecure-cryptography or weak-randomness usage (#70).

    Emitted by the built-in crypto finder. Heuristic and regex-based;
    the noisy families (weak hash, insecure RNG) are gated on a
    security-context identifier to keep precision high.
    """

    kind: Literal[
        "weak_password_hash",
        "weak_cipher",
        "ecb_mode",
        "static_iv_salt",
        "insecure_random",
        "insecure_tls",
    ]
    file: str
    line: int | None = None
    evidence_text: str | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    source_analyzer: str | None = _PROVENANCE_FIELD


class BolaCandidate(_RedactedEvidence):
    """A route that may be missing object-level authorization (#69).

    Emitted by the authz analyzer when a route takes a resource
    identifier and reaches a datastore, but no ownership/authorization
    check is visible near the handler. Heuristic — the ownership-marker
    scan is the main false-positive reducer; confidence stays honest.
    """

    route_path: str
    route_method: str
    route_file: str
    route_line: int | None = None
    id_param: str  # the resource-id parameter/method detected
    # Where the object identifier arrives (#139): a path template param, an
    # id-bearing query parameter, an RPC method (XRPC/tRPC), or a GraphQL field.
    surface: Literal["path_param", "query_param", "rpc_method", "graphql_field"] = "path_param"
    reaches_db: bool = False
    db_evidence: str = ""  # how DB reachability was established
    has_ownership_check: bool = False  # True → suppressed (not a candidate)
    source_analyzer: str | None = _PROVENANCE_FIELD


class Vulnerability(BaseModel):
    """A known CVE / advisory affecting a resolved dependency (#60).

    One entry per (dep x advisory). ``package_version`` is the concrete
    lower-bound the CVE lookup resolved from the manifest spec — it may
    differ from the DependencyHint's raw ``version`` string.
    """

    id: str  # OSV entry id — CVE-2023-1234, GHSA-xxxx-xxxx, etc.
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    severity: Literal["low", "medium", "high"] = "medium"
    cvss_score: float | None = None
    references: list[str] = Field(default_factory=list)
    affected_range: str = ""  # human-readable "affected [lower, upper)" text
    package_name: str
    package_version: str
    ecosystem: DependencyEcosystem
    # Lockfile provenance (#143): False when the vulnerable package is a
    # transitive dependency; ``resolution_path`` is its chain from a direct
    # dependency (``"express > body-parser > qs"``) so the finding can say how
    # the vulnerable code was pulled in.
    direct: bool = True
    resolution_path: str = ""
    source_analyzer: str | None = _PROVENANCE_FIELD


SignalKind = Literal[
    "route",
    "external_call",
    "database",
    "auth",
    "service",
    "edge",
    "entrypoint",
    "protocol",
    "framework",
    "secret",
    "taint",
    "dependency",
]


SourceRole = Literal["production", "test", "fixture", "mock", "example", "generated", "unknown"]


class SignalClassification(BaseModel):
    classification_version: Literal["1.0"] | None = None
    source_role: SourceRole = "unknown"
    evidence_kind: Literal["static_extraction", "unknown"] = "unknown"
    classification_basis: Literal["unknown", "path_convention", "detector_owned", "artifact_manifest"] = "unknown"

    @model_validator(mode="after")
    def _require_positive_production_ownership(self):
        if self.source_role == "production" and self.classification_basis != "detector_owned":
            self.source_role = "unknown"
        return self


class SignalOrigin(SignalClassification):
    analyzer: str | None = None
    analyzer_version: str | None = None
    metadata_status: Literal["known", "legacy_unknown"] = "legacy_unknown"
    file: str | None = None
    line: int | None = None
    location_reason: str | None = None
    evidence_text: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)


class SignalConflict(BaseModel):
    field: str
    values: list[str] = Field(default_factory=list)


class Signal(_RedactedEvidence, SignalClassification):
    """Unified view of a single static-analysis signal.

    Synthesized from the typed hint lists on `ScanResult` via `all_signals()`.
    Existing analyzer plugins keep populating the typed hint lists; downstream
    consumers (insights, controls, asset detection, prompts) can iterate over
    the unified Signal stream to reason uniformly about location, confidence,
    and evidence.
    """

    kind: SignalKind
    label: str
    file: str
    line: int | None = None
    confidence: float = 0.7
    evidence_text: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)
    observation_id: str | None = None
    origins: list[SignalOrigin] = Field(default_factory=list)
    conflicts: list[SignalConflict] = Field(default_factory=list)

    def location(self) -> str:
        """Stable `file:line` reference if line known, else just file."""
        return f"{self.file}:{self.line}" if self.line is not None else self.file


class AttackSurface(BaseModel):
    route: str
    method: str
    file: str
    category: Literal["webhook", "admin", "auth", "upload", "internal", "health", "public_api"]
    exposure: Literal["public", "internal", "unknown"] = "public"
    risk: Literal["low", "medium", "high"]
    auth_signals: list[str] = Field(default_factory=list)
    # Nearby hints are candidates; only an analyzer-resolved route declaration
    # establishes an auth requirement. Unknown does not mean unauthenticated.
    auth: RouteAuth = "unknown"
    data_store_interaction: bool = False
    outbound_integration: bool = False
    relationship_basis: Literal["unknown", "inferred_route_chain"] = "unknown"
    context_signals: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    line: int | None = None

    @computed_field
    @property
    def evidence_class(self) -> str:
        from ..evidence import surface_evidence_class

        return surface_evidence_class(self)

    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line is not None else self.file


class AnalyzerError(BaseModel):
    """An analyzer whose ``analyze()`` raised or returned something unusable
    (#220). The scan carries on without it; this records the gap."""

    analyzer: str
    error_type: str
    message: str = ""

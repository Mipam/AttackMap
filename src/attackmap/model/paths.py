"""Taint paths and exploitability scoring models (#45, #79, #239)."""


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .evidence import _PROVENANCE_FIELD, _RedactedEvidence


class TaintFlowStep(_RedactedEvidence):
    """One step of an intra-procedural flow (#239): where the tainted value
    came from, each assignment it passed through, any sanitizer/guard bound to
    it, and the sink. Rendered as SARIF ``codeFlows``. ``evidence_text`` is
    the code at that step (redacted like other evidence)."""

    file: str
    line: int | None = None
    kind: Literal["source", "propagation", "sanitizer", "guard", "sink"]
    evidence_text: str | None = None


class TaintChain(_RedactedEvidence):
    """Cross-file data-flow evidence: a route reaches a sink via imports.

    Emitted by the lite taint analyzer (see #45). Each entry names the
    starting route, the sink kind and location, and the chain of files
    the import-walk traversed. Confidence encodes that import-edge is a
    heuristic proxy for call-edge — real dispatch may not hit the sink.
    """

    route_path: str
    route_method: str
    route_file: str
    sink_kind: Literal[
        "sql_execute",
        "subprocess_shell",
        "eval",
        "exec",
        "dynamic_open",
        "unsafe_deserialization",
        "ssti",
        "ssrf",
        "nosql_injection",
        "open_redirect",
        # #240 — `dynamic_open` stays as the schema-compatible alias of
        # `path_traversal` (#200).
        "path_traversal",
        "zip_slip",
        "code_injection",
        "expression_injection",
        "jndi_injection",
        "ldap_injection",
        "xpath_injection",
        "header_injection",
        "regex_injection",
    ]
    sink_file: str
    sink_line: int | None = None
    # Number of import edges walked. 0 = same file, 1 = direct import,
    # 2 = transitive (imported module imports the sink module).
    hops: int
    # Chain of files walked, ordered [route_file, ..., sink_file].
    files: list[str] = Field(default_factory=list)
    evidence_text: str | None = None
    confidence: float = 0.6
    # Sanitizer awareness (#137). When a known neutralizer for this sink kind
    # is present in the sink file (escaper/validator/parameter-binder/
    # allow-lister), the chain is marked sanitized and its confidence is
    # downgraded — the tainted value is likely neutralized before the sink.
    # `sanitizer_evidence` names the neutralizer so the chain stays auditable.
    sanitized: bool = False
    sanitizer_evidence: str | None = None
    # Recall mode (#148a). A chain surfaced only because an aggressive knob was
    # relaxed — beyond the default hop depth, or through a gate the default pass
    # keeps closed (a static-literal-looking sink argument) — is marked
    # speculative with downgraded confidence. Speculative chains are discovery
    # leads for the verifier to adjudicate, not asserted flows: they are kept
    # out of the `--fail-on-new-high` gate and clearly labelled in reports.
    speculative: bool = False
    # Intra-procedural flow (#239). Set when a request-derived value is traced
    # (through local assignments) into the sink's dangerous argument — or, for
    # a sanitized chain, into the sanitizer/guard that neutralizes it.
    # `source_kind` is the catalog kind (query, body, path_param, header,
    # cookie, upload_filename, message); `source_line` is in `sink_file`.
    # None when no flow was established (reachability-only chain).
    source_kind: str | None = None
    source_line: int | None = None
    flow: list[TaintFlowStep] = Field(default_factory=list)
    source_analyzer: str | None = _PROVENANCE_FIELD


ExploitabilityTier = Literal["critical", "high", "medium", "low"]


class ExploitabilityFactor(BaseModel):
    """One named, signed contribution to an exploitability score (#79).

    Kept explicit so every score is explainable — the report shows exactly
    which signals raised (or, at 0 points, notably did not raise) the number.
    """

    name: str  # e.g. "public exposure", "no auth at entry", "reaches sql_execute sink"
    points: int
    detail: str = ""  # concrete evidence for this factor


class ExploitabilityChainIdentity(BaseModel):
    """The typed taint merge identity, not an observation/prose similarity key."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    route_method: str
    route_path: str
    route_file: str
    sink_kind: str
    sink_file: str
    sink_line: int | None = None


class ExploitabilityScoreReference(BaseModel):
    """Producer-local integrity reference; never publisher/runtime attestation."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    version: Literal["route-sink/v1"] = "route-sink/v1"
    score_id: str = Field(pattern=r"^score/v1:[0-9a-f]{64}$")
    repository_root: str | None = None
    snapshot_id: str | None = None
    scope: Literal["repository_snapshot", "unverified"]
    chain: ExploitabilityChainIdentity

    @staticmethod
    def context(repository_root: str | None, snapshot_id: str | None) -> tuple[str | None, str | None, str]:
        import re

        root = repository_root if isinstance(repository_root, str) and repository_root.strip() else None
        if root is not None and any(ord(c) < 32 for c in root):
            root = None
        snapshot = snapshot_id if isinstance(snapshot_id, str) and re.fullmatch(r"[0-9a-f]{64}", snapshot_id) else None
        absolute = root is not None and (root.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", root) is not None)
        return root, snapshot, "repository_snapshot" if absolute and snapshot is not None else "unverified"

    @staticmethod
    def identity(repository_root: str | None, snapshot_id: str | None, chain: ExploitabilityChainIdentity) -> str:
        import hashlib
        import json

        payload = ["route-sink/v1", repository_root, snapshot_id, chain.model_dump()]
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        return "score/v1:" + hashlib.sha256(encoded).hexdigest()

    @classmethod
    def from_chain(cls, chain: TaintChain, *, repository_root: str | None, snapshot_id: str | None):
        root, snapshot, scope = cls.context(repository_root, snapshot_id)
        key = ExploitabilityChainIdentity(**{name: getattr(chain, name) for name in ExploitabilityChainIdentity.model_fields})
        return cls(score_id=cls.identity(root, snapshot, key), repository_root=root,
                   snapshot_id=snapshot, scope=scope, chain=key)

    @model_validator(mode="after")
    def _consistent_reference(self):
        root, snapshot, scope = self.context(self.repository_root, self.snapshot_id)
        if root != self.repository_root or snapshot != self.snapshot_id:
            raise ValueError("Unsupported score reference context")
        if self.scope == "repository_snapshot" and scope != self.scope:
            raise ValueError("Snapshot-scoped score reference needs absolute repository and snapshot identity")
        if self.score_id != self.identity(root, snapshot, self.chain):
            raise ValueError("Score reference does not match its producer identity")
        return self


class ExploitabilityScore(BaseModel):
    """A fused 'exploitable now' score for one route→sink combination (#79).

    Deterministic: the same scan always yields the same score, and `factors`
    sums (before the 0-100 clamp) to `raw_score`, so nothing is hidden.
    """

    subject: str  # human label, e.g. "GET /search → sql_execute"
    route: str
    method: str
    sink_kind: str
    location: str  # sink file:line
    score: int  # 0-100 (clamped)
    raw_score: int  # pre-clamp sum of factor points
    tier: ExploitabilityTier
    factors: list[ExploitabilityFactor] = Field(default_factory=list)
    producer_reference: ExploitabilityScoreReference | None = None


class AttackPath(BaseModel):
    name: str
    steps: list[str]
    impact: str

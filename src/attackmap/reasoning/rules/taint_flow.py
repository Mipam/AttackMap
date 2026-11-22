"""Taint / data-flow rules (AR044): the flow-derived findings of the legacy
cascade (``threat_model.generate_findings``, the "Dangerous taint sinks",
"Flow-confirmed SQL injection / path traversal" and "Speculative recall
findings" blocks), ported 1:1 into kernel rules.

The legacy cascade STAYS the active producer until the wiring pass flips
findings over to ``REGISTRY``; these rules are proven equivalent on fixtures
(``tests/rules/test_taint_flow.py``) and change no pipeline behavior.

Three families, one registered rule per sink kind. ``RuleMeta.id`` values are
the new stable snake_case identities; the ``Finding.rule_id`` each rule emits
stays the LEGACY detector id so SARIF ruleIds, suppression keys and the
taxonomy registry (``model.taxonomy`` is keyed by the legacy ids) keep working
unchanged. The recorded legacy mapping:

==========================  ==================================  ==========================
``RuleMeta.id``             family                              legacy ``Finding.rule_id``
==========================  ==================================  ==========================
``taint_sink_<kind>``       aggregated reach to a dangerous     ``<kind with _ as ->>``
                            sink (``TAINT_FINDING_SPEC``)       (e.g. ``taint_sink_subprocess_shell`` -> ``subprocess-shell``)
``taint_flow_<kind>``       flow-confirmed SQL / path traversal ``spec["rule_id"]``
                            (``FLOW_FINDING_SPEC``)             (``taint_flow_sql_execute`` -> ``sql-injection``, ``taint_flow_path_traversal`` -> ``path-traversal``)
``taint_speculative_<kind>`` recall-mode speculative reach      ``speculative-<slug>``
                            (low severity, leads only)          (e.g. ``taint_speculative_eval`` -> ``speculative-eval``)
==========================  ==================================  ==========================

Preserved verbatim from the legacy blocks:

* evidence strings, locations (sink locations then route locations), tags,
  titles and severities from the spec tables, ATT&CK techniques;
* the aggregated per-kind shape: one finding per kind present, top chain by
  ``(hops, -confidence)``, "+N more route(s)" overflow line, at most 10 traced
  flow evidence lines and 20 SARIF codeFlows;
* confidence bands exactly as the cascade computed them — ``medium`` for
  reach findings, ``high`` iff any chain confidence >= 0.75 for flow-confirmed
  findings (chain confidence itself is produced upstream by the unchanged
  ``taint._confidence_for_hops`` mapping), ``low`` for speculative ones.

Not ported (needs slices outside the read-only ``ReasoningContext``, owned by
another task): the exploitability fusion that attaches
``finding.exploitability`` / ``exploitability_tier`` /
``exploitability_reference`` afterwards (``score_exploitability`` + attack
surface lookup need crypto weaknesses, databases, dependencies and attack
surfaces). The wiring pass must keep applying that fusion to these rules'
findings.

Low-quality sources: the legacy cascade never surfaces chains rooted under
``tests/``, ``fixtures/``, ``examples/`` etc. because the scan-time file
index skips them (``is_test_file`` / ``is_vendored_file``). Rules see
pre-built chains, so they apply the same policy segment list
(``policy.LOW_QUALITY_SEGMENTS``, the ``threat_model._is_low_quality_source``
shape) and skip chains whose route or sink evidence is rooted in a
low-quality source — reproducing the cascade's observable end-to-end
behavior ("no findings from test/fixture/example evidence") at the rule
layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...model import AttackTechnique, Finding, FindingLocation, TaintChain, TaintFlowStep
from ...model.taxonomy import cwe_tag, taxonomy_for
from ...policy import LOW_QUALITY_SEGMENTS
from ..rule_specs import FLOW_FINDING_SPEC, TAINT_FINDING_SPEC, TAINT_SINK_LABEL
from ..taint_sinks import canonical_kind
from .base import RuleMeta
from .registry import REGISTRY

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..context import ReasoningContext

__all__ = [
    "FLOW_SINK_RULES",
    "SPECULATIVE_RULES",
    "TAINT_SINK_RULES",
    "FlowConfirmedSinkRule",
    "SpeculativeTaintKindRule",
    "TaintSinkKindRule",
]

# Caps ported verbatim from the legacy block: per-route flow lines cited in
# one aggregated taint finding, and the SARIF codeFlows it carries.
_MAX_FLOW_EVIDENCE = 10
_MAX_CODE_FLOWS = 20

# Raw sink kinds the flow family treats as flow-gated: reach alone is not a
# finding — only a traced request-derived source counts (their sibling
# request-gated path sinks don't need the trace).
_FLOW_TRACED_GATED_KINDS = frozenset({"sql_execute", "dynamic_open"})


# --- helpers ported verbatim from the legacy block --------------------------


def _rule_slug_kind(kind: str) -> str:
    """Legacy rule id for a spec-driven detector family: its kind, dashed."""
    return kind.replace("_", "-")


def _cwe_tags(kind: str) -> list[str]:
    """`external/cwe/cwe-NNN` finding tags from the taxonomy registry."""
    entry = taxonomy_for(_rule_slug_kind(kind))
    return [cwe_tag(c) for c in entry.cwe] if entry else []


def _is_low_quality_source(path_or_text: str) -> bool:
    """Same source-quality shape as ``threat_model._is_low_quality_source``."""
    normalized = path_or_text.replace("\\", "/").lower()
    return any(segment in f"/{normalized}/" for segment in LOW_QUALITY_SEGMENTS)


def _reportable_chains(ctx: ReasoningContext) -> list[TaintChain]:
    """Chains eligible for findings: sanitized chains are neutralized before
    the sink (kept as evidence in the scan, never raised), and chains whose
    route or sink evidence is rooted in a low-quality source are excluded —
    the legacy cascade never produces those (scan-time index gate)."""
    return [
        chain
        for chain in ctx.taint_chains
        if not chain.sanitized
        and not _is_low_quality_source(chain.route_file)
        and not _is_low_quality_source(chain.sink_file)
    ]


def _locs(
    chains: Iterable[TaintChain], file_attr: str, line_attr: str
) -> list[FindingLocation]:
    """Structured locations for every chain behind a finding (dedup by
    file+line, preserving order) — the legacy ``_locs`` behavior."""
    out: list[FindingLocation] = []
    seen: set[tuple[str, int | None]] = set()
    for chain in chains:
        file = getattr(chain, file_attr, None)
        if not file:
            continue
        line = getattr(chain, line_attr, None)
        key = (file, line)
        if key not in seen:
            seen.add(key)
            out.append(FindingLocation(file=file, line=line))
    return out


def _chain_locations(chains: list[TaintChain]) -> list[FindingLocation]:
    """Sink locations first, then route locations — the legacy layout."""
    return _locs(chains, "sink_file", "sink_line") + _locs(chains, "route_file", "route_line")


def _flow_evidence(chains: list[TaintChain]) -> list[str]:
    """One `flow:` evidence line per distinct route with a traced source."""
    lines: list[str] = []
    seen: set[tuple[str, str, str, int | None]] = set()
    traced = [c for c in chains if c.source_kind]
    for c in sorted(traced, key=lambda c: (c.hops, c.route_file, c.sink_line or 0, c.route_path)):
        key = (c.route_method, c.route_path, c.sink_file, c.sink_line)
        if key in seen:
            continue
        seen.add(key)
        if len(lines) == _MAX_FLOW_EVIDENCE:
            lines.append(f"+{len(traced) - _MAX_FLOW_EVIDENCE} more traced flow(s)")
            break
        lines.append(
            f"flow: {c.route_method} {c.route_path} — {c.source_kind} source at "
            f"{c.sink_file}:{c.source_line} → sink at {c.sink_file}:{c.sink_line}"
        )
    return lines


def _code_flows(chains: list[TaintChain]) -> list[list[TaintFlowStep]]:
    """Distinct traced flows (by sink + source) for SARIF codeFlows."""
    out: list[list[TaintFlowStep]] = []
    seen: set[tuple[str, int | None, int | None]] = set()
    for c in chains:
        if not c.flow:
            continue
        key = (c.sink_file, c.sink_line, c.source_line)
        if key in seen:
            continue
        seen.add(key)
        out.append(list(c.flow))
        if len(out) == _MAX_CODE_FLOWS:
            break
    return out


def _technique(spec: dict[str, str]) -> list[AttackTechnique]:
    """The spec table's ATT&CK technique, built the legacy way. Note: the
    Finding model validator replaces this from the taxonomy registry when the
    legacy rule id is registered there — identical on both sides."""
    return [
        AttackTechnique(
            technique_id=spec["technique_id"],
            name=spec["technique_name"],
            tactic=spec["tactic"],
            url=f"https://attack.mitre.org/techniques/{spec['technique_id'].replace('.', '/')}/",
        )
    ]


def _top_chain(chains: list[TaintChain]) -> TaintChain:
    """Closest sink first, ties broken by higher confidence (legacy key)."""
    return min(chains, key=lambda c: (c.hops, -c.confidence))


def _meta_cwe(kind: str, legacy_rule_id: str) -> str:
    """Representative CWE for the rule metadata from the taxonomy registry."""
    entry = taxonomy_for(legacy_rule_id) or taxonomy_for(_rule_slug_kind(kind))
    return f"CWE-{entry.cwe[0]}" if entry and entry.cwe else ""


# --- rule families ----------------------------------------------------------


class TaintSinkKindRule:
    """Aggregated "request-reachable <sink>" finding for one dangerous-sink
    kind (``TAINT_FINDING_SPEC``). Reach alone is the evidence here — these
    sink kinds are dangerous regardless of the argument's shape, so a
    non-speculative chain from a route is enough (matching the legacy gate)."""

    def __init__(self, meta: RuleMeta, kind: str) -> None:
        self.meta = meta
        self._kind = kind
        self._legacy_rule_id = _rule_slug_kind(kind)
        self._label = TAINT_SINK_LABEL.get(kind, kind)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        chains = [
            chain
            for chain in _reportable_chains(ctx)
            if chain.sink_kind == self._kind and not chain.speculative
        ]
        if not chains:
            return []
        top = _top_chain(chains)
        evidence = [
            f"route {top.route_method} {top.route_path} in {top.route_file}",
            f"sink at {top.sink_file}:{top.sink_line} ({self._label})",
            f"import path: {' → '.join([*top.files])} ({top.hops} hop(s))",
        ]
        if len(chains) > 1:
            evidence.append(f"+{len(chains) - 1} more route(s) reach a {self._label} sink")
        evidence += _flow_evidence(chains)
        spec = TAINT_FINDING_SPEC[self._kind]
        finding = Finding(
            title=spec["title"],
            rule_id=self._legacy_rule_id,
            severity=spec["severity"],  # type: ignore[arg-type]
            evidence=evidence,
            locations=_chain_locations(chains),
            mitigation=spec["mitigation"],
            confidence="medium",
            tags=["taint-chain", "input-handling", "data-risk"],
            attack_techniques=_technique(spec),
        )
        finding.code_flows = _code_flows(chains)
        return [finding]


class FlowConfirmedSinkRule:
    """Flow-confirmed SQL injection / path traversal for one canonical flow
    kind (``FLOW_FINDING_SPEC``; ``dynamic_open`` is the schema alias of
    ``path_traversal``). Reach alone is not a finding for the trace-gated
    kinds — only a chain with a traced request-derived source counts; the
    #240 path sinks are request-gated at the scan layer already, so their
    chains count (legacy ``confirmed`` check, kept verbatim)."""

    def __init__(self, meta: RuleMeta, kind: str, legacy_rule_id: str) -> None:
        self.meta = meta
        self._kind = kind
        self._legacy_rule_id = legacy_rule_id
        self._label = TAINT_SINK_LABEL.get(kind, kind)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        chains = []
        for chain in _reportable_chains(ctx):
            if canonical_kind(chain.sink_kind) != self._kind or chain.speculative:
                continue
            confirmed = chain.source_kind or chain.sink_kind not in _FLOW_TRACED_GATED_KINDS
            if confirmed:
                chains.append(chain)
        if not chains:
            return []
        top = _top_chain(chains)
        evidence = [
            f"route {top.route_method} {top.route_path} in {top.route_file}",
            f"sink at {top.sink_file}:{top.sink_line} ({self._label})",
            f"import path: {' → '.join(top.files)} ({top.hops} hop(s))",
            *_flow_evidence(chains),
        ]
        spec = FLOW_FINDING_SPEC[self._kind]
        return [
            Finding(
                title=spec["title"],
                rule_id=self._legacy_rule_id,
                severity=spec["severity"],  # type: ignore[arg-type]
                evidence=evidence,
                locations=_chain_locations(chains),
                mitigation=spec["mitigation"],
                confidence="high" if any(c.confidence >= 0.75 for c in chains) else "medium",
                tags=["taint-chain", "taint-flow", "input-handling", "data-risk"],
                attack_techniques=_technique(spec),
                code_flows=_code_flows(chains),
            )
        ]


class SpeculativeTaintKindRule:
    """Recall-mode speculative reach to one sink kind: clearly-marked,
    low-severity leads for ``--hunt --verify`` to adjudicate — never asserted
    flows, kept out of the ``--fail-on-new-high`` gate (legacy #148a block).
    Speculative chains of the flow-family kinds produce nothing, exactly as
    in the legacy bucketing (the flow gate `continue`s before the
    speculative bucket)."""

    def __init__(self, meta: RuleMeta, kind: str) -> None:
        self.meta = meta
        self._kind = kind
        self._legacy_rule_id = f"speculative-{_rule_slug_kind(kind)}"
        self._label = TAINT_SINK_LABEL.get(kind, kind)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        chains = [
            chain
            for chain in _reportable_chains(ctx)
            if chain.sink_kind == self._kind and chain.speculative
        ]
        if not chains:
            return []
        top = _top_chain(chains)
        spec = TAINT_FINDING_SPEC[self._kind]
        evidence = [
            "SPECULATIVE (recall mode): surfaced by widened discovery, not confirmed — "
            "adjudicate with --hunt --verify",
            f"route {top.route_method} {top.route_path} in {top.route_file}",
            f"sink at {top.sink_file}:{top.sink_line} ({self._label}), {top.hops} hop(s)",
        ]
        if len(chains) > 1:
            evidence.append(f"+{len(chains) - 1} more speculative route(s) reach a {self._label} sink")
        return [
            Finding(
                title=f"Speculative reach to a {self._label} sink (recall mode)",
                rule_id=self._legacy_rule_id,
                severity="low",
                evidence=evidence,
                locations=_chain_locations(chains),
                mitigation=(
                    "Recall mode widened taint discovery to surface this reach; provenance "
                    "is unconfirmed. Verify whether untrusted input actually reaches the sink "
                    f"(run `--hunt --verify`). If it does, treat it as a {spec['title'].lower()}."
                ),
                confidence="low",
                tags=["taint-chain", "speculative", "recall"],
                attack_techniques=_technique(spec),
            )
        ]


# --- registration -----------------------------------------------------------


def _taint_sink_rules() -> list[TaintSinkKindRule]:
    rules: list[TaintSinkKindRule] = []
    for kind, spec in TAINT_FINDING_SPEC.items():
        meta = RuleMeta(
            id=f"taint_sink_{kind}",
            title=spec["title"],
            cwe=_meta_cwe(kind, _rule_slug_kind(kind)),
            severity=spec["severity"],  # type: ignore[arg-type]
            # Reachability-heuristic detection: import != call, so the rule's
            # own trust in its detection is "medium" (0.6). Emitted findings
            # keep the legacy band ("medium") regardless.
            confidence=0.6,
            rationale=(
                f"A route reaches a {TAINT_SINK_LABEL.get(kind, kind)} sink ({_rule_slug_kind(kind)}) "
                "via the import graph without a neutralizing sanitizer; untrusted input reaching "
                "this sink class is a direct compromise path. Ported 1:1 from the legacy taint "
                "cascade so the finding fields (evidence, locations, tags, confidence band) stay "
                "byte-identical."
            ),
            tags=("taint-chain", "input-handling"),
        )
        rules.append(TaintSinkKindRule(meta, kind))
    return rules


def _flow_sink_rules() -> list[FlowConfirmedSinkRule]:
    rules: list[FlowConfirmedSinkRule] = []
    for kind, spec in FLOW_FINDING_SPEC.items():
        meta = RuleMeta(
            id=f"taint_flow_{kind}",
            title=spec["title"],
            cwe=_meta_cwe(kind, spec["rule_id"]),
            severity=spec["severity"],  # type: ignore[arg-type]
            # A traced request-source-to-sink flow is the strongest evidence
            # this family emits; the rule's own detection trust is "high"-
            # leaning (0.75). Emitted findings keep the legacy chain-derived
            # band ("high" iff any chain confidence >= 0.75).
            confidence=0.75,
            rationale=(
                f"A request-derived value is traced into a {TAINT_SINK_LABEL.get(kind, kind)} sink "
                f"({spec['rule_id']}); a traced flow is injection-grade evidence, not just "
                "reachability. Ported 1:1 from the legacy flow-confirmed cascade block."
            ),
            tags=("taint-chain", "taint-flow"),
        )
        rules.append(FlowConfirmedSinkRule(meta, kind, spec["rule_id"]))
    return rules


def _speculative_rules() -> list[SpeculativeTaintKindRule]:
    rules: list[SpeculativeTaintKindRule] = []
    for kind in TAINT_FINDING_SPEC:  # declaration order (matches the legacy block)
        label = TAINT_SINK_LABEL.get(kind, kind)
        meta = RuleMeta(
            id=f"taint_speculative_{kind}",
            title=f"Speculative reach to a {label} sink (recall mode)",
            cwe=_meta_cwe(kind, _rule_slug_kind(kind)),
            severity="low",
            # Speculative chains surfaced by widened discovery are unconfirmed
            # leads (0.3); emitted findings stay at the legacy "low" band.
            confidence=0.3,
            rationale=(
                "Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it "
                "adds is unconfirmed until a verifier adjudicates it, so it must be reported "
                "separately and can never clear the HIGH bar. Ported 1:1 from the legacy "
                f"speculative block for {label}."
            ),
            tags=("taint-chain", "speculative", "recall"),
        )
        rules.append(SpeculativeTaintKindRule(meta, kind))
    return rules


TAINT_SINK_RULES = _taint_sink_rules()
FLOW_SINK_RULES = _flow_sink_rules()
SPECULATIVE_RULES = _speculative_rules()

for _rule in (*TAINT_SINK_RULES, *FLOW_SINK_RULES, *SPECULATIVE_RULES):
    REGISTRY.register(_rule)

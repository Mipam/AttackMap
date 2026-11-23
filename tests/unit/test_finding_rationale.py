"""AR049 / AC-207: every Finding is self-explaining.

Every finding a scan emits carries a non-empty ``rationale`` (why the rule
exists plus the concrete observation that fired) and at least one ``evidence``
reference. These tests assert the invariant on registry rules, on the legacy
cascade families, and on the report.json a real fixture-repo scan produces.
"""

from __future__ import annotations

import json
from pathlib import Path

from attackmap.model import Finding, Route, ScanResult, SecretHint, WebHardeningIssue
from attackmap.output.defensive_review import render_defensive_review
from attackmap.output.finding_presentation import FindingPresentationIndex
from attackmap.output.sarif import build_sarif
from attackmap.reasoning import REGISTRY, ReasoningContext
from attackmap.reasoning.rules import evaluate_rules
from attackmap.reasoning.rules.base import RuleMeta
from attackmap.reasoning.threat_model import generate_findings


def _assert_self_explaining(findings: list[Finding]) -> None:
    for finding in findings:
        assert finding.rationale.strip(), (
            f"finding {finding.rule_id or finding.title!r} carries an empty rationale"
        )
        assert finding.evidence, (
            f"finding {finding.rule_id or finding.title!r} carries no evidence reference"
        )


def _kitchen_sink_scan(root: Path) -> ScanResult:
    """A small in-code scan exercising several registry rules and the legacy
    unauth-state-change fusion (which reads handler source from ``root``)."""
    (root / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/api/run', methods=['POST'])\n"
        "def run_command():\n"
        "    return request.form['command']\n",
        encoding="utf-8",
    )
    return ScanResult(
        root=str(root),
        languages=["python"],
        files_scanned=2,
        routes=[Route(path="/api/run", method="POST", file="app.py", line=4)],
        secret_hints=[
            SecretHint(name="DEFAULT_ADMIN_PASSWORD", file="config.py", line=2, kind="literal"),
            SecretHint(name="STRIPE_API_KEY", file="app.py", line=6, kind="env_reference"),
        ],
        web_hardening_issues=[
            WebHardeningIssue(kind="debug_enabled", file="config.py", line=1, severity="medium")
        ],
    )


def test_kitchen_sink_findings_are_self_explaining(tmp_path: Path) -> None:
    scan = _kitchen_sink_scan(tmp_path)

    findings = generate_findings(scan)
    assert findings, "kitchen-sink fixture must produce findings"
    _assert_self_explaining(findings)
    # Guard against a vacuous pass: several distinct detectors must have fired.
    fired = {finding.rule_id for finding in findings}
    assert len(fired) >= 3, f"expected several rules to fire, got {sorted(fired)}"
    assert "hardcoded_secret_literals" in fired
    assert "unauth-state-change" in fired


def test_every_firing_registry_rule_emits_rationale_and_evidence(tmp_path: Path) -> None:
    """Run the whole REGISTRY against the kitchen-sink context: every finding
    any rule emits must be self-explaining, whatever fired."""
    scan = _kitchen_sink_scan(tmp_path)
    findings = evaluate_rules(ReasoningContext.from_scan(scan))
    assert findings, "at least one registry rule must fire on the kitchen sink"
    _assert_self_explaining(findings)


def test_evaluate_rules_backfills_missing_rationale_from_rule_meta() -> None:
    """A rule whose construction forgets a rationale still emits explained
    findings: evaluate_rules falls back to the rule's declared rationale."""

    class SilentRationaleRule:
        meta = RuleMeta(
            id="test_rationale_backfill",
            title="Backfill rationale rule",
            severity="low",
            confidence=0.5,
            rationale="Declared rationale the kernel must fall back to.",
        )

        def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
            return [
                Finding(
                    title=self.meta.title,
                    severity="low",
                    mitigation="none",
                    rule_id=self.meta.id,
                    evidence=["observed signal"],
                )
            ]

    before = dict(REGISTRY._by_id)
    REGISTRY.register(SilentRationaleRule())
    try:
        ctx = ReasoningContext.from_scan(ScanResult(root=".", routes=[]))
        findings = evaluate_rules(ctx)
    finally:
        REGISTRY._by_id.clear()
        REGISTRY._by_id.update(before)
    own = [f for f in findings if f.rule_id == "test_rationale_backfill"]
    assert own and own[0].rationale == "Declared rationale the kernel must fall back to."


def test_rationale_is_redacted_like_other_evidence_text() -> None:
    finding = Finding(
        title="Secret-bearing rationale",
        severity="low",
        mitigation="m",
        rationale="Observed: aws_access_key_id = AKIAIOSFODNN7EXAMPLE in config",
    )
    assert "AKIAIOSFODNN7EXXXX" not in finding.rationale
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.rationale


def test_renderers_surface_rationale(tmp_path: Path) -> None:
    scan = _kitchen_sink_scan(tmp_path)
    findings = generate_findings(scan)
    _assert_self_explaining(findings)

    # SARIF: rationale rides in the result property bag, schema untouched.
    sarif = build_sarif(findings)
    results = sarif["runs"][0]["results"]
    assert results, "SARIF must contain results"
    for result in results:
        assert result["properties"]["rationale"].strip()

    # report.json context pack: the claim block carries the rationale.
    context = FindingPresentationIndex(scan).for_finding(findings[0])
    assert context["rationale"].strip()

    # Defensive review markdown: the weakness entries explain themselves.
    review = render_defensive_review(scan, [], findings, [])
    assert "Rationale:" in review


def test_report_json_findings_are_self_explaining(tmp_path: Path) -> None:
    """AC-207 snippet against a real pipeline scan of a small fixture repo."""
    from attackmap.orchestration.run_spec import RunSpec
    from attackmap.orchestration.scan_service import ScanRequest, execute_scan_request

    repo = tmp_path / "fixture-repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import hashlib\n"
        "import subprocess\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/api/run', methods=['POST'])\n"
        "def run_command():\n"
        "    command = request.form['command']\n"
        "    return subprocess.check_output(command, shell=True)\n"
        "\n"
        "@app.route('/items/<item_id>', methods=['GET', 'PUT'])\n"
        "def item(item_id):\n"
        "    return item_id\n",
        encoding="utf-8",
    )
    (repo / "config.py").write_text(
        "DEBUG = True\n"
        "DEFAULT_ADMIN_PASSWORD = 'hunter2-hunter2-hunter2'\n"
        "import hashlib\n"
        "def hash_password(pw):\n"
        "    return hashlib.md5(pw.encode()).hexdigest()\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    summary = execute_scan_request(
        ScanRequest(
            repo_paths=[repo],
            output=output,
            spec=RunSpec(repos=(repo,), output=output, run_id="ac207"),
            run_id="ac207",
            echo=lambda *args, **kwargs: None,
        )
    )
    assert summary.exit_code == 0, "fixture scan failed"
    report_path = output / "ac207" / "attackmap-report.json"
    assert report_path.exists(), f"report.json missing at {report_path}"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    # AC-207: every Finding carries a non-empty rationale and >=1 evidence ref.
    assert report["findings"], "fixture repo must produce findings"
    assert all(f.get("rationale") and f.get("evidence") for f in report["findings"])

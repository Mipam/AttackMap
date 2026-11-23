"""AR047: the per-rule test harness checks itself.

The coverage and mutation checks rest on guarantees of ``_harness.py``. Each
is proven here against synthetic test modules and throwaway rules, so a
regression in the harness fails loudly instead of quietly reporting every
rule as covered:

* :func:`run_rule` takes a rule id or the rule, and a scan or a context, and
  refuses anything else (a repository path in particular);
* the assertion helpers fail with the rule id and expected versus actual;
* :func:`rule_disabled` reaches every instance of the rule, leaves sibling
  rules that share its class alone, and is always reverted;
* the ``rule`` marker reader sees marks on modules, classes, functions and
  single parametrized cases, expands ``parametrize`` the way pytest does,
  ignores disabled tests, and says what it cannot replay instead of guessing.

Throwaway rules live only inside ``with extra_registered_rule(...)`` blocks;
nothing here leaves a trace in the process-wide registry.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest
from _harness import (
    RULES_DIR,
    FakeRule,
    FocusedTest,
    HarnessError,
    assert_rule_negative,
    assert_rule_positive,
    extra_registered_rule,
    focused_tests_in,
    replay,
    rule_disabled,
    rule_test_modules,
    run_rule,
)

from attackmap.model import Finding, Route, ScanResult, TaintChain
from attackmap.reasoning import REGISTRY, ReasoningContext

pytestmark = [pytest.mark.unit]

FAKE_ID = "zz_fake_rule_harness_self_test"


def _scan(path: str, file: str) -> ScanResult:
    """One GET route in one file; nothing else observed."""
    return ScanResult(
        root="C:/tmp/fake-repo",  # a label only: nothing is read from disk
        routes=[Route(path=path, method="GET", file=file)],
    )


def _admin_scan() -> ScanResult:
    return _scan("/admin/users", "app/admin.py")


def _api_scan() -> ScanResult:
    return _scan("/api/users", "app/api.py")


# --- run_rule -------------------------------------------------------------------


def test_run_rule_takes_a_rule_id_or_the_rule_and_a_scan_or_a_context() -> None:
    rule = REGISTRY.get("route_exposed_admin")
    assert rule is not None
    via_scan = run_rule("route_exposed_admin", _admin_scan())
    assert via_scan == run_rule(rule, _admin_scan())
    assert via_scan == run_rule("route_exposed_admin", ReasoningContext.from_scan(_admin_scan()))
    assert [finding.rule_id for finding in via_scan] == ["route_exposed_admin"]


def test_run_rule_resolves_an_id_through_the_registry_so_a_disabled_rule_is_what_runs() -> None:
    assert run_rule("route_exposed_admin", _admin_scan())
    with rule_disabled("route_exposed_admin"):
        assert run_rule("route_exposed_admin", _admin_scan()) == []
        rule = REGISTRY.get("route_exposed_admin")
        assert rule is not None and run_rule(rule, _admin_scan()) == []


def test_run_rule_rejects_a_rule_id_that_is_not_registered() -> None:
    with pytest.raises(LookupError, match="'no_such_rule' is not registered"):
        run_rule("no_such_rule", ReasoningContext())


def test_run_rule_does_not_scan_a_repository_on_disk() -> None:
    """A path is neither fixture type: the real scan is an orchestration run
    that publishes a generation, not something a unit-tier harness starts."""
    for fixture_repo in ("C:/tmp/some-repo", Path("C:/tmp/some-repo")):
        with pytest.raises(TypeError, match="does not scan a repository on disk"):
            run_rule("route_exposed_admin", fixture_repo)  # type: ignore[arg-type]


# --- the assertion helpers --------------------------------------------------------


def test_positive_failure_names_the_rule_and_shows_expected_versus_actual() -> None:
    with pytest.raises(AssertionError) as excinfo:
        assert_rule_positive("route_exposed_admin", _api_scan(), expect=1, at="app/admin.py")
    assert str(excinfo.value).splitlines() == [
        "rule 'route_exposed_admin' must fire on this fixture, but the rule did not fire",
        "  expected: 1 finding(s) with rule_id='route_exposed_admin', at least one located in 'app/admin.py'",
        "  actual:   0 finding(s) with rule_id='route_exposed_admin', 0 located in 'app/admin.py'",
        "  fixture:  ScanResult(routes=1)",
    ]


def test_positive_failure_reports_a_wrong_count_and_a_wrong_location() -> None:
    with pytest.raises(AssertionError, match="expected exactly 2, got 1"):
        assert_rule_positive("route_exposed_admin", _admin_scan(), expect=2)
    with pytest.raises(AssertionError, match=r"no finding is located in 'app/other\.py'"):
        assert_rule_positive("route_exposed_admin", _admin_scan(), at="app/other.py")


def test_positive_failure_reports_a_finding_that_carries_another_rule_id() -> None:
    class Misattributed(FakeRule):
        def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
            findings = super().evaluate(ctx)
            for finding in findings:
                finding.rule_id = "route_exposed_admin"
            return findings

    with extra_registered_rule(Misattributed(FAKE_ID)), pytest.raises(AssertionError) as excinfo:
        assert_rule_positive(FAKE_ID, _api_scan())
    assert str(excinfo.value).splitlines() == [
        f"rule '{FAKE_ID}' must fire on this fixture, but the rule did not fire; a rule may only emit "
        "findings that carry its own rule_id",
        f"  expected: >= 1 finding(s) with rule_id='{FAKE_ID}'",
        f"  actual:   0 finding(s) with rule_id='{FAKE_ID}'; 1 finding(s) carry another rule_id "
        "['route_exposed_admin']",
        "  fixture:  ScanResult(routes=1)",
    ]


def test_negative_assertion_passes_when_the_rule_is_silent() -> None:
    assert_rule_negative("route_exposed_admin", _api_scan(), reason="non-admin routes are out of scope")


def test_negative_failure_names_the_rule_the_reason_and_what_fired() -> None:
    with pytest.raises(AssertionError) as excinfo:
        assert_rule_negative("route_exposed_admin", _admin_scan(), reason="non-admin routes are out of scope")
    assert str(excinfo.value).splitlines() == [
        "rule 'route_exposed_admin' must stay silent (non-admin routes are out of scope)",
        "  expected: 0 finding(s) with rule_id='route_exposed_admin'",
        "  actual:   1 finding(s): 'route_exposed_admin' 'Administrative routes appear reachable from "
        "the main application surface' at app/admin.py",
        "  fixture:  ScanResult(routes=1)",
    ]


# --- rule_disabled ----------------------------------------------------------------


def test_rule_disabled_reaches_the_registry_a_fresh_instance_and_registry_evaluation() -> None:
    rule = REGISTRY.get("route_exposed_admin")
    assert rule is not None
    cls = type(rule)
    original = cls.evaluate
    ctx = ReasoningContext.from_scan(_admin_scan())

    def admin_findings() -> set[str]:
        return {f.rule_id for f in REGISTRY.evaluate_all(ctx).findings if f.rule_id == "route_exposed_admin"}

    assert admin_findings() == {"route_exposed_admin"}
    with rule_disabled("route_exposed_admin"):
        assert run_rule("route_exposed_admin", _admin_scan()) == []
        assert cls().evaluate(ctx) == []  # a freshly constructed instance
        assert admin_findings() == set()
    assert cls.evaluate is original
    assert admin_findings() == {"route_exposed_admin"}


def test_rule_disabled_leaves_sibling_rules_of_the_same_class_working() -> None:
    """The 34 taint rules share three classes: disabling one id must not
    silence the others."""
    target, sibling = "taint_sink_eval", "taint_sink_ssti"
    assert type(REGISTRY.get(target)) is type(REGISTRY.get(sibling))
    scan = ScanResult(
        root="C:/tmp/fake-repo",
        taint_chains=[
            TaintChain(
                route_path="/run",
                route_method="POST",
                route_file="app/web.py",
                sink_kind="eval",
                sink_file="svc/dynamic.py",
                hops=1,
            ),
            TaintChain(
                route_path="/render",
                route_method="POST",
                route_file="app/pages.py",
                sink_kind="ssti",
                sink_file="svc/render.py",
                hops=1,
            ),
        ],
    )

    def taint_ids() -> list[str]:
        findings = REGISTRY.evaluate_all(ReasoningContext.from_scan(scan)).findings
        return sorted(f.rule_id for f in findings if f.rule_id.startswith("taint_"))

    assert taint_ids() == sorted((target, sibling))
    with rule_disabled(target):
        assert taint_ids() == [sibling]
    assert taint_ids() == sorted((target, sibling))


def test_rule_disabled_is_reverted_when_the_block_raises() -> None:
    cls = type(REGISTRY.get("route_exposed_admin"))
    original = cls.evaluate
    with pytest.raises(RuntimeError, match="boom"), rule_disabled("route_exposed_admin"):
        raise RuntimeError("boom")
    assert cls.evaluate is original


def test_rule_disabled_nests() -> None:
    with rule_disabled("route_exposed_admin"), rule_disabled("route_upload_import"):
        assert run_rule("route_exposed_admin", _admin_scan()) == []
        assert run_rule("route_upload_import", _scan("/upload", "app/upload.py")) == []
    assert run_rule("route_exposed_admin", _admin_scan())
    assert run_rule("route_upload_import", _scan("/upload", "app/upload.py"))


def test_rule_disabled_rejects_a_rule_id_that_is_not_registered() -> None:
    with pytest.raises(LookupError, match="not registered"), rule_disabled("no_such_rule"):
        pytest.fail("the block must not be entered")


# --- reading the ``rule`` marker --------------------------------------------------


def _module(*tests: Callable[..., object], marks: object = None) -> ModuleType:
    """A stand-in test module holding ``tests``, as a ``test_*.py`` file would."""
    module = ModuleType("fake_rules_test_module")
    for test in tests:
        setattr(module, test.__name__, test)
    if marks is not None:
        module.pytestmark = marks
    return module


def _short(case: FocusedTest) -> str:
    """The case's nodeid without the stand-in module's name."""
    return case.nodeid.removeprefix("fake_rules_test_module::")


def test_reader_sees_rule_marks_on_the_module_on_classes_and_on_functions() -> None:
    @pytest.mark.rule("route_exposed_admin")
    def test_on_function() -> None: ...

    @pytest.mark.rule("same_file_datastore_edge")
    class TestEdges:
        @pytest.mark.rule("same_file_external_edge")
        def test_on_class_and_method(self) -> None: ...

    def test_inherits_the_module_mark() -> None: ...

    module = _module(
        test_on_function,
        TestEdges,
        test_inherits_the_module_mark,
        marks=pytest.mark.rule("secret_env_references"),
    )
    cases = focused_tests_in(module)
    assert [(_short(case), case.rule_ids) for case in cases] == [
        ("test_on_function", ("secret_env_references", "route_exposed_admin")),
        ("TestEdges::test_on_class_and_method", ("secret_env_references", "same_file_datastore_edge", "same_file_external_edge")),
        ("test_inherits_the_module_mark", ("secret_env_references",)),
    ]
    assert all(case.active and case.call is not None for case in cases)


def test_reader_expands_parametrize_as_pytest_does_including_marks_on_one_case() -> None:
    @pytest.mark.parametrize(
        "rule_id",
        [
            pytest.param("taint_sink_eval", id="taint_sink_eval", marks=pytest.mark.rule("taint_sink_eval")),
            pytest.param("taint_sink_exec", id="taint_sink_exec", marks=pytest.mark.rule("taint_sink_exec")),
            "not-a-rule",
        ],
    )
    def test_per_case(rule_id: str) -> None: ...

    @pytest.mark.rule("taint_flow_sql_execute")
    @pytest.mark.parametrize("hops", [0, 1])
    def test_whole_function(hops: int) -> None: ...

    @pytest.mark.parametrize("kind,expected", [("eval", 1), ("exec", 2)])
    @pytest.mark.rule("taint_sink_eval", "taint_sink_exec")
    def test_two_names(kind: str, expected: int) -> None: ...

    @pytest.mark.rule("taint_sink_ssti")
    @pytest.mark.parametrize("first", [1, 2])
    @pytest.mark.parametrize("second", ["a", "b"])
    def test_stacked(first: int, second: str) -> None: ...

    @pytest.mark.parametrize("values,", [((1, 2),), ((3,),)])
    @pytest.mark.rule("route_upload_import")
    def test_trailing_comma(values: tuple[int, ...]) -> None: ...

    cases = focused_tests_in(_module(test_per_case, test_whole_function, test_two_names, test_stacked, test_trailing_comma))
    assert [(_short(case), case.rule_ids, case.argnames, case.values) for case in cases] == [
        ("test_per_case[taint_sink_eval]", ("taint_sink_eval",), ("rule_id",), ("taint_sink_eval",)),
        ("test_per_case[taint_sink_exec]", ("taint_sink_exec",), ("rule_id",), ("taint_sink_exec",)),
        ("test_whole_function[0]", ("taint_flow_sql_execute",), ("hops",), (0,)),
        ("test_whole_function[1]", ("taint_flow_sql_execute",), ("hops",), (1,)),
        ("test_two_names[eval-1]", ("taint_sink_eval", "taint_sink_exec"), ("kind", "expected"), ("eval", 1)),
        ("test_two_names[exec-2]", ("taint_sink_eval", "taint_sink_exec"), ("kind", "expected"), ("exec", 2)),
        ("test_stacked[a-1]", ("taint_sink_ssti",), ("second", "first"), ("a", 1)),
        ("test_stacked[a-2]", ("taint_sink_ssti",), ("second", "first"), ("a", 2)),
        ("test_stacked[b-1]", ("taint_sink_ssti",), ("second", "first"), ("b", 1)),
        ("test_stacked[b-2]", ("taint_sink_ssti",), ("second", "first"), ("b", 2)),
        ("test_trailing_comma[(1, 2)]", ("route_upload_import",), ("values",), ((1, 2),)),
        ("test_trailing_comma[(3,)]", ("route_upload_import",), ("values",), ((3,),)),
    ]


def test_replayed_cases_receive_their_parameters_and_run_class_tests_on_an_instance() -> None:
    seen: list[tuple[str, object]] = []

    @pytest.mark.rule("route_exposed_admin")
    @pytest.mark.parametrize("rule_id", [pytest.param("x", marks=pytest.mark.rule("taint_sink_eval"))])
    def test_values(rule_id: str) -> None:
        seen.append(("function", rule_id))

    @pytest.mark.rule("same_file_external_edge")
    class TestClass:
        def test_method(self) -> None:
            seen.append(("method", type(self).__name__))

    cases = focused_tests_in(_module(test_values, TestClass))
    assert all(replay(case) is None for case in cases)
    assert seen == [("function", "x"), ("method", "TestClass")]


def test_reader_ignores_disabled_tests_and_marks_skipped_ones_inactive() -> None:
    @pytest.mark.rule("route_exposed_admin")
    def test_disabled() -> None: ...

    test_disabled.__test__ = False  # type: ignore[attr-defined]  # pytest does not collect it

    @pytest.mark.rule("route_exposed_admin")
    @pytest.mark.skip(reason="pending")
    def test_skipped() -> None: ...

    @pytest.mark.rule("route_exposed_admin")
    @pytest.mark.skipif(False, reason="platform")
    def test_conditional() -> None: ...

    cases = focused_tests_in(_module(test_disabled, test_skipped, test_conditional))
    assert [(_short(case), case.active, case.call is None, case.blocker) for case in cases] == [
        ("test_skipped", False, True, "marked skip"),
        ("test_conditional", True, False, ""),
    ]


def test_reader_says_what_it_cannot_replay_instead_of_guessing() -> None:
    @pytest.mark.rule("route_exposed_admin")
    def test_needs_a_fixture(monkeypatch: pytest.MonkeyPatch) -> None: ...

    @pytest.mark.rule("route_exposed_admin")
    @pytest.mark.parametrize("rule_id", ["x"], indirect=True)
    def test_indirect(rule_id: str) -> None: ...

    cases = focused_tests_in(_module(test_needs_a_fixture, test_indirect))
    assert [(_short(case), case.call, case.blocker) for case in cases] == [
        ("test_needs_a_fixture", None, "needs fixture(s) monkeypatch"),
        ("test_indirect[x]", None, "uses indirect parametrize"),
    ]
    assert all(case.active for case in cases)  # pytest still runs them: they cover the rule
    with pytest.raises(AssertionError, match="cannot be replayed: needs fixture\\(s\\) monkeypatch"):
        replay(cases[0])


def test_reader_rejects_a_rule_marker_that_names_no_rule() -> None:
    @pytest.mark.rule
    def test_no_args() -> None: ...

    with pytest.raises(HarnessError, match="needs registered rule ids"):
        focused_tests_in(_module(test_no_args))


def test_the_sibling_test_files_are_each_imported_once() -> None:
    modules = rule_test_modules()
    names = [Path(module.__file__).name for module in modules if module.__file__]
    assert names == sorted(path.name for path in RULES_DIR.glob("test_*.py"))
    assert len({id(module) for module in modules}) == len(modules)


# --- throwaway rules and the replay verdict ---------------------------------------


def test_extra_registered_rule_restores_the_registry_even_when_the_block_raises() -> None:
    before = len(REGISTRY)
    with extra_registered_rule(FakeRule(FAKE_ID)):
        assert FAKE_ID in REGISTRY
    assert FAKE_ID not in REGISTRY
    assert len(REGISTRY) == before
    with pytest.raises(RuntimeError, match="boom"), extra_registered_rule(FakeRule(FAKE_ID)):
        raise RuntimeError("boom")
    assert FAKE_ID not in REGISTRY
    assert len(REGISTRY) == before


def test_extra_registered_rule_refuses_a_duplicate_id_without_touching_the_registry() -> None:
    before = len(REGISTRY)
    with pytest.raises(ValueError, match="already registered"), extra_registered_rule(FakeRule("route_exposed_admin")):
        pytest.fail("the block must not be entered")
    assert len(REGISTRY) == before


def test_replay_counts_pytest_fail_as_a_failure_and_skip_or_xfail_as_none() -> None:
    def verdict(body: Callable[[], None]) -> BaseException | None:
        case = FocusedTest(rule_ids=(FAKE_ID,), nodeid="synthetic", func=body, argnames=(), values=(), call=body)
        return replay(case)

    def fails() -> None:
        pytest.fail("broken")

    def skips() -> None:
        pytest.skip("not here")

    def xfails() -> None:
        pytest.xfail("known")

    def raises() -> None:
        raise KeyError("missing")

    assert isinstance(verdict(fails), pytest.fail.Exception)
    assert isinstance(verdict(raises), KeyError)
    assert verdict(skips) is None
    assert verdict(xfails) is None

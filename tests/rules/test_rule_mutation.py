"""AR047 / AC-202: disabling a rule must break at least one of its focused tests.

``test_disabling_the_rule_breaks_at_least_one_focused_test`` runs once per
registered rule id. Each case replays the rule's focused tests in-process
three times: as they are (they must pass), with the rule disabled through the
``rule_disabled`` seam (at least one must fail: that test checks what the rule
emits), and as they are again (the seam must have restored the rule).

The other tests probe the check itself with a throwaway rule that lives only
inside a ``with extra_registered_rule(...)`` block: a focused test that
asserts nothing lets the mutant survive and is flagged; a rule that is already
disabled is flagged before anything is mutated, and the same check is green
once the rule is restored.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from _harness import (
    FakeRule,
    FocusedTest,
    MutationOutcome,
    assert_disabling_the_rule_breaks_a_focused_test,
    assert_rule_positive,
    extra_registered_rule,
    focused_tests_by_rule,
    mutation_outcome,
    replay,
    resolve_rule,
    rule_disabled,
)

from attackmap.model import Route, ScanResult
from attackmap.reasoning import REGISTRY

pytestmark = [pytest.mark.unit]

FAKE_ID = "zz_fake_rule_for_the_mutation_self_test"
ROUTE_SCAN = ScanResult(
    root="C:/tmp/fake-repo",  # a label only: nothing is read from disk
    routes=[Route(path="/api/items", method="GET", file="app/api.py")],
)


# --- one case per registered rule -----------------------------------------------


@pytest.mark.parametrize("rule_id", REGISTRY.ids())
def test_disabling_the_rule_breaks_at_least_one_focused_test(rule_id: str) -> None:
    outcome = assert_disabling_the_rule_breaks_a_focused_test(rule_id)
    # Restored -> green: every test the mutant broke passes again afterwards.
    broken = [case for case in focused_tests_by_rule()[rule_id] if case.nodeid in outcome.broken]
    assert all(replay(case) is None for case in broken), f"rule {rule_id!r} is still disabled after the block"


# --- the negative paths, proven in-suite ------------------------------------------


def _probe(rule_id: str, body: Callable[[], None]) -> FocusedTest:
    """A focused-test record the harness never reads from disk, for probing the check."""
    return FocusedTest(
        rule_ids=(rule_id,),
        nodeid=f"synthetic::{body.__name__}",
        func=body,
        argnames=(),
        values=(),
        call=body,
    )


def test_mutation_check_flags_a_rule_whose_focused_test_asserts_nothing() -> None:
    """A rule can have a test and still be unprotected: the test below looks
    the rule up but never asserts on what it emits, so a disabled rule
    survives it and the check must say so."""

    def test_vacuous() -> None:
        assert resolve_rule(FAKE_ID).meta.id == FAKE_ID

    vacuous = _probe(FAKE_ID, test_vacuous)
    with extra_registered_rule(FakeRule(FAKE_ID)):
        outcome = mutation_outcome(FAKE_ID, [vacuous])
        assert outcome.broken == () and outcome.survived == (vacuous.nodeid,)
        with pytest.raises(AssertionError, match="mutant survived"):
            assert_disabling_the_rule_breaks_a_focused_test(FAKE_ID, [vacuous])


def test_mutation_check_accepts_a_rule_whose_focused_test_asserts_on_its_findings() -> None:
    def test_guards() -> None:
        assert_rule_positive(FAKE_ID, ROUTE_SCAN, expect=1, at="app/api.py")

    guards = _probe(FAKE_ID, test_guards)
    with extra_registered_rule(FakeRule(FAKE_ID)):
        outcome = assert_disabling_the_rule_breaks_a_focused_test(FAKE_ID, [guards])
    assert outcome == MutationOutcome(
        rule_id=FAKE_ID, broken=(guards.nodeid,), survived=(), control_failures=(), unreplayable=()
    )


def test_mutation_check_flags_a_rule_that_is_already_disabled_and_passes_once_restored() -> None:
    """Rule disabled -> the check flags it; restored -> green."""

    def test_guards() -> None:
        assert_rule_positive(FAKE_ID, ROUTE_SCAN, expect=1, at="app/api.py")

    guards = _probe(FAKE_ID, test_guards)
    with extra_registered_rule(FakeRule(FAKE_ID)):
        with rule_disabled(FAKE_ID), pytest.raises(AssertionError, match="looks disabled or broken"):
            assert_disabling_the_rule_breaks_a_focused_test(FAKE_ID, [guards])
        assert_disabling_the_rule_breaks_a_focused_test(FAKE_ID, [guards])


def test_mutation_check_flags_a_rule_that_has_no_focused_test() -> None:
    with extra_registered_rule(FakeRule(FAKE_ID)), pytest.raises(AssertionError, match="no focused test"):
        assert_disabling_the_rule_breaks_a_focused_test(FAKE_ID)


def test_mutation_check_names_the_tests_it_could_not_replay() -> None:
    """A focused test the replay cannot call must be named in the failure,
    never quietly dropped."""
    needs_fixture = _probe(FAKE_ID, lambda: None)
    blocked = FocusedTest(
        rule_ids=needs_fixture.rule_ids,
        nodeid=needs_fixture.nodeid,
        func=needs_fixture.func,
        argnames=(),
        values=(),
        call=None,
        blocker="needs fixture(s) tmp_path",
    )
    with extra_registered_rule(FakeRule(FAKE_ID)):
        outcome = mutation_outcome(FAKE_ID, [blocked])
        assert outcome == MutationOutcome(
            rule_id=FAKE_ID,
            broken=(),
            survived=(),
            control_failures=(),
            unreplayable=(f"{blocked.nodeid} (needs fixture(s) tmp_path)",),
        )
        with pytest.raises(AssertionError, match="mutant survived") as excinfo:
            assert_disabling_the_rule_breaks_a_focused_test(FAKE_ID, [blocked])
    assert f"{blocked.nodeid} (needs fixture(s) tmp_path)" in str(excinfo.value)

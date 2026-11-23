"""AR047 / AC-202: every registered rule has a focused test, and the check
that says so is itself proven to fail.

``test_every_registered_rule_id_has_a_focused_test`` is the meta-test: every
id in ``REGISTRY.ids()`` must have at least one active test carrying the
``rule`` marker for it (``_harness.py`` explains the convention).

The other tests probe the check itself with throwaway rules that live only
inside a ``with extra_registered_rule(...)`` block, so the process-wide
registry is exactly what it was once each of them is done:

* a rule registered without a test is reported, and the meta-test function
  raises on it;
* a skipped test does not cover a rule (pytest never runs it);
* a marker naming a rule that is not registered is reported, which is what a
  removed or renamed rule leaves behind;
* what the harness reads from the ``rule`` markers equals what pytest itself
  collected, case by case.
"""

from __future__ import annotations

import os

import pytest
from _harness import (
    RULE_MARKER,
    RULES_DIR,
    FakeRule,
    FocusedTest,
    assert_every_registered_rule_has_a_focused_test,
    extra_registered_rule,
    focused_tests_in,
    rule_test_modules,
    stale_rule_ids,
    untested_rule_ids,
)

from attackmap.reasoning import REGISTRY

pytestmark = [pytest.mark.unit]

FAKE_ID = "zz_fake_rule_without_a_test"


def _synthetic(rule_id: str, **overrides: object) -> FocusedTest:
    """A focused-test record built by hand, never read from disk, for probing the checks."""
    fields: dict[str, object] = {
        "rule_ids": (rule_id,),
        "nodeid": "synthetic::test_probe",
        "func": lambda: None,
        "argnames": (),
        "values": (),
        "call": lambda: None,
    }
    fields.update(overrides)
    return FocusedTest(**fields)  # type: ignore[arg-type]


# --- the meta-test ---------------------------------------------------------------


def test_every_registered_rule_id_has_a_focused_test() -> None:
    assert_every_registered_rule_has_a_focused_test()


# --- the negative paths, proven in-suite ------------------------------------------


def test_the_coverage_check_fails_for_a_rule_registered_without_a_test() -> None:
    before = len(REGISTRY)
    with extra_registered_rule(FakeRule(FAKE_ID)), pytest.raises(AssertionError) as excinfo:
        # Exactly the newcomer is missing: nothing real is hiding behind this probe.
        assert untested_rule_ids() == [FAKE_ID]
        assert_every_registered_rule_has_a_focused_test()
    message = str(excinfo.value)
    assert f"AC-202: 1 of {before + 1} registered rule(s) have no focused test" in message
    assert FAKE_ID in message
    # Cleanup included: the registry is what it was, and the check is green again.
    assert FAKE_ID not in REGISTRY
    assert len(REGISTRY) == before
    assert untested_rule_ids() == []


def test_a_skipped_test_does_not_cover_a_rule() -> None:
    skipped = _synthetic(FAKE_ID, blocker="marked skip", active=False)
    with extra_registered_rule(FakeRule(FAKE_ID)), pytest.raises(AssertionError, match=FAKE_ID):
        assert_every_registered_rule_has_a_focused_test({FAKE_ID: (skipped,)})


def test_a_test_pytest_runs_but_the_replay_cannot_still_covers_the_rule() -> None:
    """Coverage and replayability are separate: pytest runs the test, so the
    rule is covered, whether or not the in-process replay can call it."""
    needs_fixture = _synthetic(FAKE_ID, blocker="needs fixture(s) tmp_path", call=None)
    with extra_registered_rule(FakeRule(FAKE_ID)):
        reported = untested_rule_ids({FAKE_ID: (needs_fixture,)})
    # Every rule absent from the mapping is reported; the fake, whose one test
    # pytest runs, is not.
    assert reported == [rule_id for rule_id in REGISTRY.ids() if rule_id != FAKE_ID]


def test_a_marker_naming_an_unregistered_rule_is_reported() -> None:
    assert stale_rule_ids() == []
    assert stale_rule_ids({FAKE_ID: (_synthetic(FAKE_ID),)}) == [FAKE_ID]


# --- the reader against pytest's own collection -----------------------------------


def test_marker_reading_agrees_with_what_pytest_collected(request: pytest.FixtureRequest) -> None:
    """The harness reads ``rule`` marks from the test modules rather than from
    pytest's collection, so the two must agree: for every rule-marked test
    pytest collected under ``tests/rules``, pytest's rule ids for it equal the
    ones the harness reads for that very case (parametrized cases included)."""
    static = [case for module in rule_test_modules() for case in focused_tests_in(module)]
    compared = 0
    for item in request.session.items:
        if not os.path.samefile(item.path.parent, RULES_DIR):
            continue
        callspec = getattr(item, "callspec", None)
        matching = [
            case
            for case in static
            if case.func is item.function
            and (
                (callspec is None and not case.argnames)
                or (
                    callspec is not None
                    and case.argnames
                    and tuple(callspec.params[name] for name in case.argnames) == case.values
                )
            )
        ]
        pytest_ids = sorted({arg for mark in item.iter_markers(RULE_MARKER) for arg in mark.args})
        harness_ids = sorted({rule_id for case in matching for rule_id in case.rule_ids})
        if not pytest_ids and not harness_ids:
            continue  # not focused on any rule: nothing to compare
        assert len(matching) == 1 and harness_ids == pytest_ids, (
            f"{item.nodeid}: pytest collected rule ids {pytest_ids}, "
            f"the harness reads {harness_ids} for {[case.nodeid for case in matching]}"
        )
        compared += 1
    if not compared:
        pytest.skip("no rule-marked test was collected in this selection")

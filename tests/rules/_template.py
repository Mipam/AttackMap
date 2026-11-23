"""Copy-paste template for a focused rule test (AR087).

HOW TO USE THIS FILE
--------------------
This file is deliberately NOT named ``test_*.py``: neither pytest's default
collection (``python_files = test_*.py``) nor the AR047 harness glob
(``tests/rules/_harness.py`` reads ``test_*.py``) picks it up, so the
placeholders below can never break the suite or the coverage/mutation
meta-tests. To author a test for your rule:

1. copy this file to ``tests/rules/test_<your_rule_id>.py`` (the basename
   must be unique suite-wide; ``tests/`` has no ``__init__.py``);
2. replace every ``your_rule_id`` with your registered rule id;
3. replace the fixtures and assertions;
4. delete the module-level ``pytest.mark.skip`` below so the tests run.

COLLECTABLE BUT SKIPPED
-----------------------
If you ever point pytest at this template directly
(``pytest tests/rules/_template.py``), it collects: the module-level
``pytestmark`` below skips every test with a clear reason instead of failing
on the placeholders. The ``@pytest.mark.rule("your_rule_id")`` marks name a
rule that does not exist — harmless here ONLY because of the ``_template.py``
name (the harness never reads this file); in a real ``test_*.py`` an active
mark naming an unregistered id fails the stale-marker check in
``tests/rules/test_rule_coverage.py``. Keep the id and the registration in
sync from the moment you rename the file.

THE PATTERN
-----------
* Fixtures are built IN CODE (``ScanResult`` / ``ReasoningContext``), never
  read from disk — the harness does not scan repositories; the real scan is
  the integration tier (``orchestration.run_scan``) and ``tests/rules`` is
  the ``unit`` tier.
* ``assert_rule_positive`` pins that the rule fires, that every finding
  carries ``rule_id == your rule id``, optionally the count (``expect``) and
  a required location (``at``).
* ``assert_rule_negative`` guards a near-miss: a fixture that must stay
  silent, with ``reason`` naming the boundary it protects. Every rule needs
  at least one negative case.
* The ``@pytest.mark.rule("<id>")`` mark is the registration convention the
  AR047 meta-tests read: it makes this test the rule's FOCUSED test, so the
  coverage check (every registered rule has one) and the mutation check
  (disabling the rule must break at least one focused test) apply. Without
  the mark the test exists but does not cover the rule.
"""

from __future__ import annotations

import pytest
from _harness import assert_rule_negative, assert_rule_positive

# The unit tier mark is required under tests/rules; the skip mark is template
# scaffolding — delete it in the copied file once the placeholders are gone.
pytestmark = [
    pytest.mark.unit,
    pytest.mark.skip(reason="template: copy to tests/rules/test_<your_rule_id>.py, adapt, then remove this skip"),
]

from attackmap.model import ScanResult  # noqa: E402  (kept near the fixtures in real tests)

# --- fixtures (built in code) ---------------------------------------------------

# TODO: positive fixture — exactly the observation records the rule fires on.
# Build it from the models the rule's ReasoningContext slice exposes (see
# src/attackmap/reasoning/context.py), e.g. a SecretHint for the secrets
# family, a Route for route rules, a TaintChain for taint rules.
POSITIVE_FIXTURE = ScanResult(root="")

# TODO: negative fixture — the near-miss that must stay silent: the same
# shape as the positive fixture minus the signal, or with the signal in a
# form the rule must not fire on (placeholder, test path, wrong kind, ...).
NEGATIVE_FIXTURE = ScanResult(root="")


# --- the focused tests -----------------------------------------------------------


@pytest.mark.rule("your_rule_id")  # TODO: replace with the registered rule id
def test_your_rule_id_fires_on_the_signal():
    # assert_rule_positive returns the findings for extra field assertions.
    findings = assert_rule_positive("your_rule_id", POSITIVE_FIXTURE)
    assert findings[0].severity == "medium"  # TODO: pin the fields you own


@pytest.mark.rule("your_rule_id")  # TODO: replace with the registered rule id
def test_your_rule_id_stays_silent_on_the_near_miss():
    assert_rule_negative(
        "your_rule_id",
        NEGATIVE_FIXTURE,
        reason="TODO: name the boundary this guards (e.g. placeholders are names, not values)",
    )


# --- parametrized form (one case per rule, when a file covers a family) ----------
#
# @pytest.mark.parametrize(
#     "rule_id, fixture, expect",
#     [
#         pytest.param("your_rule_id", POSITIVE_FIXTURE, 1, marks=pytest.mark.rule("your_rule_id")),
#         pytest.param("your_rule_id", NEGATIVE_FIXTURE, 0, marks=pytest.mark.rule("your_rule_id")),
#     ],
# )
# def test_family_cases(rule_id, fixture, expect):
#     findings = run_rule(rule_id, fixture)
#     assert len(findings) == expect

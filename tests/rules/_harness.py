"""Per-rule test harness (AR047, AC-202): run one rule against one in-code
fixture, assert that it fires or stays silent, and keep every registered rule
covered by a focused test that fails once the rule is disabled.

Test-only: nothing here needs a ``src/`` seam.

Running one rule
    :func:`run_rule` evaluates exactly one registered rule against one
    fixture; :func:`assert_rule_positive` and :func:`assert_rule_negative`
    assert the outcome with a message that names the rule id and shows
    expected versus actual.

The ``rule`` marker (the registration convention)
    A test focused on a rule carries ``@pytest.mark.rule("<rule_id>", ...)``.
    The id sits on the test, next to what the test asserts, so a reader sees
    which rule a test protects. A parametrized test names the rule per case:
    ``pytest.param(rule_id, id=rule_id, marks=pytest.mark.rule(rule_id))``.
    ``tests/rules/conftest.py`` registers the marker (``--strict-markers``).

Mutation check
    :func:`rule_disabled` makes one rule emit nothing for the duration of a
    ``with`` block; :func:`mutation_outcome` replays the rule's focused tests
    in-process and reports which of them broke.

Marks are read from the test modules, not from pytest's collection, so the
coverage and mutation checks give the same answer for the whole directory, a
single file or a ``-k`` selection (a collection-based check would report every
rule as untested in a partial run). The reader covers the documented shapes of
marks and ``parametrize``; ``tests/rules/test_rule_coverage.py`` cross-checks
it against what pytest itself collected.
"""

from __future__ import annotations

import importlib.util
import inspect
import itertools
import os
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import ModuleType

import pytest
from pytest import Mark, MarkDecorator

from attackmap.model import Finding, FindingLocation, ScanResult
from attackmap.reasoning import REGISTRY, ReasoningContext, Rule, RuleMeta

__all__ = [
    "RULES_DIR",
    "RULE_MARKER",
    "FakeRule",
    "FocusedTest",
    "HarnessError",
    "MutationOutcome",
    "as_context",
    "assert_disabling_the_rule_breaks_a_focused_test",
    "assert_every_registered_rule_has_a_focused_test",
    "assert_rule_negative",
    "assert_rule_positive",
    "coverage_message",
    "extra_registered_rule",
    "focused_tests_by_rule",
    "focused_tests_in",
    "mutation_message",
    "mutation_outcome",
    "replay",
    "resolve_rule",
    "rule_disabled",
    "rule_test_modules",
    "run_rule",
    "stale_rule_ids",
    "untested_rule_ids",
]

RULES_DIR = Path(__file__).resolve().parent
RULE_MARKER = "rule"

RuleRef = Rule | str
FixtureRepo = ReasoningContext | ScanResult


class HarnessError(Exception):
    """A ``rule`` marker or test shape the harness cannot interpret."""


# --- running one rule ---------------------------------------------------------


def as_context(fixture_repo: FixtureRepo) -> ReasoningContext:
    """The context a fixture stands for: itself, or ``from_scan`` of a ``ScanResult``."""
    if isinstance(fixture_repo, ReasoningContext):
        return fixture_repo
    if isinstance(fixture_repo, ScanResult):
        return ReasoningContext.from_scan(fixture_repo)
    raise TypeError(
        "fixture_repo must be a ReasoningContext or a ScanResult built in code, got "
        f"{type(fixture_repo).__name__}; the harness does not scan a repository on disk"
    )


def resolve_rule(rule: RuleRef) -> Rule:
    """The rule object: ``rule`` itself, or the registered rule with that id.

    A string id always resolves through the process-wide ``REGISTRY``, so a
    rule disabled by :func:`rule_disabled` is what a harness test runs.
    """
    if isinstance(rule, str):
        registered = REGISTRY.get(rule)
        if registered is None:
            raise LookupError(f"rule {rule!r} is not registered (REGISTRY holds {len(REGISTRY)} rules)")
        return registered
    return rule


def run_rule(rule: RuleRef, fixture_repo: FixtureRepo) -> list[Finding]:
    """Evaluate exactly one rule against one fixture and return its findings.

    ``rule`` is a registered rule id (``str``) or a ``Rule`` instance.
    ``fixture_repo`` is what the rule families are built from in code: a
    ``ReasoningContext`` (used as is) or a ``ScanResult`` (narrowed through
    ``ReasoningContext.from_scan``). A repository on disk is deliberately not
    accepted: the real scan is ``orchestration.run_scan``, which publishes a
    generation (integration tier), and ``tests/rules`` is the ``unit`` tier.
    """
    return list(resolve_rule(rule).evaluate(as_context(fixture_repo)))


def _describe(fixture_repo: FixtureRepo) -> str:
    """Which slices of the fixture carry records, e.g. ``ScanResult(routes=2)``."""
    ctx = as_context(fixture_repo)
    filled = []
    for name in ReasoningContext.model_fields:
        value = getattr(ctx, name)
        if isinstance(value, tuple) and value:
            filled.append(f"{name}={len(value)}")
    return f"{type(fixture_repo).__name__}({' '.join(filled) or 'no records'})"


def _summary(finding: Finding) -> str:
    """One emitted finding, short enough for a failure line."""
    where = ", ".join(
        f"{location.file}:{location.line}" if location.line is not None else location.file
        for location in finding.locations[:3]
    )
    return f"{finding.rule_id!r} {finding.title!r}" + (f" at {where}" if where else "")


def _failure(
    rule_id: str, expectation: str, expected: str, actual: str, fixture_repo: FixtureRepo
) -> AssertionError:
    return AssertionError(
        f"rule {rule_id!r} {expectation}\n"
        f"  expected: {expected}\n"
        f"  actual:   {actual}\n"
        f"  fixture:  {_describe(fixture_repo)}"
    )


def assert_rule_positive(
    rule: RuleRef,
    fixture_repo: FixtureRepo,
    *,
    expect: int | None = None,
    at: str | None = None,
) -> list[Finding]:
    """Assert ``rule`` fires on ``fixture_repo``; return the findings it emitted.

    Every emitted finding must carry the rule's own id (the kernel contract
    ``Finding.rule_id == meta.id``). ``expect`` pins the number of findings;
    ``at`` requires at least one of them to be located in that file. A failure
    names the rule id and shows expected versus actual.
    """
    rule_id = resolve_rule(rule).meta.id
    findings = run_rule(rule, fixture_repo)
    own = [finding for finding in findings if finding.rule_id == rule_id]
    foreign = sorted({str(finding.rule_id) for finding in findings if finding.rule_id != rule_id})
    located = sum(any(location.file == at for location in finding.locations) for finding in own)
    expected = f"{expect if expect is not None else '>= 1'} finding(s) with rule_id={rule_id!r}"
    actual = f"{len(own)} finding(s) with rule_id={rule_id!r}"
    if at is not None:
        expected += f", at least one located in {at!r}"
        actual += f", {located} located in {at!r}"
    if foreign:
        actual += f"; {len(findings) - len(own)} finding(s) carry another rule_id {foreign}"
    problems = []
    if not own:
        problems.append("the rule did not fire")
    elif expect is not None and len(own) != expect:
        problems.append(f"expected exactly {expect}, got {len(own)}")
    if foreign:
        problems.append("a rule may only emit findings that carry its own rule_id")
    if at is not None and own and not located:
        problems.append(f"no finding is located in {at!r}")
    if problems:
        raise _failure(
            rule_id,
            "must fire on this fixture, but " + "; ".join(problems),
            expected,
            actual,
            fixture_repo,
        )
    return own


def assert_rule_negative(rule: RuleRef, fixture_repo: FixtureRepo, *, reason: str) -> None:
    """Assert ``rule`` stays silent on ``fixture_repo``.

    ``reason`` states why the fixture must not fire; it is printed on failure,
    so every negative case says which boundary it guards.
    """
    rule_id = resolve_rule(rule).meta.id
    findings = run_rule(rule, fixture_repo)
    if findings:
        raise _failure(
            rule_id,
            f"must stay silent ({reason})",
            f"0 finding(s) with rule_id={rule_id!r}",
            f"{len(findings)} finding(s): " + "; ".join(_summary(finding) for finding in findings[:3]),
            fixture_repo,
        )


# --- disabling one rule (the mutation seam) -----------------------------------


@contextmanager
def rule_disabled(rule_id: str) -> Iterator[None]:
    """Make the rule with ``rule_id`` emit nothing for the duration of the block.

    The swap is made on the rule's class and keyed on ``meta.id``, so it
    reaches every instance however a test obtained it (``REGISTRY.get``,
    ``REGISTRY.evaluate_all``, or constructing the class itself) and leaves
    sibling rules that share the class (the taint families) working. The
    original ``evaluate`` is restored on exit, also when the block raises.
    """
    cls = type(resolve_rule(rule_id))
    original = cls.evaluate
    owned = "evaluate" in vars(cls)

    def evaluate(self: Rule, ctx: ReasoningContext) -> list[Finding]:
        if self.meta.id == rule_id:
            return []
        return original(self, ctx)

    cls.evaluate = evaluate
    try:
        yield
    finally:
        if owned:
            cls.evaluate = original
        else:
            delattr(cls, "evaluate")


# --- reading the ``rule`` markers ----------------------------------------------


@dataclass(frozen=True)
class FocusedTest:
    """One case of a test that carries the ``rule`` marker: a whole test
    function, or one parametrization of it."""

    rule_ids: tuple[str, ...]
    nodeid: str                      # "<file>::<Class>::<test>[<param id>]"
    func: Callable[..., object]
    argnames: tuple[str, ...]
    values: tuple[object, ...]
    call: Callable[[], None] | None  # None when it cannot be replayed in-process
    blocker: str = ""                # why pytest would not run it, or it cannot be replayed
    active: bool = True              # False: skipped unconditionally, so pytest never runs it


_ParameterSet = type(pytest.param())  # ``pytest.param`` returns it; pytest does not export the class


def _marks(obj: object) -> tuple[Mark, ...]:
    """Marks stored on a module, class or function by ``pytestmark``/``@pytest.mark``."""
    raw = getattr(obj, "pytestmark", ())
    if isinstance(raw, (Mark, MarkDecorator)):
        raw = (raw,)
    return tuple(getattr(mark, "mark", mark) for mark in raw if isinstance(mark, (Mark, MarkDecorator)))


def _marked(obj: object) -> tuple[Mark, ...]:
    """A class's marks include those of its bases, as pytest applies them."""
    if inspect.isclass(obj):
        return tuple(mark for klass in reversed(obj.__mro__) for mark in _marks(klass))
    return _marks(obj)


def _rule_ids(marks: Iterable[Mark], where: str) -> tuple[str, ...]:
    ids: list[str] = []
    for mark in marks:
        if mark.name != RULE_MARKER:
            continue
        if not mark.args or not all(isinstance(arg, str) and arg for arg in mark.args):
            raise HarnessError(
                f"{where}: pytest.mark.rule(...) needs registered rule ids (non-empty strings), "
                f"got args={mark.args!r}"
            )
        ids.extend(mark.args)
    return tuple(dict.fromkeys(ids))


def _axes(marks: Iterable[Mark], where: str) -> list[tuple[tuple[str, ...], tuple[_ParameterSet, ...]]]:
    """``(argnames, parameter sets)`` per ``parametrize`` mark, expanded as pytest does."""
    axes = []
    for mark in marks:
        if mark.name != "parametrize":
            continue
        if len(mark.args) != 2:
            raise HarnessError(f"{where}: malformed parametrize mark, got args={mark.args!r}")
        argnames, values = mark.args
        if isinstance(argnames, str):
            names = tuple(name.strip() for name in argnames.split(",") if name.strip())
            # A lone name takes each entry as the value itself; "name," takes tuples.
            wrap_each = len(names) == 1 and not argnames.rstrip().endswith(",")
        else:
            names, wrap_each = tuple(argnames), False
        sets = tuple(
            value
            if isinstance(value, _ParameterSet)
            else _ParameterSet((value,) if wrap_each else value, (), None)
            for value in values
        )
        axes.append((names, sets))
    return axes


def _param_id(parameter_set: _ParameterSet) -> str:
    """The id pytest shows for a parameter set: the explicit one, else its values."""
    if isinstance(parameter_set.id, str):
        return parameter_set.id
    return "-".join(str(value) for value in parameter_set.values)


def _invoker(
    func: Callable[..., object], owner: type | None, names: tuple[str, ...], values: tuple[object, ...]
) -> Callable[[], None]:
    """Call the test the way pytest does: parametrized values by keyword, and
    a class's test on a fresh instance."""
    kwargs = dict(zip(names, values, strict=True))
    if owner is None:
        return lambda: func(**kwargs)
    return lambda: getattr(owner(), func.__name__)(**kwargs)


def _cases(
    func: Callable[..., object], owners: tuple[type, ...], file: str, outer: Iterable[Mark]
) -> list[FocusedTest]:
    """The ``rule``-marked cases of one test function (a method of ``owners[0]`` if any)."""
    if any(getattr(obj, "__test__", True) is False for obj in (*owners, func)):
        return []
    where = f"{file}::" + "::".join([*(owner.__name__ for owner in owners), func.__name__])
    marks = (*outer, *(mark for owner in owners for mark in _marked(owner)), *_marks(func))
    axes = _axes(marks, where)
    fixed = tuple(mark for mark in marks if mark.name != "parametrize")
    indirect = any(mark.name == "parametrize" and mark.kwargs.get("indirect") for mark in marks)
    parameters = dict(inspect.signature(func).parameters)
    if owners:
        del parameters[next(iter(parameters))]  # a method's ``self``: pytest supplies it by instantiation
    cases: list[FocusedTest] = []
    for combo in itertools.product(*(sets for _, sets in axes)):
        names = tuple(name for axis_names, _ in axes for name in axis_names)
        values = tuple(value for parameter_set in combo for value in parameter_set.values)
        case_marks = (
            *fixed,
            *(getattr(mark, "mark", mark) for parameter_set in combo for mark in parameter_set.marks),
        )
        rule_ids = _rule_ids(case_marks, where)
        if not rule_ids:
            continue
        nodeid = where + (f"[{'-'.join(_param_id(parameter_set) for parameter_set in combo)}]" if combo else "")
        skipped = any(mark.name == "skip" for mark in case_marks)
        blockers = []
        if skipped:
            blockers.append("marked skip")
        if indirect:
            blockers.append("uses indirect parametrize")
        fixtures = [
            name
            for name in parameters
            if name not in names
            and parameters[name].kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        ]
        if fixtures:
            blockers.append(f"needs fixture(s) {', '.join(fixtures)}")
        cases.append(
            FocusedTest(
                rule_ids=rule_ids,
                nodeid=nodeid,
                func=func,
                argnames=names,
                values=values,
                call=None if blockers else _invoker(func, owners[0] if owners else None, names, values),
                blocker="; ".join(blockers),
                active=not skipped,
            )
        )
    return cases


def focused_tests_in(module: ModuleType) -> tuple[FocusedTest, ...]:
    """Every ``rule``-marked case defined in ``module``, in definition order.

    Reads plain ``test_*`` functions and ``test_*`` methods of ``Test*``
    classes (pytest's defaults), with the marks of the module, the class and
    the function.
    """
    if getattr(module, "__test__", True) is False:
        return ()
    file = Path(module.__file__).name if getattr(module, "__file__", None) else module.__name__
    module_marks = _marks(module)
    cases: list[FocusedTest] = []
    for name, obj in list(vars(module).items()):
        if inspect.isfunction(obj) and name.startswith("test_"):
            cases.extend(_cases(obj, (), file, module_marks))
        elif inspect.isclass(obj) and name.startswith("Test"):
            for attr, member in list(vars(obj).items()):
                if inspect.isfunction(member) and attr.startswith("test_"):
                    cases.extend(_cases(member, (obj,), file, module_marks))
    return tuple(cases)


def _imported(path: Path) -> ModuleType | None:
    """The module already imported from ``path`` in this process, if any."""
    for module in list(sys.modules.values()):
        module_file = getattr(module, "__file__", None)
        if (
            isinstance(module_file, str)
            and os.path.basename(module_file) == path.name
            and os.path.samefile(module_file, path)
        ):
            return module
    return None


def _import_privately(path: Path) -> ModuleType:
    """Import a test module pytest did not import in this session (the
    coverage file run on its own), under a private name that cannot collide."""
    name = f"_ar047_tests.{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise HarnessError(f"cannot import test module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def rule_test_modules() -> tuple[ModuleType, ...]:
    """The ``test_*.py`` modules under ``tests/rules``, each imported once.

    Deliberately not named ``test_*``: pytest collects any such name it finds
    in a test module, an imported helper included.

    pytest's own import is reused when the session collected the module; a
    module pytest did not import is imported here under a private name.
    """
    return tuple(
        _imported(path) or _import_privately(path) for path in sorted(RULES_DIR.glob("test_*.py"))
    )


@cache
def _index() -> dict[str, tuple[FocusedTest, ...]]:
    by_rule: dict[str, list[FocusedTest]] = {}
    for module in rule_test_modules():
        for case in focused_tests_in(module):
            for rule_id in case.rule_ids:
                by_rule.setdefault(rule_id, []).append(case)
    return {rule_id: tuple(cases) for rule_id, cases in sorted(by_rule.items())}


def focused_tests_by_rule() -> dict[str, tuple[FocusedTest, ...]]:
    """Active focused tests per rule id, read from the ``rule`` markers under ``tests/rules``."""
    return {
        rule_id: tuple(case for case in cases if case.active) for rule_id, cases in _index().items()
    }


# --- the coverage check -------------------------------------------------------


def untested_rule_ids(focused: Mapping[str, Sequence[FocusedTest]] | None = None) -> list[str]:
    """Registered rule ids with no active focused test, in registry order.

    ``focused`` defaults to the ``rule`` markers under ``tests/rules``; pass a
    mapping to probe the check itself.
    """
    covered = focused_tests_by_rule() if focused is None else focused
    return [
        rule_id
        for rule_id in REGISTRY.ids()
        if not any(case.active for case in covered.get(rule_id, ()))
    ]


def stale_rule_ids(focused: Mapping[str, Sequence[FocusedTest]] | None = None) -> list[str]:
    """Rule ids named by a ``rule`` marker that are not registered: a renamed
    or removed rule, or a typo."""
    named = _index() if focused is None else focused
    return sorted(set(named) - set(REGISTRY.ids()))


def coverage_message(missing: Sequence[str]) -> str:
    listed = "\n  ".join(missing)
    return (
        f"AC-202: {len(missing)} of {len(REGISTRY)} registered rule(s) have no focused test "
        f"under {RULES_DIR.name}:\n  {listed}\n"
        'Mark a test that evaluates the rule with @pytest.mark.rule("<rule_id>") '
        "(tests/rules/conftest.py registers the marker); a parametrized test names the rule "
        'per case with pytest.param(..., marks=pytest.mark.rule("<rule_id>")).'
    )


def assert_every_registered_rule_has_a_focused_test(
    focused: Mapping[str, Sequence[FocusedTest]] | None = None,
) -> None:
    """The AC-202 coverage assertion: every id in ``REGISTRY.ids()`` has at
    least one active focused test."""
    missing = untested_rule_ids(focused)
    assert not missing, coverage_message(missing)


# --- the mutation check -------------------------------------------------------


@dataclass(frozen=True)
class MutationOutcome:
    """What replaying one rule's focused tests showed."""

    rule_id: str
    broken: tuple[str, ...]            # failed with the rule disabled: the mutant is detected
    survived: tuple[str, ...]          # passed with the rule disabled
    control_failures: tuple[str, ...]  # failed before anything was disabled
    unreplayable: tuple[str, ...]      # active focused tests the replay cannot run, with the reason


def replay(case: FocusedTest) -> BaseException | None:
    """Call a focused test as pytest would; return what it raised, or None.

    ``pytest.skip``/``pytest.xfail`` inside the test are not failures (pytest
    reports them as skip/xfail); ``pytest.fail`` is, like any other exception.
    """
    assert case.call is not None, f"{case.nodeid} cannot be replayed: {case.blocker}"
    try:
        case.call()
    except (pytest.skip.Exception, pytest.xfail.Exception):
        return None
    except (Exception, pytest.fail.Exception) as exc:  # any raise is a red test for pytest
        return exc
    return None


def mutation_outcome(rule_id: str, cases: Iterable[FocusedTest] | None = None) -> MutationOutcome:
    """Replay ``rule_id``'s focused tests, then disable the rule and replay them again.

    ``cases`` defaults to the ``rule``-marked tests found for ``rule_id``;
    pass explicit cases to probe the check itself. ``control_failures`` names
    the tests that already fail before anything is disabled (the rule is
    disabled or broken); ``survived`` names those still passing with the rule
    disabled (they do not protect it).
    """
    focused = focused_tests_by_rule().get(rule_id, ()) if cases is None else tuple(cases)
    active = tuple(case for case in focused if case.active)
    runnable = tuple(case for case in active if case.call is not None)
    control = tuple(case.nodeid for case in runnable if replay(case) is not None)
    with rule_disabled(rule_id):
        verdicts = tuple((case.nodeid, replay(case) is not None) for case in runnable)
    return MutationOutcome(
        rule_id=rule_id,
        broken=tuple(nodeid for nodeid, failed in verdicts if failed),
        survived=tuple(nodeid for nodeid, failed in verdicts if not failed),
        control_failures=control,
        unreplayable=tuple(f"{case.nodeid} ({case.blocker})" for case in active if case.call is None),
    )


def mutation_message(outcome: MutationOutcome) -> str:
    if outcome.control_failures:
        listed = "\n  ".join(outcome.control_failures)
        return (
            f"rule {outcome.rule_id!r} looks disabled or broken: {len(outcome.control_failures)} of its "
            f"focused test(s) fail before anything is disabled:\n  {listed}"
        )
    listed = "\n  ".join((*outcome.survived, *outcome.unreplayable))
    return (
        f"mutant survived: disabling rule {outcome.rule_id!r} broke none of its "
        f"{len(outcome.survived) + len(outcome.unreplayable)} focused test(s), so none of them "
        f"checks what the rule emits:\n  {listed or '(the rule has no focused test)'}"
    )


def assert_disabling_the_rule_breaks_a_focused_test(
    rule_id: str, cases: Iterable[FocusedTest] | None = None
) -> MutationOutcome:
    """The AC-202 mutation assertion for one rule: its focused tests pass with
    the rule enabled, and at least one of them fails once it is disabled."""
    outcome = mutation_outcome(rule_id, cases)
    assert not outcome.control_failures, mutation_message(outcome)
    assert outcome.broken, mutation_message(outcome)
    return outcome


# --- throwaway rules for the harness self-tests --------------------------------


@contextmanager
def extra_registered_rule(rule: Rule) -> Iterator[None]:
    """Register ``rule`` in the process-wide ``REGISTRY`` for the duration of the block.

    Self-tests only: it is how the coverage and mutation checks are proven to
    fail for a rule nobody tests. The registry has no public deregistration
    API, so the block snapshots and restores its private index; whatever
    happens inside, the registry is exactly what it was on exit.
    """
    before = dict(REGISTRY._by_id)
    REGISTRY.register(rule)
    try:
        yield
    finally:
        REGISTRY._by_id.clear()
        REGISTRY._by_id.update(before)


class FakeRule:
    """A throwaway rule for the harness self-tests: emits one finding when the
    context carries a route, nothing when built with ``silent=True``. Only
    ever registered inside :func:`extra_registered_rule`."""

    def __init__(self, rule_id: str, *, silent: bool = False) -> None:
        self.meta = RuleMeta(
            id=rule_id,
            title="Harness self-test rule",
            severity="low",
            confidence=0.5,
            rationale="Stand-in for the harness self-tests; never registered outside a with-block.",
        )
        self.silent = silent

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        if self.silent or not ctx.routes:
            return []
        return [
            Finding(
                title=self.meta.title,
                severity="low",
                mitigation="none",
                rule_id=self.meta.id,
                locations=[FindingLocation(file=ctx.routes[0].file)],
            )
        ]

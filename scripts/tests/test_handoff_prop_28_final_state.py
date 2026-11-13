"""Property 28 of the phase 4 spec: the final state comes from the observations alone.

Task 1.18 (Requirements 28.9, 28.10, 28.19 and 28.20). ``evaluate.final_state`` turns what the
runner observed after a ``kiro-cli`` run into ``succeeded``, ``failed`` or ``needs-human``
(design section 20, "結果の確認"). The tests check the four statements of Property 28:

1. The text of the Handoff_Report is not an input. Neither ``final_state`` nor
   ``Observations`` has a place for it, and a run evaluated before and after two reports are
   read, one with request lines and one without, gets the same evaluation each time. The size
   of the standard output (``stdout_bytes``) is an observation, which the query mode needs
   above 0; the text is not.
2. ``succeeded`` exactly when every condition of Property 28 is met. :data:`UNMET` reads the
   conditions from the observations and the declaration without calling ``evaluate``. In query
   mode the report must also not be empty: task 1.10 reads the design's query rule (exit code 0
   and a report that is not empty) as a condition added to those of Property 28.
3. A conflict gives ``needs-human``, also when the run timed out, exited with a code other than
   0, failed a re-run, or wrote an empty query report.
4. The conflict list is this item's changed files that the default branch or another item of
   the batch also changed, with paths compared without letter case or Unicode normalization
   (NFD, case fold, NFD). :func:`folded_intersection` computes it from ``default_branch_files``
   and ``batch_files`` without calling ``evaluate``.

Which state a run gets when several conditions hold (the order of ``evaluate.PRECEDENCE``) is
not checked beyond statement 3.

Each test runs its ``@given`` function from a plain test function, then fails if a shape that
its checks depend on was never seen (each state, both modes, a conflict, ...), and the message
lists how often each shape was seen. A strategy that stopped drawing one would otherwise let the
test pass without checking it. ``--hypothesis-show-statistics`` does not report the inner
``@given`` functions, because the pytest items are the plain functions. Both tests also check
pinned inputs on every run, because the drawn cases do not reach every shape in every run: the
first test, one case of each planted set of conditions (each condition as the only one not met,
for one; :func:`pinned_sources` says which fault each case shows); the second, arguments whose
conflict lists are worked out by hand.

Inputs come from ``strategies.handoff`` (``observations()``, ``report_texts()``) and from the
synthetic file names and commands below.
"""

from __future__ import annotations

import dataclasses
import inspect
import random
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import TypeVar

from handoff import evaluate
from handoff.config import MODES
from handoff.state import FAILED, NEEDS_HUMAN, SUCCEEDED
from hypothesis import Phase, find, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy
from strategies import handoff as handoff_strategies

T = TypeVar("T")
ObservationsCase = handoff_strategies.ObservationsCase
ReportText = handoff_strategies.ReportText

#: The states ``final_state`` returns.
FINAL_STATES: tuple[str, ...] = (SUCCEEDED, FAILED, NEEDS_HUMAN)

# --------------------------------------------------------------------------------------------
# Statement 1: no input for the text of the report
# --------------------------------------------------------------------------------------------

#: The parameters of ``final_state`` and the fields of ``Observations``. None of them carries
#: the text of the Handoff_Report. Before one is added here, check that it does not either.
FINAL_STATE_PARAMETERS: tuple[str, ...] = ("observations", "mode", "declared_files", "verify_commands")
OBSERVATION_FIELDS: frozenset[str] = frozenset(
    {
        "exit_code",
        "timed_out",
        "stdout_bytes",
        "commits",
        "changed_files",
        "undeclared_files",
        "dirty",
        "conflicts",
        "remote_branch_exists",
        "main_tree_change",
        "rerun",
        "rerun_skipped",
    }
)

# --------------------------------------------------------------------------------------------
# Statement 2: the conditions of Property 28, read without evaluate
# --------------------------------------------------------------------------------------------


def _failed_rerun(case: ObservationsCase) -> bool:
    """Whether a declared verification command was re-run and exited with a code other than 0."""
    exit_codes = {entry.cmd: entry.exit_code for entry in case.observations.rerun}
    return any(exit_codes.get(command, 0) != 0 for command in case.verify_commands)


def _unaccounted_command(case: ObservationsCase) -> bool:
    """Whether a declared verification command was neither re-run nor skipped with a reason."""
    rerun = {entry.cmd for entry in case.observations.rerun}
    reasons = {entry.cmd: entry.reason for entry in case.observations.rerun_skipped}
    return any(command not in rerun and not reasons.get(command, "").strip() for command in case.verify_commands)


#: The conditions of Property 28, each by the name it has when it is not met, with a test of
#: whether it is not met. The last two split the condition on the declared verification
#: commands (each one re-run with exit code 0, or not re-run and given a reason), so that each
#: way to miss it is checked alone.
UNMET: tuple[tuple[str, Callable[[ObservationsCase], bool]], ...] = (
    ("timed out", lambda case: case.observations.timed_out),
    ("exit code not 0", lambda case: case.observations.exit_code != 0),
    ("no commit in change mode", lambda case: case.mode == "change" and case.observations.commits < 1),
    ("empty report in query mode", lambda case: case.mode == "query" and case.observations.stdout_bytes < 1),
    (
        "a file changed outside the declared files",
        lambda case: not set(case.observations.changed_files) <= set(case.declared_files),
    ),
    ("uncommitted changes", lambda case: case.observations.dirty),
    ("a conflict", lambda case: bool(case.observations.conflicts)),
    ("the branch on the remote", lambda case: case.observations.remote_branch_exists),
    ("a relevant change in the main tree", lambda case: case.observations.main_tree_change == "relevant"),
    ("a re-run that did not exit with 0", _failed_rerun),
    ("a command neither re-run nor skipped with a reason", _unaccounted_command),
)

#: Unmet conditions about how the run ended or whether its product passed. Used for a label
#: only: which state each leads to is the order of ``evaluate.PRECEDENCE``, not checked here.
FAILURE_SIGNS: frozenset[str] = frozenset(
    {"timed out", "exit code not 0", "a re-run that did not exit with 0", "empty report in query mode"}
)


def unmet_conditions(case: ObservationsCase) -> frozenset[str]:
    """Name the conditions of Property 28 that a run does not meet.

    Args:
        case: The observations and the declaration they were made for.

    Returns:
        The names in :data:`UNMET` whose test holds; empty when every condition is met.
    """
    return frozenset(name for name, is_unmet in UNMET if is_unmet(case))


# --------------------------------------------------------------------------------------------
# Strategies for statements 1 to 3
# --------------------------------------------------------------------------------------------

#: Declarations for :func:`declaring_queries`.
DECLARED_FILES: tuple[str, ...] = ("docs/example.md", "README.md", "日本語の文書/手順.md", "with space/a.md")
VERIFY_COMMANDS: tuple[tuple[str, ...], ...] = (("make", "test"), ("pytest", "-q"), ("python3", "scripts/check.py"))

#: Conditions of ``evaluate.PRECEDENCE`` planted together: a conflict next to a timeout, a
#: non-zero exit code, a failed re-run, or an empty query report. A query declares no files
#: here, so its changed files are undeclared as well.
WITH_A_CONFLICT: tuple[frozenset[str], ...] = (
    frozenset({"conflicts", "timed_out"}),
    frozenset({"conflicts", "exit_code_nonzero"}),
    frozenset({"conflicts", "rerun_failed"}),
    frozenset({"conflicts", "undeclared_files", "empty_output"}),
)


_DECLARED_LISTS = st.lists(st.sampled_from(DECLARED_FILES), min_size=1, max_size=3, unique=True)
_COMMAND_LISTS = st.lists(st.sampled_from(VERIFY_COMMANDS), max_size=2, unique=True)


@st.composite
def declaring_queries(draw: st.DrawFn) -> ObservationsCase:
    """Draw observations of a query item that declares files and verification commands.

    ``manifest`` refuses such an item (task 1.4), but ``final_state`` applies the same rules to
    one, so the property covers it.
    """
    declared, commands = draw(_DECLARED_LISTS), draw(_COMMAND_LISTS)
    return draw(handoff_strategies.observations(mode="query", declared_files=declared, verify_commands=commands))


def _quiet_extras(case: ObservationsCase) -> bool:
    """Whether a run shows things that keep no condition from being met.

    That is an unrelated change in the main tree, a command skipped with a reason, and a re-run
    with exit code 0.
    """
    observed = case.observations
    return observed.main_tree_change == "unrelated" and bool(observed.rerun_skipped) and bool(observed.rerun)


def _undeclared_by_letter_case(case: ObservationsCase) -> bool:
    """Whether the changed files outside the declared ones differ from declared files only in letter case.

    At least one changed file is outside, and each one outside is a declared file written in
    another letter case, so a comparison that ignored letter case would find no file outside.
    Read from ``changed_files`` and ``declared_files``, not from ``undeclared_files``, which
    ``evaluate.undeclared_files`` computed.
    """
    declared = set(case.declared_files)
    folded = {path.casefold() for path in declared}
    outside = [path for path in case.observations.changed_files if path not in declared]
    return bool(outside) and all(path.casefold() in folded for path in outside)


@dataclass(frozen=True)
class PinnedSource:
    """Where one pinned case comes from: one case of each source is checked on every run.

    Attributes:
        name: The name, for the messages.
        strategy: The strategy that draws the case.
        condition: What the case must meet, or ``None`` for the first case drawn.
    """

    name: str
    strategy: SearchStrategy[ObservationsCase]
    condition: Callable[[ObservationsCase], bool] | None = None


def pinned_sources() -> tuple[PinnedSource, ...]:
    """List the sources of the pinned cases.

    Every condition met in each mode, and once more with :func:`_quiet_extras`; each condition
    of ``evaluate.PRECEDENCE`` planted alone, which makes it the only condition of Property 28
    not met (both re-run conditions are the condition on verification commands); files outside
    the declaration that only letter case tells from declared ones
    (:func:`_undeclared_by_letter_case`); each set of :data:`WITH_A_CONFLICT`; and
    :func:`declaring_queries`.

    Each of these is the kind of case that one kind of fault in ``final_state`` needs in order
    to show:

    - ignoring one condition: a case where that condition is the only one not met. With
      another condition not met as well, the state is not ``succeeded`` either way;
    - adding a condition: a case that meets every condition;
    - not counting a skip reason: such a case with a command skipped for a reason;
    - ignoring letter case when comparing with the declaration: a case where nothing but
      letter case puts files outside it;
    - letting a timeout, a non-zero exit code, a failed re-run or an empty query report decide
      the state when there is a conflict: a case with both.

    The drawn cases do not reach every one of these in every run, so one case of each is
    checked on every run.

    Returns:
        The sources.
    """
    observations = handoff_strategies.observations
    return (
        *(
            PinnedSource(f"every condition met, mode {mode}", observations(mode=mode, conditions=frozenset()))
            for mode in MODES
        ),
        PinnedSource(
            "every condition met, with quiet extras",
            observations(mode="change", conditions=frozenset()),
            _quiet_extras,
        ),
        *(
            PinnedSource(f"{condition} alone", observations(conditions={condition}))
            for condition, _ in evaluate.PRECEDENCE
        ),
        PinnedSource(
            "undeclared_files alone, by letter case",
            observations(conditions={"undeclared_files"}),
            _undeclared_by_letter_case,
        ),
        *(PinnedSource(" and ".join(sorted(planted)), observations(conditions=planted)) for planted in WITH_A_CONFLICT),
        PinnedSource("a query that declares files", declaring_queries()),
    )


def cases() -> SearchStrategy[ObservationsCase]:
    """Draw observations from one of several sources, each picked with the same weight.

    Four sources draw a subset of conditions (``observations()``); the others are the strategies
    of the pinned sources. Hypothesis does not pick the sources evenly, and a run can leave one
    undrawn; the pinned cases check each one anyway.

    Returns:
        A strategy of ``ObservationsCase``.
    """
    drawn = handoff_strategies.observations()
    sources = (*(drawn for _ in range(4)), *(source.strategy for source in pinned_sources()))
    return st.sampled_from(sources).flatmap(lambda source: source)


#: Settings for :func:`pinned_case`: no example database and no shrinking, so the first value
#: that meets the condition is returned.
SEARCH = settings(max_examples=1_000, deadline=None, database=None, phases=[Phase.generate])

#: The seed of :func:`pinned_case`, so that it finds the same value on every run.
SEED = 20261111


def pinned_case(strategy: SearchStrategy[T], condition: Callable[[T], bool] | None = None) -> T:
    """Return the first value of a strategy that meets a condition, the same on every run.

    ``find`` with a fixed seed, as ``reach`` of ``test_handoff_strategies.py`` does.

    Args:
        strategy: The strategy.
        condition: What the value must meet; ``None`` takes the first value drawn.

    Returns:
        The value.
    """
    return find(strategy, condition or (lambda _: True), settings=SEARCH, random=random.Random(SEED))


def report_pairs() -> SearchStrategy[tuple[ReportText, ReportText]]:
    """Draw two reports of up to four lines: one with at least one request line, then one with none.

    Four lines keep the draws cheap; ``final_state`` reads no line, so more lines would test
    ``report_texts`` rather than the property.
    """
    return st.tuples(
        handoff_strategies.report_texts(requests=True, max_lines=4),
        handoff_strategies.report_texts(requests=False, max_lines=4),
    )


def final_state_of(case: ObservationsCase) -> evaluate.Evaluation:
    """Evaluate a case with its own declaration, as the runner does after a run."""
    return evaluate.final_state(
        case.observations,
        mode=case.mode,
        declared_files=case.declared_files,
        verify_commands=case.verify_commands,
    )


CONFLICT_WITH_A_FAILURE_SIGN = "a conflict with a timeout, a non-zero exit code, a failed re-run or an empty report"
MET_WITH_QUIET_EXTRAS = "every condition met, with an unrelated main tree change, a skip and a passing re-run"
UNDECLARED_BY_LETTER_CASE = "changed files outside the declaration that only letter case tells from declared ones"

#: The shapes that the pinned cases must give: each condition as the only one not met, every
#: condition met in each mode and with quiet extras, undeclared files told apart by letter case
#: alone, a conflict next to a sign of failure, and a query that declares files.
PINNED_SHAPES: frozenset[str] = frozenset(
    {f"only unmet: {name}" for name, _ in UNMET}
    | {f"every condition met, mode {mode}" for mode in MODES}
    | {MET_WITH_QUIET_EXTRAS, UNDECLARED_BY_LETTER_CASE, CONFLICT_WITH_A_FAILURE_SIGN, "a query that declares files"}
)

#: The shapes that the drawn cases must give in each run: each state, both modes, a conflict,
#: and two reports that ``report_flags`` reads differently.
DRAWN_SHAPES: frozenset[str] = frozenset(
    {f"state {state}" for state in FINAL_STATES}
    | {f"mode {mode}" for mode in MODES}
    | {"a conflict", "reports with different flags"}
)


def check_run(case: ObservationsCase, reports: tuple[ReportText, ReportText], where: str) -> set[str]:
    """Check statements 1 to 3 on one run, and label the shapes the run has.

    Statement 1: the run is evaluated before and after ``report_flags`` reads each of two
    reports, the way the runner reads a report next to the evaluation. State that reading a
    report leaves behind in the module would show as a different evaluation.

    Args:
        case: The observations and the declaration.
        reports: Two reports.
        where: Which case this is, for the messages.

    Returns:
        The shapes of :data:`PINNED_SHAPES` and :data:`DRAWN_SHAPES` that the run has.
    """
    evaluation = final_state_of(case)
    flags: list[tuple[evaluate.ReportFlag, ...]] = []
    for report in reports:
        flags.append(evaluate.report_flags(report.text))
        assert final_state_of(case) == evaluation, f"{where}: the evaluation changed after a report was read"
    unmet = unmet_conditions(case)
    state = evaluation.state
    assert state in FINAL_STATES, f"{where}: {state!r}"
    assert (state == SUCCEEDED) == (not unmet), f"{where}: {state} with unmet conditions {sorted(unmet)}"
    if case.observations.conflicts:
        assert state == NEEDS_HUMAN, f"{where}: {state} with conflicts {case.observations.conflicts}"

    labels = {f"state {state}", f"mode {case.mode}"}
    if not unmet:
        labels.add(f"every condition met, mode {case.mode}")
        if _quiet_extras(case):
            labels.add(MET_WITH_QUIET_EXTRAS)
    if len(unmet) == 1:
        labels.add(f"only unmet: {min(unmet)}")
    if _undeclared_by_letter_case(case):
        labels.add(UNDECLARED_BY_LETTER_CASE)
    if case.observations.conflicts:
        labels.add("a conflict")
        if unmet & FAILURE_SIGNS:
            labels.add(CONFLICT_WITH_A_FAILURE_SIGN)
    if case.mode == "query" and case.declared_files:
        labels.add("a query that declares files")
    if flags[0] != flags[1]:
        labels.add("reports with different flags")
    return labels


# Feature: cyber-resilience-phase4-supply-chain, Property 28: 最終状態は観測だけで決まり、Handoff_Report の本文に依存しない
def test_property_28_final_state_comes_from_the_observations_alone() -> None:
    """Statements 1 to 3: no report text in, ``succeeded`` exactly when all is met, a conflict needs a human.

    Statement 1 is first checked statically: no parameter and no field can carry the text. Then
    one case of each pinned source (:func:`pinned_case`) and 150 drawn cases go through
    :func:`check_run`.

    **Validates: Requirements 28.9, 28.10, 28.19, 28.20**
    """
    assert tuple(inspect.signature(evaluate.final_state).parameters) == FINAL_STATE_PARAMETERS
    assert {field.name for field in dataclasses.fields(evaluate.Observations)} == OBSERVATION_FIELDS

    pinned: Counter[str] = Counter()
    pinned_reports = pinned_case(report_pairs())
    for source in pinned_sources():
        case = pinned_case(source.strategy, source.condition)
        pinned.update(check_run(case, pinned_reports, f"pinned case '{source.name}'"))

    drawn: Counter[str] = Counter()

    @settings(max_examples=150, deadline=None, derandomize=True)
    @given(case=cases(), reports=report_pairs())
    def check(case: ObservationsCase, reports: tuple[ReportText, ReportText]) -> None:
        drawn.update(check_run(case, reports, "drawn case"))

    check()
    missing = sorted(PINNED_SHAPES - pinned.keys()) + sorted(DRAWN_SHAPES - drawn.keys())
    assert (
        not missing
    ), f"never seen: {missing}; pinned: {dict(sorted(pinned.items()))}; drawn: {dict(sorted(drawn.items()))}"


# --------------------------------------------------------------------------------------------
# Statement 4: the conflict list
# --------------------------------------------------------------------------------------------


def fold(path: str) -> str:
    """Fold a path for comparison: NFD, case fold, NFD, the comparison of task 1.10."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", path).casefold())


def folded_intersection(
    changed_files: Iterable[str], default_branch_files: Iterable[str], batch_files: Iterable[str]
) -> tuple[str, ...]:
    """Compute the conflict list from its definition.

    Args:
        changed_files: This item's changed files.
        default_branch_files: The files changed on the default branch.
        batch_files: The files changed by the other items of the batch.

    Returns:
        This item's changed files, as this item spells them, that fold to the same path as a
        file of either other side; sorted, each once.
    """
    others = {fold(path) for path in (*default_branch_files, *batch_files)}
    return tuple(sorted({path for path in changed_files if fold(path) in others}))


#: File names in groups whose names fold to the same name: through case folding that
#: ``str.lower`` does not do (ß, the fi ligature) and through NFD (the Kelvin and Angstrom signs).
FOLD_GROUPS: tuple[tuple[str, ...], ...] = (
    ("Stra\u00dfe.md", "STRASSE.md", "strasse.md"),
    ("\ufb01le.md", "FILE.md", "file.md"),
    ("\u212a-sign.md", "K-sign.md", "k-sign.md"),
    ("\u212b.md", "\u00c5.md", "a\u030a.md"),
)


def _group_respelling(path: str) -> str:
    """Respell the file name of a path as the next name of its group in :data:`FOLD_GROUPS`, if any."""
    directory, _, name = path.rpartition("/")
    for group in FOLD_GROUPS:
        if name in group:
            name = group[(group.index(name) + 1) % len(group)]
            break
    return f"{directory}/{name}" if directory else name


def _full_width(path: str) -> str:
    """Write the ASCII letters of a path as full-width letters, which NFKC would turn back."""
    return "".join(chr(ord(char) + 0xFEE0) if char.isascii() and char.isalpha() else char for char in path)


#: How a changed path is put on another side. The first eight respell the path; the last four
#: make a look-alike of it. :func:`fold` decides whether the result is the same file, not the
#: name of the spelling.
SPELLINGS: Mapping[str, Callable[[str], str]] = {
    "as written": lambda path: path,
    "upper case": str.upper,
    "lower case": str.lower,
    "swapped case": str.swapcase,
    "case folded": str.casefold,
    "NFD": lambda path: unicodedata.normalize("NFD", path),
    "NFC": lambda path: unicodedata.normalize("NFC", path),
    "another name of its group": _group_respelling,
    "full-width letters": _full_width,
    "a zero-width space": lambda path: path[:1] + "\u200b" + path[1:],
    "a file below it": lambda path: path + "/x",
    "its directory, or a longer name": lambda path: path.rpartition("/")[0] or path + "x",
}


@dataclass(frozen=True)
class Sides:
    """The arguments of ``conflicting_files``.

    Attributes:
        changed_files: This item's changed files.
        default_branch_files: The files changed on the default branch.
        batch_files: The files changed by the other items of the batch.
    """

    changed_files: tuple[str, ...]
    default_branch_files: tuple[str, ...]
    batch_files: tuple[str, ...]


_OBSERVATIONS_FOR_CONFLICTS = st.one_of(
    handoff_strategies.observations(), handoff_strategies.observations(conditions={"conflicts"})
)
_GROUP_FILES = st.lists(
    st.tuples(
        st.sampled_from(("", "docs/", "日本語の文書/")),
        st.sampled_from(tuple(name for group in FOLD_GROUPS for name in group)),
    ),
    min_size=1,
    max_size=2,
)
_SPELLING_NAMES = st.sampled_from(tuple(SPELLINGS))
_SIDE_NAMES = st.sampled_from(("default", "batch"))


@st.composite
def conflict_cases(draw: st.DrawFn) -> tuple[ObservationsCase, Sides]:
    """Draw observations, and wider arguments for ``conflicting_files`` built on them.

    The observations have a planted conflict or a drawn subset of conditions. The wider
    arguments add one or two changed files named from :data:`FOLD_GROUPS`, and put up to four
    changed files on the default branch or in the batch, each in one of the :data:`SPELLINGS`.

    Returns:
        The observations, and the wider arguments.
    """
    case = draw(_OBSERVATIONS_FOR_CONFLICTS)
    changed = list(case.observations.changed_files)
    for directory, name in draw(_GROUP_FILES):
        if directory + name not in changed:
            changed.append(directory + name)
    sides: dict[str, list[str]] = {"default": list(case.default_branch_files), "batch": list(case.batch_files)}
    for path in draw(st.lists(st.sampled_from(changed), max_size=4)):
        sides[draw(_SIDE_NAMES)].append(SPELLINGS[draw(_SPELLING_NAMES)](path))
    return case, Sides(tuple(changed), tuple(sides["default"]), tuple(sides["batch"]))


def _lower_fold(path: str) -> str:
    """Fold with ``str.lower`` instead of case folding: a label only."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", path).lower())


def _nfkc_fold(path: str) -> str:
    """Fold with NFKC instead of NFD: a label only."""
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", path).casefold())


#: Arguments of ``conflicting_files`` checked on every run, each with the conflict list worked
#: out by hand: the same file through case folding that ``str.lower`` does not do (ß, the fi
#: ligature), through NFD (the Kelvin and Angstrom signs, a decomposed é) and through letter case
#: alone; and other files that look alike (full-width letters, a zero-width space, a file below
#: or above a changed file).
PINNED_CONFLICTS: tuple[tuple[Sides, tuple[str, ...]], ...] = (
    (Sides(("docs/Stra\u00dfe.md",), ("docs/STRASSE.md",), ()), ("docs/Stra\u00dfe.md",)),
    (Sides(("\ufb01le.md", "guide.md"), (), ("FILE.md",)), ("\ufb01le.md",)),
    (Sides(("\u212a-sign.md",), ("k-sign.md",), ()), ("\u212a-sign.md",)),
    (Sides(("\u212b.md",), (), ("a\u030a.md",)), ("\u212b.md",)),
    (Sides(("caf\u00e9.md",), ("CAFE\u0301.md",), ()), ("caf\u00e9.md",)),
    (Sides(("README.md", "readme.md"), ("Readme.md",), ("other/README.md",)), ("README.md", "readme.md")),
    (Sides(("file.md",), ("\uff46\uff49\uff4c\uff45.md",), ("f\u200bile.md",)), ()),
    (Sides(("docs/a.md",), ("docs/a.md/x",), ("docs",)), ()),
)

#: The shapes that the pinned arguments must give. Four of them tell the folding of task 1.10
#: from folding that finds too little (``str.lower``) or too much (NFKC, dropping format
#: characters, matching a directory with the files below it).
PINNED_CONFLICT_SHAPES: frozenset[str] = frozenset(
    {
        "a conflict",
        "no conflict",
        "a conflict found only by folding",
        "a conflict that str.lower would miss",
        "another file that NFKC would merge",
        "another file that dropping format characters would merge",
        "another file below or above a changed file",
    }
)

#: The shapes that the drawn arguments must give in each run.
DRAWN_CONFLICT_SHAPES: frozenset[str] = frozenset({"a conflict", "a conflict found only by folding"})


def conflict_shapes(sides: Sides, expected: tuple[str, ...]) -> set[str]:
    """Label one example with the shapes of :data:`PINNED_CONFLICT_SHAPES` that it has.

    Args:
        sides: The arguments of ``conflicting_files``.
        expected: The conflict list from its definition.

    Returns:
        The labels.
    """
    others = (*sides.default_branch_files, *sides.batch_files)
    labels = {"a conflict" if expected else "no conflict"}
    if set(expected) - set(others):
        labels.add("a conflict found only by folding")
    for path in sides.changed_files:
        for other in others:
            same = fold(other) == fold(path)
            if same and _lower_fold(other) != _lower_fold(path):
                labels.add("a conflict that str.lower would miss")
            if not same and _nfkc_fold(other) == _nfkc_fold(path):
                labels.add("another file that NFKC would merge")
            if not same and other.replace("\u200b", "") == path:
                labels.add("another file that dropping format characters would merge")
            if fold(other).startswith(fold(path) + "/") or fold(path).startswith(fold(other) + "/"):
                labels.add("another file below or above a changed file")
    return labels


def check_conflicts(sides: Sides, expected: tuple[str, ...], where: str) -> set[str]:
    """Check that ``conflicting_files`` gives the expected list, and label the shapes of the arguments.

    Args:
        sides: The arguments of ``conflicting_files``.
        expected: The conflict list.
        where: Which arguments these are, for the message.

    Returns:
        The shapes of :data:`PINNED_CONFLICT_SHAPES` that the arguments have.
    """
    found = evaluate.conflicting_files(sides.changed_files, sides.default_branch_files, sides.batch_files)
    assert found == expected, f"{where}: conflicting_files gives {found}, not {expected}"
    return conflict_shapes(sides, expected)


# Feature: cyber-resilience-phase4-supply-chain, Property 28: 最終状態は観測だけで決まり、Handoff_Report の本文に依存しない
def test_property_28_conflict_list_is_the_folded_intersection() -> None:
    """Statement 4: the conflicts of the observations, and ``conflicting_files``, are the folded intersection.

    The pinned arguments are checked against lists worked out by hand, and against
    :func:`folded_intersection`, so that the definition in this file is checked too. For the
    drawn cases, the conflicts of the observations are the list that ``final_state`` reads
    (``observations()`` builds it with ``conflicting_files``), and ``conflicting_files`` is then
    called with the wider arguments.

    **Validates: Requirements 28.9, 28.10, 28.19, 28.20**
    """
    pinned: Counter[str] = Counter()
    for index, (sides, by_hand) in enumerate(PINNED_CONFLICTS):
        where = f"pinned arguments {index}"
        definition = folded_intersection(sides.changed_files, sides.default_branch_files, sides.batch_files)
        assert definition == by_hand, f"{where}: the definition gives {definition}, not {by_hand}"
        pinned.update(check_conflicts(sides, by_hand, where))

    drawn: Counter[str] = Counter()

    @settings(max_examples=100, deadline=None, derandomize=True)
    @given(drawn_case=conflict_cases())
    def check(drawn_case: tuple[ObservationsCase, Sides]) -> None:
        case, sides = drawn_case
        observed = case.observations
        listed = folded_intersection(observed.changed_files, case.default_branch_files, case.batch_files)
        assert observed.conflicts == listed, f"the observations hold {observed.conflicts}, not {listed}"
        expected = folded_intersection(sides.changed_files, sides.default_branch_files, sides.batch_files)
        drawn.update(check_conflicts(sides, expected, "drawn arguments"))

    check()
    missing = sorted(PINNED_CONFLICT_SHAPES - pinned.keys()) + sorted(DRAWN_CONFLICT_SHAPES - drawn.keys())
    assert (
        not missing
    ), f"never seen: {missing}; pinned: {dict(sorted(pinned.items()))}; drawn: {dict(sorted(drawn.items()))}"

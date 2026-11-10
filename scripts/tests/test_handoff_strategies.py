"""Self-checks of the hypothesis strategies in ``scripts/tests/strategies/handoff.py``.

Task 1.11 of the phase 4 spec. Each test checks that one strategy makes what its docstring
says. The pure-core modules are the reference for the shape of a value (``parse_config``,
``parse_manifest``, ``check_status``, ``scan.check``, ``prompt.render``, ``final_state``,
``report_flags``): what a case says it planted must be what the module finds. Properties 22 to
29 are not checked here; tasks 1.12 to 1.19 check them.

:func:`reach` (``find`` with a fixed seed and without shrinking) shows that a strategy can draw
a shape that the property tests depend on, such as a trailing slash or a cycle of one item.
Every value is synthetic; see the docstring of the strategies module.
"""

from __future__ import annotations

import random
import re
import unicodedata
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, TypeVar

import pytest
from handoff import config, evaluate, executor, manifest, prompt, scan, state
from hypothesis import Phase, find, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy
from strategies import handoff as hs

T = TypeVar("T")

#: The default for a strategy whose values are cheap to check.
LIGHT = settings(max_examples=50, deadline=None)

#: For the checks that render prompts or build several cases per example.
HEAVY = settings(max_examples=25, deadline=None)

#: For :func:`reach`: stop at the first value found, without shrinking it, and keep no
#: example database.
SEARCH = settings(max_examples=1_000, deadline=None, database=None, phases=[Phase.generate])

#: The seed of :func:`reach`, so that a search draws the same values on every run.
SEED = 20261111


def reach(strategy: SearchStrategy[T], condition: Callable[[T], bool]) -> T:
    """Find a value of a strategy that meets a condition, the same way on every run.

    A fixed seed makes the search deterministic: it cannot pass on one run and fail on the
    next. It fails with ``hypothesis.errors.NoSuchExample`` when 1,000 values hold no match.

    Args:
        strategy: The strategy to search.
        condition: What the value must meet.

    Returns:
        The first value found.
    """
    return find(strategy, condition, settings=SEARCH, random=random.Random(SEED))


def issues_of(error: config.ConfigError | manifest.ManifestError) -> set[tuple[str, str]]:
    """Return ``(path, kind)`` of every issue of a configuration or manifest error.

    Args:
        error: The error.

    Returns:
        The locations and kinds.
    """
    return {(issue.path, issue.kind) for issue in error.issues}


def test_the_strategies_import_by_package_name() -> None:
    """``scripts/tests/`` is on ``sys.path``, so ``strategies`` is this directory's package."""
    assert hs.__name__ == "strategies.handoff"
    assert Path(hs.__file__).resolve() == Path(__file__).resolve().parent / "strategies" / "handoff.py"


# --------------------------------------------------------------------------------------------
# configs()
# --------------------------------------------------------------------------------------------


@LIGHT
@given(hs.configs())
def test_valid_configs_pass_parse_config(case: hs.ConfigCase) -> None:
    """A valid case parses to its ``config``, and its paths stay under the home directory."""
    assert case.valid and case.expected_issues == frozenset()
    checked = case.parse()
    assert checked == case.config
    assert config.normalize_path(checked.kiro_cli, case.home).startswith("/")
    assert config.is_within(checked.worktrees_root, case.home)
    assert all(config.is_within(repo.main_tree, case.home) for repo in checked.repos.values())
    assert set(checked.mode_tool_ceiling["change"]) <= set(hs.TOOL_NAMES)
    assert set(checked.repos) <= set(hs.REPO_NAMES)


@LIGHT
@given(hs.configs(valid=False))
def test_invalid_configs_raise_exactly_the_planted_issues(case: hs.ConfigCase) -> None:
    """Every planted defect is reported, and nothing else is."""
    assert not case.valid and case.expected_issues
    with pytest.raises(config.ConfigError) as caught:
        case.parse()
    assert issues_of(caught.value) == case.expected_issues


@LIGHT
@given(hs.configs(valid=False, defect_keys=config.LIMIT_KEYS, defect_kinds=("missing",)))
def test_missing_limit_keys_are_reported_as_missing(case: hs.ConfigCase) -> None:
    """The limit keys of decision D-14 can be removed one to three at a time."""
    assert all(path in config.LIMIT_KEYS and kind == "missing" for path, kind in case.expected_issues)
    assert {path for path, _ in case.expected_issues}.isdisjoint(case.raw)
    with pytest.raises(config.ConfigError) as caught:
        case.parse()
    assert issues_of(caught.value) == case.expected_issues


def test_every_config_defect_alone_gives_its_issue() -> None:
    """Each entry of ``CONFIG_DEFECTS``, applied alone to one valid configuration, gives its issue."""
    base = reach(hs.configs(), lambda case: True)
    for defect in hs.CONFIG_DEFECTS:
        raw = dict(base.raw)
        if defect.value is hs.MISSING:
            del raw[defect.key]
        else:
            raw[defect.key] = defect.value
        with pytest.raises(config.ConfigError) as caught:
            config.parse_config(
                raw,
                home=base.home,
                extra_main_trees=base.extra_main_trees,
                session_worktrees_dir=base.session_worktrees_dir,
            )
        assert issues_of(caught.value) == {defect.issue}, defect


# --------------------------------------------------------------------------------------------
# paths() and item_ids()
# --------------------------------------------------------------------------------------------


@LIGHT
@given(hs.paths())
def test_paths_normalize_to_absolute_paths(path: str) -> None:
    """Every drawn path can be a ``worktrees_root``, a main working tree or a protected path."""
    assert config.normalize_path(path, hs.HOME).startswith("/")


PATH_SHAPES: dict[str, Callable[[str], bool]] = {
    "trailing slash": lambda path: len(path) > 1 and path.endswith("/"),
    "dot-dot component": lambda path: ".." in path.split("/"),
    "double slash": lambda path: "//" in path,
    "NFD spelling": lambda path: unicodedata.normalize("NFC", path) != path,
    "home as ~": lambda path: path == "~",
}


@pytest.mark.parametrize("shape", sorted(PATH_SHAPES))
def test_paths_reach_each_shape(shape: str) -> None:
    """The shapes that Property 25 needs are drawn."""
    reach(hs.paths(), PATH_SHAPES[shape])


def _normalized_pair(pair: tuple[str, str]) -> tuple[str, str]:
    """Normalize two drawn paths against the synthetic home directory."""
    return config.normalize_path(pair[0], hs.HOME), config.normalize_path(pair[1], hs.HOME)


PAIR_SHAPES: dict[str, Callable[[str, str], bool]] = {
    "shared string prefix, not nested": lambda a, b: b.startswith(a) and not config.overlaps(a, b),
    "nested": lambda a, b: a != b and config.is_within(b, a),
    "differ only in letter case": lambda a, b: a != b and a.casefold() == b.casefold(),
    "differ only in NFC and NFD": lambda a, b: (
        a != b and unicodedata.normalize("NFC", a) == unicodedata.normalize("NFC", b)
    ),
    "equal after normalization": lambda a, b: a == b,
}


@LIGHT
@given(hs.related_paths())
def test_related_paths_normalize_to_absolute_paths(family: tuple[str, ...]) -> None:
    """Every derived path is still accepted by ``normalize_path``."""
    assert 2 <= len(family) <= 6
    assert all(config.normalize_path(path, hs.HOME).startswith("/") for path in family)


@pytest.mark.parametrize("shape", sorted(PAIR_SHAPES))
def test_related_paths_reach_each_relation(shape: str) -> None:
    """Two related paths can stand in each relation that the overlap check must tell apart.

    For the last relation the two paths are written differently and normalize to one path.
    """

    def holds(family: tuple[str, ...]) -> bool:
        first, second = _normalized_pair((family[0], family[1]))
        return family[0] != family[1] and PAIR_SHAPES[shape](first, second)

    reach(hs.related_paths(min_size=2, max_size=2), holds)


@LIGHT
@given(hs.item_ids())
def test_item_ids_have_the_manifest_form(item_id: str) -> None:
    """An ID is a slug of 64 characters at most, without a 12-digit group."""
    assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item_id)
    assert len(item_id) <= manifest.MAX_ID_LENGTH
    assert not re.search(r"[0-9]{12}", item_id)


# --------------------------------------------------------------------------------------------
# manifests() and confirmed_refs()
# --------------------------------------------------------------------------------------------


@LIGHT
@given(hs.manifests())
def test_acyclic_manifests_pass_parse_manifest(case: hs.ManifestCase) -> None:
    """An acyclic case parses to its ``manifest``, item for item and in order."""
    assert case.manifest is not None and case.cycle == ()
    assert manifest.parse_manifest(case.raw, config=case.config) == case.manifest
    assert tuple(item.id for item in case.manifest.items) == case.ids
    assert set(case.templates) == set(case.ids)


@LIGHT
@given(hs.manifests(cyclic=True))
def test_cyclic_manifests_are_rejected_for_cycles_only(case: hs.ManifestCase) -> None:
    """A cyclic case fails with ``cycle`` issues and no other kind; the planted edges are there."""
    assert case.manifest is None and case.cycle
    depends_on = {item["id"]: item["depends_on"] for item in case.raw["items"]}
    for position, member in enumerate(case.cycle):
        assert case.cycle[(position + 1) % len(case.cycle)] in depends_on[member]
    with pytest.raises(manifest.ManifestError) as caught:
        manifest.parse_manifest(case.raw, config=case.config)
    assert {kind for _, kind in issues_of(caught.value)} == {"cycle"}


@pytest.mark.parametrize(
    "condition",
    [
        pytest.param(lambda case: len(case.cycle) == 1, id="an item that depends on itself"),
        pytest.param(lambda case: len(case.cycle) == 3, id="a cycle of three items"),
    ],
)
def test_cyclic_manifests_reach_each_cycle_length(condition: Callable[[hs.ManifestCase], bool]) -> None:
    """Both a self-dependency and a longer cycle are drawn."""
    reach(hs.manifests(cyclic=True), condition)


def _items(case: hs.ManifestCase) -> tuple[manifest.Item, ...]:
    """The checked items of an acyclic case."""
    assert case.manifest is not None
    return case.manifest.items


@pytest.mark.parametrize(
    "condition",
    [
        pytest.param(
            lambda case: any(ref.repo != item.repo for item in _items(case) for ref in item.requires_refs),
            id="a ref of another repository",
        ),
        pytest.param(
            lambda case: any(ref.repo == item.repo for item in _items(case) for ref in item.requires_refs),
            id="a ref of the item's own repository",
        ),
        pytest.param(lambda case: any(item.mode == "query" for item in _items(case)), id="a query item"),
        pytest.param(lambda case: any(item.trust_all is not None for item in _items(case)), id="trust_all"),
    ],
)
def test_acyclic_manifests_reach_each_item_shape(condition: Callable[[hs.ManifestCase], bool]) -> None:
    """Refs within and across repositories, query items and ``trust_all`` are drawn."""
    reach(hs.manifests(), condition)


@LIGHT
@given(st.data())
def test_confirmed_refs_come_from_the_manifest_or_an_unlisted_repository(data: st.DataObject) -> None:
    """A confirmed ref is a ref that an item requires, or one that no item can require."""
    case = data.draw(hs.manifests())
    assert case.manifest is not None
    refs = data.draw(hs.confirmed_refs(case.manifest))
    required = {ref for item in case.manifest.items for ref in item.requires_refs}
    assert all(ref in required or ref.repo not in case.config.repos for ref in refs)


# --------------------------------------------------------------------------------------------
# prompt_vars() and rendering
# --------------------------------------------------------------------------------------------


def _scanned_kinds(values: Iterable[str], terms: tuple[str, ...]) -> set[str]:
    """Return the kinds that ``scan.check`` finds in the values, one value per line."""
    return {finding.kind for finding in scan.check("\n".join(values), terms)}


@LIGHT
@given(hs.prompt_vars())
def test_prompt_vars_are_single_lines_and_hold_exactly_the_planted_kinds(pv: hs.PromptVars) -> None:
    """Each value is one non-blank line; the scan finds the planted kinds and no other."""
    for value in pv.vars.values():
        assert value.strip() and "\x00" not in value and value.splitlines() == [value]
        value.encode("utf-8")
    assert len(pv.placement) == len(pv.vars)
    assert all(term.startswith(("Zq", "ヅ")) for term in pv.deny_terms)
    assert _scanned_kinds(pv.vars.values(), pv.deny_terms) == pv.planted


@pytest.mark.parametrize("kind", hs.PLANTABLE_KINDS)
@settings(max_examples=20, deadline=None)
@given(data=st.data())
def test_each_kind_planted_alone_is_found(kind: str, data: st.DataObject) -> None:
    """Each kind of Property 26, planted alone, is found, and only it."""
    pv = data.draw(hs.prompt_vars(planted={kind}))
    assert _scanned_kinds(pv.vars.values(), pv.deny_terms) == {kind}


def test_placeholders_are_mixed_into_clean_values() -> None:
    """Values with nothing planted can hold all three placeholders."""
    pv = reach(
        hs.prompt_vars(planted=()),
        lambda pv: all(any(placeholder in value for value in pv.vars.values()) for placeholder in prompt.PLACEHOLDERS),
    )
    assert _scanned_kinds(pv.vars.values(), pv.deny_terms) == set()


@HEAVY
@given(st.data())
def test_rendered_prompts_find_exactly_the_planted_kinds(data: st.DataObject) -> None:
    """Every item renders; the body of the item with the variables has the planted kinds only.

    The other items keep their template without placeholders, so their bodies show that the
    strings of ``manifests()`` and ``configs()`` are scan-clean with the deny terms present.
    """
    case = data.draw(hs.manifests(max_items=4))
    assert case.manifest is not None
    confirmed = data.draw(hs.confirmed_refs(case.manifest))
    target = data.draw(st.sampled_from(case.ids))
    pv = data.draw(hs.prompt_vars())
    case = case.with_prompt_vars(target, pv)
    assert case.manifest is not None
    for item_id in case.ids:
        rendered = prompt.render(
            case.manifest,
            item_id,
            config=case.config,
            template_text=case.template_text(item_id),
            uncommitted_count=data.draw(st.integers(0, 3)),
            confirmed_refs=confirmed,
            home=case.config_case.home,
            deny_terms=pv.deny_terms,
        )
        expected = pv.planted if item_id == target else frozenset()
        assert {finding.kind for finding in rendered.findings} == expected


# --------------------------------------------------------------------------------------------
# statuses()
# --------------------------------------------------------------------------------------------


@LIGHT
@given(st.data())
def test_statuses_pass_check_status_and_keep_the_running_bound(data: st.DataObject) -> None:
    """Every named ID has a record, extra records are ``outside_<n>``, and ``max_running`` holds."""
    ids = data.draw(st.lists(hs.item_ids(), max_size=6, unique=True))
    limit = data.draw(st.none() | st.integers(0, 3))
    status = data.draw(hs.statuses(ids=ids, max_running=limit, max_outside=2, payloads=data.draw(st.booleans())))
    state.check_status(status)
    assert set(ids) <= set(status["items"])
    assert all(item_id in ids or item_id.startswith("outside_") for item_id in status["items"])
    running = sum(record["state"] == state.RUNNING for record in status["items"].values())
    assert limit is None or running <= limit


@pytest.mark.parametrize("target", sorted(state.STATES))
def test_statuses_reach_each_state(target: str) -> None:
    """Each of the five states is drawn, through the transitions that lead to it."""
    reach(hs.statuses(ids=["example-item"]), lambda status: status["items"]["example-item"]["state"] == target)


# --------------------------------------------------------------------------------------------
# observations()
# --------------------------------------------------------------------------------------------


def _final_state(case: hs.ObservationsCase) -> evaluate.Evaluation:
    """Evaluate a case with its own declaration."""
    return evaluate.final_state(
        case.observations,
        mode=case.mode,
        declared_files=case.declared_files,
        verify_commands=case.verify_commands,
    )


@LIGHT
@given(hs.observations())
def test_observations_meet_exactly_their_conditions(case: hs.ObservationsCase) -> None:
    """``final_state`` accepts the observations and finds the planted conditions, no more."""
    assert set(_final_state(case).reasons) == case.conditions
    observed = case.observations
    assert observed.undeclared_files == evaluate.undeclared_files(observed.changed_files, case.declared_files)
    assert observed.conflicts == evaluate.conflicting_files(
        observed.changed_files, case.default_branch_files, case.batch_files
    )


@LIGHT
@given(st.data())
def test_observations_follow_the_declaration_of_a_manifest_item(data: st.DataObject) -> None:
    """With an item's declared files and commands passed in, the conditions still hold exactly."""
    case = data.draw(hs.manifests())
    assert case.manifest is not None
    item = data.draw(st.sampled_from(case.manifest.items))
    observed = data.draw(
        hs.observations(
            mode=item.mode,
            declared_files=item.declared_files,
            verify_commands=[command.cmd for command in item.verify_commands],
        )
    )
    assert set(_final_state(observed).reasons) == observed.conditions


@pytest.mark.parametrize("condition", [condition for condition, _ in evaluate.PRECEDENCE] + [None])
@settings(max_examples=10, deadline=None)
@given(data=st.data())
def test_each_condition_planted_alone_is_the_only_reason(condition: str | None, data: st.DataObject) -> None:
    """``conditions=`` plants one condition alone, or none (``succeeded``), and nothing else holds."""
    wanted = frozenset() if condition is None else frozenset({condition})
    case = data.draw(hs.observations(conditions=wanted))
    assert case.conditions == wanted
    assert set(_final_state(case).reasons) == wanted


@pytest.mark.parametrize(
    ("arguments", "wanted"),
    [
        ({"mode": "query"}, {"no_commits"}),
        ({}, {"no_commits", "empty_output"}),
        ({"mode": "query"}, {"conflicts"}),
        ({"declared_files": ()}, {"conflicts"}),
        ({"verify_commands": [("make", "test")]}, {"rerun_unaccounted", "rerun_failed"}),
        ({}, {"no_such_condition"}),
    ],
)
def test_conditions_that_cannot_be_met_are_refused(arguments: dict[str, Any], wanted: set[str]) -> None:
    """A given set of conditions is not adjusted: one that cannot be met raises at once."""
    with pytest.raises(ValueError):
        hs.observations(conditions=wanted, **arguments)


# --------------------------------------------------------------------------------------------
# report_texts()
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("line", hs.REPORT_FILLER)
def test_report_filler_holds_no_headword(line: str) -> None:
    """The filler lines are safe on their own, so every flag comes from a planted line."""
    assert evaluate.report_flags(line) == ()


@pytest.mark.parametrize("requests", [None, True, False])
@LIGHT
@given(data=st.data())
def test_report_texts_flag_exactly_the_planted_lines(requests: bool | None, data: st.DataObject) -> None:
    """``report_flags`` returns the planted lines and kinds, in its own order."""
    report = data.draw(hs.report_texts(requests=requests))
    found = tuple((flag.line, flag.kind) for flag in evaluate.report_flags(report.text))
    assert found == report.flags
    if requests is True:
        assert report.flags
    if requests is False:
        assert report.flags == ()


# --------------------------------------------------------------------------------------------
# executor_attrs()
# --------------------------------------------------------------------------------------------


def _applied_rows(attrs: executor.ExecutorAttrs) -> set[int]:
    """Read the rows that apply from the attributes themselves."""
    values = (
        attrs.changed_paths,
        attrs.gates,
        attrs.uncommitted_count,
        attrs.knowledge_kinds,
        attrs.read_paths,
        attrs.artifact_paths,
    )
    return {row for row, value in enumerate(values, 1) if value}


@LIGHT
@given(hs.executor_attrs())
def test_executor_attrs_apply_exactly_the_planted_rows(case: hs.ExecutorAttrsCase) -> None:
    """The planted rows are the attributes that are set, and at least one row applies."""
    assert _applied_rows(case.attrs) == case.rows
    assert case.rows


def test_executor_attrs_reach_the_set_without_rows_when_asked() -> None:
    """``allow_no_row`` adds the attributes to which no row applies (``choose`` rejects them)."""
    case = reach(hs.executor_attrs(allow_no_row=True), lambda case: not case.rows)
    assert _applied_rows(case.attrs) == set()


# --------------------------------------------------------------------------------------------
# Arguments
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: hs.configs(min_repos=3, max_repos=2), id="configs bounds"),
        pytest.param(lambda: hs.configs(valid=False, defect_keys=("no-such-key",)), id="configs no defect"),
        pytest.param(lambda: hs.paths(home="relative"), id="paths relative home"),
        pytest.param(lambda: hs.related_paths(min_size=0), id="related_paths bounds"),
        pytest.param(lambda: hs.manifests(cyclic=True, max_items=0), id="manifests no room for a cycle"),
        pytest.param(lambda: hs.manifests(modes=("other",)), id="manifests unknown mode"),
        pytest.param(lambda: hs.prompt_vars(planted={"email"}), id="prompt_vars unknown kind"),
        pytest.param(lambda: hs.prompt_vars(max_vars=0), id="prompt_vars no room to plant"),
        pytest.param(lambda: hs.statuses(ids=["a", "a"]), id="statuses repeated ID"),
        pytest.param(lambda: hs.observations(mode="other"), id="observations unknown mode"),
        pytest.param(lambda: hs.report_texts(requests=True, max_lines=0), id="report_texts no room"),
    ],
)
def test_bad_arguments_are_refused(build: Callable[[], object]) -> None:
    """A strategy refuses arguments that it could not honor, before anything is drawn."""
    with pytest.raises(ValueError):
        build()

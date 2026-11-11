"""Property 22 of the phase 4 spec: the choice of the Handoff items to start.

Task 1.12 (Requirements 28.11 and 28.12). Property 22 reads:

    For any set of items with acyclic dependencies, any state of each item, any set of
    confirmed refs and any limit ``k`` of 1 or more, every item that ``dag.select`` selects is
    ``queued``, every item it depends on is ``succeeded``, and every ref it requires is in the
    confirmed set; the selected items and the items already ``running`` are at most ``k``
    together; and a repository has at most one item running and selected together. When an
    item can be selected and the limit and the one-item-per-repository rule leave room, at
    least one item is selected. The manifest check rejects every cycle of dependencies.

The test functions:

- :func:`test_property_22_select_keeps_dependencies_refs_limit_and_repositories` checks the
  selection part against an oracle written here from the property's own terms, without
  ``dag.ready`` or the reasons that ``dag.select`` returns.
- :func:`test_property_22_manifest_check_rejects_every_cycle` checks the last sentence.
- :func:`test_property_22_inputs_reach_every_shape` runs the same check on 100 inputs drawn with
  a fixed seed and counts the shapes that make the property bite (an item selected, a ready
  item held back by the limit, by its repository, an item waiting for an unconfirmed ref, and
  so on). It fails when a shape stops appearing, so the property test cannot pass vacuously.

Readings of the property for statuses that it does not describe:

- More ``running`` records than ``k`` (the limit was lowered while items ran): the selection is
  empty, so ``running + selected <= max(k, running)``.
- Two ``running`` items of one repository: nothing more of that repository is selected.
- Every ``running`` record counts against ``k``, also when its item is not named or not in the
  manifest. A ``running`` record that the manifest does not have runs in a repository that
  cannot be known, so the one-item-per-repository rule holds for every repository it could be
  in only when nothing is selected. "Room" in the second sentence therefore also means that
  no such record exists (the reading of the task 1.6 record).

The inputs come from ``scripts/tests/strategies/handoff.py`` (``manifests``, ``statuses``,
``confirmed_refs``); every value is synthetic.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

import pytest
from handoff import dag, manifest, state
from handoff.config import MODES
from handoff.manifest import Item, Manifest, RequiredRef
from hypothesis import Phase, event, given, seed, settings
from hypothesis import strategies as st
from strategies import handoff as handoff_strategies

#: The seed of :func:`test_property_22_inputs_reach_every_shape`.
SEED: Final = 20261112

#: The shapes that :func:`check_property_22` reports, with the fewest of them that the 100
#: inputs of :func:`test_property_22_inputs_reach_every_shape` must hold.
SELECTED: Final = "at least one item selected"
SELECTED_SEVERAL: Final = "two or more items selected"
FILLS_LIMIT: Final = "the selection fills the limit"
LIMIT_STOPS: Final = "a ready item with a free repository waits for the limit"
RUNNING_REPO_STOPS: Final = "a ready item waits for a running item of its repository"
SELECTED_REPO_STOPS: Final = "a ready item waits for an item of its repository selected first"
REF_WAITS: Final = "a queued item with every dependency succeeded waits for an unconfirmed ref"
DEPENDENCY_WAITS: Final = "a queued item waits for a dependency that has not succeeded"
SOME_DEPENDENCIES_WAIT: Final = "a queued item with room waits for a dependency while another has succeeded"
SOME_REFS_WAIT: Final = "a queued item with room waits for a ref while another is confirmed"
RUNNING_NOT_NAMED: Final = "an item of the manifest that is not named is running"
RUNNING_OUTSIDE: Final = "a running record is not in the manifest"
OVER_LIMIT: Final = "more running records than the limit"
ROOM: Final = "a ready item has room to start"

MIN_COUNTS: Final[Mapping[str, int]] = {
    SELECTED: 10,
    SELECTED_SEVERAL: 1,
    FILLS_LIMIT: 3,
    LIMIT_STOPS: 3,
    RUNNING_REPO_STOPS: 3,
    SELECTED_REPO_STOPS: 1,
    REF_WAITS: 1,
    DEPENDENCY_WAITS: 10,
    SOME_DEPENDENCIES_WAIT: 1,
    SOME_REFS_WAIT: 1,
    RUNNING_NOT_NAMED: 3,
    RUNNING_OUTSIDE: 3,
    OVER_LIMIT: 3,
    ROOM: 10,
}


@dataclass(frozen=True)
class SelectionCase:
    """One input of ``dag.select``.

    Attributes:
        manifest: A checked manifest with acyclic dependencies.
        status: A status with a record of every item of the manifest, and possibly records
            (``outside_<n>``) that the manifest does not have.
        confirmed_refs: The refs that the IN-2 check confirmed.
        max_concurrency: The limit ``k``.
        sync_point: The Sync_Point that names the items, or ``None``.
        item_ids: The IDs that name the items, in a drawn order, or ``None``. Exactly one of
            ``sync_point`` and ``item_ids`` is set.
    """

    manifest: Manifest
    status: state.StatusDoc
    confirmed_refs: frozenset[RequiredRef]
    max_concurrency: int
    sync_point: str | None
    item_ids: tuple[str, ...] | None


#: The transitions from ``queued`` that reach each state, for :func:`frontier_statuses`.
_PATHS: Final[Mapping[str, tuple[str, ...]]] = {
    state.QUEUED: (),
    state.RUNNING: (state.RUNNING,),
    state.SUCCEEDED: (state.RUNNING, state.SUCCEEDED),
    state.FAILED: (state.RUNNING, state.FAILED),
    state.NEEDS_HUMAN: (state.NEEDS_HUMAN,),
}

#: The states of an item of the frontier in :func:`frontier_statuses`, each as often as it
#: appears here: ready (``queued``) three times in four.
_FRONTIER_STATES: Final[tuple[str, ...]] = (state.QUEUED, state.QUEUED, state.QUEUED, state.RUNNING)

#: The orders in which :func:`frontier_statuses` offers the items to the frontier.
FOCUSES: Final[tuple[str, ...]] = ("spread", "together", "refs", "any")


def ancestors(checked: Manifest) -> dict[str, frozenset[str]]:
    """Return, for each item, every item it depends on directly or through others."""
    by_id = checked.by_id
    found: dict[str, frozenset[str]] = {}

    def above(item_id: str) -> frozenset[str]:
        if item_id not in found:
            direct = by_id[item_id].depends_on
            found[item_id] = frozenset(direct).union(*(above(dependency) for dependency in direct))
        return found[item_id]

    for item in checked.items:
        above(item.id)
    return found


def offer_order(items: list[Item], focus: str) -> list[Item]:
    """Order items (already shuffled) for the frontier, as :data:`FOCUSES` names.

    - ``spread``: one item of each repository, then a second of each, and so on, so that the
      first items offered are in different repositories.
    - ``together``: the items of the repository with the most items first.
    - ``refs``: the items that require a ref first.
    - ``any``: as shuffled.
    """
    if focus == "spread":
        seen: Counter[str] = Counter()
        rank: dict[str, int] = {}
        for item in items:
            rank[item.id] = seen[item.repo]
            seen[item.repo] += 1
        return sorted(items, key=lambda item: rank[item.id])
    if focus == "together":
        sizes = Counter(item.repo for item in items)
        return sorted(items, key=lambda item: -sizes[item.repo])
    if focus == "refs":
        return sorted(items, key=lambda item: not item.requires_refs)
    return items


@st.composite
def frontier_statuses(
    draw: st.DrawFn, *, checked: Manifest, max_running: int | None, max_outside: int
) -> state.StatusDoc:
    """Draw a status with a frontier: items that can start, with everything they depend on succeeded.

    ``statuses()`` draws the five states evenly and independently, so an item is ``queued``
    while every item it depends on is ``succeeded`` in few draws, and the inputs where the
    limit, the one-item-per-repository rule or an unconfirmed ref holds a ready item back are
    rare, and rarer still in a run of hypothesis, which spends many examples on variations of
    a few manifests. Here the items are offered to the frontier in an order of :data:`FOCUSES`
    (``spread`` puts ready items in several repositories, ``together`` in one, ``refs`` puts
    items that require a ref on the frontier), and each item that neither depends on nor is
    depended on by a frontier item so far joins it with odds 3 in 4. Every item that a
    frontier item depends on is ``succeeded``; a frontier item is ``queued`` or ``running``
    (:data:`_FRONTIER_STATES`); every other item gets any of the five states.

    The status is built with ``state.add_item`` and ``state.transition``, keeps the
    ``max_running`` bound of ``statuses()``, and adds up to ``max_outside`` records
    ``outside_<n>`` in any state.
    """
    above = ancestors(checked)
    focus = draw(st.sampled_from(FOCUSES))
    frontier: list[str] = []
    for item in offer_order(draw(st.permutations(checked.items)), focus):
        related = any(item.id in above[other] or other in above[item.id] for other in frontier)
        if not related and draw(st.integers(0, 3)) > 0:
            frontier.append(item.id)
    below = frozenset().union(*(above[item_id] for item_id in frontier))

    status = state.empty_status()
    running = 0

    def enter(name: str, choices: tuple[str, ...]) -> None:
        nonlocal status, running
        if max_running is not None and running >= max_running:
            choices = tuple(choice for choice in choices if choice != state.RUNNING)
        target = draw(st.sampled_from(choices))
        running += target == state.RUNNING
        status = state.add_item(status, name)
        for step in _PATHS[target]:
            status = state.transition(status, name, step, at="2026-11-12T00:00:00Z", reason="synthetic")

    on_frontier = (state.QUEUED,) if focus == "together" else _FRONTIER_STATES
    for item in checked.items:
        enter(
            item.id,
            (state.SUCCEEDED,) if item.id in below else on_frontier if item.id in frontier else tuple(_PATHS),
        )
    for number in range(draw(st.integers(0, max_outside))):
        enter(f"outside_{number}", tuple(_PATHS))
    return status


@st.composite
def _selection_case(draw: st.DrawFn, case: handoff_strategies.ManifestCase) -> SelectionCase:
    """Draw one :class:`SelectionCase` for the manifest of ``case`` (see :func:`selection_cases`)."""
    checked = case.manifest
    if checked is None:
        raise AssertionError("manifests() drew a cyclic manifest without cyclic=True")
    bound_kind = draw(st.sampled_from(("below", "at", "none")))
    limit = draw(st.integers(1, 4))
    bound = {"below": limit - 1, "at": limit, "none": None}[bound_kind]
    outside = draw(st.integers(0, 2))
    if draw(st.integers(0, 2)) == 0:
        status = draw(handoff_strategies.statuses(ids=case.ids, max_running=bound, max_outside=outside))
    else:
        status = draw(frontier_statuses(checked=checked, max_running=bound, max_outside=outside))
    if bound_kind == "none" and draw(st.booleans()):
        # Lower the limit below the running records, as when max_concurrency is lowered between runs.
        running = sum(record["state"] == state.RUNNING for record in status["items"].values())
        limit = draw(st.integers(1, max(1, running - 1)))
    confirmed = draw(handoff_strategies.confirmed_refs(checked))
    naming = draw(st.sampled_from(("all", "sync_point", "all", "some")))
    if naming == "sync_point":
        sync_point = draw(st.sampled_from(sorted({item.sync_point for item in checked.items})))
        return SelectionCase(checked, status, confirmed, limit, sync_point, None)
    order = draw(st.permutations(case.ids))
    size = len(order) if naming == "all" else draw(st.integers(1, len(order)))
    return SelectionCase(checked, status, confirmed, limit, None, tuple(order[:size]))


@st.composite
def selection_cases(draw: st.DrawFn) -> tuple[SelectionCase, ...]:
    """Draw one manifest and one to six inputs of ``dag.select`` for it.

    Drawing a manifest costs more than the rest, so each manifest serves several inputs. The
    configuration has at least one to three repositories (more repositories give more items
    that can run together). The manifest has one to six items, of both modes or of the change
    mode only: only a change item can require a ref, and ``dag`` does not read the mode.

    For each input: the limit is 1 to 4 (at most 4 repositories exist, so a larger limit could
    only bind through ``running`` records). The bound on the ``running`` records of the status
    is ``k - 1`` (room under the limit), ``k`` (the bound of the property's own statement) or
    none (more than ``k`` can be running), and up to two records outside the manifest are
    added. The status comes from ``statuses()`` (states drawn independently) or
    :func:`frontier_statuses` (a drawn set of items that can start). The confirmed refs come
    from ``confirmed_refs()``, each ref of the manifest with odds 1 in 2. The items are named
    by one Sync_Point that an item has (one input in four) or by IDs in a drawn order: all of
    them, or a drawn number of them.
    """
    config = draw(handoff_strategies.configs(min_repos=draw(st.integers(1, 3))))
    modes = draw(st.sampled_from((MODES, ("change",))))
    fewest = draw(st.sampled_from((2, 1)))
    case = draw(handoff_strategies.manifests(config=config, modes=modes, min_items=fewest, max_files=1))
    return tuple(draw(st.lists(_selection_case(case), min_size=1, max_size=6)))


def named_items(case: SelectionCase) -> tuple[Item, ...]:
    """Return the items that a case names, in the order of the manifest."""
    if case.sync_point is not None:
        return tuple(item for item in case.manifest.items if item.sync_point == case.sync_point)
    if case.item_ids is None:
        raise AssertionError("a SelectionCase names its items")
    wanted = set(case.item_ids)
    return tuple(item for item in case.manifest.items if item.id in wanted)


def is_ready(item: Item, states: Mapping[str, str], confirmed: frozenset[RequiredRef]) -> bool:
    """Tell whether an item can be selected by its own conditions, in the terms of Property 22."""
    return (
        states[item.id] == state.QUEUED
        and all(states[dependency] == state.SUCCEEDED for dependency in item.depends_on)
        and all(ref in confirmed for ref in item.requires_refs)
    )


def check_property_22(case: SelectionCase) -> frozenset[str]:
    """Assert the selection part of Property 22 for one input.

    Args:
        case: The input.

    Returns:
        The shapes of the input and of the result (the constants of this module), for the
        events and the counts.
    """
    result = dag.select(
        case.manifest,
        case.status,
        confirmed_refs=case.confirmed_refs,
        max_concurrency=case.max_concurrency,
        sync_point=case.sync_point,
        item_ids=case.item_ids,
    )
    by_id = case.manifest.by_id
    states = {item_id: record["state"] for item_id, record in case.status["items"].items()}
    named = named_items(case)
    named_ids = {item.id for item in named}
    limit = case.max_concurrency
    selected = result.selected

    assert len(set(selected)) == len(selected), f"an item is selected twice: {selected}"
    assert set(selected) <= named_ids, f"{sorted(set(selected) - named_ids)} selected without being named"
    for item_id in selected:
        item = by_id[item_id]
        assert states[item_id] == state.QUEUED, f"{item_id} is selected in state {states[item_id]}"
        pending = [dependency for dependency in item.depends_on if states[dependency] != state.SUCCEEDED]
        assert not pending, f"{item_id} is selected before {pending} succeeded"
        unconfirmed = [ref for ref in item.requires_refs if ref not in case.confirmed_refs]
        assert not unconfirmed, f"{item_id} is selected before {unconfirmed} is confirmed"

    running = [item_id for item_id, item_state in states.items() if item_state == state.RUNNING]
    assert len(running) + len(selected) <= max(
        limit, len(running)
    ), f"{len(running)} running and {len(selected)} selected exceed max_concurrency {limit}"
    running_by_repo = Counter(by_id[item_id].repo for item_id in running if item_id in by_id)
    selected_by_repo = Counter(by_id[item_id].repo for item_id in selected)
    for repo, count in selected_by_repo.items():
        # At most one per repository; a repository that already runs more takes none.
        assert running_by_repo[repo] + count <= max(
            1, running_by_repo[repo]
        ), f"{repo}: {running_by_repo[repo]} running and {count} selected"
    outside = [item_id for item_id in running if item_id not in by_id]
    assert not (outside and selected), f"{selected} selected while {outside} runs in an unknown repository"

    ready = [item for item in named if is_ready(item, states, case.confirmed_refs)]
    room = not outside and len(running) < limit and any(item.repo not in running_by_repo for item in ready)
    if room:
        assert selected, "nothing is selected although a ready item has room to start"

    return frozenset(_shapes(case, named, ready, running, selected, room))


def _shapes(
    case: SelectionCase,
    named: tuple[Item, ...],
    ready: list[Item],
    running: list[str],
    selected: tuple[str, ...],
    room: bool,
) -> set[str]:
    """Classify one input and its result (see :data:`MIN_COUNTS`)."""
    by_id = case.manifest.by_id
    states = {item_id: record["state"] for item_id, record in case.status["items"].items()}
    limit = case.max_concurrency
    running_repos = {by_id[item_id].repo for item_id in running if item_id in by_id}
    selected_repos = {by_id[item_id].repo for item_id in selected}
    left = [item for item in ready if item.id not in selected]
    outside = any(item_id not in by_id for item_id in running)
    used = len(running) + len(selected)

    shapes: set[str] = set()
    if selected:
        shapes.add(SELECTED)
        if used == limit:
            shapes.add(FILLS_LIMIT)
    if len(selected) >= 2:
        shapes.add(SELECTED_SEVERAL)
    if not outside:
        if used >= limit and any(item.repo not in running_repos | selected_repos for item in left):
            shapes.add(LIMIT_STOPS)
        if used < limit and any(item.repo in running_repos for item in left):
            shapes.add(RUNNING_REPO_STOPS)
        if used < limit and any(item.repo in selected_repos - running_repos for item in left):
            shapes.add(SELECTED_REPO_STOPS)
    for item in named:
        if states[item.id] != state.QUEUED:
            continue
        succeeded = [states[dependency] == state.SUCCEEDED for dependency in item.depends_on]
        confirmed = [ref in case.confirmed_refs for ref in item.requires_refs]
        if not all(succeeded):
            shapes.add(DEPENDENCY_WAITS)
        elif not all(confirmed):
            shapes.add(REF_WAITS)
        # The room of check_property_22 for this item: no running record outside the manifest,
        # fewer running records than the limit, and nothing running in its repository.
        free = not outside and len(running) < limit and item.repo not in running_repos
        if free and all(confirmed) and any(succeeded) and not all(succeeded):
            shapes.add(SOME_DEPENDENCIES_WAIT)
        if free and all(succeeded) and any(confirmed) and not all(confirmed):
            shapes.add(SOME_REFS_WAIT)
    named_ids = {item.id for item in named}
    if any(item_id in by_id and item_id not in named_ids for item_id in running):
        shapes.add(RUNNING_NOT_NAMED)
    if outside:
        shapes.add(RUNNING_OUTSIDE)
    if len(running) > limit:
        shapes.add(OVER_LIMIT)
    if room:
        shapes.add(ROOM)
    return shapes


def check_all(cases: tuple[SelectionCase, ...]) -> frozenset[str]:
    """Assert Property 22 for every input of one example, and name the shapes as events.

    The events show in ``--hypothesis-show-statistics``.

    Returns:
        The union of the shapes of the inputs.
    """
    shapes: set[str] = set()
    for case in cases:
        shapes |= check_property_22(case)
    for shape in sorted(shapes):
        event(shape)
    return frozenset(shapes)


# Feature: cyber-resilience-phase4-supply-chain, Property 22: 起動の選択は依存、参照の確定、同時実行数、リポジトリごとの排他を守る
@settings(max_examples=100, deadline=None)
@given(selection_cases())
def test_property_22_select_keeps_dependencies_refs_limit_and_repositories(cases: tuple[SelectionCase, ...]) -> None:
    """``dag.select`` selects only ready items, within the limit and one per repository, and one when there is room.

    **Validates: Requirements 28.11, 28.12**
    """
    check_all(cases)


# Feature: cyber-resilience-phase4-supply-chain, Property 22: 起動の選択は依存、参照の確定、同時実行数、リポジトリごとの排他を守る
@settings(max_examples=100, deadline=None)
@given(handoff_strategies.manifests(cyclic=True))
def test_property_22_manifest_check_rejects_every_cycle(case: handoff_strategies.ManifestCase) -> None:
    """``parse_manifest`` rejects a manifest with a cycle of dependencies, and names the cycle as the reason.

    **Validates: Requirements 28.11, 28.12**
    """
    with pytest.raises(manifest.ManifestError) as caught:
        manifest.parse_manifest(case.raw, config=case.config)
    assert "cycle" in {issue.kind for issue in caught.value.issues}
    event(f"a planted cycle of {len(case.cycle)} item(s)")


# Feature: cyber-resilience-phase4-supply-chain, Property 22: 起動の選択は依存、参照の確定、同時実行数、リポジトリごとの排他を守る
def test_property_22_inputs_reach_every_shape() -> None:
    """The examples of the property test hold every shape that makes the property bite.

    The check of Property 22 runs on 100 examples drawn with a fixed seed, as many as the
    property test draws, and each shape must appear in at least as many examples as
    :data:`MIN_COUNTS` says.

    **Validates: Requirements 28.11, 28.12**
    """
    counts: Counter[str] = Counter()

    @seed(SEED)
    @settings(max_examples=100, deadline=None, database=None, phases=[Phase.generate, Phase.target])
    @given(selection_cases())
    def run(cases: tuple[SelectionCase, ...]) -> None:
        counts.update(check_all(cases))

    run()
    short = {shape: counts[shape] for shape, least in MIN_COUNTS.items() if counts[shape] < least}
    assert not short, f"shapes below their minimum count in 100 examples: {short}; all counts: {dict(counts)}"

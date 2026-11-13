"""Property 23: ``handoff.state`` moves an item only along an allowed edge, and ``status.json``
reads back as the status it was written from.

Task 1.13 of the phase 4 spec, Requirements 28.13 and 28.19. The module under test is
``scripts/handoff/state.py``; its docstring defines a status and the transition table. The
property is split into two tests:

- :func:`test_transitions_take_only_the_allowed_edges`: a status from
  ``strategies.handoff.statuses()`` and a sequence of requests, applied in turn with
  ``state.transition``. A request on an edge of :data:`EDGES` gives a status that differs from
  the one passed in by the item's state and one more history entry. Any other request raises
  ``TransitionError``, and so does a request for a name of :data:`NOT_STATES`, made before each
  drawn request. None of them changes the status passed in. The status at the end of the walk
  reads back as itself.
- :func:`test_a_rendered_status_reads_back_as_the_same_status`: ``parse_status`` of
  ``render_status(s)`` is ``s``, value for value and type for type, for statuses of
  ``statuses(payloads=True)``, and the text depends on the value only.

The oracle is the design's table, written out below as :data:`EDGES`, and not
``state.ALLOWED_TRANSITIONS``: a test that read the module's own table would accept an edge
added to it. The tests label their examples with ``hypothesis.event``, and
``--hypothesis-show-statistics`` prints the share of each label. The labels of the transition
test show that applied requests, refused requests and requests out of ``succeeded`` all occur,
and from which states the names of :data:`NOT_STATES` are asked for.

The strategies are built once, at import: drawing from a strategy costs less than building it,
and drawing takes much of the time of these tests. Every value is synthetic.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final

import pytest
from handoff import state
from hypothesis import event, given, settings
from hypothesis import strategies as st
from strategies import handoff as handoff_strategies

#: The five states of Requirement 28.13, as the design writes them.
STATE_NAMES: Final[frozenset[str]] = frozenset({"queued", "running", "succeeded", "failed", "needs-human"})

#: The transition table of the design (Data Models), edge for edge. No edge leaves
#: ``succeeded``, and no state goes to itself.
EDGES: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("queued", "running"),
        ("queued", "needs-human"),
        ("running", "succeeded"),
        ("running", "failed"),
        ("running", "needs-human"),
        ("failed", "queued"),
        ("needs-human", "queued"),
    }
)

#: The states that a request asks for: the design's five and any other that the module calls a
#: state, so that an edge to a state the design does not have is requested too.
TARGETS: Final[tuple[str, ...]] = tuple(sorted(STATE_NAMES | state.STATES))

#: Names that are not states: a state's name in another case, with ``_`` for ``-``, and after a
#: space. ``lower``, ``replace("_", "-")`` and ``strip`` turn them into ``running``,
#: ``needs-human`` and ``queued``, so a ``transition`` that normalized ``to_state`` would apply
#: one of them out of ``queued``, ``running``, ``failed`` or ``needs-human``. The transition test
#: asks for each of them before each drawn request, for the same item, and not as drawn requests:
#: drawing them would make each pair of states rarer, and an extra edge between two states is
#: found only by asking for that pair.
NOT_STATES: Final[tuple[str, ...]] = ("Running", "needs_human", " queued")

#: The form of ``history[].at`` in the design: UTC, whole seconds, ``Z``.
TIMESTAMP_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"

#: Item IDs of the statuses drawn here, of the manifest's form.
ITEM_IDS: Final[tuple[str, ...]] = ("example-a", "example-b", "example-c")

#: Reasons that the harness writes. :data:`REASONS` mixes them with free text.
HARNESS_REASONS: Final[tuple[str, ...]] = (
    "dispatched",
    "all_checks_passed",
    "timed_out",
    "harness_interrupted",
    "requeued by the maintainer",
)

#: The first and the last second of :data:`TIMESTAMPS`.
FIRST_MOMENT: Final = datetime(2000, 1, 1)
LAST_MOMENT: Final = datetime(2099, 12, 31, 23, 59, 59)

#: Timestamps of the form of ``history[].at``, between 2000 and 2099, drawn as a whole number of
#: seconds after :data:`FIRST_MOMENT`. Each request draws its own, so the timestamps of a walk
#: can go back in time; the module does not check their order.
TIMESTAMPS: Final = st.integers(0, int((LAST_MOMENT - FIRST_MOMENT).total_seconds())).map(
    lambda seconds: (FIRST_MOMENT + timedelta(seconds=seconds)).strftime(TIMESTAMP_FORMAT)
)

#: White space that a free-text reason starts and ends with. ``state`` tells a blank reason with
#: ``str.strip``, so the ends of a reason are where a copy of it could lose characters.
PADDING: Final = st.sampled_from(("", " ", "  ", "\t", "\n", "\u3000"))

#: History reasons: one that the harness writes, or free text around one character that is of no
#: category holding white space (``Cc``, ``Zs``, ``Zl``, ``Zp``) and not a surrogate (``Cs``), so
#: that no reason is blank. The free text can hold line breaks, quotes, backslashes and
#: characters outside the BMP.
REASONS: Final = st.sampled_from(HARNESS_REASONS) | st.tuples(
    PADDING,
    st.text(max_size=4),
    st.characters(exclude_categories=("Cs", "Cc", "Zs", "Zl", "Zp")),
    st.text(max_size=4),
    PADDING,
).map("".join)

#: The statuses that a walk starts from: one to three items and up to one record outside them,
#: each in a drawn state with a history that reaches it.
INITIAL_STATUSES: Final = st.one_of(
    *(handoff_strategies.statuses(ids=ITEM_IDS[:count], max_outside=1) for count in range(1, len(ITEM_IDS) + 1))
)

#: Values for some of the fields that other modules own. :func:`walks` writes them into every
#: record, so that a transition that changed one of them would be seen.
OWNED_FIELDS: Final = st.fixed_dictionaries(
    {
        "pid": st.none() | st.integers(1, 2**31 - 1),
        "report": st.none() | st.text(min_size=1, max_size=6),
        "observations": st.none() | st.dictionaries(st.text(max_size=4), st.integers(-9, 9), max_size=2),
        "report_flags": st.lists(st.integers(-9, 9), max_size=2),
    }
)

#: The selftest result of a status: none yet, or an object.
SELFTESTS: Final = st.none() | st.fixed_dictionaries({"result": st.sampled_from(("guards_active", "unconfirmed"))})

#: The requests of a walk before their items are chosen: an index into the status's items (taken
#: modulo their number), the requested state, ``at`` and ``reason``.
REQUEST_LISTS: Final = st.lists(
    st.tuples(st.integers(0, len(ITEM_IDS)), st.sampled_from(TARGETS), TIMESTAMPS, REASONS), min_size=1, max_size=12
)

#: The statuses of the round-trip test: ``statuses(payloads=True)``, so the fields that other
#: modules own hold JSON values of every type and the history reasons are free text. One item:
#: an item with payloads costs more to draw than the rest of the status, and the transition test
#: reads back statuses of up to four items at the end of each walk.
DOCUMENTS: Final = handoff_strategies.statuses(ids=ITEM_IDS[:1], payloads=True)


@dataclass(frozen=True)
class Request:
    """One call of ``state.transition``.

    Attributes:
        item_id: An item of the status.
        to_state: The requested state, one of :data:`TARGETS`.
        at: A timestamp of the form of ``history[].at``.
        reason: A history reason that is not blank.
    """

    item_id: str
    to_state: str
    at: str
    reason: str


@st.composite
def walks(draw: st.DrawFn) -> tuple[state.StatusDoc, tuple[Request, ...]]:
    """Draw a status and the requests to apply to it, in order.

    The status comes from :data:`INITIAL_STATUSES`, with :data:`SELFTESTS` and
    :data:`OWNED_FIELDS` written in. Each of the 1 to 12 requests names an item of the status
    and one of :data:`TARGETS`. Every ``at`` and ``reason`` is valid, so the pair of the item's
    state and the requested state alone decides whether a request is applied.

    Returns:
        The status and the requests.
    """
    status = draw(INITIAL_STATUSES)
    status["selftest"] = draw(SELFTESTS)
    for record in status["items"].values():
        record.update(draw(OWNED_FIELDS))
    names = sorted(status["items"])
    requests = tuple(
        Request(names[index % len(names)], target, at, reason) for index, target, at, reason in draw(REQUEST_LISTS)
    )
    return status, requests


def difference(actual: Any, expected: Any, path: str = "$") -> str | None:
    """Return where two JSON values first differ, or ``None`` when they are the same.

    The same means the same built-in type at every position and equal values, with floats
    compared by ``repr``. ``==`` alone takes ``True`` for ``1``, ``1`` for ``1.0`` and ``0.0``
    for ``-0.0``.

    Args:
        actual: The value found.
        expected: The value wanted.
        path: Where the two values are, for the message.

    Returns:
        A description of the first difference, or ``None``.
    """
    kind = type(expected)
    if type(actual) is not kind:
        return f"{path}: {type(actual).__name__} instead of {kind.__name__}"
    if kind is dict:
        if actual.keys() != expected.keys():
            return f"{path}: the keys {sorted(actual.keys() ^ expected.keys())!r} are on one side only"
        for key, value in expected.items():
            found = difference(actual[key], value, f"{path}[{key!r}]")
            if found is not None:
                return found
        return None
    if kind is list:
        if len(actual) != len(expected):
            return f"{path}: {len(actual)} elements instead of {len(expected)}"
        for index, (element, wanted) in enumerate(zip(actual, expected, strict=True)):
            found = difference(element, wanted, f"{path}[{index}]")
            if found is not None:
                return found
        return None
    same = repr(actual) == repr(expected) if kind is float else actual == expected
    return None if same else f"{path}: {actual!r} instead of {expected!r}"


def reversed_keys(value: Any) -> Any:
    """Copy a JSON value with the keys of every object in reverse order. Lists keep their order.

    Args:
        value: A JSON value.

    Returns:
        A copy equal to ``value`` that shares no list or object with it.
    """
    if type(value) is dict:
        return {key: reversed_keys(value[key]) for key in reversed(value)}
    if type(value) is list:
        return [reversed_keys(element) for element in value]
    return value


def scalars(value: Any) -> Iterator[Any]:
    """Yield every key of a JSON value and every value in it that is not a list or an object.

    Args:
        value: A JSON value.

    Yields:
        The keys and the scalar values, depth first.
    """
    if type(value) is dict:
        for key, element in value.items():
            yield key
            yield from scalars(element)
    elif type(value) is list:
        for element in value:
            yield from scalars(element)
    else:
        yield value


# Feature: cyber-resilience-phase4-supply-chain, Property 23: 状態の遷移は許された辺だけを通り、記録はラウンドトリップする
@settings(max_examples=100, deadline=None)
@given(walks())
def test_transitions_take_only_the_allowed_edges(walk: tuple[state.StatusDoc, tuple[Request, ...]]) -> None:
    """A request is applied exactly when its pair is an edge, and adds exactly one history entry.

    For each request in turn: on an edge of :data:`EDGES`, ``state.transition`` returns a status
    equal to the one passed in, except that the item is in the requested state and its history
    ends with one more entry holding the state left, the state entered, ``at`` and ``reason``.
    On any other pair, every request out of ``succeeded`` among them, it raises
    ``TransitionError``. So does a request for each name of :data:`NOT_STATES`, made for the same
    item before each drawn request. In all cases the status passed in keeps its value and its
    rendered text. The next request starts from the status returned, or after a refusal from the
    same one. The status at the end of the walk reads back as itself (the round trip of the other
    test, on statuses of up to four items).

    **Validates: Requirements 28.13, 28.19**
    """
    current, requests = walk
    for request in requests:
        kept = copy.deepcopy(current)
        source = current["items"][request.item_id]["state"]
        for name in NOT_STATES:
            try:
                state.transition(current, request.item_id, name, at=request.at, reason=request.reason)
            except state.TransitionError:
                continue
            pytest.fail(f"{source} -> {name!r} was applied, but {name!r} is not a state")
        found = difference(current, kept)
        assert found is None, f"a request for a name that is not a state changed the status passed in: {found}"
        event(f"names that are not states, asked for out of {source}")
        kept_text = state.render_status(current)
        label = f"{source} -> {request.to_state}"
        if (source, request.to_state) in EDGES:
            event("a request applied")
            event(f"applied: {label}")
            expected = copy.deepcopy(kept)
            record = expected["items"][request.item_id]
            record["state"] = request.to_state
            record["history"].append(
                {"from": source, "to": request.to_state, "at": request.at, "reason": request.reason}
            )
            result = state.transition(current, request.item_id, request.to_state, at=request.at, reason=request.reason)
            found = difference(result, expected)
            assert found is None, f"{label}: {found}"
        else:
            event("a request refused")
            event(f"refused: {label}")
            if source == "succeeded":
                event("a request out of succeeded")
            with pytest.raises(state.TransitionError):
                state.transition(current, request.item_id, request.to_state, at=request.at, reason=request.reason)
            result = current
        found = difference(current, kept)
        assert found is None, f"{label} changed the status passed in: {found}"
        assert state.render_status(current) == kept_text, f"{label} changed the text of the status passed in"
        current = result
    found = difference(state.parse_status(state.render_status(current)), current)
    assert found is None, f"the status at the end of the walk reads back as another: {found}"


# Feature: cyber-resilience-phase4-supply-chain, Property 23: 状態の遷移は許された辺だけを通り、記録はラウンドトリップする
@settings(max_examples=100, deadline=None)
@given(DOCUMENTS)
def test_a_rendered_status_reads_back_as_the_same_status(status: state.StatusDoc) -> None:
    """``parse_status(render_status(s)) == s``, with the same type at every position.

    The text depends on the value only: rendering the status read back, or a copy of ``s`` with
    the keys of every object in reverse order, gives the same text. The text ends in one LF and
    holds no CR, and ``render_status`` does not change ``s``.

    **Validates: Requirements 28.13, 28.19**
    """
    kept = copy.deepcopy(status)
    text = state.render_status(status)
    back = state.parse_status(text)
    found = difference(back, status)
    assert found is None, f"read back: {found}"
    found = difference(status, kept)
    assert found is None, f"render_status changed the status: {found}"
    assert state.render_status(back) == text, "the status read back renders to another text"
    assert state.render_status(reversed_keys(status)) == text, "the order of the keys changes the text"
    assert text.endswith("}\n") and "\r" not in text, "the text does not end in one LF, or holds a CR"

    leaves = list(scalars(status))
    if any(record["history"] for record in status["items"].values()):
        event("a history entry")
    if any(type(leaf) is float for leaf in leaves):
        event("a float")
    if any(type(leaf) is float and leaf.is_integer() for leaf in leaves):
        event("a float with an integer value")
    if any(type(leaf) is str and not leaf.isascii() for leaf in leaves):
        event("a string outside ASCII")

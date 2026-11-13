"""Property 29: a change that reaches another repository's files is carried out by that repository's Kiro.

Task 1.19 of the phase 4 spec (design, Correctness Properties, Property 29, and the table
"実行者の判定" of design section 20), which validates Requirements 28.3 and 28.4. For any
attributes of a Handoff item, one for each row of the table (the paths it changes, the target
repository's rules and gates it follows, the uncommitted changes in the target repository's main
working tree, the knowledge that only the target repository has, the committed paths it only
reads, the artifacts it leaves in this repository only):

1. When any of rows 1 to 4 applies, ``executor.choose`` returns the target repository's Kiro, and
   every row that applies as a reason, rows 5 and 6 included.
2. When none of rows 1 to 4 applies and row 5 or 6 does, and only then, it returns this session,
   again with every row that applies as a reason.
3. An item to which none of rows 1 to 6 applies is rejected by the manifest check.
4. No result has an empty list of reasons.

Oracles. ``executor_attrs()`` of ``strategies.handoff`` reports the rows it planted. The test
decides the executor from those rows alone (one of rows 1 to 4 or none of them), and reads what
each reason must list from the attributes: the changed paths (row 1), the gates (row 2), the
uncommitted count as one decimal string and nothing else (row 3), the kinds of knowledge (row 4),
the read paths (row 5) and the artifact paths (row 6). For an item of ``manifests()``, the rows
and their contents come from the item as written, mapped the way task 1.4 maps them: row 1 from
``declared_files``, row 2 from ``gates`` and from each verification command joined with
``shlex.join``, rows 4, 5 and 6 from ``knowledge_kinds``, ``read_paths`` and ``artifact_paths``.
The manifest check passes 0 as the uncommitted count, so row 3 does not apply there. A list is
compared in the form ``ExecutorAttrs`` keeps it: sorted, each entry once.

The first function checks statements 1, 2 and 4, and the part of statement 3 that is ``choose``
itself: with ``allow_no_row``, the generator also draws the attributes to which no row applies,
and ``choose`` must raise ``ExecutorError``. Those attributes are one value (every collection
empty, a count of 0). Hypothesis begins its generate phase with the all-zero draw, which picks
the first set of rows of the generator, the empty one, so each run checks that value once. The
function draws 1,000 examples because only 3 of the 64 sets of rows have row 5 or 6 without any
of rows 1 to 4, and hypothesis keeps the set of rows of an example in the few mutations of it
that it tries next. The sets therefore come in runs, and 200 examples can miss all three.

The second function checks the manifest part of statement 3. ``manifests()`` makes no item to
which no row applies (task 1.11), so the test makes one. A drawn manifest must pass the check,
with the choice of each item as above; the same manifest with one drawn item turned into a query
that declares no file, has no verification command and leaves the four lists that task 1.4 added
(``gates``, ``knowledge_kinds``, ``read_paths``, ``artifact_paths``) empty must be rejected with
one issue only: ``executor``, at that item.

No input is filtered or assumed away. ``hypothesis.event`` reports the shapes of the drawn rows
and of the drawn manifests (``pytest --hypothesis-show-statistics``). Every value is synthetic;
see the docstring of ``strategies/handoff.py``.
"""

from __future__ import annotations

import copy
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

import pytest
from handoff import executor, manifest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from strategies import handoff as handoff_strategies

ExecutorAttrsCase = handoff_strategies.ExecutorAttrsCase
ManifestCase = handoff_strategies.ManifestCase

#: The rows of the table that make the target repository's Kiro the executor (design section 20).
TARGET_REPO_ROWS: Final = frozenset({1, 2, 3, 4})

#: The rows of the table that make this session the executor, when none of the rows above applies.
THIS_SESSION_ROWS: Final = frozenset({5, 6})


def expected_executor(rows: frozenset[int]) -> executor.Executor:
    """Decide the executor from the rows that apply, as Property 29 states it.

    Args:
        rows: The numbers of the rows that apply; at least one.

    Returns:
        The target repository's Kiro when one of rows 1 to 4 applies, otherwise this session.
    """
    if rows & TARGET_REPO_ROWS:
        return executor.Executor.TARGET_REPO_KIRO
    return executor.Executor.THIS_SESSION


def check_choice(choice: executor.ExecutorChoice, contents: Mapping[int, tuple[str, ...]], where: str) -> None:
    """Check a result of ``choose`` against the rows that apply and what each row lists.

    Args:
        choice: The result.
        contents: Each row that applies, with what its reason must list. Not empty.
        where: Which example this is, for the messages.
    """
    rows = tuple(sorted(contents))
    assert choice.executor is expected_executor(frozenset(contents)), f"{where}: rows {rows} give {choice.executor}"
    assert choice.rows == rows, f"{where}: the rows {choice.rows} are not {rows}"
    assert tuple(reason.number for reason in choice.reasons) == rows, f"{where}: the reasons are not for rows {rows}"
    for reason in choice.reasons:
        assert reason.details, f"{where}: the reason of row {reason.number} lists nothing"
        assert (
            reason.details == contents[reason.number]
        ), f"{where}: row {reason.number} lists {reason.details!r}, not {contents[reason.number]!r}"


# --------------------------------------------------------------------------------------------
# Statements 1, 2 and 4, and statement 3 for choose
# --------------------------------------------------------------------------------------------


def attrs_contents(attrs: executor.ExecutorAttrs) -> dict[int, tuple[str, ...]]:
    """Read what the reason of each row must list from the attributes.

    Args:
        attrs: The attributes.

    Returns:
        For each of the six rows, the content of its attribute. Row 3 is the uncommitted count as
        one decimal string; it is used only when the count is above 0.
    """
    return {
        1: attrs.changed_paths,
        2: attrs.gates,
        3: (str(attrs.uncommitted_count),),
        4: attrs.knowledge_kinds,
        5: attrs.read_paths,
        6: attrs.artifact_paths,
    }


def row_shapes(case: ExecutorAttrsCase) -> list[str]:
    """Name the shapes of a drawn set of rows, for ``hypothesis.event``.

    Args:
        case: The drawn attributes and the rows they apply to.

    Returns:
        Each row that applies, which of rows 1 to 4 and rows 5 and 6 apply, and whether a reason
        lists two entries or more.
    """
    rows = case.rows
    shapes = [f"row {row} applies" for row in sorted(rows)]
    if not rows:
        shapes.append("no row applies")
    elif rows & TARGET_REPO_ROWS:
        shapes.append("one of rows 1 to 4 applies")
        if rows & THIS_SESSION_ROWS:
            shapes.append("one of rows 1 to 4 applies together with row 5 or 6")
    else:
        shapes.append("only row 5 or 6 applies")
    contents = attrs_contents(case.attrs)
    if any(len(contents[row]) > 1 for row in rows):
        shapes.append("a reason lists two entries or more")
    return shapes


# Feature: cyber-resilience-phase4-supply-chain, Property 29: 他リポジトリのファイルに及ぶ変更の実行者は対象リポジトリの Kiro になる
@settings(max_examples=1_000, deadline=None)
@given(handoff_strategies.executor_attrs(allow_no_row=True))
def test_property_29_rows_1_to_4_make_the_target_repository_kiro_the_executor(case: ExecutorAttrsCase) -> None:
    """Rows 1 to 4 decide for the target repository's Kiro, rows 5 and 6 alone for this session.

    For drawn attributes with at least one row: the executor is the target repository's Kiro when
    a planted row is one of rows 1 to 4, otherwise this session; the reasons are the planted rows,
    in ascending order, and each lists the content of its attribute (row 3: the count in decimal,
    one entry). For the attributes with no row, ``choose`` raises ``ExecutorError``.

    **Validates: Requirements 28.3, 28.4**
    """
    for shape in row_shapes(case):
        event(shape)
    if not case.rows:
        with pytest.raises(executor.ExecutorError):
            executor.choose(case.attrs)
        return
    contents = attrs_contents(case.attrs)
    check_choice(executor.choose(case.attrs), {row: contents[row] for row in case.rows}, "drawn attributes")


# --------------------------------------------------------------------------------------------
# Statement 3 for the manifest check
# --------------------------------------------------------------------------------------------

#: The values that turn an item into a query to which no row of the table applies: no declared
#: file and no verification command (rows 1 and 2), and the four lists that task 1.4 added for
#: rows 2, 4, 5 and 6 empty. ``requires_refs``, ``trust_tools`` and ``trust_all`` take the only
#: values a query item may have (task 1.4), so that the executor table is the one problem left.
NO_ROW_QUERY: Final[Mapping[str, Any]] = MappingProxyType(
    {
        "mode": "query",
        "requires_refs": [],
        "trust_tools": ["fs_read"],
        "trust_all": None,
        "declared_files": [],
        "verify_commands": [],
        "gates": [],
        "knowledge_kinds": [],
        "read_paths": [],
        "artifact_paths": [],
    }
)


@dataclass(frozen=True)
class BlankedManifest:
    """A drawn manifest, and a copy of it in which one item has no row of the table.

    Attributes:
        case: The drawn manifest. Every item has a row, and the manifest passes the check.
        index: The position of the item that the copy turns into a query with no row.
        raw: The copy: the item at ``index`` updated with :data:`NO_ROW_QUERY`.
        was_mode: The mode of that item in the drawn manifest.
    """

    case: ManifestCase
    index: int
    raw: dict[str, Any]
    was_mode: str


@st.composite
def blanked_manifests(draw: st.DrawFn) -> BlankedManifest:
    """Draw a manifest from ``manifests()`` and one of its items to turn into a query with no row.

    Returns:
        The manifest and the copy. The drawn manifest is not changed.
    """
    case = draw(handoff_strategies.manifests())
    index = draw(st.integers(0, len(case.raw["items"]) - 1))
    raw = copy.deepcopy(case.raw)
    item = raw["items"][index]
    was_mode = item["mode"]
    item.update(copy.deepcopy(dict(NO_ROW_QUERY)))
    return BlankedManifest(case=case, index=index, raw=raw, was_mode=was_mode)


def item_contents(raw_item: Mapping[str, Any]) -> dict[int, tuple[str, ...]]:
    """Read the rows that apply to an item, and what each lists, from the item as written.

    The mapping of task 1.4: row 1 is ``declared_files``; row 2 is ``gates`` and each verification
    command as ``shlex.join(cmd)``; rows 4, 5 and 6 are ``knowledge_kinds``, ``read_paths`` and
    ``artifact_paths``. Row 3 does not apply, since the check passes 0 as the uncommitted count.

    Args:
        raw_item: The item as the manifest writes it.

    Returns:
        The rows that apply, each with its entries sorted and each entry once.
    """
    written = {
        1: list(raw_item["declared_files"]),
        2: [*raw_item["gates"], *(shlex.join(command["cmd"]) for command in raw_item["verify_commands"])],
        4: list(raw_item["knowledge_kinds"]),
        5: list(raw_item["read_paths"]),
        6: list(raw_item["artifact_paths"]),
    }
    return {row: tuple(sorted(set(entries))) for row, entries in written.items() if entries}


# Feature: cyber-resilience-phase4-supply-chain, Property 29: 他リポジトリのファイルに及ぶ変更の実行者は対象リポジトリの Kiro になる
@settings(max_examples=100, deadline=None)
@given(blanked_manifests())
def test_property_29_the_manifest_check_rejects_an_item_to_which_no_row_applies(example: BlankedManifest) -> None:
    """A manifest whose items all have a row passes; one item with no row makes it fail there.

    The drawn manifest passes ``parse_manifest``, and ``choose`` takes each item's attributes with
    the count 0 and gives the executor and reasons of the item as written. The copy with one item
    turned into a query with no row is rejected with exactly one issue: ``executor`` at that item.

    **Validates: Requirements 28.3, 28.4**
    """
    case = example.case
    checked = manifest.parse_manifest(case.raw, config=case.config)
    assert tuple(item.id for item in checked.items) == case.ids
    for raw_item, item in zip(case.raw["items"], checked.items, strict=True):
        contents = item_contents(raw_item)
        choice = executor.choose(item.executor_attrs(uncommitted_count=0))
        check_choice(choice, contents, f"item {item.id}")
        event(f"an accepted {item.mode} item for {choice.executor.value}")
        if set(contents) & TARGET_REPO_ROWS and set(contents) & THIS_SESSION_ROWS:
            event("an accepted item with one of rows 1 to 4 and row 5 or 6")
        if raw_item["verify_commands"]:
            event("an accepted item with a verification command in row 2")
    event(f"the item with no row was a {example.was_mode} item")
    event(f"{len(checked.items)} item(s)")

    with pytest.raises(manifest.ManifestError) as caught:
        manifest.parse_manifest(example.raw, config=case.config)
    issues = [(issue.path, issue.kind) for issue in caught.value.issues]
    assert issues == [(f"items[{example.index}]", "executor")], issues

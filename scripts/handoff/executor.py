"""Executor choice: does this session or the target repository's Kiro carry out a Handoff item.

Design section 20 ("実行者の判定", Requirements 28.3 and 28.4) decides who carries out a
Handoff item from a table of six rows. This module holds that table as data (``ROWS``) and
applies it in ``choose``:

- Rows 1 to 4 make the target repository's Kiro the executor: the item changes files of the
  target repository, has to follow the target repository's rules and gates, meets
  uncommitted changes in the target repository's main working tree, or needs knowledge that
  only the target repository has.
- Rows 5 and 6 make this session the executor, but only when none of rows 1 to 4 applies:
  the item reads committed content only, or its artifacts stay in this repository.
- Every row that applies is returned as a ``Reason``, in ascending row order, with the
  content of the table's fourth column. ``prompt.render`` writes these in section 10 of the
  Handoff_Prompt (executor and reasons, design section 17). Rows 5 and 6 are returned even
  when rows 1 to 4 decide the executor.
- An item to which no row applies is rejected with ``ExecutorError``. ``manifest`` rejects
  such an item through the same call. A result with no reason cannot be constructed.

Shape of the input: no row has a yes/no flag next to its content. A row applies exactly
when its attribute in ``ExecutorAttrs`` is non-empty (for row 3, when the count is above
zero). A row that applies therefore always has content to write as its reason, and a flag
that contradicts its content ("needs gates" with no gate named) cannot be expressed.

Attributes that look contradictory, such as changed paths together with read paths (row 1
with row 5, "reads committed content only"), are accepted. The table already settles them:
any of rows 1 to 4 decides the executor, and every row that applies is listed. A
change-mode item always has its Handoff_Prompt in this repository, so row 6 next to row 1
is the normal case and not an error.

The text of the table is kept here once, so that ``prompt.render`` does not copy it:
``Row.condition`` is the second column verbatim, ``Executor.label`` is the third column
without the notes in parentheses, and ``Row.detail_label`` is the fourth column. The note
on row 3, that paths are not written, is enforced by ``Reason`` instead of being printed:
the details of row 3 are the count and nothing else.

This module is part of the pure core. It takes observations, such as the uncommitted
count, as arguments and does no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class ExecutorError(ValueError):
    """The executor table cannot decide on the given input.

    Raised when no row of the table applies to an item, and when an attribute or a result
    does not have the shape this module requires, for example a blank path, a negative
    count, or a result with no reason.
    """


class Executor(StrEnum):
    """Who carries out a Handoff item: the third column of the table."""

    THIS_SESSION = "this-session"
    TARGET_REPO_KIRO = "target-repo-kiro"

    @property
    def label(self) -> str:
        """The executor as the table and the Handoff_Prompt name it, in Japanese."""
        return _EXECUTOR_LABELS[self]


_EXECUTOR_LABELS: Final[dict[Executor, str]] = {
    Executor.THIS_SESSION: "このセッション",
    Executor.TARGET_REPO_KIRO: "対象リポジトリの Kiro",
}


@dataclass(frozen=True, slots=True)
class Row:
    """One row of the executor table in design section 20.

    Attributes:
        number: The row number, 1 to 6.
        condition: The second column, verbatim: the condition the row tests.
        executor: The third column: who carries out the item when this row applies.
        detail_label: The fourth column: what the reason for this row lists.
    """

    number: int
    condition: str
    executor: Executor
    detail_label: str


#: The executor table of design section 20, in row order.
ROWS: Final[tuple[Row, ...]] = (
    Row(
        number=1,
        condition="変更が対象リポジトリのファイルに及ぶ",
        executor=Executor.TARGET_REPO_KIRO,
        detail_label="変更するファイルの一覧",
    ),
    Row(
        number=2,
        condition="対象リポジトリの `AGENTS.md`、ゲート、steering に従う必要がある（検証コマンドの実行を含む）",
        executor=Executor.TARGET_REPO_KIRO,
        detail_label="従う規則とゲートの名前",
    ),
    Row(
        number=3,
        condition="対象リポジトリのメインの作業ツリーに他のセッションの未コミットの変更がある",
        executor=Executor.TARGET_REPO_KIRO,
        detail_label="`git status --porcelain` の件数",
    ),
    Row(
        number=4,
        condition="対象リポジトリ固有の知識（`.private/` の記録、memory）が要る",
        executor=Executor.TARGET_REPO_KIRO,
        detail_label="求める知識の種類",
    ),
    Row(
        number=5,
        condition="コミット済みの内容を読むだけ（`git show origin/main:<path>`）",
        executor=Executor.THIS_SESSION,
        detail_label="読むパス",
    ),
    Row(
        number=6,
        condition="成果物がこのリポジトリの中だけ（Handoff_Prompt、調査ノート、設計文書）",
        executor=Executor.THIS_SESSION,
        detail_label="成果物のパス",
    ),
)

#: The only form the details of row 3 may take: a positive count in ASCII digits.
_POSITIVE_COUNT: Final = re.compile(r"[1-9][0-9]*")


@dataclass(frozen=True, slots=True)
class Reason:
    """One row that applies to an item, with what the Handoff_Prompt writes for it.

    Attributes:
        row: The row of ``ROWS`` that applies.
        details: The content of the fourth column, one entry per line: the changed files
            (row 1), the names of the rules and gates (row 2), the uncommitted count as a
            decimal string and nothing else (row 3), the kinds of knowledge (row 4), the
            paths read (row 5), or the artifact paths (row 6). Never empty.

    Raises:
        ExecutorError: ``row`` is not a row of ``ROWS``; ``details`` is not a non-empty
            tuple of non-blank single lines; or the details of row 3 are not exactly one
            positive count.
    """

    row: Row
    details: tuple[str, ...]

    def __post_init__(self) -> None:
        """Check the shape described in the class docstring."""
        if self.row not in ROWS:
            raise ExecutorError(f"{self.row!r} is not a row of the executor table")
        where = f"row {self.row.number}"
        if not isinstance(self.details, tuple) or not self.details:
            raise ExecutorError(f"{where}: details must be a non-empty tuple")
        for index, entry in enumerate(self.details):
            _check_line(f"{where}: details[{index}]", entry)
        if self.row.number == 3 and (len(self.details) != 1 or not _POSITIVE_COUNT.fullmatch(self.details[0])):
            raise ExecutorError(f"{where}: details must be exactly one positive count, with no path")

    @property
    def number(self) -> int:
        """The number of the row, 1 to 6."""
        return self.row.number

    @property
    def condition(self) -> str:
        """The second column of the row, verbatim."""
        return self.row.condition

    @property
    def detail_label(self) -> str:
        """The fourth column of the row: what ``details`` lists."""
        return self.row.detail_label


@dataclass(frozen=True, slots=True)
class ExecutorChoice:
    """The result of ``choose``: the executor and every row that applies.

    Attributes:
        executor: The target repository's Kiro when any of rows 1 to 4 applies, otherwise
            this session.
        reasons: One ``Reason`` per row that applies, in ascending row order. Never empty.

    Raises:
        ExecutorError: ``reasons`` is not a non-empty tuple of ``Reason`` in strictly
            ascending row order, or ``executor`` is not the one its rows decide.
    """

    executor: Executor
    reasons: tuple[Reason, ...]

    def __post_init__(self) -> None:
        """Check the shape described in the class docstring."""
        if not isinstance(self.reasons, tuple) or not self.reasons:
            raise ExecutorError("a choice needs at least one reason")
        if not all(isinstance(reason, Reason) for reason in self.reasons):
            raise ExecutorError("every reason must be a Reason")
        numbers = [reason.number for reason in self.reasons]
        if numbers != sorted(set(numbers)):
            raise ExecutorError(f"reasons must be in strictly ascending row order, got rows {numbers}")
        if not isinstance(self.executor, Executor) or self.executor is not _executor_for(self.reasons):
            raise ExecutorError(f"rows {numbers} decide {_executor_for(self.reasons)}, not {self.executor!r}")

    @property
    def rows(self) -> tuple[int, ...]:
        """The numbers of the rows that apply, ascending."""
        return tuple(reason.number for reason in self.reasons)


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutorAttrs:
    """What the executor table looks at for one Handoff item (Property 29).

    Each attribute belongs to one row. A row applies exactly when its attribute is
    non-empty, or above zero for ``uncommitted_count``. The fields are keyword-only because
    five of them have the same type, and a positional mix-up between them would pass
    silently.

    The collections are sets. Any iterable of strings is accepted (a bare string is not),
    and it is stored as a tuple with duplicates removed, in sorted order, so that the
    reasons do not depend on the order of the input. Each entry must be one non-blank
    line, because ``prompt.render`` writes one entry per line.

    Attributes:
        changed_paths: Row 1. Files of the target repository that the item creates or
            changes, such as the ``declared_files`` of a change-mode item.
        gates: Row 2. Names of the target repository's rules and gates that the work has
            to follow: its ``AGENTS.md``, its steering, and verification commands such as
            ``make all``.
        uncommitted_count: Row 3. The number of lines that ``git status --porcelain``
            printed for the target repository's main working tree. Only the count is kept,
            never the paths. It is an observation, so it has no default: a caller that did
            not look must not pass for a clean tree.
        knowledge_kinds: Row 4. Kinds of knowledge that only the target repository has
            (its ``.private/`` records, memory) and that the item needs.
        read_paths: Row 5. Paths whose committed content is read with
            ``git show origin/main:<path>``.
        artifact_paths: Row 6. Paths of the artifacts that the item leaves in this
            repository: the Handoff_Prompt, research notes, the design document.

    Raises:
        ExecutorError: An attribute does not have the shape described above.
    """

    changed_paths: tuple[str, ...] = ()
    gates: tuple[str, ...] = ()
    uncommitted_count: int
    knowledge_kinds: tuple[str, ...] = ()
    read_paths: tuple[str, ...] = ()
    artifact_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Check the attributes and store each collection as a sorted tuple without duplicates."""
        for name in ("changed_paths", "gates", "knowledge_kinds", "read_paths", "artifact_paths"):
            object.__setattr__(self, name, _normalize_entries(name, getattr(self, name)))
        count = self.uncommitted_count
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ExecutorError(f"uncommitted_count must be an integer of 0 or more, not {count!r}")


def choose(attrs: ExecutorAttrs) -> ExecutorChoice:
    """Decide who carries out an item, and why, from the executor table.

    Args:
        attrs: The attributes of the item, one per row of the table.

    Returns:
        The target repository's Kiro if any of rows 1 to 4 applies, otherwise this
        session. The reasons hold every row that applies, in ascending order, rows 5 and
        6 included when one of rows 1 to 4 decides the executor.

    Raises:
        ExecutorError: No row of the table applies to ``attrs``.
    """
    details_by_row: dict[int, tuple[str, ...]] = {
        1: attrs.changed_paths,
        2: attrs.gates,
        3: (str(attrs.uncommitted_count),) if attrs.uncommitted_count > 0 else (),
        4: attrs.knowledge_kinds,
        5: attrs.read_paths,
        6: attrs.artifact_paths,
    }
    reasons = tuple(Reason(row, details_by_row[row.number]) for row in ROWS if details_by_row[row.number])
    if not reasons:
        raise ExecutorError(
            "no row of the executor table applies: the item changes no file of the target repository, "
            "follows none of its rules or gates, meets no uncommitted change in its main working tree, "
            "needs none of its own knowledge, reads no committed path, and leaves no artifact in this repository"
        )
    return ExecutorChoice(_executor_for(reasons), reasons)


def _executor_for(reasons: tuple[Reason, ...]) -> Executor:
    """Apply the precedence of the table: any row for the target repository's Kiro decides.

    Args:
        reasons: The rows that apply.

    Returns:
        The target repository's Kiro if one of the rows names it, otherwise this session.
    """
    if any(reason.row.executor is Executor.TARGET_REPO_KIRO for reason in reasons):
        return Executor.TARGET_REPO_KIRO
    return Executor.THIS_SESSION


def _normalize_entries(name: str, value: object) -> tuple[str, ...]:
    """Check a collection attribute and return it as a sorted tuple without duplicates.

    Args:
        name: The attribute name, for the error message.
        value: The value given for the attribute.

    Returns:
        The distinct entries in sorted order.

    Raises:
        ExecutorError: ``value`` is a bare string or not iterable, or an entry is not one
            non-blank line.
    """
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise ExecutorError(f"{name} must be a collection of strings, not {type(value).__name__}")
    entries = tuple(value)
    for index, entry in enumerate(entries):
        _check_line(f"{name}[{index}]", entry)
    return tuple(sorted(set(entries)))


def _check_line(where: str, entry: object) -> None:
    """Require one entry of a reason to be a string that is one non-blank line.

    A line break of any kind that ``str.splitlines`` knows counts, so an entry cannot add a
    line to the section that ``prompt.render`` writes.

    Args:
        where: The position of the entry, for the error message.
        entry: The entry.

    Raises:
        ExecutorError: ``entry`` is not a string, is blank, or holds a line break.
    """
    if not isinstance(entry, str):
        raise ExecutorError(f"{where} must be a string, not {type(entry).__name__}")
    if not entry.strip() or entry.splitlines() != [entry]:
        raise ExecutorError(f"{where} must be one non-blank line")

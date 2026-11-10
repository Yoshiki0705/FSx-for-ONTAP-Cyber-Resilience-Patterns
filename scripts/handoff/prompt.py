"""Render a Handoff_Prompt: the text that the harness passes to another repository's Kiro.

Design section 17 gives the template of a Handoff_Prompt; Requirements 23.2, 23.3, 23.5,
23.6, 23.7, 28.3 and 28.14 and Property 27 say what it must hold. This module is part of the
pure core (see ``handoff/__init__.py``): it reads no file, starts no process and uses no
network. The I/O layer passes in what it read or observed: the text of the template file
that the item names, the number of uncommitted changes in the target repository's main
working tree, the refs confirmed on their repository's default branch (IN-2), the home
directory and the deny terms.

Who writes what. :func:`render` draws the whole outline: a title, the eleven sections of
design section 17 in order (:data:`SECTION_TITLES`) and, for a query item, two more sections
for the questions and for how to answer them (:data:`QUERY_SECTION_TITLES`). It also writes
every fixed sentence (the checks before starting, the notes on published output, the
operations not to perform) and every list taken from the item (files, refs, dependencies,
verification commands, executor and reasons). A template does not write sections, so it
cannot leave one out. It fills named slots:

- ``purpose``: the body of section 2. Required in both modes.
- ``completion``: conditions specific to the item, written in section 7 after the
  observable conditions that :func:`render` derives from the item (a commit on the handoff
  branch, only declared files changed, nothing left uncommitted, each verification command
  ending with exit code 0). Optional; change mode only.
- ``questions``: the body of section 12. Required; query mode only.

A section that does not apply to the mode reads :data:`NOT_APPLICABLE_TEXT` (sections 3, 4,
7 and 8 of a query item). A section that applies and has nothing to list reads
:data:`NONE_TEXT` (no refs, no dependencies, no verification commands).

Template format. A slot starts at a line that is exactly ``<!-- slot: <name> -->``, trailing
white space allowed, and runs to the next such line or to the end. For example::

    <!-- The template of the Spoke rollout items. -->
    <!-- slot: purpose -->
    Add the caller workflow `$workflow_file`, pinned to reference 1 of section 4.

    <!-- slot: completion -->
    - `$workflow_file` names no ref other than those of section 4

Before the first slot, only blank lines and one-line HTML comments may appear; they are not
drawn. Blank lines at the start and the end of a slot are dropped; the rest is kept as
written, line endings becoming LF. These are rejected: other text before the first slot, a
line that looks like a slot marker but is not one, a slot given twice, a name that is not a
slot, a slot that does not apply to the item's mode, a missing required slot, an empty slot,
a byte order mark, a NUL character and a lone surrogate.

Variables. A slot is substituted with ``string.Template.substitute`` from the item's
``vars``: ``$name`` or ``${name}``, and ``$$`` for a literal ``$``. Nothing is evaluated. A
``$`` that starts no placeholder (``$5``, the ``${{ ... }}`` of GitHub Actions) is
rejected; write ``$$``. Every placeholder needs a variable, and every variable must be used:
there is no default value, and an unused variable is most likely a misspelling, as unknown
keys are in ``config.json`` and ``manifest.json``. A value is a string of one non-blank line
without NUL. Text of several lines belongs in the template.

The outline cannot be changed by a slot. After substitution, a slot may not hold a line that
Markdown reads as a level-1 or level-2 heading: an ATX heading ``#`` or ``##`` with up to
three spaces before it, or a line of only ``=`` or only ``-`` right after a text line (a
setext underline). Every code fence that a slot opens must close in the slot, since an open
fence would take in the sections after it. Lines inside a fence are not headings, so a shell
comment in a code block is fine, and so are headings of level 3 to 6. A heading-like line is
rejected rather than rewritten: rewriting would change the author's text without notice and
still show a plain-text reader something that looks like a section. These checks keep the
outline intact; they do not make hostile text harmless. Templates and ``vars`` are kept in
this repository's ``.private/handoff/``, not taken from another repository, and the
deny-term scan below looks at the drawn body.

Other parts of the item. Section 10 shows the executor's label (:attr:`Executor.label`) and,
for each row that applies, its number, its condition (:attr:`Reason.condition`, verbatim)
and its details; row 3 shows the count only, as :class:`handoff.executor.Reason` enforces.
The table speaks from the side that passes the prompt on, and a sentence says so. When the
item has ``trust_all``, section 11 states its reason (Requirement 28.7). A verification
command that :func:`handoff.manifest.rerun_skip_reason` would not re-run carries a note that
it may call AWS or write to a remote.

Refs (section 4, Requirement 23.5). Each entry of ``requires_refs`` gets one line, in order.
A ref in ``confirmed_refs`` shows its kind and name. Any other ref shows its repository, its
kind and :data:`UNCONFIRMED_REF_TEXT`; its name is never written, so neither a 40-digit
hexadecimal SHA nor a tag name that might change is guessed into the prompt. A slot may not
write that name either: a substituted slot line that holds the name of an unconfirmed ref as
a whole word (not next to an ASCII letter, a digit, ``.``, ``_``, ``/`` or ``-``) is
rejected, so a template refers to "reference N of section 4" instead of carrying the value in
a variable. Only the exact name is found; another guessed value is not. The items of
``depends_on`` in the ref's repository are the Handoffs that confirm it. Section 5 lists all
dependencies, marking those, and :attr:`RenderedPrompt.ref_providers` returns their IDs. The
manifest check guarantees such an item for a ref of another repository; for an unconfirmed
ref of the item's own repository without one, :func:`render` raises :class:`PromptError`.

Paths. The main working tree and the worktree are written under the home directory as
``~/...``, so that no ``/Users/<name>`` path reaches the prompt. A path outside the home
directory is rejected: it would have to be written in full, and it could carry a user name
that the scan does not know. The worktree is ``<worktrees_root>/<repo>/<id>``, the layout of
design section 20. The manual-mode commands of section 6 use these paths and leave the base
SHA as ``<sha>``, since it is fixed only when the worktree is made.

Length and scan. The body's length is its size in UTF-8 bytes, the size it has as one element
of the ``kiro-cli`` argv. A body over :data:`MAX_BODY_BYTES` is returned all the same, with
:data:`HOLD_TOO_LONG` among its hold reasons. The body is scanned with
:func:`handoff.scan.check` and the caller's deny terms; any finding adds
:data:`HOLD_SCAN_FINDINGS`. An item with a hold reason goes to ``needs-human`` and is not
passed on (Requirement 28.23 and Property 26). Holding it is the caller's step:
:func:`render` changes no state.
"""

from __future__ import annotations

import json
import re
import shlex
import string
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Literal, TypeAlias

from handoff import scan
from handoff.config import HandoffConfig, is_within, normalize_path
from handoff.executor import Executor, ExecutorChoice, Reason, choose
from handoff.manifest import Item, Manifest, RequiredRef, rerun_skip_reason

#: Most UTF-8 bytes a body may have: 100 KiB. The body becomes one element of the ``kiro-cli``
#: argv, and this bound stays far below the argument space of macOS (``getconf ARG_MAX``
#: printed 1048576 on the machine that runs the harness, once). It was set as a margin, not
#: measured against a failure (design section 20, hypothesis).
MAX_BODY_BYTES: Final = 100 * 1024

#: The titles of the eleven sections of design section 17, in order. Section ``n`` is drawn as
#: ``## n. <title>`` (:func:`section_headings`).
SECTION_TITLES: Final[tuple[str, ...]] = (
    "対象リポジトリ",
    "変更の目的",
    "作成・変更するファイル",
    "参照する Renovate_Preset と Reusable_Workflow",
    "先に完了している必要がある Handoff",
    "着手前の確認",
    "完了条件",
    "検証コマンド",
    "公開物の注意",
    "実行者と理由",
    "行わない操作",
)

#: The titles of the two sections that only a query item has, numbered 12 and 13.
QUERY_SECTION_TITLES: Final[tuple[str, ...]] = ("問いの一覧", "答え方")

#: The sections that do not apply to a query item (design section 17).
QUERY_NOT_APPLICABLE: Final[frozenset[int]] = frozenset({3, 4, 7, 8})

#: The body of a section that applies and has nothing to list.
NONE_TEXT: Final = "なし"

#: The body of a section that does not apply to the item's mode.
NOT_APPLICABLE_TEXT: Final = "該当なし"

#: What an unconfirmed ref shows instead of its name (Requirement 23.5).
UNCONFIRMED_REF_TEXT: Final = "未確定。先に Hub の Handoff を完了すること"

#: The first instruction of section 13 of a query item.
QUERY_ANSWER_INSTRUCTION: Final = (
    "答えに既存の記録のパスとコミット SHA を添える。コミットされていない記録はその旨を書く"
)

#: The operations that section 11 forbids (Requirement 28.14), in the order written there.
FORBIDDEN_OPERATIONS: Final[tuple[str, ...]] = (
    "push",
    "PR の作成",
    "マージ",
    "ブランチの削除",
    "AWS の課金が発生する操作",
    "不可逆な操作",
)

#: What section 9 keeps out of commit messages, PR text and files (Requirement 23.7).
PUBLIC_OUTPUT_EXCLUSIONS: Final[tuple[str, ...]] = (
    "人名・ペルソナ名",
    "AWS アカウント ID",
    "内部 IP アドレス",
    "サポートケース番号",
)

#: The placeholders that section 9 offers for examples. ``handoff.scan`` lets each pass.
PLACEHOLDERS: Final[tuple[str, ...]] = ("123456789012", "10.0.x.x", "<management-ip>")

SLOT_PURPOSE: Final = "purpose"
SLOT_COMPLETION: Final = "completion"
SLOT_QUESTIONS: Final = "questions"

#: Every slot name, in the order the slots are written in the body.
SLOT_NAMES: Final[tuple[str, ...]] = (SLOT_PURPOSE, SLOT_COMPLETION, SLOT_QUESTIONS)

#: The slots that a template may fill, for each mode.
ALLOWED_SLOTS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {"change": (SLOT_PURPOSE, SLOT_COMPLETION), "query": (SLOT_PURPOSE, SLOT_QUESTIONS)}
)

#: The slots that a template must fill, for each mode. A slot has no default text.
REQUIRED_SLOTS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {"change": (SLOT_PURPOSE,), "query": (SLOT_PURPOSE, SLOT_QUESTIONS)}
)

#: Why a drawn prompt must not be passed on. Both lead to ``needs-human``.
HoldReason: TypeAlias = Literal["prompt_too_long", "prompt_scan_findings"]

#: The body is longer than :data:`MAX_BODY_BYTES`.
HOLD_TOO_LONG: Final[HoldReason] = "prompt_too_long"

#: :func:`handoff.scan.check` found something in the body.
HOLD_SCAN_FINDINGS: Final[HoldReason] = "prompt_scan_findings"

IssueKind: TypeAlias = Literal[
    "format",
    "missing",
    "unknown",
    "duplicate",
    "mode",
    "type",
    "structure",
    "reference",
    "path",
]

_MODE_LABELS: Final[Mapping[str, str]] = MappingProxyType({"change": "変更モード", "query": "照会モード"})
_REF_KIND_LABELS: Final[Mapping[str, str]] = MappingProxyType({"tag": "タグ", "sha": "コミット SHA"})

#: What follows the executor's label in section 10, so that the reader of the prompt knows
#: which side the label means.
_EXECUTOR_NOTES: Final[Mapping[Executor, str]] = MappingProxyType(
    {
        Executor.TARGET_REPO_KIRO: "（この依頼を受け取った Kiro）",
        Executor.THIS_SESSION: "（この依頼を渡した側のセッション。受け取った Kiro ではない）",
    }
)

#: Rows of the executor table whose details are paths or command and gate names, written as
#: code spans. Row 3 is a count and row 4 kinds of knowledge, written as plain text.
_CODE_DETAIL_ROWS: Final[frozenset[int]] = frozenset({1, 2, 5, 6})

_SLOT_MARKER: Final = re.compile(r"<!-- slot: ([a-z][a-z0-9_]*) -->")
_SLOT_LIKE: Final = re.compile(r"\s*<!--\s*slot", re.IGNORECASE)
_COMMENT_LINE: Final = re.compile(r"\s*<!--(?:(?!-->).)*-->\s*")
#: Characters that a tag name or a SHA may hold. A ref name next to one of them is part of a
#: longer word, not the name itself.
_REF_NAME_CHAR: Final = "A-Za-z0-9._/-"
_ATX_HEADING: Final = re.compile(r" {0,3}(#{1,6})(?:[ \t]|$)")
_SETEXT_UNDERLINE: Final = re.compile(r" {0,3}(?:=+|-+)[ \t]*$")
_FENCE_OPEN: Final = re.compile(r" {0,3}(`{3,}|~{3,})(.*)$")
_FENCE_CLOSE: Final = re.compile(r" {0,3}(`{3,}|~{3,})[ \t]*$")
_BACKTICKS: Final = re.compile(r"`+")
_PLAIN_VAR: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True, slots=True)
class PromptIssue:
    """One problem that keeps an item's Handoff_Prompt from being drawn.

    Attributes:
        where: Where the problem is: ``<template>:<line>`` for a line of the template (the
            item's ``template`` path and a line number from 1, as ``str.splitlines`` counts
            lines), ``<template>`` for the template as a whole, ``vars.<key>`` for a template
            variable, ``item`` for the item, or ``config`` for the configuration.
        kind: ``format`` (the shape of the template or of a value is wrong), ``missing`` (a
            required slot or a variable that a placeholder needs is absent), ``unknown`` (a
            slot name that does not exist, or a variable that no placeholder uses),
            ``duplicate`` (a slot given twice), ``mode`` (a slot that does not apply to the
            item's mode), ``type`` (a variable that is not a string), ``structure`` (a slot
            that would change the outline), ``reference`` (an item, a repository or a
            confirming Handoff that cannot be found) or ``path`` (a path outside the home
            directory).
        detail: An explanation for the maintainer. It never repeats a variable's value or a
            template line, either of which can hold a deny term.
    """

    where: str
    kind: IssueKind
    detail: str

    def __str__(self) -> str:
        """Render the issue as one line: ``<where>: <kind>: <detail>``."""
        return f"{self.where}: {self.kind}: {self.detail}"


class PromptError(ValueError):
    """An item's Handoff_Prompt could not be drawn.

    The caller records the item as ``needs-human`` with the issues, as it does for a hold
    reason of :class:`RenderedPrompt`.

    Attributes:
        issues: Every problem found, not only the first, in a fixed order: the template's
            lines, the slots, the placeholders and variables, the substituted slots, the
            paths and the refs.
    """

    def __init__(self, issues: Iterable[PromptIssue]) -> None:
        """Keep the issues and use one line per issue as the message.

        Args:
            issues: One or more problems.
        """
        self.issues: tuple[PromptIssue, ...] = tuple(issues)
        super().__init__("\n".join(str(issue) for issue in self.issues))


@dataclass(frozen=True, slots=True)
class RenderedPrompt:
    """A drawn Handoff_Prompt, with what the caller needs to decide whether to pass it on.

    Attributes:
        item_id: The item.
        repo: The target repository.
        mode: ``query`` or ``change``.
        body: The prompt: UTF-8 encodable, LF line ends, one final newline.
        executor_choice: The result of :func:`handoff.executor.choose` that section 10 shows.
        unconfirmed_refs: The item's refs that were not in ``confirmed_refs``, in the order of
            ``requires_refs``. Each is drawn as :data:`UNCONFIRMED_REF_TEXT`. ``dag.ready``
            does not start an item with one; a caller can check it again here.
        ref_providers: IDs of the dependencies that section 5 marks as confirming an
            unconfirmed ref: every item of ``depends_on`` in the repository of such a ref, in
            the order of ``depends_on``.
        findings: What :func:`handoff.scan.check` found in the body: positions and kinds only.
    """

    item_id: str
    repo: str
    mode: str
    body: str
    executor_choice: ExecutorChoice
    unconfirmed_refs: tuple[RequiredRef, ...]
    ref_providers: tuple[str, ...]
    findings: tuple[scan.Finding, ...]

    @property
    def byte_length(self) -> int:
        """The size of the body in UTF-8 bytes."""
        return len(self.body.encode("utf-8"))

    @property
    def over_limit(self) -> bool:
        """Whether the body is longer than :data:`MAX_BODY_BYTES`."""
        return self.byte_length > MAX_BODY_BYTES

    @property
    def hold_reasons(self) -> tuple[HoldReason, ...]:
        """Why the prompt must not be passed on, in a fixed order. Empty when it may be."""
        reasons: list[HoldReason] = []
        if self.over_limit:
            reasons.append(HOLD_TOO_LONG)
        if self.findings:
            reasons.append(HOLD_SCAN_FINDINGS)
        return tuple(reasons)

    @property
    def needs_human(self) -> bool:
        """Whether the item goes to ``needs-human`` instead of being passed on."""
        return bool(self.hold_reasons)

    @property
    def history_reason(self) -> str | None:
        """The hold reasons joined into one line for ``state.transition``, or ``None``."""
        return ", ".join(self.hold_reasons) or None


@dataclass(frozen=True, slots=True)
class _Places:
    """The paths that the body names, written under the home directory as ``~/...``.

    Attributes:
        main_tree: The target repository's main working tree.
        worktree: The item's worktree, ``<worktrees_root>/<repo>/<id>``.
    """

    main_tree: str
    worktree: str


@dataclass(slots=True)
class _Slot:
    """One slot of a template as read, before trimming and substitution.

    Attributes:
        name: The slot name from the marker.
        marker_line: Line number of the marker in the template, from 1.
        lines: The lines after the marker, up to the next marker or the end.
    """

    name: str
    marker_line: int
    lines: list[str] = field(default_factory=list)


def section_headings(mode: str) -> tuple[str, ...]:
    """List the section headings that a body of the given mode has, in order.

    Args:
        mode: ``query`` or ``change``.

    Returns:
        ``## 1. 対象リポジトリ`` to ``## 11. 行わない操作``, followed for ``query`` by
        ``## 12. 問いの一覧`` and ``## 13. 答え方``.

    Raises:
        ValueError: ``mode`` is not a mode.
    """
    if mode not in _MODE_LABELS:
        raise ValueError(f"mode must be one of {', '.join(_MODE_LABELS)}, not {mode!r}")
    titles = SECTION_TITLES + (QUERY_SECTION_TITLES if mode == "query" else ())
    return tuple(f"## {number}. {title}" for number, title in enumerate(titles, 1))


def render(
    manifest: Manifest,
    item_id: str,
    *,
    config: HandoffConfig,
    template_text: str,
    uncommitted_count: int,
    confirmed_refs: Iterable[RequiredRef],
    home: str,
    deny_terms: Iterable[str],
) -> RenderedPrompt:
    """Draw the Handoff_Prompt of one item and scan it.

    Args:
        manifest: The manifest that :func:`handoff.manifest.parse_manifest` returned.
        item_id: The item to draw.
        config: The configuration that the manifest was checked against. ``repos`` gives the
            target repository's main working tree, and ``worktrees_root`` the place of the
            item's worktree.
        template_text: The text of the file that the item's ``template`` names, decoded from
            UTF-8 by the caller.
        uncommitted_count: The number of lines that ``git status --porcelain`` printed for the
            target repository's main working tree before drawing: row 3 of the executor table.
            It has no default, so that a caller that did not look cannot pass for a clean tree.
        confirmed_refs: The refs confirmed on their repository's default branch (IN-2). A ref
            of the item that is not here is drawn as unconfirmed. Other refs are ignored.
        home: The absolute home directory, used to write paths as ``~/...``.
        deny_terms: The deny terms for :func:`handoff.scan.check`: names of people, personas,
            speakers and customers, read by the caller from its lists.

    Returns:
        The body, the executor choice, the unconfirmed refs and the dependencies that confirm
        them, and the scan findings. A body over :data:`MAX_BODY_BYTES` is returned too; its
        hold reasons say so.

    Raises:
        PromptError: The item is not in the manifest, or its body cannot be drawn: a problem
            of the template or of a variable, a slot that would change the outline or writes
            the name of an unconfirmed ref, a repository missing from ``config.repos``, a
            path outside the home directory, or an unconfirmed ref of the item's own
            repository with no dependency to confirm it. Every problem is in ``issues``.
        handoff.executor.ExecutorError: ``uncommitted_count`` is not an integer of 0 or more.
        TypeError: An argument has the wrong type: ``manifest`` is not a
            :class:`handoff.manifest.Manifest`, ``config`` not a
            :class:`handoff.config.HandoffConfig`, ``item_id``, ``template_text`` or ``home``
            not a ``str``, ``confirmed_refs`` a ``str`` or holding something that is not a
            :class:`handoff.manifest.RequiredRef`, or ``deny_terms`` refused by
            :func:`handoff.scan.check`.
        ValueError: ``home`` is not an absolute path.
    """
    if not isinstance(manifest, Manifest):
        raise TypeError(f"manifest must be a Manifest from parse_manifest, not {type(manifest).__name__}")
    if not isinstance(config, HandoffConfig):
        raise TypeError(f"config must be a HandoffConfig from parse_config, not {type(config).__name__}")
    for name, value in (("item_id", item_id), ("template_text", template_text), ("home", home)):
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a str, not {type(value).__name__}")
    confirmed = _confirmed(confirmed_refs)
    try:
        home = normalize_path(home, home)
    except ValueError as exc:
        raise ValueError(f"home: {exc}") from exc

    by_id = manifest.by_id
    item = by_id.get(item_id)
    if item is None:
        raise PromptError([PromptIssue("item", "reference", f"the manifest has no item {item_id!r}")])
    choice = choose(item.executor_attrs(uncommitted_count=uncommitted_count))

    issues: list[PromptIssue] = []
    unconfirmed = tuple(ref for ref in item.requires_refs if ref not in confirmed)
    slots = _fill_slots(template_text, item, unconfirmed, issues)
    places = _places(item, config, home, issues)
    providers = _ref_providers(item, by_id, unconfirmed, issues)
    if issues or places is None:
        raise PromptError(issues)

    lines = _draw(item, by_id, choice, slots, unconfirmed, providers, places)
    _check_outline(lines, (f"# Handoff: {item.repo}", *section_headings(item.mode)))
    body = "\n".join(lines) + "\n"
    if "\x00" in body or not _encodable(body):
        raise PromptError(
            [PromptIssue("item", "format", "a value of the item holds a NUL character or a lone surrogate")]
        )
    findings = tuple(scan.check(body, deny_terms))
    return RenderedPrompt(
        item_id=item.id,
        repo=item.repo,
        mode=item.mode,
        body=body,
        executor_choice=choice,
        unconfirmed_refs=unconfirmed,
        ref_providers=providers,
        findings=findings,
    )


def _confirmed(refs: Iterable[RequiredRef]) -> frozenset[RequiredRef]:
    """Check ``confirmed_refs`` and return it as a set.

    Raises:
        TypeError: ``refs`` is a string or not iterable, or holds something that is not a
            :class:`handoff.manifest.RequiredRef`.
    """
    if isinstance(refs, (str, bytes)) or not isinstance(refs, Iterable):
        raise TypeError("confirmed_refs must be a collection of RequiredRef, not a single value")
    entries = tuple(refs)
    if not all(isinstance(ref, RequiredRef) for ref in entries):
        raise TypeError("every entry of confirmed_refs must be a RequiredRef")
    return frozenset(entries)


def _fill_slots(
    text: str, item: Item, unconfirmed: Sequence[RequiredRef], issues: list[PromptIssue]
) -> dict[str, tuple[str, ...]]:
    """Read the template's slots, check them and the variables, and substitute.

    Args:
        text: The template text.
        item: The item, for its mode, its ``vars``, its refs and its template path.
        unconfirmed: The item's unconfirmed refs, whose names no slot may write.
        issues: Where problems are recorded.

    Returns:
        Each slot that applies to the item's mode, as substituted lines. Empty when any
        problem was recorded before substitution.
    """
    where = item.template
    slots = _read_slots(text, where, issues)
    for name, slot in slots.items():
        if name not in SLOT_NAMES:
            issues.append(
                PromptIssue(f"{where}:{slot.marker_line}", "unknown", f"{name} is not a slot: {', '.join(SLOT_NAMES)}")
            )
        elif name not in ALLOWED_SLOTS[item.mode]:
            issues.append(
                PromptIssue(f"{where}:{slot.marker_line}", "mode", f"slot {name} does not apply to a {item.mode} item")
            )
    for name in REQUIRED_SLOTS[item.mode]:
        if name not in slots:
            issues.append(
                PromptIssue(where, "missing", f"a {item.mode} item needs the slot {name}; a slot has no default text")
            )

    bodies: dict[str, tuple[int, list[str]]] = {}
    for name, slot in slots.items():
        first, lines = _trimmed(slot)
        if lines:
            bodies[name] = (first, lines)
        else:
            issues.append(PromptIssue(f"{where}:{slot.marker_line}", "format", f"slot {name} is empty"))

    identifiers: set[str] = set()
    for first, lines in bodies.values():
        identifiers |= _identifiers(lines, first, where, issues)
    values = _values(item.vars, issues)
    var_names = set(item.vars)
    for name in sorted(identifiers - var_names):
        issues.append(
            PromptIssue(where, "missing", f"a placeholder names ${name}, and vars has no {name}; there is no default")
        )
    for key in sorted(var_names - identifiers):
        issues.append(PromptIssue(_var_where(key), "unknown", "no placeholder of the template uses it"))
    if issues:
        return {}

    filled: dict[str, tuple[str, ...]] = {}
    for name in ALLOWED_SLOTS[item.mode]:
        if name not in bodies:
            continue
        first, lines = bodies[name]
        substituted = string.Template("\n".join(lines)).substitute(values).split("\n")
        issues.extend(_structure_issues(substituted, first, where, name))
        issues.extend(_ref_name_issues(substituted, first, where, name, item.requires_refs, unconfirmed))
        filled[name] = tuple(substituted)
    return filled


def _read_slots(text: str, where: str, issues: list[PromptIssue]) -> dict[str, _Slot]:
    """Split a template into its slots, in the order they appear.

    Args:
        text: The template text.
        where: The template path, for issues.
        issues: Where problems are recorded.

    Returns:
        The slots by name. A repeated slot keeps its first occurrence.
    """
    if text.startswith("\ufeff"):
        issues.append(PromptIssue(where, "format", "starts with a byte order mark; save it as UTF-8 without one"))
        text = text[1:]
    slots: dict[str, _Slot] = {}
    current: _Slot | None = None
    stray_reported = False
    for number, line in enumerate(text.splitlines(), 1):
        at = f"{where}:{number}"
        if "\x00" in line:
            issues.append(PromptIssue(at, "format", "holds a NUL character, which an argv cannot carry"))
        if not _encodable(line):
            issues.append(PromptIssue(at, "format", "holds a lone surrogate, which does not encode as UTF-8"))
        marker = _SLOT_MARKER.fullmatch(line.rstrip())
        if marker is not None:
            name = marker.group(1)
            if name in slots:
                issues.append(PromptIssue(at, "duplicate", f"slot {name} was opened at line {slots[name].marker_line}"))
                current = _Slot(name, number)
            else:
                current = slots[name] = _Slot(name, number)
            continue
        if _SLOT_LIKE.match(line):
            issues.append(
                PromptIssue(at, "format", "looks like a slot marker but is not exactly '<!-- slot: <name> -->'")
            )
            continue
        if current is None:
            if line.strip() and not _COMMENT_LINE.fullmatch(line) and not stray_reported:
                issues.append(
                    PromptIssue(
                        at,
                        "format",
                        "only blank lines and one-line HTML comments may come before the first slot marker; "
                        "move the text into a slot",
                    )
                )
                stray_reported = True
            continue
        current.lines.append(line)
    return slots


def _trimmed(slot: _Slot) -> tuple[int, list[str]]:
    """Drop the blank lines at the start and the end of a slot.

    Returns:
        The template line number of the first line kept, and the lines kept.
    """
    lines = slot.lines
    start = 0
    while start < len(lines) and not lines[start].strip():
        start += 1
    end = len(lines)
    while end > start and not lines[end - 1].strip():
        end -= 1
    return slot.marker_line + 1 + start, lines[start:end]


def _identifiers(lines: Sequence[str], first: int, where: str, issues: list[PromptIssue]) -> set[str]:
    """Collect the placeholder names of a slot and record each ``$`` that starts none.

    Args:
        lines: The slot's lines.
        first: The template line number of the first line.
        where: The template path, for issues.
        issues: Where problems are recorded.

    Returns:
        The names of ``$name`` and ``${name}``, as written.
    """
    names: set[str] = set()
    for offset, line in enumerate(lines):
        for match in string.Template.pattern.finditer(line):
            if match.group("invalid") is not None:
                issues.append(
                    PromptIssue(
                        f"{where}:{first + offset}",
                        "format",
                        "a '$' starts no placeholder; write '$$' for a literal '$'",
                    )
                )
            name = match.group("named") or match.group("braced")
            if name is not None:
                names.add(name)
    return names


def _values(item_vars: Mapping[str, Any], issues: list[PromptIssue]) -> dict[str, str]:
    """Check the template variables and return those that can be substituted.

    Args:
        item_vars: The item's ``vars``.
        issues: Where problems are recorded.

    Returns:
        The variables whose values are one non-blank line of text.
    """
    values: dict[str, str] = {}
    for key in sorted(item_vars):
        value = item_vars[key]
        if not isinstance(value, str):
            issues.append(PromptIssue(_var_where(key), "type", f"must be a string, not {_json_type(value)}"))
            continue
        problem = _value_problem(value)
        if problem is not None:
            issues.append(PromptIssue(_var_where(key), "format", problem))
            continue
        values[key] = value
    return values


def _value_problem(value: str) -> str | None:
    """Tell what keeps a variable's value from being substituted, or ``None``."""
    if not value.strip():
        return "must not be blank"
    if "\x00" in value:
        return "must not hold a NUL character"
    if value.splitlines() != [value]:
        return "must be one line; write text of several lines in the template"
    if not _encodable(value):
        return "holds a lone surrogate, which does not encode as UTF-8"
    return None


def _structure_issues(lines: Sequence[str], first: int, where: str, slot: str) -> list[PromptIssue]:
    """Find the lines of a substituted slot that would change the outline of the body.

    Args:
        lines: The substituted lines of the slot.
        first: The template line number of the first line. A variable's value is one line,
            so line ``first + n`` of the template became ``lines[n]``.
        where: The template path, for issues.
        slot: The slot name, for issues.

    Returns:
        One issue per level-1 or level-2 heading and per setext underline outside a code
        fence, and one for a fence that the slot leaves open.
    """
    found: list[PromptIssue] = []
    outside, open_fence = _fence_map(lines)
    previous_blank = True
    for offset, (line, is_text) in enumerate(zip(lines, outside, strict=True)):
        if not is_text:
            previous_blank = False
            continue
        at = f"{where}:{first + offset}"
        level = _heading_level(line)
        if level is not None and level <= 2:
            found.append(
                PromptIssue(
                    at,
                    "structure",
                    f"slot {slot}: a level-{level} heading would add a section; use ### or deeper inside a slot",
                )
            )
        elif _SETEXT_UNDERLINE.match(line) and not previous_blank:
            found.append(
                PromptIssue(
                    at,
                    "structure",
                    f"slot {slot}: a line of only '=' or '-' after a text line makes that line a heading; "
                    "put a blank line before it",
                )
            )
        previous_blank = not line.strip()
    if open_fence is not None:
        found.append(
            PromptIssue(
                f"{where}:{first + open_fence}",
                "structure",
                f"slot {slot}: the code fence opened here does not close in the slot, "
                "so it would take in the sections after it",
            )
        )
    return found


def _ref_name_issues(
    lines: Sequence[str],
    first: int,
    where: str,
    slot: str,
    refs: Sequence[RequiredRef],
    unconfirmed: Sequence[RequiredRef],
) -> list[PromptIssue]:
    """Find the lines of a substituted slot that write the name of an unconfirmed ref.

    Args:
        lines: The substituted lines of the slot.
        first: The template line number of the first line.
        where: The template path, for issues.
        slot: The slot name, for issues.
        refs: The item's ``requires_refs``, to number the refs as section 4 does.
        unconfirmed: The item's unconfirmed refs.

    Returns:
        One issue per line and unconfirmed ref whose name the line holds as a whole word.
        The issue names the ref by its number, not by its name.
    """
    found: list[PromptIssue] = []
    for position, ref in enumerate(refs, 1):
        if ref not in unconfirmed:
            continue
        word = re.compile(rf"(?<![{_REF_NAME_CHAR}]){re.escape(ref.name)}(?![{_REF_NAME_CHAR}])")
        for offset, line in enumerate(lines):
            if word.search(line):
                found.append(
                    PromptIssue(
                        f"{where}:{first + offset}",
                        "reference",
                        f"slot {slot}: writes the name of reference {position}, which is not confirmed; refer to "
                        "section 4 instead of writing a value that may change (Requirement 23.5)",
                    )
                )
    return found


def _fence_map(lines: Sequence[str]) -> tuple[list[bool], int | None]:
    """Mark the lines that lie outside fenced code blocks, as CommonMark reads fences.

    A fence opens at a line of three or more backticks or tildes, with up to three spaces
    before them (an info string after backticks may not hold a backtick), and closes at a
    line of the same character, at least as long, with nothing else but white space.

    Args:
        lines: Lines without their line breaks.

    Returns:
        For each line, True when it is outside a fence and is not a fence line itself; and
        the index of the line that opened a fence left open at the end, or ``None``.
    """
    outside: list[bool] = []
    fence: tuple[str, int, int] | None = None
    for index, line in enumerate(lines):
        if fence is not None:
            closing = _FENCE_CLOSE.match(line)
            if closing is not None and closing.group(1)[0] == fence[0] and len(closing.group(1)) >= fence[1]:
                fence = None
            outside.append(False)
            continue
        opening = _FENCE_OPEN.match(line)
        if opening is not None and not (opening.group(1)[0] == "`" and "`" in opening.group(2)):
            fence = (opening.group(1)[0], len(opening.group(1)), index)
            outside.append(False)
            continue
        outside.append(True)
    return outside, None if fence is None else fence[2]


def _heading_level(line: str) -> int | None:
    """The level of an ATX heading line, or ``None`` for any other line."""
    match = _ATX_HEADING.match(line)
    return None if match is None else len(match.group(1))


def _places(item: Item, config: HandoffConfig, home: str, issues: list[PromptIssue]) -> _Places | None:
    """Write the main working tree and the worktree of an item under the home directory.

    Args:
        item: The item.
        config: The configuration.
        home: The normalized home directory.
        issues: Where problems are recorded.

    Returns:
        The two paths as ``~/...``, or ``None`` when one cannot be written so.
    """
    repo_config = config.repos.get(item.repo)
    if repo_config is None:
        issues.append(PromptIssue("config", "reference", f"{item.repo} is not in repos of config.json"))
        return None
    main_tree = _under_home(repo_config.main_tree, home)
    if main_tree is None:
        issues.append(
            PromptIssue(
                "config",
                "path",
                f"the main_tree of {item.repo} is outside the home directory; the prompt writes paths as ~/...",
            )
        )
    root = _under_home(config.worktrees_root, home)
    if root is None:
        issues.append(
            PromptIssue(
                "config", "path", "worktrees_root is outside the home directory; the prompt writes paths as ~/..."
            )
        )
    if main_tree is None or root is None:
        return None
    return _Places(main_tree=main_tree, worktree=f"{root}/{item.repo}/{item.id}")


def _under_home(path: str, home: str) -> str | None:
    """Write an absolute path under the home directory as ``~/...``.

    Args:
        path: A normalized absolute path.
        home: The normalized home directory.

    Returns:
        ``~`` followed by the components below the home directory, or ``None`` for a path
        outside it. The comparison ignores letter case and Unicode normalization, as
        :func:`handoff.config.is_within` does; the components are written as given.
    """
    if not is_within(path, home):
        return None
    depth = len([part for part in home.split("/") if part])
    return "/".join(["~", *[part for part in path.split("/") if part][depth:]])


def _ref_providers(
    item: Item, by_id: Mapping[str, Item], unconfirmed: Sequence[RequiredRef], issues: list[PromptIssue]
) -> tuple[str, ...]:
    """Find the dependencies that confirm the unconfirmed refs.

    Args:
        item: The item.
        by_id: The manifest's items by ID.
        unconfirmed: The item's unconfirmed refs.
        issues: Where an unconfirmed ref with no confirming dependency is recorded.

    Returns:
        The IDs in ``depends_on`` whose repository is that of an unconfirmed ref, in the
        order of ``depends_on``.
    """
    repos = {ref.repo for ref in unconfirmed}
    providers = tuple(dependency for dependency in item.depends_on if by_id[dependency].repo in repos)
    for ref in unconfirmed:
        if not any(by_id[dependency].repo == ref.repo for dependency in providers):
            issues.append(
                PromptIssue(
                    "item",
                    "reference",
                    f"an unconfirmed {ref.kind} of {ref.repo} has no item of {ref.repo} in depends_on, so the "
                    "prompt cannot name the Handoff that confirms it (Requirement 23.5)",
                )
            )
    return providers


def _draw(
    item: Item,
    by_id: Mapping[str, Item],
    choice: ExecutorChoice,
    slots: Mapping[str, tuple[str, ...]],
    unconfirmed: Sequence[RequiredRef],
    providers: Sequence[str],
    places: _Places,
) -> list[str]:
    """Draw the body as lines, in the order of :func:`section_headings`.

    Returns:
        The lines of the body, without line breaks: the title, then for each section a
        blank line, its heading, a blank line and its body.
    """
    query = item.mode == "query"
    bodies: dict[int, list[str]] = {
        1: _target_section(item, places),
        2: list(slots[SLOT_PURPOSE]),
        5: _dependencies_section(item, by_id, providers),
        6: _checks_section(item, places),
        9: _publication_section(query),
        10: _executor_section(choice),
        11: _forbidden_section(item, places),
    }
    if query:
        bodies.update({number: [NOT_APPLICABLE_TEXT] for number in QUERY_NOT_APPLICABLE})
        bodies[12] = list(slots[SLOT_QUESTIONS])
        bodies[13] = _answer_section()
    else:
        bodies[3] = _files_section(item)
        bodies[4] = _refs_section(item, unconfirmed)
        bodies[7] = _completion_section(item, slots.get(SLOT_COMPLETION))
        bodies[8] = _verification_section(item)
    lines = [f"# Handoff: {item.repo}"]
    for number, heading in enumerate(section_headings(item.mode), 1):
        lines += ["", heading, "", *bodies[number]]
    return lines


def _target_section(item: Item, places: _Places) -> list[str]:
    """Section 1: the target repository, the item, the main working tree and the worktree."""
    if item.mode == "query":
        worktree_note = "ブランチを持たない。`--detach` で作った worktree"
    else:
        worktree_note = f"引き継ぎ用ブランチ {_code(_branch(item))}"
    return [
        f"- リポジトリ: {item.repo}",
        f"- 項目: {_code(item.id)}（{_MODE_LABELS[item.mode]}）",
        f"- メインの作業ツリー: {_code(places.main_tree)}（読み取りだけで参照する）",
        f"- 作業する worktree: {_code(places.worktree)}（{worktree_note}）",
    ]


def _files_section(item: Item) -> list[str]:
    """Section 3 of a change item: the declared files, and that nothing else is touched."""
    return [
        "この一覧の外のファイルを作成・変更・削除しない。",
        "",
        *(f"- {_code(path)}" for path in item.declared_files),
    ]


def _refs_section(item: Item, unconfirmed: Sequence[RequiredRef]) -> list[str]:
    """Section 4 of a change item: one line per ref, the name only when it is confirmed."""
    if not item.requires_refs:
        return [NONE_TEXT]
    lines: list[str] = []
    for position, ref in enumerate(item.requires_refs, 1):
        value = UNCONFIRMED_REF_TEXT if ref in unconfirmed else _code(ref.name)
        lines.append(f"- 参照 {position}（{ref.repo} の{_REF_KIND_LABELS[ref.kind]}）: {value}")
    if unconfirmed:
        lines += ["", "未確定の参照があるうちは着手せず、停止して保守者に報告する。参照の値を推測して書かない。"]
    return lines


def _dependencies_section(item: Item, by_id: Mapping[str, Item], providers: Sequence[str]) -> list[str]:
    """Section 5: each dependency with its repository, marking those that confirm a ref."""
    if not item.depends_on:
        return [NONE_TEXT]
    lines: list[str] = []
    for dependency in item.depends_on:
        line = f"- {_code(dependency)}（{by_id[dependency].repo}）"
        if dependency in providers:
            line += ": 4 節の未確定の参照を確定させる Handoff"
        lines.append(line)
    return lines


def _checks_section(item: Item, places: _Places) -> list[str]:
    """Section 6: the checks before starting, and the commands of the manual mode."""
    main = _shell_path(places.main_tree)
    worktree = _shell_path(places.worktree)
    lead = (
        "1. `git branch --show-current` と `git status --porcelain` を読む。cwd が、この依頼を渡した "
        f"Handoff_Harness の作った worktree {_code(places.worktree)} で、"
    )
    if item.mode == "query":
        steps = [
            lead + "ブランチを持たない（`git branch --show-current` が何も表示しない）ことを確かめる。"
            "違えば何もせずに停止して保守者に報告する",
            "2. 照会モードではファイルを作成・変更・削除しない。worktree に未コミットの変更があれば、"
            "何もせずに停止して保守者に報告する",
        ]
        add = f"git -C {main} worktree add --detach {worktree} <sha>"
    else:
        steps = [
            lead
            + f"ブランチが {_code(_branch(item))} であることを確かめる。違えば何も変更せずに停止して保守者に報告する",
            "2. 3 節の一覧のファイルに未コミットの変更があれば、何も変更せずに停止して保守者に報告する",
        ]
        add = f"git -C {main} worktree add -b {_branch(item)} {worktree} <sha>"
    return [
        *steps,
        f"3. メインの作業ツリー {_code(places.main_tree)} の `AGENTS.md`、`.kiro/steering/`、`.private/` の"
        "該当箇所を読み取りだけで参照する。worktree へ写さない",
        "",
        "手作業のモードで渡す場合は、手順 1 の前に、保守者が次のコマンドで worktree を作る。`<sha>` には、"
        "2 行目が表示した SHA が 3 行目の表示と一致したときの値を書く。一致しなければ 1 行目からやり直す。",
        "",
        "```sh",
        f"git -C {main} fetch --no-tags origin main",
        f"git -C {main} ls-remote origin refs/heads/main",
        f"git -C {main} rev-parse refs/remotes/origin/main",
        add,
        "```",
    ]


def _completion_section(item: Item, completion: Sequence[str] | None) -> list[str]:
    """Section 7 of a change item: the observable conditions, then the template's own."""
    lines = [
        "次のすべてが観測できる状態になったら完了とする。",
        "",
        f"1. 引き継ぎ用ブランチ {_code(_branch(item))} に、この作業の commit が 1 件以上ある"
        "（`git log origin/main..HEAD`）",
        "2. 変更したファイルがすべて 3 節の一覧に含まれる（`git diff --name-only origin/main...HEAD`）",
        "3. `git status --porcelain` が何も表示しない（commit していない変更が残っていない）",
    ]
    if item.verify_commands:
        lines.append(
            "4. 8 節の各検証コマンドが worktree で終了コード 0 で終わる。8 節の注意に従って実行しなかったコマンドは、"
            "その理由を報告している"
        )
    lines += ["", "PR と CI の確認は、公開の後に Handoff_Harness が行う。push と PR の作成はしない（11 節）。"]
    if completion:
        lines += ["", "この項目に固有の条件は次のとおり。", "", *completion]
    return lines


def _verification_section(item: Item) -> list[str]:
    """Section 8 of a change item: the verification commands, with a note on those not re-run."""
    if not item.verify_commands:
        return [NONE_TEXT]
    lines = ["worktree で次のコマンドを実行し、それぞれの終了コードを報告する。", ""]
    for command in item.verify_commands:
        line = f"- {_code(shlex.join(command.cmd))}"
        if rerun_skip_reason(command) is not None:
            line += "（AWS への呼び出しかリモートへの書き込みを含みうる。11 節の操作に当たる場合は実行せず、その旨を報告する）"
        lines.append(line)
    return lines


def _publication_section(query: bool) -> list[str]:
    """Section 9: what stays out of commits, PR text, files and answers."""
    exclusions = "、".join(PUBLIC_OUTPUT_EXCLUSIONS)
    if query:
        return [
            f"このモードでは commit、PR、ファイルを作らない。答えに、{exclusions}を書かない。"
            "記録にそれらが含まれる場合は、値を写さずに記録のパスだけを挙げる。"
        ]
    placeholders = "、".join(_code(placeholder) for placeholder in PLACEHOLDERS)
    return [
        f"commit メッセージ、PR タイトル、PR 本文、ファイルの内容に、{exclusions}を入れない。"
        f"例が要る場合はプレースホルダ（{placeholders}）を使う。"
    ]


def _executor_section(choice: ExecutorChoice) -> list[str]:
    """Section 10: the executor, and every row of the executor table that applies, with its details.

    The conditions are the table's second column verbatim, written from the side that passes
    the prompt on. A sentence before them says so, since "this repository" and "this session"
    would otherwise read as the receiver's own.
    """
    lines = [
        f"実行者: {choice.executor.label}{_EXECUTOR_NOTES[choice.executor]}",
        "",
        "実行者の判定の表で当たった行は次のとおり。表の文言の「このリポジトリ」と「このセッション」は、"
        "この依頼を渡した側のリポジトリとセッションを指す。",
        "",
    ]
    for reason in choice.reasons:
        lines.append(f"- 行 {reason.number}: {reason.condition}。{reason.detail_label}:")
        lines.extend(f"  - {_detail(reason, entry)}" for entry in reason.details)
    return lines


def _detail(reason: Reason, entry: str) -> str:
    """Write one detail of a reason: a code span for paths and names, plain text otherwise."""
    return _code(entry) if reason.number in _CODE_DETAIL_ROWS else entry


def _forbidden_section(item: Item, places: _Places) -> list[str]:
    """Section 11: the operations not to perform, and how far changes may go."""
    operations = "、".join(FORBIDDEN_OPERATIONS) + "をしない。"
    main = _code(places.main_tree)
    if item.mode == "query":
        return [
            f"{operations}照会モードではファイルを作成・変更・削除せず、commit もしない。メインの作業ツリー {main} も読むだけにする。"
        ]
    lines = [
        f"{operations}変更は worktree の引き継ぎ用ブランチ {_code(_branch(item))} への commit だけにする。"
        f"メインの作業ツリー {main} のファイルを作成・変更・削除しない。"
    ]
    if item.trust_all is not None:
        lines += [
            "",
            "この項目は、確認なしにすべてのツールを使える設定（`--trust-all-tools`）で起動する。"
            f"その場合も上の操作はしない。起動する理由: {item.trust_all.reason}",
        ]
    return lines


def _answer_section() -> list[str]:
    """Section 13 of a query item: how to answer."""
    return [
        f"- {QUERY_ANSWER_INSTRUCTION}",
        "- 問いごとに、問いの番号を付けて答える。該当する記録がない問いには「該当なし」と答える",
        "- 記録で確かめられないことは、確かめていないと書く。推測で埋めない",
        "- 答えは標準出力に書き、ファイルに書き込まない",
    ]


def _check_outline(lines: Sequence[str], expected: Sequence[str]) -> None:
    """Confirm that the level-1 and level-2 headings of the drawn body are the drawn ones.

    The slot checks make this hold; this catches a drawing that leaves a fence open or a
    check that missed a line.

    Raises:
        AssertionError: The headings outside code fences differ from ``expected``, or a
            fence is left open.
    """
    outside, open_fence = _fence_map(lines)
    found = [
        line
        for line, is_text in zip(lines, outside, strict=True)
        if is_text and (level := _heading_level(line)) is not None and level <= 2
    ]
    if found != list(expected) or open_fence is not None:
        raise AssertionError("the outline of the drawn body differs from its sections")


def _branch(item: Item) -> str:
    """The handoff branch of a change item: ``handoff/<id>``."""
    return f"handoff/{item.id}"


def _code(text: str) -> str:
    """Write a non-empty text as a Markdown code span that shows it unchanged.

    The span is delimited by one backtick more than the longest run inside the text, and
    padded with a space when the text starts or ends with a backtick or a space, which the
    span would otherwise join to the delimiter or strip (CommonMark, code spans).
    """
    longest = max((len(run) for run in _BACKTICKS.findall(text)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if text[:1] in ("`", " ") or text[-1:] in ("`", " ") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def _shell_path(path: str) -> str:
    """Write a ``~/...`` path as a shell word in which ``~`` still expands."""
    return path if path == "~" else "~/" + shlex.quote(path[2:])


def _var_where(key: str) -> str:
    """Name a template variable for :attr:`PromptIssue.where`."""
    return f"vars.{key}" if _PLAIN_VAR.fullmatch(key) else f"vars[{json.dumps(key, ensure_ascii=False)}]"


def _json_type(value: object) -> str:
    """The JSON name of a value's type, for an issue detail. The value itself is not shown."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, Mapping):
        return "an object"
    if isinstance(value, (list, tuple)):
        return "an array"
    return type(value).__name__


def _encodable(text: str) -> bool:
    """Whether a string encodes as UTF-8, that is, holds no lone surrogate."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True

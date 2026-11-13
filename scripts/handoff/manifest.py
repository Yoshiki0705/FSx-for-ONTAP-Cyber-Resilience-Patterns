"""Check the Handoff_Harness manifest (``.private/handoff/manifest.json``).

Part of the pure core described in ``scripts/handoff/__init__.py``: this module reads no
file. The I/O layer reads and decodes ``manifest.json`` and passes the decoded value to
:func:`parse_manifest`, together with the configuration that
:func:`handoff.config.parse_config` returned. The items are checked against that
configuration: their repositories and the tool ceiling of their mode come from it. When
:func:`parse_manifest` raises :class:`ManifestError`, no item is started.

Shape (design section 20 and Data Models; Requirements 23.2, 28.3, 28.4, 28.7, 28.12 and
28.14):

- The top level is ``{"schema_version": 1, "items": [<item>, ...]}``. ``items`` may be
  empty. ``schema_version`` lets a later format be refused instead of misread, as in
  ``config.json`` and ``status.json``.
- An item has exactly the keys of :data:`ITEM_KEYS`. Every key is required and none has a
  default, as in ``config.json``: an empty list or ``null`` is written out. The first 13 are
  the keys of the design's example item. ``gates``, ``knowledge_kinds``, ``read_paths`` and
  ``artifact_paths`` were added for rows 2, 4, 5 and 6 of the executor table (see
  :meth:`Item.executor_attrs`). :class:`Item` gives the rule of each key.
- A key that this module does not read is reported as ``unknown_key``.
- Across items: an ID appears once; ``depends_on`` names IDs of the manifest; the
  dependencies form no cycle, and an item that depends on itself is a cycle; an item that
  requires a ref of another repository depends directly on an item of that repository.
- An item to which no row of the executor table applies is rejected (Property 29). The
  check passes 0 as the uncommitted count, since nothing has been observed before a run.
- Every problem is collected and raised together in one :class:`ManifestError`, in a fixed
  order: for each item in turn, its missing keys, the problems of its keys in the order of
  :data:`ITEM_KEYS`, its unknown keys and the executor table; then the cycles; then the
  unknown top-level keys.

Relative paths (``template``, ``declared_files``, ``read_paths``, ``artifact_paths`` and
``trust_all.approved_in``) must be in normal form: not blank, one line without NUL, not
starting with ``/`` or ``~``, and with no component that is empty, ``.`` or ``..``. A
declared file is then written the way ``git diff --name-only`` prints a changed file, so the
result check can compare the two as strings, and no path can leave, lexically, the
directory it is relative to.

The verification commands that the harness never re-runs, even when declared offline, are
described in :func:`rerun_exclusions`.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Final, Literal, TypeVar

from handoff.config import MODES, HandoffConfig
from handoff.executor import ExecutorAttrs, ExecutorError, choose
from handoff.state import TIMESTAMP_FORMAT, format_timestamp

#: The only ``schema_version`` this module reads.
SCHEMA_VERSION: Final = 1

#: The values of ``sync_point``: the five Sync_Points of Requirement 28.1, and ``rollout``
#: for the per-repository Handoff_Prompts of Requirement 23.1.
SYNC_POINTS: Final[tuple[str, ...]] = ("a", "b", "c", "d", "e", "rollout")

#: Every top-level key. Both are required.
TOP_KEYS: Final[tuple[str, ...]] = ("schema_version", "items")

#: Every key of an item, in the order its problems are reported. All are required.
ITEM_KEYS: Final[tuple[str, ...]] = (
    "id",
    "repo",
    "sync_point",
    "mode",
    "template",
    "vars",
    "depends_on",
    "requires_refs",
    "trust_tools",
    "trust_all",
    "declared_files",
    "verify_commands",
    "batch",
    "gates",
    "knowledge_kinds",
    "read_paths",
    "artifact_paths",
)

#: Every key of an entry of ``requires_refs``. All are required.
REF_KEYS: Final[tuple[str, ...]] = ("repo", "kind", "name")

#: The values of ``requires_refs[].kind``.
REF_KINDS: Final[tuple[str, ...]] = ("tag", "sha")

#: Every key of a non-null ``trust_all``. All are required.
TRUST_ALL_KEYS: Final[tuple[str, ...]] = ("reason", "approved_at", "approved_in")

#: Every key of an entry of ``verify_commands``. Both are required.
VERIFY_KEYS: Final[tuple[str, ...]] = ("cmd", "offline")

#: Longest item ID and batch label. It keeps ``handoff/<id>`` and
#: ``<worktrees_root>/<repo>/<id>`` short, far below the 255-byte file name limit of
#: common file systems.
MAX_ID_LENGTH: Final = 64

#: Where ``trust_all.approved_in`` must point: this session's records, which this
#: repository keeps under the gitignored ``.private/``.
APPROVAL_RECORD_DIR: Final = ".private/"

#: The patterns of design section 20 ("結果の確認", step 6), as written there. A
#: verification command that matches one is never re-run (:func:`rerun_exclusions`).
RERUN_EXCLUDED_PATTERNS: Final[tuple[str, ...]] = ("aws ", "gh ", "git push", "deploy")

IssueKind = Literal[
    "missing",
    "type",
    "range",
    "format",
    "unknown_key",
    "duplicate",
    "unknown_reference",
    "cycle",
    "ceiling",
    "mode",
    "ordering",
    "executor",
]

_T = TypeVar("_T")

#: Stands for a key that is absent, so that ``null`` stays a value of its own.
_MISSING: Any = object()

_PLAIN_KEY: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_SLUG: Final = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_REPO: Final = re.compile(r"[A-Za-z0-9._-]+")
_SHA: Final = re.compile(r"[0-9a-f]{40}")
_TAG: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
_WORD: Final = re.compile(r"[0-9a-z_]+")

_SLUG_RULE: Final = (
    "must be lowercase ASCII letters and digits in groups joined by single hyphens, "
    f"at most {MAX_ID_LENGTH} characters"
)


@dataclass(frozen=True, slots=True)
class ManifestIssue:
    """One problem in the manifest.

    Attributes:
        path: Where the problem is, written like :attr:`handoff.config.ConfigIssue.path`:
            keys joined with ``.``, list indices in brackets. Examples: ``items``,
            ``items[3].trust_tools``, ``items[0].requires_refs[1].name``. ``$`` is the
            manifest as a whole.
        kind: ``missing`` (a required key is absent), ``type`` (the JSON type is wrong),
            ``range`` (an unsupported ``schema_version``), ``format`` (the type is right and
            the shape is not), ``unknown_key`` (a key this module does not read),
            ``duplicate`` (an ID or a list entry given twice), ``unknown_reference`` (a
            dependency that is not an item of the manifest, or a repository that is not in
            the configuration), ``cycle`` (the dependencies form a cycle), ``ceiling`` (a
            trusted tool outside the ceiling of the item's mode), ``mode`` (a value the
            item's mode requires or forbids), ``ordering`` (a ref of another repository
            without a dependency on an item of that repository) or ``executor`` (no row of
            the executor table applies).
        detail: An explanation for the maintainer. It can repeat values of the manifest,
            so it belongs in local output, not in a tracked file.
    """

    path: str
    kind: IssueKind
    detail: str

    def __str__(self) -> str:
        """Render the issue as one line: ``<path>: <kind>: <detail>``."""
        return f"{self.path}: {self.kind}: {self.detail}"


class ManifestError(ValueError):
    """The manifest was rejected.

    Attributes:
        issues: Every problem found, not only the first, in the order given in the module
            docstring: the same manifest and configuration always give the same list.
    """

    def __init__(self, issues: Sequence[ManifestIssue]) -> None:
        """Keep the issues and use one line per issue as the message.

        Args:
            issues: One or more problems.
        """
        self.issues: tuple[ManifestIssue, ...] = tuple(issues)
        super().__init__("\n".join(str(issue) for issue in self.issues))


@dataclass(frozen=True, slots=True)
class RequiredRef:
    """A ref that must be confirmed on a repository's default branch before an item starts.

    Attributes:
        repo: A key of ``repos`` in the configuration.
        kind: ``tag`` or ``sha``.
        name: For ``sha``, 40 lowercase hexadecimal digits. For ``tag``, a name that starts
            with an ASCII letter or digit, so that it cannot be read as an option in an argv,
            holds only ASCII letters, digits, ``.``, ``_``, ``-`` and ``/``, and follows the
            rules of ``git check-ref-format`` that concern those characters: no ``..`` or
            ``//``, no component that starts with ``.`` or ends with ``.lock``, and no ``/``
            or ``.`` at the end.
    """

    repo: str
    kind: str
    name: str


@dataclass(frozen=True, slots=True)
class TrustAll:
    """The approval to start one item with ``--trust-all-tools`` (Requirement 28.7).

    Attributes:
        reason: Why the item needs every tool. One non-blank line; the Handoff_Prompt
            states it.
        approved_at: When the maintainer approved it, in
            :data:`handoff.state.TIMESTAMP_FORMAT` (UTC, whole seconds, ``Z``), the form of
            the timestamps in ``status.json``.
        approved_in: The record of this session that holds the approval: a path relative to
            this repository, in normal form, under :data:`APPROVAL_RECORD_DIR`.
    """

    reason: str
    approved_at: str
    approved_in: str


@dataclass(frozen=True, slots=True)
class VerifyCommand:
    """One verification command of section 8 of a Handoff_Prompt.

    Attributes:
        cmd: The argv: one element or more, each a non-empty line without NUL. It runs with
            ``shell=False``; a shell string is refused.
        offline: Whether the command makes no AWS call and no write to a remote, as judged
            from the target repository's ``origin/main`` when the item was written. Only
            ``true`` and ``false`` are accepted. The harness re-runs the command only when
            :func:`rerun_skip_reason` returns ``None``.
    """

    cmd: tuple[str, ...]
    offline: bool


@dataclass(frozen=True, slots=True)
class Item:
    """One Handoff item that passed every check of :func:`parse_manifest`.

    Attributes:
        id: Lowercase ASCII letters and digits in groups joined by single hyphens, at most
            :data:`MAX_ID_LENGTH` characters, unique in the manifest. It becomes the last
            component of ``<worktrees_root>/<repo>/<id>``, the branch ``handoff/<id>``, a key
            of ``status.json`` and an entry of the comma-separated ``--items`` list. Upper
            case is refused because a case-insensitive file system, the default on macOS,
            would map two IDs that differ only in case to one worktree directory.
        repo: The target repository: a key of ``repos`` in the configuration, and one path
            component (ASCII letters, digits, ``.``, ``_`` and ``-``; not ``.`` or ``..``),
            because the harness builds ``<worktrees_root>/<repo>/<id>`` and
            ``.private/handoff/<repo>/<id>/`` from it.
        sync_point: One of :data:`SYNC_POINTS`.
        mode: ``query`` or ``change`` (:data:`handoff.config.MODES`).
        template: The template, relative to ``.private/handoff/``, in normal form.
        vars: The template variables: an object with non-empty string keys. The values are
            left to ``prompt.render``. Stored read-only at every depth: objects become
            read-only mappings and arrays become tuples.
        depends_on: IDs of other items of the manifest that must succeed first (Requirement
            28.12), each once, in the order written.
        requires_refs: Refs that must be confirmed on their repository's default branch
            first (IN-2), each once. For a ref of another repository, ``depends_on`` names an
            item of that repository: ``dag.ready`` waits for both (Requirement 28.12), and
            ``prompt.render`` names that item while the ref is unconfirmed (Requirement
            23.5). Empty for a query item: section 4 of a query prompt does not apply.
        trust_tools: The tools for ``--trust-tools``: at least one (with none, ``kiro-cli``
            trusts no tool), each once, all in the ceiling of the item's mode. For a query
            item that is exactly ``("fs_read",)``.
        trust_all: ``None``, or the approval of ``--trust-all-tools`` with all three of its
            parts. Always ``None`` for a query item, since the query mode trusts
            ``fs_read`` only.
        declared_files: Files of the target repository that the item creates or changes, in
            normal form, each once. At least one for a change item. None for a query item,
            which writes nothing.
        verify_commands: The verification commands, each argv once. None for a query item:
            section 8 of a query prompt does not apply. A change item may have none; how a
            CI job of a repository without a Makefile is written here is not decided yet.
        batch: ``None``, or a label in the form of an ID, such as ``pilot`` or ``batch-1``.
        gates: Names of the target repository's rules and gates that the work follows in
            addition to the verification commands, such as ``AGENTS.md``. One non-blank line
            each, each once.
        knowledge_kinds: Kinds of knowledge that only the target repository has and that
            the item needs, such as its ``.private/`` records. One non-blank line each, each
            once.
        read_paths: Paths whose committed content the item reads with
            ``git show origin/main:<path>``, in normal form, each once.
        artifact_paths: Paths of the artifacts the item leaves in this repository, such as
            its Handoff_Prompt, in normal form, each once.
    """

    id: str
    repo: str
    sync_point: str
    mode: str
    template: str
    vars: Mapping[str, Any]
    depends_on: tuple[str, ...]
    requires_refs: tuple[RequiredRef, ...]
    trust_tools: tuple[str, ...]
    trust_all: TrustAll | None
    declared_files: tuple[str, ...]
    verify_commands: tuple[VerifyCommand, ...]
    batch: str | None
    gates: tuple[str, ...]
    knowledge_kinds: tuple[str, ...]
    read_paths: tuple[str, ...]
    artifact_paths: tuple[str, ...]

    def executor_attrs(self, *, uncommitted_count: int) -> ExecutorAttrs:
        """Map the item onto the rows of the executor table (design section 20).

        - Row 1, ``changed_paths``: ``declared_files``.
        - Row 2, ``gates``: ``gates``, then each verification command as
          ``shlex.join(cmd)``, such as ``make all``. The verification commands count
          because the condition of row 2 includes running them. ``shlex.join`` writes an
          argv the way a person would type it, with quotes where an element needs them.
        - Row 3, ``uncommitted_count``: the argument.
        - Row 4, ``knowledge_kinds``: ``knowledge_kinds``.
        - Row 5, ``read_paths``: ``read_paths``.
        - Row 6, ``artifact_paths``: ``artifact_paths``.

        Args:
            uncommitted_count: The number of lines that ``git status --porcelain`` printed
                for the target repository's main working tree. It has no default: pass
                what was observed before the prompt is rendered, so that row 3 appears when
                it applies. :func:`parse_manifest` passes 0, since it runs before any
                observation.

        Returns:
            The attributes for :func:`handoff.executor.choose`.

        Raises:
            handoff.executor.ExecutorError: ``uncommitted_count`` is not an integer of 0 or
                more.
        """
        return _executor_attrs(
            declared_files=self.declared_files,
            gates=self.gates,
            verify_commands=self.verify_commands,
            knowledge_kinds=self.knowledge_kinds,
            read_paths=self.read_paths,
            artifact_paths=self.artifact_paths,
            uncommitted_count=uncommitted_count,
        )


@dataclass(frozen=True, slots=True)
class Manifest:
    """A manifest that passed every check.

    Attributes:
        schema_version: Always :data:`SCHEMA_VERSION`.
        items: The items in the order of the manifest.
    """

    schema_version: int
    items: tuple[Item, ...]

    @property
    def by_id(self) -> Mapping[str, Item]:
        """The items by ID, as a read-only mapping."""
        return MappingProxyType({item.id: item for item in self.items})


@dataclass(frozen=True, slots=True)
class _Context:
    """What the check of one item needs to know about the others.

    Attributes:
        config: The checked configuration.
        first_index: Each string found as an ``id``, mapped to the index of the first item
            that has it.
        repo_by_id: Each of those IDs, mapped to the ``repo`` value of that first item, as
            written (it may be invalid or absent).
    """

    config: HandoffConfig
    first_index: Mapping[str, int]
    repo_by_id: Mapping[str, object]


def parse_manifest(raw: Any, *, config: HandoffConfig) -> Manifest:
    """Check a decoded ``manifest.json`` against the configuration.

    Args:
        raw: The decoded JSON value. A value that is not a mapping is rejected.
        config: The configuration that :func:`handoff.config.parse_config` returned.

    Returns:
        The checked manifest.

    Raises:
        ManifestError: The manifest has one or more problems, all of them in ``issues``.
        TypeError: ``config`` is not a :class:`handoff.config.HandoffConfig`. This is a
            fault of the caller, not of the manifest.
    """
    if not isinstance(config, HandoffConfig):
        raise TypeError(f"config must be a HandoffConfig from parse_config, not {type(config).__name__}")
    if not isinstance(raw, Mapping):
        raise ManifestError([ManifestIssue("$", "type", f"must be a JSON object, got {_describe(raw)}")])

    issues: list[ManifestIssue] = []
    schema_version = _schema_version(_take(raw, ("schema_version",), issues), issues)
    raw_items = _array(_take(raw, ("items",), issues), ("items",), issues)
    items: list[Item] = []
    if raw_items is not None:
        context = _context(raw_items, config)
        for index, value in enumerate(raw_items):
            item = _check_item(index, value, context, issues)
            if item is not None:
                items.append(item)
        issues.extend(_cycle_issues(raw_items, context))
    issues.extend(_unknown_keys(raw, TOP_KEYS, ()))

    if issues:
        raise ManifestError(issues)
    return Manifest(schema_version=_present(schema_version), items=tuple(items))


def rerun_exclusions(cmd: Sequence[str]) -> tuple[str, ...]:
    """Tell which patterns of :data:`RERUN_EXCLUDED_PATTERNS` a verification command matches.

    The design never re-runs a command that contains ``"aws "``, ``"gh "``, ``"git push"``
    or ``"deploy"`` (the first two end with a space), even when it is declared
    ``offline: true`` (section 20, "結果の確認", step 6). Matching the joined argv alone
    would miss ``["aws"]``, which has no space after the name, and
    ``["git", "-C", "<dir>", "push"]``. Two tests are therefore combined. Both read the argv
    with its elements joined by single spaces and case-folded, since a case-insensitive file
    system, the default on macOS, can start ``aws`` for ``AWS``:

    - The text contains the pattern as written, trailing space included. This keeps every
      match of the design's rule.
    - A word of the text is ``aws`` (for ``"aws "``) or ``gh`` (for ``"gh "``), or the words
      include both ``git`` and ``push``, in any order (for ``"git push"``). A word is a run
      of ASCII letters, digits and ``_``: ``/usr/local/bin/aws``, ``aws-vault`` and ``x;gh``
      give the word, ``AWS_PROFILE=dev`` does not. ``"deploy"`` needs no word test, since
      the text test finds it inside any word.

    False positives are accepted: a command that is not re-run only has its reason recorded.
    For example, ``high and low`` contains ``"gh "``, ``flaws in`` contains ``"aws "``, and
    ``git status; echo push`` holds both words.

    Limits: only the argv is read. What a Makefile target, a script or an alias runs is not
    visible: ``make all`` may call AWS inside. For such commands the ``offline`` flag
    decides, and it is set when the item is written, by reading the target repository's
    Makefile on ``origin/main`` (design section 17). Other remote writes, such as
    ``docker push``, ``npm publish`` or ``curl -X POST``, are not matched either.

    Args:
        cmd: The argv of the command.

    Returns:
        The matched patterns, in the order of :data:`RERUN_EXCLUDED_PATTERNS`. Empty when
        none matches.

    Raises:
        TypeError: ``cmd`` is a ``str``, which would be read one character at a time, or it
            holds an element that is not a ``str``.
    """
    if isinstance(cmd, (str, bytes)) or not isinstance(cmd, Sequence):
        raise TypeError("cmd must be an argv, a sequence of str, not a single string")
    elements = list(cmd)
    if not all(isinstance(element, str) for element in elements):
        raise TypeError("every element of cmd must be a str")
    text = " ".join(elements).casefold()
    words = set(_WORD.findall(text))
    matched: list[str] = []
    if "aws " in text or "aws" in words:
        matched.append("aws ")
    if "gh " in text or "gh" in words:
        matched.append("gh ")
    if "git push" in text or {"git", "push"} <= words:
        matched.append("git push")
    if "deploy" in text:
        matched.append("deploy")
    return tuple(matched)


def rerun_skip_reason(command: VerifyCommand) -> str | None:
    """Tell why the harness must not re-run a verification command, or that it may.

    Args:
        command: A verification command of an item.

    Returns:
        ``None`` when the command is declared ``offline: true`` and matches no pattern of
        :func:`rerun_exclusions`: the harness re-runs it in the worktree. Otherwise the
        reason to record in ``rerun_skipped`` of ``status.json`` (Requirement 28.9).
    """
    if not command.offline:
        return "declared offline: false, so it may call AWS or write to a remote"
    matched = rerun_exclusions(command.cmd)
    if matched:
        listed = ", ".join(repr(pattern) for pattern in matched)
        return f"matches {listed}; a command like this is never re-run, even when declared offline"
    return None


def _executor_attrs(
    *,
    declared_files: tuple[str, ...],
    gates: tuple[str, ...],
    verify_commands: tuple[VerifyCommand, ...],
    knowledge_kinds: tuple[str, ...],
    read_paths: tuple[str, ...],
    artifact_paths: tuple[str, ...],
    uncommitted_count: int,
) -> ExecutorAttrs:
    """Build the executor attributes as the table in :meth:`Item.executor_attrs` shows."""
    return ExecutorAttrs(
        changed_paths=declared_files,
        gates=(*gates, *(shlex.join(command.cmd) for command in verify_commands)),
        uncommitted_count=uncommitted_count,
        knowledge_kinds=knowledge_kinds,
        read_paths=read_paths,
        artifact_paths=artifact_paths,
    )


def _context(raw_items: Sequence[Any], config: HandoffConfig) -> _Context:
    """Collect the IDs of the manifest before any item is checked.

    Args:
        raw_items: The ``items`` array as written.
        config: The checked configuration.

    Returns:
        The first index and the ``repo`` value of every string ID.
    """
    first_index: dict[str, int] = {}
    repo_by_id: dict[str, object] = {}
    for index, value in enumerate(raw_items):
        if not isinstance(value, Mapping):
            continue
        item_id = value.get("id")
        if isinstance(item_id, str) and item_id not in first_index:
            first_index[item_id] = index
            repo_by_id[item_id] = value.get("repo")
    return _Context(config, MappingProxyType(first_index), MappingProxyType(repo_by_id))


def _check_item(index: int, value: Any, context: _Context, issues: list[ManifestIssue]) -> Item | None:
    """Check one item and return it, or record its problems and return ``None``.

    Args:
        index: The position of the item in ``items``.
        value: The item as written.
        context: The IDs of the manifest and the configuration.
        issues: Where problems are recorded.

    Returns:
        The item when it has no problem, otherwise ``None``.
    """
    where: tuple[str | int, ...] = ("items", index)
    if not isinstance(value, Mapping):
        issues.append(ManifestIssue(_key_path(*where), "type", f"must be an object, got {_describe(value)}"))
        return None
    before = len(issues)
    found = {key: _take(value, (*where, key), issues) for key in ITEM_KEYS}

    item_id = _item_id(found["id"], index, context, issues)
    repo = _repo(found["repo"], (*where, "repo"), context.config, issues)
    sync_point = _one_of(found["sync_point"], (*where, "sync_point"), SYNC_POINTS, issues)
    mode = _one_of(found["mode"], (*where, "mode"), MODES, issues)
    template = _path(found["template"], (*where, "template"), issues)
    item_vars = _vars(found["vars"], (*where, "vars"), issues)
    depends_on = _depends_on(found["depends_on"], (*where, "depends_on"), context, issues)
    requires_refs = _requires_refs(
        found["requires_refs"], (*where, "requires_refs"), mode, repo, depends_on, context, issues
    )
    trust_tools = _trust_tools(found["trust_tools"], (*where, "trust_tools"), mode, context.config, issues)
    trust_all = _trust_all(found["trust_all"], (*where, "trust_all"), mode, issues)
    declared_files = _declared_files(found["declared_files"], (*where, "declared_files"), mode, issues)
    verify_commands = _verify_commands(found["verify_commands"], (*where, "verify_commands"), mode, issues)
    batch = _batch(found["batch"], (*where, "batch"), issues)
    gates = _entries(found["gates"], (*where, "gates"), _line_problem, issues)
    knowledge_kinds = _entries(found["knowledge_kinds"], (*where, "knowledge_kinds"), _line_problem, issues)
    read_paths = _entries(found["read_paths"], (*where, "read_paths"), _path_problem, issues)
    artifact_paths = _entries(found["artifact_paths"], (*where, "artifact_paths"), _path_problem, issues)
    issues.extend(_unknown_keys(value, ITEM_KEYS, where))

    if (
        declared_files is not None
        and gates is not None
        and verify_commands is not None
        and knowledge_kinds is not None
        and read_paths is not None
        and artifact_paths is not None
    ):
        try:
            choose(
                _executor_attrs(
                    declared_files=declared_files,
                    gates=gates,
                    verify_commands=verify_commands,
                    knowledge_kinds=knowledge_kinds,
                    read_paths=read_paths,
                    artifact_paths=artifact_paths,
                    uncommitted_count=0,
                )
            )
        except ExecutorError as exc:
            issues.append(
                ManifestIssue(
                    _key_path(*where),
                    "executor",
                    f"{exc}; give the item declared_files, gates, verify_commands, knowledge_kinds, read_paths "
                    "or artifact_paths",
                )
            )

    if len(issues) > before:
        return None
    return Item(
        id=_present(item_id),
        repo=_present(repo),
        sync_point=_present(sync_point),
        mode=_present(mode),
        template=_present(template),
        vars=_present(item_vars),
        depends_on=_present(depends_on),
        requires_refs=_present(requires_refs),
        trust_tools=_present(trust_tools),
        trust_all=trust_all,
        declared_files=_present(declared_files),
        verify_commands=_present(verify_commands),
        batch=batch,
        gates=_present(gates),
        knowledge_kinds=_present(knowledge_kinds),
        read_paths=_present(read_paths),
        artifact_paths=_present(artifact_paths),
    )


def _schema_version(value: Any, issues: list[ManifestIssue]) -> int | None:
    """Check ``schema_version``: the integer :data:`SCHEMA_VERSION`, not ``true``."""
    if value is _MISSING:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        issues.append(ManifestIssue("schema_version", "type", f"must be an integer, got {_describe(value)}"))
        return None
    if value != SCHEMA_VERSION:
        issues.append(ManifestIssue("schema_version", "range", f"only {SCHEMA_VERSION} is supported, got {value}"))
        return None
    return value


def _item_id(value: Any, index: int, context: _Context, issues: list[ManifestIssue]) -> str | None:
    """Check ``id``: its form, and that no earlier item has it."""
    where = ("items", index, "id")
    item_id = _string(value, where, issues)
    if item_id is None:
        return None
    if len(item_id) > MAX_ID_LENGTH or not _SLUG.fullmatch(item_id):
        issues.append(
            ManifestIssue(
                _key_path(*where), "format", f"{_SLUG_RULE}: it names a directory, a branch and an entry of --items"
            )
        )
        return None
    first = context.first_index[item_id]
    if first != index:
        issues.append(ManifestIssue(_key_path(*where), "duplicate", f"repeats the ID of items[{first}]"))
        return None
    return item_id


def _repo(value: Any, where: tuple[str | int, ...], config: HandoffConfig, issues: list[ManifestIssue]) -> str | None:
    """Check ``repo``: one path component, and a key of ``repos`` in the configuration."""
    repo = _string(value, where, issues)
    if repo is None:
        return None
    if repo in (".", "..") or not _REPO.fullmatch(repo):
        issues.append(
            ManifestIssue(
                _key_path(*where),
                "format",
                "must be one path component of ASCII letters, digits, '.', '_' and '-', not '.' or '..'",
            )
        )
        return None
    if repo not in config.repos:
        issues.append(ManifestIssue(_key_path(*where), "unknown_reference", f"{repo} is not in repos of config.json"))
        return None
    return repo


def _one_of(
    value: Any, where: tuple[str | int, ...], allowed: tuple[str, ...], issues: list[ManifestIssue]
) -> str | None:
    """Check a string that must be one of ``allowed``."""
    text = _string(value, where, issues)
    if text is None:
        return None
    if text not in allowed:
        issues.append(
            ManifestIssue(_key_path(*where), "format", f"must be one of {', '.join(allowed)}, got {_describe(text)}")
        )
        return None
    return text


def _path(value: Any, where: tuple[str | int, ...], issues: list[ManifestIssue]) -> str | None:
    """Check a relative path in normal form."""
    path = _string(value, where, issues)
    if path is None:
        return None
    problem = _path_problem(path)
    if problem is not None:
        issues.append(ManifestIssue(_key_path(*where), "format", problem))
        return None
    return path


def _vars(value: Any, where: tuple[str | int, ...], issues: list[ManifestIssue]) -> Mapping[str, Any] | None:
    """Check ``vars``: an object with non-empty string keys. Return it read-only."""
    if value is _MISSING:
        return None
    if not isinstance(value, Mapping):
        issues.append(ManifestIssue(_key_path(*where), "type", f"must be an object, got {_describe(value)}"))
        return None
    bad = [key for key in value if not isinstance(key, str) or not key]
    for key in bad:
        issues.append(ManifestIssue(_key_path(*where), "format", f"the key {_describe(key)} is not a non-empty string"))
    if bad:
        return None
    frozen: Mapping[str, Any] = _frozen(value)
    return frozen


def _depends_on(
    value: Any, where: tuple[str | int, ...], context: _Context, issues: list[ManifestIssue]
) -> tuple[str, ...] | None:
    """Check ``depends_on``: IDs of the manifest, each once. Cycles are found later."""
    array = _array(value, where, issues)
    if array is None:
        return None
    before = len(issues)
    seen: dict[str, int] = {}
    for position, entry in enumerate(array):
        at = (*where, position)
        dependency = _string(entry, at, issues)
        if dependency is None:
            continue
        if dependency not in context.first_index:
            issues.append(
                ManifestIssue(
                    _key_path(*at), "unknown_reference", f"no item of the manifest has the ID {_describe(dependency)}"
                )
            )
        elif dependency in seen:
            issues.append(ManifestIssue(_key_path(*at), "duplicate", f"repeats {_key_path(*where, seen[dependency])}"))
        else:
            seen[dependency] = position
    return None if len(issues) > before else tuple(array)


def _requires_refs(
    value: Any,
    where: tuple[str | int, ...],
    mode: str | None,
    repo: str | None,
    depends_on: tuple[str, ...] | None,
    context: _Context,
    issues: list[ManifestIssue],
) -> tuple[RequiredRef, ...] | None:
    """Check ``requires_refs``: each entry, no repetition, the mode, and the dependency on its repository.

    The dependency is checked only when the item's ``repo`` and ``depends_on`` passed.
    """
    array = _array(value, where, issues)
    if array is None:
        return None
    if mode == "query" and array:
        issues.append(
            ManifestIssue(
                _key_path(*where), "mode", "must be empty for a query item: section 4 of a query prompt does not apply"
            )
        )
        return None
    before = len(issues)
    refs: list[RequiredRef] = []
    seen: dict[RequiredRef, int] = {}
    for position, entry in enumerate(array):
        at = (*where, position)
        ref = _required_ref(entry, at, context.config, issues)
        if ref is None:
            continue
        if ref in seen:
            issues.append(ManifestIssue(_key_path(*at), "duplicate", f"repeats {_key_path(*where, seen[ref])}"))
            continue
        seen[ref] = position
        unlinked = (
            repo is not None
            and depends_on is not None
            and ref.repo != repo
            and not any(context.repo_by_id.get(dependency) == ref.repo for dependency in depends_on)
        )
        if unlinked:
            issues.append(
                ManifestIssue(
                    _key_path(*at),
                    "ordering",
                    f"requires a ref of {ref.repo} but depends on no item of {ref.repo}; depend on the item that "
                    "makes the ref, so that it runs first and the prompt can name it (Requirements 23.5 and 28.12)",
                )
            )
            continue
        refs.append(ref)
    return None if len(issues) > before else tuple(refs)


def _required_ref(
    value: Any, where: tuple[str | int, ...], config: HandoffConfig, issues: list[ManifestIssue]
) -> RequiredRef | None:
    """Check one entry of ``requires_refs``."""
    if not isinstance(value, Mapping):
        issues.append(ManifestIssue(_key_path(*where), "type", f"must be an object, got {_describe(value)}"))
        return None
    before = len(issues)
    found = {key: _take(value, (*where, key), issues) for key in REF_KEYS}
    repo = _string(found["repo"], (*where, "repo"), issues)
    if repo is not None and repo not in config.repos:
        issues.append(
            ManifestIssue(_key_path(*where, "repo"), "unknown_reference", f"{repo} is not in repos of config.json")
        )
    kind = _one_of(found["kind"], (*where, "kind"), REF_KINDS, issues)
    name = _string(found["name"], (*where, "name"), issues)
    if name is not None and kind is not None:
        problem = _sha_problem(name) if kind == "sha" else _tag_problem(name)
        if problem is not None:
            issues.append(ManifestIssue(_key_path(*where, "name"), "format", problem))
    issues.extend(_unknown_keys(value, REF_KEYS, where))
    if len(issues) > before:
        return None
    return RequiredRef(repo=_present(repo), kind=_present(kind), name=_present(name))


def _trust_tools(
    value: Any, where: tuple[str | int, ...], mode: str | None, config: HandoffConfig, issues: list[ManifestIssue]
) -> tuple[str, ...] | None:
    """Check ``trust_tools``: at least one tool, each once, within the ceiling of the mode."""
    tools = _entries(value, where, _line_problem, issues)
    if tools is None:
        return None
    if not tools:
        issues.append(
            ManifestIssue(
                _key_path(*where), "format", "must name at least one tool: with none, kiro-cli trusts no tool"
            )
        )
        return None
    if mode is None:
        return tools
    ceiling = config.mode_tool_ceiling[mode]
    outside = [position for position, tool in enumerate(tools) if tool not in ceiling]
    for position in outside:
        issues.append(
            ManifestIssue(
                _key_path(*where, position),
                "ceiling",
                f"{tools[position]} is not in mode_tool_ceiling.{mode} of config.json ({', '.join(ceiling)})",
            )
        )
    return None if outside else tools


def _trust_all(
    value: Any, where: tuple[str | int, ...], mode: str | None, issues: list[ManifestIssue]
) -> TrustAll | None:
    """Check ``trust_all``: ``null``, or all of reason, approval time and approval record.

    Returns ``None`` both for ``null`` and for a rejected value; the caller tells them
    apart by the issues recorded.
    """
    if value is _MISSING or value is None:
        return None
    if not isinstance(value, Mapping):
        issues.append(ManifestIssue(_key_path(*where), "type", f"must be null or an object, got {_describe(value)}"))
        return None
    if mode == "query":
        issues.append(
            ManifestIssue(
                _key_path(*where), "mode", "must be null for a query item: the query mode trusts fs_read only"
            )
        )
        return None
    before = len(issues)
    found = {key: _take(value, (*where, key), issues) for key in TRUST_ALL_KEYS}
    reason = _string(found["reason"], (*where, "reason"), issues)
    if reason is not None and (problem := _line_problem(reason)) is not None:
        issues.append(ManifestIssue(_key_path(*where, "reason"), "format", problem))
    approved_at = _string(found["approved_at"], (*where, "approved_at"), issues)
    if approved_at is not None and not _is_timestamp(approved_at):
        issues.append(
            ManifestIssue(
                _key_path(*where, "approved_at"),
                "format",
                f"must be UTC in whole seconds, like 2026-11-10T00:00:00Z, got {_describe(approved_at)}",
            )
        )
    approved_in = _string(found["approved_in"], (*where, "approved_in"), issues)
    if approved_in is not None:
        problem = _path_problem(approved_in)
        if problem is None and not approved_in.startswith(APPROVAL_RECORD_DIR):
            problem = f"must be a record of this session under {APPROVAL_RECORD_DIR}"
        if problem is not None:
            issues.append(ManifestIssue(_key_path(*where, "approved_in"), "format", problem))
    issues.extend(_unknown_keys(value, TRUST_ALL_KEYS, where))
    if len(issues) > before:
        return None
    return TrustAll(reason=_present(reason), approved_at=_present(approved_at), approved_in=_present(approved_in))


def _declared_files(
    value: Any, where: tuple[str | int, ...], mode: str | None, issues: list[ManifestIssue]
) -> tuple[str, ...] | None:
    """Check ``declared_files``: paths in normal form, at least one for a change item, none for a query."""
    files = _entries(value, where, _path_problem, issues)
    if files is None:
        return None
    if mode == "change" and not files:
        issues.append(
            ManifestIssue(
                _key_path(*where),
                "mode",
                "a change item declares at least one file: the result check compares the changed files with these",
            )
        )
        return None
    if mode == "query" and files:
        issues.append(ManifestIssue(_key_path(*where), "mode", "must be empty for a query item, which writes no file"))
        return None
    return files


def _verify_commands(
    value: Any, where: tuple[str | int, ...], mode: str | None, issues: list[ManifestIssue]
) -> tuple[VerifyCommand, ...] | None:
    """Check ``verify_commands``: each entry, no repeated argv, and none for a query item."""
    array = _array(value, where, issues)
    if array is None:
        return None
    if mode == "query" and array:
        issues.append(
            ManifestIssue(
                _key_path(*where), "mode", "must be empty for a query item: section 8 of a query prompt does not apply"
            )
        )
        return None
    before = len(issues)
    commands: list[VerifyCommand] = []
    seen: dict[tuple[str, ...], int] = {}
    for position, entry in enumerate(array):
        at = (*where, position)
        command = _verify_command(entry, at, issues)
        if command is None:
            continue
        if command.cmd in seen:
            issues.append(
                ManifestIssue(_key_path(*at), "duplicate", f"repeats the cmd of {_key_path(*where, seen[command.cmd])}")
            )
            continue
        seen[command.cmd] = position
        commands.append(command)
    return None if len(issues) > before else tuple(commands)


def _verify_command(value: Any, where: tuple[str | int, ...], issues: list[ManifestIssue]) -> VerifyCommand | None:
    """Check one entry of ``verify_commands``: an argv and a boolean ``offline``."""
    if not isinstance(value, Mapping):
        issues.append(ManifestIssue(_key_path(*where), "type", f"must be an object, got {_describe(value)}"))
        return None
    before = len(issues)
    found = {key: _take(value, (*where, key), issues) for key in VERIFY_KEYS}
    cmd = _argv(found["cmd"], (*where, "cmd"), issues)
    offline = found["offline"]
    if offline is not _MISSING and not isinstance(offline, bool):
        issues.append(
            ManifestIssue(
                _key_path(*where, "offline"),
                "type",
                f"must be true or false (no AWS call and no remote write), got {_describe(offline)}",
            )
        )
    issues.extend(_unknown_keys(value, VERIFY_KEYS, where))
    if len(issues) > before:
        return None
    return VerifyCommand(cmd=_present(cmd), offline=offline)


def _argv(value: Any, where: tuple[str | int, ...], issues: list[ManifestIssue]) -> tuple[str, ...] | None:
    """Check an argv: one element or more, each a non-empty line without NUL."""
    array = _array(value, where, issues)
    if array is None:
        return None
    if not array:
        issues.append(ManifestIssue(_key_path(*where), "format", "must name a program: an argv of one element or more"))
        return None
    before = len(issues)
    for position, element in enumerate(array):
        at = (*where, position)
        text = _string(element, at, issues)
        if text is not None and (not text or "\x00" in text or text.splitlines() != [text]):
            issues.append(ManifestIssue(_key_path(*at), "format", "must be a non-empty line without NUL"))
    return None if len(issues) > before else tuple(array)


def _batch(value: Any, where: tuple[str | int, ...], issues: list[ManifestIssue]) -> str | None:
    """Check ``batch``: ``null`` or a label in the form of an ID."""
    if value is _MISSING or value is None:
        return None
    if not isinstance(value, str):
        issues.append(ManifestIssue(_key_path(*where), "type", f"must be null or a string, got {_describe(value)}"))
        return None
    if len(value) > MAX_ID_LENGTH or not _SLUG.fullmatch(value):
        issues.append(ManifestIssue(_key_path(*where), "format", _SLUG_RULE))
        return None
    return value


def _entries(
    value: Any,
    where: tuple[str | int, ...],
    problem_of: Callable[[str], str | None],
    issues: list[ManifestIssue],
) -> tuple[str, ...] | None:
    """Check an array of distinct strings, each of which ``problem_of`` accepts."""
    array = _array(value, where, issues)
    if array is None:
        return None
    before = len(issues)
    seen: dict[str, int] = {}
    for position, entry in enumerate(array):
        at = (*where, position)
        text = _string(entry, at, issues)
        if text is None:
            continue
        problem = problem_of(text)
        if problem is not None:
            issues.append(ManifestIssue(_key_path(*at), "format", problem))
        elif text in seen:
            issues.append(ManifestIssue(_key_path(*at), "duplicate", f"repeats {_key_path(*where, seen[text])}"))
        else:
            seen[text] = position
    return None if len(issues) > before else tuple(array)


def _cycle_issues(raw_items: Sequence[Any], context: _Context) -> list[ManifestIssue]:
    """Report each cycle of ``depends_on`` once, at the first item of the cycle in manifest order.

    The graph has one node per ID, from the first item with that ID, and an edge for each
    ``depends_on`` entry that names an ID of the manifest. Other problems of the items do
    not hide a cycle.

    Args:
        raw_items: The ``items`` array as written.
        context: The IDs of the manifest.

    Returns:
        One ``cycle`` issue per strongly connected component that holds a cycle, ordered by
        the index of its first item. The detail shows one shortest cycle through that item.
    """
    graph: dict[str, list[str]] = {}
    for item_id, index in context.first_index.items():
        dependencies = raw_items[index].get("depends_on")
        successors: list[str] = []
        if _is_array(dependencies):
            for dependency in dependencies:
                if isinstance(dependency, str) and dependency in context.first_index and dependency not in successors:
                    successors.append(dependency)
        graph[item_id] = successors

    found: list[tuple[int, ManifestIssue]] = []
    for component in _strongly_connected(graph):
        if len(component) == 1 and component[0] not in graph[component[0]]:
            continue
        start = min(component, key=context.first_index.__getitem__)
        cycle = _shortest_cycle(start, set(component), graph)
        index = context.first_index[start]
        found.append(
            (
                index,
                ManifestIssue(_key_path("items", index, "depends_on"), "cycle", "forms a cycle: " + " -> ".join(cycle)),
            )
        )
    return [issue for _, issue in sorted(found, key=lambda pair: pair[0])]


def _strongly_connected(graph: Mapping[str, Sequence[str]]) -> list[list[str]]:
    """Find the strongly connected components of a graph (Tarjan's algorithm, without recursion).

    Args:
        graph: Each node mapped to its successors, all of which are nodes of the graph.

    Returns:
        The components, each a list of nodes.
    """
    order: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []
    for root in graph:
        if root in order:
            continue
        order[root] = low[root] = len(order)
        stack.append(root)
        on_stack.add(root)
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, next_edge = work[-1]
            successors = graph[node]
            if next_edge < len(successors):
                work[-1] = (node, next_edge + 1)
                successor = successors[next_edge]
                if successor not in order:
                    order[successor] = low[successor] = len(order)
                    stack.append(successor)
                    on_stack.add(successor)
                    work.append((successor, 0))
                elif successor in on_stack:
                    low[node] = min(low[node], order[successor])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == order[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(component)
    return components


def _shortest_cycle(start: str, members: set[str], graph: Mapping[str, Sequence[str]]) -> list[str]:
    """Find a shortest cycle through ``start`` inside one strongly connected component.

    Args:
        start: A node of the component.
        members: The nodes of the component.
        graph: Each node mapped to its successors.

    Returns:
        The nodes of the cycle, from ``start`` back to ``start``: ``["a", "a"]`` for a node
        that depends on itself.
    """
    parent: dict[str, str] = {}
    queue = [start]
    position = 0
    while position < len(queue):
        node = queue[position]
        position += 1
        for successor in graph[node]:
            if successor not in members:
                continue
            if successor == start:
                path = [node]
                while path[-1] != start:
                    path.append(parent[path[-1]])
                path.reverse()
                return [*path, start]
            if successor not in parent:
                parent[successor] = node
                queue.append(successor)
    raise AssertionError("a strongly connected component with a cycle has one through each of its nodes")


def _path_problem(path: str) -> str | None:
    """Tell what keeps a string from being a relative path in normal form, or ``None``."""
    if not path.strip():
        return "must not be blank"
    if "\x00" in path or path.splitlines() != [path]:
        return "must be one line without NUL"
    if path.startswith(("/", "~")):
        return "must be a relative path, not starting with / or ~"
    if any(part in ("", ".", "..") for part in path.split("/")):
        return "must be in normal form: no empty, '.' or '..' component (no './', '//' or trailing '/')"
    return None


def _line_problem(text: str) -> str | None:
    """Tell what keeps a string from being one non-blank line without NUL, or ``None``."""
    if not text.strip():
        return "must not be blank"
    if "\x00" in text or text.splitlines() != [text]:
        return "must be one line without NUL"
    return None


def ref_name_problem(kind: str, name: str) -> str | None:
    """Tell what keeps a name from being the ``name`` of a :class:`RequiredRef` of this kind, or ``None``.

    Args:
        kind: ``tag`` or ``sha``.
        name: The name as given.

    Returns:
        The problem in a phrase, or ``None`` when the name has its form.

    Raises:
        ValueError: ``kind`` is neither ``tag`` nor ``sha``.
    """
    if kind not in REF_KINDS:
        raise ValueError(f"kind must be one of {', '.join(REF_KINDS)}, not {kind!r}")
    return _sha_problem(name) if kind == "sha" else _tag_problem(name)


def _sha_problem(name: str) -> str | None:
    """Tell what keeps a string from being a full commit SHA, or ``None``."""
    return None if _SHA.fullmatch(name) else "must be 40 lowercase hexadecimal digits"


def _tag_problem(name: str) -> str | None:
    """Tell what keeps a string from being a tag name as :class:`RequiredRef` defines it, or ``None``."""
    if not _TAG.fullmatch(name):
        return "must start with an ASCII letter or digit and hold only ASCII letters, digits, '.', '_', '-' and '/'"
    if ".." in name or "//" in name:
        return "must not contain '..' or '//'"
    if name.endswith(("/", ".")):
        return "must not end with '/' or '.'"
    if any(part.startswith(".") or part.endswith(".lock") for part in name.split("/")):
        return "no component may start with '.' or end with '.lock'"
    return None


def _is_timestamp(value: str) -> bool:
    """Whether a string is a moment written exactly as :func:`handoff.state.format_timestamp` writes it.

    ``strptime`` alone accepts fields of one digit and digits of other scripts; writing the
    parsed moment back and comparing refuses both.
    """
    try:
        moment = datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return False
    return format_timestamp(moment.replace(tzinfo=timezone.utc)) == value


def _string(value: Any, where: tuple[str | int, ...], issues: list[ManifestIssue]) -> str | None:
    """Return ``value`` if it is a string. Record a ``type`` issue otherwise; an absent key gives ``None`` silently."""
    if value is _MISSING:
        return None
    if not isinstance(value, str):
        issues.append(ManifestIssue(_key_path(*where), "type", f"must be a string, got {_describe(value)}"))
        return None
    return value


def _array(value: Any, where: tuple[str | int, ...], issues: list[ManifestIssue]) -> Sequence[Any] | None:
    """Return ``value`` if it is an array. Record a ``type`` issue otherwise; an absent key gives ``None`` silently."""
    if value is _MISSING:
        return None
    if not _is_array(value):
        issues.append(ManifestIssue(_key_path(*where), "type", f"must be an array, got {_describe(value)}"))
        return None
    array: Sequence[Any] = value
    return array


def _is_array(value: Any) -> bool:
    """Whether a value is a JSON array: a list, or a tuple from a Python caller."""
    return isinstance(value, (list, tuple))


def _frozen(value: Any) -> Any:
    """Copy a JSON value with every object made a read-only mapping and every array a tuple."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _frozen(element) for key, element in value.items()})
    if _is_array(value):
        return tuple(_frozen(element) for element in value)
    return value


def _take(mapping: Mapping[str, Any], where: tuple[str | int, ...], issues: list[ManifestIssue]) -> Any:
    """Return ``mapping[where[-1]]``, or record a ``missing`` issue and return ``_MISSING``."""
    key = where[-1]
    if isinstance(key, str) and key in mapping:
        return mapping[key]
    issues.append(ManifestIssue(_key_path(*where), "missing", "required; there is no default value"))
    return _MISSING


def _unknown_keys(
    mapping: Mapping[Any, Any], known: tuple[str, ...], where: tuple[str | int, ...]
) -> list[ManifestIssue]:
    """Report the keys of ``mapping`` that are not in ``known``, in sorted order."""
    return [
        ManifestIssue(_key_path(*where, key), "unknown_key", "not read by the harness")
        for key in sorted(map(str, mapping))
        if key not in known
    ]


def _key_path(*parts: str | int) -> str:
    """Render the location of a value for :attr:`ManifestIssue.path`. No parts is ``$``."""
    rendered = ""
    for part in parts:
        if isinstance(part, int):
            rendered += f"[{part}]"
        elif _PLAIN_KEY.fullmatch(part):
            rendered += f".{part}" if rendered else part
        else:
            rendered += f"[{json.dumps(part, ensure_ascii=False)}]"
    return rendered or "$"


def _describe(value: Any) -> str:
    """Show a value as JSON for an issue detail, clipped to 80 characters."""
    text = json.dumps(value, ensure_ascii=False, default=repr)
    return text if len(text) <= 80 else text[:77] + "..."


def _present(value: _T | None) -> _T:
    """Return a checked value. Every check that gives ``None`` has recorded an issue."""
    if value is None:
        raise AssertionError("a check rejected a value without recording an issue")
    return value

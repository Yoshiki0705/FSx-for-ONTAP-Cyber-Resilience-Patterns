"""Decide the final state of a Handoff item from what the runner observed.

Design section 20 ("結果の確認") lists what the runner observes after ``kiro-cli`` ends, and
the rules that turn those observations into ``succeeded``, ``failed`` or ``needs-human``
(Requirements 28.9, 28.19 and 28.20, Property 28). This module holds those rules
(:func:`final_state`), the helpers that build two of the observations
(:func:`undeclared_files`, :func:`conflicting_files`, :func:`main_tree_change`), the
heuristic scan of a Handoff_Report for lines that look like instructions
(:func:`report_flags`, Requirement 28.10) and the selftest verdict (:func:`selftest_verdict`,
Requirements 28.16 and 28.17).

This module is part of the pure core (see ``handoff/__init__.py``). The runner runs git,
measures the output and passes plain values in. :func:`final_state` never receives the
text of the Handoff_Report, so what the report says cannot change the state (Property 28).

Precedence. Several conditions can hold at once, and each leads to one state. The final
state is the state of the first condition in :data:`PRECEDENCE` that holds, and
``succeeded`` when none holds. The order, highest first:

1. Needs a human because the run crossed a boundary or clashes with other work. A re-run
   from the same worktree cannot clear these, and a re-run could repeat the first two:
   ``remote_branch_exists`` (the handoff branch is on the remote, against Requirement
   28.14), ``main_tree_changed`` (``main_tree_change`` is ``relevant``),
   ``undeclared_files`` (a commit changed a file outside the declared list; design H4 and
   H9) and ``conflicts`` (Requirement 28.20; the maintainer decides the base, design H11).
2. Failed because ``kiro-cli`` did not end normally: ``timed_out`` (Requirement 28.19),
   then ``exit_code_nonzero``.
3. Needs a human because the run ended with a result that is not ready:
   ``no_commits`` (change mode only; this includes a receiver that stopped at the checks
   of Requirement 23.6), ``dirty`` (uncommitted changes in the worktree) and
   ``rerun_unaccounted`` (a declared verification command with neither a re-run result
   nor a reason for not re-running it).
4. Failed because the product did not pass: ``rerun_failed`` (a re-run verification
   command exited with a code other than 0), then ``empty_output`` (query mode only:
   ``kiro-cli`` wrote nothing to standard output).

Group 3 ranks below group 2 because a killed or crashed run usually leaves exactly these
behind (an uncommitted edit, no commit, no re-run), and ``failed`` names the cause.
Group 1 ranks above group 2 because ``failed`` invites a plain re-run, which is wrong when
a boundary was crossed or the base has to be decided. The cost is that a timed-out run
with a group 1 condition is ``needs-human`` although Requirement 28.19 says ``failed``;
Requirement 28.20 and Property 28 put a conflict at ``needs-human`` with no exception, and
both cannot hold for a timed-out run with a conflict. Every condition that holds is kept
in :attr:`Evaluation.reasons`, so the timeout is still recorded.

Property 28 holds by construction: ``succeeded`` is returned only when no condition
holds, and each of its conditions is one of the conditions above.

Path comparison. Paths are repository-relative, as git prints them with ``-z`` (no
quoting). Each comparison is made in the direction that reports more, never fewer:

- :func:`undeclared_files` compares exactly. ``readme.md`` is not the declared
  ``README.md``: git keeps them as two paths, and a case-sensitive checkout has both.
- :func:`conflicting_files` and :func:`main_tree_change` ignore letter case and Unicode
  normalization (NFD, case fold, NFD, as ``config.is_within`` does), because on the default
  APFS format the two spellings open the same file.

Commands are identified by their argv: two commands are the same when their argv tuples
are equal, element by element. No shell parsing, no case folding.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal, TypeAlias, TypeVar, get_args

from handoff.config import MODES
from handoff.state import FAILED, MAX_SAFE_INTEGER, NEEDS_HUMAN, SUCCEEDED

#: A condition that keeps an item from ``succeeded``. The module docstring describes each.
Condition: TypeAlias = Literal[
    "remote_branch_exists",
    "main_tree_changed",
    "undeclared_files",
    "conflicts",
    "timed_out",
    "exit_code_nonzero",
    "no_commits",
    "dirty",
    "rerun_unaccounted",
    "rerun_failed",
    "empty_output",
]

#: Every condition, highest precedence first, with the state it leads to.
PRECEDENCE: Final[tuple[tuple[Condition, str], ...]] = (
    ("remote_branch_exists", NEEDS_HUMAN),
    ("main_tree_changed", NEEDS_HUMAN),
    ("undeclared_files", NEEDS_HUMAN),
    ("conflicts", NEEDS_HUMAN),
    ("timed_out", FAILED),
    ("exit_code_nonzero", FAILED),
    ("no_commits", NEEDS_HUMAN),
    ("dirty", NEEDS_HUMAN),
    ("rerun_unaccounted", NEEDS_HUMAN),
    ("rerun_failed", FAILED),
    ("empty_output", FAILED),
)

_STATE_OF: Final[dict[str, str]] = dict(PRECEDENCE)

#: The reason written to the history when no condition holds.
CHECKS_PASSED: Final = "all_checks_passed"

#: How the main working tree changed during a run (design section 20, step 8).
MainTreeChange: TypeAlias = Literal["none", "relevant", "unrelated"]
MAIN_TREE_CHANGES: Final[tuple[str, ...]] = get_args(MainTreeChange)

#: The keys of the ``observations`` object of ``status.json``.
OBSERVATION_KEYS: Final[tuple[str, ...]] = (
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
)

#: The two characters of a ``git status --porcelain=v1`` status code.
_STATUS_CODE: Final = re.compile(r"[ MTADRCU?!]{2}")

_T = TypeVar("_T")


class EvaluationError(ValueError):
    """An observation, a declaration or a result does not have the shape this module needs.

    This is a fault of the caller (the runner), not a property of the run, so it is raised
    instead of being turned into a state.
    """


@dataclass(frozen=True, slots=True)
class RerunResult:
    """A declared verification command that the runner re-ran in the worktree.

    Attributes:
        cmd: The argv, as declared. Stored as a tuple.
        exit_code: The exit code; negative when a signal ended the command.
    """

    cmd: tuple[str, ...]
    exit_code: int

    def __post_init__(self) -> None:
        """Check the argv and the exit code."""
        object.__setattr__(self, "cmd", _argv("cmd", self.cmd))
        _integer("exit_code", self.exit_code)


@dataclass(frozen=True, slots=True)
class RerunSkip:
    """A declared verification command that the runner did not re-run, and why.

    Attributes:
        cmd: The argv, as declared. Stored as a tuple.
        reason: Why it was not re-run, for example that it calls AWS. Not blank.
    """

    cmd: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        """Check the argv and the reason."""
        object.__setattr__(self, "cmd", _argv("cmd", self.cmd))
        if type(self.reason) is not str or not self.reason.strip() or not _encodable(self.reason):
            raise EvaluationError(f"reason must be a non-blank str, not {self.reason!r}")


@dataclass(frozen=True, slots=True, kw_only=True)
class Observations:
    """What the runner observed after one ``kiro-cli`` run (design section 20, steps 1 to 8).

    The fields follow ``observations``, ``rerun`` and ``rerun_skipped`` of an item in
    ``status.json``, plus ``stdout_bytes``, which the query mode needs. Every field is
    required: an observation has no default, so a runner that did not look cannot pass for
    a clean result. The fields are keyword-only because several share a type.

    Attributes:
        exit_code: The exit code of ``kiro-cli``; negative when a signal ended it.
        timed_out: Whether ``timeout_seconds`` passed and the runner stopped the process.
        stdout_bytes: Bytes ``kiro-cli`` wrote to standard output. The query mode needs
            more than 0; the text itself is not passed here.
        commits: Commits in ``origin/main..HEAD`` of the worktree.
        changed_files: Files in ``git diff --name-only origin/main...HEAD``.
        undeclared_files: The changed files outside the declared list, as
            :func:`undeclared_files` computes them. A subset of ``changed_files``.
        dirty: Whether ``git status --porcelain`` of the worktree printed anything.
        conflicts: The changed files that :func:`conflicting_files` reports. A subset of
            ``changed_files``.
        remote_branch_exists: Whether ``git ls-remote origin refs/heads/handoff/<id>``
            printed a line.
        main_tree_change: The result of :func:`main_tree_change`.
        rerun: The declared verification commands that were re-run, in the order run.
        rerun_skipped: The declared verification commands that were not re-run.

    Path collections are stored as sorted tuples without duplicates. A command appears at
    most once across ``rerun`` and ``rerun_skipped``.

    Raises:
        EvaluationError: A field does not have the shape described above.
    """

    exit_code: int
    timed_out: bool
    stdout_bytes: int
    commits: int
    changed_files: tuple[str, ...]
    undeclared_files: tuple[str, ...]
    dirty: bool
    conflicts: tuple[str, ...]
    remote_branch_exists: bool
    main_tree_change: MainTreeChange
    rerun: tuple[RerunResult, ...]
    rerun_skipped: tuple[RerunSkip, ...]

    def __post_init__(self) -> None:
        """Check the fields and normalize the collections."""
        _integer("exit_code", self.exit_code)
        _integer("stdout_bytes", self.stdout_bytes, minimum=0)
        _integer("commits", self.commits, minimum=0)
        for name in ("timed_out", "dirty", "remote_branch_exists"):
            if type(getattr(self, name)) is not bool:
                raise EvaluationError(f"{name} must be a bool, not {getattr(self, name)!r}")
        for name in ("changed_files", "undeclared_files", "conflicts"):
            object.__setattr__(self, name, _paths(name, getattr(self, name)))
        changed = set(self.changed_files)
        for name in ("undeclared_files", "conflicts"):
            outside = [path for path in getattr(self, name) if path not in changed]
            if outside:
                raise EvaluationError(f"{name} must be a subset of changed_files; not changed: {outside!r}")
        if type(self.main_tree_change) is not str or self.main_tree_change not in MAIN_TREE_CHANGES:
            raise EvaluationError(f"main_tree_change must be one of {MAIN_TREE_CHANGES}, not {self.main_tree_change!r}")
        object.__setattr__(self, "rerun", _instances("rerun", self.rerun, RerunResult))
        object.__setattr__(self, "rerun_skipped", _instances("rerun_skipped", self.rerun_skipped, RerunSkip))
        first_seen: dict[tuple[str, ...], str] = {}
        for name, entries in (("rerun", self.rerun), ("rerun_skipped", self.rerun_skipped)):
            for entry in entries:
                if entry.cmd in first_seen:
                    raise EvaluationError(
                        f"{name}: {list(entry.cmd)!r} appears again (first in {first_seen[entry.cmd]})"
                    )
                first_seen[entry.cmd] = name

    def to_json(self) -> dict[str, Any]:
        """Return the three item fields of ``status.json`` that hold these observations.

        Returns:
            ``{"observations": {...}, "rerun": [...], "rerun_skipped": [...]}``, built from
            new lists and dicts, so ``record.update(obs.to_json())`` leaves an item that
            passes ``state.check_status``.
        """
        return {
            "observations": {
                "exit_code": self.exit_code,
                "timed_out": self.timed_out,
                "stdout_bytes": self.stdout_bytes,
                "commits": self.commits,
                "changed_files": list(self.changed_files),
                "undeclared_files": list(self.undeclared_files),
                "dirty": self.dirty,
                "conflicts": list(self.conflicts),
                "remote_branch_exists": self.remote_branch_exists,
                "main_tree_change": self.main_tree_change,
            },
            "rerun": [{"cmd": list(entry.cmd), "exit_code": entry.exit_code} for entry in self.rerun],
            "rerun_skipped": [{"cmd": list(entry.cmd), "reason": entry.reason} for entry in self.rerun_skipped],
        }

    @classmethod
    def from_json(cls, fields: Mapping[str, Any]) -> Observations:
        """Read observations back from the item fields that :meth:`to_json` wrote.

        Args:
            fields: A mapping with the keys ``observations``, ``rerun`` and
                ``rerun_skipped``, such as an item of ``status.json``. Other keys are not
                read. Values must be the JSON types ``json.loads`` returns (``dict`` and
                ``list``, not tuples).

        Returns:
            The observations. ``Observations.from_json(obs.to_json()) == obs``.

        Raises:
            EvaluationError: A key is missing, ``observations`` is ``null`` (the item has
                not run), an object has a missing or unknown key, or a value has the wrong
                type or shape.
        """
        if not isinstance(fields, Mapping):
            raise EvaluationError(f"fields must be a mapping, not {type(fields).__name__}")
        missing = [key for key in ("observations", "rerun", "rerun_skipped") if key not in fields]
        if missing:
            raise EvaluationError(f"fields has no {missing}")
        raw = fields["observations"]
        if type(raw) is not dict:
            raise EvaluationError(f"observations must be an object, not {_json_type(raw)}")
        _exact_keys("observations", raw, OBSERVATION_KEYS)
        reruns = [
            _nested(f"rerun[{index}]", lambda e: RerunResult(_json_list("cmd", e["cmd"]), e["exit_code"]), entry)
            for index, entry in enumerate(_json_list("rerun", fields["rerun"]))
            if _exact_keys(f"rerun[{index}]", entry, ("cmd", "exit_code"))
        ]
        skips = [
            _nested(f"rerun_skipped[{index}]", lambda e: RerunSkip(_json_list("cmd", e["cmd"]), e["reason"]), entry)
            for index, entry in enumerate(_json_list("rerun_skipped", fields["rerun_skipped"]))
            if _exact_keys(f"rerun_skipped[{index}]", entry, ("cmd", "reason"))
        ]
        return cls(
            exit_code=raw["exit_code"],
            timed_out=raw["timed_out"],
            stdout_bytes=raw["stdout_bytes"],
            commits=raw["commits"],
            changed_files=_json_list("observations.changed_files", raw["changed_files"]),
            undeclared_files=_json_list("observations.undeclared_files", raw["undeclared_files"]),
            dirty=raw["dirty"],
            conflicts=_json_list("observations.conflicts", raw["conflicts"]),
            remote_branch_exists=raw["remote_branch_exists"],
            main_tree_change=raw["main_tree_change"],
            rerun=reruns,
            rerun_skipped=skips,
        )


@dataclass(frozen=True, slots=True)
class Evaluation:
    """The result of :func:`final_state`.

    Attributes:
        state: ``succeeded``, ``failed`` or ``needs-human``: the state of the first reason,
            or ``succeeded`` when there is none.
        reasons: Every condition that holds, in :data:`PRECEDENCE` order, including the
            ones that did not decide the state. Empty exactly when ``state`` is
            ``succeeded``.
        unaccounted_commands: The declared verification commands with neither a re-run
            result nor a skip reason, in declared order. Not empty exactly when
            ``rerun_unaccounted`` is a reason.

    Raises:
        EvaluationError: ``state`` is not the one ``reasons`` decide, or ``reasons`` is not
            in precedence order without repeats.
    """

    state: str
    reasons: tuple[Condition, ...]
    unaccounted_commands: tuple[tuple[str, ...], ...]

    def __post_init__(self) -> None:
        """Check that the state and the reasons agree."""
        order = [condition for condition, _ in PRECEDENCE]
        if not isinstance(self.reasons, tuple) or any(reason not in _STATE_OF for reason in self.reasons):
            raise EvaluationError(f"reasons must be a tuple of conditions, not {self.reasons!r}")
        if list(self.reasons) != [condition for condition in order if condition in self.reasons]:
            raise EvaluationError(f"reasons must follow PRECEDENCE without repeats, not {self.reasons!r}")
        if self.state != _state_for(self.reasons):
            raise EvaluationError(f"reasons {self.reasons!r} decide {_state_for(self.reasons)}, not {self.state!r}")
        if bool(self.unaccounted_commands) != ("rerun_unaccounted" in self.reasons):
            raise EvaluationError("unaccounted_commands must be non-empty exactly when rerun_unaccounted is a reason")

    @property
    def history_reason(self) -> str:
        """The ``reason`` to pass to ``state.transition``: the reasons joined, or ``all_checks_passed``."""
        return ", ".join(self.reasons) or CHECKS_PASSED


def final_state(
    observations: Observations,
    *,
    mode: str,
    declared_files: Iterable[str],
    verify_commands: Iterable[Iterable[str]],
) -> Evaluation:
    """Decide the final state of one run from its observations and the item's declaration.

    Args:
        observations: What the runner observed. The text of the Handoff_Report is not an
            input.
        mode: ``query`` or ``change``. ``no_commits`` applies to the change mode and
            ``empty_output`` to the query mode; every other condition applies to both.
        declared_files: The files the item declares it creates or changes (the section
            「作成・変更するファイル」). Empty for a query item.
        verify_commands: The argv of each declared verification command. A repeated argv
            counts once.

    Returns:
        The state, every condition that holds, and the unaccounted commands.

    Raises:
        EvaluationError: ``mode`` is not a mode; a declared path or argv has the wrong
            shape; ``observations.undeclared_files`` is not what :func:`undeclared_files`
            gives for this declaration; or ``rerun`` or ``rerun_skipped`` holds a command
            that is not declared. These mean the observations were not built for this
            item, so no state is returned.
    """
    if not isinstance(observations, Observations):
        raise EvaluationError(f"observations must be Observations, not {type(observations).__name__}")
    if type(mode) is not str or mode not in MODES:
        raise EvaluationError(f"mode must be one of {MODES}, not {mode!r}")
    declared = _paths("declared_files", declared_files)
    commands = _argv_list("verify_commands", verify_commands)
    expected = undeclared_files(observations.changed_files, declared)
    if observations.undeclared_files != expected:
        raise EvaluationError(
            f"undeclared_files is {list(observations.undeclared_files)!r}, but this declaration gives {list(expected)!r}"
        )
    known = set(commands)
    stray = [list(entry.cmd) for entry in (*observations.rerun, *observations.rerun_skipped) if entry.cmd not in known]
    if stray:
        raise EvaluationError(f"rerun or rerun_skipped holds commands that are not declared: {stray!r}")
    exit_codes = {entry.cmd: entry.exit_code for entry in observations.rerun}
    skipped = {entry.cmd for entry in observations.rerun_skipped}
    unaccounted = tuple(command for command in commands if command not in exit_codes and command not in skipped)
    holds: dict[Condition, bool] = {
        "remote_branch_exists": observations.remote_branch_exists,
        "main_tree_changed": observations.main_tree_change == "relevant",
        "undeclared_files": bool(observations.undeclared_files),
        "conflicts": bool(observations.conflicts),
        "timed_out": observations.timed_out,
        "exit_code_nonzero": observations.exit_code != 0,
        "no_commits": mode == "change" and observations.commits == 0,
        "dirty": observations.dirty,
        "rerun_unaccounted": bool(unaccounted),
        "rerun_failed": any(code != 0 for code in exit_codes.values()),
        "empty_output": mode == "query" and observations.stdout_bytes == 0,
    }
    reasons = tuple(condition for condition, _ in PRECEDENCE if holds[condition])
    return Evaluation(_state_for(reasons), reasons, unaccounted)


def undeclared_files(changed_files: Iterable[str], declared_files: Iterable[str]) -> tuple[str, ...]:
    """List the changed files that the item did not declare (design section 20, step 4).

    Paths are compared exactly (see the module docstring).

    Args:
        changed_files: Repository-relative paths, as in :attr:`Observations.changed_files`.
        declared_files: The declared paths.

    Returns:
        The changed files not in ``declared_files``, sorted, without duplicates.

    Raises:
        EvaluationError: A path is not a repository-relative path such as ``docs/a.md``.
    """
    declared = set(_paths("declared_files", declared_files))
    return tuple(path for path in _paths("changed_files", changed_files) if path not in declared)


def conflicting_files(
    changed_files: Iterable[str], default_branch_files: Iterable[str], batch_files: Iterable[str]
) -> tuple[str, ...]:
    """List this item's changed files that the default branch or another item also changed.

    Design section 20, step 5, and Requirement 28.20: a file changed on both sides is a
    conflict, even when the edits do not meet line by line. Paths that differ only in
    letter case or Unicode normalization count as the same file (see the module docstring).

    Args:
        changed_files: This item's changed files.
        default_branch_files: Files changed in ``<base_sha>..origin/main``.
        batch_files: Files changed by the other items of the same batch, all together. Do
            not include this item's own files: every file would then conflict.

    Returns:
        This item's paths, as this item spells them, that conflict; sorted.

    Raises:
        EvaluationError: A path is not a repository-relative path.
    """
    others = {_fold(path) for path in _paths("default_branch_files", default_branch_files)}
    others.update(_fold(path) for path in _paths("batch_files", batch_files))
    return tuple(path for path in _paths("changed_files", changed_files) if _fold(path) in others)


@dataclass(frozen=True, slots=True, kw_only=True)
class MainTreeSnapshot:
    """The main working tree of the target repository, before or after a run.

    Attributes:
        head: ``git rev-parse HEAD``, or ``None`` on a branch with no commit yet.
        branch: ``git branch --show-current``, or ``None`` when HEAD is detached.
        status: ``(code, path)`` for each path in ``git status --porcelain=v1 -z``, as
            :func:`parse_status_z` reads it.

    Raises:
        EvaluationError: A field has the wrong type.
    """

    head: str | None
    branch: str | None
    status: frozenset[tuple[str, str]]

    def __post_init__(self) -> None:
        """Check the fields and store ``status`` as a frozenset."""
        for name in ("head", "branch"):
            value = getattr(self, name)
            if value is not None and (type(value) is not str or not value):
                raise EvaluationError(f"{name} must be a non-empty str or None, not {value!r}")
        if isinstance(self.status, (str, bytes)) or not isinstance(self.status, Iterable):
            raise EvaluationError(
                f"status must be a collection of (code, path) pairs, not {type(self.status).__name__}"
            )
        entries = frozenset(self.status)
        for entry in entries:
            if not (type(entry) is tuple and len(entry) == 2 and all(type(part) is str for part in entry)):
                raise EvaluationError(f"status entries must be (code, path) pairs of str, not {entry!r}")
        object.__setattr__(self, "status", entries)


def parse_status_z(text: str) -> frozenset[tuple[str, str]]:
    """Read the output of ``git status --porcelain=v1 -z`` (without ``--branch``).

    Each entry is ``XY <path>`` followed by NUL. A rename or copy (``R`` or ``C`` in either
    column) is followed by its source path and another NUL. Git does not quote paths in
    this form, so a path can hold any character but NUL.

    Args:
        text: The output, decoded by the caller.

    Returns:
        ``(XY, path)`` for every path; a rename or copy gives one pair for each of its two
        paths.

    Raises:
        TypeError: ``text`` is not a ``str``.
        EvaluationError: ``text`` does not have the shape above.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, not {type(text).__name__}")
    if not text:
        return frozenset()
    if not text.endswith("\0"):
        raise EvaluationError("git status -z output must end with NUL")
    fields = text[:-1].split("\0")
    entries: set[tuple[str, str]] = set()
    index = 0
    while index < len(fields):
        field = fields[index]
        code, separator, path = field[:2], field[2:3], field[3:]
        if not _STATUS_CODE.fullmatch(code) or separator != " " or not path:
            raise EvaluationError(f"git status -z entry {index} is not 'XY <path>'")
        entries.add((code, path))
        index += 1
        if "R" in code or "C" in code:
            if index == len(fields) or not fields[index]:
                raise EvaluationError(f"git status -z entry {index - 1} is a rename or copy without its source path")
            entries.add((code, fields[index]))
            index += 1
    return frozenset(entries)


def main_tree_change(
    before: MainTreeSnapshot, after: MainTreeSnapshot, declared_files: Iterable[str]
) -> MainTreeChange:
    """Classify how the main working tree changed during a run (design section 20, step 8).

    Rules:

    - ``relevant`` when the branch or HEAD changed.
    - Otherwise, the paths whose ``(code, path)`` entry appeared or disappeared are the
      changed paths. ``relevant`` when one of them is a declared file, lies below one, or is
      a directory holding one (``git status`` shows an untracked directory as ``dir/``).
      Letter case and Unicode normalization are ignored.
    - ``unrelated`` when there are changed paths and none of them is relevant. Another
      session may have made them, so they are not attributed to the run.
    - ``none`` when nothing changed.

    A file that was already modified before the run and was modified again keeps the same
    entry, so that change is not seen. The runner does not undo anything either way.

    Args:
        before: The snapshot taken before ``kiro-cli`` started.
        after: The snapshot taken after it ended.
        declared_files: The item's declared files.

    Returns:
        ``none``, ``relevant`` or ``unrelated``.

    Raises:
        EvaluationError: A snapshot is not a :class:`MainTreeSnapshot`, or a declared path
            is not a repository-relative path.
    """
    for name, snapshot in (("before", before), ("after", after)):
        if not isinstance(snapshot, MainTreeSnapshot):
            raise EvaluationError(f"{name} must be a MainTreeSnapshot, not {type(snapshot).__name__}")
    declared = [_parts(path) for path in _paths("declared_files", declared_files)]
    if before.head != after.head or before.branch != after.branch:
        return "relevant"
    changed = {path for _, path in before.status ^ after.status}
    if not changed:
        return "none"
    for path in changed:
        parts = _parts(path)
        if any(parts[: len(item)] == item or item[: len(parts)] == parts for item in declared):
            return "relevant"
    return "unrelated"


#: What a flagged line of a Handoff_Report looks like.
ReportFlagKind: TypeAlias = Literal["instruction_to_session", "allowlist_expansion", "command_request"]
REPORT_FLAG_KINDS: Final[tuple[str, ...]] = get_args(ReportFlagKind)

#: The headwords of each kind, in Japanese and English. A line is flagged for a kind when,
#: after folding (see :func:`report_flags`), it contains one of the kind's headwords.
REPORT_FLAG_TERMS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "instruction_to_session": (
            "このセッション",
            "呼び出し元",
            "依頼元",
            "親セッション",
            "元のセッション",
            "引き継ぎ元",
            "オーケストレータ",
            "あなたのセッション",
            "そちらのセッション",
            "this session",
            "calling session",
            "parent session",
            "originating session",
            "requesting session",
            "your session",
            "the caller",
            "orchestrator",
        ),
        "allowlist_expansion": (
            "許可一覧",
            "許可リスト",
            "信頼するツール",
            "ツールを許可",
            "ツールの許可",
            "権限を追加",
            "権限を付与",
            "権限を広げ",
            "権限の追加",
            "権限の付与",
            "--trust-tools",
            "trust-all",
            "trust_all",
            "trust all",
            "allowlist",
            "allow list",
            "allow-list",
            "whitelist",
            "grant permission",
            "grant access",
            "additional permission",
            "more permission",
        ),
        "command_request": (
            "実行してください",
            "実行して下さい",
            "実行をお願い",
            "実行してほしい",
            "実行して欲しい",
            "実行していただ",
            "走らせてください",
            "回してください",
            "コマンドを実行",
            "次のコマンド",
            "以下のコマンド",
            "please run",
            "please execute",
            "kindly run",
            "run the following",
            "execute the following",
            "run this command",
            "run these commands",
            "run the command",
            "you should run",
            "you need to run",
            "you must run",
            "make sure to run",
            "be sure to run",
        ),
    }
)

#: ANSI escape sequences: CSI (colors, cursor), OSC (titles, links) and two-byte escapes.
_ANSI_ESCAPE: Final = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")


@dataclass(frozen=True, slots=True)
class ReportFlag:
    """A line of a Handoff_Report that looks like an instruction. It holds no text of the line.

    Attributes:
        line: The line number, from 1, in the numbering :func:`report_flags` was given.
        kind: Which kind of request the line looks like.
    """

    line: int
    kind: ReportFlagKind

    def __post_init__(self) -> None:
        """Check the line number and the kind."""
        _integer("line", self.line, minimum=1)
        if type(self.kind) is not str or self.kind not in REPORT_FLAG_KINDS:
            raise EvaluationError(f"kind must be one of {REPORT_FLAG_KINDS}, not {self.kind!r}")

    def to_json(self) -> dict[str, Any]:
        """Return the entry of ``report_flags`` in ``status.json``: ``{"line": ..., "kind": ...}``."""
        return {"line": self.line, "kind": self.kind}

    @classmethod
    def from_json(cls, value: object) -> ReportFlag:
        """Read an entry of ``report_flags`` back.

        Raises:
            EvaluationError: ``value`` is not an object with exactly ``line`` and ``kind``.
        """
        if type(value) is not dict:
            raise EvaluationError(f"a report flag must be an object, not {_json_type(value)}")
        _exact_keys("report flag", value, ("line", "kind"))
        return cls(value["line"], value["kind"])


_TERM_PATTERNS: dict[str, re.Pattern[str]] = {}


def report_flags(text: str, *, first_line: int = 1) -> tuple[ReportFlag, ...]:
    """Find lines that look like a request to this session, to widen the allowlist, or to run a command.

    This is a heuristic headword match (Requirement 28.10, design H9). A flag only points
    the maintainer at a line; it changes no state and decides nothing. No line of a
    Handoff_Report is carried out, flagged or not, so a missed instruction is not carried
    out either. Expect both false flags (a report that quotes its own rules, or says
    "this session" of its own session) and misses (an imperative without a headword, other
    languages, words split over lines).

    Each line is folded before matching: ANSI escape sequences and Unicode format characters
    (such as zero-width spaces) are removed, the text is put in NFKC form (full-width letters
    become ASCII), case-folded, and each run of whitespace becomes one space.

    Args:
        text: The part of the report to scan, such as the standard output of ``kiro-cli``.
            Scan only what ``kiro-cli`` wrote: the argv that the runner records holds
            ``--trust-tools``, which is a headword.
        first_line: The number of the first line of ``text`` in the report, so that the
            flags point at report lines. Lines are split at ``\\n`` only, as ``grep -n``
            counts them.

    Returns:
        One flag per line and kind, ordered by line, then by :data:`REPORT_FLAG_KINDS`.

    Raises:
        TypeError: ``text`` is not a ``str``.
        EvaluationError: ``first_line`` is not an integer of 1 or more.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, not {type(text).__name__}")
    _integer("first_line", first_line, minimum=1)
    if not _TERM_PATTERNS:
        for kind, terms in REPORT_FLAG_TERMS.items():
            _TERM_PATTERNS[kind] = re.compile("|".join(re.escape(_fold_text(term)) for term in terms))
    flags: list[ReportFlag] = []
    for offset, line in enumerate(text.split("\n")):
        folded = _fold_text(line)
        if folded:
            flags.extend(
                ReportFlag(first_line + offset, kind)
                for kind in REPORT_FLAG_KINDS
                if _TERM_PATTERNS[kind].search(folded)
            )
    return tuple(flags)


#: What became of one selftest trial.
TrialOutcome: TypeAlias = Literal["completed", "blocked_by_guard", "failed_otherwise"]
TRIAL_OUTCOMES: Final[tuple[str, ...]] = get_args(TrialOutcome)

GUARDS_ACTIVE: Final = "guards_active"
UNCONFIRMED: Final = "unconfirmed"
SelftestResult: TypeAlias = Literal["guards_active", "unconfirmed"]


@dataclass(frozen=True, slots=True, kw_only=True)
class SelftestTrials:
    """The outcome of each selftest trial (design section 20, "selftest").

    Each outcome is ``completed`` (the operation took effect), ``blocked_by_guard`` (a
    PreToolUse guard stopped it) or ``failed_otherwise`` (it did not take effect for another
    reason, such as layer 3 or a missing login). For T2, ``failed_otherwise`` is the push
    that the guard let through and layer 3 made fail, so the guard and layer 3 are told
    apart.

    Attributes:
        t0: Control: add a line to ``README.md`` and commit. Expected ``completed``.
        t1: Commit with a message holding a private-range example address. Expected
            ``blocked_by_guard``.
        t2: ``git push --force`` to the local bare remote. Expected ``blocked_by_guard``.
        t3: ``gh auth status`` in the child shell. Expected ``failed_otherwise`` (layer 3).
            Recorded only; not used by :func:`selftest_verdict`.
        t4: Use a tool left out of ``--trust-tools``. Expected not ``completed`` (layer 1).
            Recorded only; not used by :func:`selftest_verdict`.

    Raises:
        EvaluationError: An outcome is not one of :data:`TRIAL_OUTCOMES`.
    """

    t0: TrialOutcome
    t1: TrialOutcome
    t2: TrialOutcome
    t3: TrialOutcome
    t4: TrialOutcome

    def __post_init__(self) -> None:
        """Check each outcome."""
        for name in ("t0", "t1", "t2", "t3", "t4"):
            value = getattr(self, name)
            if type(value) is not str or value not in TRIAL_OUTCOMES:
                raise EvaluationError(f"{name} must be one of {TRIAL_OUTCOMES}, not {value!r}")


def selftest_verdict(trials: SelftestTrials) -> SelftestResult:
    """Decide whether the PreToolUse guards are active in ``kiro-cli`` runs.

    ``guards_active`` only when T0 completed and the guards stopped both T1 and T2. A T1 or
    T2 that failed for another reason does not count as stopped. When T0 did not complete,
    T1 and T2 say nothing. T3 and T4 test layers 3 and 1, not the guards, and are not read.

    Args:
        trials: The outcomes of T0 to T4.

    Returns:
        ``guards_active`` or ``unconfirmed``. With ``unconfirmed``, change-mode items become
        ``needs-human`` and the allowlist is cut to ``fs_read`` (Requirement 28.17).

    Raises:
        EvaluationError: ``trials`` is not a :class:`SelftestTrials`.
    """
    if not isinstance(trials, SelftestTrials):
        raise EvaluationError(f"trials must be SelftestTrials, not {type(trials).__name__}")
    if trials.t0 == "completed" and trials.t1 == "blocked_by_guard" and trials.t2 == "blocked_by_guard":
        return GUARDS_ACTIVE
    return UNCONFIRMED


def _state_for(reasons: tuple[Condition, ...]) -> str:
    """The state of the first reason, or ``succeeded`` when there is none."""
    return _STATE_OF[reasons[0]] if reasons else SUCCEEDED


def _integer(name: str, value: object, *, minimum: int = -MAX_SAFE_INTEGER) -> int:
    """Require an ``int`` (not a ``bool``) from ``minimum`` to ``state.MAX_SAFE_INTEGER``."""
    if type(value) is not int:
        raise EvaluationError(f"{name} must be an int, not {value!r}")
    if not minimum <= value <= MAX_SAFE_INTEGER:
        raise EvaluationError(f"{name} must be from {minimum} to {MAX_SAFE_INTEGER}, not {value}")
    return value


def _encodable(text: str) -> bool:
    """Whether a string encodes as UTF-8, that is, holds no lone surrogate."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _collection(name: str, value: object) -> tuple[Any, ...]:
    """Turn a collection that is not a bare ``str`` or ``bytes`` into a tuple."""
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise EvaluationError(f"{name} must be a collection, not {type(value).__name__}")
    return tuple(value)


def _paths(name: str, value: object) -> tuple[str, ...]:
    """Check repository-relative paths and return them sorted without duplicates.

    A path is a non-empty ``str`` of ``/``-separated components, none of them empty, ``.``
    or ``..``, with no NUL and no lone surrogate: ``docs/a.md``, not ``/docs/a.md``,
    ``docs/``, ``./docs/a.md`` or ``docs//a.md``.
    """
    paths: set[str] = set()
    for index, path in enumerate(_collection(name, value)):
        if (
            type(path) is not str
            or "\0" in path
            or not _encodable(path)
            or any(part in ("", ".", "..") for part in path.split("/"))
        ):
            raise EvaluationError(f"{name}[{index}] must be a repository-relative path such as docs/a.md, not {path!r}")
        paths.add(path)
    return tuple(sorted(paths))


def _argv(name: str, value: object) -> tuple[str, ...]:
    """Check an argv: a non-empty sequence of ``str`` whose first element names a program."""
    argv = _collection(name, value)
    if not argv:
        raise EvaluationError(f"{name} must not be empty")
    for index, part in enumerate(argv):
        if type(part) is not str or "\0" in part or not _encodable(part):
            raise EvaluationError(f"{name}[{index}] must be a str without NUL, not {part!r}")
    if not argv[0].strip():
        raise EvaluationError(f"{name}[0] must name a program")
    return argv


def _argv_list(name: str, value: object) -> tuple[tuple[str, ...], ...]:
    """Check a collection of argvs and return them in order, each once."""
    argvs = (_argv(f"{name}[{index}]", argv) for index, argv in enumerate(_collection(name, value)))
    return tuple(dict.fromkeys(argvs))


def _instances(name: str, value: object, cls: type[_T]) -> tuple[_T, ...]:
    """Check that a collection holds only instances of ``cls``."""
    entries = _collection(name, value)
    for index, entry in enumerate(entries):
        if not isinstance(entry, cls):
            raise EvaluationError(f"{name}[{index}] must be {cls.__name__}, not {type(entry).__name__}")
    return entries


def _fold(path: str) -> str:
    """Fold a path for comparison as ``config.is_within`` does: NFD, case fold, NFD."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", path).casefold())


def _parts(path: str) -> tuple[str, ...]:
    """Split a folded path into its non-empty components (``dir/`` becomes ``("dir",)``)."""
    return tuple(part for part in _fold(path).split("/") if part)


def _fold_text(line: str) -> str:
    """Fold one line of a report for headword matching, as :func:`report_flags` describes."""
    line = _ANSI_ESCAPE.sub("", line)
    if not line.isascii():
        line = "".join(char for char in line if unicodedata.category(char) != "Cf")
        line = unicodedata.normalize("NFKC", line)
    return " ".join(line.casefold().split())


def _exact_keys(where: str, value: object, keys: tuple[str, ...]) -> bool:
    """Require a JSON object with exactly ``keys``. Returns True so it can guard a comprehension."""
    if type(value) is not dict:
        raise EvaluationError(f"{where} must be an object, not {_json_type(value)}")
    missing = sorted(set(keys) - value.keys())
    unknown = sorted(map(str, value.keys() - set(keys)))
    if missing or unknown:
        raise EvaluationError(f"{where}: missing keys {missing}, unknown keys {unknown}")
    return True


def _json_list(where: str, value: object) -> list[Any]:
    """Require a JSON array (a ``list``, as ``json.loads`` returns it)."""
    if type(value) is not list:
        raise EvaluationError(f"{where} must be an array, not {_json_type(value)}")
    return value


def _nested(where: str, build: Any, entry: dict[str, Any]) -> Any:
    """Build a value from a JSON entry, prefixing an error with where the entry is."""
    try:
        return build(entry)
    except EvaluationError as exc:
        raise EvaluationError(f"{where}: {exc}") from exc


def _json_type(value: object) -> str:
    """The JSON name of a value's type, for error messages."""
    names = {dict: "object", list: "array", str: "string", int: "number", float: "number", bool: "boolean"}
    return "null" if value is None else names.get(type(value), type(value).__name__)

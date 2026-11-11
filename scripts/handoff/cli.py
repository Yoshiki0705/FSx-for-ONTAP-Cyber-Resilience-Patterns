"""Command line of the Handoff_Harness: ``plan``, ``run``, ``manual``, ``status`` and ``cleanup``.

Task 2.3 of the phase 4 spec (design section 20; Requirements 28.11, 28.12, 28.13, 28.19, 28.21
and 28.23). The pure core decides, :mod:`handoff.runner` starts every process and writes every
file below ``.private/handoff/``, and this module parses the command line, reads and checks the
inputs, wires them to the runner and shows the results. It starts no process itself.

Start it from the repository root::

    python3 scripts/handoff/cli.py [--handoff-dir <dir>] <subcommand> ...

The handoff directory is this repository's ``.private/handoff``. ``--handoff-dir`` names it: an
absolute path in normal form that ends with ``.private/handoff``. Without the option it is
``<main working tree>/.private/handoff``, where the main working tree is the parent of git's
common directory of the repository that holds this file (:func:`handoff.runner.harness_tree_of`),
so a start from a linked worktree uses the main working tree's records, never the worktree's own
``.private/``. The main working tree two levels above the handoff directory is this repository's
own, protected like the main working trees of ``repos``.

Inputs, read and checked first, in this order: ``HOME`` (absolute), then ``config.json`` and
``manifest.json`` of the handoff directory. Each file must be UTF-8 JSON with no repeated key and
no ``NaN`` or ``Infinity``, and pass :func:`handoff.config.parse_config` (with this repository's
main working tree in ``extra_main_trees`` and ``~/Projects/.kiro-worktrees`` as
``session_worktrees_dir``) or :func:`handoff.manifest.parse_manifest`. A problem ends the command
with exit code 2, and every issue goes to standard error. With ``--handoff-dir`` nothing else has
been read, written or started by then; without it, one ``git rev-parse`` found the directory. The
items named by ``--sync-point`` or ``--items`` are checked against the manifest at the same point.

``plan``, ``run`` and ``manual`` scan each prompt with :func:`handoff.runner.load_deny_terms`: the
customer-name list, which is required (the file named by the environment variable
``CUSTOMER_TERMS_FILE``, as for ``guard_customer_names.py``, or else
``~/.kiro/hooks/private/customer-terms.txt``), and ``.private/research/phase4/deny-terms.txt`` of
this repository's main working tree, which may be missing until the research writes it. No ref is
confirmed yet (IN-2 is wired in task 15.4), so every prompt draws its refs as unconfirmed.

Agent configurations (task 2.5). ``plan``, ``run`` and ``manual`` also read
``agents/approved.json`` of the handoff directory by the rules of ``config.json``, after the items
are checked and before the deny lists: ``{"schema_version": 1, "agents": [...]}``, where each
approval has exactly ``name`` (of the form ``[A-Za-z0-9_][A-Za-z0-9_.-]*`` that
``command.build_kiro_argv`` requires), ``mode`` (one of :data:`handoff.config.MODES`), ``path``
(exactly ``~/.kiro/agents/<name>.json``), ``sha256`` (64 lowercase hexadecimal digits),
``approved_at`` (:data:`handoff.state.TIMESTAMP_FORMAT`) and ``approved_in`` (not blank), and no
name or mode appears twice. A missing file approves nothing. A file that cannot be read or is
malformed ends the command with exit code 2 before any process starts. Then, each time one of the
three commands runs, the approval whose name and mode are those of ``agents.<mode>`` of
``config.json`` is checked against its file: ``path`` with ``~`` expanded is a regular file and not
a symbolic link (``lstat``), its SHA-256 is ``sha256``, and as JSON it has that ``name``,
``tools`` and ``allowedTools`` lists within ``mode_tool_ceiling.<mode>``, ``mcpServers`` ``{}``
and ``includeMcpJson`` ``false``. Each failed check goes to standard error, and the approval does
not count; this does not change the exit code. An approval counts for its own mode only. An item
whose mode names an agent gets ``--agent <name>`` when that approval counts; otherwise the runner
holds it in ``needs-human`` (``agent_not_approved``) and never starts it with the default agent.
An item whose mode names no agent starts without ``--agent``. Before ``kiro-cli`` starts with
``--agent``, the runner holds the item (``agent_shadowed``) when the new worktree has a
configuration of that name in ``.kiro/agents/`` or ``.amazonq/cli-agents/``
(:mod:`handoff.runner`, step 6). The checks are made when the command starts, and ``kiro-cli``
reads the file again when it starts, so a change in between is not seen.

Subcommands:

- ``plan (--sync-point X | --items ID,...)``: for each named item, its state, its dependencies,
  the executor and the rows of the executor table that decide it, whether its argv gets
  ``--agent`` (or why the item is held for its agent instead), the path of the drawn
  Handoff_Prompt, the scan result, and what ``run`` would do with it if every item it starts
  ended ``succeeded``: start it (and in which turn), hold it in ``needs-human`` (with the
  reason), or not start it (with the reasons of ``dag.select``). An item that waits for a
  dependency or for room is shown with the turn it would get once the items before it end.
  It takes the lock and writes the prompts of the ``queued`` items, as ``run`` does, and starts
  nothing. The records it needs are added to an in-memory copy of the status, and the status file
  is not written, except by :meth:`handoff.runner.Harness.open` after an abnormal end of an earlier
  harness (a stale lock, or a ``running`` record whose process is gone).
- ``run (--sync-point X | --items ID,...)``: starts the named items in the order of
  ``dag.select``, up to ``max_concurrency`` at a time in worker threads, choosing again each time
  an item starts or ends, until no named item can start. A change item is held in
  ``needs-human`` (``change_mode_not_wired``) until task 5 wires the change mode. The runner holds
  a query item whose prompt has a scan finding, is too long, cannot be drawn, or names this
  session as its executor, and one whose agent is not approved or has a configuration of the
  same name in the worktree (above). Each item is attempted at most once per run. SIGINT stops
  starting items, stops the running ones (they become ``failed``, ``harness_interrupted``; one
  that had not reached ``kiro-cli`` stays ``queued``) and waits for them (design H8). ``LoginRequired``,
  ``DiskSpaceLow``, ``UnsafeLocation`` and the other runner errors stop starting items and let the
  running ones finish. When ``kiro-cli`` cannot be found, before the first item or at an item's
  ``whoami``, the manual display of each named item that is ``queued`` and ready is printed
  instead, and nothing more starts (Requirement 28.21).
- ``manual ID``: prints the Handoff_Prompt in full, the repository to paste it in, and the
  commands from ``git -C <main> fetch --no-tags origin main`` to ``git worktree add`` that make the
  worktree (with ``<sha>`` for the base commit). The item must be ``queued`` (or have no record
  yet), ``failed`` or ``needs-human``: ``run`` holds a change item in ``needs-human`` and points
  to this command, and design H2 and H3 hand a failed item or a held change item over by hand.
  ``running`` and ``succeeded`` are refused. The status is not changed. A prompt with a scan finding is not shown: the kinds and
  line numbers of the findings go to standard error and the exit code is 1, so that a deny term is
  not handed over by hand either. A prompt that cannot be drawn, or whose executor is this
  session, is not shown either.
- ``status``: reads the status without the lock, so it works while ``run`` goes on. Shows each
  item's state, its last transition and its time in ``running``, the items that wait because a
  dependency failed, the total time in ``running``, and the differences between the worktrees
  that git lists below ``worktrees_root`` (``git worktree list`` of each main working tree of
  ``repos``) and the ``worktree`` fields of the status (design H6, H8).
  ``status set ID queued --reason TEXT`` moves a ``failed`` or ``needs-human`` item back to
  ``queued``.
- ``cleanup ID [--approved]``: lists what would be removed (the item's worktree, and for a change
  item its branch ``handoff/<id>``) and the command ``git -C <main> worktree remove <path>``
  (without ``--force``). Only with ``--approved`` does it run the command; git refuses a worktree
  with modified or untracked files. The removal is recorded in ``events`` and the record's
  ``worktree`` becomes ``null``. A branch is never deleted here: after the pull request is merged,
  the maintainer runs the ``git branch -d`` that the listing shows. Reports are kept.

Exit codes:

====  =====================================================================================
0     Success. For ``run``: every item it started or held ended ``succeeded`` (also when no
      item could start).
1     An item ended ``failed`` or ``needs-human`` in this ``run``, or a request was refused
      for an item's state or content: ``manual`` of an item that is ``running`` or
      ``succeeded``, has a scan finding, cannot be drawn or belongs to this session; ``status set`` from a state other
      than ``failed`` and ``needs-human``; ``cleanup`` where git refused or could not tell;
      ``status`` that could not list a repository's worktrees.
2     The configuration or the manifest was rejected, the arguments were wrong (both or neither
      of ``--sync-point`` and ``--items``, an unknown item, a blank ``--reason``), or the
      handoff directory or the home directory could not be determined.
3     The harness did not open: another harness holds the lock (H5), or the lock or
      ``status.json`` cannot be read.
4     ``kiro-cli whoami`` failed: log in to ``kiro-cli``, then run again (H1, Requirement 28.18).
5     The environment refused: too little free disk space (H7), a place that resolves into a
      protected tree, or a deny list that is missing or unreadable.
6     ``kiro-cli`` was not found, and the manual display was printed instead (Requirement 28.21).
130   Interrupted (SIGINT).
====  =====================================================================================

Output: standard output carries the results, with paths under the home directory written as
``~/...``. Standard error carries the details, which can hold local paths: the issues of a
rejected input, the checks that an agent approval failed, the ``detail`` of an outcome, the
messages of the runner's errors, and the warnings of the ``handoff`` loggers.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):
    _here = Path(__file__).resolve().parent
    sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != _here]
    sys.path.insert(0, str(_here.parent))

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import posixpath  # noqa: E402
import re  # noqa: E402
import shlex  # noqa: E402
import signal  # noqa: E402
import stat  # noqa: E402
import threading  # noqa: E402
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence  # noqa: E402
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait  # noqa: E402
from contextlib import contextmanager  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from typing import Any, Final  # noqa: E402

from handoff import command, dag, runner, state  # noqa: E402
from handoff.config import MODES, ConfigError, HandoffConfig, is_within, normalize_path, parse_config  # noqa: E402
from handoff.executor import Executor, ExecutorChoice, choose  # noqa: E402
from handoff.manifest import SYNC_POINTS, Item, Manifest, ManifestError, parse_manifest  # noqa: E402
from handoff.prompt import MAX_BODY_BYTES, RenderedPrompt  # noqa: E402

#: The IDE sessions' worktree directory, protected like a main working tree.
SESSION_WORKTREES_DIR: Final = "~/Projects/.kiro-worktrees"

#: The environment variable that names the customer-name list, as for ``guard_customer_names.py``.
CUSTOMER_TERMS_VARIABLE: Final = "CUSTOMER_TERMS_FILE"

#: The configuration and the manifest, directly below the handoff directory.
CONFIG_FILE: Final = "config.json"
MANIFEST_FILE: Final = "manifest.json"

#: The approvals of agent configurations, relative to the handoff directory (task 2.5).
APPROVALS_FILE: Final = "agents/approved.json"

#: The one place where an approved agent configuration may be: kiro-cli's global agent directory.
APPROVED_AGENT_PATH: Final = "~/.kiro/agents/{name}.json"

_APPROVAL_KEYS: Final[tuple[str, ...]] = ("schema_version", "agents")
_APPROVAL_ENTRY_KEYS: Final[tuple[str, ...]] = ("name", "mode", "path", "sha256", "approved_at", "approved_in")

#: The agent name that ``command.build_kiro_argv`` accepts after ``--agent`` (task 1.9). It has no
#: ``/`` and does not start with ``.``, so ``~/.kiro/agents/<name>.json`` stays in that directory.
_AGENT_NAME: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP_SHAPE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

#: The history reason of a change item that ``run`` holds until task 5 wires the change mode.
CHANGE_MODE_HELD: Final = "change_mode_not_wired"

#: The reason ``run`` and ``plan`` give an item that they mark ``running`` in an in-memory copy of
#: the status, so that ``dag.select`` counts it. It is never written to ``status.json``.
_IN_MEMORY_RUNNING: Final = "chosen by cli.py, not written"

#: The reason ``plan`` gives an item that it marks ``succeeded`` in its in-memory copy, to see
#: what ``run`` reaches once that item ends so. It is never written to ``status.json``.
_IN_MEMORY_SUCCEEDED: Final = "assumed by cli.py plan, not written"

#: The states from which ``manual`` hands an item over by hand. A ``needs-human`` item is handed
#: over this way while the change mode is not wired or the guard is unconfirmed (design H3), and
#: a ``failed`` one after its report and worktree were read (H2). ``running`` is refused because
#: a harness is running it, and ``succeeded`` because its work is done.
_MANUAL_STATES: Final[tuple[str, ...]] = (state.QUEUED, state.FAILED, state.NEEDS_HUMAN)

EXIT_OK: Final = 0
EXIT_ITEMS: Final = 1
EXIT_USAGE: Final = 2
EXIT_HARNESS: Final = 3
EXIT_LOGIN: Final = 4
EXIT_ENVIRONMENT: Final = 5
EXIT_MANUAL: Final = 6
EXIT_INTERRUPTED: Final = 130

_MODE_LABELS: Final[Mapping[str, str]] = {"query": "照会モード", "change": "変更モード"}

#: What ``plan`` adds after a hold reason, for the reasons whose cause it can name.
_HOLD_NOTES: Final[Mapping[str, str]] = {
    CHANGE_MODE_HELD: "変更モードはまだ配線していない（タスク 5）。手作業で渡すなら cli.py manual {id}",
    runner.EXECUTOR_IS_THIS_SESSION: "このセッションが行う。対象リポジトリの Kiro には渡さない",
    "prompt_scan_findings": "走査の該当がある本文は渡さない。テンプレートか変数を直してから status set で queued に戻す",
    "prompt_too_long": f"本文が {MAX_BODY_BYTES} バイトを超える",
    "worktree_exists": "worktree が既にある。cli.py cleanup {id} で消してから",
    runner.AGENT_NOT_APPROVED: "承認の検証で落ちた点は標準エラー出力にある。既定のエージェントでは起動しない",
}


class _Exit(Exception):
    """End the subcommand with an exit code, and a message for standard error.

    Attributes:
        code: The exit code.
        message: The message, possibly with local paths; empty for none.
    """

    def __init__(self, code: int, message: str = "") -> None:
        """Keep the code and the message.

        Args:
            code: The exit code.
            message: The message for standard error.
        """
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class _Inputs:
    """The checked inputs that every subcommand starts from.

    Attributes:
        home: The home directory, absolute and in normal form.
        handoff_dir: This repository's ``.private/handoff``, absolute and in normal form.
        harness_tree: This repository's main working tree, two levels above ``handoff_dir``.
        session_worktrees_dir: The IDE sessions' worktree directory, ``~`` expanded.
        config: The checked configuration.
        manifest: The checked manifest.
    """

    home: str
    handoff_dir: str
    harness_tree: str
    session_worktrees_dir: str
    config: HandoffConfig
    manifest: Manifest

    @property
    def by_id(self) -> Mapping[str, Item]:
        """The items of the manifest by ID."""
        return self.manifest.by_id


@dataclass(frozen=True, slots=True)
class _Forecast:
    """What ``run`` would do with the named items, as ``plan`` shows it.

    Attributes:
        start: The items it would start, in the order it would start them.
        hold: The items it would hold in ``needs-human``, with the history reason.
        after: The items of ``start`` and ``hold`` that ``run`` reaches only after an item it
            started earlier ends: they wait for the room that item holds, or for that item as a
            dependency, which must end ``succeeded``.
        ready: The named items that were ready (``dag.ready``) before anything started; an item
            of ``after`` that is not among them waits for a dependency.
        waiting: Every other named item, with the reasons of ``dag.select``. ``run`` does not
            start them, even when every item it starts succeeds.
    """

    start: tuple[str, ...]
    hold: Mapping[str, str]
    after: frozenset[str]
    ready: frozenset[str]
    waiting: Mapping[str, tuple[dag.SkipReason, ...]]


@dataclass(frozen=True, slots=True)
class _Approval:
    """One approval of ``agents/approved.json`` that has its form (the module docstring).

    Attributes:
        name: The agent configuration's name.
        mode: The mode that it is approved for.
        path: ``~/.kiro/agents/<name>.json``, as written.
        sha256: The SHA-256 of the approved file, 64 lowercase hexadecimal digits.
        approved_at: When the approval was written, in ``state.TIMESTAMP_FORMAT``.
        approved_in: Where the decision is recorded.
    """

    name: str
    mode: str
    path: str
    sha256: str
    approved_at: str
    approved_in: str


def main(argv: Sequence[str] | None = None) -> int:
    """Run one subcommand.

    Args:
        argv: The arguments after the program name; ``sys.argv[1:]`` when ``None``.

    Returns:
        The exit code (the table in the module docstring).
    """
    parser = _parser()
    try:
        args = parser.parse_args(None if argv is None else list(argv))
    except SystemExit as stop:
        if stop.code is None:
            return EXIT_OK
        return stop.code if isinstance(stop.code, int) else EXIT_USAGE
    with _stderr_logging():
        try:
            inputs = _load(args)
            return _SUBCOMMANDS[args.command](args, inputs)
        except _Exit as stop:
            if stop.message:
                _err(stop.message)
            return stop.code
        except runner.RunnerError as error:
            _err(str(error))
            return _exit_code_of(error)
        except KeyboardInterrupt:
            _err("中断した。この後に起動したものはない")
            return EXIT_INTERRUPTED


def _parser() -> argparse.ArgumentParser:
    """Build the argument parser of the subcommands in the module docstring."""
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Hand Handoff_Prompts to other repositories' Kiro and track them (design section 20).",
    )
    parser.add_argument(
        "--handoff-dir",
        metavar="DIR",
        help="this repository's .private/handoff (absolute, ending with .private/handoff); "
        "by default the one of the main working tree of the repository that holds cli.py",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="<subcommand>")
    for name, text in (
        ("plan", "show what run would start, hold or leave queued, and start nothing"),
        ("run", "start the named items (query mode only; change items are held)"),
    ):
        sub = commands.add_parser(name, help=text, description=text)
        which = sub.add_mutually_exclusive_group(required=True)
        which.add_argument("--sync-point", choices=SYNC_POINTS, help="the items of one Sync_Point")
        which.add_argument("--items", type=_item_list, metavar="ID,...", help="the items listed, comma-separated")
    manual = commands.add_parser(
        "manual",
        help="print an item's Handoff_Prompt and the commands that make its worktree, for pasting by hand",
    )
    manual.add_argument("item_id", metavar="ID")
    status_parser = commands.add_parser("status", help="show the state of every item; 'status set' re-queues one")
    actions = status_parser.add_subparsers(dest="status_action", metavar="set")
    setter = actions.add_parser("set", help="move a failed or needs-human item back to queued")
    setter.add_argument("item_id", metavar="ID")
    setter.add_argument("target", choices=(state.QUEUED,), metavar=state.QUEUED)
    setter.add_argument("--reason", required=True, help="why it may run again, one line")
    cleanup = commands.add_parser(
        "cleanup", help="list an item's worktree and branch; remove the worktree with --approved"
    )
    cleanup.add_argument("item_id", metavar="ID")
    cleanup.add_argument("--approved", action="store_true", help="run git worktree remove (without --force)")
    return parser


def _item_list(value: str) -> tuple[str, ...]:
    """Split the value of ``--items``.

    Raises:
        argparse.ArgumentTypeError: The value is empty or has an empty entry.
    """
    entries = tuple(value.split(","))
    if not value or not all(entries):
        raise argparse.ArgumentTypeError("give item IDs separated by single commas")
    return entries


def _load(args: argparse.Namespace) -> _Inputs:
    """Read and check ``HOME``, the handoff directory, ``config.json`` and ``manifest.json``.

    Raises:
        _Exit: With exit code 2 on any problem.
    """
    home = _home()
    handoff_dir = _handoff_dir(args.handoff_dir)
    harness_tree = posixpath.dirname(posixpath.dirname(handoff_dir))
    session = normalize_path(SESSION_WORKTREES_DIR, home)
    config_path = posixpath.join(handoff_dir, CONFIG_FILE)
    raw_config = _read_json(config_path)
    try:
        config = parse_config(raw_config, home=home, extra_main_trees=[harness_tree], session_worktrees_dir=session)
    except ConfigError as error:
        raise _Exit(EXIT_USAGE, _issue_lines(f"{config_path} was rejected", error.issues)) from None
    manifest_path = posixpath.join(handoff_dir, MANIFEST_FILE)
    raw_manifest = _read_json(manifest_path)
    try:
        manifest = parse_manifest(raw_manifest, config=config)
    except ManifestError as error:
        raise _Exit(EXIT_USAGE, _issue_lines(f"{manifest_path} was rejected", error.issues)) from None
    return _Inputs(home, handoff_dir, harness_tree, session, config, manifest)


def _home() -> str:
    """The home directory from ``HOME``, in normal form.

    Raises:
        _Exit: ``HOME`` is unset or not absolute (exit code 2).
    """
    home = os.environ.get("HOME", "")
    if not home.startswith("/"):
        raise _Exit(EXIT_USAGE, "HOME must be set to an absolute path")
    return normalize_path(home, home)


def _handoff_dir(given: str | None) -> str:
    """The handoff directory: ``--handoff-dir``, or the one of the main working tree that holds this file.

    Raises:
        _Exit: The option does not have its form, or the main working tree was not found
            (exit code 2).
    """
    if given is not None:
        if not _is_handoff_dir(given):
            raise _Exit(
                EXIT_USAGE,
                f"--handoff-dir must be an absolute path in normal form that ends with .private/handoff, got {given!r}",
            )
        return given
    try:
        tree = runner.harness_tree_of(str(Path(__file__).resolve().parent))
    except runner.GitCommandFailed as error:
        raise _Exit(EXIT_USAGE, f"the main working tree was not found ({error}); give --handoff-dir") from None
    return posixpath.join(tree, ".private", "handoff")


def _is_handoff_dir(path: str) -> bool:
    """Whether a path is absolute, in normal form, on one line, and ends with ``.private/handoff``."""
    if not path.startswith("/") or "\x00" in path or path.splitlines() != [path]:
        return False
    if "/" + posixpath.normpath(path).lstrip("/") != path:
        return False
    return posixpath.basename(path) == "handoff" and posixpath.basename(posixpath.dirname(path)) == ".private"


def _read_json(path: str) -> Any:
    """Read one UTF-8 JSON file, refusing a repeated key and a non-standard constant.

    Raises:
        _Exit: The file is missing or unreadable, or its text is not such JSON (exit code 2).
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except FileNotFoundError:
        raise _Exit(EXIT_USAGE, f"{path} does not exist") from None
    except OSError as exc:
        raise _Exit(EXIT_USAGE, f"{path} cannot be read: {exc}") from None
    try:
        text = data.decode("utf-8")
        return json.loads(text, object_pairs_hook=_without_repeated_keys, parse_constant=_no_constant)
    except (ValueError, RecursionError) as exc:
        raise _Exit(EXIT_USAGE, f"{path} is not valid JSON: {exc}") from None


def _without_repeated_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object, refusing a key that appears twice (the later one would win silently)."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"the key {key!r} appears more than once in one object")
        result[key] = value
    return result


def _no_constant(name: str) -> Any:
    """Refuse ``NaN``, ``Infinity`` and ``-Infinity``, which are not JSON (RFC 8259)."""
    raise ValueError(f"{name} is not a JSON value")


def _issue_lines(title: str, issues: Iterable[object]) -> str:
    """One title line and one indented line per issue."""
    return "\n".join([title + ":", *(f"  {issue}" for issue in issues)])


def _named_items(inputs: _Inputs, args: argparse.Namespace) -> tuple[dict[str, Any], tuple[Item, ...]]:
    """Check ``--sync-point`` or ``--items`` against the manifest, before any other I/O.

    The check is ``dag.select`` itself, on an in-memory status in which every item is ``queued``.

    Returns:
        The keyword argument for ``dag.select``, and the named items in the order of the manifest.

    Raises:
        _Exit: The Sync_Point has no item, or an ID is unknown or listed twice (exit code 2).
    """
    selector: dict[str, Any]
    if args.sync_point is not None:
        selector = {"sync_point": args.sync_point}
    else:
        selector = {"item_ids": args.items}
    try:
        dag.select(
            inputs.manifest,
            _with_records(state.empty_status(), inputs.manifest),
            confirmed_refs=(),
            max_concurrency=inputs.config.max_concurrency,
            **selector,
        )
    except dag.SelectionError as error:
        raise _Exit(EXIT_USAGE, str(error)) from None
    if args.sync_point is not None:
        named = tuple(item for item in inputs.manifest.items if item.sync_point == args.sync_point)
    else:
        wanted = set(args.items)
        named = tuple(item for item in inputs.manifest.items if item.id in wanted)
    return selector, named


def _item(inputs: _Inputs, item_id: str) -> Item:
    """The manifest's item with this ID.

    Raises:
        _Exit: The manifest has no such item (exit code 2).
    """
    item = inputs.by_id.get(item_id)
    if item is None:
        raise _Exit(EXIT_USAGE, f"the manifest has no item {item_id!r}")
    return item


def _with_records(status: state.StatusDoc, manifest: Manifest) -> state.StatusDoc:
    """A copy of a status with a ``queued`` record for each item of the manifest that it lacks."""
    for item in manifest.items:
        if item.id not in status["items"]:
            status = state.add_item(status, item.id)
    return status


def _deny_terms(inputs: _Inputs) -> runner.DenyTerms:
    """Read the two deny lists of the module docstring.

    Raises:
        _Exit: ``CUSTOMER_TERMS_FILE`` is not absolute (exit code 2).
        handoff.runner.DenyListUnavailable: A list is missing or unreadable (exit code 5).
    """
    named = os.environ.get(CUSTOMER_TERMS_VARIABLE) or runner.CUSTOMER_TERMS_FILE
    try:
        customer = normalize_path(named, inputs.home)
    except ValueError as exc:
        raise _Exit(EXIT_USAGE, f"{CUSTOMER_TERMS_VARIABLE}: {exc}") from None
    return runner.load_deny_terms(customer, posixpath.join(inputs.harness_tree, runner.EXTRA_TERMS_FILE))


def _agent_approvals(inputs: _Inputs) -> tuple[_Approval, ...]:
    """Read ``agents/approved.json`` of the handoff directory and check its form (the module docstring).

    Returns:
        The approvals, in the order of the file; none when the file does not exist.

    Raises:
        _Exit: The file cannot be read, is not such JSON, or lacks its form (exit code 2).
    """
    path = posixpath.join(inputs.handoff_dir, APPROVALS_FILE)
    if not os.path.lexists(path):
        return ()
    raw = _read_json(path)
    issues = _approval_issues(raw)
    if issues:
        raise _Exit(EXIT_USAGE, _issue_lines(f"{path} was rejected", issues))
    return tuple(_Approval(**{key: entry[key] for key in _APPROVAL_ENTRY_KEYS}) for entry in raw["agents"])


def _approval_issues(raw: Any) -> list[str]:
    """Every way in which the JSON of ``agents/approved.json`` lacks its form, one ``<where>: <what>`` each."""
    if type(raw) is not dict:
        return [f"$: must be an object, got {type(raw).__name__}"]
    issues = _key_issues("$", raw, _APPROVAL_KEYS)
    version = raw.get("schema_version")
    if "schema_version" in raw and (type(version) is not int or version != 1):
        issues.append(f"$.schema_version: must be 1, got {version!r}")
    if "agents" not in raw:
        return issues
    agents = raw["agents"]
    if type(agents) is not list:
        return [*issues, f"$.agents: must be a list, got {type(agents).__name__}"]
    first: dict[tuple[str, str], int] = {}
    for index, entry in enumerate(agents):
        where = f"$.agents[{index}]"
        if type(entry) is not dict:
            issues.append(f"{where}: must be an object, got {type(entry).__name__}")
            continue
        issues.extend(_key_issues(where, entry, _APPROVAL_ENTRY_KEYS))
        issues.extend(_approval_entry_issues(where, entry))
        for key in ("name", "mode"):
            value = entry.get(key)
            if type(value) is not str:
                continue
            if (key, value) in first:
                issues.append(f"{where}.{key}: {value!r} is also the {key} of $.agents[{first[(key, value)]}]")
            else:
                first[(key, value)] = index
    return issues


def _key_issues(where: str, obj: Mapping[str, Any], keys: tuple[str, ...]) -> list[str]:
    """The keys of ``keys`` that an object lacks, then the keys that it has besides them."""
    missing = [f"{where}.{key}: missing" for key in keys if key not in obj]
    unknown = [f"{where}: unknown key {key!r}" for key in sorted(obj) if key not in keys]
    return [*missing, *unknown]


def _approval_entry_issues(where: str, entry: Mapping[str, Any]) -> list[str]:
    """The fields of one approval that lack their form. A missing field is left to :func:`_key_issues`."""
    issues: list[str] = []
    name = entry.get("name")
    named = type(name) is str and _AGENT_NAME.fullmatch(name) is not None
    if "name" in entry and not named:
        issues.append(f"{where}.name: must be of the form {_AGENT_NAME.pattern}, got {name!r}")
    mode = entry.get("mode")
    if "mode" in entry and (type(mode) is not str or mode not in MODES):
        issues.append(f"{where}.mode: must be one of {', '.join(MODES)}, got {mode!r}")
    path = entry.get("path")
    expected = APPROVED_AGENT_PATH.format(name=name if named else "<name>")
    if "path" in entry and (not named or type(path) is not str or path != expected):
        issues.append(f"{where}.path: must be exactly {expected}, got {path!r}")
    digest = entry.get("sha256")
    if "sha256" in entry and (type(digest) is not str or _SHA256.fullmatch(digest) is None):
        issues.append(f"{where}.sha256: must be 64 lowercase hexadecimal digits, got {digest!r}")
    if "approved_at" in entry and not _is_timestamp(entry["approved_at"]):
        issues.append(
            f"{where}.approved_at: must be a moment written as {state.TIMESTAMP_FORMAT}, got {entry['approved_at']!r}"
        )
    recorded = entry.get("approved_in")
    if "approved_in" in entry and (type(recorded) is not str or not recorded.strip()):
        issues.append(f"{where}.approved_in: must be a string that is not blank, got {recorded!r}")
    return issues


def _is_timestamp(value: object) -> bool:
    """Whether a value is a moment written exactly as :func:`handoff.state.format_timestamp` writes it."""
    if type(value) is not str or _TIMESTAMP_SHAPE.fullmatch(value) is None:
        return False
    try:
        moment = datetime.strptime(value, state.TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return state.format_timestamp(moment) == value


def _context(inputs: _Inputs, deny: runner.DenyTerms, approvals: Sequence[_Approval]) -> runner.RunContext:
    """The inputs of the runner, with the agent approvals that pass their checks now. No ref is confirmed yet."""
    return runner.RunContext(
        config=inputs.config,
        manifest=inputs.manifest,
        home=inputs.home,
        harness_tree=inputs.harness_tree,
        session_worktrees_dir=inputs.session_worktrees_dir,
        deny=deny,
        confirmed_refs=frozenset(),
        approved_agents=_verified_agents(inputs, approvals),
    )


def _verified_agents(inputs: _Inputs, approvals: Sequence[_Approval]) -> frozenset[tuple[str, str]]:
    """Check, now, the approval of each agent that ``config.json`` names, and return the pairs that pass.

    For each mode whose ``agents.<mode>`` names an agent, the approval with that name and that
    mode is checked against its file with :func:`_agent_file_problems`. An approval of the same
    name for another mode does not count. Each reason why a named agent is not approved goes to
    standard error, one line each; the exit code does not change for it.

    Args:
        inputs: The checked inputs.
        approvals: What :func:`_agent_approvals` returned.

    Returns:
        The ``(name, mode)`` pairs whose approval passed every check.
    """
    passed: set[tuple[str, str]] = set()
    for mode, name in inputs.config.agents.items():
        approval = next((entry for entry in approvals if (entry.name, entry.mode) == (name, mode)), None)
        if approval is None:
            others = [entry.mode for entry in approvals if entry.name == name]
            note = f"（{'、'.join(others)} の承認はあるが、承認は承認した mode の項目にだけ使う）" if others else ""
            _err(
                f"エージェント設定 {name}（{mode}）は承認されていない: {APPROVALS_FILE} に {name} の {mode} の承認がない{note}"
            )
            continue
        problems = _agent_file_problems(approval, inputs.config.mode_tool_ceiling.get(mode, ()), inputs.home)
        for check, detail in problems:
            _err(f"エージェント設定 {name}（{mode}）の承認を使わない: {check}: {detail}")
        if not problems:
            passed.add((name, mode))
    return frozenset(passed)


def _agent_file_problems(approval: _Approval, ceiling: Sequence[str], home: str) -> list[tuple[str, str]]:
    """Check an approval against its file, now; every failed check as ``(check, detail)``.

    The file first: ``path`` with ``~`` expanded must be a regular file and not a symbolic link
    (``lstat``); it is read without following a link, and its SHA-256 must be ``sha256``. Then
    its content, also when the SHA-256 differs, so that every difference is shown: JSON by the
    rules of ``config.json``, ``name`` equal to the approval's, ``tools`` and ``allowedTools``
    lists of names in ``ceiling``, ``mcpServers`` ``{}`` and ``includeMcpJson`` ``false``.

    Args:
        approval: An approval that has its form.
        ceiling: ``mode_tool_ceiling`` of the approval's mode.
        home: The home directory, to expand ``~``.

    Returns:
        The failed checks, in that order; empty when the approval passes.
    """
    path = normalize_path(approval.path, home)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return [("lstat", f"{path} does not exist")]
    except OSError as exc:
        return [("lstat", f"{path}: {exc.strerror or exc}")]
    if stat.S_ISLNK(before.st_mode):
        return [("symlink", f"{path} is a symbolic link, and a link is not followed")]
    if not stat.S_ISREG(before.st_mode):
        return [("regular_file", f"{path} is not a regular file")]
    try:
        data = _read_regular(path, before)
    except OSError as exc:
        return [("read", f"{path}: {exc.strerror or exc}")]
    problems: list[tuple[str, str]] = []
    actual = hashlib.sha256(data).hexdigest()
    if actual != approval.sha256:
        problems.append(("sha256", f"{path} has the SHA-256 {actual}, not the approved {approval.sha256}"))
    try:
        document = json.loads(
            data.decode("utf-8"), object_pairs_hook=_without_repeated_keys, parse_constant=_no_constant
        )
    except (ValueError, RecursionError) as exc:
        return [*problems, ("json", f"{path} is not valid JSON: {exc}")]
    if type(document) is not dict:
        return [*problems, ("json", f"{path} holds {type(document).__name__}, not an object")]

    def got(key: str) -> str:
        return "missing" if key not in document else repr(document[key])

    if document.get("name") != approval.name:
        problems.append(("name", f"must be {approval.name!r}, got {got('name')}"))
    for key in ("tools", "allowedTools"):
        tools = document.get(key)
        if type(tools) is not list:
            problems.append((key, f"must be a list, got {got(key)}"))
            continue
        outside = [tool for tool in tools if type(tool) is not str or tool not in ceiling]
        if outside:
            problems.append((key, f"{outside!r} not in mode_tool_ceiling.{approval.mode} ({', '.join(ceiling)})"))
    servers = document.get("mcpServers")
    if type(servers) is not dict or servers:
        problems.append(("mcpServers", f"must be {{}}, got {got('mcpServers')}"))
    if document.get("includeMcpJson") is not False:
        problems.append(("includeMcpJson", f"must be false, got {got('includeMcpJson')}"))
    return problems


def _read_regular(path: str, seen: os.stat_result) -> bytes:
    """Read a file without following a symbolic link, requiring it to be the regular file that ``lstat`` saw.

    Raises:
        OSError: It cannot be opened or read, or it is not that file any more.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (seen.st_dev, seen.st_ino):
            raise OSError("it changed between lstat and open")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1 << 16):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


# --------------------------------------------------------------------------------------------
# plan
# --------------------------------------------------------------------------------------------


def _plan(args: argparse.Namespace, inputs: _Inputs) -> int:
    """``plan``: show what ``run`` would do with the named items, and start nothing."""
    selector, named = _named_items(inputs, args)
    approvals = _agent_approvals(inputs)
    deny = _deny_terms(inputs)
    with runner.Harness.open(inputs.handoff_dir) as harness:
        context = _context(inputs, deny, approvals)
        view = _with_records(harness.status, inputs.manifest)
        drafts = {
            item.id: harness.draw_prompt(context, item.id)
            for item in named
            if view["items"][item.id]["state"] == state.QUEUED
        }
        forecast = _forecast(inputs, view, selector, drafts, context.confirmed_refs)
        settled = harness.stale_lock is not None or bool(harness.interrupted_items)
    target = f"Sync_Point {selector['sync_point']}" if "sync_point" in selector else "--items " + ",".join(args.items)
    if settled:
        written = "ハーネスを開いたときに、前のハーネスが残したもの（古いロック、終わっていた running）だけを状態ファイルに記録した"
    else:
        written = "状態ファイルは変えていない"
    _out(
        f"計画: {target}（{len(named)} 項目、max_concurrency {inputs.config.max_concurrency}）。何も起動していない。{written}"
    )
    _out("run の扱いは、run が起動する項目がすべて succeeded で終わった場合の見込み")
    for item in named:
        _out("")
        _plan_item(inputs, item, view, drafts.get(item.id), forecast, context.approved_agents)
    return EXIT_OK


def _forecast(
    inputs: _Inputs,
    view: state.StatusDoc,
    selector: Mapping[str, Any],
    drafts: Mapping[str, runner.PromptDraft],
    confirmed_refs: frozenset[Any],
) -> _Forecast:
    """Repeat the choices of ``run`` on an in-memory copy of the status.

    Each item that ``dag.select`` chooses is marked ``needs-human`` when ``run`` would hold it and
    ``running`` otherwise, and the choice is made again. When nothing more is chosen, the item
    marked ``running`` first is marked ``succeeded``, as if its run had ended so, and the choice
    goes on, until nothing is chosen and nothing is marked ``running``. The forecast is therefore
    the most that ``run`` would do: an item that ends otherwise frees its repository and its room
    but not the items that depend on it.
    """
    start: list[str] = []
    hold: dict[str, str] = {}
    after: set[str] = set()
    running: list[str] = []
    ready: frozenset[str] | None = None
    assumed = False
    while True:
        selection = dag.select(
            inputs.manifest,
            view,
            confirmed_refs=confirmed_refs,
            max_concurrency=inputs.config.max_concurrency,
            **selector,
        )
        if ready is None:
            ready = frozenset(selection.selected) | {
                entry.item_id
                for entry in selection.not_selected
                if all(reason.kind in dag.ROOM_KINDS for reason in entry.reasons)
            }
        if selection.selected:
            item_id = selection.selected[0]
            if assumed:
                after.add(item_id)
            reason = _forecast_hold(inputs.by_id[item_id], drafts.get(item_id))
            if reason is None:
                view = state.transition(view, item_id, state.RUNNING, at=_now(), reason=_IN_MEMORY_RUNNING)
                start.append(item_id)
                running.append(item_id)
            else:
                view = state.transition(view, item_id, state.NEEDS_HUMAN, at=_now(), reason=reason)
                hold[item_id] = reason
            continue
        if not running:
            break
        view = state.transition(view, running.pop(0), state.SUCCEEDED, at=_now(), reason=_IN_MEMORY_SUCCEEDED)
        assumed = True
    waiting = {
        entry.item_id: entry.reasons
        for entry in selection.not_selected
        if entry.item_id not in hold and entry.item_id not in start
    }
    return _Forecast(tuple(start), hold, frozenset(after), ready or frozenset(), waiting)


def _forecast_hold(item: Item, draft: runner.PromptDraft | None) -> str | None:
    """The reason with which ``run`` would hold an item before ``kiro-cli``, as far as ``plan`` can tell."""
    if item.mode != "query":
        return CHANGE_MODE_HELD
    if draft is None:
        return None
    if draft.hold_reason is not None:
        return draft.hold_reason
    if draft.git_plan is not None and os.path.lexists(draft.git_plan.worktree):
        return "worktree_exists"
    return None


def _plan_item(
    inputs: _Inputs,
    item: Item,
    view: state.StatusDoc,
    draft: runner.PromptDraft | None,
    forecast: _Forecast,
    approved: frozenset[tuple[str, str]],
) -> None:
    """Show one item of ``plan``."""
    record = view["items"][item.id]
    _out(f"{item.id}（{item.repo}、Sync_Point {item.sync_point}、{_MODE_LABELS[item.mode]}）")
    _out(f"  状態: {_state_text(record)}")
    if item.depends_on:
        listed = "、".join(f"{dep}（{view['items'][dep]['state']}）" for dep in item.depends_on)
        _out(f"  依存: {listed}")
    else:
        _out("  依存: なし")
    rendered = None if draft is None else draft.rendered
    if rendered is not None:
        _write_executor(rendered.executor_choice, "")
    else:
        note = "（本文を描いていないので、未コミットの件数を 0 として判定）"
        _write_executor(choose(item.executor_attrs(uncommitted_count=0)), note)
    if draft is None:
        _out("  本文: 描いていない（状態が queued でない）")
    elif rendered is None:
        _out(f"  本文: 描けなかった（{draft.hold_reason}）。{_tilde(draft.path, inputs.home)} には書いていない")
        _err(f"{item.id}: {draft.detail}")
    else:
        _out(f"  本文: {_tilde(draft.path, inputs.home)}（{rendered.byte_length} バイト）")
        _out(f"  走査: {_scan_text(rendered)}")
    _out(f"  エージェント: {_agent_text(inputs.config, item, approved)}")
    _out(f"  run の扱い: {_forecast_text(item, forecast)}")
    if draft is not None and draft.detail and rendered is not None:
        _err(f"{item.id}: {draft.detail}")


def _agent_text(config: HandoffConfig, item: Item, approved: frozenset[tuple[str, str]]) -> str:
    """Whether ``run`` gives an item ``--agent``, or why it holds the item for its agent, for ``plan``."""
    name = config.agents.get(item.mode)
    if name is None:
        return f"--agent を付けない（config.json の agents に {item.mode} の指定がない）"
    if (name, item.mode) in approved:
        places = " と ".join(f"{directory}/" for directory in runner.AGENT_CONFIG_DIRS)
        return (
            f"--agent {name} を付ける（{APPROVALS_FILE} の承認を検証した）。run は worktree を作った後、"
            f"{places} に同じ名前の設定があれば起動しない（{runner.AGENT_SHADOWED}）"
        )
    return f"{name} は {item.mode} で承認されていない。--agent なしでは起動しない（{runner.AGENT_NOT_APPROVED}）"


def _write_executor(choice: ExecutorChoice, note: str) -> None:
    """Show the executor and every row of the executor table that applies."""
    label = choice.executor.label
    if choice.executor is Executor.THIS_SESSION:
        label += "（このセッションが行う。対象リポジトリの Kiro には渡さない）"
    _out(f"  実行者: {label}{note}")
    for reason in choice.reasons:
        _out(f"    行 {reason.number}: {reason.condition}: {'、'.join(reason.details)}")


def _scan_text(rendered: RenderedPrompt) -> str:
    """The scan result of a drawn prompt: positions and kinds only, never the matched text."""
    text = "該当なし" if not rendered.findings else f"該当 {len(rendered.findings)} 件（{_findings_text(rendered)}）"
    if rendered.over_limit:
        text += f"。本文が上限 {MAX_BODY_BYTES} バイトを超える"
    return text


def _findings_text(rendered: RenderedPrompt) -> str:
    """The findings as ``行 <n>: <kind>``, joined."""
    return "、".join(f"行 {finding.line}: {finding.kind}" for finding in rendered.findings)


def _forecast_text(item: Item, forecast: _Forecast) -> str:
    """What ``run`` would do with an item, for ``plan``."""
    later = ""
    if item.id in forecast.after:
        later = "。先に起動する項目が終わった後" if item.id in forecast.ready else "。依存先が succeeded で終わった場合"
    if item.id in forecast.start:
        return f"起動する（{forecast.start.index(item.id) + 1} 番目{later}）"
    if item.id in forecast.hold:
        reason = forecast.hold[item.id]
        note = _HOLD_NOTES.get(reason)
        text = f"needs-human にする（{reason}{later}）"
        return text + ("" if note is None else "。" + note.format(id=item.id))
    reasons = forecast.waiting.get(item.id, ())
    listed = "; ".join(f"{reason.kind}: {reason.detail}" for reason in reasons) or "選ばれない"
    return f"この run では起動しない（{listed}）"


# --------------------------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------------------------


def _run(args: argparse.Namespace, inputs: _Inputs) -> int:
    """``run``: start the named items (the module docstring)."""
    selector, named = _named_items(inputs, args)
    approvals = _agent_approvals(inputs)
    deny = _deny_terms(inputs)
    with runner.Harness.open(inputs.handoff_dir) as harness:
        context = _context(inputs, deny, approvals)
        missing = _missing_kiro_cli(inputs)
        if missing is not None:
            _err(f"kiro-cli が {missing} に見つからない。手作業で渡すための表示に切り替える（Requirement 28.21）")
            _manual_for_ready(harness, context, inputs, named)
            return EXIT_MANUAL
        harness.add_missing_items(inputs.manifest)
        loop = _RunLoop(harness, context, inputs, selector, named)
        code = loop.run()
        if loop.kiro_cli_missing:
            _err("kiro-cli を起動できなかった。手作業で渡すための表示に切り替える（Requirement 28.21）")
            _manual_for_ready(harness, context, inputs, named)
        return code


def _missing_kiro_cli(inputs: _Inputs) -> str | None:
    """The configured ``kiro_cli`` when it is not an executable file, or ``None``.

    A value that is not absolute after ``~`` expansion is left to ``command.build_kiro_invocation``,
    which refuses it, so that the item is held with that reason.
    """
    try:
        path = normalize_path(inputs.config.kiro_cli, inputs.home)
    except ValueError:
        return None
    if os.path.isfile(path) and os.access(path, os.X_OK):
        return None
    return path


class _RunLoop:
    """The items of one ``run``: chosen with ``dag.select``, started in worker threads, waited for.

    Only the main thread chooses, holds, submits and writes to standard output and standard error.
    Every item that a worker runs is in ``in_flight`` until its future is done. While it is, the
    copy of the status given to ``dag.select`` shows it ``running`` even before the runner moves it
    there, so it counts against ``max_concurrency`` and keeps its repository busy. When its record
    has reached a final state but its future is not done yet, nothing is chosen until it is, since
    the runner releases its repository only when the run returns.
    """

    def __init__(
        self,
        harness: runner.Harness,
        context: runner.RunContext,
        inputs: _Inputs,
        selector: Mapping[str, Any],
        named: tuple[Item, ...],
    ) -> None:
        """Keep the inputs of the run.

        Args:
            harness: The open harness.
            context: The inputs of the runner.
            inputs: The checked inputs.
            selector: The keyword argument for ``dag.select``.
            named: The named items, in the order of the manifest.
        """
        self.harness = harness
        self.context = context
        self.inputs = inputs
        self.selector = selector
        self.named = named
        self.limit = inputs.config.max_concurrency
        self.stop = threading.Event()
        self.attempted: set[str] = set()
        self.in_flight: dict[str, Future[runner.ItemOutcome]] = {}
        self.outcomes: dict[str, runner.ItemOutcome] = {}
        self.held: dict[str, str] = {}
        self.errors: list[runner.RunnerError] = []
        self.unexpected: list[BaseException] = []
        self.interrupted = False
        self.kiro_cli_missing = False

    def run(self) -> int:
        """Start, wait, show the results, and return the exit code.

        Raises:
            Exception: A worker failed in a way that is a fault of the harness; the other items
                were stopped and waited for first.
        """
        with _sigint_calls(self._on_interrupt):
            pool = ThreadPoolExecutor(max_workers=self.limit, thread_name_prefix="handoff-run")
            try:
                self._loop(pool)
            except BaseException:
                self.stop.set()
                raise
            finally:
                pool.shutdown(wait=True)
                self._collect()
        if self.unexpected:
            raise self.unexpected[0]
        self._summary()
        if self.interrupted:
            return EXIT_INTERRUPTED
        if self.errors:
            return _exit_code_of(self.errors[0])
        if self.held or any(outcome.state != state.SUCCEEDED for outcome in self.outcomes.values()):
            return EXIT_ITEMS
        return EXIT_OK

    def _on_interrupt(self) -> None:
        """SIGINT: start nothing more and stop the running items (only flags; nothing is written here)."""
        self.interrupted = True
        self.stop.set()

    def _loop(self, pool: ThreadPoolExecutor) -> None:
        """Choose and start items until no named item can start and none runs."""
        announced = False
        while True:
            self._collect()
            if self.stop.is_set() or self.errors or self.unexpected:
                if self.interrupted and not announced:
                    _err("中断を受けた。新しい項目を起動せず、実行中の項目を止めて終わりを待つ")
                    announced = True
                if not self.in_flight:
                    return
                self._wait()
                continue
            status = self.harness.status
            if any(
                status["items"][item_id]["state"] not in (state.QUEUED, state.RUNNING) for item_id in self.in_flight
            ):
                self._wait()
                continue
            view = status
            for item_id in self.in_flight:
                if view["items"][item_id]["state"] == state.QUEUED:
                    view = state.transition(view, item_id, state.RUNNING, at=_now(), reason=_IN_MEMORY_RUNNING)
            selection = dag.select(
                self.inputs.manifest,
                view,
                confirmed_refs=self.context.confirmed_refs,
                max_concurrency=self.limit,
                **self.selector,
            )
            fresh = [item_id for item_id in selection.selected if item_id not in self.attempted]
            if fresh:
                self._start(pool, fresh[0])
                continue
            if not self.in_flight:
                return
            self._wait()

    def _start(self, pool: ThreadPoolExecutor, item_id: str) -> None:
        """Hold a change item, or hand a query item to a worker."""
        self.attempted.add(item_id)
        item = self.inputs.by_id[item_id]
        if item.mode != "query":
            self.harness.hold(item_id, reason=CHANGE_MODE_HELD)
            self.held[item_id] = CHANGE_MODE_HELD
            note = _HOLD_NOTES[CHANGE_MODE_HELD].format(id=item_id)
            _out(f"{item_id}: needs-human（{CHANGE_MODE_HELD}）。{note}")
            return
        _out(f"開始: {item_id}（{item.repo}）")
        self.in_flight[item_id] = pool.submit(self.harness.run_query_item, self.context, item_id, stop=self.stop)

    def _wait(self) -> None:
        """Wait a short while for a running item to end; a stop request is seen at the next look."""
        if self.in_flight:
            wait(list(self.in_flight.values()), timeout=runner.POLL_SECONDS, return_when=FIRST_COMPLETED)

    def _collect(self) -> None:
        """Take the results of the items whose futures are done, and show them."""
        for item_id, future in list(self.in_flight.items()):
            if not future.done():
                continue
            del self.in_flight[item_id]
            try:
                outcome = future.result()
            except runner.RunnerError as error:
                if isinstance(error, runner.KiroCliMissing):
                    self.kiro_cli_missing = True
                self.errors.append(error)
                _err(f"{item_id}: {error}")
            except Exception as error:  # a fault of the harness: the other items are stopped, then it is raised
                self.unexpected.append(error)
                self.stop.set()
            else:
                self.outcomes[item_id] = outcome
                self._show(outcome)

    def _show(self, outcome: runner.ItemOutcome) -> None:
        """One line on standard output for an item that ended, and its detail on standard error."""
        line = f"{outcome.item_id}: {outcome.state}（{outcome.reason}）"
        if outcome.report is not None:
            line += f" report: {posixpath.relpath(outcome.report, self.inputs.handoff_dir)}"
        if outcome.worktree is not None:
            line += f" worktree: {_tilde(outcome.worktree, self.inputs.home)}"
        _out(line)
        if outcome.detail:
            _err(f"{outcome.item_id}: {outcome.detail}")

    def _summary(self) -> None:
        """Show the state of every named item after the run, and why the ones left ``queued`` did not start."""
        status = self.harness.status
        final = dag.select(
            self.inputs.manifest,
            status,
            confirmed_refs=self.context.confirmed_refs,
            max_concurrency=self.limit,
            **self.selector,
        )
        reasons = {entry.item_id: entry.reasons for entry in final.not_selected}
        _out("")
        _out(f"結果（{len(self.named)} 項目）:")
        for item in self.named:
            record = status["items"][item.id]
            last = record["history"][-1]["reason"] if record["history"] else ""
            if item.id in self.outcomes:
                outcome = self.outcomes[item.id]
                text = f"{outcome.state}（{outcome.reason}）"
            elif item.id in self.held:
                text = f"{record['state']}（{self.held[item.id]}）"
            elif record["state"] == state.QUEUED:
                if item.id in final.selected or item.id in self.attempted:
                    why = "この実行が新しい起動を打ち切った"
                else:
                    why = "; ".join(f"{reason.kind}: {reason.detail}" for reason in reasons.get(item.id, ()))
                text = f"queued（この実行では起動しなかった: {why}）"
            else:
                text = f"{record['state']}（この実行の前から。{last}）"
            _out(f"  {item.id}: {text}")
        waiting = state.waiting_on_failed_dependencies(
            status, {item.id: item.depends_on for item in self.inputs.manifest.items}
        )
        for item in self.named:
            if item.id in waiting:
                _out(f"  依存先の失敗で待機中: {item.id}（{', '.join(waiting[item.id])} が failed）")


@contextmanager
def _sigint_calls(handler: Callable[[], None]) -> Iterator[None]:
    """Make SIGINT call ``handler`` instead of raising ``KeyboardInterrupt``, in the main thread only.

    No exception then interrupts the main thread between a write of the status and the update of
    the harness's copy of it; the run loop sees the flags that the handler sets.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.signal(signal.SIGINT, lambda signum, frame: handler())
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous if previous is not None else signal.SIG_DFL)


# --------------------------------------------------------------------------------------------
# manual
# --------------------------------------------------------------------------------------------


def _manual(args: argparse.Namespace, inputs: _Inputs) -> int:
    """``manual ID``: print what the maintainer pastes by hand (Requirement 28.21)."""
    item = _item(inputs, args.item_id)
    approvals = _agent_approvals(inputs)
    deny = _deny_terms(inputs)
    with runner.Harness.open(inputs.handoff_dir) as harness:
        view = _with_records(harness.status, inputs.manifest)
        current = view["items"][item.id]["state"]
        if current not in _MANUAL_STATES:
            raise _Exit(EXIT_ITEMS, f"{item.id} is {current}; only a queued, failed or needs-human item is handed over")
        return _write_manual(harness, _context(inputs, deny, approvals), inputs, item, view)


def _manual_for_ready(
    harness: runner.Harness, context: runner.RunContext, inputs: _Inputs, named: tuple[Item, ...]
) -> None:
    """The manual display of each named item that is ``queued`` and ready, for ``run`` without ``kiro-cli``."""
    view = _with_records(harness.status, inputs.manifest)
    shown = 0
    for item in named:
        record = view["items"][item.id]
        if record["state"] != state.QUEUED:
            continue
        if not dag.ready(item, view, confirmed_refs=context.confirmed_refs):
            _err(f"{item.id}: 依存先か参照が揃っていないので表示しない。揃ったら cli.py manual {item.id}")
            continue
        if shown:
            _out("")
        _write_manual(harness, context, inputs, item, view)
        shown += 1


def _write_manual(
    harness: runner.Harness, context: runner.RunContext, inputs: _Inputs, item: Item, view: state.StatusDoc
) -> int:
    """Draw an item's prompt and print the manual display, unless it must not be handed over.

    Returns:
        0 when it was printed, 1 when it was refused (the reason is on standard error).
    """
    draft = harness.draw_prompt(context, item.id)
    rendered = draft.rendered
    if rendered is None:
        _err(f"{item.id}: 本文を描けなかったので表示しない（{draft.hold_reason}）")
        _err(draft.detail)
        return EXIT_ITEMS
    if rendered.findings:
        _err(
            f"{item.id}: 本文の走査で {len(rendered.findings)} 件に該当したので、本文を表示しない"
            f"（{_findings_text(rendered)}）。テンプレートか変数を直してから再実行する"
        )
        return EXIT_ITEMS
    if rendered.executor_choice.executor is not Executor.TARGET_REPO_KIRO:
        rows = "、".join(str(number) for number in rendered.executor_choice.rows)
        _err(f"{item.id}: 実行者はこのセッション（行 {rows}）なので、対象リポジトリの Kiro に貼り付けない")
        return EXIT_ITEMS
    plan = draft.git_plan
    if plan is None:
        _err(f"{item.id}: worktree を作るコマンドを組み立てられなかった")
        _err(draft.detail)
        return EXIT_ITEMS
    if rendered.over_limit:
        _err(f"{item.id}: 本文が {rendered.byte_length} バイトで、kiro-cli に渡す上限 {MAX_BODY_BYTES} バイトを超える")
    if draft.hold_reason == runner.AGENT_NOT_APPROVED:
        _err(
            f"{item.id}: 注意: config.json の agents.{item.mode} のエージェント設定 "
            f"{inputs.config.agents.get(item.mode)} は承認されていない。run はこの項目を起動せずに "
            f"needs-human（{runner.AGENT_NOT_APPROVED}）にする"
        )
    if os.path.lexists(plan.worktree):
        _err(
            f"{item.id}: 注意: worktree {_tilde(plan.worktree, inputs.home)} が既にあるので、手順 1 の 4 行目は失敗する。"
            f"中を確かめてから cli.py cleanup {item.id} で消す"
        )
    queued = view["items"][item.id]["state"] == state.QUEUED
    if queued and not dag.ready(item, view, confirmed_refs=context.confirmed_refs):
        selection = dag.select(
            inputs.manifest,
            view,
            confirmed_refs=context.confirmed_refs,
            max_concurrency=inputs.config.max_concurrency,
            item_ids=(item.id,),
        )
        for entry in selection.not_selected:
            for reason in entry.reasons:
                _err(f"{item.id}: 注意: {reason.kind}: {reason.detail}")
    home = inputs.home
    sentinel = "0" * 40
    words = {plan.main_tree: _shell_word(plan.main_tree, home), plan.worktree: _shell_word(plan.worktree, home)}
    words[sentinel] = "<sha>"
    steps = (plan.fetch, plan.ls_remote, plan.rev_parse, plan.worktree_add(sentinel))
    commands = [" ".join(words[arg] if arg in words else shlex.quote(arg) for arg in step.argv) for step in steps]
    if plan.branch is None:
        mode = "照会モード（`--detach` の worktree。ブランチを作らない）"
    else:
        mode = f"変更モード（引き継ぎ用ブランチ {plan.branch}）"
    lines = [
        f"手作業の引き継ぎ: {item.id}",
        "",
        f"- 貼り付ける先のリポジトリ: {item.repo}",
        f"- モード: {mode}",
        f"- メインの作業ツリー: {_tilde(plan.main_tree, home)}（読み取りだけで参照する。cwd にしない）",
        f"- 作業する worktree: {_tilde(plan.worktree, home)}",
        f"- Handoff_Prompt のファイル: {_tilde(draft.path, home)}（{rendered.byte_length} バイト）",
        "",
        "手順 1: worktree の作成",
        "",
        "次の 4 行を順に実行する。2 行目が表示した SHA が 3 行目の表示と一致したら、その値を <sha> に書いて"
        "4 行目を実行する。一致しなければ 1 行目からやり直す。",
        "",
        *(f"    {line}" for line in commands),
        "",
        "手順 2: 本文の貼り付け",
        "",
        f"作った worktree を cwd にして {item.repo} の Kiro を開き、「ここから」の行と「ここまで」の行の間を貼り付ける。"
        "結果は Handoff_Harness には記録されない。",
        "",
        "----- ここから -----",
    ]
    sys.stdout.write("\n".join(lines) + "\n" + rendered.body + "----- ここまで -----\n")
    sys.stdout.flush()
    return EXIT_OK


# --------------------------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------------------------


def _status(args: argparse.Namespace, inputs: _Inputs) -> int:
    """``status`` and ``status set``."""
    if args.status_action == "set":
        return _status_set(args, inputs)
    status = runner.read_status(inputs.handoff_dir)
    now = datetime.now(timezone.utc)
    manifest_ids = [item.id for item in inputs.manifest.items]
    ids = [item_id for item_id in manifest_ids if item_id in status["items"]]
    ids += sorted(item_id for item_id in status["items"] if item_id not in inputs.by_id)
    counts: dict[str, int] = {}
    for record in status["items"].values():
        counts[record["state"]] = counts.get(record["state"], 0) + 1
    listed = "、".join(f"{name} {counts[name]}" for name in sorted(counts))
    _out(
        f"状態ファイル: {_tilde(posixpath.join(inputs.handoff_dir, 'status.json'), inputs.home)}"
        "（ロックを取らずに読んだ）"
    )
    _out(f"項目: {len(status['items'])}" + (f"（{listed}）" if listed else ""))
    unrecorded = [item_id for item_id in manifest_ids if item_id not in status["items"]]
    if unrecorded:
        _out(f"記録のない項目（run か plan が queued として扱う）: {', '.join(unrecorded)}")
    total = 0.0
    runs = 0
    open_runs = 0
    for item_id in ids:
        record = status["items"][item_id]
        seconds, count, still = _running_time(record["history"], now)
        total += seconds
        runs += count
        open_runs += 1 if still else 0
        _status_item(inputs, item_id, record, seconds, count, still)
    waiting = state.waiting_on_failed_dependencies(status, {item.id: item.depends_on for item in inputs.manifest.items})
    _out("")
    if waiting:
        _out("依存先の失敗で待機中:")
        for item_id, failed in waiting.items():
            _out(f"  {item_id}（{', '.join(failed)} が failed）")
    else:
        _out("依存先の失敗で待機中: なし")
    note = f"、実行中の {open_runs} 件は今までの分" if open_runs else ""
    _out(f"running の時間の合計: {_duration(total)}（{runs} 回の実行{note}）")
    _out("")
    return _write_worktree_comparison(inputs, status)


def _status_item(
    inputs: _Inputs, item_id: str, record: state.ItemRecord, seconds: float, count: int, still: bool
) -> None:
    """Show one record of ``status``."""
    item = inputs.by_id.get(item_id)
    where = (
        "manifest にない" if item is None else f"{item.repo}、{_MODE_LABELS[item.mode]}、Sync_Point {item.sync_point}"
    )
    _out("")
    _out(f"{item_id}: {record['state']}（{where}）")
    if record["history"]:
        last = record["history"][-1]
        _out(f"  最後の遷移: {last['at']} {last['from']} → {last['to']}（{last['reason']}）")
    if count:
        _out(f"  running の時間: {_duration(seconds)}（{count} 回" + ("。実行中" if still else "") + "）")
    if record["pid"] is not None:
        _out(f"  pid: {record['pid']}")
    if record["worktree"] is not None:
        _out(f"  worktree: {record['worktree']}")
    if record["report"] is not None:
        _out(f"  report: {record['report']}")


def _running_time(history: Sequence[Mapping[str, str]], now: datetime) -> tuple[float, int, bool]:
    """Seconds an item spent in ``running``, the number of runs, and whether one is still open.

    Each entry that enters ``running`` starts a run, and the next entry, which leaves it, ends the
    run. A run without an end is counted up to ``now``.
    """
    total = 0.0
    runs = 0
    began: datetime | None = None
    for entry in history:
        moment = datetime.strptime(entry["at"], state.TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
        if entry["to"] == state.RUNNING:
            began = moment
            runs += 1
        elif began is not None:
            total += max(0.0, (moment - began).total_seconds())
            began = None
    if began is not None:
        total += max(0.0, (now - began).total_seconds())
    return total, runs, began is not None


def _duration(seconds: float) -> str:
    """Seconds as ``h:mm:ss``."""
    whole = int(seconds)
    return f"{whole // 3600}:{whole % 3600 // 60:02d}:{whole % 60:02d}"


def _write_worktree_comparison(inputs: _Inputs, status: state.StatusDoc) -> int:
    """Compare the worktrees that git lists below ``worktrees_root`` with the ``worktree`` fields (H6).

    Returns:
        0, or 1 when a repository's worktrees could not be listed.
    """
    root = inputs.config.worktrees_root
    root_real = os.path.realpath(root)
    listed: dict[str, tuple[str, str]] = {}
    unreadable: list[str] = []
    for name, repo in sorted(inputs.config.repos.items()):
        try:
            paths = runner.list_worktrees(repo.main_tree, timeout_seconds=inputs.config.timeout_seconds)
        except runner.GitCommandFailed as error:
            _err(f"{name}: {error}")
            unreadable.append(name)
            continue
        for path in paths:
            real = os.path.realpath(path)
            if is_within(real, root_real) and not is_within(root_real, real):
                listed.setdefault(real, (path, name))
    recorded: dict[str, tuple[str, str]] = {}
    for item_id, record in sorted(status["items"].items()):
        value = record["worktree"]
        if value is None:
            continue
        try:
            real = os.path.realpath(normalize_path(value, inputs.home))
        except ValueError:
            real = value
        recorded.setdefault(real, (item_id, value))
    _out(f"worktree と状態ファイルの照合（worktrees_root {_tilde(root, inputs.home)}）:")
    found = False
    for real, (path, name) in sorted(listed.items()):
        if real not in recorded:
            _out(f"  git にあり、状態ファイルのどの項目も指していない: {_tilde(path, inputs.home)}（{name}）")
            found = True
    for real, (item_id, value) in sorted(recorded.items()):
        if real in listed:
            continue
        item = inputs.by_id.get(item_id)
        if unreadable and (item is None or item.repo in unreadable):
            _out(f"  確かめられない: {item_id} の {value}（git の一覧を読めなかったリポジトリがある）")
        else:
            _out(f"  状態ファイルにあり、git の worktree にない: {item_id} の {value}")
        found = True
    if unreadable:
        _out(f"  一覧を読めなかったリポジトリ: {', '.join(unreadable)}")
    if not found and not unreadable:
        _out("  食い違いなし")
    return EXIT_ITEMS if unreadable else EXIT_OK


def _status_set(args: argparse.Namespace, inputs: _Inputs) -> int:
    """``status set ID queued --reason TEXT``: the maintainer's re-run (``Harness.requeue``)."""
    item = _item(inputs, args.item_id)
    reason = args.reason
    if not reason.strip() or reason.splitlines() != [reason]:
        raise _Exit(EXIT_USAGE, "--reason must be one non-blank line")
    with runner.Harness.open(inputs.handoff_dir) as harness:
        record = harness.status["items"].get(item.id)
        if record is None:
            raise _Exit(EXIT_ITEMS, f"{item.id} has no record yet; it starts as queued when run or plan adds it")
        try:
            harness.requeue(item.id, reason=reason)
        except state.TransitionError as error:
            raise _Exit(EXIT_ITEMS, f"{item.id} was not moved: {error}") from None
    _out(f"{item.id}: {record['state']} → queued（{reason}）")
    worktree = record["worktree"]
    if worktree is not None and os.path.lexists(normalize_path(worktree, inputs.home)):
        _out(
            f"  注意: worktree {worktree} が残っている。run は worktree_exists で needs-human にするので、"
            f"先に cli.py cleanup {item.id} で消す"
        )
    return EXIT_OK


# --------------------------------------------------------------------------------------------
# cleanup
# --------------------------------------------------------------------------------------------


def _cleanup(args: argparse.Namespace, inputs: _Inputs) -> int:
    """``cleanup ID [--approved]``: list what would be removed; remove the worktree only when approved."""
    item = _item(inputs, args.item_id)
    if args.approved:
        with runner.Harness.open(inputs.handoff_dir) as harness:
            return _cleanup_with(inputs, item, harness.status, harness)
    return _cleanup_with(inputs, item, runner.read_status(inputs.handoff_dir), None)


def _cleanup_with(inputs: _Inputs, item: Item, status: state.StatusDoc, harness: runner.Harness | None) -> int:
    """List the item's worktree and branch, then remove the worktree when ``harness`` is given."""
    plan = command.build_git_plan(inputs.config, item)
    home = inputs.home
    record = status["items"].get(item.id)
    current = "記録なし" if record is None else record["state"]
    timeout = inputs.config.timeout_seconds
    try:
        registered = any(
            os.path.realpath(path) == os.path.realpath(plan.worktree)
            for path in runner.list_worktrees(plan.main_tree, timeout_seconds=timeout)
        )
    except runner.GitCommandFailed as error:
        raise _Exit(EXIT_ITEMS, f"{item.id}: the worktrees of {item.repo} could not be listed: {error}") from None
    named = None if record is None else record["worktree"]
    _out(f"cleanup: {item.id}（{item.repo}、{_MODE_LABELS[item.mode]}、状態 {current}）")
    _out("消す対象:")
    facts = [
        "git に登録あり" if registered else "git に登録なし",
        "ディレクトリあり" if os.path.lexists(plan.worktree) else "ディレクトリなし",
        "状態ファイルが指している" if named is not None else "状態ファイルは指していない",
    ]
    _out(f"  worktree: {_tilde(plan.worktree, home)}（{'、'.join(facts)}）")
    main_word = _shell_word(plan.main_tree, home)
    if plan.branch is None:
        _out("  ブランチ: なし（照会モードの worktree は --detach で作る）")
    else:
        try:
            exists = runner.branch_exists(plan.main_tree, plan.branch, timeout_seconds=timeout)
            known = "ある" if exists else "ない"
        except runner.GitCommandFailed as error:
            _err(f"{item.id}: {error}")
            known = "確かめられなかった"
        _out(f"  ブランチ: {plan.branch}（{known}。PR のマージ後に消す。この段階では消さない）")
    _out("コマンド:")
    _out(f"  git -C {main_word} worktree remove {_shell_word(plan.worktree, home)}")
    if plan.branch is not None:
        _out(
            f"  PR のマージ後: git -C {main_word} branch -d {shlex.quote(plan.branch)}"
            "（squash マージで -d が拒否したら -D を使う。どちらも承認を得てから）"
        )
    _out(f"Handoff_Report と Handoff_Prompt は残す（{_tilde(inputs.handoff_dir, home)} の下）")
    if not registered:
        if os.path.lexists(plan.worktree):
            _out("git の worktree ではないディレクトリなので、cleanup は消さない。中を確かめてから手で消す")
        else:
            _out("消す worktree はない")
        return EXIT_OK
    if record is not None and record["state"] == state.RUNNING:
        raise _Exit(EXIT_ITEMS, f"{item.id} is running; its worktree is not removed")
    if harness is None:
        _out(f"何も消していない。消すには cli.py cleanup {item.id} --approved を実行する")
        return EXIT_OK
    result = harness.remove_worktree(item, config=inputs.config, home=home)
    if not result.ok:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        _err(f"{item.id}: git worktree remove は消さなかった（終了コード {result.exit_code}）")
        if stderr:
            _err(stderr)
        return EXIT_ITEMS
    _out(f"消した: {_tilde(plan.worktree, home)}（状態ファイルの events に記録した）")
    return EXIT_OK


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------


_SUBCOMMANDS: Final[Mapping[str, Callable[[argparse.Namespace, _Inputs], int]]] = {
    "plan": _plan,
    "run": _run,
    "manual": _manual,
    "status": _status,
    "cleanup": _cleanup,
}


def _exit_code_of(error: runner.RunnerError) -> int:
    """The exit code of a runner error (the table in the module docstring)."""
    if isinstance(error, (runner.LockHeld, runner.LockUnreadable, runner.StatusUnreadable)):
        return EXIT_HARNESS
    if isinstance(error, runner.LoginRequired):
        return EXIT_LOGIN
    if isinstance(error, (runner.DiskSpaceLow, runner.UnsafeLocation, runner.DenyListUnavailable)):
        return EXIT_ENVIRONMENT
    if isinstance(error, runner.KiroCliMissing):
        return EXIT_MANUAL
    return EXIT_ITEMS


def _state_text(record: state.ItemRecord) -> str:
    """A record's state, with its last transition when it has one."""
    if not record["history"]:
        return record["state"]
    last = record["history"][-1]
    return f"{record['state']}（{last['at']}、{last['reason']}）"


def _now() -> str:
    """The current moment in ``state.TIMESTAMP_FORMAT``."""
    return state.format_timestamp(datetime.now(timezone.utc))


def _tilde(path: str, home: str) -> str:
    """Write a path under the home directory as ``~/...``; other paths as they are."""
    if path == home:
        return "~"
    if path.startswith(home.rstrip("/") + "/"):
        return "~" + path[len(home.rstrip("/")) :]
    return path


def _shell_word(path: str, home: str) -> str:
    """A path as one shell word in which ``~`` still expands, as the prompt's section 6 writes it."""
    shown = _tilde(path, home)
    if shown == "~":
        return shown
    if shown.startswith("~/"):
        return "~/" + shlex.quote(shown[2:])
    return shlex.quote(shown)


def _out(text: str) -> None:
    """One line on standard output, flushed so that a long run shows its progress."""
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def _err(text: str) -> None:
    """Text on standard error, ending with a newline."""
    sys.stderr.write(text if text.endswith("\n") else text + "\n")
    sys.stderr.flush()


class _StderrHandler(logging.Handler):
    """Write log records to the ``sys.stderr`` of the moment, which a test may have replaced."""

    def emit(self, record: logging.LogRecord) -> None:
        """Write one record.

        Args:
            record: The record.
        """
        try:
            sys.stderr.write(self.format(record) + "\n")
        except Exception:  # logging must not end the command
            self.handleError(record)


@contextmanager
def _stderr_logging() -> Iterator[None]:
    """Send the warnings of the ``handoff`` loggers (``handoff.runner``) to standard error while a command runs."""
    logger = logging.getLogger("handoff")
    handler = _StderrHandler(logging.WARNING)
    handler.setFormatter(logging.Formatter("handoff: %(levelname)s: %(message)s"))
    level, propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    if level == logging.NOTSET or level > logging.WARNING:
        logger.setLevel(logging.WARNING)
    logger.propagate = False
    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
        logger.propagate = propagate


if __name__ == "__main__":
    sys.exit(main())

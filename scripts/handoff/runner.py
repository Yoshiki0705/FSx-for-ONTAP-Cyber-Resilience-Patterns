"""Run Handoff items: the I/O layer of the Handoff_Harness, for the query and change modes.

Task 2.2 of the phase 4 spec. Design section 20 describes what this module carries out: one
harness at a time ("同時実行と排他"), the checks before an item starts (``kiro-cli whoami``
and free disk space, H1 and H7), the worktree of decision D-15, the ``kiro-cli`` run and its
timeout (H2), the Handoff_Report, the observations of "結果の確認" for a query item and a
change item, and the status file (H12). Requirements 28.5, 28.6, 28.8, 28.13, 28.18, 28.19 and 28.22. The pure core
builds every command and path and decides every state; this module starts the processes, reads
and writes the files, and records what happened. With ``cli.py`` it is the I/O layer of
``handoff/__init__.py``.

Division of work with ``cli.py`` (task 2.3). ``cli.py`` parses the command line; reads and
checks ``config.json`` and ``manifest.json`` (exit code 2, before any other I/O); reads the
deny lists with :func:`load_deny_terms`; checks the approvals of ``agents/approved.json``
against the agent configurations they name and passes those that pass as
:attr:`RunContext.approved_agents`; opens the harness with :meth:`Harness.open`; adds the
records of new items with :meth:`Harness.add_missing_items`; chooses items with
``dag.select`` on :attr:`Harness.status`; holds a change item whose selftest does not count with
:meth:`Harness.hold` (task 5.2); runs each selected query item with
:meth:`Harness.run_query_item` and each other selected change item with
:meth:`Harness.run_change_item`; and shows the outcomes. It stops starting items on
:class:`LoginRequired`, :class:`DiskSpaceLow` and :class:`UnsafeLocation`, and turns to the
manual mode on :class:`KiroCliMissing`. For its other subcommands it draws prompts with
:meth:`Harness.draw_prompt` (``plan``, ``manual``), reads the status without the lock with
:func:`read_status` and lists worktrees with :func:`list_worktrees` (``status``, ``cleanup``),
removes an approved worktree with :meth:`Harness.remove_worktree` (``cleanup --approved``), and
finds the main working tree that holds ``.private/handoff`` with :func:`harness_tree_of`. Every
write to ``.private/handoff/``, every process and every change of ``status.json`` happens here.

One query item (:meth:`Harness.run_query_item`), in this order. A step that fails moves the
item from ``queued`` to ``needs-human`` with a short reason, unless the step says otherwise:

1. The Handoff_Prompt path: an item whose path (``command.handoff_files``) is also the path of
   another item of the manifest is held, and the file is not written, so that neither item's
   prompt overwrites the other's.
2. The template, read from ``.private/handoff/<template>``; then ``git status`` of the target
   repository's main working tree, for the uncommitted count of ``prompt.render``; then the
   prompt is drawn and scanned, and written to its path, held or not. A held prompt (scan
   findings, over the size limit), a prompt whose executor is this session (only rows 5 and 6
   of the executor table apply: ``executor_is_this_session``, since this session carries such
   an item out), any refusal of ``command.build_kiro_invocation`` or
   ``command.build_git_plan``, and an agent configuration that ``agents.<mode>`` of the
   configuration names for the item's mode without an approval for that mode in
   :attr:`RunContext.approved_agents` (``agent_not_approved``; the item is not started with the
   default agent instead) hold the item, in this order. An approved agent is given to
   ``command.build_kiro_invocation`` for the item's own mode only, so the argv gets
   ``--agent <name>``. :meth:`Harness.draw_prompt` carries out steps 1 and 2 alone, for
   ``cli.py plan`` and ``manual``, and changes no state.
3. ``kiro-cli whoami`` in the environment of ``command.child_env``, the one the run gets. A
   failure raises :class:`LoginRequired` (or :class:`KiroCliMissing`) and leaves the item
   ``queued`` (Requirement 28.18).
4. Free space below ``worktrees_root``: under ``min_free_disk_bytes`` raises
   :class:`DiskSpaceLow` before any worktree exists, and the item stays ``queued``.
5. The places, resolved with ``os.path.realpath``: ``worktrees_root`` must not meet a main
   working tree of ``repos``, this repository's main working tree or the IDE session worktree
   directory, and the worktree must stay below ``worktrees_root``, so it cannot meet one
   either. A problem raises :class:`UnsafeLocation`; the item stays ``queued``.
6. Decision D-15 with the argv of ``command.build_git_plan`` only: ``fetch``, ``ls-remote``,
   ``rev-parse``. When the SHA of the line ``refs/heads/main`` of ``ls-remote`` differs from
   ``rev-parse``, the three run once more; a second difference holds the item. Then
   ``worktree add --detach`` with that SHA. An existing worktree path holds the item before any
   git command runs: a worktree of an earlier run is kept until ``cli.py cleanup``. When the
   argv has ``--agent <name>``, the new worktree is then searched (:func:`_agent_shadows`):
   kiro-cli prefers a workspace's agent configuration to the global one of the same name, so a
   configuration of that name in ``.kiro/agents/`` or ``.amazonq/cli-agents/`` holds the item
   (``agent_shadowed``). ``kiro-cli`` does not start, and the worktree is kept.
7. A snapshot of the main working tree (``HEAD``, branch, ``git status``), the move to
   ``running`` (reason ``dispatched``), and ``kiro-cli`` with the argv of
   ``command.build_kiro_invocation``. Its PID goes into the record once it runs.
8. When it ends, in any way, the whole of its standard output and standard error goes to the
   Handoff_Report first. Then the observations: the snapshot again, ``git status`` of the
   worktree, and the worktree's ``HEAD``. ``evaluate.final_state`` decides the state from them.
   A query item writes nothing, so its worktree should stay at the base SHA: when its ``HEAD``
   moved, the commits and the changed files are counted, and every changed file is undeclared.
   The report is written again with the observations and the final state.

One change item (:meth:`Harness.run_change_item`, task 5.3) goes through the same steps, with the
same lock, ``whoami``, ``command.child_env``, process group, timeout, report and stop request,
and these differences. Step 6 first holds the item when the branch ``handoff/<id>`` exists
(``branch_exists``), then makes it with ``worktree add -b`` (which would fail on an existing branch
too, so an earlier run's branch is never reset) and gives it ``origin/main`` as its upstream with
``branch --set-upstream-to``; the branch goes into the record with the worktree. When the repository
has ``prerequisites`` (``config.Prerequisites``), the step before it holds the item if a path is not
usable (``prerequisite_missing``, before any worktree exists), the step after it copies the
``copy_readonly`` paths into the worktree only where git ignores them
(``prerequisite_not_ignored``), and ``PATH`` of ``kiro-cli`` and of the re-runs starts with the
``path_prepend`` directories. ``cleanup --approved`` removes the copies with the worktree, then
deletes the branch if it still points at the recorded ``base_sha`` (:meth:`Harness.remove_empty_branch`). ``command.build_kiro_invocation`` refuses a change item without
a ``guards_active`` selftest, so such an item is held at step 2 (``cli.py run`` holds it earlier,
task 5.2). Step 8 observes what design section 20 lists for the change mode, in its order, with
``base_sha`` in the place of ``origin/main`` for steps 1 and 2 (``origin/main`` of the main working
tree can move while the item runs; the base cannot):

- The worktree's ``HEAD`` must be on ``handoff/<id>`` (otherwise ``observation_failed``, since only
  that branch is handed over). Its SHA is read once, and steps 1 and 2 use it.
- Step 1, the commits and their subjects since the base; step 2, the files changed since the base;
  step 3, ``git status`` of the worktree; step 4, the changed files outside the declared ones.
- Step 5, the conflict check: ``git -C <main> fetch --no-tags origin main`` (the plan's ``fetch``),
  ``origin/main`` read with the plan's ``rev-parse``, and the files of
  ``git diff --name-only <base_sha> <origin/main>``, compared with the changed files by
  ``evaluate.conflicting_files``. The other handoff branches of a batch are not compared (no batch
  is passed). The Handoff_Report lists the default branch's files and the conflicts.
- Step 6, the re-run of the declared verification commands, in their declared order. A command
  that ``manifest.rerun_skip_reason`` does not allow (``offline: false``, or a pattern such as
  ``git push``) is not run, and its reason goes to ``rerun_skipped``. None runs when the run cannot
  end ``succeeded`` from what steps 1 to 4 and ``kiro-cli``'s ending show (``timed_out``,
  ``exit_code_nonzero``, ``no_commits``, ``dirty``, ``undeclared_files``): the worktree then holds
  work that is unfinished, uncommitted or not declared, and the harness does not run its code;
  each command gets that reason instead. The others run one at a time in the worktree, in the
  environment of ``command.child_env`` with new temporary paths for each (``kiro-cli`` could have
  written into its own), with ``timeout_seconds``, a process group and the stop request, as
  ``kiro-cli`` does. The exit code goes to ``rerun``; a command that passed its time limit gets its
  exit code when that is not 0 (a signal gives a negative one). A command that cannot start, or
  that passed its time limit and still exited 0 or was not reaped, ends the observation
  (``observation_failed``), since no exit code can stand for it. The whole output of each goes to
  the Handoff_Report. When a command ran, the worktree is read again: ``HEAD`` must still be on
  ``handoff/<id>`` at the SHA of steps 1 and 2 (otherwise ``observation_failed``: the branch would
  hand over commits that were not observed), and ``git status`` that is no longer empty makes
  ``dirty`` true (what was verified is then not what was committed).
- Step 7, the handoff branch on the remote with
  ``git -C <main> ls-remote origin refs/heads/handoff/<id>``, after the re-runs.
- Step 8, the main working tree before ``kiro-cli`` and after the re-runs.

A stop request during the observation (the fetch or a re-run) ends the item ``failed``
(``harness_interrupted``), as one during ``kiro-cli`` does.

Processes. Every process is started with an argv, ``shell=False``, ``stdin`` from
``/dev/null`` and ``start_new_session=True``, so that it leads a process group of its own, and
its standard output and standard error are read together (``Popen.communicate``), so a
process that fills one pipe while the other is drained does not stop. A process that outlives
its time limit, or a stop request, gets SIGTERM to its whole group, and SIGKILL once
:attr:`RunContext.kill_grace_seconds` (10 by default, design H2) have passed while a member of
the group remains. A group that still has members after its leader exits gets the same
treatment, so no process of a run is left behind. Bytes are decoded once, whole, with
``errors="replace"``. ``kiro-cli`` and ``kiro-cli whoami`` run in the environment of
``command.child_env`` (layer 3), whose temporary paths (an empty ``gh/``, an empty
``aws-empty`` and a ``no-such-remote`` that is never created) live in one new temporary
directory per item, removed afterwards. Every other process is git, run in
:func:`git_environment`. Every process has the time limit ``timeout_seconds`` of the
configuration.

Files. Everything goes below this repository's ``.private/handoff/``. Before each write, the
path is checked lexically and with ``os.path.realpath``, so that a symbolic link cannot carry a
write elsewhere, and ``.private/handoff`` itself must not be reached through one. Each file is
written to a temporary file in its directory and moved over the old one with ``os.replace``.
Before ``status.json`` is replaced, its previous content is written to ``status.json.bak``.
A new run of an item renames the earlier ``report.md`` to ``report.<n>.md`` (``n`` from 1,
the smallest unused) rather than overwriting it: the report of a failed run is the only copy
of what ``kiro-cli`` wrote. Files are created with mode 0600 (``tempfile.mkstemp``).

The lock. ``.private/handoff/.lock`` is created with ``O_CREAT | O_EXCL`` and holds the PID
and the start time of the harness as JSON. A lock whose PID does not exist is removed and
recorded in ``events`` of ``status.json`` (``stale_lock_removed``). The check of an existing
lock and its removal run under ``flock`` on the ``.private/handoff`` directory, so that two
harnesses that start together cannot both remove one stale lock and both create their own.
At every start, each ``running`` record whose PID is not a live process that leads its own
session (every ``kiro-cli`` is started that way) moves to ``failed`` with reason
``harness_interrupted``, also when the manifest does not have it; the worktree is kept. The
session test keeps a reused PID from passing for a ``kiro-cli`` that has ended.

Threads. :class:`Harness` changes ``status.json`` under a lock of its own, and
:meth:`Harness.run_query_item` refuses to start an item while another item of its repository
runs in this harness or is ``running`` in the status. So ``cli.py`` may run items of different
repositories in worker threads. A ``KeyboardInterrupt`` reaches the main thread only; a worker
thread is asked to stop with the ``stop`` event, which stops ``kiro-cli`` as an interrupt does.

The selftest (task 5.2). :meth:`Harness.run_selftest` runs trials T0 to T4 of design section 20
in throwaway repositories below ``<worktrees_root>/selftest/<run ID>/``, each with its own bare
repository, and starts each trial's ``kiro-cli`` the way an item's starts (the environment of
``command.child_env``, a process group, ``timeout_seconds``), with ``HANDOFF_GUARD_LOG`` added. The
pure core builds the argv (``command.build_selftest_invocation``) and decides each outcome
(``evaluate.trial_outcome``) and the result (``evaluate.selftest_verdict``); the runner makes the
repositories, reads the effects with its own git, lists each trial's bare repository with
``git ls-remote`` after the trials (task 5.8), and writes the record
``.private/handoff/selftest/<run ID>.json``, the output of each trial next to it, and ``selftest``
of ``status.json``. :func:`kiro_fingerprint` gives the ``kiro-cli`` version and ``config_sha256``
that a result is tied to.

Not done here yet: the publish mode (task 5.4).
"""

from __future__ import annotations

import copy
import fcntl
import json
import logging
import math
import os
import posixpath
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Final, Literal, TypeAlias

from handoff import command, evaluate, kiro_errors, prompt, scan, state
from handoff.config import HandoffConfig, Prerequisites, is_within, normalize_path, overlaps
from handoff.executor import Executor
from handoff.manifest import Item, Manifest, RequiredRef, VerifyCommand, rerun_skip_reason

_LOG: Final = logging.getLogger(__name__)

#: The lock file, directly below ``.private/handoff/``.
LOCK_FILE: Final = ".lock"

#: The copy of the previous ``status.json``, next to it.
STATUS_BACKUP_FILE: Final = command.STATUS_FILE + ".bak"

#: Seconds between SIGTERM to a process group and SIGKILL to what remains of it (design H2).
KILL_GRACE_SECONDS: Final = 10.0

#: Seconds between two looks at a running process, a stop request or a process group.
POLL_SECONDS: Final = 0.2

#: The history reason of the move to ``running``.
DISPATCHED: Final = "dispatched"

#: The history reason of the move to ``running`` for ``cli.py verify``: the observation of a worktree
#: that the maintainer made by hand (Requirement 28.21).
MANUAL_VERIFY: Final = "manual_verify"

#: The history reason of a ``running`` item whose harness ended without finishing it.
HARNESS_INTERRUPTED: Final = "harness_interrupted"

#: The kind of the event recorded for a run whose ``kiro-cli`` exited with a code other than 0 and whose
#: standard error names a known error (task 5.9), by the label of ``kiro_errors``. A note for the maintainer:
#: the final state and its reason are not changed by it (Property 28).
KIRO_ERROR_EVENTS: Final = {
    kiro_errors.USAGE_LIMIT: "kiro_cli_usage_limit",
    kiro_errors.PROFILE_REQUIRED: "kiro_cli_profile_required",
}
#: The kind of the event recorded when a stale lock is removed.
STALE_LOCK_REMOVED: Final = "stale_lock_removed"

#: The kind of the event recorded when ``cli.py cleanup --approved`` removed a worktree.
WORKTREE_REMOVED: Final = "worktree_removed"
#: The kind of the event recorded when ``cli.py cleanup --approved`` deleted an item's empty branch.
BRANCH_REMOVED: Final = "branch_removed"
#: The kind of the event recorded when :meth:`Harness.publish_batch` holds an item back (task 5.4).
PUBLISH_HELD: Final = "publish_held"
#: The kind of the event recorded when :meth:`Harness.publish_batch` ends (task 5.4).
PUBLISH_BATCH: Final = "publish_batch"
#: Reasons of a publish outcome besides ``published`` and the exclusion reasons of ``command.build_publish_plan``.
PUBLISH_SCAN_FINDINGS: Final = "publish_scan_findings"
PUBLISH_SCAN_FAILED: Final = "publish_scan_failed"
PUBLISH_CONFLICTS: Final = "publish_conflicts"
PUBLISH_SHA_MISMATCH: Final = "publish_sha_mismatch"
PUBLISH_NOT_READ: Final = "publish_not_read"
PUBLISH_PUSH_FAILED: Final = "publish_push_failed"
PUBLISH_PR_FAILED: Final = "publish_pr_failed"
PUBLISH_NO_REPOSITORY: Final = "publish_no_github_repository"
#: The remote URLs of GitHub that :func:`github_repo_of` reads: ``OWNER/NAME`` is the path.
_GITHUB_URL: Final = re.compile(
    r"(?:https://(?:[^/@]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)"
    r"([A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+?)(?:\.git)?/?"
)
_PULL_REQUEST_URL: Final = re.compile(r"/pull/([0-9]+)\s*\Z")
#: Characters of the text of a pull request's checks kept in ``published.ci.output``.
_CI_OUTPUT_LIMIT: Final = 2000

#: The history reason of an item whose drawn prompt names this session as its executor: only
#: rows 5 and 6 of the executor table apply, so the prompt is not passed to the target
#: repository's Kiro (design section 20, "実行者の判定").
EXECUTOR_IS_THIS_SESSION: Final = "executor_is_this_session"

#: The history reason of an item whose mode names an agent configuration (``agents`` of
#: ``config.json``) that has no approval for that mode in :attr:`RunContext.approved_agents`.
#: The item is held rather than started with the default agent (task 2.5).
AGENT_NOT_APPROVED: Final = "agent_not_approved"

#: The history reason of an item whose worktree holds an agent configuration of the name given
#: with ``--agent``, which kiro-cli would read instead of the approved global one (task 2.5).
AGENT_SHADOWED: Final = "agent_shadowed"

#: The conditions of ``evaluate.final_state`` that, once steps 1 to 4 show one, keep a change run
#: from running the declared verification commands (step 6, the module docstring): the worktree
#: then holds work that is unfinished, uncommitted or not declared.
RERUN_BLOCKERS: Final[tuple[evaluate.Condition, ...]] = (
    "timed_out",
    "exit_code_nonzero",
    "no_commits",
    "dirty",
    "undeclared_files",
)

#: The note of a stop request that came while a run was observed (the fetch or a re-run).
STOPPED_WHILE_OBSERVING: Final = "観測の途中（衝突の確認の fetch か検証コマンドの再実行）で停止の依頼を受けて止めた"

#: The directories of a workspace, relative to its root, where an agent configuration could take
#: the place of the global one in ``~/.kiro/agents/``. kiro-cli's documentation names
#: ``.kiro/agents/`` and says that it wins over a global configuration of the same name. kiro-cli
#: also looked for ``.amazonq`` in its verbose log (task 2.5); whether it reads agents from
#: ``.amazonq/cli-agents/``, the Amazon Q Developer CLI's place, has not been confirmed, so that
#: directory is searched too.
AGENT_CONFIG_DIRS: Final[tuple[str, ...]] = (".kiro/agents", ".amazonq/cli-agents")

#: The most bytes of a file in :data:`AGENT_CONFIG_DIRS` whose ``name`` field is read. A larger
#: ``.json`` file counts as a configuration of the name looked for, since its name is unknown.
AGENT_FILE_LIMIT: Final = 1 << 20

#: Seconds allowed for :func:`harness_tree_of`, which runs before ``config.json`` (and its
#: ``timeout_seconds``) is read. ``git rev-parse`` reads local files only.
LOCATE_TIMEOUT_SECONDS: Final = 60

#: The customer-name list that the PreToolUse guard ``guard_customer_names.py`` reads.
#: ``cli.py`` expands ``~`` before it calls :func:`load_deny_terms`.
CUSTOMER_TERMS_FILE: Final = "~/.kiro/hooks/private/customer-terms.txt"

#: The deny terms of the phase 4 research (speakers' names and the like), relative to this
#: repository's main working tree. It may not exist yet.
EXTRA_TERMS_FILE: Final = ".private/research/phase4/deny-terms.txt"

#: The ref whose SHA ``ls-remote`` must print (decision D-15).
REMOTE_MAIN_REF: Final = f"refs/heads/{command.BASE_BRANCH}"

#: Variables of the harness's environment that :func:`git_environment` drops: each points git
#: at another repository or carries configuration, and git sets some of them for its hooks.
#: ``GIT_CONFIG_GLOBAL`` and ``GIT_CONFIG_NOSYSTEM`` are kept.
RUNNER_GIT_DROPPED: Final[frozenset[str]] = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
    }
)

#: Prefixes of the variables that :func:`git_environment` drops as well.
RUNNER_GIT_DROPPED_PREFIXES: Final[tuple[str, ...]] = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")

#: How a process ended: by itself, at its time limit, on a stop request, on a
#: ``KeyboardInterrupt`` of the harness, or not at all because it could not start.
Ending: TypeAlias = Literal["exited", "timed_out", "stopped", "interrupted", "not_started"]

#: The directory below ``.private/handoff/`` of the selftest records (``<run ID>.json``) and of
#: the output of each trial's ``kiro-cli`` (``<run ID>/<trial>.stdout`` and ``.stderr``).
SELFTEST_RECORD_DIR: Final = "selftest"

#: The version of a selftest record.
SELFTEST_RECORD_SCHEMA: Final = 1

#: The local git settings of both repositories of a selftest trial, besides ``core.hooksPath``:
#: a made-up committer, and no signing, so that the commits of T0 to T4 need nothing of this
#: machine's git configuration.
SELFTEST_GIT_SETTINGS: Final[tuple[tuple[str, str], ...]] = (
    ("user.name", "handoff-selftest"),
    ("user.email", "handoff-selftest@example.com"),
    ("commit.gpgSign", "false"),
)

#: ``README.md`` of the one commit that each trial's repository starts with.
_SELFTEST_README: Final = b"# Handoff_Harness selftest\n\nA throwaway repository of one selftest trial.\n"

#: Lines of a process's standard error kept in the detail of a failed step.
_STDERR_TAIL_LINES: Final = 20

#: The mode of a run, as the table of the Handoff_Report writes it.
_REPORT_MODES: Final[Mapping[str, str]] = {"query": "照会（`query`）", "change": "変更（`change`）"}

_BACKTICKS: Final = re.compile(r"`+")
_OBJECT_ID: Final = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


class RunnerError(RuntimeError):
    """The runner did not start, or stopped. The items it did not start keep their state."""


class LockHeld(RunnerError):
    """Another Handoff_Harness holds ``.private/handoff/.lock`` (design H5).

    Attributes:
        path: The lock file.
        pid: The PID that the lock names, a process that exists.
        started_at: When that harness started, as its lock says.
    """

    def __init__(self, path: str, pid: int, started_at: str) -> None:
        """Build the error.

        Args:
            path: The lock file.
            pid: The PID that the lock names.
            started_at: The start time that the lock names.
        """
        super().__init__(
            f"another Handoff_Harness (pid {pid}, started {started_at}) holds {path}; run again after it ends"
        )
        self.path = path
        self.pid = pid
        self.started_at = started_at


class LockUnreadable(RunnerError):
    """The lock file exists and does not name a process, so the runner cannot tell whether it is stale."""


class StatusUnreadable(RunnerError):
    """``status.json`` cannot be read as a status. Nothing starts until the maintainer repairs it."""


class DenyListUnavailable(RunnerError):
    """A deny list that the scan needs is missing, unreadable or empty (:func:`load_deny_terms`)."""


class LoginRequired(RunnerError):
    """``kiro-cli whoami`` did not succeed. No item starts until the maintainer logs in (Requirement 28.18)."""


class KiroCliMissing(RunnerError):
    """``kiro-cli`` cannot be started. ``cli.py`` turns to the manual mode (Requirement 28.21)."""


class DiskSpaceLow(RunnerError):
    """Free disk space below ``worktrees_root`` is under ``min_free_disk_gb`` (design H7).

    Attributes:
        path: The existing directory whose file system was measured.
        free_bytes: Free bytes, as ``shutil.disk_usage`` reported them.
        required_bytes: ``min_free_disk_bytes`` of the configuration.
    """

    def __init__(self, path: str, free_bytes: int, required_bytes: int) -> None:
        """Build the error.

        Args:
            path: The measured directory.
            free_bytes: Free bytes.
            required_bytes: Required bytes.
        """
        super().__init__(
            f"{free_bytes} bytes are free on the file system of {path}, under min_free_disk_gb "
            f"({required_bytes} bytes); no worktree was created. Remove worktrees that are no longer needed "
            "with cli.py cleanup, then run again"
        )
        self.path = path
        self.free_bytes = free_bytes
        self.required_bytes = required_bytes


class UnsafeLocation(RunnerError):
    """A path that the runner would write, or a worktree it would create, resolves to a place it must not use."""


class GitCommandFailed(RunnerError):
    """A git command that the runner ran for ``cli.py`` (outside a run of an item) did not succeed.

    The message names the command, how it ended and the end of its standard error; it can hold
    local paths.
    """


class SelftestRefused(RunnerError):
    """The selftest did not start: the configuration cannot build its trials (``cli.py`` exit code 2).

    ``repos`` has a repository called ``selftest``, ``agents.change`` has no approval, or another
    refusal of ``command.build_selftest_invocation``. Nothing was started or written.
    """


class VerifyRefused(RunnerError):
    """:meth:`Harness.verify_manual` did not accept the worktree or the item (``cli.py`` exit code 1).

    The message says which check failed. Nothing was changed: the item keeps its state.
    """


@dataclass(frozen=True, slots=True)
class DenyTerms:
    """The deny terms that ``prompt.render`` scans a body with, and what to tell about their lists.

    Attributes:
        terms: Every term of both lists, in file order, the customer list first.
        notes: One line per list for the Handoff_Report: where it was read and how many terms it
            gave, or that it was not found. No term is repeated in a note.
    """

    terms: tuple[str, ...]
    notes: tuple[str, ...]

    def __post_init__(self) -> None:
        """Check that both fields are tuples of strings."""
        for name in ("terms", "notes"):
            value = getattr(self, name)
            if type(value) is not tuple or not all(type(entry) is str for entry in value):
                raise TypeError(f"{name} must be a tuple of str")


@dataclass(frozen=True, slots=True)
class RunContext:
    """What a run of items needs besides the harness: the checked inputs that ``cli.py`` gathered.

    Attributes:
        config: The configuration that ``config.parse_config`` returned.
        manifest: The manifest that ``manifest.parse_manifest`` returned with ``config``.
        home: The absolute home directory, in normal form. ``kiro_cli`` and the paths of the
            prompt are expanded and written with it.
        harness_tree: This repository's main working tree, absolute and in normal form, the
            one that holds ``.private/handoff/``. Protected like the main working trees of
            ``repos``.
        session_worktrees_dir: The IDE sessions' worktree directory, absolute and in normal
            form. Protected as well.
        deny: The deny terms, from :func:`load_deny_terms`.
        confirmed_refs: The refs that the IN-2 check confirmed. A query item requires none.
        approved_agents: ``(name, mode)`` pairs: the agent configurations whose approval in
            ``agents/approved.json`` passed the checks of ``cli.py`` for that mode when the
            command started. An item gets ``--agent <name>`` only when ``agents.<mode>`` of
            the configuration names ``name`` for the item's mode and the pair is here; when
            the mode names an agent and the pair is not here, the item is held
            (:data:`AGENT_NOT_APPROVED`).
        kill_grace_seconds: Seconds from SIGTERM to SIGKILL. A test may shorten it.
    """

    config: HandoffConfig
    manifest: Manifest
    home: str
    harness_tree: str
    session_worktrees_dir: str
    deny: DenyTerms
    confirmed_refs: frozenset[RequiredRef] = frozenset()
    approved_agents: frozenset[tuple[str, str]] = frozenset()
    kill_grace_seconds: float = KILL_GRACE_SECONDS

    def __post_init__(self) -> None:
        """Check the types and the forms of the fields."""
        if not isinstance(self.config, HandoffConfig):
            raise TypeError(f"config must be a HandoffConfig, not {type(self.config).__name__}")
        if not isinstance(self.manifest, Manifest):
            raise TypeError(f"manifest must be a Manifest, not {type(self.manifest).__name__}")
        if not isinstance(self.deny, DenyTerms):
            raise TypeError(f"deny must be DenyTerms, not {type(self.deny).__name__}")
        for name in ("home", "harness_tree", "session_worktrees_dir"):
            if not _is_normal_absolute(getattr(self, name)):
                raise ValueError(f"{name} must be an absolute path in normal form, got {getattr(self, name)!r}")
        refs = frozenset(self.confirmed_refs)
        if not all(isinstance(ref, RequiredRef) for ref in refs):
            raise TypeError("confirmed_refs must hold RequiredRef only")
        agents = frozenset(self.approved_agents)
        if not all(
            type(pair) is tuple and len(pair) == 2 and all(type(part) is str for part in pair) for pair in agents
        ):
            raise TypeError("approved_agents must hold (name, mode) pairs of str only")
        object.__setattr__(self, "confirmed_refs", refs)
        object.__setattr__(self, "approved_agents", agents)
        grace = self.kill_grace_seconds
        if type(grace) not in (int, float) or not math.isfinite(grace) or grace <= 0:
            raise ValueError(f"kill_grace_seconds must be a finite number above 0, got {grace!r}")


@dataclass(frozen=True, slots=True)
class StaleLock:
    """A lock that :meth:`Harness.open` removed because its process did not exist.

    Attributes:
        pid: The PID that the lock named.
        started_at: The start time that the lock named, as written.
    """

    pid: int
    started_at: str


@dataclass(frozen=True, slots=True)
class ItemOutcome:
    """What became of one item that :meth:`Harness.run_query_item` or :meth:`Harness.run_change_item` was asked to run.

    Attributes:
        item_id: The item.
        state: Its state afterwards: ``succeeded``, ``failed`` or ``needs-human``, or ``queued``
            when a stop request came before ``kiro-cli`` started.
        reason: The reason written to its history (``queued``: why it did not start).
        detail: More for the maintainer, for local output: the failed command and the end of
            its standard error, the issues of a refusal. It can hold local paths.
        prompt: The Handoff_Prompt that was written, or ``None``.
        report: The Handoff_Report, or ``None`` when ``kiro-cli`` did not run.
        worktree: The worktree, when one was created (it is kept), or ``None``.
        exit_code: The exit code of ``kiro-cli`` (negative: the signal that ended it), or ``None``.
        timed_out: Whether ``kiro-cli`` passed ``timeout_seconds``.
        kiro_error: ``usage_limit`` or ``profile_required`` when ``kiro-cli`` exited with a code other than 0
            and its standard error held the wording of that error, otherwise ``None``. A heuristic label
            (``handoff.kiro_errors``) kept next to ``reason``; it does not change ``state`` or ``reason``.
    """

    item_id: str
    state: str
    reason: str
    detail: str
    prompt: str | None
    report: str | None
    worktree: str | None
    exit_code: int | None
    timed_out: bool
    kiro_error: str | None = None


@dataclass(frozen=True, slots=True)
class BranchRemoval:
    """What :meth:`Harness.remove_empty_branch` did.

    Attributes:
        removed: Whether ``handoff/<id>`` was deleted.
        detail: Why it was or was not, for the maintainer.
    """

    removed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class PublishOutcome:
    """What became of one item that :meth:`Harness.publish_batch` was asked to publish.

    Attributes:
        item_id: The item.
        published: Whether its branch was pushed, the push was confirmed on the remote and the
            draft pull request was opened.
        reason: ``published``; or why not: an exclusion reason of ``command.build_publish_plan``,
            or one of the ``PUBLISH_*`` reasons of this module.
        detail: More for the maintainer, for local output. It can hold local paths.
        held: Whether the item was held back (the ``hold`` of ``published`` in ``status.json``):
            a scan finding, a conflict or a branch that is not what was pushed.
        pr: The pull request number, or ``None``.
        ci: The result of ``gh pr checks`` right after the pull request was opened
            (``passing``, ``failing``, ``pending``, ``none`` or ``unreadable``), or ``None``.
    """

    item_id: str
    published: bool
    reason: str
    detail: str
    held: bool = False
    pr: int | None = None
    ci: str | None = None


@dataclass(frozen=True, slots=True)
class PromptDraft:
    """An item's Handoff_Prompt, drawn, scanned and written as a run does, before anything starts.

    :meth:`Harness.draw_prompt` returns it for ``cli.py plan`` and ``manual``, and a run of a
    query item starts from one (steps 1 and 2 of the module docstring). Drawing changes no state.

    Attributes:
        item_id: The item.
        path: Where the item's Handoff_Prompt goes (``command.handoff_files``).
        written: Whether the body was written to ``path``. ``False`` when the path is shared with
            another item or the body could not be drawn.
        rendered: The drawn and scanned prompt, or ``None`` when it could not be drawn.
        uncommitted_count: The entries of ``git status`` in the target repository's main working
            tree (row 3 of the executor table), or ``None`` when they were not read.
        git_plan: The git commands that create the item's worktree (``command.build_git_plan``),
            or ``None`` when they were refused or the body could not be drawn.
        invocation: The ``kiro-cli`` run (``command.build_kiro_invocation``), or ``None`` when it
            was refused (a held prompt always is), the body could not be drawn, or the item is
            held for :data:`AGENT_NOT_APPROVED` (so that no argv without the configured agent
            exists to be started).
        hold_reason: The history reason with which a run moves the item to ``needs-human``
            instead of passing the prompt on, or ``None`` when it may be passed on. One line
            without local paths.
        detail: More for the maintainer, for local output: the issues, or the positions and kinds
            of the scan findings. Empty when ``hold_reason`` is ``None``.
    """

    item_id: str
    path: str
    written: bool
    rendered: prompt.RenderedPrompt | None
    uncommitted_count: int | None
    git_plan: command.GitPlan | None
    invocation: command.KiroInvocation | None
    hold_reason: str | None
    detail: str


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """One process that the runner started, and how it ended.

    Attributes:
        argv: The argv.
        cwd: The working directory.
        pid: The PID, or ``None`` when it did not start.
        ending: How it ended (:data:`Ending`).
        exit_code: ``returncode``: negative when a signal ended it; ``None`` when it did not
            start or was not reaped.
        stdout: Everything it wrote to standard output that was read.
        stderr: The same for standard error.
        signals: The signals sent to its process group, in order.
        stragglers: Whether members of its group were left after it exited by itself.
        output_complete: ``False`` when reading stopped while a pipe was still open (a process
            outside the group held it), so the output may be cut.
        start_error: Why it did not start, or ``None``.
        missing_program: Whether it did not start because the program does not exist.
        started_at: When it started, in ``state.TIMESTAMP_FORMAT``.
        ended_at: When the runner was done with it.
        duration_seconds: Seconds from start to end, by the monotonic clock.
    """

    argv: tuple[str, ...]
    cwd: str
    pid: int | None
    ending: Ending
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    signals: tuple[str, ...]
    stragglers: bool
    output_complete: bool
    start_error: str | None
    missing_program: bool
    started_at: str
    ended_at: str
    duration_seconds: float

    @property
    def ok(self) -> bool:
        """Whether it exited by itself with exit code 0."""
        return self.ending == "exited" and self.exit_code == 0

    @property
    def timed_out(self) -> bool:
        """Whether it passed its time limit."""
        return self.ending == "timed_out"


@dataclass(frozen=True, slots=True)
class SelftestContext:
    """What :meth:`Harness.run_selftest` needs besides the harness: the checked inputs of ``cli.py``.

    Attributes:
        config: The configuration that ``config.parse_config`` returned.
        home: The absolute home directory, in normal form. ``kiro_cli`` is expanded with it,
            and ``~/.kiro`` below it is read for ``config_sha256``.
        harness_tree: This repository's main working tree, absolute and in normal form.
            Protected like the main working trees of ``repos``.
        session_worktrees_dir: The IDE sessions' worktree directory. Protected as well.
        approved_agents: ``(name, mode)`` pairs whose approval passed the checks of ``cli.py``,
            as for :attr:`RunContext.approved_agents`. The selftest reads the pair of
            ``agents.change`` for the change mode only.
        kill_grace_seconds: Seconds from SIGTERM to SIGKILL. A test may shorten it.
    """

    config: HandoffConfig
    home: str
    harness_tree: str
    session_worktrees_dir: str
    approved_agents: frozenset[tuple[str, str]] = frozenset()
    kill_grace_seconds: float = KILL_GRACE_SECONDS

    def __post_init__(self) -> None:
        """Check the types and the forms of the fields."""
        if not isinstance(self.config, HandoffConfig):
            raise TypeError(f"config must be a HandoffConfig, not {type(self.config).__name__}")
        for name in ("home", "harness_tree", "session_worktrees_dir"):
            if not _is_normal_absolute(getattr(self, name)):
                raise ValueError(f"{name} must be an absolute path in normal form, got {getattr(self, name)!r}")
        agents = frozenset(self.approved_agents)
        if not all(
            type(pair) is tuple and len(pair) == 2 and all(type(part) is str for part in pair) for pair in agents
        ):
            raise TypeError("approved_agents must hold (name, mode) pairs of str only")
        object.__setattr__(self, "approved_agents", agents)
        grace = self.kill_grace_seconds
        if type(grace) not in (int, float) or not math.isfinite(grace) or grace <= 0:
            raise ValueError(f"kill_grace_seconds must be a finite number above 0, got {grace!r}")


@dataclass(frozen=True, slots=True)
class KiroFingerprint:
    """What a selftest result counts for: the ``kiro-cli`` version and ``config_sha256`` (task 5.2).

    ``cli.py run`` compares both with ``selftest`` of ``status.json`` before it starts a change
    item, and the selftest records them.

    Attributes:
        program: The ``kiro-cli`` that was asked: ``kiro_cli`` with ``~`` expanded.
        version_output: What ``kiro-cli --version`` wrote to standard output, decoded.
        version: ``command.kiro_cli_version`` of it. Not empty.
        agent: The ``--agent`` name the digest covers, or ``None``.
        digest: ``command.selftest_config_digest`` of the configuration, the agent
            configuration and the hook files as they were read.
    """

    program: str
    version_output: str
    version: str
    agent: str | None
    digest: command.ConfigDigest


@dataclass(frozen=True, slots=True)
class SelftestOutcome:
    """What :meth:`Harness.run_selftest` decided and where it wrote it.

    Attributes:
        result: ``guards_active`` or ``unconfirmed``, as ``evaluate.selftest_verdict`` decided.
        run_id: The selftest's start, in ``command.SELFTEST_RUN_ID_FORMAT``.
        record: The record, ``.private/handoff/selftest/<run ID>.json``.
        run_dir: ``<worktrees_root>/selftest/<run ID>``, which holds the trials' repositories
            and is kept.
        outcomes: ``(trial, outcome)`` for T0 to T4 in order, as passed to
            ``evaluate.SelftestTrials``: ``failed_otherwise`` for a trial that did not start.
        started: The trials whose ``kiro-cli`` started, in order.
        fingerprint: The version and the digest that the result is tied to.
        detail: Why the result is ``unconfirmed``, in one line for local output, or empty.
    """

    result: str
    run_id: str
    record: str
    run_dir: str
    outcomes: tuple[tuple[str, str], ...]
    started: tuple[str, ...]
    fingerprint: KiroFingerprint
    detail: str


def load_deny_terms(customer_terms: str, extra_terms: str) -> DenyTerms:
    """Read the deny lists that each Handoff_Prompt body is scanned with (Requirement 28.23).

    Both files are read the way ``~/.kiro/hooks/scripts/guard_customer_names.py`` reads its
    list: one term per line, white space around a term stripped, and blank lines and lines
    that start with ``#`` skipped. A byte order mark at the start is dropped. Every other line
    is a term; ``handoff.scan.check`` folds case and width itself. No term is logged, and the
    notes give counts only.

    - The customer list (``customer_terms``) is required: when it is missing, unreadable or
      has no term, the runner refuses to start, because a scan without it would pass
      customer names on.
    - The list of the phase 4 research (``extra_terms``) may be missing until the research
      writes it (task 4). Then the scan runs without its terms, and a note says so in every
      Handoff_Report and once on standard error (a warning of this module's logger). When it
      exists, it must be readable; an empty list gives a note of 0 terms.

    Args:
        customer_terms: The customer list, an absolute path (``~`` expanded by the caller).
        extra_terms: The research list, an absolute path.

    Returns:
        The terms and the notes.

    Raises:
        ValueError: A path is not absolute.
        DenyListUnavailable: The customer list is missing, unreadable or empty, or the research
            list exists and cannot be read as UTF-8.
    """
    for name, path in (("customer_terms", customer_terms), ("extra_terms", extra_terms)):
        if type(path) is not str or not path.startswith("/"):
            raise ValueError(f"{name} must be an absolute path, got {path!r}")
    customer, customer_status = _read_terms(customer_terms)
    if customer_status != "ok":
        raise DenyListUnavailable(
            f"the customer-name list {customer_terms} is {customer_status}; the prompts cannot be scanned for "
            "customer names, so no item starts"
        )
    notes = [f"顧客名の一覧 `{customer_terms}`: {len(customer)} 語を読んだ"]
    extra, extra_status = _read_terms(extra_terms)
    if extra_status == "unreadable":
        raise DenyListUnavailable(f"the deny list {extra_terms} exists and cannot be read as UTF-8 text")
    if extra_status == "missing":
        notes.append(f"拒否語の一覧 `{extra_terms}`: 見つからない。この一覧の語なしで走査した")
        _LOG.warning("the deny list %s was not found; prompts are scanned without its terms", extra_terms)
    else:
        notes.append(f"拒否語の一覧 `{extra_terms}`: {len(extra)} 語を読んだ")
    return DenyTerms(tuple(customer) + tuple(extra), tuple(notes))


def git_environment(parent: Mapping[str, str]) -> dict[str, str]:
    """Build the environment of the runner's own git commands.

    A copy of ``parent`` without :data:`RUNNER_GIT_DROPPED` and the variables that start with
    :data:`RUNNER_GIT_DROPPED_PREFIXES`, which would point git at another repository or carry
    configuration (a harness started from a git hook inherits ``GIT_DIR``), and with
    ``GIT_TERMINAL_PROMPT=0``, so that a fetch that needs credentials fails instead of waiting
    for a terminal. ``kiro-cli`` gets ``command.child_env`` instead.

    Args:
        parent: The harness's environment.

    Returns:
        A new dictionary.
    """
    env = {
        key: value
        for key, value in parent.items()
        if key not in RUNNER_GIT_DROPPED and not key.startswith(RUNNER_GIT_DROPPED_PREFIXES)
    }
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def read_status(handoff_dir: str) -> state.StatusDoc:
    """Read ``status.json`` without taking the lock, for ``cli.py status`` and ``cleanup``'s listing.

    These displays must work while another harness runs. That harness replaces the file with
    ``os.replace``, so a read sees the previous version or the new one, never part of one.
    Nothing is created or written, and no record is reconciled: a ``running`` record whose
    process is gone stays ``running`` until the next :meth:`Harness.open`.

    Args:
        handoff_dir: This repository's ``.private/handoff`` directory, as for :meth:`Harness.open`.

    Returns:
        The status; an empty one when ``status.json`` does not exist yet.

    Raises:
        TypeError: ``handoff_dir`` is not a ``str``.
        ValueError: ``handoff_dir`` does not have its form.
        UnsafeLocation: ``.private`` or ``handoff`` is a symbolic link, or ``status.json`` resolves
            outside ``.private/handoff``.
        StatusUnreadable: ``status.json`` is not a status.
    """
    directory = _checked_handoff_dir(handoff_dir)
    _check_physical_handoff_dir(directory)
    return _StatusFile(directory).load()


def harness_tree_of(directory: str) -> str:
    """Find the main working tree of the repository that holds a directory.

    ``git -C <directory> rev-parse --path-format=absolute --git-common-dir`` names the ``.git``
    directory that the main working tree and every linked worktree of a repository share. Its
    parent is the main working tree, also when ``directory`` lies in a linked worktree, so a
    harness started from a worktree finds the main working tree's ``.private/handoff``. This
    runs before ``config.json`` is read, with the time limit :data:`LOCATE_TIMEOUT_SECONDS`.

    Args:
        directory: An absolute directory inside the repository, such as the one of ``cli.py``.

    Returns:
        The main working tree, absolute and in normal form.

    Raises:
        ValueError: ``directory`` is not an absolute path.
        GitCommandFailed: git did not succeed, printed no absolute path, or named a common
            directory that is not called ``.git`` (a bare repository, or one made with
            ``--separate-git-dir``), whose parent is not a main working tree.
    """
    if type(directory) is not str or not directory.startswith("/"):
        raise ValueError(f"directory must be an absolute path, got {directory!r}")
    argv = ("git", "-C", directory, "rev-parse", "--path-format=absolute", "--git-common-dir")
    result = _git_once(argv, directory, "finding the main working tree", timeout_seconds=LOCATE_TIMEOUT_SECONDS)
    common = result.stdout.decode("utf-8", "replace").strip()
    if not common.startswith("/") or "\n" in common:
        raise GitCommandFailed(f"git rev-parse --git-common-dir printed {_clip(common)}, not one absolute path")
    common = "/" + posixpath.normpath(common).lstrip("/")
    if posixpath.basename(common) != ".git":
        raise GitCommandFailed(f"the common git directory {common} is not the .git directory of a main working tree")
    return posixpath.dirname(common)


def list_worktrees(main_tree: str, *, timeout_seconds: float) -> tuple[str, ...]:
    """List the worktrees that a repository's main working tree knows of, reading only.

    ``git --no-optional-locks -C <main> worktree list --porcelain``: the path of each ``worktree``
    line, the main working tree first, as git wrote them (absolute). A worktree whose directory
    is gone is listed too, until ``git worktree prune``.

    Args:
        main_tree: The repository's main working tree, absolute.
        timeout_seconds: The time limit, ``timeout_seconds`` of the configuration.

    Returns:
        The paths, in git's order.

    Raises:
        GitCommandFailed: git did not succeed, for example because ``main_tree`` is not a
            repository or does not exist.
    """
    argv = ("git", "--no-optional-locks", "-C", main_tree, "worktree", "list", "--porcelain")
    result = _git_once(argv, main_tree, "listing the worktrees", timeout_seconds=timeout_seconds)
    lines = result.stdout.decode("utf-8", "replace").splitlines()
    return tuple(line[len("worktree ") :] for line in lines if line.startswith("worktree "))


def branch_exists(main_tree: str, branch: str, *, timeout_seconds: float) -> bool:
    """Tell whether a repository has a local branch, reading only.

    ``git --no-optional-locks -C <main> rev-parse --verify -q refs/heads/<branch>``: exit code 0
    when it exists, 1 when it does not.

    Args:
        main_tree: The repository's main working tree, absolute.
        branch: The branch name without ``refs/heads/``, such as ``handoff/<id>``.
        timeout_seconds: The time limit.

    Returns:
        Whether ``refs/heads/<branch>`` exists.

    Raises:
        GitCommandFailed: git ended with another code, or did not end.
    """
    argv = ("git", "--no-optional-locks", "-C", main_tree, "rev-parse", "--verify", "-q", f"refs/heads/{branch}")
    result = _git_once(argv, main_tree, "looking up a branch", timeout_seconds=timeout_seconds, allowed=(0, 1))
    return result.exit_code == 0


def _git_once(
    argv: tuple[str, ...], cwd: str, what: str, *, timeout_seconds: float, allowed: tuple[int, ...] = (0,)
) -> ProcessResult:
    """Run one git command of ``cli.py``'s in :func:`git_environment`, requiring an allowed exit code.

    Raises:
        GitCommandFailed: It did not start, did not end in time, or ended with another code.
        KeyboardInterrupt: The harness was interrupted while it ran; its group was stopped.
    """
    result = _run_process(
        argv,
        cwd=cwd,
        env=git_environment(os.environ),
        timeout_seconds=timeout_seconds,
        kill_grace_seconds=KILL_GRACE_SECONDS,
    )
    if result.ending == "interrupted":
        raise KeyboardInterrupt
    if result.ending != "exited" or result.exit_code not in allowed:
        raise GitCommandFailed(f"{what}: {_detail(result)}")
    return result


def kiro_fingerprint(
    config: HandoffConfig, *, home: str, agent: str | None, kill_grace_seconds: float = KILL_GRACE_SECONDS
) -> KiroFingerprint:
    """Ask ``kiro-cli --version`` and read the files of ``config_sha256`` (task 5.2).

    ``kiro-cli --version`` runs in the environment of ``command.child_env``, as every
    ``kiro-cli`` does, with the time limit ``timeout_seconds``. Then the files are read:
    ``command.KIRO_AGENT_FILE`` for ``agent``, and each entry directly in
    ``command.KIRO_HOOK_DIRS`` that is a regular file once symbolic links are followed (the
    bytes that would run). A file that cannot be read counts with no SHA-256, and a directory
    that does not exist has no files. Nothing is written.

    Args:
        config: The checked configuration.
        home: The absolute home directory, in normal form.
        agent: The name that the argv gives with ``--agent``, or ``None``.
        kill_grace_seconds: Seconds from SIGTERM to SIGKILL.

    Returns:
        The version and the digest.

    Raises:
        KiroCliMissing: ``kiro_cli`` is not absolute after ``~`` expansion, ``kiro-cli`` cannot
            be started, or ``--version`` did not exit 0 with a version: a result tied to no
            version could not be compared later.
        RunnerError: A directory of ``command.KIRO_HOOK_DIRS`` exists and cannot be listed.
        KeyboardInterrupt: The harness was interrupted while ``kiro-cli`` ran.
    """
    try:
        program = normalize_path(config.kiro_cli, home)
    except ValueError as exc:
        raise KiroCliMissing(f"kiro_cli of config.json: {exc}") from exc
    with _ChildPaths() as child:
        env = command.child_env(
            os.environ, push_url=child.push_url, gh_config_dir=child.gh_config_dir, aws_empty_file=child.aws_empty_file
        )
        result = _run_process(
            (program, "--version"),
            cwd=child.directory,
            env=env,
            timeout_seconds=config.timeout_seconds,
            kill_grace_seconds=kill_grace_seconds,
        )
    if result.ending == "interrupted":
        raise KeyboardInterrupt
    if result.ending == "not_started":
        raise KiroCliMissing(f"{program} cannot be started ({result.start_error})")
    output = result.stdout.decode("utf-8", "replace")
    version = command.kiro_cli_version(output)
    if not result.ok or not version:
        raise KiroCliMissing(
            f"`kiro-cli --version` {_how(result)} and printed {_clip(output)}: no version to tie a selftest to"
        )
    agent_file: bytes | None = None
    if agent is not None:
        agent_file = _read_or_none(normalize_path(command.KIRO_AGENT_FILE.format(name=agent), home))
    hook_files: dict[str, bytes | None] = {}
    for listed in command.KIRO_HOOK_DIRS:
        directory = normalize_path(listed, home)
        try:
            names = sorted(os.listdir(directory))
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            raise RunnerError(f"{directory} cannot be listed ({exc.strerror or exc}), so config_sha256 is unknown")
        for name in names:
            path = posixpath.join(directory, name)
            if os.path.isfile(path):
                hook_files[path] = _read_or_none(path)
    digest = command.selftest_config_digest(
        config, home=home, agent=agent, agent_file=agent_file, hook_files=hook_files
    )
    return KiroFingerprint(program=program, version_output=output, version=version, agent=agent, digest=digest)


class Harness:
    """The one running Handoff_Harness: it holds ``.private/handoff/.lock`` and writes ``status.json``.

    Open it with :meth:`open`, preferably as a context manager, which releases the lock::

        with Harness.open(handoff_dir) as harness:
            harness.add_missing_items(manifest)
            ...

    Every change of the status is written at once (Requirement 28.13). Methods that change it
    may be called from several threads.
    """

    def __init__(self, handoff_dir: str, lock: _Lock, status_file: _StatusFile, status: state.StatusDoc) -> None:
        """Keep what :meth:`open` prepared. Use :meth:`open` rather than this constructor.

        Args:
            handoff_dir: The checked ``.private/handoff`` directory.
            lock: The lock this harness holds.
            status_file: Where the status is read and written.
            status: The status as read.
        """
        self._handoff_dir = handoff_dir
        self._lock = lock
        self._file = status_file
        self._status = status
        self._mutex = threading.RLock()
        self._active_repos: set[str] = set()
        self._stale_lock: StaleLock | None = None
        self._interrupted: tuple[str, ...] = ()
        self._closed = False

    @classmethod
    def open(cls, handoff_dir: str) -> Harness:
        """Take the lock, read the status, and settle what an earlier harness left.

        In order: the directory is checked (lexically, then that ``.private/handoff`` is not
        reached through a symbolic link, before and after it is created when missing); the
        lock is taken, and a stale one removed; ``status.json`` is read (an empty status when it
        does not exist yet; nothing is written until the first change); the removal of a stale
        lock is recorded in ``events``; and each ``running`` record whose process is gone moves
        to ``failed`` (``harness_interrupted``).

        Args:
            handoff_dir: This repository's ``.private/handoff`` directory: absolute, in normal
                form, ending with ``.private/handoff``.

        Returns:
            The harness. The caller closes it.

        Raises:
            TypeError: ``handoff_dir`` is not a ``str``.
            ValueError: ``handoff_dir`` does not have that form.
            UnsafeLocation: ``.private`` or ``handoff`` is a symbolic link, or ``status.json``
                resolves outside ``.private/handoff``.
            LockHeld: Another harness runs.
            LockUnreadable: The lock file exists and names no process.
            StatusUnreadable: ``status.json`` is not a status.
        """
        directory = _checked_handoff_dir(handoff_dir)
        _check_physical_handoff_dir(directory)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        _check_physical_handoff_dir(directory)
        lock, stale = _Lock.acquire(posixpath.join(directory, LOCK_FILE))
        if stale is not None:
            _LOG.warning("removed a stale lock of pid %s (started %s)", stale.pid, _clip(stale.started_at))
        try:
            status_file = _StatusFile(directory)
            harness = cls(directory, lock, status_file, status_file.load())
            if stale is not None:
                harness._record_stale_lock(stale)
            harness._reconcile()
        except BaseException:
            lock.release()
            raise
        return harness

    def close(self) -> None:
        """Release the lock. Calling it again does nothing."""
        with self._mutex:
            if self._closed:
                return
            self._closed = True
        self._lock.release()

    def __enter__(self) -> Harness:
        """Return the harness itself."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the harness."""
        self.close()

    @property
    def handoff_dir(self) -> str:
        """The ``.private/handoff`` directory."""
        return self._handoff_dir

    @property
    def status(self) -> state.StatusDoc:
        """A copy of the current status, as written to ``status.json``."""
        with self._mutex:
            return copy.deepcopy(self._status)

    @property
    def stale_lock(self) -> StaleLock | None:
        """The stale lock that :meth:`open` removed, or ``None``."""
        return self._stale_lock

    @property
    def interrupted_items(self) -> tuple[str, ...]:
        """The items that :meth:`open` moved from ``running`` to ``failed``, sorted."""
        return self._interrupted

    def add_missing_items(self, manifest: Manifest) -> tuple[str, ...]:
        """Add a ``queued`` record for each item of the manifest that the status does not have.

        ``dag.select`` needs a record of every item of the manifest; a record is never added
        again, so a ``succeeded`` item cannot be reset to ``queued`` this way.

        Args:
            manifest: The checked manifest.

        Returns:
            The IDs added, in the order of the manifest.

        Raises:
            TypeError: ``manifest`` is not a :class:`handoff.manifest.Manifest`.
        """
        if not isinstance(manifest, Manifest):
            raise TypeError(f"manifest must be a Manifest, not {type(manifest).__name__}")
        with self._mutex:
            status = self._status
            added: list[str] = []
            for item in manifest.items:
                if item.id not in status["items"]:
                    status = state.add_item(status, item.id)
                    added.append(item.id)
            if added:
                self._commit(status)
            return tuple(added)

    def hold(self, item_id: str, *, reason: str) -> None:
        """Move a ``queued`` item to ``needs-human`` without starting it.

        ``cli.py`` holds a change item this way when its selftest does not count (task 5.2).

        Args:
            item_id: An item of the status.
            reason: The history reason. One line without local paths.

        Raises:
            handoff.state.TransitionError: The item does not exist or is not ``queued``, or the
                reason is blank.
        """
        with self._mutex:
            record = self._status["items"].get(item_id)
            if record is None or record["state"] != state.QUEUED:
                found = "no record" if record is None else record["state"]
                raise state.TransitionError(f"only a queued item can be held; {item_id!r} has {found}")
            self._move(item_id, state.NEEDS_HUMAN, reason)

    def requeue(self, item_id: str, *, reason: str) -> None:
        """Move a ``failed`` or ``needs-human`` item back to ``queued``: the maintainer's re-run.

        Args:
            item_id: An item of the status.
            reason: The history reason, such as what the maintainer fixed.

        Raises:
            handoff.state.TransitionError: The item is in another state, does not exist, or the
                reason is blank.
        """
        self._move(item_id, state.QUEUED, reason)

    def run_query_item(self, context: RunContext, item_id: str, *, stop: threading.Event | None = None) -> ItemOutcome:
        """Run one ``queued`` query item to its final state (the module docstring lists the steps).

        Args:
            context: The checked inputs.
            item_id: A query item of ``context.manifest`` whose record is ``queued``.
            stop: When set (from another thread), the run stops: before ``kiro-cli`` starts the
                item stays ``queued``; once it runs, its process group is stopped and the item
                moves to ``failed`` (``harness_interrupted``).

        Returns:
            What became of the item.

        Raises:
            TypeError: ``context`` is not a :class:`RunContext`.
            RunnerError: The item is not in the manifest, is not a query item, is not ``queued``
                or has no record; another item of its repository runs in this harness or is
                ``running`` in the status, or a ``running`` record is not in the manifest (its
                repository is unknown, as for ``dag.select``); or ``handoff_dir`` is not in
                ``context.harness_tree``. Nothing was started.
            LoginRequired: ``kiro-cli whoami`` failed; the item stays ``queued``.
            KiroCliMissing: ``kiro-cli`` cannot be started; the item stays ``queued``.
            DiskSpaceLow: Too little free space; the item stays ``queued``.
            UnsafeLocation: A place resolves where the runner must not go; the item stays
                ``queued``.
            KeyboardInterrupt: The harness was interrupted. When ``kiro-cli`` ran, its group was
                stopped, the report written and the item moved to ``failed`` first.
        """
        item = self._context_item(context, item_id)
        if item.mode != "query":
            raise RunnerError(f"{item_id} is a {item.mode} item; run_query_item starts query items only")
        with self._reserve(context.manifest, item):
            return _QueryRun(self, context, item, stop).run()

    def run_change_item(self, context: RunContext, item_id: str, *, stop: threading.Event | None = None) -> ItemOutcome:
        """Run one ``queued`` change item to its final state, in a worktree on ``handoff/<id>``.

        The steps of :meth:`run_query_item`, with the differences that the module docstring lists
        for a change item. The selftest's version and ``config_sha256`` are compared by ``cli.py``
        before this is called (task 5.2); here, ``command.build_kiro_invocation`` refuses the item
        without a ``guards_active`` selftest, and the item is held.

        Args:
            context: The checked inputs.
            item_id: A change item of ``context.manifest`` whose record is ``queued``.
            stop: As for :meth:`run_query_item`.

        Returns:
            What became of the item.

        Raises:
            TypeError: As for :meth:`run_query_item`.
            RunnerError: As for :meth:`run_query_item`, with a change item in the place of a query
                item. Nothing was started.
            LoginRequired: As for :meth:`run_query_item`.
            KiroCliMissing: As for :meth:`run_query_item`.
            DiskSpaceLow: As for :meth:`run_query_item`.
            UnsafeLocation: As for :meth:`run_query_item`.
            KeyboardInterrupt: As for :meth:`run_query_item`.
        """
        item = self._context_item(context, item_id)
        if item.mode != "change":
            raise RunnerError(f"{item_id} is a {item.mode} item; run_change_item starts change items only")
        with self._reserve(context.manifest, item):
            return _ChangeRun(self, context, item, stop).run()

    def verify_manual(
        self, context: RunContext, item_id: str, worktree: str, *, stop: threading.Event | None = None
    ) -> ItemOutcome:
        """Observe a worktree that the maintainer made by hand, and record the final state of a change item.

        The observation is that of :meth:`run_change_item` (steps 1 to 8 of the design's "結果の確認"):
        the same method builds the observations and ``evaluate.final_state`` decides. ``kiro-cli`` does
        not run; the observations take its exit code as 0, no time-out and no output. The item moves
        ``queued`` to ``running`` (``manual_verify``) and then to its final state.

        Everything is checked before the move, and a refusal changes nothing. The worktree must be an
        absolute path in normal form that resolves outside every protected tree, be listed by
        ``git worktree list`` of the item's repository, have ``HEAD`` on ``handoff/<id>``, and descend
        from the item's ``base_sha``. A record without a ``base_sha`` gets the merge base of ``HEAD``
        and ``origin/main`` after a fetch.

        Args:
            context: The checked inputs.
            item_id: A change item of ``context.manifest`` whose record is ``queued``.
            worktree: The worktree, absolute.
            stop: As for :meth:`run_query_item`.

        Returns:
            What became of the item.

        Raises:
            TypeError: ``context`` is not a :class:`RunContext`.
            VerifyRefused: A check above failed. Nothing was changed.
            RunnerError: As for :meth:`run_change_item`.
            KeyboardInterrupt: The harness was interrupted; the item moved to ``failed`` first.
        """
        item = self._context_item(context, item_id)
        if item.mode != "change":
            raise VerifyRefused(f"{item_id} is a {item.mode} item; verify observes change items only")
        run = _ManualVerify(self, context, item, worktree, stop)
        try:
            run.admit()
        except _Stopped:
            return run.stopped()
        # The checks only read; the records are added after them, so that a refusal changes nothing.
        self.add_missing_items(context.manifest)
        with self._reserve(context.manifest, item):
            return run.run()

    def publish_batch(
        self,
        context: RunContext,
        approval: command.PublishApproval,
        *,
        github_repos: Mapping[str, str] | None = None,
    ) -> tuple[PublishOutcome, ...]:
        """Publish the ``succeeded`` items that one approval lists: push, confirm, open a draft pull request.

        This is the publishing run that Requirement 23.4 excepts from its ban on pushes and pull
        requests and that Requirement 28.15 approves: the maintainer approved the batch in this
        session and ``approval`` lists it. No item outside the list is pushed or opened.

        Only the argv of ``command.build_publish_plan`` is run (no ``kiro-cli``, in the harness's
        own environment). Before a push, the commit messages and the added lines of the diff
        are scanned with ``scan.check_publish``, and the default branch is fetched again to check
        for conflicts; an item with a finding or a conflict is not published and is held (see
        below). After the push, ``git ls-remote origin refs/heads/handoff/<id>`` must print the
        SHA of the local branch before the pull request is opened. The number goes to
        ``published.pr`` and the result of ``gh pr checks`` to ``published.ci`` (IN-3).

        A held item stays ``succeeded``: no transition leaves that state. ``published.hold`` holds
        the reason and an event ``publish_held`` is added; the item is published by a new approval
        once its cause is gone.

        Args:
            context: The checked inputs.
            approval: The approval. It covers the items it lists and no other.
            github_repos: ``OWNER/NAME`` by target repository for ``gh pr create --repo``,
                for a repository whose ``origin`` URL does not name one; by default it is read
                from ``remote.origin.url`` of the main working tree.

        Returns:
            One outcome per listed item, in the order listed.

        Raises:
            TypeError: An argument is not of its type.
            RunnerError: ``handoff_dir`` is not in the harness tree, or the harness is closed.
            KeyboardInterrupt: The harness was interrupted during a command.
        """
        if not isinstance(context, RunContext):
            raise TypeError(f"context must be a RunContext, not {type(context).__name__}")
        if not isinstance(approval, command.PublishApproval):
            raise TypeError(f"approval must be a PublishApproval, not {type(approval).__name__}")
        if not (is_within(self._handoff_dir, context.harness_tree) and self._handoff_dir != context.harness_tree):
            raise RunnerError(f"{self._handoff_dir} is not in the harness tree {context.harness_tree}")
        return _Publish(self, context, approval, dict(github_repos or {})).run()

    def draw_prompt(self, context: RunContext, item_id: str) -> PromptDraft:
        """Draw, scan and write one item's Handoff_Prompt as a run does, and start nothing else.

        Steps 1 and 2 of the module docstring, for an item of either mode and in any state:
        ``cli.py plan`` shows the result and ``cli.py manual`` prints the body for the maintainer
        to paste. The status is not changed. The only process is ``git status`` of the target
        repository's main working tree, and the only file written is the item's Handoff_Prompt
        (not when its path is shared or it cannot be drawn).

        Args:
            context: The checked inputs.
            item_id: An item of ``context.manifest``.

        Returns:
            The draft, with the hold reason that a run would record, if any.

        Raises:
            TypeError: ``context`` is not a :class:`RunContext`.
            RunnerError: The item is not in the manifest, or ``handoff_dir`` is not in
                ``context.harness_tree``.
            UnsafeLocation: A file of the item resolves outside ``.private/handoff``.
        """
        item = self._context_item(context, item_id)
        return _QueryRun(self, context, item, None).draw()

    def remove_worktree(self, item: Item, *, config: HandoffConfig, home: str) -> ProcessResult:
        """Remove an item's worktree with ``git worktree remove``, without ``--force``.

        ``cli.py cleanup <id> --approved`` calls this once the maintainer approved; nothing removes
        a worktree on its own (design section 20, "後片付けの方針"). The worktree is the one that
        ``command.build_git_plan`` names, ``<worktrees_root>/<repo>/<id>``. git refuses one with
        modified or untracked files, and then nothing is removed. When git removes it, the item's
        record forgets the path (``worktree`` becomes ``null``; the Handoff_Report keeps it) and
        ``events`` gets a ``worktree_removed`` entry, in one write of the status. No branch is
        touched.

        Args:
            item: An item of the checked manifest.
            config: The checked configuration.
            home: The absolute home directory, to expand the ``~`` of the record's path.

        Returns:
            The ``git worktree remove`` process: ``ok`` tells whether git removed the worktree.

        Raises:
            TypeError: ``item`` is not an :class:`handoff.manifest.Item`.
            handoff.command.CommandError: The worktree path cannot be built.
            RunnerError: The item is ``running`` in the status, or an item of its repository runs
                in this harness, or its record names a worktree other than the one above.
            KeyboardInterrupt: The harness was interrupted while git ran.
        """
        if not isinstance(item, Item):
            raise TypeError(f"item must be an Item, not {type(item).__name__}")
        plan = command.build_git_plan(config, item)
        with self._mutex:
            if self._closed:
                raise RunnerError("the harness is closed; open it again")
            record = self._status["items"].get(item.id)
            if record is not None and record["state"] == state.RUNNING:
                raise RunnerError(f"{item.id} is running; its worktree is not removed")
            if item.repo in self._active_repos:
                raise RunnerError(f"an item of {item.repo} runs in this harness; its worktree is not removed now")
            named = None if record is None else record["worktree"]
            if named is not None:
                expanded = normalize_path(named, home)
                if not (is_within(expanded, plan.worktree) and is_within(plan.worktree, expanded)):
                    raise RunnerError(
                        f"the record of {item.id} names the worktree {named}, not {plan.worktree}; "
                        "remove it by hand after reading it"
                    )
            self._active_repos.add(item.repo)
        try:
            self._remove_prerequisite_copies(item, plan, config)
            argv = ("git", "-C", plan.main_tree, "worktree", "remove", plan.worktree)
            result = _run_process(
                argv,
                cwd=plan.main_tree,
                env=git_environment(os.environ),
                timeout_seconds=config.timeout_seconds,
                kill_grace_seconds=KILL_GRACE_SECONDS,
            )
            if result.ending == "interrupted":
                raise KeyboardInterrupt
            if result.ok:
                with self._mutex:
                    status = copy.deepcopy(self._status)
                    if item.id in status["items"]:
                        status["items"][item.id]["worktree"] = None
                    detail = f"{item.id}: git worktree remove {_tilde(plan.worktree, home)}"
                    self._commit(state.record_event(status, at=_now(), kind=WORKTREE_REMOVED, detail=detail))
                _LOG.info("%s: removed its worktree", item.id)
            return result
        finally:
            with self._mutex:
                self._active_repos.discard(item.repo)

    @staticmethod
    def _remove_prerequisite_copies(item: Item, plan: command.GitPlan, config: HandoffConfig) -> None:
        """Remove the read-only copies of ``prerequisites.copy_readonly`` from an item's worktree, before git removes it.

        A read-only directory stops ``git worktree remove`` from deleting what is inside it, and git
        ignores ignored files in its cleanliness check, so the copies are the harness's to remove.
        Nothing is removed from a worktree that does not exist, and a path that resolves outside the
        worktree is refused.

        Raises:
            RunnerError: A copy could not be removed.
        """
        wanted = config.repos[item.repo].prerequisites
        if item.mode != "change" or wanted is None or not os.path.isdir(plan.worktree):
            return
        for rel in wanted.copy_readonly:
            target = posixpath.join(plan.worktree, rel)
            try:
                _check_below(target, plan.worktree)
                _remove_prerequisite_copy(target)
            except (OSError, UnsafeLocation) as error:
                raise RunnerError(
                    f"the copy of {rel} in the worktree of {item.id} could not be removed: {error}"
                ) from error

    def remove_empty_branch(self, item: Item, *, config: HandoffConfig, home: str) -> BranchRemoval:
        """Delete ``handoff/<id>`` when it still points at the SHA that was recorded when it was created.

        ``cli.py cleanup <id> --approved`` calls this after the worktree is gone. A branch at the
        recorded creation SHA has no commit of its own, so nothing is lost; the deletion is
        ``git update-ref -d refs/heads/handoff/<id> <sha>``, which git refuses if the branch moved in
        the meantime. A branch with a commit, one checked out in another worktree, and an item whose
        record has no creation SHA are kept, and ``detail`` says why. ``branch -d`` and ``branch -D`` are
        not used (``-d`` compares with the local ``main``, ``-D`` compares with nothing). On success the
        status gets a ``branch_removed`` event.

        Args:
            item: An item of the checked manifest.
            config: The checked configuration.
            home: The absolute home directory (kept for symmetry with :meth:`remove_worktree`).

        Returns:
            Whether the branch was deleted, and the reason in either case.

        Raises:
            TypeError: ``item`` is not an :class:`handoff.manifest.Item`.
            handoff.command.CommandError: The git plan cannot be built.
            RunnerError: The item is ``running``, or an item of its repository runs in this harness.
            KeyboardInterrupt: The harness was interrupted while git ran.
        """
        if not isinstance(item, Item):
            raise TypeError(f"item must be an Item, not {type(item).__name__}")
        del home
        plan = command.build_git_plan(config, item)
        branch = plan.branch
        if branch is None:
            return BranchRemoval(False, "a query item has no branch")
        with self._mutex:
            if self._closed:
                raise RunnerError("the harness is closed; open it again")
            record = self._status["items"].get(item.id)
            if record is not None and record["state"] == state.RUNNING:
                raise RunnerError(f"{item.id} is running; its branch is not removed")
            if item.repo in self._active_repos:
                raise RunnerError(f"an item of {item.repo} runs in this harness; its branch is not removed now")
            created = None if record is None else record["base_sha"]
            self._active_repos.add(item.repo)
        try:
            env, timeout = git_environment(os.environ), config.timeout_seconds

            def git(*args: str) -> ProcessResult:
                result = _run_process(
                    ("git", "--no-optional-locks", "-C", plan.main_tree, *args),
                    cwd=plan.main_tree,
                    env=env,
                    timeout_seconds=timeout,
                    kill_grace_seconds=KILL_GRACE_SECONDS,
                )
                if result.ending == "interrupted":
                    raise KeyboardInterrupt
                return result

            if created is None:
                return BranchRemoval(
                    False, f"the record of {item.id} has no creation SHA, so {branch} is not judged empty"
                )
            looked = git("rev-parse", "--verify", "-q", f"refs/heads/{branch}")
            if looked.exit_code == 1:
                return BranchRemoval(False, f"{branch} does not exist")
            if not looked.ok:
                return BranchRemoval(False, f"{branch} could not be read ({_how(looked)})")
            tip = looked.stdout.decode("ascii", "replace").strip()
            if tip != created:
                return BranchRemoval(
                    False,
                    f"{branch} is at {tip[:12]}, not at the recorded creation SHA {created[:12]}: it holds work and is kept",
                )
            listed = git("worktree", "list", "--porcelain")
            if not listed.ok:
                return BranchRemoval(False, f"the worktrees of {item.repo} could not be listed ({_how(listed)})")
            if f"branch refs/heads/{branch}" in listed.stdout.decode("utf-8", "replace").splitlines():
                return BranchRemoval(False, f"{branch} is checked out in a worktree and is kept")
            deleted = _run_process(
                plan.delete_branch_at(created).argv,
                cwd=plan.main_tree,
                env=env,
                timeout_seconds=timeout,
                kill_grace_seconds=KILL_GRACE_SECONDS,
            )
            if deleted.ending == "interrupted":
                raise KeyboardInterrupt
            if not deleted.ok:
                return BranchRemoval(False, f"git update-ref -d refused ({_how(deleted)}): {_detail(deleted)}")
            with self._mutex:
                status = copy.deepcopy(self._status)
                detail = f"{item.id}: git update-ref -d refs/heads/{branch} {created[:12]} (no commit of its own)"
                self._commit(state.record_event(status, at=_now(), kind=BRANCH_REMOVED, detail=detail))
            _LOG.info("%s: removed its empty branch", item.id)
            return BranchRemoval(
                True, f"{branch} was at the recorded creation SHA {created[:12]}, with no commit of its own"
            )
        finally:
            with self._mutex:
                self._active_repos.discard(item.repo)

    def selftest_result(self) -> str | None:
        """``result`` of the latest selftest in the status, or ``None`` before the first one."""
        with self._mutex:
            selftest = self._status["selftest"]
            if isinstance(selftest, dict) and type(selftest.get("result")) is str:
                return selftest["result"]
            return None

    def run_selftest(self, context: SelftestContext) -> SelftestOutcome:
        """Run the selftest of design section 20: trials T0 to T4 in throwaway repositories (task 5.2).

        The steps, in order:

        1. The run ID (the start in UTC), the tokens, and the five invocations of
           ``command.build_selftest_invocation``. A refusal raises :class:`SelftestRefused`.
        2. The record and the output directory of the run ID must not exist in
           ``.private/handoff/selftest/`` (:class:`UnsafeLocation`).
        3. :func:`kiro_fingerprint`: ``kiro-cli --version`` and the files of ``config_sha256``.
        4. ``kiro-cli whoami`` once, in the environment of ``command.child_env``
           (:class:`LoginRequired`, :class:`KiroCliMissing`).
        5. Free space below ``worktrees_root`` (:class:`DiskSpaceLow`), and the places
           resolved with ``os.path.realpath``: ``<worktrees_root>/selftest`` meets no main working
           tree of ``repos``, this repository's main working tree or the IDE session worktree
           directory, and the run's directory is new and below it (:class:`UnsafeLocation`).
        6. The trials, in order. For each: a new bare repository and a clone with one commit on
           ``main`` (T2: ``remote.origin.pushurl`` set to the bare repository and one more
           commit, so that a push that reaches it changes a ref), the bare repository's refs,
           then ``kiro-cli`` with the trial's argv in the environment of ``command.child_env``
           plus ``HANDOFF_GUARD_LOG`` naming the trial's guard log. Its output is saved below
           ``.private/handoff/selftest/<run ID>/``, the effects are read with the harness's own
           git, the guard log is read, and ``evaluate.trial_outcome`` decides. A T0 that is
           not ``completed`` ends the trials; so does a trial whose repositories could not be
           made. A trial that did not start counts as ``failed_otherwise``.
        7. After the last trial, ``git ls-remote`` on each trial's bare repository (task 5.8), and
           ``evaluate.gh_auth_failed`` on T3. ``evaluate.selftest_verdict`` decides: T0
           ``completed``, T1 and T2 ``blocked_by_guard`` (so T2's push did not take effect),
           ``gh auth status`` failed in T3 (a non-zero ``gh-exit`` was observed), and no remote
           holds a ref other than before. A success of the push or of ``gh auth status``, or a
           branch on a remote, gives ``unconfirmed`` (Requirements 28.16, 28.17). The record
           keeps ``gh_failed``, ``remote_branch_absent`` and ``ls_remote`` of each trial. Then
           the record and ``selftest`` of ``status.json``: ``result``, ``at``,
           ``kiro_cli_version``, ``record`` and ``config_sha256``.

        Up to step 5 nothing is written, and an error leaves ``status.json`` and an earlier
        result as they were. A ``KeyboardInterrupt`` during the trials stops the running
        ``kiro-cli``, writes the record with ``result`` ``null``, does not change
        ``status.json``, and goes on. The repositories are kept: every input of the decision
        is in the record.

        Args:
            context: The checked inputs.

        Returns:
            The result and where it was written.

        Raises:
            TypeError: ``context`` is not a :class:`SelftestContext`.
            RunnerError: The harness is closed, an item runs in it, or ``handoff_dir`` is not
                in ``context.harness_tree``.
            SelftestRefused: Step 1.
            UnsafeLocation: Steps 2 and 5, or a file resolves outside ``.private/handoff``.
            KiroCliMissing: Steps 3 and 4.
            LoginRequired: Step 4.
            DiskSpaceLow: Step 5.
            KeyboardInterrupt: The harness was interrupted.
        """
        if not isinstance(context, SelftestContext):
            raise TypeError(f"context must be a SelftestContext, not {type(context).__name__}")
        if not (is_within(self._handoff_dir, context.harness_tree) and self._handoff_dir != context.harness_tree):
            raise RunnerError(f"{self._handoff_dir} is not in the harness tree {context.harness_tree}")
        with self._mutex:
            if self._closed:
                raise RunnerError("the harness is closed; open it again")
            if self._active_repos:
                raise RunnerError("an item runs in this harness; run the selftest on its own")
        return _Selftest(self, context).run()

    def _record_selftest(self, entry: dict[str, Any]) -> None:
        """Replace ``selftest`` of the status with a new result, and write the status."""
        with self._mutex:
            status = copy.deepcopy(self._status)
            status["selftest"] = entry
            self._commit(status)

    def _record_event(self, kind: str, detail: str) -> None:
        """Add one entry to ``events`` and write the status."""
        with self._mutex:
            self._commit(state.record_event(self._status, at=_now(), kind=kind, detail=detail))

    def _publish_record(self, item_id: str, published: Mapping[str, Any], *, event: tuple[str, str] | None) -> None:
        """Replace ``published`` of an item's record, with an event if given, and write the status."""
        with self._mutex:
            status = copy.deepcopy(self._status)
            _set_fields(status["items"][item_id], {"published": dict(published)})
            if event is not None:
                status = state.record_event(status, at=_now(), kind=event[0], detail=event[1])
            self._commit(status)

    def _context_item(self, context: RunContext, item_id: str) -> Item:
        """Check the context and return the manifest's item, for :meth:`run_query_item` and :meth:`draw_prompt`.

        Raises:
            TypeError: ``context`` is not a :class:`RunContext`.
            RunnerError: The manifest has no such item, or ``handoff_dir`` is not in the harness tree.
        """
        if not isinstance(context, RunContext):
            raise TypeError(f"context must be a RunContext, not {type(context).__name__}")
        item = context.manifest.by_id.get(item_id)
        if item is None:
            raise RunnerError(f"the manifest has no item {item_id!r}")
        if not (is_within(self._handoff_dir, context.harness_tree) and self._handoff_dir != context.harness_tree):
            raise RunnerError(f"{self._handoff_dir} is not in the harness tree {context.harness_tree}")
        return item

    def _move(self, item_id: str, to_state: str, reason: str, **fields: Any) -> None:
        """Apply one transition, set fields of the item's record, and write the status."""
        with self._mutex:
            status = state.transition(self._status, item_id, to_state, at=_now(), reason=reason)
            _set_fields(status["items"][item_id], fields)
            self._commit(status)

    def _update(self, item_id: str, **fields: Any) -> None:
        """Set fields of an item's record without a transition, and write the status."""
        with self._mutex:
            status = copy.deepcopy(self._status)
            _set_fields(status["items"][item_id], fields)
            self._commit(status)

    def _commit(self, status: state.StatusDoc) -> None:
        """Write a status and make it the current one. Fails when the harness is closed."""
        with self._mutex:
            if self._closed:
                raise RunnerError("the harness is closed; open it again")
            self._file.save(status)
            self._status = status

    def _record_stale_lock(self, stale: StaleLock) -> None:
        """Record in ``events`` that :meth:`open` removed a stale lock."""
        detail = f"the lock named pid {stale.pid} (started {_clip(stale.started_at)}), which no longer runs"
        with self._mutex:
            self._commit(state.record_event(self._status, at=_now(), kind=STALE_LOCK_REMOVED, detail=detail))
            self._stale_lock = stale

    def _reconcile(self) -> None:
        """Move each ``running`` record whose ``kiro-cli`` is gone to ``failed`` (``harness_interrupted``)."""
        with self._mutex:
            status = self._status
            moved: list[str] = []
            for item_id in sorted(status["items"]):
                record = status["items"][item_id]
                if record["state"] != state.RUNNING:
                    continue
                pid = record["pid"]
                if pid is not None and _session_leader_alive(pid):
                    continue
                status = state.transition(status, item_id, state.FAILED, at=_now(), reason=HARNESS_INTERRUPTED)
                status["items"][item_id]["pid"] = None
                moved.append(item_id)
                _LOG.warning("%s was running when an earlier harness ended; it is now failed", item_id)
            if moved:
                self._commit(status)
            self._interrupted = tuple(moved)

    @contextmanager
    def _reserve(self, manifest: Manifest, item: Item) -> Iterator[None]:
        """Keep other runs off the item's repository while the item runs in this harness."""
        with self._mutex:
            if self._closed:
                raise RunnerError("the harness is closed; open it again")
            record = self._status["items"].get(item.id)
            if record is None:
                raise RunnerError(f"status.json has no record of {item.id}; call add_missing_items first")
            if record["state"] != state.QUEUED:
                raise RunnerError(f"{item.id} is {record['state']}, not queued")
            if item.repo in self._active_repos:
                raise RunnerError(f"another item of {item.repo} runs in this harness")
            repos = {listed.id: listed.repo for listed in manifest.items}
            for other_id, other in self._status["items"].items():
                if other["state"] == state.RUNNING and repos.get(other_id) in (item.repo, None):
                    raise RunnerError(
                        f"{other_id} is running in {repos.get(other_id) or 'a repository the manifest does not name'}"
                    )
            self._active_repos.add(item.repo)
        try:
            yield
        finally:
            with self._mutex:
                self._active_repos.discard(item.repo)


class _Stopped(Exception):
    """A stop request came before ``kiro-cli`` started."""


class _StepFailed(Exception):
    """A git command of the preparation or the observation did not succeed.

    Attributes:
        what: The step, for the reason (``git status`` of the main working tree, ...).
        result: The process, or ``None`` when its output could not be read.
        detail: The command, how it ended and the end of its standard error.
    """

    def __init__(self, what: str, result: ProcessResult | None, detail: str) -> None:
        """Build the error.

        Args:
            what: The step.
            result: The process.
            detail: The detail.
        """
        super().__init__(f"{what}: {detail}")
        self.what = what
        self.result = result
        self.detail = detail


@dataclass(frozen=True, slots=True)
class _ConflictCheck:
    """Step 5 of a change run, for the Handoff_Report.

    Attributes:
        origin_main: ``refs/remotes/origin/main`` of the main working tree after the fetch.
        default_branch_files: The files of ``git diff --name-only <base_sha> <origin_main>``, sorted.
        conflicts: The item's changed files among them (``evaluate.conflicting_files``).
    """

    origin_main: str
    default_branch_files: tuple[str, ...]
    conflicts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Rerun:
    """One declared verification command of a change run (step 6), for the Handoff_Report.

    Attributes:
        cmd: The argv, as declared.
        skip_reason: Why it was not run, or ``None`` when it ran.
        result: How it ran, or ``None`` when it did not.
    """

    cmd: tuple[str, ...]
    skip_reason: str | None
    result: ProcessResult | None


class _QueryRun:
    """One query item from ``queued`` to its final state. :meth:`Harness.run_query_item` uses it once.

    :meth:`Harness.draw_prompt` uses one for :meth:`draw` alone, for an item of either mode, and
    :class:`_ChangeRun` builds on it for a change item.
    """

    def __init__(self, harness: Harness, context: RunContext, item: Item, stop: threading.Event | None) -> None:
        """Keep the inputs of the run.

        Args:
            harness: The harness, which owns the status.
            context: The checked inputs.
            item: The item: a query item, or a change item for :class:`_ChangeRun`.
            stop: The stop request, or ``None``.
        """
        self.harness = harness
        self.context = context
        self.config = context.config
        self.item = item
        self.stop = stop
        self.directory = harness.handoff_dir
        self.files = command.handoff_files(
            self.directory,
            repo=item.repo,
            item_id=item.id,
            sync_point=item.sync_point,
            split=command.prompt_is_split(context.manifest.items, item),
        )
        self.main_tree = self.config.repos[item.repo].main_tree
        self.git_env = git_environment(os.environ)
        self.timeout = self.config.timeout_seconds
        self.grace = context.kill_grace_seconds
        self.prompt_path: str | None = None
        self.worktree: str | None = None
        self.base_sha: str | None = None
        self.branch: str | None = None
        self.plan: command.GitPlan | None = None

    def run(self) -> ItemOutcome:
        """Carry out the steps of the module docstring.

        Returns:
            The outcome.
        """
        try:
            return self._run()
        except _Stopped:
            _LOG.info("%s: stopped before kiro-cli started; it stays queued", self.item.id)
            return self._outcome(state.QUEUED, "stopped before kiro-cli started", "")

    def draw(self) -> PromptDraft:
        """Steps 1 and 2: the prompt path, the template, the uncommitted count, the body and its checks.

        Changes no state; :meth:`_run` holds the item with the draft's reason, if any.
        """
        item, context, files = self.item, self.context, self.files
        sharers = _prompt_sharers(context.manifest, item, self.directory, files.prompt)
        if sharers:
            return self._draft(
                "prompt_path_shared",
                f"{_rel(files.prompt, self.directory)} is also the Handoff_Prompt path of {', '.join(sharers)}; "
                "neither is written or started until the manifest gives them separate paths",
            )
        for path in (files.prompt, files.report, files.status):
            _check_below(path, self.directory)
        try:
            template_text = _read_template(posixpath.join(self.directory, item.template), self.directory)
        except (OSError, UnicodeDecodeError, UnsafeLocation) as exc:
            return self._draft("template_unreadable", f"{item.template}: {exc}")
        try:
            uncommitted = _status_entry_count(self._main_tree_status())
        except _StepFailed as failure:
            return self._draft("main_tree_unreadable", failure.detail)
        try:
            rendered = prompt.render(
                context.manifest,
                item.id,
                config=self.config,
                template_text=template_text,
                uncommitted_count=uncommitted,
                confirmed_refs=context.confirmed_refs,
                home=context.home,
                deny_terms=context.deny.terms,
            )
        except prompt.PromptError as error:
            kinds = ", ".join(dict.fromkeys(issue.kind for issue in error.issues))
            return self._draft(f"prompt_not_drawn ({kinds})", str(error), uncommitted=uncommitted)
        _write_file(files.prompt, rendered.body.encode("utf-8"), self.directory)
        invocation: command.KiroInvocation | None = None
        git_plan: command.GitPlan | None = None
        refusals: list[command.CommandError] = []
        agent = self.config.agents.get(item.mode)
        agent_approved = agent is not None and (agent, item.mode) in context.approved_agents
        try:
            invocation = command.build_kiro_invocation(
                self.config,
                item,
                rendered,
                home=context.home,
                selftest_result=self.harness.selftest_result(),
                approved_agents=frozenset({agent}) if agent is not None and agent_approved else frozenset(),
            )
        except command.CommandError as error:
            refusals.append(error)
        try:
            git_plan = command.build_git_plan(self.config, item)
        except command.CommandError as error:
            refusals.append(error)
        hold: tuple[str, str] | None = None
        if rendered.needs_human:
            found = ", ".join(f"line {finding.line}: {finding.kind}" for finding in rendered.findings) or "none"
            hold = (
                _present(rendered.history_reason),
                f"the Handoff_Prompt {_rel(files.prompt, self.directory)} is held and not passed on "
                f"({rendered.byte_length} bytes; scan findings: {found})",
            )
        elif rendered.executor_choice.executor is not Executor.TARGET_REPO_KIRO:
            rows = ", ".join(str(number) for number in rendered.executor_choice.rows)
            hold = (
                EXECUTOR_IS_THIS_SESSION,
                f"only rows {rows} of the executor table apply, so this session carries {item.id} out; "
                f"its Handoff_Prompt is not passed to the Kiro of {item.repo}",
            )
        elif refusals:
            hold = (refusals[0].history_reason, str(refusals[0]))
        elif agent is not None and not agent_approved:
            hold = (
                AGENT_NOT_APPROVED,
                f"agents.{item.mode} of config.json names the agent configuration {agent}, and no approval of "
                f"{agent} for the {item.mode} mode passed the checks of cli.py (agents/approved.json); the item is "
                "not started with the default agent instead",
            )
            invocation = None
        return PromptDraft(
            item_id=item.id,
            path=files.prompt,
            written=True,
            rendered=rendered,
            uncommitted_count=uncommitted,
            git_plan=git_plan,
            invocation=invocation,
            hold_reason=None if hold is None else hold[0],
            detail="" if hold is None else hold[1],
        )

    def _draft(self, reason: str, detail: str, *, uncommitted: int | None = None) -> PromptDraft:
        """A draft whose body was not drawn or not written, with the reason that holds the item."""
        return PromptDraft(
            item_id=self.item.id,
            path=self.files.prompt,
            written=False,
            rendered=None,
            uncommitted_count=uncommitted,
            git_plan=None,
            invocation=None,
            hold_reason=reason,
            detail=detail,
        )

    def _run(self) -> ItemOutcome:
        """Steps 1 to 7, up to the start of ``kiro-cli``."""
        item = self.item
        draft = self.draw()
        if draft.written:
            self.prompt_path = draft.path
        if draft.hold_reason is not None:
            return self._hold(draft.hold_reason, draft.detail)
        invocation, plan, rendered = _present(draft.invocation), _present(draft.git_plan), _present(draft.rendered)
        self._check_stop()
        with _ChildPaths() as child:
            env = command.child_env(
                os.environ,
                push_url=child.push_url,
                gh_config_dir=child.gh_config_dir,
                aws_empty_file=child.aws_empty_file,
                path_prepend=self._path_prepend(),
            )
            self._check_login(invocation.argv[0], env, child.directory)
            self._check_disk()
            self._check_location(plan)
            if os.path.lexists(plan.worktree):
                return self._hold(
                    "worktree_exists",
                    f"{plan.worktree} exists already, from an earlier run or by hand; remove it with "
                    f"cli.py cleanup {item.id} after reading it, then queue the item again",
                )
            problems = self._prerequisite_problems()
            if problems:
                return self._hold(
                    "prerequisite_missing",
                    f"{item.repo} needs these from its main working tree, and they are not usable: "
                    f"{'; '.join(problems)}. No worktree was made",
                )
            held = self._create_worktree(plan)
            if held is not None:
                return held
            held = self._provide_copies()
            if held is not None:
                return held
            if invocation.agent is not None:
                shadows = _agent_shadows(_present(self.worktree), invocation.agent)
                if shadows:
                    return self._hold(
                        AGENT_SHADOWED,
                        f"the worktree has what kiro-cli could read as the agent configuration {invocation.agent} "
                        f"instead of the approved global one: {'; '.join(shadows)}. kiro-cli was not started, and "
                        f"the worktree is kept for cli.py cleanup {item.id}",
                    )
            try:
                before = self._snapshot()
            except _StepFailed as failure:
                return self._hold("main_tree_unreadable", failure.detail)
            return self._launch(invocation, rendered, before, env)

    def _launch(
        self,
        invocation: command.KiroInvocation,
        rendered: prompt.RenderedPrompt,
        before: evaluate.MainTreeSnapshot,
        env: Mapping[str, str],
    ) -> ItemOutcome:
        """Step 7: move to ``running`` and run ``kiro-cli``, then finish."""
        item = self.item
        _retire_report(self.files.report, self.directory)
        self.harness._move(
            item.id,
            state.RUNNING,
            DISPATCHED,
            pid=None,
            worktree=_tilde(_present(self.worktree), self.context.home),
            branch=self.branch,
            base_sha=self.base_sha,
            report=_rel(self.files.report, self.directory),
            observations=None,
            rerun=[],
            rerun_skipped=[],
            report_flags=[],
        )
        result = _run_process(
            invocation.argv,
            cwd=invocation.cwd,
            env=env,
            timeout_seconds=invocation.timeout_seconds,
            kill_grace_seconds=self.grace,
            stop=self.stop,
            on_start=lambda pid: self.harness._update(item.id, pid=pid),
        )
        return self._finish(_Report(self, invocation, rendered, result, before), result, before)

    def _finish(self, report: _Report, result: ProcessResult, before: evaluate.MainTreeSnapshot) -> ItemOutcome:
        """Step 8: save the output, observe, decide and record the final state."""
        report.write()
        if result.ending == "interrupted":
            self._end(report, state.FAILED, HARNESS_INTERRUPTED, note="ハーネスが中断された（KeyboardInterrupt）")
            raise KeyboardInterrupt
        if result.ending == "stopped":
            return self._end(report, state.FAILED, HARNESS_INTERRUPTED, note="停止の依頼を受けて止めた")
        if result.ending == "not_started":
            return self._end(
                report, state.FAILED, "kiro_cli_not_started", note=f"起動できなかった: {result.start_error}"
            )
        if result.exit_code is None:
            return self._end(report, state.FAILED, "kiro_cli_not_reaped", note="SIGKILL の後も終了を確かめられなかった")
        try:
            observations, after = self._observe(result, before)
        except _StepFailed as failure:
            if result.timed_out:
                return self._end(report, state.FAILED, "timed_out, observation_failed", note=failure.detail)
            return self._end(report, state.NEEDS_HUMAN, "observation_failed", note=failure.detail)
        except _Stopped:
            return self._end(report, state.FAILED, HARNESS_INTERRUPTED, note=STOPPED_WHILE_OBSERVING)
        except KeyboardInterrupt:
            self._end(report, state.FAILED, HARNESS_INTERRUPTED, note="観測の途中でハーネスが中断された")
            raise
        evaluation = self._evaluate(observations)
        return self._end(
            report,
            evaluation.state,
            evaluation.history_reason,
            observations=observations,
            after=after,
        )

    def _evaluate(self, observations: evaluate.Observations) -> evaluate.Evaluation:
        """Decide the final state from the observations alone (``evaluate.final_state``); the report is not an input."""
        return evaluate.final_state(
            observations,
            mode=self.item.mode,
            declared_files=self.item.declared_files,
            verify_commands=[verify.cmd for verify in self.item.verify_commands],
        )

    def _end(
        self,
        report: _Report,
        to_state: str,
        reason: str,
        *,
        note: str | None = None,
        observations: evaluate.Observations | None = None,
        after: evaluate.MainTreeSnapshot | None = None,
    ) -> ItemOutcome:
        """Record the final state of a run that started, then write the report again with it."""
        flags = report.flags()
        fields: dict[str, Any] = {"pid": None, "report_flags": [flag.to_json() for flag in flags]}
        if observations is not None:
            fields.update(observations.to_json())
        self.harness._move(self.item.id, to_state, reason, **fields)
        report.write(final=(to_state, reason), note=note, observations=observations, after=after, flags=flags)
        result = report.result
        _LOG.info("%s: %s (%s)", self.item.id, to_state, reason)
        if report.kiro_error is not None:
            self.harness._record_event(
                KIRO_ERROR_EVENTS[report.kiro_error],
                f"{self.item.id}: kiro-cli exited with code {result.exit_code} and its standard error held the "
                f"wording of {report.kiro_error} (a heuristic match; the final state and reason are unchanged)",
            )
        return ItemOutcome(
            item_id=self.item.id,
            state=to_state,
            reason=reason,
            detail=note or "",
            prompt=self.prompt_path,
            report=self.files.report,
            worktree=self.worktree,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            kiro_error=report.kiro_error,
        )

    def _hold(self, reason: str, detail: str) -> ItemOutcome:
        """Move the item from ``queued`` to ``needs-human`` before ``kiro-cli`` started."""
        fields: dict[str, Any] = {}
        if self.worktree is not None:
            fields = {"worktree": _tilde(self.worktree, self.context.home), "base_sha": self.base_sha}
        if self.branch is not None:
            fields["branch"] = self.branch
        self.harness._move(self.item.id, state.NEEDS_HUMAN, reason, **fields)
        _LOG.info("%s: needs-human (%s)", self.item.id, reason)
        return self._outcome(state.NEEDS_HUMAN, reason, detail)

    def _outcome(self, item_state: str, reason: str, detail: str) -> ItemOutcome:
        """Build the outcome of a run in which ``kiro-cli`` did not start."""
        return ItemOutcome(
            item_id=self.item.id,
            state=item_state,
            reason=reason,
            detail=detail,
            prompt=self.prompt_path,
            report=None,
            worktree=self.worktree,
            exit_code=None,
            timed_out=False,
        )

    def _check_stop(self) -> None:
        """Raise :class:`_Stopped` when a stop was requested."""
        if self.stop is not None and self.stop.is_set():
            raise _Stopped

    def _check_login(self, program: str, env: Mapping[str, str], cwd: str) -> None:
        """Step 3: ``kiro-cli whoami`` in the environment of the run."""
        self._check_stop()
        result = _run_process(
            (program, "whoami"),
            cwd=cwd,
            env=env,
            timeout_seconds=self.timeout,
            kill_grace_seconds=self.grace,
            stop=self.stop,
        )
        if result.ending == "interrupted":
            raise KeyboardInterrupt
        if result.ending == "stopped":
            raise _Stopped
        if result.ending == "not_started":
            raise KiroCliMissing(
                f"{program} cannot be started ({result.start_error}); use cli.py manual {self.item.id} instead"
            )
        if not result.ok:
            raise LoginRequired(
                f"`kiro-cli whoami` {_how(result)}: log in to kiro-cli, then run again. No item was started; "
                f"{self.item.id} and the other queued items stay queued"
            )

    def _check_disk(self) -> None:
        """Step 4: free space below ``worktrees_root``, before a worktree exists."""
        probe = _existing_ancestor(self.config.worktrees_root)
        free = shutil.disk_usage(probe).free
        if free < self.config.min_free_disk_bytes:
            raise DiskSpaceLow(probe, free, self.config.min_free_disk_bytes)

    def _check_location(self, plan: command.GitPlan) -> None:
        """Step 5: compare the places again after resolving symbolic links, then create ``worktrees_root``.

        Two checks, on resolved paths: ``worktrees_root`` meets no protected tree, and the
        worktree is strictly below ``worktrees_root``. Together they keep the worktree out of
        every protected tree, since a path below ``worktrees_root`` that met a protected tree
        would make that tree meet ``worktrees_root`` too. Nothing is created before both pass.
        """
        root = self.config.worktrees_root
        root_real = os.path.realpath(root)
        protected = [(f"the main working tree of {name}", repo.main_tree) for name, repo in self.config.repos.items()]
        protected.append(("this repository's main working tree", self.context.harness_tree))
        protected.append(("the IDE session worktree directory", self.context.session_worktrees_dir))
        problems: list[str] = []
        for label, path in sorted(protected):
            real = os.path.realpath(path)
            if overlaps(root_real, real):
                problems.append(f"worktrees_root {root} resolves to {root_real}, which meets {label} ({real})")
        worktree_real = os.path.realpath(plan.worktree)
        if not is_within(worktree_real, root_real) or is_within(root_real, worktree_real):
            problems.append(f"the worktree {plan.worktree} resolves to {worktree_real}, outside {root_real}")
        if problems:
            raise UnsafeLocation("; ".join(problems))
        os.makedirs(root, exist_ok=True)

    def _create_worktree(self, plan: command.GitPlan) -> ItemOutcome | None:
        """Step 6: decision D-15. Returns the outcome when the item is held, ``None`` when the worktree exists."""
        self.plan = plan
        if plan.branch is not None:
            try:
                taken = branch_exists(plan.main_tree, plan.branch, timeout_seconds=self.timeout)
            except GitCommandFailed as error:
                return self._hold("git_branch_lookup_failed", str(error))
            if taken:
                return self._hold(
                    "branch_exists",
                    f"{plan.branch} exists already in {plan.main_tree}, from an earlier run or by hand. "
                    "git worktree add -b would fail on it and the branch is never reset. Read it, then remove it "
                    f"(cli.py cleanup {self.item.id} --approved removes one that has no commit) and queue the item again",
                )
        agreed: str | None = None
        attempts: list[str] = []
        for attempt in (1, 2):
            fetched = self._git(plan.fetch)
            if not fetched.ok:
                return self._hold(f"git_fetch_failed ({_how(fetched)})", _detail(fetched))
            listed = self._git(plan.ls_remote)
            if not listed.ok:
                return self._hold(f"git_ls_remote_failed ({_how(listed)})", _detail(listed))
            remote = _ls_remote_sha(listed.stdout, REMOTE_MAIN_REF)
            if remote is None:
                return self._hold("remote_main_missing", f"git ls-remote printed no single SHA for {REMOTE_MAIN_REF}")
            parsed = self._git(plan.rev_parse)
            if not parsed.ok:
                return self._hold(f"git_rev_parse_failed ({_how(parsed)})", _detail(parsed))
            local = parsed.stdout.decode("utf-8", "replace").strip()
            if local == remote:
                agreed = remote
                break
            attempts.append(f"attempt {attempt}: ls-remote {remote}, rev-parse {local}")
            _LOG.warning("%s: ls-remote and rev-parse disagree (%s)", self.item.id, attempts[-1])
        if agreed is None:
            return self._hold("base_sha_mismatch", "; ".join(attempts))
        try:
            add = plan.worktree_add(agreed)
        except command.CommandError as error:
            return self._hold(error.history_reason, str(error))
        created = self._git(add)
        if not created.ok:
            if os.path.lexists(plan.worktree):
                self.worktree, self.base_sha = plan.worktree, agreed
            return self._hold(f"git_worktree_add_failed ({_how(created)})", _detail(created))
        self.worktree, self.base_sha, self.branch = plan.worktree, agreed, plan.branch
        if plan.branch is not None:
            followed = self._git(plan.set_upstream())
            if not followed.ok:
                return self._hold(f"git_set_upstream_failed ({_how(followed)})", _detail(followed))
        return None

    def _prerequisites(self) -> Prerequisites | None:
        """What the repository's change items take from the main working tree; ``None`` for a query item or none."""
        if self.item.mode != "change":
            return None
        return self.config.repos[self.item.repo].prerequisites

    def _path_prepend(self) -> tuple[str, ...]:
        """The directories for the front of ``PATH`` of ``kiro-cli`` and of the re-runs, absolute."""
        wanted = self._prerequisites()
        return () if wanted is None else tuple(posixpath.join(self.main_tree, rel) for rel in wanted.path_prepend)

    def _prerequisite_problems(self) -> list[str]:
        """What keeps the prerequisites from being provided, read before a worktree is made. Empty when all is usable."""
        wanted = self._prerequisites()
        if wanted is None:
            return []
        problems: list[str] = []
        real_tree = os.path.realpath(self.main_tree)
        for rel in wanted.copy_readonly:
            source = posixpath.join(self.main_tree, rel)
            if not os.path.lexists(source):
                problems.append(f"{rel} is not in the main working tree")
            elif os.path.islink(source) or not is_within(os.path.realpath(source), real_tree):
                problems.append(f"{rel} is a symbolic link or resolves outside the main working tree")
            elif links := _symlinks_below(source):
                problems.append(
                    f"{rel} holds symbolic links ({', '.join(links[:3])}), which a read-only copy cannot keep safe"
                )
        for rel in wanted.path_prepend:
            if not os.path.isdir(posixpath.join(self.main_tree, rel)):
                problems.append(f"{rel} is not a directory in the main working tree")
        return problems

    def _provide_copies(self) -> ItemOutcome | None:
        """Copy each ``copy_readonly`` path into the worktree, check that git ignores it there, and make it read-only.

        Returns:
            The outcome when the item is held (the copy is withdrawn first), ``None`` when all copies are in place.
        """
        wanted = self._prerequisites()
        if wanted is None or not wanted.copy_readonly:
            return None
        worktree = _present(self.worktree)
        kept = f"kiro-cli was not started, and the worktree is kept for cli.py cleanup {self.item.id}"
        for rel in wanted.copy_readonly:
            source, target = posixpath.join(self.main_tree, rel), posixpath.join(worktree, rel)
            if os.path.lexists(target):
                return self._hold(
                    "prerequisite_target_exists",
                    f"{rel} exists in the worktree already, so it is not overwritten; {kept}",
                )
            try:
                _check_below(target, worktree)
                os.makedirs(posixpath.dirname(target), exist_ok=True)
                _copy_prerequisite(source, target)
            except (OSError, UnsafeLocation) as error:
                _remove_prerequisite_copy(target)
                return self._hold(
                    "prerequisite_copy_failed", f"copying {rel} into the worktree failed: {error}; {kept}"
                )
            try:
                ignored = (
                    self._read(
                        ("git", "--no-optional-locks", "-C", worktree, "check-ignore", "-q", "--", rel),
                        worktree,
                        "git check-ignore of a copied prerequisite",
                        allowed=(0, 1),
                    ).exit_code
                    == 0
                )
            except _StepFailed as failure:
                _remove_prerequisite_copy(target)
                return self._hold("prerequisite_ignore_check_failed", f"{failure.detail}; {kept}")
            if not ignored:
                _remove_prerequisite_copy(target)
                return self._hold(
                    "prerequisite_not_ignored",
                    f"git does not ignore {rel} in the worktree, so a copy could be committed; the copy was withdrawn. "
                    f"Ignore it in {self.item.repo} (.gitignore or .git/info/exclude); {kept}",
                )
            _make_readonly(target)
        return None

    def _git(self, step: command.Command) -> ProcessResult:
        """Run a command of the git plan, which a stop request or an interrupt can end."""
        self._check_stop()
        result = _run_process(
            step.argv,
            cwd=step.cwd,
            env=self.git_env,
            timeout_seconds=self.timeout,
            kill_grace_seconds=self.grace,
            stop=self.stop,
        )
        if result.ending == "interrupted":
            raise KeyboardInterrupt
        if result.ending == "stopped":
            raise _Stopped
        return result

    def _read(self, argv: tuple[str, ...], cwd: str, what: str, *, allowed: tuple[int, ...] = (0,)) -> ProcessResult:
        """Run a git command that only reads, and require one of the allowed exit codes."""
        result = _run_process(
            argv, cwd=cwd, env=self.git_env, timeout_seconds=self.timeout, kill_grace_seconds=self.grace
        )
        if result.ending == "interrupted":
            raise KeyboardInterrupt
        if result.ending != "exited" or result.exit_code not in allowed:
            raise _StepFailed(what, result, _detail(result))
        return result

    def _main_tree_status(self) -> str:
        """``git status --porcelain=v1 -z`` of the main working tree, without taking the index lock."""
        argv = ("git", "--no-optional-locks", "-C", self.main_tree, "status", "--porcelain=v1", "-z")
        output = self._read(argv, self.main_tree, "git status of the main working tree").stdout
        return output.decode("utf-8", "replace")

    def _snapshot(self) -> evaluate.MainTreeSnapshot:
        """``HEAD``, the branch and ``git status`` of the main working tree, read only."""
        text = self._main_tree_status()
        head = self._head(self.main_tree, "HEAD of the main working tree", unborn_ok=True)
        argv = ("git", "--no-optional-locks", "-C", self.main_tree, "branch", "--show-current")
        branch = self._read(argv, self.main_tree, "the branch of the main working tree").stdout
        try:
            entries = evaluate.parse_status_z(text)
            return evaluate.MainTreeSnapshot(
                head=head, branch=branch.decode("utf-8", "replace").strip() or None, status=entries
            )
        except evaluate.EvaluationError as exc:
            raise _StepFailed("git status of the main working tree", None, str(exc)) from exc

    def _head(self, tree: str, what: str, *, unborn_ok: bool) -> str | None:
        """``git rev-parse --verify -q HEAD``: the SHA, or ``None`` on a branch with no commit."""
        argv = ("git", "--no-optional-locks", "-C", tree, "rev-parse", "--verify", "-q", "HEAD")
        result = self._read(argv, tree, what, allowed=(0, 1) if unborn_ok else (0,))
        if result.exit_code != 0:
            return None
        return result.stdout.decode("utf-8", "replace").strip() or None

    def _observe(
        self, result: ProcessResult, before: evaluate.MainTreeSnapshot
    ) -> tuple[evaluate.Observations, evaluate.MainTreeSnapshot]:
        """Build the observations of a query run (design section 20, "結果の確認").

        Returns:
            The observations, and the snapshot of the main working tree that they compare
            with ``before``. The snapshot is taken first.
        """
        after = self._snapshot()
        worktree, base = _present(self.worktree), _present(self.base_sha)
        argv = ("git", "--no-optional-locks", "-C", worktree, "status", "--porcelain=v1", "-z")
        dirty = bool(self._read(argv, worktree, "git status of the worktree").stdout)
        head = self._head(worktree, "HEAD of the worktree", unborn_ok=False)
        commits = 0
        changed: tuple[str, ...] = ()
        if head != base:
            counted = self._read(
                ("git", "-C", worktree, "rev-list", "--count", f"{base}..HEAD"), worktree, "commits in the worktree"
            )
            try:
                commits = int(counted.stdout.decode("ascii", "replace").strip())
            except ValueError as exc:
                raise _StepFailed("commits in the worktree", counted, "rev-list printed no number") from exc
            names = self._read(
                ("git", "-C", worktree, "diff", "--name-only", "--no-renames", "-z", base, "HEAD"),
                worktree,
                "files changed in the worktree",
            ).stdout.decode("utf-8", "replace")
            changed = tuple(sorted({name for name in names.split("\0") if name}))
        try:
            observations = evaluate.Observations(
                exit_code=_present(result.exit_code),
                timed_out=result.timed_out,
                stdout_bytes=len(result.stdout),
                commits=commits,
                changed_files=changed,
                undeclared_files=evaluate.undeclared_files(changed, self.item.declared_files),
                dirty=dirty,
                conflicts=(),
                remote_branch_exists=False,
                main_tree_change=evaluate.main_tree_change(before, after, self.item.declared_files),
                rerun=(),
                rerun_skipped=(),
            )
        except evaluate.EvaluationError as exc:
            raise _StepFailed("the observations", None, str(exc)) from exc
        return observations, after

    def report_data(self) -> dict[str, Any]:
        """More keys for the JSON block of the Handoff_Report's observations; none for a query run."""
        return {}

    def report_sections(self) -> list[str]:
        """More lines for the Handoff_Report, after the observations' notes; none for a query run."""
        return []


class _ChangeRun(_QueryRun):
    """One change item from ``queued`` to its final state. :meth:`Harness.run_change_item` uses it once.

    The steps of :class:`_QueryRun`; the worktree is on ``handoff/<id>`` (``command.build_git_plan``)
    and the observations are those of the change mode (the module docstring).
    """

    def __init__(self, harness: Harness, context: RunContext, item: Item, stop: threading.Event | None) -> None:
        """Keep the inputs of the run, as :class:`_QueryRun` does.

        Args:
            harness: The harness, which owns the status.
            context: The checked inputs.
            item: The change item.
            stop: The stop request, or ``None``.
        """
        super().__init__(harness, context, item, stop)
        self.commits: tuple[tuple[str, str], ...] | None = None
        self.conflict_check: _ConflictCheck | None = None
        self.reruns: list[_Rerun] | None = None

    def report_data(self) -> dict[str, Any]:
        """The commits since the base and the conflict check; ``None`` for what was not reached.

        Returns:
            ``commits`` as ``{"sha", "subject"}`` objects, and ``conflict_check`` as
            ``{"origin_main", "default_branch_files", "conflicts"}``.
        """
        commits = None if self.commits is None else [{"sha": sha, "subject": text} for sha, text in self.commits]
        check = self.conflict_check
        conflict_check = None
        if check is not None:
            conflict_check = {
                "origin_main": check.origin_main,
                "default_branch_files": list(check.default_branch_files),
                "conflicts": list(check.conflicts),
            }
        return {"commits": commits, "conflict_check": conflict_check}

    def report_sections(self) -> list[str]:
        """The conflict check (step 5) and the re-run of each verification command (step 6), with its output."""
        lines = ["", "### 衝突の確認（結果の確認の手順 5）", ""]
        check = self.conflict_check
        if check is None:
            lines.append("行っていない（観測がこの手順の前に終わった）。")
        else:
            lines += [
                f"- `fetch` の後の `origin/main`: {_code(check.origin_main)}",
                f"- base_sha から origin/main までに変わったファイル: {len(check.default_branch_files)} 件",
                *(f"  - {_code(path)}" for path in check.default_branch_files),
                f"- 衝突（この項目が変えたファイルと同じファイル）: {len(check.conflicts)} 件",
                *(f"  - {_code(path)}" for path in check.conflicts),
            ]
        lines += ["", "### 検証コマンドの再実行（結果の確認の手順 6）", ""]
        declared = self.item.verify_commands
        if not declared:
            lines.append("宣言した検証コマンドはない。")
            return lines
        done = self.reruns or []
        if len(done) < len(declared):
            lines += [f"宣言した {len(declared)} 件のうち、観測が終わる前に扱ったのは {len(done)} 件。", ""]
        for index, rerun in enumerate(done, 1):
            if index > 1:
                lines.append("")
            lines += [f"#### {index}. {_code(shlex.join(rerun.cmd))}", ""]
            if rerun.result is None:
                lines.append(f"- 再実行しなかった: {_one_line(rerun.skip_reason or '')}")
                continue
            ran = rerun.result
            lines.append(f"- 再実行した: {_rerun_ending(ran, self.timeout)}、所要時間 {ran.duration_seconds:.1f} 秒")
            if ran.signals:
                lines.append(f"- プロセスグループへのシグナル: {', '.join(ran.signals)}")
            for title, data in (("標準出力", ran.stdout), ("標準エラー出力", ran.stderr)):
                text = data.decode("utf-8", "replace")
                fence = _fence(text)
                lines += [
                    f"- {title}（{len(data)} バイト。UTF-8 として読めないバイトは置換文字にした）:",
                    "",
                    fence + "text",
                    _block(text) + fence,
                ]
        return lines

    def _observe(
        self, result: ProcessResult, before: evaluate.MainTreeSnapshot
    ) -> tuple[evaluate.Observations, evaluate.MainTreeSnapshot]:
        """Build the observations of a change run (design section 20, "結果の確認", and the module docstring).

        Returns:
            The observations, and the snapshot of the main working tree that they compare with
            ``before``, taken last.

        Raises:
            _StepFailed: A git command failed, ``git log`` printed something else than commits,
                the worktree's ``HEAD`` is not on ``handoff/<id>`` or a re-run moved it, or a
                verification command has no exit code to record.
            _Stopped: A stop request came during the fetch or a re-run.
        """
        worktree, base = _present(self.worktree), _present(self.base_sha)
        head = self._branch_head("the branch of the worktree")
        logged = self._read(
            ("git", "-C", worktree, "log", "-z", "--no-show-signature", "--format=%H%x09%s", f"{base}..{head}"),
            worktree,
            "the commits of the worktree",
        )
        self.commits = _commit_subjects(logged.stdout)
        names = self._read(
            ("git", "-C", worktree, "diff", "--name-only", "--no-renames", "-z", base, head),
            worktree,
            "files changed in the worktree",
        ).stdout.decode("utf-8", "replace")
        changed = tuple(sorted({name for name in names.split("\0") if name}))
        dirty = self._worktree_dirty()
        try:
            undeclared = evaluate.undeclared_files(changed, self.item.declared_files)
            conflicts = self._conflicts(changed)
        except evaluate.EvaluationError as exc:
            raise _StepFailed("the observations", None, str(exc)) from exc
        blockers = {
            "timed_out": result.timed_out,
            "exit_code_nonzero": result.exit_code != 0,
            "no_commits": not self.commits,
            "dirty": dirty,
            "undeclared_files": bool(undeclared),
        }
        rerun, rerun_skipped = self._reruns(tuple(name for name in RERUN_BLOCKERS if blockers[name]))
        if rerun:
            # A verification command runs the worktree's code, which can commit or leave files.
            if self._branch_head("the branch of the worktree after the re-runs") != head:
                raise _StepFailed(
                    "the branch of the worktree after the re-runs",
                    None,
                    f"a verification command moved {self.branch} from {head}; the commits that steps 1 and 2 "
                    "observed are no longer the ones the branch would hand over",
                )
            dirty = self._worktree_dirty() or dirty
        listed = self._read(
            ("git", "-C", self.main_tree, "ls-remote", command.REMOTE, f"refs/heads/{_present(self.branch)}"),
            self.main_tree,
            "the handoff branch on the remote",
        )
        after = self._snapshot()
        try:
            observations = evaluate.Observations(
                exit_code=_present(result.exit_code),
                timed_out=result.timed_out,
                stdout_bytes=len(result.stdout),
                commits=len(self.commits),
                changed_files=changed,
                undeclared_files=undeclared,
                dirty=dirty,
                conflicts=conflicts,
                remote_branch_exists=bool(listed.stdout.strip()),
                main_tree_change=evaluate.main_tree_change(before, after, self.item.declared_files),
                rerun=rerun,
                rerun_skipped=rerun_skipped,
            )
        except evaluate.EvaluationError as exc:
            raise _StepFailed("the observations", None, str(exc)) from exc
        return observations, after

    def _branch_head(self, what: str) -> str:
        """The SHA of the worktree's ``HEAD``, which must be on ``handoff/<id>``.

        Raises:
            _StepFailed: ``HEAD`` is detached or on another branch: only ``handoff/<id>`` is handed over.
        """
        worktree, branch = _present(self.worktree), _present(self.branch)
        ref = f"refs/heads/{branch}"
        on = self._read(
            ("git", "--no-optional-locks", "-C", worktree, "symbolic-ref", "-q", "HEAD"),
            worktree,
            what,
            allowed=(0, 1),
        )
        current = on.stdout.decode("utf-8", "replace").strip() if on.exit_code == 0 else ""
        if current != ref:
            raise _StepFailed(
                what,
                None,
                f"HEAD of the worktree {worktree} is {current or 'detached'}, not {ref}; only {branch} is handed over",
            )
        return _present(self._head(worktree, "HEAD of the worktree", unborn_ok=False))

    def _worktree_dirty(self) -> bool:
        """Step 3: whether ``git status --porcelain`` of the worktree prints anything."""
        worktree = _present(self.worktree)
        argv = ("git", "--no-optional-locks", "-C", worktree, "status", "--porcelain=v1", "-z")
        return bool(self._read(argv, worktree, "git status of the worktree").stdout)

    def _conflicts(self, changed: tuple[str, ...]) -> tuple[str, ...]:
        """Step 5, the conflict check, against the default branch after a new fetch.

        Args:
            changed: The item's changed files.

        Returns:
            The changed files that ``origin/main`` also changed since the base, as
            ``evaluate.conflicting_files`` gives them. The check is kept for the report.

        Raises:
            _StepFailed: The fetch, ``rev-parse`` or ``diff`` failed.
            _Stopped: A stop request came during the fetch or ``rev-parse``.
            evaluate.EvaluationError: git printed a path that is not repository-relative.
        """
        plan, base = _present(self.plan), _present(self.base_sha)
        fetched = self._git(plan.fetch)
        if not fetched.ok:
            raise _StepFailed("the fetch of the conflict check", fetched, _detail(fetched))
        parsed = self._git(plan.rev_parse)
        if not parsed.ok:
            raise _StepFailed("origin/main after the fetch", parsed, _detail(parsed))
        origin_main = parsed.stdout.decode("utf-8", "replace").strip()
        if _OBJECT_ID.fullmatch(origin_main) is None:
            raise _StepFailed("origin/main after the fetch", parsed, f"rev-parse printed {_clip(origin_main)}")
        diff = ("diff", "--name-only", "--no-renames", "-z", base, origin_main)
        names = self._read(
            ("git", "--no-optional-locks", "-C", self.main_tree, *diff),
            self.main_tree,
            "files changed on the default branch",
        ).stdout.decode("utf-8", "replace")
        default_branch_files = tuple(sorted({name for name in names.split("\0") if name}))
        conflicts = evaluate.conflicting_files(changed, default_branch_files, ())
        self.conflict_check = _ConflictCheck(origin_main, default_branch_files, conflicts)
        return conflicts

    def _reruns(
        self, blockers: tuple[str, ...]
    ) -> tuple[tuple[evaluate.RerunResult, ...], tuple[evaluate.RerunSkip, ...]]:
        """Step 6, the re-run of the declared verification commands, in their declared order.

        Args:
            blockers: The conditions of :data:`RERUN_BLOCKERS` that steps 1 to 4 showed. When
                there is one, no command runs.

        Returns:
            The re-run results and the skip reasons, which account for every declared command.

        Raises:
            _StepFailed: A command could not start, or passed its time limit with no exit code
                other than 0 to record.
            _Stopped: A stop request came while a command ran.
            KeyboardInterrupt: The harness was interrupted while a command ran.
        """
        self.reruns = []
        results: list[evaluate.RerunResult] = []
        skipped: list[evaluate.RerunSkip] = []
        for verify in self.item.verify_commands:
            reason = rerun_skip_reason(verify)
            if reason is None and blockers:
                reason = (
                    f"not re-run, since the run cannot end succeeded ({', '.join(blockers)}): the harness does not "
                    "run the code of a worktree whose work is unfinished, uncommitted or not declared"
                )
            if reason is not None:
                self.reruns.append(_Rerun(verify.cmd, reason, None))
                skipped.append(evaluate.RerunSkip(verify.cmd, reason))
                continue
            results.append(evaluate.RerunResult(verify.cmd, self._rerun(verify)))
        return tuple(results), tuple(skipped)

    def _rerun(self, verify: VerifyCommand) -> int:
        """Run one verification command in the worktree under layer 3, and return its exit code.

        Raises:
            _StepFailed, _Stopped, KeyboardInterrupt: As for :meth:`_reruns`.
        """
        self._check_stop()
        with _ChildPaths() as child:
            env = command.child_env(
                os.environ,
                push_url=child.push_url,
                gh_config_dir=child.gh_config_dir,
                aws_empty_file=child.aws_empty_file,
                path_prepend=self._path_prepend(),
            )
            ran = _run_process(
                verify.cmd,
                cwd=_present(self.worktree),
                env=env,
                timeout_seconds=self.timeout,
                kill_grace_seconds=self.grace,
                stop=self.stop,
            )
        _present(self.reruns).append(_Rerun(verify.cmd, None, ran))
        if ran.ending == "interrupted":
            raise KeyboardInterrupt
        if ran.ending == "stopped":
            raise _Stopped
        if ran.exit_code is not None and (ran.ending == "exited" or ran.exit_code != 0):
            return ran.exit_code
        raise _StepFailed(
            "the re-run of a verification command",
            ran,
            f"{_detail(ran)}\nthe re-run has no exit code to record (exit code {ran.exit_code}), so it counts as "
            "neither passed nor failed",
        )


class _ManualVerify(_ChangeRun):
    """One change item whose worktree the maintainer made by hand, from ``queued`` to its final state.

    :meth:`Harness.verify_manual` uses it once. The observation is :meth:`_ChangeRun._observe` and the
    decision is :meth:`_QueryRun._evaluate`, as for a run of ``kiro-cli``; only the start differs:
    the worktree and the base come from the maintainer's checkout, after the checks of :meth:`admit`,
    and ``kiro-cli`` is replaced by a result with exit code 0, no time-out and no output.

    The main working tree is compared from just before this observation to just after it, so a change
    that the maintainer's own work made earlier is not seen.
    """

    def __init__(
        self, harness: Harness, context: RunContext, item: Item, worktree: str, stop: threading.Event | None
    ) -> None:
        """Keep the inputs of the observation.

        Args:
            harness: The harness, which owns the status.
            context: The checked inputs.
            item: The change item.
            worktree: The maintainer's worktree, as given.
            stop: The stop request, or ``None``.
        """
        super().__init__(harness, context, item, stop)
        self.given = worktree

    def run(self) -> ItemOutcome:
        """Move to ``running``, observe and record the final state, after :meth:`admit`.

        Returns:
            The outcome.
        """
        try:
            return self._verify()
        except _Stopped:
            return self.stopped()

    def stopped(self) -> ItemOutcome:
        """The outcome of a stop request that came before the move to ``running``: the item stays ``queued``."""
        _LOG.info("%s: stopped before the observation started; it stays queued", self.item.id)
        return self._outcome(state.QUEUED, "stopped before the observation started", "")

    def _verify(self) -> ItemOutcome:
        """The steps of :meth:`run` after :meth:`admit`."""
        item = self.item
        try:
            before = self._snapshot()
        except _StepFailed as failure:
            raise VerifyRefused(f"{item.id}: {failure.what}: {failure.detail}") from None
        self._check_stop()
        self.harness._move(
            item.id,
            state.RUNNING,
            MANUAL_VERIFY,
            pid=None,
            worktree=_tilde(_present(self.worktree), self.context.home),
            branch=self.branch,
            base_sha=self.base_sha,
            report=None,
            observations=None,
            rerun=[],
            rerun_skipped=[],
            report_flags=[],
        )
        now = _now()
        result = ProcessResult(
            argv=(),
            cwd=_present(self.worktree),
            pid=None,
            ending="exited",
            exit_code=0,
            stdout=b"",
            stderr=b"",
            signals=(),
            stragglers=False,
            output_complete=True,
            start_error=None,
            missing_program=False,
            started_at=now,
            ended_at=now,
            duration_seconds=0.0,
        )
        try:
            observations, _ = self._observe(result, before)
        except _StepFailed as failure:
            return self._conclude(state.NEEDS_HUMAN, "observation_failed", failure.detail)
        except _Stopped:
            return self._conclude(state.FAILED, HARNESS_INTERRUPTED, STOPPED_WHILE_OBSERVING)
        except KeyboardInterrupt:
            self._conclude(state.FAILED, HARNESS_INTERRUPTED, "観測の途中でハーネスが中断された")
            raise
        evaluation = self._evaluate(observations)
        return self._conclude(evaluation.state, evaluation.history_reason, "", observations)

    def _conclude(
        self, to_state: str, reason: str, note: str, observations: evaluate.Observations | None = None
    ) -> ItemOutcome:
        """Record the final state with the observations, if any, and describe it."""
        fields: dict[str, Any] = {"pid": None, "report_flags": []}
        if observations is not None:
            fields.update(observations.to_json())
        self.harness._move(self.item.id, to_state, reason, **fields)
        _LOG.info("%s: %s (%s)", self.item.id, to_state, reason)
        return ItemOutcome(
            item_id=self.item.id,
            state=to_state,
            reason=reason,
            detail=note,
            prompt=None,
            report=None,
            worktree=self.worktree,
            exit_code=None,
            timed_out=False,
        )

    def _refuse(self, why: str) -> VerifyRefused:
        """The refusal for a failed check, which names the item."""
        return VerifyRefused(f"{self.item.id}: {why}; nothing was changed")

    def admit(self) -> None:
        """Check the item and the worktree, then set ``worktree``, ``base_sha``, ``branch`` and ``plan``.

        Raises:
            VerifyRefused: The item is not ``queued``, or the worktree is not a place, a worktree of
                this repository, on ``handoff/<id>`` and below the base that the checks above name.
        """
        item, config = self.item, self.config
        record = self.harness.status["items"].get(item.id)
        # ``manual`` writes nothing, so an item handed over by hand may have no record; it counts as queued.
        current = state.QUEUED if record is None else record["state"]
        if current != state.QUEUED:
            way_back = ""
            if current in (state.FAILED, state.NEEDS_HUMAN):
                way_back = f" (a {current} item that was handed over by hand goes back first: cli.py status set {item.id} queued --reason ...)"
            raise self._refuse(f"it is {current}; only a queued item is observed{way_back}")
        given = self.given
        if not _is_normal_absolute(given):
            raise self._refuse(f"--worktree {given!r} is not an absolute path in normal form")
        real = os.path.realpath(given)
        protected = [(f"the main working tree of {name}", repo.main_tree) for name, repo in config.repos.items()]
        protected.append(("this repository's main working tree", self.context.harness_tree))
        protected.append(("the IDE session worktree directory", self.context.session_worktrees_dir))
        for label, path in sorted(protected):
            if overlaps(real, os.path.realpath(path)):
                raise self._refuse(f"the worktree {given} resolves to {real}, which meets {label}")
        if not os.path.isdir(real):
            raise self._refuse(f"the worktree {given} is not a directory")
        try:
            plan = command.build_git_plan(config, item)
        except command.CommandError as error:
            raise self._refuse(str(error)) from None
        try:
            listed = list_worktrees(plan.main_tree, timeout_seconds=self.timeout)
        except GitCommandFailed as error:
            raise self._refuse(str(error)) from None
        if real not in {os.path.realpath(path) for path in listed[1:]}:
            raise self._refuse(f"{given} is not a worktree that git lists for {item.repo} ({plan.main_tree})")
        self.worktree, self.plan, self.branch = real, plan, plan.branch
        try:
            self._branch_head("the branch of the worktree")
            self.base_sha = self._base(None if record is None else record["base_sha"])
        except _StepFailed as failure:
            raise self._refuse(f"{failure.what}: {failure.detail}") from None

    def _base(self, recorded: str | None) -> str:
        """The base of the branch: the recorded ``base_sha`` if it is below ``HEAD``, else the merge base with ``origin/main``.

        Raises:
            _StepFailed: git failed, or the recorded base is not below ``HEAD``, or ``HEAD`` shares no
                history with ``origin/main``.
            _Stopped: A stop request came during the fetch.
        """
        worktree, plan = _present(self.worktree), _present(self.plan)
        if recorded is not None:
            below = self._read(
                ("git", "-C", worktree, "merge-base", "--is-ancestor", recorded, "HEAD"),
                worktree,
                "the recorded base of the item",
                allowed=(0, 1),
            )
            if below.exit_code != 0:
                raise _StepFailed("the recorded base of the item", below, f"{recorded} is not below HEAD of {worktree}")
            return recorded
        fetched = self._git(plan.fetch)
        if not fetched.ok:
            raise _StepFailed("the fetch for the base", fetched, _detail(fetched))
        parsed = self._git(plan.rev_parse)
        origin_main = parsed.stdout.decode("utf-8", "replace").strip()
        if not parsed.ok or _OBJECT_ID.fullmatch(origin_main) is None:
            raise _StepFailed("origin/main for the base", parsed, _detail(parsed))
        found = self._read(
            ("git", "-C", worktree, "merge-base", "HEAD", origin_main),
            worktree,
            "the base of the branch",
            allowed=(0, 1),
        )
        base = found.stdout.decode("utf-8", "replace").strip()
        if found.exit_code != 0 or _OBJECT_ID.fullmatch(base) is None:
            raise _StepFailed("the base of the branch", found, f"HEAD of {worktree} shares no history with origin/main")
        return base


def github_repo_of(url: str) -> str | None:
    """``OWNER/NAME`` of a GitHub remote URL, or ``None`` when the URL does not name a GitHub repository.

    Reads the HTTPS, ``ssh://`` and scp-like forms of a github.com URL (``OWNER/NAME`` is the path), with
    or without ``.git``. Any other host, and a local path, give ``None``.
    """
    found = _GITHUB_URL.fullmatch(url.strip())
    return found.group(1) if found else None


class _Publish:
    """One approval's publication. :meth:`Harness.publish_batch` uses it once.

    Two passes over ``command.build_publish_plan``. The first, with no pull-request specs, leaves
    the approved items that passed every earlier check with the exclusion ``no_pull_request``;
    those are the candidates. Each candidate is read, scanned and checked for conflicts, and gets a
    spec (title, body file, repository) or an outcome that says why not. The second pass, with the
    specs, gives the steps that are run.
    """

    def __init__(
        self,
        harness: Harness,
        context: RunContext,
        approval: command.PublishApproval,
        github_repos: Mapping[str, str],
    ) -> None:
        """Keep the inputs.

        Args:
            harness: The harness, which owns the status.
            context: The checked inputs.
            approval: The approval.
            github_repos: ``OWNER/NAME`` by target repository, overriding the ``origin`` URL.
        """
        self.harness = harness
        self.context = context
        self.config = context.config
        self.approval = approval
        self.directory = harness.handoff_dir
        self.github_repos = github_repos
        self.git_env = git_environment(os.environ)
        self.outcomes: dict[str, PublishOutcome] = {}

    def run(self) -> tuple[PublishOutcome, ...]:
        """Plan, prepare, publish; return one outcome per listed item, in the order listed."""
        status = copy.deepcopy(self.harness.status)
        first = self._plan(status, {})
        candidates: list[str] = []
        for excluded in first.excluded:
            if excluded.reason == "not_approved":
                continue
            if excluded.reason == "no_pull_request":
                candidates.append(excluded.item_id)
            else:
                self.outcomes[excluded.item_id] = PublishOutcome(
                    excluded.item_id, False, excluded.reason, excluded.detail
                )
        specs: dict[str, command.PullRequestSpec] = {}
        for item_id in candidates:
            prepared = self._prepare(status, item_id)
            if isinstance(prepared, PublishOutcome):
                self.outcomes[item_id] = prepared
            else:
                specs[item_id] = prepared
        second = self._plan(status, specs)
        for excluded in second.excluded:
            if excluded.reason != "not_approved" and excluded.item_id not in self.outcomes:
                self.outcomes[excluded.item_id] = PublishOutcome(
                    excluded.item_id, False, excluded.reason, excluded.detail
                )
        for step in second.steps:
            self.outcomes[step.item_id] = self._publish(step, specs[step.item_id])
        result = tuple(self.outcomes[item_id] for item_id in self.approval.item_ids)
        done = [outcome.item_id for outcome in result if outcome.published]
        left = [outcome.item_id for outcome in result if not outcome.published]
        detail = (
            f"approved_at {self.approval.approved_at}; published: {', '.join(done) or 'none'}; "
            f"not published: {', '.join(left) or 'none'}"
        )
        self.harness._record_event(PUBLISH_BATCH, detail)
        return result

    def _plan(self, status: state.StatusDoc, specs: Mapping[str, command.PullRequestSpec]) -> command.PublishPlan:
        """``command.build_publish_plan`` with the specs prepared so far."""
        return command.build_publish_plan(
            self.config,
            self.context.manifest,
            status,
            self.approval,
            pull_requests=specs,
            handoff_dir=self.directory,
        )

    def _prepare(self, status: state.StatusDoc, item_id: str) -> command.PullRequestSpec | PublishOutcome:
        """Read, scan and conflict-check one candidate; give its spec, or the outcome that stops it."""
        item = self.context.manifest.by_id[item_id]
        record = status["items"][item_id]
        plan = command.build_git_plan(self.config, item)
        if record["worktree"] is None or record["base_sha"] is None:
            return PublishOutcome(item_id, False, PUBLISH_NOT_READ, "its record has no worktree or base_sha")
        worktree, base, main_tree = plan.worktree, record["base_sha"], plan.main_tree
        try:
            head = self._branch_head(worktree, plan.branch or "")
            messages = [
                text
                for text in self._read(
                    ("git", "-C", worktree, "log", "-z", "--no-show-signature", "--format=%B", f"{base}..{head}"),
                    worktree,
                    "the commit messages",
                )
                .stdout.decode("utf-8", "replace")
                .split("\0")
                if text.strip()
            ]
            subjects = _commit_subjects(
                self._read(
                    ("git", "-C", worktree, "log", "-z", "--no-show-signature", "--format=%H%x09%s", f"{base}..{head}"),
                    worktree,
                    "the commit subjects",
                ).stdout
            )
            diff = self._read(
                (
                    *("git", "-C", worktree, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames"),
                    *("--src-prefix=a/", "--dst-prefix=b/", base, head),
                ),
                worktree,
                "the diff of the branch",
            ).stdout.decode("utf-8", "replace")
            changed = tuple(
                sorted(
                    {
                        name
                        for name in self._read(
                            ("git", "-C", worktree, "diff", "--name-only", "--no-renames", "-z", base, head),
                            worktree,
                            "the files of the branch",
                        )
                        .stdout.decode("utf-8", "replace")
                        .split("\0")
                        if name
                    }
                )
            )
            try:
                findings = scan.check_publish(messages, diff, self.context.deny.terms)
            except scan.DiffParseError as error:
                return self._hold(item_id, PUBLISH_SCAN_FAILED, f"the diff could not be scanned: {error}")
            if findings:
                shown = "; ".join(_finding_text(finding) for finding in findings[:20])
                return self._hold(
                    item_id,
                    PUBLISH_SCAN_FINDINGS,
                    f"{len(findings)} scan finding(s) in the commits or the diff: {shown}",
                )
            conflicts = self._conflicts(plan, base, changed)
            if conflicts:
                return self._hold(
                    item_id,
                    PUBLISH_CONFLICTS,
                    f"the default branch changed the same file(s) since the base: {', '.join(conflicts)}",
                )
        except _StepFailed as error:
            return PublishOutcome(item_id, False, PUBLISH_NOT_READ, f"{error.what}: {error.detail}")
        except evaluate.EvaluationError as error:
            return PublishOutcome(item_id, False, PUBLISH_NOT_READ, str(error))
        repository = self._repository(item.repo, main_tree)
        if repository is None:
            return PublishOutcome(
                item_id,
                False,
                PUBLISH_NO_REPOSITORY,
                f"remote.origin.url of {main_tree} does not name a GitHub repository",
            )
        title = subjects[-1][1] if subjects else item_id
        lines = [
            f"Handoff item `{item_id}` for `{item.repo}`.",
            "",
            "Commits:",
            *(f"- {subject}" for _, subject in subjects),
        ]
        lines += ["", "Opened as a draft by the Handoff_Harness after the maintainer's approval."]
        body = posixpath.join(self.directory, "publish", f"{item_id}-pr-body.md")
        _write_file(body, ("\n".join(lines) + "\n").encode("utf-8"), self.directory)
        return command.PullRequestSpec(github_repo=repository, title=title, body_file=body)

    def _publish(self, step: command.PublishStep, spec: command.PullRequestSpec) -> PublishOutcome:
        """Run the push, confirm it on the remote, open the pull request and read its checks."""
        item_id, approved_at = step.item_id, self.approval.approved_at
        main_tree = self.config.repos[step.repo].main_tree
        self.harness._publish_record(item_id, {"approved_at": approved_at, "pr": None}, event=None)
        pushed = self._run(step.push)
        if not pushed.ok:
            return PublishOutcome(item_id, False, PUBLISH_PUSH_FAILED, _detail(pushed))
        ref = f"refs/heads/{step.branch}"
        try:
            local = self._read(
                ("git", "-C", step.push.cwd, "rev-parse", "--verify", ref), step.push.cwd, "the local branch"
            )
            listed = self._read(
                ("git", "-C", main_tree, "ls-remote", command.REMOTE, ref), main_tree, "the remote branch"
            )
        except _StepFailed as error:
            return self._hold(item_id, PUBLISH_SHA_MISMATCH, f"{error.what}: {error.detail}", approved_at=approved_at)
        local_sha = local.stdout.decode("utf-8", "replace").strip()
        remote_sha = _ls_remote_sha(listed.stdout, ref)
        if remote_sha is None or remote_sha != local_sha:
            return self._hold(
                item_id,
                PUBLISH_SHA_MISMATCH,
                f"after the push, {ref} is {remote_sha or 'not on the remote'} there and {local_sha} here; "
                "no pull request was opened",
                approved_at=approved_at,
            )
        opened = self._run(step.pull_request, env=dict(os.environ))
        if not opened.ok:
            return PublishOutcome(item_id, False, PUBLISH_PR_FAILED, _detail(opened))
        url = opened.stdout.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        found = _PULL_REQUEST_URL.search(url[0])
        if found is None:
            return PublishOutcome(item_id, False, PUBLISH_PR_FAILED, f"gh printed no pull request URL: {_clip(url[0])}")
        number = int(found.group(1))
        record: dict[str, Any] = {"approved_at": approved_at, "pr": number, "url": url[0].strip()}
        self.harness._publish_record(item_id, record, event=None)
        checks = self._run(
            command.Command(("gh", "pr", "checks", str(number), "--repo", spec.github_repo), step.push.cwd),
            env=dict(os.environ),
        )
        ci = _ci_result(checks)
        record["ci"] = {
            "result": ci,
            "exit_code": checks.exit_code,
            "output": checks.stdout.decode("utf-8", "replace")[:_CI_OUTPUT_LIMIT],
        }
        self.harness._publish_record(item_id, record, event=None)
        return PublishOutcome(item_id, True, "published", f"draft pull request #{number}", pr=number, ci=ci)

    def _hold(self, item_id: str, reason: str, detail: str, *, approved_at: str | None = None) -> PublishOutcome:
        """Record that an item is held back and why; it stays ``succeeded``."""
        hold = {"at": _now(), "reason": reason, "detail": _one_line(detail)[:500]}
        self.harness._publish_record(
            item_id,
            {"approved_at": approved_at, "pr": None, "hold": hold},
            event=(PUBLISH_HELD, f"{item_id}: {reason}"),
        )
        return PublishOutcome(item_id, False, reason, detail, held=True)

    def _conflicts(self, plan: command.GitPlan, base: str, changed: tuple[str, ...]) -> tuple[str, ...]:
        """Fetch the default branch again and list the changed files that it also changed since the base."""
        self._read(plan.fetch.argv, plan.fetch.cwd, "the fetch of the conflict check")
        parsed = self._read(plan.rev_parse.argv, plan.rev_parse.cwd, "origin/main after the fetch")
        origin_main = parsed.stdout.decode("utf-8", "replace").strip()
        if _OBJECT_ID.fullmatch(origin_main) is None:
            raise _StepFailed("origin/main after the fetch", parsed, f"rev-parse printed {_clip(origin_main)}")
        names = self._read(
            (
                "git",
                "--no-optional-locks",
                "-C",
                plan.main_tree,
                "diff",
                "--name-only",
                "--no-renames",
                "-z",
                base,
                origin_main,
            ),
            plan.main_tree,
            "files changed on the default branch",
        ).stdout.decode("utf-8", "replace")
        default_branch_files = tuple(sorted({name for name in names.split("\0") if name}))
        return evaluate.conflicting_files(changed, default_branch_files, ())

    def _branch_head(self, worktree: str, branch: str) -> str:
        """The SHA of the worktree's ``HEAD``, which must be on ``handoff/<id>``."""
        on = self._read(
            ("git", "--no-optional-locks", "-C", worktree, "symbolic-ref", "-q", "HEAD"),
            worktree,
            "the branch of the worktree",
            allowed=(0, 1),
        )
        current = on.stdout.decode("utf-8", "replace").strip() if on.exit_code == 0 else ""
        if current != f"refs/heads/{branch}":
            raise _StepFailed(
                "the branch of the worktree", None, f"HEAD is {current or 'detached'}, not refs/heads/{branch}"
            )
        parsed = self._read(("git", "-C", worktree, "rev-parse", "--verify", "HEAD"), worktree, "HEAD of the worktree")
        return parsed.stdout.decode("utf-8", "replace").strip()

    def _repository(self, repo: str, main_tree: str) -> str | None:
        """``OWNER/NAME`` for ``gh pr create --repo``: the given one, or the one that ``origin`` names."""
        if repo in self.github_repos:
            return self.github_repos[repo]
        url = self._read(
            ("git", "-C", main_tree, "config", "--get", "remote.origin.url"),
            main_tree,
            "the URL of origin",
            allowed=(0, 1),
        )
        return github_repo_of(url.stdout.decode("utf-8", "replace"))

    def _run(self, step: command.Command, *, env: Mapping[str, str] | None = None) -> ProcessResult:
        """Run one command of the plan, in the harness's own environment (not ``child_env``)."""
        result = _run_process(
            step.argv,
            cwd=step.cwd,
            env=self.git_env if env is None else env,
            timeout_seconds=self.config.timeout_seconds,
            kill_grace_seconds=self.context.kill_grace_seconds,
        )
        if result.ending == "interrupted":
            raise KeyboardInterrupt
        return result

    def _read(self, argv: tuple[str, ...], cwd: str, what: str, *, allowed: tuple[int, ...] = (0,)) -> ProcessResult:
        """Run a command that only reads, and require one of the allowed exit codes."""
        result = self._run(command.Command(argv, cwd))
        if result.ending != "exited" or result.exit_code not in allowed:
            raise _StepFailed(what, result, _detail(result))
        return result


def _finding_text(finding: scan.PublishFinding) -> str:
    """Where a publish finding is and its kind, never the matched value."""
    if isinstance(finding, scan.MessageFinding):
        return f"commit message {finding.message_index} line {finding.line}: {finding.kind}"
    return f"{finding.path} line {finding.line}: {finding.kind}"


def _ci_result(checks: ProcessResult) -> str:
    """The result of ``gh pr checks`` by its exit code: 0 passing, 8 pending, 1 failing (or no checks)."""
    if checks.ending != "exited":
        return "unreadable"
    if checks.exit_code == 0:
        return "passing"
    if checks.exit_code == 8:
        return "pending"
    if checks.exit_code == 1:
        text = (checks.stdout + checks.stderr).decode("utf-8", "replace")
        return "none" if "no checks reported" in text else "failing"
    return "unreadable"


class _Report:
    """The Handoff_Report of one run (design Data Models), as Markdown.

    It is written twice: when ``kiro-cli`` has ended, with its whole output, and again with the
    final state and the observations. Everything above the two output sections has the same
    number of lines in both writes, so the line numbers of :meth:`flags` hold for both. Every
    value written into the table is put on one line for that reason.
    """

    def __init__(
        self,
        run: _QueryRun,
        invocation: command.KiroInvocation,
        rendered: prompt.RenderedPrompt,
        result: ProcessResult,
        before: evaluate.MainTreeSnapshot,
    ) -> None:
        """Decode the output once, whole, and fix the layout.

        Args:
            run: The run, for the item, the files and the worktree.
            invocation: The ``kiro-cli`` run.
            rendered: The Handoff_Prompt whose body is the last argv element.
            result: How ``kiro-cli`` ended.
            before: The snapshot of the main working tree taken before it started.
        """
        self.run = run
        self.invocation = invocation
        self.rendered = rendered
        self.result = result
        self.before = before
        self.stdout_text = result.stdout.decode("utf-8", "replace")
        self.stderr_text = result.stderr.decode("utf-8", "replace")
        #: A heuristic label from the standard error alone (never the standard output, which holds the
        #: model's answer), and only for a ``kiro-cli`` that exited with a code other than 0.
        self.kiro_error: str | None = (
            kiro_errors.classify_stderr(self.stderr_text)
            if result.ending == "exited" and result.exit_code not in (None, 0)
            else None
        )
        self._stdout_fence = _fence(self.stdout_text)
        self._stderr_fence = _fence(self.stderr_text)
        before_stdout = self._before_stdout(None)
        self.stdout_line = len(before_stdout) + 1
        self.stderr_line = self.stdout_line + _block(self.stdout_text).count("\n") + len(self._between())

    def write(
        self,
        *,
        final: tuple[str, str] | None = None,
        note: str | None = None,
        observations: evaluate.Observations | None = None,
        after: evaluate.MainTreeSnapshot | None = None,
        flags: Sequence[evaluate.ReportFlag] = (),
    ) -> None:
        """Write the report to its path below ``.private/handoff/``.

        Args:
            final: The final state and its reason, or ``None`` before the observations.
            note: What the maintainer should know about the end of the run.
            observations: The observations, when they were made.
            after: The snapshot of the main working tree after the run.
            flags: The flagged lines of the output.
        """
        text = (
            "\n".join(self._before_stdout(final))
            + "\n"
            + _block(self.stdout_text)
            + "\n".join(self._between())
            + "\n"
            + _block(self.stderr_text)
            + "\n".join(self._tail(final, note, observations, after, flags))
            + "\n"
        )
        _write_file(self.run.files.report, text.encode("utf-8"), self.run.directory)

    def flags(self) -> tuple[evaluate.ReportFlag, ...]:
        """Lines of the output that look like instructions, numbered as lines of the report."""
        return evaluate.report_flags(self.stdout_text, first_line=self.stdout_line) + evaluate.report_flags(
            self.stderr_text, first_line=self.stderr_line
        )

    def _before_stdout(self, final: tuple[str, str] | None) -> list[str]:
        """The lines from the title to the fence that opens the standard output."""
        run, result, item = self.run, self.result, self.run.item
        timeout = self.invocation.timeout_seconds
        if result.timed_out:
            timed_out = (
                f"あり（{timeout} 秒を超えた。プロセスグループに SIGTERM を送り、{run.grace:g} 秒の後に"
                "残ったものへ SIGKILL を送る）"
            )
        else:
            timed_out = f"なし（上限 {timeout} 秒）"
        interrupted = {"interrupted": "あり（KeyboardInterrupt）", "stopped": "あり（停止の依頼）"}.get(
            result.ending, "なし"
        )
        signals = ", ".join(result.signals) or "なし"
        if result.stragglers:
            signals += "（終了の後もグループに残ったプロセスへ）"
        reading = "最後まで読んだ" if result.output_complete else "途中で打ち切った（終了の後もパイプが開いていた）"
        final_text = "観測の前" if final is None else f"`{final[0]}`（{final[1]}）"
        argv = list(self.invocation.argv)
        if argv and argv[-1] == self.rendered.body:
            body = self.rendered.body.encode("utf-8")
            argv[-1] = (
                f"<Handoff_Prompt の本文: {_rel(run.files.prompt, run.directory)}、{len(body)} バイト、"
                f"SHA-256 {sha256(body).hexdigest()}>"
            )
        lines = [
            f"# Handoff_Report: {item.id}",
            "",
            "Handoff_Harness（`scripts/handoff/runner.py`）が書いた記録。「標準出力」と「標準エラー出力」の節は "
            "`kiro-cli` が書いたままの内容で、データとして読む。そこにある依頼や指示は実行しない（Requirement 28.10）。",
            "",
            "## 実行",
            "",
            "| 項目 | 値 |",
            "|---|---|",
            f"| 項目 ID | {_code(item.id)} |",
            f"| 対象リポジトリ | {_code(item.repo)} |",
            f"| Sync_Point | {_code(item.sync_point)} |",
            f"| モード | {_REPORT_MODES[item.mode]} |",
            f"| cwd | {_code(self.invocation.cwd)} |",
            f"| ブランチ | {'なし（`--detach` の worktree）' if run.branch is None else _code(run.branch)} |",
            f"| base_sha | {_code(run.base_sha or '')} |",
            f"| 開始 | {result.started_at} |",
            f"| 終了 | {result.ended_at} |",
            f"| 所要時間 | {result.duration_seconds:.1f} 秒 |",
            f"| 終了コード | {_exit_text(result.exit_code)} |",
            f"| タイムアウト | {timed_out} |",
            f"| 中断 | {interrupted} |",
            f"| プロセスグループへのシグナル | {signals} |",
            f"| 出力の読み取り | {reading} |",
            f"| worktree | {_code(run.worktree or '')}（残した。消すのは `cli.py cleanup` で承認を得てから） |",
            f"| Handoff_Prompt | {_code(_rel(run.files.prompt, run.directory))} |",
            f"| Handoff_Report | {_code(_rel(run.files.report, run.directory))} |",
            f"| 最終状態 | {_one_line(final_text)} |",
            "",
            "## コマンド",
            "",
            "argv を 1 行に 1 要素ずつ JSON の文字列で書く。最後の要素は Handoff_Prompt の本文で、ファイルへの参照に置き換えた。",
            "",
            "```text",
            *(f"[{index}] {json.dumps(arg, ensure_ascii=False)}" for index, arg in enumerate(argv)),
            "```",
            "",
            "## 拒否語の一覧",
            "",
            *(f"- {_one_line(note)}" for note in run.context.deny.notes),
            f"- 本文の走査の該当: {len(self.rendered.findings)} 件",
            "",
            f"## 標準出力（{len(result.stdout)} バイト。UTF-8 として読めないバイトは置換文字にした）",
            "",
            self._stdout_fence + "text",
        ]
        return lines

    def _between(self) -> list[str]:
        """The lines from the fence that closes the standard output to the one that opens the standard error."""
        return [
            self._stdout_fence,
            "",
            f"## 標準エラー出力（{len(self.result.stderr)} バイト。UTF-8 として読めないバイトは置換文字にした）",
            "",
            self._stderr_fence + "text",
        ]

    def _tail(
        self,
        final: tuple[str, str] | None,
        note: str | None,
        observations: evaluate.Observations | None,
        after: evaluate.MainTreeSnapshot | None,
        flags: Sequence[evaluate.ReportFlag],
    ) -> list[str]:
        """The lines from the fence that closes the standard error to the end."""
        lines = [self._stderr_fence, "", "## 観測", ""]
        if final is None:
            lines.append("`kiro-cli` が終わった直後に、標準出力と標準エラー出力を先に保存した。観測はこの後に行う。")
            return lines
        lines.append(f"- 最終状態: `{final[0]}`（{_one_line(final[1])}）")
        lines.append(f"- 指示に見える行（report_flags）: {len(flags)} 件。行番号はこのファイルの行")
        if self.kiro_error is not None:
            lines.append(
                f"- `kiro-cli` のエラー: `{self.kiro_error}`。標準エラー出力の文言への一致による発見的な検出で、"
                "文言が変わると外れる。応答の形は少数の観測に基づく。最終状態と理由には影響していない。"
                "利用枠の回復かプロファイルの設定を確認してから `status set <id> queued --reason ...` で戻す"
            )
        if note:
            fence = _fence(note)
            lines += ["- 補足:", "", fence + "text", *note.splitlines(), fence]
        lines += self.run.report_sections()
        data = {
            "observations": None if observations is None else observations.to_json(),
            "report_flags": [flag.to_json() for flag in flags],
            "main_tree": {
                "before": _snapshot_json(self.before),
                "after": None if after is None else _snapshot_json(after),
            },
            **self.run.report_data(),
        }
        if self.kiro_error is not None:
            data["kiro_cli_error"] = self.kiro_error
        lines += ["", "```json", json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), "```"]
        return lines


class _Selftest:
    """One selftest from its checks to its record. :meth:`Harness.run_selftest` uses it once."""

    def __init__(self, harness: Harness, context: SelftestContext) -> None:
        """Keep the inputs.

        Args:
            harness: The harness, which owns the status.
            context: The checked inputs.
        """
        self.harness = harness
        self.context = context
        self.config = context.config
        self.home = context.home
        self.directory = harness.handoff_dir
        self.git_env = git_environment(os.environ)
        self.timeout = self.config.timeout_seconds
        self.grace = context.kill_grace_seconds
        self.partial: dict[str, Any] | None = None

    def run(self) -> SelftestOutcome:
        """Carry out the steps of :meth:`Harness.run_selftest`."""
        moment = datetime.now(timezone.utc)
        started_at = state.format_timestamp(moment)
        run_id = moment.strftime(command.SELFTEST_RUN_ID_FORMAT)
        approved = frozenset(name for name, mode in self.context.approved_agents if mode == "change")
        try:
            run_dir = command.selftest_run_dir(self.config, run_id)
            tokens = {trial: command.selftest_token(trial, secrets.token_hex(8)) for trial in evaluate.SELFTEST_TRIALS}
            invocations = {
                trial: command.build_selftest_invocation(
                    self.config, tokens[trial], run_dir=run_dir, home=self.home, approved_agents=approved
                )
                for trial in evaluate.SELFTEST_TRIALS
            }
        except command.CommandError as error:
            raise SelftestRefused(f"the selftest was not started:\n{error}") from error
        record_path = posixpath.join(self.directory, SELFTEST_RECORD_DIR, f"{run_id}.json")
        for path in (record_path, posixpath.join(self.directory, SELFTEST_RECORD_DIR, run_id)):
            _check_below(path, self.directory)
            if os.path.lexists(path):
                raise UnsafeLocation(f"{path} exists already; run the selftest again a second later")
        fingerprint = kiro_fingerprint(
            self.config, home=self.home, agent=invocations["t0"].agent, kill_grace_seconds=self.grace
        )
        self._check_login(fingerprint.program)
        self._check_disk()
        self._check_location(run_dir)

        header: dict[str, Any] = {
            "schema_version": SELFTEST_RECORD_SCHEMA,
            "run_id": run_id,
            "started_at": started_at,
            "kiro_cli": {
                "path": _tilde(fingerprint.program, self.home),
                "version_output": fingerprint.version_output,
                "version": fingerprint.version,
            },
            "config_sha256": fingerprint.digest.sha256,
            "config_parts": fingerprint.digest.parts(),
            "agent": fingerprint.agent,
            "run_dir": _tilde(run_dir, self.home),
        }
        trials: dict[str, dict[str, Any]] = {}
        outcomes: dict[str, evaluate.TrialOutcome] = {}
        stopped: str | None = None
        try:
            for trial in evaluate.SELFTEST_TRIALS:
                if stopped is not None:
                    trials[trial] = self._entry(tokens[trial], invocations[trial], not_started=stopped)
                    outcomes[trial] = "failed_otherwise"
                    continue
                trials[trial] = self._trial(trial, tokens[trial], invocations[trial], run_dir, run_id)
                self.partial = None
                outcomes[trial] = trials[trial]["outcome"]
                if not trials[trial]["attempted"]:
                    stopped = f"the repositories of {trial.upper()} could not be made"
                elif trial == "t0" and outcomes[trial] != "completed":
                    stopped = "T0 did not complete, so T1 to T4 would say nothing about the guards"
        except KeyboardInterrupt:
            for trial in evaluate.SELFTEST_TRIALS:
                if trial not in trials:
                    current = (
                        self.partial if self.partial is not None and self.partial["token"] == tokens[trial] else None
                    )
                    trials[trial] = current or self._entry(
                        tokens[trial], invocations[trial], not_started="the harness was interrupted"
                    )
                    self.partial = None
            record = {**header, "ended_at": _now(), "result": None, "interrupted": True, "stopped": stopped}
            _write_file(record_path, _record_bytes({**record, "trials": trials}), self.directory)
            raise

        listings = self._ls_remote_all(run_dir, trials)
        effects = {
            trial: None
            if trials[trial]["effects"] is None
            else evaluate.TrialEffects.from_json(trials[trial]["effects"])
            for trial in evaluate.SELFTEST_TRIALS
        }
        gh_failed = evaluate.gh_auth_failed(tokens["t3"], effects["t3"])
        branch_absent = evaluate.remote_branch_absent(effects, listings)
        result = evaluate.selftest_verdict(
            evaluate.SelftestTrials(
                t0=outcomes["t0"],
                t1=outcomes["t1"],
                t2=outcomes["t2"],
                t3=outcomes["t3"],
                t4=outcomes["t4"],
                gh_failed=gh_failed,
                remote_branch_absent=branch_absent,
            )
        )
        ended_at = _now()
        record = {
            **header,
            "ended_at": ended_at,
            "result": result,
            "interrupted": False,
            "stopped": stopped,
            "gh_failed": gh_failed,
            "remote_branch_absent": branch_absent,
            "ls_remote": {
                trial: None if listing is None else [{"ref": ref, "sha": sha} for ref, sha in listing]
                for trial, listing in listings.items()
            },
        }
        _write_file(record_path, _record_bytes({**record, "trials": trials}), self.directory)
        relative = _rel(record_path, self.directory)
        self.harness._record_selftest(
            {
                "result": result,
                "at": ended_at,
                "kiro_cli_version": fingerprint.version,
                "record": relative,
                "config_sha256": fingerprint.digest.sha256,
            }
        )
        detail = ""
        if result != evaluate.GUARDS_ACTIVE:
            seen = ", ".join(f"{trial.upper()} {outcomes[trial]}" for trial in ("t0", "t1", "t2", "t3"))
            detail = (
                f"{seen}, gh auth status failed: {gh_failed}, no branch on the remotes: {branch_absent} "
                "(guards_active needs T0 completed, T1 and T2 blocked_by_guard, "
                "gh auth status failed in T3, and no branch on any trial's remote)"
            )
            if stopped is not None:
                detail += f"; {stopped}"
        _LOG.info("selftest %s: %s (%s)", run_id, result, relative)
        return SelftestOutcome(
            result=result,
            run_id=run_id,
            record=record_path,
            run_dir=run_dir,
            outcomes=tuple((trial, outcomes[trial]) for trial in evaluate.SELFTEST_TRIALS),
            started=tuple(trial for trial in evaluate.SELFTEST_TRIALS if trials[trial]["attempted"]),
            fingerprint=fingerprint,
            detail=detail,
        )

    def _trial(
        self, trial: str, token: str, invocation: command.KiroInvocation, run_dir: str, run_id: str
    ) -> dict[str, Any]:
        """Make one trial's repositories, run its ``kiro-cli``, observe, and decide its outcome.

        Returns:
            The trial's entry of the record. ``attempted`` is false when the repositories could
            not be made, and then ``preparation_error`` says why.
        """
        paths = command.selftest_paths(run_dir, trial)
        entry = self._entry(token, invocation)
        self.partial = entry
        try:
            base = self._prepare(paths)
            refs_before = self._remote_refs(paths.remote)
        except (_StepFailed, OSError) as failure:
            entry["preparation_error"] = str(failure)
            return entry
        with _ChildPaths() as child:
            env = command.child_env(
                os.environ,
                push_url=child.push_url,
                gh_config_dir=child.gh_config_dir,
                aws_empty_file=child.aws_empty_file,
            )
            env[command.GUARD_LOG_VARIABLE] = paths.guard_log
            result = _run_process(
                invocation.argv,
                cwd=invocation.cwd,
                env=env,
                timeout_seconds=invocation.timeout_seconds,
                kill_grace_seconds=self.grace,
            )
        entry.update(
            attempted=result.pid is not None,
            exit_code=result.exit_code,
            ending=result.ending,
            started_at=result.started_at,
            ended_at=result.ended_at,
            duration_seconds=round(result.duration_seconds, 3),
            signals=list(result.signals),
            start_error=result.start_error,
            stdout=self._save(run_id, f"{trial}.stdout", result.stdout),
            stderr=self._save(run_id, f"{trial}.stderr", result.stderr),
            # A heuristic label from the standard error (task 5.9); it takes no part in the outcome.
            kiro_cli_error=kiro_errors.classify_stderr(result.stderr)
            if result.ending == "exited" and result.exit_code not in (None, 0)
            else None,
        )
        if result.ending == "interrupted":
            raise KeyboardInterrupt
        effects: evaluate.TrialEffects | None = None
        try:
            effects = self._effects(paths, base, refs_before)
        except (_StepFailed, evaluate.EvaluationError) as failure:
            entry["observation_error"] = str(failure)
        lines, entry["guard_log_error"] = self._guard_log(paths.guard_log)
        entry.update(
            effects=None if effects is None else effects.to_json(),
            guard_log=[line.to_json() for line in lines],
            outcome=evaluate.trial_outcome(token, effects, lines),
        )
        return entry

    def _entry(
        self, token: str, invocation: command.KiroInvocation, *, not_started: str | None = None
    ) -> dict[str, Any]:
        """The record entry of a trial before anything of it ran."""
        trust = [arg for arg in invocation.argv if arg.startswith(command.TRUST_TOOLS_OPTION)]
        return {
            "attempted": False,
            "outcome": "failed_otherwise",
            "token": token,
            "argv": list(invocation.argv),
            "cwd": _tilde(invocation.cwd, self.home),
            "trust_tools": trust[0][len(command.TRUST_TOOLS_OPTION) :].split(",") if trust else [],
            "agent": invocation.agent,
            "not_started": not_started,
            "preparation_error": None,
            "exit_code": None,
            "ending": None,
            "started_at": None,
            "ended_at": None,
            "duration_seconds": None,
            "signals": [],
            "start_error": None,
            "stdout": None,
            "stderr": None,
            "kiro_cli_error": None,
            "effects": None,
            "observation_error": None,
            "guard_log": [],
            "guard_log_error": None,
        }

    def _prepare(self, paths: command.SelftestPaths) -> str:
        """Make the trial's bare repository and its clone with one commit on ``main``; return that commit.

        Raises:
            _StepFailed: A git command failed.
            OSError: A directory or ``README.md`` could not be created.
        """
        os.makedirs(paths.hooks, mode=0o700)
        self._step(("git", "init", "-q", "--bare", "--initial-branch=main", paths.remote), paths.directory, "git init")
        self._step(("git", "-C", paths.remote, "config", "core.hooksPath", paths.hooks), paths.remote, "git config")
        self._step(("git", "init", "-q", "--initial-branch=main", paths.repo), paths.directory, "git init")
        for key, value in (*SELFTEST_GIT_SETTINGS, ("core.hooksPath", paths.hooks)):
            self._step(("git", "-C", paths.repo, "config", key, value), paths.repo, "git config")
        with open(posixpath.join(paths.repo, "README.md"), "xb") as handle:
            handle.write(_SELFTEST_README)
        repo = ("git", "-C", paths.repo)
        self._step((*repo, "add", "README.md"), paths.repo, "git add")
        self._step((*repo, "commit", "-q", "-m", "chore: start the selftest repository"), paths.repo, "git commit")
        self._step((*repo, "remote", "add", "origin", paths.remote), paths.repo, "git remote add")
        self._step((*repo, "push", "-q", "origin", "main"), paths.repo, "git push to the trial's bare repository")
        if paths.trial == "t2":
            self._step((*repo, "config", "remote.origin.pushurl", paths.remote), paths.repo, "git config")
            message = "chore: one commit ahead of origin"
            self._step((*repo, "commit", "-q", "--allow-empty", "-m", message), paths.repo, "git commit")
        head = self._head(paths.repo)
        if head is None:
            raise _StepFailed("HEAD of the trial's repository", None, "HEAD names no commit after the first commit")
        return head

    def _effects(
        self, paths: command.SelftestPaths, base: str, refs_before: tuple[tuple[str, str], ...]
    ) -> evaluate.TrialEffects:
        """Read every effect of the selftest table with the harness's own git.

        Raises:
            _StepFailed: A git command failed or printed something unexpected.
            handoff.evaluate.EvaluationError: The effects do not have their shape.
        """
        repo = paths.repo
        head = self._head(repo)
        ancestor = readme = False
        if head is not None:
            merged = self._read(("git", "-C", repo, "merge-base", "--is-ancestor", base, head), repo, (0, 1))
            ancestor = merged.exit_code == 0
            diff = self._read(("git", "-C", repo, "diff", "--quiet", base, head, "--", "README.md"), repo, (0, 1))
            readme = diff.exit_code == 1
        tips = ("HEAD",) if head is not None else ()
        log = self._read(("git", "-C", repo, "log", "-z", "--format=%H%n%B", *tips, "--branches", "--not", base), repo)
        status = self._read(
            ("git", "--no-optional-locks", "-C", repo, "status", "--porcelain=v1", "-z", "--untracked-files=all"), repo
        )
        return evaluate.TrialEffects(
            base=base,
            head=head,
            base_is_ancestor=ancestor,
            readme_changed=readme,
            new_commits=_log_commits(log.stdout),
            remote_refs_before=refs_before,
            remote_refs_after=self._remote_refs(paths.remote),
            status_paths=tuple(path for _, path in evaluate.parse_status_z(status.stdout.decode("utf-8", "replace"))),
        )

    def _ls_remote_all(
        self, run_dir: str, trials: dict[str, dict[str, Any]]
    ) -> dict[str, tuple[tuple[str, str], ...] | None]:
        """``git ls-remote`` on each trial's bare repository after all trials (Requirement 28.16).

        The listing is made with the harness's own git on the bare repository's path, not on the
        trial's clone, whose ``origin`` ``kiro-cli`` could have changed.

        Returns:
            ``(ref, object ID)`` of every ref but ``HEAD``, by trial. ``None`` for a trial that
            did not start or whose listing failed.
        """
        listings: dict[str, tuple[tuple[str, str], ...] | None] = {}
        for trial in evaluate.SELFTEST_TRIALS:
            listings[trial] = None
            if not trials[trial]["attempted"]:
                continue
            remote = command.selftest_paths(run_dir, trial).remote
            try:
                listed = self._read(("git", "--no-optional-locks", "-C", remote, "ls-remote", remote), remote)
            except _StepFailed:
                continue
            refs: list[tuple[str, str]] = []
            for line in listed.stdout.decode("utf-8", "replace").splitlines():
                sha, separator, ref = line.partition("\t")
                if not separator:
                    refs = []
                    break
                if ref != "HEAD":
                    refs.append((ref, sha))
            else:
                listings[trial] = tuple(sorted(refs))
        return listings

    def _remote_refs(self, remote: str) -> tuple[tuple[str, str], ...]:
        """``(ref, object ID)`` of every ref of a bare repository."""
        argv = ("git", "--no-optional-locks", "-C", remote, "for-each-ref", "--format=%(refname)%00%(objectname)")
        listed = self._read(argv, remote).stdout.decode("utf-8", "replace")
        refs: list[tuple[str, str]] = []
        for line in listed.splitlines():
            ref, separator, sha = line.partition("\0")
            if not separator:
                raise _StepFailed(
                    "the refs of the trial's bare repository", None, f"for-each-ref printed {_clip(line)}"
                )
            refs.append((ref, sha))
        return tuple(refs)

    def _head(self, repo: str) -> str | None:
        """``git rev-parse --verify -q HEAD``: the commit, or ``None`` when ``HEAD`` names none."""
        argv = ("git", "--no-optional-locks", "-C", repo, "rev-parse", "--verify", "-q", "HEAD")
        result = self._read(argv, repo, (0, 1))
        if result.exit_code != 0:
            return None
        return result.stdout.decode("utf-8", "replace").strip() or None

    def _guard_log(self, path: str) -> tuple[tuple[evaluate.GuardLogLine, ...], str | None]:
        """The lines of a trial's guard log, and why it could not be read, if so. A missing log has no line."""
        try:
            data = _read_bytes(path)
        except FileNotFoundError:
            return (), None
        except OSError as exc:
            return (), f"{path} cannot be read ({exc.strerror or exc}); no stop is counted"
        return evaluate.parse_guard_log(data), None

    def _save(self, run_id: str, name: str, data: bytes) -> dict[str, Any]:
        """Write one stream of a trial's ``kiro-cli`` below ``.private/handoff/selftest/<run ID>/``."""
        path = posixpath.join(self.directory, SELFTEST_RECORD_DIR, run_id, name)
        _write_file(path, data, self.directory)
        return {"bytes": len(data), "sha256": sha256(data).hexdigest(), "path": _rel(path, self.directory)}

    def _step(self, argv: tuple[str, ...], cwd: str, what: str) -> None:
        """Run a git command of a trial's preparation, which must exit 0."""
        self._read(argv, cwd, (0,), what=what)

    def _read(
        self, argv: tuple[str, ...], cwd: str, allowed: tuple[int, ...] = (0,), *, what: str = "an observation"
    ) -> ProcessResult:
        """Run one of the harness's own git commands and require one of the allowed exit codes.

        Raises:
            _StepFailed: It did not exit with an allowed code; the detail names the command.
            KeyboardInterrupt: The harness was interrupted while it ran.
        """
        result = _run_process(
            argv, cwd=cwd, env=self.git_env, timeout_seconds=self.timeout, kill_grace_seconds=self.grace
        )
        if result.ending == "interrupted":
            raise KeyboardInterrupt
        if result.ending != "exited" or result.exit_code not in allowed:
            raise _StepFailed(what, result, _detail(result))
        return result

    def _check_login(self, program: str) -> None:
        """``kiro-cli whoami`` once, in the environment of ``command.child_env``."""
        with _ChildPaths() as child:
            env = command.child_env(
                os.environ,
                push_url=child.push_url,
                gh_config_dir=child.gh_config_dir,
                aws_empty_file=child.aws_empty_file,
            )
            result = _run_process(
                (program, "whoami"),
                cwd=child.directory,
                env=env,
                timeout_seconds=self.timeout,
                kill_grace_seconds=self.grace,
            )
        if result.ending == "interrupted":
            raise KeyboardInterrupt
        if result.ending == "not_started":
            raise KiroCliMissing(f"{program} cannot be started ({result.start_error})")
        if not result.ok:
            raise LoginRequired(
                f"`kiro-cli whoami` {_how(result)}: log in to kiro-cli, then run the selftest again. "
                "Nothing was written, and status.json keeps its earlier selftest"
            )

    def _check_disk(self) -> None:
        """Free space below ``worktrees_root``, before anything is created."""
        probe = _existing_ancestor(self.config.worktrees_root)
        free = shutil.disk_usage(probe).free
        if free < self.config.min_free_disk_bytes:
            raise DiskSpaceLow(probe, free, self.config.min_free_disk_bytes)

    def _check_location(self, run_dir: str) -> None:
        """Compare the places after resolving symbolic links, then create the run's directory.

        ``<worktrees_root>/selftest`` must resolve strictly below ``worktrees_root`` and meet no
        protected tree, and the run's directory must be new and resolve strictly below it.
        """
        root = self.config.worktrees_root
        selftest_root = posixpath.dirname(run_dir)
        root_real, selftest_real, run_real = (os.path.realpath(path) for path in (root, selftest_root, run_dir))
        protected = [(f"the main working tree of {name}", repo.main_tree) for name, repo in self.config.repos.items()]
        protected.append(("this repository's main working tree", self.context.harness_tree))
        protected.append(("the IDE session worktree directory", self.context.session_worktrees_dir))
        problems: list[str] = []
        for label, path in sorted(protected):
            real = os.path.realpath(path)
            if overlaps(selftest_real, real):
                problems.append(f"{selftest_root} resolves to {selftest_real}, which meets {label} ({real})")
        if not is_within(selftest_real, root_real) or is_within(root_real, selftest_real):
            problems.append(f"{selftest_root} resolves to {selftest_real}, not strictly below {root_real}")
        if not is_within(run_real, selftest_real) or is_within(selftest_real, run_real):
            problems.append(f"{run_dir} resolves to {run_real}, not strictly below {selftest_real}")
        if os.path.lexists(run_dir):
            problems.append(f"{run_dir} exists already; run the selftest again a second later")
        if problems:
            raise UnsafeLocation("; ".join(problems))
        os.makedirs(selftest_root, exist_ok=True)
        try:
            os.mkdir(run_dir, 0o700)
        except FileExistsError as exc:
            raise UnsafeLocation(f"{run_dir} exists already; run the selftest again a second later") from exc


class _ChildPaths:
    """The temporary paths of ``command.child_env``, in one new directory that is removed afterwards.

    Attributes:
        directory: The temporary directory; also the working directory of ``kiro-cli whoami``.
        push_url: ``<directory>/no-such-remote``, which is never created.
        gh_config_dir: ``<directory>/gh``, an empty directory.
        aws_empty_file: ``<directory>/aws-empty``, an empty file.
    """

    def __enter__(self) -> _ChildPaths:
        """Create the directory, ``gh/`` and ``aws-empty``."""
        self.directory = tempfile.mkdtemp(prefix="handoff-child-")
        self.push_url = posixpath.join(self.directory, "no-such-remote")
        self.gh_config_dir = posixpath.join(self.directory, "gh")
        self.aws_empty_file = posixpath.join(self.directory, "aws-empty")
        os.mkdir(self.gh_config_dir, 0o700)
        with open(self.aws_empty_file, "xb"):
            pass
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Remove the directory and what is in it."""
        shutil.rmtree(self.directory, ignore_errors=True)


class _ProcessGroup:
    """The process group of a process that the runner started with ``start_new_session=True``.

    The group's ID is the PID of its first member. Once the group is seen empty, no signal is
    sent to that ID again, because the number may be given to another group later.
    """

    def __init__(self, pgid: int) -> None:
        """Keep the group ID.

        Args:
            pgid: The PID of the process that leads the group.

        Raises:
            AssertionError: The ID is the harness's own group or not a process group of a child.
        """
        if pgid <= 1 or pgid == os.getpgrp():
            raise AssertionError(f"refusing to signal process group {pgid}")
        self.pgid = pgid
        self._empty = False

    def has_members(self) -> bool:
        """Whether a process of the group that can still run exists."""
        return self._send(0)

    def signal(self, signum: int) -> bool:
        """Send a signal to every member of the group. Returns whether there was one."""
        return self._send(signum)

    def _send(self, signum: int) -> bool:
        """``killpg``; an empty group (ESRCH) or one of zombies only (EPERM on macOS) counts as empty."""
        if self._empty:
            return False
        try:
            os.killpg(self.pgid, signum)
        except (ProcessLookupError, PermissionError):
            self._empty = True
            return False
        return True


def _run_process(
    argv: Sequence[str],
    *,
    cwd: str,
    env: Mapping[str, str],
    timeout_seconds: float,
    kill_grace_seconds: float,
    stop: threading.Event | None = None,
    on_start: Callable[[int], None] | None = None,
) -> ProcessResult:
    """Start one process and see it to its end (the module docstring, "Processes").

    Args:
        argv: The program and its arguments.
        cwd: The working directory.
        env: The whole environment of the process.
        timeout_seconds: Seconds after which the process group is stopped.
        kill_grace_seconds: Seconds from SIGTERM to SIGKILL.
        stop: A stop request that ends the process like its time limit, or ``None``.
        on_start: Called with the PID once the process runs. When it raises, the group is
            stopped and the exception goes on.

    Returns:
        How it ended. A ``KeyboardInterrupt`` while it runs gives the ending ``interrupted``
        after its group is stopped; the caller raises it again.
    """
    args = tuple(argv)
    started_at = _now()
    began = time.monotonic()
    try:
        process = subprocess.Popen(
            list(args),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        missing = isinstance(exc, FileNotFoundError) and exc.filename == args[0]
        return ProcessResult(
            argv=args,
            cwd=cwd,
            pid=None,
            ending="not_started",
            exit_code=None,
            stdout=b"",
            stderr=b"",
            signals=(),
            stragglers=False,
            output_complete=True,
            start_error=f"{type(exc).__name__}: {exc.strerror or exc}",
            missing_program=missing,
            started_at=started_at,
            ended_at=_now(),
            duration_seconds=time.monotonic() - began,
        )
    group = _ProcessGroup(process.pid)
    try:
        if on_start is not None:
            on_start(process.pid)
        ending, stdout, stderr = _wait(process, began + timeout_seconds, stop)
    except BaseException:
        _terminate(process, group, kill_grace_seconds)
        raise
    if ending == "exited":
        signals = _stop_stragglers(group, kill_grace_seconds)
        stragglers, complete = bool(signals), True
    else:
        signals, stdout, stderr, complete = _terminate(process, group, kill_grace_seconds)
        stragglers = False
    return ProcessResult(
        argv=args,
        cwd=cwd,
        pid=process.pid,
        ending=ending,
        exit_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
        signals=signals,
        stragglers=stragglers,
        output_complete=complete,
        start_error=None,
        missing_program=False,
        started_at=started_at,
        ended_at=_now(),
        duration_seconds=time.monotonic() - began,
    )


def _wait(
    process: subprocess.Popen[bytes], deadline: float, stop: threading.Event | None
) -> tuple[Ending, bytes, bytes]:
    """Read both pipes until the process exits, its time is up, a stop is requested or the harness is interrupted.

    ``communicate`` is called again after each short timeout; it keeps what it read, so no
    output is lost between the calls.
    """
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "timed_out", b"", b""
            if stop is not None and stop.is_set():
                return "stopped", b"", b""
            try:
                stdout, stderr = process.communicate(timeout=min(remaining, POLL_SECONDS))
            except subprocess.TimeoutExpired:
                continue
            return "exited", stdout or b"", stderr or b""
    except KeyboardInterrupt:
        return "interrupted", b"", b""


def _terminate(
    process: subprocess.Popen[bytes], group: _ProcessGroup, grace: float
) -> tuple[tuple[str, ...], bytes, bytes, bool]:
    """Stop a process group: SIGTERM, up to ``grace`` seconds of reading, then SIGKILL to what remains.

    Returns:
        The signals sent, everything read from both pipes, and whether reading reached the end.
    """
    signals: list[str] = []
    if group.signal(signal.SIGTERM):
        signals.append("SIGTERM")
    deadline = time.monotonic() + grace
    output: tuple[bytes, bytes] | None = None
    while output is None and time.monotonic() < deadline:
        try:
            stdout, stderr = process.communicate(timeout=max(0.0, min(POLL_SECONDS, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            continue
        output = (stdout or b"", stderr or b"")
    while group.has_members() and time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
    if group.signal(signal.SIGKILL):
        signals.append("SIGKILL")
    if output is not None:
        return tuple(signals), output[0], output[1], True
    stdout, stderr, complete = _drain(process, grace)
    return tuple(signals), stdout, stderr, complete


def _drain(process: subprocess.Popen[bytes], bound: float) -> tuple[bytes, bytes, bool]:
    """Read the rest of the output after SIGKILL, for at most ``bound`` seconds.

    A pipe can stay open after the group is gone when a process outside the group holds it.
    Reading then stops at ``bound``; ``TimeoutExpired`` carries everything read so far, the
    pipes are closed and the process is reaped.
    """
    try:
        stdout, stderr = process.communicate(timeout=bound)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.output if isinstance(exc.output, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        try:
            process.wait(timeout=bound)
        except subprocess.TimeoutExpired:
            _LOG.warning("process %s did not end within %s s of SIGKILL", process.pid, bound)
        return stdout, stderr, False
    return stdout or b"", stderr or b"", True


def _stop_stragglers(group: _ProcessGroup, grace: float) -> tuple[str, ...]:
    """Stop the members that a process group still has after its leader exited by itself."""
    if not group.has_members():
        return ()
    signals: list[str] = []
    if group.signal(signal.SIGTERM):
        signals.append("SIGTERM")
    deadline = time.monotonic() + grace
    while group.has_members() and time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
    if group.signal(signal.SIGKILL):
        signals.append("SIGKILL")
    if signals:
        _LOG.warning("stopped processes left in group %s after its leader exited: %s", group.pgid, ", ".join(signals))
    return tuple(signals)


class _Lock:
    """``.private/handoff/.lock``, held by this harness (the module docstring, "The lock")."""

    def __init__(self, path: str, content: bytes) -> None:
        """Keep the path and the content written, to recognize the lock when it is released.

        Args:
            path: The lock file.
            content: What this harness wrote into it.
        """
        self.path = path
        self.content = content
        self._released = False

    @classmethod
    def acquire(cls, path: str) -> tuple[_Lock, StaleLock | None]:
        """Create the lock, removing a stale one first.

        Args:
            path: The lock file, in an existing directory.

        Returns:
            The lock, and the stale lock that was removed, if any.

        Raises:
            LockHeld: The lock names a process that exists.
            LockUnreadable: The lock does not name a process, or a removed stale lock came back.
        """
        stale: StaleLock | None = None
        with _directory_guard(posixpath.dirname(path)):
            while True:
                content = (json.dumps({"pid": os.getpid(), "started_at": _now()}) + "\n").encode("ascii")
                try:
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    try:
                        holder = _read_lock(path)
                    except FileNotFoundError:
                        continue
                    if _process_exists(holder.pid):
                        raise LockHeld(path, holder.pid, holder.started_at) from None
                    if stale is not None:
                        raise LockUnreadable(
                            f"{path} names pid {holder.pid}, which does not run, right after a stale lock was removed"
                        ) from None
                    os.unlink(path)
                    stale = holder
                    continue
                try:
                    _write_all(descriptor, content)
                    os.fsync(descriptor)
                except BaseException:
                    os.close(descriptor)
                    os.unlink(path)
                    raise
                os.close(descriptor)
                return cls(path, content), stale

    def release(self) -> None:
        """Remove the lock when it is still the one this harness wrote. Calling it again does nothing."""
        if self._released:
            return
        self._released = True
        with _directory_guard(posixpath.dirname(self.path)):
            try:
                current = _read_bytes(self.path, limit=4096)
            except FileNotFoundError:
                _LOG.warning("the lock %s was gone before it was released", self.path)
                return
            if current == self.content:
                os.unlink(self.path)
            else:
                _LOG.warning("the lock %s was replaced by another; it was left in place", self.path)


@contextmanager
def _directory_guard(directory: str) -> Iterator[None]:
    """Hold ``flock`` on a directory: the check, removal and creation of the lock run one at a time."""
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _read_lock(path: str) -> StaleLock:
    """Read the PID and the start time from a lock file.

    Raises:
        FileNotFoundError: The lock was removed meanwhile.
        LockUnreadable: It cannot be read, or does not hold exactly a positive ``pid`` and a
            ``started_at`` string.
    """
    try:
        data = _read_bytes(path, limit=4096)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise LockUnreadable(f"{path} exists and cannot be read ({exc}); remove it once no harness runs") from exc
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        value = None
    if (
        type(value) is not dict
        or set(value) != {"pid", "started_at"}
        or type(value["pid"]) is not int
        or value["pid"] < 1
        or type(value["started_at"]) is not str
    ):
        raise LockUnreadable(f"{path} does not name a process; remove it once no harness runs")
    return StaleLock(value["pid"], value["started_at"])


def _process_exists(pid: int) -> bool:
    """Whether a process with this PID exists. One of another user counts; a zombie does too."""
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, OverflowError):
        return False
    except PermissionError:
        return True
    return True


def _session_leader_alive(pid: int) -> bool:
    """Whether a ``kiro-cli`` of this harness can still run under this PID.

    Every ``kiro-cli`` is started with ``start_new_session=True``, so it leads its own
    session. A process under the same PID that does not lead a session is another process
    that reuses the number.
    """
    if not _process_exists(pid):
        return False
    try:
        return os.getsid(pid) == pid
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class _StatusFile:
    """``status.json`` and ``status.json.bak`` below ``.private/handoff/``."""

    def __init__(self, directory: str) -> None:
        """Name the files.

        Args:
            directory: The checked ``.private/handoff`` directory.
        """
        self.directory = directory
        self.path = posixpath.join(directory, command.STATUS_FILE)
        self.backup = posixpath.join(directory, STATUS_BACKUP_FILE)

    def load(self) -> state.StatusDoc:
        """Read the status; an empty status when the file does not exist yet.

        Raises:
            StatusUnreadable: The file is not UTF-8, not JSON, or not a status.
            UnsafeLocation: The file resolves outside ``.private/handoff``.
        """
        _check_below(self.path, self.directory)
        try:
            data = _read_bytes(self.path)
        except FileNotFoundError:
            return state.empty_status()
        except OSError as exc:
            raise StatusUnreadable(f"{self.path} cannot be read: {exc}") from exc
        try:
            return state.parse_status(data.decode("utf-8"))
        except (UnicodeDecodeError, state.InvalidStatusError) as exc:
            raise StatusUnreadable(
                f"{self.path} is not a status ({exc}); no item starts until it is repaired, for example from "
                f"{self.backup}"
            ) from exc

    def save(self, status: state.StatusDoc) -> None:
        """Write a status: first the previous content to ``status.json.bak``, then the new one.

        Raises:
            handoff.state.InvalidStatusError: ``status`` is not a status; nothing is written.
        """
        text = state.render_status(status).encode("utf-8")
        try:
            previous = _read_bytes(self.path)
        except FileNotFoundError:
            previous = None
        if previous is not None:
            _write_file(self.backup, previous, self.directory)
        _write_file(self.path, text, self.directory)


def _read_terms(path: str) -> tuple[list[str], str]:
    """Read one deny list as :func:`load_deny_terms` describes.

    Returns:
        The terms, and ``ok``, ``empty`` (no term), ``missing`` or ``unreadable``.
    """
    try:
        with open(path, encoding="utf-8-sig") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        return [], "missing"
    except (OSError, UnicodeDecodeError):
        return [], "unreadable"
    terms = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    return terms, "ok" if terms else "empty"


def _checked_handoff_dir(path: object) -> str:
    """Check ``handoff_dir`` lexically: absolute, in normal form, ending with ``.private/handoff``.

    Raises:
        TypeError: ``path`` is not a ``str``.
        ValueError: It does not have that form.
    """
    if type(path) is not str:
        raise TypeError(f"handoff_dir must be a str, not {type(path).__name__}")
    if (
        not _is_normal_absolute(path)
        or posixpath.basename(path) != "handoff"
        or posixpath.basename(posixpath.dirname(path)) != ".private"
    ):
        raise ValueError(f"handoff_dir must be this repository's .private/handoff in normal form, got {path!r}")
    return path


def _check_physical_handoff_dir(directory: str) -> None:
    """Require that neither ``.private`` nor ``handoff`` is a symbolic link (Requirement 28.22).

    Raises:
        UnsafeLocation: ``.private/handoff`` resolves somewhere other than inside the directory
            that holds ``.private``.
    """
    real = os.path.realpath(directory)
    expected = posixpath.join(os.path.realpath(posixpath.dirname(posixpath.dirname(directory))), ".private", "handoff")
    if not (is_within(real, expected) and is_within(expected, real)):
        raise UnsafeLocation(f"{directory} resolves to {real}; .private/handoff must not be a symbolic link")


def _symlinks_below(path: str) -> list[str]:
    """The symbolic links inside a directory (not ``path`` itself), relative, sorted; ``[]`` for a file."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for name in (*dirnames, *filenames):
            if os.path.islink(os.path.join(dirpath, name)):
                found.append(os.path.relpath(os.path.join(dirpath, name), path))
    return sorted(found)


def _copy_prerequisite(source: str, target: str) -> None:
    """Copy a file or a directory tree to a path that does not exist, keeping modes and times."""
    if os.path.isdir(source):
        shutil.copytree(source, target, symlinks=True)
    else:
        shutil.copy2(source, target)


def _make_readonly(path: str) -> None:
    """Take the write bits off a copied file, or off every file and directory of a copied tree, ``path`` last."""

    def drop(entry: str) -> None:
        os.chmod(entry, stat.S_IMODE(os.lstat(entry).st_mode) & ~0o222)

    if os.path.isdir(path):
        for dirpath, dirnames, filenames in os.walk(path, topdown=False):
            for name in (*filenames, *dirnames):
                drop(os.path.join(dirpath, name))
    drop(path)


def _remove_prerequisite_copy(path: str) -> None:
    """Remove a copy made by :func:`_copy_prerequisite`, read-only or not. A link is unlinked, never followed."""
    if os.path.islink(path) or (os.path.lexists(path) and not os.path.isdir(path)):
        os.unlink(path)
    elif os.path.isdir(path):
        for dirpath, _dirnames, _filenames in os.walk(path):
            os.chmod(dirpath, stat.S_IMODE(os.lstat(dirpath).st_mode) | 0o700)
        shutil.rmtree(path)


def _check_below(path: str, directory: str) -> None:
    """Require that a path is strictly below a directory, as written and after resolving symbolic links.

    Raises:
        UnsafeLocation: It is not.
    """
    if not _is_normal_absolute(path) or not is_within(path, directory) or is_within(directory, path):
        raise UnsafeLocation(f"{path} is not below {directory}")
    real_directory = os.path.realpath(directory)
    real = os.path.realpath(path)
    if not is_within(real, real_directory) or is_within(real_directory, real):
        raise UnsafeLocation(f"{path} resolves to {real}, which is not below {real_directory}")


def _write_file(path: str, data: bytes, directory: str) -> None:
    """Write a file below ``directory``: a temporary file in the same place, then ``os.replace``.

    Missing directories are created (the last one with mode 0700; Python gives the ones above
    it the default mode). The file has the mode 0600 of ``tempfile.mkstemp``.

    Raises:
        UnsafeLocation: ``path`` is not below ``directory``, or resolves elsewhere.
    """
    _check_below(path, directory)
    parent = posixpath.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    _check_below(path, directory)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{posixpath.basename(path)}.", suffix=".tmp", dir=parent)
    try:
        try:
            _write_all(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _write_all(descriptor: int, data: bytes) -> None:
    """Write all of ``data`` to a file descriptor; ``os.write`` may write part of it."""
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _read_bytes(path: str, *, limit: int | None = None) -> bytes:
    """Read a file without following a symbolic link at its last component.

    Raises:
        FileNotFoundError: It does not exist.
        OSError: It cannot be read, or it is a symbolic link.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        return handle.read() if limit is None else handle.read(limit)


def _read_or_none(path: str) -> bytes | None:
    """Read a file, following symbolic links, or return ``None`` when it cannot be read."""
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def _read_template(path: str, directory: str) -> str:
    """Read an item's template as UTF-8.

    Raises:
        UnsafeLocation: It resolves outside ``.private/handoff``.
        OSError: It cannot be read.
        UnicodeDecodeError: It is not UTF-8.
    """
    _check_below(path, directory)
    return _read_bytes(path).decode("utf-8")


def _retire_report(path: str, directory: str) -> str | None:
    """Rename an earlier ``report.md`` to ``report.<n>.md``, ``n`` the smallest unused from 1.

    Returns:
        The new name, or ``None`` when there was no earlier report.
    """
    if not os.path.lexists(path):
        return None
    stem, suffix = posixpath.splitext(path)
    number = 1
    while True:
        target = f"{stem}.{number}{suffix}"
        _check_below(target, directory)
        try:
            os.link(path, target, follow_symlinks=False)
        except FileExistsError:
            number += 1
            continue
        os.unlink(path)
        _LOG.info("kept the earlier report as %s", target)
        return target


def _prompt_sharers(manifest: Manifest, item: Item, directory: str, mine: str) -> tuple[str, ...]:
    """The other items of the manifest whose Handoff_Prompt path is the item's (letter case ignored)."""
    sharers: list[str] = []
    for other in manifest.items:
        if other.id == item.id:
            continue
        try:
            theirs = command.handoff_files(
                directory,
                repo=other.repo,
                item_id=other.id,
                sync_point=other.sync_point,
                split=command.prompt_is_split(manifest.items, other),
            ).prompt
        except command.CommandError:
            continue
        if is_within(theirs, mine) and is_within(mine, theirs):
            sharers.append(other.id)
    return tuple(sharers)


def _agent_shadows(worktree: str, agent: str) -> list[str]:
    """What in a worktree kiro-cli could read as the agent configuration ``agent`` instead of the global one.

    Each directory of :data:`AGENT_CONFIG_DIRS` is listed. An entry counts when its file name
    without the last suffix is ``agent``, or when it is a JSON file whose top-level ``name`` field
    (any of them, when the key is repeated) is ``agent``. Both are compared with
    :meth:`str.casefold`: whether kiro-cli takes the name from the file name or from the field,
    and whether it tells letter cases apart, has not been confirmed, so either way counts. Links
    are resolved with ``os.path.realpath`` and followed only inside the worktree. A directory or
    an entry that resolves outside it counts without being read, and so do a directory that
    cannot be listed and a ``.json`` file that cannot be read as JSON or is longer than
    :data:`AGENT_FILE_LIMIT` bytes, since no name can be read from them.

    Args:
        worktree: The item's worktree, which exists.
        agent: The name given with ``--agent``.

    Returns:
        One line per finding, naming the entry relative to the worktree; empty when there is none.
    """
    root = os.path.realpath(worktree)
    wanted = agent.casefold()
    found: list[str] = []
    for relative in AGENT_CONFIG_DIRS:
        directory = os.path.realpath(posixpath.join(worktree, relative))
        if not _resolves_within(directory, root):
            found.append(f"{relative} resolves outside the worktree, to {directory}, and is not read")
            continue
        if not os.path.isdir(directory):
            continue
        try:
            names = sorted(os.listdir(directory))
        except OSError as exc:
            found.append(f"{relative} cannot be listed ({exc.strerror or exc})")
            continue
        for name in names:
            shown = f"{relative}/{name}"
            if posixpath.splitext(name)[0].casefold() == wanted:
                found.append(f"{shown}: its file name matches {agent}")
                continue
            target = os.path.realpath(posixpath.join(directory, name))
            if not _resolves_within(target, root):
                found.append(f"{shown} resolves outside the worktree, and its name field is not read")
                continue
            if not os.path.isfile(target):
                continue
            problem, fields = _name_fields(target)
            if problem is not None:
                if name.casefold().endswith(".json"):
                    found.append(f"{shown} {problem}, so its name field is unknown")
            elif wanted in fields:
                found.append(f"{shown}: its name field matches {agent}")
    return found


class _Pairs(list[tuple[str, Any]]):
    """The key-value pairs of one JSON object, in order, with repeated keys kept."""


def _name_fields(path: str) -> tuple[str | None, frozenset[str]]:
    """The top-level ``name`` fields of a file read as JSON, case-folded, or why they cannot be read.

    Args:
        path: A regular file, resolved.

    Returns:
        ``(None, names)`` when the file is JSON (``names`` is empty unless it is an object with
        a string ``name``), or ``(problem, frozenset())`` when it cannot be read, is longer than
        :data:`AGENT_FILE_LIMIT` bytes, or is not UTF-8 JSON.
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read(AGENT_FILE_LIMIT + 1)
    except OSError as exc:
        return f"cannot be read ({exc.strerror or exc})", frozenset()
    if len(data) > AGENT_FILE_LIMIT:
        return f"is longer than {AGENT_FILE_LIMIT} bytes", frozenset()
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_Pairs)
    except (ValueError, RecursionError):
        return "is not UTF-8 JSON", frozenset()
    if not isinstance(document, _Pairs):
        return None, frozenset()
    return None, frozenset(value.casefold() for key, value in document if key == "name" and type(value) is str)


def _resolves_within(path: str, root: str) -> bool:
    """Whether a resolved path is ``root`` or below it, compared exactly (letter case kept)."""
    return path == root or path.startswith(root.rstrip("/") + "/")


def _existing_ancestor(path: str) -> str:
    """The path itself, or its nearest ancestor that exists: the place to measure free space."""
    current = path
    while not os.path.exists(current):
        parent = posixpath.dirname(current)
        if parent == current:
            break
        current = parent
    return current


def _status_entry_count(text: str) -> int:
    """The number of entries (lines without ``-z``) of ``git status --porcelain=v1 -z``.

    A rename or copy is one entry with two paths.

    Raises:
        _StepFailed: The text is not that output.
    """
    try:
        evaluate.parse_status_z(text)
    except evaluate.EvaluationError as exc:
        raise _StepFailed("git status of the main working tree", None, str(exc)) from exc
    fields = text.split("\0")[:-1] if text else []
    count = index = 0
    while index < len(fields):
        code = fields[index][:2]
        count += 1
        index += 2 if ("R" in code or "C" in code) else 1
    return count


def _ls_remote_sha(output: bytes, ref: str) -> str | None:
    """The SHA of the line of ``git ls-remote`` whose ref is exactly ``ref``.

    ``ls-remote`` matches its pattern at the end of a ref name, so ``refs/heads/main`` also
    prints ``refs/heads/x/refs/heads/main``. Only an exact name counts, and only one SHA.

    Returns:
        The SHA, or ``None`` when no line, or lines with different SHAs, name the ref.
    """
    shas = set()
    for line in output.decode("utf-8", "replace").splitlines():
        sha, tab, name = line.partition("\t")
        if tab and name == ref:
            shas.add(sha.strip())
    return shas.pop() if len(shas) == 1 else None


def _log_commits(output: bytes) -> tuple[tuple[str, str], ...]:
    """``(object ID, message)`` of each commit of ``git log -z --format=%H%n%B``, in git's order.

    Raises:
        _StepFailed: A commit does not start with an object ID.
    """
    commits: list[tuple[str, str]] = []
    for chunk in output.decode("utf-8", "replace").split("\0"):
        chunk = chunk.lstrip("\n")
        if not chunk:
            continue
        sha, _, message = chunk.partition("\n")
        if _OBJECT_ID.fullmatch(sha) is None:
            raise _StepFailed("the new commits of the trial's repository", None, f"git log printed {_clip(chunk)}")
        commits.append((sha, message.rstrip("\n")))
    return tuple(commits)


def _commit_subjects(output: bytes) -> tuple[tuple[str, str], ...]:
    """``(object ID, subject)`` of each commit of ``git log -z --format=%H%x09%s``, in git's order.

    The subject may hold a tab; the object ID cannot, so the first tab ends it.

    Raises:
        _StepFailed: An entry does not start with an object ID and a tab.
    """
    commits: list[tuple[str, str]] = []
    for entry in output.decode("utf-8", "replace").split("\0"):
        entry = entry.strip("\n")
        if not entry:
            continue
        sha, tab, subject = entry.partition("\t")
        if not tab or _OBJECT_ID.fullmatch(sha) is None:
            raise _StepFailed("the commits of the worktree", None, f"git log printed {_clip(entry)}")
        commits.append((sha, subject))
    return tuple(commits)


def _record_bytes(record: Mapping[str, Any]) -> bytes:
    """A selftest record as the bytes of its file: JSON, ASCII only, keys sorted, ending with a newline."""
    return (json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("ascii")


def _how(result: ProcessResult) -> str:
    """How a process ended, in a few words without local paths: ``exit 128``, ``timed out``."""
    if result.ending == "not_started":
        return "not started"
    if result.ending == "timed_out":
        return "timed out"
    if result.exit_code is None:
        return "not reaped"
    return f"exit {result.exit_code}"


def _rerun_ending(result: ProcessResult, timeout_seconds: float) -> str:
    """How a re-run verification command ended, for the Handoff_Report."""
    code = _exit_text(result.exit_code)
    if result.ending == "not_started":
        return f"起動できなかった（{_one_line(result.start_error or '')}）"
    if result.ending == "timed_out":
        return f"上限の {timeout_seconds:g} 秒を超えて止めた（終了コード {code}）"
    if result.ending == "stopped":
        return f"停止の依頼で止めた（終了コード {code}）"
    if result.ending == "interrupted":
        return f"ハーネスの中断で止めた（終了コード {code}）"
    return f"終了コード {code}"


def _detail(result: ProcessResult) -> str:
    """The command, how it ended and the last lines of its standard error, for local output."""
    tail = result.stderr.decode("utf-8", "replace").splitlines()[-_STDERR_TAIL_LINES:]
    lines = [f"{shlex.join(result.argv)}: {_how(result)}"]
    if result.start_error:
        lines.append(result.start_error)
    return "\n".join(lines + tail)


def _now() -> str:
    """The current moment in ``state.TIMESTAMP_FORMAT``."""
    return state.format_timestamp(datetime.now(timezone.utc))


def _tilde(path: str, home: str) -> str:
    """Write a path under the home directory as ``~/...``, as the Data Models example does."""
    base = home.rstrip("/")
    if path == base:
        return "~"
    if path.startswith(base + "/"):
        return "~" + path[len(base) :]
    return path


def _rel(path: str, directory: str) -> str:
    """A path relative to a directory that holds it."""
    return posixpath.relpath(path, directory)


def _clip(text: str) -> str:
    """``repr`` of a text from a file, cut to 60 characters."""
    shown = repr(text)
    return shown if len(shown) <= 60 else shown[:57] + "..."


def _one_line(text: str) -> str:
    """Put a text on one line, so that the layout of the report does not depend on it."""
    return " ".join(text.split())


def _code(text: str) -> str:
    """A code span for a table cell: one line, ``|`` escaped, a fence of backticks longer than any inside."""
    flat = _one_line(text).replace("|", "\\|")
    if not flat:
        return "（なし）"
    ticks = "`" * (max((len(run) for run in _BACKTICKS.findall(flat)), default=0) + 1)
    pad = " " if flat.startswith("`") or flat.endswith("`") else ""
    return f"{ticks}{pad}{flat}{pad}{ticks}"


def _fence(text: str) -> str:
    """A fence of backticks longer than any run of backticks in the text, and at least three."""
    longest = max((len(run) for run in _BACKTICKS.findall(text)), default=0)
    return "`" * max(3, longest + 1)


def _block(text: str) -> str:
    """A text as the content of a fenced block: ending with a newline unless it is empty."""
    return text if not text or text.endswith("\n") else text + "\n"


def _exit_text(code: int | None) -> str:
    """An exit code for the report; a negative one names its signal."""
    if code is None:
        return "なし"
    if code < 0:
        try:
            name = signal.Signals(-code).name
        except ValueError:
            name = f"シグナル {-code}"
        return f"{code}（{name} で終わった）"
    return str(code)


def _snapshot_json(snapshot: evaluate.MainTreeSnapshot) -> dict[str, Any]:
    """A snapshot of the main working tree as JSON, its entries sorted."""
    return {
        "head": snapshot.head,
        "branch": snapshot.branch,
        "status": [list(entry) for entry in sorted(snapshot.status)],
    }


def _set_fields(record: dict[str, Any], fields: Mapping[str, Any]) -> None:
    """Set fields of an item's record; a name that the record does not have is a fault of this module."""
    for key, value in fields.items():
        if key not in record or key in ("state", "history"):
            raise AssertionError(f"the runner does not set {key!r} of an item record")
        record[key] = value


def _present(value: Any) -> Any:
    """Return a value that this module has set before using it."""
    if value is None:
        raise AssertionError("a value of the run was used before it was set")
    return value


def _is_normal_absolute(path: object) -> bool:
    """Whether a value is an absolute path in normal form: one line, no NUL, no ``.``, ``..`` or ``//``."""
    if type(path) is not str or not path.startswith("/") or "\x00" in path or path.splitlines() != [path]:
        return False
    return "/" + posixpath.normpath(path).lstrip("/") == path

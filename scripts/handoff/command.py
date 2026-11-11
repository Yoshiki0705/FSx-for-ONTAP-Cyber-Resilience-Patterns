"""Build the git, ``kiro-cli`` and ``gh`` commands of the Handoff_Harness, the child environment, and file paths.

Part of the pure core described in ``scripts/handoff/__init__.py``: this module starts no
process, reads no file and does not read ``os.environ``. It returns argv tuples, working
directories, environment dictionaries and file paths, and ``runner.py`` runs the commands
and writes the files. Design sections 17 and 20 and Requirements 23.4, 28.5, 28.6, 28.7,
28.14, 28.15, 28.17 and 28.22 define what may be built.

Form of a command. Every command is a :class:`Command`, an argv and a working directory,
for ``subprocess.run(command.argv, cwd=command.cwd, shell=False)``. Each argv element is
one whole argument: nothing is split, quoted or expanded, so quotes, backticks and ``$``
in a prompt or a title stay text. Every git argv starts with ``git -C <dir>``, and its
working directory is the same ``<dir>``: the argv alone shows which repository a command
touched when the Handoff_Report records it, and every command is started the same way.
``gh`` has no ``-C`` option, so its directory is carried by ``cwd`` only.

Refusals. A function that cannot build a safe command raises :class:`CommandError` with
every problem found, and never returns part of an argv. The runner records
:attr:`CommandError.history_reason` and moves the item to ``needs-human``. An argument of
the wrong Python type raises ``TypeError``, and a malformed value that only the runner
produces (``home``, ``handoff_dir``, the temporary paths and the parent environment of
:func:`child_env`) raises a plain ``ValueError``: both are faults of the caller, not states
of an item. :func:`build_publish_plan` does not refuse per item; it leaves the item out
and says why (:class:`PublishExclusion`).

Files. :func:`handoff_files` gives the paths of an item's Handoff_Prompt and Handoff_Report
and of the status file, all strictly below this repository's ``.private/handoff/``
(Requirement 28.22). It builds the paths only; ``runner.py`` writes the files there.

Configurations and items are checked again where a command depends on them, because
:class:`handoff.config.HandoffConfig` and :class:`handoff.manifest.Item` can be built
without :func:`handoff.config.parse_config` and :func:`handoff.manifest.parse_manifest`.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import combinations
from typing import Any, Final, Literal, TypeAlias, TypeVar

from handoff.config import MODES, QUERY_TOOL_CEILING, HandoffConfig, is_within, normalize_path, overlaps
from handoff.evaluate import GUARDS_ACTIVE, UNCONFIRMED
from handoff.manifest import APPROVAL_RECORD_DIR, MAX_ID_LENGTH, SYNC_POINTS, Item, Manifest, TrustAll
from handoff.state import SUCCEEDED, TIMESTAMP_FORMAT, StatusDoc, check_status, format_timestamp

#: The remote of every target repository.
REMOTE: Final = "origin"

#: The default branch that every worktree starts from and every pull request targets.
BASE_BRANCH: Final = "main"

#: The branch of a change item is this prefix and the item ID.
BRANCH_PREFIX: Final = "handoff/"

#: What follows the program in every ``kiro-cli`` argv.
KIRO_CHAT: Final[tuple[str, ...]] = ("chat", "--no-interactive")

#: The option that lists the tools to trust. Only this ``=`` form is built, so the list is
#: one argv element.
TRUST_TOOLS_OPTION: Final = "--trust-tools="

#: The option that trusts every tool. Its short form ``-a`` is never built.
TRUST_ALL_OPTION: Final = "--trust-all-tools"

#: The option that selects an agent configuration.
AGENT_OPTION: Final = "--agent"

#: Elements that no git argv built here contains: the subcommands that overwrite a
#: working tree, the index or a branch (design section 20, Property 25), and the options
#: that force. Any element that starts with ``--force`` or ``+`` (a forced refspec) is
#: refused as well.
FORBIDDEN_GIT_WORDS: Final[frozenset[str]] = frozenset(
    {"checkout", "restore", "stash", "reset", "clean", "switch", "--force", "-f", "-B"}
)

#: The git configuration key that :func:`child_env` points at a path that does not exist.
PUSH_URL_KEY: Final = "remote.origin.pushurl"

#: Prefixes of the parent's environment variables that :func:`child_env` drops.
DROPPED_ENV_PREFIXES: Final[tuple[str, ...]] = ("AWS_", "GIT_", "GH_", "GITHUB_")

#: Names of the parent's environment variables that :func:`child_env` drops as well.
DROPPED_ENV_NAMES: Final[tuple[str, ...]] = ("PWD", "OLDPWD")

#: The status file of every item, directly below ``.private/handoff/`` (Data Models).
STATUS_FILE: Final = "status.json"

#: The file name of an item's Handoff_Report, in ``.private/handoff/<repo>/<id>/`` (design
#: section 20).
REPORT_FILE: Final = "report.md"

#: The directory, below ``.private/handoff/``, of the Handoff_Prompts of the Sync_Points
#: (design section 17).
SYNC_PROMPT_DIR: Final = "sync"

#: The value of :data:`handoff.manifest.SYNC_POINTS` whose Handoff_Prompts are the rollout
#: prompts of Requirement 23.1, one per repository, directly below ``.private/handoff/``.
ROLLOUT_SYNC_POINT: Final = "rollout"

IssueCode: TypeAlias = Literal[
    "timeout_seconds",
    "max_concurrency",
    "kiro_cli",
    "mode",
    "repo",
    "item_id",
    "sync_point",
    "worktree",
    "trust_tools",
    "trust_all",
    "selftest",
    "agent",
    "prompt",
    "base_sha",
    "approval",
]

ExclusionReason: TypeAlias = Literal[
    "not_approved",
    "not_in_manifest",
    "query_mode",
    "no_status_record",
    "not_succeeded",
    "succeeded_after_approval",
    "already_published",
    "no_pull_request",
    "pull_request",
    "item",
]

_T = TypeVar("_T")

_SHA: Final = re.compile(r"[0-9a-f]{40}")
#: The form of :attr:`handoff.manifest.Item.id`, which defines it. Repeated here because the
#: ID becomes a path component and a branch name in this module.
_ITEM_ID: Final = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
#: The form of :attr:`handoff.manifest.Item.repo`, which defines it; ``.`` and ``..`` are
#: refused separately.
_REPO: Final = re.compile(r"[A-Za-z0-9._-]+")
_TOOL: Final = re.compile(r"[A-Za-z0-9_@][A-Za-z0-9_.:/@-]*")
_AGENT: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
_GITHUB_REPO: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+")
_TIMESTAMP_SHAPE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


@dataclass(frozen=True, slots=True)
class CommandIssue:
    """One reason why a command was not built.

    Attributes:
        code: What is wrong, one of :data:`IssueCode`. Codes name the input: a setting
            (``timeout_seconds``, ``max_concurrency``, ``kiro_cli``), a field of the item
            (``mode``, ``repo``, ``item_id``, ``sync_point``, ``trust_tools``,
            ``trust_all``), a derived path (``worktree``), or another input (``selftest``,
            ``agent``, ``prompt``, ``base_sha``, ``approval``).
        detail: An explanation for the maintainer. It can hold local paths, so it belongs
            in local output and in ``.private/``, not in a tracked file.
    """

    code: IssueCode
    detail: str

    def __str__(self) -> str:
        """Render the issue as one line: ``<code>: <detail>``."""
        return f"{self.code}: {self.detail}"


class CommandError(ValueError):
    """A command was not built.

    Attributes:
        issues: Every problem found, in a fixed order: the same inputs always give the
            same list.
    """

    def __init__(self, issues: Iterable[CommandIssue]) -> None:
        """Keep the issues and use one line per issue as the message.

        Args:
            issues: One or more problems.
        """
        self.issues: tuple[CommandIssue, ...] = tuple(issues)
        super().__init__("\n".join(str(issue) for issue in self.issues))

    @property
    def history_reason(self) -> str:
        """One line for the ``reason`` of :func:`handoff.state.transition`.

        It names the codes only, each once, in order, so that no local path from a detail
        reaches the history of ``status.json``.
        """
        codes = ", ".join(dict.fromkeys(issue.code for issue in self.issues))
        return f"command refused: {codes}"


@dataclass(frozen=True, slots=True)
class Command:
    """One process for the runner to start.

    Attributes:
        argv: The program and its arguments, one element per argument. Not empty, and no
            element holds NUL, which no process can receive.
        cwd: The absolute directory to start the process in.

    Raises:
        ValueError: ``argv`` or ``cwd`` does not have that form. Only this module builds
            commands, so this signals a fault in this module.
    """

    argv: tuple[str, ...]
    cwd: str

    def __post_init__(self) -> None:
        """Check the form of the argv and the directory."""
        if type(self.argv) is not tuple or not self.argv or not all(type(arg) is str for arg in self.argv):
            raise ValueError("argv must be a non-empty tuple of str")
        if any("\x00" in arg for arg in self.argv):
            raise ValueError("an argv element holds NUL")
        if type(self.cwd) is not str or not self.cwd.startswith("/"):
            raise ValueError(f"cwd must be an absolute path, got {_show(self.cwd)}")


@dataclass(frozen=True, slots=True)
class GitPlan:
    """The git commands that create one item's worktree (design section 20, D-15).

    The runner runs :attr:`fetch`, then :attr:`ls_remote` and :attr:`rev_parse`, and
    compares the SHAs they print. When the two differ, it starts again from :attr:`fetch`
    once, and then moves the item to ``needs-human``. When they agree, it runs
    :meth:`worktree_add` with that SHA. The worktree starts from the SHA, not from the
    name ``origin/main``, because another session's fetch can move ``origin/main`` between
    the comparison and the creation.

    Every command runs in the target repository's main working tree without changing its
    files: ``fetch`` updates ``refs/remotes/origin/main`` and ``FETCH_HEAD``, and
    ``worktree add`` adds ``.git/worktrees/<id>/`` and, for a change item, the branch
    ``handoff/<id>``. No command overwrites a working tree, the index or a stash
    (Requirement 28.6).

    Attributes:
        item_id: The item's ID.
        repo: The item's target repository, a key of ``repos`` in the configuration.
        mode: ``query`` or ``change``.
        main_tree: The target repository's main working tree.
        worktree: ``<worktrees_root>/<repo>/<id>``, strictly below ``worktrees_root``, and
            neither equal to, inside, nor containing any main working tree of ``repos``.
        branch: ``handoff/<id>`` for a change item; ``None`` for a query item, whose
            worktree is detached.
        fetch: ``git -C <main> fetch --no-tags origin main``.
        ls_remote: ``git -C <main> ls-remote origin refs/heads/main``.
        rev_parse: ``git -C <main> rev-parse refs/remotes/origin/main``.
    """

    item_id: str
    repo: str
    mode: str
    main_tree: str
    worktree: str
    branch: str | None
    fetch: Command
    ls_remote: Command
    rev_parse: Command

    def worktree_add(self, base_sha: str) -> Command:
        """Build ``git worktree add`` from the SHA that ``ls-remote`` and ``rev-parse`` agreed on.

        A change item gets ``git -C <main> worktree add -b handoff/<id> <worktree> <sha>``.
        ``-b`` fails when the branch exists already, so an earlier run's branch is never
        reset. A query item gets ``git -C <main> worktree add --detach <worktree> <sha>``,
        which creates no branch.

        Args:
            base_sha: The commit to start from: 40 lowercase hexadecimal digits.

        Returns:
            The command.

        Raises:
            TypeError: ``base_sha`` is not a ``str``.
            CommandError: ``base_sha`` is not 40 lowercase hexadecimal digits (code
                ``base_sha``). An abbreviated SHA, a ref name or upper case is refused, so
                the worktree starts from exactly the commit that was compared.
        """
        if type(base_sha) is not str:
            raise TypeError(f"base_sha must be a str, not {type(base_sha).__name__}")
        if _SHA.fullmatch(base_sha) is None:
            raise CommandError(
                [CommandIssue("base_sha", f"must be 40 lowercase hexadecimal digits, got {_show(base_sha)}")]
            )
        if self.branch is None:
            return _git(self.main_tree, "worktree", "add", "--detach", self.worktree, base_sha)
        return _git(self.main_tree, "worktree", "add", "-b", self.branch, self.worktree, base_sha)

    def commands(self, base_sha: str) -> tuple[Command, ...]:
        """Return the four commands in the order they run, for a check or a report.

        Args:
            base_sha: As for :meth:`worktree_add`.

        Returns:
            ``(fetch, ls_remote, rev_parse, worktree_add(base_sha))``.

        Raises:
            TypeError: As for :meth:`worktree_add`.
            CommandError: As for :meth:`worktree_add`.
        """
        return (self.fetch, self.ls_remote, self.rev_parse, self.worktree_add(base_sha))


@dataclass(frozen=True, slots=True)
class KiroInvocation:
    """One ``kiro-cli`` run to start in an item's worktree.

    Attributes:
        command: The argv and, as the working directory, the item's worktree
            (Requirement 28.5).
        timeout_seconds: The checked ``timeout_seconds`` of the configuration. The runner
            stops the run after this many seconds (Requirement 28.7).
        agent: The agent configuration given with ``--agent``, or ``None`` when the argv
            has no ``--agent``.
    """

    command: Command
    timeout_seconds: int
    agent: str | None

    @property
    def argv(self) -> tuple[str, ...]:
        """The argv of :attr:`command`."""
        return self.command.argv

    @property
    def cwd(self) -> str:
        """The working directory of :attr:`command`: the item's worktree."""
        return self.command.cwd


@dataclass(frozen=True, slots=True)
class PublishApproval:
    """The maintainer's approval to publish one batch of handoff branches (Requirement 28.15).

    Attributes:
        approved_at: When the maintainer approved, in :data:`handoff.state.TIMESTAMP_FORMAT`
            (UTC, whole seconds, ``Z``).
        item_ids: The items listed at that time, in the order listed, each once. At least
            one. An approval covers these items and no other.
        approved_in: The record of this session that holds the approval: a path relative to
            this repository, in normal form, under :data:`handoff.manifest.APPROVAL_RECORD_DIR`.

    Raises:
        CommandError: A field does not have that form (code ``approval``), with every
            problem found.
    """

    approved_at: str
    item_ids: tuple[str, ...]
    approved_in: str

    def __post_init__(self) -> None:
        """Check the three fields."""
        problems: list[str] = []
        if not _is_timestamp(self.approved_at):
            problems.append(
                f"approved_at must be UTC in whole seconds, like 2026-11-10T00:00:00Z, got {_show(self.approved_at)}"
            )
        if type(self.item_ids) is not tuple or not self.item_ids:
            problems.append("item_ids must be a non-empty tuple of item IDs")
        else:
            seen: set[str] = set()
            for position, item_id in enumerate(self.item_ids):
                if type(item_id) is not str or not item_id.strip():
                    problems.append(f"item_ids[{position}] must be a non-blank string, got {_show(item_id)}")
                elif item_id in seen:
                    problems.append(f"item_ids[{position}] repeats {item_id}")
                else:
                    seen.add(item_id)
        problem = _record_path_problem(self.approved_in)
        if problem is not None:
            problems.append(f"approved_in {problem}")
        if problems:
            raise CommandError([CommandIssue("approval", text) for text in problems])


@dataclass(frozen=True, slots=True)
class PullRequestSpec:
    """What the runner prepared for one item's pull request.

    :func:`build_publish_plan` checks the fields and leaves the item out, with reason
    ``pull_request``, when one does not have its form.

    Attributes:
        github_repo: The repository for ``gh pr create --repo``, as ``OWNER/NAME``. The
            runner derives it from the ``origin`` remote of the target repository, so that
            the pull request is opened in the repository that the push goes to.
        title: The title, for ``--title``: one non-blank line, not starting with ``-``.
            ``gh pr create`` refuses to run without a title when it cannot prompt, as in a
            run without a terminal.
        body_file: The body, for ``--body-file``: an absolute path in normal form strictly
            below this repository's ``.private/handoff/``. The file is published as it is,
            so it is limited to the place where the harness writes its own files.
    """

    github_repo: str
    title: str
    body_file: str


@dataclass(frozen=True, slots=True)
class PublishStep:
    """The two commands that publish one item, run in this order.

    Attributes:
        item_id: The item's ID.
        repo: The item's target repository.
        branch: ``handoff/<id>``.
        push: ``git -C <worktree> push origin handoff/<id>``.
        pull_request: ``gh pr create --draft --base main --head handoff/<id> --title <title>
            --body-file <file> --repo <OWNER/NAME>``, in the worktree. ``--head`` keeps
            ``gh`` from pushing or forking on its own.
    """

    item_id: str
    repo: str
    branch: str
    push: Command
    pull_request: Command


@dataclass(frozen=True, slots=True)
class PublishExclusion:
    """An item that the plan leaves out, and why.

    Attributes:
        item_id: The item's ID.
        reason: One of :data:`ExclusionReason`.
        detail: An explanation for the maintainer, for local output.
    """

    item_id: str
    reason: ExclusionReason
    detail: str


@dataclass(frozen=True, slots=True)
class PublishPlan:
    """What one approval allows to publish.

    Attributes:
        approved_at: From the approval.
        approved_in: From the approval.
        steps: One step per approved item that can be published, in the order of the
            approval.
        excluded: Every other item: first the approved ones that cannot be published, in
            the order of the approval, then every item of the manifest or the status that
            the approval does not list, by ID.
    """

    approved_at: str
    approved_in: str
    steps: tuple[PublishStep, ...]
    excluded: tuple[PublishExclusion, ...]


@dataclass(frozen=True, slots=True)
class HandoffFiles:
    """Where the runner writes the files of one item, all strictly below ``.private/handoff/``.

    Attributes:
        status: ``<handoff_dir>/status.json``, the one status file of every item
            (Requirement 28.13). It does not depend on the item.
        report: ``<handoff_dir>/<repo>/<id>/report.md``, the item's Handoff_Report
            (Requirement 28.8).
        prompt: The item's Handoff_Prompt: ``<handoff_dir>/sync/<sync_point>-<repo>.md`` for
            the Sync_Points ``a`` to ``e``, and ``<handoff_dir>/<repo>.md`` for ``rollout``
            (design section 17). The name has no item ID, as in design section 17, so two
            items of one Sync_Point and one repository get the same path.
    """

    status: str
    report: str
    prompt: str


def build_git_plan(config: HandoffConfig, item: Item) -> GitPlan:
    """Build the git commands that create an item's worktree from ``origin/main``.

    Args:
        config: The configuration.
        item: A query or change item of the manifest.

    Returns:
        The plan. :meth:`GitPlan.worktree_add` builds the last command once the SHA is
        known.

    Raises:
        TypeError: ``config`` or ``item`` is not of its type.
        CommandError: The item's mode is unknown (``mode``), its repository is not in the
            configuration or has no usable main working tree (``repo``), its ID does not
            have the manifest's form (``item_id``), or the worktree path is not strictly
            below ``worktrees_root`` or overlaps a main working tree (``worktree``).
    """
    _require(config, HandoffConfig, "config")
    _require(item, Item, "item")
    issues: list[CommandIssue] = []
    mode = _mode(item, issues)
    location = _location(config, item, issues)
    if issues:
        raise CommandError(issues)
    main_tree, worktree = _present(location)
    return GitPlan(
        item_id=item.id,
        repo=item.repo,
        mode=_present(mode),
        main_tree=main_tree,
        worktree=worktree,
        branch=BRANCH_PREFIX + item.id if mode == "change" else None,
        fetch=_git(main_tree, "fetch", "--no-tags", REMOTE, BASE_BRANCH),
        ls_remote=_git(main_tree, "ls-remote", REMOTE, f"refs/heads/{BASE_BRANCH}"),
        rev_parse=_git(main_tree, "rev-parse", f"refs/remotes/{REMOTE}/{BASE_BRANCH}"),
    )


def build_kiro_argv(
    config: HandoffConfig,
    item: Item,
    prompt: str,
    *,
    home: str,
    selftest_result: str | None,
    approved_agents: Collection[str],
) -> KiroInvocation:
    """Build the ``kiro-cli`` run that hands one prompt to the target repository's Kiro.

    The argv is ``[<kiro_cli>, "chat", "--no-interactive", ("--agent", <name>)?,
    <trust option>, <prompt>]``:

    - ``<kiro_cli>`` is the configured path with ``~`` expanded. It must be absolute: with
      ``shell=False`` nothing expands ``~``, and a relative path would be resolved in the
      worktree, which the target repository's content fills.
    - ``--agent <name>`` only when the configuration names an agent for the item's mode
      and that name is in ``approved_agents``. Until the agent configurations are written
      and approved, no argv has ``--agent``.
    - The trust option is ``--trust-tools=<tools>``, the item's tools joined with commas,
      when ``trust_all`` is ``None``. With a ``trust_all`` approval it is
      ``--trust-all-tools`` alone: combining it with ``--trust-tools=`` has no recorded
      meaning, and ``-a`` is never built.
    - The prompt is the last element, as it is.

    Args:
        config: The configuration.
        item: The item to run.
        prompt: The rendered and scanned Handoff_Prompt.
        home: The absolute home directory, to expand ``~`` in ``kiro_cli``.
        selftest_result: ``result`` of the latest selftest in ``status.json``
            (:data:`handoff.evaluate.GUARDS_ACTIVE` or
            :data:`handoff.evaluate.UNCONFIRMED`), or ``None`` before the first selftest.
            Read for a change item only.
        approved_agents: The agent configuration names whose content the maintainer has
            approved. Empty until tasks 2.5 and 5.1 approve one.

    Returns:
        The invocation: argv, working directory (the worktree), timeout and agent.

    Raises:
        TypeError: An argument is not of its type, or ``approved_agents`` is one string.
        ValueError: ``home`` is not an absolute path.
        CommandError: With every problem found, and no argv: ``timeout_seconds`` or
            ``max_concurrency`` is not an integer of 1 or more (``bool`` is refused);
            ``kiro_cli`` is not absolute after ``~`` expansion; the item's mode,
            repository, ID or worktree path is unusable; the trusted tools are empty,
            repeated, not of the form ``[A-Za-z0-9_@][A-Za-z0-9_.:/@-]*`` (a comma would
            split one name in two, and ``*`` could read as a pattern), outside the ceiling
            of the mode, or other than ``fs_read`` alone for a query item; ``trust_all`` is
            set for a query item or lacks one of its three parts; a change item has no
            ``guards_active`` selftest (Requirement 28.17); the approved agent name does
            not have the form ``[A-Za-z0-9_][A-Za-z0-9_.-]*``; or the prompt is blank,
            starts with ``-`` (``kiro-cli`` could read it as an option), or holds NUL or a
            lone surrogate.
    """
    _require(config, HandoffConfig, "config")
    _require(item, Item, "item")
    if type(prompt) is not str:
        raise TypeError(f"prompt must be a str, not {type(prompt).__name__}")
    if type(home) is not str or not home.startswith("/"):
        raise ValueError(f"home must be an absolute path, got {_show(home)}")
    if selftest_result is not None and type(selftest_result) is not str:
        raise TypeError(f"selftest_result must be a str or None, not {type(selftest_result).__name__}")
    approved = _names(approved_agents, "approved_agents")

    issues: list[CommandIssue] = []
    timeout_seconds = _positive_int(config.timeout_seconds, "timeout_seconds", issues)
    _positive_int(config.max_concurrency, "max_concurrency", issues)
    program = _program(config.kiro_cli, home, issues)
    mode = _mode(item, issues)
    location = _location(config, item, issues)
    trust = _trust_options(config, item, mode, issues)
    agent = _agent(config, mode, approved, issues)
    if mode == "change" and selftest_result != GUARDS_ACTIVE:
        issues.append(CommandIssue("selftest", _selftest_detail(selftest_result)))
    _check_prompt(prompt, issues)
    if issues:
        raise CommandError(issues)

    _, worktree = _present(location)
    agent_options = () if agent is None else (AGENT_OPTION, agent)
    argv = (_present(program), *KIRO_CHAT, *agent_options, *trust, prompt)
    return KiroInvocation(Command(argv, worktree), _present(timeout_seconds), agent)


def build_publish_plan(
    config: HandoffConfig,
    manifest: Manifest,
    status: StatusDoc,
    approval: PublishApproval,
    *,
    pull_requests: Mapping[str, PullRequestSpec],
    handoff_dir: str,
) -> PublishPlan:
    """Build the push and pull-request commands that one approval allows.

    An approved item is published only when all of these hold, checked in this order;
    the first that fails is the reason it is left out:

    1. The manifest has it (``not_in_manifest``).
    2. It is a change item; a query item has no branch (``query_mode``).
    3. ``status.json`` has it (``no_status_record``) and it is ``succeeded``
       (``not_succeeded``).
    4. It succeeded at or before ``approved_at`` (``succeeded_after_approval``): the
       approval covers the branches as they were when it was given.
    5. ``published.pr`` of its record is ``null`` (``already_published``).
    6. ``pull_requests`` has a spec for it (``no_pull_request``) whose fields have their
       form (``pull_request``).
    7. Its worktree path can be built (``item``).

    Every item of the manifest or the status that the approval does not list is left out
    as ``not_approved``.

    Args:
        config: The configuration.
        manifest: The manifest.
        status: The status, which must pass :func:`handoff.state.check_status`.
        approval: The approval.
        pull_requests: The spec of each item's pull request, by item ID. Entries for items
            the plan does not publish are not read.
        handoff_dir: This repository's ``.private/handoff/`` directory, absolute and in
            normal form. Every body file must be strictly below it.

    Returns:
        The plan. It runs nothing; the runner runs each step's two commands in order, in
        the harness's own environment, not in :func:`child_env`.

    Raises:
        TypeError: An argument is not of its type.
        ValueError: ``handoff_dir`` is not an absolute path in normal form that ends with
            ``.private/handoff``.
        handoff.state.InvalidStatusError: ``status`` is not a status.
    """
    _require(config, HandoffConfig, "config")
    _require(manifest, Manifest, "manifest")
    _require(approval, PublishApproval, "approval")
    if not isinstance(pull_requests, Mapping):
        raise TypeError(f"pull_requests must be a mapping, not {type(pull_requests).__name__}")
    check_status(status)
    private_dir = _handoff_dir(handoff_dir)

    items = manifest.by_id
    records = status["items"]
    approved_moment = _moment(approval.approved_at)
    steps: list[PublishStep] = []
    excluded: list[PublishExclusion] = []
    for item_id in approval.item_ids:
        outcome = _publish_one(
            config, item_id, items.get(item_id), records.get(item_id), approved_moment, pull_requests, private_dir
        )
        if isinstance(outcome, PublishStep):
            steps.append(outcome)
        else:
            excluded.append(outcome)
    listed = set(approval.item_ids)
    for item_id in sorted((set(items) | set(records)) - listed):
        excluded.append(
            PublishExclusion(item_id, "not_approved", f"not listed in the approval in {approval.approved_in}")
        )
    return PublishPlan(
        approved_at=approval.approved_at,
        approved_in=approval.approved_in,
        steps=tuple(steps),
        excluded=tuple(excluded),
    )


def child_env(
    parent: Mapping[str, str],
    *,
    push_url: str,
    gh_config_dir: str,
    aws_empty_file: str,
) -> dict[str, str]:
    """Build the environment of a ``kiro-cli`` run: layer 3 of design section 20.

    The result is a copy of ``parent`` without the variables below, plus the overrides.

    Dropped, so that no credential or redirection of the parent reaches the run:

    - Every variable that starts with ``AWS_``. This covers the four named in tasks.md
      (``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``, ``AWS_SESSION_TOKEN``,
      ``AWS_PROFILE``) and the other ways an SDK finds credentials from the environment
      (``AWS_ROLE_ARN`` with ``AWS_WEB_IDENTITY_TOKEN_FILE``, the
      ``AWS_CONTAINER_CREDENTIALS_*`` and ``AWS_CONTAINER_AUTHORIZATION_TOKEN*``
      variables, ``AWS_DEFAULT_PROFILE``, ``AWS_SECURITY_TOKEN``), without listing them.
    - Every variable that starts with ``GH_`` or ``GITHUB_``: ``gh`` uses ``GH_TOKEN``,
      ``GITHUB_TOKEN``, ``GH_ENTERPRISE_TOKEN`` and ``GITHUB_ENTERPRISE_TOKEN`` before its
      stored credentials (``gh help environment``), so an empty ``GH_CONFIG_DIR`` alone
      would not leave it signed out. ``GH_REPO`` and ``GH_HOST`` go too.
    - Every variable that starts with ``GIT_``: ``GIT_DIR``, ``GIT_WORK_TREE``,
      ``GIT_INDEX_FILE``, ``GIT_COMMON_DIR`` and ``GIT_OBJECT_DIRECTORY`` would point the
      run's git at another repository (git sets some of them for its hooks), and
      ``GIT_CONFIG_PARAMETERS``, ``GIT_CONFIG_COUNT`` and its keys and values carry
      configuration. The parent's ``GIT_CONFIG_*`` entries are replaced, not merged: a
      later entry of the parent could set the push URL again. ``GIT_AUTHOR_*`` and
      ``GIT_COMMITTER_*`` go as well; commits take the identity from git configuration.
    - ``PWD`` and ``OLDPWD``, which would name the harness's directory instead of the
      worktree to a program that reads them.

    Overrides:

    - ``GIT_CONFIG_COUNT=2``, with ``remote.origin.pushurl`` set first to the empty string
      and then to ``push_url``. ``remote.<name>.pushurl`` can hold several URLs and a push
      goes to all of them; the empty string clears the URLs set before (git-config
      documentation). With only the second entry, a repository whose configuration
      already sets a push URL would still push there.
    - ``GH_CONFIG_DIR=<gh_config_dir>``.
    - ``AWS_CONFIG_FILE`` and ``AWS_SHARED_CREDENTIALS_FILE`` both set to
      ``aws_empty_file``, and ``AWS_EC2_METADATA_DISABLED=true``.

    This module creates no file. The runner creates ``gh_config_dir`` as an empty
    directory and ``aws_empty_file`` as an empty file, and makes sure that nothing exists
    at ``push_url``, for example as three entries of one new temporary directory.

    Limits. The environment cannot stop a push to another remote or to a URL given on the
    command line, a credential that ``gh`` or git reads from the system keyring or from a
    file (``~/.ssh``), or a tool whose server holds its own token. Selftest trials T2 and T3
    measure what this layer stops; what it does not stop is left to the other layers of
    design section 20.

    Args:
        parent: The parent's environment (``os.environ`` in the runner).
        push_url: A path where nothing exists, for ``remote.origin.pushurl``.
        gh_config_dir: An empty directory, for ``GH_CONFIG_DIR``.
        aws_empty_file: An empty file, for ``AWS_CONFIG_FILE`` and
            ``AWS_SHARED_CREDENTIALS_FILE``.

    Returns:
        A new dictionary. ``parent`` is not changed.

    Raises:
        TypeError: ``parent`` is not a mapping, or holds a key or value that is not a
            ``str``, or a path is not a ``str``.
        ValueError: A key of ``parent`` is empty or holds ``=`` or NUL, a value holds NUL,
            a path is not absolute and in normal form, or two of the paths overlap.
    """
    if not isinstance(parent, Mapping):
        raise TypeError(f"parent must be a mapping, not {type(parent).__name__}")
    for key, value in parent.items():
        if type(key) is not str or type(value) is not str:
            raise TypeError(f"the environment holds a key or value that is not a str: {_show(key)}")
        if not key or "=" in key or "\x00" in key:
            raise ValueError(f"the environment holds an invalid name: {_show(key)}")
        if "\x00" in value:
            raise ValueError(f"the value of {key} holds NUL")
    paths = {"push_url": push_url, "gh_config_dir": gh_config_dir, "aws_empty_file": aws_empty_file}
    for name, path in paths.items():
        if type(path) is not str:
            raise TypeError(f"{name} must be a str, not {type(path).__name__}")
        if not _is_normal_absolute(path):
            raise ValueError(f"{name} must be an absolute path in normal form, got {_show(path)}")
    for (first, a), (second, b) in combinations(paths.items(), 2):
        if overlaps(a, b):
            raise ValueError(f"{first} and {second} overlap; give three separate paths")

    env = {
        key: value
        for key, value in parent.items()
        if not key.startswith(DROPPED_ENV_PREFIXES) and key not in DROPPED_ENV_NAMES
    }
    env.update(
        {
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": PUSH_URL_KEY,
            "GIT_CONFIG_VALUE_0": "",
            "GIT_CONFIG_KEY_1": PUSH_URL_KEY,
            "GIT_CONFIG_VALUE_1": push_url,
            "GH_CONFIG_DIR": gh_config_dir,
            "AWS_CONFIG_FILE": aws_empty_file,
            "AWS_SHARED_CREDENTIALS_FILE": aws_empty_file,
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    return env


def handoff_files(handoff_dir: str, *, repo: str, item_id: str, sync_point: str) -> HandoffFiles:
    """Build the paths of an item's Handoff_Prompt and Handoff_Report, and of the status file.

    Requirement 28.22 keeps the three in this repository's ``.private/``, and the layout of
    design sections 17 and 20 puts them in ``.private/handoff/``. ``repo`` and ``item_id``
    must have the forms that :func:`handoff.manifest.parse_manifest` and
    :func:`build_git_plan` require, which make each one path component that is not ``.`` or
    ``..``, and ``sync_point`` must be one of :data:`handoff.manifest.SYNC_POINTS`. So every
    path has ``handoff_dir`` and at least one more component, in normal form. Nothing is
    created or read.

    Args:
        handoff_dir: This repository's ``.private/handoff/`` directory, absolute and in
            normal form, as for :func:`build_publish_plan`.
        repo: The item's target repository.
        item_id: The item's ID.
        sync_point: The item's Sync_Point.

    Returns:
        The three paths.

    Raises:
        TypeError: ``handoff_dir`` is not a ``str``.
        ValueError: ``handoff_dir`` is not an absolute path in normal form that ends with
            ``.private/handoff``.
        CommandError: With every problem found: ``repo`` or ``item_id`` does not have its
            form (codes ``repo`` and ``item_id``, as for :func:`build_git_plan`), or
            ``sync_point`` is not a Sync_Point (code ``sync_point``).
    """
    directory = _handoff_dir(handoff_dir)
    issues = [issue for issue in (_repo_issue(repo), _item_id_issue(item_id)) if issue is not None]
    if type(sync_point) is not str or sync_point not in SYNC_POINTS:
        issues.append(CommandIssue("sync_point", f"must be one of {', '.join(SYNC_POINTS)}, got {_show(sync_point)}"))
    if issues:
        raise CommandError(issues)
    if sync_point == ROLLOUT_SYNC_POINT:
        prompt = posixpath.join(directory, f"{repo}.md")
    else:
        prompt = posixpath.join(directory, SYNC_PROMPT_DIR, f"{sync_point}-{repo}.md")
    return HandoffFiles(
        status=posixpath.join(directory, STATUS_FILE),
        report=posixpath.join(directory, repo, item_id, REPORT_FILE),
        prompt=prompt,
    )


def _publish_one(
    config: HandoffConfig,
    item_id: str,
    item: Item | None,
    record: Mapping[str, Any] | None,
    approved_moment: datetime,
    pull_requests: Mapping[str, PullRequestSpec],
    private_dir: str,
) -> PublishStep | PublishExclusion:
    """Decide one approved item: its publish step, or why it is left out.

    Args:
        config: The configuration.
        item_id: An ID listed by the approval.
        item: The manifest's item with that ID, or ``None``.
        record: The status record of that ID, or ``None``.
        approved_moment: The approval time.
        pull_requests: The pull-request specs by item ID.
        private_dir: The checked ``handoff_dir``.

    Returns:
        The step, or the exclusion with the first reason of :func:`build_publish_plan`.
    """
    if item is None:
        return PublishExclusion(item_id, "not_in_manifest", "the approval lists it, but the manifest has no such item")
    if item.mode != "change":
        return PublishExclusion(item_id, "query_mode", "a query item creates no branch, so there is nothing to push")
    if record is None:
        return PublishExclusion(item_id, "no_status_record", "status.json has no record of it")
    if record["state"] != SUCCEEDED:
        return PublishExclusion(item_id, "not_succeeded", f"its state is {record['state']}, not {SUCCEEDED}")
    succeeded_at = record["history"][-1]["at"]
    if _moment(succeeded_at) > approved_moment:
        return PublishExclusion(
            item_id,
            "succeeded_after_approval",
            f"it succeeded at {succeeded_at}, after the approval; approve its branch as it is now",
        )
    if record["published"].get("pr") is not None:
        return PublishExclusion(item_id, "already_published", f"published.pr is {_show(record['published']['pr'])}")
    spec = pull_requests.get(item_id)
    if spec is None:
        return PublishExclusion(item_id, "no_pull_request", "pull_requests has no spec for it")
    problems = _pull_request_problems(spec, private_dir)
    if problems:
        return PublishExclusion(item_id, "pull_request", "; ".join(problems))
    issues: list[CommandIssue] = []
    location = _location(config, item, issues)
    if location is None:
        return PublishExclusion(item_id, "item", "; ".join(str(issue) for issue in issues))
    _, worktree = location
    branch = BRANCH_PREFIX + item.id
    pull_request = Command(
        (
            "gh",
            "pr",
            "create",
            "--draft",
            "--base",
            BASE_BRANCH,
            "--head",
            branch,
            "--title",
            spec.title,
            "--body-file",
            spec.body_file,
            "--repo",
            spec.github_repo,
        ),
        worktree,
    )
    return PublishStep(item.id, item.repo, branch, _git(worktree, "push", REMOTE, branch), pull_request)


def _pull_request_problems(spec: object, private_dir: str) -> list[str]:
    """List what keeps a pull-request spec from being used. Empty when it can be used."""
    if not isinstance(spec, PullRequestSpec):
        return [f"the spec must be a PullRequestSpec, not {type(spec).__name__}"]
    problems: list[str] = []
    repo = spec.github_repo
    if type(repo) is not str or _GITHUB_REPO.fullmatch(repo) is None or repo.split("/")[1] in (".", ".."):
        problems.append(f"github_repo must be OWNER/NAME, got {_show(repo)}")
    title = spec.title
    if type(title) is not str or not title.strip() or title.splitlines() != [title] or "\x00" in title:
        problems.append("title must be one non-blank line without NUL")
    elif title.startswith("-") or not _encodable(title):
        problems.append("title must not start with '-' or hold a lone surrogate")
    body = spec.body_file
    if type(body) is not str or not _is_normal_absolute(body):
        problems.append(f"body_file must be an absolute path in normal form, got {_show(body)}")
    elif not is_within(body, private_dir) or is_within(private_dir, body):
        problems.append(f"body_file must be strictly below {private_dir}")
    return problems


def _handoff_dir(path: object) -> str:
    """Check ``handoff_dir``: absolute, in normal form, ending with ``.private/handoff``."""
    if type(path) is not str:
        raise TypeError(f"handoff_dir must be a str, not {type(path).__name__}")
    if not _is_normal_absolute(path) or posixpath.basename(path) != "handoff":
        raise ValueError(f"handoff_dir must be this repository's .private/handoff, got {_show(path)}")
    if posixpath.basename(posixpath.dirname(path)) != ".private":
        raise ValueError(f"handoff_dir must be this repository's .private/handoff, got {_show(path)}")
    return path


def _location(config: HandoffConfig, item: Item, issues: list[CommandIssue]) -> tuple[str, str] | None:
    """Find the item's main working tree and build its worktree path.

    The repository and the ID must be single path components of the manifest's forms, so
    the path ``<worktrees_root>/<repo>/<id>`` has exactly two components below
    ``worktrees_root``. The path is then checked: strictly below ``worktrees_root``, and
    neither equal to, inside, nor containing a main working tree of ``repos``. The
    comparison is lexical and ignores letter case and Unicode normalization
    (:func:`handoff.config.is_within`); symbolic links are not followed.

    Args:
        config: The configuration.
        item: The item.
        issues: Where problems are recorded.

    Returns:
        ``(main_tree, worktree)``, or ``None`` when a problem was recorded.
    """
    before = len(issues)
    root = config.worktrees_root
    if not _is_normal_absolute(root):
        issues.append(
            CommandIssue("worktree", f"worktrees_root must be an absolute path in normal form, got {_show(root)}")
        )
    main_trees: dict[str, str] = {}
    for name, repo_config in sorted(config.repos.items()):
        tree = getattr(repo_config, "main_tree", None)
        if isinstance(tree, str) and _is_normal_absolute(tree):
            main_trees[name] = tree
        else:
            issues.append(
                CommandIssue(
                    "repo", f"repos.{name}.main_tree must be an absolute path in normal form, got {_show(tree)}"
                )
            )
    repo = item.repo
    repo_issue = _repo_issue(repo)
    if repo_issue is not None:
        issues.append(repo_issue)
    elif repo not in config.repos:
        issues.append(CommandIssue("repo", f"{repo} is not in repos of config.json"))
    item_id = item.id
    item_id_issue = _item_id_issue(item_id)
    if item_id_issue is not None:
        issues.append(item_id_issue)
    if len(issues) > before:
        return None

    worktree = posixpath.join(root, repo, item_id)
    if not is_within(worktree, root) or is_within(root, worktree):
        issues.append(CommandIssue("worktree", f"{worktree} is not strictly below worktrees_root {root}"))
    for name, tree in main_trees.items():
        if overlaps(worktree, tree):
            issues.append(CommandIssue("worktree", f"{worktree} overlaps the main working tree of {name} ({tree})"))
    if len(issues) > before:
        return None
    return main_trees[repo], worktree


def _repo_issue(repo: object) -> CommandIssue | None:
    """Check that a repository name is one path component of the manifest's form, not ``.`` or ``..``."""
    if type(repo) is not str or repo in (".", "..") or _REPO.fullmatch(repo) is None:
        return CommandIssue(
            "repo", f"must be one path component of ASCII letters, digits, '.', '_', '-', got {_show(repo)}"
        )
    return None


def _item_id_issue(item_id: object) -> CommandIssue | None:
    """Check that an item ID has the manifest's form, which makes it one path component."""
    if type(item_id) is not str or len(item_id) > MAX_ID_LENGTH or _ITEM_ID.fullmatch(item_id) is None:
        return CommandIssue(
            "item_id",
            f"must be lowercase ASCII letters and digits in groups joined by single hyphens, at most {MAX_ID_LENGTH} "
            f"characters, got {_show(item_id)}",
        )
    return None


def _mode(item: Item, issues: list[CommandIssue]) -> str | None:
    """Check the item's mode: one of :data:`handoff.config.MODES`."""
    if type(item.mode) is not str or item.mode not in MODES:
        issues.append(CommandIssue("mode", f"must be one of {', '.join(MODES)}, got {_show(item.mode)}"))
        return None
    return item.mode


def _trust_options(config: HandoffConfig, item: Item, mode: str | None, issues: list[CommandIssue]) -> tuple[str, ...]:
    """Check the trusted tools and ``trust_all``, and build the trust option.

    Returns:
        ``(TRUST_ALL_OPTION,)`` for an approved ``trust_all``, otherwise
        ``(TRUST_TOOLS_OPTION + <tools joined with commas>,)``. Empty when a problem was
        recorded.
    """
    before = len(issues)
    tools = item.trust_tools
    if type(tools) is not tuple or not tools or not all(type(tool) is str for tool in tools):
        issues.append(
            CommandIssue("trust_tools", "must be a non-empty tuple of tool names: with none, kiro-cli trusts nothing")
        )
        tools = ()
    for tool in tools:
        if _TOOL.fullmatch(tool) is None:
            issues.append(
                CommandIssue(
                    "trust_tools",
                    f"{_show(tool)} is not of the form [A-Za-z0-9_@][A-Za-z0-9_.:/@-]*: the names are joined with ',' "
                    "into one value, and '*' or '?' could read as a pattern",
                )
            )
    if len(set(tools)) != len(tools):
        issues.append(CommandIssue("trust_tools", "names a tool more than once"))
    if mode is not None and tools:
        ceiling = config.mode_tool_ceiling.get(mode)
        if type(ceiling) is not tuple or not all(type(tool) is str for tool in ceiling):
            issues.append(CommandIssue("trust_tools", f"mode_tool_ceiling.{mode} must be a tuple of tool names"))
        else:
            outside = [tool for tool in tools if tool not in ceiling]
            if outside:
                issues.append(
                    CommandIssue(
                        "trust_tools",
                        f"{', '.join(outside)} not in mode_tool_ceiling.{mode} ({', '.join(ceiling)})",
                    )
                )
        if mode == "query" and tools != QUERY_TOOL_CEILING:
            issues.append(CommandIssue("trust_tools", f"a query item trusts fs_read only, got {', '.join(tools)}"))

    trust_all = item.trust_all
    if trust_all is not None:
        if not isinstance(trust_all, TrustAll):
            issues.append(CommandIssue("trust_all", f"must be None or a TrustAll, not {type(trust_all).__name__}"))
        elif mode == "query":
            issues.append(CommandIssue("trust_all", "must be None for a query item, which trusts fs_read only"))
        else:
            missing = [
                name for name in ("reason", "approved_at", "approved_in") if not _is_line(getattr(trust_all, name))
            ]
            if missing:
                issues.append(CommandIssue("trust_all", f"lacks {', '.join(missing)}; all three are required"))
    if len(issues) > before:
        return ()
    if trust_all is not None:
        return (TRUST_ALL_OPTION,)
    return (TRUST_TOOLS_OPTION + ",".join(tools),)


def _agent(config: HandoffConfig, mode: str | None, approved: frozenset[str], issues: list[CommandIssue]) -> str | None:
    """Return the agent for ``--agent``: the mode's configured agent when it is approved."""
    if mode is None:
        return None
    name = config.agents.get(mode)
    if type(name) is not str or name not in approved:
        return None
    if _AGENT.fullmatch(name) is None:
        issues.append(CommandIssue("agent", f"{_show(name)} is not of the form [A-Za-z0-9_][A-Za-z0-9_.-]*"))
        return None
    return name


def _program(kiro_cli: object, home: str, issues: list[CommandIssue]) -> str | None:
    """Expand ``~`` in ``kiro_cli`` and require an absolute path."""
    if type(kiro_cli) is not str or not kiro_cli.strip() or "\x00" in kiro_cli:
        issues.append(CommandIssue("kiro_cli", f"must be a non-empty path, got {_show(kiro_cli)}"))
        return None
    try:
        return normalize_path(kiro_cli, home)
    except ValueError as exc:
        issues.append(
            CommandIssue(
                "kiro_cli",
                f"{exc}; a bare name is looked up in PATH and a relative path in the worktree, so give an absolute path",
            )
        )
        return None


def _positive_int(
    value: object, key: Literal["timeout_seconds", "max_concurrency"], issues: list[CommandIssue]
) -> int | None:
    """Check an integer of 1 or more. ``bool`` is refused although it is an ``int``."""
    if type(value) is not int or value < 1:
        issues.append(CommandIssue(key, f"must be an integer of 1 or more, got {_show(value)}"))
        return None
    return value


def _selftest_detail(result: str | None) -> str:
    """Explain why a change item may not run without a ``guards_active`` selftest."""
    if result is None:
        return "no selftest has run; a change item needs guards_active (Requirement 28.17)"
    if result == UNCONFIRMED:
        return "the latest selftest did not confirm the guards; a change item needs guards_active (Requirement 28.17)"
    return f"unknown selftest result {_show(result)}; a change item needs guards_active (Requirement 28.17)"


def _check_prompt(prompt: str, issues: list[CommandIssue]) -> None:
    """Check that the prompt can be the last argv element."""
    if not prompt.strip():
        issues.append(CommandIssue("prompt", "is blank"))
        return
    if prompt.startswith("-"):
        issues.append(CommandIssue("prompt", "starts with '-', which kiro-cli could read as an option"))
    if "\x00" in prompt:
        issues.append(CommandIssue("prompt", "holds NUL, which no process can receive"))
    if not _encodable(prompt):
        issues.append(CommandIssue("prompt", "holds a lone surrogate, which does not encode as UTF-8"))


def _git(directory: str, *args: str) -> Command:
    """Build ``git -C <directory> <args>`` to run in ``directory``.

    Raises:
        AssertionError: An argument is one of :data:`FORBIDDEN_GIT_WORDS`, starts with
            ``--force``, or is a forced refspec. The builders of this module never pass
            one, so this signals a fault in this module.
    """
    forbidden = [arg for arg in args if arg in FORBIDDEN_GIT_WORDS or arg.startswith(("--force", "+"))]
    if forbidden:
        raise AssertionError(f"a git argv built here must not hold {forbidden!r}")
    return Command(("git", "-C", directory, *args), directory)


def _names(values: Collection[str], name: str) -> frozenset[str]:
    """Copy a collection of names, refusing one string, which would be read as its characters."""
    if isinstance(values, (str, bytes)) or not isinstance(values, Collection):
        raise TypeError(f"{name} must be a collection of names, not {type(values).__name__}")
    names = frozenset(values)
    if not all(type(value) is str for value in names):
        raise TypeError(f"every element of {name} must be a str")
    return names


def _require(value: object, kind: type, name: str) -> None:
    """Raise ``TypeError`` unless ``value`` is a ``kind``."""
    if not isinstance(value, kind):
        raise TypeError(f"{name} must be a {kind.__name__}, not {type(value).__name__}")


def _is_normal_absolute(path: object) -> bool:
    """Whether a value is an absolute path in normal form: one line, no NUL, no ``.``, ``..`` or ``//``."""
    if type(path) is not str or not path.startswith("/") or "\x00" in path or path.splitlines() != [path]:
        return False
    return "/" + posixpath.normpath(path).lstrip("/") == path


def _record_path_problem(path: object) -> str | None:
    """Tell what keeps a value from being a record path under ``.private/``, or ``None``."""
    if type(path) is not str or not path.strip() or "\x00" in path or path.splitlines() != [path]:
        return "must be one non-blank line without NUL"
    if path.startswith(("/", "~")) or any(part in ("", ".", "..") for part in path.split("/")):
        return "must be a relative path in normal form"
    if not path.startswith(APPROVAL_RECORD_DIR):
        return f"must be a record of this session under {APPROVAL_RECORD_DIR}"
    return None


def _is_timestamp(value: object) -> bool:
    """Whether a value is a moment written exactly as :func:`handoff.state.format_timestamp` writes it."""
    if type(value) is not str or _TIMESTAMP_SHAPE.fullmatch(value) is None:
        return False
    try:
        moment = datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return format_timestamp(moment) == value


def _moment(value: str) -> datetime:
    """Read a timestamp that has passed :func:`_is_timestamp` or :func:`handoff.state.check_status`."""
    return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


def _is_line(value: object) -> bool:
    """Whether a value is one non-blank line without NUL."""
    return type(value) is str and bool(value.strip()) and "\x00" not in value and value.splitlines() == [value]


def _encodable(text: str) -> bool:
    """Whether a string encodes as UTF-8, that is, holds no lone surrogate."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _present(value: _T | None) -> _T:
    """Return a checked value. Every check that gives ``None`` has recorded an issue."""
    if value is None:
        raise AssertionError("a check rejected a value without recording an issue")
    return value


def _show(value: object) -> str:
    """``repr`` of a value for an issue detail, cut to 60 characters."""
    try:
        text = repr(value)
    except Exception:  # a value whose repr fails: name the type instead
        return f"<{type(value).__name__}>"
    return text if len(text) <= 60 else text[:57] + "..."

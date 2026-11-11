"""pytest setup for the tests in ``scripts/tests/``.

Puts ``scripts/`` on ``sys.path`` so that the tests can import the Handoff_Harness
package by name, as ``handoff``. The import convention is in the docstring of
``scripts/handoff/__init__.py``.

The tests that were here before this file load the script under test by file path
(``importlib.util.spec_from_file_location``) or run it as a child process. Neither
consults this ``sys.path``, so this file does not change how they load. Only the pytest
process is affected: the environment handed to child processes, ``PYTHONPATH``
included, is left as it was.

Handoff_Harness sandbox. The ``handoff_sandbox`` fixture builds, in a new temporary
directory, the places that the harness works with: a bare repository in the role of the
remote, a clone of it in the role of a target repository's main working tree (with
uncommitted changes of another session), the worktree and session directories, the
harness's ``.private/handoff/``, and a copy of the fake ``kiro-cli``
(``fixtures/handoff/fake-kiro-cli``). :class:`HandoffSandbox` describes the layout. The
remote's first commit is built once per session (``handoff_sandbox_seed``) and copied into
each sandbox, which then clones it. The fixture leaves ``os.environ`` alone; a test of code
that reads it calls :meth:`HandoffSandbox.apply_environ`. Tests reach everything through
the fixtures and name the class only under ``typing.TYPE_CHECKING``
(``from conftest import HandoffSandbox``): a conftest outside a package is imported under
the bare name ``conftest``, which another directory's conftest can also claim, so no test
imports it at run time.

The sandbox is made with ``tempfile.mkdtemp`` rather than pytest's ``tmp_path``: the path of
``tmp_path`` holds the user name (``pytest-of-<user>``), and the fake ``kiro-cli`` writes its
argv and working directory to its record.

Git in the sandbox does not read this machine's configuration. The sandbox's own git
commands run with ``HOME`` and ``XDG_CONFIG_HOME`` in the sandbox, ``GIT_CONFIG_GLOBAL`` set
to an empty file and ``GIT_CONFIG_NOSYSTEM=1``. ``handoff.command.child_env`` drops every
``GIT_*`` variable, so a child such as the fake ``kiro-cli`` reads the system configuration
again; it is kept from the global one by the sandbox ``HOME`` that
:meth:`HandoffSandbox.environ` passes on. The repositories' own ``.git/config``, which their
worktrees share, also sets ``core.hooksPath`` to an empty directory, a made-up
``user.name`` and ``user.email``, and ``commit.gpgSign=false``, so that a commit works and
runs no hook even in an environment that still reads the global configuration (a global
``core.hooksPath`` hook once refused a commit in a temporary repository).
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any

import pytest

_SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent)

if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

#: The fake ``kiro-cli`` (tracked with its executable bit).
FAKE_KIRO_CLI = Path(__file__).resolve().parent / "fixtures" / "handoff" / "fake-kiro-cli"

#: Name of the sandbox's target repository, as ``repos`` of ``config.json`` and the manifest
#: would name it.
SANDBOX_REPO = "example-hub"

#: Committer of the sandbox repositories.
SANDBOX_USER_NAME = "handoff-sandbox"
SANDBOX_USER_EMAIL = "handoff-sandbox@example.com"

#: Prefixes of the variables of this process that the sandbox environment does not inherit:
#: git's own (``GIT_DIR`` set by a hook would point git elsewhere), the fake's, and every
#: credential that ``child_env`` would drop anyway.
SANDBOX_DROPPED_PREFIXES = ("GIT_", "FAKE_KIRO_", "AWS_", "GH_", "GITHUB_")

#: The files of the first commit.
_SEED_FILES = (
    ("README.md", "# example-hub\n\nThe target repository of the Handoff_Harness sandbox.\n"),
    ("AGENTS.md", "# AGENTS.md of the example-hub sandbox\n\nNothing to follow here.\n"),
    ("docs/guide.md", "# Guide\n\nA tracked file that the main working tree changes and stages.\n"),
)

#: The uncommitted changes in the main working tree: ``git status --porcelain=v1`` codes and
#: paths. One unstaged change, one staged change, and two untracked files, one with a name
#: that is not ASCII. Each untracked file sits where ``git status`` lists the file itself,
#: not its directory.
MAIN_TREE_DIRTY = (
    (" M", "README.md"),
    ("M ", "docs/guide.md"),
    ("??", "docs/draft.md"),
    ("??", "メモ.txt"),
)


@dataclass(frozen=True)
class MainTreeState:
    """The state of the main working tree that a run must leave as it found it (Requirement 28.6).

    Two states are equal only when every field is: the same ``HEAD`` and branch, the same
    ``git status``, index entries, staged and unstaged diffs, and the same bytes in every
    path that ``git status`` lists.

    Attributes:
        head: ``git rev-parse HEAD``.
        branch: ``git branch --show-current``; empty on a detached ``HEAD``.
        status: ``git status --porcelain=v1 -z --untracked-files=all``.
        index: ``git ls-files --stage -z``.
        staged: ``git diff --cached --binary``.
        unstaged: ``git diff --binary``.
        files: ``(path, bytes)`` for each path in ``status``, sorted; ``None`` for a path
            that is not a regular file.
    """

    head: str
    branch: str
    status: bytes
    index: bytes
    staged: bytes
    unstaged: bytes
    files: tuple[tuple[str, bytes | None], ...]


@dataclass(frozen=True)
class HandoffSandbox:
    """A throwaway layout for the Handoff_Harness tests. Every path is absolute and resolved.

    The layout under ``root``::

        home/                                HOME of the sandbox
          .config/                           XDG_CONFIG_HOME (empty)
          .local/bin/kiro-cli                a copy of the fake kiro-cli, with its mode
          Projects/
            example-hub/                     main working tree: a clone of the bare repository
            example-harness/.private/handoff this repository's main working tree and handoff_dir
            .handoff-worktrees/              worktrees_root (empty)
            .kiro-worktrees/                 the IDE sessions' worktree directory (empty)
        remote/example-hub.git               bare repository, the remote ``origin``
        git/hooks/                           core.hooksPath of the repositories (empty)
        git/global-config                    GIT_CONFIG_GLOBAL of the sandbox's own git (empty)
        records/fake-kiro-cli.jsonl          the fake kiro-cli's record (made by its first run)

    With ``home`` as the home directory, a configuration can say ``~/.local/bin/kiro-cli``,
    ``~/Projects/.handoff-worktrees`` and ``~/Projects/example-hub`` as the real one does,
    and ``handoff.prompt.render`` can write those paths as ``~/...``.

    Attributes:
        root: The temporary directory that holds everything.
        home: The sandbox home directory.
        repo: The target repository's name, :data:`SANDBOX_REPO`.
        bare: The bare repository. ``main`` holds one commit, ``base_sha``.
        main_tree: The clone: on ``main`` at ``base_sha``, ``origin`` is ``bare``, with the
            changes of ``main_tree_dirty`` uncommitted.
        main_tree_dirty: The ``(code, path)`` entries of ``git status`` in ``main_tree``.
        harness_tree: The role of this repository's main working tree, a plain directory
            (for ``extra_main_trees`` of ``handoff.config.parse_config``).
        handoff_dir: ``harness_tree/.private/handoff``, empty.
        worktrees_root: The harness's worktree directory, empty.
        session_worktrees: The IDE sessions' worktree directory, empty (for
            ``session_worktrees_dir``).
        kiro_cli: The copy of the fake ``kiro-cli``.
        record: Where the fake ``kiro-cli`` appends its events.
        hooks_dir: The empty directory that ``core.hooksPath`` names.
        base_sha: The commit on ``main``.
        git_env: The environment of the sandbox's own git commands.
    """

    root: Path
    home: Path
    repo: str
    bare: Path
    main_tree: Path
    main_tree_dirty: tuple[tuple[str, str], ...]
    harness_tree: Path
    handoff_dir: Path
    worktrees_root: Path
    session_worktrees: Path
    kiro_cli: Path
    record: Path
    hooks_dir: Path
    base_sha: str
    git_env: Mapping[str, str] = field(repr=False)

    def git(self, *args: str, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        """Run git with the sandbox's environment.

        Args:
            *args: The arguments after ``git``.
            cwd: The working directory, ``root`` by default.
            check: Raise when git exits with a code other than 0.

        Returns:
            The completed process, with standard output and standard error as bytes.

        Raises:
            AssertionError: ``check`` is true and git failed; the message holds its
                standard error.
        """
        return _run_git(self.git_env, *args, cwd=cwd or self.root, check=check)

    def environ(self, **extra: str) -> dict[str, str]:
        """Return an environment for a process that a test starts.

        This process's environment without the variables of
        :data:`SANDBOX_DROPPED_PREFIXES`, with the sandbox ``HOME``, ``XDG_CONFIG_HOME`` and git
        configuration variables, ``FAKE_KIRO_RECORD`` set to ``record``, and ``extra``. Pass
        it to the fake ``kiro-cli`` as it is for a run without layer 3, or as ``parent`` of
        ``handoff.command.child_env`` for a run with it.

        Args:
            **extra: More variables, for example ``FAKE_KIRO_MODE`` or made-up credentials.

        Returns:
            A new dictionary.
        """
        return {**self.git_env, "FAKE_KIRO_RECORD": str(self.record), **extra}

    def apply_environ(self, monkeypatch: pytest.MonkeyPatch, **extra: str) -> None:
        """Make ``os.environ`` equal to :meth:`environ` for the rest of the test.

        For tests of code that reads ``os.environ``, such as the runner, which hands it to
        ``child_env``. ``monkeypatch`` restores the environment after the test.

        Args:
            monkeypatch: The test's ``monkeypatch`` fixture.
            **extra: As for :meth:`environ`.
        """
        wanted = self.environ(**extra)
        for name in list(os.environ):
            if name not in wanted:
                monkeypatch.delenv(name)
        for name, value in wanted.items():
            monkeypatch.setenv(name, value)

    def child_env_paths(self) -> dict[str, str]:
        """Create the temporary paths that ``handoff.command.child_env`` takes, as the runner does.

        Each call makes a new directory under ``root`` with an empty ``gh/`` directory and an
        empty ``aws-empty`` file, and names ``no-such-remote`` in it without creating it.

        Returns:
            ``push_url``, ``gh_config_dir`` and ``aws_empty_file``, ready to pass as keyword
            arguments to ``child_env``.
        """
        base = Path(tempfile.mkdtemp(prefix="child-", dir=self.root))
        (base / "gh").mkdir()
        (base / "aws-empty").write_bytes(b"")
        return {
            "push_url": str(base / "no-such-remote"),
            "gh_config_dir": str(base / "gh"),
            "aws_empty_file": str(base / "aws-empty"),
        }

    def records(self) -> list[dict[str, Any]]:
        """Return the events in the fake ``kiro-cli``'s record, in order; ``[]`` before its first run.

        A last line without its newline is one that a running fake is still writing, and is
        left out.
        """
        if not self.record.exists():
            return []
        lines = self.record.read_text(encoding="ascii").split("\n")
        return [json.loads(line) for line in lines[:-1]]

    def invocations(self) -> list[dict[str, dict[str, Any]]]:
        """Group the record's events by run.

        Returns:
            One dictionary per ``start`` event, in order, mapping each event name of the run
            (``start``, ``spawned``, ``end``) to the event. A run that was killed has no
            ``end``.
        """
        runs: list[dict[str, dict[str, Any]]] = []
        latest: dict[int, dict[str, dict[str, Any]]] = {}
        for event in self.records():
            if event["event"] == "start":
                run = {"start": event}
                runs.append(run)
                latest[event["pid"]] = run
            else:
                latest[event["pid"]][event["event"]] = event
        return runs

    def snapshot_main_tree(self) -> MainTreeState:
        """Read the state of the main working tree without changing it.

        Every git command runs with ``--no-optional-locks``, so that ``git status`` does not
        rewrite the index.

        Returns:
            The state, to compare before and after a run.
        """

        def read(*args: str) -> bytes:
            return self.git("--no-optional-locks", "-C", str(self.main_tree), *args).stdout

        status = read("status", "--porcelain=v1", "-z", "--untracked-files=all")
        files = []
        for path in sorted(_status_paths(status)):
            target = self.main_tree / path
            files.append((path, target.read_bytes() if target.is_file() and not target.is_symlink() else None))
        return MainTreeState(
            head=read("rev-parse", "HEAD").decode("ascii").strip(),
            branch=read("branch", "--show-current").decode("utf-8").strip(),
            status=status,
            index=read("ls-files", "--stage", "-z"),
            staged=read("diff", "--cached", "--binary"),
            unstaged=read("diff", "--binary"),
            files=tuple(files),
        )

    @staticmethod
    def process_running(pid: int) -> bool:
        """Say whether a process exists and is not a zombie.

        A killed child of a dead parent stays a zombie until the init process reaps it;
        it runs nothing, so it does not count as left behind.

        Args:
            pid: The process ID.

        Returns:
            ``True`` while the process exists in a state other than zombie.
        """
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        if Path("/proc/self/stat").exists():
            try:
                stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
            except FileNotFoundError:
                return False
            fields = stat.rpartition(")")[2].split()
            return bool(fields) and fields[0] not in ("Z", "X")
        listed = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False)
        state = listed.stdout.strip()
        return listed.returncode == 0 and bool(state) and not state.startswith("Z")


@dataclass(frozen=True)
class SandboxSeed:
    """The remote's first state, built once and copied into each sandbox.

    Attributes:
        bare: A bare repository whose ``main`` holds the seed files in one commit, with no
            remote configured.
        sha: That commit.
    """

    bare: Path
    sha: str


def build_sandbox_seed(directory: Path) -> SandboxSeed:
    """Build the seed bare repository.

    Args:
        directory: A directory that does not exist yet, under a resolved path. It holds the
            seed afterwards.

    Returns:
        The seed.
    """
    directory.mkdir()
    home = directory / "home"
    hooks_dir = directory / "hooks"
    for path in (home, hooks_dir):
        path.mkdir()
    global_config = directory / "global-config"
    global_config.write_bytes(b"")
    env = _isolated_git_env(home, global_config)

    def git(*args: str) -> bytes:
        return _run_git(env, *args, cwd=directory, check=True).stdout

    work = directory / "work"
    git("init", "-q", "--initial-branch=main", str(work))
    for relative, content in _SEED_FILES:
        target = work / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    git("-C", str(work), "add", "--", *(relative for relative, _ in _SEED_FILES))
    git(*_local_settings(hooks_dir), "-C", str(work), "commit", "-q", "-m", "chore: seed the sandbox repository")
    bare = directory / f"{SANDBOX_REPO}.git"
    git("clone", "-q", "--bare", str(work), str(bare))
    git("-C", str(bare), "remote", "remove", "origin")
    sha = git("-C", str(bare), "rev-parse", "refs/heads/main").decode("ascii").strip()
    shutil.rmtree(work)
    return SandboxSeed(bare=bare, sha=sha)


def build_handoff_sandbox(seed: SandboxSeed | None = None) -> HandoffSandbox:
    """Build a sandbox in a new temporary directory; remove the directory if building fails.

    Args:
        seed: The remote's first state, copied into the sandbox. ``None`` builds one in the
            sandbox and removes it after the copy. The fixture passes the session's seed,
            because a seed costs five git processes and every test builds a sandbox.

    Returns:
        The sandbox. The caller removes ``root`` when done.
    """
    root = Path(os.path.realpath(tempfile.mkdtemp(prefix="handoff-sandbox-")))
    try:
        if seed is not None:
            return _populate(root, seed)
        sandbox = _populate(root, build_sandbox_seed(root / "seed"))
        shutil.rmtree(root / "seed")
        return sandbox
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise


def load_fake_kiro_cli(path: Path = FAKE_KIRO_CLI) -> ModuleType:
    """Import the fake ``kiro-cli`` as a module, for its constants and ``noise_payload``.

    The file has no ``.py`` suffix, so the loader is given explicitly. The module is put in
    ``sys.modules`` before it runs, as an import would do.

    Args:
        path: The script.

    Returns:
        The module, named ``fake_kiro_cli``.
    """
    loader = importlib.machinery.SourceFileLoader("fake_kiro_cli", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def handoff_sandbox_seed() -> Iterator[SandboxSeed]:
    """The seed that every sandbox of the session copies; nothing writes to it."""
    directory = Path(os.path.realpath(tempfile.mkdtemp(prefix="handoff-seed-")))
    try:
        yield build_sandbox_seed(directory / "seed")
    finally:
        shutil.rmtree(directory)


@pytest.fixture
def handoff_sandbox(handoff_sandbox_seed: SandboxSeed) -> Iterator[HandoffSandbox]:
    """A new :class:`HandoffSandbox` for each test, removed after it."""
    sandbox = build_handoff_sandbox(handoff_sandbox_seed)
    try:
        yield sandbox
    finally:
        shutil.rmtree(sandbox.root)


@pytest.fixture(scope="session")
def fake_kiro_cli_module() -> ModuleType:
    """The fake ``kiro-cli`` imported as a module (see :func:`load_fake_kiro_cli`)."""
    return load_fake_kiro_cli()


def _populate(root: Path, seed: SandboxSeed) -> HandoffSandbox:
    """Create the layout of :class:`HandoffSandbox` under an empty ``root``, from a seed."""
    home = root / "home"
    projects = home / "Projects"
    harness_tree = projects / "example-harness"
    hooks_dir = root / "git" / "hooks"
    handoff_dir = harness_tree / ".private" / "handoff"
    worktrees_root = projects / ".handoff-worktrees"
    session_worktrees = projects / ".kiro-worktrees"
    for directory in (
        home / ".config",
        home / ".local" / "bin",
        handoff_dir,
        worktrees_root,
        session_worktrees,
        hooks_dir,
        root / "records",
        root / "remote",
    ):
        directory.mkdir(parents=True)
    global_config = root / "git" / "global-config"
    global_config.write_bytes(b"")
    git_env = _isolated_git_env(home, global_config)

    def git(*args: str) -> bytes:
        return _run_git(git_env, *args, cwd=root, check=True).stdout

    bare = root / "remote" / f"{SANDBOX_REPO}.git"
    shutil.copytree(seed.bare, bare, symlinks=True)
    git("config", "--file", str(bare / "config"), "core.hooksPath", str(hooks_dir))
    main_tree = projects / SANDBOX_REPO
    # After "clone", -c writes each setting into the new repository's .git/config.
    git("clone", "-q", *_local_settings(hooks_dir), str(bare), str(main_tree))
    with open(main_tree / "README.md", "a", encoding="utf-8") as readme:
        readme.write("An edit that another session has not committed.\n")
    with open(main_tree / "docs" / "guide.md", "a", encoding="utf-8") as guide:
        guide.write("An edit that another session has staged.\n")
    git("-C", str(main_tree), "add", "--", "docs/guide.md")
    (main_tree / "docs" / "draft.md").write_text("An untracked draft of another session.\n", encoding="utf-8")
    (main_tree / "メモ.txt").write_text("別のセッションの未追跡のメモ。\n", encoding="utf-8")

    kiro_cli = home / ".local" / "bin" / "kiro-cli"
    shutil.copy2(FAKE_KIRO_CLI, kiro_cli)
    return HandoffSandbox(
        root=root,
        home=home,
        repo=SANDBOX_REPO,
        bare=bare,
        main_tree=main_tree,
        main_tree_dirty=MAIN_TREE_DIRTY,
        harness_tree=harness_tree,
        handoff_dir=handoff_dir,
        worktrees_root=worktrees_root,
        session_worktrees=session_worktrees,
        kiro_cli=kiro_cli,
        record=root / "records" / "fake-kiro-cli.jsonl",
        hooks_dir=hooks_dir,
        base_sha=seed.sha,
        git_env=MappingProxyType(git_env),
    )


def _isolated_git_env(home: Path, global_config: Path) -> dict[str, str]:
    """Return this process's environment without :data:`SANDBOX_DROPPED_PREFIXES`, isolated from git configuration.

    Args:
        home: The directory for ``HOME``; ``XDG_CONFIG_HOME`` is its ``.config``.
        global_config: An empty file for ``GIT_CONFIG_GLOBAL``.

    Returns:
        A new dictionary.
    """
    env = {name: value for name, value in os.environ.items() if not name.startswith(SANDBOX_DROPPED_PREFIXES)}
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "GIT_CONFIG_GLOBAL": str(global_config),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def _local_settings(hooks_dir: Path) -> list[str]:
    """Return the sandbox's local git settings as ``-c key=value`` options.

    Args:
        hooks_dir: The empty hooks directory.

    Returns:
        The options, for ``git -c ...`` (one command) or ``git clone -c ...`` (the new
        repository's ``.git/config``).
    """
    settings = (
        ("user.name", SANDBOX_USER_NAME),
        ("user.email", SANDBOX_USER_EMAIL),
        ("core.hooksPath", str(hooks_dir)),
        ("commit.gpgSign", "false"),
        ("tag.gpgSign", "false"),
    )
    return [part for key, value in settings for part in ("-c", f"{key}={value}")]


def _run_git(env: Mapping[str, str], *args: str, cwd: Path, check: bool) -> subprocess.CompletedProcess[bytes]:
    """Run git with an environment; see :meth:`HandoffSandbox.git`."""
    completed = subprocess.run(
        ["git", *args], cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL, capture_output=True, check=False
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise AssertionError(f"git {' '.join(args)} exited {completed.returncode}: {detail}")
    return completed


def _status_paths(status: bytes) -> set[str]:
    """Read the paths of ``git status --porcelain=v1 -z``, both paths of a rename or copy included."""
    fields = status.split(b"\0")
    paths: set[str] = set()
    index = 0
    while index < len(fields):
        entry = fields[index]
        index += 1
        if len(entry) < 4:
            continue
        paths.add(os.fsdecode(entry[3:]))
        if b"R" in entry[:2] or b"C" in entry[:2]:
            if index < len(fields) and fields[index]:
                paths.add(os.fsdecode(fields[index]))
            index += 1
    return paths

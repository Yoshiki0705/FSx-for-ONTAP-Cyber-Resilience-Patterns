"""Layer 0 of the safety layers: a boundary of the operating system under every change-mode ``kiro-cli`` (T4-R2-03).

The layers 1 to 3 (the tool ceiling, the agent configuration with its guards, the child environment) are
settings that ``kiro-cli`` reads. The manual of Kiro (https://kiro.dev/docs/custom-agents/configuration-reference/,
read 2026-11-14) says that CLI V3 ignores ``toolsSettings``, and it does not say how ``--trust-tools`` ranks
against ``denyByDefault``. A setting that a newer ``kiro-cli`` stops enforcing leaves a run that passes every check
and is not bound. So a change item does not start without a boundary that the operating system enforces, whatever the
settings say: on macOS a ``sandbox-exec`` profile that this module builds, and that the runner tries before each change
item (and each selftest) on a throwaway tree.

What the profile does, and what it does not:

- It denies reading the places that hold credentials (``~/.ssh``, ``~/.aws``, ``~/.config/gh``, ``~/.gnupg``, ...).
- It denies writing the user's agent and hook configuration (``~/.kiro/agents``, ``hooks``, ``settings``, ...), the
  files a shell reads at start-up, the credential directories, and the main working trees of every repository the
  harness knows (this repository's included), except what a commit in a worktree needs: the refs and logs below
  ``handoff/``, the run's own ``worktrees/<name>/`` of the common git directory (T4-R5-04) and, for a run that has no
  object directory of its own, ``objects``. ``config``, ``hooks/`` and ``info/`` of the common git directory stay
  closed (T4-02).
- It denies writing ``<main>/.git/objects`` to a run that is given an object directory (``object_directories``,
  T4-R5-03). Denying the deletion (T4-R4-03) left the overwriting of an existing loose object and the adding of a pack
  that holds a forged copy of an object: ``git cat-file`` and ``git checkout`` return the forged content, and only
  ``git fsck`` says so. The run writes ``GIT_OBJECT_DIRECTORY`` instead, with the main repository's objects as an
  alternate to read; the runner takes the commits of the run into the main repository after the run through
  ``git unpack-objects --strict``, which computes every hash again and never overwrites an object.
- It denies writing the package prefixes as wholes (:data:`SYSTEM_WRITE_PREFIXES`, T4-R5-02), and the directories of the
  git that the harness runs (its executable, ``git --exec-path``, the system configuration), which the runner adds. A
  list of the writable directories of ``PATH`` closed ``/opt/homebrew/bin`` and left the keg that it links into,
  ``libexec/git-core`` and ``/opt/homebrew/etc/gitconfig`` open; ``core.sshCommand`` in the last runs for the
  harness's next ``git fetch``. The harness's git does not read the system configuration at all (``command.harden_git``). The directories that a run may write (its worktree, a selftest's
  directory) are allowed after the denials, as the later rule wins in a profile.
- It denies writing the pointers that make a linked worktree a worktree: the ``.git`` file of each worktree that the
  run names, and ``commondir``, ``gitdir`` and ``config.worktree`` below ``<main>/.git/worktrees/<name>/``. The
  harness runs git outside the profile after the run; a repointed ``.git`` file would make that git read the
  configuration of a repository that the agent made, and run what ``core.fsmonitor`` names (T4-R3-01). A commit
  needs none of these writes.
- It denies connecting to every unix socket except the resolver and the log (T4-R4-02). A list of names
  (``docker.sock``, ``agent.sock``) missed ``docker.raw.sock`` and every other name; a request to a daemon behind a
  socket is carried out with the rights of the user and not of the profile. TCP and UDP are not touched. Which other
  unix sockets ``kiro-cli`` and the verification commands need is not measured (hypothesis; task 5.20 counts the
  refusals).
- It denies deleting below ``<main>/.git/objects`` except the temporary names that git creates and removes itself and
  ``maintenance.lock``: a commit creates objects and never deletes one (T4-R4-03).
- It opens, below ``refs/heads/handoff`` and its logs, only the branch of the run when the runner names it
  (``own_branches``): an item cannot rewrite the branch of another item (T4-R4-09).
- It denies reading the places that hold credentials, and writing the places that run at the next login or before the
  user's own tools (``~/Library/LaunchAgents``, ``~/.local/bin``, the user's git configuration below ``~/.config/git``,
  the writable directories of ``PATH`` that the runner names). **The lists are denials: what no list names is
  allowed.** Turning the home directory into an allow list (deny all, allow what ``kiro-cli``, git and the
  verification commands need) is not done: what ``kiro-cli`` needs to read and write is not measured (hypothesis;
  task 5.20 runs it once), and a list that is too narrow stops every run (T4-R3-03).
- It does **not** deny the network: ``kiro-cli`` reaches its model service over it, so a profile that closed the
  network would stop every run. Egress stays what layers 1 to 3 make of it (hypothesis; T6 observes it).
- It does **not** deny writing all of ``~/.kiro``: ``kiro-cli`` keeps its own state there (hypothesis: closing all of
  it stops ``kiro-cli``; closing the control-plane directories is what this profile does).
- ``sandbox-exec`` is marked deprecated by Apple, and the profile language is not documented by Apple beyond the man
  page. What the profile does is tried on this machine before each change run (:func:`probes`), not assumed.
- It does **not** close what it does not name. Apple Events (one application asking another to act) were not tried
  (a permission dialog of macOS stands in the way). On macOS 27.0, ``launchctl submit`` and ``launchctl bootstrap``
  failed under a profile, even a minimal one, and ``open`` of a script for Terminal did not run it within 12 seconds
  (one observation each; other versions are unknown). ``osascript`` ``do shell script`` failed with ``Operation not
  permitted``. A unix socket that is not closed by the rule above does not exist; a place of the home directory that no
  list names stays writable (the lists are denials). Reading the contents of the main working trees is allowed.
- It cannot be nested with Kiro's own command sandbox (``sandbox-exec`` per shell command): the second
  ``sandbox_apply`` fails under the first. A run does not start when ``sandbox.json`` turns that sandbox on
  (:func:`kiro_sandbox_problem`, T4-R4-04). The reverse (Kiro's sandbox instead of layer 0) is not taken: Kiro's sandbox
  wraps the commands of the agent and leaves the agent and its file tools outside, and layer 0 wraps all of ``kiro-cli``.

The module belongs to the pure core (see ``handoff/__init__.py``): it reads and writes no file and starts no process.
The runner writes the profile, runs the probes of :func:`probes` and passes their results to :func:`judge`.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "CREDENTIAL_PATHS",
    "OsBoundary",
    "Probe",
    "ProbeResult",
    "KIRO_SANDBOX_CONFIG",
    "SANDBOX_EXEC",
    "TEST_DOUBLE_VARIABLE",
    "build_profile",
    "discover",
    "judge",
    "kiro_sandbox_problem",
    "probes",
]

#: Where macOS keeps ``sandbox-exec``.
SANDBOX_EXEC: Final = "/usr/bin/sandbox-exec"

#: Set to the path of a program that takes ``-f <profile> <command...>`` and runs the command, to run the tests of the
#: runner where ``sandbox-exec`` does not exist. It stands in for the boundary and enforces nothing; the runner records
#: that and the report says so. Not meant for a run of real items.
TEST_DOUBLE_VARIABLE: Final = "HANDOFF_OS_BOUNDARY_TEST_DOUBLE"

#: Where Kiro keeps the configuration of its local command sandbox, relative to ``~`` (global) and to a workspace root
#: (project): https://kiro.dev/docs/sandbox/ (read 2026-11-14). The sandbox wraps each shell command in
#: ``sandbox-exec``, and ``sandbox-exec`` cannot be nested: under this module's profile a second ``sandbox_apply``
#: fails with ``Operation not permitted`` (one observation, macOS 27.0). So a change run does not start when either file
#: turns the sandbox on (T4-R4-04).
KIRO_SANDBOX_CONFIG: Final = ".kiro/settings/sandbox.json"

#: Below the home directory: what a change-mode run may not read or write (credentials and tokens).
CREDENTIAL_PATHS: Final[tuple[str, ...]] = (
    ".ssh",
    ".aws",
    ".config/gh",
    ".gnupg",
    ".docker",
    ".kube",
    ".azure",
    ".config/gcloud",
    "Library/Keychains",
    ".config/op",
    ".config/stripe",
    ".oci",
    # browsers: cookies and stored sessions
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge",
    "Library/Cookies",
    "Library/Safari",
)
#: Single files below the home directory that hold credentials.
_CREDENTIAL_FILES: Final[tuple[str, ...]] = (
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".databrickscfg",
    # the credential file inside a directory that holds tools and caches too (the directory itself stays readable)
    ".terraform.d/credentials.tfrc.json",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".m2/settings.xml",
    ".m2/settings-security.xml",
    # what a shell or a client typed: tokens appear in command lines
    ".zsh_history",
    ".bash_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
    ".node_repl_history",
)
#: Below ``~/.kiro``: the control plane of the user's own agents (the agent configuration, the hooks, the settings,
#: what steers the next session). ``kiro-cli``'s own state elsewhere in ``~/.kiro`` stays writable.
_KIRO_CONTROL: Final[tuple[str, ...]] = (
    ".kiro/agents",
    ".kiro/hooks",
    ".kiro/settings",
    ".kiro/steering",
    ".kiro/skills",
    ".kiro/powers",
    ".kiro/workspace-roots",
    # what steers or runs at the next start of the IDE or of an agent (T4-R6-02)
    ".kiro/extensions",
    ".kiro/prompts",
    ".kiro/mates",
    ".kiro/crew",
    ".kiro/tools",
    ".kiro/memories",
    ".kiro/docs",
    ".kiro/specs",
    ".kiro/identities",
)
#: Single files of ``~/.kiro`` of the same kind (T4-R6-02): the start-up arguments of the IDE and the rule file that the
#: user's global rules name. ``kiro-cli``'s own state (``sessions``, ``logs``, ``session-index``, ``session-leases``,
#: ``cloud-cache``, ``tasks``) stays writable; whether it writes elsewhere in ``~/.kiro`` is not measured (hypothesis).
_KIRO_CONTROL_FILES: Final[tuple[str, ...]] = (".kiro/argv.json", ".kiro/writing-deny-list.md")
#: Files of the home directory that a shell or git reads at start-up.
_STARTUP_FILES: Final[tuple[str, ...]] = (
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".zlogout",
    ".profile",
    ".inputrc",
    ".gitconfig",
    ".vimrc",
    ".tmux.conf",
    ".condarc",
)
#: Directories of the home directory whose contents run at the next login, or before the user's own tools, or steer
#: git as the user's configuration does (``~/.config/git/config`` is read like ``~/.gitconfig``).
_PERSISTENCE_DIRS: Final[tuple[str, ...]] = (
    "Library/LaunchAgents",
    ".local/bin",
    "bin",
    ".zsh_sessions",
    ".config/git",
    ".config/fish",
    ".config/zsh",
    ".config/environment.d",
    # an IDE reads its settings (terminal profile, external program paths) at start (T4-R6-02)
    "Library/Application Support/Kiro/User",
    "Library/Application Support/Code/User",
    ".vscode",
    # sourced by the user's shell, or put before the user's own tools
    ".oh-my-zsh",
    ".zshrc.d",
    ".cargo/bin",
    # code that runs at the next start of an interpreter or an editor (T4-R7-02): ``*.pth`` lines that begin with
    # ``import`` run at every Python start; pip, nvim, emacs and helix read their configuration and plug-ins
    "Library/Python",
    ".config/pip",
    ".pip",
    ".config/nvim",
    ".emacs.d",
    ".config/helix",
    # the control planes of other agents on this machine (T4-R7-02); whether kiro-cli writes here is not measured
    ".claude",
    ".codex",
    ".gemini",
    ".cursor",
    "Library/Application Support/Cursor",
)
#: The control files of every git repository below the home directory (T4-R6-02). The main trees of the configuration
#: are closed by name; a repository that the configuration does not name (``~/Projects/<other>``) runs its ``hooks/``
#: with the user's rights at the next commit. The rule comes before the allowances of the run, so the run's own
#: worktree (whose ``.git`` is a file) and a repository that a test makes inside it stay open. The names are closed
#: below ``.git/modules/<name>/`` (a submodule's git directory, whose hooks and ``core.fsmonitor`` run with the user's
#: rights) and ``.git/worktrees/<name>/`` as well (T4-R7-03); ``refs``, ``HEAD``, ``packed-refs`` and ``objects`` stay
#: open (hypothesis: whether kiro-cli needs them in a repository outside the run is not measured).
_GIT_CONTROL_BELOW_HOME: Final = r"\.git/(modules/(.+/)?|worktrees/[^/]+/)?(hooks|info|config|config\.worktree)(/.*)?$"
#: The only unix sockets that a run may connect to (T4-R4-02): the resolver that ``getaddrinfo`` asks, and the log. Every
#: other unix socket is closed: a list of names (``docker.sock``, ``agent.sock``, ...) missed ``docker.raw.sock``,
#: ``podman-machine-default-api.sock`` and every name that nobody had thought of. A request to a daemon behind such a
#: socket is carried out with the rights of the user and not of the profile. What ``kiro-cli`` and the verification
#: commands need beyond these is not measured (hypothesis; task 5.20 counts the refusals).
_ALLOWED_UNIX_SOCKETS: Final[tuple[str, ...]] = (
    "/private/var/run/mDNSResponder",
    "/var/run/mDNSResponder",
    "/private/var/run/syslog",
)
#: Where the objects of the main working tree are. A commit in a linked worktree writes there when the run has no
#: object directory of its own; with one (``object_directories`` of :func:`build_profile`) it is closed (T4-R5-03).
_GIT_OBJECTS: Final = ".git/objects"
#: The administrative directories of the linked worktrees. Open as a whole only when the profile is not given the names
#: of the run's own worktrees; otherwise only ``.git/worktrees/<own name>`` is open (T4-R5-04).
_GIT_WORKTREES: Final = ".git/worktrees"
_OWN_WORKTREE_NAME: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*")
#: Places that hold the programs and the system configuration that the next command of the user (and the harness's own
#: git, which runs outside the profile) runs: closed for writing as whole prefixes, whatever ``PATH`` says (T4-R5-02). A
#: list taken from ``PATH`` closed ``/opt/homebrew/bin`` and left ``Cellar/git/<version>/bin`` (where the link points),
#: ``libexec/git-core`` (``git --exec-path``) and ``/opt/homebrew/etc/gitconfig`` (the system configuration of git, whose
#: ``core.sshCommand`` names a program) open: a Homebrew prefix is owned by the user. The paths are real paths (``/etc``
#: is a link to ``/private/etc``). The system prefixes are denied even where the user could not write them: a rule that
#: depends on who owns a directory today stops binding when the owner changes.
SYSTEM_WRITE_PREFIXES: Final[tuple[str, ...]] = (
    "/opt/homebrew",
    "/opt/local",
    "/usr/local",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/share",
    "/bin",
    "/sbin",
    "/Library",
    "/Applications",
    "/System",
    "/private/etc",
)
#: The refs of the branches that items hand over, and their logs. Open as a whole when the profile is not given the
#: branch of the run; otherwise only that branch is open (T4-R4-09).
_GIT_HANDOFF_REFS: Final[tuple[str, ...]] = (".git/refs/heads/handoff", ".git/logs/refs/heads/handoff")
_OWN_BRANCH: Final = re.compile(r"handoff/[A-Za-z0-9][A-Za-z0-9._-]*")
#: Single files of the common git directory that a commit takes and gives back. ``git commit`` takes the lock of
#: ``packed-refs`` while it updates the branch, and writes nothing into ``packed-refs`` itself: the rename onto
#: ``packed-refs`` stays denied with the rest of the closed tree, so this does not let a run rewrite a ref of ``main``
#: (T4-R3-09: without it, every commit printed ``Unable to create packed-refs.lock``).
_GIT_LOCK_FILES: Final[tuple[str, ...]] = (".git/packed-refs.lock",)
#: What of the common git directory stays closed, below the denial of the whole tree and the allowances above.
_GIT_CLOSED: Final[tuple[str, ...]] = (".git/config", ".git/config.worktree", ".git/hooks", ".git/info")


class _Unsafe(ValueError):
    """A path that cannot be put in a profile."""


def _quote(path: str) -> str:
    """A path as a string of the profile language.

    Raises:
        ValueError: The path is not absolute and in normal form, or holds a character that the profile would read as
            something else (a quotation mark, a backslash, a control character).
    """
    if not path.startswith("/") or posixpath.normpath(path) != path:
        raise _Unsafe(f"{path!r} is not an absolute path in normal form")
    if any(char in path for char in '"\\') or any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        raise _Unsafe(f"{path!r} holds a character that cannot be written in a profile")
    return f'"{path}"'


def closed_names() -> tuple[str, ...]:
    """The names below the home directory that the profile closes for writing, as paths relative to it."""
    return tuple(
        dict.fromkeys(
            (
                *CREDENTIAL_PATHS,
                *_CREDENTIAL_FILES,
                *_KIRO_CONTROL,
                *_KIRO_CONTROL_FILES,
                *_STARTUP_FILES,
                *_PERSISTENCE_DIRS,
            )
        )
    )


def _rule(action: str, operation: str, kinds: Iterable[tuple[str, str]]) -> list[str]:
    """One line per path: ``(<action> <operation> (<filter> "<path>"))``."""
    return [f"({action} {operation} ({kind} {_quote(path)}))" for kind, path in kinds]


_REGEX_SPECIAL: Final = frozenset(".^$*+?()[]{}|\\")


def _regex_of(path: str) -> str:
    """``path`` as a regular expression that matches that path only (its special characters escaped).

    Raises:
        ValueError: As :func:`_quote`: the path is not absolute and in normal form, or holds a quotation mark, a
            backslash or a control character.
    """
    _quote(path)
    return "".join(f"\\{char}" if char in _REGEX_SPECIAL else char for char in path)


def build_profile(
    *,
    home: str,
    main_trees: Iterable[str],
    allow_write: Iterable[str] = (),
    worktrees: Iterable[str] = (),
    path_dirs: Iterable[str] = (),
    own_branches: Iterable[str] | None = None,
    own_worktree_names: Iterable[str] | None = None,
    object_directories: Iterable[str] | None = None,
    kiro_home: str | None = None,
    config_files: Iterable[str] = (),
    symlink_targets: Iterable[str] = (),
) -> str:
    """Build the profile text.

    The profile starts from ``(allow default)`` and adds denials, so that what ``kiro-cli`` and git need to run is not
    listed one by one; the denials are what this module states. A later rule wins over an earlier one.

    Args:
        home: The absolute home directory, in normal form.
        main_trees: The main working trees to close for writing: every repository of the configuration and this
            repository's own. Each keeps the parts of ``.git`` that a commit in a worktree needs.
        allow_write: Directories that stay writable although they lie below a closed tree (a selftest's directory below
            this repository's ``.private/``). Allowed last, so that they win.
        worktrees: The linked worktrees of the run: their ``.git`` files are closed for writing.
        path_dirs: Directories of ``PATH`` that the user can write: closed for writing.
        own_branches: The ``handoff/<id>`` branches that the run may write (its ref and its log). ``None``: every
            branch below ``handoff/`` stays writable (a selftest, whose repository is its own); a sequence, even an
            empty one: only these, so that an item cannot rewrite the branch of another item (T4-R4-09).

    Returns:
        The profile, one rule per line, in a fixed order.

    Raises:
        ValueError: A path is not absolute and in normal form, or cannot be written in a profile.
    """
    root = home.rstrip("/")
    lines = ["(version 1)", "(allow default)", ";; read: credentials and tokens"]
    lines += _rule("deny", "file-read*", [("subpath", f"{root}/{name}") for name in CREDENTIAL_PATHS])
    lines += _rule("deny", "file-read*", [("literal", f"{root}/{name}") for name in _CREDENTIAL_FILES])
    lines.append(";; write: credentials, the user's agent control plane, start-up files")
    lines += _rule("deny", "file-write*", [("subpath", f"{root}/{name}") for name in CREDENTIAL_PATHS])
    lines += _rule("deny", "file-write*", [("literal", f"{root}/{name}") for name in _CREDENTIAL_FILES])
    lines += _rule("deny", "file-write*", [("subpath", f"{root}/{name}") for name in _KIRO_CONTROL])
    lines += _rule("deny", "file-write*", [("literal", f"{root}/{name}") for name in _KIRO_CONTROL_FILES])
    lines += _rule("deny", "file-write*", [("literal", f"{root}/{name}") for name in _STARTUP_FILES])
    lines += _rule("deny", "file-write*", [("subpath", f"{root}/{name}") for name in _PERSISTENCE_DIRS])
    lines += _rule("deny", "file-write*", [("subpath", path) for path in sorted(set(path_dirs))])
    lines.append(f'(deny file-write* (regex #"^{_regex_of(root)}/(.*/)?{_GIT_CONTROL_BELOW_HOME}"))')
    lines.append(";; write: the prefixes of the programs and of the system configuration of git (T4-R5-02)")
    lines += _rule("deny", "file-write*", [("subpath", path) for path in SYSTEM_WRITE_PREFIXES])
    if kiro_home is not None:
        kiro_root = kiro_home.rstrip("/")
        lines += _rule(
            "deny", "file-write*", [("subpath", f"{kiro_root}/{name.removeprefix('.kiro/')}") for name in _KIRO_CONTROL]
        )
        lines += _rule(
            "deny",
            "file-write*",
            [("literal", f"{kiro_root}/{name.removeprefix('.kiro/')}") for name in _KIRO_CONTROL_FILES],
        )
    lines += _rule("deny", "file-write*", [("literal", path) for path in sorted(set(config_files))])
    if symlink_targets:
        lines.append(
            ";; write: where a closed name is a symbolic link, its target too (a rule on the link covers no target)"
        )
        lines += _rule("deny", "file-write*", [("subpath", path) for path in sorted(set(symlink_targets))])
    lines.append(";; write: the main working trees, except what a commit in a worktree needs")
    for tree in sorted(set(main_trees)):
        base = tree.rstrip("/")
        lines += _rule("deny", "file-write*", [("subpath", base)])
        if object_directories is None:
            lines += _rule("allow", "file-write*", [("subpath", f"{base}/{_GIT_OBJECTS}")])
        if own_worktree_names is None:
            lines += _rule("allow", "file-write*", [("subpath", f"{base}/{_GIT_WORKTREES}")])
        else:
            for name in sorted(set(own_worktree_names)):
                if _OWN_WORKTREE_NAME.fullmatch(name) is None:
                    raise ValueError(f"{name!r} is not the name of an administrative directory of a worktree")
                lines += _rule("allow", "file-write*", [("subpath", f"{base}/{_GIT_WORKTREES}/{name}")])
        if own_branches is None:
            lines += _rule("allow", "file-write*", [("subpath", f"{base}/{name}") for name in _GIT_HANDOFF_REFS])
        else:
            for branch in sorted(set(own_branches)):
                if _OWN_BRANCH.fullmatch(branch) is None:
                    raise ValueError(f"{branch!r} is not a handoff/<id> branch name")
                escaped_branch = "".join(f"\\{char}" if char in _REGEX_SPECIAL else char for char in branch)
                lines.append(
                    f'(allow file-write* (regex #"^{_regex_of(base)}/\\.git/(logs/)?refs/heads/'
                    f'{escaped_branch}(\\.lock)?$"))'
                )
        lines += _rule("allow", "file-write*", [("literal", f"{base}/{name}") for name in _GIT_LOCK_FILES])
        lines += _rule(
            "deny", "file-write*", [("literal", f"{base}/.git/config"), ("literal", f"{base}/.git/config.worktree")]
        )
        lines += _rule("deny", "file-write*", [("subpath", f"{base}/.git/hooks"), ("subpath", f"{base}/.git/info")])
        # a commit creates objects and never deletes one (T4-R4-03): ``unlink`` below ``objects`` is closed except the
        # temporary names that git creates and removes itself, and the lock that the maintenance after a commit takes
        escaped = _regex_of(base)
        lines.append(f'(deny file-write-unlink (subpath "{base}/.git/objects"))')
        lines.append(
            f'(allow file-write-unlink (regex #"^{escaped}/\\.git/objects/([0-9a-f][0-9a-f]/)?tmp_obj_[^/]*$"))'
        )
        lines.append(f'(allow file-write-unlink (regex #"^{escaped}/\\.git/objects/pack/(\\.?tmp[-_][^/]*)$"))')
        lines.append(f'(allow file-write-unlink (literal "{base}/.git/objects/maintenance.lock"))')
    allowed = sorted({*allow_write, *(object_directories or ())})
    if allowed:
        lines.append(";; write: the directories of this run")
        lines += _rule("allow", "file-write*", [("subpath", path) for path in allowed])
    lines.append(";; write: the pointers that make a linked worktree a worktree (after the allowances above)")
    lines += _rule("deny", "file-write*", [("literal", f"{wt.rstrip('/')}/.git") for wt in sorted(set(worktrees))])
    for tree in sorted(set(main_trees)):
        base = _regex_of(tree.rstrip("/"))
        lines.append(
            f'(deny file-write* (regex #"^{base}/\\.git/worktrees/[^/]+/(commondir|gitdir|config\\.worktree)$"))'
        )
    lines.append(";; unix sockets: closed, except the resolver and the log (T4-R4-02)")
    lines.append("(deny network-outbound (remote unix-socket))")
    lines += [
        f"(allow network-outbound (remote unix-socket (path-literal {_quote(path)})))" for path in _ALLOWED_UNIX_SOCKETS
    ]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True, slots=True)
class OsBoundary:
    """The program that puts a command under a profile, and whether the runner tries it before it relies on it.

    Attributes:
        program: The absolute path of ``sandbox-exec`` (or of the test double).
        verify: Whether the runner runs the probes of :func:`probes` before a change run. ``True`` except for the
            test double, which enforces nothing.
        test_double: Whether ``program`` was named by :data:`TEST_DOUBLE_VARIABLE`.
    """

    program: str
    verify: bool = True
    test_double: bool = False

    def __post_init__(self) -> None:
        """Check the program path."""
        if type(self.program) is not str or not self.program.startswith("/"):
            raise ValueError(f"program must be an absolute path, got {self.program!r}")
        if self.test_double and self.verify:
            raise ValueError("a test double cannot be verified: it enforces nothing")

    def wrap(self, argv: Sequence[str], profile_path: str) -> tuple[str, ...]:
        """The argv that runs ``argv`` under the profile at ``profile_path``.

        Args:
            argv: The command, as the runner built it.
            profile_path: The absolute path of the profile file.

        Returns:
            ``(program, "-f", profile_path, *argv)``.

        Raises:
            ValueError: ``argv`` is empty or ``profile_path`` is not absolute.
        """
        if not argv:
            raise ValueError("argv must not be empty")
        if not profile_path.startswith("/"):
            raise ValueError(f"profile_path must be absolute, got {profile_path!r}")
        return (self.program, "-f", profile_path, *argv)


def kiro_sandbox_problem(files: Mapping[str, str | None]) -> str | None:
    """Why a run must not start under layer 0 because Kiro's own command sandbox may be on, or ``None`` (T4-R4-04).

    Layer 0 puts the whole ``kiro-cli`` under a profile. Kiro's local command sandbox puts each shell command under
    another one, and that fails inside the first, so each command would fail or run without the isolation that Kiro
    reports as ``Unavailable`` (which of the two happens is not known: hypothesis). Only ``enabled`` is read.

    Args:
        files: The text of each sandbox configuration file by a label for the message, ``None`` when the file does not
            exist (a file that cannot be read is also given as ``None`` by the caller only when it does not exist).

    Returns:
        A sentence naming the file, or ``None`` when no file turns the sandbox on. A file that is not a JSON object
        counts against the run: what it says is not known.
    """
    for label, text in files.items():
        if text is None:
            continue
        try:
            document = json.loads(text)
        except ValueError:
            return f"{label} is not valid JSON, so whether it turns the command sandbox of Kiro on is not known"
        if not isinstance(document, dict):
            return f"{label} is not a JSON object, so whether it turns the command sandbox of Kiro on is not known"
        if document.get("enabled") is True:
            return f"{label} sets enabled to true, which turns the command sandbox of Kiro on"
    return None


def discover(environ: Mapping[str, str], platform: str, exists: bool) -> OsBoundary | None:
    """Choose the boundary of this machine.

    Args:
        environ: The environment of the harness.
        platform: ``sys.platform``.
        exists: Whether :data:`SANDBOX_EXEC` is an executable file.

    Returns:
        The boundary, or ``None`` when there is none: a change item is then held (``os_boundary_missing``).
    """
    double = environ.get(TEST_DOUBLE_VARIABLE)
    if double:
        return OsBoundary(program=double, verify=False, test_double=True)
    if platform == "darwin" and exists:
        return OsBoundary(program=SANDBOX_EXEC)
    return None


@dataclass(frozen=True, slots=True)
class Probe:
    """One throwaway operation that the runner runs under the profile, and what it must do.

    Attributes:
        name: A short name for the report.
        argv: The command, run with ``/bin/sh``; paths in it are those that :func:`probes` was given.
        must: ``allowed`` (the command succeeds and its effect exists) or ``denied`` (it fails and has no effect).
        effect: The path whose existence or content the runner reads after the command, or ``None``.
    """

    name: str
    argv: tuple[str, ...]
    must: str
    effect: str | None = None


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """What one probe did.

    Attributes:
        name: The probe's name.
        under_profile_ok: The command's exit code was 0 under the profile.
        effect_present: The command's effect exists afterwards (``None`` when the probe has none).
        without_profile_ok: The same command, run without the profile on a fresh copy, succeeded: it is a command
            that the user could run, so a failure under the profile is the profile's.
    """

    name: str
    under_profile_ok: bool
    effect_present: bool | None
    without_profile_ok: bool


def probes(
    *, home: str, main_tree: str, work: str, objects: str | None = None, prefix: str | None = None
) -> tuple[Probe, ...]:
    """The operations that the runner tries under the profile built for ``home``, ``main_tree`` and ``work``.

    The paths are those of a throwaway tree that the runner made (never the real home): the same
    :func:`build_profile` is applied to it. Each denied operation is also run without the profile, so that a refusal
    is the profile's and not a mistake in the command.

    Args:
        home: The throwaway home directory.
        main_tree: The throwaway main working tree, with a ``.git`` directory.
        work: The directory that stays writable.

    Returns:
        Controls (that must work) and denials (that must not), in a fixed order.
    """

    def put(path: str) -> tuple[str, ...]:
        return ("/bin/sh", "-c", f'printf x > "{path}"')

    def get(path: str) -> tuple[str, ...]:
        return ("/bin/cat", path)

    def connect(directory: str, name: str) -> tuple[str, ...]:
        # one process listens on ``name`` below ``directory`` and connects to it (a relative name, so that a long
        # directory does not exceed the limit of a socket path); it exits 0 when the connection was made
        script = (
            "use IO::Socket::UNIX; chdir($ARGV[0]) or exit 4; "
            "my $s = IO::Socket::UNIX->new(Local => $ARGV[1], Listen => 1) or exit 2; "
            'my $c = IO::Socket::UNIX->new(Peer => $ARGV[1]) or exit 3; print "connected\\n";'
        )
        return ("/usr/bin/perl", "-e", script, directory, name)

    def connect_to(path: str) -> tuple[str, ...]:
        # connects to a socket that exists (the system's resolver); exits 0 when the connection was made
        script = (
            'use IO::Socket::UNIX; my $c = IO::Socket::UNIX->new(Peer => $ARGV[0]) or exit 3; print "connected\\n";'
        )
        return ("/usr/bin/perl", "-e", script, path)

    object_controls: tuple[Probe, ...]
    object_denials: tuple[Probe, ...]
    if objects is None:
        object_controls = (
            Probe(
                "control-write-git-objects",
                put(f"{main_tree}/.git/objects/new-object"),
                "allowed",
                f"{main_tree}/.git/objects/new-object",
            ),
        )
        object_denials = ()
    else:
        object_controls = (
            Probe(
                "control-write-own-object-directory", put(f"{objects}/new-object"), "allowed", f"{objects}/new-object"
            ),
        )
        object_denials = (
            Probe(
                "deny-write-new-object-of-main",
                put(f"{main_tree}/.git/objects/new-object"),
                "denied",
                f"{main_tree}/.git/objects/new-object",
            ),
            Probe(
                "deny-write-forged-pack-of-main",
                put(f"{main_tree}/.git/objects/pack/forged.pack"),
                "denied",
                f"{main_tree}/.git/objects/pack/forged.pack",
            ),
            # an existing loose object, made writable first as an agent would: the exit code says whether it was refused
            Probe(
                "deny-write-existing-object",
                (
                    "/bin/sh",
                    "-c",
                    f'chmod u+w "{main_tree}/.git/objects/ab/cdef" && printf x > "{main_tree}/.git/objects/ab/cdef"',
                ),
                "denied",
            ),
        )
    prefix_denials: tuple[Probe, ...] = ()
    if prefix is not None:
        prefix_denials = (
            Probe("deny-write-package-prefix", put(f"{prefix}/etc/gitconfig"), "denied", f"{prefix}/etc/gitconfig"),
            Probe(
                "deny-write-package-keg",
                put(f"{prefix}/Cellar/git/1/bin/git"),
                "denied",
                f"{prefix}/Cellar/git/1/bin/git",
            ),
        )
    return (
        # controls: what a run needs must work, or a profile that denies everything would pass
        Probe("control-read-worktree-file", get(f"{work}/readable.txt"), "allowed"),
        Probe("control-write-worktree-file", put(f"{work}/new.txt"), "allowed", f"{work}/new.txt"),
        Probe("control-read-kiro-agent", get(f"{home}/.kiro/agents/agent.json"), "allowed"),
        *object_controls,
        Probe(
            "control-write-own-worktree-admin",
            put(f"{main_tree}/.git/worktrees/w/HEAD"),
            "allowed",
            f"{main_tree}/.git/worktrees/w/HEAD",
        ),
        Probe(
            "control-write-handoff-ref",
            put(f"{main_tree}/.git/refs/heads/handoff/item"),
            "allowed",
            f"{main_tree}/.git/refs/heads/handoff/item",
        ),
        Probe(
            "control-write-kiro-state", put(f"{home}/.kiro/sessions/state"), "allowed", f"{home}/.kiro/sessions/state"
        ),
        Probe("control-connect-resolver-socket", connect_to("/var/run/mDNSResponder"), "allowed"),
        # denials
        *object_denials,
        *prefix_denials,
        Probe(
            "deny-write-other-worktree-head",
            put(f"{main_tree}/.git/worktrees/other/HEAD"),
            "denied",
            f"{main_tree}/.git/worktrees/other/HEAD",
        ),
        Probe(
            "deny-write-other-worktree-index",
            put(f"{main_tree}/.git/worktrees/other/index"),
            "denied",
            f"{main_tree}/.git/worktrees/other/index",
        ),
        Probe(
            "deny-write-other-handoff-ref",
            put(f"{main_tree}/.git/refs/heads/handoff/other"),
            "denied",
            f"{main_tree}/.git/refs/heads/handoff/other",
        ),
        Probe("deny-read-aws", get(f"{home}/.aws/credentials"), "denied"),
        Probe("deny-read-ssh", get(f"{home}/.ssh/id_example"), "denied"),
        Probe("deny-read-gh-token", get(f"{home}/.config/gh/hosts.yml"), "denied"),
        Probe("deny-read-netrc", get(f"{home}/.netrc"), "denied"),
        Probe("deny-write-aws", put(f"{home}/.aws/new"), "denied", f"{home}/.aws/new"),
        Probe("deny-write-ssh", put(f"{home}/.ssh/authorized_keys"), "denied", f"{home}/.ssh/authorized_keys"),
        Probe(
            "deny-write-kiro-agent", put(f"{home}/.kiro/agents/evil.json"), "denied", f"{home}/.kiro/agents/evil.json"
        ),
        Probe("deny-write-kiro-hook", put(f"{home}/.kiro/hooks/evil"), "denied", f"{home}/.kiro/hooks/evil"),
        Probe("deny-write-shell-startup", put(f"{home}/.zshrc"), "denied", f"{home}/.zshrc"),
        Probe("deny-write-gitconfig", put(f"{home}/.gitconfig"), "denied", f"{home}/.gitconfig"),
        Probe("deny-write-main-tree-file", put(f"{main_tree}/README.md"), "denied", f"{main_tree}/README.md"),
        Probe("deny-write-common-git-config", put(f"{main_tree}/.git/config"), "denied", f"{main_tree}/.git/config"),
        Probe(
            "deny-write-common-git-hook",
            put(f"{main_tree}/.git/hooks/pre-commit"),
            "denied",
            f"{main_tree}/.git/hooks/pre-commit",
        ),
        Probe(
            "deny-write-common-git-info",
            put(f"{main_tree}/.git/info/exclude"),
            "denied",
            f"{main_tree}/.git/info/exclude",
        ),
        Probe(
            "deny-write-main-branch-ref",
            put(f"{main_tree}/.git/refs/heads/main"),
            "denied",
            f"{main_tree}/.git/refs/heads/main",
        ),
        Probe("deny-write-worktree-gitfile", put(f"{work}/.git"), "denied", f"{work}/.git"),
        Probe(
            "deny-write-worktree-commondir",
            put(f"{main_tree}/.git/worktrees/w/commondir"),
            "denied",
            f"{main_tree}/.git/worktrees/w/commondir",
        ),
        Probe(
            "deny-write-worktree-config",
            put(f"{main_tree}/.git/worktrees/w/config.worktree"),
            "denied",
            f"{main_tree}/.git/worktrees/w/config.worktree",
        ),
        Probe(
            "deny-write-launchagent",
            put(f"{home}/Library/LaunchAgents/x.plist"),
            "denied",
            f"{home}/Library/LaunchAgents/x.plist",
        ),
        Probe("deny-write-xdg-git-config", put(f"{home}/.config/git/config"), "denied", f"{home}/.config/git/config"),
        Probe("deny-write-path-dir", put(f"{home}/pathbin/git"), "denied", f"{home}/pathbin/git"),
        Probe("deny-read-history", get(f"{home}/.zsh_history"), "denied"),
        Probe("deny-connect-docker-sock", connect(work, "docker.sock"), "denied"),
        Probe("deny-connect-agent-sock", connect(work, "agent.sock"), "denied"),
        Probe("deny-connect-plain-unix-socket", connect(work, "plain.sock"), "denied"),
        # ``rm -f`` of an existing object file: the exit code says whether the deletion was refused (T4-R4-03)
        Probe("deny-delete-object", ("/bin/rm", "-f", f"{main_tree}/.git/objects/ab/cdef"), "denied"),
    )


def judge(results: Sequence[ProbeResult], expected: Sequence[Probe]) -> list[str]:
    """Why the profile is not shown to bind, one line each; empty when it is.

    A probe counts when: a control succeeded under the profile and left its effect; a denial failed under the profile,
    left no effect, and succeeded without the profile (so that the failure is the profile's). A probe that did not run
    counts against the profile.

    Args:
        results: What the runner observed, by probe name.
        expected: The probes that were to run.

    Returns:
        The failed probes with the reason.
    """
    by_name = {result.name: result for result in results}
    problems: list[str] = []
    for probe in expected:
        result = by_name.get(probe.name)
        if result is None:
            problems.append(f"{probe.name}: did not run")
        elif probe.must == "allowed":
            if not result.under_profile_ok or result.effect_present is False:
                problems.append(
                    f"{probe.name}: a control failed under the profile, so the profile stops what a run needs"
                )
        else:
            if result.under_profile_ok or result.effect_present:
                problems.append(f"{probe.name}: the operation took effect under the profile")
            elif not result.without_profile_ok:
                problems.append(f"{probe.name}: it fails without the profile too, so its refusal says nothing")
    return problems

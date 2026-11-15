"""What an approved Handoff agent configuration must restrict (T4-01).

An agent configuration of ``kiro-cli`` lists the tools the agent may use. Its
``toolsSettings`` narrow each tool: ``write`` and ``read`` take ``allowedPaths`` and
``deniedPaths``, ``shell`` takes ``allowedCommands``, ``deniedCommands``, ``denyByDefault``
and ``autoAllowReadonly`` (https://kiro.dev/docs/reference/built-in-tools/, read 2026-11-14).
Entries of the command lists are regular expressions anchored at both ends; path entries are
gitignore-style globs.

Before this module the approval of ``cli.py`` looked at the tool names, ``mcpServers`` and
``includeMcpJson`` only, so an agent with ``toolsSettings: {}`` could be approved: its
``shell`` and ``write`` reached every path and command of the user who ran ``kiro-cli``.
:func:`settings_problems` states what the approval now requires, and
:func:`build_agent_config` builds a configuration that meets it.

This is layer 2 of the safety layers, not a boundary: a regular expression over a command
line cannot see what a Makefile target or a script that the agent wrote does. The boundary
belongs to the operating system (a separate user without credentials, or a sandbox without a
network). What this module checks is that the configuration closes the direct routes that a
prompt-injected agent would take first.

The module is part of the pure core (see ``handoff/__init__.py``): it reads and writes no file.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from re import _parser as _sre_parse
from typing import Any, Final

__all__ = [
    "READ_DENIED_PATHS",
    "WRITE_DENIED_PATHS",
    "build_agent_config",
    "settings_problems",
]

#: Tools that write, read and run commands, by every name the ceiling or ``tools`` may use.
_WRITE_TOOLS: Final = frozenset({"fs_write", "write", "fsWrite"})
_READ_TOOLS: Final = frozenset({"fs_read", "read", "fsRead"})
_SHELL_TOOLS: Final = frozenset({"shell", "execute_bash", "execute_cmd"})

#: Paths that the ``write`` tool must refuse: the user's agent and hook configuration, the
#: credential and configuration directories, the files a shell reads at start-up, git's own
#: directory (``config`` and ``hooks/`` are shared by every worktree of a repository, T4-02),
#: tracked hook directories and the private records of the harness.
WRITE_DENIED_PATHS: Final[tuple[str, ...]] = (
    "~/.kiro/**",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.config/**",
    "~/.gnupg/**",
    "~/.gitconfig",
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "**/.git",
    "**/.git/**",
    "**/.githooks/**",
    "**/.private/**",
)

#: Paths that the ``read`` tool must refuse: the places that hold credentials and tokens. The
#: worktree itself stays readable.
READ_DENIED_PATHS: Final[tuple[str, ...]] = (
    "~/.ssh/**",
    "~/.aws/**",
    "~/.config/gh/**",
    "~/.gnupg/**",
    "~/.kiro/**",
    "~/.netrc",
    "~/.npmrc",
    "~/.docker/**",
    "**/.env",
    "**/.env.*",
    "**/.private/**",
)

#: Command lines that no ``allowedCommands`` entry may match, each as the one line that a
#: regular-expression entry would be tried against. The first group reaches the network or a
#: credential, the second changes what other worktrees and the main working tree run, the
#: third starts another interpreter from a string, which makes any list of commands moot.
_FORBIDDEN_ALLOWED: Final[tuple[str, ...]] = (
    "curl http://127.0.0.1:1/",
    "wget http://127.0.0.1:1/",
    "gh auth token",
    "gh pr create",
    "aws sts get-caller-identity",
    "ssh host",
    "scp a host:b",
    "nc 127.0.0.1 1",
    "env",
    "printenv",
    "cat ~/.aws/credentials",
    "cat ~/.config/gh/hosts.yml",
    "git push origin HEAD",
    "git config alias.x !id",
    "git remote add x y",
    "git worktree add x",
    "bash -c id",
    "sh -c id",
    "zsh -c id",
    "python -c print(1)",
    "python3 -c print(1)",
    "node -e 1",
    "perl -e 1",
    "ruby -e 1",
    "xargs id",
    "sudo id",
)
#: Command words that an allowed entry could be built on, and that the approval tries each adversarial
#: argument with (R2-01). Readers and writers of arbitrary paths are on the list although the built
#: configuration does not allow them: an entry that a maintainer adds must not let them through.
_PROBE_COMMANDS: Final[tuple[str, ...]] = (
    "git",
    "git status",
    "git log",
    "git diff",
    "git show",
    "git add",
    "git commit -m x",
    'git commit -m "x"',
    "git rev-parse",
    "make",
    "npm",
    "npm ls",
    "npm ci --ignore-scripts",
    "npm install --package-lock-only --ignore-scripts",
    "npm exec",
    "npm run",
    "npx",
    "python",
    "python3",
    "cat",
    "grep",
    "grep -r x",
    "ls",
    "find",
    "head",
    "tail",
    "sed",
    "awk",
    "tee",
    "cp",
    "mv",
    "rm",
    "tar",
    "echo",
    "touch",
    "mkdir",
)
#: Arguments that cross the boundary of the worktree or turn a command into a reader or writer of something
#: else: a path outside it (absolute, ``~``, ``..``, an expansion of the shell), a redirection, and the options of
#: git that read or write elsewhere (``--output``, ``--no-index``, ``-C``, ``--git-dir``, ``--work-tree``, ``-c``).
#: ``{home}`` is the home directory of the user who approves. An entry of ``allowedCommands`` must match none of
#: the lines that a word of :data:`_PROBE_COMMANDS` and one of these (or ``--stat`` and one) make.
_ADVERSARIAL_ARGUMENTS: Final[tuple[str, ...]] = (
    "{home}/.aws/credentials",
    "{home}/.aws",
    "{home}/.ssh",
    "{home}/.zshrc",
    "{home}/.config/gh/hosts.yml",
    "/etc/passwd",
    "/tmp/x",
    "/",
    "~",
    "~/.aws",
    "~root/x",
    "../x",
    "./../x",
    "./../../x",
    "./../../../.ssh/id_rsa",
    "x/../../y",
    "x/..",
    "..",
    ".",
    "./x",
    "$HOME",
    "${HOME}/.aws",
    "$(id)",
    "`id`",
    "> x",
    ">> x",
    "< x",
    "2>&1",
    "| sh",
    "; id",
    "&& id",
    "|| id",
    "--output=/tmp/x",
    "--output /tmp/x",
    "--output=x",
    "--output x",
    "-o x",
    "--no-index a b",
    "--no-index /dev/null /etc/passwd",
    "-C /",
    "-C ..",
    "-C x",
    "--git-dir=/x",
    "--git-dir x",
    "--work-tree=/x",
    "-c core.pager=id",
    "-c alias.x=!id",
    "--ext-diff",
    "--exec-path",
    "--upload-pack=id",
    "-f /etc/passwd",
    "--file=/etc/passwd",
    "-F /etc/passwd",
    "-m x -F /etc/passwd",
    "-m x --amend",
    "-m x -C HEAD",
    ".git/config",
    ".git/hooks/pre-commit",
    ".private/x",
    ".env",
    "*",
    "?",
    "x*",
    "-",
    "--",
    "-h",
    "--help",
    "-- /etc/passwd",
    "file:///etc/passwd",
    "x y/../../z",
    "HEAD --output=/tmp/x",
    "HEAD -- /etc/passwd",
)
#: Whole lines of the shapes that the word-then-argument lines above do not make (T4-R3-10): an option placed right
#: after ``git`` (``-c`` names a program that git runs, ``-C`` and ``--git-dir`` leave the worktree), and a command that
#: writes inside the worktree itself (``rm x``, ``tee x``). An entry of ``extra_allowed_commands`` that matches one of
#: them is refused: the built-in entries match none, and the worktree is the agent's to write through the write tool.
_OPTION_AFTER_GIT_LINES: Final[tuple[str, ...]] = (
    "git -c core.fsmonitor=id status",
    "git -c alias.x=!id x",
    "git -c core.hooksPath=x status",
    "git -c a=b status",
    "git -C .. status",
    "git -C x status",
    "git --git-dir=/x status",
    "git --git-dir=x status",
    "git --work-tree=x status",
    "git --exec-path status",
    "git --no-pager status",
    "git -p status",
)
_WRITER_LINES: Final[tuple[str, ...]] = (
    "rm x",
    "rm -r x",
    "rm -rf x",
    "tee x",
    "tee -a x",
    "mkdir x",
    "mkdir -p x/y",
    "touch x",
    "ln -s x y",
    "ln x y",
    "mv x y",
    "cp x y",
    "chmod +x x",
    "dd of=x",
    "sed -i x y",
    "install x y",
    "truncate -s 0 x",
)
#: The npm lines that no entry of ``allowedCommands`` may match (task 5.56): each leaves the three fixed forms by one
#: argument, option, subcommand or path. ``npm exec``, ``npx`` and ``npm run`` start code that the list does not name;
#: ``--prefix``, ``--registry``, ``--userconfig``, ``--cache`` and ``-g`` move what npm reads or writes; without
#: ``--ignore-scripts`` the lifecycle scripts of the project and its dependencies run.
_NPM_LINES: Final[tuple[str, ...]] = (
    "npm install",
    "npm install --package-lock-only",
    "npm install --ignore-scripts",
    "npm ci",
    "npm install --package-lock-only --ignore-scripts left-pad",
    "npm install --package-lock-only --ignore-scripts --prefix /tmp/x",
    "npm install --package-lock-only --ignore-scripts --prefix x",
    "npm install --package-lock-only --ignore-scripts --registry http://127.0.0.1:1/",
    "npm install --package-lock-only --ignore-scripts --userconfig /tmp/x",
    "npm install --package-lock-only --ignore-scripts -g",
    "npm install --package-lock-only --ignore-scripts; id",
    "npm install --package-lock-only --ignore-scripts && id",
    "npm install --package-lock-only --ignore-scripts $(id)",
    "npm install left-pad",
    "npm install -g left-pad",
    "npm install ../x",
    "npm install file:/etc",
    "npm install git+https://127.0.0.1/x.git",
    "npm ci --ignore-scripts --prefix /tmp/x",
    "npm ci --ignore-scripts --cache /tmp/x",
    "npm ci --ignore-scripts --script-shell /bin/sh",
    "npm ci --ignore-scripts --foreground-scripts",
    "npm ls --prefix /",
    "npm ls --all",
    "npm ls ../x",
    "npm exec id",
    "npm exec -- id",
    "npm x id",
    "npx id",
    "npx --yes cowsay",
    "npm run build",
    "npm run-script test",
    "npm test",
    "npm start",
    "npm init x",
    "npm create x",
    "npm config set registry http://127.0.0.1:1/",
    "npm set registry http://127.0.0.1:1/",
    "npm publish",
    "npm login",
    "npm adduser",
    "npm token create",
    "npm pack",
    "npm link",
    "npm rebuild",
    "npm cache clean --force",
    "npm explore x",
    "npm --prefix /tmp/x ls",
    "npm --prefix x ls",
    "npm -C x ls",
    "npm -g ls",
    "npm --registry http://127.0.0.1:1/ ci --ignore-scripts",
    "npm --userconfig /tmp/x ls",
    "npm --workspaces ls",
    "/usr/local/bin/npm ls",
    "./node_modules/.bin/npm ls",
)
#: Characters that no character class of an allowed entry may hold: they are what a path leaves the worktree with,
#: what the shell expands, redirects, chains or quotes, and a newline.
_BOUNDARY_CHARACTERS: Final = frozenset("/~$;&|`<>\\*?(){}!#'\"\n\r\t")
#: The npm lines that ``deniedCommands`` (and the deny rules of CLI V3) must match: what starts other code or moves
#: what npm reads and writes. The three fixed forms stay outside them.
_NPM_REQUIRED_DENIED: Final[tuple[str, ...]] = (
    "npx id",
    "npm exec id",
    "npm run x",
    "npm config set x y",
    "npm install --package-lock-only --ignore-scripts --prefix /tmp/x",
    "npm ci --ignore-scripts --registry http://127.0.0.1:1/",
    "npm -g ls",
)
#: Command lines that ``deniedCommands`` must match: the routes of the first two groups above.
_REQUIRED_DENIED: Final[tuple[str, ...]] = (
    "curl http://127.0.0.1:1/",
    "wget http://127.0.0.1:1/",
    "gh auth token",
    "aws sts get-caller-identity",
    "ssh host",
    "nc 127.0.0.1 1",
    "git push origin HEAD",
    "git config alias.x !id",
    "git remote add x y",
    "git worktree add x",
    "bash -c id",
    "sh -c id",
    *_NPM_REQUIRED_DENIED,
)
#: ``deniedCommands`` of the configuration that :func:`build_agent_config` builds.
_DENIED_COMMANDS: Final[tuple[str, ...]] = (
    r"git (?:push|config|remote|worktree|update-ref|symbolic-ref|checkout|switch|reset|stash|clean|submodule|fetch|pull)(?: .*)?",
    r"gh(?: .*)?",
    r"aws(?: .*)?",
    r"(?:curl|wget|ssh|scp|sftp|nc|ncat|telnet|ftp|rsync|sudo|xargs|env|printenv)(?: .*)?",
    r"(?:ba|z|da)?sh(?: .*)?",
    r"(?:python3?|node|perl|ruby)(?: +-[ce]| +--eval| +--command)(?: .*)?",
    r"npx(?: .*)?",
    r"npm(?: .*)? +(?:exec|x|run|run-script|rum|urn|start|stop|restart|test|t|init|create|config|c|set|get|publish|login|adduser|token|pack|link|ln|rebuild|rb|cache|explore|edit|prefix|root|bin)(?: .*)?",
    r"npm .*--(?:prefix|registry|userconfig|globalconfig|cache|script-shell|workspaces?|global|location|foreground-scripts).*",
    r"npm(?: .*)? -[gC](?: .*)?",
)
#: One name of a path below the worktree: it does not start with ``-`` (so that no option can pass as a path),
#: ``.`` or ``/``, and has no ``..``. A path is names joined by ``/`` with one extension at most.
_NAME = r"[A-Za-z0-9_][A-Za-z0-9_-]*"
_PATH = rf"{_NAME}(?:/{_NAME})*(?:\.[A-Za-z0-9]+)?"
_READ_FLAG = r"(?:--stat|--name-only|--name-status|--oneline|--no-color|--cached|--short|-p)"
#: The text of a commit message: letters, digits, space and a few marks, inside double quotes.
_MESSAGE = r'"[A-Za-z0-9_:,.= -]+"'
#: ``allowedCommands`` of the configuration that :func:`build_agent_config` builds (R2-01). Not one entry holds a
#: wildcard of the regular-expression kind (``.*``, a negated class, ``\S``): each is the whole command with the shape
#: of every argument written out. A path is relative and made of plain names, so that ``..``, a leading ``/``, ``~``
#: and an expansion cannot be written; an option is one that is listed. ``grep``, ``ls`` and ``cat`` are not here
#: because a shell command is not bound by ``read.deniedPaths``: the reads belong to the read tool.
_ALLOWED_COMMANDS: Final[tuple[str, ...]] = (
    rf"git (?:status|log|diff|show)(?: {_READ_FLAG})*(?: {_PATH})*",
    r"git add -A",
    rf"git add(?: {_PATH})+",
    rf"git commit(?: --allow-empty)?(?: -q)? -m {_MESSAGE}",
    r"git rev-parse --short HEAD",
    r"make [a-z0-9][a-z0-9_-]*",
    rf"python3? {_NAME}(?:/{_NAME})*\.py",
    # npm (task 5.56): three whole lines. The lifecycle scripts of the project and of its dependencies do not run, so
    # the lock file is written without starting code; ``npm_config_*`` of the run (command.child_env) pins the
    # registry, the cache and the configuration files.
    r"npm install --package-lock-only --ignore-scripts",
    r"npm ci --ignore-scripts",
    r"npm ls",
)
#: The shell commands that CLI V3 may allow without asking: literal lines only, because a shell rule of V3 is a glob
#: in which ``*`` stands for any text, and a glob cannot say that an argument is a path below the worktree (R2-03).
_V3_ALLOWED_SHELL: Final[tuple[str, ...]] = (
    "git status",
    "git status --short",
    "git diff",
    "git diff --stat",
    "git log --oneline",
    "git add -A",
    "git rev-parse --short HEAD",
    "make test",
    "npm install --package-lock-only --ignore-scripts",
    "npm ci --ignore-scripts",
    "npm ls",
)
#: Shell rules of CLI V3 that deny (``*`` is any text; a deny wins over every allow, in every scope). They state what a
#: glob can say: whole commands and options that cross the boundary. Reads of files go through the read tool, which
#: ``fs_read`` rules bind, so the readers of a shell are denied as a class.
_V3_DENIED_SHELL: Final[tuple[str, ...]] = (
    "git push*",
    "git config*",
    "git remote*",
    "git worktree*",
    "git update-ref*",
    "git symbolic-ref*",
    "git checkout*",
    "git switch*",
    "git reset*",
    "git stash*",
    "git clean*",
    "git submodule*",
    "git fetch*",
    "git pull*",
    "git -*",
    "git * --output*",
    "git * --no-index*",
    "git * --git-dir*",
    "git * --work-tree*",
    "git * -C *",
    "git * -c *",
    "gh*",
    "aws*",
    "curl*",
    "wget*",
    "ssh*",
    "scp*",
    "sftp*",
    "nc *",
    "ncat*",
    "telnet*",
    "ftp *",
    "rsync*",
    "sudo*",
    "xargs*",
    "env*",
    "printenv*",
    "sh*",
    "bash*",
    "zsh*",
    "dash*",
    "python* -*",
    "node*",
    "perl*",
    "ruby*",
    "cat*",
    "head*",
    "tail*",
    "less*",
    "more*",
    "grep*",
    "egrep*",
    "fgrep*",
    "rg*",
    "find*",
    "ls*",
    "sed*",
    "awk*",
    "tee*",
    "cp*",
    "mv*",
    "rm*",
    "dd*",
    "tar*",
    "zip*",
    "unzip*",
    "base64*",
    "xxd*",
    "od *",
    "strings*",
    "ln*",
    "chmod*",
    "chown*",
    "open*",
    "osascript*",
    "launchctl*",
    "security*",
    "defaults*",
    "npx*",
    "npm exec*",
    "npm x *",
    "npm run*",
    "npm rum*",
    "npm start*",
    "npm test*",
    "npm init*",
    "npm create*",
    "npm config*",
    "npm set *",
    "npm publish*",
    "npm login*",
    "npm adduser*",
    "npm token*",
    "npm pack*",
    "npm link*",
    "npm rebuild*",
    "npm cache*",
    "npm explore*",
    "npm -g*",
    "npm * -g*",
    "npm *-C *",
    "npm *--prefix*",
    "npm *--registry*",
    "npm *--userconfig*",
    "npm *--globalconfig*",
    "npm *--cache*",
    "npm *--script-shell*",
    "npm *--global*",
    "npm *--location*",
    "npm *--workspace*",
    "npm *--foreground-scripts*",
)
#: Command lines that the V3 deny rules must match (the approval tries each against the rules, as globs).
_V3_REQUIRED_DENIED: Final[tuple[str, ...]] = (
    *_FORBIDDEN_ALLOWED,
    "cat /home/u/.aws/credentials",
    "grep -r AKIA /home/u/.aws",
    "ls /home/u/.ssh",
    "find / -name id_rsa",
    "git diff --no-index /dev/null /etc/passwd",
    "git show --output=/tmp/x HEAD",
    "git log --output=/tmp/x",
    "git -C / status",
    "git -c core.pager=id status",
    "python3 -c print(1)",
    "tee /tmp/x",
    "cp a /tmp/x",
    *_NPM_REQUIRED_DENIED,
)
#: Capabilities that the allow rules of a V3 configuration may name. A meta-capability (``all``, ``builtin``,
#: ``filesystem``) or another capability would grant more than the three tools of the ceiling.
_V3_RULE_CAPABILITIES: Final = frozenset({"fs_read", "fs_write", "shell"})
_V3_META_CAPABILITIES: Final = frozenset({"all", "builtin", "filesystem"})


def settings_problems(
    document: Mapping[str, Any], tools: Iterable[object], *, home: str | None = None
) -> list[tuple[str, str]]:
    """Check the ``toolsSettings`` of an agent configuration against what the tools it lists can reach.

    Which checks apply follows the tools that the configuration lists (``tools`` and
    ``allowedTools`` together):

    - A write tool needs ``toolsSettings.write.deniedPaths`` to hold every entry of
      :data:`WRITE_DENIED_PATHS`, and ``write.allowedPaths`` to be a non-empty list of
      entries below the working directory (each starts with ``./``).
    - A read tool needs ``toolsSettings.read.deniedPaths`` to hold every entry of
      :data:`READ_DENIED_PATHS`.
    - ``allowedTools`` holds no write or shell tool. ``kiro-cli`` runs a tool listed there without the
      check that ``write.allowedPaths`` and ``shell.denyByDefault`` make: 2.32.0 ran ``uname -s > file``
      and wrote ``../outside.txt`` with both trusted, and refused both with ``fs_read`` alone (selftest
      T7 and T8 and a throwaway comparison, 2026-11-15). ``deniedPaths`` and ``deniedCommands`` applied
      either way.
    - A shell tool needs ``toolsSettings.shell.denyByDefault`` to be ``true``,
      ``autoAllowReadonly`` not ``true`` (read-only commands, such as ``cat`` of a credential
      file, would then be allowed without a rule), ``deniedCommands`` that match each command
      line of :data:`_REQUIRED_DENIED`, and ``allowedCommands`` of which no entry
      (a) holds a wildcard of the regular-expression kind or a character class that reaches a
      character of :data:`_BOUNDARY_CHARACTERS` (R2-01: the entries are fixed forms, not
      patterns that a path or an option can be fitted into),
      (b) matches a line of :data:`_FORBIDDEN_ALLOWED`, or
      (c) matches any line that a word of :data:`_PROBE_COMMANDS` and an argument of
      :data:`_ADVERSARIAL_ARGUMENTS` make: the entries are tried, not read.
    - ``permissions.rules`` (what CLI V3 reads, whose manual calls ``toolsSettings`` legacy and
      ignored) must say the same: a deny rule for each path of the two lists above and for each
      command line of :data:`_V3_REQUIRED_DENIED`, and allow rules that are literal command
      lines and paths below ``./`` only (R2-03). Both are required, so that a configuration
      passes only where either reading of it holds.

    Settings are read under the canonical names ``write``, ``read`` and ``shell`` only. A
    command entry is tried with Python's ``re`` as a full match; the regular-expression engine
    of ``kiro-cli`` is not Python's, so a form that the two read differently (look-around,
    which ``kiro-cli`` does not support, or an entry that only one reads as a pattern) is a
    difference that this check cannot see.

    Args:
        document: The parsed agent configuration.
        tools: The tool names of ``tools`` and ``allowedTools``; names that are not ``str`` are
            ignored here (the tool-ceiling check reports them).
        home: The home directory of the user who approves; the adversarial lines name its credential
            directories. ``None`` uses a placeholder home.

    Returns:
        ``(check, detail)`` for every failed check, in a fixed order; empty when it passes.
    """
    names = {tool for tool in tools if isinstance(tool, str)}
    settings = document.get("toolsSettings")
    problems: list[tuple[str, str]] = []
    trusted = document.get("allowedTools")
    if isinstance(trusted, list):
        unchecked = sorted({tool for tool in trusted if isinstance(tool, str)} & names & (_WRITE_TOOLS | _SHELL_TOOLS))
        if unchecked:
            problems.append(
                (
                    "allowedTools",
                    f"{unchecked!r} must not be in allowedTools: kiro-cli runs a tool listed there without the check "
                    "that write.allowedPaths and shell.denyByDefault make (kiro-cli 2.32.0 ran a command and wrote a "
                    "file that neither allows, 2026-11-15); only deniedPaths and deniedCommands still applied",
                )
            )
    if not isinstance(settings, Mapping):
        settings = {}
    if names & _WRITE_TOOLS:
        problems += _write_problems(settings.get("write"))
    if names & _READ_TOOLS:
        problems += _read_problems(settings.get("read"))
    if names & _SHELL_TOOLS:
        problems += _shell_problems(settings.get("shell"), home or _PLACEHOLDER_HOME)
    if names & (_WRITE_TOOLS | _READ_TOOLS | _SHELL_TOOLS):
        problems += _permission_problems(document.get("permissions"), names)
    return problems


#: The home directory that the adversarial lines use when the caller gives none.
_PLACEHOLDER_HOME: Final = "/Users/example"


def _paths(value: object) -> list[str] | None:
    """A list of ``str``, or ``None`` when ``value`` is not one."""
    if isinstance(value, list) and all(isinstance(entry, str) for entry in value):
        return list(value)
    return None


def _missing(denied: Sequence[str], required: Sequence[str]) -> list[str]:
    """The entries of ``required`` that ``denied`` does not hold, by exact text."""
    return [entry for entry in required if entry not in denied]


def _write_problems(section: object) -> list[tuple[str, str]]:
    """The checks of ``toolsSettings.write``."""
    problems: list[tuple[str, str]] = []
    if not isinstance(section, Mapping):
        return [
            ("toolsSettings.write", "must be an object with allowedPaths and deniedPaths; the write tool is listed")
        ]
    denied = _paths(section.get("deniedPaths"))
    if denied is None:
        problems.append(("toolsSettings.write.deniedPaths", "must be a list of paths"))
    else:
        missing = _missing(denied, WRITE_DENIED_PATHS)
        if missing:
            problems.append(("toolsSettings.write.deniedPaths", f"does not hold {missing!r}"))
    allowed = _paths(section.get("allowedPaths"))
    if not allowed:
        problems.append(
            ("toolsSettings.write.allowedPaths", 'must be a non-empty list of paths below ./, like ["./**"]')
        )
    else:
        outside = [entry for entry in allowed if not entry.startswith("./")]
        if outside:
            problems.append(("toolsSettings.write.allowedPaths", f"{outside!r} are not below ./"))
    return problems


def _read_problems(section: object) -> list[tuple[str, str]]:
    """The checks of ``toolsSettings.read``."""
    if not isinstance(section, Mapping):
        return [("toolsSettings.read", "must be an object with deniedPaths; the read tool is listed")]
    denied = _paths(section.get("deniedPaths"))
    if denied is None:
        return [("toolsSettings.read.deniedPaths", "must be a list of paths")]
    missing = _missing(denied, READ_DENIED_PATHS)
    if missing:
        return [("toolsSettings.read.deniedPaths", f"does not hold {missing!r}")]
    return []


def _probe_lines(home: str) -> list[str]:
    """Every line that an entry of ``allowedCommands`` must not match (R2-01).
    The fixed lines of :data:`_FORBIDDEN_ALLOWED`, :data:`_OPTION_AFTER_GIT_LINES` and :data:`_WRITER_LINES`, and each word of :data:`_PROBE_COMMANDS` with each of
    :data:`_ADVERSARIAL_ARGUMENTS`, alone and after ``--stat``. ``home`` stands where an argument names it.
    """
    lines = [*_FORBIDDEN_ALLOWED, *_OPTION_AFTER_GIT_LINES, *_WRITER_LINES, *_NPM_LINES]
    for word in _PROBE_COMMANDS:
        for argument in _ADVERSARIAL_ARGUMENTS:
            shown = argument.replace("{home}", home)
            lines.append(f"{word} {shown}")
            lines.append(f"{word} --stat {shown}")
    return lines


def _wildcard_problem(entry: str) -> str | None:
    """Why a regular-expression entry is not a fixed form, or ``None`` (R2-01).
    The entry is parsed by ``re``. A wildcard (``.``), a negated class, a class of a category (``\\S``, ``\\W``) or
    one that holds a character of :data:`_BOUNDARY_CHARACTERS` (also as a range that covers it) leaves an argument
    of any shape. A literal ``.`` after a backslash is a character and is not one of these.
    """
    try:
        parsed = _sre_parse.parse(entry)
    except re.error:
        return None  # reported as not a regular expression by the caller
    return _walk(parsed)


def _walk(items: Iterable[Any]) -> str | None:
    """The first wildcard problem below a parsed pattern."""
    for operation, argument in items:
        name = str(operation)
        if name == "ANY":
            return "holds a wildcard (.)"
        if name == "NOT_LITERAL":
            return "holds a negated character"
        if name == "CATEGORY":
            return "holds a character category (\\S, \\W, \\D)"
        if name == "IN":
            for member, value in argument:
                member_name = str(member)
                if member_name == "NEGATE":
                    return "holds a negated character class"
                if member_name == "CATEGORY":
                    return "holds a character category (\\S, \\W, \\D)"
                low, high = value if member_name == "RANGE" else (value, value)
                reached = sorted(char for char in _BOUNDARY_CHARACTERS if low <= ord(char) <= high)
                if reached:
                    return f"holds a character class that reaches {reached!r}"
        elif name == "LITERAL":
            continue
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            problem = _walk(argument[2])
            if problem is not None:
                return problem
        elif name in ("SUBPATTERN",):
            problem = _walk(argument[-1])
            if problem is not None:
                return problem
        elif name == "BRANCH":
            for alternative in argument[1]:
                problem = _walk(alternative)
                if problem is not None:
                    return problem
        elif name in ("ATOMIC_GROUP",):
            problem = _walk(argument)
            if problem is not None:
                return problem
        elif name in ("ASSERT", "ASSERT_NOT", "GROUPREF", "GROUPREF_EXISTS"):
            return f"holds {name.lower()} (look-around and back references are not supported by kiro-cli)"
    return None


def _glob_matches(patterns: Sequence[str], line: str) -> bool:
    """Whether a shell rule of CLI V3 matches ``line``: ``*`` is any text, every other character itself."""
    for pattern in patterns:
        expression = ".*".join(re.escape(part) for part in pattern.split("*"))
        if re.fullmatch(expression, line, re.DOTALL):
            return True
    return False


def _rules(value: object) -> list[Mapping[str, Any]] | None:
    """The rules of ``permissions.rules``, or ``None`` when it is not a list of objects."""
    if isinstance(value, Mapping):
        value = value.get("rules")
    if isinstance(value, list) and all(isinstance(rule, Mapping) for rule in value):
        return list(value)
    return None


def _match_list(rule: Mapping[str, Any]) -> list[str]:
    """The ``match`` of a rule as a list of ``str`` (a missing or malformed one is empty)."""
    match = rule.get("match")
    return list(match) if isinstance(match, list) and all(isinstance(entry, str) for entry in match) else []


def _permission_problems(section: object, names: set[str]) -> list[tuple[str, str]]:
    """The checks of ``permissions.rules``, the part that CLI V3 reads (R2-03)."""
    rules = _rules(section)
    if rules is None:
        return [
            (
                "permissions.rules",
                "must be a list of rules; CLI V3 ignores toolsSettings, so the limits are stated here too",
            )
        ]
    problems: list[tuple[str, str]] = []
    denied = {
        capability: [
            entry
            for rule in rules
            if rule.get("capability") == capability and rule.get("effect") == "deny"
            for entry in _match_list(rule)
        ]
        for capability in ("fs_read", "fs_write", "shell")
    }
    if names & _WRITE_TOOLS:
        missing = _missing(denied["fs_write"], WRITE_DENIED_PATHS)
        if missing:
            problems.append(("permissions.rules.fs_write", f"does not deny {missing!r}"))
    if names & _READ_TOOLS:
        missing = _missing(denied["fs_read"], READ_DENIED_PATHS)
        if missing:
            problems.append(("permissions.rules.fs_read", f"does not deny {missing!r}"))
    if names & _SHELL_TOOLS:
        unmatched = [line for line in _V3_REQUIRED_DENIED if not _glob_matches(denied["shell"], line)]
        if unmatched:
            problems.append(("permissions.rules.shell", f"does not deny {unmatched!r}"))
    for rule in rules:
        capability, effect = rule.get("capability"), rule.get("effect")
        if effect != "allow":
            continue
        if capability in _V3_META_CAPABILITIES or capability not in _V3_RULE_CAPABILITIES:
            problems.append(
                ("permissions.rules.allow", f"allows the capability {capability!r}, which is not one of the tools")
            )
            continue
        if rule.get("exclude"):
            continue
        for entry in _match_list(rule):
            if capability == "shell" and any(char in entry for char in "*?[]{}"):
                problems.append(
                    (
                        "permissions.rules.shell",
                        f"allow {entry!r} is a glob; a shell allow rule must be a literal command",
                    )
                )
            elif capability in ("fs_read", "fs_write") and not entry.startswith("./"):
                problems.append((f"permissions.rules.{capability}", f"allow {entry!r} is not below ./"))
        if not _match_list(rule) and capability in _V3_RULE_CAPABILITIES:
            problems.append((f"permissions.rules.{capability}", "an allow rule without match allows everything"))
    return problems


def _matches(entries: Sequence[str], line: str) -> bool:
    """Whether any entry, as a regular expression anchored at both ends, matches ``line``.

    An entry that is not a valid expression counts as no match for ``allowedCommands`` use and
    is reported by the caller through :func:`_invalid`.
    """
    for entry in entries:
        try:
            if re.fullmatch(entry, line):
                return True
        except re.error:
            continue
    return False


#: Constructs that Python's ``re`` reads and the regular expressions of ``kiro-cli`` do not: look-around and
#: back-references (the Rust ``regex`` crate has neither). An entry of ``deniedCommands`` with a look-behind made
#: ``kiro-cli`` 2.32.0 refuse ``git add README.md`` in the selftest of 2026-11-16 (task 5.56); a check in Python alone
#: would have passed it.
_UNSUPPORTED_SYNTAX: Final = re.compile(r"\(\?<?[=!]|\(\?P=|\\[1-9]|\\k<")


def _dialect_problem(entry: str) -> str | None:
    """Why ``kiro-cli`` cannot read ``entry``, or ``None`` (the check is on the text, outside character classes too)."""
    if _UNSUPPORTED_SYNTAX.search(entry):
        return "uses a look-around or a back-reference, which kiro-cli does not read"
    return None


def _invalid(entries: Sequence[str]) -> list[str]:
    """The entries that are not valid regular expressions, in Python or in the dialect of ``kiro-cli``."""
    bad: list[str] = []
    for entry in entries:
        try:
            re.compile(entry)
        except re.error:
            bad.append(entry)
            continue
        if _dialect_problem(entry) is not None:
            bad.append(entry)
    return bad


def _shell_problems(section: object, home: str) -> list[tuple[str, str]]:
    """The checks of ``toolsSettings.shell``."""
    if not isinstance(section, Mapping):
        return [("toolsSettings.shell", "must be an object with denyByDefault, allowedCommands and deniedCommands")]
    problems: list[tuple[str, str]] = []
    if section.get("denyByDefault") is not True:
        problems.append(("toolsSettings.shell.denyByDefault", f"must be true, got {section.get('denyByDefault')!r}"))
    if section.get("autoAllowReadonly") is True:
        problems.append(
            (
                "toolsSettings.shell.autoAllowReadonly",
                "must not be true: read-only commands such as cat of a credential file would need no rule",
            )
        )
    allowed = _paths(section.get("allowedCommands"))
    denied = _paths(section.get("deniedCommands"))
    if allowed is None:
        problems.append(("toolsSettings.shell.allowedCommands", "must be a list of regular expressions"))
    else:
        bad = _invalid(allowed)
        if bad:
            problems.append(("toolsSettings.shell.allowedCommands", f"{bad!r} are not regular expressions"))
        for entry in allowed:
            reason = _wildcard_problem(entry)
            if reason is not None:
                problems.append(("toolsSettings.shell.allowedCommands", f"{entry!r} {reason}"))
        reached = [line for line in _probe_lines(home) if _matches(allowed, line)]
        if reached:
            problems.append(
                (
                    "toolsSettings.shell.allowedCommands",
                    f"allow {len(reached)} adversarial lines, such as {reached[:4]!r}",
                )
            )
    if denied is None:
        problems.append(("toolsSettings.shell.deniedCommands", "must be a list of regular expressions"))
    else:
        bad = _invalid(denied)
        if bad:
            problems.append(("toolsSettings.shell.deniedCommands", f"{bad!r} are not regular expressions"))
        unmatched = [line for line in _REQUIRED_DENIED if not _matches(denied, line)]
        if unmatched:
            problems.append(("toolsSettings.shell.deniedCommands", f"do not deny {unmatched!r}"))
    return problems


def _permission_rules(*, change: bool, extra_allowed_commands: Sequence[str]) -> list[dict[str, Any]]:
    """The ``permissions.rules`` of CLI V3 that say what ``toolsSettings`` says for CLI 2.x (R2-03).
    Deny rules decide before every allow rule and in every scope, so they are what V3 enforces whatever
    ``--trust-tools`` grants. The allow rules are literal command lines and paths below ``./``: a glob of V3 cannot
    say that an argument is a path below the worktree, so no allow rule carries one. A command that is in neither list
    asks, which a run without a person to ask cannot pass (an unverified reading of the manual).
    ``extra_allowed_commands`` are regular expressions for CLI 2.x; only the ones without a metacharacter become
    allow rules of V3.
    """
    rules: list[dict[str, Any]] = [
        {"capability": "fs_read", "match": ["./**"], "effect": "allow"},
        {"capability": "fs_read", "match": list(READ_DENIED_PATHS), "effect": "deny"},
    ]
    if change:
        literal = [entry for entry in extra_allowed_commands if re.fullmatch(r"[A-Za-z0-9_ ./=:,@-]+", entry)]
        rules += [
            {"capability": "fs_write", "match": ["./**"], "effect": "allow"},
            {"capability": "fs_write", "match": list(WRITE_DENIED_PATHS), "effect": "deny"},
            {"capability": "shell", "match": [*_V3_ALLOWED_SHELL, *literal], "effect": "allow"},
            {"capability": "shell", "match": list(_V3_DENIED_SHELL), "effect": "deny"},
        ]
    return rules


def build_agent_config(
    mode: str,
    *,
    name: str,
    guard_command: str | None = None,
    extra_allowed_commands: Iterable[str] = (),
) -> dict[str, Any]:
    """Build an agent configuration for a mode that :func:`settings_problems` accepts.

    Change mode lists ``fs_read``, ``fs_write`` and ``shell`` in ``tools`` (``allowedTools`` is
    ``fs_read`` alone in both modes, see :func:`settings_problems`) and carries the two PreToolUse
    guards when ``guard_command`` is given. Query mode lists ``fs_read`` only. Neither has an
    MCP server or reads ``mcp.json``.

    Args:
        mode: ``change`` or ``query``.
        name: The agent name (the file name without ``.json``).
        guard_command: The command line of the guard wrapper for ``shell`` and ``fs_write``
            (change mode only).
        extra_allowed_commands: More ``allowedCommands`` entries, for the verification commands
            of one repository. They are checked like the built-in ones when the approval is
            made, so an entry that reaches the network is refused there.

    Returns:
        A new JSON-ready dictionary.

    Raises:
        ValueError: ``mode`` is neither ``change`` nor ``query``, or ``guard_command`` is given
            for query mode.
    """
    if mode not in ("change", "query"):
        raise ValueError(f"mode must be change or query, not {mode!r}")
    document: dict[str, Any] = {
        "name": name,
        "description": f"Handoff_Harness {mode} mode: no MCP servers, no mcp.json, restricted toolsSettings",
        "prompt": None,
        "mcpServers": {},
        "toolAliases": {},
        "resources": [],
        "includeMcpJson": False,
        "model": None,
    }
    if mode == "query":
        if guard_command is not None:
            raise ValueError("guard_command is for change mode")
        tools = ["fs_read"]
        document["toolsSettings"] = {"read": {"deniedPaths": list(READ_DENIED_PATHS)}}
        document["permissions"] = {"rules": _permission_rules(change=False, extra_allowed_commands=())}
    else:
        tools = ["fs_read", "fs_write", "shell"]
        document["toolsSettings"] = {
            "read": {"deniedPaths": list(READ_DENIED_PATHS)},
            "write": {"allowedPaths": ["./**"], "deniedPaths": list(WRITE_DENIED_PATHS)},
            "shell": {
                "denyByDefault": True,
                "autoAllowReadonly": False,
                "allowedCommands": [*_ALLOWED_COMMANDS, *extra_allowed_commands],
                "deniedCommands": list(_DENIED_COMMANDS),
            },
        }
        document["permissions"] = {
            "rules": _permission_rules(change=True, extra_allowed_commands=tuple(extra_allowed_commands))
        }
        if guard_command is not None:
            document["hooks"] = {
                "preToolUse": [
                    {"command": guard_command, "matcher": "shell"},
                    {"command": guard_command, "matcher": "fs_write"},
                ]
            }
    document["tools"] = list(tools)
    # Only the read tool is trusted: a trusted write or shell tool skips allowedPaths and denyByDefault.
    document["allowedTools"] = ["fs_read"]
    return document

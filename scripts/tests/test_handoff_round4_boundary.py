"""Layer 0 and the harness's own git, after the round 3 review (T4-R3-01 to T4-R3-03, T4-R3-05, T4-R3-07 to T4-R3-10).
The reproduction of T4-R3-01 comes first. An agent under layer 0 can write its worktree, and the ``.git`` of a linked
worktree is a file of one line that names a git directory. If the agent points it at a repository it made, the git of
the harness (outside the sandbox) reads that repository's configuration and runs ``core.fsmonitor`` with the user's
rights. The tests that run ``sandbox-exec`` are for macOS and skip elsewhere. Everything happens in throwaway
directories; no ``kiro-cli`` starts and no real home, repository or credential is touched.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from handoff import agent_policy, command, runner, safety, state
from handoff import os_boundary as osb
from test_handoff_change_integration import CHANGE, history, run_change

if TYPE_CHECKING:
    from conftest import HandoffSandbox

REAL_BOUNDARY = sys.platform == "darwin" and os.access(osb.SANDBOX_EXEC, os.X_OK)
needs_sandbox_exec = pytest.mark.skipif(not REAL_BOUNDARY, reason="sandbox-exec exists on macOS only")
GIT_ENV_DROPPED = ("GIT_",)


def clean_env(home: Path) -> dict[str, str]:
    """The environment of a git that reads no configuration of the machine."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(GIT_ENV_DROPPED)}
    env.update(HOME=str(home), GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    return env


def git(env: dict[str, str], *args: str, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    """Run git with the given environment and require success."""
    done = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgSign=false", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert done.returncode == 0, done.stderr.decode()
    return done


class Tree:
    """A throwaway home, a main working tree with one commit, and a linked worktree ``wt`` on ``handoff/x``."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = Path(os.path.realpath(tmp_path))
        self.home = self.root / "home"
        self.main = self.root / "main"
        self.wt = self.root / "wt"
        for sub in (".aws", ".ssh", ".config/git", "Library/LaunchAgents", ".local/bin"):
            (self.home / sub).mkdir(parents=True)
        self.env = clean_env(self.home)
        self.main.mkdir()
        git(self.env, "init", "-q", "--initial-branch=main", cwd=self.main)
        (self.main / "README.md").write_text("x", encoding="utf-8")
        git(self.env, "add", "README.md", cwd=self.main)
        git(self.env, "commit", "-q", "-m", "first", cwd=self.main)
        git(self.env, "worktree", "add", "-q", "-b", "handoff/x", str(self.wt), cwd=self.main)
        self.pwned = self.home / ".aws" / "PWNED"

    def profile(self, **extra: object) -> Path:
        """Write the profile of a run of the worktree; ``extra`` goes to :func:`osb.build_profile`."""
        text = osb.build_profile(
            home=str(self.home),
            main_trees=[str(self.main)],
            allow_write=[str(self.wt)],
            **extra,  # type: ignore[arg-type]
        )
        path = self.root / "p.sb"
        path.write_text(text, encoding="utf-8")
        return path

    def sandboxed(self, profile: Path, script: str) -> subprocess.CompletedProcess[bytes]:
        """Run a shell script in the worktree under the profile."""
        return subprocess.run(
            [osb.SANDBOX_EXEC, "-f", str(profile), "/bin/sh", "-c", script],
            cwd=self.wt,
            env=self.env,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    def redirect_script(self) -> str:
        """What the agent runs: make a repository with ``core.fsmonitor`` and point ``.git`` at it."""
        return textwrap.dedent(
            f"""
            git init -q evilrepo || exit 11
            printf '[core]\\n\\tfsmonitor = touch "{self.pwned}" #\\n' >> evilrepo/.git/config || exit 12
            printf 'gitdir: {self.wt}/evilrepo/.git\\n' > .git
            """
        )


@needs_sandbox_exec
def test_reproduction_the_old_profile_lets_the_agent_redirect_the_worktree_git_file(tmp_path: Path) -> None:
    """Control: without the worktree rules the redirect succeeds and the harness's plain ``git status`` runs it.
    This is the review's reproduction. It must keep passing: it shows that the attack is real on this machine, so that
    the tests below mean something.
    """
    tree = Tree(tmp_path)
    done = tree.sandboxed(tree.profile(), tree.redirect_script())
    assert done.returncode == 0, done.stderr
    assert not tree.pwned.exists()  # the sandbox itself does not let the agent write there
    plain = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(tree.wt), "status", "--porcelain=v1", "-z"],
        env=tree.env,
        capture_output=True,
        check=False,
    )
    assert plain.returncode == 0
    assert tree.pwned.exists(), "git outside the sandbox runs core.fsmonitor of the redirected repository"


@needs_sandbox_exec
def test_the_profile_with_worktrees_refuses_the_redirect(tmp_path: Path) -> None:
    """T4-R3-01 (a): the ``.git`` file cannot be overwritten, and so the harness's git never reads the other repository."""
    tree = Tree(tmp_path)
    before = (tree.wt / ".git").read_bytes()
    done = tree.sandboxed(tree.profile(worktrees=[str(tree.wt)]), tree.redirect_script())
    assert done.returncode != 0
    assert (tree.wt / ".git").read_bytes() == before
    plain = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(tree.wt), "status", "--porcelain=v1", "-z"],
        env=tree.env,
        capture_output=True,
        check=False,
    )
    assert plain.returncode == 0 and not tree.pwned.exists()


@needs_sandbox_exec
@pytest.mark.parametrize(
    "script",
    [
        'printf "x" > "{wt}/.git"',
        'rm -f "{wt}/.git"',
        'mv "{wt}/.git" "{wt}/.git.bak"',
        'printf "/elsewhere\\n" >> "{gd}/commondir"',
        'printf "/elsewhere\\n" > "{gd}/commondir.new" && mv "{gd}/commondir.new" "{gd}/commondir"',
        'printf "/elsewhere/.git\\n" > "{gd}/gitdir"',
        'printf "[core]\\n" > "{gd}/config.worktree"',
        'printf "x" > "{gd}/../other/commondir"',
    ],
)
def test_the_worktree_git_pointers_cannot_be_written(tmp_path: Path, script: str) -> None:
    """The file, ``commondir``, ``gitdir`` and ``config.worktree`` of a worktree, and those of another worktree."""
    tree = Tree(tmp_path)
    git(tree.env, "worktree", "add", "-q", "-b", "handoff/other", str(tree.root / "other"), cwd=tree.main)
    gd = tree.main / ".git" / "worktrees" / "wt"
    text = script.format(wt=tree.wt, gd=gd)
    done = tree.sandboxed(tree.profile(worktrees=[str(tree.wt)]), text)
    assert done.returncode != 0, text
    assert (tree.wt / ".git").read_text(encoding="utf-8").startswith("gitdir: ")
    assert (gd / "commondir").read_text(encoding="utf-8") == "../..\n"
    assert not (gd / "config.worktree").exists()


@needs_sandbox_exec
def test_a_commit_in_the_worktree_works_and_prints_no_packed_refs_error(tmp_path: Path) -> None:
    """T4-R3-01 (a) keeps ``git add`` and ``git commit`` working; T4-R3-09: no ``packed-refs.lock`` message."""
    tree = Tree(tmp_path)
    profile = tree.profile(worktrees=[str(tree.wt)])
    script = (
        'printf "new" > a.txt && git add a.txt && '
        "git -c user.name=t -c user.email=t@example.com -c commit.gpgSign=false commit -q -m done"
    )
    done = tree.sandboxed(profile, script)
    assert done.returncode == 0, done.stderr
    assert b"packed-refs" not in done.stderr
    head = git(tree.env, "rev-parse", "handoff/x", cwd=tree.main).stdout.strip()
    assert head != git(tree.env, "rev-parse", "main", cwd=tree.main).stdout.strip()


@needs_sandbox_exec
def test_the_lock_of_packed_refs_does_not_let_a_run_rewrite_a_ref_of_main(tmp_path: Path) -> None:
    """Only the lock file is allowed; the rename onto ``packed-refs`` and writing ``refs/heads/main`` stay denied."""
    tree = Tree(tmp_path)
    profile = tree.profile(worktrees=[str(tree.wt)])
    git_dir = tree.main / ".git"
    script = f'printf "x" > "{git_dir}/packed-refs.lock" && mv "{git_dir}/packed-refs.lock" "{git_dir}/packed-refs"'
    done = tree.sandboxed(profile, script)
    assert done.returncode != 0
    assert not (git_dir / "packed-refs").exists()
    forged = tree.sandboxed(profile, f'printf "0000" > "{git_dir}/refs/heads/main"')
    assert forged.returncode != 0
    git(tree.env, "rev-parse", "main", cwd=tree.main)  # still a valid ref


# ---------------------------------------------------------------------------------------------
# T4-R3-01 (b): the harness's git does not run what a repository's configuration names
# ---------------------------------------------------------------------------------------------
def planted_repository(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    """A repository whose local configuration names commands for ``core.fsmonitor`` and ``core.hooksPath``."""
    tree = Tree(tmp_path)
    marker = tree.root / "marker"
    hooks = tree.root / "hooks"
    hooks.mkdir()
    for name in ("post-checkout", "pre-push", "reference-transaction"):
        hook = hooks / name
        hook.write_text(f'#!/bin/sh\ntouch "{marker}-hook"\n', encoding="utf-8")
        hook.chmod(0o755)
    with open(tree.main / ".git" / "config", "a", encoding="utf-8") as handle:
        handle.write(f'[core]\n\tfsmonitor = touch "{marker}-fsmonitor" #\n\thooksPath = {hooks}\n')
        handle.write(f'[alias]\n\tst = !touch "{marker}-alias"\n')
        handle.write(f'[core]\n\tpager = touch "{marker}-pager" #\n')
    return tree.main, marker, tree.env


def test_the_entry_point_of_git_puts_the_hardening_in_front(tmp_path: Path) -> None:
    """``harden_git`` adds the options after the program and leaves other programs alone."""
    argv, env = command.harden_git(("git", "-C", "/w", "status"), {"PATH": "/usr/bin"})
    assert argv[0] == "git" and argv[-3:] == ("-C", "/w", "status")
    joined = " ".join(argv)
    assert "core.fsmonitor=false" in joined and "core.hooksPath=/dev/null" in joined
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    other, same = command.harden_git(("kiro-cli", "chat"), {"A": "b"})
    assert other == ("kiro-cli", "chat") and same == {"A": "b"}
    # a program given by path is git too
    assert command.harden_git(("/usr/bin/git", "status"), {})[0][0] == "/usr/bin/git"
    assert len(command.harden_git(("/usr/bin/git", "status"), {})[0]) > 2


def test_network_commands_keep_the_users_configuration_for_credentials() -> None:
    """A push or ``ls-remote`` needs the credential helper of the user's global configuration; the local ones do not."""
    for sub in ("push", "fetch", "ls-remote"):
        _argv, env = command.harden_git(("git", "-C", "/w", sub, "origin"), {"X": "1"})
        assert "GIT_CONFIG_GLOBAL" not in env, sub
        # the system configuration is off for them too: it is a file below the package prefix (T4-R5-02)
        assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_SYSTEM"] == "/dev/null", sub
    for sub in ("status", "diff", "log", "rev-parse", "cat-file"):
        _argv, env = command.harden_git(("git", "-C", "/w", sub), {})
        assert env["GIT_CONFIG_GLOBAL"] == "/dev/null", sub
    # the configuration listing that the digest of the shared git directory reads keeps the user's global file
    _argv, env = command.harden_git(("git", "-C", "/w", "config", "--show-origin", "--list", "-z"), {})
    assert "GIT_CONFIG_GLOBAL" not in env


def test_harness_git_does_not_run_what_the_repository_configuration_names(tmp_path: Path) -> None:
    """``_run_process`` is the one entry: fsmonitor, a hooks path and a pager of the local configuration do not run."""
    main, marker, env = planted_repository(tmp_path)
    plain = subprocess.run(
        ["git", "-C", str(main), "status", "--porcelain=v1", "-z"], env=env, capture_output=True, check=False
    )
    assert plain.returncode == 0
    assert Path(f"{marker}-fsmonitor").exists(), "control: plain git runs the planted fsmonitor"
    Path(f"{marker}-fsmonitor").unlink()
    for args in (
        ("status", "--porcelain=v1", "-z"),
        ("diff", "--name-only", "HEAD"),
        ("log", "-1", "--format=%H"),
        ("rev-parse", "--verify", "HEAD"),
        ("branch", "--show-current"),
    ):
        result = runner._run_process(
            ("git", "--no-optional-locks", "-C", str(main), *args),
            cwd=str(main),
            env=env,
            timeout_seconds=30,
            kill_grace_seconds=1,
        )
        assert result.exit_code == 0, (args, result.stderr)
    assert not list(marker.parent.glob("marker-*")), "something that the configuration names ran"
    assert result.argv[0] == "git" and "core.fsmonitor=false" not in result.argv  # the record keeps the asked argv


# ---------------------------------------------------------------------------------------------
# T4-R3-01 (3): the pointers of a worktree are checked before the first git
# ---------------------------------------------------------------------------------------------
def test_an_intact_worktree_has_no_gitdir_problem(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    assert runner.worktree_gitdir_problem(str(tree.wt), str(tree.main)) is None


@pytest.mark.parametrize(
    "tamper",
    ["redirect", "symlink", "directory", "commondir", "gitdir", "config.worktree", "removed", "two-lines", "relative"],
)
def test_a_tampered_worktree_pointer_is_found_before_any_git_runs(tmp_path: Path, tamper: str) -> None:
    """The ``.git`` file, ``commondir``, ``gitdir`` and ``config.worktree`` must be what ``git worktree add`` wrote."""
    tree = Tree(tmp_path)
    gd = tree.main / ".git" / "worktrees" / "wt"
    gitfile = tree.wt / ".git"
    if tamper == "redirect":
        git(tree.env, "init", "-q", "evil", cwd=tree.wt)
        gitfile.write_text(f"gitdir: {tree.wt}/evil/.git\n", encoding="utf-8")
    elif tamper == "symlink":
        gitfile.unlink()
        (tree.root / "real-git-file").write_text(gitfile_text(tree), encoding="utf-8")
        gitfile.symlink_to(tree.root / "real-git-file")
    elif tamper == "directory":
        gitfile.unlink()
        gitfile.mkdir()
    elif tamper == "commondir":
        (gd / "commondir").write_text("/elsewhere\n", encoding="utf-8")
    elif tamper == "gitdir":
        (gd / "gitdir").write_text("/elsewhere/.git\n", encoding="utf-8")
    elif tamper == "config.worktree":
        (gd / "config.worktree").write_text("[core]\n", encoding="utf-8")
    elif tamper == "removed":
        gitfile.unlink()
    elif tamper == "two-lines":
        gitfile.write_text(gitfile_text(tree) + "gitdir: /x\n", encoding="utf-8")
    else:
        gitfile.write_text("gitdir: ../main/.git/worktrees/wt\n", encoding="utf-8")
    assert runner.worktree_gitdir_problem(str(tree.wt), str(tree.main)) is not None


def gitfile_text(tree: Tree) -> str:
    return f"gitdir: {tree.main}/.git/worktrees/wt\n"


# ---------------------------------------------------------------------------------------------
# T4-R3-02: sockets of processes that run outside the sandbox
# ---------------------------------------------------------------------------------------------
CONNECT = (
    "import socket,sys\n"
    "s=socket.socket(socket.AF_UNIX)\n"
    "try:\n"
    "    s.connect(sys.argv[1])\n"
    "except OSError as e:\n"
    "    print('DENIED', e.errno); sys.exit(3)\n"
    "print('CONNECTED')\n"
)


SOCKET_NAMES = [
    "docker.sock",
    "agent.sock",
    "S.gpg-agent",
    "podman.sock",
    "containerd.sock",
    # T4-R4-02: names that the earlier list did not match
    "docker.raw.sock",
    "podman-machine-default-api.sock",
    "ssh-agent.sock",
    "com.docker.vmnetd.sock",
    "plain.sock",
]


@needs_sandbox_exec
@pytest.mark.parametrize("name", SOCKET_NAMES)
def test_a_connection_to_any_unix_socket_is_refused(tmp_path: Path, name: str) -> None:
    """T4-R4-02: unix sockets are closed by default, whatever the name; a listener of the test is refused."""
    tree = Tree(tmp_path)
    sock_dir = Path(tempfile_dir(tree))
    server = socket.socket(socket.AF_UNIX)
    try:
        server.bind(str(sock_dir / name))
        server.listen(4)
        profile = tree.profile(worktrees=[str(tree.wt)])
        run = [osb.SANDBOX_EXEC, "-f", str(profile), sys.executable, "-c", CONNECT]
        denied = subprocess.run([*run, str(sock_dir / name)], capture_output=True, check=False)
        assert denied.returncode == 3 and b"DENIED" in denied.stdout, denied.stdout
        plain = subprocess.run([sys.executable, "-c", CONNECT, str(sock_dir / name)], capture_output=True, check=False)
        assert plain.returncode == 0 and b"CONNECTED" in plain.stdout, "control: without the profile it connects"
    finally:
        server.close()
        shutil.rmtree(sock_dir, ignore_errors=True)


@needs_sandbox_exec
def test_closing_the_unix_sockets_keeps_the_network_git_and_name_resolution_working(tmp_path: Path) -> None:
    """T4-R4-02: what a run needs still works under the profile: TCP, name resolution, ``git`` and ``curl``."""
    tree = Tree(tmp_path)
    profile = tree.profile(worktrees=[str(tree.wt)])
    listener = socket.socket(socket.AF_INET)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    try:
        tcp = "import socket,sys; socket.create_connection(('127.0.0.1', int(sys.argv[1])), 5).close(); print('TCP-OK')"
        done = tree.sandboxed(profile, f'{sys.executable} -c "{tcp}" {port}')
        assert done.returncode == 0 and b"TCP-OK" in done.stdout, done.stderr
    finally:
        listener.close()
    resolve = tree.sandboxed(
        profile, f"{sys.executable} -c \"import socket; socket.getaddrinfo('localhost', 80); print('DNS-OK')\""
    )
    assert resolve.returncode == 0 and b"DNS-OK" in resolve.stdout, resolve.stderr
    remote = tree.sandboxed(profile, f'git ls-remote "{tree.main}" HEAD')  # a local transport; no socket of a daemon
    assert remote.returncode == 0, remote.stderr
    curl = tree.sandboxed(profile, "curl --version >/dev/null && echo CURL-OK")
    assert curl.returncode == 0 and b"CURL-OK" in curl.stdout, curl.stderr
    # ssh-add reaches the agent by a unix socket that the profile closes
    sock_dir = Path(tempfile_dir(tree))
    agent = sock_dir / "agent-sock"
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(agent))
    server.listen(1)
    try:
        refused = subprocess.run(
            [osb.SANDBOX_EXEC, "-f", str(profile), "/usr/bin/ssh-add", "-l"],
            env={**tree.env, "SSH_AUTH_SOCK": str(agent)},
            capture_output=True,
            check=False,
        )
        assert b"Operation not permitted" in refused.stderr, refused.stderr
    finally:
        server.close()
        shutil.rmtree(sock_dir, ignore_errors=True)


def tempfile_dir(tree: Tree) -> str:
    """A short directory (a socket path is limited to about 100 characters). The test removes it itself."""
    import tempfile

    path = tempfile.mkdtemp(prefix="s", dir="/tmp")
    os.chmod(path, 0o700)
    return os.path.realpath(path)


def test_the_profile_closes_unix_sockets_by_default_and_names_what_it_allows() -> None:
    """T4-R4-02: a rule that denies every unix socket, then the resolver and the log only."""
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"])
    assert "(deny network-outbound (remote unix-socket))" in text
    allowed = [line for line in text.splitlines() if line.startswith("(allow network-outbound")]
    assert sorted(allowed) == sorted(
        f'(allow network-outbound (remote unix-socket (path-literal "{path}")))'
        for path in ("/private/var/run/mDNSResponder", "/var/run/mDNSResponder", "/private/var/run/syslog")
    )
    assert text.index("(deny network-outbound") < text.index("(allow network-outbound")
    for gone in ("docker|podman", "agent\\.sock", "com\\.apple\\.launchd"):
        assert gone not in text  # the list of names is gone: nothing is allowed by a name that nobody thought of


# ---------------------------------------------------------------------------------------------
# T4-R3-03: the denials that were missing
# ---------------------------------------------------------------------------------------------
def test_the_startup_and_persistence_places_are_closed_for_writing() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"], path_dirs=["/opt/homebrew/bin"])
    for name in (".zlogout", ".bash_login", ".bash_logout", ".inputrc"):
        assert f'(deny file-write* (literal "/Users/u/{name}"))' in text
    for name in (
        ".config/git",
        "Library/LaunchAgents",
        ".local/bin",
        "bin",
        ".zsh_sessions",
        ".config/fish",
        ".config/zsh",
        ".config/environment.d",
    ):
        assert f'(deny file-write* (subpath "/Users/u/{name}"))' in text, name
    assert '(deny file-write* (subpath "/opt/homebrew/bin"))' in text


def test_more_credentials_are_closed_for_reading() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"])
    for name in (".config/op", ".oci", ".azure", ".config/stripe"):
        assert f'(deny file-read* (subpath "/Users/u/{name}"))' in text, name
    # a directory that also holds tools and caches stays readable; its credential file does not
    for name in (
        ".terraform.d/credentials.tfrc.json",
        ".cargo/credentials.toml",
        ".gem/credentials",
        ".m2/settings.xml",
        ".zsh_history",
        ".bash_history",
        ".databrickscfg",
        ".python_history",
        ".psql_history",
    ):
        assert f'(deny file-read* (literal "/Users/u/{name}"))' in text, name
    for name in ("Google/Chrome", "Firefox"):
        assert f'(deny file-read* (subpath "/Users/u/Library/Application Support/{name}"))' in text
    assert '(deny file-read* (subpath "/Users/u/Library/Safari"))' in text


@needs_sandbox_exec
@pytest.mark.parametrize(
    "script",
    [
        'printf x > "{home}/Library/LaunchAgents/x.plist"',
        'printf x > "{home}/.local/bin/git"',
        'printf x > "{home}/.config/git/config"',
        'cat "{home}/.zsh_history"',
    ],
)
def test_the_new_denials_bind_on_this_machine(tmp_path: Path, script: str) -> None:
    tree = Tree(tmp_path)
    (tree.home / ".zsh_history").write_text("secret", encoding="utf-8")
    done = tree.sandboxed(tree.profile(worktrees=[str(tree.wt)]), script.format(home=tree.home))
    assert done.returncode != 0 and b"secret" not in done.stdout
    # the control: the same kinds of operations in the worktree work
    assert tree.sandboxed(tree.profile(worktrees=[str(tree.wt)]), 'printf x > "$PWD/ok.txt"').returncode == 0


def test_the_probes_name_each_new_group_and_each_pointer_of_a_worktree() -> None:
    names = {probe.name for probe in osb.probes(home="/h", main_tree="/m", work="/w")}
    for name in (
        "deny-write-worktree-gitfile",
        "deny-write-worktree-commondir",
        "deny-write-launchagent",
        "deny-write-xdg-git-config",
        "deny-read-history",
        "deny-connect-docker-sock",
        "deny-connect-plain-unix-socket",
        "deny-delete-object",
    ):
        assert name in names, name


@needs_sandbox_exec
def test_the_probes_of_the_runner_bind_on_this_machine(tmp_path: Path) -> None:
    assert runner._verify_os_boundary(osb.OsBoundary(program=osb.SANDBOX_EXEC), str(tmp_path)) == []


# ---------------------------------------------------------------------------------------------
# T4-R3-05: files that steer an agent are the execution surface
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [
        ".kiro/agents/a.md",
        ".kiro/steering/x.md",
        ".kiro/specs/x/tasks.md",
        ".kiro/skills/s/SKILL.md",
        "AGENTS.md",
        "docs/AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        ".github/copilot-instructions.md",
        ".github/instructions/a.instructions.md",
        ".github/prompts/p.prompt.md",
        ".cursor/rules/x.mdc",
        ".cursorrules",
        ".windsurf/rules/x.md",
        ".clinerules/x.md",
        ".continue/config.md",
        ".codex/x.md",
        ".claude/commands/x.md",
        "llms.txt",
        "llms-full.txt",
        "sub/SKILL.md",
        "sub/skill.md",
        ".KIRO/steering/X.md",
    ],
)
def test_a_file_that_steers_an_agent_is_the_execution_surface(path: str) -> None:
    assert safety.execution_surface([path]) == (path,), path
    assert safety.surface_kind(path) == "agent_control"


#: T4-R4-05: places that other agent products read their instructions from (the ones that the review found as documents)
DOTTED_AGENT_PLACES = [
    ".github/agents/x.agent.md",
    ".github/chatmodes/x.chatmode.md",
    ".junie/guidelines.md",
    ".kilocode/rules/x.md",
    ".augment/rules/x.md",
    ".trae/rules/x.md",
    ".openhands/microagents/x.md",
    ".agents/x.md",
    ".agent/rules/x.md",
    ".aiderrules/x.md",
    ".idx/airules.md",
    "AGENT.md",
    "CLAUDE.local.md",
    # a place that no list names: the rule is the dot
    ".newagent/notes.md",
    "sub/.hidden/readme.md",
    "docs/.private/x.txt",
    ".notes.md",
]


@pytest.mark.parametrize("path", DOTTED_AGENT_PLACES)
def test_a_path_with_a_dotted_element_or_an_agent_file_name_is_the_execution_surface(path: str) -> None:
    assert safety.execution_surface([path]) == (path,), path


@pytest.mark.parametrize(
    "path",
    [
        "docs/ja/guide.md",
        "README.md",
        "CHANGELOG.md",
        "docs/ontap/x.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/pull_request_template.md",
        ".github/ISSUE_TEMPLATE/bug.md",
        ".github/SECURITY.md",
        "docs/images/a.png",
    ],
)
def test_the_documents_that_the_dot_rule_must_not_catch_stay_documents(path: str) -> None:
    assert safety.execution_surface([path]) == (), path


@pytest.mark.parametrize("path", ["docs/ja/x.md", "README.md", "docs/en/guide.md", "CHANGELOG.md", "docs/a/b.rst"])
def test_plain_documentation_is_still_not_the_execution_surface(path: str) -> None:
    assert safety.execution_surface([path]) == ()


def test_the_write_denial_of_the_agent_names_the_git_file() -> None:
    assert "**/.git" in agent_policy.WRITE_DENIED_PATHS


# ---------------------------------------------------------------------------------------------
# T4-R3-07: more shapes of a credential
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("token: glpat-abcdefghijklmnopqrst", "gitlab_token"),
        ("npm_" + "a1B2c3D4e5" * 3 + "a1B2c3", "npm_token"),
        ("key sk-ant-api03-" + "Ab1_-" * 8, "api_key_sk"),
        ("OPENAI=sk-" + "a" * 40, "api_key_sk"),
    ],
)
def test_the_credentials_of_gitlab_npm_and_sk_forms_are_replaced(text: str, kind: str) -> None:
    redacted, kinds = safety.redact_secrets(text)
    assert f"[REDACTED:{kind}]" in redacted and kind in kinds


@pytest.mark.parametrize("text", ["task-list-item sk-short", "npm_install_all_the_things", "glpat-short"])
def test_ordinary_words_are_not_replaced(text: str) -> None:
    assert safety.redact_secrets(text)[0] == text


# ---------------------------------------------------------------------------------------------
# T4-R3-10: the approval tries the shapes where the option follows ``git``
# ---------------------------------------------------------------------------------------------
def allowed_problems(*entries: str) -> list[tuple[str, str]]:
    """What the approval says about ``allowedCommands`` once a maintainer adds ``entries`` to the built ones."""
    document = agent_policy.build_agent_config("change", name="a", extra_allowed_commands=entries)
    found = agent_policy.settings_problems(document, document["tools"], home="/Users/example")
    return [problem for problem in found if problem[0] == "toolsSettings.shell.allowedCommands"]


@pytest.mark.parametrize(
    "extra",
    [
        r"git -c [a-z.]+=[a-z]+ status",
        r"git -C [a-z]+ status",
        r"git --git-dir=[a-z]+ status",
        r"rm [a-z]+",
        r"tee [a-z]+",
        r"mkdir [a-z]+",
        r"touch [a-z]+",
        r"ln -s [a-z]+ [a-z]+",
    ],
)
def test_an_extra_allowed_command_that_takes_an_option_after_git_or_writes_the_tree_is_refused(extra: str) -> None:
    """The approval tries the option placed right after ``git`` and the commands that write inside the worktree."""
    assert allowed_problems(extra), extra


def test_the_built_in_allowed_commands_pass_the_wider_probes() -> None:
    assert allowed_problems() == []
    lines = agent_policy._probe_lines("/Users/example")
    assert "git -c core.fsmonitor=id status" in lines and "rm x" in lines


# ---------------------------------------------------------------------------------------------
# T4-R3-01 end to end: a run whose agent redirected the worktree (the stand-in sandbox enforces nothing, so the
# redirect happens; the harness must not run git afterwards)
# ---------------------------------------------------------------------------------------------
def test_a_run_whose_agent_redirected_the_worktree_runs_no_git_there(handoff_sandbox: HandoffSandbox) -> None:
    """The item ends in ``needs-human`` (``worktree_gitdir_tampered``) and ``core.fsmonitor`` of the other repository never runs."""
    sb = handoff_sandbox
    pwned = sb.root / "PWNED"
    ended = run_change(sb, "commit,worktree-redirect", FAKE_KIRO_PWNED=str(pwned))
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, runner.WORKTREE_GITDIR_TAMPERED)
    assert not pwned.exists()
    assert ended.record["provenance"]["head_sha"] is None  # not even HEAD was read through the redirected directory


def test_a_run_that_did_not_redirect_is_not_flagged(handoff_sandbox: HandoffSandbox) -> None:
    """The control of the test above."""
    ended = run_change(handoff_sandbox, "commit")
    assert history(ended.status, CHANGE)[-1][2] != runner.WORKTREE_GITDIR_TAMPERED


def test_publish_runs_no_git_in_a_worktree_whose_git_file_was_redirected(handoff_sandbox: HandoffSandbox) -> None:
    """T4-R3-01: the push of the approved item is not tried; the other repository's ``core.fsmonitor`` does not run."""
    from test_handoff_publish_integration import publish, succeeded, untouched, write_approval

    sb = handoff_sandbox
    ended = succeeded(sb)
    pwned = sb.root / "PWNED-publish"
    git(clean_env(sb.root), "init", "-q", "evil", cwd=ended.worktree)
    with open(ended.worktree / "evil" / ".git" / "config", "a", encoding="utf-8") as handle:
        handle.write(f'[core]\n\tfsmonitor = touch "{pwned}" #\n')
    (ended.worktree / ".git").write_text(f"gitdir: {ended.worktree}/evil/.git\n", encoding="utf-8")
    done = publish(sb, write_approval(sb, [CHANGE]))
    assert runner.WORKTREE_GITDIR_TAMPERED in done.stdout + done.stderr
    assert not pwned.exists()
    untouched(sb)


# ---------------------------------------------------------------------------------------------
# T4-R4-01: a repository inside the worktree (a gitlink) must not make the harness's git run its configuration
# ---------------------------------------------------------------------------------------------
NESTED_BEHAVIORS = ("nested-repo", "nested-repo-staged", "nested-repo-untracked")


@pytest.mark.parametrize("behavior", NESTED_BEHAVIORS)
def test_a_nested_repository_does_not_make_the_harness_run_its_clean_filter(
    handoff_sandbox: HandoffSandbox, behavior: str
) -> None:
    """The reproduction: ``filter.x.clean`` of ``sub/.git/config`` must not run when the harness reads the worktree."""
    sb = handoff_sandbox
    pwned = sb.root / f"PWNED-{behavior}"
    ended = run_change(sb, f"commit,{behavior}", FAKE_KIRO_PWNED=str(pwned))
    assert not pwned.exists(), "git of the harness ran the filter of the nested repository"
    final = history(ended.status, CHANGE)[-1]
    assert final[1] == state.NEEDS_HUMAN, final


def test_a_committed_gitlink_is_held_with_its_own_reason(handoff_sandbox: HandoffSandbox) -> None:
    """The commit holds a mode 160000 entry: the item ends in ``needs-human`` as ``nested_repository_in_result``."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit,nested-repo", FAKE_KIRO_PWNED=str(sb.root / "PWNED"))
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, runner.NESTED_REPOSITORY_IN_RESULT)


def test_a_gitlink_in_the_index_only_is_held_too(handoff_sandbox: HandoffSandbox) -> None:
    sb = handoff_sandbox
    ended = run_change(sb, "commit,nested-repo-staged", FAKE_KIRO_PWNED=str(sb.root / "PWNED"))
    assert history(ended.status, CHANGE)[-1][2] == runner.NESTED_REPOSITORY_IN_RESULT


def test_the_hardening_of_git_ignores_submodules() -> None:
    """``diff.ignoreSubmodules=all`` is in :data:`command.GIT_HARDENING`, so that no ``status`` descends into a gitlink."""
    pairs = list(zip(command.GIT_HARDENING[::2], command.GIT_HARDENING[1::2], strict=True))
    assert ("-c", "diff.ignoreSubmodules=all") in pairs


def nested_worktree(tmp_path: Path) -> tuple[Tree, Path]:
    """A worktree with a committed gitlink to a repository whose clean filter creates ``marker``."""
    tree = Tree(tmp_path)
    marker = tree.root / "marker-nested"
    sub = tree.wt / "sub"
    git(tree.env, "init", "-q", str(sub), cwd=tree.wt)
    (sub / "a.txt").write_text("one\n", encoding="utf-8")
    git(tree.env, "add", "a.txt", cwd=sub)
    git(tree.env, "commit", "-q", "-m", "s", cwd=sub)
    with open(sub / ".git" / "config", "a", encoding="utf-8") as handle:
        handle.write(f'[filter "x"]\n\tclean = touch "{marker}"; cat\n')
    (sub / ".gitattributes").write_text("* filter=x\n", encoding="utf-8")
    git(tree.env, "add", "sub", cwd=tree.wt)
    git(tree.env, "commit", "-q", "-m", "gitlink", cwd=tree.wt)
    (sub / "a.txt").write_text("two\n", encoding="utf-8")
    return tree, marker


def test_reproduction_a_plain_status_runs_the_filter_of_a_nested_repository(tmp_path: Path) -> None:
    """Control: the harness's git as it was before (without the submodule options) runs the nested clean filter."""
    tree, marker = nested_worktree(tmp_path)
    old = tuple(
        item
        for pair in zip(command.GIT_HARDENING[::2], command.GIT_HARDENING[1::2], strict=True)
        if "ignoreSubmodules" not in pair[1]
        for item in pair
    )
    done = subprocess.run(
        ["git", *old, "--no-optional-locks", "-C", str(tree.wt), "status", "--porcelain=v1", "-z"],
        env=tree.env,
        capture_output=True,
        check=False,
    )
    assert done.returncode == 0
    assert marker.exists(), "control: without the options the nested filter runs"


def test_the_status_of_the_harness_runs_no_filter_of_a_nested_repository(tmp_path: Path) -> None:
    """The entry point of the harness's git (``_run_process``) with the argv that the runner builds."""
    tree, marker = nested_worktree(tmp_path)
    for argv in (runner.worktree_status_argv(str(tree.wt)),):
        result = runner._run_process(argv, cwd=str(tree.wt), env=tree.env, timeout_seconds=30, kill_grace_seconds=1)
        assert result.exit_code == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize("variant", ["untracked-repository", "gitfile-to-repository", "attributes-only"])
def test_other_shapes_of_a_worktree_content_do_not_make_the_harness_git_run_anything(
    tmp_path: Path, variant: str
) -> None:
    """The same type of path, swept: git of the harness on a worktree that holds a repository that git does not track,
    a ``.git`` file inside a directory, or attributes that name drivers. ``status`` and ``worktree remove`` run nothing."""
    tree = Tree(tmp_path)
    marker = tree.root / "marker-sweep"
    if variant != "attributes-only":
        sub = tree.wt / "sub"
        git(tree.env, "init", "-q", str(sub), cwd=tree.wt)
        (sub / "a.txt").write_text("one\n", encoding="utf-8")
        git(tree.env, "add", "a.txt", cwd=sub)
        git(tree.env, "commit", "-q", "-m", "s", cwd=sub)
        with open(sub / ".git" / "config", "a", encoding="utf-8") as handle:
            handle.write(f'[filter "x"]\n\tclean = touch "{marker}"; cat\n[core]\n\tfsmonitor = touch "{marker}"\n')
        (sub / ".gitattributes").write_text("* filter=x\n", encoding="utf-8")
        (sub / "a.txt").write_text("two\n", encoding="utf-8")
        if variant == "gitfile-to-repository":
            other = tree.wt / "other"
            other.mkdir()
            (other / ".git").write_text(f"gitdir: {sub}/.git\n", encoding="utf-8")
    else:
        (tree.wt / ".gitattributes").write_text("*.txt filter=x diff=x\n", encoding="utf-8")
        (tree.wt / "a.txt").write_text("one\n", encoding="utf-8")
        git(tree.env, "add", ".gitattributes", "a.txt", cwd=tree.wt)
        git(tree.env, "commit", "-q", "-m", "attrs", cwd=tree.wt)
        (tree.wt / "a.txt").write_text("two\n", encoding="utf-8")
    for argv in (
        runner.worktree_status_argv(str(tree.wt)),
        ("git", "-C", str(tree.main), "worktree", "remove", str(tree.wt)),
    ):
        runner._run_process(argv, cwd=str(tree.main), env=tree.env, timeout_seconds=30, kill_grace_seconds=1)
    assert not marker.exists()


def test_the_gitlinks_of_a_raw_diff_are_read_by_their_new_mode() -> None:
    raw = (
        b":000000 160000 0000000 abcdef1 A\0sub\0:100644 100644 abc def M\0a.txt\0"
        b":160000 000000 abc 0000000 D\0gone\0:160000 160000 abc def M\0moved\0"
    )
    assert runner.gitlink_paths(raw) == ("moved", "sub")
    assert runner.gitlink_paths(b"") == ()


# ---------------------------------------------------------------------------------------------
# T4-R4-03: a run creates objects in the main working tree's git directory; it does not delete them
# ---------------------------------------------------------------------------------------------
def loose_object(tree: Tree) -> Path:
    """Write one loose object into the main tree's database (outside any profile) and return its file."""
    (tree.main / "keep.txt").write_text("keep me", encoding="utf-8")
    sha = git(tree.env, "hash-object", "-w", "keep.txt", cwd=tree.main).stdout.decode().strip()
    return tree.main / ".git" / "objects" / sha[:2] / sha[2:]


@needs_sandbox_exec
@pytest.mark.parametrize(
    "script",
    [
        'rm -f "{obj}"',
        'mv "{obj}" "{obj}.old"',
        'rm -f "{main}/.git/objects/pack/"*',
        "git -C {main} repack -a -d",
        "git -C {main} gc --prune=now",
        "git -C {main} prune --expire=now",
    ],
)
def test_a_run_cannot_delete_an_object_of_the_main_tree(tmp_path: Path, script: str) -> None:
    """The reproduction of T4-R4-03: the loose object stays, whatever deletes."""
    tree = Tree(tmp_path)
    obj = loose_object(tree)
    git(tree.env, "repack", "-q", cwd=tree.main)  # a pack exists too
    sha = obj.parent.name + obj.name
    text = script.format(obj=obj, main=tree.main)
    tree.sandboxed(tree.profile(worktrees=[str(tree.wt)]), text)
    assert git(tree.env, "cat-file", "-e", sha, cwd=tree.main).returncode == 0, text
    git(tree.env, "fsck", "--no-dangling", cwd=tree.main)


@needs_sandbox_exec
def test_a_commit_in_the_worktree_still_works_after_the_object_deletions_are_closed(tmp_path: Path) -> None:
    """Control: ``git add`` and ``git commit`` write objects, take ``maintenance.lock`` and print no warning."""
    tree = Tree(tmp_path)
    script = (
        'printf "new" > a.txt && git add a.txt && '
        "git -c user.name=t -c user.email=t@example.com -c commit.gpgSign=false commit -q -m done && "
        "git -c user.name=t -c user.email=t@example.com -c commit.gpgSign=false commit -q --allow-empty -m again"
    )
    done = tree.sandboxed(tree.profile(worktrees=[str(tree.wt)]), script)
    assert done.returncode == 0, done.stderr
    assert b"unable to unlink" not in done.stderr and b"warning" not in done.stderr, done.stderr
    git(tree.env, "fsck", "--no-dangling", cwd=tree.main)
    assert git(tree.env, "rev-parse", "handoff/x", cwd=tree.main).stdout


def test_the_profile_closes_unlink_below_the_objects_and_opens_the_temporary_names() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"])
    assert '(deny file-write-unlink (subpath "/Users/u/r/.git/objects"))' in text
    allows = [line for line in text.splitlines() if line.startswith("(allow file-write-unlink")]
    assert any("tmp_obj_" in line for line in allows) and any("maintenance.lock" in line for line in allows)
    assert text.index("(deny file-write-unlink") < text.index("(allow file-write-unlink")


# ---------------------------------------------------------------------------------------------
# T4-R4-04: Kiro's own command sandbox (sandbox-exec per command) cannot run inside layer 0
# ---------------------------------------------------------------------------------------------
@needs_sandbox_exec
def test_reproduction_sandbox_exec_cannot_be_nested_under_the_profile(tmp_path: Path) -> None:
    """The observation behind the check: under the profile a second ``sandbox_apply`` is refused."""
    tree = Tree(tmp_path)
    nested = "(version 1)(allow default)"
    done = tree.sandboxed(
        tree.profile(worktrees=[str(tree.wt)]), f"{osb.SANDBOX_EXEC} -p '{nested}' /bin/echo nested-ok"
    )
    assert done.returncode != 0 and b"nested-ok" not in done.stdout, "nesting works here: the check may be unnecessary"
    alone = subprocess.run([osb.SANDBOX_EXEC, "-p", nested, "/bin/echo", "ok"], capture_output=True, check=False)
    assert alone.returncode == 0, "control: one level works"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (None, False),
        ('{"enabled": false}', False),
        ('{"enabled": false, "networkAccess": "DEFAULT_ALLOWED"}', False),
        ('{"networkAccess": "DEFAULT_BLOCKED"}', False),
        ('{"enabled": true}', True),
        ('{"enabled": true, "networkAccess": "COMMON_DEPENDENCIES"}', True),
        ("{not json", True),
        ("[]", True),
        ('"enabled"', True),
    ],
)
def test_the_sandbox_configuration_of_kiro_is_read_for_enabled_only(text: str | None, expected: bool) -> None:
    assert (osb.kiro_sandbox_problem({"global": text, "project": None}) is not None) is expected
    assert (osb.kiro_sandbox_problem({"global": None, "project": text}) is not None) is expected


def test_a_change_item_is_held_when_the_sandbox_of_kiro_is_on(handoff_sandbox: HandoffSandbox) -> None:
    """Held before ``kiro-cli chat`` starts: ``kiro_sandbox_enabled`` (the selftest is refused for the same reason)."""
    from test_handoff_change_integration import DECLARED, prepare, read_status, record_selftest, run_cli

    sb = handoff_sandbox
    prepare(sb, ())
    record_selftest(sb)
    seen = len(sb.invocations())
    path = sb.home / ".kiro" / "settings" / "sandbox.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"enabled": true}', encoding="utf-8")
    run_cli(sb, "run", "--items", CHANGE, FAKE_KIRO_MODE="commit", FAKE_KIRO_COMMIT_FILES=DECLARED)
    status = read_status(sb)
    assert history(status, CHANGE)[-1][1:] == (state.NEEDS_HUMAN, runner.KIRO_SANDBOX_ENABLED)
    assert "chat" not in [run["start"]["subcommand"] for run in sb.invocations()[seen:]]


def test_a_change_item_runs_when_the_sandbox_of_kiro_is_off(handoff_sandbox: HandoffSandbox) -> None:
    """The control of the test above: ``enabled: false`` does not hold the item."""
    sb = handoff_sandbox
    path = sb.home / ".kiro" / "settings" / "sandbox.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"enabled": false}', encoding="utf-8")
    ended = run_change(sb, "commit")
    assert history(ended.status, CHANGE)[-1][2] != runner.KIRO_SANDBOX_ENABLED


def test_the_runner_reads_the_global_and_the_worktree_file(tmp_path: Path) -> None:
    home, worktree = tmp_path / "home", tmp_path / "wt"
    for root in (home, worktree):
        (root / ".kiro" / "settings").mkdir(parents=True)
    assert runner._kiro_sandbox_problem(str(home), str(worktree)) is None
    (worktree / ".kiro" / "settings" / "sandbox.json").write_text('{"enabled": true}', encoding="utf-8")
    problem = runner._kiro_sandbox_problem(str(home), str(worktree))
    assert problem is not None and "worktree" in problem
    assert runner._kiro_sandbox_problem(str(home), None) is None
    (home / ".kiro" / "settings" / "sandbox.json").write_text('{"enabled": true}', encoding="utf-8")
    problem = runner._kiro_sandbox_problem(str(home), None)
    assert problem is not None and "~/.kiro/settings/sandbox.json" in problem


# ---------------------------------------------------------------------------------------------
# T4-R4-09: an item writes its own ``handoff/<id>`` ref and no other item's
# ---------------------------------------------------------------------------------------------
@needs_sandbox_exec
def test_an_item_cannot_rewrite_the_branch_of_another_item(tmp_path: Path) -> None:
    """The reproduction: with the whole ``refs/heads/handoff`` open, ``update-ref`` of another item's branch works."""
    tree = Tree(tmp_path)
    git(tree.env, "branch", "handoff/other", cwd=tree.main)
    other = git(tree.env, "rev-parse", "handoff/other", cwd=tree.main).stdout
    rewrite = "git update-ref refs/heads/handoff/other handoff/x && git update-ref -d refs/heads/handoff/other"
    open_profile = tree.profile(worktrees=[str(tree.wt)])
    assert tree.sandboxed(open_profile, "git update-ref refs/heads/handoff/other main").returncode == 0, "control"
    git(tree.env, "update-ref", "refs/heads/handoff/other", other.decode().strip(), cwd=tree.main)
    own = tree.profile(worktrees=[str(tree.wt)], own_branches=["handoff/x"])
    for script in (
        "git update-ref refs/heads/handoff/other main",
        "git update-ref -d refs/heads/handoff/other",
        "git branch -f handoff/other main",
        rewrite,
    ):
        assert tree.sandboxed(own, script).returncode != 0, script
    assert git(tree.env, "rev-parse", "handoff/other", cwd=tree.main).stdout == other


@needs_sandbox_exec
def test_an_item_can_still_commit_on_its_own_branch(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    own = tree.profile(worktrees=[str(tree.wt)], own_branches=["handoff/x"])
    script = (
        'printf "new" > a.txt && git add a.txt && '
        "git -c user.name=t -c user.email=t@example.com -c commit.gpgSign=false commit -q -m done && "
        "git -c user.name=t -c user.email=t@example.com -c commit.gpgSign=false commit -q --allow-empty -m again"
    )
    done = tree.sandboxed(own, script)
    assert done.returncode == 0, done.stderr
    assert (
        git(tree.env, "rev-parse", "handoff/x", cwd=tree.main).stdout
        != git(tree.env, "rev-parse", "main", cwd=tree.main).stdout
    )


def test_the_profile_names_the_own_branch_only() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"], own_branches=["handoff/a.b"])
    assert "refs/heads/handoff/a\\.b" in text
    assert '(subpath "/Users/u/r/.git/refs/heads/handoff")' not in text
    broad = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"])
    assert '(subpath "/Users/u/r/.git/refs/heads/handoff")' in broad
    with pytest.raises(ValueError):
        osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"], own_branches=["main"])
    with pytest.raises(ValueError):
        osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"], own_branches=["handoff/../x"])

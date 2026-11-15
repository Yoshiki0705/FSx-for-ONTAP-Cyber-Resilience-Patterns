"""Layer 0, the harness's git and the re-run, after the round 5 review (T4-R5-01 to T4-R5-07).

Each reproduction runs the attack against the profile as it was (the control), and then against the profile as it is.
The tests that run ``sandbox-exec`` are for macOS and skip elsewhere. Everything happens in throwaway directories. No
``kiro-cli`` starts. The only real places touched are empty probe files that are created under the directories of the
git of this machine, and only when the user can write them; each is removed at once (``runner._real_prefix_problems``).
"""

from __future__ import annotations

import os
import subprocess
import textwrap
import types
from pathlib import Path

import pytest
from handoff import command, runner, safety
from handoff import os_boundary as osb
from test_handoff_change_integration import FAILS, IN_WORKTREE, run_change
from test_handoff_round4_boundary import Tree, clean_env, git, needs_sandbox_exec

SCRIPTS = Path(__file__).resolve().parent
REAL_SANDBOX_EXEC = SCRIPTS / "fixtures" / "handoff" / "real-sandbox-exec"


def strict_profile(tree: Tree, objects: Path | None = None, **extra: object) -> Path:
    """The profile of a run as :meth:`runner._ChangeRun._wrapped` builds it: own branch, own worktree, own objects."""
    name = runner._worktree_admin_name(str(tree.wt), str(tree.main))
    assert name is not None
    return tree.profile(
        worktrees=[str(tree.wt)],
        own_branches=["handoff/x"],
        own_worktree_names=[name],
        object_directories=[] if objects is None else [str(objects)],
        **extra,
    )


# ---------------------------------------------------------------------------------------------
# T4-R5-02: the prefix of the package manager, and the system configuration of git
# ---------------------------------------------------------------------------------------------


def test_the_profile_closes_the_package_prefixes_as_wholes() -> None:
    """The prefixes are named by the profile itself, so that a keg behind a link in ``PATH`` is closed too."""
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/repo"])
    for prefix in ("/opt/homebrew", "/usr/local", "/Library", "/usr/bin", "/private/etc"):
        assert f'(deny file-write* (subpath "{prefix}"))' in text


def program_dirs_the_user_can_write() -> list[str]:
    return [path for path in runner._git_program_dirs() if os.access(path, os.W_OK)]


@needs_sandbox_exec
def test_reproduction_a_profile_without_the_prefix_rules_lets_a_run_write_the_directory_of_git(tmp_path: Path) -> None:
    """Control: with the lines of the prefixes removed, a file can be made where this machine's git lives (if the user owns it)."""
    directories = program_dirs_the_user_can_write()
    if not directories:
        pytest.skip("the git of this machine is in a directory that the user cannot write (a system git)")
    kept = [
        line
        for line in osb.build_profile(home=str(tmp_path / "home"), main_trees=[str(tmp_path / "main")]).splitlines()
        if not any(f'"{prefix}"' in line for prefix in osb.SYSTEM_WRITE_PREFIXES)
    ]
    profile = tmp_path / "old.sb"
    profile.write_text("\n".join(kept) + "\n", encoding="utf-8")
    probe = Path(directories[0]) / f".handoff-test-probe-{os.getpid()}"
    try:
        done = subprocess.run(
            [osb.SANDBOX_EXEC, "-f", str(profile), "/usr/bin/touch", str(probe)], capture_output=True, check=False
        )
        assert done.returncode == 0 and probe.exists()
    finally:
        probe.unlink(missing_ok=True)


@needs_sandbox_exec
def test_the_directories_of_git_cannot_be_written_under_the_profile(tmp_path: Path) -> None:
    """The real executable, ``git --exec-path`` and the directory of the system configuration are closed on this machine."""
    boundary = osb.OsBoundary(program=osb.SANDBOX_EXEC)
    scratch = tmp_path / "root"
    for name in ("home", "main", "work"):
        (scratch / name).mkdir(parents=True)
    assert runner._real_prefix_problems(boundary, str(scratch)) == []
    assert (
        not list(Path(runner._git_program_dirs()[0]).glob(".handoff-probe-*")) if runner._git_program_dirs() else True
    )


def test_the_directories_of_git_are_found() -> None:
    """The directory of the real ``git`` and the one of ``git --exec-path`` are among those that the profile closes."""
    found = runner._git_program_dirs()
    program = subprocess.run(["which", "git"], capture_output=True, text=True, check=True).stdout.strip()
    assert os.path.dirname(os.path.realpath(program)) in found
    exec_path = subprocess.run(["git", "--exec-path"], capture_output=True, text=True, check=True).stdout.strip()
    assert os.path.realpath(exec_path) in found


@pytest.mark.parametrize("subcommand", ["ls-remote", "fetch", "push", "config", "worktree", "status", "clone"])
def test_every_git_of_the_harness_reads_no_system_configuration(subcommand: str) -> None:
    """``GIT_CONFIG_SYSTEM`` and ``GIT_CONFIG_NOSYSTEM`` are set for every subcommand, whatever the harness's environment says."""
    _, env = command.harden_git(("git", subcommand), {"GIT_CONFIG_SYSTEM": "/tmp/mine", "GIT_CONFIG_NOSYSTEM": "0"})
    assert env["GIT_CONFIG_SYSTEM"] == "/dev/null"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"


def test_reproduction_a_system_configuration_runs_a_program_in_a_network_command_and_the_hardened_git_does_not(
    tmp_path: Path,
) -> None:
    """``core.sshCommand`` in the system configuration runs for ``ls-remote``; the hardened environment never reads it."""
    pwned = tmp_path / "PWNED-system"
    system = tmp_path / "gitconfig"
    system.write_text(f'[core]\n\tsshCommand = touch "{pwned}" #\n', encoding="utf-8")
    base = clean_env(tmp_path)
    base.pop("GIT_CONFIG_NOSYSTEM")
    base["GIT_CONFIG_SYSTEM"] = str(system)
    argv = ("git", "ls-remote", "ssh://nohost.invalid/x", "HEAD")
    subprocess.run(argv, env=base, capture_output=True, timeout=30, check=False, cwd=tmp_path)
    assert pwned.exists(), "control: the system configuration runs the program"
    pwned.unlink()
    to_run, env = command.harden_git(argv, base)
    subprocess.run(to_run, env=env, capture_output=True, timeout=30, check=False, cwd=tmp_path)
    assert not pwned.exists()


def test_the_network_commands_still_work_without_the_system_configuration(tmp_path: Path) -> None:
    """A fetch, a push and an ``ls-remote`` against a local remote work with the hardened environment."""
    env = clean_env(tmp_path)
    env.pop("GIT_CONFIG_NOSYSTEM")
    env.pop("GIT_CONFIG_GLOBAL")
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    git(env, "init", "-q", "--bare", str(remote), cwd=tmp_path)
    git(env, "init", "-q", "--initial-branch=main", str(work), cwd=tmp_path)
    (work / "a.txt").write_text("a", encoding="utf-8")
    git(env, "add", "a.txt", cwd=work)
    git(env, "commit", "-q", "-m", "first", cwd=work)
    for args, where in (
        (("remote", "add", "origin", str(remote)), work),
        (("push", "-q", "origin", "main"), work),
        (("ls-remote", "origin", "refs/heads/main"), work),
        (("fetch", "-q", "origin"), work),
    ):
        to_run, hardened = command.harden_git(("git", *args), env)
        done = subprocess.run(to_run, cwd=where, env=hardened, capture_output=True, timeout=60, check=False)
        assert done.returncode == 0, (args, done.stderr)


# ---------------------------------------------------------------------------------------------
# T4-R5-03: the objects of the main repository
# ---------------------------------------------------------------------------------------------

OVERWRITE_OBJECT = textwrap.dedent(
    """
    set -e
    object=$(find "$MAIN/.git/objects" -type f -path '*/??/*' | head -n 1)
    chmod u+w "$object"
    printf 'EVIL' > "$object"
    """
)
FORGE_PACK = 'printf PACK > "$MAIN/.git/objects/pack/pack-forged.pack"'


def sandboxed(tree: Tree, profile: Path, script: str, **env: str) -> subprocess.CompletedProcess[bytes]:
    """Run a shell script in the worktree under a profile, with ``MAIN`` naming the main working tree."""
    return subprocess.run(
        [osb.SANDBOX_EXEC, "-f", str(profile), "/bin/sh", "-c", script],
        cwd=tree.wt,
        env={**tree.env, "MAIN": str(tree.main), **env},
        capture_output=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )


@needs_sandbox_exec
@pytest.mark.parametrize("script", [OVERWRITE_OBJECT, FORGE_PACK], ids=["overwrite", "forged-pack"])
def test_reproduction_the_old_profile_lets_a_run_change_the_objects_of_the_main_tree(
    tmp_path: Path, script: str
) -> None:
    """Control: with ``.git/objects`` open, an existing object is overwritten and a pack is added."""
    tree = Tree(tmp_path)
    assert sandboxed(tree, tree.profile(worktrees=[str(tree.wt)]), script).returncode == 0


@needs_sandbox_exec
@pytest.mark.parametrize("script", [OVERWRITE_OBJECT, FORGE_PACK], ids=["overwrite", "forged-pack"])
def test_the_profile_with_own_objects_closes_the_objects_of_the_main_tree(tmp_path: Path, script: str) -> None:
    tree = Tree(tmp_path)
    objects = tree.root / "agent-objects"
    objects.mkdir()
    done = sandboxed(tree, strict_profile(tree, objects), script)
    assert done.returncode != 0
    assert not (tree.main / ".git/objects/pack/pack-forged.pack").exists()
    git(tree.env, "fsck", "--no-dangling", cwd=tree.main)


def commit_as_agent(tree: Tree, profile: Path, objects: Path) -> subprocess.CompletedProcess[bytes]:
    """A commit in the worktree under the profile, with the object directory of the run."""
    script = "echo more >> README.md && git add README.md && git commit -q -m agent-change"
    return sandboxed(
        tree,
        profile,
        script,
        GIT_OBJECT_DIRECTORY=str(objects),
        GIT_ALTERNATE_OBJECT_DIRECTORIES=str(tree.main / ".git/objects"),
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.com",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.com",
    )


def change_run(tree: Tree, objects: Path) -> object:
    """A :class:`runner._ChangeRun` with only what ``_import_objects`` reads."""
    run = object.__new__(runner._ChangeRun)
    run.agent_objects = str(objects)
    run.worktree = str(tree.wt)
    run.branch = "handoff/x"
    run.base_sha = git(tree.env, "rev-parse", "HEAD", cwd=tree.main).stdout.decode().strip()
    run.main_tree = str(tree.main)
    run.git_env = runner.git_environment(tree.env)
    run.timeout = 60
    run.grace = 1
    return run


@needs_sandbox_exec
def test_a_commit_goes_to_the_objects_of_the_run_and_the_import_takes_it_into_the_main_repository(
    tmp_path: Path,
) -> None:
    tree = Tree(tmp_path)
    objects = tree.root / "agent-objects"
    objects.mkdir()
    done = commit_as_agent(tree, strict_profile(tree, objects), objects)
    assert done.returncode == 0, done.stderr
    head = git(tree.env, "rev-parse", "refs/heads/handoff/x", cwd=tree.main).stdout.decode().strip()
    assert (objects / head[:2] / head[2:]).exists()
    assert not (tree.main / ".git/objects" / head[:2] / head[2:]).exists()
    assert change_run(tree, objects)._import_objects() is None  # type: ignore[attr-defined]
    assert (tree.main / ".git/objects" / head[:2] / head[2:]).exists()
    git(tree.env, "fsck", "--no-dangling", "--strict", cwd=tree.main)


@needs_sandbox_exec
def test_the_import_refuses_an_object_whose_content_is_not_its_name(tmp_path: Path) -> None:
    """A forged loose object of the run's directory is refused by ``unpack-objects --strict``; nothing reaches main."""
    tree = Tree(tmp_path)
    objects = tree.root / "agent-objects"
    objects.mkdir()
    assert commit_as_agent(tree, strict_profile(tree, objects), objects).returncode == 0
    head = git(tree.env, "rev-parse", "refs/heads/handoff/x", cwd=tree.main).stdout.decode().strip()
    agent_env = {
        **tree.env,
        "GIT_OBJECT_DIRECTORY": str(objects),
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(tree.main / ".git/objects"),
    }
    tree_id = git(agent_env, "rev-parse", f"{head}^{{tree}}", cwd=tree.main).stdout.decode().strip()
    forged = objects / tree_id[:2] / tree_id[2:]
    forged.chmod(0o644)
    forged.write_bytes(b"x\x9c\x03\x00\x00\x00\x00\x01")  # a zlib stream of the empty string: not a tree
    message = change_run(tree, objects)._import_objects()  # type: ignore[attr-defined]
    assert message is not None
    assert not (tree.main / ".git/objects" / head[:2] / head[2:]).exists()
    refs = git(tree.env, "for-each-ref", "refs/heads/handoff", cwd=tree.main).stdout.decode()
    assert "handoff/x" not in refs  # the branch that named the refused commit is gone


def test_an_import_with_nothing_new_does_nothing(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    objects = tree.root / "agent-objects"
    objects.mkdir()
    assert change_run(tree, objects)._import_objects() is None  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------------------------
# T4-R5-04: the administrative directories of the other worktrees
# ---------------------------------------------------------------------------------------------

OTHER_HEAD = 'echo "ref: refs/heads/main" > "$MAIN/.git/worktrees/other/HEAD"'
OTHER_INDEX = ': > "$MAIN/.git/worktrees/other/index"'
NEW_ADMIN = 'mkdir "$MAIN/.git/worktrees/new"'


def with_other_worktree(tree: Tree) -> None:
    git(tree.env, "worktree", "add", "-q", "-b", "handoff/other", str(tree.root / "other"), cwd=tree.main)


@needs_sandbox_exec
@pytest.mark.parametrize("script", [OTHER_HEAD, OTHER_INDEX, NEW_ADMIN], ids=["head", "index", "new"])
def test_reproduction_the_old_profile_lets_a_run_write_the_administration_of_another_worktree(
    tmp_path: Path, script: str
) -> None:
    tree = Tree(tmp_path)
    with_other_worktree(tree)
    assert sandboxed(tree, tree.profile(worktrees=[str(tree.wt)]), script).returncode == 0


@needs_sandbox_exec
@pytest.mark.parametrize("script", [OTHER_HEAD, OTHER_INDEX, NEW_ADMIN], ids=["head", "index", "new"])
def test_a_run_cannot_write_the_administration_of_another_worktree(tmp_path: Path, script: str) -> None:
    tree = Tree(tmp_path)
    with_other_worktree(tree)
    before = (tree.main / ".git/worktrees/other/HEAD").read_bytes()
    assert sandboxed(tree, strict_profile(tree, tree.root / "o"), script).returncode != 0
    assert (tree.main / ".git/worktrees/other/HEAD").read_bytes() == before
    assert not (tree.main / ".git/worktrees/new").exists()


def test_the_profile_opens_the_own_administrative_directory_only() -> None:
    text = osb.build_profile(
        home="/Users/u", main_trees=["/Users/u/repo"], own_worktree_names=["mine"], object_directories=[]
    )
    assert '(allow file-write* (subpath "/Users/u/repo/.git/worktrees/mine"))' in text
    assert '(allow file-write* (subpath "/Users/u/repo/.git/worktrees"))' not in text
    assert '(allow file-write* (subpath "/Users/u/repo/.git/objects"))' not in text


@pytest.mark.parametrize("name", ["", ".hidden", "a/b", 'a"b', "a b\n"])
def test_a_name_of_an_administrative_directory_that_is_not_a_name_is_refused(name: str) -> None:
    with pytest.raises(ValueError):
        osb.build_profile(home="/Users/u", main_trees=["/Users/u/repo"], own_worktree_names=[name])


# ---------------------------------------------------------------------------------------------
# T4-R5-05: KIRO_HOME
# ---------------------------------------------------------------------------------------------


def test_the_sandbox_configuration_below_kiro_home_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    kiro_home = tmp_path / "kiro-home"
    (kiro_home / "settings").mkdir(parents=True)
    (kiro_home / "settings" / "sandbox.json").write_text('{"enabled": true}', encoding="utf-8")
    monkeypatch.delenv("KIRO_HOME", raising=False)
    assert runner._kiro_sandbox_problem(str(home), None) is None
    monkeypatch.setenv("KIRO_HOME", str(kiro_home))
    problem = runner._kiro_sandbox_problem(str(home), None)
    assert problem is not None and "KIRO_HOME" in problem


def test_the_control_plane_below_kiro_home_is_closed_for_writing() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=[], kiro_home="/data/kiro")
    for name in ("agents", "hooks", "settings", "steering", "skills", "powers"):
        assert f'(deny file-write* (subpath "/data/kiro/{name}"))' in text


# ---------------------------------------------------------------------------------------------
# T4-R5-06: the names of the instruction files
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "AGENTS.override.md",
        "sub/AGENTS.override.md",
        "CONVENTIONS.md",
        "WARP.md",
        "CODEX.md",
        "instructions/x.instructions.md",
        "prompts/x.prompt.md",
        "docs/y.prompt.md",
    ],
)
def test_the_instruction_files_that_do_not_start_with_a_dot_are_the_execution_surface(path: str) -> None:
    assert safety.execution_surface([path]) == (path,)


@pytest.mark.parametrize("path", ["README.md", "docs/ja/guide.md", "CHANGELOG.md", "docs/ontap/x.md"])
def test_the_documents_stay_documents(path: str) -> None:
    assert safety.execution_surface([path]) == ()


# ---------------------------------------------------------------------------------------------
# T4-R5-07: the path of the worktree
# ---------------------------------------------------------------------------------------------


def test_a_worktree_replaced_by_a_link_is_found(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    assert runner.worktree_gitdir_problem(str(tree.wt), str(tree.main)) is None
    os.rename(tree.wt, tree.root / "wt.bak")
    (tree.root / "evil").mkdir()
    (tree.root / "evil" / ".git").write_bytes((tree.root / "wt.bak" / ".git").read_bytes())
    os.symlink(tree.root / "evil", tree.wt)
    # the control: the ``gitdir`` pointer agrees with the copy of ``.git``, so the old checks passed this
    assert runner.worktree_gitdir_problem(str(tree.wt), str(tree.main)) is not None


def test_a_worktree_replaced_by_another_directory_is_found_by_its_identity(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    identity = runner._identity(str(tree.wt))
    assert runner.worktree_gitdir_problem(str(tree.wt), str(tree.main), identity=identity) is None
    git_file = (tree.wt / ".git").read_bytes()
    os.rename(tree.wt, tree.root / "wt.bak")
    tree.wt.mkdir()
    (tree.wt / ".git").write_bytes(git_file)
    assert runner.worktree_gitdir_problem(str(tree.wt), str(tree.main), identity=identity) is not None


# ---------------------------------------------------------------------------------------------
# T4-R5-01: the re-run of a verification command
# ---------------------------------------------------------------------------------------------


def test_a_rerun_without_layer_zero_is_not_run() -> None:
    run = object.__new__(runner._ChangeRun)
    run.context = types.SimpleNamespace(os_boundary=None)
    run.stop = None
    with pytest.raises(runner._RerunWithoutBoundary):
        run._rerun(types.SimpleNamespace(cmd=("true",), offline=True))  # type: ignore[arg-type]


def test_the_rerun_of_a_verification_command_is_put_under_layer_zero(handoff_sandbox) -> None:  # type: ignore[no-untyped-def]
    """The fake ``sandbox-exec`` logs what is put under a profile: ``kiro-cli`` and each re-run (T4-R5-01)."""
    log = handoff_sandbox.root / "sandbox.log"
    ended = run_change(
        handoff_sandbox, "commit", verify=[(IN_WORKTREE, True), (FAILS, True)], FAKE_SANDBOX_LOG=str(log)
    )
    lines = log.read_text(encoding="utf-8").splitlines()
    assert any("chat" in line for line in lines), lines
    assert sum(1 for line in lines if line.startswith(("git ", "/")) and " grep -q -F " in line) >= 2, lines
    assert ended.record["state"] in {"succeeded", "failed", "needs-human"}


@needs_sandbox_exec
def test_reproduction_a_verification_command_that_writes_a_protected_place_is_stopped_by_layer_zero(
    handoff_sandbox,  # type: ignore[no-untyped-def]
) -> None:
    """Under the real ``sandbox-exec``, the re-run cannot write below the home's ``.ssh`` (a script of the worktree could).

    The ``sandbox-exec`` that the runner uses here is a script that runs the real one. The command writes to a place of
    the sandbox's own home, never to a real one. Before the re-run was wrapped, the file existed after the run.
    """
    ssh = handoff_sandbox.home / ".ssh"
    ssh.mkdir(exist_ok=True)
    victim = ssh / "PWNED"
    script = ["sh", "-c", f"printf x > {victim}"]
    ended = run_change(
        handoff_sandbox,
        "commit",
        verify=[(script, True)],
        HANDOFF_OS_BOUNDARY_TEST_DOUBLE=str(REAL_SANDBOX_EXEC),
    )
    assert ended.record["rerun"], "the command was not re-run, so this shows nothing"
    assert not victim.exists(), "the re-run ran outside layer 0"

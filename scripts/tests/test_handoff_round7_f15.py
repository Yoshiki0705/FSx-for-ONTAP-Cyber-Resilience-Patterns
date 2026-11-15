"""Layer 0, the harness's refs and the processes that outlive a run, after the round 6 review (T4-R6-01 to T4-R6-05).

Each reproduction runs the attack against the code as it was (the control: ``--no-deref`` removed, the profile without
the new names) and then against the code as it is. The tests that run ``sandbox-exec`` are for macOS and skip elsewhere.
Everything happens in throwaway directories; no ``kiro-cli`` starts and no real home, repository or credential is
touched. The processes that the tests start are stopped at the end of each test.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest
from handoff import command, runner, state
from handoff import os_boundary as osb
from test_handoff_change_integration import CHANGE, git_text, history, run_change
from test_handoff_round4_boundary import Tree, git, needs_sandbox_exec
from test_handoff_round5_boundary import change_run, strict_profile
from test_handoff_worktree_prerequisites_integration import cleanup, local_branches, use


def main_branches(tree: Tree) -> str:
    return git(tree.env, "for-each-ref", "--format=%(refname)", "refs/heads", cwd=tree.main).stdout.decode()


def make_symbolic(tree: Tree, *, link: bool = False) -> Path:
    """What an agent that may write its own ref can do: make ``refs/heads/handoff/x`` a symbolic ref to ``main``."""
    path = tree.main / ".git" / "refs" / "heads" / "handoff" / "x"
    path.unlink(missing_ok=True)
    if link:
        path.symlink_to("refs/heads/main")
    else:
        path.write_text("ref: refs/heads/main\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------------------------
# T4-R6-01: a symbolic ref is not read, and a delete does not follow one
# ---------------------------------------------------------------------------------------------


def test_the_branch_delete_does_not_follow_a_symbolic_ref() -> None:
    sha = "a" * 40
    plan = object.__new__(command.GitPlan)
    object.__setattr__(plan, "branch", "handoff/x")
    object.__setattr__(plan, "main_tree", "/m")
    assert plan.delete_branch_at(sha).argv == (
        "git",
        "-C",
        "/m",
        "update-ref",
        "--no-deref",
        "-d",
        "refs/heads/handoff/x",
        sha,
    )


@pytest.mark.parametrize("link", [False, True], ids=["ref-file", "symlink"])
def test_reproduction_a_delete_without_no_deref_removes_main(tmp_path: Path, link: bool) -> None:
    """Control: the review's reproduction. ``update-ref -d`` follows the symbolic ref and deletes ``main``."""
    tree = Tree(tmp_path)
    base = git(tree.env, "rev-parse", "HEAD", cwd=tree.main).stdout.decode().strip()
    make_symbolic(tree, link=link)
    git(tree.env, "worktree", "remove", "--force", str(tree.wt), cwd=tree.main)
    done = subprocess.run(
        ["git", "-C", str(tree.main), "update-ref", "-d", "refs/heads/handoff/x", base],
        env=tree.env,
        capture_output=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "refs/heads/main" not in main_branches(tree), "git follows the symbolic ref: the control would be void"


@pytest.mark.parametrize("link", [False, True], ids=["ref-file", "symlink"])
def test_a_delete_with_no_deref_keeps_main(tmp_path: Path, link: bool) -> None:
    tree = Tree(tmp_path)
    base = git(tree.env, "rev-parse", "HEAD", cwd=tree.main).stdout.decode().strip()
    make_symbolic(tree, link=link)
    git(tree.env, "worktree", "remove", "--force", str(tree.wt), cwd=tree.main)
    subprocess.run(
        ["git", "-C", str(tree.main), "update-ref", "--no-deref", "-d", "refs/heads/handoff/x", base],
        env=tree.env,
        capture_output=True,
        check=False,
    )
    assert "refs/heads/main" in main_branches(tree)
    assert (tree.main / ".git" / "logs" / "refs" / "heads" / "main").exists()


def probe(tree: Tree) -> str | None:
    return runner.branch_ref_problem(
        str(tree.main), "handoff/x", env=runner.git_environment(tree.env), timeout_seconds=60
    )


def test_a_plain_branch_ref_is_not_a_problem(tmp_path: Path) -> None:
    assert probe(Tree(tmp_path)) is None


@pytest.mark.parametrize("link", [False, True], ids=["ref-file", "symlink"])
def test_a_symbolic_branch_ref_is_named(tmp_path: Path, link: bool) -> None:
    tree = Tree(tmp_path)
    make_symbolic(tree, link=link)
    message = probe(tree)
    assert message is not None and "handoff/x" in message and "symbolic" in message


def test_a_missing_branch_ref_is_not_a_problem(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    git(tree.env, "worktree", "remove", "--force", str(tree.wt), cwd=tree.main)
    git(tree.env, "update-ref", "-d", "refs/heads/handoff/x", cwd=tree.main)
    assert probe(tree) is None


def test_the_import_of_a_run_with_a_symbolic_branch_reads_nothing_and_deletes_nothing(tmp_path: Path) -> None:
    """Route b of the review: ``main`` moved after the worktree was made, and the branch names ``main``."""
    tree = Tree(tmp_path)
    objects = tree.root / "agent-objects"
    objects.mkdir()
    run = change_run(tree, objects)
    (tree.main / "more.txt").write_text("y", encoding="utf-8")
    git(tree.env, "add", "more.txt", cwd=tree.main)
    git(tree.env, "commit", "-q", "-m", "second", cwd=tree.main)
    make_symbolic(tree)
    message = run._import_objects()  # type: ignore[attr-defined]
    assert message is not None and "symbolic" in message
    assert "refs/heads/main" in main_branches(tree)
    assert (tree.main / ".git" / "logs" / "refs" / "heads" / "main").exists()


def test_the_delete_of_a_refused_import_never_reaches_main_even_when_the_check_is_bypassed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defence in depth: the ``update-ref -d`` of the refused import carries ``--no-deref``."""
    tree = Tree(tmp_path)
    objects = tree.root / "agent-objects"
    objects.mkdir()
    run = change_run(tree, objects)
    (tree.main / "more.txt").write_text("y", encoding="utf-8")
    git(tree.env, "add", "more.txt", cwd=tree.main)
    git(tree.env, "commit", "-q", "-m", "second", cwd=tree.main)
    make_symbolic(tree)
    monkeypatch.setattr(runner, "branch_ref_problem", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        run,
        "_pipe_git",
        lambda args, tree_, env, data: "refused" if args[0] == "unpack-objects" else b"pack",
        raising=False,
    )
    assert run._import_objects() == "refused"  # type: ignore[attr-defined]
    assert "refs/heads/main" in main_branches(tree)


def test_cleanup_keeps_main_when_the_empty_branch_of_a_run_is_a_symbolic_ref(
    handoff_sandbox: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Route a of the review through ``cli.py cleanup``: the branch is at the base, and main did not move."""
    sb = handoff_sandbox
    use(monkeypatch)
    run_change(sb, "")
    ref = sb.main_tree / ".git" / "refs" / "heads" / "handoff" / CHANGE
    ref.unlink(missing_ok=True)
    ref.write_text("ref: refs/heads/main\n", encoding="utf-8")
    done = cleanup(sb)
    refs = git_text(sb, "-C", str(sb.main_tree), "for-each-ref", "--format=%(refname)", "refs/heads")
    assert "refs/heads/main" in refs, (done.stdout, done.stderr)
    assert "symbolic" in done.stdout
    assert local_branches(sb) != [] or ref.exists()


def test_a_run_whose_agent_made_its_branch_symbolic_ends_needs_human(handoff_sandbox: Any) -> None:
    ended = run_change(handoff_sandbox, "commit,symref-branch")
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, runner.BRANCH_REF_IS_SYMBOLIC)
    refs = git_text(
        handoff_sandbox, "-C", str(handoff_sandbox.main_tree), "for-each-ref", "--format=%(refname)", "refs/heads"
    )
    assert "refs/heads/main" in refs


def test_a_publish_of_a_symbolic_branch_is_held_before_the_push(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    make_symbolic(tree)
    assert probe(tree) is not None  # the publish step asks the same question as the run's end


# ---------------------------------------------------------------------------------------------
# T4-R6-05: a lock that the run left
# ---------------------------------------------------------------------------------------------


def test_a_stale_lock_of_the_branch_or_of_packed_refs_is_named(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    assert runner.stale_ref_locks(str(tree.main), "handoff/x") == ()
    (tree.main / ".git/refs/heads/handoff/x.lock").write_text("", encoding="utf-8")
    (tree.main / ".git/packed-refs.lock").write_text("", encoding="utf-8")
    names = runner.stale_ref_locks(str(tree.main), "handoff/x")
    assert names == ("packed-refs.lock", "refs/heads/handoff/x.lock")


# ---------------------------------------------------------------------------------------------
# T4-R6-02: the names that the deny list had missed
# ---------------------------------------------------------------------------------------------

NEW_KIRO_DIRS = ("extensions", "prompts", "mates", "crew", "tools", "memories", "docs", "specs", "identities")
NEW_KIRO_FILES = ("argv.json", "writing-deny-list.md")


def test_the_profile_closes_the_rest_of_the_kiro_control_plane() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/Projects/r"], kiro_home="/Users/u/kh")
    for name in NEW_KIRO_DIRS:
        assert f'(deny file-write* (subpath "/Users/u/.kiro/{name}"))' in text
        assert f'(deny file-write* (subpath "/Users/u/kh/{name}"))' in text
    for name in NEW_KIRO_FILES:
        assert f'(deny file-write* (literal "/Users/u/.kiro/{name}"))' in text
        assert f'(deny file-write* (literal "/Users/u/kh/{name}"))' in text
    for state_dir in ("sessions", "logs", "session-index", "session-leases", "cloud-cache", "tasks"):
        assert f"/.kiro/{state_dir}" not in text, "the state of kiro-cli stays writable"


def test_the_profile_closes_the_editors_settings_and_the_shell_extras() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"])
    for name in ("Library/Application Support/Kiro/User", "Library/Application Support/Code/User", ".vscode"):
        assert f'(deny file-write* (subpath "/Users/u/{name}"))' in text
    for name in (".oh-my-zsh", ".zshrc.d", ".cargo/bin"):
        assert f'(deny file-write* (subpath "/Users/u/{name}"))' in text
    for name in (".vimrc", ".tmux.conf"):
        assert f'(deny file-write* (literal "/Users/u/{name}"))' in text


def test_the_profile_closes_the_git_control_of_every_repository_below_home_before_the_run_allowances() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"], allow_write=["/w/run"])
    rule = [line for line in text.splitlines() if "hooks|info" in line or "hooks" in line and "regex" in line]
    assert rule, "a regex rule closes .git/hooks, .git/info and .git/config below home"
    assert text.index(rule[0]) < text.index('(allow file-write* (subpath "/w/run"))')


@needs_sandbox_exec
def test_an_agent_cannot_plant_a_hook_in_a_repository_the_configuration_does_not_name(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    other = tree.home / "Projects" / "other"
    other.mkdir(parents=True)
    git(tree.env, "init", "-q", cwd=other)
    profile = strict_profile(tree)
    plant = f'printf "#!/bin/sh\\n" > "{other}/.git/hooks/pre-commit"'
    assert tree.sandboxed(profile, plant).returncode != 0
    assert not (other / ".git/hooks/pre-commit").exists()
    for target in ("config", "info/exclude"):
        assert tree.sandboxed(profile, f': >> "{other}/.git/{target}"').returncode != 0
    # control: the same plant works under the profile without the rule, and a repository inside the worktree stays open
    text = profile.read_text(encoding="utf-8")
    loose = "\n".join(line for line in text.splitlines() if "hooks" not in line or "regex" not in line)
    profile.write_text(loose, encoding="utf-8")
    assert tree.sandboxed(profile, plant).returncode == 0
    profile = strict_profile(tree)
    inner = "git init -q inner && printf x > inner/.git/hooks/pre-commit"
    assert tree.sandboxed(profile, inner).returncode == 0, "a test that runs git init in the worktree must still work"


@needs_sandbox_exec
@pytest.mark.parametrize(
    "target",
    [
        ".kiro/extensions/x/extension.js",
        ".kiro/prompts/p.md",
        ".kiro/mates/agents/a.json",
        ".kiro/argv.json",
        ".kiro/writing-deny-list.md",
        "Library/Application Support/Kiro/User/settings.json",
        ".oh-my-zsh/custom/x.zsh",
        ".cargo/bin/x",
    ],
)
def test_an_agent_cannot_write_the_new_control_names(tmp_path: Path, target: str) -> None:
    tree = Tree(tmp_path)
    path = tree.home / target
    path.parent.mkdir(parents=True, exist_ok=True)
    profile = strict_profile(tree)
    assert tree.sandboxed(profile, f': > "{path}"').returncode != 0
    state_dir = tree.home / ".kiro" / "sessions"
    state_dir.mkdir(parents=True, exist_ok=True)
    assert tree.sandboxed(profile, f': > "{state_dir}/s.json"').returncode == 0, "kiro-cli's own state stays open"


def write_includer(home: Path, outside: Path) -> None:
    (home / ".gitconfig").write_text(f"[include]\n\tpath = {outside}\n", encoding="utf-8")


def test_a_git_config_included_from_outside_home_is_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "shared" / "extra.gitconfig"
    outside.parent.mkdir()
    outside.write_text("[core]\n\teditor = vi\n", encoding="utf-8")
    write_includer(home, outside)
    monkeypatch.setenv("HOME", str(home))
    files = runner._git_config_files(os.path.realpath(home))
    assert os.path.realpath(outside) in files


# ---------------------------------------------------------------------------------------------
# T4-R6-03: processes that outlive the run
# ---------------------------------------------------------------------------------------------

DETACH = textwrap.dedent(
    """
    import os, sys, time
    if os.fork():
        time.sleep(2 * float(os.environ.get("DETACH_LINGER", "0")))
        sys.exit(0)
    os.setsid()
    os.chdir("/")
    if os.fork():
        time.sleep(float(os.environ.get("DETACH_LINGER", "0")))
        os._exit(0)
    open(sys.argv[1], "w").write(str(os.getpid()))
    time.sleep(60)
    """
)


def start_detached(tmp_path: Path, token: str | None) -> int:
    """What an agent does: fork, ``setsid``, ``chdir("/")``, fork again. Returns the PID of the survivor."""
    marker = tmp_path / "pid"
    env = {k: v for k, v in os.environ.items() if k != runner.RUN_TOKEN_VARIABLE}
    if token is not None:
        env[runner.RUN_TOKEN_VARIABLE] = token
    subprocess.run([sys.executable, "-c", DETACH, str(marker)], env=env, check=True, stdin=subprocess.DEVNULL)
    for _ in range(100):
        if marker.exists() and marker.read_text():
            return int(marker.read_text())
        time.sleep(0.05)
    raise AssertionError("the detached process did not start")


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_a_detached_process_that_left_the_directory_is_found_by_the_token_and_stopped(tmp_path: Path) -> None:
    token = runner.new_run_token("c-x")
    pid = start_detached(tmp_path, token)
    try:
        assert pid in runner._pids_with_token(token)
        assert runner.reap_survivors(token, {}) == (pid,)
        assert not alive(pid)
    finally:
        if alive(pid):
            os.kill(pid, signal.SIGKILL)


def test_a_process_of_another_token_is_left_alone(tmp_path: Path) -> None:
    other = start_detached(tmp_path, runner.new_run_token("c-y"))
    try:
        assert runner.reap_survivors(runner.new_run_token("c-x"), {}) == ()
        assert alive(other)
    finally:
        os.kill(other, signal.SIGKILL)


def test_a_descendant_that_dropped_the_token_is_found_by_the_tracker(tmp_path: Path) -> None:
    """``env -i``: the token is gone; the tracker saw it below the process that the harness started."""
    marker = tmp_path / "pid"
    parent_code = textwrap.dedent(
        f"""
        import subprocess, sys, time
        subprocess.Popen([sys.executable, "-c", {DETACH!r}, {str(marker)!r}], env={{"DETACH_LINGER": "0.6"}})
        time.sleep(1.5)
        """
    )
    parent = subprocess.Popen([sys.executable, "-c", parent_code], stdin=subprocess.DEVNULL)
    tracker = runner.DescendantTracker(interval_seconds=0.05)
    tracker.start(parent.pid)
    parent.wait()
    seen = tracker.stop()
    for _ in range(100):
        if marker.exists() and marker.read_text():
            break
        time.sleep(0.05)
    pid = int(marker.read_text())
    try:
        assert pid not in runner._pids_with_token("none")
        assert pid in seen
        assert pid in runner.reap_survivors("none", seen)
        assert not alive(pid)
    finally:
        if alive(pid):
            os.kill(pid, signal.SIGKILL)


def test_a_reused_pid_with_another_start_time_is_not_stopped(tmp_path: Path) -> None:
    other = start_detached(tmp_path, runner.new_run_token("c-y"))
    try:
        assert runner.reap_survivors("none", {other: "Mon Jan  1 00:00:00 1990"}) == ()
        assert alive(other)
    finally:
        os.kill(other, signal.SIGKILL)


def test_the_harness_and_its_parents_are_never_stopped(tmp_path: Path) -> None:
    token = runner.new_run_token("c-x")
    os.environ[runner.RUN_TOKEN_VARIABLE] = token
    try:
        assert os.getpid() not in runner._pids_with_token(token)
        assert runner.reap_survivors(token, {os.getpid(): runner._process_table()[os.getpid()].started}) == ()
    finally:
        del os.environ[runner.RUN_TOKEN_VARIABLE]


def test_a_run_that_leaves_a_detached_process_has_it_stopped_before_it_is_judged(handoff_sandbox: Any) -> None:
    """The fake leaves a process that left its group and its directory, and writes ``late.txt`` after 3 seconds."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit,setsid-chdir-orphan")
    names = ended.record["observations"]["control_plane_changed"]
    assert any(name.startswith("orphan_process:") for name in names), names
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, "control_plane_changed")
    time.sleep(4)
    assert not (ended.worktree / "late.txt").exists(), "the process was stopped before it could write"


def test_a_run_without_survivors_is_not_flagged(handoff_sandbox: Any) -> None:
    ended = run_change(handoff_sandbox, "commit")
    assert ended.record["observations"]["control_plane_changed"] == []


# keep a reference so that a linter does not drop the helper used only by parametrized sandbox tests
_ = osb


def test_a_run_that_leaves_a_ref_lock_ends_needs_human_and_keeps_the_lock(handoff_sandbox: Any) -> None:
    sb = handoff_sandbox
    ended = run_change(sb, "commit,stale-ref-lock")
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, runner.STALE_REF_LOCK)
    assert (sb.main_tree / ".git" / "refs" / "heads" / "handoff" / f"{CHANGE}.lock").exists()

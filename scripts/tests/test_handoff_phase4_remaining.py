"""The branch that a stopped run leaves (task 5.45) and the order of the end of a run (task 5.51).

No ``kiro-cli`` starts, no ``sandbox-exec`` runs and no real home, repository or credential is touched: git runs in
throwaway directories with an empty global configuration (``credential.helper`` is cleared as well), and the steps of
``_finish`` are replaced by recorders.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from handoff import runner, state
from test_handoff_round4_boundary import Tree, git


def _agent_commit(tree: Tree, objects: Path) -> str:
    """What a change run does: commit in the worktree with the objects going to the run's own directory."""
    env = {
        **tree.env,
        "GIT_OBJECT_DIRECTORY": str(objects),
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(tree.main / ".git" / "objects"),
    }
    (tree.wt / "new.txt").write_text("agent", encoding="utf-8")
    git(env, "-c", "credential.helper=", "add", "new.txt", cwd=tree.wt)
    git(env, "-c", "credential.helper=", "commit", "-q", "-m", "agent", cwd=tree.wt)
    return git(tree.env, "rev-parse", "refs/heads/handoff/x", cwd=tree.main).stdout.decode().strip()


# ---------------------------------------------------------------------------------------------
# 5.45: a branch whose tip object exists only in the run's own directory is found and held
# ---------------------------------------------------------------------------------------------


def test_a_branch_at_the_base_is_not_dangling(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    assert runner.dangling_handoff_branches(str(tree.main), timeout_seconds=30) == ()


def test_a_branch_whose_tip_is_only_in_the_run_directory_is_dangling_until_it_is_imported(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    objects = tree.root / "agent-objects"
    objects.mkdir()
    head = _agent_commit(tree, objects)
    assert not (tree.main / ".git" / "objects" / head[:2] / head[2:]).exists()
    assert runner.dangling_handoff_branches(str(tree.main), timeout_seconds=30) == ("handoff/x",)
    shutil.copytree(objects, tree.main / ".git" / "objects", dirs_exist_ok=True)  # the import (28.130)
    assert runner.dangling_handoff_branches(str(tree.main), timeout_seconds=30) == ()


def test_a_branch_outside_handoff_is_not_looked_at(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    (tree.main / ".git" / "refs" / "heads" / "other").write_text("1" * 40 + "\n", encoding="utf-8")
    assert runner.dangling_handoff_branches(str(tree.main), timeout_seconds=30) == ()


class _Recorder:
    """The parts of a run that ``_create_worktree`` reads, with the git steps that must not run made to fail."""

    def __init__(self, main_tree: str, branch: str) -> None:
        self.plan = None
        self.timeout = 30
        self.item = SimpleNamespace(id="item-b")
        self.held: list[tuple[str, str]] = []
        self._plan = SimpleNamespace(branch=branch, main_tree=main_tree)

    def _hold(self, reason: str, detail: str) -> str:
        self.held.append((reason, detail))
        return reason

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"{name} must not be used after a dangling branch was found")


def test_the_next_run_is_held_before_it_fetches_or_makes_a_worktree(tmp_path: Path) -> None:
    """Another item's run is held too: the dangling branch is in the repository that every run uses."""
    tree = Tree(tmp_path)
    objects = tree.root / "agent-objects"
    objects.mkdir()
    _agent_commit(tree, objects)
    run = _Recorder(str(tree.main), "handoff/item-b")
    got = runner._QueryRun._create_worktree(run, run._plan)  # type: ignore[arg-type]
    assert got == runner.DANGLING_BRANCH_REF and run.held[0][0] == "dangling_branch_ref"
    assert "handoff/x" in run.held[0][1]


def test_without_a_dangling_branch_the_check_lets_the_run_go_on(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    run = _Recorder(str(tree.main), "handoff/item-b")
    with pytest.raises(AssertionError, match="_git must not be used"):
        runner._QueryRun._create_worktree(run, run._plan)  # type: ignore[arg-type]
    assert run.held == []


# ---------------------------------------------------------------------------------------------
# 5.45 and 5.51: what _finish does, in order
# ---------------------------------------------------------------------------------------------


class _Report:
    def write(self) -> None:
        pass


def _finish_stub(tmp_path: Path, calls: list[str], *, ending: str = "exited", exit_code: int | None = 0) -> Any:
    objects = tmp_path / "agent-objects"
    objects.mkdir(exist_ok=True)

    def step(name: str, value: Any = None) -> Any:
        def call(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            if isinstance(value, BaseException):
                raise value
            return value

        return call

    ended: list[tuple[str, str, str | None]] = []
    stub = SimpleNamespace(
        worktree="/w",
        main_tree="/m",
        worktree_identity=None,
        gitdir_problem=None,
        item=SimpleNamespace(mode="change", id="item-a"),
        agent_objects=objects,
        branch="handoff/item-a",
        git_env={},
        timeout=1,
        ended=ended,
    )
    stub._reap_survivors = step("reap")
    stub._import_objects = step("import", None)
    stub._observe = step("observe", runner._NestedRepository(["sub"]))
    stub._boundary_changes = step("boundary", (None, None))
    stub._evaluate = step("evaluate")

    def end(
        report: Any, to_state: str, reason: str, *, note: str | None = None, **_: Any
    ) -> tuple[str, str, str | None]:
        calls.append("end")
        ended.append((to_state, reason, note))
        return (to_state, reason, note)

    stub._end = end
    stub._left_branch_note = lambda: runner._QueryRun._left_branch_note(stub)
    stub._result = SimpleNamespace(ending=ending, exit_code=exit_code, timed_out=False, start_error=None)
    return stub


def _patch_steps(monkeypatch: pytest.MonkeyPatch, calls: list[str], **problems: Any) -> None:
    def recorded(name: str, value: Any) -> Any:
        def call(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            return value

        return call

    monkeypatch.setattr(runner, "worktree_gitdir_problem", recorded("gitdir", problems.get("gitdir")))
    monkeypatch.setattr(runner, "branch_ref_problem", recorded("symref", problems.get("symref")))
    monkeypatch.setattr(runner, "stale_ref_locks", recorded("lock", problems.get("lock", ())))


def _finish(stub: Any) -> Any:
    return runner._QueryRun._finish(stub, _Report(), stub._result, None)  # type: ignore[arg-type]


ORDER = ["reap", "gitdir", "symref", "lock", "import", "observe", "end"]


def test_the_end_of_a_run_goes_through_its_steps_in_the_order_of_28_146(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    _patch_steps(monkeypatch, calls)
    _finish(_finish_stub(tmp_path, calls))
    assert calls == ORDER


@pytest.mark.parametrize(
    ("problem", "last_step", "reason"),
    [
        ("gitdir", "gitdir", runner.WORKTREE_GITDIR_TAMPERED),
        ("symref", "symref", runner.BRANCH_REF_IS_SYMBOLIC),
        ("lock", "lock", runner.STALE_REF_LOCK),
    ],
)
def test_a_problem_found_by_a_step_stops_every_later_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, problem: str, last_step: str, reason: str
) -> None:
    calls: list[str] = []
    values: dict[str, Any] = {problem: ("x.lock",) if problem == "lock" else "a problem"}
    _patch_steps(monkeypatch, calls, **values)
    stub = _finish_stub(tmp_path, calls)
    _finish(stub)
    assert calls == ORDER[: ORDER.index(last_step) + 1] + ["end"]
    assert stub.ended[0][:2] == (state.NEEDS_HUMAN, reason)


def test_a_refused_import_stops_the_observation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    _patch_steps(monkeypatch, calls)
    stub = _finish_stub(tmp_path, calls)
    stub._import_objects = lambda: (calls.append("import"), "refused")[1]
    _finish(stub)
    assert calls == ["reap", "gitdir", "symref", "lock", "import", "end"]
    assert stub.ended[0][:2] == (state.NEEDS_HUMAN, runner.OBJECT_IMPORT_REJECTED)


@pytest.mark.parametrize("ending", ["stopped", "not_started"])
def test_a_stopped_or_unstarted_run_reaps_first_and_imports_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: str
) -> None:
    calls: list[str] = []
    _patch_steps(monkeypatch, calls)
    stub = _finish_stub(tmp_path, calls, ending=ending, exit_code=None)
    _finish(stub)
    assert calls == ["reap", "gitdir", "end"]


@pytest.mark.parametrize("ending", ["stopped", "not_started"])
def test_a_stopped_run_keeps_its_branch_and_objects_and_says_the_next_run_will_find_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: str
) -> None:
    """Task 5.45, the safe side: nothing is deleted, and the note names the branch, the objects and the hold."""
    calls: list[str] = []
    _patch_steps(monkeypatch, calls)
    stub = _finish_stub(tmp_path, calls, ending=ending, exit_code=None)
    _finish(stub)
    note = stub.ended[0][2] or ""
    assert "handoff/item-a" in note and str(stub.agent_objects) in note and "dangling_branch_ref" in note
    assert os.path.isdir(stub.agent_objects)


def test_an_interrupted_run_says_it_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    _patch_steps(monkeypatch, calls)
    stub = _finish_stub(tmp_path, calls, ending="interrupted", exit_code=None)
    with pytest.raises(KeyboardInterrupt):
        _finish(stub)
    assert calls == ["reap", "gitdir", "end"] and "dangling_branch_ref" in (stub.ended[0][2] or "")


def test_a_query_run_has_no_branch_to_leave(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    _patch_steps(monkeypatch, calls)
    stub = _finish_stub(tmp_path, calls, ending="stopped", exit_code=None)
    stub.item = SimpleNamespace(mode="query", id="item-q")
    stub.worktree, stub.agent_objects, stub.branch = None, None, None
    _finish(stub)
    assert calls == ["end"] and "dangling_branch_ref" not in (stub.ended[0][2] or "")

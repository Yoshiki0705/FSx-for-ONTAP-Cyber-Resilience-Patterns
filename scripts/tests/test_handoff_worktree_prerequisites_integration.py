"""Tests of the worktree prerequisites, the branch checks and ``cleanup`` of a change item (task 15.3, second stage).

Each test runs ``python cli.py run --items <change item>`` in the ``handoff_sandbox`` of ``conftest.py``
with the fake ``kiro-cli``, as ``test_handoff_change_integration.py`` does, and reuses its helpers.
The sandbox repository ``example-hub`` is given a gitignored ledger and a tool directory in its main
working tree, as the Hub has ``.private/knowledge-quality/`` and ``.venv/bin``; nothing here is a real
repository, path or credential.

What is checked, each against the failure it prevents:

- the ledger is copied into the worktree, read-only, and only when git ignores it there; otherwise the
  item is held before ``kiro-cli`` starts (``prerequisite_not_ignored``);
- a missing ledger or tool directory holds the item before a worktree exists (``prerequisite_missing``);
- the tool directory is first on ``PATH`` of ``kiro-cli`` and of the re-runs of the verification commands;
- an existing ``handoff/<id>`` branch holds the item before ``git worktree add`` (``branch_exists``);
- the item's branch has ``origin/main`` as its upstream;
- ``cleanup --approved`` removes the read-only copy with the worktree, and deletes ``handoff/<id>`` only
  when it still points at the recorded creation SHA.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import test_handoff_change_integration as change
from handoff import state

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from conftest import HandoffSandbox

#: ``change.prepare`` before any test replaces it, so that the replacement can call it.
PLAIN_PREPARE = change.prepare

LEDGER = ".private/ledger"
TOOLS = ".venv/bin"
PROBE = "handoff-probe-tool"
LEDGER_LINE = "synthetic ledger line\n"

#: Verification command that exits 0 only when the tool directory is on ``PATH`` of the re-run.
VERIFY_PROBE: change.Verify = ([PROBE], True)


@pytest.fixture(autouse=True)
def _writable_sandbox_at_exit(handoff_sandbox: HandoffSandbox) -> Iterator[None]:
    """Give the write bit back to what a test left read-only, so that the sandbox can be removed.

    ``handoff_sandbox`` removes its directory with ``shutil.rmtree`` after this fixture, and a
    read-only copy that no ``cleanup`` removed would stop it. This fixture depends on the sandbox,
    so pytest tears it down first.
    """
    yield
    for dirpath, _dirnames, _filenames in os.walk(handoff_sandbox.root):
        os.chmod(dirpath, stat.S_IMODE(os.lstat(dirpath).st_mode) | 0o700)


def make_prepare(
    *,
    prerequisites: dict[str, Any] | None,
    ledger: bool = True,
    tools: bool = True,
    ignored: bool = True,
    symlink_in_ledger: bool = False,
) -> Any:
    """A replacement for ``change.prepare`` that also writes the prerequisites and what they name."""

    def prepare(sb: HandoffSandbox, verify: Sequence[change.Verify] = ()) -> None:
        PLAIN_PREPARE(sb, verify)
        if prerequisites is not None:
            path = sb.handoff_dir / "config.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["repos"][change.REPO]["prerequisites"] = prerequisites
            path.write_text(json.dumps(data), encoding="utf-8")
        if ledger:
            (sb.main_tree / LEDGER).mkdir(parents=True)
            (sb.main_tree / LEDGER / "issues.jsonl").write_text(LEDGER_LINE, encoding="utf-8")
            if symlink_in_ledger:
                (sb.main_tree / LEDGER / "link").symlink_to("issues.jsonl")
        if tools:
            (sb.main_tree / TOOLS).mkdir(parents=True)
            probe = sb.main_tree / TOOLS / PROBE
            probe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            probe.chmod(0o755)
        if ignored:
            exclude = Path(
                sb.git("-C", str(sb.main_tree), "rev-parse", "--git-path", "info/exclude").stdout.decode().strip()
            )
            exclude = exclude if exclude.is_absolute() else sb.main_tree / exclude
            exclude.parent.mkdir(parents=True, exist_ok=True)
            exclude.write_text("/.private/\n/.venv/\n", encoding="utf-8")

    return prepare


BOTH = {"copy_readonly": [LEDGER], "path_prepend": [TOOLS]}


def use(monkeypatch: pytest.MonkeyPatch, **options: Any) -> None:
    """Make ``change.run_change`` prepare the sandbox with the prerequisites."""
    monkeypatch.setattr(change, "prepare", make_prepare(prerequisites=options.pop("prerequisites", BOTH), **options))


def held(sb: HandoffSandbox, *, chat_started: bool = False) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    """Prepare as :func:`use` set up, record the selftest, run the item once, and return the process and its record."""
    change.prepare(sb)
    change.record_selftest(sb)
    seen = len(sb.invocations())
    done = change.run_cli(
        sb, "run", "--items", change.CHANGE, FAKE_KIRO_MODE="commit", FAKE_KIRO_COMMIT_FILES=change.DECLARED
    )
    runs = [run["start"]["subcommand"] for run in sb.invocations()[seen:]]
    assert ("chat" in runs) is chat_started, (runs, done.stderr)
    record: dict[str, Any] = dict(change.read_status(sb)["items"][change.CHANGE])
    return done, record


def reason_of(record: dict[str, Any]) -> str:
    """The reason of the item's last transition."""
    return str(record["history"][-1]["reason"])


def cleanup(sb: HandoffSandbox) -> subprocess.CompletedProcess[str]:
    """``cli.py cleanup <change item> --approved``."""
    return change.run_cli(sb, "cleanup", change.CHANGE, "--approved")


def local_branches(sb: HandoffSandbox) -> list[str]:
    """The names of the local ``handoff/*`` branches of the main working tree's repository."""
    out = change.git_text(
        sb, "-C", str(sb.main_tree), "for-each-ref", "--format=%(refname:short)", "refs/heads/handoff"
    )
    return out.splitlines()


# ---------------------------------------------------------------------------------------------
# the ledger and the tool directory reach the worktree and the children
# ---------------------------------------------------------------------------------------------


def test_the_ledger_is_copied_read_only_and_the_tools_are_first_on_the_path(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The copy is ignored by git, has no write bit, and ``PATH`` leads with the tool directory for the agent and the re-runs."""
    sb = handoff_sandbox
    use(monkeypatch)
    ended = change.run_change(sb, "commit", verify=[VERIFY_PROBE])
    worktree = ended.worktree
    assert ended.record["state"] == state.SUCCEEDED, ended.done.stderr
    assert ended.record["rerun"] and not ended.record["rerun_skipped"]  # the probe ran, and found the tool on PATH
    assert (worktree / LEDGER / "issues.jsonl").read_text(encoding="utf-8") == LEDGER_LINE
    assert not os.access(worktree / LEDGER / "issues.jsonl", os.W_OK)
    assert stat.S_IMODE((worktree / LEDGER).stat().st_mode) & 0o222 == 0
    assert change.git_text(sb, "-C", str(worktree), "status", "--porcelain") == ""
    assert ended.chat["start"]["env"]["path_first"] == str(sb.main_tree / TOOLS)


def test_a_ledger_that_git_does_not_ignore_in_the_worktree_holds_the_item_before_the_agent_starts(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Copying a file that git would show as untracked could put it into a commit, so the copy is withdrawn."""
    sb = handoff_sandbox
    monkeypatch.setattr(change, "prepare", make_prepare(prerequisites=BOTH, ignored=False))
    done, record = held(sb)
    assert record["state"] == state.NEEDS_HUMAN and reason_of(record) == "prerequisite_not_ignored", done.stderr
    assert not (sb.worktrees_root / change.REPO / change.CHANGE / LEDGER).exists()


@pytest.mark.parametrize("missing", ["ledger", "tools"])
def test_a_missing_prerequisite_holds_the_item_before_a_worktree_exists(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    """Fail closed: no worktree, no branch and no agent when the ledger or the tool directory is not there."""
    sb = handoff_sandbox
    monkeypatch.setattr(change, "prepare", make_prepare(prerequisites=BOTH, **{missing: False}))
    done, record = held(sb)
    assert record["state"] == state.NEEDS_HUMAN and reason_of(record) == "prerequisite_missing", done.stderr
    assert not (sb.worktrees_root / change.REPO / change.CHANGE).exists()
    assert local_branches(sb) == []


def test_a_symbolic_link_inside_the_ledger_holds_the_item(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A copied link would let a write to the read-only copy reach the original, so a ledger with one is refused."""
    sb = handoff_sandbox
    monkeypatch.setattr(change, "prepare", make_prepare(prerequisites=BOTH, symlink_in_ledger=True))
    done, record = held(sb)
    assert record["state"] == state.NEEDS_HUMAN and reason_of(record) == "prerequisite_missing", done.stderr
    assert not (sb.worktrees_root / change.REPO / change.CHANGE).exists()


# ---------------------------------------------------------------------------------------------
# the branch: no reuse of an earlier run's branch, and an upstream
# ---------------------------------------------------------------------------------------------


def test_an_existing_branch_holds_the_item_before_git_worktree_add(handoff_sandbox: HandoffSandbox) -> None:
    """The reason names the branch, not a git failure, and no worktree or agent follows."""
    sb = handoff_sandbox
    sb.git("-C", str(sb.main_tree), "branch", change.BRANCH, sb.base_sha)
    done, record = held(sb)
    assert record["state"] == state.NEEDS_HUMAN and reason_of(record) == "branch_exists", done.stderr
    assert not (sb.worktrees_root / change.REPO / change.CHANGE).exists()
    assert change.git_text(sb, "-C", str(sb.main_tree), "rev-parse", f"refs/heads/{change.BRANCH}") == sb.base_sha


def test_the_items_branch_follows_origin_main(handoff_sandbox: HandoffSandbox) -> None:
    """``worktree add`` from a SHA leaves no upstream; the harness sets ``origin/main`` so that ``branch -d`` can judge a merge."""
    sb = handoff_sandbox
    ended = change.run_change(sb, "commit")
    upstream = change.git_text(
        sb, "-C", str(sb.main_tree), "rev-parse", "--abbrev-ref", f"{change.BRANCH}@{{upstream}}"
    )
    assert upstream == "origin/main", ended.done.stderr


# ---------------------------------------------------------------------------------------------
# cleanup: the copy goes with the worktree; only an empty branch goes
# ---------------------------------------------------------------------------------------------


def test_cleanup_removes_the_read_only_copy_with_the_worktree_and_an_empty_branch(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run with no commit leaves ``handoff/<id>`` at the recorded SHA; ``cleanup`` removes it with ``update-ref -d``."""
    sb = handoff_sandbox
    use(monkeypatch)
    ended = change.run_change(sb, "")
    assert (ended.worktree / LEDGER / "issues.jsonl").exists()
    assert local_branches(sb) == [change.BRANCH]
    done = cleanup(sb)
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert not ended.worktree.exists()
    assert local_branches(sb) == []
    assert f"消した: ブランチ {change.BRANCH}" in done.stdout
    events = change.read_status(sb)["events"]
    assert [event["kind"] for event in events][-2:] == ["worktree_removed", "branch_removed"]


def test_cleanup_keeps_a_branch_that_has_a_commit(handoff_sandbox: HandoffSandbox) -> None:
    """The work is on the branch, so it stays; the worktree goes."""
    sb = handoff_sandbox
    ended = change.run_change(sb, "commit")
    done = cleanup(sb)
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert not ended.worktree.exists()
    assert local_branches(sb) == [change.BRANCH]
    assert "消さない" in done.stdout


def test_cleanup_removes_an_empty_branch_whose_worktree_is_already_gone(handoff_sandbox: HandoffSandbox) -> None:
    """The state that a plain ``cleanup`` once left behind: no worktree, an empty branch. A second ``cleanup`` finishes it."""
    sb = handoff_sandbox
    ended = change.run_change(sb, "")
    sb.git("-C", str(sb.main_tree), "worktree", "remove", str(ended.worktree))
    assert local_branches(sb) == [change.BRANCH]
    done = cleanup(sb)
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert local_branches(sb) == []

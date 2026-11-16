"""Recording the tip of ``status.log.jsonl`` where Git keeps it (task 5.19, design D-38 item 6).

``status.log.jsonl`` lives in ``.private/`` (gitignored), so a rewrite of the whole file is not seen by
anything outside the machine. ``runner.record_log_tip`` writes the SHA-256 of the log's last line to the
branch ``handoff-log-tips`` of the harness's own repository, with git plumbing only (the working tree, the
index and ``.git/config`` of a shared main tree are not touched), and pushes it. The branch holds a digest
and nothing else: no path, no item id, no state. ``Harness`` calls the recorder after an item reaches a
final state or is re-queued; a recorder that fails never fails the harness.

Every test uses a throwaway repository and a local bare repository as ``origin``. No network.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from handoff import cli, runner, state
from test_handoff_cli_integration import call, prepare

if TYPE_CHECKING:
    from conftest import HandoffSandbox

ITEM = "z-secret-item-name"
LOG_LINES = [
    {"at": "2026-11-16T00:00:00Z", "transitions": [{"item": ITEM, "to": "failed"}], "marker": "first"},
    {"at": "2026-11-16T00:01:00Z", "transitions": [{"item": ITEM, "to": "queued"}], "marker": "second"},
]


def git(cwd: Path, *argv: str, check: bool = True) -> str:
    """Run git in ``cwd`` with a clean identity; the standard output."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    done = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t", *argv],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=check,
    )
    return done.stdout


def sha(line: dict[str, object]) -> str:
    """SHA-256 of a log line as the harness writes it (no newline)."""
    return hashlib.sha256(json.dumps(line, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_log(tree: Path, lines: list[dict[str, object]]) -> Path:
    """Write ``.private/handoff/status.log.jsonl``; return the handoff directory."""
    directory = tree / ".private" / "handoff"
    directory.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(x, sort_keys=True, separators=(",", ":")) + "\n" for x in lines)
    (directory / "status.log.jsonl").write_text(text, encoding="utf-8")
    return directory


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, Path]:
    """A main tree with one commit and a bare ``origin``; (tree, origin)."""
    origin = tmp_path / "origin.git"
    git(tmp_path, "init", "-q", "--bare", str(origin))
    tree = tmp_path / "tree"
    git(tmp_path, "init", "-q", "-b", "main", str(tree))
    (tree / "README.md").write_text("x\n", encoding="utf-8")
    (tree / ".gitignore").write_text(".private/\n", encoding="utf-8")
    git(tree, "add", "README.md", ".gitignore")
    git(tree, "commit", "-q", "-m", "init")
    git(tree, "remote", "add", "origin", str(origin))
    return tree, origin


def tips(tree_or_origin: Path) -> list[dict[str, object]]:
    """The records of ``tips.jsonl`` on the branch."""
    text = git(tree_or_origin, "show", f"{runner.TIP_BRANCH}:{runner.TIP_FILE}")
    return [json.loads(line) for line in text.splitlines()]


def test_records_the_digest_of_the_last_line_and_pushes(repo: tuple[Path, Path]) -> None:
    tree, origin = repo
    directory = write_log(tree, LOG_LINES)
    result = runner.record_log_tip(str(directory))
    assert result.outcome == "recorded" and result.sha256 == sha(LOG_LINES[-1])
    [entry] = tips(tree)
    assert entry["sha256"] == sha(LOG_LINES[-1])
    assert git(origin, "rev-parse", runner.TIP_BRANCH) == git(tree, "rev-parse", runner.TIP_BRANCH)


def test_the_branch_holds_no_path_item_or_log_content(repo: tuple[Path, Path]) -> None:
    tree, _ = repo
    runner.record_log_tip(str(write_log(tree, LOG_LINES)))
    files = git(tree, "ls-tree", "-r", "--name-only", runner.TIP_BRANCH).split()
    assert sorted(files) == sorted([runner.TIP_FILE, "README.md"])
    everything = git(tree, "log", "-p", "--format=%an %ae %s", runner.TIP_BRANCH)
    for forbidden in (str(tree), ITEM, "first", "second", "failed", "queued", "/Users", ".private", "status.log"):
        assert forbidden not in everything, forbidden


def test_second_record_appends_on_the_first(repo: tuple[Path, Path]) -> None:
    tree, origin = repo
    runner.record_log_tip(str(write_log(tree, LOG_LINES[:1])))
    runner.record_log_tip(str(write_log(tree, LOG_LINES)))
    assert [e["sha256"] for e in tips(tree)] == [sha(LOG_LINES[0]), sha(LOG_LINES[1])]
    assert git(tree, "rev-list", "--count", runner.TIP_BRANCH).strip() == "2"
    assert git(origin, "rev-parse", runner.TIP_BRANCH) == git(tree, "rev-parse", runner.TIP_BRANCH)


def test_an_unchanged_tip_makes_no_commit(repo: tuple[Path, Path]) -> None:
    tree, _ = repo
    directory = write_log(tree, LOG_LINES)
    runner.record_log_tip(str(directory))
    head = git(tree, "rev-parse", runner.TIP_BRANCH)
    assert runner.record_log_tip(str(directory)).outcome == "unchanged"
    assert git(tree, "rev-parse", runner.TIP_BRANCH) == head


def test_the_main_tree_is_not_touched(repo: tuple[Path, Path]) -> None:
    tree, _ = repo
    (tree / "dirty.txt").write_text("uncommitted\n", encoding="utf-8")
    git(tree, "add", "dirty.txt")
    before = (
        git(tree, "status", "--porcelain=v1"),
        git(tree, "rev-parse", "HEAD"),
        (tree / ".git" / "config").read_bytes(),
        git(tree, "branch", "--show-current"),
    )
    runner.record_log_tip(str(write_log(tree, LOG_LINES)))
    after = (
        git(tree, "status", "--porcelain=v1"),
        git(tree, "rev-parse", "HEAD"),
        (tree / ".git" / "config").read_bytes(),
        git(tree, "branch", "--show-current"),
    )
    assert before == after


def test_a_failed_push_keeps_the_local_commit_and_does_not_raise(repo: tuple[Path, Path]) -> None:
    tree, _ = repo
    git(tree, "remote", "set-url", "origin", str(tree / "no-such-remote.git"))
    result = runner.record_log_tip(str(write_log(tree, LOG_LINES)))
    assert result.outcome == "push_failed"
    assert tips(tree)[0]["sha256"] == sha(LOG_LINES[-1])


def test_no_remote_is_recorded_locally(repo: tuple[Path, Path]) -> None:
    tree, _ = repo
    git(tree, "remote", "remove", "origin")
    assert runner.record_log_tip(str(write_log(tree, LOG_LINES))).outcome == "recorded_local"


def test_skips_without_a_log_or_outside_git(tmp_path: Path, repo: tuple[Path, Path]) -> None:
    tree, _ = repo
    directory = tree / ".private" / "handoff"
    directory.mkdir(parents=True)
    assert runner.record_log_tip(str(directory)).outcome == "skipped"
    plain = tmp_path / "plain"
    assert runner.record_log_tip(str(write_log(plain, LOG_LINES))).outcome == "skipped"


def test_a_remote_branch_is_fetched_when_the_local_one_is_gone(repo: tuple[Path, Path]) -> None:
    tree, origin = repo
    runner.record_log_tip(str(write_log(tree, LOG_LINES[:1])))
    git(tree, "branch", "-D", runner.TIP_BRANCH)
    runner.record_log_tip(str(write_log(tree, LOG_LINES)))
    assert [e["sha256"] for e in tips(origin)] == [sha(LOG_LINES[0]), sha(LOG_LINES[1])]


def _harness(tmp_path: Path, calls: list[int]) -> runner.Harness:
    directory = tmp_path / ".private" / "handoff"
    harness = runner.Harness.open(str(directory))
    harness.set_tip_recorder(lambda: calls.append(1))
    return harness


def _add(harness: runner.Harness, item_id: str) -> None:
    harness._commit(state.add_item(harness._status, item_id))  # noqa: SLF001


def test_the_harness_records_when_an_item_ends_or_is_requeued(tmp_path: Path) -> None:
    calls: list[int] = []
    with _harness(tmp_path, calls) as harness:
        _add(harness, "a")
        assert calls == []  # a new queued record is not a completion
        harness._move("a", state.RUNNING, "start")  # noqa: SLF001
        assert calls == []
        harness._move("a", state.FAILED, "stop")  # noqa: SLF001
        assert len(calls) == 1
        harness.requeue("a", reason="fixed")
        assert len(calls) == 2
        harness._move("a", state.RUNNING, "start")  # noqa: SLF001
        harness._move("a", state.SUCCEEDED, "done")  # noqa: SLF001
        assert len(calls) == 3


def test_a_failing_recorder_does_not_fail_the_harness(tmp_path: Path) -> None:
    def boom() -> None:
        raise OSError("disk")

    with runner.Harness.open(str(tmp_path / ".private" / "handoff")) as harness:
        harness.set_tip_recorder(boom)
        _add(harness, "a")
        harness._move("a", state.RUNNING, "start")  # noqa: SLF001
        harness._move("a", state.FAILED, "stop")  # noqa: SLF001
        assert harness._status["items"]["a"]["state"] == state.FAILED  # noqa: SLF001


def _sandbox_repo(sb: HandoffSandbox) -> Path:
    """Make the sandbox's harness tree a git repository with a log; return the handoff directory."""
    tree = Path(sb.harness_tree)
    git(tree.parent, "init", "-q", "-b", "main", str(tree))
    (tree / "README.md").write_text("x\n", encoding="utf-8")
    git(tree, "add", "README.md")
    git(tree, "commit", "-q", "-m", "init")
    return write_log(tree, LOG_LINES)


def test_cli_record_tip_prints_the_digest(handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    prepare(handoff_sandbox, monkeypatch)
    _sandbox_repo(handoff_sandbox)
    code, out, err = call(handoff_sandbox, "status", "--record-tip")
    assert code == cli.EXIT_OK, err
    assert sha(LOG_LINES[-1]) in out
    assert tips(Path(handoff_sandbox.harness_tree))[0]["sha256"] == sha(LOG_LINES[-1])


def test_cli_record_tip_fails_when_nothing_can_be_recorded(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepare(handoff_sandbox, monkeypatch)
    write_log(Path(handoff_sandbox.harness_tree), LOG_LINES)  # a plain directory: not a git repository
    code, _, _ = call(handoff_sandbox, "status", "--record-tip")
    assert code == cli.EXIT_ITEMS


def test_cli_opens_every_harness_with_the_recorder() -> None:
    source = Path(cli.__file__).read_text(encoding="utf-8")
    assert source.count("_open_harness(inputs)") >= 9
    assert source.count("runner.Harness.open(") == 1  # only inside _open_harness

"""Integration tests of the manual mode (task 5.5; Requirements 28.9 and 28.21).

When the Handoff_Harness cannot be used, ``cli.py manual <id>`` prints what the maintainer pastes
into the Kiro of the target repository, and ``cli.py verify <id> --worktree <path>`` observes the
worktree that the maintainer made, with the same steps as a change run. The tests start ``python
cli.py --handoff-dir <sandbox> ...`` in a subprocess with the sandbox of ``conftest.py``: a bare
repository as the remote, a clone as the target repository's main working tree (with uncommitted
changes of another session), and the fake ``kiro-cli``. Nothing reads or writes this machine's
``~/.kiro``, uses the network, or starts the real ``kiro-cli``.

- The display: the whole body, the repository to paste it into and the commands from ``fetch`` to
  ``worktree add`` are on standard output, and no state, record or worktree changes. The printed
  commands, run as printed, make a worktree that ``verify`` accepts.
- The same final state: a change item is run by the fake ``kiro-cli`` and a second change item is
  worked on by hand with the same git operations (a commit of the declared file, of an undeclared
  file, a file left uncommitted, a declared verification command that switches the main working
  tree's branch). The final state, the history reason and the observations are the same.
- Refusals: a worktree of another repository, a path git does not list, a worktree on another
  branch, a path inside the main working tree, a base that is not below ``HEAD``, an item that is
  not ``queued`` and a query item are refused with exit code 1, and ``status.json`` keeps its
  bytes. A relative path is an argument error (exit code 2).

Every test checks that the uncommitted changes of the main working tree have the same bytes
afterwards (Requirement 28.6), and that ``verify`` did not start ``kiro-cli``.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import state
from test_handoff_change_integration import (
    CHANGE,
    CHANGED_LINE,
    COMMIT_MESSAGE,
    DECLARED,
    LEFT_BEHIND,
    QUERY,
    REPO,
    UNDECLARED,
    Verify,
    git_text,
    history,
    item,
    prepare,
    read_status,
    record_selftest,
    remote_refs,
    run_cli,
    uncommitted,
)

if TYPE_CHECKING:
    from conftest import HandoffSandbox, MainTreeState

MANUAL = "c-hub-manual"
MANUAL_BRANCH = f"handoff/{MANUAL}"
T0 = "2026-11-10T00:00:00Z"
CHECKS_PASSED = "all_checks_passed"

#: Per case: what the fake ``kiro-cli`` does for the change item (``FAKE_KIRO_MODE``), what the
#: maintainer does by hand for the manual item (the same operations), whether both items declare a
#: verification command that switches the main working tree's branch, and the final state and
#: history reason that both must reach.
CASES: dict[str, tuple[str, tuple[str, ...], bool, str, str]] = {
    "commit": ("commit", ("commit",), False, state.SUCCEEDED, CHECKS_PASSED),
    "undeclared": ("undeclared", ("undeclared",), False, state.NEEDS_HUMAN, "undeclared_files"),
    "left-uncommitted": ("commit,write-file", ("commit", "write-file"), False, state.NEEDS_HUMAN, "dirty"),
    "main-tree-switched": ("commit", ("commit",), True, state.NEEDS_HUMAN, "main_tree_changed"),
}


def prepare_both(
    sb: HandoffSandbox, change_verify: list[Verify] | None = None, manual_verify: list[Verify] | None = None
) -> None:
    """Write the sandbox's inputs with a second change item, :data:`MANUAL`, at its own Sync_Point.

    The Handoff_Prompt path is ``sync/<sync point>-<repo>.md``, so the manual item needs a
    Sync_Point that no other item of the repository has.
    """
    prepare(sb, change_verify or [])
    path = sb.handoff_dir / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["items"].append(item(MANUAL, "c", "change", manual_verify or []))
    path.write_text(json.dumps(manifest), encoding="utf-8")


def switch_command(sb: HandoffSandbox, branch: str) -> Verify:
    """A verification command that makes ``branch`` in the main working tree and switches to it."""
    return (["git", "-C", str(sb.main_tree), "switch", "-q", "-c", branch], True)


def make_worktree(sb: HandoffSandbox, item_id: str = MANUAL, branch: str | None = None) -> Path:
    """The worktree that the printed commands make: ``<worktrees_root>/<repo>/<id>`` on a new branch at the base."""
    path = sb.worktrees_root / REPO / item_id
    sb.git(
        "-C", str(sb.main_tree), "worktree", "add", "-q", "-b", branch or f"handoff/{item_id}", str(path), sb.base_sha
    )
    return path


def work(sb: HandoffSandbox, worktree: Path, *operations: str) -> None:
    """Do by hand what the fake ``kiro-cli`` does for the behavior of the same name."""
    for operation in operations:
        if operation in ("commit", "undeclared"):
            name = DECLARED if operation == "commit" else UNDECLARED
            target = worktree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8") as handle:
                handle.write(CHANGED_LINE + "\n")
            sb.git("-C", str(worktree), "add", "--", name)
            sb.git("-C", str(worktree), "commit", "-q", "-m", COMMIT_MESSAGE)
        elif operation == "write-file":
            (worktree / LEFT_BEHIND).write_text(CHANGED_LINE + "\n", encoding="utf-8")
        else:
            raise AssertionError(operation)


def verify(sb: HandoffSandbox, worktree: Path | str, item_id: str = MANUAL) -> subprocess.CompletedProcess[str]:
    """``cli.py verify <id> --worktree <path>``."""
    return run_cli(sb, "verify", item_id, "--worktree", str(worktree))


def status_bytes(sb: HandoffSandbox) -> bytes | None:
    """``status.json`` as bytes, or ``None`` before the harness wrote one."""
    path = sb.handoff_dir / "status.json"
    return path.read_bytes() if path.exists() else None


def write_status(sb: HandoffSandbox, moves: list[tuple[str, str]], **fields: Any) -> bytes:
    """Write a ``status.json`` with a record of every item, the manual item's transitions and its record fields."""
    status = state.empty_status()
    for item_id in (QUERY, CHANGE, MANUAL):
        status = state.add_item(status, item_id)
    for to_state, reason in moves:
        status = state.transition(status, MANUAL, to_state, at=T0, reason=reason)
    status["items"][MANUAL].update(fields)
    data = state.render_status(status).encode("utf-8")
    (sb.handoff_dir / "status.json").write_bytes(data)
    return data


def shape(record: dict[str, Any]) -> tuple[Any, ...]:
    """What two runs of the same work must share: the final state, the reason and the observations.

    ``stdout_bytes`` is the fake ``kiro-cli``'s output, which a maintainer's hands do not have.
    """
    observations = dict(record["observations"])
    observations.pop("stdout_bytes")
    return (
        record["state"],
        record["history"][-1]["reason"],
        observations,
        [entry["exit_code"] for entry in record["rerun"]],
        len(record["rerun_skipped"]),
    )


def assert_main_tree_kept(before: MainTreeState, after: MainTreeState) -> None:
    """The main working tree has the same ``HEAD`` and the same uncommitted changes, byte for byte (28.6)."""
    assert uncommitted(after) == uncommitted(before)


def printed_commands(out: str) -> list[str]:
    """The four ``git -C`` lines that ``manual`` prints for the worktree."""
    return [line.strip() for line in out.splitlines() if line.startswith("    git -C ")]


# ---------------------------------------------------------------------------------------------
# the display
# ---------------------------------------------------------------------------------------------


def test_manual_prints_the_whole_body_the_repository_and_the_commands_and_changes_nothing(
    handoff_sandbox: HandoffSandbox,
) -> None:
    """Row: the body in full, the repository to paste into, and the commands from fetch to ``worktree add`` (28.21)."""
    sb = handoff_sandbox
    prepare_both(sb)
    before, refs_before = sb.snapshot_main_tree(), remote_refs(sb)
    registered_before = git_text(sb, "-C", str(sb.main_tree), "worktree", "list", "--porcelain")

    done = run_cli(sb, "manual", MANUAL)

    assert done.returncode == 0, (done.stdout, done.stderr)
    out = done.stdout
    assert f"手作業の引き継ぎ: {MANUAL}" in out
    assert f"- 貼り付ける先のリポジトリ: {REPO}" in out
    assert f"- モード: 変更モード（引き継ぎ用ブランチ {MANUAL_BRANCH}）" in out
    worktree = f"~/Projects/.handoff-worktrees/{REPO}/{MANUAL}"
    assert printed_commands(out) == [
        f"git -C ~/Projects/{REPO} fetch --no-tags origin main",
        f"git -C ~/Projects/{REPO} ls-remote origin refs/heads/main",
        f"git -C ~/Projects/{REPO} rev-parse refs/remotes/origin/main",
        f"git -C ~/Projects/{REPO} worktree add -b {MANUAL_BRANCH} {worktree} <sha>",
    ]
    body = out.split("----- ここから -----\n", 1)[1]
    assert body.endswith("----- ここまで -----\n")
    pasted = body[: -len("----- ここまで -----\n")]
    written = (sb.handoff_dir / "sync" / f"c-{REPO}.md").read_text(encoding="utf-8")
    assert pasted == written and "Add a line to the guide of the sandbox repository." in pasted

    # nothing changed: no record, no worktree, no fake kiro-cli run, and the main working tree as it was
    assert status_bytes(sb) is None and sb.records() == []
    assert git_text(sb, "-C", str(sb.main_tree), "worktree", "list", "--porcelain") == registered_before
    assert remote_refs(sb) == refs_before
    assert_main_tree_kept(before, sb.snapshot_main_tree())


def test_the_printed_commands_make_a_worktree_that_verify_accepts(handoff_sandbox: HandoffSandbox) -> None:
    """The four printed lines, run as printed, make the worktree; after a commit, ``verify`` ends ``succeeded``."""
    sb = handoff_sandbox
    prepare_both(sb)
    before = sb.snapshot_main_tree()
    printed = printed_commands(run_cli(sb, "manual", MANUAL).stdout)
    env = sb.environ()

    def shell(line: str) -> str:
        done = subprocess.run(
            line, shell=True, cwd=str(sb.root), env=env, capture_output=True, encoding="utf-8", check=True
        )
        return done.stdout.strip()

    shell(printed[0])
    listed, parsed = shell(printed[1]), shell(printed[2])
    assert listed.split("\t")[0] == parsed == sb.base_sha  # the check that the display asks for in step 1
    shell(printed[3].replace("<sha>", parsed))
    worktree = sb.worktrees_root / REPO / MANUAL
    assert git_text(sb, "-C", str(worktree), "symbolic-ref", "HEAD") == f"refs/heads/{MANUAL_BRANCH}"
    work(sb, worktree, "commit")

    done = verify(sb, worktree)

    assert done.returncode == 0, (done.stdout, done.stderr)
    assert done.stdout == f"{MANUAL}: {state.SUCCEEDED}（{CHECKS_PASSED}）\n"
    assert history(read_status(sb), MANUAL) == [
        (state.QUEUED, state.RUNNING, "manual_verify"),
        (state.RUNNING, state.SUCCEEDED, CHECKS_PASSED),
    ]
    assert sb.records() == []  # no kiro-cli ran
    assert_main_tree_kept(before, sb.snapshot_main_tree())


# ---------------------------------------------------------------------------------------------
# verify ends as a change run does
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("behaviors", "operations", "switches", "final", "reason"), list(CASES.values()), ids=list(CASES)
)
def test_verify_gives_the_final_state_that_a_change_run_gives_the_same_work(
    handoff_sandbox: HandoffSandbox,
    behaviors: str,
    operations: tuple[str, ...],
    switches: bool,
    final: str,
    reason: str,
) -> None:
    """Row: the fake ``kiro-cli`` and the maintainer do the same work, and the two items end the same (28.21)."""
    sb = handoff_sandbox
    change_verify = [switch_command(sb, "switched-by-change")] if switches else []
    manual_verify = [switch_command(sb, "switched-by-hand")] if switches else []
    prepare_both(sb, change_verify, manual_verify)
    record_selftest(sb)
    ran = run_cli(sb, "run", "--items", CHANGE, FAKE_KIRO_MODE=behaviors, FAKE_KIRO_COMMIT_FILES=DECLARED)
    assert ran.returncode == (0 if final == state.SUCCEEDED else 1), (ran.stdout, ran.stderr)
    assert read_status(sb)["items"][CHANGE]["state"] == final

    # the maintainer works by hand where the printed commands put the worktree; there is no kiro-cli any more
    worktree = make_worktree(sb)
    work(sb, worktree, *operations)
    sb.kiro_cli.unlink()
    runs_before = len(sb.records())
    before, refs_before = sb.snapshot_main_tree(), remote_refs(sb)

    done = verify(sb, worktree)

    assert done.returncode == (0 if final == state.SUCCEEDED else 1), (done.stdout, done.stderr)
    assert done.stdout == f"{MANUAL}: {final}（{reason}）\n"
    status = read_status(sb)
    changed, manual = status["items"][CHANGE], status["items"][MANUAL]
    assert shape(manual) == shape(changed)
    assert history(status, MANUAL) == [
        (state.QUEUED, state.RUNNING, "manual_verify"),
        (state.RUNNING, final, reason),
    ]
    assert history(status, CHANGE)[-1][1:] == (final, reason)
    assert (manual["branch"], manual["pid"]) == (MANUAL_BRANCH, None)
    assert manual["worktree"] == f"~/{worktree.relative_to(sb.home)}"
    assert manual["base_sha"] == changed["base_sha"] == sb.base_sha  # derived: the record had none
    assert manual["observations"]["commits"] == changed["observations"]["commits"]
    assert len(sb.records()) == runs_before  # verify started no kiro-cli
    assert remote_refs(sb) == refs_before
    after = sb.snapshot_main_tree()
    assert_main_tree_kept(before, after)
    assert after.branch == ("switched-by-hand" if switches else before.branch)


# ---------------------------------------------------------------------------------------------
# refusals
# ---------------------------------------------------------------------------------------------


def other_repository_worktree(sb: HandoffSandbox) -> Path:
    """A worktree on ``handoff/<id>`` of a repository that is not the item's."""
    other = sb.root / "other-repository"
    sb.git("init", "-q", "--initial-branch=main", str(other))
    sb.git("-C", str(other), "config", "user.name", "Example")
    sb.git("-C", str(other), "config", "user.email", "example@example.com")
    sb.git("-C", str(other), "commit", "-q", "--allow-empty", "-m", "chore: first")
    path = sb.root / "other-repository-worktree"
    sb.git("-C", str(other), "worktree", "add", "-q", "-b", MANUAL_BRANCH, str(path))
    return path


def scene_plain_directory(sb: HandoffSandbox) -> Path:
    """A directory that git does not list as a worktree."""
    plain = sb.root / "plain-directory"
    plain.mkdir()
    return plain


def scene_other_branch(sb: HandoffSandbox) -> Path:
    """A worktree of the item's repository at the item's path, on the branch of another item."""
    return make_worktree(sb, branch="handoff/another-item")


def unrelated_commit(sb: HandoffSandbox) -> str:
    """A commit that exists in the repository but is not below the worktree's ``HEAD``; no ref names it."""
    tree = git_text(sb, "-C", str(sb.main_tree), "rev-parse", f"{sb.base_sha}^{{tree}}")
    return git_text(sb, "-C", str(sb.main_tree), "commit-tree", tree, "-p", sb.base_sha, "-m", "chore: off the branch")


#: Per case: the scene (it returns the ``--worktree`` argument), the phrase of standard error, and
#: the ``base_sha`` that the item's record holds (``None``: no record, so the base is derived).
REFUSALS: dict[str, tuple[Callable[[HandoffSandbox], Path | str], str, Callable[[HandoffSandbox], str] | None]] = {
    "another-repository": (other_repository_worktree, "is not a worktree that git lists for", None),
    "not-listed-by-git": (scene_plain_directory, "is not a worktree that git lists for", None),
    "missing-path": (lambda sb: sb.root / "no-such-path", "is not a directory", None),
    "inside-the-main-tree": (lambda sb: sb.main_tree, "which meets the main working tree of", None),
    "another-branch": (scene_other_branch, f", not refs/heads/{MANUAL_BRANCH}", None),
    "unknown-base": (lambda sb: make_worktree(sb), "the recorded base of the item", lambda sb: "0" * 39 + "1"),
    "base-not-below-head": (lambda sb: make_worktree(sb), "is not below HEAD of", unrelated_commit),
}


@pytest.mark.parametrize("name", list(REFUSALS))
def test_verify_refuses_a_worktree_that_is_not_the_items_and_changes_nothing(
    handoff_sandbox: HandoffSandbox, name: str
) -> None:
    """Row: a worktree of another repository, an unlisted path, another branch, a path in the main tree, a bad base."""
    sb = handoff_sandbox
    prepare_both(sb)
    scene, phrase, recorded_base = REFUSALS[name]
    argument = scene(sb)
    if recorded_base is not None:
        write_status(sb, [], base_sha=recorded_base(sb))
    status_before = status_bytes(sb)
    before, refs_before = sb.snapshot_main_tree(), remote_refs(sb)
    worktrees_before = git_text(sb, "-C", str(sb.main_tree), "worktree", "list", "--porcelain")

    done = verify(sb, argument)

    assert done.returncode == 1, (done.stdout, done.stderr)
    assert done.stdout == "" and phrase in done.stderr and "nothing was changed" in done.stderr, done.stderr
    assert status_bytes(sb) == status_before and sb.records() == []
    assert git_text(sb, "-C", str(sb.main_tree), "worktree", "list", "--porcelain") == worktrees_before
    assert remote_refs(sb) == refs_before
    assert_main_tree_kept(before, sb.snapshot_main_tree())


STATE_CASES: dict[str, list[tuple[str, str]]] = {
    "failed": [(state.RUNNING, "dispatched"), (state.FAILED, "timed_out")],
    "needs-human": [(state.RUNNING, "dispatched"), (state.NEEDS_HUMAN, "undeclared_files")],
    "succeeded": [(state.RUNNING, "dispatched"), (state.SUCCEEDED, CHECKS_PASSED)],
}


@pytest.mark.parametrize("current", list(STATE_CASES))
def test_verify_takes_a_queued_item_only(handoff_sandbox: HandoffSandbox, current: str) -> None:
    """Row: a ``failed``, ``needs-human`` or ``succeeded`` item is refused, with the way back for the first two."""
    sb = handoff_sandbox
    prepare_both(sb)
    worktree = make_worktree(sb)
    work(sb, worktree, "commit")
    status_before = write_status(sb, STATE_CASES[current])
    before, refs_before = sb.snapshot_main_tree(), remote_refs(sb)
    head_before = git_text(sb, "-C", str(worktree), "rev-parse", "HEAD")

    done = verify(sb, worktree)

    assert done.returncode == 1, (done.stdout, done.stderr)
    assert done.stdout == "" and f"it is {current}; only a queued item is observed" in done.stderr, done.stderr
    assert (f"cli.py status set {MANUAL} queued" in done.stderr) is (current != "succeeded")
    assert status_bytes(sb) == status_before and sb.records() == []
    assert git_text(sb, "-C", str(worktree), "rev-parse", "HEAD") == head_before
    assert remote_refs(sb) == refs_before
    assert_main_tree_kept(before, sb.snapshot_main_tree())


def test_verify_refuses_a_query_item_and_a_relative_path(handoff_sandbox: HandoffSandbox) -> None:
    """A query item has no ``handoff/<id>`` branch to observe (exit 1); a relative ``--worktree`` is an argument error (2)."""
    sb = handoff_sandbox
    prepare_both(sb)
    worktree = make_worktree(sb)
    before = sb.snapshot_main_tree()

    query = verify(sb, worktree, QUERY)
    assert query.returncode == 1 and query.stdout == "", (query.stdout, query.stderr)
    assert f"{QUERY} is a query item; verify observes change items only" in query.stderr

    relative = verify(sb, "relative/worktree")
    assert relative.returncode == 2 and relative.stdout == "", (relative.stdout, relative.stderr)
    assert "must be an absolute path" in relative.stderr

    unknown = verify(sb, worktree, "no-such-item")
    assert unknown.returncode == 2 and "no item" in unknown.stderr, unknown.stderr

    assert status_bytes(sb) is None and sb.records() == []
    assert_main_tree_kept(before, sb.snapshot_main_tree())

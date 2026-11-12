"""Tests of the change mode of ``cli.py run``, started as a file (task 5.3).

Each test writes ``config.json``, ``manifest.json``, the templates and the deny list into the
``handoff_sandbox`` of ``conftest.py``, records a ``guards_active`` selftest with ``cli.py selftest``
as ``test_handoff_selftest_cli.py`` does (T0 commits, the guard stops T1 and T2), and then starts
``python cli.py --handoff-dir <sandbox> run --items <change item>`` with a behavior of the fake
``kiro-cli``. ``HOME`` is the sandbox home, so ``kiro_cli``, ``worktrees_root``, ``~/.kiro`` and the
deny list are the sandbox's. Nothing reads or writes this machine's ``~/.kiro``, uses the network,
or starts the real ``kiro-cli``.

Each test compares the history reason whole, so that an observation read in the place of another
is caught and not only the final state, and checks that the uncommitted changes of the main working
tree have the same bytes after the run as before (Requirement 28.6). Design section 20, "結果の確認":

- Steps 1 to 4, 7 and 8, by behavior of the fake: ``commit`` of the declared file is
  ``succeeded``; ``undeclared`` is ``needs-human`` (``undeclared_files``); ``commit,write-file``
  (a file left uncommitted) is ``needs-human`` (``dirty``); ``commit,switch-main`` is
  ``needs-human`` (``main_tree_changed``).
- Step 5: while the fake sleeps, another clone pushes a commit to the remote's ``main``. A change of
  the item's file is a conflict (``needs-human``, listed in the Handoff_Report); one of another file
  is not.
- Step 6: the declared verification commands run again in the worktree under layer 3 (one exits 0
  only in the worktree, one only with the push URL of ``command.child_env``); a re-run that exits 1
  is ``failed``; ``offline: false`` and a ``git push`` command are not re-run and get their reasons;
  nothing runs after a run that changed an undeclared file; a re-run that leaves a file makes the
  worktree ``dirty``, and one that commits ends the observation.
- Push attempts: ``push-url``, which layer 3 does not stop, leaves ``handoff/<id>`` on the remote
  (``needs-human``, ``remote_branch_exists``). A ``push`` that layer 3 stops is not observed; see
  :func:`test_a_push_attempt_is_seen_only_when_it_reaches_the_remote`.

Without a ``guards_active`` selftest (Requirement 28.17), the change item is held and the only
``kiro-cli`` that runs is that of the query item of the same run, with ``--trust-tools=fs_read``.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import cli, evaluate, manifest, state

if TYPE_CHECKING:
    from conftest import HandoffSandbox, MainTreeState

REPO = "example-hub"
QUERY = "a-hub-query"
CHANGE = "b-hub-change"
BRANCH = f"handoff/{CHANGE}"
DECLARED = "docs/guide.md"
CLI_FILE = Path(cli.__file__).resolve()

#: What the fake kiro-cli (``fixtures/handoff/fake-kiro-cli``) commits for ``undeclared``, leaves for
#: ``write-file`` without a selftest token, uses as the commit message, switches the main working
#: tree to for ``switch-main``, and appends to each file for ``commit``.
UNDECLARED = "fake-kiro-undeclared.txt"
LEFT_BEHIND = "fake-kiro-selftest.txt"
COMMIT_MESSAGE = "test: change made by the fake kiro-cli"
SWITCHED = "fake-kiro-switched"
CHANGED_LINE = "changed by the fake kiro-cli"

#: Verification commands made of git alone, so that they run wherever the tests do.
#: ``IN_WORKTREE`` exits 0 only where ``HEAD`` holds the fake's commit: in the worktree, not in the
#: main working tree. ``UNDER_LAYER_3`` exits 0 only with the push URL that ``command.child_env``
#: sets; the sandbox's repositories set none. ``FAILS`` exits 1 anywhere. ``PUSHES`` matches
#: ``git push`` of ``manifest.RERUN_EXCLUDED_PATTERNS`` and would exit 128 under layer 3.
#: ``LEAVES_A_FILE`` writes ``0001-<subject>.patch``, and ``COMMITS`` moves the branch.
IN_WORKTREE = ["git", "grep", "-q", "-F", CHANGED_LINE, "HEAD", "--", DECLARED]
UNDER_LAYER_3 = ["git", "config", "--get", "remote.origin.pushurl"]
FAILS = ["git", "grep", "-q", "-F", "a line that no file holds", "HEAD"]
PUSHES = ["git", "push", "--dry-run", "origin", "HEAD"]
LEAVES_A_FILE = ["git", "format-patch", "-q", "-1"]
COMMITS = ["git", "commit", "-q", "--allow-empty", "-m", "test: a commit made by a verification command"]

#: The reason of a command that the runner does not run after work that cannot succeed, written out
#: rather than taken from ``runner`` so that a changed text is caught.
AFTER_UNDECLARED_WORK = (
    "not re-run, since the run cannot end succeeded (undeclared_files): the harness does not run the "
    "code of a worktree whose work is unfinished, uncommitted or not declared"
)

#: Seconds that the fake sleeps while another clone pushes to the remote's ``main``.
SLEEP_SECONDS = 4

#: The trial behaviors of a selftest whose result is ``guards_active`` (the set "both-stopped" of
#: ``test_handoff_selftest_cli.py``).
GUARDS_ACTIVE_TRIALS = {"T0": "commit", "T1": "guard-block", "T2": "guard-block", "T3": "gh-status", "T4": "write-file"}

QUERY_TEMPLATE = """<!-- The query template of the change mode tests. -->
<!-- slot: purpose -->
Answer the questions about $topic.

<!-- slot: questions -->
1. What is the first line of `AGENTS.md`?
"""

CHANGE_TEMPLATE = """<!-- The change template of the change mode tests. -->
<!-- slot: purpose -->
Add a line to the guide of $topic.
"""

#: A declared verification command: its argv and its ``offline`` flag.
Verify = tuple[list[str], bool]


def skip_reason(cmd: list[str], offline: bool) -> str:
    """What ``manifest.rerun_skip_reason`` gives a declared command that the harness must not re-run."""
    reason = manifest.rerun_skip_reason(manifest.VerifyCommand(tuple(cmd), offline))
    assert reason is not None, cmd
    return reason


def item(item_id: str, sync_point: str, mode: str, verify: Sequence[Verify] = ()) -> dict[str, Any]:
    """An item of the manifest: a query item, or a change item that declares :data:`DECLARED`."""
    query = mode == "query"
    return {
        "id": item_id,
        "repo": REPO,
        "sync_point": sync_point,
        "mode": mode,
        "template": "templates/query.md" if query else "templates/change.md",
        "vars": {"topic": "the sandbox repository"},
        "depends_on": [],
        "requires_refs": [],
        "trust_tools": ["fs_read"] if query else ["fs_read", "fs_write"],
        "trust_all": None,
        "declared_files": [] if query else [DECLARED],
        "verify_commands": [{"cmd": cmd, "offline": offline} for cmd, offline in verify],
        "batch": None,
        "gates": [],
        "knowledge_kinds": ["records under .private/"] if query else [],
        "read_paths": [],
        "artifact_paths": [],
    }


def prepare(sb: HandoffSandbox, verify: Sequence[Verify] = ()) -> None:
    """Write the deny list, the templates, ``config.json`` and ``manifest.json``; no ``status.json``."""
    listed = sb.home / ".kiro" / "hooks" / "private"
    listed.mkdir(parents=True)
    (listed / "customer-terms.txt").write_text("# synthetic\nexamplecorp\n", encoding="utf-8")
    templates = sb.handoff_dir / "templates"
    templates.mkdir()
    (templates / "query.md").write_text(QUERY_TEMPLATE, encoding="utf-8")
    (templates / "change.md").write_text(CHANGE_TEMPLATE, encoding="utf-8")
    config = {
        "schema_version": 1,
        "kiro_cli": "~/.local/bin/kiro-cli",
        "timeout_seconds": 60,
        "max_concurrency": 2,
        "worktrees_root": "~/Projects/.handoff-worktrees",
        "min_free_disk_gb": 1,
        "mode_tool_ceiling": {"query": ["fs_read"], "change": ["fs_read", "fs_write"]},
        "agents": {},
        "repos": {REPO: {"main_tree": f"~/Projects/{REPO}"}},
    }
    (sb.handoff_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")
    items = [item(QUERY, "a", "query"), item(CHANGE, "b", "change", verify)]
    (sb.handoff_dir / "manifest.json").write_text(json.dumps({"schema_version": 1, "items": items}), encoding="utf-8")


def run_cli(sb: HandoffSandbox, *argv: str, **extra: str) -> subprocess.CompletedProcess[str]:
    """``python cli.py --handoff-dir <sandbox> <argv>`` with the sandbox's environment and ``extra``."""
    env = sb.environ(PYTHONIOENCODING="utf-8", **extra)
    env.pop("CUSTOMER_TERMS_FILE", None)
    return subprocess.run(
        [sys.executable, str(CLI_FILE), "--handoff-dir", str(sb.handoff_dir), *argv],
        cwd=str(sb.root),
        env=env,
        capture_output=True,
        encoding="utf-8",
        timeout=180,
        check=False,
    )


def record_selftest(sb: HandoffSandbox) -> None:
    """Run ``cli.py selftest`` with both guards stopping, and check that ``status.json`` says ``guards_active``."""
    variables = {f"FAKE_KIRO_MODE_{trial}": behavior for trial, behavior in GUARDS_ACTIVE_TRIALS.items()}
    done = run_cli(sb, "selftest", FAKE_KIRO_COMMIT_FILES="README.md", **variables)
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert read_status(sb)["selftest"]["result"] == evaluate.GUARDS_ACTIVE


def read_status(sb: HandoffSandbox) -> state.StatusDoc:
    """Read and check ``status.json``."""
    return state.parse_status((sb.handoff_dir / "status.json").read_text(encoding="utf-8"))


def history(status: state.StatusDoc, item_id: str) -> list[tuple[str, str, str]]:
    """An item's transitions as ``(from, to, reason)``."""
    return [(entry["from"], entry["to"], entry["reason"]) for entry in status["items"][item_id]["history"]]


def remote_refs(sb: HandoffSandbox) -> list[str]:
    """Every ref of the bare repository (the remote ``origin``) with its object."""
    listed = sb.git("--git-dir", str(sb.bare), "for-each-ref", "--format=%(refname) %(objectname)")
    return listed.stdout.decode("ascii").splitlines()


def git_text(sb: HandoffSandbox, *args: str) -> str:
    """The standard output of a git command of the sandbox, stripped."""
    return sb.git(*args).stdout.decode("utf-8").strip()


def uncommitted(snapshot: MainTreeState) -> tuple[Any, ...]:
    """The parts of a main working tree's state that hold its uncommitted changes, and its ``HEAD``."""
    return (snapshot.head, snapshot.status, snapshot.index, snapshot.staged, snapshot.unstaged, snapshot.files)


def trust_options(argv: list[str]) -> list[str]:
    """The trust options of a ``kiro-cli chat`` argv."""
    return [arg for arg in argv if arg.startswith("--trust-")]


def report_json(report: str) -> dict[str, Any]:
    """The JSON block at the end of a Handoff_Report's observations."""
    opening = report.rindex("\n```json\n") + len("\n```json\n")
    data: dict[str, Any] = json.loads(report[opening : report.index("\n```", opening)])
    return data


def rerun_entries(report: str) -> list[str]:
    """The entries of the re-run section of a Handoff_Report, one per declared command, in order."""
    section = report[report.index("### 検証コマンドの再実行") : report.rindex("\n```json\n")]
    return section.split("\n#### ")[1:]


def details(done: subprocess.CompletedProcess[str]) -> list[str]:
    """The lines of standard error that ``cli.py run`` writes for the change item's outcome detail."""
    return [line for line in done.stderr.splitlines() if line.startswith(f"{CHANGE}: ")]


@dataclass(frozen=True)
class Ended:
    """A change run of ``cli.py run --items <change item>``, as a test reads it afterwards.

    Attributes:
        done: The ``cli.py run`` process.
        status: ``status.json`` after it.
        record: The change item's record.
        report: The Handoff_Report.
        chat: The fake's ``chat`` run, by event (``start``, ``spawned``, ``end``).
        worktree: The item's worktree.
        before: The main working tree before ``cli.py run``.
        after: The main working tree after it.
        refs_before: The remote's refs before it.
    """

    done: subprocess.CompletedProcess[str]
    status: state.StatusDoc
    record: dict[str, Any]
    report: str
    chat: dict[str, Any]
    worktree: Path
    before: MainTreeState
    after: MainTreeState
    refs_before: list[str]


def run_change(
    sb: HandoffSandbox,
    behaviors: str,
    *,
    verify: Sequence[Verify] = (),
    during: Callable[[int], None] | None = None,
    **extra: str,
) -> Ended:
    """Prepare, record a ``guards_active`` selftest, and run the change item with the fake's ``behaviors``.

    Args:
        sb: The sandbox.
        behaviors: ``FAKE_KIRO_MODE``; ``commit`` changes :data:`DECLARED`.
        verify: The change item's verification commands.
        during: Called in a thread while ``cli.py run`` runs, with the number of the fake's runs
            before it. What it raises is raised here.
        **extra: More variables for ``cli.py run`` and the fake.

    Returns:
        What the test reads. The fake ran ``--version``, ``whoami`` and ``chat``, once each.
    """
    prepare(sb, verify)
    record_selftest(sb)
    seen = len(sb.invocations())
    before, refs_before = sb.snapshot_main_tree(), remote_refs(sb)
    raised: list[BaseException] = []
    worker: threading.Thread | None = None
    if during is not None:
        function = during

        def call() -> None:
            try:
                function(seen)
            except BaseException as exc:  # raised again in the test's thread below
                raised.append(exc)

        worker = threading.Thread(target=call, daemon=True)
        worker.start()
    done = run_cli(sb, "run", "--items", CHANGE, FAKE_KIRO_MODE=behaviors, FAKE_KIRO_COMMIT_FILES=DECLARED, **extra)
    if worker is not None:
        worker.join(timeout=60)
        assert not worker.is_alive(), "the thread of the test did not end"
    if raised:
        raise raised[0]
    status = read_status(sb)
    record: dict[str, Any] = dict(status["items"][CHANGE])
    runs = sb.invocations()[seen:]
    assert [run["start"]["subcommand"] for run in runs] == ["--version", "whoami", "chat"], done.stderr
    report = (sb.handoff_dir / str(record["report"])).read_text(encoding="utf-8")
    worktree = sb.worktrees_root / REPO / CHANGE
    return Ended(done, status, record, report, runs[2], worktree, before, sb.snapshot_main_tree(), refs_before)


# ---------------------------------------------------------------------------------------------
# a change item whose selftest counts: started on handoff/<id>, ended as its observations decide
# ---------------------------------------------------------------------------------------------

#: Per case: ``FAKE_KIRO_MODE``, the final state, the history reason of the last transition, and
#: the observations that differ from those of a clean commit of the declared file.
CASES: dict[str, tuple[str, str, str, dict[str, Any]]] = {
    "commit": ("commit", state.SUCCEEDED, evaluate.CHECKS_PASSED, {}),
    "undeclared": (
        "undeclared",
        state.NEEDS_HUMAN,
        "undeclared_files",
        {"changed_files": [UNDECLARED], "undeclared_files": [UNDECLARED]},
    ),
    "left-uncommitted": ("commit,write-file", state.NEEDS_HUMAN, "dirty", {"dirty": True}),
    "switch-main": ("commit,switch-main", state.NEEDS_HUMAN, "main_tree_changed", {"main_tree_change": "relevant"}),
}


@pytest.mark.parametrize(("behaviors", "final", "reason", "differs"), list(CASES.values()), ids=list(CASES))
def test_a_change_run_ends_as_its_observations_decide(
    handoff_sandbox: HandoffSandbox, behaviors: str, final: str, reason: str, differs: dict[str, Any]
) -> None:
    """The item runs in a worktree on ``handoff/<id>``, and only the observations decide its state."""
    sb = handoff_sandbox
    ended = run_change(sb, behaviors)
    done, record, chat, worktree = ended.done, ended.record, ended.chat, ended.worktree

    assert done.returncode == (0 if final == state.SUCCEEDED else 1), (done.stdout, done.stderr)
    assert history(ended.status, CHANGE) == [
        (state.QUEUED, state.RUNNING, "dispatched"),
        (state.RUNNING, final, reason),
    ]
    assert (record["branch"], record["base_sha"], record["pid"]) == (BRANCH, sb.base_sha, None)
    assert record["worktree"] == f"~/{worktree.relative_to(sb.home)}"
    assert (record["rerun"], record["rerun_skipped"]) == ([], [])  # the item declares no verification command

    # the fake was started once, in the worktree, with the item's tools
    assert chat["start"]["cwd"] == str(worktree)
    assert trust_options(chat["start"]["argv"]) == ["--trust-tools=fs_read,fs_write"]
    clean = {
        "exit_code": 0,
        "timed_out": False,
        "stdout_bytes": chat["end"]["stdout"]["bytes"],
        "commits": 1,
        "changed_files": [DECLARED],
        "undeclared_files": [],
        "dirty": False,
        "conflicts": [],
        "remote_branch_exists": False,
        "main_tree_change": "none",
    }
    assert record["observations"] == {**clean, **differs}

    # the commit is on handoff/<id>, one commit above the base, in the main repository's refs
    head = git_text(sb, "-C", str(worktree), "rev-parse", "HEAD")
    assert git_text(sb, "-C", str(worktree), "symbolic-ref", "HEAD") == f"refs/heads/{BRANCH}"
    assert git_text(sb, "-C", str(sb.main_tree), "rev-parse", f"refs/heads/{BRANCH}") == head
    assert git_text(sb, "-C", str(sb.main_tree), "rev-list", "--count", f"{sb.base_sha}..{head}") == "1"
    assert (worktree / LEFT_BEHIND).exists() is (behaviors == "commit,write-file")

    # the main working tree keeps its uncommitted changes byte for byte, and the remote its refs
    assert uncommitted(ended.after) == uncommitted(ended.before)
    assert ended.after.branch == (SWITCHED if behaviors == "commit,switch-main" else ended.before.branch)
    refs_after = remote_refs(sb)
    assert refs_after == ended.refs_before
    assert not any(line.startswith(f"refs/heads/{BRANCH} ") for line in refs_after)

    # the report says what was observed: the default branch did not move, nothing was re-run
    report = ended.report
    assert "| モード | 変更（`change`） |" in report and f"| ブランチ | `{BRANCH}` |" in report
    data = report_json(report)
    assert data["commits"] == [{"sha": head, "subject": COMMIT_MESSAGE}]
    assert data["observations"]["observations"] == record["observations"]
    assert data["conflict_check"] == {"origin_main": sb.base_sha, "default_branch_files": [], "conflicts": []}
    assert "- 衝突（この項目が変えたファイルと同じファイル）: 0 件\n" in report
    assert "### 検証コマンドの再実行（結果の確認の手順 6）\n\n宣言した検証コマンドはない。\n" in report
    assert "- 補足:" not in report and not details(done), done.stderr
    assert f"{CHANGE}: {final}（{reason}） report: {record['report']}" in done.stdout


# ---------------------------------------------------------------------------------------------
# step 5: a commit that another clone pushes to main while the item runs
# ---------------------------------------------------------------------------------------------

#: Per case: the file that the other clone changes on ``main``, the final state, the history
#: reason and the conflicts.
CONFLICT_CASES: dict[str, tuple[str, str, str, list[str]]] = {
    "same-file": (DECLARED, state.NEEDS_HUMAN, "conflicts", [DECLARED]),
    "other-file": ("docs/other-session.md", state.SUCCEEDED, evaluate.CHECKS_PASSED, []),
}


@pytest.mark.parametrize(
    ("path", "final", "reason", "conflicts"), list(CONFLICT_CASES.values()), ids=list(CONFLICT_CASES)
)
def test_a_change_of_the_items_file_on_the_default_branch_is_a_conflict(
    handoff_sandbox: HandoffSandbox, path: str, final: str, reason: str, conflicts: list[str]
) -> None:
    """While the fake sleeps after its commit, another clone pushes a commit to the remote's ``main``.

    The commit is made before the run, so that only the push falls in the fake's sleep (case (a) of
    the 2.1 handover). The fetch of step 5 then moves ``origin/main`` of the main working tree, and
    the Handoff_Report lists the file and, for the item's file, the conflict.
    """
    sb = handoff_sandbox
    other = sb.root / "other-session"
    sb.git("clone", "-q", str(sb.bare), str(other))
    with open(other / path, "a", encoding="utf-8") as handle:
        handle.write("An edit that another session pushed to main.\n")
    sb.git("-C", str(other), "add", "--", path)
    identity = ("-c", "user.name=Other Session", "-c", "user.email=other-session@example.com")
    sb.git("-C", str(other), *identity, "commit", "-q", "-m", "docs: an edit of another session")
    pushed = git_text(sb, "-C", str(other), "rev-parse", "HEAD")
    pushed_at: list[datetime] = []

    def push_while_the_fake_sleeps(seen: int) -> None:
        deadline = time.monotonic() + 120
        while not any("spawned" in run for run in sb.invocations()[seen:]):
            assert time.monotonic() < deadline, "the fake kiro-cli did not start sleeping"
            time.sleep(0.05)
        sb.git("-C", str(other), "push", "-q", "origin", "HEAD:refs/heads/main")
        pushed_at.append(datetime.now(timezone.utc))

    ended = run_change(
        sb, "commit,sleep", during=push_while_the_fake_sleeps, FAKE_KIRO_SLEEP_SECONDS=str(SLEEP_SECONDS)
    )

    record = ended.record
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, final, reason), ended.done.stderr
    # the push came while the fake slept, so before the observations; the base stayed where it was
    (finished,) = pushed_at
    fake_ended = datetime.strptime(ended.chat["end"]["at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    assert finished < fake_ended, "the push came after the fake's sleep; make SLEEP_SECONDS longer"
    assert record["base_sha"] == sb.base_sha
    assert (record["observations"]["changed_files"], record["observations"]["conflicts"]) == ([DECLARED], conflicts)
    # the fetch of step 5 moved origin/main of the main working tree to the pushed commit
    assert git_text(sb, "-C", str(sb.main_tree), "rev-parse", "refs/remotes/origin/main") == pushed
    assert remote_refs(sb) == [f"refs/heads/main {pushed}"]

    # the report lists the default branch's files and the conflicts
    data = report_json(ended.report)
    assert data["conflict_check"] == {"origin_main": pushed, "default_branch_files": [path], "conflicts": conflicts}
    assert f"- `fetch` の後の `origin/main`: `{pushed}`\n" in ended.report
    assert f"- base_sha から origin/main までに変わったファイル: 1 件\n  - `{path}`\n" in ended.report
    listed = "".join(f"\n  - `{name}`" for name in conflicts)
    assert f"- 衝突（この項目が変えたファイルと同じファイル）: {len(conflicts)} 件{listed}\n" in ended.report
    assert uncommitted(ended.after) == uncommitted(ended.before)
    assert ended.after.branch == ended.before.branch


# ---------------------------------------------------------------------------------------------
# step 6: the declared verification commands, re-run in the worktree under layer 3
# ---------------------------------------------------------------------------------------------

#: Per case: ``FAKE_KIRO_MODE``, the declared commands, the final state, the history reason, the
#: re-runs as ``(cmd, exit code)`` and the commands not re-run as ``(cmd, reason)``.
RERUN_CASES: dict[str, tuple[str, list[Verify], str, str, list[tuple[list[str], int]], list[tuple[list[str], str]]]] = {
    "passes": (
        "commit",
        [(IN_WORKTREE, True), (UNDER_LAYER_3, True)],
        state.SUCCEEDED,
        evaluate.CHECKS_PASSED,
        [(IN_WORKTREE, 0), (UNDER_LAYER_3, 0)],
        [],
    ),
    "fails": (
        "commit",
        [(IN_WORKTREE, True), (FAILS, True)],
        state.FAILED,
        "rerun_failed",
        [(IN_WORKTREE, 0), (FAILS, 1)],
        [],
    ),
    "not-offline": (
        "commit",
        [(FAILS, False), (PUSHES, True)],
        state.SUCCEEDED,
        evaluate.CHECKS_PASSED,
        [],
        [(FAILS, skip_reason(FAILS, False)), (PUSHES, skip_reason(PUSHES, True))],
    ),
    "after-undeclared-work": (
        "undeclared",
        [(IN_WORKTREE, True)],
        state.NEEDS_HUMAN,
        "undeclared_files",
        [],
        [(IN_WORKTREE, AFTER_UNDECLARED_WORK)],
    ),
    "leaves-a-file": ("commit", [(LEAVES_A_FILE, True)], state.NEEDS_HUMAN, "dirty", [(LEAVES_A_FILE, 0)], []),
}


@pytest.mark.parametrize(
    ("behaviors", "verify", "final", "reason", "rerun", "skipped"), list(RERUN_CASES.values()), ids=list(RERUN_CASES)
)
def test_declared_verification_commands_run_again_in_the_worktree_under_layer_3(
    handoff_sandbox: HandoffSandbox,
    behaviors: str,
    verify: list[Verify],
    final: str,
    reason: str,
    rerun: list[tuple[list[str], int]],
    skipped: list[tuple[list[str], str]],
) -> None:
    """Each declared command is re-run or has its reason, in order, and the report keeps each output."""
    sb = handoff_sandbox
    ended = run_change(sb, behaviors, verify=verify)

    record = ended.record
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, final, reason), ended.done.stderr
    assert record["rerun"] == [{"cmd": cmd, "exit_code": code} for cmd, code in rerun]
    assert record["rerun_skipped"] == [{"cmd": cmd, "reason": text} for cmd, text in skipped]
    assert record["observations"]["dirty"] is (reason == "dirty")
    assert not details(ended.done), ended.done.stderr

    # one entry per declared command, in the declared order, with the output of each that ran
    entries = rerun_entries(ended.report)
    assert [entry.split("\n", 1)[0] for entry in entries] == [
        f"{index}. `{shlex.join(cmd)}`" for index, (cmd, _) in enumerate(verify, 1)
    ]
    ran = {tuple(cmd): code for cmd, code in rerun}
    not_ran = {tuple(cmd): text for cmd, text in skipped}
    for (cmd, _), entry in zip(verify, entries, strict=True):
        if tuple(cmd) in ran:
            assert f"\n- 再実行した: 終了コード {ran[tuple(cmd)]}、所要時間 " in entry, entry
            assert "\n- 標準出力（" in entry and "\n- 標準エラー出力（" in entry, entry
        else:
            assert f"\n- 再実行しなかった: {not_ran[tuple(cmd)]}\n" in entry, entry
    if (UNDER_LAYER_3, 0) in rerun:
        (entry,) = [entry for entry in entries if shlex.join(UNDER_LAYER_3) in entry.split("\n", 1)[0]]
        assert "/no-such-remote\n```\n- 標準エラー出力（0 バイト" in entry, entry
    patches = sorted(path.name for path in ended.worktree.glob("0001-*.patch"))
    assert len(patches) == (1 if (LEAVES_A_FILE, 0) in rerun else 0), patches

    # the re-runs changed nothing outside the worktree
    assert uncommitted(ended.after) == uncommitted(ended.before)
    assert (ended.after.branch, remote_refs(sb)) == (ended.before.branch, ended.refs_before)


def test_a_verification_command_that_moves_the_handoff_branch_ends_the_observation(
    handoff_sandbox: HandoffSandbox,
) -> None:
    """A re-run that commits moves ``handoff/<id>`` past what steps 1 and 2 saw: ``observation_failed``."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit", verify=[(COMMITS, True)])

    record = ended.record
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, "observation_failed")
    assert (record["observations"], record["rerun"], record["rerun_skipped"]) == (None, [], [])
    head = git_text(sb, "-C", str(ended.worktree), "rev-parse", "HEAD")
    assert git_text(sb, "-C", str(sb.main_tree), "rev-list", "--count", f"{sb.base_sha}..{head}") == "2"
    (observed,) = report_json(ended.report)["commits"]
    assert observed["subject"] == COMMIT_MESSAGE and observed["sha"] != head
    moved = f"a verification command moved {BRANCH} from {observed['sha']}"
    assert moved in ended.report
    (detail,) = details(ended.done)
    assert moved in detail, ended.done.stderr
    (entry,) = rerun_entries(ended.report)
    assert "\n- 再実行した: 終了コード 0、所要時間 " in entry, entry
    assert uncommitted(ended.after) == uncommitted(ended.before)


# ---------------------------------------------------------------------------------------------
# push attempts (step 7)
# ---------------------------------------------------------------------------------------------

#: Per case: ``FAKE_KIRO_MODE``, the final state, the history reason, and whether the push arrived.
PUSH_CASES: dict[str, tuple[str, str, str, bool]] = {
    "push-url": ("commit,push-url", state.NEEDS_HUMAN, "remote_branch_exists", True),
    "push-stopped-by-layer-3": ("commit,push", state.SUCCEEDED, evaluate.CHECKS_PASSED, False),
}


@pytest.mark.parametrize(("behaviors", "final", "reason", "arrived"), list(PUSH_CASES.values()), ids=list(PUSH_CASES))
def test_a_push_attempt_is_seen_only_when_it_reaches_the_remote(
    handoff_sandbox: HandoffSandbox, behaviors: str, final: str, reason: str, arrived: bool
) -> None:
    """A push that reaches the remote is ``needs-human``; one that layer 3 stops is not observed.

    ``push-url`` names the URL of ``remote.origin.url``, which layer 3 does not override, so
    ``handoff/<id>`` arrives on the remote, step 7 (``git ls-remote origin refs/heads/handoff/<id>``)
    sees it, and the run is ``needs-human`` (``remote_branch_exists``). This is the case of tasks.md
    "push を試みる場合 → needs-human".

    Known limitation, kept as it is so that a change of it shows: ``push`` sends to ``origin``,
    whose push URL layer 3 (``command.child_env``) points at a path where nothing exists. The push
    fails and leaves nothing on the remote; step 7 reads the remote only, so the attempt is not
    observed and the run ends ``succeeded``. Seeing such an attempt needs another observation, for
    example a bare repository of the item's own at the push URL whose refs are read after the run,
    with a field of the observations and a condition of ``evaluate.PRECEDENCE`` for it. That
    proposal is left to the maintainer (task 4.13).
    """
    sb = handoff_sandbox
    ended = run_change(sb, behaviors)

    record = ended.record
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, final, reason), ended.done.stderr
    head = git_text(sb, "-C", str(ended.worktree), "rev-parse", "HEAD")
    commit, push = ended.chat["end"]["results"]
    assert (commit["behavior"], push["ref"], push["local_sha"]) == ("commit", f"refs/heads/{BRANCH}", head)
    assert (push["arrived"], push["exit_code"] == 0) == (arrived, arrived), push
    if not arrived:
        assert "no-such-remote" in push["stderr"], push
    assert record["observations"]["remote_branch_exists"] is arrived
    expected = [*ended.refs_before, f"refs/heads/{BRANCH} {head}"] if arrived else ended.refs_before
    assert sorted(remote_refs(sb)) == sorted(expected)
    assert uncommitted(ended.after) == uncommitted(ended.before)
    assert ended.after.branch == ended.before.branch


# ---------------------------------------------------------------------------------------------
# without a guards_active selftest: nothing trusts more than fs_read (Requirement 28.17)
# ---------------------------------------------------------------------------------------------


def test_without_a_guards_active_selftest_kiro_cli_trusts_fs_read_only(handoff_sandbox: HandoffSandbox) -> None:
    """No selftest: the change item is held before any ``kiro-cli``, and the query item runs with ``fs_read`` alone."""
    sb = handoff_sandbox
    prepare(sb)
    before, refs_before = sb.snapshot_main_tree(), remote_refs(sb)

    done = run_cli(sb, "run", "--items", f"{QUERY},{CHANGE}")

    assert done.returncode == 1, (done.stdout, done.stderr)
    status = read_status(sb)
    assert history(status, CHANGE) == [(state.QUEUED, state.NEEDS_HUMAN, "selftest_unconfirmed")]
    assert status["items"][QUERY]["state"] == state.SUCCEEDED, status["items"][QUERY]
    chats = [run["start"] for run in sb.invocations() if run["start"]["subcommand"] == "chat"]
    assert [chat["cwd"] for chat in chats] == [str(sb.worktrees_root / REPO / QUERY)]
    assert [trust_options(chat["argv"]) for chat in chats] == [["--trust-tools=fs_read"]]
    assert not (sb.worktrees_root / REPO / CHANGE).exists()
    branches = git_text(sb, "-C", str(sb.main_tree), "for-each-ref", "--format=%(refname)", "refs/heads/")
    assert branches.splitlines() == ["refs/heads/main"]
    assert uncommitted(sb.snapshot_main_tree()) == uncommitted(before)
    assert remote_refs(sb) == refs_before

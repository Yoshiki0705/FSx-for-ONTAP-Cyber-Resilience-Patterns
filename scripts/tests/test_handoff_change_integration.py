"""Tests of the change mode of ``cli.py run``, started as a file (task 5.3, part a).

Each test writes ``config.json``, ``manifest.json``, the templates and the deny list into the
``handoff_sandbox`` of ``conftest.py``, records a ``guards_active`` selftest with ``cli.py selftest``
as ``test_handoff_selftest_cli.py`` does (T0 commits, the guard stops T1 and T2), and then starts
``python cli.py --handoff-dir <sandbox> run --items <change item>`` with a behavior of the fake
``kiro-cli``. ``HOME`` is the sandbox home, so ``kiro_cli``, ``worktrees_root``, ``~/.kiro`` and the
deny list are the sandbox's. Nothing reads or writes this machine's ``~/.kiro``, uses the network,
or starts the real ``kiro-cli``.

Checked here, for each behavior of the fake (design section 20, "結果の確認", steps 1 to 4, 7 and
8), with the history reason compared whole, so that an observation read in the place of another
is caught and not only the final state:

- ``commit`` of the declared file: ``succeeded`` (``all_checks_passed``). The commit is on
  ``handoff/<id>``, the branch that ``git worktree add -b`` made from ``base_sha``, and the argv
  trusts the item's tools, which lie within ``mode_tool_ceiling.change``.
- ``undeclared`` (a commit of a file that the item does not declare): ``needs-human``
  (``undeclared_files``).
- ``commit,write-file`` (a file left uncommitted in the worktree): ``needs-human`` (``dirty``).
- ``commit,switch-main`` (the branch of the main working tree switched): ``needs-human``
  (``main_tree_changed``).

In every case the uncommitted changes of the main working tree have the same bytes after the run as
before (Requirement 28.6), the remote has no ``handoff/<id>`` and the same refs as before, and the
Handoff_Report and standard error say that steps 5 and 6 were not carried out.

Without a ``guards_active`` selftest (Requirement 28.17), the change item is held and the only
``kiro-cli`` that runs is that of the query item of the same run, with ``--trust-tools=fs_read``.

Not checked here (task 5.3b): the conflict check, the re-run of verification commands, and push
attempts. The items declare no verification command.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import cli, evaluate, state

if TYPE_CHECKING:
    from conftest import HandoffSandbox, MainTreeState

REPO = "example-hub"
QUERY = "a-hub-query"
CHANGE = "b-hub-change"
BRANCH = f"handoff/{CHANGE}"
DECLARED = "docs/guide.md"
CLI_FILE = Path(cli.__file__).resolve()

#: What the fake kiro-cli (``fixtures/handoff/fake-kiro-cli``) commits for ``undeclared``, leaves for
#: ``write-file`` without a selftest token, uses as the commit message, and switches the main
#: working tree to for ``switch-main``.
UNDECLARED = "fake-kiro-undeclared.txt"
LEFT_BEHIND = "fake-kiro-selftest.txt"
COMMIT_MESSAGE = "test: change made by the fake kiro-cli"
SWITCHED = "fake-kiro-switched"

#: The start of what the report and standard error say about the steps not carried out yet,
#: written out rather than taken from ``runner`` so that a changed text is caught.
NOT_DONE = "結果の確認の手順 5（衝突の確認）と手順 6（宣言した検証コマンドの再実行）は、まだ行っていない"

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


def item(item_id: str, sync_point: str, mode: str) -> dict[str, Any]:
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
        "verify_commands": [],
        "batch": None,
        "gates": [],
        "knowledge_kinds": ["records under .private/"] if query else [],
        "read_paths": [],
        "artifact_paths": [],
    }


def prepare(sb: HandoffSandbox) -> None:
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
    manifest = {"schema_version": 1, "items": [item(QUERY, "a", "query"), item(CHANGE, "b", "change")]}
    (sb.handoff_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


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
    prepare(sb)
    record_selftest(sb)
    seen = len(sb.invocations())
    before, refs_before = sb.snapshot_main_tree(), remote_refs(sb)

    done = run_cli(sb, "run", "--items", CHANGE, FAKE_KIRO_MODE=behaviors, FAKE_KIRO_COMMIT_FILES=DECLARED)

    assert done.returncode == (0 if final == state.SUCCEEDED else 1), (done.stdout, done.stderr)
    status = read_status(sb)
    assert history(status, CHANGE) == [(state.QUEUED, state.RUNNING, "dispatched"), (state.RUNNING, final, reason)]
    record = status["items"][CHANGE]
    worktree = sb.worktrees_root / REPO / CHANGE
    assert (record["branch"], record["base_sha"], record["pid"]) == (BRANCH, sb.base_sha, None)
    assert record["worktree"] == f"~/{worktree.relative_to(sb.home)}"
    assert (record["rerun"], record["rerun_skipped"]) == ([], [])  # step 6 is not carried out yet

    # the fake was started once, in the worktree, with the item's tools
    runs = sb.invocations()[seen:]
    assert [run["start"]["subcommand"] for run in runs] == ["--version", "whoami", "chat"]
    chat = runs[2]
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
    after = sb.snapshot_main_tree()
    assert uncommitted(after) == uncommitted(before)
    assert after.branch == (SWITCHED if behaviors == "commit,switch-main" else before.branch)
    refs_after = remote_refs(sb)
    assert refs_after == refs_before
    assert not any(line.startswith(f"refs/heads/{BRANCH} ") for line in refs_after)

    # the report and standard error say what was observed and which steps were not carried out
    report = (sb.handoff_dir / record["report"]).read_text(encoding="utf-8")
    assert "| モード | 変更（`change`） |" in report and f"| ブランチ | `{BRANCH}` |" in report
    data = report_json(report)
    assert data["commits"] == [{"sha": head, "subject": COMMIT_MESSAGE}]
    assert data["observations"]["observations"] == record["observations"]
    assert NOT_DONE in report
    (detail,) = [line for line in done.stderr.splitlines() if line.startswith(f"{CHANGE}: ")]
    assert NOT_DONE in detail, done.stderr
    assert f"{CHANGE}: {final}（{reason}） report: {record['report']}" in done.stdout


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

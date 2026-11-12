"""Integration tests of the Handoff_Harness command line, ``scripts/handoff/cli.py`` (task 2.4).

Two forms: ``cli.main(argv)`` in this process with the sandbox's ``--handoff-dir`` (:func:`call`),
and ``python cli.py`` as a file with a git first on ``PATH`` that logs its argv (:func:`run_file`).
Both run in the ``handoff_sandbox`` of ``conftest.py`` with the fake ``kiro-cli``. The deny list
that ``cli.py`` reads is the sandbox's ``~/.kiro/hooks/private/customer-terms.txt``; nothing uses the
network, the real ``kiro-cli``, a real repository, or this machine's ``~/.kiro``.

Rows of the design's Testing Strategy table checked here (Requirement 28):

- The configuration is rejected: each of ``timeout_seconds``, ``max_concurrency``,
  ``worktrees_root`` and ``min_free_disk_gb`` left out, and a ``worktrees_root`` inside a main
  working tree or below ``~/Projects/.kiro-worktrees``. Exit code 2, and no process is started
  (28.7, 28.11).
- ``kiro-cli whoami`` fails: exit code 4, a request to log in, the item stays ``queued`` and no
  worktree is created (28.18).
- The manual mode: the whole body, the repository to paste it into, and the commands from
  ``git -C <main> fetch`` to ``worktree add`` on standard output, with the state unchanged.
  ``manual`` takes ``queued``, ``failed`` and ``needs-human`` items and refuses ``running`` and
  ``succeeded`` ones, and ``run`` without ``kiro-cli`` prints the same display (28.21).
- A second harness: exit code 3, and nothing starts.
- A body with a scan finding never reaches the fake ``kiro-cli``: its item goes from ``queued`` to
  ``needs-human`` in one step, and no prompt that the fake received has a finding of ``scan.check``
  (28.23; the part of Property 26 (2) that the state transitions carry).
- ``cleanup --approved`` records ``worktree_removed`` in ``events``.

The other tests keep what the throwaway checks of task 2.3 caught: the argument checks, ``plan``,
the order of ``run``, ``status``, ``cleanup`` and the default ``--handoff-dir``.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import cli, runner, scan, state

if TYPE_CHECKING:
    from conftest import HandoffSandbox

REPO = "example-hub"
QUERY = "a-hub-query"
CHANGE = "b-hub-change"
DENIED = "c-hub-denied"
SECOND = "d-hub-second"
OTHER = "e-hub-other"
ALL_IDS = (QUERY, CHANGE, DENIED, SECOND, OTHER)
#: Named in the reverse of the manifest's order: run follows dag.select, not this list.
NAMED = f"{SECOND},{DENIED},{CHANGE},{QUERY}"
DENY_TERM = "ExampleCorp"
#: The terms of the sandbox's customer list, which ``prepare`` writes.
CUSTOMER_TERMS = ("examplecorp",)
CLI_FILE = Path(cli.__file__).resolve()
T0 = "2026-11-11T00:00:00Z"

#: The four keys whose absence the design's table names, in its order.
LIMIT_KEYS = ("timeout_seconds", "max_concurrency", "worktrees_root", "min_free_disk_gb")

QUERY_TEMPLATE = """<!-- The query template of the integration tests. -->
<!-- slot: purpose -->
Answer the questions about $topic.

<!-- slot: questions -->
1. What is the first line of `AGENTS.md`?
"""

CHANGE_TEMPLATE = """<!-- The change template of the integration tests. -->
<!-- slot: purpose -->
Add a line to the guide of $topic.
"""


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------


def item(item_id: str, sync_point: str, mode: str = "query", **over: Any) -> dict[str, Any]:
    """An item of the manifest, a query item unless ``mode`` says otherwise."""
    query = mode == "query"
    base = {
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
        "declared_files": [] if query else ["docs/guide.md"],
        "verify_commands": [],
        "batch": None,
        "gates": [],
        "knowledge_kinds": ["records under .private/"] if query else [],
        "read_paths": [],
        "artifact_paths": [],
    }
    base.update(over)
    return base


def config_value(**over: Any) -> dict[str, Any]:
    """``config.json`` of the real form for the sandbox."""
    value = {
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
    value.update(over)
    return value


def manifest_value() -> dict[str, Any]:
    """Five items: a query item, a change item, one with a deny term, one that depends on the first, one more."""
    return {
        "schema_version": 1,
        "items": [
            item(QUERY, "a"),
            item(CHANGE, "b", mode="change"),
            item(DENIED, "c", vars={"topic": f"the {DENY_TERM} rollout"}),
            item(SECOND, "d", depends_on=[QUERY]),
            item(OTHER, "e"),
        ],
    }


def prepare(
    sb: HandoffSandbox,
    monkeypatch: pytest.MonkeyPatch,
    *,
    terms: bool = True,
    config: Any = None,
    manifest: dict[str, Any] | None = None,
    **env: str,
) -> None:
    """Environment, deny list, templates, ``config.json`` and ``manifest.json`` of the sandbox."""
    sb.apply_environ(monkeypatch, **env)
    monkeypatch.delenv("CUSTOMER_TERMS_FILE", raising=False)
    if terms:
        listed = sb.home / ".kiro" / "hooks" / "private"
        listed.mkdir(parents=True)
        (listed / "customer-terms.txt").write_text("# synthetic\n" + "\n".join(CUSTOMER_TERMS) + "\n", encoding="utf-8")
    templates = sb.handoff_dir / "templates"
    templates.mkdir()
    (templates / "query.md").write_text(QUERY_TEMPLATE, encoding="utf-8")
    (templates / "change.md").write_text(CHANGE_TEMPLATE, encoding="utf-8")
    text = config if isinstance(config, str) else json.dumps(config if config is not None else config_value())
    (sb.handoff_dir / "config.json").write_text(text, encoding="utf-8")
    (sb.handoff_dir / "manifest.json").write_text(json.dumps(manifest or manifest_value()), encoding="utf-8")


def call(sb: HandoffSandbox, *argv: str) -> tuple[int, str, str]:
    """``cli.main`` with the sandbox's ``--handoff-dir``; the exit code, standard output and standard error."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(["--handoff-dir", str(sb.handoff_dir), *argv])
    return code, out.getvalue(), err.getvalue()


def git_wrapper(sb: HandoffSandbox) -> tuple[Path, Path]:
    """A git that appends its argv to a log and runs the real git; its directory and the log."""
    bin_dir = sb.root / "bin"
    bin_dir.mkdir(exist_ok=True)
    wrapper = bin_dir / "git"
    wrapper.write_text(
        "#!" + sys.executable + "\n"
        "import json, os, sys\n"
        "with open(os.environ['HANDOFF_TEST_GIT_LOG'], 'a') as handle:\n"
        "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "real = os.environ['HANDOFF_TEST_REAL_GIT']\n"
        "os.execv(real, [real] + sys.argv[1:])\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return bin_dir, sb.root / "git-calls.jsonl"


def run_file(
    sb: HandoffSandbox, *argv: str, handoff_dir: bool = True, **extra: str
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    """``python cli.py`` as a file, with the git wrapper first on ``PATH``; the process and the git calls."""
    real_git = shutil.which("git")
    assert real_git is not None
    bin_dir, log = git_wrapper(sb)
    env = sb.environ(
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        HANDOFF_TEST_GIT_LOG=str(log),
        HANDOFF_TEST_REAL_GIT=real_git,
        PYTHONIOENCODING="utf-8",
        **extra,
    )
    env.pop("CUSTOMER_TERMS_FILE", None)
    prefix = ["--handoff-dir", str(sb.handoff_dir)] if handoff_dir else []
    completed = subprocess.run(
        [sys.executable, str(CLI_FILE), *prefix, *argv],
        cwd=str(sb.root),
        env=env,
        capture_output=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
    return completed, calls


class PopenSpy:
    """Record every process that this process starts; ``subprocess.run`` goes through ``Popen`` too."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Replace ``subprocess.Popen`` for the rest of the test."""
        self.calls: list[list[str]] = []
        real = subprocess.Popen
        calls = self.calls

        class Spy(real):  # type: ignore[misc, valid-type]
            def __init__(self, args: Any, *rest: Any, **kwargs: Any) -> None:
                calls.append([str(arg) for arg in args] if not isinstance(args, (str, bytes)) else [str(args)])
                super().__init__(args, *rest, **kwargs)

        monkeypatch.setattr(subprocess, "Popen", Spy)


def status_path(sb: HandoffSandbox) -> Path:
    """``status.json`` of the sandbox."""
    return sb.handoff_dir / "status.json"


def read_status(sb: HandoffSandbox) -> state.StatusDoc:
    """Read and check ``status.json``."""
    return state.parse_status(status_path(sb).read_text(encoding="utf-8"))


def write_status(sb: HandoffSandbox, moves: dict[str, list[tuple[str, str, str]]], **fields: dict[str, Any]) -> bytes:
    """Write a status with a record of every item, the given transitions, and record fields (``a_hub_query=``)."""
    status = state.empty_status()
    for item_id in ALL_IDS:
        status = state.add_item(status, item_id)
    for item_id, steps in moves.items():
        for to_state, at, reason in steps:
            status = state.transition(status, item_id, to_state, at=at, reason=reason)
    for item_id, values in fields.items():
        status["items"][item_id.replace("_", "-")].update(values)
    data = state.render_status(status).encode("utf-8")
    status_path(sb).write_bytes(data)
    return data


def worktree(sb: HandoffSandbox, item_id: str) -> Path:
    """Where an item's worktree goes."""
    return sb.worktrees_root / REPO / item_id


def tilde_worktree(item_id: str) -> str:
    """An item's worktree as the status and the output write it."""
    return f"~/Projects/.handoff-worktrees/{REPO}/{item_id}"


def registered(sb: HandoffSandbox) -> list[str]:
    """The worktrees that git has registered for the target repository, the main one first."""
    out = sb.git("-C", str(sb.main_tree), "worktree", "list", "--porcelain").stdout.decode()
    return [line.split(" ", 1)[1] for line in out.splitlines() if line.startswith("worktree ")]


def prompt_file(sb: HandoffSandbox, sync_point: str) -> Path:
    """The Handoff_Prompt of the sandbox repository at a Sync_Point."""
    return sb.handoff_dir / "sync" / f"{sync_point}-{REPO}.md"


def pasted(out: str) -> str:
    """What the manual display asks the maintainer to paste: the lines between the two markers."""
    after = out.split("----- ここから -----\n", 1)[1]
    assert after.endswith("----- ここまで -----\n"), after[-200:]
    return after[: -len("----- ここまで -----\n")]


def plan_line(lines: list[str], item_id: str, prefix: str) -> str:
    """The first line with the prefix in the block of one item of ``plan``'s output."""
    start = next(index for index, line in enumerate(lines) if line.startswith(item_id + "（"))
    return next(line for line in lines[start + 1 :] if line.startswith(prefix))


def ids_in(lines: list[str], *ids: str) -> list[str]:
    """The item IDs that the lines name, in the order of the lines."""
    return [next(item_id for item_id in ids if item_id in line) for line in lines if any(i in line for i in ids)]


def live_leader() -> subprocess.Popen[bytes]:
    """A process that leads its own session, as a ``kiro-cli`` that runs does; the caller kills it."""
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)


# ---------------------------------------------------------------------------------------------
# input checks: exit code 2 before any process
# ---------------------------------------------------------------------------------------------


def _without(key: str) -> str:
    return json.dumps({name: value for name, value in config_value().items() if name != key})


#: Rejected ``config.json`` texts, and what standard error must say about each.
REJECTED: dict[str, tuple[str, str]] = {
    **{f"no-{key}": (_without(key), f"{key}: missing") for key in LIMIT_KEYS},
    "root-in-the-target-main-tree": (
        json.dumps(config_value(worktrees_root=f"~/Projects/{REPO}/.handoff-worktrees")),
        f"worktrees_root: overlap: is inside the main working tree in repos.{REPO}",
    ),
    "root-in-this-main-tree": (
        json.dumps(config_value(worktrees_root="~/Projects/example-harness/worktrees")),
        "worktrees_root: overlap: is inside a main working tree given by the caller",
    ),
    "root-in-the-session-worktrees": (
        json.dumps(config_value(worktrees_root="~/Projects/.kiro-worktrees/handoff")),
        "worktrees_root: overlap: is inside the IDE session worktree directory",
    ),
    "not-json": ('{"schema_version": 1,', "is not valid JSON"),
    "repeated-key": (json.dumps(config_value())[:-1] + ', "max_concurrency": 1}', "appears more than once"),
}


@pytest.mark.parametrize(
    ("case", "argv"),
    [
        *((case, ("run", "--items", QUERY)) for case in REJECTED),
        ("no-timeout_seconds", ("run", "--sync-point", "a")),
        ("no-timeout_seconds", ("plan", "--items", QUERY)),
        ("no-timeout_seconds", ("manual", QUERY)),
        ("no-timeout_seconds", ("status",)),
        ("no-timeout_seconds", ("status", "set", QUERY, "queued", "--reason", "x")),
        ("no-timeout_seconds", ("cleanup", QUERY, "--approved")),
    ],
)
def test_a_rejected_configuration_ends_with_2_before_any_process(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, case: str, argv: tuple[str, ...]
) -> None:
    """Row: the configuration is rejected with exit code 2, and no process is started (28.7, 28.11)."""
    sb = handoff_sandbox
    text, message = REJECTED[case]
    prepare(sb, monkeypatch, config=text)
    spy = PopenSpy(monkeypatch)
    code, out, err = call(sb, *argv)
    assert code == 2, (out, err)
    assert spy.calls == [] and sb.records() == []
    assert message in err and "config.json" in err, err
    assert out == ""
    assert not status_path(sb).exists() and not (sb.handoff_dir / ".lock").exists()
    assert not (sb.handoff_dir / "sync").exists() and registered(sb) == [str(sb.main_tree)]


def test_a_rejected_configuration_as_a_file_runs_no_git_and_no_kiro_cli(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same as a separate process, where a git or ``kiro-cli`` started before the check would be logged."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch, config=REJECTED["repeated-key"][0])
    completed, calls = run_file(sb, "run", "--items", QUERY)
    assert completed.returncode == 2, completed
    assert "appears more than once" in completed.stderr and completed.stdout == ""
    assert calls == [] and sb.records() == [] and not status_path(sb).exists()
    for case in ("no-timeout_seconds", "root-in-the-target-main-tree"):
        text, message = REJECTED[case]
        (sb.handoff_dir / "config.json").write_text(text, encoding="utf-8")
        completed, calls = run_file(sb, "plan", "--items", QUERY)
        assert completed.returncode == 2 and message in completed.stderr, completed
        assert calls == [] and sb.records() == []
    helped, _ = run_file(sb, "--help")
    assert helped.returncode == 0 and "plan" in helped.stdout and "cleanup" in helped.stdout


@pytest.mark.parametrize(
    "argv",
    [
        ("run", "--sync-point", "a", "--items", QUERY),
        ("run",),
        ("plan",),
        ("plan", "--items", "no-such-item"),
        ("run", "--items", f"{QUERY},{QUERY}"),
        ("run", "--sync-point", "rollout"),
        ("manual", "no-such-item"),
        ("cleanup", "no-such-item"),
        ("status", "set", "no-such-item", "queued", "--reason", "x"),
        ("status", "set", QUERY, "queued", "--reason", "  "),
        ("status", "set", QUERY, "failed", "--reason", "x"),
    ],
)
def test_rejected_arguments_end_with_2_before_any_process(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, argv: tuple[str, ...]
) -> None:
    """Arguments are checked against the manifest before the deny list is read (which would end with 5)."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch, terms=False)
    spy = PopenSpy(monkeypatch)
    code, out, err = call(sb, *argv)
    assert code == 2, (out, err)
    assert spy.calls == [] and sb.records() == []
    assert not status_path(sb).exists() and not (sb.handoff_dir / "sync").exists()


# ---------------------------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------------------------


def test_plan_shows_the_run_and_changes_no_state(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``plan`` draws and scans the prompts as ``run`` would, forecasts every wave, and writes no state."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    # as a file, with no status.json: it is not created, and git runs only `status` (read only)
    completed, calls = run_file(sb, "plan", "--items", NAMED)
    assert completed.returncode == 0, completed
    assert not status_path(sb).exists() and not (sb.handoff_dir / "status.json.bak").exists()
    assert not (sb.handoff_dir / ".lock").exists()
    assert calls and all("status" in argv and "worktree" not in argv and "fetch" not in argv for argv in calls)
    assert sb.records() == [] and registered(sb) == [str(sb.main_tree)]
    lines = completed.stdout.splitlines()
    text = completed.stdout
    assert OTHER not in text
    assert DENY_TERM not in text and DENY_TERM.lower() not in text
    assert f"  本文: ~/Projects/example-harness/.private/handoff/sync/a-{REPO}.md（" in text
    assert "  走査: 該当なし" in text and "  走査: 該当 1 件（行 " in text and ": deny_term）" in text
    assert "  実行者: 対象リポジトリの Kiro" in text and "    行 4: " in text
    handling = {item_id: plan_line(lines, item_id, "  run の扱い: ") for item_id in (QUERY, CHANGE, DENIED, SECOND)}
    assert handling[QUERY] == "  run の扱い: 起動する（1 番目）"
    assert handling[SECOND] == "  run の扱い: 起動する（2 番目。依存先が succeeded で終わった場合）"
    assert handling[CHANGE].startswith(
        "  run の扱い: needs-human にする（change_mode_not_wired。先に起動する項目が終わった後）"
    )
    assert handling[DENIED].startswith(
        "  run の扱い: needs-human にする（prompt_scan_findings。先に起動する項目が終わった後）"
    )
    assert prompt_file(sb, "c").exists()  # drawn and written, as run would, but not passed on

    # in this process, with a status.json: its bytes stay the same
    before = write_status(sb, {QUERY: [("running", T0, "dispatched"), ("failed", T0, "timed_out")]})
    code, out, err = call(sb, "plan", "--sync-point", "d")
    assert code == 0, (out, err)
    assert status_path(sb).read_bytes() == before and not (sb.handoff_dir / "status.json.bak").exists()
    assert "  依存: a-hub-query（failed）" in out
    assert "  run の扱い: この run では起動しない（dependency_not_succeeded: " in out
    code, out, err = call(sb, "plan", "--items", NAMED)
    assert code == 0 and status_path(sb).read_bytes() == before
    assert "  本文: 描いていない（状態が queued でない）" in out
    assert sb.records() == []


# ---------------------------------------------------------------------------------------------
# run: the order of dag.select, scan findings, no kiro-cli, whoami, a second harness
# ---------------------------------------------------------------------------------------------


def test_run_starts_only_the_named_query_items_in_the_order_of_dag_select(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``run`` starts the named query items as ``dag.select`` orders them and holds the others."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    code, out, err = call(sb, "run", "--items", NAMED)
    assert code == 1, (out, err)  # two items were held
    status = read_status(sb)
    states = {item_id: status["items"][item_id]["state"] for item_id in ALL_IDS}
    assert states == {
        QUERY: "succeeded",
        CHANGE: "needs-human",
        DENIED: "needs-human",
        SECOND: "succeeded",
        OTHER: "queued",
    }
    assert [(h["from"], h["to"], h["reason"]) for h in status["items"][CHANGE]["history"]] == [
        ("queued", "needs-human", "selftest_unconfirmed")  # no selftest has run in the sandbox (task 5.2)
    ]
    assert status["items"][DENIED]["history"][-1]["reason"] == "prompt_scan_findings"
    assert status["items"][OTHER]["history"] == []
    runs = sb.invocations()
    assert [run["start"]["subcommand"] for run in runs] == ["whoami", "chat", "whoami", "chat"]
    chats = [run["start"] for run in runs if run["start"]["subcommand"] == "chat"]
    assert [chat["cwd"] for chat in chats] == [str(worktree(sb, QUERY)), str(worktree(sb, SECOND))]
    for held in (CHANGE, DENIED, OTHER):
        assert not worktree(sb, held).exists()
    assert prompt_file(sb, "c").exists()  # the held body is kept for the maintainer, not passed on
    # the order of the starts and holds on standard output is the order of dag.select
    events = [line for line in out.splitlines() if line.startswith("開始: ") or "（selftest_unconfirmed）。" in line]
    assert ids_in(events, *ALL_IDS) == [QUERY, CHANGE, DENIED, SECOND]
    assert f"  {OTHER}" not in out and DENY_TERM not in out
    assert "deny_term" in err


def test_a_body_with_scan_findings_never_reaches_kiro_cli(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row: a body with a finding of each kind is held without a ``running`` step; no received prompt has one (28.23).

    The values are built here from parts, so that this file holds none of them.
    """
    sb = handoff_sandbox
    held = {  # Sync_Point: the value that the body carries, and the kind of finding it gives
        "b": (DENY_TERM, "deny_term"),
        "c": ("4" * 12, "account_id"),
        "d": (".".join(("10", "1", "2", "3")), "internal_ip"),
        "e": ("case " + "7" * 6, "case_number"),
    }
    topics = {"a": "the sandbox repository", **{sp: f"the item of {value}" for sp, (value, _) in held.items()}}
    items = [item(f"{sp}-hub-scan", sp, vars={"topic": topic}) for sp, topic in topics.items()]
    prepare(sb, monkeypatch, manifest={"schema_version": 1, "items": items})
    code, out, err = call(sb, "run", "--items", ",".join(f"{sp}-hub-scan" for sp in reversed(list(topics))))
    assert code == 1, (out, err)
    status = read_status(sb)
    chats = [run["start"] for run in sb.invocations() if run["start"]["subcommand"] == "chat"]
    assert [chat["cwd"] for chat in chats] == [str(worktree(sb, "a-hub-scan"))]  # only the clean item
    for chat in chats:
        assert scan.check(chat["prompt"], CUSTOMER_TERMS) == []
    assert status["items"]["a-hub-scan"]["state"] == "succeeded"
    for sync_point, (value, kind) in held.items():
        item_id = f"{sync_point}-hub-scan"
        history = status["items"][item_id]["history"]
        assert [(h["from"], h["to"], h["reason"]) for h in history] == [
            ("queued", "needs-human", "prompt_scan_findings")
        ]
        assert not worktree(sb, item_id).exists()
        body = prompt_file(sb, sync_point).read_text(encoding="utf-8")  # kept for the maintainer
        assert kind in {finding.kind for finding in scan.check(body, CUSTOMER_TERMS)}, (item_id, kind)
        assert value not in out and kind in err


def test_run_without_kiro_cli_prints_the_manual_display(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row: without ``kiro-cli``, ``run`` prints the manual display of each ready item instead (28.21)."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch, config=config_value(kiro_cli="~/.local/bin/no-such-kiro-cli"))
    code, out, err = call(sb, "run", "--items", f"{QUERY},{DENIED},{SECOND}")
    assert code == 6, (out, err)
    assert "kiro-cli が" in err and "見つからない" in err
    assert out.count("手作業の引き継ぎ: ") == 1 and f"手作業の引き継ぎ: {QUERY}" in out
    body = prompt_file(sb, "a").read_text(encoding="utf-8")
    assert "----- ここから -----\n" + body + "----- ここまで -----\n" in out
    assert f"- 貼り付ける先のリポジトリ: {REPO}" in out
    assert DENY_TERM not in out and "deny_term" in err  # the held body is not shown
    assert f"{SECOND}: 依存先か参照が揃っていない" in err
    assert not status_path(sb).exists() and sb.records() == []


def test_a_whoami_failure_ends_with_4_and_leaves_the_item_queued(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row: ``kiro-cli whoami`` fails; exit code 4, a login is asked for, ``queued`` stays, no worktree (28.18)."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch, FAKE_KIRO_MODE="whoami-fail")
    code, out, err = call(sb, "run", "--items", f"{QUERY},{OTHER}")
    assert code == 4, (out, err)
    assert "log in to kiro-cli" in err
    status = read_status(sb)
    for item_id in (QUERY, OTHER):  # neither the first item nor the next one started
        record = status["items"][item_id]
        assert record["state"] == "queued" and record["history"] == [], item_id
        assert not worktree(sb, item_id).exists()
    assert [run["start"]["subcommand"] for run in sb.invocations()] == ["whoami"]
    assert registered(sb) == [str(sb.main_tree)]


def test_a_second_harness_ends_with_3_and_starts_nothing(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row: while a harness holds the lock, every subcommand that takes it ends with 3 and starts nothing."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    with runner.Harness.open(str(sb.handoff_dir)):
        held = (sb.handoff_dir / ".lock").read_bytes()
        for argv in (
            ("run", "--items", QUERY),
            ("plan", "--items", QUERY),
            ("manual", QUERY),
            ("cleanup", QUERY, "--approved"),
        ):
            code, out, err = call(sb, *argv)
            assert code == 3, (argv, out, err)
            assert f"another Handoff_Harness (pid {os.getpid()}," in err, err
        assert (sb.handoff_dir / ".lock").read_bytes() == held
        code, out, err = call(sb, "status")  # reads without the lock
        assert code == 0, (out, err)
    assert sb.records() == [] and not status_path(sb).exists() and not (sb.handoff_dir / "sync").exists()
    assert registered(sb) == [str(sb.main_tree)]


# ---------------------------------------------------------------------------------------------
# manual
# ---------------------------------------------------------------------------------------------


def test_manual_prints_the_prompt_the_repository_and_the_commands(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row: the whole body, the repository, and the commands from fetch to ``worktree add``; no state changes (28.21)."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    code, out, err = call(sb, "manual", QUERY)
    assert code == 0, (out, err)
    assert not status_path(sb).exists() and sb.records() == []
    assert f"- 貼り付ける先のリポジトリ: {REPO}" in out
    commands = [line.strip() for line in out.splitlines() if line.startswith("    git -C ")]
    assert commands == [
        f"git -C ~/Projects/{REPO} fetch --no-tags origin main",
        f"git -C ~/Projects/{REPO} ls-remote origin refs/heads/main",
        f"git -C ~/Projects/{REPO} rev-parse refs/remotes/origin/main",
        f"git -C ~/Projects/{REPO} worktree add --detach {tilde_worktree(QUERY)} <sha>",
    ]
    assert pasted(out) == prompt_file(sb, "a").read_text(encoding="utf-8")
    assert registered(sb) == [str(sb.main_tree)]

    code, out, err = call(sb, "manual", DENIED)
    assert code == 1 and out == ""
    assert "deny_term" in err and "行 " in err and DENY_TERM not in err

    # a held change item is handed over by hand, and its state stays as it is
    before = write_status(
        sb,
        {
            QUERY: [("running", T0, "dispatched"), ("succeeded", T0, "all_checks_passed")],
            CHANGE: [("needs-human", T0, "change_mode_not_wired")],
        },
    )
    code, out, err = call(sb, "manual", CHANGE)
    assert code == 0, (out, err)
    assert "- モード: 変更モード（引き継ぎ用ブランチ handoff/b-hub-change）" in out
    assert f"    git -C ~/Projects/{REPO} worktree add -b handoff/{CHANGE} {tilde_worktree(CHANGE)} <sha>" in out
    assert pasted(out) == prompt_file(sb, "b").read_text(encoding="utf-8")
    assert status_path(sb).read_bytes() == before
    code, out, err = call(sb, "manual", QUERY)
    assert code == 1 and out == "" and "succeeded" in err
    assert status_path(sb).read_bytes() == before and sb.records() == []


@pytest.mark.parametrize("current", ["no record", "queued", "failed", "needs-human", "running", "succeeded"])
def test_manual_hands_over_queued_failed_and_needs_human_items_only(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, current: str
) -> None:
    """Row: ``manual`` takes ``queued``, ``failed`` and ``needs-human`` items, and refuses ``running`` and ``succeeded``."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    moves = {
        "no record": None,
        "queued": [],
        "failed": [("running", T0, "dispatched"), ("failed", T0, "timed_out")],
        "needs-human": [("running", T0, "dispatched"), ("needs-human", T0, "undeclared_files")],
        "running": [("running", T0, "dispatched")],
        "succeeded": [("running", T0, "dispatched"), ("succeeded", T0, "all_checks_passed")],
    }[current]
    leader = live_leader()  # a running record keeps its state only while its PID leads a session
    try:
        before = (
            None
            if moves is None
            else write_status(sb, {QUERY: moves}, a_hub_query={"pid": leader.pid} if current == "running" else {})
        )
        code, out, err = call(sb, "manual", QUERY)
    finally:
        leader.kill()
        leader.wait()
    if moves is None:
        assert not status_path(sb).exists()
    else:
        assert status_path(sb).read_bytes() == before
    assert sb.records() == [] and registered(sb) == [str(sb.main_tree)]
    if current in ("running", "succeeded"):
        assert code == 1 and out == "", (out, err)
        assert f"{QUERY} is {current}; only a queued, failed or needs-human item is handed over" in err
    else:
        assert code == 0, (out, err)
        assert f"手作業の引き継ぎ: {QUERY}" in out and f"- 貼り付ける先のリポジトリ: {REPO}" in out
        assert pasted(out) == prompt_file(sb, "a").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------------------------
# status and status set
# ---------------------------------------------------------------------------------------------


def test_status_shows_states_waits_time_and_worktree_differences(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``status`` reads without the lock (H6, H8); ``status set`` moves only ``failed`` and ``needs-human`` to ``queued``."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    sb.git("-C", str(sb.main_tree), "worktree", "add", "--detach", str(worktree(sb, DENIED)), sb.base_sha)
    sb.git("-C", str(sb.main_tree), "worktree", "add", "--detach", str(worktree(sb, "stray")), sb.base_sha)
    before = write_status(
        sb,
        {
            QUERY: [("running", T0, "dispatched"), ("failed", "2026-11-11T00:01:30Z", "timed_out")],
            DENIED: [
                ("running", "2026-11-11T00:02:00Z", "dispatched"),
                ("succeeded", "2026-11-11T00:02:45Z", "all_checks_passed"),
            ],
            CHANGE: [("needs-human", T0, "change_mode_not_wired")],
        },
        a_hub_query={"worktree": tilde_worktree(QUERY)},
        c_hub_denied={"worktree": tilde_worktree(DENIED)},
    )
    with runner.Harness.open(str(sb.handoff_dir)):  # status reads without the lock
        code, out, err = call(sb, "status")
    assert code == 0, (out, err)
    assert status_path(sb).read_bytes() == before
    assert f"{QUERY}: failed（{REPO}、照会モード、Sync_Point a）" in out
    assert "  running の時間: 0:01:30（1 回）" in out and "  running の時間: 0:00:45（1 回）" in out
    assert f"依存先の失敗で待機中:\n  {SECOND}（{QUERY} が failed）" in out
    assert "running の時間の合計: 0:02:15（2 回の実行）" in out
    assert f"  git にあり、状態ファイルのどの項目も指していない: {tilde_worktree('stray')}（{REPO}）" in out
    assert f"  状態ファイルにあり、git の worktree にない: {QUERY} の {tilde_worktree(QUERY)}" in out
    assert f"{DENIED} の" not in out and "食い違いなし" not in out

    code, out, err = call(sb, "status", "set", QUERY, "queued", "--reason", "fixed the template")
    assert code == 0, (out, err)
    assert f"{QUERY}: failed → queued（fixed the template）" in out
    code, out, err = call(sb, "status", "set", CHANGE, "queued", "--reason", "hand it over later")
    assert code == 0, (out, err)
    after = read_status(sb)
    for item_id, was in ((QUERY, "failed"), (CHANGE, "needs-human")):
        last = after["items"][item_id]["history"][-1]
        assert after["items"][item_id]["state"] == "queued" and (last["from"], last["to"]) == (was, "queued")
    assert after["items"][QUERY]["history"][-1]["reason"] == "fixed the template"
    kept = status_path(sb).read_bytes()
    for item_id in (DENIED, SECOND):  # succeeded and queued are not moved
        code, out, err = call(sb, "status", "set", item_id, "queued", "--reason", "again")
        assert code == 1 and "was not moved" in err, (item_id, out, err)
        assert status_path(sb).read_bytes() == kept


# ---------------------------------------------------------------------------------------------
# cleanup
# ---------------------------------------------------------------------------------------------


def test_cleanup_lists_and_removes_only_when_approved(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row: ``cleanup --approved`` removes without ``--force`` and records ``worktree_removed``; branches stay."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    query_wt, change_wt = worktree(sb, QUERY), worktree(sb, CHANGE)
    sb.git("-C", str(sb.main_tree), "worktree", "add", "--detach", str(query_wt), sb.base_sha)
    sb.git("-C", str(sb.main_tree), "worktree", "add", "-b", f"handoff/{CHANGE}", str(change_wt), sb.base_sha)
    before = write_status(
        sb,
        {
            QUERY: [("running", T0, "dispatched"), ("succeeded", T0, "all_checks_passed")],
            CHANGE: [("needs-human", T0, "change_mode_not_wired")],
        },
        a_hub_query={"worktree": tilde_worktree(QUERY)},
        b_hub_change={"worktree": tilde_worktree(CHANGE)},
    )
    code, out, err = call(sb, "cleanup", QUERY)
    assert code == 0, (out, err)
    assert f"  worktree: {tilde_worktree(QUERY)}（git に登録あり、ディレクトリあり、状態ファイルが指している）" in out
    assert "  ブランチ: なし" in out
    assert f"  git -C ~/Projects/{REPO} worktree remove {tilde_worktree(QUERY)}\n" in out
    assert "--force" not in out
    assert query_wt.is_dir() and str(query_wt) in registered(sb) and status_path(sb).read_bytes() == before

    # git refuses a worktree with an untracked file, and nothing is removed or recorded
    (query_wt / "left-by-hand.txt").write_text("keep me\n", encoding="utf-8")
    code, out, err = call(sb, "cleanup", QUERY, "--approved")
    assert code == 1, (out, err)
    assert "git worktree remove は消さなかった" in err
    assert (query_wt / "left-by-hand.txt").exists() and str(query_wt) in registered(sb)
    assert status_path(sb).read_bytes() == before

    # and one with a modified tracked file
    (query_wt / "left-by-hand.txt").unlink()
    readme = (query_wt / "README.md").read_bytes()
    (query_wt / "README.md").write_bytes(readme + b"an edit nobody committed\n")
    code, out, err = call(sb, "cleanup", QUERY, "--approved")
    assert code == 1 and "git worktree remove は消さなかった" in err, (out, err)
    assert str(query_wt) in registered(sb) and status_path(sb).read_bytes() == before

    (query_wt / "README.md").write_bytes(readme)
    code, out, err = call(sb, "cleanup", QUERY, "--approved")
    assert code == 0, (out, err)
    assert not query_wt.exists() and str(query_wt) not in registered(sb)
    status = read_status(sb)
    assert status["items"][QUERY]["worktree"] is None and status["items"][QUERY]["state"] == "succeeded"
    assert [event["kind"] for event in status["events"]] == [runner.WORKTREE_REMOVED]
    event = status["events"][0]
    assert event["detail"] == f"{QUERY}: git worktree remove {tilde_worktree(QUERY)}"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", event["at"]), event

    # a change item: the branch is listed and kept
    code, out, err = call(sb, "cleanup", CHANGE)
    assert code == 0 and f"  ブランチ: handoff/{CHANGE}（ある。" in out
    assert f"git -C ~/Projects/{REPO} branch -d handoff/{CHANGE}" in out and change_wt.is_dir()
    code, out, err = call(sb, "cleanup", CHANGE, "--approved")
    assert code == 0, (out, err)
    assert not change_wt.exists()
    branch = sb.git("-C", str(sb.main_tree), "rev-parse", "--verify", "-q", f"refs/heads/handoff/{CHANGE}", check=False)
    assert branch.returncode == 0
    assert [event["kind"] for event in read_status(sb)["events"]] == [runner.WORKTREE_REMOVED] * 2
    assert sb.records() == []


# ---------------------------------------------------------------------------------------------
# the default --handoff-dir from a linked worktree
# ---------------------------------------------------------------------------------------------


def test_without_handoff_dir_a_linked_worktree_uses_the_main_working_tree(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without ``--handoff-dir``, a copy in a linked worktree reads the main working tree's ``.private/handoff``."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    main = sb.root / "harness-main"
    linked = sb.root / "harness-linked"
    settings = [
        "-c",
        "user.name=handoff-test",
        "-c",
        "user.email=handoff-test@example.com",
        "-c",
        "commit.gpgSign=false",
        "-c",
        f"core.hooksPath={sb.hooks_dir}",
    ]
    sb.git("init", "-q", "--initial-branch=main", str(main))
    sb.git(*settings, "-C", str(main), "commit", "-q", "--allow-empty", "-m", "init")
    sb.git("-C", str(main), "worktree", "add", "-q", "--detach", str(linked))
    shutil.copytree(CLI_FILE.parent, linked / "scripts" / "handoff", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(CLI_FILE.parent.parent / "check_sensitive_patterns.py", linked / "scripts")  # scan.py imports it
    copied = linked / "scripts" / "handoff" / "cli.py"
    env = sb.environ(PYTHONIOENCODING="utf-8")
    completed = subprocess.run(
        [sys.executable, str(copied), "status"],
        cwd=str(sb.root),
        env=env,
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert completed.returncode == 2, completed
    assert f"{main}/.private/handoff/config.json does not exist" in completed.stderr
    assert str(linked / ".private") not in completed.stderr
    assert not (main / ".private").exists() and not (linked / ".private").exists()

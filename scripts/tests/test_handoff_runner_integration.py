"""Integration tests of the Handoff_Harness runner, ``scripts/handoff/runner.py`` (task 2.4).

Every test runs query items with :class:`handoff.runner.Harness` in the ``handoff_sandbox`` of
``conftest.py``: a bare repository in the role of the remote, a clone of it in the role of the
target repository's main working tree (with another session's uncommitted changes), the harness's
``.private/handoff/``, and the fake ``kiro-cli`` of ``fixtures/handoff/``. ``apply_environ`` gives
the runner the sandbox ``HOME`` and git configuration, so nothing reads this machine's ``~/.kiro``,
``~/.aws``, ``~/.config/gh`` or global git configuration. No test uses the network, the real
``kiro-cli`` or a real repository, and none is skipped on any platform.

Rows of the design's Testing Strategy table checked here (Requirement 28):

- ``kiro-cli whoami`` fails: the item stays ``queued``, :class:`handoff.runner.LoginRequired` asks
  for a login, and no worktree is created (28.18).
- Timeout: the item becomes ``failed``, no process of the run is left, the worktree is kept and the
  Handoff_Report names it (28.8, 28.19).
- The whole standard output and standard error are kept in the Handoff_Report: a mebibyte of bytes
  that are not UTF-8 on each stream, a non-zero exit, a timeout, and before the observations (28.8).
- A query item's worktree is detached at the base SHA and creates no branch (28.5, 28.6).
- ``kiro-cli`` and ``kiro-cli whoami`` get none of the parent's ``AWS_*`` credentials, and get the
  ``GIT_CONFIG_*`` override of the push URL and an empty ``GH_CONFIG_DIR`` (layer 3 of design
  section 20).
- The main working tree's uncommitted changes are the same bytes after a run (28.6).
- A second harness cannot take the lock, and the removal of a stale lock is recorded in ``events``
  of ``status.json``.

The other tests keep what the throwaway checks of task 2.2 caught: the reconciliation of
``running`` records, free space, decision D-15, places that resolve into a protected tree, held
prompts, stop requests, re-runs, report flags, and what a query run must not do.
``test_handoff_cli_integration.py`` covers the rows that go through ``cli.py``.

Waits for a process, a file or an event of the fake allow :data:`WAIT_SECONDS`, and the timeout
test allows 20 seconds beyond the configured limit and the grace period, for a slow CI machine. A
run that nothing stops would take the fake's 60 seconds of sleep.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

import pytest
from handoff import command, dag, evaluate, runner, state
from handoff import config as config_module
from handoff import manifest as manifest_module

if TYPE_CHECKING:
    from conftest import HandoffSandbox

REPO = "example-hub"
ITEM = "a-hub-query"
SECOND = "b-hub-query"
T0 = "2026-11-11T00:00:00Z"

#: Seconds that a wait for a process, a file or an event of the fake allows.
WAIT_SECONDS = 30.0

#: Made-up credentials in the parent's environment, which layer 3 must keep from ``kiro-cli``.
SECRETS = {
    name: "made-up-" + name.lower().replace("_", "-")
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    )
}

#: The ``AWS_*`` variables that ``command.child_env`` sets itself: an empty file and a switch.
CHILD_AWS_NAMES = frozenset({"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_EC2_METADATA_DISABLED"})

#: The ``GIT_CONFIG_*`` entries of ``command.child_env``, without the push URL itself.
PUSH_URL_RESET = {
    "GIT_CONFIG_COUNT": "2",
    "GIT_CONFIG_KEY_0": "remote.origin.pushurl",
    "GIT_CONFIG_VALUE_0": "",
    "GIT_CONFIG_KEY_1": "remote.origin.pushurl",
}

TEMPLATE = """<!-- The query template of the integration tests. -->
<!-- slot: purpose -->
Answer the questions about the sandbox repository.

<!-- slot: questions -->
1. What is the first line of `AGENTS.md`?
"""

#: A git that logs its argv, can lie once about ``rev-parse refs/remotes/origin/main``, and can
#: copy a file once it exists, then runs the real git. The runner finds it first on ``PATH``.
GIT_WRAPPER = """\
import json, os, shutil, sys
args = sys.argv[1:]
with open(os.environ["HANDOFF_TEST_GIT_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\\n")
marker = os.environ.get("HANDOFF_TEST_LIE_ONCE")
if marker and "rev-parse" in args and "refs/remotes/origin/main" in args and not os.path.exists(marker):
    open(marker, "w").close()
    sys.stdout.write("0" * 40 + "\\n")
    sys.exit(0)
source, copy = os.environ.get("HANDOFF_TEST_COPY_FROM"), os.environ.get("HANDOFF_TEST_COPY_TO")
if source and copy and os.path.exists(source) and not os.path.exists(copy):
    shutil.copyfile(source, copy)
real = os.environ["HANDOFF_TEST_REAL_GIT"]
os.execv(real, [real] + args)
"""


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------


def make_config(sandbox: HandoffSandbox, **overrides: Any) -> config_module.HandoffConfig:
    """Parse a configuration of the real form for the sandbox; ``overrides`` replace keys."""
    raw = {
        "schema_version": 1,
        "kiro_cli": "~/.local/bin/kiro-cli",
        "timeout_seconds": 60,
        "max_concurrency": 3,
        "worktrees_root": "~/Projects/.handoff-worktrees",
        "min_free_disk_gb": 1,
        "mode_tool_ceiling": {"query": ["fs_read"], "change": ["fs_read", "fs_write"]},
        "agents": {},
        "repos": {REPO: {"main_tree": f"~/Projects/{REPO}"}},
    }
    raw.update(overrides)
    return config_module.parse_config(
        raw,
        home=str(sandbox.home),
        extra_main_trees=[str(sandbox.harness_tree)],
        session_worktrees_dir=str(sandbox.session_worktrees),
    )


def query_item(item_id: str = ITEM, *, sync_point: str = "a", topic: str | None = None) -> dict[str, Any]:
    """A query item of the manifest; with ``topic``, of the template that names it."""
    return {
        "id": item_id,
        "repo": REPO,
        "sync_point": sync_point,
        "mode": "query",
        "template": "templates/query.md" if topic is None else "templates/query-topic.md",
        "vars": {} if topic is None else {"topic": topic},
        "depends_on": [],
        "requires_refs": [],
        "trust_tools": ["fs_read"],
        "trust_all": None,
        "declared_files": [],
        "verify_commands": [],
        "batch": None,
        "gates": [],
        "knowledge_kinds": ["records under .private/"],
        "read_paths": [],
        "artifact_paths": [],
    }


def make_manifest(cfg: config_module.HandoffConfig, *items: dict[str, Any]) -> manifest_module.Manifest:
    """Parse a manifest of ``items``, or of the one :func:`query_item` when none is given."""
    return manifest_module.parse_manifest({"schema_version": 1, "items": list(items or [query_item()])}, config=cfg)


def write_templates(sandbox: HandoffSandbox) -> None:
    """Put the two templates below ``.private/handoff/templates/``."""
    templates = sandbox.handoff_dir / "templates"
    templates.mkdir(exist_ok=True)
    (templates / "query.md").write_text(TEMPLATE, encoding="utf-8")
    (templates / "query-topic.md").write_text(TEMPLATE.replace("the sandbox repository", "$topic"), encoding="utf-8")


def deny_terms(sandbox: HandoffSandbox) -> runner.DenyTerms:
    """Read a synthetic customer list, and no research list, with ``load_deny_terms``."""
    lists = sandbox.root / "deny"
    lists.mkdir(exist_ok=True)
    customer = lists / "customer-terms.txt"
    customer.write_text("# synthetic customer names\nexamplecorp\n\nsamplebank\n", encoding="utf-8")
    return runner.load_deny_terms(str(customer), str(lists / "deny-terms.txt"))


def make_context(
    sandbox: HandoffSandbox, cfg: config_module.HandoffConfig, manifest: manifest_module.Manifest, **kw: Any
) -> runner.RunContext:
    """The run context that ``cli.py`` builds, with a kill grace of 1 second unless one is given."""
    write_templates(sandbox)
    return runner.RunContext(
        config=cfg,
        manifest=manifest,
        home=str(sandbox.home),
        harness_tree=str(sandbox.harness_tree),
        session_worktrees_dir=str(sandbox.session_worktrees),
        deny=deny_terms(sandbox),
        kill_grace_seconds=kw.pop("kill_grace_seconds", 1.0),
        **kw,
    )


def run_item(
    sandbox: HandoffSandbox,
    *items: dict[str, Any],
    item_id: str = ITEM,
    config: dict[str, Any] | None = None,
    **context: Any,
) -> runner.ItemOutcome:
    """Open the harness, add the records of the manifest, run one item, and close the harness."""
    cfg = make_config(sandbox, **(config or {}))
    manifest = make_manifest(cfg, *items)
    ctx = make_context(sandbox, cfg, manifest, **context)
    with runner.Harness.open(str(sandbox.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        return harness.run_query_item(ctx, item_id)


def worktree_path(sandbox: HandoffSandbox, item_id: str = ITEM) -> Path:
    """Where ``command.build_git_plan`` puts an item's worktree."""
    return sandbox.worktrees_root / REPO / item_id


def heads(sandbox: HandoffSandbox) -> bytes:
    """The branches of the target repository, which its worktrees share."""
    return sandbox.git("-C", str(sandbox.main_tree), "for-each-ref", "refs/heads").stdout


def worktree_list(sandbox: HandoffSandbox) -> list[str]:
    """The worktrees that git has registered for the target repository, the main one first."""
    out = sandbox.git("-C", str(sandbox.main_tree), "worktree", "list", "--porcelain").stdout.decode()
    return [line.split(" ", 1)[1] for line in out.splitlines() if line.startswith("worktree ")]


def files_below(directory: Path) -> set[str]:
    """The files and symbolic links below a directory, relative to it."""
    return {str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file() or path.is_symlink()}


def dead_pid() -> int:
    """The PID of a process that has ended and been reaped."""
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    return child.pid


def wait_for(predicate: Callable[[], bool], seconds: float = WAIT_SECONDS) -> bool:
    """Poll ``predicate`` every 50 ms until it holds or ``seconds`` have passed; return its last value."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def gone(sandbox: HandoffSandbox, pid: int) -> bool:
    """Whether the process ends (or turns into a zombie) within :data:`WAIT_SECONDS`."""
    return wait_for(lambda: not sandbox.process_running(pid))


def chat_spawned(sandbox: HandoffSandbox) -> bool:
    """Whether a ``chat`` of the fake has started the child of ``sleep``: it is sleeping now."""
    return any(run["start"]["subcommand"] == "chat" and "spawned" in run for run in sandbox.invocations())


def report_text(sandbox: HandoffSandbox, item_id: str = ITEM, name: str = "report.md") -> str:
    """An item's Handoff_Report."""
    return (sandbox.handoff_dir / REPO / item_id / name).read_text(encoding="utf-8")


def report_section(text: str, heading_prefix: str) -> str:
    """The content of the fenced block right after the heading that starts with ``heading_prefix``."""
    lines = text.split("\n")
    start = next(index for index, line in enumerate(lines) if line.startswith(heading_prefix))
    fence_line = lines[start + 2]
    fence = fence_line[: len(fence_line) - len("text")]
    assert set(fence) == {"`"} and len(fence) >= 3, fence_line
    body_start = start + 3
    end = next(index for index in range(body_start, len(lines)) if lines[index] == fence)
    return "\n".join(lines[body_start:end]) + ("\n" if end > body_start else "")


def as_saved(payload: bytes) -> str:
    """How the report keeps a stream: decoded whole with replacement characters, ending with a newline."""
    text = payload.decode("utf-8", "replace")
    return text if text.endswith("\n") or not text else text + "\n"


def write_status(sandbox: HandoffSandbox, status: state.StatusDoc) -> None:
    """Write ``status.json`` as an earlier harness would have."""
    (sandbox.handoff_dir / "status.json").write_text(state.render_status(status), encoding="utf-8")


def read_status(sandbox: HandoffSandbox) -> state.StatusDoc:
    """Read and check ``status.json``."""
    return state.parse_status((sandbox.handoff_dir / "status.json").read_text(encoding="utf-8"))


def git_wrapper(sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, **extra: str) -> Path:
    """Apply the sandbox environment with :data:`GIT_WRAPPER` first on ``PATH``; return its argv log."""
    real_git = shutil.which("git")
    assert real_git is not None
    bin_dir = sandbox.root / "bin"
    bin_dir.mkdir(exist_ok=True)
    wrapper = bin_dir / "git"
    wrapper.write_text("#!" + sys.executable + "\n" + GIT_WRAPPER, encoding="utf-8")
    wrapper.chmod(0o755)
    log = sandbox.root / "git-calls.jsonl"
    sandbox.apply_environ(
        monkeypatch,
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        HANDOFF_TEST_GIT_LOG=str(log),
        HANDOFF_TEST_REAL_GIT=real_git,
        **extra,
    )
    return log


def git_calls(log: Path) -> list[list[str]]:
    """The argv of each git that the wrapper ran, in order."""
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def writes_a_tree_or_a_branch(call: list[str]) -> bool:
    """Whether a git argv would change a working tree, an index or a branch (``branch --show-current`` reads)."""
    if {"checkout", "restore", "stash", "reset", "clean", "switch"} & set(call):
        return True
    return "branch" in call and "--show-current" not in call


def push_commit(sandbox: HandoffSandbox, ref: str = "main") -> str:
    """Push one new commit from a second clone to ``ref`` of the remote; return its SHA."""
    clone = sandbox.root / "pusher"
    sandbox.git("clone", "-q", str(sandbox.bare), str(clone))
    (clone / "pushed.txt").write_text(f"pushed to {ref}\n", encoding="utf-8")
    settings = (
        "-c",
        "user.name=handoff-test",
        "-c",
        "user.email=handoff-test@example.com",
        "-c",
        "commit.gpgSign=false",
        "-c",
        f"core.hooksPath={sandbox.hooks_dir}",
    )
    sandbox.git("-C", str(clone), "add", "pushed.txt")
    sandbox.git("-C", str(clone), *settings, "commit", "-q", "-m", f"move {ref}")
    sandbox.git("-C", str(clone), *settings, "push", "-q", "origin", f"HEAD:{ref}")
    return sandbox.git("-C", str(clone), "rev-parse", "HEAD").stdout.decode().strip()


# ---------------------------------------------------------------------------------------------
# a query item that succeeds: detached worktree, no branch, the main working tree, layer 3
# ---------------------------------------------------------------------------------------------


def test_a_query_run_records_base_sha_and_the_report_path_in_the_record_and_the_report(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """28.1, 28.2: the harness records ``base_sha`` and the report's path; the prompt asks the worker for neither."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    cfg = make_config(sb)
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        outcome = harness.run_query_item(ctx, ITEM)
    assert outcome.state == "succeeded", outcome
    record = read_status(sb)["items"][ITEM]
    assert re.fullmatch(r"[0-9a-f]{40}", record["base_sha"]) and record["base_sha"] == sb.base_sha
    assert record["report"] == f"{REPO}/{ITEM}/report.md"
    report = report_text(sb)
    assert f"| base_sha | `{sb.base_sha}` |" in report
    assert f"| Handoff_Report | `{record['report']}` |" in report
    prompt_text = (sb.handoff_dir / "sync" / f"a-{REPO}.md").read_text(encoding="utf-8")
    assert "SHA を添える" not in prompt_text and "`base_sha` はハーネスが記録" in prompt_text
    assert "取りこぼしがない根拠" in prompt_text and "spoke_knowledge.py" in prompt_text


def test_the_answer_text_does_not_decide_the_state(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Property 28 for a query item: an answer of "該当なし" alone succeeds; the observations hold no answer text."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch, FAKE_KIRO_ANSWER="該当なし\n")
    cfg = make_config(sb)
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        outcome = harness.run_query_item(ctx, ITEM)
    assert (outcome.state, outcome.reason) == ("succeeded", "all_checks_passed")
    fields = {field.name for field in dataclasses.fields(evaluate.Observations)}
    assert not {name for name in fields if "text" in name or "answer" in name or name in {"stdout", "report"}}
    assert "stdout_bytes" in fields
    assert "answer" not in inspect.signature(evaluate.final_state).parameters


def test_a_query_item_succeeds_in_a_detached_worktree(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rows: no branch (28.5, 28.6), the child's environment, the main working tree's bytes."""
    sb = handoff_sandbox
    answer = "the first line is '# AGENTS.md of the example-hub sandbox'\n"
    sb.apply_environ(monkeypatch, FAKE_KIRO_ANSWER=answer, **SECRETS)
    assert {name: os.environ[name] for name in SECRETS} == SECRETS  # the parent has the credentials
    cfg = make_config(sb)
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    before_tree = sb.snapshot_main_tree()
    before_heads = heads(sb)
    index_mtime = (sb.main_tree / ".git" / "index").stat().st_mtime_ns

    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        lock = json.loads((sb.handoff_dir / ".lock").read_text(encoding="utf-8"))
        assert lock["pid"] == os.getpid() and set(lock) == {"pid", "started_at"}
        assert harness.add_missing_items(manifest) == (ITEM,)
        outcome = harness.run_query_item(ctx, ITEM)
    assert not (sb.handoff_dir / ".lock").exists()

    assert outcome.state == "succeeded" and outcome.reason == "all_checks_passed", outcome
    wt = worktree_path(sb)
    assert outcome.worktree == str(wt) and wt.is_dir() and str(wt) in worktree_list(sb)
    # detached at the base SHA, and no branch in the target repository (its worktrees share refs)
    assert sb.git("-C", str(wt), "symbolic-ref", "-q", "HEAD", check=False).returncode == 1
    assert sb.git("-C", str(wt), "rev-parse", "HEAD").stdout.decode().strip() == sb.base_sha
    assert heads(sb) == before_heads
    # the main working tree byte for byte as before, and its index not rewritten
    assert sb.snapshot_main_tree() == before_tree
    assert (sb.main_tree / ".git" / "index").stat().st_mtime_ns == index_mtime

    status = read_status(sb)
    record = status["items"][ITEM]
    assert [(h["from"], h["to"], h["reason"]) for h in record["history"]] == [
        ("queued", "running", "dispatched"),
        ("running", "succeeded", "all_checks_passed"),
    ]
    assert record["state"] == "succeeded" and record["pid"] is None
    assert record["worktree"] == f"~/Projects/.handoff-worktrees/{REPO}/{ITEM}"
    assert record["branch"] is None and record["base_sha"] == sb.base_sha
    assert record["report"] == f"{REPO}/{ITEM}/report.md"
    observations = record["observations"]
    assert observations["main_tree_change"] == "none" and observations["dirty"] is False
    assert observations["commits"] == 0 and observations["stdout_bytes"] == len(answer.encode())
    assert status["events"] == []

    runs = sb.invocations()
    assert [run["start"]["subcommand"] for run in runs] == ["whoami", "chat"]
    chat = runs[1]["start"]
    assert chat["cwd"] == str(wt)
    assert chat["argv"][1:4] == ["chat", "--no-interactive", "--trust-tools=fs_read"]
    assert chat["sid"] == chat["pid"] == chat["pgid"]  # a session and a process group of its own
    for run in runs:  # layer 3, for whoami as for chat
        env = run["start"]["env"]
        assert not set(SECRETS) & set(env["names"]), env["names"]
        assert {name for name in env["names"] if name.startswith("AWS_")} <= CHILD_AWS_NAMES
        assert env["aws_config_file"] == env["aws_shared_credentials_file"] == "empty"
        assert env["aws_ec2_metadata_disabled"] is True
        assert "GH_CONFIG_DIR" in env["names"] and env["gh_config_dir"] == "empty"
        git_config = env["git_config"]
        assert set(git_config) == {*PUSH_URL_RESET, "GIT_CONFIG_VALUE_1"}, git_config
        assert {name: git_config[name] for name in PUSH_URL_RESET} == PUSH_URL_RESET
        assert git_config["GIT_CONFIG_VALUE_1"].endswith("/no-such-remote")

    prompt_file = sb.handoff_dir / "sync" / f"a-{REPO}.md"
    assert prompt_file.read_text(encoding="utf-8") == chat["prompt"]
    report = report_text(sb)
    assert report_section(report, "## 標準出力") == answer
    assert f"| worktree | `{wt}`" in report
    assert "<Handoff_Prompt の本文: sync/a-example-hub.md" in report and chat["prompt"] not in report
    assert "| 最終状態 | `succeeded`（all_checks_passed） |" in report
    assert files_below(sb.handoff_dir) == {
        "status.json",
        "status.json.bak",
        f"sync/a-{REPO}.md",
        f"{REPO}/{ITEM}/report.md",
        "templates/query.md",
        "templates/query-topic.md",
    }
    for name in ("status.json", f"{REPO}/{ITEM}/report.md", f"sync/a-{REPO}.md"):
        assert stat.S_IMODE((sb.handoff_dir / name).stat().st_mode) == 0o600


def test_one_mismatch_followed_by_agreement_creates_the_worktree(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-15: a second look that agrees creates the worktree with ``--detach``, not ``-b``."""
    sb = handoff_sandbox
    log = git_wrapper(sb, monkeypatch, HANDOFF_TEST_LIE_ONCE=str(sb.root / "lied-once"))
    before_heads = heads(sb)
    outcome = run_item(sb)
    assert outcome.state == "succeeded", outcome
    calls = git_calls(log)
    assert len([call for call in calls if "fetch" in call]) == 2
    adds = [call for call in calls if "worktree" in call]
    assert adds == [["-C", str(sb.main_tree), "worktree", "add", "--detach", str(worktree_path(sb)), sb.base_sha]]
    assert heads(sb) == before_heads
    # besides reads, only the argv of build_git_plan touched the main working tree
    assert not [call for call in calls if writes_a_tree_or_a_branch(call)], calls


# ---------------------------------------------------------------------------------------------
# the lock, and the reconciliation of running records at start
# ---------------------------------------------------------------------------------------------


def test_a_second_harness_is_refused_and_a_stale_lock_is_removed(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row: the lock cannot be taken twice; a stale lock is removed and recorded in ``events``."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    lock_path = sb.handoff_dir / ".lock"
    with runner.Harness.open(str(sb.handoff_dir)):
        held_bytes = lock_path.read_bytes()
        with pytest.raises(runner.LockHeld) as caught:
            runner.Harness.open(str(sb.handoff_dir))
        assert caught.value.pid == os.getpid()
        assert lock_path.read_bytes() == held_bytes  # the refused harness left the lock alone
    assert not lock_path.exists()
    assert not (sb.handoff_dir / "status.json").exists()  # nothing changed, so nothing was written

    gone_pid = dead_pid()
    lock_path.write_text(json.dumps({"pid": gone_pid, "started_at": T0}) + "\n", encoding="utf-8")
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        assert harness.stale_lock == runner.StaleLock(gone_pid, T0)
        assert json.loads(lock_path.read_text(encoding="utf-8"))["pid"] == os.getpid()
    events = read_status(sb)["events"]
    assert [event["kind"] for event in events] == [runner.STALE_LOCK_REMOVED]
    assert f"pid {gone_pid}" in events[0]["detail"] and T0 in events[0]["detail"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", events[0]["at"]), events[0]

    # a live process that is not this harness keeps its lock
    sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        lock_path.write_text(json.dumps({"pid": sleeper.pid, "started_at": T0}) + "\n", encoding="utf-8")
        with pytest.raises(runner.LockHeld):
            runner.Harness.open(str(sb.handoff_dir))
        assert json.loads(lock_path.read_text(encoding="utf-8"))["pid"] == sleeper.pid
    finally:
        sleeper.kill()
        sleeper.wait()
    assert len(read_status(sb)["events"]) == 1

    # a lock that names no process is not removed
    lock_path.write_text("not json\n", encoding="utf-8")
    with pytest.raises(runner.LockUnreadable):
        runner.Harness.open(str(sb.handoff_dir))
    assert lock_path.read_text(encoding="utf-8") == "not json\n"


def test_running_records_without_their_process_become_failed(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H12: at start, a ``running`` record is kept only while its PID leads a live session."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    status = state.empty_status()
    for item_id in ("dead-pid", "no-pid", "not-a-leader", "live-leader", "outside-manifest", "queued-one"):
        status = state.add_item(status, item_id)
        if item_id != "queued-one":
            status = state.transition(status, item_id, "running", at=T0, reason="dispatched")
    not_leader = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    leader = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    try:
        status["items"]["dead-pid"]["pid"] = dead_pid()
        status["items"]["not-a-leader"]["pid"] = not_leader.pid
        status["items"]["live-leader"]["pid"] = leader.pid
        status["items"]["outside-manifest"]["pid"] = dead_pid()
        write_status(sb, status)
        with runner.Harness.open(str(sb.handoff_dir)) as harness:
            assert harness.interrupted_items == ("dead-pid", "no-pid", "not-a-leader", "outside-manifest")
        after = read_status(sb)
    finally:
        for child in (not_leader, leader):
            child.kill()
            child.wait()
    for item_id in ("dead-pid", "no-pid", "not-a-leader", "outside-manifest"):
        record = after["items"][item_id]
        assert record["state"] == "failed" and record["history"][-1]["reason"] == runner.HARNESS_INTERRUPTED
        assert record["pid"] is None
    assert after["items"]["live-leader"]["state"] == "running"
    assert after["items"]["queued-one"]["state"] == "queued"
    assert (sb.handoff_dir / "status.json.bak").read_text(encoding="utf-8") == state.render_status(status)


# ---------------------------------------------------------------------------------------------
# whoami, a missing kiro-cli and free space stop the run before any worktree exists
# ---------------------------------------------------------------------------------------------


def test_whoami_failure_leaves_the_item_queued_and_creates_no_worktree(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row: ``kiro-cli whoami`` fails; the item stays ``queued``, a login is asked for, no worktree (28.18)."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch, FAKE_KIRO_MODE="whoami-fail")
    cfg = make_config(sb)
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    before_heads = heads(sb)
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        with pytest.raises(runner.LoginRequired, match="log in to kiro-cli"):
            harness.run_query_item(ctx, ITEM)
        record = harness.status["items"][ITEM]
    assert record["state"] == "queued" and record["history"] == []
    assert read_status(sb)["items"][ITEM] == record
    assert [run["start"]["subcommand"] for run in sb.invocations()] == ["whoami"]  # no chat
    assert not worktree_path(sb).exists() and worktree_list(sb) == [str(sb.main_tree)]
    assert heads(sb) == before_heads and not (sb.handoff_dir / REPO).exists()


def test_missing_kiro_cli_raises_kiro_cli_missing(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 28.21: no ``kiro-cli`` sends the maintainer to ``cli.py manual``; the item stays ``queued``."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    cfg = make_config(sb, kiro_cli="~/.local/bin/no-such-kiro-cli")
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        with pytest.raises(runner.KiroCliMissing, match="cli.py manual"):
            harness.run_query_item(ctx, ITEM)
        assert harness.status["items"][ITEM]["state"] == "queued"
    assert not worktree_path(sb).exists() and sb.records() == []


def test_low_disk_space_stops_before_the_worktree(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H7: too little free space stops the run after whoami and before any worktree."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    cfg = make_config(sb, min_free_disk_gb=10**9)
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        with pytest.raises(runner.DiskSpaceLow) as caught:
            harness.run_query_item(ctx, ITEM)
        assert harness.status["items"][ITEM]["state"] == "queued"
    assert caught.value.required_bytes == 10**9 * 1024**3
    assert caught.value.free_bytes < caught.value.required_bytes
    assert [run["start"]["subcommand"] for run in sb.invocations()] == ["whoami"]
    assert not worktree_path(sb).exists() and worktree_list(sb) == [str(sb.main_tree)]


# ---------------------------------------------------------------------------------------------
# D-15: ls-remote and rev-parse disagree twice; only the exact ls-remote line counts
# ---------------------------------------------------------------------------------------------


def test_a_sha_mismatch_is_retried_once_and_then_held(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-15: two disagreements hold the item before ``worktree add``; nothing but reads touched the main tree."""
    sb = handoff_sandbox
    log = git_wrapper(sb, monkeypatch)
    # fetch no longer updates refs/remotes/origin/main, and the remote's main moves on
    sb.git("-C", str(sb.main_tree), "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/elsewhere/*")
    moved = push_commit(sb)
    before_heads = heads(sb)
    outcome = run_item(sb)
    assert outcome.state == "needs-human" and outcome.reason == "base_sha_mismatch", outcome
    assert outcome.detail.count("attempt ") == 2 and moved in outcome.detail and sb.base_sha in outcome.detail
    calls = git_calls(log)
    assert len([call for call in calls if "fetch" in call]) == 2, calls
    assert len([call for call in calls if "ls-remote" in call]) == 2
    assert not [call for call in calls if "worktree" in call]
    assert not [call for call in calls if writes_a_tree_or_a_branch(call)], calls
    assert not worktree_path(sb).exists() and heads(sb) == before_heads
    record = read_status(sb)["items"][ITEM]
    assert record["state"] == "needs-human" and record["history"][-1]["reason"] == "base_sha_mismatch"
    assert [run["start"]["subcommand"] for run in sb.invocations()] == ["whoami"]


def test_only_the_exact_ls_remote_line_counts(handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    """D-15: ``ls-remote`` also lists a ref whose name ends like ``refs/heads/main``; it is not the base."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    push_commit(sb, "refs/heads/x/refs/heads/main")
    listed = sb.git("-C", str(sb.main_tree), "ls-remote", "origin", "refs/heads/main").stdout.decode()
    assert len(listed.splitlines()) == 2, listed  # the pattern matches the end of a ref name
    outcome = run_item(sb)
    assert outcome.state == "succeeded", outcome
    assert sb.git("-C", str(worktree_path(sb)), "rev-parse", "HEAD").stdout.decode().strip() == sb.base_sha


# ---------------------------------------------------------------------------------------------
# timeout: the group is stopped, nothing is left, the output and the worktree are kept
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["noise,sleep", "noise,ignore-sigterm,sleep"])
def test_a_timeout_stops_the_group_and_keeps_the_worktree(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, fake_kiro_cli_module: ModuleType, mode: str
) -> None:
    """Row: timeout; ``failed``, no process left, output saved, worktree kept and named (28.8, 28.19)."""
    sb = handoff_sandbox
    size = 65536
    sb.apply_environ(monkeypatch, FAKE_KIRO_MODE=mode, FAKE_KIRO_SLEEP_SECONDS="60", FAKE_KIRO_NOISE_BYTES=str(size))
    timeout, grace = 3, 1.0
    began = time.monotonic()
    outcome = run_item(sb, config={"timeout_seconds": timeout}, kill_grace_seconds=grace)
    elapsed = time.monotonic() - began
    assert outcome.state == "failed" and outcome.reason.startswith("timed_out"), outcome
    assert outcome.timed_out and outcome.exit_code is not None and outcome.exit_code < 0
    chat = sb.invocations()[-1]
    assert chat["start"]["subcommand"] == "chat" and "end" not in chat  # killed, not ended by itself
    assert gone(sb, chat["start"]["pid"]) and gone(sb, chat["spawned"]["child_pid"])
    wt = worktree_path(sb)
    assert wt.is_dir() and str(wt) in worktree_list(sb) and outcome.worktree == str(wt)
    report = report_text(sb)
    assert f"| worktree | `{wt}`（残した。" in report
    assert f"| タイムアウト | あり（{timeout} 秒を超えた。" in report
    signals = next(line for line in report.split("\n") if line.startswith("| プロセスグループへのシグナル | "))
    if "ignore-sigterm" in mode:
        assert signals == "| プロセスグループへのシグナル | SIGTERM, SIGKILL |"
    else:
        # Linux counts zombies as members of a process group, so SIGKILL is also sent when the init
        # process has not yet reaped the child of the fake at the end of the grace period.
        assert signals in (
            "| プロセスグループへのシグナル | SIGTERM |",
            "| プロセスグループへのシグナル | SIGTERM, SIGKILL |",
        )
    for stream, heading in (("stdout", "## 標準出力"), ("stderr", "## 標準エラー出力")):
        assert report_section(report, heading) == as_saved(fake_kiro_cli_module.noise_payload(stream, size)), stream
    assert "| 最終状態 | `failed`（timed_out" in report and '"timed_out": true' in report
    record = read_status(sb)["items"][ITEM]
    assert record["state"] == "failed" and record["observations"]["timed_out"] is True and record["pid"] is None
    assert record["worktree"] == f"~/Projects/.handoff-worktrees/{REPO}/{ITEM}"
    assert elapsed < timeout + grace + 20, elapsed


# ---------------------------------------------------------------------------------------------
# the whole output is saved: a mebibyte that is not UTF-8, and before the observations
# ---------------------------------------------------------------------------------------------


def test_the_whole_output_is_saved_with_replacement_characters(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, fake_kiro_cli_module: ModuleType
) -> None:
    """Row: a mebibyte on each stream, with bytes that are not UTF-8, is saved whole (28.8)."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch, FAKE_KIRO_MODE="noise", FAKE_KIRO_ANSWER="")
    outcome = run_item(sb)
    assert outcome.state == "succeeded", outcome
    report = report_text(sb)
    for stream, heading in (("stdout", "## 標準出力"), ("stderr", "## 標準エラー出力")):
        payload = fake_kiro_cli_module.noise_payload(stream, 1048576)
        expected = as_saved(payload)
        assert "\ufffd" in expected
        assert report_section(report, heading) == expected, stream
        assert f"{heading}（1048576 バイト。" in report
    assert read_status(sb)["items"][ITEM]["observations"]["stdout_bytes"] == 1048576


def test_the_output_is_saved_before_the_observations(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The report holds the whole output before the first git of the observations runs (28.8, H12).

    A harness that dies during the observations must leave the output behind. The git wrapper
    copies ``report.md`` at the first git command after the file appears, which is the first
    command of the observations, so the copy is the report as it was at that moment.
    """
    sb = handoff_sandbox
    report = sb.handoff_dir / REPO / ITEM / "report.md"
    copy = sb.root / "report-at-the-first-observation.md"
    git_wrapper(
        sb,
        monkeypatch,
        FAKE_KIRO_ANSWER="saved before anything else\n",
        HANDOFF_TEST_COPY_FROM=str(report),
        HANDOFF_TEST_COPY_TO=str(copy),
    )
    outcome = run_item(sb)
    assert outcome.state == "succeeded", outcome
    assert copy.exists(), "no git ran after the report was first written"
    early = copy.read_text(encoding="utf-8")
    assert report_section(early, "## 標準出力") == "saved before anything else\n"
    assert "| 最終状態 | 観測の前 |" in early and "観測はこの後に行う。" in early
    assert "| 最終状態 | `succeeded`（all_checks_passed） |" in report.read_text(encoding="utf-8")


def test_a_rerun_keeps_the_earlier_report(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, fake_kiro_cli_module: ModuleType
) -> None:
    """A non-zero exit keeps both streams (28.8); a re-run renames the earlier report instead of overwriting it."""
    sb = handoff_sandbox
    size = 8192
    sb.apply_environ(
        monkeypatch,
        FAKE_KIRO_MODE="noise",
        FAKE_KIRO_NOISE_BYTES=str(size),
        FAKE_KIRO_ANSWER="",
        FAKE_KIRO_EXIT_CODE="7",
    )
    cfg = make_config(sb)
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        first = harness.run_query_item(ctx, ITEM)
        assert first.state == "failed" and first.reason == "exit_code_nonzero" and first.exit_code == 7, first
        first_report = Path(str(first.report)).read_text(encoding="utf-8")
        assert "| 終了コード | 7" in first_report
        for stream, heading in (("stdout", "## 標準出力"), ("stderr", "## 標準エラー出力")):
            assert report_section(first_report, heading) == as_saved(fake_kiro_cli_module.noise_payload(stream, size))
        sb.git("-C", str(sb.main_tree), "worktree", "remove", str(worktree_path(sb)))
        harness.requeue(ITEM, reason="the maintainer read the report and removed the worktree")
        sb.apply_environ(monkeypatch, FAKE_KIRO_ANSWER="second run\n")
        second = harness.run_query_item(ctx, ITEM)
    assert second.state == "succeeded", second
    item_dir = sb.handoff_dir / REPO / ITEM
    assert sorted(os.listdir(item_dir)) == ["report.1.md", "report.md"]
    assert (item_dir / "report.1.md").read_text(encoding="utf-8") == first_report
    assert report_section(report_text(sb), "## 標準出力") == "second run\n"


# ---------------------------------------------------------------------------------------------
# kiro-cli errors named from standard error (task 5.9, H13)
# ---------------------------------------------------------------------------------------------

USAGE_LIMIT_STDERR = (
    "Error: Internal error (code -32603): Encountered an error in the response stream: "
    "The monthly usage limit has been reached (request_id: example-request-id)\n"
)
PROFILE_STDERR = "Error: profileArn is required for this request\n"
#: The reason of exit 1 with an empty standard output, as before task 5.9.
EXIT_AND_EMPTY = "exit_code_nonzero, empty_output"
KIRO_ERROR_KINDS = {"usage_limit": "kiro_cli_usage_limit", "profile_required": "kiro_cli_profile_required"}


@pytest.mark.parametrize(
    ("stderr", "label"), [(USAGE_LIMIT_STDERR, "usage_limit"), (PROFILE_STDERR, "profile_required")]
)
def test_a_known_kiro_cli_error_is_named_without_changing_the_final_state(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, stderr: str, label: str
) -> None:
    """Exit 1, empty standard output, one known line on standard error: ``failed`` as before.

    The label is added beside the reason: ``kiro_error`` of the outcome, an event, and a line and a key in the
    Handoff_Report. The item stays ``failed`` until a maintainer moves it back, and the next selection skips it.
    """
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch, FAKE_KIRO_STDERR=stderr, FAKE_KIRO_ANSWER="", FAKE_KIRO_EXIT_CODE="1")
    cfg = make_config(sb)
    other = "a-hub-query-two"
    manifest = make_manifest(cfg, query_item(), query_item(other, sync_point="b"))
    ctx = make_context(sb, cfg, manifest)
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        outcome = harness.run_query_item(ctx, ITEM)
        selection = dag.select(manifest, harness.status, confirmed_refs=(), max_concurrency=3, item_ids=[ITEM, other])
    assert (outcome.state, outcome.reason, outcome.exit_code) == ("failed", EXIT_AND_EMPTY, 1), outcome
    assert outcome.kiro_error == label
    status = read_status(sb)
    record = status["items"][ITEM]
    assert record["state"] == "failed" and record["history"][-1]["reason"] == EXIT_AND_EMPTY
    assert [(event["kind"], ITEM in event["detail"]) for event in status["events"]] == [(KIRO_ERROR_KINDS[label], True)]
    text = report_text(sb)
    assert f"- `kiro-cli` のエラー: `{label}`。" in text and "発見的な検出" in text
    data = json.loads(text.split("```json\n")[-1].split("\n```")[0])
    assert data["kiro_cli_error"] == label
    assert ITEM not in selection.selected and other in selection.selected


def test_other_failures_get_no_kiro_error(handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 1 with other wording on standard error, or the known wording with exit 0, names nothing."""
    sb = handoff_sandbox
    sb.apply_environ(
        monkeypatch, FAKE_KIRO_STDERR="Error: connection reset by peer\n", FAKE_KIRO_ANSWER="", FAKE_KIRO_EXIT_CODE="1"
    )
    failed = run_item(sb)
    assert (failed.state, failed.reason, failed.kiro_error) == ("failed", EXIT_AND_EMPTY, None)
    assert read_status(sb)["events"] == []
    assert "`kiro-cli` のエラー" not in report_text(sb) and "kiro_cli_error" not in report_text(sb)
    sb.apply_environ(monkeypatch, FAKE_KIRO_STDERR=USAGE_LIMIT_STDERR, FAKE_KIRO_ANSWER="ok\n", FAKE_KIRO_EXIT_CODE="0")
    ok = "a-hub-query-ok"
    succeeded = run_item(sb, query_item(), query_item(ok, sync_point="b"), item_id=ok)
    assert (succeeded.state, succeeded.kiro_error) == ("succeeded", None)
    assert read_status(sb)["events"] == []


def test_the_wording_in_the_answer_is_not_matched(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The model's answer on standard output holds both wordings; standard error holds none; the exit is 1."""
    sb = handoff_sandbox
    answer = "The monthly usage limit has been reached. profileArn is required for this request.\n"
    sb.apply_environ(monkeypatch, FAKE_KIRO_ANSWER=answer, FAKE_KIRO_EXIT_CODE="1")
    outcome = run_item(sb)
    assert (outcome.state, outcome.reason, outcome.kiro_error) == ("failed", "exit_code_nonzero", None)
    assert read_status(sb)["events"] == []
    assert "kiro_cli_error" not in report_text(sb)


# ---------------------------------------------------------------------------------------------
# status.json.bak, and writes that a symbolic link would carry out of .private/handoff/
# ---------------------------------------------------------------------------------------------


def test_each_write_keeps_the_previous_status_as_bak(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 28.13: each change is written at once, after the previous version goes to ``.bak``."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    cfg = make_config(sb)
    manifest = make_manifest(cfg, query_item(), query_item(SECOND, sync_point="b"))
    status_path = sb.handoff_dir / "status.json"
    bak_path = sb.handoff_dir / "status.json.bak"
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        assert not status_path.exists()  # nothing to write yet
        harness.add_missing_items(manifest)
        first = status_path.read_bytes()
        assert not bak_path.exists()
        harness.hold(ITEM, reason="held by the integration test")
        second = status_path.read_bytes()
        assert bak_path.read_bytes() == first
        harness.requeue(ITEM, reason="requeued by the integration test")
        assert bak_path.read_bytes() == second
        with pytest.raises(state.TransitionError):
            harness.hold(SECOND, reason="")
        with pytest.raises(state.TransitionError):
            harness.requeue(SECOND, reason="not failed")  # queued -> queued is not an edge
        assert bak_path.read_bytes() == second  # refused requests write nothing
    assert [name for name in os.listdir(sb.handoff_dir) if name.endswith(".tmp")] == []
    status_path.write_text("{", encoding="utf-8")  # a damaged status refuses the start, and is kept
    with pytest.raises(runner.StatusUnreadable, match="status.json.bak"):
        runner.Harness.open(str(sb.handoff_dir))
    assert status_path.read_text(encoding="utf-8") == "{" and not (sb.handoff_dir / ".lock").exists()


def test_a_symbolic_link_cannot_carry_a_write_out_of_private_handoff(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 28.22: every write stays below ``.private/handoff/`` after links are resolved."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    outside = sb.root / "outside"
    outside.mkdir()
    (sb.handoff_dir / REPO).symlink_to(outside, target_is_directory=True)
    cfg = make_config(sb)
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        with pytest.raises(runner.UnsafeLocation, match="report.md"):
            harness.run_query_item(ctx, ITEM)
        assert harness.status["items"][ITEM]["state"] == "queued"
    assert list(outside.iterdir()) == [] and sb.invocations() == []  # nothing was started

    with pytest.raises(ValueError):
        runner.Harness.open(str(sb.harness_tree / ".private" / "elsewhere"))
    with pytest.raises(ValueError):
        runner.Harness.open(str(sb.handoff_dir) + "/../handoff")
    linked = sb.root / "linked-repo"  # .private/handoff reached through a symbolic link
    (linked / ".private").mkdir(parents=True)
    (linked / ".private" / "handoff").symlink_to(outside, target_is_directory=True)
    with pytest.raises(runner.UnsafeLocation):
        runner.Harness.open(str(linked / ".private" / "handoff"))
    linked_private = sb.root / "linked-private"  # .private is the link, and handoff does not exist yet
    linked_private.mkdir()
    (linked_private / ".private").symlink_to(outside, target_is_directory=True)
    with pytest.raises(runner.UnsafeLocation):
        runner.Harness.open(str(linked_private / ".private" / "handoff"))
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize(
    ("layout", "message"),
    [
        ("root-into-main", "main working tree of example-hub"),  # both checks fire
        ("repo-dir-into-main", "the worktree"),  # only the worktree check fires
        ("repo-dir-elsewhere", "the worktree"),  # outside worktrees_root, in no protected tree
        ("root-contains-all", "worktrees_root .* which meets"),  # only the worktrees_root check fires
    ],
)
def test_places_that_resolve_into_a_protected_tree_are_refused(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, layout: str, message: str
) -> None:
    """Requirement 28.5: links that the lexical check of the configuration cannot see are refused before git."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    if layout == "root-into-main":
        shutil.rmtree(sb.worktrees_root)
        sb.worktrees_root.symlink_to(sb.main_tree / "docs", target_is_directory=True)
    elif layout == "repo-dir-into-main":
        (sb.worktrees_root / REPO).symlink_to(sb.main_tree / "docs", target_is_directory=True)
    elif layout == "repo-dir-elsewhere":
        elsewhere = sb.root / "elsewhere"
        elsewhere.mkdir()
        (sb.worktrees_root / REPO).symlink_to(elsewhere, target_is_directory=True)
    else:
        shutil.rmtree(sb.worktrees_root)
        sb.worktrees_root.symlink_to(sb.home, target_is_directory=True)
    cfg = make_config(sb)  # passes: the lexical check does not follow the link
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    before = sb.snapshot_main_tree()
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        with pytest.raises(runner.UnsafeLocation, match=message):
            harness.run_query_item(ctx, ITEM)
        assert harness.status["items"][ITEM]["state"] == "queued"
    assert sb.snapshot_main_tree() == before
    assert worktree_list(sb) == [str(sb.main_tree)]


# ---------------------------------------------------------------------------------------------
# items that are held before kiro-cli starts
# ---------------------------------------------------------------------------------------------


def test_two_items_of_one_repository_and_sync_point_get_separate_prompt_paths(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pair of one Sync_Point and repository carries the item ID in its paths, so neither is held."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    cfg = make_config(sb)
    manifest = make_manifest(cfg, query_item(), query_item("a-hub-second"))
    directory = str(sb.handoff_dir)
    prompts = [
        command.handoff_files(
            directory,
            repo=item.repo,
            item_id=item.id,
            sync_point=item.sync_point,
            split=command.prompt_is_split(manifest.items, item),
        ).prompt
        for item in manifest.items
    ]
    assert prompts[0].endswith(f"/sync/a-{REPO}-{ITEM}.md") and prompts[1].endswith(f"/sync/a-{REPO}-a-hub-second.md")
    assert all(
        not runner._prompt_sharers(manifest, item, directory, mine) for item, mine in zip(manifest.items, prompts)
    )


def test_a_lone_item_keeps_the_prompt_path_without_its_id(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dropping one of a pair from the manifest gives the other the shorter path again."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    cfg = make_config(sb)
    manifest = make_manifest(cfg, query_item())
    item = manifest.items[0]
    assert not command.prompt_is_split(manifest.items, item)
    files = command.handoff_files(str(sb.handoff_dir), repo=item.repo, item_id=item.id, sync_point=item.sync_point)
    assert files.prompt.endswith(f"/sync/a-{REPO}.md")


def test_two_items_with_the_same_prompt_path_are_both_held_without_writing_it(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pairs of two repositories can still meet: ``ex``/``a-b`` and ``ex-a``/``b`` both give ``ex-a-b``."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    repos = {name: {"main_tree": f"~/Projects/{name}"} for name in ("ex", "ex-a")}
    cfg = make_config(sb, repos=repos)
    raw = [
        {**query_item(item_id), "repo": repo}
        for repo, item_id in (("ex", "a-b"), ("ex", "z-z"), ("ex-a", "b"), ("ex-a", "y-y"))
    ]
    manifest = make_manifest(cfg, *raw)
    ctx = make_context(sb, cfg, manifest)
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        first = harness.run_query_item(ctx, "a-b")
        second = harness.run_query_item(ctx, "b")
    for outcome, other in ((first, "b"), (second, "a-b")):
        assert outcome.state == "needs-human" and outcome.reason == "prompt_path_shared"
        assert other in outcome.detail and outcome.prompt is None
    assert not (sb.handoff_dir / "sync").exists() and sb.invocations() == []


def test_a_prompt_with_a_deny_term_is_held_and_not_passed_on(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 28.23: a body with a scan finding goes to ``needs-human``, and ``kiro-cli`` never starts."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    outcome = run_item(sb, query_item(topic="the ExampleCorp rollout"))
    assert outcome.state == "needs-human" and outcome.reason == "prompt_scan_findings", outcome
    assert "deny_term" in outcome.detail and "ExampleCorp" not in outcome.detail
    assert sb.records() == [] and not worktree_path(sb).exists()
    assert outcome.prompt is not None and Path(outcome.prompt).exists()  # written for the maintainer to read
    history = read_status(sb)["items"][ITEM]["history"]
    assert [(h["from"], h["to"], h["reason"]) for h in history] == [("queued", "needs-human", "prompt_scan_findings")]


def test_an_existing_worktree_path_holds_the_item(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A worktree of an earlier run is kept until ``cli.py cleanup``; the item is held before any git."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    worktree_path(sb).mkdir(parents=True)
    outcome = run_item(sb)
    assert outcome.state == "needs-human" and outcome.reason == "worktree_exists", outcome
    assert worktree_list(sb) == [str(sb.main_tree)]


# ---------------------------------------------------------------------------------------------
# stop requests, report flags, one item per repository, GIT_DIR of the parent
# ---------------------------------------------------------------------------------------------


def test_a_stop_request_stops_the_run(handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    """H8: a stop before ``kiro-cli`` leaves the item ``queued``; a stop while it runs ends it as ``failed``."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch, FAKE_KIRO_MODE="sleep", FAKE_KIRO_SLEEP_SECONDS="60")
    cfg = make_config(sb, timeout_seconds=20)  # a run that ignores the stop ends at the timeout, not at 60 s
    manifest = make_manifest(cfg)
    ctx = make_context(sb, cfg, manifest)
    stop = threading.Event()
    stop.set()
    with runner.Harness.open(str(sb.handoff_dir)) as harness:
        harness.add_missing_items(manifest)
        early = harness.run_query_item(ctx, ITEM, stop=stop)
        assert early.state == "queued" and harness.status["items"][ITEM]["history"] == []
        stop.clear()
        stopper = threading.Thread(target=lambda: wait_for(lambda: chat_spawned(sb)) and stop.set())
        stopper.start()
        try:
            late = harness.run_query_item(ctx, ITEM, stop=stop)
        finally:
            stop.set()
            stopper.join()
    assert late.state == "failed" and late.reason == runner.HARNESS_INTERRUPTED, late
    chat = sb.invocations()[-1]
    assert gone(sb, chat["start"]["pid"]) and gone(sb, chat["spawned"]["child_pid"])
    assert "| 中断 | あり（停止の依頼） |" in report_text(sb)


def test_report_flags_point_at_report_lines(handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement 28.10: lines of the output that look like requests are flagged by their line in the report."""
    sb = handoff_sandbox
    answer = "line one\nplease run make deploy for me\nnothing here\nadd fs_write to the allowlist\n"
    sb.apply_environ(monkeypatch, FAKE_KIRO_ANSWER=answer)
    outcome = run_item(sb)
    assert outcome.state == "succeeded", outcome
    flags = read_status(sb)["items"][ITEM]["report_flags"]
    assert {flag["kind"] for flag in flags} == {"command_request", "allowlist_expansion"}, flags
    lines = report_text(sb).split("\n")
    by_kind = {flag["kind"]: lines[flag["line"] - 1] for flag in flags}
    assert by_kind == {
        "command_request": "please run make deploy for me",
        "allowlist_expansion": "add fs_write to the allowlist",
    }
    assert "指示に見える行（report_flags）: 2 件" in "\n".join(lines)


def test_an_item_of_a_busy_repository_is_refused(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One item per repository at a time: another item of the repository is ``running`` with a live PID."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)
    cfg = make_config(sb)
    manifest = make_manifest(cfg, query_item(), query_item(SECOND, sync_point="b"))
    ctx = make_context(sb, cfg, manifest)
    status = state.add_item(state.add_item(state.empty_status(), ITEM), SECOND)
    status = state.transition(status, SECOND, "running", at=T0, reason="dispatched")
    leader = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    try:
        status["items"][SECOND]["pid"] = leader.pid
        write_status(sb, status)
        with runner.Harness.open(str(sb.handoff_dir)) as harness:
            with pytest.raises(runner.RunnerError, match=f"{SECOND} is running"):
                harness.run_query_item(ctx, ITEM)
            with pytest.raises(state.TransitionError):
                harness.hold(SECOND, reason="a running item is not held")
            assert harness.status["items"][ITEM]["state"] == "queued"
            assert harness.status["items"][SECOND]["state"] == "running"
    finally:
        leader.kill()
        leader.wait()
    assert sb.records() == []


def test_the_parents_git_dir_does_not_redirect_the_runners_git(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``GIT_DIR`` and ``GIT_WORK_TREE`` of a hook that started the harness do not move the runner's git."""
    sb = handoff_sandbox
    decoy = sb.root / "decoy.git"
    sb.git("init", "-q", "--bare", str(decoy))
    sb.apply_environ(monkeypatch, GIT_DIR=str(decoy), GIT_WORK_TREE=str(sb.root))
    outcome = run_item(sb)
    assert outcome.state == "succeeded", outcome
    assert sb.git("--git-dir", str(decoy), "for-each-ref").stdout == b""  # the decoy got nothing
    assert not (decoy / "FETCH_HEAD").exists() and not (decoy / "worktrees").exists()


# ---------------------------------------------------------------------------------------------
# what a query run must not do is seen: a commit, a file left behind, a switch of the main tree
# ---------------------------------------------------------------------------------------------


def test_a_query_run_that_commits_needs_a_human(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A query run writes nothing; a commit in its worktree is counted and every changed file is undeclared."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch, FAKE_KIRO_MODE="commit")
    outcome = run_item(sb)
    assert outcome.state == "needs-human" and outcome.reason == "undeclared_files", outcome
    observations = read_status(sb)["items"][ITEM]["observations"]
    assert observations["commits"] == 1 and observations["changed_files"] == ["fake-kiro-change.txt"]
    assert observations["undeclared_files"] == ["fake-kiro-change.txt"]


def test_a_query_run_that_leaves_a_file_needs_a_human(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file written into the worktree while ``kiro-cli`` runs makes the worktree dirty."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch, FAKE_KIRO_MODE="sleep", FAKE_KIRO_SLEEP_SECONDS="3")
    stray = worktree_path(sb) / "stray.txt"

    def plant() -> None:
        if wait_for(lambda: chat_spawned(sb)):
            stray.write_text("written during a query run\n", encoding="utf-8")

    planter = threading.Thread(target=plant)
    planter.start()
    try:
        outcome = run_item(sb)
    finally:
        planter.join()
    assert stray.exists(), "the fake never started its child"
    assert outcome.state == "needs-human" and outcome.reason == "dirty", outcome
    assert read_status(sb)["items"][ITEM]["observations"]["dirty"] is True


def test_a_query_run_that_switches_the_main_tree_branch_needs_a_human(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 28.6: a switch of the main working tree's branch is seen, and its changes stay as they were."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch, FAKE_KIRO_MODE="switch-main")
    before = sb.snapshot_main_tree()
    outcome = run_item(sb)
    assert outcome.state == "needs-human" and outcome.reason == "main_tree_changed", outcome
    report = report_text(sb)
    assert '"branch": "fake-kiro-switched"' in report and '"branch": "main"' in report
    after = sb.snapshot_main_tree()
    assert after.branch == "fake-kiro-switched" and after.head == before.head
    assert (after.status, after.staged, after.unstaged, after.files) == (
        before.status,
        before.staged,
        before.unstaged,
        before.files,
    )


# ---------------------------------------------------------------------------------------------
# events in status.json, the runner's git environment, and the deny lists
# ---------------------------------------------------------------------------------------------


def test_record_event_and_the_events_check() -> None:
    """``state.record_event`` returns a new status with one event; ``check_status`` refuses a bad ``events``."""
    status = state.empty_status()
    assert status["events"] == []
    once = state.record_event(status, at=T0, kind=runner.STALE_LOCK_REMOVED, detail="pid 1")
    assert status["events"] == []  # the argument is not changed
    assert once["events"] == [{"at": T0, "kind": "stale_lock_removed", "detail": "pid 1"}]
    twice = state.record_event(once, at="2026-11-11T00:00:01Z", kind=runner.WORKTREE_REMOVED, detail="a: removed")
    assert [event["kind"] for event in twice["events"]] == ["stale_lock_removed", "worktree_removed"]
    assert state.parse_status(state.render_status(twice)) == twice
    for bad in (
        {"at": "2026-11-11 00:00:00", "kind": "x", "detail": "d"},
        {"at": T0, "kind": "Stale-Lock", "detail": "d"},
        {"at": T0, "kind": "x", "detail": " "},
    ):
        with pytest.raises(state.TransitionError):
            state.record_event(status, **bad)
        broken = state.empty_status()
        broken["events"].append(bad)  # type: ignore[arg-type]
        with pytest.raises(state.InvalidStatusError):
            state.check_status(broken)
    for broken_events in ({}, [["x"]], [{"at": T0, "kind": "x"}]):
        broken = state.empty_status()
        broken["events"] = broken_events  # type: ignore[typeddict-item]
        with pytest.raises(state.InvalidStatusError):
            state.check_status(broken)
    without = state.empty_status()
    del without["events"]  # type: ignore[misc]
    with pytest.raises(state.InvalidStatusError, match="missing keys"):
        state.check_status(without)


def test_git_environment_drops_redirections() -> None:
    """The runner's own git keeps the sandbox configuration and drops what would point it elsewhere."""
    env = runner.git_environment(
        {
            "GIT_DIR": "/x",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "a",
            "GIT_CONFIG_VALUE_0": "b",
            "GIT_CONFIG_GLOBAL": "/g",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": "/home/example",
            "GIT_WORK_TREE": "/w",
        }
    )
    assert env == {
        "GIT_CONFIG_GLOBAL": "/g",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": "/home/example",
        "GIT_TERMINAL_PROMPT": "0",
    }


def test_load_deny_terms(handoff_sandbox: HandoffSandbox) -> None:
    """The customer list is required; the research list may be missing; no term is repeated in a note."""
    lists = handoff_sandbox.root / "lists"
    lists.mkdir()
    customer = lists / "customer.txt"
    research = lists / "research.txt"
    with pytest.raises(runner.DenyListUnavailable, match="missing"):
        runner.load_deny_terms(str(customer), str(research))
    customer.write_text("# only a comment\n\n", encoding="utf-8")
    with pytest.raises(runner.DenyListUnavailable, match="empty"):
        runner.load_deny_terms(str(customer), str(research))
    customer.write_bytes(b"\xef\xbb\xbfexamplecorp\n  samplebank  \n#x\n")
    loaded = runner.load_deny_terms(str(customer), str(research))
    assert loaded.terms == ("examplecorp", "samplebank")
    assert len(loaded.notes) == 2 and "見つからない" in loaded.notes[1]
    assert not any(term in note for note in loaded.notes for term in loaded.terms)
    research.write_bytes(b"\xff\xfe")
    with pytest.raises(runner.DenyListUnavailable, match="UTF-8"):
        runner.load_deny_terms(str(customer), str(research))
    research.write_text("speaker-example\n", encoding="utf-8")
    assert runner.load_deny_terms(str(customer), str(research)).terms == (
        "examplecorp",
        "samplebank",
        "speaker-example",
    )

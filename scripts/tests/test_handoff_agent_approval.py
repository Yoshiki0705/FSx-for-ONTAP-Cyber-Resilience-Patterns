"""Tests of the agent approvals of task 2.5: ``agents/approved.json``, the checks before ``--agent``, and the holds.

Everything runs in the ``handoff_sandbox`` of ``conftest.py`` with the fake ``kiro-cli``, through
``cli.main`` in this process. The agent configuration goes to the sandbox's
``~/.kiro/agents/handoff-query.json`` and the approval record to ``agents/approved.json`` of the
sandbox's handoff directory, so nothing reads or writes this machine's ``~/.kiro``. The
configuration has the form of the one that task 2.5 placed, with made-up text.

Rows of task 2.5 (second half) checked here:

1. An approval that matches its file gives the chat of the fake ``kiro-cli`` ``--agent handoff-query``.
2. An approval whose file fails one check (its SHA-256, a symbolic link, a tool above the ceiling in
   ``tools`` or ``allowedTools``, an MCP server, ``includeMcpJson``, another ``name``, no file), an
   approval for another mode, and no approval while ``config.json`` names the agent: the item goes to
   ``needs-human`` (``agent_not_approved``), no ``kiro-cli`` process starts, and standard error names
   the check that failed, and only that one.
3. A malformed approval record ends ``run``, ``plan`` and ``manual`` with exit code 2 before any
   process starts.
4. A configuration of the same name committed to the target repository (by its file name in either
   directory, letter case ignored, or by its ``name`` field alone) holds the item (``agent_shadowed``)
   after the worktree is created: no chat starts and the worktree is kept. One of another name does
   not. The search follows a link only when it stays inside the worktree.
5. ``config.json`` that names no agent for the mode starts the chat without ``--agent``, as before.
6. ``plan`` shows whether ``--agent`` is given and why an item is held, and changes no state.
   ``manual`` notes the hold and still prints the prompt.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import cli, runner, state

if TYPE_CHECKING:
    from conftest import HandoffSandbox

REPO = "example-hub"
QUERY = "a-hub-query"
AGENT = "handoff-query"
OTHER_AGENT = "review-helper"
CUSTOMER_TERMS = ("examplecorp",)
APPROVED_AT = "2026-11-11T16:28:34Z"
WORKTREE_SHOWN = f"~/Projects/.handoff-worktrees/{REPO}/{QUERY}"

QUERY_TEMPLATE = """<!-- The query template of the agent approval tests. -->
<!-- slot: purpose -->
Answer the questions about $topic.

<!-- slot: questions -->
1. What is the first line of `AGENTS.md`?
"""

#: An agent configuration of the form that task 2.5 placed, with made-up text.
AGENT_DOCUMENT: dict[str, Any] = {
    "name": AGENT,
    "description": "Handoff_Harness query mode of the test sandbox: fs_read only",
    "prompt": None,
    "mcpServers": {},
    "tools": ["fs_read"],
    "toolAliases": {},
    "allowedTools": ["fs_read"],
    "resources": [],
    "toolsSettings": {},
    "includeMcpJson": False,
    "model": None,
}

#: The line of ``plan`` for an item that gets ``--agent``.
PLAN_AGENT_GIVEN = (
    f"  エージェント: --agent {AGENT} を付ける（agents/approved.json の承認を検証した）。run は worktree を作った後、"
    ".kiro/agents/ と .amazonq/cli-agents/ に同じ名前の設定があれば起動しない（agent_shadowed）"
)


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------


def query_item(item_id: str = QUERY) -> dict[str, Any]:
    """A query item of the manifest for the sandbox repository."""
    return {
        "id": item_id,
        "repo": REPO,
        "sync_point": "a",
        "mode": "query",
        "template": "templates/query.md",
        "vars": {"topic": "the sandbox repository"},
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


def config_value(**over: Any) -> dict[str, Any]:
    """``config.json`` of the real form for the sandbox, naming the agent for the query mode."""
    value = {
        "schema_version": 1,
        "kiro_cli": "~/.local/bin/kiro-cli",
        "timeout_seconds": 60,
        "max_concurrency": 2,
        "worktrees_root": "~/Projects/.handoff-worktrees",
        "min_free_disk_gb": 1,
        "mode_tool_ceiling": {"query": ["fs_read"], "change": ["fs_read", "fs_write"]},
        "agents": {"query": AGENT},
        "repos": {REPO: {"main_tree": f"~/Projects/{REPO}"}},
    }
    value.update(over)
    return value


def prepare(sb: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, *, config: dict[str, Any] | None = None) -> None:
    """Environment, deny list, template, ``config.json`` and ``manifest.json`` of the sandbox."""
    sb.apply_environ(monkeypatch)
    monkeypatch.delenv("CUSTOMER_TERMS_FILE", raising=False)
    listed = sb.home / ".kiro" / "hooks" / "private"
    listed.mkdir(parents=True)
    (listed / "customer-terms.txt").write_text("# synthetic\n" + "\n".join(CUSTOMER_TERMS) + "\n", encoding="utf-8")
    templates = sb.handoff_dir / "templates"
    templates.mkdir()
    (templates / "query.md").write_text(QUERY_TEMPLATE, encoding="utf-8")
    (sb.handoff_dir / "config.json").write_text(json.dumps(config or config_value()), encoding="utf-8")
    manifest = {"schema_version": 1, "items": [query_item()]}
    (sb.handoff_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def agent_file(sb: HandoffSandbox) -> Path:
    """Where kiro-cli finds the global agent configuration of the sandbox."""
    return sb.home / ".kiro" / "agents" / f"{AGENT}.json"


def agent_bytes(document: dict[str, Any] | None = None) -> bytes:
    """The bytes of an agent configuration, as ``kiro-cli agent create`` lays it out."""
    return (json.dumps(AGENT_DOCUMENT if document is None else document, indent=2) + "\n").encode("utf-8")


def write_agent(sb: HandoffSandbox, document: dict[str, Any] | None = None, *, at: Path | None = None) -> bytes:
    """Write an agent configuration to the global place (or to ``at``); its bytes."""
    data = agent_bytes(document)
    target = agent_file(sb) if at is None else at
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return data


def approval(data: bytes, **over: Any) -> dict[str, Any]:
    """An approval of the agent configuration whose bytes are ``data``, with fields replaced by ``over``."""
    entry = {
        "name": AGENT,
        "mode": "query",
        "path": f"~/.kiro/agents/{AGENT}.json",
        "sha256": hashlib.sha256(data).hexdigest(),
        "approved_at": APPROVED_AT,
        "approved_in": ".private/tasks/phase4/decisions.md",
    }
    entry.update(over)
    return entry


def approvals_file(sb: HandoffSandbox) -> Path:
    """``agents/approved.json`` of the sandbox's handoff directory."""
    return sb.handoff_dir / "agents" / "approved.json"


def write_approvals(sb: HandoffSandbox, *entries: dict[str, Any], data: bytes | None = None) -> None:
    """Write the approval record: the given approvals, or ``data`` as it is."""
    target = approvals_file(sb)
    target.parent.mkdir(exist_ok=True)
    if data is None:
        data = json.dumps({"schema_version": 1, "agents": list(entries)}, indent=2).encode("utf-8")
    target.write_bytes(data)


def call(sb: HandoffSandbox, *argv: str) -> tuple[int, str, str]:
    """``cli.main`` with the sandbox's ``--handoff-dir``; the exit code, standard output and standard error."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(["--handoff-dir", str(sb.handoff_dir), *argv])
    return code, out.getvalue(), err.getvalue()


def chats(sb: HandoffSandbox) -> list[dict[str, Any]]:
    """The ``start`` events of the fake ``kiro-cli``'s chats, in order."""
    return [run["start"] for run in sb.invocations() if run["start"]["subcommand"] == "chat"]


def read_status(sb: HandoffSandbox) -> state.StatusDoc:
    """Read and check ``status.json``."""
    return state.parse_status((sb.handoff_dir / "status.json").read_text(encoding="utf-8"))


def history(sb: HandoffSandbox) -> list[tuple[str, str, str]]:
    """The transitions of the query item: ``(from, to, reason)``."""
    return [(h["from"], h["to"], h["reason"]) for h in read_status(sb)["items"][QUERY]["history"]]


def worktree(sb: HandoffSandbox) -> Path:
    """Where the query item's worktree goes."""
    return sb.worktrees_root / REPO / QUERY


def failed_checks(err: str, mode: str = "query") -> list[str]:
    """The checks that standard error says the approval of the agent for ``mode`` failed, in order."""
    prefix = f"エージェント設定 {AGENT}（{mode}）の承認を使わない: "
    return [line[len(prefix) :].split(":", 1)[0] for line in err.splitlines() if line.startswith(prefix)]


def plan_line(out: str, prefix: str) -> str:
    """The one line of ``plan``'s output that starts with the prefix."""
    [line] = [line for line in out.splitlines() if line.startswith(prefix)]
    return line


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


def commit_to_remote(sb: HandoffSandbox, files: dict[str, str]) -> str:
    """Commit files on a new clone of the sandbox's bare repository and push them to its ``main``; the commit."""
    work = sb.root / "publisher"
    settings = (
        *("-c", f"core.hooksPath={sb.hooks_dir}"),
        *("-c", "user.name=handoff-sandbox"),
        *("-c", "user.email=handoff-sandbox@example.com"),
        *("-c", "commit.gpgSign=false"),
    )
    sb.git("clone", "-q", *settings, str(sb.bare), str(work))
    for relative, text in files.items():
        target = work / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    sb.git("-C", str(work), "add", "--", *files)
    sb.git("-C", str(work), "commit", "-q", "-m", "test: add an agent configuration")
    sb.git("-C", str(work), "push", "-q", "origin", "HEAD:refs/heads/main")
    return sb.git("-C", str(work), "rev-parse", "HEAD").stdout.decode("ascii").strip()


# ---------------------------------------------------------------------------------------------
# 1. an approval that matches its file
# ---------------------------------------------------------------------------------------------


def test_an_approval_that_matches_its_file_gives_the_chat_the_agent(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row 1: the chat gets ``--agent handoff-query`` right after ``--no-interactive``, and the item succeeds."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    write_approvals(sb, approval(write_agent(sb)))
    code, out, err = call(sb, "run", "--items", QUERY)
    assert code == 0, (out, err)
    [chat] = chats(sb)
    assert chat["argv"][1:6] == ["chat", "--no-interactive", "--agent", AGENT, "--trust-tools=fs_read"]
    assert chat["options"]["agent"] == AGENT and chat["cwd"] == str(worktree(sb))
    assert read_status(sb)["items"][QUERY]["state"] == "succeeded"
    assert "エージェント設定" not in err
    report = (sb.handoff_dir / REPO / QUERY / "report.md").read_text(encoding="utf-8")
    assert f'[3] "--agent"\n[4] "{AGENT}"' in report  # the argv of the run is in the Handoff_Report


# ---------------------------------------------------------------------------------------------
# 2. an approval that does not count: the item is held, and no kiro-cli starts
# ---------------------------------------------------------------------------------------------


def _changed_after_the_approval(sb: HandoffSandbox) -> None:
    write_approvals(sb, approval(write_agent(sb)))
    write_agent(sb, {**AGENT_DOCUMENT, "description": "changed after the approval"})


def _a_symbolic_link(sb: HandoffSandbox) -> None:
    elsewhere = sb.root / "elsewhere" / f"{AGENT}.json"
    data = write_agent(sb, at=elsewhere)
    agent_file(sb).parent.mkdir(parents=True)
    agent_file(sb).symlink_to(elsewhere)
    write_approvals(sb, approval(data))


def _approved_as_written(**over: Any) -> Callable[[HandoffSandbox], None]:
    """A file with ``over`` in its content, approved with its own SHA-256: only the content check can fail."""

    def setup(sb: HandoffSandbox) -> None:
        write_approvals(sb, approval(write_agent(sb, {**AGENT_DOCUMENT, **over})))

    return setup


def _no_file(sb: HandoffSandbox) -> None:
    write_approvals(sb, approval(agent_bytes()))


def _for_another_mode(sb: HandoffSandbox) -> None:
    write_approvals(sb, approval(write_agent(sb), mode="change"))


def _no_record(sb: HandoffSandbox) -> None:
    write_agent(sb)


def _an_empty_record(sb: HandoffSandbox) -> None:
    write_agent(sb)
    write_approvals(sb)


NOT_APPROVED: dict[str, tuple[Callable[[HandoffSandbox], None], str | None, dict[str, Any]]] = {
    # case: (setup, the one check that fails or None, config.json overrides)
    "sha256-differs": (_changed_after_the_approval, "sha256", {}),
    "a-symbolic-link": (_a_symbolic_link, "symlink", {}),
    "tools-above-the-ceiling": (_approved_as_written(tools=["fs_read", "fs_write"]), "tools", {}),
    "allowed-tools-above-the-ceiling": (_approved_as_written(allowedTools=["fs_read", "fs_write"]), "allowedTools", {}),
    "an-mcp-server": (
        _approved_as_written(mcpServers={"example-server": {"command": "example-server"}}),
        "mcpServers",
        {},
    ),
    "include-mcp-json": (_approved_as_written(includeMcpJson=True), "includeMcpJson", {}),
    "another-name": (_approved_as_written(name=OTHER_AGENT), "name", {}),
    "no-file": (_no_file, "lstat", {}),
    # the agent is named for both modes and approved for the change mode only
    "approved-for-another-mode": (_for_another_mode, None, {"agents": {"query": AGENT, "change": AGENT}}),
    "no-record": (_no_record, None, {}),
    "an-empty-record": (_an_empty_record, None, {}),
}


@pytest.mark.parametrize("case", NOT_APPROVED)
def test_an_approval_that_does_not_count_holds_the_item_before_any_kiro_cli(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """Row 2: ``needs-human`` (``agent_not_approved``) in one step, no kiro-cli process, no worktree."""
    sb = handoff_sandbox
    setup, check, over = NOT_APPROVED[case]
    prepare(sb, monkeypatch, config=config_value(**over))
    setup(sb)
    code, out, err = call(sb, "run", "--items", QUERY)
    assert code == 1, (out, err)
    assert history(sb) == [("queued", "needs-human", "agent_not_approved")]
    assert sb.records() == []  # neither whoami nor chat: the item is not started with the default agent
    assert not worktree(sb).exists()
    assert f"{QUERY}: needs-human（agent_not_approved）" in out
    if check is not None:
        assert failed_checks(err) == [check], err
    else:
        assert failed_checks(err) == []
        missing = f"エージェント設定 {AGENT}（query）は承認されていない: agents/approved.json に {AGENT} の query の承認がない"
        assert missing in err, err
        if case == "approved-for-another-mode":
            assert "（change の承認はあるが、" in err and failed_checks(err, "change") == []


# ---------------------------------------------------------------------------------------------
# 3. a malformed approval record: exit code 2 before any process
# ---------------------------------------------------------------------------------------------


def _record(*entries: Any, **top: Any) -> bytes:
    """An approval record with the given entries; ``top`` replaces or adds top-level keys."""
    return json.dumps({"schema_version": 1, "agents": list(entries), **top}).encode("utf-8")


def _malformed() -> dict[str, tuple[bytes, str]]:
    """Malformed approval records, and what standard error must say about each."""
    good = approval(agent_bytes())
    other = {**good, "name": OTHER_AGENT, "path": f"~/.kiro/agents/{OTHER_AGENT}.json"}
    lacking = {key: value for key, value in good.items() if key != "approved_in"}
    return {
        "not-json": (b'{"schema_version": 1,', "is not valid JSON"),
        "repeated-key": (b'{"schema_version": 1, "agents": [], "agents": []}', "appears more than once"),
        "nan": (b'{"schema_version": NaN, "agents": []}', "NaN is not a JSON value"),
        "not-utf-8": (b'{"schema_version": 1, "agents": [], "note": "\xff"}', "is not valid JSON"),
        "not-an-object": (b"[]", "$: must be an object, got list"),
        "schema-version-2": (_record(good, schema_version=2), "$.schema_version: must be 1, got 2"),
        "schema-version-true": (_record(good, schema_version=True), "$.schema_version: must be 1, got True"),
        "an-unknown-top-key": (_record(good, note="x"), "$: unknown key 'note'"),
        "no-agents": (json.dumps({"schema_version": 1}).encode("utf-8"), "$.agents: missing"),
        "agents-not-a-list": (_record(agents=good), "$.agents: must be a list, got dict"),
        "an-entry-not-an-object": (_record(AGENT), "$.agents[0]: must be an object, got str"),
        "an-unknown-entry-key": (_record({**good, "note": "x"}), "$.agents[0]: unknown key 'note'"),
        "a-missing-entry-key": (_record(lacking), "$.agents[0].approved_in: missing"),
        "a-name-with-a-slash": (
            _record({**good, "name": f"../{AGENT}", "path": f"~/.kiro/agents/../{AGENT}.json"}),
            "$.agents[0].name: must be of the form",
        ),
        "a-name-with-a-space": (_record({**good, "name": "handoff query"}), "$.agents[0].name: must be of the form"),
        "an-unknown-mode": (_record({**good, "mode": "publish"}), "$.agents[0].mode: must be one of query, change"),
        "a-path-elsewhere": (
            _record({**good, "path": f"~/.kiro/agents/{OTHER_AGENT}.json"}),
            f"$.agents[0].path: must be exactly ~/.kiro/agents/{AGENT}.json",
        ),
        "an-absolute-path": (
            _record({**good, "path": f"/home/example/.kiro/agents/{AGENT}.json"}),
            f"$.agents[0].path: must be exactly ~/.kiro/agents/{AGENT}.json",
        ),
        "an-uppercase-sha256": (
            _record({**good, "sha256": good["sha256"].upper()}),
            "$.agents[0].sha256: must be 64 lowercase hexadecimal digits",
        ),
        "a-short-sha256": (
            _record({**good, "sha256": good["sha256"][:-1]}),
            "$.agents[0].sha256: must be 64 lowercase hexadecimal digits",
        ),
        "approved-at-with-an-offset": (
            _record({**good, "approved_at": "2026-11-11T16:28:34+00:00"}),
            "$.agents[0].approved_at: must be a moment",
        ),
        "approved-at-not-a-day": (
            _record({**good, "approved_at": "2026-02-30T00:00:00Z"}),
            "$.agents[0].approved_at: must be a moment",
        ),
        "approved-in-blank": (_record({**good, "approved_in": "  "}), "$.agents[0].approved_in: must be a string"),
        "a-name-twice": (
            _record(good, {**good, "mode": "change"}),
            f"$.agents[1].name: '{AGENT}' is also the name of $.agents[0]",
        ),
        "a-mode-twice": (_record(good, other), "$.agents[1].mode: 'query' is also the mode of $.agents[0]"),
    }


MALFORMED = _malformed()


def assert_nothing_started(sb: HandoffSandbox, spy: PopenSpy) -> None:
    """No process, no status, no lock, no prompt, no worktree."""
    assert spy.calls == [] and sb.records() == []
    assert not (sb.handoff_dir / "status.json").exists() and not (sb.handoff_dir / ".lock").exists()
    assert not (sb.handoff_dir / "sync").exists() and not worktree(sb).exists()


@pytest.mark.parametrize("case", MALFORMED)
def test_a_malformed_approval_record_ends_run_with_2_before_any_process(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """Row 3: each form problem of ``agents/approved.json`` ends ``run`` with exit code 2, and nothing starts."""
    sb = handoff_sandbox
    data, message = MALFORMED[case]
    prepare(sb, monkeypatch)
    write_agent(sb)
    write_approvals(sb, data=data)
    spy = PopenSpy(monkeypatch)
    code, out, err = call(sb, "run", "--items", QUERY)
    assert code == 2, (out, err)
    assert out == "" and str(approvals_file(sb)) in err and message in err, err
    assert_nothing_started(sb, spy)


@pytest.mark.parametrize("argv", [("plan", "--items", QUERY), ("manual", QUERY)], ids=["plan", "manual"])
def test_a_malformed_approval_record_ends_plan_and_manual_with_2(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, argv: tuple[str, ...]
) -> None:
    """Row 3 for the other two commands that read the record; ``status`` does not read it."""
    sb = handoff_sandbox
    data, message = MALFORMED["an-unknown-entry-key"]
    prepare(sb, monkeypatch)
    write_agent(sb)
    write_approvals(sb, data=data)
    spy = PopenSpy(monkeypatch)
    code, out, err = call(sb, *argv)
    assert code == 2, (out, err)
    assert out == "" and message in err, err
    assert_nothing_started(sb, spy)
    code, out, err = call(sb, "status")
    assert code == 0, (out, err)


# ---------------------------------------------------------------------------------------------
# 4. a configuration of the same name in the worktree
# ---------------------------------------------------------------------------------------------

#: case: (the committed file, its ``name`` field, whether it holds the item)
SAME_NAME: dict[str, tuple[str, str, bool]] = {
    "by-the-file-name": (f".kiro/agents/{AGENT}.json", AGENT, True),
    "by-the-name-field-only": (f".kiro/agents/{OTHER_AGENT}.json", AGENT, True),
    "by-the-name-field-in-another-case": (f".kiro/agents/{OTHER_AGENT}.json", AGENT.upper(), True),
    "by-the-file-name-in-another-case-in-the-older-directory": (
        ".amazonq/cli-agents/Handoff-Query.json",
        OTHER_AGENT,
        True,
    ),
    "another-agent": (f".kiro/agents/{OTHER_AGENT}.json", OTHER_AGENT, False),
}


@pytest.mark.parametrize("case", SAME_NAME)
def test_a_configuration_of_the_same_name_in_the_target_repository_holds_the_item(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """Row 4: committed to ``origin/main``, it is in the new worktree; the item is held there and the worktree kept."""
    sb = handoff_sandbox
    relative, name, held = SAME_NAME[case]
    prepare(sb, monkeypatch)
    write_approvals(sb, approval(write_agent(sb)))
    document = {**AGENT_DOCUMENT, "name": name, "description": "An agent of the target repository"}
    head = commit_to_remote(sb, {relative: json.dumps(document, indent=2) + "\n"})
    code, out, err = call(sb, "run", "--items", QUERY)
    tree = worktree(sb)
    assert (tree / relative).is_file(), (out, err)  # the worktree was made from the new origin/main
    assert sb.git("-C", str(tree), "rev-parse", "HEAD").stdout.decode("ascii").strip() == head
    if not held:
        assert code == 0, (out, err)
        [chat] = chats(sb)
        assert chat["options"]["agent"] == AGENT
        return
    assert code == 1, (out, err)
    assert chats(sb) == [] and [run["start"]["subcommand"] for run in sb.invocations()] == ["whoami"]
    assert history(sb) == [("queued", "needs-human", "agent_shadowed")]
    record = read_status(sb)["items"][QUERY]
    assert record["worktree"] == WORKTREE_SHOWN and record["base_sha"] == head
    assert f"{QUERY}: needs-human（agent_shadowed） worktree: {WORKTREE_SHOWN}" in out
    assert f"{relative}: its " in err, err
    listed = sb.git("-C", str(sb.main_tree), "worktree", "list", "--porcelain").stdout.decode()
    assert f"worktree {tree}\n" in listed


#: The document outside the worktree that a link points to: it would match if it were read.
OUTSIDE_DOCUMENT = json.dumps({**AGENT_DOCUMENT, "name": AGENT})


def _layout(tree: Path, outside: Path, case: str) -> None:
    """Build one layout of the search test below the worktree ``tree``."""
    agents = tree / ".kiro" / "agents"
    (outside / "kiro" / "agents").mkdir(parents=True)
    (outside / "agent.json").write_text(OUTSIDE_DOCUMENT, encoding="utf-8")
    (outside / "kiro" / "agents" / f"{AGENT}.json").write_text(OUTSIDE_DOCUMENT, encoding="utf-8")
    (tree / "docs").mkdir(parents=True)
    (tree / "docs" / "agent.json").write_text(OUTSIDE_DOCUMENT, encoding="utf-8")
    (tree / "docs" / "other.json").write_text(json.dumps({"name": OTHER_AGENT}), encoding="utf-8")
    if case == "a-directory-that-links-outside":
        (tree / ".kiro").symlink_to(outside / "kiro")
        return
    agents.mkdir(parents=True)
    if case == "an-entry-that-links-outside":
        (agents / f"{OTHER_AGENT}.json").symlink_to(outside / "agent.json")
    elif case == "an-entry-that-links-inside":
        (agents / f"{OTHER_AGENT}.json").symlink_to(Path("..") / ".." / "docs" / "agent.json")
    elif case == "an-entry-that-links-inside-to-another-name":
        (agents / f"{OTHER_AGENT}.json").symlink_to(Path("..") / ".." / "docs" / "other.json")
    elif case == "a-json-file-that-is-not-json":
        (agents / "broken.json").write_text("{not json", encoding="utf-8")
    elif case == "another-file-that-is-not-json":
        (agents / "notes.md").write_text("# Notes\n", encoding="utf-8")
    elif case == "the-file-name-with-another-suffix":
        (agents / "HANDOFF-QUERY.yaml").write_text("name: other\n", encoding="utf-8")


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("a-directory-that-links-outside", [".kiro/agents resolves outside the worktree, to "]),
        (
            "an-entry-that-links-outside",
            [f".kiro/agents/{OTHER_AGENT}.json resolves outside the worktree, and its name field is not read"],
        ),
        ("an-entry-that-links-inside", [f".kiro/agents/{OTHER_AGENT}.json: its name field matches {AGENT}"]),
        ("an-entry-that-links-inside-to-another-name", []),
        ("a-json-file-that-is-not-json", [".kiro/agents/broken.json is not UTF-8 JSON, so its name field is unknown"]),
        ("another-file-that-is-not-json", []),
        ("the-file-name-with-another-suffix", [f".kiro/agents/HANDOFF-QUERY.yaml: its file name matches {AGENT}"]),
    ],
)
def test_the_search_follows_a_link_only_inside_the_worktree(tmp_path: Path, case: str, expected: list[str]) -> None:
    """Row 4: what resolves outside the worktree counts unread; a link inside is followed; unreadable JSON counts."""
    tree, outside = tmp_path / "worktree", tmp_path / "outside"
    _layout(tree, outside, case)
    found = runner._agent_shadows(str(tree), AGENT)
    assert len(found) == len(expected) and all(line.startswith(want) for line, want in zip(found, expected)), found


# ---------------------------------------------------------------------------------------------
# 5. no agent named for the mode
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("recorded", [True, False], ids=["with-an-approval", "without-a-record"])
def test_a_mode_that_names_no_agent_starts_without_agent(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, recorded: bool
) -> None:
    """Row 5: ``agents`` of ``{}`` starts the chat without ``--agent``, also when an approval exists for the agent."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch, config=config_value(agents={}))
    data = write_agent(sb)
    if recorded:
        write_approvals(sb, approval(data))
    code, out, err = call(sb, "run", "--items", QUERY)
    assert code == 0, (out, err)
    [chat] = chats(sb)
    assert chat["argv"][1:4] == ["chat", "--no-interactive", "--trust-tools=fs_read"]
    assert "--agent" not in chat["argv"] and chat["options"]["agent"] is None
    assert read_status(sb)["items"][QUERY]["state"] == "succeeded"
    assert "エージェント設定" not in err


# ---------------------------------------------------------------------------------------------
# 6. plan and manual
# ---------------------------------------------------------------------------------------------


def test_plan_shows_the_agent_and_the_hold_and_changes_no_state(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row 6: ``--agent`` given, held for the agent, and no agent named; no state, no kiro-cli, inputs unchanged."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    write_approvals(sb, approval(write_agent(sb)))

    code, out, err = call(sb, "plan", "--items", QUERY)
    assert code == 0, (out, err)
    assert plan_line(out, "  エージェント: ") == PLAN_AGENT_GIVEN
    assert plan_line(out, "  run の扱い: ") == "  run の扱い: 起動する（1 番目）"
    assert "エージェント設定" not in err

    write_agent(sb, {**AGENT_DOCUMENT, "description": "changed after the approval"})
    code, out, err = call(sb, "plan", "--items", QUERY)
    assert code == 0, (out, err)
    assert plan_line(out, "  エージェント: ") == (
        f"  エージェント: {AGENT} は query で承認されていない。--agent なしでは起動しない（agent_not_approved）"
    )
    assert plan_line(out, "  run の扱い: ").startswith("  run の扱い: needs-human にする（agent_not_approved）。")
    assert failed_checks(err) == ["sha256"], err

    (sb.handoff_dir / "config.json").write_text(json.dumps(config_value(agents={})), encoding="utf-8")
    code, out, err = call(sb, "plan", "--items", QUERY)
    assert code == 0, (out, err)
    assert (
        plan_line(out, "  エージェント: ")
        == "  エージェント: --agent を付けない（config.json の agents に query の指定がない）"
    )
    assert plan_line(out, "  run の扱い: ") == "  run の扱い: 起動する（1 番目）"

    saved = {path: path.read_bytes() for path in (agent_file(sb), approvals_file(sb), sb.handoff_dir / "config.json")}
    code, out, err = call(sb, "plan", "--items", QUERY)
    assert code == 0, (out, err)
    assert {path: path.read_bytes() for path in saved} == saved
    assert not (sb.handoff_dir / "status.json").exists() and not (sb.handoff_dir / ".lock").exists()
    assert sb.records() == [] and not worktree(sb).exists()


def test_manual_notes_the_hold_and_still_prints_the_prompt(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The manual display does not use ``--agent``: it is printed, with a note that ``run`` would hold the item."""
    sb = handoff_sandbox
    prepare(sb, monkeypatch)
    write_agent(sb)  # no approval record
    code, out, err = call(sb, "manual", QUERY)
    assert code == 0, (out, err)
    assert f"手作業の引き継ぎ: {QUERY}" in out and "----- ここから -----\n" in out
    assert f"{QUERY}: 注意: config.json の agents.query のエージェント設定 {AGENT} は承認されていない。" in err
    assert "needs-human（agent_not_approved）にする" in err
    assert not (sb.handoff_dir / "status.json").exists() and sb.records() == []

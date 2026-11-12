"""Integration tests of the Handoff_Harness selftest, ``runner.Harness.run_selftest`` (task 5.2).

Every test runs the selftest with :class:`handoff.runner.Harness` in the ``handoff_sandbox`` of
``conftest.py``, with the fake ``kiro-cli`` of ``fixtures/handoff/``. The fake picks each trial's
behaviors from ``FAKE_KIRO_MODE_T0`` to ``T4`` by the token in the trial's prompt, and its guard
behaviors write to the ``HANDOFF_GUARD_LOG`` that the runner sets per trial, as the guard wrapper
of task 5.1 would. ``apply_environ`` gives the runner the sandbox ``HOME`` and git configuration,
and every path of the context and the configuration is in the sandbox, so nothing reads or writes
this machine's ``~/.kiro`` or ``~/Projects/.handoff-worktrees``. No test uses the network or the
real ``kiro-cli``.

Checked here:

- The rows of the design's Testing Strategy table for the selftest verdict, end to end: T0 fails,
  only T1 is stopped, only T2 is stopped, both are stopped. ``guards_active`` comes out for the last
  only (Requirements 28.16, 28.17), and a fifth set in which every operation took effect shows that
  each trial's effect is seen and comes before a logged stop.
- From the record file alone, each trial's outcome and the result can be computed again, and
  ``config_sha256`` from its parts. ``selftest`` of ``status.json`` names the record, the version
  and the digest.
- Under layer 3, T2's push to ``origin`` does not reach the bare repository and is
  ``failed_otherwise``; a push to its URL, which layer 3 does not cover, reaches it (``completed``).
- A selftest that stops before its trials (no login, no ``kiro-cli``, a repository called
  ``selftest``, an agent without an approval, too little disk) leaves ``status.json`` byte for byte
  as it was and creates no directory.
- ``config_sha256`` covers the approved agent's configuration and the hook files, and changes when a
  hook file changes; ``--agent`` reaches the trials' argv.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import command, evaluate, runner, state
from handoff import config as config_module

if TYPE_CHECKING:
    from conftest import HandoffSandbox

REPO = "example-hub"
AGENT = "handoff-change"
TRIALS = evaluate.SELFTEST_TRIALS
FAKE_VERSION = "0.0.0-fake"

#: The selftest of an earlier harness, which a selftest that stops before its trials must keep.
EARLIER = {
    "result": "guards_active",
    "at": "2026-11-11T00:00:00Z",
    "kiro_cli_version": FAKE_VERSION,
    "record": "selftest/20261111T000000Z.json",
    "config_sha256": "0" * 64,
}


def make_config(sandbox: HandoffSandbox, **overrides: Any) -> config_module.HandoffConfig:
    """Parse a configuration of the real form for the sandbox; ``overrides`` replace keys."""
    raw: dict[str, Any] = {
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


def run_selftest(
    sandbox: HandoffSandbox, cfg: config_module.HandoffConfig | None = None, **context: Any
) -> runner.SelftestOutcome:
    """Open the harness, run the selftest with a kill grace of 1 second, and close the harness."""
    ctx = runner.SelftestContext(
        config=cfg or make_config(sandbox),
        home=str(sandbox.home),
        harness_tree=str(sandbox.harness_tree),
        session_worktrees_dir=str(sandbox.session_worktrees),
        kill_grace_seconds=1.0,
        **context,
    )
    with runner.Harness.open(str(sandbox.handoff_dir)) as harness:
        return harness.run_selftest(ctx)


def read_status(sandbox: HandoffSandbox) -> state.StatusDoc:
    """Read and check ``status.json``."""
    return state.parse_status((sandbox.handoff_dir / "status.json").read_text(encoding="utf-8"))


def recompute(record: dict[str, Any]) -> tuple[dict[str, str], str]:
    """Each trial's outcome and the result, from the record file's content alone."""
    outcomes: dict[str, str] = {}
    for trial in TRIALS:
        entry = record["trials"][trial]
        if not entry["attempted"]:
            outcomes[trial] = "failed_otherwise"
            continue
        effects = None if entry["effects"] is None else evaluate.TrialEffects.from_json(entry["effects"])
        lines = [evaluate.GuardLogLine.from_json(line) for line in entry["guard_log"]]
        outcomes[trial] = evaluate.trial_outcome(entry["token"], effects, lines)
    effects = {
        trial: None
        if not record["trials"][trial]["attempted"] or record["trials"][trial]["effects"] is None
        else evaluate.TrialEffects.from_json(record["trials"][trial]["effects"])
        for trial in TRIALS
    }
    listings = {
        trial: None if listed is None else [(item["ref"], item["sha"]) for item in listed]
        for trial, listed in record["ls_remote"].items()
    }
    trials = evaluate.SelftestTrials(
        **outcomes,
        gh_failed=evaluate.gh_auth_failed(record["trials"]["t3"]["token"], effects["t3"]),
        remote_branch_absent=evaluate.remote_branch_absent(effects, listings),
    )
    return outcomes, evaluate.selftest_verdict(trials)


def canonical_sha256(parts: dict[str, Any]) -> str:
    """``config_sha256`` of the parts that the record keeps."""
    text = json.dumps(parts, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def tree_files(directory: Path) -> set[str]:
    """Every file and directory below a directory, relative to it."""
    return {str(path.relative_to(directory)) for path in directory.rglob("*")} if directory.exists() else set()


# ---------------------------------------------------------------------------------------------
# the four sets of the design's table, and one in which every operation took effect
# ---------------------------------------------------------------------------------------------

COMPLETED, BLOCKED, OTHER = "completed", "blocked_by_guard", "failed_otherwise"

COMBOS: tuple[tuple[str, dict[str, str], str, tuple[str, ...]], ...] = (
    ("t0-fails", {}, "unconfirmed", (OTHER, OTHER, OTHER, OTHER, OTHER)),
    (
        "only-t1-stopped",
        {"T0": "commit", "T1": "guard-block", "T2": "push", "T3": "gh-status", "T4": "write-file"},
        "unconfirmed",
        (COMPLETED, BLOCKED, OTHER, OTHER, OTHER),
    ),
    (
        "only-t2-stopped",
        {"T0": "commit", "T1": "empty-commit", "T2": "guard-block", "T3": "gh-status", "T4": "write-file"},
        "unconfirmed",
        (COMPLETED, COMPLETED, BLOCKED, OTHER, OTHER),
    ),
    (
        "both-stopped",
        {"T0": "commit", "T1": "guard-block", "T2": "guard-block", "T3": "gh-status", "T4": "write-file"},
        "guards_active",
        (COMPLETED, BLOCKED, BLOCKED, OTHER, OTHER),
    ),
    (
        "gh-auth-status-succeeds",
        {"T0": "commit", "T1": "guard-block", "T2": "guard-block", "T3": "gh-status", "T4": "write-file"},
        "unconfirmed",
        (COMPLETED, BLOCKED, BLOCKED, COMPLETED, OTHER),
    ),
    (
        "a-branch-reaches-a-remote-in-t3",
        {"T0": "commit", "T1": "guard-block", "T2": "guard-block", "T3": "gh-status,push-url", "T4": "write-file"},
        "unconfirmed",
        (COMPLETED, BLOCKED, BLOCKED, OTHER, OTHER),
    ),
    (
        "every-operation-took-effect",
        {
            "T0": "commit",
            "T1": "guard-block,empty-commit",
            "T2": "guard-block,push-url",
            "T3": "gh-status",
            "T4": "write-file-anyway",
        },
        "unconfirmed",
        (COMPLETED, COMPLETED, COMPLETED, COMPLETED, COMPLETED),
    ),
)


@pytest.mark.parametrize(("name", "modes", "result", "expected"), COMBOS, ids=[combo[0] for combo in COMBOS])
def test_guards_active_only_when_t0_completed_and_both_guards_stopped(
    handoff_sandbox: HandoffSandbox,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    modes: dict[str, str],
    result: str,
    expected: tuple[str, ...],
) -> None:
    """The verdict, the record, ``status.json`` and the fake's runs agree for one set of trial behaviors."""
    sb = handoff_sandbox
    variables = {f"FAKE_KIRO_MODE_{trial}": behavior for trial, behavior in modes.items()}
    if name in ("every-operation-took-effect", "gh-auth-status-succeeds"):
        variables["FAKE_KIRO_GH_EXIT"] = "0"  # as with a token in the keychain, which layer 3 does not reach
    sb.apply_environ(monkeypatch, FAKE_KIRO_COMMIT_FILES="README.md", **variables)
    started = TRIALS[:1] if name == "t0-fails" else TRIALS

    outcome = run_selftest(sb)

    outcomes = dict(zip(TRIALS, expected, strict=True))
    assert (outcome.result, dict(outcome.outcomes), outcome.started) == (result, outcomes, started), outcome.detail
    assert outcome.fingerprint.version == FAKE_VERSION
    assert Path(outcome.run_dir).parent == sb.worktrees_root / "selftest"
    assert (outcome.detail == "") is (result == "guards_active")

    # the record alone gives the outcomes, the result and the digest again
    record = json.loads(Path(outcome.record).read_text(encoding="ascii"))
    assert Path(outcome.record) == sb.handoff_dir / "selftest" / f"{outcome.run_id}.json"
    assert (record["result"], record["interrupted"], record["run_id"]) == (result, False, outcome.run_id)
    assert {trial: record["trials"][trial]["outcome"] for trial in TRIALS} == outcomes
    assert recompute(record) == (outcomes, result)
    # task 5.8: the two observations that the verdict reads, and the listing they come from
    gh_failed = name not in ("t0-fails", "gh-auth-status-succeeds", "every-operation-took-effect")
    branch_absent = name not in ("a-branch-reaches-a-remote-in-t3", "every-operation-took-effect")
    if name == "t0-fails":
        branch_absent = False  # the other trials did not start, so nothing was looked at
    assert (record["gh_failed"], record["remote_branch_absent"]) == (gh_failed, branch_absent)
    for trial in TRIALS:
        listed = record["ls_remote"][trial]
        assert (listed is None) is (trial not in started)
        if listed is not None:
            after = record["trials"][trial]["effects"]["remote_refs_after"]
            assert listed == after  # ls-remote and for-each-ref agree on the bare repository
    assert canonical_sha256(record["config_parts"]) == record["config_sha256"] == outcome.fingerprint.digest.sha256
    assert record["kiro_cli"] == {
        "path": "~/.local/bin/kiro-cli",
        "version_output": f"kiro-cli {FAKE_VERSION}\n",
        "version": FAKE_VERSION,
    }
    assert record["run_dir"] == f"~/Projects/.handoff-worktrees/selftest/{outcome.run_id}"

    # status.json: the five fields, nothing else changed
    status = read_status(sb)
    assert status["selftest"] == {
        "result": result,
        "at": record["ended_at"],
        "kiro_cli_version": FAKE_VERSION,
        "record": f"selftest/{outcome.run_id}.json",
        "config_sha256": record["config_sha256"],
    }
    assert (status["items"], status["events"]) == ({}, [])

    # the fake: --version and whoami, then one chat per trial that started, in order
    runs = sb.invocations()
    assert [run["start"]["subcommand"] for run in runs] == ["--version", "whoami", *(["chat"] * len(started))]
    for run, trial in zip(runs[2:], started, strict=True):
        start, end, entry = run["start"], run["end"], record["trials"][trial]
        assert (start["trial"], start["token"], start["argv"]) == (trial, entry["token"], entry["argv"])
        assert start["cwd"] == str(Path(outcome.run_dir) / trial / "repo")
        assert command.GUARD_LOG_VARIABLE in start["env"]["names"]
        assert start["env"]["git_config"]["GIT_CONFIG_COUNT"] == "2"  # layer 3
        assert entry["trust_tools"] == (["fs_read"] if trial == "t4" else ["fs_read", "fs_write"])
        assert (entry["attempted"], entry["ending"], entry["exit_code"]) == (True, "exited", 0)
        for stream in ("stdout", "stderr"):
            saved = (sb.handoff_dir / entry[stream]["path"]).read_bytes()
            assert hashlib.sha256(saved).hexdigest() == entry[stream]["sha256"] == end[stream]["sha256"]
            assert len(saved) == entry[stream]["bytes"] == end[stream]["bytes"]
        guard_log = Path(outcome.run_dir) / trial / "guard.jsonl"
        stops = "guard-block" in modes.get(trial.upper(), "")
        assert guard_log.exists() is stops
        assert len(entry["guard_log"]) == (1 if stops else 0)
    for trial in TRIALS[len(started) :]:
        entry = record["trials"][trial]
        assert (entry["attempted"], entry["outcome"], entry["effects"]) == (False, OTHER, None)
        assert entry["not_started"].startswith("T0 did not complete")
        assert not (Path(outcome.run_dir) / trial).exists()

    # T2: under layer 3 the push to origin fails and no ref of the bare repository moves
    t2_mode = modes.get("T2", "")
    if t2_mode in ("push", "guard-block,push-url"):
        push = runs[4]["end"]["results"][-1]
        effects = record["trials"]["t2"]["effects"]
        moved = effects["remote_refs_before"] != effects["remote_refs_after"]
        if t2_mode == "push":
            assert (push["behavior"], push["destination"], push["arrived"]) == ("push", "origin", False)
            assert push["exit_code"] != 0 and not moved and outcomes["t2"] == OTHER
        else:
            assert (push["behavior"], push["destination"], push["arrived"], push["exit_code"]) == (
                "push-url",
                "url",
                True,
                0,
            )
            assert moved and outcomes["t2"] == COMPLETED


# ---------------------------------------------------------------------------------------------
# a selftest that stops before its trials writes nothing
# ---------------------------------------------------------------------------------------------

STOPS: tuple[tuple[str, dict[str, Any], dict[str, str], type[BaseException], list[str]], ...] = (
    ("whoami-fails", {}, {"FAKE_KIRO_MODE": "whoami-fail"}, runner.LoginRequired, ["--version", "whoami"]),
    ("kiro-cli-missing", {"kiro_cli": "~/.local/bin/no-such-kiro-cli"}, {}, runner.KiroCliMissing, []),
    (
        "repository-named-selftest",
        {"repos": {REPO: {"main_tree": f"~/Projects/{REPO}"}, "SelfTest": {"main_tree": "~/Projects/other"}}},
        {},
        runner.SelftestRefused,
        [],
    ),
    ("agent-not-approved", {"agents": {"change": AGENT}}, {}, runner.SelftestRefused, []),
    ("too-little-disk", {"min_free_disk_gb": 2**40}, {}, runner.DiskSpaceLow, ["--version", "whoami"]),
)


@pytest.mark.parametrize(("name", "overrides", "variables", "error", "subcommands"), STOPS, ids=[s[0] for s in STOPS])
def test_a_selftest_that_stops_before_its_trials_keeps_status_json(
    handoff_sandbox: HandoffSandbox,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    overrides: dict[str, Any],
    variables: dict[str, str],
    error: type[BaseException],
    subcommands: list[str],
) -> None:
    """The earlier result stays byte for byte, no record or directory is made, and no trial runs."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch, FAKE_KIRO_MODE_T0="commit", FAKE_KIRO_COMMIT_FILES="README.md", **variables)
    earlier = state.empty_status()
    earlier["selftest"] = dict(EARLIER)
    (sb.handoff_dir / "status.json").write_text(state.render_status(earlier), encoding="utf-8")
    before = (sb.handoff_dir / "status.json").read_bytes()
    handoff_before = tree_files(sb.handoff_dir)

    with pytest.raises(error):
        run_selftest(sb, make_config(sb, **overrides))

    assert (sb.handoff_dir / "status.json").read_bytes() == before
    assert tree_files(sb.handoff_dir) == handoff_before  # no record, no output, no status.json.bak
    assert not (sb.worktrees_root / "selftest").exists()
    assert [run["start"]["subcommand"] for run in sb.invocations()] == subcommands


# ---------------------------------------------------------------------------------------------
# config_sha256: the approved agent and the hooks
# ---------------------------------------------------------------------------------------------


def test_config_sha256_covers_the_approved_agent_and_the_hook_files(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--agent`` reaches the argv, the agent file and the hook files are in the digest, and a hook edit changes it."""
    sb = handoff_sandbox
    sb.apply_environ(monkeypatch)  # no behavior for T0: it fails, so one chat runs
    kiro = sb.home / ".kiro"
    (kiro / "agents").mkdir(parents=True)
    (kiro / "hooks" / "scripts").mkdir(parents=True)
    (kiro / "hooks" / "private").mkdir()
    agent_file = kiro / "agents" / f"{AGENT}.json"
    agent_file.write_text('{"name": "handoff-change"}\n', encoding="utf-8")
    wrapper = kiro / "hooks" / "guard_wrapper.py"
    wrapper.write_text("# a made-up guard wrapper\n", encoding="utf-8")
    (kiro / "hooks" / "scripts" / "guard_example.py").write_text("# a made-up guard\n", encoding="utf-8")
    (kiro / "hooks" / "private" / "customer-terms.txt").write_text("examplecorp\n", encoding="utf-8")
    cfg = make_config(sb, agents={"change": AGENT})

    outcome = run_selftest(sb, cfg, approved_agents=frozenset({(AGENT, "change"), ("other", "query")}))

    record = json.loads(Path(outcome.record).read_text(encoding="ascii"))
    assert record["agent"] == AGENT and outcome.started == ("t0",)
    argv = record["trials"]["t0"]["argv"]
    assert argv[3:5] == ["--agent", AGENT]
    assert sb.invocations()[2]["start"]["options"]["agent"] == AGENT
    parts = record["config_parts"]
    assert parts["agent_file"] == {
        "path": f"~/.kiro/agents/{AGENT}.json",
        "sha256": hashlib.sha256(agent_file.read_bytes()).hexdigest(),
    }
    assert [entry["path"] for entry in parts["hook_files"]] == [
        "~/.kiro/hooks/guard_wrapper.py",
        "~/.kiro/hooks/scripts/guard_example.py",
    ]
    assert parts["config"] == {
        "kiro_cli": "~/.local/bin/kiro-cli",
        "mode_tool_ceiling.change": ["fs_read", "fs_write"],
        "agents.change": AGENT,
    }
    assert canonical_sha256(parts) == record["config_sha256"]

    # what cli.py run would compare: the same files give the same digest, an edited hook another
    again = runner.kiro_fingerprint(cfg, home=str(sb.home), agent=AGENT, kill_grace_seconds=1.0)
    assert (again.version, again.digest.sha256) == (FAKE_VERSION, record["config_sha256"])
    wrapper.write_text("# a made-up guard wrapper, edited\n", encoding="utf-8")
    edited = runner.kiro_fingerprint(cfg, home=str(sb.home), agent=AGENT, kill_grace_seconds=1.0)
    assert edited.digest.sha256 != record["config_sha256"]
    assert read_status(sb)["selftest"]["config_sha256"] == record["config_sha256"]

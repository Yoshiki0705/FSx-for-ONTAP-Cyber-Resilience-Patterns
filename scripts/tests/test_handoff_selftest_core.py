"""Unit tests of the pure core of the Handoff_Harness selftest (task 5.2).

``command.build_selftest_invocation`` and its helpers, the change of ``command.child_env``
(the parent's ``HANDOFF_GUARD_LOG`` is dropped), ``command.selftest_config_digest`` and
``command.kiro_cli_version``, and the outcome of a trial in ``evaluate``
(``trial_outcome``, ``guard_stopped``, ``parse_guard_log``, ``TrialEffects``). The rules
come from the observation agreement of task 5.2: the effect decides first, a stop counts
only when a ``block`` entry names the trial's token, and a line that is not JSON is not
read. No test starts a process or reads a file; every value is synthetic.

The argv of a selftest trial must keep the form of Property 24 (its head, a trust list
within the ceiling, no trust-all option). That property is tested on ``build_kiro_argv`` in
``test_handoff_prop_24_kiro_argv.py``; the selftest builder is a separate function, so its
argv is checked here with examples, one per trial.
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import json
from types import MappingProxyType, ModuleType
from typing import Any

import pytest
from handoff import command, evaluate
from handoff import config as config_module

HOME = "/home/example"
RUN_ID = "20261112T000000Z"
NONCE = "0123456789abcdef"
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40
CEILING = ("fs_read", "fs_write", "execute_bash")
AGENT = "handoff-change"


def make_config(**overrides: Any) -> config_module.HandoffConfig:
    """A configuration of the real form under the synthetic home; ``overrides`` replace keys."""
    raw: dict[str, Any] = {
        "schema_version": 1,
        "kiro_cli": "~/.local/bin/kiro-cli",
        "timeout_seconds": 600,
        "max_concurrency": 2,
        "worktrees_root": "~/Projects/.handoff-worktrees",
        "min_free_disk_gb": 1,
        "mode_tool_ceiling": {"query": ["fs_read"], "change": list(CEILING)},
        "agents": {},
        "repos": {"example-hub": {"main_tree": "~/Projects/example-hub"}},
    }
    raw.update(overrides)
    return config_module.parse_config(
        raw,
        home=HOME,
        extra_main_trees=[f"{HOME}/Projects/example-harness"],
        session_worktrees_dir=f"{HOME}/Projects/.kiro-worktrees",
    )


def token(trial: str, nonce: str = NONCE) -> str:
    """The token of a trial."""
    return command.selftest_token(trial, nonce)


def invocation(cfg: config_module.HandoffConfig, trial: str, approved: tuple[str, ...] = ()) -> command.KiroInvocation:
    """Build the run of one trial of the selftest whose run ID is :data:`RUN_ID`."""
    run_dir = command.selftest_run_dir(cfg, RUN_ID)
    return command.build_selftest_invocation(cfg, token(trial), run_dir=run_dir, home=HOME, approved_agents=approved)


def codes(error: command.CommandError) -> set[str]:
    """The issue codes of a refusal."""
    return {issue.code for issue in error.issues}


# ---------------------------------------------------------------------------------------------
# build_selftest_invocation
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("approved", [False, True], ids=["no-agent", "approved-agent"])
@pytest.mark.parametrize("trial", evaluate.SELFTEST_TRIALS)
def test_a_trial_argv_keeps_the_form_of_property_24(
    trial: str, approved: bool, fake_kiro_cli_module: ModuleType
) -> None:
    """Head, one trust list within the ceiling (``fs_read`` alone for T4), no trust-all, the prompt last."""
    cfg = make_config(agents={"change": AGENT}) if approved else make_config()
    run = invocation(cfg, trial, (AGENT,) if approved else ())
    argv = run.argv

    assert argv[:3] == (config_module.normalize_path(cfg.kiro_cli, HOME), "chat", "--no-interactive")
    assert "--trust-all-tools" not in argv and "-a" not in argv
    trust = [arg for arg in argv if arg.startswith(command.TRUST_TOOLS_OPTION)]
    assert len(trust) == 1
    tools = tuple(trust[0][len(command.TRUST_TOOLS_OPTION) :].split(","))
    assert tools == (("fs_read",) if trial == "t4" else CEILING)
    assert set(tools) <= set(cfg.mode_tool_ceiling["change"]) | {"fs_read"}
    middle = argv[3:-2]
    assert middle == ((command.AGENT_OPTION, AGENT) if approved else ())
    assert run.agent == (AGENT if approved else None)
    assert argv[-2] == trust[0]
    assert run.cwd == f"{HOME}/Projects/.handoff-worktrees/selftest/{RUN_ID}/{trial}/repo"
    assert run.timeout_seconds == cfg.timeout_seconds

    prompt = argv[-1]
    assert not prompt.startswith("-") and prompt.count(token(trial)) >= 1
    # the fake kiro-cli finds exactly this token, so it picks this trial's behaviors
    found = {match.group(0): match.group(1) for match in fake_kiro_cli_module.SELFTEST_TOKEN.finditer(prompt)}
    assert found == {token(trial): trial}


def test_the_t1_prompt_holds_a_private_address_outside_the_placeholder_ranges() -> None:
    """T1's address is private, built at run time, and not in the ranges ``.gitleaks.toml`` allows."""
    address = ipaddress.ip_address(command.SELFTEST_EXAMPLE_ADDRESS)
    assert address.is_private and address.version == 4
    assert address not in ipaddress.ip_network("10.0.0.0/16") and address not in ipaddress.ip_network("192.168.0.0/16")
    prompts = {trial: invocation(make_config(), trial).argv[-1] for trial in evaluate.SELFTEST_TRIALS}
    assert [trial for trial, text in prompts.items() if command.SELFTEST_EXAMPLE_ADDRESS in text] == ["t1"]
    assert f'"{token("t1")} {command.SELFTEST_EXAMPLE_ADDRESS}"' in prompts["t1"]
    assert "README.md" in prompts["t0"] and "push --force" in prompts["t2"]
    assert 'gh-exit=$?"' in prompts["t3"] and f"{token('t4')}.txt" in prompts["t4"]


def _replace(cfg: config_module.HandoffConfig, **fields: Any) -> config_module.HandoffConfig:
    """A configuration that ``parse_config`` would not return, as a caller could build one."""
    return dataclasses.replace(cfg, **fields)


REFUSALS: tuple[tuple[str, Any, set[str]], ...] = (
    ("repo-named-selftest", lambda: make_config(repos={"selftest": {"main_tree": "~/Projects/selftest"}}), {"repo"}),
    ("repo-named-SelfTest", lambda: make_config(repos={"SelfTest": {"main_tree": "~/Projects/x"}}), {"repo"}),
    ("unapproved-agent", lambda: make_config(agents={"change": AGENT}), {"agent"}),
    ("timeout-zero", lambda: _replace(make_config(), timeout_seconds=0), {"timeout_seconds"}),
    ("timeout-bool", lambda: _replace(make_config(), timeout_seconds=True), {"timeout_seconds"}),
    ("relative-kiro-cli", lambda: _replace(make_config(), kiro_cli="kiro-cli"), {"kiro_cli"}),
    (
        "empty-ceiling",
        lambda: _replace(make_config(), mode_tool_ceiling=MappingProxyType({"query": ("fs_read",), "change": ()})),
        {"trust_tools"},
    ),
    (
        "comma-in-ceiling",
        lambda: _replace(
            make_config(), mode_tool_ceiling=MappingProxyType({"query": ("fs_read",), "change": ("fs_read,use_aws",)})
        ),
        {"trust_tools"},
    ),
    (
        "repeated-tool",
        lambda: _replace(
            make_config(), mode_tool_ceiling=MappingProxyType({"query": ("fs_read",), "change": ("fs_read", "fs_read")})
        ),
        {"trust_tools"},
    ),
)


@pytest.mark.parametrize(("name", "build", "expected"), REFUSALS, ids=[name for name, _, _ in REFUSALS])
def test_a_selftest_run_is_refused_without_an_argv(name: str, build: Any, expected: set[str]) -> None:
    """Each refusal names its input. T4 trusts ``fs_read`` alone, so a broken change ceiling spares it."""
    cfg = build()
    run_dir = f"{HOME}/Projects/.handoff-worktrees/selftest/{RUN_ID}"
    trials = ("t0",) if "ceiling" in name or "tool" in name else evaluate.SELFTEST_TRIALS
    for trial in trials:
        with pytest.raises(command.CommandError) as caught:
            command.build_selftest_invocation(cfg, token(trial), run_dir=run_dir, home=HOME, approved_agents=())
        assert codes(caught.value) == expected, (trial, caught.value)
    if "ceiling" in name or "tool" in name:
        run = command.build_selftest_invocation(cfg, token("t4"), run_dir=run_dir, home=HOME, approved_agents=())
        assert run.argv[-2] == "--trust-tools=fs_read"


def test_run_dir_must_be_the_selftest_directory_of_worktrees_root() -> None:
    """Another root with the same shape is refused; ``selftest_run_dir`` refuses ``repos`` named selftest too."""
    cfg = make_config()
    elsewhere = f"{HOME}/elsewhere/selftest/{RUN_ID}"
    with pytest.raises(command.CommandError) as caught:
        command.build_selftest_invocation(cfg, token("t0"), run_dir=elsewhere, home=HOME, approved_agents=())
    assert codes(caught.value) == {"worktree"}
    with pytest.raises(command.CommandError) as caught:
        command.selftest_run_dir(make_config(repos={"Selftest": {"main_tree": "~/Projects/s"}}), RUN_ID)
    assert codes(caught.value) == {"repo"}
    assert command.selftest_run_dir(cfg, RUN_ID) == f"{HOME}/Projects/.handoff-worktrees/selftest/{RUN_ID}"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("token", "handoff-selftest-t5-" + NONCE, "token"),
        ("token", "handoff-selftest-t0-" + NONCE.upper(), "token"),
        ("run_dir", f"{HOME}/Projects/.handoff-worktrees/selftest/2026-11-12", "run ID"),
        ("run_dir", f"{HOME}/Projects/.handoff-worktrees/other/{RUN_ID}", "selftest/<run ID>"),
        ("run_dir", f"{HOME}/Projects/.handoff-worktrees/selftest/20261340T000000Z", "moment"),
        ("run_dir", f"{HOME}/Projects/.handoff-worktrees/selftest/../selftest/{RUN_ID}", "normal form"),
        ("home", "home/example", "home"),
    ],
)
def test_malformed_values_of_the_runner_raise_value_error(field: str, value: str, message: str) -> None:
    """A token, run directory or home that only the runner makes is a fault of the caller, not a refusal."""
    arguments = {"token": token("t0"), "run_dir": f"{HOME}/Projects/.handoff-worktrees/selftest/{RUN_ID}", "home": HOME}
    arguments[field] = value
    with pytest.raises(ValueError, match=message) as caught:
        command.build_selftest_invocation(
            make_config(),
            arguments["token"],
            run_dir=arguments["run_dir"],
            home=arguments["home"],
            approved_agents=(),
        )
    assert not isinstance(caught.value, command.CommandError)


def test_tokens_and_paths_have_their_forms() -> None:
    """``selftest_token`` takes 16 lowercase hexadecimal digits; ``selftest_paths`` lays out one trial."""
    assert token("t3") == "handoff-selftest-t3-0123456789abcdef"
    for trial, nonce in (("t5", NONCE), ("T0", NONCE), ("t0", NONCE[:-1]), ("t0", NONCE.upper()), ("t0", NONCE + "0")):
        with pytest.raises(ValueError):
            command.selftest_token(trial, nonce)
    paths = command.selftest_paths(f"/w/selftest/{RUN_ID}", "t2")
    assert (paths.directory, paths.remote, paths.repo, paths.guard_log, paths.hooks) == tuple(
        f"/w/selftest/{RUN_ID}/t2/{name}".rstrip("/") for name in ("", "remote.git", "repo", "guard.jsonl", "hooks")
    )


# ---------------------------------------------------------------------------------------------
# child_env
# ---------------------------------------------------------------------------------------------


def test_child_env_drops_the_parents_guard_log_and_keeps_other_handoff_variables() -> None:
    """Only a selftest trial sets ``HANDOFF_GUARD_LOG``, on top of ``child_env``; an item's run never gets it."""
    parent = {"PATH": "/usr/bin", "HANDOFF_GUARD_LOG": "/home/example/guard.jsonl", "HANDOFF_TEST_X": "kept"}
    env = command.child_env(
        parent,
        push_url="/tmp/example-child/no-such-remote",
        gh_config_dir="/tmp/example-child/gh",
        aws_empty_file="/tmp/example-child/aws-empty",
    )
    assert command.GUARD_LOG_VARIABLE == "HANDOFF_GUARD_LOG" and "HANDOFF_GUARD_LOG" not in env
    assert env["HANDOFF_TEST_X"] == "kept" and env["PATH"] == "/usr/bin"
    assert parent["HANDOFF_GUARD_LOG"] == "/home/example/guard.jsonl"


# ---------------------------------------------------------------------------------------------
# trial_outcome: the effect first, then a block entry that names the token
# ---------------------------------------------------------------------------------------------


def effects(**fields: Any) -> evaluate.TrialEffects:
    """Effects of a trial in which nothing happened, with ``fields`` changed."""
    values: dict[str, Any] = {
        "base": SHA_A,
        "head": SHA_A,
        "base_is_ancestor": True,
        "readme_changed": False,
        "new_commits": (),
        "remote_refs_before": (("refs/heads/main", SHA_A),),
        "remote_refs_after": (("refs/heads/main", SHA_A),),
        "status_paths": (),
    }
    values.update(fields)
    return evaluate.TrialEffects(**values)


def entry(trial: str, *, decision: str = "block", schema: Any = 1, with_token: bool = True, **extra: Any) -> bytes:
    """One line of the guard log as the wrapper writes it."""
    command_text = f"git commit {token(trial)}" if with_token else "an unrelated call"
    value: dict[str, Any] = {
        "schema": schema,
        "at": "2026-11-12T00:00:00Z",
        "guard": "guard_example",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "input": {"tool_name": "shell", "tool_input": {"command": command_text}},
    }
    value.update(extra)
    return json.dumps(value).encode("ascii") + b"\n"


#: For each trial, effects of the operation having taken effect.
TOOK_EFFECT: dict[str, evaluate.TrialEffects] = {
    "t0": effects(head=SHA_B, readme_changed=True),
    "t1": effects(head=SHA_B, new_commits=((SHA_B, f"{token('t1')} {command.SELFTEST_EXAMPLE_ADDRESS}"),)),
    "t2": effects(remote_refs_after=(("refs/heads/main", SHA_B),)),
    "t3": effects(head=SHA_B, new_commits=((SHA_B, f"{token('t3')} gh-exit=0"),)),
    "t4": effects(status_paths=(f"{token('t4')}.txt",)),
}


@pytest.mark.parametrize("trial", evaluate.SELFTEST_TRIALS)
def test_the_three_outcomes_of_each_trial(trial: str) -> None:
    """Effect: ``completed`` even with a stop logged. No effect: a stop that names the token, or nothing."""
    stop = evaluate.parse_guard_log(entry(trial))
    nothing = effects()
    assert evaluate.trial_outcome(token(trial), TOOK_EFFECT[trial], ()) == "completed"
    assert evaluate.trial_outcome(token(trial), TOOK_EFFECT[trial], stop) == "completed"
    assert evaluate.trial_outcome(token(trial), nothing, stop) == "blocked_by_guard"
    assert evaluate.trial_outcome(token(trial), nothing, ()) == "failed_otherwise"
    assert evaluate.trial_outcome(token(trial), None, stop) == "failed_otherwise"


NO_EFFECT: tuple[tuple[str, str, evaluate.TrialEffects], ...] = (
    ("t0-head-unborn", "t0", effects(head=None, base_is_ancestor=False)),
    ("t0-head-not-moved", "t0", effects(readme_changed=True)),
    ("t0-history-rewritten", "t0", effects(head=SHA_B, base_is_ancestor=False, readme_changed=True)),
    ("t0-readme-unchanged", "t0", effects(head=SHA_B)),
    (
        "t2-same-refs-reordered",
        "t2",
        effects(
            remote_refs_before=(("refs/heads/main", SHA_A), ("refs/heads/x", SHA_B)),
            remote_refs_after=(("refs/heads/x", SHA_B), ("refs/heads/main", SHA_A)),
        ),
    ),
    ("t3-gh-exit-1", "t3", effects(head=SHA_B, new_commits=((SHA_B, f"{token('t3')} gh-exit=1"),))),
    ("t3-gh-exit-10", "t3", effects(head=SHA_B, new_commits=((SHA_B, f"{token('t3')} gh-exit=10"),))),
    ("t3-no-token", "t3", effects(head=SHA_B, new_commits=((SHA_B, "gh-exit=0"),))),
    ("t3-other-token", "t3", effects(head=SHA_B, new_commits=((SHA_B, f"{token('t3', 'f' * 16)} gh-exit=0"),))),
    ("t4-other-path", "t4", effects(status_paths=("notes.txt",))),
)

WITH_EFFECT: tuple[tuple[str, str, evaluate.TrialEffects], ...] = (
    ("t1-commit-on-another-branch", "t1", effects(new_commits=((SHA_B, "anything"),))),
    (
        "t2-ref-added",
        "t2",
        effects(remote_refs_after=(("refs/heads/main", SHA_A), (f"refs/heads/{token('t2')}", SHA_B))),
    ),
    ("t2-ref-removed", "t2", effects(remote_refs_after=())),
    ("t3-two-codes", "t3", effects(head=SHA_B, new_commits=((SHA_B, f"{token('t3')} gh-exit=1 gh-exit=0"),))),
    ("t4-token-directory", "t4", effects(status_paths=(f"{token('t4')}/x.txt",))),
    ("t4-new-commit", "t4", effects(head=SHA_B, new_commits=((SHA_B, "wrote it"),))),
)


@pytest.mark.parametrize(("name", "trial", "observed"), NO_EFFECT, ids=[row[0] for row in NO_EFFECT])
def test_boundaries_that_are_not_the_effect(name: str, trial: str, observed: evaluate.TrialEffects) -> None:
    """Each just misses its trial's effect, so a logged stop decides."""
    assert evaluate.trial_outcome(token(trial), observed, evaluate.parse_guard_log(entry(trial))) == "blocked_by_guard"
    assert evaluate.trial_outcome(token(trial), observed, ()) == "failed_otherwise"


@pytest.mark.parametrize(("name", "trial", "observed"), WITH_EFFECT, ids=[row[0] for row in WITH_EFFECT])
def test_boundaries_that_are_the_effect(name: str, trial: str, observed: evaluate.TrialEffects) -> None:
    """Each just meets its trial's effect, so it is ``completed`` with a stop logged."""
    assert evaluate.trial_outcome(token(trial), observed, evaluate.parse_guard_log(entry(trial))) == "completed"


NOT_A_STOP: tuple[tuple[str, bytes], ...] = (
    ("allow", entry("t1", decision="allow")),
    ("block-without-token", entry("t1", with_token=False)),
    ("block-of-another-trial", entry("t2")),
    ("schema-2", entry("t1", schema=2)),
    ("schema-true", entry("t1", schema=True)),
    ("decision-in-capitals", entry("t1", decision="BLOCK")),
    ("no-input", json.dumps({"schema": 1, "decision": "block", "note": token("t1")}).encode() + b"\n"),
    ("not-json", f'{{"schema": 1, "decision": "block", "input": "{token("t1")}"\n'.encode()),
    ("not-utf8", b'{"schema": 1, "decision": "block", "input": "' + token("t1").encode() + b'\xff"}\n'),
    ("nan", f'{{"schema": 1, "decision": "block", "input": "{token("t1")}", "n": NaN}}\n'.encode()),
    ("huge-float", f'{{"schema": 1, "decision": "block", "input": "{token("t1")}", "n": 1e999}}\n'.encode()),
    ("an-array", json.dumps(["block", token("t1")]).encode() + b"\n"),
)


@pytest.mark.parametrize(("name", "line"), NOT_A_STOP, ids=[row[0] for row in NOT_A_STOP])
def test_guard_log_lines_that_do_not_count_as_a_stop(name: str, line: bytes) -> None:
    """Only a readable ``block`` entry of schema 1 whose input names the token counts."""
    log = evaluate.parse_guard_log(line)
    assert len(log) == 1
    assert evaluate.guard_stopped(log, token("t1")) is False
    assert evaluate.trial_outcome(token("t1"), effects(), log) == "failed_otherwise"
    # the control: the same log with one real stop added counts
    assert evaluate.trial_outcome(token("t1"), effects(), log + evaluate.parse_guard_log(entry("t1"))) == (
        "blocked_by_guard"
    )


def test_a_stop_whose_input_is_text_counts_when_the_text_names_the_token() -> None:
    """The wrapper keeps an input it cannot read as JSON as a string; its JSON text still holds the token."""
    line = json.dumps({"schema": 1, "decision": "block", "input": f"raw stdin {token('t2')}"}).encode() + b"\n"
    assert evaluate.trial_outcome(token("t2"), effects(), evaluate.parse_guard_log(line)) == "blocked_by_guard"


def test_parse_guard_log_keeps_every_line_and_round_trips() -> None:
    """Numbering, a missing final newline, a blank line, and the record form of each line."""
    data = entry("t1") + b"\n" + b"\xffnot json\n" + entry("t1", decision="allow").rstrip(b"\n")
    lines = evaluate.parse_guard_log(data)
    assert [(line.number, line.readable) for line in lines] == [(1, True), (2, False), (3, False), (4, True)]
    assert lines[1].value == "" and lines[2].value == "\ufffdnot json"
    assert evaluate.parse_guard_log(b"") == ()
    assert tuple(evaluate.GuardLogLine.from_json(json.loads(json.dumps(line.to_json()))) for line in lines) == lines
    with pytest.raises(evaluate.EvaluationError):
        evaluate.GuardLogLine(1, False, {"not": "text"})


def test_trial_effects_round_trip_and_refuse_bad_shapes() -> None:
    """The record form reads back to equal effects; impossible combinations are refused."""
    for observed in (*TOOK_EFFECT.values(), effects(head=None, base_is_ancestor=False)):
        assert evaluate.TrialEffects.from_json(json.loads(json.dumps(observed.to_json()))) == observed
    bad: list[dict[str, Any]] = [
        {"base": "A" * 40},
        {"head": "abc"},
        {"head": None, "base_is_ancestor": True},
        {"head": None, "base_is_ancestor": False, "readme_changed": True},
        {"remote_refs_after": (("refs/heads/main", SHA_A), ("refs/heads/main", SHA_B))},
        {"new_commits": ((SHA_B,),)},
        {"status_paths": ("",)},
    ]
    for fields in bad:
        with pytest.raises(evaluate.EvaluationError):
            effects(**fields)
    with pytest.raises(evaluate.EvaluationError):
        evaluate.trial_outcome("handoff-selftest-t9-0123456789abcdef", effects(), ())


# ---------------------------------------------------------------------------------------------
# config_sha256 and the version
# ---------------------------------------------------------------------------------------------

HOOKS = f"{HOME}/.kiro/hooks"


def digest(cfg: config_module.HandoffConfig | None = None, **kwargs: Any) -> command.ConfigDigest:
    """The digest of a configuration with two hook files and no agent, unless ``kwargs`` say otherwise."""
    arguments: dict[str, Any] = {
        "agent": None,
        "agent_file": None,
        "hook_files": {f"{HOOKS}/guard_wrapper.py": b"wrapper", f"{HOOKS}/scripts/guard_a.py": b"guard"},
    }
    arguments.update(kwargs)
    return command.selftest_config_digest(cfg or make_config(), home=HOME, **arguments)


def test_the_digest_is_fixed_by_its_inputs_and_not_by_their_order() -> None:
    """Hook files in another order give the same digest; the canonical text is what is hashed."""
    first = digest()
    reordered = digest(hook_files={f"{HOOKS}/scripts/guard_a.py": b"guard", f"{HOOKS}/guard_wrapper.py": b"wrapper"})
    assert first == reordered
    assert hashlib.sha256(first.canonical.encode("ascii")).hexdigest() == first.sha256
    parts = first.parts()
    assert [entry["path"] for entry in parts["hook_files"]] == [
        "~/.kiro/hooks/guard_wrapper.py",
        "~/.kiro/hooks/scripts/guard_a.py",
    ]
    assert parts["config"] == {
        "kiro_cli": "~/.local/bin/kiro-cli",
        "mode_tool_ceiling.change": list(CEILING),
        "agents.change": None,
    }
    assert parts["agent_file"] is None
    parts["config"]["kiro_cli"] = "changed"
    assert first.parts()["config"]["kiro_cli"] == "~/.local/bin/kiro-cli"  # a new object each time
    assert json.dumps(first.parts(), sort_keys=True, separators=(",", ":"), ensure_ascii=True) == first.canonical


def test_each_part_changes_the_digest() -> None:
    """A byte of a hook, a hook moved between the two directories, an unreadable hook, the agent and its file, the configuration."""
    base = digest().sha256
    variants = {
        "hook-byte": digest(
            hook_files={f"{HOOKS}/guard_wrapper.py": b"wrapper!", f"{HOOKS}/scripts/guard_a.py": b"guard"}
        ),
        "hook-moved": digest(
            hook_files={f"{HOOKS}/scripts/guard_wrapper.py": b"wrapper", f"{HOOKS}/scripts/guard_a.py": b"guard"}
        ),
        "hook-unreadable": digest(
            hook_files={f"{HOOKS}/guard_wrapper.py": None, f"{HOOKS}/scripts/guard_a.py": b"guard"}
        ),
        "hook-added": digest(
            hook_files={
                f"{HOOKS}/guard_wrapper.py": b"wrapper",
                f"{HOOKS}/scripts/guard_a.py": b"guard",
                f"{HOOKS}/new": b"",
            }
        ),
        "agent": digest(make_config(agents={"change": AGENT}), agent=AGENT, agent_file=b"{}"),
        "agent-unreadable": digest(make_config(agents={"change": AGENT}), agent=AGENT, agent_file=None),
        "agent-configured-only": digest(make_config(agents={"change": AGENT})),
        "kiro-cli": digest(make_config(kiro_cli="/opt/kiro/bin/kiro-cli")),
        "ceiling": digest(
            make_config(mode_tool_ceiling={"query": ["fs_read"], "change": ["fs_write", "fs_read", "execute_bash"]})
        ),
    }
    shas = {name: value.sha256 for name, value in variants.items()}
    assert base not in shas.values()
    assert len(set(shas.values())) == len(shas), shas
    assert variants["agent"].parts()["agent_file"] == {
        "path": "~/.kiro/agents/handoff-change.json",
        "sha256": hashlib.sha256(b"{}").hexdigest(),
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"hook_files": {f"{HOOKS}/private/customer-terms.txt": b"x"}},
        {"hook_files": {f"{HOME}/.kiro/agents/a.json": b"x"}},
        {"hook_files": {f"{HOOKS}/../hooks/a.py": b"x"}},
        {"agent": None, "agent_file": b"{}"},
        {"agent": "-a", "agent_file": None},
    ],
)
def test_the_digest_refuses_inputs_from_other_places(kwargs: dict[str, Any]) -> None:
    """Only files directly in the two hook directories, and an agent file only with an agent."""
    with pytest.raises(ValueError):
        digest(**kwargs)


@pytest.mark.parametrize(
    ("output", "version"),
    [
        ("kiro-cli 2.32.0\n", "2.32.0"),
        ("  kiro-cli 2.32.0  \n\n", "2.32.0"),
        ("kiro-cli 2.32.0 (build 7)\n", "2.32.0 (build 7)"),
        ("kiro-cli\n", "kiro-cli"),
        ("Kiro CLI 2.32.0\n", "Kiro CLI 2.32.0"),
        ("kiro-cli 2.32.0\nupdate available\n", "kiro-cli 2.32.0\nupdate available"),
        ("", ""),
    ],
)
def test_kiro_cli_version(output: str, version: str) -> None:
    """``<version>`` of one line ``kiro-cli <version>``, otherwise the stripped output."""
    assert command.kiro_cli_version(output) == version

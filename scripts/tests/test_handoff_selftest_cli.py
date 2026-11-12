"""Tests of ``cli.py selftest`` started as a file, as the maintainer starts it (task 5.2).

Each test writes ``config.json``, ``manifest.json``, the templates, the deny list and an earlier
``status.json`` into the ``handoff_sandbox`` of ``conftest.py``, then starts
``python cli.py --handoff-dir <sandbox> selftest`` with the sandbox's environment. ``HOME`` is the
sandbox home, so ``kiro_cli`` (``~/.local/bin/kiro-cli``) is the fake ``kiro-cli`` that the sandbox
copied there, and ``worktrees_root``, ``~/.kiro`` and the deny list are the sandbox's. Nothing
reads or writes this machine's ``~/.kiro`` or ``~/Projects/.handoff-worktrees``, uses the network,
or starts the real ``kiro-cli``.

Checked here, by the exit codes that the selftest's design note of task 5.2 sets:

- 0 and 1 follow the verdict, for two sets of the design's Testing Strategy table: both guards
  stopped (``guards_active``) and T0 failed (``unconfirmed``). Standard output shows the verdict,
  each trial's outcome and whether its ``kiro-cli`` started, the record, and the new ``selftest``
  of ``status.json``, and these agree with the record file and ``status.json``.
- 2 for a repository called ``selftest`` and 4 for a failed ``whoami``: ``status.json`` stays byte
  for byte, and nothing is added below ``.private/handoff`` or ``worktrees_root``.
- 6 when ``kiro-cli`` is not where ``config.json`` says and when ``kiro-cli --version`` fails:
  standard error tells the two apart, the manual display is printed for the change item that is
  ``queued`` and ready only (not for the query item, the change item that waits for a dependency,
  or the change item in ``needs-human``), and ``status.json`` stays byte for byte.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import cli, evaluate, state

if TYPE_CHECKING:
    from conftest import HandoffSandbox

REPO = "example-hub"
QUERY = "a-hub-query"
CHANGE = "b-hub-change"
WAITING = "c-hub-waiting"
HELD = "d-hub-held"
ALL_IDS = (QUERY, CHANGE, WAITING, HELD)
CLI_FILE = Path(cli.__file__).resolve()
TRIALS = evaluate.SELFTEST_TRIALS
FAKE_VERSION = "0.0.0-fake"
T0 = "2026-11-11T00:00:00Z"

#: The selftest of an earlier harness, which a selftest that stops before its trials keeps.
EARLIER = {
    "result": "guards_active",
    "at": T0,
    "kiro_cli_version": FAKE_VERSION,
    "record": "selftest/20261111T000000Z.json",
    "config_sha256": "0" * 64,
}

QUERY_TEMPLATE = """<!-- The query template of the selftest tests. -->
<!-- slot: purpose -->
Answer the questions about $topic.

<!-- slot: questions -->
1. What is the first line of `AGENTS.md`?
"""

CHANGE_TEMPLATE = """<!-- The change template of the selftest tests. -->
<!-- slot: purpose -->
Add a line to the guide of $topic.
"""

COMPLETED, BLOCKED, OTHER = "completed", "blocked_by_guard", "failed_otherwise"


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
    """``config.json`` of the real form for the sandbox; ``over`` replaces keys."""
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
    """A query item, a ready change item, a change item that waits for the query item, one held."""
    return {
        "schema_version": 1,
        "items": [
            item(QUERY, "a"),
            item(CHANGE, "b", mode="change"),
            item(WAITING, "c", mode="change", depends_on=[QUERY]),
            item(HELD, "d", mode="change"),
        ],
    }


def prepare(sb: HandoffSandbox, *, config: dict[str, Any] | None = None) -> bytes:
    """Write the deny list, the templates, the two files and an earlier ``status.json``; return its bytes.

    The earlier status has a record of every item, :data:`HELD` in ``needs-human``, and
    :data:`EARLIER` as ``selftest``.
    """
    listed = sb.home / ".kiro" / "hooks" / "private"
    listed.mkdir(parents=True)
    (listed / "customer-terms.txt").write_text("# synthetic\nexamplecorp\n", encoding="utf-8")
    templates = sb.handoff_dir / "templates"
    templates.mkdir()
    (templates / "query.md").write_text(QUERY_TEMPLATE, encoding="utf-8")
    (templates / "change.md").write_text(CHANGE_TEMPLATE, encoding="utf-8")
    (sb.handoff_dir / "config.json").write_text(json.dumps(config or config_value()), encoding="utf-8")
    (sb.handoff_dir / "manifest.json").write_text(json.dumps(manifest_value()), encoding="utf-8")
    status = state.empty_status()
    for item_id in ALL_IDS:
        status = state.add_item(status, item_id)
    status = state.transition(status, HELD, state.NEEDS_HUMAN, at=T0, reason="change_mode_not_wired")
    status["selftest"] = dict(EARLIER)
    data = state.render_status(status).encode("utf-8")
    (sb.handoff_dir / "status.json").write_bytes(data)
    return data


def run_selftest(sb: HandoffSandbox, **extra: str) -> subprocess.CompletedProcess[str]:
    """``python cli.py --handoff-dir <sandbox> selftest`` with the sandbox's environment and ``extra``."""
    env = sb.environ(PYTHONIOENCODING="utf-8", **extra)
    env.pop("CUSTOMER_TERMS_FILE", None)
    return subprocess.run(
        [sys.executable, str(CLI_FILE), "--handoff-dir", str(sb.handoff_dir), "selftest"],
        cwd=str(sb.root),
        env=env,
        capture_output=True,
        encoding="utf-8",
        timeout=180,
        check=False,
    )


def read_status(sb: HandoffSandbox) -> state.StatusDoc:
    """Read and check ``status.json``."""
    return state.parse_status((sb.handoff_dir / "status.json").read_text(encoding="utf-8"))


def tree_files(directory: Path) -> set[str]:
    """Every file and directory below a directory, relative to it."""
    return {str(path.relative_to(directory)) for path in directory.rglob("*")} if directory.exists() else set()


# ---------------------------------------------------------------------------------------------
# 0 and 1: the verdict
# ---------------------------------------------------------------------------------------------

#: Two sets of the design's table: the trial behaviors, the exit code, the result, the outcomes
#: of T0 to T4, and the trials whose ``kiro-cli`` started.
VERDICTS: dict[str, tuple[dict[str, str], int, str, tuple[str, ...], tuple[str, ...]]] = {
    "both-stopped": (
        {"T0": "commit", "T1": "guard-block", "T2": "guard-block", "T3": "gh-status", "T4": "write-file"},
        0,
        evaluate.GUARDS_ACTIVE,
        (COMPLETED, BLOCKED, BLOCKED, OTHER, OTHER),
        TRIALS,
    ),
    "t0-fails": ({}, 1, evaluate.UNCONFIRMED, (OTHER,) * 5, ("t0",)),
}


@pytest.mark.parametrize(
    ("modes", "code", "result", "outcomes", "started"), list(VERDICTS.values()), ids=list(VERDICTS)
)
def test_exit_codes_0_and_1_follow_the_verdict_and_the_output_agrees_with_the_record(
    handoff_sandbox: HandoffSandbox,
    modes: dict[str, str],
    code: int,
    result: str,
    outcomes: tuple[str, ...],
    started: tuple[str, ...],
) -> None:
    """The exit code is the verdict's, and the verdict, the trials, the record and ``status.json`` agree."""
    sb = handoff_sandbox
    before = prepare(sb)
    variables = {f"FAKE_KIRO_MODE_{trial}": behavior for trial, behavior in modes.items()}

    done = run_selftest(sb, FAKE_KIRO_COMMIT_FILES="README.md", **variables)

    assert done.returncode == code, (done.stdout, done.stderr)
    lines = done.stdout.splitlines()
    head = re.fullmatch(r"selftest ([0-9]{8}T[0-9]{6}Z): ([a-z_]+)", lines[0])
    assert head is not None and head.group(2) == result, lines
    run_id = head.group(1)
    assert lines[1:6] == [
        f"  {trial.upper()}: {outcome}（{'kiro-cli を起動した' if trial in started else '起動しなかった'}）"
        for trial, outcome in zip(TRIALS, outcomes, strict=True)
    ]
    record_file = sb.handoff_dir / "selftest" / f"{run_id}.json"
    assert lines[6] == f"記録: ~/{record_file.relative_to(sb.home)}"
    assert sorted(path.name for path in record_file.parent.glob("*.json")) == [record_file.name]

    # the record and status.json say what standard output said
    record = json.loads(record_file.read_text(encoding="ascii"))
    assert (record["result"], record["run_id"]) == (result, run_id)
    assert {trial: record["trials"][trial]["outcome"] for trial in TRIALS} == dict(zip(TRIALS, outcomes, strict=True))
    assert tuple(trial for trial in TRIALS if record["trials"][trial]["attempted"]) == started
    status = read_status(sb)
    assert status["selftest"] == {
        "result": result,
        "at": record["ended_at"],
        "kiro_cli_version": FAKE_VERSION,
        "record": f"selftest/{run_id}.json",
        "config_sha256": record["config_sha256"],
    }
    shown = f"result {result}、kiro_cli_version {FAKE_VERSION}、config_sha256 {record['config_sha256']}"
    assert lines[7:] == [f"status.json の selftest を更新した（{shown}）"]
    earlier = state.parse_status(before.decode("utf-8"))
    assert (status["items"], status["events"]) == (earlier["items"], earlier["events"])
    assert ("selftest: T0 " in done.stderr) is (result == evaluate.UNCONFIRMED)

    # the sandbox's kiro-cli ran, and the trials ran below the sandbox's worktrees_root
    runs = sb.invocations()
    assert [run["start"]["subcommand"] for run in runs] == ["--version", "whoami", *(["chat"] * len(started))]
    assert runs[0]["start"]["argv"] == [str(sb.kiro_cli), "--version"]
    assert tuple(run["start"]["trial"] for run in runs[2:]) == started
    run_dir = sb.worktrees_root / "selftest" / run_id
    assert record["run_dir"] == f"~/{run_dir.relative_to(sb.home)}" and run_dir.is_dir()
    assert all(Path(run["start"]["cwd"]).is_relative_to(run_dir) for run in runs[2:])


# ---------------------------------------------------------------------------------------------
# 2 and 4: stopped before the trials
# ---------------------------------------------------------------------------------------------

#: The configuration's keys, the fake's variables, the exit code, a part of the message, and
#: the invocations of the fake.
STOPS: dict[str, tuple[dict[str, Any], dict[str, str], int, str, list[str]]] = {
    "repository-named-selftest": (
        {"repos": {REPO: {"main_tree": f"~/Projects/{REPO}"}, "selftest": {"main_tree": "~/Projects/other"}}},
        {},
        2,
        "the selftest was not started",
        [],
    ),
    "whoami-fails": ({}, {"FAKE_KIRO_MODE": "whoami-fail"}, 4, "log in to kiro-cli", ["--version", "whoami"]),
}


@pytest.mark.parametrize(
    ("overrides", "variables", "code", "message", "subcommands"), list(STOPS.values()), ids=list(STOPS)
)
def test_exit_codes_2_and_4_keep_status_json_and_write_nothing(
    handoff_sandbox: HandoffSandbox,
    overrides: dict[str, Any],
    variables: dict[str, str],
    code: int,
    message: str,
    subcommands: list[str],
) -> None:
    """A selftest that stops before its trials ends with its code, and ``status.json`` keeps its bytes."""
    sb = handoff_sandbox
    before = prepare(sb, config=config_value(**overrides))
    handoff_before = tree_files(sb.handoff_dir)

    done = run_selftest(sb, FAKE_KIRO_MODE_T0="commit", FAKE_KIRO_COMMIT_FILES="README.md", **variables)

    assert done.returncode == code, (done.stdout, done.stderr)
    assert done.stdout == ""
    assert message in done.stderr
    assert done.stderr.splitlines()[-1] == "status.json の selftest は変えていない"
    assert (sb.handoff_dir / "status.json").read_bytes() == before
    assert tree_files(sb.handoff_dir) == handoff_before
    assert not (sb.worktrees_root / "selftest").exists()
    assert [run["start"]["subcommand"] for run in sb.invocations()] == subcommands


# ---------------------------------------------------------------------------------------------
# 6: kiro-cli cannot be used, and the manual display is printed instead
# ---------------------------------------------------------------------------------------------

#: The fake's variables (``None`` removes the fake), what standard error must say first, what
#: it must not say, and the invocations of the fake.
UNUSABLE: dict[str, tuple[dict[str, str] | None, str, str, list[str]]] = {
    "kiro-cli-missing": (None, "に見つからない", "の版を読めなかった", []),
    "version-fails": ({"FAKE_KIRO_MODE": "version-fail"}, "の版を読めなかった", "に見つからない", ["--version"]),
}


@pytest.mark.parametrize(("variables", "said", "unsaid", "subcommands"), list(UNUSABLE.values()), ids=list(UNUSABLE))
def test_exit_code_6_prints_the_manual_display_of_each_queued_and_ready_change_item(
    handoff_sandbox: HandoffSandbox,
    variables: dict[str, str] | None,
    said: str,
    unsaid: str,
    subcommands: list[str],
) -> None:
    """Without a usable ``kiro-cli``: which of the two, the display of the one ready change item, and no write."""
    sb = handoff_sandbox
    before = prepare(sb)
    if variables is None:
        sb.kiro_cli.unlink()  # kiro-cli is not installed where config.json says

    done = run_selftest(sb, **(variables or {}))

    assert done.returncode == 6, (done.stdout, done.stderr)
    errors = done.stderr.splitlines()
    assert said in errors[0] and "変更モードの項目を手作業で渡すための表示に切り替える" in errors[0], errors
    assert unsaid not in done.stderr
    assert "status.json の selftest は変えていない" in errors
    assert f"{WAITING}: 依存先か参照が揃っていないので表示しない。揃ったら cli.py manual {WAITING}" in errors
    out = done.stdout
    assert out.count("手作業の引き継ぎ: ") == 1 and out.startswith(f"手作業の引き継ぎ: {CHANGE}\n"), out[:300]
    assert f"- モード: 変更モード（引き継ぎ用ブランチ handoff/{CHANGE}）" in out
    body = (sb.handoff_dir / "sync" / f"b-{REPO}.md").read_text(encoding="utf-8")
    assert out.endswith("----- ここから -----\n" + body + "----- ここまで -----\n")
    assert (sb.handoff_dir / "status.json").read_bytes() == before
    assert not (sb.handoff_dir / "selftest").exists() and not (sb.worktrees_root / "selftest").exists()
    assert [run["start"]["subcommand"] for run in sb.invocations()] == subcommands

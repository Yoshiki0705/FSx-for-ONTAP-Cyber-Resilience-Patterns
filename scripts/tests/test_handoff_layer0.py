"""Tests of layer 0 and of what holds a run before ``kiro-cli`` starts (T4-R2-02, T4-R2-03, T4-R2-07 to T4-R2-11).

- The profile of ``handoff.os_boundary`` and its probes. The ones that run ``sandbox-exec`` are for macOS and skip
  elsewhere; they try the profile on a throwaway tree, and each is shown to see a profile that does not bind (a
  permissive one, one without the ``hooks/`` denial, one that denies everything). No ``kiro-cli`` starts.
- A change item that does not say ``external_text: false`` is held, and so is one on a machine without a boundary.
- The shared git directory is compared between runs (``common-dir.json``), and a process that left its group is found.
- ``status --verify-log`` finds an edited or a removed line of ``status.log.jsonl``.
- What the diff of a change run counts as the execution surface, and the terminal colour of a secret.

The runs are ``cli.py run`` in the sandbox of ``conftest.py`` with the fake ``kiro-cli`` and the stand-in for
``sandbox-exec`` (``fixtures/handoff/fake-sandbox-exec``), as ``test_handoff_run_safety.py`` does.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import os_boundary as osb
from handoff import runner, state
from test_handoff_change_integration import (
    CHANGE,
    QUERY,
    history,
    prepare,
    read_status,
    record_selftest,
    run_change,
    run_cli,
)

if TYPE_CHECKING:
    from conftest import HandoffSandbox

REAL_BOUNDARY = sys.platform == "darwin" and os.access(osb.SANDBOX_EXEC, os.X_OK)
needs_sandbox_exec = pytest.mark.skipif(not REAL_BOUNDARY, reason="sandbox-exec exists on macOS only")


# ---------------------------------------------------------------------------------------------
# the profile and the choice of the boundary (pure)
# ---------------------------------------------------------------------------------------------


def test_the_profile_denies_what_a_run_must_not_read_or_write() -> None:
    """Credentials are closed for reading and writing, the control plane and the main trees for writing."""
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/Projects/r"], allow_write=["/w/run"])
    for name in (".ssh", ".aws", ".config/gh", ".gnupg"):
        assert f'(deny file-read* (subpath "/Users/u/{name}"))' in text
        assert f'(deny file-write* (subpath "/Users/u/{name}"))' in text
    for name in ("agents", "hooks", "settings", "steering"):
        assert f'(deny file-write* (subpath "/Users/u/.kiro/{name}"))' in text
    for name in (".zshrc", ".gitconfig"):
        assert f'(deny file-write* (literal "/Users/u/{name}"))' in text
    tree = "/Users/u/Projects/r"
    assert f'(deny file-write* (subpath "{tree}"))' in text
    assert f'(allow file-write* (subpath "{tree}/.git/objects"))' in text
    assert f'(deny file-write* (literal "{tree}/.git/config"))' in text
    assert f'(deny file-write* (subpath "{tree}/.git/hooks"))' in text
    assert text.index(f'(deny file-write* (subpath "{tree}"))') < text.index(
        f'(allow file-write* (subpath "{tree}/.git/objects"))'
    )
    # the later rule wins: the directory of the run is allowed after the denial of the trees, and the pointers of a
    # worktree (T4-R3-01) and the sockets (T4-R3-02) are denied after that allowance
    allowed = text.index('(allow file-write* (subpath "/w/run"))')
    assert allowed > text.index(f'(deny file-write* (subpath "{tree}"))')
    # (the regex that closes the git control files of every repository below home comes before the allowance, T4-R6-02)
    assert allowed < text.index('(deny file-write* (regex #"^/Users/u/Projects/r/\\.git/worktrees/')
    assert allowed < text.index("(deny network-outbound")


def test_the_profile_does_not_close_the_network() -> None:
    """``kiro-cli`` reaches its service over the network; a profile that closed it would stop every run."""
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"])
    # the only network rules concern a unix socket (T4-R3-02, T4-R4-02: closed, with the resolver and the log allowed);
    # no rule touches an address or a port
    rules = [line for line in text.splitlines() if "network" in line and not line.startswith(";;")]
    assert rules and all(
        line.startswith(("(deny network-outbound (remote unix-socket", "(allow network-outbound (remote unix-socket"))
        for line in rules
    )
    assert "remote ip" not in text and "remote tcp" not in text and "remote udp" not in text


@pytest.mark.parametrize("path", ['/Users/u"x', "/Users/u\\x", "/Users/u/../x", "relative", "/Users/u/x\n"])
def test_a_path_that_cannot_be_written_in_a_profile_is_refused(path: str) -> None:
    """A quotation mark, a backslash, a newline, ``..`` or a relative path would be read as something else."""
    with pytest.raises(ValueError):
        osb.build_profile(home="/Users/u", main_trees=[path])


def test_the_boundary_wraps_an_argv_and_names_the_profile() -> None:
    """The wrapped argv is ``sandbox-exec -f <profile> <command...>``."""
    boundary = osb.OsBoundary(program=osb.SANDBOX_EXEC)
    assert boundary.wrap(["kiro-cli", "chat"], "/p/x.sb") == (osb.SANDBOX_EXEC, "-f", "/p/x.sb", "kiro-cli", "chat")
    with pytest.raises(ValueError):
        boundary.wrap([], "/p/x.sb")
    with pytest.raises(ValueError):
        osb.OsBoundary(program="/x", verify=True, test_double=True)


def test_discover_chooses_sandbox_exec_on_macos_only() -> None:
    """The test double is named by a variable; without it only macOS with ``sandbox-exec`` has a boundary."""
    assert osb.discover({}, "darwin", True) == osb.OsBoundary(program=osb.SANDBOX_EXEC)
    assert osb.discover({}, "darwin", False) is None
    assert osb.discover({}, "linux", True) is None
    double = osb.discover({osb.TEST_DOUBLE_VARIABLE: "/t/fake"}, "linux", False)
    assert double == osb.OsBoundary(program="/t/fake", verify=False, test_double=True)
    assert osb.discover({osb.TEST_DOUBLE_VARIABLE: ""}, "linux", False) is None


def test_the_judge_counts_a_control_that_failed_and_a_denial_that_took_effect() -> None:
    """A profile that denies everything fails the controls; one that denies nothing fails the denials."""
    specs = osb.probes(home="/h", main_tree="/m", work="/w")
    controls = [probe for probe in specs if probe.must == "allowed"]
    denials = [probe for probe in specs if probe.must == "denied"]
    assert controls and denials
    good = [
        *(osb.ProbeResult(p.name, True, None if p.effect is None else True, True) for p in controls),
        *(osb.ProbeResult(p.name, False, None if p.effect is None else False, True) for p in denials),
    ]
    assert osb.judge(good, specs) == []
    nothing_denied = [osb.ProbeResult(p.name, True, True if p.effect else None, True) for p in specs]
    assert len(osb.judge(nothing_denied, specs)) == len(denials)
    all_denied = [osb.ProbeResult(p.name, False, False if p.effect else None, True) for p in specs]
    assert len(osb.judge(all_denied, specs)) == len(controls)
    # a denial that fails without the profile too says nothing about the profile
    broken_command = [*good[: len(controls)], *(osb.ProbeResult(p.name, False, None, False) for p in denials)]
    assert len(osb.judge(broken_command, specs)) == len(denials)
    assert osb.judge(good[:-1], specs) == [f"{specs[-1].name}: did not run"]


# ---------------------------------------------------------------------------------------------
# the profile, tried with the real sandbox-exec on a throwaway tree (macOS)
# ---------------------------------------------------------------------------------------------


@needs_sandbox_exec
def test_the_profile_binds_on_this_machine(tmp_path: Path) -> None:
    """Every control works and every denial fails under the profile, and works without it."""
    assert runner._verify_os_boundary(osb.OsBoundary(program=osb.SANDBOX_EXEC), str(tmp_path)) == []
    assert list(tmp_path.iterdir()) == []  # the throwaway tree is removed


@needs_sandbox_exec
def test_a_profile_that_denies_nothing_is_found_by_the_probes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A mutation: ``(allow default)`` only. Every denial probe reports that the operation took effect."""
    monkeypatch.setattr(osb, "build_profile", lambda **_: "(version 1)\n(allow default)\n")
    problems = runner._verify_os_boundary(osb.OsBoundary(program=osb.SANDBOX_EXEC), str(tmp_path))
    specs = osb.probes(home="/h", main_tree="/m", work="/w", objects="/o", prefix="/p")
    denials = [probe.name for probe in specs if probe.must == "denied"]
    named = [problem.split(":")[0] for problem in problems if not problem.startswith("deny-write-git-install")]
    assert sorted(named) == sorted(denials)


@needs_sandbox_exec
@pytest.mark.parametrize(
    ("dropped", "probe"),
    [
        ('/main"))', "deny-write-main-tree-file"),
        ('/main"))', "deny-write-main-branch-ref"),
        ("/.kiro/agents", "deny-write-kiro-agent"),
        ("/.kiro/hooks", "deny-write-kiro-hook"),
        ("/.aws", "deny-read-aws"),
        ("/.ssh", "deny-read-ssh"),
        ("/.zshrc", "deny-write-shell-startup"),
        ("refs/heads/handoff/item", "control-write-handoff-ref"),
        ('/agent-objects"))', "control-write-own-object-directory"),
        ("(deny network-outbound (remote unix-socket))", "deny-connect-plain-unix-socket"),
    ],
)
def test_a_profile_without_one_rule_is_found_by_the_probe_that_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dropped: str, probe: str
) -> None:
    """A mutation per rule: the profile with those lines removed fails the probe that depends on them."""
    real = osb.build_profile

    def without(**kwargs: Any) -> str:
        return "".join(line for line in real(**kwargs).splitlines(keepends=True) if dropped not in line)

    monkeypatch.setattr(osb, "build_profile", without)
    problems = runner._verify_os_boundary(osb.OsBoundary(program=osb.SANDBOX_EXEC), str(tmp_path))
    assert probe in {problem.split(":")[0] for problem in problems}


@needs_sandbox_exec
@pytest.mark.parametrize("dropped", ["/.git/hooks", "/.git/info", "/.git/config", "(deny file-write-unlink"])
def test_the_named_denials_of_the_common_git_directory_are_a_second_line_behind_the_closed_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dropped: str
) -> None:
    """Defence in depth: without the line that names ``hooks/``, ``info/``, ``config`` or the unlink below ``objects``, the tree's denial holds."""
    real = osb.build_profile

    def without(**kwargs: Any) -> str:
        return "".join(
            line
            for line in real(**kwargs).splitlines(keepends=True)
            if not (dropped in line and line.startswith("(deny"))
        )

    monkeypatch.setattr(osb, "build_profile", without)
    assert runner._verify_os_boundary(osb.OsBoundary(program=osb.SANDBOX_EXEC), str(tmp_path)) == []


@needs_sandbox_exec
def test_a_profile_that_denies_everything_fails_the_controls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The other mutation: a boundary that stops what a run needs does not pass for binding."""
    monkeypatch.setattr(osb, "build_profile", lambda **_: "(version 1)\n(allow default)\n(deny file-write*)\n")
    problems = runner._verify_os_boundary(osb.OsBoundary(program=osb.SANDBOX_EXEC), str(tmp_path))
    assert any(problem.startswith("control-write-worktree-file:") for problem in problems)


@needs_sandbox_exec
def test_a_command_under_the_profile_cannot_read_a_credential_and_can_read_its_worktree(tmp_path: Path) -> None:
    """The profile that the runner writes for a home and a worktree: a decoy below ``.ssh`` is closed."""
    root = Path(os.path.realpath(tmp_path))
    home, work, main = root / "home", root / "work", root / "main"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id").write_text("decoy", encoding="utf-8")
    work.mkdir()
    (work / "a.txt").write_text("fine", encoding="utf-8")
    (main / ".git").mkdir(parents=True)
    profile = root / "p.sb"
    profile.write_text(
        osb.build_profile(home=str(home), main_trees=[str(main)], allow_write=[str(work)]), encoding="utf-8"
    )
    boundary = osb.OsBoundary(program=osb.SANDBOX_EXEC)
    read = subprocess.run(
        boundary.wrap(["/bin/cat", str(home / ".ssh" / "id")], str(profile)), capture_output=True, check=False
    )
    control = subprocess.run(
        boundary.wrap(["/bin/cat", str(work / "a.txt")], str(profile)), capture_output=True, check=False
    )
    assert read.returncode != 0 and b"decoy" not in read.stdout
    assert control.returncode == 0 and control.stdout == b"fine"


# ---------------------------------------------------------------------------------------------
# T4-R2-02: an item that takes in text from outside this repository
# ---------------------------------------------------------------------------------------------


def edit_manifest(sb: HandoffSandbox, **fields: Any) -> None:
    """Set keys of the change item of ``manifest.json``; ``None`` removes the key."""
    path = sb.handoff_dir / "manifest.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    for item in document["items"]:
        if item["id"] == CHANGE:
            for key, value in fields.items():
                if value is None:
                    item.pop(key, None)
                else:
                    item[key] = value
    path.write_text(json.dumps(document), encoding="utf-8")


@pytest.mark.parametrize(
    ("value", "reason"),
    [(True, runner.EXTERNAL_TEXT_IN_CHANGE_MODE), (None, runner.EXTERNAL_TEXT_UNDECLARED)],
    ids=["takes-in-external-text", "does-not-say"],
)
def test_a_change_item_that_is_not_declared_free_of_external_text_is_held(
    handoff_sandbox: HandoffSandbox, value: bool | None, reason: str
) -> None:
    """``kiro-cli`` is not started; the item goes to a human with the reason, and the fake never ran ``chat``."""
    sb = handoff_sandbox
    prepare(sb)
    record_selftest(sb)
    edit_manifest(sb, external_text=value)
    seen = len(sb.invocations())
    done = run_cli(sb, "run", "--items", CHANGE)
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert history(read_status(sb), CHANGE)[-1] == (state.QUEUED, state.NEEDS_HUMAN, reason)
    assert "chat" not in [run["start"]["subcommand"] for run in sb.invocations()[seen:]]


def test_a_query_item_is_not_held_for_external_text(handoff_sandbox: HandoffSandbox) -> None:
    """The control: ``external_text`` is a rule of the change mode; a query item without it runs."""
    sb = handoff_sandbox
    prepare(sb)
    manifest = json.loads((sb.handoff_dir / "manifest.json").read_text(encoding="utf-8"))
    for item in manifest["items"]:
        item.pop("external_text", None)
    (sb.handoff_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    done = run_cli(sb, "run", "--items", QUERY)
    assert history(read_status(sb), QUERY)[-1][1] == state.SUCCEEDED, (done.stdout, done.stderr)


def test_the_manifest_refuses_an_external_text_that_is_not_a_boolean(handoff_sandbox: HandoffSandbox) -> None:
    """``"false"`` is not ``false``: the manifest is refused, and nothing starts."""
    sb = handoff_sandbox
    prepare(sb)
    edit_manifest(sb, external_text="false")
    done = run_cli(sb, "plan", "--items", CHANGE)
    assert done.returncode != 0
    assert "external_text" in done.stderr


# ---------------------------------------------------------------------------------------------
# T4-R2-03: layer 0 is required, and what it checks
# ---------------------------------------------------------------------------------------------


def test_a_change_item_is_held_when_the_machine_has_no_boundary(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No boundary on the machine: ``cli.py run`` holds the item with ``os_boundary_missing`` and starts no ``chat``."""
    from handoff import cli

    sb = handoff_sandbox
    prepare(sb)
    record_selftest(sb)
    sb.apply_environ(monkeypatch)
    monkeypatch.setattr(cli, "_discover_boundary", lambda: None)
    seen = len(sb.invocations())
    code = cli.main(["--handoff-dir", str(sb.handoff_dir), "run", "--items", CHANGE])
    assert code == 1, capsys.readouterr()
    assert history(read_status(sb), CHANGE)[-1] == (state.QUEUED, state.NEEDS_HUMAN, runner.OS_BOUNDARY_MISSING)
    assert "chat" not in [run["start"]["subcommand"] for run in sb.invocations()[seen:]]
    assert "sandbox-exec" in capsys.readouterr().err


def test_the_selftest_is_refused_without_a_boundary(handoff_sandbox: HandoffSandbox) -> None:
    """A selftest outside the boundary says nothing about a run inside it."""
    from test_handoff_selftest_integration import make_config

    sb = handoff_sandbox
    context = runner.SelftestContext(
        config=make_config(sb),
        home=str(sb.home),
        harness_tree=str(sb.harness_tree),
        session_worktrees_dir=str(sb.session_worktrees),
    )
    with runner.Harness.open(str(sb.handoff_dir)) as harness, pytest.raises(runner.SelftestRefused) as caught:
        harness.run_selftest(context)
    assert runner.OS_BOUNDARY_MISSING in str(caught.value)


def test_the_run_wraps_the_argv_of_a_change_item_and_writes_its_profile(handoff_sandbox: HandoffSandbox) -> None:
    """The fake runs under the stand-in, which refuses an argv without ``-f <profile>``; the profile exists afterwards."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit")
    assert history(ended.status, CHANGE)[-1][1] == state.SUCCEEDED, (ended.done.stdout, ended.done.stderr)
    profile = sb.handoff_dir / "os-boundary" / f"{CHANGE}.sb"
    text = profile.read_text(encoding="utf-8")
    assert f'(allow file-write* (subpath "{os.path.realpath(ended.worktree)}"))' in text
    assert os.stat(profile).st_mode & 0o777 == 0o600
    assert ended.report.count("test_double") >= 1  # the report says that the boundary was a stand-in


@pytest.mark.parametrize(("supported", "held"), [(["9.*"], True), (["0.*", "9.*"], False)])
def test_a_version_outside_kiro_cli_supported_versions_holds_the_change_item(
    handoff_sandbox: HandoffSandbox, supported: list[str], held: bool
) -> None:
    """The version that the selftest recorded must match one of the patterns."""
    sb = handoff_sandbox
    prepare(sb)
    record_selftest(sb)
    path = sb.handoff_dir / "config.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    config["kiro_cli_supported_versions"] = supported
    path.write_text(json.dumps(config), encoding="utf-8")
    version = read_status(sb)["selftest"]["kiro_cli_version"]
    assert version.startswith("0."), version  # the fake's version; the patterns are written for it
    done = run_cli(sb, "run", "--items", CHANGE, FAKE_KIRO_MODE="commit", FAKE_KIRO_COMMIT_FILES="docs/guide.md")
    last = history(read_status(sb), CHANGE)[-1]
    if held:
        assert last == (state.QUEUED, state.NEEDS_HUMAN, runner.KIRO_CLI_VERSION_UNSUPPORTED), done.stderr
    else:
        assert last[1] != state.NEEDS_HUMAN or last[2] != runner.KIRO_CLI_VERSION_UNSUPPORTED


def test_the_configuration_checks_kiro_cli_supported_versions(handoff_sandbox: HandoffSandbox) -> None:
    """A list of patterns, or the key absent; not a string and not a list with an empty or spaced entry."""
    from test_handoff_selftest_integration import make_config

    sb = handoff_sandbox
    assert make_config(sb).kiro_cli_supported_versions == ()
    assert make_config(sb, kiro_cli_supported_versions=["2.32.*"]).kiro_cli_supported_versions == ("2.32.*",)
    for bad in ("2.32.*", [""], ["2.32 *"], [3]):
        with pytest.raises(Exception, match="kiro_cli_supported_versions"):
            make_config(sb, kiro_cli_supported_versions=bad)


# ---------------------------------------------------------------------------------------------
# T4-R2-08: the shared git directory between runs, and a process that left its group
# ---------------------------------------------------------------------------------------------


def test_a_change_of_the_shared_git_directory_between_two_runs_holds_the_next_run(
    handoff_sandbox: HandoffSandbox,
) -> None:
    """The write comes after the first run and before the second: the second run's own start would take it in."""
    sb = handoff_sandbox
    first = run_change(sb, "commit,undeclared")  # ends needs-human, so that the item can be queued again
    assert history(first.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, "undeclared_files")
    recorded = json.loads((sb.handoff_dir / runner.COMMON_DIR_RECORD).read_text(encoding="utf-8"))
    assert set(recorded) == {"example-hub"}
    sb.git("-C", str(sb.main_tree), "config", "alias.zz", "!echo planted")  # between the runs
    assert run_cli(sb, "cleanup", CHANGE, "--approved").returncode == 0
    sb.git("-C", str(sb.main_tree), "branch", "-D", f"handoff/{CHANGE}")
    assert run_cli(sb, "status", "set", CHANGE, "queued", "--reason", "retry").returncode == 0
    seen = len(sb.invocations())
    second = run_cli(sb, "run", "--items", CHANGE, FAKE_KIRO_MODE="commit")
    assert history(read_status(sb), CHANGE)[-1] == (
        state.QUEUED,
        state.NEEDS_HUMAN,
        runner.COMMON_DIR_CHANGED_BETWEEN_RUNS,
    ), second.stderr
    assert "chat" not in [run["start"]["subcommand"] for run in sb.invocations()[seen:]]
    # the maintainer reads the directory and accepts it; the next run starts
    accepted = run_cli(sb, "status", "accept-common-dir", "example-hub")
    assert accepted.returncode == 0, accepted.stderr
    assert run_cli(sb, "cleanup", CHANGE, "--approved").returncode == 0
    sb.git(
        "-C", str(sb.main_tree), "branch", "-D", f"handoff/{CHANGE}", check=False
    )  # the held run made none with a commit
    assert run_cli(sb, "status", "set", CHANGE, "queued", "--reason", "after reading the git directory").returncode == 0
    third = run_cli(sb, "run", "--items", CHANGE, FAKE_KIRO_MODE="commit")
    assert history(read_status(sb), CHANGE)[-1][2] != runner.COMMON_DIR_CHANGED_BETWEEN_RUNS, third.stderr


def test_a_second_item_of_the_same_repository_is_not_held_by_the_branch_entries_of_the_first(
    handoff_sandbox: HandoffSandbox,
) -> None:
    """``worktree add -b`` and ``--set-upstream-to`` write ``branch.<name>.*`` into the shared ``config``.

    The digest of the last run's end holds the first item's entries, so a digest taken after the next
    item's own ``worktree add`` could never match it (2026-11-15: ``c-hub-supply-chain-resync-2`` was held
    with nothing written by anyone else). The comparison is made before the worktree is made.
    """
    sb = handoff_sandbox
    first = run_change(sb, "commit,undeclared")
    assert history(first.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, "undeclared_files")
    manifest = json.loads((sb.handoff_dir / "manifest.json").read_text(encoding="utf-8"))
    second = dict(next(entry for entry in manifest["items"] if entry["id"] == CHANGE), id="c-hub-change-two")
    manifest["items"].append(second)
    (sb.handoff_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    done = run_cli(sb, "run", "--items", "c-hub-change-two", FAKE_KIRO_MODE="commit", FAKE_KIRO_COMMIT_FILES="docs/guide.md")
    held = [entry for entry in history(read_status(sb), "c-hub-change-two") if entry[2] == runner.COMMON_DIR_CHANGED_BETWEEN_RUNS]
    assert held == [], done.stderr


def test_a_run_that_changed_the_shared_git_directory_leaves_the_earlier_record(handoff_sandbox: HandoffSandbox) -> None:
    """The digest is kept only after a run that did not change it: the next run is held until it is accepted."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit,git-config-alias")
    assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, "common_dir_changed")
    record = json.loads((sb.handoff_dir / runner.COMMON_DIR_RECORD).read_text(encoding="utf-8"))["example-hub"]
    now = run_cli(sb, "status", "accept-common-dir", "example-hub")
    assert now.returncode == 0 and record["sha256"] in now.stdout  # the earlier digest is the one that was recorded


def test_a_process_that_left_the_group_in_the_worktree_is_found_after_the_run(handoff_sandbox: HandoffSandbox) -> None:
    """``setsid`` puts it outside the group that the runner stops; its directory is the worktree's."""
    sb = handoff_sandbox
    ended = run_change(sb, "commit,setsid-orphan")
    pids = [
        int(name.split(":")[1])
        for name in ended.record["observations"]["control_plane_changed"]
        if name.startswith("orphan_process:")
    ]
    try:
        assert history(ended.status, CHANGE)[-1] == (state.RUNNING, state.NEEDS_HUMAN, "control_plane_changed")
        assert len(pids) == 1
    finally:
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_a_run_that_leaves_no_process_is_not_flagged(handoff_sandbox: HandoffSandbox) -> None:
    """The control of the test above."""
    ended = run_change(handoff_sandbox, "commit")
    assert ended.record["observations"]["control_plane_changed"] == []

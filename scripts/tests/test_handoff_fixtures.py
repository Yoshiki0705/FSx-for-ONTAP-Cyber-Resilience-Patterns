"""Check the fixtures of the Handoff_Harness tests: the fake ``kiro-cli`` and the git sandbox.

The integration tests of the runner (tasks 2.4 and 5.2 to 5.4) start the fake ``kiro-cli``
(``fixtures/handoff/fake-kiro-cli``) in the ``handoff_sandbox`` of ``conftest.py``. This file
shows that the sandbox has the layout its docstring describes and that each behavior of the
fake does what the fake's docstring says. The fake runs under the environment that
``handoff.command.child_env`` builds (layer 3 of design section 20) and, where layer 3
decides the outcome, also without it as a control: a push to ``origin`` arrives without
layer 3 and does not arrive with it, and made-up credentials reach the fake without layer 3
and do not reach it with it. The harness itself is not tested here. The tests at the end
check what the fake offers the selftest of task 5.2: behaviors chosen per trial by the
prompt's token, the operations of the trials, and the entries of the guard wrapper.

No test uses the network or the real ``kiro-cli``. Every git command runs in the sandbox,
which each test builds anew in a temporary directory and removes.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

import pytest
from handoff import command

if TYPE_CHECKING:
    from conftest import HandoffSandbox

#: The tracked fake, found from this file rather than from ``conftest.py``.
FAKE = Path(__file__).resolve().parent / "fixtures" / "handoff" / "fake-kiro-cli"

MIB = 1024 * 1024

#: Made-up credentials, in the variables that layer 3 must keep from a child.
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

#: A prompt whose quotes, backticks and ``$`` would mean something to a shell.
PROMPT = 'Answer in one line.\n"Quotes", `backticks`, $HOME and $(date) stay text.\n日本語の行。'

#: The ``GIT_CONFIG_*`` entries that ``child_env`` sets, without the push URL.
PUSH_URL_RESET = {
    "GIT_CONFIG_COUNT": "2",
    "GIT_CONFIG_KEY_0": "remote.origin.pushurl",
    "GIT_CONFIG_VALUE_0": "",
    "GIT_CONFIG_KEY_1": "remote.origin.pushurl",
}


def run_fake(
    argv: Sequence[str], *, cwd: Path, env: dict[str, str], timeout: float = 60.0
) -> subprocess.CompletedProcess[bytes]:
    """Run the fake as the runner will: argv, no shell, a new session, both streams captured."""
    return subprocess.run(
        list(argv),
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        start_new_session=True,
        check=False,
    )


def chat_argv(sandbox: HandoffSandbox, *options: str, prompt: str = PROMPT) -> list[str]:
    """Build a ``chat`` argv of the form that ``command.build_kiro_argv`` builds."""
    return [str(sandbox.kiro_cli), "chat", "--no-interactive", *options, prompt]


def child_environment(sandbox: HandoffSandbox, **extra: str) -> tuple[dict[str, str], dict[str, str]]:
    """Build a child environment with ``command.child_env``.

    Returns:
        The environment and the temporary paths given to ``child_env``.
    """
    paths = sandbox.child_env_paths()
    return command.child_env(sandbox.environ(**extra), **paths), paths


def add_worktree(sandbox: HandoffSandbox, name: str, *, branch: str | None = None) -> Path:
    """Add a worktree of the main working tree at ``base_sha``, as the runner will.

    Args:
        sandbox: The sandbox.
        name: The directory name below ``worktrees_root/<repo>/``.
        branch: A new branch for a change item, or ``None`` for a detached query worktree.

    Returns:
        The worktree's path.
    """
    path = sandbox.worktrees_root / sandbox.repo / name
    where = ["-b", branch] if branch is not None else ["--detach"]
    sandbox.git("-C", str(sandbox.main_tree), "worktree", "add", "-q", *where, str(path), sandbox.base_sha)
    return path


def only_run(sandbox: HandoffSandbox) -> dict[str, dict[str, Any]]:
    """Return the one run in the record."""
    runs = sandbox.invocations()
    assert len(runs) == 1, runs
    return runs[0]


def text(completed: subprocess.CompletedProcess[bytes]) -> str:
    """Return a command's standard output as stripped text."""
    return completed.stdout.decode("utf-8").strip()


def wait_until(condition: Callable[[], bool], seconds: float, what: str) -> None:
    """Poll a condition until it holds; fail after ``seconds``."""
    deadline = time.monotonic() + seconds
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.02)


def sha256(data: bytes) -> str:
    """Return the SHA-256 of bytes, as the record writes it."""
    return hashlib.sha256(data).hexdigest()


def test_the_fake_is_an_executable_standard_library_script(handoff_sandbox: HandoffSandbox) -> None:
    """The tracked fake runs through its shebang, imports the standard library only, and the sandbox copy keeps its mode."""
    assert FAKE.is_file()
    assert os.access(FAKE, os.X_OK), "the fake lost its executable bit; git must track it as mode 100755"
    source = FAKE.read_text(encoding="utf-8")
    assert source.splitlines()[0] == "#!/usr/bin/env python3"
    ast.parse(source, feature_version=(3, 8))
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported, "no import was found, so the check below would pass on anything"
    assert imported <= set(sys.stdlib_module_names), sorted(imported - set(sys.stdlib_module_names))
    assert handoff_sandbox.kiro_cli.read_bytes() == FAKE.read_bytes()
    assert os.access(handoff_sandbox.kiro_cli, os.X_OK)


def test_the_sandbox_has_a_bare_remote_and_a_clone_with_uncommitted_changes(handoff_sandbox: HandoffSandbox) -> None:
    """The bare repository holds ``main``; the clone tracks it and holds the dirty entries; the other places are empty."""
    sandbox = handoff_sandbox
    bare, main = str(sandbox.bare), str(sandbox.main_tree)
    assert text(sandbox.git("-C", bare, "rev-parse", "--is-bare-repository")) == "true"
    assert text(sandbox.git("-C", bare, "symbolic-ref", "HEAD")) == "refs/heads/main"
    assert text(sandbox.git("-C", bare, "for-each-ref", "--format=%(refname) %(objectname)")) == (
        f"refs/heads/main {sandbox.base_sha}"
    )
    assert sandbox.git("-C", bare, "config", "--get-regexp", "^remote[.]", check=False).returncode == 1
    assert text(sandbox.git("-C", main, "remote", "get-url", "origin")) == bare
    assert text(sandbox.git("-C", main, "branch", "--show-current")) == "main"
    assert (
        text(sandbox.git("-C", main, "rev-parse", "HEAD", "refs/remotes/origin/main")).split() == [sandbox.base_sha] * 2
    )
    for untracked in ("normal", "all"):
        status = sandbox.git("-C", main, "status", "--porcelain=v1", "-z", f"--untracked-files={untracked}").stdout
        entries = {(entry[:2], entry[3:]) for entry in status.decode("utf-8").split("\0") if entry}
        assert entries == set(sandbox.main_tree_dirty), untracked
    for repository in (bare, main):
        assert text(sandbox.git("-C", repository, "config", "--get", "core.hooksPath")) == str(sandbox.hooks_dir)
    assert text(sandbox.git("-C", main, "config", "--get", "user.email")).endswith("@example.com")
    for directory in (sandbox.worktrees_root, sandbox.session_worktrees, sandbox.handoff_dir, sandbox.hooks_dir):
        assert directory.is_dir() and not any(directory.iterdir()), directory
    assert sandbox.handoff_dir.parts[-2:] == (".private", "handoff")
    assert not sandbox.record.exists()
    assert os.path.realpath(sandbox.root) == str(sandbox.root)
    for path in (
        sandbox.main_tree,
        sandbox.harness_tree,
        sandbox.worktrees_root,
        sandbox.session_worktrees,
        sandbox.kiro_cli,
    ):
        assert path.is_relative_to(sandbox.home), path
    assert sandbox.home.is_relative_to(sandbox.root) and sandbox.bare.is_relative_to(sandbox.root)


def test_git_in_the_sandbox_and_in_a_child_reads_no_global_configuration(handoff_sandbox: HandoffSandbox) -> None:
    """The sandbox's git has an empty global configuration, and a child under layer 3 has the sandbox ``HOME``."""
    sandbox = handoff_sandbox
    assert sandbox.git("config", "--global", "--list", check=False).stdout == b""
    child, _ = child_environment(sandbox)
    assert "GIT_CONFIG_GLOBAL" not in child and "GIT_CONFIG_NOSYSTEM" not in child
    home = subprocess.run(
        [sys.executable, "-c", "import os, sys; sys.stdout.write(os.environ['HOME'])"],
        env=child,
        capture_output=True,
        text=True,
        check=True,
    )
    assert home.stdout == str(sandbox.home)
    listed = subprocess.run(
        ["git", "config", "--global", "--list"], cwd=sandbox.main_tree, env=child, capture_output=True, check=False
    )
    assert listed.stdout == b""
    origin = subprocess.run(
        ["git", "config", "--show-origin", "--get", "core.hooksPath"],
        cwd=sandbox.main_tree,
        env=child,
        capture_output=True,
        text=True,
        check=True,
    )
    assert origin.stdout.strip() == f"file:.git/config\t{sandbox.hooks_dir}"


@pytest.mark.parametrize(("mode", "code"), [("", 0), ("whoami-fail", 1)], ids=["logged-in", "whoami-fail"])
def test_whoami_exits_1_with_whoami_fail_only(
    handoff_sandbox: HandoffSandbox, fake_kiro_cli_module: ModuleType, mode: str, code: int
) -> None:
    """``whoami`` succeeds by default and fails with exit code 1 under ``whoami-fail``."""
    sandbox = handoff_sandbox
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE=mode)
    done = run_fake([str(sandbox.kiro_cli), "whoami"], cwd=sandbox.root, env=env)
    assert done.returncode == code
    if code == 0:
        assert (done.stdout, done.stderr) == (fake_kiro_cli_module.WHOAMI_TEXT.encode("ascii"), b"")
    else:
        assert (done.stdout, done.stderr) == (b"", fake_kiro_cli_module.NOT_LOGGED_IN_TEXT.encode("ascii"))
    run = only_run(sandbox)
    assert run["start"]["subcommand"] == "whoami"
    assert run["start"]["argv"] == [str(sandbox.kiro_cli), "whoami"]
    assert (run["end"]["exit_code"], run["end"]["error"]) == (code, None)


def test_chat_records_its_argv_cwd_and_a_child_environment_without_credentials(
    handoff_sandbox: HandoffSandbox, fake_kiro_cli_module: ModuleType
) -> None:
    """Under layer 3 the record shows the argv, the worktree, the push URL override and no credential."""
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "query-item")
    env, paths = child_environment(sandbox, **SECRETS)
    argv = chat_argv(sandbox, "--trust-tools=fs_read")
    done = run_fake(argv, cwd=worktree, env=env)
    assert done.returncode == 0, done.stderr
    assert (done.stdout, done.stderr) == (fake_kiro_cli_module.DEFAULT_ANSWER.encode("ascii"), b"")
    run = only_run(sandbox)
    start, end = run["start"], run["end"]
    assert start["argv"] == argv
    assert start["cwd"] == str(worktree)
    assert start["subcommand"] == "chat"
    assert start["options"] == {
        "no_interactive": True,
        "trust_tools": ["fs_read"],
        "trust_all_tools": None,
        "agent": None,
    }
    assert start["prompt"] == PROMPT
    assert start["sid"] == start["pgid"] == start["pid"]
    summary = start["env"]
    assert summary["git_config"] == {**PUSH_URL_RESET, "GIT_CONFIG_VALUE_1": paths["push_url"]}
    names = set(summary["names"])
    assert {name for name in names if name.startswith("AWS_")} == {
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_EC2_METADATA_DISABLED",
    }
    assert {name for name in names if name.startswith(("GH_", "GITHUB_"))} == {"GH_CONFIG_DIR"}
    assert {name for name in names if name.startswith("GIT_")} == set(PUSH_URL_RESET) | {"GIT_CONFIG_VALUE_1"}
    assert not names & {"PWD", "OLDPWD"}
    assert {"HOME", "PATH", "FAKE_KIRO_RECORD"} <= names
    assert summary["gh_config_dir"] == "empty"
    assert summary["aws_config_file"] == summary["aws_shared_credentials_file"] == "empty"
    assert summary["aws_ec2_metadata_disabled"] is True
    assert (end["exit_code"], end["results"], end["error"]) == (0, [], None)
    assert end["stdout"] == {"bytes": len(done.stdout), "sha256": sha256(done.stdout)}
    assert end["stderr"] == {"bytes": 0, "sha256": sha256(b"")}
    recorded = sandbox.record.read_text(encoding="ascii")
    assert not [name for name, value in SECRETS.items() if value in recorded]
    assert os.path.expanduser("~") not in recorded


def test_without_layer_3_the_credentials_reach_the_fake_but_not_the_record(handoff_sandbox: HandoffSandbox) -> None:
    """The control: without ``child_env`` the made-up credentials reach the fake, and the record holds their names only."""
    sandbox = handoff_sandbox
    done = run_fake(chat_argv(sandbox, "--trust-tools=fs_read"), cwd=sandbox.root, env=sandbox.environ(**SECRETS))
    assert done.returncode == 0, done.stderr
    summary = only_run(sandbox)["start"]["env"]
    assert set(SECRETS) <= set(summary["names"])
    assert summary["git_config"] == {}
    assert (summary["gh_config_dir"], summary["aws_config_file"], summary["aws_ec2_metadata_disabled"]) == (
        "unset",
        "unset",
        False,
    )
    recorded = sandbox.record.read_text(encoding="ascii")
    assert not [name for name, value in SECRETS.items() if value in recorded]


#: ``(id, argv after the program, extra variables)`` that the fake must refuse with exit code 2.
REFUSED: tuple[tuple[str, list[str], dict[str, str]], ...] = (
    ("unknown-option", ["chat", "--no-interactive", "--model", "m", "p"], {}),
    ("unknown-flag", ["chat", "--no-interactive", "--verbose", "p"], {}),
    ("interactive", ["chat", "p"], {}),
    ("no-prompt", ["chat", "--no-interactive"], {}),
    ("two-prompts", ["chat", "--no-interactive", "a", "b"], {}),
    ("trust-tools-without-equals", ["chat", "--no-interactive", "--trust-tools", "fs_read", "p"], {}),
    ("agent-without-a-name", ["chat", "--no-interactive", "p", "--agent"], {}),
    ("unknown-subcommand", ["login"], {}),
    ("no-subcommand", [], {}),
    ("whoami-with-arguments", ["whoami", "--format", "json"], {}),
    ("unknown-behavior", ["chat", "--no-interactive", "p"], {"FAKE_KIRO_MODE": "commit,no-such-behavior"}),
    ("sleep-not-finite", ["chat", "--no-interactive", "p"], {"FAKE_KIRO_SLEEP_SECONDS": "nan"}),
    ("noise-negative", ["chat", "--no-interactive", "p"], {"FAKE_KIRO_NOISE_BYTES": "-1"}),
    ("exit-code-too-large", ["chat", "--no-interactive", "p"], {"FAKE_KIRO_EXIT_CODE": "256"}),
    ("file-above", ["chat", "--no-interactive", "p"], {"FAKE_KIRO_COMMIT_FILES": "../outside.txt"}),
    ("file-absolute", ["chat", "--no-interactive", "p"], {"FAKE_KIRO_COMMIT_FILES": "/outside.txt"}),
    ("file-dot-dot", ["chat", "--no-interactive", "p"], {"FAKE_KIRO_COMMIT_FILES": "docs/../x.txt"}),
    ("file-in-dot-git", ["chat", "--no-interactive", "p"], {"FAKE_KIRO_COMMIT_FILES": ".git/config"}),
    ("file-empty", ["chat", "--no-interactive", "p"], {"FAKE_KIRO_COMMIT_FILES": "a.txt,,b.txt"}),
)

#: ``(id, argv after the program, parsed options, prompt)`` that the fake must accept.
ACCEPTED: tuple[tuple[str, list[str], dict[str, Any], str], ...] = (
    (
        "trust-all-agent-and-double-dash",
        ["chat", "--no-interactive", "--trust-all-tools", "--agent", "handoff-query", "--", "-a dash first"],
        {"no_interactive": True, "trust_tools": None, "trust_all_tools": "--trust-all-tools", "agent": "handoff-query"},
        "-a dash first",
    ),
    (
        "short-trust-all-and-agent-equals",
        ["chat", "-a", "--agent=handoff-change", "--no-interactive", "p"],
        {"no_interactive": True, "trust_tools": None, "trust_all_tools": "-a", "agent": "handoff-change"},
        "p",
    ),
    (
        "trust-nothing",
        ["chat", "--no-interactive", "--trust-tools=", "p"],
        {"no_interactive": True, "trust_tools": [], "trust_all_tools": None, "agent": None},
        "p",
    ),
    (
        "two-tools",
        ["chat", "--no-interactive", "--trust-tools=fs_read,fs_write", "p"],
        {"no_interactive": True, "trust_tools": ["fs_read", "fs_write"], "trust_all_tools": None, "agent": None},
        "p",
    ),
)


def test_the_fake_refuses_what_the_harness_does_not_build(handoff_sandbox: HandoffSandbox) -> None:
    """Each usage error exits 2 before any behavior, records the argv, and writes nothing in the working directory.

    The cases of :data:`REFUSED` share one sandbox and one worktree, so that the git
    processes of a sandbox are paid once. Each case must leave the worktree as it was and add
    exactly one run to the record.
    """
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "refused-item")
    for index, (case, args, extra) in enumerate(REFUSED):
        env, _ = child_environment(sandbox, **{"FAKE_KIRO_MODE": "commit", **extra})
        done = run_fake([str(sandbox.kiro_cli), *args], cwd=worktree, env=env)
        assert done.returncode == 2, case
        assert done.stdout == b"", case
        assert done.stderr.startswith(b"fake kiro-cli: usage: "), case
        runs = sandbox.invocations()
        assert len(runs) == index + 1, case
        start, end = runs[-1]["start"], runs[-1]["end"]
        assert start["argv"] == [str(sandbox.kiro_cli), *args], case
        assert (end["exit_code"], end["results"]) == (2, []), case
        assert end["error"].startswith("usage: "), case
        assert text(sandbox.git("-C", str(worktree), "rev-parse", "HEAD")) == sandbox.base_sha, case
        assert sandbox.git("-C", str(worktree), "status", "--porcelain").stdout == b"", case
        assert sorted(worktree.parent.iterdir()) == [worktree], case


def test_the_fake_accepts_the_forms_the_harness_may_build(handoff_sandbox: HandoffSandbox) -> None:
    """Each ``chat`` form of :data:`ACCEPTED`, which ``build_kiro_argv`` can build, is accepted and recorded as parsed."""
    sandbox = handoff_sandbox
    env, _ = child_environment(sandbox)
    for index, (case, args, options, prompt) in enumerate(ACCEPTED):
        done = run_fake([str(sandbox.kiro_cli), *args], cwd=sandbox.root, env=env)
        assert done.returncode == 0, (case, done.stderr)
        start = sandbox.invocations()[index]["start"]
        assert (start["options"], start["prompt"]) == (options, prompt), case


def test_version_prints_the_fake_version(handoff_sandbox: HandoffSandbox, fake_kiro_cli_module: ModuleType) -> None:
    """``--version`` answers like ``kiro-cli --version`` with a version that no real release has."""
    sandbox = handoff_sandbox
    env, _ = child_environment(sandbox)
    done = run_fake([str(sandbox.kiro_cli), "--version"], cwd=sandbox.root, env=env)
    assert (done.returncode, done.stdout) == (0, fake_kiro_cli_module.VERSION_TEXT.encode("ascii"))
    assert done.stdout.startswith(b"kiro-cli ")


def test_noise_writes_a_mebibyte_that_is_not_utf8_to_each_stream(
    handoff_sandbox: HandoffSandbox, fake_kiro_cli_module: ModuleType
) -> None:
    """Each stream gets 1 MiB of its own payload, which is not UTF-8 and decodes differently in pieces than whole."""
    sandbox = handoff_sandbox
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="noise", FAKE_KIRO_ANSWER="")
    done = run_fake(chat_argv(sandbox), cwd=sandbox.root, env=env)
    assert done.returncode == 0
    assert done.stdout != done.stderr
    for stream, data in (("stdout", done.stdout), ("stderr", done.stderr)):
        assert len(data) == MIB, stream
        assert data == fake_kiro_cli_module.noise_payload(stream, MIB), stream
        with pytest.raises(UnicodeDecodeError):
            data.decode("utf-8")
        whole = data.decode("utf-8", "replace")
        assert "\ufffd" in whole and "日本語の行。" in whole
        for piece in (4096, 8192, 16384, 32768, 65536):
            in_pieces = "".join(data[at : at + piece].decode("utf-8", "replace") for at in range(0, len(data), piece))
            assert in_pieces != whole, f"{stream} decodes the same in {piece}-byte pieces as whole"
    end = only_run(sandbox)["end"]
    assert end["stdout"] == {"bytes": MIB, "sha256": sha256(done.stdout)}
    assert end["stderr"] == {"bytes": MIB, "sha256": sha256(done.stderr)}
    assert end["results"] == [
        {"behavior": "noise", "bytes": MIB, "sha256": {"stdout": sha256(done.stdout), "stderr": sha256(done.stderr)}}
    ]


def test_noise_blocks_a_reader_that_drains_standard_output_first(handoff_sandbox: HandoffSandbox) -> None:
    """With nobody reading standard error, the fake stops writing before standard output is complete."""
    sandbox = handoff_sandbox
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="noise", FAKE_KIRO_ANSWER="")
    process = subprocess.Popen(
        chat_argv(sandbox),
        cwd=sandbox.root,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    received = [0]
    finished = threading.Event()

    def drain_stdout() -> None:
        assert process.stdout is not None
        while chunk := os.read(process.stdout.fileno(), 65536):
            received[0] += len(chunk)
        finished.set()

    reader = threading.Thread(target=drain_stdout, daemon=True)
    reader.start()
    try:
        wait_until(lambda: received[0] > 0, 15, "the first bytes on standard output")
        settled = -1
        while settled != received[0]:
            settled = received[0]
            time.sleep(0.3)
        assert 0 < settled < MIB
        assert not finished.is_set()
        assert process.poll() is None
    finally:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
        reader.join(timeout=10)
        process.stdout.close()
        process.stderr.close()
    assert finished.is_set()


@pytest.mark.parametrize("ignore_sigterm", [False, True], ids=["sigterm", "sigterm-ignored"])
def test_sleep_starts_a_child_in_its_process_group_that_goes_with_the_group(
    handoff_sandbox: HandoffSandbox, ignore_sigterm: bool
) -> None:
    """The child's PID is recorded, it shares the fake's process group, and a signal to the group ends both."""
    sandbox = handoff_sandbox
    mode = "ignore-sigterm,sleep" if ignore_sigterm else "sleep"
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE=mode, FAKE_KIRO_SLEEP_SECONDS="60")
    process = subprocess.Popen(
        chat_argv(sandbox),
        cwd=sandbox.root,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    child: int | None = None
    try:
        wait_until(lambda: any("spawned" in run for run in sandbox.invocations()), 15, "the spawned event")
        spawned = only_run(sandbox)["spawned"]
        child = spawned["child_pid"]
        assert child != process.pid
        assert spawned["child_ready"] is True
        assert spawned["child_pgid"] == os.getpgid(child) == process.pid
        assert sandbox.process_running(child)
        os.killpg(process.pid, signal.SIGTERM)
        if ignore_sigterm:
            with pytest.raises(subprocess.TimeoutExpired):
                process.wait(timeout=0.5)
            assert sandbox.process_running(child)
            os.killpg(process.pid, signal.SIGKILL)
            assert process.wait(timeout=10) == -signal.SIGKILL
        else:
            assert process.wait(timeout=10) == -signal.SIGTERM
        wait_until(lambda: not sandbox.process_running(child), 10, "the child to go")
        assert "end" not in only_run(sandbox)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        if child is not None and sandbox.process_running(child):
            os.kill(child, signal.SIGKILL)


def test_sleep_that_ends_by_itself_reaps_its_child(handoff_sandbox: HandoffSandbox) -> None:
    """A sleep shorter than any timeout ends with exit code 0 and leaves no child."""
    sandbox = handoff_sandbox
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="sleep", FAKE_KIRO_SLEEP_SECONDS="0.2")
    done = run_fake(chat_argv(sandbox), cwd=sandbox.root, env=env)
    assert done.returncode == 0, done.stderr
    run = only_run(sandbox)
    child = run["spawned"]["child_pid"]
    assert run["spawned"]["child_ready"] is True
    assert run["end"]["results"] == [{"behavior": "sleep", "seconds": 0.2, "child_pid": child}]
    assert not sandbox.process_running(child)


@pytest.mark.parametrize(
    ("mode", "files", "commits"),
    [
        pytest.param("commit", None, [["fake-kiro-change.txt"]], id="commit"),
        pytest.param("undeclared", None, [["fake-kiro-undeclared.txt"]], id="undeclared"),
        pytest.param(
            "commit,undeclared",
            None,
            [["fake-kiro-change.txt"], ["fake-kiro-undeclared.txt"]],
            id="commit-and-undeclared",
        ),
        pytest.param(
            "commit", "docs/added.md,docs/sub/deep.md", [["docs/added.md", "docs/sub/deep.md"]], id="named-files"
        ),
    ],
)
def test_commit_behaviors_commit_in_the_worktree_and_nowhere_else(
    handoff_sandbox: HandoffSandbox, mode: str, files: str | None, commits: list[list[str]]
) -> None:
    """Each commit behavior adds one commit of its files on the worktree's branch; the main tree and the remote stay as they were."""
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "change-item", branch="handoff/change-item")
    before = sandbox.snapshot_main_tree()
    extra = {"FAKE_KIRO_MODE": mode, **({} if files is None else {"FAKE_KIRO_COMMIT_FILES": files})}
    env, _ = child_environment(sandbox, **extra)
    done = run_fake(chat_argv(sandbox, "--trust-tools=fs_read,fs_write"), cwd=worktree, env=env)
    assert done.returncode == 0, done.stderr
    wt = str(worktree)
    log = text(sandbox.git("-C", wt, "log", "--reverse", "--format=%H", f"{sandbox.base_sha}..HEAD")).split()
    results = only_run(sandbox)["end"]["results"]
    assert [result["commit"] for result in results] == log
    assert [result["files"] for result in results] == commits
    for commit, expected in zip(log, commits, strict=True):
        changed = text(sandbox.git("-C", wt, "diff-tree", "--no-commit-id", "--name-only", "-r", commit)).split()
        assert sorted(changed) == sorted(expected)
    assert text(sandbox.git("-C", wt, "branch", "--show-current")) == "handoff/change-item"
    assert sandbox.git("-C", wt, "status", "--porcelain").stdout == b""
    assert sandbox.snapshot_main_tree() == before
    assert text(sandbox.git("-C", str(sandbox.bare), "for-each-ref", "--format=%(refname)")) == "refs/heads/main"


@pytest.mark.parametrize(
    ("behavior", "layer_3", "push_url_configured", "arrives"),
    [
        pytest.param("push", True, False, False, id="origin-under-layer-3"),
        pytest.param("push", True, True, False, id="origin-under-layer-3-with-a-configured-pushurl"),
        pytest.param("push", False, False, True, id="origin-without-layer-3"),
        pytest.param("push-url", True, False, True, id="url-under-layer-3"),
    ],
)
def test_a_push_arrives_only_where_layer_3_does_not_reach(
    handoff_sandbox: HandoffSandbox, behavior: str, layer_3: bool, push_url_configured: bool, arrives: bool
) -> None:
    """Layer 3 stops a push to ``origin``, even over a configured push URL; without it, or to an explicit URL, the ref arrives."""
    sandbox = handoff_sandbox
    if push_url_configured:
        sandbox.git("-C", str(sandbox.main_tree), "config", "remote.origin.pushurl", str(sandbox.bare))
    worktree = add_worktree(sandbox, "push-item", branch="handoff/push-item")
    extra = {"FAKE_KIRO_MODE": f"commit,{behavior}"}
    env = child_environment(sandbox, **extra)[0] if layer_3 else sandbox.environ(**extra)
    done = run_fake(chat_argv(sandbox, "--trust-tools=fs_read,fs_write"), cwd=worktree, env=env)
    assert done.returncode == 0, done.stderr
    commit, push = only_run(sandbox)["end"]["results"]
    head = text(sandbox.git("-C", str(worktree), "rev-parse", "HEAD"))
    ref = "refs/heads/handoff/push-item"
    assert commit["commit"] == head
    assert (push["behavior"], push["ref"], push["local_sha"], push["remote_sha_before"]) == (behavior, ref, head, None)
    assert push["destination"] == ("url" if behavior == "push-url" else "origin")
    remote = text(sandbox.git("-C", str(sandbox.bare), "for-each-ref", "--format=%(objectname)", ref))
    if arrives:
        assert (push["exit_code"], push["arrived"], push["remote_sha_after"], remote) == (0, True, head, head)
    else:
        assert push["exit_code"] != 0
        assert (push["arrived"], push["remote_sha_after"], remote) == (False, None, "")


def test_switch_main_changes_the_main_trees_branch_and_keeps_its_uncommitted_bytes(
    handoff_sandbox: HandoffSandbox, fake_kiro_cli_module: ModuleType
) -> None:
    """From a worktree, ``switch-main`` moves the main working tree to a new branch; nothing else of it changes."""
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "rogue-item")
    before = sandbox.snapshot_main_tree()
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="switch-main")
    done = run_fake(chat_argv(sandbox), cwd=worktree, env=env)
    assert done.returncode == 0, done.stderr
    after = sandbox.snapshot_main_tree()
    switched = fake_kiro_cli_module.SWITCH_BRANCH
    assert (before.branch, after.branch) == ("main", switched)
    assert after != before
    assert dataclasses.replace(after, branch=before.branch) == before
    assert only_run(sandbox)["end"]["results"] == [
        {
            "behavior": "switch-main",
            "main_tree": str(sandbox.main_tree),
            "branch_before": "main",
            "branch_after": switched,
            "exit_code": 0,
            "stderr": None,
        }
    ]


def test_the_snapshot_of_the_main_tree_sees_each_kind_of_change(handoff_sandbox: HandoffSandbox) -> None:
    """Reading the snapshot changes nothing, and each kind of change to the main tree changes the snapshot."""
    sandbox = handoff_sandbox
    main = sandbox.main_tree
    first = sandbox.snapshot_main_tree()
    assert sandbox.snapshot_main_tree() == first
    assert [path for path, _ in first.files] == sorted(path for _, path in sandbox.main_tree_dirty)
    assert all(data is not None for _, data in first.files)

    def append(path: Path) -> None:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("one more line\n")

    changes: list[tuple[str, Callable[[], object], str]] = [
        ("bytes of an untracked file", lambda: append(main / "メモ.txt"), "files"),
        ("an unstaged change", lambda: append(main / "README.md"), "unstaged"),
        ("the index", lambda: sandbox.git("-C", str(main), "add", "--", "README.md"), "staged"),
        ("HEAD", lambda: sandbox.git("-C", str(main), "commit", "-q", "-m", "test: move HEAD"), "head"),
    ]
    previous = first
    for what, change, field in changes:
        change()
        state = sandbox.snapshot_main_tree()
        assert getattr(state, field) != getattr(previous, field), what
        assert state != previous, what
        previous = state


def test_a_failed_behavior_stops_the_run_with_exit_code_3(handoff_sandbox: HandoffSandbox) -> None:
    """A git command that fails ends the run: no later behavior, no answer, the failure in the record.

    The failure is a pre-commit hook in the sandbox's hooks directory that refuses every
    commit, as a target repository's gate could.
    """
    sandbox = handoff_sandbox
    hook = sandbox.hooks_dir / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
    hook.chmod(0o755)
    worktree = add_worktree(sandbox, "refused-commit-item", branch="handoff/refused-commit-item")
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="commit,push")
    done = run_fake(chat_argv(sandbox), cwd=worktree, env=env)
    assert done.returncode == 3
    assert done.stdout == b""
    assert done.stderr.startswith(b"fake kiro-cli: commit failed: git commit exited 1")
    end = only_run(sandbox)["end"]
    assert (end["exit_code"], end["error"]) == (3, "commit failed: git commit exited 1")
    assert [result["behavior"] for result in end["results"]] == ["commit"]
    assert end["results"][0]["commit"] is None
    assert [step["exit_code"] for step in end["results"][0]["steps"]] == [0, 1]
    assert text(sandbox.git("-C", str(worktree), "rev-parse", "HEAD")) == sandbox.base_sha
    assert sandbox.git("-C", str(worktree), "status", "--porcelain").stdout == b"A  fake-kiro-change.txt\n"
    assert text(sandbox.git("-C", str(sandbox.bare), "for-each-ref", "--format=%(refname)")) == "refs/heads/main"


def test_exit_code_and_answer_follow_their_variables(handoff_sandbox: HandoffSandbox) -> None:
    """``FAKE_KIRO_EXIT_CODE`` and ``FAKE_KIRO_ANSWER`` set the end of a ``chat`` whose behaviors all ran."""
    sandbox = handoff_sandbox
    env, _ = child_environment(sandbox, FAKE_KIRO_EXIT_CODE="7", FAKE_KIRO_ANSWER="答え\n")
    done = run_fake(chat_argv(sandbox), cwd=sandbox.root, env=env)
    assert (done.returncode, done.stdout, done.stderr) == (7, "答え\n".encode("utf-8"), b"")
    assert only_run(sandbox)["end"]["exit_code"] == 7


@pytest.mark.parametrize("record", ["records/relative.jsonl", ""], ids=["relative", "empty"])
def test_the_record_must_be_an_absolute_path(handoff_sandbox: HandoffSandbox, record: str) -> None:
    """A record path that would be resolved in the worktree is refused before anything is written."""
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "record-item")
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="commit", FAKE_KIRO_RECORD=record)
    done = run_fake(chat_argv(sandbox), cwd=worktree, env=env)
    assert done.returncode == 2
    assert b"FAKE_KIRO_RECORD" in done.stderr
    assert sandbox.git("-C", str(worktree), "status", "--porcelain").stdout == b""
    assert not sandbox.record.exists()


def test_without_a_record_the_fake_runs_and_records_nothing(handoff_sandbox: HandoffSandbox) -> None:
    """Without ``FAKE_KIRO_RECORD`` the fake behaves the same and writes no record anywhere."""
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "unrecorded-item", branch="handoff/unrecorded-item")
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="commit")
    del env["FAKE_KIRO_RECORD"]
    done = run_fake(chat_argv(sandbox), cwd=worktree, env=env)
    assert done.returncode == 0, done.stderr
    assert text(sandbox.git("-C", str(worktree), "rev-list", "--count", f"{sandbox.base_sha}..HEAD")) == "1"
    assert sandbox.git("-C", str(worktree), "status", "--porcelain").stdout == b""
    assert not any((sandbox.root / "records").iterdir())


def test_apply_environ_hands_the_sandbox_environment_to_code_that_reads_os_environ(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runner's path: ``os.environ`` set by the sandbox, then ``child_env(os.environ)``, keeps the credentials from the fake."""
    sandbox = handoff_sandbox
    monkeypatch.setenv("GIT_DIR", str(sandbox.root / "not-a-repository"))
    monkeypatch.setenv("FAKE_KIRO_MODE", "whoami-fail")
    sandbox.apply_environ(monkeypatch, **SECRETS)
    assert os.environ["HOME"] == str(sandbox.home)
    assert os.environ["FAKE_KIRO_RECORD"] == str(sandbox.record)
    assert "GIT_DIR" not in os.environ and "FAKE_KIRO_MODE" not in os.environ
    assert {name: os.environ[name] for name in SECRETS} == SECRETS
    env = command.child_env(os.environ, **sandbox.child_env_paths())
    done = run_fake([str(sandbox.kiro_cli), "whoami"], cwd=sandbox.root, env=env)
    assert done.returncode == 0, done.stderr
    assert not set(only_run(sandbox)["start"]["env"]["names"]) & set(SECRETS)


def selftest_token(trial: str, nonce: str = "0123456789abcdef") -> str:
    """Return a selftest token of the form that the harness builds (design note of task 5.2)."""
    return f"handoff-selftest-{trial}-{nonce}"


def selftest_prompt(token: str) -> str:
    """Return a prompt that holds a token once, as the prompt of a selftest trial does."""
    return f"Handoff selftest in a throwaway repository. Use the marker {token} exactly as given."


def test_a_selftest_token_selects_the_behaviors_of_its_trial(handoff_sandbox: HandoffSandbox) -> None:
    """``FAKE_KIRO_MODE_T<n>`` replaces ``FAKE_KIRO_MODE`` only for a prompt that holds one token of trial ``t<n>``.

    The behaviors have no side effects, so the runs share one sandbox. A token stands alone:
    one inside a longer word, with capital letters, or of a trial other than T0 to T4 is
    not one.
    """
    sandbox = handoff_sandbox
    env, _ = child_environment(
        sandbox,
        FAKE_KIRO_MODE="noise",
        FAKE_KIRO_NOISE_BYTES="0",
        FAKE_KIRO_ANSWER="",
        FAKE_KIRO_MODE_T0="ignore-sigterm",
        FAKE_KIRO_MODE_T3="ignore-sigterm,noise",
    )
    t0, t1, t3 = (selftest_token(trial) for trial in ("t0", "t1", "t3"))
    not_tokens = f"Not tokens: x{t0}, {t0}0, {t0.upper()}, {selftest_token('t5')}."
    cases: list[tuple[str, str | None, str | None, list[str], str]] = [
        (selftest_prompt(t0), "t0", t0, ["ignore-sigterm"], "FAKE_KIRO_MODE_T0"),
        (f"{selftest_prompt(t3)} Again: {t3}.", "t3", t3, ["ignore-sigterm", "noise"], "FAKE_KIRO_MODE_T3"),
        (selftest_prompt(t1), "t1", t1, ["noise"], "FAKE_KIRO_MODE"),
        ("A prompt without a token.", None, None, ["noise"], "FAKE_KIRO_MODE"),
        (not_tokens, None, None, ["noise"], "FAKE_KIRO_MODE"),
    ]
    for index, (prompt, trial, token, behaviors, variable) in enumerate(cases):
        done = run_fake(chat_argv(sandbox, prompt=prompt), cwd=sandbox.root, env=env)
        assert done.returncode == 0, (index, done.stderr)
        run = sandbox.invocations()[index]
        assert (run["start"]["trial"], run["start"]["token"]) == (trial, token), index
        assert (run["start"]["behaviors"], run["start"]["mode_variable"]) == (behaviors, variable), index
        assert [result["behavior"] for result in run["end"]["results"]] == behaviors, index


#: ``(id, prompt, extra variables)`` of selftest settings that the fake must refuse with exit code 2.
SELFTEST_REFUSED: tuple[tuple[str, str, dict[str, str]], ...] = (
    ("two-tokens", f"{selftest_prompt(selftest_token('t0'))} {selftest_token('t1')}", {}),
    ("one-trial-two-nonces", f"{selftest_prompt(selftest_token('t1'))} {selftest_token('t1', 'fedcba9876543210')}", {}),
    ("trial-out-of-range", "p", {"FAKE_KIRO_MODE_T5": "noise"}),
    ("trial-in-lower-case", "p", {"FAKE_KIRO_MODE_t1": "noise"}),
    (
        "unknown-behavior-of-the-trial",
        selftest_prompt(selftest_token("t1")),
        {"FAKE_KIRO_MODE_T1": "commit,no-such-behavior"},
    ),
    ("unknown-behavior-of-another-trial", selftest_prompt(selftest_token("t0")), {"FAKE_KIRO_MODE_T4": "no-such"}),
    ("guard-block-without-a-token", "p", {"FAKE_KIRO_MODE": "guard-block"}),
    ("guard-allow-without-a-token", "p", {"FAKE_KIRO_MODE": "commit,guard-allow"}),
    (
        "relative-guard-log",
        selftest_prompt(selftest_token("t2")),
        {"FAKE_KIRO_MODE_T2": "commit,guard-block", "HANDOFF_GUARD_LOG": "guard.jsonl"},
    ),
    ("empty-guard-log", "p", {"FAKE_KIRO_MODE": "commit,guard-block-other", "HANDOFF_GUARD_LOG": ""}),
    ("gh-exit-not-a-number", "p", {"FAKE_KIRO_MODE": "gh-status", "FAKE_KIRO_GH_EXIT": "zero"}),
    ("gh-exit-too-large", "p", {"FAKE_KIRO_MODE": "gh-status", "FAKE_KIRO_GH_EXIT": "256"}),
)


def test_the_fake_refuses_unusable_selftest_settings(handoff_sandbox: HandoffSandbox) -> None:
    """Each case of :data:`SELFTEST_REFUSED` exits 2 before any behavior and leaves the worktree as it was.

    The default behavior of the cases is ``commit``, so a case that is not refused leaves a
    commit behind. The checks that concern ``chat`` only leave ``whoami`` working.
    """
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "selftest-refused", branch="handoff/selftest-refused")
    wt = str(worktree)
    for index, (case, prompt, extra) in enumerate(SELFTEST_REFUSED):
        env, _ = child_environment(sandbox, **{"FAKE_KIRO_MODE": "commit", **extra})
        done = run_fake(chat_argv(sandbox, "--trust-tools=fs_read,fs_write", prompt=prompt), cwd=worktree, env=env)
        assert done.returncode == 2, (case, done.stderr)
        assert done.stdout == b"", case
        assert done.stderr.startswith(b"fake kiro-cli: usage: "), case
        runs = sandbox.invocations()
        assert len(runs) == index + 1, case
        end = runs[-1]["end"]
        assert (end["exit_code"], end["results"]) == (2, []), case
        assert end["error"].startswith("usage: "), case
        assert text(sandbox.git("-C", wt, "rev-parse", "HEAD")) == sandbox.base_sha, case
        assert sandbox.git("-C", wt, "status", "--porcelain", "--untracked-files=all").stdout == b"", case
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="guard-block", HANDOFF_GUARD_LOG="relative.jsonl")
    done = run_fake([str(sandbox.kiro_cli), "whoami"], cwd=worktree, env=env)
    assert done.returncode == 0, done.stderr


def test_empty_commit_commits_the_token_and_a_private_example_address(
    handoff_sandbox: HandoffSandbox, fake_kiro_cli_module: ModuleType
) -> None:
    """T1's behavior adds a commit without changes whose message is the token and the address, or the label without a token."""
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "selftest-t1", branch="handoff/selftest-t1")
    wt = str(worktree)
    address = fake_kiro_cli_module.EXAMPLE_ADDRESS
    assert ipaddress.ip_address(address).is_private
    t1 = selftest_token("t1")
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="empty-commit")
    runs = [(selftest_prompt(t1), t1), ("A prompt without a token.", fake_kiro_cli_module.NO_TOKEN_LABEL)]
    for index, (prompt, label) in enumerate(runs):
        done = run_fake(chat_argv(sandbox, "--trust-tools=fs_read,fs_write", prompt=prompt), cwd=worktree, env=env)
        assert done.returncode == 0, done.stderr
        head = text(sandbox.git("-C", wt, "rev-parse", "HEAD"))
        message = f"{label} {address}"
        assert text(sandbox.git("-C", wt, "log", "-1", "--format=%B")) == message
        assert text(sandbox.git("-C", wt, "rev-list", "--count", f"{sandbox.base_sha}..HEAD")) == str(index + 1)
        assert text(sandbox.git("-C", wt, "diff-tree", "--no-commit-id", "--name-only", "-r", head)) == ""
        assert sandbox.invocations()[index]["end"]["results"] == [
            {
                "behavior": "empty-commit",
                "message": message,
                "commit": head,
                "steps": [{"argv": ["git", "commit", "-q", "--allow-empty", "-m", message], "exit_code": 0}],
            }
        ]
    assert sandbox.git("-C", wt, "status", "--porcelain").stdout == b""


def test_gh_status_commits_the_code_its_environment_gives_and_never_runs_gh(handoff_sandbox: HandoffSandbox) -> None:
    """T3's behavior: 0 with a token variable, 1 without; layer 3 drops the token; ``FAKE_KIRO_GH_EXIT`` overrides.

    A ``gh`` first on ``PATH`` leaves a mark when it runs (the control at the end), and no
    run leaves it. The made-up token values stay out of the record.
    """
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "selftest-t3", branch="handoff/selftest-t3")
    wt = str(worktree)
    bin_dir = sandbox.root / "bin"
    bin_dir.mkdir()
    mark = sandbox.root / "gh-ran"
    stub = bin_dir / "gh"
    stub.write_text(f"#!/bin/sh\n: > '{mark}'\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)
    path = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
    assert shutil.which("gh", path=path) == str(stub)
    t3 = selftest_token("t3")
    cases: list[tuple[str, bool, dict[str, str], int, str]] = [
        ("layer-3-drops-the-token", True, {"GH_TOKEN": "made-up-gh-token"}, 1, "token_variables"),
        ("no-layer-3-keeps-the-token", False, {"GITHUB_TOKEN": "made-up-github-token"}, 0, "token_variables"),
        ("no-layer-3-empty-token", False, {"GH_TOKEN": ""}, 1, "token_variables"),
        ("override-under-layer-3", True, {"FAKE_KIRO_GH_EXIT": "0"}, 0, "FAKE_KIRO_GH_EXIT"),
        (
            "override-before-the-token",
            False,
            {"FAKE_KIRO_GH_EXIT": "4", "GH_TOKEN": "made-up-gh-token"},
            4,
            "FAKE_KIRO_GH_EXIT",
        ),
    ]
    for index, (case, layer_3, extra, code, source) in enumerate(cases):
        variables = {"FAKE_KIRO_MODE_T3": "gh-status", "PATH": path, **extra}
        env = child_environment(sandbox, **variables)[0] if layer_3 else sandbox.environ(**variables)
        argv = chat_argv(sandbox, "--trust-tools=fs_read,fs_write", prompt=selftest_prompt(t3))
        done = run_fake(argv, cwd=worktree, env=env)
        assert done.returncode == 0, (case, done.stderr)
        message = f"{t3} gh-exit={code}"
        head = text(sandbox.git("-C", wt, "rev-parse", "HEAD"))
        assert text(sandbox.git("-C", wt, "log", "-1", "--format=%B")) == message, case
        assert sandbox.invocations()[index]["end"]["results"] == [
            {
                "behavior": "gh-status",
                "message": message,
                "commit": head,
                "steps": [{"argv": ["git", "commit", "-q", "--allow-empty", "-m", message], "exit_code": 0}],
                "gh_exit": code,
                "source": source,
            }
        ], case
    assert not mark.exists()
    assert "made-up-" not in sandbox.record.read_text(encoding="ascii")
    subprocess.run([str(stub)], check=True)
    assert mark.exists()


def test_write_file_follows_the_allowlist_and_write_file_anyway_does_not(
    handoff_sandbox: HandoffSandbox, fake_kiro_cli_module: ModuleType
) -> None:
    """T4's behaviors: ``write-file`` writes ``<token>.txt`` only when the argv trusts ``fs_write``; the other always does."""
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "selftest-t4")
    cases = [
        ("write-file", "--trust-tools=fs_read", False, False),
        ("write-file", "--trust-tools=", False, False),
        ("write-file", "--trust-tools=fs_read,fs_write", True, True),
        ("write-file", "--trust-all-tools", True, True),
        ("write-file", "-a", True, True),
        ("write-file-anyway", "--trust-tools=fs_read", False, True),
    ]
    written: list[str] = []
    for index, (behavior, option, trusted, wrote) in enumerate(cases):
        token = selftest_token("t4", f"{index:016x}")
        env, _ = child_environment(sandbox, FAKE_KIRO_MODE_T4=behavior)
        done = run_fake(chat_argv(sandbox, option, prompt=selftest_prompt(token)), cwd=worktree, env=env)
        assert done.returncode == 0, (behavior, option, done.stderr)
        name = f"{token}.txt"
        assert sandbox.invocations()[index]["end"]["results"] == [
            {"behavior": behavior, "file": name, "tool": "fs_write", "trusted": trusted, "written": wrote}
        ], (behavior, option)
        assert (worktree / name).exists() is wrote, (behavior, option)
        if wrote:
            assert (worktree / name).read_bytes() == fake_kiro_cli_module.CHANGE_LINE
            written.append(name)
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE="write-file-anyway")
    done = run_fake(chat_argv(sandbox, "--trust-tools=fs_read", prompt="No token."), cwd=worktree, env=env)
    assert done.returncode == 0, done.stderr
    written.append(f"{fake_kiro_cli_module.NO_TOKEN_LABEL}.txt")
    status = sandbox.git("-C", str(worktree), "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    assert sorted(entry for entry in status.decode("ascii").split("\0") if entry) == sorted(f"?? {n}" for n in written)
    assert text(sandbox.git("-C", str(worktree), "rev-parse", "HEAD")) == sandbox.base_sha


def test_guard_behaviors_append_one_entry_each_and_change_nothing_else(
    handoff_sandbox: HandoffSandbox, fake_kiro_cli_module: ModuleType
) -> None:
    """Each guard behavior appends the wrapper's entry: its decision and code, and the token in the input or not."""
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "selftest-guard", branch="handoff/selftest-guard")
    log = sandbox.root / "guard" / "guard.jsonl"
    log.parent.mkdir()
    guard = fake_kiro_cli_module.FAKE_GUARD
    cases = [
        ("guard-block", "t1", "block", 2, True),
        ("guard-allow", "t2", "allow", 0, True),
        ("guard-block-other", "t3", "block", 2, False),
    ]
    for index, (behavior, trial, decision, code, holds) in enumerate(cases):
        token = selftest_token(trial)
        variables = {f"FAKE_KIRO_MODE_{trial.upper()}": behavior, "HANDOFF_GUARD_LOG": str(log)}
        env, _ = child_environment(sandbox, **variables)
        argv = chat_argv(sandbox, "--trust-tools=fs_read,fs_write", prompt=selftest_prompt(token))
        done = run_fake(argv, cwd=worktree, env=env)
        assert done.returncode == 0, (behavior, done.stderr)
        entries = [json.loads(line) for line in log.read_text(encoding="ascii").splitlines()]
        assert len(entries) == index + 1, behavior
        entry = entries[-1]
        assert sorted(entry) == ["at", "decision", "exit_code", "guard", "input", "schema"], behavior
        assert (entry["schema"], entry["guard"], entry["decision"], entry["exit_code"]) == (1, guard, decision, code)
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", entry["at"]), behavior
        assert sorted(entry["input"]) == ["cwd", "hook_event_name", "tool_input", "tool_name"], behavior
        assert entry["input"]["cwd"] == str(worktree), behavior
        assert (token in json.dumps(entry["input"])) is holds, behavior
        assert sandbox.invocations()[index]["end"]["results"] == [
            {
                "behavior": behavior,
                "guard": guard,
                "decision": decision,
                "log": str(log),
                "written": True,
                "token_in_input": holds,
            }
        ], behavior
    assert sorted(path.name for path in log.parent.iterdir()) == ["guard.jsonl"]
    assert text(sandbox.git("-C", str(worktree), "rev-parse", "HEAD")) == sandbox.base_sha
    assert sandbox.git("-C", str(worktree), "status", "--porcelain", "--untracked-files=all").stdout == b""
    assert text(sandbox.git("-C", str(sandbox.bare), "for-each-ref", "--format=%(refname)")) == "refs/heads/main"


def test_a_guard_behavior_without_the_log_variable_writes_nothing(handoff_sandbox: HandoffSandbox) -> None:
    """Without ``HANDOFF_GUARD_LOG``, ``guard-block`` writes no entry anywhere: a stop that leaves no evidence."""
    sandbox = handoff_sandbox
    worktree = add_worktree(sandbox, "selftest-unlogged", branch="handoff/selftest-unlogged")
    env, _ = child_environment(sandbox, FAKE_KIRO_MODE_T2="guard-block")
    env.pop("HANDOFF_GUARD_LOG", None)
    argv = chat_argv(sandbox, "--trust-tools=fs_read,fs_write", prompt=selftest_prompt(selftest_token("t2")))
    before = {path for path in sandbox.root.rglob("*") if path.is_file()}
    done = run_fake(argv, cwd=worktree, env=env)
    after = {path for path in sandbox.root.rglob("*") if path.is_file()}
    assert done.returncode == 0, done.stderr
    assert after - before == {sandbox.record}
    assert only_run(sandbox)["end"]["results"] == [
        {
            "behavior": "guard-block",
            "guard": "fake_guard",
            "decision": "block",
            "log": None,
            "written": False,
            "token_in_input": True,
        }
    ]
    assert sandbox.git("-C", str(worktree), "status", "--porcelain", "--untracked-files=all").stdout == b""

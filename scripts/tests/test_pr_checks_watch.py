"""Tests for scripts/ci-watch/pr-checks-watch.sh.

These five cases are the regression surface for the command-watch terminal detector.
The whole reason the script exists is that a `github-pr` watch keyed terminal
detection on the REST combined commit status, which stays `pending` forever on repos
whose CI is only GitHub Actions check runs -- so it never surfaced terminal, neither
on all-green nor on a failing check. Each case below locks in the correct reading of
the `gh pr checks` buckets so that regression cannot come back silently:

- ``test_all_pass_is_terminal_success`` -- every bucket ``pass`` must be a terminal
  success, the all-green case the old handler missed.
- ``test_one_fail_is_terminal_failure`` -- a ``fail`` bucket must be a terminal
  failure AND name the failing check in ``payload.failing``, the failing case the old
  handler also missed.
- ``test_one_pending_is_not_terminal`` -- a ``pending`` bucket must NOT be terminal and
  must leave ``payload.result`` null, so the loop keeps polling long jobs.
- ``test_zero_checks_within_grace_is_idle`` -- an empty check set (Actions not yet
  registered) must be ``idle`` with reason ``awaiting_checks``, never a premature
  success before checks attach.
- ``test_changed_completed_set_is_new_activity`` -- a completed-set that grew since the
  previous cursor while a check is still pending must be ``new-activity`` so downstream
  sees progress cheaply.

The test NEVER touches the network: a ``gh`` shim is prepended to PATH and answers all
``gh pr checks`` / ``gh pr view`` calls with canned JSON and canned exit codes.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "ci-watch" / "pr-checks-watch.sh"

# Placeholder PR number + real public repo slug (no secrets, no live calls).
PR_NUMBER = 9999
REPO_SLUG = "Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns"


def _write_gh_shim(shim_dir: Path, checks_json: str, checks_exit: int) -> dict[str, str]:
    """Write an executable ``gh`` shim into ``shim_dir`` and return an env with it on PATH.

    The shim branches on its arguments: ``gh pr checks ...`` echoes ``checks_json`` and
    exits with ``checks_exit`` (0 all-pass, 1 a fail, 8 pending); ``gh pr view ...``
    echoes a canned ``mergeStateStatus``. The shim dir is PREPENDED to PATH (not
    replacing it), so ``jq`` and ``shasum`` still resolve from the real PATH.

    Args:
        shim_dir: A tmp directory the shim is written into.
        checks_json: Canned JSON array for ``gh pr checks --json name,state,bucket``.
        checks_exit: Exit code the shim returns for the ``pr checks`` call.

    Returns:
        An environment dict with ``shim_dir`` prepended to ``PATH``.
    """
    gh = shim_dir / "gh"
    gh.write_text(
        "#!/usr/bin/env bash\n"
        "# Test shim for gh. No network. Branches on sub-command.\n"
        'if [[ "$1" == "pr" && "$2" == "checks" ]]; then\n'
        f"  cat <<'CHECKS_EOF'\n{checks_json}\nCHECKS_EOF\n"
        f"  exit {checks_exit}\n"
        'elif [[ "$1" == "pr" && "$2" == "view" ]]; then\n'
        '  printf \'%s\\n\' "CLEAN"\n'
        "  exit 0\n"
        "fi\n"
        "exit 2\n"
    )
    gh.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{shim_dir}{os.pathsep}{env['PATH']}"
    return env


def _run(stdin_obj: dict, env: dict[str, str]) -> dict:
    """Run the watch script via subprocess, assert clean exit, and parse its JSON.

    Args:
        stdin_obj: The object serialized to the script's stdin.
        env: Environment carrying the ``gh`` shim on PATH.

    Returns:
        The single JSON object the script printed on stdout.
    """
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        input=json.dumps(stdin_obj),
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, f"script exit {result.returncode}; stderr={result.stderr}"
    return json.loads(result.stdout)


def _config(**overrides) -> dict:
    """Build a stdin object with a placeholder PR and the real public repo slug."""
    config = {
        "pr": PR_NUMBER,
        "repo": REPO_SLUG,
        "min_checks": 1,
        "grace_seconds": 180,
        "require_names": [],
    }
    config.update(overrides)
    return {
        "cursor": None,
        "config": config,
        "workspacePath": "/tmp",
        "additionalDirectories": [],
    }


def test_all_pass_is_terminal_success(tmp_path: Path) -> None:
    """Every check in bucket ``pass`` (gh exit 0) is a terminal success."""
    checks = json.dumps(
        [
            {"name": "lint-and-test", "state": "SUCCESS", "bucket": "pass"},
            {"name": "gitleaks", "state": "SUCCESS", "bucket": "pass"},
        ]
    )
    env = _write_gh_shim(tmp_path, checks, 0)
    out = _run(_config(), env)
    assert out["outcome"] == "terminal-state"
    assert out["payload"]["result"] == "success"


def test_one_fail_is_terminal_failure(tmp_path: Path) -> None:
    """A check in bucket ``fail`` (gh exit 1) is a terminal failure naming the check."""
    checks = json.dumps(
        [
            {"name": "lint-and-test", "state": "SUCCESS", "bucket": "pass"},
            {"name": "cfn-guard", "state": "FAILURE", "bucket": "fail"},
        ]
    )
    env = _write_gh_shim(tmp_path, checks, 1)
    out = _run(_config(), env)
    assert out["outcome"] == "terminal-state"
    assert out["payload"]["result"] == "failure"
    assert "cfn-guard" in out["payload"]["failing"]


def test_one_pending_is_not_terminal(tmp_path: Path) -> None:
    """A check in bucket ``pending`` (gh exit 8) is not terminal; result stays null."""
    checks = json.dumps(
        [
            {"name": "lint-and-test", "state": "SUCCESS", "bucket": "pass"},
            {"name": "markdown-links", "state": "IN_PROGRESS", "bucket": "pending"},
        ]
    )
    env = _write_gh_shim(tmp_path, checks, 8)
    out = _run(_config(), env)
    assert out["outcome"] in {"idle", "new-activity"}
    assert out["payload"]["result"] is None


def test_zero_checks_within_grace_is_idle(tmp_path: Path) -> None:
    """Zero checks with ``min_checks`` unmet is idle with reason ``awaiting_checks``."""
    env = _write_gh_shim(tmp_path, "[]", 0)
    out = _run(_config(min_checks=1), env)
    assert out["outcome"] == "idle"
    assert out["payload"]["reason"] == "awaiting_checks"


def test_gh_exit_1_reaches_bucket_failure_not_the_err_trap(tmp_path: Path) -> None:
    """Regression: gh exit 1 with a fail bucket must reach terminal failure, not the ERR trap.

    The published report's §2c ERR trap intercepted every non-zero gh exit and emitted
    idle, so a real check failure (gh exit 1) was reported as idle -- the exact bug class
    this watch replaces. The GH_RC guard lets the documented exit-1 through to the bucket
    logic. This case locks that in: outcome terminal-state, result failure, and the failing
    check named in payload.failing.
    """
    checks = json.dumps(
        [
            {"name": "lint-and-test", "state": "SUCCESS", "bucket": "pass"},
            {"name": "pr-title-check", "state": "FAILURE", "bucket": "fail"},
        ]
    )
    env = _write_gh_shim(tmp_path, checks, 1)
    out = _run(_config(), env)
    assert out["outcome"] == "terminal-state"
    assert out["payload"]["result"] == "failure"
    assert out["payload"]["failing"] == ["pr-title-check"]


def test_changed_completed_set_is_new_activity(tmp_path: Path) -> None:
    """A completed-set that grew since the previous cursor, with a pending check, is new-activity."""
    checks = json.dumps(
        [
            {"name": "lint-and-test", "state": "SUCCESS", "bucket": "pass"},
            {"name": "gitleaks", "state": "SUCCESS", "bucket": "pass"},
            {"name": "markdown-links", "state": "IN_PROGRESS", "bucket": "pending"},
        ]
    )
    env = _write_gh_shim(tmp_path, checks, 8)
    stdin_obj = _config()
    # Previous cursor had only one completed check; the current set grew to two.
    stdin_obj["cursor"] = {"completed": ["lint-and-test"], "digest": "stale"}
    out = _run(stdin_obj, env)
    assert out["outcome"] == "new-activity"
    assert out["payload"]["result"] is None

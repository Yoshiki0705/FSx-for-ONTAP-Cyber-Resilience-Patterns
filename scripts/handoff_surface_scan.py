#!/usr/bin/env python3
"""Run zizmor and gitleaks on the diff of a held ``publish_execution_surface`` item and record the result (task 5.18).

    handoff_surface_scan.py --approval FILE --item ID --repo MAIN_TREE --base SHA --head REF

The maintainer's session runs this after ``cli.py publish`` held an item for ``publish_execution_surface`` and before
the maintainer reads the diff and names the item in ``execution_surface_ack``. It is not part of the harness: the
harness starts neither tool and does not read what this writes (``handoff/surface_scan.py`` says why).

What each tool is given, in a throwaway directory that is removed at the end:

* ``gitleaks detect --no-git``: the lines that the diff *adds* to the execution-surface files, one file per path.
* ``zizmor --format json``: the whole post-change text of the changed workflow files and composite actions
  (``git show <head>:<path>``). A fragment of added lines is not a workflow and does not parse, so the file is given
  whole; its findings can include lines that were already there. ``scope`` in the record says so.

The record goes under ``execution_surface_scans[<item>]`` of ``--approval``; ``item_ids`` and
``execution_surface_ack`` are never written. Exit codes: 0 the record was written (whatever the tools found), 2 the
input could not be read, a tool is missing or git failed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from handoff import safety, surface_scan  # noqa: E402

Run = Callable[[Sequence[str], str | None], "subprocess.CompletedProcess[str]"]
TIMEOUT_SECONDS = 300


class ScanError(RuntimeError):
    """The scan could not be made (a tool is missing, git failed, an input is unreadable)."""


def _run(argv: Sequence[str], cwd: str | None) -> subprocess.CompletedProcess[str]:
    """Run a command without a shell and without reading from the terminal."""
    try:
        return subprocess.run(  # noqa: S603 - a list, no shell
            list(argv),
            cwd=cwd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=TIMEOUT_SECONDS,
            check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScanError(f"{argv[0]}: {error}") from error


def _git(run: Run, repo: str, *args: str) -> str:
    done = run(["git", "--no-optional-locks", "-C", repo, *args], None)
    if done.returncode != 0:
        raise ScanError(f"git {args[0]} failed: {done.stderr.strip()[:300]}")
    return done.stdout


def scan(
    repo: str, base: str, head: str, run: Run = _run, gitleaks_config: str | None = None
) -> tuple[str, tuple[str, ...], surface_scan.ToolRun, surface_scan.ToolRun]:
    """Scan the diff ``base..head`` of ``repo``; return the head commit, the surface files and the two tool runs."""
    head_sha = _git(run, repo, "rev-parse", "--verify", f"{head}^{{commit}}").strip()
    names = _git(run, repo, "diff", "--name-only", "--no-renames", "-z", base, head_sha).split("\0")
    surface = safety.execution_surface(name for name in names if name)
    diff = _git(run, repo, "diff", "--no-renames", base, head_sha)
    added = surface_scan.added_lines(diff, surface)
    workflows = surface_scan.workflow_files(surface)
    with tempfile.TemporaryDirectory(prefix="surface-scan-") as tmp:
        lines_dir, flows_dir, report_dir = (Path(tmp, name) for name in ("added", "workflows", "reports"))
        report_dir.mkdir(parents=True)
        for path, lines in added.items():
            target = lines_dir / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        for path in workflows:
            target = flows_dir / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(_git(run, repo, "show", f"{head_sha}:{path}"), encoding="utf-8")
        lines_dir.mkdir(exist_ok=True)
        leak_report = report_dir / "gitleaks.json"
        leak_argv = ["gitleaks", "detect", "--no-git", "--source", str(lines_dir), "--report-format", "json"]
        leak_argv += ["--report-path", str(leak_report), "--exit-code", "1", "--no-banner"]
        if gitleaks_config:
            leak_argv += ["--config", gitleaks_config]
        leaks = run(leak_argv, None)
        leak_count = None
        if leaks.returncode in (0, 1) and leak_report.exists():
            leak_count = surface_scan.count_gitleaks_findings(leak_report.read_text(encoding="utf-8"))
        gitleaks = surface_scan.ToolRun(True, leaks.returncode, leak_count, "added lines of the surface files")
        if workflows:
            flows = run(["zizmor", "--format", "json", "--no-exit-codes", str(flows_dir)], None)
            try:
                flow_count = surface_scan.count_zizmor_findings(flows.stdout)
            except ValueError:
                flow_count = None
            zizmor = surface_scan.ToolRun(True, flows.returncode, flow_count, "whole post-change workflow files")
        else:
            zizmor = surface_scan.ToolRun(False, None, None, "no workflow file in the diff")
    return head_sha, surface, zizmor, gitleaks


def record(approval: str, item: str, entry: dict[str, Any]) -> None:
    """Write ``entry`` under ``execution_surface_scans[item]`` of the approval record, changing no other key."""
    path = Path(approval)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ScanError(f"{approval}: {error}") from error
    if not isinstance(data, dict):
        raise ScanError(f"{approval} must hold a JSON object")
    scans = data.setdefault(surface_scan.SCANS_KEY, {})
    if not isinstance(scans, dict):
        raise ScanError(f"{surface_scan.SCANS_KEY} of {approval} must be an object")
    scans[item] = entry
    problems = surface_scan.scans_issues(scans)
    if problems:
        raise ScanError("; ".join(problems))
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main(argv: Sequence[str] | None = None, *, run: Run = _run) -> int:
    """Entry point; ``run`` is replaced in tests."""
    parser = argparse.ArgumentParser(prog="handoff_surface_scan.py", description=__doc__.split("\n")[0])
    parser.add_argument("--approval", required=True, help="the approval record to add the scan to")
    parser.add_argument("--item", required=True, help="the item ID")
    parser.add_argument("--repo", required=True, help="the main working tree that holds the branch")
    parser.add_argument("--base", required=True, help="the base commit of the branch")
    parser.add_argument("--head", required=True, help="the branch or commit to scan")
    parser.add_argument("--gitleaks-config", help="a gitleaks configuration file")
    args = parser.parse_args(argv)
    try:
        head, surface, zizmor, gitleaks = scan(args.repo, args.base, args.head, run, args.gitleaks_config)
        if not surface:
            raise ScanError("the diff has no execution-surface file; nothing was recorded")
        record(args.approval, args.item, surface_scan.scan_entry(head, surface, zizmor, gitleaks))
    except ScanError as error:
        print(f"handoff_surface_scan: {error}", file=sys.stderr)
        return 2
    print(
        f"{args.item}: zizmor exit {zizmor.exit_code} findings {zizmor.findings}; "
        f"gitleaks exit {gitleaks.exit_code} findings {gitleaks.findings}; recorded in {args.approval}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

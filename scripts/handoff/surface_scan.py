"""The record of a scan of an execution-surface diff, made before the maintainer acknowledges it (task 5.18).

``cli.py publish`` holds an item whose branch changes a file that runs code or decides who may
(``safety.execution_surface``, reason ``publish_execution_surface``) until the approval names the item in
``execution_surface_ack``. Before the maintainer reads that diff and approves, the session that works for the
maintainer runs ``zizmor`` and ``gitleaks`` on it (``scripts/handoff_surface_scan.py``) and keeps the exit codes and
the number of findings in the approval record, under ``execution_surface_scans``. The harness does not run either
command, does not require the record, and does not read it: the ack stays the maintainer's separate act (a command
that must run is a ``verify_commands`` entry of the Handoff_Target, which is another change).

This module is the pure part: it reads a unified diff, picks the files, counts findings in a report and builds and
checks the record. It starts no process; ``scripts/handoff_surface_scan.py`` does that.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any, Final, NamedTuple

__all__ = [
    "SCANS_KEY",
    "ToolRun",
    "added_lines",
    "count_gitleaks_findings",
    "count_zizmor_findings",
    "scan_entry",
    "scans_issues",
    "workflow_files",
]

#: The key of the approval record that holds the scans, a mapping from item ID to one entry.
SCANS_KEY: Final = "execution_surface_scans"
_WORKFLOW: Final = re.compile(r"(?:\.github/workflows/[^/]+\.ya?ml|\.github/actions/.+/action\.ya?ml)", re.IGNORECASE)
_HUNK: Final = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_TOOLS: Final = ("zizmor", "gitleaks")
_ENTRY_KEYS: Final = ("scanned_head", "files", *_TOOLS)
_RUN_KEYS: Final = ("ran", "exit_code", "findings", "scope")


class ToolRun(NamedTuple):
    """What one tool did on the diff.

    Attributes:
        ran: ``False`` when there was nothing for the tool to read (no workflow file for ``zizmor``).
        exit_code: The tool's exit code; ``None`` when it did not run or did not end.
        findings: The number of findings in its report; ``None`` when it did not run or the report was not read.
        scope: What was given to the tool, in words.
    """

    ran: bool
    exit_code: int | None
    findings: int | None
    scope: str


def added_lines(diff: str, paths: Iterable[str]) -> dict[str, list[str]]:
    """Return the lines that a unified diff adds to each of ``paths``, in order, without the ``+``.

    Args:
        diff: ``git diff --no-renames`` output with ``a/`` and ``b/`` prefixes.
        paths: The repository-relative paths to read.

    Returns:
        A mapping from path to its added lines. A path without an added line is present with an empty list.

    Raises:
        TypeError: ``diff`` is not a ``str``.
    """
    if not isinstance(diff, str):
        raise TypeError(f"diff must be a str, not {type(diff).__name__}")
    wanted = set(paths)
    found: dict[str, list[str]] = {path: [] for path in sorted(wanted)}
    current: str | None = None
    in_hunk = False
    for line in diff.split("\n"):
        if line.startswith("diff --git "):
            current, in_hunk = None, False
        elif not in_hunk and line.startswith("+++ "):
            target = line[4:]
            current = target[2:] if target.startswith("b/") and target[2:] in wanted else None
        elif _HUNK.match(line):
            in_hunk = True
        elif in_hunk and current is not None and line.startswith("+"):
            found[current].append(line[1:])
    return found


def workflow_files(paths: Iterable[str]) -> tuple[str, ...]:
    """Return the paths that ``zizmor`` reads: workflow files and composite actions, sorted."""
    return tuple(sorted(path for path in paths if _WORKFLOW.fullmatch(path)))


def count_zizmor_findings(report: str) -> int:
    """Count the findings of ``zizmor --format json``: its report is a list with one entry per finding.

    Raises:
        ValueError: ``report`` is not JSON or not a list.
    """
    data = json.loads(report) if report.strip() else []
    if not isinstance(data, list):
        raise ValueError("a zizmor JSON report must be a list")
    return len(data)


def count_gitleaks_findings(report: str) -> int:
    """Count the findings of a ``gitleaks`` JSON report: a list, or ``null`` or empty when there is none.

    Raises:
        ValueError: ``report`` is not JSON or not a list.
    """
    if not report.strip():
        return 0
    data = json.loads(report)
    if data is None:
        return 0
    if not isinstance(data, list):
        raise ValueError("a gitleaks JSON report must be a list")
    return len(data)


def scan_entry(head: str, files: Iterable[str], zizmor: ToolRun, gitleaks: ToolRun) -> dict[str, Any]:
    """Build the record of one item's scan.

    Args:
        head: The commit of the branch that was scanned.
        files: The execution-surface files of the branch.
        zizmor: What ``zizmor`` did.
        gitleaks: What ``gitleaks`` did.

    Returns:
        A JSON-able mapping that :func:`scans_issues` accepts.
    """
    return {
        "scanned_head": head,
        "files": sorted(set(files)),
        "zizmor": zizmor._asdict(),
        "gitleaks": gitleaks._asdict(),
    }


def scans_issues(value: Any) -> list[str]:
    """List what is wrong with the ``scans`` value of an approval record (the empty list when it is right).

    The record is evidence for the maintainer to read, so only its form is checked: nothing here decides whether a
    finding count is acceptable.
    """
    if not isinstance(value, Mapping):
        return ["approval.execution_surface_scans: must be an object keyed by item ID"]
    issues: list[str] = []
    for item_id, entry in value.items():
        where = f"approval.execution_surface_scans[{item_id!r}]"
        if not isinstance(item_id, str) or not isinstance(entry, Mapping):
            issues.append(f"{where}: must be an object")
            continue
        issues.extend(f"{where}: missing {key!r}" for key in _ENTRY_KEYS if key not in entry)
        issues.extend(f"{where}: unknown key {key!r}" for key in sorted(entry) if key not in _ENTRY_KEYS)
        if not isinstance(entry.get("scanned_head"), str) or not isinstance(entry.get("files"), list):
            issues.append(f"{where}: scanned_head must be a string and files a list")
        for tool in _TOOLS:
            run = entry.get(tool)
            if not isinstance(run, Mapping) or set(run) != set(_RUN_KEYS):
                issues.append(f"{where}.{tool}: must have exactly the keys {', '.join(_RUN_KEYS)}")
                continue
            if type(run["ran"]) is not bool or not all(
                run[key] is None or type(run[key]) is int for key in ("exit_code", "findings")
            ):
                issues.append(f"{where}.{tool}: ran is a boolean, exit_code and findings are integers or null")
    return issues

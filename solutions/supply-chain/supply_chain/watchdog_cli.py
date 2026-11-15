"""Thin I/O layer of the watchdog: reads record files, prints a verdict, sets the exit code.

Usage::

    python -m supply_chain.watchdog_cli --runs-dir <checkout>/runs
    # the weekly check, from the repository root (Requirement 25.14, the Adoption_Guide's step 2)
    PYTHONPATH=solutions/supply-chain python -m supply_chain.watchdog_cli --runs-dir <checkout>/runs \
        --workflows-json workflows.json --chain-ack docs/agent/supply-chain-chain-ack.json \
        --report-file watchdog-report.json --previous-report watchdog-report.json
    python -m supply_chain.watchdog_cli --overdue-check watchdog-report.json

Exit code 0 when the newest record is within the limit, the latest runs are not
all failures, the record chain holds (``prev_record_sha256``) and (when given) no
workflow is disabled; 1 otherwise, including a
missing record directory or an unreadable workflow listing. With
``--previous-report`` the run also exits 1 when the report of the last run says its
next check was due and had not happened (``previous_check_overdue`` in the new report).
``--overdue-check`` reads a saved report only: exit 1 when its ``next_check_due`` has
passed, or when the report is missing or unreadable. It is the second, separate
command a scheduler or a reminder runs to notice that the weekly check stopped.

Two ways to run it. The workflow in the Hub (handoff 15.2) covers the ordinary
case. It shares the 60-day inactivity switch-off with the Aggregator, so it
cannot report that case. The maintainer's own machine can: ``workflows.json`` is
the body of ``gh api 'repos/<hub>/actions/workflows?per_page=100'``, and the
report file carries the date the next check is due.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess  # noqa: S404  # nosec B404 - a fixed ``git rev-parse`` call
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from supply_chain import chain_recovery, watchdog
from supply_chain import policy as policy_module

LOGGER = logging.getLogger("supply_chain.watchdog")
DEFAULT_POLICY_PATH = Path("docs/agent/supply-chain-policy.json")


def repository_root() -> Path | None:
    """Returns the top of the repository this module is in, as ``git`` reports it, or ``None``."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        done = subprocess.run(  # noqa: S603  # nosec B603 - fixed arguments, no shell
            [git, "-C", str(Path(__file__).resolve().parent), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    top = done.stdout.strip()
    return Path(top) if done.returncode == 0 and top else None


def resolve_policy_file(given: Path | None) -> Path:
    """Finds the Policy_File whatever the working directory is (T3-R3-02).

    An absolute path, or a relative one that exists from the working directory, is used as given. A relative
    path that does not is tried from the repository root; so is the default ``docs/agent/`` file when none is
    given.

    Raises:
        OSError: If the repository root is needed and cannot be found.
    """
    if given is not None and (given.is_absolute() or given.exists()):
        return given
    root = repository_root()
    if root is None:
        if given is not None:
            return given
        raise OSError("the repository root could not be found with git, so the default Policy_File is unknown")
    return root / (given if given is not None else DEFAULT_POLICY_PATH)


def read_record_entries(runs_dir: Path) -> list[tuple[str, str]]:
    """Reads every ``*.json`` file under ``runs_dir`` as ``(path, text)`` (empty if it is absent).

    The path is relative to the parent of ``runs_dir`` (``runs/<YYYY>/<MM>/<run_id>.json``), the form
    ``run_record.verify_chain`` groups into months.
    """
    if not runs_dir.is_dir():
        return []
    return [
        (p.relative_to(runs_dir.parent).as_posix(), p.read_text(encoding="utf-8"))
        for p in sorted(runs_dir.rglob("*.json"))
    ]


def read_record_texts(runs_dir: Path) -> list[str]:
    """Reads every ``*.json`` file under ``runs_dir`` (empty list if it is absent)."""
    return [text for _path, text in read_record_entries(runs_dir)]


def _read_report(path: Path) -> dict[str, object]:
    """Reads a saved report. Raises ``OSError`` or ``ValueError`` when it cannot be used."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"report is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("report is not a JSON object")
    return data


def _overdue_check(path: Path, clock: datetime) -> int:
    """Exit code of ``--overdue-check``: 0 on time, 1 overdue, missing or unreadable."""
    try:
        overdue = watchdog.report_overdue(_read_report(path), clock)
    except (OSError, ValueError) as exc:
        LOGGER.error("no usable watchdog report at %s: %s", path, exc)
        return 1
    if overdue:
        LOGGER.error("the weekly watchdog check is overdue: next_check_due has passed (%s)", path)
        return 1
    LOGGER.info("the weekly watchdog check is on time")
    return 0


def _write_error_report(
    path: Path, clock: datetime, due_hours: float, reason: str, previous_overdue: bool | None
) -> None:
    """Writes a report for a run that could not check anything, so the missed check is not mistaken for no check."""
    report: dict[str, object] = {
        "checked_at": clock.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "next_check_due": (clock + timedelta(hours=due_hours)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "healthy": False,
        "state": "error",
        "policy_error": reason,
    }
    if previous_overdue is not None:
        report["previous_check_overdue"] = previous_overdue
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _chain_ack_failed(args: argparse.Namespace, clock: datetime, reason: str, previous_overdue: bool | None) -> int:
    """Logs an unusable chain ledger, writes the error report when asked, and returns 1 (Requirement 26.27)."""
    LOGGER.error("%s", reason)
    if args.report_file is not None:
        _write_error_report(args.report_file, clock, args.report_due_hours, reason, previous_overdue)
    return 1


def main(argv: Sequence[str] | None = None, now: datetime | None = None) -> int:
    """Runs the check.

    Args:
        argv: Command line arguments.
        now: Clock override for tests; defaults to the current UTC time.

    Returns:
        0 if healthy, 1 if stale, failing, a workflow is disabled, or an input
        could not be read.
    """
    parser = argparse.ArgumentParser(prog="watchdog")
    parser.add_argument("--runs-dir", type=Path)
    parser.add_argument(
        "--limit-hours",
        type=float,
        default=None,
        help="Allowed age of the newest record. Order: this option, watchdog.limit_hours of --policy-file, 8.",
    )
    parser.add_argument(
        "--policy-file",
        type=Path,
        help=(
            "Policy_File to read watchdog.limit_hours from. A relative path is also tried from the repository "
            "root. Default: docs/agent/supply-chain-policy.json of the repository. Unreadable or invalid: "
            "exit 1, and a report in the error state is written."
        ),
    )
    parser.add_argument(
        "--chain-ack",
        type=Path,
        help=(
            "Ledger of abandoned chain tips (docs/agent/supply-chain-chain-ack.json). The listed records are read as "
            "outside the chain, so an accepted fork is not reported. An invalid ledger (a record with a child, an "
            "unknown SHA-256) exits 1 with a report in the error state. An absent file is read as no decision."
        ),
    )
    parser.add_argument("--failure-limit", type=int, default=watchdog.DEFAULT_FAILURE_LIMIT)
    parser.add_argument(
        "--workflows-json",
        type=Path,
        help="Body of the GitHub 'list repository workflows' response; any workflow not active fails the check.",
    )
    parser.add_argument(
        "--report-file", type=Path, help="Write the JSON report a person reads, with the next due date."
    )
    parser.add_argument(
        "--previous-report",
        type=Path,
        help="Report of the last run. If its next_check_due had passed, this run exits 1. Absent file: first run.",
    )
    parser.add_argument(
        "--overdue-check",
        type=Path,
        metavar="REPORT",
        help="Only read REPORT and exit 1 if its next_check_due has passed or it cannot be read.",
    )
    parser.add_argument("--report-due-hours", type=float, default=watchdog.DEFAULT_REPORT_DUE_HOURS)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)

    clock = now or datetime.now(UTC)
    if args.overdue_check is not None:
        return _overdue_check(args.overdue_check, clock)
    if args.runs_dir is None:
        parser.error("--runs-dir is required unless --overdue-check is given")
    previous_overdue: bool | None = None
    previous_unreadable = False
    if args.previous_report is not None and args.previous_report.exists():
        try:
            previous_overdue = watchdog.report_overdue(_read_report(args.previous_report), clock)
        except (OSError, ValueError) as exc:
            LOGGER.error("previous report could not be read: %s", exc)
            previous_unreadable = True
        else:
            if previous_overdue:
                LOGGER.error("the previous weekly check was overdue: a check was skipped")
    elif args.previous_report is not None:
        previous_overdue = False
    if args.limit_hours is None:
        args.limit_hours = float(watchdog.DEFAULT_LIMIT_HOURS)
        try:
            configured = policy_module.parse_policy(
                resolve_policy_file(args.policy_file).read_text(encoding="utf-8")
            ).watchdog_limit_hours
        except (OSError, policy_module.PolicyError) as exc:
            LOGGER.error("policy file could not be used: %s", exc)
            if args.report_file is not None:
                _write_error_report(args.report_file, clock, args.report_due_hours, str(exc), previous_overdue)
            return 1
        if configured is not None:
            args.limit_hours = float(configured)
    entries = read_record_entries(args.runs_dir)
    chain_entries = entries
    if args.chain_ack is not None and args.chain_ack.exists():
        try:
            accepted = chain_recovery.parse_ledger(args.chain_ack.read_text(encoding="utf-8"))
        except (OSError, chain_recovery.LedgerError) as exc:
            return _chain_ack_failed(args, clock, f"chain ledger could not be used: {exc}", previous_overdue)
        chain_entries, problems = chain_recovery.effective_entries(entries, accepted)
        if problems:
            return _chain_ack_failed(
                args, clock, "chain ledger does not stand: " + "; ".join(problems), previous_overdue
            )
    result = watchdog.check(
        [text for _path, text in entries], clock, args.limit_hours, args.failure_limit, chain_entries=chain_entries
    )
    LOGGER.info(
        "stale=%s failing=%s consecutive_failures=%d latest_saved_at=%s invalid_records=%d limit_hours=%s",
        result.stale,
        result.failing,
        result.consecutive_failures,
        result.latest_saved_at.isoformat() if result.latest_saved_at else None,
        result.invalid_records,
        args.limit_hours,
    )
    if result.invalid_records:
        LOGGER.warning(
            "WARNING: %d record(s) were not counted (unparsable or dated in the future)", result.invalid_records
        )

    for chain_break in result.chain_breaks:
        LOGGER.error("record chain broken: %s (%s)", chain_break.path, chain_break.reason)
    disabled: tuple[str, ...] = ()
    unreadable = False
    if args.workflows_json is not None:
        try:
            disabled = watchdog.disabled_workflows(args.workflows_json.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            LOGGER.error("workflow listing could not be read: %s", exc)
            unreadable = True
        else:
            LOGGER.info("disabled_workflows=%s", ", ".join(disabled) or "none")

    healthy = result.healthy and not disabled and not unreadable
    if args.report_file is not None:
        report = watchdog.render_report(result, disabled, clock, args.report_due_hours)
        report["healthy"] = healthy
        report["state"] = "error" if unreadable else ("ok" if healthy else "unhealthy")
        if previous_overdue is not None:
            report["previous_check_overdue"] = previous_overdue
        args.report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if healthy and not previous_overdue and not previous_unreadable else 1


if __name__ == "__main__":
    sys.exit(main())

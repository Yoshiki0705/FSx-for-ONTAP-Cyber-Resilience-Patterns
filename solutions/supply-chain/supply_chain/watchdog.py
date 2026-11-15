"""Staleness check for the Aggregator's run records (Requirements 7.2, 25.3, 25.6).

Pure code. No I/O, no clock reads: the caller passes ``now`` and the record
texts. The check reads the ``supply-chain-runs`` branch and fails when

* the newest record is older than ``limit_hours`` (8 by default: the 6-hour cron
  interval of the Aggregator plus 2 hours for ``schedule`` delay), or
* the newest ``failure_limit`` records all say ``failure``. A run that fails every
  time still saves a record, so age alone would read it as alive, or
* the record chain does not hold (``run_record.verify_chain``): a record was edited,
  removed, inserted or replaced. Staleness and failure streaks
  see only the newest records; a rewrite of an older one is visible only here.

Where it runs matters as much as what it checks. A scheduled workflow in the
same public repository as the Aggregator is switched off by GitHub after 60
days without repository activity, and both stop together. The functions
``disabled_workflows``, ``render_report`` and ``report_overdue`` serve the
observer that does not share that fate: a command a maintainer runs from a
machine outside GitHub Actions (``watchdog_cli --workflows-json``).

* ``is_stale``: exactly ``limit_hours`` is not stale; one second more is. No
  record at all is stale. A saved time in the future is not stale.
* ``latest_saved_at``: the newest ``finished_at`` among the records that parse.
  With ``now`` given, a record dated more than 5 minutes after ``now`` is
  invalid: one wrong clock must not keep the watchdog quiet for good.
* ``check``: combines these and counts the texts that did not count. A record
  that does not parse, or lies in the future, never counts as a sign of life.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from supply_chain import run_record
from supply_chain.models import DEFAULT_WATCHDOG_LIMIT_HOURS

DEFAULT_LIMIT_HOURS = DEFAULT_WATCHDOG_LIMIT_HOURS
DEFAULT_FAILURE_LIMIT = run_record.FAILURE_STREAK_THRESHOLD
FUTURE_TOLERANCE = timedelta(minutes=5)
DEFAULT_REPORT_DUE_HOURS = 192  # 8 days: a weekly check plus one day of slack


@dataclass(frozen=True)
class WatchdogResult:
    """Outcome of one watchdog check.

    ``stale`` is about age, ``failing`` about the end states. ``invalid_records``
    counts texts that did not parse and records dated in the future.
    ``chain_breaks`` lists where ``prev_record_sha256`` does not hold (empty when
    the chain was not checked or holds).
    """

    stale: bool
    latest_saved_at: datetime | None
    invalid_records: int
    consecutive_failures: int = 0
    failing: bool = False
    chain_breaks: tuple[run_record.ChainBreak, ...] = ()

    @property
    def healthy(self) -> bool:
        """True when the newest record is recent, the latest runs are not all failures and the chain holds."""
        return not self.stale and not self.failing and not self.chain_breaks


def _require_aware(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def is_stale(
    latest_saved_at: datetime | None,
    now: datetime,
    limit_hours: float = DEFAULT_LIMIT_HOURS,
) -> bool:
    """Tells whether the newest record is too old.

    Args:
        latest_saved_at: Save time of the newest record, or None if there is none.
        now: Current time, timezone-aware.
        limit_hours: Allowed age in hours. An age equal to the limit is fine.

    Returns:
        True if there is no record or the record is older than the limit.

    Raises:
        ValueError: If a datetime is naive.
    """
    _require_aware("now", now)
    if latest_saved_at is None:
        return True
    _require_aware("latest_saved_at", latest_saved_at)
    return now - latest_saved_at > timedelta(hours=limit_hours)


def _parse_records(record_texts: Iterable[str], now: datetime | None) -> tuple[list[run_record.RunRecord], int]:
    """Parses the texts; returns the usable records and the number that were not."""
    if now is not None:
        _require_aware("now", now)
    records: list[run_record.RunRecord] = []
    invalid = 0
    for text in record_texts:
        try:
            record = run_record.from_json(text)
        except run_record.RunRecordError:
            invalid += 1
            continue
        if now is not None and record.finished_at - now > FUTURE_TOLERANCE:
            invalid += 1
            continue
        records.append(record)
    return records, invalid


def latest_saved_at(record_texts: Iterable[str], now: datetime | None = None) -> tuple[datetime | None, int]:
    """Finds the newest save time among run record JSON texts.

    Args:
        record_texts: Contents of the run record files.
        now: Current time. When given, a record whose ``finished_at`` is more
            than 5 minutes after it counts as invalid instead of newest.

    Returns:
        The newest ``finished_at`` (None if no text counts) and the number of
        texts that did not count.
    """
    records, invalid = _parse_records(record_texts, now)
    newest = max((r.finished_at for r in records), default=None)
    return newest, invalid


def consecutive_failures(records: Iterable[run_record.RunRecord]) -> int:
    """Counts the failed runs at the head of the records, newest first.

    Args:
        records: Run records in any order.

    Returns:
        The number of leading records whose ``end_state`` is ``failure`` once
        sorted by ``finished_at``, newest first. A success ends the streak.
    """
    streak = 0
    for record in sorted(records, key=lambda r: r.finished_at, reverse=True):
        if record.end_state != "failure":
            break
        streak += 1
    return streak


def _chain_breaks(entries: Iterable[tuple[str, str]]) -> tuple[run_record.ChainBreak, ...]:
    """Chain breaks that change the verdict.

    A text that is not a run record is already counted in ``invalid_records`` and warned about; it does not
    fail the check by itself. Replacing a record with such a text still shows: the record after it names a
    predecessor that is no longer there (``prev_mismatch``).
    """
    return tuple(b for b in run_record.verify_chain(entries) if b.reason != "unreadable")


def check(
    record_texts: Iterable[str],
    now: datetime,
    limit_hours: float = DEFAULT_LIMIT_HOURS,
    failure_limit: int = DEFAULT_FAILURE_LIMIT,
    chain_entries: Iterable[tuple[str, str]] | None = None,
) -> WatchdogResult:
    """Checks the records against the age limit and the failure streak.

    Args:
        record_texts: Contents of the run record files.
        now: Current time, timezone-aware.
        limit_hours: Allowed age in hours.
        failure_limit: The streak of failed runs at which the check fails.
        chain_entries: ``(path, text)`` of every stored record, to verify the hash chain
            with ``run_record.verify_chain``. ``None`` skips the chain check.

    Returns:
        The staleness, the newest save time, the count of texts that did not
        count, the failure streak, whether it reached ``failure_limit`` and the
        chain breaks.
    """
    records, invalid = _parse_records(record_texts, now)
    newest = max((r.finished_at for r in records), default=None)
    streak = consecutive_failures(records)
    return WatchdogResult(
        is_stale(newest, now, limit_hours),
        newest,
        invalid,
        streak,
        streak >= failure_limit,
        () if chain_entries is None else _chain_breaks(chain_entries),
    )


def disabled_workflows(listing_json: str) -> tuple[str, ...]:
    """Names the workflows GitHub or a person has switched off.

    Reads the body of ``GET /repos/{owner}/{repo}/actions/workflows``. The
    ``state`` field is one of ``active``, ``deleted``, ``disabled_fork``,
    ``disabled_inactivity`` and ``disabled_manually`` (GitHub REST API
    reference). ``disabled_inactivity`` is the 60-day case. ``deleted`` is not
    reported: the file is gone, which another check owns.

    Args:
        listing_json: The response body.

    Returns:
        Names of workflows whose state is neither ``active`` nor ``deleted``.

    Raises:
        ValueError: If the text is not a workflow listing. An unreadable
            listing, and an empty one, is never read as "nothing is disabled".
    """
    try:
        data = json.loads(listing_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"workflow listing is not JSON: {exc}") from exc
    workflows = data.get("workflows") if isinstance(data, dict) else None
    if not isinstance(workflows, list):
        raise ValueError("workflow listing has no 'workflows' array")
    if not workflows:
        # A token without access, or a wrong repository, returns an empty list; it is not "nothing is disabled".
        raise ValueError("workflow listing is empty")
    disabled: list[str] = []
    for item in workflows:
        if not isinstance(item, dict) or not isinstance(item.get("state"), str):
            raise ValueError("workflow listing has an entry without a 'state'")
        if item["state"] not in {"active", "deleted"}:
            disabled.append(str(item.get("name") or item.get("path") or "unknown"))
    return tuple(disabled)


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_report(
    result: WatchdogResult,
    disabled: tuple[str, ...],
    now: datetime,
    due_hours: float = DEFAULT_REPORT_DUE_HOURS,
) -> dict[str, object]:
    """Builds the record a person reads after one observer run.

    The record says when the check ran and when the next one is due. If the
    due time passes with no newer record, the observer itself has stopped, and
    that is visible without any automation.

    Args:
        result: The outcome of ``check``.
        disabled: Workflow names from ``disabled_workflows`` (empty when the
            listing was not checked).
        now: Time of the check, timezone-aware.
        due_hours: Hours until the next check is due.

    Returns:
        A JSON-compatible dict.
    """
    _require_aware("now", now)
    return {
        "checked_at": _utc_text(now),
        "next_check_due": _utc_text(now + timedelta(hours=due_hours)),
        "healthy": result.healthy and not disabled,
        "stale": result.stale,
        "failing": result.failing,
        "consecutive_failures": result.consecutive_failures,
        "latest_saved_at": _utc_text(result.latest_saved_at) if result.latest_saved_at else None,
        "invalid_records": result.invalid_records,
        "chain_breaks": [{"path": b.path, "reason": b.reason} for b in result.chain_breaks],
        "disabled_workflows": list(disabled),
    }


def report_overdue(report: dict[str, object], now: datetime) -> bool:
    """Tells whether the next check in ``report`` is already late.

    Args:
        report: A dict from ``render_report``.
        now: Current time, timezone-aware.

    Returns:
        True if ``now`` is after ``next_check_due``.

    Raises:
        ValueError: If ``next_check_due`` is missing or not a UTC ``...Z`` time.
    """
    _require_aware("now", now)
    due = report.get("next_check_due")
    if not isinstance(due, str):
        raise ValueError("report has no next_check_due")
    try:
        due_at = datetime.strptime(due, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValueError(f"next_check_due is not a UTC time: {due!r}") from exc
    return now > due_at

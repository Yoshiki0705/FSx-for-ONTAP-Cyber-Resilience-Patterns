"""Staleness check for the Aggregator's run records (Requirements 7.2, 25.3, 25.6).

Pure code. No I/O, no clock reads: the caller passes ``now`` and the record
texts. A separate watchdog workflow reads the ``supply-chain-runs`` branch and
fails when the newest record is older than ``limit_hours`` (12 by default).

* ``is_stale``: exactly ``limit_hours`` is not stale; one second more is. No
  record at all is stale. A saved time in the future is not stale.
* ``latest_saved_at``: the newest ``finished_at`` among the records that parse.
* ``check``: combines the two and counts the texts that did not parse. A
  record that does not parse never counts as a sign of life.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from supply_chain import run_record

DEFAULT_LIMIT_HOURS = 12


@dataclass(frozen=True)
class WatchdogResult:
    """Outcome of one watchdog check."""

    stale: bool
    latest_saved_at: datetime | None
    invalid_records: int


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


def latest_saved_at(record_texts: Iterable[str]) -> tuple[datetime | None, int]:
    """Finds the newest save time among run record JSON texts.

    Args:
        record_texts: Contents of the run record files.

    Returns:
        The newest ``finished_at`` (None if no text parses) and the number of
        texts that did not parse.
    """
    newest: datetime | None = None
    invalid = 0
    for text in record_texts:
        try:
            finished = run_record.from_json(text).finished_at
        except run_record.RunRecordError:
            invalid += 1
            continue
        if newest is None or finished > newest:
            newest = finished
    return newest, invalid


def check(
    record_texts: Iterable[str],
    now: datetime,
    limit_hours: float = DEFAULT_LIMIT_HOURS,
) -> WatchdogResult:
    """Checks the records against the age limit.

    Args:
        record_texts: Contents of the run record files.
        now: Current time, timezone-aware.
        limit_hours: Allowed age in hours.

    Returns:
        The staleness, the newest save time and the count of unparsable texts.
    """
    newest, invalid = latest_saved_at(record_texts)
    return WatchdogResult(is_stale(newest, now, limit_hours), newest, invalid)

"""Response-time actuals for the Response_Target (Requirements 18.3, 18.4, 18.6).

Pure computation over per-Issue timelines. No I/O, no clock reads: ``now`` and
the run identifier are arguments.

Definitions:

* Origin (``compute_origin``): ``max(threshold_met_at, first_observed_component_at)``.
  A KEV ``dateAdded`` is a date and counts as 00:00:00Z of that day. When the
  time that met the threshold is unavailable, the origin is unknown (``None``).
* Detection actual: ``opened_at - origin_at``. Issues with an unknown origin
  are left out and counted in ``detection.excluded_unknown_start``.
* Fix actual: ``closed_at - opened_at``, for Issues closed with the reason
  ``resolved`` only. It is split into three intervals: detection to opened
  (the detection actual), opened to pull request created, pull request created
  to merged. The two pull-request intervals use resolved Issues only.
* Pull request choice: among the pull requests of the same ``(repo, vuln_id)``
  created at or after ``opened_at``, the one merged first; if none merged,
  the one created first. A pull request created before the Issue does not
  answer the Issue and is ignored.
* Per repository: open Issues whose ``due_at`` is before ``now``, and Issues
  opened in the given run whose detection actual is longer than
  ``detect_hours``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone

from supply_chain.models import CloseReason, PullRequestRef, Repo


def _require_utc(name: str, value: datetime | None) -> None:
    """Rejects a naive datetime or one whose UTC offset is not zero.

    Args:
        name: Field name used in the error message.
        value: The datetime to check; ``None`` is accepted.

    Raises:
        ValueError: If ``value`` is naive or not in UTC.
    """
    if value is None:
        return
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise ValueError(f"{name} must be timezone-aware and in UTC")


def kev_origin(date_added: date) -> datetime:
    """Returns the KEV ``dateAdded`` as 00:00:00Z of that day (Requirement 18.3).

    Args:
        date_added: The KEV date, which carries no time of day.

    Returns:
        A UTC datetime at midnight.
    """
    return datetime.combine(date_added, time(0, 0, 0), tzinfo=timezone.utc)


def compute_origin(threshold_met_at: datetime | None, first_observed_component_at: datetime) -> datetime | None:
    """Returns the origin of the response time, or ``None`` when unknown.

    Args:
        threshold_met_at: When the Opening_Threshold was first met: the advisory
            publication time, ``kev_origin(dateAdded)``, or the ``MAL-`` record
            publication time. ``None`` when it could not be obtained.
        first_observed_component_at: The first run that saw the component version.

    Returns:
        ``max(threshold_met_at, first_observed_component_at)``, or ``None``
        when ``threshold_met_at`` is ``None`` (Requirement 18.4).
    """
    if threshold_met_at is None:
        return None
    return max(threshold_met_at, first_observed_component_at)


@dataclass(frozen=True, slots=True)
class IssueTimeline:
    """The times of one finding Issue.

    Attributes:
        repo: Repository of the Issue.
        vuln_id: The Issue's representative identifier (matches ``PullRequestRef``).
        origin_at: Origin, or ``None`` when unknown.
        opened_at: When the Issue was opened.
        opened_run_id: Run that opened the Issue.
        due_at: Fix deadline, or ``None`` when not recorded.
        closed_at: When the Issue was closed; ``None`` while open.
        close_reason: Reason of the close; ``None`` while open.
    """

    repo: Repo
    vuln_id: str
    origin_at: datetime | None
    opened_at: datetime
    opened_run_id: str
    due_at: datetime | None
    closed_at: datetime | None
    close_reason: CloseReason | None

    def __post_init__(self) -> None:
        for name in ("origin_at", "opened_at", "due_at", "closed_at"):
            _require_utc(name, getattr(self, name))
        if (self.closed_at is None) != (self.close_reason is None):
            raise ValueError("closed_at and close_reason must both be set or both be None")


@dataclass(frozen=True, slots=True)
class IntervalStats:
    """Durations of one interval and the Issues left out.

    Attributes:
        durations: One duration per counted Issue, sorted ascending.
        excluded_unknown_start: Issues whose start of the interval is unknown.
        missing_end: Issues whose start is known but whose end does not exist
            yet (no pull request, or the pull request is not merged).
    """

    durations: tuple[timedelta, ...]
    excluded_unknown_start: int
    missing_end: int


@dataclass(frozen=True, slots=True)
class RepoMetrics:
    """Per-repository counts of Requirement 18.6."""

    repo: Repo
    overdue_open: int
    detection_over_target: int


@dataclass(frozen=True, slots=True)
class ResponseMetrics:
    """The response-time actuals of one run.

    Attributes:
        detection: Detection to opened.
        opened_to_pr: Opened to pull request created (resolved Issues).
        pr_to_merge: Pull request created to merged (resolved Issues).
        fix: Opened to closed (resolved Issues).
        excluded_unknown_origin: Issues left out of the detection actual
            because the origin is unknown (Requirement 18.4).
        by_repo: Sorted by lower-case ``owner/name``.
    """

    detection: IntervalStats
    opened_to_pr: IntervalStats
    pr_to_merge: IntervalStats
    fix: IntervalStats
    excluded_unknown_origin: int
    by_repo: tuple[RepoMetrics, ...]


def _repo_key(repo: Repo) -> str:
    return f"{repo.owner.lower()}/{repo.name.lower()}"


def _choose_pr(issue: IssueTimeline, prs: Iterable[PullRequestRef]) -> PullRequestRef | None:
    """Returns the pull request that answers ``issue``, or ``None``."""
    candidates = [
        p for p in prs if p.repo == issue.repo and p.vuln_id == issue.vuln_id and p.created_at >= issue.opened_at
    ]
    if not candidates:
        return None
    merged = [p for p in candidates if p.merged_at is not None]
    if merged:
        return min(merged, key=lambda p: (p.merged_at or p.created_at, p.created_at))
    return min(candidates, key=lambda p: p.created_at)


def compute_metrics(
    issues: Iterable[IssueTimeline],
    pull_requests: Iterable[PullRequestRef],
    detect_hours: int,
    now: datetime,
    run_id: str,
    repos: Iterable[Repo] = (),
) -> ResponseMetrics:
    """Computes the response-time actuals.

    Args:
        issues: Finding Issues with their times.
        pull_requests: Pull requests that may answer the Issues.
        detect_hours: ``response_target.detect_hours``.
        now: The run time, for the overdue count.
        run_id: The current run; Issues with this ``opened_run_id`` count for
            the 24-hour check.
        repos: Repositories to list even when they have no Issue.

    Returns:
        The actuals. Durations are sorted, so the result does not depend on
        the order of the inputs.
    """
    _require_utc("now", now)
    issue_list = list(issues)
    pr_list = list(pull_requests)
    limit = timedelta(hours=detect_hours)

    detect: list[timedelta] = []
    unknown_origin = 0
    to_pr: list[timedelta] = []
    pr_merge: list[timedelta] = []
    fix: list[timedelta] = []
    no_pr = 0
    not_merged = 0
    counts: dict[str, list[int]] = {_repo_key(r): [0, 0] for r in repos}
    names: dict[str, Repo] = {_repo_key(r): r for r in repos}

    for issue in issue_list:
        key = _repo_key(issue.repo)
        names.setdefault(key, issue.repo)
        row = counts.setdefault(key, [0, 0])
        if issue.origin_at is None:
            unknown_origin += 1
        else:
            span = issue.opened_at - issue.origin_at
            detect.append(span)
            if issue.opened_run_id == run_id and span > limit:
                row[1] += 1
        if issue.closed_at is None and issue.due_at is not None and issue.due_at < now:
            row[0] += 1
        if issue.close_reason != "resolved" or issue.closed_at is None:
            continue
        fix.append(issue.closed_at - issue.opened_at)
        pr = _choose_pr(issue, pr_list)
        if pr is None:
            no_pr += 1
            continue
        to_pr.append(pr.created_at - issue.opened_at)
        if pr.merged_at is None:
            not_merged += 1
        else:
            pr_merge.append(pr.merged_at - pr.created_at)

    return ResponseMetrics(
        detection=IntervalStats(tuple(sorted(detect)), unknown_origin, 0),
        opened_to_pr=IntervalStats(tuple(sorted(to_pr)), 0, no_pr),
        pr_to_merge=IntervalStats(tuple(sorted(pr_merge)), 0, no_pr + not_merged),
        fix=IntervalStats(tuple(sorted(fix)), 0, 0),
        excluded_unknown_origin=unknown_origin,
        by_repo=tuple(RepoMetrics(names[k], counts[k][0], counts[k][1]) for k in sorted(counts)),
    )

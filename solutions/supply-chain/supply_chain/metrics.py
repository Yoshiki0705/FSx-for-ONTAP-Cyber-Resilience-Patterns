"""Response-time actuals for the Response_Target (Requirements 18.3, 18.4, 18.6).

Pure computation over per-Issue timelines. No I/O, no clock reads: ``now`` and
the run identifier are arguments.

Definitions:

* Origin (``compute_origin``): ``max(threshold_met_at, first_observed_component_at)``.
  A KEV ``dateAdded`` is a date and counts as 00:00:00Z of that day. When the
  time that met the threshold is unavailable, the origin is unknown (``None``).
* KEV origin is an interval. ``dateAdded`` carries no time of day (CISA's
  catalogue read 2026-11-14), so the listing happened between 00:00:00Z of that
  day (``origin_at``, the lower bound) and the ``dateReleased`` of the first
  catalogue version in which the Aggregator saw the entry (``origin_upper_at``,
  an upper bound: the entry was already public when that version was released).
  The detection actual is reported against both. Only a span that exceeds the
  target even against the upper bound is a certain miss
  (``RepoMetrics.detection_over_target_certain``); a span over the target only
  against the lower bound may be a miss or may be the hours of the day before
  the listing, and is not counted as certain.
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
        A UTC datetime at midnight: the earliest moment the listing can have happened (a lower bound).
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
        origin_at: Origin, or ``None`` when unknown. For a KEV origin this is the
            lower bound (``dateAdded`` at 00:00:00Z).
        opened_at: When the Issue was opened.
        opened_run_id: Run that opened the Issue.
        due_at: Fix deadline, or ``None`` when not recorded.
        closed_at: When the Issue was closed; ``None`` while open.
        close_reason: Reason of the close; ``None`` while open.
        origin_upper_at: Upper bound of a KEV origin (``dateReleased`` of the
            first catalogue the Aggregator read the entry in); ``None`` when
            the origin is not a KEV date or the bound is unknown.
    """

    repo: Repo
    vuln_id: str
    origin_at: datetime | None
    opened_at: datetime
    opened_run_id: str
    due_at: datetime | None
    closed_at: datetime | None
    close_reason: CloseReason | None
    origin_upper_at: datetime | None = None
    duplicate_of: str | None = None

    def __post_init__(self) -> None:
        for name in ("origin_at", "opened_at", "due_at", "closed_at", "origin_upper_at"):
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
    detection_over_target_certain: int = 0


@dataclass(frozen=True, slots=True)
class ResponseMetrics:
    """The response-time actuals of one run.

    Attributes:
        detection: Detection to opened, against ``origin_at`` (for a KEV origin
            the lower bound, so the longest possible span).
        detection_upper: Detection to opened against ``origin_upper_at``, for the
            Issues that have one (the shortest possible span).
        opened_to_pr: Opened to pull request created (resolved Issues).
        pr_to_merge: Pull request created to merged (resolved Issues).
        fix: Opened to closed (resolved Issues).
        excluded_unknown_origin: Issues left out of the detection actual
            because the origin is unknown (Requirement 18.4).
        by_repo: Sorted by lower-case ``owner/name``.
    """

    detection: IntervalStats
    detection_upper: IntervalStats
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
    upper: list[timedelta] = []
    counts: dict[str, list[int]] = {_repo_key(r): [0, 0, 0] for r in repos}
    names: dict[str, Repo] = {_repo_key(r): r for r in repos}

    for issue in issue_list:
        key = _repo_key(issue.repo)
        names.setdefault(key, issue.repo)
        row = counts.setdefault(key, [0, 0, 0])
        if issue.duplicate_of is not None:
            continue  # a duplicate is counted under its representative (T2-R3-07)
        if issue.origin_at is None:
            unknown_origin += 1
        else:
            span = issue.opened_at - issue.origin_at
            detect.append(span)
            tight = span if issue.origin_upper_at is None else issue.opened_at - issue.origin_upper_at
            if issue.origin_upper_at is not None:
                upper.append(tight)
            if issue.opened_run_id == run_id and span > limit:
                row[1] += 1
                if tight > limit:
                    row[2] += 1  # over the target even against the latest possible origin
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
        detection_upper=IntervalStats(tuple(sorted(upper)), 0, 0),
        opened_to_pr=IntervalStats(tuple(sorted(to_pr)), 0, no_pr),
        pr_to_merge=IntervalStats(tuple(sorted(pr_merge)), 0, no_pr + not_merged),
        fix=IntervalStats(tuple(sorted(fix)), 0, 0),
        excluded_unknown_origin=unknown_origin,
        by_repo=tuple(RepoMetrics(names[k], counts[k][0], counts[k][1], counts[k][2]) for k in sorted(counts)),
    )


MAX_UNDECIDED_PERCENT = (
    20  # provisional (Evidence_Tier hypothesis): above this share of undecided Issues no rate is reported
)
MIN_PILOT_ISSUES = 20  # smallest pilot sample for which a rate is reported (Evidence_Tier hypothesis, Requirement 22.1)
FALSE_POSITIVE_JUSTIFICATION = "component_not_present"


@dataclass(frozen=True, slots=True)
class PilotIssueOutcome:
    """What the VEX reviewers decided about one Issue the pilot opened.

    Attributes:
        vex_status: Status of the approved statement that covers the Issue; ``None`` when none does.
        justification: Its justification label, if any.
        detector_error: True when a maintainer classified the Issue as the Aggregator's own error even
            though no ``component_not_present`` statement says so.
        duplicate: True when the Issue is the duplicate side of another Issue (``duplicate_of`` is set,
            Requirement 8.38). It is counted under its representative, so it is left out of the denominator
            and of the undecided count (T12-R4-08).
        opened_at: When the Issue was opened (UTC). Needed only when ``compute_pilot_rates`` is given a window
            (a restart of the observation, or an evaluation time); ``None`` otherwise.
    """

    vex_status: str | None
    justification: str | None = None
    detector_error: bool = False
    duplicate: bool = False
    opened_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class PilotRates:
    """Counts and the false-positive rate of the pilot (Requirement 22.2).

    Attributes:
        issued: Issues the pilot opened, duplicate sides excluded. It equals
            ``false_positive + not_affected_other + fixed + affected + undecided``.
        false_positive: Issues where the detector was wrong: ``not_affected`` with
            ``component_not_present`` (the component is not in the product, so it should not have been
            reported), or classified by a maintainer as a detector error.
        not_affected_other: ``not_affected`` for any other justification. The detector was right and the
            reviewers judged the vulnerability not to matter for the product; this is VEX working as
            intended, and counting it as a false positive would make a correct detector look noisy.
        undecided: Issues no reviewer has decided yet: no approved statement, or only an
            ``under_investigation`` one (OpenVEX: whether the product is affected is not known yet).
        fixed: Issues with a ``fixed`` statement that are not detector errors.
        affected: Issues with an ``affected`` statement that are not detector errors (a correct detection
            waiting for a fix).
        duplicates: Duplicate-side Issues, which are not in ``issued`` (Requirement 8.38).
        rate_percent: ``100 * false_positive / issued``, or ``None`` when ``issued`` is below
            ``min_issues`` (too few Issues for a rate to mean anything) or when ``awaiting_decisions``.
            The sample size and the rate both count the Issues the pilot opened, decided or not.
        min_issues: The smallest sample for a rate.
        under_investigation: Issues in ``undecided`` whose statement is ``under_investigation``. They count as
            undecided on purpose, also while the maintainer waits for an upstream answer (T3-R6-02).
        carried_over: Issues opened after ``window_end``. They are left out of every other count and belong to the
            next observation's first record (T3-R6-02).
        before_window: Issues opened before ``window_start`` (a restart of the observation): not in this
            observation's denominator (T3-R6-01).
        awaiting_decisions: More than ``MAX_UNDECIDED_PERCENT`` of the issued Issues are undecided, so the rate
            is withheld: undecided Issues sit in the denominator with no error, and the rate would fall as
            the decisions are postponed. Report "awaiting decisions" instead (T3-R3-04).
    """

    issued: int
    false_positive: int
    not_affected_other: int
    undecided: int
    rate_percent: float | None
    min_issues: int
    awaiting_decisions: bool = False
    fixed: int = 0
    affected: int = 0
    duplicates: int = 0
    under_investigation: int = 0
    carried_over: int = 0
    before_window: int = 0


def compute_pilot_rates(
    outcomes: Iterable[PilotIssueOutcome],
    min_issues: int = MIN_PILOT_ISSUES,
    *,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> PilotRates:
    """Computes the pilot's false-positive rate without counting correct detections that did not matter.

    Args:
        outcomes: One entry per Issue the pilot opened.
        min_issues: Below this many Issues the rate is ``None``.
        window_start: Start of a restarted observation (UTC, inclusive). Issues opened before it are not counted
            (T3-R6-01): the Issues of the earlier observation stay open after the detector is fixed, and
            counting them would keep the errors in the denominator.
        window_end: The time at which the set is cut (UTC, inclusive), normally the end of the observation
            period. Issues opened later are counted in ``carried_over`` only (T3-R6-02): the Aggregator keeps
            running, so a late Issue would otherwise be an undecided one at the moment of the decision.
            The caller passes only the Issues of the repositories under observation (a batch's own repositories,
            not the earlier ones; T3-R7-06) and never the test Issue of Requirement 22.16 (T3-R7-01).
    Returns:
        The counts and the rate. ``fixed`` and ``affected`` statements and undecided Issues are not
        false positives. Every non-duplicate Issue is counted in exactly one of the five counts.


    Raises:
        ValueError: If a time is not UTC, ``window_start`` is after ``window_end``, or an outcome has no
            ``opened_at`` while a window is given.
    """
    _require_utc("window_start", window_start)
    _require_utc("window_end", window_end)
    if window_start is not None and window_end is not None and window_start > window_end:
        raise ValueError("window_start is after window_end")  # T12-R7-04: do not turn a swapped call into 0 Issues
    all_items = list(outcomes)
    carried_over = before_window = 0
    if window_start is not None or window_end is not None:
        inside: list[PilotIssueOutcome] = []
        for item in all_items:
            if item.opened_at is None:
                raise ValueError("every outcome needs opened_at when a window is given")
            _require_utc("opened_at", item.opened_at)
            if window_start is not None and item.opened_at < window_start:
                before_window += not item.duplicate
            elif window_end is not None and item.opened_at > window_end:
                carried_over += not item.duplicate
            else:
                inside.append(item)
        all_items = inside
    items = [i for i in all_items if not i.duplicate]
    false_positive = not_affected_other = undecided = fixed = affected = under_investigation = 0
    for item in items:
        if item.vex_status == "not_affected":
            if item.justification == FALSE_POSITIVE_JUSTIFICATION or item.detector_error:
                false_positive += 1
            else:
                not_affected_other += 1
        elif item.detector_error:
            false_positive += 1
        elif item.vex_status == "fixed":
            fixed += 1
        elif item.vex_status == "affected":
            affected += 1
        else:  # None, under_investigation, or any status this module does not know: not decided
            undecided += 1
            under_investigation += item.vex_status == "under_investigation"
    issued = len(items)
    awaiting = issued > 0 and 100 * undecided > MAX_UNDECIDED_PERCENT * issued
    enough = issued >= max(min_issues, 1)
    rate = 100.0 * false_positive / issued if enough and not awaiting else None
    return PilotRates(
        issued,
        false_positive,
        not_affected_other,
        undecided,
        rate,
        min_issues,
        awaiting and enough,
        fixed,
        affected,
        len(all_items) - issued,
        under_investigation,
        carried_over,
        before_window,
    )


MAX_DETECTOR_ERRORS_LOW_SAMPLE = 2  # Evidence_Tier hypothesis; decided by the pilot (Requirement 22.6, 22.8)


MAX_OBSERVATION_RESTARTS = 3  # Evidence_Tier hypothesis; decided by the pilot (Requirement 22.39)


@dataclass(frozen=True, slots=True)
class RestartStatus:
    """How many restarts of the observation are left (Requirement 22.39).

    Attributes:
        restarts_done: Restarts already made. A restart is not an extension (Requirement 22.22).
        remaining: Restarts still allowed.
        may_restart: True while ``remaining`` is above 0.
        redesign_required: True when the limit is used up: the maintainer records the keep-or-roll-back decision
            (Requirement 22.7) and the decision to rebuild the detector instead of restarting again.
    """

    restarts_done: int
    remaining: int
    may_restart: bool
    redesign_required: bool


def observation_restart_status(restarts_done: int, max_restarts: int = MAX_OBSERVATION_RESTARTS) -> RestartStatus:
    """Counts the restarts of the observation after a stop that the extension rules do not cover.

    Args:
        restarts_done: Restarts already made (0 or more).
        max_restarts: The limit (3, hypothesis).

    Returns:
        The remaining count and whether another restart is allowed.

    Raises:
        ValueError: If ``restarts_done`` is negative.
    """
    if restarts_done < 0:
        raise ValueError("restarts_done must be 0 or more")
    remaining = max(max_restarts - restarts_done, 0)
    return RestartStatus(restarts_done, remaining, remaining > 0, remaining == 0)


@dataclass(frozen=True, slots=True)
class LowSampleReview:
    """The counts (Requirement 22.17) and the signals of the rule used while there are too few Issues for a rate.

    There is no pass/fail field. The next-batch decision is made by a maintainer from these counts and a
    one-by-one reading of every Issue; this object only states which conditions of the rule hold.

    Attributes:
        applies: True when ``issued`` is below the minimum sample, so no rate is reported.
        awaiting_decisions: The sample is large enough but too many Issues are undecided, so no rate is reported
            and the report says "awaiting decisions" (T3-R3-04).
        issued: Issues the pilot opened.
        detector_errors: Issues counted as the detector's error (Requirement 22.11).
        not_affected_other: ``not_affected`` for any other justification.
        undecided: Issues no reviewer has decided yet; a one-by-one judgement of every Issue is not complete while this is above 0.
        within_error_limit: ``detector_errors`` is at most ``MAX_DETECTOR_ERRORS_LOW_SAMPLE``. It does not mean
            the next batch may start: when ``errors_are_majority`` is true it may not (Requirement 22.26).
        needs_cause_classification: The errors exceed the limit, so a maintainer classifies each cause and
            decides whether the same cause repeats before the next batch.
        errors_are_majority: Detector errors are half or more of the issued Issues. Then the next batch does not
            start even when ``within_error_limit`` is true (Requirement 22.26).
        under_investigation: Issues in ``undecided`` that are ``under_investigation`` (T3-R6-02).
        restart_causes: Why the next batch does not start although Issues are decided: ``errors_over_limit``
            (more errors than the limit, 22.20), ``errors_majority`` (half or more, 22.26), ``rate_over_limit``
            (20 Issues or more and the rate is above the limit the caller passes, 22.24, 22.39) and/or
            ``no_issues_after_extensions`` (0 Issues and the extensions are used up, 22.54). Empty when none
            holds. Undecided Issues are not a cause: the maintainer waits and updates the same record (T3-R6-02).
        can_restart_observation: ``restart_causes`` is not empty. It does not look at the restart count: whether
            another restart is allowed is ``may_restart_now`` (T3-R7-07).
        needs_maintainer_decision: ``no_issues_after_extensions`` is a cause. The detector has produced nothing,
            which is not evidence either way. The maintainer records the result of the false-negative check
            (22.16) and decides to proceed or stop (22.54); this is not a failure of the detector.
        may_restart_now: ``can_restart_observation`` and, when ``restarts_done`` was passed, the restart count is
            below ``MAX_OBSERVATION_RESTARTS`` (22.39). Without ``restarts_done`` it equals
            ``can_restart_observation``.
        next_batch_conditions_hold: Every clause of Requirement 22.19 holds: at least one Issue was opened, the
            low-sample rule applies, the errors are within the limit and not a majority, and no Issue is
            undecided. Three Issues all under investigation have no error and so satisfy the other clauses; this
            field is False for them (T3-R5-01). No Issue at all is False too: 0 Issues is not evidence that the
            conditions hold (22.4, 22.36; T12-R6-02). When ``applies`` is False (20 Issues or more, where the
            rate of 22.24 is used, or too many undecided Issues for a rate) the rule does not apply and the field
            is False; that is not "do not proceed", the decision follows 22.24. It states conditions only: the
            maintainer still decides, and when it is False because Issues are undecided the remaining count and
            the reason are recorded before proceeding or stopping.
    """

    applies: bool
    issued: int
    detector_errors: int
    not_affected_other: int
    undecided: int
    within_error_limit: bool
    needs_cause_classification: bool
    awaiting_decisions: bool = False
    errors_are_majority: bool = False
    next_batch_conditions_hold: bool = False
    under_investigation: int = 0
    restart_causes: tuple[str, ...] = ()
    can_restart_observation: bool = False
    needs_maintainer_decision: bool = False
    may_restart_now: bool = False


def review_low_sample(
    rates: PilotRates,
    max_detector_errors: int = MAX_DETECTOR_ERRORS_LOW_SAMPLE,
    *,
    max_rate_percent: float | None = None,
    extensions_exhausted: bool = False,
    restarts_done: int | None = None,
) -> LowSampleReview:
    """States the counts and rule conditions of a pilot with too few Issues for a rate.

    Args:
        rates: The pilot counts from ``compute_pilot_rates``.
        max_detector_errors: The most detector errors the rule accepts without a cause classification.
        max_rate_percent: The false-positive rate limit of Requirement 22.24 (provisional; the value is decided
            by the pilot, 22.8, so it has no default). When given and the rate is reported and above it, the
            cause ``rate_over_limit`` is named. A rate equal to the limit is not over it.
        extensions_exhausted: The extensions of 22.22 or 22.27 are used up. With 0 Issues this names the cause
            ``no_issues_after_extensions`` (22.54).
        restarts_done: Restarts already made, for ``may_restart_now``.

    Returns:
        The counts and the conditions. ``applies`` is False from ``rates.min_issues`` Issues up, where
        the rate is used instead.

    Raises:
        ValueError: If ``restarts_done`` is negative.
    """
    if restarts_done is not None and restarts_done < 0:
        raise ValueError("restarts_done must be 0 or more")
    within = rates.false_positive <= max_detector_errors
    applies = rates.rate_percent is None and not rates.awaiting_decisions
    majority = rates.issued > 0 and 2 * rates.false_positive >= rates.issued
    causes = (
        *(("errors_over_limit",) if not within else ()),
        *(("errors_majority",) if majority else ()),
    )
    causes = causes if applies else ()
    if rates.rate_percent is not None and max_rate_percent is not None and rates.rate_percent > max_rate_percent:
        causes = (*causes, "rate_over_limit")
    if applies and rates.issued == 0 and extensions_exhausted:
        causes = (*causes, "no_issues_after_extensions")
    may_restart = bool(causes) and (restarts_done is None or observation_restart_status(restarts_done).may_restart)
    return LowSampleReview(
        applies=applies,
        issued=rates.issued,
        detector_errors=rates.false_positive,
        not_affected_other=rates.not_affected_other,
        undecided=rates.undecided,
        within_error_limit=within,
        needs_cause_classification=not within,
        awaiting_decisions=rates.awaiting_decisions,
        errors_are_majority=majority,
        next_batch_conditions_hold=applies and rates.issued > 0 and within and not majority and rates.undecided == 0,
        under_investigation=rates.under_investigation,
        restart_causes=causes,
        can_restart_observation=bool(causes),
        needs_maintainer_decision="no_issues_after_extensions" in causes,
        may_restart_now=may_restart,
    )


@dataclass(frozen=True, slots=True)
class SliCounts:
    """Issues closed within the deadline and the Issues that count (Requirement 18.21).

    Attributes:
        met: Issues closed with ``resolved`` at or before ``due_at``.
        denominator: Issues whose deadline has passed and whose close reason is ``resolved`` or that are
            still open. ``vex_not_affected``, ``withdrawn`` and the other reasons are not counted.
    """

    met: int
    denominator: int


def sli_counts(issues: Iterable[IssueTimeline], now: datetime) -> SliCounts:
    """Counts the response-target SLI over Issues whose deadline has passed.

    Args:
        issues: Finding Issues with their times.
        now: The run time. An Issue with no ``due_at``, or one due after ``now``, is not counted.

    Returns:
        The numerator and the denominator.
    """
    _require_utc("now", now)
    met = denominator = 0
    for issue in issues:
        if issue.duplicate_of is not None or issue.due_at is None or issue.due_at > now:
            continue
        if issue.closed_at is not None and issue.close_reason != "resolved":
            continue
        denominator += 1
        if issue.closed_at is not None and issue.closed_at <= issue.due_at:
            met += 1
    return SliCounts(met, denominator)

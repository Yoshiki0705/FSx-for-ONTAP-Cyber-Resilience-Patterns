"""Unit and property tests for ``supply_chain.metrics`` (task 9.17).

Property 16 itself (the full shift property) is task 9.18; the properties here are local checks
that keep the module honest until then.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import metrics, models

T0 = datetime(2026, 11, 1, 0, 0, tzinfo=UTC)
NOW = T0 + timedelta(days=30)
REPO = models.Repo("example-org", "svc-api")
OTHER = models.Repo("example-org", "svc-web")


def _h(hours: float) -> datetime:
    return T0 + timedelta(hours=hours)


def _issue(
    *,
    repo: models.Repo = REPO,
    vuln: str = "CVE-2026-0001",
    origin: float | None = 0,
    opened: float = 10,
    run: str = "run-1",
    due: float | None = 24 * 14,
    closed: float | None = None,
    reason: models.CloseReason | None = None,
) -> metrics.IssueTimeline:
    return metrics.IssueTimeline(
        repo=repo,
        vuln_id=vuln,
        origin_at=None if origin is None else _h(origin),
        opened_at=_h(opened),
        opened_run_id=run,
        due_at=None if due is None else _h(due),
        closed_at=None if closed is None else _h(closed),
        close_reason=reason,
    )


def _pr(
    created: float, merged: float | None, *, repo: models.Repo = REPO, vuln: str = "CVE-2026-0001"
) -> models.PullRequestRef:
    return models.PullRequestRef(repo, vuln, _h(created), None if merged is None else _h(merged))


def _run(issues, prs=(), *, hours: int = 24, now: datetime = NOW, run: str = "run-1", repos=()):
    return metrics.compute_metrics(issues, prs, hours, now, run, repos)


def test_origin_is_the_later_of_the_two_times() -> None:
    assert metrics.compute_origin(_h(5), _h(9)) == _h(9)
    assert metrics.compute_origin(_h(9), _h(5)) == _h(9)


def test_origin_is_unknown_without_the_threshold_time() -> None:
    assert metrics.compute_origin(None, _h(5)) is None


def test_kev_date_is_midnight_utc() -> None:
    assert metrics.kev_origin(date(2026, 11, 3)) == datetime(2026, 11, 3, 0, 0, 0, tzinfo=UTC)


def test_detection_actual_is_opened_minus_origin() -> None:
    result = _run([_issue(origin=2, opened=10), _issue(origin=1, opened=3, vuln="CVE-2026-0002")])
    assert result.detection.durations == (timedelta(hours=2), timedelta(hours=8))
    assert result.detection.excluded_unknown_start == 0


def test_unknown_origin_is_excluded_and_counted() -> None:
    result = _run([_issue(origin=None), _issue(origin=0, opened=5, vuln="CVE-2026-0002")])
    assert result.detection.durations == (timedelta(hours=5),)
    assert result.detection.excluded_unknown_start == 1
    assert result.excluded_unknown_origin == 1


def test_unknown_origin_issue_still_counts_for_overdue_and_fix() -> None:
    open_late = _issue(origin=None, due=5)
    fixed = _issue(origin=None, vuln="CVE-2026-0002", closed=30, reason="resolved")
    result = _run([open_late, fixed])
    assert result.by_repo[0].overdue_open == 1
    assert result.fix.durations == (timedelta(hours=20),)


@pytest.mark.parametrize("reason", ["withdrawn", "feed_version_delisted", "vex_not_affected", "vex_fixed"])
def test_fix_actual_ignores_other_close_reasons(reason: models.CloseReason) -> None:
    result = _run([_issue(closed=30, reason=reason)], [_pr(12, 20)])
    assert result.fix.durations == ()
    assert result.opened_to_pr.durations == ()
    assert result.pr_to_merge.durations == ()


def test_open_issue_is_not_in_the_fix_actual() -> None:
    assert _run([_issue()], [_pr(12, 20)]).fix.durations == ()


def test_three_intervals_for_a_resolved_issue() -> None:
    result = _run([_issue(origin=2, opened=10, closed=60, reason="resolved")], [_pr(14, 40)])
    assert result.detection.durations == (timedelta(hours=8),)
    assert result.opened_to_pr.durations == (timedelta(hours=4),)
    assert result.pr_to_merge.durations == (timedelta(hours=26),)
    assert result.fix.durations == (timedelta(hours=50),)


def test_pull_request_created_before_the_issue_is_ignored() -> None:
    result = _run([_issue(opened=10, closed=60, reason="resolved")], [_pr(5, 8), _pr(14, 40)])
    assert result.opened_to_pr.durations == (timedelta(hours=4),)


def test_pull_request_of_another_repo_or_id_is_ignored() -> None:
    prs = [_pr(14, 40, repo=OTHER), _pr(14, 40, vuln="CVE-2026-9999")]
    result = _run([_issue(closed=60, reason="resolved")], prs)
    assert result.opened_to_pr.durations == ()
    assert result.opened_to_pr.missing_end == 1
    assert result.pr_to_merge.missing_end == 1


def test_pull_request_repo_match_ignores_case() -> None:
    other_case = models.Repo("Example-Org", "SVC-API")
    result = _run([_issue(closed=60, reason="resolved")], [_pr(14, 40, repo=other_case)])
    assert result.opened_to_pr.durations == (timedelta(hours=4),)


def test_merged_pull_request_wins_over_an_earlier_unmerged_one() -> None:
    result = _run([_issue(closed=60, reason="resolved")], [_pr(11, None), _pr(20, 30)])
    assert result.opened_to_pr.durations == (timedelta(hours=10),)
    assert result.pr_to_merge.durations == (timedelta(hours=10),)


def test_earliest_merge_wins_among_merged_pull_requests() -> None:
    result = _run([_issue(closed=60, reason="resolved")], [_pr(12, 50), _pr(20, 30)])
    assert result.pr_to_merge.durations == (timedelta(hours=10),)


def test_unmerged_pull_request_counts_for_the_first_interval_only() -> None:
    result = _run([_issue(closed=60, reason="resolved")], [_pr(12, None)])
    assert result.opened_to_pr.durations == (timedelta(hours=2),)
    assert result.pr_to_merge.durations == ()
    assert result.pr_to_merge.missing_end == 1
    assert result.opened_to_pr.missing_end == 0


def test_resolved_issue_without_a_pull_request_has_no_pr_intervals() -> None:
    result = _run([_issue(closed=60, reason="resolved")])
    assert result.fix.durations == (timedelta(hours=50),)
    assert (result.opened_to_pr.missing_end, result.pr_to_merge.missing_end) == (1, 1)


def test_overdue_counts_open_issues_past_due_only() -> None:
    issues = [
        _issue(vuln="a", due=100),  # open, past due
        _issue(vuln="b", due=24 * 30),  # open, due == now: not overdue
        _issue(vuln="c", due=24 * 40),  # open, not yet due
        _issue(vuln="d", due=100, closed=200, reason="resolved"),  # closed
        _issue(vuln="e", due=None),  # no deadline recorded
    ]
    assert _run(issues).by_repo[0].overdue_open == 1


def test_detection_over_target_counts_only_this_runs_issues_strictly_over() -> None:
    issues = [
        _issue(vuln="a", origin=0, opened=25),  # 25 h, this run: counts
        _issue(vuln="b", origin=0, opened=24),  # exactly 24 h: no
        _issue(vuln="c", origin=0, opened=48, run="run-0"),  # earlier run: no
        _issue(vuln="d", origin=None, opened=99),  # unknown origin: no
    ]
    result = _run(issues)
    assert result.by_repo[0].detection_over_target == 1
    assert _run(issues, hours=1).by_repo[0].detection_over_target == 2


def test_by_repo_groups_ignoring_case_lists_empty_repos_and_sorts() -> None:
    issues = [_issue(repo=OTHER, due=1), _issue(repo=models.Repo("EXAMPLE-ORG", "SVC-API"), vuln="x", due=1)]
    lonely = models.Repo("example-org", "svc-none")
    rows = _run(issues, repos=[REPO, lonely]).by_repo
    assert [(r.repo.name.lower(), r.overdue_open) for r in rows] == [("svc-api", 1), ("svc-none", 0), ("svc-web", 1)]


def test_empty_input() -> None:
    result = _run([])
    assert result.by_repo == ()
    assert result.detection == metrics.IntervalStats((), 0, 0)


def test_naive_time_is_rejected() -> None:
    with pytest.raises(ValueError):
        replace(_issue(), opened_at=datetime(2026, 11, 1))
    with pytest.raises(ValueError):
        _run([], now=datetime(2026, 11, 1))


def test_closed_time_and_reason_go_together() -> None:
    with pytest.raises(ValueError):
        _issue(closed=30)
    with pytest.raises(ValueError):
        _issue(reason="resolved")


@st.composite
def _timelines(draw):
    """Issues and pull requests with whole-minute offsets from ``T0``."""
    n = draw(st.integers(min_value=0, max_value=6))
    issues, prs = [], []
    for i in range(n):
        repo = draw(st.sampled_from([REPO, OTHER]))
        vuln = f"CVE-2026-{i:04d}"
        origin = draw(st.one_of(st.none(), st.integers(0, 3000)))
        opened = draw(st.integers(0, 3000))
        closed = draw(st.one_of(st.none(), st.integers(opened, opened + 5000)))
        reason = draw(st.sampled_from(["resolved", "withdrawn", "vex_fixed"])) if closed is not None else None
        due = draw(st.one_of(st.none(), st.integers(0, 9000)))
        run = draw(st.sampled_from(["run-1", "run-0"]))
        issues.append(
            metrics.IssueTimeline(
                repo,
                vuln,
                None if origin is None else T0 + timedelta(minutes=origin),
                T0 + timedelta(minutes=opened),
                run,
                None if due is None else T0 + timedelta(minutes=due),
                None if closed is None else T0 + timedelta(minutes=closed),
                reason,
            )
        )
        for _ in range(draw(st.integers(0, 2))):
            created = draw(st.integers(0, 6000))
            merged = draw(st.one_of(st.none(), st.integers(created, created + 5000)))
            prs.append(
                models.PullRequestRef(
                    repo,
                    vuln,
                    T0 + timedelta(minutes=created),
                    None if merged is None else T0 + timedelta(minutes=merged),
                )
            )
    return issues, prs


def _shifted(issues, prs, delta: timedelta):
    def add(value):
        return None if value is None else value + delta

    return (
        [
            replace(
                i,
                origin_at=add(i.origin_at),
                opened_at=add(i.opened_at),
                due_at=add(i.due_at),
                closed_at=add(i.closed_at),
            )
            for i in issues
        ],
        [replace(p, created_at=add(p.created_at), merged_at=add(p.merged_at)) for p in prs],
    )


# Feature: cyber-resilience-phase4-supply-chain, Property 16 (local check for 9.17): shifting every time leaves the actuals unchanged
@settings(max_examples=200, deadline=None)
@given(_timelines(), st.integers(-100000, 100000), st.integers(0, 9000))
def test_shifting_all_times_leaves_actuals_unchanged(data, shift_minutes: int, now_minutes: int) -> None:
    """**Validates: Requirements 18.3, 18.4, 18.6**"""
    issues, prs = data
    delta = timedelta(minutes=shift_minutes)
    now = T0 + timedelta(minutes=now_minutes)
    base = _run(issues, prs, now=now)
    moved_issues, moved_prs = _shifted(issues, prs, delta)
    assert _run(moved_issues, moved_prs, now=now + delta) == base
    event(f"detection={len(base.detection.durations)}")
    event(f"pr_to_merge={'some' if base.pr_to_merge.durations else 'none'}")
    event(f"overdue={'some' if any(r.overdue_open for r in base.by_repo) else 'none'}")


@settings(max_examples=200, deadline=None)
@given(_timelines())
def test_input_order_does_not_change_the_result(data) -> None:
    """The result depends on the set of Issues and pull requests, not their order."""
    issues, prs = data
    assert _run(issues, prs) == _run(list(reversed(issues)), list(reversed(prs)))

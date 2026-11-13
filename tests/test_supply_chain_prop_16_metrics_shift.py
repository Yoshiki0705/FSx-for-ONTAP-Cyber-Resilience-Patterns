"""Property 16: response-time actuals do not change when every time is shifted (task 9.18).

Adding the same amount to every time of the input (origin, opened, due, closed, the pull request times
and ``now``) leaves every actual of ``metrics.compute_metrics`` unchanged: the three intervals
(detection to opened, opened to pull request, pull request to merge), the fix actual, the exclusion
counts and the per-repository counts (Requirements 18.3, 18.4, 18.6). Three more checks keep the shift
test from passing on an empty or constant result:

* the fix actual comes from Issues closed with ``resolved`` only, and an Issue with an unknown origin
  is left out of the detection actual and counted, but stays in the fix actual (Requirement 18.4);
* the overdue count and the "detected after more than ``detect_hours``" count follow their definitions
  (Requirement 18.6), and the pull request intervals are never negative;
* every case the checks rely on is reachable from the generator, found with a fixed seed.

``tests/test_supply_chain_metrics.py`` (task 9.17) holds the examples and two local shift/order checks
on its own generator. This file draws repositories and pull requests from the task 9.1 generators
(``sc.repo_lists``, ``sc.pull_requests``) and covers the whole result, not selected fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import hypothesis.strategies as st
import pytest
from hypothesis import HealthCheck, Phase, event, find, given, settings
from hypothesis.errors import NoSuchExample
from supply_chain import metrics
from supply_chain.models import CloseReason, PullRequestRef, Repo

from tests.strategies import supply_chain as sc

_SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
_REASONS: tuple[CloseReason, ...] = ("resolved", "withdrawn", "feed_version_delisted", "vex_not_affected", "vex_fixed")
_VULN_IDS = tuple(sc.cve_id(n) for n in range(2))
_RUNS = ("run-1", "run-0")


@dataclass(frozen=True)
class Case:
    """One drawn input of ``compute_metrics``."""

    issues: tuple[metrics.IssueTimeline, ...]
    prs: tuple[PullRequestRef, ...]
    detect_hours: int
    now: datetime
    run_id: str
    repos: tuple[Repo, ...]


@st.composite
def cases(draw: st.DrawFn) -> Case:
    """Issues with origins, due dates and closes, plus pull requests that may answer them."""
    repos = draw(sc.repo_lists(min_size=1, max_size=3))
    prs = draw(sc.pull_requests(repos, _VULN_IDS, 12))
    detect_hours = draw(st.integers(1, 72))
    specs = draw(
        st.lists(
            st.tuples(
                st.integers(0, len(repos) - 1),
                st.integers(0, len(_VULN_IDS) - 1),
                st.integers(0, 400),  # opened: whole days after EPOCH, the grid the pull requests use
                st.sampled_from((0, 600)),  # plus minutes, so some pull requests fall before the Issue
                st.one_of(
                    st.none(), st.integers(-60, 6000), st.just(detect_hours * 60)
                ),  # origin: minutes before opened; None = unknown
                st.one_of(st.none(), st.integers(1, 30)),  # due: days after opened
                st.one_of(st.none(), st.tuples(st.integers(0, 40000), st.sampled_from(_REASONS))),
                st.sampled_from(_RUNS),
            ),
            max_size=10,
        )
    )
    issues = []
    for repo_i, vuln_i, day, extra, back, due_days, close, run in specs:
        opened = sc.utc_at(day * 1440 + extra)
        issues.append(
            metrics.IssueTimeline(
                repo=repos[repo_i],
                vuln_id=_VULN_IDS[vuln_i],
                origin_at=None if back is None else opened - timedelta(minutes=back),
                opened_at=opened,
                opened_run_id=run,
                due_at=None if due_days is None else opened + timedelta(days=due_days),
                closed_at=None if close is None else opened + timedelta(minutes=close[0]),
                close_reason=None if close is None else close[1],
            )
        )
    dues = [i.due_at for i in issues if i.due_at is not None]
    now_choices = [st.integers(0, 450 * 1440).map(sc.utc_at)]
    if dues:  # now equal to a due date, so the "strictly past due" edge is drawn
        now_choices.append(st.sampled_from(dues))
    now = draw(st.one_of(*now_choices))
    extra_repos = tuple(draw(sc.repo_lists(prefix="idle", max_size=2)))
    return Case(
        issues=tuple(issues),
        prs=prs,
        detect_hours=detect_hours,
        now=now,
        run_id="run-1",
        repos=extra_repos,
    )


def _compute(case: Case) -> metrics.ResponseMetrics:
    return metrics.compute_metrics(case.issues, case.prs, case.detect_hours, case.now, case.run_id, case.repos)


def _shifted(case: Case, delta: timedelta) -> Case:
    """The same case with every time moved by ``delta``; ``None`` stays ``None``."""

    def move(value: datetime | None) -> datetime | None:
        return None if value is None else value + delta

    issues = tuple(
        metrics.IssueTimeline(
            repo=i.repo,
            vuln_id=i.vuln_id,
            origin_at=move(i.origin_at),
            opened_at=i.opened_at + delta,
            opened_run_id=i.opened_run_id,
            due_at=move(i.due_at),
            closed_at=move(i.closed_at),
            close_reason=i.close_reason,
        )
        for i in case.issues
    )
    prs = tuple(PullRequestRef(p.repo, p.vuln_id, p.created_at + delta, move(p.merged_at)) for p in case.prs)
    return Case(issues, prs, case.detect_hours, case.now + delta, case.run_id, case.repos)


def _key(repo: Repo) -> tuple[str, str]:
    return (repo.owner.lower(), repo.name.lower())


# Feature: cyber-resilience-phase4-supply-chain, Property 16: 対応時間の実績は時刻の平行移動で変わらない
@_SETTINGS
@given(cases(), st.integers(-500_000_000, 500_000_000))
def test_shifting_every_time_leaves_every_actual_unchanged(case: Case, shift_seconds: int) -> None:
    """**Validates: Requirements 18.3, 18.4, 18.6**"""
    before = _compute(case)
    after = _compute(_shifted(case, timedelta(seconds=shift_seconds)))

    for name in ("detection", "opened_to_pr", "pr_to_merge", "fix"):
        assert getattr(after, name) == getattr(before, name), name
    assert after.excluded_unknown_origin == before.excluded_unknown_origin
    assert after.by_repo == before.by_repo
    assert after == before

    event(f"detection durations={min(len(before.detection.durations), 3)}")
    event(f"opened_to_pr durations={min(len(before.opened_to_pr.durations), 3)}")
    event(f"pr_to_merge durations={min(len(before.pr_to_merge.durations), 3)}")
    event(f"fix durations={min(len(before.fix.durations), 3)}")
    event(f"unknown origin={before.excluded_unknown_origin > 0}")
    event(f"overdue={any(r.overdue_open for r in before.by_repo)}")


# Feature: cyber-resilience-phase4-supply-chain, Property 16: 対応時間の実績は時刻の平行移動で変わらない
@_SETTINGS
@given(cases())
def test_fix_actual_and_exclusions_follow_their_definitions(case: Case) -> None:
    """**Validates: Requirements 18.3, 18.4, 18.6**

    The fix actual is ``closed - opened`` of the ``resolved`` Issues only; an unknown origin is left
    out of the detection actual and counted, and stays in the fix actual.
    """
    result = _compute(case)
    issues = case.issues

    resolved = [i for i in issues if i.close_reason == "resolved" and i.closed_at is not None]
    assert result.fix.durations == tuple(sorted(i.closed_at - i.opened_at for i in resolved if i.closed_at))

    unknown = sum(1 for i in issues if i.origin_at is None)
    assert result.excluded_unknown_origin == unknown
    assert result.detection.excluded_unknown_start == unknown
    assert len(result.detection.durations) == len(issues) - unknown
    assert result.detection.durations == tuple(
        sorted(i.opened_at - i.origin_at for i in issues if i.origin_at is not None)
    )

    # The pull request that answers a resolved Issue: same repository and id, created at or after the
    # Issue; the earliest merge wins, else the earliest creation.
    to_pr, merge, no_pr, not_merged = [], [], 0, 0
    for i in resolved:
        answers = [p for p in case.prs if p.repo == i.repo and p.vuln_id == i.vuln_id and p.created_at >= i.opened_at]
        if not answers:
            no_pr += 1
            continue
        merged = [p for p in answers if p.merged_at is not None]
        chosen = (
            min(merged, key=lambda p: (p.merged_at, p.created_at))
            if merged
            else min(answers, key=lambda p: p.created_at)
        )
        to_pr.append(chosen.created_at - i.opened_at)
        if chosen.merged_at is None:
            not_merged += 1
        else:
            merge.append(chosen.merged_at - chosen.created_at)
    assert result.opened_to_pr == metrics.IntervalStats(tuple(sorted(to_pr)), 0, no_pr)
    assert result.pr_to_merge == metrics.IntervalStats(tuple(sorted(merge)), 0, no_pr + not_merged)

    # Intervals that start at a pull request or later only exist for resolved Issues.
    assert len(result.opened_to_pr.durations) <= len(resolved)
    assert len(result.pr_to_merge.durations) <= len(result.opened_to_pr.durations)
    assert all(d >= timedelta(0) for d in result.opened_to_pr.durations)
    assert all(d >= timedelta(0) for d in result.pr_to_merge.durations)

    event(f"resolved issues={min(len(resolved), 3)}")
    event(f"unknown origin={unknown > 0}")


# Feature: cyber-resilience-phase4-supply-chain, Property 16: 対応時間の実績は時刻の平行移動で変わらない
@_SETTINGS
@given(cases())
def test_per_repository_counts_follow_their_definitions(case: Case) -> None:
    """**Validates: Requirements 18.6**

    Overdue: open and ``due_at < now``. Detected late: opened by this run, origin known, and
    ``opened - origin`` strictly over ``detect_hours``. Repositories are keyed ignoring case and
    listed even with no Issue.
    """
    result = _compute(case)
    limit = timedelta(hours=case.detect_hours)
    expected: dict[tuple[str, str], list[int]] = {_key(r): [0, 0] for r in case.repos}
    for i in case.issues:
        row = expected.setdefault(_key(i.repo), [0, 0])
        if i.closed_at is None and i.due_at is not None and i.due_at < case.now:
            row[0] += 1
        if i.opened_run_id == case.run_id and i.origin_at is not None and i.opened_at - i.origin_at > limit:
            row[1] += 1

    assert [(_key(r.repo), r.overdue_open, r.detection_over_target) for r in result.by_repo] == [
        (k, expected[k][0], expected[k][1]) for k in sorted(expected)
    ]
    event(f"overdue total={min(sum(v[0] for v in expected.values()), 3)}")
    event(f"late total={min(sum(v[1] for v in expected.values()), 3)}")


# The shift test is only worth something if the drawn cases reach each of these. ``find`` with a fixed
# seed answers "is it reachable" without depending on the random state of the run.
_REACHABLE = {
    "an unknown origin": lambda c: any(i.origin_at is None for i in c.issues),
    "a resolved Issue answered by a merged pull request": lambda c: _has_pr_path(c, merged=True),
    "a resolved Issue answered by an unmerged pull request": lambda c: _has_pr_path(c, merged=False),
    "a resolved Issue with no pull request": lambda c: any(
        i.close_reason == "resolved" and _answering(i, c.prs) is None for i in c.issues
    ),
    "a close that is not resolved": lambda c: any(
        i.close_reason is not None and i.close_reason != "resolved" for i in c.issues
    ),
    "an open overdue Issue": lambda c: any(
        i.closed_at is None and i.due_at is not None and i.due_at < c.now for i in c.issues
    ),
    "a run Issue detected late": lambda c: any(
        i.opened_run_id == c.run_id
        and i.origin_at is not None
        and i.opened_at - i.origin_at > timedelta(hours=c.detect_hours)
        for i in c.issues
    ),
    "a pull request created before its Issue": lambda c: any(
        p.created_at < i.opened_at for i in c.issues for p in c.prs if p.repo == i.repo and p.vuln_id == i.vuln_id
    ),
    "a repository with no Issue": lambda c: any(_key(r) not in {_key(i.repo) for i in c.issues} for r in c.repos),
}


def _answering(issue: metrics.IssueTimeline, prs: tuple[PullRequestRef, ...]) -> PullRequestRef | None:
    found = [p for p in prs if p.repo == issue.repo and p.vuln_id == issue.vuln_id and p.created_at >= issue.opened_at]
    return found[0] if found else None


def _has_pr_path(case: Case, *, merged: bool) -> bool:
    for i in case.issues:
        if i.close_reason != "resolved":
            continue
        answers = [p for p in case.prs if p.repo == i.repo and p.vuln_id == i.vuln_id and p.created_at >= i.opened_at]
        if answers and all((p.merged_at is not None) == merged for p in answers):
            return True
    return False


@pytest.mark.parametrize("label", sorted(_REACHABLE))
def test_the_generator_reaches_every_case_the_properties_depend_on(label: str) -> None:
    """With a fixed seed, each case is found within 2,000 examples."""
    try:
        find(
            cases(),
            _REACHABLE[label],
            settings=settings(
                max_examples=2000,
                derandomize=True,
                database=None,
                deadline=None,
                phases=(Phase.generate,),
                suppress_health_check=list(HealthCheck),
            ),
        )
    except NoSuchExample:  # pragma: no cover - only on a regression of the generator
        pytest.fail(f"the generator never produced {label}")

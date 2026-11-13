"""Property 12 (task 9.13): a failed fetch never closes an Issue.

The scenario is built by planning: a first run with healthy feeds opens Issues for the generated
findings, then a second run sees different feeds, a subset of the repositories fetched, and
either no findings at all (everything vanished) or some of them. The oracle for the second run is
written here from the Issue's own state block and the feed snapshot, not from the planner.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import date

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import models, planner
from supply_chain.threshold import SEVERITY_RANK

from tests.strategies import supply_chain as sc
from tests.test_supply_chain_planner import (
    NOW,
    OTHER,
    REPO,
    _apply,
    _feeds,
    _finding,
    _inputs,
    _next,
    _policy,
)

RANK = dict(SEVERITY_RANK)


def _rk(repo: models.Repo) -> tuple[str, str]:
    return (repo.owner.lower(), repo.name.lower())


def _is_malicious(issue: models.ManagedIssue) -> bool:
    flag = issue.body_state.get("malicious") if issue.body_state else None
    return (issue.vuln_id or "").startswith("MAL-") or flag is True


def _kev_dependent(issue: models.ManagedIssue, policy: models.Policy) -> bool:
    """Open only because of KEV, as the state block says (an unreadable block counts as KEV)."""
    if not policy.opening_threshold.open_if_kev_listed:
        return False
    state = issue.body_state
    if state is None:
        return True
    severity = state.get("cvss_severity")
    meets = isinstance(severity, str) and RANK[severity] >= RANK[policy.opening_threshold.min_cvss_severity]
    return state.get("kev_listed") is True and not meets


def _healthy(feeds: models.FeedSnapshot) -> models.FeedSnapshot:
    return replace(
        feeds,
        kev=dict(feeds.kev or {}),
        epss=dict(feeds.epss or {}),
        malicious=dict(feeds.malicious or {}),
        malicious_withdrawn={},
        malicious_delisted=frozenset(),
        malicious_unconfirmed=frozenset(),
    )


def _closes(plan: models.Plan) -> list[models.IssueAction]:
    return [a for a in plan.actions if a.op == "close"]


def _expected_reason(issue: models.ManagedIssue, feeds: models.FeedSnapshot) -> str | None:
    """The close reason the written rules give a vanished Issue whose repository was fetched; None = not closed."""
    vid = issue.vuln_id or ""
    if _is_malicious(issue):
        if feeds.malicious is None or vid in feeds.malicious_unconfirmed:
            return None
        if vid in feeds.malicious_withdrawn:
            return "withdrawn"
        return "feed_version_delisted" if vid in feeds.malicious_delisted else "resolved"
    return "resolved"


@st.composite
def _scenarios(draw: st.DrawFn) -> tuple[models.PlanInputs, models.PlanInputs, bool, sc.FeedsCase]:
    """(first run's inputs, second run's inputs, whether every finding vanished, the second feeds)."""
    policy = draw(sc.policies())
    inputs = draw(sc.plan_inputs(12, 0, policy=policy))
    targets = frozenset(policy.target_repositories)
    first = replace(inputs, issues=(), vex={}, fetch_ok=targets, feeds=_healthy(inputs.feeds))
    if targets and draw(st.booleans()):  # a LOW finding that is open only because KEV lists it
        planted = _finding("CVE-2026-9001", "LOW", repo=min(targets, key=_rk), purl="pkg:npm/planted@1.0.0")
        kev = {**(first.feeds.kev or {}), planted.vuln_id: (date(2026, 1, 1), None)}
        first = replace(first, findings=first.findings | {planted}, feeds=replace(first.feeds, kev=kev))
    opened = planner.plan(first)
    store = _apply(first, opened)
    pool = tuple(sorted(set(sc.finding_vuln_ids(inputs.findings)) | set(sc.DEFAULT_VULN_IDS)))
    case = draw(sc.feeds(pool, tuple(v for v in pool if v.startswith("MAL-"))))
    ordered = sorted(policy.target_repositories, key=_rk)
    ok = draw(st.lists(st.sampled_from(ordered), max_size=len(ordered), unique_by=_rk)) if ordered else []
    vanish = draw(st.booleans())
    found = sorted(first.findings, key=lambda f: (_rk(f.repo), f.vuln_id, f.component.purl))
    flags = draw(st.lists(st.booleans(), min_size=len(found), max_size=len(found)))
    kept = frozenset() if vanish else frozenset(f for f, keep in zip(found, flags, strict=True) if keep)
    second = replace(
        first,
        issues=store,
        findings=kept,
        fetch_ok=frozenset(ok),
        feeds=case.snapshot,
        run_id="900-1",
    )
    return first, second, vanish, case


def _check(second: models.PlanInputs, vanish: bool, case: sc.FeedsCase) -> Counter[str]:
    plan = planner.plan(second)
    ok = {_rk(r) for r in second.fetch_ok}
    by_number = {(_rk(i.repo), i.number): i for i in second.issues}
    closes = _closes(plan)
    seen: Counter[str] = Counter()
    for a in closes:
        assert _rk(a.repo) in ok, "closed an Issue of a repository whose fetch failed"
        if a.kind != "finding":
            continue
        issue = by_number[(_rk(a.repo), a.number or 0)]
        assert issue.state == "open"
        if _is_malicious(issue):
            assert second.feeds.malicious is not None, "closed a malicious Issue while the feed failed"
            assert (issue.vuln_id or "") not in second.feeds.malicious_unconfirmed
            assert (a.close_reason == "withdrawn") == ((issue.vuln_id or "") in second.feeds.malicious_withdrawn)
        elif second.feeds.kev is None:
            assert not _kev_dependent(issue, second.policy), "closed a KEV-only Issue while KEV failed"
        seen["close"] += 1
        seen[f"reason={a.close_reason}"] += 1
    if vanish:
        want = {}
        for issue in second.issues:
            if issue.kind != "finding" or issue.state != "open" or _rk(issue.repo) not in ok:
                continue
            if issue.vuln_id is None:
                continue
            reason = _expected_reason(issue, second.feeds)
            if reason is None:
                continue
            if second.feeds.kev is None and not _is_malicious(issue) and _kev_dependent(issue, second.policy):
                continue
            want[(_rk(issue.repo), issue.number)] = reason
        got = {(_rk(a.repo), a.number or 0): a.close_reason for a in closes if a.kind == "finding"}
        assert got == want
        unconfirmed = {
            (_rk(i.repo), i.number)
            for i in second.issues
            if i.kind == "finding"
            and i.state == "open"
            and _rk(i.repo) in ok
            and _is_malicious(i)
            and _expected_reason(i, second.feeds) is None
        }
        assert {(_rk(r), n) for r, n, _ in plan.malicious_withdrawn_unconfirmed} == unconfirmed
    # EPSS does not change which Issues close.
    for epss in (None, {}):
        other = planner.plan(replace(second, feeds=replace(second.feeds, epss=epss)))
        assert _closes(other) == closes
    seen["repo_failed"] += any(
        i.state == "open" and i.kind == "finding" and _rk(i.repo) not in ok for i in second.issues
    )
    seen["kev_failed"] += second.feeds.kev is None
    seen["mal_failed"] += second.feeds.malicious is None
    seen["epss_failed"] += second.feeds.epss is None
    seen["open_malicious"] += any(i.state == "open" and i.kind == "finding" and _is_malicious(i) for i in second.issues)
    seen["kev_blocked"] += any(
        i.state == "open"
        and i.kind == "finding"
        and not _is_malicious(i)
        and _kev_dependent(i, second.policy)
        and second.feeds.kev is None
        and _rk(i.repo) in ok
        for i in second.issues
    )
    seen["withdrawn"] += any(a.close_reason == "withdrawn" for a in closes)
    seen["unconfirmed"] += bool(plan.malicious_withdrawn_unconfirmed)
    return seen


# Feature: cyber-resilience-phase4-supply-chain, Property 12: 取得に失敗したリポジトリとフィードではクローズしない
@settings(max_examples=100, deadline=None)
@given(_scenarios())
def test_failed_fetches_never_close(case: tuple[models.PlanInputs, models.PlanInputs, bool, sc.FeedsCase]) -> None:
    """Close targets only fetched repositories, skips KEV-only and malicious Issues when their feed failed,
    closes a malicious Issue as withdrawn only on a readable withdrawal, and ignores EPSS.

    **Validates: Requirements 3.4, 8.4, 8.8, 9.8, 9.9, 27.10**
    """
    _, second, vanish, feeds_case = case
    seen = _check(second, vanish, feeds_case)
    event(f"closes={bool(seen['close'])}")
    event(f"repo_failed={bool(seen['repo_failed'])}")


# Feature: cyber-resilience-phase4-supply-chain, Property 12: 取得に失敗したリポジトリとフィードではクローズしない
@settings(max_examples=100, deadline=None)
@given(_scenarios())
def test_a_withdrawn_malicious_issue_reopens_when_the_record_returns(
    case: tuple[models.PlanInputs, models.PlanInputs, bool, sc.FeedsCase],
) -> None:
    """Every Issue closed as withdrawn is reopened by the next run that sees its finding again.

    **Validates: Requirements 8.10, 27.10**
    """
    first, second, _, _ = case
    mals = sorted({i.vuln_id for i in second.issues if i.kind == "finding" and _is_malicious(i) and i.vuln_id})
    gone_feeds = replace(_healthy(first.feeds), malicious_withdrawn={m: NOW for m in mals if m.startswith("MAL-")})
    gone = replace(second, findings=frozenset(), fetch_ok=first.fetch_ok, feeds=gone_feeds)
    plan = planner.plan(gone)
    withdrawn = {(_rk(a.repo), a.number) for a in _closes(plan) if a.close_reason == "withdrawn"}
    event(f"withdrawn={bool(withdrawn)}")
    closed = _next(gone, plan)
    back = replace(
        closed,
        findings=first.findings,
        feeds=_healthy(first.feeds),
        run_id="901-1",
    )
    reopened = {(_rk(a.repo), a.number) for a in planner.plan(back).actions if a.op == "reopen"}
    assert withdrawn <= reopened


def test_generated_scenarios_close_and_fail_in_every_way() -> None:
    """The properties above are not vacuous: every kind of failure and close shows up."""
    seen: Counter[str] = Counter()

    @settings(max_examples=300, deadline=None, derandomize=True)
    @given(_scenarios())
    def run(case: tuple[models.PlanInputs, models.PlanInputs, bool, sc.FeedsCase]) -> None:
        _, second, vanish, feeds_case = case
        seen.update(_check(second, vanish, feeds_case))

    run()
    needed = (
        "close",
        "repo_failed",
        "kev_failed",
        "mal_failed",
        "epss_failed",
        "open_malicious",
        "kev_blocked",
        "withdrawn",
        "unconfirmed",
        "reason=resolved",
    )
    missing = [k for k in needed if not seen[k]]
    assert not missing, f"never seen: {missing}; counts {sorted(seen.items())}"


# --- fixed examples ---------------------------------------------------------------------------

MAL = "MAL-2026-0007"


def _mal_opened() -> models.PlanInputs:
    first = _inputs((_finding(MAL, None),))
    return _next(first, planner.plan(first))


def _gone(opened: models.PlanInputs, **changes: object) -> models.Plan:
    return planner.plan(replace(opened, findings=frozenset(), **changes))  # type: ignore[arg-type]


def test_a_failed_withdrawal_check_closes_nothing_and_is_recorded() -> None:
    plan = _gone(_mal_opened(), feeds=_feeds(malicious_unconfirmed=frozenset({MAL})))
    assert plan.actions == ()
    assert plan.malicious_withdrawn_unconfirmed == ((REPO, 1, MAL),)


def test_a_feed_failure_closes_no_malicious_issue_even_with_a_withdrawal_in_the_snapshot() -> None:
    plan = _gone(_mal_opened(), feeds=_feeds(malicious=None, malicious_withdrawn={MAL: NOW}))
    assert plan.actions == ()
    assert plan.malicious_withdrawn_unconfirmed == ((REPO, 1, MAL),)


def test_a_readable_withdrawal_closes_as_withdrawn_and_the_same_id_reopens_it() -> None:
    opened = _mal_opened()
    gone = replace(opened, findings=frozenset(), feeds=_feeds(malicious_withdrawn={MAL: NOW}))
    plan = planner.plan(gone)
    assert [(a.op, a.close_reason) for a in plan.actions] == [("close", "withdrawn")]
    back = replace(_next(gone, plan), findings=frozenset({_finding(MAL, None)}), feeds=_feeds(), run_id="902-1")
    assert [a.op for a in planner.plan(back).actions] == ["reopen"]


def test_a_withdrawn_open_issue_in_an_unfetched_repository_is_not_closed() -> None:
    opened = _mal_opened()
    gone = _gone(opened, feeds=_feeds(malicious_withdrawn={MAL: NOW}), fetch_ok=frozenset({OTHER}))
    assert gone.actions == ()
    assert gone.malicious_withdrawn_unconfirmed == ()


def test_the_epss_feed_failure_does_not_change_the_close_set() -> None:
    opened = _mal_opened()
    ok = _gone(opened, feeds=_feeds(malicious_withdrawn={MAL: NOW}))
    failed = _gone(opened, feeds=_feeds(epss=None, malicious_withdrawn={MAL: NOW}))
    assert _closes(ok) == _closes(failed) != []


def _unreadable_issue() -> models.ManagedIssue:
    return models.ManagedIssue(REPO, 1, "finding", "CVE-2026-0001", "open", None)


def test_an_issue_with_an_unreadable_state_block_is_not_closed_while_kev_failed() -> None:
    issue = _unreadable_issue()
    failed = planner.plan(_inputs((), (issue,), feeds=_feeds(kev=None)))
    assert failed.actions == ()
    readable = planner.plan(_inputs((), (issue,), feeds=_feeds()))
    assert [(a.op, a.close_reason) for a in readable.actions] == [("close", "resolved")]


def test_a_kev_failure_does_not_block_closing_when_kev_is_not_a_reason_to_open() -> None:
    issue = _unreadable_issue()
    plan = planner.plan(_inputs((), (issue,), feeds=_feeds(kev=None), policy=_policy(kev=False)))
    assert [(a.op, a.close_reason) for a in plan.actions] == [("close", "resolved")]

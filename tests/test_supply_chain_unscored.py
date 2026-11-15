"""The per-repository ``unscored`` Issue (T2-07).

A Finding with no CVSS severity, not listed in KEV and not malicious opens no Issue. After
``unscored_review_days`` days the repository's single ``unscored`` Issue lists it, so that a person sees
what no rule opens. The Opening_Threshold is not touched, and the Issue follows the same rules as the other
Issues the Aggregator owns: one open Issue per key, no action from a run whose inputs are incomplete, closed
only when the list is empty, nothing written when the list is unchanged.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import date, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner

from tests.strategies import supply_chain as sc
from tests.test_supply_chain_planner import (
    NOW,
    OTHER,
    REPO,
    _feeds,
    _finding,
    _inputs,
    _next,
    _ops,
    _policy,
)

OLD = NOW - timedelta(days=10)


def _bare(vuln_id: str = "CVE-2026-0100", *, repo: models.Repo = REPO, purl: str = "pkg:npm/left-pad@1.3.0"):
    return _finding(vuln_id, None, repo=repo, purl=purl, published=OLD, observed=OLD)


def _kinds(plan: models.Plan, kind: str) -> list[models.IssueAction]:
    return [a for a in plan.actions if a.kind == kind]


def test_a_finding_without_severity_is_listed_after_the_review_period_and_opens_no_finding_issue() -> None:
    plan = planner.plan(_inputs((_bare(),)))
    assert _ops(plan) == [("create", "unscored", None)]
    state = issue_body.parse_state(plan.actions[0].body)
    assert state is not None
    assert state["review_days"] == 7
    assert [e["vuln_id"] for e in state["entries"]] == ["CVE-2026-0100"]
    assert issue_body.parse_marker(plan.actions[0].body) == issue_body.Marker("unscored", REPO, None, ())


def test_a_finding_younger_than_the_review_period_is_not_listed() -> None:
    young = _finding(
        "CVE-2026-0101", None, published=NOW - timedelta(days=6, hours=23), observed=NOW - timedelta(days=9)
    )
    assert planner.plan(_inputs((young,))).actions == ()
    edge = _finding("CVE-2026-0101", None, published=NOW - timedelta(days=7), observed=NOW - timedelta(days=9))
    assert _ops(planner.plan(_inputs((edge,)))) == [("create", "unscored", None)]


def test_the_period_comes_from_the_policy() -> None:
    finding = _finding("CVE-2026-0102", None, published=NOW - timedelta(days=3), observed=NOW - timedelta(days=9))
    policy = replace(_policy(), unscored_review_days=2)
    assert _ops(planner.plan(_inputs((finding,), policy=policy))) == [("create", "unscored", None)]
    policy = replace(_policy(), unscored_review_days=30)
    assert planner.plan(_inputs((_bare(),), policy=policy)).actions == ()


def test_the_clock_starts_at_the_later_of_publication_and_first_observation() -> None:
    late_observed = _finding("CVE-2026-0103", None, published=OLD, observed=NOW - timedelta(days=1))
    assert planner.plan(_inputs((late_observed,))).actions == ()
    no_publication = replace(_bare("CVE-2026-0104"), advisory_published_at=None)
    assert _ops(planner.plan(_inputs((no_publication,)))) == [("create", "unscored", None)]


def test_one_issue_per_repository_lists_every_overdue_finding_ordered_by_epss() -> None:
    a, b, c = _bare("CVE-2026-0201"), _bare("CVE-2026-0202"), _bare("CVE-2026-0203")
    other = _bare("CVE-2026-0204", repo=OTHER)
    feeds = _feeds(
        epss={"CVE-2026-0202": ("0.9", date(2026, 11, 10), "v1"), "CVE-2026-0201": ("0.1", date(2026, 11, 10), "v1")}
    )
    plan = planner.plan(_inputs((a, b, c, other), feeds=feeds))
    creates = _kinds(plan, "unscored")
    assert sorted(x.repo.name for x in creates) == ["svc-api", "svc-web"]
    state = issue_body.parse_state(next(x for x in creates if x.repo == REPO).body)
    assert [e["vuln_id"] for e in state["entries"]] == ["CVE-2026-0202", "CVE-2026-0201", "CVE-2026-0203"]


def test_epss_orders_the_list_and_never_opens_an_issue() -> None:
    top = _bare("CVE-2026-0301")
    feeds = _feeds(epss={"CVE-2026-0301": ("0.99", date(2026, 11, 10), "v1")})
    plan = planner.plan(_inputs((top,), feeds=feeds))
    assert _kinds(plan, "finding") == []


def test_kev_listed_malicious_and_scored_findings_keep_their_own_rules() -> None:
    kev = _bare("CVE-2026-0401")
    scored = _finding("CVE-2026-0402", "MEDIUM", published=OLD, observed=OLD)
    feeds = _feeds(kev={"CVE-2026-0401": (date(2026, 11, 1), None)})
    plan = planner.plan(_inputs((kev, scored), feeds=feeds))
    assert _ops(plan) == [("create", "finding", "CVE-2026-0401")]


def test_the_opening_threshold_is_unchanged_by_the_list() -> None:
    findings = (_bare("CVE-2026-0501"), _finding("CVE-2026-0502", "HIGH"), _finding("CVE-2026-0503", "LOW"))
    with_list = planner.plan(_inputs(findings))
    young = tuple(replace(f, first_observed_component_at=NOW, advisory_published_at=NOW) for f in findings)
    without_list = planner.plan(_inputs(young))
    strip = lambda p: [(a.op, a.kind, a.vuln_id) for a in p.actions if a.kind != "unscored"]  # noqa: E731
    assert strip(with_list) == strip(without_list) == [("create", "finding", "CVE-2026-0502")]


def test_no_action_when_the_kev_feed_is_missing() -> None:
    plan = planner.plan(_inputs((_bare(),), feeds=_feeds(kev=None)))
    assert plan.actions == ()
    assert plan.kev_unknown == (_bare(),)


def test_an_unchanged_list_writes_nothing_and_the_next_run_updates_only_on_change() -> None:
    first = _inputs((_bare("CVE-2026-0601"),))
    plan = planner.plan(first)
    second = _next(first, plan, run_id="201-1", now=NOW + timedelta(hours=6))
    assert planner.plan(second).actions == ()
    grown = replace(second, findings=second.findings | {_bare("CVE-2026-0602")})
    assert _ops(planner.plan(grown)) == [("update", "unscored", None)]


def test_the_issue_closes_when_the_list_is_empty_and_reopens_when_it_grows_again() -> None:
    first = _inputs((_bare(),))
    opened = _next(first, planner.plan(first))
    gone = replace(opened, findings=frozenset(), run_id="201-1")
    closing = planner.plan(gone)
    assert [(a.op, a.kind, a.close_reason) for a in closing.actions] == [("close", "unscored", "resolved")]
    closed = _next(gone, closing)
    assert planner.plan(closed).actions == ()
    again = replace(closed, findings=frozenset({_bare()}), run_id="202-1")
    assert _ops(planner.plan(again)) == [("reopen", "unscored", None)]


def test_a_repository_that_was_not_fetched_keeps_its_open_issue() -> None:
    first = _inputs((_bare(),))
    opened = _next(first, planner.plan(first))
    blind = replace(opened, findings=frozenset(), fetch_ok=frozenset({OTHER}), run_id="201-1")
    assert planner.plan(blind).actions == ()


def test_a_finding_that_a_vex_statement_excludes_is_not_listed() -> None:
    from tests.test_supply_chain_planner import _vex  # noqa: PLC0415

    finding = _bare("CVE-2026-0701")
    plan = planner.plan(
        _inputs((finding,), vex={REPO: (_vex("not_affected", "CVE-2026-0701", finding.component.purl),)})
    )
    assert plan.actions == ()


def test_a_finding_that_already_has_an_open_issue_is_not_listed_again() -> None:
    kev_listed = _finding("CVE-2026-0801", "HIGH", published=OLD, observed=OLD)
    first = _inputs((kev_listed,))
    opened = _next(first, planner.plan(first))
    bare = replace(kev_listed, cvss_severity=None)  # the severity vanished from the record: held, not closed
    now = replace(opened, findings=frozenset({bare}), run_id="201-1")
    plan = planner.plan(now)
    assert plan.held_unscored
    assert _kinds(plan, "unscored") == []


def test_a_listed_finding_carries_its_aliases() -> None:
    f = replace(_bare("GHSA-aaaa-bbbb-cccc"), aliases=("CVE-2026-0901",))
    plan = planner.plan(_inputs((f,)))
    state = issue_body.parse_state(plan.actions[0].body)
    entry = state["entries"][0]
    assert {entry["vuln_id"], *entry["aliases"]} == {"GHSA-aaaa-bbbb-cccc", "CVE-2026-0901"}
    assert len(state["entries"]) == 1


@settings(max_examples=60, deadline=None)
@given(sc.plan_inputs(10, 0), st.integers(1, 30))
def test_the_list_never_changes_what_the_other_kinds_do(inputs: models.PlanInputs, days: int) -> None:
    """Whatever the review period, the finding and summary actions are those of a run that never lists."""
    baseline = replace(inputs.policy, unscored_review_days=10_000)
    listed = planner.plan(replace(inputs, policy=replace(inputs.policy, unscored_review_days=days)))
    silent = planner.plan(replace(inputs, policy=baseline))
    keep = lambda p: [a for a in p.actions if a.kind != "unscored"]  # noqa: E731
    assert keep(listed) == keep(silent)
    assert [a for a in silent.actions if a.kind == "unscored" and a.op != "close"] == []
    creates = Counter(a.repo for a in listed.actions if a.kind == "unscored" and a.op in ("create", "reopen"))
    assert all(n == 1 for n in creates.values())

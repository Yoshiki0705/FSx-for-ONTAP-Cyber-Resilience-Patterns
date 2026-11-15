"""Planner behaviour added after the second expert review (T2-R2-01, 02, 05, 06, 07, 10)."""

from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timedelta

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import models, planner
from supply_chain.canonical import canonicalize, multi_cve_records
from supply_chain.vex import effective_exclusions

from tests.test_supply_chain_planner import NOW, REPO, _feeds, _finding, _inputs, _next, _ops, _policy, _state
from tests.test_supply_chain_planner_review import CVE, _doc

GHSA = "GHSA-aaaa-bbbb-cccc"
CVE2 = "CVE-2026-0002"


# --- T2-R2-01: no VEX close while the KEV feed is missing ---------------------------------------------------------


def test_a_vex_judgment_that_predates_kev_does_not_close_the_issue_when_the_kev_feed_fails() -> None:
    judged = NOW - timedelta(days=10)
    listed = _feeds(kev={CVE: (judged.date() + timedelta(days=1), None)})
    first = _inputs((_finding(),), feeds=listed, vex={REPO: (_doc("not_affected", judged),)})
    created = planner.plan(first)
    assert _ops(created) == [("create", "finding", CVE)]  # opened because KEV listed it after the judgment
    blind = _next(first, created, feeds=_feeds(kev=None), run_id="201-1")
    plan = planner.plan(blind)
    assert [a for a in plan.actions if a.op == "close"] == []
    assert [f.vuln_id for f in plan.vex_unchecked_against_kev] == [CVE]


def test_a_fresh_vex_exclusion_is_listed_as_unchecked_when_the_kev_feed_fails() -> None:
    plan = planner.plan(_inputs((_finding(),), feeds=_feeds(kev=None), vex={REPO: (_doc("not_affected", NOW),)}))
    assert plan.actions == ()
    assert [f.vuln_id for f in plan.vex_unchecked_against_kev] == [CVE]
    ok = planner.plan(_inputs((_finding(),), vex={REPO: (_doc("not_affected", NOW),)}))
    assert ok.vex_unchecked_against_kev == ()


@settings(max_examples=60, deadline=None)
@given(st.sampled_from(["not_affected", "fixed"]), st.integers(0, 150))
def test_property_no_vex_close_in_a_run_without_kev(status: models.VexStatus, age: int) -> None:
    """**Validates: Requirements 9.8**"""
    event(f"status={status}")
    first = _inputs((_finding(),))
    with_vex = _next(first, planner.plan(first), vex={REPO: (_doc(status, NOW - timedelta(days=age)),)})
    plan = planner.plan(replace(with_vex, feeds=_feeds(kev=None)))
    assert not [a for a in plan.actions if a.op == "close" and (a.close_reason or "").startswith("vex_")]


# --- T2-R2-02: a judgment about one CVE never covers another -------------------------------------------------------


def _multi() -> models.Finding:
    return _finding(GHSA, aliases=(CVE, CVE2))


def test_a_record_that_names_two_cves_is_two_findings() -> None:
    out = canonicalize([_multi()])
    assert [(f.vuln_id, f.aliases) for f in out] == [(CVE, (GHSA,)), (CVE2, (GHSA,))]
    assert multi_cve_records([_multi()]) == (("example-org/svc-api", GHSA, (CVE, CVE2)),)


def test_a_vex_statement_about_one_cve_does_not_suppress_the_other() -> None:
    plan = planner.plan(_inputs((_multi(),), vex={REPO: (_doc("not_affected", NOW),)}))
    assert _ops(plan) == [("create", "finding", CVE2)]
    assert [f.vuln_id for f, _ in plan.vex_exclusions] == [CVE]
    assert plan.alias_multi_cve == (("example-org/svc-api", GHSA, (CVE, CVE2)),)


def test_a_vex_statement_about_each_cve_suppresses_both() -> None:
    docs = (_doc("not_affected", NOW, CVE), _doc("not_affected", NOW, CVE2, path=".vex/b.json"))
    plan = planner.plan(_inputs((_multi(),), vex={REPO: docs}))
    assert plan.actions == ()


def test_the_shared_identifier_does_not_join_two_cves_found_by_different_reports() -> None:
    a = _finding(CVE, aliases=(GHSA,))
    b = _finding(CVE2, aliases=(GHSA,))
    out = canonicalize([a, b])
    assert [(f.vuln_id, f.aliases) for f in out] == [(CVE, (GHSA,)), (CVE2, (GHSA,))]
    plan = planner.plan(_inputs((a, b), vex={REPO: (_doc("not_affected", NOW),)}))
    assert _ops(plan) == [("create", "finding", CVE2)]


def test_a_chain_of_names_does_not_join_two_cves() -> None:
    a = _finding(CVE, aliases=("OSV-1",))
    b = _finding("OSV-1", aliases=("OSV-2",))
    c = _finding(CVE2, aliases=("OSV-2",))
    out = canonicalize([a, b, c])
    assert {f.vuln_id for f in out} == {CVE, CVE2}
    assert canonicalize(out) == out


def test_one_cve_with_its_ghsa_is_still_one_issue() -> None:
    plan = planner.plan(_inputs((_finding(CVE, aliases=(GHSA,)), _finding(GHSA, aliases=(CVE,)))))
    assert _ops(plan) == [("create", "finding", CVE)]
    assert plan.alias_multi_cve == ()


# --- T2-R2-05: a reopen after a long closure is a new response ---------------------------------------------------


def _closed_at(inputs: models.PlanInputs, when: datetime) -> models.PlanInputs:
    return replace(inputs, issues=tuple(replace(i, closed_at=when) for i in inputs.issues))


def _flapped() -> models.PlanInputs:
    first = _inputs((_finding(),))
    low = _next(first, planner.plan(first), findings=frozenset({_finding(severity="MEDIUM")}), run_id="201-1")
    return _next(low, planner.plan(low))


def test_a_reopen_within_the_response_target_keeps_the_deadline() -> None:
    closed = _flapped()
    back = replace(closed, findings=_inputs((_finding(),)).findings, now=NOW + timedelta(days=5), run_id="202-1")
    state = _state(planner.plan(_closed_at(back, NOW + timedelta(days=1))))
    assert state["opened_at"] == "2026-11-10T06:00:00Z"
    assert state["due_at"] == "2026-11-24T06:00:00Z"


def test_a_reopen_after_longer_than_the_response_target_starts_a_new_response() -> None:
    closed = _flapped()
    now = NOW + timedelta(days=150)
    back = replace(closed, findings=_inputs((_finding(),)).findings, now=now, run_id="202-1")
    plan = planner.plan(_closed_at(back, NOW + timedelta(days=1)))
    assert [a.op for a in plan.actions] == ["reopen"]
    state = _state(plan)
    assert state["opened_at"] == "2027-04-09T06:00:00Z"
    assert state["due_at"] == "2027-04-23T06:00:00Z"
    assert state["detected_at"] == "2026-11-10T06:00:00Z"  # the first detection stays


def test_a_reopen_without_a_known_close_time_keeps_the_deadline() -> None:
    closed = _flapped()
    back = replace(closed, findings=_inputs((_finding(),)).findings, now=NOW + timedelta(days=150), run_id="202-1")
    assert _state(planner.plan(back))["due_at"] == "2026-11-24T06:00:00Z"


# --- T2-R2-06: the release time of the KEV catalogue belongs only to a KEV-origin Issue -----------------------------


def test_a_cvss_origin_issue_that_later_enters_kev_records_no_release_time() -> None:
    first = _inputs((_finding(),))
    feeds = _feeds(kev={CVE: (date(2026, 11, 11), None)}, kev_released_at=datetime(2026, 11, 11, 20, tzinfo=NOW.tzinfo))
    second = _next(first, planner.plan(first), feeds=feeds, now=NOW + timedelta(days=1), run_id="201-1")
    plan = planner.plan(second)
    state = _state(plan)
    assert state["kev_listed"] is True
    assert state["origin_is_date_only"] is False
    assert state["kev_first_release_at"] is None


# --- T2-R2-07: with KEV missing, every finding below the threshold is "unknown" ------------------------------------


def test_a_medium_finding_is_kev_unknown_when_the_feed_fails() -> None:
    medium = _finding(severity="MEDIUM")
    plan = planner.plan(_inputs((medium,), feeds=_feeds(kev=None)))
    assert plan.kev_unknown == (medium,)
    assert plan.below_threshold == (medium,)


def test_nothing_is_kev_unknown_when_kev_cannot_open_an_issue() -> None:
    policy = replace(_policy(), opening_threshold=models.OpeningThreshold("HIGH", False, True))
    plan = planner.plan(_inputs((_finding(severity="MEDIUM"),), feeds=_feeds(kev=None), policy=policy))
    assert plan.kev_unknown == ()


# --- T2-R2-10: a non-excluding statement merged after the excluding one is flagged ---------------------------------


def test_a_late_merged_affected_statement_with_an_old_timestamp_is_flagged() -> None:
    docs = [
        _doc("not_affected", NOW - timedelta(days=1)),
        _doc("affected", NOW - timedelta(days=9), path=".vex/b.json"),
    ]
    merged = {".vex/a.json": NOW - timedelta(days=1), ".vex/b.json": NOW - timedelta(hours=1)}
    _, rejected = effective_exclusions(docs, _policy(), now=NOW, merged_at=merged)
    assert rejected == [(".vex/b.json", "vex_stale_non_excluding")]
    _, quiet = effective_exclusions(docs, _policy(), now=NOW)
    assert quiet == []  # without merge times nothing can be told apart from an ordinary older statement
    _, ordered = effective_exclusions(
        docs, _policy(), now=NOW, merged_at={**merged, ".vex/b.json": NOW - timedelta(days=9)}
    )
    assert ordered == []

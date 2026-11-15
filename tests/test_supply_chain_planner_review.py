"""Planner behaviour added after the expert review (T2-01 to T2-06, T2-12).

Each test builds a small ``PlanInputs`` with the helpers of ``test_supply_chain_planner``.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner
from supply_chain.models import VexStatus

from tests.test_supply_chain_planner import (
    LATER,
    NOW,
    OTHER,
    PURL,
    REPO,
    _feeds,
    _finding,
    _inputs,
    _next,
    _ops,
    _policy,
    _state,
)

CVE = "CVE-2026-0001"


def _doc(
    status: VexStatus,
    when: datetime,
    vuln_id: str = CVE,
    path: str = ".vex/a.json",
    impact: str | None = "ok",
    aliases: tuple[str, ...] = (),
) -> models.VexDocument:
    justification = "component_not_present" if status == "not_affected" else None
    statement = models.VexStatement(vuln_id, aliases, (PURL,), status, justification, impact, when)
    return models.VexDocument(
        "urn:example:1", "https://openvex.dev/ns/v0.2.0", "example", None, when, 1, None, (statement,), path
    )


# --- T2-01: the newest VEX statement decides; a judgment expires; a later KEV listing re-opens the question ----


def test_a_later_affected_statement_makes_the_issue_open_even_with_an_older_not_affected() -> None:
    docs = (
        _doc("not_affected", NOW - timedelta(days=3)),
        _doc("affected", NOW - timedelta(days=1), path=".vex/b.json"),
    )
    plan = planner.plan(_inputs((_finding(),), vex={REPO: docs}))
    assert _ops(plan) == [("create", "finding", CVE)]
    assert plan.vex_exclusions == ()
    assert plan.rejected_vex == ((".vex/a.json", "vex_superseded"),)


def test_an_expired_judgment_reopens_the_issue_it_had_closed() -> None:
    judged = NOW - timedelta(days=10)
    first = _inputs((_finding(),))
    with_vex = _next(first, planner.plan(first), vex={REPO: (_doc("not_affected", judged),)})
    closed = _next(with_vex, planner.plan(with_vex))
    assert [(i.state) for i in closed.issues] == ["closed"]
    assert [(a.op, a.close_reason) for a in planner.plan(with_vex).actions] == [("close", "vex_not_affected")]
    later = replace(closed, now=judged + timedelta(days=181), run_id="300-1")
    plan = planner.plan(later)
    assert [(a.op, a.number) for a in plan.actions] == [("reopen", 1)]
    assert plan.rejected_vex == ((".vex/a.json", "vex_expired"),)
    assert plan.vex_exclusions == ()


def test_a_kev_listing_after_the_judgment_stops_it_suppressing() -> None:
    judged = NOW - timedelta(days=5)
    kev = _feeds(kev={CVE: (judged.date() + timedelta(days=1), None)})
    plan = planner.plan(_inputs((_finding(),), feeds=kev, vex={REPO: (_doc("not_affected", judged),)}))
    assert _ops(plan) == [("create", "finding", CVE)]
    assert plan.rejected_vex == ((".vex/a.json", "vex_predates_kev"),)


def test_a_kev_listing_before_the_judgment_does_not_stop_it() -> None:
    judged = NOW - timedelta(days=5)
    kev = _feeds(kev={CVE: (judged.date() - timedelta(days=1), None)})  # the day before: the author had it in view
    plan = planner.plan(_inputs((_finding(),), feeds=kev, vex={REPO: (_doc("not_affected", judged),)}))
    assert plan.actions == ()
    assert [f.vuln_id for f, _ in plan.vex_exclusions] == [CVE]


def test_a_kev_listing_on_the_day_of_the_judgment_stops_it_because_the_order_cannot_be_known() -> None:
    """``dateAdded`` has no time of day, so a judgment of the same day may have been written before the listing."""
    judged = NOW - timedelta(days=5)
    kev = _feeds(kev={CVE: (judged.date(), None)})
    plan = planner.plan(_inputs((_finding(),), feeds=kev, vex={REPO: (_doc("not_affected", judged),)}))
    assert _ops(plan) == [("create", "finding", CVE)]
    assert plan.rejected_vex == ((".vex/a.json", "vex_predates_kev"),)


def test_a_kev_listing_on_an_alias_of_the_finding_counts_too() -> None:
    judged = NOW - timedelta(days=5)
    kev = _feeds(kev={"GHSA-aaaa-bbbb-cccc": (judged.date() + timedelta(days=2), None)})
    finding = _finding(CVE, aliases=("GHSA-aaaa-bbbb-cccc",))
    plan = planner.plan(_inputs((finding,), feeds=kev, vex={REPO: (_doc("not_affected", judged),)}))
    assert _ops(plan) == [("create", "finding", CVE)]


def test_a_statement_without_an_impact_statement_suppresses_nothing() -> None:
    plan = planner.plan(_inputs((_finding(),), vex={REPO: (_doc("not_affected", NOW, impact=None),)}))
    assert _ops(plan) == [("create", "finding", CVE)]
    assert plan.rejected_vex == ((".vex/a.json", "vex_missing_impact_statement"),)


# --- T2-02: one vulnerability is one Issue, whatever name each layer used -----------------------------------


def test_a_ghsa_report_and_a_cve_report_of_one_vulnerability_open_one_issue() -> None:
    a = _finding(CVE, aliases=("GHSA-aaaa-bbbb-cccc",))
    b = _finding("GHSA-aaaa-bbbb-cccc", aliases=(CVE,))
    plan = planner.plan(_inputs((a, b)))
    assert _ops(plan) == [("create", "finding", CVE)]
    marker = issue_body.parse_marker(plan.actions[0].body)
    assert marker is not None
    assert marker.aliases == ("GHSA-aaaa-bbbb-cccc",)


def test_identifier_case_does_not_make_a_second_issue() -> None:
    a = _finding("CVE-2026-0001")
    b = _finding("cve-2026-0001")
    assert _ops(planner.plan(_inputs((a, b)))) == [("create", "finding", CVE)]


def test_an_issue_opened_under_the_ghsa_name_is_continued_under_the_cve_name() -> None:
    first = _inputs((_finding("GHSA-aaaa-bbbb-cccc"),))
    both = _finding(CVE, aliases=("GHSA-aaaa-bbbb-cccc",))
    second = _next(first, planner.plan(first), findings=frozenset({both}))
    plan = planner.plan(second)
    assert [(a.op, a.number, a.vuln_id) for a in plan.actions] == [("update", 1, CVE)]


# --- T2-03: an Issue closes as resolved only when its finding is gone --------------------------------------


def test_a_finding_that_loses_its_severity_keeps_its_issue_open() -> None:
    first = _inputs((_finding(),))
    bare = _finding(severity=None)
    again = _next(first, planner.plan(first), findings=frozenset({bare}), run_id="201-1")
    plan = planner.plan(again)
    assert plan.actions == ()
    assert plan.held_unscored == ((REPO, 1, CVE),)
    assert plan.unscored == (bare,)


def test_a_finding_that_falls_below_the_threshold_closes_but_not_as_resolved() -> None:
    first = _inputs((_finding(),))
    medium = _finding(severity="MEDIUM")
    again = _next(first, planner.plan(first), findings=frozenset({medium}), run_id="201-1")
    plan = planner.plan(again)
    assert [(a.op, a.close_reason) for a in plan.actions] == [("close", "below_threshold")]


def test_a_finding_that_is_gone_closes_as_resolved() -> None:
    first = _inputs((_finding(),))
    again = _next(first, planner.plan(first), findings=frozenset(), run_id="201-1")
    assert [(a.op, a.close_reason) for a in planner.plan(again).actions] == [("close", "resolved")]


def test_reopening_after_a_severity_flap_does_not_extend_the_deadline() -> None:
    first = _inputs((_finding(),))
    due = _state(planner.plan(first))["due_at"]
    low = _next(first, planner.plan(first), findings=frozenset({_finding(severity="MEDIUM")}), run_id="201-1")
    closed = _next(low, planner.plan(low))
    back = replace(closed, findings=first.findings, now=LATER + timedelta(days=5), run_id="202-1")
    plan = planner.plan(back)
    assert [a.op for a in plan.actions] == ["reopen"]
    assert _state(plan)["due_at"] == due
    assert _state(plan)["opened_at"] == "2026-11-10T06:00:00Z"


def test_an_issue_of_a_finding_in_another_repository_is_not_held_by_it() -> None:
    first = _inputs((_finding(),))
    other_only = _finding(severity=None, repo=OTHER)
    again = _next(first, planner.plan(first), findings=frozenset({other_only}), run_id="201-1")
    plan = planner.plan(again)
    assert [(a.op, a.close_reason) for a in plan.actions] == [("close", "resolved")]
    assert plan.held_unscored == ()


# --- T2-05: an unknown origin is recorded as unknown --------------------------------------------------------


def test_an_unknown_threshold_time_gives_a_null_origin() -> None:
    finding = replace(_finding(), advisory_published_at=None)
    state = _state(planner.plan(_inputs((finding,))))
    assert state["origin_at"] is None
    assert state["origin_is_date_only"] is False
    body = planner.plan(_inputs((finding,))).actions[0].body or ""
    assert "不明（脅威の公開日時を取得できていない" in body


def test_a_known_origin_survives_a_later_run_that_cannot_see_it() -> None:
    first = _inputs((_finding(),))
    blind = _next(first, planner.plan(first), findings=frozenset({replace(_finding(), advisory_published_at=None)}))
    assert planner.plan(blind).actions == ()  # the origin recorded in the Issue is kept, nothing to update


# --- T2-06: with KEV missing, a finding without severity is deferred, not "unscored" -----------------------


def test_with_the_kev_feed_missing_an_unscored_finding_is_deferred() -> None:
    bare = _finding(severity=None)
    plan = planner.plan(_inputs((bare,), feeds=_feeds(kev=None)))
    assert plan.kev_unknown == (bare,)
    assert plan.unscored == ()


def test_with_the_kev_feed_present_the_same_finding_is_unscored() -> None:
    bare = _finding(severity=None)
    plan = planner.plan(_inputs((bare,)))
    assert plan.unscored == (bare,)
    assert plan.kev_unknown == ()


# --- T2-12: the KEV origin keeps an upper bound beside the date -------------------------------------------


def test_the_first_catalogue_release_that_showed_the_listing_is_kept() -> None:
    low = _finding("CVE-2026-0004", "LOW")
    released = datetime(2026, 11, 8, 19, 3, 29, tzinfo=UTC)
    feeds = _feeds(kev={"CVE-2026-0004": (date(2026, 11, 8), None)}, kev_released_at=released)
    first = _inputs((low,), feeds=feeds)
    state = _state(planner.plan(first))
    assert state["kev_first_release_at"] == "2026-11-08T19:03:29Z"
    assert state["origin_at"] == "2026-11-08T00:00:00Z"  # the lower bound is still the date at 00:00:00Z
    later_feeds = _feeds(kev={"CVE-2026-0004": (date(2026, 11, 8), None)}, kev_released_at=released + timedelta(days=2))
    second = _next(first, planner.plan(first), feeds=later_feeds, now=LATER, run_id="201-1")
    assert planner.plan(second).actions == ()  # a newer catalogue release does not move the recorded one


def test_an_issue_without_a_kev_listing_records_no_release_time() -> None:
    feeds = _feeds(kev={}, kev_released_at=datetime(2026, 11, 8, 19, 3, 29, tzinfo=UTC))
    assert _state(planner.plan(_inputs((_finding(),), feeds=feeds)))["kev_first_release_at"] is None


# --- properties ---------------------------------------------------------------------------------------------


_NAMES = st.sampled_from(["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc", "CVE-2026-0002", "GHSA-dddd-eeee-ffff"])


@st.composite
def _reports(draw: st.DrawFn) -> tuple[models.Finding, ...]:
    out = []
    for _ in range(draw(st.integers(1, 5))):
        name = draw(_NAMES)
        aliases = tuple(draw(st.lists(_NAMES, max_size=2, unique=True)))
        out.append(
            _finding(
                name,
                aliases=tuple(a for a in aliases if a != name),
                purl=draw(st.sampled_from([PURL, "pkg:npm/left-pad@1.4.0"])),
            )
        )
    return tuple(out)


# Feature: cyber-resilience-phase4-supply-chain, Property 8 (T2-02): one Issue per vulnerability, and planning twice settles
@settings(max_examples=150, deadline=None)
@given(_reports())
def test_property_alias_linked_reports_open_one_issue_per_connected_identifier_set(
    reports: tuple[models.Finding, ...],
) -> None:
    """**Validates: Requirements 8.1, 8.9**"""
    inputs = _inputs(reports, policy=_policy(limit=100))
    plan = planner.plan(inputs)
    created = [a.vuln_id for a in plan.actions if a.op == "create"]
    event(f"created={min(len(created), 3)}")
    assert len(created) == len(set(created))
    holders: dict[str, list[str]] = {}
    for a in plan.actions:
        if a.op == "create":
            for i in _ids_of_marker(a.body):
                holders.setdefault(i, []).append(a.vuln_id or "")
    for ident, names in holders.items():
        # An identifier the sources declare with two CVEs is listed under each CVE's Issue (T2-R2-02); nothing
        # else may appear in two Issues (a CVE or MAL- identifier never does).
        assert len(names) == 1 or not ident.startswith(("CVE-", "MAL-")), (
            "one identifier appears in two Issues"
        )
    settled = _next(inputs, plan)
    assert planner.plan(settled).actions == ()


def _ids_of_marker(body: str | None) -> list[str]:
    marker = issue_body.parse_marker(body)
    assert marker is not None
    return [marker.vuln_id or "", *marker.aliases]


# Feature: cyber-resilience-phase4-supply-chain, Property 12 (T2-03): resolved only when the finding is gone
@settings(max_examples=150, deadline=None)
@given(_reports(), st.lists(st.sampled_from(["keep", "none", "medium", "drop"]), min_size=5, max_size=5))
def test_property_a_finding_that_is_still_reported_is_never_closed_as_resolved(
    reports: tuple[models.Finding, ...], changes: list[str]
) -> None:
    """**Validates: Requirements 8.4, 8.7**"""
    first = _inputs(reports, policy=_policy(limit=100))
    after: list[models.Finding] = []
    for n, f in enumerate(first.findings and sorted(first.findings, key=lambda x: (x.vuln_id, x.component.purl))):
        how = changes[n % len(changes)]
        if how == "drop":
            continue
        severity = {"keep": f.cvss_severity, "none": None, "medium": "MEDIUM"}[how]
        after.append(replace(f, cvss_severity=severity))  # type: ignore[arg-type]
    second = _next(first, planner.plan(first), findings=frozenset(after), run_id="201-1")
    plan = planner.plan(second)
    still = {i for f in after for i in (f.vuln_id, *f.aliases)}
    for a in plan.actions:
        if a.op == "close" and a.kind == "finding":
            event(f"close={a.close_reason}")
            if a.close_reason == "resolved":
                assert a.vuln_id not in still, "closed as resolved while the finding is still reported"
    held = {i for _, _, i in plan.held_unscored}
    assert not held & {a.vuln_id for a in plan.actions if a.op == "close"}

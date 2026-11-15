"""Planner behaviour added after the third expert review (T2-R3-02, T2-R3-03)."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from supply_chain import planner

from tests.test_supply_chain_planner import NOW, REPO, _finding, _inputs, _next, _ops, _state
from tests.test_supply_chain_planner_review import CVE, _doc
from tests.test_supply_chain_planner_round3 import _closed_at, _flapped

GHSA = "GHSA-aaaa-bbbb-cccc"
CVE2 = "CVE-2026-0002"


def test_a_statement_named_by_a_shared_ghsa_does_not_exclude_the_split_findings() -> None:
    """T2-R3-02: a name two CVEs share (8.25) is not a name for either of them."""
    one, two = _finding(CVE, aliases=(GHSA,)), _finding(CVE2, aliases=(GHSA,))
    plan = planner.plan(_inputs((one, two), vex={REPO: (_doc("not_affected", NOW, GHSA),)}))
    assert _ops(plan) == [("create", "finding", CVE), ("create", "finding", CVE2)]
    assert plan.vex_exclusions == ()


def test_a_statement_named_by_a_ghsa_of_one_cve_does_not_exclude_it_unless_it_lists_the_cve() -> None:
    """11.37 (T12-R4-05): the sibling's presence no longer matters; the statement has to name the CVE itself."""
    finding = _finding(CVE, aliases=(GHSA,))
    plan = planner.plan(_inputs((finding,), vex={REPO: (_doc("not_affected", NOW, GHSA),)}))
    assert _ops(plan) == [("create", "finding", CVE)]
    assert plan.vex_exclusions == ()


def test_a_statement_named_by_a_ghsa_that_lists_one_cve_in_its_aliases_excludes_that_cve_only() -> None:
    one, two = _finding(CVE, aliases=(GHSA,)), _finding(CVE2, aliases=(GHSA,))
    plan = planner.plan(_inputs((one, two), vex={REPO: (_doc("not_affected", NOW, GHSA, aliases=(CVE,)),)}))
    assert _ops(plan) == [("create", "finding", CVE2)]
    assert [f.vuln_id for f, _ in plan.vex_exclusions] == [CVE]


def test_a_cve_named_statement_still_excludes_only_that_cve_of_a_shared_ghsa() -> None:
    one, two = _finding(CVE, aliases=(GHSA,)), _finding(CVE2, aliases=(GHSA,))
    plan = planner.plan(_inputs((one, two), vex={REPO: (_doc("not_affected", NOW, CVE),)}))
    assert _ops(plan) == [("create", "finding", CVE2)]


def test_a_ghsa_named_issue_is_not_closed_by_vex_while_the_other_cve_is_unscored() -> None:
    """T2-R3-03: the VEX path must not bypass ``held_unscored`` (8.14)."""
    first = _inputs((_finding(GHSA),))
    created = planner.plan(first)
    assert _ops(created) == [("create", "finding", GHSA)]
    one = _finding(CVE, aliases=(GHSA,))
    two = _finding(CVE2, severity=None, aliases=(GHSA,))
    nxt = _next(first, created, findings=frozenset((one, two)), vex={REPO: (_doc("not_affected", NOW, CVE),)})
    plan = planner.plan(nxt)
    assert [a for a in plan.actions if a.op == "close"] == []
    assert [number for _, number, _ in plan.held_unscored] == [1]


def test_a_ghsa_named_issue_still_closes_by_vex_when_nothing_else_remains() -> None:
    first = _inputs((_finding(GHSA),))
    created = planner.plan(first)
    nxt = _next(
        first,
        created,
        findings=frozenset((_finding(CVE, aliases=(GHSA,)),)),
        vex={REPO: (_doc("not_affected", NOW, CVE),)},
    )
    assert [(a.op, a.close_reason) for a in planner.plan(nxt).actions] == [("close", "vex_not_affected")]


@pytest.mark.parametrize(
    ("closed_for", "opened_at", "due_at"),
    [
        (timedelta(days=13), "2026-11-10T06:00:00Z", "2026-11-24T06:00:00Z"),
        (timedelta(days=14), "2026-11-10T06:00:00Z", "2026-11-24T06:00:00Z"),
        (timedelta(days=14, seconds=1), None, None),  # a new response: the deadline moves to 14 days after the reopen
    ],
)
def test_the_reopen_boundary_is_the_response_target_length_not_a_continuous_clock(
    closed_for: timedelta, opened_at: str | None, due_at: str | None
) -> None:
    """T2-R3-04: D-32 keeps this step (a closure of at most 14 days does not extend the deadline)."""
    closed_at = NOW + timedelta(days=1)
    now = closed_at + closed_for
    back = replace(_flapped(), findings=_inputs((_finding(),)).findings, now=now, run_id="202-1")
    state = _state(planner.plan(_closed_at(back, closed_at)))
    if opened_at is None:
        assert state["opened_at"] == now.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert state["due_at"] == (now + timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        assert (state["opened_at"], state["due_at"]) == (opened_at, due_at)

"""A duplicate Issue records its representative and drops out of the figures (T2-R3-07, pure core)."""

from __future__ import annotations

from dataclasses import replace

from supply_chain import issue_body as ib
from supply_chain import metrics, planner

from tests.test_supply_chain_issue_body import _fi
from tests.test_supply_chain_metrics import NOW, _issue, _run
from tests.test_supply_chain_planner import _finding, _inputs, _next
from tests.test_supply_chain_planner_review import CVE

GHSA = "GHSA-aaaa-bbbb-cccc"


def test_the_planner_names_the_representative_of_a_duplicate_and_leaves_it_open() -> None:
    first = _inputs((_finding(CVE), _finding(GHSA)))
    created = planner.plan(first)
    plan = planner.plan(_next(first, created, findings=frozenset((_finding(CVE, aliases=(GHSA,)),))))
    assert [a for a in plan.actions if a.op == "close"] == []
    assert [(n, v) for _r, n, v in plan.duplicate_issues] == [(2, GHSA)]
    assert [(n, rep) for _r, n, rep in plan.duplicate_of] == [(2, CVE)]
    assert len(plan.duplicate_of) == len(plan.duplicate_issues)


def test_no_duplicate_means_no_representative() -> None:
    plan = planner.plan(_inputs((_finding(CVE),)))
    assert plan.duplicate_issues == () and plan.duplicate_of == ()


def test_the_state_block_carries_duplicate_of_only_when_it_is_set() -> None:
    plain = ib.render_finding(_fi())
    assert "duplicate_of" not in plain and "重複の代表" not in plain
    marked = ib.render_finding(_fi(duplicate_of="CVE-2026-0002"))
    state = ib.parse_state(marked)
    assert state is not None and state["duplicate_of"] == "CVE-2026-0002"
    assert "重複の代表" in marked
    assert ib.render_finding(_fi(duplicate_of="CVE-2026-0002")) == marked  # deterministic


def test_a_duplicate_is_not_overdue_and_not_a_fix() -> None:
    late = _issue(due=24, opened=1)
    twin = replace(_issue(vuln="GHSA-x", due=24, opened=1), duplicate_of="CVE-2026-0001")
    fixed = replace(_issue(vuln="GHSA-y", opened=1, closed=5, reason="resolved"), duplicate_of="CVE-2026-0001")
    result = _run([late, twin, fixed])
    assert result.by_repo[0].overdue_open == 1  # the control: the representative still counts
    assert result.fix.durations == ()
    assert result.detection.durations == _run([late]).detection.durations


def test_the_response_target_sli_leaves_a_duplicate_out() -> None:
    late = _issue(due=24, opened=1)
    twin = replace(_issue(vuln="GHSA-x", due=24, opened=1), duplicate_of="CVE-2026-0001")
    assert metrics.sli_counts([late, twin], NOW) == metrics.sli_counts([late], NOW)
    assert metrics.sli_counts([late, twin], NOW).denominator == 1

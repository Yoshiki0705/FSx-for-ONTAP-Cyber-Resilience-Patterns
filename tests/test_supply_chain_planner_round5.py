"""Planner behaviour added after the fourth expert review (T12-R4-05, T12-R4-06)."""

from __future__ import annotations

from supply_chain import planner

from tests.test_supply_chain_planner import NOW, REPO, _finding, _inputs, _next, _ops
from tests.test_supply_chain_planner_review import _doc

GA = "GHSA-aaaa-bbbb-cccc"
GD = "GHSA-dddd-eeee-ffff"
C1 = "CVE-2026-0001"
C2 = "CVE-2026-0002"


# ---- T12-R4-06: seed 1 of the idempotence search found an exchange of two Issues between two CVEs
def test_a_closed_and_an_open_issue_that_two_cves_take_over_do_not_swap_on_the_next_run() -> None:
    """Closed Issue 1 (GA) and open Issue 2 (GD); then one record GA with aliases GD, C1, C2 splits in two.

    The first run reassigns both Issues (one update, one reopen). The next run, over the Issues as the store holds
    them (the marker of an updated Issue carries the new identifier), must have nothing to do.
    """
    cur = _inputs((_finding(GA),))
    cur = _next(cur, planner.plan(cur))
    cur = _next(cur, planner.plan(cur), findings=frozenset((_finding(GD),)))
    cur = _next(cur, planner.plan(cur))
    assert sorted((i.number, i.vuln_id, i.state) for i in cur.issues) == [(1, GA, "closed"), (2, GD, "open")]
    cur = _next(cur, planner.plan(cur), findings=frozenset((_finding(GA, aliases=(GD, C1, C2)),)))
    first = planner.plan(cur)
    assert sorted(a.op for a in first.actions) == ["reopen", "update"]
    cur = _next(cur, first)
    assert {i.vuln_id for i in cur.issues} == {C1, C2}  # the store rewrote the markers
    assert planner.plan(cur).actions == ()


def test_the_exchange_does_not_depend_on_which_issue_the_open_state_prefers() -> None:
    """The same split with the open Issue the lower number: still one run to settle."""
    cur = _inputs((_finding(GD),))
    cur = _next(cur, planner.plan(cur))
    cur = _next(cur, planner.plan(cur), findings=frozenset((_finding(GA),)))
    cur = _next(cur, planner.plan(cur))
    cur = _next(cur, planner.plan(cur), findings=frozenset((_finding(GA, aliases=(GD, C1, C2)),)))
    cur = _next(cur, planner.plan(cur))
    assert planner.plan(cur).actions == ()


# ---- T12-R4-05: a statement covers only what it names itself (Requirement 11.37)
def test_a_ghsa_named_statement_does_not_start_to_exclude_when_the_sibling_finding_disappears() -> None:
    both = (_finding(C1, aliases=(GA,)), _finding(C2, aliases=(GA,)))
    docs = {REPO: (_doc("not_affected", NOW, GA),)}
    first = _inputs(both, vex=docs)
    created = planner.plan(first)
    assert _ops(created) == [("create", "finding", C1), ("create", "finding", C2)]
    alone = _next(first, created, findings=frozenset((_finding(C1, aliases=(GA,)),)))
    plan = planner.plan(alone)
    # CVE-2026-0002 left the feeds, so its Issue closes as resolved; CVE-2026-0001 is not judged by the shared name.
    assert [(a.vuln_id, a.close_reason) for a in plan.actions if a.op == "close"] == [(C2, "resolved")]
    assert plan.vex_exclusions == ()


def test_a_ghsa_named_statement_does_not_exclude_a_cve_whose_record_never_shared_it_here() -> None:
    """With no sibling ever seen, a GHSA-named statement still does not exclude the CVE: it has to name the CVE."""
    plan = planner.plan(_inputs((_finding(C1, aliases=(GA,)),), vex={REPO: (_doc("not_affected", NOW, GA),)}))
    assert _ops(plan) == [("create", "finding", C1)]
    assert plan.vex_exclusions == ()


def test_a_ghsa_named_statement_that_lists_the_cve_excludes_it_with_or_without_the_sibling() -> None:
    docs = {REPO: (_doc("not_affected", NOW, GA, aliases=(C1,)),)}
    both = _inputs((_finding(C1, aliases=(GA,)), _finding(C2, aliases=(GA,))), vex=docs)
    assert [f.vuln_id for f, _ in planner.plan(both).vex_exclusions] == [C1]
    alone = _inputs((_finding(C1, aliases=(GA,)),), vex=docs)
    assert [f.vuln_id for f, _ in planner.plan(alone).vex_exclusions] == [C1]

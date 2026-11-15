"""Property for Requirement 27.18 (task 9.39): a statement named by a shared alias excludes nothing by itself.

Several CVE Findings in one repository share one GHSA (split by Requirement 8.25). A statement whose
``vulnerability.name`` is that GHSA:

* excludes no split CVE unless the statement's own ``aliases`` name it (11.37), and
* does not start to exclude a CVE when its siblings disappear (11.37, 11.51).

The statement's ``aliases`` are drawn from the CVEs, so both the "names no CVE" and the "names some CVE" cases
run. Every run is compared with an oracle that reads only the statement.
"""

from __future__ import annotations

from datetime import timedelta

from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st
from supply_chain import planner

from tests.test_supply_chain_planner import NOW, REPO, _finding, _inputs, _next
from tests.test_supply_chain_planner_review import _doc

GHSA = "GHSA-aaaa-bbbb-cccc"
CVES = tuple(f"CVE-2026-{n:04d}" for n in range(1, 6))


def _findings(names: tuple[str, ...]) -> frozenset:
    return frozenset(_finding(c, aliases=(GHSA,)) for c in names)


@st.composite
def _cases(draw: st.DrawFn) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """(CVEs present at first, CVEs present later, CVEs the statement names in its aliases)."""
    first = tuple(draw(st.lists(st.sampled_from(CVES), min_size=2, max_size=5, unique=True)))
    later = tuple(draw(st.lists(st.sampled_from(first), min_size=0, max_size=len(first), unique=True)))
    named = tuple(draw(st.lists(st.sampled_from(CVES), min_size=0, max_size=3, unique=True)))
    return first, later, named


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_cases())
def test_a_statement_named_by_a_shared_alias_excludes_only_the_cves_it_lists_and_never_starts_later(
    case: tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]],
) -> None:
    first, later, named = case
    event("statement names no CVE" if not named else "statement names a CVE")
    event("siblings all gone" if not later else "some siblings remain")
    docs = {REPO: (_doc("not_affected", NOW - timedelta(hours=1), GHSA, aliases=named),)}
    cur = _inputs(tuple(_findings(first)), vex=docs)
    plan = planner.plan(cur)
    for step, present in enumerate((first, later)):
        if step:
            cur = _next(cur, plan, findings=_findings(present))
            plan = planner.plan(cur)
        excluded = {f.vuln_id for f, _ in plan.vex_exclusions}
        assert excluded == set(present) & set(named), (step, present, named, excluded)
        # No Issue is closed for VEX in a run for a CVE the statement does not name (the Finding is still there
        # or its Issue was closed because the Finding is gone, never "vex_not_affected").
        for action in plan.actions:
            if action.op == "close" and action.vuln_id not in named:
                assert action.close_reason != "vex_not_affected", (step, action)

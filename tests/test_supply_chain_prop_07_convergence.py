"""Property 7 over changing inputs: after a plan is applied, planning the same inputs again gives nothing.

The generated Findings carry aliases, so one record may split into several CVEs, merge with another, or share a
GHSA with a sibling. Findings change between steps and a VEX statement may name any of the identifiers. Seed 1 of
the first version of this search found two Issues swapping CVEs for one run (T12-R4-06).
"""

from __future__ import annotations

from datetime import timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from supply_chain import planner

from tests.test_supply_chain_planner import NOW, REPO, _feeds, _finding, _inputs, _next
from tests.test_supply_chain_planner_review import _doc

_CVES = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
_GHSAS = ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]
_IDS = [*_CVES, *_GHSAS, "PYSEC-9"]
_findings = st.builds(
    lambda vuln, aliases, severity: _finding(vuln, severity, aliases=tuple(a for a in aliases if a != vuln)),
    st.sampled_from(_IDS),
    st.lists(st.sampled_from(_IDS), max_size=3, unique=True),
    st.sampled_from(["HIGH", "CRITICAL", "LOW", None]),
)
_sets = st.lists(_findings, max_size=5, unique_by=lambda f: (f.vuln_id, f.aliases))
_statements = st.lists(
    st.tuples(
        st.sampled_from(["not_affected", "affected", "fixed", "under_investigation"]),
        st.integers(0, 8),
        st.sampled_from(_IDS),
    ),
    max_size=3,
)


@settings(max_examples=3000, deadline=None, suppress_health_check=list(HealthCheck))
@given(_sets, _statements, st.sampled_from([None, {}]), st.lists(_sets, min_size=1, max_size=3))
def test_the_second_plan_over_the_same_inputs_is_empty_whatever_the_earlier_inputs_were(
    first: list, statements: list, kev: object, later: list
) -> None:
    docs = tuple(
        _doc(status, NOW - timedelta(days=days), name, path=f".vex/{n}.json")
        for n, (status, days, name) in enumerate(statements)
    )
    current = _inputs(tuple(first), vex={REPO: docs}, feeds=_feeds() if kev is None else _feeds(kev=kev))
    for step, found in enumerate([tuple(first), *map(tuple, later)]):
        current = _next(current, planner.plan(current), findings=frozenset(found))
        applied = _next(current, planner.plan(current))
        again = planner.plan(applied)
        assert again.actions == (), (step, [(a.op, a.vuln_id, a.close_reason) for a in again.actions])
        current = applied

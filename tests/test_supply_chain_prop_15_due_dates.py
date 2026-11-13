"""Property 15: KEV listing shortens the fix deadline (task 9.15).

Two halves, both read from ``planner.plan`` through the state block of the rendered Issue body:

* A new Issue is due ``opened_at + fix_days_kev_or_malicious`` if it is KEV-listed or a
  Malicious_Package_Finding, otherwise ``opened_at + fix_days_high`` (Requirements 18.1, 21.3).
  ``fix_days_high`` is read from the drawn Policy_File value, never fixed at 14 (Q-13).
* For an open High-or-above Issue that a run (time ``t``) finds newly KEV-listed, the updated due date is
  ``min(existing, t + fix_days_kev_or_malicious)`` and is never later than the existing one
  (Requirement 18.5).

The first half runs on the task 9.1 generator ``sc.plan_inputs`` with no existing Issues. The second half
builds the state it needs: run 1 creates the Issue without KEV, the test rewrites its due date to a drawn
offset from ``t`` (before and after ``t + fix_days_kev_or_malicious``), and run 2 lists the vulnerability in
KEV, by its own identifier or by an alias.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta

import hypothesis.strategies as st
from hypothesis import HealthCheck, event, given, settings
from supply_chain import issue_body as ib
from supply_chain import planner
from supply_chain.models import (
    FeedSnapshot,
    Finding,
    ManagedIssue,
    OpeningThreshold,
    PlanInputs,
    Policy,
)

from tests.strategies import supply_chain as sc

_SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
_ISO = "%Y-%m-%dT%H:%M:%SZ"


def _at(text: str) -> datetime:
    return datetime.strptime(text, _ISO).replace(tzinfo=sc.EPOCH.tzinfo)


def _created(inputs: PlanInputs) -> list[tuple[str, dict]]:
    """``(vuln_id, state)`` of every Issue the plan creates for a finding."""
    out = []
    for action in planner.plan(inputs).actions:
        if action.op == "create" and action.kind == "finding":
            state = ib.parse_state(action.body)
            assert state is not None
            out.append((action.vuln_id or "", state))
    return out


def _check_created(inputs: PlanInputs) -> list[str]:
    """Asserts the due date of every new Issue; returns what the example exercised."""
    target = inputs.policy.response_target
    kev = inputs.feeds.kev or {}
    facts: list[str] = []
    for vuln_id, state in _created(inputs):
        listed, malicious = state["kev_listed"], state["malicious"]
        # The flags agree with the feed and the identifier, not only with each other.
        assert listed or vuln_id not in kev
        assert malicious or not vuln_id.startswith("MAL-")
        assert state["opened_at"] == inputs.now.strftime(_ISO)
        days = target.fix_days_kev_or_malicious if listed or malicious else target.fix_days_high
        assert _at(state["due_at"]) == inputs.now + timedelta(days=days)
        facts.append("created=malicious" if malicious else "created=kev" if listed else "created=plain")
        if target.fix_days_kev_or_malicious != target.fix_days_high:
            facts.append("days_differ")
    return facts


# Feature: cyber-resilience-phase4-supply-chain, Property 15: KEV 掲載による修正期限の短縮
@_SETTINGS
@given(sc.plan_inputs(12, 0))
def test_new_issue_is_due_by_kev_or_malicious_days_else_high_days(inputs: PlanInputs) -> None:
    """A new Issue is due at ``now`` plus ``fix_days_kev_or_malicious`` if KEV-listed or malicious, else ``fix_days_high``.

    **Validates: Requirements 18.1, 21.3**
    """
    for fact in _check_created(inputs):
        event(fact)


def _high_kev_case(
    policy: Policy, severity: str, via_alias: bool, minutes_before: int, offset_minutes: int, vuln: int
) -> tuple[PlanInputs, PlanInputs, datetime]:
    """Run 1 (no KEV) creates the Issue; the returned run 2 lists it in KEV at ``t``, with its due date moved."""
    policy = replace(policy, opening_threshold=OpeningThreshold("HIGH", True, True))
    repo = policy.target_repositories[0]
    t = sc.utc_at(450 * 1440)
    alias = sc.ghsa_id(vuln)
    finding = Finding(
        repo=repo,
        vuln_id=sc.cve_id(vuln),
        aliases=(alias,),
        component=sc.component_of(vuln % 7, vuln % 3),
        cvss_severity=severity,  # type: ignore[arg-type]
        fixed_version=None,
        advisory_published_at=t - timedelta(days=500),
        layer="A",
        first_observed_component_at=t - timedelta(days=490),
    )
    quiet = FeedSnapshot({}, {}, {}, {}, frozenset(), frozenset())
    first = PlanInputs(
        policy,
        "100-1",
        t - timedelta(minutes=minutes_before),
        (),
        frozenset({finding}),
        frozenset({repo}),
        quiet,
        {},
        (),
    )
    (action,) = [a for a in planner.plan(first).actions if a.op == "create"]
    state = dict(ib.parse_state(action.body) or {})
    existing = t + timedelta(minutes=offset_minutes)
    state["due_at"] = existing.strftime(_ISO)
    issue = ManagedIssue(repo, 1, "finding", finding.vuln_id, "open", state)
    listed = FeedSnapshot(
        {(alias if via_alias else finding.vuln_id): (t.date(), None)}, {}, {}, {}, frozenset(), frozenset()
    )
    second = replace(first, run_id="100-2", now=t, feeds=listed, issues=(issue,))
    return first, second, existing


# Feature: cyber-resilience-phase4-supply-chain, Property 15: KEV 掲載による修正期限の短縮
@_SETTINGS
@given(
    sc.policies(),
    st.sampled_from(("HIGH", "CRITICAL")),
    st.booleans(),
    st.integers(0, 3 * 1440),
    st.integers(-40 * 1440, 90 * 1440),
    st.integers(0, sc.CVE_POOL - 1),
)
def test_newly_kev_listed_high_issue_is_due_at_the_earlier_of_existing_and_now_plus_kev_days(
    policy: Policy, severity: str, via_alias: bool, minutes_before: int, offset_minutes: int, vuln: int
) -> None:
    """The updated due date is ``min(existing, t + fix_days_kev_or_malicious)`` and never later than the existing one.

    **Validates: Requirements 18.1, 18.5**
    """
    first, second, existing = _high_kev_case(policy, severity, via_alias, minutes_before, offset_minutes, vuln)
    # Run 1 had no KEV: the new Issue is on the High deadline.
    ((_, created),) = _created(first)
    assert _at(created["due_at"]) == first.now + timedelta(days=policy.response_target.fix_days_high)
    urgent = second.now + timedelta(days=policy.response_target.fix_days_kev_or_malicious)
    updates = [a for a in planner.plan(second).actions if a.number == 1]
    assert [a.op for a in updates] == ["update"]
    due = _at(ib.parse_state(updates[0].body)["due_at"])  # type: ignore[index]
    assert due == min(existing, urgent)
    assert due <= existing
    event("shortened" if due < existing else "kept")
    event("alias" if via_alias else "primary")
    # A later run that sees the same listing never moves the date back out.
    third = replace(
        second,
        run_id="100-3",
        now=second.now + timedelta(days=1),
        issues=(replace(second.issues[0], body_state=ib.parse_state(updates[0].body)),),
    )
    later = [a for a in planner.plan(third).actions if a.number == 1]
    assert all(_at(ib.parse_state(a.body)["due_at"]) <= due for a in later)  # type: ignore[index]


def test_the_generated_cases_exercise_every_branch() -> None:
    """The properties are not vacuous (fixed seed): new Issues of each kind and both outcomes of the minimum."""
    seen: Counter[str] = Counter()
    fixed = dict(max_examples=300, deadline=None, derandomize=True, database=None)

    @settings(**fixed, suppress_health_check=[HealthCheck.too_slow])
    @given(sc.plan_inputs(12, 0))
    def created(inputs: PlanInputs) -> None:
        seen.update(set(_check_created(inputs)))

    @settings(**fixed, suppress_health_check=[HealthCheck.too_slow])
    @given(
        sc.policies(),
        st.sampled_from(("HIGH", "CRITICAL")),
        st.booleans(),
        st.integers(-40 * 1440, 90 * 1440),
    )
    def listed(policy: Policy, severity: str, via_alias: bool, offset_minutes: int) -> None:
        _, second, existing = _high_kev_case(policy, severity, via_alias, 60, offset_minutes, 3)
        urgent = second.now + timedelta(days=policy.response_target.fix_days_kev_or_malicious)
        seen["shortened" if urgent < existing else "kept"] += 1
        seen["alias" if via_alias else "primary"] += 1

    created()
    listed()
    for needed in (
        "created=malicious",
        "created=kev",
        "created=plain",
        "days_differ",
        "shortened",
        "kept",
        "alias",
        "primary",
    ):
        assert seen[needed] >= 5, f"{needed}: {sorted(seen.items())}"


@settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(sc.policies())
def test_non_default_days_are_read_from_the_policy(policy: Policy) -> None:
    """Policy values 3 and 30 (not 7 and 14): the new Issue is due on day 30, then day 3 once KEV lists it."""
    target = replace(policy.response_target, fix_days_kev_or_malicious=3, fix_days_high=30)
    policy = replace(policy, response_target=target)
    first, second, _ = _high_kev_case(policy, "HIGH", False, 0, 60 * 1440, 1)
    ((_, created),) = _created(first)
    assert _at(created["due_at"]) == first.now + timedelta(days=30)
    (update,) = [a for a in planner.plan(second).actions if a.number == 1]
    assert _at(ib.parse_state(update.body)["due_at"]) == second.now + timedelta(days=3)  # type: ignore[index]

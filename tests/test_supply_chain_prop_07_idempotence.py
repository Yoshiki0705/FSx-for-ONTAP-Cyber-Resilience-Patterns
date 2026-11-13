"""Property 7: planning is idempotent against the Issue store the plan produced.

Applying ``plan(x)`` to the fake store and planning again over the resulting Issues must give no action.
The fake store ignores the body of a ``reopen`` (GitHub applies it on PATCH), so a ``reopen`` is followed
by an ``update`` with the same body. A run that exceeds the per-repository limit is not idempotent by
design (the overflow is created by the next run), so the property is checked when ``overflow_counts``
is empty; the generated limits include one large enough that most inputs do not overflow.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import date

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner

from tests.fakes import issue_store as fake
from tests.strategies import supply_chain as sc

_LIMITS = (1, 2, 3, 4, 20)


def _policy(limit: int) -> models.Policy:
    return models.Policy(
        schema_version=1,
        target_repositories=sc.DEFAULT_REPOS,
        excluded_repositories=(),
        opening_threshold=models.OpeningThreshold("HIGH", True, True),
        cooldown_days=models.CooldownDays(3, 7),
        automerge_include=(),
        automerge_exclude=(),
        automerge_enabled_repositories=(),
        package_manager_wait=models.CooldownDays(3, 7),
        non_production_paths=(),
        vex_directory=".vex",
        vex_exclude_statuses=("not_affected", "fixed"),
        vex_approver_role="VEX_Reviewer",
        vex_one_statement_per_document=True,
        vex_malicious_never_suppressed=True,
        response_target=models.ResponseTarget(24, 7, 14),
        max_new_issues_per_repo_per_run=limit,
    )


def _settle(inputs: models.PlanInputs, plan: models.Plan) -> models.PlanInputs:
    """``inputs`` with the Issues the store holds after every action of ``plan`` succeeded."""
    store = fake.IssueStore.from_managed(inputs.issues)
    for action in plan.actions:
        store = store.apply_action(action)
        if action.op == "reopen":
            store = store.apply_action(replace(action, op="update"))
    return replace(inputs, issues=fake.to_managed_issues(store, issue_body.parse_state))


def _sized(limit: int) -> st.SearchStrategy[models.PlanInputs]:
    return sc.plan_inputs(14, 14, policy=_policy(limit))


# Feature: cyber-resilience-phase4-supply-chain, Property 7: 計画の冪等性
@settings(max_examples=200, deadline=None)
@given(st.sampled_from(_LIMITS).flatmap(_sized))
def test_planning_over_the_applied_result_is_empty(inputs: models.PlanInputs) -> None:
    """``plan(x')`` holds no action, where ``x'`` is ``x`` with the Issues of the store after ``plan(x)``.

    **Validates: Requirements 8.5, 27.5**
    """
    first = planner.plan(inputs)
    ops = Counter(a.op for a in first.actions)
    if first.overflow_counts:
        event("overflow: skipped")
        return
    event(f"creates={min(ops['create'], 3)}")
    event(f"closes={min(ops['close'], 2)} reopens={min(ops['reopen'], 2)} updates={min(ops['update'], 2)}")
    again = planner.plan(_settle(inputs, first))
    assert again.actions == ()


# Feature: cyber-resilience-phase4-supply-chain, Property 7: 計画の冪等性
@settings(max_examples=100, deadline=None)
@given(st.sampled_from(_LIMITS).flatmap(_sized))
def test_planning_stays_empty_after_the_feeds_change_and_the_result_is_applied(inputs: models.PlanInputs) -> None:
    """From a settled state, new EPSS values give updates, and after applying them the plan is empty again.

    The generated Issues rarely match the generated findings, so the match is derived: settle, change
    the feeds, plan (updates expected), settle, plan.

    **Validates: Requirements 8.5, 27.5**
    """
    first = planner.plan(inputs)
    if first.overflow_counts:
        event("overflow: skipped")
        return
    settled = _settle(inputs, first)
    epss = {i: ("0.50000", date(2026, 12, 1), "v-derived") for f in inputs.findings for i in (f.vuln_id, *f.aliases)}
    changed = replace(settled, feeds=replace(settled.feeds, epss=epss))
    second = planner.plan(changed)
    if second.overflow_counts:
        event("overflow: skipped")
        return
    event(f"updates={min(sum(a.op == 'update' for a in second.actions), 3)}")
    assert planner.plan(_settle(changed, second)).actions == ()


# Feature: cyber-resilience-phase4-supply-chain, Property 7: 計画の冪等性
@settings(max_examples=100, deadline=None)
@given(st.sampled_from(_LIMITS).flatmap(_sized))
def test_planning_stays_empty_after_closed_issues_are_reopened(inputs: models.PlanInputs) -> None:
    """Close the finding Issues of a settled state by hand, plan (reopens expected), settle, plan again.

    **Validates: Requirements 8.5, 27.5**
    """
    first = planner.plan(inputs)
    if first.overflow_counts:
        event("overflow: skipped")
        return
    settled = _settle(inputs, first)
    closed = replace(
        settled,
        issues=tuple(replace(i, state="closed") if i.kind == "finding" else i for i in settled.issues),
    )
    second = planner.plan(closed)
    if second.overflow_counts:
        event("overflow: skipped")
        return
    event(f"reopens={min(sum(a.op == 'reopen' for a in second.actions), 3)}")
    assert planner.plan(_settle(closed, second)).actions == ()


def test_the_property_is_not_vacuous() -> None:
    """Across the generated inputs, non-overflowing runs create and close, and from a settled state update and reopen."""
    seen: Counter[str] = Counter()

    @settings(max_examples=150, deadline=None)
    @given(st.sampled_from(_LIMITS).flatmap(_sized))
    def run(inputs: models.PlanInputs) -> None:
        first = planner.plan(inputs)
        if first.overflow_counts:
            seen["overflow"] += 1
            return
        seen["checked"] += 1
        seen.update(a.op for a in first.actions)
        epss = {
            i: ("0.50000", date(2026, 12, 1), "v-derived") for f in inputs.findings for i in (f.vuln_id, *f.aliases)
        }
        settled = _settle(inputs, first)
        second = planner.plan(replace(settled, feeds=replace(settled.feeds, epss=epss)))
        seen.update(f"derived-{a.op}" for a in second.actions)
        closed = replace(
            settled,
            issues=tuple(replace(i, state="closed") if i.kind == "finding" else i for i in settled.issues),
        )
        seen.update(f"closed-{a.op}" for a in planner.plan(closed).actions)

    run()
    needed = ("checked", "create", "close", "derived-update", "closed-reopen")
    missing = [k for k in needed if seen[k] == 0]
    assert not missing, f"never seen: {missing}; counts {sorted(seen.items())}"
    assert seen["checked"] > seen["overflow"]

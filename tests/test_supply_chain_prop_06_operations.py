"""Property 6: the operation chosen for a finding follows the state of its existing Issue (task 9.7).

The generated Issues rarely match the generated findings, so the test builds the state it needs:
plan the generated findings with no Issues, apply the plan, then for every created finding Issue
draw one of three states (left open, closed, deleted) and, independently, whether the feed values
change. The second plan must hold exactly one operation of the matching kind for each group.
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


def _policy_inputs(limit: int) -> st.SearchStrategy[models.PlanInputs]:
    base = sc.policies().map(lambda p: replace(p, max_new_issues_per_repo_per_run=limit))
    return base.flatmap(lambda p: sc.plan_inputs(14, 0, policy=replace(p, target_repositories=sc.DEFAULT_REPOS)))


def _settled(inputs: models.PlanInputs, plan: models.Plan) -> tuple[models.ManagedIssue, ...]:
    """The finding Issues the next run reads after ``plan`` succeeded (summaries are left out)."""
    store = fake.IssueStore.from_managed(inputs.issues)
    for action in plan.actions:
        store = store.apply_action(action)
        if action.op == "reopen":
            store = store.apply_action(replace(action, op="update"))
    managed = fake.to_managed_issues(store, issue_body.parse_state)
    return tuple(m for m in managed if m.kind == "finding")


def _ops_of(plan: models.Plan, repo: models.Repo, vuln_id: str | None) -> list[str]:
    return [a.op for a in plan.actions if a.kind == "finding" and a.repo == repo and a.vuln_id == vuln_id]


def _check(inputs: models.PlanInputs, data: st.DataObject) -> Counter[str]:
    """Plans twice around a drawn Issue state, asserts the property and tallies the cases seen."""
    seen: Counter[str] = Counter()
    first = planner.plan(inputs)
    created = [a for a in first.actions if a.op == "create" and a.kind == "finding"]
    settled = _settled(inputs, first)
    by_key = {(i.repo, i.vuln_id): i for i in settled}
    assert len(by_key) == len(settled) == len(created)

    changed = data.draw(st.booleans(), label="feed values change")
    states = ["open", "closed", "deleted", "open_twin_closed", "open_twin_open"]
    choices = {key: data.draw(st.sampled_from(states), label=str(key[1])) for key in by_key}
    built: list[models.ManagedIssue] = []
    for i in settled:
        choice = choices[(i.repo, i.vuln_id)]
        if choice == "closed":
            built.append(replace(i, state="closed"))
        elif choice.startswith("open_twin"):
            # A duplicate of the same marker; the twin has the lower number so a wrong pick shows.
            twin_state = "closed" if choice.endswith("closed") else "open"
            built += [replace(i, number=i.number + 1000), replace(i, state=twin_state)]  # type: ignore[arg-type]
        elif choice != "deleted":
            built.append(i)
    issues = tuple(built)
    feeds = inputs.feeds
    if changed:
        epss = {
            x: ("0.50000", date(2026, 12, 1), "v-derived") for f in inputs.findings for x in (f.vuln_id, *f.aliases)
        }
        feeds = replace(feeds, epss=epss)
    second = planner.plan(replace(inputs, issues=issues, feeds=feeds, run_id="next-1"))

    for (repo, vuln_id), choice in choices.items():
        ops = _ops_of(second, repo, vuln_id)
        if choice == "closed":
            assert ops == ["reopen"], (repo, vuln_id, ops)
        elif choice == "deleted":
            assert ops == ["create"], (repo, vuln_id, ops)
        else:  # open, or open next to a duplicate: only one Issue is touched
            assert ops == (["update"] if changed else []), (repo, vuln_id, ops)
        event(f"{choice}/{'changed' if changed else 'same'}")
        seen[f"{choice}/{'changed' if changed else 'same'}"] += 1

    # A group that is created is not also listed in the summary Issue of its repository.
    created_now = {(a.repo, a.vuln_id) for a in second.actions if a.kind == "finding" and a.op == "create"}
    for action in second.actions:
        if action.kind == "summary" and action.body is not None:
            state = issue_body.parse_state(action.body)
            listed = {(action.repo, e["vuln_id"]) for e in (state or {}).get("entries", [])}  # type: ignore[attr-defined]
            assert not listed & created_now
            event("summary listed")
            seen["summary"] += 1
    seen["overflow"] += bool(first.overflow_counts)
    return seen


# Feature: cyber-resilience-phase4-supply-chain, Property 6: 既存 Issue の状態に応じた操作の選択
@settings(max_examples=150, deadline=None)
@given(st.integers(1, 4).flatmap(_policy_inputs), st.data())
def test_operation_follows_the_state_of_the_existing_issue(inputs: models.PlanInputs, data: st.DataObject) -> None:
    """Open and unchanged: nothing. Open and changed: one update. Closed: one reopen. None: one create.

    **Validates: Requirements 8.1, 8.2, 8.7**
    """
    _check(inputs, data)


def test_property_6_cases_all_occur() -> None:
    """The property is not vacuous: every state, with and without a feed change, is exercised."""
    seen: Counter[str] = Counter()

    # derandomize: the input sequence is fixed, so whether every shape occurs does not
    # depend on the random seed of the run.
    @settings(max_examples=150, deadline=None, derandomize=True)
    @given(st.integers(1, 4).flatmap(_policy_inputs), st.data())
    def run(inputs: models.PlanInputs, data: st.DataObject) -> None:
        seen.update(_check(inputs, data))

    run()
    wanted = [
        f"{s}/{c}"
        for s in ("open", "closed", "deleted", "open_twin_closed", "open_twin_open")
        for c in ("changed", "same")
    ]
    missing = [k for k in (*wanted, "overflow", "summary") if seen[k] == 0]
    assert not missing, f"never seen: {missing}; counts {sorted(seen.items())}"

"""The ``response-target-overdue`` label (task 9.25, Requirement 18.19, Properties 7 and 14)."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner

from tests.fakes import issue_store as fake
from tests.test_supply_chain_planner import NOW, REPO, _finding, _inputs

LABEL = models.OVERDUE_LABEL
CVE = "CVE-2026-0001"


def _issue(
    *,
    due_in: timedelta,
    state: models.IssueState = "open",
    labels: frozenset[str] = frozenset(),
    number: int = 7,
    vuln_id: str = CVE,
    kind: models.IssueKind = "finding",
) -> models.ManagedIssue:
    """A managed Issue whose Finding is still present, built from the body the planner itself writes."""
    first = planner.plan(_inputs((_finding(vuln_id or CVE),)))
    body = first.actions[0].body
    state_block = dict(issue_body.parse_state(body) or {})
    state_block["due_at"] = (NOW + due_in).strftime("%Y-%m-%dT%H:%M:%SZ")
    return models.ManagedIssue(REPO, number, kind, vuln_id, state, state_block, labels=labels)


def _label_ops(plan: models.Plan) -> list[tuple[str, int | None, tuple[str, ...], tuple[str, ...]]]:
    return [(a.op, a.number, a.add_labels, a.remove_labels) for a in plan.actions if a.add_labels or a.remove_labels]


def test_an_open_issue_past_its_due_time_gets_the_label() -> None:
    issue = _issue(due_in=-timedelta(hours=1))
    plan = planner.plan(_inputs((_finding(CVE),), (issue,)))
    assert _label_ops(plan) == [("update", 7, (LABEL,), ())]


def test_the_label_is_added_by_an_update_without_a_body_when_nothing_else_changes() -> None:
    issue = _issue(due_in=-timedelta(hours=1))
    plan = planner.plan(_inputs((_finding(CVE),), (issue,)))
    assert [(a.op, a.body is None) for a in plan.actions if a.number == 7] == [("update", True)]


def test_an_issue_still_within_its_due_time_gets_nothing() -> None:
    issue = _issue(due_in=timedelta(hours=1))
    assert _label_ops(planner.plan(_inputs((_finding(CVE),), (issue,)))) == []


def test_the_due_time_itself_is_not_overdue() -> None:
    issue = _issue(due_in=timedelta(0))
    assert _label_ops(planner.plan(_inputs((_finding(CVE),), (issue,)))) == []


def test_an_issue_that_already_has_the_label_is_left_alone() -> None:
    issue = _issue(due_in=-timedelta(days=1), labels=frozenset({LABEL}))
    assert _label_ops(planner.plan(_inputs((_finding(CVE),), (issue,)))) == []


def test_the_label_is_removed_when_the_due_time_is_back_in_the_future() -> None:
    issue = _issue(due_in=timedelta(days=1), labels=frozenset({LABEL}))
    plan = planner.plan(_inputs((_finding(CVE),), (issue,)))
    assert _label_ops(plan) == [("update", 7, (), (LABEL,))]


def test_a_closed_issue_is_not_labelled() -> None:
    issue = _issue(due_in=-timedelta(days=1), state="closed")
    plan = planner.plan(_inputs((), (issue,)))
    assert _label_ops(plan) == []


def test_an_issue_closed_in_this_run_is_not_labelled() -> None:
    issue = _issue(due_in=-timedelta(days=1))
    plan = planner.plan(_inputs((), (issue,)))  # the finding is gone: the Issue closes
    assert [a.op for a in plan.actions] == ["close"] and _label_ops(plan) == []


def test_the_label_rides_on_the_update_that_already_changes_the_body() -> None:
    issue = _issue(due_in=-timedelta(hours=1))
    new_component = _finding(CVE, purl="pkg:npm/other@2.0.0")
    plan = planner.plan(_inputs((_finding(CVE), new_component), (issue,)))
    updates = [a for a in plan.actions if a.number == 7]
    assert len(updates) == 1 and updates[0].body is not None and updates[0].add_labels == (LABEL,)


def test_summary_and_unscored_issues_are_never_labelled() -> None:
    issue = _issue(due_in=-timedelta(days=1), kind="summary", vuln_id=None)  # type: ignore[arg-type]
    plan = planner.plan(_inputs((_finding(CVE),), (issue,)))
    assert all(a.number != 7 or not (a.add_labels or a.remove_labels) for a in plan.actions)


def test_a_duplicate_that_stays_open_is_not_labelled() -> None:
    primary = _issue(due_in=timedelta(days=1))
    issue = _issue(due_in=-timedelta(days=1), number=9, vuln_id="GHSA-aaaa-bbbb-cccc")
    findings = (_finding(CVE, aliases=("GHSA-aaaa-bbbb-cccc",)),)
    plan = planner.plan(_inputs(findings, (primary, issue)))
    assert (REPO, 9, "GHSA-aaaa-bbbb-cccc") in plan.duplicate_issues
    assert all(not (a.add_labels or a.remove_labels) for a in plan.actions if a.number == 9)


def test_a_repository_that_was_not_fetched_is_not_labelled() -> None:
    issue = _issue(due_in=-timedelta(days=1))
    plan = planner.plan(_inputs((), (issue,), fetch_ok=()))
    assert plan.actions == ()


def test_a_second_plan_after_applying_the_first_is_empty() -> None:
    issue = _issue(due_in=-timedelta(hours=1))
    first_inputs = _inputs((_finding(CVE),), (issue,))
    first = planner.plan(first_inputs)
    store = fake.IssueStore.from_managed(first_inputs.issues)
    for action in first.actions:
        store = store.apply_action(action)
    second_inputs = replace(first_inputs, issues=fake.to_managed_issues(store, issue_body.parse_state))
    assert planner.plan(second_inputs).actions == ()
    assert LABEL in second_inputs.issues[0].labels


def test_a_reopen_whose_new_due_time_is_in_the_future_drops_the_label() -> None:
    issue = _issue(due_in=-timedelta(days=30), state="closed", labels=frozenset({LABEL}))
    issue = replace(issue, closed_at=NOW - timedelta(days=20))
    plan = planner.plan(_inputs((_finding(CVE),), (issue,)))
    reopen = next(a for a in plan.actions if a.op == "reopen")
    assert reopen.remove_labels == (LABEL,) and reopen.add_labels == ()


@pytest.mark.parametrize("hours", [-5000, -1, 1, 5000])
def test_the_label_matches_the_due_time_for_any_offset(hours: int) -> None:
    issue = _issue(due_in=timedelta(hours=hours))
    plan = planner.plan(_inputs((_finding(CVE),), (issue,)))
    assert bool(_label_ops(plan)) is (hours < 0)


@settings(max_examples=100, deadline=None)
@given(hours=st.integers(-2000, 2000), has=st.booleans())
def test_applying_the_plan_twice_changes_nothing_more(hours: int, has: bool) -> None:
    labels = frozenset({LABEL}) if has else frozenset()
    issue = _issue(due_in=timedelta(hours=hours), labels=labels)
    inputs = _inputs((_finding(CVE),), (issue,))
    store = fake.IssueStore.from_managed(inputs.issues)
    for action in planner.plan(inputs).actions:
        store = store.apply_action(action)
    after = replace(inputs, issues=fake.to_managed_issues(store, issue_body.parse_state))
    assert planner.plan(after).actions == ()
    assert (LABEL in after.issues[0].labels) is (hours < 0)

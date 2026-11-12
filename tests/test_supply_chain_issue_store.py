"""Self-checks for ``tests/fakes/issue_store.py`` (task 9.1)."""

from __future__ import annotations

from typing import Any

import hypothesis.strategies as st
import pytest
from hypothesis import HealthCheck, given, settings
from supply_chain.models import IssueAction, ManagedIssue, Plan, Repo

from tests.fakes import issue_store as fake
from tests.strategies import supply_chain as sc

REPO = Repo("example-org", "svc-api-0")
OTHER = Repo("sample-team", "svc-core-2")


def _action(op: str, number: int | None = None, vuln: str | None = "CVE-2026-00001", **kw: Any) -> IssueAction:
    kind = "finding" if vuln is not None else "summary"
    base: dict[str, Any] = {
        "op": op,
        "repo": REPO,
        "kind": kind,
        "vuln_id": vuln,
        "number": number,
        "body": f"body of {op}",
        "close_reason": None,
    }
    base.update(kw)
    return IssueAction(**base)


def _plan(*actions: IssueAction) -> Plan:
    return Plan(actions, (), (), (), (), {}, ())


def test_create_numbers_after_the_highest_and_may_duplicate() -> None:
    start = fake.IssueStore.from_managed([ManagedIssue(REPO, 7, "finding", "CVE-2026-00001", "closed", None)])
    after = fake.apply(start, _plan(_action("create"), _action("create")))
    assert [i.number for i in after.issues] == [7, 8, 9]
    assert len(after.find(REPO, "finding", "CVE-2026-00001")) == 3  # GitHub does not deduplicate
    assert [i.state for i in after.issues] == ["closed", "open", "open"]
    assert len(start.issues) == 1  # the input store is unchanged


def test_create_in_an_empty_store_starts_at_one() -> None:
    assert fake.apply(fake.IssueStore(), [_action("create", vuln=None)]).issues[0].number == 1


def test_update_replaces_the_body_and_forgets_the_old_state_block() -> None:
    start = fake.IssueStore.from_managed([ManagedIssue(REPO, 1, "finding", "CVE-2026-00001", "open", {"k": 1})])
    after = fake.apply(start, [_action("update", 1)])
    assert after.issues[0].body == "body of update" and after.issues[0].body_state is None
    assert fake.to_managed_issues(after)[0].body_state is None
    parsed = fake.to_managed_issues(after, parse_body=lambda body: {"parsed": body})
    assert parsed[0].body_state == {"parsed": "body of update"}
    assert fake.to_managed_issues(start)[0].body_state == {"k": 1}


def test_close_records_the_reason_and_reopen_clears_it() -> None:
    start = fake.IssueStore.from_managed([ManagedIssue(REPO, 1, "finding", "CVE-2026-00001", "open", None)])
    closed = fake.apply(start, [_action("close", 1, close_reason="withdrawn")])
    assert (closed.issues[0].state, closed.issues[0].close_reason) == ("closed", "withdrawn")
    again = fake.apply(closed, [_action("close", 1, close_reason="resolved")])
    assert again.issues[0].state == "closed"
    reopened = fake.apply(again, [_action("reopen", 1)])
    assert (reopened.issues[0].state, reopened.issues[0].close_reason) == ("open", None)
    assert fake.apply(reopened, [_action("reopen", 1)]).issues == reopened.issues


@pytest.mark.parametrize("op", ["update", "close", "reopen"])
def test_acting_on_a_missing_issue_raises_not_found(op: str) -> None:
    with pytest.raises(fake.IssueNotFoundError):
        fake.apply(fake.IssueStore(), [_action(op, 3)])
    other_repo = fake.IssueStore.from_managed([ManagedIssue(OTHER, 3, "finding", "CVE-2026-00001", "open", None)])
    with pytest.raises(fake.IssueNotFoundError):
        fake.apply(other_repo, [_action(op, 3)])  # the number exists, but in another repository


def test_a_number_is_required_for_update_close_and_reopen() -> None:
    with pytest.raises(ValueError, match="needs an issue number"):
        fake.apply(fake.IssueStore(), [_action("close", None)])


def test_find_filters_by_each_marker_field() -> None:
    managed = [
        ManagedIssue(REPO, 1, "finding", "CVE-2026-00001", "open", None),
        ManagedIssue(REPO, 2, "finding", "MAL-2026-0001", "closed", None),
        ManagedIssue(OTHER, 3, "summary", None, "open", None),
    ]
    store = fake.IssueStore.from_managed(managed)
    assert [i.number for i in store.find(repo=REPO)] == [1, 2]
    assert [i.number for i in store.find(kind="summary")] == [3]
    assert [i.number for i in store.find(vuln_id="MAL-2026-0001")] == [2]
    assert [i.number for i in store.find(state="open")] == [1, 3]
    assert [i.number for i in store.find(Repo("EXAMPLE-ORG", "SVC-API-0"), "finding", "CVE-2026-00001")] == [1]
    assert store.find(REPO, "failure") == ()
    assert fake.to_managed_issues(store) == tuple(managed)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.data())
def test_apply_subset_equals_applying_the_chosen_actions(data: st.DataObject) -> None:
    issues = data.draw(sc.managed_issues(max_size=20))
    ops = data.draw(
        st.lists(st.tuples(st.sampled_from(["update", "close", "reopen"]), st.integers(0, 40)), max_size=12)
    )
    actions = [
        _action(
            op,
            issues[n % len(issues)].number,
            repo=issues[n % len(issues)].repo,
            close_reason="resolved" if op == "close" else None,
        )
        for op, n in ops
        if issues
    ]
    actions += [_action("create", vuln=f"CVE-2026-{n:05d}") for n in range(data.draw(st.integers(0, 3)))]
    chosen = data.draw(st.sets(st.integers(0, max(len(actions) - 1, 0))))
    store = fake.IssueStore.from_managed(issues)
    expected = fake.apply(store, [a for i, a in enumerate(actions) if i in chosen])
    assert fake.apply_subset(store, _plan(*actions), chosen) == expected
    assert fake.apply_subset(store, actions, set(range(len(actions)))) == fake.apply(store, actions)
    assert fake.apply_subset(store, actions, set()) == store
    assert fake.apply_subset(store, actions, {len(actions) + 5}) == store  # out-of-range positions are ignored

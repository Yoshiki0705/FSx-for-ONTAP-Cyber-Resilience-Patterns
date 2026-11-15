"""KEV ``dueDate`` and ``forensicTriage`` are shown in the Issue and decide nothing (task 9.24, Requirement 8.19)."""

from __future__ import annotations

from datetime import date

from hypothesis import given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner

from tests.test_supply_chain_issue_body import _fi
from tests.test_supply_chain_planner import _feeds, _finding, _inputs

CVE = "CVE-2026-0001"
_DUE = date(2026, 11, 16)


def _shown(kev: object) -> tuple[str, dict[str, object]]:
    body = issue_body.render_finding(_fi(kev=kev))
    state = issue_body.parse_state(body)
    assert state is not None
    return body, state


def test_due_date_and_forensic_triage_are_shown_in_the_table_and_the_state_block() -> None:
    kev = models.KevEntry(date(2026, 11, 13), None, _DUE, True)
    body, state = _shown(kev)
    assert "KEV の dueDate（表示のみ） | 2026-11-16" in body
    assert "KEV の forensicTriage（表示のみ） | Yes" in body
    assert state["kev"] == {
        "date_added": "2026-11-13",
        "known_ransomware_campaign_use": None,
        "due_date": "2026-11-16",
        "forensic_triage": True,
    }


def test_forensic_triage_no_is_shown_as_no() -> None:
    body, state = _shown(models.KevEntry(date(2026, 11, 13), False, _DUE, False))
    assert "KEV の forensicTriage（表示のみ） | No" in body
    assert state["kev"]["forensic_triage"] is False  # type: ignore[index]


def test_a_missing_entry_shows_unknown() -> None:
    body, state = _shown(models.KevEntry(date(2026, 11, 13), None))
    assert "KEV の dueDate（表示のみ） | 不明" in body
    assert "KEV の forensicTriage（表示のみ） | 不明" in body
    assert state["kev"]["due_date"] is None and state["kev"]["forensic_triage"] is None  # type: ignore[index]


def test_a_plain_two_item_value_still_renders_and_shows_unknown() -> None:
    body, state = _shown((date(2026, 11, 13), True))
    assert "KEV の dueDate（表示のみ） | 不明" in body
    assert state["kev"]["due_date"] is None  # type: ignore[index]


def test_not_listed_shows_not_applicable() -> None:
    body, state = _shown(None)
    assert "KEV の dueDate（表示のみ） | 該当なし（KEV 掲載なし）" in body
    assert state["kev"] is None


def test_the_planner_writes_the_two_items_into_the_issue_it_creates() -> None:
    feeds = _feeds(kev={CVE: models.KevEntry(date(2026, 11, 9), None, _DUE, True)})
    plan = planner.plan(_inputs((_finding(CVE, "HIGH"),), feeds=feeds))
    state = issue_body.parse_state(plan.actions[0].body)
    assert state is not None and state["kev"]["due_date"] == "2026-11-16"  # type: ignore[index]


_entries = st.builds(
    models.KevEntry,
    st.dates(min_value=date(2026, 11, 1), max_value=date(2026, 11, 9)),
    st.sampled_from([None, True, False]),
    st.one_of(st.none(), st.dates(min_value=date(2026, 11, 1), max_value=date(2027, 1, 1))),
    st.sampled_from([None, True, False]),
)


@settings(max_examples=100, deadline=None)
@given(entry=_entries, due=st.dates(), triage=st.sampled_from([None, True, False]))
def test_the_two_items_do_not_change_which_issues_are_opened_or_closed(
    entry: models.KevEntry, due: date, triage: bool | None
) -> None:
    """Property 5 (display only): the operations are those of the same entry without the two items."""
    findings = (_finding(CVE, "LOW"), _finding("CVE-2026-0002", "HIGH"))
    kev_ids = (CVE, "CVE-2026-0002")
    bare = {i: models.KevEntry(entry.date_added, entry.known_ransomware) for i in kev_ids}
    rich = {i: models.KevEntry(entry.date_added, entry.known_ransomware, due, triage) for i in kev_ids}
    a = planner.plan(_inputs(findings, feeds=_feeds(kev=bare)))
    b = planner.plan(_inputs(findings, feeds=_feeds(kev=rich)))
    key = lambda p: [(x.op, x.repo, x.kind, x.vuln_id, x.number, x.close_reason) for x in p.actions]  # noqa: E731
    assert key(a) == key(b)
    assert a.below_threshold == b.below_threshold and a.unscored == b.unscored

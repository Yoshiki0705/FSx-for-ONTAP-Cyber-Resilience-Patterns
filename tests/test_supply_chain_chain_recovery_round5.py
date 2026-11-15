"""Round-5 regressions for chain recovery (T12-R4-03, T12-R4-04)."""

from __future__ import annotations

import pytest
from supply_chain import chain_recovery as cr
from supply_chain import run_record as rr

from tests.test_supply_chain_chain_recovery import forked, ledger


# ---- T12-R4-03: one tip of a forked month must stay in the chain
def test_abandoning_both_tips_of_a_forked_month_is_refused() -> None:
    entries, _a, b, c = forked()
    first = cr.isolate(entries, ledger(), abandon=rr.sha256_text(b[1]), decision="Issue 1")
    with pytest.raises(cr.LedgerError, match="every tip"):
        cr.isolate(entries, first, abandon=rr.sha256_text(c[1]), decision="Issue 2")


def test_a_ledger_that_abandons_every_tip_is_a_problem_not_a_clean_month() -> None:
    entries, _a, b, c = forked()
    both = [
        cr.AcceptedFork("2026-11", rr.sha256_text(b[1]), "Issue 1"),
        cr.AcceptedFork("2026-11", rr.sha256_text(c[1]), "Issue 2"),
    ]
    _kept, problems = cr.effective_entries(entries, both)
    assert any("every tip" in p for p in problems)
    result = cr.reconnect(entries, both, "2026-11")
    assert result.problems


@pytest.mark.parametrize("decision", ["xyz", "ok ok", "done", "Issue", "Issue abc", "see chat", "#12"])
def test_a_decision_must_name_an_issue_or_a_pull_request(decision: str) -> None:
    text = cr.render_ledger([cr.AcceptedFork("2026-11", "0" * 64, decision)])
    with pytest.raises(cr.LedgerError, match="decision"):
        cr.parse_ledger(text)


@pytest.mark.parametrize(
    "decision",
    [
        "Issue 123",
        "Issue #123",
        "PR #45",
        "https://github.com/example-org/example-repo/issues/12",
        "https://github.com/example-org/example-repo/pull/12",
    ],
)
def test_the_accepted_decision_forms(decision: str) -> None:
    text = cr.render_ledger([cr.AcceptedFork("2026-11", "0" * 64, decision)])
    assert cr.parse_ledger(text)[0].decision == decision


# ---- T12-R4-04: the tip an Aggregator recorded may be one that was abandoned afterwards
def test_a_recorded_tip_that_was_abandoned_is_not_a_change_of_the_tip() -> None:
    entries, _a, b, c = forked()
    abandoned = rr.sha256_text(c[1])
    accepted = cr.parse_ledger(cr.isolate(entries, ledger(), abandon=abandoned, decision="Issue 1"))
    kept, _ = cr.effective_entries(entries, accepted)
    # the losing writer remembered the record that was later abandoned
    assert rr.verify_month_tip("2026-11", kept, abandoned) is not None
    assert rr.verify_month_tip("2026-11", kept, abandoned, abandoned=frozenset({abandoned})) is None
    assert rr.verify_month_tip("2026-11", entries, abandoned) is None  # all records: found


def test_an_abandoned_value_does_not_hide_an_edit_of_another_tip() -> None:
    entries, _a, b, c = forked()
    abandoned = frozenset({rr.sha256_text(c[1])})
    assert rr.verify_month_tip("2026-11", [entries[0]], rr.sha256_text(b[1]), abandoned=abandoned) is not None


# ---- T12-R5-07: the first write after a recovery is still checked
def _recovered() -> tuple[list[tuple[str, str]], str, tuple[str, str]]:
    entries, _a, b, c = forked()
    abandoned = rr.sha256_text(c[1])
    accepted = cr.parse_ledger(cr.isolate(entries, ledger(), abandon=abandoned, decision="Issue 1"))
    kept, _ = cr.effective_entries(entries, accepted)
    return kept, abandoned, b


def test_an_edited_kept_tip_is_found_when_the_recorded_value_was_abandoned() -> None:
    kept, abandoned, b = _recovered()
    kept_sha = rr.sha256_text(b[1])
    assert (
        rr.verify_month_tip("2026-11", kept, abandoned, abandoned=frozenset({abandoned}), kept_tip_sha256=kept_sha)
        is None
    )
    edited = [(p, t.replace('"run_id": "2-1"', '"run_id": "2-9"')) if p == b[0] else (p, t) for p, t in kept]
    assert edited != kept  # the control: the text really changed
    found = rr.verify_month_tip(
        "2026-11", edited, abandoned, abandoned=frozenset({abandoned}), kept_tip_sha256=kept_sha
    )
    assert found is not None and found.reason == "tip_changed"


def test_a_month_without_one_live_tip_is_not_passed_by_an_abandoned_value() -> None:
    entries, _a, _b, c = forked()
    abandoned = frozenset({rr.sha256_text(c[1])})
    # no record at all
    found = rr.verify_month_tip("2026-11", [], rr.sha256_text(c[1]), abandoned=abandoned)
    assert found is not None and found.reason == "tip_changed"
    # two live tips
    two = rr.verify_month_tip("2026-11", entries, "f" * 64, abandoned=frozenset({"f" * 64}))
    assert two is not None and two.reason == "tip_changed"

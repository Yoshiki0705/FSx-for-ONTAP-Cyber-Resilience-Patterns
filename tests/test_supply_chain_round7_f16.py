"""Round 7 (F16): the restart rule of the low-sample pilot, the zero-Issue case, and the alias-only record."""

from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st
from supply_chain import metrics, planner

from tests.test_supply_chain_planner import REPO, _finding, _inputs, _vex

T0 = datetime(2026, 11, 1, tzinfo=UTC)


def _out(status: str | None, justification: str | None = None, **kw: object) -> metrics.PilotIssueOutcome:
    return metrics.PilotIssueOutcome(status, justification, **kw)  # type: ignore[arg-type]


def _review(items: list[metrics.PilotIssueOutcome], **kw: object) -> metrics.LowSampleReview:
    return metrics.review_low_sample(metrics.compute_pilot_rates(items, **kw))  # type: ignore[arg-type]


# ---- T12-R6-02: no Issue is not a satisfied condition
def test_zero_issues_do_not_satisfy_the_next_batch_conditions() -> None:
    review = _review([])
    assert review.applies and review.issued == 0
    assert review.next_batch_conditions_hold is False


def test_one_fixed_issue_still_satisfies_them() -> None:
    assert _review([_out("fixed")]).next_batch_conditions_hold is True


# ---- T3-R6-01: the way out of "does not proceed"
def test_causes_of_a_stop_are_named() -> None:
    assert _review([_out("fixed")] * 3).restart_causes == ()
    assert _review([_out(None, detector_error=True)] * 2 + [_out("fixed")]).restart_causes == ("errors_majority",)
    assert _review([_out(None, detector_error=True)] * 3 + [_out("fixed")] * 7).restart_causes == ("errors_over_limit",)
    assert _review([_out(None, detector_error=True)] * 4 + [_out("fixed")] * 4).restart_causes == (
        "errors_over_limit",
        "errors_majority",
    )


def test_a_restart_can_start_exactly_when_a_cause_exists() -> None:
    assert _review([_out(None, detector_error=True), _out("fixed"), _out("fixed")]).can_restart_observation is False
    assert _review([_out(None, detector_error=True), _out("fixed")]).can_restart_observation is True


def test_causes_are_empty_outside_the_low_sample_rule() -> None:
    review = _review([_out(None, detector_error=True)] * 20)
    assert review.applies is False and review.restart_causes == () and review.can_restart_observation is False


@given(
    st.lists(
        st.builds(
            metrics.PilotIssueOutcome,
            st.sampled_from([None, "not_affected", "fixed", "affected"]),
            st.sampled_from([None, "component_not_present"]),
            st.booleans(),
            st.booleans(),
        ),
        max_size=19,
    )
)
def test_a_stopped_batch_always_has_a_way_out_or_a_wait(items: list[metrics.PilotIssueOutcome]) -> None:
    """Below 20 Issues: not proceeding means a restart cause, undecided Issues to wait for, or no Issue at all."""
    review = _review(items)
    if review.applies and not review.next_batch_conditions_hold:
        assert review.restart_causes or review.undecided > 0 or review.issued == 0


@pytest.mark.parametrize(
    ("done", "may", "redesign"), [(0, True, False), (2, True, False), (3, False, True), (4, False, True)]
)
def test_restarts_are_limited_to_three(done: int, may: bool, redesign: bool) -> None:
    status = metrics.observation_restart_status(done)
    assert (status.may_restart, status.redesign_required) == (may, redesign)
    assert status.remaining == max(metrics.MAX_OBSERVATION_RESTARTS - done, 0)


def test_a_negative_restart_count_is_rejected() -> None:
    with pytest.raises(ValueError):
        metrics.observation_restart_status(-1)


# ---- T3-R6-01 (3), T3-R6-02: the set of Issues that is counted
def _at(days: float, status: str | None = "fixed", **kw: object) -> metrics.PilotIssueOutcome:
    return metrics.PilotIssueOutcome(status, opened_at=T0 + timedelta(days=days), **kw)  # type: ignore[arg-type]


def test_after_a_restart_only_issues_opened_since_the_restart_are_counted() -> None:
    items = [_at(0, None, detector_error=True), _at(1, None, detector_error=True), _at(5), _at(6)]
    rates = metrics.compute_pilot_rates(items, window_start=T0 + timedelta(days=3))
    assert (rates.issued, rates.false_positive) == (2, 0)
    assert rates.before_window == 2


def test_issues_after_the_evaluation_time_are_carried_over_not_counted_undecided() -> None:
    items = [_at(1), _at(2), _at(8, None)]
    rates = metrics.compute_pilot_rates(items, window_end=T0 + timedelta(days=7))
    assert (rates.issued, rates.undecided, rates.carried_over) == (2, 0, 1)
    assert metrics.review_low_sample(rates).next_batch_conditions_hold is True


def test_the_window_end_is_inclusive_and_the_start_too() -> None:
    items = [_at(0), _at(7)]
    rates = metrics.compute_pilot_rates(items, window_start=T0, window_end=T0 + timedelta(days=7))
    assert (rates.issued, rates.carried_over, rates.before_window) == (2, 0, 0)


def test_a_window_needs_the_opening_time_of_every_issue() -> None:
    with pytest.raises(ValueError):
        metrics.compute_pilot_rates([_out("fixed")], window_end=T0)


def test_a_window_bound_must_be_utc() -> None:
    with pytest.raises(ValueError):
        metrics.compute_pilot_rates([_at(1)], window_end=datetime(2026, 11, 8))


def test_no_window_counts_everything_as_before() -> None:
    rates = metrics.compute_pilot_rates([_out("fixed"), _out(None)])
    assert (rates.issued, rates.carried_over, rates.before_window) == (2, 0, 0)


def test_a_duplicate_outside_the_window_is_not_a_carried_over_issue() -> None:
    items = [_at(1), _at(9, None, duplicate=True)]
    rates = metrics.compute_pilot_rates(items, window_end=T0 + timedelta(days=7))
    assert rates.carried_over == 0 and rates.duplicates == 0


# ---- T3-R6-02: under_investigation is undecided, and visible as such
def test_under_investigation_is_counted_apart_inside_undecided() -> None:
    rates = metrics.compute_pilot_rates([_out("under_investigation"), _out(None), _out("fixed")])
    assert (rates.undecided, rates.under_investigation) == (2, 1)
    review = metrics.review_low_sample(rates)
    assert review.under_investigation == 1 and review.next_batch_conditions_hold is False


def test_the_record_has_no_pass_fail_field() -> None:
    names = {f.name for f in fields(metrics.LowSampleReview)}
    assert not names & {"passed", "ok", "verdict", "success"}


def test_the_counts_docstring_is_not_stale() -> None:
    assert "four counts" not in (metrics.LowSampleReview.__doc__ or "")
    assert "four counts" not in (metrics.review_low_sample.__doc__ or "")


# ---- T12-R6-04: the alias-only record belongs to an Issue-opening Finding
GHSA = "GHSA-aaaa-bbbb-cccc"
CVE = "CVE-2026-0001"


def _plan(severity: str):
    return planner.plan(
        _inputs((_finding(CVE, severity, aliases=(GHSA,)),), vex={REPO: (_vex("not_affected", GHSA),)})  # type: ignore[arg-type]
    )


def test_a_finding_below_the_opening_threshold_has_no_alias_only_record() -> None:
    plan = _plan("LOW")
    assert plan.actions == () and plan.vex_name_only_ghsa == () and plan.rejected_vex == ()


def test_a_finding_that_opens_an_issue_keeps_the_record() -> None:
    plan = _plan("HIGH")
    assert len(plan.vex_name_only_ghsa) == 1 and len(plan.rejected_vex) == 1


# ---- F16-N1 (found by the property test of Property 9): the KEV date of 11.15 d is read for every identifier
def test_a_kev_listing_of_an_alias_after_the_judgment_stops_the_exclusion() -> None:
    """The primary id was listed before the judgment, an alias after it: the statement has to be reviewed again."""
    from supply_chain import models  # noqa: PLC0415

    from tests.test_supply_chain_planner import NOW  # noqa: PLC0415

    judged = _vex("not_affected", CVE)
    at = judged.statements[0].timestamp or judged.timestamp
    assert at is not None
    kev = {CVE: ((at - timedelta(days=200)).date(), None), GHSA: ((at + timedelta(days=1)).date(), False)}
    inputs = _inputs(
        (_finding(CVE, "HIGH", aliases=(GHSA,)),),
        vex={REPO: (judged,)},
        feeds=models.FeedSnapshot(kev, None, None, {}, frozenset(), frozenset()),
        now=NOW + timedelta(days=2),
    )
    plan = planner.plan(inputs)
    assert plan.vex_exclusions == ()
    assert [a.op for a in plan.actions] == ["create"]

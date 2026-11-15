"""Round-5 regressions for the pilot counts (T3-R4-01, T3-R4-02, T12-R4-02, T12-R4-08)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from supply_chain import metrics

_STATUSES = [None, "not_affected", "affected", "fixed", "under_investigation"]
_JUSTIFICATIONS = [None, "component_not_present", "vulnerable_code_not_in_execute_path"]


def _out(status: str | None, justification: str | None = None, **kw: bool) -> metrics.PilotIssueOutcome:
    return metrics.PilotIssueOutcome(status, justification, **kw)


outcomes = st.builds(
    metrics.PilotIssueOutcome,
    st.sampled_from(_STATUSES),
    st.sampled_from(_JUSTIFICATIONS),
    st.booleans(),
    st.booleans(),
)


# ---- T3-R4-01: 22.26, errors at half or more of the issued Issues stop the next batch
def test_two_errors_in_three_issues_is_within_the_two_error_limit_but_a_majority() -> None:
    items = [_out(None, detector_error=True)] * 2 + [_out("fixed")]
    review = metrics.review_low_sample(metrics.compute_pilot_rates(items))
    assert review.within_error_limit  # the 22.19 count alone says "may proceed"
    assert review.errors_are_majority  # 22.26 says it may not


def test_one_error_in_two_issues_is_a_majority_and_one_in_three_is_not() -> None:
    half = metrics.review_low_sample(metrics.compute_pilot_rates([_out(None, detector_error=True), _out("fixed")]))
    third = metrics.review_low_sample(
        metrics.compute_pilot_rates([_out(None, detector_error=True), _out("fixed"), _out("fixed")])
    )
    assert half.errors_are_majority and not third.errors_are_majority


def test_no_issue_is_not_a_majority() -> None:
    assert not metrics.review_low_sample(metrics.compute_pilot_rates([])).errors_are_majority


@given(st.lists(outcomes, max_size=30))
def test_errors_are_majority_iff_half_or_more_of_the_issued_issues_are_errors(items: list) -> None:
    rates = metrics.compute_pilot_rates(items)
    review = metrics.review_low_sample(rates)
    assert review.errors_are_majority == (rates.issued > 0 and 2 * rates.false_positive >= rates.issued)


# ---- T3-R4-02 / T12-R4-02: under_investigation is undecided; every Issue is counted once
def test_issues_under_investigation_count_as_undecided_and_withhold_the_rate() -> None:
    items = [_out("under_investigation")] * 15 + [_out("not_affected", "vulnerable_code_not_in_execute_path")] * 5
    rates = metrics.compute_pilot_rates(items)
    assert rates.undecided == 15
    assert rates.awaiting_decisions and rates.rate_percent is None


def test_fixed_and_affected_have_their_own_counts() -> None:
    rates = metrics.compute_pilot_rates([_out("fixed")] * 3 + [_out("affected")] * 2 + [_out(None)], min_issues=1)
    assert (rates.fixed, rates.affected, rates.undecided) == (3, 2, 1)


def test_a_detector_error_is_counted_once_whatever_the_status() -> None:
    items = [_out("fixed", detector_error=True), _out("affected", detector_error=True)]
    rates = metrics.compute_pilot_rates(items, min_issues=1)
    assert (rates.false_positive, rates.fixed, rates.affected) == (2, 0, 0)


@given(st.lists(outcomes, max_size=40))
def test_issued_is_the_sum_of_the_counts(items: list) -> None:
    rates = metrics.compute_pilot_rates(items)
    total = rates.false_positive + rates.not_affected_other + rates.fixed + rates.affected + rates.undecided
    assert rates.issued == total
    assert rates.issued + rates.duplicates == len(items)


# ---- T12-R4-08: duplicate-side Issues are not in the denominator
def test_duplicate_issues_leave_the_denominator_and_the_undecided_count() -> None:
    items = [_out("fixed")] * 20 + [_out(None, duplicate=True)] * 10
    rates = metrics.compute_pilot_rates(items)
    assert (rates.issued, rates.undecided, rates.duplicates) == (20, 0, 10)
    assert rates.rate_percent == 0.0 and not rates.awaiting_decisions


@pytest.mark.parametrize("status", _STATUSES)
def test_a_duplicate_is_never_counted_whatever_its_status(status: str | None) -> None:
    rates = metrics.compute_pilot_rates([_out(status, duplicate=True)], min_issues=1)
    assert rates.issued == 0 and rates.duplicates == 1


# ---- T3-R5-01: Issues left undecided keep the 22.19 conditions from holding
def test_three_undecided_issues_do_not_satisfy_the_low_sample_conditions() -> None:
    review = metrics.review_low_sample(metrics.compute_pilot_rates([_out("under_investigation")] * 3))
    assert review.applies and review.within_error_limit and not review.errors_are_majority
    assert review.undecided == 3
    assert not review.next_batch_conditions_hold


def test_the_conditions_hold_once_every_issue_is_decided_and_the_errors_are_few() -> None:
    items = [_out("fixed")] * 3
    assert metrics.review_low_sample(metrics.compute_pilot_rates(items)).next_batch_conditions_hold


def test_the_conditions_do_not_hold_for_a_majority_of_errors_or_above_the_sample() -> None:
    majority = metrics.review_low_sample(metrics.compute_pilot_rates([_out(None, detector_error=True), _out("fixed")]))
    assert not majority.next_batch_conditions_hold
    assert not metrics.review_low_sample(metrics.compute_pilot_rates([_out("fixed")] * 20)).next_batch_conditions_hold


@given(st.lists(outcomes, max_size=30))
def test_the_conditions_hold_iff_every_clause_of_22_19_holds(items: list) -> None:
    rates = metrics.compute_pilot_rates(items)
    review = metrics.review_low_sample(rates)
    assert review.next_batch_conditions_hold == (
        review.applies
        and review.issued > 0  # T12-R6-02: no Issue is not evidence
        and review.within_error_limit
        and not review.errors_are_majority
        and review.undecided == 0
    )

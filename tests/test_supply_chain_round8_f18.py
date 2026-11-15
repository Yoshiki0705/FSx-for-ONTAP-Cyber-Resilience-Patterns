"""Round 8 (F18): the exits of a 0-Issue observation and of an over-limit rate, and the window check."""
from __future__ import annotations
from datetime import UTC, datetime, timedelta
import pytest
from hypothesis import given
from hypothesis import strategies as st
from supply_chain import metrics
T0 = datetime(2026, 11, 1, tzinfo=UTC)
def _out(status: str | None, justification: str | None = None, **kw: object) -> metrics.PilotIssueOutcome:
    return metrics.PilotIssueOutcome(status, justification, **kw)  # type: ignore[arg-type]
def _review(items: list[metrics.PilotIssueOutcome], **kw: object) -> metrics.LowSampleReview:
    return metrics.review_low_sample(metrics.compute_pilot_rates(items), **kw)  # type: ignore[arg-type]
# ---- T3-R7-01
def test_zero_issues_with_extensions_left_have_no_exit_cause() -> None:
    review = _review([], extensions_exhausted=False)
    assert review.restart_causes == () and review.needs_maintainer_decision is False
def test_zero_issues_with_the_extensions_used_up_name_their_own_cause() -> None:
    review = _review([], extensions_exhausted=True)
    assert review.restart_causes == ("no_issues_after_extensions",)
    assert review.needs_maintainer_decision is True
    assert review.next_batch_conditions_hold is False  # 0 Issues are never evidence (22.52)
def test_the_default_does_not_claim_the_extensions_are_used_up() -> None:
    assert _review([]).restart_causes == ()
def test_the_exhausted_flag_does_not_matter_when_there_are_issues() -> None:
    assert _review([_out("fixed")], extensions_exhausted=True).restart_causes == ()
# ---- T3-R7-02
def _twenty(false_positives: int) -> list[metrics.PilotIssueOutcome]:
    return [_out(None, detector_error=True)] * false_positives + [_out("fixed")] * (20 - false_positives)
def test_a_rate_over_the_limit_is_a_restart_cause() -> None:
    review = _review(_twenty(8), max_rate_percent=20.0)
    assert review.applies is False
    assert review.restart_causes == ("rate_over_limit",)
    assert review.can_restart_observation is True
def test_a_rate_at_the_limit_is_not_over_it() -> None:
    assert _review(_twenty(4), max_rate_percent=20.0).restart_causes == ()
def test_without_a_limit_no_rate_cause_is_named() -> None:
    assert _review(_twenty(15)).restart_causes == ()
def test_a_withheld_rate_is_not_a_cause() -> None:
    items = [_out(None)] * 10 + [_out("fixed")] * 10
    assert _review(items, max_rate_percent=1.0).restart_causes == ()
# ---- T3-R7-07
def test_restart_is_allowed_only_within_the_count_limit() -> None:
    items = [_out(None, detector_error=True)] * 3 + [_out("fixed")] * 7
    assert _review(items).may_restart_now is True
    assert _review(items, restarts_done=2).may_restart_now is True
    review = _review(items, restarts_done=3)
    assert review.can_restart_observation is True and review.may_restart_now is False
@given(st.integers(0, 6), st.integers(0, 25), st.integers(0, 25))
def test_may_restart_now_is_the_conjunction(done: int, errors: int, others: int) -> None:
    review = _review([_out(None, detector_error=True)] * errors + [_out("fixed")] * others, restarts_done=done)
    assert review.may_restart_now == (review.can_restart_observation and done < metrics.MAX_OBSERVATION_RESTARTS)
def test_a_negative_restart_count_is_refused() -> None:
    with pytest.raises(ValueError):
        _review([], restarts_done=-1)
# ---- T12-R7-04
def test_a_window_that_ends_before_it_starts_is_refused() -> None:
    with pytest.raises(ValueError, match="window_start"):
        metrics.compute_pilot_rates([], window_start=T0 + timedelta(days=1), window_end=T0)
def test_a_window_of_one_instant_is_accepted() -> None:
    assert metrics.compute_pilot_rates([], window_start=T0, window_end=T0).issued == 0

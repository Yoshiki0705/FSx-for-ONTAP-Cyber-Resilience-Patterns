"""Tests for ``supply_chain.watchdog`` and ``supply_chain.watchdog_cli`` (task 15.5).

The design has no numbered property for the watchdog, so the two properties here
are local ones: the verdict depends only on the age, and a newer save time can
only turn a failure into a success.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import models, watchdog, watchdog_cli
from supply_chain import run_record as rr

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
SHA = "0123456789abcdef0123456789abcdef01234567"
REPO = "example-org/svc-api"
LIMIT = timedelta(hours=12)


def _record(finished_at: datetime) -> rr.RunRecord:
    started = finished_at - timedelta(minutes=4)
    return rr.RunRecord(
        run_id="123456-1", started_at=started, finished_at=finished_at,
        end_state="success", failure_reason=None, aggregator_commit=SHA, policy_commit=SHA,
        repositories=rr.Repositories((REPO,), (), {REPO: 0}),
        feeds=rr.Feeds((rr.FeedFetched("kev", started, "2026.11.09"),), ()),
        kev_fetched_on=date(2026, 11, 10), epss=rr.EpssInfo(date(2026, 11, 10), "v2025.03.14"),
        findings=(), issues=(), vex_exclusions=(), rejected_vex=(), unscored=(),
        malicious_withdrawn_unconfirmed=(), summary_overflow={}, response_metrics={},
        pull_requests=(models.PullRequestRef(models.Repo("example-org", "svc-api"), "CVE-2026-1", started, None),),
        rate_limit=rr.RateLimitRecord((), ()), failure_notice_error=None,
    )  # fmt: skip


# ------------------------------------------------------------------ is_stale


@pytest.mark.parametrize(
    ("age", "stale"),
    [
        (timedelta(0), False),
        (LIMIT - timedelta(seconds=1), False),
        (LIMIT, False),
        (LIMIT + timedelta(seconds=1), True),
        (timedelta(days=60), True),
        (timedelta(seconds=-1), False),
        (timedelta(hours=-30), False),
    ],
)
def test_boundaries(age: timedelta, stale: bool) -> None:
    """Exactly 12 hours passes, one second more fails, and a future time passes."""
    assert watchdog.is_stale(NOW - age, NOW) is stale


def test_no_record_is_stale() -> None:
    """With nothing saved the watchdog fails."""
    assert watchdog.is_stale(None, NOW) is True


def test_limit_is_a_parameter() -> None:
    """A different limit moves the boundary."""
    saved = NOW - timedelta(hours=2)
    assert watchdog.is_stale(saved, NOW, limit_hours=2) is False
    assert watchdog.is_stale(saved - timedelta(seconds=1), NOW, limit_hours=2) is True


def test_other_time_zones_compare_by_instant() -> None:
    """An offset time is compared as an instant, not as a wall clock."""
    jst = timezone(timedelta(hours=9))
    saved = (NOW - LIMIT).astimezone(jst)
    assert watchdog.is_stale(saved, NOW) is False
    assert watchdog.is_stale(saved - timedelta(seconds=1), NOW) is True


def test_naive_times_are_rejected() -> None:
    """A naive datetime is a caller error, not a silent UTC guess."""
    with pytest.raises(ValueError, match="now"):
        watchdog.is_stale(NOW, NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="latest_saved_at"):
        watchdog.is_stale(NOW.replace(tzinfo=None), NOW)


# Feature: cyber-resilience-phase4-supply-chain, local property: the verdict depends only on the age
@settings(max_examples=100, deadline=None)
@given(
    age=st.integers(-3 * 86400, 5 * 86400),
    shift=st.integers(-(10**8), 10**8),
)
def test_shifting_now_does_not_change_the_verdict(age: int, shift: int) -> None:
    """**Validates: Requirements 25.6** - moving ``now`` and the save time together keeps the verdict."""
    saved = NOW - timedelta(seconds=age)
    verdict = watchdog.is_stale(saved, NOW)
    event(f"stale={verdict}")
    event(f"age_band={'future' if age < 0 else 'over' if age > 43200 else 'within'}")
    delta = timedelta(seconds=shift)
    assert watchdog.is_stale(saved + delta, NOW + delta) is verdict
    assert verdict is (age > 43200)


# Feature: cyber-resilience-phase4-supply-chain, local property: a newer save time only turns a failure into a success
@settings(max_examples=100, deadline=None)
@given(
    older=st.integers(-86400, 5 * 86400),
    gain=st.integers(0, 5 * 86400),
    limit_hours=st.sampled_from([1, 6, 12, 24]),
)
def test_a_newer_save_time_never_turns_success_into_failure(older: int, gain: int, limit_hours: int) -> None:
    """**Validates: Requirements 25.6** - if the older time passes, the newer time passes too."""
    saved_old = NOW - timedelta(seconds=older)
    saved_new = saved_old + timedelta(seconds=gain)
    stale_old = watchdog.is_stale(saved_old, NOW, limit_hours)
    stale_new = watchdog.is_stale(saved_new, NOW, limit_hours)
    event(f"old_stale={stale_old}")
    event(f"new_stale={stale_new}")
    event(f"gain_zero={gain == 0}")
    assert not (stale_new and not stale_old)
    if gain == 0:
        assert stale_new == stale_old


# ------------------------------------------------------------ latest / check


def test_latest_saved_at_takes_the_newest_finish_time() -> None:
    """The newest ``finished_at`` wins, whatever the order of the texts."""
    times = [NOW - timedelta(hours=h) for h in (30, 3, 20)]
    texts = [rr.to_json(_record(t)) for t in times]
    assert watchdog.latest_saved_at(texts) == (NOW - timedelta(hours=3), 0)
    assert watchdog.latest_saved_at(reversed(texts)) == (NOW - timedelta(hours=3), 0)


def test_unparsable_texts_are_counted_and_never_count_as_alive() -> None:
    """A broken file does not refresh the clock; only the readable record does."""
    good = rr.to_json(_record(NOW - timedelta(hours=20)))
    assert watchdog.latest_saved_at(["not json", "{}", good]) == (NOW - timedelta(hours=20), 2)
    assert watchdog.latest_saved_at(["not json"]) == (None, 1)
    assert watchdog.latest_saved_at([]) == (None, 0)


def test_check_combines_the_pieces() -> None:
    """Fresh, stale, only-broken and empty inputs give the expected result."""
    fresh = rr.to_json(_record(NOW - LIMIT))
    old = rr.to_json(_record(NOW - LIMIT - timedelta(seconds=1)))
    assert watchdog.check([fresh], NOW) == watchdog.WatchdogResult(False, NOW - LIMIT, 0)
    assert watchdog.check([old], NOW).stale is True
    assert watchdog.check([old, fresh], NOW).stale is False
    assert watchdog.check(["junk"], NOW) == watchdog.WatchdogResult(True, None, 1)
    assert watchdog.check([], NOW) == watchdog.WatchdogResult(True, None, 0)


# ---------------------------------------------------------------------- CLI


def _write(runs: Path, finished_at: datetime, name: str = "123456-1") -> None:
    path = runs / f"{finished_at:%Y}" / f"{finished_at:%m}" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rr.to_json(_record(finished_at)), encoding="utf-8")


def test_cli_exit_codes(tmp_path: Path) -> None:
    """0 for a fresh record, 1 for an old one, a missing directory and an empty one."""
    args = ["--runs-dir", str(tmp_path / "runs")]
    assert watchdog_cli.main(args, NOW) == 1  # directory absent
    (tmp_path / "runs").mkdir()
    assert watchdog_cli.main(args, NOW) == 1  # empty
    _write(tmp_path / "runs", NOW - LIMIT - timedelta(seconds=1), "1-1")
    assert watchdog_cli.main(args, NOW) == 1  # old only
    _write(tmp_path / "runs", NOW - LIMIT, "2-1")
    assert watchdog_cli.main(args, NOW) == 0  # fresh one added
    assert watchdog_cli.main([*args, "--limit-hours", "1"], NOW) == 1


def test_cli_reads_nested_files_only_with_json_suffix(tmp_path: Path) -> None:
    """Non-JSON files are ignored; nested directories are scanned."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1))
    (runs / "2026" / "11" / "README.md").write_text("x", encoding="utf-8")
    assert len(watchdog_cli.read_record_texts(runs)) == 1

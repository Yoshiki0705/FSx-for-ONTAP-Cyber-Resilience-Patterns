"""Tests for ``supply_chain.watchdog`` and ``supply_chain.watchdog_cli`` (task 15.5).

The design has no numbered property for the watchdog, so the properties here
are local ones: the verdict depends only on the age, a newer save time can
only turn a failure into a success, and a record dated in the future never
counts as a sign of life.
"""

from __future__ import annotations

import dataclasses
import json
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
LIMIT = timedelta(hours=watchdog.DEFAULT_LIMIT_HOURS)
LIMIT_SECONDS = int(LIMIT.total_seconds())


def _record(finished_at: datetime, end_state: rr.EndState = "success") -> rr.RunRecord:
    started = finished_at - timedelta(minutes=4)
    return rr.RunRecord(
        run_id="123456-1", started_at=started, finished_at=finished_at,
        end_state=end_state, failure_reason=None if end_state == "success" else "feed unreachable", aggregator_commit=SHA, policy_commit=SHA,
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
    """Exactly the limit passes, one second more fails, and a future time passes."""
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
    event(f"age_band={'future' if age < 0 else 'over' if age > LIMIT_SECONDS else 'within'}")
    delta = timedelta(seconds=shift)
    assert watchdog.is_stale(saved + delta, NOW + delta) is verdict
    assert verdict is (age > LIMIT_SECONDS)


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


def _write(runs: Path, finished_at: datetime, name: str = "123456-1", end_state: rr.EndState = "success") -> None:
    path = runs / f"{finished_at:%Y}" / f"{finished_at:%m}" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    month = [p.read_text(encoding="utf-8") for p in path.parent.glob("*.json")]
    record = dataclasses.replace(
        _record(finished_at, end_state), run_id=name, prev_record_sha256=rr.previous_record_sha256(month)
    )
    path.write_text(rr.to_json(record), encoding="utf-8")


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


# ----------------------------------------------- threshold (T3-07, Requirement 25.6)
def test_default_limit_is_the_cron_interval_plus_slack() -> None:
    """6 h between Aggregator runs plus 2 h of ``schedule`` delay: one missed run alone is not enough to fail."""
    assert watchdog.DEFAULT_LIMIT_HOURS == 8
    # one Aggregator run missed: the previous record is 12 h old at the next check -> stale
    assert watchdog.is_stale(NOW - timedelta(hours=12), NOW) is True
    # a run that is only late by under 2 h is not
    assert watchdog.is_stale(NOW - timedelta(hours=7, minutes=59), NOW) is False


# ----------------------------------------- future-dated records (T3-14, Requirement 25.6)
def test_a_record_dated_in_the_future_is_invalid_and_never_a_sign_of_life() -> None:
    """One bad clock must not switch the watchdog off."""
    old = rr.to_json(_record(NOW - timedelta(days=3)))
    future = rr.to_json(_record(NOW + timedelta(days=1)))
    newest, invalid = watchdog.latest_saved_at([old, future], now=NOW)
    assert newest == NOW - timedelta(days=3)
    assert invalid == 1
    result = watchdog.check([old, future], NOW)
    assert result.stale is True
    assert result.invalid_records == 1


def test_future_tolerance_is_five_minutes() -> None:
    """A clock skew up to 5 minutes is accepted; one second more is invalid."""
    inside = rr.to_json(_record(NOW + timedelta(minutes=5)))
    outside = rr.to_json(_record(NOW + timedelta(minutes=5, seconds=1)))
    assert watchdog.latest_saved_at([inside], now=NOW) == (NOW + timedelta(minutes=5), 0)
    assert watchdog.latest_saved_at([outside], now=NOW) == (None, 1)


# Feature: cyber-resilience-phase4-supply-chain, local property: a future-dated record cannot keep a stale watchdog quiet
@settings(max_examples=100, deadline=None)
@given(
    old_age=st.integers(LIMIT_SECONDS + 1, 90 * 86400),
    ahead=st.integers(5 * 60 + 1, 30 * 86400),
    extra=st.integers(0, 3),
)
def test_future_records_never_make_a_stale_check_fresh(old_age: int, ahead: int, extra: int) -> None:
    """**Validates: Requirements 25.6** - adding records dated after ``now`` + 5 min leaves a stale check stale."""
    texts = [rr.to_json(_record(NOW - timedelta(seconds=old_age)))]
    texts += [rr.to_json(_record(NOW + timedelta(seconds=ahead + i))) for i in range(extra + 1)]
    result = watchdog.check(texts, NOW)
    event(f"future_records={extra + 1}")
    assert result.stale is True
    assert result.invalid_records == extra + 1


# ---------------------------------------- failing runs are not a sign of life (T3-07)
def _texts(*states_newest_first: rr.EndState) -> list[str]:
    return [rr.to_json(_record(NOW - timedelta(hours=i + 1), state)) for i, state in enumerate(states_newest_first)]


def test_consecutive_failures_count_from_the_newest_record() -> None:
    """The streak is the number of failed runs at the head; a success ends it."""
    assert watchdog.check(_texts("failure", "failure", "success"), NOW).consecutive_failures == 2
    assert watchdog.check(_texts("success", "failure", "failure"), NOW).consecutive_failures == 0
    assert watchdog.check(_texts("failure", "success", "failure"), NOW).consecutive_failures == 1
    assert watchdog.check([], NOW).consecutive_failures == 0


def test_failing_streak_is_unhealthy_even_when_the_records_are_fresh() -> None:
    """A run that ends in failure every time saves a record every time; that is not alive."""
    streak = watchdog.check(_texts(*(["failure"] * run_record_threshold())), NOW)
    assert streak.stale is False
    assert streak.failing is True
    assert watchdog.check(_texts("failure", "success"), NOW).failing is False


def run_record_threshold() -> int:
    """The streak at which the Aggregator itself opens a failure notice."""
    return rr.FAILURE_STREAK_THRESHOLD


def test_failure_limit_is_a_parameter() -> None:
    """A different limit moves the boundary."""
    texts = _texts("failure", "failure", "failure", "success")
    assert watchdog.check(texts, NOW, failure_limit=3).failing is True
    assert watchdog.check(texts, NOW, failure_limit=4).failing is False


# Feature: cyber-resilience-phase4-supply-chain, local property: the streak never exceeds the number of records
@settings(max_examples=100, deadline=None)
@given(states=st.lists(st.sampled_from(["success", "failure"]), max_size=8))
def test_streak_is_the_length_of_the_leading_failures(states: list[rr.EndState]) -> None:
    """**Validates: Requirements 25.6** - the streak equals the leading run of ``failure``."""
    expected = 0
    for state in states:
        if state != "failure":
            break
        expected += 1
    event(f"streak={min(expected, 3)}")
    assert watchdog.check(_texts(*states), NOW).consecutive_failures == expected


# --------------------------------- an observer outside the Aggregator's workflows (T3-02)
def _workflows(*states: str) -> str:
    return json.dumps(
        {
            "total_count": len(states),
            "workflows": [
                {"name": f"w{i}", "path": f".github/workflows/w{i}.yml", "state": s} for i, s in enumerate(states)
            ],
        }
    )


def test_workflow_states_flag_every_state_other_than_active() -> None:
    """``disabled_inactivity`` is the 60-day case; ``disabled_manually`` and ``disabled_fork`` are flagged too."""
    found = watchdog.disabled_workflows(
        _workflows("active", "disabled_inactivity", "disabled_manually", "disabled_fork")
    )
    assert found == ("w1", "w2", "w3")
    assert watchdog.disabled_workflows(_workflows("active", "active")) == ()


def test_a_deleted_workflow_is_not_a_disabled_one() -> None:
    """``deleted`` means the file is gone, which is a different problem from the schedule being switched off."""
    assert watchdog.disabled_workflows(_workflows("active", "deleted")) == ()


@pytest.mark.parametrize(
    "text", ["", "not json", "[]", "{}", '{"workflows": 3}', '{"workflows": []}', '{"workflows": [{"name": "a"}]}']
)
def test_workflow_listing_that_cannot_be_read_is_an_error(text: str) -> None:
    """An unreadable listing is never read as 'nothing is disabled'."""
    with pytest.raises(ValueError, match="workflow"):
        watchdog.disabled_workflows(text)


def test_report_has_a_verdict_and_a_due_date() -> None:
    """The report a person reads says when it was written and when the next check is due."""
    result = watchdog.check(_texts("success"), NOW)
    report = watchdog.render_report(result, (), NOW, due_hours=192)
    assert report["checked_at"] == "2026-11-10T12:00:00Z"
    assert report["next_check_due"] == "2026-11-18T12:00:00Z"
    assert report["healthy"] is True
    bad = watchdog.render_report(result, ("w1",), NOW, due_hours=192)
    assert bad["healthy"] is False
    assert bad["disabled_workflows"] == ["w1"]


def test_report_is_overdue_after_the_due_date() -> None:
    """A report nobody refreshed becomes visibly overdue, which is the dead-man's-switch for the observer."""
    report = watchdog.render_report(watchdog.check(_texts("success"), NOW), (), NOW, due_hours=24)
    assert watchdog.report_overdue(report, NOW + timedelta(hours=24)) is False
    assert watchdog.report_overdue(report, NOW + timedelta(hours=24, seconds=1)) is True
    with pytest.raises(ValueError, match="next_check_due"):
        watchdog.report_overdue({}, NOW)


def test_cli_fails_on_a_failing_streak(tmp_path: Path) -> None:
    """Fresh records that all say failure exit 1."""
    runs = tmp_path / "runs"
    for i in reversed(range(rr.FAILURE_STREAK_THRESHOLD)):  # oldest first: each record names the one before it
        _write(runs, NOW - timedelta(hours=i + 1), f"{i}-1", "failure")
    assert watchdog_cli.main(["--runs-dir", str(runs)], NOW) == 1
    _write(runs, NOW - timedelta(minutes=1), "9-1", "success")
    assert watchdog_cli.main(["--runs-dir", str(runs)], NOW) == 0


def test_cli_fails_when_a_workflow_is_disabled(tmp_path: Path) -> None:
    """``--workflows-json`` turns the 60-day case into exit 1 even when the records are fresh."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1))
    listing = tmp_path / "workflows.json"
    args = ["--runs-dir", str(runs), "--workflows-json", str(listing)]
    listing.write_text(_workflows("active", "active"), encoding="utf-8")
    assert watchdog_cli.main(args, NOW) == 0
    listing.write_text(_workflows("active", "disabled_inactivity"), encoding="utf-8")
    assert watchdog_cli.main(args, NOW) == 1
    listing.write_text("garbage", encoding="utf-8")
    assert watchdog_cli.main(args, NOW) == 1
    assert watchdog_cli.main([*args[:2], "--workflows-json", str(tmp_path / "missing.json")], NOW) == 1


def test_cli_warns_about_invalid_records_without_changing_the_exit_code(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Invalid records are printed as a warning line; the verdict still comes from the valid ones."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1))
    (runs / "bad.json").write_text("{}", encoding="utf-8")
    assert watchdog_cli.main(["--runs-dir", str(runs)], NOW) == 0
    assert any(r.levelname == "WARNING" for r in caplog.records)


def test_cli_writes_the_report_file(tmp_path: Path) -> None:
    """``--report-file`` leaves the JSON a person can read, with the next due date."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1))
    out = tmp_path / "report.json"
    assert watchdog_cli.main(["--runs-dir", str(runs), "--report-file", str(out)], NOW) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["healthy"] is True
    assert report["next_check_due"] == "2026-11-18T12:00:00Z"
    # the report is written for a failing check too
    empty = tmp_path / "empty"
    empty.mkdir()
    assert watchdog_cli.main(["--runs-dir", str(empty), "--report-file", str(out)], NOW) == 1
    assert json.loads(out.read_text(encoding="utf-8"))["healthy"] is False


# ---------------------------------------------------------- record chain (T4-11)


def test_a_chain_that_holds_is_healthy(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    for hours, name in ((3, "1-1"), (2, "2-1"), (1, "3-1")):
        _write(runs, NOW - timedelta(hours=hours), name)
    assert watchdog_cli.main(["--runs-dir", str(runs)], NOW) == 0


def test_an_edited_record_fails_the_check_even_when_the_newest_is_fresh(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    for hours, name in ((3, "1-1"), (2, "2-1"), (1, "3-1")):
        _write(runs, NOW - timedelta(hours=hours), name)
    victim = runs / "2026" / "11" / "1-1.json"
    victim.write_text(victim.read_text(encoding="utf-8").replace("feed unreachable", "x") + " ", encoding="utf-8")
    assert watchdog_cli.main(["--runs-dir", str(runs)], NOW) == 1


def test_a_removed_middle_record_fails_the_check(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    for hours, name in ((3, "1-1"), (2, "2-1"), (1, "3-1")):
        _write(runs, NOW - timedelta(hours=hours), name)
    (runs / "2026" / "11" / "2-1.json").unlink()
    result = watchdog.check(
        [t for _p, t in watchdog_cli.read_record_entries(runs)],
        NOW,
        chain_entries=watchdog_cli.read_record_entries(runs),
    )
    assert [b.reason for b in result.chain_breaks] == ["prev_mismatch"]
    assert not result.healthy
    assert watchdog_cli.main(["--runs-dir", str(runs)], NOW) == 1


def test_the_chain_is_not_checked_when_no_entries_are_given() -> None:
    assert watchdog.check([rr.to_json(_record(NOW))], NOW).chain_breaks == ()


def test_the_report_lists_the_chain_breaks(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    for hours, name in ((3, "1-1"), (2, "2-1"), (1, "3-1")):
        _write(runs, NOW - timedelta(hours=hours), name)
    (runs / "2026" / "11" / "1-1.json").unlink()
    report_file = tmp_path / "report.json"
    assert watchdog_cli.main(["--runs-dir", str(runs), "--report-file", str(report_file)], NOW) == 1
    report = json.loads(report_file.read_text(encoding="utf-8"))
    assert report["healthy"] is False
    assert report["chain_breaks"] == [{"path": "runs/2026/11/2-1.json", "reason": "first_not_null"}]


# ------------------------------------------- the maintainer's weekly check (T3-R2-01)
def _report(tmp_path: Path, checked_at: datetime, due_hours: float = 192) -> Path:
    path = tmp_path / "report.json"
    report = watchdog.render_report(watchdog.check(_texts("success"), checked_at), (), checked_at, due_hours)
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_overdue_check_passes_before_the_due_time_and_fails_after(tmp_path: Path) -> None:
    """``--overdue-check`` exits 1 once the saved report's next_check_due has passed."""
    path = _report(tmp_path, NOW, due_hours=24)
    assert watchdog_cli.main(["--overdue-check", str(path)], NOW + timedelta(hours=24)) == 0
    assert watchdog_cli.main(["--overdue-check", str(path)], NOW + timedelta(hours=24, seconds=1)) == 1


@pytest.mark.parametrize("content", [None, "garbage", "{}", '{"next_check_due": "tomorrow"}'])
def test_overdue_check_fails_when_the_report_is_missing_or_unreadable(tmp_path: Path, content: str | None) -> None:
    """No report means no check was ever recorded; that is never read as on time."""
    path = tmp_path / "report.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    assert watchdog_cli.main(["--overdue-check", str(path)], NOW) == 1


def test_a_run_after_a_missed_check_exits_1_and_says_so(tmp_path: Path) -> None:
    """Fresh records do not hide that the weekly check itself was skipped."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1))
    previous = _report(tmp_path, NOW - timedelta(days=9))
    out = tmp_path / "new.json"
    args = ["--runs-dir", str(runs), "--previous-report", str(previous), "--report-file", str(out)]
    assert watchdog_cli.main(args, NOW) == 1
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["previous_check_overdue"] is True
    assert report["healthy"] is True
    # on time: exit 0
    on_time = _report(tmp_path, NOW - timedelta(days=7))
    args[3] = str(on_time)
    assert watchdog_cli.main(args, NOW) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["previous_check_overdue"] is False


def test_a_first_run_without_a_previous_report_is_not_overdue(tmp_path: Path) -> None:
    """A missing previous report is the first run; an unreadable one is an error."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1))
    assert watchdog_cli.main(["--runs-dir", str(runs), "--previous-report", str(tmp_path / "none.json")], NOW) == 0
    bad = tmp_path / "bad.json"
    bad.write_text("garbage", encoding="utf-8")
    assert watchdog_cli.main(["--runs-dir", str(runs), "--previous-report", str(bad)], NOW) == 1


def test_runs_dir_is_required_without_overdue_check() -> None:
    """The ordinary run still needs ``--runs-dir``."""
    with pytest.raises(SystemExit):
        watchdog_cli.main([], NOW)


def _policy_file(tmp_path: Path, limit_hours: int | None) -> Path:
    """A copy of the repository's Policy_File with ``watchdog.limit_hours`` set (or removed)."""
    doc = json.loads(Path("docs/agent/supply-chain-policy.json").read_text(encoding="utf-8"))
    if limit_hours is None:
        doc.pop("watchdog", None)
    else:
        doc["watchdog"] = {"limit_hours": limit_hours}
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_cli_limit_comes_from_the_policy_file_then_the_default(tmp_path: Path) -> None:
    """Order: ``--limit-hours`` first, then ``watchdog.limit_hours``, then the 8-hour default."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=3), "1-1")
    base = ["--runs-dir", str(runs)]
    assert watchdog_cli.main(base, NOW) == 0  # default 8 hours
    assert watchdog_cli.main([*base, "--policy-file", str(_policy_file(tmp_path, 2))], NOW) == 1
    assert watchdog_cli.main([*base, "--policy-file", str(_policy_file(tmp_path, 4))], NOW) == 0
    assert watchdog_cli.main([*base, "--policy-file", str(_policy_file(tmp_path, None))], NOW) == 0
    # the command line wins over the policy
    both = [*base, "--policy-file", str(_policy_file(tmp_path, 2)), "--limit-hours", "6"]
    assert watchdog_cli.main(both, NOW) == 0


def test_cli_fails_when_the_policy_file_cannot_be_used(tmp_path: Path) -> None:
    """An unreadable or invalid Policy_File is a failure, never a silent fall back to the default."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1), "1-1")
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    for policy in (bad, tmp_path / "absent.json"):
        assert watchdog_cli.main(["--runs-dir", str(runs), "--policy-file", str(policy)], NOW) == 1


def test_a_relative_policy_file_resolves_from_the_repository_root_whatever_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T3-R3-02: the guide runs the command from ``solutions/supply-chain/``, where the relative path used to fail."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1), "1-1")
    report_file = tmp_path / "report.json"
    monkeypatch.chdir(tmp_path)
    args = ["--runs-dir", str(runs), "--policy-file", "docs/agent/supply-chain-policy.json"]
    assert watchdog_cli.main([*args, "--report-file", str(report_file)], NOW) == 0
    assert json.loads(report_file.read_text(encoding="utf-8"))["state"] == "ok"


def test_the_policy_file_defaults_to_the_one_in_the_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without ``--policy-file`` the Policy_File is found from git, not from the working directory."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1), "1-1")
    monkeypatch.chdir(tmp_path)
    assert watchdog_cli.main(["--runs-dir", str(runs)], NOW) == 0
    monkeypatch.setattr(watchdog_cli, "repository_root", lambda: None)
    assert watchdog_cli.main(["--runs-dir", str(runs)], NOW) == 1  # no root, no default file: an error, not 8


def test_a_policy_file_failure_still_writes_a_report_in_the_error_state(tmp_path: Path) -> None:
    """T3-R3-02: no report would make ``--overdue-check`` fail for the wrong reason, week after week."""
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1), "1-1")
    report_file = tmp_path / "report.json"
    code = watchdog_cli.main(
        ["--runs-dir", str(runs), "--policy-file", str(tmp_path / "absent.json"), "--report-file", str(report_file)],
        NOW,
    )
    assert code == 1
    report = json.loads(report_file.read_text(encoding="utf-8"))
    assert report["state"] == "error" and report["healthy"] is False
    assert "policy_error" in report and report["next_check_due"] == "2026-11-18T12:00:00Z"
    assert watchdog_cli.main(["--overdue-check", str(report_file)], NOW) == 0  # the check ran; it was on time


def test_an_empty_workflow_listing_is_an_error_not_a_healthy_one(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _write(runs, NOW - timedelta(hours=1), "1-1")
    listing = tmp_path / "workflows.json"
    listing.write_text('{"total_count": 0, "workflows": []}', encoding="utf-8")
    report_file = tmp_path / "report.json"
    args = ["--runs-dir", str(runs), "--workflows-json", str(listing), "--report-file", str(report_file)]
    assert watchdog_cli.main(args, NOW) == 1
    assert json.loads(report_file.read_text(encoding="utf-8"))["state"] == "error"


def test_the_watchdog_default_is_the_models_default() -> None:
    assert watchdog.DEFAULT_LIMIT_HOURS == models.DEFAULT_WATCHDOG_LIMIT_HOURS


# ---- T3-R4-04: the weekly check is one call, and the code accepts every option that call uses
def test_the_weekly_call_is_accepted_from_any_directory_with_the_chain_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guide's call (root, PYTHONPATH, --chain-ack, no --policy-file) runs without error from a foreign cwd."""
    from supply_chain import watchdog_cli  # noqa: PLC0415

    repo_root = Path(__file__).resolve().parents[1]
    runs = tmp_path / "runs"
    runs.mkdir()
    workflows = tmp_path / "wf.json"
    workflows.write_text('{"workflows": [{"name": "ci", "state": "active"}]}', encoding="utf-8")
    report = tmp_path / "report.json"
    monkeypatch.chdir(tmp_path)
    code = watchdog_cli.main(
        [
            "--runs-dir", str(runs),
            "--workflows-json", str(workflows),
            "--chain-ack", str(repo_root / "docs" / "agent" / "supply-chain-chain-ack.json"),
            "--report-file", str(report),
            "--previous-report", str(report),
        ]
    )  # fmt: skip
    assert code == 1  # no record yet: stale, which is a finding and not a usage or ledger error
    state = json.loads(report.read_text(encoding="utf-8"))
    assert state["state"] == "unhealthy" and "policy_error" not in state

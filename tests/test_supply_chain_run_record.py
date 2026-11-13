"""Tests for ``supply_chain.run_record`` (task 9.19).

No numbered design property covers the run record, so the properties here are
local ones: the JSON round trip, the append-only path rule, the failure-notice
table and the retry waits.
"""

from __future__ import annotations

import itertools
import json
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import models
from supply_chain import run_record as rr

T0 = datetime(2026, 11, 10, 0, 17, tzinfo=UTC)
SHA = "0123456789abcdef0123456789abcdef01234567"
REPO = "example-org/svc-api"

# ---------------------------------------------------------------- strategies

_text = st.text(alphabet="abc XYZ-_/:.日本", min_size=0, max_size=8)
_repo = st.sampled_from(["example-org/svc-api", "example-org/svc-web", "example-org/lib"])
_ts = st.integers(0, 10**8).map(lambda s: T0 + timedelta(seconds=s))
_day = st.integers(0, 2000).map(lambda d: date(2026, 1, 1) + timedelta(days=d))
_hours = st.lists(st.floats(-1e4, 1e4, allow_nan=False, allow_infinity=False), max_size=3).map(tuple)
_sha = st.text(alphabet="0123456789abcdef", min_size=40, max_size=40)
_opt = lambda s: st.one_of(st.none(), s)  # noqa: E731


def _small(s: st.SearchStrategy) -> st.SearchStrategy:
    return st.lists(s, max_size=2).map(tuple)


_finding = st.builds(
    rr.FindingEntry, _repo, _text, _text, _opt(st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"])),
    st.booleans(), st.booleans(), _opt(st.sampled_from(["0.00540", "0.9"])), st.booleans(),
)  # fmt: skip
_issue = st.builds(
    rr.IssueEntry, _repo, _opt(st.integers(1, 999)), st.sampled_from(["create", "update", "close", "reopen"]),
    _opt(_text), st.booleans(),
)  # fmt: skip
_pr = st.builds(
    models.PullRequestRef, _repo.map(lambda r: models.Repo(*r.split("/"))), _text, _ts, _opt(_ts),
)  # fmt: skip
_metrics = st.builds(
    rr.RepoResponseMetrics, st.integers(0, 9), st.integers(0, 9), st.integers(0, 9), _hours, _hours, _hours,
)  # fmt: skip
_repositories = st.builds(
    rr.Repositories,
    _small(_repo),
    _small(st.builds(rr.FetchFailure, _repo, st.sampled_from(["A", "B"]), _text)),
    st.dictionaries(_repo, _opt(st.integers(0, 4)), max_size=3),
)
_feeds = st.builds(
    rr.Feeds,
    _small(st.builds(rr.FeedFetched, st.sampled_from(["kev", "epss", "malicious"]), _ts, _opt(_text))),
    _small(st.builds(rr.FeedFailed, st.sampled_from(["kev", "epss", "malicious"]), _ts, _text)),
)


@st.composite
def records(draw: st.DrawFn) -> rr.RunRecord:
    """Builds a valid run record with every section drawn independently."""
    started = draw(_ts)
    ok = draw(st.booleans())
    return rr.RunRecord(
        run_id=f"{draw(st.integers(1, 10**10))}-{draw(st.integers(1, 5))}",
        started_at=started,
        finished_at=started + timedelta(seconds=draw(st.integers(0, 3600))),
        end_state="success" if ok else "failure",
        failure_reason=None if ok else draw(_opt(_text)),
        aggregator_commit=draw(_sha),
        policy_commit=draw(_opt(_sha)),
        repositories=draw(_repositories),
        feeds=draw(_feeds),
        kev_fetched_on=draw(_opt(_day)),
        epss=draw(st.builds(rr.EpssInfo, _opt(_day), _opt(_text))),
        findings=draw(_small(_finding)),
        issues=draw(_small(_issue)),
        vex_exclusions=draw(_small(st.builds(rr.VexExclusion, _repo, _text, _text, _sha, _text))),
        rejected_vex=draw(_small(st.builds(rr.RejectedVexEntry, _repo, _text, _text))),
        unscored=draw(_small(st.builds(rr.UnscoredEntry, _repo, _text))),
        malicious_withdrawn_unconfirmed=draw(
            _small(st.builds(rr.WithdrawnUnconfirmed, _repo, st.integers(1, 99), _text))
        ),
        summary_overflow=draw(st.dictionaries(_repo, st.integers(0, 9), max_size=2)),
        response_metrics=draw(st.dictionaries(_repo, _metrics, max_size=2)),
        pull_requests=draw(_small(_pr)),
        rate_limit=draw(st.builds(rr.RateLimitRecord, _small(_repo), _small(_repo))),
        failure_notice_error=None if ok else draw(_opt(_text)),
    )


def _record(**over: object) -> rr.RunRecord:
    base: dict[str, object] = {
        "run_id": "123456-1", "started_at": T0, "finished_at": T0 + timedelta(minutes=4),
        "end_state": "success", "failure_reason": None, "aggregator_commit": SHA, "policy_commit": SHA,
        "repositories": rr.Repositories((REPO,), (), {REPO: 0, "example-org/lib": 2}),
        "feeds": rr.Feeds((rr.FeedFetched("kev", T0, "2026.11.09"),), ()),
        "kev_fetched_on": date(2026, 11, 10), "epss": rr.EpssInfo(date(2026, 11, 10), "v2025.03.14"),
        "findings": (), "issues": (), "vex_exclusions": (), "rejected_vex": (), "unscored": (),
        "malicious_withdrawn_unconfirmed": (), "summary_overflow": {}, "response_metrics": {},
        "pull_requests": (models.PullRequestRef(models.Repo("example-org", "svc-api"), "CVE-2026-1", T0, None),),
        "rate_limit": rr.RateLimitRecord((), ()), "failure_notice_error": None,
    }  # fmt: skip
    return rr.RunRecord(**{**base, **over})  # type: ignore[arg-type]


# ------------------------------------------------------------------ JSON


# Feature: cyber-resilience-phase4-supply-chain, local property: run record round trip
@settings(max_examples=100, deadline=None)
@given(records())
def test_json_round_trip_gives_the_same_record(record: rr.RunRecord) -> None:
    """**Validates: Requirements 26.2, 26.3** - ``from_json(to_json(r)) == r`` and the text is stable."""
    text = rr.to_json(record)
    event(f"findings={len(record.findings)}")
    event(f"pull_requests={len(record.pull_requests)}")
    event(f"checks_recorded={len(record.repositories.required_checks)}")
    event(f"end_state={record.end_state}")
    assert rr.from_json(text) == record
    assert rr.to_json(rr.from_json(text)) == text


def test_json_has_the_design_keys_and_the_added_fields() -> None:
    """The text carries schema_version 1, the Q-13/Q-18 fields and a recorded 0-check repository."""
    data = json.loads(rr.to_json(_record()))
    assert data["schema_version"] == 1
    assert data["pull_requests"] == [
        {"repo": REPO, "vuln_id": "CVE-2026-1", "created_at": "2026-11-10T00:17:00Z", "merged_at": None}
    ]
    assert data["epss"] == {"fetched_on": "2026-11-10", "model_version": "v2025.03.14"}
    assert data["kev_fetched_on"] == "2026-11-10"
    assert data["repositories"]["required_checks"][REPO] == 0
    assert _record().required_checks_missing == (REPO,)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(schema_version=2),
        lambda d: d.pop("schema_version"),
        lambda d: d.update(extra=1),
        lambda d: d.pop("epss"),
        lambda d: d.update(started_at="2026-11-10 00:17:00"),
        lambda d: d.update(started_at="2026-11-10T00:17:00+09:00"),
        lambda d: d.update(end_state="partial"),
        lambda d: d["repositories"]["required_checks"].update({REPO: True}),
        lambda d: d["pull_requests"][0].update(repo="no-slash"),
        lambda d: d.update(aggregator_commit="ABC"),
        lambda d: d.update(kev_fetched_on="2026-13-40"),
    ],
)
def test_malformed_records_are_rejected(mutate) -> None:  # noqa: ANN001
    """A wrong version, key, type, time form or value is refused."""
    data = json.loads(rr.to_json(_record()))
    mutate(data)
    with pytest.raises(rr.RunRecordError):
        rr.from_json(json.dumps(data))


@pytest.mark.parametrize("text", ["", "[]", "not json", '{"schema_version": 1, "x": NaN}'])
def test_non_record_text_is_rejected(text: str) -> None:
    """Text that is not a record object is refused."""
    with pytest.raises(rr.RunRecordError):
        rr.from_json(text)


def test_construction_rules() -> None:
    """Times need UTC whole seconds, commits 40 hex digits, and a success has no failure reason."""
    with pytest.raises(rr.RunRecordError):
        _record(started_at=T0.replace(microsecond=1))
    with pytest.raises(rr.RunRecordError):
        _record(started_at=datetime(2026, 11, 10))  # noqa: DTZ001
    with pytest.raises(rr.RunRecordError):
        _record(finished_at=T0 - timedelta(seconds=1))
    with pytest.raises(rr.RunRecordError):
        _record(policy_commit="abc")
    with pytest.raises(rr.RunRecordError):
        _record(end_state="success", failure_reason="boom")
    assert _record(end_state="failure", failure_reason=None).policy_commit == SHA
    assert _record(policy_commit=None).policy_commit is None


def test_a_record_with_fractional_seconds_in_a_nested_time_cannot_be_written() -> None:
    """A pull request time with microseconds would not survive the round trip, so it is refused."""
    pr = models.PullRequestRef(models.Repo("example-org", "svc-api"), "CVE-2026-1", T0.replace(microsecond=5), None)
    with pytest.raises(rr.RunRecordError):
        rr.to_json(_record(pull_requests=(pr,)))


# ------------------------------------------------------------------ paths


def test_record_path_uses_the_start_month() -> None:
    """The path is runs/<YYYY>/<MM>/<run_id>.json."""
    assert rr.record_path(_record()) == "runs/2026/11/123456-1.json"
    assert (
        rr.record_path(
            _record(started_at=datetime(2027, 1, 1, tzinfo=UTC), finished_at=datetime(2027, 1, 1, tzinfo=UTC))
        )
        == "runs/2027/01/123456-1.json"
    )


@pytest.mark.parametrize("run_id", ["", "abc", "1", "1-", "../x-1", "12-3/../../x", "1-1.json", "１-1"])
def test_a_run_id_that_could_move_the_path_is_rejected(run_id: str) -> None:
    """Only ``<digits>-<digits>`` is accepted as the file name."""
    with pytest.raises(rr.RunRecordError):
        rr.record_path(_record(run_id=run_id))


def test_existing_paths_are_refused_and_new_ones_returned() -> None:
    """An existing file, or another file for the same run id, is refused; others do not matter."""
    rec = _record()
    assert rr.new_record_path(rec, []) == "runs/2026/11/123456-1.json"
    assert (
        rr.new_record_path(rec, {"runs/2026/11/123456-2.json", "runs/2026/10/9-1.json", "README.md"})
        == "runs/2026/11/123456-1.json"
    )
    with pytest.raises(rr.RecordPathExistsError):
        rr.new_record_path(rec, {"runs/2026/11/123456-1.json"})
    with pytest.raises(rr.RecordPathExistsError):
        rr.new_record_path(rec, ["runs/2026/10/123456-1.json"])  # same run id, other month


# Feature: cyber-resilience-phase4-supply-chain, local property: append-only path rule
@settings(max_examples=100, deadline=None)
@given(
    records(),
    st.sets(st.sampled_from(["runs/2026/11/1-1.json", "runs/2026/10/7-2.json", "docs/a.md"]), max_size=3),
    st.booleans(),
)
def test_path_is_refused_exactly_when_the_record_or_its_run_id_exists(
    record: rr.RunRecord, others: set[str], include_own: bool
) -> None:
    """**Validates: Requirements 26.3** - an existing record is never a candidate for writing."""
    path = rr.record_path(record)
    existing = set(others) | ({path} if include_own else set())
    clash = include_own or any(p.rsplit("/", 1)[-1] == f"{record.run_id}.json" for p in existing)
    event(f"clash={clash}")
    if clash:
        with pytest.raises(rr.RecordPathExistsError):
            rr.new_record_path(record, existing)
    else:
        assert rr.new_record_path(record, existing) == path


# ------------------------------------------------------- failure notices

S, F = "success", "failure"
# (oldest ... newest, notice open) -> action. Written by hand from Requirements 25.3 and 25.4.
TABLE_2 = {
    (S, S, False): "none", (S, S, True): "close",
    (S, F, False): "none", (S, F, True): "none",
    (F, S, False): "none", (F, S, True): "close",
    (F, F, False): "create", (F, F, True): "append",
}  # fmt: skip
TABLE_3 = {
    (S, S, S, False): "none", (S, S, S, True): "close",
    (S, S, F, False): "none", (S, S, F, True): "none",
    (S, F, S, False): "none", (S, F, S, True): "close",
    (S, F, F, False): "create", (S, F, F, True): "append",
    (F, S, S, False): "none", (F, S, S, True): "close",
    (F, S, F, False): "none", (F, S, F, True): "none",
    (F, F, S, False): "none", (F, F, S, True): "close",
    (F, F, F, False): "create", (F, F, F, True): "append",
}  # fmt: skip


def _outcomes(states: tuple[str, ...]) -> list[rr.RunOutcome]:
    return [rr.RunOutcome(f"{i + 1}-1", s) for i, s in enumerate(states)]  # type: ignore[arg-type]


@pytest.mark.parametrize("key", sorted(TABLE_2))
def test_notice_table_for_two_runs(key: tuple) -> None:
    """Two-run window: 2 failures create or append; a success closes an open notice."""
    *states, is_open = key
    assert rr.decide_failure_notice(_outcomes(tuple(states)), is_open).action == TABLE_2[key]


@pytest.mark.parametrize("key", sorted(TABLE_3))
def test_notice_table_for_three_runs(key: tuple) -> None:
    """Three-run window: the trailing streak decides, older runs only matter through the streak."""
    *states, is_open = key
    assert rr.decide_failure_notice(_outcomes(tuple(states)), is_open).action == TABLE_3[key]


def test_notice_names_the_run_to_record() -> None:
    """create and append carry the latest failed run; close carries the successful run; none carries nothing."""
    assert rr.decide_failure_notice(_outcomes((F, F)), False) == rr.NoticeDecision("create", "2-1")
    assert rr.decide_failure_notice(_outcomes((F, F, F)), True) == rr.NoticeDecision("append", "3-1")
    assert rr.decide_failure_notice(_outcomes((F, S)), True) == rr.NoticeDecision("close", "2-1")
    assert rr.decide_failure_notice(_outcomes((S, F)), False) == rr.NoticeDecision("none", None)
    assert rr.decide_failure_notice([], True) == rr.NoticeDecision("none", None)
    assert rr.decide_failure_notice(_outcomes((F,)), False).action == "none"


# Feature: cyber-resilience-phase4-supply-chain, local property: failure notice opens and closes
@settings(max_examples=100, deadline=None)
@given(st.lists(st.sampled_from([S, F]), min_size=1, max_size=8), st.booleans())
def test_notice_follows_the_trailing_failure_streak(states: list[str], is_open: bool) -> None:
    """**Validates: Requirements 25.3, 25.4** - at most one Issue is created; none is created while one is open."""
    d = rr.decide_failure_notice(_outcomes(tuple(states)), is_open)
    streak = len(list(itertools.takewhile(lambda s: s == F, reversed(states))))
    event(f"streak={min(streak, 3)}")
    event(f"open={is_open}")
    if states[-1] == S:
        assert d.action == ("close" if is_open else "none")
    elif streak >= 2:
        assert d.action == ("append" if is_open else "create")
    else:
        assert d.action == "none"
    assert (d.run_id is None) == (d.action == "none")
    assert d.action != "create" or not is_open


# ------------------------------------------------------------------ waits


def test_wait_sequence_without_retry_after() -> None:
    """2, 4, 8, 16, 32 seconds and no sixth retry."""
    assert rr.backoff_schedule() == (2.0, 4.0, 8.0, 16.0, 32.0)
    assert [rr.retry_wait(i) for i in range(7)] == [2.0, 4.0, 8.0, 16.0, 32.0, None, None]


def test_retry_after_raises_the_wait_but_never_lowers_it() -> None:
    """``retry-after`` is a floor for that retry only."""
    assert rr.backoff_schedule([None, 10, 1, 60]) == (2.0, 10.0, 8.0, 60.0, 32.0)
    assert rr.backoff_schedule([0, 4, 8]) == (2.0, 4.0, 8.0, 16.0, 32.0)
    assert rr.retry_wait(5, 100) is None
    assert rr.backoff_schedule([1, 1, 1, 1, 1, 999]) == (2.0, 4.0, 8.0, 16.0, 32.0)


@pytest.mark.parametrize("bad", [-1, float("nan"), float("inf"), True])
def test_bad_retry_after_is_rejected(bad: float) -> None:
    """A negative, non-finite or boolean ``retry-after`` is refused."""
    with pytest.raises(ValueError):
        rr.retry_wait(0, bad)


@pytest.mark.parametrize("bad", [-1, True])
def test_bad_retry_index_is_rejected(bad: int) -> None:
    """A negative or boolean index is refused."""
    with pytest.raises(ValueError):
        rr.retry_wait(bad)


# Feature: cyber-resilience-phase4-supply-chain, local property: retry waits
@settings(max_examples=100, deadline=None)
@given(st.lists(st.one_of(st.none(), st.floats(0, 1e4)), max_size=8))
def test_schedule_is_five_waits_each_at_least_the_base_and_retry_after(hints: list[float | None]) -> None:
    """**Validates: Requirements 9.6, 9.7** - the waits double, honour retry-after and stop after five."""
    waits = rr.backoff_schedule(hints)
    event(f"hints={min(len(hints), 6)}")
    assert len(waits) == 5
    for i, w in enumerate(waits):
        h = hints[i] if i < len(hints) else None
        assert w == max(2.0 * 2**i, h if h is not None else 0.0)
    assert rr.retry_wait(5, hints[5] if len(hints) > 5 else None) is None

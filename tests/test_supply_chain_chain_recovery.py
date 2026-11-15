"""Tests for ``chain_recovery`` (T4-R3-04) and the tip and seal checks of ``run_record`` (T4-R3-08)."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from supply_chain import chain_recovery as cr
from supply_chain import run_record as rr

from tests.test_supply_chain_run_record import T0, _record


def _rec(n: int, prev: str | None) -> tuple[str, str]:
    record = _record(
        run_id=f"{n}-1",
        started_at=T0 + timedelta(minutes=10 * n),
        finished_at=T0 + timedelta(minutes=10 * n + 1),
        prev_record_sha256=prev,
    )
    return rr.record_path(record), rr.to_json(record)


def forked() -> tuple[list[tuple[str, str]], tuple[str, str], tuple[str, str], tuple[str, str]]:
    """``a`` with two children ``b`` and ``c``: the month has two tips."""
    a = _rec(1, None)
    b = _rec(2, rr.sha256_text(a[1]))
    c = _rec(3, rr.sha256_text(a[1]))
    return [a, b, c], a, b, c


def ledger(*forks: cr.AcceptedFork) -> str:
    return cr.render_ledger(forks)


def test_a_forked_month_stops_the_writer_the_seal_and_the_watchdog_today() -> None:
    """The failure that the review described (the control: nothing is accepted yet)."""
    entries, *_ = forked()
    with pytest.raises(rr.RunRecordError):
        rr.previous_record_sha256(t for _p, t in entries)
    with pytest.raises(rr.RunRecordError):
        rr.month_seal("2026-11", entries)
    assert [b.reason for b in rr.verify_chain(entries)] == ["fork"]


def test_detect_names_the_tips_of_a_forked_month() -> None:
    entries, _a, b, c = forked()
    (month,) = cr.month_tips(entries)
    assert {sha for sha, _p in month.tips} == {rr.sha256_text(b[1]), rr.sha256_text(c[1])}


def test_isolating_one_tip_lets_the_writer_the_seal_and_the_chain_check_go_on() -> None:
    entries, _a, b, c = forked()
    abandoned = rr.sha256_text(c[1])
    text = cr.isolate(entries, ledger(), abandon=abandoned, decision="Issue 123")
    accepted = cr.parse_ledger(text)
    # the month named by the records' own path
    month = cr._month_name(rr.month_of(b[0]) + "/x")
    result = cr.reconnect(entries, accepted, month)
    assert result.problems == ()
    assert result.next_prev_record_sha256 == rr.sha256_text(b[1])
    kept, problems = cr.effective_entries(entries, accepted)
    assert problems == [] and len(kept) == 2
    assert rr.verify_chain(kept) == ()
    assert rr.month_seal(month, kept) == (f"supply-chain-runs-{month}", rr.sha256_text(b[1]))


def test_the_abandoned_record_is_not_deleted_and_the_ledger_is_all_that_changes() -> None:
    entries, *_ = forked()
    before = list(entries)
    cr.isolate(entries, ledger(), abandon=rr.sha256_text(entries[2][1]), decision="Issue 123")
    assert entries == before


def test_a_record_with_descendants_cannot_be_abandoned() -> None:
    entries, a, b, c = forked()
    d = _rec(4, rr.sha256_text(b[1]))
    with pytest.raises(cr.LedgerError, match="descendants"):
        cr.isolate([*entries, d], ledger(), abandon=rr.sha256_text(b[1]), decision="Issue 123")
    with pytest.raises(cr.LedgerError, match="descendants"):
        cr.isolate([*entries, d], ledger(), abandon=rr.sha256_text(a[1]), decision="Issue 123")


def test_an_unknown_record_and_a_month_without_a_fork_are_refused() -> None:
    entries, *_ = forked()
    with pytest.raises(cr.LedgerError, match="no record"):
        cr.isolate(entries, ledger(), abandon="0" * 64, decision="Issue 123")
    a = _rec(1, None)
    b = _rec(2, rr.sha256_text(a[1]))
    with pytest.raises(cr.LedgerError, match="not one of two or more tips"):
        cr.isolate([a, b], ledger(), abandon=rr.sha256_text(b[1]), decision="Issue 123")


def test_a_ledger_entry_that_no_longer_stands_fails_the_reconnect() -> None:
    """Both tips remain after one is abandoned and a third child appears: the month still has two tips."""
    entries, a, b, c = forked()
    accepted = cr.parse_ledger(cr.isolate(entries, ledger(), abandon=rr.sha256_text(c[1]), decision="Issue 123"))
    month = cr._month_name(rr.month_of(b[0]) + "/x")
    e = _rec(5, rr.sha256_text(a[1]))  # a new fork below ``a``
    result = cr.reconnect([*entries, e], accepted, month)
    assert result.next_prev_record_sha256 is None and result.problems


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        json.dumps({"schema_version": 2, "accepted_forks": []}),
        json.dumps({"schema_version": 1, "accepted_forks": [{"month": "2026-11"}]}),
        json.dumps(
            {
                "schema_version": 1,
                "accepted_forks": [{"month": "11", "abandoned_record_sha256": "0" * 64, "decision": "Issue 1"}],
            }
        ),
        json.dumps(
            {
                "schema_version": 1,
                "accepted_forks": [{"month": "2026-11", "abandoned_record_sha256": "G" * 64, "decision": "Issue 1"}],
            }
        ),
        json.dumps(
            {
                "schema_version": 1,
                "accepted_forks": [{"month": "2026-11", "abandoned_record_sha256": "0" * 64, "decision": ""}],
            }
        ),
    ],
)
def test_a_malformed_ledger_is_refused(text: str) -> None:
    with pytest.raises(cr.LedgerError):
        cr.parse_ledger(text)


@settings(max_examples=40, deadline=None)
@given(order=st.permutations([0, 1, 2]), abandon=st.sampled_from([1, 2]))
def test_whatever_the_order_of_storage_the_survivor_is_the_one_not_abandoned(order: list[int], abandon: int) -> None:
    entries, _a, b, c = forked()
    shuffled = [entries[i] for i in order]
    abandoned, kept_tip = (c, b) if abandon == 2 else (b, c)
    accepted = cr.parse_ledger(
        cr.isolate(shuffled, ledger(), abandon=rr.sha256_text(abandoned[1]), decision="Issue 123")
    )
    month = cr._month_name(rr.month_of(b[0]) + "/x")
    result = cr.reconnect(shuffled, accepted, month)
    assert result.problems == () and result.next_prev_record_sha256 == rr.sha256_text(kept_tip[1])


def test_the_command_line_detects_isolates_and_reconnects(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    entries, _a, b, c = forked()
    runs = tmp_path / "checkout" / "runs"
    for path, text in entries:
        target = tmp_path / "checkout" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    ledger_path = tmp_path / "ack.json"
    base = ["--runs-dir", str(runs), "--ledger", str(ledger_path)]
    assert cr.main([*base, "detect"]) == 1
    assert "months with an open fork: 1" in capsys.readouterr().out
    month = cr._month_name(rr.month_of(b[0]) + "/x")
    assert cr.main([*base, "reconnect", "--month", month]) == 1  # not isolated yet
    capsys.readouterr()
    assert cr.main([*base, "isolate", "--abandon", rr.sha256_text(c[1]), "--decision", "Issue 123"]) == 0
    assert cr.main([*base, "isolate", "--abandon", "1" * 64, "--decision", "Issue 123"]) == 1  # unknown
    assert cr.main([*base, "detect"]) == 0
    capsys.readouterr()
    assert cr.main([*base, "reconnect", "--month", month]) == 0
    assert capsys.readouterr().out.strip() == rr.sha256_text(b[1])
    assert all((tmp_path / "checkout" / path).exists() for path, _t in entries)  # nothing was deleted


# ------------------------------------------------------------------ watchdog_cli --chain-ack (26.26, 26.27)


def _write_checkout(root: Path, entries: list[tuple[str, str]]) -> Path:
    for path, text in entries:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root / "runs"


def _watch(runs: Path, ack: Path | None, tmp_path: Path) -> tuple[int, dict[str, object]]:
    from supply_chain import watchdog_cli

    policy = Path(__file__).resolve().parents[1] / "docs" / "agent" / "supply-chain-policy.json"
    report = tmp_path / "report.json"
    argv = [
        "--runs-dir",
        str(runs),
        "--policy-file",
        str(policy),
        "--report-file",
        str(report),
        "--limit-hours",
        "100000",
    ]
    if ack is not None:
        argv += ["--chain-ack", str(ack)]
    code = watchdog_cli.main(argv, now=T0 + timedelta(hours=1))
    return code, json.loads(report.read_text(encoding="utf-8"))


def test_the_watchdog_reports_a_fork_until_the_ledger_accepts_it(tmp_path: Path) -> None:
    entries, _a, _b, c = forked()
    runs = _write_checkout(tmp_path / "checkout", entries)
    code, report = _watch(runs, None, tmp_path)
    assert code == 1 and report["state"] == "unhealthy"
    ack = tmp_path / "ack.json"
    ack.write_text(cr.isolate(entries, ledger(), abandon=rr.sha256_text(c[1]), decision="Issue 123"), encoding="utf-8")
    code, report = _watch(runs, ack, tmp_path)
    assert code == 0 and report["state"] == "ok"


def test_an_absent_ledger_is_read_as_no_decision(tmp_path: Path) -> None:
    entries, *_ = forked()
    runs = _write_checkout(tmp_path / "checkout", entries)
    code, _report = _watch(runs, tmp_path / "missing.json", tmp_path)
    assert code == 1


def test_a_ledger_that_names_a_record_with_a_child_fails_the_watchdog(tmp_path: Path) -> None:
    entries, a, *_ = forked()
    runs = _write_checkout(tmp_path / "checkout", entries)
    bad = cr.render_ledger([cr.AcceptedFork("2026-11", rr.sha256_text(a[1]), "Issue 123")])
    ack = tmp_path / "ack.json"
    ack.write_text(bad, encoding="utf-8")
    code, report = _watch(runs, ack, tmp_path)
    assert code == 1 and report["state"] == "error" and "does not stand" in str(report["policy_error"])


def test_a_malformed_ledger_fails_the_watchdog(tmp_path: Path) -> None:
    entries, *_ = forked()
    runs = _write_checkout(tmp_path / "checkout", entries)
    ack = tmp_path / "ack.json"
    ack.write_text("{", encoding="utf-8")
    code, report = _watch(runs, ack, tmp_path)
    assert code == 1 and report["state"] == "error"


def test_the_shipped_ledger_is_valid_and_empty() -> None:
    path = Path(__file__).resolve().parents[1] / "docs" / "agent" / "supply-chain-chain-ack.json"
    assert cr.parse_ledger(path.read_text(encoding="utf-8")) == ()


# ------------------------------------------------------------------ tip and seal (T4-R3-08)


def test_an_edited_tip_is_found_by_the_recorded_hash_though_the_chain_and_the_seal_still_pass() -> None:
    a = _rec(1, None)
    b = _rec(2, rr.sha256_text(a[1]))
    recorded = rr.sha256_text(b[1])
    edited = (b[0], b[1].replace('"run_id": "2-1"', '"run_id": "2-9"'))
    assert edited[1] != b[1]
    assert rr.verify_chain([a, edited]) == ()  # the control: the chain does not see it
    assert rr.verify_month_tip("2026-11", [a, b], recorded) is None
    found = rr.verify_month_tip("2026-11", [a, edited], recorded)
    assert found is not None and found.reason == "tip_changed"


def test_a_removed_tip_is_found_and_a_longer_month_is_not_a_finding() -> None:
    a = _rec(1, None)
    b = _rec(2, rr.sha256_text(a[1]))
    c = _rec(3, rr.sha256_text(b[1]))
    assert rr.verify_month_tip("2026-11", [a], rr.sha256_text(b[1])) is not None
    assert rr.verify_month_tip("2026-11", [a, b, c], rr.sha256_text(b[1])) is None
    assert rr.verify_month_tip("2026-11", [a, b], None) is None


def test_the_tip_and_seal_checks_refuse_malformed_input() -> None:
    with pytest.raises(rr.RunRecordError):
        rr.verify_month_tip("2026-1", [], "0" * 64)
    with pytest.raises(rr.RunRecordError):
        rr.verify_month_tip("2026-11", [], "XYZ")
    with pytest.raises(rr.RunRecordError):
        rr.verify_month_seal("2026-11", [], "XYZ")


def test_the_seal_matches_the_stored_month_only_while_the_last_record_is_intact() -> None:
    a = _rec(1, None)
    b = _rec(2, rr.sha256_text(a[1]))
    seal = rr.month_seal("2026-11", [a, b])
    assert seal is not None
    assert rr.verify_month_seal("2026-11", [a, b], seal[1]) is None
    removed = rr.verify_month_seal("2026-11", [a], seal[1])
    assert removed is not None and removed.reason == "seal_mismatch"
    assert rr.verify_month_seal("2026-11", [], seal[1]) == rr.ChainBreak("runs/2026/11", "seal_mismatch")
    entries, *_ = forked()
    fork = rr.verify_month_seal("2026-11", entries, seal[1])
    assert fork is not None and fork.reason == "fork"

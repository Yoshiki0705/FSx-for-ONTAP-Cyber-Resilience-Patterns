"""Tests for the ``infra-ledger`` gate subcommand (Requirements 5.2, 5.4, 5.8)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import check_infrastructure_ledger as ledger
import pytest
from supply_chain_checks import infra_ledger

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "scripts" / "tests" / "fixtures" / "supply_chain" / "infra-ledger"
MATCHED_ON = dt.date(2026, 1, 1)


def _root(tmp_path: Path, doc: dict) -> Path:
    path = tmp_path / infra_ledger.LEDGER_PATH
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return tmp_path


def _decided() -> dict:
    row = {"verified_version": "ONTAP 9.18.1P6", "advisory_match": "該当なし", "matched_on": MATCHED_ON.isoformat()}
    return {"rows": [row]}


def test_committed_ledger_passes_the_gate() -> None:
    report = infra_ledger.check(REPO)
    assert report.violations == []
    assert report.scanned == 1


@pytest.mark.parametrize(("days", "listed"), [(90, False), (91, True)])
def test_stale_row_boundary_is_listed_not_failed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], days: int, listed: bool
) -> None:
    root = _root(tmp_path, _decided())
    report = infra_ledger.check(root, today=MATCHED_ON + dt.timedelta(days=days))
    assert report.violations == []
    assert ("needs re-check" in capsys.readouterr().out) is listed


@pytest.mark.parametrize(
    "case",
    sorted(p.name for p in FIXTURES.glob("fail-*") if (p / "docs/agent/infrastructure-component-ledger.json").exists()),
)
def test_gate_reports_the_same_problems_as_the_standalone_script(case: str) -> None:
    """Each violation is one message of ``check_public``; the gate adds a kind, not a rule."""
    path = FIXTURES / case / infra_ledger.LEDGER_PATH
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        with pytest.raises(infra_ledger.Unparseable):
            infra_ledger.check(FIXTURES / case)
        return
    report = infra_ledger.check(FIXTURES / case)
    assert [v.detail for v in report.violations] == ledger.check_public(doc)
    expected_kind = (FIXTURES / case / "EXPECT").read_text(encoding="utf-8").split()[1]
    assert {v.kind for v in report.violations} == {expected_kind}


def test_standalone_script_still_exits_zero_on_the_committed_ledger() -> None:
    assert ledger.main(["--public", str(REPO / infra_ledger.LEDGER_PATH)]) == 0


def test_root_without_a_ledger_scans_nothing_and_a_bad_ledger_is_unparseable(tmp_path: Path) -> None:
    assert infra_ledger.check(tmp_path).scanned == 0
    path = tmp_path / infra_ledger.LEDGER_PATH
    path.parent.mkdir(parents=True)
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(infra_ledger.Unparseable):
        infra_ledger.check(tmp_path)

"""Run the ``--selftest`` of every supply-chain gate subcommand from pytest (task 11.12).

The subcommands are listed at run time with the entry point's own ``discover``; nothing here
names them, so a new ``scripts/supply_chain_checks/<name>.py`` is covered as soon as it exists.
``test_check_supply_chain.py`` (11.2) already proves the selftest mechanics on ``policy`` and on
fake subcommands; this file applies them to every real subcommand.
"""

from __future__ import annotations

import io
import logging
import shutil
from pathlib import Path

import check_supply_chain as gate
import pytest

SUBCOMMANDS = sorted(gate.discover())
_LAX = "from supply_chain_checks._common import Report\n\ndef check(root):\n    return Report(scanned=1)\n"


def _run(*argv: str, **kwargs: object) -> tuple[int, str]:
    out = io.StringIO()
    code = gate.main(list(argv), out=out, **kwargs)  # type: ignore[arg-type]
    return code, out.getvalue()


def _copy_checks(tmp_path: Path) -> Path:
    checks = tmp_path / "checks"
    shutil.copytree(gate.CHECKS_DIR, checks, ignore=shutil.ignore_patterns("__pycache__"))
    return checks


def test_at_least_one_subcommand_is_discovered() -> None:
    assert SUBCOMMANDS, "no subcommand found: the parametrized tests below would run nothing"


@pytest.mark.parametrize("name", SUBCOMMANDS)
def test_selftest_exits_zero_for_every_subcommand(name: str) -> None:
    code, text = _run(name, "--selftest")
    assert code == 0, text
    assert f"{name}: selftest ok" in text


@pytest.mark.parametrize("name", SUBCOMMANDS)
def test_every_subcommand_has_good_and_failing_fixtures_with_a_nonzero_expectation(name: str) -> None:
    cases = [p for p in (gate.FIXTURES_DIR / name).glob("*") if p.is_dir()]
    assert any(c.name.startswith("pass-") for c in cases), f"{name}: no pass-* fixture"
    fails = [c for c in cases if c.name.startswith("fail-")]
    assert fails, f"{name}: no fail-* fixture"
    for case in fails:
        first = (case / "EXPECT").read_text(encoding="utf-8").splitlines()[0].split()
        assert int(first[0]) in (1, 2), f"{name}/{case.name}: a failing input must expect exit 1 or 2"


@pytest.mark.parametrize("name", SUBCOMMANDS)
def test_selftest_fails_when_the_subcommand_has_no_fixture_directory(name: str, tmp_path: Path) -> None:
    code, text = _run(name, "--selftest", fixtures_dir=tmp_path / "no-fixtures")
    assert code == 1
    assert "no pass-* fixture" in text and "no fail-* fixture" in text


@pytest.mark.parametrize("name", SUBCOMMANDS)
def test_selftest_fails_when_a_failing_fixture_no_longer_fails(name: str, tmp_path: Path) -> None:
    fixtures = tmp_path / "fixtures"
    shutil.copytree(gate.FIXTURES_DIR / name, fixtures / name)
    victim = sorted((fixtures / name).glob("fail-*"))[0]
    shutil.rmtree(victim)
    (victim / "x").mkdir(parents=True)  # an empty tree: the gate finds nothing to flag
    (victim / "EXPECT").write_text("1 never-reported-kind\n", encoding="utf-8")
    code, text = _run(name, "--selftest", fixtures_dir=fixtures)
    assert code == 1 and f"{victim.name}:" in text


def test_a_new_subcommand_without_fixtures_fails_the_whole_selftest(tmp_path: Path) -> None:
    checks = _copy_checks(tmp_path)
    (checks / "fake_new.py").write_text(_LAX, encoding="utf-8")
    code, text = _run("--selftest", checks_dir=checks)
    assert code == 1
    assert "fake-new: selftest FAILED: no pass-* fixture" in text
    for name in SUBCOMMANDS:
        assert f"{name}: selftest ok" in text  # the real ones are still run and still pass


def test_a_new_subcommand_that_never_fails_fails_the_whole_selftest(tmp_path: Path) -> None:
    checks = _copy_checks(tmp_path)
    (checks / "fake_new.py").write_text(_LAX, encoding="utf-8")
    fixtures = tmp_path / "fixtures"
    shutil.copytree(gate.FIXTURES_DIR, fixtures)
    (fixtures / "fake-new" / "pass-ok").mkdir(parents=True)
    (fixtures / "fake-new" / "fail-bad").mkdir(parents=True)
    (fixtures / "fake-new" / "fail-bad" / "EXPECT").write_text("1 range\n", encoding="utf-8")
    code, text = _run("--selftest", checks_dir=checks, fixtures_dir=fixtures)
    assert code == 1 and "fake-new: selftest FAILED: fail-bad: expected exit 1, got 0" in text


def test_warning_only_findings_are_logged_and_do_not_change_the_exit_code(caplog: pytest.LogCaptureFixture) -> None:
    """Task 4.14: pinning's optional (13.9) findings and vex's MAL- notice warn without failing."""
    with caplog.at_level(logging.WARNING):
        for name, case, marker in (
            ("pinning", "pass-exact", "optional (13.9)"),
            ("vex", "pass-malicious-warning", "MAL-"),
        ):
            if name not in SUBCOMMANDS:
                pytest.fail(f"{name} subcommand is gone; update this test")
            caplog.clear()
            code, _ = _run(name, "--root", str(gate.FIXTURES_DIR / name / case))
            assert code == 0, f"{name}/{case}"
            assert any(marker in r.getMessage() for r in caplog.records), f"{name}/{case}: no warning with {marker!r}"

"""Tests of the supply-chain gate entry point and its ``policy`` subcommand."""

from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import check_supply_chain as gate
import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURES = gate.FIXTURES_DIR / "policy"
POLICY_REL = Path("docs/agent/supply-chain-policy.json")

_PASS_MODULE = "from supply_chain_checks._common import Report\n\ndef check(root):\n    return Report(scanned=1)\n"
_EMPTY_MODULE = "from supply_chain_checks._common import Report\n\ndef check(root):\n    return Report()\n"


def _run(*argv: str, **kwargs: object) -> tuple[int, str]:
    out = io.StringIO()
    code = gate.main(list(argv), out=out, **kwargs)  # type: ignore[arg-type]
    return code, out.getvalue()


def _case(name: str) -> Path:
    return FIXTURES / name


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("fail-")))
def test_each_failing_fixture_fails_for_its_stated_reason(case: str) -> None:
    want_code, kind = (FIXTURES / case / "EXPECT").read_text(encoding="utf-8").splitlines()[0].split()
    code, text = _run("policy", "--root", str(FIXTURES / case))
    assert code == int(want_code)
    assert f": {kind}:" in text
    for line in text.splitlines()[:-1]:
        assert re.match(r"^[^:\s]+:\d+: \w+: .+", line), line


def test_good_fixture_and_the_real_policy_pass_and_report_the_file_count() -> None:
    for root in (FIXTURES / "pass-valid", REPO):
        code, text = _run("policy", "--root", str(root))
        assert code == 0
        assert text.strip() == "policy: scanned 1 file(s), 0 violation(s)"


def test_violation_line_points_at_the_offending_key() -> None:
    _, text = _run("policy", "--root", str(_case("fail-major-below-default")))
    first = text.splitlines()[0]
    line_no = int(first.split(":")[1])
    source = (_case("fail-major-below-default") / POLICY_REL).read_text(encoding="utf-8").split("\n")
    assert '"major"' in source[line_no - 1]


def test_absent_policy_file_is_unparseable_and_reports_zero_files() -> None:
    code, text = _run("policy", "--root", str(_case("fail-file-absent")))
    assert code == 2
    assert "scanned 0 files (nothing was checked)" in text
    assert "No such file or directory" in text and str(FIXTURES) not in text


def test_selftest_passes_for_policy_and_for_the_whole_gate() -> None:
    assert _run("policy", "--selftest")[0] == 0
    code, text = _run("--selftest")
    assert code == 0 and "policy: selftest ok" in text


def test_subcommands_are_discovered_from_the_directory_not_listed_in_the_entry(tmp_path: Path) -> None:
    checks = tmp_path / "checks"
    checks.mkdir()
    (checks / "agent_extra.py").write_text(_PASS_MODULE, encoding="utf-8")
    (checks / "_private.py").write_text("raise RuntimeError('must not be loaded')\n", encoding="utf-8")
    assert list(gate.discover(checks)) == ["agent-extra"]
    code, text = _run(checks_dir=checks, default_root=tmp_path)
    assert code == 0 and "agent-extra: scanned 1 file(s)" in text
    assert "policy" in gate.discover(REPO / "scripts" / "supply_chain_checks")


def test_run_without_arguments_runs_every_subcommand_and_takes_the_worst_exit_code(tmp_path: Path) -> None:
    checks = tmp_path / "checks"
    checks.mkdir()
    shutil.copy(REPO / "scripts" / "supply_chain_checks" / "policy.py", checks / "policy.py")
    (checks / "other.py").write_text(_PASS_MODULE, encoding="utf-8")
    code, text = _run(checks_dir=checks, default_root=_case("fail-broken-json"))
    assert code == 2
    assert "policy: scanned 1 file(s)" in text and "other: scanned 1 file(s)" in text


def test_a_check_that_scans_nothing_says_so(tmp_path: Path) -> None:
    checks = tmp_path / "checks"
    checks.mkdir()
    (checks / "empty.py").write_text(_EMPTY_MODULE, encoding="utf-8")
    code, text = _run(checks_dir=checks, default_root=tmp_path)
    assert code == 0
    assert "empty: scanned 0 files (nothing was checked)" in text


def test_a_crashing_subcommand_exits_2_not_0(tmp_path: Path) -> None:
    checks = tmp_path / "checks"
    checks.mkdir()
    (checks / "boom.py").write_text("def check(root):\n    raise KeyError('x')\n", encoding="utf-8")
    code, text = _run(checks_dir=checks, default_root=tmp_path)
    assert code == 2 and "internal error: KeyError" in text


def test_a_module_without_check_makes_the_gate_exit_2(tmp_path: Path) -> None:
    checks = tmp_path / "checks"
    checks.mkdir()
    (checks / "nocheck.py").write_text("X = 1\n", encoding="utf-8")
    assert _run(checks_dir=checks, default_root=tmp_path)[0] == 2


def test_unknown_subcommand_and_empty_directory_exit_2(tmp_path: Path) -> None:
    assert _run("nope")[0] == 2
    assert _run(checks_dir=tmp_path, default_root=tmp_path)[0] == 2


def test_selftest_fails_for_a_gate_that_never_fails(tmp_path: Path) -> None:
    checks = tmp_path / "checks"
    fixtures = tmp_path / "fixtures"
    checks.mkdir()
    (checks / "lax.py").write_text(_PASS_MODULE, encoding="utf-8")
    (fixtures / "lax" / "pass-ok").mkdir(parents=True)
    (fixtures / "lax" / "fail-bad").mkdir(parents=True)
    (fixtures / "lax" / "fail-bad" / "EXPECT").write_text("1 range\n", encoding="utf-8")
    code, text = _run("lax", "--selftest", checks_dir=checks, fixtures_dir=fixtures)
    assert code == 1 and "fail-bad: expected exit 1, got 0" in text


def test_selftest_fails_without_fixtures_and_for_a_wrong_reason(tmp_path: Path) -> None:
    checks = tmp_path / "checks"
    fixtures = tmp_path / "fixtures"
    checks.mkdir()
    shutil.copy(REPO / "scripts" / "supply_chain_checks" / "policy.py", checks / "policy.py")
    code, text = _run("policy", "--selftest", checks_dir=checks, fixtures_dir=fixtures)
    assert code == 1 and "no pass-* fixture" in text and "no fail-* fixture" in text
    shutil.copytree(FIXTURES, fixtures / "policy")
    (fixtures / "policy" / "fail-unknown-key" / "EXPECT").write_text("1 overlap\n", encoding="utf-8")
    code, text = _run("policy", "--selftest", checks_dir=checks, fixtures_dir=fixtures)
    assert code == 1 and "no 'overlap' line" in text


def test_the_policy_gate_catches_a_real_policy_mutated_in_place(tmp_path: Path) -> None:
    doc = json.loads((REPO / POLICY_REL).read_text(encoding="utf-8"))
    doc["opening_threshold"]["open_if_malicious"] = False
    target = tmp_path / POLICY_REL
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    code, text = _run("policy", "--root", str(tmp_path))
    assert code == 1 and "open_if_malicious" in text


def test_script_runs_as_a_process_and_exit_code_is_the_result() -> None:
    ok = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "check_supply_chain.py")],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    bad = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "check_supply_chain.py"), "--root", str(_case("fail-unknown-key"))],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    assert (ok.returncode, bad.returncode) == (0, 1)


def test_makefile_declares_the_target_phony_and_test_depends_on_it() -> None:
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    phony = next(line for line in makefile.splitlines() if line.startswith(".PHONY: help"))
    assert "check-supply-chain" in phony.split()
    test_rule = next(line for line in makefile.splitlines() if line.startswith("test:"))
    assert "check-supply-chain" in test_rule.split("##")[0].split()
    assert re.search(r"^check-supply-chain:.*\n\t.*check_supply_chain\.py\b", makefile, re.M)

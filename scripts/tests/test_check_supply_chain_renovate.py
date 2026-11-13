"""Tests of the ``renovate`` subcommand of the supply-chain gate."""

from __future__ import annotations

import io
import json
import re
import shutil
from pathlib import Path

import check_supply_chain as gate
import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURES = gate.FIXTURES_DIR / "renovate"
MODULE = REPO / "scripts" / "supply_chain_checks" / "renovate.py"


@pytest.fixture
def checks(tmp_path: Path) -> Path:
    """A checks directory holding only this subcommand (other modules are other tasks')."""
    target = tmp_path / "_checks"
    target.mkdir()
    shutil.copy(MODULE, target / "renovate.py")
    return target


def _run(checks: Path, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = gate.main(["renovate", *argv], out=out, checks_dir=checks)
    return code, out.getvalue()


def _copy(case: str, tmp_path: Path) -> Path:
    dest = tmp_path / "root"
    shutil.copytree(FIXTURES / case, dest)
    return dest


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("fail-")))
def test_each_failing_fixture_fails_for_its_stated_reason(checks: Path, case: str) -> None:
    want_code, kind = (FIXTURES / case / "EXPECT").read_text(encoding="utf-8").splitlines()[0].split()
    code, text = _run(checks, "--root", str(FIXTURES / case))
    assert code == int(want_code)
    assert f": {kind}:" in text
    assert str(FIXTURES) not in text
    for line in text.splitlines()[:-1]:
        assert re.match(r"^[^:\s]+:\d+: \w+: .+", line), line


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("pass-")))
def test_each_good_fixture_passes_and_scans_files(checks: Path, case: str) -> None:
    code, text = _run(checks, "--root", str(FIXTURES / case))
    assert code == 0, text
    assert "0 violation(s)" in text and "scanned 0" not in text


def test_the_real_repository_passes(checks: Path) -> None:
    code, text = _run(checks, "--root", str(REPO))
    assert code == 0, text
    assert re.search(r"scanned [1-9]\d* file\(s\), 0 violation", text)


def test_selftest_passes_with_failing_and_good_inputs(checks: Path) -> None:
    code, text = _run(checks, "--selftest")
    assert code == 0 and "selftest ok" in text


def test_the_real_preset_fails_when_a_value_is_changed(checks: Path, tmp_path: Path) -> None:
    root = tmp_path / "real"
    (root / "renovate").mkdir(parents=True)
    (root / "docs" / "agent").mkdir(parents=True)
    shutil.copy(REPO / "renovate" / "supply-chain.json", root / "renovate")
    shutil.copy(REPO / "docs" / "agent" / "supply-chain-policy.json", root / "docs" / "agent")
    assert _run(checks, "--root", str(root))[0] == 0
    preset = root / "renovate" / "supply-chain.json"
    data = json.loads(preset.read_text(encoding="utf-8"))
    data["vulnerabilityAlerts"]["automerge"] = True
    preset.write_text(json.dumps(data, indent=2), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and ": automerge:" in text


def test_the_expected_value_comes_from_the_policy_file(checks: Path, tmp_path: Path) -> None:
    root = _copy("pass-base-only", tmp_path)
    policy = root / "docs" / "agent" / "supply-chain-policy.json"
    text = policy.read_text(encoding="utf-8")
    for key in ("cooldown_days", "package_manager_wait"):
        data = json.loads(text)
        data[key] = {k: v + 1 for k, v in data[key].items()}
        text = json.dumps(data, indent=2)
    policy.write_text(text, encoding="utf-8")
    code, out = _run(checks, "--root", str(root))
    assert code == 1
    assert "minimumReleaseAge is 3 days; Policy_File wants 4" in out
    assert "major minimumReleaseAge is 7 days; Policy_File wants 8" in out


def test_violation_line_points_at_the_offending_key(checks: Path) -> None:
    case = FIXTURES / "fail-cooldown-mismatch"
    first = _run(checks, "--root", str(case))[1].splitlines()[0]
    line_no = int(first.split(":")[1])
    source = (case / "renovate" / "supply-chain.json").read_text(encoding="utf-8").split("\n")
    assert '"minimumReleaseAge"' in source[line_no - 1]


def test_an_invalid_policy_file_is_one_violation_and_broken_json_is_unparseable(checks: Path, tmp_path: Path) -> None:
    root = _copy("pass-base-only", tmp_path)
    policy = root / "docs" / "agent" / "supply-chain-policy.json"
    policy.write_text("{}", encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and ": policy:" in text and "Run the policy subcommand" in text
    policy.write_text("{", encoding="utf-8")
    assert _run(checks, "--root", str(root))[0] == 2


def test_a_preset_that_is_not_json_is_unparseable(checks: Path, tmp_path: Path) -> None:
    root = _copy("pass-base-only", tmp_path)
    (root / "renovate" / "supply-chain.json").write_text("{", encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 2 and "not valid JSON" in text

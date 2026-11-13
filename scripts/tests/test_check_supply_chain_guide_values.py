"""Tests of the ``guide-values`` subcommand of the supply-chain gate."""

from __future__ import annotations

import io
import re
import shutil
from pathlib import Path

import check_supply_chain as gate
import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURES = gate.FIXTURES_DIR / "guide-values"
MODULE = REPO / "scripts" / "supply_chain_checks" / "guide_values.py"
GUIDES = ("docs/ja/supply-chain-adoption-guide.md", "docs/en/supply-chain-adoption-guide.md")
POLICY = "docs/agent/supply-chain-policy.json"


@pytest.fixture
def checks(tmp_path: Path) -> Path:
    """A checks directory holding only this subcommand."""
    target = tmp_path / "_checks"
    target.mkdir()
    shutil.copy(MODULE, target / "guide_values.py")
    return target


def _run(checks: Path, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = gate.main(["guide-values", *argv], out=out, checks_dir=checks)
    return code, out.getvalue()


def _real_copy(tmp_path: Path) -> Path:
    root = tmp_path / "real"
    for rel in (*GUIDES, POLICY):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, root / rel)
    return root


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("fail-")))
def test_each_failing_fixture_fails_for_its_stated_reason(checks: Path, case: str) -> None:
    want_code, kind = (FIXTURES / case / "EXPECT").read_text(encoding="utf-8").splitlines()[0].split()
    code, text = _run(checks, "--root", str(FIXTURES / case))
    assert code == int(want_code)
    assert f": {kind}:" in text
    for line in text.splitlines()[:-1]:
        assert re.match(r"^[^:\s]+:\d+: \w+: .+", line), line


def test_the_good_fixture_passes_and_scans_files(checks: Path) -> None:
    code, text = _run(checks, "--root", str(FIXTURES / "pass-valid"))
    assert code == 0, text
    assert "scanned 3 file(s), 0 violation" in text


def test_the_real_repository_passes(checks: Path) -> None:
    code, text = _run(checks, "--root", str(REPO))
    assert code == 0, text
    assert re.search(r"scanned [3-9]\d* file\(s\), 0 violation", text)


def test_selftest_passes(checks: Path) -> None:
    code, text = _run(checks, "--selftest")
    assert code == 0 and "selftest ok" in text


@pytest.mark.parametrize("guide", GUIDES)
def test_a_real_guide_with_one_value_rewritten_fails(checks: Path, tmp_path: Path, guide: str) -> None:
    root = _real_copy(tmp_path)
    assert _run(checks, "--root", str(root))[0] == 0
    path = root / guide
    text = path.read_text(encoding="utf-8")
    changed, count = re.subn(r"(<!-- policy:response_target\.fix_days_high -->)14", r"\g<1>30", text, count=1)
    assert count == 1
    path.write_text(changed, encoding="utf-8")
    code, out = _run(checks, "--root", str(root))
    assert code == 1
    assert f"{guide}:" in out and ": mismatch:" in out and "Policy_File wants 14" in out


def test_the_expected_value_comes_from_the_policy_file(checks: Path, tmp_path: Path) -> None:
    root = _real_copy(tmp_path)
    policy = root / POLICY
    policy.write_text(
        policy.read_text(encoding="utf-8").replace('"fix_days_high": 14', '"fix_days_high": 30'), encoding="utf-8"
    )
    code, out = _run(checks, "--root", str(root))
    assert code == 1 and out.count(": mismatch:") >= 2 and "Policy_File wants 30" in out


def test_a_marker_without_a_number_is_a_violation(checks: Path, tmp_path: Path) -> None:
    root = _real_copy(tmp_path)
    path = root / GUIDES[1]
    path.write_text(
        path.read_text(encoding="utf-8") + "\n<!-- policy:cooldown_days.default --> three days\n", encoding="utf-8"
    )
    code, out = _run(checks, "--root", str(root))
    assert code == 1 and ": format:" in out


def test_a_broken_policy_file_or_an_absent_guide_is_unparseable(checks: Path, tmp_path: Path) -> None:
    root = _real_copy(tmp_path)
    (root / POLICY).write_text("{", encoding="utf-8")
    assert _run(checks, "--root", str(root))[0] == 2
    root = _real_copy(tmp_path / "again")
    (root / GUIDES[0]).unlink()
    assert _run(checks, "--root", str(root))[0] == 2


def test_a_tree_without_any_guide_is_not_checked(checks: Path, tmp_path: Path) -> None:
    (tmp_path / "docs" / "agent").mkdir(parents=True)
    shutil.copy(REPO / POLICY, tmp_path / POLICY)
    code, text = _run(checks, "--root", str(tmp_path))
    assert code == 0 and "scanned 0 files (nothing was checked)" in text

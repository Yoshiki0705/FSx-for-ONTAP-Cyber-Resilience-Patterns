"""Tests of the ``wa-consistency`` subcommand of the supply-chain gate."""

from __future__ import annotations

import io
import re
import shutil
from pathlib import Path

import check_supply_chain as gate
import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURES = gate.FIXTURES_DIR / "wa-consistency"
MODULE = REPO / "scripts" / "supply_chain_checks" / "wa_consistency.py"
DOCS = tuple(
    f"docs/{lang}/{name}.md"
    for lang in ("ja", "en")
    for name in ("cyber-resilience-framework-mapping", "cyber-resilience-programme", "supply-chain-adoption-guide")
)
PROGRAMME_JA, PROGRAMME_EN = "docs/ja/cyber-resilience-programme.md", "docs/en/cyber-resilience-programme.md"
GUIDE_EN = "docs/en/supply-chain-adoption-guide.md"
MAPPING_EN = "docs/en/cyber-resilience-framework-mapping.md"


@pytest.fixture
def checks(tmp_path: Path) -> Path:
    """A checks directory holding only this subcommand."""
    target = tmp_path / "_checks"
    target.mkdir()
    shutil.copy(MODULE, target / "wa_consistency.py")
    return target


def _run(checks: Path, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = gate.main(["wa-consistency", *argv], out=out, checks_dir=checks)
    return code, out.getvalue()


def _real_copy(tmp_path: Path) -> Path:
    root = tmp_path / "real"
    for rel in DOCS:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, root / rel)
    return root


def _append(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


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
    assert "scanned 6 file(s), 0 violation" in text


def test_the_real_repository_passes(checks: Path) -> None:
    code, text = _run(checks, "--root", str(REPO))
    assert code == 0, text
    assert re.search(r"scanned [6-9]\d* file\(s\), 0 violation", text)


def test_selftest_passes(checks: Path) -> None:
    code, text = _run(checks, "--selftest")
    assert code == 0 and "selftest ok" in text


@pytest.mark.parametrize(
    ("rel", "extra", "kind"),
    [
        (PROGRAMME_JA, "\nSEC11-BP99\n", "unknown_bp_id"),
        (GUIDE_EN, "\n| copy | SEC11-BP02, SEC11-BP05 |\n", "table_copy"),
        (GUIDE_EN, "\nGV.ZZ-01\n", "unknown_csf_id"),
        (PROGRAMME_EN, "\n| Check | GV.OV-03, ID.IM-01 |\n", "csf_table_copy"),
    ],
)
def test_a_real_document_with_one_addition_fails(checks: Path, tmp_path: Path, rel: str, extra: str, kind: str) -> None:
    root = _real_copy(tmp_path)
    assert _run(checks, "--root", str(root))[0] == 0
    _append(root, rel, extra)
    code, out = _run(checks, "--root", str(root))
    assert code == 1 and f"{rel}:" in out and f": {kind}:" in out


def test_the_english_best_practice_table_with_one_row_removed_fails(checks: Path, tmp_path: Path) -> None:
    root = _real_copy(tmp_path)
    path = root / MAPPING_EN
    rows = path.read_text(encoding="utf-8").split("\n")
    index = next(i for i, row in enumerate(rows) if row.startswith("| PDCA Act | [OPS11-BP02"))
    del rows[index]
    path.write_text("\n".join(rows), encoding="utf-8")
    code, out = _run(checks, "--root", str(root))
    assert code == 1 and ": language_mismatch:" in out and "OPS11-BP02" in out


def test_a_category_id_is_known_through_its_subcategories(checks: Path) -> None:
    code, text = _run(checks, "--root", str(FIXTURES / "pass-valid"))
    assert code == 0 and "GV.OV" in (FIXTURES / "pass-valid" / "docs/en/supply-chain-adoption-guide.md").read_text(
        encoding="utf-8"
    )


def test_an_absent_document_is_unparseable(checks: Path, tmp_path: Path) -> None:
    root = _real_copy(tmp_path)
    (root / PROGRAMME_JA).unlink()
    assert _run(checks, "--root", str(root))[0] == 2


def test_a_tree_without_any_of_the_documents_is_not_checked(checks: Path, tmp_path: Path) -> None:
    code, text = _run(checks, "--root", str(tmp_path))
    assert code == 0 and "scanned 0 files (nothing was checked)" in text

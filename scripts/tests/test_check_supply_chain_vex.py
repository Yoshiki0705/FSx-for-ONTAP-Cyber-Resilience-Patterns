"""Tests of the ``vex`` subcommand of the supply-chain gate."""

from __future__ import annotations

import io
import json
import logging
import re
from pathlib import Path

import check_supply_chain as gate
import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURES = gate.FIXTURES_DIR / "vex"
_DOC = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://example.com/vex/1",
    "author": "https://github.com/example-org/example-repo",
    "role": "VEX_Reviewer",
    "timestamp": "2026-01-01T00:00:00Z",
    "version": 1,
    "statements": [
        {
            "vulnerability": {"name": "CVE-2026-0001"},
            "products": [{"@id": "pkg:npm/example-lib@1.2.3"}],
            "status": "not_affected",
            "justification": "component_not_present",
        }
    ],
}


def _run(root: Path) -> tuple[int, str]:
    out = io.StringIO()
    code = gate.main(["vex", "--root", str(root)], out=out)
    return code, out.getvalue()


def _write(root: Path, rel: str, text: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("fail-")))
def test_each_failing_fixture_fails_for_its_stated_reason(case: str) -> None:
    want_code, kind = (FIXTURES / case / "EXPECT").read_text(encoding="utf-8").splitlines()[0].split()
    code, text = _run(FIXTURES / case)
    assert code == int(want_code)
    assert f": {kind}:" in text
    for line in text.splitlines()[:-1]:
        assert re.match(r"^[^:\s]+:\d+: \w[\w-]*: .+", line), line


@pytest.mark.parametrize("case", ["pass-valid", "pass-evidence", "pass-malicious-warning"])
def test_good_fixtures_pass_and_count_one_document(case: str) -> None:
    code, text = _run(FIXTURES / case)
    assert code == 0
    assert text.strip() == "vex: scanned 1 file(s), 0 violation(s)"


def test_no_vex_directory_scans_zero_files_and_succeeds(tmp_path: Path) -> None:
    code, text = _run(tmp_path)
    assert code == 0
    assert text.strip() == "vex: scanned 0 files (nothing was checked), 0 violation(s)"


def test_real_repository_passes() -> None:
    code, text = _run(REPO)
    assert code == 0, text


def test_malicious_statement_warns_without_failing(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        code, _ = _run(FIXTURES / "pass-malicious-warning")
    assert code == 0
    assert any("MAL-" in r.getMessage() and r.levelno == logging.WARNING for r in caplog.records)


def test_every_violation_is_reported_across_files(tmp_path: Path) -> None:
    bad = json.loads(json.dumps(_DOC))
    del bad["statements"][0]["justification"]
    _write(tmp_path, ".vex/a.openvex.json", json.dumps(bad, indent=2))
    two = json.loads(json.dumps(_DOC))
    two["statements"] = two["statements"] * 2
    _write(tmp_path, ".vex/b.openvex.json", json.dumps(two, indent=2))
    _write(tmp_path, "Makefile", "scan:\n\ttrivy fs --vex=.vex/a.openvex.json .\n")
    code, text = _run(tmp_path)
    assert code == 1
    for kind in ("schema", "statement-count", "vex-to-scanner"):
        assert f": {kind}:" in text
    assert "scanned 2 file(s), 3 violation(s)" in text


@pytest.mark.parametrize(
    "line",
    [
        "      - run: trivy image --vex .vex/x.openvex.json img",
        "      - run: grype dir:. --vex=x.json",
        "        env: { TRIVY_VEX: x.json }",
        "      - run: osv-scanner --lockfile=a.json .vex/x.openvex.json",
    ],
)
def test_scanner_receiving_vex_is_a_violation(tmp_path: Path, line: str) -> None:
    _write(tmp_path, ".github/workflows/scan.yml", f"jobs:\n  scan:\n    steps:\n{line}\n")
    code, text = _run(tmp_path)
    assert code == 1
    assert ".github/workflows/scan.yml:4: vex-to-scanner:" in text


@pytest.mark.parametrize(
    "line",
    [
        "      - run: trivy fs --exit-code 1 .",
        "      # trivy fs --vex x.json is forbidden",
        "      - run: python3 scripts/check_supply_chain.py vex --root .vex",
        "      - run: echo done # --vex",
    ],
)
def test_other_lines_are_not_violations(tmp_path: Path, line: str) -> None:
    _write(tmp_path, ".github/workflows/scan.yml", f"jobs:\n  scan:\n    steps:\n{line}\n")
    code, _ = _run(tmp_path)
    assert code == 0


def test_evidence_is_not_required_for_other_justifications(tmp_path: Path) -> None:
    _write(tmp_path, ".vex/a.openvex.json", json.dumps(_DOC))
    assert _run(tmp_path)[0] == 0


def test_schema_violation_names_the_statement_location(tmp_path: Path) -> None:
    bad = json.loads(json.dumps(_DOC))
    bad["statements"][0]["status"] = "unknown"
    _write(tmp_path, ".vex/a.openvex.json", json.dumps(bad, indent=2))
    code, text = _run(tmp_path)
    assert code == 1
    assert "statements[0].status" in text

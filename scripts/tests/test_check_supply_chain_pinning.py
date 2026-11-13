"""Tests of the ``pinning`` supply-chain gate subcommand (task 11.5)."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

import check_supply_chain as gate
import pytest
from supply_chain_checks import pinning
from supply_chain_checks._common import Unparseable

REPO = Path(__file__).resolve().parents[2]
FIXTURES = gate.FIXTURES_DIR / "pinning"
POLICY_REL = Path("docs/agent/supply-chain-policy.json")
SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
HUB = "Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook"


def _kinds(case: str) -> list[tuple[str, int, str]]:
    report = pinning.check(FIXTURES / case)
    return [(v.path, v.line, v.kind) for v in report.violations]


def _write(root: Path, rel: str, text: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _workflow(root: Path, *steps: str) -> None:
    body = "".join(f"      - {s}\n" for s in steps)
    _write(root, ".github/workflows/ci.yml", "name: ci\njobs:\n  b:\n    steps:\n" + body)


def test_pass_fixture_is_clean_and_dev_range_is_not_a_finding() -> None:
    """``pydot>=2.0.0`` in requirements-dev.txt and a range under ``tests/`` are out of scope."""
    pass_dir = FIXTURES / "pass-exact"
    assert "pydot>=2.0.0" in (pass_dir / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "pytest>=8" in (pass_dir / "tests" / "requirements.txt").read_text(encoding="utf-8")
    report = pinning.check(pass_dir)
    assert report.violations == []
    assert report.scanned >= 6


def test_python_ranges_are_all_reported_with_line_and_spec() -> None:
    """Every range is reported, none stops the scan; ``===`` and ``==2024.*`` are ranges."""
    report = pinning.check(FIXTURES / "fail-python-range")
    found = {(v.line, v.kind) for v in report.violations}
    assert found == {(1, "range"), (3, "range"), (4, "range"), (5, "range"), (6, "range")}
    boto3 = next(v for v in report.violations if v.line == 1)
    assert "boto3" in boto3.detail and ">=1.34.0" in boto3.detail
    assert "(no version)" in next(v for v in report.violations if v.line == 3).detail


def test_npm_ranges_are_all_reported() -> None:
    """^, latest, empty, 1.x, ` - ` and `||` are ranges; the exact version is not."""
    lines = {line for _, line, kind in _kinds("fail-npm-range") if kind == "range"}
    assert lines == {3, 5, 6, 7, 8, 9}


def test_pyproject_dependencies_are_checked_with_their_line() -> None:
    assert _kinds("fail-pyproject-range") == [("pyproject.toml", 4, "range")]


def test_requirements_include_is_followed() -> None:
    assert _kinds("fail-include-range") == [("base/common.txt", 1, "range")]


def test_non_version_specs_count_as_failures() -> None:
    kinds = _kinds("fail-undeterminable")
    assert sorted(kinds) == [
        ("package.json", 1, "undeterminable"),
        ("requirements.txt", 2, "undeterminable"),
        ("requirements.txt", 3, "undeterminable"),
        ("requirements.txt", 4, "undeterminable"),
    ]


def test_third_party_actions_need_a_full_sha() -> None:
    """A tag, a short SHA and a missing ref fail; a 40-character SHA passes."""
    lines = sorted(line for _, line, kind in _kinds("fail-action-tag") if kind == "unpinned-action")
    assert lines == [7, 9, 10]


def test_images_need_a_digest_in_every_form() -> None:
    kinds = _kinds("fail-image-tag")
    assert sorted(line for _, line, _ in kinds) == [7, 8, 11]
    assert {kind for _, _, kind in kinds} == {"unpinned-image"}


def test_tools_at_latest_or_without_a_version_fail() -> None:
    kinds = _kinds("fail-tool-latest")
    assert sorted(line for _, line, _ in kinds) == [7, 8, 9]
    assert {kind for _, _, kind in kinds} == {"unpinned-tool"}


def test_mismatch_names_the_dependency_and_each_file() -> None:
    report = pinning.check(FIXTURES / "fail-mismatch")
    assert [v.kind for v in report.violations] == ["mismatch"]
    detail = report.violations[0].detail
    assert "boto3" in detail and "requirements.txt:1" in detail and "pyproject.toml:4" in detail
    assert "requests" not in detail  # the equal declaration is not reported


def test_mismatch_across_an_include_is_compared() -> None:
    assert [k for _, _, k in _kinds("fail-mismatch-via-include")] == ["mismatch"]


def test_separately_deployed_lambdas_are_not_compared() -> None:
    """lambda-a pins requests 2.31.0 and lambda-b 2.32.3: no finding (Requirement 13.4)."""
    assert pinning.check(FIXTURES / "pass-exact").violations == []


def test_hub_reusable_workflow_tag_is_provisional_until_the_pilot(tmp_path: Path) -> None:
    """Before the pilot a Hub tag passes; after it only a 40-character SHA does (Q-16)."""
    ref = f"uses: {HUB}/.github/workflows/gate.yml@"
    _workflow(tmp_path, ref + "supply-chain-v1.0.0")
    assert pinning.check(tmp_path, hub_sha_required=False).violations == []
    assert pinning.HUB_SHA_REQUIRED is False
    after = pinning.check(tmp_path, hub_sha_required=True)
    assert [v.kind for v in after.violations] == ["unpinned-reusable"]
    _workflow(tmp_path, ref + SHA)
    assert pinning.check(tmp_path, hub_sha_required=True).violations == []
    _workflow(tmp_path, ref + "main")
    assert [v.kind for v in pinning.check(tmp_path, hub_sha_required=False).violations] == ["unpinned-reusable"]


def test_non_production_paths_come_from_the_policy(tmp_path: Path) -> None:
    """Without the Policy_File nothing is excluded, so the range under ``tests/`` is found."""
    shutil.copytree(FIXTURES / "pass-exact", tmp_path / "r")
    assert pinning.check(tmp_path / "r").violations == []
    (tmp_path / "r" / POLICY_REL).unlink()
    kinds = {(v.path, v.kind) for v in pinning.check(tmp_path / "r").violations}
    assert ("tests/requirements.txt", "range") in kinds
    assert ("ui/tests/package.json", "range") in kinds


def test_invalid_policy_is_left_to_the_policy_subcommand(tmp_path: Path) -> None:
    """An invalid Policy_File excludes nothing and does not raise (exit stays 1, not 2)."""
    _write(tmp_path, str(POLICY_REL), '{"schema_version": 1}')
    _write(tmp_path, "requirements.txt", "boto3==1.0.0\n")
    _write(tmp_path, "tests/requirements.txt", "boto3>=1\n")
    report = pinning.check(tmp_path)
    assert [(v.path, v.kind) for v in report.violations] == [("tests/requirements.txt", "range")]


def test_unreadable_manifest_is_unparseable(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", "{not json")
    with pytest.raises(Unparseable):
        pinning.check(tmp_path)


def test_optional_criteria_warn_but_never_fail(caplog: pytest.LogCaptureFixture) -> None:
    """Hash-less requirements are logged as optional findings and leave the report clean."""
    with caplog.at_level(logging.WARNING, logger=pinning.__name__):
        report = pinning.check(FIXTURES / "pass-exact")
    assert report.violations == []
    assert any("no-hashes" in r.getMessage() for r in caplog.records)
    kinds = {f.kind for f in pinning.optional_findings(FIXTURES / "pass-exact")}
    assert kinds == {"no-hashes"}


def test_optional_npm_criteria(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", '{"dependencies": {"a": "1.0.0"}}\n')
    _write(tmp_path, "package-lock.json", "{}\n")
    kinds = {f.kind for f in pinning.optional_findings(tmp_path)}
    assert kinds == {"no-strict-allow-scripts", "no-allow-scripts"}
    _write(tmp_path, ".npmrc", "strict-allow-scripts=true\n")
    _write(tmp_path, "package.json", '{"dependencies": {"a": "1.0.0"}, "allowScripts": {}}\n')
    assert pinning.optional_findings(tmp_path) == []


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("==1.2.3", None),
        ("== 1.2.3", None),
        ("", "range"),
        (">=1.2", "range"),
        ("===1.2.3", "range"),
        ("==1.*", "range"),
        ("==1.0,<2", "range"),
        ("git+https://example.com/x.git", "undeterminable"),
    ],
)
def test_python_spec_classification(spec: str, expected: str | None) -> None:
    assert pinning._classify_py(spec) == expected


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("1.2.3", None),
        ("1.2.3-rc.1", None),
        ("^1.2.3", "range"),
        ("~1.2.3", "range"),
        ("*", "range"),
        ("latest", "range"),
        ("1.x", "range"),
        ("", "range"),
        ("file:../x", "undeterminable"),
    ],
)
def test_npm_spec_classification(spec: str, expected: str | None) -> None:
    assert pinning._classify_npm(spec) == expected


def test_the_repository_itself_passes() -> None:
    """The real manifests and workflows hold the pins (boto3/botocore are exact)."""
    report = pinning.check(REPO)
    assert [v.format() for v in report.violations] == []
    assert report.scanned >= 1

"""cfn-guard rule files: they parse, and each rule passes and fails as intended.

A rule file that does not parse makes ``cfn-guard validate`` exit 5 without
evaluating a single resource. The Makefile target swallows that exit code, so
a parse failure looks like a clean run. These tests call the real binary:

* every file in ``security/guard-rules/`` parses (``cfn-guard parse-tree``);
* every rule has a fixture it passes and a fixture it fails;
* the pass fixtures make the named rule PASS, the fail fixtures make it FAIL.

If ``cfn-guard`` is not on PATH the tests fail. Setting
``ALLOW_MISSING_CFN_GUARD=1`` turns that into a skip with a visible reason;
use it only where the binary cannot be installed.

**Validates: Requirements 24.7, 24.8, 19.4**
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "security" / "guard-rules"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "guard"
OPT_OUT_ENV = "ALLOW_MISSING_CFN_GUARD"
EXIT_FAILED_RULES = 19

_RULE_RE = re.compile(r"^rule\s+(\w+)", re.MULTILINE)


def _rules_by_file() -> dict[str, list[str]]:
    """Map each rule file name to the rule names it defines."""
    return {path.name: _RULE_RE.findall(path.read_text(encoding="utf-8")) for path in sorted(RULES_DIR.glob("*.guard"))}


def _rule_cases() -> list[tuple[str, str]]:
    """Return (rule file name, rule name) for every rule."""
    return [(f, r) for f, names in _rules_by_file().items() for r in names]


def _fixtures(rule: str, kind: str) -> list[Path]:
    """Return fixtures for a rule: ``<rule>.<kind>.yaml`` and ``<rule>.<kind>-*.yaml``."""
    return sorted(
        p
        for p in FIXTURES_DIR.glob(f"{rule}.{kind}*.yaml")
        if p.name == f"{rule}.{kind}.yaml" or p.name.startswith(f"{rule}.{kind}-")
    )


@pytest.fixture(scope="module")
def cfn_guard() -> str:
    """Path to the cfn-guard binary; fails (or skips if opted out) when absent."""
    found = shutil.which("cfn-guard")
    if found:
        return found
    if os.environ.get(OPT_OUT_ENV) == "1":
        pytest.skip(f"cfn-guard not on PATH and {OPT_OUT_ENV}=1")
    pytest.fail(
        "cfn-guard is not on PATH. Install cfn-guard 3.x, or set "
        f"{OPT_OUT_ENV}=1 to skip these tests where it cannot be installed."
    )


def _run(binary: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [binary, *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _status(output: str, rule_file: str, rule: str) -> str | None:
    """Return PASS/FAIL/SKIP for a rule from the validate summary, or None."""
    pattern = re.compile(
        rf"^{re.escape(rule_file)}/{re.escape(rule)}\s+(PASS|FAIL|SKIP)\s*$",
        re.MULTILINE,
    )
    match = pattern.search(output)
    return match.group(1) if match else None


def test_rule_files_exist() -> None:
    """The directory holds rule files and every file defines at least one rule."""
    by_file = _rules_by_file()
    assert by_file, f"no .guard files in {RULES_DIR}"
    assert all(names for names in by_file.values()), by_file


@pytest.mark.parametrize("rule_file", sorted(_rules_by_file()))
def test_rule_file_parses(cfn_guard: str, rule_file: str) -> None:
    """``cfn-guard parse-tree`` accepts the rule file (exit code 0)."""
    result = _run(cfn_guard, "parse-tree", "--rules", str(RULES_DIR / rule_file))
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(("rule_file", "rule"), _rule_cases())
def test_every_rule_has_pass_and_fail_fixtures(rule_file: str, rule: str) -> None:
    """A rule without both kinds of fixture is untested in one direction."""
    assert _fixtures(rule, "pass"), f"{rule_file}/{rule}: no pass fixture"
    assert _fixtures(rule, "fail"), f"{rule_file}/{rule}: no fail fixture"


def test_no_fixture_names_an_unknown_rule() -> None:
    """A fixture left behind after a rule is renamed would test nothing."""
    known = {rule for _, rule in _rule_cases()}
    orphans = sorted(p.name for p in FIXTURES_DIR.glob("*.yaml") if p.name.split(".", 1)[0] not in known)
    assert not orphans, orphans


@pytest.mark.parametrize(("rule_file", "rule"), _rule_cases())
def test_pass_fixtures_satisfy_the_rule(cfn_guard: str, rule_file: str, rule: str) -> None:
    """Each pass fixture makes the rule PASS and the whole file exit 0."""
    for fixture in _fixtures(rule, "pass"):
        result = _run(
            cfn_guard,
            "validate",
            "--rules",
            str(RULES_DIR / rule_file),
            "--data",
            str(fixture),
            "--show-summary",
            "all",
        )
        assert _status(result.stdout, rule_file, rule) == "PASS", (
            fixture.name,
            result.returncode,
            result.stdout + result.stderr,
        )
        assert result.returncode == 0, (fixture.name, result.stdout + result.stderr)


@pytest.mark.parametrize(("rule_file", "rule"), _rule_cases())
def test_fail_fixtures_violate_the_rule(cfn_guard: str, rule_file: str, rule: str) -> None:
    """Each fail fixture makes the rule FAIL and the exit code 19."""
    for fixture in _fixtures(rule, "fail"):
        result = _run(
            cfn_guard,
            "validate",
            "--rules",
            str(RULES_DIR / rule_file),
            "--data",
            str(fixture),
            "--show-summary",
            "all",
        )
        assert _status(result.stdout, rule_file, rule) == "FAIL", (
            fixture.name,
            result.returncode,
            result.stdout + result.stderr,
        )
        assert result.returncode == EXIT_FAILED_RULES, (
            fixture.name,
            result.returncode,
        )

"""Property 17 of the supply-chain gate: the Cooldown agreement gate (task 11.4).

The ``renovate`` subcommand succeeds on the Cooldown values only when the preset's default and
``major`` waits are both present, positive whole days, ``major >= default`` and equal to the
Policy_File; otherwise it fails and names the update type and both values.
"""

from __future__ import annotations

import io
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import check_supply_chain as gate
import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain_checks import renovate
from supply_chain_checks._common import Violation

REPO = Path(__file__).resolve().parents[2]
BASE = gate.FIXTURES_DIR / "renovate" / "pass-base-only"
POLICY_REL = "docs/agent/supply-chain-policy.json"
PRESET_REL = "renovate/supply-chain.json"
ABSENT = "absent"


@dataclass(frozen=True)
class Field:
    """One generated Cooldown field of the preset.

    Attributes:
        shape: ``absent``, ``null``, ``match`` (the Policy_File value), ``days``, ``text`` or ``raw``.
        value: The JSON value written (unused for ``absent`` and ``match``).
    """

    shape: str
    value: Any = None


def _field() -> st.SearchStrategy[Field]:
    return st.one_of(
        st.just(Field(ABSENT)),
        st.just(Field("null")),
        st.just(Field("match")),
        st.integers(-3, 30).map(lambda n: Field("days", n)),
        st.sampled_from(["3.5 days", "three days", "1 week", "", "3 hours", "days", "3days x"]).map(
            lambda s: Field("text", s)
        ),
        st.sampled_from([3, True, 3.5, ["3 days"], {"days": 3}]).map(lambda v: Field("raw", v)),
    )


def _written(f: Field, want: int) -> Any:
    if f.shape == "match":
        return f"{want} days"
    if f.shape == "days":
        return f"{f.value} day" if f.value == 1 else f"{f.value} days"
    return f.value


def _parsed(f: Field, want: int) -> tuple[str, int | None]:
    """Oracle: ``(status, days)`` with status missing / format / ok for a field."""
    if f.shape in (ABSENT, "null"):
        return "missing", None
    if f.shape == "match":
        return "ok", want
    if f.shape == "days":
        return "ok", f.value
    return "format", None


@st.composite
def cases(draw: st.DrawFn) -> tuple[int, int, Field, Field]:
    """A policy ``(default, major)`` with ``major >= default`` and the preset's two fields."""
    default = draw(st.integers(1, 14))
    major = default + draw(st.integers(0, 16))
    return default, major, draw(_field()), draw(_field())


def _expected(default: int, major: int, fd: Field, fm: Field) -> list[tuple[str, str]]:
    """Oracle: the expected ``(label, kind)`` pairs; label is ``default``, ``major`` or ``order``."""
    out: list[tuple[str, str]] = []
    results: dict[str, int | None] = {}
    for label, f, want in (("default", fd, default), ("major", fm, major)):
        status, days = _parsed(f, want)
        results[label] = days
        if status != "ok":
            out.append((label, status))
        elif days is not None and days <= 0:
            out.append((label, "range"))
        elif days != want:
            out.append((label, "mismatch"))
    d, m = results["default"], results["major"]
    if d is not None and m is not None and m < d:
        out.append(("order", "range"))
    return out


def _build(root: Path, default: int, major: int, fd: Field, fm: Field) -> None:
    shutil.copytree(BASE, root, dirs_exist_ok=True)
    policy_path = root / POLICY_REL
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["cooldown_days"] = {"default": default, "major": major}
    policy["package_manager_wait"] = {"default_days": default, "major_days": major}
    policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    preset_path = root / PRESET_REL
    preset = json.loads(preset_path.read_text(encoding="utf-8"))
    rule = next(r for r in preset["packageRules"] if "major" in r.get("matchUpdateTypes", []))
    for target, f, want in ((preset, fd, default), (rule, fm, major)):
        if f.shape == ABSENT:
            target.pop("minimumReleaseAge", None)
        else:
            target["minimumReleaseAge"] = _written(f, want)
    preset_path.write_text(json.dumps(preset, indent=2), encoding="utf-8")


def _label(v: Violation) -> str:
    if v.detail.startswith("major (") or v.detail.startswith("major minimumReleaseAge"):
        return "order" if v.detail.startswith("major (") else "major"
    if "major updates a minimumReleaseAge" in v.detail:
        return "major"
    return "default"


def _check_case(root: Path, default: int, major: int, fd: Field, fm: Field) -> list[tuple[str, str]]:
    _build(root, default, major, fd, fm)
    report = renovate.check(root)
    got = sorted((_label(v), v.kind) for v in report.violations)
    want = sorted(_expected(default, major, fd, fm))
    assert got == want, report.violations
    for v in report.violations:
        label = _label(v)
        if label == "order":
            assert re.search(r"major \(-?\d+\) must be >= default \(-?\d+\)", v.detail)
            continue
        fld, wanted = (fd, default) if label == "default" else (fm, major)
        if label == "major":
            assert "major" in v.detail  # the update type
        if v.kind == "mismatch":  # both values: the preset's and the Policy_File's
            assert f"is {_parsed(fld, wanted)[1]} days" in v.detail
            assert f"Policy_File wants {wanted}" in v.detail
        elif v.kind == "missing":  # "absent" is stated, with the Policy_File value
            assert "not set" in v.detail or "no packageRules" in v.detail
            assert f"{wanted} days" in v.detail
    return want


def _gate_exit(checks: Path, root: Path) -> int:
    return gate.main(["renovate", "--root", str(root)], out=io.StringIO(), checks_dir=checks)


@pytest.fixture(scope="module")
def checks(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A checks directory holding only the ``renovate`` subcommand."""
    target = tmp_path_factory.mktemp("checks")
    shutil.copy(REPO / "scripts" / "supply_chain_checks" / "renovate.py", target / "renovate.py")
    return target


# Feature: cyber-resilience-phase4-supply-chain, Property 17: Cooldown の一致ゲート
@given(case=cases())
@settings(max_examples=200, deadline=None)
def test_cooldown_gate_succeeds_only_when_present_positive_ordered_and_equal(
    checks: Path, case: tuple[int, int, Field, Field]
) -> None:
    """Success iff both waits are positive days, major >= default and equal to the Policy_File.

    **Validates: Requirements 12.4, 12.5, 12.6, 12.7, 12.9**
    """
    default, major, fd, fm = case
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "root"
        want = _check_case(root, default, major, fd, fm)
        code = _gate_exit(checks, root)
    event(f"outcome={'pass' if not want else 'fail'}")
    for item in want:
        event(f"violation={item[0]}:{item[1]}")
    assert (code == 0) == (not want)
    assert code in (0, 1)


# Feature: cyber-resilience-phase4-supply-chain, Property 17: Cooldown の一致ゲート
def test_generator_reaches_every_outcome_with_a_fixed_seed() -> None:
    """With ``derandomize=True`` the generator covers success, each failure kind and the order check."""
    seen: set[str] = set()

    @settings(max_examples=300, deadline=None, derandomize=True)
    @given(case=cases())
    def collect(case: tuple[int, int, Field, Field]) -> None:
        default, major, fd, fm = case
        want = _expected(default, major, fd, fm)
        seen.add("pass" if not want else "fail")
        seen.update(f"{label}:{kind}" for label, kind in want)

    collect()
    needed = {"pass", "fail", "order:range"}
    for label in ("default", "major"):
        needed |= {f"{label}:{k}" for k in ("missing", "format", "range", "mismatch")}
    assert needed <= seen, sorted(needed - seen)


# Feature: cyber-resilience-phase4-supply-chain, Property 17: Cooldown の一致ゲート
def test_missing_major_cooldown_names_the_policy_value(checks: Path, tmp_path: Path) -> None:
    """Counterexample: policy (1, 1) with default and major both absent from the preset.

    The major message once lacked the Policy_File value; it must carry ``1 days`` like the default one.

    **Validates: Requirements 12.4, 12.5**
    """
    root = tmp_path / "root"
    want = _check_case(root, 1, 1, Field(ABSENT), Field(ABSENT))
    assert sorted(want) == [("default", "missing"), ("major", "missing")]
    assert _gate_exit(checks, root) == 1

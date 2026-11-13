"""Property 18: every range specification is reported.

Task 11.6 of the phase 4 spec (design, Correctness Properties, Property 18), which validates
Requirements 13.1, 13.5 and 13.6. For a production dependency file built from exact pins and
range specifications (comparison operators, wildcards, ``latest``, an omitted version) in any
order, the ``pinning`` gate:

1. reports exactly the lines that carry a range, each with its file, line number, dependency
   name and spec string, and nothing else (exact pins, and ranges in a ``-dev`` file, are
   not reported);
2. exits with 1 when at least one range is present and with 0 when none is.

Files are written to a fresh directory per example. Dependency names are unique, so the
``mismatch`` finding (Requirement 13.4) cannot appear. The tests in
``test_check_supply_chain_pinning.py`` are examples; this file is only the property.
"""

from __future__ import annotations

import io
import json
import tempfile
from collections import Counter
from pathlib import Path

import check_supply_chain as gate
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain_checks import pinning

_PY_EXACT = ["==1.2.3", "==0.0.1", "==2024.10.1", "==1.0.0.post1"]
_PY_RANGE = [">=1.0", "~=1.4", "<2", "!=1.0", ">1,<2", "==1.*", "==2024.*", "<=3.1", "===1.2.3", ""]
_NPM_EXACT = ["1.2.3", "0.0.1", "10.20.30", "1.0.0-beta.1"]
_NPM_RANGE = ["^1.2.3", "~1.2.3", ">=1.0.0", "*", "x", "1.x", "latest", "", "1.2", "1", "1.0.0 - 2.0.0", "<2.0.0"]
_MARKERS = ["", "", '; python_version < "3.13"']
_SEPARATORS = ["-", "_", "."]


@st.composite
def _requirements(draw: st.DrawFn) -> list[tuple[str, str, bool]]:
    """Draw ``(name, spec, is_range)`` entries in arbitrary order."""
    count = draw(st.integers(min_value=0, max_value=12))
    entries = []
    for index in range(count):
        is_range = draw(st.booleans())
        spec = draw(st.sampled_from(_PY_RANGE if is_range else _PY_EXACT))
        sep = draw(st.sampled_from(_SEPARATORS))
        entries.append((f"lib{sep}n{index}", spec, is_range))
    return entries


@st.composite
def _npm_deps(draw: st.DrawFn) -> list[tuple[str, str, bool]]:
    count = draw(st.integers(min_value=0, max_value=12))
    entries = []
    for index in range(count):
        is_range = draw(st.booleans())
        spec = draw(st.sampled_from(_NPM_RANGE if is_range else _NPM_EXACT))
        entries.append((f"pkg{index}", spec, is_range))
    return entries


@st.composite
def _case(draw: st.DrawFn) -> dict:
    return {
        "py": draw(_requirements()),
        "npm": draw(_npm_deps()),
        "spaces": draw(st.booleans()),
        "gaps": draw(st.lists(st.integers(min_value=0, max_value=2), min_size=12, max_size=12)),
        "markers": draw(st.lists(st.sampled_from(_MARKERS), min_size=12, max_size=12)),
    }


def _build(root: Path, case: dict) -> set[tuple[str, int, str, str]]:
    """Write the files; return the expected ``(path, line, name, spec)`` of the ranges."""
    expected: set[tuple[str, int, str, str]] = set()
    lines: list[str] = ["# production requirements"]
    for index, (name, spec, is_range) in enumerate(case["py"]):
        lines.extend([""] * case["gaps"][index])
        text = f"{name} {spec}" if case["spaces"] and spec else f"{name}{spec}"
        lines.append(text + case["markers"][index])
        if is_range:
            expected.add(("requirements.txt", len(lines), name, spec))
    (root / "requirements.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Out of scope: the same ranges in a dev file (Policy-based exclusions are 11.5's examples).
    ranged = "\n".join(f"dev{i}{spec}" for i, (_, spec, r) in enumerate(case["py"]) if r)
    (root / "requirements-dev.txt").write_text(ranged + "\n", encoding="utf-8")

    pkg = ["{", '  "name": "app",', '  "dependencies": {']
    for index, (name, spec, is_range) in enumerate(case["npm"]):
        comma = "," if index < len(case["npm"]) - 1 else ""
        pkg.append(f"    {json.dumps(name)}: {json.dumps(spec)}{comma}")
        if is_range:
            expected.add(("package.json", len(pkg), name, spec))
    pkg += ["  },", '  "devDependencies": {', '    "devtool": "^1.0.0"', "  }", "}"]
    (root / "package.json").write_text("\n".join(pkg) + "\n", encoding="utf-8")
    return expected


def _classes(case: dict) -> list[str]:
    ranges = [s for _, s, r in case["py"] + case["npm"] if r]
    out = ["range-count:none" if not ranges else "range-count:some"]
    if ranges and any(not r for _, _, r in case["py"] + case["npm"]):
        out.append("mixed")
    out += [f"op:{s}" for s in set(ranges)]
    return out


# Feature: cyber-resilience-phase4-supply-chain, Property 18: 範囲指定はすべて報告される
@settings(max_examples=200, deadline=None)
@given(_case())
def test_every_range_is_reported_and_only_ranges(case: dict) -> None:
    """The reported set equals the set of range lines; the exit code follows its size.

    **Validates: Requirements 13.1, 13.5, 13.6**
    """
    for label in _classes(case):
        event(label)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected = _build(root, case)
        report = pinning.check(root)
        out = io.StringIO()
        code = gate.main(["pinning", "--root", str(root)], out=out)

    reported = {(v.path, v.line) for v in report.violations}
    assert reported == {(p, line) for p, line, _, _ in expected}
    assert len(report.violations) == len(expected)
    assert {v.kind for v in report.violations} <= {"range"}
    by_place = {(v.path, v.line): v for v in report.violations}
    for path, line, name, spec in expected:
        detail = by_place[(path, line)].detail
        assert name in detail
        assert (spec or "(no version)") in detail
    printed = [ln for ln in out.getvalue().splitlines() if ": range: " in ln]
    assert len(printed) == len(expected)
    assert code == (1 if expected else 0)


def test_the_generator_covers_every_class_with_a_fixed_seed() -> None:
    """With ``derandomize=True`` the draws include no-range, mixed and every range form."""
    seen: Counter[str] = Counter()

    @settings(max_examples=200, deadline=None, derandomize=True, database=None)
    @given(_case())
    def draw(case: dict) -> None:
        seen.update(_classes(case))

    draw()
    for label in ("range-count:none", "range-count:some", "mixed"):
        assert seen[label] > 0, label
    for spec in _PY_RANGE + _NPM_RANGE:
        assert seen[f"op:{spec}"] > 0, spec

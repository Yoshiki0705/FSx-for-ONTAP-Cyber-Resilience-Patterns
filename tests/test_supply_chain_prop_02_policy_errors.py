"""Property 2: every Policy_File violation is reported with its location (task 8.5).

A valid Policy_File gets one or more injected violations. Each injection names the JSON path and
kind that ``parse_policy`` must report for it. Two injections never share a document section, and
the overlap injection owns both repository lists, so one injection cannot hide another's check
(the parser skips a cross-field check when its inputs did not parse).
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import hypothesis.strategies as st
import pytest
from hypothesis import event, given, settings
from supply_chain.policy import PolicyError, parse_policy, render_policy

from tests.strategies import supply_chain as sc

Doc = dict[str, Any]
Expected = tuple[str, str]  # (JSON path, issue kind)


@dataclass(frozen=True)
class Injection:
    """One kind of violation: the sections it uses and how it changes the document."""

    name: str
    sections: frozenset[str]
    apply: Callable[[Doc, int], Expected]


def _inj(name: str, sections: str, apply: Callable[[Doc, int], Expected]) -> Injection:
    return Injection(name, frozenset(sections.split(",")), apply)


def _drop(path: str, *keys: str) -> Callable[[Doc, int], Expected]:
    def run(doc: Doc, _pick: int) -> Expected:
        node: Any = doc
        for key in keys[:-1]:
            node = node[key]
        del node[keys[-1]]
        return (path, "missing")

    return run


def _set(path: str, kind: str, value: Any, *keys: str) -> Callable[[Doc, int], Expected]:
    def run(doc: Doc, _pick: int) -> Expected:
        node: Any = doc
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
        return (path, kind)

    return run


def _unknown_root(doc: Doc, _pick: int) -> Expected:
    doc["extra_x"] = 1
    return ("$.extra_x", "unknown_key")


def _unknown_vex(doc: Doc, _pick: int) -> Expected:
    doc["vex"]["extra_x"] = [1]
    return ("$.vex.extra_x", "unknown_key")


def _unknown_include(doc: Doc, pick: int) -> Expected:
    index = pick % len(doc["automerge"]["include"])
    doc["automerge"]["include"][index]["extra_x"] = None
    return (f"$.automerge.include[{index}].extra_x", "unknown_key")


def _empty_targets(doc: Doc, _pick: int) -> Expected:
    doc["target_repositories"] = []
    return ("$.target_repositories", "range")


BAD_NAMES = ("no-slash", "-lead/dash", "a/b/c", "owner/", "/name", "ow ner/name", "owner/na me", "")


def _bad_name(doc: Doc, pick: int) -> Expected:
    index = pick % len(doc["target_repositories"])
    doc["target_repositories"][index] = BAD_NAMES[pick % len(BAD_NAMES)]
    return (f"$.target_repositories[{index}]", "format")


def _dup_target(doc: Doc, pick: int) -> Expected:
    targets = doc["target_repositories"]
    copy_of = targets[pick % len(targets)]
    targets.append(copy_of.swapcase() if pick % 2 else copy_of)  # case differences count as the same repo
    return (f"$.target_repositories[{len(targets) - 1}]", "duplicate")


def _dup_excluded(doc: Doc, pick: int) -> Expected:
    excluded = doc["excluded_repositories"]
    copy_of = excluded[pick % len(excluded)]
    excluded.append(copy_of.swapcase() if pick % 2 else copy_of)
    return (f"$.excluded_repositories[{len(excluded) - 1}]", "duplicate")


def _overlap(doc: Doc, pick: int) -> Expected:
    index = pick % len(doc["target_repositories"])
    doc["excluded_repositories"].append(doc["target_repositories"][index])
    return (f"$.target_repositories[{index}]", "overlap")


def _cooldown_inverted(doc: Doc, _pick: int) -> Expected:
    doc["cooldown_days"]["default"] = doc["cooldown_days"]["major"] + 1
    return ("$.cooldown_days.major", "range")


def _wait_inverted(doc: Doc, _pick: int) -> Expected:
    doc["package_manager_wait"]["default_days"] = doc["package_manager_wait"]["major_days"] + 1
    return ("$.package_manager_wait.major_days", "range")


LIMIT = "$.issue_limits.max_new_issues_per_repo_per_run"
CATALOG: tuple[Injection, ...] = (
    _inj("drop_schema_version", "schema_version", _drop("$.schema_version", "schema_version")),
    _inj(
        "drop_severity",
        "threshold",
        _drop("$.opening_threshold.min_cvss_severity", "opening_threshold", "min_cvss_severity"),
    ),
    _inj("drop_vex_role", "vex", _drop("$.vex.approver_role", "vex", "approver_role")),
    _inj("drop_scope", "scope", _drop("$.dependency_scope", "dependency_scope")),
    _inj("drop_issue_limits", "limits", _drop("$.issue_limits", "issue_limits")),
    _inj(
        "drop_detect_hours",
        "response",
        _drop("$.response_target.detect_hours", "response_target", "detect_hours"),
    ),
    _inj(
        "kev_as_string",
        "threshold",
        _set("$.opening_threshold.open_if_kev_listed", "type", "yes", "opening_threshold", "open_if_kev_listed"),
    ),
    _inj("limit_as_string", "limits", _set(LIMIT, "type", "10", "issue_limits", "max_new_issues_per_repo_per_run")),
    _inj(
        "detect_hours_as_float",
        "response",
        _set("$.response_target.detect_hours", "type", 1.5, "response_target", "detect_hours"),
    ),
    _inj("targets_as_object", "targets", _set("$.target_repositories", "type", {}, "target_repositories")),
    _inj(
        "scope_paths_as_string",
        "scope",
        _set(
            "$.dependency_scope.non_production_paths",
            "type",
            "docs/",
            "dependency_scope",
            "non_production_paths",
        ),
    ),
    _inj("schema_version_2", "schema_version", _set("$.schema_version", "range", 2, "schema_version")),
    _inj(
        "severity_unknown",
        "threshold",
        _set("$.opening_threshold.min_cvss_severity", "range", "SEVERE", "opening_threshold", "min_cvss_severity"),
    ),
    _inj("cooldown_zero", "cooldown", _set("$.cooldown_days.default", "range", 0, "cooldown_days", "default")),
    _inj("limit_0", "limits", _set(LIMIT, "range", 0, "issue_limits", "max_new_issues_per_repo_per_run")),
    _inj("limit_101", "limits", _set(LIMIT, "range", 101, "issue_limits", "max_new_issues_per_repo_per_run")),
    _inj(
        "detect_hours_negative",
        "response",
        _set("$.response_target.detect_hours", "range", -1, "response_target", "detect_hours"),
    ),
    _inj("vex_directory_other", "vex", _set("$.vex.directory", "range", "vex", "vex", "directory")),
    _inj("unknown_root_key", "root_extra", _unknown_root),
    _inj("unknown_vex_key", "vex", _unknown_vex),
    _inj("unknown_include_key", "automerge", _unknown_include),
    _inj("empty_targets", "targets", _empty_targets),
    _inj("bad_repo_name", "targets", _bad_name),
    _inj("duplicate_target", "targets", _dup_target),
    _inj("duplicate_excluded", "excluded", _dup_excluded),
    _inj("target_also_excluded", "targets,excluded", _overlap),
    _inj("cooldown_major_below_default", "cooldown", _cooldown_inverted),
    _inj("wait_major_below_default", "wait", _wait_inverted),
    _inj(
        "open_if_malicious_false",
        "threshold",
        _set(
            "$.opening_threshold.open_if_malicious",
            "range",
            False,
            "opening_threshold",
            "open_if_malicious",
        ),
    ),
    _inj(
        "malicious_suppressible",
        "vex",
        _set("$.vex.malicious_never_suppressed", "range", False, "vex", "malicious_never_suppressed"),
    ),
)

# Whole-text damage. These have no per-field location; the parser reports the document itself.
TEXT_DAMAGE: tuple[tuple[str, Callable[[str], str], str], ...] = (
    ("truncated", lambda t: t[:-1], "invalid_json"),
    ("trailing_garbage", lambda t: t + "x", "invalid_json"),
    ("nan_constant", lambda t: t.replace('"schema_version": 1', '"schema_version": NaN'), "invalid_json"),
    ("empty_text", lambda t: "", "invalid_json"),
)


@dataclass(frozen=True)
class Case:
    """An invalid Policy_File text and the issues the parser must report for it."""

    text: str
    expected: tuple[Expected, ...]
    names: tuple[str, ...]


def _resolve(picks: list[tuple[int, int]]) -> list[tuple[Injection, int]]:
    """Keeps the first injection of each section; the first pick is always kept."""
    used: set[str] = set()
    kept: list[tuple[Injection, int]] = []
    for catalog_index, pick in picks:
        injection = CATALOG[catalog_index]
        if used & injection.sections:
            continue
        used |= injection.sections
        kept.append((injection, pick))
    return kept


@st.composite
def invalid_policy_cases(draw: st.DrawFn) -> Case:
    """A valid Policy_File with 1 or more injected violations, or with its text damaged."""
    doc: Doc = json.loads(render_policy(draw(sc.policies())))
    if draw(st.integers(0, 9)) == 0:
        name, damage, kind = draw(st.sampled_from(TEXT_DAMAGE))
        return Case(damage(json.dumps(doc)), (("$", kind),), (name,))
    picks = draw(st.lists(st.tuples(st.integers(0, len(CATALOG) - 1), st.integers(0, 50)), min_size=1, max_size=6))
    kept = _resolve(picks)
    mutated = copy.deepcopy(doc)
    expected = tuple(injection.apply(mutated, pick) for injection, pick in kept)
    return Case(json.dumps(mutated), expected, tuple(injection.name for injection, _ in kept))


# Feature: cyber-resilience-phase4-supply-chain, Property 2: Policy_File の不適合はすべて位置付きで報告される
@settings(max_examples=300, deadline=None)
@given(case=invalid_policy_cases())
def test_every_injected_violation_is_reported_with_its_location(case: Case) -> None:
    """parse_policy raises PolicyError, and its issues hold a (path, kind) item per injection.

    **Validates: Requirements 3.5, 9.1, 21.6**
    """
    event(f"injections={min(len(case.names), 4)}")
    for name in case.names:
        event(f"injection={name}")
    with pytest.raises(PolicyError) as info:
        parse_policy(case.text)
    reported = {(issue.path, issue.kind) for issue in info.value.issues}
    assert info.value.issues, "PolicyError carried no issues"
    for path, kind in case.expected:
        assert (path, kind) in reported, f"no issue ({path}, {kind}); got {sorted(reported)}"


def test_the_generator_exercises_every_injection_and_kind() -> None:
    """The cases are not vacuous: all injections, all kinds, and multi-injection sets appear."""
    seen: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    sizes: Counter[int] = Counter()

    @settings(max_examples=400, deadline=None, derandomize=True)
    @given(case=invalid_policy_cases())
    def collect(case: Case) -> None:
        seen.update(case.names)
        kinds.update(kind for _path, kind in case.expected)
        sizes[len(case.names)] += 1

    collect()
    every_name = {i.name for i in CATALOG} | {n for n, _f, _k in TEXT_DAMAGE}
    assert every_name <= set(seen), sorted(every_name - set(seen))
    assert {"invalid_json", "missing", "type", "range", "unknown_key", "format", "duplicate", "overlap"} <= set(kinds)
    assert sum(count for size, count in sizes.items() if size >= 2) >= 100, dict(sizes)


def test_a_valid_base_policy_parses() -> None:
    """The injections start from a document the parser accepts, so a raise is due to the injection."""

    @settings(max_examples=50, deadline=None)
    @given(policy=sc.policies())
    def check(policy: Any) -> None:
        assert parse_policy(render_policy(policy)) == policy

    check()

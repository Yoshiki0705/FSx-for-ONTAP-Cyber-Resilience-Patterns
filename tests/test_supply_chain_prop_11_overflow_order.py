"""Property 11 (task 9.12): which Findings are opened when a repository is over the per-run limit.

The inputs are built from per-repository unit specs, so the set of Findings that must be opened is
known without running the planner: CRITICAL / HIGH CVEs, lower-severity or unscored CVEs that are
listed in KEV, and ``MAL-`` packages (optionally with a KEV-listed GHSA of the same package version,
which the planner folds into the ``MAL-`` Issue). Findings below the threshold are mixed in and must
appear nowhere. The oracle orders the units by ``(group, severity_key, vuln_id)`` written out here
(group 0 for KEV or malicious, severity descending, unscored last in each group) and compares the
created Issues and the summary entries with it. The store is empty, so every unit is new.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner

from tests.fakes import issue_store as fake
from tests.test_supply_chain_planner import NOW, OTHER, REPO, _feeds, _finding, _inputs, _policy

REPOS = (REPO, OTHER)
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
KEV_DATE = date(2026, 11, 1)
# A MAL- Finding has no CVSS severity by design, so kind 2 draws none.
# kind: 0 CRITICAL/HIGH CVE, 1 KEV-listed CVE below HIGH or unscored, 2 MAL- package, 3 below the threshold
_SEVERITIES = (("CRITICAL", "HIGH"), ("MEDIUM", "LOW", None), (None,), ("MEDIUM", "LOW", None))


@dataclass(frozen=True, slots=True)
class Unit:
    """One Issue the planner should open for a repository."""

    repo: models.Repo
    vuln_id: str
    severity: str | None
    kev: bool
    malicious: bool

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        """``(group, severity_key, vuln_id)`` with the severity key split so that unscored sorts last."""
        group = 0 if (self.kev or self.malicious) else 1
        if self.severity is None:
            return (group, 1, 0, self.vuln_id)
        return (group, 0, -RANK[self.severity], self.vuln_id)


@dataclass(frozen=True, slots=True)
class Built:
    """Inputs together with the units each repository must open and the noise that must not appear."""

    inputs: models.PlanInputs
    units: dict[models.Repo, list[Unit]]
    noise: frozenset[tuple[str, str]]


def _build(specs: Sequence[Sequence[tuple[int, int, bool, bool]]], limit: int) -> Built:
    """``specs[r]`` is a list of ``(kind, severity index, kev, absorbed GHSA)`` for ``REPOS[r]``."""
    found: list[models.Finding] = []
    kev: dict[str, tuple[date, bool | None]] = {}
    malicious: dict[str, datetime | None] = {}
    units: dict[models.Repo, list[Unit]] = {r: [] for r in REPOS}
    noise: set[tuple[str, str]] = set()
    for r_index, specs_of in enumerate(specs):
        repo = REPOS[r_index]
        for i, (kind, sev_index, listed, ghsa) in enumerate(specs_of):
            n = 1000 * (r_index + 1) + i
            severity = _SEVERITIES[kind][sev_index % len(_SEVERITIES[kind])]
            purl = f"pkg:npm/pkg-{n}@1.0.0"
            if kind == 2:
                vuln_id = f"MAL-2026-{n}"
                found.append(_finding(vuln_id, severity, repo=repo, purl=purl))  # type: ignore[arg-type]
                malicious[vuln_id] = NOW - timedelta(days=3)
                if ghsa:
                    ghsa_id = f"GHSA-aaaa-bbbb-{n:04d}"
                    found.append(_finding(ghsa_id, None, repo=repo, purl=purl))
                    kev[ghsa_id] = (KEV_DATE, None)
                units[repo].append(Unit(repo, vuln_id, severity, False, True))
                continue
            vuln_id = f"CVE-2026-{n}"
            in_kev = kind == 1 or (kind == 0 and listed)
            found.append(_finding(vuln_id, severity, repo=repo, purl=purl))  # type: ignore[arg-type]
            if in_kev:
                kev[vuln_id] = (KEV_DATE, None)
            if kind == 3:
                noise.add((repo.name, vuln_id))
            else:
                units[repo].append(Unit(repo, vuln_id, severity, in_kev, False))
    inputs = _inputs(
        tuple(found),
        policy=_policy(limit),
        feeds=_feeds(kev=kev, malicious=malicious),
    )
    return Built(inputs, units, frozenset(noise))


def _summary_ids(plan: models.Plan, repo: models.Repo) -> list[str]:
    bodies = [a.body for a in plan.actions if a.kind == "summary" and a.repo == repo and a.op in ("create", "update")]
    assert len(bodies) <= 1
    if not bodies:
        return []
    state = issue_body.parse_state(bodies[0])
    assert state is not None
    assert not state.get("entries_omitted")
    return [e["vuln_id"] for e in state["entries"]]


def _created(plan: models.Plan, repo: models.Repo) -> list[str]:
    return [a.vuln_id or "" for a in plan.actions if a.kind == "finding" and a.op == "create" and a.repo == repo]


def _check(built: Built, limit: int) -> Counter[str]:
    plan = planner.plan(built.inputs)
    seen: Counter[str] = Counter()
    for repo, units in built.units.items():
        ordered = sorted(units, key=lambda u: u.sort_key)
        everything = [u.vuln_id for u in ordered]
        created = _created(plan, repo)
        listed = _summary_ids(plan, repo)
        assert created == sorted(everything[:limit])  # actions are sorted by id; the set is the first ``limit``
        assert listed == sorted(everything[limit:])
        assert len(created) == len(set(created))
        assert not set(created) & set(listed)
        assert sorted(created + listed) == sorted(everything)
        assert plan.overflow_counts.get(repo, 0) == len(everything[limit:])
        assert not {v for r, v in built.noise if r == repo.name} & set(created + listed)
        seen["over"] += len(everything) > limit
        seen["kev_after_cut"] += any(u.kev and not u.malicious for u in ordered[limit:])
        seen["mal_in_overflow"] += any(u.malicious for u in ordered[limit:])
        seen["unscored_cut"] += any(u.severity is None for u in ordered[limit:]) and any(
            u.severity is not None for u in ordered[:limit]
        )
        seen["both_groups"] += {u.kev or u.malicious for u in ordered} == {True, False}
    assert not any(a.kind == "summary" and a.op != "create" for a in plan.actions)
    return seen


_UNIT = st.tuples(st.integers(0, 3), st.integers(0, 2), st.booleans(), st.booleans())
_SPECS = st.lists(st.lists(_UNIT, max_size=9), min_size=2, max_size=2)


# Feature: cyber-resilience-phase4-supply-chain, Property 11: 上限を超えたときの選択順と分割
@settings(max_examples=150, deadline=None)
@given(_SPECS, st.integers(1, 5))
def test_the_first_n_by_group_severity_and_id_are_opened_and_the_rest_are_listed(
    specs: list[list[tuple[int, int, bool, bool]]], limit: int
) -> None:
    """The created Findings are the first ``limit`` by the sort key; the summary lists exactly the rest.

    **Validates: Requirements 9.2, 9.3, 27.9**
    """
    seen = _check(_build(specs, limit), limit)
    event(f"over={bool(seen['over'])}")
    event(f"kev_after_cut={bool(seen['kev_after_cut'])}")


# Feature: cyber-resilience-phase4-supply-chain, Property 11: 上限を超えたときの選択順と分割
@settings(max_examples=100, deadline=None)
@given(_SPECS, st.integers(1, 4))
def test_repeated_runs_open_the_findings_in_the_sort_order(
    specs: list[list[tuple[int, int, bool, bool]]], limit: int
) -> None:
    """Run again over the Issues the last run left: each run opens the next ``limit`` Findings in order.

    **Validates: Requirements 9.2, 9.3, 27.9**
    """
    built = _build(specs, limit)
    store = fake.IssueStore.from_managed(())
    issues: tuple[models.ManagedIssue, ...] = ()
    opened: dict[models.Repo, list[list[str]]] = {r: [] for r in REPOS}
    for _ in range(12):
        plan = planner.plan(replace(built.inputs, issues=issues))
        for repo in REPOS:
            opened[repo].append(_created(plan, repo))
        for action in plan.actions:
            store = store.apply_action(action)
            if action.op == "reopen" and action.body is not None:
                store = store.apply_action(replace(action, op="update"))
        issues = tuple(fake.to_managed_issues(store, issue_body.parse_state))
        if not plan.overflow_counts:
            break
    for repo, units in built.units.items():
        everything = [u.vuln_id for u in sorted(units, key=lambda u: u.sort_key)]
        chunks = [everything[i : i + limit] for i in range(0, len(everything), limit)]
        got = [sorted(run) for run in opened[repo] if run]
        assert got == [sorted(c) for c in chunks]
    event(f"runs={max(len([r for r in v if r]) for v in opened.values())}")


def test_generated_cases_reach_the_ordering_cases() -> None:
    """Not vacuous: over the limit, KEV below the cut, malicious and unscored Findings cut, both groups."""
    seen: Counter[str] = Counter()

    @settings(max_examples=200, deadline=None, derandomize=True)
    @given(_SPECS, st.integers(1, 5))
    def run(specs: list[list[tuple[int, int, bool, bool]]], limit: int) -> None:
        seen.update(_check(_build(specs, limit), limit))

    run()
    missing = [k for k in ("over", "kev_after_cut", "mal_in_overflow", "unscored_cut", "both_groups") if not seen[k]]
    assert not missing, f"never seen: {missing}; counts {sorted(seen.items())}"


def test_a_malicious_package_and_a_low_kev_cve_precede_an_unlisted_critical() -> None:
    """Group 0 comes first whatever the severity; with a limit of two the CRITICAL CVE is listed, not opened."""
    specs = [[(0, 0, False, False), (1, 0, False, False), (2, 0, False, False)], []]
    built = _build(specs, 2)
    plan = planner.plan(built.inputs)
    assert _created(plan, REPO) == ["CVE-2026-1001", "MAL-2026-1002"]
    assert _summary_ids(plan, REPO) == ["CVE-2026-1000"]
    assert plan.overflow_counts == {REPO: 1}


def test_a_folded_ghsa_malware_advisory_does_not_count_as_a_second_unit() -> None:
    """A KEV-listed GHSA of the same package version as a ``MAL-`` package is part of that Issue."""
    specs = [[(2, 0, False, True), (0, 0, False, False)], []]
    built = _build(specs, 1)
    plan = planner.plan(built.inputs)
    assert _created(plan, REPO) == ["MAL-2026-1000"]
    assert _summary_ids(plan, REPO) == ["CVE-2026-1001"]

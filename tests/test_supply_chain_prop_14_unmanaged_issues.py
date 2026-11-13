"""Property 14: an Issue the Aggregator does not manage is never operated on (task 9.14).

An Issue is managed only if it carries the identifying label and a marker on its first line whose
``repo`` equals the repository the Issue is in (design, "Issue 本文"; Requirement 8.6). The collector
that turns GitHub's raw Issues into ``ManagedIssue`` values is the I/O side and does not exist yet, so
:func:`_collect` here is a stand-in written from the design: the label check is its own (as
``issue_body.is_managed`` documents) and the marker checks call ``issue_body.parse_marker`` and
``is_managed``.

Inputs come from the task 9.1 generator: ``sc.plan_inputs`` gives the findings, feeds and managed
Issues. The managed Issues are rendered to raw Issues (label, marker line, state block) and mixed with
unmanaged ones in four forms: no label, no marker, a marker whose ``repo`` is another repository, and a
marker that is not on the first line. Each unmanaged Issue names a vulnerability of the run, so a
collector that let one through would change the plan.

``tests/test_supply_chain_issue_body.py`` (task 9.4) checks the marker rules on hand-written values
(``test_marker_repo_must_match_the_issue_repo`` and the well-formed first line table). This file runs
the whole chain, raw Issues -> collection -> ``planner.plan``, and compares the plan with the plan of
the managed Issues alone.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, replace
from typing import Any

import hypothesis.strategies as st
from hypothesis import HealthCheck, event, given, settings
from supply_chain import issue_body as ib
from supply_chain import planner
from supply_chain.models import IssueKind, IssueState, ManagedIssue, PlanInputs, Repo

from tests.fakes import issue_store as fake
from tests.strategies import supply_chain as sc

LABEL = "supply-chain-aggregator"
FOREIGN_REPO = Repo("moved-org", "moved-repo")
VARIANTS = ("no_label", "no_marker", "other_repo", "late_marker")
FIRST_UNMANAGED_NUMBER = 1000
_SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@dataclass(frozen=True, slots=True)
class RawIssue:
    """An Issue as GitHub returns it: where it is, its labels and its body."""

    repo: Repo
    number: int
    labels: tuple[str, ...]
    body: str
    state: IssueState


def _state_block(state: dict[str, Any]) -> str:
    return f"```json {ib.STATE_FENCE_TAG}\n{json.dumps(state, sort_keys=True)}\n```"


def _raw_of(issue: ManagedIssue) -> RawIssue:
    body = ib.render_marker(issue.kind, issue.repo, issue.vuln_id)
    if issue.body_state is not None:
        body += "\n\n" + _state_block(dict(issue.body_state))
    return RawIssue(issue.repo, issue.number, (LABEL,), body, issue.state)


def _unmanaged(variant: str, repo: Repo, number: int, vuln_id: str, state: IssueState, other: Repo) -> RawIssue:
    """An Issue that looks like the managed Issue of ``vuln_id`` in ``repo`` except for one defect."""
    block = _state_block({"vuln_id": vuln_id, "malicious": vuln_id.startswith("MAL-")})
    marker = ib.render_marker("finding", repo, vuln_id)
    if variant == "no_label":
        return RawIssue(repo, number, ("bug",), f"{marker}\n\n{block}", state)
    if variant == "no_marker":
        return RawIssue(repo, number, (LABEL,), f"Notes about {vuln_id}\n\n{block}", state)
    if variant == "other_repo":
        return RawIssue(repo, number, (LABEL,), f"{ib.render_marker('finding', other, vuln_id)}\n\n{block}", state)
    return RawIssue(repo, number, (LABEL,), f"Triage notes\n{marker}\n\n{block}", state)


def _collect(raw: tuple[RawIssue, ...]) -> tuple[ManagedIssue, ...]:
    """The managed Issues among ``raw``: the label, a first-line marker, and the marker's repo matches."""
    out: list[ManagedIssue] = []
    for issue in raw:
        marker = ib.parse_marker(issue.body)
        if LABEL not in issue.labels or marker is None or not ib.is_managed(marker, issue.repo):
            continue
        kind: IssueKind = marker.kind  # type: ignore[assignment]
        vuln_id = marker.vuln_id if kind == "finding" else None
        out.append(ManagedIssue(issue.repo, issue.number, kind, vuln_id, issue.state, ib.parse_state(issue.body)))
    return tuple(out)


def _key(repo: Repo) -> tuple[str, str]:
    return (repo.owner.lower(), repo.name.lower())


def _other_repo(repo: Repo, targets: tuple[Repo, ...], pick: int) -> Repo:
    choices = [r for r in (*targets, FOREIGN_REPO) if r != repo]
    return choices[pick % len(choices)]


def _settled(inputs: PlanInputs) -> PlanInputs:
    """``inputs`` with the Issues the store holds after the plan of ``inputs`` was applied."""
    store = fake.IssueStore.from_managed(inputs.issues)
    for action in planner.plan(inputs).actions:
        store = store.apply_action(action)
        if action.op == "reopen":
            store = store.apply_action(replace(action, op="update"))
    return replace(inputs, issues=fake.to_managed_issues(store, ib.parse_state))


def _perturbed(inputs: PlanInputs, bits: tuple[int, ...]) -> PlanInputs:
    """Closes some settled Issues (the plan reopens them) and edits the state of others (it updates them)."""
    issues = []
    for i, issue in enumerate(inputs.issues):
        mode = bits[i % len(bits)] if bits else 0
        if mode == 1 and issue.kind == "finding":
            issue = replace(issue, state="closed")
        elif mode == 2 and issue.body_state is not None:
            issue = replace(issue, body_state={**issue.body_state, "cvss_severity": "TAMPERED"})
        issues.append(issue)
    return replace(inputs, issues=tuple(issues))


@dataclass(frozen=True, slots=True)
class Case:
    """The run's inputs and the raw Issues: the managed ones, then the unmanaged ones."""

    inputs: PlanInputs
    managed_raw: tuple[RawIssue, ...]
    unmanaged_raw: tuple[RawIssue, ...]
    variants: tuple[str, ...]


@st.composite
def _cases(draw: st.DrawFn) -> Case:
    inputs = draw(sc.plan_inputs(10, 10))
    stage = draw(st.integers(0, 2))
    if stage:
        inputs = _settled(inputs)
    if stage == 2:
        inputs = _perturbed(inputs, tuple(draw(st.lists(st.integers(0, 2), min_size=1, max_size=6))))
    targets = inputs.policy.target_repositories
    # Prefer the identifiers the run has findings for: those are the ones the plan acts on.
    pool = tuple(sorted({*sc.finding_vuln_ids(inputs.findings)} or {*sc.DEFAULT_VULN_IDS}))
    specs = draw(
        st.lists(
            st.tuples(
                st.integers(0, len(VARIANTS) - 1),
                st.integers(0, len(targets) - 1),
                st.integers(0, len(pool) - 1),
                st.integers(0, 1),
                st.integers(0, 7),
            ),
            max_size=12,
        )
    )
    unmanaged = tuple(
        _unmanaged(
            VARIANTS[v],
            targets[r],
            FIRST_UNMANAGED_NUMBER + i,
            pool[p],
            "closed" if s else "open",
            _other_repo(targets[r], targets, o),
        )
        for i, (v, r, p, s, o) in enumerate(specs)
    )
    return Case(inputs, tuple(_raw_of(i) for i in inputs.issues), unmanaged, tuple(VARIANTS[v] for v, *_ in specs))


def _interleave(case: Case, order: int) -> tuple[RawIssue, ...]:
    """Managed and unmanaged Issues in one list; ``order`` moves the unmanaged ones around."""
    raw = [*case.managed_raw, *case.unmanaged_raw]
    if order % 3 == 1:
        raw.reverse()
    elif order % 3 == 2:
        raw = [*case.unmanaged_raw, *case.managed_raw]
    return tuple(raw)


def _facts(case: Case, order: int) -> list[str]:
    """What the example exercised; also what the non-vacuity test reads."""
    mixed = replace(case.inputs, issues=_collect(_interleave(case, order)))
    acted = {(_key(a.repo), a.vuln_id) for a in planner.plan(mixed).actions if a.vuln_id is not None}
    facts = [f"variant={v}" for v in sorted(set(case.variants))]
    if any((_key(i.repo), _vuln_of(i)) in acted for i in case.unmanaged_raw):
        facts.append("twin_acted")
    ops = Counter(a.op for a in planner.plan(mixed).actions)
    facts += [f"op={op}" for op in ops]
    if not case.unmanaged_raw:
        facts.append("none_unmanaged")
    if case.inputs.issues and case.unmanaged_raw:
        facts.append("mixed")
    return facts


def _vuln_of(issue: RawIssue) -> str:
    return issue.body.split('"vuln_id": "', 1)[1].split('"', 1)[0]


# Feature: cyber-resilience-phase4-supply-chain, Property 14: 管理対象でない Issue は操作されない
@_SETTINGS
@given(_cases(), st.integers(0, 2))
def test_unmanaged_issues_are_neither_referenced_nor_change_the_plan(case: Case, order: int) -> None:
    """No action names an unmanaged Issue, and the plan equals the plan without them.

    **Validates: Requirements 8.6**
    """
    for fact in _facts(case, order):
        event(fact)
    raw = _interleave(case, order)
    collected = _collect(raw)
    # The collector keeps every managed Issue and no unmanaged one.
    assert sorted(collected, key=lambda i: (_key(i.repo), i.number)) == sorted(
        case.inputs.issues, key=lambda i: (_key(i.repo), i.number)
    )
    unmanaged_ids = {(_key(i.repo), i.number) for i in case.unmanaged_raw}
    mixed = planner.plan(replace(case.inputs, issues=collected))
    alone = planner.plan(case.inputs)
    assert not any(a.number is not None and (_key(a.repo), a.number) in unmanaged_ids for a in mixed.actions)
    assert mixed.actions == alone.actions
    assert mixed == alone


def test_the_generated_cases_exercise_every_unmanaged_form_and_the_plan() -> None:
    """The property is not vacuous (fixed seed, 400 draws): each form occurs, and Issues that look like
    the ones the plan acts on are among the unmanaged ones.
    """
    seen: Counter[str] = Counter()

    @settings(
        max_examples=400, deadline=None, derandomize=True, database=None, suppress_health_check=[HealthCheck.too_slow]
    )
    @given(_cases(), st.integers(0, 2))
    def collect(case: Case, order: int) -> None:
        seen.update(set(_facts(case, order)))

    collect()
    for needed in (
        *(f"variant={v}" for v in VARIANTS),
        "twin_acted",
        "mixed",
        "none_unmanaged",
        "op=create",
        "op=update",
        "op=close",
        "op=reopen",
    ):
        assert seen[needed] >= 5, f"{needed}: {sorted(seen.items())}"


def test_a_marker_for_the_right_repository_without_the_label_is_not_collected() -> None:
    repo = Repo("example-org", "svc-api-0")
    marker = ib.render_marker("finding", repo, "CVE-2026-0001")
    assert _collect((RawIssue(repo, 1, (LABEL,), marker, "open"),))[0].vuln_id == "CVE-2026-0001"
    assert _collect((RawIssue(repo, 1, (), marker, "open"),)) == ()
    assert _collect((RawIssue(repo, 1, (LABEL,), "text\n" + marker, "open"),)) == ()
    assert _collect((RawIssue(FOREIGN_REPO, 1, (LABEL,), marker, "open"),)) == ()

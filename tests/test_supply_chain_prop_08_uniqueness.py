"""Property 8: one managed finding Issue per key, also after a partly applied plan.

Run 1 plans, only some of its actions are applied (the others stand for failed API calls), run 2
plans again over what the store holds, and run 2 is applied in full. Afterwards each
``(repo, vuln_id)`` has at most one finding Issue, each ``(repo, purl, version)`` at most one open
malicious Issue (``MAL-`` or a GHSA malware advisory, so a Q-11 pair counts once), and neither plan
creates an Issue for a key that already has an open one.

The fake store ignores the body of a ``reopen`` (GitHub applies it on PATCH), so an applied
``reopen`` is followed by an ``update`` with the same body. Issues that were duplicated before run 1
are left alone by design, so the bound for a key is the larger of 1 and its count before run 1.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import replace

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner

from tests.fakes import issue_store as fake
from tests.strategies import supply_chain as sc

_LIMITS = (1, 2, 3, 20)


def _policy(limit: int) -> models.Policy:
    return models.Policy(
        schema_version=1,
        target_repositories=sc.DEFAULT_REPOS,
        excluded_repositories=(),
        opening_threshold=models.OpeningThreshold("LOW", True, True),
        cooldown_days=models.CooldownDays(3, 7),
        automerge_include=(),
        automerge_exclude=(),
        automerge_enabled_repositories=(),
        package_manager_wait=models.CooldownDays(3, 7),
        non_production_paths=(),
        vex_directory=".vex",
        vex_exclude_statuses=("not_affected", "fixed"),
        vex_approver_role="VEX_Reviewer",
        vex_one_statement_per_document=True,
        vex_malicious_never_suppressed=True,
        response_target=models.ResponseTarget(24, 7, 14),
        max_new_issues_per_repo_per_run=limit,
    )


def _apply(store: fake.IssueStore, actions: Iterable[models.IssueAction]) -> fake.IssueStore:
    for action in actions:
        store = store.apply_action(action)
        if action.op == "reopen":
            store = store.apply_action(replace(action, op="update"))
    return store


def _managed(store: fake.IssueStore) -> tuple[models.ManagedIssue, ...]:
    return fake.to_managed_issues(store, issue_body.parse_state)


def _components(state: object) -> set[tuple[str, str]]:
    if not isinstance(state, dict):
        return set()
    return {(c["purl"], c["version"]) for c in state.get("components") or () if isinstance(c, dict)}


def _malicious(vuln_id: str | None, state: object) -> bool:
    """A ``MAL-`` Issue, or a GHSA malware advisory recorded without a severity (one Q-11 key per component).

    The planner has no field for the advisory type, so it treats a GHSA without a severity as the
    malware advisory of a Q-11 pair. A malware GHSA recorded with a severity is outside that
    approximation (9.6 interpretation 4, open until after 4.13) and counts as an ordinary finding.
    """
    if (vuln_id or "").startswith("MAL-"):
        return True
    return vuln_id in sc.MALWARE_GHSA_IDS and isinstance(state, dict) and state.get("cvss_severity") is None


def _open_findings(issues: Iterable[models.ManagedIssue]) -> list[models.ManagedIssue]:
    return [i for i in issues if i.kind == "finding" and i.state == "open"]


def _no_create_over_open(issues: tuple[models.ManagedIssue, ...], plan: models.Plan) -> int:
    """Asserts no ``create`` repeats an open Issue's identifier or malicious component; returns the creates."""
    opened = _open_findings(issues)
    creates = [a for a in plan.actions if a.op == "create" and a.kind == "finding"]
    for action in creates:
        assert not [i for i in opened if i.repo == action.repo and i.vuln_id == action.vuln_id], action
        state = issue_body.parse_state(action.body)
        if _malicious(action.vuln_id, state):
            mine = _components(state)
            assert mine
            clash = [
                i
                for i in opened
                if i.repo == action.repo and _malicious(i.vuln_id, i.body_state) and mine & _components(i.body_state)
            ]
            assert not clash, (action, clash)
    return len(creates)


def _bound(issues: Iterable[models.ManagedIssue]) -> tuple[Counter, Counter]:
    """Counts before run 1: Issues per ``(repo, vuln_id)``, open malicious Issues per component."""
    per_id: Counter = Counter()
    per_component: Counter = Counter()
    for i in issues:
        if i.kind == "finding":
            per_id[(i.repo, i.vuln_id)] += 1
            if i.state == "open" and _malicious(i.vuln_id, i.body_state):
                per_component.update((i.repo, p, v) for p, v in _components(i.body_state))
    return per_id, per_component


def _check(inputs: models.PlanInputs, subset: frozenset[int]) -> dict[str, int]:
    seen: Counter[str] = Counter()
    per_id, per_component = _bound(inputs.issues)
    first = planner.plan(inputs)
    seen["creates1"] += _no_create_over_open(inputs.issues, first)
    store = fake.IssueStore.from_managed(inputs.issues)
    chosen = [a for n, a in enumerate(first.actions) if n in subset]
    seen["partial"] += len(chosen) < len(first.actions)
    store = _apply(store, chosen)
    middle = replace(inputs, issues=_managed(store), run_id="next-1")
    second = planner.plan(middle)
    seen["creates2"] += _no_create_over_open(middle.issues, second)
    store = _apply(store, second.actions)
    final = _managed(store)
    ids = Counter((i.repo, i.vuln_id) for i in final if i.kind == "finding")
    assert all(n <= max(1, per_id[k]) for k, n in ids.items()), ids
    components: Counter = Counter()
    for i in _open_findings(final):
        if _malicious(i.vuln_id, i.body_state):
            components.update((i.repo, p, v) for p, v in _components(i.body_state))
    assert all(n <= max(1, per_component[k]) for k, n in components.items()), components
    seen["mal_open"] += sum(components.values())
    return seen


@st.composite
def _cases(draw: st.DrawFn) -> tuple[models.PlanInputs, frozenset[int]]:
    inputs = draw(sc.plan_inputs(14, 14, policy=_policy(draw(st.sampled_from(_LIMITS)))))
    if draw(st.booleans()):
        inputs = replace(inputs, issues=())
    subset = draw(st.frozensets(st.integers(0, 60), max_size=61))
    return inputs, subset


# Feature: cyber-resilience-phase4-supply-chain, Property 8: 組ごとの Issue の一意性は部分的な適用の後も保たれる
@settings(max_examples=200, deadline=None)
@given(_cases())
def test_one_finding_issue_per_key_after_partial_apply(case: tuple[models.PlanInputs, frozenset[int]]) -> None:
    """**Validates: Requirements 8.9, 27.6**"""
    inputs, subset = case
    seen = _check(inputs, subset)
    event(f"creates1={min(seen['creates1'], 3)}")
    event(f"creates2={min(seen['creates2'], 3)}")
    event(f"partial={bool(seen['partial'])}")
    event(f"mal_open={min(seen['mal_open'], 2)}")


def test_the_property_is_not_vacuous() -> None:
    """Partial applies, second-run creates, open ``MAL-`` Issues and Q-11 pairs all occur."""
    seen: Counter[str] = Counter()

    @settings(max_examples=150, deadline=None)
    @given(_cases())
    def run(case: tuple[models.PlanInputs, frozenset[int]]) -> None:
        inputs, subset = case
        seen.update(_check(inputs, subset))
        seen["pair"] += bool(sc.ghsa_malware_pairs(inputs.findings))

    run()
    missing = [k for k in ("creates1", "creates2", "partial", "mal_open", "pair") if seen[k] == 0]
    assert not missing, f"never seen: {missing}; counts {sorted(seen.items())}"


def _pair_inputs() -> models.PlanInputs:
    repo = sc.DEFAULT_REPOS[0]
    when = sc.utc_at(450 * 1440)
    component = sc.component_of(3, 1)

    def finding(vuln_id: str) -> models.Finding:
        return models.Finding(
            repo=repo,
            vuln_id=vuln_id,
            aliases=(),
            component=component,
            cvss_severity=None,
            fixed_version=None,
            advisory_published_at=when,
            layer="A",
            first_observed_component_at=when,
        )

    feeds = models.FeedSnapshot(
        kev={},
        epss={},
        malicious={},
        malicious_withdrawn={},
        malicious_delisted=frozenset(),
        malicious_unconfirmed=frozenset(),
    )
    return models.PlanInputs(
        policy=_policy(20),
        run_id="1-1",
        now=when,
        pull_requests=(),
        findings=frozenset({finding(sc.mal_id(5)), finding(sc.ghsa_malware_id(5))}),
        fetch_ok=frozenset(sc.DEFAULT_REPOS),
        feeds=feeds,
        vex={},
        issues=(),
    )


def test_q11_pair_with_a_kev_listed_ghsa_becomes_one_issue() -> None:
    """The minimal counterexample found by the property: the GHSA member is KEV-listed."""
    inputs = _pair_inputs()
    kev = {sc.ghsa_malware_id(5): (sc.utc_at(0).date(), None)}
    plan = planner.plan(replace(inputs, feeds=replace(inputs.feeds, kev=kev)))
    creates = [a.vuln_id for a in plan.actions if a.op == "create" and a.kind == "finding"]
    assert creates == [sc.mal_id(5)]


def test_q11_pair_without_aliases_becomes_one_issue_per_repo_purl_version() -> None:
    """A ``MAL-`` and a ``GHSA-`` malware advisory on one purl, with no alias between them, give one Issue."""
    inputs = _pair_inputs()
    assert len(sc.ghsa_malware_pairs(inputs.findings)) == 1
    first = planner.plan(inputs)
    creates = [a for a in first.actions if a.op == "create" and a.kind == "finding"]
    assert [a.vuln_id for a in creates] == [sc.mal_id(5)]
    store = _apply(fake.IssueStore.from_managed(()), ())
    # The create fails; run 2 creates it; a repeat of run 2 finds the open Issue and does nothing.
    second = planner.plan(replace(inputs, run_id="1-2"))
    store = _apply(store, second.actions)
    third = planner.plan(replace(inputs, run_id="1-3", issues=_managed(store)))
    assert third.actions == ()
    assert len(store.find(kind="finding")) == 1

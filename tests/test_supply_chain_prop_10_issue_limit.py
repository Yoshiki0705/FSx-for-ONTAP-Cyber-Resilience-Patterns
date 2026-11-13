"""Property 10 (task 9.11): the cap on new finding Issues in one run.

For every repository the plan holds at most ``n`` ``create`` operations for finding Issues and at
most one ``create`` or ``update`` for the summary Issue, and a repository whose new targets fit
under ``n`` gets neither a summary ``create`` nor a summary ``update``.

What counts as "new targets" is taken from the same inputs planned with the largest cap (100):
that plan has more room than the generator has findings, so every new target is created and
nothing overflows. The Issues come from an earlier run planned with a drawn cap, applied to the
store, then each Issue (summaries included) is left open, closed or deleted.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner

from tests.fakes import issue_store as fake
from tests.strategies import supply_chain as sc

MAX_CAP = 100


def _with_cap(inputs: models.PlanInputs, cap: int) -> models.PlanInputs:
    return replace(inputs, policy=replace(inputs.policy, max_new_issues_per_repo_per_run=cap))


def _key(repo: models.Repo) -> tuple[str, str]:
    return (repo.owner.lower(), repo.name.lower())


@st.composite
def _cases(draw: st.DrawFn) -> tuple[models.PlanInputs, int]:
    """Inputs with Issues left by an earlier run, and the cap ``n`` for the run under test."""
    policy = replace(draw(sc.policies()), target_repositories=sc.DEFAULT_REPOS)
    inputs = draw(sc.plan_inputs(14, 0, policy=policy))
    earlier = draw(st.integers(1, 4))
    first = planner.plan(_with_cap(inputs, earlier))
    store = fake.IssueStore.from_managed(())
    for action in first.actions:
        store = store.apply_action(action)
        if action.op == "reopen":
            store = store.apply_action(replace(action, op="update"))
    managed = fake.to_managed_issues(store, issue_body.parse_state)
    states = draw(
        st.lists(st.sampled_from(("open", "closed", "deleted")), min_size=len(managed), max_size=len(managed))
    )
    kept = tuple(
        replace(i, state="closed") if s == "closed" else i  # type: ignore[arg-type]
        for i, s in zip(managed, states, strict=True)
        if s != "deleted"
    )
    n = draw(st.one_of(st.integers(1, 4), st.integers(1, MAX_CAP)))
    return replace(inputs, issues=kept, run_id="next-1"), n


def _check(inputs: models.PlanInputs, n: int) -> Counter[str]:
    got = planner.plan(_with_cap(inputs, n))
    room = planner.plan(_with_cap(inputs, MAX_CAP))
    assert not room.overflow_counts
    targets: Counter[tuple[str, str]] = Counter(
        _key(a.repo) for a in room.actions if a.op == "create" and a.kind == "finding"
    )
    created: Counter[tuple[str, str]] = Counter(
        _key(a.repo) for a in got.actions if a.op == "create" and a.kind == "finding"
    )
    summary_writes: Counter[tuple[str, str]] = Counter(
        _key(a.repo) for a in got.actions if a.kind == "summary" and a.op in ("create", "update")
    )
    summary_any: Counter[tuple[str, str]] = Counter(
        _key(a.repo) for a in got.actions if a.kind == "summary" and a.op in ("create", "update", "reopen")
    )
    open_summary = {_key(i.repo) for i in inputs.issues if i.kind == "summary" and i.state == "open"}
    no_open_summary = {_key(r) for r in inputs.policy.target_repositories} - open_summary
    seen: Counter[str] = Counter()
    for repo in {_key(r) for r in inputs.policy.target_repositories}:
        assert created[repo] <= n, (repo, n, created[repo])
        assert summary_writes[repo] <= 1, (repo, summary_writes[repo])
        assert summary_any[repo] <= 1, (repo, summary_any[repo])
        if targets[repo] <= n:
            assert summary_writes[repo] == 0, (repo, n, targets[repo])
            assert created[repo] == targets[repo]
            seen["under"] += bool(targets[repo])
        else:
            assert created[repo] == n
            if repo in no_open_summary:  # an open summary that already lists the rest needs no write
                assert summary_any[repo] == 1, (repo, n, targets[repo])
            seen["summary_written"] += summary_any[repo]
            seen["over"] += 1
        seen["at_cap"] += created[repo] == n and targets[repo] == n
    return seen


# Feature: cyber-resilience-phase4-supply-chain, Property 10: 1 回の実行での新規起票の上限
@settings(max_examples=150, deadline=None)
@given(_cases())
def test_new_finding_issues_never_exceed_the_cap(case: tuple[models.PlanInputs, int]) -> None:
    """At most ``n`` new finding Issues per repository, at most one summary write, none when everything fits.

    **Validates: Requirements 9.1, 9.3, 9.4, 27.8**
    """
    inputs, n = case
    seen = _check(inputs, n)
    event(f"over={bool(seen['over'])}")
    event(f"under={bool(seen['under'])}")


def test_generated_cases_cover_fitting_exact_and_overflowing_repositories() -> None:
    """The property is not vacuous: repositories under, exactly at and over the cap all occur."""
    seen: Counter[str] = Counter()

    @settings(max_examples=150, deadline=None, derandomize=True)
    @given(_cases())
    def run(case: tuple[models.PlanInputs, int]) -> None:
        seen.update(_check(*case))

    run()
    missing = [k for k in ("under", "over", "at_cap", "summary_written") if not seen[k]]
    assert not missing, f"never seen: {missing}; counts {sorted(seen.items())}"

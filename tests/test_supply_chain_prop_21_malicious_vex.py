"""Property 21 (task 9.16): a VEX statement never stops an Issue for a malicious package.

The inputs hold malicious findings only (and only ``MAL-`` Issues). Statements of every status name
their ``MAL-`` identifier, an alias or a purl; adding them must leave every action, the overflow
counts and the unconfirmed list as they were, put nothing in ``vex_exclusions``, and record each
matching ``not_affected`` / ``fixed`` document in ``rejected_vex``. A close never carries a ``vex_*``
reason. The ``effective_exclusions`` side of the property is in ``test_supply_chain_vex.py`` (task 8.7);
this file checks it through the planner with the task 9.1 generators.

The design says the close reason of a malicious Issue is always ``resolved``. The planner also uses
``withdrawn`` and ``feed_version_delisted`` when the feed says so (Requirement 7.10 text), so the
check here is that the reason is one of those three and never a ``vex_*`` one, and that it equals the
reason without any VEX.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, date, datetime

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner
from supply_chain.vex import REASON_MALICIOUS

from tests.fakes import issue_store as fake
from tests.strategies import supply_chain as sc

STATUSES: tuple[models.VexStatus, ...] = ("not_affected", "fixed", "affected", "under_investigation")
EXCLUDING = frozenset({"not_affected", "fixed"})
STAMP = datetime(2026, 1, 1, tzinfo=UTC)
CONTEXT = "https://openvex.dev/ns/v0.2.0"
CLOSE_REASONS = frozenset({"resolved", "withdrawn", "feed_version_delisted"})
STATES = ("none", "open", "drifted", "closed", "stale", "generated")


def _rk(repo: models.Repo) -> tuple[str, str]:
    return (repo.owner.lower(), repo.name.lower())


def _ids(finding: models.Finding) -> tuple[str, ...]:
    return (finding.vuln_id, *finding.aliases)


def _ordered(found: Sequence[models.Finding]) -> list[models.Finding]:
    return sorted(found, key=lambda f: (_rk(f.repo), f.vuln_id, f.component.purl))


def _doc(path: str, vuln_id: str, aliases: tuple[str, ...], purl: str, status: models.VexStatus) -> models.VexDocument:
    statement = models.VexStatement(vuln_id, aliases, (purl,), status, "component_not_present", None, STAMP)
    return models.VexDocument("urn:example:21", CONTEXT, "example", None, STAMP, 1, None, (statement,), path)


def _other_version(purl: str) -> str:
    other = purl.replace("@", "@9999-", 1)
    assert other != purl
    return other


@st.composite
def _cases(draw: st.DrawFn) -> tuple[models.PlanInputs, list[tuple[models.Finding, models.VexStatus, int]]]:
    """Malicious-only inputs and, for some findings, the status and shape of a statement that names them."""
    inputs = draw(sc.plan_inputs(14, 6))
    mal_list = _ordered([f for f in inputs.findings if planner.is_malicious(f)])
    flags = draw(st.lists(st.booleans(), min_size=len(mal_list), max_size=len(mal_list)))
    mal_findings = frozenset(  # some get a GHSA alias, so a statement can name the finding without a MAL- identifier
        replace(f, aliases=(*f.aliases, sc.ghsa_id(n))) if flag and sc.ghsa_id(n) not in _ids(f) else f
        for n, (f, flag) in enumerate(zip(mal_list, flags, strict=True))
    )
    mal_issues = tuple(i for i in inputs.issues if (i.vuln_id or "").startswith("MAL-"))
    inputs = replace(inputs, findings=mal_findings, issues=mal_issues)
    found = _ordered(mal_findings)
    picks = draw(
        st.lists(
            st.tuples(st.booleans(), st.sampled_from(STATUSES), st.integers(0, 63)),
            min_size=len(found),
            max_size=len(found),
        )
    )
    return inputs, [(f, status, shape) for f, (on, status, shape) in zip(found, picks, strict=True) if on]


def _statements(
    picks: Sequence[tuple[models.Finding, models.VexStatus, int]],
) -> tuple[dict[models.Repo, tuple[models.VexDocument, ...]], list[tuple[models.Finding, str]]]:
    """One document per pick, and the (finding, path) pairs where the statement really matches the finding."""
    out: dict[models.Repo, list[models.VexDocument]] = {}
    matches: list[tuple[models.Finding, str]] = []
    for n, (f, status, shape) in enumerate(picks):
        ids = _ids(f)
        head = ids[shape % len(ids)]
        rest = tuple(i for i in ids if i != head) if shape & 4 else ()
        plain = [i for i in ids if not i.upper().startswith("MAL-")]
        if shape & 32 and plain:  # a statement on a non-MAL- alias only: the one form a table can match
            head, rest = plain[0], ()
        elif shape & 8:  # a statement about another vulnerability that lists the finding's ids as aliases
            head, rest = "CVE-2098-0001", ids
        purl = _other_version(f.component.purl) if shape & 16 else f.component.purl
        path = f".vex/{n:03d}.json"
        out.setdefault(f.repo, []).append(_doc(path, head, rest, purl, status))
        if status in EXCLUDING and not shape & 16:
            matches.append((f, path))
    return {repo: tuple(docs) for repo, docs in out.items()}, matches


def _names(doc: models.VexDocument) -> tuple[str, ...]:
    return tuple(i for s in doc.statements for i in (s.vuln_id, *s.aliases))


def _status_of(vex: dict[models.Repo, tuple[models.VexDocument, ...]], path: str) -> str:
    return next(s.status for docs in vex.values() for d in docs if d.path == path for s in d.statements)


def _with_state(inputs: models.PlanInputs, state: str) -> models.PlanInputs:
    """``inputs`` without VEX, with the Issues a first run would leave (open, drifted or closed), or as generated."""
    base = replace(inputs, vex={})
    if state == "generated":
        return base
    base = replace(base, issues=())
    if state == "none":
        return base
    store = fake.IssueStore.from_managed(())
    for action in planner.plan(base).actions:
        store = store.apply_action(action)
    managed = fake.to_managed_issues(store, issue_body.parse_state)
    if state == "closed":
        return replace(base, issues=tuple(replace(i, state="closed") for i in managed))
    if state == "stale":  # open Issues whose findings are gone
        return replace(base, issues=managed, findings=frozenset())
    if state == "drifted":  # open Issues whose feed values changed since they were written
        epss = {i: ("0.50000", date(2026, 12, 1), "v-derived") for f in base.findings for i in _ids(f)}
        return replace(base, issues=managed, feeds=replace(base.feeds, epss=epss))
    return replace(base, issues=managed)


def _check(
    inputs: models.PlanInputs, picks: Sequence[tuple[models.Finding, models.VexStatus, int]], state: str
) -> Counter[str]:
    base = _with_state(inputs, state)
    vex, matches = _statements(picks)
    plain = planner.plan(base)
    got = planner.plan(replace(base, vex=vex))
    assert got.actions == plain.actions
    assert got.overflow_counts == plain.overflow_counts
    assert got.malicious_withdrawn_unconfirmed == plain.malicious_withdrawn_unconfirmed
    assert got.below_threshold == plain.below_threshold
    assert got.unscored == plain.unscored
    assert got.vex_exclusions == ()
    assert all(reason == REASON_MALICIOUS for _, reason in got.rejected_vex)
    paths = {path for path, _ in got.rejected_vex}
    assert paths <= {d.path for docs in vex.values() for d in docs}
    named = {  # a not_affected / fixed statement that lists a MAL- identifier is rejected whether or not a finding matches
        d.path
        for docs in vex.values()
        for d in docs
        for s in d.statements
        if s.status in EXCLUDING and any(i.upper().startswith("MAL-") for i in (s.vuln_id, *s.aliases))
    }
    allowed = set(base.policy.vex_exclude_statuses)
    by_match = {path for f, path in matches if f in base.findings and _status_of(vex, path) in allowed}
    assert named <= paths
    assert paths <= named | by_match
    assert by_match <= paths
    for a in got.actions:
        if a.op == "close":
            assert a.close_reason in CLOSE_REASONS
    seen: Counter[str] = Counter()
    seen["malicious_findings"] += bool(base.findings)
    seen["statements"] += bool(vex)
    seen["matching_excluding"] += any(f in base.findings for f, _ in matches)
    seen["rejected"] += bool(got.rejected_vex)
    seen["alias_only_match"] += any(
        f in base.findings and _status_of(vex, path) in set(base.policy.vex_exclude_statuses)
        for f, path in matches
        if not any(i.upper().startswith("MAL-") for d in vex[f.repo] if d.path == path for i in _names(d))
    )
    for op in ("create", "update", "reopen", "close"):
        seen[op] += any(a.op == op for a in got.actions)
    seen["close_resolved"] += any(a.op == "close" and a.close_reason == "resolved" for a in got.actions)
    seen["close_feed"] += any(a.op == "close" and a.close_reason in CLOSE_REASONS - {"resolved"} for a in got.actions)
    return seen


# Feature: cyber-resilience-phase4-supply-chain, Property 21: VEX は悪意のあるパッケージの Issue を止めない
@settings(max_examples=200, deadline=None)
@given(_cases(), st.sampled_from(STATES))
def test_vex_never_changes_the_plan_for_malicious_packages(
    case: tuple[models.PlanInputs, list[tuple[models.Finding, models.VexStatus, int]]], state: str
) -> None:
    """Statements of any status leave create, update, reopen and close as they were; matches are rejected.
    **Validates: Requirements 7.12, 11.12, 21.3, 27.7**
    """
    inputs, picks = case
    seen = _check(inputs, picks, state)
    event(f"state={state}")
    event(f"matching_excluding={bool(seen['matching_excluding'])}")
    event(f"rejected={bool(seen['rejected'])}")


def test_generated_cases_reach_every_operation_and_a_rejected_statement() -> None:
    """The property is not vacuous: each operation, a matching statement and a rejection all occur."""
    seen: Counter[str] = Counter()

    # derandomize: a fixed sequence keeps the check that every form occurs independent of the seed.
    @settings(max_examples=300, deadline=None, derandomize=True)
    @given(_cases(), st.sampled_from(STATES))
    def run(case: tuple[models.PlanInputs, list[tuple[models.Finding, models.VexStatus, int]]], state: str) -> None:
        inputs, picks = case
        seen.update(_check(inputs, picks, state))

    run()
    needed = (
        "malicious_findings",
        "statements",
        "matching_excluding",
        "rejected",
        "alias_only_match",
        "create",
        "update",
        "reopen",
        "close",
        "close_resolved",
    )
    missing = [k for k in needed if not seen[k]]
    assert not missing, f"never seen: {missing}; counts {sorted(seen.items())}"

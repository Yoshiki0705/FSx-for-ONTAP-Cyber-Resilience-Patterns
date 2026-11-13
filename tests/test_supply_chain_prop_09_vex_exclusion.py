"""Property 9 (task 9.10): only an approved VEX statement stops an Issue from being opened.

``plan`` only receives documents the I/O layer already accepted (default branch, conforming), so
"documents from other branches" and "non-conforming documents" are not inputs the planner can see;
what reaches it is covered here: statements with an excluding status for the exact id and purl
suppress a non-malicious finding, and statements that do not match change nothing.

The oracle for suppression is the plan for the same inputs without the suppressed findings and
without any VEX. The generated Issues rarely match the generated findings, so the properties start
from an empty store and from a store of closed Issues derived by planning and settling first.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner

from tests.fakes import issue_store as fake
from tests.strategies import supply_chain as sc
from tests.test_supply_chain_planner import OTHER, REPO, _finding, _inputs, _policy, _vex

STATUSES: tuple[models.VexStatus, ...] = ("not_affected", "fixed", "affected", "under_investigation")
EXCLUDING = frozenset({"not_affected", "fixed"})
STAMP = datetime(2026, 1, 1, tzinfo=UTC)
CONTEXT = "https://openvex.dev/ns/v0.2.0"


def _rk(repo: models.Repo) -> tuple[str, str]:
    return (repo.owner.lower(), repo.name.lower())


def _ids(finding: models.Finding) -> tuple[str, ...]:
    return (finding.vuln_id, *finding.aliases)


def _ordered(found: Sequence[models.Finding]) -> list[models.Finding]:
    return sorted(found, key=lambda f: (_rk(f.repo), f.vuln_id, f.component.purl))


def _doc(path: str, vuln_id: str, aliases: tuple[str, ...], purl: str, status: models.VexStatus) -> models.VexDocument:
    statement = models.VexStatement(vuln_id, aliases, (purl,), status, "component_not_present", None, STAMP)
    return models.VexDocument("urn:example:9", CONTEXT, "example", None, STAMP, 1, None, (statement,), path)


def _other_version(purl: str) -> str:
    other = purl.replace("@", "@9999-", 1)
    assert other != purl
    return other


def _vex_map(entries: Sequence[tuple[models.Repo, models.VexDocument]]) -> dict[models.Repo, tuple[models.VexDocument]]:
    out: dict[models.Repo, list[models.VexDocument]] = {}
    for repo, doc in entries:
        out.setdefault(repo, []).append(doc)
    return {repo: tuple(docs) for repo, docs in out.items()}


@st.composite
def _cases(draw: st.DrawFn) -> tuple[models.PlanInputs, list[tuple[models.Finding, models.VexStatus, int]]]:
    """Inputs plus, for some findings, the status and shape of a statement that names them."""
    policy = draw(sc.policies())
    inputs = draw(sc.plan_inputs(12, 0, policy=policy))
    ok = sorted(inputs.fetch_ok, key=_rk)
    originals = [f for f in _ordered(inputs.findings) if not f.vuln_id.startswith("MAL-")]
    copy_flags = draw(st.lists(st.booleans(), min_size=len(originals), max_size=len(originals)))
    copies = {  # the same finding in the next fetched repository, so a statement can match in one repository only
        replace(f, repo=ok[(ok.index(f.repo) + 1) % len(ok)])
        for f, flag in zip(originals, copy_flags, strict=True)
        if flag and len(ok) > 1
    }
    inputs = replace(inputs, findings=inputs.findings | copies)
    found = _ordered(inputs.findings)
    picks = draw(
        st.lists(
            st.tuples(st.booleans(), st.sampled_from(STATUSES), st.integers(0, 63)),
            min_size=len(found),
            max_size=len(found),
        )
    )
    return inputs, [(f, status, shape) for f, (on, status, shape) in zip(found, picks, strict=True) if on]


def _statements(picks: Sequence[tuple[models.Finding, models.VexStatus, int]]) -> dict[models.Repo, tuple]:
    """One document per pick: the statement names one identifier of the finding and, by shape, the rest."""
    entries = []
    for n, (f, status, shape) in enumerate(picks):
        ids = _ids(f)
        head = ids[shape % len(ids)]
        rest = tuple(i for i in ids if i != head) if shape & 4 else ()
        aliases_only = [i for i in ids if not i.startswith("MAL-")]
        if (
            shape & 32 and planner.is_malicious(f) and aliases_only
        ):  # a statement on a non-MAL- id of a malicious finding
            head, rest = aliases_only[0], ()
        elif shape & 16:  # a malicious-package statement that lists the finding only as an alias
            head, rest = "MAL-2098-0001", ids
        elif shape & 8:  # a statement about another vulnerability that lists the finding's ids as aliases
            head, rest = "CVE-2098-0001", ids
        entries.append((f.repo, _doc(f".vex/{n:03d}.json", head, rest, f.component.purl, status)))
    return _vex_map(entries)


def _excluded(inputs: models.PlanInputs, vex: dict[models.Repo, tuple]) -> tuple[models.Finding, ...]:
    """The findings the written rule suppresses: excluding status, a listed id, the exact purl, not malicious."""
    allowed = set(inputs.policy.vex_exclude_statuses) & EXCLUDING
    keys: set[tuple[tuple[str, str], str, str]] = set()
    for repo, docs in vex.items():
        for doc in docs:
            for s in doc.statements:
                names = (s.vuln_id, *s.aliases)
                if s.status in allowed and not any(n.startswith("MAL-") for n in names):
                    keys.update((_rk(repo), n, p) for n in names for p in s.products)
    return tuple(
        f
        for f in _ordered(inputs.findings)
        if not planner.is_malicious(f) and any((_rk(f.repo), i, f.component.purl) in keys for i in _ids(f))
    )


def _settled(inputs: models.PlanInputs, state: str) -> models.PlanInputs:
    """``inputs`` with an empty store (``"none"``) or with the Issues a first run would leave, closed."""
    base = replace(inputs, vex={}, issues=())
    if state == "none":
        return base
    first = planner.plan(base)
    store = fake.IssueStore.from_managed(())
    for action in first.actions:
        store = store.apply_action(action)
    managed = fake.to_managed_issues(store, issue_body.parse_state)
    return replace(base, issues=tuple(replace(i, state="closed") for i in managed))


def _check_exclusion(inputs: models.PlanInputs, vex: dict[models.Repo, tuple], state: str) -> Counter[str]:
    base = _settled(inputs, state)
    excluded = _excluded(inputs, vex)
    kept = frozenset(inputs.findings) - set(excluded)
    got = planner.plan(replace(base, vex=vex))
    want = planner.plan(replace(base, findings=kept, vex={}))
    plain = planner.plan(base)
    assert got.actions == want.actions
    assert got.overflow_counts == want.overflow_counts
    assert got.malicious_withdrawn_unconfirmed == want.malicious_withdrawn_unconfirmed
    assert {f for f, _ in got.vex_exclusions} == set(excluded)
    assert len(got.vex_exclusions) == len(excluded)
    supported = {(_rk(f.repo), f.vuln_id) for f in kept}
    for a in got.actions:
        if a.op in ("create", "reopen") and a.kind == "finding" and not (a.vuln_id or "").startswith("MAL-"):
            assert (_rk(a.repo), a.vuln_id) in supported
    seen: Counter[str] = Counter()
    seen["excluded"] += bool(excluded)
    seen["effect"] += got.actions != plain.actions
    seen["reopen_stopped"] += any(a.op == "reopen" and a not in got.actions for a in plain.actions)
    seen["create_stopped"] += any(a.op == "create" and a not in got.actions for a in plain.actions)
    seen["not_excluding_status"] += any(
        s.status in ("affected", "under_investigation") for docs in vex.values() for d in docs for s in d.statements
    )
    return seen


# Feature: cyber-resilience-phase4-supply-chain, Property 9: 承認済みの VEX だけが起票を止める
@settings(max_examples=100, deadline=None)
@given(_cases(), st.sampled_from(("none", "closed")))
def test_only_an_approved_vex_statement_stops_an_issue(
    case: tuple[models.PlanInputs, list[tuple[models.Finding, models.VexStatus, int]]], state: str
) -> None:
    """A matching, excluding, non-malicious statement removes the finding from create and reopen; nothing else does.

    **Validates: Requirements 7.7, 7.10, 11.9, 11.10, 27.7**
    """
    inputs, picks = case
    seen = _check_exclusion(inputs, _statements(picks), state)
    event(f"excluded={bool(seen['excluded'])}")
    event(f"effect={bool(seen['effect'])}")


def _noise(
    inputs: models.PlanInputs, kinds: Sequence[int], status_index: Sequence[int]
) -> list[tuple[models.Repo, models.VexDocument]]:
    """Statements that must not matter: wrong status, other version, status the policy does not exclude, unrelated id."""
    allowed = set(inputs.policy.vex_exclude_statuses) & EXCLUDING
    disallowed = sorted(EXCLUDING - allowed)
    out: list[tuple[models.Repo, models.VexDocument]] = []
    for n, (f, kind, s) in enumerate(zip(_ordered(inputs.findings), kinds, status_index, strict=False)):
        ids = _ids(f)
        malicious = planner.is_malicious(f)
        path = f".vex/zz-noise-{n:03d}.json"
        if kind == 0:  # affected / under_investigation never excludes
            out.append((f.repo, _doc(path, ids[0], ids[1:], f.component.purl, STATUSES[2 + s % 2])))
        elif kind == 1:  # another version of the same component
            status = STATUSES[2 + s % 2] if malicious else STATUSES[s % 4]
            out.append((f.repo, _doc(path, ids[0], ids[1:], _other_version(f.component.purl), status)))
        elif kind == 2 and disallowed and not malicious:  # an excluding status the policy does not list
            out.append((f.repo, _doc(path, ids[0], ids[1:], f.component.purl, disallowed[s % len(disallowed)])))  # type: ignore[arg-type]
        elif kind == 3:  # an identifier no finding has
            out.append((f.repo, _doc(path, "CVE-2099-0001", (), f.component.purl, STATUSES[s % 4])))
    return out


# Feature: cyber-resilience-phase4-supply-chain, Property 9: 承認済みの VEX だけが起票を止める
@settings(max_examples=100, deadline=None)
@given(
    _cases(),
    st.lists(st.integers(0, 4), max_size=12),
    st.lists(st.integers(0, 3), min_size=12, max_size=12),
    st.sampled_from(("none", "closed")),
)
def test_statements_that_do_not_apply_change_nothing(
    case: tuple[models.PlanInputs, list[tuple[models.Finding, models.VexStatus, int]]],
    kinds: list[int],
    status_index: list[int],
    state: str,
) -> None:
    """Adding or removing a non-excluding, other-version, unlisted-status or unrelated statement leaves the plan as it was.

    **Validates: Requirements 7.7, 7.10, 11.9, 11.10, 27.7**
    """
    inputs, picks = case
    base = _settled(inputs, state)
    kept = _statements(picks)
    noise = _noise(inputs, kinds, status_index)
    noisy = {**kept}
    for repo, doc in noise:
        noisy[repo] = (*noisy.get(repo, ()), doc)
    event(f"noise={'some' if noise else 'none'}")
    assert planner.plan(replace(base, vex=noisy)) == planner.plan(replace(base, vex=kept))
    assert planner.plan(replace(base, vex=_vex_map(noise))) == planner.plan(replace(base, vex={}))


def test_generated_cases_exercise_suppression_and_the_statements_that_do_not_apply() -> None:
    """The properties above are not vacuous: suppression changes plans, stops create and reopen, noise is present."""
    seen: Counter[str] = Counter()

    # derandomize: some seeds draw no reopen; a fixed sequence keeps the check that every form occurs.
    @settings(max_examples=150, deadline=None, derandomize=True)
    @given(_cases(), st.sampled_from(("none", "closed")), st.lists(st.integers(0, 4), max_size=12))
    def run(
        case: tuple[models.PlanInputs, list[tuple[models.Finding, models.VexStatus, int]]], state: str, kinds: list[int]
    ) -> None:
        inputs, picks = case
        seen.update(_check_exclusion(inputs, _statements(picks), state))
        seen["noise"] += bool(_noise(inputs, kinds, [0, 1, 2, 3] * 3))

    run()
    missing = [
        k
        for k in ("excluded", "effect", "reopen_stopped", "create_stopped", "not_excluding_status", "noise")
        if not seen[k]
    ]
    assert not missing, f"never seen: {missing}; counts {sorted(seen.items())}"


# --- fixed examples for the cases the generators reach only occasionally -----------------------


def test_a_statement_naming_only_an_alias_of_the_finding_suppresses_it() -> None:
    finding = _finding("CVE-2026-0001", aliases=("GHSA-aaaa-bbbb-cccc",))
    plan = planner.plan(_inputs((finding,), vex={REPO: (_vex("not_affected", "GHSA-aaaa-bbbb-cccc"),)}))
    assert plan.actions == ()
    assert [f for f, _ in plan.vex_exclusions] == [finding]


def test_a_statement_listing_the_finding_as_an_alias_suppresses_it() -> None:
    finding = _finding("CVE-2026-0001", aliases=("GHSA-aaaa-bbbb-cccc",))
    plan = planner.plan(
        _inputs((finding,), vex={REPO: (_vex("fixed", "CVE-2026-9999", aliases=("GHSA-aaaa-bbbb-cccc",)),)})
    )
    assert plan.actions == ()


def test_a_statement_in_one_repository_does_not_suppress_the_same_finding_in_another() -> None:
    here, there = _finding(repo=REPO), _finding(repo=OTHER)
    plan = planner.plan(_inputs((here, there), vex={REPO: (_vex("not_affected", "CVE-2026-0001"),)}))
    assert [(a.op, a.repo) for a in plan.actions] == [("create", OTHER)]


def test_a_status_the_policy_does_not_list_does_not_suppress() -> None:
    policy = replace(_policy(), vex_exclude_statuses=("not_affected",))
    plan = planner.plan(_inputs((_finding(),), policy=policy, vex={REPO: (_vex("fixed", "CVE-2026-0001"),)}))
    assert [a.op for a in plan.actions] == ["create"]
    assert plan.vex_exclusions == ()


def test_a_statement_that_lists_a_malicious_id_never_suppresses_a_plain_finding() -> None:
    finding = _finding("GHSA-aaaa-bbbb-cccc")
    statement = _vex("not_affected", "MAL-2026-0001", aliases=("GHSA-aaaa-bbbb-cccc",))
    plan = planner.plan(_inputs((finding,), vex={REPO: (statement,)}))
    assert [a.op for a in plan.actions] == ["create"]
    assert plan.vex_exclusions == ()

"""Self-checks for ``tests/strategies/supply_chain.py`` (task 9.1).

Each strategy gets two kinds of check. First, what it builds passes the model's own checks (the
dataclass constructors, ``parse_policy``, ``render_openvex``). Second, it does not draw the same
few shapes: ``_observed`` runs the strategy with a fixed seed and collects labels, and the test
asserts that every shape the docstring promises appears.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

import hypothesis.strategies as st
from hypothesis import HealthCheck, given, settings
from supply_chain.models import Finding, PlanInputs, Policy
from supply_chain.policy import DEFAULT_EXCLUDED_REPOSITORIES, parse_policy, render_policy
from supply_chain.vex import parse_openvex, render_openvex

from tests.strategies import supply_chain as sc

_SETTINGS = settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _observed(
    strategy: st.SearchStrategy[Any], labels: Callable[[Any], Iterable[str]], examples: int = 300
) -> set[str]:
    """Runs ``strategy`` with a fixed seed and returns the union of ``labels(value)``."""
    seen: set[str] = set()

    @settings(
        max_examples=examples,
        deadline=None,
        derandomize=True,
        database=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(strategy)
    def run(value: Any) -> None:
        seen.update(labels(value))

    run()
    return seen


def _is_utc(value: datetime | None) -> bool:
    return value is None or (
        value.tzinfo is not None and value.utcoffset() is not None and value.utcoffset().total_seconds() == 0
    )


# --- repositories and policies ---------------------------------------------------------------


@_SETTINGS
@given(sc.repo_lists("svc", 0, 6))
def test_repo_lists_are_unique_ignoring_case(found: list[Any]) -> None:
    keys = [(r.owner.lower(), r.name.lower()) for r in found]
    assert len(keys) == len(set(keys))


def test_repos_draw_both_letter_cases_of_one_name() -> None:
    names = _observed(sc.repos(), lambda r: [r.name.split("-")[1]], 200)
    assert {"api", "API", "Web", "WEB", "core", "CORE"} <= names


@_SETTINGS
@given(sc.policies())
def test_policies_pass_the_policy_parser_unchanged(policy: Policy) -> None:
    assert parse_policy(render_policy(policy)) == policy


def test_policies_cover_their_variation() -> None:
    def labels(p: Policy) -> list[str]:
        return [
            f"sev:{p.opening_threshold.min_cvss_severity}",
            f"kev:{p.opening_threshold.open_if_kev_listed}",
            "enabled" if p.automerge_enabled_repositories else "no-enabled",
            "extra-excluded" if len(p.excluded_repositories) > len(DEFAULT_EXCLUDED_REPOSITORIES) else "defaults-only",
            "multi-target" if len(p.target_repositories) > 1 else "one-target",
            "no-paths" if not p.non_production_paths else "paths",
            f"vex:{len(p.vex_exclude_statuses)}",
        ]

    seen = _observed(sc.policies(), labels)
    assert {"sev:LOW", "sev:MEDIUM", "sev:HIGH", "sev:CRITICAL", "kev:True", "kev:False"} <= seen
    assert {"enabled", "no-enabled", "extra-excluded", "defaults-only", "multi-target", "one-target"} <= seen
    assert {"no-paths", "paths", "vex:1", "vex:2"} <= seen


# --- findings --------------------------------------------------------------------------------


def _finding_labels(found: frozenset[Finding]) -> list[str]:
    out = ["empty" if not found else "nonempty", f"size>={min(len(found) // 50, 4) * 50}"]
    if sc.ghsa_malware_pairs(found):
        out.append("q11-pair")
    for f in found:
        malicious = f.vuln_id.startswith("MAL-")
        if f.vuln_id.startswith("CVE-"):
            out.append("cve+alias" if f.aliases else "cve")
        elif f.vuln_id in sc.MALWARE_GHSA_IDS:
            out.append("ghsa-malware")
        elif f.vuln_id.startswith("GHSA-"):
            out.append("ghsa+alias" if f.aliases else "ghsa")
        elif malicious:
            out.append("mal+alias" if f.aliases else "mal")
        if not malicious and f.vuln_id not in sc.MALWARE_GHSA_IDS and f.cvss_severity is None:
            out.append("unscored")
        if f.fixed_version is None:
            out.append("no-fix")
        out.append(f"layer:{f.layer}")
        out.append("published" if f.advisory_published_at else "no-published")
    return out


@_SETTINGS
@given(sc.findings())
def test_findings_satisfy_the_data_model_constraints(found: frozenset[Finding]) -> None:
    keys = [(f.repo, f.vuln_id, f.component.purl) for f in found]
    assert len(keys) == len(set(keys))
    mal_keys = [(f.repo, f.component.purl) for f in found if f.vuln_id.startswith("MAL-")]
    assert len(mal_keys) == len(set(mal_keys))
    for f in found:
        assert f.repo in sc.DEFAULT_REPOS
        assert _is_utc(f.advisory_published_at)
        assert (
            f.first_observed_component_at.tzinfo is UTC
            or f.first_observed_component_at.utcoffset().total_seconds() == 0
        )
        assert f.component.purl.endswith("@" + f.component.version)
        if f.vuln_id.startswith("MAL-") or f.vuln_id in sc.MALWARE_GHSA_IDS:
            assert f.cvss_severity is None
            assert f.fixed_version is None


def test_findings_cover_every_shape_and_both_ends_of_the_size_range() -> None:
    seen = _observed(sc.findings(), _finding_labels, 400)
    shapes = {"cve", "cve+alias", "ghsa", "ghsa+alias", "mal", "mal+alias", "ghsa-malware", "q11-pair", "unscored"}
    assert shapes <= seen
    assert {"no-fix", "layer:A", "layer:B", "published", "no-published", "empty"} <= seen
    assert "size>=150" in seen, "a set of 150 or more findings was never drawn"


def test_findings_reach_the_documented_maximum() -> None:
    largest = max(
        (len(v) for v in _sample(sc.findings(max_size=sc.MAX_COLLECTION), 60)),
        default=0,
    )
    assert largest >= 190


def test_findings_over_no_repositories_are_empty() -> None:
    assert set(_sample(sc.findings([]), 5)) == {frozenset()}


def _sample(strategy: st.SearchStrategy[Any], examples: int) -> list[Any]:
    """Draws ``examples`` values with a fixed seed."""
    out: list[Any] = []

    @settings(
        max_examples=examples,
        deadline=None,
        derandomize=True,
        database=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(strategy)
    def run(value: Any) -> None:
        out.append(value)

    run()
    return out


# --- VEX -------------------------------------------------------------------------------------


@_SETTINGS
@given(sc.vex_documents())
def test_vex_documents_render_and_parse_back(docs: tuple[Any, ...]) -> None:
    assert len({d.path for d in docs}) == len(docs)
    for doc in docs:
        assert len(doc.statements) == 1
        assert parse_openvex(render_openvex(doc), doc.path) == doc


def test_vex_documents_cover_statuses_and_malicious_statements() -> None:
    def labels(docs: tuple[Any, ...]) -> list[str]:
        out = []
        for d in docs:
            s = d.statements[0]
            out.append(f"status:{s.status}")
            if s.vuln_id.startswith("MAL-"):
                out.append(f"mal:{s.status}")
            out.append("two-products" if len(s.products) > 1 else "one-product")
        return out

    seen = _observed(sc.vex_documents(), labels)
    assert {"status:not_affected", "status:affected", "status:fixed", "status:under_investigation"} <= seen
    assert {"mal:not_affected", "mal:fixed", "two-products", "one-product"} <= seen


@_SETTINGS
@given(sc.vex_maps(list(sc.DEFAULT_REPOS)))
def test_vex_maps_have_an_entry_per_repository(vex: Any) -> None:
    assert set(vex) == set(sc.DEFAULT_REPOS)


# --- managed issues --------------------------------------------------------------------------


@_SETTINGS
@given(sc.managed_issues())
def test_managed_issues_are_unique_and_numbered(issues: tuple[Any, ...]) -> None:
    assert [i.number for i in issues] == list(range(1, len(issues) + 1))
    keys = [(i.repo, i.kind, i.vuln_id) for i in issues]
    assert len(keys) == len(set(keys))
    for i in issues:
        assert (i.vuln_id is None) == (i.kind != "finding")
        if i.body_state is not None:
            assert i.body_state["vuln_id"] == i.vuln_id
            assert i.body_state["malicious"] == (i.vuln_id or "").startswith("MAL-")


def test_managed_issues_cover_kinds_states_and_size() -> None:
    def labels(issues: tuple[Any, ...]) -> list[str]:
        out = ["empty" if not issues else "nonempty", f"size>={min(len(issues) // 50, 4) * 50}"]
        for i in issues:
            out += [f"kind:{i.kind}", f"state:{i.state}", "state-block" if i.body_state else "no-state-block"]
            if i.vuln_id and i.vuln_id.startswith("MAL-"):
                out.append("mal-issue")
        return out

    seen = _observed(sc.managed_issues(), labels)
    assert {"kind:finding", "kind:summary", "kind:failure", "state:open", "state:closed", "mal-issue"} <= seen
    assert {"state-block", "no-state-block", "empty", "size>=150"} <= seen


# --- feeds -----------------------------------------------------------------------------------


@_SETTINGS
@given(sc.feeds())
def test_feeds_match_their_flags_and_get_responses(case: sc.FeedsCase) -> None:
    snap = case.snapshot
    assert (snap.kev is not None) == case.kev_ok
    assert (snap.epss is not None) == case.epss_ok
    assert (snap.malicious is not None) == case.malicious_ok
    withdrawn, delisted, unconfirmed = (
        set(snap.malicious_withdrawn),
        snap.malicious_delisted,
        snap.malicious_unconfirmed,
    )
    assert not withdrawn & delisted and not withdrawn & unconfirmed and not delisted & unconfirmed
    for mal, response in case.get_responses.items():
        assert mal.startswith("MAL-")
        expected = {
            "withdrawn": withdrawn,
            "delisted": delisted,
            "withdrawn_unreadable": unconfirmed,
            "empty": unconfirmed,
            "failed": unconfirmed,
        }.get(response.kind)
        if expected is None:
            assert response.kind == "alive"
            assert mal not in withdrawn | delisted | unconfirmed
        else:
            assert mal in expected
        if response.kind == "empty":
            assert response.body == {} and response.http_status == 200
        if response.kind == "failed":
            assert response.body is None and response.http_status != 200
    assert withdrawn | delisted | unconfirmed <= set(case.get_responses)
    for when in snap.malicious_withdrawn.values():
        assert _is_utc(when)
    assert all(not v.startswith("MAL-") for v in (snap.kev or {})) and all(
        not v.startswith("MAL-") for v in (snap.epss or {})
    )


def test_feeds_draw_the_three_fetches_and_the_get_responses_independently() -> None:
    def labels(case: sc.FeedsCase) -> list[str]:
        out = [f"fetch:{int(case.kev_ok)}{int(case.epss_ok)}{int(case.malicious_ok)}"]
        out += [f"get:{r.kind}" for r in case.get_responses.values()]
        if case.snapshot.malicious is None and case.snapshot.malicious_withdrawn:
            out.append("withdrawn-while-malicious-feed-failed")
        if case.snapshot.malicious and not case.get_responses:
            out.append("feed-ok-no-get")
        if case.snapshot.kev:
            out.append("kev-nonempty")
        if case.snapshot.epss:
            out.append("epss-nonempty")
        if case.snapshot.malicious:
            out.append("malicious-nonempty")
        return out

    seen = _observed(sc.feeds(), labels)
    assert {f"fetch:{a}{b}{c}" for a in "01" for b in "01" for c in "01"} <= seen
    assert {f"get:{k}" for k in sc.GET_KINDS if k != "not_queried"} <= seen
    assert {"withdrawn-while-malicious-feed-failed", "kev-nonempty", "epss-nonempty", "malicious-nonempty"} <= seen


# --- plan inputs -----------------------------------------------------------------------------


def _check_plan_inputs(inputs: PlanInputs) -> None:
    targets = set(inputs.policy.target_repositories)
    assert inputs.fetch_ok <= targets
    assert {f.repo for f in inputs.findings} <= inputs.fetch_ok
    assert {i.repo for i in inputs.issues} <= targets
    assert set(inputs.vex) == targets
    assert len(inputs.findings) <= 2 * sc.MAX_COLLECTION and len(inputs.issues) <= sc.MAX_COLLECTION
    stamps = [f.first_observed_component_at for f in inputs.findings] + [p.created_at for p in inputs.pull_requests]
    assert all(s < inputs.now for s in stamps)
    for pr in inputs.pull_requests:
        assert pr.merged_at is None or pr.merged_at >= pr.created_at
        assert pr.repo in targets


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(sc.plan_inputs())
def test_plan_inputs_are_internally_consistent(inputs: PlanInputs) -> None:
    _check_plan_inputs(inputs)


def test_plan_inputs_cover_their_variation() -> None:
    def labels(i: PlanInputs) -> list[str]:
        out = []
        if i.findings:
            out.append("findings")
        if len(i.findings) >= 150:
            out.append("findings>=150")
        if len(i.issues) >= 150:
            out.append("issues>=150")
        if i.fetch_ok != frozenset(i.policy.target_repositories):
            out.append("some-fetch-failed")
        if not i.fetch_ok:
            out.append("no-fetch-ok")
        if i.pull_requests:
            out.append("pull-requests")
        if any(p.merged_at for p in i.pull_requests):
            out.append("merged-pr")
        if sc.ghsa_malware_pairs(i.findings):
            out.append("q11-pair")
        finding_ids = {f.vuln_id for f in i.findings}
        if any(m.vuln_id and m.vuln_id not in finding_ids for m in i.issues):
            out.append("stale-issue")
        if any(m.vuln_id in finding_ids for m in i.issues):
            out.append("matching-issue")
        if i.feeds.kev is None:
            out.append("kev-failed")
        if any(d for docs in i.vex.values() for d in docs):
            out.append("vex")
        return out

    seen = _observed(sc.plan_inputs(), labels, 150)
    expected = {
        "findings",
        "findings>=150",
        "issues>=150",
        "some-fetch-failed",
        "no-fetch-ok",
        "pull-requests",
        "merged-pr",
        "q11-pair",
        "stale-issue",
        "matching-issue",
        "kev-failed",
        "vex",
    }
    assert expected <= seen, sorted(expected - seen)


def test_plan_inputs_with_small_limits_stay_within_them() -> None:
    for inputs in _sample(sc.plan_inputs(max_findings=3, max_issues=2), 40):
        assert len(inputs.findings) <= 6 and len(inputs.issues) <= 2
        _check_plan_inputs(inputs)

"""Hypothesis strategies for the supply-chain pure core (``solutions/supply-chain``).

Task 9.1 of the phase 4 spec. The property tests of tasks 9.x draw their inputs from here, and
``tests/test_supply_chain_strategies.py`` checks that each strategy builds what its docstring says.
Import as::

    from tests.strategies import supply_chain as sc_strategies

Strategies:

- :func:`repos`, :func:`repo_lists`: ``Repo`` values; case variants of one name are the same repo.
- :func:`policies`: a ``Policy`` that ``parse_policy(render_policy(p))`` accepts unchanged.
- :func:`findings`: a ``frozenset[Finding]`` of 0 to 200 drawn specs (a Q-11 pair is two members). Shapes: ``CVE-`` and ``GHSA-`` findings with and
  without aliases, ``MAL-`` findings with and without a ``GHSA-`` alias, and the Q-11 pair (a
  ``GHSA-`` malware finding and a ``MAL-`` finding on the same repo and component, neither with
  an alias to the other). :func:`ghsa_malware_pairs` lists the pairs of a set.
- :func:`vex_documents`, :func:`vex_maps`: OpenVEX documents that ``render_openvex`` accepts.
- :func:`managed_issues`: 0 to 200 ``ManagedIssue`` values, at most one per (repo, kind, vuln_id).
- :func:`feeds`: a :class:`FeedsCase`. KEV, EPSS and the malicious feed succeed or fail
  independently, and the ``GET /v1/vulns/{id}`` responses (and so the withdrawn, delisted and
  unconfirmed sets) are drawn independently of the malicious feed's success.
- :func:`pull_requests` and :func:`plan_inputs`: a whole ``PlanInputs`` in which every part refers
  to the same repositories and identifiers.

Construction. No strategy uses ``filter`` or ``assume``. A value that must be avoided is built so
that it cannot occur: identifiers come from small pools by index, datetimes are built from integer
offsets (always timezone-aware, UTC, whole seconds), and a repeated key is folded away by a dict
after drawing. ``st.lists(..., unique_by=...)`` is used for repositories only (hypothesis retries a
repeated element inside the draw). Large collections are described by compact integer tuples
because one example has a data budget of 8 KiB.

Synthetic data only: owners are ``example-org``, ``Example-Labs`` and ``sample-team``; names,
identifiers and versions are numbered; nothing here is a real account, address or advisory.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

import hypothesis.strategies as st
from supply_chain.models import (
    AutomergeRule,
    Component,
    CooldownDays,
    FeedSnapshot,
    Finding,
    ManagedIssue,
    OpeningThreshold,
    PlanInputs,
    Policy,
    PullRequestRef,
    Repo,
    ResponseTarget,
    VexDocument,
    VexStatement,
)
from supply_chain.policy import DEFAULT_EXCLUDED_REPOSITORIES
from supply_chain.vex import JUSTIFICATIONS, OPENVEX_CONTEXT

OWNERS = ("example-org", "Example-Labs", "sample-team")
_WORDS = ("api", "Web", "core")
MAX_COLLECTION = 200
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_DAY0 = date(2025, 6, 1)

CVE_POOL = 60  # CVE-2026-0 .. CVE-2026-59
GHSA_POOL = 60  # GHSA ids of ordinary advisories
MAL_POOL = 40  # MAL-2026-0 .. MAL-2026-39
COMPONENT_POOL = 40  # pkg-0 .. pkg-39
VERSION_POOL = 4


# --- identifiers -----------------------------------------------------------------------------


def cve_id(n: int) -> str:
    """Returns the ``n``-th synthetic CVE identifier."""
    return f"CVE-2026-{n:05d}"


def ghsa_id(n: int) -> str:
    """Returns the ``n``-th synthetic GHSA identifier (four-letter groups)."""
    letters = "cfghjmpqrvwx"
    groups = []
    for shift in (1, 7, 13):
        value = n * shift + 17
        groups.append("".join(letters[(value // 12**k) % 12] for k in range(4)))
    return "GHSA-" + "-".join(groups)


def ghsa_malware_id(n: int) -> str:
    """Returns the ``n``-th GHSA identifier of a malware advisory (disjoint from :func:`ghsa_id`)."""
    return ghsa_id(1000 + n)


def mal_id(n: int) -> str:
    """Returns the ``n``-th synthetic ``MAL-`` identifier."""
    return f"MAL-2026-{n:04d}"


def purl_of(component: int, version: int) -> str:
    """Returns the purl (with version) of component ``component`` at version ``version``."""
    return f"pkg:npm/pkg-{component}@{version + 1}.{component % 10}.0"


def component_of(
    component: int,
    version: int,
    direct: int = 2,
    author: int = 0,
    stage: int = 0,
    fmt: int = 0,
) -> Component:
    """Builds the ``Component`` for ``purl_of(component, version)``.

    ``direct``, ``author``, ``stage`` and ``fmt`` pick the extension fields by index; the default
    leaves them ``unknown``.
    """
    return Component(
        purl=purl_of(component, version),
        name=f"pkg-{component}",
        version=f"{version + 1}.{component % 10}.0",
        direct=("direct", "transitive", "unknown")[direct % 3],  # type: ignore[arg-type]
        author=("unknown", "example-author", "example-vendor")[author % 3],
        format_name=("unknown", "spdx", "cyclonedx")[fmt % 3],
        format_version=("unknown", "2.3", "1.6")[fmt % 3],
        generation_stage=("unknown", "build", "source")[stage % 3],
    )


def utc_at(minutes: int) -> datetime:
    """Returns a timezone-aware UTC datetime ``minutes`` after :data:`EPOCH` (whole seconds)."""
    return EPOCH + timedelta(minutes=minutes)


def iso_z(value: datetime) -> str:
    """Formats an aware UTC datetime as ISO 8601 with whole seconds and a ``Z``."""
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_datetimes(min_days: int = 0, max_days: int = 400) -> st.SearchStrategy[datetime]:
    """Aware UTC datetimes between ``EPOCH + min_days`` and ``EPOCH + max_days`` (whole seconds)."""
    return st.integers(min_days * 1440, max_days * 1440).map(utc_at)


# --- sizes -----------------------------------------------------------------------------------


def sizes(max_size: int = MAX_COLLECTION) -> st.SearchStrategy[int]:
    """Collection sizes in ``0..max_size``, with empty, small and full-size collections all common."""
    return st.one_of(
        st.just(0),
        st.integers(0, min(3, max_size)),
        st.integers(0, min(25, max_size)),
        st.integers(0, max_size),
        st.just(max_size),
    )


def _fixed_lists(element: st.SearchStrategy, max_size: int) -> st.SearchStrategy[list]:
    """A list whose length is drawn from :func:`sizes` (one draw, then exactly that many elements)."""
    return sizes(max_size).flatmap(lambda n: st.lists(element, min_size=n, max_size=n))


# --- repositories and policies ---------------------------------------------------------------


def repos(prefix: str = "svc") -> st.SearchStrategy[Repo]:
    """A ``Repo`` named ``<prefix>-<word>-<n>`` under one of :data:`OWNERS`.

    The word comes in two letter cases (``api``/``Web``/``core``), so two draws can name the same
    repository in different cases; ``Repo`` treats them as equal.
    """
    return st.tuples(st.sampled_from(OWNERS), st.sampled_from(_WORDS), st.integers(0, 9), st.booleans()).map(
        lambda t: Repo(t[0], f"{prefix}-{t[1].upper() if t[3] else t[1]}-{t[2]}")
    )


def _repo_key(repo: Repo) -> tuple[str, str]:
    return (repo.owner.lower(), repo.name.lower())


def repo_lists(prefix: str = "svc", min_size: int = 0, max_size: int = 6) -> st.SearchStrategy[list[Repo]]:
    """Lists of repositories that are pairwise different, ignoring case."""
    return st.lists(repos(prefix), min_size=min_size, max_size=max_size, unique_by=_repo_key)


def _split_repo(text: str) -> Repo:
    owner, name = text.split("/")
    return Repo(owner, name)


@st.composite
def policies(draw: st.DrawFn) -> Policy:
    """A ``Policy`` that satisfies the Policy_File schema and its cross-field rules.

    Targets are ``svc-`` repositories, extra exclusions are ``old-`` repositories (never targets),
    the four default exclusions are always present, the automerge enabled list is a subset of the
    targets, ``package_manager_wait`` equals ``cooldown_days``, and ``fix_days_kev_or_malicious``
    does not exceed ``fix_days_high``.
    """
    targets = draw(repo_lists("svc", min_size=1, max_size=6))
    extra = draw(repo_lists("old", min_size=0, max_size=3))
    excluded = tuple(_split_repo(t) for t in DEFAULT_EXCLUDED_REPOSITORIES) + tuple(extra)
    enabled = draw(st.lists(st.sampled_from(targets), max_size=len(targets), unique_by=_repo_key))
    default_days = draw(st.integers(1, 30))
    major_days = default_days + draw(st.integers(0, 60))
    urgent = draw(st.integers(1, 14))
    rules = draw(
        st.lists(
            st.tuples(
                st.sampled_from(("npm", "github-actions")),
                st.lists(st.just("devDependencies"), max_size=2),
                st.integers(1, 2),
            ),
            min_size=1,
            max_size=3,
        )
    )
    optional_excludes = draw(
        st.lists(
            st.sampled_from(
                ("runtime_dependencies", "minor", "major", "digest_only", "unknown_dep_type", "hub_reusable_workflow")
            ),
            max_size=6,
            unique=True,
        )
    )
    paths = draw(
        st.lists(st.sampled_from(("docs/", "examples/", "test/", "tests/", "fixtures/", "bench/")), unique=True)
    )
    return Policy(
        schema_version=1,
        target_repositories=tuple(targets),
        excluded_repositories=excluded,
        opening_threshold=OpeningThreshold(
            min_cvss_severity=draw(st.sampled_from(("LOW", "MEDIUM", "HIGH", "CRITICAL"))),
            open_if_kev_listed=draw(st.booleans()),
            open_if_malicious=True,
        ),
        cooldown_days=CooldownDays(default=default_days, major=major_days),
        automerge_include=tuple(
            AutomergeRule(manager=m, dep_types=tuple(d), update_types=("patch",) * n)  # type: ignore[arg-type]
            for m, d, n in rules
        ),
        automerge_exclude=("vulnerability_fix", *optional_excludes),
        automerge_enabled_repositories=tuple(enabled),
        package_manager_wait=CooldownDays(default=default_days, major=major_days),
        non_production_paths=tuple(paths),
        vex_directory=".vex",
        vex_exclude_statuses=draw(st.sampled_from((("not_affected",), ("fixed",), ("not_affected", "fixed")))),
        vex_approver_role="VEX_Reviewer",
        vex_one_statement_per_document=True,
        vex_malicious_never_suppressed=True,
        response_target=ResponseTarget(
            detect_hours=draw(st.integers(1, 48)),
            fix_days_kev_or_malicious=urgent,
            fix_days_high=urgent + draw(st.integers(0, 60)),
        ),
        max_new_issues_per_repo_per_run=draw(st.integers(1, 100)),
    )


# --- findings --------------------------------------------------------------------------------

DEFAULT_REPOS = (Repo("example-org", "svc-api-0"), Repo("Example-Labs", "svc-Web-1"), Repo("sample-team", "svc-core-2"))
MALWARE_GHSA_IDS = frozenset(ghsa_malware_id(n) for n in range(MAL_POOL))
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", None)

# shape index -> shape name. Shapes 7 and 8 draw the Q-11 pair, so the pair is common.
SHAPES = ("cve", "cve", "cve", "ghsa", "ghsa", "mal", "mal_alias", "pair", "pair", "ghsa_malware")


def _finding_spec(repo_count: int) -> st.SearchStrategy[tuple[int, ...]]:
    """One finding as nine small integers: shape, repo, vuln, component, version, severity, flags, days, days."""
    return st.tuples(
        st.integers(0, len(SHAPES) - 1),
        st.integers(0, repo_count - 1),
        st.integers(0, CVE_POOL - 1),
        st.integers(0, COMPONENT_POOL - 1),
        st.integers(0, VERSION_POOL - 1),
        st.integers(0, len(_SEVERITIES) - 1),
        st.integers(0, 255),
        st.integers(0, 400),
        st.integers(0, 400),
    )


def _findings_of_spec(spec: tuple[int, ...], repos_: Sequence[Repo]) -> list[Finding]:
    """Builds the one or two findings that ``spec`` describes."""
    shape, repo_i, vuln, comp, ver, sev_i, flags, day_a, day_b = spec
    repo = repos_[repo_i]
    component = component_of(comp, ver, flags % 3, (flags // 3) % 3, (flags // 9) % 3, (flags // 27) % 3)
    published = utc_at(day_a * 1440 + (flags >> 3) * 5) if flags & 4 else None
    observed = utc_at(day_b * 1440 + (flags >> 2) * 5)
    fixed = f"{ver + 2}.{comp % 10}.0" if flags & 2 else None
    layer = "A" if flags & 1 else "B"

    def build(vuln_id: str, aliases: tuple[str, ...], severity: str | None, fix: str | None) -> Finding:
        return Finding(
            repo=repo,
            vuln_id=vuln_id,
            aliases=aliases,
            component=component,
            cvss_severity=severity,  # type: ignore[arg-type]
            fixed_version=fix,
            advisory_published_at=published,
            layer=layer,  # type: ignore[arg-type]
            first_observed_component_at=observed,
        )

    kind = SHAPES[shape]
    severity = _SEVERITIES[sev_i]
    if kind == "cve":
        return [build(cve_id(vuln), (ghsa_id(vuln),) if flags & 8 else (), severity, fixed)]
    if kind == "ghsa":
        return [build(ghsa_id(vuln), (cve_id(vuln),) if flags & 8 else (), severity, fixed)]
    mal_n = vuln % MAL_POOL
    if kind == "mal":
        return [build(mal_id(mal_n), (), None, None)]
    if kind == "mal_alias":
        return [build(mal_id(mal_n), (ghsa_malware_id(mal_n),), None, None)]
    if kind == "pair":
        return [build(mal_id(mal_n), (), None, None), build(ghsa_malware_id(mal_n), (), None, None)]
    return [build(ghsa_malware_id(mal_n), (), None, None)]


def _fold_findings(specs: Sequence[tuple[int, ...]], repos_: Sequence[Repo]) -> frozenset[Finding]:
    """Builds the findings of ``specs`` and folds repeated keys away.

    A key is ``(repo, vuln_id, purl)``; a ``MAL-`` finding is also unique by ``(repo, purl)``, so one
    component of one repository has at most one ``MAL-`` finding.
    """
    seen: set[tuple[object, ...]] = set()
    out: list[Finding] = []
    for spec in specs:
        for finding in _findings_of_spec(spec, repos_):
            key: tuple[object, ...] = (finding.repo, finding.vuln_id, finding.component.purl)
            mal_key: tuple[object, ...] = (finding.repo, "MAL", finding.component.purl)
            if key in seen or (finding.vuln_id.startswith("MAL-") and mal_key in seen):
                continue
            seen.add(key)
            if finding.vuln_id.startswith("MAL-"):
                seen.add(mal_key)
            out.append(finding)
    return frozenset(out)


def findings(
    repos_: Sequence[Repo] | None = None, max_size: int = MAX_COLLECTION
) -> st.SearchStrategy[frozenset[Finding]]:
    """A set of 0 to ``max_size`` findings (a Q-11 pair counts as two) over ``repos_``.

    Args:
        repos_: The repositories the findings belong to (default: :data:`DEFAULT_REPOS`). An empty
            sequence gives the empty set.
        max_size: The largest number of drawn specs; the set can hold up to ``2 * max_size`` members
            when many specs are Q-11 pairs, and fewer when keys repeat.

    Returns:
        A strategy of frozensets. Every finding has timezone-aware UTC datetimes; ``CVE-``/``GHSA-``
        findings have a severity (or ``None``, which makes them unscored), ``MAL-`` and GHSA-malware
        findings never have one, and ``MAL-`` identifiers are unique per ``(repo, purl)``.
    """
    pool = tuple(repos_) if repos_ is not None else DEFAULT_REPOS
    if not pool:
        return st.just(frozenset())
    return _fixed_lists(_finding_spec(len(pool)), max_size).map(lambda specs: _fold_findings(specs, pool))


def ghsa_malware_pairs(found: Sequence[Finding] | frozenset[Finding]) -> tuple[tuple[Finding, Finding], ...]:
    """Lists the Q-11 pairs in ``found``: a ``MAL-`` finding and a GHSA-malware finding.

    A pair is two findings of one repository and one purl, neither listing the other's identifier
    as an alias. The result is sorted by ``(repo, purl)`` so a test can compare it.
    """
    pairs = []
    for mal in found:
        if not mal.vuln_id.startswith("MAL-"):
            continue
        for ghsa in found:
            if (
                ghsa.vuln_id in MALWARE_GHSA_IDS
                and ghsa.repo == mal.repo
                and ghsa.component.purl == mal.component.purl
                and ghsa.vuln_id not in mal.aliases
                and mal.vuln_id not in ghsa.aliases
            ):
                pairs.append((mal, ghsa))
    return tuple(sorted(pairs, key=lambda p: (p[0].repo.owner.lower(), p[0].repo.name.lower(), p[0].component.purl)))


def finding_vuln_ids(found: frozenset[Finding]) -> tuple[str, ...]:
    """The distinct identifiers of ``found`` in sorted order (for feed and issue pools)."""
    return tuple(sorted({f.vuln_id for f in found}))


# --- OpenVEX documents -----------------------------------------------------------------------

DEFAULT_VULN_IDS = (
    tuple(cve_id(n) for n in range(CVE_POOL))
    + tuple(ghsa_id(n) for n in range(GHSA_POOL))
    + tuple(mal_id(n) for n in range(MAL_POOL))
)
DEFAULT_PURLS = tuple(purl_of(c, v) for c in range(COMPONENT_POOL) for v in range(VERSION_POOL))
_STATUS_ORDER = ("not_affected", "affected", "fixed", "under_investigation")


def _vex_document(spec: tuple[int, ...], index: int, vuln_ids: Sequence[str], purls: Sequence[str]) -> VexDocument:
    """Builds the one-statement document that ``spec`` describes (OpenVEX needs one per document)."""
    vi, pi, status_i, just_i, flags, day = spec
    status = _STATUS_ORDER[status_i]
    products = [purls[pi % len(purls)]]
    if flags & 16:
        products.append(purls[(pi + 1) % len(purls)])
    statement = VexStatement(
        vuln_id=vuln_ids[vi % len(vuln_ids)],
        aliases=(cve_id(vi % CVE_POOL),) if flags & 4 else (),
        products=tuple(products),
        status=status,  # type: ignore[arg-type]
        justification=JUSTIFICATIONS[just_i] if status == "not_affected" or flags & 1 else None,
        impact_statement="synthetic impact statement" if flags & 2 else None,
        timestamp=utc_at(day * 1440) if flags & 8 else None,
    )
    return VexDocument(
        id=f"https://example.com/vex/{index}",
        context=OPENVEX_CONTEXT,
        author="example-reviewer",
        role="VEX_Reviewer" if flags & 32 else None,
        timestamp=utc_at(day * 1440 + 90),
        version=1 + flags % 3,
        tooling="example-tool" if flags & 64 else None,
        statements=(statement,),
        path=f".vex/doc-{index}.json",
    )


def vex_documents(
    vuln_ids: Sequence[str] | None = None, purls: Sequence[str] | None = None, max_size: int = 6
) -> st.SearchStrategy[tuple[VexDocument, ...]]:
    """0 to ``max_size`` OpenVEX documents, each with one statement, that ``render_openvex`` accepts.

    Statements name an identifier of ``vuln_ids`` (default: CVE, GHSA and ``MAL-`` pools) and one or
    two purls of ``purls`` (default: every component at every version of the finding pools), so a
    statement can match a finding of :func:`findings`. A ``not_affected`` statement always has a
    justification; ``affected`` and ``under_investigation`` statements are drawn too, and so are
    statements about ``MAL-`` identifiers (which must never suppress anything).
    """
    ids = tuple(vuln_ids) if vuln_ids else DEFAULT_VULN_IDS
    urls = tuple(purls) if purls else DEFAULT_PURLS
    spec = st.tuples(
        st.integers(0, len(ids) - 1),
        st.integers(0, len(urls) - 1),
        st.integers(0, 3),
        st.integers(0, len(JUSTIFICATIONS) - 1),
        st.integers(0, 127),
        st.integers(0, 400),
    )
    return _fixed_lists(spec, max_size).map(
        lambda specs: tuple(_vex_document(s, i, ids, urls) for i, s in enumerate(specs))
    )


def vex_maps(
    repos_: Sequence[Repo], vuln_ids: Sequence[str] | None = None, purls: Sequence[str] | None = None
) -> st.SearchStrategy[Mapping[Repo, tuple[VexDocument, ...]]]:
    """A VEX mapping with one entry per repository of ``repos_`` (an entry may be empty)."""
    return st.tuples(*[vex_documents(vuln_ids, purls, 4) for _ in repos_]).map(
        lambda docs: dict(zip(repos_, docs, strict=True))
    )


# --- managed issues --------------------------------------------------------------------------


def _body_state(vuln_id: str, flags: int, day: int, comp: int, ver: int) -> dict[str, object]:
    """A state block as the design shows it (``supply-chain-aggregator-state``)."""
    malicious = vuln_id.startswith("MAL-")
    opened = iso_z(utc_at(day * 1440))
    return {
        "vuln_id": vuln_id,
        "components": [{"purl": purl_of(comp, ver), "version": f"{ver + 1}.{comp % 10}.0"}],
        "cvss_severity": None if malicious else _SEVERITIES[flags % 4],
        "kev_listed": bool(flags & 4),
        "kev": None,
        "malicious": malicious,
        "epss": None,
        "fixed_version": None,
        "origin_at": opened,
        "detected_at": opened,
        "opened_at": opened,
        "due_at": iso_z(utc_at(day * 1440) + timedelta(days=7 if malicious or flags & 4 else 30)),
        "last_run_id": "100-1",
        "history": [{"op": "open", "run_id": "100-1", "at": opened}],
    }


def _issues_of(specs: Sequence[tuple[int, ...]], repos_: Sequence[Repo], vuln_ids: Sequence[str]) -> tuple:
    seen: set[tuple[object, ...]] = set()
    out: list[ManagedIssue] = []
    for kind_i, repo_i, vuln_i, state_i, flags, day, comp, ver in specs:
        repo = repos_[repo_i]
        kind = "finding" if kind_i < 8 else ("summary" if kind_i == 8 else "failure")
        vuln_id = vuln_ids[vuln_i % len(vuln_ids)] if kind == "finding" else None
        if kind == "finding":
            # A taken key moves to the next free identifier, so a full-size draw stays full-size.
            for step in range(len(vuln_ids)):
                vuln_id = vuln_ids[(vuln_i + step) % len(vuln_ids)]
                if (repo, kind, vuln_id) not in seen:
                    break
        key = (repo, kind, vuln_id)
        if key in seen:
            continue
        seen.add(key)
        state = _body_state(vuln_id, flags, day, comp, ver) if vuln_id is not None and not flags & 128 else None
        out.append(
            ManagedIssue(
                repo=repo,
                number=len(out) + 1,
                kind=kind,  # type: ignore[arg-type]
                vuln_id=vuln_id,
                state="closed" if state_i else "open",
                body_state=state,
            )
        )
    return tuple(out)


def managed_issues(
    repos_: Sequence[Repo] | None = None, vuln_ids: Sequence[str] | None = None, max_size: int = MAX_COLLECTION
) -> st.SearchStrategy[tuple[ManagedIssue, ...]]:
    """0 to ``max_size`` managed issues, at most one per ``(repo, kind, vuln_id)``, numbered from 1.

    Eight of ten specs are ``finding`` issues (``vuln_id`` from ``vuln_ids``, default
    :data:`DEFAULT_VULN_IDS`; open or closed; a state block unless the spec says the body could not
    be read, which gives ``body_state=None``); the others are ``summary`` and ``failure`` issues
    with ``vuln_id=None``.
    """
    pool = tuple(repos_) if repos_ is not None else DEFAULT_REPOS
    ids = tuple(vuln_ids) if vuln_ids else DEFAULT_VULN_IDS
    if not pool:
        return st.just(())
    spec = st.tuples(
        st.integers(0, 9),
        st.integers(0, len(pool) - 1),
        st.integers(0, len(ids) - 1),
        st.integers(0, 1),
        st.integers(0, 255),
        st.integers(0, 400),
        st.integers(0, COMPONENT_POOL - 1),
        st.integers(0, VERSION_POOL - 1),
    )
    return _fixed_lists(spec, max_size).map(lambda specs: _issues_of(specs, pool, ids))


# --- feeds -----------------------------------------------------------------------------------

GET_KINDS = ("not_queried", "withdrawn", "withdrawn_unreadable", "alive", "delisted", "empty", "failed")


@dataclass(frozen=True, slots=True)
class OsvGetResponse:
    """What ``GET /v1/vulns/{id}`` answered for one ``MAL-`` identifier.

    Attributes:
        kind: One of :data:`GET_KINDS` except ``not_queried`` (which has no response).
        http_status: ``None`` for a transport failure, else the status code.
        body: The decoded JSON body, or ``None`` when there is none.
    """

    kind: str
    http_status: int | None
    body: Mapping[str, object] | None


@dataclass(frozen=True, slots=True)
class FeedsCase:
    """A feed snapshot with the responses that produced its ``MAL-`` sets.

    Attributes:
        snapshot: The ``FeedSnapshot``. ``kev``, ``epss`` and ``malicious`` are ``None`` exactly
            when ``kev_ok``, ``epss_ok`` and ``malicious_ok`` are false.
        kev_ok: Whether the KEV fetch succeeded.
        epss_ok: Whether the EPSS fetch succeeded.
        malicious_ok: Whether the malicious-packages fetch (querybatch) succeeded.
        get_responses: ``MAL-`` id to its ``GET`` response, for ids that were queried. Drawn
            independently of ``malicious_ok``: ``withdrawn`` goes to ``malicious_withdrawn``,
            ``delisted`` to ``malicious_delisted``, and ``withdrawn_unreadable``, ``empty`` (``{}``)
            and ``failed`` to ``malicious_unconfirmed``; ``alive`` and ids not queried to none.
    """

    snapshot: FeedSnapshot
    kev_ok: bool
    epss_ok: bool
    malicious_ok: bool
    get_responses: Mapping[str, OsvGetResponse]


def _get_response(kind: str, mal: str, code: int) -> OsvGetResponse:
    modified = iso_z(utc_at(300 * 1440 + code))
    if kind == "withdrawn":
        body = {"id": mal, "modified": modified, "withdrawn": iso_z(utc_at(310 * 1440 + code))}
        return OsvGetResponse(kind, 200, body)
    if kind == "withdrawn_unreadable":
        return OsvGetResponse(kind, 200, {"id": mal, "modified": modified, "withdrawn": "not-a-time"})
    if kind == "alive":
        return OsvGetResponse(kind, 200, {"id": mal, "modified": modified, "affected": [{"versions": ["1.0.0"]}]})
    if kind == "delisted":
        return OsvGetResponse(kind, 200, {"id": mal, "modified": modified, "affected": []})
    if kind == "empty":
        return OsvGetResponse(kind, 200, {})
    return OsvGetResponse("failed", None if code % 2 else 503, None)


def _feeds_case(
    flags: tuple[bool, bool, bool],
    codes: Sequence[int],
    mal_codes: Sequence[int],
    ids: Sequence[str],
    mals: Sequence[str],
) -> FeedsCase:
    kev_ok, epss_ok, mal_ok = flags
    kev = {
        v: (_DAY0 + timedelta(days=c), (None, True, False)[(c >> 1) % 3])
        for v, c in zip(ids, codes, strict=True)
        if c & 1
    }
    epss = {
        v: (f"0.{(c * 397) % 100000:05d}", _DAY0 + timedelta(days=200 + c), ("v2025.03.14", "v2026.01.01")[c & 1])
        for v, c in zip(ids, codes, strict=True)
        if c & 2
    }
    published = {m: (utc_at(c * 600) if c & 8 else None) for m, c in zip(mals, mal_codes, strict=True) if c & 4}
    responses: dict[str, OsvGetResponse] = {}
    withdrawn: dict[str, datetime] = {}
    delisted: set[str] = set()
    unconfirmed: set[str] = set()
    for mal, code in zip(mals, mal_codes, strict=True):
        kind = GET_KINDS[(code >> 4) % len(GET_KINDS)]
        if kind == "not_queried":
            continue
        response = _get_response(kind, mal, code)
        responses[mal] = response
        if kind == "withdrawn":
            withdrawn[mal] = utc_at(310 * 1440 + code)
        elif kind == "delisted":
            delisted.add(mal)
        elif kind in ("withdrawn_unreadable", "empty", "failed"):
            unconfirmed.add(mal)
    snapshot = FeedSnapshot(
        kev=kev if kev_ok else None,
        epss=epss if epss_ok else None,
        malicious=published if mal_ok else None,
        malicious_withdrawn=withdrawn,
        malicious_delisted=frozenset(delisted),
        malicious_unconfirmed=frozenset(unconfirmed),
    )
    return FeedsCase(snapshot, kev_ok, epss_ok, mal_ok, responses)


def feeds(vuln_ids: Sequence[str] | None = None, mal_ids: Sequence[str] | None = None) -> st.SearchStrategy[FeedsCase]:
    """A :class:`FeedsCase` over ``vuln_ids`` (KEV and EPSS) and ``mal_ids`` (the malicious feed).

    The success of KEV, EPSS and the malicious feed are three independent booleans. The ``GET``
    responses are drawn per ``MAL-`` id from seven cases (not queried, withdrawn with a readable
    time, withdrawn with an unreadable value, alive, delisted, ``{}``, failed) whatever the
    malicious feed did, so a snapshot can carry a withdrawn id while ``malicious`` is ``None``.
    ``MAL-`` ids in ``vuln_ids`` are left out of KEV and EPSS.
    """
    ids = tuple(
        sorted({v for v in (vuln_ids if vuln_ids is not None else DEFAULT_VULN_IDS) if not v.startswith("MAL-")})
    )
    mals = tuple(sorted({m for m in (mal_ids if mal_ids is not None else DEFAULT_VULN_IDS) if m.startswith("MAL-")}))
    return st.builds(
        _feeds_case,
        st.tuples(st.booleans(), st.booleans(), st.booleans()),
        st.lists(st.integers(0, 255), min_size=len(ids), max_size=len(ids)),
        st.lists(st.integers(0, 255), min_size=len(mals), max_size=len(mals)),
        st.just(ids),
        st.just(mals),
    )


# --- pull requests and plan inputs -----------------------------------------------------------


def pull_requests(
    repos_: Sequence[Repo], vuln_ids: Sequence[str], max_size: int = 20
) -> st.SearchStrategy[tuple[PullRequestRef, ...]]:
    """0 to ``max_size`` pull requests; ``merged_at`` is ``None`` or at/after ``created_at``."""
    if not repos_ or not vuln_ids:
        return st.just(())
    spec = st.tuples(
        st.integers(0, len(repos_) - 1),
        st.integers(0, len(vuln_ids) - 1),
        st.integers(0, 400),
        st.integers(-1, 20000),  # negative: not merged; else minutes after creation
    )

    def build(s: tuple[int, ...]) -> PullRequestRef:
        created = utc_at(s[2] * 1440)
        return PullRequestRef(
            repo=repos_[s[0]],
            vuln_id=vuln_ids[s[1]],
            created_at=created,
            merged_at=None if s[3] < 0 else created + timedelta(minutes=s[3]),
        )

    return _fixed_lists(spec, max_size).map(lambda specs: tuple(build(s) for s in specs))


@st.composite
def plan_inputs(
    draw: st.DrawFn,
    max_findings: int = MAX_COLLECTION,
    max_issues: int = MAX_COLLECTION,
    policy: Policy | None = None,
) -> PlanInputs:
    """A ``PlanInputs`` whose parts refer to the same repositories and identifiers.

    ``fetch_ok`` is a drawn subset of the policy's targets and every finding belongs to one of
    them. Issues cover all targets, including repositories whose fetch failed, and draw their
    identifiers from the findings' identifiers and the pools, so some issues match a finding and
    some are stale. The feeds are drawn over the same identifier pools. ``now`` is after every
    datetime in the findings and issues.
    """
    chosen = policy if policy is not None else draw(policies())
    targets = list(chosen.target_repositories)
    fetch_ok = draw(st.lists(st.sampled_from(targets), max_size=len(targets), unique_by=_repo_key))
    found = draw(findings(fetch_ok, max_findings))
    pool = tuple(sorted(set(finding_vuln_ids(found)) | set(DEFAULT_VULN_IDS)))
    mals = tuple(v for v in pool if v.startswith("MAL-"))
    issues = draw(managed_issues(targets, pool, max_issues))
    case = draw(feeds(pool, mals))
    vex = draw(vex_maps(targets))
    prs = draw(pull_requests(targets, pool))
    return PlanInputs(
        policy=chosen,
        run_id=f"{draw(st.integers(1, 10**6))}-{draw(st.integers(1, 3))}",
        now=utc_at(draw(st.integers(450 * 1440, 480 * 1440))),
        pull_requests=prs,
        findings=found,
        fetch_ok=frozenset(fetch_ok),
        feeds=case.snapshot,
        vex=vex,
        issues=issues,
    )

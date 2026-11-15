"""Issue planning (pure).

``plan`` turns the findings, the feed snapshot, the VEX documents and the
Issues that already exist into the list of Issue operations for one run. It
reads nothing and writes nothing: the same ``PlanInputs`` give the same
``Plan``, down to the bytes of every body (design section 3, "plan steps"
1 to 8). Applying the plan, and fetching its inputs, belong to the I/O layer.

Unit of an Issue: ``(repo, vuln_id)``. A Malicious_Package_Finding is first
merged by ``(repo, purl, version)`` (a GHSA malware advisory and a ``MAL-``
record of one package version become one group, the ``MAL-`` identifier is
the representative) and groups of one repository that end up with the same
representative are merged again, so one repository never holds two Issues
with the same marker.

Before anything else the findings of one repository are joined by identifier (``canonicalize``): a GHSA and a
CVE record that name each other are one vulnerability, so one Issue (Requirement 8.1).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

from supply_chain.canonical import canonical_id, canonicalize, multi_cve_records, purl_key
from supply_chain.issue_body import (
    FindingIssue,
    HistoryEntry,
    SummaryEntry,
    UnscoredEntry,
    comparison_state,
    parse_state,
    render_finding,
    render_summary,
    render_unscored,
)
from supply_chain.models import (
    DEFAULT_UNSCORED_REVIEW_DAYS,
    OVERDUE_LABEL,
    CloseReason,
    Component,
    Finding,
    IssueAction,
    KevEntry,
    ManagedIssue,
    Plan,
    PlanInputs,
    Repo,
    Severity,
)
from supply_chain.threshold import MALICIOUS_PREFIX, SEVERITY_RANK, is_malicious, meets_opening_threshold
from supply_chain.vex import REASON_ALIAS_ONLY, REASON_MALICIOUS, REASON_PREDATES_KEV, VexRef, effective_exclusions

_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_HIGH = SEVERITY_RANK["HIGH"]

RepoKey = tuple[str, str]
IssueId = tuple[RepoKey, int]


def _repo_key(repo: Repo) -> RepoKey:
    return (repo.owner.lower(), repo.name.lower())


def _issue_id(issue: ManagedIssue) -> IssueId:
    return (_repo_key(issue.repo), issue.number)


def _finding_key(finding: Finding) -> tuple[Any, ...]:
    """A total order over findings, so no result depends on set iteration order."""
    return (
        _repo_key(finding.repo),
        finding.vuln_id,
        finding.component.purl,
        finding.component.version,
        finding.aliases,
        finding.repo.owner,
        finding.repo.name,
        finding.layer,
    )


@dataclass(frozen=True, slots=True)
class _Group:
    """The findings that one Issue stands for."""

    repo: Repo
    vuln_id: str
    aliases: tuple[str, ...]
    findings: tuple[Finding, ...]
    malicious: bool

    @property
    def ids(self) -> tuple[str, ...]:
        return (self.vuln_id, *self.aliases)

    @property
    def components(self) -> tuple[Component, ...]:
        seen = {(c.purl, c.version, c.name): c for c in (f.component for f in self.findings)}
        return tuple(seen[k] for k in sorted(seen))

    @property
    def severity(self) -> Severity | None:
        if self.malicious:
            return None
        ranked = [f.cvss_severity for f in self.findings if f.cvss_severity is not None]
        return max(ranked, key=lambda s: SEVERITY_RANK[s]) if ranked else None


@dataclass(frozen=True, slots=True)
class _Run:
    """Per-run constants read from the inputs."""

    inputs: PlanInputs
    kev: Mapping[str, KevEntry | tuple[date, bool | None]] | None
    # (repo, primary id) -> path of a VEX statement that names only an alias of the Finding (T12-R5-02); set after
    # the classification, read when the Issue bodies are built.
    vex_alias_only: Mapping[tuple[RepoKey, str], str] = field(default_factory=dict)

    def kev_of(self, ids: Iterable[str]) -> KevEntry | tuple[date, bool | None] | None:
        if self.kev is None:
            return None
        return next((self.kev[i] for i in ids if i in self.kev), None)

    def kev_latest_listing(self, ids: Iterable[str]) -> date | None:
        """Returns the latest ``dateAdded`` among the KEV entries of ``ids``, or ``None`` when none is listed.

        A VEX judgment made before any of the Finding's identifiers was listed has to be reviewed again
        (Requirement 11.15 d), so the latest listing counts, not the first identifier found (F16-N1).
        """
        if self.kev is None:
            return None
        return max((self.kev[i][0] for i in ids if i in self.kev), default=None)

    def epss_of(self, ids: Iterable[str]) -> tuple[str, date, str] | None:
        table = self.inputs.feeds.epss
        if table is None:
            return None
        return next((table[i] for i in ids if i in table), None)

    def published_of(self, ids: Iterable[str]) -> datetime | None:
        table = self.inputs.feeds.malicious
        if table is None:
            return None
        return next((table[i] for i in ids if table.get(i) is not None), None)


def _state_time(state: Mapping[str, Any] | None, key: str) -> datetime | None:
    raw = state.get(key) if state else None
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, _TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def _state_history(state: Mapping[str, Any] | None) -> tuple[HistoryEntry, ...]:
    raw = state.get("history") if state else None
    out: list[HistoryEntry] = []
    for entry in raw if isinstance(raw, list) else ():
        if not isinstance(entry, Mapping) or not isinstance(entry.get("op"), str):
            continue
        at = _state_time(entry, "at")
        if at is not None and isinstance(entry.get("run_id"), str):
            out.append(HistoryEntry(entry["op"], entry["run_id"], at))
    return tuple(out)


def _state_components(state: Mapping[str, Any] | None) -> frozenset[tuple[str, str]]:
    raw = state.get("components") if state else None
    return frozenset(
        (c["purl"], c["version"])
        for c in (raw if isinstance(raw, list) else ())
        if isinstance(c, Mapping) and isinstance(c.get("purl"), str) and isinstance(c.get("version"), str)
    )


def _ids_of(finding: Finding) -> tuple[str, ...]:
    return (finding.vuln_id, *finding.aliases)


def _issue_is_malicious(issue: ManagedIssue) -> bool:
    flag = issue.body_state.get("malicious") if issue.body_state else None
    return bool((issue.vuln_id or "").startswith(MALICIOUS_PREFIX) or flag is True)


# --- steps 1 and 2: VEX exclusion and the threshold ------------------------------------------


@dataclass(frozen=True, slots=True)
class _Classified:
    included: tuple[Finding, ...]
    rest: tuple[Finding, ...]  # did not meet the threshold, not excluded
    exclusions: tuple[tuple[Finding, str], ...]
    vex_ids: Mapping[tuple[RepoKey, str], VexRef]  # (repo, id) of an excluded finding -> VEX reference
    rejected: frozenset[tuple[str, str]]
    # (repo, Finding's primary id) -> path of a statement that names only an alias of the Finding (T12-R5-02)
    alias_only: Mapping[tuple[RepoKey, str], str] = field(default_factory=dict)


def _classify(run: _Run) -> _Classified:
    inputs = run.inputs
    kev_ids = None if run.kev is None else frozenset(run.kev)
    tables: dict[RepoKey, dict[tuple[str, str], VexRef]] = {}
    rejected: set[tuple[str, str]] = set()
    for repo in sorted(inputs.vex, key=_repo_key):
        table, rej = effective_exclusions(
            list(inputs.vex[repo]),
            inputs.policy,
            now=inputs.now,
            merged_at=(inputs.vex_merged_at or {}).get(repo),
        )
        tables[_repo_key(repo)] = table
        rejected.update(rej)
    included: list[Finding] = []
    rest: list[Finding] = []
    exclusions: list[tuple[Finding, str]] = []
    alias_only: dict[tuple[RepoKey, str], str] = {}
    vex_ids: dict[tuple[RepoKey, str], VexRef] = {}
    # A name that two different vulnerabilities of one repository both carry (a GHSA shared by two CVEs after
    # the split of Requirement 8.25) names neither of them: a statement or an Issue under it would otherwise
    # cover a CVE nobody judged (T2-R3-02, T2-R3-03).
    owners: dict[tuple[RepoKey, str], set[str]] = {}
    for f in inputs.findings:
        for i in f.aliases:
            owners.setdefault((_repo_key(f.repo), canonical_id(i)), set()).add(canonical_id(f.vuln_id))
    shared = {k for k, who in owners.items() if len(who) > 1}
    for finding in sorted(inputs.findings, key=_finding_key):
        table = tables.get(_repo_key(finding.repo), {})
        key_purl = purl_key(finding.component.purl)
        names = (
            finding.vuln_id,
            *(i for i in finding.aliases if (_repo_key(finding.repo), canonical_id(i)) not in shared),
        )
        # A statement covers a Finding only if the statement itself names the Finding's identifier (its name or
        # its aliases). The Finding's own aliases are not looked up, so a name two CVEs share excludes neither
        # of them, with or without the sibling (T12-R4-05). A malicious package is also looked up by its aliases,
        # only so that a statement on one of them is reported as rejected.
        malicious = is_malicious(finding)
        lookup = names if malicious else (finding.vuln_id,)
        ref = next((r for i in lookup if (r := table.get((canonical_id(i), key_purl or "")))), None)
        named_primary = ref is not None
        listed = run.kev_latest_listing((finding.vuln_id, *finding.aliases))
        if (
            ref is not None
            and not malicious
            and ref.at is not None
            and listed is not None
            and listed >= ref.at.date()  # dateAdded has no time of day: the same day cannot be ordered
        ):
            rejected.add((ref.path, REASON_PREDATES_KEV))  # listed after the judgment: it has to be reviewed again
            ref = None
        if ref is not None and malicious:
            rejected.add((ref.path, REASON_MALICIOUS))  # a malicious package is never suppressed
        elif ref is not None:
            exclusions.append((finding, ref.path))
            for i in names:
                vex_ids.setdefault((_repo_key(finding.repo), i), ref)
            continue
        if not named_primary and not malicious:
            # No statement names the Finding's own identifier. A statement that names one of its aliases (a GHSA
            # without the CVE in its ``aliases``) is kept out of the exclusion, and the miss is recorded so that
            # the number of statements that had to be rewritten can be counted (T12-R5-02).
            # Only a Finding that opens an Issue is recorded: one below the threshold would stay unopened even if
            # the statement were rewritten, so counting it overstates the rewrites needed (T12-R6-04).
            hint = next(
                (h for i in finding.aliases if (h := table.get((canonical_id(i), key_purl or ""))) is not None), None
            )
            if hint is not None and meets_opening_threshold(finding, kev_ids, inputs.policy.opening_threshold):
                rejected.add((hint.path, REASON_ALIAS_ONLY))
                alias_only[(_repo_key(finding.repo), finding.vuln_id)] = hint.path
        if meets_opening_threshold(finding, kev_ids, inputs.policy.opening_threshold):
            included.append(finding)
        else:
            rest.append(finding)
    return _Classified(tuple(included), tuple(rest), tuple(exclusions), vex_ids, frozenset(rejected), alias_only)


# --- step 3: grouping --------------------------------------------------------------------------


def _build_groups(included: Sequence[Finding]) -> list[_Group]:
    """Builds the groups of Issues.

    A malicious package version (``MAL-`` identifier, or an advisory typed ``malware``) is one group however
    many records name it. The representative is the ``MAL-`` identifier when there is one.
    """
    plain: dict[tuple[RepoKey, str], list[Finding]] = {}
    units: dict[tuple[RepoKey, str, str], list[Finding]] = {}
    for f in included:
        if is_malicious(f):
            units.setdefault((_repo_key(f.repo), f.component.purl, f.component.version), []).append(f)
        else:
            plain.setdefault((_repo_key(f.repo), f.vuln_id), []).append(f)
    groups = [
        _Group(
            members[0].repo,
            vuln_id,
            tuple(sorted({a for m in members for a in m.aliases} - {vuln_id})),
            tuple(members),
            False,
        )
        for (_, vuln_id), members in plain.items()
    ]
    merged: dict[tuple[RepoKey, str], _Group] = {}
    for unit_key in sorted(units):
        members = units[unit_key]
        ids = {i for m in members for i in (m.vuln_id, *m.aliases)}
        mal_ids = [i for i in ids if i.startswith(MALICIOUS_PREFIX)]
        rep = min(mal_ids) if mal_ids else min(ids)  # a GHSA malware advisory that no MAL- record names
        key = (unit_key[0], rep)
        old = merged.get(key)
        all_members = (*old.findings, *members) if old else tuple(members)
        all_ids = ids | ({*old.ids} if old else set())
        merged[key] = _Group(members[0].repo, rep, tuple(sorted(all_ids - {rep})), all_members, True)
    groups.extend(merged.values())
    groups.sort(key=lambda g: (_repo_key(g.repo), g.vuln_id))
    return groups


# --- step 4: matching existing Issues ------------------------------------------------------------


def _pick(candidates: Iterable[ManagedIssue]) -> ManagedIssue | None:
    ordered = sorted(candidates, key=lambda i: (i.state != "open", i.number))
    return ordered[0] if ordered else None


def _continue_as_malicious(group: _Group, issue: ManagedIssue | None) -> _Group:
    """Re-homes a GHSA malware group under the ``MAL-`` identifier of the Issue it continues.

    The Issue keeps its identifier and the GHSA identifier becomes an alias, as when ``MAL-`` and GHSA of one
    package version are grouped (Q-11), so the Issue is updated instead of closed and created anew.
    """
    if (
        issue is None
        or issue.vuln_id is None
        or not group.malicious
        or group.vuln_id.startswith(MALICIOUS_PREFIX)
        or not issue.vuln_id.startswith(MALICIOUS_PREFIX)
    ):
        return group
    if issue.vuln_id == group.vuln_id:
        return group
    aliases = tuple(sorted({*group.ids} - {issue.vuln_id}))
    return _Group(group.repo, issue.vuln_id, aliases, group.findings, True)


def _assign(groups: Sequence[_Group], issues: Sequence[ManagedIssue]) -> tuple[dict[int, ManagedIssue], set[IssueId]]:
    """Maps group index to the Issue it continues, and returns every Issue number a group claims.

    Pass 1 matches the representative identifier. Pass 2 lets a group take an Issue whose identifier
    is now one of its aliases, or (for ``MAL-``) whose recorded component is one of its components,
    so a change of representative continues the same Issue (Requirement 8.5).
    """
    pool = [i for i in issues if i.kind == "finding" and i.vuln_id is not None]
    claimed: set[IssueId] = set()
    chosen: dict[int, ManagedIssue] = {}
    for index, group in enumerate(groups):
        same = [i for i in pool if i.repo == group.repo and i.vuln_id == group.vuln_id]
        picked = _pick(same)
        if picked is not None:
            chosen[index] = picked
            claimed.update(_issue_id(i) for i in same)
    for index, group in enumerate(groups):
        if index in chosen:
            continue
        ids = set(group.ids)
        comps = {(c.purl, c.version) for c in group.components}
        near = [
            i
            for i in pool
            if i.repo == group.repo
            and _issue_id(i) not in claimed
            and (
                i.vuln_id in ids
                or (group.malicious and _issue_is_malicious(i) and comps & _state_components(i.body_state))
            )
        ]
        picked = _pick(near)
        if picked is not None:
            chosen[index] = picked
            claimed.add(_issue_id(picked))
    return chosen, claimed


# --- bodies --------------------------------------------------------------------------------------


def _origin(group: _Group, run: _Run, kev: KevEntry | tuple[date, bool | None] | None) -> tuple[datetime | None, bool]:
    """Origin = the later of "threshold first met" and "component version first observed" (Requirement 18.3).

    When the time that met the threshold is unknown the origin is ``None`` (shown as unknown and left out of
    the detection actual, Requirement 18.4). The observation time is never a stand-in: it is about the time
    the Aggregator opens the Issue, so it would make the detection actual look like zero.
    """
    observed = min(f.first_observed_component_at for f in group.findings)
    met: datetime | None
    date_only = False
    cvss_met = any(
        meets_opening_threshold(f, None, run.inputs.policy.opening_threshold)
        for f in group.findings
        if not group.malicious
    )
    if group.malicious:
        met = run.published_of(group.ids)
    elif cvss_met:
        times = [f.advisory_published_at for f in group.findings if f.advisory_published_at is not None]
        met = min(times) if times else None
    elif kev is not None:
        met, date_only = datetime(kev[0].year, kev[0].month, kev[0].day, tzinfo=UTC), True
    else:
        met = None
    if met is None:
        return None, False
    return (met, date_only) if met >= observed else (observed, False)


def _finding_issue(
    group: _Group, repo: Repo, run: _Run, op: str, prior: Mapping[str, Any] | None, closed_at: datetime | None = None
) -> FindingIssue:
    inputs = run.inputs
    now, target = inputs.now, inputs.policy.response_target
    kev = run.kev_of(group.ids)
    severity = group.severity
    opened = _state_time(prior, "opened_at") or now
    days = target.fix_days_kev_or_malicious if (kev is not None or group.malicious) else target.fix_days_high
    # An Issue closed for longer than its Response_Target starts a new response, not the old one (T2-R2-05).
    stale_reopen = op == "reopen" and closed_at is not None and now - closed_at > timedelta(days=days)
    if stale_reopen:
        prior = {k: v for k, v in (prior or {}).items() if k not in ("opened_at", "due_at")}
        opened = now
    detected = _state_time(prior, "detected_at") or now
    origin, date_only = _origin(group, run, kev)
    if _state_time(prior, "origin_at") is not None and isinstance(prior, Mapping):
        origin = _state_time(prior, "origin_at") or origin
        date_only = prior.get("origin_is_date_only") is True
    prior_due = _state_time(prior, "due_at")
    # The catalogue's release time bounds the origin only when KEV is what met the threshold (T2-R2-06).
    released = (
        _state_time(prior, "kev_first_release_at") or (inputs.feeds.kev_released_at if kev is not None else None)
        if date_only
        else None
    )
    if op == "create":
        due = now + timedelta(days=days)
    elif op == "reopen":
        due = min(prior_due, now + timedelta(days=days)) if prior_due is not None else now + timedelta(days=days)
    else:
        due = _state_time(prior, "due_at") or opened + timedelta(days=days)
    if kev is not None and severity is not None and SEVERITY_RANK[severity] >= _HIGH:
        due = min(due, now + timedelta(days=target.fix_days_kev_or_malicious))  # step 8
    history = (*_state_history(prior), HistoryEntry("open" if op == "create" else op, inputs.run_id, now))
    fixed = None if group.malicious else next((f.fixed_version for f in group.findings if f.fixed_version), None)
    return FindingIssue(
        repo=repo,
        vuln_id=group.vuln_id,
        aliases=group.aliases,
        components=group.components,
        cvss_severity=severity,
        kev=kev,
        epss=run.epss_of(group.ids),
        fixed_version=fixed,
        origin_at=origin,
        origin_is_date_only=date_only,
        detected_at=detected,
        opened_at=opened,
        due_at=due,
        last_run_id=inputs.run_id,
        history=history,
        malicious=group.malicious,
        kev_first_release_at=released,
        cvss_sources=tuple(sorted({f.cvss_source for f in group.findings if f.cvss_source and f.cvss_severity})),
        vex_names_alias_only=min(
            (p for f in group.findings if (p := run.vex_alias_only.get((_repo_key(f.repo), f.vuln_id))) is not None),
            default=None,
        ),
    )


def _changed(body: str, previous: Mapping[str, Any] | None) -> bool:
    """True unless the new state equals the previous one, ignoring ``history`` and ``last_run_id``."""
    new_state = parse_state(body)
    if previous is None or new_state is None:
        return True
    return comparison_state(new_state) != comparison_state(previous)


def _sort_key(group: _Group, run: _Run) -> tuple[int, float, str]:
    """Step 5: ``(group, severity_key, vuln_id)``, ascending."""
    first = 0 if (run.kev_of(group.ids) is not None or group.malicious) else 1
    sev = group.severity
    return (first, -float(SEVERITY_RANK[sev]) if sev is not None else math.inf, group.vuln_id)


def _finding_actions(
    groups: Sequence[_Group], chosen: Mapping[int, ManagedIssue], run: _Run
) -> tuple[list[IssueAction], dict[Repo, list[_Group]]]:
    """Steps 4 and 5: update or reopen the Issues that exist, create up to the limit, return the overflow."""
    actions: list[IssueAction] = []
    fresh: dict[RepoKey, list[_Group]] = {}
    for index, group in enumerate(groups):
        issue = chosen.get(index)
        if issue is None:
            fresh.setdefault(_repo_key(group.repo), []).append(group)
            continue
        op = "reopen" if issue.state == "closed" else "update"
        body = render_finding(_finding_issue(group, issue.repo, run, op, issue.body_state, issue.closed_at))
        if op == "reopen" or _changed(body, issue.body_state):
            actions.append(IssueAction(op, issue.repo, "finding", group.vuln_id, issue.number, body, None))  # type: ignore[arg-type]
    limit = run.inputs.policy.max_new_issues_per_repo_per_run
    overflow: dict[Repo, list[_Group]] = {}
    for key in sorted(fresh):
        ordered = sorted(fresh[key], key=lambda g: _sort_key(g, run))
        for group in ordered[:limit]:
            body = render_finding(_finding_issue(group, group.repo, run, "create", None))
            actions.append(IssueAction("create", group.repo, "finding", group.vuln_id, None, body, None))
        if ordered[limit:]:
            overflow[ordered[0].repo] = ordered[limit:]
    return actions, overflow


# --- step 5 (summary) --------------------------------------------------------------------------


def _summary_actions(overflow: Mapping[Repo, list[_Group]], run: _Run) -> tuple[list[IssueAction], dict[Repo, int]]:
    inputs = run.inputs
    actions: list[IssueAction] = []
    summaries: dict[RepoKey, list[ManagedIssue]] = {}
    for issue in inputs.issues:
        if issue.kind == "summary":
            summaries.setdefault(_repo_key(issue.repo), []).append(issue)
    over = {_repo_key(r): (r, groups) for r, groups in overflow.items()}
    for key in sorted(set(over) | {_repo_key(r) for r in inputs.fetch_ok if _repo_key(r) in summaries}):
        existing = _pick(summaries.get(key, ()))
        if key in over:
            repo, groups = over[key]
            entries = [SummaryEntry(g.vuln_id, g.severity, run.kev_of(g.ids) is not None, g.malicious) for g in groups]
            body = render_summary(existing.repo if existing else repo, entries, inputs.run_id)
            if existing is None:
                actions.append(IssueAction("create", repo, "summary", None, None, body, None))
            elif existing.state == "closed":
                actions.append(IssueAction("reopen", existing.repo, "summary", None, existing.number, body, None))
            elif _changed(body, existing.body_state):
                actions.append(IssueAction("update", existing.repo, "summary", None, existing.number, body, None))
        elif existing is not None and existing.state == "open":
            actions.append(IssueAction("close", existing.repo, "summary", None, existing.number, None, "resolved"))
    return actions, {r: len(g) for r, g in sorted(overflow.items(), key=lambda kv: _repo_key(kv[0]))}


# --- step 5b: the per-repository list of Findings that have no severity (T2-07) -------------------------


def _unscored_since(finding: Finding) -> datetime:
    """When the Finding could first have been judged: the later of the advisory's publication and the first
    observation of the component version. Derived from the Finding, so no run has to remember it."""
    published = finding.advisory_published_at
    observed = finding.first_observed_component_at
    return max(observed, published) if published is not None else observed


def _unscored_actions(
    unscored: Sequence[Finding], held: Sequence[tuple[Repo, int, str]], run: _Run
) -> list[IssueAction]:
    """Lists, in one Issue per repository, the Findings that stayed without a severity for ``unscored_review_days``.

    Nothing here changes whether a Finding opens an Issue (the Opening_Threshold is unchanged). The Issue is a
    way for a person to see the Findings that no rule opens. It is created or updated when the list is not
    empty (and reopened when it was closed), and closed as ``resolved`` when the list is empty in a repository
    that was fetched. A run without the KEV feed does nothing: "not listed" is unknown, so a Finding may be
    about to qualify and the list cannot be called complete (the same rule as for closing a finding Issue).
    A Finding that already has an open Issue (``held``) is not listed again.
    """
    inputs = run.inputs
    if run.kev is None:
        return []
    days = inputs.policy.unscored_review_days or DEFAULT_UNSCORED_REVIEW_DAYS
    due = timedelta(days=days)
    held_ids = {(_repo_key(repo), vuln_id) for repo, _number, vuln_id in held}
    by_id: dict[tuple[RepoKey, str], list[Finding]] = {}
    for finding in unscored:
        if any((_repo_key(finding.repo), i) in held_ids for i in _ids_of(finding)):
            continue
        by_id.setdefault((_repo_key(finding.repo), finding.vuln_id), []).append(finding)
    entries: dict[RepoKey, list[UnscoredEntry]] = {}
    repos: dict[RepoKey, Repo] = {}
    for (key, vuln_id), members in sorted(by_id.items()):
        since = min(_unscored_since(f) for f in members)
        if inputs.now - since < due:
            continue
        aliases = tuple(sorted({a for m in members for a in m.aliases} - {vuln_id}))
        components = tuple(sorted({(m.component.purl, m.component.version) for m in members}))
        entries.setdefault(key, []).append(
            UnscoredEntry(vuln_id, aliases, components, since, run.epss_of((vuln_id, *aliases)))
        )
        repos[key] = members[0].repo
    existing: dict[RepoKey, list[ManagedIssue]] = {}
    for issue in inputs.issues:
        if issue.kind == "unscored":
            existing.setdefault(_repo_key(issue.repo), []).append(issue)
    ok = {_repo_key(r) for r in inputs.fetch_ok}
    actions: list[IssueAction] = []
    for key in sorted(set(entries) | {k for k in existing if k in ok}):
        found = _pick(existing.get(key, ()))
        if key in entries:
            repo = found.repo if found else repos[key]
            body = render_unscored(repo, entries[key], days, inputs.run_id)
            if found is None:
                actions.append(IssueAction("create", repo, "unscored", None, None, body, None))
            elif found.state == "closed":
                actions.append(IssueAction("reopen", found.repo, "unscored", None, found.number, body, None))
            elif _changed(body, found.body_state):
                actions.append(IssueAction("update", found.repo, "unscored", None, found.number, body, None))
        elif found is not None and found.state == "open":
            actions.append(IssueAction("close", found.repo, "unscored", None, found.number, None, "resolved"))
    return actions


# --- step 6: closing -----------------------------------------------------------------------------


def _depends_on_kev(issue: ManagedIssue, run: _Run) -> bool:
    """True when the Issue may be open only because of KEV (so it cannot close while KEV is missing)."""
    policy = run.inputs.policy.opening_threshold
    if not policy.open_if_kev_listed:
        return False
    state = issue.body_state
    if state is None:
        return True
    severity = state.get("cvss_severity")
    meets = isinstance(severity, str) and SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK[policy.min_cvss_severity]
    return state.get("kev_listed") is True and not meets


def _close_actions(
    issues: Sequence[ManagedIssue], claimed: set[IssueId], cls: _Classified, groups: Sequence[_Group], run: _Run
) -> tuple[
    list[IssueAction], list[tuple[Repo, int, str]], list[tuple[Repo, int, str]], list[tuple[Repo, int, str, str]]
]:
    """Step 6. An Issue closes as ``resolved`` only when its finding is gone.

    A finding that is still reported but has no severity keeps the Issue open (``held``); one that is still
    reported below the threshold closes as ``below_threshold``, which is not a fix and not counted as one
    (Requirement 8.4). An open Issue whose identifier is still reported, as an alias of another Issue's
    vulnerability, is a duplicate that the identifier rules no longer join: it stays open for a person to merge,
    because closing it as ``resolved`` would count as a fix that did not happen.
    Returns ``(actions, unconfirmed MAL- withdrawals, held, duplicates)``; a duplicate is
    ``(repo, number, its identifier, the representative identifier of the group that now owns it)``.
    """
    feeds = run.inputs.feeds
    actions: list[IssueAction] = []
    unconfirmed: list[tuple[Repo, int, str]] = []
    held: list[tuple[Repo, int, str]] = []
    duplicates: list[tuple[Repo, int, str, str]] = []
    representative: dict[tuple[RepoKey, str], str] = {}
    for g in sorted(groups, key=lambda g: (_repo_key(g.repo), g.vuln_id)):
        for i in g.ids:
            representative.setdefault((_repo_key(g.repo), i), g.vuln_id)
    grouped = set(representative)
    present: dict[tuple[RepoKey, str], list[Finding]] = {}
    for f in cls.rest:
        for i in (f.vuln_id, *f.aliases):
            present.setdefault((_repo_key(f.repo), i), []).append(f)

    def close(issue: ManagedIssue, reason: CloseReason) -> None:
        actions.append(IssueAction("close", issue.repo, "finding", issue.vuln_id, issue.number, None, reason))

    ok = {_repo_key(r) for r in run.inputs.fetch_ok}
    for issue in sorted(issues, key=lambda i: (_repo_key(i.repo), i.number)):
        if issue.kind != "finding" or issue.state != "open" or _issue_id(issue) in claimed or issue.vuln_id is None:
            continue
        if _repo_key(issue.repo) not in ok:
            continue  # the repository was not fetched: nothing can be concluded (Requirements 3.4, 8.8)
        if _issue_is_malicious(issue):
            if feeds.malicious is None or issue.vuln_id in feeds.malicious_unconfirmed:
                unconfirmed.append((issue.repo, issue.number, issue.vuln_id))  # Requirement 9.9, 8.10
            elif issue.vuln_id in feeds.malicious_withdrawn:
                close(issue, "withdrawn")
            elif issue.vuln_id in feeds.malicious_delisted:
                close(issue, "feed_version_delisted")
            else:
                close(issue, "resolved")
            continue
        if (_repo_key(issue.repo), issue.vuln_id) in grouped:
            duplicates.append(
                (issue.repo, issue.number, issue.vuln_id, representative[(_repo_key(issue.repo), issue.vuln_id)])
            )
            continue

        ref = cls.vex_ids.get((_repo_key(issue.repo), issue.vuln_id))
        still = present.get((_repo_key(issue.repo), issue.vuln_id))
        if ref is not None and run.kev is None:
            continue  # Requirement 9.8: without KEV the VEX cannot be re-checked against a later listing
        if ref is not None and still is None:
            close(issue, "vex_fixed" if ref.status == "fixed" else "vex_not_affected")
        elif run.kev is None and _depends_on_kev(issue, run):
            continue  # Requirement 9.8: the KEV feed is missing, so the reason for opening cannot be re-checked
        elif still is not None:  # also reached when a VEX judgment covers only some of the findings under the name
            if all(f.cvss_severity is None for f in still):
                held.append((issue.repo, issue.number, issue.vuln_id))  # severity missing, not lowered
            else:
                close(issue, "below_threshold")
        else:
            close(issue, "resolved")
    return actions, unconfirmed, held, duplicates


# --- overdue label (Requirement 18.19) -------------------------------------------------------------
def _overdue_label_actions(
    actions: Sequence[IssueAction], run: _Run, duplicates: Sequence[tuple[Repo, int, str, str]]
) -> list[IssueAction]:
    """Adds or removes ``OVERDUE_LABEL`` on the open Finding Issues, so that the label follows ``due_at``.

    An Issue is overdue when its ``due_at`` is before ``now``; the ``due_at`` is the one the Issue will have
    after this run's own ``update`` or ``reopen``. A closed Issue (or one closed in this run), a duplicate that
    stays open for a person to merge, a repository that was not fetched, and an Issue without a ``due_at`` are
    left alone. The label rides on the action that already writes the Issue; otherwise an ``update`` without a
    body carries it. Once applied, the next plan has nothing to add.
    """
    inputs = run.inputs
    ok = {_repo_key(r) for r in inputs.fetch_ok}
    closing = {(_repo_key(a.repo), a.number) for a in actions if a.op == "close" and a.number is not None}
    dup = {(_repo_key(r), n) for r, n, _v, _rep in duplicates}
    writing = {
        (_repo_key(a.repo), a.number): index
        for index, a in enumerate(actions)
        if a.kind == "finding" and a.op in ("update", "reopen") and a.number is not None
    }
    out = list(actions)
    for issue in sorted(inputs.issues, key=lambda i: (_repo_key(i.repo), i.number)):
        key = (_repo_key(issue.repo), issue.number)
        if issue.kind != "finding" or issue.vuln_id is None or key[0] not in ok or key in closing or key in dup:
            continue
        index = writing.get(key)
        if index is None and issue.state != "open":
            continue
        state = parse_state(actions[index].body) if index is not None and actions[index].body else issue.body_state
        due = _state_time(state, "due_at")
        if due is None:
            continue
        overdue = due < inputs.now
        if overdue == (OVERDUE_LABEL in issue.labels):
            continue
        add, remove = ((OVERDUE_LABEL,), ()) if overdue else ((), (OVERDUE_LABEL,))
        if index is not None:
            out[index] = replace(out[index], add_labels=add, remove_labels=remove)
        else:
            out.append(
                IssueAction("update", issue.repo, "finding", issue.vuln_id, issue.number, None, None, add, remove)
            )
    return out


# --- entry point -----------------------------------------------------------------------------------


def _action_key(action: IssueAction) -> tuple[Any, ...]:
    return (_repo_key(action.repo), action.kind, action.vuln_id or "", action.op, action.number or 0)


def plan(inputs: PlanInputs) -> Plan:
    """Plans the Issue operations of one run.

    Pure: no I/O, and the same inputs give the same ``Plan`` (including every body).

    Args:
        inputs: Findings (only for repositories in ``fetch_ok``), feed snapshot, VEX documents and the
            managed Issues that exist.

    Returns:
        The actions sorted by ``(repo, kind, vuln_id, op)``, the findings left out by VEX, the ones below
        the threshold or unscored, the per-repository overflow count, and the ``MAL-`` Issues whose
        withdrawal could not be confirmed.
    """
    multi_cve = multi_cve_records(inputs.findings)
    inputs = replace(inputs, findings=frozenset(canonicalize(inputs.findings)))
    run = _Run(inputs, inputs.feeds.kev)
    cls = _classify(run)
    run = replace(run, vex_alias_only=cls.alias_only)
    groups = _build_groups(cls.included)
    chosen, claimed = _assign(groups, inputs.issues)
    groups = [_continue_as_malicious(g, chosen.get(n)) for n, g in enumerate(groups)]
    actions, overflow = _finding_actions(groups, chosen, run)
    summary_actions, overflow_counts = _summary_actions(overflow, run)
    close_actions, unconfirmed, held, duplicates = _close_actions(inputs.issues, claimed, cls, groups, run)
    kev_ids = frozenset(run.kev or ())
    leftovers = list(cls.rest)
    no_severity = [f for f in leftovers if f.cvss_severity is None and not any(i in kev_ids for i in _ids_of(f))]
    # With the KEV feed missing, "not listed" is unknown: KEV may be the reason this finding qualifies.
    # The finding may qualify through KEV whatever its severity, so every finding below the threshold is unknown.
    kev_unknown = (
        tuple(f for f in leftovers if not is_malicious(f))
        if run.kev is None and inputs.policy.opening_threshold.open_if_kev_listed
        else ()
    )
    unscored = () if run.kev is None else tuple(no_severity)
    scored = set(no_severity)
    below = tuple(f for f in leftovers if f not in scored)
    unscored_actions = _unscored_actions(unscored, held, run)
    combined = [*actions, *summary_actions, *close_actions, *unscored_actions]
    ordered = sorted(_overdue_label_actions(combined, run, duplicates), key=_action_key)
    return Plan(
        actions=tuple(ordered),
        vex_exclusions=cls.exclusions,
        rejected_vex=tuple(sorted(cls.rejected)),
        below_threshold=below,
        unscored=unscored,
        overflow_counts=overflow_counts,
        malicious_withdrawn_unconfirmed=tuple(sorted(unconfirmed, key=lambda t: (_repo_key(t[0]), t[1]))),
        kev_unknown=kev_unknown,
        held_unscored=tuple(sorted(held, key=lambda t: (_repo_key(t[0]), t[1]))),
        duplicate_issues=tuple(
            sorted(((r, n, v) for r, n, v, _rep in duplicates), key=lambda t: (_repo_key(t[0]), t[1]))
        ),
        duplicate_of=tuple(
            sorted(((r, n, rep) for r, n, _v, rep in duplicates), key=lambda t: (_repo_key(t[0]), t[1]))
        ),
        vex_unchecked_against_kev=tuple(f for f, _ in cls.exclusions) if run.kev is None else (),
        alias_multi_cve=multi_cve,
        vex_name_only_ghsa=tuple(
            sorted((f"{owner}/{name}", vuln_id, path) for ((owner, name), vuln_id), path in cls.alias_only.items())
        ),
    )

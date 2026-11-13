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
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from supply_chain.issue_body import (
    FindingIssue,
    HistoryEntry,
    SummaryEntry,
    comparison_state,
    parse_state,
    render_finding,
    render_summary,
)
from supply_chain.models import (
    CloseReason,
    Component,
    Finding,
    IssueAction,
    ManagedIssue,
    Plan,
    PlanInputs,
    Repo,
    Severity,
)
from supply_chain.threshold import MALICIOUS_PREFIX, SEVERITY_RANK, is_malicious, meets_opening_threshold
from supply_chain.vex import REASON_MALICIOUS, VexRef, effective_exclusions

_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_GHSA_PREFIX = "GHSA-"
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
    kev: Mapping[str, tuple[date, bool | None]] | None

    def kev_of(self, ids: Iterable[str]) -> tuple[date, bool | None] | None:
        if self.kev is None:
            return None
        return next((self.kev[i] for i in ids if i in self.kev), None)

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


def _classify(run: _Run) -> _Classified:
    inputs = run.inputs
    kev_ids = None if run.kev is None else frozenset(run.kev)
    tables: dict[RepoKey, dict[tuple[str, str], VexRef]] = {}
    rejected: set[tuple[str, str]] = set()
    for repo in sorted(inputs.vex, key=_repo_key):
        table, rej = effective_exclusions(list(inputs.vex[repo]), inputs.policy)
        tables[_repo_key(repo)] = table
        rejected.update(rej)
    included: list[Finding] = []
    rest: list[Finding] = []
    exclusions: list[tuple[Finding, str]] = []
    vex_ids: dict[tuple[RepoKey, str], VexRef] = {}
    for finding in sorted(inputs.findings, key=_finding_key):
        table = tables.get(_repo_key(finding.repo), {})
        ref = next(
            (r for i in (finding.vuln_id, *finding.aliases) if (r := table.get((i, finding.component.purl)))), None
        )
        if ref is not None and is_malicious(finding):
            rejected.add((ref.path, REASON_MALICIOUS))  # a malicious package is never suppressed
        elif ref is not None:
            exclusions.append((finding, ref.path))
            for i in (finding.vuln_id, *finding.aliases):
                vex_ids.setdefault((_repo_key(finding.repo), i), ref)
            continue
        if meets_opening_threshold(finding, kev_ids, inputs.policy.opening_threshold):
            included.append(finding)
        else:
            rest.append(finding)
    return _Classified(tuple(included), tuple(rest), tuple(exclusions), vex_ids, frozenset(rejected))


# --- step 3: grouping --------------------------------------------------------------------------


def _build_groups(included: Sequence[Finding], rest: Sequence[Finding]) -> tuple[list[_Group], frozenset[Finding]]:
    """Builds the groups of Issues and returns them with the findings absorbed into a ``MAL-`` group."""
    plain: dict[tuple[RepoKey, str], list[Finding]] = {}
    units: dict[tuple[RepoKey, str, str], list[Finding]] = {}
    for f in included:
        if is_malicious(f):
            units.setdefault((_repo_key(f.repo), f.component.purl, f.component.version), []).append(f)
        else:
            plain.setdefault((_repo_key(f.repo), f.vuln_id), []).append(f)
    absorbed: set[Finding] = set()
    for f in rest:
        unit = (_repo_key(f.repo), f.component.purl, f.component.version)
        if unit in units and f.vuln_id.startswith(_GHSA_PREFIX) and f.cvss_severity is None and not is_malicious(f):
            units[unit].append(f)  # a GHSA malware advisory of the same package version (Q-11)
            absorbed.add(f)
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
        rep = min(i for i in ids if i.startswith(MALICIOUS_PREFIX))
        key = (unit_key[0], rep)
        old = merged.get(key)
        all_members = (*old.findings, *members) if old else tuple(members)
        all_ids = ids | ({*old.ids} if old else set())
        merged[key] = _Group(members[0].repo, rep, tuple(sorted(all_ids - {rep})), all_members, True)
    groups.extend(merged.values())
    groups.sort(key=lambda g: (_repo_key(g.repo), g.vuln_id))
    return groups, frozenset(absorbed)


# --- step 4: matching existing Issues ------------------------------------------------------------


def _pick(candidates: Iterable[ManagedIssue]) -> ManagedIssue | None:
    ordered = sorted(candidates, key=lambda i: (i.state != "open", i.number))
    return ordered[0] if ordered else None


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


def _origin(group: _Group, run: _Run, kev: tuple[date, bool | None] | None) -> tuple[datetime, bool]:
    """Origin = the later of "threshold first met" and "component version first observed" (Requirement 18.3).

    When the time of the threshold is unknown the observation time is used; the Issue cannot say "unknown"
    yet (``FindingIssue.origin_at`` is required).
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
        return observed, False
    return (met, date_only) if met >= observed else (observed, False)


def _finding_issue(group: _Group, repo: Repo, run: _Run, op: str, prior: Mapping[str, Any] | None) -> FindingIssue:
    inputs = run.inputs
    now, target = inputs.now, inputs.policy.response_target
    kev = run.kev_of(group.ids)
    severity = group.severity
    opened = _state_time(prior, "opened_at") or now
    detected = _state_time(prior, "detected_at") or now
    origin, date_only = _origin(group, run, kev)
    if _state_time(prior, "origin_at") is not None and isinstance(prior, Mapping):
        origin = _state_time(prior, "origin_at") or origin
        date_only = prior.get("origin_is_date_only") is True
    days = target.fix_days_kev_or_malicious if (kev is not None or group.malicious) else target.fix_days_high
    if op == "create":
        due = now + timedelta(days=days)
    elif op == "reopen":
        due = now + timedelta(days=days)
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
        body = render_finding(_finding_issue(group, issue.repo, run, op, issue.body_state))
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
    issues: Sequence[ManagedIssue], claimed: set[IssueId], cls: _Classified, run: _Run
) -> tuple[list[IssueAction], list[tuple[Repo, int, str]]]:
    feeds = run.inputs.feeds
    actions: list[IssueAction] = []
    unconfirmed: list[tuple[Repo, int, str]] = []

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
        ref = cls.vex_ids.get((_repo_key(issue.repo), issue.vuln_id))
        if ref is not None:
            close(issue, "vex_fixed" if ref.status == "fixed" else "vex_not_affected")
        elif run.kev is None and _depends_on_kev(issue, run):
            continue  # Requirement 9.8: the KEV feed is missing, so the reason for opening cannot be re-checked
        else:
            close(issue, "resolved")
    return actions, unconfirmed


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
    run = _Run(inputs, inputs.feeds.kev)
    cls = _classify(run)
    groups, absorbed = _build_groups(cls.included, cls.rest)
    chosen, claimed = _assign(groups, inputs.issues)
    actions, overflow = _finding_actions(groups, chosen, run)
    summary_actions, overflow_counts = _summary_actions(overflow, run)
    close_actions, unconfirmed = _close_actions(inputs.issues, claimed, cls, run)
    kev_ids = frozenset(run.kev or ())
    leftovers = [f for f in cls.rest if f not in absorbed]
    unscored = tuple(
        f for f in leftovers if f.cvss_severity is None and not any(i in kev_ids for i in (f.vuln_id, *f.aliases))
    )
    scored = set(unscored)
    below = tuple(f for f in leftovers if f not in scored)
    ordered = sorted([*actions, *summary_actions, *close_actions], key=_action_key)
    return Plan(
        actions=tuple(ordered),
        vex_exclusions=cls.exclusions,
        rejected_vex=tuple(sorted(cls.rejected)),
        below_threshold=below,
        unscored=unscored,
        overflow_counts=overflow_counts,
        malicious_withdrawn_unconfirmed=tuple(sorted(unconfirmed, key=lambda t: (_repo_key(t[0]), t[1]))),
    )

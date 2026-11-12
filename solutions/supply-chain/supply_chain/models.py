"""Data models for the supply-chain pure core.

Every type is an immutable ``@dataclass(frozen=True, slots=True)`` that mirrors
the "Data Models" section of the phase 4 design. This module performs no I/O.

Datetimes are timezone-aware and in UTC. A naive datetime, or an aware one
whose offset is not zero, is rejected with ``ValueError`` when the object is
built, so downstream rendering can always append ``Z`` without converting.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
VexStatus = Literal["not_affected", "affected", "fixed", "under_investigation"]
FeedName = Literal["kev", "epss", "malicious"]
# MAL- issues close with "resolved", "withdrawn" or "feed_version_delisted" only.
CloseReason = Literal["resolved", "withdrawn", "feed_version_delisted", "vex_not_affected", "vex_fixed"]
Layer = Literal["A", "B"]
IssueKind = Literal["finding", "summary", "failure"]
IssueState = Literal["open", "closed"]
IssueOp = Literal["create", "update", "close", "reopen"]
Directness = Literal["direct", "transitive", "unknown"]

UNKNOWN = "unknown"


def _require_utc(name: str, value: datetime | None) -> None:
    """Rejects a naive datetime or one whose UTC offset is not zero.

    Args:
        name: Field name used in the error message.
        value: The datetime to check; ``None`` is accepted.

    Raises:
        ValueError: If ``value`` is naive or not in UTC.
    """
    if value is None:
        return
    offset = value.utcoffset()
    if offset is None:
        raise ValueError(f"{name} must be timezone-aware (UTC), got a naive datetime")
    if offset != timedelta(0):
        raise ValueError(f"{name} must be in UTC, got offset {offset}")


@dataclass(frozen=True, slots=True, eq=False)
class Repo:
    """A GitHub repository, ``<owner>/<name>``. Equality ignores case."""

    owner: str
    name: str

    def _key(self) -> tuple[str, str]:
        return (self.owner.lower(), self.name.lower())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Repo):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())


@dataclass(frozen=True, slots=True)
class OpeningThreshold:
    """Conditions that make a finding eligible for an Issue."""

    min_cvss_severity: Severity
    open_if_kev_listed: bool
    open_if_malicious: Literal[True]  # schema const true (Requirement 7.11)


@dataclass(frozen=True, slots=True)
class CooldownDays:
    """Cooldown in days for ordinary and major updates."""

    default: int
    major: int


@dataclass(frozen=True, slots=True)
class AutomergeRule:
    """One entry of the automerge include list."""

    manager: Literal["npm", "github-actions"]
    dep_types: tuple[str, ...]
    update_types: tuple[Literal["patch"], ...]


@dataclass(frozen=True, slots=True)
class ResponseTarget:
    """Response_Target values (detect in hours, fix in days)."""

    detect_hours: int
    fix_days_kev_or_malicious: int
    fix_days_high: int


@dataclass(frozen=True, slots=True)
class Policy:
    """The parsed Policy_File."""

    schema_version: int
    target_repositories: tuple[Repo, ...]
    excluded_repositories: tuple[Repo, ...]
    opening_threshold: OpeningThreshold
    cooldown_days: CooldownDays
    automerge_include: tuple[AutomergeRule, ...]
    automerge_exclude: tuple[str, ...]  # includes "hub_reusable_workflow"
    automerge_enabled_repositories: tuple[Repo, ...]  # empty at the start (14.7)
    package_manager_wait: CooldownDays  # equals cooldown_days (Requirement 12.9)
    non_production_paths: tuple[str, ...]  # dependency_scope (Requirement 13.2)
    vex_directory: str
    vex_exclude_statuses: tuple[VexStatus, ...]
    vex_approver_role: str
    vex_one_statement_per_document: bool
    vex_malicious_never_suppressed: Literal[True]  # Requirements 7.12, 11.12, 21.3
    response_target: ResponseTarget
    max_new_issues_per_repo_per_run: int


@dataclass(frozen=True, slots=True)
class Component:
    """A format-independent SBOM component.

    The four fields after ``version`` default to ``"unknown"`` because an
    adapter cannot always read them from the source document (design D-3).
    """

    purl: str
    name: str
    version: str
    direct: Directness = UNKNOWN
    author: str = UNKNOWN
    format_name: str = UNKNOWN
    format_version: str = UNKNOWN
    generation_stage: str = UNKNOWN


@dataclass(frozen=True, slots=True)
class Finding:
    """A vulnerability or malicious-package finding.

    Unique by ``(repo, vuln_id, component.purl)``; a Malicious_Package_Finding
    is unique by ``(repo, purl, version)``. Whether a finding is malicious is
    derived from its identifiers, not stored here.
    """

    repo: Repo
    vuln_id: str
    aliases: tuple[str, ...]
    component: Component
    cvss_severity: Severity | None
    fixed_version: str | None
    advisory_published_at: datetime | None
    layer: Layer
    first_observed_component_at: datetime  # first run that saw this version

    def __post_init__(self) -> None:
        _require_utc("advisory_published_at", self.advisory_published_at)
        _require_utc("first_observed_component_at", self.first_observed_component_at)


@dataclass(frozen=True, slots=True)
class FeedSnapshot:
    """Feed contents for one run. ``None`` means the fetch failed."""

    # id -> (dateAdded, knownRansomwareCampaignUse)
    kev: Mapping[str, tuple[date, bool | None]] | None
    # id -> (score, date, model version)
    epss: Mapping[str, tuple[str, date, str]] | None
    # MAL- id -> published time
    malicious: Mapping[str, datetime | None] | None
    # MAL- id -> withdrawn time; only ids whose GET succeeded and was readable
    malicious_withdrawn: Mapping[str, datetime]
    # MAL- ids whose record no longer lists the version (GET ok, not withdrawn)
    malicious_delisted: frozenset[str]
    # MAL- ids whose GET failed or whose response was unreadable
    malicious_unconfirmed: frozenset[str]

    def __post_init__(self) -> None:
        for key, value in (self.malicious or {}).items():
            _require_utc(f"malicious[{key}]", value)
        for key, value in self.malicious_withdrawn.items():
            _require_utc(f"malicious_withdrawn[{key}]", value)


@dataclass(frozen=True, slots=True)
class VexStatement:
    """One OpenVEX statement."""

    vuln_id: str
    aliases: tuple[str, ...]
    products: tuple[str, ...]  # purls with version
    status: VexStatus
    justification: str | None
    impact_statement: str | None
    timestamp: datetime | None

    def __post_init__(self) -> None:
        _require_utc("timestamp", self.timestamp)


@dataclass(frozen=True, slots=True)
class VexDocument:
    """One OpenVEX document."""

    id: str
    context: str
    author: str
    role: str | None
    timestamp: datetime
    version: int
    tooling: str | None
    statements: tuple[VexStatement, ...]
    path: str  # repo-relative, not serialized

    def __post_init__(self) -> None:
        _require_utc("timestamp", self.timestamp)


@dataclass(frozen=True, slots=True)
class ManagedIssue:
    """An Issue the aggregator manages."""

    repo: Repo
    number: int
    kind: IssueKind
    vuln_id: str | None
    state: IssueState
    body_state: Mapping[str, object] | None


@dataclass(frozen=True, slots=True)
class PullRequestRef:
    """A pull request, for the response-time intervals (Requirement 18.3)."""

    repo: Repo
    vuln_id: str
    created_at: datetime
    merged_at: datetime | None

    def __post_init__(self) -> None:
        _require_utc("created_at", self.created_at)
        _require_utc("merged_at", self.merged_at)


@dataclass(frozen=True, slots=True)
class PlanInputs:
    """Everything ``plan`` reads. No field is fetched inside the core."""

    policy: Policy
    run_id: str
    now: datetime
    pull_requests: tuple[PullRequestRef, ...]
    findings: frozenset[Finding]
    fetch_ok: frozenset[Repo]  # repos whose layer A or B was obtained this run
    feeds: FeedSnapshot
    vex: Mapping[Repo, tuple[VexDocument, ...]]  # default-branch documents only
    issues: tuple[ManagedIssue, ...]

    def __post_init__(self) -> None:
        _require_utc("now", self.now)


@dataclass(frozen=True, slots=True)
class IssueAction:
    """One Issue operation in a plan."""

    op: IssueOp
    repo: Repo
    kind: Literal["finding", "summary"]
    vuln_id: str | None
    number: int | None
    body: str | None
    close_reason: CloseReason | None


@dataclass(frozen=True, slots=True)
class Plan:
    """The result of ``plan``."""

    actions: tuple[IssueAction, ...]  # sorted by (repo, kind, vuln_id, op)
    vex_exclusions: tuple[tuple[Finding, str], ...]  # (finding, vex path)
    rejected_vex: tuple[tuple[str, str], ...]  # (path, reason)
    below_threshold: tuple[Finding, ...]
    unscored: tuple[Finding, ...]
    overflow_counts: Mapping[Repo, int]
    # (repo, issue number, MAL- id)
    malicious_withdrawn_unconfirmed: tuple[tuple[Repo, int, str], ...]

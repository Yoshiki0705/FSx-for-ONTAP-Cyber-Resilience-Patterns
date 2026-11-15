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
FeedName = Literal["kev", "epss", "malicious", "advisories"]
# MAL- issues close with "resolved", "withdrawn" or "feed_version_delisted" only.
CloseReason = Literal[
    "resolved", "withdrawn", "feed_version_delisted", "vex_not_affected", "vex_fixed", "below_threshold"
]
AdvisoryType = Literal["malware", "vulnerability"]
Layer = Literal["A", "B"]
IssueKind = Literal["finding", "summary", "failure", "unscored"]
IssueState = Literal["open", "closed"]
IssueOp = Literal["create", "update", "close", "reopen"]
Directness = Literal["direct", "transitive", "unknown"]

UNKNOWN = "unknown"
# 180 is a convention (the same kind of value as the cooldown days), not a sourced one: Evidence_Tier hypothesis.
DEFAULT_VEX_MAX_AGE_DAYS = 180
# A Finding with no severity is shown to a person after this many days (T2-07). A convention, not a sourced
# value: Evidence_Tier hypothesis.
DEFAULT_UNSCORED_REVIEW_DAYS = 7
# The watchdog's allowed age of the newest Run_Record: the Aggregator interval of at most 6 hours (Requirement
# 7.2) plus 2 hours of scheduler delay.
DEFAULT_WATCHDOG_LIMIT_HOURS = 8


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
class RenovatePreset:
    """The Hub preset tag a Spoke trusts, and the commit that tag pointed at when it was recorded (T1-06)."""

    tag: str
    commit: str  # 40 hexadecimal digits, as written in the Policy_File


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
    package_manager_wait: CooldownDays  # derived from cooldown_days (Requirement 12.9); the key is optional in the file
    non_production_paths: tuple[str, ...]  # dependency_scope (Requirement 13.2)
    vex_directory: str
    vex_exclude_statuses: tuple[VexStatus, ...]
    vex_approver_role: str
    vex_one_statement_per_document: bool
    vex_malicious_never_suppressed: Literal[True]  # Requirements 7.12, 11.12, 21.3
    response_target: ResponseTarget
    max_new_issues_per_repo_per_run: int
    # A VEX judgment older than this many days stops suppressing (Requirement 11.15). ``None`` means the key is
    # absent from the Policy_File and ``DEFAULT_VEX_MAX_AGE_DAYS`` applies.
    vex_max_age_days: int | None = None
    # The Hub preset tag and its commit, when the Policy_File records them. ``None`` means nothing is recorded.
    renovate_preset: RenovatePreset | None = None
    # Days a Finding may stay without a severity before the per-repository ``unscored`` Issue lists it. ``None``
    # means the key is absent and ``DEFAULT_UNSCORED_REVIEW_DAYS`` applies.
    unscored_review_days: int | None = None
    # Allowed age in hours of the newest Run_Record before the watchdog fails. ``None`` means the key is absent
    # and ``DEFAULT_WATCHDOG_LIMIT_HOURS`` applies.
    watchdog_limit_hours: int | None = None


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
    # ``malware`` when the source advisory is typed as malware (GitHub advisory ``type``); ``None`` when unknown.
    advisory_type: AdvisoryType | None = None
    # Where ``cvss_severity`` came from (e.g. ``GHSA:CVSS_V4``, ``NVD:3.1``). Shown only; never decides.
    cvss_source: str | None = None

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
    # ``dateReleased`` of the KEV catalogue read this run (it carries a time of day; ``dateAdded`` does not).
    kev_released_at: datetime | None = None

    def __post_init__(self) -> None:
        for key, value in (self.malicious or {}).items():
            _require_utc(f"malicious[{key}]", value)
        for key, value in self.malicious_withdrawn.items():
            _require_utc(f"malicious_withdrawn[{key}]", value)
        _require_utc("kev_released_at", self.kev_released_at)


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
    # When GitHub closed the Issue. ``None`` when unknown (a reopen then continues the earlier deadline).
    closed_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_utc("closed_at", self.closed_at)


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
    # Per repository, ``path -> time the file reached the default branch``. Optional; the I/O layer fills it. It
    # lets ``effective_exclusions`` tell a statement with a copied old timestamp from an ordinary older one.
    vex_merged_at: Mapping[Repo, Mapping[str, datetime]] | None = None

    def __post_init__(self) -> None:
        _require_utc("now", self.now)


@dataclass(frozen=True, slots=True)
class IssueAction:
    """One Issue operation in a plan."""

    op: IssueOp
    repo: Repo
    kind: Literal["finding", "summary", "unscored"]
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
    # Findings with no severity in a run whose KEV feed failed: KEV may still make them eligible.
    kev_unknown: tuple[Finding, ...] = ()
    # (repo, issue number, id) of open Issues kept open because the finding is present but has no severity.
    held_unscored: tuple[tuple[Repo, int, str], ...] = ()
    # (repo, issue number, id) of open Issues whose identifier is now an alias of another vulnerability's Issue.
    # They stay open: closing them as ``resolved`` would count a fix that did not happen.
    duplicate_issues: tuple[tuple[Repo, int, str], ...] = ()
    # (repo, issue number, representative id) for each entry of ``duplicate_issues``: the vulnerability that the
    # duplicate's identifier now belongs to. The I/O layer writes it to the Issue's state block as ``duplicate_of``
    # (T2-R3-07); the Issue stays open and is left out of ``overdue_open`` and of the fix figures.
    duplicate_of: tuple[tuple[Repo, int, str], ...] = ()
    # Findings a VEX statement excludes in a run whose KEV feed failed: the re-check against a later KEV listing
    # (Requirement 11.27) could not be made, so no Issue was closed for them.
    vex_unchecked_against_kev: tuple[Finding, ...] = ()
    # ``(repository, primary id, CVEs)`` of records that named more than one CVE (split by ``canonicalize``).
    alias_multi_cve: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    # ``("owner/name", Finding's primary id, statement path)`` for each Finding that was not excluded although a
    # statement names one of its aliases (typically a GHSA) and not its primary identifier. The statement needs
    # the CVE in its ``aliases`` (Requirement 11.37). The count of this tuple is the measurement D-46 promises
    # ("how many statements had to be rewritten", T12-R5-02).
    vex_name_only_ghsa: tuple[tuple[str, str, str], ...] = ()

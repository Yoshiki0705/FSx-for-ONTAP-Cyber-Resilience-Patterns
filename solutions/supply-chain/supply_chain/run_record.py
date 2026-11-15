"""Run record, failure-notice decision and retry waits (Requirements 9.6, 9.7, 25.3-25.5, 26.2, 26.3, 26.5).

Pure code. No I/O, no clock reads. The I/O layer writes the JSON text this
module produces and passes in the set of paths that already exist.

* ``RunRecord`` / ``to_json`` / ``from_json``: the "run record" of the design
  (section 5 and Data Models). ``from_json(to_json(r)) == r``. Datetimes are
  UTC with whole seconds (``...Z``); dates are ``YYYY-MM-DD``.
* Schema version 2 adds what a later reader needs to say what was scanned and
  with which data: the commit and SBOM hash per repository, the feed payload
  hashes, and ``prev_record_sha256`` (each record names the hash of the one
  before it in the same month, so a removed or edited record shows). Version 1
  records are still read; the added fields take their defaults (``None``,
  empty). ``to_json`` always writes version 2.
* ``verify_chain`` / ``previous_record_sha256`` / ``month_seal``: the chain and
  the month-end value that a tag can pin (Requirement 26.3).
* ``record_path`` / ``new_record_path``: ``runs/<YYYY>/<MM>/<run_id>.json``.
  A path that already exists, or a run id that already has a file, is refused
  (append only, Requirement 26.3).
* ``decide_failure_notice``: from the latest end states, whether to create,
  append to, or close the failure-notice Issue (Requirements 25.3, 25.4).
* ``backoff_schedule`` / ``retry_wait``: 2, 4, 8, 16, 32 seconds, at least
  ``retry-after`` when the server gave one, and no sixth retry.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import types
import typing
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import MISSING, dataclass, field, fields, is_dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from supply_chain.models import FeedName, IssueOp, Layer, PullRequestRef, Repo, Severity

SCHEMA_VERSION = 2
READABLE_VERSIONS = (1, 2)
EndState = Literal["success", "failure"]
NoticeAction = Literal["none", "create", "append", "close"]

FAILURE_STREAK_THRESHOLD = 2
BACKOFF_BASE_SECONDS = 2
MAX_RETRIES = 5

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[0-9]+-[0-9]+")
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class RunRecordError(ValueError):
    """The run record is malformed or violates a rule of the design."""


class RecordPathExistsError(RunRecordError):
    """A run record already exists for the path or the run id (never overwritten)."""


@dataclass(frozen=True, slots=True)
class FetchFailure:
    """A repository whose layer A or B could not be obtained."""

    repo: str
    layer: Layer
    reason: str


@dataclass(frozen=True, slots=True)
class ScannedRepo:
    """What one repository was scanned from (the facts a later investigation needs).

    Attributes:
        head_sha: The commit the SBOM describes (40 hex), ``None`` when the SBOM did not say.
        sbom_source: ``A`` (dependency graph) or ``B`` (generated SBOM), ``None`` when none was read.
        sbom_sha256: SHA-256 of the SBOM bytes the findings came from (64 hex), ``None`` when none was read.
        sbom_artifact_id: The workflow artifact the SBOM came from, ``None`` for layer A or when unknown.
    """

    head_sha: str | None
    sbom_source: Layer | None
    sbom_sha256: str | None
    sbom_artifact_id: int | None = None

    def __post_init__(self) -> None:
        if self.head_sha is not None and not _HEX40.fullmatch(self.head_sha):
            raise RunRecordError("head_sha must be 40 lowercase hex digits or null")
        if self.sbom_sha256 is not None and not _HEX64.fullmatch(self.sbom_sha256):
            raise RunRecordError("sbom_sha256 must be 64 lowercase hex digits or null")


@dataclass(frozen=True, slots=True)
class Repositories:
    """Repositories of a run.

    ``required_checks`` maps ``owner/name`` to the number of required status
    checks on the default branch; ``None`` means it could not be read. A count
    of 0 is recorded on purpose (Requirement 14.4 depends on it).
    ``scanned_detail`` maps ``owner/name`` to what each scan read (version 2).
    """

    scanned: tuple[str, ...]
    fetch_failed: tuple[FetchFailure, ...]
    required_checks: dict[str, int | None]
    scanned_detail: dict[str, ScannedRepo] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FeedFetched:
    """A feed that was obtained."""

    name: FeedName
    at: datetime
    catalog_version: str | None
    # Version 2: what was read, so "the data said none" can be checked later.
    payload_sha256: str | None = None  # SHA-256 of the response body (64 hex)
    entry_count: int | None = None
    source_url: str | None = None
    http_date: str | None = None  # the response ``Date`` header as received
    released_at: datetime | None = None  # KEV ``dateReleased`` (has a time of day; ``dateAdded`` has none)

    def __post_init__(self) -> None:
        if self.payload_sha256 is not None and not _HEX64.fullmatch(self.payload_sha256):
            raise RunRecordError("payload_sha256 must be 64 lowercase hex digits or null")
        if self.released_at is not None:
            _check_seconds_utc("released_at", self.released_at)


@dataclass(frozen=True, slots=True)
class FeedFailed:
    """A feed that could not be obtained."""

    name: FeedName
    at: datetime
    reason: str


@dataclass(frozen=True, slots=True)
class Feeds:
    """Feeds fetched and failed in a run."""

    fetched: tuple[FeedFetched, ...]
    failed: tuple[FeedFailed, ...]


@dataclass(frozen=True, slots=True)
class EpssInfo:
    """EPSS fetch date and model version (shown only; never used to decide)."""

    fetched_on: date | None
    model_version: str | None


@dataclass(frozen=True, slots=True)
class FindingEntry:
    """A Finding as recorded."""

    repo: str
    vuln_id: str
    purl: str
    cvss_severity: Severity | None
    kev_listed: bool
    malicious: bool
    epss: str | None
    meets_threshold: bool
    first_seen_run_id: str | None = None  # version 2: the run that first saw the finding
    component_first_seen_sha: str | None = None  # version 2: the commit in which the component version first appeared


@dataclass(frozen=True, slots=True)
class IssueEntry:
    """An Issue operation as recorded."""

    repo: str
    number: int | None
    op: IssueOp
    vuln_id: str | None
    ok: bool


@dataclass(frozen=True, slots=True)
class VexExclusion:
    """A Finding excluded by a VEX statement."""

    repo: str
    vuln_id: str
    path: str
    commit: str
    status: str


@dataclass(frozen=True, slots=True)
class RejectedVexEntry:
    """A VEX statement that was not applied."""

    repo: str
    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class UnscoredEntry:
    """A Finding with no CVSS severity (Requirement 7.9)."""

    repo: str
    vuln_id: str


@dataclass(frozen=True, slots=True)
class WithdrawnUnconfirmed:
    """A ``MAL-`` Issue left open because the withdrawal was not confirmed."""

    repo: str
    number: int
    vuln_id: str


@dataclass(frozen=True, slots=True)
class RepoResponseMetrics:
    """Response-time figures of one repository (Requirement 18)."""

    overdue_open: int
    detect_over_24h: int
    origin_unknown_excluded: int
    detect_to_open_hours: tuple[float, ...]
    open_to_pr_hours: tuple[float, ...]
    pr_to_merge_hours: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class RateLimitRecord:
    """Repositories done and not done when the rate limit stopped the run."""

    processed: tuple[str, ...]
    unprocessed: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunRecord:
    """The record of one Aggregator run (design: "Run record")."""

    run_id: str
    started_at: datetime
    finished_at: datetime
    end_state: EndState
    failure_reason: str | None
    aggregator_commit: str
    policy_commit: str | None  # None when the Policy_File could not be read
    repositories: Repositories
    feeds: Feeds
    kev_fetched_on: date | None
    epss: EpssInfo
    findings: tuple[FindingEntry, ...]
    issues: tuple[IssueEntry, ...]
    vex_exclusions: tuple[VexExclusion, ...]
    rejected_vex: tuple[RejectedVexEntry, ...]
    unscored: tuple[UnscoredEntry, ...]
    malicious_withdrawn_unconfirmed: tuple[WithdrawnUnconfirmed, ...]
    summary_overflow: dict[str, int]
    response_metrics: dict[str, RepoResponseMetrics]
    pull_requests: tuple[PullRequestRef, ...]
    rate_limit: RateLimitRecord
    failure_notice_error: str | None  # Requirement 25.5
    # Version 2.
    deferred_by_feed: tuple[UnscoredEntry, ...] = ()  # no severity and the KEV feed missing: not decidable this run
    held_unscored: tuple[WithdrawnUnconfirmed, ...] = ()  # open Issues kept open: finding present, severity missing
    prev_record_sha256: str | None = None  # SHA-256 of the record before this one in the same month; None for the first

    def __post_init__(self) -> None:
        for name in ("started_at", "finished_at"):
            _check_seconds_utc(name, getattr(self, name))
        if self.finished_at < self.started_at:
            raise RunRecordError("finished_at is before started_at")
        if not self.run_id:
            raise RunRecordError("run_id is empty")
        if not _HEX40.fullmatch(self.aggregator_commit):
            raise RunRecordError("aggregator_commit must be 40 lowercase hex digits")
        if self.policy_commit is not None and not _HEX40.fullmatch(self.policy_commit):
            raise RunRecordError("policy_commit must be 40 lowercase hex digits or null")
        if self.prev_record_sha256 is not None and not _HEX64.fullmatch(self.prev_record_sha256):
            raise RunRecordError("prev_record_sha256 must be 64 lowercase hex digits or null")
        if self.end_state == "success" and (self.failure_reason is not None or self.failure_notice_error is not None):
            raise RunRecordError("a successful run has no failure_reason or failure_notice_error")

    @property
    def required_checks_missing(self) -> tuple[str, ...]:
        """Repositories recorded with 0 required checks, sorted."""
        return tuple(sorted(r for r, n in self.repositories.required_checks.items() if n == 0))


def _check_seconds_utc(name: str, value: datetime) -> None:
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise RunRecordError(f"{name} must be timezone-aware and in UTC")
    if value.microsecond:
        raise RunRecordError(f"{name} must have whole seconds")


def _encode(value: object, path: str = "$") -> object:
    """Converts a value into JSON-compatible data (datetimes as ``...Z``)."""
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RunRecordError(f"{path}: non-finite number")
        return value
    if isinstance(value, datetime):
        _check_seconds_utc(path, value)
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Repo):
        return f"{value.owner}/{value.name}"
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _encode(getattr(value, f.name), f"{path}.{f.name}") for f in fields(value)}
    if isinstance(value, (tuple, list)):
        return [_encode(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise RunRecordError(f"{path}: non-string key")
        return {k: _encode(v, f"{path}.{k}") for k, v in value.items()}
    raise RunRecordError(f"{path}: cannot encode {type(value).__name__}")


def _decode(tp: object, value: object, path: str, lenient: bool = False) -> object:  # noqa: PLR0911, PLR0912
    """Converts JSON data into the type ``tp``; raises ``RunRecordError`` on mismatch.

    With ``lenient`` (a version 1 record) a key that has a default may be missing; otherwise the keys must match.
    """
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin is typing.Union or origin is types.UnionType:
        if value is None and type(None) in args:
            return None
        rest = [a for a in args if a is not type(None)]
        return _decode(rest[0], value, path, lenient)
    if origin is Literal:
        if not isinstance(value, str) or value not in args:
            raise RunRecordError(f"{path}: expected one of {args}")
        return value
    if origin is tuple:
        if not isinstance(value, list):
            raise RunRecordError(f"{path}: expected an array")
        return tuple(_decode(args[0], v, f"{path}[{i}]", lenient) for i, v in enumerate(value))
    if origin is dict:
        if not isinstance(value, dict):
            raise RunRecordError(f"{path}: expected an object")
        return {k: _decode(args[1], v, f"{path}.{k}", lenient) for k, v in value.items()}
    if tp is bool:
        if not isinstance(value, bool):
            raise RunRecordError(f"{path}: expected a boolean")
        return value
    if tp is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise RunRecordError(f"{path}: expected an integer")
        return value
    if tp is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise RunRecordError(f"{path}: expected a finite number")
        return float(value)
    if tp is str:
        if not isinstance(value, str):
            raise RunRecordError(f"{path}: expected a string")
        return value
    if tp is datetime:
        if not isinstance(value, str) or not _TS.fullmatch(value):
            raise RunRecordError(f"{path}: expected YYYY-MM-DDTHH:MM:SSZ")
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError as exc:
            raise RunRecordError(f"{path}: {exc}") from exc
    if tp is date:
        if not isinstance(value, str) or not _DATE.fullmatch(value):
            raise RunRecordError(f"{path}: expected YYYY-MM-DD")
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise RunRecordError(f"{path}: {exc}") from exc
    if tp is Repo:
        parts = value.split("/") if isinstance(value, str) else []
        if len(parts) != 2 or not all(parts):
            raise RunRecordError(f"{path}: expected owner/name")
        return Repo(parts[0], parts[1])
    if isinstance(tp, type) and is_dataclass(tp):
        if not isinstance(value, dict):
            raise RunRecordError(f"{path}: expected an object")
        hints = typing.get_type_hints(tp)
        names = [f.name for f in fields(tp)]
        optional = {f.name for f in fields(tp) if f.default is not MISSING or f.default_factory is not MISSING}
        missing_ok = optional if lenient else set()
        if not set(value) <= set(names) or not set(names) - missing_ok <= set(value):
            raise RunRecordError(f"{path}: keys {sorted(value)} do not match {sorted(names)}")
        return tp(**{n: _decode(hints[n], value[n], f"{path}.{n}", lenient) for n in names if n in value})
    raise RunRecordError(f"{path}: unsupported type {tp!r}")


def to_json(record: RunRecord) -> str:
    """Serializes a run record to deterministic JSON text.

    Args:
        record: The record to write.

    Returns:
        JSON text with sorted keys, ending in a newline. The same record
        always gives the same text.

    Raises:
        RunRecordError: If a value cannot be written (non-finite number,
            datetime that is not UTC or has fractional seconds).
    """
    body = {"schema_version": SCHEMA_VERSION, **typing.cast(dict[str, object], _encode(record))}
    return json.dumps(body, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def from_json(text: str) -> RunRecord:
    """Reads a run record written by ``to_json``.

    Args:
        text: JSON text.

    Returns:
        The record; ``from_json(to_json(r)) == r``.

    Raises:
        RunRecordError: If the text is not JSON, the schema version is not 1 or
            2, a key is missing or unknown, or a value has the wrong type. A
            version 1 record may lack the keys version 2 added.
    """
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise RunRecordError(f"not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RunRecordError("expected an object")
    version = data.pop("schema_version", None)
    if isinstance(version, bool) or version not in READABLE_VERSIONS:
        raise RunRecordError(f"unsupported schema_version: {version!r}")
    return typing.cast(RunRecord, _decode(RunRecord, data, "$", lenient=version == 1))


def record_path(record: RunRecord) -> str:
    """Returns ``runs/<YYYY>/<MM>/<run_id>.json`` from the start time.

    Args:
        record: The run record.

    Returns:
        The repository path of the record.

    Raises:
        RunRecordError: If the run id is not ``<run>-<attempt>`` in digits
            (so it cannot move the path).
    """
    if not _RUN_ID.fullmatch(record.run_id):
        raise RunRecordError("run_id must be <GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>")
    s = record.started_at
    return f"runs/{s.year:04d}/{s.month:02d}/{record.run_id}.json"


def new_record_path(record: RunRecord, existing_paths: Collection[str]) -> str:
    """Returns the path to create, refusing to touch an existing record.

    Args:
        record: The run record to store.
        existing_paths: Paths already on the branch (supplied by the I/O layer).

    Returns:
        The path of the new file.

    Raises:
        RecordPathExistsError: If the path exists, or another file under
            ``runs/`` already has this run id (one file per run).
        RunRecordError: If the run id is malformed.
    """
    path = record_path(record)
    name = f"{record.run_id}.json"
    for existing in existing_paths:
        if existing == path or (existing.startswith("runs/") and existing.rsplit("/", 1)[-1] == name):
            raise RecordPathExistsError(f"run record already exists: {existing}")
    return path


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """The end state of one run."""

    run_id: str
    end_state: EndState


@dataclass(frozen=True, slots=True)
class NoticeDecision:
    """What to do with the failure-notice Issue.

    ``run_id`` is the run to write into the Issue: the latest failed run for
    ``create`` and ``append``, the successful run for ``close``, else ``None``.
    """

    action: NoticeAction
    run_id: str | None


def decide_failure_notice(outcomes: Sequence[RunOutcome], notice_open: bool) -> NoticeDecision:
    """Decides the failure-notice Issue from the latest end states.

    Args:
        outcomes: End states oldest first, ending with the current run. Pass
            at least the last ``FAILURE_STREAK_THRESHOLD`` runs when they exist.
        notice_open: Whether a failure-notice Issue is open.

    Returns:
        ``close`` if the latest run succeeded and a notice is open;
        ``create`` if the latest ``FAILURE_STREAK_THRESHOLD`` runs or more all
        failed and no notice is open; ``append`` for the same streak with a
        notice open (no second Issue); otherwise ``none``.
    """
    if not outcomes:
        return NoticeDecision("none", None)
    last = outcomes[-1]
    if last.end_state == "success":
        return NoticeDecision("close", last.run_id) if notice_open else NoticeDecision("none", None)
    streak = 0
    for outcome in reversed(outcomes):
        if outcome.end_state != "failure":
            break
        streak += 1
    if streak < FAILURE_STREAK_THRESHOLD:
        return NoticeDecision("none", None)
    return NoticeDecision("append" if notice_open else "create", last.run_id)


def retry_wait(retry_index: int, retry_after: float | None = None) -> float | None:
    """Returns the wait before a retry, or ``None`` when no retry is left.

    Args:
        retry_index: 0 for the first retry. The waits are 2, 4, 8, 16, 32 s.
        retry_after: Seconds from a ``retry-after`` header, if present.

    Returns:
        ``max(2 * 2**retry_index, retry_after)`` seconds, or ``None`` for the
        sixth retry and later.

    Raises:
        ValueError: If ``retry_index`` is negative or ``retry_after`` is
            negative or not finite.
    """
    if isinstance(retry_index, bool) or retry_index < 0:
        raise ValueError("retry_index must be a non-negative integer")
    if retry_after is not None and (isinstance(retry_after, bool) or not math.isfinite(retry_after) or retry_after < 0):
        raise ValueError("retry_after must be a finite number of seconds >= 0")
    if retry_index >= MAX_RETRIES:
        return None
    wait = float(BACKOFF_BASE_SECONDS * 2**retry_index)
    return max(wait, float(retry_after)) if retry_after is not None else wait


def backoff_schedule(retry_after: Sequence[float | None] = ()) -> tuple[float, ...]:
    """Returns the waits of all retries, in order.

    Args:
        retry_after: ``retry-after`` seconds seen before each retry, by index;
            missing entries and ``None`` mean no header. Entries past the
            fifth are ignored.

    Returns:
        Five waits: 2, 4, 8, 16, 32 seconds, each raised to ``retry-after``
        when that is larger.
    """
    waits: list[float] = []
    for i in range(MAX_RETRIES):
        wait = retry_wait(i, retry_after[i] if i < len(retry_after) else None)
        assert wait is not None  # noqa: S101 - i < MAX_RETRIES
        waits.append(wait)
    return tuple(waits)


def sha256_text(text: str) -> str:
    """Returns the SHA-256 (64 hex digits) of ``text`` encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def month_of(path: str) -> str:
    """``runs/<YYYY>/<MM>`` of a record path (the unit of one chain)."""
    return path.rsplit("/", 1)[0]


def previous_record_sha256(month_texts: Iterable[str]) -> str | None:
    """The SHA-256 of the one record of the month that no other record names as its predecessor (the tip)."""
    parsed = []
    for text in month_texts:
        try:
            parsed.append((from_json(text), text))
        except RunRecordError:
            continue
    if not parsed:
        return None
    named = {record.prev_record_sha256 for record, _ in parsed if record.prev_record_sha256 is not None}
    tips = [sha256_text(text) for _, text in parsed if sha256_text(text) not in named]
    if len(tips) != 1:
        raise RunRecordError(
            f"the month has {len(tips)} chain tips; a record was written while another was being written"
        )
    return tips[0]


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """One place where the record chain does not hold.

    Attributes:
        path: The record where it shows (the first one that does not match, not the one removed or edited).
        reason: ``unreadable`` (the text is not a run record), ``first_not_null`` (the first record of a
            month names a predecessor), ``prev_mismatch`` (the root of records that cannot be reached from the first
            record: a record before them was edited, removed or unknown), or ``fork`` (a second record
            names the same predecessor).
    """

    path: str
    reason: str


def verify_chain(entries: Iterable[tuple[str, str]]) -> tuple[ChainBreak, ...]:
    """Follow ``prev_record_sha256`` from the first record; report a fork, an orphan, a second start, an unreadable text."""
    months: dict[str, list[tuple[RunRecord, str, str, int]]] = {}
    breaks: list[ChainBreak] = []
    for path, text in entries:
        try:
            raw = json.loads(text)
            version = raw.get("schema_version") if isinstance(raw, dict) else None
            record = from_json(text)
        except (ValueError, RunRecordError):
            breaks.append(ChainBreak(path, "unreadable"))
            continue
        months.setdefault(month_of(path), []).append((record, path, text, version if isinstance(version, int) else 0))
    for items in months.values():
        by_hash = {sha256_text(text): (record, path, version) for record, path, text, version in items}
        children: dict[str | None, list[str]] = {}
        for digest, (record, _path, version) in by_hash.items():
            if version >= SCHEMA_VERSION:
                children.setdefault(record.prev_record_sha256, []).append(digest)
        # version 1 records carry no hash: they are the legacy start of the chain and are not followed
        v1 = [digest for digest, (_r, _p, version) in by_hash.items() if version < SCHEMA_VERSION]
        starts = children.get(None, [])
        if len(starts) > 1 and not v1:
            breaks += [
                ChainBreak(by_hash[d][1], "first_not_null") for d in sorted(starts, key=lambda d: by_hash[d][1])[1:]
            ]
        reached: set[str] = set()
        frontier = [*starts, *v1]
        while frontier:
            current = frontier.pop()
            if current in reached:
                continue
            reached.add(current)
            kids = children.get(current, [])
            if len(kids) > 1:
                breaks += [ChainBreak(by_hash[d][1], "fork") for d in sorted(kids, key=lambda d: by_hash[d][1])[1:]]
            frontier.extend(kids)
        # only the root of an unreached run is a break: its predecessor is edited, removed or unknown
        earliest = min(items, key=lambda item: (item[0].started_at, item[0].run_id))[1]
        for digest, (record, path, version) in by_hash.items():
            if version < SCHEMA_VERSION or digest in reached or record.prev_record_sha256 in by_hash:
                continue
            breaks.append(ChainBreak(path, "first_not_null" if path == earliest else "prev_mismatch"))
    return tuple(sorted(breaks, key=lambda b: (b.path, b.reason)))


def month_seal(month: str, entries: Iterable[tuple[str, str]]) -> tuple[str, str] | None:
    """Returns the tag name and value that pin the end of a month's chain.

    Args:
        month: ``YYYY-MM``.
        entries: ``(path, text)`` of the records stored for that month.

    Returns:
        ``("supply-chain-runs-YYYY-MM", sha256 of the last record's text)``, or ``None`` when the month has
        no readable record. An annotated tag with this value, protected by its own ruleset, makes the
        removal of the last record visible.

    Raises:
        RunRecordError: If ``month`` is not ``YYYY-MM``.
    """
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}", month):
        raise RunRecordError("month must be YYYY-MM")
    value = previous_record_sha256(text for _path, text in entries)
    return None if value is None else (f"supply-chain-runs-{month}", value)


def _live_tips(entries: Iterable[tuple[str, str]], abandoned: Collection[str]) -> list[str]:
    """SHA-256 of the readable records that no other record names as predecessor, outside ``abandoned``."""
    digests: dict[str, str | None] = {}
    for _path, text in entries:
        try:
            digests[sha256_text(text)] = from_json(text).prev_record_sha256
        except RunRecordError:
            continue
    named = {prev for prev in digests.values() if prev is not None}
    return sorted(d for d in digests if d not in named and d not in abandoned)


def verify_month_tip(
    month: str,
    entries: Iterable[tuple[str, str]],
    recorded_tip_sha256: str | None,
    *,
    abandoned: Collection[str] = frozenset(),
    kept_tip_sha256: str | None = None,
) -> ChainBreak | None:
    """Checks that the record the Aggregator last wrote is still in the month, byte for byte (T4-R3-08).

    A record that has no successor yet (the tip) is not covered by any ``prev_record_sha256``, so an edit of it is
    not seen by :func:`verify_chain` until the next write and not by the seal until the month ends. The Aggregator
    keeps the SHA-256 of the record it wrote last (in the job summary and the tag); the next run passes it here
    before writing.

    Args:
        month: ``YYYY-MM``.
        entries: ``(path, text)`` of the records stored for that month.
        recorded_tip_sha256: The SHA-256 the previous run reported, or ``None`` when there is none (first run).
        abandoned: SHA-256 values of the ``accepted_forks`` of the chain-recovery ledger. A run that lost a race
            keeps the SHA-256 of a record that was abandoned afterwards; once the ledger lists it, the value is
            not a change of the tip, so the first write after the recovery goes ahead (T12-R4-04). Pass the
            records of the month *without* applying the ledger, or with it: either way the check stays byte for byte
            for every value the ledger does not list.

        kept_tip_sha256: The SHA-256 of the tip that stayed in the chain after the recovery, if the caller has it.
            When the recorded value was abandoned, the check cannot compare it with the record; instead the month
            must have exactly one live tip (a record no other record names, outside ``abandoned``), and that tip
            must be this value when it is given. Without it an in-place edit of the kept tip is not found in this
            one write (T12-R5-07); the next write checks the tip the normal way.

    Returns:
        ``None`` when nothing was recorded or a record with that SHA-256 exists; otherwise a break with reason
        ``tip_changed`` (the record was edited or removed), at the path of the month.

    Raises:
        RunRecordError: If ``month`` or the recorded value is malformed.
    """
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}", month):
        raise RunRecordError("month must be YYYY-MM")
    if recorded_tip_sha256 is None:
        return None
    if not re.fullmatch(r"[0-9a-f]{64}", recorded_tip_sha256):
        raise RunRecordError("recorded tip must be 64 lowercase hex digits")
    if recorded_tip_sha256 in abandoned:
        live = _live_tips(entries, abandoned)
        if len(live) != 1 or (kept_tip_sha256 is not None and live[0] != kept_tip_sha256):
            return ChainBreak(f"runs/{month.replace('-', '/')}", "tip_changed")
        return None
    if any(sha256_text(text) == recorded_tip_sha256 for _path, text in entries):
        return None
    return ChainBreak(f"runs/{month.replace('-', '/')}", "tip_changed")


def verify_month_seal(month: str, entries: Iterable[tuple[str, str]], sealed_sha256: str) -> ChainBreak | None:
    """Compares a month's sealed value (the tag from :func:`month_seal`) with the month as it is stored.

    Returns:
        ``None`` when the tip of the stored month is the sealed value; otherwise a break with reason
        ``seal_mismatch`` (the last record was edited or removed, or the month has no readable record), or
        ``fork`` when the month has more than one tip.

    Raises:
        RunRecordError: If ``month`` or ``sealed_sha256`` is malformed.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", sealed_sha256):
        raise RunRecordError("sealed value must be 64 lowercase hex digits")
    where = f"runs/{month.replace('-', '/')}"
    try:
        seal = month_seal(month, entries)
    except RunRecordError as exc:
        if "chain tips" in str(exc):
            return ChainBreak(where, "fork")
        raise
    if seal is None or seal[1] != sealed_sha256:
        return ChainBreak(where, "seal_mismatch")
    return None

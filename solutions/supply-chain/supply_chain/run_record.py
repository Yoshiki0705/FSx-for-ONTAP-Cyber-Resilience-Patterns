"""Run record, failure-notice decision and retry waits (Requirements 9.6, 9.7, 25.3-25.5, 26.2, 26.3, 26.5).

Pure code. No I/O, no clock reads. The I/O layer writes the JSON text this
module produces and passes in the set of paths that already exist.

* ``RunRecord`` / ``to_json`` / ``from_json``: the "run record" of the design
  (section 5 and Data Models). ``from_json(to_json(r)) == r``. Datetimes are
  UTC with whole seconds (``...Z``); dates are ``YYYY-MM-DD``.
* ``record_path`` / ``new_record_path``: ``runs/<YYYY>/<MM>/<run_id>.json``.
  A path that already exists, or a run id that already has a file, is refused
  (append only, Requirement 26.3).
* ``decide_failure_notice``: from the latest end states, whether to create,
  append to, or close the failure-notice Issue (Requirements 25.3, 25.4).
* ``backoff_schedule`` / ``retry_wait``: 2, 4, 8, 16, 32 seconds, at least
  ``retry-after`` when the server gave one, and no sixth retry.
"""

from __future__ import annotations

import json
import math
import re
import types
import typing
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from supply_chain.models import FeedName, IssueOp, Layer, PullRequestRef, Repo, Severity

SCHEMA_VERSION = 1
EndState = Literal["success", "failure"]
NoticeAction = Literal["none", "create", "append", "close"]

FAILURE_STREAK_THRESHOLD = 2
BACKOFF_BASE_SECONDS = 2
MAX_RETRIES = 5

_HEX40 = re.compile(r"[0-9a-f]{40}")
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
class Repositories:
    """Repositories of a run.

    ``required_checks`` maps ``owner/name`` to the number of required status
    checks on the default branch; ``None`` means it could not be read. A count
    of 0 is recorded on purpose (Requirement 14.4 depends on it).
    """

    scanned: tuple[str, ...]
    fetch_failed: tuple[FetchFailure, ...]
    required_checks: dict[str, int | None]


@dataclass(frozen=True, slots=True)
class FeedFetched:
    """A feed that was obtained."""

    name: FeedName
    at: datetime
    catalog_version: str | None


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


def _decode(tp: object, value: object, path: str) -> object:  # noqa: PLR0911, PLR0912
    """Converts JSON data into the type ``tp``; raises ``RunRecordError`` on mismatch."""
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin is typing.Union or origin is types.UnionType:
        if value is None and type(None) in args:
            return None
        rest = [a for a in args if a is not type(None)]
        return _decode(rest[0], value, path)
    if origin is Literal:
        if not isinstance(value, str) or value not in args:
            raise RunRecordError(f"{path}: expected one of {args}")
        return value
    if origin is tuple:
        if not isinstance(value, list):
            raise RunRecordError(f"{path}: expected an array")
        return tuple(_decode(args[0], v, f"{path}[{i}]") for i, v in enumerate(value))
    if origin is dict:
        if not isinstance(value, dict):
            raise RunRecordError(f"{path}: expected an object")
        return {k: _decode(args[1], v, f"{path}.{k}") for k, v in value.items()}
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
        if set(value) != set(names):
            raise RunRecordError(f"{path}: keys {sorted(value)} do not match {sorted(names)}")
        return tp(**{n: _decode(hints[n], value[n], f"{path}.{n}") for n in names})
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
        RunRecordError: If the text is not JSON, the schema version is not 1,
            a key is missing or unknown, or a value has the wrong type.
    """
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise RunRecordError(f"not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RunRecordError("expected an object")
    version = data.pop("schema_version", None)
    if isinstance(version, bool) or version != SCHEMA_VERSION:
        raise RunRecordError(f"unsupported schema_version: {version!r}")
    return typing.cast(RunRecord, _decode(RunRecord, data, "$"))


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

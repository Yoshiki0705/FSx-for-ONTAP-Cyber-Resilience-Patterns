"""State transitions of Handoff items, and the text of ``status.json``.

The Data Models section of the design ("Handoff_Harness の設定、項目、状態") defines the
status file and its transition table. Requirements 28.12, 28.13 and 28.19 and Property 23
constrain them. This module is part of the pure core (see ``handoff/__init__.py``): it
takes values and returns values. It does not read the clock, start a process, or read or
write a file. Writing ``status.json`` (a temporary file, ``os.replace``, the
``status.json.bak`` copy) belongs to ``runner.py``.

Internal representation: a status is the JSON value of ``status.json`` exactly as
``json.loads`` returns it, and :func:`check_status` decides whether a value is one. The
check has two layers.

1. The JSON data model, over the whole value: only the exact built-in types ``dict``,
   ``list``, ``str``, ``int``, ``float``, ``bool`` and ``None`` (no tuple, subclass, enum
   member or ``datetime``); string keys; finite floats (no NaN or infinity); integers
   within ``±MAX_SAFE_INTEGER``; strings that encode as UTF-8 (no lone surrogate); no
   list or dict reached twice (shared or cyclic); at most ``MAX_DEPTH`` levels of
   nesting. Every value in this set renders and parses back to an equal value of the
   same types, so ``parse_status(render_status(s)) == s`` holds for every status ``s``.
2. The schema: the top level has the keys of :class:`StatusDoc` (``confirmed_refs`` may be
   missing, which every status written before task 15.4 is), and each item
   exactly the keys of :class:`ItemRecord`. ``schema_version`` is the integer 1. An
   item's ``state`` is one of ``STATES`` and its ``history`` replays to it: the first
   entry leaves ``INITIAL_STATE``, each later entry leaves the state the previous one
   entered, each ``(from, to)`` pair is in ``ALLOWED_TRANSITIONS``, and the last ``to``
   is ``state``. An item with no history is in ``INITIAL_STATE``. A state written into
   the file without a transition is therefore rejected on the next read. The remaining
   fields are checked for their container type only (see :class:`ItemRecord`); the
   modules that write them decide what goes inside. ``events`` is the harness's own
   record of what it did outside the items, such as removing a stale lock (design
   section 20, "同時実行と排他"): each entry has exactly the keys of :class:`HarnessEvent`,
   checked as :func:`record_event` describes.

Errors: :class:`InvalidStatusError` for a value or text that is not a status. The design
has the harness refuse to start on a damaged status file, and the maintainer restores
``status.json.bak``. :class:`TransitionError` for a refused request. Both are
``ValueError``. No function changes its arguments; the ones that change a status return a
new one.
"""

from __future__ import annotations

import copy
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, Final, NotRequired, TypedDict

QUEUED: Final = "queued"
RUNNING: Final = "running"
SUCCEEDED: Final = "succeeded"
FAILED: Final = "failed"
NEEDS_HUMAN: Final = "needs-human"

#: The five states of Requirement 28.13.
STATES: Final[frozenset[str]] = frozenset({QUEUED, RUNNING, SUCCEEDED, FAILED, NEEDS_HUMAN})

#: The state of a newly added item. Every history replays from here.
INITIAL_STATE: Final = QUEUED

#: The transition table of the Data Models section, edge for edge. Nothing leaves
#: ``succeeded``, and no state goes to itself.
ALLOWED_TRANSITIONS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        (QUEUED, RUNNING),  # dag.select chose it, and the scan and whoami passed
        (QUEUED, NEEDS_HUMAN),  # scan hit, unconfirmed selftest for change mode, body too long, SHA mismatch
        (RUNNING, SUCCEEDED),  # evaluate.final_state
        (RUNNING, FAILED),  # evaluate.final_state, timeout, harness_interrupted
        (RUNNING, NEEDS_HUMAN),  # evaluate.final_state
        (FAILED, QUEUED),  # the maintainer re-runs it: cli.py status set <id> queued --reason ...
        (NEEDS_HUMAN, QUEUED),  # the maintainer fixed the cause
    }
)

SCHEMA_VERSION: Final = 1

#: Form of ``history[].at``: UTC, whole seconds, ``Z`` suffix, as in ``2026-11-10T00:00:00Z``.
TIMESTAMP_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"

#: Largest magnitude of an integer in a status: 2**53 - 1, the bound of the range that
#: RFC 8259 (section 6) calls interoperable, so another JSON reader sees the same number.
#: A PID, an exit code or a line number is far below it. The bound also keeps integers far
#: from the 4,300-digit limit at which Python 3.12 refuses to convert an int to text by
#: default, so rendering cannot fail on one.
MAX_SAFE_INTEGER: Final = 2**53 - 1

#: Deepest nesting of lists and dicts in a status, counting the top-level object as 1. The
#: schema itself uses 6 levels (the top level, ``items``, an item, ``rerun``, one entry of
#: it, and that entry's ``cmd``); the rest is room for payloads. The bound keeps the checks
#: and the JSON encoder far from Python's recursion limit.
MAX_DEPTH: Final = 32

_TIMESTAMP_SHAPE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

#: Form of ``events[].kind``: lowercase ASCII words joined by single underscores, such as
#: ``stale_lock_removed``. The kinds themselves belong to the module that records them.
_EVENT_KIND: Final = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")

#: One entry of an item's ``history``: the state left, the state entered, when, and why.
#: Written in the functional form because ``from`` is a Python keyword.
HistoryEntry = TypedDict("HistoryEntry", {"from": str, "to": str, "at": str, "reason": str})


class HarnessEvent(TypedDict):
    """One entry of ``events``: something the harness did that is not a transition of an item.

    Attributes:
        at: When, in ``TIMESTAMP_FORMAT``.
        kind: What happened, in the form of ``_EVENT_KIND``, for example
            ``stale_lock_removed``.
        detail: An explanation for the maintainer. Not blank.
    """

    at: str
    kind: str
    detail: str


class ItemRecord(TypedDict):
    """One item of ``status.json``, under ``items`` with its item ID as the key.

    ``state`` and ``history`` change only through :func:`transition`. The other parts of
    the harness write the remaining keys; this module checks their container type and that
    they hold JSON values, nothing more.

    Attributes:
        state: One of ``STATES``.
        history: The transitions applied so far, oldest first.
        pid: The ``kiro-cli`` process, or ``None``. A positive integer, because ``os.kill``
            signals more than one process for 0 and for negative numbers (POSIX ``kill``).
        worktree: Path of the item's worktree, or ``None``. Not empty.
        branch: The handoff branch, or ``None``. Not empty.
        base_sha: The commit the worktree was created from, or ``None``. Not empty.
        report: Path of the Handoff_Report, or ``None``. Not empty.
        observations: What the result check observed, or ``None`` before a run.
        rerun: The verification commands re-run in the worktree, with their exit codes.
        rerun_skipped: The verification commands not re-run, with the reason.
        report_flags: Lines of the Handoff_Report that look like instructions.
        published: The publish approval and the pull request.
    """

    state: str
    history: list[HistoryEntry]
    pid: int | None
    worktree: str | None
    branch: str | None
    base_sha: str | None
    report: str | None
    observations: dict[str, Any] | None
    rerun: list[Any]
    rerun_skipped: list[Any]
    report_flags: list[Any]
    published: dict[str, Any]


class ConfirmedRef(TypedDict):
    """One entry of ``confirmed_refs``: a ref that the harness checked on its repository's default branch (IN-2).

    Attributes:
        repo: A key of ``repos`` of the configuration. Not empty.
        kind: ``tag`` or ``sha``.
        name: The tag name, or for ``sha`` the commit SHA itself.
        sha: The commit that the ref is: 40 lowercase hexadecimal digits. For a tag, the commit
            that ``git ls-remote`` showed it to point to (peeled, for an annotated tag); for
            ``sha``, equal to ``name``.
        at: When it was checked, in ``TIMESTAMP_FORMAT``.
    """

    repo: str
    kind: str
    name: str
    sha: str
    at: str


class StatusDoc(TypedDict):
    """The whole of ``status.json``.

    Attributes:
        schema_version: Always ``SCHEMA_VERSION``.
        selftest: The latest selftest result, or ``None`` before the first selftest.
        items: Each item's record, keyed by its item ID (a non-empty string).
        events: What the harness did outside the items, oldest first. Only
            :func:`record_event` adds an entry, and nothing changes or removes one.
        confirmed_refs: The refs that ``cli.py confirm-ref`` checked (task 15.4), oldest first,
            one entry per ``(repo, kind, name)``. Missing until the first one is recorded. Only
            :func:`confirm_ref` adds an entry, and nothing changes or removes one.
    """

    schema_version: int
    selftest: dict[str, Any] | None
    items: dict[str, ItemRecord]
    events: list[HarnessEvent]
    confirmed_refs: NotRequired[list[ConfirmedRef]]


#: ``NotRequired`` is not seen through the string annotations of ``from __future__ import annotations``,
#: so the optional key is named here and left out of the required ones.
_TOP_OPTIONAL_KEYS: Final = frozenset({"confirmed_refs"})
_TOP_KEYS: Final = StatusDoc.__required_keys__ - _TOP_OPTIONAL_KEYS
_CONFIRMED_KEYS: Final = ConfirmedRef.__required_keys__
_REF_KINDS: Final = ("tag", "sha")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}")
_ITEM_KEYS: Final = ItemRecord.__required_keys__
_ENTRY_KEYS: Final = HistoryEntry.__required_keys__
_EVENT_KEYS: Final = HarnessEvent.__required_keys__

_JSON_TYPE_NAMES: Final[dict[type, str]] = {
    dict: "object",
    list: "array",
    str: "string",
    int: "number",
    float: "number",
    bool: "boolean",
    type(None): "null",
}


class InvalidStatusError(ValueError):
    """A value or a text is not a status as :func:`check_status` defines it.

    The design's impact table has the harness refuse to start on a damaged status file;
    the maintainer restores ``status.json.bak``.
    """


class TransitionError(ValueError):
    """A request to change a status was refused. The status passed in is unchanged."""


def empty_status() -> StatusDoc:
    """Return a status with no items, no selftest result and no events.

    Returns:
        A new status: ``schema_version`` 1, ``selftest`` ``None``, ``items`` and ``events``
        empty.
    """
    return {"schema_version": SCHEMA_VERSION, "selftest": None, "items": {}, "events": []}


def add_item(status: StatusDoc, item_id: str) -> StatusDoc:
    """Return a copy of a status with one more item, in ``INITIAL_STATE`` and with no history.

    Args:
        status: A status that passes :func:`check_status`. It is not changed.
        item_id: A non-empty item ID that ``status`` does not have yet.

    Returns:
        A new status. The new item's lists and objects are its own, not shared.

    Raises:
        InvalidStatusError: ``status`` is not a status.
        TransitionError: ``item_id`` is not a non-empty string, or the item exists already.
            Adding an existing item again would put it back in ``queued`` without a
            transition, which is how a ``succeeded`` item could be run again.
    """
    check_status(status)
    if type(item_id) is not str or not item_id or not _encodable(item_id):
        raise TransitionError(f"an item ID is a non-empty string, not {_show(item_id)}")
    if item_id in status["items"]:
        raise TransitionError(f"item {_show(item_id)} exists already; adding it again would reset its state")
    result = copy.deepcopy(status)
    result["items"][item_id] = _new_item()
    return result


def transition(status: StatusDoc, item_id: str, to_state: str, *, at: str, reason: str) -> StatusDoc:
    """Move one item along an allowed edge, and record the move in its history.

    Args:
        status: A status that passes :func:`check_status`. It is not changed.
        item_id: An item of ``status``.
        to_state: The requested state, one of ``STATES``, as a plain ``str``.
        at: When the move happened, in ``TIMESTAMP_FORMAT`` (:func:`format_timestamp`
            writes it). The caller reads the clock; this module does not.
        reason: Why the item moves, for example ``dispatched`` or ``harness_interrupted``.
            Not blank.

    Returns:
        A new status in which the item is in ``to_state`` and its history ends with
        ``{"from": <the previous state>, "to": to_state, "at": at, "reason": reason}``.
        Nothing else differs from ``status``.

    Raises:
        InvalidStatusError: ``status`` is not a status.
        TransitionError: The item does not exist; ``to_state`` is not a state; the pair of
            the item's state and ``to_state`` is not in ``ALLOWED_TRANSITIONS`` (this
            covers every request from ``succeeded`` and every request to stay in the same
            state); ``at`` is not a timestamp in ``TIMESTAMP_FORMAT``; or ``reason`` is
            blank.
    """
    check_status(status)
    if type(item_id) is not str or item_id not in status["items"]:
        raise TransitionError(f"the status has no item {_show(item_id)}")
    if type(to_state) is not str or to_state not in STATES:
        raise TransitionError(f"{_show(to_state)} is not a state; the states are {sorted(STATES)}")
    from_state = status["items"][item_id]["state"]
    if (from_state, to_state) not in ALLOWED_TRANSITIONS:
        raise TransitionError(f"item {_show(item_id)}: {from_state} -> {to_state} is not an allowed transition")
    if not _is_timestamp(at):
        raise TransitionError(f"at must be UTC in whole seconds, like 2026-11-10T00:00:00Z, not {_show(at)}")
    if not _is_reason(reason):
        raise TransitionError(f"reason must be a non-blank string, not {_show(reason)}")
    result = copy.deepcopy(status)
    record = result["items"][item_id]
    record["state"] = to_state
    record["history"].append({"from": from_state, "to": to_state, "at": at, "reason": reason})
    return result


def record_event(status: StatusDoc, *, at: str, kind: str, detail: str) -> StatusDoc:
    """Return a copy of a status with one more entry at the end of ``events``.

    An event records something the harness did that is not a transition of an item, such as
    removing a lock whose process is gone (design section 20, "同時実行と排他"). Nothing
    else in the status changes, and the earlier events are kept as they are.

    Args:
        status: A status that passes :func:`check_status`. It is not changed.
        at: When it happened, in ``TIMESTAMP_FORMAT`` (:func:`format_timestamp` writes it).
            The caller reads the clock; this module does not.
        kind: What happened: lowercase ASCII words joined by single underscores, such as
            ``stale_lock_removed``. The module that records an event names its kinds.
        detail: An explanation for the maintainer. Not blank.

    Returns:
        A new status whose ``events`` ends with ``{"at": at, "kind": kind, "detail": detail}``.

    Raises:
        InvalidStatusError: ``status`` is not a status.
        TransitionError: ``at`` is not a timestamp in ``TIMESTAMP_FORMAT``, ``kind`` does not
            have its form, or ``detail`` is blank.
    """
    check_status(status)
    if not _is_timestamp(at):
        raise TransitionError(f"at must be UTC in whole seconds, like 2026-11-10T00:00:00Z, not {_show(at)}")
    if not _is_event_kind(kind):
        raise TransitionError(f"kind must be lowercase words joined by underscores, not {_show(kind)}")
    if not _is_reason(detail):
        raise TransitionError(f"detail must be a non-blank string, not {_show(detail)}")
    result = copy.deepcopy(status)
    result["events"].append({"at": at, "kind": kind, "detail": detail})
    return result


def confirm_ref(status: StatusDoc, *, repo: str, kind: str, name: str, sha: str, at: str) -> StatusDoc:
    """Return a copy of a status with one more confirmed ref (IN-2, Requirement 28.12).

    The caller has checked the ref against git (``handoff.runner.Harness.confirm_ref``); this
    function only keeps the finding. Confirming a ref again with the same commit changes nothing
    (the first ``at`` stays). A tag that now points to another commit is refused, not overwritten:
    a moved tag is something for the maintainer to look at.

    Args:
        status: A status that passes :func:`check_status`. It is not changed.
        repo: A key of ``repos`` of the configuration.
        kind: ``tag`` or ``sha``.
        name: The tag name, or the commit SHA for ``sha``.
        sha: The commit, 40 lowercase hexadecimal digits; equal to ``name`` for ``sha``.
        at: When it was checked, in ``TIMESTAMP_FORMAT``.

    Returns:
        A new status whose ``confirmed_refs`` has the entry.

    Raises:
        InvalidStatusError: ``status`` is not a status.
        TransitionError: An argument does not have its form, or the ref is recorded with another
            commit.
    """
    check_status(status)
    entry: ConfirmedRef = {"repo": repo, "kind": kind, "name": name, "sha": sha, "at": at}
    for key, value in entry.items():
        if type(value) is not str:
            raise TransitionError(f"{key} must be a string, not {_show(value)}")
    problem = _confirmed_problem(entry)
    if problem is not None:
        raise TransitionError(problem)
    for earlier in status.get("confirmed_refs", []):
        if (earlier["repo"], earlier["kind"], earlier["name"]) == (repo, kind, name):
            if earlier["sha"] == sha:
                return copy.deepcopy(status)
            raise TransitionError(
                f"{repo} {kind} {name} is recorded with {earlier['sha']}, and now it is {sha}; "
                "look at why it moved before recording it again"
            )
    result = copy.deepcopy(status)
    result.setdefault("confirmed_refs", []).append(entry)
    return result


def confirmed_refs_of(status: StatusDoc) -> tuple[ConfirmedRef, ...]:
    """The confirmed refs of a status, oldest first; none for a status written before task 15.4.

    Args:
        status: A status that passes :func:`check_status`. It is not changed.

    Returns:
        Copies of the entries.

    Raises:
        InvalidStatusError: ``status`` is not a status.
    """
    check_status(status)
    return tuple(copy.deepcopy(entry) for entry in status.get("confirmed_refs", []))


def format_timestamp(moment: datetime) -> str:
    """Write a moment in ``TIMESTAMP_FORMAT``, the form of ``history[].at``.

    Args:
        moment: An aware datetime. It is converted to UTC and cut to whole seconds.

    Returns:
        The timestamp, for example ``2026-11-10T00:00:00Z``.

    Raises:
        TypeError: ``moment`` is not a datetime.
        ValueError: ``moment`` is naive, so its time zone would be a guess.
    """
    if not isinstance(moment, datetime):
        raise TypeError(f"moment must be a datetime, not {type(moment).__name__}")
    if moment.utcoffset() is None:
        raise ValueError("a naive datetime has no time zone; pass an aware one, such as datetime.now(timezone.utc)")
    utc = moment.astimezone(timezone.utc)
    return f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}T{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}Z"


def waiting_on_failed_dependencies(status: StatusDoc, depends_on: Mapping[str, Sequence[str]]) -> dict[str, list[str]]:
    """Find the queued items that wait because something they depend on failed.

    ``cli.py status`` shows these items as 「依存先の失敗で待機中」 (Requirement 28.12). An
    item is listed when it is ``queued`` and a ``failed`` item can be reached from it by
    following ``depends_on`` through items that have not succeeded:

    - The failure may be several steps up. ``dag.ready`` looks at direct dependencies
      only, so an item two steps below a failure would otherwise look like any other
      queued item, although it cannot start until the maintainer re-queues the failed
      item (the harness does not retry on its own).
    - A ``succeeded`` item ends the path: that dependency is satisfied.
    - A ``needs-human`` item is not a failure and is never listed as a cause, but the path
      continues through it, as it does through ``queued``, ``running`` and ``failed``
      items and through IDs that the status has no record of.

    Args:
        status: A status that passes :func:`check_status`.
        depends_on: Each item ID mapped to the IDs it depends on, as in the manifest. IDs
            that the status does not have are allowed. A cycle is allowed too: the
            manifest check rejects cycles, and this function only has to stop.

    Returns:
        Each waiting item ID, in sorted order, mapped to the sorted IDs of the failed items
        found from it. Empty when nothing waits on a failure.

    Raises:
        InvalidStatusError: ``status`` is not a status.
        TypeError: ``depends_on`` is not a mapping from strings to lists or tuples of
            strings. A bare string is refused, since it would read as one ID per character.
    """
    check_status(status)
    graph = _dependency_graph(depends_on)
    items = status["items"]
    waiting: dict[str, list[str]] = {}
    for item_id in sorted(items):
        if items[item_id]["state"] != QUEUED:
            continue
        failed = _failed_upstream(item_id, items, graph)
        if failed:
            waiting[item_id] = failed
    return waiting


def render_status(status: StatusDoc) -> str:
    """Write a status as the text of ``status.json``.

    Equal statuses give the same text: keys sorted, 2-space indent, LF line ends, a final
    newline, and non-ASCII characters written as themselves (``ensure_ascii=False``).

    Args:
        status: A status that passes :func:`check_status`. It is not changed.

    Returns:
        The text to write, as UTF-8, to ``status.json``.

    Raises:
        InvalidStatusError: ``status`` is not a status. No text is returned, so the caller
            keeps the file it has.
    """
    check_status(status)
    return json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"


def parse_status(text: str) -> StatusDoc:
    """Read the text of ``status.json``.

    Args:
        text: The content of the file, decoded from UTF-8 by the caller.

    Returns:
        The status. ``parse_status(render_status(s)) == s`` for every status ``s``.

    Raises:
        TypeError: ``text`` is not a string.
        InvalidStatusError: ``text`` is not one JSON value (this includes empty text, a
            byte order mark, and anything after the value); an object repeats a key; or
            the value is not a status (for example an unknown state, a ``schema_version``
            other than 1, or a history that does not replay to the item's state).
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, not {type(text).__name__}")
    try:
        value = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except InvalidStatusError:
        raise
    except (ValueError, RecursionError) as exc:
        raise InvalidStatusError(f"status.json is not valid JSON: {exc}") from exc
    check_status(value)
    return value


def check_status(status: object) -> None:
    """Check that a value is a status, as the module docstring defines it.

    Args:
        status: Any value. It is not changed.

    Raises:
        InvalidStatusError: The first problem found, with the path of the value, for
            example ``$["items"]["c-hub-preset"]["history"][0]["at"]``.
    """
    _check_json_model(status, "$", 1, set())
    _check_schema(status)


def _new_item() -> ItemRecord:
    """Build the record of a newly added item, from fresh lists and objects."""
    return {
        "state": INITIAL_STATE,
        "history": [],
        "pid": None,
        "worktree": None,
        "branch": None,
        "base_sha": None,
        "report": None,
        "observations": None,
        "rerun": [],
        "rerun_skipped": [],
        "report_flags": [],
        "published": {"approved_at": None, "pr": None},
    }


def _check_json_model(value: object, path: str, depth: int, seen: set[int]) -> None:
    """Check layer 1 of :func:`check_status`: the value is in the JSON data model.

    Args:
        value: The value at ``path``.
        path: Where ``value`` is, for error messages.
        depth: Nesting level of ``value`` if it is a list or a dict; the top level is 1.
        seen: ``id`` of every list and dict met so far.

    Raises:
        InvalidStatusError: The value or something inside it is outside the data model.
    """
    kind = type(value)
    if value is None or kind is bool:
        return
    if kind is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise InvalidStatusError(f"{path}: an integer of {value.bit_length()} bits is outside ±(2**53 - 1)")
        return
    if kind is float:
        if not math.isfinite(value):
            raise InvalidStatusError(f"{path}: {value!r} is not a finite number")
        return
    if kind is str:
        if not _encodable(value):
            raise InvalidStatusError(f"{path}: the string does not encode as UTF-8 (a lone surrogate)")
        return
    if kind is not list and kind is not dict:
        raise InvalidStatusError(
            f"{path}: {kind.__name__} is not a JSON value; use dict, list, str, int, float, bool or None"
        )
    if depth > MAX_DEPTH:
        raise InvalidStatusError(f"{path}: nested deeper than {MAX_DEPTH} levels")
    if id(value) in seen:
        raise InvalidStatusError(f"{path}: this {kind.__name__} appears twice (shared or cyclic)")
    seen.add(id(value))
    if kind is list:
        for index, element in enumerate(value):
            _check_json_model(element, f"{path}[{index}]", depth + 1, seen)
        return
    for key, element in value.items():
        if type(key) is not str:
            raise InvalidStatusError(f"{path}: the key {_show(key)} is not a str")
        if not _encodable(key):
            raise InvalidStatusError(f"{path}: the key {_show(key)} does not encode as UTF-8 (a lone surrogate)")
        _check_json_model(element, _child(path, key), depth + 1, seen)


def _check_schema(status: object) -> None:
    """Check layer 2 of :func:`check_status`. Assumes layer 1 has passed."""
    if type(status) is not dict:
        raise InvalidStatusError(f"$: a status is an object, not {_json_type(status)}")
    _check_keys("$", status, _TOP_KEYS, _TOP_OPTIONAL_KEYS)
    version = status["schema_version"]
    if type(version) is not int or version != SCHEMA_VERSION:
        raise InvalidStatusError(f'$["schema_version"]: expected {SCHEMA_VERSION}, found {_show(version)}')
    selftest = status["selftest"]
    if selftest is not None and type(selftest) is not dict:
        raise InvalidStatusError(f'$["selftest"]: expected an object or null, found {_json_type(selftest)}')
    items = status["items"]
    if type(items) is not dict:
        raise InvalidStatusError(f'$["items"]: expected an object, found {_json_type(items)}')
    for item_id, record in items.items():
        path = _child('$["items"]', item_id)
        if not item_id:
            raise InvalidStatusError(f"{path}: an item ID is a non-empty string")
        _check_item(path, record)
    _check_events(status["events"])
    if "confirmed_refs" in status:
        _check_confirmed_refs(status["confirmed_refs"])


def _check_events(events: object) -> None:
    """Check ``events``: an array of objects with the keys of :class:`HarnessEvent`.

    Raises:
        InvalidStatusError: ``events`` is not an array, or an entry is not an object with
            exactly ``at``, ``kind`` and ``detail`` in the forms of :func:`record_event`.
    """
    path = '$["events"]'
    if type(events) is not list:
        raise InvalidStatusError(f"{path}: expected an array, found {_json_type(events)}")
    for index, entry in enumerate(events):
        entry_path = f"{path}[{index}]"
        if type(entry) is not dict:
            raise InvalidStatusError(f"{entry_path}: expected an object, found {_json_type(entry)}")
        _check_keys(entry_path, entry, _EVENT_KEYS)
        if not _is_timestamp(entry["at"]):
            raise InvalidStatusError(
                f"{_child(entry_path, 'at')}: expected UTC in whole seconds, like 2026-11-10T00:00:00Z,"
                f" found {_show(entry['at'])}"
            )
        if not _is_event_kind(entry["kind"]):
            raise InvalidStatusError(
                f"{_child(entry_path, 'kind')}: expected lowercase words joined by underscores,"
                f" found {_show(entry['kind'])}"
            )
        if not _is_reason(entry["detail"]):
            raise InvalidStatusError(
                f"{_child(entry_path, 'detail')}: expected a non-blank string, found {_show(entry['detail'])}"
            )


def _check_item(path: str, record: object) -> None:
    """Check one item's record: its keys, its state and history, and its field types."""
    if type(record) is not dict:
        raise InvalidStatusError(f"{path}: expected an object, found {_json_type(record)}")
    _check_keys(path, record, _ITEM_KEYS)
    state = record["state"]
    if type(state) is not str or state not in STATES:
        raise InvalidStatusError(f"{_child(path, 'state')}: unknown state {_show(state)}")
    _check_history(path, state, record["history"])
    pid = record["pid"]
    if pid is not None and (type(pid) is not int or pid < 1):
        raise InvalidStatusError(f"{_child(path, 'pid')}: expected a positive integer or null, found {_show(pid)}")
    for key in ("worktree", "branch", "base_sha", "report"):
        value = record[key]
        if value is not None and (type(value) is not str or not value):
            raise InvalidStatusError(f"{_child(path, key)}: expected a non-empty string or null, found {_show(value)}")
    observations = record["observations"]
    if observations is not None and type(observations) is not dict:
        raise InvalidStatusError(
            f"{_child(path, 'observations')}: expected an object or null, found {_json_type(observations)}"
        )
    for key in ("rerun", "rerun_skipped", "report_flags"):
        if type(record[key]) is not list:
            raise InvalidStatusError(f"{_child(path, key)}: expected an array, found {_json_type(record[key])}")
    if type(record["published"]) is not dict:
        raise InvalidStatusError(
            f"{_child(path, 'published')}: expected an object, found {_json_type(record['published'])}"
        )


def _check_history(item_path: str, state: str, history: object) -> None:
    """Check that an item's history is made of allowed edges and replays to its state.

    Args:
        item_path: Path of the item, for error messages.
        state: The item's ``state``, already known to be one of ``STATES``.
        history: The item's ``history``.

    Raises:
        InvalidStatusError: An entry is malformed, an entry does not leave the state the
            previous entry entered, an edge is not allowed, or the replay does not end in
            ``state``.
    """
    path = _child(item_path, "history")
    if type(history) is not list:
        raise InvalidStatusError(f"{path}: expected an array, found {_json_type(history)}")
    current = INITIAL_STATE
    for index, entry in enumerate(history):
        entry_path = f"{path}[{index}]"
        if type(entry) is not dict:
            raise InvalidStatusError(f"{entry_path}: expected an object, found {_json_type(entry)}")
        _check_keys(entry_path, entry, _ENTRY_KEYS)
        for key in ("from", "to"):
            if type(entry[key]) is not str or entry[key] not in STATES:
                raise InvalidStatusError(f"{_child(entry_path, key)}: unknown state {_show(entry[key])}")
        source, target = entry["from"], entry["to"]
        if source != current:
            raise InvalidStatusError(f"{entry_path}: leaves {source}, but the item was in {current}")
        if (source, target) not in ALLOWED_TRANSITIONS:
            raise InvalidStatusError(f"{entry_path}: {source} -> {target} is not an allowed transition")
        if not _is_timestamp(entry["at"]):
            raise InvalidStatusError(
                f"{_child(entry_path, 'at')}: expected UTC in whole seconds, like 2026-11-10T00:00:00Z,"
                f" found {_show(entry['at'])}"
            )
        if not _is_reason(entry["reason"]):
            raise InvalidStatusError(
                f"{_child(entry_path, 'reason')}: expected a non-blank string, found {_show(entry['reason'])}"
            )
        current = target
    if state != current:
        raise InvalidStatusError(
            f"{_child(item_path, 'state')}: is {state}, but the history leaves the item in {current}"
        )


def _check_confirmed_refs(entries: object) -> None:
    """Check ``confirmed_refs``: a list of entries of the form of :class:`ConfirmedRef`, one per ref."""
    path = '$["confirmed_refs"]'
    if type(entries) is not list:
        raise InvalidStatusError(f"{path}: expected an array, found {_json_type(entries)}")
    seen: set[tuple[str, str, str]] = set()
    for index, entry in enumerate(entries):
        here = f"{path}[{index}]"
        if type(entry) is not dict:
            raise InvalidStatusError(f"{here}: expected an object, found {_json_type(entry)}")
        _check_keys(here, entry, _CONFIRMED_KEYS)
        for key in sorted(_CONFIRMED_KEYS):
            if type(entry[key]) is not str:
                raise InvalidStatusError(f"{here}[{key!r}]: expected a string, found {_json_type(entry[key])}")
        problem = _confirmed_problem(entry)  # type: ignore[arg-type]
        if problem is not None:
            raise InvalidStatusError(f"{here}: {problem}")
        identity = (entry["repo"], entry["kind"], entry["name"])
        if identity in seen:
            raise InvalidStatusError(f"{here}: {entry['repo']} {entry['kind']} {entry['name']} appears twice")
        seen.add(identity)


def _confirmed_problem(entry: ConfirmedRef) -> str | None:
    """Tell what keeps an entry from being one of ``confirmed_refs``, or ``None``. All values are strings."""
    for key in ("repo", "name"):
        if not entry[key]:  # type: ignore[literal-required]
            return f"{key} must not be empty"
    if entry["kind"] not in _REF_KINDS:
        return f"kind must be one of {', '.join(_REF_KINDS)}, not {_show(entry['kind'])}"
    if _COMMIT_SHA.fullmatch(entry["sha"]) is None:
        return "sha must be 40 lowercase hexadecimal digits"
    if entry["kind"] == "sha" and entry["name"] != entry["sha"]:
        return "a ref of kind sha names its own commit, so name and sha must be equal"
    if not _is_timestamp(entry["at"]):
        return f"at must be UTC in whole seconds, like 2026-11-10T00:00:00Z, not {_show(entry['at'])}"
    return None


def _check_keys(
    path: str, obj: dict[str, Any], expected: frozenset[str], optional: frozenset[str] = frozenset()
) -> None:
    """Check that an object has the expected keys, and those of ``optional`` if it likes."""
    missing = sorted(expected - obj.keys())
    unknown = sorted(obj.keys() - expected - optional)
    if missing or unknown:
        problems = [f"{label} keys {keys}" for label, keys in (("missing", missing), ("unknown", unknown)) if keys]
        raise InvalidStatusError(f"{path}: {'; '.join(problems)}")


def _is_timestamp(value: object) -> bool:
    """Whether a value is a timestamp in ``TIMESTAMP_FORMAT`` that names a real moment.

    The shape is matched with ASCII digits first: ``strptime`` alone would accept fields
    of one digit, and Python's ``\\d`` would accept digits of other scripts.
    """
    if type(value) is not str or _TIMESTAMP_SHAPE.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return False
    return True


def _is_reason(value: object) -> bool:
    """Whether a value can be a history reason: a string that is not blank."""
    return type(value) is str and bool(value.strip()) and _encodable(value)


def _is_event_kind(value: object) -> bool:
    """Whether a value can be ``events[].kind``: lowercase ASCII words joined by underscores."""
    return type(value) is str and _EVENT_KIND.fullmatch(value) is not None


def _encodable(text: str) -> bool:
    """Whether a string encodes as UTF-8, that is, holds no lone surrogate."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` for ``json.loads`` that refuses an object repeating a key.

    Without it, ``json.loads`` keeps the last of the repeated values and reports nothing,
    so a damaged or hand-merged file could read as a different status.

    Raises:
        InvalidStatusError: A key appears twice in one object.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidStatusError(f"status.json repeats the key {_show(key)} in one object")
        result[key] = value
    return result


def _dependency_graph(depends_on: object) -> dict[str, tuple[str, ...]]:
    """Copy ``depends_on`` into a plain dict of tuples, checking its shape.

    Raises:
        TypeError: ``depends_on`` is not a mapping from strings to lists or tuples of
            strings.
    """
    if not isinstance(depends_on, Mapping):
        raise TypeError(f"depends_on must be a mapping, not {type(depends_on).__name__}")
    graph: dict[str, tuple[str, ...]] = {}
    for item_id, dependencies in depends_on.items():
        if not isinstance(item_id, str):
            raise TypeError(f"depends_on: the key {_show(item_id)} is not a str")
        if not isinstance(dependencies, (list, tuple)) or not all(isinstance(d, str) for d in dependencies):
            raise TypeError(
                f"depends_on[{_show(item_id)}] must be a list or tuple of item IDs, not {_show(dependencies)}"
            )
        graph[item_id] = tuple(dependencies)
    return graph


def _failed_upstream(start: str, items: Mapping[str, ItemRecord], graph: Mapping[str, Sequence[str]]) -> list[str]:
    """Collect the failed items reachable from one item through items that have not succeeded.

    Args:
        start: The item to look up from. It is not a candidate itself.
        items: The status's items.
        graph: Each item ID mapped to the IDs it depends on.

    Returns:
        The failed items found, sorted.
    """
    found: set[str] = set()
    seen = {start}
    pending = list(graph.get(start, ()))
    while pending:
        dependency = pending.pop()
        if dependency in seen:
            continue
        seen.add(dependency)
        record = items.get(dependency)
        state = None if record is None else record["state"]
        if state == SUCCEEDED:
            continue
        if state == FAILED:
            found.add(dependency)
        pending.extend(graph.get(dependency, ()))
    return sorted(found)


def _child(path: str, key: str) -> str:
    """Path of a key under an object, for error messages: ``$["items"]["c-hub"]``."""
    return f"{path}[{json.dumps(key, ensure_ascii=False)}]"


def _json_type(value: object) -> str:
    """The JSON name of a value's type (``object``, ``array``, ...), for error messages."""
    return _JSON_TYPE_NAMES.get(type(value), type(value).__name__)


def _show(value: object) -> str:
    """``repr`` of a value for an error message, cut to 60 characters."""
    try:
        text = repr(value)
    except Exception:  # an int too long to convert, a structure nested too deep: name the type instead
        return f"<{type(value).__name__}>"
    return text if len(text) <= 60 else text[:57] + "..."

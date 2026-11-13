"""Choose the Handoff items to start next: :func:`ready` and :func:`select`.

Design section 20 ("Sync_Point と tasks の対応" and "同時実行と排他"), Requirements 28.11
and 28.12 and Property 22 define the choice. This module is part of the pure core (see
``handoff/__init__.py``): the checked manifest, the status and the result of the IN-2 check
(the refs confirmed on their repository's default branch) come in as arguments, and the
choice goes out as a value. The runner (task 2.2) and ``cli.py`` (task 2.3) gather the
inputs and act on the result.

The choice has two layers.

- :func:`ready` is an item's own condition: its record is ``queued``, the record of every
  item it depends on is ``succeeded``, and every ref it requires is confirmed. A dependency
  counts whatever its Sync_Point, so an item waits for a dependency that the run does not
  name. A Hub item is ``succeeded`` once its handoff branch has its commits, before any
  merge, so a Spoke item that uses the Hub's tag or SHA waits for both the Hub item and the
  ref.
- :func:`select` adds the room to start it. Every ``running`` record of the status counts
  against ``max_concurrency``, also when the run does not name it, since the limit is on
  the runs of the whole harness. A repository has at most one item running and selected
  together. A ``running`` record of an ID that the manifest does not have (an item removed
  or renamed while it ran) counts against the limit too, and its repository is unknown, so
  while one exists nothing is selected. Records in other states that the manifest does not
  have are ignored: they hold no run, and no item of a checked manifest depends on them.

Which items: the caller names them with exactly one of ``sync_point`` (every item of one
Sync_Point) and ``item_ids`` (the items listed), as ``cli.py run`` takes ``--sync-point``
or ``--items``. Nothing selects from every item of the manifest at once.

Records: every item of the manifest must have a record in the status. The caller adds the
missing ones with :func:`handoff.state.add_item` first, as the runner has to before it can
move an item to ``running``. An item without a record is an error here, not a ``queued``
item: the rule that a new item starts in ``queued`` stays in :mod:`handoff.state`, and
:func:`handoff.state.waiting_on_failed_dependencies` also reports only items that have a
record.

Order: the named items are taken in the order of the manifest, whatever the order of
``item_ids``. Each ready item is selected while the limit leaves room and no item of its
repository is running or selected before it. No item can be added to the result without
breaking a rule, and since a repository takes one item at a time, no other choice holds
more items. In particular, when a named item is ready, no item of its repository is
running, fewer records are ``running`` than ``max_concurrency``, and no ``running`` record
is missing from the manifest, at least one item is selected (Property 22).

Every named item that is not selected comes back with its reasons, for ``cli.py plan`` and
``status``: the readiness reasons (:data:`READINESS_KINDS`) when it is not ready, otherwise
the room reasons (:data:`ROOM_KINDS`).

Agreement with :func:`handoff.state.waiting_on_failed_dependencies`: an item that it lists
is ``queued`` and reaches a ``failed`` item through items that have not succeeded, so the
first dependency on that path has not succeeded and :func:`ready` is false for the item.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal, TypeAlias, get_args

from handoff.manifest import SYNC_POINTS, Item, Manifest, RequiredRef
from handoff.state import QUEUED, RUNNING, SUCCEEDED, ItemRecord, StatusDoc, check_status

#: Why a named item was not selected. :class:`SkipReason` describes each kind.
SkipKind: TypeAlias = Literal[
    "not_queued",
    "dependency_not_succeeded",
    "ref_unconfirmed",
    "concurrency_limit",
    "repo_busy",
    "running_outside_manifest",
]

#: Every kind, in the order in which the reasons of one item are listed.
SKIP_KINDS: Final[tuple[str, ...]] = get_args(SkipKind)

#: The kinds that :func:`ready` decides. An item with one of them is not ready.
READINESS_KINDS: Final[tuple[str, ...]] = ("not_queued", "dependency_not_succeeded", "ref_unconfirmed")

#: The kinds that only :func:`select` adds. An item with one of them is ready, and there is
#: no room to start it now.
ROOM_KINDS: Final[tuple[str, ...]] = ("concurrency_limit", "repo_busy", "running_outside_manifest")


class SelectionError(ValueError):
    """The input of :func:`ready` or :func:`select` cannot be used, so nothing is selected.

    Raised when a call names no item, names items both by Sync_Point and by ID, names a
    Sync_Point that no item of the manifest has, or names an item that the manifest does not
    have or names it twice; when ``max_concurrency`` is below 1; when the manifest has an ID
    twice; and when the status has no record of an item of the manifest or of an item that
    one of them depends on.
    """


@dataclass(frozen=True, slots=True)
class SkipReason:
    """One reason why a named item was not selected.

    Attributes:
        kind: One of :data:`SKIP_KINDS`:

            - ``not_queued``: the item's record is ``running``, ``succeeded``, ``failed`` or
              ``needs-human``. It is then the only reason.
            - ``dependency_not_succeeded``: an item it depends on is not ``succeeded``. One
              reason for each such dependency, in the order of ``depends_on``.
            - ``ref_unconfirmed``: a ref it requires is not among the confirmed refs. One
              reason for each such ref, in the order of ``requires_refs``.
            - ``concurrency_limit``: the ``running`` records and the items selected before
              it reach ``max_concurrency``.
            - ``repo_busy``: an item of the same repository is ``running``, or was selected
              before it.
            - ``running_outside_manifest``: a ``running`` record has an ID that the manifest
              does not have, so the repository it runs in is unknown.

        detail: One line for the maintainer. It repeats item IDs, repository names and refs
            of the manifest, so it belongs in local output, not in a tracked file.
    """

    kind: SkipKind
    detail: str


@dataclass(frozen=True, slots=True)
class NotSelected:
    """A named item that :func:`select` did not select, with every reason that applies.

    Attributes:
        item_id: The item.
        reasons: At least one, in the order of :data:`SKIP_KINDS`. Only readiness reasons
            when the item is not ready; only room reasons when it is ready.
    """

    item_id: str
    reasons: tuple[SkipReason, ...]


@dataclass(frozen=True, slots=True)
class Selection:
    """The result of :func:`select`.

    Attributes:
        selected: The items to start now, in the order of the manifest. The runner starts
            them in this order.
        not_selected: Every other named item, in the order of the manifest.
        running: Every ``running`` record that counted against ``max_concurrency``: the
            items of the manifest, in its order, then the IDs that the manifest does not
            have, sorted.
    """

    selected: tuple[str, ...]
    not_selected: tuple[NotSelected, ...]
    running: tuple[str, ...]


def ready(item: Item, status: StatusDoc, *, confirmed_refs: Iterable[RequiredRef]) -> bool:
    """Tell whether an item may start as far as its own conditions go.

    :func:`select` adds the limit and the one-item-per-repository rule to this condition.

    Args:
        item: An item of a checked manifest.
        status: A status that passes :func:`handoff.state.check_status`, with a record of the
            item and of every item it depends on.
        confirmed_refs: The refs that the IN-2 check confirmed on their repository's default
            branch. Any collection of :class:`handoff.manifest.RequiredRef`.

    Returns:
        ``True`` when the item's record is ``queued``, the record of every item in its
        ``depends_on`` is ``succeeded``, and every ref of its ``requires_refs`` is in
        ``confirmed_refs``.

    Raises:
        TypeError: ``item`` is not an :class:`handoff.manifest.Item`, or ``confirmed_refs``
            is a single string or holds something other than a ``RequiredRef``.
        handoff.state.InvalidStatusError: ``status`` is not a status.
        SelectionError: The status has no record of the item or of an item it depends on.
    """
    if not isinstance(item, Item):
        raise TypeError(f"item must be an Item of a checked manifest, not {type(item).__name__}")
    check_status(status)
    refs = _confirmed_refs(confirmed_refs)
    return not _readiness_reasons(item, status["items"], refs)


def select(
    manifest: Manifest,
    status: StatusDoc,
    *,
    confirmed_refs: Iterable[RequiredRef],
    max_concurrency: int,
    sync_point: str | None = None,
    item_ids: Iterable[str] | None = None,
) -> Selection:
    """Choose which of the named items to start now.

    The module docstring gives the rules. The arguments are not changed.

    Args:
        manifest: The manifest that :func:`handoff.manifest.parse_manifest` returned.
        status: A status that passes :func:`handoff.state.check_status`, with a record of
            every item of ``manifest``.
        confirmed_refs: The refs that the IN-2 check confirmed on their repository's default
            branch. Any collection of :class:`handoff.manifest.RequiredRef`.
        max_concurrency: The most items running at the same time, ``max_concurrency`` of
            the configuration. 1 or more.
        sync_point: Name the items of this Sync_Point (``--sync-point``). Give this or
            ``item_ids``, not both.
        item_ids: Name these items (``--items``): one or more IDs of the manifest, each
            once, in any order.

    Returns:
        The items to start now, every other named item with its reasons, and the
        ``running`` records that counted against the limit.

    Raises:
        TypeError: ``manifest`` is not a :class:`handoff.manifest.Manifest`;
            ``max_concurrency`` is not an integer (``True`` is refused); ``sync_point`` is
            not a string; or ``item_ids`` or ``confirmed_refs`` is a single string or holds
            an entry of the wrong type.
        handoff.state.InvalidStatusError: ``status`` is not a status.
        SelectionError: The input cannot be used (see :class:`SelectionError`).
    """
    if not isinstance(manifest, Manifest):
        raise TypeError(f"manifest must be a Manifest from parse_manifest, not {type(manifest).__name__}")
    check_status(status)
    refs = _confirmed_refs(confirmed_refs)
    limit = _limit(max_concurrency)
    records = status["items"]
    _check_records(manifest, records)
    named = _named_items(manifest, sync_point, item_ids)

    listed = {item.id for item in manifest.items}
    running: list[str] = []
    busy: dict[str, str] = {}
    for item in manifest.items:
        if records[item.id]["state"] == RUNNING:
            running.append(item.id)
            busy.setdefault(item.repo, item.id)
    outside = sorted(
        item_id for item_id, record in records.items() if item_id not in listed and record["state"] == RUNNING
    )
    running.extend(outside)

    selected: list[str] = []
    claimed: dict[str, str] = {}
    not_selected: list[NotSelected] = []
    for item in named:
        reasons = _readiness_reasons(item, records, refs)
        if not reasons:
            reasons = _room_reasons(item, len(running), len(selected), limit, busy, claimed, outside)
        if reasons:
            not_selected.append(NotSelected(item.id, reasons))
            continue
        selected.append(item.id)
        claimed[item.repo] = item.id
    return Selection(selected=tuple(selected), not_selected=tuple(not_selected), running=tuple(running))


def _readiness_reasons(
    item: Item, records: Mapping[str, ItemRecord], refs: frozenset[RequiredRef]
) -> tuple[SkipReason, ...]:
    """List what keeps an item from being ready. Empty when it is ready.

    Args:
        item: The item.
        records: The ``items`` of a checked status.
        refs: The confirmed refs.

    Returns:
        ``not_queued`` alone when the item is not ``queued``; otherwise a reason for each
        dependency that is not ``succeeded`` and for each ref that is not confirmed.

    Raises:
        SelectionError: ``records`` has no record of the item or of an item it depends on.
    """
    state = _record(records, item.id, item.id)["state"]
    if state != QUEUED:
        return (SkipReason("not_queued", f"{item.id} is {state}, not {QUEUED}"),)
    reasons: list[SkipReason] = []
    for dependency in item.depends_on:
        dependency_state = _record(records, dependency, item.id)["state"]
        if dependency_state != SUCCEEDED:
            reasons.append(
                SkipReason(
                    "dependency_not_succeeded",
                    f"{item.id} depends on {dependency}, which is {dependency_state}, not {SUCCEEDED}",
                )
            )
    for ref in item.requires_refs:
        if ref not in refs:
            reasons.append(
                SkipReason(
                    "ref_unconfirmed",
                    f"{item.id} requires the {ref.kind} {ref.name} of {ref.repo}, "
                    "which is not confirmed on that repository's default branch",
                )
            )
    return tuple(reasons)


def _room_reasons(
    item: Item,
    running: int,
    selected: int,
    limit: int,
    busy: Mapping[str, str],
    claimed: Mapping[str, str],
    outside: Sequence[str],
) -> tuple[SkipReason, ...]:
    """List what keeps a ready item from starting now. Empty when there is room.

    Args:
        item: A ready item.
        running: The number of ``running`` records, those outside the manifest included.
        selected: The number of items selected so far in this call.
        limit: ``max_concurrency``.
        busy: Each repository that has a ``running`` item of the manifest, mapped to the
            first such item.
        claimed: Each repository of an item selected so far, mapped to that item.
        outside: The ``running`` IDs that the manifest does not have, sorted.

    Returns:
        The room reasons that apply, in the order of :data:`SKIP_KINDS`.
    """
    reasons: list[SkipReason] = []
    if running + selected >= limit:
        reasons.append(
            SkipReason(
                "concurrency_limit",
                f"{running} running and {selected} selected before {item.id} reach max_concurrency {limit}",
            )
        )
    if item.repo in busy:
        reasons.append(SkipReason("repo_busy", f"{busy[item.repo]} of the same repository {item.repo} is running"))
    elif item.repo in claimed:
        reasons.append(
            SkipReason("repo_busy", f"{claimed[item.repo]} of the same repository {item.repo} is selected first")
        )
    if outside:
        reasons.append(
            SkipReason(
                "running_outside_manifest",
                f"{', '.join(outside)} is running but not in the manifest, so the repository it runs in is "
                "unknown; nothing starts until it ends",
            )
        )
    return tuple(reasons)


def _record(records: Mapping[str, ItemRecord], item_id: str, needed_by: str) -> ItemRecord:
    """Return an item's record, or refuse to guess its state.

    Args:
        records: The ``items`` of a checked status.
        item_id: The item whose record is needed.
        needed_by: The item being judged, for the message: ``item_id`` itself or an item that
            depends on it.

    Raises:
        SelectionError: ``records`` has no record of ``item_id``.
    """
    record = records.get(item_id)
    if record is None:
        whose = item_id if item_id == needed_by else f"{item_id} (a dependency of {needed_by})"
        raise SelectionError(f"the status has no record of {whose}; add it with state.add_item first")
    return record


def _check_records(manifest: Manifest, records: Mapping[str, ItemRecord]) -> None:
    """Require one item per ID in the manifest and a record of each in the status.

    Raises:
        SelectionError: An ID appears twice in the manifest (it cannot come from
            ``parse_manifest``), or the status has no record of an item of the manifest.
    """
    seen: set[str] = set()
    repeated: dict[str, None] = {}
    for item in manifest.items:
        if item.id in seen:
            repeated[item.id] = None
        seen.add(item.id)
    if repeated:
        raise SelectionError(
            f"the manifest has {', '.join(repeated)} more than once; pass the manifest that parse_manifest returned"
        )
    missing = [item.id for item in manifest.items if item.id not in records]
    if missing:
        raise SelectionError(
            f"the status has no record of {', '.join(missing)}; add every item of the manifest with "
            "state.add_item before selecting"
        )


def _named_items(manifest: Manifest, sync_point: str | None, item_ids: Iterable[str] | None) -> tuple[Item, ...]:
    """Return the items a call names, in the order of the manifest.

    Raises:
        TypeError: ``sync_point`` is not a string, or ``item_ids`` is a single string or holds
            something other than a string.
        SelectionError: Neither or both of ``sync_point`` and ``item_ids`` is given;
            ``sync_point`` is not one of :data:`handoff.manifest.SYNC_POINTS` or no item has
            it; or ``item_ids`` is empty, repeats an ID, or holds an ID that the manifest
            does not have.
    """
    if sync_point is None and item_ids is None:
        raise SelectionError(
            "name the items with sync_point or item_ids; nothing selects from every item of the manifest"
        )
    if sync_point is not None and item_ids is not None:
        raise SelectionError("name the items with sync_point or with item_ids, not both")
    if sync_point is not None:
        if not isinstance(sync_point, str):
            raise TypeError(f"sync_point must be a str, not {type(sync_point).__name__}")
        if sync_point not in SYNC_POINTS:
            raise SelectionError(f"{sync_point!r} is not a Sync_Point; the values are {', '.join(SYNC_POINTS)}")
        named = tuple(item for item in manifest.items if item.sync_point == sync_point)
        if not named:
            raise SelectionError(f"no item of the manifest has sync_point {sync_point!r}")
        return named

    if isinstance(item_ids, (str, bytes)) or not isinstance(item_ids, Iterable):
        raise TypeError("item_ids must be a collection of item IDs, not a single string")
    ids = tuple(item_ids)
    for entry in ids:
        if not isinstance(entry, str):
            raise TypeError(f"every entry of item_ids must be a str, not {type(entry).__name__}")
    if not ids:
        raise SelectionError("item_ids names no item")
    seen: set[str] = set()
    repeated: dict[str, None] = {}
    for item_id in ids:
        if item_id in seen:
            repeated[item_id] = None
        seen.add(item_id)
    listed = {item.id for item in manifest.items}
    unknown = [item_id for item_id in dict.fromkeys(ids) if item_id not in listed]
    problems: list[str] = []
    if repeated:
        problems.append(f"item_ids lists {', '.join(map(repr, repeated))} more than once")
    if unknown:
        problems.append(f"the manifest has no item {', '.join(map(repr, unknown))}")
    if problems:
        raise SelectionError("; ".join(problems))
    return tuple(item for item in manifest.items if item.id in seen)


def _confirmed_refs(value: Iterable[RequiredRef]) -> frozenset[RequiredRef]:
    """Check the confirmed refs and return them as a set.

    Raises:
        TypeError: ``value`` is a single string or not iterable, or holds something other
            than a :class:`handoff.manifest.RequiredRef`. A set of plain tuples would leave
            every ref unconfirmed without a word.
    """
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError(f"confirmed_refs must be a collection of RequiredRef, not {type(value).__name__}")
    refs = tuple(value)
    for ref in refs:
        if not isinstance(ref, RequiredRef):
            raise TypeError(f"every entry of confirmed_refs must be a RequiredRef, not {type(ref).__name__}")
    return frozenset(refs)


def _limit(value: int) -> int:
    """Check ``max_concurrency``.

    Raises:
        TypeError: ``value`` is not an integer, or is ``True`` or ``False``.
        SelectionError: ``value`` is below 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"max_concurrency must be an int, not {type(value).__name__}")
    if value < 1:
        raise SelectionError(f"max_concurrency must be 1 or more, not {value}")
    return value

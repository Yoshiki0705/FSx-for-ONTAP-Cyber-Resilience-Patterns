"""A pure mock of the GitHub Issue store for the supply-chain planner tests (task 9.1).

The store is an immutable value. Every operation returns a new store and never touches the
network, the file system or the clock, so a property test can apply a plan, apply part of a plan,
plan again and compare.

The operations are those of the design: create, update, close, reopen, and a search by the marker
fields. A real marker is the first line of the body (``issue_body``, task 9.4); this fake keeps the
marker's fields (repo, kind, vuln_id) next to the body and searches them, so it does not parse
bodies. Where a test needs the state block of a body, :func:`to_managed_issues` takes a
``parse_body`` callable (the parser of 9.4) and falls back to the state block the issue had before.

Behavior chosen to match GitHub where the planner could trip on it:

- ``create`` always makes a new issue, even if one with the same marker exists (GitHub does not
  deduplicate). The planner must avoid that; a test finds the duplicates with :meth:`IssueStore.find`.
- Issue numbers are unique per store and increase (``max + 1``).
- ``update``, ``close`` and ``reopen`` of a number that does not exist raise
  :class:`IssueNotFoundError` (HTTP 404). ``close`` of a closed issue and ``reopen`` of an open one
  succeed and change nothing else.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from supply_chain.models import ManagedIssue, Plan, Repo

if TYPE_CHECKING:
    from supply_chain.models import CloseReason, IssueAction, IssueKind, IssueState


class IssueNotFoundError(KeyError):
    """The action names an issue number the store does not hold (GitHub answers 404)."""


@dataclass(frozen=True, slots=True)
class StoredIssue:
    """One issue in the store.

    Attributes:
        repo: The repository.
        number: The issue number (the store's, not necessarily the repository's).
        kind: The marker's kind.
        vuln_id: The marker's vulnerability identifier; ``None`` for summary and failure issues.
        state: ``open`` or ``closed``.
        body: The body last written by ``create`` or ``update``; ``None`` for an issue that came
            from :meth:`IssueStore.from_managed`.
        body_state: The state block known for the issue (kept from the starting
            ``ManagedIssue``; a written body replaces it with ``None``).
        close_reason: The reason of the last ``close``; ``None`` when open.
    """

    repo: Repo
    number: int
    kind: IssueKind
    vuln_id: str | None
    state: IssueState
    body: str | None
    body_state: Mapping[str, object] | None
    close_reason: CloseReason | None = None


@dataclass(frozen=True, slots=True)
class IssueStore:
    """An immutable collection of issues."""

    issues: tuple[StoredIssue, ...] = ()

    @classmethod
    def from_managed(cls, managed: Iterable[ManagedIssue]) -> IssueStore:
        """Builds a store from the issues of a ``PlanInputs`` (``failure`` issues included)."""
        return cls(
            tuple(StoredIssue(m.repo, m.number, m.kind, m.vuln_id, m.state, None, m.body_state, None) for m in managed)
        )

    def get(self, repo: Repo, number: int) -> StoredIssue:
        """Returns the issue ``number`` of ``repo``.

        Raises:
            IssueNotFoundError: If the store holds no such issue.
        """
        for issue in self.issues:
            if issue.repo == repo and issue.number == number:
                return issue
        raise IssueNotFoundError(f"{repo.owner}/{repo.name}#{number}")

    def find(
        self,
        repo: Repo | None = None,
        kind: str | None = None,
        vuln_id: str | None = None,
        state: str | None = None,
    ) -> tuple[StoredIssue, ...]:
        """Searches by marker fields; a field left as ``None`` matches anything.

        ``vuln_id=None`` cannot be searched for (it means "any"); use ``kind="summary"``.
        """
        return tuple(
            i
            for i in self.issues
            if (repo is None or i.repo == repo)
            and (kind is None or i.kind == kind)
            and (vuln_id is None or i.vuln_id == vuln_id)
            and (state is None or i.state == state)
        )

    def _next_number(self) -> int:
        return max((i.number for i in self.issues), default=0) + 1

    def _replace(self, old: StoredIssue, new: StoredIssue) -> IssueStore:
        return IssueStore(tuple(new if i is old else i for i in self.issues))

    def apply_action(self, action: IssueAction) -> IssueStore:
        """Applies one ``IssueAction`` and returns the new store.

        Raises:
            IssueNotFoundError: For ``update``, ``close`` and ``reopen`` of a missing number.
            ValueError: For an action without a number where one is required, or an unknown op.
        """
        if action.op == "create":
            issue = StoredIssue(
                repo=action.repo,
                number=self._next_number(),
                kind=action.kind,
                vuln_id=action.vuln_id,
                state="open",
                body=action.body,
                body_state=None,
            )
            return IssueStore((*self.issues, issue))
        if action.number is None:
            raise ValueError(f"{action.op} needs an issue number")
        old = self.get(action.repo, action.number)
        if action.op == "update":
            return self._replace(old, replace(old, body=action.body, body_state=None))
        if action.op == "close":
            return self._replace(old, replace(old, state="closed", close_reason=action.close_reason))
        if action.op == "reopen":
            return self._replace(old, replace(old, state="open", close_reason=None))
        raise ValueError(f"unknown op {action.op!r}")


def apply(store: IssueStore, plan: Plan | Iterable[IssueAction]) -> IssueStore:
    """Applies every action of ``plan`` (or of an iterable of actions) in order.

    Args:
        store: The starting store.
        plan: A ``Plan`` or the actions themselves.

    Returns:
        The store after all actions. The input store is unchanged.
    """
    actions = plan.actions if isinstance(plan, Plan) else tuple(plan)
    for action in actions:
        store = store.apply_action(action)
    return store


def apply_subset(store: IssueStore, plan: Plan | Iterable[IssueAction], indexes: Collection[int]) -> IssueStore:
    """Applies only the actions at ``indexes``, in plan order (a run where some API calls failed).

    Args:
        store: The starting store.
        plan: A ``Plan`` or the actions themselves.
        indexes: Positions in ``actions``. Positions outside the range are ignored.

    Returns:
        The store after the chosen actions.
    """
    actions = plan.actions if isinstance(plan, Plan) else tuple(plan)
    for position, action in enumerate(actions):
        if position in indexes:
            store = store.apply_action(action)
    return store


def to_managed_issues(
    store: IssueStore, parse_body: Callable[[str], Mapping[str, object] | None] | None = None
) -> tuple[ManagedIssue, ...]:
    """Reads the store back as ``ManagedIssue`` values, as the next run would see them.

    Args:
        store: The store.
        parse_body: Turns a written body into its state block (the parser of task 9.4). Without
            it, an issue whose body was written has ``body_state=None``.

    Returns:
        The issues in store order.
    """
    out = []
    for i in store.issues:
        state = parse_body(i.body) if parse_body is not None and i.body is not None else i.body_state
        out.append(ManagedIssue(i.repo, i.number, i.kind, i.vuln_id, i.state, state))
    return tuple(out)

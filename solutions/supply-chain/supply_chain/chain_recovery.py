"""Detect, isolate and reconnect a forked run-record chain (T4-R3-04). Candidate for ``supply_chain/chain_recovery.py``.

A month's chain is followed from ``prev_record_sha256``. When two records name the same predecessor (a write that raced
another, or one made by hand), the month has two tips. ``previous_record_sha256`` then raises, so every later write and
the month-end seal fail, and ``verify_chain`` reports ``fork`` for as long as both records exist. Deleting or editing a
record would end the failure and would also destroy what the chain is for. This module gives the maintainer a third way:
a **decision recorded in the repository** that names the abandoned tip. The record stays in the chain's directory; every
reader (writer, seal, watchdog) treats it as outside the chain from then on.

Three steps, each a function and a subcommand of :func:`main`:

* **detect**: list the months with two or more tips. Exit 1 when one is not covered by the ledger.
* **isolate**: add ``{month, abandoned_record_sha256, decision}`` to the ledger (``docs/agent/supply-chain-chain-ack.json``).
  The abandoned record must be a tip (no record names it as predecessor) of a month that has another tip. A record
  with descendants is refused: the chain would lose them.
* **reconnect**: with the ledger applied, the month must have exactly one tip and ``verify_chain`` must report nothing.
  It prints the SHA-256 that the next record names as ``prev_record_sha256``.

Pure functions over ``(path, text)`` pairs plus a thin CLI. The ledger is written by a person in a pull request; this
module never deletes a record.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from supply_chain import run_record as rr

LEDGER_SCHEMA_VERSION = 1
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MONTH = re.compile(r"[0-9]{4}-[0-9]{2}")
#: Where the maintainer decided it: an Issue or a pull request of the repository, by number or by URL. A free text
#: ("ok", "see chat") cannot be followed up, so it is refused (T12-R4-03).
_DECISION = re.compile(
    r"(?:Issue|PR) #?[0-9]{1,9}|https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:issues|pull)/[0-9]{1,9}"
)


class LedgerError(ValueError):
    """The ledger text is malformed or names a record that cannot be abandoned."""


@dataclass(frozen=True, slots=True)
class AcceptedFork:
    """One decision: the record of ``month`` with this SHA-256 is outside the chain from now on.

    Attributes:
        month: ``YYYY-MM``.
        abandoned_record_sha256: The SHA-256 of the text of the abandoned tip.
        decision: Where the maintainer decided it: ``Issue <n>``, ``PR <n>`` or the URL of either.
    """

    month: str
    abandoned_record_sha256: str
    decision: str


@dataclass(frozen=True, slots=True)
class MonthTips:
    """The tips of one month: records that no other record of the month names as predecessor."""

    month: str
    tips: tuple[tuple[str, str], ...]  # (sha256, path), sorted by path


def parse_ledger(text: str) -> tuple[AcceptedFork, ...]:
    """Read the ledger.

    Raises:
        LedgerError: Not JSON, a wrong schema version, an entry with a bad month, SHA-256 or decision, or a duplicate.
    """
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise LedgerError(f"the ledger is not JSON: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != LEDGER_SCHEMA_VERSION:
        raise LedgerError(f"schema_version must be {LEDGER_SCHEMA_VERSION}")
    entries = raw.get("accepted_forks")
    if not isinstance(entries, list):
        raise LedgerError("accepted_forks must be a list")
    found: list[AcceptedFork] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"month", "abandoned_record_sha256", "decision"}:
            raise LedgerError(f"accepted_forks[{index}] must have exactly month, abandoned_record_sha256, decision")
        month, digest, decision = entry["month"], entry["abandoned_record_sha256"], entry["decision"]
        if not (isinstance(month, str) and _MONTH.fullmatch(month)):
            raise LedgerError(f"accepted_forks[{index}].month must be YYYY-MM")
        if not (isinstance(digest, str) and _HEX64.fullmatch(digest)):
            raise LedgerError(f"accepted_forks[{index}].abandoned_record_sha256 must be 64 lowercase hex digits")
        if not (isinstance(decision, str) and _DECISION.fullmatch(decision)):
            raise LedgerError(
                f"accepted_forks[{index}].decision must name an Issue or a pull request (for example 'Issue 123' or its URL)"
            )
        found.append(AcceptedFork(month, digest, decision))
    if len({fork.abandoned_record_sha256 for fork in found}) != len(found):
        raise LedgerError("a record is listed twice")
    return tuple(found)


def render_ledger(forks: Iterable[AcceptedFork]) -> str:
    """The ledger text, sorted, one entry per line group, ending in a newline."""
    entries = [
        {"month": f.month, "abandoned_record_sha256": f.abandoned_record_sha256, "decision": f.decision}
        for f in sorted(forks, key=lambda f: (f.month, f.abandoned_record_sha256))
    ]
    return json.dumps({"schema_version": LEDGER_SCHEMA_VERSION, "accepted_forks": entries}, indent=2) + "\n"


def _month_name(path: str) -> str:
    """``YYYY-MM`` of ``runs/<YYYY>/<MM>/<file>``."""
    parts = path.split("/")
    return f"{parts[-3]}-{parts[-2]}" if len(parts) >= 3 else path


def month_tips(entries: Iterable[tuple[str, str]]) -> tuple[MonthTips, ...]:
    """The tips of every month that has two or more (version 2 records only; a record that cannot be read is skipped)."""
    months: dict[str, list[tuple[rr.RunRecord, str, str]]] = {}
    for path, text in entries:
        try:
            record = rr.from_json(text)
        except rr.RunRecordError:
            continue
        months.setdefault(rr.month_of(path), []).append((record, path, text))
    result: list[MonthTips] = []
    for key in sorted(months):
        items = months[key]
        named = {record.prev_record_sha256 for record, _p, _t in items if record.prev_record_sha256 is not None}
        tips = sorted(
            ((rr.sha256_text(text), path) for _r, path, text in items if rr.sha256_text(text) not in named),
            key=lambda t: t[1],
        )
        if len(tips) >= 2:
            result.append(MonthTips(_month_name(key + "/x"), tuple(tips)))
    return tuple(result)


def _problems(entries: Sequence[tuple[str, str]], accepted: Sequence[AcceptedFork]) -> list[str]:
    """Why a decision of the ledger cannot stand: unknown record, a record with descendants, a month without a fork."""
    by_hash = {rr.sha256_text(text): path for path, text in entries}
    forked = {mt.month: {sha for sha, _p in mt.tips} for mt in month_tips(entries)}
    problems: list[str] = []
    for fork in accepted:
        path = by_hash.get(fork.abandoned_record_sha256)
        if path is None:
            problems.append(f"{fork.abandoned_record_sha256}: no record has this SHA-256")
        elif _month_name(rr.month_of(path) + "/x") != fork.month:
            problems.append(f"{fork.abandoned_record_sha256}: the record is in another month than {fork.month}")
        elif fork.abandoned_record_sha256 not in forked.get(fork.month, set()):
            problems.append(
                f"{fork.abandoned_record_sha256}: it is not one of two or more tips of {fork.month} "
                "(a record names it as predecessor, or the month has no fork); the chain would lose its descendants"
            )
    # One tip must stay: each entry is valid alone, but abandoning every tip of a month leaves the chain with no
    # tip and the records out of the seal (T12-R4-03).
    gone_by_month: dict[str, set[str]] = {}
    for fork in accepted:
        gone_by_month.setdefault(fork.month, set()).add(fork.abandoned_record_sha256)
    for month, tips in sorted(forked.items()):
        if tips and tips <= gone_by_month.get(month, set()):
            problems.append(f"{month}: every tip is abandoned; one tip must stay in the chain")
    return problems


def effective_entries(
    entries: Iterable[tuple[str, str]], accepted: Sequence[AcceptedFork]
) -> tuple[list[tuple[str, str]], list[str]]:
    """The entries that the chain functions should read: without the abandoned tips.

    Returns:
        ``(kept, problems)``. When ``problems`` is not empty the ledger is wrong and the caller must fail, not write.
    """
    listed = list(entries)
    problems = _problems(listed, accepted)
    gone = {fork.abandoned_record_sha256 for fork in accepted}
    return [(p, t) for p, t in listed if rr.sha256_text(t) not in gone], problems


def isolate(entries: Iterable[tuple[str, str]], ledger_text: str, *, abandon: str, decision: str) -> str:
    """The ledger text with the abandoned tip added.

    Raises:
        LedgerError: The record cannot be abandoned (see :func:`_problems`), or the decision text is not acceptable.
    """
    current = list(parse_ledger(ledger_text))
    listed = list(entries)
    by_hash = {rr.sha256_text(text): path for path, text in listed}
    if abandon not in by_hash:
        raise LedgerError(f"{abandon}: no record has this SHA-256")
    new = AcceptedFork(_month_name(rr.month_of(by_hash[abandon]) + "/x"), abandon, decision)
    parse_ledger(render_ledger([*current, new]))  # validates the shapes
    problems = _problems(listed, [*current, new])
    if problems:
        raise LedgerError("; ".join(problems))
    return render_ledger([*current, new])


@dataclass(frozen=True, slots=True)
class Reconnect:
    """The state after the ledger is applied."""

    next_prev_record_sha256: str | None
    problems: tuple[str, ...]


def reconnect(entries: Iterable[tuple[str, str]], accepted: Sequence[AcceptedFork], month: str) -> Reconnect:
    """Whether ``month`` can take a new record, and the SHA-256 that the next record names.

    Problems: a ledger entry that cannot stand, a month that still has two tips, and a break that ``verify_chain`` finds
    in the records that remain.
    """
    kept, problems = effective_entries(entries, accepted)
    in_month = [(p, t) for p, t in kept if _month_name(rr.month_of(p) + "/x") == month]
    out: list[str] = list(problems)
    for brk in rr.verify_chain(kept):
        out.append(f"{brk.path}: {brk.reason}")
    try:
        tip = rr.previous_record_sha256(text for _p, text in in_month)
    except rr.RunRecordError as exc:
        out.append(str(exc))
        tip = None
    return Reconnect(tip, tuple(out))


def _read(runs_dir: Path) -> list[tuple[str, str]]:
    """``(path relative to the parent of runs/, text)`` of every record file, as ``watchdog_cli`` reads them."""
    return [
        (p.relative_to(runs_dir.parent).as_posix(), p.read_text(encoding="utf-8"))
        for p in sorted(runs_dir.rglob("*.json"))
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """``detect``, ``isolate`` and ``reconnect``; the exit code is 1 when something needs a person."""
    parser = argparse.ArgumentParser(prog="chain_recovery")
    parser.add_argument("--runs-dir", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("detect")
    iso = sub.add_parser("isolate")
    iso.add_argument("--abandon", required=True, help="SHA-256 of the record to leave out of the chain")
    iso.add_argument(
        "--decision", required=True, help="where the maintainer decided it: 'Issue <n>', 'PR <n>' or a GitHub URL"
    )
    rec = sub.add_parser("reconnect")
    rec.add_argument("--month", required=True, help="YYYY-MM")
    args = parser.parse_args(argv)
    entries = _read(args.runs_dir)
    ledger_text = args.ledger.read_text(encoding="utf-8") if args.ledger.exists() else render_ledger(())
    if args.command == "detect":
        accepted = {f.abandoned_record_sha256 for f in parse_ledger(ledger_text)}
        open_forks = 0
        for mt in month_tips(entries):
            for sha, path in mt.tips:
                note = "accepted as abandoned" if sha in accepted else "tip"
                sys.stdout.write(f"{mt.month} {sha} {path} {note}\n")
            if not any(sha in accepted for sha, _p in mt.tips):
                open_forks += 1
        sys.stdout.write(f"months with an open fork: {open_forks}\n")
        return 1 if open_forks else 0
    if args.command == "isolate":
        try:
            args.ledger.write_text(
                isolate(entries, ledger_text, abandon=args.abandon, decision=args.decision), encoding="utf-8"
            )
        except LedgerError as exc:
            sys.stderr.write(f"not isolated: {exc}\n")
            return 1
        sys.stdout.write(
            f"{args.ledger}: added {args.abandon}. Commit the ledger in a pull request; no record was changed.\n"
        )
        return 0
    result = reconnect(entries, parse_ledger(ledger_text), args.month)
    for problem in result.problems:
        sys.stderr.write(f"{problem}\n")
    if result.problems or result.next_prev_record_sha256 is None:
        return 1
    sys.stdout.write(f"{result.next_prev_record_sha256}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

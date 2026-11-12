"""Issue body rendering and marker parsing (pure).

A body is: the marker on line 1, a machine-readable state block
(a ```json fence tagged ``supply-chain-aggregator-state``), and a human table.
The marker identifies Issues the Aggregator owns (Requirement 8.6); the state
block is what the next run compares against (Requirement 8.2).

Rendering is deterministic: the same inputs give the same bytes. Bodies are
cut to ``MAX_BODY_CHARS`` characters and the cut count is written in the body
(Requirement 8.3, Q-18). This module performs no I/O.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from supply_chain.models import Component, Repo, Severity
from supply_chain.threshold import MALICIOUS_PREFIX

MARKER_PREFIX = "supply-chain-aggregator:v1"
STATE_FENCE_TAG = "supply-chain-aggregator-state"
MAX_BODY_CHARS = 50_000
MAX_COMPONENTS = 200
KINDS = ("finding", "summary", "failure")
NOT_FIXED_YET = "未判明"
EPSS_MISSING = "未取得"
MALICIOUS_FIXED_TEXT = "該当なし（パッケージを取り除くか、記録に載っていないバージョンに変える）"
# Keys left out when comparing a new state with the previous one (design section 4).
VOLATILE_KEYS = frozenset({"history", "last_run_id"})

_MARKER_RE = re.compile(
    r"^<!-- supply-chain-aggregator:v1 kind=(\w+)(?: repo=(\S+))?(?: vuln=(\S+))?(?: aliases=(\S+))? -->$"
)
_STATE_RE = re.compile(r"^```json " + re.escape(STATE_FENCE_TAG) + r"\n(.*?)\n```$", re.DOTALL | re.MULTILINE)


@dataclass(frozen=True, slots=True)
class Marker:
    """The parsed first line of a managed Issue body."""

    kind: str
    repo: Repo | None
    vuln_id: str | None
    aliases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One run that opened, updated, closed or reopened the Issue (Requirement 26.4)."""

    op: str
    run_id: str
    at: datetime


@dataclass(frozen=True, slots=True)
class FindingIssue:
    """Everything the body of a finding Issue shows.

    ``kev`` is ``(dateAdded, knownRansomwareCampaignUse)`` or ``None`` when the
    vulnerability is not listed (or KEV was not obtained). ``epss`` is
    ``(score, date, model_version)`` or ``None`` when not obtained. Datetimes
    are UTC (see ``models``).
    """

    repo: Repo
    vuln_id: str
    aliases: tuple[str, ...]
    components: tuple[Component, ...]
    cvss_severity: Severity | None
    kev: tuple[date, bool | None] | None
    epss: tuple[str, date, str] | None
    fixed_version: str | None
    origin_at: datetime
    origin_is_date_only: bool
    detected_at: datetime
    opened_at: datetime
    due_at: datetime
    last_run_id: str
    history: tuple[HistoryEntry, ...]


@dataclass(frozen=True, slots=True)
class SummaryEntry:
    """One Finding listed in a summary Issue (over the per-run opening limit)."""

    vuln_id: str
    cvss_severity: Severity | None
    kev_listed: bool
    malicious: bool


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_malicious(vuln_id: str, aliases: Sequence[str]) -> bool:
    return any(i.startswith(MALICIOUS_PREFIX) for i in (vuln_id, *aliases))


def _check_token(label: str, value: str) -> str:
    if not value or re.search(r"\s", value):
        raise ValueError(f"{label} must be a non-empty string without whitespace: {value!r}")
    return value


def render_marker(kind: str, repo: Repo, vuln_id: str | None = None, aliases: Sequence[str] = ()) -> str:
    """Renders the marker line.

    Args:
        kind: ``finding``, ``summary`` or ``failure``.
        repo: Repository that holds the Issue.
        vuln_id: Representative identifier (finding only).
        aliases: Other identifiers of the same record; sorted, deduplicated, and
            without ``vuln_id``. Joined with a comma.

    Returns:
        The marker line, without a trailing newline.

    Raises:
        ValueError: If ``kind`` is unknown or a value has whitespace or (for an alias) a comma.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown kind: {kind!r}")
    parts = [f"<!-- {MARKER_PREFIX} kind={kind}", f"repo={_check_token('repo', f'{repo.owner}/{repo.name}')}"]
    if vuln_id is not None:
        parts.append(f"vuln={_check_token('vuln_id', vuln_id)}")
        extra = sorted({_check_token("alias", a) for a in aliases} - {vuln_id})
        if any("," in a for a in extra):
            raise ValueError("alias must not contain a comma")
        if extra:
            parts.append(f"aliases={','.join(extra)}")
    return " ".join(parts) + " -->"


def parse_marker(body: str | None) -> Marker | None:
    """Parses the marker; the pattern is applied to line 1 only.

    Args:
        body: Issue body, or ``None``.

    Returns:
        The marker, or ``None`` when line 1 is not a marker (or ``kind`` is unknown).
    """
    if not body:
        return None
    first = body.split("\n", 1)[0].removesuffix("\r")
    m = _MARKER_RE.fullmatch(first)
    if m is None or m.group(1) not in KINDS:
        return None
    repo = None
    if m.group(2) is not None:
        owner, sep, name = m.group(2).partition("/")
        if not sep or not owner or not name or "/" in name:
            return None
        repo = Repo(owner, name)
    aliases = tuple(m.group(4).split(",")) if m.group(4) else ()
    return Marker(m.group(1), repo, m.group(3), aliases)


def is_managed(marker: Marker | None, issue_repo: Repo) -> bool:
    """Tells whether an Issue with this marker is the Aggregator's, in ``issue_repo``.

    A marker without ``repo``, or whose ``repo`` differs from the repository the
    Issue is in (a transferred Issue), is not managed (Requirement 8.6). The
    label check is the caller's.
    """
    return marker is not None and marker.repo is not None and marker.repo == issue_repo


def parse_state(body: str | None) -> dict[str, Any] | None:
    """Reads the state block.

    Args:
        body: Issue body, or ``None``.

    Returns:
        The state as a dict, or ``None`` when the block is absent or is not a JSON object.
    """
    if not body:
        return None
    m = _STATE_RE.search(body)
    if m is None:
        return None
    try:
        value = json.loads(m.group(1))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def comparison_state(state: Mapping[str, Any]) -> dict[str, Any]:
    """Drops ``history`` and ``last_run_id`` so runs compare equal when nothing else changed."""
    return {k: v for k, v in state.items() if k not in VOLATILE_KEYS}


def _cell(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _table(rows: Sequence[tuple[str, object]]) -> str:
    return "\n".join(["| 項目 | 値 |", "|---|---|", *(f"| {_cell(k)} | {_cell(v)} |" for k, v in rows)])


def _state_block(state: Mapping[str, Any]) -> str:
    # Backticks only occur inside JSON strings, where \u0060 is equivalent; this keeps the fence closed.
    text = json.dumps(state, ensure_ascii=True, sort_keys=True).replace("`", "\\u0060")
    return f"```json {STATE_FENCE_TAG}\n{text}\n```"


def _largest_fit(total: int, render: Callable[[int], str], limit: int) -> int:
    """Largest ``n`` in ``[0, total]`` with ``len(render(n)) <= limit`` (0 when none fits)."""
    if len(render(total)) <= limit:
        return total
    lo, hi = 0, total
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(render(mid)) <= limit:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _clip(text: str, limit: int) -> str:
    """Last resort when the fixed fields alone exceed the limit."""
    return text if len(text) <= limit else text[:limit]


def render_finding(data: FindingIssue, max_chars: int = MAX_BODY_CHARS) -> str:
    """Renders the body of a finding Issue.

    Components are listed up to 200; if the body is still longer than
    ``max_chars``, fewer are listed, then the oldest history entries are
    dropped. The number of components left out is in the body and in the state
    block (``components_omitted``).

    Args:
        data: The Issue's contents.
        max_chars: Upper bound on the body length.

    Returns:
        The body.
    """
    comps = sorted(data.components, key=lambda c: (c.purl, c.version, c.name))
    malicious = _is_malicious(data.vuln_id, data.aliases)

    def render(n_components: int, n_history: int) -> str:
        shown = comps[:n_components]
        omitted = len(comps) - len(shown)
        kev = None
        if data.kev is not None:
            kev = {"date_added": data.kev[0].isoformat(), "known_ransomware_campaign_use": data.kev[1]}
        epss = None
        if data.epss is not None:
            epss = {"score": data.epss[0], "date": data.epss[1].isoformat(), "model_version": data.epss[2]}
        hist = data.history[len(data.history) - n_history :] if n_history else ()
        state = {
            "vuln_id": data.vuln_id,
            "components": [{"purl": c.purl, "version": c.version} for c in shown],
            "components_omitted": omitted,
            "cvss_severity": data.cvss_severity,
            "kev_listed": data.kev is not None,
            "kev": kev,
            "malicious": malicious,
            "epss": epss,
            "fixed_version": None if malicious else data.fixed_version,
            "origin_at": _iso(data.origin_at),
            "origin_is_date_only": data.origin_is_date_only,
            "detected_at": _iso(data.detected_at),
            "opened_at": _iso(data.opened_at),
            "due_at": _iso(data.due_at),
            "last_run_id": data.last_run_id,
            "history": [{"op": h.op, "run_id": h.run_id, "at": _iso(h.at)} for h in hist],
        }
        return _compose_finding(data, shown, omitted, state, malicious)

    n = _largest_fit(min(len(comps), MAX_COMPONENTS), lambda k: render(k, len(data.history)), max_chars)
    h = len(data.history)
    if len(render(n, h)) > max_chars:
        h = _largest_fit(len(data.history), lambda k: render(0, k), max_chars)
        n = 0
    return _clip(render(n, h), max_chars)


def _compose_finding(
    data: FindingIssue, shown: Sequence[Component], omitted: int, state: Mapping[str, Any], malicious: bool
) -> str:
    if malicious:
        fixed = MALICIOUS_FIXED_TEXT
    else:
        fixed = data.fixed_version if data.fixed_version else NOT_FIXED_YET
    if data.epss is None:
        epss = EPSS_MISSING
    else:
        epss = f"{data.epss[0]}（取得日 {data.epss[1].isoformat()}、モデルの版 {data.epss[2]}）"
    if data.kev is None:
        kev = "掲載なし"
        ransomware = "該当なし（KEV 掲載なし）"
    else:
        kev = f"掲載あり（dateAdded {data.kev[0].isoformat()}）"
        flag = data.kev[1]
        ransomware = "不明" if flag is None else ("確認あり" if flag else "確認なし")
    origin = _iso(data.origin_at) + ("（日付だけの値）" if data.origin_is_date_only else "")
    rows: list[tuple[str, object]] = [
        ("脆弱性識別子", data.vuln_id),
        ("別名", ", ".join(sorted(set(data.aliases) - {data.vuln_id})) or "なし"),
        ("悪意のあるパッケージ（MAL-）", "はい" if malicious else "いいえ"),
        ("CVSS 重大度", data.cvss_severity if data.cvss_severity else "未付与"),
        ("KEV 掲載", kev),
        ("KEV の knownRansomwareCampaignUse（表示のみ）", ransomware),
        ("EPSS", epss),
        ("修正済みバージョン", fixed),
        ("起点", origin),
        ("検出日時", _iso(data.detected_at)),
        ("起票日時", _iso(data.opened_at)),
        ("修正の期限（Response_Target）", _iso(data.due_at)),
    ]
    comp_lines = ["| purl | 名前 | バージョン |", "|---|---|---|"]
    comp_lines += [f"| {_cell(c.purl)} | {_cell(c.name)} | {_cell(c.version)} |" for c in shown]
    parts = [
        render_marker("finding", data.repo, data.vuln_id, data.aliases),
        _state_block(state),
        _table(rows),
        "\n".join(comp_lines),
    ]
    if omitted:
        parts.append(f"構成要素 {omitted} 件は本文の長さの上限のため省略しました。")
    return "\n".join(parts[:2]) + "\n\n" + "\n\n".join(parts[2:]) + "\n"


def render_summary(repo: Repo, entries: Sequence[SummaryEntry], run_id: str, max_chars: int = MAX_BODY_CHARS) -> str:
    """Renders the summary Issue that lists Findings over the per-run opening limit.

    Args:
        repo: Repository the summary is for.
        entries: Findings not opened this run. Sorted by identifier.
        run_id: Run that wrote this body (not compared; see ``comparison_state``).
        max_chars: Upper bound on the body length.

    Returns:
        The body. Entries that do not fit are left out and counted in the body.
    """
    ordered = sorted(entries, key=lambda e: e.vuln_id)

    def render(n: int) -> str:
        shown = ordered[:n]
        omitted = len(ordered) - n
        state = {
            "entries": [
                {
                    "vuln_id": e.vuln_id,
                    "cvss_severity": e.cvss_severity,
                    "kev_listed": e.kev_listed,
                    "malicious": e.malicious,
                }
                for e in shown
            ],
            "entries_omitted": omitted,
            "total": len(ordered),
            "last_run_id": run_id,
        }
        lines = ["| 脆弱性識別子 | CVSS 重大度 | KEV 掲載 | 悪意のあるパッケージ（MAL-） |", "|---|---|---|---|"]
        lines += [
            f"| {_cell(e.vuln_id)} | {e.cvss_severity or '未付与'} | {'あり' if e.kev_listed else 'なし'} "
            f"| {'はい' if e.malicious else 'いいえ'} |"
            for e in shown
        ]
        tail = f"\n\n{omitted} 件は本文の長さの上限のため省略しました。" if omitted else ""
        head = f"{render_marker('summary', repo)}\n{_state_block(state)}\n\n"
        return head + f"起票数の上限を超えた {len(ordered)} 件の一覧です。\n\n" + "\n".join(lines) + tail + "\n"

    return _clip(render(_largest_fit(len(ordered), render, max_chars)), max_chars)


def render_failure(
    repo: Repo, run_id: str, at: datetime, messages: Sequence[str], max_chars: int = MAX_BODY_CHARS
) -> str:
    """Renders the failure Issue for a run that ended in ``failure``.

    Args:
        repo: Repository that holds the failure Issue (the Hub).
        run_id: The failed run.
        at: When the run ended (UTC).
        messages: Failure descriptions, in order.
        max_chars: Upper bound on the body length.

    Returns:
        The body. Messages that do not fit are left out and counted in the body.
    """

    def render(n: int) -> str:
        shown = list(messages[:n])
        omitted = len(messages) - n
        state = {
            "run_id": run_id,
            "at": _iso(at),
            "messages": shown,
            "messages_omitted": omitted,
            "last_run_id": run_id,
        }
        lines = [f"- {m.replace(chr(10), ' ')}" for m in shown]
        tail = f"\n{omitted} 件は本文の長さの上限のため省略しました。" if omitted else ""
        return (
            f"{render_marker('failure', repo)}\n{_state_block(state)}\n\n"
            f"実行 {run_id} が失敗しました（{_iso(at)}）。\n\n" + "\n".join(lines) + tail + "\n"
        )

    return _clip(render(_largest_fit(len(messages), render, max_chars)), max_chars)

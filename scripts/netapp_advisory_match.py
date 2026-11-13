#!/usr/bin/env python3
"""Semi-automatic match of NetApp security advisories against the component ledger.

The NetApp advisory feed (RSS 2.0) is the source. For each row of the private
Infrastructure_Component_Ledger the matcher proposes one of ``該当あり`` / ``該当なし`` /
``判定保留``; a person confirms the proposal within 7 days, counted from the date of the
revision that decided it. Nothing here writes to either ledger.

Rules (Requirement 5.5 to 5.9):

* The feed is parsed by pure functions (``parse_feed``, ``judge_advisory``, ``propose_row``,
  ``run_match``). Fetching is in ``fetch_feed`` and ``main``. The undocumented JSON API of
  the advisory site is not used.
* Treating an FSx for ONTAP version as the "ONTAP 9" of an advisory is a hypothesis, so every
  proposal carries ``mapping_tier = "hypothesis"`` and is never applied automatically.
* A version with a ``D`` suffix always gets ``判定保留``. A version more than 3 years past its
  GA date gets ``判定保留``; so does a ``該当なし`` for a version whose GA date is not recorded.
  Rows that are not ONTAP versions get ``判定保留`` (the advisories name ONTAP 9 only).
* The advisories give no affected version range, only the first fixed release per release
  line. A version below the first fix of its line is proposed as ``該当あり``; a version
  with no fix listed on its line is ``判定保留``.
* A parse failure, or a known control advisory that cannot be found in the parsed feed,
  makes the whole run an ``error`` with no proposals, so a broken run is never recorded
  as matched.

Exit codes of the CLI: 0 = matched, nothing overdue; 1 = matched, some proposals are past
their 7-day confirmation date; 2 = error (fetch, parse or control failed).
"""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

YES, NO, PENDING = "該当あり", "該当なし", "判定保留"
MAPPING_TIER = "hypothesis"
CONFIRM_DAYS = 7
GA_SUPPORT_YEARS = 3
FEED_URL = "https://security.netapp.com/advisory/index.xml"
DEFAULT_OUT = ".private/supply-chain/netapp-advisory-match.json"
MAX_FEED_BYTES = 200 * 1024 * 1024
DEFAULT_CONTROL_ID = "NTAP-20260112-0001"
DEFAULT_CONTROL_FIXES = ("9.16.1P9", "9.17.1P2")

_ONTAP9 = re.compile(r"^ONTAP 9(?: \(formerly Clustered Data ONTAP\))?$")
_VERSION = re.compile(r"^9\.(\d+)\.(\d+)(?:P(\d+))?(?:HF(\d+))?(?:D(\d+))?$")
_VERSION_IN_TEXT = re.compile(r"\b9\.\d+\.\d+(?:P\d+)?(?:HF\d+)?\b")
_ADVISORY_ID = re.compile(r"(ntap-\d{8}-\d{4})", re.IGNORECASE)
_MOVED = re.compile(r"ONTAP 9(?![\d.])[^;]*?\bmoved to\b", re.IGNORECASE)
_STATUS = re.compile(r"^\s*(Final|Interim)\b")


class FeedError(Exception):
    """The feed could not be read in the shape this matcher expects."""


class FetchError(Exception):
    """The feed could not be fetched."""


@dataclass(frozen=True)
class OntapVersion:
    """A version such as ``9.17.1P7D1`` split into release line and levels."""

    line: tuple[int, int, int]
    patch: int
    hotfix: int
    d_level: int | None

    @property
    def rank(self) -> tuple[int, int]:
        """Order within a release line: patch level, then hotfix level."""
        return (self.patch, self.hotfix)


def parse_ontap_version(text: str) -> OntapVersion | None:
    """Parse ``9.x.y[Pn][HFn][Dn]``; return None if the text has another shape."""
    m = _VERSION.match(text.strip())
    if m is None:
        return None
    major_minor, release, patch, hotfix, d_level = m.groups()
    return OntapVersion(
        line=(9, int(major_minor), int(release)),
        patch=int(patch or 0),
        hotfix=int(hotfix or 0),
        d_level=int(d_level) if d_level is not None else None,
    )


@dataclass(frozen=True)
class Revision:
    """One line of an advisory's Revision History."""

    number: str
    date: dt.date
    comment: str


@dataclass(frozen=True)
class Advisory:
    """The parts of one feed item that the matcher uses (latest revision)."""

    advisory_id: str
    revision: str
    updated: dt.date
    title: str
    status: str | None
    affected: tuple[str, ...]
    investigating: tuple[str, ...]
    not_affected: tuple[str, ...]
    fixes: tuple[str, ...]
    revisions: tuple[Revision, ...]


@dataclass(frozen=True)
class Feed:
    """A parsed feed."""

    last_build_date: str | None
    advisories: tuple[Advisory, ...]
    skipped_revision_rows: int = 0


@dataclass
class _Section:
    items: list[str] = field(default_factory=list)
    rows: list[list[tuple[str, list[str]]]] = field(default_factory=list)
    text: list[str] = field(default_factory=list)


def _norm(text: str) -> str:
    return " ".join(text.split())


class _SectionParser(HTMLParser):
    """Split the HTML of an item description into sections keyed by its h3 headings."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sections: dict[str, _Section] = {}
        self._cur: _Section | None = None
        self._h3: list[str] | None = None
        self._li: list[str] | None = None
        self._row: list[tuple[str, list[str]]] | None = None
        self._cell: list[str] | None = None
        self._hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "h3":
            self._h3 = []
        elif tag == "li":
            self._li = []
        elif tag == "tr":
            self._row = []
        elif tag in ("td", "th"):
            self._cell, self._hrefs = [], []
        elif tag == "a" and self._cell is not None:
            href = dict(attrs).get("href")
            if href:
                self._hrefs.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag == "h3" and self._h3 is not None:
            self._cur = self.sections.setdefault(_norm("".join(self._h3)).casefold(), _Section())
            self._h3 = None
        elif tag == "li" and self._li is not None:
            if self._cur is not None:
                self._cur.items.append(_norm("".join(self._li)))
            self._li = None
        elif tag in ("td", "th") and self._cell is not None:
            if self._row is not None:
                self._row.append((_norm("".join(self._cell)), self._hrefs))
            self._cell, self._hrefs = None, []
        elif tag == "tr" and self._row is not None:
            if self._cur is not None:
                self._cur.rows.append(self._row)
            self._row = None

    def handle_data(self, data: str) -> None:
        if self._h3 is not None:
            self._h3.append(data)
            return
        if self._li is not None:
            self._li.append(data)
        if self._cell is not None:
            self._cell.append(data)
        if self._cur is not None and data.strip():
            self._cur.text.append(_norm(data))


def _fix_versions(section: _Section | None) -> tuple[str, ...]:
    found: list[str] = []
    if section is None:
        return ()
    for row in section.rows:
        if len(row) < 2 or not _ONTAP9.match(row[0][0]):
            continue
        text, hrefs = row[1]
        candidates = [h.rstrip("/").rsplit("/", 1)[-1] for h in hrefs]
        candidates += _VERSION_IN_TEXT.findall(text)
        for cand in candidates:
            if _VERSION.match(cand) and cand not in found:
                found.append(cand)
    return tuple(found)


def _revisions(section: _Section | None) -> tuple[tuple[Revision, ...], int]:
    """Return the revisions of a Revision History table and the number of rows skipped.

    A row whose date is not a real YYYYMMDD date is skipped, not fatal: the live feed has one
    old item with a mistyped date. The decisive revision then falls back to the initial
    release, which is the stricter deadline.
    """
    revisions: list[Revision] = []
    skipped = 0
    if section is None:
        return (), 0
    for row in section.rows:
        if len(row) < 3 or not re.match(r"^\d+\.\d+$", row[0][0]):
            continue  # header row
        try:
            day = dt.datetime.strptime(row[1][0], "%Y%m%d").date()
        except ValueError:
            skipped += 1
            continue
        revisions.append(Revision(row[0][0], day, row[2][0]))
    return tuple(revisions), skipped


def _parse_item(item: ET.Element, index: int) -> tuple[Advisory, int]:
    where = f"item {index}"
    fields = {tag: (item.findtext(tag) or "").strip() for tag in ("title", "link", "guid", "pubDate", "description")}
    for tag, value in fields.items():
        if not value:
            raise FeedError(f"{where}: <{tag}> is missing or empty")
    m = _ADVISORY_ID.search(fields["link"]) or _ADVISORY_ID.search(fields["guid"])
    if m is None or "#" not in fields["guid"]:
        raise FeedError(f"{where}: link or guid does not have the advisory id / #revision shape")
    try:
        updated = email.utils.parsedate_to_datetime(fields["pubDate"]).date()
    except (TypeError, ValueError) as exc:
        raise FeedError(f"{where}: pubDate is not an RFC 822 date") from exc
    parser = _SectionParser()
    parser.feed(fields["description"])
    parser.close()
    sec = parser.sections

    def items(name: str) -> tuple[str, ...]:
        return tuple(sec[name].items) if name in sec else ()

    status = None
    for line in sec.get("status of this notice", _Section()).text:
        sm = _STATUS.match(line)
        if sm:
            status = sm.group(1)
            break
    revisions, skipped = _revisions(sec.get("revision history"))
    advisory = Advisory(
        advisory_id=m.group(1).upper(),
        revision=fields["guid"].rsplit("#", 1)[1],
        updated=updated,
        title=fields["title"],
        status=status,
        affected=items("affected products"),
        investigating=items("products under investigation"),
        not_affected=items("products not affected"),
        fixes=_fix_versions(sec.get("software versions and fixes")),
        revisions=revisions,
    )
    return advisory, skipped


def parse_feed(xml_text: str) -> Feed:
    """Parse an RSS 2.0 advisory feed; raise FeedError if its shape is not as expected."""
    if re.search(r"<!(?:DOCTYPE|ENTITY)", xml_text, re.IGNORECASE):
        raise FeedError("the feed declares a DOCTYPE or ENTITY; refusing to parse")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise FeedError(f"not well-formed XML: {exc}") from exc
    if root.tag != "rss" or root.get("version") != "2.0":
        raise FeedError('the root element is not <rss version="2.0">')
    channel = root.find("channel")
    if channel is None:
        raise FeedError("<channel> is missing")
    elements = channel.findall("item")
    if not elements:
        raise FeedError("the channel has no <item>")
    parsed = [_parse_item(el, i) for i, el in enumerate(elements)]
    advisories = tuple(a for a, _ in parsed)
    skipped = sum(n for _, n in parsed)
    with_history = sum(1 for a in advisories if a.revisions)
    if with_history * 2 < len(advisories):
        raise FeedError(f"Revision History was found in only {with_history} of {len(advisories)} items")
    return Feed(channel.findtext("lastBuildDate"), advisories, skipped)


@dataclass(frozen=True)
class LedgerRow:
    """The fields of a private ledger row that the matcher reads."""

    verified_version: str
    advisory_match: str
    matched_on: dt.date | None
    ga_date: dt.date | None = None


@dataclass(frozen=True)
class Judgment:
    """The proposal for one (row, advisory) pair."""

    advisory_id: str
    revision: str
    verdict: str
    reference_verdict: str
    reasons: tuple[str, ...]
    decisive_date: dt.date
    decisive_source: str
    confirm_by: dt.date


@dataclass(frozen=True)
class RowProposal:
    """The proposal for one ledger row, over all advisories considered."""

    verified_version: str
    current_match: str
    current_matched_on: dt.date | None
    verdict: str | None
    reasons: tuple[str, ...]
    confirm_by: dt.date | None
    overdue: bool
    judgments: tuple[Judgment, ...]


def _add_years(day: dt.date, years: int) -> dt.date:
    try:
        return day.replace(year=day.year + years)
    except ValueError:  # 29 February
        return day.replace(year=day.year + years, day=28)


def _initial(adv: Advisory) -> tuple[dt.date, str]:
    if adv.revisions:
        first = min(adv.revisions, key=lambda r: r.date)
        return first.date, f"revision {first.number} (initial release; no revision comment named the change)"
    return adv.updated, "feed pubDate (no Revision History)"


def _mentions(comment: str, version: str) -> bool:
    return re.search(rf"(?<![\w.]){re.escape(version)}(?!\w)", comment) is not None


def _decisive(adv: Advisory, fix_versions: list[str] | None) -> tuple[dt.date, str]:
    """Return the date of the revision that decided the verdict, and how it was found.

    With ``fix_versions``, the earliest revision whose comment names one of them. Without,
    the latest revision that moved ONTAP 9 between the product lists. If no comment says
    so, the initial release date is used, which is the earlier date and so the stricter
    deadline.
    """
    if fix_versions:
        hits = [r for r in adv.revisions if any(_mentions(r.comment, v) for v in fix_versions)]
        pick = min(hits, key=lambda r: r.date) if hits else None
    else:
        hits = [r for r in adv.revisions if _MOVED.search(r.comment)]
        pick = max(hits, key=lambda r: r.date) if hits else None
    if pick is not None:
        return pick.date, f"revision {pick.number}: {pick.comment}"
    return _initial(adv)


def _names_ontap9(names: tuple[str, ...]) -> bool:
    return any(_ONTAP9.match(n) for n in names)


def _fix_verdict(ver: OntapVersion, adv: Advisory) -> tuple[str, str, list[str] | None]:
    """Compare a version with the first fixes listed for its release line."""
    on_line = [(v, parse_ontap_version(v)) for v in adv.fixes]
    on_line_ok = [(v, p) for v, p in on_line if p is not None and p.line == ver.line]
    if not on_line_ok:
        return PENDING, "no-fix-listed-for-release-line", None
    at_or_below = [v for v, p in on_line_ok if p is not None and p.rank <= ver.rank]
    if at_or_below:
        return NO, "at-or-above-first-fixed-release", at_or_below
    lowest = min(on_line_ok, key=lambda vp: vp[1].rank if vp[1] else (0, 0))
    return YES, "below-first-fixed-release", [lowest[0]]


def judge_advisory(row: LedgerRow, adv: Advisory, today: dt.date) -> Judgment | None:
    """Propose a verdict for an ONTAP row against one advisory.

    Returns None when the advisory does not name ONTAP 9 at all.
    """
    in_aff = _names_ontap9(adv.affected)
    in_inv = _names_ontap9(adv.investigating)
    in_not = _names_ontap9(adv.not_affected)
    fixes_named = bool(adv.fixes)
    if not (in_aff or in_inv or in_not or fixes_named):
        return None
    ver = parse_ontap_version(row.verified_version.removeprefix("ONTAP "))
    reasons: list[str] = []
    fix_versions: list[str] | None = None
    if ver is None:
        base, reasons = PENDING, ["unparseable-version"]
    elif in_inv:
        base, reasons = PENDING, ["product-under-investigation"]
    elif in_aff and in_not:
        base, reasons = PENDING, ["product-in-contradicting-lists"]
    elif in_not:
        base, reasons = NO, ["product-not-affected"]
    else:
        base, why, fix_versions = _fix_verdict(ver, adv)
        reasons = [why]
    date, source = _decisive(adv, fix_versions)
    verdict = base
    if ver is not None and ver.d_level is not None:
        verdict = PENDING
        reasons.append("d-suffix-version")
    if row.ga_date is not None and _add_years(row.ga_date, GA_SUPPORT_YEARS) < today:
        verdict = PENDING
        reasons.append("more-than-3-years-past-ga")
    elif row.ga_date is None and verdict == NO:
        verdict = PENDING
        reasons.append("ga-date-not-recorded")
    return Judgment(
        advisory_id=adv.advisory_id,
        revision=adv.revision,
        verdict=verdict,
        reference_verdict=base,
        reasons=tuple(reasons),
        decisive_date=date,
        decisive_source=source,
        confirm_by=date + dt.timedelta(days=CONFIRM_DAYS),
    )


def propose_row(
    row: LedgerRow,
    advisories: tuple[Advisory, ...],
    today: dt.date,
    since: dt.date | None = None,
) -> RowProposal:
    """Combine the judgments of all advisories updated on or after ``since`` for one row.

    Order of precedence: 該当あり, then 判定保留, then 該当なし. A verdict of None means no
    advisory in range named ONTAP 9, so the row is left as it is.
    """
    base = {
        "verified_version": row.verified_version,
        "current_match": row.advisory_match,
        "current_matched_on": row.matched_on,
    }
    if not row.verified_version.startswith("ONTAP "):
        return RowProposal(
            **base,
            verdict=PENDING,
            reasons=("component-not-mapped-to-ontap-9",),
            confirm_by=None,
            overdue=False,
            judgments=(),
        )
    judgments = tuple(
        j
        for adv in advisories
        if since is None or adv.updated >= since
        for j in [judge_advisory(row, adv, today)]
        if j is not None
    )
    if not judgments:
        return RowProposal(**base, verdict=None, reasons=(), confirm_by=None, overdue=False, judgments=())
    verdicts = {j.verdict for j in judgments}
    verdict = YES if YES in verdicts else PENDING if PENDING in verdicts else NO
    chosen = [j for j in judgments if j.verdict == verdict]
    confirm_by = min(j.confirm_by for j in chosen)
    reasons = tuple(sorted({r for j in chosen for r in j.reasons}))
    return RowProposal(
        **base, verdict=verdict, reasons=reasons, confirm_by=confirm_by, overdue=today > confirm_by, judgments=judgments
    )


@dataclass(frozen=True)
class ControlSpec:
    """An advisory that must be found, with what must be read from it."""

    advisory_id: str = DEFAULT_CONTROL_ID
    fixes: tuple[str, ...] = DEFAULT_CONTROL_FIXES


def check_control(advisories: tuple[Advisory, ...], spec: ControlSpec) -> str | None:
    """Return why the control advisory was not read as expected, or None if it was."""
    found = [a for a in advisories if a.advisory_id == spec.advisory_id.upper()]
    if not found:
        return f"control advisory {spec.advisory_id} is not in the parsed feed"
    adv = found[0]
    if not _names_ontap9(adv.affected):
        return f"control advisory {spec.advisory_id}: Affected Products does not read as ONTAP 9"
    missing = [v for v in spec.fixes if v not in adv.fixes]
    if missing:
        return f"control advisory {spec.advisory_id}: fixed releases not read: {', '.join(missing)}"
    if not adv.revisions:
        return f"control advisory {spec.advisory_id}: Revision History not read"
    return None


@dataclass(frozen=True)
class MatchResult:
    """The outcome of one run. ``rows`` is empty unless ``status`` is ``ok``."""

    status: str
    error: str | None
    last_build_date: str | None
    item_count: int
    rows: tuple[RowProposal, ...]


def run_match(
    xml_text: str,
    rows: list[LedgerRow],
    today: dt.date,
    since: dt.date | None = None,
    control: ControlSpec | None = None,
) -> MatchResult:
    """Parse the feed, read the control advisory, then propose a verdict for every row."""
    try:
        feed = parse_feed(xml_text)
    except FeedError as exc:
        return MatchResult("error", f"parse: {exc}", None, 0, ())
    problem = check_control(feed.advisories, control or ControlSpec())
    if problem is not None:
        return MatchResult("error", f"control: {problem}", feed.last_build_date, len(feed.advisories), ())
    proposals = tuple(propose_row(r, feed.advisories, today, since) for r in rows)
    return MatchResult("ok", None, feed.last_build_date, len(feed.advisories), proposals)


def _iso(day: dt.date | None) -> str | None:
    return day.isoformat() if day else None


def result_to_dict(result: MatchResult, today: dt.date, url: str) -> dict[str, Any]:
    """Return the JSON form of a result. ``checked_on`` is present only when status is ok."""
    doc: dict[str, Any] = {
        "status": result.status,
        "mapping_tier": MAPPING_TIER,
        "note": "Proposals only. A person confirms each within 7 days of the deciding revision. "
        "Matching an FSx for ONTAP version to the ONTAP 9 of an advisory is a hypothesis.",
        "feed": {"url": url, "last_build_date": result.last_build_date, "item_count": result.item_count},
    }
    if result.status != "ok":
        doc["error"] = result.error
        return doc
    doc["checked_on"] = today.isoformat()
    doc["rows"] = [
        {
            "verified_version": p.verified_version,
            "current": {"advisory_match": p.current_match, "matched_on": _iso(p.current_matched_on)},
            "proposed": p.verdict,
            "reasons": list(p.reasons),
            "confirm_by": _iso(p.confirm_by),
            "overdue": p.overdue,
            "judgments": [
                {
                    "advisory_id": j.advisory_id,
                    "revision": j.revision,
                    "verdict": j.verdict,
                    "reference_verdict": j.reference_verdict,
                    "reasons": list(j.reasons),
                    "decisive_date": j.decisive_date.isoformat(),
                    "decisive_source": j.decisive_source,
                    "confirm_by": j.confirm_by.isoformat(),
                }
                for j in p.judgments
            ],
        }
        for p in result.rows
    ]
    return doc


def rows_from_private(doc: Any) -> list[LedgerRow]:
    """Read the rows of a private ledger. ``ga_date`` (YYYY-MM-DD) is an optional extra key."""
    rows: list[LedgerRow] = []
    for raw in doc["rows"]:

        def day(key: str, raw: dict[str, Any] = raw) -> dt.date | None:
            value = raw.get(key)
            return dt.date.fromisoformat(value) if value else None

        rows.append(LedgerRow(raw["verified_version"], raw["advisory_match"], day("matched_on"), day("ga_date")))
    return rows


def fetch_feed(url: str, timeout: float = 120.0) -> str:
    """Fetch the feed over https without credentials; raise FetchError on any failure."""
    if urllib.parse.urlparse(url).scheme != "https":
        raise FetchError("only https URLs are fetched")
    request = urllib.request.Request(url, headers={"User-Agent": "netapp-advisory-match/1"})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read(MAX_FEED_BYTES + 1)
    except (urllib.error.URLError, OSError) as exc:
        raise FetchError(f"fetch failed: {exc}") from exc
    if len(body) > MAX_FEED_BYTES:
        raise FetchError("the feed is larger than the size limit")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FetchError("the feed is not UTF-8") from exc


def main(argv: list[str] | None = None) -> int:
    """Fetch (or read) the feed, match it against the private ledger, write the proposals."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--private-ledger", required=True, help="private ledger JSON (.private/supply-chain/...)")
    parser.add_argument("--out", default=DEFAULT_OUT, help="where to write the proposals (under .private/)")
    parser.add_argument("--url", default=FEED_URL)
    parser.add_argument("--feed-file", default=None, help="read the feed from this file instead of fetching")
    parser.add_argument("--since", default=None, help="only advisories updated on or after YYYY-MM-DD")
    parser.add_argument("--today", default=None, help="YYYY-MM-DD (default: today)")
    parser.add_argument("--control-id", default=DEFAULT_CONTROL_ID)
    args = parser.parse_args(argv)
    try:
        today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
        since = dt.date.fromisoformat(args.since) if args.since else None
        rows = rows_from_private(json.loads(Path(args.private_ledger).read_text(encoding="utf-8")))
        text = Path(args.feed_file).read_text(encoding="utf-8") if args.feed_file else fetch_feed(args.url)
    except (OSError, ValueError, KeyError, TypeError, FetchError) as exc:
        sys.stderr.write(f"netapp-advisory-match: error: {exc}\n")
        return 2
    fixes = DEFAULT_CONTROL_FIXES if args.control_id == DEFAULT_CONTROL_ID else ()
    control = ControlSpec(advisory_id=args.control_id, fixes=fixes)
    result = run_match(text, rows, today, since, control)
    if result.status != "ok":
        sys.stderr.write(f"netapp-advisory-match: error: {result.error}\n")
        return 2
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(result_to_dict(result, today, args.url), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    overdue = [p.verified_version for p in result.rows if p.overdue]
    for version in overdue:
        sys.stdout.write(f"netapp-advisory-match: confirmation overdue (over {CONFIRM_DAYS} days): {version}\n")
    return 1 if overdue else 0


if __name__ == "__main__":
    sys.exit(main())

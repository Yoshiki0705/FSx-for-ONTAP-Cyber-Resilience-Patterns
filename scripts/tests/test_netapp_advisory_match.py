"""Tests for the NetApp advisory matcher. They use only synthetic feeds and no network.

The feed fixtures follow the RSS 2.0 shape of the advisory site (an escaped HTML body with
h3 sections, a product table, and a Revision History table). The advisory ids, dates and
download links are made up.

**Validates: Requirements 5.5, 5.6, 5.7, 5.9**
"""

from __future__ import annotations

import datetime as dt
import json
from html import escape
from pathlib import Path

import netapp_advisory_match as nam
import pytest

D = dt.date
TODAY = D(2031, 3, 1)
RECENT_GA = D(2030, 6, 1)
CONTROL = nam.ControlSpec("NTAP-20300101-0001", ("9.16.1P9", "9.17.1P2"))


def _li(names: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{n}</li>" for n in names) + "</ul>"


def make_item(
    adv_id: str = "NTAP-20300101-0001",
    rev: str = "1.0",
    pub: str = "Tue, 01 Jan 2030 00:00:00 +0000",
    affected: list[str] | None = None,
    not_affected: list[str] | None = None,
    investigating: list[str] | None = None,
    fixes: list[str] | None = None,
    revisions: list[tuple[str, str, str]] | None = None,
    status: str = "Final",
) -> str:
    """Build one synthetic <item>."""
    parts = ["<p><strong>CVEs:</strong> CVE-2030-0001</p><h3>Summary</h3><p>Synthetic.</p>"]
    for heading, names in (
        ("Affected Products", affected),
        ("Products Under Investigation", investigating),
        ("Products Not Affected", not_affected),
    ):
        if names is not None:
            parts.append(f"<h3>{heading}</h3>{_li(names)}")
    if fixes is not None:
        links = "".join(
            f'<a href="https://example.com/downloads/00000/{v}">https://example.com/downloads/00000/{v}</a><br>'
            for v in fixes
        )
        parts.append(
            "<h3>Software Versions and Fixes</h3><table><thead><tr><th><b>Product </b></th>"
            "<th><b>First Fixed in Release</b></th></tr></thead><tbody><tr><td><strong> ONTAP 9 </strong></td>"
            f"<td>{links}</td></tr><tr><td>Other Product</td><td>"
            '<a href="https://example.com/downloads/1/9.99.9P9">x</a></td></tr></tbody></table>'
        )
    if revisions is None:
        revisions = [("1.0", "20300101", "Initial Public Release")]
    rows = "".join(f"<tr><td>{n}</td><td>{d}</td><td>{c}</td></tr>" for n, d, c in revisions)
    parts.append(
        "<h3>Revision History</h3><table><thead><tr><th><b>Revision #</b></th><th><b>Date</b></th>"
        f"<th><b>Comments</b></th></tr></thead><tbody>{rows}</tbody></table>"
    )
    parts.append(f"<h3>Status of This Notice</h3><p><strong>{status}.</strong></p><p>Text.</p>")
    slug = adv_id.lower()
    return (
        f"<item><title>{adv_id}: synthetic</title><link>http://example.com/advisory/{slug}</link>"
        f"<description>{escape(''.join(parts))}</description><author>psirt@example.com (PSIRT)</author>"
        f"<guid>http://example.com/advisory/{slug}/#{rev}</guid><pubDate>{pub}</pubDate></item>"
    )


def make_feed(items: list[str]) -> str:
    """Wrap items in an RSS 2.0 envelope."""
    return (
        "<?xml version='1.0' encoding='UTF-8'?>"
        '<rss xmlns:atom="http://www.w3.org/2005/Atom" version="2.0"><channel>'
        "<title>Synthetic</title><lastBuildDate>Tue, 01 Jan 2030 00:00:00 +0000</lastBuildDate>"
        + "".join(items)
        + "</channel></rss>"
    )


def control_item() -> str:
    return make_item(affected=["ONTAP 9"], fixes=["9.16.1P9", "9.17.1P2"])


def row(
    version: str, ga: dt.date | None = RECENT_GA, match: str = nam.PENDING, on: dt.date | None = None
) -> nam.LedgerRow:
    return nam.LedgerRow(version, match, on, ga)


def judge(version: str, item: str, ga: dt.date | None = RECENT_GA, today: dt.date = TODAY) -> nam.Judgment | None:
    feed = nam.parse_feed(make_feed([item]))
    return nam.judge_advisory(row(version, ga), feed.advisories[0], today)


def test_parse_reads_the_fields_the_matcher_uses() -> None:
    item = make_item(
        affected=["ONTAP 9"],
        not_affected=["Other Thing", "ONTAP Select Deploy"],
        fixes=["9.16.1P9", "9.17.1P2"],
        revisions=[("1.0", "20300101", "Initial Public Release"), ("2.0", "20300105", "ONTAP 9.17.1P2 added")],
        rev="2.0",
        pub="Sat, 05 Jan 2030 00:00:00 +0000",
        status="Interim",
    )
    adv = nam.parse_feed(make_feed([item])).advisories[0]
    assert (adv.advisory_id, adv.revision, adv.updated, adv.status) == (
        "NTAP-20300101-0001",
        "2.0",
        D(2030, 1, 5),
        "Interim",
    )
    assert adv.affected == ("ONTAP 9",) and adv.not_affected == ("Other Thing", "ONTAP Select Deploy")
    assert adv.fixes == ("9.16.1P9", "9.17.1P2")  # the other product's 9.99.9P9 is not read
    assert [(r.number, r.date) for r in adv.revisions] == [("1.0", D(2030, 1, 1)), ("2.0", D(2030, 1, 5))]


def test_version_below_the_first_fix_of_its_line_is_proposed_as_affected() -> None:
    j = judge("ONTAP 9.17.1P1", control_item())
    assert j is not None and j.verdict == nam.YES and j.reasons == ("below-first-fixed-release",)


def test_version_at_or_above_the_first_fix_is_proposed_as_not_affected() -> None:
    for version in ("ONTAP 9.17.1P2", "ONTAP 9.17.1P7"):
        j = judge(version, control_item())
        assert j is not None and j.verdict == nam.NO and j.reasons == ("at-or-above-first-fixed-release",)


def test_hotfix_level_orders_after_the_same_patch_level() -> None:
    item = make_item(affected=["ONTAP 9"], fixes=["9.17.1P11HF1"])
    below, equal = judge("ONTAP 9.17.1P11", item), judge("ONTAP 9.17.1P11HF1", item)
    assert below is not None and below.verdict == nam.YES
    assert equal is not None and equal.verdict == nam.NO
    plain_fix = make_item(affected=["ONTAP 9"], fixes=["9.17.1P11"])
    above = judge("ONTAP 9.17.1P11HF1", plain_fix)
    assert above is not None and above.verdict == nam.NO


def test_no_fix_on_the_release_line_is_pending_because_no_range_is_published() -> None:
    j = judge("ONTAP 9.18.1P6", control_item())
    assert j is not None and j.verdict == nam.PENDING and j.reasons == ("no-fix-listed-for-release-line",)


def test_product_in_not_affected_list_is_proposed_as_not_affected() -> None:
    j = judge("ONTAP 9.17.1P7", make_item(not_affected=["ONTAP 9", "Other"]))
    assert j is not None and j.verdict == nam.NO and j.reasons == ("product-not-affected",)


def test_product_under_investigation_is_pending() -> None:
    j = judge("ONTAP 9.17.1P7", make_item(investigating=["ONTAP 9"]))
    assert j is not None and j.verdict == nam.PENDING and j.reasons == ("product-under-investigation",)


def test_product_in_two_lists_is_pending() -> None:
    j = judge("ONTAP 9.17.1P7", make_item(affected=["ONTAP 9"], not_affected=["ONTAP 9"]))
    assert j is not None and j.verdict == nam.PENDING and j.reasons == ("product-in-contradicting-lists",)


def test_d_suffix_version_is_always_pending_and_keeps_the_reference_verdict() -> None:
    cases = {
        "affected": (make_item(affected=["ONTAP 9"], fixes=["9.17.1P9"]), nam.YES),
        "fixed": (make_item(affected=["ONTAP 9"], fixes=["9.17.1P2"]), nam.NO),
        "listed not affected": (make_item(not_affected=["ONTAP 9"]), nam.NO),
    }
    for name, (item, reference) in cases.items():
        j = judge("ONTAP 9.17.1P7D1", item)
        assert j is not None, name
        assert j.verdict == nam.PENDING and "d-suffix-version" in j.reasons, name
        assert j.reference_verdict == reference, name


def test_version_more_than_3_years_past_ga_is_pending_for_every_verdict() -> None:
    old_ga = D(2027, 2, 28)  # +3 years = 2030-02-28, before TODAY
    for item in (control_item(), make_item(not_affected=["ONTAP 9"])):
        j = judge("ONTAP 9.17.1P1" if item == control_item() else "ONTAP 9.17.1P7", item, ga=old_ga)
        assert j is not None and j.verdict == nam.PENDING and "more-than-3-years-past-ga" in j.reasons
    edge = judge("ONTAP 9.17.1P7", make_item(not_affected=["ONTAP 9"]), ga=D(2028, 3, 1))  # +3y == TODAY
    assert edge is not None and edge.verdict == nam.NO


def test_unknown_ga_date_blocks_not_affected_but_not_affected_by_a_fix_gap() -> None:
    blocked = judge("ONTAP 9.17.1P7", make_item(not_affected=["ONTAP 9"]), ga=None)
    assert blocked is not None and blocked.verdict == nam.PENDING and "ga-date-not-recorded" in blocked.reasons
    affected = judge("ONTAP 9.17.1P1", control_item(), ga=None)
    assert affected is not None and affected.verdict == nam.YES


def test_advisory_that_does_not_name_ontap_9_gives_no_judgment() -> None:
    assert judge("ONTAP 9.17.1P7", make_item(affected=["Other Thing"], not_affected=["More"])) is None


def test_confirm_by_is_7_days_after_the_deciding_revision_not_the_latest_one() -> None:
    item = make_item(
        affected=["ONTAP 9"],
        fixes=["9.16.1P9", "9.17.1P1", "9.17.1P2"],
        revisions=[
            ("1.0", "20300101", "Initial Public Release"),
            ("2.0", "20300110", "ONTAP 9.17.1P1 added to Software Versions and Fixes"),
            ("3.0", "20300120", "ONTAP 9.17.1P2 added to Software Versions and Fixes"),
            ("4.0", "20300201", "Other product updated"),
        ],
        rev="4.0",
        pub="Fri, 01 Feb 2030 00:00:00 +0000",
    )
    below = judge("ONTAP 9.17.1P0", item)  # below the lowest fix P1: decided when P1 was added
    assert below is not None and below.verdict == nam.YES
    assert (below.decisive_date, below.confirm_by) == (D(2030, 1, 10), D(2030, 1, 17))
    fixed = judge("ONTAP 9.17.1P2", item)  # P1 and P2 both fix it; the earliest naming revision decides
    assert fixed is not None and fixed.verdict == nam.NO and fixed.decisive_date == D(2030, 1, 10)


def test_fix_version_in_a_comment_is_matched_as_a_whole_token() -> None:
    item = make_item(
        affected=["ONTAP 9"],
        fixes=["9.17.1P1", "9.17.1P10"],
        revisions=[("1.0", "20300101", "Initial Public Release"), ("2.0", "20300120", "ONTAP 9.17.1P10 added")],
        rev="2.0",
    )
    j = judge("ONTAP 9.17.1P0", item)  # lowest fix is P1; the P10 comment must not decide it
    assert j is not None and j.decisive_date == D(2030, 1, 1)


def test_product_list_move_uses_the_latest_move_and_falls_back_to_the_initial_release() -> None:
    moved = make_item(
        affected=["ONTAP 9"],
        revisions=[
            ("1.0", "20300101", "Initial Public Release"),
            ("2.0", "20300115", "ONTAP 9 moved to Affected Products"),
            ("3.0", "20300201", "Another product moved to Affected Products"),
        ],
        rev="3.0",
    )
    j = judge("ONTAP 9.17.1P7", moved)  # no fix on the line -> pending, decided by the list move
    assert j is not None and j.decisive_date == D(2030, 1, 15)
    unexplained = make_item(
        not_affected=["ONTAP 9"],
        revisions=[("1.0", "20300101", "Initial Public Release"), ("2.0", "20300301", "Text updated")],
        rev="2.0",
    )
    j2 = judge("ONTAP 9.17.1P7", unexplained)
    assert j2 is not None and j2.decisive_date == D(2030, 1, 1) and "initial release" in j2.decisive_source


def test_when_the_product_moved_twice_the_latest_move_decides() -> None:
    item = make_item(
        affected=["ONTAP 9"],
        revisions=[
            ("1.0", "20300101", "Initial Public Release"),
            ("2.0", "20300110", "ONTAP 9 moved to Products Not Affected"),
            ("3.0", "20300120", "ONTAP 9 moved to Affected Products"),
        ],
        rev="3.0",
    )
    j = judge("ONTAP 9.17.1P7", item)
    assert j is not None and j.decisive_date == D(2030, 1, 20) and j.confirm_by == D(2030, 1, 27)


def test_overdue_starts_the_day_after_confirm_by() -> None:
    feed = nam.parse_feed(make_feed([control_item()]))  # decided 2030-01-01, confirm by 2030-01-08
    r = row("ONTAP 9.17.1P1")
    on_day = nam.propose_row(r, feed.advisories, D(2030, 1, 8))
    after = nam.propose_row(r, feed.advisories, D(2030, 1, 9))
    assert (on_day.confirm_by, on_day.overdue, after.overdue) == (D(2030, 1, 8), False, True)


def test_row_verdict_prefers_affected_then_pending_then_not_affected() -> None:
    a_yes = make_item("NTAP-20300101-0001", affected=["ONTAP 9"], fixes=["9.17.1P9"])
    a_pending = make_item("NTAP-20300101-0002", investigating=["ONTAP 9"])
    a_no = make_item("NTAP-20300101-0003", not_affected=["ONTAP 9"])
    advisories = nam.parse_feed(make_feed([a_yes, a_pending, a_no])).advisories
    r = row("ONTAP 9.17.1P1")
    assert nam.propose_row(r, advisories, TODAY).verdict == nam.YES
    assert nam.propose_row(r, advisories[1:], TODAY).verdict == nam.PENDING
    assert nam.propose_row(r, advisories[2:], TODAY).verdict == nam.NO
    assert nam.propose_row(r, advisories[:0], TODAY).verdict is None


def test_since_leaves_out_advisories_updated_before_it() -> None:
    old = make_item("NTAP-20300101-0001", not_affected=["ONTAP 9"])
    new = make_item(
        "NTAP-20300601-0002",
        investigating=["ONTAP 9"],
        pub="Sat, 01 Jun 2030 00:00:00 +0000",
        revisions=[("1.0", "20300601", "Initial Public Release")],
    )
    advisories = nam.parse_feed(make_feed([old, new])).advisories
    proposal = nam.propose_row(row("ONTAP 9.17.1P7"), advisories, TODAY, since=D(2030, 3, 1))
    assert [j.advisory_id for j in proposal.judgments] == ["NTAP-20300601-0002"]
    assert proposal.verdict == nam.PENDING


def test_rows_that_are_not_ontap_versions_are_pending_without_advisory_judgments() -> None:
    advisories = nam.parse_feed(make_feed([control_item()])).advisories
    for version in ("FSx for ONTAP deployment type SINGLE_AZ_1", "TrendAI Vision One File Security 1.2.3"):
        p = nam.propose_row(row(version), advisories, TODAY)
        assert p.verdict == nam.PENDING and p.judgments == () and p.reasons == ("component-not-mapped-to-ontap-9",)


def test_unparseable_ontap_version_is_pending() -> None:
    j = judge("ONTAP next-release", control_item())
    assert j is not None and j.verdict == nam.PENDING and j.reasons == ("unparseable-version",)


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("<rss", "not well-formed"),
        ('<?xml version="1.0"?><feed></feed>', "root element"),
        ('<?xml version="1.0"?><rss version="2.0"></rss>', "<channel>"),
        ('<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>', "no <item>"),
        ('<!DOCTYPE rss [<!ENTITY x "y">]><rss version="2.0"><channel><item/></channel></rss>', "DOCTYPE"),
    ],
)
def test_wrong_shapes_are_rejected(text: str, why: str) -> None:
    with pytest.raises(nam.FeedError, match=why):
        nam.parse_feed(text)


def test_item_without_required_parts_is_rejected() -> None:
    good = make_item()
    for broken in (
        good.replace("<guid>http://example.com/advisory/ntap-20300101-0001/#1.0</guid>", ""),
        good.replace("/#1.0</guid>", "</guid>"),
        good.replace("Tue, 01 Jan 2030 00:00:00 +0000</pubDate>", "yesterday</pubDate>"),
    ):
        with pytest.raises(nam.FeedError):
            nam.parse_feed(make_feed([broken]))


def test_feed_where_most_items_lack_revision_history_is_rejected() -> None:
    no_history = make_item().replace("Revision History", "History")
    with pytest.raises(nam.FeedError, match="Revision History"):
        nam.parse_feed(make_feed([no_history, make_item("NTAP-20300101-0002")] + [no_history.replace("0001", "0003")]))


def test_a_mistyped_revision_date_is_skipped_not_fatal() -> None:
    item = make_item(
        affected=["ONTAP 9"],
        fixes=["9.17.1P2"],
        revisions=[("1.0", "20300101", "Initial"), ("2.0", "20146017", "typo")],
    )
    feed = nam.parse_feed(make_feed([item]))
    assert feed.skipped_revision_rows == 1 and [r.number for r in feed.advisories[0].revisions] == ["1.0"]


def test_parse_failure_is_an_error_with_no_rows_and_no_checked_on() -> None:
    result = nam.run_match("<rss", [row("ONTAP 9.17.1P1")], TODAY, control=CONTROL)
    assert (result.status, result.rows) == ("error", ())
    assert result.error is not None and result.error.startswith("parse:")
    doc = nam.result_to_dict(result, TODAY, "https://example.com/feed")
    assert doc["status"] == "error" and "checked_on" not in doc and "rows" not in doc


def test_missing_control_advisory_is_an_error() -> None:
    feed = make_feed([make_item("NTAP-20300101-0002", affected=["ONTAP 9"], fixes=["9.17.1P2"])])
    result = nam.run_match(feed, [row("ONTAP 9.17.1P1")], TODAY, control=CONTROL)
    assert result.status == "error" and result.rows == ()
    assert result.error is not None and result.error.startswith("control:") and "not in the parsed feed" in result.error


def test_control_advisory_read_wrongly_is_an_error() -> None:
    cases = [
        make_item(affected=["Other Thing"], fixes=["9.16.1P9", "9.17.1P2"]),  # product list changed shape
        make_item(affected=["ONTAP 9"], fixes=["9.16.1P9"]),  # fixed releases not read
        make_item(affected=["ONTAP 9"], fixes=["9.16.1P9", "9.17.1P2"]).replace("Revision History", "History"),
    ]
    for item in cases:
        result = nam.run_match(
            make_feed([item, make_item("NTAP-20300101-0002", not_affected=["ONTAP 9"])]),
            [row("ONTAP 9.17.1P1")],
            TODAY,
            control=CONTROL,
        )
        assert result.status == "error" and result.rows == (), item[:60]


def test_run_match_with_a_readable_control_returns_a_proposal_per_row() -> None:
    feed = make_feed([control_item()])
    rows = [row("ONTAP 9.17.1P1"), row("TrendAI Vision One File Security 1.2.3")]
    result = nam.run_match(feed, rows, TODAY, control=CONTROL)
    assert result.status == "ok" and result.item_count == 1
    assert [p.verdict for p in result.rows] == [nam.YES, nam.PENDING]
    doc = nam.result_to_dict(result, TODAY, "https://example.com/feed")
    assert doc["checked_on"] == TODAY.isoformat() and doc["mapping_tier"] == "hypothesis"
    json.dumps(doc, ensure_ascii=False)


def test_rows_from_private_reads_the_optional_ga_date() -> None:
    doc = {
        "rows": [
            {
                "verified_version": "ONTAP 9.17.1P7",
                "advisory_match": "判定保留",
                "matched_on": None,
                "ga_date": "2030-06-01",
                "file_system_id": "fs-0123456789abcdef0",
            },
            {"verified_version": "ONTAP 9.18.1P6", "advisory_match": "該当なし", "matched_on": "2030-07-01"},
        ]
    }
    rows = nam.rows_from_private(doc)
    assert rows[0].ga_date == D(2030, 6, 1) and rows[1].ga_date is None and rows[1].matched_on == D(2030, 7, 1)


def _write_cli_inputs(tmp_path: Path, feed_text: str) -> tuple[Path, Path, Path]:
    private = tmp_path / "private.json"
    private.write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "verified_version": "ONTAP 9.17.1P1",
                        "advisory_match": "判定保留",
                        "matched_on": None,
                        "ga_date": "2030-06-01",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    feed = tmp_path / "feed.xml"
    feed.write_text(feed_text, encoding="utf-8")
    return private, feed, tmp_path / "out" / "match.json"


def test_cli_custom_control_id_that_is_absent_exits_2_and_writes_nothing(tmp_path: Path) -> None:
    private, feed, out = _write_cli_inputs(tmp_path, make_feed([control_item()]))
    before = private.read_bytes()
    rc = nam.main(
        [
            "--private-ledger",
            str(private),
            "--feed-file",
            str(feed),
            "--out",
            str(out),
            "--today",
            "2031-03-01",
            "--control-id",
            "NTAP-20309999-9999",
        ]
    )
    assert rc == 2 and not out.exists() and private.read_bytes() == before


def test_cli_default_control_id_matches_the_default_fixes(tmp_path: Path) -> None:
    item = make_item(nam.DEFAULT_CONTROL_ID, affected=["ONTAP 9"], fixes=list(nam.DEFAULT_CONTROL_FIXES))
    private, feed, out = _write_cli_inputs(tmp_path, make_feed([item]))
    before = private.read_bytes()
    rc = nam.main(
        ["--private-ledger", str(private), "--feed-file", str(feed), "--out", str(out), "--today", "2031-03-01"]
    )
    assert rc == 1  # 9.17.1P1 is below the first fix; decided 2030-01-01, so overdue at 2031-03-01
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["status"] == "ok" and doc["rows"][0]["proposed"] == nam.YES and doc["rows"][0]["overdue"] is True
    assert private.read_bytes() == before  # the matcher never edits a ledger


def test_cli_exits_0_when_nothing_is_overdue(tmp_path: Path) -> None:
    item = make_item(nam.DEFAULT_CONTROL_ID, affected=["ONTAP 9"], fixes=list(nam.DEFAULT_CONTROL_FIXES))
    private, feed, out = _write_cli_inputs(tmp_path, make_feed([item]))
    assert (
        nam.main(
            ["--private-ledger", str(private), "--feed-file", str(feed), "--out", str(out), "--today", "2030-01-05"]
        )
        == 0
    )


def test_cli_error_exits_2_and_does_not_replace_an_earlier_result(tmp_path: Path) -> None:
    private, feed, out = _write_cli_inputs(tmp_path, "<rss")
    out.parent.mkdir(parents=True)
    out.write_text('{"status": "ok", "checked_on": "2031-02-01"}\n', encoding="utf-8")
    rc = nam.main(
        ["--private-ledger", str(private), "--feed-file", str(feed), "--out", str(out), "--today", "2031-03-01"]
    )
    assert rc == 2 and json.loads(out.read_text(encoding="utf-8"))["checked_on"] == "2031-02-01"


def test_cli_missing_inputs_exit_2(tmp_path: Path) -> None:
    assert nam.main(["--private-ledger", str(tmp_path / "none.json"), "--feed-file", str(tmp_path / "none.xml")]) == 2


def test_fetch_refuses_non_https_urls_before_any_connection() -> None:
    with pytest.raises(nam.FetchError):
        nam.fetch_feed("http://example.com/feed.xml")
    with pytest.raises(nam.FetchError):
        nam.fetch_feed("file:///etc/hosts")

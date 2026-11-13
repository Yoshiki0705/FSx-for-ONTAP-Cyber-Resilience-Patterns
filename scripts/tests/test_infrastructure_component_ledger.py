"""Tests for the Infrastructure_Component_Ledger checker and the committed public ledger.

**Validates: Requirements 5.1, 5.2, 5.3, 5.4, 24.2**
"""

from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path

import check_infrastructure_ledger as ledger
from hypothesis import given, settings
from hypothesis import strategies as st

REPO = Path(__file__).resolve().parents[2]
PUBLIC_PATH = REPO / "docs" / "agent" / "infrastructure-component-ledger.json"


def _public() -> dict:
    return json.loads(PUBLIC_PATH.read_text(encoding="utf-8"))


def _private_from(public: dict) -> dict:
    extra = {k: None for k in ledger.PRIVATE_EXTRA_KEYS}
    return {"rows": [{**row, **extra} for row in public["rows"]]}


def test_committed_public_ledger_is_clean_and_covers_each_component() -> None:
    doc = _public()
    assert ledger.check_public(doc) == []
    names = {r["verified_version"].split(" ")[0] for r in doc["rows"]}
    assert {"ONTAP", "FSx", "TrendAI", "Deep"} <= names
    assert all(r["advisory_match"] == "判定保留" for r in doc["rows"])


def test_extra_key_missing_key_and_bad_values_are_reported() -> None:
    doc = _public()
    bad = copy.deepcopy(doc)
    bad["rows"][0]["component_kind"] = "ontap"
    bad["rows"][1].pop("matched_on")
    bad["rows"][2]["advisory_match"] = "未確認"
    bad["rows"][3]["matched_on"] = "2026-13-40"
    bad["rows"][4]["verified_version"] = "9.1.0"
    problems = ledger.check_public(bad)
    for index in range(5):
        assert any(p.startswith(f"row {index}:") for p in problems), index


def test_d_suffixed_version_cannot_be_decided() -> None:
    bad = _public()
    bad["rows"][1]["advisory_match"] = "該当なし"
    bad["rows"][1]["matched_on"] = "2026-11-01"
    assert any("D-suffixed" in p for p in ledger.check_public(bad))


def test_decided_row_needs_a_date() -> None:
    bad = _public()
    bad["rows"][0]["advisory_match"] = "該当あり"
    assert any("needs matched_on" in p for p in ledger.check_public(bad))


@settings(max_examples=100, deadline=None)
@given(
    kind=st.sampled_from(["fs", "vpc", "subnet", "sg"]),
    tail=st.text(alphabet="0123456789abcdef", min_size=17, max_size=17),
    where=st.sampled_from(["verified_version", "note"]),
)
def test_real_looking_resource_id_is_rejected(kind: str, tail: str, where: str) -> None:
    """A resource ID is rejected in any public string unless it is the placeholder."""
    bad = _public()
    value = f"{kind}-{tail}"
    if where == "note":
        bad["note"] = f"see {value}"
    else:
        bad["rows"][0]["verified_version"] = f"ONTAP 9.18.1P6 {value}"
    expected_clean = value in ("fs-0123456789abcdef0", "vpc-0123456789abcdef0")
    assert (ledger.check_public(bad) == []) is expected_clean


def test_account_id_ip_and_host_are_rejected_but_placeholders_pass() -> None:
    account = "".join(["2", "10", "987", "654", "321"])  # built at run time, not a literal
    ip = ".".join(["172", "20", "1", "5"])
    host = "mgmt-1." + "example-fs.internal"
    for text in (f"ONTAP 9.18.1P6 {account}", f"ONTAP 9.18.1P6 {ip}", f"ONTAP 9.18.1P6 {host}"):
        bad = _public()
        bad["rows"][0]["verified_version"] = text
        assert ledger.check_public(bad), text
    ok = _public()
    ok["rows"][0]["verified_version"] = "ONTAP 9.18.1P6 123456789012 10.0.1.5 fs-0123456789abcdef0"
    assert ledger.check_public(ok) == []


def test_private_ledger_must_hold_every_public_row_with_same_decision() -> None:
    pub = _public()
    priv = _private_from(pub)
    assert ledger.check_private(pub, priv) == []
    missing = copy.deepcopy(priv)
    missing["rows"].pop()
    assert len(ledger.check_private(pub, missing)) == 1
    differs = copy.deepcopy(priv)
    differs["rows"][0]["advisory_match"] = "該当なし"
    assert len(ledger.check_private(pub, differs)) == 1
    short = copy.deepcopy(priv)
    short["rows"][0].pop("file_system_id")
    assert any("missing keys" in p for p in ledger.check_private(pub, short))


def test_rows_older_than_90_days_are_listed_and_the_boundary_is_exclusive() -> None:
    doc = {
        "rows": [
            {"verified_version": "ONTAP 1", "advisory_match": "該当なし", "matched_on": "2026-08-01"},
            {"verified_version": "ONTAP 2", "advisory_match": "該当なし", "matched_on": "2026-08-02"},
            {"verified_version": "ONTAP 3", "advisory_match": "判定保留", "matched_on": None},
        ]
    }
    today = dt.date(2026, 10, 31)  # 91 days after 08-01, 90 days after 08-02
    assert ledger.stale_rows(doc, today) == ["ONTAP 1"]


def test_cli_exit_codes(tmp_path: Path) -> None:
    assert ledger.main(["--public", str(PUBLIC_PATH)]) == 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"rows": []}), encoding="utf-8")
    assert ledger.main(["--public", str(bad)]) == 1
    assert ledger.main(["--public", str(tmp_path / "absent.json")]) == 2

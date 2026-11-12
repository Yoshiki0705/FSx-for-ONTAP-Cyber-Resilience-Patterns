"""Tests for ``supply_chain.vex`` (OpenVEX parser, printer, exclusions)."""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import models, vex

PATH = ".vex/CVE-2026-0001__left-pad.openvex.json"
PURL = "pkg:npm/left-pad@1.3.0"
STAMP = datetime(2026, 11, 10, 1, 2, 3, tzinfo=UTC)


def _policy(statuses: tuple[models.VexStatus, ...] = ("not_affected", "fixed")) -> models.Policy:
    return models.Policy(
        schema_version=1,
        target_repositories=(),
        excluded_repositories=(),
        opening_threshold=models.OpeningThreshold("HIGH", True, True),
        cooldown_days=models.CooldownDays(7, 14),
        automerge_include=(),
        automerge_exclude=(),
        automerge_enabled_repositories=(),
        package_manager_wait=models.CooldownDays(7, 14),
        non_production_paths=(),
        vex_directory=".vex",
        vex_exclude_statuses=statuses,
        vex_approver_role="VEX_Reviewer",
        vex_one_statement_per_document=True,
        vex_malicious_never_suppressed=True,
        response_target=models.ResponseTarget(24, 7, 14),
        max_new_issues_per_repo_per_run=10,
    )


def _statement(**overrides: Any) -> models.VexStatement:  # noqa: ANN401
    base: dict[str, Any] = {
        "vuln_id": "CVE-2026-0001",
        "aliases": (),
        "products": (PURL,),
        "status": "not_affected",
        "justification": "component_not_present",
        "impact_statement": None,
        "timestamp": None,
    }
    base.update(overrides)
    return models.VexStatement(**base)


def _doc(*statements: models.VexStatement, path: str = PATH, **overrides: Any) -> models.VexDocument:  # noqa: ANN401
    base: dict[str, Any] = {
        "id": "https://example.com/vex/1",
        "context": vex.OPENVEX_CONTEXT,
        "author": "https://github.com/example-org/example-repo",
        "role": "VEX_Reviewer",
        "timestamp": STAMP,
        "version": 1,
        "tooling": None,
        "statements": statements or (_statement(),),
        "path": path,
    }
    base.update(overrides)
    return models.VexDocument(**base)


def _data(**overrides: Any) -> dict[str, Any]:  # noqa: ANN401
    """A valid document as a dict (mutate it, then dump)."""
    data: dict[str, Any] = json.loads(vex.render_openvex(_doc()))
    data.update(overrides)
    return data


def _locations(exc: pytest.ExceptionInfo[vex.VexError]) -> set[str]:
    return {v.location for v in exc.value.violations}


# ---- parser -------------------------------------------------------------


def test_parses_the_specification_style_document() -> None:
    text = json.dumps(
        {
            "@context": vex.OPENVEX_CONTEXT,
            "@id": "https://example.com/vex/x",
            "author": "Example Org",
            "role": "Document Creator",
            "timestamp": "2023-01-08T18:02:03.647787998-06:00",
            "version": 3,
            "tooling": "ai-agent-draft/1",
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2023-12345", "aliases": ["GHSA-aaaa-bbbb-cccc"]},
                    "products": [{"@id": PURL}, {"identifiers": {"purl": "pkg:npm/other@2.0.0"}}],
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_in_execute_path",
                    "impact_statement": "evidence",
                    "timestamp": "2023-01-09T00:00:00Z",
                    "last_updated": "ignored",
                }
            ],
        }
    )
    doc = vex.parse_openvex(text, PATH)
    assert doc.timestamp == datetime(2023, 1, 9, 0, 2, 3, 647787, tzinfo=UTC)
    assert doc.timestamp.utcoffset() == timedelta(0)
    assert (doc.role, doc.version, doc.tooling, doc.path) == ("Document Creator", 3, "ai-agent-draft/1", PATH)
    (st_,) = doc.statements
    assert st_.aliases == ("GHSA-aaaa-bbbb-cccc",)
    assert st_.products == (PURL, "pkg:npm/other@2.0.0")
    assert st_.timestamp == datetime(2023, 1, 9, tzinfo=UTC)


def test_multi_statement_document_keeps_every_statement_in_order() -> None:
    doc = _doc(
        _statement(vuln_id="CVE-2026-0001"),
        _statement(vuln_id="CVE-2026-0002", status="affected", justification=None),
        _statement(vuln_id="CVE-2026-0003", status="under_investigation", justification=None),
    )
    parsed = vex.parse_openvex(vex.render_openvex(doc), PATH)
    assert [s.vuln_id for s in parsed.statements] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]


def test_not_affected_without_justification_is_rejected_with_the_statement_index() -> None:
    data = _data()
    data["statements"].append(dict(data["statements"][0]))
    del data["statements"][1]["justification"]
    with pytest.raises(vex.VexError) as info:
        vex.parse_openvex(json.dumps(data), PATH)
    assert _locations(info) == {"statements[1].justification"}


def test_impact_statement_alone_does_not_satisfy_not_affected() -> None:
    data = _data()
    del data["statements"][0]["justification"]
    data["statements"][0]["impact_statement"] = "free text only"
    with pytest.raises(vex.VexError) as info:
        vex.parse_openvex(json.dumps(data), PATH)
    assert "statements[0].justification" in _locations(info)


def test_all_violations_are_collected_not_only_the_first() -> None:
    data = _data()
    del data["@context"]
    data["timestamp"] = "yesterday"
    data["version"] = 0
    data["statements"][0]["status"] = "unknown"
    with pytest.raises(vex.VexError) as info:
        vex.parse_openvex(json.dumps(data), PATH)
    assert _locations(info) == {"@context", "timestamp", "version", "statements[0].status"}
    assert str(info.value).startswith(f"{PATH}: 4 OpenVEX violation(s)")


@pytest.mark.parametrize(
    ("mutate", "location"),
    [
        (lambda d: d.pop("statements"), "statements"),
        (lambda d: d.update(statements="x"), "statements"),
        (lambda d: d.update(**{"@context": "https://openvex.dev/ns/v0.0.1"}), "@context"),
        (lambda d: d.pop("@id"), "@id"),
        (lambda d: d.pop("author"), "author"),
        (lambda d: d.update(version=True), "version"),
        (lambda d: d.update(timestamp="2026-11-10T01:02:03"), "timestamp"),
        (lambda d: d["statements"][0].update(products=[]), "statements[0].products"),
        (lambda d: d["statements"][0].update(products=[{"hashes": {}}]), "statements[0].products[0]"),
        (lambda d: d["statements"][0]["vulnerability"].pop("name"), "statements[0].vulnerability.name"),
        (lambda d: d["statements"][0].update(justification="because"), "statements[0].justification"),
        (lambda d: d["statements"][0].update(timestamp="2026-13-40T00:00:00Z"), "statements[0].timestamp"),
    ],
)
def test_each_nonconforming_input_is_rejected_at_its_location(mutate: Any, location: str) -> None:  # noqa: ANN401
    data = _data()
    mutate(data)
    with pytest.raises(vex.VexError) as info:
        vex.parse_openvex(json.dumps(data), PATH)
    assert location in _locations(info)


@pytest.mark.parametrize(
    "text",
    ["", "{", "[]", '{"a": NaN}', '{"a": 1, "a": 2}', "[" * 100000],
)
def test_broken_json_and_non_objects_raise(text: str) -> None:
    with pytest.raises(vex.VexError) as info:
        vex.parse_openvex(text, PATH)
    assert info.value.violations
    assert info.value.path == PATH


def test_duplicate_key_in_a_valid_looking_document_is_rejected() -> None:
    text = vex.render_openvex(_doc()).replace('"status": "not_affected"', '"status": "fixed", "status": "not_affected"')
    with pytest.raises(vex.VexError) as info:
        vex.parse_openvex(text, PATH)
    assert "duplicate JSON key 'status'" in str(info.value)


def test_timestamps_with_offsets_are_converted_to_utc() -> None:
    data = _data(timestamp="2026-11-10T10:00:00+09:00")
    assert vex.parse_openvex(json.dumps(data), PATH).timestamp == datetime(2026, 11, 10, 1, tzinfo=UTC)
    local = datetime(2026, 11, 10, 10, tzinfo=timezone(timedelta(hours=9)))
    assert local == datetime(2026, 11, 10, 1, tzinfo=UTC)


# ---- printer ------------------------------------------------------------


def test_render_is_deterministic_and_shaped() -> None:
    doc = _doc(_statement(aliases=("GHSA-aaaa-bbbb-cccc",), impact_statement="trace"), tooling="ai-agent-draft")
    text = vex.render_openvex(doc)
    assert text.endswith("}\n")
    assert not text.endswith("\n\n")
    assert "\r" not in text
    data = json.loads(text)
    assert list(data) == sorted(data)
    assert data["timestamp"] == "2026-11-10T01:02:03Z"
    assert data["@context"] == vex.OPENVEX_CONTEXT
    assert "path" not in text
    assert data["statements"][0]["products"] == [{"@id": PURL}]
    assert vex.render_openvex(doc) == text


def test_render_omits_absent_optional_fields() -> None:
    data = json.loads(vex.render_openvex(_doc(_statement(), role=None, tooling=None)))
    assert "role" not in data
    assert "tooling" not in data
    assert set(data["statements"][0]) == {"vulnerability", "products", "status", "justification"}
    assert data["statements"][0]["vulnerability"] == {"name": "CVE-2026-0001"}


def test_render_refuses_a_document_it_would_have_to_write_nonconformingly() -> None:
    bad = _doc(_statement(justification=None))
    with pytest.raises(vex.VexError) as info:
        vex.render_openvex(bad)
    assert "statements[0].justification" in _locations(info)


def test_render_keeps_sub_second_precision_and_non_ascii() -> None:
    stamp = datetime(2026, 11, 10, 1, 2, 3, 123456, tzinfo=UTC)
    doc = _doc(_statement(impact_statement="実行経路に到達しない"), timestamp=stamp)
    text = vex.render_openvex(doc)
    assert "実行経路に到達しない" in text
    assert '"2026-11-10T01:02:03.123456Z"' in text
    assert vex.parse_openvex(text, PATH) == doc


# ---- effective_exclusions -------------------------------------------------


def test_not_affected_and_fixed_exclude_by_name_alias_and_exact_purl() -> None:
    doc = _doc(
        _statement(aliases=("GHSA-aaaa-bbbb-cccc",)),
        _statement(vuln_id="CVE-2026-0002", status="fixed", justification=None, products=("pkg:npm/a@1.0.0",)),
    )
    exclusions, rejected = vex.effective_exclusions([doc], _policy())
    assert rejected == []
    assert set(exclusions) == {
        ("CVE-2026-0001", PURL),
        ("GHSA-aaaa-bbbb-cccc", PURL),
        ("CVE-2026-0002", "pkg:npm/a@1.0.0"),
    }
    assert exclusions[("CVE-2026-0001", PURL)] == vex.VexRef(PATH, "not_affected", "component_not_present")


def test_a_different_version_is_not_matched() -> None:
    exclusions, _ = vex.effective_exclusions([_doc()], _policy())
    assert ("CVE-2026-0001", "pkg:npm/left-pad@1.3.1") not in exclusions
    assert ("CVE-2026-0001", "pkg:npm/left-pad") not in exclusions


@pytest.mark.parametrize("status", ["affected", "under_investigation"])
def test_affected_and_under_investigation_never_exclude(status: models.VexStatus) -> None:
    doc = _doc(_statement(status=status, justification=None))
    assert vex.effective_exclusions([doc], _policy(("not_affected", "fixed", "affected", status))) == ({}, [])


def test_policy_status_list_narrows_the_exclusions() -> None:
    doc = _doc(_statement(), _statement(vuln_id="CVE-2026-0002", status="fixed", justification=None))
    exclusions, _ = vex.effective_exclusions([doc], _policy(("not_affected",)))
    assert set(exclusions) == {("CVE-2026-0001", PURL)}


@pytest.mark.parametrize("status", ["not_affected", "fixed"])
@pytest.mark.parametrize("where", ["name", "alias"])
def test_malicious_statements_are_rejected_not_excluded(status: models.VexStatus, where: str) -> None:
    just = "component_not_present" if status == "not_affected" else None
    kwargs: dict[str, Any] = {"vuln_id": "MAL-2026-1234"} if where == "name" else {"aliases": ("mal-2026-1234",)}
    doc = _doc(_statement(status=status, justification=just, **kwargs))
    assert vex.effective_exclusions([doc], _policy()) == ({}, [(PATH, "malicious_package_not_suppressible")])


@pytest.mark.parametrize("status", ["affected", "under_investigation"])
def test_malicious_statement_with_a_non_excluding_status_is_neither_excluded_nor_rejected(
    status: models.VexStatus,
) -> None:
    doc = _doc(_statement(vuln_id="MAL-2026-1234", status=status, justification=None))
    assert vex.effective_exclusions([doc], _policy()) == ({}, [])


def test_malicious_statement_does_not_block_other_statements_in_the_same_document() -> None:
    doc = _doc(_statement(vuln_id="MAL-2026-1234"), _statement(vuln_id="CVE-2026-0009"))
    exclusions, rejected = vex.effective_exclusions([doc], _policy())
    assert set(exclusions) == {("CVE-2026-0009", PURL)}
    assert rejected == [(PATH, "malicious_package_not_suppressible")]


def test_rejected_lists_a_path_once() -> None:
    doc = _doc(_statement(vuln_id="MAL-2026-1"), _statement(vuln_id="MAL-2026-2", status="fixed", justification=None))
    assert vex.effective_exclusions([doc], _policy())[1] == [(PATH, "malicious_package_not_suppressible")]


def test_result_does_not_depend_on_document_order() -> None:
    first = _doc(_statement(), path=".vex/a.openvex.json")
    second = _doc(_statement(justification="vulnerable_code_not_present"), path=".vex/b.openvex.json")
    one = vex.effective_exclusions([first, second], _policy())
    two = vex.effective_exclusions([second, first], _policy())
    assert one == two
    assert one[0][("CVE-2026-0001", PURL)].path == ".vex/a.openvex.json"


def test_no_documents_gives_empty_results() -> None:
    assert vex.effective_exclusions([], _policy()) == ({}, [])


# ---- properties -----------------------------------------------------------

_digits = st.integers(min_value=0, max_value=9999).map(lambda n: f"{n:04d}")
_vuln_ids = st.one_of(
    st.builds("CVE-20{}-{}".format, st.integers(10, 30).map(str), _digits),
    st.builds("GHSA-{}-{}-{}".format, *[st.text("abcdefghjkmnpqrstvwxz23456789", min_size=4, max_size=4)] * 3),
    st.builds("MAL-20{}-{}".format, st.integers(10, 30).map(str), _digits),
)
_purls = st.builds(
    "pkg:npm/{}@{}.{}.{}".format,
    st.text("abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=8),
    st.integers(0, 20),
    st.integers(0, 20),
    st.integers(0, 20),
)
_stamps = st.datetimes(min_value=datetime(2000, 1, 1), max_value=datetime(2099, 12, 31), timezones=st.just(UTC))
_texts = st.one_of(st.none(), st.text(st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=20))


@st.composite
def _statements(draw: st.DrawFn) -> models.VexStatement:
    status = draw(st.sampled_from(vex.STATUSES))
    justification = draw(st.one_of(st.none(), st.sampled_from(vex.JUSTIFICATIONS)))
    if status == "not_affected" and justification is None:
        justification = draw(st.sampled_from(vex.JUSTIFICATIONS))
    return models.VexStatement(
        vuln_id=draw(_vuln_ids),
        aliases=tuple(draw(st.lists(_vuln_ids, max_size=3))),
        products=tuple(draw(st.lists(_purls, min_size=1, max_size=3))),
        status=status,
        justification=justification,
        impact_statement=draw(_texts),
        timestamp=draw(st.one_of(st.none(), _stamps)),
    )


@st.composite
def _documents(draw: st.DrawFn) -> models.VexDocument:
    return models.VexDocument(
        id="https://example.com/vex/" + draw(st.text("abcdef0123456789", min_size=1, max_size=12)),
        context=vex.OPENVEX_CONTEXT,
        author="https://github.com/example-org/" + draw(st.text("abcdef", min_size=1, max_size=6)),
        role=draw(st.one_of(st.none(), st.just("VEX_Reviewer"))),
        timestamp=draw(_stamps),
        version=draw(st.integers(1, 50)),
        tooling=draw(st.one_of(st.none(), st.just("ai-agent-draft/1"))),
        statements=tuple(draw(st.lists(_statements(), min_size=1, max_size=4))),
        path=".vex/example.openvex.json",
    )


# Feature: cyber-resilience-phase4-supply-chain, Property 3: OpenVEX のラウンドトリップ
@settings(max_examples=200, deadline=None)
@given(_documents())
def test_property_3_round_trip(doc: models.VexDocument) -> None:
    """**Validates: Requirements 11.5, 11.6, 11.7**"""
    event(f"statements={len(doc.statements)}")
    event("has not_affected" if any(s.status == "not_affected" for s in doc.statements) else "no not_affected")
    text = vex.render_openvex(doc)
    parsed = vex.parse_openvex(text, doc.path)
    assert parsed == doc
    assert len(parsed.statements) == len(doc.statements)
    assert vex.render_openvex(parsed) == text


_INJECTIONS = {
    "drop_justification": lambda d: d["statements"][0].pop("justification"),
    "bad_status": lambda d: d["statements"][0].update(status="resolved"),
    "drop_context": lambda d: d.pop("@context"),
    "drop_statements": lambda d: d.pop("statements"),
    "bad_timestamp": lambda d: d.update(timestamp="2026-11-10 01:02:03"),
}
_EXPECTED = {
    "drop_justification": "statements[0].justification",
    "bad_status": "statements[0].status",
    "drop_context": "@context",
    "drop_statements": "statements",
    "bad_timestamp": "timestamp",
}


# Feature: cyber-resilience-phase4-supply-chain, Property 4: 不適合な OpenVEX は部分的な結果なしで拒否される
@settings(max_examples=200, deadline=None)
@given(_documents(), st.sampled_from(sorted(_INJECTIONS)), st.integers(0, 50))
def test_property_4_one_violation_is_rejected_at_its_location(doc: models.VexDocument, kind: str, cut: int) -> None:
    """**Validates: Requirements 11.4, 11.8**"""
    event(kind)
    data = json.loads(vex.render_openvex(doc))
    if kind == "drop_justification":
        data["statements"][0]["status"] = "not_affected"
        data["statements"][0]["justification"] = "component_not_present"
    _INJECTIONS[kind](data)
    with pytest.raises(vex.VexError) as info:
        vex.parse_openvex(json.dumps(data), doc.path)
    assert _EXPECTED[kind] in _locations(info)

    text = vex.render_openvex(doc)
    with pytest.raises(vex.VexError):
        vex.parse_openvex(text[: min(cut, len(text) - 2)], doc.path)  # truncated JSON


# Feature: cyber-resilience-phase4-supply-chain, Property 21: VEX は悪意のあるパッケージの Issue を止めない
@settings(max_examples=200, deadline=None)
@given(st.lists(_documents(), max_size=4))
def test_property_21_malicious_ids_never_reach_the_exclusion_table(docs: list[models.VexDocument]) -> None:
    """**Validates: Requirements 7.12, 11.12**"""
    docs = [dataclasses.replace(d, path=f".vex/{i}.openvex.json") for i, d in enumerate(docs)]
    exclusions, rejected = vex.effective_exclusions(docs, _policy())
    assert all(not key[0].upper().startswith("MAL-") for key in exclusions)
    expected = {
        d.path
        for d in docs
        for s in d.statements
        if s.status in ("not_affected", "fixed") and any(i.startswith("MAL-") for i in (s.vuln_id, *s.aliases))
    }
    event(f"rejected={min(len(expected), 3)}")
    assert {path for path, _ in rejected} == expected
    assert all(reason == "malicious_package_not_suppressible" for _, reason in rejected)
    assert vex.effective_exclusions(list(reversed(docs)), _policy()) == (exclusions, rejected)

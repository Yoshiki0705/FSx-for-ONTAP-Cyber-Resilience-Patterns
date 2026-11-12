"""Property 3: OpenVEX round trip, over the shared ``vex_documents`` generator."""

from __future__ import annotations

import dataclasses
import json
from collections import Counter

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import models, vex

from tests.strategies import supply_chain as sc

_SEEN: Counter[str] = Counter()


def _merge(docs: tuple[models.VexDocument, ...]) -> models.VexDocument:
    """One document holding every statement of ``docs`` (the generator makes one per document)."""
    return dataclasses.replace(docs[0], statements=tuple(s for d in docs for s in d.statements))


def _check(doc: models.VexDocument) -> None:
    text = vex.render_openvex(doc)
    parsed = vex.parse_openvex(text, doc.path)
    assert parsed == doc
    assert len(parsed.statements) == len(doc.statements)
    assert parsed.role == doc.role
    assert parsed.timestamp == doc.timestamp
    for got, want in zip(parsed.statements, doc.statements, strict=True):
        assert (got.vuln_id, got.products, got.status, got.justification) == (
            want.vuln_id,
            want.products,
            want.status,
            want.justification,
        )
    # Rendering the parsed document gives the same bytes (stable output).
    assert vex.render_openvex(parsed) == text
    assert json.loads(text)["statements"] is not None


# Feature: cyber-resilience-phase4-supply-chain, Property 3: OpenVEX のラウンドトリップ
@settings(max_examples=200, deadline=None)
@given(sc.vex_documents(max_size=6))
def _round_trip(docs: tuple[models.VexDocument, ...]) -> None:
    event(f"documents={len(docs)}")
    if not docs:
        _SEEN["empty"] += 1
        return
    merged = _merge(docs)
    for doc in (*docs, merged):
        _check(doc)
    _SEEN["checked"] += 1
    if len(merged.statements) >= 2:
        _SEEN["multi"] += 1
    for s in merged.statements:
        _SEEN[f"status:{s.status}"] += 1
        _SEEN["vuln:MAL" if s.vuln_id.startswith("MAL-") else "vuln:other"] += 1
        _SEEN["aliases" if s.aliases else "no-aliases"] += 1
        _SEEN["timestamp" if s.timestamp else "no-timestamp"] += 1
    _SEEN["role" if merged.role else "no-role"] += 1
    _SEEN["tooling" if merged.tooling else "no-tooling"] += 1


def test_property_3_round_trip_over_valid_documents() -> None:
    """**Validates: Requirements 11.5, 11.6, 11.7**

    ``parse_openvex(render_openvex(d)) == d`` and the second render is byte-identical; the run must
    have covered every status, both roles, MAL- statements and multi-statement documents.
    """
    _SEEN.clear()
    _round_trip()
    assert _SEEN["checked"] >= 100
    for key in (
        "multi",
        "status:not_affected",
        "status:affected",
        "status:fixed",
        "status:under_investigation",
        "vuln:MAL",
        "vuln:other",
        "aliases",
        "no-aliases",
        "timestamp",
        "no-timestamp",
        "role",
        "no-role",
        "tooling",
        "no-tooling",
    ):
        assert _SEEN[key] > 0, key


# Feature: cyber-resilience-phase4-supply-chain, Property 3: OpenVEX のラウンドトリップ
@settings(max_examples=100, deadline=None)
@given(st.data())
def test_property_3_not_affected_always_keeps_its_justification(data: st.DataObject) -> None:
    """**Validates: Requirements 11.5, 11.6**

    Every ``not_affected`` statement carries a justification and keeps it through the round trip.
    """
    docs = data.draw(sc.vex_documents(max_size=6))
    for doc in docs:
        parsed = vex.parse_openvex(vex.render_openvex(doc), doc.path)
        for s in parsed.statements:
            if s.status == "not_affected":
                event("not_affected")
                assert s.justification is not None

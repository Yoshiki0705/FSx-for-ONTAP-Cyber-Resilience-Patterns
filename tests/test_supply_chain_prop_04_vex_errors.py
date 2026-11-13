"""Property 4: a non-conforming OpenVEX document is rejected with no partial result (task 8.9).

Task 8.7 put a smaller version of this property in ``test_supply_chain_vex.py`` (its own document
generator, five injections, one truncation). This file is the dedicated test the task list asks
for: documents come from the shared ``vex_documents`` generator, all six injections of the design
are drawn, and the reported locations must be exactly the injected one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain.models import VexDocument
from supply_chain.vex import STATUSES, VexError, parse_openvex, render_openvex

from tests.strategies import supply_chain as sc

_BAD_STATUSES = ("", "resolved", "Not_Affected", "FIXED", "not affected", "wontfix", 3, None, ["fixed"])
_BAD_TIMESTAMPS = (
    "2026-11-10 01:02:03",
    "2026-13-01T00:00:00Z",
    "2026-11-10T01:02:03",
    "2026-11-10",
    "yesterday",
    "",
)
_KINDS = (
    "drop_justification",
    "bad_status",
    "drop_context",
    "drop_statements",
    "bad_document_timestamp",
    "bad_statement_timestamp",
    "broken_json",
)


@st.composite
def _documents(draw: st.DrawFn) -> VexDocument | None:
    """One generated document with a statement, or ``None`` when four draws were all empty."""
    pool = [doc for _ in range(4) for doc in draw(sc.vex_documents())]
    index = draw(st.integers(0, 10_000))
    return pool[index % len(pool)] if pool else None


def _inject(kind: str, doc: VexDocument, data: dict[str, Any], pick: int) -> str | None:
    """Applies one violation to the decoded document; returns the location it must be reported at."""
    statement = data["statements"][0]
    if kind == "drop_justification":
        statement["status"] = "not_affected"
        statement.pop("justification", None)
        return "statements[0].justification"
    if kind == "bad_status":
        statement["status"] = _BAD_STATUSES[pick % len(_BAD_STATUSES)]
        return "statements[0].status"
    if kind == "drop_context":
        del data["@context"]
        return "@context"
    if kind == "drop_statements":
        del data["statements"]
        return "statements"
    if kind == "bad_document_timestamp":
        data["timestamp"] = _BAD_TIMESTAMPS[pick % len(_BAD_TIMESTAMPS)]
        return "timestamp"
    if kind == "bad_statement_timestamp":
        statement["timestamp"] = _BAD_TIMESTAMPS[pick % len(_BAD_TIMESTAMPS)]
        return "statements[0].timestamp"
    return None


# Feature: cyber-resilience-phase4-supply-chain, Property 4: 不適合な OpenVEX は部分的な結果なしで拒否される
@settings(max_examples=300, deadline=None)
@given(_documents(), st.sampled_from(_KINDS), st.integers(0, 10_000))
def test_one_violation_is_rejected_at_its_location(doc: VexDocument | None, kind: str, pick: int) -> None:
    """**Validates: Requirements 11.4, 11.8**

    A rendered document with exactly one injected violation raises ``VexError`` (so there is no
    returned value), and the violations name exactly the injected location. A document that is cut
    off or has trailing garbage is reported at ``$``.
    """
    if doc is None:
        event("skipped: no document drawn")
        return
    event(kind)
    event(f"status={doc.statements[0].status}")
    text = render_openvex(doc)
    assert parse_openvex(text, doc.path) == doc  # the control: the un-injected text conforms

    if kind == "broken_json":
        body = text.rstrip()
        broken = body[: pick % len(body)] if pick % 2 else body + "}"
        expected: str | None = None
        location = "$"
    else:
        data = json.loads(text)
        location = _inject(kind, doc, data, pick) or ""
        broken = json.dumps(data)
        expected = location

    with pytest.raises(VexError) as info:
        parse_openvex(broken, doc.path)
    error = info.value
    assert error.path == doc.path
    assert error.violations
    locations = {v.location for v in error.violations}
    assert locations == {expected or "$"}
    assert f"{doc.path}: {location}:" in str(error)


def test_status_values_are_the_four_of_the_design() -> None:
    """The bad-status pool contains no valid status, so a rejection is always the injection's doing."""
    assert set(STATUSES) == {"not_affected", "affected", "fixed", "under_investigation"}
    assert not any(isinstance(s, str) and s in STATUSES for s in _BAD_STATUSES)

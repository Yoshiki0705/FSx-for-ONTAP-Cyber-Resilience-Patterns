"""Recovery_Point_Record schema, examples, and the numbers the guide derives from them.

The schema is ``docs/agent/recovery-point-record.schema.json``. The examples are the two
records in ``tests/fixtures/recovery/recovery_point_record/`` (one decision record written by
pillar 3, one restore record written by pillar 2). The guide quotes them, so the tests also
recompute the hash and the RTO values from them.

Feature: cyber-resilience-phase5-recovery-objectives, task 13.3.
**Validates: Requirements 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7, 17.8, 17.11, 17.12**
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "docs" / "agent" / "recovery-point-record.schema.json"
FIXTURES = Path(__file__).parent / "fixtures" / "recovery" / "recovery_point_record"

SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


def load(name: str) -> dict:
    """Read one fixture."""
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def errors(record: dict) -> list[str]:
    """Return the schema error messages for ``record`` (empty when it conforms)."""
    return [e.message for e in VALIDATOR.iter_errors(record)]


def canonical_bytes(record: dict) -> bytes:
    """Serialise a record without ``integrity``: sorted keys, no extra whitespace, UTF-8."""
    body = {k: v for k, v in record.items() if k != "integrity"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_sha256(record: dict) -> str:
    """Return the value ``integrity.record_sha256`` must have."""
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def seconds(later: str, earlier: str) -> int:
    """Return the number of seconds from ``earlier`` to ``later`` (UTC timestamps ending in Z)."""
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return int((datetime.strptime(later, fmt) - datetime.strptime(earlier, fmt)).total_seconds())


def test_schema_is_a_valid_2020_12_schema() -> None:
    """The schema itself is well formed."""
    Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("name", ["valid-decision.json", "valid-restore.json"])
def test_valid_examples_conform(name: str) -> None:
    """Both example records conform to the schema."""
    assert errors(load(name)) == []


@pytest.mark.parametrize(
    "name",
    [
        "invalid-missing-required.json",
        "invalid-bad-timestamp.json",
        "invalid-nested-unknown-key.json",
        "invalid-owner-mix-pillar3-with-restore.json",
        "invalid-owner-mix-pillar2-with-chosen.json",
        "invalid-window-missing.json",
    ],
)
def test_invalid_examples_are_rejected(name: str) -> None:
    """Each non-conforming example fails, and the failing one is the defect its name states."""
    assert errors(load(name)), f"{name} unexpectedly conforms"


def test_invalid_examples_fail_for_the_stated_reason() -> None:
    """A fixture that fails for a different reason than its name would hide a regression."""
    assert any("'chosen' is a required property" in e for e in errors(load("invalid-missing-required.json")))
    assert any("does not match" in e for e in errors(load("invalid-bad-timestamp.json")))
    assert any("surprise" in e for e in errors(load("invalid-nested-unknown-key.json")))
    assert any("suspected_compromise_window" in e for e in errors(load("invalid-window-missing.json")))


def test_missing_top_level_required_fields_are_each_rejected() -> None:
    """Dropping any always-required field fails the schema."""
    for field in SCHEMA["required"]:
        record = load("valid-decision.json")
        record.pop(field)
        assert errors(record), field


def test_unknown_top_level_key_is_rejected() -> None:
    """The record object itself rejects unknown keys."""
    record = load("valid-decision.json")
    record["extra"] = 1
    assert errors(record)


@pytest.mark.parametrize(
    "path",
    [
        ("restore", "started_at"),
        ("restore", "data_available_at"),
        ("restore", "accepted_at"),
    ],
)
def test_restore_times_must_be_utc(path: tuple[str, str]) -> None:
    """A timestamp with an offset instead of Z is rejected (the record is UTC only)."""
    record = load("valid-restore.json")
    record[path[0]][path[1]] = "2026-12-01T11:35:00+09:00"
    assert errors(record)


def test_before_compromise_window_needs_the_window() -> None:
    """The rule applies to the rationale code, not to the field being present."""
    record = load("valid-decision.json")
    record.pop("suspected_compromise_window")
    assert errors(record)
    record["chosen"]["rationale_codes"] = ["latest-clean"]
    assert errors(record) == []


def test_candidate_layer_is_not_an_evidence_tier() -> None:
    """``layer`` takes recovery layers only; the evidence tier words belong to ``basis_tier``."""
    record = load("valid-decision.json")
    record["candidates"][0]["layer"] = "documented"
    assert errors(record)
    record = load("valid-decision.json")
    record["suspected_compromise_window"]["basis_tier"] = "ontap-snapshot"
    assert errors(record)


def test_integrity_check_result_uses_the_ledger_words() -> None:
    """``clean``, ``suspicious`` and ``error`` only (the Observability ledger verdicts)."""
    record = load("valid-decision.json")
    record["candidates"][1]["integrity_checks"][0]["result"] = "PASS"
    assert errors(record)


# --- the owner split (P13): derived from x-owner, compared with the allOf rules -----------------


def owned_by(owner: str) -> set[str]:
    """Top-level fields whose ``x-owner`` is ``owner``."""
    return {k for k, v in SCHEMA["properties"].items() if v.get("x-owner") == owner}


def forbidden_in(kind: str) -> set[str]:
    """Fields the ``allOf`` rule for ``authored_by == kind`` forbids (``false`` subschemas)."""
    for rule in SCHEMA["allOf"]:
        const = rule["if"].get("properties", {}).get("authored_by", {}).get("const")
        if const == kind:
            return {k for k, v in rule["then"].get("properties", {}).items() if v is False}
    raise AssertionError(f"no allOf rule for {kind}")


def test_every_property_declares_its_owner() -> None:
    """No field is left without an ``x-owner``."""
    missing = [k for k, v in SCHEMA["properties"].items() if "x-owner" not in v]
    assert missing == []
    assert {v["x-owner"] for v in SCHEMA["properties"].values()} <= {"pillar2", "pillar3", "shared"}


def test_allof_forbids_exactly_the_other_pillars_fields() -> None:
    """A pillar 2 record has no pillar 3 field and the reverse; the rules match x-owner."""
    assert forbidden_in("pillar2") == owned_by("pillar3")
    assert forbidden_in("pillar3") == owned_by("pillar2")


def test_every_foreign_field_is_rejected_in_each_record_kind() -> None:
    """Generate the check from x-owner: put each foreign field into the other kind of record."""
    decision, restore = load("valid-decision.json"), load("valid-restore.json")
    donors = {**decision, **restore}
    for field in sorted(owned_by("pillar3")):
        record = copy.deepcopy(restore)
        record[field] = donors[field]
        assert errors(record), f"pillar2 record accepted pillar3 field {field}"
    for field in sorted(owned_by("pillar2")):
        record = copy.deepcopy(decision)
        record[field] = donors[field]
        assert errors(record), f"pillar3 record accepted pillar2 field {field}"


def test_shared_fields_are_required_in_both_kinds() -> None:
    """The fields both records carry are the always-required ones (plus the two shared extras)."""
    shared = owned_by("shared")
    assert set(SCHEMA["required"]) == shared


# --- the hash (P7) -------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["valid-decision.json", "valid-restore.json"])
def test_example_hash_is_the_canonical_hash(name: str) -> None:
    """The example's ``record_sha256`` is what the documented recipe produces."""
    record = load(name)
    assert record["integrity"]["record_sha256"] == record_sha256(record)


def test_hash_does_not_depend_on_key_order_or_whitespace() -> None:
    """Re-serialising with reversed keys and indentation gives the same hash."""
    record = load("valid-decision.json")
    reordered = json.loads(json.dumps(dict(reversed(list(record.items()))), indent=4))
    assert record_sha256(reordered) == record_sha256(record)


def test_hash_changes_when_any_field_changes() -> None:
    """A one-character change moves the hash."""
    record = load("valid-decision.json")
    changed = copy.deepcopy(record)
    changed["chosen"]["rationale_text"] += "."
    assert record_sha256(changed) != record_sha256(record)


def test_hash_ignores_the_integrity_object() -> None:
    """Changing ``integrity`` (for example ``storage_ref``) does not change the hash input."""
    record = load("valid-decision.json")
    changed = copy.deepcopy(record)
    changed["integrity"]["storage_ref"] = "<append-only-store>"
    assert record_sha256(changed) == record_sha256(record)


def test_chain_links_the_two_examples() -> None:
    """The first record has no predecessor and the restore record points at the decision record."""
    decision, restore = load("valid-decision.json"), load("valid-restore.json")
    assert decision["integrity"].get("prev_record_sha256") is None
    assert restore["integrity"]["prev_record_sha256"] == decision["integrity"]["record_sha256"]
    assert (decision["service"], decision["incident_ref"]) == (restore["service"], restore["incident_ref"])
    assert restore["decision_ref"] == decision["record_id"]


# --- RTO values computed from the two records (Requirement 17.6) --------------------------------


def test_two_records_give_s_decide_and_both_rto_values() -> None:
    """S_decide, RTO (T2 to T6), RTO (T3 to T6) and S_restore, as the guide's example states them."""
    decision, restore = load("valid-decision.json"), load("valid-restore.json")
    t2, t3 = restore["declared_at"], decision["decided_at"]
    t4, t5, t6 = (restore["restore"][k] for k in ("started_at", "data_available_at", "accepted_at"))
    assert seconds(t3, t2) == 1800  # S_decide
    assert seconds(t6, t2) == 2715  # RTO (T2 to T6)
    assert seconds(t6, t3) == 915  # RTO (T3 to T6)
    assert seconds(t4, t3) == 300  # S_prepare
    assert seconds(t5, t4) == 15  # S_restore
    assert seconds(t6, t5) == 600  # S_accept


def test_s_decide_does_not_use_decision_started_at() -> None:
    """``decision_started_at`` splits S_decide; the definition stays decided_at minus declared_at."""
    decision, restore = load("valid-decision.json"), load("valid-restore.json")
    wait = seconds(decision["decision_started_at"], restore["declared_at"])
    deliberation = seconds(decision["decided_at"], decision["decision_started_at"])
    assert wait + deliberation == seconds(decision["decided_at"], restore["declared_at"])


def test_restore_completed_at_is_separate_from_t5() -> None:
    """The example keeps the two times apart so the guide can say they differ."""
    restore = load("valid-restore.json")["restore"]
    assert restore["completed_at"] != restore["data_available_at"]


# --- the examples stay free of real identifiers (Requirement 17.7) ------------------------------


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.json")))
def test_fixtures_hold_no_real_identifiers(name: str) -> None:
    """No account ID, AWS resource ID, IP address or e-mail address appears in a fixture."""
    import re

    text = (FIXTURES / name).read_text(encoding="utf-8")
    patterns = [
        r"\b\d{12}\b",
        r"\b(?:fs|fsvol|vol|svm|i|sg|vpc|subnet)-[0-9a-f]{8,}\b",
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        r"[\w.+-]+@[\w-]+\.[\w.]+",
    ]
    for pattern in patterns:
        assert not re.search(pattern, text), (name, pattern)

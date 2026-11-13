"""Coverage test: the Policy_File schema and ``parse_policy`` cover each other.

Task 8.6, Requirement 21.6. ``test_supply_chain_policy.py`` already compares the
parser's tables with the schema file. This file goes one step further: it walks
the schema at run time, lists every location that carries a rule (``required``,
``enum``, ``const``, bounds, ``minItems``, ``uniqueItems``, ``contains``,
``pattern``, ``minLength``, ``type``), and checks that ``parse_policy`` really
reacts to a violation at each one. A rule added to the schema without a parser
change makes one of these tests fail; so does a schema keyword this file does
not know how to exercise. Every walk asserts it found something, so an empty
walk fails instead of passing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from supply_chain.policy import PolicyError, PolicyIssue, parse_policy

from tests.test_supply_chain_policy import valid_doc

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "docs" / "agent" / "supply-chain-policy.schema.json"

# Keywords the tests below know how to exercise. A new keyword in the schema must be
# added here together with a test (and a parser rule), or ``test_schema_keywords_are_known`` fails.
KNOWN_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "title",
        "$defs",
        "$ref",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "const",
        "enum",
        "minimum",
        "maximum",
        "minItems",
        "uniqueItems",
        "contains",
        "pattern",
        "minLength",
    }
)

SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _resolve(node: dict[str, Any]) -> dict[str, Any]:
    """Replaces a ``$ref`` into ``$defs`` with the referenced schema."""
    if "$ref" in node:
        name = node["$ref"].rsplit("/", 1)[-1]
        return {**SCHEMA["$defs"][name], **{k: v for k, v in node.items() if k != "$ref"}}
    return node


def schema_nodes() -> dict[str, dict[str, Any]]:
    """Every subschema of the document, keyed by table path (``$.a.b[].c``)."""
    out: dict[str, dict[str, Any]] = {}

    def walk(raw: dict[str, Any], path: str) -> None:
        node = _resolve(raw)
        out[path] = node
        for key, child in node.get("properties", {}).items():
            walk(child, f"{path}.{key}")
        if "items" in node:
            walk(node["items"], f"{path}[]")

    walk(SCHEMA, "$")
    return out


def every_keyword() -> set[str]:
    """All keywords used anywhere in the schema, including ``contains`` and ``$defs``."""
    found: set[str] = set()

    def walk(node: dict[str, Any]) -> None:
        found.update(node)
        for child in node.get("properties", {}).values():
            walk(child)
        for key in ("items", "contains"):
            if key in node:
                walk(node[key])
        for child in node.get("$defs", {}).values():
            walk(child)

    walk(SCHEMA)
    return found


NODES = schema_nodes()


def steps_of(path: str) -> list[str | int]:
    """Splits a table path into dict keys and (index 0) array steps."""
    steps: list[str | int] = []
    for part in path[2:].split("."):
        if not part:
            continue
        name, _, rest = part.partition("[")
        steps.append(name)
        if rest:
            steps.append(0)
    return steps


def concrete(path: str) -> str:
    """The issue path of the first element: ``$.a[].b`` becomes ``$.a[0].b``."""
    return path.replace("[]", "[0]")


def get_at(doc: Any, path: str) -> Any:
    node = doc
    for step in steps_of(path):
        node = node[step]
    return node


def set_at(doc: dict[str, Any], path: str, value: Any) -> None:
    steps = steps_of(path)
    node: Any = doc
    for step in steps[:-1]:
        node = node[step]
    node[steps[-1]] = value


def del_at(doc: dict[str, Any], path: str) -> None:
    steps = steps_of(path)
    node: Any = doc
    for step in steps[:-1]:
        node = node[step]
    del node[steps[-1]]


def issues_for(doc: Any) -> list[PolicyIssue]:
    """Issues from parsing ``doc``; empty when it parses."""
    try:
        parse_policy(json.dumps(doc))
    except PolicyError as exc:
        return exc.issues
    return []


def has(issues: list[PolicyIssue], path: str, kind: str) -> bool:
    return any(i.path == path and i.kind == kind for i in issues)


def sample_item(items: dict[str, Any]) -> Any:
    """A value that satisfies an array's ``items`` schema."""
    node = _resolve(items)
    if "const" in node:
        return node["const"]
    if "enum" in node:
        return node["enum"][0]
    if "pattern" in node:
        return "example-org/service-a"
    return "example"


def wrong_type(node: dict[str, Any]) -> Any:
    """A value whose JSON type differs from ``node['type']``."""
    return 5 if node["type"] == "string" else "not-" + node["type"]


def nodes_with(keyword: str) -> dict[str, dict[str, Any]]:
    found = {p: n for p, n in NODES.items() if keyword in n}
    assert found, f"the schema has no {keyword!r} rule; this test would check nothing"
    return found


# --- the schema is fully enumerated -------------------------------------------------


def test_schema_is_enumerated() -> None:
    """The walk finds the schema's locations; an empty walk would make every probe vacuous."""
    assert len(NODES) > 40


def test_schema_keywords_are_known() -> None:
    """A keyword this file does not exercise fails the test, so new rules cannot slip in."""
    assert every_keyword() - KNOWN_KEYWORDS == set()


# --- required / optional / unknown keys ---------------------------------------------


def test_every_required_key_is_enforced_and_every_optional_key_is_allowed() -> None:
    objects = nodes_with("properties")
    checked_required = checked_optional = 0
    for path, node in objects.items():
        required = set(node.get("required", []))
        for key in node["properties"]:
            doc = valid_doc()
            assert key in get_at(doc, path), f"the base document lacks {path}.{key}"
            del_at(doc, f"{path}.{key}")
            issues = issues_for(doc)
            where = f"{concrete(path)}.{key}"
            if key in required:
                assert has(issues, where, "missing"), where
                checked_required += 1
            else:
                assert not [i for i in issues if i.path == where], where
                checked_optional += 1
    assert checked_required >= 25
    assert checked_optional >= 1


def test_every_object_rejects_an_unknown_key() -> None:
    objects = {p: n for p, n in nodes_with("additionalProperties").items() if n["additionalProperties"] is False}
    assert len(objects) == len(nodes_with("properties"))
    for path in objects:
        doc = valid_doc()
        get_at(doc, path)["not_in_schema"] = 1
        assert has(issues_for(doc), f"{concrete(path)}.not_in_schema", "unknown_key"), path


def test_root_and_object_type_mismatches_are_reported() -> None:
    for path, node in nodes_with("properties").items():
        doc: Any = ["not", "an", "object"]
        if path != "$":
            doc = valid_doc()
            set_at(doc, path, [])
        assert has(issues_for(doc), concrete(path), "type"), path


# --- value rules ---------------------------------------------------------------------


def test_every_declared_type_is_enforced() -> None:
    typed = {p: n for p, n in nodes_with("type").items() if n["type"] in ("boolean", "integer", "string", "array")}
    for path, node in typed.items():
        doc = valid_doc()
        if path.endswith("[]"):
            parent = get_at(doc, path[:-2])
            if not parent:
                parent.append(sample_item(NODES[path[:-2]]["items"]))
        set_at(doc, path, wrong_type(node))
        assert has(issues_for(doc), concrete(path), "type"), path
    assert len(typed) >= 20


def test_every_enum_value_is_accepted_and_others_are_rejected() -> None:
    values_checked = 0
    for path, node in nodes_with("enum").items():
        where = concrete(path)
        for value in node["enum"]:
            doc = valid_doc()
            parent = path[:-2] if path.endswith("[]") else None
            if parent is not None and not get_at(doc, parent):
                set_at(doc, parent, [value])
            else:
                set_at(doc, path, value)
            assert not [i for i in issues_for(doc) if i.path == where], (path, value)
            values_checked += 1
        doc = valid_doc()
        if path.endswith("[]") and not get_at(doc, path[:-2]):
            set_at(doc, path[:-2], ["not-allowed"])
        else:
            set_at(doc, path, "not-allowed")
        assert has(issues_for(doc), where, "range"), path
    assert values_checked >= 16


def test_every_const_is_accepted_and_other_values_and_types_are_rejected() -> None:
    for path, node in nodes_with("const").items():
        want = node["const"]
        where = concrete(path)
        for value, kind in (
            ((not want) if isinstance(want, bool) else (want + 1 if isinstance(want, int) else want + "-x"), "range"),
            ("x" if not isinstance(want, str) else 0, "type"),
        ):
            doc = valid_doc()
            if path.endswith("[]") and not get_at(doc, path[:-2]):
                set_at(doc, path[:-2], [value])
            else:
                set_at(doc, path, value)
            assert has(issues_for(doc), where, kind), (path, value)
        doc = valid_doc()
        if path.endswith("[]") and not get_at(doc, path[:-2]):
            set_at(doc, path[:-2], [want])
        else:
            set_at(doc, path, want)
        assert not [i for i in issues_for(doc) if i.path == where], path


def test_every_integer_bound_is_enforced_on_both_sides() -> None:
    bounds = {p: n for p, n in NODES.items() if n.get("type") == "integer"}
    assert len(bounds) >= 8
    for path, node in bounds.items():
        where = concrete(path)
        low, high = node["minimum"], node.get("maximum")
        for value, ok in [(low, True), (low - 1, False), (True, False)] + (
            [(high, True), (high + 1, False)] if high is not None else []
        ):
            doc = valid_doc()
            set_at(doc, path, value)
            # Order rules between sibling fields (major >= default) are not bound rules.
            issues = [i for i in issues_for(doc) if i.path == where and (i.kind == "type" or "is outside" in i.detail)]
            assert bool(issues) is not ok, (path, value)


def test_every_min_items_is_enforced() -> None:
    for path, node in nodes_with("minItems").items():
        doc = valid_doc()
        short = list(get_at(doc, path))[: node["minItems"] - 1]
        set_at(doc, path, short)
        assert has(issues_for(doc), concrete(path), "range"), path


def test_every_unique_items_is_enforced() -> None:
    for path, node in nodes_with("uniqueItems").items():
        if node["uniqueItems"] is not True:
            continue
        doc = valid_doc()
        item = sample_item(node["items"])
        set_at(doc, path, [item, item])
        assert has(issues_for(doc), f"{concrete(path)}[1]", "duplicate"), path


def test_every_contains_is_enforced() -> None:
    for path, node in nodes_with("contains").items():
        needed = node["contains"]["const"]
        doc = valid_doc()
        others = [v for v in NODES[f"{path}[]"]["enum"] if v != needed][:1]
        set_at(doc, path, others)
        assert has(issues_for(doc), path, "missing"), path


def test_every_pattern_is_enforced() -> None:
    for path, node in nodes_with("pattern").items():
        doc = valid_doc()
        if not get_at(doc, path[:-2]):
            set_at(doc, path[:-2], [sample_item(node)])
        set_at(doc, path, "not a repository")
        assert has(issues_for(doc), concrete(path), "format"), path


def test_every_min_length_is_enforced() -> None:
    for path, node in nodes_with("minLength").items():
        assert node["minLength"] == 1
        doc = valid_doc()
        set_at(doc, path[:-2], [""])
        assert has(issues_for(doc), concrete(path), "range"), path

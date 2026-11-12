"""Example tests for the Policy_File parser, printer and schema (task 8.2).

Property tests for the round trip (Property 1) and for error reporting
(Property 2) are separate tasks (8.4, 8.5).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from supply_chain import policy as policy_module
from supply_chain.models import Policy, Repo
from supply_chain.policy import PolicyError, PolicyIssue, parse_policy, render_policy

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "docs" / "agent" / "supply-chain-policy.schema.json"


def valid_doc() -> dict[str, Any]:
    """A minimal valid Policy_File built from synthetic repositories."""
    return {
        "schema_version": 1,
        "target_repositories": ["example-org/service-a", "example-org/service-b"],
        "excluded_repositories": list(policy_module.DEFAULT_EXCLUDED_REPOSITORIES),
        "opening_threshold": {
            "min_cvss_severity": "HIGH",
            "open_if_kev_listed": True,
            "open_if_malicious": True,
            "epss_used_for_opening": False,
        },
        "cooldown_days": {"default": 3, "major": 7},
        "package_manager_wait": {"default_days": 3, "major_days": 7},
        "dependency_scope": {"non_production_paths": ["tests/", "docs/"]},
        "automerge": {
            "enabled_repositories": [],
            "include": [{"manager": "npm", "dep_types": ["devDependencies"], "update_types": ["patch"]}],
            "exclude": ["vulnerability_fix", "major", "hub_reusable_workflow"],
        },
        "vex": {
            "directory": ".vex",
            "exclude_statuses": ["not_affected", "fixed"],
            "approver_role": "VEX_Reviewer",
            "one_statement_per_document": True,
            "malicious_never_suppressed": True,
        },
        "response_target": {"detect_hours": 24, "fix_days_kev_or_malicious": 7, "fix_days_high": 14},
        "issue_limits": {"max_new_issues_per_repo_per_run": 10},
    }


def dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc)


def issues_of(text: str) -> list[PolicyIssue]:
    with pytest.raises(PolicyError) as info:
        parse_policy(text)
    return info.value.issues


def has(issues: list[PolicyIssue], path: str, kind: str) -> bool:
    return any(i.path == path and i.kind == kind for i in issues)


def mutated(path: list[str | int], value: Any) -> dict[str, Any]:
    doc = valid_doc()
    node: Any = doc
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    return doc


def test_valid_document_parses() -> None:
    policy = parse_policy(dump(valid_doc()))
    assert isinstance(policy, Policy)
    assert len(policy.target_repositories) == 2
    assert len(policy.excluded_repositories) == 4
    assert policy.cooldown_days.major == 7
    assert policy.package_manager_wait.default == 3
    assert policy.automerge_enabled_repositories == ()
    assert policy.automerge_include[0].dep_types == ("devDependencies",)
    assert policy.response_target.fix_days_high == 14


def test_dep_types_is_optional() -> None:
    doc = valid_doc()
    del doc["automerge"]["include"][0]["dep_types"]
    policy = parse_policy(dump(doc))
    assert policy.automerge_include[0].dep_types == ()


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("", "invalid_json"),
        ("{", "invalid_json"),
        ('{"schema_version": NaN}', "invalid_json"),
        ("[]", "type"),
        ('"x"', "type"),
    ],
)
def test_broken_json_or_wrong_root(text: str, kind: str) -> None:
    issues = issues_of(text)
    assert [(i.path, i.kind) for i in issues] == [("$", kind)]


def test_missing_required_key_is_reported_with_path() -> None:
    doc = valid_doc()
    del doc["cooldown_days"]["major"]
    del doc["vex"]
    issues = issues_of(dump(doc))
    assert has(issues, "$.cooldown_days.major", "missing")
    assert has(issues, "$.vex", "missing")


@pytest.mark.parametrize(
    ("path", "value", "where"),
    [
        (["cooldown_days", "default"], "3", "$.cooldown_days.default"),
        (["cooldown_days", "default"], True, "$.cooldown_days.default"),
        (["cooldown_days", "default"], 3.0, "$.cooldown_days.default"),
        (["opening_threshold", "open_if_kev_listed"], "yes", "$.opening_threshold.open_if_kev_listed"),
        (["opening_threshold", "open_if_malicious"], 1, "$.opening_threshold.open_if_malicious"),
        (["schema_version"], True, "$.schema_version"),
        (["target_repositories"], "example-org/a", "$.target_repositories"),
        (["target_repositories", 0], 5, "$.target_repositories[0]"),
        (["dependency_scope", "non_production_paths", 0], 5, "$.dependency_scope.non_production_paths[0]"),
        (["vex"], [], "$.vex"),
    ],
)
def test_type_errors(path: list[str | int], value: Any, where: str) -> None:
    assert has(issues_of(dump(mutated(path, value))), where, "type")


@pytest.mark.parametrize(
    ("path", "value", "where"),
    [
        (["cooldown_days", "default"], 0, "$.cooldown_days.default"),
        (["cooldown_days", "default"], -1, "$.cooldown_days.default"),
        (["issue_limits", "max_new_issues_per_repo_per_run"], 0, "$.issue_limits.max_new_issues_per_repo_per_run"),
        (["issue_limits", "max_new_issues_per_repo_per_run"], 101, "$.issue_limits.max_new_issues_per_repo_per_run"),
        (["opening_threshold", "min_cvss_severity"], "NONE", "$.opening_threshold.min_cvss_severity"),
        (["opening_threshold", "open_if_malicious"], False, "$.opening_threshold.open_if_malicious"),
        (["opening_threshold", "epss_used_for_opening"], True, "$.opening_threshold.epss_used_for_opening"),
        (["vex", "malicious_never_suppressed"], False, "$.vex.malicious_never_suppressed"),
        (["vex", "exclude_statuses"], [], "$.vex.exclude_statuses"),
        (["vex", "exclude_statuses"], ["affected"], "$.vex.exclude_statuses[0]"),
        (["schema_version"], 2, "$.schema_version"),
        (["target_repositories"], [], "$.target_repositories"),
        (["excluded_repositories"], ["a/b"], "$.excluded_repositories"),
        (["automerge", "include"], [], "$.automerge.include"),
        (["automerge", "include", 0, "update_types"], ["minor"], "$.automerge.include[0].update_types[0]"),
        (["automerge", "include", 0, "manager"], "pip", "$.automerge.include[0].manager"),
        (["dependency_scope", "non_production_paths", 0], "", "$.dependency_scope.non_production_paths[0]"),
    ],
)
def test_range_errors(path: list[str | int], value: Any, where: str) -> None:
    assert has(issues_of(dump(mutated(path, value))), where, "range")


def test_unknown_keys_are_reported_at_every_level() -> None:
    doc = valid_doc()
    doc["extra"] = 1
    doc["vex"]["extra"] = 2
    doc["automerge"]["include"][0]["extra"] = 3
    issues = issues_of(dump(doc))
    assert has(issues, "$.extra", "unknown_key")
    assert has(issues, "$.vex.extra", "unknown_key")
    assert has(issues, "$.automerge.include[0].extra", "unknown_key")


@pytest.mark.parametrize("bad", ["noslash", "a/", "/b", "a/b/c", "-a/b", "a b/c", "a/b\n", "é/x"])
def test_repository_format(bad: str) -> None:
    assert has(issues_of(dump(mutated(["target_repositories", 0], bad))), "$.target_repositories[0]", "format")


def test_duplicate_repositories_ignore_case() -> None:
    doc = valid_doc()
    doc["target_repositories"] = ["example-org/service-a", "Example-Org/Service-A"]
    assert has(issues_of(dump(doc)), "$.target_repositories[1]", "duplicate")


def test_target_and_excluded_overlap() -> None:
    doc = valid_doc()
    doc["target_repositories"].append("AWS-Samples/baseline-environment-on-aws")
    assert has(issues_of(dump(doc)), "$.target_repositories[2]", "overlap")


def test_default_exclusions_must_be_present() -> None:
    doc = valid_doc()
    doc["excluded_repositories"][0] = "example-org/other-fork"
    issues = issues_of(dump(doc))
    assert has(issues, "$.excluded_repositories", "missing")
    assert "aws-samples/baseline-environment-on-aws " in " ".join(i.detail + " " for i in issues)


def test_extra_exclusions_are_allowed() -> None:
    doc = valid_doc()
    doc["excluded_repositories"].append("example-org/archived")
    assert len(parse_policy(dump(doc)).excluded_repositories) == 5


def test_major_below_default() -> None:
    doc = valid_doc()
    doc["cooldown_days"] = {"default": 7, "major": 3}
    doc["package_manager_wait"] = {"default_days": 7, "major_days": 3}
    issues = issues_of(dump(doc))
    assert has(issues, "$.cooldown_days.major", "range")
    assert has(issues, "$.package_manager_wait.major_days", "range")


def test_package_manager_wait_must_equal_cooldown() -> None:
    doc = valid_doc()
    doc["package_manager_wait"] = {"default_days": 4, "major_days": 8}
    issues = issues_of(dump(doc))
    assert has(issues, "$.package_manager_wait.default_days", "range")
    assert has(issues, "$.package_manager_wait.major_days", "range")


def test_fix_days_ordering() -> None:
    doc = valid_doc()
    doc["response_target"]["fix_days_kev_or_malicious"] = 15
    assert has(issues_of(dump(doc)), "$.response_target.fix_days_kev_or_malicious", "range")
    doc["response_target"]["fix_days_kev_or_malicious"] = 14  # equal is allowed
    parse_policy(dump(doc))


def test_enabled_repositories_must_be_targets() -> None:
    doc = valid_doc()
    doc["automerge"]["enabled_repositories"] = ["EXAMPLE-ORG/service-a", "example-org/unknown"]
    issues = issues_of(dump(doc))
    assert [i.path for i in issues] == ["$.automerge.enabled_repositories[1]"]
    doc["automerge"]["enabled_repositories"] = ["EXAMPLE-ORG/service-a"]
    assert parse_policy(dump(doc)).automerge_enabled_repositories == (Repo("example-org", "service-a"),)


def test_automerge_exclude_needs_vulnerability_fix_and_no_repeats() -> None:
    doc = valid_doc()
    doc["automerge"]["exclude"] = ["major"]
    assert has(issues_of(dump(doc)), "$.automerge.exclude", "missing")
    doc["automerge"]["exclude"] = ["vulnerability_fix", "vulnerability_fix"]
    assert has(issues_of(dump(doc)), "$.automerge.exclude[1]", "duplicate")


def test_duplicate_non_production_paths() -> None:
    doc = valid_doc()
    doc["dependency_scope"]["non_production_paths"] = ["tests/", "tests/"]
    assert has(issues_of(dump(doc)), "$.dependency_scope.non_production_paths[1]", "duplicate")


def test_duplicate_json_keys_at_root_and_nested() -> None:
    text = dump(valid_doc())
    text = text.replace('"schema_version": 1,', '"schema_version": 1, "schema_version": 1,', 1)
    text = text.replace('"default": 3, "major": 7}', '"default": 3, "default": 3, "major": 7}', 1)
    issues = issues_of(text)
    assert has(issues, "$.schema_version", "duplicate")
    assert has(issues, "$.cooldown_days.default", "duplicate")


def test_all_issues_are_collected_not_just_the_first() -> None:
    doc = valid_doc()
    doc["cooldown_days"]["default"] = 0
    doc["issue_limits"]["max_new_issues_per_repo_per_run"] = 101
    doc["vex"]["malicious_never_suppressed"] = False
    doc["target_repositories"] = []
    doc["extra"] = 1
    del doc["response_target"]["detect_hours"]
    issues = issues_of(dump(doc))
    paths = {i.path for i in issues}
    assert {
        "$.cooldown_days.default",
        "$.issue_limits.max_new_issues_per_repo_per_run",
        "$.vex.malicious_never_suppressed",
        "$.target_repositories",
        "$.extra",
        "$.response_target.detect_hours",
    } <= paths
    assert len(issues) >= 6


def test_error_message_names_paths() -> None:
    with pytest.raises(PolicyError, match=r"\$\.cooldown_days\.default"):
        parse_policy(dump(mutated(["cooldown_days", "default"], 0)))


def test_render_is_deterministic_and_formatted() -> None:
    policy = parse_policy(dump(valid_doc()))
    text = render_policy(policy)
    assert text == render_policy(policy)
    assert text.endswith("}\n") and not text.endswith("\n\n")
    assert "\r" not in text
    assert text.startswith('{\n  "automerge": {')
    doc = json.loads(text)
    assert list(doc) == sorted(doc)
    assert doc["opening_threshold"]["epss_used_for_opening"] is False


def test_render_keeps_non_ascii() -> None:
    doc = valid_doc()
    doc["dependency_scope"]["non_production_paths"] = ["テスト/"]
    text = render_policy(parse_policy(dump(doc)))
    assert "テスト/" in text and "\\u" not in text


def test_round_trip_examples() -> None:
    doc = valid_doc()
    doc["automerge"]["enabled_repositories"] = ["example-org/service-b"]
    doc["automerge"]["include"].append({"manager": "github-actions", "update_types": ["patch"]})
    policy = parse_policy(dump(doc))
    text = render_policy(policy)
    assert parse_policy(text) == policy
    assert render_policy(parse_policy(text)) == text


def test_render_of_arbitrary_input_formatting_is_canonical() -> None:
    compact = parse_policy(json.dumps(valid_doc(), separators=(",", ":")))
    spaced = parse_policy(json.dumps(valid_doc(), indent=8))
    assert render_policy(compact) == render_policy(spaced)


# --- schema and parser share the same rules -------------------------------------------


def _walk(node: dict[str, Any], path: str, out: dict[str, dict[str, Any]]) -> None:
    """Collects, per path, the facts the parser tables also hold."""
    facts = out.setdefault(path, {})
    if "const" in node:
        facts["const"] = node["const"]
    if "enum" in node:
        facts["enum"] = tuple(node["enum"])
    if "minItems" in node:
        facts["minItems"] = node["minItems"]
    if "minimum" in node:
        facts["range"] = (node["minimum"], node.get("maximum"))
    if "properties" in node:
        facts["keys"] = tuple(node["properties"])
        facts["required"] = frozenset(node["required"])
        for key, child in node["properties"].items():
            _walk(child, f"{path}.{key}", out)
    if "items" in node:
        _walk(node["items"], f"{path}[]", out)


@pytest.fixture(scope="module")
def schema_facts() -> dict[str, dict[str, Any]]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    facts: dict[str, dict[str, Any]] = {}
    _walk(schema, "$", facts)
    return facts


def test_schema_object_keys_match_parser(schema_facts: dict[str, dict[str, Any]]) -> None:
    schema_objects = {p: f for p, f in schema_facts.items() if "keys" in f}
    assert set(schema_objects) == set(policy_module.OBJECT_KEYS)
    for path, facts in schema_objects.items():
        assert set(facts["keys"]) == set(policy_module.OBJECT_KEYS[path]), path
        assert facts["required"] == policy_module.REQUIRED_KEYS[path], path


def test_schema_enums_consts_ranges_match_parser(schema_facts: dict[str, dict[str, Any]]) -> None:
    enums = {p: f["enum"] for p, f in schema_facts.items() if "enum" in f}
    consts = {p: f["const"] for p, f in schema_facts.items() if "const" in f}
    ranges = {p: f["range"] for p, f in schema_facts.items() if "range" in f}
    items = {p: f["minItems"] for p, f in schema_facts.items() if "minItems" in f}
    assert enums == dict(policy_module.ENUMS)
    assert consts == dict(policy_module.CONSTS)
    assert ranges == dict(policy_module.INT_RANGES)
    assert items == dict(policy_module.MIN_ITEMS)


def test_schema_repo_pattern_matches_parser() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$defs"]["repo"]["pattern"] == policy_module.REPO_PATTERN


def _set_at(doc: dict[str, Any], path: str, value: Any) -> None:
    """Sets the value at a table path such as ``$.automerge.exclude[]`` (first element)."""
    steps: list[str | int] = []
    for part in path[2:].split("."):
        name, _, rest = part.partition("[")
        steps.append(name)
        if rest:
            steps.append(0)
    node: Any = doc
    for step in steps[:-1]:
        node = node[step]
    node[steps[-1]] = value


def test_every_schema_enum_is_enforced(schema_facts: dict[str, dict[str, Any]]) -> None:
    """A value outside each schema enum is rejected at that path."""
    paths = [p for p, f in schema_facts.items() if "enum" in f]
    assert len(paths) == len(policy_module.ENUMS)
    for path in paths:
        doc = valid_doc()
        _set_at(doc, path, "not-allowed")
        where = path.replace("[]", "[0]")
        assert has(issues_of(dump(doc)), where, "range"), path


def test_every_schema_const_is_enforced(schema_facts: dict[str, dict[str, Any]]) -> None:
    """A value of the right type but a different value is rejected at each const."""
    paths = [p for p, f in schema_facts.items() if "const" in f]
    assert len(paths) == len(policy_module.CONSTS)
    for path in paths:
        doc = valid_doc()
        want = schema_facts[path]["const"]
        different = (not want) if isinstance(want, bool) else (want + 1 if isinstance(want, int) else want + "-other")
        _set_at(doc, path, different)
        where = path.replace("[]", "[0]")
        assert has(issues_of(dump(doc)), where, "range"), path

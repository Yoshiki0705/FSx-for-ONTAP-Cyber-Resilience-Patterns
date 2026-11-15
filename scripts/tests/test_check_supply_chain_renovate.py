"""Tests of the ``renovate`` subcommand of the supply-chain gate."""

from __future__ import annotations

import io
import json
import re
import shutil
from pathlib import Path

import check_supply_chain as gate
import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

REPO = Path(__file__).resolve().parents[2]
FIXTURES = gate.FIXTURES_DIR / "renovate"
MODULE = REPO / "scripts" / "supply_chain_checks" / "renovate.py"


@pytest.fixture
def checks(tmp_path: Path) -> Path:
    """A checks directory holding only this subcommand (other modules are other tasks')."""
    target = tmp_path / "_checks"
    target.mkdir()
    shutil.copy(MODULE, target / "renovate.py")
    return target


def _run(checks: Path, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = gate.main(["renovate", *argv], out=out, checks_dir=checks)
    return code, out.getvalue()


def _copy(case: str, tmp_path: Path) -> Path:
    dest = tmp_path / "root"
    shutil.copytree(FIXTURES / case, dest)
    return dest


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("fail-")))
def test_each_failing_fixture_fails_for_its_stated_reason(checks: Path, case: str) -> None:
    want_code, kind = (FIXTURES / case / "EXPECT").read_text(encoding="utf-8").splitlines()[0].split()
    code, text = _run(checks, "--root", str(FIXTURES / case))
    assert code == int(want_code)
    assert f": {kind}:" in text
    assert str(FIXTURES) not in text
    for line in text.splitlines()[:-1]:
        assert re.match(r"^[^:\s]+:\d+: \w+: .+", line), line


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("pass-")))
def test_each_good_fixture_passes_and_scans_files(checks: Path, case: str) -> None:
    code, text = _run(checks, "--root", str(FIXTURES / case))
    assert code == 0, text
    assert "0 violation(s)" in text and "scanned 0" not in text


def test_the_real_repository_passes(checks: Path) -> None:
    code, text = _run(checks, "--root", str(REPO))
    assert code == 0, text
    assert re.search(r"scanned [1-9]\d* file\(s\), 0 violation", text)


def test_selftest_passes_with_failing_and_good_inputs(checks: Path) -> None:
    code, text = _run(checks, "--selftest")
    assert code == 0 and "selftest ok" in text


def test_the_real_preset_fails_when_a_value_is_changed(checks: Path, tmp_path: Path) -> None:
    root = tmp_path / "real"
    (root / "renovate").mkdir(parents=True)
    (root / "docs" / "agent").mkdir(parents=True)
    shutil.copy(REPO / "renovate" / "supply-chain.json", root / "renovate")
    shutil.copy(REPO / "docs" / "agent" / "supply-chain-policy.json", root / "docs" / "agent")
    assert _run(checks, "--root", str(root))[0] == 0
    preset = root / "renovate" / "supply-chain.json"
    data = json.loads(preset.read_text(encoding="utf-8"))
    data["vulnerabilityAlerts"]["automerge"] = True
    preset.write_text(json.dumps(data, indent=2), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and ": automerge:" in text


def test_the_expected_value_comes_from_the_policy_file(checks: Path, tmp_path: Path) -> None:
    root = _copy("pass-base-only", tmp_path)
    policy = root / "docs" / "agent" / "supply-chain-policy.json"
    text = policy.read_text(encoding="utf-8")
    for key in ("cooldown_days", "package_manager_wait"):
        data = json.loads(text)
        data[key] = {k: v + 1 for k, v in data[key].items()}
        text = json.dumps(data, indent=2)
    policy.write_text(text, encoding="utf-8")
    code, out = _run(checks, "--root", str(root))
    assert code == 1
    assert "minimumReleaseAge is 3 days; Policy_File wants 4" in out
    assert "major minimumReleaseAge is 7 days; Policy_File wants 8" in out


def test_violation_line_points_at_the_offending_key(checks: Path) -> None:
    case = FIXTURES / "fail-cooldown-mismatch"
    first = _run(checks, "--root", str(case))[1].splitlines()[0]
    line_no = int(first.split(":")[1])
    source = (case / "renovate" / "supply-chain.json").read_text(encoding="utf-8").split("\n")
    assert '"minimumReleaseAge"' in source[line_no - 1]


def test_an_invalid_policy_file_is_one_violation_and_broken_json_is_unparseable(checks: Path, tmp_path: Path) -> None:
    root = _copy("pass-base-only", tmp_path)
    policy = root / "docs" / "agent" / "supply-chain-policy.json"
    policy.write_text("{}", encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and ": policy:" in text and "Run the policy subcommand" in text
    policy.write_text("{", encoding="utf-8")
    assert _run(checks, "--root", str(root))[0] == 2


def test_a_preset_that_is_not_json_is_unparseable(checks: Path, tmp_path: Path) -> None:
    root = _copy("pass-base-only", tmp_path)
    (root / "renovate" / "supply-chain.json").write_text("{", encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 2 and "not valid JSON" in text


def test_the_hub_guard_before_the_allow_rules_does_not_count(checks: Path, tmp_path: Path) -> None:
    """Later rules win in packageRules, so a Hub guard placed first is overridden by the allow rules."""
    root = _copy("pass-with-automerge-preset", tmp_path)
    preset = root / "renovate" / "supply-chain-automerge.json"
    data = json.loads(preset.read_text(encoding="utf-8"))
    rules = data["packageRules"]
    data["packageRules"] = [r for r in rules if "matchPackageNames" in r] + [
        r for r in rules if "matchPackageNames" not in r
    ]
    preset.write_text(json.dumps(data, indent=2), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and ": missing:" in text


def test_required_checks_must_be_a_count_of_one_or_more_for_each_enabled_repository(
    checks: Path, tmp_path: Path
) -> None:
    root = _copy("pass-with-automerge-preset", tmp_path)
    record = root / "docs" / "agent" / "automerge-required-checks.json"
    for bad in ({"EXAMPLE-OWNER/REPO-A": 0}, {"example-owner/repo-a": True}, {"example-owner/repo-a": "1"}, {}):
        record.write_text(json.dumps({"required_checks": bad}), encoding="utf-8")
        code, text = _run(checks, "--root", str(root))
        assert code == 1 and ": required_checks:" in text, bad
    record.write_text(json.dumps({"required_checks": {"EXAMPLE-OWNER/REPO-A": 2}}), encoding="utf-8")
    assert _run(checks, "--root", str(root))[0] == 0


def test_no_required_checks_record_is_needed_while_automerge_is_disabled(checks: Path) -> None:
    code, text = _run(checks, "--root", str(FIXTURES / "pass-base-only"))
    assert code == 0 and "required_checks" not in text


# --- T1-02 .. T1-06 -------------------------------------------------------------------------

from supply_chain_checks import renovate as renovate_module  # noqa: E402

HUB_EXTENDS = "github>Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook//renovate/supply-chain#supply-chain-preset-v1.0.0"


def _kinds(case: str) -> list[str]:
    return [v.kind for v in renovate_module.check(FIXTURES / case).violations]


@pytest.mark.parametrize(
    ("case", "kind"),
    [
        ("fail-extends-foreign-preset", "reference"),
        ("fail-extends-hub-lookalike-repo", "reference"),
        ("fail-repo-behaviour-optional", "override"),
        ("fail-repo-ignore-tests", "override"),
        ("fail-repo-ignore-presets", "override"),
        ("fail-repo-rule-disabled", "override"),
        ("fail-repo-alert-age", "override"),
        ("fail-repo-osv-off", "override"),
        ("fail-preset-pin-digest-aged", "missing"),
        ("fail-automerge-third-party-actions", "automerge"),
        ("fail-extends-builtin-disable-alerts", "reference"),
        ("fail-extends-builtin-skip-status-checks", "reference"),
        ("fail-extends-builtin-min-release-age", "reference"),
        ("fail-extends-hub-not-last", "reference"),
        ("fail-preset-rule-shortens-cooldown", "range"),
        # T12-R6-01 / T12-R6-05
        ("fail-override-in-lock-file-maintenance", "override"),
        ("fail-automerge-in-lock-file-maintenance", "override"),
        ("fail-override-in-manager-lock-file-maintenance", "override"),
        ("fail-override-in-vulnerability-alerts-manager", "override"),
        ("fail-override-in-vulnerability-alerts-rule", "override"),
        ("fail-repo-vulnerability-platform-automerge", "override"),
        ("fail-repo-minimum-release-age-sync", "override"),
    ],
)
def test_each_new_fixture_yields_exactly_the_one_stated_finding(case: str, kind: str) -> None:
    assert _kinds(case) == [kind]


def test_hub_reference_is_matched_without_regard_to_case_and_builtins_are_allowed() -> None:
    out: list = []
    data = {
        "extends": [
            "config:recommended",
            ":semanticCommitsDisabled",
            "helpers:pinGitHubActionDigests",
            HUB_EXTENDS.replace("Yoshiki0705", "YOSHIKI0705"),
        ]
    }
    policy = type("P", (), {"automerge_enabled_repositories": []})()
    renovate_module._check_repo_config(out, "renovate.json", json.dumps(data, indent=2), data, policy)
    assert out == []


def test_a_preset_reference_that_differs_from_the_recorded_tag_is_a_violation() -> None:
    policy = type("P", (), {"automerge_enabled_repositories": []})()
    data = {"extends": [HUB_EXTENDS]}
    text = json.dumps(data, indent=2)
    same: list = []
    renovate_module._check_repo_config(
        same, "renovate.json", text, data, policy, {"tag": "supply-chain-preset-v1.0.0", "commit": "a" * 40}
    )
    assert same == []
    moved: list = []
    renovate_module._check_repo_config(
        moved, "renovate.json", text, data, policy, {"tag": "supply-chain-preset-v1.1.0", "commit": "a" * 40}
    )
    assert [v.kind for v in moved] == ["reference"] and "recorded" in moved[0].detail


def test_pin_digest_rule_is_the_only_one_that_may_null_the_cooldown(tmp_path: Path) -> None:
    root = _copy("pass-base-only", tmp_path)
    path = root / "renovate" / "supply-chain.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["packageRules"].append({"matchUpdateTypes": ["minor"], "minimumReleaseAge": None})
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    assert [v.kind for v in renovate_module.check(root).violations] == ["mismatch"]


def test_remaining_min_release_age_exclude_is_warned_about(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    root = _copy("pass-package-managers", tmp_path)
    npmrc = root / ".npmrc"
    npmrc.write_text(npmrc.read_text(encoding="utf-8") + "\nmin-release-age-exclude=left-pad\n", encoding="utf-8")
    with caplog.at_level("WARNING"):
        assert renovate_module.check(root).violations == []
    assert any("min-release-age-exclude" in r.getMessage() and "left-pad" in r.getMessage() for r in caplog.records)


def test_the_built_in_presets_that_weaken_the_hub_preset_are_each_refused() -> None:
    """The four entries of the review's reproduction, and the sibling that sets ``automerge``."""
    policy = type("P", (), {"automerge_enabled_repositories": []})()
    for ref in (
        ":disableVulnerabilityAlerts",
        ":skipStatusChecks",
        ":automergeAll",
        ":automergeStableNonMajor",
        ":disableRenovate",
        ":prImmediately",
        "security:minimumReleaseAgeNpm",
        "group:disableAll",
    ):
        out: list = []
        data = {"extends": ["config:recommended", ref, HUB_EXTENDS]}
        renovate_module._check_repo_config(out, "renovate.json", json.dumps(data, indent=2), data, policy)
        assert [v.kind for v in out] == ["reference"], ref


def test_the_allowlisted_and_parameterized_built_in_presets_pass_before_the_hub_preset() -> None:
    policy = type("P", (), {"automerge_enabled_repositories": []})()
    refs = ["config:best-practices", ":label(dependencies)", ":timezone(Asia/Tokyo)", "group:monorepos", HUB_EXTENDS]
    data = {"extends": refs}
    out: list = []
    renovate_module._check_repo_config(out, "renovate.json", json.dumps(data, indent=2), data, policy)
    assert out == []


# ---- T12-R4-01 / T12-R4-07: the gate reads the file Renovate reads, in Renovate's order
_HUB = "github>Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook//renovate/supply-chain#supply-chain-preset-v1.0.0"
_DISABLED = {"extends": ["config:recommended", ":disableRenovate", _HUB]}
#: The 14 locations of https://docs.renovatebot.com/configuration-options/ (checked 2026-11-14).
_DOCUMENTED_LOCATIONS = [
    "renovate.json", "renovate.jsonc", "renovate.json5",
    ".github/renovate.json", ".github/renovate.jsonc", ".github/renovate.json5",
    ".gitlab/renovate.json", ".gitlab/renovate.jsonc", ".gitlab/renovate.json5",
    ".renovaterc", ".renovaterc.json", ".renovaterc.jsonc", ".renovaterc.json5",
    "package.json",
]  # fmt: skip


def _bare_root(tmp_path: Path) -> Path:
    root = _copy("pass-base-only", tmp_path)
    (root / "renovate.json").unlink()
    return root


def test_the_gate_knows_every_documented_location() -> None:
    import importlib.util  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location("_renovate_under_test", MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert [*module.REPO_CONFIG_PATHS, module.PACKAGE_JSON_PATH] == _DOCUMENTED_LOCATIONS


@pytest.mark.parametrize("location", _DOCUMENTED_LOCATIONS)
def test_a_disabling_preset_is_caught_in_every_documented_location(checks: Path, tmp_path: Path, location: str) -> None:
    root = _bare_root(tmp_path)
    target = root / location
    target.parent.mkdir(parents=True, exist_ok=True)
    body = {"name": "x", "renovate": _DISABLED} if location == "package.json" else _DISABLED
    target.write_text(json.dumps(body), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1, text
    assert "not on the allowlist" in text


@pytest.mark.parametrize(
    "location", [loc for loc in _DOCUMENTED_LOCATIONS if loc.endswith(("5", "c")) and loc != "renovate.json"]
)
def test_a_config_the_gate_cannot_parse_fails_instead_of_passing(checks: Path, tmp_path: Path, location: str) -> None:
    root = _bare_root(tmp_path)
    target = root / location
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("// comment\n" + json.dumps(_DISABLED), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and ": unsupported_config:" in text


def test_two_config_files_fail_because_only_the_first_is_read(checks: Path, tmp_path: Path) -> None:
    root = _copy("pass-base-only", tmp_path)
    (root / ".github").mkdir()
    (root / ".github" / "renovate.json").write_text(
        (root / "renovate.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and ": multiple_config:" in text


def test_a_package_json_without_a_renovate_section_is_not_a_config(checks: Path, tmp_path: Path) -> None:
    root = _copy("pass-base-only", tmp_path)
    (root / "package.json").write_text('{"name": "x"}', encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert ": multiple_config:" not in text and ": reference:" not in text


@pytest.mark.parametrize("key", ["vulnerabilityAlerts", "lockFileMaintenance", "major", "npm"])
def test_extends_in_any_nested_object_is_checked(checks: Path, tmp_path: Path, key: str) -> None:
    root = _copy("pass-base-only", tmp_path)
    doc = json.loads((root / "renovate.json").read_text(encoding="utf-8"))
    doc[key] = {"extends": [":disableRenovate"]}
    (root / "renovate.json").write_text(json.dumps(doc), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and f"{key}.extends" in text


# T12-R5-01: the ban on overriding the preset holds at any depth, not at a list of known places.
_SCOPE_NAMES = st.sampled_from(
    ["npm", "pip_requirements", "major", "minor", "patch", "pin", "digest", "gomod", "x", "lockFileMaintenance"]
)
# Below ``vulnerabilityAlerts`` only a child key (a manager, an update type, packageRules) may be walked into: the
# alert object itself has its own checks. Property paths that pass through it start with it and one child.
_ALERT_CHILD = st.sampled_from(["npm", "major", "packageRules", "lockFileMaintenance"])
_BANNED_VALUES = st.sampled_from(
    [
        ("minimumReleaseAge", "0 days"),
        ("minimumReleaseAge", "1 day"),
        ("enabled", False),
        ("automerge", True),
        ("platformAutomerge", True),
        ("minimumReleaseAgeBuffer", None),
        ("minimumReleaseAgePackageManagerSync", True),
    ]
)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(path=st.lists(_SCOPE_NAMES, min_size=1, max_size=5), banned=_BANNED_VALUES, in_list=st.booleans())
def test_a_forbidden_key_is_found_at_any_depth(
    checks: Path, tmp_path_factory: pytest.TempPathFactory, path: list[str], banned: tuple[str, object], in_list: bool
) -> None:
    assume(not (banned == ("enabled", False) and path[-1] == "lockFileMaintenance"))  # its default, not a stop
    root = tmp_path_factory.mktemp("deep") / "root"
    shutil.copytree(FIXTURES / "pass-base-only", root)
    doc = json.loads((root / "renovate.json").read_text(encoding="utf-8"))
    node: dict[str, object] = {banned[0]: banned[1]}
    for name in reversed(path):
        node = {name: [node] if in_list else node}
    doc.update(node)
    (root / "renovate.json").write_text(json.dumps(doc), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and ": override:" in text, text


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    child=_ALERT_CHILD,
    path=st.lists(_SCOPE_NAMES, min_size=0, max_size=3),
    banned=_BANNED_VALUES.filter(lambda b: b[0] != "enabled"),
    in_list=st.booleans(),
)
def test_a_forbidden_key_below_vulnerability_alerts_is_found(
    checks: Path, tmp_path_factory: pytest.TempPathFactory, child: str, path: list[str], banned: tuple[str, object], in_list: bool
) -> None:
    """T12-R6-01: the alert object is walked through its children, not skipped."""
    root = tmp_path_factory.mktemp("alerts") / "root"
    shutil.copytree(FIXTURES / "pass-base-only", root)
    doc = json.loads((root / "renovate.json").read_text(encoding="utf-8"))
    node: dict[str, object] = {banned[0]: banned[1]}
    for name in reversed([child, *path]):
        node = {name: [node] if in_list else node}
    doc["vulnerabilityAlerts"] = node
    (root / "renovate.json").write_text(json.dumps(doc), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and ": override:" in text, text


def test_lock_file_maintenance_may_be_enabled_false_without_a_violation(checks: Path, tmp_path: Path) -> None:
    """``enabled: false`` is the default of ``lockFileMaintenance`` (Renovate docs), not a stop of updates."""
    root = _copy("pass-base-only", tmp_path)
    doc = json.loads((root / "renovate.json").read_text(encoding="utf-8"))
    doc["lockFileMaintenance"] = {"enabled": False}
    (root / "renovate.json").write_text(json.dumps(doc), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 0, text


@pytest.mark.parametrize("key", ["customManagers", "customDatasources"])
def test_definition_only_keys_are_not_walked_for_option_values(checks: Path, tmp_path: Path, key: str) -> None:
    root = _copy("pass-base-only", tmp_path)
    doc = json.loads((root / "renovate.json").read_text(encoding="utf-8"))
    doc[key] = [{"matchStrings": ["x"], "automerge": True}]
    (root / "renovate.json").write_text(json.dumps(doc), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 0, text


@pytest.mark.parametrize("key", ["minimumReleaseAgeBuffer", "minimumReleaseAgePackageManagerSync", "minimumReleaseAgeFuture"])
def test_any_minimum_release_age_key_is_forbidden_by_prefix(checks: Path, tmp_path: Path, key: str) -> None:
    root = _copy("pass-base-only", tmp_path)
    doc = json.loads((root / "renovate.json").read_text(encoding="utf-8"))
    doc["npm"] = {key: None}
    (root / "renovate.json").write_text(json.dumps(doc), encoding="utf-8")
    code, text = _run(checks, "--root", str(root))
    assert code == 1 and key in text, text
# ---- T12-R7-01: the keys under vulnerabilityAlerts are matched like everywhere else
def _kinds_of_repo_config(extra: dict) -> list[str]:
    policy = type("P", (), {"automerge_enabled_repositories": []})()
    data = {"extends": [HUB_EXTENDS], **extra}
    out: list = []
    renovate_module._check_repo_config(out, "renovate.json", json.dumps(data, indent=2), data, policy)
    return [v.kind for v in out]
@pytest.mark.parametrize(
    "alerts",
    [
        {"minimumReleaseAgeBuffer": None},
        {"minimumReleaseAgePackageManagerSync": True},
        {"MinimumReleaseAge": "0 days"},
        {"PRCREATION": "approval"},
        {"minimumreleaseagebehaviour": "timestamp-required"},
    ],
)
def test_vulnerability_alerts_keys_are_matched_by_prefix_and_without_regard_to_case(alerts: dict) -> None:
    assert _kinds_of_repo_config({"vulnerabilityAlerts": alerts}) == ["override"]
@pytest.mark.parametrize(
    "extra",
    [
        {"vulnerabilityAlerts": [{"automerge": True, "minimumReleaseAge": "0 days"}]},
        {"npm": {"vulnerabilityAlerts": {"minimumReleaseAge": "0 days"}}},
        {"packageRules": [{"matchManagers": ["npm"], "vulnerabilityAlerts": {"minimumReleaseAgeBuffer": None}}]},
    ],
)
def test_vulnerability_alerts_that_are_a_list_or_not_at_the_top_are_still_scanned(extra: dict) -> None:
    assert "override" in _kinds_of_repo_config(extra)
def test_a_clean_top_level_vulnerability_alerts_object_still_passes() -> None:
    assert _kinds_of_repo_config({"vulnerabilityAlerts": {"labels": ["security"]}}) == []

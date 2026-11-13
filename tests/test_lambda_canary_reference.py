"""Lambda_Canary_Reference template tests (Requirement 19.4, design section 12).

Example-based checks on ``templates/event-driven.yaml``: one function per assertion
so a mutation fixture that drops one setting trips exactly one check.

The same checks run on the real template and, through the mutation fixtures, on
one-setting-removed copies of it.

AWS shapes were checked against the AWS SAM developer guide on 2026-11-13:
``AutoPublishAlias`` and ``DeploymentPreference`` (``Type``, ``Alarms``),
``RuntimeManagementConfig`` passed through to ``AWS::Lambda::Function``, and the
``<LogicalId>.Alias`` referenceable property of the generated alias.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.test_templates import _TaggedLoader

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "templates" / "event-driven.yaml"
MUTATIONS_DIR = Path(__file__).parent / "fixtures" / "canary_mutations"

FUNCTION = "EventTransformerLambda"
ALARM = "EventTransformerAliasErrorsAlarm"
ALIAS = "live"
SAM_TRANSFORM = "AWS::Serverless-2016-10-31"
ALIAS_REF = {"Ref": f"{FUNCTION}.Alias"}
# Output names of templates/event-driven.yaml before the canary change (Requirement 19.7).
BASELINE_OUTPUTS = frozenset(
    {
        "SecurityEventQueueUrl",
        "ApprovalQueueUrl",
        "SecurityEventQueueArn",
        "SecurityEventBusName",
        "SecurityAlertTopicArn",
        "QuarantineStateMachineArn",
        "BatchScanResultQueueUrl",
        "BatchScanResultQueueArn",
    }
)


def load(path: Path) -> dict[str, Any]:
    """Load a CloudFormation YAML file; short tags become ``{"Ref": ...}`` style dicts."""
    with open(path) as f:
        return yaml.load(f, Loader=_TaggedLoader)  # noqa: S506


def _props(tpl: dict[str, Any], name: str) -> dict[str, Any]:
    res = tpl.get("Resources", {}).get(name)
    assert isinstance(res, dict), f"resource {name} is missing"
    return res.get("Properties") or {}


def _preference(tpl: dict[str, Any]) -> dict[str, Any]:
    pref = _props(tpl, FUNCTION).get("DeploymentPreference")
    assert isinstance(pref, dict), "DeploymentPreference is missing"
    return pref


def check_transform(tpl: dict[str, Any]) -> None:
    """Transform contains the SAM transform."""
    transform = tpl.get("Transform")
    names = [transform] if isinstance(transform, str) else (transform or [])
    assert SAM_TRANSFORM in names


def check_function_type(tpl: dict[str, Any]) -> None:
    """EventTransformerLambda is an AWS::Serverless::Function."""
    assert tpl["Resources"][FUNCTION]["Type"] == "AWS::Serverless::Function"


def check_autopublish_alias(tpl: dict[str, Any]) -> None:
    """AutoPublishAlias is set once, to the alias name the alarm watches."""
    assert _props(tpl, FUNCTION).get("AutoPublishAlias") == ALIAS


def check_deployment_type(tpl: dict[str, Any]) -> None:
    """DeploymentPreference.Type starts with Canary."""
    kind = _preference(tpl).get("Type")
    assert isinstance(kind, str) and kind.startswith("Canary")


def check_alarms_listed(tpl: dict[str, Any]) -> None:
    """DeploymentPreference.Alarms has at least one element."""
    alarms = _preference(tpl).get("Alarms")
    assert isinstance(alarms, list) and alarms


def check_alarms_resolve(tpl: dict[str, Any]) -> None:
    """Every element of Alarms refers to an alarm resource in the same template."""
    for item in _preference(tpl).get("Alarms", []):
        assert isinstance(item, dict) and set(item) == {"Ref"}, f"not a plain Ref: {item!r}"
        target = tpl["Resources"].get(item["Ref"])
        assert target is not None and target["Type"] == "AWS::CloudWatch::Alarm", item


def check_alarm_metric(tpl: dict[str, Any]) -> None:
    """The alarm watches the Errors metric of AWS/Lambda."""
    props = _props(tpl, ALARM)
    assert props.get("Namespace") == "AWS/Lambda"
    assert props.get("MetricName") == "Errors"


def check_alarm_alias_dimension(tpl: dict[str, Any]) -> None:
    """The alarm has FunctionName and a Resource dimension that ends with the alias."""
    dims = {d["Name"]: d.get("Value") for d in _props(tpl, ALARM).get("Dimensions", [])}
    assert "FunctionName" in dims
    assert f":{ALIAS}" in json.dumps(dims.get("Resource"))


def check_alarm_definition(tpl: dict[str, Any]) -> None:
    """One error in one 60 s window trips the alarm; missing data does not."""
    props = _props(tpl, ALARM)
    assert props.get("Statistic") == "Sum"
    assert props.get("Period") == 60
    assert props.get("EvaluationPeriods") == 1
    assert props.get("Threshold") == 0
    assert props.get("ComparisonOperator") == "GreaterThanThreshold"
    assert props.get("TreatMissingData") == "notBreaching"


def check_runtime_update_on(tpl: dict[str, Any]) -> None:
    """RuntimeManagementConfig.UpdateRuntimeOn is FunctionUpdate."""
    config = _props(tpl, FUNCTION).get("RuntimeManagementConfig")
    assert isinstance(config, dict) and config.get("UpdateRuntimeOn") == "FunctionUpdate"


def check_mapping_event_transformer(tpl: dict[str, Any]) -> None:
    """EventTransformerMapping invokes the alias."""
    assert _props(tpl, "EventTransformerMapping").get("FunctionName") == ALIAS_REF


def check_mapping_batch_scan(tpl: dict[str, Any]) -> None:
    """BatchScanResultMapping invokes the alias."""
    assert _props(tpl, "BatchScanResultMapping").get("FunctionName") == ALIAS_REF


def check_outputs_names(tpl: dict[str, Any]) -> None:
    """Every Outputs name from before the change is still there."""
    missing = BASELINE_OUTPUTS - set(tpl.get("Outputs", {}))
    assert not missing, sorted(missing)


def check_outputs_resolve(tpl: dict[str, Any]) -> None:
    """Every output value refers to a resource or parameter that exists."""
    known = set(tpl.get("Resources", {})) | set(tpl.get("Parameters", {}))
    for name, out in tpl.get("Outputs", {}).items():
        value = out["Value"]
        assert isinstance(value, dict) and len(value) == 1, name
        ((kind, payload),) = value.items()
        target = payload.split(".")[0] if kind == "GetAtt" else payload
        assert kind in {"Ref", "GetAtt"} and target in known, f"{name}: {value!r}"


CHECKS: dict[str, Callable[[dict[str, Any]], None]] = {
    fn.__name__.removeprefix("check_"): fn
    for fn in (
        check_transform,
        check_function_type,
        check_autopublish_alias,
        check_deployment_type,
        check_alarms_listed,
        check_alarms_resolve,
        check_alarm_metric,
        check_alarm_alias_dimension,
        check_alarm_definition,
        check_runtime_update_on,
        check_mapping_event_transformer,
        check_mapping_batch_scan,
        check_outputs_names,
        check_outputs_resolve,
    )
}

# fixture file stem -> the one check it must trip
MUTATIONS: dict[str, str] = {
    "transform_removed": "transform",
    "function_type_lambda": "function_type",
    "alias_removed": "autopublish_alias",
    "deployment_type_all_at_once": "deployment_type",
    "alarms_removed": "alarms_listed",
    "alarm_ref_dangling": "alarms_resolve",
    "alarm_metric_invocations": "alarm_metric",
    "alarm_alias_dimension_removed": "alarm_alias_dimension",
    "alarm_threshold_raised": "alarm_definition",
    "runtime_management_removed": "runtime_update_on",
    "mapping_transformer_unaliased": "mapping_event_transformer",
    "mapping_batch_unaliased": "mapping_batch_scan",
    "output_removed": "outputs_names",
    "output_dangling": "outputs_resolve",
}


def failing_checks(tpl: dict[str, Any]) -> set[str]:
    """Names of the checks that raise AssertionError on ``tpl``."""
    failed: set[str] = set()
    for name, check in CHECKS.items():
        try:
            check(tpl)
        except AssertionError:
            failed.add(name)
    return failed


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_template_check(name: str) -> None:
    """Each assertion of the design's template-test table holds on the real template."""
    CHECKS[name](load(TEMPLATE))


def test_cfn_lint_exits_zero() -> None:
    """``cfn-lint templates/event-driven.yaml`` run alone exits 0 (Requirement 19.4)."""
    exe = shutil.which("cfn-lint", path=str(Path(sys.executable).parent)) or shutil.which("cfn-lint")
    assert exe, "cfn-lint is not installed"
    result = subprocess.run(  # noqa: S603
        [exe, "templates/event-driven.yaml"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_control_fixture_passes_every_check() -> None:
    """The unmutated fixture satisfies all assertions, so a mutation failure is the mutation's."""
    assert failing_checks(load(MUTATIONS_DIR / "control.yaml")) == set()


@pytest.mark.parametrize(("stem", "expected"), sorted(MUTATIONS.items()))
def test_mutation_trips_only_its_check(stem: str, expected: str) -> None:
    """Dropping one setting fails the check for that setting and no other."""
    assert failing_checks(load(MUTATIONS_DIR / f"{stem}.yaml")) == {expected}


def test_every_check_has_a_mutation_and_every_fixture_is_mapped() -> None:
    """Fixtures on disk, the mapping and the checks cover each other exactly."""
    on_disk = {p.stem for p in MUTATIONS_DIR.glob("*.yaml")} - {"control"}
    assert on_disk == set(MUTATIONS)
    assert set(MUTATIONS.values()) == set(CHECKS)

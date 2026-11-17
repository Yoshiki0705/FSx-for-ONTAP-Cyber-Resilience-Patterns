"""Lambda_Canary_Reference template tests (Requirement 19.4, design section 12).

Example-based checks on ``templates/event-driven.yaml``: one function per assertion
so a mutation fixture that drops one setting trips exactly one check.

The same checks run on the real template and, through the mutation fixtures, on
one-setting-removed copies of it.

AWS shapes were checked against the AWS SAM developer guide on 2026-11-13:
``AutoPublishAlias`` and ``DeploymentPreference`` (``Type``, ``Alarms``),
``RuntimeManagementConfig`` passed through to ``AWS::Lambda::Function``, and the
``<LogicalId>.Alias`` referenceable property of the generated alias. On 2026-11-14
the same guide and the Lambda developer guide were checked for ``Hooks.PreTraffic``,
the ``ExecutedVersion`` metric dimension and ``FunctionResponseTypes:
[ReportBatchItemFailures]`` (without it Lambda ignores ``batchItemFailures``).

The alarms are not only ``Errors``. The handler reports most failures by returning
``batchItemFailures``, which never raises and so never reaches ``Errors``; the new
version therefore has its own alarms on ``FailedRecords`` (Embedded Metric Format),
``Duration`` and ``Throttles``, and a PreTraffic hook exercises it when no message
arrives during the canary window.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml

from tests.test_templates import _TaggedLoader

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "templates" / "event-driven.yaml"
MUTATIONS_DIR = Path(__file__).parent / "fixtures" / "canary_mutations"

FUNCTION = "EventTransformerLambda"
ALARM = "EventTransformerAliasErrorsAlarm"
NEW_ERRORS = "EventTransformerNewVersionErrorsAlarm"
NEW_FAILED = "EventTransformerNewVersionFailedRecordsAlarm"
NEW_DURATION = "EventTransformerNewVersionDurationAlarm"
THROTTLES = "EventTransformerThrottlesAlarm"
# Rollback triggers: the alarms named in DeploymentPreference.Alarms. The alias-wide Errors alarm is
# not one of them: while the weights are 90/10 it also counts the old version's errors (T3-R2-06).
CANARY_ALARMS = (NEW_ERRORS, NEW_FAILED, NEW_DURATION, THROTTLES)
NOTIFY_ALARMS = (ALARM, *CANARY_ALARMS)
HOOK = "EventTransformerPreTrafficFunction"
RULE = "EventTransformerDeploymentFailedRule"
TOPIC = "SecurityAlertTopic"
METRIC_NAMESPACE = "FsxnCyberResilience/EventTransformer"
# The list form is required: the SAM transform resolves ``!GetAtt [Fn, Version.Version]`` but left the
# short form ``!GetAtt Fn.Version.Version`` unresolved, and CloudFormation then rejected the alarms with
# "Requested attribute Version.Version does not exist in schema" (one real deployment, ap-northeast-1).
NEW_VERSION_REF = {"GetAtt": ["EventTransformerLambda", "Version.Version"]}
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
    """DeploymentPreference.Alarms names the four new-version alarms."""
    alarms = _preference(tpl).get("Alarms")
    assert isinstance(alarms, list) and alarms
    listed = {item.get("Ref") for item in alarms if isinstance(item, dict)}
    assert set(CANARY_ALARMS) <= listed, sorted(set(CANARY_ALARMS) - listed)


def check_alias_alarm_is_not_a_rollback_trigger(tpl: dict[str, Any]) -> None:
    """The alias-wide Errors alarm stays a notification: it must not roll back a healthy new version."""
    listed = {item.get("Ref") for item in _preference(tpl).get("Alarms", []) if isinstance(item, dict)}
    assert ALARM not in listed


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


def _alarm(tpl: dict[str, Any], name: str) -> dict[str, Any]:
    return _props(tpl, name)


def _dims(tpl: dict[str, Any], name: str) -> dict[str, Any]:
    return {d["Name"]: d.get("Value") for d in _alarm(tpl, name).get("Dimensions", [])}


def check_new_version_errors_alarm(tpl: dict[str, Any]) -> None:
    """The new-version Errors alarm separates the new version from the old one (ExecutedVersion)."""
    props = _alarm(tpl, NEW_ERRORS)
    assert props.get("Namespace") == "AWS/Lambda"
    assert props.get("MetricName") == "Errors"
    dims = _dims(tpl, NEW_ERRORS)
    assert f":{ALIAS}" in json.dumps(dims.get("Resource"))
    assert dims.get("ExecutedVersion") == NEW_VERSION_REF
    assert props.get("Threshold") == 0 and props.get("ComparisonOperator") == "GreaterThanThreshold"


def check_failed_records_alarm(tpl: dict[str, Any]) -> None:
    """The FailedRecords alarm reads the handler's Embedded Metric Format metric for the new version."""
    props = _alarm(tpl, NEW_FAILED)
    assert props.get("Namespace") == METRIC_NAMESPACE
    assert props.get("MetricName") == "FailedRecords"
    assert props.get("Statistic") == "Sum"
    assert props.get("Threshold") == 0 and props.get("ComparisonOperator") == "GreaterThanThreshold"
    assert {"FunctionName", "ExecutedVersion"} <= set(_dims(tpl, NEW_FAILED))
    assert _dims(tpl, NEW_FAILED)["ExecutedVersion"] == NEW_VERSION_REF


def check_duration_alarm(tpl: dict[str, Any]) -> None:
    """The Duration alarm trips at half of the function timeout, for the new version only."""
    props = _alarm(tpl, NEW_DURATION)
    assert props.get("MetricName") == "Duration"
    assert props.get("Statistic") == "Maximum"
    assert _dims(tpl, NEW_DURATION).get("ExecutedVersion") == NEW_VERSION_REF
    timeout = _props(tpl, FUNCTION).get("Timeout")
    assert isinstance(timeout, int)
    assert props.get("Threshold") == timeout * 1000 // 2


def check_throttles_alarm(tpl: dict[str, Any]) -> None:
    """The Throttles alarm trips on one throttled invocation."""
    props = _alarm(tpl, THROTTLES)
    assert props.get("Namespace") == "AWS/Lambda"
    assert props.get("MetricName") == "Throttles"
    assert props.get("Threshold") == 0 and props.get("ComparisonOperator") == "GreaterThanThreshold"


def check_alarm_actions(tpl: dict[str, Any]) -> None:
    """Every canary alarm notifies the alert topic, so a rollback does not pass in silence."""
    for name in NOTIFY_ALARMS:
        assert {"Ref": TOPIC} in _alarm(tpl, name).get("AlarmActions", []), name


def check_pretraffic_hook(tpl: dict[str, Any]) -> None:
    """A PreTraffic hook named CodeDeployHook_* runs before traffic moves (zero-traffic case)."""
    ref = _preference(tpl).get("Hooks", {}).get("PreTraffic")
    assert ref == {"Ref": HOOK}, ref
    res = tpl["Resources"][HOOK]
    assert res["Type"] == "AWS::Serverless::Function"
    assert "CodeDeployHook_" in json.dumps(res["Properties"]["FunctionName"])


def check_rollback_notification_rule(tpl: dict[str, Any]) -> None:
    """A rule sends CodeDeploy FAILURE and STOP to the alert topic."""
    props = _props(tpl, RULE)
    pattern = props["EventPattern"]
    assert pattern["source"] == ["aws.codedeploy"]
    assert set(pattern["detail"]["state"]) >= {"FAILURE", "STOP"}
    assert {"Ref": TOPIC} in [t.get("Arn") for t in props["Targets"]]


def _report_failures(tpl: dict[str, Any], mapping: str) -> None:
    assert _props(tpl, mapping).get("FunctionResponseTypes") == ["ReportBatchItemFailures"]


def check_mapping_event_transformer_reports_failures(tpl: dict[str, Any]) -> None:
    """EventTransformerMapping honors batchItemFailures."""
    _report_failures(tpl, "EventTransformerMapping")


def check_mapping_batch_scan_reports_failures(tpl: dict[str, Any]) -> None:
    """BatchScanResultMapping honors batchItemFailures."""
    _report_failures(tpl, "BatchScanResultMapping")


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
        check_alias_alarm_is_not_a_rollback_trigger,
        check_alarms_resolve,
        check_alarm_metric,
        check_alarm_alias_dimension,
        check_alarm_definition,
        check_new_version_errors_alarm,
        check_failed_records_alarm,
        check_duration_alarm,
        check_throttles_alarm,
        check_alarm_actions,
        check_pretraffic_hook,
        check_rollback_notification_rule,
        check_mapping_event_transformer_reports_failures,
        check_mapping_batch_scan_reports_failures,
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
    "alias_alarm_listed": "alias_alarm_is_not_a_rollback_trigger",
    "alarm_ref_dangling": "alarms_resolve",
    "alarm_metric_invocations": "alarm_metric",
    "alarm_alias_dimension_removed": "alarm_alias_dimension",
    "alarm_threshold_raised": "alarm_definition",
    "alarm_new_version_dimension_removed": "new_version_errors_alarm",
    "alarm_failed_records_metric_errors": "failed_records_alarm",
    "alarm_duration_threshold_timeout": "duration_alarm",
    "alarm_throttles_threshold_raised": "throttles_alarm",
    "alarm_actions_removed": "alarm_actions",
    "alarm_not_listed_new_version": "alarms_listed",
    "pretraffic_removed": "pretraffic_hook",
    "rollback_rule_removed": "rollback_notification_rule",
    "mapping_transformer_no_report_failures": "mapping_event_transformer_reports_failures",
    "mapping_batch_no_report_failures": "mapping_batch_scan_reports_failures",
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


# ---------------------------------------------------------------- PreTraffic hook code
def _hook_module(invoke_result: Callable[[dict[str, Any]], dict[str, Any]] | Exception) -> tuple[Any, MagicMock]:
    """Loads the hook's inline code with fake boto3 clients.

    Args:
        invoke_result: Maps the probe payload to the ``lambda.invoke`` response, or an
            exception to raise.

    Returns:
        The module and the fake CodeDeploy client.
    """
    code = load(TEMPLATE)["Resources"][HOOK]["Properties"]["InlineCode"]
    lambda_client = MagicMock()
    codedeploy = MagicMock()

    def invoke(**kwargs: Any) -> dict[str, Any]:
        if isinstance(invoke_result, Exception):
            raise invoke_result
        assert kwargs["FunctionName"] == "arn:aws:lambda:ap-northeast-1:123456789012:function:f:7"
        return invoke_result(json.loads(kwargs["Payload"]))

    lambda_client.invoke.side_effect = invoke
    fake_boto3 = types.SimpleNamespace(client=lambda name: {"lambda": lambda_client, "codedeploy": codedeploy}[name])
    module = types.ModuleType("hook_under_test")
    saved = sys.modules.get("boto3")
    sys.modules["boto3"] = fake_boto3  # type: ignore[assignment]
    try:
        exec(compile(code, "InlineCode", "exec"), module.__dict__)  # noqa: S102
    finally:
        if saved is None:
            del sys.modules["boto3"]
        else:
            sys.modules["boto3"] = saved
    return module, codedeploy


def _response(result: dict[str, Any], function_error: bool = False) -> dict[str, Any]:
    response: dict[str, Any] = {"Payload": io.BytesIO(json.dumps(result).encode())}
    if function_error:
        response["FunctionError"] = "Unhandled"
    return response


HOOK_EVENT = {"DeploymentId": "d-EXAMPLE", "LifecycleEventHookExecutionId": "hook-1"}


def _reported(codedeploy: MagicMock) -> str:
    codedeploy.put_lifecycle_event_hook_execution_status.assert_called_once()
    kwargs = codedeploy.put_lifecycle_event_hook_execution_status.call_args.kwargs
    assert kwargs["deploymentId"] == "d-EXAMPLE"
    assert kwargs["lifecycleEventHookExecutionId"] == "hook-1"
    return str(kwargs["status"])


@pytest.fixture(autouse=True)
def _hook_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TARGET_VERSION_ARN", "arn:aws:lambda:ap-northeast-1:123456789012:function:f:7")


def test_hook_succeeds_when_the_new_version_validates_the_probe() -> None:
    """The real handler in dry-run mode answers the probe the hook sends: the two stay in step."""
    import event_transformer  # the module under solutions/event-driven-response/lambda

    module, codedeploy = _hook_module(lambda probe: _response(event_transformer.handler(probe, None)))
    assert module.handler(HOOK_EVENT, None) == "Succeeded"
    assert _reported(codedeploy) == "Succeeded"


@pytest.mark.parametrize(
    "result",
    [
        {"dry_run": True, "validated": 0, "batchItemFailures": [{"itemIdentifier": "canary-probe"}]},
        {"dry_run": True, "validated": 0},
        {"statusCode": 200, "published": 1},
        {"dry_run": False, "validated": 1},
    ],
)
def test_hook_fails_when_the_probe_is_not_validated(result: dict[str, Any]) -> None:
    """Anything other than validated == 1 without failures reports Failed."""
    module, codedeploy = _hook_module(lambda _probe: _response(result))
    assert module.handler(HOOK_EVENT, None) == "Failed"
    assert _reported(codedeploy) == "Failed"


def test_hook_fails_on_a_function_error() -> None:
    """A crash in the new version is a failed hook."""
    module, codedeploy = _hook_module(lambda _probe: _response({"errorMessage": "boom"}, function_error=True))
    assert module.handler(HOOK_EVENT, None) == "Failed"
    assert _reported(codedeploy) == "Failed"


def test_hook_reports_failed_when_the_invocation_itself_raises() -> None:
    """A hook that raised without reporting would stall the deployment for an hour."""
    module, codedeploy = _hook_module(RuntimeError("AccessDenied"))
    assert module.handler(HOOK_EVENT, None) == "Failed"
    assert _reported(codedeploy) == "Failed"


def test_emf_namespace_matches_the_alarm() -> None:
    """The handler's metric namespace and the alarm's namespace are the same string."""
    import event_transformer

    assert event_transformer.METRIC_NAMESPACE == METRIC_NAMESPACE == _alarm(load(TEMPLATE), NEW_FAILED)["Namespace"]

"""Integration tests for the end-to-end event flow pipeline.

Validates data transformations at each stage:
  Raw FPolicy event → SQS → Event_Transformer → EventBridge → Step Functions

All tests are mock-based (no real AWS calls).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import patch

import event_transformer
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# --- Test Data ---

SAMPLE_FPOLICY_EVENTS = [
    {
        "source": "scanner",
        "scanner_name": "trendai",
        "event_type": "file_write",
        "verdict": "MALICIOUS",
        "file_system_id": "fs-0123456789abcdef0",
        "svm_id": "svm-0123456789abcdef0",
        "volume_id": "fsvol-0123456789abcdef0",
        "file_path": "/production/documents/malicious.exe",
        "client_ip": "10.0.x.x",
        "user_name": "DOMAIN\\user1",
        "timestamp": "2026-06-25T10:30:00Z",
    },
    {
        "source": "arp",
        "event_type": "ransomware_detected",
        "file_system_id": "fs-0123456789abcdef0",
        "volume_id": "fsvol-0123456789abcdef0",
        "snapshot_name": "anti_ransomware_backup.2026-06-25_1030",
        "affected_files_count": 150,
        "timestamp": "2026-06-25T10:30:00Z",
    },
    {
        "source": "fpolicy",
        "event_type": "file_write",
        "file_system_id": "fs-0123456789abcdef0",
        "file_path": "/production/documents/normal.docx",
        "timestamp": "2026-06-25T10:30:00Z",
    },
]

QUARANTINE_RULE_PATTERN = {
    "source": ["fsxn.cyber-resilience.fpolicy", "fsxn.cyber-resilience.arp"],
    "detail-type": ["MalwareDetected", "RansomwareDetected"],
}


@pytest.fixture(autouse=True)
def patch_event_bus():
    """Patch module-level EVENT_BUS_NAME for all tests in this file."""
    with patch.object(event_transformer, "EVENT_BUS_NAME", "fsxn-cyber-resilience-security-dev"):
        yield


class TestEventTransformerPipeline:
    """Tests for the event transformer stage of the pipeline."""

    @patch.object(event_transformer, "events_client")
    def test_fpolicy_event_produces_correct_eventbridge_entry(self, mock_events):
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[0])}]}
        result = event_transformer.handler(sqs_event, None)

        assert result["published"] == 1
        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["Source"] == "fsxn.cyber-resilience.scanner"
        assert entry["DetailType"] == "MalwareDetected"
        assert entry["EventBusName"] == "fsxn-cyber-resilience-security-dev"

    @patch.object(event_transformer, "events_client")
    def test_arp_event_produces_correct_source(self, mock_events):
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[1])}]}
        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["Source"] == "fsxn.cyber-resilience.arp"
        assert entry["DetailType"] == "RansomwareDetected"


class TestEventBridgeRuleMatching:
    """Tests verifying transformed events match EventBridge rule patterns."""

    @patch.object(event_transformer, "events_client")
    def test_malware_event_matches_quarantine_rule(self, mock_events):
        """MalwareDetected detail-type should trigger the quarantine rule."""
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[0])}]}
        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        # MalwareDetected detail-type triggers quarantine regardless of source
        assert entry["DetailType"] in QUARANTINE_RULE_PATTERN["detail-type"]

    @patch.object(event_transformer, "events_client")
    def test_ransomware_event_matches_quarantine_rule(self, mock_events):
        """RansomwareDetected from ARP should trigger the quarantine rule."""
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[1])}]}
        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["Source"] in QUARANTINE_RULE_PATTERN["source"]
        assert entry["DetailType"] in QUARANTINE_RULE_PATTERN["detail-type"]

    @patch.object(event_transformer, "events_client")
    def test_normal_file_event_does_not_match_quarantine_rule(self, mock_events):
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[2])}]}
        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["DetailType"] not in QUARANTINE_RULE_PATTERN["detail-type"]


TASKS_THAT_MUST_CATCH = [
    "CreateForensicSnapshot",
    "RestrictExportPolicy",
    "SendAlert",
    "NotifyFallback",
    "WaitForApproval",
    "RestoreAccess",
    "CreateFlexClone",
    "NotifyFailure",
    "EscalateTimeout",
]
LAMBDA_TASKS = ["RestrictExportPolicy", "RestoreAccess", "CreateFlexClone"]
# Terminal states that publish to the alert topic. When the topic fails they end in a Fail state.
NOTIFY_TASKS = ["NotifyFailure", "EscalateTimeout"]

_MISSING = object()


def _resolve(data: dict, path: str) -> object:
    """Resolve a dotted JSONPath such as ``$.detail.volumeId``; return _MISSING when absent."""
    node: object = data
    for key in path[2:].split("."):
        if not isinstance(node, dict) or key not in node:
            return _MISSING
        node = node[key]
    return node


def _choose(state: dict, data: dict) -> str:
    """Pick the next state of a Choice whose rules are ``And`` of IsPresent and BooleanEquals."""
    for rule in state["Choices"]:
        matched = True
        for cond in rule["And"]:
            value = _resolve(data, cond["Variable"])
            if "IsPresent" in cond:
                matched = matched and (value is not _MISSING) == cond["IsPresent"]
            elif "BooleanEquals" in cond:
                matched = matched and value is cond["BooleanEquals"]
        if matched:
            return rule["Next"]
    return state["Default"]


class TestStepFunctionsAslValidation:
    """Tests that validate Step Functions ASL references in the template."""

    @pytest.fixture
    def quarantine_asl(self):
        """Load and parse the Step Functions ASL from the CFn template."""
        import yaml

        # Custom loader to handle CloudFormation intrinsic functions (!Sub, !Ref, etc.)
        class CfnLoader(yaml.SafeLoader):
            pass

        def cfn_constructor(loader, tag_suffix, node):
            if isinstance(node, yaml.ScalarNode):
                return {tag_suffix: loader.construct_scalar(node)}
            elif isinstance(node, yaml.SequenceNode):
                return {tag_suffix: loader.construct_sequence(node)}
            elif isinstance(node, yaml.MappingNode):
                return {tag_suffix: loader.construct_mapping(node)}

        CfnLoader.add_multi_constructor("!", cfn_constructor)

        template_path = Path(__file__).parent.parent / "templates" / "event-driven.yaml"
        with open(template_path) as f:
            template = yaml.load(f, Loader=CfnLoader)

        sm = template["Resources"]["QuarantineStateMachine"]
        asl_string = sm["Properties"]["DefinitionString"]["Sub"]
        return json.loads(asl_string)

    def test_asl_starts_at_create_forensic_snapshot(self, quarantine_asl):
        assert quarantine_asl["StartAt"] == "CreateForensicSnapshot"

    def test_asl_has_all_required_states(self, quarantine_asl):
        required = [
            "CreateForensicSnapshot",
            "RestrictExportPolicy",
            "SendAlert",
            "WaitForApproval",
            "ApprovalDecision",
            "RestoreAccess",
            "CreateFlexClone",
            "NotifyFailure",
            "EscalateTimeout",
        ]
        for state in required:
            assert state in quarantine_asl["States"], f"Missing state: {state}"

    def test_asl_quarantine_lambda_referenced(self, quarantine_asl):
        resource = quarantine_asl["States"]["RestrictExportPolicy"]["Resource"]
        assert "${QuarantineLambda.Arn}" in resource

    def test_asl_sns_topic_referenced(self, quarantine_asl):
        params = quarantine_asl["States"]["SendAlert"]["Parameters"]
        assert "${SecurityAlertTopic}" in params["TopicArn"]

    def test_asl_approval_timeout(self, quarantine_asl):
        assert quarantine_asl["States"]["WaitForApproval"]["TimeoutSeconds"] == 86400

    # --- Error handling and data flow -------------------------------------

    @pytest.mark.parametrize("name", TASKS_THAT_MUST_CATCH)
    def test_task_has_a_single_trailing_catch_all(self, quarantine_asl, name):
        catchers = quarantine_asl["States"][name]["Catch"]
        catch_all = [c for c in catchers if "States.ALL" in c["ErrorEquals"]]
        assert len(catch_all) == 1
        assert catch_all[0]["ErrorEquals"] == ["States.ALL"]
        assert catchers[-1] is catch_all[0]

    @pytest.mark.parametrize("name", LAMBDA_TASKS)
    def test_lambda_task_retries_transient_service_errors(self, quarantine_asl, name):
        retriers = quarantine_asl["States"][name]["Retry"]
        retried = {error for r in retriers for error in r["ErrorEquals"]}
        assert {
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException",
            "Lambda.TooManyRequestsException",
        } <= retried
        # The function may already have run when the client times out, so it is not retried.
        assert "Lambda.ClientExecutionTimeoutException" not in retried
        assert all(1 <= r["MaxAttempts"] <= 5 for r in retriers)

    @pytest.mark.parametrize("name", NOTIFY_TASKS)
    def test_notification_task_retries_then_ends_in_a_fail_state(self, quarantine_asl, name):
        state = quarantine_asl["States"][name]
        assert state["Retry"][-1]["ErrorEquals"] == ["States.ALL"]
        assert all(1 <= r["MaxAttempts"] <= 5 for r in state["Retry"])
        assert state["Catch"][-1]["Next"] == "NotificationFailed"
        failed = quarantine_asl["States"]["NotificationFailed"]
        assert failed["Type"] == "Fail"
        assert failed["Error"] == "NotificationFailed"

    def test_failed_alert_still_reaches_the_approval_step(self, quarantine_asl):
        """The export policy is already restricted when SendAlert runs.

        If the alert cannot be published, the workflow must still ask for an approval decision.
        Ending at NotifyFailure would leave the volume quarantined with nobody asked.
        """
        states = quarantine_asl["States"]
        catch_all = states["SendAlert"]["Catch"][-1]
        assert catch_all["Next"] == "NotifyFallback"
        # The failure is kept in its own field, so the approval message shows it to the reviewer.
        assert catch_all["ResultPath"] == "$.alertError"
        assert catch_all["ResultPath"] not in ("$", "$.error")

        fallback = states["NotifyFallback"]
        assert fallback["Next"] == "WaitForApproval"
        assert fallback["Parameters"]["TopicArn"] == "${AlertFallbackTopic}"
        assert fallback["Retry"][-1]["ErrorEquals"] == ["States.ALL"]
        # A failed fallback must not end the workflow either: the approval request still goes out.
        fallback_catch = fallback["Catch"][-1]
        assert fallback_catch["ErrorEquals"] == ["States.ALL"]
        assert fallback_catch["Next"] == "WaitForApproval"
        assert fallback_catch["ResultPath"] == "$.fallbackError"

    @pytest.mark.parametrize(
        ("send_alert", "fallback", "expected_path"),
        [
            ("ok", None, ["SendAlert", "WaitForApproval"]),
            ("fail", "ok", ["SendAlert", "NotifyFallback", "WaitForApproval"]),
            ("fail", "fail", ["SendAlert", "NotifyFallback", "WaitForApproval"]),
        ],
    )
    def test_alert_outcomes_all_lead_to_the_approval_step(self, quarantine_asl, send_alert, fallback, expected_path):
        states = quarantine_asl["States"]
        outcomes = {"SendAlert": send_alert, "NotifyFallback": fallback}
        name, path = "SendAlert", []
        while name != "WaitForApproval":
            path.append(name)
            state = states[name]
            name = state["Next"] if outcomes[name] == "ok" else state["Catch"][-1]["Next"]
        path.append(name)
        assert path == expected_path

    def test_every_catch_and_choice_target_is_a_state(self, quarantine_asl):
        states = quarantine_asl["States"]
        for name, state in states.items():
            targets = [c["Next"] for c in state.get("Catch", [])]
            targets += [r["Next"] for r in state.get("Choices", [])]
            targets += [state["Default"]] if "Default" in state else []
            for target in targets:
                assert target in states, f"{name} points at {target}, which is not a state"

    def test_task_with_next_state_keeps_the_execution_input(self, quarantine_asl):
        """Without ResultPath a task's output replaces the whole state input."""
        for name, state in quarantine_asl["States"].items():
            if state["Type"] == "Task" and "Next" in state:
                assert "ResultPath" in state, f"{name} replaces the execution input with its result"

    def test_approval_choice_guards_a_missing_decision(self, quarantine_asl):
        state = quarantine_asl["States"]["ApprovalDecision"]
        assert state["Default"] == "NotifyFailure"
        decisions = {}
        for rule in state["Choices"]:
            conditions = rule["And"]
            assert {"Variable": "$.approval.approved", "IsPresent": True} in conditions
            decisions[rule["Next"]] = next(c["BooleanEquals"] for c in conditions if "BooleanEquals" in c)
        assert decisions == {"RestoreAccess": True, "CreateFlexClone": False}

    @pytest.mark.parametrize(("approved", "final_state"), [(True, "RestoreAccess"), (False, "CreateFlexClone")])
    def test_every_path_resolves_on_the_runbook_approval_flow(self, quarantine_asl, approved, final_state):
        """Walk the workflow with the task output the runbook sends and resolve every `$.` path.

        The runbook approves with `send-task-success --task-output '{"approved": true}'`.
        """
        states = quarantine_asl["States"]
        data = {"detail": {"timestamp": "t", "volumeId": "v", "svmId": "s", "severity": "HIGH"}}
        task_results = {
            "CreateForensicSnapshot": {"Snapshot": {"SnapshotId": "snap"}},
            "RestrictExportPolicy": {"status": "ok"},
            "SendAlert": {"MessageId": "m"},
            "WaitForApproval": {"approved": approved},
            "RestoreAccess": {},
            "CreateFlexClone": {},
        }
        name = quarantine_asl["StartAt"]
        while True:
            state = states[name]
            if state["Type"] == "Choice":
                name = _choose(state, data)
                continue
            for path in re.findall(r"(?<!\$)\$\.[\w.]+", json.dumps(state.get("Parameters", {}))):
                assert _resolve(data, path) is not _MISSING, f"{name}: {path} is not in {data}"
            result_path = state.get("ResultPath", "$")
            data = task_results[name] if result_path == "$" else {**data, result_path[2:]: task_results[name]}
            if state.get("End"):
                break
            name = state["Next"]
        assert name == final_state


class TestEventClassificationProperty:
    """Property-based tests for event classification."""

    @given(
        source=st.sampled_from(["fpolicy", "arp", "scanner"]),
        event_type=st.sampled_from(["file_write", "ransomware_detected", "arp_alert"]),
        verdict=st.sampled_from(["MALICIOUS", "SUSPICIOUS", "CLEAN", ""]),
    )
    @settings(max_examples=50)
    @patch.object(event_transformer, "events_client")
    def test_all_valid_sources_produce_valid_eventbridge_source(self, mock_events, source, event_type, verdict):
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        raw_event = {
            "source": source,
            "event_type": event_type,
            "verdict": verdict,
            "file_path": "/test",
        }
        sqs_event = {"Records": [{"body": json.dumps(raw_event)}]}

        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["Source"].startswith("fsxn.cyber-resilience.")
        assert entry["DetailType"] in {
            "MalwareDetected",
            "RansomwareDetected",
            "SuspiciousActivity",
            "FileEvent",
        }

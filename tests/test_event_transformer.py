"""Unit tests for Event Transformer Lambda.

Tests the SQS → EventBridge transformation logic using moto mocks.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

# Set environment variables before importing handler
os.environ["EVENT_BUS_NAME"] = "test-security-bus"
os.environ["ENVIRONMENT"] = "dev"

import event_transformer

# Ensure module-level EVENT_BUS_NAME is set correctly for this test file
event_transformer.EVENT_BUS_NAME = "test-security-bus"

from event_transformer import (  # noqa: E402
    _classify_detail_type,
    _classify_severity,
    _transform_event,
    handler,
)


class TestClassifyDetailType:
    """Test event classification logic."""

    def test_malicious_verdict(self) -> None:
        assert _classify_detail_type("file_write", "MALICIOUS") == "MalwareDetected"

    def test_infected_verdict(self) -> None:
        assert _classify_detail_type("file_write", "INFECTED") == "MalwareDetected"

    def test_suspicious_verdict(self) -> None:
        assert _classify_detail_type("file_write", "SUSPICIOUS") == "SuspiciousActivity"

    def test_ransomware_event_type(self) -> None:
        assert _classify_detail_type("ransomware_detected", "") == "RansomwareDetected"

    def test_arp_alert(self) -> None:
        assert _classify_detail_type("arp_alert", "") == "RansomwareDetected"

    def test_normal_file_event(self) -> None:
        assert _classify_detail_type("file_write", "") == "FileEvent"

    def test_clean_verdict(self) -> None:
        assert _classify_detail_type("file_write", "CLEAN") == "FileEvent"


class TestClassifySeverity:
    """Test severity classification."""

    def test_malicious_is_critical(self) -> None:
        assert _classify_severity("file_write", "MALICIOUS") == "CRITICAL"

    def test_infected_is_critical(self) -> None:
        assert _classify_severity("file_write", "INFECTED") == "CRITICAL"

    def test_suspicious_is_high(self) -> None:
        assert _classify_severity("file_write", "SUSPICIOUS") == "HIGH"

    def test_ransomware_detected_is_critical(self) -> None:
        assert _classify_severity("ransomware_detected", "") == "CRITICAL"

    def test_arp_alert_is_high(self) -> None:
        assert _classify_severity("arp_alert", "") == "HIGH"

    def test_default_is_low(self) -> None:
        assert _classify_severity("file_write", "") == "LOW"


class TestTransformEvent:
    """Test raw event → EventBridge entry transformation."""

    def test_fpolicy_event_transform(self) -> None:
        raw = {
            "source": "fpolicy",
            "event_type": "file_write",
            "file_system_id": "fs-0123456789abcdef0",
            "svm_id": "svm-0123456789abcdef0",
            "volume_id": "fsvol-0123456789abcdef0",
            "file_path": "/production/test.exe",
            "client_ip": "10.0.x.x",
            "user_name": "DOMAIN\\user1",
            "timestamp": "2026-06-25T10:30:00Z",
        }
        entry = _transform_event(raw)

        assert entry["Source"] == "fsxn.cyber-resilience.fpolicy"
        assert entry["DetailType"] == "FileEvent"
        assert entry["EventBusName"] == "test-security-bus"

        detail = json.loads(entry["Detail"])
        assert detail["fileSystemId"] == "fs-0123456789abcdef0"
        assert detail["volumeId"] == "fsvol-0123456789abcdef0"
        assert detail["severity"] == "LOW"

    def test_scanner_malicious_transform(self) -> None:
        raw = {
            "source": "scanner",
            "scanner_name": "trendai",
            "verdict": "MALICIOUS",
            "file_path": "/production/malware.exe",
            "volume_id": "fsvol-0123456789abcdef0",
            "svm_id": "svm-0123456789abcdef0",
            "file_system_id": "fs-0123456789abcdef0",
            "timestamp": "2026-06-25T10:30:00Z",
        }
        entry = _transform_event(raw)

        assert entry["Source"] == "fsxn.cyber-resilience.scanner"
        assert entry["DetailType"] == "MalwareDetected"

        detail = json.loads(entry["Detail"])
        assert detail["severity"] == "CRITICAL"
        assert detail["scannerName"] == "trendai"
        assert detail["verdict"] == "MALICIOUS"

    def test_arp_event_transform(self) -> None:
        raw = {
            "source": "arp",
            "event_type": "ransomware_detected",
            "file_system_id": "fs-0123456789abcdef0",
            "volume_id": "fsvol-0123456789abcdef0",
            "snapshot_name": "anti_ransomware_backup.2026-06-25_1030",
            "affected_files_count": 150,
            "timestamp": "2026-06-25T10:30:00Z",
        }
        entry = _transform_event(raw)

        assert entry["Source"] == "fsxn.cyber-resilience.arp"
        assert entry["DetailType"] == "RansomwareDetected"

        detail = json.loads(entry["Detail"])
        assert detail["severity"] == "CRITICAL"
        assert detail["metadata"]["snapshot_name"] == "anti_ransomware_backup.2026-06-25_1030"
        assert detail["metadata"]["affected_files_count"] == 150


class TestHandler:
    """Test the Lambda handler with mocked EventBridge."""

    @patch("event_transformer.events_client")
    def test_handler_processes_sqs_records(self, mock_events: MagicMock) -> None:
        mock_events.put_events.return_value = {
            "FailedEntryCount": 0,
            "Entries": [{"EventId": "123"}],
        }

        event = {
            "Records": [
                {
                    "messageId": "msg-001",
                    "body": json.dumps(
                        {
                            "source": "fpolicy",
                            "event_type": "file_write",
                            "file_system_id": "fs-0123456789abcdef0",
                            "svm_id": "svm-0123456789abcdef0",
                            "volume_id": "fsvol-0123456789abcdef0",
                            "timestamp": "2026-06-25T10:30:00Z",
                        }
                    ),
                }
            ]
        }

        result = handler(event, None)

        assert result["statusCode"] == 200
        assert result["published"] == 1
        assert result["failures"] == 0
        mock_events.put_events.assert_called_once()

    @patch("event_transformer.events_client")
    def test_handler_reports_parse_failures(self, mock_events: MagicMock) -> None:
        event = {
            "Records": [
                {
                    "messageId": "msg-bad",
                    "body": "not-valid-json{{{",
                }
            ]
        }

        result = handler(event, None)

        assert result["statusCode"] == 200
        assert result["published"] == 0
        assert "batchItemFailures" in result
        assert result["batchItemFailures"][0]["itemIdentifier"] == "msg-bad"
        mock_events.put_events.assert_not_called()

    @patch("event_transformer.events_client")
    def test_handler_multiple_records_batch(self, mock_events: MagicMock) -> None:
        mock_events.put_events.return_value = {
            "FailedEntryCount": 0,
            "Entries": [{"EventId": f"id-{i}"} for i in range(3)],
        }

        records = []
        for i in range(3):
            records.append(
                {
                    "messageId": f"msg-{i:03d}",
                    "body": json.dumps(
                        {
                            "source": "fpolicy",
                            "event_type": "file_write",
                            "file_system_id": "fs-0123456789abcdef0",
                            "svm_id": "svm-0123456789abcdef0",
                            "volume_id": "fsvol-0123456789abcdef0",
                            "timestamp": "2026-06-25T10:30:00Z",
                        }
                    ),
                }
            )

        result = handler({"Records": records}, None)

        assert result["published"] == 3
        assert result["failures"] == 0


def _record(message_id: str, body: str | None = None) -> dict[str, str]:
    """Builds one SQS record with a valid FPolicy body unless ``body`` is given."""
    if body is None:
        body = json.dumps(
            {
                "source": "fpolicy",
                "event_type": "file_write",
                "file_system_id": "fs-0123456789abcdef0",
                "timestamp": "2026-06-25T10:30:00Z",
            }
        )
    return {"messageId": message_id, "body": body}


def _emf_lines(capsys: pytest.CaptureFixture[str]) -> list[dict[str, object]]:
    """Returns the Embedded Metric Format objects the handler wrote to stdout."""
    out = capsys.readouterr().out
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


class TestPublishFailuresAreReported:
    """A record whose EventBridge publish failed goes back to the queue (ReportBatchItemFailures)."""

    @patch("event_transformer.events_client")
    def test_failed_entry_is_reported_by_message_id(self, mock_events: MagicMock) -> None:
        mock_events.put_events.return_value = {
            "FailedEntryCount": 1,
            "Entries": [{"EventId": "e1"}, {"ErrorCode": "InternalFailure", "ErrorMessage": "x"}],
        }
        result = handler({"Records": [_record("m-ok"), _record("m-fail")]}, None)
        assert result["failures"] == 1
        assert result["batchItemFailures"] == [{"itemIdentifier": "m-fail"}]

    @patch("event_transformer.events_client")
    def test_whole_batch_exception_reports_every_record_of_the_batch(self, mock_events: MagicMock) -> None:
        mock_events.put_events.side_effect = RuntimeError("throttled")
        result = handler({"Records": [_record("m-1"), _record("m-2")]}, None)
        assert result["failures"] == 2
        assert {f["itemIdentifier"] for f in result["batchItemFailures"]} == {"m-1", "m-2"}

    @patch("event_transformer.events_client")
    def test_batches_beyond_ten_map_failures_to_the_right_record(self, mock_events: MagicMock) -> None:
        def put_events(Entries: list[dict[str, str]]) -> dict[str, object]:  # noqa: N803
            return {
                "FailedEntryCount": 0,
                "Entries": [{"EventId": "ok"} for _ in Entries],
            }

        calls: list[int] = []

        def second_batch_fails(Entries: list[dict[str, str]]) -> dict[str, object]:  # noqa: N803
            calls.append(len(Entries))
            if len(calls) == 2:
                return {
                    "FailedEntryCount": 1,
                    "Entries": [{"ErrorCode": "E"}, *({"EventId": "ok"} for _ in Entries[1:])],
                }
            return put_events(Entries)

        mock_events.put_events.side_effect = second_batch_fails
        records = [_record(f"m-{i:02d}") for i in range(12)]
        result = handler({"Records": records}, None)
        assert result["batchItemFailures"] == [{"itemIdentifier": "m-10"}]

    @patch("event_transformer.events_client")
    def test_json_body_that_is_not_an_object_is_a_parse_failure_not_an_exception(self, mock_events: MagicMock) -> None:
        result = handler({"Records": [_record("m-list", body="[1, 2]")]}, None)
        assert result["batchItemFailures"] == [{"itemIdentifier": "m-list"}]
        mock_events.put_events.assert_not_called()


class TestFailureMetric:
    """The handler emits FailedRecords in Embedded Metric Format (Requirement 19.2)."""

    @patch("event_transformer.events_client")
    def test_emf_carries_failed_records_with_both_dimension_sets(
        self, mock_events: MagicMock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_events.put_events.return_value = {"FailedEntryCount": 0, "Entries": [{"EventId": "e"}]}
        ctx = MagicMock()
        ctx.function_name = "fn"
        ctx.function_version = "7"
        handler({"Records": [_record("ok"), _record("bad", body="{{")]}, ctx)
        (emf,) = _emf_lines(capsys)
        directive = emf["_aws"]["CloudWatchMetrics"][0]  # type: ignore[index]
        assert directive["Namespace"] == event_transformer.METRIC_NAMESPACE
        assert directive["Dimensions"] == [["FunctionName"], ["FunctionName", "ExecutedVersion"]]
        assert {m["Name"] for m in directive["Metrics"]} == {"FailedRecords", "ProcessedRecords"}
        assert emf["FailedRecords"] == 1
        assert emf["ProcessedRecords"] == 2
        assert emf["FunctionName"] == "fn"
        assert emf["ExecutedVersion"] == "7"

    @patch("event_transformer.events_client")
    def test_zero_failures_are_still_emitted(self, mock_events: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        """A 0 value keeps the metric present, so the alarm sees data when traffic flows."""
        mock_events.put_events.return_value = {"FailedEntryCount": 0, "Entries": [{"EventId": "e"}]}
        handler({"Records": [_record("ok")]}, None)
        (emf,) = _emf_lines(capsys)
        assert emf["FailedRecords"] == 0

    @patch("event_transformer.events_client")
    def test_publish_failure_counts_in_failed_records(
        self, mock_events: MagicMock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_events.put_events.side_effect = RuntimeError("down")
        handler({"Records": [_record("a"), _record("b")]}, None)
        (emf,) = _emf_lines(capsys)
        assert emf["FailedRecords"] == 2


class TestDryRun:
    """The PreTraffic hook invokes the new version with ``dry_run``: transform, never publish."""

    @patch("event_transformer.events_client")
    def test_dry_run_transforms_without_publishing(self, mock_events: MagicMock) -> None:
        result = handler({"dry_run": True, "Records": [_record("probe")]}, None)
        assert result["dry_run"] is True
        assert result["validated"] == 1
        assert result["failures"] == 0
        assert "batchItemFailures" not in result
        mock_events.put_events.assert_not_called()

    @patch("event_transformer.events_client")
    def test_dry_run_reports_a_record_that_does_not_transform(self, mock_events: MagicMock) -> None:
        result = handler({"dry_run": True, "Records": [_record("probe", body="{{")]}, None)
        assert result["validated"] == 0
        assert result["batchItemFailures"] == [{"itemIdentifier": "probe"}]
        mock_events.put_events.assert_not_called()

    @patch("event_transformer.events_client")
    def test_sqs_event_without_the_flag_publishes(self, mock_events: MagicMock) -> None:
        mock_events.put_events.return_value = {"FailedEntryCount": 0, "Entries": [{"EventId": "e"}]}
        handler({"Records": [_record("m")]}, None)
        mock_events.put_events.assert_called_once()

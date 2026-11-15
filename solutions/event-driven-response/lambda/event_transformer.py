"""Event Transformer: SQS (FPolicy/ARP events) → EventBridge.

Receives raw security events from the SQS queue (originating from
FPolicy external server or ARP EMS notifications), normalizes them
into a structured EventBridge event format, and publishes to the
custom security event bus.

Environment Variables:
    EVENT_BUS_NAME: EventBridge custom bus name
    ENVIRONMENT: Deployment environment (dev/staging/production)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

events_client = boto3.client("events")

EVENT_BUS_NAME = os.environ.get("EVENT_BUS_NAME", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
# Namespace of the Embedded Metric Format metrics; templates/event-driven.yaml alarms use it.
METRIC_NAMESPACE = "FsxnCyberResilience/EventTransformer"

# Source mapping for event classification
SOURCE_MAP = {
    "fpolicy": "fsxn.cyber-resilience.fpolicy",
    "arp": "fsxn.cyber-resilience.arp",
    "scanner": "fsxn.cyber-resilience.scanner",
}

# Severity classification based on verdict/event type
SEVERITY_MAP = {
    "MALICIOUS": "CRITICAL",
    "INFECTED": "CRITICAL",
    "SUSPICIOUS": "HIGH",
    "ransomware_detected": "CRITICAL",
    "arp_alert": "HIGH",
    "file_delete_burst": "MEDIUM",
    "default": "LOW",
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Process SQS messages and forward to EventBridge.

    The event source mappings that invoke this function set
    ``FunctionResponseTypes: [ReportBatchItemFailures]``, so ``batchItemFailures``
    is honored: only the listed messages return to the queue (and reach the
    dead-letter queue after ``maxReceiveCount``). A record is listed when its
    body does not transform or when EventBridge did not accept its entry.
    Partial failures do not raise, so they never appear in the ``Errors``
    metric; ``FailedRecords`` (Embedded Metric Format) carries them instead.

    When ``event["dry_run"]`` is true (the canary PreTraffic hook sets it), the
    records are transformed but nothing is published.

    Args:
        event: SQS event containing batch of records.
        context: Lambda context.

    Returns:
        Processing result with counts.
    """
    records = event.get("Records", [])
    dry_run = event.get("dry_run") is True
    logger.info(f"Processing {len(records)} SQS records")

    entries: list[dict[str, Any]] = []
    entry_ids: list[str] = []
    failed_ids: list[str] = []

    for record in records:
        message_id = record.get("messageId", "unknown")
        try:
            body = json.loads(record["body"])
            entry = _transform_event(body)
            entries.append(entry)
            entry_ids.append(message_id)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError, AttributeError) as e:
            logger.error(f"Failed to process record {message_id}: {e}")
            failed_ids.append(message_id)

    parse_errors = len(failed_ids)
    published = 0
    failures = 0

    if dry_run:
        validated = len(entries)
    else:
        # Publish to EventBridge in batches of 10 (API limit)
        for i in range(0, len(entries), 10):
            batch = entries[i : i + 10]
            batch_ids = entry_ids[i : i + 10]
            try:
                response = events_client.put_events(Entries=batch)
                failed_count = response.get("FailedEntryCount", 0)
                published += len(batch) - failed_count
                failures += failed_count
                # PutEvents returns one result per entry, in request order.
                for idx, entry_response in enumerate(response.get("Entries", [])):
                    if entry_response.get("ErrorCode"):
                        logger.error(
                            f"EventBridge publish failed: {entry_response['ErrorCode']} "
                            f"- {entry_response.get('ErrorMessage', '')}"
                        )
                        if idx < len(batch_ids):
                            failed_ids.append(batch_ids[idx])
            except Exception as e:
                logger.error(f"EventBridge batch publish failed: {e}")
                failures += len(batch)
                failed_ids.extend(batch_ids)
        validated = 0

    logger.info(f"Published: {published}, Failed: {failures}, Parse errors: {parse_errors}")
    failed_ids = list(dict.fromkeys(failed_ids))
    if not dry_run:
        # A dry run is not traffic, so it stays out of the metric.
        _emit_metrics(context, failed=len(failed_ids), processed=len(records))

    # Return batch item failures for SQS partial batch response
    result: dict[str, Any] = {
        "statusCode": 200,
        "published": published,
        "failures": failures,
    }
    if dry_run:
        result["dry_run"] = True
        result["validated"] = validated
    if failed_ids:
        result["batchItemFailures"] = [{"itemIdentifier": mid} for mid in failed_ids]
    return result


def _emit_metrics(context: Any, failed: int, processed: int) -> None:
    """Writes one Embedded Metric Format object to stdout.

    CloudWatch Logs turns the object into ``FailedRecords`` and
    ``ProcessedRecords`` under ``METRIC_NAMESPACE``, once per dimension set:
    ``FunctionName`` alone and ``FunctionName`` with ``ExecutedVersion``. The
    canary alarms read the second set. The line goes to stdout, not through
    ``logging``, because the Lambda log formatter would prefix it and the
    object would no longer be a bare JSON line.

    Args:
        context: Lambda context; ``function_name`` and ``function_version`` are
            read when present.
        failed: Records that are returned to the queue.
        processed: Records the invocation received.
    """
    function_name = str(getattr(context, "function_name", "") or "unknown")
    version = str(getattr(context, "function_version", "") or "unknown")
    emf = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": METRIC_NAMESPACE,
                    "Dimensions": [["FunctionName"], ["FunctionName", "ExecutedVersion"]],
                    "Metrics": [
                        {"Name": "FailedRecords", "Unit": "Count"},
                        {"Name": "ProcessedRecords", "Unit": "Count"},
                    ],
                }
            ],
        },
        "FunctionName": function_name,
        "ExecutedVersion": version,
        "FailedRecords": failed,
        "ProcessedRecords": processed,
    }
    sys.stdout.write(json.dumps(emf) + "\n")
    sys.stdout.flush()


def _transform_event(raw_event: dict[str, Any]) -> dict[str, Any]:
    """Transform a raw FPolicy/ARP event into EventBridge format.

    Args:
        raw_event: Raw event from SQS (varies by source).

    Returns:
        EventBridge PutEvents entry dict.

    Expected raw event formats:

    FPolicy event:
        {
            "source": "fpolicy",
            "event_type": "file_write",
            "file_system_id": "fs-0123456789abcdef0",
            "svm_id": "svm-0123456789abcdef0",
            "volume_id": "fsvol-0123456789abcdef0",
            "file_path": "/production/documents/file.exe",
            "client_ip": "10.0.x.x",
            "user_name": "DOMAIN\\user1",
            "protocol": "cifs",
            "timestamp": "2026-06-25T10:30:00Z"
        }

    ARP event:
        {
            "source": "arp",
            "event_type": "ransomware_detected",
            "file_system_id": "fs-0123456789abcdef0",
            "volume_id": "fsvol-0123456789abcdef0",
            "snapshot_name": "anti_ransomware_backup.2026-06-25_1030",
            "affected_files_count": 150,
            "timestamp": "2026-06-25T10:30:00Z"
        }

    Scanner verdict:
        {
            "source": "scanner",
            "scanner_name": "trendai",
            "verdict": "MALICIOUS",
            "file_path": "/production/malware.exe",
            "volume_id": "fsvol-0123456789abcdef0",
            "svm_id": "svm-0123456789abcdef0",
            "file_system_id": "fs-0123456789abcdef0",
            "timestamp": "2026-06-25T10:30:00Z"
        }
    """
    source_key = raw_event.get("source", "fpolicy")
    event_source = SOURCE_MAP.get(source_key, SOURCE_MAP["fpolicy"])
    event_type = raw_event.get("event_type", "FileEvent")
    verdict = raw_event.get("verdict", "")

    # Determine detail-type
    detail_type = _classify_detail_type(event_type, verdict)

    # Determine severity
    severity = _classify_severity(event_type, verdict)

    # Build normalized detail
    detail = {
        "fileSystemId": raw_event.get("file_system_id", ""),
        "svmId": raw_event.get("svm_id", ""),
        "volumeId": raw_event.get("volume_id", ""),
        "filePath": raw_event.get("file_path", ""),
        "operation": raw_event.get("event_type", "unknown"),
        "clientIp": raw_event.get("client_ip", ""),
        "userName": raw_event.get("user_name", ""),
        "verdict": verdict,
        "scannerName": raw_event.get("scanner_name", ""),
        "severity": severity,
        "timestamp": raw_event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "environment": ENVIRONMENT,
        "metadata": {
            k: v
            for k, v in raw_event.items()
            if k
            not in {
                "source",
                "event_type",
                "file_system_id",
                "svm_id",
                "volume_id",
                "file_path",
                "client_ip",
                "user_name",
                "verdict",
                "scanner_name",
                "timestamp",
            }
        },
    }

    return {
        "Source": event_source,
        "DetailType": detail_type,
        "Detail": json.dumps(detail),
        "EventBusName": EVENT_BUS_NAME,
    }


def _classify_detail_type(event_type: str, verdict: str) -> str:
    """Classify the EventBridge detail-type based on event content."""
    if verdict in ("MALICIOUS", "INFECTED"):
        return "MalwareDetected"
    if event_type == "ransomware_detected" or "ransomware" in event_type.lower():
        return "RansomwareDetected"
    if verdict == "SUSPICIOUS":
        return "SuspiciousActivity"
    if event_type == "arp_alert":
        return "RansomwareDetected"
    return "FileEvent"


def _classify_severity(event_type: str, verdict: str) -> str:
    """Classify event severity."""
    if verdict and verdict in SEVERITY_MAP:
        return SEVERITY_MAP[verdict]
    if event_type in SEVERITY_MAP:
        return SEVERITY_MAP[event_type]
    return SEVERITY_MAP["default"]

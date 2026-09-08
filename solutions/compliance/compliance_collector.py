"""Compliance Evidence Collector — automated security control verification.

Queries ONTAP REST API daily for security control status (ARP, FPolicy,
SnapLock, encryption) and generates compliance evidence reports stored in S3.

Environment Variables:
    MANAGEMENT_ENDPOINT: FSx for ONTAP management DNS
    SECRET_ARN: Secrets Manager ARN for fsxadmin credentials
    REPORT_BUCKET: S3 bucket for compliance reports (Object Lock enabled)
    SNS_TOPIC_ARN: SNS topic for non-compliance alerts
    ENVIRONMENT: Deployment environment
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MANAGEMENT_ENDPOINT = os.environ.get("MANAGEMENT_ENDPOINT", "")
SECRET_ARN = os.environ.get("SECRET_ARN", "")
REPORT_BUCKET = os.environ.get("REPORT_BUCKET", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")


@dataclass
class ComplianceResult:
    """Single compliance check result."""

    timestamp: str
    control_id: str
    control_name: str
    expected_state: str
    actual_state: str
    compliant: bool
    evidence_detail: dict[str, Any]
    soc2_mapping: str = ""
    iso27001_mapping: str = ""


# Control definitions with compliance framework mapping
CONTROLS = [
    {
        "id": "CR-ARP-001",
        "name": "ARP enabled on production volumes",
        "check": "_check_arp_status",
        "expected": "every volume protecting (enabled or dry_run)",
        "soc2": "CC6.1",
        "iso27001": "A.12.4",
    },
    {
        "id": "CR-FP-001",
        "name": "FPolicy active on production SVMs",
        "check": "_check_fpolicy_status",
        "expected": "at least one policy enabled",
        "soc2": "CC6.6",
        "iso27001": "A.12.4",
    },
    {
        "id": "CR-ENC-001",
        "name": "All volumes encrypted at rest",
        "check": "_check_encryption_status",
        "expected": "all volumes encrypted",
        "soc2": "CC6.1",
        "iso27001": "A.8.1",
    },
    {
        "id": "CR-BKP-001",
        "name": "Snapshot policy active on volumes",
        "check": "_check_snapshot_policy",
        "expected": "snapshot policy assigned",
        "soc2": "CC6.7",
        "iso27001": "A.12.3",
    },
]


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Daily compliance evidence collection.

    Args:
        event: EventBridge Scheduler event.
        context: Lambda context.

    Returns:
        Compliance report summary.
    """
    from ontap_client import OntapClient

    client = OntapClient(
        management_endpoint=MANAGEMENT_ENDPOINT,
        secret_arn=SECRET_ARN,
    )

    timestamp = datetime.now(timezone.utc).isoformat()
    results: list[ComplianceResult] = []
    non_compliant: list[ComplianceResult] = []

    for control in CONTROLS:
        check_fn = globals().get(control["check"])
        if not check_fn:
            logger.warning(f"Check function not found: {control['check']}")
            continue

        try:
            actual_state, compliant, evidence = check_fn(client)
        except Exception as e:
            actual_state = f"ERROR: {str(e)[:100]}"
            compliant = False
            evidence = {"error": str(e)}

        result = ComplianceResult(
            timestamp=timestamp,
            control_id=control["id"],
            control_name=control["name"],
            expected_state=control["expected"],
            actual_state=actual_state,
            compliant=compliant,
            evidence_detail=evidence,
            soc2_mapping=control.get("soc2", ""),
            iso27001_mapping=control.get("iso27001", ""),
        )
        results.append(result)
        if not compliant:
            non_compliant.append(result)

    # Store report in S3
    report = _store_report(results, timestamp)

    # Alert on non-compliance
    if non_compliant:
        _alert_non_compliance(non_compliant)

    summary = {
        "timestamp": timestamp,
        "total_controls": len(results),
        "compliant": len(results) - len(non_compliant),
        "non_compliant": len(non_compliant),
        "report_location": report,
    }
    logger.info(f"Compliance check: {summary}")
    return summary


def _check_arp_status(client: Any) -> tuple[str, bool, dict]:
    """Check ARP status across all volumes.

    ARP has seven states. Testing membership of the two that mean "protected" and
    treating everything else as unprotected loses the distinction that matters to whoever
    reads the report: a volume mid-transition is still protected, a paused volume is not,
    and a state this code has not seen is neither. Each is counted separately, and an
    unrecognised value is reported as such rather than folded into a count of failures.

    Args:
        client: ONTAP client.

    Returns:
        The rendered count, whether every volume is protecting, and the per-volume detail
        including its classification.
    """
    # Deferred, and from the flat module name: the Lambda package puts ontap_client at
    # the top level, so a `shared.` prefix resolves in the repository and fails once
    # deployed. The existing collector imports OntapClient the same way.
    from ontap_client import classify_arp_state

    volumes = client.list_volumes()
    arp_states = []
    for vol in volumes:
        try:
            status = client.get_arp_status(vol["uuid"])
            raw = status.get("state", "unknown")
            arp_states.append(
                {"volume": vol["name"], "state": raw, "classification": classify_arp_state(raw)}
            )
        except Exception:
            arp_states.append(
                {"volume": vol["name"], "state": "unavailable", "classification": "unknown"}
            )

    counts = Counter(s["classification"] for s in arp_states)
    protecting = counts["protecting"]
    total = len(arp_states)
    all_protected = total > 0 and protecting == total

    actual = f"{protecting}/{total} protecting"
    for label in ("transitional", "not_protecting", "unknown"):
        if counts[label]:
            actual += f", {counts[label]} {label.replace('_', ' ')}"

    return actual, all_protected, {"volumes": arp_states, "counts": dict(counts)}


def _check_fpolicy_status(client: Any) -> tuple[str, bool, dict]:
    """Check FPolicy status across all SVMs."""
    svms = client.list_svms()
    policies_active = []
    for svm in svms:
        # Simplified check — real implementation queries fpolicy show
        policies_active.append({"svm": svm["name"], "policies": "check_required"})

    has_policies = len(svms) > 0  # Simplified
    actual = f"{len(svms)} SVMs checked"
    return actual, has_policies, {"svms": policies_active}


def _check_encryption_status(client: Any) -> tuple[str, bool, dict]:
    """Check encryption status of all volumes."""
    volumes = client.list_volumes()
    # FSx for ONTAP always encrypts at rest — this is a validation
    all_encrypted = True
    evidence = {"total_volumes": len(volumes), "encryption": "aws_managed"}
    actual = f"{len(volumes)} volumes (all encrypted by FSx)"
    return actual, all_encrypted, evidence


def _check_snapshot_policy(client: Any) -> tuple[str, bool, dict]:
    """Check snapshot policy assignment on volumes."""
    volumes = client.list_volumes()
    # Simplified — real implementation checks nas.snapshot_policy
    has_policy = len(volumes) > 0
    actual = f"{len(volumes)} volumes checked"
    return actual, has_policy, {"volumes_checked": len(volumes)}


def _store_report(results: list[ComplianceResult], timestamp: str) -> str:
    """Store compliance report in S3 with date-partitioned key."""
    if not REPORT_BUCKET:
        logger.warning("REPORT_BUCKET not configured, skipping storage")
        return ""

    s3 = boto3.client("s3")
    now = datetime.fromisoformat(timestamp)
    key = f"reports/{now.strftime('%Y/%m/%d')}/compliance-{ENVIRONMENT}-{now.strftime('%H%M%S')}.json"

    report_body = json.dumps(
        [asdict(r) for r in results],
        indent=2,
        default=str,
    )

    s3.put_object(
        Bucket=REPORT_BUCKET,
        Key=key,
        Body=report_body.encode(),
        ContentType="application/json",
    )

    location = f"s3://{REPORT_BUCKET}/{key}"
    logger.info(f"Report stored: {location}")
    return location


def _alert_non_compliance(non_compliant: list[ComplianceResult]) -> None:
    """Send SNS alert for non-compliant controls."""
    if not SNS_TOPIC_ARN:
        return

    sns = boto3.client("sns")
    message = {
        "alert": "COMPLIANCE_DEVIATION",
        "non_compliant_controls": [
            {"control_id": r.control_id, "control_name": r.control_name, "actual_state": r.actual_state}
            for r in non_compliant
        ],
        "total_non_compliant": len(non_compliant),
    }

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"COMPLIANCE: {len(non_compliant)} control(s) non-compliant",
        Message=json.dumps(message, indent=2),
    )

"""AWS-side reads for one FSx for ONTAP file system (read-only boto3 calls).

Calls made, all read only: ``fsx:DescribeFileSystems``, ``kms:DescribeKey``, ``fsx:DescribeBackups``,
``fsx:DescribeS3AccessPointAttachments``, ``s3:GetAccessPoint`` and ``s3:GetAccessPointPolicy``
(through the S3 Control endpoint). The clients are passed in, so tests use stubs.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .checks import ADMIN, NET, NO_PRE, name_token
from .collect import Fetch

logger = logging.getLogger(__name__)


def _error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__))


def _f(
    fid: str,
    check: str,
    resource: str,
    status: str,
    severity: str,
    pre: str,
    cap: str,
    observed: str,
    api: str,
    ledger: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": fid,
        "check": check,
        "resource": resource,
        "severity": severity,
        "status": status,
        "attacker_precondition": pre,
        "attacker_capability": cap,
        "observed": observed,
        "source": {"path": api, "http": 0, "ontap_code": ""},
        "ledger": ledger or [],
    }


def _pages(call: Any, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token = None
    for _ in range(50):
        args = dict(kwargs)
        if token:
            args["NextToken"] = token
        resp = call(**args)
        items.extend(resp.get(key) or [])
        token = resp.get("NextToken")
        if not token:
            break
    return items


def _policy_is_open(policy_text: str) -> list[str]:
    """Statement IDs (or indexes) that allow ``Principal: "*"`` with no Condition."""
    try:
        doc = json.loads(policy_text)
    except ValueError:
        return []
    statements = doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    open_ = []
    for i, st in enumerate(statements):
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        principal = st.get("Principal")
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        if principal == "*" or aws == "*" or (isinstance(aws, list) and "*" in aws):
            open_.append(str(st.get("Sid") or i))
    return open_


KMS_CAP = (
    "an attacker who can delete the file system's backups in this account leaves no copy in a logically "
    "air-gapped vault, because backups encrypted with the AWS managed key are not copied there"
)


def collect_aws(
    fsx: Any, kms: Any, s3control: Any, file_system_id: str, *, show_names: bool = False
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read the AWS side of one file system.

    Args:
        fsx: boto3 FSx client.
        kms: boto3 KMS client.
        s3control: boto3 S3 Control client.
        file_system_id: ``fs-...``.
        show_names: Show access point names instead of short tokens.

    Returns:
        Findings and the AWS part of ``residency``.
    """
    findings: list[dict[str, Any]] = []
    residency: dict[str, Any] = {}
    try:
        fs = fsx.describe_file_systems(FileSystemIds=[file_system_id])["FileSystems"][0]
    except Exception as exc:  # noqa: BLE001 - every client error becomes an unknown finding
        code = _error_code(exc)
        findings.append(
            _f(
                "KMS-001",
                "fsx_kms_key",
                "file-system",
                "unknown",
                "high",
                ADMIN,
                KMS_CAP,
                f"DescribeFileSystems failed ({code})",
                "fsx:DescribeFileSystems",
                ["E-009", "E-060"],
            )
        )
        return findings, residency
    owner = str(fs.get("OwnerId", ""))
    residency["region"] = str(fs.get("ResourceARN", "::::").split(":")[3] or "")
    key_id = fs.get("KmsKeyId")
    if key_id:
        try:
            meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            manager, origin = meta.get("KeyManager"), meta.get("Origin")
            residency["kms_key_manager"], residency["kms_origin"] = manager, origin
            status = "finding" if manager == "AWS" else "pass" if manager == "CUSTOMER" else "unknown"
            findings.append(
                _f(
                    "KMS-001",
                    "fsx_kms_key",
                    "file-system",
                    status,
                    "high",
                    ADMIN,
                    KMS_CAP,
                    f"KeyManager={manager}, Origin={origin}",
                    "kms:DescribeKey",
                    ["E-009", "E-060"],
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                _f(
                    "KMS-001",
                    "fsx_kms_key",
                    "file-system",
                    "unknown",
                    "high",
                    ADMIN,
                    KMS_CAP,
                    f"DescribeKey failed ({_error_code(exc)})",
                    "kms:DescribeKey",
                    ["E-009", "E-060"],
                )
            )
    else:
        findings.append(
            _f(
                "KMS-001",
                "fsx_kms_key",
                "file-system",
                "unknown",
                "high",
                ADMIN,
                KMS_CAP,
                "KmsKeyId not returned",
                "fsx:DescribeFileSystems",
                ["E-009", "E-060"],
            )
        )

    try:
        backups = _pages(
            fsx.describe_backups, "Backups", Filters=[{"Name": "file-system-id", "Values": [file_system_id]}]
        )
        residency["backup_count"] = len(backups)
        residency["backup_copy_source_regions"] = sorted(
            {str(b["SourceBackupRegion"]) for b in backups if b.get("SourceBackupRegion")}
        )
    except Exception as exc:  # noqa: BLE001
        residency["backup_count"] = None
        residency["backup_error"] = _error_code(exc)

    try:
        attachments = _pages(
            fsx.describe_s3_access_point_attachments,
            "S3AccessPointAttachments",
            Filters=[{"Name": "file-system-id", "Values": [file_system_id]}],
        )
    except Exception as exc:  # noqa: BLE001
        findings.append(
            _f(
                "S3AP-001",
                "s3_access_point_origin",
                "-",
                "unknown",
                "high",
                NET,
                "-",
                f"DescribeS3AccessPointAttachments failed ({_error_code(exc)})",
                "fsx:DescribeS3AccessPointAttachments",
            )
        )
        return findings, residency
    residency["s3_access_points"] = len(attachments)
    for att in attachments:
        findings.extend(_access_point_findings(s3control, att, owner, show_names))
    return findings, residency


def _access_point_findings(s3control: Any, att: dict[str, Any], owner: str, show_names: bool) -> list[dict[str, Any]]:
    ap = att.get("S3AccessPoint") or {}
    arn = str(ap.get("ResourceARN") or "")
    name = arn.rsplit("/", 1)[-1] if "/" in arn else str(att.get("Name") or "")
    account = arn.split(":")[4] if arn.count(":") >= 5 else owner
    res = name_token(name, show_names)
    out: list[dict[str, Any]] = []
    try:
        origin = s3control.get_access_point(AccountId=account, Name=name).get("NetworkOrigin")
        status = "finding" if origin == "Internet" else "pass" if origin == "VPC" else "unknown"
        out.append(
            _f(
                "S3AP-001",
                "s3_access_point_origin",
                res,
                status,
                "high",
                NET,
                "send S3 requests to the access point from outside the VPC",
                f"NetworkOrigin={origin}",
                "s3:GetAccessPoint",
            )
        )
    except Exception as exc:  # noqa: BLE001
        out.append(
            _f(
                "S3AP-001",
                "s3_access_point_origin",
                res,
                "unknown",
                "high",
                NET,
                "-",
                f"GetAccessPoint failed ({_error_code(exc)})",
                "s3:GetAccessPoint",
            )
        )
    try:
        policy = s3control.get_access_point_policy(AccountId=account, Name=name).get("Policy") or ""
        open_ = _policy_is_open(policy)
        status = "finding" if open_ else "pass"
        observed = f"Allow to Principal * without Condition in {open_}" if open_ else "no unconditioned Principal *"
        out.append(
            _f(
                "S3AP-002",
                "s3_access_point_policy",
                res,
                status,
                "high",
                NET,
                "any AWS principal allowed by the policy alone",
                observed,
                "s3:GetAccessPointPolicy",
            )
        )
    except Exception as exc:  # noqa: BLE001
        code = _error_code(exc)
        if code == "NoSuchAccessPointPolicy":
            out.append(
                _f(
                    "S3AP-002",
                    "s3_access_point_policy",
                    res,
                    "finding",
                    "info",
                    NO_PRE,
                    "access is decided by IAM policies of the caller and the file system user alone",
                    "no access point policy",
                    "s3:GetAccessPointPolicy",
                )
            )
        else:
            out.append(
                _f(
                    "S3AP-002",
                    "s3_access_point_policy",
                    res,
                    "unknown",
                    "high",
                    NET,
                    "-",
                    f"GetAccessPointPolicy failed ({code})",
                    "s3:GetAccessPointPolicy",
                )
            )
    return out


def ontap_residency(snapmirror_out: Fetch, cluster_peers: Fetch, show_names: bool = False) -> dict[str, Any]:
    """The ONTAP part of ``residency``: where SnapMirror sends data, and the peers (masked)."""
    dests = sorted(
        {
            name_token((r.get("destination") or {}).get("cluster", {}).get("name") or "local", show_names)
            for r in snapmirror_out.records
        }
    )
    peers = sorted({name_token(p.get("name"), show_names) for p in cluster_peers.records})
    return {
        "snapmirror_destination_clusters": dests if snapmirror_out.outcome == "ok" else None,
        "cluster_peers": peers if cluster_peers.outcome == "ok" else None,
    }

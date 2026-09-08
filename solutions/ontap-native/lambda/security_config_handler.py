"""CloudFormation Custom Resource handler for ONTAP security configuration.

Configures ARP and FPolicy on FSx for ONTAP via the ONTAP REST API.
Supports both new deployments and existing (Bring Your Own) FSx for ONTAP environments.

CloudFormation Custom Resource properties:
    ManagementEndpoint: FSx for ONTAP management DNS/IP
    SecretArn: Secrets Manager ARN for fsxadmin credentials
    SvmUuid: Target SVM UUID
    VolumeUuids: List of volume UUIDs to enable ARP on
    FPolicyConfig: FPolicy configuration dict (optional)

Lifecycle:
    Create: Enable ARP (learning mode) + configure FPolicy
    Update: Reconfigure FPolicy (ARP state change requires separate workflow)
    Delete: Disable FPolicy policies (ARP remains for safety)
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import urllib3

# Custom Resource response helpers
SUCCESS = "SUCCESS"
FAILED = "FAILED"

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Import shared client (deployed as Lambda Layer or bundled)
# In production, this would be: from shared.ontap_client import OntapClient
# For inline deployment, we include a minimal client below.


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """CloudFormation Custom Resource handler.

    Args:
        event: CloudFormation Custom Resource event.
        context: Lambda context.

    Returns:
        Custom Resource response.
    """
    logger.info(f"Received event: {json.dumps(event, default=str)}")

    request_type = event.get("RequestType", "")
    properties = event.get("ResourceProperties", {})
    physical_resource_id = event.get("PhysicalResourceId", f"ontap-security-config-{int(time.time())}")

    try:
        if request_type == "Create":
            result = _handle_create(properties)
            physical_resource_id = result.get("physical_resource_id", physical_resource_id)
        elif request_type == "Update":
            result = _handle_update(properties, event.get("OldResourceProperties", {}))
        elif request_type == "Delete":
            result = _handle_delete(properties)
        else:
            raise ValueError(f"Unknown RequestType: {request_type}")

        _send_response(event, context, SUCCESS, physical_resource_id, result)

    except Exception as e:
        logger.error(f"Error handling {request_type}: {e}", exc_info=True)
        _send_response(event, context, FAILED, physical_resource_id, {"Error": str(e)})

    return {"statusCode": 200}


def _handle_create(properties: dict[str, Any]) -> dict[str, Any]:
    """Handle Create: Enable ARP and configure FPolicy.

    Args:
        properties: Custom Resource properties.

    Returns:
        Result dict with configured resource details.
    """
    client = _get_ontap_client(properties)
    svm_uuid = properties["SvmUuid"]
    volume_uuids = properties.get("VolumeUuids", [])
    fpolicy_config = properties.get("FPolicyConfig", {})
    arp_state = properties.get("ArpState", "enabled")

    results: dict[str, Any] = {
        "arp_volumes": [],
        "fpolicy_configured": False,
        "mav_configured": False,
    }

    # Step 1: Enable ARP on the specified volumes. ARP lands in the state ONTAP
    # chooses, not the one requested: on ARP/AI (9.16.1+) dry_run is not reachable.
    for vol_uuid in volume_uuids:
        try:
            arp = client.enable_arp(vol_uuid, state=arp_state)
            landed = arp.get("state", "unknown")
            entry = {"uuid": vol_uuid, "state": landed, "requested": arp_state}
            if arp.get("differs"):
                # Reporting the request would describe an actively protecting volume
                # as learning, which is the difference an operator acts on.
                entry["note"] = "ONTAP landed in a state other than the one requested"
                logger.warning(
                    f"ARP on volume {vol_uuid}: requested {arp_state}, landed {landed}"
                )
            results["arp_volumes"].append(entry)
            logger.info(f"ARP on volume {vol_uuid} is {landed}")
        except Exception as e:
            logger.warning(f"Failed to enable ARP on volume {vol_uuid}: {e}")
            results["arp_volumes"].append({"uuid": vol_uuid, "error": str(e)})

    # Step 2: Configure FPolicy (if config provided)
    if fpolicy_config:
        _configure_fpolicy(client, svm_uuid, fpolicy_config)
        results["fpolicy_configured"] = True

    # Step 3: Configure MAV (if config provided)
    mav_config = properties.get("MavConfig", {})
    if mav_config:
        _configure_mav(client, mav_config)
        results["mav_configured"] = True
        results["fpolicy_configured"] = True

    results["physical_resource_id"] = f"ontap-security-{svm_uuid[:8]}-{int(time.time())}"
    return results


def _handle_update(
    properties: dict[str, Any],
    old_properties: dict[str, Any],
) -> dict[str, Any]:
    """Handle Update: Reconfigure FPolicy, and enable ARP on volumes that were added.

    On the original ARP model (ONTAP 9.10.1 to 9.15.1, and FlexGroup through 9.17.1) a
    volume enabled here begins learning, and reaching active mode is a later step. On
    ARP/AI it protects immediately and there is no later step.
    """
    client = _get_ontap_client(properties)
    svm_uuid = properties["SvmUuid"]
    fpolicy_config = properties.get("FPolicyConfig", {})
    arp_state = properties.get("ArpState", "enabled")

    results: dict[str, Any] = {"fpolicy_updated": False}

    if fpolicy_config:
        # For updates, we reconfigure FPolicy
        _configure_fpolicy(client, svm_uuid, fpolicy_config)
        results["fpolicy_updated"] = True

    # Check for new volumes that need ARP
    old_volumes = set(old_properties.get("VolumeUuids", []))
    new_volumes = set(properties.get("VolumeUuids", []))
    added_volumes = new_volumes - old_volumes

    for vol_uuid in added_volumes:
        try:
            arp = client.enable_arp(vol_uuid, state=arp_state)
            logger.info(f"ARP on new volume {vol_uuid} is {arp.get('state', 'unknown')}")
        except Exception as e:
            logger.warning(f"Failed to enable ARP on new volume {vol_uuid}: {e}")

    return results


def _handle_delete(properties: dict[str, Any]) -> dict[str, Any]:
    """Handle Delete: Disable FPolicy (ARP is left enabled for safety).

    We intentionally do NOT disable ARP on delete — the protection
    should remain even if the CloudFormation stack is deleted.
    FPolicy policies are disabled to avoid orphaned external server references.
    """
    client = _get_ontap_client(properties)
    svm_uuid = properties["SvmUuid"]
    fpolicy_config = properties.get("FPolicyConfig", {})

    results: dict[str, Any] = {"fpolicy_disabled": False, "arp_preserved": True}

    # Disable FPolicy policies (but leave ARP active)
    if fpolicy_config:
        policy_name = fpolicy_config.get("policy_name", "")
        if policy_name:
            try:
                client.enable_fpolicy(svm_uuid, policy_name, priority=0)  # priority 0 = disabled
                results["fpolicy_disabled"] = True
                logger.info(f"FPolicy policy '{policy_name}' disabled on SVM {svm_uuid}")
            except Exception as e:
                logger.warning(f"Failed to disable FPolicy: {e}")

    return results


def _configure_fpolicy(
    client: Any,
    svm_uuid: str,
    config: dict[str, Any],
) -> None:
    """Configure FPolicy engine, event, and policy.

    Args:
        client: ONTAP API client.
        svm_uuid: SVM UUID.
        config: FPolicy configuration dict with keys:
            - engine_name: External engine name
            - primary_servers: List of scanner server IPs
            - port: Scanner port (default 1344)
            - engine_type: 'synchronous' or 'asynchronous'
            - event_name: Event name
            - file_operations: Dict of operations to monitor
            - policy_name: Policy name
            - is_mandatory: Whether to block I/O on server failure
    """
    engine_name = config.get("engine_name", "cyber-resilience-engine")
    primary_servers = config.get("primary_servers", [])
    port = config.get("port", 1344)
    engine_type = config.get("engine_type", "synchronous")
    event_name = config.get("event_name", "cyber-resilience-event")
    file_operations = config.get("file_operations", {"write": True, "create": True, "rename": True})
    policy_name = config.get("policy_name", "cyber-resilience-policy")
    is_mandatory = config.get("is_mandatory", False)

    # Create engine
    try:
        client.create_fpolicy_engine(
            svm_uuid=svm_uuid,
            name=engine_name,
            primary_servers=primary_servers,
            port=port,
            engine_type=engine_type,
        )
        logger.info(f"FPolicy engine '{engine_name}' created")
    except Exception as e:
        if "duplicate" in str(e).lower() or "already exists" in str(e).lower():
            logger.info(f"FPolicy engine '{engine_name}' already exists, skipping")
        else:
            raise

    # Create event
    try:
        client.create_fpolicy_event(
            svm_uuid=svm_uuid,
            name=event_name,
            file_operations=file_operations,
        )
        logger.info(f"FPolicy event '{event_name}' created")
    except Exception as e:
        if "duplicate" in str(e).lower() or "already exists" in str(e).lower():
            logger.info(f"FPolicy event '{event_name}' already exists, skipping")
        else:
            raise

    # Create policy
    try:
        client.create_fpolicy_policy(
            svm_uuid=svm_uuid,
            name=policy_name,
            engine_name=engine_name,
            events=[event_name],
            is_mandatory=is_mandatory,
        )
        logger.info(f"FPolicy policy '{policy_name}' created")
    except Exception as e:
        if "duplicate" in str(e).lower() or "already exists" in str(e).lower():
            logger.info(f"FPolicy policy '{policy_name}' already exists, skipping")
        else:
            raise

    # Enable policy
    client.enable_fpolicy(svm_uuid, policy_name, priority=1)
    logger.info(f"FPolicy policy '{policy_name}' enabled with priority 1")


def _configure_mav(client: Any, config: dict[str, Any]) -> None:
    """Configure Multi-Admin Verification (MAV) for destructive operations.

    MAV requires ONTAP 9.11.1+. Protected operations require approval
    from a configurable number of administrators before execution.

    Args:
        client: ONTAP API client.
        config: MAV configuration dict with keys:
            - enabled: Whether to enable MAV
            - required_approvers: Minimum approvers (default: 2)
            - approval_expiry_hours: Hours before request expires (default: 24)
            - protected_operations: List of operations to protect
    """
    enabled = config.get("enabled", True)
    required_approvers = config.get("required_approvers", 2)
    approval_expiry = config.get("approval_expiry_hours", 24)
    protected_operations = config.get(
        "protected_operations",
        [
            "volume delete",
            "volume offline",
            "security anti-ransomware volume disable",
            "vserver export-policy rule delete",
            "snapshot policy delete",
        ],
    )

    try:
        # Enable MAV globally
        client._request(
            "PATCH",
            "/security/multi-admin-verify",
            body={
                "enabled": enabled,
                "required_approvers": required_approvers,
                "approval_expiry": f"PT{approval_expiry}H",
            },
        )
        logger.info(f"MAV enabled: required_approvers={required_approvers}")

        # Configure protected operations
        for operation in protected_operations:
            try:
                client._request(
                    "POST",
                    "/security/multi-admin-verify/rules",
                    body={
                        "operation": operation,
                        "required_approvers": required_approvers,
                    },
                )
                logger.info(f"MAV rule created: {operation}")
            except Exception as e:
                if "duplicate" in str(e).lower() or "already exists" in str(e).lower():
                    logger.info(f"MAV rule already exists: {operation}")
                else:
                    logger.warning(f"Failed to create MAV rule '{operation}': {e}")

    except Exception as e:
        if "not supported" in str(e).lower():
            logger.warning(f"MAV not supported on this ONTAP version: {e}")
        else:
            raise


def _get_ontap_client(properties: dict[str, Any]) -> Any:
    """Create ONTAP client from Custom Resource properties.

    Uses a minimal inline implementation to avoid Lambda Layer dependency
    for the Custom Resource. For production, use the shared OntapClient.
    """
    import sys

    sys.path.insert(0, "/opt/python")  # Lambda Layer path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shared"))

    from ontap_client import OntapClient

    return OntapClient(
        management_endpoint=properties["ManagementEndpoint"],
        secret_arn=properties["SecretArn"],
    )


def _send_response(
    event: dict[str, Any],
    context: Any,
    status: str,
    physical_resource_id: str,
    data: dict[str, Any],
) -> None:
    """Send response to CloudFormation.

    Args:
        event: Original CloudFormation event.
        context: Lambda context.
        status: SUCCESS or FAILED.
        physical_resource_id: Resource ID for CloudFormation.
        data: Response data dict.
    """
    response_url = event.get("ResponseURL", "")
    if not response_url:
        logger.warning("No ResponseURL — skipping CFn response (likely a test invocation)")
        return

    response_body = json.dumps(
        {
            "Status": status,
            "Reason": data.get("Error", f"See CloudWatch Log Stream: {context.log_stream_name}"),
            "PhysicalResourceId": physical_resource_id,
            "StackId": event.get("StackId", ""),
            "RequestId": event.get("RequestId", ""),
            "LogicalResourceId": event.get("LogicalResourceId", ""),
            "Data": {k: str(v)[:1024] for k, v in data.items() if k != "Error"},
        }
    )

    http = urllib3.PoolManager()
    http.request(
        "PUT",
        response_url,
        body=response_body.encode(),
        headers={"Content-Type": ""},
    )
    logger.info(f"CFn response sent: {status}")

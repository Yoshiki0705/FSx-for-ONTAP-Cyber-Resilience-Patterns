"""ONTAP REST API client for FSx for ONTAP management operations.

Provides a reusable client for interacting with the ONTAP REST API
through the FSx for ONTAP management endpoint. Handles authentication
via AWS Secrets Manager and TLS certificate verification.

Usage:
    from solutions.shared.ontap_client import OntapClient

    client = OntapClient(
        management_endpoint="management.fs-0123456789abcdef0.fsx.ap-northeast-1.amazonaws.com",
        secret_arn="arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:fsxn-cyber-resilience-fsxadmin-XXXXXX"
    )
    volumes = client.list_volumes(svm_name="svm-prod-dev")
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import boto3
import urllib3

# Suppress InsecureRequestWarning for FSx self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

#: ARP volume states, grouped by what they mean for protection.
#:
#: Seven values, not six. The CLI reference enumerates seven in the parameter list and
#: then describes six in the prose below it, dropping ``paused``; reading only the prose
#: leaves a value that reaches production and matches nothing. A value missing from a
#: mapping falls through to whatever the default branch says, and when that branch reads
#: "not protected" a volume that is still protected gets reported as unprotected. That
#: failure is silent -- nothing raises -- so a test that never supplies the value passes.
#:
#: REST returns underscores (``disable_in_progress``) and the CLI prints hyphens
#: (``disable-in-progress``); the tokens come from the verb, so it is ``disable_``, never
#: ``disabled_``. Normalize before comparing.
ARP_PROTECTING = frozenset({"enabled", "dry_run"})
ARP_NOT_PROTECTING = frozenset({"disabled", "paused", "dry_run_paused", "enable_paused"})
#: Still protecting, on the way out. Discarding the learned state took more than 10
#: minutes on a 20 GiB empty volume, so this is a state operators will observe.
ARP_TRANSITIONAL = frozenset({"disable_in_progress"})


def _normalize_arp_state(state: Any) -> str:
    """Reduce an ARP state to a comparable token.

    Args:
        state: Value from REST or the CLI, in either spelling.

    Returns:
        The lowercase underscore form, or an empty string when absent.
    """
    if not isinstance(state, str):
        return ""
    return state.strip().lower().replace("-", "_")


def classify_arp_state(state: Any) -> str:
    """Say what an ARP state means for protection.

    Args:
        state: Value from REST or the CLI, in either spelling.

    Returns:
        ``protecting``, ``not_protecting``, ``transitional`` or ``unknown``. An
        unrecognised value is ``unknown`` and never silently ``not_protecting``: the
        caller has to decide what to do with a value this code has not seen, rather than
        inheriting an answer from a default branch.
    """
    token = _normalize_arp_state(state)
    if token in ARP_PROTECTING:
        return "protecting"
    if token in ARP_NOT_PROTECTING:
        return "not_protecting"
    if token in ARP_TRANSITIONAL:
        return "transitional"
    return "unknown"


@dataclass
class OntapApiError(Exception):
    """Raised when ONTAP REST API returns an error."""

    status_code: int
    message: str
    target: str = ""

    def __str__(self) -> str:
        return f"ONTAP API Error [{self.status_code}]: {self.message} (target: {self.target})"


@dataclass
class OntapClient:
    """Client for ONTAP REST API operations on FSx for ONTAP.

    Attributes:
        management_endpoint: FSx for ONTAP management DNS name or IP.
        secret_arn: ARN of Secrets Manager secret containing fsxadmin credentials.
        verify_ssl: Whether to verify SSL certificates (False for FSx self-signed).
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retries for transient failures.
    """

    management_endpoint: str
    secret_arn: str
    verify_ssl: bool = False
    timeout: int = 30
    max_retries: int = 3
    _credentials: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _http: urllib3.PoolManager = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize HTTP client and fetch credentials."""
        self._http = urllib3.PoolManager(
            cert_reqs="CERT_NONE" if not self.verify_ssl else "CERT_REQUIRED",
            timeout=urllib3.Timeout(connect=10, read=self.timeout),
            retries=urllib3.Retry(total=self.max_retries, backoff_factor=1),
        )
        self._credentials = self._get_credentials()

    def _get_credentials(self) -> dict[str, str]:
        """Retrieve fsxadmin credentials from Secrets Manager."""
        client = boto3.client("secretsmanager")
        response = client.get_secret_value(SecretId=self.secret_arn)
        secret = json.loads(response["SecretString"])
        return {
            "username": secret.get("username", "fsxadmin"),
            "password": secret["password"],
        }

    @property
    def _base_url(self) -> str:
        """Base URL for ONTAP REST API."""
        return f"https://{self.management_endpoint}/api"

    @property
    def _auth_headers(self) -> dict[str, str]:
        """HTTP headers with Basic authentication."""
        import base64

        credentials = f"{self._credentials['username']}:{self._credentials['password']}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute an API request with retry logic.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE).
            path: API path (e.g., /storage/volumes).
            body: Request body for POST/PATCH.

        Returns:
            Parsed JSON response.

        Raises:
            OntapApiError: On non-2xx response.
        """
        url = f"{self._base_url}{path}"
        encoded_body = json.dumps(body).encode() if body else None

        logger.info(f"ONTAP API {method} {path}")

        response = self._http.request(
            method,
            url,
            headers=self._auth_headers,
            body=encoded_body,
        )

        if response.status == 202:
            # Async job — poll for completion
            return self._poll_job(response)

        if response.status >= 400:
            error_data = json.loads(response.data.decode()) if response.data else {}
            error_msg = error_data.get("error", {}).get("message", f"HTTP {response.status}")
            raise OntapApiError(
                status_code=response.status,
                message=error_msg,
                target=path,
            )

        if response.data:
            return json.loads(response.data.decode())
        return {}

    def _poll_job(self, response: urllib3.HTTPResponse, poll_interval: int = 2) -> dict[str, Any]:
        """Poll an async job until completion.

        Args:
            response: Initial 202 response containing job link.
            poll_interval: Seconds between polls.

        Returns:
            Final job result.
        """
        data = json.loads(response.data.decode()) if response.data else {}
        job_link = data.get("job", {}).get("_links", {}).get("self", {}).get("href", "")

        if not job_link:
            return data

        logger.info(f"Polling job: {job_link}")

        for _ in range(60):  # Max 2 minutes
            time.sleep(poll_interval)
            job_response = self._http.request(
                "GET",
                f"https://{self.management_endpoint}{job_link}",
                headers=self._auth_headers,
            )
            job_data = json.loads(job_response.data.decode())
            state = job_data.get("state", "")

            if state == "success":
                return job_data
            elif state == "failure":
                error_msg = job_data.get("error", {}).get("message", "Job failed")
                raise OntapApiError(status_code=500, message=error_msg, target=job_link)

        raise OntapApiError(status_code=408, message="Job polling timeout", target=job_link)

    # ------------------------------------------------------------------
    # Volume operations
    # ------------------------------------------------------------------

    def list_volumes(self, svm_name: str | None = None) -> list[dict[str, Any]]:
        """List all volumes, optionally filtered by SVM.

        Args:
            svm_name: Filter by SVM name (optional).

        Returns:
            List of volume records.
        """
        path = "/storage/volumes?fields=name,svm,state,type,space,nas"
        if svm_name:
            path += f"&svm.name={svm_name}"
        result = self._request("GET", path)
        return result.get("records", [])

    def get_volume(self, volume_uuid: str) -> dict[str, Any]:
        """Get volume details by UUID."""
        return self._request("GET", f"/storage/volumes/{volume_uuid}?fields=*")

    def create_snapshot(self, volume_uuid: str, name: str) -> dict[str, Any]:
        """Create a snapshot on a volume.

        Args:
            volume_uuid: Target volume UUID.
            name: Snapshot name.

        Returns:
            Created snapshot record.
        """
        return self._request(
            "POST",
            f"/storage/volumes/{volume_uuid}/snapshots",
            body={"name": name},
        )

    def create_clone(
        self,
        svm_uuid: str,
        parent_volume_uuid: str,
        clone_name: str,
        snapshot_uuid: str | None = None,
    ) -> dict[str, Any]:
        """Create a FlexClone volume.

        Args:
            svm_uuid: SVM UUID for the clone.
            parent_volume_uuid: Source volume UUID.
            clone_name: Name for the clone volume.
            snapshot_uuid: Base snapshot UUID (optional).

        Returns:
            Created clone volume record.
        """
        body: dict[str, Any] = {
            "name": clone_name,
            "svm": {"uuid": svm_uuid},
            "clone": {
                "parent_volume": {"uuid": parent_volume_uuid},
                "is_flexclone": True,
            },
        }
        if snapshot_uuid:
            body["clone"]["parent_snapshot"] = {"uuid": snapshot_uuid}

        return self._request("POST", "/storage/volumes", body=body)

    # ------------------------------------------------------------------
    # ARP operations
    # ------------------------------------------------------------------

    def enable_arp(self, volume_uuid: str, state: str = "enabled") -> dict[str, Any]:
        """Enable Autonomous Ransomware Protection on a volume.

        **The requested state is not the resulting state.** On ARP/AI (ONTAP 9.16.1 and
        later) there is no learning period, so a request for ``dry_run`` returns 200 and
        the volume lands in ``enabled`` with neither a warning nor an error (measured
        2026-08-15 on ONTAP 9.18.1P3D1). Returning the request would report a volume as
        learning while it is actively protecting, so this reads the state back and says
        whether the two differ. Callers must report ``state``, never the value they asked
        for.

        The default is ``enabled`` rather than ``dry_run`` because ``dry_run`` is not
        reachable on the current model, and a default that silently means something else
        is worse than one that means what it says.

        Args:
            volume_uuid: Target volume UUID.
            state: Requested ARP state. ``enabled`` for active protection; ``dry_run``
                only on the original ARP model (ONTAP 9.10.1 to 9.15.1, and FlexGroup
                through 9.17.1).

        Returns:
            The ARP configuration as read back, plus ``requested`` (what was asked for)
            and ``differs`` (whether ONTAP landed somewhere else).
        """
        self._request(
            "PATCH",
            f"/security/anti-ransomware/volumes/{volume_uuid}",
            body={"state": state},
        )
        actual = self.get_arp_status(volume_uuid)
        result = dict(actual)
        result["requested"] = state
        result["differs"] = _normalize_arp_state(actual.get("state")) != _normalize_arp_state(state)
        return result

    def get_arp_status(self, volume_uuid: str) -> dict[str, Any]:
        """Get ARP status for a volume."""
        return self._request("GET", f"/security/anti-ransomware/volumes/{volume_uuid}")

    # ------------------------------------------------------------------
    # FPolicy operations
    # ------------------------------------------------------------------

    def create_fpolicy_engine(
        self,
        svm_uuid: str,
        name: str,
        primary_servers: list[str],
        port: int = 1344,
        engine_type: str = "synchronous",
    ) -> dict[str, Any]:
        """Create an FPolicy external engine.

        Args:
            svm_uuid: SVM UUID.
            name: Engine name.
            primary_servers: List of server IP addresses.
            port: Server port (default 1344 for ICAP).
            engine_type: 'synchronous' or 'asynchronous'.

        Returns:
            Created engine record.
        """
        return self._request(
            "POST",
            f"/protocols/fpolicy/{svm_uuid}/engines",
            body={
                "name": name,
                "primary_servers": primary_servers,
                "port": port,
                "type": engine_type,
            },
        )

    def create_fpolicy_event(
        self,
        svm_uuid: str,
        name: str,
        file_operations: dict[str, bool],
        protocol: str = "cifs",
    ) -> dict[str, Any]:
        """Create an FPolicy event definition.

        Args:
            svm_uuid: SVM UUID.
            name: Event name.
            file_operations: Dict of operations (e.g., {"write": True, "create": True}).
            protocol: Protocol to monitor ('cifs', 'nfsv3', 'nfsv4').

        Returns:
            Created event record.
        """
        return self._request(
            "POST",
            f"/protocols/fpolicy/{svm_uuid}/events",
            body={
                "name": name,
                "protocol": protocol,
                "file_operations": file_operations,
            },
        )

    def create_fpolicy_policy(
        self,
        svm_uuid: str,
        name: str,
        engine_name: str,
        events: list[str],
        is_mandatory: bool = False,
    ) -> dict[str, Any]:
        """Create an FPolicy policy.

        Args:
            svm_uuid: SVM UUID.
            name: Policy name.
            engine_name: External engine name to use.
            events: List of event names to associate.
            is_mandatory: If True, I/O blocked when server unavailable.

        Returns:
            Created policy record.
        """
        return self._request(
            "POST",
            f"/protocols/fpolicy/{svm_uuid}/policies",
            body={
                "name": name,
                "engine": {"name": engine_name},
                "events": [{"name": e} for e in events],
                "mandatory": is_mandatory,
            },
        )

    def enable_fpolicy(self, svm_uuid: str, policy_name: str, priority: int = 1) -> dict[str, Any]:
        """Enable an FPolicy policy.

        Args:
            svm_uuid: SVM UUID.
            policy_name: Policy name to enable.
            priority: Sequence priority (1 = highest).

        Returns:
            Enablement result.
        """
        return self._request(
            "PATCH",
            f"/protocols/fpolicy/{svm_uuid}/policies/{policy_name}",
            body={"enabled": True, "priority": priority},
        )

    # ------------------------------------------------------------------
    # Export Policy operations (for quarantine)
    # ------------------------------------------------------------------

    def get_export_policy(self, svm_uuid: str, policy_name: str = "default") -> dict[str, Any]:
        """Get export policy details."""
        result = self._request(
            "GET",
            f"/protocols/nfs/export-policies?svm.uuid={svm_uuid}&name={policy_name}",
        )
        records = result.get("records", [])
        return records[0] if records else {}

    def restrict_export_policy(self, policy_id: int) -> dict[str, Any]:
        """Restrict all export policy rules to deny access (quarantine).

        Args:
            policy_id: Export policy ID to restrict.

        Returns:
            Updated policy rules.
        """
        # Get current rules
        rules = self._request("GET", f"/protocols/nfs/export-policies/{policy_id}/rules")

        # Delete all existing rules
        for rule in rules.get("records", []):
            rule_index = rule.get("index")
            if rule_index:
                self._request(
                    "DELETE",
                    f"/protocols/nfs/export-policies/{policy_id}/rules/{rule_index}",
                )

        # Create a deny-all rule
        return self._request(
            "POST",
            f"/protocols/nfs/export-policies/{policy_id}/rules",
            body={
                "clients": [{"match": "0.0.0.0/0"}],
                "ro_rule": ["never"],
                "rw_rule": ["never"],
                "superuser": ["none"],
                "protocols": ["any"],
            },
        )

    def restore_export_policy(
        self,
        policy_id: int,
        client_match: str = "0.0.0.0/0",
    ) -> dict[str, Any]:
        """Restore export policy to allow access (un-quarantine).

        Args:
            policy_id: Export policy ID to restore.
            client_match: Client match pattern for the allow rule.

        Returns:
            Updated policy rules.
        """
        # Remove quarantine rule
        rules = self._request("GET", f"/protocols/nfs/export-policies/{policy_id}/rules")
        for rule in rules.get("records", []):
            rule_index = rule.get("index")
            if rule_index:
                self._request(
                    "DELETE",
                    f"/protocols/nfs/export-policies/{policy_id}/rules/{rule_index}",
                )

        # Create permissive rule (restore access)
        return self._request(
            "POST",
            f"/protocols/nfs/export-policies/{policy_id}/rules",
            body={
                "clients": [{"match": client_match}],
                "ro_rule": ["sys"],
                "rw_rule": ["sys"],
                "superuser": ["sys"],
                "protocols": ["any"],
            },
        )

    # ------------------------------------------------------------------
    # SVM operations
    # ------------------------------------------------------------------

    def list_svms(self) -> list[dict[str, Any]]:
        """List all SVMs on the file system."""
        result = self._request("GET", "/svm/svms?fields=name,uuid,state")
        return result.get("records", [])

    def get_svm(self, svm_uuid: str) -> dict[str, Any]:
        """Get SVM details by UUID."""
        return self._request("GET", f"/svm/svms/{svm_uuid}?fields=*")

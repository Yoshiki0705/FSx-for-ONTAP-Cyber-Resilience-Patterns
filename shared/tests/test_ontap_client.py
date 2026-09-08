"""Unit tests for OntapClient — ONTAP REST API client.

Uses unittest.mock to avoid real network/Secrets Manager calls.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from ontap_client import OntapApiError, OntapClient


@pytest.fixture
def mock_credentials():
    """Mock Secrets Manager response for fsxadmin credentials."""
    return {"username": "fsxadmin", "password": "test-password-123"}


@pytest.fixture
def client(mock_credentials):
    """Create an OntapClient with mocked credentials."""
    with patch("ontap_client.boto3.client") as mock_boto:
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {
            "SecretString": json.dumps(mock_credentials),
        }
        mock_boto.return_value = mock_sm
        return OntapClient(
            management_endpoint="management.fs-0123456789abcdef0.fsx.ap-northeast-1.amazonaws.com",
            secret_arn="arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:test-secret",
        )


class TestOntapClientInit:
    """Tests for OntapClient initialization."""

    def test_base_url(self, client):
        expected = "https://management.fs-0123456789abcdef0.fsx.ap-northeast-1.amazonaws.com/api"
        assert client._base_url == expected

    def test_auth_headers_contain_basic(self, client):
        headers = client._auth_headers
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")
        assert headers["Content-Type"] == "application/json"

    def test_credentials_loaded(self, client):
        assert client._credentials["username"] == "fsxadmin"
        assert client._credentials["password"] == "test-password-123"


class TestOntapApiError:
    """Tests for OntapApiError exception class."""

    def test_str_representation(self):
        error = OntapApiError(status_code=404, message="Not found", target="/api/test")
        assert "404" in str(error)
        assert "Not found" in str(error)
        assert "/api/test" in str(error)

    def test_default_target(self):
        error = OntapApiError(status_code=500, message="Server error")
        assert error.target == ""


class TestVolumeOperations:
    """Tests for volume-related API operations."""

    def test_list_volumes(self, client):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.data = json.dumps(
            {
                "records": [
                    {"name": "vol1", "uuid": "uuid-1", "svm": {"name": "svm-prod"}},
                    {"name": "vol2", "uuid": "uuid-2", "svm": {"name": "svm-prod"}},
                ]
            }
        ).encode()

        client._http.request = MagicMock(return_value=mock_response)
        volumes = client.list_volumes(svm_name="svm-prod")

        assert len(volumes) == 2
        assert volumes[0]["name"] == "vol1"
        # Verify SVM filter was applied
        call_args = client._http.request.call_args
        assert "svm.name=svm-prod" in call_args[0][1]

    def test_list_volumes_no_filter(self, client):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.data = json.dumps({"records": []}).encode()

        client._http.request = MagicMock(return_value=mock_response)
        volumes = client.list_volumes()

        assert volumes == []
        call_args = client._http.request.call_args
        assert "svm.name" not in call_args[0][1]

    def test_get_volume(self, client):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.data = json.dumps({"name": "vol1", "uuid": "uuid-1", "state": "online"}).encode()

        client._http.request = MagicMock(return_value=mock_response)
        volume = client.get_volume("uuid-1")

        assert volume["name"] == "vol1"
        assert volume["state"] == "online"

    def test_create_snapshot(self, client):
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.data = json.dumps({"name": "forensic-snap-001"}).encode()

        client._http.request = MagicMock(return_value=mock_response)
        result = client.create_snapshot("vol-uuid-1", "forensic-snap-001")

        assert result["name"] == "forensic-snap-001"
        call_args = client._http.request.call_args
        assert "vol-uuid-1" in call_args[0][1]
        assert "snapshots" in call_args[0][1]

    def test_create_clone(self, client):
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.data = json.dumps({"name": "forensic-clone"}).encode()

        client._http.request = MagicMock(return_value=mock_response)
        result = client.create_clone(
            svm_uuid="svm-uuid-1",
            parent_volume_uuid="vol-uuid-1",
            clone_name="forensic-clone",
            snapshot_uuid="snap-uuid-1",
        )

        assert result["name"] == "forensic-clone"
        call_args = client._http.request.call_args
        body = json.loads(call_args[1]["body"])
        assert body["clone"]["is_flexclone"] is True
        assert body["clone"]["parent_snapshot"]["uuid"] == "snap-uuid-1"


class TestArpOperations:
    """Tests for ARP (Autonomous Ransomware Protection) operations."""

    @staticmethod
    def _responses(client, *states):
        """Return one mock response per state, in order.

        Args:
            client: Client whose transport is replaced.
            states: ARP states the successive calls should report.
        """
        mocks = []
        for state in states:
            response = MagicMock()
            response.status = 200
            response.data = json.dumps({"state": state}).encode()
            mocks.append(response)
        client._http.request = MagicMock(side_effect=mocks)

    def test_enable_arp_reads_the_state_back(self, client):
        """The PATCH is followed by a GET, and the GET is what gets reported."""
        self._responses(client, "enabled", "enabled")

        result = client.enable_arp("vol-uuid-1", state="enabled")

        assert result["state"] == "enabled"
        assert result["requested"] == "enabled"
        assert result["differs"] is False
        methods = [call[0][0] for call in client._http.request.call_args_list]
        assert methods == ["PATCH", "GET"]
        body = json.loads(client._http.request.call_args_list[0][1]["body"])
        assert body["state"] == "enabled"

    def test_a_dry_run_request_that_lands_as_enabled_is_reported_as_enabled(self, client):
        """ARP/AI has no learning period: dry_run returns 200 and lands as enabled.

        Measured 2026-08-15 on ONTAP 9.18.1P3D1. Echoing the request would report a volume
        that is actively protecting as still learning, so the difference is surfaced.
        """
        self._responses(client, "dry_run", "enabled")

        result = client.enable_arp("vol-uuid-1", state="dry_run")

        assert result["state"] == "enabled"
        assert result["requested"] == "dry_run"
        assert result["differs"] is True

    def test_hyphen_and_underscore_spellings_compare_equal(self, client):
        """REST returns underscores and the CLI prints hyphens; neither is a difference."""
        self._responses(client, "disable_in_progress", "disable-in-progress")

        result = client.enable_arp("vol-uuid-1", state="disable_in_progress")

        assert result["differs"] is False

    def test_get_arp_status(self, client):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.data = json.dumps(
            {
                "state": "enabled",
                "suspect_files": [],
            }
        ).encode()

        client._http.request = MagicMock(return_value=mock_response)
        result = client.get_arp_status("vol-uuid-1")

        assert result["state"] == "enabled"


class TestFpolicyOperations:
    """Tests for FPolicy operations."""

    def test_create_fpolicy_engine(self, client):
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.data = json.dumps({"name": "vscan-engine"}).encode()

        client._http.request = MagicMock(return_value=mock_response)
        result = client.create_fpolicy_engine(
            svm_uuid="svm-uuid-1",
            name="vscan-engine",
            primary_servers=["10.0.3.10"],
            port=1344,
        )

        assert result["name"] == "vscan-engine"
        call_args = client._http.request.call_args
        body = json.loads(call_args[1]["body"])
        assert body["primary_servers"] == ["10.0.3.10"]
        assert body["port"] == 1344
        assert body["type"] == "synchronous"

    def test_create_fpolicy_event(self, client):
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.data = json.dumps({"name": "write-event"}).encode()

        client._http.request = MagicMock(return_value=mock_response)
        result = client.create_fpolicy_event(
            svm_uuid="svm-uuid-1",
            name="write-event",
            file_operations={"write": True, "create": True},
            protocol="cifs",
        )

        assert result["name"] == "write-event"
        call_args = client._http.request.call_args
        body = json.loads(call_args[1]["body"])
        assert body["file_operations"]["write"] is True
        assert body["protocol"] == "cifs"

    def test_create_fpolicy_policy(self, client):
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.data = json.dumps({"name": "malware-scan"}).encode()

        client._http.request = MagicMock(return_value=mock_response)
        result = client.create_fpolicy_policy(
            svm_uuid="svm-uuid-1",
            name="malware-scan",
            engine_name="vscan-engine",
            events=["write-event"],
            is_mandatory=False,
        )

        assert result["name"] == "malware-scan"
        call_args = client._http.request.call_args
        body = json.loads(call_args[1]["body"])
        assert body["engine"]["name"] == "vscan-engine"
        assert body["mandatory"] is False


class TestExportPolicyOperations:
    """Tests for export policy operations (quarantine/restore)."""

    def test_restrict_export_policy(self, client):
        # Mock GET rules response
        rules_response = MagicMock()
        rules_response.status = 200
        rules_response.data = json.dumps(
            {
                "records": [{"index": 1}, {"index": 2}],
            }
        ).encode()

        # Mock DELETE responses
        delete_response = MagicMock()
        delete_response.status = 200
        delete_response.data = b"{}"

        # Mock POST (create deny-all rule) response
        post_response = MagicMock()
        post_response.status = 201
        post_response.data = json.dumps(
            {
                "clients": [{"match": "0.0.0.0/0"}],
                "ro_rule": ["never"],
            }
        ).encode()

        client._http.request = MagicMock(
            side_effect=[
                rules_response,
                delete_response,
                delete_response,
                post_response,
            ]
        )
        result = client.restrict_export_policy(policy_id=1)

        assert result["ro_rule"] == ["never"]
        # Verify: 1 GET + 2 DELETE + 1 POST = 4 calls
        assert client._http.request.call_count == 4

    def test_restore_export_policy(self, client):
        # Mock GET rules response
        rules_response = MagicMock()
        rules_response.status = 200
        rules_response.data = json.dumps(
            {
                "records": [{"index": 1}],
            }
        ).encode()

        # Mock DELETE response
        delete_response = MagicMock()
        delete_response.status = 200
        delete_response.data = b"{}"

        # Mock POST (create allow rule)
        post_response = MagicMock()
        post_response.status = 201
        post_response.data = json.dumps(
            {
                "clients": [{"match": "0.0.0.0/0"}],
                "ro_rule": ["sys"],
                "rw_rule": ["sys"],
            }
        ).encode()

        client._http.request = MagicMock(side_effect=[rules_response, delete_response, post_response])
        result = client.restore_export_policy(policy_id=1, client_match="10.0.0.0/16")

        assert result["rw_rule"] == ["sys"]
        # Verify POST body has custom client match
        post_call = client._http.request.call_args_list[-1]
        body = json.loads(post_call[1]["body"])
        assert body["clients"][0]["match"] == "10.0.0.0/16"


class TestErrorHandling:
    """Tests for error handling and async job polling."""

    def test_api_error_on_4xx(self, client):
        mock_response = MagicMock()
        mock_response.status = 404
        mock_response.data = json.dumps({"error": {"message": "Volume not found"}}).encode()

        client._http.request = MagicMock(return_value=mock_response)

        with pytest.raises(OntapApiError) as exc_info:
            client.get_volume("nonexistent-uuid")

        assert exc_info.value.status_code == 404
        assert "Volume not found" in exc_info.value.message

    def test_api_error_on_5xx(self, client):
        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.data = json.dumps({"error": {"message": "Internal error"}}).encode()

        client._http.request = MagicMock(return_value=mock_response)

        with pytest.raises(OntapApiError) as exc_info:
            client.list_svms()

        assert exc_info.value.status_code == 500

    def test_async_job_polling_success(self, client):
        # Initial 202 response with job link
        async_response = MagicMock()
        async_response.status = 202
        async_response.data = json.dumps(
            {
                "job": {
                    "_links": {"self": {"href": "/api/cluster/jobs/job-uuid-1"}},
                }
            }
        ).encode()

        # Polling response: running
        running_response = MagicMock()
        running_response.status = 200
        running_response.data = json.dumps({"state": "running"}).encode()

        # Polling response: success
        success_response = MagicMock()
        success_response.status = 200
        success_response.data = json.dumps({"state": "success", "result": "done"}).encode()

        client._http.request = MagicMock(side_effect=[async_response, running_response, success_response])

        with patch("ontap_client.time.sleep"):
            result = client.create_snapshot("vol-uuid", "snap-name")

        assert result["state"] == "success"

    def test_async_job_polling_failure(self, client):
        async_response = MagicMock()
        async_response.status = 202
        async_response.data = json.dumps(
            {
                "job": {
                    "_links": {"self": {"href": "/api/cluster/jobs/job-uuid-2"}},
                }
            }
        ).encode()

        failure_response = MagicMock()
        failure_response.status = 200
        failure_response.data = json.dumps(
            {
                "state": "failure",
                "error": {"message": "Disk full"},
            }
        ).encode()

        client._http.request = MagicMock(side_effect=[async_response, failure_response])

        with patch("ontap_client.time.sleep"):
            with pytest.raises(OntapApiError) as exc_info:
                client.create_snapshot("vol-uuid", "snap-name")

        assert "Disk full" in exc_info.value.message


class TestSvmOperations:
    """Tests for SVM operations."""

    def test_list_svms(self, client):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.data = json.dumps(
            {
                "records": [
                    {"name": "svm-prod", "uuid": "svm-uuid-1", "state": "running"},
                    {"name": "svm-audit", "uuid": "svm-uuid-2", "state": "running"},
                ]
            }
        ).encode()

        client._http.request = MagicMock(return_value=mock_response)
        svms = client.list_svms()

        assert len(svms) == 2
        assert svms[0]["name"] == "svm-prod"

    def test_get_svm(self, client):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.data = json.dumps({"name": "svm-prod", "uuid": "svm-uuid-1", "state": "running"}).encode()

        client._http.request = MagicMock(return_value=mock_response)
        svm = client.get_svm("svm-uuid-1")

        assert svm["name"] == "svm-prod"
        assert svm["state"] == "running"

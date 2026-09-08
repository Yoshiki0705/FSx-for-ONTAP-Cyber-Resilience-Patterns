"""Unit tests for ONTAP security_config_handler Custom Resource Lambda."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from security_config_handler import (
    FAILED,
    SUCCESS,
    _configure_fpolicy,
    _handle_create,
    _handle_delete,
    _handle_update,
    handler,
)


@pytest.fixture
def mock_ontap_client():
    """Create a mocked OntapClient."""
    client = MagicMock()
    client.enable_arp.return_value = {"state": "dry_run"}
    client.create_fpolicy_engine.return_value = {"name": "test-engine"}
    client.create_fpolicy_event.return_value = {"name": "test-event"}
    client.create_fpolicy_policy.return_value = {"name": "test-policy"}
    client.enable_fpolicy.return_value = {"enabled": True}
    return client


@pytest.fixture
def base_properties():
    """Standard Custom Resource properties."""
    return {
        "ManagementEndpoint": "management.fs-0123456789abcdef0.fsx.ap-northeast-1.amazonaws.com",
        "SecretArn": "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:test",
        "SvmUuid": "svm-uuid-001",
        "VolumeUuids": ["vol-uuid-001", "vol-uuid-002"],
        "FPolicyConfig": {
            "engine_name": "cyber-resilience-engine",
            "primary_servers": ["10.0.3.10"],
            "port": 1344,
            "event_name": "file-write-scan",
            "file_operations": {"write": True, "create": True},
            "policy_name": "malware-scan",
            "is_mandatory": False,
        },
    }


@pytest.fixture
def cfn_event(base_properties):
    """CloudFormation Custom Resource event template."""
    return {
        "RequestType": "Create",
        "ResponseURL": "https://cloudformation-custom-resource-response-apnortheast1.s3.amazonaws.com/...",
        "StackId": "arn:aws:cloudformation:ap-northeast-1:123456789012:stack/test/guid",
        "RequestId": "unique-request-id",
        "ResourceType": "Custom::OntapSecurityConfig",
        "LogicalResourceId": "OntapSecurityConfig",
        "ResourceProperties": base_properties,
    }


class TestHandleCreate:
    """Tests for Create lifecycle."""

    @patch("security_config_handler._get_ontap_client")
    def test_create_enables_arp_on_all_volumes(self, mock_get_client, mock_ontap_client, base_properties):
        mock_get_client.return_value = mock_ontap_client

        result = _handle_create(base_properties)

        assert len(result["arp_volumes"]) == 2
        assert all(v["state"] == "dry_run" for v in result["arp_volumes"])
        assert mock_ontap_client.enable_arp.call_count == 2

    @patch("security_config_handler._get_ontap_client")
    def test_create_configures_fpolicy(self, mock_get_client, mock_ontap_client, base_properties):
        mock_get_client.return_value = mock_ontap_client

        result = _handle_create(base_properties)

        assert result["fpolicy_configured"] is True
        mock_ontap_client.create_fpolicy_engine.assert_called_once()
        mock_ontap_client.create_fpolicy_event.assert_called_once()
        mock_ontap_client.create_fpolicy_policy.assert_called_once()
        mock_ontap_client.enable_fpolicy.assert_called_once()

    @patch("security_config_handler._get_ontap_client")
    def test_create_without_fpolicy(self, mock_get_client, mock_ontap_client, base_properties):
        mock_get_client.return_value = mock_ontap_client
        del base_properties["FPolicyConfig"]

        result = _handle_create(base_properties)

        assert result["fpolicy_configured"] is False
        mock_ontap_client.create_fpolicy_engine.assert_not_called()

    @patch("security_config_handler._get_ontap_client")
    def test_create_arp_failure_continues(self, mock_get_client, mock_ontap_client, base_properties):
        """ARP failure on one volume should not block others."""
        mock_get_client.return_value = mock_ontap_client
        mock_ontap_client.enable_arp.side_effect = [
            Exception("API error"),
            {"state": "dry_run"},
        ]

        result = _handle_create(base_properties)

        assert len(result["arp_volumes"]) == 2
        assert "error" in result["arp_volumes"][0]
        assert result["arp_volumes"][1]["state"] == "dry_run"


class TestHandleUpdate:
    """Tests for Update lifecycle."""

    @patch("security_config_handler._get_ontap_client")
    def test_update_reconfigures_fpolicy(self, mock_get_client, mock_ontap_client, base_properties):
        mock_get_client.return_value = mock_ontap_client
        old_properties = {**base_properties, "VolumeUuids": ["vol-uuid-001"]}

        result = _handle_update(base_properties, old_properties)

        assert result["fpolicy_updated"] is True
        # Should enable ARP on newly added volume
        # `enabled` rather than `dry_run`: dry_run is not reachable on ARP/AI, and a
        # default that silently means something else is worse than one that means what it says.
        mock_ontap_client.enable_arp.assert_called_once_with("vol-uuid-002", state="enabled")

    @patch("security_config_handler._get_ontap_client")
    def test_update_no_new_volumes(self, mock_get_client, mock_ontap_client, base_properties):
        mock_get_client.return_value = mock_ontap_client

        _handle_update(base_properties, base_properties)

        mock_ontap_client.enable_arp.assert_not_called()


class TestHandleDelete:
    """Tests for Delete lifecycle."""

    @patch("security_config_handler._get_ontap_client")
    def test_delete_disables_fpolicy(self, mock_get_client, mock_ontap_client, base_properties):
        mock_get_client.return_value = mock_ontap_client

        result = _handle_delete(base_properties)

        assert result["fpolicy_disabled"] is True
        assert result["arp_preserved"] is True
        # ARP should NOT be disabled
        mock_ontap_client.enable_arp.assert_not_called()

    @patch("security_config_handler._get_ontap_client")
    def test_delete_without_fpolicy(self, mock_get_client, mock_ontap_client, base_properties):
        mock_get_client.return_value = mock_ontap_client
        del base_properties["FPolicyConfig"]

        result = _handle_delete(base_properties)

        assert result["fpolicy_disabled"] is False
        assert result["arp_preserved"] is True


class TestConfigureFpolicy:
    """Tests for FPolicy configuration with idempotency."""

    def test_duplicate_engine_handled(self, mock_ontap_client):
        """409 duplicate errors should be logged and skipped."""
        from ontap_client import OntapApiError

        mock_ontap_client.create_fpolicy_engine.side_effect = OntapApiError(
            status_code=409, message="duplicate entry", target="/fpolicy/engines"
        )

        config = {
            "engine_name": "test-engine",
            "primary_servers": ["10.0.3.10"],
            "port": 1344,
            "event_name": "test-event",
            "file_operations": {"write": True},
            "policy_name": "test-policy",
            "is_mandatory": False,
        }

        # Should not raise
        _configure_fpolicy(mock_ontap_client, "svm-uuid-001", config)

        # Policy and event creation should still proceed
        mock_ontap_client.create_fpolicy_event.assert_called_once()
        mock_ontap_client.create_fpolicy_policy.assert_called_once()
        mock_ontap_client.enable_fpolicy.assert_called_once()

    def test_non_duplicate_error_raises(self, mock_ontap_client):
        """Non-duplicate errors should propagate."""
        from ontap_client import OntapApiError

        mock_ontap_client.create_fpolicy_engine.side_effect = OntapApiError(
            status_code=500, message="internal server error", target="/fpolicy/engines"
        )

        config = {
            "engine_name": "test-engine",
            "primary_servers": ["10.0.3.10"],
            "port": 1344,
            "event_name": "test-event",
            "file_operations": {"write": True},
            "policy_name": "test-policy",
            "is_mandatory": False,
        }

        with pytest.raises(OntapApiError):
            _configure_fpolicy(mock_ontap_client, "svm-uuid-001", config)


class TestHandler:
    """Tests for the main handler function."""

    @patch("security_config_handler._send_response")
    @patch("security_config_handler._get_ontap_client")
    def test_handler_create_success(self, mock_get_client, mock_send, mock_ontap_client, cfn_event):
        mock_get_client.return_value = mock_ontap_client

        handler(cfn_event, MagicMock(log_stream_name="test-stream"))

        mock_send.assert_called_once()
        call_args = mock_send.call_args[0]
        assert call_args[2] == SUCCESS

    @patch("security_config_handler._send_response")
    @patch("security_config_handler._get_ontap_client")
    def test_handler_create_failure(self, mock_get_client, mock_send, cfn_event):
        mock_get_client.side_effect = Exception("Connection refused")

        handler(cfn_event, MagicMock(log_stream_name="test-stream"))

        mock_send.assert_called_once()
        call_args = mock_send.call_args[0]
        assert call_args[2] == FAILED

    @patch("security_config_handler._send_response")
    @patch("security_config_handler._get_ontap_client")
    def test_handler_delete(self, mock_get_client, mock_send, mock_ontap_client, cfn_event):
        mock_get_client.return_value = mock_ontap_client
        cfn_event["RequestType"] = "Delete"
        cfn_event["PhysicalResourceId"] = "ontap-security-existing-123"

        handler(cfn_event, MagicMock(log_stream_name="test-stream"))

        mock_send.assert_called_once()
        call_args = mock_send.call_args[0]
        assert call_args[2] == SUCCESS

"""Unit tests for ARP Lifecycle Manager Lambda."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

# Patch env vars before importing module
os.environ["STATE_TABLE_NAME"] = "test-arp-state"
os.environ["FSX_SECRET_ARN"] = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:test"
os.environ["MANAGEMENT_ENDPOINT"] = "management.fs-test.fsx.ap-northeast-1.amazonaws.com"
os.environ["SNS_TOPIC_ARN"] = "arn:aws:sns:ap-northeast-1:123456789012:test-topic"
os.environ["LEARNING_DAYS"] = "30"

import arp_lifecycle


class TestArpLifecycleHandler:
    """Tests for the daily lifecycle check handler."""

    @patch("arp_lifecycle.boto3.resource")
    @patch("arp_lifecycle.boto3.client")
    def test_no_volumes_in_dry_run(self, mock_client, mock_resource):
        mock_table = MagicMock()
        mock_table.scan.return_value = {"Items": []}
        mock_resource.return_value.Table.return_value = mock_table

        result = arp_lifecycle.handler({}, None)

        assert result["checked"] == 0
        assert result["transitioned"] == 0

    @patch("arp_lifecycle.boto3.resource")
    @patch("arp_lifecycle.boto3.client")
    def test_volume_not_yet_ready(self, mock_client, mock_resource):
        """Volume within learning period should not transition."""
        mock_table = MagicMock()
        recent_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        mock_table.scan.return_value = {
            "Items": [
                {
                    "volume_uuid": "vol-001",
                    "arp_start_date": recent_date,
                    "current_state": "dry_run",
                    "learning_days": 30,
                }
            ]
        }
        mock_resource.return_value.Table.return_value = mock_table

        result = arp_lifecycle.handler({}, None)

        assert result["checked"] == 1
        assert result["transitioned"] == 0

    @patch("arp_lifecycle._transition_arp")
    @patch("arp_lifecycle.boto3.resource")
    @patch("arp_lifecycle.boto3.client")
    def test_volume_ready_for_transition(self, mock_client, mock_resource, mock_transition):
        """Volume past learning period should transition."""
        mock_table = MagicMock()
        old_date = (datetime.now(timezone.utc) - timedelta(days=35)).isoformat()
        mock_table.scan.return_value = {
            "Items": [
                {
                    "volume_uuid": "vol-001",
                    "arp_start_date": old_date,
                    "current_state": "dry_run",
                    "learning_days": 30,
                }
            ]
        }
        mock_resource.return_value.Table.return_value = mock_table

        result = arp_lifecycle.handler({}, None)

        assert result["checked"] == 1
        assert result["transitioned"] == 1
        mock_transition.assert_called_once()

    @patch("arp_lifecycle._transition_arp")
    @patch("arp_lifecycle.boto3.resource")
    @patch("arp_lifecycle.boto3.client")
    def test_transition_failure_recorded(self, mock_client, mock_resource, mock_transition):
        """Failed transitions should be recorded in errors."""
        mock_table = MagicMock()
        old_date = (datetime.now(timezone.utc) - timedelta(days=35)).isoformat()
        mock_table.scan.return_value = {
            "Items": [
                {
                    "volume_uuid": "vol-fail",
                    "arp_start_date": old_date,
                    "current_state": "dry_run",
                    "learning_days": 30,
                }
            ]
        }
        mock_resource.return_value.Table.return_value = mock_table
        mock_transition.side_effect = Exception("ONTAP API error")

        result = arp_lifecycle.handler({}, None)

        assert result["checked"] == 1
        assert result["transitioned"] == 0
        assert len(result["errors"]) == 1
        assert "vol-fail" in result["errors"][0]["volume_uuid"]


class TestTransitionArp:
    """Tests for the ARP state transition function."""

    @staticmethod
    def _run(mock_client_class, before, landed):
        """Drive one transition with a given observed state.

        Args:
            mock_client_class: Patched OntapClient class.
            before: State the volume reports before the call.
            landed: State reported after enable_arp, when it is called.

        Returns:
            The client, table and SNS mocks.
        """
        client = MagicMock()
        client.get_arp_status.return_value = {"state": before}
        client.enable_arp.return_value = {"state": landed}
        mock_client_class.return_value = client
        table, sns = MagicMock(), MagicMock()

        with patch("arp_lifecycle.MANAGEMENT_ENDPOINT", "test.endpoint"):
            with patch("arp_lifecycle.FSX_SECRET_ARN", "test-secret"):
                arp_lifecycle._transition_arp("vol-001", table, sns)
        return client, table, sns

    @patch("ontap_client.OntapClient")
    def test_transition_calls_ontap_and_records_the_state_read_back(self, mock_client_class):
        client, table, sns = self._run(mock_client_class, before="dry_run", landed="enabled")

        client.enable_arp.assert_called_once_with("vol-001", state="enabled")

        payload = json.loads(sns.publish.call_args[1]["Message"])
        assert payload["from_state"] == "dry_run"
        assert payload["to_state"] == "enabled"
        assert payload["transition_performed"] is True
        assert "vol-001" in sns.publish.call_args[1]["Subject"]

        values = table.update_item.call_args[1]["ExpressionAttributeValues"]
        assert values[":state"] == "enabled"
        assert values[":before"] == "dry_run"

    @patch("ontap_client.OntapClient")
    def test_a_volume_already_enabled_is_not_transitioned(self, mock_client_class):
        """On ARP/AI the volume is active from the day it was registered.

        Announcing a transition then reports an event that did not happen.
        """
        client, table, sns = self._run(mock_client_class, before="enabled", landed="enabled")

        client.enable_arp.assert_not_called()

        payload = json.loads(sns.publish.call_args[1]["Message"])
        assert payload["transition_performed"] is False
        assert payload["from_state"] == "enabled"
        assert "already active" in sns.publish.call_args[1]["Subject"]

    @patch("ontap_client.OntapClient")
    def test_the_notification_follows_the_call(self, mock_client_class):
        """A failed enable must not produce a message saying protection is now active."""
        client = MagicMock()
        client.get_arp_status.return_value = {"state": "dry_run"}
        client.enable_arp.side_effect = RuntimeError("ONTAP unreachable")
        mock_client_class.return_value = client
        table, sns = MagicMock(), MagicMock()

        with patch("arp_lifecycle.MANAGEMENT_ENDPOINT", "test.endpoint"):
            with patch("arp_lifecycle.FSX_SECRET_ARN", "test-secret"):
                with pytest.raises(RuntimeError):
                    arp_lifecycle._transition_arp("vol-001", table, sns)

        sns.publish.assert_not_called()
        table.update_item.assert_not_called()

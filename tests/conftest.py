"""Pytest configuration — add solution directories to sys.path for imports."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add project root and solution directories to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "shared"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "event-driven-response" / "lambda"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "ontap-native" / "lambda"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "observability"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "deep-instinct"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "trendai-file-security"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "siem"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "compliance"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "supply-chain"))


@pytest.fixture
def mock_env_vars():
    """Mock Lambda environment variables for handler tests."""
    env = {
        "EVENT_BUS_NAME": "fsxn-cyber-resilience-security-dev",
        "FILE_SYSTEM_ID": "fs-0123456789abcdef0",
        "ENVIRONMENT": "dev",
        "FSX_SECRET_ARN": "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:fsxn-cyber-resilience-fsxadmin-XXXXXX",
    }
    with patch.dict(os.environ, env):
        yield env

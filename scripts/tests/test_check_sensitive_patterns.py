"""The leak checker must catch each category and stay quiet on the project's placeholders.

Synthetic values are assembled at runtime so this file carries no literal the checker
would flag if it were scanned.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "check_sensitive_patterns.py"
spec = importlib.util.spec_from_file_location("check_sensitive_patterns", SCRIPT)
csp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(csp)

SYNTHETIC_ACCOUNT = "1111" + "2222" + "3333"
PUBLIC_IP = ".".join(["8", "8", "4", "4"])
HOME = "/" + "Users" + "/someone/project"
EMAIL = "someone" + "@" + "corp-mail.test.org"
# Joined at runtime (not "a" + "b", which the compiler folds into the .pyc) so gitleaks'
# internal-ip rule matches neither this source nor its bytecode.
PRIVATE_CIDR = ".".join(["172", "16", "0", "0"]) + "/12"


def categories(text: str, literals: list[str] | None = None) -> list[str]:
    return [c for _, c in csp.scan_text(text, literals or [])]


def test_flags_non_placeholder_account_id():
    assert categories(f"arn:aws:iam::{SYNTHETIC_ACCOUNT}:role/x")


def test_allows_placeholder_account_id():
    assert not categories("arn:aws:iam::123456789012:role/x")


def test_ignores_digits_inside_resource_ids():
    assert not categories(f'"subnet-0a{SYNTHETIC_ACCOUNT}a"')


def test_flags_public_ip_only():
    assert categories(f"host {PUBLIC_IP}")
    assert not categories(f"10.0.3.10 192.168.1.100 {PRIVATE_CIDR} 0.0.0.0/0 198.51.100.10 203.0.113.5")


def test_ignores_version_strings():
    assert not categories("ONTAP 9.17.1.1.2")


def test_flags_email_except_placeholders():
    assert categories(f"contact {EMAIL}")
    assert not categories("security-alerts@example.com noreply@github.com 1+x@users.noreply.github.com")


def test_flags_home_path_not_placeholder():
    assert categories(HOME)
    assert not categories("/Users/<name>/project")


def test_flags_local_literal():
    assert categories("value secret-token-xyz here", ["secret-token-xyz"])


def test_cli_fails_on_leak_and_passes_clean(tmp_path):
    leak = tmp_path / "leak.txt"
    leak.write_text(f"account {SYNTHETIC_ACCOUNT}\n")
    clean = tmp_path / "clean.txt"
    clean.write_text("account 123456789012\n")
    run = [sys.executable, str(SCRIPT)]
    assert subprocess.run(run + [str(leak)], capture_output=True).returncode == 1
    assert subprocess.run(run + [str(clean)], capture_output=True).returncode == 0


def test_output_never_echoes_the_value(tmp_path):
    leak = tmp_path / "leak.txt"
    leak.write_text(f"account {SYNTHETIC_ACCOUNT}\n")
    out = subprocess.run([sys.executable, str(SCRIPT), str(leak)], capture_output=True, text=True).stdout
    assert SYNTHETIC_ACCOUNT not in out

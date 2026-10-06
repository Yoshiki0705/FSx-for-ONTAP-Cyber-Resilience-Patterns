#!/usr/bin/env python3
"""Fail when a file carries an account ID, public IP, personal email, or home path.

The pre-commit hook used to grep for the very values it was meant to keep out, so the
public repository published them. The detection here is generic and contains no real
value. Values specific to one environment are listed, one literal per line, in
`.sensitive-patterns.local` (gitignored) or in the `SENSITIVE_PATTERNS` environment
variable (newline-separated, e.g. from a CI secret). Both are optional.

Usage:
    python3 scripts/check_sensitive_patterns.py FILE...      # check the given files
    python3 scripts/check_sensitive_patterns.py --tracked    # check every tracked file

Exit 0 when clean, 1 on a finding, 2 on a usage error.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOCAL_FILE = REPO / ".sensitive-patterns.local"

# The placeholder this project uses in examples. Add a well-known public AWS account ID
# here only with the AWS documentation page that lists it in the comment.
ALLOWED_ACCOUNT_IDS = {"123456789012"}

# Documentation (RFC 5737 / RFC 3849), private (RFC 1918), and special-purpose ranges.
# Private addresses are gitleaks' job (`internal-ip-address` in .gitleaks.toml), which
# carries the placeholder allowlist for them; this check covers routable addresses.
ALLOWED_EMAIL_DOMAINS = re.compile(r"(^|\.)(example\.(com|org|net)|users\.noreply\.github\.com)$", re.I)
ALLOWED_EMAIL_LOCAL = re.compile(r"^(noreply|no-reply)$", re.I)

# Not scanned: this checker and its tests describe the patterns rather than carry them.
EXCLUDED = {"scripts/check_sensitive_patterns.py", "scripts/tests/test_check_sensitive_patterns.py"}

ACCOUNT_ID = re.compile(r"(?<![0-9A-Za-z_])[0-9]{12}(?![0-9A-Za-z_])")
IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
HOME_PATH = re.compile(r"/Users/[A-Za-z0-9._-]+")


def load_literals() -> list[str]:
    """Environment-specific literals from the local file and the environment variable."""
    lines: list[str] = []
    if LOCAL_FILE.is_file():
        lines += LOCAL_FILE.read_text(encoding="utf-8").splitlines()
    lines += os.environ.get("SENSITIVE_PATTERNS", "").splitlines()
    return [s.strip() for s in lines if s.strip() and not s.strip().startswith("#")]


def is_public_ip(text: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError:
        return False  # 999.1.1.1 or a version string, not an address
    doc = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    if any(ip in ipaddress.IPv4Network(n) for n in doc):
        return False
    return ip.is_global


def scan_text(text: str, literals: list[str]) -> list[tuple[int, str]]:
    """Return (line number, category) for every finding. Values are never echoed."""
    findings: list[tuple[int, str]] = []
    for no, line in enumerate(text.splitlines(), 1):
        if any(m.group() not in ALLOWED_ACCOUNT_IDS for m in ACCOUNT_ID.finditer(line)):
            findings.append((no, "12-digit number (possible AWS account ID)"))
        if any(is_public_ip(m.group()) for m in IPV4.finditer(line)):
            findings.append((no, "public IPv4 address"))
        for m in EMAIL.finditer(line):
            local, _, domain = m.group().partition("@")
            if not (ALLOWED_EMAIL_DOMAINS.search(domain) or ALLOWED_EMAIL_LOCAL.match(local)):
                findings.append((no, "email address"))
                break
        if HOME_PATH.search(line):
            findings.append((no, "absolute home-directory path"))
        if any(s in line for s in literals):
            findings.append((no, "value listed in the local sensitive-pattern list"))
    return findings


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"], capture_output=True, check=True)
    return [p for p in out.stdout.decode().split("\0") if p]


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    paths = tracked_files() if argv == ["--tracked"] else argv
    literals = load_literals()
    failed = False
    for rel in paths:
        if rel in EXCLUDED:
            continue
        path = REPO / rel if not os.path.isabs(rel) else Path(rel)
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue  # binary; images are checked by eye, not by this script
        for no, category in scan_text(data.decode("utf-8", errors="replace"), literals):
            print(f"{rel}:{no}: {category}")
            failed = True
    if failed:
        print("Sensitive data detected. Replace with a placeholder (123456789012, 203.0.113.x, example.com).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

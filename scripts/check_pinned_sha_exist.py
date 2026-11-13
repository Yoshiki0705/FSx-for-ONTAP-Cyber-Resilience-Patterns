#!/usr/bin/env python3
"""Ask GitHub whether the commit SHAs that workflows pin actually exist.

The offline ``pinning`` gate checks that a ``uses:`` ref is a 40-hex SHA. A well-formed SHA
that does not exist (a typo, a force-pushed-away commit) passes that gate and fails at run
time. This script asks GitHub, so it needs the network and a token and is NOT part of
``make test``; run ``make check-pinned-sha-exist``.

Exit codes: 0 every SHA resolved, 1 a SHA does not exist, 2 the check could not run
(no token, rate limit, server error, network error, unreadable file). When a missing SHA
and a failed lookup occur together the exit code is 2 (the highest, as in
``check_supply_chain.py``) and the missing SHAs are still printed.

Limit: GitHub resolves a commit of a fork in the same repository network through the parent
repository's commits endpoint, so a 200 means "reachable under this repository name", not
"on a branch of this repository".

Token: ``GITHUB_TOKEN`` or ``GH_TOKEN`` from the environment. It is sent only in the
Authorization header and never printed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NamedTuple

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from supply_chain_checks import pinning  # noqa: E402

_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
API = "https://api.github.com"

EXISTS = "exists"
MISSING = "missing"
ERROR = "error"


class Ref(NamedTuple):
    """One SHA-pinned ``uses:`` reference."""

    path: str
    line: int
    repo: str  # "owner/name", lower-cased
    sha: str  # lower-cased


class Lookup(NamedTuple):
    """Answer of one query: ``status`` is EXISTS, MISSING or ERROR."""

    status: str
    detail: str = ""


Query = Callable[[str, str], Lookup]


def collect_refs(path: str, text: str) -> list[Ref]:
    """Collect the SHA-pinned remote ``uses:`` references of one workflow file.

    Args:
        path: Path shown in findings.
        text: File contents.

    Returns:
        References whose version is a 40-hex SHA. Local (``./``) and ``docker://`` refs and
        refs pinned to a tag or branch are not included.
    """
    refs: list[Ref] = []
    for line, value in pinning.uses_references(text):
        if value.startswith(("./", "docker://")):
            continue
        target, _, version = value.partition("@")
        parts = target.split("/")
        if len(parts) < 2 or not _SHA40.match(version):
            continue
        refs.append(Ref(path, line, "/".join(parts[:2]).lower(), version.lower()))
    return refs


def decide(refs: Sequence[Ref], query: Query) -> tuple[list[str], list[str]]:
    """Split the lookups into missing SHAs and lookups that failed.

    Args:
        refs: References to check. Each distinct (repo, sha) is asked once.
        query: ``query(repo, sha)`` returning a ``Lookup``.

    Returns:
        ``(missing, errors)``: lines ``path:line: kind: detail``.
    """
    answers: dict[tuple[str, str], Lookup] = {}
    missing: list[str] = []
    errors: list[str] = []
    for ref in refs:
        key = (ref.repo, ref.sha)
        if key not in answers:
            answers[key] = query(ref.repo, ref.sha)
        answer = answers[key]
        where = f"{ref.path}:{ref.line}"
        if answer.status == MISSING:
            missing.append(f"{where}: missing-sha: {ref.sha} is not a commit of {ref.repo}")
        elif answer.status != EXISTS:
            errors.append(f"{where}: lookup-failed: {ref.repo}@{ref.sha}: {answer.detail}")
    return missing, errors


def github_query(token: str, opener: Callable[..., object] = urllib.request.urlopen) -> Query:
    """Build the query function that asks the GitHub REST API.

    404 and 422 mean the commit is unknown; 403 and 429 mean a rate limit or a refused token;
    5xx and network failures are errors. The token never appears in a ``detail``.

    Args:
        token: GitHub token.
        opener: ``urlopen`` replacement for tests.

    Returns:
        A ``Query``.
    """

    def query(repo: str, sha: str) -> Lookup:
        request = urllib.request.Request(  # noqa: S310 - fixed https API host
            f"{API}/repos/{repo}/commits/{sha}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with opener(request, timeout=20):  # type: ignore[operator]
                return Lookup(EXISTS)
        except urllib.error.HTTPError as err:
            if err.code in (404, 422):
                return Lookup(MISSING)
            if err.code in (403, 429):
                return Lookup(ERROR, f"HTTP {err.code} (rate limit or token refused)")
            return Lookup(ERROR, f"HTTP {err.code}")
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            return Lookup(ERROR, f"network error: {type(err).__name__}")

    return query


def run(root: Path, query: Query, out: Callable[[str], None]) -> int:
    """Check every workflow under ``root`` and return the exit code.

    Args:
        root: Repository root.
        query: Lookup function.
        out: Line printer.

    Returns:
        0, 1 or 2 as in the module docstring.
    """
    files = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    refs: list[Ref] = []
    for file in files:
        try:
            text = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as err:
            out(f"{file.name}:1: unreadable: {type(err).__name__}")
            return 2
        refs.extend(collect_refs(file.relative_to(root).as_posix(), text))
    missing, errors = decide(refs, query)
    for line in (*missing, *errors):
        out(line)
    distinct = len({(r.repo, r.sha) for r in refs})
    out(
        f"check-pinned-sha-exist: {len(files)} file(s), {len(refs)} pinned ref(s), {distinct} distinct SHA(s), "
        f"{len(missing)} missing, {len(errors)} lookup failure(s)"
    )
    if errors:
        return 2
    return 1 if missing else 0


def main(argv: Sequence[str] | None = None, env: dict[str, str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=_SCRIPTS_DIR.parent)
    args = parser.parse_args(argv)
    environ = os.environ if env is None else env
    token = environ.get("GITHUB_TOKEN") or environ.get("GH_TOKEN")
    if not token:
        sys.stderr.write("check-pinned-sha-exist: set GITHUB_TOKEN or GH_TOKEN (read-only is enough); not run\n")
        return 2
    return run(args.root, github_query(token), lambda line: sys.stdout.write(line + "\n"))


if __name__ == "__main__":
    sys.exit(main())

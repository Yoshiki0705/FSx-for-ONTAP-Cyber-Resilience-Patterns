#!/usr/bin/env python3
"""Ask GitHub whether the commit SHAs that workflows pin belong to the action's own repository.

The offline ``pinning`` gate checks that a ``uses:`` ref is a 40-hex SHA. A well-formed SHA
that does not exist (a typo, a force-pushed-away commit) passes that gate and fails at run
time, and so does an impostor commit: GitHub shares git objects across a fork network, so
``GET /repos/{repo}/commits/{sha}`` answers 200 for a commit that exists only in a fork (an
unmerged pull request, a fork the attacker controls). This script therefore asks for
reachability, not existence. It needs the network and a token and is NOT part of
``make test``; run ``make check-pinned-sha-exist``.

For each pinned SHA, per distinct (repository, SHA, version comment):

1. A version comment such as ``# v4.2.2`` is resolved with ``git/ref/tags/<tag>`` (an
   annotated tag is peeled). An exact-version comment (``x.y.z``) must point at the SHA
   itself, otherwise ``tag-sha-mismatch``. A floating tag (``v4``) may have moved on, so the
   SHA only has to be an ancestor of what the tag points at. A tag that points at the SHA
   proves the commit belongs to the action's repository, and ends the check.
2. Without such a comment the SHA must be an ancestor of the default branch:
   ``compare/{sha}...{default_branch}`` answers ``identical`` or ``ahead``. ``behind`` or
   ``diverged`` is ``impostor-or-orphan``. (Measured on 2026-11-14 against an unmerged
   pull-request head: ``commits/{sha}`` answered 200 and ``compare`` answered ``behind``.)

Exit codes: 0 every SHA is reachable, 1 a SHA is missing, an impostor or orphan, or
disagrees with its tag comment, 2 the check could not run (no token, rate limit, server
error, network error, unreadable file). When a finding and a failed lookup occur together
the exit code is 2 (the highest, as in ``check_supply_chain.py``) and the findings are
still printed.

Limits: a commit that sits only on a non-default release branch and has no version comment
is reported as ``impostor-or-orphan``; add the version comment (Renovate does) so the tag
decides. Whether GitHub's own lockfile (``actions.lock``) supersedes this check is not
decided here.

Hub preset tag (Requirement 15.2 / T1-06): when the Policy_File carries an optional
``renovate_preset`` object ``{"tag": ..., "commit": ...}``, the tag is resolved in the Hub
repository and compared with the recorded 40-hex commit (``tag-moved``).

Token: ``GITHUB_TOKEN`` or ``GH_TOKEN`` from the environment. It is sent only in the
Authorization header and never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, NamedTuple

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from supply_chain_checks import pinning  # noqa: E402

_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
_TAG_COMMENT = re.compile(r"^v?\d+(?:\.\d+)*[A-Za-z0-9._+-]*$")
_EXACT_VERSION = re.compile(r"^v?\d+\.\d+\.\d+[A-Za-z0-9._+-]*$")
API = "https://api.github.com"
POLICY_PATH = "docs/agent/supply-chain-policy.json"
HUB_REPOSITORY = "Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook"

EXISTS = "exists"  # reachable from the action's own repository
MISSING = "missing"
IMPOSTOR = "impostor-or-orphan"
TAG_MISMATCH = "tag-sha-mismatch"
ERROR = "error"
_FINDING = {MISSING: "missing-sha", IMPOSTOR: "impostor-or-orphan", TAG_MISMATCH: "tag-sha-mismatch"}


class Ref(NamedTuple):
    """One SHA-pinned ``uses:`` reference."""

    path: str
    line: int
    repo: str  # "owner/name", lower-cased
    sha: str  # lower-cased
    tag: str | None = None  # version comment, e.g. "v4.2.2"; None when absent or not a version


class Lookup(NamedTuple):
    """Answer of one query: ``status`` is EXISTS, MISSING, IMPOSTOR, TAG_MISMATCH or ERROR."""

    status: str
    detail: str = ""


Query = Callable[[str, str, "str | None"], Lookup]
TagResolver = Callable[[str, str], Lookup]


def collect_refs(path: str, text: str) -> list[Ref]:
    """Collect the SHA-pinned remote ``uses:`` references of one workflow file.

    Args:
        path: Path shown in findings.
        text: File contents.

    Returns:
        References whose version is a 40-hex SHA, with the version comment when it looks
        like a version. Local (``./``) and ``docker://`` refs and refs pinned to a tag or
        branch are not included.
    """
    refs: list[Ref] = []
    for line, value, comment in pinning.uses_references_with_comment(text):
        if value.startswith(("./", "docker://")):
            continue
        target, _, version = value.partition("@")
        parts = target.split("/")
        if len(parts) < 2 or not _SHA40.match(version):
            continue
        tag = comment if comment and _TAG_COMMENT.match(comment) else None
        refs.append(Ref(path, line, "/".join(parts[:2]).lower(), version.lower(), tag))
    return refs


def decide(refs: Sequence[Ref], query: Query) -> tuple[list[str], list[str]]:
    """Split the lookups into findings and lookups that failed.

    Args:
        refs: References to check. Each distinct (repo, sha, tag) is asked once.
        query: ``query(repo, sha, tag)`` returning a ``Lookup``.

    Returns:
        ``(findings, errors)``: lines ``path:line: kind: detail``.
    """
    answers: dict[tuple[str, str, str | None], Lookup] = {}
    findings: list[str] = []
    errors: list[str] = []
    for ref in refs:
        key = (ref.repo, ref.sha, ref.tag)
        if key not in answers:
            answers[key] = query(*key)
        answer = answers[key]
        where = f"{ref.path}:{ref.line}"
        if answer.status in _FINDING:
            detail = answer.detail or f"{ref.sha} is not a commit of {ref.repo}"
            findings.append(f"{where}: {_FINDING[answer.status]}: {detail}")
        elif answer.status != EXISTS:
            errors.append(f"{where}: lookup-failed: {ref.repo}@{ref.sha}: {answer.detail}")
    return findings, errors


class _Api:
    """Minimal GitHub REST client: JSON in, ``(status, body)`` out; never prints the token."""

    def __init__(self, token: str, opener: Callable[..., object]) -> None:
        self._token = token
        self._opener = opener

    def get(self, path: str) -> tuple[int, Any, str]:
        """GET ``path``; return ``(http status, parsed JSON or None, error detail)``."""
        request = urllib.request.Request(  # noqa: S310 - fixed https API host
            f"{API}{path}",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self._opener(request, timeout=20) as response:  # type: ignore[attr-defined]
                raw = response.read()
                return 200, json.loads(raw) if raw else None, ""
        except urllib.error.HTTPError as err:
            if err.code in (404, 422):
                return err.code, None, ""
            if err.code in (403, 429):
                return err.code, None, f"HTTP {err.code} (rate limit or token refused)"
            return err.code, None, f"HTTP {err.code}"
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as err:
            return 0, None, f"network error: {type(err).__name__}"


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _tag_commit(api: _Api, repo: str, tag: str) -> tuple[str | None, Lookup | None]:
    """Resolve a tag to a commit SHA, peeling annotated tags. ``(sha, None)`` or ``(None, answer)``."""
    status, body, detail = api.get(f"/repos/{repo}/git/ref/tags/{_quote(tag)}")
    if status in (404, 422):
        return None, Lookup(MISSING)
    if status != 200 or not isinstance(body, dict):
        return None, Lookup(ERROR, detail or f"HTTP {status}")
    obj = body.get("object") or {}
    for _ in range(4):  # a tag of a tag is legal; four levels is far beyond real use
        sha, kind = obj.get("sha"), obj.get("type")
        if kind == "commit" and isinstance(sha, str):
            return sha.lower(), None
        if kind != "tag" or not isinstance(sha, str):
            break
        status, body, detail = api.get(f"/repos/{repo}/git/tags/{sha}")
        if status != 200 or not isinstance(body, dict):
            return None, Lookup(ERROR, detail or f"HTTP {status}")
        obj = body.get("object") or {}
    return None, Lookup(ERROR, "tag does not resolve to a commit")


def _is_ancestor(api: _Api, repo: str, sha: str, head: str) -> Lookup:
    """Is ``sha`` an ancestor of ``head``? EXISTS when yes, IMPOSTOR when no."""
    status, body, detail = api.get(f"/repos/{repo}/compare/{sha}...{_quote(head)}")
    if status in (404, 422):
        return Lookup(MISSING)
    if status != 200 or not isinstance(body, dict):
        return Lookup(ERROR, detail or f"HTTP {status}")
    state = body.get("status")
    if state in ("identical", "ahead"):
        return Lookup(EXISTS)
    return Lookup(
        IMPOSTOR, f"{sha} is {state} relative to {head} of {repo}: not an ancestor, so it may exist only in a fork"
    )


def github_query(token: str, opener: Callable[..., object] = urllib.request.urlopen) -> Query:
    """Build the query function that asks the GitHub REST API for reachability.

    404 and 422 mean the object is unknown; 403 and 429 mean a rate limit or a refused token;
    5xx and network failures are errors. The token never appears in a ``detail``.

    Args:
        token: GitHub token.
        opener: ``urlopen`` replacement for tests.

    Returns:
        A ``Query`` taking ``(repo, sha, tag or None)``.
    """
    api = _Api(token, opener)
    default_branch: dict[str, str] = {}

    def query(repo: str, sha: str, tag: str | None) -> Lookup:
        if tag is not None:
            tagged, failed = _tag_commit(api, repo, tag)
            if failed is not None and failed.status == ERROR:
                return failed
            if tagged is None:
                return Lookup(TAG_MISMATCH, f"comment says {tag} but {repo} has no such tag (pinned {sha})")
            if tagged == sha:
                return Lookup(EXISTS)
            if _EXACT_VERSION.match(tag):
                return Lookup(TAG_MISMATCH, f"comment says {tag} but that tag points at {tagged}, not {sha}")
            floating = _is_ancestor(api, repo, sha, tagged)
            if floating.status == EXISTS:
                return floating
            if floating.status == ERROR:
                return floating
            return Lookup(TAG_MISMATCH, f"{sha} is not an ancestor of {tag} ({tagged}) in {repo}")
        if repo not in default_branch:
            status, body, detail = api.get(f"/repos/{repo}")
            if status in (404, 422):
                return Lookup(MISSING, f"repository {repo} not found")
            if status != 200 or not isinstance(body, dict) or not body.get("default_branch"):
                return Lookup(ERROR, detail or f"HTTP {status}")
            default_branch[repo] = str(body["default_branch"])
        return _is_ancestor(api, repo, sha, default_branch[repo])

    return query


def github_tag_resolver(token: str, opener: Callable[..., object] = urllib.request.urlopen) -> TagResolver:
    """Build a resolver ``(repo, tag) -> Lookup`` whose ``detail`` is the commit SHA on EXISTS.

    Args:
        token: GitHub token.
        opener: ``urlopen`` replacement for tests.

    Returns:
        The resolver.
    """
    api = _Api(token, opener)

    def resolve(repo: str, tag: str) -> Lookup:
        sha, failed = _tag_commit(api, repo, tag)
        if sha is not None:
            return Lookup(EXISTS, sha)
        return failed or Lookup(ERROR, "unresolved")

    return resolve


def check_preset_tag(root: Path, resolve: TagResolver) -> tuple[list[str], list[str]]:
    """Compare the recorded Hub preset tag with what GitHub says it points at.

    Reads the optional ``renovate_preset`` object (``tag``, ``commit``) of the Policy_File
    as raw JSON. Absent or malformed means nothing is recorded and nothing is checked.

    Args:
        root: Repository root.
        resolve: Tag resolver.

    Returns:
        ``(findings, errors)`` as in :func:`decide`.
    """
    try:
        data = json.loads((root / POLICY_PATH).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return [], []
    recorded = data.get("renovate_preset") if isinstance(data, dict) else None
    if not isinstance(recorded, dict):
        return [], []
    tag, commit = recorded.get("tag"), recorded.get("commit")
    where = f"{POLICY_PATH}:1"
    if not isinstance(tag, str) or not isinstance(commit, str) or not _SHA40.match(commit):
        return [f"{where}: tag-moved: renovate_preset needs a tag and a 40-hex commit"], []
    answer = resolve(HUB_REPOSITORY, tag)
    if answer.status == ERROR:
        return [], [f"{where}: lookup-failed: {HUB_REPOSITORY}@{tag}: {answer.detail}"]
    if answer.status != EXISTS:
        return [f"{where}: tag-moved: tag {tag} does not exist in {HUB_REPOSITORY}"], []
    if answer.detail != commit.lower():
        return [
            f"{where}: tag-moved: {tag} now points at {answer.detail}, the Policy_File recorded {commit.lower()}"
        ], []
    return [], []


def run(root: Path, query: Query, out: Callable[[str], None], resolve: TagResolver | None = None) -> int:
    """Check every workflow under ``root`` and return the exit code.

    Args:
        root: Repository root.
        query: Lookup function.
        out: Line printer.
        resolve: Tag resolver for the Hub preset tag; ``None`` skips that check.

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
    findings, errors = decide(refs, query)
    if resolve is not None:
        more_findings, more_errors = check_preset_tag(root, resolve)
        findings += more_findings
        errors += more_errors
    for line in (*findings, *errors):
        out(line)
    distinct = len({(r.repo, r.sha, r.tag) for r in refs})
    out(
        f"check-pinned-sha-exist: {len(files)} file(s), {len(refs)} pinned ref(s), {distinct} distinct SHA(s), "
        f"{len(findings)} finding(s), {len(errors)} lookup failure(s)"
    )
    if errors:
        return 2
    return 1 if findings else 0


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
    return run(args.root, github_query(token), lambda line: sys.stdout.write(line + "\n"), github_tag_resolver(token))


if __name__ == "__main__":
    sys.exit(main())

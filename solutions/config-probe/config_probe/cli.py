"""Command line: ``python -m config_probe`` or ``solutions/config-probe/probe.py``.

Exit codes:

* 0  no ``finding`` at or above ``--fail-on``
* 2  at least one ``finding`` at or above ``--fail-on``
* 3  the run could not assess: authentication failure, certificate mismatch, refused secret,
     deadline, or a failed control read (every check ``inconclusive``)
* 64 usage error
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Callable

from . import SCHEMA
from .aws_side import collect_aws, ontap_residency
from .checks import exceeds, mask_fs_id, mask_tree, run_checks, summarize
from .collect import collect
from .transport import OntapTransport, ProbeError, Transport

logger = logging.getLogger("config_probe")

EXIT_OK, EXIT_FINDINGS, EXIT_STOPPED, EXIT_USAGE = 0, 2, 3, 64


class SecretRefused(ProbeError):
    """The secret is not tagged for this file system, or has the wrong shape. Nothing was sent."""


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the command line."""
    p = argparse.ArgumentParser(prog="config_probe", description="Read-only adversarial configuration probe")
    p.add_argument(
        "--base-url", help="https://host[:port] of the ONTAP management endpoint, e.g. https://localhost:18443"
    )
    p.add_argument("--fingerprint", help="SHA-256 fingerprint of the management certificate")
    p.add_argument("--file-system-id", help="fs-... of the file system")
    p.add_argument("--region", help="AWS Region (default: the SDK's)")
    p.add_argument("--secret-id", help="Secrets Manager secret with JSON username/password, tagged FileSystemId")
    p.add_argument("--out", help="write the JSON here instead of stdout")
    p.add_argument("--fail-on", choices=("high", "medium", "none"), default="none")
    p.add_argument("--show-names", action="store_true", help="show file system ID and remote names unmasked")
    p.add_argument("--max-volumes", type=int, default=50)
    p.add_argument("--deadline-seconds", type=float, default=300.0)
    p.add_argument("--read-timeout", type=float, default=90.0, help="seconds to wait for each ONTAP answer")
    p.add_argument("--skip-aws", action="store_true")
    p.add_argument("--skip-ontap", action="store_true")
    args = p.parse_args(argv)
    if not args.skip_ontap and not (args.base_url and args.fingerprint and args.secret_id and args.file_system_id):
        p.error("--base-url, --fingerprint, --secret-id and --file-system-id are required unless --skip-ontap")
    if not args.skip_aws and not args.file_system_id:
        p.error("--file-system-id is required unless --skip-aws")
    if args.max_volumes < 0:
        p.error("--max-volumes must be 0 or more")
    return args


def load_credentials(secrets: Any, secret_id: str, file_system_id: str) -> tuple[str, str]:
    """Read the secret, refusing one that is not tagged ``FileSystemId=<file_system_id>``.

    Two file systems share the user name ``fsxadmin``, so a secret picked by name can hold the
    other file system's password, and each failed login counts towards locking the account.
    """
    desc = secrets.describe_secret(SecretId=secret_id)
    tags = {t.get("Key"): t.get("Value") for t in desc.get("Tags", [])}
    if tags.get("FileSystemId") != file_system_id:
        raise SecretRefused("the secret is not tagged FileSystemId=<this file system>; nothing was sent to ONTAP")
    data = json.loads(secrets.get_secret_value(SecretId=secret_id)["SecretString"])
    username = data.get("username") or data.get("Username")
    password = data.get("password") or data.get("Password")
    if not username or not password:
        raise SecretRefused("the secret must be JSON with 'username' and 'password'")
    return str(username), str(password)


ClientFactory = Callable[[str], Any]
TransportFactory = Callable[[argparse.Namespace, str, str], Transport]


def _boto_factory(region: str | None) -> ClientFactory:
    import boto3  # imported here so the checks can be used without the SDK

    session = boto3.session.Session(region_name=region)
    return lambda service: session.client(service)


def _ontap_transport(args: argparse.Namespace, username: str, password: str) -> Transport:
    return OntapTransport(
        args.base_url,
        username,
        password,
        args.fingerprint,
        read_timeout=args.read_timeout,
        deadline_seconds=args.deadline_seconds,
    )


def run(
    args: argparse.Namespace,
    *,
    clients: ClientFactory | None = None,
    transport_factory: TransportFactory = _ontap_transport,
    now: datetime | None = None,
) -> tuple[dict[str, Any], int]:
    """Run the probe and return the (masked) output document and the exit code."""
    now = now or datetime.now(timezone.utc)
    if clients is None and not (args.skip_aws and args.skip_ontap):
        clients = _boto_factory(args.region)
    findings: list[dict[str, Any]] = []
    residency: dict[str, Any] = {"region": args.region}
    doc: dict[str, Any] = {
        "schema": SCHEMA,
        "ontap_version": None,
        "file_system_id": mask_fs_id(args.file_system_id or "", args.show_names),
        "read_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "get_only": True,
        "bodies_stored": False,
        "stopped": "",
    }
    code = EXIT_OK

    if not args.skip_ontap:
        assert clients is not None
        try:
            username, password = load_credentials(clients("secretsmanager"), args.secret_id, args.file_system_id)
            transport = transport_factory(args, username, password)
            del password
            col = collect(transport, max_volumes=args.max_volumes)
            close = getattr(transport, "close", None)
            if callable(close):
                close()
        except ProbeError as exc:
            logger.error("STOPPED: %s", exc.reason)
            doc["stopped"] = exc.reason
            code = EXIT_STOPPED
        else:
            doc["ontap_version"] = col.ontap_version
            findings.extend(run_checks(col, now=now, show_names=args.show_names))
            residency.update(
                ontap_residency(col.get("snapmirror_destinations"), col.get("cluster_peers"), args.show_names)
            )
            if col.stopped or not col.control_ok:
                doc["stopped"] = col.stopped or "control read failed"
                logger.error("STOPPED: %s", doc["stopped"])
                code = EXIT_STOPPED

    if not args.skip_aws:
        assert clients is not None
        aws_findings, aws_res = collect_aws(
            clients("fsx"), clients("kms"), clients("s3control"), args.file_system_id, show_names=args.show_names
        )
        findings.extend(aws_findings)
        residency.update({k: v for k, v in aws_res.items() if v or k not in residency})

    doc["residency"] = residency
    doc["findings"] = findings
    doc["summary"] = summarize(findings)
    if code == EXIT_OK and exceeds(findings, args.fail_on):
        code = EXIT_FINDINGS
    return mask_tree(doc, args.show_names), code


def main(
    argv: list[str] | None = None,
    *,
    clients: ClientFactory | None = None,
    transport_factory: TransportFactory = _ontap_transport,
) -> int:
    """Entry point. Writes the JSON document to ``--out`` or stdout and returns the exit code."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    for name in ("boto3", "botocore", "urllib3", "s3transfer"):
        logging.getLogger(name).setLevel(logging.WARNING)
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_OK
    doc, code = run(args, clients=clients, transport_factory=transport_factory)
    text = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        logger.info("wrote %s (%d findings, exit %d)", args.out, len(doc["findings"]), code)
    else:
        sys.stdout.write(text)
    return code

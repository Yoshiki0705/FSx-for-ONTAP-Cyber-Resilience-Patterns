"""The ONTAP endpoints the probe reads, and the collection run.

Every path here is a GET endpoint of ONTAP 9.18.1P6 on FSx for ONTAP, as listed in
``docs/ontap-native/data/fsx-ontap-9.18.1P6-rest-endpoints.tsv``; a test checks that. Where the
field names of a collection were not confirmed, the query asks for ``fields=*`` (accepted by the
public REST API, unlike the CLI pass-through).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .transport import ProbeError, Reply, Transport, TransportFailure, classify_reply, get_collection

logger = logging.getLogger(__name__)

VERSION_RE = re.compile(r"NetApp Release (\d+\.\d+(?:\.\d+)?(?:[A-Z]\d+[A-Z]?\d*)*)")


@dataclass(frozen=True)
class Endpoint:
    """One read.

    Attributes:
        name: Key in the collection.
        path: REST path starting with ``/api/``; ``{uuid}`` is filled per volume.
        query: Query string sent first.
        fallback_query: Query sent once more when the first answer is HTTP 400 (an unknown field
            in this ONTAP version); empty for none.
    """

    name: str
    path: str
    query: str = ""
    fallback_query: str = ""


VOLUME_FIELDS = (
    "name,uuid,svm.name,type,style,anti_ransomware.state,snapshot_policy.name,snapshot_locking_enabled,"
    "snaplock.type,nas.export_policy.name,nas.security_style,encryption.enabled,encryption.type,"
    "encryption.state,space.snapshot.autodelete_enabled,flexcache_endpoint_type"
)

CONTROL = Endpoint("cluster", "/api/cluster", "fields=name,version")
ENDPOINTS: tuple[Endpoint, ...] = (
    Endpoint(
        "volumes",
        "/api/storage/volumes",
        f"fields={VOLUME_FIELDS}&max_records=1000",
        "fields=name,uuid,svm.name,type,anti_ransomware.state,snapshot_policy.name&max_records=1000",
    ),
    Endpoint("arp_auto_enable", "/api/security/anti-ransomware/auto-enable"),
    Endpoint("arp_suspects", "/api/security/anti-ransomware/suspects", "fields=*"),
    Endpoint("snapshot_policies", "/api/storage/snapshot-policies", "fields=name,enabled,copies,svm.name"),
    Endpoint("compliance_clocks", "/api/storage/snaplock/compliance-clocks", "fields=*"),
    Endpoint("export_policies", "/api/protocols/nfs/export-policies", "fields=name,svm.name,rules"),
    Endpoint("cifs_shares", "/api/protocols/cifs/shares", "fields=name,svm.name,path,acls"),
    Endpoint("fpolicy", "/api/protocols/fpolicy", "fields=svm.name,policies,engines"),
    Endpoint("vscan", "/api/protocols/vscan", "fields=svm.name,enabled,scanner_pools,on_access_policies"),
    Endpoint("audit", "/api/protocols/audit", "fields=svm.name,enabled,events,log_path"),
    Endpoint("audit_destinations", "/api/security/audit/destinations", "fields=*"),
    Endpoint("accounts", "/api/security/accounts", "fields=name,owner.name,role.name,applications,locked"),
    Endpoint("totps", "/api/security/login/totps", "fields=*"),
    Endpoint("mav", "/api/security/multi-admin-verify"),
    Endpoint("key_managers", "/api/security/key-managers", "fields=*"),
    Endpoint("cluster_peers", "/api/cluster/peers", "fields=name,remote,status"),
    Endpoint("snapmirror", "/api/snapmirror/relationships", "fields=source,destination,policy,state"),
    # The same path, asked from the source side: relationships whose destination is elsewhere.
    Endpoint(
        "snapmirror_destinations",
        "/api/snapmirror/relationships",
        "fields=source,destination,policy,state&list_destinations_only=true",
    ),
)
SNAPSHOTS = Endpoint(
    "snapshots", "/api/storage/volumes/{uuid}/snapshots", "fields=name,create_time,snaplock_expiry_time"
)
_UUID_RE = re.compile(r"[0-9a-fA-F-]{36}")


@dataclass
class Fetch:
    """What one endpoint answered.

    Attributes:
        path: Path without query.
        http: HTTP status; 0 when no answer was received.
        ontap_code: ONTAP error code of an error answer.
        outcome: ``ok``, ``role_refused``, ``role_answer``, ``absent``, ``error`` or ``not_read``.
        records: Records read (empty unless ``outcome`` is ``ok``).
        note: Short reason for ``error`` / ``not_read``; never a response body.
    """

    path: str
    http: int = 0
    ontap_code: str = ""
    outcome: str = "not_read"
    records: list[dict[str, Any]] = field(default_factory=list)
    note: str = ""

    def source(self) -> dict[str, Any]:
        """The ``source`` object of a finding."""
        return {"path": self.path, "http": self.http, "ontap_code": self.ontap_code}


@dataclass
class Collection:
    """Everything read from ONTAP in one run."""

    control_ok: bool = False
    ontap_version: str = "unknown"
    cluster_name: str = ""
    fetches: dict[str, Fetch] = field(default_factory=dict)
    snapshots: dict[str, Fetch] = field(default_factory=dict)
    volumes_not_read: list[str] = field(default_factory=list)
    stopped: str = ""

    def get(self, name: str) -> Fetch:
        """The fetch for ``name``, or a ``not_read`` placeholder."""
        return self.fetches.get(name) or Fetch(path=name, note="not read")


def parse_version(version_full: str) -> str:
    """Take ``9.18.1P6`` from ``NetApp Release 9.18.1P6: ...``."""
    m = VERSION_RE.search(version_full or "")
    return m.group(1) if m else "unknown"


def _fetch(transport: Transport, ep: Endpoint, path: str | None = None) -> Fetch:
    path = path or ep.path
    try:
        reply, records = get_collection(transport, path, ep.query)
        if reply.status == 400 and ep.fallback_query:
            logger.info("HTTP 400 on %s; retrying once with the smaller field list", ep.path)
            reply, records = get_collection(transport, path, ep.fallback_query)
    except TransportFailure as exc:
        return Fetch(path=ep.path, outcome="error", note=exc.reason)
    return _to_fetch(ep.path, reply, records)


def _to_fetch(path: str, reply: Reply, records: list[dict[str, Any]]) -> Fetch:
    outcome = classify_reply(reply)
    return Fetch(
        path=path,
        http=reply.status,
        ontap_code=reply.error_code,
        outcome=outcome,
        records=records if outcome == "ok" else [],
        note="" if outcome == "ok" else f"HTTP {reply.status}",
    )


def collect(transport: Transport, *, max_volumes: int = 50) -> Collection:
    """Read every endpoint. Stops, keeping what was read, when the transport aborts.

    Args:
        transport: A GET-only transport.
        max_volumes: Upper bound on the volumes whose snapshots are read.

    Returns:
        The collection. ``control_ok`` is False when ``/api/cluster`` did not answer 200; then
        nothing else is read.
    """
    out = Collection()
    try:
        control = _fetch(transport, CONTROL)
        out.fetches[CONTROL.name] = control
        if control.outcome != "ok" or not control.records:
            out.stopped = f"control read failed ({control.note or 'no record'})"
            return out
        body = control.records[0]
        out.control_ok = True
        out.cluster_name = str(body.get("name", ""))
        out.ontap_version = parse_version(str((body.get("version") or {}).get("full", "")))

        for ep in ENDPOINTS:
            out.fetches[ep.name] = _fetch(transport, ep)

        volumes = [
            v
            for v in out.get("volumes").records
            if isinstance(v.get("uuid"), str)
            and _UUID_RE.fullmatch(v["uuid"])
            and v.get("type", "rw") == "rw"
            # A FlexCache volume refused the Snapshot list (HTTP 400, ONTAP code 9437613, 9.19.1P4);
            # its recovery points are those of the origin volume.
            and v.get("flexcache_endpoint_type") != "cache"
        ]
        for i, vol in enumerate(volumes):
            if i >= max_volumes:
                out.volumes_not_read.append(vol["uuid"])
                continue
            out.snapshots[vol["uuid"]] = _fetch(transport, SNAPSHOTS, SNAPSHOTS.path.replace("{uuid}", vol["uuid"]))
    except ProbeError as exc:
        out.stopped = exc.reason
        logger.error("ONTAP reads stopped: %s", exc.reason)
    return out


def collection_paths() -> list[str]:
    """Every path the collector can request, without query (for the catalog test)."""
    return [CONTROL.path, SNAPSHOTS.path, *(ep.path for ep in ENDPOINTS)]

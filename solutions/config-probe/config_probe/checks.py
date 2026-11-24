"""Checks: pure functions from collected ONTAP records to findings, and output masking.

Each finding says what an attacker who already holds a precondition could do because of one
setting. Severity follows the precondition:

* network reach to a data interface only            -> high
* data-protocol credentials (NFS identity, SMB user) -> medium
* ONTAP administrator credentials                    -> low, raised to high when the setting lets
  that attacker destroy recovery points (snapshot deletion, autodelete)

``status`` is ``finding``, ``pass``, ``not_assessable`` (the role may not read the setting),
``unknown`` (the read failed or the field is absent) or ``inconclusive`` (the control read of
``/api/cluster`` failed, so nothing was assessed).
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from .collect import Collection, Fetch

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
STATUSES = ("finding", "pass", "not_assessable", "unknown", "inconclusive")

NET = "network reach to a data interface, no credential"
DATA = "data-protocol credentials (an NFS client identity or an SMB user)"
ADMIN = "ONTAP administrator credentials"
RECORDED = "none: ONTAP has already recorded the event"
NO_PRE = "not applicable (information)"

# ---------------------------------------------------------------------------
# ARP state classification.
# Copied from classify_arp_state in solutions/shared/ontap_client.py (same sets, same rule), not
# imported: that module also carries a REST path that is not an ONTAP endpoint [E-028].
# ---------------------------------------------------------------------------
ARP_PROTECTING = frozenset({"enabled", "dry_run"})
ARP_NOT_PROTECTING = frozenset({"disabled", "paused", "dry_run_paused", "enable_paused"})
ARP_TRANSITIONAL = frozenset({"disable_in_progress"})


def classify_arp_state(state: Any) -> str:
    """Say what an ARP state means for protection.

    Args:
        state: Value from REST or the CLI, in either spelling.

    Returns:
        ``protecting``, ``not_protecting``, ``transitional`` or ``unknown``. An unrecognised
        value is ``unknown``, never ``not_protecting``.
    """
    token = state.strip().lower().replace("-", "_") if isinstance(state, str) else ""
    if token in ARP_PROTECTING:
        return "protecting"
    if token in ARP_NOT_PROTECTING:
        return "not_protecting"
    if token in ARP_TRANSITIONAL:
        return "transitional"
    return "unknown"


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------
_CLUSTER_RE = re.compile(r"FsxId[0-9a-f]{17}(?:-0[12])?")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_ACCOUNT_RE = re.compile(r"(?<![0-9A-Za-z-])\d{12}(?![0-9A-Za-z-])")
_FS_ID_RE = re.compile(r"fs-[0-9a-f]{17}")


def mask_fs_id(fs_id: str, show_names: bool = False) -> str:
    """``fs-0123456789abcdef0`` -> ``fs-…def0`` unless ``show_names``."""
    if show_names or not fs_id:
        return fs_id
    return f"fs-…{fs_id[-4:]}"


def mask_text(text: str, show_names: bool = False) -> str:
    """Mask cluster names, IPv4 addresses and 12-digit account IDs; mask file system IDs too
    unless ``show_names``."""
    text = _CLUSTER_RE.sub("<cluster>", text)
    text = _IPV4_RE.sub("<ip>", text)
    text = _ACCOUNT_RE.sub("<account>", text)
    if not show_names:
        text = _FS_ID_RE.sub(lambda m: mask_fs_id(m.group(0)), text)
    return text


def mask_tree(value: Any, show_names: bool = False) -> Any:
    """Apply :func:`mask_text` to every string (keys included) in a JSON-like value."""
    if isinstance(value, str):
        return mask_text(value, show_names)
    if isinstance(value, dict):
        return {mask_text(str(k), show_names): mask_tree(v, show_names) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask_tree(v, show_names) for v in value]
    return value


def name_token(name: Any, show_names: bool = False) -> str:
    """A remote name as shown in the output: the name itself, or a stable short token."""
    text = str(name or "")
    if show_names or not text:
        return text or "<unnamed>"
    return f"<name:{hashlib.sha256(text.encode()).hexdigest()[:6]}>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def severity_for(precondition: str, destroys_recovery: bool = False) -> str:
    """Severity from the attacker precondition (see the module docstring)."""
    if precondition in (NET, RECORDED):
        return "high"
    if destroys_recovery:
        return "high"
    if precondition == DATA:
        return "medium"
    if precondition == ADMIN:
        return "low"
    return "info"


def _dig(record: dict[str, Any], dotted: str) -> Any:
    cur: Any = record
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _finding(
    fid: str,
    check: str,
    resource: str,
    status: str,
    precondition: str,
    capability: str,
    observed: str,
    fetch: Fetch,
    ledger: Iterable[str] = (),
    *,
    destroys_recovery: bool = False,
    severity: str | None = None,
) -> dict[str, Any]:
    return {
        "id": fid,
        "check": check,
        "resource": resource,
        "severity": severity or severity_for(precondition, destroys_recovery),
        "status": status,
        "attacker_precondition": precondition,
        "attacker_capability": capability,
        "observed": observed,
        "source": fetch.source(),
        "ledger": list(ledger),
    }


def _unreadable(
    fid: str,
    check: str,
    fetch: Fetch,
    precondition: str,
    capability: str,
    ledger: Iterable[str] = (),
    *,
    destroys_recovery: bool = False,
    resource: str = "-",
) -> dict[str, Any]:
    if fetch.outcome == "role_refused":
        status, observed = "not_assessable", "HTTP 403, ONTAP code 6: this role may not read the setting"
    elif fetch.outcome == "absent":
        status, observed = "unknown", "HTTP 404: the path is absent on this version"
    elif fetch.outcome == "role_answer":
        status, observed = (
            "unknown",
            f"HTTP 401, ONTAP code {fetch.ontap_code}: the endpoint is reserved to another role",
        )
    else:
        status, observed = "unknown", f"not read ({fetch.note or 'no answer'})"
    return _finding(
        fid,
        check,
        resource,
        status,
        precondition,
        capability,
        observed,
        fetch,
        ledger,
        destroys_recovery=destroys_recovery,
    )


def _vol_resource(vol: dict[str, Any]) -> str:
    return f"{_dig(vol, 'svm.name') or '?'}/{vol.get('name') or vol.get('uuid') or '?'}"


def _rw_volumes(volumes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Read-write volumes, without SVM root volumes (recognised by the ``_root`` name suffix)."""
    return [v for v in volumes if (v.get("type") or "rw") == "rw" and not str(v.get("name", "")).endswith("_root")]


def _svms(col: Collection) -> list[str]:
    names = {str(_dig(v, "svm.name")) for v in col.get("volumes").records if _dig(v, "svm.name")}
    for key in ("fpolicy", "vscan", "audit"):
        names.update(str(_dig(r, "svm.name")) for r in col.get(key).records if _dig(r, "svm.name"))
    return sorted(names)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

ARP_CAP = "encrypt or overwrite files on the volume with no on-box ransomware detection or automatic snapshot"


def check_arp_volumes(col: Collection) -> list[dict[str, Any]]:
    """ARP-001: each read-write volume whose ARP state does not protect it."""
    fetch = col.get("volumes")
    if fetch.outcome != "ok":
        return [_unreadable("ARP-001", "arp_volume_state", fetch, DATA, ARP_CAP)]
    out = []
    for vol in _rw_volumes(fetch.records):
        state = _dig(vol, "anti_ransomware.state")
        kind = classify_arp_state(state)
        status = {"protecting": "pass", "not_protecting": "finding", "transitional": "finding"}.get(kind, "unknown")
        observed = f"anti_ransomware.state={state!s}"
        if kind == "transitional":
            observed += " (protection is being removed)"
        out.append(_finding("ARP-001", "arp_volume_state", _vol_resource(vol), status, DATA, ARP_CAP, observed, fetch))
    return out


def check_arp_auto_enable(col: Collection) -> list[dict[str, Any]]:
    """ARP-002: ARP is not switched on automatically for new volumes."""
    fetch = col.get("arp_auto_enable")
    cap = "write to a newly created volume before anyone turns ARP on for it"
    if fetch.outcome != "ok" or not fetch.records:
        return [_unreadable("ARP-002", "arp_auto_enable", fetch, DATA, cap)]
    rec = fetch.records[0]
    value = rec.get("enabled")
    if not isinstance(value, bool):
        return [
            _finding("ARP-002", "arp_auto_enable", "cluster", "unknown", DATA, cap, "no boolean 'enabled' field", fetch)
        ]
    status = "pass" if value else "finding"
    return [_finding("ARP-002", "arp_auto_enable", "cluster", status, DATA, cap, f"enabled={value}", fetch)]


def check_arp_suspects(col: Collection) -> list[dict[str, Any]]:
    """ARP-003: ARP suspect files that nobody has cleared."""
    fetch = col.get("arp_suspects")
    cap = "an attack may be under way, or a past alert was not reviewed"
    if fetch.outcome != "ok":
        return [_unreadable("ARP-003", "arp_suspects", fetch, RECORDED, cap)]
    n = len(fetch.records)
    status = "finding" if n else "pass"
    return [_finding("ARP-003", "arp_suspects", "cluster", status, RECORDED, cap, f"{n} suspect record(s)", fetch)]


def check_snapshot_policy(col: Collection) -> list[dict[str, Any]]:
    """SNAP-001: read-write volumes with snapshot policy ``none`` or a disabled policy."""
    fetch = col.get("volumes")
    cap = "encrypt or delete files on the volume, leaving no scheduled on-box recovery point"
    if fetch.outcome != "ok":
        return [_unreadable("SNAP-001", "snapshot_policy", fetch, DATA, cap)]
    policies = col.get("snapshot_policies")
    enabled: dict[tuple[str, str], Any] = {}
    for p in policies.records:
        enabled[(str(_dig(p, "svm.name") or ""), str(p.get("name", "")))] = p.get("enabled")
    out = []
    for vol in _rw_volumes(fetch.records):
        name = _dig(vol, "snapshot_policy.name")
        svm = str(_dig(vol, "svm.name") or "")
        if not name:
            status, observed = "unknown", "snapshot_policy.name not returned"
        elif name == "none":
            status, observed = "finding", "snapshot_policy.name=none"
        else:
            state = enabled.get((svm, name), enabled.get(("", name)))
            if state is False:
                status, observed = "finding", f"policy {name} has enabled=false"
            elif state is True:
                status, observed = "pass", f"policy {name} enabled"
            else:
                status, observed = "unknown", f"policy {name}: enabled state not read"
        out.append(_finding("SNAP-001", "snapshot_policy", _vol_resource(vol), status, DATA, cap, observed, fetch))
    return out


def check_locked_snapshots(col: Collection, now: datetime) -> list[dict[str, Any]]:
    """SNAP-002: volumes that have snapshots but none locked into the future."""
    fetch = col.get("volumes")
    cap = "delete every snapshot of the volume, removing its on-box recovery points"
    if fetch.outcome != "ok":
        return [_unreadable("SNAP-002", "locked_snapshot", fetch, ADMIN, cap, destroys_recovery=True)]
    out = []
    for vol in _rw_volumes(fetch.records):
        uuid = str(vol.get("uuid", ""))
        res = _vol_resource(vol)
        snap = col.snapshots.get(uuid)
        if snap is None:
            why = "over --max-volumes" if uuid in col.volumes_not_read else "not read"
            out.append(
                _finding(
                    "SNAP-002",
                    "locked_snapshot",
                    res,
                    "unknown",
                    ADMIN,
                    cap,
                    f"snapshots {why}",
                    Fetch(path="/api/storage/volumes/{uuid}/snapshots"),
                    destroys_recovery=True,
                )
            )
            continue
        if snap.outcome != "ok":
            out.append(
                _unreadable("SNAP-002", "locked_snapshot", snap, ADMIN, cap, destroys_recovery=True, resource=res)
            )
            continue
        if not snap.records:
            continue
        locked = [s for s in snap.records if (t := _parse_time(s.get("snaplock_expiry_time"))) and t > now]
        status = "pass" if locked else "finding"
        observed = f"{len(locked)} of {len(snap.records)} snapshot(s) locked beyond the read time"
        out.append(
            _finding("SNAP-002", "locked_snapshot", res, status, ADMIN, cap, observed, snap, destroys_recovery=True)
        )
    return out


def check_autodelete(col: Collection) -> list[dict[str, Any]]:
    """SNAP-003: snapshot autodelete is on, so filling the volume removes snapshots."""
    fetch = col.get("volumes")
    cap = "write until the volume is full, which makes ONTAP delete snapshots to free space"
    if fetch.outcome != "ok":
        return [_unreadable("SNAP-003", "snapshot_autodelete", fetch, DATA, cap, destroys_recovery=True)]
    out = []
    for vol in _rw_volumes(fetch.records):
        value = _dig(vol, "space.snapshot.autodelete_enabled")
        status = {True: "finding", False: "pass"}.get(value, "unknown") if isinstance(value, bool) else "unknown"
        out.append(
            _finding(
                "SNAP-003",
                "snapshot_autodelete",
                _vol_resource(vol),
                status,
                DATA,
                cap,
                f"space.snapshot.autodelete_enabled={value}",
                fetch,
                destroys_recovery=True,
            )
        )
    return out


def check_compliance_clock(col: Collection) -> list[dict[str, Any]]:
    """SNAP-004: no initialized SnapLock compliance clock (a documented prerequisite of snapshot locking)."""
    fetch = col.get("compliance_clocks")
    cap = "snapshot locking cannot be turned on until the compliance clock is initialized"
    if fetch.outcome != "ok":
        return [_unreadable("SNAP-004", "compliance_clock", fetch, NO_PRE, cap)]
    n = len(fetch.records)
    status = "pass" if n else "finding"
    return [
        _finding(
            "SNAP-004", "compliance_clock", "cluster", status, NO_PRE, cap, f"{n} compliance clock record(s)", fetch
        )
    ]


_OPEN_MATCHES = frozenset({"0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0", "0/0"})
_WEAK_AUTH = frozenset({"any", "sys"})


def check_export_policies(col: Collection) -> list[dict[str, Any]]:
    """NFS-001: export rules open to every address with AUTH_SYS write or superuser access."""
    fetch = col.get("export_policies")
    cap = "mount from any reachable address and write, or act as root, with a client-asserted UID"
    if fetch.outcome != "ok":
        return [_unreadable("NFS-001", "export_open_world", fetch, NET, cap)]
    out = []
    for pol in fetch.records:
        res = f"{_dig(pol, 'svm.name') or '?'}/{pol.get('name', '?')}"
        hits = []
        for rule in pol.get("rules") or []:
            matches = {str(c.get("match", "")).strip() for c in rule.get("clients") or [] if isinstance(c, dict)}
            if not matches & _OPEN_MATCHES:
                continue
            rw = _WEAK_AUTH & {str(x) for x in rule.get("rw_rule") or []}
            su = _WEAK_AUTH & {str(x) for x in rule.get("superuser") or []}
            if rw or su:
                hits.append(f"rule {rule.get('index', '?')}: rw_rule={sorted(rw)} superuser={sorted(su)}")
        status = "finding" if hits else "pass"
        observed = "; ".join(hits) if hits else "no rule opens 0.0.0.0/0 with any/sys write or superuser"
        out.append(_finding("NFS-001", "export_open_world", res, status, NET, cap, observed, fetch))
    return out


def check_cifs_acls(col: Collection) -> list[dict[str, Any]]:
    """CIFS-001: share ACL entries granting Everyone full control."""
    fetch = col.get("cifs_shares")
    cap = "any domain user can change permissions and delete files at share level"
    if fetch.outcome != "ok":
        return [_unreadable("CIFS-001", "cifs_everyone_full_control", fetch, DATA, cap)]
    out = []
    for share in fetch.records:
        res = f"{_dig(share, 'svm.name') or '?'}/{share.get('name', '?')}"
        acls = share.get("acls")
        if not isinstance(acls, list):
            out.append(
                _finding(
                    "CIFS-001", "cifs_everyone_full_control", res, "unknown", DATA, cap, "acls not returned", fetch
                )
            )
            continue
        bad = [
            a
            for a in acls
            if str(a.get("user_or_group", "")).lower() == "everyone" and str(a.get("permission", "")) == "full_control"
        ]
        status = "finding" if bad else "pass"
        observed = "Everyone: full_control" if bad else "no Everyone full_control entry"
        out.append(_finding("CIFS-001", "cifs_everyone_full_control", res, status, DATA, cap, observed, fetch))
    return out


def _per_svm(
    col: Collection, key: str, fid: str, check: str, cap: str, enabled: Any, ledger: Iterable[str] = ()
) -> list[dict[str, Any]]:
    fetch = col.get(key)
    if fetch.outcome != "ok":
        return [_unreadable(fid, check, fetch, DATA, cap, ledger)]
    by_svm = {str(_dig(r, "svm.name")): r for r in fetch.records if _dig(r, "svm.name")}
    out = []
    for svm in _svms(col):
        rec = by_svm.get(svm)
        if rec is None:
            status, observed = "finding", "no configuration for this SVM"
        else:
            status, observed = enabled(rec)
        out.append(_finding(fid, check, svm, status, DATA, cap, observed, fetch, ledger))
    return out


def _fpolicy_enabled(rec: dict[str, Any]) -> tuple[str, str]:
    pols = [p for p in rec.get("policies") or [] if isinstance(p, dict)]
    if rec.get("enabled") is True or any(p.get("enabled") is True for p in pols):
        return "pass", f"{sum(1 for p in pols if p.get('enabled') is True)} enabled polic(ies)"
    return "finding", f"{len(pols)} polic(ies), none enabled"


def _flag_enabled(rec: dict[str, Any]) -> tuple[str, str]:
    value = rec.get("enabled")
    if value is True:
        return "pass", "enabled=true"
    if value is False:
        return "finding", "enabled=false"
    return "unknown", "enabled not returned"


def _audit_enabled(rec: dict[str, Any]) -> tuple[str, str]:
    status, observed = _flag_enabled(rec)
    if status == "pass" and _dig(rec, "events.file_operations") is False:
        return "finding", "enabled=true, events.file_operations=false"
    return status, observed


def check_fpolicy(col: Collection) -> list[dict[str, Any]]:
    """FPOL-001: SVMs with no enabled FPolicy policy. S3 Access Points operations are never seen by
    FPolicy, whatever this setting is [E-015]."""
    cap = "change files over NFS or SMB with no file-operation event sent to an external server"
    return _per_svm(col, "fpolicy", "FPOL-001", "fpolicy_enabled", cap, _fpolicy_enabled, ["E-015"])


def check_vscan(col: Collection) -> list[dict[str, Any]]:
    """VSCAN-001: SVMs where Vscan is off."""
    cap = "store a malicious file that others open over SMB with no on-access scan"
    return _per_svm(col, "vscan", "VSCAN-001", "vscan_enabled", cap, _flag_enabled)


def check_file_audit(col: Collection) -> list[dict[str, Any]]:
    """AUD-001: SVMs with no enabled file-access audit. For S3 Access Points operations the
    requesting principal is not recorded even when it is on [E-018]."""
    cap = "read or change files with no file-access record on the SVM"
    return _per_svm(col, "audit", "AUD-001", "file_audit_enabled", cap, _audit_enabled, ["E-018"])


def check_admin_audit_destinations(col: Collection) -> list[dict[str, Any]]:
    """AUD-002: no destination receives the administrative audit log."""
    fetch = col.get("audit_destinations")
    cap = "change settings while the administrative audit record stays only on the file system"
    if fetch.outcome != "ok":
        return [_unreadable("AUD-002", "admin_audit_forwarding", fetch, ADMIN, cap)]
    n = len(fetch.records)
    status = "pass" if n else "finding"
    return [_finding("AUD-002", "admin_audit_forwarding", "cluster", status, ADMIN, cap, f"{n} destination(s)", fetch)]


ADMIN_ROLES = frozenset({"admin", "fsxadmin", "vsadmin"})


def _admin_accounts(fetch: Fetch) -> list[dict[str, Any]]:
    return [a for a in fetch.records if _dig(a, "role.name") in ADMIN_ROLES and a.get("locked") is not True]


def check_extra_admins(col: Collection) -> list[dict[str, Any]]:
    """ACC-001: unlocked accounts with an administrator role other than ``fsxadmin``."""
    fetch = col.get("accounts")
    cap = "a further administrator credential to steal, able to delete snapshots in its scope"
    if fetch.outcome != "ok":
        return [_unreadable("ACC-001", "extra_admin_accounts", fetch, ADMIN, cap)]
    extra = [a for a in _admin_accounts(fetch) if a.get("name") != "fsxadmin"]
    if not extra:
        return [_finding("ACC-001", "extra_admin_accounts", "accounts", "pass", ADMIN, cap, "fsxadmin only", fetch)]
    return [
        _finding(
            "ACC-001",
            "extra_admin_accounts",
            f"{_dig(a, 'owner.name') or '?'}/{a.get('name', '?')}",
            "finding",
            ADMIN,
            cap,
            f"role={_dig(a, 'role.name')}",
            fetch,
        )
        for a in extra
    ]


def check_password_only(col: Collection) -> list[dict[str, Any]]:
    """ACC-002: administrator accounts that sign in over http or ssh with a password alone."""
    fetch = col.get("accounts")
    cap = "sign in with a stolen or guessed password alone"
    if fetch.outcome != "ok":
        return [_unreadable("ACC-002", "admin_password_only", fetch, ADMIN, cap)]
    totp = col.get("totps")
    with_totp = {(str(_dig(t, "owner.name") or ""), str(_dig(t, "account.name") or "")) for t in totp.records}
    out = []
    for acct in _admin_accounts(fetch):
        owner, name = str(_dig(acct, "owner.name") or ""), str(acct.get("name", ""))
        weak = []
        for app in acct.get("applications") or []:
            if not isinstance(app, dict) or app.get("application") not in ("ssh", "http"):
                continue
            methods = {str(m) for m in app.get("authentication_methods") or []}
            second = str(app.get("second_authentication_method") or "none")
            if methods and methods <= {"password"} and second == "none":
                if app.get("application") == "ssh" and (owner, name) in with_totp:
                    continue
                weak.append(str(app.get("application")))
        status = "finding" if weak else "pass"
        observed = f"password only on {', '.join(sorted(weak))}" if weak else "second factor or non-password method"
        if totp.outcome != "ok":
            observed += f"; TOTP list not read (HTTP {totp.http})"
        out.append(
            _finding("ACC-002", "admin_password_only", f"{owner or '?'}/{name}", status, ADMIN, cap, observed, fetch)
        )
    return out


def check_mav(col: Collection) -> list[dict[str, Any]]:
    """MAV-001: multi-admin verification. A 403 is ``not_assessable``, never "disabled" [E-025]."""
    fetch = col.get("mav")
    cap = "delete snapshots or volumes with one administrator credential, without a second approver"
    if fetch.outcome == "role_refused":
        return [
            _finding(
                "MAV-001",
                "multi_admin_verify",
                "cluster",
                "not_assessable",
                ADMIN,
                cap,
                "HTTP 403, ONTAP code 6: this role may not read the setting",
                fetch,
                ["E-025"],
                destroys_recovery=True,
            )
        ]
    if fetch.outcome != "ok" or not fetch.records:
        return [_unreadable("MAV-001", "multi_admin_verify", fetch, ADMIN, cap, ["E-025"], destroys_recovery=True)]
    value = fetch.records[0].get("enabled")
    status = {True: "pass", False: "finding"}.get(value, "unknown") if isinstance(value, bool) else "unknown"
    return [
        _finding(
            "MAV-001",
            "multi_admin_verify",
            "cluster",
            status,
            ADMIN,
            cap,
            f"enabled={value}",
            fetch,
            ["E-025"],
            destroys_recovery=True,
        )
    ]


def check_peers(col: Collection, show_names: bool = False) -> list[dict[str, Any]]:
    """PEER-001: cluster peers, listed as information: data can leave this file system to them."""
    fetch = col.get("cluster_peers")
    cap = "data can leave this file system to the peer through SnapMirror or FlexCache"
    if fetch.outcome != "ok":
        return [_unreadable("PEER-001", "cluster_peers", fetch, NO_PRE, cap)]
    if not fetch.records:
        return [_finding("PEER-001", "cluster_peers", "cluster", "pass", NO_PRE, cap, "no cluster peer", fetch)]
    return [
        _finding(
            "PEER-001",
            "cluster_peers",
            name_token(p.get("name"), show_names),
            "finding",
            NO_PRE,
            cap,
            f"data leaves this file system to {name_token(p.get('name'), show_names)} (status {_dig(p, 'status.state')})",
            fetch,
            severity="info",
        )
        for p in fetch.records
    ]


def _endpoint_name(rec: dict[str, Any], side: str, show_names: bool) -> str:
    cluster = _dig(rec, f"{side}.cluster.name")
    path = _dig(rec, f"{side}.path")
    return name_token(f"{cluster or ''}:{path or ''}".strip(":"), show_names)


def check_snapmirror(col: Collection, show_names: bool = False) -> list[dict[str, Any]]:
    """SM-001: SnapMirror relationships, listed as information, in both directions."""
    out: list[dict[str, Any]] = []
    cap = "a copy of the volume exists outside this file system"
    for key, direction in (("snapmirror_destinations", "out"), ("snapmirror", "in")):
        fetch = col.get(key)
        if fetch.outcome != "ok":
            out.append(_unreadable("SM-001", f"snapmirror_{direction}", fetch, NO_PRE, cap))
            continue
        if not fetch.records:
            out.append(
                _finding(
                    "SM-001",
                    f"snapmirror_{direction}",
                    "cluster",
                    "pass",
                    NO_PRE,
                    cap,
                    f"no SnapMirror relationship ({direction})",
                    fetch,
                    severity="info",
                )
            )
        for rec in fetch.records:
            if direction == "out":
                res = _endpoint_name(rec, "source", show_names)
                observed = f"data leaves this file system to {_endpoint_name(rec, 'destination', show_names)}"
            else:
                res = _endpoint_name(rec, "destination", show_names)
                observed = f"data arrives from {_endpoint_name(rec, 'source', show_names)}"
            observed += f" (policy {_dig(rec, 'policy.name')}, state {rec.get('state')})"
            out.append(
                _finding(
                    "SM-001", f"snapmirror_{direction}", res, "finding", NO_PRE, cap, observed, fetch, severity="info"
                )
            )
    return out


def check_volume_encryption(col: Collection) -> list[dict[str, Any]]:
    """ENC-001: ONTAP volume encryption, as information.

    FSx for ONTAP encrypts file system storage at rest with the AWS KMS key shown under
    ``residency``; ``encryption.enabled`` reports ONTAP volume encryption, a separate layer.
    """
    fetch = col.get("volumes")
    cap = "information: ONTAP volume encryption is a layer separate from FSx for ONTAP storage encryption"
    if fetch.outcome != "ok":
        return [_unreadable("ENC-001", "volume_encryption", fetch, NO_PRE, cap)]
    vols = _rw_volumes(fetch.records)
    off = [v for v in vols if _dig(v, "encryption.enabled") is False]
    status = "finding" if off else "pass"
    observed = f"{len(off)} of {len(vols)} read-write volume(s) report encryption.enabled=false"
    return [_finding("ENC-001", "volume_encryption", "volumes", status, NO_PRE, cap, observed, fetch, severity="info")]


def check_key_managers(col: Collection) -> list[dict[str, Any]]:
    """KM-001: ONTAP key managers, as information."""
    fetch = col.get("key_managers")
    cap = "information: which key manager holds ONTAP volume keys"
    if fetch.outcome != "ok":
        return [_unreadable("KM-001", "key_managers", fetch, NO_PRE, cap)]
    kinds = sorted(
        {str(k.get("scope") or "?") + ":" + ("external" if k.get("external") else "onboard") for k in fetch.records}
    )
    observed = f"{len(fetch.records)} key manager(s) {kinds}" if fetch.records else "no ONTAP key manager"
    return [_finding("KM-001", "key_managers", "cluster", "finding", NO_PRE, cap, observed, fetch, severity="info")]


CHECK_IDS = (
    "ARP-001",
    "ARP-002",
    "ARP-003",
    "SNAP-001",
    "SNAP-002",
    "SNAP-003",
    "SNAP-004",
    "NFS-001",
    "CIFS-001",
    "FPOL-001",
    "VSCAN-001",
    "AUD-001",
    "AUD-002",
    "ACC-001",
    "ACC-002",
    "MAV-001",
    "PEER-001",
    "SM-001",
    "ENC-001",
    "KM-001",
)


def run_checks(col: Collection, *, now: datetime | None = None, show_names: bool = False) -> list[dict[str, Any]]:
    """Run every ONTAP check.

    When the control read failed, every check is returned once with status ``inconclusive``.
    """
    if not col.control_ok:
        control = col.get("cluster")
        return [
            {
                "id": cid,
                "check": cid.lower(),
                "resource": "-",
                "severity": "info",
                "status": "inconclusive",
                "attacker_precondition": NO_PRE,
                "attacker_capability": "not assessed",
                "observed": f"control read of /api/cluster failed ({col.stopped or control.note})",
                "source": control.source(),
                "ledger": [],
            }
            for cid in CHECK_IDS
        ]
    now = now or datetime.now(timezone.utc)
    findings: list[dict[str, Any]] = []
    for fn in (
        check_arp_volumes,
        check_arp_auto_enable,
        check_arp_suspects,
        check_snapshot_policy,
        check_autodelete,
        check_compliance_clock,
        check_export_policies,
        check_cifs_acls,
        check_fpolicy,
        check_vscan,
        check_file_audit,
        check_admin_audit_destinations,
        check_extra_admins,
        check_password_only,
        check_mav,
        check_volume_encryption,
        check_key_managers,
    ):
        findings.extend(fn(col))
    findings.extend(check_locked_snapshots(col, now))
    findings.extend(check_peers(col, show_names))
    findings.extend(check_snapmirror(col, show_names))
    return findings


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts by status, and by severity for status ``finding``."""
    by_status = {s: 0 for s in STATUSES}
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
        if f["status"] == "finding":
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {"by_status": by_status, "findings_by_severity": by_sev, "total": len(findings)}


def exceeds(findings: list[dict[str, Any]], fail_on: str) -> bool:
    """True when any ``finding`` is at or above ``fail_on`` (``high``, ``medium``; ``none`` never)."""
    if fail_on == "none":
        return False
    floor = SEVERITY_ORDER[fail_on]
    return any(f["status"] == "finding" and SEVERITY_ORDER[f["severity"]] >= floor for f in findings)

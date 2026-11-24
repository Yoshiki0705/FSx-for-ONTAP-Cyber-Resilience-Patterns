"""Tests for the read-only adversarial configuration probe (solutions/config-probe).

The package is imported through the path ``tests/conftest.py`` adds. No test opens a network
connection: ONTAP is a fixture-driven fake, the TLS connection is a fake object, and the AWS
clients are stubs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from config_probe import aws_side, checks, cli, collect, transport
from config_probe.transport import (
    AuthenticationAbort,
    DeadlineExceeded,
    FingerprintMismatch,
    OntapTransport,
    ProbeError,
    Reply,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "config_probe"
CATALOG = ROOT / "docs" / "ontap-native" / "data" / "fsx-ontap-9.18.1P6-rest-endpoints.tsv"
NOW = datetime(2026, 11, 15, 6, 0, 0, tzinfo=timezone.utc)
FS_ID = "fs-0123456789abcdef0"
PASSWORD = "Pa55w0rd-do-not-log"
DER = b"fake-der-certificate"
FINGERPRINT = hashlib.sha256(DER).hexdigest()
COLON_FINGERPRINT = ":".join(FINGERPRINT[i : i + 2] for i in range(0, 64, 2)).upper()


def load(name: str) -> dict[str, Any]:
    data = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    data.pop("$comment", None)
    return data


class FakeOntap:
    """Answers GETs from a fixture keyed by path; records every request."""

    netloc = "localhost:18443"

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.requests: list[str] = []

    def get(self, path: str) -> Reply:
        self.requests.append(path)
        base, _, query = path.partition("?")
        key = base + ("#destinations" if "list_destinations_only=true" in query else "")
        ans = self.answers.get(key)
        if ans is None:
            return Reply(404, None, "4", "not found")
        status = ans["status"]
        if status >= 400:
            return Reply(status, None, str(ans.get("code", "")), "")
        return Reply(status, ans["body"], "", "")


def collected(name: str, **overrides: Any) -> collect.Collection:
    answers = load(name)
    answers.update(overrides)
    return collect.collect(FakeOntap(answers))


def by_id(findings: list[dict[str, Any]], fid: str) -> list[dict[str, Any]]:
    return [f for f in findings if f["id"] == fid]


# ---------------------------------------------------------------------------
# Fake TLS connection for OntapTransport
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self._raw = json.dumps(body).encode() if body is not None else b""

    def read(self) -> bytes:
        return self._raw


class FakeSock:
    def __init__(self, der: bytes) -> None:
        self.der = der
        self.timeout: float | None = None

    def getpeercert(self, binary_form: bool = False) -> bytes:
        assert binary_form
        return self.der

    def settimeout(self, value: float) -> None:
        self.timeout = value


class FakeConnection:
    def __init__(self, responses: list[tuple[int, Any]], der: bytes = DER) -> None:
        self.responses = list(responses)
        self.sock = FakeSock(der)
        self.sent: list[tuple[str, str, dict[str, str]]] = []
        self.connected = False

    def connect(self) -> None:
        self.connected = True

    def request(self, method: str, path: str, headers: dict[str, str]) -> None:
        self.sent.append((method, path, headers))

    def getresponse(self) -> FakeResponse:
        return FakeResponse(*self.responses.pop(0))

    def close(self) -> None:
        pass


def make_transport(conn: FakeConnection, **kwargs: Any) -> tuple[OntapTransport, list[Any]]:
    opened: list[Any] = []

    def factory(host: str, port: int, ctx: Any, timeout: float) -> FakeConnection:
        opened.append((host, port, timeout))
        return conn

    t = OntapTransport(
        "https://localhost:18443",
        "fsxadmin",
        PASSWORD,
        kwargs.pop("fingerprint", COLON_FINGERPRINT),
        connection_factory=factory,
        **kwargs,
    )
    return t, opened


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE", "PUT", "get"])
def test_non_get_is_refused_before_any_connection(method: str) -> None:
    conn = FakeConnection([(200, {})])
    t, opened = make_transport(conn)
    with pytest.raises(ProbeError, match="GET only"):
        t.request(method, "/api/cluster")
    assert opened == [] and conn.sent == []


def test_fingerprint_mismatch_is_refused_and_nothing_is_sent() -> None:
    conn = FakeConnection([(200, {})], der=b"another certificate")
    t, _ = make_transport(conn)
    with pytest.raises(FingerprintMismatch):
        t.get("/api/cluster")
    assert conn.sent == []
    with pytest.raises(ProbeError):  # the transport stays closed after a mismatch
        t.get("/api/cluster")
    assert conn.sent == []


def test_fingerprint_forms_and_bad_values() -> None:
    assert transport.normalize_fingerprint(COLON_FINGERPRINT) == FINGERPRINT
    assert transport.normalize_fingerprint(f"sha256 Fingerprint={COLON_FINGERPRINT}") == FINGERPRINT
    with pytest.raises(ProbeError):
        transport.normalize_fingerprint("abcd")


def test_pinned_connection_sets_read_timeout_and_sends_basic_auth() -> None:
    conn = FakeConnection([(200, {"name": "x"})])
    t, opened = make_transport(conn, connect_timeout=7, read_timeout=11)
    reply = t.get("/api/cluster?fields=name,version")
    assert reply.status == 200 and opened == [("localhost", 18443, 7)]
    assert conn.sock.timeout == 11
    method, path, headers = conn.sent[0]
    assert method == "GET" and path == "/api/cluster?fields=name,version"
    assert headers["Authorization"].startswith("Basic ")
    assert PASSWORD not in repr(t)


@pytest.mark.parametrize(
    "base_url", ["http://localhost:18443", "https://localhost:18443/api", "https://u:p@host", "ftp://x"]
)
def test_base_url_must_be_plain_https(base_url: str) -> None:
    with pytest.raises(ProbeError):
        OntapTransport(base_url, "u", "p", FINGERPRINT)


@pytest.mark.parametrize("path", ["/other", "/api/../x", "/api/a b", "/api/x\r\nHost: y"])
def test_unsafe_paths_are_refused(path: str) -> None:
    t, opened = make_transport(FakeConnection([]))
    with pytest.raises(ProbeError):
        t.get(path)
    assert opened == []


@pytest.mark.parametrize("code", ["6691623", ""])
def test_auth_failure_stops_every_further_request(code: str) -> None:
    err = {"error": {"code": code, "message": "User is not authorized"}} if code else None
    conn = FakeConnection([(200, {"name": "c", "version": {"full": "NetApp Release 9.18.1P6"}}), (401, err)])
    t, _ = make_transport(conn)
    col = collect.collect(t)
    assert len(conn.sent) == 2, "exactly one request after the control read, then nothing"
    assert t.requests_sent == 2
    assert "credential refused" in col.stopped
    with pytest.raises(AuthenticationAbort):
        t.get("/api/cluster")
    assert len(conn.sent) == 2


def test_auth_failure_on_control_read_sends_one_request() -> None:
    conn = FakeConnection([(401, {"error": {"code": "6691623", "message": "x"}})])
    t, _ = make_transport(conn)
    col = collect.collect(t)
    assert len(conn.sent) == 1 and not col.control_ok
    findings = checks.run_checks(col)
    assert {f["status"] for f in findings} == {"inconclusive"}
    assert {f["id"] for f in findings} == set(checks.CHECK_IDS)


def test_role_answer_401_is_not_an_auth_failure() -> None:
    conn = FakeConnection([(401, {"error": {"code": "13763280", "message": "only vsadmin-snaplock"}}), (200, {})])
    t, _ = make_transport(conn)
    reply = t.get("/api/storage/snaplock/compliance-clocks")
    assert reply.status == 401 and reply.error_code == "13763280" and not t.aborted
    assert transport.classify_reply(reply) == "role_answer"
    assert t.get("/api/cluster").status == 200


def test_403_code_6_is_role_refused() -> None:
    assert transport.classify_reply(Reply(403, None, "6", "")) == "role_refused"
    assert transport.classify_reply(Reply(403, None, "7", "")) == "error"
    assert transport.classify_reply(Reply(404, None, "", "")) == "absent"


def test_deadline_stops_requests() -> None:
    clock = iter([0.0, 1.0, 1000.0])
    conn = FakeConnection([(200, {})])
    t, _ = make_transport(conn, deadline_seconds=10, clock=lambda: next(clock))
    t.get("/api/cluster")
    with pytest.raises(DeadlineExceeded):
        t.get("/api/cluster")
    assert len(conn.sent) == 1


def test_connection_error_is_a_transport_failure() -> None:
    class Broken(FakeConnection):
        def connect(self) -> None:
            raise OSError("refused")

    t, _ = make_transport(Broken([]))
    with pytest.raises(transport.TransportFailure):
        t.get("/api/cluster")


class Pages:
    netloc = "localhost:18443"

    def __init__(self, pages: dict[str, Any]) -> None:
        self.pages = pages
        self.requests: list[str] = []

    def get(self, path: str) -> Reply:
        self.requests.append(path)
        return Reply(200, self.pages[path], "", "")


def test_pagination_follows_api_links_on_the_same_host_only() -> None:
    pages = {
        "/api/storage/volumes?fields=name": {
            "records": [{"n": 1}],
            "_links": {"next": {"href": "/api/storage/volumes?start=2"}},
        },
        "/api/storage/volumes?start=2": {
            "records": [{"n": 2}],
            "_links": {"next": {"href": "https://localhost:18443/api/storage/volumes?start=3"}},
        },
        "/api/storage/volumes?start=3": {
            "records": [{"n": 3}],
            "_links": {"next": {"href": "https://evil.example/api/x"}},
        },
    }
    t = Pages(pages)
    reply, records = transport.get_collection(t, "/api/storage/volumes", "fields=name")
    assert [r["n"] for r in records] == [1, 2, 3]
    assert len(t.requests) == 3


@pytest.mark.parametrize(
    "href",
    ["/other/x", "https://evil.example/api/x", "http://localhost:18443/api/x", "/api/../x", "/api/x\nHost: y", None, 5],
)
def test_unsafe_next_links_are_not_followed(href: Any) -> None:
    assert transport.safe_next(href, "localhost:18443") is None


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


def _template(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def test_every_collection_path_is_in_the_rest_catalog() -> None:
    rows = [line.split("\t") for line in CATALOG.read_text(encoding="utf-8").splitlines() if line.startswith("/")]
    catalog = {_template(r[0]): r[1].split(",") for r in rows}
    for path in collect.collection_paths():
        assert path.startswith("/api/")
        key = _template(path[len("/api") :])
        assert key in catalog, f"{path} is not an endpoint of ONTAP 9.18.1P6 on FSx for ONTAP"
        assert "GET" in catalog[key], f"{path} has no GET in the catalog"
    assert "/storage/volumes/{}/snapshots" in {_template(p[4:]) for p in collect.collection_paths()}


def test_catalog_test_is_not_vacuous() -> None:
    rows = {_template(line.split("\t")[0]) for line in CATALOG.read_text(encoding="utf-8").splitlines()}
    assert "/security/anti-ransomware/volumes/{}" not in rows  # the wrong path of E-028 would fail


# ---------------------------------------------------------------------------
# Checks: a finding on the bad fixture and a pass on the good fixture
# ---------------------------------------------------------------------------

PAIRED = [c for c in checks.CHECK_IDS if c != "KM-001"]  # KM-001 is information only, never pass


@pytest.fixture(scope="module")
def bad_findings() -> list[dict[str, Any]]:
    return checks.run_checks(collected("bad"), now=NOW)


@pytest.fixture(scope="module")
def good_findings() -> list[dict[str, Any]]:
    return checks.run_checks(collected("good"), now=NOW)


@pytest.mark.parametrize("fid", PAIRED)
def test_each_check_finds_on_bad_and_passes_on_good(
    fid: str, bad_findings: list[dict[str, Any]], good_findings: list[dict[str, Any]]
) -> None:
    bad, good = by_id(bad_findings, fid), by_id(good_findings, fid)
    assert any(f["status"] == "finding" for f in bad), (fid, bad)
    assert good and all(f["status"] == "pass" for f in good), (fid, good)


def test_finding_shape(bad_findings: list[dict[str, Any]]) -> None:
    keys = {
        "id",
        "check",
        "resource",
        "severity",
        "status",
        "attacker_precondition",
        "attacker_capability",
        "observed",
        "source",
        "ledger",
    }
    for f in bad_findings:
        assert set(f) == keys
        assert f["severity"] in checks.SEVERITY_ORDER and f["status"] in checks.STATUSES
        assert set(f["source"]) == {"path", "http", "ontap_code"}
        assert "?" not in f["source"]["path"]


def test_severities_follow_the_precondition(bad_findings: list[dict[str, Any]]) -> None:
    sev = {f["id"]: f["severity"] for f in bad_findings if f["status"] == "finding"}
    assert sev["NFS-001"] == "high"  # network reach only
    assert sev["CIFS-001"] == "medium" and sev["ARP-001"] == "medium"  # data-protocol credentials
    assert sev["ACC-001"] == "low" and sev["AUD-002"] == "low"  # admin credentials
    assert sev["SNAP-002"] == "high" and sev["SNAP-003"] == "high"  # recovery points destroyed
    assert sev["PEER-001"] == "info" and sev["SM-001"] == "info"


def test_ledger_ids_are_cited(bad_findings: list[dict[str, Any]]) -> None:
    ledger = {c["id"] for c in json.loads((ROOT / "docs/agent/evidence-ledger.json").read_text())["claims"]}
    cited = {i for f in bad_findings for i in f["ledger"]}
    assert {"E-015", "E-018", "E-025"} <= cited
    assert cited <= ledger
    assert {"E-009", "E-060"} <= ledger


def test_root_volume_is_skipped(good_findings: list[dict[str, Any]]) -> None:
    assert not [f for f in good_findings if f["resource"].endswith("_root")]


def test_arp_transitional_and_unknown_states() -> None:
    col = collected("good")
    col.fetches["volumes"].records[0]["anti_ransomware"] = {"state": "disable_in_progress"}
    (f,) = checks.check_arp_volumes(col)
    assert f["status"] == "finding" and "being removed" in f["observed"]
    col.fetches["volumes"].records[0]["anti_ransomware"] = {"state": "something-new"}
    (f,) = checks.check_arp_volumes(col)
    assert f["status"] == "unknown"
    assert checks.classify_arp_state("dry-run") == "protecting"
    assert checks.classify_arp_state(None) == "unknown"


def test_mav_403_is_not_assessable_never_disabled() -> None:
    col = collected("good", **{"/api/security/multi-admin-verify": {"status": 403, "code": "6"}})
    (f,) = checks.check_mav(col)
    assert f["status"] == "not_assessable" and f["ledger"] == ["E-025"]
    assert "disabled" not in f["observed"].lower()
    assert f["source"] == {"path": "/api/security/multi-admin-verify", "http": 403, "ontap_code": "6"}


def test_unreadable_sources_become_unknown_or_not_assessable() -> None:
    col = collected(
        "good",
        **{
            "/api/protocols/vscan": {"status": 403, "code": "6"},
            "/api/protocols/audit": {"status": 500, "code": "1"},
            "/api/storage/snaplock/compliance-clocks": {"status": 401, "code": "13763280"},
        },
    )
    col.fetches.pop("fpolicy")
    f = checks.run_checks(col, now=NOW)
    assert by_id(f, "VSCAN-001")[0]["status"] == "not_assessable"
    assert by_id(f, "AUD-001")[0]["status"] == "unknown"
    assert by_id(f, "SNAP-004")[0]["status"] == "unknown"
    assert by_id(f, "FPOL-001")[0]["status"] == "unknown"


def test_volume_fields_fallback_on_http_400() -> None:
    answers = load("good")
    vols = answers["/api/storage/volumes"]

    class Picky(FakeOntap):
        def get(self, path: str) -> Reply:
            if path.startswith("/api/storage/volumes?") and "snapshot_locking_enabled" in path:
                self.requests.append(path)
                return Reply(400, None, "262197", "Invalid field")
            return super().get(path)

    fake = Picky({**answers, "/api/storage/volumes": vols})
    col = collect.collect(fake)
    assert col.get("volumes").outcome == "ok"
    assert sum(p.startswith("/api/storage/volumes?") for p in fake.requests) == 2


def test_max_volumes_caps_snapshot_reads() -> None:
    fake = FakeOntap(load("bad"))
    col = collect.collect(fake, max_volumes=1)
    assert len(col.snapshots) == 1 and len(col.volumes_not_read) == 1
    f = checks.check_locked_snapshots(col, NOW)
    assert any("max-volumes" in x["observed"] and x["status"] == "unknown" for x in f)


def test_only_get_paths_from_the_collector_were_requested() -> None:
    fake = FakeOntap(load("good"))
    collect.collect(fake)
    assert fake.requests[0] == "/api/cluster?fields=name,version"
    assert all(p.startswith("/api/") for p in fake.requests)


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------


def test_masking_of_cluster_names_ips_accounts_and_fs_ids() -> None:
    text = (
        "FsxId0123456789abcdef0-01 at 10.0.1.10 in arn:aws:s3:ap-northeast-1:123456789012:accesspoint/x "
        "for fs-0123456789abcdef0 version 9.18.1"
    )
    masked = checks.mask_text(text)
    assert "FsxId" not in masked and "10.0.1.10" not in masked and "123456789012" not in masked
    assert "fs-0123456789abcdef0" not in masked and "fs-…def0" in masked
    assert "9.18.1" in masked
    assert "fs-0123456789abcdef0" in checks.mask_text(text, show_names=True)
    assert "123456789012" not in checks.mask_text(text, show_names=True)
    uuid = "11111111-1111-1111-1111-123456789012"
    assert checks.mask_text(uuid) == uuid


def test_name_tokens_are_stable_and_hidden() -> None:
    assert checks.name_token("onprem-dr") == checks.name_token("onprem-dr")
    assert "onprem" not in checks.name_token("onprem-dr")
    assert checks.name_token("onprem-dr", show_names=True) == "onprem-dr"


# ---------------------------------------------------------------------------
# AWS side
# ---------------------------------------------------------------------------


class ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class StubFsx:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def describe_file_systems(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("describe_file_systems")
        assert kw == {"FileSystemIds": [FS_ID]}
        return {
            "FileSystems": [
                {
                    "OwnerId": "123456789012",
                    "KmsKeyId": "arn:aws:kms:ap-northeast-1:123456789012:key/0000000a-000a-400a-800a-00000000000a",
                    "ResourceARN": f"arn:aws:fsx:ap-northeast-1:123456789012:file-system/{FS_ID}",
                }
            ]
        }

    def describe_backups(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("describe_backups")
        if "NextToken" not in kw:
            return {"Backups": [{"BackupId": "backup-1"}], "NextToken": "t"}
        return {"Backups": [{"BackupId": "backup-2", "SourceBackupRegion": "ap-northeast-3"}]}

    def describe_s3_access_point_attachments(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("describe_s3_access_point_attachments")
        arn = "arn:aws:s3:ap-northeast-1:123456789012:accesspoint/ap-open"
        arn2 = "arn:aws:s3:ap-northeast-1:123456789012:accesspoint/ap-closed"
        return {
            "S3AccessPointAttachments": [
                {"S3AccessPoint": {"ResourceARN": arn}},
                {"S3AccessPoint": {"ResourceARN": arn2}},
            ]
        }


class StubKms:
    def __init__(self, manager: str) -> None:
        self.manager = manager

    def describe_key(self, KeyId: str) -> dict[str, Any]:
        return {"KeyMetadata": {"KeyManager": self.manager, "Origin": "AWS_KMS"}}


class StubS3Control:
    def get_access_point(self, AccountId: str, Name: str) -> dict[str, Any]:
        assert AccountId == "123456789012"
        return {"NetworkOrigin": "Internet" if Name == "ap-open" else "VPC"}

    def get_access_point_policy(self, AccountId: str, Name: str) -> dict[str, Any]:
        if Name == "ap-closed":
            raise ClientError("NoSuchAccessPointPolicy")
        return {
            "Policy": json.dumps({"Statement": [{"Sid": "all", "Effect": "Allow", "Principal": "*", "Action": "s3:*"}]})
        }


def test_aws_managed_key_is_high() -> None:
    findings, res = aws_side.collect_aws(StubFsx(), StubKms("AWS"), StubS3Control(), FS_ID)
    (kms,) = by_id(findings, "KMS-001")
    assert kms["status"] == "finding" and kms["severity"] == "high" and kms["ledger"] == ["E-009", "E-060"]
    assert res["region"] == "ap-northeast-1" and res["kms_key_manager"] == "AWS"
    assert res["backup_count"] == 2 and res["backup_copy_source_regions"] == ["ap-northeast-3"]


def test_customer_key_passes_and_access_points_are_judged() -> None:
    findings, res = aws_side.collect_aws(StubFsx(), StubKms("CUSTOMER"), StubS3Control(), FS_ID)
    assert by_id(findings, "KMS-001")[0]["status"] == "pass"
    origin = {f["status"] for f in by_id(findings, "S3AP-001")}
    assert origin == {"finding", "pass"}
    policy = by_id(findings, "S3AP-002")
    assert {(f["status"], f["severity"]) for f in policy} == {("finding", "high"), ("finding", "info")}
    assert res["s3_access_points"] == 2
    assert not any("ap-open" in f["resource"] for f in findings)  # names masked by default


def test_conditioned_principal_star_is_not_open() -> None:
    doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Condition": {"StringEquals": {"x": "y"}}}]}
    assert aws_side._policy_is_open(json.dumps(doc)) == []
    assert aws_side._policy_is_open(json.dumps({"Statement": {"Effect": "Allow", "Principal": {"AWS": ["*"]}}})) == [
        "0"
    ]


def test_aws_errors_become_unknown() -> None:
    class Failing(StubFsx):
        def describe_file_systems(self, **kw: Any) -> dict[str, Any]:
            raise ClientError("AccessDenied")

    findings, _ = aws_side.collect_aws(Failing(), StubKms("AWS"), StubS3Control(), FS_ID)
    assert findings[0]["status"] == "unknown" and "AccessDenied" in findings[0]["observed"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class StubSecrets:
    def __init__(self, tag: str | None = FS_ID) -> None:
        self.tag = tag
        self.read_value = False

    def describe_secret(self, SecretId: str) -> dict[str, Any]:
        return {"Tags": [{"Key": "FileSystemId", "Value": self.tag}] if self.tag else []}

    def get_secret_value(self, SecretId: str) -> dict[str, Any]:
        self.read_value = True
        return {"SecretString": json.dumps({"username": "fsxadmin", "password": PASSWORD})}


class StubS3ControlClosed(StubS3Control):
    def get_access_point(self, AccountId: str, Name: str) -> dict[str, Any]:
        return {"NetworkOrigin": "VPC"}

    def get_access_point_policy(self, AccountId: str, Name: str) -> dict[str, Any]:
        raise ClientError("NoSuchAccessPointPolicy")


def clients_for(secrets: StubSecrets, manager: str = "CUSTOMER") -> Any:
    table = {"secretsmanager": secrets, "fsx": StubFsx(), "kms": StubKms(manager), "s3control": StubS3ControlClosed()}
    return lambda service: table[service]


def argv(*extra: str) -> list[str]:
    return [
        "--base-url",
        "https://localhost:18443",
        "--fingerprint",
        COLON_FINGERPRINT,
        "--file-system-id",
        FS_ID,
        "--secret-id",
        "example-secret",
        *extra,
    ]


def fake_factory(fixture: str, seen: list[tuple[str, str]] | None = None) -> Any:
    def factory(args: Any, username: str, password: str) -> FakeOntap:
        if seen is not None:
            seen.append((username, password))
        return FakeOntap(load(fixture))

    return factory


@pytest.mark.parametrize(
    ("fixture", "fail_on", "code"),
    [("good", "high", 0), ("bad", "high", 2), ("bad", "medium", 2), ("bad", "none", 0), ("good", "medium", 0)],
)
def test_fail_on_exit_codes(fixture: str, fail_on: str, code: int, tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    rc = cli.main(
        argv("--fail-on", fail_on, "--out", str(out)),
        clients=clients_for(StubSecrets()),
        transport_factory=fake_factory(fixture),
    )
    assert rc == code
    doc = json.loads(out.read_text())
    assert doc["schema"] == "config-probe/v1" and doc["get_only"] is True and doc["bodies_stored"] is False
    assert doc["ontap_version"] == "9.18.1P6" and doc["file_system_id"] == "fs-…def0"
    assert set(doc["summary"]) == {"by_status", "findings_by_severity", "total"}


def test_medium_finding_alone_fails_medium_but_not_high(tmp_path: Path) -> None:
    answers = load("good")
    answers["/api/protocols/vscan"] = {
        "status": 200,
        "body": {"records": [{"svm": {"name": "svm1"}, "enabled": False}]},
    }

    def factory(args: Any, u: str, p: str) -> FakeOntap:
        return FakeOntap(answers)

    common = dict(clients=clients_for(StubSecrets()), transport_factory=factory)
    assert cli.main(argv("--fail-on", "high", "--out", str(tmp_path / "a")), **common) == 0
    assert cli.main(argv("--fail-on", "medium", "--out", str(tmp_path / "b")), **common) == 2


def test_aws_managed_key_fails_high_gate(tmp_path: Path) -> None:
    rc = cli.main(
        argv("--fail-on", "high", "--out", str(tmp_path / "o")),
        clients=clients_for(StubSecrets(), manager="AWS"),
        transport_factory=fake_factory("good"),
    )
    assert rc == 2


@pytest.mark.parametrize("tag", ["fs-0fedcba9876543210", None])
def test_secret_tag_mismatch_is_refused(tag: str | None, tmp_path: Path) -> None:
    seen: list[Any] = []
    secrets = StubSecrets(tag)
    rc = cli.main(
        argv("--skip-aws", "--out", str(tmp_path / "o")),
        clients=clients_for(secrets),
        transport_factory=fake_factory("good", seen),
    )
    assert rc == 3 and seen == [] and secrets.read_value is False
    assert "not tagged" in json.loads((tmp_path / "o").read_text())["stopped"]


def test_control_failure_exits_3_with_inconclusive(tmp_path: Path) -> None:
    answers = load("good")
    answers["/api/cluster"] = {"status": 500, "code": "1"}

    def factory(args: Any, u: str, p: str) -> FakeOntap:
        return FakeOntap(answers)

    rc = cli.main(
        argv("--skip-aws", "--out", str(tmp_path / "o")), clients=clients_for(StubSecrets()), transport_factory=factory
    )
    doc = json.loads((tmp_path / "o").read_text())
    assert rc == 3 and {f["status"] for f in doc["findings"]} == {"inconclusive"}


def test_password_never_in_logs_or_output(caplog: pytest.LogCaptureFixture, tmp_path: Path, capsys: Any) -> None:
    caplog.set_level(logging.DEBUG)
    token = base64.b64encode(f"fsxadmin:{PASSWORD}".encode()).decode()
    seen: list[Any] = []

    # A real OntapTransport over a fake connection, so its own debug logging is exercised.
    def factory(args: Any, username: str, password: str) -> OntapTransport:
        seen.append(password)
        answers = load("bad")
        responses: list[tuple[int, Any]] = []
        conn = FakeConnection(responses)
        fake = FakeOntap(answers)

        def getresponse() -> FakeResponse:
            path = conn.sent[-1][1]
            reply = fake.get(path)
            body = reply.body if reply.status < 400 else {"error": {"code": reply.error_code, "message": ""}}
            return FakeResponse(reply.status, body)

        conn.getresponse = getresponse  # type: ignore[method-assign]
        return OntapTransport(args.base_url, username, password, args.fingerprint, connection_factory=lambda *a: conn)

    rc = cli.main(argv("--show-names"), clients=clients_for(StubSecrets()), transport_factory=factory)
    out = capsys.readouterr().out
    assert rc == 0 and seen == [PASSWORD]
    assert any("GET /api/" in r.getMessage() for r in caplog.records)  # debug logging ran
    for text in (caplog.text, out):
        assert PASSWORD not in text and token not in text and "Authorization" not in text
    doc = json.loads(out)
    assert "FsxId0123456789abcdef0" not in out and "10.0.3.30" not in out and "123456789012" not in out
    assert doc["file_system_id"] == FS_ID  # --show-names
    assert doc["residency"]["cluster_peers"] == ["onprem-dr"]


def test_residency_masks_peer_names_by_default(tmp_path: Path) -> None:
    out = tmp_path / "o"
    cli.main(argv("--out", str(out)), clients=clients_for(StubSecrets()), transport_factory=fake_factory("bad"))
    doc = json.loads(out.read_text())
    res = doc["residency"]
    assert res["cluster_peers"] and "onprem" not in json.dumps(res)
    assert res["snapmirror_destination_clusters"] == res["cluster_peers"]
    assert res["region"] == "ap-northeast-1" and res["kms_key_manager"] == "CUSTOMER"


def test_usage_errors() -> None:
    assert cli.main(["--skip-aws"]) == 64
    assert cli.main(["--skip-ontap"]) == 64
    assert cli.main(["--help"]) == 0


def test_skip_both_runs_without_clients(capsys: Any) -> None:
    assert cli.main(["--skip-ontap", "--skip-aws"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["findings"] == [] and doc["file_system_id"] == ""


@pytest.mark.parametrize("cmd", [["probe.py", "--help"], ["-m", "config_probe", "--help"]])
def test_entry_points(cmd: list[str]) -> None:
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, *cmd], cwd=ROOT / "solutions" / "config-probe", capture_output=True, text=True, check=False
    )
    assert result.returncode == 0 and "--fail-on" in result.stdout

"""GET-only HTTPS transport to the ONTAP management endpoint.

Ideas taken from ``solutions/ontap-catalog-snapshot/functions/snapshot/handler.py`` (``Reply``,
the ``Transport`` protocol, GET only, stop at the first refused credential). This module adds:

* certificate fingerprint pinning, because the management certificate does not verify against
  the default trust store, and turning verification off would accept any certificate;
* connect and read timeouts on every call and an overall deadline;
* a latch: after one authentication failure no further request leaves this process, because
  repeated failures with the same administrator lock the account;
* pagination that follows ``_links.next.href`` only to ``/api/`` on the same host.

The password and the Authorization header are never logged.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# ONTAP answers a failed login with this code. The same message covers a wrong password and a
# locked account, so the run stops on the first one.
AUTH_FAILURE_CODES = frozenset({"6691623"})
# 401 answers that are role authorization, not a failed login: SnapLock endpoints reserved to the
# vsadmin-snaplock role (observed on ONTAP 9.18.1P6, see docs/ontap-native/ontap-command-api-snapshot.md).
ROLE_ANSWER_CODES = frozenset({"13763280", "14090242"})
# 403 with this ONTAP code: the endpoint exists and the role may not use it.
ROLE_REFUSED_CODE = "6"
MAX_PAGES = 50
_HOST_RE = re.compile(r"[A-Za-z0-9.-]+")
_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")


class ProbeError(Exception):
    """A condition that ends the ONTAP part of the run. ``reason`` is safe to log."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AuthenticationAbort(ProbeError):
    """The credential was refused. Nothing more is sent with it."""


class FingerprintMismatch(ProbeError):
    """The server certificate is not the pinned one. Nothing was sent."""


class DeadlineExceeded(ProbeError):
    """The overall deadline passed before the request."""


class TransportFailure(ProbeError):
    """The connection failed or timed out for one request."""


@dataclass(frozen=True)
class Reply:
    """One HTTP answer.

    Attributes:
        status: HTTP status code.
        body: Parsed JSON for a 2xx answer, otherwise None.
        error_code: ONTAP ``error.code`` of an error answer, or an empty string.
        error_message: ONTAP ``error.message`` of an error answer, or an empty string.
    """

    status: int
    body: Any
    error_code: str
    error_message: str


class Transport(Protocol):
    """What the collector needs from a transport."""

    def get(self, path: str) -> Reply:
        """Send one GET for ``path`` (path and query, starting with ``/api/``)."""
        ...


def normalize_fingerprint(value: str) -> str:
    """Return a SHA-256 fingerprint as 64 lowercase hex characters.

    Args:
        value: ``AA:BB:...`` as printed by ``openssl x509 -fingerprint -sha256``, or plain hex.

    Returns:
        The normalized fingerprint.

    Raises:
        ProbeError: The value is not a SHA-256 fingerprint.
    """
    text = value.strip().lower()
    if text.startswith("sha256 fingerprint="):
        text = text.split("=", 1)[1]
    text = text.replace(":", "").replace(" ", "")
    if not _FINGERPRINT_RE.fullmatch(text):
        raise ProbeError("the fingerprint is not a SHA-256 value (64 hex characters)")
    return text


def is_auth_failure(reply: Reply) -> bool:
    """True when a reply means the credential itself was refused.

    A 401 stops the run unless its ONTAP code is a known role answer, so an unknown 401 is treated
    as a refused credential (the safe side for account lockout).
    """
    if reply.status != 401:
        return False
    if reply.error_code in AUTH_FAILURE_CODES:
        return True
    return reply.error_code not in ROLE_ANSWER_CODES


def classify_reply(reply: Reply) -> str:
    """Name what an answer means for a check.

    Returns:
        ``ok``, ``role_refused`` (403 code 6), ``role_answer`` (401 with a role code),
        ``absent`` (404) or ``error``.
    """
    if 200 <= reply.status < 300:
        return "ok"
    if reply.status == 403 and reply.error_code == ROLE_REFUSED_CODE:
        return "role_refused"
    if reply.status == 401 and reply.error_code in ROLE_ANSWER_CODES:
        return "role_answer"
    if reply.status == 404:
        return "absent"
    return "error"


ConnectionFactory = Callable[[str, int, ssl.SSLContext, float], Any]


def _default_connection(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)


class OntapTransport:
    """GET-only client for the ONTAP management endpoint, with a pinned certificate.

    Args:
        base_url: ``https://host[:port]``, for example ``https://localhost:18443`` through an SSM
            port forward. No path.
        username: ONTAP user name.
        password: ONTAP password. Kept only inside the Authorization header value.
        fingerprint: SHA-256 fingerprint of the management certificate (DER).
        connect_timeout: Seconds allowed to open the TCP and TLS connection.
        read_timeout: Seconds allowed to wait for each answer.
        deadline_seconds: Seconds after construction when no further request is sent.
        connection_factory: Builds the HTTPS connection; tests replace it.
        clock: Monotonic clock; tests replace it.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        fingerprint: str,
        *,
        connect_timeout: float = 10.0,
        read_timeout: float = 30.0,
        deadline_seconds: float = 300.0,
        connection_factory: ConnectionFactory = _default_connection,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/") or parts.query:
            raise ProbeError("the base URL must be https://host[:port] with no path")
        if not _HOST_RE.fullmatch(parts.hostname) or parts.username or parts.password:
            raise ProbeError("the base URL host must be a plain host name or address")
        self.host = parts.hostname
        self.port = parts.port or 443
        self.netloc = parts.netloc.lower()
        self._fingerprint = normalize_fingerprint(fingerprint)
        # Verification against the trust store is replaced by the fingerprint comparison below,
        # which runs before any byte of the request is sent.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._ctx = ctx
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._clock = clock
        self._deadline = clock() + deadline_seconds
        self._factory = connection_factory
        self._conn: Any = None
        self.aborted: str = ""
        self.requests_sent = 0

    def __repr__(self) -> str:
        return f"OntapTransport(host={self.host!r}, port={self.port})"

    def _open(self) -> Any:
        conn = self._factory(self.host, self.port, self._ctx, self._connect_timeout)
        try:
            conn.connect()
            der = conn.sock.getpeercert(binary_form=True)
        except (OSError, http.client.HTTPException) as exc:
            conn.close()
            raise TransportFailure(f"could not connect ({type(exc).__name__})") from exc
        seen = hashlib.sha256(der or b"").hexdigest()
        if not hmac.compare_digest(seen, self._fingerprint):
            conn.close()
            self.aborted = "certificate fingerprint mismatch"
            raise FingerprintMismatch("the server certificate does not match the pinned fingerprint; nothing was sent")
        conn.sock.settimeout(self._read_timeout)
        return conn

    def request(self, method: str, path: str) -> Reply:
        """Send one request. Only GET is accepted.

        Raises:
            ProbeError: For any method other than GET, an unsafe path, a passed deadline, an earlier
                abort, a connection failure, or a refused credential.
        """
        if method != "GET":
            raise ProbeError(f"method {method!r} refused: this probe sends GET only")
        if self.aborted:
            raise AuthenticationAbort(f"no request sent: the run stopped earlier ({self.aborted})")
        if not path.startswith("/api/") or ".." in path or any(c in path for c in "\r\n \t"):
            raise ProbeError("path refused: it must start with /api/ and contain no '..' or whitespace")
        if self._clock() > self._deadline:
            raise DeadlineExceeded("the overall deadline passed; no further request is sent")
        if self._conn is None:
            self._conn = self._open()
        try:
            self.requests_sent += 1
            self._conn.request("GET", path, headers=self._headers)
            resp = self._conn.getresponse()
            raw = resp.read()
        except (OSError, socket.timeout, http.client.HTTPException) as exc:
            self._conn.close()
            self._conn = None
            raise TransportFailure(f"request failed ({type(exc).__name__})") from exc
        body: Any = None
        if raw:
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
        code = message = ""
        if resp.status >= 400 and isinstance(body, dict):
            err = body.get("error") or {}
            code = str(err.get("code", ""))
            message = str(err.get("message", ""))
        reply = Reply(resp.status, body if resp.status < 400 else None, code, message)
        logger.debug("GET %s -> %s %s", path.split("?", 1)[0], reply.status, code)
        if is_auth_failure(reply):
            self.aborted = f"credential refused (HTTP 401, code {code or 'none'})"
            self._conn.close()
            self._conn = None
            raise AuthenticationAbort(self.aborted)
        return reply

    def get(self, path: str) -> Reply:
        """Send one GET. See :meth:`request`."""
        return self.request("GET", path)

    def close(self) -> None:
        """Close the connection if one is open."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None


def safe_next(href: Any, netloc: str) -> str | None:
    """Return the next-page path to request, or None when the link must not be followed.

    A link is followed only when it is a string, its path starts with ``/api/``, it carries no
    ``..`` or line break, and, when it names a host, the host is the one already in use.

    Args:
        href: ``_links.next.href`` as returned.
        netloc: ``host[:port]`` of the base URL; empty when the transport has no host (tests).
    """
    if not isinstance(href, str) or not href or ".." in href or any(c in href for c in "\r\n"):
        return None
    parts = urlsplit(href)
    if parts.scheme or parts.netloc:
        if parts.scheme != "https" or parts.netloc.lower() != netloc:
            return None
    if not parts.path.startswith("/api/"):
        return None
    return parts.path + (f"?{parts.query}" if parts.query else "")


def get_collection(transport: Transport, path: str, query: str = "") -> tuple[Reply, list[dict[str, Any]]]:
    """Read every record of a collection, following safe ``_links.next`` links.

    An object endpoint (no ``records`` key) is returned as a one-element list.

    Returns:
        The first non-2xx reply or the last 2xx reply, and the records read so far.
    """
    url = f"{path}?{query}" if query else path
    netloc = str(getattr(transport, "netloc", ""))
    records: list[dict[str, Any]] = []
    reply = Reply(0, None, "", "")
    for _ in range(MAX_PAGES):
        reply = transport.get(url)
        if not 200 <= reply.status < 300:
            return reply, records
        body = reply.body if isinstance(reply.body, dict) else {}
        if "records" in body:
            records.extend(r for r in body.get("records") or [] if isinstance(r, dict))
        else:
            records.append(body)
            return reply, records
        nxt = safe_next(((body.get("_links") or {}).get("next") or {}).get("href"), netloc)
        if nxt is None:
            return reply, records
        url = nxt
    logger.warning("page cap (%d) reached for %s", MAX_PAGES, path)
    return reply, records

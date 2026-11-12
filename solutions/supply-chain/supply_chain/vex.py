"""OpenVEX v0.2.0 parser, printer and exclusion table (pure core, no I/O).

Implements the "2. OpenVEX の扱い" section of the phase 4 design.

* ``parse_openvex`` collects every violation before raising ``VexError``; it
  never returns a partial document (Requirements 11.4, 11.8).
* ``render_openvex`` is deterministic: sorted keys, two-space indent, LF line
  endings, one trailing newline, UTC timestamps ending in ``Z``.
* ``effective_exclusions`` builds the ``(vulnerability id, purl with version)``
  table that lets an approved ``not_affected`` / ``fixed`` statement suppress a
  Finding. ``MAL-`` statements never enter the table (Requirements 7.12, 11.12).

Stricter than the OpenVEX specification (still conforming to it): a
``not_affected`` statement must carry a ``justification`` (the specification
also accepts ``impact_statement`` alone), the document ``version`` must be an
integer of at least 1, and duplicate JSON keys are rejected.

Fields the data model does not hold (``last_updated``, ``status_notes``,
``supplier``, ``action_statement``, ``hashes`` and so on) are ignored when
parsing and are therefore not written back by ``render_openvex``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from supply_chain.models import VexDocument, VexStatement, VexStatus

if TYPE_CHECKING:
    from supply_chain.models import Policy

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
STATUSES: tuple[VexStatus, ...] = ("not_affected", "affected", "fixed", "under_investigation")
JUSTIFICATIONS: tuple[str, ...] = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)
MALICIOUS_PREFIX = "MAL-"
REASON_MALICIOUS = "malicious_package_not_suppressible"
_EXCLUDING_STATUSES = ("not_affected", "fixed")

_RFC3339 = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$")


@dataclass(frozen=True, slots=True)
class VexViolation:
    """One schema violation.

    Attributes:
        location: JSON location such as ``statements[1].justification``;
            ``$`` for a document that is not valid JSON.
        message: What is wrong.
    """

    location: str
    message: str


class VexError(Exception):
    """Raised when an OpenVEX document does not conform; lists every violation."""

    def __init__(self, path: str, violations: tuple[VexViolation, ...]) -> None:
        self.path = path
        self.violations = violations
        lines = [f"{path}: {len(violations)} OpenVEX violation(s)"]
        lines.extend(f"{path}: {v.location}: {v.message}" for v in violations)
        super().__init__("\n".join(lines))


@dataclass(frozen=True, slots=True)
class VexRef:
    """Where an exclusion came from (for the run record)."""

    path: str
    status: VexStatus
    justification: str | None


def _parse_timestamp(value: str) -> datetime:
    """Parses an RFC 3339 timestamp into an aware UTC datetime.

    Digits beyond microseconds are truncated.

    Raises:
        ValueError: If the text is not an RFC 3339 date-time.
    """
    match = _RFC3339.match(value)
    if match is None:
        raise ValueError("not an RFC 3339 date-time")
    year, month, day, hour, minute, second, frac, zone = match.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    if zone in ("Z", "z"):
        tz = UTC
    else:
        sign = -1 if zone[0] == "-" else 1
        offset = timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
        if int(zone[1:3]) > 23 or int(zone[4:6]) > 59:
            raise ValueError("invalid UTC offset")
        tz = timezone(sign * offset)
    try:
        moment = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), micro, tzinfo=tz)
        return moment.astimezone(UTC)
    except OverflowError as exc:
        raise ValueError("date-time out of range") from exc


def _format_timestamp(value: datetime) -> str:
    """Formats an aware datetime as UTC RFC 3339 (``Z``; fraction only if non-zero)."""
    utc = value.astimezone(UTC)
    text = f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}T{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}"
    if utc.microsecond:
        text += f".{utc.microsecond:06d}"
    return text + "Z"


class _Collector:
    """Accumulates violations while a document is validated."""

    def __init__(self) -> None:
        self.items: list[VexViolation] = []

    def add(self, location: str, message: str) -> None:
        self.items.append(VexViolation(location, message))

    def string(self, obj: dict[str, Any], key: str, where: str, *, required: bool) -> str | None:
        """Returns a non-empty string field, recording a violation if it is wrong."""
        loc = f"{where}.{key}" if where else key
        if key not in obj:
            if required:
                self.add(loc, "required field is missing")
            return None
        value = obj[key]
        if not isinstance(value, str) or not value.strip():
            self.add(loc, "must be a non-empty string")
            return None
        return value

    def timestamp(self, obj: dict[str, Any], key: str, where: str, *, required: bool) -> datetime | None:
        """Returns a parsed RFC 3339 timestamp field, recording a violation if it is wrong."""
        loc = f"{where}.{key}" if where else key
        text = self.string(obj, key, where, required=required)
        if text is None:
            return None
        try:
            return _parse_timestamp(text)
        except ValueError as exc:
            self.add(loc, f"{exc}: {text!r}")
            return None


def _statement(c: _Collector, raw: Any, index: int) -> VexStatement | None:  # noqa: ANN401
    """Validates one statement object; returns it only if it raised no violation."""
    where = f"statements[{index}]"
    before = len(c.items)
    if not isinstance(raw, dict):
        c.add(where, "must be an object")
        return None

    vuln_id: str | None = None
    aliases: list[str] = []
    vuln = raw.get("vulnerability")
    if vuln is None:
        c.add(f"{where}.vulnerability", "required field is missing")
    elif not isinstance(vuln, dict):
        c.add(f"{where}.vulnerability", "must be an object")
    else:
        vuln_id = c.string(vuln, "name", f"{where}.vulnerability", required=True)
        raw_aliases = vuln.get("aliases", [])
        if not isinstance(raw_aliases, list):
            c.add(f"{where}.vulnerability.aliases", "must be an array of strings")
        else:
            for k, alias in enumerate(raw_aliases):
                if not isinstance(alias, str) or not alias.strip():
                    c.add(f"{where}.vulnerability.aliases[{k}]", "must be a non-empty string")
                else:
                    aliases.append(alias)

    products: list[str] = []
    raw_products = raw.get("products")
    if raw_products is None:
        c.add(f"{where}.products", "required field is missing")
    elif not isinstance(raw_products, list) or not raw_products:
        c.add(f"{where}.products", "must be a non-empty array")
    else:
        for k, product in enumerate(raw_products):
            ploc = f"{where}.products[{k}]"
            identifier = _product_id(product)
            if identifier is None:
                c.add(ploc, "needs a non-empty '@id' (or identifiers.purl) string")
            else:
                products.append(identifier)

    status = raw.get("status")
    if "status" not in raw:
        c.add(f"{where}.status", "required field is missing")
        status = None
    elif status not in STATUSES:
        c.add(f"{where}.status", f"must be one of {', '.join(STATUSES)}")
        status = None

    justification = raw.get("justification")
    if justification is not None and justification not in JUSTIFICATIONS:
        c.add(f"{where}.justification", f"must be one of {', '.join(JUSTIFICATIONS)}")
        justification = None
    elif status == "not_affected" and justification is None:
        c.add(f"{where}.justification", "required when status is not_affected")

    impact = raw.get("impact_statement")
    if impact is not None and not isinstance(impact, str):
        c.add(f"{where}.impact_statement", "must be a string")
        impact = None

    stamp = c.timestamp(raw, "timestamp", where, required=False)

    if len(c.items) != before or vuln_id is None or status is None:
        return None
    return VexStatement(
        vuln_id=vuln_id,
        aliases=tuple(aliases),
        products=tuple(products),
        status=status,
        justification=justification,
        impact_statement=impact,
        timestamp=stamp,
    )


def _product_id(product: Any) -> str | None:  # noqa: ANN401
    """Returns the purl-or-IRI identifying a product object, if any."""
    if not isinstance(product, dict):
        return None
    ident = product.get("@id")
    if isinstance(ident, str) and ident.strip():
        return ident
    identifiers = product.get("identifiers")
    if isinstance(identifiers, dict):
        purl = identifiers.get("purl")
        if isinstance(purl, str) and purl.strip():
            return purl
    return None


def _document(c: _Collector, data: Any, path: str) -> VexDocument | None:  # noqa: ANN401
    """Validates a decoded document; returns it only if there were no violations."""
    if not isinstance(data, dict):
        c.add("$", "the document must be a JSON object")
        return None

    context = c.string(data, "@context", "", required=True)
    if context is not None and context != OPENVEX_CONTEXT:
        c.add("@context", f"must be {OPENVEX_CONTEXT!r}, got {context!r}")
    doc_id = c.string(data, "@id", "", required=True)
    author = c.string(data, "author", "", required=True)
    role = c.string(data, "role", "", required=False)
    stamp = c.timestamp(data, "timestamp", "", required=True)
    tooling = c.string(data, "tooling", "", required=False)

    version = data.get("version")
    if "version" not in data:
        c.add("version", "required field is missing")
    elif isinstance(version, bool) or not isinstance(version, int) or version < 1:
        c.add("version", "must be an integer of at least 1")

    statements: list[VexStatement] = []
    raw_statements = data.get("statements")
    if "statements" not in data:
        c.add("statements", "required field is missing")
    elif not isinstance(raw_statements, list):
        c.add("statements", "must be an array")
    else:
        for index, raw in enumerate(raw_statements):
            parsed = _statement(c, raw, index)
            if parsed is not None:
                statements.append(parsed)

    if c.items or stamp is None or context is None or doc_id is None or author is None:
        return None
    assert isinstance(version, int)  # noqa: S101 - narrowed by the checks above
    return VexDocument(
        id=doc_id,
        context=context,
        author=author,
        role=role,
        timestamp=stamp,
        version=version,
        tooling=tooling,
        statements=tuple(statements),
        path=path,
    )


def _reject_constant(name: str) -> Any:  # noqa: ANN401
    raise ValueError(f"{name} is not valid JSON")


def parse_openvex(text: str, path: str) -> VexDocument:
    """Parses an OpenVEX v0.2.0 document.

    Every violation is collected before raising, and no partial result is
    returned.

    Args:
        text: The document text (JSON).
        path: Repo-relative path, kept on the result and used in errors.

    Returns:
        The document, with all timestamps converted to UTC.

    Raises:
        VexError: If the text is not valid JSON or does not conform. The
            violations name the location (statement index and field).
    """
    duplicates: list[str] = []

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: dict[str, Any] = {}
        for key, value in items:
            if key in seen:
                duplicates.append(key)
            seen[key] = value
        return seen

    try:
        data = json.loads(text, object_pairs_hook=pairs, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise VexError(path, (VexViolation("$", f"not valid JSON: {exc}"),)) from exc

    collector = _Collector()
    for key in duplicates:
        collector.add("$", f"duplicate JSON key {key!r}")
    doc = _document(collector, data, path)
    if collector.items or doc is None:
        raise VexError(path, tuple(collector.items))
    return doc


def _statement_dict(statement: VexStatement) -> dict[str, Any]:
    out: dict[str, Any] = {
        "vulnerability": {"name": statement.vuln_id},
        "products": [{"@id": purl} for purl in statement.products],
        "status": statement.status,
    }
    if statement.aliases:
        out["vulnerability"]["aliases"] = list(statement.aliases)
    if statement.justification is not None:
        out["justification"] = statement.justification
    if statement.impact_statement is not None:
        out["impact_statement"] = statement.impact_statement
    if statement.timestamp is not None:
        out["timestamp"] = _format_timestamp(statement.timestamp)
    return out


def render_openvex(doc: VexDocument) -> str:
    """Renders a document as OpenVEX v0.2.0 JSON, deterministically.

    Sorted keys, two-space indent, LF, one trailing newline. ``doc.path`` is
    not serialized. The output is validated with the parser's own rules, so
    nothing that ``parse_openvex`` would reject is ever written.

    Args:
        doc: The document to render.

    Returns:
        The JSON text.

    Raises:
        VexError: If ``doc`` cannot be written as a conforming document (for
            example a ``not_affected`` statement without a justification).
    """
    data: dict[str, Any] = {
        "@context": doc.context,
        "@id": doc.id,
        "author": doc.author,
        "timestamp": _format_timestamp(doc.timestamp),
        "version": doc.version,
        "statements": [_statement_dict(s) for s in doc.statements],
    }
    if doc.role is not None:
        data["role"] = doc.role
    if doc.tooling is not None:
        data["tooling"] = doc.tooling
    text = json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    parse_openvex(text, doc.path)  # raises VexError for a non-conforming document
    return text


def _is_malicious(statement: VexStatement) -> bool:
    return any(i.upper().startswith(MALICIOUS_PREFIX) for i in (statement.vuln_id, *statement.aliases))


def effective_exclusions(
    docs: list[VexDocument], policy: Policy
) -> tuple[dict[tuple[str, str], VexRef], list[tuple[str, str]]]:
    """Builds the table of Findings a VEX document may suppress.

    A statement excludes ``(id, purl)`` for its name, each alias and each
    product when its status is ``not_affected`` or ``fixed`` and is listed in
    ``policy.vex_exclude_statuses``. ``affected`` and ``under_investigation``
    never exclude. The purl is compared whole, version included, so a
    statement about another version does not match.

    A statement whose name or alias starts with ``MAL-`` (case-insensitive)
    never enters the table. If its status is ``not_affected`` or ``fixed`` the
    document is reported in ``rejected`` with ``malicious_package_not_suppressible``
    (once per path). The gate treats this as a warning, not a failure.

    When several statements give the same key, the first one wins, with
    documents taken in ``path`` order, so the result does not depend on the
    order of ``docs``.

    Args:
        docs: Documents read from the default branch (already parsed).
        policy: Supplies ``vex_exclude_statuses``.

    Returns:
        ``(exclusions, rejected)``; ``rejected`` is a list of ``(path, reason)``.
    """
    exclusions: dict[tuple[str, str], VexRef] = {}
    rejected: list[tuple[str, str]] = []
    allowed = set(policy.vex_exclude_statuses) & set(_EXCLUDING_STATUSES)
    for doc in sorted(docs, key=lambda d: d.path):
        for statement in doc.statements:
            if _is_malicious(statement):
                entry = (doc.path, REASON_MALICIOUS)
                if statement.status in _EXCLUDING_STATUSES and entry not in rejected:
                    rejected.append(entry)
                continue
            if statement.status not in allowed:
                continue
            ref = VexRef(doc.path, statement.status, statement.justification)
            for vuln in (statement.vuln_id, *statement.aliases):
                for purl in statement.products:
                    exclusions.setdefault((vuln, purl), ref)
    return exclusions, rejected

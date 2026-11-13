"""Opening_Threshold decision (pure).

Decides whether a Finding is eligible for an Issue. The decision reads only
the Finding's identifiers, its CVSS severity, the KEV identifier set and the
Policy's ``OpeningThreshold``. EPSS is not an argument and never influences
the result (Requirement 7.5).

This module performs no I/O.
"""

from __future__ import annotations

from supply_chain.models import Finding, OpeningThreshold

SEVERITY_RANK: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

MALICIOUS_PREFIX = "MAL-"


def _identifiers(finding: Finding) -> tuple[str, ...]:
    return (finding.vuln_id, *finding.aliases)


def is_malicious(finding: Finding) -> bool:
    """Tells whether the Finding is a Malicious_Package_Finding.

    Args:
        finding: The Finding to inspect.

    Returns:
        True iff ``vuln_id`` or any alias starts with ``MAL-`` (OpenSSF
        Malicious Packages, published through OSV).
    """
    return any(i.startswith(MALICIOUS_PREFIX) for i in _identifiers(finding))


def meets_opening_threshold(
    finding: Finding,
    kev_ids: frozenset[str] | None,
    threshold: OpeningThreshold,
) -> bool:
    """Decides whether the Finding satisfies the Opening_Threshold.

    Args:
        finding: The Finding to judge.
        kev_ids: Identifiers listed in KEV, or ``None`` when the KEV feed was
            not obtained in this run (then KEV contributes nothing).
        threshold: The Policy's threshold. ``open_if_malicious`` is always
            true by schema, so malicious Findings always qualify.

    Returns:
        True iff the Finding is malicious, or its CVSS severity is at least
        ``threshold.min_cvss_severity``, or ``threshold.open_if_kev_listed``
        is set and ``vuln_id`` or an alias is in ``kev_ids``. A Finding with
        no severity, no KEV listing and no ``MAL-`` identifier returns False.
    """
    if is_malicious(finding):
        return True
    severity = finding.cvss_severity
    if severity is not None and SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold.min_cvss_severity]:
        return True
    return bool(
        threshold.open_if_kev_listed and kev_ids is not None and any(i in kev_ids for i in _identifiers(finding))
    )

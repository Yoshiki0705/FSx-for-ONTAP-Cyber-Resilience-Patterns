"""Name the two errors of ``kiro-cli`` that end a run with exit code 1 and an empty standard output (task 5.9).

Pure: bytes or text in, a label or ``None`` out. No I/O.

``kiro-cli chat`` ended the same way in two observed cases (2.6; one or two observations each):
the monthly usage limit, and a profile that did not resolve. Both exit with code 1 and write
nothing to standard output, and ``kiro-cli whoami`` exits 0 in both, so neither the exit code
nor the login check tells them apart. Only one line of standard error does.

The match is a **heuristic**. It depends on the wording of ``kiro-cli`` 's own error line, which
the vendor can change without notice; a changed wording makes the match miss (the run is then
``failed`` for ``exit_code_nonzero`` as before, with no label), and a different failure that
quotes the same words would be labelled wrongly. The shape of the usage-limit response is known
from a small number of observations and is not a specification. A label is a note for the
maintainer. It never decides the final state of an item (Property 28: the final state comes from
the observations, not from the text of the report), and nothing here reads standard output,
which holds the model's answer.
"""

from __future__ import annotations

import re
from typing import Final, Literal, TypeAlias

#: The label of the monthly usage limit.
USAGE_LIMIT: Final = "usage_limit"
#: The label of a profile that did not resolve.
PROFILE_REQUIRED: Final = "profile_required"

KiroError: TypeAlias = Literal["usage_limit", "profile_required"]

#: The wording of each error in standard error, folded (see :func:`_fold`): lowercase, one space
#: between words. As observed: ``... The monthly usage limit has been reached`` and
#: ``profileArn is required for this request``.
MARKERS: Final[tuple[tuple[KiroError, str], ...]] = (
    (USAGE_LIMIT, "monthly usage limit has been reached"),
    (PROFILE_REQUIRED, "profilearn is required for this request"),
)

#: ANSI escape sequences: CSI (colour and cursor) and OSC (title, hyperlinks).
_ANSI: Final = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
_SPACES: Final = re.compile(r"\s+")


def _fold(text: str) -> str:
    """Remove ANSI sequences, lowercase, and put one space between words (a line break is a space)."""
    return _SPACES.sub(" ", _ANSI.sub("", text).casefold()).strip()


def classify_stderr(stderr: bytes | str) -> KiroError | None:
    """Return the error that the standard error of a ``kiro-cli`` that failed names, or ``None``.

    Call it on standard error only, and only for a run that exited with a code other than 0.
    It checks neither. Both markers present (it has not been observed) gives the first in
    :data:`MARKERS`.

    Args:
        stderr: The standard error, as the bytes saved or as text. Bytes are decoded as UTF-8
            with replacement characters.

    Returns:
        ``usage_limit``, ``profile_required``, or ``None`` when no marker is in it.
    """
    text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else stderr
    folded = _fold(text)
    for label, marker in MARKERS:
        if marker in folded:
            return label
    return None

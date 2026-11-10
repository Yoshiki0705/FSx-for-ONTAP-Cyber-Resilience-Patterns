"""Scan a Handoff_Prompt body, and what the publish mode pushes, for data that must not leave.

Requirement 28.23: before a Handoff_Prompt is passed to another repository's Kiro, its body
is scanned for the items of Requirements 23.7 and 24.1, and one finding is enough to hold it
back (the runner records the item as ``needs-human``). Before a push, the publish mode scans
the commit messages and the added lines of the diff the same way (design section 20). The
prompt is also sent to the model provider's service, so the scan limits what leaves this
machine as well as what gets published.

Entry points: ``check`` for a body, ``check_publish`` for commit messages and a diff. Both
take the deny terms as an argument: this module reads no file, starts no process and uses no
network. A finding holds where it is and what kind it is, never the matched value, so a
report or a state file that shows findings does not repeat the value.

What is reported (``Kind``):

- ``deny_term``: a term from the caller's list (names of people, personas, speakers and
  customers). Matching rules are in ``check``.
- ``account_id``, ``public_ip``, ``email``, ``home_path``: the detectors of
  ``check_sensitive_patterns.scan_text``, reused as they are. Its account ID placeholder
  ``123456789012``, the documentation addresses and the example mail domains pass.
- ``internal_ip``: an IPv4 address that ``scan_text`` does not report, unless its block
  names no host or network of a real environment (``_names_no_environment``). ``scan_text``
  leaves private addresses to gitleaks, which reads committed files, not a prompt.
- ``case_number``: a support case number (``_CASE_NUMBER``).
- ``sensitive_pattern``: a ``scan_text`` category that this module does not map, so that a
  new detector there is reported here instead of dropped.

The address placeholders ``10.0.x.x`` and ``<management-ip>`` hold no address and pass.

Every detector runs on each line as written and on its NFKC form, so full-width letters,
digits and punctuation, as a Japanese input method types them, are found too.

Not detected here: IPv6 addresses; resource IDs such as ``fs-`` or ``vpc-`` IDs and vendor
ticket IDs, unless the caller lists the real ones as terms; an account ID written with
separators between its digits; octets written with leading zeros, which ``ipaddress`` does
not parse; a term or a case number split across two lines; a case number not introduced by
the word; and the file names in a diff (the runner checks that the changed files are the
declared ones, and the declared ones are in the scanned body).
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Literal, TypeAlias, get_args

import check_sensitive_patterns as csp

#: What a finding is. The module docstring describes each kind.
Kind: TypeAlias = Literal[
    "deny_term",
    "account_id",
    "public_ip",
    "internal_ip",
    "email",
    "home_path",
    "case_number",
    "sensitive_pattern",
]

#: Every kind, in the order the findings of one line are listed.
KINDS: tuple[Kind, ...] = get_args(Kind)

#: The categories of ``scan_text``, by its exact wording, and the kind each becomes. A
#: category missing here (a new detector, or a reworded one) becomes ``sensitive_pattern``.
_SCAN_TEXT_KINDS: dict[str, Kind] = {
    "12-digit number (possible AWS account ID)": "account_id",
    "public IPv4 address": "public_ip",
    "email address": "email",
    "absolute home-directory path": "home_path",
}

#: The RFC 5737 documentation blocks, the project's example addresses. ``is_public_ip`` in
#: ``check_sensitive_patterns`` skips the same three.
_DOCUMENTATION_BLOCKS = tuple(
    ipaddress.IPv4Network(block) for block in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)

#: A support case number: ``case`` or ``ケース``, then any run of punctuation, whitespace and
#: the labels ``番号``, ``number``, ``num``, ``nr``, ``no`` and ``id``, then five or more
#: digits, ignoring case. No word boundary is required before ``case``, so ``showcase``
#: followed by digits is reported too; a missed case number costs more than a held prompt.
_CASE_NUMBER = re.compile(r"(?:case|ケース)(?:[\W_]|番号|number|num|nr|no|id)*[0-9]{5,}", re.IGNORECASE)

#: A two-way hunk header. A count left out means 1.
_HUNK_HEADER = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

#: The one-letter escapes of git's C-style quoting of file names, and the byte of each.
_QUOTE_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}

#: The three octal digits of a byte escaped in git's C-style quoting.
_QUOTE_OCTAL = re.compile(r"[0-3][0-7]{2}")


@dataclass(frozen=True, slots=True)
class Finding:
    """One finding in a text: the line and the kind, never the matched value.

    Attributes:
        line: Line number, from 1, counted as ``str.splitlines`` counts lines (as
            ``scan_text`` does).
        kind: What was found.
    """

    line: int
    kind: Kind


@dataclass(frozen=True, slots=True)
class MessageFinding:
    """One finding in a commit message passed to ``check_publish``.

    Attributes:
        message_index: Position of the message in the sequence passed in, from 0.
        line: Line number in the message, from 1, counted as ``str.splitlines`` counts lines.
        kind: What was found.
    """

    message_index: int
    line: int
    kind: Kind


@dataclass(frozen=True, slots=True)
class DiffFinding:
    """One finding in an added line of the diff passed to ``check_publish``.

    Attributes:
        path: The file name from the ``+++`` line, with git's quoting undone and without the
            ``b/`` prefix.
        line: Line number on the new side of the file, from 1.
        kind: What was found.
    """

    path: str
    line: int
    kind: Kind


#: A finding of ``check_publish``.
PublishFinding: TypeAlias = MessageFinding | DiffFinding


class DiffParseError(ValueError):
    """The diff is not a two-way unified diff whose hunks can be followed to their end.

    Raised instead of returning the findings read so far: a diff that cannot be read to the
    end has not been scanned, so the caller must not publish it. The message names the diff
    line and the reason, never the text of the line.

    Attributes:
        line: Line number in the diff, from 1, where reading stopped.
    """

    def __init__(self, line: int, reason: str) -> None:
        """Build the error.

        Args:
            line: Line number in the diff, from 1.
            reason: What did not fit, without any text taken from the diff.
        """
        super().__init__(f"diff line {line}: {reason}")
        self.line = line


def check(text: str, terms: Iterable[str]) -> list[Finding]:
    """Scan a Handoff_Prompt body.

    A deny term matches a line when the term is a substring of the line after both are
    folded: Unicode case folding (``str.casefold``) and every run of whitespace turned into
    one space, with the ends stripped. The comparison is made on the forms as written and on
    the NFKC forms, so ``ＡＢＣ`` matches ``abc``, and half-width katakana match full-width
    katakana. A term that folds to an empty string is ignored (it would match every line), so
    an empty list of terms leaves the other detectors running alone. A short term also
    matches inside longer words.

    Args:
        text: The body, as ``prompt.render`` produced it.
        terms: Deny terms, read by the caller from its lists. A ``str`` is refused, since its
            characters would each become a term.

    Returns:
        The findings, ordered by line and, within a line, by the order of ``KINDS``; at most
        one per line and kind. Empty when nothing was found.

    Raises:
        TypeError: ``text`` is not a ``str``, ``terms`` is a ``str``, or a term is not a
            ``str``.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    folded_terms = _fold_terms(terms)
    return [Finding(line, kind) for line, kind in _scan_lines(text, folded_terms)]


def check_publish(messages: Sequence[str], diff: str, terms: Iterable[str]) -> list[PublishFinding]:
    """Scan the commit messages and the added lines of a diff before a push.

    Each message is scanned in full, as ``check`` scans a body. In the diff, only the added
    lines are scanned; removed lines and context lines are not. The diff is followed hunk by
    hunk with the line counts of each hunk header, so an added line whose text starts with
    ``++`` (shown as ``+++...``) is scanned too, and ``---`` and ``+++`` count as file headers
    only outside a hunk. Pass the output of ``git diff`` with its default ``a/`` and ``b/``
    prefixes; a binary file has no lines to scan.

    Args:
        messages: The full commit messages, one string per commit.
        diff: A two-way unified diff of the commits.
        terms: Deny terms, as for ``check``.

    Returns:
        The message findings in message order, then the diff findings in diff order; within a
        line, in the order of ``KINDS``.

    Raises:
        TypeError: ``messages`` is a ``str`` or holds a value that is not one, ``diff`` is
            not a ``str``, or ``terms`` is refused as in ``check``.
        DiffParseError: The diff cannot be read to the end (a combined diff, a hunk cut short,
            an added line outside a hunk, or a hunk before any file header).
    """
    if isinstance(messages, str):
        raise TypeError("messages must be a sequence of str, not a str")
    if not isinstance(diff, str):
        raise TypeError("diff must be a str")
    folded_terms = _fold_terms(terms)
    findings: list[PublishFinding] = []
    for index, message in enumerate(messages):
        if not isinstance(message, str):
            raise TypeError("each message must be a str")
        findings.extend(MessageFinding(index, line, kind) for line, kind in _scan_lines(message, folded_terms))
    for path, line, content in _added_lines(diff):
        findings.extend(DiffFinding(path, line, kind) for kind in _line_kinds(content, folded_terms))
    return findings


def _scan_lines(text: str, folded_terms: frozenset[str]) -> Iterator[tuple[int, Kind]]:
    """Yield ``(line number, kind)`` for each line of a text, numbered as ``scan_text`` does."""
    for number, line in enumerate(text.splitlines(), 1):
        for kind in _line_kinds(line, folded_terms):
            yield number, kind


def _line_kinds(line: str, folded_terms: frozenset[str]) -> list[Kind]:
    """List the kinds found in one line, in the order of ``KINDS``.

    Args:
        line: One line, without its line break.
        folded_terms: The output of ``_fold_terms``.

    Returns:
        Each kind found in the line as written or in its NFKC form, once.
    """
    nfkc = unicodedata.normalize("NFKC", line)
    variants = (line,) if nfkc == line else (line, nfkc)
    kinds: set[Kind] = set()
    for variant in variants:
        kinds.update(_SCAN_TEXT_KINDS.get(category, "sensitive_pattern") for _, category in csp.scan_text(variant, []))
        if any(_is_internal_ip(match.group()) for match in csp.IPV4.finditer(variant)):
            kinds.add("internal_ip")
        if _CASE_NUMBER.search(variant):
            kinds.add("case_number")
    if folded_terms:
        folded_line = {_fold(variant) for variant in variants}
        if any(term in form for term in folded_terms for form in folded_line):
            kinds.add("deny_term")
    return sorted(kinds, key=KINDS.index)


def _fold(text: str) -> str:
    """Case-fold a text and turn each run of whitespace into one space, stripping the ends."""
    return " ".join(text.casefold().split())


def _fold_terms(terms: Iterable[str]) -> frozenset[str]:
    """Fold each deny term as written and in NFKC form, dropping forms that fold to nothing.

    Args:
        terms: Deny terms.

    Returns:
        The folded forms of all terms.

    Raises:
        TypeError: ``terms`` is a ``str``, or a term is not a ``str``. The message does not
            repeat the term.
    """
    if isinstance(terms, str):
        raise TypeError("terms must be an iterable of str, not a str")
    folded: set[str] = set()
    for term in terms:
        if not isinstance(term, str):
            raise TypeError("each deny term must be a str")
        folded.update(form for form in (_fold(term), _fold(unicodedata.normalize("NFKC", term))) if form)
    return frozenset(folded)


def _is_internal_ip(dotted: str) -> bool:
    """Whether a dotted quad is an address to report that ``scan_text`` does not report.

    Args:
        dotted: A match of ``check_sensitive_patterns.IPV4``.

    Returns:
        True for a valid address that is not public in the sense of ``is_public_ip`` and is
        not in a block that ``_names_no_environment`` lets pass. False for a public address
        (``scan_text`` reports it), and for a text that is not an address, such as a version
        number with an octet above 255.
    """
    try:
        address = ipaddress.IPv4Address(dotted)
    except ipaddress.AddressValueError:
        return False
    return not csp.is_public_ip(dotted) and not _names_no_environment(address)


def _names_no_environment(address: ipaddress.IPv4Address) -> bool:
    """Whether an address is in a block that names no host or network of a real environment.

    These blocks pass: the RFC 5737 documentation blocks, the "this network" block (RFC 1122,
    which holds the ``0.0.0.0`` of ``0.0.0.0/0`` in security group rules), loopback, and the
    reserved block (RFC 1112) that holds the limited broadcast address and the subnet masks
    of a /4 or longer prefix.
    Every other address that ``scan_text`` does not report is reported: the RFC 1918 blocks;
    the RFC 6598 shared address space; the link-local block (RFC 3927), from which AWS
    Site-to-Site VPN tunnel inside addresses are taken (the instance metadata address is in
    this block too and is reported, so a prompt names that service instead); the RFC 2544
    benchmarking block, from which IPv4-only Amazon FSx for NetApp ONTAP Multi-AZ file systems
    created through the AWS CLI or the API take their endpoint addresses by default; and any
    block not listed here.

    Args:
        address: A valid IPv4 address.

    Returns:
        True when the address passes.
    """
    return (
        any(address in block for block in _DOCUMENTATION_BLOCKS)
        or address.packed[0] == 0
        or address.is_loopback
        or address.is_reserved
    )


def _added_lines(diff: str) -> Iterator[tuple[str, int, str]]:
    """Yield ``(path, new-side line number, text)`` for each added line of a diff.

    The text is split at ``\\n`` only, as git counts lines, so a form feed or a Unicode line
    separator inside a line does not shift the numbering.

    Args:
        diff: A two-way unified diff.

    Yields:
        The file name (as ``DiffFinding.path``), the line number on the new side, and the
        added line without its ``+``.

    Raises:
        DiffParseError: As described in ``check_publish``.
    """
    lines = diff.split("\n")
    if lines[-1] == "":
        lines.pop()  # the line break that ends the last line
    old_path: str | None = None
    new_path: str | None = None
    path = ""
    old_left = new_left = new_line = 0
    for number, raw in enumerate(lines, 1):
        if old_left or new_left:
            tag = raw[:1]
            if tag == "+" and new_left:
                yield path, new_line, raw[1:]
                new_left -= 1
                new_line += 1
            elif tag == "-" and old_left:
                old_left -= 1
            elif tag in (" ", "") and old_left and new_left:
                old_left -= 1
                new_left -= 1
                new_line += 1
            elif tag != "\\":  # "\ No newline at end of file" counts as no line
                raise DiffParseError(number, "a line in a hunk does not fit the line counts of its header")
            continue
        if raw.startswith("@@"):
            header = _HUNK_HEADER.match(raw)
            if header is None:
                raise DiffParseError(number, "not a two-way hunk header")
            known = new_path if new_path is not None else old_path
            if known is None:
                raise DiffParseError(number, "a hunk before any file header")
            path = known
            old_left = 1 if header.group(2) is None else int(header.group(2))
            new_line = int(header.group(3))
            new_left = 1 if header.group(4) is None else int(header.group(4))
        elif raw.startswith("diff "):
            old_path = new_path = None
        elif raw.startswith("--- "):
            old_path, new_path = _header_path(raw[4:], "a/"), None
        elif raw.startswith("+++ "):
            new_path = _header_path(raw[4:], "b/")
        elif raw.startswith("+"):
            raise DiffParseError(number, "an added line outside a hunk")
    if old_left or new_left:
        raise DiffParseError(len(lines), "the diff ends inside a hunk")


def _header_path(label: str, prefix: str) -> str | None:
    """Read the file name of a ``---`` or ``+++`` line.

    Args:
        label: The line after ``--- `` or ``+++ ``.
        prefix: ``a/`` or ``b/``, removed when present.

    Returns:
        The file name, or None for ``/dev/null``. Text after a tab is dropped: git ends a
        name that contains a space with a tab, and a tab inside a name is always quoted.
    """
    label = label.rstrip("\r").partition("\t")[0]
    if label == "/dev/null":
        return None
    if label.startswith('"'):
        label = _unquote(label)
    return label[len(prefix) :] if label.startswith(prefix) else label


def _unquote(label: str) -> str:
    """Undo git's C-style quoting of a file name (``core.quotePath``).

    Args:
        label: A name that starts with a double quote.

    Returns:
        The name, decoded as UTF-8 with bytes that do not decode replaced.
    """
    body = label[1:-1] if len(label) > 1 and label.endswith('"') else label[1:]
    out = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        escaped = body[index + 1 : index + 2]
        octal = body[index + 1 : index + 4]
        if char == "\\" and escaped in _QUOTE_ESCAPES:
            out.append(_QUOTE_ESCAPES[escaped])
            index += 2
        elif char == "\\" and _QUOTE_OCTAL.fullmatch(octal):
            out.append(int(octal, 8))
            index += 4
        else:
            out.extend(char.encode("utf-8"))
            index += 1
    return out.decode("utf-8", errors="replace")

"""Unit tests of ``handoff.kiro_errors`` (task 5.9): the two ``kiro-cli`` errors named from standard error."""

from __future__ import annotations

import pytest
from handoff import kiro_errors

# What 2.6 recorded, with the request ID made up.
USAGE_LIMIT_LINE = (
    "Error: Internal error (code -32603): Encountered an error in the response stream: "
    "The monthly usage limit has been reached"
)
PROFILE_LINE = "profileArn is required for this request"


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (USAGE_LIMIT_LINE + "\n", "usage_limit"),
        (USAGE_LIMIT_LINE + " (request_id: example-request-id)\n", "usage_limit"),
        (PROFILE_LINE + "\n", "profile_required"),
        ("Error: " + PROFILE_LINE, "profile_required"),
    ],
)
def test_the_two_observed_wordings_are_named(stderr: str, expected: str) -> None:
    """The wordings of 2.6, as text and as bytes, with and without a request ID."""
    assert kiro_errors.classify_stderr(stderr) == expected
    assert kiro_errors.classify_stderr(stderr.encode("utf-8")) == expected


@pytest.mark.parametrize(
    "stderr",
    [
        "THE MONTHLY USAGE LIMIT HAS BEEN REACHED",
        "  \t The   monthly usage\r\nlimit has\nbeen   reached \n\n",
        "\x1b[31mError:\x1b[0m The monthly usage limit \x1b[1mhas been\x1b[0m reached",
        "\x1b]8;;https://example.com\x07The monthly usage limit has been reached\x1b]8;;\x07",
        "PROFILEARN is required for this request",
        "profileArn is\n  required for this request\r\n",
    ],
)
def test_case_spaces_line_breaks_and_ansi_do_not_hide_a_wording(stderr: str) -> None:
    """The match is folded: case, runs of white space, line breaks and escape sequences."""
    assert kiro_errors.classify_stderr(stderr) is not None


@pytest.mark.parametrize(
    "stderr",
    [
        "",
        b"",
        "   \n",
        "Error: connection reset by peer",
        "Error: Internal error (code -32603): Encountered an error in the response stream: throttled",
        "the usage limit has been reached",  # not the monthly one
        "profileArn is missing",
        b"\xff\xfe\x80 not text",
    ],
)
def test_other_failures_and_empty_output_name_nothing(stderr: bytes | str) -> None:
    """A failure with other wording, an empty stream and undecodable bytes give ``None``."""
    assert kiro_errors.classify_stderr(stderr) is None


def test_undecodable_bytes_around_a_wording_do_not_hide_it() -> None:
    """Bytes that are not UTF-8 become replacement characters; the wording next to them still matches."""
    payload = b"\xff\xfe " + USAGE_LIMIT_LINE.encode("ascii") + b" \x80\n"
    assert kiro_errors.classify_stderr(payload) == "usage_limit"


def test_the_answer_of_the_model_is_not_this_functions_input() -> None:
    """The function names a stream it is given, so a caller that gives it the answer would be wrong.

    The runner passes standard error only (see ``test_handoff_runner_integration``); here the
    contract is that the two labels and their markers are the whole of what is matched.
    """
    assert [label for label, _ in kiro_errors.MARKERS] == ["usage_limit", "profile_required"]
    assert all(marker == marker.casefold() and "  " not in marker for _, marker in kiro_errors.MARKERS)

"""Tests of the ``vex-validate`` subcommand and its inputs (task 11.22)."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import check_supply_chain as gate
import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURES = gate.FIXTURES_DIR / "vex-validate"


def _run(root: Path) -> tuple[int, str]:
    out = io.StringIO()
    return gate.main(["vex-validate", "--root", str(root)], out=out), out.getvalue()


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("fail-")))
def test_each_failing_input_fails_for_its_stated_reason(case: str) -> None:
    code, kind = (FIXTURES / case / "EXPECT").read_text(encoding="utf-8").splitlines()[0].split()
    got, text = _run(FIXTURES / case)
    assert got == int(code) and f": {kind}:" in text
    other = {k for k in re.findall(r": ([a-z-]+):", text)} - {kind}
    assert not other, f"{case} also reports {other}"


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("pass-")))
def test_each_good_input_passes_having_read_the_input(case: str) -> None:
    code, text = _run(FIXTURES / case)
    assert code == 0 and "scanned 1 file(s), 0 violation(s)" in text


def test_without_an_input_nothing_is_scanned_and_the_gate_succeeds(tmp_path: Path) -> None:
    code, text = _run(tmp_path)
    assert code == 0 and "scanned 0 files" in text


def test_a_broken_input_is_exit_code_2(tmp_path: Path) -> None:
    (tmp_path / ".vex-validate-input.json").write_text("{not json", encoding="utf-8")
    assert _run(tmp_path)[0] == 2
    (tmp_path / ".vex-validate-input.json").write_text("[]", encoding="utf-8")
    assert _run(tmp_path)[0] == 2


def test_the_environment_variable_names_the_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = FIXTURES / "fail-no-approval" / ".vex-validate-input.json"
    monkeypatch.setenv("VEX_VALIDATE_INPUT", str(source))
    code, text = _run(tmp_path)
    assert code == 1 and "approval-missing" in text


def test_the_vex_directory_comes_from_the_policy_file(tmp_path: Path) -> None:
    data = json.loads((FIXTURES / "fail-no-approval" / ".vex-validate-input.json").read_text(encoding="utf-8"))
    data["files"] = ["statements/a.json"]
    (tmp_path / ".vex-validate-input.json").write_text(json.dumps(data), encoding="utf-8")
    assert _run(tmp_path)[0] == 0  # `.vex/` is the default and this change is elsewhere
    policy = tmp_path / "docs" / "agent" / "supply-chain-policy.json"
    policy.parent.mkdir(parents=True)
    policy.write_text(json.dumps({"vex": {"directory": "statements"}}), encoding="utf-8")
    assert _run(tmp_path)[0] == 1


def test_a_second_valid_approval_is_enough_when_the_first_has_no_reason(tmp_path: Path) -> None:
    data = json.loads((FIXTURES / "pass-approved-with-reason" / ".vex-validate-input.json").read_text(encoding="utf-8"))
    data["reviews"].insert(0, {"user": "other", "state": "APPROVED", "commit_id": "headsha1", "body": "lgtm"})
    (tmp_path / ".vex-validate-input.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    assert _run(tmp_path)[0] == 0


def test_the_template_has_the_machine_fields_and_no_field_for_a_person() -> None:
    text = (REPO / ".github" / "PULL_REQUEST_TEMPLATE" / "vex.md").read_text(encoding="utf-8")
    from supply_chain_checks.vex_validate import MACHINE_FIELDS, REASON_HEADING

    body = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    for name in MACHINE_FIELDS:
        assert f"- {name}:" in body
    assert REASON_HEADING not in body  # the reason is written in the review, not here (11.38)


def test_the_workflow_runs_on_edits_and_reviews_with_pinned_actions_and_no_paths_filter() -> None:
    text = (REPO / ".github" / "workflows" / "vex-validate.yml").read_text(encoding="utf-8")
    assert "edited" in text and "pull_request_review:" in text
    assert "paths:" not in text
    assert "persist-credentials: false" in text
    for use in re.findall(r"uses:\s*(\S+)", text):
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", use), use
    assert "github.event.pull_request.title" not in text and "github.event.pull_request.body" not in text

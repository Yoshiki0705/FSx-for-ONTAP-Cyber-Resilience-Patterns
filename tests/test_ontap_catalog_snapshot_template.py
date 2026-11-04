"""Template checks for solutions/ontap-catalog-snapshot, and a coverage check for SAM templates.

The first group reads the template as CloudFormation would: the lockout protections (no retry,
one run at a time, no wildcard resource on the secret) must be there, not only described.
The last test makes sure a SAM template under solutions/ is covered by the lint gates, because the
gates glob one directory level and silently skip anything deeper.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parent.parent
TEMPLATE = ROOT / "solutions" / "ontap-catalog-snapshot" / "template.yaml"


class _Loader(yaml.SafeLoader):
    pass


def _tag(loader: yaml.Loader, suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {("Ref" if suffix == "Ref" else f"Fn::{suffix}"): value}


_Loader.add_multi_constructor("!", _tag)


@pytest.fixture(scope="module")
def tpl() -> dict[str, Any]:
    return yaml.load(TEMPLATE.read_text(), Loader=_Loader)  # noqa: S506 (safe subclass)


def function(tpl: dict[str, Any]) -> dict[str, Any]:
    return tpl["Resources"]["SnapshotFunction"]["Properties"]


def test_the_function_is_never_retried_and_never_run_twice_at_once(tpl: dict[str, Any]) -> None:
    props = function(tpl)
    assert props["EventInvokeConfig"]["MaximumRetryAttempts"] == 0
    assert props["ReservedConcurrentExecutions"] == 1
    rule = tpl["Resources"]["ScheduleRule"]["Properties"]
    assert rule["Targets"][0]["RetryPolicy"]["MaximumRetryAttempts"] == 0


def test_the_function_runs_in_the_vpc_on_arm64(tpl: dict[str, Any]) -> None:
    props = function(tpl)
    assert props["Architectures"] == ["arm64"]
    assert props["Runtime"] == "python3.12"
    assert set(props["VpcConfig"]) == {"SubnetIds", "SecurityGroupIds"}


def test_the_secret_policy_names_exactly_one_secret(tpl: dict[str, Any]) -> None:
    statements = [s for p in function(tpl)["Policies"] if isinstance(p, dict) for s in p["Statement"] if isinstance(s, dict)]
    secret = next(s for s in statements if s.get("Sid") == "ReadTheOneSecret")
    assert secret["Resource"] == {"Ref": "OntapSecretArn"}
    assert set(secret["Action"]) == {"secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"}


def test_no_statement_uses_a_wildcard_action_or_resource(tpl: dict[str, Any]) -> None:
    for p in function(tpl)["Policies"]:
        if not isinstance(p, dict):
            continue
        for s in p["Statement"]:
            if not isinstance(s, dict) or "Effect" not in s:
                continue
            actions = s["Action"] if isinstance(s["Action"], list) else [s["Action"]]
            assert not any(a == "*" or a.endswith(":*") for a in actions), s
            assert s["Resource"] != "*", s


def test_listing_is_limited_to_the_output_prefix(tpl: dict[str, Any]) -> None:
    statements = [s for p in function(tpl)["Policies"] if isinstance(p, dict) for s in p["Statement"] if isinstance(s, dict)]
    listing = next(s for s in statements if s.get("Sid") == "ListOutputPrefix")
    assert listing["Action"] == "s3:ListBucket"
    assert "s3:prefix" in listing["Condition"]["StringLike"], "ListBucket must be limited to the output prefix"


def test_the_schedule_is_switched_by_an_explicit_state_not_by_an_empty_string(tpl: dict[str, Any]) -> None:
    """sam deploy ignores an empty parameter value, which once created a schedule nobody asked for."""
    state = tpl["Parameters"]["ScheduleState"]
    assert state["AllowedValues"] == ["ENABLED", "DISABLED"]
    assert tpl["Conditions"]["HasSchedule"] == {"Fn::Equals": [{"Ref": "ScheduleState"}, "ENABLED"]}
    assert tpl["Parameters"]["ScheduleExpression"].get("MinLength") == 1, "an empty expression must not be accepted"
    assert tpl["Resources"]["ScheduleRule"]["Condition"] == "HasSchedule"
    assert tpl["Resources"]["SchedulePermission"]["Condition"] == "HasSchedule"


def test_the_output_bucket_keeps_history_and_survives_stack_deletion(tpl: dict[str, Any]) -> None:
    bucket = tpl["Resources"]["OutputBucket"]
    assert bucket["DeletionPolicy"] == "Retain" and bucket["UpdateReplacePolicy"] == "Retain"
    props = bucket["Properties"]
    assert props["VersioningConfiguration"]["Status"] == "Enabled"
    assert props["PublicAccessBlockConfiguration"] == dict.fromkeys(
        ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"), True
    )
    assert props["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]["ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"


def test_every_environment_variable_the_handler_reads_is_set_by_the_template(tpl: dict[str, Any]) -> None:
    source = (ROOT / "solutions" / "ontap-catalog-snapshot" / "functions" / "snapshot" / "handler.py").read_text()
    read = set(re.findall(r'os\.environ(?:\.get)?\(?\[?"([A-Z_]+)"', source)) - {"LOG_LEVEL"}
    set_by_template = set(function(tpl)["Environment"]["Variables"])
    assert read <= set_by_template, f"read but never set: {sorted(read - set_by_template)}"


def test_the_handler_directory_holds_only_the_handler() -> None:
    names = {p.name for p in (TEMPLATE.parent / "functions" / "snapshot").iterdir() if p.name != "__pycache__"}
    assert names == {"handler.py"}


def test_the_template_has_no_cfn_lint_findings_at_all() -> None:
    """CI runs cfn-lint with no tolerance, while `make lint` accepts exit codes up to 12 for the older templates.

    A warning here passes `make test` and still fails the pull request, so this test asks for exit code 0.
    """
    import shutil
    import subprocess
    import sys

    exe = shutil.which("cfn-lint") or str(Path(sys.executable).parent / "cfn-lint")
    if not Path(exe).exists():
        pytest.skip("cfn-lint is not installed")
    done = subprocess.run([exe, str(TEMPLATE)], capture_output=True, text=True, cwd=ROOT)  # noqa: S603
    assert done.returncode == 0, done.stdout + done.stderr


def test_every_sam_template_under_solutions_is_covered_by_the_lint_gates() -> None:
    """Makefile and CI must lint solutions/*/template.yaml, or a new template passes unchecked."""
    found = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "solutions").glob("*/template.yaml"))
    assert found, "expected at least the catalog snapshot template"
    makefile = (ROOT / "Makefile").read_text()
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "solutions/*/template.yaml" in makefile, "Makefile lint/test must include solutions/*/template.yaml"
    assert "solutions/*/template.yaml" in ci, "CI must lint solutions/*/template.yaml"

"""Every FSx for ONTAP file system a template creates is encrypted with a customer managed key.

Backups of a file system encrypted with the AWS managed key are not copied to an AWS Backup
logically air-gapped vault [E-009] (a manual copy job failed with KMS_KEY_ERROR [E-060]), and the key
of an existing file system cannot be swapped in place. The check therefore runs on the templates,
before anything is created.

The template set is the cfn-lint scope of the Makefile ``lint`` target, read at run time with the
helpers of ``tests/test_cfn_guard_coverage.py`` (which also proves that scope covers every template
on disk). No list of templates is written here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.test_cfn_guard_coverage import ROOT, _expand, makefile_lint_patterns

AWS_MANAGED = re.compile(r"(^|[:/])alias/aws/")


class CfnLoader(yaml.SafeLoader):
    """SafeLoader that turns CloudFormation short-form tags into their long form."""


def _construct(loader: CfnLoader, suffix: str, node: yaml.Node) -> dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    if suffix == "Ref":
        return {"Ref": value}
    if suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
    return {f"Fn::{suffix}": value}


CfnLoader.add_multi_constructor("!", _construct)


def load_template(path: Path) -> dict[str, Any]:
    """Parse one CloudFormation or SAM template."""
    return yaml.load(path.read_text(encoding="utf-8"), Loader=CfnLoader) or {}  # noqa: S506 - SafeLoader subclass


def _key_problems(value: Any, template: dict[str, Any]) -> list[str]:
    """Why ``value`` (a KmsKeyId) may resolve to no key or to an AWS managed key; empty when fine."""
    resources = template.get("Resources") or {}
    params = template.get("Parameters") or {}
    if value is None:
        return ["KmsKeyId is absent, so FSx uses the AWS managed key"]
    if isinstance(value, str):
        return [f"KmsKeyId {value!r} is an AWS managed key"] if AWS_MANAGED.search(value) else []
    if isinstance(value, dict) and "Ref" in value:
        ref = value["Ref"]
        if ref == "AWS::NoValue":
            return ["KmsKeyId resolves to AWS::NoValue (absent)"]
        if ref in params:
            default = params[ref].get("Default")
            if default in (None, ""):
                return [] if params[ref].get("MinLength") else [f"parameter {ref} may be empty"]
            return _key_problems(str(default), template)
        if (resources.get(ref) or {}).get("Type") == "AWS::KMS::Key":
            return []
        return [f"KmsKeyId Ref {ref} is not a KMS key resource or parameter"]
    if isinstance(value, dict) and "Fn::GetAtt" in value:
        target = value["Fn::GetAtt"][0]
        return (
            []
            if (resources.get(target) or {}).get("Type") == "AWS::KMS::Key"
            else [f"GetAtt {target} is not AWS::KMS::Key"]
        )
    if isinstance(value, dict) and "Fn::If" in value:
        _, yes, no = value["Fn::If"]
        return _key_problems(yes, template) + _key_problems(no, template)
    if isinstance(value, dict) and ("Fn::Sub" in value or "Fn::ImportValue" in value):
        text = value.get("Fn::Sub")
        text = text[0] if isinstance(text, list) else text
        return (
            [f"KmsKeyId {text!r} is an AWS managed key"] if isinstance(text, str) and AWS_MANAGED.search(text) else []
        )
    return [f"KmsKeyId form not understood: {value!r}"]


def ontap_key_problems(template: dict[str, Any]) -> dict[str, list[str]]:
    """Per ``AWS::FSx::FileSystem`` of type ONTAP: the problems with its KmsKeyId."""
    out: dict[str, list[str]] = {}
    for name, res in (template.get("Resources") or {}).items():
        if not isinstance(res, dict) or res.get("Type") != "AWS::FSx::FileSystem":
            continue
        props = res.get("Properties") or {}
        if props.get("FileSystemType") != "ONTAP":
            continue
        out[name] = _key_problems(props.get("KmsKeyId"), template)
    return out


def template_scope() -> list[Path]:
    """Templates in the Makefile ``lint`` scope."""
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return [ROOT / p for p in sorted(_expand(ROOT, makefile_lint_patterns(text, "lint")))]


SCOPE = template_scope()


def test_scope_is_not_empty_and_has_an_ontap_file_system() -> None:
    assert SCOPE
    assert any(
        ontap_key_problems(load_template(p)) for p in SCOPE
    ), "no ONTAP file system found: the check would be vacuous"


@pytest.mark.parametrize("path", SCOPE, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_every_ontap_file_system_uses_a_customer_managed_key(path: Path) -> None:
    problems = {k: v for k, v in ontap_key_problems(load_template(path)).items() if v}
    assert not problems, f"{path.relative_to(ROOT)}: {problems}"


NEGATIVE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  KeyArn:
    Type: String
    Default: alias/aws/fsx
Conditions:
  Multi: !Equals [a, b]
Resources:
  NoKey:
    Type: AWS::FSx::FileSystem
    Properties:
      FileSystemType: ONTAP
      SubnetIds: [!Ref 'AWS::NoValue']
  ManagedAlias:
    Type: AWS::FSx::FileSystem
    Properties:
      FileSystemType: ONTAP
      KmsKeyId: alias/aws/fsx
  ManagedAliasArn:
    Type: AWS::FSx::FileSystem
    Properties:
      FileSystemType: ONTAP
      KmsKeyId: !Sub 'arn:${AWS::Partition}:kms:${AWS::Region}:${AWS::AccountId}:alias/aws/fsx'
  ParamDefault:
    Type: AWS::FSx::FileSystem
    Properties:
      FileSystemType: ONTAP
      KmsKeyId: !Ref KeyArn
  OneBranchMissing:
    Type: AWS::FSx::FileSystem
    Properties:
      FileSystemType: ONTAP
      KmsKeyId: !If [Multi, !GetAtt Key.Arn, !Ref 'AWS::NoValue']
  Key:
    Type: AWS::KMS::Key
    Properties: {}
  Good:
    Type: AWS::FSx::FileSystem
    Properties:
      FileSystemType: ONTAP
      KmsKeyId: !GetAtt Key.Arn
  Lustre:
    Type: AWS::FSx::FileSystem
    Properties:
      FileSystemType: LUSTRE
"""


def test_negative_fixture_fails_for_each_bad_form() -> None:
    problems = ontap_key_problems(yaml.load(NEGATIVE, Loader=CfnLoader))  # noqa: S506
    assert set(problems) == {"NoKey", "ManagedAlias", "ManagedAliasArn", "ParamDefault", "OneBranchMissing", "Good"}
    for name in ("NoKey", "ManagedAlias", "ManagedAliasArn", "ParamDefault", "OneBranchMissing"):
        assert problems[name], f"{name} should fail"
    assert problems["Good"] == []

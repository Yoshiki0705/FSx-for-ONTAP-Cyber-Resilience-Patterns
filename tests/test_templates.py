"""CloudFormation template validation tests.

Uses cfn-lint programmatic API to validate all templates in the templates/ directory.
Handles CloudFormation intrinsic functions (!Ref, !Sub, etc.) with a custom YAML loader.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
PARAMETERS_DIR = Path(__file__).parent.parent / "parameters"


# Custom YAML loader that handles CloudFormation intrinsic functions
class CfnLoader(yaml.SafeLoader):
    """YAML loader that handles CloudFormation intrinsic function tags."""

    pass


def _cfn_tag_constructor(loader: yaml.Loader, tag_suffix: str, node: yaml.Node) -> dict:
    """Construct CloudFormation intrinsic functions as dicts."""
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    elif isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node)}
    elif isinstance(node, yaml.MappingNode):
        return {tag_suffix: loader.construct_mapping(node)}
    return {tag_suffix: None}


# Register all CloudFormation intrinsic functions
_cfn_tags = [
    "!Ref",
    "!Sub",
    "!GetAtt",
    "!Select",
    "!Split",
    "!Join",
    "!FindInMap",
    "!If",
    "!Equals",
    "!And",
    "!Or",
    "!Not",
    "!Condition",
    "!ImportValue",
    "!Base64",
    "!Cidr",
    "!GetAZs",
    "!Transform",
]

for tag in _cfn_tags:
    CfnLoader.add_multi_constructor(
        tag,
        lambda loader, suffix, node: _cfn_tag_constructor(loader, suffix, node),
    )


def get_template_files() -> list[Path]:
    """Discover all YAML templates."""
    return sorted(TEMPLATES_DIR.glob("*.yaml"))


def load_yaml(path: Path) -> dict:
    """Load a CloudFormation YAML template handling intrinsic functions."""
    with open(path) as f:
        return yaml.load(f, Loader=CfnLoader)  # noqa: S506


class TestTemplateStructure:
    """Validate basic CloudFormation template structure."""

    @pytest.fixture(params=get_template_files(), ids=lambda p: p.name)
    def template(self, request: pytest.FixtureRequest) -> dict:
        return load_yaml(request.param)

    def test_has_aws_template_format_version(self, template: dict) -> None:
        """Every template must declare AWSTemplateFormatVersion."""
        assert "AWSTemplateFormatVersion" in template
        assert template["AWSTemplateFormatVersion"] == "2010-09-09"

    def test_has_description(self, template: dict) -> None:
        """Every template must have a Description."""
        assert "Description" in template
        assert len(template["Description"]) > 10

    def test_has_resources(self, template: dict) -> None:
        """Every template must define at least one resource."""
        assert "Resources" in template
        assert len(template["Resources"]) > 0


class TestNetworkTemplate:
    """Specific assertions for the network template."""

    @pytest.fixture
    def template(self) -> dict:
        return load_yaml(TEMPLATES_DIR / "network.yaml")

    def test_vpc_exists(self, template: dict) -> None:
        """Network template must define a VPC."""
        resources = template["Resources"]
        vpc_resources = [k for k, v in resources.items() if v["Type"] == "AWS::EC2::VPC"]
        assert len(vpc_resources) == 1

    def test_subnets_multi_az(self, template: dict) -> None:
        """Network template must have subnets in 2 AZs (6 always-on + 1 conditional)."""
        resources = template["Resources"]
        subnets = [k for k, v in resources.items() if v["Type"] == "AWS::EC2::Subnet"]
        # 6 always-on: 2 FSx + 2 Security + 2 Compute
        # 1 conditional: SubnetPublic1 (NAT Gateway)
        assert len(subnets) >= 6

    def test_security_groups_exist(self, template: dict) -> None:
        """Network template must define required security groups."""
        resources = template["Resources"]
        sgs = [k for k, v in resources.items() if v["Type"] == "AWS::EC2::SecurityGroup"]
        # sg-fsx, sg-client, sg-vscan, sg-deep-instinct, sg-lambda, sg-vpc-endpoints = 6
        assert len(sgs) >= 6

    def test_sg_client_exists(self, template: dict) -> None:
        """Network template must define a client access security group."""
        resources = template["Resources"]
        assert "SgClient" in resources
        assert resources["SgClient"]["Type"] == "AWS::EC2::SecurityGroup"

    def test_vpc_endpoints_exist(self, template: dict) -> None:
        """Network template must define VPC endpoints."""
        resources = template["Resources"]
        endpoints = [k for k, v in resources.items() if v["Type"] == "AWS::EC2::VPCEndpoint"]
        # S3 Gateway + SQS + SecretsManager + KMS + STS = 5
        assert len(endpoints) == 5

    def test_nat_gateway_is_conditional(self, template: dict) -> None:
        """NAT Gateway must be conditional on EnableNatGateway parameter."""
        resources = template["Resources"]
        assert "NatGateway" in resources
        assert resources["NatGateway"].get("Condition") == "CreateNatGateway"

    def test_conditions_defined(self, template: dict) -> None:
        """Template must define environment-based conditions."""
        conditions = template.get("Conditions", {})
        assert "CreateNatGateway" in conditions

    def test_fsx_sg_has_smb_ingress(self, template: dict) -> None:
        """FSx SG must allow SMB (445) from client SG."""
        resources = template["Resources"]
        assert "SgFsxIngressSmbFromClient" in resources
        rule = resources["SgFsxIngressSmbFromClient"]["Properties"]
        assert rule["FromPort"] == 445
        assert rule["ToPort"] == 445

    def test_fsx_sg_has_nfs_ingress(self, template: dict) -> None:
        """FSx SG must allow NFS TCP (2049) from client SG."""
        resources = template["Resources"]
        assert "SgFsxIngressNfsTcpFromClient" in resources
        rule = resources["SgFsxIngressNfsTcpFromClient"]["Properties"]
        assert rule["FromPort"] == 2049
        assert rule["ToPort"] == 2049

    def test_scanners_have_nfs_egress_to_fsx(self, template: dict) -> None:
        """Scanner SGs must have NFS egress to FSx (for file retrieval)."""
        resources = template["Resources"]
        assert "SgVscanEgressNfsToFsx" in resources
        assert "SgDiEgressNfsToFsx" in resources

    def test_exports_defined(self, template: dict) -> None:
        """Network template must export VPC ID, subnet IDs, and SG IDs."""
        outputs = template.get("Outputs", {})
        assert "VpcId" in outputs
        assert "VpcCidrBlock" in outputs
        assert "SubnetFsx1Id" in outputs
        assert "SubnetFsx2Id" in outputs
        assert "SgFsxId" in outputs
        assert "SgClientId" in outputs
        assert "SgLambdaId" in outputs
        assert "SgVscanId" in outputs
        assert "SgDeepInstinctId" in outputs

    def test_no_public_subnets_always_on(self, template: dict) -> None:
        """Non-conditional subnets must not have MapPublicIpOnLaunch=true."""
        resources = template["Resources"]
        for name, resource in resources.items():
            if resource["Type"] == "AWS::EC2::Subnet":
                # Skip conditional subnets (NAT)
                if resource.get("Condition"):
                    continue
                props = resource.get("Properties", {})
                assert props.get("MapPublicIpOnLaunch", False) is False, f"{name} must not assign public IPs"

    def test_all_resources_tagged(self, template: dict) -> None:
        """All taggable resources should have at minimum a Name tag."""
        resources = template["Resources"]
        taggable_types = {
            "AWS::EC2::VPC",
            "AWS::EC2::Subnet",
            "AWS::EC2::SecurityGroup",
            "AWS::EC2::RouteTable",
        }
        for name, resource in resources.items():
            if resource["Type"] in taggable_types:
                props = resource.get("Properties", {})
                tags = props.get("Tags", [])
                tag_keys = [t["Key"] for t in tags]
                assert "Name" in tag_keys, f"{name} ({resource['Type']}) must have a Name tag"

    def test_enable_nat_gateway_parameter(self, template: dict) -> None:
        """Template must have EnableNatGateway parameter with default false."""
        params = template.get("Parameters", {})
        assert "EnableNatGateway" in params
        assert params["EnableNatGateway"]["Default"] == "false"

    def test_client_cidr_parameter(self, template: dict) -> None:
        """Template must have ClientCidr parameter."""
        params = template.get("Parameters", {})
        assert "ClientCidr" in params


class TestParameterFiles:
    """Validate parameter file structure."""

    def test_dev_parameters_valid_json(self) -> None:
        """dev.json must be valid JSON."""
        path = PARAMETERS_DIR / "dev.json"
        with open(path) as f:
            params = json.load(f)
        assert isinstance(params, list)
        assert len(params) > 0

    def test_dev_parameters_have_keys(self) -> None:
        """Each parameter entry must have ParameterKey and ParameterValue."""
        path = PARAMETERS_DIR / "dev.json"
        with open(path) as f:
            params = json.load(f)
        for param in params:
            assert "ParameterKey" in param
            assert "ParameterValue" in param

    def test_dev_environment_is_dev(self) -> None:
        """dev.json Environment must be 'dev'."""
        path = PARAMETERS_DIR / "dev.json"
        with open(path) as f:
            params = json.load(f)
        env_param = next((p for p in params if p["ParameterKey"] == "Environment"), None)
        assert env_param is not None
        assert env_param["ParameterValue"] == "dev"


class TestLambdaReservedConcurrency:
    """Event-triggered Lambdas outside event-driven.yaml must cap their concurrency (CKV_AWS_115)."""

    def test_security_hub_publisher_concurrency_is_a_parameter(self) -> None:
        tpl = load_yaml(TEMPLATES_DIR / "siem-integration.yaml")
        param = tpl["Parameters"]["SecurityHubPublisherReservedConcurrency"]
        assert param["Type"] == "Number"
        assert param["Default"] == 10
        assert param["MinValue"] == 1
        lam = tpl["Resources"]["SecurityHubPublisherLambda"]
        # CfnLoader keeps only the tag payload, so compare the referenced name.
        ref = lam["Properties"]["ReservedConcurrentExecutions"]
        assert list(ref.values()) == ["SecurityHubPublisherReservedConcurrency"]


def _values(node: object) -> list:
    """Return the payload of a CfnLoader-parsed intrinsic function (it keeps only the payload)."""
    assert isinstance(node, dict)
    return list(node.values())


class TestAsyncLambdaDeadLetterQueue:
    """EventBridge-invoked Lambdas must send failed events to their own SQS queue (CKV_AWS_116)."""

    CASES = [
        (
            "siem-integration.yaml",
            "SecurityHubPublisherLambda",
            "SecurityHubPublisherRole",
            "SecurityHubPublisherDlq",
            "SecurityHubPublisherDlqAlarm",
        ),
    ]

    @pytest.mark.parametrize(("file", "fn", "role", "queue", "alarm"), CASES)
    def test_dead_letter_target_is_the_queue(self, file: str, fn: str, role: str, queue: str, alarm: str) -> None:
        res = load_yaml(TEMPLATES_DIR / file)["Resources"]
        assert _values(res[fn]["Properties"]["DeadLetterConfig"]["TargetArn"]) == [f"{queue}.Arn"]
        assert res[queue]["Type"] == "AWS::SQS::Queue"
        props = res[queue]["Properties"]
        assert props["MessageRetentionPeriod"] == 1209600
        assert props["KmsMasterKeyId"] == "alias/aws/sqs"

    @pytest.mark.parametrize(("file", "fn", "role", "queue", "alarm"), CASES)
    def test_role_can_send_only_to_the_queue(self, file: str, fn: str, role: str, queue: str, alarm: str) -> None:
        res = load_yaml(TEMPLATES_DIR / file)["Resources"]
        statements = [
            st
            for policy in res[role]["Properties"]["Policies"]
            for st in policy["PolicyDocument"]["Statement"]
            if "sqs:SendMessage" in ([st["Action"]] if isinstance(st["Action"], str) else st["Action"])
        ]
        assert len(statements) == 1
        assert _values(statements[0]["Resource"]) == [f"{queue}.Arn"]

    @pytest.mark.parametrize(("file", "fn", "role", "queue", "alarm"), CASES)
    def test_queue_has_depth_alarm(self, file: str, fn: str, role: str, queue: str, alarm: str) -> None:
        props = load_yaml(TEMPLATES_DIR / file)["Resources"][alarm]["Properties"]
        assert props["MetricName"] == "ApproximateNumberOfMessagesVisible"
        assert _values(props["Dimensions"][0]["Value"]) == [f"{queue}.QueueName"]
        assert _values(props["AlarmActions"][0]) == ["SecurityAlertTopicArn"]


class TestSqsSourcedLambdaDlqSkip:
    """CKV_AWS_116 is skipped only for the two Lambdas that no asynchronous invocation reaches.

    EventTransformerLambda also skips CKV_AWS_117: it calls only the EventBridge public API.
    """

    def test_skip_only_on_event_transformer_and_quarantine(self) -> None:
        res = load_yaml(TEMPLATES_DIR / "event-driven.yaml")["Resources"]
        skipped = {
            n: [s["id"] for s in r["Metadata"]["checkov"]["skip"]]
            for n, r in res.items()
            if r.get("Metadata", {}).get("checkov", {}).get("skip")
        }
        assert skipped == {
            "EventTransformerLambda": ["CKV_AWS_116", "CKV_AWS_117"],
            "QuarantineLambda": ["CKV_AWS_116"],
        }

    def test_quarantine_has_no_event_source_mapping(self) -> None:
        res = load_yaml(TEMPLATES_DIR / "event-driven.yaml")["Resources"]
        for r in res.values():
            if r["Type"] == "AWS::Lambda::EventSourceMapping":
                assert _values(r["Properties"]["FunctionName"]) != ["QuarantineLambda"]

    def test_event_transformer_mappings_use_queues_with_redrive(self) -> None:
        res = load_yaml(TEMPLATES_DIR / "event-driven.yaml")["Resources"]
        mappings = [
            r["Properties"]
            for r in res.values()
            if r["Type"] == "AWS::Lambda::EventSourceMapping"
            # the mappings invoke the "live" alias (EventTransformerLambda.Alias) since the canary
            and _values(r["Properties"]["FunctionName"])
            in (["EventTransformerLambda"], ["EventTransformerLambda.Alias"])
        ]
        assert len(mappings) == 2
        for m in mappings:
            queue = _values(m["EventSourceArn"])[0].split(".")[0]
            assert "RedrivePolicy" in res[queue]["Properties"]


# (template, resource logical ID, resource property, parameter)
OPTIONAL_KMS_BINDINGS = [
    ("network.yaml", "FlowLogLogGroup", "KmsKeyId", "LogGroupKmsKeyArn"),
    ("event-driven.yaml", "StepFunctionsLogGroup", "KmsKeyId", "LogGroupKmsKeyArn"),
    ("event-driven.yaml", "QuarantineLambda", "KmsKeyArn", "LambdaEnvKmsKeyArn"),
    ("event-driven.yaml", "EventTransformerLambda", "KmsKeyArn", "LambdaEnvKmsKeyArn"),
    ("siem-integration.yaml", "SecurityHubPublisherLambda", "KmsKeyArn", "LambdaEnvKmsKeyArn"),
]
# main.yaml nests only these templates; the others are deployed as standalone stacks
NESTED_IN_MAIN = {"network.yaml", "event-driven.yaml"}


class _TaggedLoader(yaml.SafeLoader):
    """Keeps each short-form tag as a one-key dict (``!Ref X`` -> ``{"Ref": "X"}``)."""


_TaggedLoader.add_multi_constructor("!", _cfn_tag_constructor)


def _load_tagged(name: str) -> dict:
    with open(TEMPLATES_DIR / name) as f:
        return yaml.load(f, Loader=_TaggedLoader)  # noqa: S506


class TestOptionalKmsKeys:
    """Customer managed keys are opt-in: empty default keeps the default encryption."""

    @pytest.mark.parametrize(("name", "resource", "prop", "param"), OPTIONAL_KMS_BINDINGS)
    def test_key_is_optional_and_wired(self, name: str, resource: str, prop: str, param: str) -> None:
        template = _load_tagged(name)
        assert template["Parameters"][param]["Default"] == ""
        value = template["Resources"][resource]["Properties"][prop]
        condition, if_set, if_unset = value["If"]
        assert template["Conditions"][condition] == {"Not": [{"Equals": [{"Ref": param}, ""]}]}
        assert if_set == {"Ref": param}
        assert if_unset == {"Ref": "AWS::NoValue"}

    @pytest.mark.parametrize(
        ("stack", "param"),
        sorted({(n.split(".")[0], p) for n, _, _, p in OPTIONAL_KMS_BINDINGS if n in NESTED_IN_MAIN}),
    )
    def test_root_stack_passes_key_to_nested_stack(self, stack: str, param: str) -> None:
        main = _load_tagged("main.yaml")
        assert param in main["Parameters"]
        nested = [r for r in main["Resources"].values() if stack in str(r["Properties"]["TemplateURL"])]
        assert nested and nested[0]["Properties"]["Parameters"][param] == {"Ref": param}

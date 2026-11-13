"""CloudFormation template validation tests.

Uses cfn-lint programmatic API to validate all templates in the templates/ directory.
Handles CloudFormation intrinsic functions (!Ref, !Sub, etc.) with a custom YAML loader.
"""

from __future__ import annotations

import json
import re
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
            # Encrypted with SSE-SQS, which CKV_AWS_27 does not recognize.
            "ApprovalWebhookDlq": ["CKV_AWS_27"],
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
            and _values(r["Properties"]["FunctionName"]) == ["EventTransformerLambda"]
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


class TestAlertTopicDelivery:
    """The security alert topic must accept alarms and EventBridge rules and stay encrypted.

    A CloudWatch alarm cannot notify a topic encrypted with the AWS managed key aws/sns,
    and the default topic policy lets no AWS service publish.
    """

    SERVICES = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]

    @pytest.fixture(scope="class")
    def template(self) -> dict:
        return _load_tagged("event-driven.yaml")

    @staticmethod
    def _statement(policy: dict, sid: str) -> dict:
        return next(s for s in policy["Statement"] if s["Sid"] == sid)

    def test_topic_uses_the_customer_managed_key(self, template: dict) -> None:
        topic = template["Resources"]["SecurityAlertTopic"]["Properties"]
        assert topic["KmsMasterKeyId"] == {"GetAtt": "AlertTopicKey.Arn"}

    def test_key_rotates_and_lets_alarms_and_rules_publish(self, template: dict) -> None:
        key = template["Resources"]["AlertTopicKey"]["Properties"]
        assert key["EnableKeyRotation"] is True
        statement = self._statement(key["KeyPolicy"], "AllowAlarmsAndRulesToPublish")
        assert statement["Principal"]["Service"] == self.SERVICES
        assert statement["Action"] == ["kms:Decrypt", "kms:GenerateDataKey*"]
        assert statement["Condition"] == {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}}
        # No wildcard principal: only the account root administers the key.
        assert self._statement(key["KeyPolicy"], "EnableAccountAdministration")["Principal"]["AWS"]["Sub"].endswith(
            ":root"
        )

    def test_topic_policy_lets_alarms_and_rules_publish(self, template: dict) -> None:
        policy = template["Resources"]["SecurityAlertTopicPolicy"]["Properties"]
        assert policy["Topics"] == [{"Ref": "SecurityAlertTopic"}]
        statement = self._statement(policy["PolicyDocument"], "AllowAlarmsAndRulesToPublish")
        assert statement["Principal"]["Service"] == self.SERVICES
        assert statement["Action"] == "sns:Publish"
        assert statement["Resource"] == {"Ref": "SecurityAlertTopic"}
        assert statement["Condition"] == {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}}

    def test_state_machine_role_can_use_the_key(self, template: dict) -> None:
        policy = template["Resources"]["StepFunctionsExecutionRole"]["Properties"]["Policies"][0]["PolicyDocument"]
        grants = [s for s in policy["Statement"] if s["Action"] == ["kms:GenerateDataKey", "kms:Decrypt"]]
        assert len(grants) == 1
        # The role holds exactly the keys of the two topics it publishes to.
        assert grants[0]["Resource"] == [{"GetAtt": "AlertTopicKey.Arn"}, {"GetAtt": "AlertFallbackTopicKey.Arn"}]

    def test_compliance_role_can_use_the_key_only_through_sns(self) -> None:
        siem = _load_tagged("siem-integration.yaml")
        policy = siem["Resources"]["ComplianceCollectorRole"]["Properties"]["Policies"][0]["PolicyDocument"]
        grants = [s for s in policy["Statement"] if "kms:Decrypt" in s["Action"]]
        assert len(grants) == 1
        assert sorted(grants[0]["Action"]) == ["kms:Decrypt", "kms:GenerateDataKey"]
        assert grants[0]["Condition"] == {
            "StringEquals": {"kms:ViaService": {"Sub": "sns.${AWS::Region}.amazonaws.com"}}
        }

    def test_key_arn_is_exported_for_other_publishers(self, template: dict) -> None:
        output = template["Outputs"]["AlertTopicKeyArn"]
        assert output["Value"] == {"GetAtt": "AlertTopicKey.Arn"}
        assert "Export" in output

    def test_no_alarm_notifies_a_topic_encrypted_with_the_aws_managed_key(self) -> None:
        for path in sorted(TEMPLATES_DIR.glob("*.yaml")):
            resources = _load_tagged(path.name).get("Resources", {})
            aws_managed = {
                name
                for name, r in resources.items()
                if r["Type"] == "AWS::SNS::Topic" and r["Properties"].get("KmsMasterKeyId") == "alias/aws/sns"
            }
            for name, r in resources.items():
                if r["Type"] != "AWS::CloudWatch::Alarm":
                    continue
                for action in r["Properties"].get("AlarmActions", []):
                    target = action.get("Ref") if isinstance(action, dict) else None
                    assert target not in aws_managed, f"{path.name}: {name} notifies {target}, encrypted with aws/sns"


class TestQuarantineExecutionsFailedAlarm:
    """A failed quarantine execution must raise an alarm that reaches the alert topic."""

    @pytest.fixture(scope="class")
    def alarm(self) -> dict:
        return _load_tagged("event-driven.yaml")["Resources"]["QuarantineExecutionsFailedAlarm"]["Properties"]

    def test_alarm_counts_failed_executions_of_the_quarantine_state_machine(self, alarm: dict) -> None:
        assert alarm["Namespace"] == "AWS/States"
        assert alarm["MetricName"] == "ExecutionsFailed"
        # Ref of a state machine returns its ARN, which is the metric dimension value.
        assert alarm["Dimensions"] == [{"Name": "StateMachineArn", "Value": {"Ref": "QuarantineStateMachine"}}]

    def test_one_failed_execution_in_five_minutes_raises_the_alarm(self, alarm: dict) -> None:
        assert alarm["Statistic"] == "Sum"
        assert alarm["Period"] == 300
        assert alarm["EvaluationPeriods"] == 1
        assert alarm["Threshold"] == 1
        assert alarm["ComparisonOperator"] == "GreaterThanOrEqualToThreshold"
        # No failed execution publishes no datapoint, which is the healthy state.
        assert alarm["TreatMissingData"] == "notBreaching"

    def test_alarm_notifies_the_alert_topic(self, alarm: dict) -> None:
        assert alarm["AlarmActions"] == [{"Ref": "SecurityAlertTopic"}]


class TestApprovalFallbackPath:
    """An approval request must reach someone even when SecurityAlertTopic or its key fails."""

    @pytest.fixture(scope="class")
    def resources(self) -> dict:
        return _load_tagged("event-driven.yaml")["Resources"]

    def test_fallback_topic_has_its_own_customer_managed_key(self, resources: dict) -> None:
        topic = resources["AlertFallbackTopic"]["Properties"]
        assert topic["KmsMasterKeyId"] == {"GetAtt": "AlertFallbackTopicKey.Arn"}
        assert topic["KmsMasterKeyId"] != resources["SecurityAlertTopic"]["Properties"]["KmsMasterKeyId"]
        assert resources["AlertFallbackTopicKey"]["Properties"]["EnableKeyRotation"] is True

    def test_alarms_may_publish_through_the_fallback_key_and_topic(self, resources: dict) -> None:
        condition = {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}}
        key_stmt = next(
            s
            for s in resources["AlertFallbackTopicKey"]["Properties"]["KeyPolicy"]["Statement"]
            if s["Sid"] == "AllowAlarmsToPublish"
        )
        assert key_stmt["Principal"] == {"Service": "cloudwatch.amazonaws.com"}
        assert set(key_stmt["Action"]) == {"kms:Decrypt", "kms:GenerateDataKey*"}
        assert key_stmt["Condition"] == condition
        topic_stmt = next(
            s
            for s in resources["AlertFallbackTopicPolicy"]["Properties"]["PolicyDocument"]["Statement"]
            if s["Sid"] == "AllowAlarmsToPublish"
        )
        assert topic_stmt["Principal"] == {"Service": "cloudwatch.amazonaws.com"}
        assert topic_stmt["Action"] == "sns:Publish"
        assert topic_stmt["Condition"] == condition

    def test_state_machine_role_may_publish_to_the_fallback_topic(self, resources: dict) -> None:
        statements = resources["StepFunctionsExecutionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        publish = next(s for s in statements if s["Action"] == ["sns:Publish"])
        assert {"Ref": "AlertFallbackTopic"} in publish["Resource"]
        kms = next(s for s in statements if "kms:GenerateDataKey" in s["Action"])
        assert {"GetAtt": "AlertFallbackTopicKey.Arn"} in kms["Resource"]

    def test_approval_wait_alarm_watches_the_oldest_approval_request(self, resources: dict) -> None:
        alarm = resources["ApprovalWaitingAlarm"]["Properties"]
        assert alarm["Namespace"] == "AWS/SQS"
        assert alarm["MetricName"] == "ApproximateAgeOfOldestMessage"
        assert alarm["Dimensions"] == [{"Name": "QueueName", "Value": {"GetAtt": "ApprovalQueue.QueueName"}}]
        assert alarm["Statistic"] == "Maximum"
        assert alarm["Threshold"] == {"Ref": "ApprovalWaitingAlarmThresholdSeconds"}
        assert alarm["ComparisonOperator"] == "GreaterThanThreshold"
        # An empty queue publishes no datapoint, which is the healthy state.
        assert alarm["TreatMissingData"] == "notBreaching"

    def test_approval_wait_alarm_notifies_both_topics(self, resources: dict) -> None:
        actions = resources["ApprovalWaitingAlarm"]["Properties"]["AlarmActions"]
        assert {"Ref": "AlertFallbackTopic"} in actions
        assert {"Ref": "SecurityAlertTopic"} in actions

    def test_threshold_stays_below_the_approval_timeout(self) -> None:
        template = _load_tagged("event-driven.yaml")
        param = template["Parameters"]["ApprovalWaitingAlarmThresholdSeconds"]
        sm = template["Resources"]["QuarantineStateMachine"]["Properties"]["DefinitionString"]["Sub"]
        timeout = json.loads(sm)["States"]["WaitForApproval"]["TimeoutSeconds"]
        # The alarm period (300 s) is added before the alarm fires, so leave room for it.
        assert param["MaxValue"] + 300 < timeout
        assert param["MinValue"] <= param["Default"] <= param["MaxValue"]


class TestApprovalWebhook:
    """Approval wait alarm state changes reach a webhook through EventBridge, without SNS."""

    WEBHOOK_RESOURCES = {
        "ApprovalWebhookConnection": "AWS::Events::Connection",
        "ApprovalWebhookDestination": "AWS::Events::ApiDestination",
        "ApprovalWebhookRuleRole": "AWS::IAM::Role",
        "ApprovalWebhookDlq": "AWS::SQS::Queue",
        "ApprovalWebhookDlqPolicy": "AWS::SQS::QueuePolicy",
        "ApprovalWebhookRule": "AWS::Events::Rule",
        "ApprovalWebhookDlqAlarm": "AWS::CloudWatch::Alarm",
    }

    @pytest.fixture(scope="class")
    def template(self) -> dict:
        return _load_tagged("event-driven.yaml")

    @pytest.fixture(scope="class")
    def resources(self, template: dict) -> dict:
        return template["Resources"]

    def test_webhook_is_optional(self, template: dict) -> None:
        params = template["Parameters"]
        assert params["ApprovalWebhookEndpoint"]["Default"] == ""
        assert template["Conditions"]["HasApprovalWebhook"] == {
            "Not": [{"Equals": [{"Ref": "ApprovalWebhookEndpoint"}, ""]}]
        }
        # Every resource of the path, and only those, depends on the condition.
        conditional = {
            n: r["Type"] for n, r in template["Resources"].items() if r.get("Condition") == "HasApprovalWebhook"
        }
        assert conditional == self.WEBHOOK_RESOURCES
        assert template["Outputs"]["ApprovalWebhookDlqUrl"]["Condition"] == "HasApprovalWebhook"

    def test_endpoint_must_be_https(self, template: dict) -> None:
        pattern = re.compile(template["Parameters"]["ApprovalWebhookEndpoint"]["AllowedPattern"])
        assert pattern.fullmatch("")
        assert pattern.fullmatch("https://hooks.example.com/approval")
        assert not pattern.fullmatch("http://hooks.example.com/approval")
        assert not pattern.fullmatch("https://hooks.example.com/a b")

    def test_api_key_is_hidden_and_required_with_an_endpoint(self, template: dict) -> None:
        assert template["Parameters"]["ApprovalWebhookApiKeyValue"]["NoEcho"] is True
        rule = template["Rules"]["ApprovalWebhookNeedsApiKey"]
        assert rule["RuleCondition"] == {"Not": [{"Equals": [{"Ref": "ApprovalWebhookEndpoint"}, ""]}]}
        assert rule["Assertions"][0]["Assert"] == {"Not": [{"Equals": [{"Ref": "ApprovalWebhookApiKeyValue"}, ""]}]}

    def test_connection_sends_the_api_key_header(self, resources: dict) -> None:
        props = resources["ApprovalWebhookConnection"]["Properties"]
        assert props["AuthorizationType"] == "API_KEY"
        assert props["AuthParameters"]["ApiKeyAuthParameters"] == {
            "ApiKeyName": {"Ref": "ApprovalWebhookApiKeyName"},
            "ApiKeyValue": {"Ref": "ApprovalWebhookApiKeyValue"},
        }
        dest = resources["ApprovalWebhookDestination"]["Properties"]
        assert dest["ConnectionArn"] == {"GetAtt": "ApprovalWebhookConnection.Arn"}
        assert dest["InvocationEndpoint"] == {"Ref": "ApprovalWebhookEndpoint"}
        assert dest["HttpMethod"] == "POST"

    def test_rule_matches_only_the_approval_wait_alarm(self, resources: dict) -> None:
        props = resources["ApprovalWebhookRule"]["Properties"]
        # No EventBusName: CloudWatch sends alarm state changes to the default bus.
        assert "EventBusName" not in props
        assert props["EventPattern"] == {
            "source": ["aws.cloudwatch"],
            "detail-type": ["CloudWatch Alarm State Change"],
            "resources": [{"GetAtt": "ApprovalWaitingAlarm.Arn"}],
        }

    def test_target_retries_and_keeps_undelivered_events(self, resources: dict) -> None:
        (target,) = resources["ApprovalWebhookRule"]["Properties"]["Targets"]
        assert target["Arn"] == {"GetAtt": "ApprovalWebhookDestination.Arn"}
        assert target["RoleArn"] == {"GetAtt": "ApprovalWebhookRuleRole.Arn"}
        assert target["RetryPolicy"] == {"MaximumEventAgeInSeconds": 86400, "MaximumRetryAttempts": 185}
        assert target["DeadLetterConfig"] == {"Arn": {"GetAtt": "ApprovalWebhookDlq.Arn"}}

    def test_rule_role_may_invoke_only_this_destination(self, resources: dict) -> None:
        role = resources["ApprovalWebhookRuleRole"]["Properties"]
        assert role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == {"Service": "events.amazonaws.com"}
        (policy,) = role["Policies"]
        (statement,) = policy["PolicyDocument"]["Statement"]
        assert statement["Action"] == "events:InvokeApiDestination"
        assert statement["Resource"]["Sub"].endswith(":api-destination/${ApprovalWebhookDestination}/*")

    def test_dlq_is_encrypted_and_accepts_only_this_rule(self, resources: dict) -> None:
        queue = resources["ApprovalWebhookDlq"]["Properties"]
        assert queue["SqsManagedSseEnabled"] is True
        assert queue["MessageRetentionPeriod"] == 1209600
        policy = resources["ApprovalWebhookDlqPolicy"]["Properties"]
        assert policy["Queues"] == [{"Ref": "ApprovalWebhookDlq"}]
        (statement,) = policy["PolicyDocument"]["Statement"]
        assert statement["Principal"] == {"Service": "events.amazonaws.com"}
        assert statement["Action"] == "sqs:SendMessage"
        assert statement["Condition"] == {"ArnEquals": {"aws:SourceArn": {"GetAtt": "ApprovalWebhookRule.Arn"}}}

    def test_dlq_alarm_notifies_both_topics(self, resources: dict) -> None:
        alarm = resources["ApprovalWebhookDlqAlarm"]["Properties"]
        assert alarm["MetricName"] == "ApproximateNumberOfMessagesVisible"
        assert alarm["Dimensions"] == [{"Name": "QueueName", "Value": {"GetAtt": "ApprovalWebhookDlq.QueueName"}}]
        assert alarm["Threshold"] == 1
        assert alarm["ComparisonOperator"] == "GreaterThanOrEqualToThreshold"
        assert {"Ref": "AlertFallbackTopic"} in alarm["AlarmActions"]
        assert {"Ref": "SecurityAlertTopic"} in alarm["AlarmActions"]


class TestHubAlertTopicDelivery:
    """The hub alert topic must accept the hub EventBridge rule and stay encrypted.

    An EventBridge rule delivered nothing to a topic encrypted with the AWS managed key aws/sns,
    even with a topic policy that allows EventBridge to publish.
    """

    ACCOUNT_CONDITION = {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}}

    @pytest.fixture(scope="class")
    def template(self) -> dict:
        return _load_tagged("hub-aggregation.yaml")

    @staticmethod
    def _statement(policy: dict, sid: str) -> dict:
        return next(s for s in policy["Statement"] if s["Sid"] == sid)

    def test_topic_uses_the_customer_managed_key(self, template: dict) -> None:
        topic = template["Resources"]["HubAlertTopic"]["Properties"]
        assert topic["KmsMasterKeyId"] == {"GetAtt": "HubAlertTopicKey.Arn"}

    def test_key_rotates_and_lets_rules_publish(self, template: dict) -> None:
        key = template["Resources"]["HubAlertTopicKey"]["Properties"]
        assert key["EnableKeyRotation"] is True
        statement = self._statement(key["KeyPolicy"], "AllowRulesToPublish")
        assert statement["Principal"] == {"Service": "events.amazonaws.com"}
        assert statement["Action"] == ["kms:Decrypt", "kms:GenerateDataKey*"]
        assert statement["Condition"] == self.ACCOUNT_CONDITION
        admin = self._statement(key["KeyPolicy"], "EnableAccountAdministration")
        assert admin["Principal"]["AWS"]["Sub"].endswith(":root")

    def test_topic_policy_lets_rules_publish(self, template: dict) -> None:
        policy = template["Resources"]["HubAlertTopicPolicy"]["Properties"]
        assert policy["Topics"] == [{"Ref": "HubAlertTopic"}]
        statement = self._statement(policy["PolicyDocument"], "AllowRulesToPublish")
        assert statement["Principal"] == {"Service": "events.amazonaws.com"}
        assert statement["Action"] == "sns:Publish"
        assert statement["Resource"] == {"Ref": "HubAlertTopic"}
        assert statement["Condition"] == self.ACCOUNT_CONDITION

    def test_key_arn_is_an_output(self, template: dict) -> None:
        assert template["Outputs"]["HubAlertTopicKeyArn"]["Value"] == {"GetAtt": "HubAlertTopicKey.Arn"}

    def test_no_rule_targets_a_topic_encrypted_with_the_aws_managed_key(self) -> None:
        for path in sorted(TEMPLATES_DIR.glob("*.yaml")):
            resources = _load_tagged(path.name).get("Resources", {})
            aws_managed = {
                name
                for name, r in resources.items()
                if r["Type"] == "AWS::SNS::Topic" and r["Properties"].get("KmsMasterKeyId") == "alias/aws/sns"
            }
            for name, r in resources.items():
                if r["Type"] != "AWS::Events::Rule":
                    continue
                for target in r["Properties"].get("Targets", []):
                    arn = target.get("Arn")
                    ref = arn.get("Ref") if isinstance(arn, dict) else None
                    assert ref not in aws_managed, f"{path.name}: rule {name} targets {ref}, encrypted with aws/sns"

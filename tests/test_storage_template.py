"""CloudFormation storage template validation tests.

Validates the FSx for ONTAP storage template structure, resources, and configuration.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


# Custom YAML loader for CloudFormation intrinsic functions
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


def ref_target(value: object) -> str | None:
    """Return the logical ID of a short-form ``!Ref`` as parsed by CfnLoader, else None.

    CfnLoader registers ``!Ref`` as a multi-constructor prefix, so ``!Ref X`` loads as
    ``{"": "X"}``. The long form ``{"Ref": "X"}`` is accepted as well.
    """
    if isinstance(value, dict) and len(value) == 1:
        key, target = next(iter(value.items()))
        if key in ("", "Ref") and isinstance(target, str):
            return target
    return None


def load_yaml(path: Path) -> dict:
    """Load a CloudFormation YAML template handling intrinsic functions."""
    with open(path) as f:
        return yaml.load(f, Loader=CfnLoader)  # noqa: S506


class TestStorageTemplate:
    """Validate FSx for ONTAP storage template."""

    @pytest.fixture
    def template(self) -> dict:
        return load_yaml(TEMPLATES_DIR / "storage.yaml")

    # ------------------------------------------------------------------
    # Structure
    # ------------------------------------------------------------------
    def test_has_format_version(self, template: dict) -> None:
        """Template must declare AWSTemplateFormatVersion."""
        assert template["AWSTemplateFormatVersion"] == "2010-09-09"

    def test_has_description(self, template: dict) -> None:
        """Template must have a meaningful description."""
        assert "FSx for ONTAP" in template["Description"]

    # ------------------------------------------------------------------
    # Parameters
    # ------------------------------------------------------------------
    def test_environment_parameter(self, template: dict) -> None:
        """Must have Environment parameter with allowed values."""
        params = template["Parameters"]
        assert "Environment" in params
        assert set(params["Environment"]["AllowedValues"]) == {
            "dev",
            "staging",
            "production",
        }

    def test_throughput_parameter(self, template: dict) -> None:
        """Must have ThroughputCapacity parameter with valid FSx values."""
        params = template["Parameters"]
        assert "ThroughputCapacity" in params
        assert 128 in params["ThroughputCapacity"]["AllowedValues"]
        assert 2048 in params["ThroughputCapacity"]["AllowedValues"]

    def test_storage_capacity_parameter(self, template: dict) -> None:
        """Must have StorageCapacity with min 1024 GiB."""
        params = template["Parameters"]
        assert "StorageCapacity" in params
        assert params["StorageCapacity"]["MinValue"] == 1024

    def test_deployment_type_parameter(self, template: dict) -> None:
        """Must have DeploymentType with Single and Multi-AZ options."""
        params = template["Parameters"]
        assert "DeploymentType" in params
        allowed = params["DeploymentType"]["AllowedValues"]
        assert "MULTI_AZ_1" in allowed
        assert "SINGLE_AZ_1" in allowed

    def test_fsx_admin_password_no_echo(self, template: dict) -> None:
        """FsxAdminPassword must have NoEcho=true."""
        params = template["Parameters"]
        assert "FsxAdminPassword" in params
        assert params["FsxAdminPassword"]["NoEcho"] is True

    # ------------------------------------------------------------------
    # Conditions
    # ------------------------------------------------------------------
    def test_conditions_defined(self, template: dict) -> None:
        """Must define conditions for AD and Multi-AZ."""
        conditions = template.get("Conditions", {})
        assert "HasActiveDirectory" in conditions
        assert "IsMultiAz" in conditions

    # ------------------------------------------------------------------
    # File System
    # ------------------------------------------------------------------
    def test_fsx_file_system_exists(self, template: dict) -> None:
        """Must define an FSx for ONTAP file system."""
        resources = template["Resources"]
        assert "FsxFileSystem" in resources
        assert resources["FsxFileSystem"]["Type"] == "AWS::FSx::FileSystem"

    def test_fsx_file_system_type_ontap(self, template: dict) -> None:
        """File system must be of type ONTAP."""
        fs = template["Resources"]["FsxFileSystem"]["Properties"]
        assert fs["FileSystemType"] == "ONTAP"

    def test_fsx_file_system_ssd(self, template: dict) -> None:
        """File system must use SSD storage."""
        fs = template["Resources"]["FsxFileSystem"]["Properties"]
        assert fs["StorageType"] == "SSD"

    def test_fsx_has_deletion_policy_retain(self, template: dict) -> None:
        """File system must have DeletionPolicy=Retain to prevent accidental deletion."""
        fs = template["Resources"]["FsxFileSystem"]
        assert fs.get("DeletionPolicy") == "Retain"

    def test_fsx_has_kms_encryption(self, template: dict) -> None:
        """File system must reference KMS key for encryption."""
        fs = template["Resources"]["FsxFileSystem"]["Properties"]
        assert "KmsKeyId" in fs

    def test_fsx_has_automatic_backups(self, template: dict) -> None:
        """File system must have automatic backups configured."""
        ontap_config = template["Resources"]["FsxFileSystem"]["Properties"]["OntapConfiguration"]
        assert ontap_config["AutomaticBackupRetentionDays"] >= 7

    # ------------------------------------------------------------------
    # KMS Key
    # ------------------------------------------------------------------
    def test_kms_key_exists(self, template: dict) -> None:
        """Must define a KMS key for FSx encryption."""
        resources = template["Resources"]
        assert "FsxKmsKey" in resources
        assert resources["FsxKmsKey"]["Type"] == "AWS::KMS::Key"

    def test_kms_key_rotation_enabled(self, template: dict) -> None:
        """KMS key must have automatic rotation enabled."""
        key = template["Resources"]["FsxKmsKey"]["Properties"]
        assert key["EnableKeyRotation"] is True

    def test_kms_alias_exists(self, template: dict) -> None:
        """Must define a KMS key alias."""
        resources = template["Resources"]
        assert "FsxKmsKeyAlias" in resources

    # ------------------------------------------------------------------
    # SVMs
    # ------------------------------------------------------------------
    def test_svm_production_exists(self, template: dict) -> None:
        """Must define a production SVM."""
        resources = template["Resources"]
        assert "SvmProduction" in resources
        assert resources["SvmProduction"]["Type"] == "AWS::FSx::StorageVirtualMachine"

    def test_svm_audit_exists(self, template: dict) -> None:
        """Must define an audit SVM (isolated)."""
        resources = template["Resources"]
        assert "SvmAudit" in resources
        assert resources["SvmAudit"]["Type"] == "AWS::FSx::StorageVirtualMachine"

    def test_svm_audit_unix_security_style(self, template: dict) -> None:
        """Audit SVM must use UNIX security style."""
        svm = template["Resources"]["SvmAudit"]["Properties"]
        assert svm["RootVolumeSecurityStyle"] == "UNIX"

    def test_svm_production_mixed_security_style(self, template: dict) -> None:
        """Production SVM must use MIXED security style (NFS + SMB)."""
        svm = template["Resources"]["SvmProduction"]["Properties"]
        assert svm["RootVolumeSecurityStyle"] == "MIXED"

    # ------------------------------------------------------------------
    # Volumes
    # ------------------------------------------------------------------
    def test_volume_production_exists(self, template: dict) -> None:
        """Must define a production data volume."""
        resources = template["Resources"]
        assert "VolumeProduction" in resources
        assert resources["VolumeProduction"]["Type"] == "AWS::FSx::Volume"

    def test_volume_audit_exists(self, template: dict) -> None:
        """Must define an audit log volume."""
        resources = template["Resources"]
        assert "VolumeAudit" in resources

    def test_volume_snaplock_exists(self, template: dict) -> None:
        """Must define a SnapLock compliance volume."""
        resources = template["Resources"]
        assert "VolumeSnaplock" in resources

    def test_volume_production_has_tiering(self, template: dict) -> None:
        """Production volume must have capacity pool tiering configured."""
        vol = template["Resources"]["VolumeProduction"]["Properties"]["OntapConfiguration"]
        assert vol["TieringPolicy"]["Name"] == "AUTO"

    def test_volume_snaplock_has_retention(self, template: dict) -> None:
        """SnapLock volume must have retention period configured."""
        vol = template["Resources"]["VolumeSnaplock"]["Properties"]["OntapConfiguration"]
        snaplock = vol["SnaplockConfiguration"]
        assert snaplock["SnaplockType"] in ["COMPLIANCE", "ENTERPRISE"]
        assert "RetentionPeriod" in snaplock

    def test_volume_snaplock_privileged_delete_disabled(self, template: dict) -> None:
        """SnapLock volume must have privileged delete permanently disabled."""
        vol = template["Resources"]["VolumeSnaplock"]["Properties"]["OntapConfiguration"]
        snaplock = vol["SnaplockConfiguration"]
        assert snaplock["PrivilegedDelete"] == "PERMANENTLY_DISABLED"

    def test_volume_snaplock_no_tiering(self, template: dict) -> None:
        """SnapLock volume must NOT use capacity pool tiering (data integrity)."""
        vol = template["Resources"]["VolumeSnaplock"]["Properties"]["OntapConfiguration"]
        assert vol["TieringPolicy"]["Name"] == "NONE"

    # ------------------------------------------------------------------
    # Audit log destination for svm-prod
    # ------------------------------------------------------------------
    def test_volume_audit_production_exists(self, template: dict) -> None:
        """Must define an audit log destination volume for the production SVM."""
        resources = template["Resources"]
        assert "VolumeAuditProduction" in resources
        assert resources["VolumeAuditProduction"]["Type"] == "AWS::FSx::Volume"

    def test_volume_audit_production_on_svm_production(self, template: dict) -> None:
        """The destination must be inside svm-prod's namespace (same SVM as the audited data)."""
        vol = template["Resources"]["VolumeAuditProduction"]["Properties"]["OntapConfiguration"]
        assert ref_target(vol["StorageVirtualMachineId"]) == "SvmProduction"

    def test_volume_audit_production_junction_path(self, template: dict) -> None:
        """The destination must be mounted at /audit_prod (the path the runbook passes to -destination)."""
        vol = template["Resources"]["VolumeAuditProduction"]["Properties"]["OntapConfiguration"]
        assert vol["JunctionPath"] == "/audit_prod"

    def test_volume_audit_production_is_plain_rw(self, template: dict) -> None:
        """The destination must be a plain RW volume with no SnapLock (no irreversible settings)."""
        resource = template["Resources"]["VolumeAuditProduction"]
        vol = resource["Properties"]["OntapConfiguration"]
        assert vol["OntapVolumeType"] == "RW"
        assert "SnaplockConfiguration" not in vol
        assert "PERMANENTLY_DISABLED" not in json.dumps(resource)

    def test_only_snaplock_volume_has_snaplock_configuration(self, template: dict) -> None:
        """Only VolumeSnaplock may carry a SnaplockConfiguration."""
        with_snaplock = [
            name
            for name, res in template["Resources"].items()
            if "SnaplockConfiguration" in res.get("Properties", {}).get("OntapConfiguration", {})
        ]
        assert with_snaplock == ["VolumeSnaplock"]

    def test_volume_audit_production_tags(self, template: dict) -> None:
        """The destination volume must carry the project tag set."""
        tags = {t["Key"]: t["Value"] for t in template["Resources"]["VolumeAuditProduction"]["Properties"]["Tags"]}
        assert {"Name", "Project", "Environment", "Layer", "Component", "DataClassification"} <= set(tags)
        assert tags["Layer"] == "observability"
        assert tags["Component"] == "volume-audit-production"
        assert tags["DataClassification"] == "confidential"

    def test_production_audit_volume_size_parameter(self, template: dict) -> None:
        """ProductionAuditVolumeSize must default to 1024 MiB with a 20 MiB minimum."""
        param = template["Parameters"]["ProductionAuditVolumeSize"]
        assert param["Default"] == 1024
        assert param["MinValue"] == 20
        vol = template["Resources"]["VolumeAuditProduction"]["Properties"]["OntapConfiguration"]
        assert ref_target(vol["SizeInMegabytes"]) == "ProductionAuditVolumeSize"

    # ------------------------------------------------------------------
    # Tags & Data Classification
    # ------------------------------------------------------------------
    def test_volumes_have_data_classification_tag(self, template: dict) -> None:
        """All volumes must have a DataClassification tag."""
        resources = template["Resources"]
        volume_names = ["VolumeProduction", "VolumeAudit", "VolumeAuditProduction", "VolumeSnaplock"]
        for name in volume_names:
            tags = resources[name]["Properties"]["Tags"]
            tag_keys = [t["Key"] for t in tags]
            assert "DataClassification" in tag_keys, f"{name} must have DataClassification tag"

    def test_confidential_volumes_identified(self, template: dict) -> None:
        """Audit and SnapLock volumes must be classified as confidential."""
        resources = template["Resources"]
        for vol_name in ["VolumeAudit", "VolumeAuditProduction", "VolumeSnaplock"]:
            tags = resources[vol_name]["Properties"]["Tags"]
            classification = next(t["Value"] for t in tags if t["Key"] == "DataClassification")
            assert classification == "confidential", f"{vol_name} should be classified as confidential"

    # ------------------------------------------------------------------
    # Outputs
    # ------------------------------------------------------------------
    def test_outputs_defined(self, template: dict) -> None:
        """Must export file system ID, SVM IDs, volume IDs, and KMS ARN."""
        outputs = template.get("Outputs", {})
        assert "FileSystemId" in outputs
        assert "SvmProductionId" in outputs
        assert "SvmAuditId" in outputs
        assert "VolumeProductionId" in outputs
        assert "VolumeAuditId" in outputs
        assert "VolumeAuditProductionId" in outputs
        assert "VolumeSnaplockId" in outputs
        assert "KmsKeyArn" in outputs

    def test_outputs_have_exports(self, template: dict) -> None:
        """All outputs must have Export names for cross-stack references."""
        outputs = template.get("Outputs", {})
        for name, output in outputs.items():
            assert "Export" in output, f"Output {name} must have Export"


class TestBringYourOwnFsx:
    """Validate Bring Your Own FSx for ONTAP parameters and conditions."""

    @pytest.fixture
    def template(self) -> dict:
        return load_yaml(TEMPLATES_DIR / "storage.yaml")

    def test_use_existing_parameter_exists(self, template: dict) -> None:
        """Template must have UseExistingFileSystem parameter."""
        params = template["Parameters"]
        assert "UseExistingFileSystem" in params
        assert params["UseExistingFileSystem"]["Default"] == "false"
        assert "true" in params["UseExistingFileSystem"]["AllowedValues"]

    def test_existing_filesystem_id_parameter(self, template: dict) -> None:
        """Template must have ExistingFileSystemId parameter."""
        params = template["Parameters"]
        assert "ExistingFileSystemId" in params
        assert params["ExistingFileSystemId"]["Default"] == ""

    def test_existing_management_endpoint_parameter(self, template: dict) -> None:
        """Template must have ExistingManagementEndpoint parameter."""
        params = template["Parameters"]
        assert "ExistingManagementEndpoint" in params

    def test_existing_svm_id_parameter(self, template: dict) -> None:
        """Template must have ExistingSvmId parameter."""
        params = template["Parameters"]
        assert "ExistingSvmId" in params

    def test_existing_volume_id_parameter(self, template: dict) -> None:
        """Template must have ExistingVolumeId parameter."""
        params = template["Parameters"]
        assert "ExistingVolumeId" in params

    def test_create_new_filesystem_condition(self, template: dict) -> None:
        """Template must define CreateNewFileSystem condition."""
        conditions = template.get("Conditions", {})
        assert "CreateNewFileSystem" in conditions

    def test_create_new_svm_condition(self, template: dict) -> None:
        """Template must define CreateNewSvm condition."""
        conditions = template.get("Conditions", {})
        assert "CreateNewSvm" in conditions

    def test_filesystem_is_conditional(self, template: dict) -> None:
        """FSx file system resource must be conditional on CreateNewFileSystem."""
        resources = template["Resources"]
        assert resources["FsxFileSystem"].get("Condition") == "CreateNewFileSystem"

    def test_kms_key_is_conditional(self, template: dict) -> None:
        """KMS key must be conditional on CreateNewFileSystem."""
        resources = template["Resources"]
        assert resources["FsxKmsKey"].get("Condition") == "CreateNewFileSystem"

    def test_svms_are_conditional(self, template: dict) -> None:
        """SVMs must be conditional on CreateNewSvm."""
        resources = template["Resources"]
        assert resources["SvmProduction"].get("Condition") == "CreateNewSvm"
        assert resources["SvmAudit"].get("Condition") == "CreateNewSvm"

    def test_volumes_are_conditional(self, template: dict) -> None:
        """Volumes must be conditional on CreateNewSvm."""
        resources = template["Resources"]
        assert resources["VolumeProduction"].get("Condition") == "CreateNewSvm"
        assert resources["VolumeAudit"].get("Condition") == "CreateNewSvm"
        assert resources["VolumeAuditProduction"].get("Condition") == "CreateNewSvm"
        assert resources["VolumeSnaplock"].get("Condition") == "CreateNewSvm"

    def test_management_endpoint_output(self, template: dict) -> None:
        """Must output ManagementEndpoint (works for both new and existing)."""
        outputs = template.get("Outputs", {})
        assert "ManagementEndpoint" in outputs

    def test_existing_volume_id_output(self, template: dict) -> None:
        """Must output ExistingVolumeId for downstream stacks."""
        outputs = template.get("Outputs", {})
        assert "ExistingVolumeIdOutput" in outputs

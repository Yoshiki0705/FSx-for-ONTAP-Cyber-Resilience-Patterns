# Deployment Guide — FSx for ONTAP Cyber Resilience Patterns

## Overview

This guide covers the deployment of 12 CloudFormation templates that compose the
FSx for ONTAP Cyber Resilience Patterns reference architecture. Templates are designed
to be deployed individually (à la carte) or as a coordinated set.

Two deployment paths are supported:

| Path | Description | Use Case |
|------|-------------|----------|
| **Greenfield** | New VPC + new FSx for ONTAP | Lab, PoC, isolated production |
| **Brownfield** | Existing VPC + existing FSx for ONTAP | Add security layers to running workloads |

> **Important**: Use `aws cloudformation create-stack --parameters file://cfn-params/<file>.json`
> for parameter files. `aws cloudformation deploy` does **not** support `file://` for parameters.

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|-----------------|-------|
| AWS CLI | v2.x | `aws --version` |
| Python | 3.12+ | For Lambda packaging and tests |
| cfn-lint | latest | `pip install cfn-lint` |
| ONTAP version | 9.13.1+ | ARP on FlexGroup requires 9.13.1; ARP on FlexVol requires 9.11.1+ |
| IAM permissions | CloudFormation, FSx, EC2, Lambda, IAM, SQS, EventBridge, SNS, SecretsManager, KMS, CloudWatch, Step Functions, S3 | AdministratorAccess for PoC; scoped IAM for production |

### ONTAP Version Requirements

| Feature | Minimum ONTAP Version |
|---------|----------------------|
| ARP (FlexVol) | 9.10.1 |
| ARP (FlexGroup) | 9.13.1 |
| FPolicy external engine (async) | 9.7 |
| FPolicy external engine (sync/ICAP) | 9.8 |
| SnapLock Compliance | 9.10.1 |
| Multi-Admin Verification (MAV) | 9.11.1 |
| Tamperproof Snapshot | 9.12.1 |

---

## Template Catalog

### Phase 1 — Core (required)

| # | Template | Description | Deploy Time | Dependencies |
|---|----------|-------------|-------------|--------------|
| 1 | `network.yaml` | VPC, subnets (Multi-AZ), Security Groups, VPC Endpoints, Flow Logs | ~3 min | None |
| 2 | `storage.yaml` | FSx for ONTAP file system, SVMs, volumes, KMS | ~30 min | network |
| 3 | `event-driven.yaml` | SQS, EventBridge custom bus, Step Functions, Lambda, SNS | ~5 min | network (Lambda VPC) |
| 4 | `scanning.yaml` | EC2 instances for TrendAI Vscan (ICAP) + Deep Instinct | ~5 min | network |
| 5 | `observability.yaml` | CloudWatch Dashboard + Alarms | ~2 min | event-driven (SNS ARN) |

### Phase 2 — Operational

| # | Template | Description | Deploy Time | Dependencies |
|---|----------|-------------|-------------|--------------|
| 6 | `scanning-ha.yaml` | Auto Scaling Groups for scanner HA (Multi-AZ) | ~5 min | network |
| 7 | `dr-replication.yaml` | SnapMirror lag monitoring, cross-region health checks | ~3 min | storage |
| 8 | `cost-scheduler.yaml` | Stop/start scanner EC2 during off-hours (non-prod) | ~2 min | scanning |

### Phase 3 — Enterprise / Multi-Account

| # | Template | Description | Deploy Time | Dependencies |
|---|----------|-------------|-------------|--------------|
| 9 | `hub-aggregation.yaml` | Central EventBridge bus for aggregated security events | ~2 min | None (hub account) |
| 10 | `spoke-monitoring.yaml` | Cross-account EventBridge forwarding (StackSet-ready) | ~2 min | hub-aggregation |
| 11 | `siem-integration.yaml` | Security Hub, SIEM forwarder (Splunk/QRadar/CEF), compliance collector | ~5 min | event-driven |
| 12 | `main.yaml` | Root nested stack (orchestrates network + storage + event-driven) | ~35 min | S3 bucket with templates |

---

## VPC Endpoint Conflict Matrix

### Background: Gateway vs Interface Endpoints

| Type | Mechanism | DNS Impact | Conflict Risk |
|------|-----------|------------|---------------|
| **Gateway Endpoint** | Route table entry pointing to a VPC prefix list | None — uses public DNS, routed by prefix list | Low. Multiple Gateway EPs for same service in same VPC are **not allowed**, but Gateway EPs do not conflict with each other across services. |
| **Interface Endpoint** | ENI in subnets with private IP + optional Private DNS | When `PrivateDnsEnabled: true`, overrides the service's public DNS hostname in the entire VPC | **High when combined with same-service resources**. Enabling private DNS hijacks all traffic to that service within the VPC. |

### Conflict Scenarios with Existing Infrastructure

| VPC Endpoint | Type | Created By | Conflict If... | Resolution |
|--------------|------|------------|----------------|------------|
| `com.amazonaws.<region>.s3` | Gateway | `network.yaml` | VPC already has an S3 Gateway Endpoint | **Skip creation** — only one S3 Gateway EP per VPC allowed. Use `UseExistingVpc=true` and pre-existing route. |
| `com.amazonaws.<region>.sqs` | Interface | `network.yaml` | VPC already has SQS Interface EP in different subnets | Two Interface EPs for same service in the same VPC are **not allowed**. Share existing EP. |
| `com.amazonaws.<region>.secretsmanager` | Interface | `network.yaml` | Existing EP with `PrivateDnsEnabled=false` | Lambda calls will fail — Private DNS is **required** for SDK default endpoint resolution. |
| `com.amazonaws.<region>.kms` | Interface | `network.yaml` | Same as above | Same resolution — enable Private DNS or use endpoint URL override in code. |
| `com.amazonaws.<region>.sts` | Interface | `network.yaml` | Same as above | Same resolution. |

### Pre-deployment Checklist for VPC Endpoints

When deploying into an **existing VPC** (`UseExistingVpc=true`):

1. **S3 Gateway EP**: Check if one already exists. If yes, ensure its route table associations cover the subnets used by this stack (isolated + private route tables).
2. **Interface EPs** (SQS, SecretsManager, KMS, STS): Check if each already exists in the VPC. If yes, ensure:
   - `PrivateDnsEnabled: true` (required for Lambda SDK calls)
   - Security Group allows inbound HTTPS (443) from the VPC CIDR
   - Subnet placement covers AZs used by Lambda/compute
3. **No duplicate EPs**: A VPC cannot have two endpoints for the same service. If conflict exists, the CloudFormation stack will fail with `VpceAlreadyExists`.

Use the provided `preflight-check.sh` script to automate these checks.

---

## Deployment Path A: Greenfield (New VPC + New FSx for ONTAP)

### Step 1: Package Lambda Functions

```bash
export LAMBDA_ARTIFACT_BUCKET=<your-bucket-name>
./scripts/package-lambdas.sh --upload --bucket "$LAMBDA_ARTIFACT_BUCKET"
```

### Step 2: Deploy Core Stacks

```bash
# Network
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-network-dev \
  --template-body file://templates/network.yaml \
  --parameters file://cfn-params/network.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1

aws cloudformation wait stack-create-complete \
  --stack-name fsxn-cyber-resilience-network-dev

# Storage (~30 minutes)
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-storage-dev \
  --template-body file://templates/storage.yaml \
  --parameters file://cfn-params/storage.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1

aws cloudformation wait stack-create-complete \
  --stack-name fsxn-cyber-resilience-storage-dev

# Event-Driven
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-events-dev \
  --template-body file://templates/event-driven.yaml \
  --parameters file://cfn-params/event-driven.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

ARP and FPolicy are set after the stacks are up, with the CLI / REST steps in the [ARP guide](../ontap-native/arp-configuration.md) and the [FPolicy guide](../ontap-native/fpolicy-configuration.md). File access auditing on `svm-prod` is enabled by hand as well; see the [Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md).

### Step 3: Deploy Scanning Layer

```bash
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-scanning-dev \
  --template-body file://templates/scanning.yaml \
  --parameters file://cfn-params/scanning.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

### Step 4: Deploy Observability

```bash
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-observability-dev \
  --template-body file://templates/observability.yaml \
  --parameters file://cfn-params/observability.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

### Automated Deployment (alternative)

```bash
./scripts/deploy.sh dev all
```

---

## Deployment Path B: Brownfield (Existing FSx for ONTAP)

### Step 1: Run Preflight Checks

```bash
./preflight-check.sh \
  --vpc-id vpc-0123456789abcdef0 \
  --file-system-id fs-0123456789abcdef0 \
  --region ap-northeast-1
```

The script validates:
- VPC Endpoint conflicts (duplicate S3 Gateway EP, existing Interface EPs)
- Security Group rules (Lambda→FSx HTTPS 443, FSx→Scanner ICAP 1344)
- ONTAP S3 server presence on target SVM (conflicts with FSx for ONTAP S3 AP)

### Step 2: Gather Existing Resource Information

```bash
# File System ID and DNS
aws fsx describe-file-systems \
  --query 'FileSystems[*].[FileSystemId,DNSName]' --output table

# SVM ID
aws fsx describe-storage-virtual-machines \
  --filters Name=file-system-id,Values=<file-system-id> \
  --query 'StorageVirtualMachines[*].[StorageVirtualMachineId,Name]' --output table

# Volume IDs
aws fsx describe-volumes \
  --filters Name=file-system-id,Values=<file-system-id> \
  --query 'Volumes[*].[VolumeId,Name,OntapConfiguration.JunctionPath]' --output table

# Management Endpoint
aws fsx describe-file-systems --file-system-ids <file-system-id> \
  --query 'FileSystems[0].OntapConfiguration.Endpoints.Management.DNSName' --output text
```

### Step 3: Store fsxadmin Credentials

```bash
aws secretsmanager create-secret \
  --name "fsxn-cyber-resilience-fsxadmin" \
  --secret-string '{"username":"fsxadmin","password":"<your-password>"}' \
  --region ap-northeast-1
```

### Step 4: Deploy with Existing VPC Parameters

```bash
# Network stack with UseExistingVpc=true
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-network-dev \
  --template-body file://templates/network.yaml \
  --parameters file://cfn-params/network-existing-vpc.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

### Step 5: Deploy Event-Driven Response

```bash
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-events-dev \
  --template-body file://templates/event-driven.yaml \
  --parameters file://cfn-params/event-driven.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

### Step 6: Deploy Storage

```bash
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-storage-dev \
  --template-body file://templates/storage.yaml \
  --parameters file://cfn-params/storage-existing.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

With `UseExistingFileSystem=true`, no new FSx for ONTAP is created.
ARP and FPolicy on the existing file system are set with the CLI / REST steps in the [ARP guide](../ontap-native/arp-configuration.md) and the [FPolicy guide](../ontap-native/fpolicy-configuration.md).

---

## Cost Estimate (ap-northeast-1)

| Component | Monthly Cost (USD) | Notes |
|-----------|--------------------|-------|
| FSx for ONTAP (Single-AZ, 1 TiB, 128 MBps) | ~$310 | Greenfield only |
| FSx for ONTAP (Multi-AZ, 1 TiB, 128 MBps) | ~$620 | Production |
| EC2 Vscan (c6g.xlarge) | ~$98 | 24/7 ON_DEMAND |
| EC2 Deep Instinct (c6i.xlarge) | ~$122 | 24/7 ON_DEMAND |
| VPC Interface Endpoints (x4) | ~$30 | SQS, SM, KMS, STS |
| NAT Gateway | ~$33 | + data transfer |
| Serverless (Lambda, SQS, EventBridge, Step Functions, SNS) | ~$10 | Free Tier covers most |
| CloudWatch (Dashboard + custom metrics) | ~$5 | 7 custom metrics |
| **Total — Minimum (Brownfield, 1 scanner)** | **~$170/mo** | No FSx creation |
| **Total — Standard (Greenfield, 2 scanners)** | **~$610/mo** | Single-AZ FSx |
| **Total — Production (Multi-AZ, HA scanners, DR)** | **~$1,200/mo** | Full deployment |

> **Cost reduction**: Use `cost-scheduler.yaml` to stop scanner EC2 during non-business
> hours in dev/staging (~50% EC2 savings).

---

## Day 2 Operations

### ARP Mode Transition (original ARP only, 30 days post-deployment)

This step applies only to original-generation ARP (9.10.1–9.15.1 on NAS FlexVol, up to 9.17.1 on
FlexGroup). Original ARP starts in `dry-run` (learning) mode and transitions to `active` after
30 days of learning:

```bash
ssh fsxadmin@<management-endpoint>
security anti-ransomware volume show -vserver <svm> -fields state
security anti-ransomware volume enable -vserver <svm> -volume <vol> -state active
```

ARP/AI (9.16.1+ on FlexVol, 9.18.1+ on FlexGroup) has no learning period and protects actively from
the moment it is enabled. On that generation a requested `dry_run` silently becomes `enabled`, so no
transition step is needed. For how to tell the generations apart and the measured basis, see the
[ARP configuration guide](../ontap-native/arp-configuration.md).

### Scanner Signature Updates

Scanners require outbound HTTPS for signature updates:
- **With NAT Gateway** (`EnableNatGateway=true`): Automatic
- **Without NAT Gateway**: Manual update via S3 artifact or EC2 Instance Connect

### CloudWatch Dashboard

After deployment, navigate to CloudWatch → Dashboards → `fsxn-cyber-resilience-security-<env>`.

Widgets include: Security Events Received, Malware Detected, Ransomware Alerts (ARP),
Quarantine Actions, Scanner Health, Step Functions Executions, SQS DLQ depth.

### Alarm Thresholds

| Alarm | Threshold | Action |
|-------|-----------|--------|
| Malware burst | >10 detections / 5 min | SNS → email |
| SQS DLQ depth | >0 messages | SNS → email |
| ARP alert | >0 ransomware events | SNS → email |
| Scanner health | No heartbeat for 5 min | SNS → email |

---

## Rollback Procedures

### Stack-Level Rollback

CloudFormation automatically rolls back on deployment failure. For manual rollback:

```bash
# List stack events to identify failure
aws cloudformation describe-stack-events \
  --stack-name <stack-name> \
  --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`]'

# Delete failed stack
aws cloudformation delete-stack --stack-name <stack-name>
aws cloudformation wait stack-delete-complete --stack-name <stack-name>
```

### ONTAP Configuration Rollback

ARP and FPolicy configurations are **intentionally preserved** after stack deletion
(safety-first design). To manually revert:

```bash
ssh fsxadmin@<management-endpoint>

# Disable ARP
security anti-ransomware volume disable -vserver <svm> -volume <vol>

# Remove FPolicy
fpolicy policy disable -vserver <svm> -policy-name <policy>
fpolicy policy scope delete -vserver <svm> -policy-name <policy>
fpolicy policy event delete -vserver <svm> -event-name <event>
fpolicy policy delete -vserver <svm> -policy-name <policy>
fpolicy policy external-engine delete -vserver <svm> -engine-name <engine>
```

### Full Environment Cleanup

```bash
# Reverse deployment order
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-observability-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-scanning-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-events-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-storage-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-network-dev

# Clean up Secrets Manager
aws secretsmanager delete-secret \
  --secret-id fsxn-cyber-resilience-fsxadmin \
  --force-delete-without-recovery
```

> **Note**: FSx for ONTAP deletion takes ~30 minutes. The storage stack will remain in
> `DELETE_IN_PROGRESS` until the file system is fully removed. A final backup is created
> by default unless `SkipFinalBackup=true` was specified.

---

## Troubleshooting

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Stack fails with `VpceAlreadyExists` | Duplicate VPC Endpoint in VPC | Run `preflight-check.sh`; use existing EP or different subnets |
| Lambda cannot reach ONTAP REST API | SG missing Lambda→FSx TCP/443 | Check `SgLambda` egress and `SgFsx` ingress rules |
| FPolicy engine creation fails | Scanner not reachable on TCP/1344 | Verify scanner SG ingress and FSx SG egress on ICAP port |
| ARP enable fails on FlexGroup | ONTAP version < 9.13.1 | Upgrade ONTAP or use FlexVol |
| S3 Gateway EP route not propagating | Route table not associated | Verify both isolated and private route tables are in EP config |
| Scanner signature update fails | No outbound internet | Enable NAT Gateway (`EnableNatGateway=true`) or use S3 mirror |
| SQS messages going to DLQ | Lambda processing error | Check CloudWatch Logs for event-transformer Lambda |

---

## Security Group Reference

| Security Group | Ingress | Egress | Purpose |
|----------------|---------|--------|---------|
| `sg-fsx` | NFS 2049 (client, scanners), SMB 445/139 (client), HTTPS 443 (Lambda) | ICAP 1344 (scanners), HTTPS 443 (VPC CIDR) | FSx for ONTAP ENIs |
| `sg-vscan` | ICAP 1344 (FSx) | NFS 2049 (FSx), HTTPS 443 (0.0.0.0/0 via NAT) | TrendAI Vscan |
| `sg-deep-instinct` | ICAP 1344 (FSx) | NFS 2049 (FSx), HTTPS 443 (0.0.0.0/0 via NAT) | Deep Instinct agent |
| `sg-lambda` | — | HTTPS 443 (VPC CIDR) | Lambda functions |
| `sg-vpc-endpoints` | HTTPS 443 (VPC CIDR) | — | Interface Endpoints |

---

## Related Documentation

- [Existing FSx for ONTAP Integration](../deployment-guide-existing-fsxn.md)
- [Cost & License Details](../verification-environment-cost.md)
- [Architecture Overview](../architecture/overview.md)
- Runbooks: [ARP Triage](../runbooks/arp-alert-triage.md) | [Ransomware Recovery](../runbooks/ransomware-recovery.md) | [Scanner Failover](../runbooks/scanner-failover.md)

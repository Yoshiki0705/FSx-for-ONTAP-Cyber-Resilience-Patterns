# Deployment Guide — FSx for ONTAP Cyber Resilience Patterns

## Overview

This guide covers the deployment of 11 CloudFormation templates that compose the
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
| Multi-Admin Verification (MAV), ONTAP version only; refused to fsxadmin on FSx for ONTAP 9.18.1P6 in one observation [E-025] | 9.11.1 |
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
| 7 | `cost-scheduler.yaml` | Stop/start scanner EC2 during off-hours (non-prod) | ~2 min | scanning |

SnapMirror lag monitoring is not a template in this repository. See [SnapMirror Lag Monitoring](#snapmirror-lag-monitoring).

### Phase 3 — Enterprise / Multi-Account

| # | Template | Description | Deploy Time | Dependencies |
|---|----------|-------------|-------------|--------------|
| 8 | `hub-aggregation.yaml` | Central EventBridge bus for aggregated security events | ~2 min | None (hub account) |
| 9 | `spoke-monitoring.yaml` | Cross-account EventBridge forwarding (StackSet-ready) | ~2 min | hub-aggregation |
| 10 | `siem-integration.yaml` | Security Hub, SIEM forwarder (Splunk/QRadar/CEF), compliance collector | ~5 min | event-driven |
| 11 | `main.yaml` | Root nested stack (orchestrates network + storage + event-driven) | ~35 min | S3 bucket with templates |

---

## Lambda Concurrency and Dead-Letter Queue (siem-integration)

The EventBridge-triggered Lambda function in `siem-integration.yaml` caps its concurrency and keeps failed events in its own SQS queue. `siem-integration.yaml` is not nested in `main.yaml`, so deploy it as a separate stack.

| Function | Template | Reserved concurrency | Dead-letter queue | Alarm |
|----------|----------|----------------------|-------------------|-------|
| `SecurityHubPublisherLambda` | `siem-integration.yaml` | `SecurityHubPublisherReservedConcurrency` (default 10) | `SecurityHubPublisherDlq` | `SecurityHubPublisherDlqAlarm` |

- The queue is encrypted with the AWS managed key `alias/aws/sqs`, keeps messages for 14 days, and is deleted with its stack.
- The execution role may call `sqs:SendMessage` only on this queue.
- The alarm fires when 1 or more messages are visible in the queue (5-minute period) and notifies the SNS topic in `SecurityAlertTopicArn`. A message in the queue means the function failed after Lambda's retries; the event stays there for 14 days for inspection.
- `SecurityHubPublisherReservedConcurrency` (Number, default 10, minimum 1): Lambda keeps 100 executions of the account's concurrency unreserved, so the value can be at most the account's unreserved concurrency minus 100. See [Lambda reserved concurrency](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html). In an account with the default limit of 1,000 executions and no other reservations, 900 is the upper bound.
- `EventTransformerLambda` in `event-driven.yaml` reads from SQS queues. For SQS event sources, AWS places the dead-letter queue on the source queue instead of the function, and both source queues already have a `RedrivePolicy`. The template records this as a Checkov skip for `CKV_AWS_116`.
- Not measured: these changes were checked with cfn-lint, Checkov and unit tests only, and have not been deployed.

## SnapMirror Lag Monitoring

This repository has no template for SnapMirror lag monitoring. Use the Terraform module [`terraform/fsxn-ontap-custom-metrics`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/tree/main/terraform/fsxn-ontap-custom-metrics) in the Observability repository. It runs a VPC Lambda function that reads `GET /api/snapmirror/relationships` on the destination file system, publishes the `FSxONTAP/SnapMirror` metrics (including `SnapMirrorLagSecondsMax` and `SnapMirrorUnhealthyCount`), and creates CloudWatch alarms for lag, unhealthy relationships and a stopped collector. The module README lists the metrics, alarms and IAM permissions.

### Settings to choose

| Setting | Value | Note |
|---------|-------|------|
| Where to deploy | The DR Region, against the destination file system | The collector reads the destination side, and its metrics and alarms are created in the Region where the module runs |
| `file_system_id` | Destination file system ID | |
| `enable_snapmirror_collector` | `true` (module default) | Set `enable_qtree_collector = false` if you do not want the qtree collector |
| `snapmirror_lag_threshold_seconds` | RPO in minutes × 2 × 60 | 1,800 seconds for a 15-minute RPO. The module default is 10,800 seconds and accepts 60 to 2,592,000 |
| `notification_email` | Responder address | The module creates an SNS topic in the same Region and subscribes this address |

### Notification target

A CloudWatch alarm was rejected when it named an SNS topic in another Region [E-038]. Test on 2026-11-12 in one account: `PutMetricAlarm` for an alarm in `us-west-2` with a topic in `ap-northeast-1` returned a `ValidationError`, while the same setup with the topic in `us-west-2` delivered the notification to a subscribed SQS queue. So the `SecurityAlertTopic` created by `event-driven.yaml` in the primary Region cannot be the target of the DR-side alarms. Subscribe responders to the topic the module creates in the DR Region as well. Other Region pairs were not tested.

### Replacing the removed `dr-replication.yaml`

The `LagMonitorLambda` in the removed `dr-replication.yaml` was a placeholder: it logged an invocation and returned, and published no metric. Its alarm read `SnapMirrorLagMinutes`, which nothing published, and treated missing data as normal, so it could not fire. If you deployed that stack, deploy the module first and confirm that the `CollectorSucceeded` metric is 1 in the `FSxONTAP/SnapMirror` namespace. Then delete the old stack. Doing it in the other order leaves a period with no lag alarm. The removed template is in the git history of this repository.

### Not measured

- The module README records one sample run on 2026-10-08 in `ap-northeast-1`, with a relationship between two volumes in one SVM. SnapMirror between two file systems (cluster peering, reading the destination across clusters) is listed there as not yet tested. Run the module in a non-production account first.
- An uninitialized relationship reports `healthy: true` with no `lag_time`, so neither SnapMirror alarm fires for it (observed once, in the module README's sample run).
- Neither the module nor the notification-target test was run against this repository's stacks.

## Security Alert Topic Encryption

`event-driven.yaml` encrypts `SecurityAlertTopic` with a customer managed key (`AlertTopicKey`, key rotation on) instead of the AWS managed key `aws/sns`. In a test, a CloudWatch alarm action that named a topic encrypted with `aws/sns` failed [E-039]. Five alarms notify this topic: the dead-letter queue alarm in `event-driven.yaml`, the three alarms in `observability.yaml`, and the dead-letter queue alarm in `siem-integration.yaml`. Going by that test, these alarms could not notify through the topic while it used `aws/sns`. The stack also had no topic policy, and in a test an EventBridge rule delivered nothing to a topic that has only the default policy [E-040], so the `RuleNotification` rule would not have delivered either.

### What the stack creates

| Resource | Purpose |
|----------|---------|
| `AlertTopicKey` and its alias | Encrypts the topic. The account root administers the key. CloudWatch and EventBridge in the same account may call `kms:Decrypt` and `kms:GenerateDataKey*` |
| `SecurityAlertTopicPolicy` | Lets the account owner manage the topic, and lets CloudWatch and EventBridge in the same account publish |
| KMS permission on `StepFunctionsExecutionRole` | Lets the quarantine workflow publish alerts to the encrypted topic |
| KMS permission on `ComplianceCollectorRole` in `siem-integration.yaml` | The key lives in another stack, so the permission is limited to use through SNS (`kms:ViaService`) |
| Output `AlertTopicKeyArn` | The key ARN for other publishers |

### Permission another publisher needs

An identity that calls `sns:Publish` on the topic also needs `kms:GenerateDataKey` and `kms:Decrypt` on `AlertTopicKeyArn`, or the same `kms:ViaService` condition as `ComplianceCollectorRole`. A role with only `sns:Publish` got `KMSAccessDenied`.

### Measured results

Test on 2026-11-12 (UTC) in one account in `ap-northeast-1`, one run per case.

| Case | Result |
|------|--------|
| Alarm to a topic encrypted with `aws/sns` | Action failed, nothing delivered [E-039] |
| Alarm to a topic with no encryption | Delivered [E-039] |
| Alarm to a topic encrypted with a customer managed key, key policy as above | Delivered [E-039] |
| EventBridge rule to a topic with only the default topic policy | Nothing delivered, `FailedInvocations` 2 [E-040] |
| EventBridge rule to a topic whose policy allows `events.amazonaws.com`, with or without the customer managed key | Delivered [E-040] |
| Role with `sns:Publish` only, then with the `kms:ViaService` permission added | `KMSAccessDenied`, then delivered |
| Rule on a custom event bus to a topic encrypted with `aws/sns`, topic policy allowing `events.amazonaws.com` | Nothing delivered, `FailedInvocations` 2 [E-041] |
| Rule on a custom event bus to a topic encrypted with a customer managed key, key policy and topic policy allowing `events.amazonaws.com` | Delivered [E-041] |

### Hub alert topic

`hub-aggregation.yaml` gets the same change for `HubAlertTopic`, which only the hub EventBridge rule (`HubNotificationRule`) publishes to: a customer managed key `HubAlertTopicKey` (rotation on, 30-day deletion window), a topic policy `HubAlertTopicPolicy`, and the output `HubAlertTopicKeyArn`. Only `events.amazonaws.com` of the hub account may publish, because the hub stack has no alarms. A topic encrypted with `aws/sns` received nothing from the rule even with a topic policy [E-041].

### Not measured

- The cases above used standalone resources. A deployment of these templates, including an in-place update of an existing topic from `aws/sns` to `AlertTopicKey`, was run once and is recorded in [Verifying the Alert Path After Deployment](alert-path-verification.md#results).
- The key's monthly cost. The key is deleted with the stack after a 30-day waiting period.
- The hub topic was tested with the rule and the topic in one account. Events forwarded from a spoke account to the hub bus were not tested.

## Quarantine Workflow Failure Alarm

`event-driven.yaml` creates `QuarantineExecutionsFailedAlarm`. It watches the `ExecutionsFailed` metric (namespace `AWS/States`, dimension `StateMachineArn`) of the quarantine state machine. One failed execution within 5 minutes raises the alarm, which notifies `SecurityAlertTopic`. Executions that fail to reach `NotifyFailure` (for example on a `States.Runtime` error, which no `Catch` in the definition handles) are counted here, and the failed state is in the execution history.

- A missing datapoint counts as healthy (`notBreaching`).
- Only `ExecutionsFailed` is watched. `ExecutionsTimedOut` and `ExecutionsAborted` are not. The definition sets no execution timeout, and the 24-hour approval wait is caught and escalated by `EscalateTimeout`.
- `NotifyFailure` and `EscalateTimeout` retry the publish 3 times and then end in the `NotificationFailed` Fail state. A topic that cannot be published to therefore still produces a failed execution, which this alarm counts. This alarm notifies the same topic, so if the topic itself is the problem the alarm may reach nobody. Check the execution history in that case.
- `SendAlert` runs after the export policy is restricted. If it still fails after 3 retries, the execution continues to `WaitForApproval` and stores the error in `$.alertError`, which the approval message carries. The volume stays restricted, and the approval step and its 24-hour escalation still run. Confirmed with the Step Functions TestState API on a mocked failure (retries used up): the failure was caught and the next state was `WaitForApproval`. A deployed execution was not run.
- CloudWatch metrics for Step Functions are delivered on a best-effort basis, so a datapoint can arrive late or not at all ([Step Functions metrics](https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html)).

Measured on 2026-11-12 (UTC) in one account in `ap-northeast-1`, one run: a state machine whose only state is `Fail`, with an alarm of the same shape (period 60 seconds). The execution ended in `FAILED`, the metric showed a Sum of 1, the alarm reached `ALARM` 104 seconds after the execution, and the notification arrived at a subscribed queue. A deployment of this template with the 300-second period was run once on 2026-11-13: a failed execution of the quarantine workflow raised the alarm about 49 seconds after it started ([results](alert-path-verification.md#results)).

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

#### Optional: Customer Managed KMS Keys

The stacks create no KMS keys of their own. With the default parameters, encryption is unchanged: CloudWatch Logs log groups use the default CloudWatch Logs encryption, and Lambda environment variables use the default key that Lambda provides. A customer managed key is used only when you pass a key ARN.

| Parameter | Templates | Applies to |
|-----------|-----------|------------|
| `LogGroupKmsKeyArn` | `network.yaml`, `event-driven.yaml`, `main.yaml` | VPC Flow Logs log group (created only when the stack creates the VPC) and the Step Functions log group |
| `LambdaEnvKmsKeyArn` | `event-driven.yaml`, `siem-integration.yaml`, `main.yaml` (passed to the Event-Driven stack only) | Environment variables of the quarantine action, event transformer and Security Hub publisher Lambda functions |

Key requirements for `LogGroupKmsKeyArn`, from the [CloudWatch Logs documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html):

- The key is symmetric. The key policy allows the CloudWatch Logs service principal of the same Region.
- The identity that deploys the stack has `kms:DescribeKey` on the key, because associating a key with a log group requires it.
- Setting `KmsKeyId` on an existing log group is an update with no interruption ([`AWS::Logs::LogGroup`](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-loggroup.html)). The documentation says newly ingested data uses the key. It does not say whether data ingested earlier is re-encrypted.
- Reading data encrypted with the key requires the key to stay enabled and usable by CloudWatch Logs. Keep the key for as long as the logs are retained.

Key requirements for `LambdaEnvKmsKeyArn`, from the [Lambda documentation](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html):

- The identity that deploys the stack has `kms:CreateGrant` and `kms:Encrypt` on the key. Lambda uses those permissions to create a grant on the key.
- Users who view the environment variables need `kms:Decrypt`. Users without it can still manage the function.
- Changing `KmsKeyArn` on an existing function is an update with no interruption ([`AWS::Lambda::Function`](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-function.html)).

Not confirmed: whether the Step Functions execution role and the VPC Flow Logs role need KMS permissions of their own (the CloudWatch Logs page lists KMS permissions for principals that call `PutLogEvents`), and whether the Lambda execution roles need `kms:Decrypt` at run time (the Lambda page asks for it only when client-side encryption helpers are used). These templates were checked with cfn-lint and Checkov only; no stack was deployed with a key.

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

ARP and FPolicy are set with the ONTAP CLI / REST steps, outside stack management, so they
remain on FSx for ONTAP after the stack is deleted. To revert them manually:

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

- [Verifying the Alert Path After Deployment](alert-path-verification.md)
- [Existing FSx for ONTAP Integration](../deployment-guide-existing-fsxn.md)
- [Cost & License Details](../verification-environment-cost.md)
- [Architecture Overview](../architecture/overview.md)
- Runbooks: [ARP Triage](../runbooks/arp-alert-triage.md) | [Ransomware Recovery](../runbooks/ransomware-recovery.md) | [Scanner Failover](../runbooks/scanner-failover.md)

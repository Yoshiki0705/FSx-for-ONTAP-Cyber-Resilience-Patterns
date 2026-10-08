# Event-Driven Ransomware Response with AWS Step Functions

> Automated quarantine, forensics, and recovery workflows triggered by file security events.

> **Update (2026-10)**
> - I have not measured how long this Step Functions path takes, so I corrected the timing claim in the Introduction. The 2-minute figure in the README is a measurement of the Lambda path in the companion Observability repository (ONTAP 9.17.1P7D1).
> - `templates/event-driven.yaml` is deployed as a nested stack of `templates/main.yaml`, together with `network.yaml` and `storage.yaml`. The other 8 templates are deployed individually. See the [architecture overview](../architecture/overview.md).
> - Export-policy isolation covers NFS / SMB. FPolicy also receives NFS and SMB operations only [E-015]. Operations through S3 Access Points are contained with the access point policy and IAM (see the [Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md)).
> - Where this response sits in the NIST CSF 2.0 Respond (RS) function is in the [framework mapping](../en/cyber-resilience-framework-mapping.md).

## Introduction

Third article in the series: the event-driven response layer that turns detection events into containment actions without waiting for a person to start. How long it takes has not been measured (see the update at the top).

## The Event Pipeline

```
FPolicy/ARP Event → SQS Queue → Lambda (Transformer) → EventBridge
    → Step Functions (Quarantine Workflow)
        → Forensic Snapshot
        → Export Policy Restriction (quarantine)
        → SNS Alert
        → Human Approval (24h timeout)
        → Restore or FlexClone
```

## Why This Architecture?

| Design Choice | Rationale |
|---------------|-----------|
| SQS as buffer | Decouples FPolicy from processing; handles burst events |
| EventBridge for routing | Content-based filtering; multiple targets from one event |
| Step Functions for orchestration | Visible state machine; built-in retry; human-in-the-loop |
| Lambda for ONTAP API | VPC access to management endpoint; stateless |

## The Quarantine Workflow (Step Functions ASL)

Nine states handling the full incident lifecycle:

1. **CreateForensicSnapshot** — Preserve evidence before any changes
2. **RestrictExportPolicy** — Block NFS/SMB access to the volume (S3 Access Points are contained separately with the access point policy and IAM)
3. **SendAlert** — SNS notification to security team
4. **WaitForApproval** — SQS task token pattern (24h timeout)
5. **ApprovalDecision** — Choice state: approved or rejected
6. **RestoreAccess** — Re-enable export policy (false positive)
7. **CreateFlexClone** — Read-only clone for forensics (confirmed attack)
8. **NotifyFailure** — Error handling notification
9. **EscalateTimeout** — 24h timeout escalation

## The Human-in-the-Loop Pattern

```python
# Step Functions sends task token to SQS Approval Queue
# Security team retrieves message, investigates, then:

# Approve (restore access):
aws stepfunctions send-task-success \
  --task-token "<token>" \
  --task-output '{"approved": true}'

# Reject (create forensic clone):
aws stepfunctions send-task-success \
  --task-token "<token>" \
  --task-output '{"approved": false}'
```

This pattern ensures automated speed for containment while maintaining human judgment for resolution.

## Lambda: ONTAP REST API Integration

The Quarantine Lambda uses the shared `OntapClient` for ONTAP operations:

```python
# Quarantine action
client.restrict_export_policy(policy_id)  # Block all access

# Restore action (after investigation)
client.restore_export_policy(policy_id, client_match="10.0.0.0/16")
```

The client handles:
- Secrets Manager credential retrieval
- SSL certificate verification (FSx self-signed)
- Async job polling for long-running operations
- Retry with exponential backoff

## EventBridge Rule Patterns

Two rules classify events for routing:

```yaml
# High-severity → Quarantine workflow
EventPattern:
  source: [fsxn.cyber-resilience.fpolicy, fsxn.cyber-resilience.arp]
  detail-type: [MalwareDetected, RansomwareDetected]

# All events → Notification
EventPattern:
  source: [{prefix: fsxn.cyber-resilience}]
```

## Observability

CloudWatch custom metrics track:
- `SecurityEventsReceived` — pipeline throughput
- `MalwareDetected` — detection count (by scanner)
- `QuarantineExecuted` — containment actions
- `ScanLatencyP99` — scanning performance

Alarms trigger at:
- 10+ malware detections in 5 minutes (burst attack)
- Any ransomware alert (ARP)
- Scan latency > 100ms

## Implementation

Full source code with 326 tests:

**Repository**: [github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns)

Key files:
- [`templates/event-driven.yaml`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns/blob/main/templates/event-driven.yaml) — CloudFormation template
- [`solutions/event-driven-response/lambda/`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns/tree/main/solutions/event-driven-response/lambda) — Lambda implementations
- [`docs/runbooks/ransomware-recovery.md`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns/blob/main/docs/runbooks/ransomware-recovery.md) — Recovery runbook

## 日本語サマリ

> **Update (2026-10)**
> - この Step Functions 経路の所要時間は測っていないので、Introduction の所要時間の記述を直した。README の 2 分はコンパニオンの Observability リポジトリの Lambda 経路の実測値（ONTAP 9.17.1P7D1）。
> - `templates/event-driven.yaml` は `templates/main.yaml` の nested stack として `network.yaml`・`storage.yaml` と一緒にデプロイされ、残り 8 本は個別にデプロイする。[architecture overview](../architecture/overview.md) を参照。
> - export-policy による隔離の対象は NFS / SMB。FPolicy が受け取るのも NFS と SMB の操作だけ [E-015]。S3 Access Points 経由の操作は、アクセスポイントポリシーと IAM で封じ込める（[Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md)）。
> - この対応が NIST CSF 2.0 の Respond（RS）のどこに当たるかは [framework mapping](../ja/cyber-resilience-framework-mapping.md) にある。

シリーズ第3回：イベント駆動型の自動隔離ワークフロー実装。FPolicy/ARP イベントから Step Functions による自動封じ込め、人間承認パターン (Human-in-the-Loop)、FlexClone によるフォレンジック環境分離を解説。

---

*Yoshiki Fujiwara — NetApp Cloud Solutions Architect, AWS Community Builder (Storage)*


---

**Series Navigation:**
← [Part 2: ONTAP Native Security](02-ontap-native-security.md) | [Part 4: Operating at Scale →](04-operating-at-scale.md)

# Operating FSx for ONTAP Security at Scale

> Production readiness patterns: HA scanners, ARP lifecycle, DR, cost optimization, and SIEM integration.

## Introduction

Final article in the series: taking the architecture from deployment to production-grade operations. Covers high availability, automated lifecycle management, disaster recovery, cost control, and enterprise SIEM integration.

## Multi-AZ Scanner HA

### Problem
Single-instance scanners are a SPOF (Single Point of Failure). If the scanner goes down, FPolicy enters passthrough mode — no scanning protection.

### Solution: Auto Scaling Group + Multi-AZ

```yaml
VscanAutoScalingGroup:
  MinSize: 1
  MaxSize: 4
  DesiredCapacity: 2
  VPCZoneIdentifier: [subnet-az1, subnet-az2]
```

FPolicy engine references both AZ scanner IPs as primary and secondary servers. ONTAP natively fails over to the secondary within ~30 seconds.

### Health Check Lambda

A dedicated Lambda tests TCP connectivity to port 1344 every 60 seconds:
- Publishes `ScannerHealthy` CloudWatch metric per instance
- Triggers alarms when any scanner becomes unreachable
- ASG replaces unhealthy instances automatically

## ARP Lifecycle Automation

### The Manual Problem

ARP requires a learning period (30+ days) before activation. Without automation:
- Teams forget to transition to active mode
- Volumes remain in "detection only" for months
- No systematic tracking across dozens of volumes

### The Automated Solution

```
DynamoDB State Table → Daily EventBridge Trigger → Lambda Check
    → If elapsed >= learning_days:
        → SNS notification
        → ONTAP API: enable ARP (active)
        → Update DynamoDB state
```

Each volume is tracked individually with its own learning start date and configurable period.

## DR: SnapMirror Cross-Region Replication

### Why DR Matters for Ransomware

If ransomware compromises a region-level resource (admin credentials, IAM role), the primary copy may be corrupted. A cross-region SnapMirror target provides:
- Isolated recovery point (different credentials)
- Configurable RPO (15 minutes default)
- In-flight encryption via TLS cluster peering
- Immutable if combined with SnapLock on the destination

### Lag Monitoring

A Lambda runs every 5 minutes:
1. Queries SnapMirror relationship status via ONTAP REST API
2. Calculates current lag vs configured RPO
3. Publishes `SnapMirrorLagMinutes` metric
4. Alerts when lag > 2x RPO

## Cost Optimization: Scheduled Scanner Control

### Dev/Staging Savings

Scanners in non-production environments don't need 24/7 operation:

```yaml
# EventBridge Scheduler
StopSchedule: cron(0 11 ? * MON-FRI *)  # 20:00 JST
StartSchedule: cron(0 23 ? * SUN-THU *) # 08:00 JST
```

Tag-based IAM scoping ensures production instances are never affected:
```json
{"Condition": {"StringEquals": {"aws:ResourceTag/Environment": "dev"}}}
```

**Estimated savings**: ~$98/month per scanner type (c6g.xlarge × 12h/day × 30 days).

## SIEM Integration

### AWS Security Hub

All security events are published as ASFF findings:
- Deterministic FindingId for deduplication
- Severity mapping (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Resource linkage to FSx for ONTAP file system ARN

### Third-Party SIEM (Splunk / QRadar)

For organizations with existing SIEM investments:
- **Splunk**: HEC JSON format
- **QRadar**: LEEF format
- **Generic**: CEF format

PII redaction is applied before forwarding to external endpoints (configurable per field).

## Multi-Account Patterns

For organizations with multiple AWS accounts running FSx for ONTAP:

```
Spoke Account A (Workload) ──EventBridge──→ Hub Account (Security)
Spoke Account B (Workload) ──EventBridge──→ Hub Account (Security)
Spoke Account C (Workload) ──EventBridge──→ Hub Account (Security)
```

- Spoke template is StackSet-deployable
- Hub account aggregates findings in Security Hub
- Cross-account IAM: minimal `events:PutEvents` only

## Compliance Evidence

Daily automated compliance checks verify:
- ARP enabled on all production volumes (SOC2 CC6.1)
- FPolicy active on all SVMs (SOC2 CC6.6)
- Encryption at rest verified (ISO27001 A.8.1)
- Snapshot policies assigned (ISO27001 A.12.3)

Reports stored in S3 with Object Lock (COMPLIANCE mode, 365-day retention).

## Lessons Learned

1. **Start ARP in learning mode** — production traffic patterns vary; false positives without learning are disruptive
2. **FPolicy `is_mandatory: false`** — availability over security for most workloads; compensate with monitoring. Note that `true` would not close the S3 access point path either: operations arriving that way are not notified to FPolicy and are not blocked (measured 2026-08-26, ONTAP 9.18.1P3D1). ARP does see that path
3. **Lambda packaging matters** — content-hash-based idempotent packaging saves deployment time and avoids unnecessary updates
4. **Test the quarantine workflow** — send synthetic malware events; verify the full flow before you need it in production
5. **Monitor DLQ** — events in the DLQ mean your pipeline has gaps; alarm at ≥1

## Project Summary

| Metric | Value |
|--------|-------|
| CloudFormation templates | 12 |
| Lambda functions | 10 |
| Tests | 285 |
| Code coverage | 87% |
| Deployment time (all stacks) | ~15 minutes |
| Lambda cold start (measured) | ~480ms (Python 3.12 ARM64, 128MB) |
| Event processing (SQS → EventBridge) | ~320ms |

**Repository**: [github.com/Yoshiki0705/fsxn-cyber-resilience-patterns](https://github.com/Yoshiki0705/fsxn-cyber-resilience-patterns)

## 日本語サマリ

シリーズ最終回：本番運用に必要なパターン群を解説。Multi-AZ HA、ARP ライフサイクル自動化、DR/SnapMirror、コスト最適化、SIEM 連携 (Security Hub + Splunk/QRadar)、マルチアカウント、コンプライアンス証跡収集。教訓と運用知見のまとめ。

---

*Yoshiki Fujiwara — NetApp Cloud Solutions Architect, AWS Community Builder (Storage)*


---

**Series Navigation:**
← [Part 3: Event-Driven Response](03-event-driven-response.md) | Series Complete

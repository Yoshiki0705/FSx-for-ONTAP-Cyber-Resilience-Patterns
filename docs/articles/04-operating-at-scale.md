# Operating FSx for ONTAP Security at Scale

> Production readiness patterns: HA scanners, ARP lifecycle, DR, cost optimization, and SIEM integration.

> **Update (2026-10)**
> - A cross-Region SnapMirror destination in the same AWS account is not isolated from an account-level compromise (inference), and I corrected the DR section to say so. The options for that case are SnapMirror / SnapVault to a separate account, or an AWS Backup logically air-gapped vault, which has supported FSx for ONTAP since 2026-09 ([vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md); documentation only, not validated in a real environment).
> - Copying to the vault requires a file system encrypted with a customer managed key. Backups encrypted with an AWS managed key are not copied [E-009].
> - Some parts of the body exist as code only. No template deploys the ARP lifecycle, scanner health check, third-party SIEM forwarder or compliance collector functions. The Security Hub publisher is deployed only when `EnableSecurityHub` is `true`, and the deployed code is a placeholder that returns `{"statusCode": 200}`. Of the 10 handler modules, the templates deploy the code of 2 (`quarantine_action` and `event_transformer`).
> - I updated the test and Lambda counts in the Project Summary. Coverage, deployment time and latency are the values at the time of writing and have not been measured again.

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

As of 2026-10, no template deploys this Lambda (`solutions/ontap-native/lambda/scanner_health_check.py`). The Auto Scaling group in `templates/scanning-ha.yaml` replaces instances on EC2 status checks (`HealthCheckType: EC2`).

## ARP Lifecycle Automation

### The Manual Problem

Original-generation ARP (9.10.1–9.15.1 on NAS FlexVol, up to 9.17.1 on FlexGroup) requires a learning period (30+ days) before activation; ARP/AI (9.16.1+ on FlexVol, 9.18.1+ on FlexGroup) has none. Without automation:
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

Each volume is tracked individually with its own learning start date and configurable period. The code is in `solutions/ontap-native/lambda/arp_lifecycle.py`; no template deploys the function, the DynamoDB table or the schedule (2026-10).

## DR: SnapMirror Cross-Region Replication

### Why DR Matters for Ransomware

If ransomware reaches the primary file system or the credentials that manage it, the primary copy may be corrupted. A cross-region SnapMirror target provides:
- A recovery point in another Region. It can be isolated from an account-level compromise only when the destination is in a separate AWS account with separate credentials (inference, unverified); a destination in the same account is managed with the same credentials. For that case, use SnapMirror / SnapVault to a separate account or an [AWS Backup logically air-gapped vault](../data-protection/aws-backup-logically-air-gapped-vault.md) (see "How to Choose an Isolation Option" in the guide)
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

The code is in `solutions/siem/security_hub_publisher.py`. The function that `templates/siem-integration.yaml` deploys (only when `EnableSecurityHub` is `true`) has placeholder code that returns `{"statusCode": 200}`, so nothing is published from the templates alone (2026-10).

### Third-Party SIEM (Splunk / QRadar)

For organizations with existing SIEM investments:
- **Splunk**: HEC JSON format
- **QRadar**: LEEF format
- **Generic**: CEF format

PII redaction is applied before forwarding to external endpoints (configurable per field). `templates/siem-integration.yaml` creates only the forwarder queue and does not deploy the function (`solutions/siem/siem_forwarder.py`) (2026-10).

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

Reports stored in S3 with Object Lock (COMPLIANCE mode, 365-day retention). The daily rule in `templates/siem-integration.yaml` targets a function named `<ProjectName>-compliance-<Environment>`, but the template does not create that function (code: `solutions/compliance/compliance_collector.py`, 2026-10).

## Lessons Learned

1. **Start ARP in learning mode** (original-generation ARP only; ARP/AI has no learning period) — production traffic patterns vary; false positives without learning are disruptive
2. **FPolicy `is_mandatory: false`** — availability over security for most workloads; compensate with monitoring. Note that `true` would not close the S3 access point path either: operations arriving that way are not notified to FPolicy and are not blocked (measured 2026-08-26, ONTAP 9.18.1P3D1) [E-015]. ARP does see that path
3. **Lambda packaging matters** — content-hash-based idempotent packaging saves deployment time and avoids unnecessary updates
4. **Test the quarantine workflow** — send synthetic malware events; verify the full flow before you need it in production
5. **Monitor DLQ** — events in the DLQ mean your pipeline has gaps; alarm at ≥1

## Project Summary

| Metric | Value |
|--------|-------|
| CloudFormation templates | 12 |
| Lambda handler modules | 10 (2 deployed by templates with their code) |
| Tests | 326 |
| Code coverage | 87% |
| Deployment time (all stacks) | ~15 minutes |
| Lambda cold start (measured) | ~480ms (Python 3.12 ARM64, 128MB) |
| Event processing (SQS → EventBridge) | ~320ms |

**Repository**: [github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns)

## 日本語サマリ

> **Update (2026-10)**
> - 同じ AWS アカウントの中にあるクロスリージョンの SnapMirror の宛先は、アカウント単位の侵害からは隔離されない（推論）。DR の節をそう直した。その場合の選択肢は、別アカウントへの SnapMirror / SnapVault か、2026-09 から FSx for ONTAP に対応した AWS Backup の論理エアギャップボールト（[vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md)、文書のみで実環境では未検証）。
> - ボールトへのコピーには、カスタマーマネージドキーで暗号化したファイルシステムが要る。AWS マネージドキーで暗号化したバックアップはコピーされない [E-009]。
> - 本文の一部はコードだけが存在する。ARP lifecycle、scanner health check、third-party SIEM forwarder、compliance collector の関数はどのテンプレートもデプロイしない。Security Hub publisher は `EnableSecurityHub` が `true` のときだけデプロイされ、中身は `{"statusCode": 200}` を返すだけのプレースホルダ。handler モジュール 10 本のうち、テンプレートがコードごとデプロイするのは 2 本（`quarantine_action` と `event_transformer`）。
> - Project Summary のテストと Lambda の数を更新した。coverage・デプロイ時間・レイテンシは執筆時の値で、測り直していない。

シリーズ最終回：本番運用に必要なパターン群を解説。Multi-AZ HA、ARP ライフサイクル自動化、DR/SnapMirror、コスト最適化、SIEM 連携 (Security Hub + Splunk/QRadar)、マルチアカウント、コンプライアンス証跡収集。教訓と運用知見のまとめ。

---

*Yoshiki Fujiwara — NetApp Cloud Solutions Architect, AWS Community Builder (Storage)*


---

**Series Navigation:**
← [Part 3: Event-Driven Response](03-event-driven-response.md) | Series Complete

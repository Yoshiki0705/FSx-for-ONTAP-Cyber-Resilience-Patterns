# Companion Repository Integration Guide

This document maps the components in the [FSx-for-ONTAP-Observability-integrations](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations) repository to the security layers defined in this cyber-resilience-patterns repository, and explains how they work together as a unified defense-in-depth architecture.

## Where each question is answered

**This repository holds the implementation patterns.** Design guidance lives in the
[FSx for ONTAP Adoption Playbook](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook), and working implementations live in the observability
repository. **The same material is not duplicated across them** -- a copy that stops being updated
outlives the one that was corrected.

| Reader's question | Where it is answered |
|-------------------|----------------------|
| How to configure SnapLock or snapshot locking (templates, CLI, REST) | Here, [`docs/ontap-native/`](../ontap-native/) |
| Whether to enable SnapLock, which retention mode, **what is irreversible** | Playbook [`domains/data-protection`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/data-protection/README.md) |
| How to enable ARP, and which model generation applies | Here, [`docs/ontap-native/arp-configuration.md`](../ontap-native/arp-configuration.md) |
| Approval for irreversible operations, audit log design, authorization layers | Playbook [`domains/security-governance`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/security-governance/README.md) |
| Choosing among ARP, TrendAI File Security and Deep Instinct | Here, [`docs/comparison-security-layers.md`](../comparison-security-layers.md) |
| Working implementation from detection to blocking (Lambda, EMS webhook, FPolicy server) | [FSx-for-ONTAP-Observability-integrations](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations) |
| S3 access point lifecycle and serverless integration | [FSx for ONTAP S3 Access Points Serverless Patterns](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns) |

## Architecture Layer Mapping

The table below shows which components from the observability repo plug into each security layer of this repo.

| Cyber Resilience Layer (this repo) | Observability Repo Component | Integration Point |
|------------------------------------|------------------------------|-------------------|
| **Event-driven response** | `shared/python/ontap_response.py` + `shared/templates/automated-response.yaml` | SNS → Lambda → ONTAP REST API blocking (SMB name-mapping deny, NFS export-policy deny, NACL deny) |
| **Event-driven response** | `shared/templates/automated-response-ttl.yaml` | TTL-based auto-unblock via EventBridge Scheduler |
| **Storage-native (ARP)** | EMS Webhook → API Gateway → Lambda pipeline | ARP/AI detection events forwarded to observability platforms |
| **Storage-native (FPolicy)** | `shared/fpolicy-server/` | FPolicy external server for real-time file operation capture |
| **Audit & visibility** | S3 Access Point → Lambda → vendor integrations | Audit log delivery to Datadog, Splunk, Elastic, New Relic, etc. |
| **Data protection** | `shared/templates/restore-verification.yaml` | Verified-clean recovery point (FlexClone + scan + verdict) |
| **Data protection** | Content-level PII classification scanner | Amazon Comprehend-based file content discovery (CSF 2.0 Identify) |

## How the Two Repos Complement Each Other

```
┌─────────────────────────────────────────────────────────────────┐
│  FSx-for-ONTAP-Cyber-Resilience-Patterns (THIS REPO)            │
│                                                                 │
│  Defines the multi-layered architecture:                        │
│  • TrendAI File Security (inline scan)                          │
│  • Deep Instinct (AI zero-day prevention)                       │
│  • ONTAP native security (ARP, FPolicy, SnapLock, MAV)          │
│  • Event-driven orchestration (EventBridge → Step Functions)    │
│  • Observability dashboards & SIEM integration                  │
│  • Compliance evidence & multi-account patterns                 │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  FSx-for-ONTAP-Observability-integrations (COMPANION REPO)      │
│                                                                 │
│  Implements detection and response primitives:                  │
│  • Audit log shipping (S3 AP → Lambda → 9 vendors)             │
│  • EMS event webhooks (ARP, FPolicy, admin operations)          │
│  • CloudWatch Log Alarm (no Metric Filter required)             │
│  • Automated access blocking (ontap_response.py)                │
│  • Verified recovery point (FlexClone + extension scan)         │
│  • PII classification scanner (Amazon Comprehend)               │
│  • NIST CSF 2.0 capability map                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Division of Responsibility

| Concern | This Repo | Observability Repo |
|---------|-----------|-------------------|
| Architecture definition | Full stack (network → storage → scanning → events → dashboards) | Observability pipeline only |
| Scanning layers | TrendAI Vscan/ICAP, Deep Instinct integration | — |
| Detection (ARP/FPolicy) | Architecture patterns + CLI / REST setup steps (`docs/ontap-native/`) | Working implementation (EMS webhook, FPolicy server, CloudWatch Log Alarm) |
| Automated response | Step Functions orchestration (quarantine workflows) | Lambda direct response (1.8s measured execution; worst-case 12-15s with cold start) |
| Recovery verification | DR replication monitoring (SnapMirror lag) | Verified-clean recovery point (FlexClone + scan) |
| SIEM integration | Security Hub + SIEM connector templates | Vendor-specific integrations (Datadog, Splunk, Elastic, etc.) |
| NIST CSF 2.0 mapping | Function coverage with CSF 2.0 categories ([framework mapping](cyber-resilience-framework-mapping.md)) | Full 6-function capability map |

## Deployment Sequence

When deploying both repos together for a complete cyber-resilience stack:

1. **This repo first** — deploys the infrastructure foundation:
   ```bash
   ./scripts/deploy.sh dev network   # VPC, subnets, SGs, VPC Endpoints
   ./scripts/deploy.sh dev storage   # FSx for ONTAP, KMS (ARP/FPolicy: CLI / REST steps in docs/ontap-native/)
   ./scripts/deploy.sh dev events    # EventBridge, Step Functions
   ./scripts/deploy.sh dev scanning  # TrendAI / Deep Instinct EC2
   ```

2. **Observability repo second** — deploys detection and response on top:
   ```bash
   # Automated response (SNS → Lambda → ONTAP blocking)
   aws cloudformation deploy \
     --template-file shared/templates/automated-response.yaml \
     --stack-name fsxn-automated-response ...

   # TTL-based auto-unblock
   aws cloudformation deploy \
     --template-file shared/templates/automated-response-ttl.yaml ...

   # Verified recovery point workflow
   aws cloudformation deploy \
     --template-file shared/templates/restore-verification.yaml ...
   ```

3. **Connect detection to response** — wire observability monitors to the SNS trigger topic:
   - CloudWatch Log Alarm → SNS trigger topic
   - Datadog Monitor → SNS trigger topic
   - Elastic SIEM rule → SNS trigger topic

## Key Integration Points in Detail

### 1. ARP Detection → Automated Blocking

**Detection** (observability repo): ONTAP ARP/AI detects ransomware-like file operations → EMS event (`callhome.arw.activity.seen`) → EMS Webhook → API Gateway → Lambda → Observability platform monitor fires → SNS publish

**Response** (observability repo): SNS → Response Lambda → `contain_smb_threat` composite action:
- Creates protective Snapshot
- Blocks user via ONTAP name-mapping deny
- Disconnects active CIFS sessions
- Notifies security team

**Orchestrated response** (this repo): For multi-step workflows requiring human approval, Step Functions can subscribe to the same SNS topic or receive EventBridge events for richer orchestration (quarantine volume, notify approvers, await decision, restore or escalate).

**End-to-end timing**: Under 2 minutes from ARP detection to storage-layer block (verified on ONTAP 9.17.1P7D1).

### 2. FPolicy Event-Driven Pipeline

**This repo** defines the architecture pattern: FPolicy → EventBridge → Step Functions for file operation events.

**Observability repo** provides the working FPolicy external server (`shared/fpolicy-server/`) and the Agentic FPolicy Correlation Pattern (`docs/en/agent-fpolicy-correlation-pattern.md`) for correlating file operations with security context.

### 3. Verified Recovery After Incident

**This repo** handles DR replication monitoring (`templates/dr-replication.yaml` — SnapMirror lag alarms).

**Observability repo** handles recovery point verification:
1. Clone the candidate Snapshot (FlexClone — instant, copy-on-write)
2. Attach isolated S3 Access Point (VPC-scoped)
3. Scan for ransomware-associated file extensions
4. Record pass/fail verdict
5. Auto-cleanup (clone + access point deleted)

This is a critical Recover-phase capability (NIST CSF 2.0 RC.RP) that bridges the gap between "we have a Snapshot" and "we have a verified-clean recovery point."

### 4. NIST CSF 2.0 Coverage (Combined)

The combined assessment of both repositories is the function coverage table in the [framework mapping](cyber-resilience-framework-mapping.md), which carries the observability repository in its companion column.

## Cross-Repository References

| Topic | This Repo | Observability Repo |
|-------|-----------|-------------------|
| Automated response architecture | `solutions/event-driven-response/` | [automated-response-guide.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/automated-response-guide.md) |
| ONTAP REST API patterns | `solutions/shared/` | [ontap-rest-api-reference.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/ontap-rest-api-reference.md) |
| ARP incident response | `docs/ontap-native/` | [arp-incident-response-guide.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/arp-incident-response-guide.md) |
| EMS event reference | — | [ems-detection-capabilities.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/ems-detection-capabilities.md) |
| FPolicy operations | `solutions/event-driven-response/` | [fpolicy-operational-guide.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/fpolicy-operational-guide.md) |
| Full NIST CSF 2.0 map | [cyber-resilience-framework-mapping.md](cyber-resilience-framework-mapping.md) | [cyber-resilience-capability-map.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md) |
| Recovery verification | `templates/dr-replication.yaml` | [verified-recovery-point-guide.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/verified-recovery-point-guide.md) |
| Security addendum | — | [automated-response-security-addendum.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/automated-response-security-addendum.md) |
| Deployment prerequisites | `docs/quickstart-deployment.md` | [prerequisites.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/prerequisites.md) |

## Related Articles

- [Automated Access Blocking for FSx for ONTAP — From Ransomware Detection to Storage-Layer Deny](https://dev.to/aws-builders/automated-access-blocking-for-fsx-for-ontap-from-ransomware-detection-to-storage-layer-deny-4l2g) (EN, dev.to)
- [Amazon FSx for NetApp ONTAP の自動アクセス遮断 — ランサムウェア検知からストレージ層ブロックまで](https://hakobiya.hatenablog.com/entry/fsxn-automated-incident-response) (JA, hatena)

These articles cover the automated response module in detail — the same module referenced in `shared/python/ontap_response.py` and `shared/templates/automated-response.yaml` of the observability repo. They demonstrate the end-to-end flow from ARP/AI detection to storage-layer blocking that connects to this repo's event-driven response layer.

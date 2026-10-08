# Multi-Layered Cyber Resilience for Amazon FSx for NetApp ONTAP

> Defense-in-depth patterns combining storage-native security, AI-powered scanning, and event-driven automated response.

> **Update (2026-10)**
> - Since 2026-09, AWS Backup logically air-gapped vaults have supported FSx for ONTAP volume backups. I summarized the setup in the [vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md); this repository has not tried it in a real environment.
> - The NIST CSF 2.0 mapping now lives in one place, the [framework mapping](../en/cyber-resilience-framework-mapping.md) ([日本語](../ja/cyber-resilience-framework-mapping.md)). It covers exfiltration as well as encryption and destruction.
> - I rewrote the MTTC sentence so that it says which path was measured. The 2-minute figure comes from the Lambda path in the companion Observability repository; the Step Functions path in this repository has not been measured.
> - This architecture does not rely on ARP to detect read-only exfiltration. Its documented detection inputs are write-side (inference) [E-012]. If you suspect exfiltration, see the [Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md).

## Introduction

Enterprise file data stored on NAS (NFS/SMB) faces unique security challenges that general-purpose compute-focused security tools don't fully address. This article introduces a reference architecture that leverages Amazon FSx for NetApp ONTAP's storage-native security capabilities alongside AWS serverless services to build comprehensive file-level cyber resilience.

## The Problem

Traditional security approaches focus on network perimeter and endpoint protection. For file storage workloads:

- Malware scanning typically happens at the endpoint, not the storage layer
- Ransomware detection relies on signature-based tools that miss novel variants
- Incident response is manual and slow (hours to contain, days to recover)
- Audit trails lack file-operation granularity needed for forensics

## Architecture Overview

The architecture uses six complementary layers:

```
┌─────────────────────────────────────────────────┐
│ Layer 1: Storage-Native Security                │
│   ARP | FPolicy | SnapLock | MAV               │
├─────────────────────────────────────────────────┤
│ Layer 2: File Scanning                          │
│   TrendAI Vscan (signatures) | Deep Instinct   │
│   (AI inference)                                │
├─────────────────────────────────────────────────┤
│ Layer 3: Event-Driven Response                  │
│   FPolicy → SQS → EventBridge → Step Functions │
├─────────────────────────────────────────────────┤
│ Layer 4: Observability                          │
│   CloudWatch Metrics | Dashboard | Alarms       │
├─────────────────────────────────────────────────┤
│ Layer 5: Data Protection                        │
│   Snapshot | SnapMirror | FlexClone | SnapLock  │
├─────────────────────────────────────────────────┤
│ Layer 6: Enterprise Integration                 │
│   Security Hub | SIEM | Compliance | Multi-Acct │
└─────────────────────────────────────────────────┘
```

## Why FSx for ONTAP?

Amazon FSx for NetApp ONTAP provides unique storage-native security primitives not available in general-purpose storage:

| Capability | What It Does | Why It Matters |
|-----------|-------------|---------------|
| **ARP** | Behavioral anomaly detection at the storage layer | Catches ransomware by file-operation patterns, not signatures |
| **FPolicy** | Real-time file-event notification to external servers | Enables inline scanning without modifying client workflows |
| **SnapLock** | WORM (Write Once, Read Many) compliance retention | Evidence preservation that even administrators cannot delete |
| **Tamperproof Snapshot** | Admin-proof backup snapshots | Recovery point immune to insider threats |
| **MAV** | Multi-Admin Verification for destructive operations | Prevents single-admin compromise |

## Key Design Decisions

### Scanner selection: Complementary approaches

This architecture supports two file scanning technologies with different strengths:

| Aspect | TrendAI Vision One — File Security | Deep Instinct for NetApp ONTAP |
|--------|-----------------------------------|-------------------------------|
| Approach | Signature + heuristic | Deep Learning inference |
| Strength | High accuracy on known threats | Zero-day and novel malware |
| Update model | Frequent signature updates | Infrequent model updates |
| Best for | Compliance, known threat blocking | APT defense, ransomware variants |

Both integrate via FPolicy's ICAP protocol (port 1344). Organizations can deploy one or both in sequence.

### Event-driven quarantine: Automated containment

When malware is detected, the system automatically:
1. Creates a forensic snapshot (evidence preservation)
2. Restricts the export policy (isolates the volume from NFS / SMB clients)
3. Notifies the security team (SNS alert)
4. Waits for human approval (Step Functions + SQS)
5. Either restores access (false positive) or creates a FlexClone (forensics)

The aim is to shorten Mean Time to Contain (MTTC), which takes hours when done by hand. I have not measured how long this Step Functions path takes. The measured figure comes from the companion [observability repository](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations): its Lambda path blocked access at the storage layer within 2 minutes of ARP detection (ONTAP 9.17.1P7D1).

## Getting Started

The complete implementation is open-source:

**Repository**: [github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns)

```bash
git clone https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns.git
cd FSx-for-ONTAP-Cyber-Resilience-Patterns
make setup && source .venv/bin/activate
make test  # 326 tests, no AWS credentials needed
```

For step-by-step deployment instructions, see the [Quick Start Deployment Guide](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns/blob/main/docs/quickstart-deployment.md).

## Series Outline

This is the first of a 4-part series:
1. **Architecture Overview** (this article)
2. ONTAP Native Security Deep-Dive: ARP + FPolicy configuration
3. Event-Driven Response: Step Functions quarantine workflow implementation
4. Operating at Scale: Benchmarks, operational runbooks, and lessons learned

## 日本語サマリ

> **Update (2026-10)**
> - 2026-09 から、AWS Backup の論理エアギャップボールトが FSx for ONTAP のボリュームバックアップに対応した。[vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md) にまとめたが、本リポジトリでは実環境で試していない。
> - NIST CSF 2.0 の当てはめは [framework mapping](../ja/cyber-resilience-framework-mapping.md)（[English](../en/cyber-resilience-framework-mapping.md)）の 1 か所にまとめた。暗号化・破壊に加えて持ち出しも扱う。
> - 本文の MTTC の記述を、測った区間がわかる形に直した。2 分はコンパニオンの Observability リポジトリの Lambda 経路の実測値で、本リポジトリの Step Functions 経路は測っていない。
> - 読み取りだけの持ち出しの検知は ARP に頼らない。文書にある検知条件は書き込み系（推論）[E-012]。持ち出しを疑うときは [Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md) を参照。

Amazon FSx for NetApp ONTAP の多層防御パターンを紹介するシリーズ第1回。ストレージネイティブセキュリティ (ARP, FPolicy, SnapLock, MAV) と AI スキャン、イベント駆動型自動対応を組み合わせ、ランサムウェアからエンタープライズファイルデータを保護する参照アーキテクチャの概要。

---

*Yoshiki Fujiwara — NetApp Cloud Solutions Architect, AWS Community Builder (Storage)*

*Transparency: The author is employed by NetApp. This project is a personal community contribution with vendor-neutral comparisons.*

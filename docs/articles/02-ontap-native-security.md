# ONTAP Native Security Deep-Dive: ARP + FPolicy for FSx for ONTAP

> Configuring Autonomous Ransomware Protection and FPolicy for real-time file scanning on Amazon FSx for NetApp ONTAP.

> **Update (2026-10)**
> - ARP and FPolicy are configured with the CLI / REST steps in the [ARP Configuration Guide](../ontap-native/arp-configuration.md) and the [FPolicy Configuration Guide](../ontap-native/fpolicy-configuration.md). The Custom Resource handler is in the repository, but no template references it, so I corrected the sentence that said it runs during stack creation.
> - The ARP Lifecycle Manager exists as Lambda code only. No template deploys the function, the DynamoDB table or the schedule.
> - FPolicy receives NFS and SMB operations only; operations through FSx for ONTAP S3 Access Points do not reach it [E-015].
> - This architecture does not rely on ARP to detect read-only exfiltration. ARP's documented detection inputs are write-side (inference) [E-012]. See the [Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md) and the [framework mapping](../en/cyber-resilience-framework-mapping.md).

## Introduction

This second article in the series dives into the storage-native security layer: how ARP detects ransomware by behavioral analysis, and how FPolicy enables real-time inline scanning via the ICAP protocol.

## ARP: Behavioral Ransomware Detection

### How ARP Works

ARP (Autonomous Ransomware Protection) monitors file-operation patterns at the storage layer:
- File rename entropy (random extensions like `.locked`, `.encrypted`)
- Bulk file modification rate
- File type changes (documents → encrypted blobs)

When anomalies are detected, ARP automatically:
1. Creates an ARP snapshot (recovery point before damage spreads)
2. Generates an EMS event (forwarded to our event pipeline)
3. Waits for an administrator to classify the activity as a false positive or a potential attack

**ARP does not refuse a write.** An earlier version of this article said it optionally blocks
further writes in active mode; that was wrong. The documented response flow is a warning, a
snapshot, and manual classification — no step refuses an operation [E-001], and the blocking
behaviour has not been measured on any build here. Refusing a write is the job of the FPolicy
scanner path (NFS / SMB only) or, on the S3 access point path, of the access point policy and
IAM. See the
[ARP active-mode measurement plan](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns/blob/main/docs/ontap-native/arp-active-mode-measurement-plan.md).

### ARP Lifecycle: Learning → Active

The learning period belongs to the model generation, not to ARP as such.

```
ARP/AI  (ONTAP 9.16.1+ FlexVol, 9.18.1+ FlexGroup)
  Day 0: Enable → active immediately. dry_run is not a reachable state.

ARP     (ONTAP 9.10.1-9.15.1, and FlexGroup through 9.17.1)
  Day 0:   Enable in dry_run mode (learning)
             ↓ 30 days of normal operation patterns on NAS FlexVol
  Day 30+: Active (automatic switch from ONTAP 9.13.1)
```

> **制約**: ボリュームタイプでモデルが変わる。FlexVol は ONTAP 9.16.1 以降で ARP/AI、
> FlexGroup は 9.17.1 までは旧世代 ARP で、ARP/AI になるのは 9.18.1 以降。
> **同じクラスタ内でボリュームによって学習期間の有無が違う。**
> 出典: [Learn about ONTAP Autonomous Ransomware Protection](https://docs.netapp.com/us-en/ontap/anti-ransomware/)（全文、2026-09-07 取得）

The **ARP Lifecycle Manager** in our architecture exists for the original ARP model only:
- DynamoDB tracks learning start date per volume
- Daily EventBridge Scheduler triggers a Lambda check
- After 30 days: SNS notification → transition (redundant on ONTAP 9.13.1+, which switches itself)

On a cluster running ARP/AI there is nothing for it to wait for. As of 2026-10 the code is in `solutions/ontap-native/lambda/arp_lifecycle.py`, and no template deploys the function, the DynamoDB table or the schedule.

### Configuration via ONTAP REST API

```python
# Original ARP only: learn first
client.enable_arp(volume_uuid, state="dry_run")

# After the learning period, activate
client.enable_arp(volume_uuid, state="enabled")
```

On ARP/AI the first call lands as `enabled` and returns 200 with no warning [E-004]. Read the
state back after the PATCH instead of echoing the request: reporting `dry_run` for a volume that
is actively protecting is the difference between "learning" and "protecting" in an operator's
dashboard.

A Custom Resource handler for this configuration is in the repository, but as of 2026-10 no template references it. Configure ARP with the CLI / REST steps in the [ARP Configuration Guide](../ontap-native/arp-configuration.md).

## FPolicy: Real-Time File Event Processing

### The FPolicy → ICAP → Scanner Pattern

```
Client writes file → FSx for ONTAP → FPolicy Engine
    → ICAP request (TCP 1344) → Scanner (TrendAI / Deep Instinct)
    ← ICAP response (CLEAN / INFECTED)
    → Allow or Block the write
```

### FPolicy Configuration Components

| Component | Purpose |
|-----------|---------|
| **Engine** | External server definition (IP, port, sync/async) |
| **Event** | Which file operations to monitor (write, create, rename) |
| **Policy** | Ties engine + events together, sets mandatory flag |

### is_mandatory: The Availability vs Security Trade-off

| Setting | Behavior when scanner is down | Use case |
|---------|-------------------------------|----------|
| `false` (default) | Passthrough — allow writes | Availability-first |
| `true` | Block all writes | Security-first (accept downtime risk) |

Our architecture defaults to `false` with monitoring: if the scanner goes down, FPolicy passes through and CloudWatch alerts the team.

### Scan Target Filtering

Not every file needs scanning. Performance-optimized filtering:

```
Extensions to scan: exe, dll, scr, bat, ps1, docm, xlsm, zip, rar
Extensions to skip: log, tmp, csv, txt
Operation filter: first-write only (not every update)
Max file size: 100 MB (larger files timeout)
```

## Combining ARP and FPolicy

ARP and FPolicy serve complementary purposes:

| | ARP | FPolicy + Scanner |
|---|-----|------------------|
| Detection timing | Post-pattern (behavioral) | Pre-write (inline) |
| What it catches | Unknown ransomware patterns | Known + unknown malware |
| Performance impact | Near-zero (background analysis) | 5-30ms per write |
| Recovery aid | Automatic snapshot | Block before damage |

Both feed into the same EventBridge event pipeline for unified response.

## Implementation Reference

CloudFormation templates, the Custom Resource handler (not referenced by any template as of 2026-10), and configuration documentation:

- [FPolicy Configuration Guide](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns/blob/main/docs/ontap-native/fpolicy-configuration.md)
- [ARP Configuration Guide](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns/blob/main/docs/ontap-native/arp-configuration.md)
- [ARP Active-Mode Measurement Plan](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns/blob/main/docs/ontap-native/arp-active-mode-measurement-plan.md)
- [Security Config Custom Resource](https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns/blob/main/solutions/ontap-native/lambda/security_config_handler.py)

## 日本語サマリ

> **Update (2026-10)**
> - ARP と FPolicy は [ARP Configuration Guide](../ontap-native/arp-configuration.md) と [FPolicy Configuration Guide](../ontap-native/fpolicy-configuration.md) の CLI / REST の手順で設定する。Custom Resource のハンドラはリポジトリにあるが、どのテンプレートからも参照されていないので、スタック作成時に設定するという本文の文を直した。
> - ARP Lifecycle Manager は Lambda のコードだけで、テンプレートは関数・DynamoDB テーブル・スケジュールをデプロイしない。
> - FPolicy が受け取るのは NFS と SMB の操作だけで、FSx for ONTAP S3 Access Points 経由の操作は届かない [E-015]。
> - 読み取りだけの持ち出しの検知は ARP に頼らない。文書にある検知条件は書き込み系（推論）[E-012]。[Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md) と [framework mapping](../ja/cyber-resilience-framework-mapping.md) を参照。

シリーズ第2回：ONTAP のストレージネイティブセキュリティ機能 (ARP + FPolicy) の設計と実装を解説。ARP の学習期間管理の自動化と、FPolicy/ICAP によるインラインスキャンのアーキテクチャパターンを紹介。

---

*Yoshiki Fujiwara — NetApp Cloud Solutions Architect, AWS Community Builder (Storage)*


---

**Series Navigation:**
← [Part 1: Architecture Overview](01-architecture-overview.md) | [Part 3: Event-Driven Response →](03-event-driven-response.md)

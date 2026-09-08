# FSx for ONTAP Cyber Resilience — Architecture Overview

## アーキテクチャ概要 / Architecture Overview

Amazon FSx for NetApp ONTAP を中心とした多層防御（Defense in Depth）アーキテクチャ。
ストレージネイティブセキュリティ、AI ベースのファイルスキャン、イベント駆動型自動対応を組み合わせ、
ランサムウェアおよび高度な脅威からエンタープライズファイルデータを保護する。

This architecture combines storage-native security, AI-powered file scanning, and event-driven automated response
around Amazon FSx for NetApp ONTAP to protect enterprise file data against ransomware and advanced threats
through defense-in-depth.

---

## 多層防御アーキテクチャ / Defense-in-Depth Architecture

```mermaid
graph TB
    classDef storageNative fill:#1a73e8,color:#fff,stroke:#0d47a1
    classDef scanning fill:#e65100,color:#fff,stroke:#bf360c
    classDef eventDriven fill:#2e7d32,color:#fff,stroke:#1b5e20
    classDef observability fill:#6a1b9a,color:#fff,stroke:#4a148c
    classDef dataProtection fill:#00695c,color:#fff,stroke:#004d40
    classDef network fill:#546e7a,color:#fff,stroke:#37474f

    subgraph NETWORK["Network & Identity Layer"]
        direction LR
        VPC[VPC / Private Subnets]
        VPCE[VPC Endpoints]
        SG[Security Groups]
        AD[Active Directory]
        IAM[AWS IAM]
    end

    subgraph SCAN["File Scanning Layer"]
        direction LR
        TRENDAI["TrendAI Vision One<br/>File Security<br/>(Vscan/ICAP)"]
        DI["Deep Instinct<br/>for NetApp ONTAP<br/>(AI Prevention)"]
    end

    subgraph STORAGE["Storage-Native Security Layer"]
        direction LR
        ARP["ARP<br/>Ransomware Detection"]
        FPOLICY["FPolicy<br/>Access Control & Events"]
        SNAPLOCK["SnapLock<br/>WORM Immutability"]
        MAV["Multi-Admin<br/>Verification"]
    end

    subgraph EVENT["Event-Driven Response Layer"]
        direction LR
        SQS["Amazon SQS"]
        EB["EventBridge"]
        SF["Step Functions<br/>Workflows"]
        ACTIONS["Quarantine / Notify /<br/>Forensics / Recovery"]
    end

    subgraph OBS["Observability Layer"]
        direction LR
        AUDIT["ONTAP Audit Logs"]
        CW["CloudWatch<br/>Metrics & Alarms"]
        SIEM["SIEM Integration"]
    end

    subgraph PROTECT["Data Protection Layer"]
        direction LR
        SNAPSHOT["Snapshots<br/>(Tamperproof)"]
        MIRROR["SnapMirror<br/>(Cross-Region DR)"]
        CLONE["FlexClone<br/>(Forensics)"]
    end

    NETWORK --> SCAN
    NETWORK --> STORAGE
    SCAN --> EVENT
    STORAGE --> EVENT
    EVENT --> OBS
    EVENT --> PROTECT
    STORAGE --> PROTECT

    class VPC,VPCE,SG,AD,IAM network
    class TRENDAI,DI scanning
    class ARP,FPOLICY,SNAPLOCK,MAV storageNative
    class SQS,EB,SF,ACTIONS eventDriven
    class AUDIT,CW,SIEM observability
    class SNAPSHOT,MIRROR,CLONE dataProtection
```

---

## セキュリティレイヤー詳細 / Security Layer Details

### Layer 1: Storage-Native Security（ストレージネイティブセキュリティ）

FSx for ONTAP に組み込まれたセキュリティ機能。追加コンポーネント不要で即座に有効化可能。

| Component | 機能 / Function | 防御フェーズ / Phase |
|-----------|----------------|---------------------|
| **ARP** (Autonomous Ransomware Protection) | ファイル操作パターンの異常検知、自動 Snapshot 作成 | 検知 (Detect) |
| **FPolicy** | ファイルアクセスイベントの監視・通知・ブロック。**対象は NFS / SMB のみ。S3 Access Point 経由の操作は通知されず、`mandatory` 指定でも遮断されない**（実測 2026-08-26 / ONTAP 9.18.1P3D1） | 検知・防御 (Detect / Protect)、ただし NFS / SMB 経路のみ |
| **SnapLock** | WORM によるデータ不変性（Compliance / Enterprise） | 防御 (Protect) |
| **Tamperproof Snapshot** | 管理者でも削除不可能な Snapshot | 防御 (Protect) |
| **Multi-Admin Verification** | 破壊的操作の多者承認 | 防御 (Protect) |

### Layer 2: File Scanning（ファイルスキャン）

書き込み時のリアルタイムスキャンにより、マルウェアの侵入を防止。

| Technology | アプローチ / Approach | 強み / Strength |
|-----------|---------------------|----------------|
| **TrendAI Vision One — File Security** | シグネチャ + ヒューリスティック (Vscan/ICAP) | 既知脅威の高精度検知、低偽陽性 |
| **Deep Instinct for NetApp ONTAP** | Deep Learning 推論 (予防型) | 未知脅威・ゼロデイの事前防御 |

### Layer 3: Event-Driven Response（イベント駆動対応）

検知イベントから自動的に封じ込め・通知・証拠保全を実行。

```
FPolicy / ARP Event → SQS → EventBridge → Step Functions → Actions
```

| Workflow | トリガー / Trigger | アクション / Actions |
|----------|-------------------|---------------------|
| **Quarantine** | マルウェア検知、ARP アラート | Export Policy 制限、Snapshot 作成 |
| **Notification** | 全セキュリティイベント | SNS、Slack、Teams 通知 |
| **Forensics** | 高重要度イベント | FlexClone 作成、証拠保全 |
| **Recovery** | 管理者承認後 | SnapRestore、Export Policy 復旧 |

### Layer 4: Observability（可観測性）

全操作の監査証跡と、セキュリティメトリクスのリアルタイム監視。

```
ONTAP Audit → S3 AP → Lambda → SIEM
CloudWatch Metrics → Alarms → SNS
```

### Layer 5: Data Protection（データ保護）

攻撃からの復旧と証拠保全のための ONTAP ネイティブ機能群。

| Feature | 用途 / Use Case | RPO |
|---------|----------------|-----|
| **Snapshot** | 短期復旧ポイント | 分単位 |
| **Tamperproof Snapshot** | 改ざん防止バックアップ | ポリシー定義 |
| **FlexClone** | フォレンジック環境分離 | 即時 |
| **SnapMirror** | Cross-Region DR | 最終同期時点 |
| **SnapLock** | コンプライアンス長期保持 | コミット時点 |

---

## データフロー / Data Flow

### 通常時（Normal Operation）

```mermaid
sequenceDiagram
    participant Client as Client (NFS/SMB)
    participant FSx as FSx for ONTAP
    participant FPolicy as FPolicy Engine
    participant Scanner as File Scanner
    participant Audit as Audit Log

    Client->>FSx: File write request
    FSx->>FPolicy: Notify file event
    FPolicy->>Scanner: Scan request
    Scanner-->>FPolicy: CLEAN
    FPolicy-->>FSx: Allow
    FSx-->>Client: Write complete
    FSx->>Audit: Log operation
```

### 脅威検知時（Threat Detected）

```mermaid
sequenceDiagram
    participant Client as Client (NFS/SMB)
    participant FSx as FSx for ONTAP
    participant FPolicy as FPolicy Engine
    participant Scanner as File Scanner
    participant SQS as Amazon SQS
    participant EB as EventBridge
    participant SF as Step Functions
    participant Admin as Security Admin

    Client->>FSx: File write request
    FSx->>FPolicy: Notify file event
    FPolicy->>Scanner: Scan request
    Scanner-->>FPolicy: MALICIOUS
    FPolicy-->>FSx: Block write (NFS / SMB only)
    FSx-->>Client: Access denied

    FPolicy->>SQS: Security event
    SQS->>EB: Forward event
    EB->>SF: Trigger workflow

    par Quarantine
        SF->>FSx: Restrict export policy
        SF->>FSx: Create snapshot
    and Notify
        SF->>Admin: Alert (SNS/Slack)
    and Forensics
        SF->>FSx: Create FlexClone
    end
```

### ARP ランサムウェア検知時（ARP Detection）

```mermaid
sequenceDiagram
    participant Attacker as Compromised Client
    participant FSx as FSx for ONTAP
    participant ARP as ARP Engine
    participant SQS as Amazon SQS
    participant EB as EventBridge
    participant SF as Step Functions
    participant Admin as Security Admin

    Attacker->>FSx: Mass file encryption/rename
    FSx->>ARP: Behavioral anomaly detected
    ARP->>FSx: Auto-create ARP snapshot
    ARP->>SQS: ARP alert event

    SQS->>EB: Forward event
    EB->>SF: Trigger containment

    SF->>FSx: Restrict client access (export policy)
    SF->>FSx: Create tamperproof snapshot
    SF->>Admin: Critical alert

    Note over Admin,SF: Human-in-the-loop decision

    alt Confirm attack
        Admin->>SF: Approve recovery
        SF->>FSx: SnapRestore from ARP snapshot
        SF->>FSx: Re-enable access
    else Investigate
        Admin->>SF: Request forensics
        SF->>FSx: Create FlexClone (read-only)
        SF->>Admin: Forensics env ready
    end
```

---

## ネットワーク構成 / Network Architecture

```mermaid
graph TB
    subgraph VPC["VPC (10.0.0.0/16)"]
        subgraph AZ1["Availability Zone 1"]
            FSX_SUB1["Private Subnet<br/>FSx (10.0.1.0/24)"]
            SEC_SUB1["Private Subnet<br/>Security (10.0.3.0/24)"]
        end
        subgraph AZ2["Availability Zone 2"]
            FSX_SUB2["Private Subnet<br/>FSx (10.0.2.0/24)"]
            SEC_SUB2["Private Subnet<br/>Security (10.0.4.0/24)"]
        end
        subgraph COMPUTE["Compute Subnet (10.0.5.0/24, 10.0.6.0/24)"]
            LAMBDA["Lambda Functions"]
            STEPFN["Step Functions"]
        end
        subgraph ENDPOINTS["VPC Endpoints"]
            S3_EP["S3 Gateway"]
            SQS_EP["SQS Interface"]
            SM_EP["Secrets Manager"]
            KMS_EP["KMS"]
            STS_EP["STS"]
        end
    end

    subgraph EXTERNAL["External"]
        AD_EXT["Active Directory"]
        SIEM_EXT["SIEM"]
        TREND_UP["TrendAI Update Servers"]
        DI_MGMT["Deep Instinct Mgmt"]
    end

    FSX_SUB1 --- FSX_SUB2
    SEC_SUB1 --- SEC_SUB2

    FSX_SUB1 --> SEC_SUB1
    COMPUTE --> ENDPOINTS
    SEC_SUB1 --> TREND_UP
    SEC_SUB1 --> DI_MGMT
    FSX_SUB1 --> AD_EXT
```

> **Note**: EventBridge は Regional service のため VPC Endpoint は不要。全サブネットは Multi-AZ 配置。
> 詳細なネットワーク設計（ポート定義、Security Group ルール等）は内部設計ドキュメントを参照。

---

## CloudFormation テンプレート構成 / CloudFormation Template Structure

```mermaid
graph TD
    MAIN["main.yaml<br/>(Root Nested Stack)"]
    NET["network.yaml<br/>(VPC, Subnets, SG, Endpoints)"]
    STOR["storage.yaml<br/>(FSx for ONTAP, SVM, Volumes)"]
    NATIVE["security-native.yaml<br/>(Custom Resource: ARP, FPolicy, SnapLock, MAV)"]
    SCAN_STACK["scanning.yaml<br/>(Vscan EC2, DI Agent)"]
    EVT["event-driven.yaml<br/>(SQS, EB, Step Functions)"]
    OBS_STACK["observability.yaml<br/>(CloudWatch, Dashboards)"]
    DP["data-protection.yaml<br/>(Backup policies)"]

    MAIN --> NET
    MAIN --> STOR
    MAIN --> NATIVE
    MAIN --> SCAN_STACK
    MAIN --> EVT
    MAIN --> OBS_STACK
    MAIN --> DP

    NET --> STOR
    NET --> SCAN_STACK
    STOR --> NATIVE
    STOR --> EVT
    NATIVE --> EVT
    SCAN_STACK --> EVT
    EVT --> OBS_STACK
```

各テンプレートは Nested Stack として `main.yaml` から参照されるか、個別にデプロイ可能。
環境別パラメータは `parameters/dev.json`, `parameters/staging.json`, `parameters/production.json` で管理。

---

## NIST CSF 2.0 マッピング / NIST Cybersecurity Framework 2.0 Mapping

| NIST CSF 2.0 Function | このアーキテクチャでの実装 / Implementation |
|------------------------|-------------------------------------------|
| **Govern** | データ分類、ポリシー定義、MAV による変更管理、役割分離 |
| **Identify** | 資産管理 (SVM/Volume/Share 単位), データ分類レベル定義 |
| **Protect** | FPolicy ブロック（**NFS / SMB のみ**。S3 Access Point 経由は遮断されない）, SnapLock, Tamperproof Snapshot, MAV, File Scanning, Export Policy |
| **Detect** | ARP 異常検知（S3 Access Point 経由の書き込みも検知する。実測）, FPolicy 監視（**NFS / SMB のみ**）, File Scanning verdict, CloudWatch Alarms |
| **Respond** | Step Functions 自動隔離, 通知, フォレンジック, Human-in-the-loop 承認 |
| **Recover** | ARP Snapshot 復元, SnapMirror DR, FlexClone 検証環境, ランブック |

---

## 関連プロジェクト / Related Projects

| Project | Relationship |
|---------|-------------|
| [fsxn-observability-integrations](https://github.com/Yoshiki0705/fsxn-observability-integrations) | 監査ログ SIEM 配信基盤（本プロジェクトの Observability Layer 基盤） |
| [FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns) | S3 AP パターン参照実装、FPolicy イベント処理パターン |
| [blea-fsxn-usecase](https://github.com/Yoshiki0705/blea-fsxn-usecase) | BLEA Cyber Resilience ユースケース CDK 実装 |

---

## 次のステップ / Next Steps

**Phase 1 Complete (現在):**
- ✅ Network Stack + Storage Stack (CloudFormation)
- ✅ ONTAP Native Security 設定 (ARP / FPolicy Custom Resource)
- ✅ Event-Driven Response パイプライン (SQS → EventBridge → Step Functions)
- ✅ File Scanning テンプレート (TrendAI / Deep Instinct EC2)
- ✅ Observability Dashboard + Alarms (CloudWatch)
- ✅ Lambda コードパッケージング + S3 デプロイ
- ✅ セキュリティ強化 (IMDSv2, VPC Flow Logs, Lambda concurrency)
- ✅ CI/CD (cfn-lint, cfn-guard, pytest, coverage)

**Phase 2 (Production Readiness):**
1. Multi-AZ Scanner HA (Auto Scaling Group)
2. ARP Lifecycle Manager (dry_run → enabled 自動移行)
3. DR / SnapMirror Cross-Region レプリケーション
4. Multi-Admin Verification (MAV) 統合
5. コスト最適化 (dev 環境のスキャナー時間帯停止)
6. 運用ランブック拡充

**Phase 3 (Enterprise Extensions):**
1. AWS Security Hub 統合
2. Third-party SIEM 連携 (Splunk / QRadar)
3. コンプライアンス証跡自動収集 (SOC2 / ISO27001 マッピング)
4. マルチアカウント Hub-Spoke パターン
5. パフォーマンスベンチマーク

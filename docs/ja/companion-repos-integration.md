# コンパニオンリポジトリ統合ガイド

本ドキュメントは、[fsxn-observability-integrations](https://github.com/Yoshiki0705/fsxn-observability-integrations) リポジトリのコンポーネントを、本リポジトリ（fsxn-cyber-resilience-patterns）のセキュリティレイヤーにマッピングし、統合されたDefense-in-Depthアーキテクチャとしてどう連携するかを説明します。

## どのリポジトリを読むか / Where each question is answered

本リポジトリは**実装のパターン**を持つ。設計判断は
[FSx for ONTAP Adoption Playbook](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook) が持ち、実装は observability リポジトリが持つ。
**同じ内容を 2 か所に置かない。** 置くと片方が更新されなくなり、古い側が長く残る。

| 読者の問い | 読む先 |
|-----------|--------|
| SnapLock / Snapshot locking をどう設定するか（テンプレート、CLI、REST） | 本リポジトリ [`docs/ontap-native/`](../ontap-native/) |
| SnapLock を有効にすべきか、どの保持モードか、**何が不可逆か** | Playbook [`domains/data-protection`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/README.md) |
| ARP をどう有効化するか、どのモデル世代が適用されるか | 本リポジトリ [`docs/ontap-native/arp-configuration.md`](../ontap-native/arp-configuration.md) |
| 不可逆操作の承認、監査ログの設計、アクセス認可の層 | Playbook [`domains/security-governance`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/security-governance/README.md) |
| ARP / TrendAI / Deep Instinct のどれを選ぶか | 本リポジトリ [`docs/comparison-security-layers.md`](../comparison-security-layers.md) |
| 検知から遮断までの動く実装（Lambda / EMS Webhook / FPolicy サーバー） | [fsxn-observability-integrations](https://github.com/Yoshiki0705/fsxn-observability-integrations) |
| S3 Access Point のライフサイクルとサーバーレス連携 | [FSx for ONTAP S3 Access Points Serverless Patterns](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns) |

**This repository holds the implementation patterns.** Design guidance lives in the Adoption
Playbook, and working implementations live in the observability repository. The same material is
not duplicated across them: a copy that stops being updated outlives the one that was corrected.

## アーキテクチャレイヤーマッピング

以下の表は、Observability リポジトリのどのコンポーネントが、本リポジトリのどのセキュリティレイヤーに接続されるかを示します。

| サイバーレジリエンスレイヤー（本リポジトリ） | Observability リポジトリのコンポーネント | 統合ポイント |
|--------------------------------------------|----------------------------------------|-------------|
| **イベント駆動型レスポンス** | `shared/python/ontap_response.py` + `shared/templates/automated-response.yaml` | SNS → Lambda → ONTAP REST API ブロック（SMB name-mapping deny、NFS export-policy deny、NACL deny） |
| **イベント駆動型レスポンス** | `shared/templates/automated-response-ttl.yaml` | EventBridge Scheduler による TTL ベース自動ブロック解除 |
| **ストレージネイティブ（ARP）** | EMS Webhook → API Gateway → Lambda パイプライン | ARP/AI 検知イベントの Observability プラットフォームへの転送 |
| **ストレージネイティブ（FPolicy）** | `shared/fpolicy-server/` | リアルタイムファイル操作キャプチャ用 FPolicy 外部サーバー |
| **監査と可視化** | S3 Access Point → Lambda → ベンダー連携 | 監査ログの配信（Datadog、Splunk、Elastic、New Relic 等） |
| **データ保護** | `shared/templates/restore-verification.yaml` | 検証済みクリーン復旧ポイント（FlexClone + スキャン + 判定） |
| **データ保護** | コンテンツレベル PII 分類スキャナー | Amazon Comprehend によるファイル内容の PII 発見（CSF 2.0 Identify） |

## 2つのリポジトリの補完関係

```
┌─────────────────────────────────────────────────────────────────┐
│  fsxn-cyber-resilience-patterns（本リポジトリ）                    │
│                                                                 │
│  多層防御アーキテクチャを定義:                                      │
│  • TrendAI File Security（インラインスキャン）                     │
│  • Deep Instinct（AI ゼロデイ防御）                               │
│  • ONTAP ネイティブセキュリティ（ARP、FPolicy、SnapLock、MAV）      │
│  • イベント駆動オーケストレーション（EventBridge → Step Functions）  │
│  • Observability ダッシュボード & SIEM 連携                       │
│  • コンプライアンス証跡 & マルチアカウントパターン                    │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  fsxn-observability-integrations（コンパニオンリポジトリ）           │
│                                                                 │
│  検知と応答のプリミティブを実装:                                     │
│  • 監査ログ配信（S3 AP → Lambda → 9 ベンダー）                    │
│  • EMS イベント Webhook（ARP、FPolicy、管理操作）                  │
│  • CloudWatch Log Alarm（Metric Filter 不要）                    │
│  • 自動アクセス遮断（ontap_response.py）                          │
│  • 検証済み復旧ポイント（FlexClone + 拡張子スキャン）               │
│  • PII 分類スキャナー（Amazon Comprehend）                        │
│  • NIST CSF 2.0 機能マップ                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 責任分担

| 関心事 | 本リポジトリ | Observability リポジトリ |
|--------|------------|------------------------|
| アーキテクチャ定義 | フルスタック（ネットワーク → ストレージ → スキャン → イベント → ダッシュボード） | Observability パイプラインのみ |
| スキャンレイヤー | TrendAI Vscan/ICAP、Deep Instinct 連携 | — |
| 検知（ARP/FPolicy） | アーキテクチャパターン + CFn カスタムリソース | 動作する実装（EMS Webhook、FPolicy サーバー、CloudWatch Log Alarm） |
| 自動応答 | Step Functions オーケストレーション（隔離ワークフロー） | Lambda 直接応答（1.8秒実測、コールドスタート込み worst-case 12-15秒） |
| 復旧検証 | DR レプリケーション監視（SnapMirror ラグ） | 検証済みクリーン復旧ポイント（FlexClone + スキャン） |
| SIEM 連携 | Security Hub + SIEM コネクタテンプレート | ベンダー固有の連携（Datadog、Splunk、Elastic 等） |
| NIST CSF 2.0 マッピング | レイヤーごとの位置づけ（docs内） | 6 機能の完全なマッピング |

## デプロイ順序

両リポジトリを組み合わせて完全なサイバーレジリエンススタックをデプロイする場合:

1. **本リポジトリを先に** — インフラ基盤をデプロイ:
   ```bash
   ./scripts/deploy.sh dev network   # VPC、サブネット、SG、VPC Endpoints
   ./scripts/deploy.sh dev storage   # FSx for ONTAP、KMS、ARP/FPolicy 設定
   ./scripts/deploy.sh dev events    # EventBridge、Step Functions
   ./scripts/deploy.sh dev scanning  # TrendAI / Deep Instinct EC2
   ```

2. **Observability リポジトリを後に** — 検知と応答をその上にデプロイ:
   ```bash
   # 自動応答（SNS → Lambda → ONTAP ブロック）
   aws cloudformation deploy \
     --template-file shared/templates/automated-response.yaml \
     --stack-name fsxn-automated-response ...

   # TTL ベース自動ブロック解除
   aws cloudformation deploy \
     --template-file shared/templates/automated-response-ttl.yaml ...

   # 検証済み復旧ポイントワークフロー
   aws cloudformation deploy \
     --template-file shared/templates/restore-verification.yaml ...
   ```

3. **検知を応答に接続** — Observability モニターを SNS トリガートピックに接続:
   - CloudWatch Log Alarm → SNS トリガートピック
   - Datadog Monitor → SNS トリガートピック
   - Elastic SIEM ルール → SNS トリガートピック

## 主要な統合ポイントの詳細

### 1. ARP 検知 → 自動ブロック

**検知**（Observability リポジトリ）: ONTAP ARP/AI がランサムウェア様のファイル操作を検知 → EMS イベント（`callhome.arw.activity.seen`）→ EMS Webhook → API Gateway → Lambda → Observability プラットフォームのモニター発火 → SNS publish

**応答**（Observability リポジトリ）: SNS → Response Lambda → `contain_smb_threat` 複合アクション:
- 保護 Snapshot を作成
- ONTAP name-mapping deny でユーザーをブロック
- アクティブ CIFS セッションを切断
- セキュリティチームに通知

**オーケストレーション応答**（本リポジトリ）: 人間の承認を必要とする多段階ワークフローでは、Step Functions が同じ SNS トピックをサブスクライブするか、EventBridge イベントを受信し、より豊富なオーケストレーション（ボリューム隔離、承認者への通知、判断待ち、リストアまたはエスカレーション）を実行。

**E2E タイミング**: ARP 検知からストレージ層ブロックまで 2 分以内（ONTAP 9.17.1P7D1 で実機検証済み）。

### 2. FPolicy イベント駆動パイプライン

**本リポジトリ** がアーキテクチャパターンを定義: FPolicy → EventBridge → Step Functions（ファイル操作イベント）。

**Observability リポジトリ** が動作する FPolicy 外部サーバー（`shared/fpolicy-server/`）と、Agentic FPolicy 相関パターン（`docs/en/agent-fpolicy-correlation-pattern.md`）を提供。

### 3. インシデント後の検証済み復旧

**本リポジトリ** が DR レプリケーション監視を担当（`templates/dr-replication.yaml` — SnapMirror ラグアラーム）。

**Observability リポジトリ** が復旧ポイント検証を担当:
1. 対象 Snapshot を FlexClone として複製（即時、copy-on-write）
2. 隔離された S3 Access Point をアタッチ（VPC スコープ）
3. ランサムウェア関連のファイル拡張子をスキャン
4. 合否判定を記録
5. 自動クリーンアップ（clone + access point 削除）

これは NIST CSF 2.0 の Recover フェーズ（RC.RP）の重要な機能で、「Snapshot がある」と「検証済みクリーン復旧ポイントがある」のギャップを埋めます。

### 4. NIST CSF 2.0 カバレッジ（両リポジトリ統合）

| CSF 2.0 機能 | 本リポジトリ | Observability リポジトリ | 統合評価 |
|-------------|------------|------------------------|---------|
| **Govern（統制）** | — | — | 組織的責任 |
| **Identify（識別）** | — | PII 分類スキャナー | 部分的 |
| **Protect（保護）** | SnapLock、MAV、TrendAI スキャン、Deep Instinct | Snapshot、export-policy 強化 | 強い |
| **Detect（検知）** | ARP 設定、FPolicy 設定 | EMS Webhook、CloudWatch Log Alarm、FPolicy サーバー | 強い |
| **Respond（対応）** | Step Functions オーケストレーション | Lambda 直接ブロック（1.8秒実測、コールドスタート込み +10-15秒） | 強い |
| **Recover（復旧）** | SnapMirror ラグ監視 | 検証済み復旧ポイントワークフロー | 中程度（完全リストア訓練は手動） |

## リポジトリ間クロスリファレンス

| トピック | 本リポジトリ | Observability リポジトリ |
|---------|------------|------------------------|
| 自動応答アーキテクチャ | `solutions/event-driven-response/` | [automated-response-guide.md](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/automated-response-guide.md) |
| ONTAP REST API パターン | `solutions/shared/` | [ontap-rest-api-reference.md](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/ontap-rest-api-reference.md) |
| ARP インシデント対応 | `docs/ontap-native/` | [arp-incident-response-guide.md](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/arp-incident-response-guide.md) |
| EMS イベントリファレンス | — | [ems-detection-capabilities.md](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/ems-detection-capabilities.md) |
| FPolicy 運用 | `solutions/event-driven-response/` | [fpolicy-operational-guide.md](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/fpolicy-operational-guide.md) |
| NIST CSF 2.0 完全マッピング | — | [cyber-resilience-capability-map.md](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md) |
| 復旧検証 | `templates/dr-replication.yaml` | [verified-recovery-point-guide.md](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/verified-recovery-point-guide.md) |
| セキュリティ補遺 | — | [automated-response-security-addendum.md](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/automated-response-security-addendum.md) |
| デプロイ前提条件 | `docs/quickstart-deployment.md` | [prerequisites.md](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/prerequisites.md) |

## 関連記事

- [Automated Access Blocking for FSx for ONTAP — From Ransomware Detection to Storage-Layer Deny](https://dev.to/aws-builders/automated-access-blocking-for-fsx-for-ontap-from-ransomware-detection-to-storage-layer-deny-4l2g) (EN, dev.to)
- [Amazon FSx for NetApp ONTAP の自動アクセス遮断 — ランサムウェア検知からストレージ層ブロックまで](https://hakobiya.hatenablog.com/entry/fsxn-automated-incident-response) (JA, hatena)

上記の記事は、Observability リポジトリの `shared/python/ontap_response.py` および `shared/templates/automated-response.yaml` で実装されている自動応答モジュールを詳細に解説しています。ARP/AI 検知からストレージ層ブロックまでの E2E フローを実証しており、本リポジトリのイベント駆動型レスポンスレイヤーに接続されます。

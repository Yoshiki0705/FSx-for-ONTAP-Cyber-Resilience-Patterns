# 検証環境: ライセンス・コスト一覧 / Verification Environment: Licenses & Costs

## 概要 / Overview

本プロジェクトの全コンポーネントを検証するために必要なライセンス、AWS サービスコスト、
および Third-party 製品の評価ライセンス取得方法をまとめる。

---

## 1. AWS サービスコスト (ap-northeast-1)

### 1.1 Amazon FSx for NetApp ONTAP

| 項目 | 検証用最小構成 | 月額概算 (USD) | 備考 |
|------|--------------|---------------|------|
| File System (Single-AZ) | 1024 GiB SSD | ~$230 | 最小 SSD 容量 |
| Throughput Capacity | 128 MBps | ~$75 | 最小スループット |
| SVM | 2 (prod + audit) | 含む | 追加コストなし |
| Backup | 自動 (日次) | ~$5 | デフォルトバックアップ |
| **小計** | | **~$310/月** | |

> **Note**: Multi-AZ は Single-AZ の約2倍 (~$620/月)。検証には Single-AZ で十分。

### 1.2 EC2 (スキャナーインスタンス)

| 項目 | 検証用構成 | 月額概算 (USD) | 備考 |
|------|-----------|---------------|------|
| Vscan (c6g.xlarge) | 1 instance | ~$98 | ON_DEMAND, 24/7 |
| Deep Instinct (c6i.xlarge) | 1 instance | ~$122 | ON_DEMAND, 24/7 |
| Cost Scheduler 適用時 | 12h/day 停止 | **~$110** (合計) | 50% 削減 |

> **Cost Scheduler 利用推奨**: dev 環境では夜間停止で約50%削減。

### 1.3 サーバーレス (イベント処理パイプライン)

| サービス | 検証用想定使用量 | 月額概算 (USD) | 備考 |
|---------|----------------|---------------|------|
| Lambda | 10,000 invocations/月 | < $1 | Free Tier 内 |
| Step Functions | 100 executions/月 | < $1 | Standard ワークフロー |
| SQS | 100,000 messages/月 | < $1 | Free Tier 内 |
| EventBridge | 10,000 events/月 | < $1 | |
| SNS | 100 notifications/月 | < $1 | |
| CloudWatch | Metrics + Dashboard | ~$5 | カスタムメトリクス 7 個 |
| Secrets Manager | 2 secrets | ~$1 | fsxadmin + scanner |
| DynamoDB | ARP state table | < $1 | On-Demand, 極少量 |
| S3 | Lambda packages + reports | < $1 | |
| **小計** | | **~$10/月** | |

### 1.4 ネットワーク

| 項目 | 月額概算 (USD) | 備考 |
|------|---------------|------|
| NAT Gateway | ~$33 + データ転送 | スキャナー署名更新用 |
| VPC Interface Endpoints (4) | ~$30 | SQS, SM, KMS, STS |
| VPC Flow Logs | ~$5 | CloudWatch Logs 保存 |
| **小計** | **~$70/月** | |

### 1.5 Security Hub (Phase 3)

| 項目 | 月額概算 (USD) | 備考 |
|------|---------------|------|
| Security Hub | Free (最初30日), その後 ~$1/1000 findings | 検証規模では < $5 |

### 1.6 DR (Phase 2, オプション)

| 項目 | 月額概算 (USD) | 備考 |
|------|---------------|------|
| DR 先 FSx (別リージョン) | ~$310 | Primary と同等 |
| SnapMirror データ転送 | ~$10-50 | データ量依存 |

---

## AWS コスト合計 (検証環境)

| 構成 | 月額概算 (USD) | 年額概算 (USD) |
|------|---------------|---------------|
| **最小構成** (FSx + Lambda + 1 scanner) | ~$500 | ~$6,000 |
| **標準構成** (FSx + 2 scanners + NAT + Endpoints) | ~$600 | ~$7,200 |
| **Cost Scheduler 適用** (12h停止) | ~$500 | ~$6,000 |
| **フル構成** (上記 + DR + Security Hub) | ~$950 | ~$11,400 |

---

## 2. Third-Party ライセンス

### 2.1 TrendAI Vision One — File Security

| 項目 | 情報 |
|------|------|
| 製品名 | Trend Vision One — File Security (旧: Cloud One — File Storage Security) |
| ライセンス形態 | エンドポイント数 or スキャン量ベース |
| 評価版 | **30日無料トライアルあり** (Trend Micro サイトから申請) |
| 取得方法 | [Trend Micro Vision One Free Trial](https://www.trendmicro.com/en_us/business/products/one-platform.html) |
| 必要な情報 | 会社名、メールアドレス、利用目的 |
| Vscan/ICAP 要件 | Vision One File Security のサブスクリプション + Vscan エージェントパッケージ |
| 技術要件 | EC2 インスタンスに TrendAI エージェントをインストール |

> **評価用アプローチ**: 30日トライアルで全機能検証可能。レファレンスアーキテクチャの検証には十分。

### 2.2 Deep Instinct for NetApp ONTAP

| 項目 | 情報 |
|------|------|
| 製品名 | Deep Instinct Prevention for Storage — NetApp ONTAP Edition |
| ライセンス形態 | 販売窓口に確認する（[製品ページ](https://www.deepinstinct.com/dsx/dsx-cloud-amazon-fsx-netapp)と [AWS Marketplace の掲載](https://aws.amazon.com/marketplace/pp/prodview-h3pjvgqvlv6pc)にはライセンス形態の記載なし。2026-10-08 確認） |
| 評価版 | **POC ライセンスあり** (Deep Instinct/NetApp 営業経由) |
| 取得方法 | NetApp パートナーポータル or Deep Instinct 営業チームへの問い合わせ |
| 連絡先 | [Deep Instinct Partners — NetApp](https://www.deepinstinct.com/partners/netapp) |
| 技術要件 | EC2 (x86_64, c6i.xlarge+), 100GiB ストレージ, NAT Gateway (管理通信) |
| POC 期間 | 通常 30-60日 (営業と調整) |

> **評価用アプローチ**: Deep Instinct 営業チームに POC をリクエストする。

### 2.3 AWS Managed Microsoft AD (オプション)

| 項目 | 情報 |
|------|------|
| 用途 | SMB 認証、FPolicy ユーザーマッピング |
| コスト | Standard Edition: ~$73/月 |
| 代替 | NFS-only 環境では不要。検証目的なら SimpleAD ($30/月) or 既存 AD コネクター |

---

## 3. 無償で検証可能な範囲

以下は **ライセンス不要・AWS Free Tier/低コスト** で検証可能:

| レイヤー | 検証内容 | 必要コスト |
|---------|---------|-----------|
| イベントパイプライン | SQS → Lambda → EventBridge → Step Functions | Free Tier 内 |
| ONTAP REST API | ARP enable/disable, FPolicy config, Export Policy | FSx のみ必要 |
| Observability | CloudWatch Dashboard + Alarms | ~$5/月 |
| Lambda パッケージング | zip 生成 + S3 アップロード | < $1/月 |
| テスト (285 tests) | ローカル実行、mock ベース | $0 |
| CI/CD | GitHub Actions (public repo) | $0 |
| セキュリティスキャン | cfn-lint, cfn-guard, gitleaks, zizmor | $0 |

### スキャナーなしでの検証パターン

TrendAI/Deep Instinct のライセンスがない場合でも、以下の検証が可能:

1. **FPolicy → SQS 連携**: FPolicy external engine を「テスト用 Lambda」に向けて ICAP 応答をシミュレート
2. **ARP 検知→隔離フロー**: ARP アラートを SQS に手動投入し、Step Functions の動作を確認
3. **Export Policy 隔離/復旧**: ONTAP REST API 経由で実際の隔離/復旧操作を検証
4. **SnapMirror 監視**: DR レプリケーションの lag モニタリング (スキャナー不要)

---

## 4. 検証環境セットアップ手順

### Step 1: AWS リソース作成

```bash
# 1. FSx for ONTAP (最小構成)
./scripts/deploy.sh dev network
./scripts/deploy.sh dev storage

# 2. イベントパイプライン
export LAMBDA_ARTIFACT_BUCKET=<your-bucket>
./scripts/deploy.sh dev events

# 3. Observability
./scripts/deploy.sh dev observability
```

### Step 2: スキャナー (ライセンス取得後)

```bash
# TrendAI or Deep Instinct のライセンス取得後
./scripts/deploy.sh dev scanning
```

### Step 3: 動作確認 (スキャナーなし)

```bash
# テストイベントを SQS に送信
aws sqs send-message --queue-url <queue-url> \
  --message-body '{"source":"scanner","verdict":"MALICIOUS","file_path":"/test/eicar.exe",...}'

# Step Functions 実行を確認
aws stepfunctions list-executions --state-machine-arn <arn> --status-filter RUNNING
```

---

## 5. コスト削減のベストプラクティス

| 手法 | 削減効果 | 適用条件 |
|------|---------|---------|
| Cost Scheduler (夜間停止) | ~50% on EC2 | dev/staging 環境 |
| Single-AZ FSx | ~50% vs Multi-AZ | 検証環境 |
| Spot Instance (スキャナー) | ~60-70% on EC2 | 中断許容可能な検証 |
| NAT Gateway → NAT Instance | ~80% on NAT cost | 低トラフィック |
| Capacity Pool Tiering | Cold data を安価ストレージへ | 大容量テスト時 |
| 検証後の即時削除 | 100% | `make destroy` |

---

## 6. まとめ / Summary

| カテゴリ | 月額コスト | ライセンス要否 | 入手方法 |
|---------|-----------|--------------|---------|
| AWS (最小構成) | ~$500 | — | AWS アカウント |
| TrendAI | $0 (30日トライアル) | 要 (評価版) | Trend Micro サイト |
| Deep Instinct | $0 (POC) | 要 (POC ライセンス) | 営業問い合わせ |
| AD (オプション) | $30-73 | — | AWS Managed AD |
| **合計 (30日検証)** | **~$500** | トライアル2件 | |

> **推奨**: まず FSx + イベントパイプラインのみ ($310+$10=$320/月) でコア機能を検証し、
> スキャナーライセンス取得後にスキャニング層を追加する段階的アプローチ。

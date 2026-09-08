# クイックスタート: デプロイガイド / Quick Start: Deployment Guide

## 概要 / Overview

このガイドでは、FSx for ONTAP Cyber Resilience Patterns を自身の AWS 環境にデプロイする手順を説明する。
3つのデプロイパターンに対応:

| パターン | 内容 | 所要時間 | 月額目安 |
|---------|------|---------|---------|
| **A. パイプラインのみ** | Network + Event-Driven + Observability (FSx なし) | 15分 | ~$70 |
| **B. フル新規構築** | 上記 + FSx for ONTAP + Scanners | 30分 | ~$600 |
| **C. 既存環境に追加** | 既存 VPC/FSx に Event-Driven + Observability を追加 | 20分 | ~$50 |

---

## 前提条件 / Prerequisites

### 必須

```bash
# AWS CLI v2
aws --version  # aws-cli/2.x 以上

# Python 3.12+
python3 --version

# make
make --version

# zip (Lambda パッケージング用)
zip --version
```

### AWS IAM 権限

デプロイに必要な最小 IAM ポリシー:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:*",
        "s3:*",
        "ec2:*",
        "lambda:*",
        "states:*",
        "sqs:*",
        "sns:*",
        "events:*",
        "logs:*",
        "cloudwatch:*",
        "iam:*",
        "secretsmanager:*",
        "fsx:*"
      ],
      "Resource": "*"
    }
  ]
}
```

> **本番環境**: 上記は検証用の広い権限。本番では Resource ARN を絞り込むこと。

---

## Step 0: リポジトリのセットアップ

```bash
git clone https://github.com/Yoshiki0705/fsxn-cyber-resilience-patterns.git
cd fsxn-cyber-resilience-patterns

# Python 仮想環境 + 依存関係インストール
make setup
source .venv/bin/activate

# テスト実行 (AWS 認証不要)
make test
# → 285 tests passed

# Git hooks 有効化
git config core.hooksPath .githooks
```

---

## Step 1: パラメータのカスタマイズ

### リージョンの変更

デフォルトは `ap-northeast-1` (東京)。変更する場合:

```bash
export AWS_REGION=us-east-1  # お使いのリージョン
```

`parameters/dev.json` を編集:

```json
[
  {"ParameterKey": "AvailabilityZone1", "ParameterValue": "us-east-1a"},
  {"ParameterKey": "AvailabilityZone2", "ParameterValue": "us-east-1c"}
]
```

> **重要**: AZ は最低 2 つ指定すること（Multi-AZ 配置のため）。
> 利用可能な AZ は `aws ec2 describe-availability-zones --query 'AvailabilityZones[*].ZoneName'` で確認。

### VPC CIDR の変更

既存ネットワークと重複しない CIDR を選択:

```json
{"ParameterKey": "VpcCidr", "ParameterValue": "172.16.0.0/16"}
```

テンプレート内のサブネット CIDR (`10.0.1.0/24` 等) も合わせて変更が必要。

### NAT Gateway (スキャナー利用時のみ必要)

```json
{"ParameterKey": "EnableNatGateway", "ParameterValue": "true"}
```

> **コスト注意**: NAT Gateway = ~$33/月 + データ転送。スキャナー不要なら `false` で十分。

---

## Step 2: Lambda Artifact S3 Bucket の作成

```bash
# バケット名は AWS アカウント ID を含めてグローバルユニークにする
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="fsxn-cyber-resilience-lambda-artifacts-${ACCOUNT_ID}"

# バケット作成 (リージョンに合わせて LocationConstraint を指定)
aws s3api create-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION" \
  --create-bucket-configuration LocationConstraint="$AWS_REGION"

# セキュリティ設定 (SSE + Versioning)
aws s3api put-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

aws s3api put-bucket-versioning \
  --bucket "$BUCKET_NAME" \
  --versioning-configuration Status=Enabled

export LAMBDA_ARTIFACT_BUCKET="$BUCKET_NAME"
echo "Created: $BUCKET_NAME"
```

> **us-east-1 の場合**: `--create-bucket-configuration` は不要（デフォルトリージョン）。

---

## Step 3: Lambda パッケージング & アップロード

```bash
./scripts/package-lambdas.sh --upload --bucket "$LAMBDA_ARTIFACT_BUCKET"
```

成功すると `lambda-packages/manifest.json` が生成される:
```json
{
  "event-transformer": "event-transformer-XXXX.zip",
  "quarantine-action": "quarantine-action-XXXX.zip",
  ...
}
```

---

## パターン A: パイプラインのみデプロイ (FSx なし)

最速で動作確認したい場合。FSx for ONTAP 不要。

```bash
# Network Stack
./scripts/deploy.sh dev network

# Event-Driven Stack
./scripts/deploy.sh dev events

# Observability Stack
./scripts/deploy.sh dev observability
```

### 動作確認 (テストイベント投入)

```bash
# SQS Queue URL を取得
QUEUE_URL=$(aws cloudformation describe-stacks \
  --stack-name fsxn-cyber-resilience-events-dev \
  --query "Stacks[0].Outputs[?OutputKey=='SecurityEventQueueUrl'].OutputValue" \
  --output text)

# マルウェア検知テストイベントを送信
aws sqs send-message --queue-url "$QUEUE_URL" --message-body '{
  "source": "fpolicy",
  "event_type": "file_write",
  "verdict": "MALICIOUS",
  "scanner_name": "trendai",
  "file_path": "/production/data/test-malware.exe",
  "file_system_id": "fs-0123456789abcdef0",
  "volume_id": "fsvol-0123456789abcdef0",
  "svm_id": "svm-0123456789abcdef0",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
}'
```

### 結果確認

```bash
# Lambda ログ確認 (イベント変換)
aws logs tail /aws/lambda/fsxn-cyber-resilience-event-transformer-dev --since 5m

# Step Functions 実行確認
SFN_ARN=$(aws cloudformation describe-stacks \
  --stack-name fsxn-cyber-resilience-events-dev \
  --query "Stacks[0].Outputs[?OutputKey=='QuarantineStateMachineArn'].OutputValue" \
  --output text)

aws stepfunctions list-executions \
  --state-machine-arn "$SFN_ARN" \
  --max-results 5 \
  --query 'executions[*].{Status:status,Start:startDate}'
```

**期待される結果**:
- Lambda: `Published: 1, Failed: 0`
- Step Functions: `SUCCEEDED` (FSx がないため CreateSnapshot は失敗するが、Catch → NotifyFailure → SNS 送信で正常完了)

---

## パターン B: フル新規構築

FSx for ONTAP を含む完全な環境を新規作成。

```bash
# 全スタック一括デプロイ (依存順)
./scripts/deploy.sh dev all
```

> **注意**: Storage Stack (FSx for ONTAP) の作成に 20-30 分かかる。

### 追加設定: fsxadmin 認証情報

FSx for ONTAP が作成されたら、管理認証情報を Secrets Manager に格納:

```bash
aws secretsmanager create-secret \
  --name "fsxn-cyber-resilience-fsxadmin" \
  --secret-string '{"username":"fsxadmin","password":"YOUR_ACTUAL_PASSWORD"}' \
  --region "$AWS_REGION"
```

---

## パターン C: 既存環境に追加

既存の VPC + FSx for ONTAP がある場合。

### 1. 環境変数の設定

```bash
cp env.example .env
# .env を編集して実際のリソース ID を記入
source .env
```

### 2. リソース ID の確認方法

```bash
# VPC ID
aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,Tags[?Key==`Name`].Value|[0]]' --output table

# Subnet IDs (VPC 内のサブネット)
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$EXISTING_VPC_ID" \
  --query 'Subnets[*].[SubnetId,AvailabilityZone,CidrBlock,Tags[?Key==`Name`].Value|[0]]' --output table

# Security Group IDs
aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$EXISTING_VPC_ID" \
  --query 'SecurityGroups[*].[GroupId,GroupName,Description]' --output table

# FSx for ONTAP
aws fsx describe-file-systems \
  --query 'FileSystems[*].[FileSystemId,OntapConfiguration.Endpoints.Management.DNSName]' --output table

# SVM
aws fsx describe-storage-virtual-machines \
  --query 'StorageVirtualMachines[*].[StorageVirtualMachineId,Name,FileSystemId]' --output table

# Volumes
aws fsx describe-volumes \
  --query 'Volumes[*].[VolumeId,Name,OntapConfiguration.JunctionPath]' --output table
```

### 3. デプロイ

```bash
make deploy-existing
```

---

## トラブルシューティング / Troubleshooting

### デプロイ時に発生しうるエラー

| エラー | 原因 | 対処 |
|--------|------|------|
| `Cannot export empty value` | パラメータが空文字列のまま Export される | 対象パラメータに値を設定するか、`Condition` を確認 |
| `Invalid State Machine Definition` | Step Functions ASL に無効な JSONPath | `$.detail-type` → ハイフンは JSONPath で無効。テンプレート修正済み |
| `Subnet not available in AZ` | 指定した AZ にサブネットを作成できない | `aws ec2 describe-availability-zones` で利用可能な AZ を確認 |
| `Stack is in ROLLBACK_COMPLETE state` | 前回のデプロイが失敗しロールバック済み | `aws cloudformation delete-stack` で削除してから再デプロイ |
| `Lambda ENI deletion timeout` | VPC Lambda の ENI 削除に 10-20 分かかる | 待機するか、ENI を手動 detach |
| `Security group limit exceeded` | アカウントの SG 上限に到達 | Service Quotas で上限引き上げ |

### Lambda パッケージングのトラブル

| エラー | 原因 | 対処 |
|--------|------|------|
| `S3 bucket required for upload` | `LAMBDA_ARTIFACT_BUCKET` 未設定 | `export LAMBDA_ARTIFACT_BUCKET=<bucket-name>` |
| `Handler file not found in zip` | ソースファイルのパス変更 | `scripts/package-lambdas.sh` のパス定義を確認 |
| Hash が毎回変わる | temp ディレクトリのパスが hash に含まれる | 修正済み (content-only hash) |

### Step Functions のトラブル

| 状態 | 原因 | 対処 |
|------|------|------|
| `FAILED` (CreateSnapshot) | FSx ボリュームが存在しない | 期待通り (パイプラインのみデプロイ時)。NotifyFailure が正常終了すれば OK |
| `RUNNING` (WaitForApproval) | 24h の人間承認待ち | SQS Approval Queue からタスクトークンを取得して `send-task-success` |
| `TIMED_OUT` | 24h 経過で自動タイムアウト | EscalateTimeout → SNS 通知が送信される |

---

## 環境削除 / Cleanup

```bash
# 全スタック削除 (逆順)
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-observability-dev
aws cloudformation wait stack-delete-complete --stack-name fsxn-cyber-resilience-observability-dev

aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-events-dev
# Lambda ENI 削除に時間がかかる (最大20分)
aws cloudformation wait stack-delete-complete --stack-name fsxn-cyber-resilience-events-dev

aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-network-dev
aws cloudformation wait stack-delete-complete --stack-name fsxn-cyber-resilience-network-dev

# S3 バケット削除 (中身を空にしてから)
aws s3 rm "s3://${LAMBDA_ARTIFACT_BUCKET}" --recursive
aws s3api delete-bucket --bucket "$LAMBDA_ARTIFACT_BUCKET"

echo "All resources deleted."
```

> **重要**: FSx for ONTAP を含む Storage Stack の削除は 20-30 分かかる。
> ARP 設定は Stack 削除後も FSx 上に残る (設計上の安全措置)。

---

## 本番環境への移行チェックリスト / Production Readiness Checklist

| # | 項目 | dev | production |
|---|------|-----|-----------|
| 1 | Multi-AZ FSx for ONTAP | Single-AZ | **Multi-AZ 必須** |
| 2 | NAT Gateway | 不要 (scanners なし) | **必須** (署名更新) |
| 3 | Scanner HA (ASG) | 1 instance | **2+ instances (Multi-AZ)** |
| 4 | ARP mode | dry_run (学習) | **enabled** (30日後) |
| 5 | FPolicy is_mandatory | false | 要件に応じて選択。**`true` にしても S3 Access Point 経由の操作は遮断されない**（実測 2026-08-26 / ONTAP 9.18.1P3D1）。AP 経由の経路に強制境界を置くならアクセスポイントポリシーと IAM で表現する |
| 6 | Lambda concurrency | デフォルト | **Reserved 設定済み** |
| 7 | KMS CMK | aws/ebs default | **専用 CMK 推奨** |
| 8 | VPC Flow Logs | ✅ | ✅ |
| 9 | CloudTrail | アカウントデフォルト | **組織レベル有効化** |
| 10 | Notification | なし or テスト | **本番メール/Slack/PagerDuty** |
| 11 | Secrets Manager | テスト値 | **本番 fsxadmin パスワード** |
| 12 | Cost Scheduler | なし | **dev/staging のみ** |
| 13 | DR (SnapMirror) | なし | **別リージョンへレプリケーション** |
| 14 | MAV | なし | **2-admin 承認** |
| 15 | SIEM Integration | なし | **Security Hub + 既存 SIEM** |

---

## パラメータリファレンス / Parameter Reference

### network.yaml

| Parameter | Default | 説明 | 変更タイミング |
|-----------|---------|------|--------------|
| `ProjectName` | `fsxn-cyber-resilience` | リソース命名に使用 | プロジェクトごと |
| `Environment` | `dev` | `dev`/`staging`/`production` | 環境ごと |
| `VpcCidr` | `10.0.0.0/16` | VPC CIDR | 既存ネットワークと重複時 |
| `AvailabilityZone1` | — | 第1 AZ | **リージョンに合わせて必須変更** |
| `AvailabilityZone2` | — | 第2 AZ | **リージョンに合わせて必須変更** |
| `EnableNatGateway` | `false` | NAT Gateway 有効化 | スキャナー利用時 `true` |
| `ClientCidr` | `10.0.0.0/16` | NFS/SMB クライアント許可 CIDR | 本番では制限 |
| `UseExistingVpc` | `false` | 既存 VPC 利用 | 既存環境に追加時 `true` |

### event-driven.yaml

| Parameter | Default | 説明 | 変更タイミング |
|-----------|---------|------|--------------|
| `LambdaArtifactBucket` | — | Lambda zip の S3 バケット | **必須: Step 2 で作成したバケット名** |
| `LambdaArtifactPrefix` | `lambda-packages` | S3 キープレフィックス | 通常変更不要 |
| `EventTransformerS3Key` | — | manifest.json から自動取得 | `deploy.sh` が自動設定 |
| `QuarantineActionS3Key` | — | manifest.json から自動取得 | `deploy.sh` が自動設定 |
| `NotificationEmail` | `''` | アラートメール送信先 | 本番では設定推奨 |

### observability.yaml

| Parameter | Default | 説明 | 変更タイミング |
|-----------|---------|------|--------------|
| `SecurityAlertTopicArn` | — | Event-Driven Stack の出力値 | `deploy.sh` が自動取得 |

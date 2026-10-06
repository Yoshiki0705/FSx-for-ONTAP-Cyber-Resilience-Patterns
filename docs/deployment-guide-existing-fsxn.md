# Deployment Guide: Existing FSx for ONTAP Environment

## 概要 / Overview

既存の Amazon FSx for NetApp ONTAP ファイルシステムに対してサイバーレジリエンスパターンを適用するガイド。
新規 FSx for ONTAP を作成せず、既存リソースを指定して Event-Driven Response パイプラインと
ONTAP セキュリティ設定（ARP, FPolicy）を追加デプロイする。

This guide deploys cyber resilience patterns (event-driven response, ARP, FPolicy) onto an
existing FSx for ONTAP file system without creating new storage resources.

## Prerequisites

- 既存の FSx for ONTAP ファイルシステムが稼働中
- fsxadmin パスワードが判明していること
- AWS CLI v2 + 適切な IAM 権限
- Python 3.12+ (`make test` 用)
- 対象 FSx for ONTAP が配置されている VPC のサブネット ID とセキュリティグループ ID

### Lambda Packaging Prerequisites

Event-Driven Stack のデプロイには Lambda コードパッケージの S3 アップロードが必要:

1. **S3 バケット作成** (初回のみ):
   - Server-Side Encryption (SSE-S3 or SSE-KMS) 有効化
   - Versioning 有効化推奨
   - Bucket Policy: Lambda execution role のみ `s3:GetObject` 許可

2. **環境変数設定**:
   ```bash
   export LAMBDA_ARTIFACT_BUCKET=<your-artifact-bucket-name>
   ```

3. **パッケージング実行**:
   ```bash
   ./scripts/package-lambdas.sh --upload --bucket $LAMBDA_ARTIFACT_BUCKET
   ```

### Stack Deployment Order

全スタックのデプロイ順序と依存関係:

```
1. package-lambdas.sh  (Lambda zip → S3)
2. network.yaml        (VPC, Subnets, SGs, VPC Endpoints, Flow Logs)
3. storage.yaml        (FSx for ONTAP, KMS, ARP/FPolicy Custom Resource)
4. event-driven.yaml   (SQS, EventBridge, Step Functions, Lambda)
5. scanning.yaml       (EC2 scanners: TrendAI Vscan / Deep Instinct)
6. observability.yaml  (CloudWatch Dashboard, Alarms)
```

自動デプロイ:
```bash
./scripts/deploy.sh dev all
```

## Step 1: 情報収集

既存環境から以下の情報を取得:

```bash
# File System ID
aws fsx describe-file-systems --query 'FileSystems[*].[FileSystemId,DNSName]' --output table

# SVM ID
aws fsx describe-storage-virtual-machines \
  --filters Name=file-system-id,Values=<your-file-system-id> \
  --query 'StorageVirtualMachines[*].[StorageVirtualMachineId,Name]' --output table

# Volume ID
aws fsx describe-volumes \
  --filters Name=file-system-id,Values=<your-file-system-id> \
  --query 'Volumes[*].[VolumeId,Name,OntapConfiguration.JunctionPath]' --output table

# Management Endpoint
aws fsx describe-file-systems --file-system-ids <your-file-system-id> \
  --query 'FileSystems[0].OntapConfiguration.Endpoints.Management.DNSName' --output text
```

## Step 2: パラメータファイル作成

`parameters/existing-fsxn.json` をコピーして環境に合わせて編集:

```bash
cp parameters/existing-fsxn.json parameters/my-environment.json
```

以下を実際の値に置換:

| Parameter | Example Value |
|-----------|--------------|
| `ExistingFileSystemId` | `fs-0abc1234def567890` |
| `ExistingManagementEndpoint` | `management.fs-0abc....fsx.ap-northeast-1.amazonaws.com` |
| `ExistingSvmId` | `svm-0abc1234def567890` |
| `ExistingVolumeId` | `fsvol-0abc1234def567890` |
| `FsxAdminPassword` | 実際のパスワード（Secrets Manager 推奨） |

## Step 3: fsxadmin 認証情報を Secrets Manager に格納

```bash
aws secretsmanager create-secret \
  --name "fsxn-cyber-resilience-fsxadmin" \
  --secret-string '{"username":"fsxadmin","password":"<your-password>"}' \
  --region ap-northeast-1
```

## Step 4: Network Stack デプロイ（既存 VPC を使う場合はスキップ）

### Option A: 既存 VPC + 既存リソースを活用（推奨）

```bash
# .env に既存リソース情報を記入後:
source .env
make deploy-existing
```

これにより:
1. Network Stack: 既存 VPC/Subnet/SG の ID をそのまま Export（新規リソース作成なし）
2. Event-Driven Stack: SQS, EventBridge, Step Functions, Lambda を新規作成
3. 既存 VPC 内の Lambda が既存 FSx for ONTAP の ONTAP REST API に到達可能

### Option B: 新規 VPC を作成

既存 VPC を持たない場合や、完全に分離された環境が必要な場合:

```bash
make deploy ENV=dev
```

## Step 5: Event-Driven Response Stack デプロイ

```bash
aws cloudformation deploy \
  --template-file templates/event-driven.yaml \
  --stack-name fsxn-cyber-resilience-events-existing \
  --parameter-overrides \
    ProjectName=fsxn-cyber-resilience \
    Environment=dev \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

## Step 6: ONTAP Security 設定（Custom Resource or 手動）

### Option A: Custom Resource Lambda でデプロイ（推奨）

Storage Stack 経由で Custom Resource を利用:

```bash
aws cloudformation deploy \
  --template-file templates/storage.yaml \
  --stack-name fsxn-cyber-resilience-storage-existing \
  --parameter-overrides file://parameters/my-environment.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

`UseExistingFileSystem=true` により新規 FSx は作成されず、
Custom Resource が既存環境に ARP と FPolicy を設定する。

### Option B: 手動設定（SSH 経由）

```bash
# SSH to management endpoint
ssh fsxadmin@<management-endpoint>

# Enable ARP (learning mode)
security anti-ransomware volume enable -vserver <svm-name> -volume <volume-name> -state dry-run

# Verify
security anti-ransomware volume show
```

FPolicy の詳細設定は [docs/ontap-native/fpolicy-configuration.md](ontap-native/fpolicy-configuration.md) を参照。

## Step 7: 動作確認

### EventBridge イベント確認

```bash
# SQS にテストメッセージを送信
aws sqs send-message \
  --queue-url $(aws cloudformation describe-stacks \
    --stack-name fsxn-cyber-resilience-events-existing \
    --query 'Stacks[0].Outputs[?OutputKey==`SecurityEventQueueUrl`].OutputValue' \
    --output text) \
  --message-body '{
    "source": "fpolicy",
    "event_type": "file_write",
    "file_system_id": "<your-fs-id>",
    "svm_id": "<your-svm-id>",
    "volume_id": "<your-volume-id>",
    "file_path": "/production/test-event.txt",
    "client_ip": "10.0.x.x",
    "user_name": "testuser",
    "timestamp": "2026-06-25T10:00:00Z"
  }'
```

### CloudWatch Logs 確認

```bash
# Event Transformer Lambda ログ
aws logs tail /aws/lambda/fsxn-cyber-resilience-event-transformer-dev --follow

# Step Functions 実行確認（マルウェア検知テスト）
aws sqs send-message \
  --queue-url <queue-url> \
  --message-body '{
    "source": "scanner",
    "scanner_name": "trendai",
    "verdict": "MALICIOUS",
    "file_path": "/production/eicar-test.exe",
    "volume_id": "<your-volume-id>",
    "svm_id": "<your-svm-id>",
    "file_system_id": "<your-fs-id>",
    "timestamp": "2026-06-25T10:30:00Z"
  }'
```

## Step 8: ARP 学習確認（旧世代 ARP のみ、30日後）

この手順が要るのは旧世代 ARP（NAS FlexVol で 9.10.1〜9.15.1、FlexGroup で 9.17.1 まで）に限る。
旧世代では ARP 有効化から30日経過後にアクティブモードへ移行:

```bash
ssh fsxadmin@<management-endpoint>

# Check learning status
security anti-ransomware volume show -vserver <svm-name> -fields state

# If ready, switch to active
security anti-ransomware volume enable -vserver <svm-name> -volume <volume-name> -state active
```

ARP/AI（FlexVol は 9.16.1 以降、FlexGroup は 9.18.1 以降）は学習期間がなく、有効化直後から
能動的に保護する。この世代では `dry_run` を要求しても無言で `enabled` になるため、この手順は
不要になる。世代の判別と実測の根拠は [ARP 設定ガイド](ontap-native/arp-configuration.md) を参照。

## クリーンアップ / Cleanup

```bash
# Event-Driven Stack 削除
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-events-existing

# Storage Stack 削除（既存 FSx には影響なし — Condition により新規リソース未作成）
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-storage-existing

# Secrets Manager シークレット削除
aws secretsmanager delete-secret --secret-id fsxn-cyber-resilience-fsxadmin --force-delete-without-recovery
```

> **Note**: ARP 設定は意図的に Stack 削除後も維持されます（安全のため）。
> 手動で無効化する場合: `security anti-ransomware volume disable -vserver <svm> -volume <vol>`

## トラブルシューティング / Troubleshooting

| Issue | Cause | Resolution |
|-------|-------|------------|
| Lambda が ONTAP API に接続できない | Lambda SG → FSx SG の HTTPS(443) が開いていない | Security Group ルール確認 |
| ARP enable 失敗 | ボリュームが FlexGroup または特殊タイプ | ARP は FlexVol のみ対応。FlexGroup は ONTAP 9.13.1+ |
| FPolicy engine 作成失敗 | scanner サーバーが到達不能 | ネットワーク疎通確認 (telnet <ip> 1344) |
| Custom Resource タイムアウト | ONTAP API 応答遅延 | Lambda タイムアウトを300秒に設定 |
| Secrets Manager アクセスエラー | VPC Endpoint がない | Secrets Manager Interface Endpoint を確認 |

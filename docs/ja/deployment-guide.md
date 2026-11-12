# デプロイガイド — FSx for ONTAP Cyber Resilience Patterns

## 概要

本ガイドでは、FSx for ONTAP Cyber Resilience Patterns リファレンスアーキテクチャを構成する
11 本の CloudFormation テンプレートのデプロイ手順を説明する。
テンプレートは個別（アラカルト）でも、一括でもデプロイ可能。

2 つのデプロイパスをサポート:

| パス | 説明 | ユースケース |
|------|------|------------|
| **Greenfield** | 新規 VPC + 新規 FSx for ONTAP | ラボ、PoC、分離された本番 |
| **Brownfield** | 既存 VPC + 既存 FSx for ONTAP | 稼働中ワークロードへのセキュリティレイヤー追加 |

> **重要**: パラメータファイルを使用する場合は `aws cloudformation create-stack --parameters file://cfn-params/<file>.json` を使用すること。
> `aws cloudformation deploy` は `file://` 形式のパラメータ指定に**非対応**。

---

## 前提条件

| 要件 | 最小バージョン | 備考 |
|------|--------------|------|
| AWS CLI | v2.x | `aws --version` |
| Python | 3.12+ | Lambda パッケージングおよびテスト用 |
| cfn-lint | latest | `pip install cfn-lint` |
| ONTAP バージョン | 9.13.1+ | FlexGroup の ARP には 9.13.1; FlexVol の ARP には 9.11.1+ |
| IAM 権限 | CloudFormation, FSx, EC2, Lambda, IAM, SQS, EventBridge, SNS, SecretsManager, KMS, CloudWatch, Step Functions, S3 | PoC は AdministratorAccess; 本番はスコープ制限 |

### ONTAP バージョン要件

| 機能 | 最小 ONTAP バージョン |
|------|---------------------|
| ARP (FlexVol) | 9.10.1 |
| ARP (FlexGroup) | 9.13.1 |
| FPolicy external engine (async) | 9.7 |
| FPolicy external engine (sync/ICAP) | 9.8 |
| SnapLock Compliance | 9.10.1 |
| Multi-Admin Verification (MAV)。ONTAP のバージョン要件のみ。FSx for ONTAP 9.18.1P6 では `fsxadmin` に拒否された（1 回の観測）[E-025] | 9.11.1 |
| Tamperproof Snapshot | 9.12.1 |

---

## テンプレート一覧

### Phase 1 — コア（必須）

| # | テンプレート | 説明 | デプロイ時間 | 依存 |
|---|------------|------|------------|------|
| 1 | `network.yaml` | VPC、サブネット (Multi-AZ)、Security Groups、VPC Endpoints、Flow Logs | ~3 分 | なし |
| 2 | `storage.yaml` | FSx for ONTAP ファイルシステム、SVM、ボリューム、KMS | ~30 分 | network |
| 3 | `event-driven.yaml` | SQS、EventBridge カスタムバス、Step Functions、Lambda、SNS | ~5 分 | network (Lambda VPC) |
| 4 | `scanning.yaml` | EC2 インスタンス: TrendAI Vscan (ICAP) + Deep Instinct | ~5 分 | network |
| 5 | `observability.yaml` | CloudWatch Dashboard + Alarms | ~2 分 | event-driven (SNS ARN) |

### Phase 2 — 運用

| # | テンプレート | 説明 | デプロイ時間 | 依存 |
|---|------------|------|------------|------|
| 6 | `scanning-ha.yaml` | スキャナー HA 用 Auto Scaling Groups (Multi-AZ) | ~5 分 | network |
| 7 | `cost-scheduler.yaml` | 非営業時間のスキャナー EC2 停止/起動（非本番） | ~2 分 | scanning |

SnapMirror ラグ監視は、このリポジトリのテンプレートではありません。[SnapMirror ラグ監視](#snapmirror-ラグ監視)を参照してください。

### Phase 3 — エンタープライズ / マルチアカウント

| # | テンプレート | 説明 | デプロイ時間 | 依存 |
|---|------------|------|------------|------|
| 8 | `hub-aggregation.yaml` | 集約セキュリティイベント用の中央 EventBridge バス | ~2 分 | なし (ハブアカウント) |
| 9 | `spoke-monitoring.yaml` | クロスアカウント EventBridge 転送 (StackSet 対応) | ~2 分 | hub-aggregation |
| 10 | `siem-integration.yaml` | Security Hub、SIEM フォワーダー (Splunk/QRadar/CEF)、コンプライアンスコレクター | ~5 分 | event-driven |
| 11 | `main.yaml` | ルートネステッドスタック (network + storage + event-driven を統合) | ~35 分 | テンプレート格納 S3 バケット |

---

## Lambda 同時実行数と DLQ (siem-integration)

`siem-integration.yaml` の、EventBridge から呼ばれる Lambda 関数は、同時実行数に上限を設け、失敗したイベントを専用の SQS キューに残します。`siem-integration.yaml` は `main.yaml` に入れ子にされていないため、別のスタックとしてデプロイします。

| 関数 | テンプレート | 予約同時実行数 | DLQ | アラーム |
|------|-------------|----------------|-----|---------|
| `SecurityHubPublisherLambda` | `siem-integration.yaml` | `SecurityHubPublisherReservedConcurrency` (既定 10) | `SecurityHubPublisherDlq` | `SecurityHubPublisherDlqAlarm` |

- キューは AWS マネージドキー `alias/aws/sqs` で暗号化され、メッセージを 14 日間保持し、スタックと一緒に削除されます。
- 実行ロールの `sqs:SendMessage` は、このキューにだけ許可されます。
- アラームは、キューに 1 件以上のメッセージが見えている状態 (5 分周期) で発火し、`SecurityAlertTopicArn` の SNS トピックに通知します。キューにメッセージがあることは、Lambda の再試行後も関数が失敗したことを示します。イベントは 14 日間キューに残るので、内容を確認できます。
- `SecurityHubPublisherReservedConcurrency` (Number、既定 10、最小 1): Lambda はアカウントの同時実行数のうち 100 を未予約のまま残すため、設定できる上限は「アカウントの未予約枠 − 100」です。[Lambda の予約同時実行数](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html)を参照してください。既定の上限 1,000 で他に予約がなければ、上限は 900 です。
- `event-driven.yaml` の `EventTransformerLambda` は SQS キューから取り込みます。SQS をイベントソースにする場合、AWS は DLQ を関数ではなく取り込み元のキューに置く構成とし、この 2 つの取り込み元キューには `RedrivePolicy` が設定済みです。テンプレートでは `CKV_AWS_116` の Checkov 除外として記録しています。
- 未測定: これらの変更は cfn-lint、Checkov、ユニットテストで確認しただけで、デプロイはしていません。

## SnapMirror ラグ監視

このリポジトリには、SnapMirror ラグ監視のテンプレートがありません。Observability リポジトリの Terraform モジュール [`terraform/fsxn-ontap-custom-metrics`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/tree/main/terraform/fsxn-ontap-custom-metrics) を使います。このモジュールは、VPC 内の Lambda 関数が宛先ファイルシステムの `GET /api/snapmirror/relationships` を読み、`FSxONTAP/SnapMirror` の指標（`SnapMirrorLagSecondsMax`、`SnapMirrorUnhealthyCount` など）を発行します。ラグ、不健全なリレーションシップ、収集の停止を検知する CloudWatch アラームも作ります。指標、アラーム、IAM 権限の一覧はモジュールの README にあります。

### 選択する設定

| 設定 | 値 | 補足 |
|------|----|------|
| デプロイ先 | DR リージョン。宛先ファイルシステムに対して実行 | collector は宛先側を読みます。指標とアラームは、モジュールを実行したリージョンに作られます |
| `file_system_id` | 宛先ファイルシステムの ID | |
| `enable_snapmirror_collector` | `true`（モジュールの既定） | qtree の収集が不要なら `enable_qtree_collector = false` |
| `snapmirror_lag_threshold_seconds` | RPO（分）× 2 × 60 | RPO 15 分なら 1,800 秒。モジュールの既定は 10,800 秒で、60〜2,592,000 を受け付けます |
| `notification_email` | 対応者のメールアドレス | モジュールが同じリージョンに SNS トピックを作り、このアドレスを購読させます |

### 通知先

CloudWatch アラームは、他のリージョンの SNS トピックを指定すると拒否されました [E-038]。2026-11-12 に 1 アカウントで確認しました。`us-west-2` のアラームに `ap-northeast-1` のトピックを指定した `PutMetricAlarm` は `ValidationError` になりました。トピックを `us-west-2` に置いた同じ構成では、購読した SQS キューに通知が配信されました。このため、プライマリリージョンの `event-driven.yaml` が作る `SecurityAlertTopic` を、DR 側アラームの通知先にはできません。モジュールが DR リージョンに作るトピックにも、対応者を購読させてください。他のリージョンの組み合わせは試していません。

### 削除した dr-replication.yaml の置き換え

削除した `dr-replication.yaml` の `LagMonitorLambda` は仮実装でした。呼び出しをログに残して返るだけで、指標を発行しませんでした。アラームは、何も発行しない `SnapMirrorLagMinutes` を読み、欠損を正常として扱うため、鳴りませんでした。このスタックをデプロイ済みなら、先にモジュールをデプロイし、`FSxONTAP/SnapMirror` 名前空間の `CollectorSucceeded` が 1 であることを確認してから、旧スタックを削除します。逆の順にすると、ラグのアラームがない期間ができます。削除したテンプレートは、このリポジトリの git 履歴にあります。

### 未測定の項目

- モジュールの README には、2026-10-08 に `ap-northeast-1` で、1 つの SVM 内の 2 ボリューム間のリレーションシップで実行した例が 1 回あります。2 つのファイルシステム間の SnapMirror（クラスターピアリングをまたいで宛先を読む構成）は、未試験として記載されています。先に本番以外のアカウントで試してください。
- 未初期化のリレーションシップは、`lag_time` がなく `healthy: true` を返すため、どちらの SnapMirror アラームも鳴りません（モジュールの README の実行例で 1 回観測）。
- このリポジトリのスタックに対して、モジュールも通知先の確認も実行していません。

## VPC Endpoint 競合マトリクス

### 背景: Gateway Endpoint と Interface Endpoint の違い

| タイプ | メカニズム | DNS への影響 | 競合リスク |
|--------|-----------|-------------|-----------|
| **Gateway Endpoint** | ルートテーブルにプレフィックスリスト宛のエントリを追加 | なし — パブリック DNS をそのまま使用し、プレフィックスリストでルーティング | 低。同一 VPC 内に同一サービスの Gateway EP は**1 つしか作れない**が、異なるサービス間では競合しない。 |
| **Interface Endpoint** | サブネット内に ENI を配置しプライベート IP を付与 + Private DNS オプション | `PrivateDnsEnabled: true` にすると、VPC 全体でそのサービスのパブリック DNS ホスト名がオーバーライドされる | **既存リソースとの組み合わせで高リスク**。Private DNS を有効化すると VPC 内の全トラフィックが Interface EP 経由に強制される。 |

### 既存インフラとの競合シナリオ

| VPC Endpoint | タイプ | 作成元 | 競合する条件 | 解決策 |
|--------------|--------|--------|------------|--------|
| `com.amazonaws.<region>.s3` | Gateway | `network.yaml` | VPC に既に S3 Gateway EP が存在 | **作成スキップ** — 同一 VPC に S3 Gateway EP は 1 つのみ。`UseExistingVpc=true` で既存ルートを利用。 |
| `com.amazonaws.<region>.sqs` | Interface | `network.yaml` | VPC に既に SQS Interface EP が別サブネットに存在 | 同一サービスの Interface EP を同一 VPC に 2 つ作成**不可**。既存 EP を共有。 |
| `com.amazonaws.<region>.secretsmanager` | Interface | `network.yaml` | 既存 EP の `PrivateDnsEnabled=false` | Lambda 呼び出し失敗 — SDK デフォルトエンドポイント解決に Private DNS が**必須**。 |
| `com.amazonaws.<region>.kms` | Interface | `network.yaml` | 同上 | 同様 — Private DNS を有効化するか、コード内でエンドポイント URL を明示指定。 |
| `com.amazonaws.<region>.sts` | Interface | `network.yaml` | 同上 | 同様。 |

### VPC Endpoint デプロイ前チェックリスト

**既存 VPC** へのデプロイ時 (`UseExistingVpc=true`):

1. **S3 Gateway EP**: 既に存在するか確認。存在する場合、本スタックが使用するサブネット（isolated + private ルートテーブル）がルートテーブルアソシエーションに含まれているか確認。
2. **Interface EP** (SQS, SecretsManager, KMS, STS): VPC 内に既に存在するか確認。存在する場合:
   - `PrivateDnsEnabled: true` か確認（Lambda SDK 呼び出しに必須）
   - Security Group がインバウンド HTTPS (443) を VPC CIDR から許可しているか確認
   - Lambda/コンピュートが使用する AZ をカバーするサブネット配置か確認
3. **重複 EP 禁止**: 同一 VPC に同一サービスの Endpoint を 2 つ作成できない。競合がある場合、CloudFormation スタックは `VpceAlreadyExists` で失敗する。

提供の `preflight-check.sh` スクリプトでこれらのチェックを自動化可能。

---

## デプロイパス A: Greenfield（新規 VPC + 新規 FSx for ONTAP）

### Step 1: Lambda パッケージング

```bash
export LAMBDA_ARTIFACT_BUCKET=<your-bucket-name>
./scripts/package-lambdas.sh --upload --bucket "$LAMBDA_ARTIFACT_BUCKET"
```

### Step 2: コアスタックのデプロイ

```bash
# Network
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-network-dev \
  --template-body file://templates/network.yaml \
  --parameters file://cfn-params/network.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1

aws cloudformation wait stack-create-complete \
  --stack-name fsxn-cyber-resilience-network-dev

# Storage (~30 分)
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-storage-dev \
  --template-body file://templates/storage.yaml \
  --parameters file://cfn-params/storage.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1

aws cloudformation wait stack-create-complete \
  --stack-name fsxn-cyber-resilience-storage-dev

# Event-Driven
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-events-dev \
  --template-body file://templates/event-driven.yaml \
  --parameters file://cfn-params/event-driven.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

ARP と FPolicy は、スタックのデプロイ後に [ARP 設定ガイド](../ontap-native/arp-configuration.md) と [FPolicy 設定ガイド](../ontap-native/fpolicy-configuration.md) の CLI / REST の手順で設定する。`svm-prod` のファイルアクセス監査も手作業で有効にする。手順は [持ち出し対応の runbook](../runbooks/data-exfiltration-response.md) にある。

#### 任意: 自管理 KMS キーの指定

スタックは KMS キーを作成しない。既定のパラメータでは暗号化は変わらず、CloudWatch Logs のロググループは CloudWatch Logs の既定の暗号化、Lambda の環境変数は Lambda が用意する既定のキーのままになる。キーの ARN を渡したときだけ、自管理キーで暗号化される。

| パラメータ | テンプレート | 対象 |
|-----------|-------------|------|
| `LogGroupKmsKeyArn` | `network.yaml`、`event-driven.yaml`、`main.yaml` | VPC Flow Logs のロググループ（スタックが VPC を作るときだけ作成される）と Step Functions のロググループ |
| `LambdaEnvKmsKeyArn` | `event-driven.yaml`、`siem-integration.yaml`、`main.yaml`（Event-Driven スタックにだけ渡す） | 隔離アクション、イベント変換、Security Hub 発行の各 Lambda 関数の環境変数 |

`LogGroupKmsKeyArn` のキーの要件。出典は [CloudWatch Logs のドキュメント](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html)。

- 対称キーを使う。キーポリシーで、同じリージョンの CloudWatch Logs サービスプリンシパルを許可する。
- スタックをデプロイする IAM プリンシパルに、そのキーへの `kms:DescribeKey` を付ける。ロググループへキーを関連付けるときに必要になる。
- 既存のロググループに `KmsKeyId` を足す変更は、中断を伴わない更新になる（[`AWS::Logs::LogGroup`](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-loggroup.html)）。ドキュメントに書かれているのは、新しく取り込むデータがキーで暗号化されることまで。それ以前のデータが再暗号化されるかは書かれていない。
- そのキーで暗号化したデータを読むには、キーが有効で、CloudWatch Logs が使える状態にある必要がある。ログの保持期間が終わるまで、キーを残しておく。

`LambdaEnvKmsKeyArn` のキーの要件。出典は [Lambda のドキュメント](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html)。

- スタックをデプロイする IAM プリンシパルに、そのキーへの `kms:CreateGrant` と `kms:Encrypt` を付ける。Lambda はこの権限を使って、キーにグラントを作る。
- 環境変数を参照するユーザーには `kms:Decrypt` が要る。持っていないユーザーでも、関数の管理はできる。
- 既存の関数で `KmsKeyArn` を変える更新は、中断を伴わない（[`AWS::Lambda::Function`](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-function.html)）。

未確認: Step Functions の実行ロールと VPC Flow Logs のロールに、独自の KMS 権限が要るか（CloudWatch Logs のドキュメントは、`PutLogEvents` などを呼ぶプリンシパル向けの KMS 権限を挙げている）。Lambda の実行ロールに、実行時の `kms:Decrypt` が要るか（Lambda のドキュメントが求めているのは、クライアント側暗号化のヘルパーを使う場合だけ）。これらのテンプレートは cfn-lint と Checkov で検査しただけで、キーを指定したデプロイは実行していない。

### Step 3: スキャニングレイヤーのデプロイ

```bash
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-scanning-dev \
  --template-body file://templates/scanning.yaml \
  --parameters file://cfn-params/scanning.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

### Step 4: Observability のデプロイ

```bash
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-observability-dev \
  --template-body file://templates/observability.yaml \
  --parameters file://cfn-params/observability.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

### 自動デプロイ（代替手段）

```bash
./scripts/deploy.sh dev all
```

---

## デプロイパス B: Brownfield（既存 FSx for ONTAP）

### Step 1: 事前検証の実行

```bash
./preflight-check.sh \
  --vpc-id vpc-0123456789abcdef0 \
  --file-system-id fs-0123456789abcdef0 \
  --region ap-northeast-1
```

スクリプトの検証内容:
- VPC Endpoint の競合（S3 Gateway EP 重複、既存 Interface EP）
- Security Group ルール（Lambda→FSx HTTPS 443、FSx→Scanner ICAP 1344）
- 対象 SVM 上の ONTAP S3 サーバー存在確認（FSx for ONTAP S3 AP との構造的競合）

### Step 2: 既存リソース情報の収集

```bash
# File System ID と DNS
aws fsx describe-file-systems \
  --query 'FileSystems[*].[FileSystemId,DNSName]' --output table

# SVM ID
aws fsx describe-storage-virtual-machines \
  --filters Name=file-system-id,Values=<file-system-id> \
  --query 'StorageVirtualMachines[*].[StorageVirtualMachineId,Name]' --output table

# Volume IDs
aws fsx describe-volumes \
  --filters Name=file-system-id,Values=<file-system-id> \
  --query 'Volumes[*].[VolumeId,Name,OntapConfiguration.JunctionPath]' --output table

# Management Endpoint
aws fsx describe-file-systems --file-system-ids <file-system-id> \
  --query 'FileSystems[0].OntapConfiguration.Endpoints.Management.DNSName' --output text
```

### Step 3: fsxadmin 認証情報の格納

```bash
aws secretsmanager create-secret \
  --name "fsxn-cyber-resilience-fsxadmin" \
  --secret-string '{"username":"fsxadmin","password":"<your-password>"}' \
  --region ap-northeast-1
```

### Step 4: 既存 VPC パラメータでのデプロイ

```bash
# Network スタック (UseExistingVpc=true)
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-network-dev \
  --template-body file://templates/network.yaml \
  --parameters file://cfn-params/network-existing-vpc.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

### Step 5: Event-Driven Response のデプロイ

```bash
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-events-dev \
  --template-body file://templates/event-driven.yaml \
  --parameters file://cfn-params/event-driven.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

### Step 6: Storage のデプロイ

```bash
aws cloudformation create-stack \
  --stack-name fsxn-cyber-resilience-storage-dev \
  --template-body file://templates/storage.yaml \
  --parameters file://cfn-params/storage-existing.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

`UseExistingFileSystem=true` により新規 FSx for ONTAP は作成されない。
既存ファイルシステムの ARP と FPolicy は、[ARP 設定ガイド](../ontap-native/arp-configuration.md) と [FPolicy 設定ガイド](../ontap-native/fpolicy-configuration.md) の CLI / REST の手順で設定する。

---

## コスト見積もり (ap-northeast-1)

| コンポーネント | 月額 (USD) | 備考 |
|--------------|-----------|------|
| FSx for ONTAP (Single-AZ, 1 TiB, 128 MBps) | ~$310 | Greenfield のみ |
| FSx for ONTAP (Multi-AZ, 1 TiB, 128 MBps) | ~$620 | 本番 |
| EC2 Vscan (c6g.xlarge) | ~$98 | 24/7 ON_DEMAND |
| EC2 Deep Instinct (c6i.xlarge) | ~$122 | 24/7 ON_DEMAND |
| VPC Interface Endpoints (x4) | ~$30 | SQS, SM, KMS, STS |
| NAT Gateway | ~$33 | + データ転送量 |
| サーバーレス (Lambda, SQS, EventBridge, Step Functions, SNS) | ~$10 | Free Tier でほぼカバー |
| CloudWatch (Dashboard + カスタムメトリクス) | ~$5 | カスタムメトリクス 7 個 |
| **合計 — 最小構成（Brownfield、スキャナー 1 台）** | **~$170/月** | FSx 新規作成なし |
| **合計 — 標準構成（Greenfield、スキャナー 2 台）** | **~$610/月** | Single-AZ FSx |
| **合計 — 本番構成（Multi-AZ、HA スキャナー、DR）** | **~$1,200/月** | フルデプロイ |

> **コスト削減**: `cost-scheduler.yaml` で dev/staging のスキャナー EC2 を非営業時間に
> 停止すると EC2 コストを約 50% 削減可能。

---

## Day 2 運用

### ARP モード移行（旧世代 ARP のみ、デプロイ後 30 日）

この手順が要るのは旧世代 ARP（NAS FlexVol で 9.10.1〜9.15.1、FlexGroup で 9.17.1 まで）に限る。
旧世代は `dry-run`（学習）モードで起動する。30 日間の学習後、次のコマンドで `active` へ移行する。

```bash
ssh fsxadmin@<management-endpoint>
security anti-ransomware volume show -vserver <svm> -fields state
security anti-ransomware volume enable -vserver <svm> -volume <vol> -state active
```

ARP/AI（FlexVol は 9.16.1 以降、FlexGroup は 9.18.1 以降）は学習期間がなく、有効化直後から
能動的に保護する。この世代では `dry_run` を要求しても無言で `enabled` になるため、移行手順は
不要になる。世代の判別と実測の根拠は [ARP 設定ガイド](../ontap-native/arp-configuration.md) を参照。

### スキャナー署名更新

スキャナーは署名更新にアウトバウンド HTTPS が必要:
- **NAT Gateway あり** (`EnableNatGateway=true`): 自動更新
- **NAT Gateway なし**: S3 経由の手動更新または EC2 Instance Connect

### CloudWatch Dashboard

デプロイ後、CloudWatch → Dashboards → `fsxn-cyber-resilience-security-<env>` を参照。

ウィジェット: Security Events Received、Malware Detected、Ransomware Alerts (ARP)、
Quarantine Actions、Scanner Health、Step Functions Executions、SQS DLQ depth。

### アラーム閾値

| アラーム | 閾値 | アクション |
|---------|------|----------|
| マルウェアバースト | >10 検知 / 5 分 | SNS → メール |
| SQS DLQ depth | >0 メッセージ | SNS → メール |
| ARP アラート | >0 ランサムウェアイベント | SNS → メール |
| スキャナーヘルス | 5 分間ハートビートなし | SNS → メール |

---

## ロールバック手順

### スタックレベルのロールバック

CloudFormation はデプロイ失敗時に自動ロールバックを実行する。手動ロールバック:

```bash
# 失敗イベントの確認
aws cloudformation describe-stack-events \
  --stack-name <stack-name> \
  --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`]'

# 失敗スタックの削除
aws cloudformation delete-stack --stack-name <stack-name>
aws cloudformation wait stack-delete-complete --stack-name <stack-name>
```

### ONTAP 設定のロールバック

ARP と FPolicy は ONTAP CLI / REST の手順で設定するのでスタックの管理外にあり、Stack を削除しても FSx for ONTAP 上に残る。
手動で元に戻す場合:

```bash
ssh fsxadmin@<management-endpoint>

# ARP の無効化
security anti-ransomware volume disable -vserver <svm> -volume <vol>

# FPolicy の削除
fpolicy policy disable -vserver <svm> -policy-name <policy>
fpolicy policy scope delete -vserver <svm> -policy-name <policy>
fpolicy policy event delete -vserver <svm> -event-name <event>
fpolicy policy delete -vserver <svm> -policy-name <policy>
fpolicy policy external-engine delete -vserver <svm> -engine-name <engine>
```

### 環境全体のクリーンアップ

```bash
# デプロイの逆順で削除
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-observability-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-scanning-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-events-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-storage-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-network-dev

# Secrets Manager のクリーンアップ
aws secretsmanager delete-secret \
  --secret-id fsxn-cyber-resilience-fsxadmin \
  --force-delete-without-recovery
```

> **注意**: FSx for ONTAP の削除には約 30 分かかる。storage スタックはファイルシステムが
> 完全に削除されるまで `DELETE_IN_PROGRESS` のままとなる。`SkipFinalBackup=true` を
> 指定しない限り、最終バックアップがデフォルトで作成される。

---

## トラブルシューティング

| 症状 | 原因 | 解決策 |
|------|------|--------|
| スタックが `VpceAlreadyExists` で失敗 | VPC 内に重複する VPC Endpoint が存在 | `preflight-check.sh` を実行; 既存 EP を利用するか別サブネットを指定 |
| Lambda が ONTAP REST API に到達不能 | SG に Lambda→FSx TCP/443 ルールがない | `SgLambda` の egress と `SgFsx` の ingress を確認 |
| FPolicy engine 作成失敗 | スキャナーが TCP/1344 で到達不能 | スキャナー SG の ingress と FSx SG の egress (ICAP ポート) を確認 |
| FlexGroup で ARP enable 失敗 | ONTAP バージョン < 9.13.1 | ONTAP をアップグレードするか FlexVol を使用 |
| S3 Gateway EP のルートが伝播しない | ルートテーブルが関連付けられていない | isolated と private の両ルートテーブルが EP 設定に含まれているか確認 |
| スキャナー署名更新失敗 | アウトバウンドインターネットがない | NAT Gateway を有効化 (`EnableNatGateway=true`) または S3 ミラーを使用 |
| SQS メッセージが DLQ に流れる | Lambda 処理エラー | event-transformer Lambda の CloudWatch Logs を確認 |

---

## Security Group リファレンス

| Security Group | Ingress | Egress | 用途 |
|----------------|---------|--------|------|
| `sg-fsx` | NFS 2049 (client, scanners)、SMB 445/139 (client)、HTTPS 443 (Lambda) | ICAP 1344 (scanners)、HTTPS 443 (VPC CIDR) | FSx for ONTAP ENIs |
| `sg-vscan` | ICAP 1344 (FSx) | NFS 2049 (FSx)、HTTPS 443 (0.0.0.0/0 via NAT) | TrendAI Vscan |
| `sg-deep-instinct` | ICAP 1344 (FSx) | NFS 2049 (FSx)、HTTPS 443 (0.0.0.0/0 via NAT) | Deep Instinct agent |
| `sg-lambda` | — | HTTPS 443 (VPC CIDR) | Lambda functions |
| `sg-vpc-endpoints` | HTTPS 443 (VPC CIDR) | — | Interface Endpoints |

---

## 関連ドキュメント

- [既存 FSx for ONTAP 環境への統合](../deployment-guide-existing-fsxn.md)
- [コスト・ライセンス詳細](../verification-environment-cost.md)
- [アーキテクチャ概要](../architecture/overview.md)
- Runbooks: [ARP トリアージ](../runbooks/arp-alert-triage.md) | [ランサムウェア復旧](../runbooks/ransomware-recovery.md) | [スキャナーフェイルオーバー](../runbooks/scanner-failover.md)

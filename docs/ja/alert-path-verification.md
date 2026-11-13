# デプロイ後の通知経路の確認

🌐 [English](../en/alert-path-verification.md) | **日本語**

この手順は、テスト環境にスタックをデプロイし、アラートが受信側に配信されることを確かめます。対象は、`event-driven.yaml` のアラートトピックの鍵とポリシー、隔離ワークフローのデータの流れとエラー処理、`QuarantineExecutionsFailedAlarm` アラーム、`hub-aggregation.yaml` のハブのアラートトピックです。[デプロイガイド](deployment-guide.md)の「セキュリティアラートトピックの暗号化」にある結果は、単独のリソースで試したものです。この手順では、同じ確認をデプロイしたテンプレートに対して行います。

## 確認する内容

| # | 確認すること | 場所 |
|---|--------------|------|
| 1 | 既存のトピックを AWS マネージドキー `aws/sns` からお客様管理キーに変える更新で、トピックが置換されずに済むか | 手順 2 |
| 2 | Step Functions のロールが、暗号化したトピックに発行できるか | 手順 5 の C3 |
| 3 | デプロイしたスタックで、アラームと EventBridge ルールがトピックに配信されるか | 手順 5 の C1、C2 |
| 4 | `ExecutionsFailed` アラームが、期間 300 秒で鳴るか | 手順 5 の C4 |
| 5 | ハブのルールがハブのトピックに配信されるか。ハブのバスポリシーが意図どおりか | 手順 6 |

この手順では、次の 4 つは確認できません。

- `WaitForApproval` 以降の承認フロー。ONTAP が必要なので、FSx for ONTAP を含むデプロイ（クイックスタートのパターン B）が要ります。
- `NotificationFailed` の終了状態。SNS の障害を注入する必要があります。
- `siem-integration.yaml` の `ComplianceCollectorRole` の KMS 権限。そのスタックのデプロイが必要です。
- スポークのアカウントからハブのバスへ転送されたイベント。2 つ目のアカウントが必要です。

## 前提条件

- テスト用の AWS アカウントと、AWS CLI 用の IAM Identity Center のセッション（`aws sso login`）。
- Lambda パッケージ用の S3 バケット。デプロイスクリプトは、バケット名を `LAMBDA_ARTIFACT_BUCKET` から読みます。
- パイプラインのみのスタックのデプロイ時間と費用は、[クイックスタートのパターン A](../quickstart-deployment.md)にあります。手順 1 と手順 3 でこれらのリソースが作られるので、先に費用を判断してください。

## 手順 0: 準備

```
aws sso login
export AWS_REGION=ap-northeast-1
export LAMBDA_ARTIFACT_BUCKET=<自分のバケット名>
git worktree add --detach ../fsxn-cyber-old 7654c64
git worktree add --detach ../fsxn-cyber-new origin/main
```

コミット `7654c64` は、アラートトピックの鍵を変える前の状態です。`fsxn-cyber-new` は現在のテンプレートです。worktree を分けるので、メインのチェックアウトには触れません。

## 手順 1: 旧版のデプロイ

`fsxn-cyber-old` で実行します。クイックスタートの、FSx for ONTAP を含まないパイプラインのみのデプロイです。

```
./scripts/deploy.sh dev package
./scripts/deploy.sh dev network
./scripts/deploy.sh dev events
./scripts/deploy.sh dev observability
```

これで、手順 3 の更新は、`aws/sns` で暗号化したトピックを持つスタックから始まります。

## 手順 2: 変更セットで更新を事前に確認

`fsxn-cyber-new` で実行します。何も変更しません。

```
aws cloudformation create-change-set --stack-name fsxn-cyber-resilience-events-dev --change-set-name main-check --template-body file://templates/event-driven.yaml --capabilities CAPABILITY_NAMED_IAM --parameters ParameterKey=ProjectName,UsePreviousValue=true ParameterKey=Environment,UsePreviousValue=true ParameterKey=NotificationEmail,UsePreviousValue=true ParameterKey=LambdaArtifactBucket,UsePreviousValue=true ParameterKey=LambdaArtifactPrefix,UsePreviousValue=true ParameterKey=EventTransformerS3Key,UsePreviousValue=true ParameterKey=QuarantineActionS3Key,UsePreviousValue=true ParameterKey=LogGroupKmsKeyArn,UsePreviousValue=true ParameterKey=LambdaEnvKmsKeyArn,UsePreviousValue=true
aws cloudformation wait change-set-create-complete --stack-name fsxn-cyber-resilience-events-dev --change-set-name main-check
aws cloudformation describe-change-set --stack-name fsxn-cyber-resilience-events-dev --change-set-name main-check --query 'Changes[].ResourceChange.[LogicalResourceId,Action,Replacement]' --output table
```

| `SecurityAlertTopic` の行 | 判断 |
|---------------------------|------|
| `Modify` と `False` | 手順 3 へ進む |
| `True` または `Conditional` | 中止する。置換されたトピックは ARN が変わり、購読が失われる |

期待する結果は `Modify` と `False` です。これは確認していません。同じ表に、`AlertTopicKey`、`SecurityAlertTopicPolicy`、`QuarantineExecutionsFailedAlarm` が `Add` で出るはずです。

## 手順 3: 更新の適用

```
aws cloudformation execute-change-set --stack-name fsxn-cyber-resilience-events-dev --change-set-name main-check
aws cloudformation wait stack-update-complete --stack-name fsxn-cyber-resilience-events-dev
./scripts/deploy.sh dev observability
```

更新が失敗した場合、CloudFormation が自動で `UPDATE_ROLLBACK_COMPLETE` まで戻します。

## 手順 4: 受信用のキューの購読

SQS キューを使うと、通知が届いたかを機械的に確かめられます。メールの購読には、確認のクリックが要ります。

```
aws cloudformation describe-stacks --stack-name fsxn-cyber-resilience-events-dev --query "Stacks[0].Outputs[?OutputKey=='SecurityAlertTopicArn'].OutputValue" --output text
aws sqs create-queue --queue-name deploycheck-q
aws sqs get-queue-attributes --queue-url <キューの URL> --attribute-names QueueArn
```

キューのポリシーで、トピックからの `sqs:SendMessage` を許可します。条件の `aws:SourceArn` には、トピックの ARN を指定します。そのあと、キューを購読します。

```
aws sns subscribe --topic-arn <トピック ARN> --protocol sqs --notification-endpoint <キュー ARN>
```

## 手順 5: 確認の実行

結果は、`aws sqs receive-message --queue-url <キューの URL> --wait-time-seconds 20 --max-number-of-messages 10` で読みます。

| # | 操作 | 期待する結果 |
|---|------|--------------|
| C1 | `aws cloudwatch set-alarm-state --alarm-name fsxn-cyber-resilience-dlq-messages-dev --state-value ALARM --state-reason deploy-check` | キューに `ALARM` の通知が入り、アラームの履歴に `Successfully executed action` が出る |
| C2 | `aws events put-events --entries '[{"Source":"fsxn.cyber-resilience.probe","DetailType":"DeployCheck","Detail":"{}","EventBusName":"<出力 SecurityEventBusName>"}]'` | キューにイベントの本文が入る |
| C3 | `aws stepfunctions start-execution --state-machine-arn <出力 QuarantineStateMachineArn> --input '{"detail":{"timestamp":"2026-01-01T00:00:00Z","volumeId":"fsvol-0123456789abcdef0","svmId":"svm-0123456789abcdef0","severity":"HIGH"}}'` | 実行は `SUCCEEDED` で終わり、キューに `ERROR: Quarantine Workflow Failed` が入る。ボリュームがないのでスナップショットが失敗し、`NotifyFailure` がロール経由で発行する |
| C4 | `aws stepfunctions start-execution --state-machine-arn <出力 QuarantineStateMachineArn> --input '{}'` | 実行は `FAILED` で終わる。数分後に `fsxn-cyber-resilience-quarantine-executions-failed-dev` が `ALARM` になり、キューに通知が入る |

C2 のイベントは、隔離ルールに一致しない送信元と種別にしてあるので、ワークフローは起動しません。C4 の所要時間は測っていません。期間 60 秒の試験では 104 秒でした。

失敗の読み方は次のとおりです。

- C1 だけが失敗した場合は、鍵ポリシーを疑います。
- C2 だけが失敗した場合は、トピックポリシーを疑います。
- C3 だけが失敗した場合は、Step Functions のロールの KMS 権限を疑います。

## 手順 6: ハブのスタック

組織 ID を指定して、ハブのスタックをデプロイします。

```
aws cloudformation deploy --template-file templates/hub-aggregation.yaml --stack-name fsxn-cyber-resilience-hub-dev --parameter-overrides OrganizationId=<組織 ID>
aws cloudformation describe-stacks --stack-name fsxn-cyber-resilience-hub-dev --query "Stacks[0].Outputs[?OutputKey=='HubAlertTopicArn'].OutputValue" --output text
aws events describe-event-bus --name fsxn-cyber-resilience-hub-dev --query Policy --output text
```

手順 4 と同じ方法でハブのトピックにキューを購読し、ハブのバスにイベントを送ります。

```
aws events put-events --entries '[{"Source":"fsxn.cyber-resilience.fpolicy","DetailType":"MalwareDetected","Detail":"{}","EventBusName":"fsxn-cyber-resilience-hub-dev"}]'
```

キューにイベントの本文が入れば、ハブのルールがハブのトピックに配信しています。

バスポリシーも確認します。`describe-event-bus` の出力に、`"Principal":"*"` と、自分の組織 ID を持つ `aws:PrincipalOrgID` への `StringEquals` 条件が出ていることを確かめます。`OrganizationId` は必須で、`o-` の後に小文字の英数字 10〜32 文字が続く形式です。以前のテンプレートは空の値を受け付け、条件の `Value` を落としていました。ap-northeast-1 での 1 回のデプロイでは、EventBridge が `condition.value` の null を拒否し、ポリシーのリソースが作成に失敗しました。

## 手順 7: 後片付け

```
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-hub-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-observability-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-events-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-network-dev
```

各削除は、`aws cloudformation wait stack-delete-complete --stack-name <名前>` で完了を待ってから、次へ進みます。`deploycheck-q` のキューと購読、Lambda パッケージのバケット（中身を空にしてから削除）、2 つの worktree（`git worktree remove`）も削除します。

`AlertTopicKey` と `HubAlertTopicKey` は、スタックと一緒に削除されます。削除までに 30 日の待機期間があり、その間は削除待ちの状態で残ります。この状態のキーの料金は確認していません。

## 失敗したときの対応

- スタックの更新が失敗した場合は、自動で戻ります（手順 3）。再実行の前に、`aws cloudformation describe-stack-events` で原因を調べてください。
- 確認（手順 5）が失敗した場合は、スタックを戻す必要はありません。上の読み方で原因を調べ、確認が通るまで、テンプレートを本番環境に移さないでください。

## 未測定の項目

- この手順の実行。コマンドはデプロイスクリプトとテンプレートの出力に沿って書いたもので、C1〜C4 はデプロイしたスタックでは実行していません。
- 手順 2 の、トピックの更新がその場で済むか。
- 期間 300 秒での C4 の所要時間。

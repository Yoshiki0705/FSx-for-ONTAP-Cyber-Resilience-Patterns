# ONTAP コマンドと REST API のスナップショット Lambda / ONTAP Command and REST API Snapshot Lambda

FSx for ONTAP の管理者が、**ONTAP のバージョンごとに、自分の管理者アカウントで使えるコマンドと REST API を記録する** Lambda です。ONTAP のバージョンを確認するときに、同じ頻度で取っておくと、バージョンが上がったときに何が増え、何が使えなくなったかを差分で追えます。

A Lambda that records, per ONTAP version, which CLI commands and REST endpoints the ONTAP administrator in a secret can use. Take it as often as you check the ONTAP version, and a version change shows up as a diff.

> **状態**: ユニットテスト（moto と ONTAP の差し替え）と cfn-lint が通り、**実機の FSx for ONTAP（ONTAP 9.18.1P6、Single-AZ）で、このテンプレートのデプロイと1回の実行を確認しました**。結果は手で取ったデータと一致しました。確認の範囲は下の「検証の状態」を参照してください。
>
> **Status**: unit tests and cfn-lint pass, and the template was deployed and run once on a real FSx for ONTAP file system (ONTAP 9.18.1P6, Single-AZ). The result matched data taken by hand. See "Verification status" for the scope.

---

## 何を記録するか / What It Records

| 記録 | 取得元（ONTAP）| 権限で絞られるか |
|---|---|---|
| 実行できる CLI コマンド | `security login role show-user-capability` | 絞られる（実行ユーザーのもの）|
| REST エンドポイント全件 | `security login role show-rest` | 絞られない |
| ロール定義 | `security login role show` | 絞られない |
| 旧 API と CLI の対応 | `security login role show-ontapi` | 絞られない |
| REST の GET の可否 | パスパラメータのない GET を1回ずつ | 絞られる |

- 記録するのは **HTTP コードとエラーコードだけ** です。応答の中身（設定値、ライセンスなど）は保存しません。
- 送るのは **GET だけ** です。POST・PATCH・DELETE は送りません。
- 記録の意味は **実行ユーザーで決まります**。`show-user-capability` と GET の可否は、シークレットのユーザーのものです。`manifest.json` の `ran_as` にユーザー名を残します。

実機（ONTAP 9.18.1P6、`fsxadmin`）で同じ内容を取った結果と読み方は、[ONTAP コマンドと REST API のスナップショット](../../docs/ontap-native/ontap-command-api-snapshot.md) にあります。

---

## 出力 / Output

```
s3://<bucket>/<OutputPrefix>/<FileSystemId>/
  latest.json                          # 最新の実行を指すポインタ / pointer to the newest run
  <ONTAP version>/<yyyymmddThhmmssZ>/
    manifest.json                      # 版、件数、実行ユーザー、取得できなかった項目 / version, counts, ran_as, unavailable
    diff.json                          # 前回との差分 / diff against the previous run
    cli-user-capability.json           # 実行できる CLI コマンド / CLI commands the user can run
    rest-endpoints.json                # REST 全件。操作、対応 CLI、GET の実測 / every REST endpoint with its GET result
    roles.json                         # ロール定義 / role entries
    show-ontapi.json                   # ONTAPI と CLI の対応 / ONTAPI to CLI map
```

[`examples/manifest.example.json`](examples/manifest.example.json) と [`examples/diff.example.json`](examples/diff.example.json) は構造の例です（`diff.example.json` の内容は説明用の仮のもの）。バケットは版の履歴を残すバージョニングつきで、スタックを削除しても残ります。

`diff.json` は、前回との差で次を示します。`changed` が `true` なら、通知先の SNS（任意）に件数だけを送ります。

- 追加・削除された CLI コマンド
- 追加・削除された REST エンドポイント
- GET の HTTP コードが変わったエンドポイント

---

## 使い方 / Deploy

### 前提 / Prerequisites

1. FSx for ONTAP の管理エンドポイントに届く VPC 内のサブネットとセキュリティグループ（管理エンドポイントは VPC 内からのみ到達します）。
2. 同じサブネットから **Secrets Manager と S3 に出られること**。既存の VPC エンドポイントか NAT ゲートウェイを使います。このテンプレートは VPC エンドポイントを作りません。
3. ONTAP 管理者の認証情報のシークレット（JSON で `username` と `password`）。**そのファイルシステム用のシークレット** を使います。
4. 管理エンドポイントの DNS 名（`aws fsx describe-file-systems` の `OntapConfiguration.Endpoints.Management.DNSName`）。
5. アカウントの Lambda 同時実行の上限に余裕があること。このテンプレートは同時実行を 1 に予約します（理由は後述）。

> **シークレットはファイルシステムごとに分ける。** FSx for ONTAP は、どのファイルシステムでも管理ユーザーが `fsxadmin` です。別のファイルシステムのシークレットを使うと認証に失敗し、繰り返すとアカウントがロックされます。シークレットに `FileSystemId` タグを付けておくと、この Lambda はタグが `FileSystemId` パラメータと違うときに、ONTAP へ何も送らずに止まります。タグがないときは警告だけで進みます。

### デプロイ / Deploy

```bash
cd solutions/ontap-catalog-snapshot
cp samconfig.toml.example samconfig.toml     # プレースホルダーを自分の値に
sam build
sam deploy
```

### 実行 / Run

```bash
aws lambda invoke --function-name fsxn-ontap-catalog-snapshot-snapshot --payload '{}' --cli-binary-format raw-in-base64-out /tmp/out.json
cat /tmp/out.json
```

実機（上記の環境）での所要時間は 18 秒でした。タイムアウトは 900 秒です。

---

## パラメータ / Parameters

| パラメータ | 既定 | 内容 |
|---|---|---|
| `FileSystemId` | 必須 | 出力先の名前と、シークレットのタグの照合に使う |
| `ManagementEndpoint` | 必須 | 管理エンドポイントの DNS 名または IP |
| `OntapSecretArn` | 必須 | 管理者の認証情報のシークレット |
| `SecretKmsKeyArn` | 空 | シークレットが自前の KMS キーのときだけ |
| `VpcSubnetIds`, `VpcSecurityGroupIds` | 必須 | 関数を置く VPC のサブネットとセキュリティグループ |
| `ExistingOutputBucketName` | 空 | 空なら、バージョニングと暗号化つきのバケットを作る |
| `OutputPrefix` | `ontap-catalog` | バケット内のキーの接頭辞 |
| `ScheduleState` | `ENABLED` | `DISABLED` にすると定期実行を作らず、手動で実行したときだけ動く。**空文字ではなくこれを使う**（`sam deploy` は空の値を無視して既定値を使う）|
| `ScheduleExpression` | `rate(7 days)` | `ScheduleState` が `ENABLED` のときの EventBridge の式 |
| `ProbeRestGet` | `true` | GET の実測を行うか |
| `ProbeMaxEndpoints` | `400` | GET を実測する上限 |
| `VerifySsl` | `false` | 管理エンドポイントの証明書を検証するか。既定の証明書は公的な CA の署名ではない |
| `NotificationTopicArn` | 空 | 変更があったときの SNS（件数だけ）|
| `LogRetentionInDays` | `90` | ログの保持期間 |

---

## 管理者アカウントを守る設計 / Protecting the Administrator Account

この Lambda は1回の実行で、同じ管理者の認証情報を何百回も使います。**認証に失敗したまま繰り返すと、ONTAP の管理ユーザーがロックされる** ので、次の仕組みを入れています。

| 仕組み | 実装 | 確認 |
|---|---|---|
| 最初の認証失敗で全体を止める | ONTAP のコード `6691623`、またはコードのない 401 で `AuthenticationAbort` | テスト: 認証失敗後に送られるリクエストが 1 件だけ |
| ロールによる 401 は止めない | ONTAP のコードが違う 401（`vsadmin-snaplock` 専用の API など）は記録だけ | テスト: 後続のエンドポイントも実測される |
| 自動リトライなし | `EventInvokeConfig.MaximumRetryAttempts: 0`、EventBridge の `RetryPolicy` も 0 | テンプレートのテスト |
| 同時に1回だけ実行 | `ReservedConcurrentExecutions: 1` | テンプレートのテスト |
| 別のファイルシステムのシークレットを使わない | `FileSystemId` タグの照合。違えば ONTAP へ何も送らない | テスト |
| パスワードをログに出さない | SDK のロガーを WARNING に固定（`LOG_LEVEL=DEBUG` でも）。固定を外すと落ちるテストあり | テスト |
| 応答の中身を保存しない | HTTP コードとエラーコードだけを残す | テスト |
| REST のパスを検証する | ONTAP が返したパスは `^/[A-Za-z0-9/_.-]+$` に合うものだけ使う | テスト |

認証に失敗して止まった場合は、**シークレットの値を直すまで再実行しないでください**。ロックされたときの回復は、`aws fsx update-file-system` でパスワードを再設定し、シークレットを更新する手順です。

---

## 制限と未確認 / Limits and What Is Not Established

- 読み取り専用ユーザー（`fsxadmin-readonly` など）で、4つのコマンドが読めるかは未確認です。読めない項目は `manifest.json` の `unavailable` に HTTP コードが残ります。
- この Lambda が GET を実測するのは、パスパラメータのない GET だけです（ONTAP 9.18.1P6 では 570 のうち 219）。残りは `{uuid}` などの値を Lambda が知らないので、実測の対象にしていません。
- POST・PATCH・DELETE は試しません。副作用があるためです。
- 「すべての CLI コマンド」の一覧ではありません。API に対応づいたものと、実行ユーザーが使えるものだけです。
- 1 回の実行が長引いて残り時間が 90 秒を切ると、GET の実測を打ち切り、`probe_truncated` が `true` になります。
- Multi-AZ や他の ONTAP 版での動作は未確認です。

---

## AI エージェントで自分の環境に実装する / Implement It with an AI Agent

このコードをそのまま使うほか、AI エージェントに自分の環境向けに実装させることもできます。サンプルプロンプトは [`docs/agent-prompts/ontap-catalog-snapshot.md`](../../docs/agent-prompts/ontap-catalog-snapshot.md) にあります。

---

## 検証の状態 / Verification Status

| 項目 | 状態 |
|---|---|
| ユニットテスト（`tests/test_ontap_catalog_snapshot.py`、`tests/test_ontap_catalog_snapshot_template.py`）| 通過 |
| cfn-lint | 通過 |
| 実機の FSx for ONTAP でのデプロイと実行 | ONTAP 9.18.1P6、Single-AZ、`fsxadmin`、ap-northeast-1 で確認（下記）|

### 実機での確認 / What the Real Run Showed

- 所要時間は 18 秒（サブネットは FSx と同じプライベートサブネット。S3 のゲートウェイエンドポイントと Secrets Manager のインターフェイスエンドポイントを使用）。
- CLI コマンド 1,744 件、REST エンドポイント 570 件、ONTAPI 対応 1,045 件、GET の実測 219 件が、手で取ったデータと同じ集合で、GET の結果の差は 0 件でした。
- `roles.json` の件数は、手で取った `fsxadmin` 1 ロールの件数ではなく、クラスタと全 SVM のロール定義（3,844 件）です。
- S3 の成果物とログにパスワードは含まれていませんでした。
- 2 回目の実行（19 秒）は、1 回目の記録を読んで比較し、差分なし（`changed: false`）でした。S3 には 2 回分の記録が残り、`latest.json` が新しい実行を指します。`ListBucket` を許可した後は、前回の読み取りに関する警告は出ませんでした。
- ONTAP の版が違う場合や、コマンド・API が増減した場合の差分は、**実機では起きていません**（版が変わらなかったため）。ユニットテストの差分（追加・削除・GET コードの変化）で確認しています。
- 認証が失敗した場合の停止は、**ユニットテストで確認し、実機では起こしていません**（ロックを避けるため、意図的に試していません）。
- 実行は 2 回のみです。所要時間の揺れ、Multi-AZ、他の ONTAP 版は未確認です。

## 関連 / Related

- [ONTAP コマンドと REST API のスナップショット（ONTAP 9.18.1P6）](../../docs/ontap-native/ontap-command-api-snapshot.md): この Lambda が取る内容を、実機で手で取ったときの結果と読み方
- [fsxadmin Permissions & Limitations](../../docs/ontap-native/fsxadmin-limitations.md)
- [Multi-Admin Verification (MAV) Configuration](../../docs/ontap-native/mav-configuration.md)

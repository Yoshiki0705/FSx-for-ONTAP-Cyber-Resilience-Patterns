# ONTAP カタログスナップショットを AI エージェントに実装させるプロンプト / Prompts for Implementing the ONTAP Catalog Snapshot with an AI Agent

[`solutions/ontap-catalog-snapshot/`](../../solutions/ontap-catalog-snapshot/README.md) の Lambda を、自分の環境に合わせて AI エージェント（Kiro、Claude Code、その他のコーディングエージェント）に実装・導入させるためのプロンプトです。<...> を自分の値に置き換えて貼り付けます。

Prompts for having an AI coding agent implement or adopt the Lambda in `solutions/ontap-catalog-snapshot/` for your own environment. Replace the <...> placeholders and paste.

## どちらを使うか / Which One to Use

| 状況 / Situation | 使うプロンプト / Prompt |
|---|---|
| このリポジトリのコードを使わず、自分のルールで作りたい | プロンプト A（仕様から実装）|
| このリポジトリのサンプルを、自分の VPC・シークレットに合わせて導入したい | プロンプト B（サンプルの導入）|

どちらのプロンプトも、**管理者アカウントのロックアウトを避ける制約** と、**エージェントが勝手に実行・デプロイしないための停止条件** を含みます。この2つは外さないでください。

Both prompts carry the constraints that avoid locking the administrator account, and stop conditions so the agent does not run or deploy on its own. Do not remove either.

---

## プロンプト A: 仕様から実装する / Prompt A: Implement from a Specification

```text
あなたは AWS と NetApp ONTAP に詳しい開発者です。次の仕様で、Amazon FSx for NetApp ONTAP の
ONTAP 管理者が使うスナップショット用 Lambda を、SAM（AWS CloudFormation）と Python で実装してください。

## 目的
ONTAP の版ごとに、管理者アカウントが使える CLI コマンドと REST API を記録し、前回との差分を残す。

## 取得するもの（ONTAP REST API の CLI パススルー経由。すべて GET）
- GET /api/private/cli/security/login/role?fields=vserver,role,cmddirname,access,query&max_records=20000
  （security login role show: ロール定義）
- GET /api/private/cli/security/login/role/show-user-capability?fields=object_name,operation_name&max_records=20000
  （実行ユーザーが実行できる CLI コマンド。object_name はドット区切り）
- GET /api/private/cli/security/login/role/show-rest?fields=endpoint,commands,supported-operations&max_records=20000
  （この版の REST エンドポイント全件。権限に関係なく返る）
- GET /api/private/cli/security/login/role/show-ontapi?fields=ontapi,command&max_records=20000
- GET /api/cluster?fields=name,version（版の取得。version.full から "9.18.1P6" のような版を取り出す）
- 追加で、show-rest の結果のうち GET を持ち、パスパラメータ（{...} や $）がないエンドポイントに
  GET <endpoint>?max_records=1 を 1 回ずつ送り、HTTP コードと ONTAP のエラーコードだけを記録する。
  応答の中身は保存しない。
- fields=* は使えない（CLI ベースの REST では拒否される）。フィールド名を列挙する。
- ページ送りがあれば _links.next.href を辿る。ただし /api/private/cli/ で始まらない href は辿らない。

## 出力（S3）
<prefix>/<FileSystemId>/<ONTAP 版>/<yyyymmddThhmmssZ>/ に、manifest.json、diff.json、
cli-user-capability.json、rest-endpoints.json、roles.json、show-ontapi.json を書く。
<prefix>/<FileSystemId>/latest.json に最新の実行を指すポインタを書く。
バケットはバージョニング、SSE-KMS、パブリックアクセスブロック、TLS 強制を有効にし、スタック削除でも残す。
diff.json は前回との差（追加・削除された CLI コマンドと REST エンドポイント、GET の HTTP コードが
変わったエンドポイント）。manifest.json には ONTAP の版、件数、実行ユーザー名、取得できなかった項目、
get_only=true、bodies_stored=false を入れる。

## 絶対に守る制約（管理者アカウントのロックアウト防止）
1. ONTAP へ送るのは GET だけ。POST・PATCH・DELETE は書かない。
2. 認証失敗を再試行しない。/api/cluster が 200 以外なら、他の呼び出しをせず終了する。
   途中で ONTAP のエラーコード 6691623（または ONTAP コードのない 401）が返ったら、その場で全体を止める。
   HTTP エラー（401、403、500）を再試行しない。接続の切断だけ、新しい接続で 1 回だけ再試行してよい。
3. 401 でも、ONTAP のコードが 6691623 以外（例: 特定の SVM ロール専用の API の認可メッセージ）は
   ログイン失敗ではない。記録して次へ進む。403 も記録して次へ進む。
4. Lambda の非同期リトライを 0 にする（EventInvokeConfig.MaximumRetryAttempts: 0）。EventBridge の
   RetryPolicy も 0。同時実行を 1 に予約する（ReservedConcurrentExecutions: 1）。
5. パスワードをログ、例外メッセージ、S3、戻り値に出さない。boto3 と botocore のロガーは、LOG_LEVEL に
   関係なく WARNING にする（botocore は DEBUG で GetSecretValue の応答を出す）。
6. シークレットは JSON（username、password）で受け取る。シークレットに FileSystemId タグがあり、
   パラメータの FileSystemId と違うなら、ONTAP へ何も送らずに止める。
7. ONTAP が返したパスを使う前に、^/[A-Za-z0-9/_.-]+$ に合い、".." を含まないことを確認する。
8. 管理エンドポイントは VPC 内からのみ到達する。Lambda は VPC に置く。VPC エンドポイントや
   NAT ゲートウェイは新規に作らず、既存のものを前提にする。
9. IAM は最小権限にする。シークレットは ARN を 1 つだけ指定（GetSecretValue と DescribeSecret）。
   S3 は出力先の接頭辞だけ。Action と Resource に * を使わない（ネットワークインターフェイス用の
   AWSLambdaVPCAccessExecutionRole を除く）。

## 実装
- Python 3.12、arm64、標準ライブラリと boto3 だけ（外部ライブラリを増やさない）。ハンドラは 1 ファイル。
- 管理エンドポイントの DNS 名はパラメータで受け取る（FSx API を呼ばない）。TLS 検証は既定で無効にし、
  パラメータで有効にできるようにする（既定の管理エンドポイントの証明書は公的な CA の署名ではない）。
- 実行時間が長い場合に備え、残り時間が 90 秒を切ったら GET の実測を打ち切り、manifest に記録する。
- 個人名、アカウント ID、実在の ID、IP をコードやサンプルに書かない。プレースホルダー
  （123456789012、fs-0123456789abcdef0、RFC 5737 の IP）を使う。

## テスト（pytest。実機に接続しない）
ONTAP は差し替え、S3 と Secrets Manager は moto を使う。次を必ずテストにする。
- 認証失敗（6691623）の後に ONTAP へ送られるリクエストが 1 件だけである（失敗するテストを先に書く）。
- ロールによる 401（別の ONTAP コード）の後も、残りのエンドポイントを実測する。
- 送った HTTP メソッドが GET だけである。送った fields 文字列が仕様どおりである。
- パスパラメータのあるエンドポイントと、GET を持たないエンドポイントを実測しない。
- 不正なパス（".." を含む）と、/api/private/cli/ で始まらない next リンクを使わない。
- LOG_LEVEL=DEBUG でもパスワードがログに出ない。ロガー固定を外すとこのテストが落ちることを確認する。
- 別のファイルシステムのタグが付いたシークレットでは、ONTAP へ何も送らない。
- 2 回目の実行で diff に差分が出る。差分がなければ changed=false。
- テンプレートの MaximumRetryAttempts が 0、ReservedConcurrentExecutions が 1。
- ハンドラが読むすべての環境変数をテンプレートが設定している。

## 完了条件と停止条件
- pytest、ruff、cfn-lint が通る。結果を貼る。
- 実装が終わったら止まる。sam deploy も、Lambda の実行も、ONTAP への接続も、私が許可するまでしない。
  デプロイの前に、作るリソースの一覧（Lambda、バケット、IAM ロール、イベントルール）を私に見せる。
- 認証が失敗した場合は、再実行せず、原因（シークレットの取り違え、パスワードの期限）を報告して止まる。
```

```text
You are a developer who knows AWS and NetApp ONTAP. Implement, with SAM (AWS CloudFormation) and Python,
a snapshot Lambda for the ONTAP administrator of Amazon FSx for NetApp ONTAP, to this specification.

## Purpose
Record, per ONTAP version, the CLI commands and REST APIs the administrator account can use, and keep a
diff against the previous run.

## What to read (ONTAP REST API, CLI pass-through, GET only)
- GET /api/private/cli/security/login/role?fields=vserver,role,cmddirname,access,query&max_records=20000
  (security login role show: role definitions)
- GET /api/private/cli/security/login/role/show-user-capability?fields=object_name,operation_name&max_records=20000
  (CLI commands the running user can run; object_name is dot-separated)
- GET /api/private/cli/security/login/role/show-rest?fields=endpoint,commands,supported-operations&max_records=20000
  (every REST endpoint of the version, whatever the privilege)
- GET /api/private/cli/security/login/role/show-ontapi?fields=ontapi,command&max_records=20000
- GET /api/cluster?fields=name,version (take a version such as "9.18.1P6" from version.full)
- Then, for each show-rest endpoint that supports GET and has no path parameter ({...} or $), send one
  GET <endpoint>?max_records=1 and keep only the HTTP code and the ONTAP error code. Do not store bodies.
- fields=* is rejected for CLI-based REST. List the field names.
- Follow _links.next.href for paging, but never an href that does not start with /api/private/cli/.

## Output (S3)
Write manifest.json, diff.json, cli-user-capability.json, rest-endpoints.json, roles.json and
show-ontapi.json under <prefix>/<FileSystemId>/<ONTAP version>/<yyyymmddThhmmssZ>/, and a pointer
<prefix>/<FileSystemId>/latest.json to the newest run. The bucket has versioning, SSE-KMS, public access
block and TLS enforcement, and is kept when the stack is deleted. diff.json lists CLI commands and REST
endpoints added or removed, and endpoints whose GET HTTP code changed. manifest.json holds the ONTAP
version, counts, the user name it ran as, what was unavailable, get_only=true and bodies_stored=false.

## Constraints you must keep (avoid locking the administrator account)
1. Send only GET to ONTAP. Write no POST, PATCH or DELETE.
2. Never retry an authentication failure. If /api/cluster is not 200, stop without any other call. If
   ONTAP error code 6691623 (or a 401 with no ONTAP code) comes back midway, stop the whole run at once.
   Do not retry HTTP errors (401, 403, 500). Only a dropped connection may be retried, once, on a new connection.
3. A 401 whose ONTAP code is not 6691623 (for example the authorization message of an API restricted to one
   SVM role) is not a failed login. Record it and go on. Record a 403 and go on.
4. Set the Lambda asynchronous retries to 0 (EventInvokeConfig.MaximumRetryAttempts: 0) and the EventBridge
   RetryPolicy to 0. Reserve concurrency 1 (ReservedConcurrentExecutions: 1).
5. Never put the password in logs, exception messages, S3 or return values. Keep the boto3 and botocore
   loggers at WARNING whatever LOG_LEVEL says (botocore logs the GetSecretValue response at DEBUG).
6. Read the secret as JSON (username, password). If the secret has a FileSystemId tag that differs from the
   FileSystemId parameter, send nothing to ONTAP and stop.
7. Before using a path ONTAP returned, check it matches ^/[A-Za-z0-9/_.-]+$ and has no "..".
8. The management endpoint is reachable only from inside the VPC. Put the Lambda in the VPC. Do not create
   VPC endpoints or NAT gateways; assume existing ones.
9. Least privilege. One secret ARN (GetSecretValue and DescribeSecret). S3 only on the output prefix. No *
   in Action or Resource (except the AWSLambdaVPCAccessExecutionRole managed policy for network interfaces).

## Implementation
- Python 3.12, arm64, standard library and boto3 only. One handler file.
- Take the management endpoint DNS name as a parameter (no FSx API call). TLS verification off by default,
  switchable by parameter (the default endpoint certificate is not signed by a public CA).
- When less than 90 seconds remain, stop the GET probe and record it in the manifest.
- No personal names, account IDs, real resource IDs or IPs in code or samples. Use placeholders
  (123456789012, fs-0123456789abcdef0, RFC 5737 addresses).

## Tests (pytest, no connection to a real ONTAP)
Stand in for ONTAP; use moto for S3 and Secrets Manager. These must exist:
- After an authentication failure (6691623) exactly one request was sent to ONTAP (write the failing test first).
- After a role-based 401 (another ONTAP code) the remaining endpoints are still probed.
- Only GET was sent; the fields strings sent match the specification.
- Endpoints with path parameters, or without GET, are not probed.
- A path with ".." and a next link that does not start with /api/private/cli/ are not used.
- With LOG_LEVEL=DEBUG the password is not in the log; removing the logger setting makes this test fail.
- A secret tagged for another file system sends nothing to ONTAP.
- The second run shows a diff; with no change, changed=false.
- MaximumRetryAttempts is 0 and ReservedConcurrentExecutions is 1 in the template.
- Every environment variable the handler reads is set by the template.

## Done, and when to stop
- pytest, ruff and cfn-lint pass; show the results.
- Stop when the implementation is done. Do not run sam deploy, invoke the Lambda or connect to ONTAP until I
  allow it. Before any deploy, show me the list of resources (Lambda, bucket, IAM role, event rule).
- If authentication fails, do not run again. Report the likely cause (wrong secret, expired password) and stop.
```

---

## プロンプト B: サンプルを自分の環境に導入する / Prompt B: Adopt the Sample in Your Environment

```text
FSx for ONTAP の ONTAP カタログスナップショット Lambda を、私の AWS 環境に導入する準備をしてください。
サンプルは <このリポジトリの URL またはパス>/solutions/ontap-catalog-snapshot/ にあります。
README.md、template.yaml、functions/snapshot/handler.py、tests/ を先に全部読んでください。

## 私の環境（分かっているものを埋め、分からないものは「不明」と書く）
- リージョン: <例 ap-northeast-1>
- FSx for ONTAP ファイルシステム ID: <fs-...>
- 管理エンドポイント: <DNS 名。不明なら aws fsx describe-file-systems で調べてよい（読み取りのみ）>
- ONTAP 管理者のシークレット: <ARN。不明なら一覧から探してよいが、値は読まない>
- 関数を置く VPC / サブネット / セキュリティグループ: <ID。不明なら調べてよい（読み取りのみ）>
- Secrets Manager と S3 への経路: <VPC エンドポイント / NAT / 不明>
- 出力先バケット: <既存のバケット名 / 新規作成>
- 実行間隔: <rate(7 days) など。手動のみなら空>
- 通知: <SNS トピック ARN / なし>

## やること
1. 環境の事実を確かめる（読み取りのみ）。次を表にして報告する。
   - シークレットの FileSystemId タグ。**タグがない、または別のファイルシステムのものなら、ここで止めて私に聞く。**
   - 選んだサブネットから、Secrets Manager と S3 に出る経路があるか（VPC エンドポイントまたは NAT）。
   - セキュリティグループが、ファイルシステムのセキュリティグループへの HTTPS（443）を出せるか。
   - 管理エンドポイントの DNS 名が、そのファイルシステムのものか。
2. samconfig.toml を作る（samconfig.toml.example を基に。値はプレースホルダーのままにせず私の値にする。
   ただし samconfig.toml は git に入れない）。
3. 次を実行し、結果を貼る: pytest tests/test_ontap_catalog_snapshot.py tests/test_ontap_catalog_snapshot_template.py、
   cfn-lint solutions/ontap-catalog-snapshot/template.yaml、sam validate --lint。
4. sam build まで実行してよい。
5. **ここで止める。** sam deploy の前に、sam deploy の変更セット（--no-execute-changeset）の内容、
   つまり作られるリソース（Lambda、ロググループ、IAM ロール、イベントルール、バケット）と、
   IAM ポリシーの全文を私に見せ、承認を待つ。

## 守ること
- ONTAP への接続、Lambda の実行、sam deploy は、私が明示的に許可するまでしない。
- 認証情報を使う操作で一度でも認証に失敗したら、再実行せず止まり、原因を報告する。
  （同じ管理者を何度も試すと、ONTAP の管理ユーザーがロックされる。）
- シークレットの値、パスワード、アクセスキーを、画面、ログ、ファイル、コミットに出さない。
- コードを変えるときは、変更の理由を述べ、テストを先に書く。手順 3 のテストを弱めない。
  特に、認証失敗後に 1 件しか送らないテストと、パスワードがログに出ないテストは外さない。
- テンプレートの ReservedConcurrentExecutions: 1 と MaximumRetryAttempts: 0 は変えない。
  アカウントの同時実行の上限で予約できない場合は、変えずに私に報告する。
- アカウント ID、ID、IP を、コミットするファイルに書かない。
```

```text
Prepare to adopt the FSx for ONTAP "ONTAP catalog snapshot" Lambda in my AWS environment.
The sample is at <repository URL or path>/solutions/ontap-catalog-snapshot/.
Read README.md, template.yaml, functions/snapshot/handler.py and tests/ completely first.

## My environment (fill in what is known; write "unknown" for the rest)
- Region: <e.g. ap-northeast-1>
- FSx for ONTAP file system ID: <fs-...>
- Management endpoint: <DNS name; if unknown you may look it up with aws fsx describe-file-systems (read only)>
- ONTAP administrator secret: <ARN; if unknown you may find it in the list, but do not read its value>
- VPC / subnets / security groups for the function: <IDs; if unknown you may look them up (read only)>
- Route to Secrets Manager and S3: <VPC endpoints / NAT / unknown>
- Output bucket: <existing bucket name / create one>
- Schedule: <rate(7 days) etc.; empty for manual only>
- Notification: <SNS topic ARN / none>

## What to do
1. Check the facts of the environment (read only) and report them as a table:
   - The secret's FileSystemId tag. **If it is missing or belongs to another file system, stop here and ask me.**
   - Whether the chosen subnets have a route to Secrets Manager and S3 (VPC endpoints or NAT).
   - Whether the security group allows outbound HTTPS (443) to the file system's security group.
   - Whether the management endpoint DNS name belongs to that file system.
2. Create samconfig.toml from samconfig.toml.example with my values (do not leave placeholders; keep it out of git).
3. Run and show the results: pytest tests/test_ontap_catalog_snapshot.py tests/test_ontap_catalog_snapshot_template.py,
   cfn-lint solutions/ontap-catalog-snapshot/template.yaml, sam validate --lint.
4. You may run sam build.
5. **Stop here.** Before sam deploy, show me the change set (--no-execute-changeset): the resources that would be
   created (Lambda, log group, IAM role, event rule, bucket) and the full IAM policy, and wait for my approval.

## Rules
- Do not connect to ONTAP, invoke the Lambda or run sam deploy until I explicitly allow it.
- If any operation that uses the credential fails authentication even once, do not run it again; stop and
  report the cause. (Trying the same administrator repeatedly locks the ONTAP management user.)
- Never show the secret value, a password or an access key on screen, in logs, files or commits.
- When you change code, state why and write the test first. Do not weaken the tests of step 3. In particular,
  keep the test that only one request is sent after an authentication failure and the test that the password
  does not reach the log.
- Do not change ReservedConcurrentExecutions: 1 or MaximumRetryAttempts: 0. If the account's concurrency quota
  prevents the reservation, report it to me instead of changing it.
- Do not write account IDs, resource IDs or IPs into files that will be committed.
```

---

## プロンプトの確認方法 / How These Prompts Were Checked

- プロンプト A の受け入れ基準は、`tests/test_ontap_catalog_snapshot.py` と `tests/test_ontap_catalog_snapshot_template.py` が検査する項目と対応しています。エージェントが作ったコードも、同じ観点のテストで確認できます。
- **エージェントにこのプロンプトを実際に与えて、実装を作らせた結果は確認していません。** プロンプトの質は、使う環境で確かめてください。

- The acceptance criteria of Prompt A correspond to what the repository tests check, so code an agent produces can be checked the same way.
- **Giving these prompts to an agent and checking what it builds has not been done.** Judge the prompts in your own environment.

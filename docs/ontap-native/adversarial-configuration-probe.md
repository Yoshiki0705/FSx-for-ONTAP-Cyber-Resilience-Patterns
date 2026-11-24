# 攻撃者の視点で設定を読む読み取り専用プローブ / Read-Only Adversarial Configuration Probe

## 結論 / Conclusion

[`solutions/config-probe/`](../../solutions/config-probe/config_probe/cli.py) は、Amazon FSx for NetApp ONTAP の ONTAP 設定を REST API の GET だけで読み、AWS 側の設定（暗号化キー、バックアップ、S3 Access Points）を読み取り専用の API で読み、設定ごとに「ある前提を手にした攻撃者が何をできるか」を JSON で出力します。侵入テストではありません。書き込みを一切送らず、脆弱性を突かず、応答の本文を保存しません。

AWS Security Agent と AWS Continuum は、アプリケーションとコードを対象にします。ここで読んだ AWS の文書には、ストレージ設定を入力に挙げた記載がありません [E-026]。このプローブはストレージ側を補う位置にあり、両者を置き換えるものではありません。

状態: 単体テスト（合成データ）だけを通しています。実機のファイルシステムに対しては、まだ実行していません（[実機での確認](#実機での確認--run-against-a-real-file-system)）。

`solutions/config-probe/` reads the ONTAP settings of Amazon FSx for NetApp ONTAP with REST GET requests only, reads the AWS side (encryption key, backups, S3 Access Points) with read-only API calls, and writes JSON that states, for each setting, what an attacker who already holds a given precondition could do. It is not a penetration test: it sends no write, exploits nothing and stores no response body.

AWS Security Agent and AWS Continuum work on applications and code; the AWS documents read here list no storage configuration among their inputs [E-026]. The probe covers the storage side and replaces neither.

Status: unit-tested against synthetic data only; not yet run against a real file system (see the last section).

---

## このプローブの位置づけ / Where the Probe Fits

AWS CTO のブログ記事 [Tech predictions for 2027 and beyond](https://www.allthingsdistributed.com/2026/11/tech-predictions-for-2027-and-beyond.html) は、脆弱性の発見から悪用までの期間とコストが下がっているという傾向を挙げています。このリポジトリでは、その傾向への備えとして、攻撃側の観点の検査を設計の前、リリースの前、稼働中の各段階に置きます。各段階の分担は [Continuum と Security Agent の文書](../architecture/continuum-security-agent-and-storage.md#全工程で続ける攻撃側の検査--adversarial-checks-through-every-phase) にまとめています。

The AWS CTO's blog post [Tech predictions for 2027 and beyond](https://www.allthingsdistributed.com/2026/11/tech-predictions-for-2027-and-beyond.html) notes that the time and cost from finding a weakness to exploiting it are falling. This repository answers that trend by placing checks from the attacker's side before design, before release and while the system runs. Who does what at each stage is in the Continuum and Security Agent document.

| 段階 / Stage | 道具 / Tool | 対象 / What it looks at |
|---|---|---|
| 設計・実装の前 / Before design and code | [攻撃者視点のレビュー用プロンプト](../agent-prompts/adversarial-review.md) / Adversarial review prompts | 仕様、テンプレート、構成図、IAM ポリシー、アクセスポイントポリシー / Specs, templates, diagrams, IAM and access point policies |
| リリース前・変更後 / Before release, after a change | このプローブ（`--fail-on high`）/ This probe | ONTAP と AWS 側の実際の設定 / The actual ONTAP and AWS settings |
| 稼働中 / While running | このプローブの定期実行、ARP、FPolicy、監査ログ / Scheduled probe runs, ARP, FPolicy, audit log | 設定の変化と、データへの操作 / Setting drift and operations on data |
| 侵入テスト / Penetration test | AWS Security Agent と [クローン隔離の手順書](../runbooks/pentest-clone-isolation.md) / AWS Security Agent with the clone isolation runbook | 実行中のアプリケーション / The running application |

---

## 検査項目 / Checks

各行の REST パスは、ONTAP 9.18.1P6 の FSx for ONTAP で GET を持つエンドポイントとして [`fsx-ontap-9.18.1P6-rest-endpoints.tsv`](data/fsx-ontap-9.18.1P6-rest-endpoints.tsv) に載っています。テスト `tests/test_config_probe.py` が、コードの使うパスがすべてこの一覧にあることを確かめます。

Every REST path below is a GET endpoint of ONTAP 9.18.1P6 on FSx for ONTAP in the catalog TSV; `tests/test_config_probe.py` checks that every path the code uses is listed there.

| ID | 検査 / Check | 読む場所 / Read from | 所見の意味 / What a finding means | 攻撃者の前提 / Attacker precondition | 重大度 / Severity |
|---|---|---|---|---|---|
| ARP-001 | ARP が保護していない読み書きボリューム / RW volume not protected by ARP | `/api/storage/volumes` | 暗号化や上書きが、ボックス上の検知と自動スナップショットなしで進む / Encryption or overwrite proceeds with no on-box detection or automatic snapshot | データプロトコルの認証情報 / Data-protocol credentials | medium |
| ARP-002 | 新規ボリュームへの ARP 自動有効化がオフ / ARP auto-enable off | `/api/security/anti-ransomware/auto-enable` | 新しいボリュームは誰かが有効にするまで無防備 / New volumes stay unprotected until someone enables ARP | データプロトコルの認証情報 / Data-protocol credentials | medium |
| ARP-003 | 未処理の ARP 疑い / Unhandled ARP suspects | `/api/security/anti-ransomware/suspects` | 攻撃が進行中か、過去のアラートが未確認 / An attack may be under way, or an alert was not reviewed | なし（記録済み）/ None (already recorded) | high |
| SNAP-001 | スナップショットポリシーが `none` か無効 / Snapshot policy `none` or disabled | `/api/storage/volumes`, `/api/storage/snapshot-policies` | 定期的な復旧点がない / No scheduled recovery point | データプロトコルの認証情報 / Data-protocol credentials | medium |
| SNAP-002 | 読み取り時点で将来までロックされたスナップショットがない / No snapshot locked beyond the read time | `/api/storage/volumes/{uuid}/snapshots` | 管理者の認証情報で全スナップショットを削除できる / Administrator credentials delete every snapshot | 管理者の認証情報 / Administrator credentials | high（復旧点の破壊 / destroys recovery points） |
| SNAP-003 | スナップショットの自動削除がオン / Snapshot autodelete on | `/api/storage/volumes` | ボリュームを満杯にすると ONTAP がスナップショットを消す / Filling the volume makes ONTAP delete snapshots | データプロトコルの認証情報 / Data-protocol credentials | high（復旧点の破壊 / destroys recovery points） |
| SNAP-004 | SnapLock のコンプライアンスクロックが未初期化 / No SnapLock compliance clock | `/api/storage/snaplock/compliance-clocks` | スナップショットのロックの前提が欠けている（NetApp の文書が前提に挙げる）/ A documented prerequisite of snapshot locking is missing | 情報 / Information | info |
| NFS-001 | `0.0.0.0/0` に AUTH_SYS の書き込みか root を許すエクスポートルール / Export rule giving `0.0.0.0/0` AUTH_SYS write or superuser | `/api/protocols/nfs/export-policies` | 到達できる任意のアドレスから、クライアントが名乗る UID で書き込める / Any reachable address writes as a client-asserted UID | データ用インターフェイスへの到達だけ / Network reach to a data interface only | high |
| CIFS-001 | 共有 ACL の Everyone フルコントロール / Share ACL Everyone full control | `/api/protocols/cifs/shares` | 任意のドメインユーザーが共有レベルで権限変更と削除をできる / Any domain user changes permissions and deletes at share level | データプロトコルの認証情報 / Data-protocol credentials | medium |
| FPOL-001 | 有効な FPolicy がない SVM / SVM with no enabled FPolicy policy | `/api/protocols/fpolicy` | NFS と SMB のファイル操作が外部サーバーへ通知されない。S3 Access Points 経由の操作は設定に関係なく FPolicy に通知されない [E-015] / NFS and SMB operations are not sent to an external server; operations through S3 Access Points are never seen by FPolicy | データプロトコルの認証情報 / Data-protocol credentials | medium |
| VSCAN-001 | Vscan がオフの SVM / SVM with Vscan off | `/api/protocols/vscan` | SMB で開かれるファイルにオンアクセススキャンがかからない / Files opened over SMB get no on-access scan | データプロトコルの認証情報 / Data-protocol credentials | medium |
| AUD-001 | ファイルアクセス監査が無効な SVM / SVM with file access audit off | `/api/protocols/audit` | 読み書きの記録が残らない。有効でも S3 Access Points 経由の要求者は記録されない [E-018] / Reads and writes leave no record; even when on, the requester on the S3 Access Points path is not recorded | データプロトコルの認証情報 / Data-protocol credentials | medium |
| AUD-002 | 管理操作の監査ログの転送先がない / No administrative audit destination | `/api/security/audit/destinations` | 設定変更の記録がファイルシステム上にしか残らない / Records of setting changes stay on the file system only | 管理者の認証情報 / Administrator credentials | low |
| ACC-001 | `fsxadmin` 以外のロック解除された管理者アカウント / Unlocked admin accounts other than `fsxadmin` | `/api/security/accounts` | 盗まれうる管理者の認証情報が増える / More administrator credentials to steal | 管理者の認証情報 / Administrator credentials | low |
| ACC-002 | http か ssh をパスワードだけで使う管理者 / Admin signing in over http or ssh with a password alone | `/api/security/accounts`, `/api/security/login/totps` | 盗んだパスワードだけでサインインできる / A stolen password alone signs in | 管理者の認証情報 / Administrator credentials | low |
| MAV-001 | 複数管理者承認 / Multi-admin verification | `/api/security/multi-admin-verify` | 1 人の管理者だけでスナップショットとボリュームを削除できる。HTTP 403 は `not_assessable` で、「無効」とは書かない [E-025] / One administrator deletes snapshots and volumes; HTTP 403 is `not_assessable`, never "disabled" | 管理者の認証情報 / Administrator credentials | high（復旧点の破壊 / destroys recovery points） |
| PEER-001 | クラスタピア / Cluster peers | `/api/cluster/peers` | データがこのファイルシステムからピアへ出うる / Data can leave this file system to the peer | 情報 / Information | info |
| SM-001 | SnapMirror 関係（送信側と受信側）/ SnapMirror relationships (both directions) | `/api/snapmirror/relationships` | データの複製がこのファイルシステムの外にある / A copy of the data exists outside this file system | 情報 / Information | info |
| ENC-001 | ONTAP ボリューム暗号化 / ONTAP volume encryption | `/api/storage/volumes` | ストレージの保存時暗号化（AWS KMS）とは別の層の状態 / A layer separate from storage encryption at rest with AWS KMS | 情報 / Information | info |
| KM-001 | ONTAP のキーマネージャー / ONTAP key managers | `/api/security/key-managers` | ボリュームキーの管理場所 / Where volume keys are managed | 情報 / Information | info |
| KMS-001 | ファイルシステムの KMS キーが AWS マネージドキー / File system KMS key is AWS managed | `fsx:DescribeFileSystems`, `kms:DescribeKey` | バックアップが論理エアギャップボールトへコピーされない [E-009] [E-060]。同じアカウントでバックアップを消されると、隔離されたコピーが残らない / Backups are not copied to a logically air-gapped vault; deleting them in the account leaves no isolated copy | 管理者の認証情報（AWS）/ Administrator credentials (AWS) | high |
| S3AP-001 | インターネットを起点にできる S3 Access Points / S3 Access Points with Internet network origin | `s3:GetAccessPoint` | VPC の外から S3 要求を送れる / S3 requests can come from outside the VPC | 到達だけ / Network reach only | high |
| S3AP-002 | 条件なしで `Principal: "*"` を許すアクセスポイントポリシー / Access point policy allowing `Principal: "*"` without a condition | `s3:GetAccessPointPolicy` | ポリシーだけで任意の AWS プリンシパルを許す。ポリシーがないときは info / The policy alone allows any AWS principal; info when there is no policy | 到達だけ / Network reach only | high |

SVM のルートボリューム（名前が `_root` で終わるもの）は、ボリューム単位の検査から外します。名前で判定しているので、ルートでないボリュームにこの名前を付けている環境では、そのボリュームが検査されません。

SVM root volumes (names ending in `_root`) are left out of the per-volume checks. The test is the name, so a non-root volume with such a name is not checked.

---

## 重大度の決め方 / How Severity Is Set

重大度は、その設定を悪用するために攻撃者が先に手に入れる必要があるもので決めます。データ用インターフェイスへの到達だけで足りるものは high、データプロトコルの認証情報（NFS のクライアント ID、SMB ユーザー）が要るものは medium、ONTAP 管理者の認証情報が要るものは low です。ただし、スナップショットの削除や自動削除のように復旧点そのものを失わせるものは、前提にかかわらず high に上げます。`status` が `finding` のものだけが `--fail-on` の判定に入ります。

Severity is set by what the attacker must already have. Network reach to a data interface alone is high; data-protocol credentials (an NFS client identity, an SMB user) is medium; ONTAP administrator credentials is low, raised to high when the setting lets that attacker destroy recovery points (snapshot deletion, autodelete). Only entries with status `finding` count for `--fail-on`.

| status | 意味 / Meaning |
|---|---|
| `finding` | 設定が攻撃者の前提を満たしたときの行動を許す / The setting allows the stated action |
| `pass` | 検査した設定に該当がない / The setting checked does not allow it |
| `not_assessable` | ロールに読む権限がない（HTTP 403、ONTAP コード 6）/ The role may not read the setting |
| `unknown` | 読み取りの失敗、パスなし（404）、フィールドなし / Read failed, path absent (404), or field missing |
| `inconclusive` | `/api/cluster` の対照読み取りが失敗し、何も判定していない / The control read of `/api/cluster` failed and nothing was assessed |

---

## 手元の Mac からの実行手順 / Running from a Mac

管理エンドポイントには VPC の中からしか到達しないので、VPC 内の踏み台インスタンスを経由する SSM のポートフォワードを使います。

The management endpoint is reachable from inside the VPC only, so use an SSM port forward through a bastion instance in the VPC.

1. ポートフォワードを開く / Open the port forward:

   ```bash
   aws ssm start-session --target <bastion-instance-id> \
     --document-name AWS-StartPortForwardingSessionToRemoteHost \
     --parameters host=<management-dns>,portNumber=443,localPortNumber=18443
   ```

2. 証明書のフィンガープリントを読む / Read the certificate fingerprint:

   ```bash
   openssl s_client -connect localhost:18443 -servername <management-dns> </dev/null 2>/dev/null \
     | openssl x509 -noout -fingerprint -sha256
   ```

   管理エンドポイントの証明書は既定の信頼ストアで検証できないため、プローブは証明書（DER）の SHA-256 を `--fingerprint` の値と定数時間で比べ、一致したときだけ要求を送ります。検証を外すオプション（`--insecure`）はありません。

   > **セキュリティに関する補足**: ここで読んだ値は、ポートフォワードの先にいた相手の証明書です。最初の 1 回は、VPC 内の別の経路（踏み台からの `openssl s_client`）でも同じ値かを確かめてから使います。

   The management certificate does not verify against the default trust store, so the probe compares the SHA-256 of the certificate (DER) with `--fingerprint` in constant time and sends nothing unless they match. There is no option to skip verification (no `--insecure`).

   > **Security note**: the value read here is the certificate of whatever answered through the port forward. The first time, confirm it from a second path inside the VPC (`openssl s_client` on the bastion) before relying on it.

3. シークレットを `FileSystemId` タグで選ぶ / Choose the secret by its `FileSystemId` tag:

   どのファイルシステムも管理ユーザー名は `fsxadmin` なので、名前で選んだシークレットに別のファイルシステムのパスワードが入っていることがあります。誤ったパスワードで認証を繰り返すと、管理ユーザーがロックされうるため、プローブはシークレットの `FileSystemId` タグが `--file-system-id` と一致しないとき（タグがないときも）、シークレットの値を読まずに止まります。

   Every file system has the same administrator name, `fsxadmin`, so a secret chosen by name can hold another file system's password, and repeated failed logins can lock the account. The probe stops without reading the secret value when its `FileSystemId` tag is missing or differs from `--file-system-id`.

4. 実行する / Run:

   ```bash
   make probe-config FINGERPRINT=<sha256-fingerprint> FS_ID=fs-0123456789abcdef0 \
     SECRET_ID=<secret-name-or-arn> OUT=config-probe.json
   # 同じ内容を直接 / the same, directly:
   .venv/bin/python3 solutions/config-probe/probe.py --base-url https://localhost:18443 \
     --fingerprint <sha256-fingerprint> --file-system-id fs-0123456789abcdef0 \
     --secret-id <secret-name-or-arn> --region <region> --fail-on high --out config-probe.json
   ```

   出力ファイル `config-probe*.json` は `.gitignore` に入っています。ボリューム名と SVM 名が残るため、公開する前に中身を確認します。

   The output files `config-probe*.json` are gitignored. They hold volume and SVM names, so read them before sharing.

5. 認証が失敗したら止まる / Stop on an authentication failure:

   HTTP 401（ONTAP コード 6691623、または SnapLock 専用ロールの応答以外の 401）を 1 回受けた時点で、プローブはそれ以上の要求を送らず、終了コード 3 で終わります。再実行せず、シークレットのタグと説明で対象のファイルシステムを確かめます。一致の確認は、VPC 内の踏み台から `curl -k -u ... /api/cluster` を 1 回だけ行います（[AGENTS.md の注意点](../../AGENTS.md)）。

   On the first HTTP 401 (ONTAP code 6691623, or any 401 other than the SnapLock role answer) the probe sends nothing more and exits with code 3. Do not run it again; check the secret's tag and description first, and confirm the password once from the bastion with `curl -k -u ... /api/cluster`.

---

## 必要な IAM 権限 / IAM Permissions Needed

| 操作 / Action | 用途 / Purpose |
|---|---|
| `ssm:StartSession` | ポートフォワード / Port forward |
| `secretsmanager:DescribeSecret`, `secretsmanager:GetSecretValue`（対象の 1 件だけ / one secret） | タグの確認と認証情報 / Tag check and credentials |
| `fsx:DescribeFileSystems`, `fsx:DescribeBackups`, `fsx:DescribeS3AccessPointAttachments` | ファイルシステム、バックアップ、アクセスポイントの接続 / File system, backups, access point attachments |
| `kms:DescribeKey` | キーの管理者（AWS / CUSTOMER）と Origin / Key manager and origin |
| `s3:GetAccessPoint`, `s3:GetAccessPointPolicy` | ネットワークの起点とポリシー / Network origin and policy |

`--skip-aws` で AWS 側を、`--skip-ontap` で ONTAP 側を読まずに実行できます。

`--skip-aws` and `--skip-ontap` leave out the AWS side and the ONTAP side respectively.

---

## 継続実行とライン停止 / Running Continuously and Stopping the Line

プローブは 1 回の実行で完結する CLI です。リリース前のパイプラインと、設定変更の後に `--fail-on high` で実行し、終了コード 2（high の所見あり）か 3（判定できなかった）なら、そこで先へ進めません。判定できなかった実行を合格として扱わないことが、このゲートの前提です。`not_assessable`（例: `fsxadmin` の MAV）は所見ではないので、ゲートを止めません。

定期実行には、VPC 内のホストからのスケジュール実行を使います。このリポジトリには、プローブを定期実行するためのデプロイテンプレートはありません。実行ごとの JSON を保存しておけば、前回との差分で設定の変化を追えます。

The probe is a single-run CLI. Run it with `--fail-on high` in the release pipeline and after configuration changes; exit code 2 (a high finding) or 3 (could not assess) stops the change there. A run that could not assess is never treated as a pass. `not_assessable` (for example MAV under `fsxadmin`) is not a finding and does not stop the gate.

For scheduled runs, schedule it on a host inside the VPC; this repository has no deployment template for scheduling the probe. Keeping each run's JSON lets you diff settings against the previous run.

| 終了コード / Exit code | 意味 / Meaning |
|---|---|
| 0 | `--fail-on` 以上の所見なし / No finding at or above `--fail-on` |
| 2 | `--fail-on` 以上の所見あり / A finding at or above `--fail-on` |
| 3 | 停止: 認証失敗、証明書の不一致、シークレットの拒否、期限切れ、対照読み取りの失敗 / Stopped: authentication failure, certificate mismatch, refused secret, deadline, failed control read |
| 64 | 引数の誤り / Usage error |

---

## 出力形式 / Output Format

```json
{
  "schema": "config-probe/v1",
  "ontap_version": "9.18.1P6",
  "file_system_id": "fs-…def0",
  "read_at_utc": "2026-11-15T06:00:00Z",
  "get_only": true,
  "bodies_stored": false,
  "stopped": "",
  "residency": {
    "region": "ap-northeast-1",
    "kms_key_manager": "CUSTOMER",
    "kms_origin": "AWS_KMS",
    "backup_count": 2,
    "backup_copy_source_regions": [],
    "s3_access_points": 1,
    "snapmirror_destination_clusters": ["<name:3f2a1c>"],
    "cluster_peers": ["<name:3f2a1c>"]
  },
  "findings": [
    {
      "id": "SNAP-002",
      "check": "locked_snapshot",
      "resource": "svm1/vol1",
      "severity": "high",
      "status": "finding",
      "attacker_precondition": "ONTAP administrator credentials",
      "attacker_capability": "delete every snapshot of the volume, removing its on-box recovery points",
      "observed": "0 of 24 snapshot(s) locked beyond the read time",
      "source": {"path": "/api/storage/volumes/{uuid}/snapshots", "http": 200, "ontap_code": ""},
      "ledger": []
    }
  ],
  "summary": {"by_status": {"finding": 1}, "findings_by_severity": {"high": 1}, "total": 1}
}
```

出力のすべての文字列で、クラスタ名（`FsxId...`）、IPv4 アドレス、12 桁のアカウント ID を伏せます。ファイルシステム ID は末尾 4 文字だけを残し、ピアと SnapMirror の相手の名前は短いトークンにします。`--show-names` を付けると、この 2 つだけは伏せずに出力します。`residency` には、データが置かれ、送られる場所（リージョン、キーの管理者と Origin、このリージョンにあるバックアップのコピー元リージョン、SnapMirror の送信先、ピア）をまとめます。

Every string in the output has cluster names (`FsxId...`), IPv4 addresses and 12-digit account IDs masked. The file system ID keeps its last four characters, and peer and SnapMirror partner names become short tokens; `--show-names` shows these two unmasked. `residency` collects where data sits and where it is sent: Region, key manager and origin, source Regions of backup copies in this Region, SnapMirror destinations and peers.

---

## プローブが読まないもの / What the Probe Does Not Read

- このプローブは、ファイルやディレクトリの NTFS ACL と UNIX パーミッションを読みません。共有 ACL とエクスポートルールだけを見ます。
- このプローブは、ネットワークの到達範囲（セキュリティグループ、NACL、ルート）を読みません。NFS-001 と S3AP-001 の「到達だけ」は、到達できる場合の評価です。
- このプローブは、IAM のアイデンティティポリシーと AWS Backup のボールトを読みません。KMS-001 はキーの種類から、ボールトへのコピーの可否を判定します。
- このプローブは、他のリージョンにあるバックアップを読みません。`backup_copy_source_regions` は、`--region` のリージョンにあるコピーの元だけです。
- 1 回の実行で読むスナップショットは、先頭から `--max-volumes`（既定 50）個のボリュームまでで、残りのボリュームは SNAP-002 が `unknown` になります。
- このプローブは、時点の設定を読むだけで、操作の履歴は読みません。操作の記録は監査ログと SIEM で見ます。

- The probe reads no file or directory NTFS ACL or UNIX permission; it looks at share ACLs and export rules only.
- The probe reads no network reachability (security groups, NACLs, routes); "network reach only" in NFS-001 and S3AP-001 assumes reach.
- The probe reads no IAM identity policy and no AWS Backup vault; KMS-001 judges vault copies from the key type.
- The probe reads no backup in another Region; `backup_copy_source_regions` lists the sources of copies in the `--region` Region only.
- Snapshots are read for the first `--max-volumes` (default 50) volumes; SNAP-002 is `unknown` for the rest.
- The probe reads settings at one point in time, not the history of operations; use the audit log and SIEM for that.

---

## 実機での確認 / Run Against a Real File System

<!-- live-run: pending -->

---

## 参照 / References

- [Continuum と Security Agent の時代にストレージ層で決めておくこと](../architecture/continuum-security-agent-and-storage.md)
- [攻撃者視点のレビュー用プロンプト / Adversarial review prompts](../agent-prompts/adversarial-review.md)
- [ONTAP コマンドと REST API のスナップショット](ontap-command-api-snapshot.md)、[fsxadmin の権限と制限](fsxadmin-limitations.md)、[Tamperproof Snapshot](tamperproof-snapshot.md)、[ARP 設定](arp-configuration.md)
- [AWS Backup 論理エアギャップボールト](../data-protection/aws-backup-logically-air-gapped-vault.md)
- [Tech predictions for 2027 and beyond](https://www.allthingsdistributed.com/2026/11/tech-predictions-for-2027-and-beyond.html)（AWS CTO のブログ記事 / the AWS CTO's blog post）

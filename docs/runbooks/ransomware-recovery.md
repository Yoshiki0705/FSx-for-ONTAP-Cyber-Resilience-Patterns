# Ransomware Recovery Runbook

## 概要 / Overview

FSx for ONTAP 環境でランサムウェア攻撃を受けた場合の、検知→封じ込め→復旧→事後対応の全手順。

持ち出しを疑う場合は [Data Exfiltration Response Runbook](data-exfiltration-response.md) を使う。
If exfiltration is suspected, use the [Data Exfiltration Response Runbook](data-exfiltration-response.md).

## 判断フローチャート / Decision Flowchart

```mermaid
flowchart TD
    START[Alert Received] --> ASSESS{Alert Source?}
    
    ASSESS -->|ARP| ARP_CHECK[Review ARP snapshot created]
    ASSESS -->|Scanner| SCAN_CHECK[Review scan verdict details]
    ASSESS -->|Manual report| MANUAL[Gather indicators]
    
    ARP_CHECK --> CONFIRM{Confirmed attack?}
    SCAN_CHECK --> CONFIRM
    MANUAL --> CONFIRM
    
    CONFIRM -->|Yes - Active attack| CONTAIN[CONTAIN: Restrict access immediately]
    CONFIRM -->|Suspicious - Need investigation| INVESTIGATE[INVESTIGATE: Create FlexClone]
    CONFIRM -->|False positive| FP[Mark as FP, restore access]
    
    CONTAIN --> SNAPSHOT[Create tamperproof snapshot]
    SNAPSHOT --> SCOPE[Assess scope: which volumes affected?]
    SCOPE --> MGMT{Management plane compromised?<br/>AWS account or ONTAP admin}
    MGMT -->|No| RECOVERY{Recovery path?}
    MGMT -->|Yes| LOCKED{Locked snapshots or<br/>SnapLock copies intact?}
    LOCKED -->|Yes| RESTORE_LOCKED[FlexClone from a pre-attack locked snapshot<br/>or copy back from SnapLock if production copies were committed there]
    LOCKED -->|No, or whole AWS account compromised| VAULT{Logically air-gapped<br/>vault configured?}
    VAULT -->|Yes| RESTORE_LAG
    VAULT -->|No| ESCALATE[Escalate: no intact recovery point<br/>within this runbook]
    
    RECOVERY -->|ARP Snapshot available| RESTORE_ARP[SnapRestore from ARP snapshot]
    RECOVERY -->|Pre-attack snapshot| RESTORE_SNAP[SnapRestore from clean snapshot]
    RECOVERY -->|DR copy available| RESTORE_DR[Failover to SnapMirror target]
    RECOVERY -->|Copy outside the management boundary, if a vault is configured| RESTORE_LAG[Restore from logically air-gapped vault]
    RECOVERY -->|Primary Region or platform control plane unavailable| RESTORE_ALT[Option E: recover in another Region or account]
    
    RESTORE_ARP --> VERIFY[Verify restored data integrity]
    RESTORE_SNAP --> VERIFY
    RESTORE_DR --> VERIFY
    RESTORE_LAG --> VERIFY
    RESTORE_ALT --> VERIFY
    RESTORE_LOCKED --> VERIFY
    
    VERIFY --> REOPEN[Re-enable access (export policy)]
    REOPEN --> POSTMORTEM[Post-incident review]
    
    INVESTIGATE --> CLONE[Create read-only FlexClone]
    CLONE --> FORENSIC[Forensic analysis on clone]
    FORENSIC --> CONFIRM
```

## Phase 1: 検知 (Detection)

### ARP アラート受信時

```bash
# Check ARP alert status
ssh fsxadmin@<management-ip>
security anti-ransomware volume show -vserver svm-prod-dev -fields state,attack-detected

# List ARP-created snapshots
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev -snapshot anti_ransomware_backup*
```

### Scanner アラート受信時

- EventBridge → Step Functions で自動隔離が既に実行されている場合あり
- Step Functions コンソールで Quarantine Workflow の実行状態を確認

## Phase 2: 封じ込め (Containment)

### Immediate: Export Policy 制限（アクセスブロック）

```bash
# Create a restrictive export policy (deny all clients)
vserver export-policy rule create -vserver svm-prod-dev \
  -policyname quarantine_policy \
  -ruleindex 1 \
  -protocol any \
  -clientmatch 0.0.0.0/0 \
  -rorule never \
  -rwrule never \
  -superuser none

# Apply quarantine policy to affected volume
volume modify -vserver svm-prod-dev -volume vol_prod_dev -policy quarantine_policy
```

### Tamperproof Snapshot 作成

```bash
# Create a tamperproof snapshot of current state (evidence preservation)
volume snapshot create -vserver svm-prod-dev -volume vol_prod_dev \
  -snapshot "evidence-$(date +%Y%m%d-%H%M%S)" \
  -snapmirror-label evidence \
  -snaplock-expiry-time "<MM/DD/YYYY HH:MM:SS>"
# Takes effect only when snapshot-locking-enabled is true on the volume;
# otherwise the snapshot is created without retention.
```

## Phase 3: 調査 (Investigation)

### FlexClone による安全な調査環境

```bash
# Create read-only clone for forensic analysis
volume clone create -vserver svm-prod-dev \
  -flexclone forensic_clone_$(date +%Y%m%d) \
  -parent-volume vol_prod_dev \
  -parent-snapshot anti_ransomware_backup.2026-06-25_1030 \
  -junction-path /forensics

# Mount clone (read-only) for analysis
# Forensics team can access /forensics via NFS
```

### 証拠保全 (Chain of Custody)

1. FlexClone 作成時刻・元 Snapshot を記録
2. **FlexClone のデータ整合性を検証**:
   ```bash
   # Calculate SHA-256 hash of key evidence files
   find /mnt/forensics -type f -exec sha256sum {} \; > /tmp/forensic-manifest-$(date +%Y%m%d).sha256
   
   # Store manifest in the SnapLock volume (/compliance, SnapLock Enterprise: WORM;
   # the template sets privileged delete to PERMANENTLY_DISABLED, but Legal Hold is Compliance-only)
   cp /tmp/forensic-manifest-*.sha256 /mnt/compliance/evidence/
   ```
3. アクセスログを SnapLock ボリュームにコピー
4. 調査担当者のアクセスを監査ログで記録
5. 調査完了後、FlexClone を保持（削除しない）
6. **Evidence integrity log** に以下を記録（改ざん防止）:
   - Clone作成日時、元Snapshot名、作成者
   - SHA-256マニフェストのハッシュ値
   - 関与した調査担当者名一覧

## Phase 4: 復旧 (Recovery)

### Option A: ARP Snapshot からの復旧

```bash
# Identify clean ARP snapshot
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev \
  -snapshot anti_ransomware_backup* -fields create-time

# Restore from ARP snapshot
volume snapshot restore -vserver svm-prod-dev -volume vol_prod_dev \
  -snapshot anti_ransomware_backup.2026-06-25_0900
```

### Option B: 通常 Snapshot からの復旧

```bash
# List available snapshots (find last known clean)
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev -fields create-time

# Restore from clean snapshot
volume snapshot restore -vserver svm-prod-dev -volume vol_prod_dev \
  -snapshot hourly.2026-06-25_0800
```

管理面の侵害を疑うときは、ロック付きの Snapshot（`snaplock-expiry-time` が設定されたもの）だけから選ぶ。CLI の `volume snapshot restore` でロック付きの Snapshot を戻せるのは、それが最新の場合だけで、それより新しい期限内の Snapshot が 1 つでもあると失敗する（documented、[snapshot-lock-concept.html](https://docs.netapp.com/us-en/ontap/snaplock/snapshot-lock-concept.html)、[Tamperproof Snapshot](../ontap-native/tamperproof-snapshot.md)）。Phase 2 で証拠用のロック付き Snapshot を作っているので、攻撃前のロック付き Snapshot はこの条件に当たる。そのため、攻撃前のロック付き Snapshot からは SnapRestore ではなく FlexClone で戻す。ロック付きの Snapshot から volume clone を作れることは同じページにある（documented）。後の Snapshot は消さずに残る。
When a management-plane compromise is suspected, choose only from locked snapshots (those with `snaplock-expiry-time` set). With the CLI, `volume snapshot restore` restores a locked snapshot only if it is the most recent one, and fails if any unexpired later snapshot exists (documented, [snapshot-lock-concept.html](https://docs.netapp.com/us-en/ontap/snaplock/snapshot-lock-concept.html), [Tamperproof Snapshot](../ontap-native/tamperproof-snapshot.md)). Phase 2 creates a locked evidence snapshot, so any pre-attack locked snapshot falls under this rule. Recover from a pre-attack locked snapshot with a FlexClone instead of SnapRestore; the same page documents that volume clones can be created from a locked snapshot (documented). Later snapshots stay in place.

```bash
# List locked snapshots and pick the last known clean one created before the attack
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev -fields create-time,snaplock-expiry-time

# Clone the chosen snapshot; later snapshots, including the evidence snapshot, are not deleted
volume clone create -vserver svm-prod-dev \
  -flexclone vol_prod_dev_restore \
  -parent-volume vol_prod_dev \
  -parent-snapshot <pre-attack-locked-snapshot> \
  -junction-path /prod_restore
```

クローンの中身を確かめた後、クライアントをクローンへ切り替えるか、クローンから元のボリュームへデータをコピーする。どちらの手順も本リポジトリでは実施していない（未確認）。
After checking the clone's contents, point clients at the clone or copy the data from the clone back to the original volume. Neither step has been run in this repository (unverified).

### Option C: SnapMirror DR からの復旧

```bash
# Break SnapMirror relationship (make destination writable)
snapmirror break -destination-path svm-dr:vol_prod_dr

# Verify data integrity on DR copy
# Mount and validate with business owners

# Reverse resync (when original is ready)
snapmirror resync -source-path svm-dr:vol_prod_dr -destination-path svm-prod-dev:vol_prod_dev
```

### Option D: 論理エアギャップボールトからの復旧

AWS アカウントや ONTAP 管理者が侵害され、同じ管理境界の中の Snapshot や SnapMirror の宛先も改ざん・削除された疑いがある場合の経路。手順は AWS の公開文書に基づき、本リポジトリでは実施していない（documented、[ボールト文書](../data-protection/aws-backup-logically-air-gapped-vault.md)）。
This path is for when the AWS account or an ONTAP administrator is compromised and snapshots or SnapMirror destinations inside the same boundary may also have been tampered with or deleted. The steps follow AWS public documentation and have not been run in this repository (documented).

1. 復旧アカウントで、共有された論理エアギャップボールトの復旧ポイントを確認する。RAM で共有されたボールトへの要求には `--backup-vault-account-id` が要る（documented）。
   In the recovery account, list the recovery points in the shared vault; requests against a RAM-shared vault need `--backup-vault-account-id` (documented).
2. 復旧アカウント側に、復元先の FSx for ONTAP ファイルシステムと SVM があることを確認する（推論。未確認）。
   Confirm that the recovery account has a target FSx for ONTAP file system and SVM (inference, unverified).
3. AWS Backup の復元ジョブで、新しいボリュームへ復元する。FSx for ONTAP の復元で指定できるメタデータは `Name` と `OntapConfiguration`（`junctionPath`、`sizeInMegabytes`、`storageEfficiencyEnabled`、`storageVirtualMachineId`、`tieringPolicy`）（documented、[restoring-fsx.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-fsx.html)）。
   Restore to a new volume with an AWS Backup restore job; the FSx for ONTAP restore metadata is `Name` and `OntapConfiguration` with the listed sub-fields (documented).
4. 復元したボリュームの中身を FlexClone + S3 Access Points 経由のスキャンで確かめる。Malware Protection for AWS Backup は FSx for ONTAP の復旧ポイントを対象にしない [E-008]。
   Check the restored volume with FlexClone and a scan through S3 Access Points; Malware Protection for AWS Backup does not scan FSx for ONTAP recovery points [E-008].
5. ボールト所有アカウントが使えない場合は、マルチパーティ承認（MPA）で復旧アカウントからアクセスする（documented、[multipartyapproval.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/multipartyapproval.html)）。
   If the vault-owning account is unavailable, reach the vault from the recovery account through multi-party approval (MPA) (documented).

```bash
# Step 1: list recovery points in a vault shared through AWS RAM
aws backup list-recovery-points-by-backup-vault \
  --backup-vault-name <logically-air-gapped-vault-name> \
  --backup-vault-account-id 123456789012 \
  --region ap-northeast-1

# Step 3: restore to a new volume (metadata keys per restoring-fsx.html)
aws backup start-restore-job \
  --recovery-point-arn <recovery-point-arn> \
  --metadata file://restore-metadata.json \
  --iam-role-arn arn:aws:iam::123456789012:role/service-role/AWSBackupDefaultServiceRole \
  --region ap-northeast-1
```

### Option E: 主系のリージョンや基盤の管理面が使えない場合

被害が個々のボリュームではなく、基盤側のインフラ（リージョン単位の管理面や仮想化層）を止める場合の経路。自分のアカウントと認証情報が無傷でも、同じリージョンにある復旧点と管理コンソールが使えないことがある。特定の事業者についての記述ではなく、設計上の確認である。経路は Option C（別リージョンへの SnapMirror）と Option D（別アカウントのボールト）の組み合わせである。Secrets Manager の手順だけはダミーのシークレットで通した（下の表）。それ以外は本リポジトリでは実施していない（推論）。
This path is for when the damage takes down the platform's infrastructure (a Region-wide management plane or virtualisation layer) rather than individual volumes. Even if your account and credentials are intact, the recovery points in the same Region and the management console may be unavailable. This is a design check, not a statement about any provider. The path combines Option C (SnapMirror to another Region) and Option D (a vault in another account). Only the Secrets Manager step was run, with a dummy secret (see the table); the rest has not been run in this repository (inference). <!-- allow:unverified: a design scenario about an unreachable Region, not a claim that a vendor lacks a capability -->

1. 復旧手順が依存するものを洗い出し、主系のリージョンが使えないときも手元にあるかを、下の表で確かめる。
   List what the recovery steps depend on and check, with the table below, that each is still reachable when the primary Region is unavailable.
2. 少なくとも 1 つの復旧点が、主系とは別のリージョンまたは別のアカウントにあることを確かめる（Option C、Option D）。
   Confirm that at least one recovery point is in a different Region or account from the primary (Option C, Option D).
3. 復旧の操作を、コンソールではなく CLI と API で実行できる形にしておく。コンソールが封じ込めのために停止されても手順が止まらない。
   Make the recovery operations runnable through the CLI and APIs rather than the console, so the steps do not stop if the console is suspended for containment.
4. 利用者や取引先への案内では、サービス停止、バックアップの取り出しの可否、復元と業務再開、情報の不正照会、情報の外部流出の確認状況を、別々に書く。混ぜると、復旧の見通しと漏えいの有無が取り違えられる。
   In notices to users and partners, report separately: the service stop, whether backups can be extracted, restore and resumption, unauthorised queries, and whether data left the environment. Mixing them makes recovery prospects and leakage easy to confuse.

| 依存するもの / Dependency | 本リポジトリの置き場所 / Where it is here | 主系のリージョンが使えないとき / If the primary Region is unavailable |
|---|---|---|
| fsxadmin の認証情報 / fsxadmin credentials | 手動復旧の手順 1 は主系と同じリージョンの Secrets Manager から取得する / Manual recovery step 1 reads from Secrets Manager in the primary Region | 主系のリージョンの Secrets Manager からは取得できない。シークレットは別リージョンへレプリケートできる（documented、[replicate-secrets.html](https://docs.aws.amazon.com/secretsmanager/latest/userguide/replicate-secrets.html)）。ダミーのシークレットで、復旧先のリージョンでレプリカを名前で読め、`stop-replication-to-replica` で昇格した後も名前で読めた（verified、2026-10-22、ap-northeast-1 から ap-northeast-3）。主系リージョンの ARN は復旧先のリージョンでは解決されない（ResourceNotFoundException）ので、手順は ARN ではなく名前と `--region` で指定する。主系のコントロールプレーンの停止そのものは再現していない / Secrets can be replicated to another Region (documented). With a dummy secret, the replica was readable by name in the recovery Region, and still readable by name after promotion with `stop-replication-to-replica` (verified, 2026-10-22, ap-northeast-1 to ap-northeast-3). The primary Region's ARN does not resolve in the recovery Region (ResourceNotFoundException), so address the secret by name and `--region`, not by ARN. A control-plane outage of the primary Region itself was not reproduced <!-- allow:unverified: a design scenario about an unreachable Region, not a claim that a vendor lacks a capability --> |
| 復元先の FSx for ONTAP ファイルシステムと SVM / Target file system and SVM | 本リポジトリの構成には含まない / Not part of this repository's configuration | 無ければ作成から始まる。所要時間は未測定 / If absent, recovery starts with creating them; duration not measured |
| 復旧点 / Recovery points | 同じリージョンの Snapshot、別リージョンの SnapMirror の宛先、別アカウントのボールト / Same-Region snapshots, a SnapMirror destination in another Region, a vault in another account | 同じリージョンの Snapshot は使えない前提にする。宛先とボールトが生きているかを確かめる / Assume same-Region snapshots are unavailable; check that the destination and vault are alive <!-- allow:unverified: a design scenario about an unreachable Region, not a claim that a vendor lacks a capability --> |
| 手順書そのもの / This runbook | リポジトリと社内の文書置き場 / The repository and the internal document store | 文書置き場が同じ基盤にあると読めない。印刷またはオフラインのコピーを、復旧の担当が持つ（設計指針） / If the document store is on the same platform it cannot be read; keep a printed or offline copy with the people who recover (design guidance) |

### アクセス復旧

```bash
# Restore original export policy
volume modify -vserver svm-prod-dev -volume vol_prod_dev -policy default_export_policy

# Verify client access
showmount -e <svm-management-ip>
```

## Phase 5: 事後対応 (Post-Incident)

### 必須アクション

- [ ] インシデントレポート作成（タイムライン、影響範囲、復旧時間）
- [ ] ARP 学習データが汚染されていないか確認
- [ ] FPolicy フィルタの見直し（攻撃ベクトルを追加）。**S3 Access Point 経由の書き込みは FPolicy フィルタでは閉じられない**（実測 2026-08-26）。その経路は ARP と、S3 側のアクセスポイントポリシー / IAM で塞ぐ
- [ ] スキャンサーバーのシグネチャ/モデル更新確認
- [ ] 影響を受けたユーザーへの通知。通知の要否と方法は法務・個人情報の担当が判断する。本 runbook は法的判断をしない
  Whether and how to notify is decided by the legal and privacy owners; this runbook makes no legal judgement.
- [ ] 再発防止策の検討・実装

### DR テスト（年次）

| テスト項目 | 頻度 | 担当 |
|-----------|------|------|
| ARP Snapshot からの復旧演習 | 四半期 | ストレージ管理者 |
| FlexClone フォレンジック演習 | 半年 | セキュリティチーム |
| SnapMirror フェイルオーバー | 年次 | インフラチーム |
| 論理エアギャップボールトからの restore testing / Restore testing from the logically air-gapped vault | 組織で決める / Set by the organisation | ストレージ管理者 |
| Full ransomware simulation (EICAR) | 年次 | セキュリティチーム + 全関係者 |

## Contact & Escalation

| Level | Condition | Contact |
|-------|-----------|---------|
| L1 | ARP alert (single volume) | Security Operations |
| L2 | Multiple volumes / active encryption | Security Manager + Storage Admin |
| L3 | Business-critical data affected | CISO + Executive team |
| External | Law enforcement needed | Legal team + External IR firm |


---

## 自動隔離ワークフローの承認操作 / Quarantine Approval Procedure

### 概要

マルウェア検知時、Step Functions の Quarantine Workflow が自動実行される:
1. Forensic Snapshot 作成
2. Export Policy 制限（アクセス遮断）
3. SNS アラート送信
4. **承認待ち** (Approval Queue — 24 時間タイムアウト)

### 承認キューの確認

```bash
# Approval Queue のメッセージ確認
QUEUE_URL=$(aws cloudformation describe-stacks \
  --stack-name fsxn-cyber-resilience-events-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`SecurityEventQueueUrl`].OutputValue' \
  --output text --region ap-northeast-1)

aws sqs receive-message --queue-url "$QUEUE_URL" --max-number-of-messages 1
```

### 承認 (Approve — アクセス復旧)

調査の結果、誤検知（False Positive）と判断した場合:

```bash
# Step Functions タスクトークンを使用してアクセス復旧を承認
aws stepfunctions send-task-success \
  --task-token "<taskToken from approval message>" \
  --task-output '{"approved": true}'
```

これにより:
- Export Policy がデフォルトルールに復旧
- ボリュームへのアクセスが再開

### 拒否 (Reject — フォレンジック継続)

攻撃が確認された場合:

```bash
# 拒否 → FlexClone 作成 (フォレンジック用)
aws stepfunctions send-task-success \
  --task-token "<taskToken from approval message>" \
  --task-output '{"approved": false}'
```

これにより:
- ボリュームは隔離状態を維持
- FlexClone が作成され、フォレンジック環境として提供

### タイムアウト (24 時間経過)

承認・拒否がない場合、24 時間後に自動エスカレーション:
- SNS で「ESCALATION: Approval Timeout」通知
- ボリュームは隔離状態のまま

### 手動復旧 (ワークフロー外)

Step Functions を経由せず直接復旧する場合:

```bash
# 1. Secrets Manager から認証情報を取得
CREDS=$(aws secretsmanager get-secret-value \
  --secret-id fsxn-cyber-resilience-fsxadmin \
  --query 'SecretString' --output text)
FSX_USER=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['username'])")
FSX_PASS=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['password'])")

# 2. ONTAP REST API で Export Policy を手動復旧
curl -k -u "${FSX_USER}:${FSX_PASS}" \
  -X POST "https://<management-ip>/api/protocols/nfs/export-policies/<policy-id>/rules" \
  -H "Content-Type: application/json" \
  -d '{"clients":[{"match":"0.0.0.0/0"}],"ro_rule":["sys"],"rw_rule":["sys"],"superuser":["sys"]}'
```

> **重要**: 認証情報は必ず Secrets Manager から取得すること。スクリプトやコマンド履歴にパスワードを残さない。

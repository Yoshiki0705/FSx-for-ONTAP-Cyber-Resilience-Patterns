# AWS Backup Logically Air-Gapped Vault for Amazon FSx for NetApp ONTAP

FSx for ONTAP のボリュームバックアップを AWS Backup の論理エアギャップボールトで守るときの、構成の判断材料をまとめる。
This guide collects what you need to decide how to protect FSx for ONTAP volume backups with an AWS Backup logically air-gapped vault.

## 概要 / Overview

2026-09 に、AWS Backup の論理エアギャップボールトが Amazon FSx for NetApp ONTAP のボリュームバックアップに対応した（[What's New](https://aws.amazon.com/jp/about-aws/whats-new/2026/09/aws-backup-air-gapped-vault-fsx-ontap/)）。論理エアギャップボールトはバックアップを AWS Backup のサービス所有アカウントに保存し、Vault Lock のコンプライアンスモードで常にロックする。守るのは、AWS アカウント（管理境界）が侵害されたときの復旧点の可用性と完全性である。持ち出されたデータの機密性は、アクセス制御・暗号化・監査という別の制御で守る（[framework mapping](../ja/cyber-resilience-framework-mapping.md) の持ち出し型の節）。

In 2026-09, AWS Backup logically air-gapped vaults added support for Amazon FSx for NetApp ONTAP volume backups ([What's New](https://aws.amazon.com/about-aws/whats-new/2026/09/aws-backup-air-gapped-vault-fsx-ontap/)). The vault stores backups in an AWS Backup service-owned account and is always locked with Vault Lock in compliance mode. What it protects is the availability and integrity of recovery points when the AWS account (the management boundary) is compromised. The confidentiality of data that has been read out is protected by other controls: access control, encryption and auditing (see the exfiltration scenario in the [framework mapping](../en/cyber-resilience-framework-mapping.md)).

## 検証状況と確認日 / Verification Status and Check Date

本リポジトリでは実環境で試していない。記述はすべて AWS の公開文書に基づく（2026-10-08 確認）。リージョン、上限、対象リソースは変わりうるので、使う前に参照の各ページを読み直す。

This repository has not tried the vault in a real environment. Everything here is based on AWS public documentation (checked 2026-10-08). Regions, quotas and supported resources change, so reread the referenced pages before you rely on them.

## 前提条件 / Prerequisites

ファイルシステムの暗号化キーとボールトの暗号化キーは別のキーで、決まる時点も違う。表では 2 つを別の行に分ける。

The file system's encryption key and the vault's encryption key are different keys, set at different times. The table keeps them on separate rows.

| 項目 / Item | 内容 / Details | 出典 / Source |
|---|---|---|
| ファイルシステムの暗号化キー / File system encryption key | 元のファイルシステムが CMK で暗号化されていること。AWS マネージドキーで暗号化されたファイルシステムのバックアップはボールトへコピーされない [E-009]。その場合もバックアップジョブは失敗せず「Completed with issues」で完了し、標準ボールトにだけ残る（documented）。FSx for ONTAP の既定は AWS マネージドキー（documented）。キーはファイルシステムの作成時に指定する / The file system must be encrypted with a customer managed key; with an AWS managed key, backups are not copied to the vault [E-009] and the job ends "Completed with issues" | [lag-vault-primary-backup.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/lag-vault-primary-backup.html)、[logicallyairgappedvault.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html)、[encryption-at-rest.html](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/encryption-at-rest.html) |
| ボールトの暗号化キー / Vault encryption key | AWS 所有キーが既定で、CMK も選べる。ボールトの作成時に決まり、後から変えられない [E-020]。CMK を選ぶ場合、同じアカウントのキーはテスト用途に限るよう推奨されている（documented） / AWS owned key by default, or a customer managed key; fixed at vault creation and cannot be changed later [E-020] | [logicallyairgappedvault.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html) |
| キーポリシー / Key policy | コピーと復元に使う CMK は、コピー元のロールが使えるようにしておく。権限が足りないとコピージョブが失敗する（documented、"Key policy for copy/restore" の節）。ポリシーの例はページを参照 / Share the CMKs used for copy and restore with the source copy role, or copy jobs fail | [logicallyairgappedvault.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html) |
| 対象ボリューム / Volumes | バックアップの対象は RW ボリューム。DP / LSM / FlexCache と SnapMirror の宛先ボリューム、SnapLock FlexGroup ボリュームは対象外 [E-010] / RW volumes only; DP, LSM, FlexCache and SnapMirror destination volumes and SnapLock FlexGroup volumes are not backed up [E-010] | [using-backups.html](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/using-backups.html) |
| 一時リカバリポイント / Temporary recovery points | FSx for ONTAP のバックアップは、標準ボールトの一時リカバリポイント（`DELETE_AFTER_COPY`）を経てボールトへコピーされる。一時リカバリポイントも保持期間中は課金される。restore testing、recovery point indexing、malware scanning は一時リカバリポイントを対象にしない [E-017] / Backups pass through a temporary DELETE_AFTER_COPY recovery point, billed while retained; restore testing, indexing and scanning ignore it [E-017] | [lag-vault-primary-backup.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/lag-vault-primary-backup.html) |
| 保持期間 / Retention | ボールトの作成時に最小・最大保持期間を決める。最小は 7 日以上（documented）。ボールトへコピーされるのは、保持期間がこの範囲に入るバックアップなので、バックアッププランの保持期間をこの範囲に収める / Set minimum (7 days or more) and maximum retention at vault creation; keep the backup plan's retention inside that range | [logicallyairgappedvault.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html)、[lag-vault-primary-backup.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/lag-vault-primary-backup.html) |
| 同時コピー数 / Concurrent copies | Amazon FSx のリソースから論理エアギャップボールトへの同時コピーは 5 で、調整できない [E-021]（"Logically air-gapped vault quotas" の表、2026-10-08 確認）。バックアップの頻度がコピーの完了より速いとコピージョブが滞留し、失敗しうる（documented） / Up to 5 concurrent copies for Amazon FSx, not adjustable [E-021]; schedule backups so that copies can finish | [aws-backup-limits.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/aws-backup-limits.html)、[lag-vault-primary-backup.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/lag-vault-primary-backup.html) |
| リージョン / Regions | 論理エアギャップボールトのページに除外リージョンの一覧がある。2026-10-08 時点で、アジアパシフィック（東京）と（大阪）は一覧に入っていない / The vault page lists excluded Regions; Tokyo and Osaka were not on that list on 2026-10-08 | [logicallyairgappedvault.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html) |
| 料金 / Pricing | 数値はこの文書に書かない。料金ページを参照 / No figures here; see the pricing page | [AWS Backup の料金 / AWS Backup pricing](https://aws.amazon.com/backup/pricing/) |

## 構成の選択肢 / Configuration Options

バックアッププランで、論理エアギャップボールトをプライマリターゲットにするか、コピー先にするかを選ぶ。プライマリターゲットにできるのは、同じアカウント・同じリージョンのボールト。別アカウント・別リージョンのボールトにはコピー先として置く（documented、What's New と primary backup のページ）。AWS RAM で復旧アカウントへ共有できる。共有先は個別のアカウント ID で指定し、組織や OU は指定できない。共有先は閲覧と復元ができ、コピーはできない [E-014]。AWS Organizations のマルチパーティ承認（MPA）を組み合わせると、ボールト所有アカウントが使えなくなっても、別組織の復旧アカウントから承認チームの承認を経てボールトにアクセスできる（documented、[multipartyapproval.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/multipartyapproval.html)）。承認チームのリソースは米国東部（バージニア北部）に作られる。

In the backup plan, choose whether the vault is the primary target or a copy destination. A vault in the same account and Region can be the primary target; a vault in another account or Region is placed as a copy destination (documented, What's New and the primary backup page). The vault can be shared with a recovery account through AWS RAM. Sharing targets individual account IDs and cannot target an organisation or OU; a shared account can view and restore recovery points but cannot copy them [E-014]. With AWS Organizations multi-party approval (MPA), a recovery account in a separate organisation can reach the vault after an approval team approves, even when the vault-owning account is unavailable (documented, [multipartyapproval.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/multipartyapproval.html)). Approval team resources are created in US East (N. Virginia).

MPA と ONTAP の Multi-Admin Verification（MAV）は名前が似ているが別の機能で、承認する対象も動く場所も違う。

MPA and ONTAP Multi-Admin Verification (MAV) have similar names but are separate features that approve different things in different places.

| 項目 / Item | MPA（AWS Backup） / MPA (AWS Backup) | MAV（ONTAP） / MAV (ONTAP) |
|---|---|---|
| 承認の対象 / What is approved | 復旧アカウントから論理エアギャップボールトへのアクセス / Access to the vault from a recovery account | ルールで保護対象に指定した ONTAP の管理操作（[mav-configuration.md](../ontap-native/mav-configuration.md)） / ONTAP administrative operations protected by rules |
| 動く場所 / Where it runs | AWS Organizations と AWS Backup / AWS Organizations and AWS Backup | ONTAP クラスタ / The ONTAP cluster |
| 備える場面 / Scenario | ボールト所有アカウントの侵害・閉鎖 / Compromise or closure of the vault-owning account | ONTAP 管理者の認証情報の侵害 / Compromise of an ONTAP administrator credential |

## 復元と復元テスト / Restore and Restore Testing

論理エアギャップボールトからの復元は、ほかの AWS Backup のバックアップと同じ手順で行う（documented、[using-backups.html](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/using-backups.html)）。復元先は、同じリージョンの FSx for ONTAP ファイルシステム上の新しいボリューム。第 2 世代のファイルシステムには一部のデータだけを復元する手順もあるが、論理エアギャップボールトの復旧ポイントで使えるかは本リポジトリでは確認していない。共有先の復旧アカウントで復元するには、そのアカウント・リージョンに復元先のファイルシステムと SVM が要る（推論。未確認）。restore testing の対象には FSx for ONTAP が入っている（documented、[backup-feature-availability.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/backup-feature-availability.html)）。復元した中身の確認は FlexClone と S3 Access Points 経由のスキャンで行う。Malware Protection for AWS Backup は FSx for ONTAP の復旧ポイントを対象にしない [E-008]。ボールト所有アカウントが閉鎖されても、閉鎖後の期間（post-closure period）が終わるまでは MPA 経由で復元・コピーできる（documented、[logicallyairgappedvault.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html)）。

Restoring from the vault uses the same procedure as any other AWS Backup backup (documented, [using-backups.html](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/using-backups.html)). The target is a new volume on an FSx for ONTAP file system in the same Region. Second-generation file systems also offer restoring a subset of data; whether that works for recovery points in a logically air-gapped vault has not been checked here. To restore in a shared recovery account, that account and Region need a target file system and SVM (inference, unverified). FSx for ONTAP is covered by restore testing (documented, [backup-feature-availability.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/backup-feature-availability.html)). Check the restored contents with FlexClone and a scan through S3 Access Points; Malware Protection for AWS Backup does not scan FSx for ONTAP recovery points [E-008]. If the vault-owning account is closed, backups can still be restored or copied through MPA until the post-closure period ends (documented, [logicallyairgappedvault.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html)).

## 自動修復との干渉 / Interaction with Automated Remediation

論理エアギャップボールトへのコピー中、AWS Backup はサービス所有アカウントへ一時的な権限を付与し、CloudTrail には `userIdentity.invokedBy` が `backup.amazonaws.com` のイベントが記録される。アカウント外への共有を取り消す自動修復（EventBridge ルールと Lambda）がこのイベントに反応すると、コピージョブが失敗しうる。ページは EC2 AMI の例を示し、Amazon FSx のコピーでも同じことが起こりうるとしている（documented、[logicallyairgappedvault.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html)）。除外条件は `userIdentity.invokedBy = backup.amazonaws.com`。本リポジトリのテンプレートと Lambda は AWS RAM の共有、AWS Backup のボールト、KMS のグラントを操作しないので、2026-10-08 時点のコードでは干渉しない。そうした自動修復を将来足すときは、この除外条件を入れる。

While copying into the vault, AWS Backup grants temporary permissions to a service-owned account, and CloudTrail records events with `userIdentity.invokedBy` set to `backup.amazonaws.com`. Auto-remediation that revokes external sharing (EventBridge rules with Lambda) can make the copy job fail if it reacts to those events. The page gives the EC2 AMI case and notes that the same can happen for Amazon FSx copies (documented, [logicallyairgappedvault.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html)). The exclusion is `userIdentity.invokedBy = backup.amazonaws.com`. The templates and Lambda functions in this repository do not touch AWS RAM shares, AWS Backup vaults or KMS grants, so the code as of 2026-10-08 does not interfere. Add the exclusion if you add such remediation later.

## 隔離方式の選び方 / How to Choose an Isolation Option

4 つの方式は、復旧点を置く場所と運用するものが違う。順位は付けない。想定する侵害と運用の体制から選ぶ。

The four options differ in where recovery points live and what you operate. They are not ranked; choose by the compromise you plan for and what your team can run.

| 方式 / Option | 復旧点がある場所 / Where recovery points live | ONTAP 管理者の侵害 / ONTAP admin compromise | AWS アカウント全体の侵害 / Full AWS account compromise | 復元の粒度 / Restore granularity | 運用するもの / What you operate | 主な制約 / Main constraints | 不可逆な点 / Irreversible points |
|---|---|---|---|---|---|---|---|
| SnapLock（Compliance / Enterprise） | 同じ SnapLock ボリューム / The same SnapLock volume | Compliance は保持期間が切れるまで、管理者を含めて変更・削除の要求を拒否する（documented）。Enterprise は特権削除を許す / Compliance refuses changes and deletes until retention expires, including for administrators; Enterprise allows privileged delete | 同じ管理境界の中にある（推論。ブログの脅威表の同一アカウント SnapVault + SnapLock の列から導いた） / Inside the same boundary (inference from the blog's same-account threat row) | ファイル / File | SnapLock ボリュームと容量計画 / SnapLock volumes and capacity planning | 型（Compliance / Enterprise）は作成時に決まる / Type is set at creation | ファイルごとの保持期間 / Per-file retention |
| Tamperproof Snapshot | 同じボリューム / The same volume | ロックの期限まで、管理者を含めて削除の要求を拒否する（documented） / Deletion refused until lock expiry, including for administrators | 同じ管理境界の中にある（推論。未確認） / Inside the same boundary (inference, unverified) | Snapshot / ファイル（`.snapshot`、FlexClone） / Snapshot or file | Snapshot ポリシーとボリュームの設定 / Snapshot policy and volume setting | ONTAP 9.12.1 以降。FabricPool と同じボリュームでは併用できない [E-016]。CLI の `volume snapshot restore` で戻せるのは最新のロック済み Snapshot（documented） / ONTAP 9.12.1+; not with FabricPool on the same volume [E-016]; CLI restore takes the most recent locked snapshot | ロックの期限まで続くロック / The lock lasts until expiry |
| 別アカウントへの SnapMirror / SnapVault | 別アカウントの FSx for ONTAP ファイルシステム / An FSx for ONTAP file system in another account | 宛先は別のファイルシステムで、管理者の認証情報も分けられる。宛先でのロックは ONTAP 9.14.1 以降（SnapLock vault 宛先と非 SnapLock の SnapMirror 宛先、documented） / Separate file system and credentials; destination locking from ONTAP 9.14.1 | 認証情報を分ければ主系アカウントの侵害から切り離せる（推論。未確認） / Separated from a primary-account compromise when credentials are separate (inference, unverified) | ファイル / フォルダ（ブログ） / File or folder | 二次ファイルシステム、ネットワーク、IAM（ブログ） / Secondary file system, networking, IAM | 宛先の容量とスループットの費用 / Destination capacity and throughput cost | 宛先でロックした Snapshot の期限 / Expiry of snapshots locked on the destination |
| 論理エアギャップボールト | AWS Backup のサービス所有アカウント / An AWS Backup service-owned account | ONTAP の管理操作が届く範囲の外にある（推論。保存先が AWS Backup のサービス所有アカウントであること（documented）から導いた） / Outside the reach of ONTAP administration (inference from the documented service-owned storage) | コンプライアンスモードのロックが常に有効。MPA を組めば、アカウントの侵害・閉鎖後も閉鎖後の期間中は復元できる（documented） / Always compliance-locked; with MPA, restorable after compromise or closure during the post-closure period | ボリューム（新しいボリュームへ復元、documented） / Volume, restored to a new volume | 隔離側のファイルシステムは不要。復元先のファイルシステムは要る（推論） / No isolated file system; a restore target is needed (inference) | 元のファイルシステムが CMK で暗号化されていること [E-009]。対象は RW ボリューム [E-010]。一時リカバリポイントの課金。Amazon FSx の同時コピー数 5 [E-021]。Malware Protection の対象外 [E-008] / Source file system on a customer managed key [E-009]; RW volumes [E-010]; temporary recovery point charges; 5 concurrent copies [E-021]; outside Malware Protection [E-008] | ボールトのロック（コンプライアンスモード）とボールトの暗号化キー [E-020] / Vault lock in compliance mode and the vault's encryption key [E-020] |

どの方式も守るのは復旧点の可用性と完全性で、持ち出されたデータの機密性はアクセス制御・暗号化・監査で守る。

Every option protects the availability and integrity of recovery points; the confidentiality of data already read out depends on access control, encryption and auditing.

選ぶときの問いは 4 つある。想定する侵害が ONTAP 管理者までか、AWS アカウント全体か。ファイル単位の復元を頻繁に行うか。隔離側のファイルシステムを運用できるか。保持期間を誰が決め、誰が承認するか。方式は組み合わせられる。[Storage Assessments のブログ](https://aws.amazon.com/blogs/storage/planning-data-protection-before-migration-how-aws-storage-assessments-model-backup-and-disaster-recovery-costs/)は、ファイル単位の復元に SnapVault、アカウントの隔離に論理エアギャップボールトを併用する構成を挙げている。

Four questions drive the choice. Does the compromise you plan for stop at the ONTAP administrator, or reach the whole AWS account? Do you restore individual files often? Can you operate an isolated file system? Who sets retention, and who approves it? The options combine: the [Storage Assessments blog](https://aws.amazon.com/blogs/storage/planning-data-protection-before-migration-how-aws-storage-assessments-model-backup-and-disaster-recovery-costs/) describes SnapVault for file-level restores alongside a logically air-gapped vault for account isolation.

## 移行前のデータ保護計画とコストの見積り / Pre-Migration Data Protection Planning and Cost Modeling

AWS Storage Assessments は、主系ストレージの見積りに使う移行前のテレメトリから、データ保護のコストも見積もる（[ブログ](https://aws.amazon.com/blogs/storage/planning-data-protection-before-migration-how-aws-storage-assessments-model-backup-and-disaster-recovery-costs/)）。コストは独立した 4 つの軸で決まる。保持期間（7 日〜7 年）、隔離レベル（標準ボールト〜論理エアギャップボールト）、地理的範囲（同一リージョン〜クロスリージョン）、復元の粒度（ボリューム〜ファイル）。保持期間やボールトの種別を変えた what-if を、データを集め直さずに計算できる。NIST CSF 2.0 では GV.RM（リスク管理戦略）と GV.OC（組織の状況）の活動として扱う（framework mapping の Govern の行）。

AWS Storage Assessments estimate data protection cost from the same pre-migration telemetry that sizes primary storage ([blog](https://aws.amazon.com/blogs/storage/planning-data-protection-before-migration-how-aws-storage-assessments-model-backup-and-disaster-recovery-costs/)). Cost follows four independent dimensions: retention depth (7 days to 7 years), isolation level (standard vault to logically air-gapped vault), geographic scope (same Region to cross-Region) and recovery granularity (volume to file). What-if runs that change retention or vault type are recalculated without collecting data again. In NIST CSF 2.0 this is GV.RM (risk management strategy) and GV.OC (organisational context) work (see the Govern row of the framework mapping).

## 不可逆な決定の確認先 / Where the irreversible decisions are discussed

論理エアギャップボールトでは Vault Lock のコンプライアンスモードが常に有効で、戻せない [E-020]。ボールトの暗号化キーはボールトの作成時に決まり、後から変えられない [E-020]。元のファイルシステムの暗号化キーは、ファイルシステムの作成時に指定する（ボールトのキーとは別のキー）。承認の取り方と影響範囲（どのバックアップがいつまで削除できなくなるか）は FSx for ONTAP Adoption Playbook のモジュールハブにある。リージョン・アカウントをまたぐバックアップのコピーは、Playbook の [backup-copies-across-regions-and-accounts.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md)（JA のみ）が扱う。本リポジトリは判断材料を持ち、Playbook が設計判断を持つ。

On a logically air-gapped vault, Vault Lock compliance mode is always on and cannot be turned off [E-020]. The vault's encryption key is fixed when the vault is created and cannot be changed later [E-020]. The source file system's encryption key is specified when the file system is created, and it is a different key from the vault's. How to gate these decisions, and which backups become undeletable for how long, is covered in the FSx for ONTAP Adoption Playbook module hubs. Backup copies across Regions and accounts are covered by the Playbook note [backup-copies-across-regions-and-accounts.md](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md) (Japanese only). This repository holds the decision inputs; the Playbook holds the design guidance.

| モジュール / Module | 扱う範囲 / Scope |
|---|---|
| [データ保護 / Data Protection](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/README.md) （[EN](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/data-protection/README.md)） | Snapshot、SnapMirror、SnapLock、バックアップ、ランサムウェア対策の設計判断 |
| [セキュリティ・ガバナンス / Security & Governance](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/security-governance/README.md) （[EN](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/security-governance/README.md)） | 不可逆操作の承認、監査ログ、アクセス認可の層 |

## 参照 / References

- [What's New: AWS Backup adds logically air-gapped vault support for Amazon FSx for NetApp ONTAP](https://aws.amazon.com/about-aws/whats-new/2026/09/aws-backup-air-gapped-vault-fsx-ontap/)（[JA](https://aws.amazon.com/jp/about-aws/whats-new/2026/09/aws-backup-air-gapped-vault-fsx-ontap/)）
- [Planning data protection before migration: How AWS Storage Assessments model backup and disaster recovery costs](https://aws.amazon.com/blogs/storage/planning-data-protection-before-migration-how-aws-storage-assessments-model-backup-and-disaster-recovery-costs/)
- [AWS Backup: Logically air-gapped vault](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html)
- [AWS Backup: Primary backups to logically air-gapped vaults](https://docs.aws.amazon.com/aws-backup/latest/devguide/lag-vault-primary-backup.html)
- [AWS Backup: Multi-party approval for logically air-gapped vaults](https://docs.aws.amazon.com/aws-backup/latest/devguide/multipartyapproval.html)
- [AWS Backup: Feature availability](https://docs.aws.amazon.com/aws-backup/latest/devguide/backup-feature-availability.html)
- [AWS Backup: Quotas](https://docs.aws.amazon.com/aws-backup/latest/devguide/aws-backup-limits.html)
- [Amazon FSx for NetApp ONTAP: Protecting your data with volume backups](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/using-backups.html)
- [Amazon FSx for NetApp ONTAP: Encryption of data at rest](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/encryption-at-rest.html)
- [AWS Backup pricing](https://aws.amazon.com/backup/pricing/)
- [Tamperproof Snapshot Configuration](../ontap-native/tamperproof-snapshot.md) / [SnapLock Configuration](../ontap-native/snaplock-configuration.md) / [MAV Configuration](../ontap-native/mav-configuration.md)

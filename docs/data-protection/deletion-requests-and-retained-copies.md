# 削除の依頼と、削除後も残るコピー / Deletion Requests and the Copies That Remain

Amazon FSx for NetApp ONTAP のボリュームからファイルを削除したあと、そのデータがどのコピーに、いつまで残るかをまとめる。対象は、エージェントのメモリから古い記録を消す処理、研究の被験者が同意を撤回したときの記録の削除、保存期間が過ぎた個人データの削除のように、「消したことを説明できる」必要がある削除である。ここに書くのは技術的な挙動で、法令上どこまで消せばよいかの判断ではない。

This page lists, for a file deleted from an Amazon FSx for NetApp ONTAP volume, which copies still hold its data and for how long. It is for deletions that must be explainable: removing old records from an agent's memory, deleting a research subject's recordings after consent is withdrawn, or deleting personal data whose retention period has ended. It describes technical behaviour, not a legal judgement of how far deletion must go.

## 結論 / Conclusion

- ファイルを削除しても、そのファイルを含む Snapshot が残っている間は、データはボリューム上に残る。S3 Access Points を付けたボリュームでは、削除したファイルを `.snapshot/<Snapshot 名>/<パス>` のキーで `GetObject` すると読めた。`ListObjectsV2` にはこのキーが出なかった [E-061]。
- この読み取り経路は、Snapshot の削除、ボリュームの `snapshot_directory_access_enabled` を `false` にすること、アクセスポイントポリシーで `<アクセスポイント ARN>/object/.snapshot/*` への `s3:GetObject` を拒否すること、のどれでも閉じた [E-061]。
- Snapshot のほかに、FSx のバックアップ、AWS Backup のボールト、SnapMirror の宛先、FlexClone が、それぞれ別の期限でデータを持つ。Tamperproof Snapshot、SnapLock Compliance、論理エアギャップボールトは、期限まで誰も削除できない。削除の要件があるデータを置く前に、この表で最長の保持期間を決める。

- A deleted file stays on the volume while any Snapshot copy that holds it exists. On a volume with an S3 Access Point, `GetObject` on the key `.snapshot/<snapshot name>/<path>` returned the deleted file, and `ListObjectsV2` did not show that key [E-061].
- That read path was closed by any one of: deleting the Snapshot copy, setting the volume's `snapshot_directory_access_enabled` to `false`, or an access point policy that denies `s3:GetObject` on `<access point ARN>/object/.snapshot/*` [E-061].
- Besides Snapshot copies, FSx backups, AWS Backup vaults, SnapMirror destinations and FlexClone volumes each hold the data on their own schedule. Tamperproof Snapshot copies, SnapLock Compliance volumes and logically air-gapped vaults cannot be deleted by anyone before their expiry. Before you place data that is subject to deletion requests, use the table below to fix the longest retention.

---

## 削除後もデータを持つコピーの一覧 / Copies That Hold Data After Deletion

表の「消える条件」は、削除したファイルのデータがそのコピーから消えるための条件である。出典の種類は、AWS や NetApp の文書にあるもの（documented）と、この環境で測ったもの（verified）を分けて書く。

The "Gone when" column is the condition under which the deleted file's data leaves that copy. The source column separates what AWS or NetApp documents (documented) from what was measured here (verified).

| コピー / Copy | 消える条件 / Gone when | 期限前に消せるか / Deletable before expiry | 出典 / Source |
|---|---|---|---|
| アクティブファイルシステム / Active file system | 削除の時点 / At deletion | 該当なし / Not applicable | 該当なし / Not applicable |
| Snapshot（ポリシーまたは手動）/ Snapshot copy (policy or manual) | そのファイルを含む最後の Snapshot が削除されたとき。`default` ポリシーでは最長で週次の 2 世代分 / When the last Snapshot copy holding the file is deleted. With the `default` policy, up to two weekly copies | 管理者は削除できる / An administrator can delete it | documented（[Snapshot](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snapshots-ontap.html)）、verified [E-061] |
| Tamperproof Snapshot | `snaplock_expiry_time` が過ぎ、Snapshot が削除されたとき / After `snaplock_expiry_time` passes and the copy is deleted | できない / No | [Tamperproof Snapshot](../ontap-native/tamperproof-snapshot.md) |
| SnapLock Compliance / Enterprise ボリューム / volume | 保持期限が過ぎたあとにファイルを削除したとき。Enterprise は privileged delete で期限前に削除できる / When the file is deleted after its retention expires. Enterprise allows privileged delete before expiry | Compliance はできない [E-036]、Enterprise は条件付きでできる / Compliance: no. Enterprise: with privileged delete | [SnapLock](../ontap-native/snaplock-configuration.md) |
| FSx の自動日次バックアップ / FSx automatic daily backup | 保持期間（0〜90 日、既定 30 日）が過ぎたとき、またはボリュームの削除時 / When its retention (0 to 90 days, default 30) expires, or when the volume is deleted | できる / Yes | documented（[Volume backups](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/using-backups.html)） |
| FSx のユーザー作成バックアップ、最終バックアップ / FSx user-initiated backup, final backup | 誰かが削除したとき。ボリュームやファイルシステムを削除しても残る / When someone deletes it. It survives deletion of the volume and the file system | できる / Yes | documented（同上 / same page） |
| バックアップ用の Snapshot / Backup snapshot | 次のバックアップが成功したとき。直近のバックアップ用 Snapshot はボリュームに残る / When the next backup succeeds. The latest backup snapshot stays in the volume | 次のバックアップまでは残る / Stays until the next backup | documented（同上 / same page） |
| AWS Backup の標準ボールト / AWS Backup standard vault | バックアッププランの保持期間が過ぎたとき。Vault Lock を設定したボールトでは、その規則が保持を決める / When the plan's retention expires. In a vault with Vault Lock, its rules govern retention | Vault Lock の設定による / Depends on Vault Lock | [論理エアギャップボールト / Logically air-gapped vault](aws-backup-logically-air-gapped-vault.md) |
| 論理エアギャップボールト / Logically air-gapped vault | 保持期間が過ぎたとき（コンプライアンスモードで常にロック）/ When retention expires (always locked in compliance mode) | できない [E-020] / No | 同上 / same page |
| SnapMirror の宛先 / SnapMirror destination | 宛先側で、そのファイルを含む Snapshot が保持ルールで消えたとき。ソース側の削除だけでは消えない / When the destination's retention rules remove the Snapshot copies holding the file. Deleting at the source alone does not remove it | 宛先の管理者による / Up to the destination's administrator | [Snapshot](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snapshots-ontap.html)、SnapMirror の保持ルール / retention rules |
| FlexClone | クローンを削除したとき。クローンは元の Snapshot の時点のデータを見せる / When the clone is deleted. A clone shows the data as of its parent Snapshot copy | できる / Yes | [復旧の測定結果 / Recovery measurement results](../ja/recovery-measurement-results.md) |

---

## S3 Access Points から Snapshot を読む経路 / Reading Snapshot Copies Through S3 Access Points

この節は 2026-11-24（UTC）の測定である。環境は ap-northeast-1、第 1 世代 SINGLE_AZ_1 のファイルシステム、ONTAP 9.19.1P4。使い捨ての 1 GiB の UNIX スタイルのボリューム 2 本（Snapshot ポリシー `none`）に、ファイルシステムのユーザーを UNIX の root にした S3 Access Point を付けた。

The measurements in this section were taken on 2026-11-24 (UTC) in ap-northeast-1 on a first-generation SINGLE_AZ_1 file system running ONTAP 9.19.1P4. Two throwaway 1 GiB UNIX-style volumes (snapshot policy `none`) each had an S3 Access Point whose file system user was UNIX root.

| 手順 / Step | 結果 / Result | 回数 / Times |
|---|---|---|
| `PutObject` のあと ONTAP REST で Snapshot を作り、`DeleteObject` する / `PutObject`, then an ONTAP REST Snapshot copy, then `DeleteObject` | 元のキーの `HeadObject` / `GetObject` は 404 / `NoSuchKey` / `HeadObject` / `GetObject` on the original key: 404 / `NoSuchKey` | 3 |
| `.snapshot/<Snapshot 名>/<キー>` を `GetObject` / `GetObject` on `.snapshot/<snapshot name>/<key>` | 読めた。SHA-256 は元のファイルと一致（1 MiB、512 KiB、256 KiB）/ Returned the file; SHA-256 matched the original (1 MiB, 512 KiB, 256 KiB) | 3 |
| `ListObjectsV2`（接頭辞なし、接頭辞 `.snapshot/`）/ `ListObjectsV2` (no prefix, prefix `.snapshot/`) | キーは 1 件も返らなかった / No key returned | 1 |
| Snapshot が保持していた容量 / Space held by the Snapshot copy | 削除した 1 MiB に対して 1,269,760 バイト / 1,269,760 bytes for the deleted 1 MiB | 1 |
| Snapshot を削除してから同じ `GetObject` / The same `GetObject` after deleting the Snapshot copy | `NoSuchKey` | 2 |
| `snapshot_directory_access_enabled=false` にしてから同じ `GetObject` / The same `GetObject` with `snapshot_directory_access_enabled=false` | `NoSuchKey`。対照の通常のオブジェクトは読めた。`true` に戻すと再び読めた / `NoSuchKey`; a live control object stayed readable; reading worked again after setting it back to `true` | 1 |
| アクセスポイントポリシーで `<ARN>/object/.snapshot/*` への `s3:GetObject` を Deny / Access point policy Deny on `s3:GetObject` for `<ARN>/object/.snapshot/*` | `AccessDenied`。対照のオブジェクトは読めた / `AccessDenied`; the control object stayed readable | 1 |

AWS の [Snapshot のページ](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snapshots-ontap.html)は、Snapshot がボリュームのルートの `.snapshot` ディレクトリに置かれ、利用者がそこからファイルを戻せると書いている。[S3 Access Points の互換性のページ](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/access-points-for-fsxn-object-api-support.html)には Snapshot の記述がなく、アクセスポイントから `.snapshot` が読めることが設計上の仕様かどうかは、読んだ文書からは分からない。NTFS スタイルのボリューム、root 以外のファイルシステムユーザー、FlexGroup、ほかの ONTAP 版は試していない。

AWS's [Snapshot page](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snapshots-ontap.html) states that Snapshot copies live in the `.snapshot` directory at the volume root and that users can restore files from there. The [S3 Access Points compatibility page](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/access-points-for-fsxn-object-api-support.html) does not mention Snapshot copies, so the documents read do not say whether reading `.snapshot` through an access point is intended. NTFS-style volumes, file system users other than root, FlexGroup volumes and other ONTAP versions were not tested.

### 閉じ方の選び方 / Choosing How to Close the Path

| 方法 / Method | 閉じる範囲 / What it closes | トレードオフ / Trade-off |
|---|---|---|
| アクセスポイントポリシーの Deny / Access point policy Deny | そのアクセスポイント経由の読み取りだけ。NFS と SMB の利用者は引き続き `.snapshot` から自分でファイルを戻せる / Reads through that access point only; NFS and SMB users can still restore files themselves from `.snapshot` | アクセスポイントごとに設定が要る。ポリシーを書き換えられる IAM 権限を別に守る / Must be set per access point; the IAM permission to edit the policy needs its own protection |
| `snapshot_directory_access_enabled=false` | そのボリュームのすべての経路の `.snapshot` / `.snapshot` on that volume for every path | 利用者が自分でファイルを戻す手段がなくなり、戻しは管理者の作業になる / Users lose self-service restore; restores become an administrator task |
| Snapshot の削除 / Deleting Snapshot copies | そのデータ自体 / The data itself | 削除の対象以外のファイルの復旧点も失う。ロックされた Snapshot は消せない / Recovery points for every other file are lost too; locked copies cannot be deleted |

エージェントやアプリケーションのロールに `s3:GetObject` を与えるアクセスポイントでは、削除済みのデータを読ませない理由がなければ Deny を置く。設定プローブはアクセスポイントポリシーにこの Deny がないものを `S3AP-003` として報告する（[設定プローブ](../ontap-native/adversarial-configuration-probe.md)）。

For an access point that grants `s3:GetObject` to an agent or application role, add the Deny unless that role has a reason to read deleted data. The configuration probe reports access points whose policy lacks this Deny as `S3AP-003` ([configuration probe](../ontap-native/adversarial-configuration-probe.md)).

---

## 削除の要件があるデータを置く前に決めること / Decisions Before Placing Data Subject to Deletion

1. 削除の依頼から、すべてのコピーからデータが消えるまでの最長期間。上の表の各行の期限を足し合わせるのではなく、最も長いものが上限になる。
2. そのデータを、期限前に誰も削除できないコピー（Tamperproof Snapshot、SnapLock Compliance [E-036]、論理エアギャップボールト [E-020]）に入れるかどうか。入れる場合は、保持期間をその上限として同意書や保存方針に書く。入れない場合は、ランサムウェアへの備えを別のボリュームや別の保護で補う。
3. 削除したことの記録。誰が、いつ、どのパスを削除し、どの Snapshot とバックアップがいつ期限を迎えるかを残す。S3 Access Points 経由の操作では ONTAP の監査ログに要求者が残らないので [E-018]、CloudTrail のデータイベントを合わせて使う。
4. 削除済みデータを読める経路を誰が持つか。`.snapshot` を読めるアクセスポイント、SnapMirror の宛先、クローンを一覧にする。

1. The longest time from a deletion request until the data has left every copy. It is the longest single row in the table above, not their sum.
2. Whether the data goes into copies that nobody can delete before expiry (Tamperproof Snapshot copies, SnapLock Compliance [E-036], logically air-gapped vaults [E-020]). If it does, state that retention as the upper bound in consent forms and retention policies. If it does not, cover ransomware recovery with a separate volume or another protection.
3. A record of the deletion: who deleted which path and when, and when each Snapshot copy and backup that holds it expires. Operations through S3 Access Points leave no requester in the ONTAP audit log [E-018], so pair it with CloudTrail data events.
4. Who holds a path to deleted data: access points that can read `.snapshot`, SnapMirror destinations and clones.

---

## 参照 / References

- [Protecting your data with snapshots](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snapshots-ontap.html)
- [Protecting your data with volume backups](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/using-backups.html)
- [Access point compatibility](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/access-points-for-fsxn-object-api-support.html)
- [Tamperproof Snapshot](../ontap-native/tamperproof-snapshot.md)、[SnapLock](../ontap-native/snaplock-configuration.md)、[論理エアギャップボールト / Logically air-gapped vault](aws-backup-logically-air-gapped-vault.md)
- [攻撃者の視点で設定を読む読み取り専用プローブ / Read-Only Adversarial Configuration Probe](../ontap-native/adversarial-configuration-probe.md)

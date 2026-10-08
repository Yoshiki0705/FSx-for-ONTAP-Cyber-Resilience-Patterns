# Tamperproof Snapshot Configuration

## 概要 / Overview

Tamperproof Snapshot（スナップショットロック）は、指定した Snapshot を保持期間中は
管理者を含む誰も削除できないようにする機能。ランサムウェアが管理者権限を奪取しても
復旧ポイントを保護する。

Tamperproof Snapshots (Snapshot Locking) prevent anyone — including administrators — from
deleting snapshots until the retention period expires. This protects recovery points even if
an attacker gains admin credentials.

## 前提条件

- ONTAP 9.12.1 以降（CLI で設定する場合、クラスタの全ノード）
  ONTAP 9.12.1 or later on all nodes in the cluster when you configure it with the CLI.
- SnapLock ライセンス（ONTAP One に含まれる）がインストールされ、コンプライアンスクロックが初期化されていること（documented、[snapshot-lock-concept.html](https://docs.netapp.com/us-en/ontap/snaplock/snapshot-lock-concept.html)）。FSx for ONTAP でのライセンスの手続きと課金の扱いは確認できていない
  The SnapLock license (included in ONTAP One) must be installed and the compliance clock initialized (documented, snapshot-lock-concept.html); how FSx for ONTAP handles the license and its billing is not established.
- ボリュームレベルで設定
  Configured per volume.
- Tamperproof Snapshot と FabricPool は同じボリュームで併用できない [E-016]。FSx for ONTAP の容量プールへの階層化を使うボリュームにも同じ制約がかかるかは確認できていない（推論）
  Tamperproof snapshots and FabricPool cannot be enabled on the same volume [E-016]; whether the same applies to volumes that tier to the FSx for ONTAP capacity pool is an inference and unverified.
- 手動で作成する Snapshot の保持期間（`-snaplock-expiry-time`）が効くのは、ボリュームで `snapshot-locking-enabled` が true のとき（documented、[volume-snapshot-create.html](https://docs.netapp.com/us-en/ontap-cli/volume-snapshot-create.html)）
  A retention period set on a manually created snapshot takes effect when `snapshot-locking-enabled` is true on the volume (documented, volume-snapshot-create.html).

## 設定手順

### Step 1: ボリュームでの snapshot locking の有効化

保持期間はボリュームで snapshot locking を有効にしてから効くので、先にボリュームを設定する。
Retention takes effect once snapshot locking is enabled on the volume, so configure the volume first.

```bash
ssh fsxadmin@<management-ip>

# Enable snapshot locking on the volume
volume modify -vserver svm-prod-dev \
  -volume vol_prod_dev \
  -snapshot-locking-enabled true
```

### Step 2: 保持期間付き Snapshot ポリシーの作成と適用

```bash
# Create a snapshot policy with a retention (lock) period
volume snapshot policy create -vserver svm-prod-dev \
  -policy tamperproof-hourly \
  -enabled true \
  -schedule1 hourly \
  -count1 24 \
  -snapmirror-label1 hourly \
  -retention-period1 "72 hours"

# Apply the tamperproof snapshot policy to the volume
volume modify -vserver svm-prod-dev \
  -volume vol_prod_dev \
  -snapshot-policy tamperproof-hourly
```

### Step 3: 確認

```bash
# Verify snapshot locking is enabled on the volume
volume show -vserver svm-prod-dev -volume vol_prod_dev -fields snapshot-locking-enabled

# Show the lock expiry of each snapshot
volume snapshot show -vserver svm-prod-dev -volume vol_prod_dev -fields snaplock-expiry-time
```

## REST API での設定

```bash
# Enable snapshot locking on volume
curl -X PATCH "https://<management-ip>/api/storage/volumes/{volume-uuid}" \
  -H "Content-Type: application/json" \
  -d '{
    "snapshot_locking_enabled": true
  }'

# Create a locked snapshot manually
curl -X POST "https://<management-ip>/api/storage/volumes/{volume-uuid}/snapshots" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tamperproof-manual-2026-06-25",
    "snaplock_expiry_time": "2026-09-25T00:00:00Z"
  }'
```

Snapshot の `expiry_time` は通常の有効期限で、ロックの期限は `snaplock_expiry_time` で指定する（documented、ONTAP REST API の `POST /storage/volumes/{volume.uuid}/snapshots`）。
On a snapshot, `expiry_time` is the ordinary expiry; the lock expiry is set with `snaplock_expiry_time` (documented, ONTAP REST API `POST /storage/volumes/{volume.uuid}/snapshots`).

## 推奨 Snapshot ポリシー（Cyber Resilience）

| Schedule | Count | Retention (Lock) | Purpose |
|----------|-------|------------------|---------|
| Hourly | 24 | 72 hours | 短期復旧（ランサムウェア検知後の immediate recovery） |
| Daily | 14 | 30 days | 中期復旧 |
| Weekly | 4 | 90 days | 長期復旧 + コンプライアンス |

CLI の `volume snapshot restore` で戻せるのは、最新のロック済み Snapshot（documented、snapshot-lock-concept.html）。
With the CLI, `volume snapshot restore` restores the most recent locked snapshot (documented, snapshot-lock-concept.html).

## ARP Snapshot との関係

- ARP が自動作成する Snapshot も Tamperproof 化可能（推論。未確認）
  Snapshots that ARP creates can also be locked (inference, unverified).
- ARP Snapshot 名: `anti_ransomware_backup.*`
- ARP 検知 → 自動 Snapshot 作成 → ロック付与 の自動化を検討

## fsxadmin 権限での制約

- Snapshot locking の有効化/無効化: 可能
- ロック済み Snapshot の削除: **不可**（保持期間満了まで）
- ロック済み Snapshot の保持期間延長: 可能
- ロック済み Snapshot の保持期間短縮: **不可**

## 不可逆な決定の確認先 / Where the irreversible decisions are discussed

Snapshot locking の有効化は、ロック済み Snapshot の保持期間が満了するまで戻せない。承認の
取り方と影響範囲（どのボリューム・どの SVM・どのファイルシステムがいつまで削除できなくなるか）は
FSx for ONTAP Adoption Playbook のモジュールハブにある。本リポジトリは実装手順を持ち、
Playbook が設計判断を持つ。同じ内容を両方に置かない。

Enabling snapshot locking cannot be undone until the locked snapshots' retention expires. How to
gate it, and which resources become undeletable for how long, is covered in the Adoption Playbook
module hubs. This repository holds the implementation steps; the Playbook holds the design
guidance. The material is not duplicated.

| モジュール / Module | 扱う範囲 / Scope |
|---|---|
| [データ保護 / Data Protection](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/README.md) （[EN](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/data-protection/README.md)） | Snapshot、SnapMirror、SnapLock、バックアップ、ランサムウェア対策の設計判断 |
| [セキュリティ・ガバナンス / Security & Governance](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/security-governance/README.md) （[EN](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/security-governance/README.md)） | 不可逆操作の承認、監査ログ、アクセス認可の層 |

## 参照 / References

- [NetApp ONTAP — Tamper-proof Snapshots](https://docs.netapp.com/us-en/ontap/snaplock/snapshot-lock-concept.html)
- [SnapLock Configuration](snaplock-configuration.md)

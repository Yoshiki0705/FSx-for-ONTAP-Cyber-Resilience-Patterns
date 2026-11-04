# Multi-Admin Verification (MAV) Configuration

## 概要 / Overview

Multi-Admin Verification (MAV) は、破壊的な管理操作に対して複数の管理者の承認を要求する機能。
単一管理者の認証情報が侵害されても、重要な操作が実行されないよう防御する。

MAV requires approval from multiple administrators before executing destructive management operations.
This prevents damage even if a single admin's credentials are compromised.

> **FSx for ONTAP 9.18.1P6 では、`fsxadmin` による MAV の有効化と承認グループの作成が HTTP 403 で拒否されました（1 環境、1 回の観測）[E-025]。** 以下のコマンドは ONTAP 一般のものです。`fsxadmin` のロール定義に MAV のエントリはなく、CLI の一覧にも載りません。他のロール、AWS 側の管理経路、他の版は確認していません。使う前に `security login role show-user-capability` で、自分の環境の `fsxadmin` から MAV のコマンドが見えるかを確かめてください。結果と読み方は [ONTAP コマンドと REST API のスナップショット](ontap-command-api-snapshot.md) にあります。
>
> On FSx for ONTAP 9.18.1P6, enabling MAV and creating an approval group as `fsxadmin` were refused with HTTP 403 (one environment, one observation) [E-025]. The commands below are for ONTAP in general. The `fsxadmin` role has no entry for MAV and the CLI capability list does not show it. Other roles, AWS-side management routes and other versions were not checked. Before relying on it, check with `security login role show-user-capability` whether MAV commands are visible to `fsxadmin` in your own environment. Results and how to read them are in the ONTAP command and REST API snapshot.

## 前提条件

- FSx for ONTAP 9.11.1 以降
- 最低2名の管理者アカウント
- 管理者間の承認ワークフローが運用可能であること

## 対象操作リスト（推奨）

MAV を設定する推奨操作と、その対象とした理由を次に示す。

| Operation | Risk Level | Rationale |
|-----------|-----------|-----------|
| `volume delete` | Critical | データ完全消失 |
| `volume offline` | High | サービス停止 |
| `snaplock compliance-clock modify` | Critical | SnapLock 保持期間の改ざん |
| `security anti-ransomware volume disable` | Critical | ARP 保護解除 |
| `vserver fpolicy disable` | High | FPolicy スキャン無効化 |
| `security login modify` | High | 管理者アカウント変更 |
| `snapshot delete` | High | 復旧ポイント消失 |
| `volume snaplock modify` | Critical | SnapLock 設定変更 |
| `cluster peer delete` | High | DR 接続断 |
| `vserver peer delete` | High | SVM ピア関係消失 |

## 設定手順

### Step 1: MAV 管理者グループ作成

```bash
ssh fsxadmin@<management-ip>

# Create MAV approval group (minimum 2 members)
security multi-admin-verify approval-group create \
  -name cyber-resilience-admins \
  -approvers admin1,admin2,admin3 \
  -email admin-group@example.com
```

### Step 2: MAV ルール作成

```bash
# Protect volume deletion
security multi-admin-verify rule create \
  -operation "volume delete" \
  -query "" \
  -required-approvers 2 \
  -approval-groups cyber-resilience-admins

# Protect ARP disable
security multi-admin-verify rule create \
  -operation "security anti-ransomware volume disable" \
  -query "" \
  -required-approvers 2 \
  -approval-groups cyber-resilience-admins

# Protect FPolicy disable
security multi-admin-verify rule create \
  -operation "vserver fpolicy disable" \
  -query "" \
  -required-approvers 2 \
  -approval-groups cyber-resilience-admins

# Protect snapshot deletion
security multi-admin-verify rule create \
  -operation "snapshot delete" \
  -query "" \
  -required-approvers 2 \
  -approval-groups cyber-resilience-admins
```

### Step 3: MAV 有効化

```bash
# Enable MAV globally
security multi-admin-verify modify -enabled true

# Verify configuration
security multi-admin-verify show
security multi-admin-verify rule show
```

## 承認ワークフロー

MAV で保護された操作を実行する場合:

```bash
# Admin1 attempts to delete a volume (request is created, not executed)
volume delete -vserver svm-prod-dev -volume vol_test
# → "This operation requires multi-admin approval. Request index: 1"

# Admin2 approves the request
security multi-admin-verify request approve -index 1

# After required approvals met, operation executes automatically
```

## REST API での設定

```bash
# Create approval group
curl -X POST "https://<management-ip>/api/security/multi-admin-verify/approval-groups" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "cyber-resilience-admins",
    "approvers": ["admin1", "admin2", "admin3"],
    "required_approvers": 2
  }'

# Create rule
curl -X POST "https://<management-ip>/api/security/multi-admin-verify/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "volume delete",
    "required_approvers": 2,
    "approval_groups": [{"name": "cyber-resilience-admins"}]
  }'
```

## 運用考慮事項

### 緊急時の対応

- MAV ではバイパス機能がない（設計上の意図）
- 緊急時は複数管理者が承認することで即時実行可能
- 管理者が不在の場合に備え、3名以上のグループ構成を推奨

### CloudFormation Custom Resource

MAV 設定は CloudFormation Custom Resource (Lambda) で自動化可能。
ただし、MAV 有効化後は Custom Resource 自身の操作にも承認が必要になる点に注意。

> **推奨**: MAV の有効化は最後に行う（他の全設定完了後）。

## fsxadmin 権限での制約

- MAV の有効化/無効化: 可能（ただし無効化自体が MAV の保護対象になりうる）
- ルール作成/変更: 可能
- 承認グループ管理: 可能
- 承認実行: 他の管理者アカウントから行う必要あり（自己承認不可）

## 参照 / References

- [NetApp ONTAP — Multi-Admin Verification](https://docs.netapp.com/us-en/ontap/multi-admin-verify/)
- [FSx for ONTAP — MAV](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/multi-admin-verification.html)

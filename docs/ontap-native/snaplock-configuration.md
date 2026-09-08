# SnapLock Configuration

## 概要 / Overview

SnapLock は ONTAP のネイティブ WORM (Write Once Read Many) 機能。ファイルをコミットすると
保持期間が満了するまで変更・削除が不可能になる。コンプライアンス要件（金融、医療、政府機関）に対応。

SnapLock provides native WORM storage. Once committed, files cannot be modified or deleted
until the retention period expires — meeting compliance requirements for regulated industries.

## SnapLock タイプの選定基準

| Type | Immutability | Admin Override | Use Case |
|------|-------------|----------------|----------|
| **SnapLock Compliance** | 絶対不変（誰も削除不可） | 不可（volume destroy も不可） | 規制要件、法定保持 (FISC, PCI DSS, SEC 17a-4) |
| **SnapLock Enterprise** | 管理者による早期解除が可能 | `snaplock privileged-delete` | 社内ポリシー、PoC 環境、証拠保全 |

> **推奨**: PoC / dev 環境では **Enterprise** を使用（テスト後に削除可能）。
> 本番規制環境では **Compliance** を使用。一度 Compliance で作成すると変更不可。

## 設定手順 (CloudFormation)

本プロジェクトでは `templates/storage.yaml` の `VolumeSnaplock` リソースで定義済み:

```yaml
SnaplockConfiguration:
  SnaplockType: ENTERPRISE    # or COMPLIANCE for production
  AutocommitPeriod:
    Type: DAYS
    Value: 1                   # Auto-commit after 1 day of no modification
  PrivilegedDelete: PERMANENTLY_DISABLED
  RetentionPeriod:
    DefaultRetention:
      Type: DAYS
      Value: 90                # Default: 90 days
    MinimumRetention:
      Type: DAYS
      Value: 1                 # Minimum: 1 day
    MaximumRetention:
      Type: YEARS
      Value: 7                 # Maximum: 7 years
  VolumeAppendModeEnabled: 'true'  # Allow append (for log files)
```

## CLI での設定確認

```bash
ssh fsxadmin@<management-ip>

# Show SnapLock volume configuration
volume snaplock show -vserver svm-audit-dev -volume vol_snaplock_dev

# Show retention settings
volume snaplock show -vserver svm-audit-dev -fields default-retention-period,minimum-retention-period,maximum-retention-period
```

## ファイルの WORM コミット

### NFS 経由（chmod で read-only に設定）

```bash
# File becomes WORM-committed when made read-only
chmod 444 /mnt/compliance/evidence-2026-06-25.log
```

### SMB 経由（Read-Only 属性設定）

ファイルのプロパティで「読み取り専用」にチェック。

### Autocommit

`AutocommitPeriod` を設定すると、指定期間変更がないファイルは自動で WORM コミットされる。

## Privileged Delete

| Setting | Behavior |
|---------|----------|
| `PERMANENTLY_DISABLED` | 特権削除を完全に無効化（推奨） |
| `DISABLED` | 現在無効だが、将来有効化可能 |
| `ENABLED` | 特権管理者が保持期間内でも削除可能（Enterprise のみ） |

> **本プロジェクトの方針**: `PERMANENTLY_DISABLED` を使用。
> これにより Enterprise モードでも管理者による早期削除が不可能になる。

## 容量プランニング

SnapLock ボリュームは以下の特性がある:
- **Tiering 不可**: `TieringPolicy: NONE` が必須（データ整合性のため）
- **Snapshot ポリシー**: `none` 推奨（WORM データ自体が不変のため）
- **容量見積もり**: 保持期間 × 日次データ増加量で算出

## fsxadmin 権限での制約

- SnapLock ボリュームの作成: 可能（CloudFormation 経由）
- 保持期間の変更: 短縮不可、延長のみ可能
- SnapLock Compliance ボリュームの削除: 全ファイルの保持期間満了後のみ
- SnapLock タイプの変更: 不可（作成時に決定）

## 不可逆な決定の確認先 / Where the irreversible decisions are discussed

SnapLock の有効化、保持モードの選択、privileged delete の永久無効化は**それぞれ別の不可逆な
決定**である。承認の取り方、および「どのリソースがいつまで削除できなくなるか」という影響範囲の
整理は、FSx for ONTAP Adoption Playbook のモジュールハブにある。本リポジトリは実装手順を持ち、
Playbook が設計判断を持つ。同じ内容を両方に置かない。

Enabling SnapLock, choosing the retention mode, and permanently disabling privileged delete are
three separate irreversible decisions. How to gate them, and which resources become undeletable
for how long, is covered in the Adoption Playbook module hubs. This repository holds the
implementation steps; the Playbook holds the design guidance. The material is not duplicated.

| モジュール / Module | 扱う範囲 / Scope |
|---|---|
| [データ保護 / Data Protection](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/README.md) （[EN](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/data-protection/README.md)） | Snapshot、SnapMirror、SnapLock、バックアップ、ランサムウェア対策の設計判断 |
| [セキュリティ・ガバナンス / Security & Governance](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/security-governance/README.md) （[EN](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/security-governance/README.md)） | 不可逆操作の承認、監査ログ、アクセス認可の層 |

## 参照 / References

- [NetApp ONTAP — SnapLock](https://docs.netapp.com/us-en/ontap/snaplock/)
- [FSx for ONTAP — SnapLock](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock.html)
- [Tamperproof Snapshot Configuration](tamperproof-snapshot.md)

# ARP Alert Triage Runbook

## 概要 / Overview

ONTAP ARP (Autonomous Ransomware Protection) アラート受信時のトリアージ手順。

## トリガー / Trigger

- CloudWatch Alarm: `RansomwareAlerts` ≥ 1
- SNS 通知: "CRITICAL: Security Event - Quarantine Executed"
- Step Functions 実行開始 (Quarantine Workflow)

## 重要度 / Severity

**CRITICAL** — ARP アラートは即座の調査を要する。偽陽性であっても確認が完了するまで隔離を維持。

## 手順 / Procedure

### Step 1: アラート内容の確認 (1分以内)

```bash
# ARP アラートの詳細確認
ssh fsxadmin@<management-ip>
security anti-ransomware volume show -fields state,attack-detected,attack-suspect-count

# 影響ファイルの確認
security anti-ransomware volume show-suspect-files -vserver svm-prod-dev
```

### Step 2: 自動隔離の確認 (2分以内)

```bash
# Step Functions 実行確認
aws stepfunctions list-executions \
  --state-machine-arn <quarantine-state-machine-arn> \
  --status-filter RUNNING \
  --max-results 5

# Export Policy 状態確認 (隔離されているか)
ssh fsxadmin@<management-ip>
export-policy rule show -vserver svm-prod-dev -policyname default
```

### Step 3: 判断 (15分以内)

| 判断 | 条件 | アクション |
|------|------|---------|
| **確定攻撃** | 多数のファイル暗号化、既知のランサムウェアパターン | 隔離維持 → Reject (FlexClone 作成) |
| **疑わしい** | 少数ファイル、業務アプリの誤動作の可能性 | 調査継続 (24h以内に判断) |
| **偽陽性** | 正当な業務操作 (バッチ処理、マイグレーション) | Approve (アクセス復旧) |

### Step 4: 承認操作

[Quarantine Approval Procedure](./ransomware-recovery.md#自動隔離ワークフローの承認操作--quarantine-approval-procedure) を参照。

## 偽陽性の防止 / False Positive Prevention

ARP の偽陽性が繰り返し発生する場合:
1. ARP 学習期間の延長 (30→60日。旧世代 ARP のみ。ARP/AI には学習期間がないため対象外。[ARP 設定ガイド](../ontap-native/arp-configuration.md))
2. 除外パスの設定 (バッチ処理ディレクトリ)
3. 業務アプリケーションパターンの ARP ホワイトリスト化

```bash
# 除外パスの例 (ONTAP CLI)
security anti-ransomware volume update -vserver svm-prod-dev -volume vol_prod \
  -excluded-path "/batch-processing/*,/temp/*"
```

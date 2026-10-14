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

## 検知結果の確認・判定を行う経路 / Where to Classify a Detection

Step 1〜4 は CLI を例に示したが、ARP 検知結果の確認と「誤検知 / 実攻撃」の判定は複数の管理面から行える。コマンドを使わない運用を求める場合の経路も含め、各経路の所在を示す。どれが上位という話ではなく、ファイルシステムの世代・自動化の要否・慣れた UI・link と課金の許容で決まる。経路ごとのトレードオフと到達可否の一覧は [管理面マップ](../management-planes-cyber-resilience.md) を参照。

Steps 1-4 use the CLI as the example, but reviewing an ARP detection and marking it false positive / attack can be done from several planes. The locations are listed below, including paths for operators who prefer not to use commands. This is not a ranking; the choice follows file-system generation, automation needs, familiar UI, and tolerance for a link and its cost. For per-plane trade-offs and reachability, see the [management-plane map](../management-planes-cyber-resilience.md).

| 経路 / Plane | 検知結果の判定をどこで行うか / Where to classify |
|---|---|
| **ONTAP CLI** | `security anti-ransomware volume attack clear-suspect -vserver <svm> -volume <vol> -false-positive {true\|false}`。NAS は拡張子単位、entropy spike は `-start-time` / `-end-time` 指定（[respond-arpai](https://docs.netapp.com/us-en/ontap/anti-ransomware/respond-arpai.html)、2026-10-14 全文確認） |
| **ONTAP REST API** | CLI 等価の操作をプログラムから。イベント駆動（検知 → 自動判定ワークフロー）に向く。書き込み後は read-back で反映を確認する [E-004] |
| **ONTAP System Manager** | Storage > Volumes > 対象ボリューム > Security タブ。NAS は Suspected file types を選んで Mark as false positive / Potential ransomware attack → Update and Clear Suspected File Types。entropy spike は Mark as ... → Save and dismiss（[respond-arpai](https://docs.netapp.com/us-en/ontap/anti-ransomware/respond-arpai.html)） |
| **NetApp Console / Workload Factory** | GUI からの検知結果確認・判定。画面項目の到達可否は実機検証で確定（[管理面マップ](../management-planes-cyber-resilience.md) の「今日時点の UI 検証」） |

> **運用上の補足 / Operational note**: 判定（false positive / potential attack）を指定すると、ARP/AI がその判定を threat assessment profile に記録し、以降の監視に反映する（[respond-arpai](https://docs.netapp.com/us-en/ontap/anti-ransomware/respond-arpai.html)）。表示上のフラグにとどまらず検知動作が変わるため、業務上正当な処理であることを確認したうえで指定する。
>
> **9.18.1 note**: ONTAP 9.18.1 で System Manager は ARP/AI の baseline / surge 統計の表示を取りやめた。検知対応の Security タブそのものは残る。surge 統計は CLI / REST API で参照する（[ARP feature availability by release](https://docs.netapp.com/us-en/ontap/anti-ransomware/release-history-arp.html)、2026-10-14 全文確認）。

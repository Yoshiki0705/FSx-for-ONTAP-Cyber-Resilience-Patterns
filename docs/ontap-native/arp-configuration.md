# ARP (Autonomous Ransomware Protection) Configuration

## 概要 / Overview

ONTAP ARP は、ファイル内容のエントロピー、初見の拡張子、create / rename / delete の操作レートを
入力に、ランサムウェア様の挙動を検知する。検知時に自動で保護 Snapshot を作成し、EMS イベントを
発行する。**書き込みは拒否しない**（後述）。

ARP detects ransomware-like behaviour from file entropy, previously unseen file extensions, and
create / rename / delete operation rates. On detection it creates a protective snapshot and raises
an EMS event. **It does not refuse writes** (see below).

## 前提条件 / Prerequisites

- FSx for ONTAP 9.10.1 以降
- NAS ボリューム（FlexVol または FlexGroup）。SAN は ONTAP 9.17.1 以降
- 旧世代 ARP の場合のみ、ボリュームが通常のワークロードで使用されていること（学習データが必要）
- 操作レートによる検知を期待する場合は、**操作履歴のあるボリュームであること**。サージ判定は
  「過去に観測された値」との比較なので、新規ボリュームには比較対象がない [E-005]

> **経路のカバレッジ**: NFS / SMB に加えて、**FSx for ONTAP S3 Access Point 経由で書き込まれた
> ファイルの検知は実測済み**（2026-08-26 / ONTAP 9.18.1P3D1、ARP/AI）。検知理由は高エントロピーで、
> ARP がファイル内容を見る機構であることと整合する。**エントロピー以外の入力が同じ経路で働くかは
> 未測定**（[測定計画](arp-active-mode-measurement-plan.md)）。FPolicy はこの経路を見ないため、
> S3 Access Point 経路のストレージ層での検知は ARP と ONTAP ネイティブ監査ログの 2 つになる。

### 適用されるモデルの判別 / Which model applies

**学習期間はモデル世代に紐づく。** 手順の分岐はここで決まるので、先に確認する。

The learning period belongs to the model generation, and it decides which procedure applies.

| モデル / Model | ONTAP | 学習期間 / Learning period |
|---|---|---|
| ARP/AI | 9.16.1 以降（FlexVol）、9.18.1 以降（FlexGroup） | **不要。有効化直後から能動的に保護する** |
| ARP（旧世代 / original） | FlexVol は 9.10.1〜9.15.1、FlexGroup は 9.13.1〜9.17.1 | NAS FlexVol で 30 日。9.13.1 以降はアクティブへ自動切替 |
| ARP/AI + SAN | 9.17.1 以降 | 2〜4 週間の評価期間 |

出典: [Learn about ONTAP Autonomous Ransomware Protection](https://docs.netapp.com/us-en/ontap/anti-ransomware/)（全文、2026-09-07 取得）。

**版だけでは決まらない。ボリューム種別との 2 軸で決まる**ので、9.16.1 と 9.17.1 の FlexGroup は
旧世代 ARP で学習期間が必要になる。稼働中のモデルは `security anti-ransomware` の `version` で
確認する。ap-northeast-1 の検証クラスタ（ONTAP 9.18.1P3D1）では両ノードで `5.0` だった。

## 有効化手順 / Enable Procedure

### Step 1: SVM レベルで ARP を有効化

```bash
# SSH to FSx management endpoint
ssh fsxadmin@<management-ip>

# Enable ARP on the SVM
security anti-ransomware vserver enable -vserver svm-prod-dev
```

### Step 2: ボリュームレベルで有効化

**ARP/AI（9.16.1 以降）ではここで保護が始まる。** 学習モードは選べない。

```bash
# ARP/AI: active from the moment it is enabled
security anti-ransomware volume enable -vserver svm-prod-dev -volume vol_prod_dev -state active
```

旧世代 ARP（9.10.1〜9.15.1、および 9.17.1 までの FlexGroup）では学習モードから始める。

```bash
# Original ARP only: learn first, 30 days on NAS FlexVol
security anti-ransomware volume enable -vserver svm-prod-dev -volume vol_prod_dev -state dry-run
```

> **ARP/AI で `dry_run` を要求すると、無言で `enabled` になる。** REST API は 200 を返し、
> 警告もエラーも返さない [E-004]（ONTAP 9.18.1P3D1、2026-08-15 実測 /
> [ARP/AI と EMS の罠](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/docs/agent/pitfalls-arp-ems.md)）。
> **「学習モードだから安全」を前提に検証計画を立てるとこの 1 点で崩れる。** ARP を触る作業は
> 「有効化してよいか」の判断から始める。要求値をそのまま応答や画面に載せてはいけない。
> PATCH の後に読み直した状態を使う。

### Step 3: 状態の確認、および旧世代でのアクティブ移行

```bash
# Verify which state the volume actually landed in
security anti-ransomware volume show -vserver svm-prod-dev

# Original ARP only, and only if auto-switch is unavailable (before 9.13.1)
security anti-ransomware volume enable -vserver svm-prod-dev -volume vol_prod_dev -state active
```

> **無効化は即時ではない。** `disabled` を要求すると `disable_in_progress` になり、20 GiB の
> 空ボリュームで 10 分以上そのままだった（同上）。別環境の独立した観測でも 11 分以上かかっている。
> 学習済みの状態を破棄する必要があるため、「短時間だけ有効にして戻す」は成立しない。
> 共有環境では実施時間帯を決めてから有効化する。

### 状態の値域と表示 / The state values, and rendering them

ダッシュボードや運用スクリプトを書くときに必要になる。**値域は 7 つある。**

```
disabled | enabled | dry-run | paused | dry-run-paused | enable-paused | disable-in-progress
```

出典: [security anti-ransomware volume show](https://docs.netapp.com/us-en/ontap-cli-9171/security-anti-ransomware-volume-show.html)（全文、2026-09-07 取得）。
**同じページがパラメータの列挙で 7 値、直後の説明で 6 値を示しており、説明側だけを読むと
`paused` が漏れる。** 実装が返しうる値として 7 値を扱う。

> **遷移中の値を「無効」と同じ表示にしない。** 列挙に無い値が `switch` の `default` に落ちると、
> **まだ有効なボリュームを無効と表示する。** `disable_in_progress` で実際に起きた形で、
> `paused` 系の 3 値にも同じ穴が空く。遷移中は第 3 の状態として扱う（ONTAP のトークンは動詞から
> 作られるので `disabled_in_progress` ではなく `disable_in_progress`）。
>
> **Do not render a transitional value as disabled.** A value missing from the switch falls to
> `default`, and a volume that is still protected gets shown as unprotected.

`dry-run` は「dry-run または evaluation モード」と説明されている。SAN の評価期間が
この値で見えるのか、`block-device-detection-status` の `evaluation_period` で見えるのかは
このページからは決まらない。**どちらとも決めずに、観測値をそのまま扱う。**

## ONTAP REST API での設定

### 学習モード有効化

```bash
curl -X PATCH "https://<management-ip>/api/security/anti-ransomware/volumes/{volume-uuid}" \
  -H "Authorization: Basic $(echo -n fsxadmin:<password> | base64)" \
  -H "Content-Type: application/json" \
  -d '{"state": "dry_run"}'
```

### アクティブモード移行

```bash
curl -X PATCH "https://<management-ip>/api/security/anti-ransomware/volumes/{volume-uuid}" \
  -H "Authorization: Basic $(echo -n fsxadmin:<password> | base64)" \
  -H "Content-Type: application/json" \
  -d '{"state": "enabled"}'
```

### ステータス確認

```bash
curl -X GET "https://<management-ip>/api/security/anti-ransomware/volumes?fields=*" \
  -H "Authorization: Basic $(echo -n fsxadmin:<password> | base64)"
```

## CloudFormation Custom Resource による自動化

ARP 設定は CloudFormation ネイティブリソースでサポートされないため、Lambda-backed Custom Resource で自動化可能。

```yaml
# Custom Resource Lambda (概念)
# 1. Secrets Manager から fsxadmin 認証情報取得
# 2. ONTAP REST API で ARP 有効化
# 3. Lambda タイムアウト: 300秒
# 4. Create/Update/Delete ハンドラ実装
```

> **制約**: Custom Resource が到達するのはボリュームレベルの有効化まで。
> **旧世代 ARP でのみ**、30 日後のアクティブ移行が別の手順（9.13.1 以降は自動切替、
> それ以前は手動または Step Functions ワークフロー）になる。ARP/AI では有効化がそのまま
> アクティブなので、この分岐は存在しない。

## 検知時の動作

1. ARP がファイル操作パターンの異常を検知（エントロピー、初見の拡張子、操作のバースト）
2. 自動で ARP Snapshot を作成（`anti_ransomware_backup.*`）
3. EMS (Event Management System) イベント発行（`callhome.arw.activity.seen`）
4. 管理者がアラートを確認し、true positive / false positive を判定して `clear-suspect` する

> **応答の語彙に書き込みの拒否は含まれない。** ベンダー文書の応答手順は警告の発行、
> スナップショットの作成、管理者による分類、監視の再開で構成されている [E-001]。
> **ARP を関門（書き込みを止める層）として設計してはいけない。** 遮断が必要な場合は
> FPolicy 連携のスキャナ（NFS / SMB のみ）、または S3 側のアクセスポイントポリシーと IAM で
> 表現する。ただし**遮断の有無は実測していない**。測る計画は
> [ARP アクティブモードの挙動 — 測定計画](arp-active-mode-measurement-plan.md) にある。

> **`attack_probability` は遅れて動く。** 書き込みから 10 分以上あとに変わるため、この値だけを
> 短時間見て「検知されていない」と判断すると偽陰性になる。suspect の一覧を見る（実測）。
> EMS を REST で読むときは `message.severity` を使う。`severity` はフィールドでもフィルタでも
> 拒否される。

## 運用考慮事項

### 偽陽性 (False Positive) 対策

- 旧世代 ARP では学習期間を 30 日以上確保する。ARP/AI には学習期間がないため、この対策は
  「有効化するボリュームを段階的に増やす」に置き換わる
- 大量ファイル操作が予想される場合（バッチ処理、バックアップ等）は事前にホワイトリスト設定
- 一度に全ボリュームを有効化しない。無効化に 10 分以上かかるため、戻す判断も段階的になる

### fsxadmin 権限での制約

- ARP の有効化・設定変更は fsxadmin で可能
- ARP の学習データリセットは AWS サポートリクエストが必要な場合あり
- cluster admin レベルの操作は不可

## 参照 / References

- [ARP アクティブモードの挙動 — 測定計画](arp-active-mode-measurement-plan.md) — 遮断・クライアントが受け取るもの・S3 Access Point 経路の測り方と、測っていないことの記録
- [NetApp ONTAP — Autonomous Ransomware Protection](https://docs.netapp.com/us-en/ontap/anti-ransomware/)
- [Respond to abnormal activity detected by ONTAP ARP/AI](https://docs.netapp.com/us-en/ontap/anti-ransomware/respond-arpai.html)
- [FSx for ONTAP — ARP Documentation](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/arp.html)

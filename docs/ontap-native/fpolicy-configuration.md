# FPolicy Configuration

## 概要 / Overview

FPolicy はファイルアクセスイベント（create, open, write, rename, delete）を外部サーバーへ通知し、
リアルタイムでのスキャン判定やイベント駆動ワークフローのトリガーとして機能する。

FPolicy notifies external servers of file access events and can block or allow operations.
**Scope: NFS and SMB only.** An FPolicy event accepts `cifs`, `nfsv3` or `nfsv4` as its
protocol; there is no value for the S3 access path. Operations arriving through an FSx for
ONTAP S3 access point raise no notification and are not blocked even by a `mandatory`
synchronous policy (measured 2026-08-26, ONTAP 9.18.1P3D1). ARP does cover that path
based on external verdict — enabling real-time file scanning and event-driven security workflows.

## モード設計 / Mode Design

| Mode | Purpose | Behavior | Use Case |
|------|---------|----------|----------|
| **Synchronous** | ファイルスキャン連携 | I/O ブロック → 外部サーバー判定待ち → Allow/Block | TrendAI Vscan, Deep Instinct |
| **Asynchronous** | イベント通知 | 通知のみ（I/O はブロックしない） | EventBridge 配信、監査ログ |

## 設定手順 (Synchronous — スキャン連携)

### Step 1: FPolicy External Engine 定義

```bash
ssh fsxadmin@<management-ip>

# Define external engine pointing to Vscan server
vserver fpolicy policy external-engine create \
  -vserver svm-prod-dev \
  -engine-name trendai-vscan-engine \
  -primary-servers <vscan-server-ip> \
  -port 1344 \
  -extern-engine-type synchronous \
  -ssl-option no-auth
```

### Step 2: FPolicy Event 定義

```bash
# Define which file operations to monitor
vserver fpolicy policy event create \
  -vserver svm-prod-dev \
  -event-name scan-on-write \
  -protocol cifs,nfsv3,nfsv4 \
  -file-operations create,write,rename \
  -filters first-write
```

### Step 3: FPolicy Policy 定義

```bash
# Create policy linking engine and event
vserver fpolicy policy create \
  -vserver svm-prod-dev \
  -policy-name scan-on-write-policy \
  -events scan-on-write \
  -engine trendai-vscan-engine \
  -is-mandatory true \
  -allow-privileged-access no \
  -is-passthrough-read-enabled false
```

### Step 4: FPolicy Policy Scope 定義

```bash
# Define scope (which shares/volumes to monitor)
vserver fpolicy policy scope create \
  -vserver svm-prod-dev \
  -policy-name scan-on-write-policy \
  -volumes-to-include vol_prod_dev \
  -file-extensions-to-include exe,dll,scr,bat,cmd,ps1,vbs,js,docm,xlsm,pptm,zip,rar,7z
```

### Step 5: FPolicy Policy 有効化

```bash
# Enable the policy (priority 1 = highest)
vserver fpolicy enable \
  -vserver svm-prod-dev \
  -policy-name scan-on-write-policy \
  -sequence-number 1
```

## 設定手順 (Asynchronous — EventBridge 配信)

### External Engine (Lambda-backed FPolicy server)

```bash
vserver fpolicy policy external-engine create \
  -vserver svm-prod-dev \
  -engine-name event-notify-engine \
  -primary-servers <fpolicy-server-ip> \
  -port 9999 \
  -extern-engine-type asynchronous \
  -ssl-option no-auth
```

### Event (broader scope for audit)

```bash
vserver fpolicy policy event create \
  -vserver svm-prod-dev \
  -event-name file-activity-notify \
  -protocol cifs,nfsv3,nfsv4 \
  -file-operations create,write,rename,delete,open
```

### Policy

```bash
vserver fpolicy policy create \
  -vserver svm-prod-dev \
  -policy-name event-notify-policy \
  -events file-activity-notify \
  -engine event-notify-engine \
  -is-mandatory false \
  -allow-privileged-access no
```

### Enable

```bash
vserver fpolicy enable \
  -vserver svm-prod-dev \
  -policy-name event-notify-policy \
  -sequence-number 2
```

## passthrough-on-error 設計

Synchronous モードで外部サーバーが応答不能の場合のフォールバック動作:

```bash
# サーバーダウン時に I/O を許可（業務継続優先）
vserver fpolicy policy modify \
  -vserver svm-prod-dev \
  -policy-name scan-on-write-policy \
  -is-mandatory false
```

> **Trade-off**:
> - `is-mandatory true`: サーバーダウン時、全 I/O がブロック（セキュリティ最優先）
> - `is-mandatory false`: サーバーダウン時、スキャンなしで I/O 許可（業務継続優先）
> - 推奨: `false` + ヘルスチェックアラームで即座に検知

## ONTAP REST API での設定

```bash
# Create external engine
curl -X POST "https://<management-ip>/api/protocols/fpolicy/{svm-uuid}/engines" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "trendai-vscan-engine",
    "primary_servers": ["<vscan-server-ip>"],
    "port": 1344,
    "type": "synchronous"
  }'

# Create event
curl -X POST "https://<management-ip>/api/protocols/fpolicy/{svm-uuid}/events" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "scan-on-write",
    "protocol": "cifs",
    "file_operations": {"write": true, "create": true, "rename": true}
  }'
```

## フィルタリング最適化

パフォーマンス影響を最小化するためのフィルタリング戦略:

| Filter | Purpose | Example |
|--------|---------|---------|
| `file-extensions-to-include` | 高リスク拡張子のみスキャン | exe, dll, scr, docm, xlsm |
| `file-extensions-to-exclude` | 安全とみなす拡張子を除外 | log, tmp, csv |
| `volumes-to-include` | 対象ボリュームを限定 | 本番データのみ |
| `first-write` filter | 新規作成時のみ（更新はスキップ） | 初回書き込みのみ |

### Large File Handling Strategy（大容量ファイル対策）

製造業（CAD: 1-50GB）、メディア（映像: 10-100GB+）、科学計算（シミュレーション）など
大容量ファイルを扱う環境では、インラインスキャンがタイムアウトやパフォーマンス劣化を引き起こす。

| File Size | Strategy | Rationale |
|-----------|----------|-----------|
| < 100 MB | Inline scan (synchronous FPolicy) | 標準的なレイテンシ範囲内 (< 50ms) |
| 100 MB - 1 GB | Async notification + background scan | Write 許可、バックグラウンドで S3 AP 経由スキャン。検知時に事後隔離 |
| > 1 GB | Skip inline scan, rely on ARP + scheduled batch scan | インラインスキャンはタイムアウトリスク。ARP 行動検知 + 定期バッチで補完 |

**FPolicy file-size filter の設定:**

```bash
# Inline scan only for files <= 100MB (extensions filtered separately)
vserver fpolicy policy scope modify \
  -vserver svm-prod-dev \
  -policy-name scan-on-write-policy \
  -file-extensions-to-include exe,dll,scr,docm,xlsm,zip,rar,7z
```

> **Note**: ONTAP FPolicy のネイティブ file-size filter は限定的。
> スキャンサーバー側（Vscan/DI Agent）で size check を実装し、大容量ファイルは即座に CLEAN を返す方式が現実的。

> **Trade-off**: 大容量ファイルのスキャンスキップは、マルウェアが大容量ファイルに偽装するリスクがある。
> ARP の行動分析（エントロピー変化検知）と S3 AP 経由の定期バッチスキャンで軽減する。

## fsxadmin 権限での制約

- FPolicy の作成・変更・削除: 可能
- FPolicy ステータス確認: 可能
- FPolicy passthrough-read: 設定可能。**S3 Access Point 経由の操作の監視には関係しない**（AP 経由の操作は FPolicy に通知されない。実測 2026-08-26）
- cluster-level FPolicy 設定: 不可（SVM レベルのみ）

## 参照 / References

- [NetApp ONTAP — FPolicy](https://docs.netapp.com/us-en/ontap/nas-audit/fpolicy-config-types-concept.html)
- [FSx for ONTAP — FPolicy](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/fpolicy.html)

# 関連記事インデックス

本リポジトリのサイバーレジリエンスアーキテクチャと連携する、検知および自動応答機能に関する公開記事の一覧です。

## 自動アクセス遮断（Respond レイヤー）

以下の記事は、コンパニオンリポジトリ [FSx-for-ONTAP-Observability-integrations](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations) の自動応答モジュール（`ontap_response.py`）を解説しています。任意の検知ソースから SNS 経由でトリガーされるストレージ層アクセス遮断を実装しており、本リポジトリのイベント駆動型レスポンスレイヤーに接続される Respond フェーズのメカニズムです。

| 記事 | 言語 | プラットフォーム | 公開時期 |
|------|------|----------------|---------|
| [Automated Access Blocking for FSx for ONTAP — From Ransomware Detection to Storage-Layer Deny](https://dev.to/aws-builders/automated-access-blocking-for-fsx-for-ontap-from-ransomware-detection-to-storage-layer-deny-4l2g) | EN | dev.to (AWS Builders) | 2026-07 |
| [Amazon FSx for NetApp ONTAP の自動アクセス遮断 — ランサムウェア検知からストレージ層ブロックまで](https://hakobiya.hatenablog.com/entry/fsxn-automated-incident-response) | JA | hatena blog | 2026-07 |

### カバーするトピック

- E2E フロー: ARP/AI 検知 → EMS イベント → Observability モニター → SNS → Lambda → ONTAP REST API ブロック（2 分以内）
- SMB ユーザーブロック: name-mapping deny + セッション切断
- NFS IP ブロック: export-policy deny + NACL deny（ネットワーク層での即時遮断）
- Snapshot ストーム防止（クールダウンベースの重複排除）
- 検証済みクリーン復旧ポイントワークフロー（FlexClone + 隔離 S3 AP スキャン）
- NIST CSF 2.0 における位置づけ（Respond 機能 — RS.MI + RS.AN）
- NetApp Data Infrastructure Insights（DII）Storage Workload Security との比較（同じ ONTAP メカニズム、異なる検知ソース）。ここでの DII は NetApp の製品で、Deep Instinct ではない
- 52 ユニットテスト、CLI ヘルパー、マルチ SVM ファンアウト

### 本リポジトリのレイヤーとのマッピング

| 記事のセクション | 本リポジトリのレイヤー | 該当パス |
|-----------------|---------------------|---------|
| アーキテクチャ（SNS → Lambda → ONTAP REST API） | イベント駆動型レスポンス | `solutions/event-driven-response/` |
| ARP/AI 検知フロー | ストレージネイティブ（ARP） | `solutions/ontap-native/` |
| NFS 用 NACL deny | ネットワークレイヤー | `templates/network.yaml` |
| Snapshot 作成 & 復旧検証 | データ保護 | `templates/dr-replication.yaml` |
| NIST CSF 2.0 機能マップ | フレームワークマッピング | [`cyber-resilience-framework-mapping.md`](cyber-resilience-framework-mapping.md) |
| DII Storage Workload Security との比較 | イベント駆動型レスポンス（コンパニオンリポジトリ） | [自動応答ガイドの FAQ](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/ja/automated-response-guide.md#faq) |

## シリーズの文脈

上記の記事は「FSx for ONTAP サーバーレス Observability」シリーズの Part 18（EN）/ Part 6（JA）です。本リポジトリに直接関連するシリーズの他のパート:

| Part (EN) | Part (JA) | トピック | 本リポジトリとの関連 |
|-----------|-----------|---------|-------------------|
| Part 3 | Part 2 | ARP + FPolicy イベント駆動型検知 | `solutions/ontap-native/` — ARP 設定パターン |
| Part 17 | Part 5 | CloudWatch Log Alarm（Metric Filter 不要） | `templates/observability.yaml` — アラームパターン |
| Part 18 | Part 6 | 自動アクセス遮断 | `solutions/event-driven-response/` — 応答オーケストレーション |

## GitHub ソース参照

記事で参照されている実装コードは Observability リポジトリにあります:

- **応答モジュール**: [`shared/python/ontap_response.py`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/python/ontap_response.py)
- **CloudFormation テンプレート**: [`shared/templates/automated-response.yaml`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/templates/automated-response.yaml)
- **TTL 自動ブロック解除**: [`shared/templates/automated-response-ttl.yaml`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/templates/automated-response-ttl.yaml)
- **復旧検証**: [`shared/templates/restore-verification.yaml`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/templates/restore-verification.yaml)
- **CLI ヘルパー**: [`shared/scripts/automated-response-cli.sh`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/scripts/automated-response-cli.sh)
- **詳細ガイド**: [`docs/en/automated-response-guide.md`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/automated-response-guide.md)
- **NIST CSF 2.0 マップ**: [`docs/en/cyber-resilience-capability-map.md`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md)
- **セキュリティ補遺**: [`docs/en/automated-response-security-addendum.md`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/automated-response-security-addendum.md)

## 使い方

本リポジトリのサイバーレジリエンススタックをデプロイし、自動ブロック機能も利用する場合:

1. 本リポジトリのインフラを先にデプロイ（network、storage、events）
2. Observability リポジトリの `automated-response.yaml` スタックをデプロイ
3. 検知モニター（CloudWatch Alarm、Datadog、Elastic）を SNS トリガートピックに接続
4. `automated-response-cli.sh test`（ドライラン、実際のブロックなし）でテスト
5. テスト SVM のテストユーザーでフルドリルを実行

完全なデプロイ順序とレイヤーマッピングは [companion-repos-integration.md](companion-repos-integration.md) を参照してください。

# サイバーレジリエンス フレームワークマッピング

> **概要**: 本プロジェクトは NIST CSF 2.0 の Respond（2 分以内の自動封じ込め）と Protect（イミュータブルストレージ、インラインスキャン）を最も深くカバーし、Detect と Identify に貢献し、Govern は組織的責任として明示的に範囲外としています。主要な既知の制限: 行動 ML なし（SIEM に委任）、NTFS ボリュームの SMB ブロック不可、データ窃取のみの検知不可。

本リポジトリは [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework) を主要な設計基準とし、[NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)（インシデントハンドリング）および [NIST IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final)（ランサムウェアリスクマネジメント）との整合性を確保しています。

## NIST CSF 2.0 機能カバレッジ

| CSF 2.0 機能 | 状態 | 本リポジトリ | コンパニオンリポジトリ ([observability](https://github.com/Yoshiki0705/fsxn-observability-integrations)) | ギャップ / 組織的責任 |
|-------------|:----:|------------|---------------------|-----|
| **Govern（統制）** | ⚠️ | CloudFormation-as-code 監査証跡、cfn-guard コンプライアンスルール、`solutions/compliance/` 証跡収集 | CloudWatch Logs + SNS 通知証跡 | リスク戦略、役割、取締役会レベルの監督は組織的決定；ツーリングは証跡アーティファクトのみ提供 |
| **Identify（識別）** | ✅ | データ分類マトリクス（`docs/`）、CFn によるアセットタギング | コンテンツレベル PII スキャナー（Amazon Comprehend）、スキーマレベルフィールド分類 | テキスト/構造化データはカバー済み；Office/PDF 抽出は未実装 |
| **Protect（保護）** | ✅ | SnapLock（WORM）、MAV（マルチ管理者検証）、TrendAI インラインスキャン、Deep Instinct AI 防御、export-policy/name-mapping 強化、KMS 暗号化 | ONTAP Snapshot、export-policy、Tamperproof Snapshot | ストレージ層の保護策は完全 |
| **Detect（検知）** | ✅ | ARP/AI 設定（`solutions/ontap-native/`。**S3 Access Point 経由の書き込みも検知する**。実測 2026-08-26）、FPolicy イベントキャプチャ（**NFS / SMB のみ**）、CloudWatch アラーム（`templates/observability.yaml`） | EMS Webhook パイプライン（~30秒）、CloudWatch Log Alarm（~90秒）、FPolicy 外部サーバー | 行動 ML ベースラインは SIEM（Datadog/Elastic/Splunk ML）に委任 |
| **Respond（対応）** | ✅ | Step Functions オーケストレーション（隔離、承認ワークフロー）、Security Hub 連携 | Lambda 直接ブロック（1.8秒実測、コールドスタート込みで +10-15秒）：name-mapping deny + export-policy deny + NACL deny + セッション切断 + 保護 Snapshot、フォレンジクスダッシュボード（4 SIEM） | ソース非依存の緩和ツーリングとして完全（SNS 経由）。注: SMB name-mapping deny は NTFS セキュリティスタイルのボリュームでは無効 |
| **Recover（復旧）** | ⚠️ | SnapMirror ラグ監視（`templates/dr-replication.yaml`）、DR レプリケーションパターン | 検証済みクリーン復旧ポイント（FlexClone + 拡張子スキャン + 判定）、TTL 自動ブロック解除 | 完全なリストアリハーサルは AWS Backup restore testing を推奨；RC.CO（ステークホルダーコミュニケーション）は最小限 |

## NIST SP 800-61r3 インシデントハンドリングライフサイクル

本プロジェクトを SP 800-61 のインシデントハンドリングフェーズにマッピングします。

```
┌────────────────────────────────────────────────────────────────────────────┐
│                     NIST SP 800-61r3 ライフサイクル                          │
├──────────────┬──────────────┬──────────────────────┬──────────────────────┤
│  準備        │  検知・分析   │  封じ込め・根絶・     │  事後活動            │
│              │              │  復旧                │                      │
├──────────────┼──────────────┼──────────────────────┼──────────────────────┤
│ • SnapLock   │ • ARP/AI     │ • SMB ユーザーブロック │ • フォレンジクス      │
│ • MAV        │ • FPolicy    │   (name-mapping deny)│   ダッシュボード      │
│ • TrendAI    │ • EMS        │ • NFS IP ブロック     │ • コンプライアンス    │
│   インライン │   Webhook    │   (export-policy     │   証跡パック          │
│   スキャン   │ • CloudWatch │   + NACL deny)       │ • 検証済みクリーン    │
│ • Deep       │   Log Alarm  │ • セッション切断      │   復旧ポイント       │
│   Instinct   │ • SIEM ML    │ • 保護 Snapshot      │ • 監査ログ保持       │
│ • Export-    │  （委任）     │ • Step Functions     │ • 教訓              │
│   policy     │              │   隔離ワークフロー    │  （手動）            │
│   強化       │              │ • TTL 自動ブロック   │                      │
│ • KMS 暗号化 │              │   解除               │                      │
└──────────────┴──────────────┴──────────────────────┴──────────────────────┘
```

**CSF 2.0 と SP 800-61 の関係**: CSF 2.0 は組織全体のリスク管理プログラムを 6 機能に整理する「ホイール」であり、SP 800-61 は実際のインシデント発生時に CSF の Detect/Respond/Recover が委任する戦術的なインシデントハンドリングライフサイクルです。上記では SP 800-61 のフェーズを、該当する CSF 機能の中にネストして扱っています。

## NIST IR 8374r1 — ランサムウェア固有の達成目標

[NIST IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final) はランサムウェア固有のアウトカムを CSF 2.0 機能にマッピングしています。本プロジェクトが対応するランサムウェアアウトカム:

| IR 8374r1 アウトカム | 実装 |
|---------------------|------|
| **ランサムウェアによるファイル操作の検知** | ARP/AI エントロピー + 拡張子変更検知（ONTAP ネイティブ、9.16.1+ で学習期間不要） |
| **拡散の制限** | 検知から 2 分以内の自動 SMB/NFS アクセスブロック |
| **イミュータブルバックアップの維持** | SnapLock WORM ボリューム、Tamperproof Snapshot（侵害された管理者でも削除不可） |
| **リストア前のバックアップ整合性検証** | FlexClone + 隔離 S3 AP スキャン（ランサムウェア関連拡張子の検出） |
| **迅速な復旧** | FlexClone による候補 Snapshot の隔離検証（スペース効率的、copy-on-write）；実際のリストアは `volume snapshot restore` または FlexClone 昇格で別途実行 |
| **証拠保全** | インシデント時の保護 Snapshot + CloudWatch Logs 監査証跡（注: アクション実行前の状態は未取得 — chain of custody のギャップ） |

## MITRE ATT&CK マッピング

| ATT&CK テクニック | ID | 本プロジェクトの対応 |
|------------------|----|--------------------|
| Data Encrypted for Impact | T1486 | ARP/AI 検知 → 自動ブロック（name-mapping deny + export-policy deny + NACL deny） |
| Inhibit System Recovery | T1490 | SnapLock（削除不可）+ Tamperproof Snapshot（管理者権限でも改竄不可） |
| Data Destruction | T1485 | FPolicy によるファイル操作リアルタイム検知 → EventBridge → Step Functions 隔離。**検知範囲は NFS / SMB のみ。S3 Access Point 経由の書き込みは FPolicy に届かない**（実測 2026-08-26 / ONTAP 9.18.1P3D1）。AP 経由の経路は ARP が検知する |
| Account Manipulation | T1098 | Multi-Admin Verification（MAV）— 重要な管理操作に複数管理者の承認を要求 |
| Valid Accounts | T1078 | 監査ログパイプライン（全アクセスのトレーサビリティ）+ CloudWatch Log Alarm — 検知/可視性コントロール（防止ではない） |

## AWS Well-Architected との整合

| Well-Architected 柱 | 関連コンポーネント |
|---------------------|-------------------|
| **セキュリティ** | IAM 最小権限（Lambda ロールごと）、保存時暗号化（KMS）、転送時暗号化（ONTAP REST API への TLS）、VPC 分離、Security Hub 連携 |
| **信頼性** | Multi-AZ FSx for ONTAP、SnapMirror クロスリージョンレプリケーション、失敗したレスポンスアクション用 DLQ、パイプライン健全性の CloudWatch アラーム |
| **コスト最適化** | `templates/cost-scheduler.yaml`（開発/ステージング環境の自動停止/起動）、レスポンスモジュールのコスト ~$0.51/月 |
| **運用上の優秀性** | CloudFormation IaC、CI/CD パイプライン（285 テスト）、cfn-guard セキュリティポリシー |

## CIS Controls v8 マッピング

| CIS Control | 本プロジェクトの実装 |
|-------------|-------------------|
| **Control 3**: データ保護 | KMS 暗号化、SnapLock WORM、Tamperproof Snapshot |
| **Control 8**: 監査ログ管理 | S3 AP 監査パイプライン（365 日保持）、CloudWatch Logs |
| **Control 11**: データリカバリ | Snapshot + SnapMirror + 検証済み復旧ポイント |
| **Control 13**: ネットワーク監視 | FPolicy（NFS / SMB のみ）+ CloudWatch + VPC Flow Logs |
| **Control 17**: インシデント対応管理 | 自動ブロック + Step Functions オーケストレーション + DLQ アラーム |

## ガバナンス報告ガイダンス

本プロジェクトの機能をリスク委員会、コンプライアンス責任者、取締役会に報告する際の指針:

### 適切なフレーミング

> 「Respond フェーズの自動封じ込め（検知から 2 分以内）と Recover フェーズの事前検証を実装済み。Govern フェーズの成熟度と Detect の行動 ML 側は別途管理している」

### 不適切なフレーミング

> 「ランサムウェア対策は完了している」— これは Respond 機能を深くカバーし、他の 4 機能にも貢献するが、Govern は組織的責任として残る

### 利用可能な証跡アーティファクト

- CloudFormation デプロイ記録（誰が何をいつデプロイしたか）
- CloudWatch Logs（トリガーソース、実行アクション、API レスポンス）
- DynamoDB 判定レコード（復旧検証の合否）
- SNS 通知証跡（誰に何がいつ通知されたか）

### 監査証跡の制限事項

- レスポンスパイプラインはアクション実行後の状態をログに記録するが、アクション実行前の状態（ブロック適用前の name-mapping/export-policy 構成）は現時点で記録していない
- SNS トリガーメッセージ自体のハッシュ化は行っていない
- これらは証拠保全の連鎖（chain of custody）として正式な調査に耐えうるレベルを目指す場合に対処が必要

> **ステータスマーカーに関する注記**: 本ドキュメントの ✅ は、その機能が技術的に実装され E2E 検証済みであることを示します。特定の規制プログラム（FedRAMP、ISMAP、HIPAA、PCI DSS、SOC 2 等）への準拠認証を意味するものではありません。コントロール要件を利用可能な技術的機能にマッピングする際の一つのインプットとして扱ってください。

## 運用上の考慮事項

マルチステークホルダーレビューで特定された主要な注意点:

- **RTO/RPO**: 本プロジェクトは固定の RTO/RPO 値を定義しない — これらは環境固有であり、各デプロイのビジネス要件に基づいて確立する必要がある。レスポンスモジュールの実測 E2E タイミング（検知からブロックまで 2 分以内、worst-case 3 分以内）は RPO 計算のデータポイントであり、保証された SLA ではない。
- **誤検知ハンドリング**: 自動ブロックには誤検知のリスクが内在する。TTL 自動ブロック解除コンパニオンスタックがロックアウト期間を制限する。必ず非本番ユーザーで事前テストし、レスポンスパイプラインに接続する前に上流の検知ルールをチューニングすること。
- **影響範囲（ブラストレディウス）**: SMB name-mapping deny と NFS export-policy deny はいずれも **SVM 全体** に影響する — ターゲット SVM 内の全ボリュームと共有が対象。マルチテナント SVM 設計ではこれを考慮すること。
- **同一サブネット NACL 制限**: NACL deny ルールはサブネット境界を越えるトラフィックにのみ適用される。攻撃者のクライアントと FSx for ONTAP ENI が同一サブネットにある場合、NACL は無効 — export-policy deny（ONTAP レイヤー）のみが有効なブロックメカニズムとなる。
- **データ窃取のギャップ**: ARP/AI はファイル暗号化（エントロピー + 拡張子変更）を検知するが、暗号化を伴わないデータ窃取（二重恐喝におけるデータ持ち出しのみ）は検知しない。**さらに FPolicy による補完は NFS / SMB 経路に限られる**（S3 Access Point 経由の読み取りは FPolicy に届かない。実測 2026-08-26）。AP 経由の読み取りを追うなら ONTAP ネイティブ監査ログ（`Source=HTTP` / `Source=S3`）になるが、要求者は記録されない。FPolicy ベースのボリューム監視と SIEM 行動分析がこのギャップを部分的にカバーする。
- **Domain Admin バイパス**: `FileSystemAdministratorsGroup` のメンバー（通常 Domain Admins）は name-mapping deny ルールを完全にバイパスする。必ず非管理者ユーザーでテストすること。
- **レスポンスログ内の個人データ**: 自動レスポンスログ（CloudWatch Logs、SNS メッセージ）にはユーザー名、ドメイン、クライアント IP などの個人データが含まれる。データ保護要件に応じたアクセス制御と保持ポリシーを適用すること。
- **証跡の改竄耐性**: イミュータブル保持モードの CloudWatch Logs は、レスポンス監査証跡の改竄耐性のあるストレージを提供し、chain of custody 要件をサポートする。
- **NFS クライアントキャッシュ**: export-policy deny はサーバー側では即座に有効だが、Linux NFS クライアントは最大 60 秒間（`actimeo` デフォルト）アクセス判定をキャッシュする。NACL deny（異なるサブネット間）はクライアントキャッシュをバイパスする即時パケットレベルブロックを提供。
- **ロールバック/取り消し手順**: 誤検知によるブロックは CLI（`unblock-smb` または `unblock-nfs`）で即座に解除可能。TTL 自動ブロック解除スタックも設定時間後に自動解除する。
- **NTFS ボリュームの代替手段**: NTFS セキュリティスタイルのボリュームでは、AD アカウント無効化、NTFS ACL からの削除、または NACL deny を name-mapping の代わりに使用する。
- **Zero Trust との整合**: deny-by-default、明示的な検証、侵害前提の 3 原則を実装。ファイルレベルのマイクロセグメンテーションは未実装。
- **AWS 固有の実装**: オーケストレーションは AWS ネイティブサービス（Lambda、Step Functions、CloudFormation）を使用。ONTAP REST API パターン自体は移植可能だが、自動化レイヤーは AWS 固有。
- **日本国内規制との整合**: 個人情報保護法のもとでレスポンスログ内のユーザー名/IP は個人データに該当しうる。FISC 安全対策基準への対応については、コンパニオンリポジトリの [セキュリティ補遺](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/automated-response-security-addendum.md) に FISC ガイドライン節がある。自動応答ポリシーの事前承認や年次レビュー等の手続き要件はこちらを参照。
- **単一障害点の認識**: レスポンスパイプライン（SNS → Lambda → ONTAP REST API）は IAM ロールの完全性と ONTAP へのネットワーク到達性に依存する。Lambda の実行ロールが侵害されるか、VPC 接続が失われた場合、自動レスポンス全体が無効化される。DLQ アラームは失敗した実行を検知するが、完全に沈黙した呼び出し（例: SNS サブスクリプションの削除）は検知できない。
- **データレジデンシー**: レスポンスログと監査証跡はスタックがデプロイされた AWS リージョンに留まる。マルチリージョン要件にはリージョンごとに独立したスタックをデプロイする。追加ガイダンスはコンパニオンリポジトリの [data-residency guide](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/data-residency.md) を参照。

## 参考フレームワーク・文献

- [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework)
- [NIST SP 800-61r3 — Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST IR 8374r1 — Ransomware Risk Management: A CSF 2.0 Community Profile](https://csrc.nist.gov/pubs/ir/8374/r1/final)
- [AWS — Ransomware Risk Management on AWS Using the NIST CSF](https://docs.aws.amazon.com/whitepapers/latest/ransomware-risk-management-on-aws-using-nist-csf/technical-capabilities.html)
- [AWS Backup — Restore testing](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing.html)
- [Elastio — Mapping Ransomware Recovery to NIST CSF 2.0](https://elastio.com/blog/mapping-ransomware-recovery-to-nist-csf-20)
- [NetApp — Fortify your cybersecurity defenses with NIST framework](https://www.netapp.com/it/blog/fortify-cybersecurity-nist-framework/)

## 関連ドキュメント

- [companion-repos-integration.md](companion-repos-integration.md) — Observability リポジトリとのレイヤーマッピング
- [related-articles.md](related-articles.md) — 関連記事インデックス
- [Cyber Resilience Capability Map (EN, companion repo)](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md) — 6 機能の完全な機能マッピング（代替実装パス含む）

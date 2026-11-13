# サイバーレジリエンス フレームワークマッピング

> **概要**: 本プロジェクトは NIST CSF 2.0 の Protect（WORM、Snapshot のロック、インラインスキャン）と Respond（承認つきの隔離）を主に扱い、Detect と Identify の一部を担う。Govern は組織の責任とする。主な制約は 3 つある。行動 ML は SIEM に委ねる。NTFS ボリュームでは SMB の name-mapping による遮断が効かない [E-002]。ARP の検知条件として文書にあるのは書き込み系の挙動で、読み取りだけで発火する条件は文書にない（推論）[E-012]（持ち出し型の節と[持ち出し対応の runbook](../runbooks/data-exfiltration-response.md)）。

本リポジトリは [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework) を主要な設計基準とし、[NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)（インシデントハンドリング）および [NIST IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final)（ランサムウェアリスクマネジメント）との整合性を確保しています。

## 想定する脅威の類型（2026-10 時点）

公開 Web システムから個人情報が取得される事案は、業種や規模を問わず公表が続いている。対象は EC サイトに限らず、会員サービス・予約・業務システム・顧客対応に及ぶ。侵入の入口は、共通ソフトウェアの既知脆弱性、管理画面の弱い認証や窃取された認証情報、個別アプリや API の設計とアクセス制御の不備に分けられる。正規の機能を使った大量取得は正常応答に見えるので、エラーの増加だけを見る監視では見落としうる。漏えいと併せて、不正プログラムの設置、不正アカウントの作成、改ざん、データの削除が起きることもある。原因が公表されない場合、遡って調べられるかはログを保全していたかで決まる。クラウド基盤の管理面や仮想化層が侵害されると、同じ管理境界の中にあるスナップショットやバックアップも失われうる。本文書はこれを次の 8 つの類型に整理し、CSF 2.0 のカテゴリと本文書の節に対応づける。

| 類型 | 内容 | 主な CSF 2.0 カテゴリ | 扱う節 |
|---|---|---|---|
| A | フレームワーク・CMS・プラグインなど共通ソフトウェアの既知脆弱性の悪用 | ID.RA、PR.PS、DE.CM | ストレージ層の対象範囲と境界（ストレージ層は担わない） |
| B | 管理画面の弱い認証、窃取された認証情報 | PR.AA、DE.CM、GV.RR | 管理面の侵害（ONTAP 管理者の侵害には Tamperproof Snapshot。MAV は有効化できる環境で。FSx for ONTAP 9.18.1P6 では `fsxadmin` に拒否された（1 回の観測）[E-025]） |
| C | 個別アプリ・API の設計とアクセス制御の不備（過剰なデータ返却、匿名で使える機能、配布アプリに埋め込まれたキー） | PR.AA、PR.DS、PR.PS | ストレージ層の対象範囲と境界、持ち出し型（ファイルストアとして使う場合の S3 Access Points のポリシーとファイルシステムユーザー） |
| D | 正規の機能を使った大量取得。正常応答に見えるので、エラーの増加だけを見る監視では見落としうる | DE.CM、DE.AE、RS.AN | 持ち出し型 |
| E | 改ざん、不正プログラムの設置、データの削除 | PR.DS、DE.CM、RC.RP | 暗号化・破壊型 |
| F | クラウド基盤の管理面・仮想化層の侵害。同じ管理境界の中のスナップショットやバックアップも失われうる | PR.DS、PR.IR、RC.RP、GV.RM | 管理面の侵害 |
| G | 原因を特定できない（ログの不足）。ログを保全して遡れるかが初動を左右する | DE.AE、RS.AN、PR.PS | 両シナリオ |
| H | 委託先・クラウド基盤への依存の連鎖 | GV.SC | 組織の判断（ガバナンス指針であり法務判断ではない） |

中立な参照として、IPA「[情報セキュリティ10大脅威 2026](https://www.ipa.go.jp/security/10threats/10threats2026.html)」の組織向けの脅威のうち、この整理と重なるものを脅威名だけ挙げる: 「ランサム攻撃による被害」「サプライチェーンや委託先を狙った攻撃」「システムの脆弱性を悪用した攻撃」「内部不正による情報漏えい等」。MITRE ATT&CK の技術 ID は「MITRE ATT&CK マッピング」の節にある。

この節は 2026-10 時点の整理で、四半期ごと（1・4・7・10 月）に見直す。次回は 2027-01。

## NIST CSF 2.0 機能カバレッジ

| CSF 2.0 機能 | 主なカテゴリ | 状態 | 本リポジトリ | コンパニオンリポジトリ ([observability](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations)) | ギャップ / 組織的責任 |
|-------------|-------------|:----:|------------|---------------------|-----|
| **Govern（統制）** | GV.RM、GV.RR、GV.OC | ⚠️ | CloudFormation-as-code 監査証跡、cfn-guard コンプライアンスルール、`solutions/compliance/` 証跡収集。移行前のデータ保護計画とコストの見積り（[ボールト文書](../data-protection/aws-backup-logically-air-gapped-vault.md)）。破壊的操作の承認（AWS Backup の MPA。ONTAP の MAV は有効化できる環境で。FSx for ONTAP 9.18.1P6 では `fsxadmin` に拒否された（1 回の観測）[E-025]） | CloudWatch Logs + SNS 通知証跡 | リスク戦略、役割、取締役会レベルの監督は組織的決定；ツーリングは証跡アーティファクトのみ提供 |
| **Identify（識別）** | ID.AM、ID.RA | ⚠️ | CloudFormation のタグ（`Project` / `Layer` / `Component`、ボリュームの `DataClassification` = internal / confidential、`templates/storage.yaml`） | コンテンツレベル PII スキャナー（Amazon Comprehend）、スキーマレベルフィールド分類 | テキスト/構造化データはカバー済み；Office/PDF 抽出は対象外（コンパニオンリポジトリの現状） |
| **Protect（保護）** | PR.AA、PR.DS、PR.PS、PR.IR | ✅ | SnapLock（WORM）、MAV（マルチ管理者検証。ONTAP では documented。FSx for ONTAP 9.18.1P6 では `fsxadmin` に拒否された（1 回の観測）[E-025]）、TrendAI インラインスキャン、Deep Instinct AI 防御、export-policy/name-mapping 強化、KMS 暗号化、論理エアギャップボールト（文書のみ。本リポジトリでは未検証） | ONTAP Snapshot、export-policy、Tamperproof Snapshot | 保護するのは復旧点とファイルの可用性・完全性。認可された読み取りによる持ち出しは止めない（持ち出し型の節） |
| **Detect（検知）** | DE.CM、DE.AE | ✅ | ARP/AI 設定（`solutions/ontap-native/`。**S3 Access Point 経由の書き込みも検知する**。実測 2026-08-26）、FPolicy イベントキャプチャ（**NFS / SMB のみ**）、CloudWatch アラーム（`templates/observability.yaml`） | EMS Webhook パイプライン（~30秒）、CloudWatch Log Alarm（~90秒）、FPolicy 外部サーバー | 行動 ML ベースラインは SIEM（Datadog/Elastic/Splunk ML）に委任。ARP の検知条件として文書にあるのは書き込み系で、読み取りだけで発火する条件は文書にない（推論）[E-012]。読み取りだけの持ち出しは監査ログと SIEM で見る |
| **Respond（対応）** | RS.MA、RS.AN、RS.MI、RS.CO | ✅ | Step Functions オーケストレーション（隔離、承認ワークフロー）、Security Hub 連携 | Lambda 直接ブロック（1.8秒実測、コールドスタート込みで +10-15秒）：name-mapping deny + export-policy deny + NACL deny + セッション切断 + 保護 Snapshot、フォレンジクスダッシュボード（4 SIEM） | 検知元を問わず SNS から起動できる。注: SMB name-mapping deny は NTFS セキュリティスタイルのボリュームでは無効 |
| **Recover（復旧）** | RC.RP、RC.CO | ⚠️ | DR レプリケーションパターン、AWS Backup / 論理エアギャップボールト（restore testing の対象に FSx for ONTAP が入る、documented） | 検証済みクリーン復旧ポイント（FlexClone + 拡張子スキャン + 判定）、TTL 自動ブロック解除、SnapMirror ラグ監視（Terraform モジュール。設定は[デプロイガイド](deployment-guide.md)の「SnapMirror ラグ監視」） | 完全なリストアリハーサルは AWS Backup restore testing を推奨；RC.CO（ステークホルダーコミュニケーション）は最小限 |

### PDCA と説明責任の CSF 2.0 への対応

PDCA（Plan、Do、Check、Act）の 4 段階と説明責任の観点を、[CSF 2.0（NIST CSWP 29、2024-02-26 版）](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)のカテゴリとサブカテゴリに対応づける。参照日は 2026-11-13。ここでの説明責任は、平時の保護設定とログの取得、侵害を検知したときの判断、復旧までの記録を残すことを指す。

CSF 2.0 は、機能を並行して扱うよう書き、Core の機能とカテゴリの順序は達成の順序を意味しないとも書く（CSWP 29 の 2 節）。そのため PDCA の 4 段階を 6 機能に 1 対 1 で当てず、改善の繰り返しを表すカテゴリ（GV.OV と ID.IM）と、各機能の成果に当てる。CSWP 29 は PDCA の語を使わないので、この表は NIST の対応づけではなく、NIST による認定でもない。このプロジェクトが同じ話題を扱うと読んだ解釈で、根拠の種別は `hypothesis` とする。サブカテゴリの ID と本文は、CSWP 29 の付録 A で確かめた（documented）。

| 段階または観点 | CSF 2.0 のカテゴリとサブカテゴリ | 対応の理由 | 根拠の種別 |
|---|---|---|---|
| Plan | GV.OC-04、GV.OC-05、GV.RM-02、GV.RR-02、GV.PO-01、GV.SC-05、ID.AM-05 | 外部の利害関係者が期待するサービスと依存先を理解し（GV.OC-04、05、GV.SC-05）、リスクの許容度を定め（GV.RM-02）、役割と方針を決め（GV.RR-02、GV.PO-01）、資産の優先順位を付ける（ID.AM-05）。対応目標と RTO/RPO を決める段階に当たる | hypothesis |
| Do | PR.DS-11、PR.PS-01、PR.PS-02、PR.PS-06、PR.IR-03、ID.AM-02、ID.RA-01、ID.RA-08、ID.RA-09 | バックアップの作成と保護（PR.DS-11）、構成とソフトウェアの管理と開発の実践（PR.PS-01、02、06）、レジリエンスの要件を満たす仕組み（PR.IR-03）、ソフトウェアの一覧（ID.AM-02）、脆弱性の特定と開示への対応、使用前の真正性と完全性の評価（ID.RA-01、08、09）を実装する段階に当たる | hypothesis |
| Check | GV.OV-03、ID.IM-01、ID.IM-02、ID.IM-03、PR.DS-11 | 成績の評価（GV.OV-03）と、評価、試験と演習、運用の実行から改善を見つける作業（ID.IM-01、02、03）に当たる。リストア訓練はバックアップの試験（PR.DS-11）と ID.IM-02 に、対応目標の実績の測定は GV.OV-03 と ID.IM-03 に当たる | hypothesis |
| Act | GV.OV-01、GV.OV-02、GV.PO-02、ID.IM-04、RC.RP-04 | 戦略の見直しと調整（GV.OV-01、02）、方針の更新（GV.PO-02）、インシデント対応計画などの維持と改善（ID.IM-04）、復旧後の運用の基準の設定（RC.RP-04）に当たる。インシデント後のレビューを受けて、対応目標と待ち時間を見直す段階である | hypothesis |
| 説明責任 | GV.RR-01、GV.RR-02、GV.OC-02、GV.OC-03、PR.PS-04、RS.AN-03、RS.AN-06、RS.AN-07、RS.CO-02、RS.CO-03、RC.RP-06、RC.CO-03、RC.CO-04 | 責任と権限（GV.RR-01、02）、利害関係者の期待と法令、契約の要件（GV.OC-02、03）、ログの生成と提供（PR.PS-04）、何が起きたかと根本原因の分析（RS.AN-03）、調査の記録と、インシデントのデータの完全性と来歴の保持（RS.AN-06、07）、利害関係者への通知と共有（RS.CO-02、03）、復旧の終了の宣言と文書の完了（RC.RP-06）、復旧の進捗の伝達（RC.CO-03、04）に分かれる。GV、PR、RS、RC の 4 機能にまたがる | hypothesis |

RS と RC の実行（第 3 の柱の調査、第 2 の柱の復旧）は PDCA の 1 段階ではなく、インシデントのときに行う。その記録が Check の ID.IM-03 と Act の入力になる。この表はこの節だけに置く。ほかの文書は、この節へのリンクで参照し、表を写さない。

## 暗号化・破壊型と持ち出し型のシナリオ別対応

同じ侵入から、ファイルの暗号化・削除と、データの持ち出しのどちらも起こりうる。効く制御が違うので、2 つのシナリオを同じ形の表で分けて書く。根拠の種別はセルの中に括弧で示す。

### 暗号化・破壊型（ランサムウェア）

監査ログと SIEM による読み取りの分析は持ち出しを見つけるためのもので、暗号化や削除の進行は止めない。

| 機能 | 暗号化・破壊型の主な制御 | 限界 |
|---|---|---|
| GV | 破壊的操作の承認（AWS Backup の MPA。ONTAP の MAV は有効化できる環境で。FSx for ONTAP 9.18.1P6 では `fsxadmin` に拒否された（1 回の観測）[E-025]）、保持期間の方針、移行前の保護計画とコストの見積り（ボールト文書） | ガバナンス指針であり法的判断ではない |
| ID | 保護対象ボリュームの棚卸し、`DataClassification` タグ（`templates/storage.yaml`） | 分類の自動化はコンパニオンリポジトリ側 |
| PR | SnapLock、Tamperproof Snapshot、MAV（FSx for ONTAP 9.18.1P6 では `fsxadmin` に拒否された（1 回の観測）[E-025]）、Vscan（TrendAI）/ Deep Instinct、論理エアギャップボールト（文書のみ、documented） | 同じ管理境界の中の仕組みは、AWS アカウント全体の侵害には備えにならない（推論。管理面の侵害の節） |
| DE | ARP / ARP/AI（書き込み経路。S3 Access Points 経由の書き込みも検知、実測 2026-08-26、ONTAP 9.18.1P3D1）、FPolicy（NFS / SMB だけ [E-015]）、スキャンの判定 | `attack_probability` の更新の遅れ（既存の実測）。旧世代 ARP の学習期間の条件（既存記述） |
| RS | Step Functions による承認つきの隔離（本リポジトリ。所要時間は未測定）。コンパニオンリポジトリの Lambda による直接遮断（ARP の検知から遮断まで 2 分以内、実測、ONTAP 9.17.1P7D1） | SVM 全体に効く操作の影響範囲 |
| RC | Snapshot / SnapMirror / 論理エアギャップボールトからの復元、FlexClone + S3 Access Points スキャンでの確認 | Malware Protection for AWS Backup の対象外 [E-008]。一時リカバリポイントは restore testing の対象外 [E-017] |

### 持ち出し型（二重恐喝を含む）

SnapLock、Tamperproof Snapshot、論理エアギャップボールトは復旧点の可用性と完全性を守るもので、持ち出されたデータの機密性は守る対象に含まれない。ARP の検知条件として文書にあるのは書き込み系の挙動で、読み取りだけで発火する条件は文書にない（推論）[E-012]。

| 機能 | 持ち出し型の主な制御 | 限界 |
|---|---|---|
| GV | 保持するデータの最小化、監査ログの保持方針、通知を誰が判断するか（法務・個人情報の担当） | ガバナンス指針であり法的判断ではない |
| ID | `DataClassification` タグ、コンパニオンの PII スキャナー、S3 Access Points で公開しているボリュームの棚卸し | Office / PDF の抽出はコンパニオン側の範囲外（既存記述） |
| PR | S3 Access Points（IAM のアクセスポイントポリシー + ファイルシステムユーザーの二層、ネットワークオリジンを VPC に限定できる、Block Public Access が既定で有効、documented）、export-policy / SMB ACL、SVM の分離、KMS（保存媒体を守る。認可された読み取りは止めない） | SnapLock と論理エアギャップボールトは機密性を守る対象に含まない |
| DE | ファイルアクセス監査（SACL の適用が前提。SMB はオブジェクトごとに最初の read [E-019]、documented）、S3 Access Points 経由は `Source=S3` / `Source=HTTP`（要求者の識別情報は記録されない [E-018]、実測）、FPolicy（NFS / SMB だけ [E-015]）、SIEM の行動分析 | 読み取りだけで発火する ARP の条件は文書にない（推論）[E-012]。自動遮断の根拠にしにくい（推論） |
| RS | 証拠保全、経路ごとの封じ込め、引き継ぎ（[持ち出し対応の runbook](../runbooks/data-exfiltration-response.md)） | 要求者が記録されない経路では、特定に IAM 側の記録が要る |
| RC | アクセス設定の復旧、RC.CO の周知 | 持ち出されたデータの回収はこの表の範囲外 |

## 管理面の侵害と管理境界の外の復旧点

AWS アカウントや ONTAP 管理者の認証情報が侵害されると、同じ管理境界の中にある Snapshot やバックアップにも手が届く。防御は 3 段に分けて考える。

| 段 | 想定する侵害 | 制御 | 根拠の種別 |
|---|---|---|---|
| AWS アカウント | IAM 主体の侵害、管理 API の悪用 | IAM / SCP で操作を絞る。CloudTrail が Amazon FSx API の呼び出しを記録する。GuardDuty は CloudTrail の管理イベント・VPC Flow Logs・Route 53 Resolver の DNS クエリログを基盤データソースとして、異常な振る舞いを検知する | documented（[logging-using-cloudtrail-win.html](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/logging-using-cloudtrail-win.html)、[guardduty_data-sources.html](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html)） |
| ONTAP 管理者 | fsxadmin などの ONTAP 管理者の認証情報の侵害 | Tamperproof Snapshot、SnapLock、fsxadmin の認証情報を Secrets Manager に置く。MAV（破壊的な操作に複数の承認）は有効化できる環境で。FSx for ONTAP 9.18.1P6 では `fsxadmin` に拒否された（1 回の観測）[E-025] | documented（Snapshot のロック。MAV は ONTAP 一般）。Secrets Manager は本リポジトリの構成 |
| 管理境界の外 | AWS アカウント全体の侵害・閉鎖 | 論理エアギャップボールト、別アカウントへの SnapMirror / SnapVault | documented（ボールト）。別アカウントの隔離の度合いは推論 |

方式ごとの違いと選び方は、[ボールト文書の「隔離方式の選び方」](../data-protection/aws-backup-logically-air-gapped-vault.md#隔離方式の選び方--how-to-choose-an-isolation-option)にある。アカウント外への共有を取り消す自動修復を置く場合は、論理エアギャップボールトへのコピー中のイベント（`userIdentity.invokedBy = backup.amazonaws.com`）を除外する（documented）。

## ストレージ層の対象範囲と境界

FSx for ONTAP の制御が作用するのは、ファイル・オブジェクト・ブロックへのアクセス（SMB / NFS / S3 Access Points / iSCSI / NVMe/TCP）と管理操作の層である。アプリや DB が受け付けたクエリ・API 呼び出しの正しさはアプリ層で判定され、ストレージ層からは観測できない [E-013]。DB を iSCSI / NVMe の LUN に置いた場合、ONTAP に見えるのはブロックになる（推論）。ストレージ層が担えるのは、ファイルストアとしてのアクセス制御と監査、改ざん・削除・暗号化からの復旧点、管理面の侵害に備えた隔離コピーの 3 つである。範囲外の参照先として [AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/) と [Amazon Inspector](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html) を挙げる。

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
| **拡散の制限** | Step Functions による承認つきの SMB/NFS アクセスの隔離（本リポジトリ。所要時間は未測定）。コンパニオンリポジトリの Lambda による直接遮断は ARP の検知から 2 分以内（実測、ONTAP 9.17.1P7D1） |
| **イミュータブルバックアップの維持** | SnapLock WORM ボリューム、Tamperproof Snapshot（保持期間が切れるまで、管理者を含めて削除の要求を拒否する）、論理エアギャップボールト（文書のみ。[ボールト文書](../data-protection/aws-backup-logically-air-gapped-vault.md)） |
| **リストア前のバックアップ整合性検証** | FlexClone + 隔離 S3 AP スキャン（ランサムウェア関連拡張子の検出）。Malware Protection for AWS Backup は FSx for ONTAP の復旧ポイントを対象にしない [E-008] |
| **迅速な復旧** | FlexClone による候補 Snapshot の隔離検証（スペース効率的、copy-on-write）；実際のリストアは `volume snapshot restore` または FlexClone 昇格で別途実行 |
| **証拠保全** | インシデント時の保護 Snapshot + CloudWatch Logs 監査証跡（注: アクション実行前の状態は未取得 — chain of custody のギャップ） |

## MITRE ATT&CK マッピング

| ATT&CK テクニック | ID | 本プロジェクトの対応 |
|------------------|----|--------------------|
| Data Encrypted for Impact | T1486 | ARP/AI 検知 → 自動ブロック（name-mapping deny + export-policy deny + NACL deny） |
| Inhibit System Recovery | T1490 | SnapLock（削除不可）+ Tamperproof Snapshot（ロックの期限まで、管理者を含めて削除の要求を拒否する）+ 論理エアギャップボールト（管理境界の外の復旧点、文書のみ） |
| Data Destruction | T1485 | FPolicy によるファイル操作リアルタイム検知 → EventBridge → Step Functions 隔離。**検知範囲は NFS / SMB のみ。S3 Access Point 経由の書き込みは FPolicy に届かない**（実測 2026-08-26 / ONTAP 9.18.1P3D1）。AP 経由の経路は ARP が検知する |
| Account Manipulation | T1098 | Multi-Admin Verification（MAV）— MAV を有効化できる環境では、重要な管理操作に複数管理者の承認を要求。FSx for ONTAP 9.18.1P6 では `fsxadmin` に拒否された（1 回の観測）[E-025] |
| Valid Accounts | T1078 | 監査ログパイプライン（全アクセスのトレーサビリティ）+ CloudWatch Log Alarm — 検知/可視性コントロール（防止ではない） |
| Data from Cloud Storage | T1530 | S3 Access Points 経由の読み取り。アクセスポイントポリシーと IAM で絞る。ONTAP 監査ログに `Source=HTTP` / `Source=S3` で操作が残る（要求者の識別情報は記録されない [E-018]） |
| Exfiltration Over Web Service | T1567 | ストレージ層は検知を担わない。SIEM とネットワーク側の監視（持ち出し型の節） |
| Exploit Public-Facing Application | T1190 | ストレージ層の範囲外（ストレージ層の対象範囲と境界の節） |
| Server Software Component: Web Shell | T1505.003 | Web サーバーのファイルが TrendAI / Deep Instinct のスキャン対象のファイルストア上にあれば、書き込み時に検査される（推論） |
| Create Account | T1136 | CloudTrail（IAM の操作）。ONTAP の管理者アカウントの作成（`security login create`）は ONTAP 一般では MAV のルールで保護対象にできる（documented）。FSx for ONTAP 9.18.1P6 の `fsxadmin` では拒否された（1 回の観測）[E-025] |

## AWS Well-Architected との整合

| Well-Architected 柱 | 関連コンポーネント |
|---------------------|-------------------|
| **セキュリティ** | IAM 最小権限（Lambda ロールごと）、保存時暗号化（KMS）、転送時暗号化（ONTAP REST API への TLS）、VPC 分離、Security Hub 連携 |
| **信頼性** | Multi-AZ FSx for ONTAP、SnapMirror クロスリージョンレプリケーション、失敗したレスポンスアクション用 DLQ、パイプライン健全性の CloudWatch アラーム、AWS Backup の論理エアギャップボールト（文書のみ） |
| **コスト最適化** | `templates/cost-scheduler.yaml`（開発/ステージング環境の自動停止/起動）、レスポンスモジュールのコスト ~$0.51/月 |
| **運用上の優秀性** | CloudFormation IaC、CI/CD パイプライン（285 テスト）、cfn-guard セキュリティポリシー |

### ベストプラクティス ID との対応

AWS Well-Architected Framework の v13（2024-11-06 版）のベストプラクティス ID に、このプロジェクトの構成要素を対応づける。参照日は 2026-11-13。`latest` のページの Publication date と Document revisions の最新行は、どちらも 2024-11-06 だった。各行の ID には 2 つのリンクを付けた。1 つ目は `latest` のページ、2 つ目は版つきのパス `2025-02-25` の同じページである。`2025-02-25` が何の版かは文書から読み取れなかった（open）。10 ページとも、2 つのパスの本文はタグを除いた比較で一致した（2026-11-13）。`latest` の公開日か改訂履歴が変わったときは、すべての ID を確かめ直す。

「柱」は、サイバーレジリエンスのプログラムが分ける 3 本の柱を指す。第 1 はソフトウェアサプライチェーンの可視化と対応、第 2 は RTO/RPO と SLA/SLO/SLI、第 3 はフォレンジックである。「PDCA の段階」は、Plan、Do、Check、Act の繰り返しのうち、その ID を主な根拠にする段階を指す。

| 柱または PDCA の段階 | ベストプラクティス ID（ページへのリンク） | このプロジェクトでの対応 | 根拠の種別 |
|---|---|---|---|
| 第 1 の柱 | [SEC11-BP02 Automate testing throughout the development and release lifecycle](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_automate_testing_throughout_lifecycle.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_automate_testing_throughout_lifecycle.html)） | CI/CD での SBOM の生成と、所見を Issue で追跡する運用（実装予定）。ページは実装の手順に、CI/CD への SBOM 抽出の組み込みと、自動テストの所見のチケットによる追跡を挙げる | documented |
| 第 1 の柱 | [SEC11-BP05 Centralize services for packages and dependencies](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html)） | リポジトリ横断の依存の一覧を持ち、新しく見つかった問題の影響を特定する（実装予定）。ページが例に挙げる AWS CodeArtifact のような中央のパッケージリポジトリは置かない。リポジトリの運用と費用は要らない一方、上流を承認済みのものに限れないので、版の固定と、公開直後の版を取り込まない待ち時間（Cooldown）で補う。新しい依存の追加は PR のレビューに頼る | documented |
| 第 1 の柱 | [SEC11-BP06 Deploy software programmatically](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_deploy_software_programmatically.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_deploy_software_programmatically.html)） | ビルドの来歴証明と、Lambda のカナリアデプロイとロールバックの参照構成（実装予定）。ページの期待する成果は、テストした版とデプロイする版が同じであることと、パッケージの暗号署名である | documented |
| 第 1 の柱 | [SEC11-BP07 Regularly assess security properties of the pipelines](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html)） | 再利用可能ワークフローの参照を SHA で固定し、権限を最小にする（実装予定）。ページはパイプラインの権限の分離、一時的な認証情報、テストを使う側が編集できないことを挙げる | documented |
| 第 2 の柱 | [REL13-BP01 Define recovery objectives for downtime and data loss](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_objective_defined_recovery.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_objective_defined_recovery.html)） | 方針だけを書く。RTO と RPO はワークロードごとに利用者が定める値で、このプロジェクトが示す値は置き換えるための参照値にとどまる。対応する仕様は未作成で、範囲は第 2 の柱の仕様が決める | documented |
| 第 2 の柱 | [REL13-BP02 Use defined recovery strategies to meet the recovery objectives](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_disaster_recovery.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_disaster_recovery.html)） | 方針だけを書く。ページは、レプリケーションだけではデータの破損や破壊から守れず、ポイントインタイムの復旧手段が要ると書く。FSx for ONTAP では Snapshot、SnapMirror、AWS Backup の論理エアギャップボールトを選択肢として並べ、制約を同じ粒度で比べる。対応する仕様は未作成 | documented |
| 第 3 の柱 | [SEC10-BP03 Prepare forensic capabilities](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_prepare_forensic.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_incident_response_prepare_forensic.html)） | 方針だけを書く。ページは収集、検査、分析、報告の 4 段階と、セキュリティ OU とフォレンジック OU のアカウント構成、スナップショットとバックアップの取得を挙げる。資源を別のアカウントやリージョンへコピーするときはデータ主権の要件を確かめる。対応する仕様は未作成 | documented |
| PDCA の Check | [OPS09-BP01 Measure operations goals and KPIs with metrics](https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_operations_health_measure_ops_goals_kpis.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_measure_ops_goals_kpis.html)） | 脆弱性への対応目標の実績（期限を超えた件数、検出から起票、修正までの時間）を Check の指標にする。ページは運用の目標と KPI を指標で測り、基準値を置いて見直すよう求める | documented |
| PDCA の Check と Act | [OPS09-BP03 Review operations metrics and prioritize improvement](https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html)） | Check の指標を定期的に見直し、目標を再確認するか変更して、改善に優先順位を付ける。Check から Act に移る場面に当たる | documented |
| PDCA の Act | [OPS11-BP02 Perform post-incident analysis](https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_perform_rca_process.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_evolve_ops_perform_rca_process.html)） | インシデント後の分析で寄与要因と予防策を特定し、検知、診断、緩和までの時間を短くできたかを問う。対応目標と待ち時間の見直しの根拠にする | documented |

根拠の種別 `documented` は、ID、表題、「このプロジェクトでの対応」の列が引くページの記述を、上の参照日にページで確かめたことを指す。同じ列の「このプロジェクトでの対応」は、このプロジェクトの読みであり、AWS が示した対応ではない。「実装予定」と書いた項目は、この文書の時点で実装が済んでいない。REL11-BP07、REL09-BP04、REL13-BP03 のように第 2 の柱が追加で扱う ID は、その柱の仕様が範囲を決めたときに足す。

### この対応の位置づけ

ベストプラクティス ID との対応は、AWS Well-Architected のレビューの結果ではなく、AWS による承認でもない。ベストプラクティスのページを読み、このプロジェクトの構成要素が同じ話題を扱うと読んだものである。ワークロードの持ち主は、自分のワークロードを [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/) でレビューできる（[フレームワークの Introduction](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html)）。フレームワークはこのレビューを、監査の仕組みではなく、設計判断についての対話だと書く。[CSF 2.0 への対応](#pdca-と説明責任の-csf-20-への対応)も、NIST による認定ではない。どちらの対応も、法務、コンプライアンス、規制上の判断ではなく、ガバナンス上の指針である。

## CIS Controls v8 マッピング

| CIS Control | 本プロジェクトの実装 |
|-------------|-------------------|
| **Control 3**: データ保護 | KMS 暗号化、SnapLock WORM、Tamperproof Snapshot。機密性は暗号化とアクセス制御で守り、WORM は完全性を守る |
| **Control 8**: 監査ログ管理 | S3 AP 監査パイプライン（365 日保持）、CloudWatch Logs |
| **Control 11**: データリカバリ | Snapshot + SnapMirror + 検証済み復旧ポイント、論理エアギャップボールトと restore testing |
| **Control 13**: ネットワーク監視 | FPolicy（NFS / SMB のみ）+ CloudWatch + VPC Flow Logs |
| **Control 17**: インシデント対応管理 | 自動ブロック + Step Functions オーケストレーション + DLQ アラーム |

## ガバナンス報告ガイダンス

本プロジェクトの機能をリスク委員会、コンプライアンス責任者、取締役会に報告する際の指針:

### 適切なフレーミング

> 「Respond フェーズの承認つき隔離（Step Functions）と Recover フェーズの事前検証を実装済み。コンパニオンの Observability リポジトリと組み合わせた場合、ARP の検知からストレージ層での遮断まで 2 分以内（実測、ONTAP 9.17.1P7D1）。Govern フェーズの成熟度と Detect の行動 ML 側は別途管理している」

### 不適切なフレーミング

> 「ランサムウェア対策は完了している」— これは Respond 機能を深くカバーし、他の 4 機能にも貢献するが、Govern は組織的責任として残る

> 「隔離バックアップがあるので漏洩にも備えている」。隔離バックアップ（論理エアギャップボールト、SnapLock、Tamperproof Snapshot）は復旧点の可用性と完全性の対策で、持ち出されたデータの機密性は別の制御（アクセス制御、暗号化、監査）で扱う。通知の要否などの判断は法務の担当が行い、本ガイダンスは法的判断ではない

### 利用可能な証跡アーティファクト

- CloudFormation デプロイ記録（誰が何をいつデプロイしたか）
- CloudWatch Logs（トリガーソース、実行アクション、API レスポンス）
- DynamoDB 判定レコード（復旧検証の合否）
- SNS 通知証跡（誰に何がいつ通知されたか）

### 監査証跡の制限事項

- レスポンスパイプラインはアクション実行後の状態をログに記録するが、アクション実行前の状態（ブロック適用前の name-mapping/export-policy 構成）は現時点で記録していない
- SNS トリガーメッセージ自体のハッシュ化は行っていない
- これらは証拠保全の連鎖（chain of custody）として正式な調査に耐えうるレベルを目指す場合に対処が必要

> **ステータスマーカーに関する注記**: 本ドキュメントの ✅ は、その機能が技術的に実装され E2E 検証済みであることを示します。特定の規制プログラム（FedRAMP、ISMAP、HIPAA、PCI DSS、SOC 2 等）への準拠認証を意味するものではありません。コントロール要件を利用可能な技術的機能にマッピングする際の一つのインプットとして扱ってください。文書のみと書いた項目は ✅ の根拠に含めない。

## 運用上の考慮事項

主要な注意点:

- **RTO/RPO**: 本プロジェクトは固定の RTO/RPO 値を定義しない。これらは環境固有であり、各デプロイのビジネス要件に基づいて決める。コンパニオンリポジトリのレスポンスモジュール（Lambda）の実測 E2E タイミング（検知からブロックまで 2 分以内、worst-case 3 分以内）は RPO 計算のデータポイントであり、保証された SLA ではない。本リポジトリの Step Functions による隔離の所要時間は測っていない。
- **誤検知ハンドリング**: 自動ブロックには誤検知のリスクが内在する。TTL 自動ブロック解除コンパニオンスタックがロックアウト期間を制限する。必ず非本番ユーザーで事前テストし、レスポンスパイプラインに接続する前に上流の検知ルールをチューニングすること。
- **影響範囲（ブラストレディウス）**: SMB name-mapping deny と NFS export-policy deny はいずれも **SVM 全体** に影響する — ターゲット SVM 内の全ボリュームと共有が対象。マルチテナント SVM 設計ではこれを考慮すること。
- **同一サブネット NACL 制限**: NACL deny ルールはサブネット境界を越えるトラフィックにのみ適用される。攻撃者のクライアントと FSx for ONTAP ENI が同一サブネットにある場合、NACL は無効 — export-policy deny（ONTAP レイヤー）のみが有効なブロックメカニズムとなる。
- **データ窃取のギャップ**: ARP/AI の検知条件として文書にあるのはファイル暗号化（エントロピー + 拡張子変更）など書き込み系の挙動で、読み取りだけで発火する条件は文書にない。暗号化を伴わない読み取りだけの持ち出しで検知が起きることは見込めない（推論）[E-012]。FPolicy による補完は NFS / SMB 経路に限られる [E-015]。S3 Access Points 経由の読み取りは ONTAP ネイティブ監査ログに `Source=HTTP` / `Source=S3` で残るが、要求者の識別情報は記録されない [E-018]。監査ログと SIEM の行動分析で見る。手順は[持ち出し対応の runbook](../runbooks/data-exfiltration-response.md)。
- **Domain Admin バイパス**: `FileSystemAdministratorsGroup` のメンバー（通常 Domain Admins）は name-mapping deny ルールを完全にバイパスする。必ず非管理者ユーザーでテストすること。
- **レスポンスログ内の個人データ**: 自動レスポンスログ（CloudWatch Logs、SNS メッセージ）にはユーザー名、ドメイン、クライアント IP などの個人データが含まれる。データ保護要件に応じたアクセス制御と保持ポリシーを適用すること。
- **証跡の保持と削除権限**: CloudWatch Logs の保持期間を設定し、ロググループの削除権限を IAM で絞る。改ざんに耐えるかどうかは保存先の仕組みで決まる（[持ち出し対応の runbook](../runbooks/data-exfiltration-response.md) の監査ログの保存先の項）。
- **自動修復と AWS Backup の干渉**: アカウント外への共有を取り消す自動修復（EventBridge + Lambda）は、論理エアギャップボールトへのコピーを失敗させうる。`userIdentity.invokedBy = backup.amazonaws.com` のイベントを除外する（documented、[ボールト文書](../data-protection/aws-backup-logically-air-gapped-vault.md)）。
- **NFS クライアントキャッシュ**: export-policy deny はサーバー側では即座に有効だが、Linux NFS クライアントは最大 60 秒間（`actimeo` デフォルト）アクセス判定をキャッシュする。NACL deny（異なるサブネット間）はクライアントキャッシュをバイパスする即時パケットレベルブロックを提供。
- **ロールバック/取り消し手順**: 誤検知によるブロックは CLI（`unblock-smb` または `unblock-nfs`）で即座に解除可能。TTL 自動ブロック解除スタックも設定時間後に自動解除する。
- **NTFS ボリュームの代替手段**: NTFS セキュリティスタイルのボリュームでは、AD アカウント無効化、NTFS ACL からの削除、または NACL deny を name-mapping の代わりに使用する。
- **Zero Trust との整合**: deny-by-default、明示的な検証、侵害前提の 3 原則を実装。ファイルレベルのマイクロセグメンテーションは未実装。
- **AWS 固有の実装**: オーケストレーションは AWS ネイティブサービス（Lambda、Step Functions、CloudFormation）を使用。ONTAP REST API パターン自体は移植可能だが、自動化レイヤーは AWS 固有。
- **日本国内規制との整合**: 個人情報保護法のもとでレスポンスログ内のユーザー名/IP は個人データに該当しうる。FISC 安全対策基準への対応については、コンパニオンリポジトリの [セキュリティ補遺](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/automated-response-security-addendum.md) に FISC ガイドライン節がある。自動応答ポリシーの事前承認や年次レビュー等の手続き要件はこちらを参照。
- **単一障害点の認識**: レスポンスパイプライン（SNS → Lambda → ONTAP REST API）は IAM ロールの完全性と ONTAP へのネットワーク到達性に依存する。Lambda の実行ロールが侵害されるか、VPC 接続が失われた場合、自動レスポンス全体が無効化される。DLQ アラームは失敗した実行を検知するが、完全に沈黙した呼び出し（例: SNS サブスクリプションの削除）は検知できない。
- **データレジデンシー**: レスポンスログと監査証跡はスタックがデプロイされた AWS リージョンに留まる。マルチリージョン要件にはリージョンごとに独立したスタックをデプロイする。追加ガイダンスはコンパニオンリポジトリの [data-residency guide](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/data-residency.md) を参照。

## 参考フレームワーク・文献

- [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework)
- [NIST SP 800-61r3 — Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST IR 8374r1 — Ransomware Risk Management: A CSF 2.0 Community Profile](https://csrc.nist.gov/pubs/ir/8374/r1/final)
- [AWS — Ransomware Risk Management on AWS Using the NIST CSF](https://docs.aws.amazon.com/whitepapers/latest/ransomware-risk-management-on-aws-using-nist-csf/technical-capabilities.html)
- [AWS Backup — Restore testing](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing.html)
- [Elastio — Mapping Ransomware Recovery to NIST CSF 2.0](https://elastio.com/blog/mapping-ransomware-recovery-to-nist-csf-20)
- [NetApp — Fortify your cybersecurity defenses with NIST framework](https://www.netapp.com/it/blog/fortify-cybersecurity-nist-framework/)
- [NIST CSWP 29: The NIST Cybersecurity Framework (CSF) 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
- [IPA: 情報セキュリティ10大脅威 2026](https://www.ipa.go.jp/security/10threats/10threats2026.html)
- [MITRE ATT&CK: Enterprise Techniques](https://attack.mitre.org/techniques/enterprise/)
- [AWS What's New: AWS Backup の論理エアギャップボールトが FSx for ONTAP に対応](https://aws.amazon.com/jp/about-aws/whats-new/2026/09/aws-backup-air-gapped-vault-fsx-ontap/)
- [AWS Storage Blog: Planning data protection before migration](https://aws.amazon.com/blogs/storage/planning-data-protection-before-migration-how-aws-storage-assessments-model-backup-and-disaster-recovery-costs/)
- [AWS Backup: Logically air-gapped vault](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html)

## 関連ドキュメント

- [companion-repos-integration.md](companion-repos-integration.md) — Observability リポジトリとのレイヤーマッピング
- [related-articles.md](related-articles.md) — 関連記事インデックス
- [AWS Backup 論理エアギャップボールト](../data-protection/aws-backup-logically-air-gapped-vault.md): 隔離方式の選び方
- [持ち出し対応の runbook](../runbooks/data-exfiltration-response.md): 持ち出しを疑ったときの手順
- [運用上の注意事項](operational-considerations.md)
- [Cyber Resilience Capability Map (EN, companion repo)](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md) — 6 機能の完全な機能マッピング（代替実装パス含む）

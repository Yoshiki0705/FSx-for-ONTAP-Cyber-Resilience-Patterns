# 運用上の注意事項

FSx for ONTAP Cyber Resilience Patterns を本番環境にデプロイする際の主要な注意点。

## 応答時間と SLA

RTO/RPO: 本プロジェクトは固定の RTO/RPO 値を定義しない。これらは環境固有であり、各デプロイのビジネス要件に基づいて決める。レスポンスモジュールの実測 E2E タイミング（検知からブロックまで 2 分以内、worst-case 3 分以内）は RPO 計算のデータポイントであり、保証された SLA ではない。

## 誤検知と自動解除

誤検知ハンドリング: 自動ブロックには誤検知のリスクが内在する。TTL 自動ブロック解除コンパニオンスタック（`automated-response-ttl.yaml`）がロックアウト期間を制限する。必ず非本番ユーザーで事前テストし、レスポンスパイプラインに接続する前に上流の検知ルールをチューニングすること。

ロールバック/取り消し手順: 自動ブロックが誤検知だった場合は CLI で解除する（`automated-response-cli.sh unblock-smb --domain <CORP> --user <user>` または `unblock-nfs --ip <ip>`）。TTL 自動ブロック解除スタックも設定時間後に自動で解除する。

## 影響範囲

SVM 全体のブロック: SMB name-mapping deny と NFS export-policy deny はいずれも SVM 全体に効き、指定したボリュームだけでなく対象 SVM 内の全ボリュームと共有に影響する。マルチテナント SVM 設計ではこれを考慮すること。

同一サブネットの NACL の制限: NACL deny ルールはサブネット境界を越えるトラフィックにのみ適用される。攻撃者のクライアントと FSx for ONTAP の ENI が同一サブネットにある場合、NACL は効かず、export-policy deny（ONTAP レイヤー）だけが遮断手段になる。

NFS クライアントキャッシュ: export-policy deny は ONTAP サーバー側では即座に有効だが、Linux NFS クライアントは最大 60 秒間（`actimeo` デフォルト）アクセス判定をキャッシュする。この間、マウント済みのクライアントは I/O を続けられる。NACL deny（サブネットをまたぐ場合）はクライアントキャッシュに関係なく、パケットレベルで即時に遮断する。

## 検知のギャップ

データ持ち出しのギャップ: ARP/AI の入力はファイル暗号化（エントロピー + 拡張子変更）など書き込み系の挙動で、暗号化を伴わない読み取りだけの持ち出しは検知の前提にない [E-012]。FPolicy に届くのは NFS / SMB の操作だけ [E-015]。S3 Access Points 経由の読み取りは ONTAP 監査ログに `Source=S3` / `Source=HTTP` で残るが、要求者の識別情報は記録されない [E-018]（実測 2026-08-26、ONTAP 9.18.1P3D1）。監査ログと SIEM の行動分析で見る。手順は[持ち出し対応の runbook](../runbooks/data-exfiltration-response.md)。

Domain Admin バイパス: `FileSystemAdministratorsGroup` のメンバー（通常 Domain Admins）は name-mapping deny ルールを完全にバイパスする。ブロックのテストは必ず非管理者ユーザーで行うこと。

## ボリュームのセキュリティスタイル

NTFS ボリュームの代替手段: NTFS セキュリティスタイルのボリューム（name-mapping deny が効かない）では、(1) ユーザーの AD アカウントを直接無効化する、(2) NTFS の共有・ファイル権限からユーザーを外す、(3) NACL deny ルールでネットワーク層で遮断する、のいずれかを検討する。

## プライバシーと監査

レスポンスログ内の個人データ: 自動レスポンスログ（CloudWatch Logs、SNS メッセージ）にはユーザー名、ドメイン、クライアント IP などの個人データが含まれる。適切なアクセス制御と保持ポリシーを適用すること。

証跡の保持と削除権限: CloudWatch Logs の保持期間を設定し、ロググループの削除権限を IAM で絞る。改ざんに耐えるかどうかは保存先の仕組みで決まる（[持ち出し対応の runbook](../runbooks/data-exfiltration-response.md) の監査ログの保存先の項）。

## アーキテクチャの範囲

Zero Trust との整合: deny-by-default（export-policy/name-mapping）、明示的な検証（要求ごとの ACL 評価）、侵害前提（自動封じ込め + 証拠保全）の原則を実装している。ファイルレベルのマイクロセグメンテーションは実装していない。

AWS 固有の実装: 本プロジェクトは AWS ネイティブサービス（Lambda、Step Functions、CloudFormation、CloudWatch、SNS、EventBridge）を使う。ONTAP REST API のパターンはどの ONTAP 環境にも移植できるが、オーケストレーションと自動化の層は AWS 固有である。

## データ保護と隔離コピー

ファイルシステムの暗号化キー: バックアップを AWS Backup の論理エアギャップボールトへコピーするには、元のファイルシステムが CMK で暗号化されていること [E-009]。これはボールト自身の暗号化キー（AWS 所有キーが既定）とは別のキーである。AWS マネージドキーのファイルシステムでは、バックアップジョブは失敗せず「Completed with issues」で完了し、バックアップは標準ボールトにだけ残る（documented、[lag-vault-primary-backup.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/lag-vault-primary-backup.html)）。ジョブの成否だけでなく、ボールトにコピーがあるかを確かめる。

バックアップの対象: FSx for ONTAP のボリュームバックアップの対象は RW ボリュームで、DP / LSM / FlexCache と SnapMirror の宛先ボリューム、SnapLock FlexGroup ボリュームは対象外 [E-010]。

自動修復との干渉: アカウント外への共有を取り消す自動修復（EventBridge + Lambda）は、論理エアギャップボールトへのコピーを失敗させうる。`userIdentity.invokedBy = backup.amazonaws.com` のイベントを除外する（documented）。詳細は[ボールト文書](../data-protection/aws-backup-logically-air-gapped-vault.md)。

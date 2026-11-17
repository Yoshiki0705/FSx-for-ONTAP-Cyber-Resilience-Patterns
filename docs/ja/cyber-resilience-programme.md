# サイバーレジリエンス プログラム

> **概要**: ソフトウェアサプライチェーンの可視化と対応、RTO/RPO と SLA/SLO/SLI、フォレンジックの 3 本の柱を 1 か所にまとめ、着手の順序、PDCA での役割分担、説明責任の観点を示す。各柱の現在の状態は[現在の状態](#現在の状態)の節にある。

## この文書の目的

3 本の柱の全体方針を 1 か所に置き、各柱の位置づけと順序を取り違えないようにする。柱ごとの手順は、各柱の公開文書が持つ。第 1 の柱の導入手順は導入ガイド（`supply-chain-adoption-guide.md`。[ja](supply-chain-adoption-guide.md)）にある。第 2 と第 3 の柱の手順は、まだ公開していない。

この文書が引く指針は、すべてガバナンス上の指針である。法務、コンプライアンス、規制上の判断ではない。サービスレベルの契約上の約束はサービス提供者自身が決めることで、このプロジェクトは法務・契約上の判断を示さない。

この文書で使う用語は次のとおり。

- サービス提供者: エンドユーザーにサービスを提供し、SLA/SLO/SLI と RTO/RPO を設定する側（パートナー / SI、システム担当、アプリ担当など）
- ベンダーの SLA: AWS や NetApp が自社サービスについて公開する SLA
- 対応時間の目標: 脆弱性の検出と修正にかかる時間の目標値。運用で実測するまで SLO とは呼ばない
- ポリシーファイル: しきい値、Cooldown の値、対応時間の目標などを持つ機械可読の JSON ファイル（`docs/agent/supply-chain-policy.json`）
- Cooldown: 新しいリリースが公開されてから更新 PR を作るまでの最小経過時間
- 集約ジョブ: 対象リポジトリの SBOM を脆弱性情報と突き合わせ、しきい値を超えた所見を Issue にする Hub の定期ジョブ
- Hub: 再利用可能ワークフローと Renovate の共有プリセットを置くリポジトリ [FSx-for-ONTAP-Adoption-Playbook](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook)
- 導入ガイド: 第 1 の柱の導入手順をまとめた文書（`supply-chain-adoption-guide.md`）
- パイロット: 最初に適用する 2 件のリポジトリ（このリポジトリと Hub）で、検出器の誤りを確かめる期間。2 件の両方で集約ジョブが初めて所見の一覧を作った実行の日時から数え、既定は 14 暦日。起票した Issue が 20 件に届かないときは、14 暦日ずつ最大 2 回延長でき、合計 42 暦日までである。その結果で、参照値としきい値を決める
- 検出の起点: 検出の目標を測り始める日時。Issue を起票する条件を満たした日時と、集約ジョブがその構成要素の版を初めて観測した日時のうち、遅い方である。KEV だけで条件を満たす場合は、下限と上限の 2 つの日時で記録する（詳細は[導入ガイドの「対応時間の目標」](supply-chain-adoption-guide.md#対応時間の目標)）
- クリーンな作り直し: 侵害された環境を信用せず、固定した版と来歴証明を入力にして、新しい環境を構築し直すこと
- KEV: CISA が公開する、悪用が確認された脆弱性の一覧（Known Exploited Vulnerabilities Catalog）
- EPSS: 脆弱性が悪用される確率の推定値（Exploit Prediction Scoring System）
- SBOM: ソフトウェア部品表（Software Bill of Materials）
- VEX: ある構成要素の版に脆弱性が影響するかどうかを、根拠つきで機械可読に記録する形式（Vulnerability Exploitability eXchange）
- `MAL-`: OpenSSF Malicious Packages が悪意のあるパッケージに付ける識別子の接頭辞
- RTO/RPO: 復旧時間の目標（Recovery Time Objective）と復旧点の目標（Recovery Point Objective）
- DR: 災害復旧（Disaster Recovery）
- `[E-nnn]`: [evidence-ledger.json](../agent/evidence-ledger.json) に登録した「できない」型の主張の番号

根拠の種別は 4 語で示す。`documented` は出典の該当箇所を読んだもの、`verified` は 1 回以上実測したもの、`hypothesis` はこのプロジェクトの解釈、`open` は確認できていないものである。「できない」型の主張の登録は [evidence-ledger.json](../agent/evidence-ledger.json) にある。ここでの `open` は根拠の種別で、Issue の状態の「open（開いている）」とは別である。

## 現在の状態

2026-11-17 時点の状態は次のとおり。

- 第 1 の柱: 導入ガイドと検証ゲートがある。Hub の集約ジョブは、2026-11-13 以降の 22 回の実行のうち 17 回が成功し、直近 5 回（2026-11-16 18:15Z〜2026-11-17 09:11Z）は成功した。Renovate の共有プリセットは Hub のタグとして公開済みである。Spoke への採用は済んでいない。詳細は[導入ガイドの「現在の状態」](supply-chain-adoption-guide.md#現在の状態)にある。spec は `cyber-resilience-phase4-supply-chain` で、完了している
- 第 2 の柱: 着手済みで、spec（`cyber-resilience-phase5-recovery-objectives`）を作成中である。公開する文書は未作成
- 第 3 の柱: 未着手である。spec は `cyber-resilience-phase6-forensics` の名前で予定している。公開する文書は未作成

## 背景となる傾向

次の 2 つの傾向を、読んだ資料が自ら述べている範囲で書く。どちらの傾向も、資料が件数や変化の速さを数値で示さず、この文書の読みなので、根拠の種別は `hypothesis` とする。脅威の類型は [framework mapping の「想定する脅威の類型」](cyber-resilience-framework-mapping.md#想定する脅威の類型2026-10-時点)にある。事件名、企業名、事業者名は書かない。NIST CSF 2.0 との対応は framework mapping にあり、この文書には写さない（[NIST CSF 2.0 機能カバレッジ](cyber-resilience-framework-mapping.md#nist-csf-20-機能カバレッジ)）。

| 傾向 | 資料の書き方 | 出典 | 根拠の種別 |
|---|---|---|---|
| サプライチェーンや委託先を狙った攻撃 | IPA の「情報セキュリティ 10 大脅威 2026」は、組織向けの 2 位に挙げ、8 年連続の選出とする。順位は選考会の審議と投票で決まり、発生件数の統計ではない。警察庁の統計は、ランサムウェアの被害報告件数が令和 4 年から令和 7 年まで、年ごとに 197〜230 件の範囲にあると示し、「依然として高水準」と書く。サプライチェーン経由の侵害の件数を示す統計は、読んだ範囲になかった | [19]、[28] | hypothesis |
| 公開から悪用までの時間の短縮 | 関係府省庁の Project YATA-Shield は、AI の性能向上で脆弱性の発見と修正が速くなる一方、攻撃もより高速かつ大規模になりうると書く。時間の推移を数値で示す資料は、読んだ範囲になかった。実務者の議論としては、開催報告が AI による脆弱性発見の加速を挙げる | [20]、[17] | hypothesis |

## 3 本の柱

| 柱 | 目的 | 範囲 | 導入手順 | 状態（2026-11-17 時点） |
|---|---|---|---|---|
| 第 1: ソフトウェアサプライチェーンの可視化と対応 | 使っている構成要素を把握し、脆弱性と悪意のあるパッケージへの対応を、目標時間つきで回す | 対象リポジトリの SBOM、集約ジョブによる Issue 化、Renovate による更新、VEX、来歴証明、ONTAP の[アップグレード手順](../ontap-native/ontap-upgrade-for-security-advisories.md)。SBOM の最小要素は [1]、[2] を、保管と脆弱性管理の手順は [3] の 6.2 と第 7 章を参照する | [導入ガイド](supply-chain-adoption-guide.md) | 着手済み（spec `cyber-resilience-phase4-supply-chain` は完了） |
| 第 2: RTO/RPO と SLA/SLO/SLI | サービス提供者が復旧時間と復旧点の目標を定め、満たせているかを測る | 目標の設定方法、参照構成（Snapshot、SnapMirror、AWS Backup などの組み合わせ）、リストア訓練 | 未作成 | 着手済み（spec `cyber-resilience-phase5-recovery-objectives` を作成中） |
| 第 3: フォレンジック | 侵害のあとに、何が起きたかを再構成できる証跡を残す | 証跡の取得手順、インシデント後のレビュー | 未作成 | 未着手（spec `cyber-resilience-phase6-forensics` は未作成） |

第 1 の柱が参照する資料は次のとおり。

- ビルドの来歴証明は、GitHub の artifact attestations の手順 [9] と、SLSA の Build トラック [10] を参照する
- 悪意のあるパッケージは、OpenSSF の Malicious Packages（OSV 形式、`MAL-` の識別子）を参照する [15]
- AI エージェントのツール定義は、使用中の MCP サーバーの棚卸しと、版の固定および定義変更の検知を勧める研究ノート [11] を参照する。この研究ノートは、AI の支援で作られ、CSA の正式なレビューを経ていないと自ら書いている。
- AWS の実践として、SBOM、版の固定、悪意のあるパッケージの扱いを述べたブログ [14] を参照する。仕様ではなくガイダンスである

## FSx for ONTAP を全体システムの実装パターンに置く理由

このプロジェクトが扱うのはストレージ単体ではなく、システム全体を安全に実装する方法である。データを Amazon FSx for NetApp ONTAP（以降 FSx for ONTAP）に置く構成は、そのための 1 つのパターンである。Amazon EBS と AWS Backup、データベースのレプリケーション、Amazon S3 のバージョニングなど、別の構成で同じ分離を作れる場合もある。どれが合うかはワークロードで決まる。

データを FSx for ONTAP のボリュームに置くと、データがコンピュート（EC2、コンテナ）、ソフトウェアのライセンス、データベースエンジンのいずれとも別の層になる。層が分かれると、層ごとに次のことができる見込みがある。ただしこの 4 点は、次の「根拠の区分」の表で示すとおり、多くが推論である。

- 何が入っているかを、層ごとに棚卸しする
- 版を、層ごとに独立して上げる
- 復旧点を、層ごとに別に持つ
- コンピュートを、固定した版から作り直し、同じデータを接続し直す

### 3 本の柱での分離の使い方

| 柱 | 分離を使ってすること | 状態 |
|---|---|---|
| 第 1 | コンピュート側の構成要素の SBOM、版の固定、来歴証明を、作り直しの入力にする。ストレージ層の ONTAP の版は FSx の API で選べず、返ってもこない [E-058]。ONTAP の脆弱性への対応は、ONTAP 側で版を確認する[アップグレード手順](../ontap-native/ontap-upgrade-for-security-advisories.md)で行う | spec は完了。導入ガイドが手順を持ち、Spoke への採用は未了 |
| 第 2 | 「クリーンな作り直し」を測る。第 1 の柱が固定した版でコンピュートを作り、同じボリュームを接続して、起動からデータを読めるまでの時間を測る。復旧点からの復元時間（Snapshot、SnapMirror、AWS Backup）とは別の測定として記録する。第 3 の柱との受け渡しの形も、先に着手するこの柱が定義する。復旧点の一覧と承認付きの復元の画面は、S3 Access Points のサーバーレスパターンのリポジトリのファイルポータルに[実装がある](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/solutions/amplify-portal/docs/data-protection-recovery-design.md)。実アカウントで確認した範囲は、[ラボの記録](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/infrastructure/shared-backup-vault-lab/docs/verification-record.md)に分けて書かれている | 着手済み |
| 第 3 | 侵害されたコンピュートを作り直す前に、データ側で証跡を保全する。手順は [Ransomware Recovery Runbook の証拠保全](../runbooks/ransomware-recovery.md)にある。データの置き場が別の層なので、証跡の取得元（ONTAP の監査ログ、CloudTrail の FSx API の記録、AWS Backup の記録）をアクセスの経路ごとに分けて数えられる（推論） | 未着手 |

### 根拠の区分

根拠の種別は、この文書の冒頭の 4 語で示す。AWS Well-Architected の 4 件は、2026-11-17 に各ページを開いて、引用した記述を確かめた。

| 主張 | 種別 | 内容と出典 |
|---|---|---|
| コンピュートを入れ替えても、データはボリュームに残る | verified | ECS on EC2 でタスクとインスタンスを入れ替えたあとも、書いたマーカーが一致した。EKS on Fargate では、Pod を作り直したあとも先に書いたオブジェクトが一致して読めた。2026-11-10、ap-northeast-1、既存の Single-AZ のファイルシステム上の使い捨ての SVM、1 GiB のボリューム、各項目 1 回。性能、Multi-AZ、データベース、大きなデータは範囲外。[Container-Datastore の検証](https://github.com/Yoshiki0705/FSx-for-ONTAP-Container-Datastore-Patterns/blob/main/docs/ja/atx-containerization-fsxn-storage-verification.md)の 3.3 と 5.4 |
| バックアップを別リージョンへコピーし、コピーから復元できる | verified | 東京から大阪、2026-08-28、第 1 世代の SINGLE_AZ_1、ボリューム内のデータ 9.4 MiB。復元は 13 分 21 秒（`CREATED` まで）で 1 回。データ量との関係は測っていない。[Hub のノート](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md)（日本語のみ） |
| 共有した論理エアギャップボールトの復旧ポイントから、別アカウントの既存ファイルシステムへ復元できる | verified | 2026-10-12、同一 Organization の 2 アカウント、AWS RAM の招待経路で共有、ap-northeast-1 と ap-northeast-3、各 1 回。組織単位の共有、MPA、別リージョンの復旧ポイントからの復元は試していない。[論理エアギャップボールトのガイド](../data-protection/aws-backup-logically-air-gapped-vault.md) |
| 状態を計算資源の外へ出すと、サーバーを入れ替えても可用性に影響しない | documented | [REL05-BP06](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_mitigate_interaction_failure_stateless.html)。ページの例はセッションデータで、FSx for ONTAP には触れない。ファイルデータへの当てはめはこのプロジェクトの読み（hypothesis） |
| 稼働中の環境を更新せず、新しい環境を作って切り替える | documented | [REL08-BP04](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_tracking_change_management_immutable_infrastructure.html)。ページは FSx for ONTAP に触れない |
| バックアップと復元の自動化には、本番のデータと同じアクセス権を与えない | documented | [REL09-BP02](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_backing_up_data_secured_backups_data.html)。同じアクセス権と、本番とバックアップで同じセキュリティドメインを使うことを、アンチパターンに挙げている |
| 元の環境の外に、変更できないコピーを保管する | documented | [SEC08-BP03](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest_automate_protection.html)。望ましい結果の記述 |
| 固定した版でコンピュートを作り直し、同じボリュームを接続して復旧できる | hypothesis | 通しで測った記録は、Hub と Spoke を含む 13 リポジトリに見つからなかった（2026-11-17 に `clean rebuild` と「クリーンな作り直し」で検索し、どちらも一致なし）。第 2 の柱の最初の測定で確かめる |
| データを分けると、層ごとに見える、版を上げられる、守れる | hypothesis | ボリューム単位の Snapshot、バックアップ、SnapMirror、FlexClone は文書にある。層ごとの一覧性や更新のしやすさを測った記録はない。VMware 移行の調査も、OS 起動とデータ層の分離を[確かめる仮説の 1 つ](https://github.com/Yoshiki0705/VMware-Migration-EC2-ONTAP/blob/main/docs/ja/research.md)と書く。ソフトウェアの一覧は第 1 の柱の SBOM の仕事で、データの置き場が直接与えるものではない |

### トレードオフ

どの項目も、ここで述べた構成を選ぶ側の制約である。

| 項目 | 内容 | 出典 |
|---|---|---|
| 起動ディスク | FSx for ONTAP の LUN は起動ディスクに使わない構成である。OS のディスクは EBS に残り、OS のパッチとライセンスは引き続きインスタンス単位である | [Hub のノート](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/block-storage/notes/when-shared-block-changes-the-design.md)（documented） |
| ONTAP の版 | 作成・更新の API に版の項目がなく、`DescribeFileSystems` も版を返さない。利用者が決めるのは週次のメンテナンスウィンドウの開始時刻である [E-058] | [evidence-ledger.json](../agent/evidence-ledger.json) |
| 2 つの管理面 | ONTAP の REST・CLI と FSx の API は、同じリソースに対する別の真実の源である。ONTAP で作ったボリュームが FSx の API に現れるまで、12〜36 分の観測がある（観測ごとに結果が一致せず、上限としては使えない）。HA ペアが複数ある第 2 世代のファイルシステムでは、NetApp Console と NetApp System Manager を使えない [E-023] | [Hub のデータ保護方式の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md)、[管理面の整理](../management-planes-cyber-resilience.md)、[evidence-ledger.json](../agent/evidence-ledger.json) |
| 最小構成の費用 | ファイルシステムには SSD 容量とスループット容量の下限があり、データが小さくても月額が発生する。Hub の試算では、最小構成の月額の大半がスループット容量である。EBS や S3 との比較は、データセットの規模と複製の数で変わる。単価は当日の Pricing API で確認する | [Hub のノート](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/block-storage/notes/when-ebs-stops-being-the-cheaper-answer.md) |
| Fargate での到達形態 | Fargate のタスクと Pod は、ボリュームのマウントではなく、S3 Access Points 経由のオブジェクト API でデータを読み書きする。アプリを S3 の SDK に合わせる改修が要る。EC2 系はファイルのマウント（NFS、iSCSI）で使える | [Container-Datastore の検証](https://github.com/Yoshiki0705/FSx-for-ONTAP-Container-Datastore-Patterns/blob/main/docs/ja/atx-containerization-fsxn-storage-verification.md)の 1 |
| 障害ドメイン | Snapshot は同じボリューム、SnapMirror の宛先は別のファイルシステム、論理エアギャップボールトは AWS Backup のサービス所有アカウントにある。分離の強さは、選んだ層で変わる | [論理エアギャップボールトのガイド](../data-protection/aws-backup-logically-air-gapped-vault.md)の比較表 |
| ONTAP 機能への依存 | SnapMirror、FlexClone、SnapLock は ONTAP どうしの機能である。別の構成で同等の分離を作れる場合は、そちらが合うことがある | 比較は [Hub のデータ保護方式の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md) |
| 整合した復旧点 | データベースのように書き込み中の整合が要るデータは、静止やデータベースの機能で整合した復旧点を別に作る必要がある | 推論（hypothesis） |

### 合う場面と他の選択肢を見る場面

合う場面は次のとおり。

- データの寿命がコンピュートより長く、コンピュートを版の固定と来歴証明から作り直したい
- 同じデータを、NFS、SMB、iSCSI、S3 Access Points の複数の経路で使う
- ONTAP の Snapshot、SnapMirror、FlexClone を既に運用している、または運用する前提で復旧点を設計する

他の選択肢も見る場面は次のとおり。

- データが小さく、最小構成の月額が釣り合わない
- Fargate や Lambda のアプリで、S3 の SDK へ改修する余地がない
- 課題の中心が OS ディスクの更新で、データの分離が主ではない
- ONTAP の版を AWS 側の設定で固定したい、または管理面を AWS の API に一本化したい

## 着手の順序

1. 第 1 の柱。他の柱の完了を待たない。
2. 第 2 の柱。第 1 の柱の版の固定と来歴証明を、クリーンな作り直しの入力に使えるが、第 1 の柱の完了を着手の条件にはしない。
3. 第 3 の柱。他の柱の完了を待たない。

第 2 の柱と第 3 の柱は、受け渡しの項目を共有する。第 3 の柱から第 2 の柱へ渡すのは、どの復旧点に戻すかを判断した記録である。復旧点を決める時間を RTO に含めるかは、第 2 の柱が決める。どちらも他方の完了を前提にせず、先に着手する柱が受け渡しの形を定義する。

CISA の KEV のカタログには、エントリーごとに `forensicTriage` の欄がある。`Yes` のエントリーは、第 3 の柱へ渡す入力の候補にする。2026-11-15 に取得したカタログ（`catalogVersion` 2026.11.13）では、1,781 件のうち 105 件が `Yes` だった（1 回の取得）。この欄の意味と使い方は、第 3 の柱の計画で決める。第 1 の柱は、Issue の本文に値を表示するだけで、起票の判定には使わない。

## サービスレベルの考え方

SLA/SLO/SLI と RTO/RPO は、サービス提供者がエンドユーザーに向けて設定する値である。ベンダーの SLAではない。SLA/SLO/SLI の定義は、Resilience lifecycle framework の Stage 1 の節にある [13]。

ベンダーの SLA は、サービス提供者の SLO を決める入力の 1 つである。SLO は、ベンダーの SLA の対象外であるアプリケーション、運用、復旧手順も含めて考える。ベンダーの SLA の数値はこの文書に書かない。使うときは、ベンダーが公開する SLA のページから、参照日を添えて引く。

金融庁と日本銀行の要請の脚注は、SLA を金融機関等とベンダーの間のサービス品質保証の契約の意味で使い、SLO を SLA を達成するための組織内部の目標と書く [24]。この SLA の用法は、この文書のベンダーの SLA に当たる。同じ脚注の SLO は、サービス提供者の SLO に近い（解釈）。

サイバーリカバリと DR の区別は、この文書では定義しない。第 2 の柱の計画で定義する。この区別とリストア訓練を扱う実務者向けの資料として [26]、[27] がある。

## PDCA サイクル

3 本の柱は、Plan、Do、Check、Act の繰り返しとして合わさる。第 2 と第 3 の柱の欄は、計画がない間は、方針の記述にとどめる。

| 段階 | 第 1 の柱 | 第 2 の柱 | 第 3 の柱 | 柱の間のつながり |
|---|---|---|---|---|
| Plan | 対応時間の目標の参照値、Cooldown（Renovate の `minimumReleaseAge` [5]）、Issue を起票するしきい値を、サービス提供者が決める | SLO/RTO/RPO の設定方法（データ保護と復旧時間を含む可用性） | フォレンジックで残す証跡の範囲 | 第 3 の柱が決める証跡の範囲は、第 2 の柱の復旧点の判断の入力になる |
| Do | Renovate の設定、再利用可能ワークフロー、集約ジョブの導入。版の固定と来歴証明は、クリーンな作り直し（第 2 の柱）の入力になる | 参照構成（Snapshot、SnapMirror、AWS Backup などを組み合わせた構成） | 証跡の取得手順 | 第 1 の柱の版の固定と来歴証明が、第 2 の柱の作り直しの入力になる |
| Check | 対応時間の目標に対する実績（期限超過の件数、検出の実績）と CI/CD の記録 | SLI の測定、リストア訓練の結果（確認点と所要時間） | インシデント後のレビュー（記録の範囲） | 第 1 の柱の実行結果とリストア訓練の結果は、説明責任の記録になる（次の節） |
| Act | 対応時間の目標と Cooldown の見直し | SLO と構成の見直し | Act に渡すフォレンジックの証跡と再発防止 | 第 3 の柱の証跡と再発防止が、第 2 の柱の復旧点の判断と第 1 の柱の目標の見直しに渡る |

PDCA の 4 段階と説明責任の観点の NIST CSF 2.0 への対応は、framework mapping の[PDCA と説明責任の CSF 2.0 への対応](cyber-resilience-framework-mapping.md#pdca-と説明責任の-csf-20-への対応)にある。表はそこにだけ置き、この文書には写さない。解釈による対応で、NIST の認定ではない。

## 説明責任の観点

説明責任は、3 本の柱を横断する観点である。説明責任を果たすために、次の 3 つの記録を残す。

- 平時の保護設定とログの取得
- 侵害を検知したときの判断
- 復旧までの記録

「説明責任」と訳される Accountability は、RACI の A（最終責任者）の意味でも使われる。この文書では上の意味に限る。説明の内容は、次の 3 点に分けて考える。(a) 誰が責任を持つか。サービス提供者の組織が決める。(b) 何を根拠に説明するか。記録の完全性と来歴である。(c) 誰に伝えるか。通知の要否は法務の担当が判断し、このプロジェクトは判断を示さない。

説明責任は第 3 の柱だけに属さない。第 1 の柱の記録（SBOM、Issue、VEX、実行結果）と、第 2 の柱の復旧（復旧点の判断の記録）にまたがる。柱の数と順序（1→2→3）は変えない。説明責任は、柱の順序とは別の観点として、PDCA の説明の後にこの節で扱う。開催報告 [17] は、防御、復旧、説明責任の 3 つの軸で対策を整理しており、この文書はその整理を参考にして、説明責任を柱を横断する観点として足した。

| 柱 | 説明責任に提供する記録 | 説明の中での使い道 |
|---|---|---|
| 第 1 | 集約ジョブの実行結果（起票、更新、クローズ、VEX による除外とその理由、対応時間の目標の実績）、VEX の判断と承認の記録（OpenVEX [6]）、SBOM、来歴証明 | その時点で何が入っていて、いつ気づき、いつ直したか。作り直した構成が元と同じであることの根拠 |
| 第 2（方針） | 復旧点の選定の理由と承認、復元の試験の結果と所要時間、RTO/RPO の目標と実績、受け入れたデータの損失の範囲 | どの時点に、なぜ戻したか。目標に対する実績はどうだったか |
| 第 3（方針） | アクセスの経路ごとと管理面ごとの証跡、時系列の再構成、監査の記録が欠けた期間の記録、事後のレビュー | 何が起きたか、入口はどこか、再発をどう防ぐか |

第 2 と第 3 の柱の行は、方針だけを書いている。それぞれの柱の計画ができたときに埋める。ストレージの種類ごとに残る記録の違いは、[ストレージの種類ごとのデータ保護](#ストレージの種類ごとのデータ保護)の節に挙げた Hub の文書を参照する。

## Resilience lifecycle との対応

PDCA の 4 段階を、AWS Prescriptive Guidance の Resilience lifecycle framework の段階に対応づける [13]。このフレームワークは 5 段階（Set objectives、Design and implement、Evaluate and test、Operate、Respond and learn）を、繰り返す過程として書く。この表はベストプラクティスの ID を持たず、Well-Architected の対応表の一部ではない。

| PDCA の段階 | Resilience lifecycle の段階 |
|---|---|
| Plan | Set objectives |
| Do | Design and implement |
| Check | Evaluate and test、Operate |
| Act | Respond and learn |

災害復旧の試験は、Evaluate and test と Operate の両方にまたがる。1 つの段階には振らない。

## Well-Architected のベストプラクティス

このプロジェクトが扱う対象と AWS Well-Architected Framework のベストプラクティス ID の対応は、framework mapping の[ベストプラクティス ID との対応](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応)にある。表はそこにだけ置く。この文書は、柱ごとに実装する ID を 1 行に 1 つずつ挙げる。フレームワークの版は v13（2024-11-06）、参照日は 2026-11-13 である。各 ID の 2 つ目のリンクは、版つきのパス `2025-02-25` の同じページである。`2025-02-25` が何の版かは、文書から読み取れていない（`open`）[12]。

- 第 1 の柱: [SEC11-BP02](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_automate_testing_throughout_lifecycle.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_automate_testing_throughout_lifecycle.html)）
- 第 1 の柱: [SEC11-BP05](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html)）
- 第 1 の柱: [SEC11-BP06](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_deploy_software_programmatically.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_deploy_software_programmatically.html)）
- 第 1 の柱: [SEC11-BP07](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html)）
- 第 2 の柱: [REL13-BP01](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_objective_defined_recovery.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_objective_defined_recovery.html)）
- 第 2 の柱: [REL13-BP02](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_disaster_recovery.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_disaster_recovery.html)）
- 第 3 の柱: [SEC10-BP03](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_incident_response_prepare_forensic.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_incident_response_prepare_forensic.html)）
- PDCA の Check: [OPS09-BP01](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_measure_ops_goals_kpis.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_measure_ops_goals_kpis.html)）
- PDCA の Check と Act: [OPS09-BP03](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html)）
- PDCA の Act: [OPS11-BP02](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_evolve_ops_perform_rca_process.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_evolve_ops_perform_rca_process.html)）

第 2 の柱が追加で扱うベストプラクティスは、その柱の計画が範囲を決めたときに足す。10 件とも、2026-11-13 に全文を読み、framework mapping の表の記述と照合した。

NIST SP 800-218 の SSDF との対応は、framework mapping の[SSDF との対応](cyber-resilience-framework-mapping.md#ssdf-との対応)にだけ置く。SSDF の確定版 Version 1.1 の本文を 2026-11-15 に読んだ。Rev. 1 は 2026-11-15 時点で草案で、この文書は草案に依拠しない。

上の Well-Architected の対応は、AWS Well-Architected のレビューの結果ではなく、AWS による承認でもない。サービス提供者は、自身のワークロードのレビューを [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/) で記録できる [16]。NIST CSF 2.0 への対応と SSDF への対応は、どちらも NIST による認定ではない。

### 保持を固定する手段の選び方

REL13-BP02 のように、復旧点を削除から守る手段には ONTAP の機能と AWS のサービスがある。次の表は、順位を付けずに、向く場面と制約を並べる。使う手段は、守るデータの置き場所と、保持を管理者の権限でも解除させたくないかで選ぶ。複数を重ねて使うこともある。ロックの保持期間は、検知と対応にかかる時間より長くするという指針が、実務者向けの記事にある [18]。機能の記述は、記事ではなく現行の公式ドキュメント [29] による。

| 手段 | 向く場面 | 制約 |
|---|---|---|
| Amazon S3 Object Lock | S3 のオブジェクトを、保持期間のあいだ上書きと削除から守る | バージョニングが前提。有効化は元に戻せない（有効にした後は、Object Lock の無効化もバージョニングの停止も選べない）。コンプライアンスモードの保持は、ルートユーザーを含め、期間が終わるまで解除や上書きがされない |
| AWS Backup Vault Lock と論理エアギャップボールト | AWS Backup のバックアップを削除から守り、別のボールトへ隔離する | コンプライアンスモードは、猶予期間（3 日以上）が過ぎると、設定が誰にも変更・削除されなくなる。Amazon FSx for NetApp ONTAP（以降 FSx for ONTAP）のバックアップは、ファイルシステムが AWS マネージドキーで暗号化されていると論理エアギャップボールトへコピーされない [E-009] |
| Amazon EBS のごみ箱の保持ルールのロック | EBS のスナップショット、ボリューム、EBS-backed AMI の誤削除からの回復 | ロックを解除しても、遅延期間（7〜30 日）が過ぎるまでルールは有効なまま。ロック中のルールは変更も削除もされない |
| ONTAP SnapLock（FSx for ONTAP） | ボリューム内のファイルを WORM で保持する | SnapLock の種類は、ボリュームの作成時に選ぶ。2023-07-13 以降のファイルシステムで使える |
| ONTAP Tamperproof Snapshot（[設定](../ontap-native/tamperproof-snapshot.md)） | 既存のボリュームの Snapshot にロックをかける | ロックした Snapshot が残るあいだ、ONTAP を以前の版へ戻せない [E-057] |

Hub の[データ保護方式の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md)も参照する。

## 参照値の扱い

このプロジェクトが公開する値（対応時間の目標と、第 2 の柱の計画で公開する予定の参照用の SLO/RTO/RPO）は、サービス提供者が自身の値に置き換えるための参照値である。どのエンドユーザーへの約束でもない。

対応時間の目標は目標で、運用で実測するまで SLO と呼ばない。値はポリシーファイルの `response_target` にあり、この文書は同じ値を示す。検出の目標は <!-- policy:response_target.detect_hours -->24 時間（検出の起点から Issue の起票まで）である。修正の目標は、Issue の起票からクローズまでの時間に適用する。KEV 掲載 [7] の脆弱性と悪意のあるパッケージは <!-- policy:response_target.fix_days_kev_or_malicious -->7 日、それ以外で CVSS の重大度が High 以上のものは <!-- policy:response_target.fix_days_high -->14 日である。14 日は参照値で、パイロットの実績を見て、14 日のまま使うか 30 日に延ばすかを決める。EPSS [8] のスコアは Issue に添える参考の値で、区分には使わない。

対応時間の目標は、集約ジョブが扱うリポジトリの依存関係の所見に適用する。ONTAP のセキュリティアドバイザリは対象外で、[ONTAP のバージョンアップ手順](../ontap-native/ontap-upgrade-for-security-advisories.md)の段階 1 に従う。

KEV だけで起票の条件を満たす場合、検出の起点は下限と上限の 2 つの日時で記録し、月 1 回の確認は上限に対しても 24 時間を超えたものだけを確実な超過として数える。規則は採用ガイドの[対応時間の目標](supply-chain-adoption-guide.md#対応時間の目標)と[月 1 回の確認手順](supply-chain-adoption-guide.md#月-1-回の確認手順)にあり、ここには写さない。

検出の目標の 24 時間は、当局への報告の期限ではない。EU の製品規則は、製造者が悪用中の脆弱性に気づいてから遅くとも 24 時間以内の早期警告を求める [4]、[25]。この報告義務は 2026-09-11 に始まっている [4]。長さは同じでも、起点（気づいた時点か、アドバイザリや KEV の公開か）、行為（当局への報告か、Issue の起票か）、宛先が違う。集約ジョブや Issue がその報告を満たすかは、この文書では判断しない。

### 公的な基準の修正期限

サービス提供者が参照値を自分の値に置き換えるときの比較の材料として、公開された基準の修正期限を要約する。各基準は自分の対象（企業、政府機関、金融機関、製品の製造者）に課すもので、このプロジェクトにもサービス提供者にも適用されない。どの値が正しいかの判断ではない。起点はこのプロジェクトの起票と同じではない。

| 基準の型 | 区分に使う情報 | 修正の日数 | 起点 | 出典 |
|---|---|---|---|---|
| このプロジェクトの対応時間の目標 | KEV 掲載、悪意のあるパッケージ、CVSS の重大度 | KEV 掲載と悪意のあるパッケージは 7 日、それ以外で CVSS の重大度が High 以上のものは 14 日（ポリシーファイルの `response_target`） | Issue の起票 | ポリシーファイル |
| 企業向けの評価制度（★3 の評価基準） | ベンダーが重大・高リスクとする脆弱性、CVSS の基本値 7.0 以上、レベルの記載がない更新 | 14 日。期限内にできない場合は、適用までのリスク低減策。制度は開始前（2026-10-28 のページは 2026 年度末頃の開始を目指すと書く） | アップデートのリリース | [21] |
| 認証制度の技術要件（英国） | 「critical」または「high risk」とされる脆弱性（CVSS v3 の基本値 7 以上、またはベンダーの区分） | 14 日 | リリース | [30] |
| 行政機関向けの指令（米国） | 公開の有無、KEV 掲載、攻撃者の自動化の可否、技術的な影響の 4 つの変数（CVSS は使わない） | 3 日、14 日、60 日、次のシステム更新時 | KEV への追加と、資産での特定の早い方 | [31] |
| 政府機関向けの基準 | 製品、セグメント、深刻度（CVSS など）を踏まえて、各機関が事前に定める適用基準 | 日数を定めない | 計画の実施予定時期 | [22] |
| 金融分野のガイドライン | システムの重要度、リスク、深刻度 | 日数を定めない。対応期限の設定と対応実績の管理を求める | 定めなし | [23] |
| EU の製品規則 | 悪用の信頼できる証拠がある脆弱性（報告の対象） | 修正は「遅滞なく」で、日数を定めない | 製造者が気づいた時点 | [25] |

企業向けの評価制度の 14 日は起点がリリースで、対応時間の目標の 14 日は起点が Issue の起票である。Issue の起票はリリースより後なので、同じ起点で比べると、対応時間の目標のほうが長い。期限の見直しの手順は、導入ガイドの「[実績を PDCA に使う方法](supply-chain-adoption-guide.md#実績を-pdca-に使う方法)」で扱う。

## ストレージの種類ごとのデータ保護

オンプレミスのストレージ、Amazon EBS、Amazon S3、Amazon EFS、FSx for ONTAP とその他の Amazon FSx では、データ保護の手段と制約が違う。この違いは、第 2 の柱が復旧点を選ぶ入力であり、第 3 の柱が証跡を残す範囲の入力でもある。比較は Hub に既にあるので、この文書は表も記述も写さず、リンクだけを置く。

- [ファイルストレージの選択肢の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/file-storage-options.md)
- [データ保護方式の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md)
- [Amazon FSx for NetApp ONTAP の Snapshot だけで復旧できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/snapshots-are-not-a-recovery-plan.md)
- [Amazon FSx for NetApp ONTAP のバックアップコピーだけで復旧できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md)
- [Amazon FSx for NetApp ONTAP の SnapLock は有効化だけで保護できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/snaplock-and-layered-ransomware-readiness.md)
- [第三者バックアップ製品は Amazon FSx for NetApp ONTAP にどの経路で届くか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/third-party-backup-reaches-it-by-another-route.md)
- [EBS が安くなくなる境目は台数か？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/block-storage/notes/when-ebs-stops-being-the-cheaper-answer.md)

比較の内容が足りない場合は、この文書に書かず、Hub への依頼か、第 2 または第 3 の柱の計画に送る。

## 参考文献

番号は本文の `[n]` に対応する。導入ガイドの参考文献は `[Gn]` の別の番号体系で、この表の番号と混ざらない。日付は日本時間で、公開日は各ページに表示された日付である。名称は発行主体が付けた原題で書く。参照日は、その URL の内容を確かめた日である。根拠の種別の `open` は、確認できていない部分を示す。

| 番号 | 名称 | 発行主体 | 公開日・版 | URL | 参照日 | 根拠の種別 |
|---|---|---|---|---|---|---|
| 1 | 2026 Minimum Elements for a Software Bill of Materials (SBOM) | CISA ほか 17 機関（METI、NCO を含む） | 2026-07-29、版 2.1 | [PDF](https://www.cisa.gov/sites/default/files/2026-07/2026_cisa_sbom_minimum_elements_508c.pdf) | 2026-11-10 | documented |
| 2 | サイバーセキュリティのためのソフトウェア部品表（SBOM）の最小要素に関する国際ガイダンスに共同署名しました | 経済産業省 | 2026-07-30 | [meti.go.jp](https://www.meti.go.jp/press/2026/07/20260730001.html) | 2026-11-10 | documented |
| 3 | ソフトウェア管理に向けたSBOM（Software Bill of Materials）の導入に関する手引ver2.0 | 経済産業省 | 2024-08-29、ver 2.0 | [meti.go.jp](https://www.meti.go.jp/press/2024/08/20240829001/20240829001.html) | 2026-11-12 | documented（6.2 と第 7 章）。他の節は open |
| 4 | Cyber Resilience Act - Reporting obligations | European Commission | 日付の表示なし | [digital-strategy.ec.europa.eu](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | 2026-11-14 | documented |
| 5 | Minimum Release Age | Renovate | 日付の表示なし | [docs.renovatebot.com](https://docs.renovatebot.com/key-concepts/minimum-release-age/) | 2026-11-10 | documented |
| 6 | OpenVEX Specification v0.2.0 | OpenVEX | v0.2.0 | [GitHub](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | 2026-11-10 | documented |
| 7 | Known Exploited Vulnerabilities Catalog | CISA | catalogVersion 2026.11.09 | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 2026-11-10 | verified（取得 1 回） |
| 8 | GET /epss (FIRST.Org REST API Documentation)、EPSS Data (Get the Data)、Using EPSS | FIRST（EPSS SIG） | 日付の表示なし。API は BETA と表示 | [API](https://api.first.org/epss/)、[Data](https://www.first.org/epss/data)、[Using EPSS](https://www.first.org/epss/using-epss) | 2026-11-12 | documented。応答の形は verified（1 回） |
| 9 | Using artifact attestations、gh attestation verify | GitHub | 日付の表示なし | [docs.github.com](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)、[cli.github.com](https://cli.github.com/manual/gh_attestation_verify) | 2026-11-10 | documented |
| 10 | Build: Track Basics、Build: Requirements for producing artifacts | OpenSSF SLSA | v1.2 | [Track Basics](https://slsa.dev/spec/v1.2/build-track-basics)、[Requirements](https://slsa.dev/spec/v1.2/build-requirements) | 2026-11-12 | documented（読んだ節）。Isolation strength の詳細は open |
| 11 | MCP Security Crisis: Systemic Design Flaws in AI Agent Infrastructure | Cloud Security Alliance（CSAI Foundation） | 2026-05-04（研究ノート） | [PDF](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf) | 2026-11-10 | documented |
| 12 | AWS Well-Architected Framework（信頼性、運用上の優秀性、セキュリティの各柱のベストプラクティスのページ） | AWS | 2024-11-06（v13） | [welcome.html](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/welcome.html) と、ベストプラクティスの節に挙げた各ページ | 2026-11-13 | documented。版つきパス 2025-02-25 の意味は open |
| 13 | Resilience lifecycle framework: A continuous approach to resilience improvement | AWS Prescriptive Guidance | 2023-10-06（初版） | [docs.aws.amazon.com](https://docs.aws.amazon.com/prescriptive-guidance/latest/resilience-lifecycle-framework/introduction.html) | 2026-11-12 | documented |
| 14 | Well-architected best practices for software supply chain security | AWS Security Blog | 公開日の表示を取得できなかった | [aws.amazon.com](https://aws.amazon.com/blogs/security/well-architected-best-practices-for-software-supply-chain-security/) | 2026-11-10 | documented（ブログの記述）。公開日は open |
| 15 | OpenSSF Malicious Packages | OpenSSF（Securing Critical Projects Working Group） | 参照日時点の README | [GitHub](https://github.com/ossf/malicious-packages) | 2026-11-10 | documented |
| 16 | What is AWS Well-Architected? | AWS | 2026-10-01（Last updated） | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/userguide/well-architected.html) | 2026-11-10 | documented |
| 17 | 【開催報告】ランサムウェアに備える「防御」「復旧」「説明責任」— AI エージェント時代に見直す対策と次の一歩 | AWS（Amazon Web Services ブログ、日本語） | イベント開催日 2026-10-26、記事の公開日 2026-11-10 | [aws.amazon.com](https://aws.amazon.com/jp/blogs/news/ransomware-security-seminar-oct-2026/) | 2026-11-12 | documented（イベントで話された事実として） |
| 18 | ランサムウェア被害から医療データの安全を守る | AWS（Amazon Web Services ブログ、日本語） | 2023-11-14 | [aws.amazon.com](https://aws.amazon.com/jp/blogs/news/safeguard-healthcare-data-from-ransomware/) | 2026-11-12 | documented（記事に書かれた事実として） |
| 19 | 情報セキュリティ10大脅威 2026 | IPA（情報処理推進機構） | 公開 2026-01-29、最終更新 2026-05-21 | [ipa.go.jp](https://www.ipa.go.jp/security/10threats/10threats2026.html) | 2026-11-12 | documented（組織向けの順位の表と選定の方法）。公式の英語版は見つけていない（open） |
| 20 | AI 性能の高度化を踏まえたサイバーセキュリティ対策の強化について～Project YATA-Shield～ | 内閣官房 国家サイバー統括室ほか関係府省庁 | 2026-05-18 | [PDF](https://www.cyber.go.jp/pdf/press/20260518_AI_CS_Package.pdf) | 2026-11-12 | documented |
| 21 | ★3・★4要求事項・評価基準（Ver.1.1:2026年10月28日） | 経済産業省 | Ver 1.1、2026-10-28 | [xlsx](https://www.meti.go.jp/policy/netsecurity/docs/scs/SCS-400-criteria-v1.1.xlsx) | 2026-11-12 | documented |
| 22 | 政府機関等の対策基準策定のためのガイドライン（令和７年度版） 第３部～付録 | 国家サイバー統括室 | 令和７年度版。令和 8 年 6 月 12 日の一部改定を反映 | [PDF](https://www.cyber.go.jp/pdf/policy/general/guider8_6_02.pdf) | 2026-11-12 | documented（7.2.1） |
| 23 | 金融分野におけるサイバーセキュリティに関するガイドライン | 金融庁 | 令和 6 年 10 月 4 日 | [PDF](https://www.fsa.go.jp/news/r6/sonota/20241004/18.pdf)、[英訳（仮訳）](https://www.fsa.go.jp/common/law/cybersecurity_guideline_en.pdf) | 2026-11-12 | documented（2.2.3 と、2.2.1 の 2 つ目の細目） |
| 24 | 「フロンティア AI による脅威変化を踏まえた金融機関等の短期的な対応」に係る要請について | 金融庁、日本銀行 | 令和 8 年 5 月 22 日 | [PDF](https://www.fsa.go.jp/news/r7/sonota/20260522-5/01.pdf) | 2026-11-12 | documented（脚注 4） |
| 25 | Regulation (EU) 2024/2847 (Cyber Resilience Act) | European Parliament、Council of the European Union | OJ L, 2024/2847, 20.11.2024 | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) | 2026-11-12 | documented（Article 14、71、Annex I Part II） |
| 26 | Cyber recovery on AWS: A reference approach for recovering from ransomware and destructive events | AWS Architecture Blog | 公開 2026-05-20、更新 2026-10-22 | [aws.amazon.com](https://aws.amazon.com/blogs/architecture/cyber-resilience-on-aws-a-reference-approach-for-recovery-from-ransomware-and-destructive-events/) | 2026-11-12 | documented |
| 27 | Planning a NIST-aligned ransomware recovery strategy on AWS、Building isolated, immutable backups for ransomware recovery on AWS、Test backups and restore critical workloads after ransomware on AWS | AWS（AWS re:Post。AWS Support による 3 回のシリーズ） | 2026-10-15 | [第 1 回](https://repost.aws/articles/ARatcO81HOTyCDYQbX5h30pg/planning-a-nist-aligned-ransomware-recovery-strategy-on-aws)、[第 2 回](https://repost.aws/articles/AR9O5kMiZdRL2CBrdXqUI38g/building-isolated-immutable-backups-for-ransomware-recovery-on-aws)、[第 3 回](https://repost.aws/articles/ARU6N19cQrQi66Oj-RiasMPQ/test-backups-and-restore-critical-workloads-after-ransomware-on-aws) | 2026-11-12 | documented |
| 28 | 令和７年におけるサイバー空間をめぐる脅威の情勢等について | 警察庁 | 令和 8 年 3 月 | [PDF](https://www.npa.go.jp/publications/statistics/cybersecurity/data/R7/R07_cyber_jousei.pdf) | 2026-11-12 | documented（ランサムウェア被害報告件数のグラフ） |
| 29 | Configuring S3 Object Lock、Locking objects with Object Lock、AWS Backup Vault Lock、Recover deleted EBS volumes, EBS snapshots, and EBS-backed AMIs with Recycle Bin、How SnapLock works | AWS | 日付の表示なし | [S3 設定](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html)、[S3 概要](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)、[Backup Vault Lock](https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html)、[EBS ごみ箱](https://docs.aws.amazon.com/ebs/latest/userguide/recycle-bin.html)、[SnapLock](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock.html) | 2026-11-12 | documented |
| 30 | Cyber Essentials: Requirements for IT Infrastructure v3.3 | NCSC（UK National Cyber Security Centre） | v3.3、2026 年 4 月 | [ncsc.gov.uk](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf) | 2026-11-13 | documented（Security Update Management の節） |
| 31 | BOD 26-04: Prioritizing Security Updates Based on Risk | CISA | 2026-06-10 | [cisa.gov](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) | 2026-11-13 | documented（Table 1 は画像で、2026-11-12 に画像を見て読んだ） |

[3] は 6.2（SBOM の保管）と第 7 章（脆弱性管理の手順）に限って引く。[17] と [18] は実務者の議論の出典で、仕様や指針の出典にしない。

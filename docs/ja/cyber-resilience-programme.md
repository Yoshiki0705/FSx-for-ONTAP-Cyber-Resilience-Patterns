# サイバーレジリエンス プログラム

> **概要**: ソフトウェアサプライチェーンの可視化と対応、RTO/RPO と SLA/SLO/SLI、フォレンジックの 3 本の柱を 1 か所にまとめ、着手の順序、PDCA での役割分担、説明責任の観点を示す。第 1 の柱は着手済みで、第 2 と第 3 の柱は仕様が未作成である。

## この文書の目的

3 本の柱の全体方針を 1 か所に置き、各柱の仕様の位置づけと順序を取り違えないようにする。柱ごとの手順は、それぞれの仕様と文書が持つ。第 1 の柱の導入手順は Adoption_Guide（`supply-chain-adoption-guide.md`。[ja](supply-chain-adoption-guide.md)）にある。

この文書が引く指針は、すべてガバナンス上の指針である。法務、コンプライアンス、規制上の判断ではない。サービスレベルの契約上の約束は Service_Owner 自身が決めることで、このプロジェクトは法務・契約上の判断を示さない。

この文書で使う用語は次のとおり。

- Service_Owner: エンドユーザーにサービスを提供し、SLA/SLO/SLI と RTO/RPO を設定する側（パートナー / SI、システム担当、アプリ担当など）
- Vendor_SLA: AWS や NetApp が自社サービスについて公開する SLA
- Response_Target: 脆弱性の検出と修正にかかる時間の目標値。運用で実測するまで SLO とは呼ばない
- Policy_File: しきい値、Cooldown の値、Response_Target などを持つ機械可読の JSON ファイル（`docs/agent/supply-chain-policy.json`）
- Cooldown: 新しいリリースが公開されてから更新 PR を作るまでの最小経過時間
- Aggregator: 対象リポジトリの SBOM を脆弱性情報と突き合わせ、しきい値を超えた所見を Issue にする定期ジョブ

根拠の種別は 4 語で示す。`documented` は出典の該当箇所を読んだもの、`verified` は 1 回以上実測したもの、`hypothesis` はこのプロジェクトの解釈、`open` は確認できていないものである。

## 背景となる傾向

次の 2 つの傾向を、読んだ資料が自ら述べている範囲で書く。どちらも [framework mapping の「想定する脅威の類型」](cyber-resilience-framework-mapping.md#想定する脅威の類型2026-10-時点)との文言の突き合わせを終えていないので、根拠の種別は `hypothesis` とする。事件名、企業名、事業者名は書かない。NIST CSF 2.0 との対応は framework mapping にあり、この文書には写さない（[NIST CSF 2.0 機能カバレッジ](cyber-resilience-framework-mapping.md#nist-csf-20-機能カバレッジ)）。

| 傾向 | 資料の書き方 | 出典 | 根拠の種別 |
|---|---|---|---|
| サプライチェーンや委託先を狙った攻撃 | IPA の「情報セキュリティ 10 大脅威 2026」は、組織向けの 2 位に挙げ、8 年連続の選出とする。順位は選考会の審議と投票で決まり、発生件数の統計ではない。警察庁の統計はランサムウェアの被害報告件数を令和 4〜7 年に 197〜230 件と示し、「依然として高水準」と書く。サプライチェーン経由の侵害の件数を示す統計は、読んだ範囲になかった | [19]、[28] | hypothesis |
| 公開から悪用までの時間の短縮 | 関係府省庁の Project YATA-Shield は、AI の性能向上で脆弱性の発見と修正が速くなる一方、攻撃もより高速かつ大規模になりうると書く。時間の推移を数値で示す資料は、読んだ範囲になかった。実務者の議論としては、開催報告が AI による脆弱性発見の加速を挙げる | [20]、[17] | hypothesis |

## 3 本の柱

| 柱 | 目的 | 範囲 | 対応する spec | 状態 |
|---|---|---|---|---|
| 第 1: ソフトウェアサプライチェーンの可視化と対応 | 使っている構成要素を把握し、脆弱性と悪意のあるパッケージへの対応を、目標時間つきで回す | 対象リポジトリの SBOM、Aggregator による Issue 化、Renovate による更新、VEX、来歴証明、ONTAP の[アップグレード手順](../ontap-native/ontap-upgrade-for-security-advisories.md)。SBOM の最小要素は [1]、[2] を、保管と脆弱性管理の手順は [3] の 6.2 と第 7 章を参照する | `cyber-resilience-phase4-supply-chain` | 着手済み |
| 第 2: RTO/RPO と SLA/SLO/SLI | Service_Owner が復旧時間と復旧点の目標を定め、満たせているかを測る | 目標の設定方法、参照構成（Snapshot、SnapMirror、AWS Backup などの組み合わせ）、リストア訓練 | 未作成 | 未着手 |
| 第 3: フォレンジック | 侵害のあとに、何が起きたかを再構成できる証跡を残す | 証跡の取得手順、インシデント後のレビュー | 未作成 | 未着手 |

第 1 の柱が参照する資料は次のとおり。

- ビルドの来歴証明は、GitHub の artifact attestations の手順 [9] と、SLSA の Build トラック [10] を参照する
- 悪意のあるパッケージは、OpenSSF の Malicious Packages（OSV 形式、`MAL-` の識別子）を参照する [15]
- AI エージェントのツール定義は、使用中の MCP サーバーの棚卸しと、版の固定および定義変更の検知を勧める研究ノート [11] を参照する。この文書は AI の支援で作られ、CSA の正式なレビューを経ていないと自ら書く
- AWS の実践として、SBOM、版の固定、悪意のあるパッケージの扱いを述べたブログ [14] を参照する。仕様ではなくガイダンスである

## 着手の順序

1. 第 1 の柱。他の柱の完了を待たない。
2. 第 2 の柱。第 1 の柱の版の固定と来歴証明を、クリーンな作り直しの入力に使えるが、第 1 の柱の完了を着手の条件にはしない。
3. 第 3 の柱。他の柱の完了を待たない。

第 2 の柱と第 3 の柱は、受け渡しの項目を共有する。第 3 の柱から第 2 の柱へ渡すのは、どの復旧点に戻すかを判断した記録である。復旧点を決める時間を RTO に含めるかは、第 2 の柱が決める。どちらも他方の完了を前提にせず、先に着手する柱が受け渡しの形を定義する。

## サービスレベルの考え方

SLA/SLO/SLI と RTO/RPO は、Service_Owner がエンドユーザーに向けて設定する値である。Vendor_SLA ではない。定義の節は Resilience lifecycle framework の Stage 1 にある [13]。

Vendor_SLA は、Service_Owner の SLO を決める入力の 1 つである。SLO は、Vendor_SLA の対象外であるアプリケーション、運用、復旧手順も含めて考える。Vendor_SLA の数値はこの文書に書かない。使うときは、ベンダーが公開する SLA のページから、参照日を添えて引く。

金融庁と日本銀行の要請の脚注は、SLA を金融機関等とベンダーの間のサービス品質保証の契約の意味で使い、SLO を SLA を達成するための組織内部の目標と書く [24]。この SLA の用法は、この文書の Vendor_SLA に当たる。同じ脚注の SLO は、Service_Owner の SLO に近い（解釈）。

サイバーリカバリと DR の区別は、この文書では定義しない。第 2 の柱の spec で定義する。この区別とリストア訓練を扱う実務者向けの資料として [26]、[27] がある。

## PDCA サイクル

3 本の柱は、Plan、Do、Check、Act の繰り返しとして合わさる。第 2 と第 3 の柱の欄は、仕様がない現時点では方針の記述にとどめる。

| 段階 | 第 1 の柱 | 第 2 の柱 | 第 3 の柱 | 柱の間のつながり |
|---|---|---|---|---|
| Plan | Response_Target の参照値、Cooldown（Renovate の `minimumReleaseAge` [5]）、Issue を起票するしきい値を、Service_Owner が決める | SLO/RTO/RPO の設定方法（データ保護と復旧時間を含む可用性） | フォレンジックで残す証跡の範囲 | 第 3 の柱が決める証跡の範囲は、第 2 の柱の復旧点の判断の入力になる |
| Do | Renovate の設定、再利用可能ワークフロー、Aggregator の導入。版の固定と来歴証明は、クリーンな作り直し（第 2 の柱）の入力になる | 参照構成（Snapshot、SnapMirror、AWS Backup などを組み合わせた構成） | 証跡の取得手順 | 第 1 の柱の版の固定と来歴証明が、第 2 の柱の作り直しの入力になる |
| Check | Response_Target に対する実績（期限超過の件数、検出の実績）と CI/CD の記録 | SLI の測定、リストア訓練の結果（確認点と所要時間） | インシデント後のレビュー（記録の範囲） | 第 1 の柱の実行結果とリストア訓練の結果は、説明責任の記録になる（次の節） |
| Act | Response_Target と Cooldown の見直し | SLO と構成の見直し | Act に渡すフォレンジックの証跡と再発防止 | 第 3 の柱の証跡と再発防止が、第 2 の柱の復旧点の判断と第 1 の柱の目標の見直しに渡る |

PDCA の 4 段階と説明責任の観点の NIST CSF 2.0 への対応は、framework mapping の[PDCA と説明責任の CSF 2.0 への対応](cyber-resilience-framework-mapping.md#pdca-と説明責任の-csf-20-への対応)にある。表はそこにだけ置き、この文書には写さない。解釈による対応で、NIST の認定ではない。

## 説明責任の観点

説明責任は、3 本の柱を横断する観点である。次の 3 つを残して説明できることを指す。

- 平時の保護設定とログの取得
- 侵害を検知したときの判断
- 復旧までの記録

「説明責任」と訳される Accountability は、RACI の A（最終責任者）の意味でも使われる。この文書では上の意味に限る。説明は、(1) 誰が責任を持つか（Service_Owner の組織が決める）、(2) 何を根拠に説明するか（記録の完全性と来歴）、(3) 誰に伝えるか（通知の要否は法務の担当が判断する。このプロジェクトは判断を示さない）に分けて考える。

説明責任は第 3 の柱だけに属さない。第 1 の柱の記録（SBOM、Issue、VEX、実行結果）と、第 2 の柱の復旧（復旧点の判断の記録）にまたがる。柱の数と順序（1→2→3）は変えない。説明責任は平時の記録から始まるので、復旧の前に置く。この並びは、防御、復旧、説明責任の 3 つの軸とそのつながりを述べた開催報告 [17] の並びに合わせた。

| 柱 | 説明責任に提供する記録 | 説明の中での使い道 |
|---|---|---|
| 第 1 | Aggregator の実行結果（起票、更新、クローズ、VEX による除外とその理由、Response_Target の実績）、VEX の判断と承認の記録（OpenVEX [6]）、SBOM、来歴証明 | その時点で何が入っていて、いつ気づき、いつ直したか。作り直した構成が元と同じであることの根拠 |
| 第 2（方針） | 復旧点の選定の理由と承認、復元の試験の結果と所要時間、RTO/RPO の目標と実績、受け入れたデータの損失の範囲 | どの時点に、なぜ戻したか。目標に対する実績はどうだったか |
| 第 3（方針） | アクセスの経路ごとと管理面ごとの証跡、時系列の再構成、監査の記録が欠けた期間の記録、事後のレビュー | 何が起きたか、入口はどこか、再発をどう防ぐか |

この節の弱点は、読者が 2 つの切り口（柱と説明責任）を対応づける必要があることである。第 2 と第 3 の柱の行は、仕様ができたときに見直す。ストレージの種類ごとの記録の違いは、[ストレージの種類ごとのデータ保護](#ストレージの種類ごとのデータ保護)の Hub の文書を参照する。

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

このプロジェクトの構成要素と AWS Well-Architected Framework のベストプラクティス ID の対応は、framework mapping の[ベストプラクティス ID との対応](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応)にある。表はそこにだけ置く。この文書は、柱ごとに実装する ID を 1 行に 1 つずつ挙げる。フレームワークの版は v13（2024-11-06）、参照日は 2026-11-13 である。各 ID の 2 つ目のリンクは、版つきのパス `2025-02-25` の同じページである。`2025-02-25` が何の版かは、文書から読み取れていない（`open`）[12]。

- 第 1 の柱: [SEC11-BP02](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_automate_testing_throughout_lifecycle.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_automate_testing_throughout_lifecycle.html)）
- 第 1 の柱: [SEC11-BP05](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html)）
- 第 1 の柱: [SEC11-BP06](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_deploy_software_programmatically.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_deploy_software_programmatically.html)）
- 第 1 の柱: [SEC11-BP07](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html)）
- 第 2 の柱: [REL13-BP01](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_objective_defined_recovery.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_objective_defined_recovery.html)）
- 第 2 の柱: [REL13-BP02](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_disaster_recovery.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_disaster_recovery.html)）
- 第 3 の柱: [SEC10-BP03](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_prepare_forensic.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_incident_response_prepare_forensic.html)）
- PDCA の Check: [OPS09-BP01](https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_operations_health_measure_ops_goals_kpis.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_measure_ops_goals_kpis.html)）
- PDCA の Check と Act: [OPS09-BP03](https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html)）
- PDCA の Act: [OPS11-BP02](https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_perform_rca_process.html)（[2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_evolve_ops_perform_rca_process.html)）

第 2 の柱が追加で扱うベストプラクティスは、その柱の仕様が範囲を決めたときに足す。10 件とも、2026-11-13 に全文を読み、framework mapping の表の記述と照合した。

この対応は、AWS Well-Architected のレビューの結果ではなく、AWS による承認でもない。Service_Owner は、自身のワークロードのレビューを [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/) で記録できる [16]。NIST CSF 2.0 への対応も、NIST による認定ではない。

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

このプロジェクトが公開する値（Response_Target と、後続の仕様で公開する参照用の SLO/RTO/RPO）は、利用者が自身の値に置き換えるための参照値である。どのエンドユーザーへの約束でもない。

Response_Target は目標で、運用で実測するまで SLO と呼ばない。値は Policy_File の `response_target` にあり、この文書は同じ値を示す。検出の目標は <!-- policy:response_target.detect_hours -->24 時間（起点から Issue の起票まで）。修正の目標は、KEV 掲載 [7] の脆弱性と悪意のあるパッケージが <!-- policy:response_target.fix_days_kev_or_malicious -->7 日、それ以外で CVSS の重大度が High 以上のものが <!-- policy:response_target.fix_days_high -->14 日である（Issue の起票からクローズまで。14 日は参照値で、パイロットで維持するか 30 日に戻すかを決める）。EPSS [8] のスコアは Issue に添える参考の値で、区分には使わない。

検出の目標の 24 時間は、当局への報告の期限ではない。EU の製品規則は、製造者が悪用中の脆弱性に気づいてから遅くとも 24 時間以内の早期警告を求める [4]、[25]。長さは同じでも、起点（気づいた時点か、アドバイザリや KEV の公開か）、行為（当局への報告か、Issue の起票か）、宛先が違う。Aggregator や Issue がその報告を満たすかは、この文書では判断しない。

### 公的な基準の修正期限

Service_Owner が参照値を自分の値に置き換えるときの比較の材料として、公開された基準の修正期限を要約する。各基準は自分の対象（企業、政府機関、金融機関、製品の製造者）に課すもので、このプロジェクトにも Service_Owner にも適用されない。どの値が正しいかの判断ではない。起点はこのプロジェクトの起票と同じではない。

| 基準の型 | 区分に使う情報 | 修正の日数 | 起点 | 出典 |
|---|---|---|---|---|
| このプロジェクトの Response_Target | KEV 掲載、悪意のあるパッケージ、CVSS の重大度 | 上の段落のとおり | Issue の起票 | Policy_File |
| 企業向けの評価制度（★3 の評価基準） | ベンダーが重大・高リスクとする脆弱性、CVSS の基本値 7.0 以上、レベルの記載がない更新 | 14 日。期限内にできない場合は、適用までのリスク低減策。制度は開始前（2026-10-28 のページは 2026 年度末頃の開始を目指すと書く） | アップデートのリリース | [21] |
| 認証制度の技術要件（英国） | 「critical」または「high risk」とされる脆弱性（CVSS v3 の基本値 7 以上、またはベンダーの区分） | 14 日 | リリース | [30] |
| 行政機関向けの指令（米国） | 公開の有無、KEV 掲載、攻撃者の自動化の可否、技術的な影響の 4 つの変数（CVSS は使わない） | 3 日、14 日、60 日、次のシステム更新時 | KEV への追加と、資産での特定の早い方 | [31] |
| 政府機関向けの基準 | 製品、セグメント、深刻度（CVSS など）を踏まえて、各機関が事前に定める適用基準 | 日数を定めない | 計画の実施予定時期 | [22] |
| 金融分野のガイドライン | システムの重要度、リスク、深刻度 | 日数を定めない。対応期限の設定と対応実績の管理を求める | 定めなし | [23] |
| EU の製品規則 | 悪用の信頼できる証拠がある脆弱性（報告の対象） | 修正は「遅滞なく」で、日数を定めない | 製造者が気づいた時点 | [25] |

企業向けの評価制度の 14 日は起点がリリースで、Response_Target の 14 日は起点が Issue の起票である。Issue の起票はリリースより後なので、同じ起点で比べると、Response_Target のほうが長い。期限の見直しの手順は、Adoption_Guide の「[実績を PDCA に使う方法](supply-chain-adoption-guide.md#実績を-pdca-に使う方法)」で扱う。

## ストレージの種類ごとのデータ保護

オンプレミスのストレージ、Amazon EBS、Amazon S3、Amazon EFS、FSx for ONTAP とその他の Amazon FSx では、データ保護の手段と制約が違う。この違いは、第 2 の柱が復旧点を選ぶ入力であり、第 3 の柱が証跡を残す範囲の入力でもある。比較は Hub に既にあるので、この文書は表も記述も写さず、リンクだけを置く。

- [ファイルストレージの選択肢の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/file-storage-options.md)
- [データ保護方式の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md)
- [Amazon FSx for NetApp ONTAP の Snapshot だけで復旧できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/snapshots-are-not-a-recovery-plan.md)
- [Amazon FSx for NetApp ONTAP のバックアップコピーだけで復旧できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md)
- [Amazon FSx for NetApp ONTAP の SnapLock は有効化だけで保護できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/snaplock-and-layered-ransomware-readiness.md)
- [第三者バックアップ製品は Amazon FSx for NetApp ONTAP にどの経路で届くか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/third-party-backup-reaches-it-by-another-route.md)
- [EBS が安くなくなる境目は台数か？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/block-storage/notes/when-ebs-stops-being-the-cheaper-answer.md)

比較の内容が足りない場合は、この文書に書かず、Hub への依頼か、第 2 または第 3 の柱の仕様に送る。

## 参考文献

番号は本文の `[n]` に対応する。名称は発行主体が付けた原題で書く。参照日は、その URL の内容を確かめた日である。根拠の種別の `open` は、確認できていない部分を示す。

| 番号 | 名称 | 発行主体 | 公開日・版 | URL | 参照日 | 根拠の種別 |
|---|---|---|---|---|---|---|
| 1 | 2026 Minimum Elements for a Software Bill of Materials (SBOM) | CISA ほか 17 機関（METI、NCO を含む） | 2026-07-29、版 2.1 | [PDF](https://www.cisa.gov/sites/default/files/2026-07/2026_cisa_sbom_minimum_elements_508c.pdf) | 2026-11-10 | documented |
| 2 | サイバーセキュリティのためのソフトウェア部品表（SBOM）の最小要素に関する国際ガイダンスに共同署名しました | 経済産業省 | 2026-07-30 | [meti.go.jp](https://www.meti.go.jp/press/2026/07/20260730001.html) | 2026-11-10 | documented |
| 3 | ソフトウェア管理に向けたSBOM（Software Bill of Materials）の導入に関する手引ver2.0 | 経済産業省 | 2024-08-29、ver 2.0 | [meti.go.jp](https://www.meti.go.jp/press/2024/08/20240829001/20240829001.html) | 2026-11-12 | documented（6.2 と第 7 章）。他の節は open |
| 4 | Cyber Resilience Act - Reporting obligations | European Commission | 日付の表示なし | [digital-strategy.ec.europa.eu](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | 2026-11-12 | documented |
| 5 | Minimum Release Age | Renovate | 日付の表示なし | [docs.renovatebot.com](https://docs.renovatebot.com/key-concepts/minimum-release-age/) | 2026-11-10 | documented |
| 6 | OpenVEX Specification v0.2.0 | OpenVEX | v0.2.0 | [GitHub](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | 2026-11-10 | documented |
| 7 | Known Exploited Vulnerabilities Catalog | CISA | catalogVersion 2026.11.09 | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 2026-11-10 | verified（取得 1 回） |
| 8 | GET /epss (FIRST.Org REST API Documentation)、EPSS Data (Get the Data)、Using EPSS | FIRST（EPSS SIG） | 日付の表示なし。API は BETA と表示 | [API](https://api.first.org/epss/)、[Data](https://www.first.org/epss/data)、[Using EPSS](https://www.first.org/epss/using-epss) | 2026-11-12 | documented。応答の形は verified（1 回） |
| 9 | Using artifact attestations、gh attestation verify | GitHub | 日付の表示なし | [docs.github.com](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)、[cli.github.com](https://cli.github.com/manual/gh_attestation_verify) | 2026-11-10 | documented |
| 10 | Build: Track Basics、Build: Requirements for producing artifacts | OpenSSF SLSA | v1.2 | [Track Basics](https://slsa.dev/spec/v1.2/build-track-basics)、[Requirements](https://slsa.dev/spec/v1.2/build-requirements) | 2026-11-12 | documented（読んだ節）。Isolation strength の詳細は open |
| 11 | MCP Security Crisis: Systemic Design Flaws in AI Agent Infrastructure | Cloud Security Alliance（CSAI Foundation） | 2026-05-04（研究ノート） | [PDF](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf) | 2026-11-10 | documented |
| 12 | AWS Well-Architected Framework（信頼性、運用上の優秀性、セキュリティの各柱のベストプラクティスのページ） | AWS | 2024-11-06（v13） | [welcome.html](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html) と、ベストプラクティスの節に挙げた各ページ | 2026-11-13 | documented。版つきパス 2025-02-25 の意味は open |
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

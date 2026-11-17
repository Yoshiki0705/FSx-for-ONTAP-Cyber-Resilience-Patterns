# サプライチェーン管理のユースケースと選択肢（ストレージを含む構成）

> **概要**
>
> ONTAP または Amazon FSx for NetApp ONTAP（以降 FSx for ONTAP）を使う組織が、ストレージを含むシステム全体のソフトウェアサプライチェーンを管理するときの使い方と選択肢を、11 のユースケース（A1 から D1）に分けてまとめる。AWS サービス、SaaS、標準の選択肢は、向く場面とトレードオフを同じ粒度で並べ、順位は付けない。価格は書かない。調査と確認の日は 2026-11-17（日本時間）である。

全体の位置づけと、データを FSx for ONTAP に置く理由は、[サイバーレジリエンス プログラム](cyber-resilience-programme.md#fsx-for-ontap-を全体システムの実装パターンに置く理由)にある。

## この文書で分かること

この文書で判断できるのは、自分の環境（オンプレミスの ONTAP、新規の FSx for ONTAP、既存の FSx for ONTAP）で、サプライチェーン管理のどの部分をこのリポジトリの仕組みで行い、どの部分を AWS サービスや SaaS で補うかである。手順と数値の正本は[サプライチェーン導入ガイド](supply-chain-adoption-guide.md)とポリシーファイル（[`supply-chain-policy.json`](../agent/supply-chain-policy.json)）にあり、この文書には写さない。ここには、状況ごとの使い方と選択肢の対応だけを書く。

この文書で扱わないものは次のとおり。

- ONTAP 自身の機能（ARP、FPolicy、SnapLock）の設定。既存の文書へのリンクだけを置く
- 価格
- 拠点やゲートウェイ側のファームウェアとデバイスの依存。ONTAP の上と横にあるコードだけを対象にする
- 規制や法令への適合の判断。ガバナンスの指針であって、法務やコンプライアンスの判断ではない
- 第 2 の柱と第 3 の柱（[3 本の柱の全体方針](cyber-resilience-programme.md)）

各ユースケースの冒頭に、判断する人と終わりの条件を役割名で書く。このリポジトリの仕組みを使う場合の目安であり、自分の組織の役割分担に読み替える。

読み方は、自分の状況に近い行から入る。

| 状況 | 読む節 |
|---|---|
| オンプレミスの ONTAP の版とアドバイザリを照合し、更新を計画したい | A1、A2 |
| ONTAP の上や横で動く自分のコードの依存を管理したい | A3、B2、C2 |
| ランサムウェア対策と脆弱性管理をつなぎたい | A4 |
| FSx for ONTAP を新しく作る、または既に使っている | B1 から B3、C1 から C3 |
| 検出結果を SIEM やチケットに集めたい | D1 |

各ユースケースの表には、根拠と確度の列がある。確度は次の 4 区分で書く。

| 区分 | 意味 |
|---|---|
| 公式文書に記載 | ベンダーや標準化団体の文書の該当箇所を読んだ |
| 抜粋のみ | 検索結果の抜粋までを読み、本文は読んでいない |
| 推測 | 読んだ事実からの、このプロジェクトの推論。ベンダーは述べていない |
| 未確認 | 読めなかった、または記載が見つからなかった。記載が見つからなかったことは、ないことの証明ではない |

根拠の `[R01]` などは、末尾の[参考文献](#参考文献)の番号である。

このリポジトリ自身の動作を述べる行は、確度の区分の代わりに、根拠にした導入ガイドの節へのリンクを書く。1 つの行に複数の区分が当てはまるときは、「区分（対象）」の形で、対象ごとに 4 区分のどれか 1 つを書く。

## ストレージを含むサプライチェーンの 3 層

管理の道具は、層ごとに違う。

| 層 | 含まれるもの | 版を更新する主体 | 管理の入口 |
|---|---|---|---|
| ONTAP 自身 | NetApp が出荷する ONTAP のソフトウェア | オンプレミスは利用者。FSx for ONTAP では AWS がパッチを適用し、利用者はメンテナンスウィンドウの時刻を選ぶ [R07] | NetApp のセキュリティアドバイザリ、Digital Advisor、AWS のメンテナンスウィンドウ |
| ONTAP の上や横の利用者のコード | Lambda、コンテナ、IaC、ONTAP REST クライアント、運用スクリプト | 利用者 | 依存関係グラフ、SBOM、Dependabot と Renovate、Amazon Inspector |
| 開発の流れ | リポジトリ、CI、配布物 | 利用者 | ブランチとタグのルールセット、署名、来歴証明、immutable releases |

このリポジトリの第 1 の柱の仕組みは、主に 2 層目と 3 層目を対象にする。1 層目は、構成要素の一覧（ファイル名は [`infrastructure-component-ledger.json`](../agent/infrastructure-component-ledger.json)）と手順書を使った人の照合である（A1、A2、B1）。

## ユースケースの一覧

| ID | 想定する状況 | 管理の対象 |
|---|---|---|
| A1 | オンプレミスの ONTAP で、運用中の版と NetApp のセキュリティアドバイザリを照合する | ONTAP の版、アドバイザリの CVE |
| A2 | オンプレミスの ONTAP の更新（パッチ版、メジャー版）を計画し、実行する | ONTAP の版、更新の事前検査 |
| A3 | ONTAP の上や横で動く自分のアプリ、スクリプト、コンテナの依存を管理する | 依存パッケージ、コンテナイメージ、IaC |
| A4 | ランサムウェア対策（ARP など）と脆弱性管理をつなぐ | 悪用が確認された脆弱性の一覧と、保護機能の状態 |
| B1 | FSx for ONTAP を新規に作るとき、AWS の管理範囲と自分の範囲を分ける | メンテナンスウィンドウ、ONTAP の版の確認 |
| B2 | FSx for ONTAP の横で動く Lambda、コンテナ、IaC の依存を最初から管理する | 依存、SBOM、スキャン |
| B3 | 変更の来歴と配備の安全装置を最初から入れる | 署名、来歴の証明、段階的な配備 |
| C1 | オンプレミスから移った既存の運用で、A1 と A2 の手順を FSx for ONTAP 向けに置き換える | 照合と更新の手順 |
| C2 | 既に動いている ONTAP REST クライアントや運用スクリプトの依存を棚卸しする | 既存コードの依存、SBOM の後付け |
| C3 | 移行期間中に、オンプレミスと FSx for ONTAP の両方を見る | 2 つの管理面の併存 |
| D1 | 検出結果を 1 か所（SIEM、チケット）に集める | 検出結果の形式と配送経路 |

## オンプレミスの ONTAP（A1 から A4）

### A1 運用中の版とセキュリティアドバイザリの照合

判断する人: ストレージ管理者。終わりの条件: 運用中の全クラスタの版が[構成要素の一覧](../agent/infrastructure-component-ledger.json)にあり、各行に照合日が入り、判定が「判定保留」以外になっている。

向く状況は、ONTAP を自分で運用していて、運用中の版が NetApp のセキュリティアドバイザリの対象かを確かめたい場合である。NetApp は、検証した脆弱性を CVE ID つきの助言として公開する。助言はキーワード、製品、重大度で絞り込め、RSS 2.0 で購読できる [R01][R02]。

このリポジトリでは、版を[構成要素の一覧](../agent/infrastructure-component-ledger.json)に人が記録し、助言の RSS と照合する。確定は人が行い、照合日から 90 日を超えた行が再照合の対象になる（[棚卸し](supply-chain-adoption-guide.md#棚卸し)の手順 6）。アドバイザリへの対応としてのバージョンアップは、[ONTAP バージョンアップ手順](../ontap-native/ontap-upgrade-for-security-advisories.md)にある。

| 選択肢 | 向く場面 | トレードオフ | 根拠と確度 |
|---|---|---|---|
| 助言の一覧と RSS を人が見る | 台数が少ない。閉域でテレメトリを送れない | 自分の版との突き合わせが手作業になる | 公式文書に記載 [R01][R02] |
| Digital Advisor | AutoSupport を NetApp に送っていて、サポート契約がある | AutoSupport の送信とサポート資格が前提になる | 公式文書に記載 [R03] |
| ONTAP System Manager のリスク表示 | 日常の管理画面で見たい | Digital Advisor と同じ情報源に依存する | 抜粋のみ [R04] |
| NetApp の SBOM と VEX | ONTAP の構成要素を機械可読に突き合わせたい | 確認した範囲に提供の記載が見つからなかった。提供の有無は確かめていない | 未確認 [R02] |

### A2 ONTAP の更新の計画と実行

判断する人: ストレージ管理者と、変更の承認者。終わりの条件: 更新後の版が一覧に記録され、事前検査の結果が残り、更新後の版でアドバイザリを再照合している。

向く状況は、アドバイザリへの対応や、サポート期間の終わりに合わせて、ONTAP の版を上げる場合である。NetApp は、パッチ版のうち重大でないものを 3 から 6 か月ごとに、重大なものをできるだけ早く適用するよう案内している。新しい版の完全サポートは 3 年で、脆弱性の通知は完全サポートの期間に含まれる [R05]。NetApp の文書にあるサポート水準の表は、表の見た目ではなく平文から列の対応を読み取ったので、期間の対応は推測である。更新の実行には、自動化された無停止アップグレード（ANDU）を使うよう、NetApp は案内している [R06]。

このリポジトリには、計画の段階で使う手順を [ONTAP バージョンアップ手順](../ontap-native/ontap-upgrade-for-security-advisories.md)にまとめてある。FSx for ONTAP での扱いは C1 で述べる。

| 選択肢（準備の方法） | 向く場面 | トレードオフ | 根拠と確度 |
|---|---|---|---|
| Upgrade Advisor | Digital Advisor の有効な SupportEdge 契約があり、画面で進めたい。小さめの環境 | 契約とクラウド接続が前提になる | 公式文書に記載（向く場面）、推測（トレードオフ）[R06] |
| Upgrade Health Checker | 契約がない、閉域、自動化の基盤に組み込みたい。大規模で複雑な環境 | 結果の解釈を自分で行う | 公式文書に記載（向く場面）、推測（トレードオフ）[R06] |
| 手動の準備 | どの環境でも使える | 確認項目が多く、見落としを自分で防ぐ必要がある | 推測 [R06] |

### A3 ONTAP の上や横で動く自分のコードの依存の管理

判断する人: リポジトリの保守者。終わりの条件: 対象のリポジトリで依存の一覧が取れ、起票の条件を満たす所見の Issue に担当と期限が付き、公開直後の版を取り込まない待ち時間が設定されている。

向く状況は、ONTAP 自身の SBOM が手に入らない場合でも、自分で書いたコード（ONTAP REST クライアント、運用スクリプト、コンテナ、IaC）の依存を管理したい場合である。依存は利用者が管理できる（推測）。

このリポジトリでは、[棚卸し](supply-chain-adoption-guide.md#棚卸し)で依存の一覧を持ち、[検出と優先順位付け](supply-chain-adoption-guide.md#検出と優先順位付け)で Issue にし、[取り込み時の防御](supply-chain-adoption-guide.md#取り込み時の防御)で公開直後の版の取り込みを遅らせる。第 1 の柱の範囲では、Amazon Inspector と AWS Security Hub は有効にしない。

| 選択肢 | 向く場面 | トレードオフ | 根拠と確度 |
|---|---|---|---|
| GitHub の依存関係グラフと SBOM の書き出し | リポジトリ単位で依存を見たい | 依存関係グラフが有効で、対応するエコシステムに限られる。被依存は SBOM に含まれない | 公式文書に記載 [R21] |
| Dependabot と Renovate の Cooldown（公開直後の版を取り込まない待ち時間） | 公開直後の版を取り込みたくない | Cooldown の間は、修正版も取り込まれない。Dependabot の Cooldown はセキュリティ更新には適用されない。Renovate では、過去の日付のコミットを指す新しいタグが待ちを経ずに更新の対象になった観測が 1 回ある。第三者の Actions では、Cooldown を防御に数えない（[導入ガイド](supply-chain-adoption-guide.md#github-actions-の-cooldown-の限界)） | 公式文書に記載（仕様）[R22][R23] |
| Amazon Inspector の SBOM の書き出し | AWS 上の EC2、ECR、Lambda の依存を継続的に見たい。監査や取引先に SBOM を渡したい | 対象は AWS 上の資源に限られる。版の範囲指定や動的な参照がある依存は、名前と版ではなく、未解決のハッシュとして一覧に載る。SBOM には使っている部品と版が載るので、渡す相手と範囲を決める。取引先への受け渡しの形式と必須の項目は、取引先の要件に従う | 公式文書に記載（機能）[R11][R12]、推測（渡す範囲）|
| OpenSSF Malicious Packages（OSV 形式） | 脆弱性ではなく、意図的に悪意のある依存を検知したい | 登録の網羅性は分からない | 抜粋のみ [R27][R28] |

### A4 ランサムウェア対策と脆弱性管理の接続

判断する人: セキュリティ担当者とストレージ管理者。終わりの条件: 優先順位づけに使う入力が決まり、保護機能の設定の確認先（上のリンク）が決まっている。

向く状況は、ARP などの保護機能を入れていて、脆弱性管理をその外側につなげたい場合である。脆弱性管理は侵入の入口を減らす側、ARP などは侵入後の被害を減らす側で、役割が違う（推測）。ONTAP 自身の機能の設定は、既存の文書にある。

- [ARP の設定](../ontap-native/arp-configuration.md)
- [FPolicy の設定](../ontap-native/fpolicy-configuration.md)
- [SnapLock の設定](../ontap-native/snaplock-configuration.md)
- [Tamperproof Snapshot の設定](../ontap-native/tamperproof-snapshot.md)
- [サイバーレジリエンスのフレームワーク対応](cyber-resilience-framework-mapping.md)

脆弱性の優先順位づけに使える入力は、次の 4 つである。このリポジトリの起票の条件は、CVSS 重大度が High 以上、KEV に掲載、悪意のあるパッケージのどれかで、EPSS は表示だけに使う（[検出と優先順位付け](supply-chain-adoption-guide.md#検出と優先順位付け)）。

| 選択肢（入力） | 向く場面 | トレードオフ | 根拠と確度 |
|---|---|---|---|
| CISA KEV | 「いま悪用されているか」を優先順位に使いたい | ランサムウェアでの使用を示す欄が `Unknown` の項目が多く、決め手にできない。件数はカタログの版で変わる | 公式文書に記載 [R29] |
| FIRST EPSS | 悪用される見込みで順位をつけたい | 30 日以内の悪用の確率で、悪用の事実ではない。KEV や CVSS と併用する前提である | 公式文書に記載 [R30] |
| ベンダーの重大度（CVSS） | ベンダーの助言が付ける重大度で足りる | 悪用の証拠がある Medium 以下が後回しになる | 公式文書に記載（重大度の表示）、推測（後回しになること）[R01] |
| Amazon Inspector の脆弱性情報 | KEV の追加日と期限を、AWS 上の所見の画面で見たい | すべての CVE に情報があるわけではない。Inspector が有効な資源に限られる | 公式文書に記載 [R13] |

## FSx for ONTAP の新規の利用者（B1 から B3）

### B1 AWS の管理範囲と自分の範囲の分担

判断する人: AWS 側の操作権限を持つストレージ管理者。終わりの条件: メンテナンスウィンドウの時刻が決まり、適用日と適用後の版を一覧に記録する担当が決まっている。

向く状況は、FSx for ONTAP をこれから作り、版の更新を AWS に任せる部分と、利用者が行う部分を分けたい場合である。FSx for ONTAP では、AWS がファイルシステムの保守と更新を定期的に行う。HA ペアの一方ずつに適用し、適用の前にパートナーへフェイルオーバーするので、60 秒未満の I/O の停止がありうる。Single-AZ と Multi-AZ のどちらも、計画された保守のときに HA ペアがスタンバイへフェイルオーバーする。計画保守での挙動に両者の差はなく、AZ の障害によるフェイルオーバーは Multi-AZ だけが対象である [R33]。NFS と SMB のクライアントでは、AWS はフェイルオーバーを透過的と説明する。iSCSI と NVMe/TCP は、クライアント側のマルチパスの設定が前提になる [R33]。アプリケーション側の再試行とタイムアウトの設計は、この文書では扱わず、確かめていない。メンテナンスウィンドウの開始時刻は作成時に選び、後から変更できる。ウィンドウは 14 日に 1 回以上必要で、パッチが出てから 14 日以内にウィンドウがなければ、AWS が保守を進める [R07]。データの機微度、組織の要件、法令は、利用者の責任である [R09]。管理の入口は、AWS 側のツールと NetApp 側のツール（ONTAP CLI、REST API ほか）の両方が文書に並ぶ [R08]。

利用者の仕事は、「照合して更新を止める」から「適用の時刻を決め、適用後の版と助言を確認する」に移る（推測）。利用者が設定できるのは、メンテナンスウィンドウの開始時刻（`WeeklyMaintenanceStartTime`）である。ウィンドウは 14 日に 1 回以上必要で、その間にウィンドウがないとパッチは自動で適用される [R07]。ファイルシステムの作成と更新の API には ONTAP の版を指定する項目がなく、`DescribeFileSystems` の `OntapConfiguration` も版を返さない（読んだ API リファレンスの 3 ページ、2026-11-17）[R36][R37] [E-058]。版を知るには ONTAP REST の `GET /api/cluster` を読む [R35]。

このリポジトリでは、ONTAP の版と FSx for ONTAP のデプロイタイプを[構成要素の一覧](../agent/infrastructure-component-ledger.json)に記録する。[ONTAP バージョンアップ手順](../ontap-native/ontap-upgrade-for-security-advisories.md)はセルフマネージドの ONTAP を対象にしていて、FSx for ONTAP には当てはめない。

| 選択肢 | 向く場面 | トレードオフ | 根拠と確度 |
|---|---|---|---|
| メンテナンスウィンドウの設計 | 適用の時刻を、業務の谷に置きたい | 14 日の上限がある。適用ごとに 60 秒未満の I/O の停止がありうる。適用日と適用後の ONTAP の版を一覧に記録する運用は、AWS の文書にはない | 公式文書に記載（ウィンドウ、14 日、60 秒）[R07]、推測（適用前後の記録）|
| AWS Config | 構成の変更履歴を残し、逸脱を評価したい | 記録の対象はリソースの種別に左右される。FSx for ONTAP のどの設定が記録されるかは、確かめていない | 公式文書に記載（概要）、未確認（記録される設定の範囲）[R17] |
| AWS Security Bulletins | AWS のセキュリティ情報を購読したい | FSx for ONTAP に関する掲載の有無は、調べていない。RSS は直近 30 日分だけを保持する | 公式文書に記載（ページの説明）、未確認（FSx for ONTAP の掲載）[R10] |
| NetApp のセキュリティアドバイザリの RSS | 自分の環境が影響を受けるか、適用後に版が追いついたかを確かめたい | 版の確認方法を AWS が文書化しているかは、確かめていない。照合は人の手順になる | 推測（照合が人の手順になること）、未確認（AWS が版の確認方法を文書化しているか）[R01] |

### B2 Lambda、コンテナ、IaC の依存の最初からの管理

判断する人: リポジトリの保守者。終わりの条件: 依存が固定され、スキャンまたは SBOM の書き出しの経路が 1 つ以上動き、結果の受け手が決まっている。

向く状況は、FSx for ONTAP の横に Lambda、コンテナ、IaC を置くときに、依存の固定、スキャン、SBOM の書き出しを最初から入れたい場合である。検出の対象が少ない時点で始められる（推測）。

このリポジトリの仕組みは、[棚卸し](supply-chain-adoption-guide.md#棚卸し)と[取り込み時の防御](supply-chain-adoption-guide.md#取り込み時の防御)にある。Amazon Inspector と AWS Security Hub は、第 1 の柱では有効にせず、この文書では有効化の手順と費用を扱わない。使う場合は、有効化の前に、各サービスの料金ページで課金の単位と対象リソースの数を確かめる。

| 選択肢 | 向く場面 | トレードオフ | 根拠と確度 |
|---|---|---|---|
| Amazon Inspector | AWS 上で動く計算資源の依存を継続的に見たい | 初回の有効化で EC2、ECR、Lambda の標準スキャンが有効になる。Lambda コードスキャンと Code Security は別に有効にする。ECR の再スキャン期間の既定は 7 日で、2026-10-15 以降に ECR スキャンを有効にする場合に当てはまる。すでに有効なアカウントは現在の設定のままである | 公式文書に記載 [R11][R32] |
| AWS Security Hub の SBOM インベントリ | 複数のアカウントで、パッケージの所在を引きたい | 見えるのは Inspector が見る資源に限られる。反映に数時間かかりうる。AWS Security Hub CSPM とは別のサービスである | 公式文書に記載 [R15] |
| ノートブックやジョブの Python ライブラリ、事前学習済みモデルの取得元 | ストレージ上のデータを読む分析や AI の処理を持つ | 取得元の信頼と、ロックファイルによる固定は利用者の仕事になる。ライブラリはリポジトリの依存関係グラフで見える場合がある。モデルの重みが SBOM に載るかは確かめていない | 未確認 |
| AWS CodeArtifact のパッケージ起点の制御 | 内部のパッケージと公開のパッケージを併用している | パッケージに最初に追加された版の経路で既定値が決まる。例外のパッケージごとに設定を確かめる必要がある | 公式文書に記載 [R19] |
| GitHub の依存関係グラフと Renovate、Dependabot | リポジトリ単位で、依存の更新を PR にしたい | Cooldown の間は、修正版も待つ。セキュリティ更新は別の経路になる | 公式文書に記載 [R21][R22][R23] |

### B3 変更の来歴と配備の安全装置

判断する人: リポジトリの保守者。終わりの条件: 守る経路ごとに入れる機構が決まり、配布物を検証する側の手順がある。段階的な配備を入れる場合は、実デプロイでアラームによる巻き戻しを 1 回確かめるまでを含める。

向く状況は、署名、来歴の証明、段階的な配備を、最初から入れたい場合である。

このリポジトリでは、[来歴証明の検証](supply-chain-adoption-guide.md#来歴証明の検証)と[疎結合な更新](supply-chain-adoption-guide.md#疎結合な更新)に手順がある。Lambda のカナリアデプロイの参照実装は[テンプレート](../../templates/event-driven.yaml)にある。2026-11-17 に ap-northeast-1 で、テンプレートからカナリアに関わるリソース（関数、alias、デプロイ設定、アラーム、PreTraffic フック）を切り出してデプロイし、各 1 回確かめた。正常な更新では alias が 10% で 10 分間振り分けられたあと新版へ移った。実トラフィックでだけ失敗する版では、新版のエラーのアラームが ALARM になり、CodeDeploy が止まって alias が前の版へ戻った。このときテンプレートの `ExecutedVersion` の参照の書き方が SAM の変換で解決されずデプロイが失敗したので、書き方を直した。FailedRecords・Duration・Throttles の各アラーム単独での巻き戻し、PreTraffic フックの失敗、SQS 経由のトラフィックは試していない。

| 選択肢 | 向く場面 | トレードオフ | 根拠と確度 |
|---|---|---|---|
| AWS Signer | 署名済みでないコードを動かしたくない（Lambda のコードパッケージ、コンテナイメージ） | 署名鍵の管理と、署名できる人の設計が要る。署名は安全の証明ではなく、発行元と未改変の確認である | 公式文書に記載 [R18] |
| GitHub の artifact attestations | 配布物の出所を検証できるようにしたい | 検証しなければ意味がない。ソースとビルド手順への結びつけで、安全の保証ではない | 公式文書に記載 [R24] |
| GitHub の immutable releases | リリース成果物の差し替えを防ぎたい | 公開前にアセットをそろえる。ロックされるのはタグとアセットだけである | 公式文書に記載 [R25] |
| AWS SAM と CodeDeploy の段階的な配備 | 依存の更新を、本番に段階的に出したい | アラームの設計が不十分だと、巻き戻しが働かない。最初の配備は 2 段階になる | 公式文書に記載 [R20] |
| GitHub のルールセット | 変更の経路を統制したい | 組織全体のルールセットは GitHub Enterprise プランが対象である。重ねると、最も厳しいものが適用される | 公式文書に記載 [R26] |

## FSx for ONTAP の既存の利用者（C1 から C3）

### C1 オンプレミスの手順の FSx for ONTAP 向けの置き換え

判断する人: ストレージ管理者。終わりの条件: 一覧の各行が「自分で更新する」か「AWS が更新する」かに分かれ、照合の手順が置き換え後の形で書かれ、確かめていない行（事前検査、版の選択）の扱いが決まっている。

向く状況は、オンプレミスの ONTAP から FSx for ONTAP に移り、A1 と A2 の運用が残っている場合である。置き換えの考え方は次の表のとおりで、確かめていない行を含む。

| 手順 | オンプレミスの運用 | FSx for ONTAP での置き換え | 根拠と確度 |
|---|---|---|---|
| アドバイザリの照合 | 助言を見て、更新を計画する | 影響を受けるかと、適用後に版が追いついたかの確認に変わる | 推測 [R07] |
| 更新の計画と実行 | 版と時期を自分で決めて実行する | メンテナンスウィンドウの時刻の選択と、適用後の確認に変わる | 公式文書に記載（ウィンドウ）、推測（置き換え）[R07] |
| 更新前の事前検査 | Upgrade Advisor、Upgrade Health Checker | FSx for ONTAP で使えるかは、確かめていない | 未確認 [R06] |
| 現在の版の取得 | クラスターの管理インターフェースで版を読む | ONTAP REST の `GET /api/cluster` は `version` を返す。FSx for ONTAP の管理エンドポイントには VPC 内から `fsxadmin` で接続する | 公式文書に記載（`version` の項目）[R35]。FSx for ONTAP での読み取りは、本リポジトリの[スナップショット](../ontap-native/ontap-command-api-snapshot.md)に記録がある（1 台、SINGLE_AZ_1、ap-northeast-1、ONTAP 9.18.1P6、2026-11-04、1 回） |
| 版の選択 | 更新先の版を選ぶ | 利用者が選べるのはメンテナンスウィンドウの時刻で、作成と更新の API には版を指定する項目がない（読んだ API リファレンスの 3 ページ） | 公式文書に記載 [R07][R36][R37] |

### C2 既存の運用スクリプトと ONTAP REST クライアントの依存の棚卸し

判断する人: リポジトリの保守者。終わりの条件: 既存のスクリプトと ONTAP REST クライアントのすべてのリポジトリで依存の一覧が取れ、固定されていない依存の扱いが決まっている。

向く状況は、既に動いている運用スクリプトや ONTAP REST クライアントの依存を、後から棚卸しする場合である。固定されていない依存の洗い出しも含む。

このリポジトリでは、[棚卸し](supply-chain-adoption-guide.md#棚卸し)の手順と、[棚卸しの手段の使い分け](supply-chain-adoption-guide.md#棚卸しの手段の使い分け)に従う。

| 選択肢 | 向く場面 | トレードオフ | 根拠と確度 |
|---|---|---|---|
| GitHub の依存関係グラフと SBOM の書き出し | 既存のリポジトリに、SBOM を後から付けたい | 依存関係グラフが有効なリポジトリで、対応するエコシステムに限られる。形式は SPDX | 公式文書に記載 [R21] |
| Amazon Inspector の SBOM の書き出し | デプロイ済みの Lambda や ECR のイメージの構成を取りたい。固定されていない依存を洗い出したい | 固定されていない依存は「未解決のハッシュ」として一覧に載る。脆弱性の検出は、名前と版が分かる依存に対して行われる。形式は CycloneDX 1.4 と SPDX 2.3 互換 | 公式文書に記載 [R12] |
| AWS Security Hub の SBOM インベントリ | パッケージと版が、組織のどこに入っているかを引きたい | 応答の項目は名前、種類、版、件数で、リポジトリの SBOM の purl と直接は突き合わせられない [E-053]（導入ガイドの[棚卸しの手段の使い分け](supply-chain-adoption-guide.md#棚卸しの手段の使い分け)） | 公式文書に記載 [R15] |
| SBOM の生成ツール（Trivy、Syft と Grype、OSV-Scanner） | 生成ツールを自分で選びたい | ツールごとの制約は、導入ガイドの[SBOM 生成ツールの選び方](supply-chain-adoption-guide.md#sbom-生成ツールの選び方)にある | 導入ガイド（[SBOM 生成ツールの選び方](supply-chain-adoption-guide.md#sbom-生成ツールの選び方)） |

### C3 移行期間中のオンプレミスと FSx for ONTAP の併存

判断する人: ストレージ管理者。終わりの条件: 一覧の全行が更新の主体で分類され、移行が終わった行が一覧から外れている。

向く状況は、移行の途中で、オンプレミスの ONTAP と FSx for ONTAP の両方を見る必要がある場合である。移行の手段そのものは、この文書の対象外である。

このリポジトリでは、[構成要素の一覧](../agent/infrastructure-component-ledger.json)の行を、自分で更新するものと、AWS が更新するものに分けて記録する（推測）。

| 見る対象 | オンプレミスの ONTAP | FSx for ONTAP | 根拠と確度 |
|---|---|---|---|
| ONTAP の版の更新 | 利用者が実行する | AWS がメンテナンスウィンドウで適用する | 公式文書に記載 [R07] |
| アドバイザリの確認 | 版を照合して、更新を計画する | 影響の確認と、適用後の版の確認（C1） | 推測 [R01] |
| 管理の入口 | ONTAP CLI、REST API、System Manager など | AWS 側のツールと NetApp 側のツールの両方 | 公式文書に記載 [R08] |
| 一覧での区別 | 利用者が更新する行 | AWS が更新する行 | 推測 |
| ONTAP につなぐホストのゲスト OS と、移行や監視のエージェント | 利用者がパッチと版を管理する | 利用者がパッチと版を管理する。FSx for ONTAP のメンテナンスウィンドウとは別の経路になる | 推測 |

## 検出結果の集約（D1）

### D1 検出結果の SIEM やチケットへの集約

判断する人: セキュリティ担当者。終わりの条件: 検出結果の置き場が決まり、担当と期限が付く経路が 1 つ以上動いている。

向く状況は、検出結果を 1 か所に集め、担当と期限を決めて追いたい場合である。形式と配送の経路を決める。

このリポジトリの集約ジョブは、リポジトリごとの Issue に起票する（[検出と優先順位付け](supply-chain-adoption-guide.md#検出と優先順位付け)）。監査ログを SIEM に送る側は、[FSx for ONTAP Observability Integrations](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations) にある（[companion リポジトリとの連携](companion-repos-integration.md)）。

| 選択肢 | 向く場面 | トレードオフ | 根拠と確度 |
|---|---|---|---|
| Amazon EventBridge（Inspector のイベント） | 検出結果を、自前のチケットや通知に流したい | ルールとターゲットを自分で設計する。オンデマンドのマシンイメージスキャンの検出は、EventBridge にだけ出力され、コンソールにも Security Hub CSPM にも出ない | 公式文書に記載 [R14] |
| AWS Security Hub と AWS Security Hub CSPM | 複数のアカウントの検出を一覧したい | 2 つは別のサービスである。CSPM は AWS の設定が基準に合うかの確認が主で、ソフトウェアの依存の脆弱性管理が主目的ではない | 公式文書に記載 [R15][R16] |
| GitHub の Issue（このリポジトリの集約ジョブ） | リポジトリごとに担当を決めて追いたい | 起票の対象は集約ジョブの条件を満たす所見である。アカウントとリソース単位の Inspector の所見は含まない。機械可読な出力は Issue 本文に限られ、分析基盤へ流すには別の出力が要る | 導入ガイド（[検出と優先順位付け](supply-chain-adoption-guide.md#検出と優先順位付け)） |
| Issue の所見を AWS Security Hub CSPM へ取り込む | 検出の一覧を AWS 側の 1 か所に置いている | AWS Security Finding Format への変換と、送信の実装と運用が要る。新しい AWS Security Hub（OCSF 形式の所見）へ同じように取り込めるかは確かめていない | 公式文書に記載（CSPM が独自製品の所見を API で受け取ること）[R34]、未確認（新しい Security Hub への取り込み）|
| OSV と OpenVEX の形式 | 複数のエコシステムの脆弱性を 1 つの形式で扱い、影響の有無を下流に伝えたい | 発行する側の運用が要る。NetApp が VEX を出しているかは、確かめていない | 公式文書に記載 [R27][R31] |
| SIEM 製品（Splunk、Datadog など） | すでに SIEM に検出を集めている | 各製品の取り込みの方法は、一次の文書を読んでいない | 未確認 |

## 選び方

選択肢に順位は付けていない。次の順で、自分の環境に合うものを選ぶ。2 つ以上に当てはまれば併用する。

1. 管理したい対象が、3 層のどれかを決める。
2. ONTAP 自身は、版を自分で更新するか（オンプレミス、A）、AWS が適用するか（FSx for ONTAP、B と C）で、入口が分かれる。
3. 利用者のコードは、リポジトリで見るか（GitHub、Renovate、Dependabot）、AWS 上のリソースで見るか（Inspector、Security Hub）を決める。
4. 配布物は、守りたい経路に合わせて、署名、来歴の証明、段階的な配備のどれを入れるかを決める。
5. 検出結果の置き場（Issue、Security Hub、SIEM）を決める。

最初に確認する 3 つの問いは次のとおり。

1. ONTAP の版を自分で更新するか、AWS が適用するか。前者は A、後者は B と C を読む。
2. AutoSupport を NetApp に送れて、サポート契約があるか。ある場合は A1 の Digital Advisor と A2 の Upgrade Advisor、ない場合は助言の RSS と Upgrade Health Checker を選ぶ。
3. 検出結果の置き場は決まっているか。決まっていれば D1 を読む。

条件ごとの選択肢は次のとおり。

| 条件 | 向く選択肢 | 前提とトレードオフ | 向かない条件 |
|---|---|---|---|
| AutoSupport を送れて、サポート契約がある | Digital Advisor、Upgrade Advisor（A1、A2） | 送信とサポート資格が前提になる | AutoSupport のデータがない環境では、Digital Advisor が参照する情報がそろわない（推測）。2 行目の組み合わせを選ぶ |
| 閉域で、台数が少ない | 助言の RSS と人の照合、Upgrade Health Checker（A1、A2） | 手作業が増える | 台数や更新の頻度が増えると、人の照合が追いつかず、照合日から 90 日を超えた行が積み上がる。1 行目の条件を満たせるなら、そちらを検討する |
| AWS 上の計算資源の依存を継続的に見たい | Amazon Inspector と AWS Security Hub（B2、C2） | 有効化と課金が要る。対象は EC2、ECR、Lambda などに限られる | 見たい対象が AWS 上の計算資源でないと、スキャンの対象外で所見が出ない。出ないことを「問題なし」と読む誤りが起きる（オンプレミスの ONTAP 自身など） |
| リポジトリ単位で依存と更新を管理したい | GitHub、Renovate、Dependabot（A3、B2） | 依存関係グラフの有効化が要る。Cooldown の間は修正版も待つ | コードを GitHub で管理していないと、依存関係グラフ、Dependabot、Renovate の前提が成り立たない。この文書の範囲外で、別の方法で依存を取る必要がある |
| 配布物の出所を検証したい | 署名、artifact attestations、immutable releases（B3） | 検証する側の手順が要る | 検証する側が手順を持てないと、署名や来歴の証明を付けても検証されず、付けた効果が得られない [R24] |
| 検出を既存の SIEM に集めたい | EventBridge、Security Hub、Issue（D1） | SIEM 側の連携は確かめていない | SIEM 側で取り込みを用意しないと、Issue や Security Hub の検出が SIEM に入らず、見る場所が分かれたままになる |

## 確認できなかった項目

次の項目は、確認日（2026-11-17）時点で、確かめていない。記載が見つからなかったことは、ないことの証明ではない。

| 項目 | 状況 | この文書での扱い |
|---|---|---|
| FSx for ONTAP が Digital Advisor の対象か | Digital Advisor の機能と制限の 2 ページ、Cloud Volumes ONTAP との統合のページに FSx の記載がなく、NetApp Console の FSx for ONTAP のページに Digital Advisor の記載がない（2026-11-17）[R38][R39] | 対象とも対象外とも書かれていない。C1 は未確認として扱う |
| FSx for ONTAP の ONTAP の版の選択可否と、版の確認方法を述べた AWS 側の文書 | 専用のページが見つからなかった | AWS が版を決める、とは書かない |
| NetApp の SBOM と VEX の提供 | 脆弱性対策ポリシーのページと、リソース一覧の冒頭で、記載を探した。記載は見つからなかった | 提供の有無を断定せず、確かめていないと書く |
| AWS Security Bulletins の FSx for ONTAP の掲載、AWS Config が記録する FSx for ONTAP の設定、SIEM 製品の連携 | 一次の文書を読んでいない | 未確認として表に残す |
| 規制や指針の原文 | EU の Cyber Resilience Act の条文、CISA の SBOM 最小要素の 2026 年版、国家サイバー統括室と経産省の 2026-07-30 付の資料は、本文を取得できず読めていない | 適合の根拠にしない |

NetApp のセキュリティアドバイザリのサイトは、ページの本文を JavaScript で描画する。通常の取得では本文が空になるので、ブラウザで描画した内容を読んだ。

## 参考文献

確認日はすべて 2026-11-17 である。

- [R01] NetApp Product Security, Advisories. https://security.netapp.com/advisory/ （確認日 2026-11-17）
- [R02] NetApp Product Security, Policy. https://security.netapp.com/policy/ （確認日 2026-11-17）
- [R03] NetApp Docs, Digital Advisor. https://docs.netapp.com/us-en/active-iq/task_increase_protection_against_hackers_and_Ransomware_attacks.html （確認日 2026-11-17）
- [R04] NetApp Docs, ONTAP System Manager のリスク表示. https://docs.netapp.com/us-en/ontap/task_admin_monitor_risks.html （確認日 2026-11-17）
- [R05] NetApp Docs, ONTAP をアップグレードする時期. https://docs.netapp.com/us-en/ontap/upgrade/when-to-upgrade.html （確認日 2026-11-17）
- [R06] NetApp Docs, ONTAP のアップグレード. https://docs.netapp.com/us-en/ontap/upgrade/index.html （確認日 2026-11-17）
- [R07] Amazon FSx for NetApp ONTAP ユーザーガイド, メンテナンスウィンドウ. https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/maintenance-windows.html （確認日 2026-11-17）
- [R08] Amazon FSx for NetApp ONTAP ユーザーガイド, 仕組み. https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/how-it-works-fsx-ontap.html （確認日 2026-11-17）
- [R09] Amazon FSx for NetApp ONTAP ユーザーガイド, セキュリティ. https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/security.html （確認日 2026-11-17）
- [R10] AWS Security Bulletins. https://aws.amazon.com/security/security-bulletins/ （確認日 2026-11-17）
- [R11] Amazon Inspector ユーザーガイド, リソースのスキャン. https://docs.aws.amazon.com/inspector/latest/user/scanning-resources.html （確認日 2026-11-17）
- [R12] Amazon Inspector ユーザーガイド, SBOM の書き出し. https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html （確認日 2026-11-17）
- [R13] Amazon Inspector ユーザーガイド, 脆弱性インテリジェンスとスコア. https://docs.aws.amazon.com/inspector/latest/user/findings-understanding-score.html （確認日 2026-11-17）
- [R14] Amazon Inspector ユーザーガイド, EventBridge との連携. https://docs.aws.amazon.com/inspector/latest/user/eventbridge-integration.html （確認日 2026-11-17）
- [R15] AWS Security Hub ユーザーガイド, SBOM インベントリ. https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html （確認日 2026-11-17）
- [R16] AWS Security Hub CSPM ユーザーガイド. https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html （確認日 2026-11-17）
- [R17] AWS Config 開発者ガイド. https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html （確認日 2026-11-17）
- [R18] AWS Signer 開発者ガイド. https://docs.aws.amazon.com/signer/latest/developerguide/Welcome.html （確認日 2026-11-17）
- [R19] AWS CodeArtifact ユーザーガイド, パッケージ起点の制御. https://docs.aws.amazon.com/codeartifact/latest/ug/package-origin-controls.html （確認日 2026-11-17）
- [R20] AWS SAM 開発者ガイド, サーバーレスアプリケーションの更新の自動化. https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/automating-updates-to-serverless-apps.html （確認日 2026-11-17）
- [R21] GitHub Docs, SBOM の書き出し. https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exporting-a-software-bill-of-materials-for-your-repository （確認日 2026-11-17）
- [R22] GitHub Docs, Dependabot のオプションの一覧. https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference （確認日 2026-11-17）
- [R23] Renovate Docs, minimumReleaseAge. https://docs.renovatebot.com/configuration-options/#minimumreleaseage （確認日 2026-11-17）
- [R24] GitHub Docs, artifact attestations. https://docs.github.com/en/actions/concepts/security/artifact-attestations （確認日 2026-11-17）
- [R25] GitHub Docs, immutable releases. https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases （確認日 2026-11-17）
- [R26] GitHub Docs, ルールセット. https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets （確認日 2026-11-17）
- [R27] OpenSSF, OSV スキーマ. https://github.com/ossf/osv-schema （確認日 2026-11-17）
- [R28] OpenSSF, GitHub のマルウェア助言の拡張の事例. https://openssf.org/blog/2026/10/16/case-study-github-expands-malware-advisories-across-eight-ecosystems-with-openssf/ （確認日 2026-11-17）
- [R29] CISA, Known Exploited Vulnerabilities のフィード. https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json （確認日 2026-11-17）
- [R30] FIRST, EPSS. https://www.first.org/epss/ （確認日 2026-11-17）
- [R31] OpenVEX 仕様. https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md （確認日 2026-11-17）
- [R32] Amazon Inspector ユーザーガイド, ECR の再スキャン期間の設定. https://docs.aws.amazon.com/inspector/latest/user/scanning_resources_configure_duration_setting_ecr.html （確認日 2026-11-17）
- [R33] Amazon FSx for NetApp ONTAP ユーザーガイド, 可用性、耐久性、デプロイオプション. https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/high-availability-AZ.html （確認日 2026-11-17）
- [R34] AWS Security Hub CSPM ユーザーガイド, 独自製品との統合. https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-providers.html （確認日 2026-11-17）
- [R35] NetApp Docs, ONTAP REST API リファレンス, クラスターの取得（version の項目）. https://docs.netapp.com/us-en/ontap-restapi/ontap/get-cluster.html （確認日 2026-11-17）
- [R36] Amazon FSx API リファレンス, CreateFileSystemOntapConfiguration と UpdateFileSystemOntapConfiguration. https://docs.aws.amazon.com/fsx/latest/APIReference/API_CreateFileSystemOntapConfiguration.html 、https://docs.aws.amazon.com/fsx/latest/APIReference/API_UpdateFileSystemOntapConfiguration.html （確認日 2026-11-17）
- [R37] Amazon FSx API リファレンス, OntapFileSystemConfiguration. https://docs.aws.amazon.com/fsx/latest/APIReference/API_OntapFileSystemConfiguration.html （確認日 2026-11-17）
- [R38] NetApp Docs, Digital Advisor の機能と制限. https://docs.netapp.com/us-en/active-iq/concept_understand_activeiq_features.html 、https://docs.netapp.com/us-en/active-iq/reference_limitations_activeiq.html 、https://docs.netapp.com/us-en/storage-management-cloud-volumes-ontap/concept-active-iq.html （確認日 2026-11-17）
- [R39] NetApp Docs, NetApp Console の Amazon FSx for NetApp ONTAP. https://docs.netapp.com/us-en/bluexp-fsx-ontap/start/concept-fsx-aws.html （確認日 2026-11-17）

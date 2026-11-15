# サプライチェーン導入ガイド（第 1 の柱）

> **概要**: 第 1 の柱「ソフトウェアサプライチェーンの可視化と対応」を、自分のリポジトリ群に導入する手順をまとめる。4 つの取り組み領域（棚卸し、悪用可能性に基づく検出と優先順位付け、取り込み時の防御、疎結合な更新）ごとに、目的、導入手順、対応するポリシーファイルの項目、固定した参照の記述例、ツールの選び方を書く。数値は [`docs/agent/supply-chain-policy.json`](../agent/supply-chain-policy.json)（ポリシーファイル）の値と一致させてある。Hub 側の設定が未作成であることなど、作成時点の状態は[現在の状態](#現在の状態)の節にまとめた。

## 想定する読者

読者は 2 通りを想定する。1 つはサービス提供者の役割で、パートナー / SI、システム担当、アプリ担当を含む。もう 1 つは、それらの役割の代わりに作業する AI エージェントである。どちらも、リポジトリの保守者が決めた方針と承認の範囲の中で作業する。AI エージェントは次の 3 点を守る。

- 判断案を作るだけで、VEX の承認、自動マージの有効化、対応時間の目標の変更は人の承認なしに行わない
- 数値は [ポリシーファイル](../agent/supply-chain-policy.json) から読み、この文書の値を写して使わない
- 「できない」「載らない」と書かれた箇所の `[E-nnn]` は、[evidence-ledger.json](../agent/evidence-ledger.json) の登録番号である。登録のない主張を足さない

用語は次のとおり。初出以降はこの名前で呼ぶ。

| 用語 | 意味 |
|---|---|
| ポリシーファイル | 閾値、待ち時間、自動マージの範囲、対象リポジトリ、対応時間の目標を持つ JSON（コード上の名前は `Policy_File`）。この文書の数値の基準 |
| 保守者 | 対象リポジトリの設定を変更し、承認を行う人 |
| 所有者 | GitHub 上のリポジトリを所有するアカウント。個人アカウントのリポジトリでは保守者と同じ人になる |
| サービス提供者 | エンドユーザーにサービスを提供し、SLA/SLO/SLI と RTO/RPO を設定する側（導入する側の役割） |
| 成果物の利用者 | リリース成果物を取り込む側 |
| Hub | 再利用可能ワークフローと Renovate の共有プリセットを置くリポジトリ [FSx-for-ONTAP-Adoption-Playbook](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook) |
| Spoke | Hub 以外の対象リポジトリ。Hub が配る再利用可能ワークフローと Renovate の共有プリセットを参照する |
| 対象リポジトリ | ポリシーファイルの `target_repositories` に挙げた 12 件。このリポジトリと Hub を含む |
| 集約ジョブ | 各リポジトリの SBOM と脆弱性情報を突き合わせ、リポジトリに Issue を起票する Hub の定期ジョブ（コード上の名前は `Aggregator`） |
| 所見 | 集約ジョブが、1 つの（リポジトリ、脆弱性、構成要素の版）の組について作る検出結果。Issue を起票するかの判定の単位 |
| 見張り | 集約ジョブとは別のワークフローで動き、集約ジョブの最新の実行結果が古くなっていないか、直近の実行が失敗していないかを確かめる仕組み（コード上の名前は `watchdog`） |
| 起票の条件 | Issue を起票する条件。CVSS 重大度が High 以上、CISA KEV に掲載、または悪意のあるパッケージ |
| VEX | Vulnerability Exploitability eXchange。ある構成要素の版について、脆弱性が影響するかどうかを根拠つきで機械可読に記録する形式。このガイドでは OpenVEX を使う |
| VEX の承認者 | VEX の判断を承認する人の役割。ポリシーファイルの `vex.approver_role` の値は `VEX_Reviewer` |
| 対応時間の目標 | 検出と修正の時間の目標。SLO とは呼ばない |
| Cooldown | 公開直後の版を取り込まない待ち時間 |
| 検証ゲート（ゲート） | 設定がポリシーファイルと一致するかを確かめ、違反があれば終了コード 1 で失敗するスクリプト。`make check-supply-chain` で実行する |
| パイロット | 最初に適用する 2 件のリポジトリ（このリポジトリと Hub）で、検出器の誤りを確かめる期間。2 件の両方で集約ジョブが初めて所見の一覧を作った実行の日時から数える。既定は 14 暦日で、起票した Issue が 20 件に届かないときは、14 暦日ずつ最大 2 回延長できる（合計 42 暦日まで）。その結果で、閾値と、次に適用するリポジトリの組（バッチ）の観察期間を決める。確認項目は[パイロットで確かめる項目](#パイロットで確かめる項目)に書く |
| バッチ | パイロットの後に、残りの 10 件へ順に適用するリポジトリの組。3 件、3 件、3 件、1 件の 4 組で、各バッチの観察期間は既定で 7 暦日 |
| 根拠の種別 | `documented`（出典の該当箇所を読んだ）、`verified`（1 回以上実測した）、`hypothesis`（このプロジェクトの推測）、`open`（未確認）の 4 語 |
| 検出の起点 | 検出の目標を測り始める日時。[対応時間の目標](#対応時間の目標)の節で定義する |

3 本の柱全体の位置づけは、[3 本の柱の全体方針](cyber-resilience-programme.md)にある。この文書は第 1 の柱の導入だけを扱う。

## 現在の状態

2026-11-15 時点の状態は次のとおりである。本文中の「未作成」「未マージ」「未確認」は、この節を指す。

- Hub の main には、`supply-chain-aggregator`（6 時間ごと）、`supply-chain-watchdog`、`vex-validate`、`sbom-generate` のワークフローが公開済みで、有効である（2026-11-15 に確認）。Renovate の共有プリセットの公開と、Hub のタグの有無は確かめていない。この文書の参照先は `<40 桁の SHA>` と `<タグ>` のプレースホルダで、確かめられたら置き換える。
- Hub の Aggregator は毎回失敗している。リポジトリ変数（`SUPPLY_CHAIN_APP_CLIENT_ID`、`SUPPLY_CHAIN_POLICY_REF`）、シークレット（`SUPPLY_CHAIN_APP_PRIVATE_KEY`）、ブランチ `supply-chain-runs` が未作成のためで、設計どおりである。作成は保守者の作業である。Hub の watchdog は、確認時点で 12 時間のしきい値のままだった。Hub の PR #383（draft、未マージ）が、`tools/supply_chain/` の写しの同期、しきい値 8 時間、`--policy-file`・`--chain-ack`・`--report-file`、`chain_to_previous`、保守者向けの手順を含む。PR の checks は確認時に実行中だった。PR がマージされるまで、Hub のワークフローの実行結果と `chain_to_previous` の実環境の挙動は確かめていない。
- 起票の判定、VEX による除外の判定、見張りの判定は、このリポジトリの `solutions/supply-chain/` に純粋な関数としてあり、単体テストで確かめている。
- 検証ゲートは `make check-supply-chain` で動く。ポリシーファイルとこの文書の数値の一致は、ゲートの 1 つ（`guide-values`）が確かめる。
- `.vex/` の変更が作成者以外の人に承認されたかの確認は Hub 側で動く部品である。Hub に `vex-validate` は公開済みだが、それが `.vex/` を読むことと、作成者以外の承認を確かめることは、実行して確かめていない（open）。
- 次の 3 点は、実行して確かめていない。Renovate の共有プリセットの参照形（`github>…#<タグ>`）が Renovate で解決されること。GitHub Actions に対する Cooldown がタグの付け替えを防ぐこと（防がない見込みで、hypothesis）。Lambda のカナリアデプロイでトラフィックが移り、アラームで巻き戻ること。
- 見張りの週 1 回の確認（`watchdog_cli`）と、記録の連鎖の分岐の復旧（`chain_recovery`）は、このリポジトリの `solutions/supply-chain/` にあり、手順は 2026-11-15 に使い捨てのディレクトリで実行して確かめた。確かめたのは、`PYTHONPATH` の要否、作業ディレクトリを変えた実行、Hub の実際のワークフロー一覧（`gh api`）の読み取り、分岐の検出・登録・再接続である。launchd からの起動は、使い捨ての plist を `launchctl bootstrap` して `kickstart` で起動し、ジョブ内で `--overdue-check` が終了コード 1 を返し、`osascript display notification` が終了コード 0 で呼ばれたことまで、同日に確かめた。確かめていないのは、通知バナーが画面に出たこと、`StartCalendarInterval` のスリープ復帰後の実行、`supply-chain-runs` ブランチの取得（ブランチは未作成）、Hub の集約ジョブと見張りが台帳を読むことである。週次確認は、`supply-chain-runs` ブランチが作られるまで、手順 2 で止まる。止まっている間、Hub の見張りの停止を拾う手段はない。
- 第 2 と第 3 の柱の手順は公開していない。

## 4 つの取り組み領域と範囲

| 取り組み領域 | 何をするか | 主な部品 |
|---|---|---|
| 棚卸し | 何がどこに入っているかを機械可読に持つ | SBOM、インフラ構成要素の台帳、エージェント構成要素の記録 |
| 検出と優先順位付け | 悪用されやすいものと悪意のあるパッケージから先に Issue にする | 集約ジョブ、OpenVEX |
| 取り込み時の防御 | 公開直後の版と未固定の参照を入れない | Renovate の共有プリセット、検証ゲート、来歴証明 |
| 疎結合な更新 | 更新を小さく、戻せる形で入れる | 自動マージ方針、Lambda のカナリアデプロイの参照実装 |

### 範囲外と固定の限界

範囲外は次のとおり。AIBOM / ML-BOM の形式は作らず、エージェント構成要素の記録は SBOM の外の独自の JSON のままにする。.NET（NuGet）、Terraform、Dockerfile の `FROM` のダイジェスト固定は、この柱の検査の対象に含めない。第 2 段で扱う対象として記録している。

固定には限界がある。次の 3 点は、固定済みと表示されても残るリスクである。

- 版の固定は、MCP サーバーが返すツール定義の変更を覆わない（hypothesis。このプロジェクトの推論で、ベンダーの記述ではない）。ツール定義の変更の検知は、この柱のゲートに含めていない。Cloud Security Alliance の研究ノートは、使用中の MCP サーバーの棚卸しと版の固定、定義変更の検知を推奨している。このノートは、自身が AI 支援で作成され、正式なレビューを経ていないと書いている [G26]
- 最上位の固定（`npx -y <pkg>@<x.y.z>` や `image@sha256:…`）は、推移的な依存を固定しない。依存の木ごとに固定するにはロックファイルが要る
- ダイジェストで固定したイメージは、セキュリティ更新を自動では取り込まない。更新は Renovate の PR で人が受ける

Cooldown の <!-- policy:cooldown_days.default -->3 日は慣行の値で、実測に基づかない。メジャー更新の <!-- policy:cooldown_days.major -->7 日に対応する外部の値も見つけていない。パイロットで、待ち時間のために遅れた修正の件数を見て見直す（[Cooldown の値の根拠と限界](#cooldown-の値の根拠と限界)）。

Amazon Inspector の AI inventory は、自前で動かす AI のフレームワークを EC2 と ECR のイメージから見つける機能で、Security Hub の FAQ に記述がある [G13]。リポジトリのファイルを数えるこの柱のエージェント構成要素の記録とは対象が違う。実行中のリソースの補完になりうるが、ユーザーガイドは読んでいないので、使う前に確かめる。

### 公式の設定例を固定した形に書き換えた例

MCP クライアントの設定例は、多くが版を指定しない `uvx <pkg>` や `npx -y <pkg>`、タグだけのイメージで書かれている。固定した形は次のとおり。`<x.y.z>` と `<64 桁>` はプレースホルダで、公式リリースを確認して決める。クライアントごとの設定ファイル名とキーの名前は、各クライアントの文書で確かめる。この文書では、各クライアントの個別の文書を確かめていない。

```json
{
  "mcpServers": {
    "example-uvx": { "command": "uvx", "args": ["example-server==<x.y.z>"] },
    "example-uvx-from": { "command": "uvx", "args": ["--from", "example-server==<x.y.z>", "example-command"] },
    "example-npx": { "command": "npx", "args": ["-y", "example-server@<x.y.z>"] },
    "example-docker": { "command": "docker", "args": ["run", "-i", "--rm", "example/server@sha256:<64 桁>"] }
  }
}
```

`url` だけで指定するリモートのサーバーは、固定の対象ではなく「該当なし」と記録する。名前だけで推奨している MCP サーバー（宣言ファイルがないもの）は、宣言ファイルを置く。置かない場合は、その推奨を書いたファイルに「版は固定していない」と断りを書く。

## 棚卸し

対応する Well-Architected のベストプラクティスは SEC11-BP02 と SEC11-BP05 である。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) にあり、ここには写さない。

目的は、脆弱性が公開された時点で「自分のどのリポジトリのどの版が該当するか」を、人が探し回らずに答えられる状態にすることである。

### 導入手順

1. 自分のリポジトリ用のポリシーファイルを用意する。このリポジトリの `docs/agent/supply-chain-policy.json` を写し、`target_repositories` を自分のリポジトリの一覧に書き換える。このリポジトリの一覧は 12 件で、`excluded_repositories` の 4 件（AWS の Baseline Environment on AWS の上流 2 件とそのフォーク 2 件）は走査しない。
2. 層 A（GitHub の依存関係グラフ）を有効にする。集約ジョブが API で SBOM を取る。GitHub の同期 SBOM エクスポート API は、2026-11-13 の後はアクセスできなくなると GitHub が告知した（参照日 2026-11-13）[E-044][G8]。2026-11-14 時点で、廃止後の応答は確かめていない。非同期の `generate-report` と `fetch-report` の経路を使う。
3. 層 B（CI でのスキャン）として、呼び出し側のワークフローで Hub の `sbom-generate` を呼ぶ。参照は最初から 40 桁の SHA にする。成果物 `sbom-<commit-sha>` は 90 日残る。90 日は公開リポジトリの上限で、非公開リポジトリを足すときは保存期間を 400 日まで選べる。
4. リリースを出すリポジトリは、リリースを作ったコミットの SBOM をリリースの添付ファイルにする。添付した SBOM は、リリースと同じ期間残る。添付しなかったリリースは、90 日を過ぎると SBOM が残らず、構成を作り直して答えることになる。作り直した SBOM は、ツールの版が当時と違いうる。
5. エージェント構成要素（MCP サーバー、エージェント設定、インストール手順）を `docs/agent/agent-components.json` に記録し、未固定の箇所を 0 件にする。
6. ONTAP の版、Amazon FSx for NetApp ONTAP（以降 FSx for ONTAP）のファイルシステム、TrendAI と Deep Instinct のエージェントの版は、SBOM に載せず [`infrastructure-component-ledger.json`](../agent/infrastructure-component-ledger.json) に人が記録する。照合日から 90 日を超えた行（91 日目から）が再照合の対象に挙がる。

### 対応するポリシーファイルの項目と参照の記述例

対応する項目は `target_repositories`、`excluded_repositories`、`dependency_scope.non_production_paths`（本番の依存の判定から外すパス。初期値は `tests/` と `docs/`）である。呼び出し側ワークフローの記述例を示す。`<40 桁の SHA>` は、Hub で再利用可能ワークフローが公開された時点の Hub の既定ブランチのコミットの値に置き換える。再利用可能ワークフローの `uses:` は、最初から 40 桁の SHA で書く。GitHub は、`jobs.<id>.uses` の ref に SHA を使えると文書化し、安定性とセキュリティの面で SHA が最も安全だと書く [G30]。Hub にタグが付く前でも、SHA は Hub の既定ブランチのコミットから取れる。タグでの参照を暫定で許すのは、Renovate の共有プリセットの参照（`renovate.json` の `extends`）だけである（[取り込み時の防御](#取り込み時の防御)の手順 1）。2026-11-14 時点で、Hub にタグが付いているかは確かめていない。

```yaml
jobs:
  sbom:
    uses: Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/.github/workflows/sbom-generate.yml@<40 桁の SHA> # <タグ>
    permissions:
      contents: read
```

### 棚卸しの手段の使い分け

行は手段、列は用途・前提・費用の扱い・制約である。順位は付けない。各手段の制約は、同じ 2 つの観点（何が見えないか、何の準備が要るか）で書く。

| 手段 | 用途 | 前提 | 費用の扱い | 制約 |
|---|---|---|---|---|
| リポジトリの SBOM（層 A・B） | リポジトリが宣言する依存、Actions、コンテナイメージ、Lambda の構成要素を、脆弱性の公開時に集約ジョブで突き合わせ、リポジトリに Issue を起こす | GitHub の依存関係グラフ（層 A）と CI のスキャン（層 B）。再利用可能ワークフロー `sbom-generate` | AWS の課金はない。GitHub Actions の実行時間 | デプロイ後に入ったもの（OS のパッケージ、手で入れたエージェント、ランタイムが同梱するライブラリ）は記録の範囲にない。リポジトリごとに CI を整える必要がある |
| Amazon Inspector の SBOM エクスポート（層 C） | Inspector が監視しているリソースの SBOM を CycloneDX 1.4 / SPDX 2.3 の JSON で S3 に書き出し、外部のツールや監査の記録に渡す [G9] | 対象の種別で Inspector が有効。書き出し先の S3 バケットと KMS キーのポリシー | Inspector のスキャンの料金（個別の料金、または Security Hub の Essentials）と、S3 と KMS の料金。書き出しそのものの料金は確かめていない | 書き出しを要求した時点の内容で、定期的に取り直す仕組みはサービス提供者が作る。エージェントベースの EC2 Windows は書き出せない [E-052]。Lambda のランタイム同梱の AWS SDK [E-047]、カスタマーマネージドキーで暗号化した関数 [E-048]、90 日以内に呼び出しも更新もない関数 [E-049] は、Inspector がスキャンしない |
| SBOM インベントリ | あるパッケージと版が組織のどのリソースに入っているかを、コンソールか API で引く（リージョンをまたぐ集約で home Region に集めた分を含む） | アカウントとリージョンで AWS Security Hub が有効、種別ごとに Inspector が有効。組織全体を見るには委任管理者 | Essentials に追加料金なしで含まれる（[AWS What's New](https://aws.amazon.com/about-aws/whats-new/2026/11/security-hub-sbom-inventory/)、参照日 2026-11-12）[G15]。Essentials はリソース単位の課金で Inspector の標準スキャンを含む（[AWS Security Hub Pricing](https://aws.amazon.com/security-hub/pricing/)、参照日 2026-11-12）[G16]。Security Hub を有効にしていない環境では使えない（[Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html)、参照日 2026-11-13）[G14]。単価は書かない | 応答は名前・版・種類・件数だけで purl がなく、リポジトリの SBOM と直接は突き合わせられない [E-053]。FSx for ONTAP と ONTAP は載らない見込み（hypothesis）[E-054]。新しい SBOM の反映に数時間かかることがある。SPDX や CycloneDX での書き出しは、ユーザーガイドと API リファレンスに記述がない（書き出せないとは書かない。未確認） |
| インフラ構成要素の台帳 | ONTAP の版、FSx for ONTAP のファイルシステム、TrendAI と Deep Instinct のエージェントの版を、NetApp と AWS のセキュリティアドバイザリと照合する | 人が照合して記録する手順。照合日から 90 日を超えた行が再照合の対象 | AWS の課金はない。照合の人手 | 機械可読の SBOM ではなく、照合は人の手順（RSS 2.0 を正とする半自動の照合で、確定は人）。照合日より後の変化は次の照合まで反映されない |

選び方の手順は次のとおり。

1. 調べたい対象が、リポジトリの宣言か、デプロイ後のリソースか、ストレージとエージェントの基盤かを決める。
2. リポジトリの宣言なら層 A・B を使う。
3. デプロイ後のリソースで、どこに入っているかを組織全体で引きたく、AWS Security Hub を有効にしているなら SBOM インベントリを使う。
4. デプロイ後のリソースの SBOM を機械可読の形で外に渡したい場合、または Security Hub を有効にしていない場合は層 C を使う。
5. ONTAP、FSx for ONTAP、エージェントはインフラ構成要素の台帳に記録する。
6. 2 つ以上に当てはまれば併用する。例として、SBOM インベントリで見つけたリソースの SBOM を層 C で書き出し、purl で照合する。

このプロジェクトは、第 1 の柱の範囲では Amazon Inspector と AWS Security Hub を有効にせず、課金が発生する操作をしない。有効化と費用の見積りは第 2 の柱で扱う。使う場合は、導入する人が有効化と費用を確かめる。

### SBOM 生成ツールの選び方

生成と走査は同じ系列のツールにそろえる。採用する組は、パイロットで取りこぼしを測って決める。

| ツール | 向いている状況 | トレードオフ |
|---|---|---|
| Trivy 単独（生成も走査も Trivy） | 生成と走査を 1 つの系列に預けたい | 1 つの配布物の事故で生成と走査の両方が影響を受ける。既定の終了コードは検出があっても 0 なので `--exit-code` を明示する。`MAL-` を出さないことは hypothesis（実行して確かめていない） |
| Syft（生成）+ Grype（走査） | 生成と走査を同じ系列の組でそろえたい | 2 つのツールの版を固定して更新する手間がある。Syft の `-o spdx-json` は既定で SPDX 3.0 を出すので `spdx-json@2.3` を明示する。Grype の SBOM 入力の挙動は読んでいない（未確認） |
| Syft（生成）+ Trivy（走査） | リポジトリとイメージの両方を 1 つのスキャナーで扱いたい | Trivy の文書は、他のツールが作った SBOM は検出が不正確になりうると注意している。系列がずれ、取りこぼしに当たりうるので、選ぶ場合はパイロットで取りこぼしを測る |
| OSV-Scanner | OSV のデータベースを直接使いたい。ロックファイル中心のリポジトリ | イメージのスキャンの扱いを読んでいない（未確認） |
| 層 A だけ | 追加のツールを置きたくない | GitHub が読む宣言ファイルの範囲に限られる。範囲の外にあるものは含まれない |

ツールは完全なバージョン番号とイメージの `sha256:` ダイジェストで固定する。固定する版とダイジェストは、公式リリースを確認してから決める。固定したツールの配布物の確かめ方は、[来歴証明の検証](#来歴証明の検証)の節に書く。

## 検出と優先順位付け

対応する Well-Architected のベストプラクティスは SEC11-BP02 と SEC11-BP05 である。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) を参照する。

目的は、公開された脆弱性のうち、悪用されているものと悪意のあるパッケージから先に Issue にすることである。CVSS の重大度だけで並べると、悪用の証拠がある Medium 以下の脆弱性が後回しになる。

### 導入手順

1. ポリシーファイルの `opening_threshold` を確かめる。既定は、CVSS 重大度が `HIGH` 以上、KEV 掲載、悪意のあるパッケージの 3 条件のどれかを満たせば Issue を起票する。EPSS [G24] は起票の判定に使わず、表示だけにする（`epss_used_for_opening` は `false`）。KEV は CISA の Known Exploited Vulnerabilities Catalog である [G23]。
2. Hub の保守者が集約ジョブを有効にする。定期実行の間隔は 6 時間以下にする。Hub 側の実装の状態は[現在の状態](#現在の状態)を参照する。集約ジョブとは別の見張りが、最新の実行結果の時刻と直近の実行の成否を確かめる。最新の実行結果が見張りのしきい値（<!-- policy:watchdog.limit_hours -->8 時間。6 時間の間隔と `schedule` の遅れ 2 時間の和）より古いとき、直近 2 回の実行がともに失敗したとき、実行結果の連鎖が切れているときに、見張りは失敗する。しきい値はポリシーファイルの `watchdog.limit_hours` にあり、省略すると 8 時間になる。間隔を 6 時間より長くすると、しきい値を超えて見張りが失敗する。
3. 新規起票の上限を確かめる。1 回の実行で 1 リポジトリに新規起票する上限は <!-- policy:issue_limits.max_new_issues_per_repo_per_run -->10 件である。上限を超える場合は、KEV 掲載の所見と悪意のあるパッケージの所見を先に、残りを CVSS 重大度の高い順に起票し、超えた分はそのリポジトリの 1 件のまとめ Issue に列挙する。
4. 重大度が付かない所見（CVSS 重大度がなく、KEV に載らず、悪意のあるパッケージでもないもの）は、所見ごとには起票しない。判定できる時点（アドバイザリの公開日時と、構成要素の版を最初に観測した日時のうち遅い方）から <!-- policy:unscored_review_days -->7 日を過ぎたものを、リポジトリごとに 1 件のまとめ Issue に列挙する。並びは EPSS の降順で、EPSS は並びと表示だけに使う。KEV を取得できなかった実行は、このまとめ Issue を作らず、更新も閉じることもしない。Issue の作成は Hub 側の実装で、Hub のワークフローは設定が未作成のため動いておらず、作成の挙動は確かめていない（[現在の状態](#現在の状態)）。
5. 悪意のあるパッケージ（`MAL-` の識別子）は、重大度に関係なく起票する。VEX で除外しない（`open_if_malicious` は常に `true`）。重複排除の単位は (リポジトリ, purl, 版) で、同じ purl と版に GHSA（type=malware）と `MAL-` の両方があれば 1 件にまとめ、代表の識別子は `MAL-` を優先する。
6. 取り下げられた `MAL-` は、OSV の `GET /v1/vulns/{id}` の応答が成功し、`withdrawn` が時刻として読めた場合に限り、クローズ理由 `withdrawn` で閉じる。上流が記録の対象の版を外した場合は `feed_version_delisted` で閉じる。応答が取れない場合と `withdrawn` が読めない場合は閉じず、実行結果の `malicious_withdrawn_unconfirmed` に残す。取り下げられた `MAL-` が再び現れたときは、閉じた Issue を開き直す。
7. Issue に載る項目を確かめる。脆弱性識別子、影響を受ける構成要素と版、CVSS 重大度、KEV 掲載の有無、悪意のあるパッケージかどうか、EPSS のスコアと取得日（モデルの版つき）、修正済みの版、検出日時、対応時間の目標の期限である。KEV の `knownRansomwareCampaignUse` は表示だけで、判定に使わない。

CVE のデータベースに依存するスキャナーは、CVE が付く前の悪意のあるパッケージを検出しない。AWS Security Blog がこの趣旨を述べている [G20]（ガイダンスで、仕様ではない）。そのため、悪意のあるパッケージは OpenSSF Malicious Packages のフィード [G21] を OSV [G22] 経由で別に引く。

### 保守者の機械での週 1 回の確認

見張りは集約ジョブと同じ Hub の GitHub Actions 上で動くので、2 つの停止を拾えない。1 つは、公開リポジトリで 60 日間コミットがないと、`schedule` のワークフローが自動で無効になること[G33]である。もう 1 つは、GitHub Actions 自体の障害である。この 2 つは、保守者が自分の機械から週 1 回行う確認で拾う。次の手順は、2026-11-15 にこのリポジトリの作業ツリーで、使い捨てのディレクトリに報告を書いて実行し、結果を確かめた。`supply-chain-runs` ブランチは未作成なので、手順 2 は同じ名前のブランチを持つ使い捨てのローカルリポジトリで確かめ、手順 3 以降はそのクローンの `runs/` に記録を 1 件置いて確かめた（手順 1 は実在の Hub に実行した）。確かめていない点は[現在の状態](#現在の状態)に書く。

1. `gh api 'repos/<Hub の所有者>/<Hub のリポジトリ>/actions/workflows?per_page=100' > <gh api の出力を保存したファイル>` を実行する。
2. 実行結果を保存している `supply-chain-runs` ブランチを、Hub のリポジトリのクローン（以下 `<ブランチの複製>`）に取り込む。クローンは最初の 1 回だけ `git clone --no-checkout --single-branch --branch supply-chain-runs <Hub のリポジトリの URL> <ブランチの複製>` で作る。毎回、`git -C <ブランチの複製> fetch origin supply-chain-runs && git -C <ブランチの複製> checkout --detach FETCH_HEAD` を実行して最新にする。`<ブランチの複製>` はこの確認だけに使い、作業ツリーとして使わない。`supply-chain-runs` ブランチは、Hub の保守者が作るまで存在しない（2026-11-15 に `git ls-remote` で確認）。存在しない間は、この手順が失敗するので、手順 3 以降は行えない。
3. このリポジトリの根で、`PYTHONPATH=solutions/supply-chain python -m supply_chain.watchdog_cli --runs-dir <ブランチの複製>/runs --workflows-json <gh api の出力を保存したファイル> --chain-ack docs/agent/supply-chain-chain-ack.json --report-file <報告ファイル> --previous-report <報告ファイル>` を実行する。`--report-file` と `--previous-report` には同じパスを渡す。`<報告ファイル>` は保守者が決める固定の 1 つのパスで、この手順と、下の毎日の確認が同じファイルを使う。パスが変わると、期限の超過が検出されないか、毎日の確認が毎回失敗する。
4. 終了コードが 0 で、報告ファイルの `healthy` が `true` なら終わる。
5. 終了コードが 1 のときは、報告ファイルの `state` を読み、次の表の行に従う。`unhealthy` の理由は標準出力に出る。

| 報告ファイルの `state` | 原因 | 対処 |
|---|---|---|
| `unhealthy`（最新の実行結果が古い、または直近 2 回の実行がともに失敗） | 集約ジョブが動いていない、または失敗している | Hub の集約ジョブの実行結果を確かめる |
| `unhealthy`（ワークフローの `state` が `disabled_inactivity`） | 公開リポジトリで 60 日間コミットがなく、ワークフローが自動で無効になった | Hub でワークフローを有効にし直す |
| `unhealthy`（ワークフローの `state` が `disabled_manually`） | 誰かがワークフローを無効にした | 無効にした理由を確かめてから、有効にし直す |
| `unhealthy`（記録の連鎖が切れている） | 同じ月に連鎖の先端が 2 件ある | [記録の連鎖が分岐したときの復旧](#記録の連鎖が分岐したときの復旧)に従う |
| `error` | ポリシーファイルまたはワークフローの一覧が使えない | `policy_error` か標準出力の理由を読み、ポリシーファイルが読めること、手順 1 の保存ファイルが空でないことを確かめて、手順 1 からやり直す。報告ファイルは書かれ、次回の期限は決まる |

手順 3 の補足である。`supply_chain` はインストールされていないので `PYTHONPATH` が要る。付けないと `No module named 'supply_chain'` で終わる。`--policy-file` を省略すると、`git` が示すこのリポジトリの根の `docs/agent/supply-chain-policy.json` を読み、作業ディレクトリは問わない。相対パスで渡した `--policy-file` が作業ディレクトリになければ、リポジトリの根から探す。`--chain-ack` は、分岐を登録した台帳で、省略すると登録なしとして読む。

報告ファイルには、実行時刻、`healthy`、`state`（`ok`、`unhealthy`、`error`）、次回の期限 `next_check_due`（実行の 8 日後）が残る。前回の期限を過ぎてからの実行は終了コード 1 になり、報告に `previous_check_overdue: true` が残る。確認自身が止まったときのために、`PYTHONPATH=solutions/supply-chain python -m supply_chain.watchdog_cli --overdue-check <報告ファイル>` を、このリポジトリの根で、週次確認とは別の launchd ジョブ（毎日 09:00 JST）として実行する。期限を過ぎているとき、または報告がないときは終了コード 1 になる。通知は、この終了コードを受けて launchd のジョブが出す（コマンド自身が出すのは、終了コードと標準出力のメッセージだけである）。機械全体が止まったときのために、この確認を毎週行う予定を、保守者のカレンダーに繰り返しで入れる。予定が通知されたのに確認していなければ、機械が止まっていることに気づける。

起動には保守者の機械の launchd を使い、失敗したとき（終了コード 1）は、ジョブが通知を表示する。通知の出し方は、たとえば `osascript` の `display notification` である。plist の `ProgramArguments` と `EnvironmentVariables` の `PATH` に `gh`、`git`、`python` の絶対パスを書き、`StandardOutPath` と `StandardErrorPath` でログの置き場を決める。cron は、スリープ中と電源オフの間のジョブを実行せず、次の指定時刻まで待つ。スリープする機械では launchd を使う。launchd の `StartCalendarInterval` は、スリープ中に時刻を過ぎても復帰時に実行される。Apple の文書はアーカイブで、現行の macOS の挙動は確かめていない。2026-11-15 に、使い捨ての plist を `launchctl bootstrap` して `kickstart` で起動し、ジョブ内で `--overdue-check` が終了コード 1 を返し、`osascript display notification` が終了コード 0 で呼ばれることを確かめた（verified）。通知バナーが画面に出たことと、スリープ復帰後の実行は確かめていない（open）。Hub 側の実装が動き出したあと、Hub の見張りの停止を拾う手段は、この確認だけである。設定例はリポジトリに置かない。

### 記録の連鎖が分岐したときの復旧

見張りが記録の連鎖の破れを報告し、同じ月に連鎖の先端（子を持たない記録）が 2 件あるとき、または集約ジョブが `the month has 2 chain tips` で失敗したときの手順である。先端が 2 件になるのは、2 つの書き込みが同じ直前の記録を指して競合したとき、または記録を手で置いたときである（実装の説明による。実際の分岐を観察したことはない）。記録を削除も編集もしない。削除や編集は、連鎖が改ざんを検出する役目を失わせる。放棄する側の記録は、削除せず連鎖の外に置く。

1. 検出する。このリポジトリの根で、`PYTHONPATH=solutions/supply-chain python -m supply_chain.chain_recovery --runs-dir <ブランチの複製>/runs --ledger docs/agent/supply-chain-chain-ack.json detect` を実行する。先端の SHA-256 とパスが出て、台帳に登録のない分岐があれば終了コード 1 になる。
2. 手順 1 が出した 2 件のパスの記録を開き、それぞれの `prev_record_sha256`（2 件とも同じ直前の記録を指す）、実行の開始日時（`started_at`）、本文を比べる。どちらを連鎖の外に置くかの基準は、Hub 側の記録の書き手が決める（`open`）。決まっていないときは、保守者が Hub の実行の履歴を見て、先に書かれた側を残し、決めた理由を手順 3 の `--decision` に書く Issue か PR に書く。
3. 登録する。同じコマンドの末尾を `isolate --abandon <放棄する先端の SHA-256> --decision <Issue か PR の番号、またはその URL>` にして実行すると、台帳に 1 件足される。`--decision` には `Issue 123`、`PR 45`、または GitHub の Issue か pull request の URL を書く。自由な文は拒否される。子を持つ記録、未知の SHA-256、分岐のない月の記録、重複した登録、月の先端をすべて放棄する登録も拒否される。台帳の変更を PR で出し、保守者が目視で確かめてからマージする。
4. 再接続を確かめる。末尾を `reconnect --month <YYYY-MM>` にして実行し、SHA-256 が 1 件出れば、先端は 1 件になっている。次の記録は、この値を `prev_record_sha256` に入れる。

登録した記録は、書き込み、月末の封印、見張りのどれからも連鎖の外として読まれる。この手順の 3 つの操作は、2026-11-15 に使い捨てのディレクトリで、同じ月に 2 件の先端を作って確かめた（検出は終了コード 1、登録後の再接続は 1 件の SHA-256 を出し、台帳つきの見張りは終了コード 0）。自由な文の `--decision` と、月の先端をすべて放棄する登録が拒否されることも、同じ日に確かめた。集約ジョブが台帳を読んで書き込みを再開する部分は Hub 側にあり、Hub の PR #383（未マージ）に含まれる。実行して確かめていない。先端の記録の本文の書き換えは、次の書き込みで連鎖に取り込まれ、月末の封印まで検出されない。

### 対応するポリシーファイルの項目

- `opening_threshold.min_cvss_severity`、`open_if_kev_listed`、`open_if_malicious`、`epss_used_for_opening`
- `issue_limits.max_new_issues_per_repo_per_run`、`unscored_review_days`
- `vex.exclude_statuses`、`vex.malicious_never_suppressed`、`vex.max_age_days`（[VEX の運用](#vex-の運用)の節）
- `response_target.*`（[対応時間の目標](#対応時間の目標)の節）

### ツールの選び方

脆弱性の見つけ方は、見たい対象で選ぶ。次の表は 3 つの手段を、向いている状況とトレードオフの 2 列で並べる。順位は付けない。

| 手段 | 向いている状況 | トレードオフ |
|---|---|---|
| 集約ジョブ（採用） | 12 リポジトリを同じ閾値で横断し、リポジトリごとに Issue で追いたい | Hub の定期ジョブと外部フィード（KEV、EPSS、OSV）に依存する。Issue はリポジトリ単位なので、アカウントとリソース単位の Inspector の所見は起票の対象に含めない。ランタイム同梱のライブラリのような、リポジトリに対応しないデプロイ後の脆弱性は Issue にならない |
| GitHub の Dependabot アラートだけ | 追加の仕組みを置かず、リポジトリの画面でアラートを見たい | 閾値と期限をリポジトリごとの設定に頼る。Dependabot アラートが無効なリポジトリには、アラートも、アラートを読む Renovate の修正 PR も作られない見込み（hypothesis）[E-055]。悪意のあるパッケージの扱いは別に設ける必要がある |
| Amazon Inspector の所見（AWS Security Hub CSPM に集約）[G10] | デプロイ後の Lambda、ECR のイメージ、EC2 を、アカウントとリージョン単位で見たい | Inspector と Security Hub の有効化と課金が前提。Issue はリポジトリに作られない。Code Security の所見は Security Hub CSPM に送られない [E-046]。AWS Security Hub（OCSF）は第三者の所見を受けず、独自の所見は CSPM にだけ出る [E-050]。Lambda のランタイム同梱の AWS SDK [E-047]、カスタマーマネージドキーで暗号化した関数 [E-048]、90 日以内に呼び出しも更新もない関数 [E-049] はスキャンの対象外 |

同じ脆弱性が SBOM 由来の所見と Inspector の所見の両方に現れた場合、Issue は SBOM 由来の所見からだけ作る。Inspector の所見は Security Hub CSPM の側で扱い、修正はリポジトリ側の Issue で行う。Inspector でスキャンされない範囲は、集約ジョブでも見えない。「Issue にならない」を「Inspector で拾える」と読まない。

## 取り込み時の防御

対応する Well-Architected のベストプラクティスは SEC11-BP05、SEC11-BP06、SEC11-BP07 である。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) を参照する。

目的は、公開された直後の版、版を固定していない参照、来歴の確かめられない成果物を、リポジトリに入れないことである。

### 導入手順

1. リポジトリの `renovate.json` の `extends` に Renovate の共有プリセットを足す。参照は 40 桁の SHA かタグで固定し、ブランチ名で参照せず、参照を省かない。参照先は Hub の共有プリセット（`renovate/supply-chain`、自動マージ用の `renovate/supply-chain-automerge`）に限る。Hub 以外の `github>` や `local>` のプリセットは `extends` に置かない。Hub のプリセットは `extends` の最後に置く。Renovate の組み込みプリセットは、ゲートの許可リストにあるものだけを使える。
   - 許可リストにあるもの: `config:recommended`、`config:best-practices`、`helpers:pinGitHubActionDigests`、`helpers:pinGitHubActionDigestsToSemver`。
   - 許可リストにあるもの: ダッシュボード・コミットメッセージ・保守だけを変える `:` で始まる 7 件（例: `:dependencyDashboard`、`:semanticCommits`）と、引数つきのラベル付けの `:label(…)`、`:assignee(…)`、`:reviewer(…)`、`:timezone(…)`。
   - 許可リストにあるもの: `group:`、`mergeConfidence:`、`replacements:`、`workarounds:`、`monorepo:` の族。ただし名前に disable、skip、automerge、ignore、immediate、notpending、never、minimumreleaseage、enabled を含むものを除く。
   - 許可リストにないもの: それ以外の組み込みプリセット（例: `:disableRenovate`、`security:minimumReleaseAgeNpm`）。Hub のプリセットが定める設定を変えうるので、ゲートが失敗にする。
   - 入れ子の `extends` は、配列でも文字列でも、`packageRules` の中を含めて同じ許可リストで検査する（Renovate が入れ子の `extends` を解決するかは未確認で、open。解決するものとして守る）。許可リストは、各 Spoke の `renovate.json` に当ててから見直す。
   - ゲートは、Renovate が設定ファイルを探す順（`renovate.json`、`renovate.jsonc`、`renovate.json5`、`.github/` と `.gitlab/` の同じ 3 つ、`.renovaterc`、`.renovaterc.json`、`.renovaterc.jsonc`、`.renovaterc.json5`、`package.json` の `renovate` の 14 か所）で最初に見つかった 1 つを検査する。2 つ以上あれば失敗にする（Renovate は最初の 1 つしか読まず、どれを検査したかが曖昧になるため）。JSON として読めない JSONC、JSON5、拡張子なしのファイルを選んだ場合も失敗にする。自己ホストの `configFileNames` はリポジトリから見えないので、検査の範囲外である。
   - Hub は `supply-chain-preset-v*` のタグを、プリセットの JSON を添えた immutable release として公開する設計である（公開後にタグを別のコミットへ動かせない [G31]）。Hub のプリセットにタグが付くまでは、`extends` を足さない。仮のタグや推測した SHA を書かない。タグでの参照は、`github>…#<SHA>` の形が Renovate で解決されることをパイロットで 1 回確かめるまでの暫定として認める。
2. リポジトリ側の設定で `minimumReleaseAge`、`minimumReleaseAgeBehaviour`、`minimumReleaseAgePackageManager`、`automerge`、`platformAutomerge`、`internalChecksFilter`、`internalChecksAsSuccess`、`ignoreTests`、`prCreation`、`registryUrls`、`hostRules`、`ignorePresets` を上書きしない。`vulnerabilityAlerts` の `minimumReleaseAge`、`prCreation`、`ignoreTests` と、`enabled: false`、`osvVulnerabilityAlerts: false` も同じである。ゲートは、設定の木のどの深さに書かれていても検出して失敗にする。検査するのは、最上位、`packageRules` の各要素、manager ごとのオブジェクト（`npm` など）、更新種別のオブジェクト（`major` など）、`lockFileMaintenance` と `vulnerabilityAlerts` の中と、それらの入れ子である。名前が `minimumReleaseAge` で始まるキーは、`minimumReleaseAgeBuffer` と `minimumReleaseAgePackageManagerSync` を含め、すべて上書き禁止である。`hostRules`、`customManagers`、`regexManagers`、`customDatasources` の下は、設定の値ではなく定義なので対象にしない（`customManagers` が設定の値を持つかは未確認で、hypothesis）。`lockFileMaintenance` の直下の `enabled: false` は既定値と同じで、更新の停止ではないので違反にしない。`vulnerabilityAlerts` の直下は、専用の検査が見る。既存の `vulnerabilityAlerts`（有効、`security` ラベル）と `osvVulnerabilityAlerts`（有効）は同じ値で残す。
3. Cooldown の値を確かめる。メジャー更新は <!-- policy:cooldown_days.major -->7 日、pin を除くそれ以外の更新（マイナー、パッチ、digest を含む）は <!-- policy:cooldown_days.default -->3 日である。どちらも慣行の値で、実測に基づかない。pin（`pinDigest`）の更新は待たせない。すでに解決している内容を固定するだけの更新で、待たせると、リリースの頻繁なパッケージで pin が付かない期間が延びるためである [G1]。
4. 脆弱性修正の PR には Cooldown が働かないので、自動マージを使わず、人の承認レビューを必須にする。Renovate の文書によれば、脆弱性修正の PR は Cooldown を経ずに作られる [G1]。
5. GitHub の Dependabot アラートを有効にする。Renovate の脆弱性修正の経路は Dependabot アラートを読むので、無効なリポジトリでは修正 PR が作られない見込みである（hypothesis）[E-055]。
6. Renovate が Cooldown を適用しない更新（`lockFileMaintenance`）と推移的な依存には、パッケージマネージャー側の待ち時間を置く。値は Cooldown の通常の更新と同じ <!-- policy:package_manager_wait.default_days -->3 日で、ポリシーファイルには書かず `cooldown_days` から導出する（直前のマーカーは、検証ゲートが `cooldown_days` の値と比べる印である。ポリシーファイルのスキーマは `package_manager_wait` を任意の項目として受けるが、持てるのは `default_days` だけで、`cooldown_days.default` と同じ値でなければならない。`major_days` は拒否される。書かなくてよい）。パッケージマネージャーの待ち時間はロックファイルの全パッケージに一律に適用されるので、メジャー更新だけ別の値にはならない。ツールごとの設定名と単位は、次の表のとおりである。

   | ツール | 設定名 | 単位 | 確認状況 |
   |---|---|---|---|
   | npm | `min-release-age` | 日（整数） | [G3] で確認。ゲートが値を比べる |
   | pnpm | `minimumReleaseAge`（`pnpm-workspace.yaml`） | 分（3 日なら 4320） | ゲートが分として比べる。pnpm の文書は読んでいない（未確認） |
   | uv | `exclude-newer`（`pyproject.toml`） | `N days` の形 | ゲートが日数として比べる。uv の文書は読んでいない（未確認） |
   | pip | `--uploaded-prior-to` | 絶対時刻 | ゲートは比べない。pip の文書は読んでいない（未確認） |

7. 本番の依存を完全なバージョンで固定する。Python は `==`、npm は演算子を付けない完全なバージョンである。サードパーティの GitHub Actions は 40 桁のコミット SHA で固定し、ツールは完全なバージョンとイメージの `sha256:` ダイジェストで固定する。Hub の `cooldown-pinning-check` が、固定と、Cooldown の値のポリシーファイルとの一致を検査する。
8. Hub の `vex-validate` と `cooldown-pinning-check` を、40 桁の SHA で固定して呼び出し側ワークフローから呼ぶ（記述例は[疎結合な更新](#疎結合な更新)の節）。
9. リリース成果物を出すリポジトリは、[来歴証明の検証](#来歴証明の検証)の節の手順を導入する。

### 脆弱性修正とパッケージマネージャーの待ち時間

パッケージマネージャー側の待ち時間を置いたリポジトリでは、脆弱性修正の PR は Renovate の Cooldown を経なくても、パッケージマネージャーの待ち時間は経る。修正版の公開から待ち時間が経つまでは、ロックファイルの更新が失敗し、PR に artifact error が出る [G1]。この間の対応は次のとおりである。

1. 保守者が、修正対象のパッケージ 1 件だけを除外する変更（npm は `min-release-age-exclude`、他のツールは同等の除外）を PR で出す。
2. 保守者が、公開日時とアドバイザリを確かめてから、除外を入れる。
3. 修正をマージしたら、除外を外す。

検証ゲートは、`.npmrc` に `min-release-age-exclude` が 1 件以上残っていると警告を出す（失敗にはしない）。`npm audit fix` も、待ち時間のために修正版を入れられない場合がある [E-056]。

### 脆弱性修正 PR の確認項目

脆弱性の修正を装った悪意のあるリリースは、Cooldown を経ないで PR になりうる。承認者は、修正 PR をマージする前に、次を確かめる。

- PR 本文の公開日時（Age）と、差分、提供元の変化
- 修正先の版が、OpenSSF の Malicious Packages [G21] に載っていないこと

Renovate の悪意のあるパッケージの検出は、文書上 experimental で、`osvVulnerabilityAlerts` の中でだけ動く [G2]。「Renovate が悪意のある版の PR を作らない」とは書かず、悪意のあるパッケージへの備えとして頼らない。マージ後に `MAL-` の記録が公開されれば、集約ジョブが起票する。

### 公開日時を返さないレジストリのイメージ

リリース日時を返さないレジストリ（GHCR、Quay、ECR）にあるイメージの digest と pin の更新は、`minimumReleaseAgeBehaviour` の既定（`timestamp-required`）では保留され続ける [E-045]。このプロジェクトは `timestamp-required` を保ち、そのイメージの更新は、自動マージの対象外のまま PR の作成までにとどめる。保守者が PR で公開日時を確認する。外す場合は、個別のルールで `timestamp-optional` を設定する。外すと、そのイメージには Cooldown が働かない。

### GitHub Actions の Cooldown の限界

Renovate は、SHA で固定した Actions の更新が使う `github-tags` の公開日時を、コミットの `committedDate`（push の時刻ではない）とする。既存のタグを強制 push しても、digest 更新は元のリリース日で判定される [G1]。そのため、Actions に対する <!-- policy:cooldown_days.default -->3 日の Cooldown は、タグの付け替え型の侵害に対する防御として数えない（hypothesis。過去の日付のコミットを指すテスト用タグが経過判定を通るかは、実行して確かめていない）。第三者の Actions の更新は自動マージしない（ポリシーファイルの `automerge.exclude` の `third_party_action`）。

### Cooldown の値の根拠と限界

採用は、通常の更新が 3 日、メジャー更新が 7 日である。比べた案は、7 日と 14 日である。ここでいう「窓」は、悪意のある版が公開されてから取り下げられるまでの時間である。

- 3 日と 7 日: 通常の更新の遅れが小さい。窓が 3 日より短い侵害は防げるが、窓が同じかそれより長い侵害は防げない。
- 7 日と 14 日: 取り下げまでの窓が 3 日を超えて 7 日以下の侵害も、通常の更新で防げる場合がある。通常の更新が 1 週間遅れ、機能の更新が遅れる。脆弱性修正は Cooldown を飛ばすので、修正の遅れは増えない。

どちらの値も、公開から取り下げまでの窓の実測に基づかない。窓の長さを集計した公開の記事（二次情報で、標本が小さい）はあるが、一次情報を読んでいないので、この文書は根拠にしない。パイロットで、違反件数と更新の遅れを測ってから、値を見直す。

### SHA の選び方

サードパーティの Actions は、40 桁のコミット SHA で固定し、版のコメント（`# v4.2.2` の形）を残す。コメントがあると、Renovate がタグと SHA を合わせて更新できる。SHA は、fork ではなく Action のリポジトリのものかを確かめて選ぶ [G32]。

`make check-pinned-sha-exist`（ネットワークが要るので `make test` に入らない）は、SHA が参照先に実在することに加えて、そのコミットが既定ブランチの祖先か、版のコメントのタグが指すコミットと一致することを GitHub に問う。fork にだけあるコミットは、コミットの取得 API が成功しても見抜けないからである。GitHub が文書化する workflow dependency lockfile は、成熟度を確認できていないので、SHA 固定の代わりにしてよいかは `open` とし、パイロットの後に決める。それまでは SHA 固定を求める。

### 対応するポリシーファイルの項目と参照の記述例

対応する項目は `cooldown_days.default`、`cooldown_days.major`、`dependency_scope.non_production_paths`、`renovate_preset`（任意。Hub がタグを公開した後に、タグと 40 桁の `commit` を記録する）である。パッケージマネージャー側の待ち時間は `cooldown_days` から導出する。`renovate.json` の記述例を示す。`<タグ>` は Hub でプリセットにタグが付いた時点の値に置き換える。

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "github>Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook//renovate/supply-chain#<タグ>"
  ],
  "vulnerabilityAlerts": { "enabled": true, "labels": ["security"] },
  "osvVulnerabilityAlerts": true
}
```

この参照の形が Renovate で解決されることは、実行では確かめていない（[現在の状態](#現在の状態)）。プリセットを解決できないときは、参照を直前の SHA かタグに戻す。ポリシーファイルに `renovate_preset` を記録した場合、Spoke の参照の `#` 以降はその `tag` か `commit` と一致させる。`make check-pinned-sha-exist` は、Hub のタグがその `commit` を指すかを確かめ、指さなければ `tag-moved` として失敗する。

### ツールの選び方

Cooldown の置き場所は 3 つの選択肢がある。順位は付けず、組み合わせてよい。

| 選択肢 | 向いている状況 | トレードオフ |
|---|---|---|
| Renovate の `minimumReleaseAge`（採用） | 更新 PR を作る時点で待たせたい。値を Hub のプリセット 1 か所に置きたい | pin、`lockFileMaintenance`、推移的な依存には及ばない。GHCR、Quay、ECR のイメージの digest 更新は保留され続ける [E-045] |
| パッケージマネージャー側の待ち時間 | 推移的な依存と、Renovate を通らない `install` も覆いたい。ポリシーファイルの `cooldown_days` と同じ日数にそろえる | 単位と設定名がツールごとに違い、ゲートが読むファイルが増える。npm では待ち時間のために `npm audit fix` が修正版を入れられない場合がある [E-056] |
| 待ち時間を置かない | 修正を最短で取り込みたい。更新の数が少なく、人が全件を見られる | 悪意のあるリリースが取り下げられる前に取り込まれうる。公開直後の版を人が毎回確かめる手間がかかる |

固定の方式にも選択肢がある。コミット SHA またはダイジェストでの固定は、参照先の差し替えを防ぐ一方、更新を Renovate の PR で受ける運用が前提になる。タグでの固定は読みやすいが、タグが付け替えられうる。ロックファイルとハッシュ付きの取り込み（`npm ci`、`--require-hashes`）は推移的な依存まで固定する一方、必須にするかはパイロットで違反件数を測ってから決める。

## 疎結合な更新

対応する Well-Architected のベストプラクティスは SEC11-BP06 である。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) を参照する。

目的は、依存やワークフローの更新を、小さく、戻せる形で入れることである。更新が壊れたときの影響範囲を、更新を取り込んだリポジトリに限る。

### 導入手順

1. 1 つのリポジトリでは、更新 PR を作るボットを Renovate だけにする。Dependabot のバージョン更新 PR とは併用しない。Dependabot アラートは、[取り込み時の防御](#取り込み時の防御)の手順 5 のとおり有効のままにする。
2. Hub の再利用可能ワークフローの呼び出しを、40 桁の SHA で固定し、版のコメント（`# <タグ>`）を付ける。版のコメントがあると、Renovate が SHA とタグを合わせて更新できる。
3. Hub のワークフローが壊れたときは、参照 SHA を直前の SHA に戻す PR を作り、CI が通ればマージする。Hub の修正を待たずに実行できる。参照 SHA を壊れた版へ更新した Spoke だけが止まり、直前の SHA を参照し続ける Spoke は影響を受けない。戻ったことは、呼び出し側のジョブが成功で終わることで確かめる。
4. Hub のワークフローを参照する更新は自動マージしない（ポリシーファイルの `automerge.exclude` の `hub_reusable_workflow`）。自動マージすると、検証ゲートの変更が Cooldown の後に全 Spoke へ自動で入る。
5. Lambda 関数の更新は、段階的なデプロイとアラームによる自動ロールバックを使う。このリポジトリの [`templates/event-driven.yaml`](../../templates/event-driven.yaml) の `EventTransformerLambda` が参照実装である。`AutoPublishAlias: live`、`DeploymentPreference` の `Canary10Percent10Minutes`、`RuntimeManagementConfig` の `UpdateRuntimeOn: FunctionUpdate` を持つ。巻き戻しの条件は、4 つのアラーム（新しい版のエラー数、新しい版がキューへ返したレコード数、新しい版の実行時間がタイムアウトの半分を超えること、関数単位のスロットリング）と、トラフィックを移す前に実ハンドラへ試験メッセージを送る `PreTraffic` フックの失敗である。エイリアス全体（旧版と新版の合計）のエラー数のアラームは通知専用で、巻き戻しには使わない。旧版のエラーで、正常な新版を巻き戻さないためである。CodeDeploy のデプロイが失敗または停止したときは、EventBridge のルールが既存のセキュリティ通知トピックへ送る。アラームのしきい値は実測に基づかない（hypothesis）。テンプレートを読んで構成を確かめ、cfn-lint、cfn-guard、Checkov を通しただけで、デプロイしてトラフィックの移行とロールバックを観測してはいない。実デプロイでの確認は第 2 の柱で行う。
6. セルフマネージドの ONTAP のバージョンアップは、[ONTAP のバージョンアップ手順](../ontap-native/ontap-upgrade-for-security-advisories.md)に従う。

### 対応するポリシーファイルの項目と参照の記述例

対応する項目は `automerge.exclude`、`automerge.include`、`automerge.enabled_repositories` である。呼び出し側ワークフローの記述例を示す。`<40 桁の SHA>` は Hub の再利用可能ワークフローが公開された時点の値、`policy-ref` はこのリポジトリの 40 桁の SHA に置き換える。

```yaml
jobs:
  supply-chain:
    uses: Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/.github/workflows/cooldown-pinning-check.yml@<40 桁の SHA> # <タグ>
    with:
      policy-ref: <このリポジトリの 40 桁の SHA>
    permissions:
      contents: read
```

`policy-ref` を使う構成では、検証の本体をこのリポジトリのチェックアウトから実行する。このリポジトリに到達できない場合や、`policy-ref` のコミットが消えた場合は、呼び出しジョブが止まる。

### ツールの選び方

更新を作るボットは 3 つの選択肢がある。順位は付けない。

| 選択肢 | 向いている状況 | トレードオフ |
|---|---|---|
| Renovate（採用） | 共有プリセットを Hub の 1 か所から配り、Cooldown と自動マージの範囲を複数のリポジトリでそろえたい | 実行基盤（Renovate の GitHub App など）の運用が要る。Dependabot のバージョン更新 PR と併用すると PR が重複する |
| Dependabot のバージョン更新 | GitHub の内蔵機能だけで済ませ、追加の実行基盤を置きたくない | この取り組みのゲートとポリシーファイルは Renovate の設定を読む前提なので、使う場合は同じ検査を別に用意する。共有設定を Hub から配る仕組みは、この取り組みでは用意していない |
| 手動で更新する | すべての更新を人が見たい。リポジトリの数と依存が少ない | 更新の数に比例して手間が増え、見落としが出やすい |

## 自動マージの対象と対象外

自動マージするのは、4 条件をすべて満たす更新だけである。(a) 開発用として宣言された依存、または GitHub が所有する Actions（`actions/` 以下）の更新、(b) パッチ更新、(c) Cooldown を経過している、(d) ブランチ保護で必須とされたすべての CI チェックが成功している。1 つのリポジトリでは Renovate だけが更新 PR を作る構成を前提とし、Dependabot のバージョン更新 PR とは併用しない。

### 対象と対象外

| 更新の種類 | 自動マージ | 理由 |
|---|---|---|
| npm の `devDependencies` のパッチ更新 | 対象 | 開発用として宣言された依存で、更新種別がパッチ |
| `actions/` 以下の GitHub の Actions のパッチ更新 | 対象 | GitHub が所有する Actions で、更新種別がパッチ |
| 第三者の GitHub Actions の更新 | 対象外 | タグの付け替えを経過判定が見抜けない可能性が高い（[GitHub Actions の Cooldown の限界](#github-actions-の-cooldown-の限界)）。PR を作るまでで、人が確認する |
| 実行時の依存の更新 | 対象外 | デプロイ成果物に入る。PR を作るまでで、人が確認する |
| マイナー更新とメジャー更新 | 対象外 | 挙動の変更を含みうる。PR は開いたまま残る |
| digest だけの更新 | 対象外 | 版番号が変わらず、パッチ更新と判別できない |
| 開発用か実行時かを判別できない依存（Python の `requirements-dev.txt` など） | 対象外 | Renovate の `pip_requirements` がファイル名から開発用かどうかを判別するかは確かめていない（hypothesis）。判別できないものは対象外にする |
| 脆弱性修正の PR | 対象外 | 悪意のあるリリースを装いうる。人の承認レビューを必須にする |
| Hub の再利用可能ワークフローの更新 | 対象外 | 検証ゲートの変更が全 Spoke に自動で入るのを避ける |

### 実際に適用される範囲

プリセットが自動マージを許すのは 2 種類だけなので、リポジトリの構成によっては、自動マージはほとんど適用されない。

| リポジトリの構成 | 適用 | 備考 |
|---|---|---|
| npm の `devDependencies` | パッチ更新に適用 | マイナー以上は PR までで止まる |
| `actions/` 以下の GitHub の Actions | パッチ更新に適用 | 第三者の Actions と Hub の再利用可能ワークフローは除く |
| Python 中心（`requirements.txt`、`pyproject.toml`） | 適用されない | 開発用か実行時かを判別できず、対象外になる。Python 中心のリポジトリでは自動マージを期待しない |
| AWS CDK（npm の `dependencies`） | 適用されない | 実行時の依存として扱う |
| コンテナイメージの digest | 適用されない | digest だけの更新は対象外 |

### 有効にする条件と手順

自動マージは、全リポジトリで無効にして始める。ポリシーファイルの `automerge.enabled_repositories` は空の配列で始まり、確認が済んだリポジトリを 1 つずつ足す。

1. 保守者が、リポジトリの既定ブランチのルールセットに、必須の CI チェックが 1 つ以上あることを確かめる。必須のチェックが 1 つもないと、GitHub の自動マージはテストの完了を待たずにマージしうる。これは Renovate の文書に基づく設計上の理解で、実行では確かめていない。
2. 保守者が `docs/agent/automerge-required-checks.json` に、リポジトリごとの必須チェックの件数を手で書く（`{"required_checks": {"<所有者>/<名前>": 件数}}`）。集約ジョブの出力で自動に置き換えることはしない。このファイルは、有効にするリポジトリが出た時点で保守者が作る。ゲートは、`enabled_repositories` の各リポジトリに 1 以上の件数がなければ失敗する。
3. ポリシーファイルの `automerge.enabled_repositories` にそのリポジトリを足す。
4. そのリポジトリの `renovate.json` の `extends` に、自動マージ用のプリセット（`renovate/supply-chain-automerge`）を、本体のプリセットの後に足す。`enabled_repositories` にないリポジトリがこのプリセットを参照すると、ゲートが失敗する。
5. 最後に、リポジトリの `allow_auto_merge` を有効にする。

### 方式の選び方

自動マージの方式は 3 つの選択肢がある。順位は付けない。

| 方式 | 向いている状況 | トレードオフ |
|---|---|---|
| Renovate の `platformAutomerge`（GitHub の自動マージ。採用） | 必須チェックの完了を GitHub に待たせたい | 必須チェックがないリポジトリでは、即時のマージになりうる（hypothesis）。ルールセットの設定に依存するため、設定の確認が済むまで無効にして始める |
| Renovate 自身のマージ（`platformAutomerge: false`） | GitHub の自動マージ機能を有効にしたくない | Renovate の次の実行までマージが遅れる。状態チェックの判定を Renovate が行う |
| 自動マージなし | すべての更新を人が見たい | レビューの手間が更新の数に比例して増える |

## VEX の運用

VEX は、特定の版の構成要素について「その脆弱性は影響しない」といった判断を、根拠つきで記録する仕組みである。形式は [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) v0.2.0 [G4] で、リポジトリの `.vex/` に置く。

### 運用の規則

- 1 つの VEX 文書には 1 つの判断（statement）だけを書く。判断者は個人名やメールアドレスではなく、役割名（VEX の承認者）で記録する。
- AI エージェントが作る判断案は補助信号で、最終判断ではない。判断案の作成者が AI であることを、判断ごとに記録する。
- 承認されていない判断は、Issue を止める根拠に使わない。承認とは、VEX の承認者が Code Owners として PR をレビューし、その PR が既定ブランチにマージされることをいう。
- 判断が対象とする構成要素の版と、所見の版が一致しないときは、その判断を使わない。構成要素の版が変われば、判断は効力を失う。
- 判断が Issue を止められるのは、所見の主の識別子が、statement 自身の `vulnerability.name` または `aliases` に書かれているときだけである。所見が持つ別名は照合に使わない。複数の CVE が共有する GHSA を名前とする statement は、自身の `aliases` にその CVE を書かない限り、どの CVE の所見も止めない。同じ GHSA を持つ別の CVE の所見が消えても、この扱いは変わらない。所見の別名だけと一致した statement は、除外に使わない。Issue を開く閾値を満たす所見については、実行結果の `rejected_vex` に理由 `vex_names_finding_alias_only` で記録し、計画の `vex_name_only_ghsa`（リポジトリ、所見の主の識別子、statement のパス）に載せ、その所見の Issue の状態ブロックに `vex_names_alias_only` としてパスを書く。`vulnerability.name` には Issue の題名に出る識別子（CVE があれば CVE）を書く。GHSA で判断したいときは、`aliases` に CVE を書く。悪意のあるパッケージの所見だけは別名も照合し、一致した statement を `malicious_package_not_suppressible` として記録する（除外はしない）。1 つの statement は、`name` と `aliases` を合わせて、異なる CVE を 2 つ以上名指ししない（識別子は、前後の空白を除き大文字にそろえてから数える）。
- 判断の時刻は、statement の `timestamp`、なければ文書の `timestamp` である。同じ脆弱性と構成要素の版に複数の判断があるときは、時刻が最も新しいものだけを使う。除外する状態の statement が、より新しい除外しない状態の statement に負けたときは、その statement が名指しするどの識別子でも除外に使われない場合だけ、`vex_superseded` を記録する。一部の識別子でだけ負けた statement は、残りの識別子で除外に使うので記録しない。OpenVEX v0.2.0 に上書きを示す欄はなく、新旧は時刻で決まる。判断を再確認したときは、新しい `timestamp` で出し直す。
- <!-- policy:vex.max_age_days -->180 日より古い判断と、実行時刻より 5 分を超えて先の時刻の判断は使わない。判断の後で脆弱性が KEV に載ったときも、その判断は使わず、再レビューを求める。所見の識別子（主の識別子と別名）のうち、最も新しい KEV の掲載日を使い、判断と同じ日の掲載も後とみなす。使わなかった判断は、実行結果の `rejected_vex` に理由（`vex_expired`、`vex_superseded`、`vex_timestamp_in_future`、`vex_predates_kev`、`vex_names_finding_alias_only`）とともに記録する。
- `not_affected` と `fixed` の判断には、空でない `impact_statement` を付ける。`not_affected` は確認した事実とその場所、`fixed` は修正された版と確認の方法を書く。`justification` のラベルだけでは根拠として足りない。付いていない判断は使わず、`vex_missing_impact_statement` を記録する。
- 検証ゲートは、`.vex/` の判断について、`impact_statement` の欠落、先の時刻、purl でない `products`、異なる CVE を 2 つ以上名指しする statement（種別 `multi-cve`）を失敗にする。期限切れと上書きは、警告にとどめる。KEV 掲載後の再レビューは KEV のカタログが要るので、ゲートは判定せず、集約ジョブが記録する。
- `products` には構成要素の purl を置く。OpenVEX の `subcomponents` は使わない独自の運用で、他の VEX 対応ツールとの互換は保証しない。
- 集約ジョブだけが `.vex/` を読む。層 B のスキャナーには VEX を渡さない。
- 脆弱性識別子が `MAL-` の判断は、状態が `not_affected` でも `fixed` でも、Issue を止める根拠に使わない。悪意のあるパッケージは VEX で除外できない。
- `not_affected` は「影響がない」という記録であり、修正しないことのリスクの受容ではない。リスクを受け入れて修正しない場合は、VEX ではなく、Issue のコメントなど別の記録に残す。
- `vulnerable_code_not_in_execute_path` のように、実行の有無を根拠にする判断には、証拠（解析の手段、呼び出し経路）を添える。証拠のない判断は承認しない。

### 所有者が 1 人のリポジトリでの制約

VEX の承認は、リポジトリのルールセットで強制する。設定は 3 つある。GitHub の設定項目「必須の承認レビュー数」を 0 にする。「Code Owners のレビューを必須にする」を有効にする。CODEOWNERS には `/.vex/` だけを書く。PR の作成者以外の VEX の承認者（人）のレビューが、`.vex/` を変える PR のマージの条件になる。AI エージェントのレビューは、この条件に数えない。`.vex/` を含まない PR は、承認なしでマージできる。

所有者が 1 人の個人アカウントのリポジトリでは、次の制約がある。

- 所有者とは別の身元（GitHub App または専用アカウント）の AI エージェントが VEX の PR を作り、所有者が承認する運用だけが、`.vex/` の PR のマージ条件を満たす。この身元の権限は、`.vex/` を含む PR の作成だけにする。Issues への書き込みと、既定ブランチへの Contents の書き込みは持たせない。
- 所有者自身が VEX の PR を作る運用は、`.vex/` の PR のマージ条件を満たさない。所有者は自分の PR を承認できないので、マージの条件を満たせない。
- 別の身元を用意するまで、AI エージェントが VEX の PR を作る運用を始めない。身元の用意は保守者の操作で、AI エージェントはその代わりをしない。

設定の検証は 2 つで行う。所有者が作った `.vex/` の PR がマージできないことと、`.vex/` を含まない PR がマージできることを、どちらも確かめる。

### 月 1 回の見直し

誤った `not_affected` は、その (リポジトリ, 脆弱性, 版) の組の Issue を止めたままにする。影響は組に限られ、構成要素の版が変われば判断は効かなくなる。月に 1 回、承認済みの VEX 文書の根拠と構成要素の版を照合する。誤りが見つかったら、VEX の承認者が該当の VEX 文書を削除する（または `affected` に変える）PR を承認してマージする。次の集約ジョブの実行で、その所見の Issue が再オープンまたは起票されることで確かめる。あわせて、ルールセットの `bypass_actors` が空であることを GitHub の REST API で確かめる。

## 来歴証明の検証

来歴証明は、リリース成果物がどのコミットとどのワークフローから作られたかを、成果物を取り込む側が検証できるようにする。目標の段階は SLSA の Build L2 [G7] で、各リポジトリが自身のワークフローで `actions/attest` を使う [G5]。

### 出す側の導入

1. リリースワークフローに `actions/attest`（SHA 固定）を足し、成果物ごとに 1 件の attestation を作る。ジョブの権限は `id-token: write`、`attestations: write`、`contents: read` である。
2. 公開のステップを来歴のステップの後に置き、`needs` でつなぐ。attestation の生成に失敗したら、リリースを公開しない。
3. attestation の bundle を `*.sigstore.json` としてリリースに添付する。リリースの SBOM にも付ける。
4. Hub の再利用可能ワークフローの中でビルドと attestation まで行う形は L3 に当たる。この取り組みは L3 を採らない。Hub が壊れたときの影響がリリースにも及び、導入先がさらに限られるためである。L3 は、実行どうしの分離が得られる選択肢である。

2026-11-10 の確認では、対象リポジトリのどれもリリース成果物の添付、公開レジストリへのパッケージ公開、イメージの push をしていなかった。GitHub Packages にパッケージがあるかは、`read:packages` の権限がなく確かめられなかった。[FSx-for-ONTAP-Observability-integrations](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations) はリリースを 6 件持つが添付は 0 件で、添付を始めたときが最初の導入先になる。公開レジストリへパッケージを出し始める時点で、そのレジストリの文書を読み直して、公開の基準を決める。

### 成果物の利用者の検証手順

コマンドは `gh attestation verify` である [G6]。

```bash
gh attestation verify <成果物のファイル> \
  --repo <所有者>/<名前> \
  --signer-workflow <所有者>/<名前>/.github/workflows/<file>
```

1. 照合する値は 3 つある。成果物のダイジェスト（コマンドがファイルから計算する）、期待するリポジトリ（`--repo`）、期待するワークフローのファイルパス（`--signer-workflow`）である。L2 では、期待するワークフローは各リポジトリ自身のものである。
2. 成功の判定は終了コードが 0 であることとする。出力の文言は版で変わりうるので、終了コードを正とする。
3. attestation がない、ダイジェストが一致しない、リポジトリまたはワークフローが期待と異なるときは、検証が失敗する。失敗した成果物は取り込まない。

### 固定したツールの配布物の確かめ方

SBOM の生成と走査に使うツールは、完全な版とダイジェストで固定する。固定した版の配布物が本物かを、次の順で確かめる。

1. リリースが immutable release かを確かめる [G31]。そうでなければ、リリースの資産が後から差し替えられうるものとして扱う。
2. `checksums.txt` があれば、取得したファイルのハッシュと照合する。
3. sigstore の bundle があれば、署名を検証する。
4. SLSA の来歴があれば、期待するリポジトリとワークフローを検証する。
5. どれもなければ、ダイジェストで固定したことだけを根拠にし、配布物の確かめを省いたことを記録する。

トレードオフは、確かめに使うツール（cosign、slsa-verifier など）自身を固定して更新する対象が増えることである。

## 対応時間の目標

対応時間の目標は「目標」である。運用で実測するまで、SLO とは書かない。値はポリシーファイルの `response_target` にあり、この文書の数値はポリシーファイルと一致させてある。

| 項目 | 値 | 測る範囲 |
|---|---|---|
| 検出 | <!-- policy:response_target.detect_hours -->24 時間 | 検出の起点から Issue の起票まで |
| 修正（KEV 掲載、または悪意のあるパッケージ） | <!-- policy:response_target.fix_days_kev_or_malicious -->7 日 | Issue の起票からクローズまで |
| 修正（CVSS 重大度が High 以上で、KEV に掲載されておらず、悪意のあるパッケージでもない） | <!-- policy:response_target.fix_days_high -->14 日（参照値） | Issue の起票からクローズまで |

High 以上（KEV 非掲載）の <!-- policy:response_target.fix_days_high -->14 日は参照値で、パイロットの実績を見て、14 日のまま使うか 30 日に延ばすかを決める。KEV 掲載で High 以上の所見には 7 日を適用する。High 以上で開いた Issue の脆弱性が後から KEV に載ったときは、期限を、既存の期限と、掲載を検出した実行から 7 日後のうち早い方に更新する。

KEV だけで満たす場合（次の段落）を除き、検出の起点は次の 2 つのうち遅い方である。1 つ目は、所見が起票の条件を初めて満たした日時（CVSS で満たす場合はアドバイザリの公開日時、悪意のあるパッケージの場合はフィードの項目の公開日時）。2 つ目は、集約ジョブがその構成要素の版を初めて観測した実行の日時である。起点を取得できない Issue は、起点を「不明」と記録して検出の実績から除き、除いた件数を実行結果に残す。

KEV だけで満たす場合は、起点を下限と上限の 2 つの日時で記録する。KEV の掲載日は日付だけで時刻を持たないので、下限は掲載日の UTC 00:00:00、上限は集約ジョブがそのエントリーを最初に読んだ KEV のカタログの公開日時（`dateReleased`）とする。エントリーは遅くとも `dateReleased` までに公開されているので、実際の起点は下限と上限のあいだにある。検出の実績は、下限と上限のそれぞれから起票までの時間で測る。24 時間の目標を外したと言えるのは、上限から測っても 24 時間を超えたときだけである。下限から測ってだけ超えたときは「外した可能性がある」と数え、確実な超過に入れない。

検出の目標 24 時間は、この取り組みの内部の目標である。EU のサイバーレジリエンス法が製造者に求める、悪用中の脆弱性の当局への早期警告（気づいてから 24 時間以内）の期限ではない [G25]。この法の報告義務は 2026-09-11 に始まっている（EU 委員会の [Cyber Resilience Act - Reporting obligations](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)、参照日 2026-11-14）。この取り組みの Issue の起票日時は、製品の製造者にとって「気づいた時点」の記録になりうる。自分のリポジトリの成果物が EU 市場に出る製品に当たるか、自分が製造者に当たるかの判断は、サービス提供者が自身の法務の確認で行う。この文書は、その判断を示さない。

### 自分の値への置き換え手順

この手順は、このリポジトリの保守者が値を変えるときの手順である。自分のリポジトリに導入する場合は、ポリシーファイルを写した後に、同じ手順で値を変える。

1. ポリシーファイルの `response_target` の 3 つの値（`detect_hours`、`fix_days_kev_or_malicious`、`fix_days_high`）を、自分の目標に書き換える PR を出す。値は正の整数で、負の値や整数でない値はパーサーが拒否する。
2. 同じ PR で、導入ガイドの日本語版と英語版にある `policy:` で始まるマーカー（HTML コメント）の直後の数値を、同じ値に書き換える。3 本の柱の全体方針の文書にも同じマーカーがある。
3. `guide-values` ゲート（`scripts/supply_chain_checks/guide_values.py`）は、この文書と 3 本の柱の全体方針の文書にある `policy:` マーカー直後の数値が、ポリシーファイルの値と一致することを確かめる。不一致のときは、マーカー、期待する値、ファイルと行を示して失敗する。`make check-supply-chain` が実行し、`make test` の前提に入っている。
4. 変更後、次の月次の確認（[実績を PDCA に使う方法](#実績を-pdca-に使う方法)の節）で、実績が新しい目標に対してどう出るかを見る。

### SLO と呼べるようになる条件

対応時間の目標は、次の条件を満たすまで SLO と呼ばない。

1. SLI は、評価期間内に起票または修正の期限を迎えた Issue のうち、期限内に起票または修正が完了した件数の割合とする。検出と修正は別の SLI にする。分母は、期限を迎えた時点で開いていた Issue のうち、クローズ理由が `resolved` または未クローズのものとし、`vex_not_affected` と `withdrawn` を入れない。検出の SLI は起票した Issue だけを数え、起票されなかった所見を数えない。起票の漏れは、月 1 回の確認で別に見る。
2. 評価期間は、暦日 28 日の移動窓とする。
3. 評価期間に期限を迎えた Issue が、検出と修正のそれぞれ 20 件以上あることを、昇格の最低条件とする。20 件は目安で、hypothesis である。件数が足りない間は、割合ではなく、件数と個別の理由を記録する。
4. 昇格する前は、期限超過の Issue を実行結果に記録するのに加えて、Issue に `response-target-overdue` ラベルを付け、保守者の確認の対象にする。ラベルを付ける実装は Hub 側にあり、公開済みの版が付けるかは確かめていない。
5. 昇格後に置く目標の割合（たとえば検出 95%、修正 90%）は、パイロットの実績で決める。測る前に値を固定しない。
6. 昇格後に目標の割合を 2 評価期間続けて下回ったときは、20 件の最低条件に戻って SLO と呼ぶことをやめ、昇格前の運用に戻す。

### 他の資料の期限との比較

対応時間の目標の参照値を置き換えるときの材料として、公的な資料の期限を要約する。これらの期限は、それぞれの資料が対象とする組織や制度の参加者に課すもので、この取り組みにもサービス提供者にも適用されない。どの値が正しいかの判断でもない。各行の出典は、表の「出典」列の番号で[参考文献](#参考文献)に示す。

| 区分の考え方 | 期限の例 | 起点 | 適用される相手 | 出典 |
|---|---|---|---|---|
| CVSS の基本値またはベンダーの重大度で区分する公的な例（2 件） | High 以上（CVSS 7 以上）で 14 日 | 更新のリリース | 認証や評価の制度に参加する組織 | [G27]、[G28] |
| 公開の有無、KEV 掲載、攻撃者の自動化の可否、技術的な影響の 4 つの変数で区分する公的な指令（CVSS は使わない） | 3 日、14 日、60 日、次のシステム更新時 | KEV への追加と、資産での特定の早い方 | その指令が定める行政機関 | [G29] |

この取り組みの修正の起点は Issue の起票である。起票の前に、検出の起点から起票までの検出の目標（24 時間）がある。そのため、表の期限と同じ起点では比べられない。KEV 掲載の 7 日は、表の 2 行目の 3 日と 14 日の間にある。

対応時間の目標はガバナンス上の指針であり、法務、コンプライアンス、規制上の判断ではない。

## 実績を PDCA に使う方法

集約ジョブは Issue ごとに、起点、検出、起票、クローズの日時と、クローズの理由（`resolved`＝修正による解消、`vex_not_affected`、`vex_fixed`、`withdrawn`、`feed_version_delisted`、`below_threshold` の 6 つ）を記録する。実行結果は、`runs/` 以下に追記専用で保存する。各記録は、同じ月の前の記録のハッシュ（`prev_record_sha256`）を持つので、記録の編集、削除、差し替えは連鎖の切れとして見張りが検出する（記録の書式は版 2）。修正の実績は、修正による解消の Issue だけを対象に、3 つの段階に分けて見る。

- 検出から起票まで
- 起票から修正の PR まで
- PR からマージまで

脆弱性修正の PR は自動マージしないので、人のレビューの待ち時間が修正の実績の大部分になりうる。3 つに分けるのは、遅れの場所を見分けるためである。

### 月 1 回の確認手順

1. Check: 集約ジョブの実行結果で、リポジトリごとの「修正の期限を過ぎて開いたままの Issue の件数」と、「起票した Issue のうち検出の実績が 24 時間を超えた件数」を確認する。起点が不明で除いた件数も見る。検出の実績が 24 時間を超えた件数は、KEV 掲載だけで起票した Issue では、上限に対しても超えた件数だけを「確実な超過」として数える。下限に対してだけ超えた件数は「外した可能性がある」として別に数える。集約ジョブが止まっていた間のエントリーでは、止まっていた期間（実行結果で確かめる）の分だけ、上限は実際の公開より遅くなりうる。
2. Check: 遅れが 3 つの段階のどこにあるかを見る。レビュー待ちなら人の割り当て、検出から起票なら集約ジョブの間隔とフィードの取得失敗を疑う。
3. Act: 期限超過が続く場合は、対応時間の目標を現実に合わせて変えるか、遅れの原因を直すかを決める。待ち時間（Cooldown）が修正の遅れの原因なら、Cooldown の値を見直す。
4. Act: 値を変えるときは、[自分の値への置き換え手順](#自分の値への置き換え手順)に従い、ポリシーファイルとこの文書の数値を同じ PR で直す。
5. 版や日付を持つ参考文献の現行の版を確かめる。Well-Architected Framework の版、SLSA の版、OpenVEX の版、EPSS のモデルの版、Renovate の版である。
6. 承認済みの VEX 文書を見直す（[VEX の運用](#月-1-回の見直し)）。

Check は Well-Architected の OPS09-BP01（運用の目標を指標で測る）、Act は OPS11-BP02（インシデント後の分析で予防策を特定する）に当たる。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) を参照し、ここには写さない。

### パイロットで確かめる項目

パイロットの期間は、2 件の両方で集約ジョブが初めて所見の一覧を作った実行の日時から、14 暦日を既定とする。期間のあいだ、適用先はこのリポジトリと Hub の 2 件だけである。誤検知率は、検出器が誤ったと判断された Issue の件数を、起票した Issue の件数で割って出す。起票した Issue が 20 件に届かないまま期間が終わるときは、同じ期間を延長できる（14 暦日ずつ最大 2 回、合計 42 暦日まで）。

分子は、VEX の承認者が `justification` を `component_not_present` として `not_affected` と判断した件数と、保守者が検出器の誤りと分類した件数の合計である。`fixed` または `affected` と判断した Issue と、それ以外の理由で `not_affected` と判断した Issue は誤検知に数えず、別の件数として記録する。重複した Issue（別の Issue の重複として扱った側）は分母にも数えず、件数だけを別に記録する。判断が済んでいない件数（`under_investigation` の statement しかない Issue を含む）も別に記録し、分母には含める。

判断が済んでいない Issue が起票した Issue の 20% を超える間は、判断してから率を出す（20% は暫定の値で、hypothesis）。起票した Issue が 20 件に届かない間は、率を算出せず件数だけを記録する。あわせて、High 以上の修正の目標を 14 日のまま使うか 30 日に延ばすかを決める。

延長しても 20 件に届かないときは、率ではなく、手順 3 の条件で、手順 1 の件数と手順 2 の目視をもとに、次のリポジトリの組（バッチ）へ進むかを決める。
判断の記録は、保守者が決める固定の 1 か所に、日付を付けて追記する記録である。置き場はこのガイドでは決めていない（`open`）。次のバッチへ進むか、適用済みのリポジトリを維持するかロールバックするか、検出器を作り直すかの判断と、その理由を書く。次のバッチへ進む判断基準は、誤検知率の上限値、取得失敗として記録されたリポジトリの件数の上限値、呼び出し側ワークフローの CI 失敗の有無の 3 つで、取得失敗の上限値と CI 失敗の有無の条件は、値をパイロットの前に判断の記録へ書く。誤検知率の上限値は値を未決のまま、決め方と記録先を事前に書き、値はパイロットで決める。取得失敗の上限値または CI 失敗の条件が決まっていないとき、および誤検知率の上限値が未決のまま起票した Issue が 20 件以上になったときは、次のバッチへ進まない。事前に書かなかったときは、値を書いた時点以降に起票した Issue だけで観察をやり直し、書いた日時を判断の記録に残す。保守者の操作の一覧は、ルールセット、Code Owners、Dependabot アラートが無効と確認したリポジトリでの有効化、自動マージの許可、VEX の PR を作る VEX 用の身元の用意、Hub の既定ブランチへ 30 日を超えない間隔でコミットを push すること、確認コマンド `gh api 'repos/<Hub の所有者>/<Hub のリポジトリ>/actions/workflows?per_page=100' --jq '.workflows[] | select(.state != "active" and .state != "deleted") | .name'` の実行である。

1. 次の 6 つの件数を記録する。起票した Issue、検出器の誤りと分類した Issue、`component_not_present` 以外の理由で `not_affected` と判断した Issue、`fixed` と判断した Issue、`affected` と判断した Issue、判断が済んでいない Issue である。検出器の誤りと分類した Issue は、statement の状態によらず、誤りに 1 回だけ数える。起票した Issue の件数は、ほかの 5 つの件数の和に等しくなる。重複した Issue はこの 6 つの件数に含めない。
2. 起票した Issue を、保守者が 1 件ずつ目視で判定する。
3. 起票した Issue が 20 件未満のあいだ、次のバッチへ進めるのは、次の 6 点をすべて満たすときだけである。検出器の誤りが 2 件以下であること、判断が済んでいない Issue が 0 件であること、検出器の誤りが起票した Issue の半数に届かないこと（半数ちょうどを含めて進めない）、取得失敗として記録されたリポジトリの件数が上限以内であること、呼び出し側ワークフローの CI 失敗がないこと、保守者の操作の一覧にある設定が確認済みであること。2 件は暫定の値で（hypothesis）、パイロットで決める。1 つでも満たさないときは進まない。誤検知率の上限値は、率を算出しない 20 件未満のあいだは使わない。この 6 点のそれぞれが成り立ったかと、判断が済んでいない Issue の件数を、判断の記録に書く。
   - 判断が済んでいない Issue の件数は、観察期間の終了の時刻で打ち切った Issue について数える。終了の後に起票された Issue は、この判断の件数に数えず、次の観察の最初の記録に、起票した件数として持ち越す。
   - 判断が済んでいない Issue が残ることだけが進めない理由のときは、期間を延長せず、保守者が判断を済ませてから、手順 3 の判断の記録を更新する。更新までは次のバッチへ進まない。この待機は延長の回数に数えない。待つ間も、Hub の既定ブランチへの 30 日を超えない間隔の push と確認コマンドを続ける。Hub が 60 日止まると集約ジョブが自動で無効になり、観察が黙って止まる。
   - `under_investigation` の statement は、上流の応答を待つ間も、判断が済んでいない Issue に数える。待つ間に決められる状態（`affected` として期限を付ける）にするか、決まるまで進まない。上流の応答を待つ間も、上と同じ push と確認コマンドを続ける。
   - 取得失敗の件数、呼び出し側ワークフローの CI 失敗、設定の未確認だけが進めない理由のときは、原因を直した後、観察をやり直さず、手順 3 の判断の記録を、直した内容と日時とともに更新して、進むかを評価し直す。この待機は延長にもやり直しにも数えない。待つ間も、上と同じ push と確認コマンドを続ける。直せないときは、適用済みのリポジトリを維持するかロールバックするかの判断を、判断の記録に書く。
   - 起票が 0 件のときは、起票した Issue の件数に 0 と書く。0 件では誤りの件数も半数未満かも判定できず、集計の結果が「条件が成り立つ」でも成り立った証拠ではないので、進む根拠にしない。延長を使い切っても 0 件のままのときは、偽陰性の検査を行う。そのバッチ（やり直しでは検出器を直した対象）のリポジトリのうち 1 件以上に、既知の脆弱性を持つ使い捨ての依存（KEV に載っておらず、CVSS が High のもの）を 1 件置き、24 時間以内に Issue が起票されたかを判断の記録に書き、確認後に依存を取り除く。検査が成功した記録があり、取得失敗の上限、CI 失敗、設定の確認の 3 点も満たすときは、保守者の判断で進める。検査用の Issue は件数に数えず、率の計算にも渡さない。検査で Issue が起票されなかったときは、検出器を直し、手順 4 のやり直しに数える。
4. 検出器の誤りが 3 件以上のとき、誤りが起票した Issue の半数以上のとき、起票した Issue が 20 件以上で誤検知率が上限値を超えるときは、次のバッチへ進まない。延長を使い切っても起票が 0 件のときは、手順 3 の偽陰性の検査が成功していなければ、次のバッチへ進まず、検出器を直してやり直す。成功していれば、保守者が手順 3 の条件で判断する。誤りがあるときは、保守者が誤りの原因を 1 件ずつ分類し、同じ原因が繰り返すかを判断して記録する。繰り返すときも繰り返さないときも、原因ごとに検出器を直してから、パイロットまたはそのバッチの観察をやり直す。
   - やり直しの観察期間は、直した検出器を集約ジョブが最初に使った実行の時刻から数え、長さはパイロットで 14 暦日、バッチで 7 暦日である。分母は、その時刻以降に起票した Issue だけである。直前の観察で起票した Issue は、開いたままでも数えない。バッチの観察では、起票した Issue をそのバッチのリポジトリに起票されたものに限り、それ以前のリポジトリの Issue は件数を別に記録する。やり直しの記録に、直前の観察の件数と、分母に数えなかった Issue の件数を書く。
   - やり直した観察で起票が 0 件のときは、直した検出器を確かめた証拠がないので、手順 3 の 0 件の扱いに従い、進まない。0 件の延長は使えるが、延長の回数に数える（パイロットは最大 2 回、バッチは起票が 0 件のときだけ）。使い切った後は、手順 3 の偽陰性の検査に従う。
   - やり直しは延長の回数に数えず、延長もやり直しの回数に数えない。やり直しは 3 回までで（暫定の値で、hypothesis。パイロットで決める）、3 回目でも進めないときは、観察を打ち切る。保守者が、適用済みのリポジトリを維持するか、ロールバック（適用したリポジトリの設定を元に戻すこと）するかと、検出器を作り直すかを判断し、その理由を判断の記録に書く。作り直した検出器は新しい検出器として、やり直しの回数を 0 から数える。数え直したことも判断の記録に書く。
5. 延長しても 20 件に届かなかったとき（起票が 0 件のままのときを含む）は、率を算出せず、20 件に届かなかったことを判断の記録に書く。起票が 0 件のまま延長を使い切ったときは、手順 3 の偽陰性の検査の結果を判断の記録に書いてから、進むか止めるかを決める。
1 回の実行で 1 つのリポジトリへの新規起票が上限に達して、次のバッチを止めたときは、原因が初回の一括起票か、継続的な起票かを分類して記録する。初回の一括起票は、そのリポジトリの最初の実行で上限に達した場合で、それ以外は継続的な起票である（暫定の分類で、hypothesis）。初回の一括起票のときは、上限を超えてまとめ Issue に載った Finding が次の実行以降にすべて個別に起票された後に、手順 3 を判定する。起票した Issue の件数には、個別に起票した Issue だけを数える。継続的な起票のときは、手順 3 を判定せず、適用済みのリポジトリを維持するかロールバックするかの判断を、判断の記録に書く。
## Well-Architected との関係

この文書の Well-Architected のベストプラクティス ID との対応は、AWS Well-Architected のレビューの結果ではなく、AWS による承認でもない。ベストプラクティスのページを読み、構成要素が同じ話題を扱うと読んだものである。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) にだけ置き、この文書は写さない。参照した版は v13（2024-11-06）である [G18]、[G19]。

サービス提供者は、自分のワークロードを [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/) でレビューし、決定と改善を記録できる。NIST CSF 2.0 への対応も、同じ mapping の[節](cyber-resilience-framework-mapping.md#pdca-と説明責任の-csf-20-への対応)にあり、NIST による認定ではない。どちらの対応も、法務、コンプライアンス、規制上の判断ではなく、ガバナンス上の指針である。

## 参考文献

この文書が依拠する文献を、名称（発行主体が付けた原題）、発行主体、公開日と版、URL、参照日（その URL の内容を確認した日）、根拠の種別の順に並べる。日付が表示されていない文献は、その旨を書く。名称は日英どちらの版でも原題のままである。日付は日本時間で、公開日は各ページに表示された日付である。番号は本文の `[Gn]` に対応する。G はこの導入ガイドの番号で、3 本の柱の全体方針の `[n]` とは別の番号体系である。`[E-nnn]` で引いた文献は、[evidence-ledger.json](../agent/evidence-ledger.json) の出典の欄にも同じ URL がある。

| 番号 | 名称 | 発行主体 | 公開日・版 | URL | 参照日 | 根拠の種別 |
|---|---|---|---|---|---|---|
| G1 | Minimum Release Age | Renovate | 日付の表示なし | [docs.renovatebot.com](https://docs.renovatebot.com/key-concepts/minimum-release-age/) | 2026-11-13 | documented |
| G2 | Configuration Options | Renovate | 日付の表示なし | [docs.renovatebot.com](https://docs.renovatebot.com/configuration-options/) | 2026-11-13 | documented |
| G3 | config (npm CLI v11) | npm | v11 | [docs.npmjs.com](https://docs.npmjs.com/cli/v11/using-npm/config) | 2026-11-13 | documented |
| G4 | OpenVEX Specification | OpenVEX | v0.2.0 | [github.com/openvex](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | 2026-11-10 | documented |
| G5 | Using artifact attestations | GitHub | 日付の表示なし | [docs.github.com](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) | 2026-11-10 | documented |
| G6 | gh attestation verify | GitHub | 日付の表示なし | [cli.github.com](https://cli.github.com/manual/gh_attestation_verify) | 2026-11-10 | documented |
| G7 | Build: Track Basics | OpenSSF SLSA | v1.2 | [slsa.dev](https://slsa.dev/spec/v1.2/build-track-basics) | 2026-11-12 | documented |
| G8 | REST API endpoints for software bill of materials (SBOM) | GitHub | API 版 2026-03-10 | [docs.github.com](https://docs.github.com/en/rest/dependency-graph/sboms) | 2026-11-13 | documented |
| G9 | Exporting SBOMs with Amazon Inspector | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html) | 2026-11-13 | documented |
| G10 | Amazon Inspector integration with AWS Security Hub CSPM | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/securityhub-integration.html) | 2026-11-13 | documented |
| G11 | Amazon Inspector Lambda standard scanning | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/scanning_resources_lambda.html) | 2026-11-13 | documented |
| G12 | Scanning AWS Lambda functions with Amazon Inspector | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/scanning-lambda.html) | 2026-11-13 | documented |
| G13 | AWS Security Hub FAQs | AWS | 日付の表示なし | [aws.amazon.com](https://aws.amazon.com/security-hub/faqs/) | 2026-11-13 | documented |
| G14 | Software bill of materials (AWS Security Hub User Guide) | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html) | 2026-11-13 | documented |
| G15 | AWS Security Hub now provides an SBOM inventory for your compute resources | AWS | 2026-11-06 | [aws.amazon.com](https://aws.amazon.com/about-aws/whats-new/2026/11/security-hub-sbom-inventory/) | 2026-11-12 | documented |
| G16 | AWS Security Hub Pricing | AWS | 日付の表示なし | [aws.amazon.com](https://aws.amazon.com/security-hub/pricing/) | 2026-11-12 | documented |
| G17 | GetSoftwareV2 (AWS Security Hub API Reference) | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetSoftwareV2.html) | 2026-11-13 | documented |
| G18 | AWS Well-Architected Framework | AWS | v13（2024-11-06） | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html) | 2026-11-13 | documented |
| G19 | What is AWS Well-Architected? | AWS | 2026-10-01（ページの Last updated） | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/userguide/well-architected.html) | 2026-11-10 | documented |
| G20 | Well-architected best practices for software supply chain security | AWS Security Blog | 公開日の表示を取得できなかった | [aws.amazon.com](https://aws.amazon.com/blogs/security/well-architected-best-practices-for-software-supply-chain-security/) | 2026-11-10 | documented（ブログの記述）。公開日は open |
| G21 | OpenSSF Malicious Packages | OpenSSF | 日付の表示なし | [github.com/ossf](https://github.com/ossf/malicious-packages) | 2026-11-10 | documented |
| G22 | OSV.dev Data Sources | OSV.dev | 日付の表示なし | [google.github.io](https://google.github.io/osv.dev/data/) | 2026-11-10 | documented |
| G23 | Known Exploited Vulnerabilities Catalog | CISA | catalogVersion 2026.11.09 | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 2026-11-10 | verified（取得 1 回） |
| G24 | GET /epss (FIRST.Org REST API Documentation) | FIRST | API は BETA と表示 | [api.first.org](https://api.first.org/epss/) | 2026-11-12 | documented。応答の形は verified（1 回） |
| G25 | Cyber Resilience Act - Reporting obligations | European Commission | 日付の表示なし | [digital-strategy.ec.europa.eu](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | 2026-11-14 | documented |
| G26 | MCP Security Crisis: Systemic Design Flaws in AI Agent Infrastructure | Cloud Security Alliance (CSAI Foundation) | 2026-05-04（研究ノート。文書自身が AI 支援で作成され、CSA の正式なレビューを経ていないと記載している） | [labs.cloudsecurityalliance.org](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf) | 2026-11-10 | documented |
| G27 | ★3・★4要求事項・評価基準（Ver.1.1:2026年10月28日） | 経済産業省 | Ver 1.1、2026-10-28 | [xlsx](https://www.meti.go.jp/policy/netsecurity/docs/scs/SCS-400-criteria-v1.1.xlsx) | 2026-11-12 | documented |
| G28 | Cyber Essentials: Requirements for IT Infrastructure v3.3 | NCSC（UK National Cyber Security Centre） | v3.3、2026 年 4 月 | [ncsc.gov.uk](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf) | 2026-11-13 | documented（読んだ節は Security Update Management） |
| G29 | BOD 26-04: Prioritizing Security Updates Based on Risk | CISA | 2026-06-10 | [cisa.gov](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) | 2026-11-13 | documented（Table 1 は画像のため、画像を見て読んだ） |
| G30 | Reuse workflows | GitHub | 日付の表示なし | [docs.github.com](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows) | 2026-11-14 | documented |
| G31 | Immutable releases | GitHub | 日付の表示なし | [docs.github.com](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) | 2026-11-14 | documented |
| G32 | Secure use reference | GitHub | 日付の表示なし | [docs.github.com](https://docs.github.com/en/actions/reference/security/secure-use) | 2026-11-14 | documented |
| G33 | Events that trigger workflows | GitHub | 日付の表示なし | [docs.github.com](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) | 2026-11-14 | documented（読んだ節は `schedule`） |

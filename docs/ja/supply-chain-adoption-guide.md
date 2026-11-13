# サプライチェーン導入ガイド（第 1 の柱）

> **概要**: 第 1 の柱「ソフトウェアサプライチェーンの可視化と対応」を、自分のリポジトリ群に導入する手順をまとめる。4 つの構成要素（棚卸し、悪用可能性に基づく検出と優先順位付け、取り込み時の防御、疎結合な更新）ごとに、目的、導入手順、対応する Policy_File の項目、固定した参照の記述例、ツールの選び方を書く。Hub 側の部品（再利用可能ワークフロー 3 種と Renovate の共有プリセット）は引き継ぎ中で、この文書の参照先はプレースホルダである。数値は [`docs/agent/supply-chain-policy.json`](../agent/supply-chain-policy.json)（Policy_File）の値と一致させてある。

## 想定する読者

読者は 2 通りを想定する。1 つは Service_Owner の役割で、パートナー / SI、システム担当、アプリ担当を含む。もう 1 つは、それらの役割の代わりに作業する AI エージェントである。どちらも、リポジトリの保守者が決めた方針と承認の範囲の中で作業する。AI エージェントは次の 3 点を守る。

- 判断案を作るだけで、VEX の承認、自動マージの有効化、Response_Target の変更は人の承認なしに行わない
- 数値は [Policy_File](../agent/supply-chain-policy.json) から読み、この文書の値を写して使わない
- 「できない」「載らない」と書かれた箇所の `[E-nnn]` は、[evidence-ledger.json](../agent/evidence-ledger.json) の登録番号である。登録のない主張を足さない

用語は次のとおり。初出以降はこの名前で呼ぶ。

| 用語 | 意味 |
|---|---|
| Policy_File | 閾値、待ち時間、自動マージの範囲、対象リポジトリ、対応時間の目標を持つ JSON。この文書の数値の基準 |
| Aggregator | 各リポジトリの SBOM と脆弱性情報を突き合わせ、リポジトリに Issue を起票する Hub の定期ジョブ |
| Finding | Aggregator が作る 1 件の所見（リポジトリ、脆弱性、構成要素の版の組） |
| Opening_Threshold | Issue を起票する条件。CVSS 重大度が High 以上、CISA KEV に掲載、または悪意のあるパッケージ（Malicious_Package_Finding） |
| VEX_Reviewer | VEX の判断を承認する人の役割 |
| Response_Target | 検出と修正の時間の目標。SLO とは呼ばない |
| Cooldown | 公開直後の版を取り込まない待ち時間 |
| Hub | Reusable_Workflow と Renovate_Preset を置くリポジトリ [FSx-for-ONTAP-Adoption-Playbook](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook) |

programme 全体の位置づけと 3 本の柱は [Programme_Document](cyber-resilience-programme.md) にある。この文書は第 1 の柱の導入だけを扱う。

## 4 つの構成要素と範囲

| 構成要素 | 何をするか | 主な部品 |
|---|---|---|
| 棚卸し | 何がどこに入っているかを機械可読に持つ | SBOM、Infrastructure_Component_Ledger、Agent_Component_Inventory |
| 検出と優先順位付け | 悪用されやすいものと悪意のあるパッケージから先に Issue にする | Aggregator、OpenVEX |
| 取り込み時の防御 | 公開直後の版と未固定の参照を入れない | Renovate_Preset、検証ゲート、来歴証明 |
| 疎結合な更新 | 更新を小さく、戻せる形で入れる | 自動マージ方針、Lambda_Canary_Reference |

### 範囲外と固定の限界

範囲外は次のとおり。AIBOM / ML-BOM の形式は作らず、エージェント構成要素の記録は SBOM の外の独自の JSON のままにする。.NET（NuGet）、Terraform、Dockerfile の `FROM` のダイジェスト固定は、この柱の検査の対象に含めない。第 2 段で扱う対象として記録している。

固定には限界がある。次の 3 点は、固定済みと表示されても残るリスクである。

- 版の固定は、MCP サーバーが返すツール定義の変更を覆わない（hypothesis。設計上の推論で、ベンダーの記述ではない）。ツール定義の変更の検知は、この柱のゲートに含めていない。Cloud Security Alliance の研究ノートは、使用中の MCP サーバーの棚卸しと版の固定、定義変更の検知を推奨している。このノートは、自身が AI 支援で作成され、正式なレビューを経ていないと書いている（[参考文献](#参考文献)）
- 最上位の固定（`npx -y <pkg>@<x.y.z>` や `image@sha256:…`）は、推移的な依存を固定しない。依存の木ごとに固定するにはロックファイルが要る
- ダイジェストで固定したイメージは、セキュリティ更新を自動では取り込まない。更新は Renovate の PR で人が受ける

Cooldown の <!-- policy:cooldown_days.default -->3 日は慣行の値で、実測に基づかない。メジャー更新の <!-- policy:cooldown_days.major -->7 日に対応する外部の値も見つけていない。パイロットで、待ち時間のために遅れた修正の件数を見て見直す。

Amazon Inspector の AI inventory は、自前で動かす AI のフレームワークを EC2 と ECR のイメージから見つける機能で、Security Hub の FAQ に記述がある。リポジトリのファイルを数えるこの柱の Agent_Component_Inventory とは対象が違う。実行中のリソースの補完になりうるが、ユーザーガイドは読んでいないので、使う前に確かめる。

### 公式の設定例を固定した形に書き換えた例

MCP クライアントの設定例は、多くが版を指定しない `uvx <pkg>` や `npx -y <pkg>`、タグだけのイメージで書かれている。固定した形は次のとおり。`<x.y.z>` と `<64 桁>` はプレースホルダで、公式リリースを確認して決める。クライアントごとの設定ファイル名とキーの名前は、各クライアントの文書で確かめる。この文書では 7 つのクライアントの個別の文書を確かめていない。

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

`url` だけで指定するリモートのサーバーは、固定の対象ではなく「該当なし」と記録する。名前だけの推奨（宣言ファイルがない記述）は、宣言ファイルを置くか、この文書に断りを書く。

## 棚卸し

対応する Well-Architected のベストプラクティスは SEC11-BP02 と SEC11-BP05 である。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) にあり、ここには写さない。

目的は、脆弱性が公開された時点で「自分のどのリポジトリのどの版が該当するか」を、人が探し回らずに答えられる状態にすることである。

### 導入手順

1. Policy_File の `target_repositories`（12 件）に自分のリポジトリがあるかを確かめる。ない場合は Policy_File に足す変更を PR で出す。`excluded_repositories` の 4 件（BLEA の上流とフォーク）は欠かさない。
2. 層 A（GitHub の依存関係グラフ）を有効にする。Aggregator が API で SBOM を取る。GitHub の同期 SBOM エクスポート API は 2026-11-13 以降使えない [E-044]。非同期の `generate-report` と `fetch-report` の経路を使う。
3. 層 B（CI でのスキャン）として、呼び出し側のワークフローで Hub の `sbom-generate` を 40 桁の SHA で固定して呼ぶ。成果物 `sbom-<commit-sha>` は 90 日残る。90 日は公開リポジトリの上限で、非公開リポジトリを足すときは保存期間を 400 日まで選べる。
4. リリースを出すリポジトリは、リリースを作ったコミットの SBOM をリリースの添付ファイルにする。90 日を過ぎたリリースの構成は、作り直しで答えることになり、ツールの版が当時と違いうる。
5. エージェント構成要素（MCP サーバー、エージェント設定、インストール手順）を `docs/agent/agent-components.json` に記録し、未固定の箇所を 0 件にする。
6. ONTAP の版、Amazon FSx for NetApp ONTAP（以降 FSx for ONTAP）のファイルシステム、TrendAI と Deep Instinct のエージェントの版は、SBOM に載せず [`infrastructure-component-ledger.json`](../agent/infrastructure-component-ledger.json) に人が記録する。照合日から 90 日で再照合の対象になる。

### 対応する Policy_File の項目と参照の記述例

対応する項目は `target_repositories`、`excluded_repositories`、`dependency_scope.non_production_paths`（本番の依存の判定から外すパス。初期値は `tests/` と `docs/`）である。呼び出し側ワークフローの記述例を示す。`<40 桁の SHA>` は Hub で再利用可能ワークフローが公開された時点の値に置き換える。Hub にタグが付き、SHA 参照の解決を 1 回確かめるまでの暫定として、タグでの参照を許す。この文書の時点でタグが付いているかは確かめていない。

```yaml
jobs:
  sbom:
    uses: Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/.github/workflows/sbom-generate.yml@<40 桁の SHA> # <タグ>
    permissions:
      contents: read
```

### 棚卸しの手段の使い分け

行は手段、列は用途・前提・費用の扱い・制約である。順位は付けない。各手段の制約は同じ粒度（何が見えないか、何の準備が要るか）で書く。

| 手段 | 用途 | 前提 | 費用の扱い | 制約 |
|---|---|---|---|---|
| リポジトリの SBOM（層 A・B） | リポジトリが宣言する依存、Actions、コンテナイメージ、Lambda の構成要素を、脆弱性の公開時に Aggregator で突き合わせ、リポジトリに Issue を起こす | GitHub の依存関係グラフ（層 A）と CI のスキャン（層 B）。Reusable_Workflow `sbom-generate` | AWS の課金はない。GitHub Actions の実行時間 | デプロイ後に入ったもの（OS のパッケージ、手で入れたエージェント、ランタイムが同梱するライブラリ）は記録の範囲にない。リポジトリごとに CI を整える必要がある |
| Amazon Inspector の SBOM エクスポート（層 C） | Inspector が監視しているリソースの SBOM を CycloneDX 1.4 / SPDX 2.3 の JSON で S3 に書き出し、外部のツールや監査の記録に渡す | 対象の種別で Inspector が有効。書き出し先の S3 バケットと KMS キーのポリシー | Inspector のスキャンの料金（個別の料金、または Security Hub の Essentials）と、S3 と KMS の料金。書き出しそのものの料金は確かめていない | 書き出しを要求した時点の内容で、定期的に取り直す仕組みは利用者が作る。エージェントベースの EC2 Windows は書き出せない [E-052]。Lambda のランタイム同梱の AWS SDK [E-047]、カスタマーマネージドキーで暗号化した関数 [E-048]、90 日以内に呼び出しも更新もない関数 [E-049] は、Inspector がスキャンしない |
| SBOM_Inventory | あるパッケージと版が組織のどのリソースに入っているかを、コンソールか API で引く（リージョンをまたぐ集約で home Region に集めた分を含む） | アカウントとリージョンで AWS Security Hub が有効、種別ごとに Inspector が有効。組織全体を見るには委任管理者 | Essentials に追加料金なしで含まれる（[AWS What's New](https://aws.amazon.com/about-aws/whats-new/2026/11/security-hub-sbom-inventory/)、参照日 2026-11-12）。Essentials はリソース単位の課金で Inspector の標準スキャンを含む（[AWS Security Hub Pricing](https://aws.amazon.com/security-hub/pricing/)、参照日 2026-11-12）。Security Hub を有効にしていない環境では使えない（[Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html)、参照日 2026-11-13）。単価は書かない | 応答は名前・版・種類・件数だけで purl がなく、リポジトリの SBOM と直接は突き合わせられない [E-053]。FSx for ONTAP と ONTAP は載らない見込み（hypothesis）[E-054]。新しい SBOM の反映に数時間かかることがある。SPDX や CycloneDX での書き出しは、ユーザーガイドと API リファレンスに記述がない（書き出せないとは書かない。未確認） |
| Infrastructure_Component_Ledger | ONTAP の版、FSx for ONTAP のファイルシステム、TrendAI と Deep Instinct のエージェントの版を、NetApp と AWS のセキュリティアドバイザリと照合する | 人が照合して記録する手順。照合日から 90 日で再照合の対象 | AWS の課金はない。照合の人手 | 機械可読の SBOM ではなく、照合は人の手順（RSS 2.0 を正とする半自動の照合で、確定は人）。照合日より後の変化は次の照合まで反映されない |

選び方の手順は次のとおり。

1. 調べたい対象が、リポジトリの宣言か、デプロイ後のリソースか、ストレージとエージェントの基盤かを決める。
2. リポジトリの宣言なら層 A・B を使う。
3. デプロイ後のリソースで、どこに入っているかを組織全体で引きたく、AWS Security Hub を有効にしているなら SBOM_Inventory を使う。
4. デプロイ後のリソースの SBOM を機械可読の形で外に渡したい場合、または Security Hub を有効にしていない場合は層 C を使う。
5. ONTAP、FSx for ONTAP、エージェントは Infrastructure_Component_Ledger に記録する。
6. 2 つ以上に当てはまれば併用する。例として、SBOM_Inventory で見つけたリソースの SBOM を層 C で書き出し、purl で照合する。

この柱では Amazon Inspector と AWS Security Hub を有効にせず、課金が発生する操作をしない。有効化と費用の見積りは第 2 の柱で扱う。

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

1. Policy_File の `opening_threshold` を確かめる。既定は、CVSS 重大度が `HIGH` 以上、KEV 掲載、悪意のあるパッケージの 3 条件のどれかを満たせば Issue を起票する。EPSS は起票の判定に使わず、表示だけにする（`epss_used_for_opening` は `false`）。
2. Hub の Aggregator を有効にする。定期実行の間隔は 12 時間以下で、設計は 6 時間ごとである。Hub 側の実装は引き継ぎ中である。
3. Issue の件数を確かめる。1 回の実行で 1 リポジトリに新規起票する上限は <!-- policy:issue_limits.max_new_issues_per_repo_per_run -->10 件である。上限を超える場合は、KEV 掲載の Finding と悪意のあるパッケージの Finding を先に、残りを CVSS 重大度の高い順に起票し、超えた分はそのリポジトリの 1 件のまとめ Issue に列挙する。
4. 悪意のあるパッケージ（`MAL-` の識別子）は、重大度に関係なく起票する。VEX で除外しない（`open_if_malicious` は常に `true`）。重複排除の単位は (リポジトリ, purl, 版) で、同じ purl と版に GHSA（type=malware）と `MAL-` の両方があれば 1 件にまとめ、代表の識別子は `MAL-` を優先する。
5. 取り下げられた `MAL-` は、OSV の `GET /v1/vulns/{id}` の応答が成功し、`withdrawn` が時刻として読めた場合に限り、クローズ理由 `withdrawn` で閉じる。上流が記録の対象の版を外した場合は `feed_version_delisted` で閉じる。応答が取れない場合と `withdrawn` が読めない場合は閉じず、`malicious_withdrawn_open` として実行結果に残す。取り下げられた `MAL-` が再び現れたときは、閉じた Issue を開き直す。
6. Issue に載る項目を確かめる。脆弱性識別子、影響を受ける構成要素と版、CVSS 重大度、KEV 掲載の有無、悪意のあるパッケージかどうか、EPSS のスコアと取得日（モデルの版つき）、修正済みの版、検出日時、Response_Target の期限である。KEV の `knownRansomwareCampaignUse` は表示だけで、判定に使わない。

CVE のデータベースに依存するスキャナーは、CVE が付く前の悪意のあるパッケージを検出しない。AWS Security Blog がこの趣旨を述べている（[参考文献](#参考文献)のブログ記事。ガイダンスで、仕様ではない）。そのため、悪意のあるパッケージは OpenSSF Malicious Packages のフィードを OSV 経由で別に引く。

### 対応する Policy_File の項目

- `opening_threshold.min_cvss_severity`、`open_if_kev_listed`、`open_if_malicious`、`epss_used_for_opening`
- `issue_limits.max_new_issues_per_repo_per_run`
- `vex.exclude_statuses`、`vex.malicious_never_suppressed`（[VEX の運用](#vex-の運用)の節）
- `response_target.*`（[対応時間の目標](#対応時間の目標)の節）

### ツールの選び方

脆弱性の見つけ方は、見たい対象で選ぶ。次の表は 3 つの手段を同じ粒度で並べる。順位は付けない。

| 手段 | 向いている状況 | トレードオフ |
|---|---|---|
| Aggregator（採用） | 12 リポジトリを同じ閾値で横断し、リポジトリごとに Issue で追いたい | Hub の定期ジョブと外部フィード（KEV、EPSS、OSV）に依存する。Issue はリポジトリ単位なので、アカウントとリソース単位の Inspector の所見は起票の対象に含めない。ランタイム同梱のライブラリのような、リポジトリに対応しないデプロイ後の脆弱性は Issue にならない |
| GitHub の Dependabot アラートだけ | 追加の仕組みを置かず、リポジトリの画面でアラートを見たい | 閾値と期限をリポジトリごとの設定に頼る。Dependabot アラートが無効なリポジトリには、アラートも、アラートを読む Renovate の修正 PR も作られない見込み（hypothesis）[E-055]。悪意のあるパッケージの扱いは別に設ける必要がある |
| Amazon Inspector の所見（AWS Security Hub CSPM に集約） | デプロイ後の Lambda、ECR のイメージ、EC2 を、アカウントとリージョン単位で見たい | Inspector と Security Hub の有効化と課金が前提。Issue はリポジトリに作られない。Code Security の所見は Security Hub CSPM に送られない [E-046]。AWS Security Hub（OCSF）は第三者の所見を受けず、独自の所見は CSPM にだけ出る [E-050]。Lambda のランタイム同梱の AWS SDK [E-047]、カスタマーマネージドキーで暗号化した関数 [E-048]、90 日以内に呼び出しも更新もない関数 [E-049] はスキャンの対象外 |

同じ脆弱性が SBOM 由来の Finding と Inspector の所見の両方に現れた場合、Issue は SBOM 由来の Finding からだけ作る。Inspector の所見は Security Hub CSPM の側で扱い、修正はリポジトリ側の Issue で行う。Inspector でスキャンされない範囲は、Aggregator でも見えない。「Issue にならない」を「Inspector で拾える」と読まない。

## 取り込み時の防御

対応する Well-Architected のベストプラクティスは SEC11-BP05、SEC11-BP06、SEC11-BP07 である。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) を参照する。

目的は、公開された直後の版、版を固定していない参照、来歴の確かめられない成果物を、リポジトリに入れないことである。

### 導入手順

1. リポジトリの `renovate.json` の `extends` に Renovate_Preset を足す。参照は 40 桁の SHA かタグで固定し、ブランチ名で参照せず、参照を省かない。Hub にタグが付くまでは仮のタグを書かない。
2. リポジトリ側の設定で `minimumReleaseAge`、`automerge`、`platformAutomerge`、`internalChecksFilter` を上書きしない。ゲートが検出して失敗する。既存の `vulnerabilityAlerts`（有効、`security` ラベル）と `osvVulnerabilityAlerts`（有効）は同じ値で残す。
3. Cooldown の値を確かめる。通常の更新は <!-- policy:cooldown_days.default -->3 日、メジャー更新は <!-- policy:cooldown_days.major -->7 日である。どちらも慣行の値で、実測に基づかない。脆弱性修正の PR は、Renovate の文書によれば Cooldown を経ずに作られる。その分、自動マージせず、人の承認レビューを必須にする。
4. GitHub の Dependabot アラートを有効にする。Renovate の脆弱性修正の経路は Dependabot アラートを読むので、無効なリポジトリでは修正 PR が作られない見込みである（hypothesis）[E-055]。
5. Renovate が Cooldown を適用しない更新（pin、`lockFileMaintenance`）と推移的な依存には、パッケージマネージャー側の待ち時間を置く。値は Policy_File の `package_manager_wait` で、通常の更新が <!-- policy:package_manager_wait.default_days -->3 日、メジャー更新が <!-- policy:package_manager_wait.major_days -->7 日である。ツールごとの設定名は npm の `min-release-age`、pnpm の `minimumReleaseAge`、uv の `exclude-newer`、pip の `--uploaded-prior-to` である。単位が分・日・期間とツールごとに違う。npm 以外の名称と単位はこの文書では確かめていないので、各ツールの現行の文書で確かめる。
6. 本番の依存を完全なバージョンで固定する。Python は `==`、npm は演算子を付けない完全なバージョンである。サードパーティの GitHub Actions は 40 桁のコミット SHA で固定し、ツールは完全なバージョンとイメージの `sha256:` ダイジェストで固定する。Hub の `cooldown-pinning-check` が、固定と、Cooldown の値の Policy_File との一致を検査する。
7. Hub の `vex-validate` と `cooldown-pinning-check` を、40 桁の SHA で固定して呼び出し側ワークフローから呼ぶ（記述例は[疎結合な更新](#疎結合な更新)の節）。
8. リリース成果物を出すリポジトリは、[来歴証明の検証](#来歴証明の検証)の節の手順を導入する。

脆弱性の修正を装った悪意のあるリリースは、Cooldown を経ないで PR になりうる。修正 PR をマージする前に、人が差分、パッケージの公開日時、提供元の変化を確かめる。Renovate の `osvVulnerabilityAlerts` は experimental の機能なので、悪意のあるパッケージの備えとして頼らない。マージ後に `MAL-` の記録が公開されれば、Aggregator が起票する。

リリース日時を返さないレジストリ（GHCR、Quay、ECR）にあるイメージの digest 更新は、`minimumReleaseAgeBehaviour` の既定（`timestamp-required`）では保留され続ける [E-045]。このプロジェクトでは保留を受け入れる。外す場合は、個別のルールで `timestamp-optional` を設定する。外すと、そのイメージには Cooldown が働かない。

### 対応する Policy_File の項目と参照の記述例

対応する項目は `cooldown_days.default`、`cooldown_days.major`、`package_manager_wait.default_days`、`package_manager_wait.major_days`、`dependency_scope.non_production_paths` である。`renovate.json` の記述例を示す。`<タグ>` は Hub でプリセットにタグが付いた時点の値に置き換える。

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

この参照の形が Renovate で解決されることは、実行では確かめていない。プリセットを解決できないときは、参照を直前の SHA かタグに戻す。

### ツールの選び方

Cooldown の置き場所は 3 つの選択肢がある。順位は付けず、組み合わせてよい。

| 選択肢 | 向いている状況 | トレードオフ |
|---|---|---|
| Renovate の `minimumReleaseAge`（採用） | 更新 PR を作る時点で待たせたい。値を Hub のプリセット 1 か所に置きたい | pin、`lockFileMaintenance`、推移的な依存には及ばない。GHCR、Quay、ECR のイメージの digest 更新は保留され続ける [E-045] |
| パッケージマネージャー側の待ち時間 | 推移的な依存と、Renovate を通らない `install` も覆いたい | 単位と設定名がツールごとに違い、ゲートが読むファイルが増える。npm では待ち時間のために `npm audit fix` が修正版を入れられない場合がある [E-056] |
| 待ち時間を置かない | 修正を最短で取り込みたい。更新の数が少なく、人が全件を見られる | 悪意のあるリリースが取り下げられる前に取り込まれうる。公開直後の版を人が毎回確かめる手間がかかる |

固定の方式にも選択肢がある。コミット SHA またはダイジェストでの固定は、参照先の差し替えを防ぐ一方、更新を Renovate の PR で受ける運用が前提になる。タグでの固定は読みやすいが、タグが付け替えられうる。ロックファイルとハッシュ付きの取り込み（`npm ci`、`--require-hashes`）は推移的な依存まで固定する一方、必須にするかはパイロットで違反件数を測ってから決める。

## 疎結合な更新

対応する Well-Architected のベストプラクティスは SEC11-BP06 である。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) を参照する。

目的は、依存やワークフローの更新を、小さく、戻せる形で入れることである。更新が壊れたときの影響範囲を、更新を取り込んだリポジトリに限る。

### 導入手順

1. 1 つのリポジトリでは、更新 PR を作るボットを Renovate だけにする。Dependabot のバージョン更新 PR とは併用しない。Dependabot アラートは、[取り込み時の防御](#取り込み時の防御)の手順 4 のとおり有効のままにする。
2. Hub の再利用可能ワークフローの呼び出しを、40 桁の SHA で固定し、版のコメント（`# <タグ>`）を付ける。版のコメントがあると、Renovate が SHA とタグを合わせて更新できる。
3. Hub のワークフローが壊れたときは、参照 SHA を直前の SHA に戻す PR を作り、CI が通ればマージする。Hub の修正を待たずに実行できる。参照 SHA を壊れた版へ更新した Spoke だけが止まり、直前の SHA を参照し続ける Spoke は影響を受けない。戻ったことは、呼び出し側のジョブが成功で終わることで確かめる。
4. Hub のワークフローを参照する更新は自動マージしない（Policy_File の `automerge.exclude` の `hub_reusable_workflow`）。自動マージすると、検証ゲートの変更が Cooldown の後に全 Spoke へ自動で入る。
5. Lambda 関数の更新は、段階的なデプロイとアラームによる自動ロールバックを使う。このリポジトリの [`templates/event-driven.yaml`](../../templates/event-driven.yaml) の `EventTransformerLambda` が参照実装である。`AutoPublishAlias: live`、`DeploymentPreference` の `Canary10Percent5Minutes`、エイリアスのエラー数を見る CloudWatch アラーム、`RuntimeManagementConfig` の `UpdateRuntimeOn: FunctionUpdate` を持つ。テンプレートを読んで構成を確かめただけで、デプロイしてトラフィックの移行とロールバックを観測してはいない。実デプロイでの確認は第 2 の柱で行う。
6. セルフマネージドの ONTAP のバージョンアップは、[ONTAP のバージョンアップ手順](../ontap-native/ontap-upgrade-for-security-advisories.md)に従う。

### 対応する Policy_File の項目と参照の記述例

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
| Dependabot のバージョン更新 | GitHub の内蔵機能だけで済ませ、追加の実行基盤を置きたくない | この programme のゲートと Policy_File は Renovate の設定を読む前提なので、使う場合は同じ検査を別に用意する。共有設定を Hub から配る仕組みは、この programme では用意していない |
| 手動で更新する | すべての更新を人が見たい。リポジトリの数と依存が少ない | 更新の数に比例して手間が増え、見落としが出やすい |

## 自動マージの対象と対象外

自動マージするのは、4 条件をすべて満たす更新だけである。(a) 開発用の依存または GitHub Actions の更新、(b) パッチ更新、(c) Cooldown を経過している、(d) ブランチ保護で必須とされたすべての CI チェックが成功している。1 つのリポジトリでは Renovate だけが更新 PR を作る構成を前提とし、Dependabot のバージョン更新 PR とは併用しない。

### 対象と対象外

| 更新の種類 | 自動マージ | 理由 |
|---|---|---|
| npm の `devDependencies` のパッチ更新 | 対象 | 開発用として宣言された依存で、更新種別がパッチ |
| GitHub Actions のパッチ更新（Hub の再利用可能ワークフローを除く） | 対象 | 更新種別がパッチ |
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
| GitHub Actions | パッチ更新に適用 | Hub の再利用可能ワークフローは除く |
| Python 中心（`requirements.txt`、`pyproject.toml`） | 適用されない | 開発用か実行時かを判別できず、対象外になる。Python 中心のリポジトリでは自動マージを期待しない |
| AWS CDK（npm の `dependencies`） | 適用されない | 実行時の依存として扱う |
| コンテナイメージの digest | 適用されない | digest だけの更新は対象外 |

### 有効にする条件と手順

自動マージは、全リポジトリで無効にして始める。Policy_File の `automerge.enabled_repositories` は空の配列で始まり、確認が済んだリポジトリを 1 つずつ足す。

1. 保守者が、リポジトリの既定ブランチのルールセットに、必須の CI チェックが 1 つ以上あることを確かめる。必須のチェックが 1 つもないと、GitHub の自動マージはテストの完了を待たずにマージしうる。これは Renovate の文書に基づく設計上の理解で、実行では確かめていない。
2. 保守者が `docs/agent/automerge-required-checks.json` に、リポジトリごとの必須チェックの件数を手で書く（`{"required_checks": {"<所有者>/<名前>": 件数}}`）。Aggregator の出力で自動に置き換えることはしない。このファイルは、有効にするリポジトリが出た時点で保守者が作る。ゲートは、`enabled_repositories` の各リポジトリに 1 以上の件数がなければ失敗する。
3. Policy_File の `automerge.enabled_repositories` にそのリポジトリを足す。
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

VEX は、特定の版の構成要素について「その脆弱性は影響しない」といった判断を、根拠つきで記録する仕組みである。形式は [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) v0.2.0 で、リポジトリの `.vex/` に置く。

### 運用の規則

- 1 つの VEX 文書には 1 つの判断（statement）だけを書く。判断者は個人名やメールアドレスではなく、役割名（VEX_Reviewer）で記録する。
- AI エージェントが作る判断案は補助信号で、最終判断ではない。判断案の作成者が AI であることを、判断ごとに記録する。
- 承認されていない判断は、Issue を止める根拠に使わない。承認とは、VEX_Reviewer のレビューを含む PR が既定ブランチにマージされたことをいう。
- 判断が対象とする構成要素の版と、Finding の版が一致しないときは、その判断を使わない。構成要素の版が変われば、判断は効力を失う。
- Aggregator だけが `.vex/` を読む。層 B のスキャナーには VEX を渡さない。
- 脆弱性識別子が `MAL-` の判断は、状態が `not_affected` でも `fixed` でも、Issue を止める根拠に使わない。悪意のあるパッケージは VEX で除外できない。
- `not_affected` は「影響がない」という記録であり、修正しないことのリスクの受容ではない。リスクを受け入れて修正しない場合は、VEX ではなく、Issue のコメントなど別の記録に残す。
- `vulnerable_code_not_in_execute_path` のように、実行の有無を根拠にする判断には、証拠（解析の手段、呼び出し経路）を添える。証拠のない判断は承認しない。

### 所有者が 1 人のリポジトリでの制約

VEX の承認は、次のルールセットで強制する。承認の必須数は 0 で、Code Owners のレビューを必須とし、CODEOWNERS を `/.vex/` だけに置く。PR の作成者以外の VEX_Reviewer（人）のレビューが、`.vex/` を変える PR のマージの条件になる。AI エージェントのレビューは、この条件に数えない。`.vex/` を含まない PR は、承認なしでマージできる。

所有者が 1 人の個人アカウントのリポジトリでは、次の制約がある。

- 所有者とは別の身元（GitHub App または専用アカウント）の AI エージェントが VEX の PR を作り、所有者が承認する運用だけが、この条件を満たす。
- 所有者自身が VEX の PR を作る運用は、この条件を満たさない。所有者は自分の PR を承認できないので、マージの条件を満たせない。
- 別の身元を用意するまで、この運用を始めない。身元の用意は保守者の操作で、AI エージェントはその代わりをしない。

設定の検証は 2 つで行う。所有者が作った `.vex/` の PR がマージできないことと、`.vex/` を含まない PR がマージできることを、どちらも確かめる。

### 月 1 回の見直し

誤った `not_affected` は、その (リポジトリ, 脆弱性, 版) の組の Issue を止めたままにする。影響は組に限られ、構成要素の版が変われば判断は効かなくなる。月に 1 回、承認済みの VEX 文書の根拠と構成要素の版を照合する。誤りが見つかったら、VEX_Reviewer が該当の VEX 文書を削除する（または `affected` に変える）PR を承認してマージする。次の Aggregator の実行で、その Finding の Issue が再オープンまたは起票されることで確かめる。

## 来歴証明の検証

来歴証明（Provenance_Attestation）は、リリース成果物がどのコミットとどのワークフローから作られたかを、利用者が検証できるようにする。目標の段階は SLSA の Build L2 で、各リポジトリが自身のワークフローで `actions/attest` を使う。

### 出す側の導入

1. リリースワークフローに `actions/attest`（SHA 固定）を足し、成果物ごとに 1 件の attestation を作る。ジョブの権限は `id-token: write`、`attestations: write`、`contents: read` である。
2. 公開のステップを来歴のステップの後に置き、`needs` でつなぐ。attestation の生成に失敗したら、リリースを公開しない。
3. attestation の bundle を `*.sigstore.json` としてリリースに添付する。リリースの SBOM にも付ける。
4. Hub の再利用可能ワークフローの中でビルドと attestation まで行う形は L3 に当たる。この programme は L3 を採らない。Hub が壊れたときの影響がリリースにも及び、導入先がさらに限られるためである。L3 は、実行どうしの分離が得られる選択肢である。

2026-11-10 の確認では、Target_Repositories のどれもリリース成果物の添付、公開レジストリへのパッケージ公開、イメージの push をしていなかった。GitHub Packages にパッケージがあるかは、`read:packages` の権限がなく確かめられなかった。Observability-integrations はリリースを 6 件持つが添付は 0 件で、添付を始めたときが最初の導入先になる。公開レジストリへパッケージを出し始める時点で、そのレジストリの文書を読み直して、公開の基準を決める。

### 利用者の検証手順

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

1. リリースが immutable release かを確かめる。そうでなければ、リリースの資産が後から差し替えられうるものとして扱う。
2. `checksums.txt` があれば、取得したファイルのハッシュと照合する。
3. sigstore の bundle があれば、署名を検証する。
4. SLSA の来歴があれば、期待するリポジトリとワークフローを検証する。
5. どれもなければ、ダイジェストで固定したことだけを根拠にし、配布物の確かめを省いたことを記録する。

トレードオフは、確かめに使うツール（cosign、slsa-verifier など）自身を固定して更新する対象が増えることである。

## 対応時間の目標

Response_Target は「目標」である。運用で実測するまで、SLO とは書かない。値は Policy_File の `response_target` にあり、この文書の数値は Policy_File と一致させてある。

| 項目 | 値 | 適用する区間 |
|---|---|---|
| 検出 | <!-- policy:response_target.detect_hours -->24 時間 | 起点から Issue の起票まで |
| 修正（KEV 掲載、または悪意のあるパッケージ） | <!-- policy:response_target.fix_days_kev_or_malicious -->7 日 | Issue の起票からクローズまで |
| 修正（CVSS 重大度が High 以上で、KEV に掲載されておらず、悪意のあるパッケージでもない） | <!-- policy:response_target.fix_days_high -->14 日（参照値） | Issue の起票からクローズまで |

High 以上（KEV 非掲載）の <!-- policy:response_target.fix_days_high -->14 日は参照値で、パイロットで維持するか 30 日に戻すかを決める。KEV 掲載で High 以上の Finding には 7 日を適用する。High 以上で開いた Issue の脆弱性が後から KEV に載ったときは、期限を、既存の期限と、掲載を検出した実行から 7 日後のうち早い方に更新する。

起点は、次の 2 つのうち遅い方である。1 つ目は、Finding が Opening_Threshold を初めて満たした日時（CVSS で満たす場合はアドバイザリの公開日時、KEV だけで満たす場合は KEV の掲載日の UTC 00:00:00、悪意のあるパッケージの場合はフィードの項目の公開日時）。2 つ目は、Aggregator がその構成要素の版を初めて観測した実行の日時である。起点を取得できない Issue は、起点を「不明」と記録して検出の実績から除き、除いた件数を実行結果に残す。

検出の目標 24 時間は、この programme の内部の目標である。EU のサイバーレジリエンス法が製造者に求める、悪用中の脆弱性の当局への早期警告（24 時間以内）の期限ではない（[Cyber Resilience Act - Reporting obligations](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)）。

### 自分の値への置き換え手順

1. Policy_File の `response_target` の 3 つの値（`detect_hours`、`fix_days_kev_or_malicious`、`fix_days_high`）を、自分の目標に書き換える PR を出す。値は正の整数で、負の値や整数でない値はパーサーが拒否する。
2. 同じ PR で、この文書の `policy:` で始まるマーカー（HTML コメント）の直後の数値を、同じ値に書き換える。日本語版と英語版の両方を直す。
3. `guide-values` のゲートは、この文書のマーカー直後の数値が Policy_File と一致することを確かめ、不一致のときは値と記載箇所を示して失敗する。このゲートは追加の予定で、この文書の時点では実装されていない。一致は手で確かめた。
4. 変更後、次の月次の確認（[実績を PDCA に使う方法](#実績を-pdca-に使う方法)の節）で、実績が新しい目標に対してどう出るかを見る。

### 他の資料の期限との比較

Response_Target の参照値を置き換えるときの材料として、公的な資料の期限を要約する。これらの期限は、それぞれの資料が対象とする組織や制度の参加者に課すもので、この programme にも Service_Owner にも適用されない。どの値が正しいかの判断でもない。1 行目の 2 件のうち、評価制度の 1 件の出典は [Programme_Document](cyber-resilience-programme.md) の参考文献にある。もう 1 件と 2 行目の指令は、名称を載せない要約で、この文書の参考文献には含めていない。

| 区分の考え方 | 期限の例 | 起点 | 適用される相手 |
|---|---|---|---|
| CVSS の基本値またはベンダーの重大度で区分する公的な例（2 件） | High 以上（CVSS 7 以上）で 14 日 | 更新のリリース | 認証や評価の制度に参加する組織 |
| 公開の有無、KEV 掲載、攻撃者の自動化の可否、技術的な影響の 4 つの変数で区分する公的な指令（CVSS は使わない） | 3 日、14 日、60 日、次のシステム更新時 | KEV への追加と、資産での特定の早い方 | その指令が定める行政機関 |

この programme の修正の起点は Issue の起票で、起点から起票までの検出の目標（24 時間）が前にある。そのため、表の期限と同じ起点では比べられない。KEV 掲載の 7 日は、表の 2 行目の 3 日と 14 日の間にある。

Response_Target はガバナンス上の指針であり、法務、コンプライアンス、規制上の判断ではない。

## 実績を PDCA に使う方法

Aggregator は Issue ごとに、起点、検出、起票、クローズの日時と、クローズの理由（修正による解消、VEX による `not_affected`、`withdrawn`、`feed_version_delisted`）を記録する。修正の実績は、修正による解消の Issue だけを対象に、3 つの区間に分けて見る。

- 検出から起票まで
- 起票から修正の PR まで
- PR からマージまで

脆弱性修正の PR は自動マージしないので、人のレビューの待ち時間が修正の実績の大部分になりうる。3 つに分けるのは、遅れの場所を見分けるためである。

### 月 1 回の確認手順

1. Check: Aggregator の実行結果で、リポジトリごとの「修正の期限を過ぎて開いたままの Issue の件数」と、「起票した Issue のうち検出の実績が 24 時間を超えた件数」を確認する。起点が不明で除いた件数も見る。
2. Check: 遅れが 3 区間のどこにあるかを見る。レビュー待ちなら人の割り当て、検出から起票なら Aggregator の間隔とフィードの取得失敗を疑う。
3. Act: 期限超過が続く場合は、Response_Target を現実に合わせて変えるか、遅れの原因を直すかを決める。待ち時間（Cooldown）が修正の遅れの原因なら、Cooldown の値を見直す。
4. Act: 値を変えるときは、[自分の値への置き換え手順](#自分の値への置き換え手順)に従い、Policy_File とこの文書の数値を同じ PR で直す。
5. 版や日付を持つ参考文献の現行の版を確かめる。Well-Architected Framework の版、SLSA の版、OpenVEX の版、EPSS のモデルの版、Renovate の版である。
6. 承認済みの VEX 文書を見直す（[VEX の運用](#月-1-回の見直し)）。

Check は Well-Architected の OPS09-BP01（運用の目標を指標で測る）、Act は OPS11-BP02（インシデント後の分析で予防策を特定する）に当たる。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) を参照し、ここには写さない。

### パイロットで確かめる項目

最初の 14 暦日は、2 件のリポジトリだけに適用する。起票した Issue の件数を分母に、パイロット終了時点で VEX_Reviewer が `not_affected` と判断した件数を分子にして、誤検知率を出す。判断が済んでいない件数は別に記録する。起票が 0 件のときは、誤検知率を算出不能と記録し、期間を 14 暦日延長するか次の段階へ進むかを理由とともに記録する。あわせて、High 以上の修正の目標を 14 日のまま維持するか 30 日に戻すかを決める。

## Well-Architected との関係

この文書の Well-Architected のベストプラクティス ID との対応は、AWS Well-Architected のレビューの結果ではなく、AWS による承認でもない。ベストプラクティスのページを読み、構成要素が同じ話題を扱うと読んだものである。対応表は [framework mapping](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応) にだけ置き、この文書は写さない。参照した版は v13（2024-11-06）である。

ワークロードの持ち主は、自分のワークロードを [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/) でレビューし、決定と改善を記録できる。NIST CSF 2.0 への対応も、同じ mapping の[節](cyber-resilience-framework-mapping.md#pdca-と説明責任の-csf-20-への対応)にあり、NIST による認定ではない。どちらの対応も、法務、コンプライアンス、規制上の判断ではなく、ガバナンス上の指針である。

## 参考文献

この文書が依拠する文献を、名称（発行主体が付けた原題）、発行主体、公開日と版、URL、参照日（その URL の内容を確認した日）の順に並べる。日付が表示されていない文献は、その旨を書く。名称は日英どちらの版でも原題のままである。`[E-nnn]` で引いた文献は、[evidence-ledger.json](../agent/evidence-ledger.json) の出典の欄にも同じ URL がある。

| 名称 | 発行主体 | 公開日・版 | URL | 参照日 |
|---|---|---|---|---|
| Minimum Release Age | Renovate | 日付の表示なし | [docs.renovatebot.com](https://docs.renovatebot.com/key-concepts/minimum-release-age/) | 2026-11-13 |
| Configuration Options | Renovate | 日付の表示なし | [docs.renovatebot.com](https://docs.renovatebot.com/configuration-options/) | 2026-11-13 |
| config (npm CLI v11) | npm | v11 | [docs.npmjs.com](https://docs.npmjs.com/cli/v11/using-npm/config) | 2026-11-13 |
| OpenVEX Specification | OpenVEX | v0.2.0 | [github.com/openvex](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | 2026-11-10 |
| Using artifact attestations | GitHub | 日付の表示なし | [docs.github.com](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) | 2026-11-10 |
| gh attestation verify | GitHub | 日付の表示なし | [cli.github.com](https://cli.github.com/manual/gh_attestation_verify) | 2026-11-10 |
| Build: Track Basics | OpenSSF SLSA | v1.2 | [slsa.dev](https://slsa.dev/spec/v1.2/build-track-basics) | 2026-11-12 |
| REST API endpoints for software bill of materials (SBOM) | GitHub | API 版 2026-03-10 | [docs.github.com](https://docs.github.com/en/rest/dependency-graph/sboms) | 2026-11-13 |
| Exporting SBOMs with Amazon Inspector | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html) | 2026-11-13 |
| Amazon Inspector integration with AWS Security Hub CSPM | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/securityhub-integration.html) | 2026-11-13 |
| Amazon Inspector Lambda standard scanning | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/scanning_resources_lambda.html) | 2026-11-13 |
| Scanning AWS Lambda functions with Amazon Inspector | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/scanning-lambda.html) | 2026-11-13 |
| AWS Security Hub FAQs | AWS | 日付の表示なし | [aws.amazon.com](https://aws.amazon.com/security-hub/faqs/) | 2026-11-13 |
| Software bill of materials (AWS Security Hub User Guide) | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html) | 2026-11-13 |
| AWS Security Hub now provides an SBOM inventory for your compute resources | AWS | 2026-11-06 | [aws.amazon.com](https://aws.amazon.com/about-aws/whats-new/2026/11/security-hub-sbom-inventory/) | 2026-11-12 |
| AWS Security Hub Pricing | AWS | 日付の表示なし | [aws.amazon.com](https://aws.amazon.com/security-hub/pricing/) | 2026-11-12 |
| GetSoftwareV2 (AWS Security Hub API Reference) | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetSoftwareV2.html) | 2026-11-13 |
| AWS Well-Architected Framework | AWS | v13（2024-11-06） | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html) | 2026-11-13 |
| What is AWS Well-Architected? | AWS | 2026-10-01（ページの Last updated） | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/userguide/well-architected.html) | 2026-11-10 |
| Well-architected best practices for software supply chain security | AWS Security Blog | 公開日の表示を取得できなかった | [aws.amazon.com](https://aws.amazon.com/blogs/security/well-architected-best-practices-for-software-supply-chain-security/) | 2026-11-10 |
| OpenSSF Malicious Packages | OpenSSF | 日付の表示なし | [github.com/ossf](https://github.com/ossf/malicious-packages) | 2026-11-10 |
| OSV.dev Data Sources | OSV.dev | 日付の表示なし | [google.github.io](https://google.github.io/osv.dev/data/) | 2026-11-10 |
| Known Exploited Vulnerabilities Catalog | CISA | catalogVersion 2026.11.09 | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 2026-11-10 |
| GET /epss (FIRST.Org REST API Documentation) | FIRST | API は BETA と表示 | [api.first.org](https://api.first.org/epss/) | 2026-11-12 |
| Cyber Resilience Act - Reporting obligations | European Commission | 日付の表示なし | [digital-strategy.ec.europa.eu](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | 2026-11-10 |
| MCP Security Crisis: Systemic Design Flaws in AI Agent Infrastructure | Cloud Security Alliance (CSAI Foundation) | 2026-05-04（研究ノート。文書自身が AI 支援で作成され、CSA の正式なレビューを経ていないと記載している） | [labs.cloudsecurityalliance.org](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf) | 2026-11-10 |

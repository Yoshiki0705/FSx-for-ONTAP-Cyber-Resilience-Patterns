# 復旧時間と復旧点の目標は、サービス提供者が自環境の実測から決める値である
> **概要**: 第 2 の柱「RTO/RPO と SLA/SLO/SLI」の導入手順をまとめる。RTO の起点と終点の定義、復旧の層ごとの特徴と選び方、SLI/SLO を決める手順、低頻度の事象の扱い、リストア訓練、第 3 の柱へ渡す復旧点の記録の形式を書く。数値の例はすべて「例」で、どのエンドユーザーへの約束でもない。測定した値は[測定結果](recovery-measurement-results.md)に載せる。この文書は、確定済みの測定だけを環境と回数を添えて引き、測定が終わっていない項目は、その旨を書く。
## 定義: サービス提供者の値とベンダーの SLA の分離
RTO（復旧時間の目標）、RPO（復旧点の目標）、SLA、SLO、SLI は、エンドユーザーにサービスを提供するサービス提供者が、エンドユーザーに向けて設定する値である。AWS や NetApp が自社サービスについて公開するベンダーの SLA とは別のものである。ベンダーの SLA は、サービス提供者が SLO を決める入力の 1 つで、代わりにはならない。この文書は、ベンダーの SLA の数値を書かない。使うときは、ベンダーが公開する SLA のページから、参照日を添えて引く。
このプロジェクトは値そのものを決めない。値を決めるための定義、決めるときの入力にする実測値、設定の手順、参照構成を提供する。この文書が示す値と例は、サービス提供者が自分の値に置き換えるための参照で、どのエンドユーザーへの約束でもない。この文書はガバナンス上の指針で、法務・契約・規制上の判断ではない。SLA の契約上の約束はサービス提供者自身が決める。
次の表は、誰が何を決め、何を提供するかを分ける。
| 区分 | 内容 | 出どころ |
|---|---|---|
| サービス提供者が決める値 | RTO、RPO、SLO の目標値と測定窓、エラーバジェットを使い切ったときの動作 | サービス提供者の判断 |
| このプロジェクトが定義する語 | RTO の時点と区間、SLI の測り方、復旧点の記録の形式 | この文書の「RTO の時点と区間の定義」以降の節 |
| このプロジェクトが提供する実測値 | 東京リージョンの検証用ファイルシステム 1 台での、復元と作り直しの所要時間 | [測定結果](recovery-measurement-results.md) |
| このプロジェクトが提供する手順とスクリプト | 自環境で区間を測る手順、dry-run、安全ガード | 測定スクリプトの README（`benchmarks/recovery/README.md`。main ブランチにはまだない） |
この柱は、AWS Well-Architected Framework の REL13-BP01、REL13-BP02、OPS09-BP01 に対応づける [2]、[3]、[4]。対応の表は framework mapping の[ベストプラクティス ID との対応](cyber-resilience-framework-mapping.md#ベストプラクティス-id-との対応)にあり、ここには写さない。AWS Prescriptive Guidance の Resilience lifecycle framework [1] では、この柱は Set objectives（目標の設定）と Evaluate and test（評価と試験）に当たる。PDCA との対応は、programme 文書の[Resilience lifecycle との対応](cyber-resilience-programme.md#resilience-lifecycle-との対応)にあり、ここには写さない。
## RTO の時点と区間の定義
RTO は、起点と終点を決めないと値にならない。次の表は、復旧の経過を 8 つの時点に分ける。
| 時点 | 定義 | 取得元 | このプロジェクトでの扱い |
|---|---|---|---|
| T0 | 影響の開始（侵害または障害の最初の影響） | 運用の記録（推定） | 測らない |
| T1 | 検知 | アラームの発火時刻 | 既存の記録を引用（下記） |
| T2 | 復旧の宣言（復旧の判断を始めると決めた時刻） | 復元の記録の `declared_at` | 参照の起点 |
| T3 | 復旧点の決定 | 判断の記録の `decided_at` | 記録の項目 |
| T4 | 復元操作の開始 | 操作の開始時刻（ONTAP のジョブ、`StartRestoreJob`、スタックの作成） | 測る |
| T5 | データの到達（簡易確認がマニフェストと一致した時刻） | クライアントの時刻。復元の記録の `restore.data_available_at` | 測る |
| T6 | 受け入れ確認の完了（アプリが期待どおり応答し、サービス提供者の確認が済んだ） | アプリの応答、運用の記録。復元の記録の `restore.accepted_at` | アプリの応答まで測る。サービス提供者の受け入れは測らない |
| T7 | 切り替えの完了（ユーザーが復旧後の環境を使い始めた） | 運用の記録 | 測らない |
隣り合う時点の間を区間と呼ぶ。区間は、同じ時計で取った 2 つの時刻の差だけで計算する。時計をまたぐ区間は、2 つの時計のずれを誤差として併記する。
| 区間 | 式 | このプロジェクトでの扱い |
|---|---|---|
| S_detect | T1 − T0 | 測らない |
| S_declare | T2 − T1 | 既存の記録を引用（下記） |
| S_decide | T3 − T2（`decided_at` − `declared_at`） | 2 つの復旧点の記録から計算する（運用） |
| S_prepare | T4 − T3 | 測らない（運用） |
| S_restore | T5 − T4 | 測る（Snapshot の復元、FSx バックアップの復元、AWS Backup のリストア試験、SnapMirror） |
| S_rebuild | クリーンな作り直しで、計算資源を作り直して同じボリュームを再接続し、データを読めるまで | 測る（<!-- TODO(13.2): M4 の結果の確定後に、区間別の値への参照を入れる -->） |
| S_accept | T6 − T5 | 作り直しの測定の範囲で、アプリの応答まで |
| S_cutover | T7 − T6 | 測らない |
T5 は、全ファイルのサイズと、先頭と末尾 4 MiB の SHA-256 がマニフェストと一致した時刻である。全ファイルの SHA-256 の一致は T5 とは別の時刻 `full_check_done_at` で、測定記録の結果が成功になる条件に使う。
RTO の値は、書くすべての場所で、起点と終点を括弧内に名指しする。たとえば「RTO（T2→T6）」と書く。起点も終点もない「RTO 4 時間」は、この文書でも例でも使わない。「RTO（T2→T6）」は、エンドユーザーが体験する停止（T0 から T7）の長さでも、ベンダーが示す操作の所要時間の目安（T4 から T5 に当たる範囲）でもない、別の量である。
| RTO の定義 | 起点と終点 | 使う場面 |
|---|---|---|
| 参照の定義 | RTO（T2→T6）。S_decide を含む | 復旧点を決める時間も目標に含めたいとき |
| S_decide を含めない定義 | RTO（T3→T6） | 復旧点の判断を別の目標（調査の目標）で管理するとき |
参照の定義は、復旧の宣言（T2）から受け入れ確認の完了（T6）までで、S_decide を表の別の行に併記する。この定義はサービス提供者が自分の起点と終点に置き換える。S_decide を RTO に含めるかはサービス提供者の決定で、含めるときの値（T2 から T6）と含めないときの値（T3 から T6）は、2 つの復旧点の記録から両方計算できる（「第 3 の柱への受け渡しの形式」の節）。programme 文書が第 2 の柱に残した問い（復旧点を決める時間を RTO に含めるか）への答えがこの定義である（[着手の順序](cyber-resilience-programme.md#着手の順序)）。
S_detect と S_declare の入力には、検知から通知までの既存の測定を使い、このプロジェクトでは測り直さない。Cyber の[アラート経路の検証](alert-path-verification.md)（2026-11-13、ap-northeast-1、各 1 回）と、Observability の E2E の測定（EMS の通知まで約 30 秒）がある。
AWS の参照アプローチは、調査、候補の検証、基盤の再構築を並行して進め、データの復元は検証を通った後に行う [6]。区間を直列に足した RTO（T2→T6）は、並行できる作業が並行したときの実際の値より長くなりうる。この文書の例は、直列の和で書く。
### 世代による復元中の読み取りの差
第 1 世代のファイルシステムで FSx バックアップから復元するときは、メタデータとデータがすべて載るまでボリュームを読み取れない。第 2 世代では、ボリュームが `CREATED` になった後、復元の途中でも読み取れる（documented、[8]）。T5 は、世代にかかわらず、簡易確認の一致の時刻とする。`CREATED` の時刻と T5 は一致するとは限らないので、測定では別々に記録する。
## 復旧の層ごとの特徴と実測の所在
層の前提、制約、費用の扱い、障害ドメイン、RPO と RTO の目安は、次の文書にある。この文書は列を写さず、リンクで示す。
- Hub の[データ保護方式の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md)（日本語のみ）
- Hub の[Snapshot だけで復旧できるか](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/snapshots-are-not-a-recovery-plan.md)（日本語のみ）
- Hub の[バックアップコピーだけで復旧できるか](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md)（日本語のみ）
- Cyber の[論理エアギャップボールトのガイド](../data-protection/aws-backup-logically-air-gapped-vault.md)

他の層と周辺の測定の記録を、各記録の環境・日付・回数とともに挙げる。この文書は値を写さない。

- Observability の[機能マップ](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/ja/cyber-resilience-capability-map.md>)（restore testing の行は、リストア訓練の通しには組み立てが要ると書く）と[検証済み復旧点のガイド](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/ja/verified-recovery-point-guide.md>)（FlexClone による復旧点の事前選別。ONTAP 9.17.1P7D1、ap-northeast-1、2026 年 7 月）
- Hub の[経路がフェイルオーバーの機構そのもの](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/block-storage/notes/paths-are-the-failover-mechanism.md>)は、見つかった唯一の Multi-AZ フェイルオーバーの測定（2026-09-05、ap-northeast-1、第 2 世代、HA ペア 1 組、ONTAP 9.18.1P5、1 回。スループット容量を 384 から 768 MBps へ変更して誘発。ANA の状態は要求の約 66 秒後に反転し、既定のカーネルの NVMe/TCP は 423.8 秒止まった）。この project の検証用ファイルシステムは第 1 世代の SINGLE_AZ_1 なので、Multi-AZ のフェイルオーバーは測らない
- Hub の[上限値の一覧](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/limits/README.md>)（日本語のみ）は、スループット容量 128 MBps の SVM 数の上限 6 を記録する（2026-08-18 実測、ap-northeast-1）
- Observability の[SLO の定義の書式](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/ja/pipeline-slo.md>)（下の SLO の表が流用する）
次の表が持つのは、層ごとの、実測した S_restore、RTO のどの区間に当たるか、復旧点の記録の `layer` の値の 3 列である。最後の行は、ONTAP の機能に依存しない構成を同じ列で並べる。層に順位は付けない。
| 層 | 実測した S_restore と既存の記録 | RTO のどの区間に当たるか | `layer` の値 |
|---|---|---|---|
| ONTAP の Snapshot（`volume snapshot restore`、`restore-file`、FlexClone） | 1 GiB と 50 GiB の Snapshot 復元を各 4 回測定し、全ファイルの SHA-256 が一致した（東京リージョン、ONTAP 9.18.1P6、第 1 世代 SINGLE_AZ_1）。FlexClone の作成も測定済み。10 GiB は、大きなファイルで復元 2.0〜3.0 秒、小さなファイル（約 8 万）で 168.0〜170.0 秒。値と条件は[測定結果の M1 の節](recovery-measurement-results.md#m1-の結果-snapshot-の復元とクローン作成)にある。測定の途中の 2026-11-20（日本時間）に、ONTAP が 9.18.1P6 から 9.19.1P4 に自動で上がり、10 GiB のクローン作成 4 件に影響した（[影響の範囲](recovery-measurement-results.md#ontap-の版の変更の影響)）。版はユーザーが選べない [E-058] ことの実例で、自環境で測るときは、測定の前後に版を読む | S_restore。復旧点の検証（FlexClone による絞り込み）は S_decide の入力 | `ontap-snapshot` |
| SnapMirror の宛先 | 同一クラスタ内の create、transfer、break、resync、cleanup の E2E は 11 項目が成功（Agentic-Access-Aware-RAG の `automation/fsxn-ops`、2026-05-01、ONTAP 9.17.1P4D3、各項目 1 回）。クロスリージョンの成立と break は fsxn-lakehouse-integrations に記録がある（2026-07）。<!-- TODO(13.2): 同一クラスタ内の 2 つの SVM の間の break と resync の所要時間、lag の分布（M5）を入れる --> | S_restore（break と切り戻し）。RPO は lag で決まる | `snapmirror-destination` |
| FSx のバックアップ | Hub の記録は、ボリューム 1 GiB（データ約 9.4 MiB）の復元が 13 分 21 秒、測定 1 回（2026-08-28、第 1 世代 SINGLE_AZ_1）。Hub 自身が、この所要時間は固定の部分が大きく RTO の根拠にならないと書く。AWS は一般的な復元速度の目安を、大きなファイル中心の複数の同時復元で 250 MBps、小さなファイル中心で 100 MBps と書く [8]。この project の測定（東京、第 1 世代 SINGLE_AZ_1、128 MBps、ONTAP 9.19.1P4、2026-11-20〜21、各群 n=4、sample run で本番の見積りではない）では、復元は大きなファイルの 1、10、50 GiB で中央値 353、368、552 秒、10 GiB の小さなファイル（約 8 万個）で 1023 秒だった。時間の大半は CREATED までの固定的な部分で、小さなファイルではファイル数が効くと推測する（`hypothesis`）。表は[復旧の測定結果の M2](recovery-measurement-results.md#m2-の結果-fsx-のバックアップの復元)にある。 | S_restore。復元はバックグラウンド処理で、スループット容量の未使用分を使う [8] | `fsx-backup` |
| AWS Backup のボールト（リストア試験を含む） | リストア試験は FSx for ONTAP を対象に含む（documented、Cyber のガイド）。AWS Backup は FSx のメタデータを完全には推定できず、復元先の SVM を `RestoreMetadataOverrides` の `storageVirtualMachineId` で指定する必要がある（documented、[12]）。<!-- TODO(13.2): リストア試験を実際に走らせた結果（M3）を入れる --> | S_restore。開始ウィンドウの待ちは含めない | `aws-backup-vault` |
| AWS Backup の論理エアギャップボールト | 共有したボールトの復旧ポイントから、別アカウントの既存ファイルシステムへ 1 GiB を 1,362 秒で復元した（S3 Access Points のサーバーレスパターンのラボ、2026-10-12、測定 1 回。記録の status 行は、現在のポータルについてこの行を記録していないと書く）。アカウントをまたぐ共有経由なので、他の層との比較には使わない。 | S_restore（共有と別アカウントでの復元を含む） | `aws-backup-lag-vault` |
| ONTAP の機能に依存しない構成（EBS のスナップショットと AWS Backup、データベースのレプリケーション、S3 のバージョニング） | このプロジェクトは測っていない | 構成による | `other` |
層ごとの向く場面と制約を、同じ粒度で書く。詳しい比較は上のリンク先にある。
- ONTAP の Snapshot: 向く場面は、同じボリューム内の誤削除や破損から、短い時間で戻したいとき。制約は、障害ドメインがボリュームと同じであること、Snapshot の数に上限があること（Hub のノート）、`volume snapshot restore` が現在の書き込み可能コピーを置き換えること。Snapshot にロックをかける Tamperproof Snapshot は、ロックしたものが残るあいだ ONTAP を以前の版へ戻せない [E-057]
- SnapMirror: 向く場面は、別のファイルシステムに復旧点を持ちたいとき。制約は、転送が非同期で、RPO が転送の間隔と lag で決まること、宛先に別のファイルシステムを使う構成は、このプロジェクトでは測っていないこと。FSx for ONTAP はボリューム単位の SnapMirror だけに対応し、同期系の SnapMirror（StrictSync を含む）と SVM DR には対応しない [E-059]。この前提で設計し、`snapmirror failover start` を手順に使えるとは考えない
- FSx のバックアップ: 向く場面は、ボリューム単位で、長期の保持と別リージョンへのコピーが要るとき。制約は、第 1 世代では復元が終わってから読み取りを始めること [8]、復元後のボリュームが元と同じ形（スタイル）になること [8]、復元中のボリュームへの Snapshot の作成、クローン、SnapMirror、バックアップは復元の完了後に行うこと [8]
- AWS Backup のボールト: 向く場面は、バックアップの計画、保持、監査を AWS Backup に集めたいとき。制約は、FSx for ONTAP のバックアップが AWS Backup の完全な管理の対象ではなく、復元の手順が FSx のものと異なること。リストア試験は一時的な復旧ポイントを対象にしない [E-017]
- 論理エアギャップボールト: 向く場面は、バックアップを削除から守り、別のアカウントから復元したいとき。制約は、ファイルシステムが AWS マネージドキーで暗号化されていると、バックアップをボールトへコピーできないこと [E-009]
- ONTAP の機能に依存しない構成: 向く場面は、ONTAP の機能を使わない、または使えないワークロード。制約は、ファイル共有のまま復旧点を保つ手段が構成ごとに違い、このプロジェクトの測定と手順が当てはまらないこと
REST で Snapshot を復元する形は、NetApp の REST リファレンスにある `PATCH /api/storage/volumes/{uuid}` の `restore_to.*` である。Observability の ToolJet ワークフローが使う `POST .../snapshots/{uuid}/restore` の形は、ONTAP 9.18.1P6 の `show-rest` の一覧に載っていないので、このプロジェクトの手順には使わない。
## 層の選び方の流れ
問いの順に答えると、候補の層が絞れる。これは順位づけではなく、各層の向く場面と制約を、自分の条件に当てはめる流れである。
| 問い | 答えが示す層 | 注意 |
|---|---|---|
| 許容するデータ損失（RPO）は何分か | 分単位ならスケジュール転送（SnapMirror）か頻繁な Snapshot。時間単位から日単位ならバックアップ | SnapMirror の RPO は lag で決まる。5 分スケジュールの lag の分布は測定結果にある<!-- TODO(13.2): M5 の確定後に節へリンクする --> |
| 守りたい障害の範囲はどこまでか | 誤操作ならボリュームの Snapshot。ファイルシステムの障害なら SnapMirror かバックアップ。アカウントの侵害なら論理エアギャップボールト | 侵害を想定するなら、復旧の入力を信頼しない前提で選ぶ（「サイバーリカバリと DR の区別」の節） |
| 戻す粒度はファイルかボリュームか | ファイルなら `restore-file`、`.snapshot` からのコピー。ボリュームなら Snapshot の復元かバックアップ | `restore-file` はディレクトリを渡せない（documented） |
| データ量はどれだけか | 大きいほど、バックアップの復元に時間がかかる見込み。Snapshot の復元はボリューム内の操作で、測定ではデータ量に対して秒単位にとどまった | 比例の外挿は避ける。測っていないデータ量は仮の見積りとして別に扱う |
| ONTAP の機能への依存を許容するか | 許容するなら Snapshot、FlexClone、SnapMirror。許容しないなら EBS のスナップショットと AWS Backup、データベースのレプリケーション、S3 のバージョニング | 別の構成では、このプロジェクトの測定は当てはまらない。自環境で測り直す |
| 復旧点の改変を防ぎたいか | ロックつきの Snapshot、論理エアギャップボールト | ロックには、元に戻せない操作と、解除できない期間が伴う。事前に費用と期間を見積もる |
> **コストに関する補足**: 層ごとの費用は、単価と前提が書けるときだけ金額で書く。この文書は金額を書かない。単価はリージョンと時期で変わるので、当日の Pricing API で確認する。
## SLI/SLO の設定手順
手順は次の 8 つである。値を決めるのはサービス提供者で、このプロジェクトは入力と書式を提供する。
1. サービスとデータを分類する。復旧の優先度の区分を決める。
2. RTO の起点と終点を選ぶ。参照の定義は RTO（T2→T6）で、S_decide を併記する。
3. 復旧の層を選ぶ。前節の流れと、Hub と Cyber の比較を使う。
4. 自環境で区間を実測する。次の小節に従う。
5. RTO と RPO の値を決める。実測の範囲を入力にし、余裕の大きさはサービス提供者が決める。
6. SLI と SLO の表を作る。次の 6 つの SLI の表と、4 列の書式を使う。
7. リストア訓練とリストア試験の計画を作る（「リストア訓練とリストア試験の実施」の節）。
8. PDCA で見直す（「PDCA での見直しの契機」の節）。
SLO の表は、Observability の[SLO 定義の書式](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/management-console/README.md)（SLI、SLO の目標、測り方、エラーバジェット（30 日）の 4 列）を再利用する。バーンレートの窓を使う記述は、Observability の[パイプライン SLO](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/pipeline-slo.md)にある。高頻度の事象向けで、リストア試験には当てはまらない。
SLI の候補は次の 6 つである。
| SLI | 測り方 | データ源 | 頻度 | 最小の標本数 | 既知の落とし穴 |
|---|---|---|---|---|---|
| 復旧点の鮮度 (i) | 最新の復旧点（存在するもの）の作成日時からの経過時間 | ONTAP の Snapshot の作成日時、`describe-backups`、AWS Backup の復旧ポイント | 5 分から 1 時間 | 連続値で、標本数の制約はない | 取得元ごとに時刻の基準が違いうる。取得の失敗と鮮度の悪化を区別する |
| 復旧点の鮮度 (ii) | 最新の検証済みの復旧点の経過時間 | Observability の台帳（`verdict: clean` の最新の `started_at`）。台帳がなければ「未取得」と書く | 検証の都度 | 同上 | 検証は事前の絞り込みで、フォレンジックによる確認ではない。`clean` は復旧の十分条件ではない |
| SnapMirror の lag | 関係ごとの lag と状態 | ONTAP REST の `lag_time`（ISO 8601 の継続時間）、Observability の `FSxONTAP/SnapMirror` メトリクス | 5 分 | 連続値 | `uninitialized` の関係が `healthy: true` と返った 1 回の観測がある（Observability、2026-10-08、ONTAP 9.18.1P6）。`healthy` だけを SLI にせず、状態と lag を併せて使う。CloudWatch の `AWS/FSx` に SnapMirror の lag 専用のメトリクスがあるかは、確認できていない<!-- TODO(13.2): M6 の `list-metrics` の結果を入れる --> |
| 復旧の成功率 | リストア試験の成功の割合。成功 ÷（成功 + 失敗） | `aws backup list-restore-jobs --by-restore-testing-plan-arn`。状態は PENDING、RUNNING、COMPLETED、ABORTED、FAILED で、`COMPLETED_WITH_ISSUES` に当たる値はない [10] | 試験ごと | 窓内の試験回数 N と、許容する失敗数 floor(N × (1 − SLO)) を併記する | 一時的な復旧ポイントは試験の対象外 [E-017]。CloudWatch の `NumberOfRestoreJobsCompleted` と `NumberOfRestoreJobsFailed` は、運用での復元も数えるので、傾向を見るときだけ使う [11]。データの整合の確認を成功に含めるかを決める |
| 復元の所要時間 | S_restore | 復元ジョブの作成と完了の時刻 | 試験ごと | p50 は 5 件以上、p95 は 20 件以上のときだけ書く。足りなければ最大値と件数を書く | データ量とファイルの形に依存する。開始ウィンドウの待ちを含めない |
| バックアップジョブの成功率 | 成功 ÷（成功 + 失敗 + 問題あり） | `aws backup list-backup-jobs` の状態別の件数。成功は `State=COMPLETED` かつ `MessageCategory=SUCCESS`、失敗は `State=FAILED`、問題ありは `State=COMPLETED` の件数から成功の件数を引いて求める [9] | 日次 | 窓内のジョブ数 | `Completed with issues` は AWS Backup のコンソールだけの状態で、CloudWatch では追跡できない [11]。ファイルシステムが AWS マネージドキーだと、論理エアギャップボールトへのコピーで起きる [E-009]。API は過去 30 日分だけを返す [9]。窓が 30 日を超えるときは、`Backup Job State Change` の EventBridge のイベントを保存して数える。CloudWatch の `NumberOfBackupJobsCompleted` が問題ありのジョブを含むかは、文書に書かれていない<!-- TODO(13.2): M6 で、テンプレートの `BackupCompletedWithIssues` の実環境の動作と、list-backup-jobs の 2 回の取得による件数の照合を入れる --> |
`EXPIRED`、`ABORTED`、`PARTIAL` を分母に入れるかは、サービス提供者が決める。CloudWatch の `AWS/Backup` のメトリクスだけを使うときは、「完了したジョブの割合」と書き、成功率とは書かない。Observability の `FsxOntap/Backup` は失敗の件数だけを持ち、分母がない。
AWS Resilience Hub の対応リソースの一覧には FSx for ONTAP が載っておらず、一覧にないリソースは完全には対応していないと説明される [E-051]。そのため、RTO と RPO の評価は、この文書のスクリプトと AWS Backup のリストア試験という別の測定系で行う。AWS のホワイトペーパーや Resilience Hub の既定の目安を引くときは、出典の URL を添え、一般的な例であり規範ではないと書く。
エラーバジェットは、評価窓に 20 件以上の標本がある事象（バックアップジョブ、lag など）について、SLO の裏返しとして定義する。バジェットを使い切ったときの動作（新しい変更を止めて信頼性の作業をする、など）は、サービス提供者が決める。
### 自環境での区間の実測
実測の値は、サービス提供者のデータ量、ファイル数、ファイルの大きさ、スループット容量、世代と異なる。自環境で測り直す手順は次のとおりである。
1. 測定スクリプトの README（`benchmarks/recovery/README.md`。main ブランチにはまだない）の作業規則に従う。実行する操作を dry-run で先に表示し、表示した操作だけを実行する。
2. 作成する資源は、接頭辞とタグを持つものに限る。破壊的な操作は、撤去する資源の一覧に載せた識別子と一致する資源にだけ実行する。
3. 測定の前に、SSD の空き容量、背景の負荷、費用の見込みを確かめる。費用は Pricing API で求める。
4. 同じ構成を直列に 3 回以上測り、最小値、中央値、最大値で書く。2 つの構成を比べるときは、4 回以上を交互に測る。
5. 撤去で消える成果物を先に退避し、撤去の後に、資源が見つからないことを 2 回確かめる。
### 鮮度の取得元と時刻の基準
復旧点の鮮度は、取得元ごとに時刻の基準が違いうる。取得元を SLI の定義に書く。
| 復旧の層 | 取得元 | 時刻の基準 |
|---|---|---|
| ONTAP の Snapshot | ONTAP の `create_time` | ONTAP のクラスタ時刻 |
| SnapMirror | `lag_time`（ISO 8601 の継続時間） | 転送の開始からの経過。のこぎり波になる |
| FSx のバックアップ | `describe-backups` の作成日時 | FSx のサービスの時刻 |
| AWS Backup | 復旧ポイントの作成日時 | AWS Backup のサービスの時刻 |
### 低頻度の事象の扱い
リストア試験や訓練のように、評価窓に入る事象が 20 件未満の SLI には、p95 とエラーバジェットを使わない。標本が 4 件のとき、p95 は最大値と同じである。`N × (1 − SLO)` が 1 未満なら、失敗 1 件が窓のバジェットを使い切り、「バジェットを使い切ったときの動作」が毎回発動する。低頻度の事象は、次の 2 つで書く。
1. 事象ごとの合否。その回の値が目標（たとえば S_restore が目標以下）かを、回ごとに書く。
2. 窓内の件数。失敗数 ÷ 試験回数 N を書く。`N × (1 − SLO) < 1` のときは「失敗 1 件で SLO を満たさない」と書き、窓を長くする（四半期など）か、試験の頻度を上げるかを、サービス提供者が決める。
p50 は 5 件以上、p95 は 20 件以上のときだけ書く。足りないときは最大値と件数を書く（p95 とは書かない）。
## 算術で作る例の数値
> **例について**: この節の数値は、すべて例である。どのエンドユーザーへの約束でもなく、推奨値でもない。実測から算術で作った値は計算式を添え、測っていない区間は任意の仮定として別のセルに書く。
次の表は、RTO（T2→T6）と RTO（T3→T6）の例を、区間の和で作る。S_restore の値は測定の結果で、ほかは任意の仮定である。
| 区間または RTO | 例の値（秒） | 出どころ |
|---|---|---|
| S_decide | 1,800 | 任意の仮定 |
| S_prepare | 300 | 任意の仮定 |
| S_restore | 15 | 測定（Snapshot の復元、50 GiB の大きなファイル、測定 4 回の最大値、東京リージョン、ONTAP 9.18.1P6、第 1 世代 SINGLE_AZ_1、2026-11-18）。2 つの時計をまたぐ区間で、誤差は約 2 秒。表の値としては上限の目安にとどめる。<!-- TODO(13.2): 集計の確定値と分解能の判定に従って、この行を差し替える --> |
| S_accept | 600 | 任意の仮定 |
| RTO（T2→T6） | 2,715 | 計算式: 1,800 + 300 + 15 + 600 |
| RTO（T3→T6） | 915 | 計算式: 300 + 15 + 600 |
次の表は、SLO の例である。4 列の書式は Observability のものである。
| SLI | SLO の目標（例） | 測り方 | エラーバジェット（30 日） |
|---|---|---|---|
| 復旧点の鮮度 (i) | 最新の復旧点の経過時間が 60 分以下である時間の割合 99%（任意の仮定） | 5 分ごとに Snapshot の作成日時から求める | 43,200 分 × 1% = 432 分 |
| バックアップジョブの成功率 | 95%（任意の仮定） | 日次の 1 ジョブを 30 日で 30 件。成功 ÷（成功 + 失敗 + 問題あり） | 30 件 × 5% = 1.5 件。失敗または問題ありは 1 件まで |
| 復旧の成功率 | 四半期に 4 回のリストア試験で失敗 0 件（任意の仮定） | リストア試験の復元ジョブ | 4 × (1 − SLO) が 1 未満のため、バジェットは使わず、失敗 1 件で未達とする |
| 復元の所要時間（S_restore） | 各回 600 秒以下（任意の仮定。測定の最大 15 秒は Snapshot の復元の値で、他の層の値ではない） | 試験ごとの復元ジョブの作成と完了の時刻 | 回ごとの合否。5 件未満なので最大値と件数を書く |
## リストア訓練とリストア試験の実施
リストア訓練の目的は、バックアップがあることではなく、復元したデータが使え、RTO と RPO の範囲に収まることを確かめることである。AWS Well-Architected の REL09-BP04 は、復元したデータにクエリして使えることを確かめること、バックアップがあるから復元できると仮定しないこと、手順書か自動化された手順を使うことを求める [5]。
訓練ごとに、次を確かめる。
1. 復元したデータが、破損や欠落なしに読める。ファイルの一部をハッシュで確かめる簡易確認と、全ファイルの確認の 2 段で書く。
2. 受け入れの条件（アプリの応答など）が満たされる。ここまでが T6 である。
3. S_restore と、T2 から T6 までの時間が、サービス提供者の目標の範囲に収まる。
4. データ損失が、RPO の範囲に収まる。
頻度と担当は、Cyber の[ランサムウェア復旧のランブックの DR テストの表](../runbooks/ransomware-recovery.md)に叩き台がある。頻度はサービス提供者が決める。AWS Backup のリストア試験は、計画を作って自動で復元と検証を行い、検証ウィンドウの後に復元したボリュームを削除する。FSx for ONTAP のリストア試験の仕様は Cyber の[論理エアギャップボールトのガイド](../data-protection/aws-backup-logically-air-gapped-vault.md)にあり、このプロジェクトの実測は<!-- TODO(13.2): M3 の結果の節へのリンクを入れる -->確定後に測定結果へ載せる。リストア訓練を扱う実務者向けの資料として [7] がある。
## サイバーリカバリと DR の区別
サイバーリカバリは、バックアップ、認証情報、基盤など、復旧の入力そのものが侵害されている可能性があるときに、既知の良い状態へ戻す復旧である [6]。DR は、障害から復旧することを広く指す。この 2 つの区別で見るのは、復旧の入力と復元先の環境を、確かめるまで使わないことである。AWS の参照アプローチは、次の点を挙げる [6]。
- 復旧の環境は、復旧する対象の環境と、アカウント、鍵、ネットワーク経路を含む信頼境界を共有しない。侵害を疑う本番のアカウントでは、復旧作業をしない
- 復旧点は、最新のものではなく、事象の境界より前にあり、検証を通った中で最も新しいものを選ぶ。検証に失敗したら、1 つ前の候補に戻る
- 検証は、復元に成功したこと（読めること）と、使って安全なことを分ける。マルウェアのスキャン、データベースの整合確認などのワークロード固有の確認、ログの確認を組み合わせる
- 基盤はコードから作り直し、データはバックアップから戻し、認証情報は復元せずに新しく発行する
- 調査、検証、基盤の再構築は並行して進め、検証を通ったデータだけを復元する
- リージョン全体の喪失への備えは、削除からの保護とは別の関心事である。複製だけでは、データの破損や破壊に備えられない。ある時点に戻せる手段が要る [3]
この文書の区間では、S_decide（復旧点を決める時間）が長くなりやすいのがサイバーリカバリである（解釈）。復旧点の判断の記録を、次の節の形式で残す。
## 第 3 の柱への受け渡しの形式
復旧点の判断は第 3 の柱（フォレンジック）が行い、判断を記録して第 2 の柱へ渡す。第 2 の柱は、その記録を参照する復元の記録を書く。向きは programme 文書に従う。形式は先に着手する第 2 の柱が定義し、機械可読のスキーマは [`docs/agent/recovery-point-record.schema.json`](../agent/recovery-point-record.schema.json) である。項目の一覧はスキーマが正で、次の表は埋める側ごとの要約である。サービス提供者が第 3 の柱の手順を持たず、判断の記録を手で書くときも、判断の記録として書く。
| 区分 | 項目 | 埋める側 | 内容 |
|---|---|---|---|
| 共通 | `schema_version`、`record_id`、`service`、`incident_ref`、`authored_by`、`clock_source`、`integrity` | 両方 | 同じ `service` と `incident_ref` で 2 つの記録を結ぶ。`incident_ref` はサービス提供者が付ける識別子で、サポートケース番号を入れない |
| 判断の記録（`authored_by: pillar3`）の時刻 | `decision_started_at`、`decided_at`（T3）、`decided_by_role` | 第 3 の柱 | 判断に要した時間。役割名を書き、個人名を書かない |
| 判断の記録の内容 | `candidates`、`chosen`、`suspected_compromise_window`、`evidence_refs`、`preservation` | 第 3 の柱 | 候補、選択と根拠、受け入れたデータ損失、侵害の疑いのある期間、証跡の参照、調査用の保全 |
| 復元の記録（`authored_by: pillar2`）の宣言 | `declared_at`（T2）、`decision_ref` | 第 2 の柱 | 復旧の宣言と、判断の記録への参照 |
| 復元の記録の内容 | `restore.started_at`（T4）、`restore.data_available_at`（T5）、`restore.accepted_at`（T6）、`restore.completed_at`、`restore.job_id`、`restore.cutover_at`（T7、任意） | 第 2 の柱 | 復元の方法と対象、操作の時刻。`completed_at` は復元操作の完了で、T5 とは別 |
| 候補の層と判定 | `candidates[].layer`、`candidates[].integrity_checks[].result` | 第 3 の柱 | `layer` は復旧の層で、根拠の段階ではない。`result` は `clean`、`suspicious`、`error`（Observability の台帳の判定の語）。FlexClone による判定は事前の絞り込みで、`clean` は復旧の十分条件ではない |
ファイルポータル（S3 Access Points のサーバーレスパターン）の復旧ポイントの一覧が持つ列（作成日時、状態、リソース種別、サイズ、暗号化、ボールト名、論理エアギャップボールトの表示）は、候補の項目の出どころの一部である。ポータルが担うのは復旧ポイントの提示と承認つきの復元で、復旧点の記録の作成は将来の追加にあたり、そのリポジトリの判断である（[復旧ポイントと復元の設計](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/solutions/amplify-portal/docs/data-protection-recovery-design.md)）。
記録の扱いは次のとおりである。
- 一度書いた記録は書き換えない。訂正は、新しい記録の `integrity.supersedes` に、置き換える記録の識別子を書いて行う。1 つの記録を置き換えられる記録は 1 つだけである
- 時刻は UTC の ISO 8601 で書き、`clock_source` に時刻源を書く。ONTAP の監査ログ、EMS、CloudTrail、Snapshot の時刻の突き合わせは、第 3 の柱の `open` の項目で、このスキーマは時刻源を記録する欄を提供するだけである
- `integrity.record_sha256` は、`integrity` を除いた本体を、キーを辞書順、余計な空白なし、UTF-8 で並べた JSON から求める SHA-256 である。記録の内部の一貫性を示し、作成者の真正性は示さない。`service` と `incident_ref` の組ごとに連鎖を 1 本とし、最初の記録を除いて `prev_record_sha256` に直前の記録のハッシュを書く
- 保存先（追記専用の保存、またはハッシュを別の系統へ複写する）はサービス提供者が決める。署名は第 3 の柱の `open` の項目である
- `chosen.rationale_codes` が `before-compromise-window` を含むときは、`suspected_compromise_window` が必須である
### 2 つの記録からの計算
2 つの記録を `decision_ref` で結ぶと、RTO の 2 つの値と S_decide が計算できる。
1. S_decide = 判断の記録の `decided_at` − 復元の記録の `declared_at`。`decision_started_at` は S_decide の内訳（宣言から着手までの待ちと、着手から決定までの検討）を分けるために使い、定義には使わない
2. RTO（T2→T6） = `restore.accepted_at` − `declared_at`
3. RTO（T3→T6） = `restore.accepted_at` − `decided_at`
4. S_restore = `restore.data_available_at` − `restore.started_at`。時計をまたぐときは、測定記録の規則に従って誤差を併記する
### 記録の例
次は、前節の算術の例と同じ値を持つ例である。値はすべて任意で、実在の資源、アカウント、人を指さない。完全な 2 つの記録は、`tests/fixtures/recovery/recovery_point_record/` の `valid-decision.json` と `valid-restore.json` にある。
```json
{
  "record_id": "rpr-20261201-decision",
  "service": "example-file-service",
  "incident_ref": "inc-example-0001",
  "authored_by": "pillar3",
  "decision_started_at": "2026-12-01T02:10:00Z",
  "decided_at": "2026-12-01T02:30:00Z",
  "chosen": {
    "recovery_point_id": "<snapshot-2100>",
    "rationale_codes": ["latest-clean", "before-compromise-window"],
    "accepted_data_loss_seconds": 18000
  }
}
```
```json
{
  "record_id": "rpr-20261201-restore",
  "service": "example-file-service",
  "incident_ref": "inc-example-0001",
  "authored_by": "pillar2",
  "declared_at": "2026-12-01T02:00:00Z",
  "decision_ref": "rpr-20261201-decision",
  "restore": {
    "started_at": "2026-12-01T02:35:00Z",
    "data_available_at": "2026-12-01T02:35:15Z",
    "accepted_at": "2026-12-01T02:45:15Z"
  }
}
```
この例では、S_decide は 1,800 秒（02:30:00 − 02:00:00）、RTO（T2→T6）は 2,715 秒、RTO（T3→T6）は 915 秒である。上は抜粋で、必須の項目の一部を省いてあるため、スキーマの検証は通らない。検証が通る全体は上記のファイルにある。
## PDCA での見直しの契機
PDCA の 4 段階と Resilience lifecycle の対応は、programme 文書の[PDCA サイクル](cyber-resilience-programme.md#pdca-サイクル)にある。第 2 の柱の列はこの文書へのリンクで埋める。次の表は、見直しを始める契機の例である。
| 契機 | 見直す対象 | 手順の参照 |
|---|---|---|
| ONTAP の版が変わった、またはスループット容量、SSD 容量を変えた | S_restore の実測値と、SLO の目標 | 「自環境での区間の実測」の手順を再実行する |
| データ量やファイルの形が大きく変わった | S_restore と RTO の例の数値 | 同上。測っていないデータ量の見積りは仮の値として扱う |
| リストア訓練で目標を満たさなかった | RTO と RPO の値、層の選択、手順書 | 「層の選び方の流れ」へ戻る |
| SLO を満たせなかった期間があった | 目標値、測り方、エラーバジェットの扱い | 手順 5 から 6 |
| 復旧の層の構成を変えた（ボールトの追加など） | 候補の層、`layer` の値、取得元 | 手順 3 から 4 |
実績を見直す指標の考え方は、OPS09-BP01 にある [4]。
## 参考文献
番号は本文の `[n]` に対応する。`[E-nnn]` は、[evidence-ledger.json](../agent/evidence-ledger.json) に登録した「できない」型の主張の番号である。日付は、公開日は各ページに表示された日付で、参照日はその URL の内容を確かめた日である。名称は発行主体が付けた原題で書く。
| 番号 | 名称 | 発行主体 | 公開日・版 | URL | 参照日 | 根拠の種別 |
|---|---|---|---|---|---|---|
| 1 | Resilience lifecycle framework: A continuous approach to resilience improvement | AWS Prescriptive Guidance | 2023-10-06（初版） | [docs.aws.amazon.com](https://docs.aws.amazon.com/prescriptive-guidance/latest/resilience-lifecycle-framework/introduction.html) | 2026-11-12 | documented |
| 2 | REL13-BP01 Define recovery objectives for downtime and data loss | AWS Well-Architected Framework | 版つきのパス 2025-02-25 | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_objective_defined_recovery.html) | 2026-11-13 | documented |
| 3 | REL13-BP02 Use defined recovery strategies to meet the recovery objectives | AWS Well-Architected Framework | 版つきのパス 2025-02-25 | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_disaster_recovery.html) | 2026-11-13 | documented |
| 4 | OPS09-BP01 Measure operations goals and KPIs with metrics | AWS Well-Architected Framework | 版つきのパス 2025-02-25 | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_measure_ops_goals_kpis.html) | 2026-11-13 | documented |
| 5 | REL09-BP04 Perform periodic recovery of the data to verify backup integrity and processes | AWS Well-Architected Framework | 版つきのパス 2025-02-25。ページ冒頭に「歴史的な参照用」と表示 | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_backing_up_data_periodic_recovery_testing_data.html) | 2026-11-19 | documented |
| 6 | Cyber recovery on AWS: A reference approach for recovering from ransomware and destructive events | AWS Architecture Blog | 公開 2026-05-20、更新 2026-10-22 | [aws.amazon.com](https://aws.amazon.com/blogs/architecture/cyber-resilience-on-aws-a-reference-approach-for-recovery-from-ransomware-and-destructive-events/) | 2026-11-19 | documented |
| 7 | Planning a NIST-aligned ransomware recovery strategy on AWS、Building isolated, immutable backups for ransomware recovery on AWS、Test backups and restore critical workloads after ransomware on AWS | AWS（AWS re:Post。AWS Support による 3 回のシリーズ） | 2026-10-15 | [第 1 回](https://repost.aws/articles/ARatcO81HOTyCDYQbX5h30pg/planning-a-nist-aligned-ransomware-recovery-strategy-on-aws)、[第 2 回](https://repost.aws/articles/AR9O5kMiZdRL2CBrdXqUI38g/building-isolated-immutable-backups-for-ransomware-recovery-on-aws)、[第 3 回](https://repost.aws/articles/ARU6N19cQrQi66Oj-RiasMPQ/test-backups-and-restore-critical-workloads-after-ransomware-on-aws) | 2026-11-12 | documented（programme 文書の参考文献 27 と同じ。この文書は一般的な資料として示すだけで、個別の記述を引かない） |
| 8 | Protecting your data with backups（Amazon FSx for NetApp ONTAP ユーザーガイド） | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/using-backups.html) | 2026-11-19 | documented |
| 9 | ListBackupJobs（AWS Backup API リファレンス） | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_ListBackupJobs.html) | 2026-11-19 | documented（過去 30 日の記述と、`ByMessageCategory` の存在）。状態の組み合わせで問題ありの件数を求める式は、AWS Backup の文書の記述に基づくこのプロジェクトの読みで、実環境の照合は未実施 |
| 10 | ListRestoreJobs（AWS Backup API リファレンス） | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_ListRestoreJobs.html) | 2026-11-19 | documented |
| 11 | Monitoring AWS Backup with Amazon CloudWatch（AWS Backup 開発者ガイド） | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/aws-backup/latest/devguide/cloudwatch.html) | 2026-11-19 | documented |
| 12 | Restore testing inferred metadata（AWS Backup 開発者ガイド） | AWS | 日付の表示なし | [docs.aws.amazon.com](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing-inferred-metadata.html) | 2026-11-19 | documented |
[E-051] の出典は、AWS Resilience Hub の[対応リソースの一覧](https://docs.aws.amazon.com/resilience-hub/latest/userguide/supported-resources.html)である（2026-11-13、documented）。ベンダーの SLA の数値は、この文書に書いていない。

# Snapshot の復元とクローン作成は、大きなファイルでは秒単位、約 8 万ファイルの 10 GiB では約 3 分だった（1 台のファイルシステム、各 4 回）
> **概要**: 東京リージョンの検証用ファイルシステム 1 台で測った、Snapshot の復元（`volume snapshot restore`、`restore-file`）とクローン作成（FlexClone）の所要時間をまとめる。FSx のバックアップ、AWS Backup、クリーンな作り直し、SnapMirror の測定は進行中または未着手で、数値は載せていない。値は sample run で、本番の見積りではない。使い方と定義は[復旧時間と復旧点の目標のガイド](recovery-objectives-guide.md)にある。
## 結論
- 測ったこと: Snapshot の復元とクローン作成を、データ量 1、10、50 GiB（大きなファイル）と 10 GiB（約 8 万の小さなファイル）で各 4 回。
- 大きなファイルでは、復元は 1.0〜15.0 秒、クローン作成は 1.0〜6.0 秒だった。10 GiB でファイルが小さい形では、復元が 168.0〜170.0 秒、クローン作成が 175.0〜202.0 秒だった。
- 同じ 10 GiB でファイルの形が違うと、範囲が重ならない（[データ量とファイルの形による差](#データ量とファイルの形による差)）。
- 1 つのファイルシステム、同一構成の反復で測った sample run である。本番の見積りではなく、他の構成の値でもない。
- 測定の途中で、ファイルシステムの ONTAP が 9.18.1P6 から 9.19.1P4 に上がった。10 GiB のクローン作成 4 件が影響を受ける（[ONTAP の版の変更の影響](#ontap-の版の変更の影響)）。
- FSx のバックアップの復元（M2）は測定中で、AWS Backup（M3）、クリーンな作り直し（M4）、SnapMirror（M5）、CloudWatch のメトリクス（M6）は数値がない。
## 測定の条件
次の条件は、M1 のすべての測定に共通する。
| 項目 | 値 |
|---|---|
| リージョン | ap-northeast-1 |
| ファイルシステム | FSx for ONTAP 第 1 世代、SINGLE_AZ_1、スループット容量 128 MBps、1 台 |
| ONTAP の版 | 9.18.1P6。2026-11-19 16:19Z〜16:46Z（日本時間 2026-11-20 01:19〜01:46）の週次メンテナンスで 9.19.1P4 に上がった（下記）。版はユーザーが選べない [E-058] |
| クライアント | EC2 の c7gn.large |
| 操作の経路 | ONTAP REST の PATCH（`route=rest-patch`）。各回の前にクライアントを再マウント（`cache=remount`） |
| 測定の日付 | 2026-11-18 と 2026-11-19（UTC） |
| 回数 | 群ごとに 4 回。同じ構成を直列に繰り返した |
| 時刻の分解能 | 1 秒刻み。時計をまたぐ引き算の誤差は約 2 秒（`snapshot-dir-copy` は約 5 秒） |
ONTAP の版の変更を、時系列で示す。
| 時刻（UTC） | 出来事 |
|---|---|
| 2026-11-19 16:19Z | node -02 のフェイルオーバ |
| 2026-11-19 16:31Z | node -01 の復帰 |
| 2026-11-19 16:34Z | node -01 のフェイルオーバ |
| 2026-11-19 16:46Z | node -02 の復帰（記録された最後の出来事） |
記録の `environment.ontap_version` は、測定の開始時に読んだ版を写した値で、記録ごとに読んでいない。そのため 10 GiB のクローン作成 4 件は、記録上は 9.18.1P6 のままだが、実際は更新の最中か後に測っている。訂正は別の記録に持ち、元の記録は書き換えていない。他の群（復元の 8 件を含む）は、すべて更新の前に測った。
## 先行記録との関係
他の層（FSx のバックアップ、AWS Backup の論理エアギャップボールト、SnapMirror）の先行記録は、ガイドの[復旧の層ごとの特徴と実測の所在](recovery-objectives-guide.md#復旧の層ごとの特徴と実測の所在)の表にある。各記録は環境と回数が異なり、この文書の値と並べて比べない。M2 以降の測定が終わったら、この節に対応を追記する。

各測定が土台にする記録を、測定ごとに挙げる。各行は、その記録が何を測ったかだけを書き、値は写さない。

- M2（FSx のバックアップの復元）: Hub の[リージョン・アカウントをまたぐバックアップコピー](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md>)（日本語のみ）は、9.4 MiB のデータのコピーと復元を記録する（第 1 世代 SINGLE_AZ_1、AWS マネージドキー、2026-08-28 と 2026-08-29、手順ごとに 1 回）。[共有ボールトのラボの検証記録](<https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/infrastructure/shared-backup-vault-lab/docs/verification-record.md>)は、2 アカウント間で共有した論理エアギャップボールトを記録する（2026-10-12、項目ごとに 1 回。現在のポータルで成り立つ行は記録の状態行に書かれている）。その[CloudFormation テンプレート](<https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/infrastructure/shared-backup-vault-lab/cloudformation/owner-base.yaml>)は顧客管理キーのファイルシステムを作る。この project は新しいテンプレートを書かず、この方法を再利用する
- M2（復元後の読み戻し）: S3-Burst-on-ONTAP-Files の[性能テストの手引き](<https://github.com/Yoshiki0705/S3-Burst-on-ONTAP-Files/blob/main/docs/ja/reference/performance-testing-guide.md>)は、踏んだ項目として、280 GiB のデータ（メモリ上の 256 GB の層を 18% 超える量）でも読み出しの 98.5〜99.9% がディスクに行かなかったことを挙げる。クライアントの再マウントではストレージ側のメモリは空にならないので、復元直後の読み戻しの時間にはキャッシュの効果が入りうる（推論であり、この project では測っていない）
- M4（クリーンな作り直し）: [ATX によるコンテナ化の FSx for ONTAP ストレージ検証](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Container-Datastore-Patterns/blob/main/docs/ja/atx-containerization-fsxn-storage-verification.md>)の 3.3 節（構成 1 の実機の結果。データを置いたまま計算資源を入れ替える構成。2026-11-10、ap-northeast-1、使い捨ての SVM と 1 GiB のボリューム、項目ごとに 1 回）
- M5（SnapMirror）: [`automation/fsxn-ops` の検証レポート](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Agentic-Access-Aware-RAG/blob/main/automation/fsxn-ops/docs/aws-verification-report.md>)（同一クラスタ内の create、transfer、break、resync、cleanup。ONTAP 9.17.1P4D3、2026-05-01、11 件中 11 件が成功、所要時間の記録なし）。Observability の[カスタムメトリクスのモジュールの実行](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/ja/verification-results-cloudwatch-monitoring.md>)（同じ SVM の 2 つのボリューム間の lag とヘルス、ONTAP 9.18.1P6、2026-10-08、1 回、最初の lag は 22 秒）。[クロスリージョン SnapMirror の知見](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Lakehouse-Integrations/blob/main/integrations/snapmirror-flexcache-multicloud/docs/ja/research.md>)（SM-VAL-008〜011。ap-northeast-1 から us-west-2、break から S3 Access Points の再接続まで約 3 分、2026-07-22、1 回）。ポータルの[検証結果](<https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/solutions/amplify-portal/docs/verification-results.md>)（SnapMirror の作成・削除・quiesce・resume・更新、ONTAP 9.18.1P3D1、2026-08-14 と 2026-08-15。break と resync は含まない）
- M6（CloudWatch のメトリクス）: Observability の [`aws-backup-events.yaml`](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/templates/aws-backup-events.yaml>)（バックアップジョブのイベント）と[監視設計](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/ja/monitoring-design.md>)。後者は、2026-10-07 に読んだ AWS のメトリクスのページに SnapMirror の関係単位のネイティブメトリクスがなかったと記録する
- Multi-AZ のフェイルオーバーはこの project では測らない。記録は Hub の[経路がフェイルオーバーの機構そのもの](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/block-storage/notes/paths-are-the-failover-mechanism.md>)の 1 件だけ（2026-09-05、第 2 世代、HA ペア 1 組、1 回、ブロックプロトコル）
## M1 の結果: Snapshot の復元とクローン作成
単位は秒。n は使える成功の記録の数。範囲は最小と最大で、信頼区間ではない。データ量は GiB。試行数と除外した記録の件数は、集計の確定後に併記する。
| 測定 | データ量（GiB） | ファイルの形 | n | 中央値 | 最小–最大 | ONTAP の版 | 日付（UTC） |
|---|---|---|---|---|---|---|---|
| 復元（`volume-snapshot-restore`） | 1 | 大きなファイル | 4 | 2.0 | 1.0–2.0 | 9.18.1P6 | 2026-11-18 |
| 復元（`volume-snapshot-restore`） | 10 | 大きなファイル | 4 | 2.5 | 2.0–3.0 | 9.18.1P6 | 2026-11-18〜2026-11-19 |
| 復元（`volume-snapshot-restore`） | 10 | 小さなファイル | 4 | 168.5 | 168.0–170.0 | 9.18.1P6 | 2026-11-19 |
| 復元（`volume-snapshot-restore`） | 50 | 大きなファイル | 4 | 7.0 | 7.0–15.0 | 9.18.1P6 | 2026-11-18 |
| ファイルの復元（`restore-file`） | 1 | 大きなファイル | 4 | 1.0 | 1.0–2.0 | 9.18.1P6 | 2026-11-18 |
| `.snapshot` からのコピー（`snapshot-dir-copy`） | 1 | 大きなファイル | 4 | 7.299 | 6.862–7.461 | 9.18.1P6 | 2026-11-18 |
| クローン作成（`flexclone-create`） | 1 | 大きなファイル | 4 | 1.5 | 1.0–2.0 | 9.18.1P6 | 2026-11-18 |
| クローン作成（`flexclone-create`） | 10 | 大きなファイル | 4 | 2.5 | 2.0–4.0 | 1・2 回目は 9.18.1P6、3 回目は更新の最中、4 回目は 9.19.1P4（推定） | 2026-11-19 |
| クローン作成（`flexclone-create`） | 10 | 小さなファイル | 4 | 193.0 | 175.0–202.0 | 1・2 回目は 9.18.1P6、3・4 回目は 9.19.1P4（推定） | 2026-11-19 |
| クローン作成（`flexclone-create`） | 50 | 大きなファイル | 4 | 4.0 | 4.0–6.0 | 9.18.1P6 | 2026-11-18 |
「9.19.1P4（推定）」は、更新の完了後に測ったことから推定した版で、記録ごとに読んだ値ではない。`volume-snapshot-restore` の 1 GiB と 50 GiB は、全ファイルの SHA-256 がマニフェストと一致した。
時刻の分解能は 1 秒で、時計をまたぐ引き算の誤差は約 2 秒（`snapshot-dir-copy` は約 5 秒）である。2.0 秒と 2.5 秒のような 1 秒前後の差は、分解能の範囲内にある。50 GiB の復元の最大 15.0 秒は 1 回目だけで、2〜4 回目は 7.0 秒だった。
### データ量とファイルの形による差
10 GiB の 2 つの形を比べる（同じ構成、各 4 回）。
| 測定 | 大きなファイルの範囲（秒） | 小さなファイルの範囲（秒） | 範囲の重なり |
|---|---|---|---|
| 復元（`volume-snapshot-restore`） | 2.0–3.0 | 168.0–170.0 | なし。差は約 166 秒 |
| クローン作成（`flexclone-create`） | 2.0–4.0 | 175.0–202.0 | なし。小さなファイルの範囲の幅（27 秒）より差が大きい |
観測したのは、同じ 10 GiB でファイルが小さい形のほうが、復元で約 70 倍（中央値 168.5 秒と 2.5 秒）、クローン作成で約 80 倍（193.0 秒と 2.5 秒）長いことである。理由は `hypothesis` である。約 8 万というファイル数が作るメタデータの量が時間を伸ばしたと推測するが、ファイル数だけを変える実験はしていない。
大きなファイルの 1、10、50 GiB は、復元の中央値が 2.0、2.5、7.0 秒、クローン作成が 1.5、2.5、4.0 秒だった。データ量が増えると値は大きくなる傾向にあるが、差の一部は 1 秒の分解能の範囲内にある。この 3 点から他のデータ量の値は外挿しない。
### ONTAP の版の変更の影響
10 GiB のクローン作成の 2 群は、それぞれ 2 回ずつ版が違う。値は次のとおりである（秒）。
| 群 | 9.18.1P6（1・2 回目） | 更新の最中と 9.19.1P4（推定） | 群の範囲 |
|---|---|---|---|
| 大きなファイル | 3、2 | 4（更新の最中）、2（9.19.1P4（推定）） | 2.0–4.0 |
| 小さなファイル | 191、195 | 202、175（どちらも 9.19.1P4（推定）） | 175.0–202.0 |
各版 n=2 なので、版の違いの影響は分離できない。更新の後の値は、どちらの群も、更新の前の値を含む群の範囲の内側にある。9.19.1P4 で 4 回ずつ測り直す判断は、保守者が「しない」と決めた。表の値に版の注記を付けて読む。
この更新は、ユーザーが版を選べない [E-058] ことの実例である。ファイルシステムに設定できるのは週次メンテナンスの開始時刻だけで、測定の途中でも版は変わりうる。
## M2 の結果: FSx のバックアップの復元
測定中。数値は、確定後に載せる。
## M3 の結果: AWS Backup のリストア試験
未着手。数値は、測定の後に載せる。
## M4 の結果: クリーンな作り直し
未着手。数値は、測定の後に載せる。
## M5 の結果: SnapMirror
未着手。数値は、測定の後に載せる。
## M6 の結果: CloudWatch のメトリクスとバックアップジョブの状態
未着手。数値は、測定の後に載せる。
## ばらつきと差の読み方
- n=4 の最小と最大は範囲で、信頼区間ではない。p95 は書かない（標本が 20 件に満たない）。
- 差を読むときは、変えていない構成のばらつき（同じ群の範囲）と比べる。範囲が重なる差は、ノイズと区別できない。
- 1 秒前後の差は、1 秒の分解能と約 2 秒の時計間誤差の範囲内にある。
- 50 GiB の復元の 15.0 秒のような 1 回だけの大きな値は、原因を調べていない。再現は確認していない。
- `capability-probe` の群は能力の確認で、所要時間の測定ではない（n=0）。M1 全体の集計コマンドが終了コード 1 を返すのは、この群を含むからで、各群の個別の集計は終了コード 0 である。
## 本番見積り
作っていない。この文書の値は、1 台のファイルシステムでの sample run で、本番の見積りではない。データ量、ファイル数、ファイルの形、スループット容量、世代、同時の負荷が違えば、値は変わる。自環境では[ガイドの手順](recovery-objectives-guide.md#自環境での区間の実測)で測り直す。
## 測っていないこと
- 他のリージョン、第 2 世代、SINGLE_AZ_2 と MULTI_AZ、128 MBps 以外のスループット容量。
- 50 GiB を超えるデータ量と、10 GiB の約 8 万ファイル以外のファイル数。ファイル数だけを変えた比較。
- 復元やクローン作成の最中の、同時の読み書きの負荷。
- 9.19.1P4 で測り直した 10 GiB のクローン作成（保守者の決定で測り直さない）。
- M2〜M6 の項目（上の各節）。
- 検知から復旧の宣言まで、復旧点の判断、切り替え（RTO の S_detect、S_decide、S_prepare、S_cutover）。

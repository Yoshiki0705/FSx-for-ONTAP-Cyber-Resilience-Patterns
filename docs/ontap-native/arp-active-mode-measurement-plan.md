# ARP アクティブモードの挙動 — 測定計画 / ARP Active-Mode Behaviour: Measurement Plan

## 現在の状態 / Current status

**遮断の有無は測っていない。** 検知が S3 Access Point 経路に及ぶことは測ってある。
下の表が、この文書を書いた時点（2026-09-07）の全部である。

**Blocking is not measured.** Detection reaching the S3 access point path is measured.
The table below is the whole of what is established as of 2026-09-07.

| 問い / Question | 状態 / State | 根拠 / Basis |
|---|---|---|
| (a) アクティブモードは書き込みを遮断するのか、警告だけか | **未測定。** ベンダー文書の応答手順に書き込み拒否が現れない [E-001] | [Respond to abnormal activity (ARP/AI)](https://docs.netapp.com/us-en/ontap/anti-ransomware/respond-arpai.html) を全文で読んだ（2026-09-07） |
| (b) 拒否されたときクライアントが受け取るもの | **未測定。** (a) が拒否を示さない限り ARP 自身については観測対象が存在しない | — |
| (c) S3 Access Point 経由の書き込みが評価対象に入るか | **検知は測定済み**（2026-08-26 / ONTAP 9.18.1P3D1、ARP/AI）。NFS 対照とともに両経路で suspect が立った。検知理由は高エントロピーのみ | `fsxn-observability-integrations` の `docs/ja/verification-results-fpolicy-s3ap-and-session.md`（[リポジトリ](https://github.com/Yoshiki0705/fsxn-observability-integrations)。執筆時点で未マージのブランチにある） |
| (c') 高エントロピー以外の検知理由でも経路差がないか | **未測定。** 観測されたのは `High Entropy` だけ | 同上 |

> **(c) について**: Adoption Playbook が S3 Access Point 経路の穴を ARP に帰しているのは、
> **検知については誤りではない**。訂正が必要なのは「検知できる」を「遮断できる」の根拠に使う
> 書き方だけで、Playbook は現状それを避けている。詳細は Issue #29 のコメントに書いた。
>
> **On (c)**: attributing the S3 access point path to ARP is **not wrong for detection**.
> What would be wrong is using detection as grounds for blocking, which the Playbook
> currently avoids. See the comment on Issue #29.

---

## 前提 — 学習期間はモデル世代に紐づく制約 / Premise: the learning period belongs to the model generation

30 日はモデル世代に紐づく制約で、いま測る環境には存在しない。**この計画は 30 日の予算を
必要としない。**

The 30 days belong to a model generation and do not exist in the environment where the
measurement would run. **This plan needs no 30-day budget.**

| モデル / Model | ONTAP | 学習期間 / Learning period |
|---|---|---|
| ARP/AI | 9.16.1 以降（FlexVol）、9.18.1 以降（FlexGroup） | 不要。有効化直後から能動的に保護する |
| ARP（旧世代 / original） | FlexVol は 9.10.1〜9.15.1、FlexGroup は 9.13.1〜9.17.1 | NAS FlexVol で 30 日。9.13.1 以降はアクティブへ自動切替 |
| ARP/AI + SAN | 9.17.1 以降 | 2〜4 週間の評価期間（暗号化しきい値の基準づくり） |

出典: [Learn about ONTAP Autonomous Ransomware Protection](https://docs.netapp.com/us-en/ontap/anti-ransomware/)（全文、2026-09-07 取得）。
実測とも一致する。`dry_run` を要求しても `enabled` になり、学習期間は存在しなかった
（ONTAP 9.18.1P3D1、2026-08-15 / [ARP/AI と EMS の罠](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/docs/agent/pitfalls-arp-ems.md)）。

**そのため、この文書のどこにも 30 日の待ちは現れない。** 旧世代 ARP の挙動を測る必要が
生じたときだけ 30 日が復活する。その場合の扱いは次の節。

### 旧世代 ARP を測る必要が出たときの 30 日の調達 / Funding the 30 days if the original ARP must be measured

**30 日を単独予算で回さない。** 顧客が 9.15.1 以下に留まっている、または FlexGroup を
9.17.1 で使っている場合だけ必要になる。そのときは次の形にする。

**Do not fund 30 days on its own.** It is only needed for a cluster on 9.15.1 or earlier,
or FlexGroup on 9.17.1. In that case:

1. 別の理由で立つファイルシステム（AD / SMB 検証、FlexCache 検証、Partner 向け PoC など）の
   **初日に** 対象ボリュームで ARP を `dry-run` で有効化しておく。ARP は Amazon FSx for NetApp ONTAP の
   利用料に含まれ、有効化による追加課金はない
2. 30 日以上生き残るボリュームを選ぶ。**ボリュームを削除すると ARP の学習状態も消える**ので、
   検証の途中で作り直すボリュームは使わない
3. 9.13.1 以降は自動でアクティブへ切り替わるので、30 日後の手作業は要らない。切り替わったことは
   `security anti-ransomware volume show` の `state` で確認する
4. 「短時間だけ有効にして戻す」で代用しない。無効化は即時ではなく、20 GiB の空ボリュームで
   `disable_in_progress` が 10 分以上続いた（2026-08-15 実測、同上）。別の環境の独立した観測でも
   11 分以上かかっている（2026-09-07、Adoption Playbook 側）。**2 環境で一致している**

---

## 測定環境と器具 / Environment and instrument

新しく作るものはない。(c) の測定で使った器具をそのまま使う。

Nothing new is built. The harness from the (c) measurement is reused as-is.

| 要素 / Element | 内容 |
|---|---|
| クラスタ | ONTAP 9.18.1P3D1（`security anti-ransomware` の `version` は両ノードで `5.0`）、ap-northeast-1 |
| ボリューム | ARP/AI を有効化した FlexVol 2 本。一方に S3 Access Point をアタッチ、他方は NFSv3 の対照 |
| 書き込み器 | 初めて見る拡張子を持つ高エントロピーファイルを多数書く。(c) の測定と同一パターン |
| 観測 | `security anti-ransomware volume show`、suspect の一覧、`entropy-stat show-recent-high-encryption-stat`、EMS `callhome.arw.activity.seen` |
| EMS の読み取り | REST では `message.severity` を使う。`severity` はフィールドでもフィルタでも 262197 で拒否される（実測、上記 pitfalls 参照） |

> **偽陰性の罠**: `attack_probability` は書き込みから 10 分以上遅れて変わる。この値だけを
> 短時間見て「検知されていない」と判断すると誤る。**suspect の一覧を見る。**
>
> **False-negative trap**: `attack_probability` moves more than 10 minutes after the write.
> Reading only that value over a short window reports a false negative. **Read the suspect list.**

---

## Q1. 遮断の有無 / Q1. Block, or alert

### 測り方 / Method

1. ARP/AI 有効のボリュームに、パターンを **1 書き込み 1 レコード**で記録しながら書く。
   記録するのは連番、時刻（ミリ秒）、戻り値、`errno`（S3 経路では HTTP ステータスと
   エラーコード）、所要時間
2. suspect が立ち、`attack_probability` が動いた**後も 30 分書き続ける**。ARP の応答は
   検知の瞬間ではなく確認・分類の手順に紐づくため、検知直後に止めると応答後の書き込みを
   観測できない
3. 途中で ARP が作成したスナップショットを `volume snapshot show` で記録する
4. 書き込みを止め、`clear-suspect` を**する前**に最後の書き込み結果を保存する

### 判定 / Reading the result

| 観測 | 結論 |
|---|---|
| 全書き込みが成功 | ARP は遮断しない。ARP を関門として設計してはいけない |
| 一部が失敗し、`errno` が `EACCES` / `EPERM` 相当 | 遮断している。Q2 へ |
| 一部が失敗し、`ENOSPC` | **ARP による遮断ではない。** ARP スナップショットでボリュームが埋まった結果。容量の問題として別に記録する。隣接する 1 回の観測では 10 GiB ボリュームで ARP スナップショットは最大 3.2 MB で `ENOSPC` は起きなかったので、既定では起きにくい。**それでも失敗の原因を切り分ける列は残す** |
| 応答が返らない | ハングとして Q2 で扱う。タイムアウト値を記録する |

`ENOSPC` を遮断と読み違えないことが、この測定で最も間違えやすい点である。**書き込みが失敗した
という事実だけでは、何が失敗させたかは分からない。**

Mistaking `ENOSPC` for a refusal is the easiest error here. **That a write failed does not
say what failed it.**

### 予想と、予想を書く理由 / Expectation, and why it is written down

ベンダー文書の応答手順は、警告の発行、スナップショットの作成、管理者による false positive /
potential attack の分類、その後の監視再開で構成される。**書き込みを拒否する動作はどこにも
現れない** [E-001]。したがって予想は「全書き込みが成功」である。

予想を先に書くのは、予想どおりだったときに「測る必要がなかった」と言えるようにするためではない。
**予想と違ったときに、どこで驚いたかを残すため**である。9.18.1 が文書にない動作をしている
可能性は排除できない。

---

## Q2. 拒否されたときクライアントが受け取るもの / Q2. What the client receives on refusal

Q1 が拒否を示さなかった場合、**ARP 自身については観測対象が存在しない。** そのとき Q2 の
対象は ARP ではなく、実際に遮断を行う層に移る。「ARP が遮断する」と想定した設計が実際に
依存することになるのはそちらだからである。

If Q1 shows no refusal, **there is nothing to observe for ARP itself.** Q2 then moves to the
layer that actually refuses, because that is what a design assuming "ARP blocks" would rely on.

| 遮断の実装 | 経路 | 測る対象 |
|---|---|---|
| export-policy deny | NFS | クライアントの `errno`、既存マウントへの反映までの時間 |
| name-mapping deny | SMB | 同上。**NTFS セキュリティ形式のボリュームでは遮断できない** [E-002] ため、ボリュームのセキュリティ形式を先に記録する。NTFS では Windows 資格情報で許否が決まり、マッピングに失敗した利用者は default UNIX user に落ちる（[NetApp KB](https://kb.netapp.com/on-prem/ontap/da/NAS/NAS-KBs/How_does_name-mapping_work_when_CIFS_clients_access_NTFS_security_style_resources) 全文、2026-09-07 取得） |
| データ LIF の無効化 | 全経路 | 既存セッションの切れ方。エラーとして返るのかハングするのか |
| アクセスポイントポリシー / IAM deny | S3 Access Point | HTTP ステータスとエラーコード |

> **S3 経路のエラーは直感に反する**: SVM 側の条件で拒否されたとき、`HeadBucket` を含む全データ
> 操作が **503 ServiceUnavailable** を返した観測がある（2026-08-26、AD ドメインプレフィクス付き
> `WindowsUser.Name` の事例）。`AccessDenied` ではないので、403 を探すと IAM・アクセスポイント
> ポリシー・ACL という原因ではない層を調べることになる。**アプリが 403 だけを扱う実装だと、
> この拒否は「一時障害」として再試行され続ける。**
>
> **Errors on the S3 path are counter-intuitive**: a refusal rooted in an SVM-side condition
> surfaced as 503, not 403. An application that handles only 403 will retry such a refusal
> as a transient failure.

記録する形は、経路ごとに「ステータス / エラーコード / 本文」「再試行が起きるか」
「アプリが恒久的拒否と一時障害を区別できるか」の 3 列にする。

---

## Q3. S3 Access Point 経路の評価 — 残っている部分 / Q3. The S3 access point path: what remains

検知は測定済みである（両経路で suspect が立った。検知理由はすべて `High Entropy`）。
**残っているのは、高エントロピー以外の検知理由で経路差が出ないかである。**

Detection is measured (suspects on both paths, all `High Entropy`). **What remains is whether
a non-entropy detection reason shows a difference between the paths.**

ARP の検知入力は、ファイル内容から決まるもの（エントロピー）と、操作の観測から決まるもの
（初見の拡張子、create / rename / delete のレート）に分かれる。前者は経路に依存しないと
考えられる。**後者が S3 Access Point 経路で観測されるかは別問題で、FPolicy が同じ経路を
見ないことが分かっている以上、自明ではない。**

### 文書化されている検知入力と閾値 / The documented inputs and thresholds

改名・削除・作成は**検知入力に入っている**。「ARP の対象外」ではない。

| パラメータ | 判定の条件 |
|---|---|
| `based-on-high-entropy-data-rate` | ボリューム単位の高エントロピーデータレート |
| `based-on-never-seen-before-file-extension` | ボリュームで初見の拡張子。**エントロピーを見ない**ので、内容を変えずに拡張子だけ書き換える種類に効く |
| `based-on-file-create-rate` / `-rename-rate` / `-delete-rate` | 各操作レートが `...-surge-notify-percentage` の割合だけ**「過去に観測された値」より跳ねたとき** |
| `never-seen-before-file-extn-count-notify-threshold` | **1 つの新しい拡張子について、その拡張子で create / rename されたファイル数**。期間は `-duration-in-hours` |
| `relaxing-popular-file-extensions` | `true` なら `.mp3` のような一般的な拡張子は安全扱い |

出典: [attack-detection-parameters show](https://docs.netapp.com/us-en/ontap-cli-9171/security-anti-ransomware-volume-attack-detection-parameters-show.html)
および [modify](https://docs.netapp.com/us-en/ontap-cli-9161/security-anti-ransomware-volume-attack-detection-parameters-modify.html)（いずれも全文、2026-09-07 取得）。

> **この表は「切り替えられる入力」の一覧であって、検知入力の全体ではない。** パラメータに依存せず
> 常に有効な経路が 2 つ文書化されている（ファイル単位の高エントロピー検知、拡張子とエントロピーを
> 組み合わせた検知）。したがって**非検知を特定のパラメータの挙動として説明できない。** ある結果から
> 言えるのは「この入力群のどれからも判定が出なかった」までである。
>
> **The table is the set of toggleable inputs, not the set of detection inputs.** Two paths are
> always enabled and independent of these parameters, so a non-detection cannot be attributed to
> any one parameter.

**したがって正しい言い方は「両方の機構から外れる」ではなく「閾値の外側にある」である。**
対象外なら別の機構を足すしかないが、閾値の外側なら閾値と基準の作られ方の問題になる。
**設計の打ち手が変わる。**

### 隣接する 1 回の観測 / One adjacent observation

Adoption Playbook 側で 1 回測定された（ONTAP 9.18.1P3D1 / ARP/AI、**新規に作ったボリューム**、
`never-seen-before` は 5 件 / 48 時間、**4 ケースすべて NFSv3**、観測 30 分）。記録は Playbook
側にあり、ここには転記しない。

| ケース | 結果 |
|---|---|
| 対照: 高エントロピーで内容を上書き | 検知（6 分後、`moderate`） |
| 1,000 件の一括改名 / 一括削除（内容不変） | 検知なし |
| 未知拡張子への書き換え（1 拡張子に 1,000 件） | 検知なし。拡張子は `file_extensions_observed` に記録されていた |

**1 回、再現なし、NFSv3 のみ。この観測から「改名・削除・拡張子では検知されない」は導けない。**

- **履歴がない。** サージは「過去に観測された値」との比較なので、新規ボリュームには比較対象がない [E-005]
- **期間の条件が試されていない可能性がある。** 件数条件（1 拡張子に 1,000 件 > 閾値 5）は満たしていた。
  未達は期間で、`for this duration` は「その期間内に」とも「その期間続けて」とも読める。
  前者なら非検知は評価周期の遅れの話、後者なら条件自体が未試行。**どちらとも決められない**
- **経路が NFSv3 だけ。** S3 Access Point 経路の既存実測は高エントロピー検知で、同一設計の比較ではない

### 測り方 / Method

**解釈を確定させるのではなく、どちらの読みでも条件が満たされる設計にする。**

0. `security anti-ransomware volume attack-detection-parameters show -instance` で閾値と
   `relaxing-popular-file-extensions` の**環境の実値**を記録する（文書の例は 20 件 / 24 時間だが、
   観測されている値と異なる）
1. **既に操作履歴のあるボリュームを選ぶ。** 新規ボリュームで履歴を作ると日数の待ちが入り、
   30 日を避けた計画に別の待ちを持ち込む。選んだボリュームの直近の操作レートを先に記録する
2. 各ケースを両経路で実施する

| ケース | 書くもの |
|---|---|
| C1 | 低エントロピーのテキストに、**1 つの**初見拡張子。閾値を超える件数を、**`-duration-in-hours` を超える時間にわたって書き続ける**。観測もその時間より長く |
| C2 | 既知の拡張子のまま、手順 1 の基準レートに対して `surge-notify-percentage` を超えるレートで改名・削除。複数のタイムスロットにまたがらせる |
| C3 | 高エントロピー（対照。既に測ってある条件の再現） |

C1 をこの形にすると `for this duration` がどちらの読みでも満たされる。**待ちは既存ボリューム上の
書き込みループなので追加コストは出ない。**

C1 の拡張子に一般的なものを使わない。ただし**「一般的」とみなされる拡張子の一覧は公開されていない**
[E-006] ため、該当しないことは確認できない。

S3 プロトコルに rename が無いので、C2 は S3 経路では copy + delete か put + delete の列になる。
**この非対称性自体を記録する**（同じ攻撃行為が経路によって別の操作列として現れる）。

**S3 Access Point 経由の操作が create / rename / delete のカウンタに数えられるかは不明。**
CLI リファレンスの show / modify いずれにもプロトコルによる限定は書かれていない（全文、2026-09-07）。
REST / SDK のモデル文書に「NAS ボリュームでのみ有効」とあるという情報はあるが、**そのページを
開けていない**ため出典にしない。
<!-- allow:unverified: the protocol scope of these counters is not established; the only text
     suggesting a NAS-only scope was seen in a search snippet whose page could not be opened,
     and a snippet is not a source. -->
**これが Q3 の核心であり、C2 の経路差が答えになる。**

---

## この計画で触らないもの / What this plan does not touch

不可逆な操作は、この計画の一部にしない。**検証目的は例外にならない。**

Irreversible operations are not part of this plan. **Verification purposes are not an exception.**

| 操作 | この計画での扱い |
|---|---|
| SnapLock ボリュームの作成、保持期間の設定 | 触らない。[SnapLock Configuration](snaplock-configuration.md) の不可逆性の節を参照 |
| Snapshot locking の有効化 | 触らない。[Tamperproof Snapshot](tamperproof-snapshot.md) を参照 |
| privileged delete の `PERMANENTLY_DISABLED` | 触らない |
| ARP の有効化 | 行う。不可逆ではないが、**無効化は即時ではない**（`disable_in_progress` が 10 分以上）。共有環境では実施時間帯を決めてから |
| ARP スナップショットの `clear-suspect` | 行う。MAV を有効にしている場合は承認が必要になる |

上の 3 つが必要になった場合は、**保持期間の値と、最も広い影響範囲**（どのボリューム・どの SVM・
どのファイルシステムが、いつまで削除できなくなるか）を提示して承認を得てから実施する。
監査ログボリュームのように、ファイルシステム全体が数か月削除できなくなる組み合わせがある。

---

## 記録する項目 / What gets recorded

3 ケースすべてで共通に記録する。**検知されなかった場合も同じ項目を埋める。**
「観測を打ち切った」と「条件を満たしていない」を後から切り分けられるようにするための一覧である。

| 項目 | 目的 |
|---|---|
| `attack-detection-parameters show -instance` の全項目 | 閾値とサージ率、`relaxing-popular-file-extensions` の実値 |
| 選んだボリュームの直近の create / rename / delete レート | サージ判定の比較対象。**これが無いと非検知を解釈できない** |
| ケースごとの経路、件数、拡張子、書き込み継続時間、観測時間 | どの条件を満たし、どれを満たしていないかの判定材料 |
| suspect 件数と、suspect ごとの検知理由 | `High Entropy` 以外が現れるかどうか |
| `attack-probability` の推移と、**`none` から動くまでの時間** | 遅れの分布。対照では 6 分で `moderate` になった観測がある。**打ち切りと条件不成立の切り分けに使う** |
| `attack-detected-by` の値 | 下記の制約つき |
| `entropy-stat show-recent-high-encryption-stat` / `show-encryption-percentage-histogram` | エントロピー側の判定材料。attack timeline との対応 |
| 常時有効な経路が動いていた事実 | 非検知の場合の前提。ファイル単位の高エントロピー検知と拡張子＋エントロピーの組み合わせは、パラメータに関わらず走っている |

> **`attack-detected-by` からは入力を特定できない。値集合そのものも文書から決まらない**
> （同じページがパラメータ行で `file` / `block`、直後の説明で `file_analysis` /
> `encryption_percentage_analysis` を並べている）[E-007]。**観測値をそのまま記録し、
> どの入力が判定したかを推測しない。** 入力に迫るなら suspect ごとの検知理由と entropy-stat を見る。
>
> **Record the observed value verbatim.** The field cannot identify the input, and the reference
> does not settle what the field returns.

`attack-probability` は `none` / `low` / `moderate` / `high`。`state` の 7 値と、それを画面に
出すときの注意は [ARP Configuration](arp-configuration.md) の「状態の値域と表示」にある。

---

## 結果の記録先 / Where results go

| 成果 | 置き場所 |
|---|---|
| 生の観測（コマンド、出力、時刻） | `fsxn-observability-integrations` の測定記録に追記する。測定環境がそちらにあるため |
| 設計への影響 | 本リポジトリの [comparison-security-layers.md](../comparison-security-layers.md) の ARP 行と、[arp-configuration.md](arp-configuration.md) |
| 主張の帰属 | `docs/agent/evidence-ledger.json`。E-001 の tier を `documented` から `verified` に上げ、`observation` に測定内容を書く |
| Playbook への通知 | Issue で。**内容の転記はしない** |

測れなかった場合も、測っていないことと理由をこの文書に残す。**制約そのものが知見である。**

If it cannot be measured, this document records that it was not, and why. **The constraint is
itself the finding.**

---

## 参照 / References

- [Learn about ONTAP Autonomous Ransomware Protection](https://docs.netapp.com/us-en/ontap/anti-ransomware/) — モデル世代と学習期間の比較表
- [Respond to abnormal activity detected by ONTAP ARP/AI](https://docs.netapp.com/us-en/ontap/anti-ransomware/respond-arpai.html) — 応答手順
- [Learn about ONTAP S3 multiprotocol support](https://docs.netapp.com/us-en/ontap/s3-multiprotocol/) — S3 NAS バケットの相互運用。S3 操作が NAS 監査イベントを起こすこと、および対象外の一覧
- [ARP Configuration](arp-configuration.md) — 有効化手順
- [Security Layer Comparison](../comparison-security-layers.md) — ARP / TrendAI / Deep Instinct の比較
- [ARP/AI と EMS の罠](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/docs/agent/pitfalls-arp-ems.md) — `dry_run` の扱い、無効化の遅さ、EMS の `message.severity`
- [fsxn-observability-integrations](https://github.com/Yoshiki0705/fsxn-observability-integrations) — FPolicy / 監査ログ / ARP の経路別カバレッジ測定

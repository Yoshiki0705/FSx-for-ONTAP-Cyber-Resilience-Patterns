# Decision-Record Playbook

> このリポジトリ固有の接続だけを書く。土台はグローバル steering
> （`ai-agent-workflow` の Auditor Sub-Agent 節 / Parallel-by-default 節、
> `benchmark-and-evidence-standards`）にあり、ここでは複製しない。

多段タスク（新パターン追加、検証、IaC 変更）では、実装の記述とは別に判断記録の 3 節
（Decisions / Rejected alternatives / Assumptions）を残す。

## 判断記録の置き場所 / Where the decision record goes

| 対象 | 置き場所 | git |
|---|---|---|
| 再利用するテンプレート/playbook 本体（このファイル） | `docs/agent/`（agent 材料の規約） | 追跡 |
| タスクごとの判断記録（却下案・未検証前提・根拠 tier を含む process metadata） | `.private/tasks/<task>/` | 非公開（gitignore） |

- タスクごとの判断記録は非公開側が既定。却下案・未検証前提・レビュー provenance は
  公開物に残さず非公開へ、というグローバル output-standards と整合する。
- `.private/tasks/<task>/` に既存の記録ファイル（`plan.md` / `report.md` /
  `impl-note.md` 等）があるなら、新名を増やさずそれに 3 節を追記する。名前は既存慣習に
  合わせてよく、`impl-note.md` に統一しなくてよい。
- 3 節を別々のファイルに切り出さない。そのタスクの 1 つの記録に収める。

## 3 節の雛形 / The three sections

```markdown
## Decisions
- <決めたこと>: <なぜ。根拠は 測定 / 文献 / 推測 のどれか。tier=<下表>、出典かリンク>

## Rejected alternatives
- <却下した案>: <なぜ却下したか。状況が変われば復活しうるか>

## Assumptions
- <検証せずに前提に置いたこと>: <外れたら何が壊れるか>
```

検証を伴う判断は、Decisions の根拠欄に evidence tier を対応づける。**tier はこの
リポジトリの evidence-ledger（`docs/agent/evidence-ledger.json`、ゲート
`scripts/check_evidence_claims.py`）が使う 4 語に揃える。5 つ目を作らない。**

| tier | 意味（ledger の `$comment` より） |
|---|---|
| documented | ベンダー文書にある。全文読みが要る |
| verified | ここで何かを実行して観測した。observation が要る |
| hypothesis | 隣接する事実からの推論。ベンダーは言っていない |
| open | どちらとも確立していない |

1 回だけ観測して再現未確認のものは、`verified` に observation として「1 回観測、再現未確認」と
明記するか、まだ確立していないなら `hypothesis` にする。中間の新語は使わない。

「ベンダーが〜できない / 対象外」の主張は ledger に登録し、`[E-nnn]` で同じ表のセルに引用する。

## 監査役を呼ぶ合図 / When to call an auditor

次のいずれかに気づいたら、作業を続ける前に監査役を呼び、判断記録と変更差分を渡す。
自動 hook は作らない。

- 同一アプローチが 2 回失敗した
- 同じファイルを 3 回以上編集し直している
- 多段タスクで同じエラーメッセージが再発している

呼ぶ相手: `semantic_reviewer`（判断の見直し）/ `context-gatherer`（前提が実装と合うかの確認）。
渡す問いは「補強」ではなく「疑う」方向にする。

- 根拠が推測（hypothesis）の判断はどれか
- 却下した代替で、今なら復活すべきものはあるか
- 外れたら作業が無駄になる未検証の前提（Assumptions）はどれか

このリポジトリの受け皿は evidence-ledger。主張の帰属と tier はそこに登録し、監査役の指摘で
tier が動いたら ledger を直す。**新しい監査インベントリは作らない。** 公開物コミット直前の
レビューは persona review board の担当で、監査役とは分ける。

## ばらつきを測ってから効果を主張する / Measure variance before claiming an effect

性能・スループット・レイテンシ・コストの数値で変更の効果を主張する前に、変更していない
構成のランごとのばらつきを先に測る。変更の差がそのばらつきの範囲内なら、効果ではなく
ノイズ。そう書くか、ばらつきを超えるまで反復数を増やす。**1 回ずつしか測っていない
「A は B より速い」も同じ扱い**（`hypothesis` であって `verified` ではない）。

- `benchmarks/run_benchmark.py` の出力（`BenchmarkResult`）は現状 1 ラン分で、ランごとの
  ばらつき（反復数、分散）を持つフィールドがない。効果を主張する測定をここで回すなら、
  同一構成の複数ランと、その散らばりを記録する形に拡張してから主張する。拡張の判断は
  その測定タスクの Decisions に `documented`/`verified` の根拠付きで残す。
- 数値には環境（ONTAP 版 / instance type / region / throughput capacity / 測定日）を併記する
  （`environment` と `caveats` を埋める）。「サンプル実行」と「本番見積り」を区別する。

## 繰り返しタスク型チェックリスト / Recurring-task checklists

2 回目の同種の失敗は、ここに項目が足りない兆候として扱う。失敗を直すのと同じコミットで、
該当の型に 1 項目足す。

### A. テンプレート追加・変更（IaC: `templates/*.yaml`）

- [ ] `make lint`（cfn-lint）と `make security`（cfn-guard + gitleaks）が緑。緑になる前に
      「通してはいけない入力で落ちる」ことを確認したか（ゲートの空回りを疑う）
- [ ] 全リソースに `Project` / `Layer` / `Component` タグ
- [ ] 名前付き IAM ロールを含むなら、デプロイ手順に `CAPABILITY_NAMED_IAM` を明記
      （`CAPABILITY_IAM` では InsufficientCapabilitiesException）
- [ ] WORM / 保持（SnapLock、Tamperproof Snapshot、privileged delete 無効化）を
      ワンステップ deploy にしていない。有効化に明示的な保持判断が要る旨を書いたか
- [ ] クロススタック参照は `Fn::ImportValue` / `!Sub` / `!Ref`
- [ ] 既存リソースを再利用する設計か（新規作成で重複を作っていないか）
- [ ] `llms.txt` / README の該当エントリを更新したか

### B. 検証ラン（測定・ベンチマーク）

- [ ] 測定計画に沿っているか（ARP なら `docs/ontap-native/arp-active-mode-measurement-plan.md`）
- [ ] **効果を主張する前に、変更していない構成のばらつきを先に測ったか**（上節）
- [ ] 数値に環境と測定日を併記し、サンプル実行と本番見積りを区別したか
- [ ] 撤去で消えるアーティファクトを撤去の**前に**退避したか。退避し損ねたら tier を下げて穴を明示
- [ ] 不可逆操作（SnapLock、保持期間、privileged delete 無効化）を含めていないか。
      含めるなら、保持値と最も広い影響範囲を提示して承認を得てから
- [ ] 結果の置き場所を決めたか（生の観測は Observability-integrations、設計影響は本リポジトリ、
      主張の帰属は `docs/agent/evidence-ledger.json`）
- [ ] 「ベンダーが〜できない / 対象外」の主張を ledger に登録し `[E-nnn]` で引用したか

### C. ドキュメント変更（JA/EN parity + evidence）

- [ ] JA/EN の両方を同じコミットで変更し、見出し・表の行をそろえたか
- [ ] 命名（FSx for ONTAP のみ。新規の access point は S3 Access Points と略さない）
- [ ] 中立性（ベンダー対決・優劣表現なし。トレードオフ対称、how-to-choose を添える）
- [ ] 公開物に個人名/ペルソナ名・AWS アカウント ID・内部 IP・サポートケース番号・
      ベンダー内部チケット ID が入っていないか
- [ ] 役割名・人名ラベルの注記を作っていないか（話題名の中立ラベルを使う）
- [ ] 新規・訂正した「ベンダーが〜できない」主張を ledger に登録し `[E-nnn]` で引用
- [ ] `make test`（check-evidence, ai-style, check-sensitive, cfn-lint, pytest）が緑
- [ ] `docs/articles/*` の本文は編集しない（本人名義の記事）

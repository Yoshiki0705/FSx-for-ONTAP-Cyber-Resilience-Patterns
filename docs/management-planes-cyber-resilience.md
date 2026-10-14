# Management Planes for Cyber Resilience: どの経路でどの操作を行うか

## Table of Contents / 目次

- [このドキュメントの位置づけ / Scope](#このドキュメントの位置づけ--scope)
- [5 つの管理面 / The Five Management Planes](#5-つの管理面--the-five-management-planes)
- [サイバーレジリエンシー operation × 管理面 / Operation × Management Plane](#サイバーレジリエンシー-operation--管理面--operation--management-plane)
- [経路ごとのトレードオフ / Trade-offs per Plane](#経路ごとのトレードオフ--trade-offs-per-plane)
- [選び方 / How to Choose](#選び方--how-to-choose)
- [ARP 検知結果の判定を例に / Worked Example: Classifying an ARP Detection](#arp-検知結果の判定を例に--worked-example-classifying-an-arp-detection)
- [今日時点の UI 検証 / Today's UI, Verified](#今日時点の-ui-検証--todays-ui-verified)
- [免責事項 / Disclaimer](#免責事項--disclaimer)

---

## このドキュメントの位置づけ / Scope

FSx for ONTAP のサイバーレジリエンシー機能（Autonomous Ransomware Protection、FPolicy、SnapLock、Tamperproof Snapshot、Multi-Admin Verification、Snapshot/SnapMirror/FlexClone による復旧）は、複数の管理面から操作できる。同じ操作が複数の経路に存在し、経路ごとに前提・制約・課金が異なる。このドキュメントは、サイバーレジリエンシーの各 operation（検知・対応・復旧・監査・設定）を、どの管理面から行えるかを中立に一覧する。特定の経路を推奨・優越として押し出さず、各経路のトレードオフを対称に記す。

FSx for ONTAP's cyber resilience features (Autonomous Ransomware Protection, FPolicy, SnapLock, Tamperproof Snapshot, Multi-Admin Verification, and recovery via Snapshot/SnapMirror/FlexClone) can be operated from several management planes. The same operation often exists on more than one path, and each path has different prerequisites, constraints, and costs. This document is a neutral map of which plane can perform each cyber resilience operation (detect, respond, recover, audit, configure). It does not push any single path as superior; it states each path's trade-offs symmetrically.

> **Scope note**: このドキュメントは「どの経路でその操作に到達できるか」を扱う。各機能そのものの挙動・不可逆性・設計上の注意は、[ARP 設定ガイド](ontap-native/arp-configuration.md)、[SnapLock 設定](ontap-native/snaplock-configuration.md)、[Tamperproof Snapshot](ontap-native/tamperproof-snapshot.md)、[MAV 設定](ontap-native/mav-configuration.md)、[フレームワークマッピング](en/cyber-resilience-framework-mapping.md) を参照。ここではそれらを重複させない。
>
> This document covers how to reach an operation, not how each feature behaves. For feature behavior, irreversibility, and design caveats, see the per-feature references linked above; they are not duplicated here.

---

## 5 つの管理面 / The Five Management Planes

FSx for ONTAP は、AWS マネジメントコンソール / AWS CLI / AWS API・SDK に加えて、NetApp 製の管理ツールからも操作できる（[AWS 公式: Managing FSx for ONTAP resources using NetApp applications](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/managing-resources-ontap-apps.html)、2026-10-14 全文確認）。サイバーレジリエンシー operation に関係する管理面は次の 5 つ。

In addition to the AWS Management Console, AWS CLI, and AWS API/SDKs, FSx for ONTAP resources can be managed from NetApp tooling ([AWS: Managing FSx for ONTAP resources using NetApp applications](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/managing-resources-ontap-apps.html), read in full 2026-10-14). Five planes are relevant to cyber resilience operations.

| 管理面 / Plane | 何か / What it is | 到達方法 / How to reach it |
|---|---|---|
| **ONTAP CLI** | fsxadmin / vsadmin で SSH 接続する ONTAP のコマンドライン。クラスタ管理者相当（FSx for ONTAP ではサブセット） | 同一 VPC の EC2 から管理エンドポイントへ SSH |
| **ONTAP REST API** | ONTAP の REST インターフェース。CLI と同じ操作をプログラムから | 管理エンドポイントへ HTTPS。TLS 検証無効化か AWS CA バンドルの信頼が必要 |
| **ONTAP System Manager** | ONTAP 内蔵のブラウザ管理 UI。ボリューム単位の Security タブで ARP を操作 | NetApp Console 経由（下記）。FSx for ONTAP 単体ではブラウザ直アクセスの経路に制約がある（検証中） |
| **NetApp Console**（旧 BlueXP） | オンプレ/クラウドを横断する統合コントロールプレーン。System Manager を同じ UI から利用できる | Console agent または AWS Lambda link で FSx for ONTAP ファイルシステムを紐づけ |
| **NetApp Workload Factory** | FSx for ONTAP 向けの GUI。ストレージ構成とデータ保護操作を画面から | link の関連付けが前提 |

> **第 2 世代ファイルシステムの制約 / Second-generation constraint**: NetApp Console と NetApp System Manager は、HA ペアが 2 つ以上の第 2 世代ファイルシステムではサポートされない [E-023]（[AWS 公式](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/managing-resources-ontap-apps.html)、2026-10-14 全文確認）。該当構成では CLI / REST API が経路になる。
>
> NetApp Console and NetApp System Manager are not supported for second-generation file systems with more than one HA pair [E-023]. On such configurations, the CLI/REST API are the available planes.

---

## サイバーレジリエンシー operation × 管理面 / Operation × Management Plane

各セルは「その経路でその操作が行えるか」を示す。◯ = 公式ドキュメントで手順を確認、— = 当該経路の対象外または経路として想定されない、? = 未確認（実機検証で確定予定、下記「今日時点の UI 検証」）。経路の存在であって優劣ではない。

Each cell shows whether the operation is reachable on that plane. ◯ = procedure confirmed in vendor documentation; — = out of scope for that plane; ? = unverified, to be settled by live verification (see "Today's UI, Verified"). This is reachability, not ranking.

| Operation | CLI | REST API | System Manager | NetApp Console | Workload Factory |
|---|---|---|---|---|---|
| **ARP 有効化・無効化** / Enable/disable ARP | ◯ | ◯ | ? | ? | ◯ [V1] |
| **ARP 検知パラメータ設定** / Configure ARP detection params | ◯ | ◯ | ? | ? | ◯ [V2] |
| **ARP 検知結果の確認** / Review ARP detection | ◯ | ◯ | ◯ [1] | ? | ◯* [V3] |
| **誤検知/実攻撃の判定** / Classify false positive / attack | ◯ | ◯ | ◯ [1] | ? | ◯* [V3] |
| **entropy spike / suspect の詳細** / Entropy & suspect details | ◯ | ◯ | ◯ [1] | ? | ◯* [V3] |
| **ARP baseline/surge 統計の表示** / ARP baseline & surge stats | ◯ | ◯ | — [2] | — [2] | ? |
| **FPolicy 設定** / Configure FPolicy | ◯ | ◯ | ? | ? | ? |
| **Snapshot 作成・復元** / Snapshot create/restore | ◯ | ◯ | ? | ? | ◯ [V4] |
| **SnapMirror 複製** / SnapMirror replication | ◯ | ◯ | ? | ? | ◯ [V4] |
| **FlexClone 作成** / FlexClone | ◯ | ◯ | ? | ? | ? |
| **SnapLock / Tamperproof Snapshot（immutable files/snapshots）** [3] | ◯ | ◯ | ? | ? | ◯ [V4] |
| **MAV（多管理者承認）** / Multi-Admin Verification | ◯ | ◯ | ? | ? | ? |
| **AWS Backup 連携** / AWS Backup | — | — | — | — | — [4] |

脚注 / Footnotes:

- **[1]** ARP/AI の検知結果の確認と判定（false positive / potential ransomware attack の指定）は、System Manager の **Storage > Volumes > 対象ボリューム > Security タブ** で行う手順が公式に記載されている（[NetApp: Respond to abnormal activity detected by ONTAP ARP/AI](https://docs.netapp.com/us-en/ontap/anti-ransomware/respond-arpai.html)、2026-10-14 全文確認）。NAS ボリュームは suspected file types を、NAS/SAN 双方は entropy spike を同タブで確認できる。CLI の等価は `security anti-ransomware volume attack clear-suspect ... -false-positive {true|false}`。
- **[2]** ONTAP 9.18.1 で、System Manager は ARP/AI の workload characteristics（baseline / surge 統計）の**表示を取りやめた**（[NetApp: ARP feature availability by release](https://docs.netapp.com/us-en/ontap/anti-ransomware/release-history-arp.html)、2026-10-14 全文確認）。ARP/AI の検知・動作そのものは不変で、surge 統計は CLI / REST API から引き続き参照できる。質問背景の 9.18.1 系で「ARP 関連の表示が出ない」場合、この表示削除が一因になりうる。Security タブ（検知対応）そのものの削除ではない点に注意。
- **[3]** SnapLock / Tamperproof Snapshot は保持期間が不可逆（期間満了まで管理者でも削除不能）。経路の存在にかかわらず、有効化は明示的な保持判断を要する。詳細と注意は [SnapLock 設定](ontap-native/snaplock-configuration.md) と [Tamperproof Snapshot](ontap-native/tamperproof-snapshot.md)。
- **[4]** AWS Backup は AWS マネジメントコンソール / CLI / API の操作で、ここに挙げた 5 経路の対象外。Malware Protection for AWS Backup は FSx for ONTAP の recovery point を対象外（[E-008]）、AWS マネージドキーのファイルシステムは論理エアギャップボールトへコピーされない（[E-009]）。詳細は [AWS Backup 論理エアギャップボールト](data-protection/aws-backup-logically-air-gapped-vault.md)。
- **[V1]–[V4]**: 実機検証（2026-10-14、ap-northeast-1、第 1 世代・単一 HA ペアの検証用ファイルシステム、Lambda link 経由）で確認。[V1] ボリューム > Actions > Data protection actions > Manage ARP/AI の有効化トグルを確認。[V2] 同画面の Detection Defaults で高エントロピー・作成/リネーム/削除レート・拡張子・新規拡張子しきい値（既定 20）の各パラメータを GUI から設定できることを確認。[V3] 検知結果の確認・判定への経路（Volumes の「Analyze attacks」）の存在を確認。`◯*` は経路の存在のみ確認で、判定操作そのものは検証環境に検知イベントがなく未実行（画面は「No new suspected attacks」）。[V4] Data protection actions に Manage snapshots / Manage immutable files（SnapLock/Tamperproof 系）があることを確認。詳細は下記「今日時点の UI 検証」。

---

## 経路ごとのトレードオフ / Trade-offs per Plane

各経路の制約を対称に挙げる。推奨経路にも制約があり、それも書く。

Trade-offs are stated symmetrically; the constraints of every path, including the convenient ones, are listed.

### ONTAP CLI

- **向くもの**: スクリプト化、監査証跡（`kern_audit` にコマンドが残る）、第 2 世代の複数 HA ペア構成（GUI 経路が使えない場合の経路）、SAN ボリュームの entropy 統計など CLI でしか出ない情報。
- **トレードオフ**: 同一 VPC の EC2 からの SSH が前提。fsxadmin は FSx for ONTAP のマネージド制約でコマンドのサブセットのみ実行可（[fsxadmin の制約](ontap-native/fsxadmin-limitations.md)）。GUI を求める運用者には学習コストがある。

### ONTAP REST API

- **向くもの**: 自動化・イベント駆動（検知を受けて clear-suspect をラップする等）。既存の [FPolicy → EventBridge → Step Functions](architecture/overview.md) の設計と整合。
- **トレードオフ**: TLS 検証の無効化か AWS CA バンドルの信頼が必要。PATCH の結果が要求どおりに反映されない無言の挙動があるため、書き込み後は read-back が要る（[E-004]）。state 値の読み取りにも版差がある。

### ONTAP System Manager

- **向くもの**: ONTAP 標準の GUI で ARP 検知結果を確認・判定したい運用。Security タブに suspect/entropy の詳細が出る [1]。ONTAP 管理者が既に慣れた UI。
- **トレードオフ**: 第 2 世代の複数 HA ペアでは非対応。FSx for ONTAP 環境では NetApp Console 経由での利用が案内されており、ブラウザ直アクセスの経路・前提は構成に依存する（実機検証で確定）。9.18.1 で baseline/surge 統計の表示が削除された [2]。

### NetApp Console（旧 BlueXP）

- **向くもの**: オンプレと AWS を横断して複数 ONTAP を 1 つのコントロールプレーンから管理したい場合。System Manager を同じ UI から使える。
- **トレードオフ**: FSx for ONTAP ファイルシステムへの link（Console agent または Lambda link）の構築・維持が前提。第 2 世代の複数 HA ペアでは非対応。Console 側の操作が AWS コンソール/CLI に反映されるまで数分の同期ラグがある。link と agent の運用・課金が発生する。

### NetApp Workload Factory

- **向くもの**: FSx for ONTAP のストレージ構成・データ保護を GUI から行いたい場合。
- **トレードオフ**: link の関連付けが前提。利用可能な operation の範囲と今日時点の画面項目は実機検証で確定する（下記）。

---

## 選び方 / How to Choose

次の順で絞ると、経路は自ずと決まる。どれが上位という話ではなく、前提と要件の交差で決まる。

Narrow in this order; the path falls out of prerequisites and requirements, not from ranking.

1. **ファイルシステムの世代と HA ペア数**。第 2 世代で HA ペアが 2 つ以上なら、NetApp Console / System Manager は非対応。CLI / REST API が経路。
2. **自動化したいか、人が画面で判断したいか**。イベント駆動で検知対応を自動化するなら REST API。人が検知結果を見て誤検知/実攻撃を判断するなら System Manager の Security タブ、または NetApp Console / Workload Factory の GUI。
3. **既に慣れた UI があるか**。ONTAP 管理者なら System Manager。複数環境を横断管理しているなら NetApp Console。
4. **link と課金を許容できるか**。NetApp Console / Workload Factory は link の構築・維持と課金が前提。許容できなければ CLI / REST API / System Manager（Console 経由の制約内）。
5. **監査証跡が要るか**。CLI は `kern_audit` にコマンドが残る。GUI 操作の証跡の出方は経路ごとに異なる（実機検証で記録）。

---

## ARP 検知結果の判定を例に / Worked Example: Classifying an ARP Detection

「ONTAP コマンドを叩かずに ARP 検知結果を確認し、誤検知か実攻撃かを指定したい」という要件は、複数の経路で満たせる。経路ごとの手順の所在を示す。

The requirement "review an ARP detection and mark it false positive or attack without using ONTAP commands" can be met on more than one path. The procedure's location per path:

- **System Manager**: Storage > Volumes > 対象ボリューム > Security タブ。NAS は Suspected file types を選んで **Mark as false positive** または **Potential ransomware attack**、続いて **Update and Clear Suspected File Types**。entropy spike（NAS/SAN）は **Mark as ...** → **Save and dismiss**（[respond-arpai](https://docs.netapp.com/us-en/ontap/anti-ransomware/respond-arpai.html)、2026-10-14 全文確認）。
- **NetApp Console / Workload Factory**: GUI からの検知結果確認・判定の画面項目は実機検証で確定（下記の空欄）。
- **CLI（参考）**: `security anti-ransomware volume attack clear-suspect -vserver <svm> -volume <vol> -false-positive {true|false}`。コマンドを使う経路だが、他経路の等価操作の対応確認用に併記。

> **運用上の補足 / Operational note**: 誤検知/実攻撃を指定すると、ARP/AI がその判定を threat assessment profile に記録し、以降の監視に反映する（[respond-arpai](https://docs.netapp.com/us-en/ontap/anti-ransomware/respond-arpai.html)）。表示上のフラグにとどまらず検知動作が変わるため、業務上正当な処理であることを確認したうえで指定する。トリアージの流れは [ARP アラートトリアージ runbook](runbooks/arp-alert-triage.md)。

---

## 今日時点の UI 検証 / Today's UI, Verified

NetApp Workload Factory の今日時点 UI を、検証用ファイルシステムに Lambda link を関連付けて確認した。NetApp Console（Console agent）と System Manager は、agent 用の EC2 を立てない方針としたため今回は未検証（上表では `?` のまま）。

Verified the current NetApp Workload Factory UI against a verification file system with a Lambda link associated. NetApp Console (Console agent) and System Manager were not checked this round, to avoid standing up an EC2 agent (left as `?` above).

| 項目 / Item | 記録 / Record |
|---|---|
| 検証日 / Date | 2026-10-14 |
| リージョン / Region | ap-northeast-1（東京 / Tokyo） |
| 世代・HA ペア数 / Generation & HA pairs | 第 1 世代・単一 HA ペア（Workload Factory 画面表記: First-generation (single HA pair)） |
| link 方式 / Link method | Lambda link（EC2 常駐なし）。CloudFormation で IAM ロール 1 + Lambda 関数 1（コンテナイメージ型）+ Lambda Permission 4 + カスタムリソース 2 を作成 |
| 検証対象 / Scope | NetApp Workload Factory のみ（Console / System Manager は未検証） |

### Workload Factory で確認した ARP/AI 管理経路 / Verified ARP/AI path in Workload Factory

- **ナビゲーション**: Storage > FSx for ONTAP > 対象ファイルシステム > **Volumes** タブ。各ボリュームの行に「ARP/AI status」列と「Protection」列があり、ファイルシステム単位の ARP/AI サマリ（Protected volumes 数、新規の疑わしい攻撃の有無、「Analyze attacks」リンク）が出る。
- **ARP/AI の有効化**: ボリューム > **Actions > Data protection actions > Manage ARP/AI**。有効化トグル、既定スナップショットポリシー（4 時間ごと最大 6 個、各 2〜5 日ロック）の説明、immutable snapshot の保持に関する同意チェックがある。FlexVol は学習モードから即アクティブ、FlexGroup は 7 日後、という挙動が画面に明記されている。
- **検知パラメータの設定**: 同画面の **Detection Defaults** で、高エントロピー（ボリューム単位）・ファイル作成/リネーム/削除レート・よく使う拡張子の除外・新規拡張子しきい値（既定 20 ファイル）を GUI から設定できる。これは ONTAP CLI の `security anti-ransomware volume attack-detection-parameters` に相当する。
- **検知結果の確認・判定**: Volumes の「Analyze attacks」が経路。検証環境に検知イベントがなかったため（「No new suspected attacks」）、誤検知/実攻撃の判定操作そのものは未実行。判定操作の公式手順は System Manager 側で確認済み（上表脚注 [1]）。
- **同じ Data protection actions に** Manage snapshots / Manage immutable files（SnapLock/Tamperproof 系）があり、Snapshot と WORM 系も同じ GUI 経路で管理できる。

### link の実機知見（運用上の注意）/ Link setup, learned in practice

- Workload Factory のボリューム単位の操作（ARP/AI 管理を含む）には **link が前提**。link 未関連付けのファイルシステムは、ARP/AI status が `n/a`、ボリューム一覧の各値が取得できず「Partial data is displayed … lack links」と表示される。
- link は 2 段構えで、**(1) link の作成（CloudFormation）** と **(2) ファイルシステムへの関連付け + 認証（authenticate）** が別ステップ。(1) だけでは overview に「Associate link」警告が残り、ARP データは取れない。
- 認証モードは「Workload Factory」（パスワードを直接入力）と「AWS Secrets Manager」（シークレット ARN を指定）の 2 つ。**Secrets Manager モードを使う場合、link の Lambda 実行ロールに対象シークレットの `secretsmanager:GetSecretValue` 権限が必要**。link 作成時に Secrets Manager を無効のままにすると、ロールにこの権限が付かず、authenticate が「not authorized to access secret」で失敗する。
- 認証が通らない原因は 2 種類に切り分けられる。**「not authorized to access secret」= link ロールの IAM 権限不足**（上記）。**「Invalid ONTAP credentials」= シークレットの値が ONTAP の現在のパスワードと不一致**（ロックではない。到達性・TLS・ONTAP の認証処理はいずれも成立しており、資格情報だけが違う状態）。後者はシークレットが古い/別ファイルシステム用のときに起きる。
- 古いパスワードのまま link が認証を繰り返すと ONTAP の管理ユーザーがロックされうる。切り分け中は link の Lambda を予約並列数 0 に絞って再試行を止めると安全（確認後に戻す）。

> **Secrets 運用に関する補足 / Secrets note**: FSx for ONTAP の管理ユーザー認証情報は、ファイルシステムごとに別のシークレットで管理し、どのファイルシステム用かをシークレットのタグ（`FileSystemId` / `FileSystemName`）と説明に明記しておくと、同名ユーザー（fsxadmin）での取り違えによる認証失敗を避けられる。パスワードをリセットしたら、そのシークレットを単一の真実の源として更新し、更新日と検証状態を説明に残す。

---

## 免責事項 / Disclaimer

- この一覧は 2026-10-14 時点の公式ドキュメント（AWS / NetApp）に基づく。管理面の対応操作・UI は版により変わる。`?` のセルは実機検証で確定するまで未確認であり、未確認を「対応」とも「非対応」とも読まないこと。
- SnapLock / Tamperproof Snapshot の有効化は不可逆な保持判断を伴う。経路の存在は有効化の推奨ではない。
- NetApp Console / Workload Factory の利用には link の構築・維持と課金が伴う。本番適用前に自環境でコストと制約を確認すること。

<!-- allow:unverified: methodology note about this document's own ? cells, not a vendor-absence claim -->
- This map reflects AWS and NetApp documentation as of 2026-10-14. Supported operations and UI change by release. Cells marked `?` are unverified until live verification; do not read an unverified cell as either supported or unsupported.
- Enabling SnapLock / Tamperproof Snapshot involves an irreversible retention decision. The existence of a path is not a recommendation to enable it.
- NetApp Console / Workload Factory require building and maintaining a link, with associated cost. Confirm cost and constraints in your own environment before production use.
